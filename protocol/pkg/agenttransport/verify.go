package agenttransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"google.golang.org/protobuf/proto"
)

// NetworkMode is explicit because the deployed registry has no epochs yet.
type NetworkMode string

const (
	Production                 NetworkMode = "production"
	TestNetworkLegacyEpochZero NetworkMode = "test-network-legacy-epoch-zero"
	// TestNetworkEpochAware exercises the future boundary with synthetic snapshots;
	// it is not a production registry adapter or evidence of registry support.
	TestNetworkEpochAware NetworkMode = "test-network-epoch-aware"
	MaxCacheEntries                   = 1024
	RefreshAfter                      = 300 * time.Second
	RefuseAfter                       = 600 * time.Second
)

// Snapshot is one atomic finalized read. Epochs are explicit metadata from the
// same checkpoint, never inferred from generation, sequence or policy bytes.
type Snapshot struct {
	State           *nativev1.NativeStateV1
	CurrentEpoch    *uint64
	AdmissionEpochs map[[32]byte]uint64
	EpochCheckpoint uint64
}

// FinalizedResolver must honor cancellation and bound its response. An absent
// Agent is a successful read with nil State, not an availability error.
// Errors mean only that finalized state could not be read; invalid proofs or
// contradictory evidence must return a successful, invalid snapshot instead.
type FinalizedResolver interface {
	ResolveFinalizedAgent(context.Context, string) (Snapshot, error)
}

// ErrUnavailable alone permits stale-pass fallback. Proof and integrity errors
// must not wrap it.
var ErrUnavailable = errors.New("finalized read unavailable")

type Clock interface{ Now() time.Time }
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

type Config struct {
	Mode         NetworkMode
	Network      *nativev1.NetworkDomain
	ChainPolicy  ChainPolicy
	Clock        Clock
	CacheEntries int
	ReadTimeout  time.Duration
}

type Verifier struct {
	mu       sync.Mutex
	config   Config
	resolver FinalizedResolver
	passes   map[[32]byte]time.Time
	lastNow  time.Time
}

func NewVerifier(c Config, r FinalizedResolver) (*Verifier, error) {
	if c.Mode != TestNetworkLegacyEpochZero && c.Mode != TestNetworkEpochAware {
		return nil, errors.New("production transport requires a finalized registry with authorization epochs; only explicitly named test-network modes are available")
	}
	if err := c.ChainPolicy.Validate(); err != nil {
		return nil, err
	}
	if err := validateNetwork(c.Network); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, errors.New("finalized resolver required")
	}
	if c.Clock == nil {
		c.Clock = systemClock{}
	}
	if c.CacheEntries == 0 {
		c.CacheEntries = MaxCacheEntries
	}
	if c.CacheEntries < 1 || c.CacheEntries > MaxCacheEntries {
		return nil, errors.New("invalid cache capacity")
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = 5 * time.Second
	}
	if c.ReadTimeout <= 0 || c.ReadTimeout > 30*time.Second {
		return nil, errors.New("invalid finalized read timeout")
	}
	c.Network = proto.Clone(c.Network).(*nativev1.NetworkDomain)
	c.ChainPolicy.RegistryCodeHashes = append([]string(nil), c.ChainPolicy.RegistryCodeHashes...)
	return &Verifier{config: c, resolver: r, passes: make(map[[32]byte]time.Time)}, nil
}

func (v *Verifier) now() (time.Time, error) {
	now := v.config.Clock.Now()
	if now.Unix() < 0 || (!v.lastNow.IsZero() && now.Before(v.lastNow)) {
		clear(v.passes)
		return now, errors.New("transport clock moved backwards or before its epoch")
	}
	v.lastNow = now
	return now, nil
}

func checkUse(d Delegation, purpose Purpose, now time.Time) error {
	if purpose != Relay && purpose != Hints && purpose != Direct {
		return errors.New("unknown requested purpose")
	}
	if d.Purposes&purpose == 0 {
		return errors.New("delegation does not allow requested purpose")
	}
	seconds := uint64(now.Unix())
	// Subtract only after comparison, so an untrusted u64 cannot overflow now+300.
	if (d.NotBefore > seconds && d.NotBefore-seconds > 300) || seconds >= d.NotAfter {
		return errors.New("delegation is not currently valid")
	}
	return nil
}

// VerifyDelegation checks time and purpose on every use, including cached uses.
// Only an availability error permits the bounded stale-pass fallback.
func (v *Verifier) VerifyDelegation(ctx context.Context, b []byte, purpose Purpose) (Delegation, error) {
	d, err := DecodeDelegation(b)
	if err != nil {
		return d, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	now, err := v.now()
	if err != nil {
		return d, err
	}
	if err = checkUse(d, purpose, now); err != nil {
		return d, err
	}
	digest := sha256.Sum256(b)
	checked, cached := v.passes[digest]
	if cached && now.Sub(checked) < RefreshAfter {
		return d, nil
	}
	ctx, cancel := context.WithTimeout(ctx, v.config.ReadTimeout)
	defer cancel()
	snapshot, readErr := v.resolver.ResolveFinalizedAgent(ctx, d.AgentID())
	after, err := v.now()
	if err != nil {
		return d, err
	}
	if err = checkUse(d, purpose, after); err != nil {
		return d, err
	}
	if readErr != nil {
		if !errors.Is(readErr, ErrUnavailable) {
			delete(v.passes, digest)
			return d, errors.New("finalized resolver integrity failure")
		}
		if cached && after.Sub(checked) < RefuseAfter {
			return d, nil
		}
		delete(v.passes, digest)
		return d, errors.New("finalized Agent state unavailable and no usable cached pass")
	}
	// A revoking or malformed answer invalidates the previous pass immediately.
	delete(v.passes, digest)
	if err = v.checkSnapshot(d, digest, snapshot, true); err != nil {
		return d, err
	}
	if after.Sub(now) >= RefreshAfter {
		return d, errors.New("finalized read too old")
	}
	for key, t := range v.passes {
		if after.Sub(t) >= RefuseAfter {
			delete(v.passes, key)
		}
	}
	if len(v.passes) < v.config.CacheEntries {
		v.passes[digest] = now
	}
	return d, nil
}

func (v *Verifier) checkSnapshot(d Delegation, digest [32]byte, s Snapshot, admitted bool) error {
	agent, err := CheckState(v.config.ChainPolicy, v.config.Network, d.AgentID(), s.State)
	if err != nil {
		return err
	}
	if admitted {
		found := false
		for _, entry := range agent.DelegationDigests {
			if entry == "sha256:"+hex.EncodeToString(digest[:]) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("delegation is not in the finalized live set")
		}
	}
	if v.config.Mode == TestNetworkLegacyEpochZero {
		if d.AuthorizationEpoch != 0 || s.CurrentEpoch != nil || s.AdmissionEpochs != nil || s.EpochCheckpoint != 0 {
			return errors.New("legacy test network requires epoch zero and no recorded epochs")
		}
	} else {
		if s.CurrentEpoch == nil || *s.CurrentEpoch == 0 || s.State.Reference.FinalizedCheckpoint != s.EpochCheckpoint || d.AuthorizationEpoch != *s.CurrentEpoch {
			return errors.New("delegation epoch differs from the current finalized authorization epoch")
		}
		if admitted {
			epoch, present := s.AdmissionEpochs[digest]
			if !present || epoch != d.AuthorizationEpoch {
				return errors.New("delegation epoch differs from its recorded admission epoch")
			}
		}
	}
	policy, err := nativecore.PolicyCell(agent.Policy)
	if err != nil {
		return err
	}
	if !bytes.Equal(policy.Hash(), d.PolicyHash[:]) {
		return errors.New("delegation policy differs from finalized policy")
	}
	return nil
}

// BuildDelegation refuses issuance for a future/stale epoch or another policy.
// It does not require membership: committing the resulting digest is a later
// native action, authorized by the Agent's controllers.
func (v *Verifier) BuildDelegation(ctx context.Context, d Delegation) ([]byte, error) {
	b, err := d.Encode()
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, v.config.ReadTimeout)
	defer cancel()
	s, err := v.resolver.ResolveFinalizedAgent(ctx, d.AgentID())
	if err != nil {
		return nil, err
	}
	if err = v.checkSnapshot(d, sha256.Sum256(b), s, false); err != nil {
		return nil, err
	}
	return b, nil
}

// LegacyResolver is the deployed, epoch-less finalized state reader.
type LegacyResolver interface {
	ResolveAgent(context.Context, string) (*nativev1.NativeStateV1, bool, error)
}

type LegacyTestNetworkResolver struct{ source LegacyResolver }

// NewLegacyTestNetworkResolver never enables production or fabricates epochs.
func NewLegacyTestNetworkResolver(mode NetworkMode, source LegacyResolver) (*LegacyTestNetworkResolver, error) {
	if mode != TestNetworkLegacyEpochZero || source == nil {
		return nil, errors.New("epoch-less resolver requires explicit test-network-legacy-epoch-zero mode")
	}
	return &LegacyTestNetworkResolver{source: source}, nil
}

func (r *LegacyTestNetworkResolver) ResolveFinalizedAgent(ctx context.Context, id string) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	state, found, err := r.source.ResolveAgent(ctx, id)
	if err != nil {
		return Snapshot{}, err
	}
	if err = ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if !found {
		state = nil
	}
	return Snapshot{State: state}, nil
}
