package agenttransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"google.golang.org/protobuf/proto"
)

const (
	MaxCacheEntries = 1024
	RefreshAfter    = 300 * time.Second
	RefuseAfter     = 600 * time.Second
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
// Only ErrUnavailable denotes read unavailability; all other errors fail closed.
// Returned snapshots must be immutable and internally consistent for the call.
type FinalizedResolver interface {
	ResolveFinalizedAgent(context.Context, string) (Snapshot, error)
}

// ErrUnavailable alone permits stale-pass fallback. Proof and integrity errors
// must not wrap it.
var ErrUnavailable = nativecore.ErrFinalizedReadUnavailable

type Clock interface{ Now() time.Time }
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

type Config struct {
	Network      *nativev1.NetworkDomain
	ChainPolicy  ChainPolicy
	Clock        Clock
	CacheEntries int
	ReadTimeout  time.Duration
}

type Verifier struct {
	gate     chan struct{}
	config   Config
	resolver FinalizedResolver
	passes   map[[32]byte]cachedPass
	lastNow  time.Time
}

type cachedPass struct {
	agent     [32]byte
	stateHash string
	epoch     uint64
	checked   time.Time
}

// A newly observed finalized state can revoke sibling digests of this Agent.
func (v *Verifier) invalidateChangedAgentPasses(agent [32]byte, snapshot Snapshot) {
	state := snapshot.State
	typed := state.GetAgent()
	usable := typed != nil && !typed.Tombstoned && typed.EncodingVersion == nativecore.StateEncodingVersion &&
		snapshot.CurrentEpoch != nil && *snapshot.CurrentEpoch == typed.AuthorizationEpoch &&
		state.GetReference().GetFinalizedCheckpoint() == snapshot.EpochCheckpoint
	for digest, pass := range v.passes {
		if pass.agent == agent && (!usable || pass.stateHash != state.TvmStateHash ||
			pass.epoch != typed.AuthorizationEpoch || snapshot.AdmissionEpochs[digest] != pass.epoch) {
			delete(v.passes, digest)
		}
	}
}

func NewVerifier(c Config, r FinalizedResolver) (*Verifier, error) {
	if err := validateNetwork(c.Network); err != nil {
		return nil, err
	}
	if err := c.ChainPolicy.Validate(); err != nil {
		return nil, err
	}
	if len(c.ChainPolicy.RegistryCodeHashes) != 1 || c.ChainPolicy.RegistryCodeHashes[0] != nativecore.RegistryV2CodeHash {
		return nil, errors.New("transport verification requires the frozen Registry v2 code hash")
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
	return &Verifier{gate: make(chan struct{}, 1), config: c, resolver: r, passes: make(map[[32]byte]cachedPass)}, nil
}

func (v *Verifier) now() (time.Time, error) {
	now := v.config.Clock.Now()
	if now.Unix() < 0 || (!v.lastNow.IsZero() && (now.Before(v.lastNow) || now.Round(0).Before(v.lastNow.Round(0)))) {
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
	if err := ctx.Err(); err != nil {
		return Delegation{}, err
	}
	d, err := DecodeDelegation(b)
	if err != nil {
		return d, err
	}
	ctx, cancel := context.WithTimeout(ctx, v.config.ReadTimeout)
	defer cancel()
	select {
	case v.gate <- struct{}{}:
		defer func() { <-v.gate }()
	case <-ctx.Done():
		return d, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return d, err
	}
	now, err := v.now()
	if err != nil {
		return d, err
	}
	if err = checkUse(d, purpose, now); err != nil {
		return d, err
	}
	digest := sha256.Sum256(b)
	pass, cached := v.passes[digest]
	checked := pass.checked
	if cached && now.Sub(checked) < RefreshAfter {
		return d, nil
	}
	snapshot, readErr := v.resolver.ResolveFinalizedAgent(ctx, d.AgentID())
	if err := ctx.Err(); err != nil {
		delete(v.passes, sha256.Sum256(b))
		return d, err
	}
	if readErr == nil {
		v.invalidateChangedAgentPasses(d.AgentDigest, snapshot)
	} else if !errors.Is(readErr, ErrUnavailable) {
		v.invalidateChangedAgentPasses(d.AgentDigest, Snapshot{})
	}
	after, err := v.now()
	if err != nil {
		return d, err
	}
	if err = checkUse(d, purpose, after); err != nil {
		return d, err
	}
	if readErr != nil {
		if !errors.Is(readErr, ErrUnavailable) {
			return d, errors.New("finalized resolver integrity failure")
		}
		if cached && after.Sub(checked) < RefuseAfter {
			return d, nil
		}
		delete(v.passes, digest)
		return d, errors.New("finalized Agent state unavailable and no usable cached pass")
	}
	// Recheck the requested digest even when the finalized state is unchanged.
	delete(v.passes, digest)
	if err = v.checkSnapshot(d, digest, snapshot, true); err != nil {
		return d, err
	}
	if after.Sub(now) >= RefreshAfter {
		return d, errors.New("finalized read too old")
	}
	for key, pass := range v.passes {
		if after.Sub(pass.checked) >= RefuseAfter {
			delete(v.passes, key)
		}
	}
	if len(v.passes) < v.config.CacheEntries {
		v.passes[digest] = cachedPass{agent: d.AgentDigest, stateHash: snapshot.State.TvmStateHash, epoch: d.AuthorizationEpoch, checked: now}
	}
	return d, nil
}

func (v *Verifier) checkSnapshot(d Delegation, digest [32]byte, s Snapshot, admitted bool) error {
	agent, err := CheckState(v.config.ChainPolicy, v.config.Network, d.AgentID(), s.State)
	if err != nil {
		return err
	}
	if len(agent.DelegationAdmissions) > nativecore.MaxDelegationAdmissions || len(s.AdmissionEpochs) > nativecore.MaxLiveDelegations {
		return errors.New("finalized delegation set exceeds its bound")
	}
	if s.CurrentEpoch == nil || *s.CurrentEpoch == 0 ||
		agent.AuthorizationEpoch != *s.CurrentEpoch ||
		s.State.Reference.FinalizedCheckpoint != s.EpochCheckpoint || d.AuthorizationEpoch != *s.CurrentEpoch {
		return errors.New("delegation epoch differs from the current finalized authorization epoch")
	}
	if admitted {
		epoch, present := s.AdmissionEpochs[digest]
		if !present || epoch != d.AuthorizationEpoch {
			return errors.New("delegation epoch differs from its recorded admission epoch")
		}
		found := false
		for _, entry := range agent.DelegationAdmissions {
			if entry.GetDigest() == "sha256:"+hex.EncodeToString(digest[:]) && !entry.Withdrawn && entry.AdmissionEpoch == d.AuthorizationEpoch {
				found = true
				break
			}
		}
		if !found {
			return errors.New("delegation is not in the finalized live set")
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
