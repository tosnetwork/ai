package agenttransport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"google.golang.org/protobuf/proto"
)

type fakeClock struct{ at time.Time }

func (c *fakeClock) Now() time.Time          { return c.at }
func (c *fakeClock) advance(d time.Duration) { c.at = c.at.Add(d) }

type locator string

func (l locator) Locate(string, string) (string, error) { return string(l), nil }

type reader struct {
	snapshot Snapshot
	err      error
	calls    int
	after    func()
}

func (r *reader) ResolveFinalizedAgent(ctx context.Context, _ string) (Snapshot, error) {
	r.calls++
	if _, ok := ctx.Deadline(); !ok {
		return Snapshot{}, errors.New("missing read deadline")
	}
	if r.after != nil {
		r.after()
	}
	return r.snapshot, r.err
}

type fixture struct {
	d     Delegation
	wire  []byte
	c     Config
	r     *reader
	clock *fakeClock
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	d := sample()
	public := make([]byte, mldsa44.PublicKeySize)
	public[0] = 1
	id, err := mldsa44.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, Controllers: []*nativev1.ControllerV1{{KeyId: mldsa44.KeyIDText(id), Mldsa44PublicKey: public, Weight: 1, PurposeMask: 15, Recovery: true}}}
	cell, err := nativecore.PolicyCell(policy)
	if err != nil {
		t.Fatal(err)
	}
	copy(d.PolicyHash[:], cell.Hash())
	wire, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(wire)
	network := &nativev1.NetworkDomain{NetworkId: localTestNetworkID, GenesisRootHash: localTestRoot, GenesisFileHash: localTestFile}
	code := nativecore.RegistryV2CodeHash
	state := &nativev1.NativeStateV1{Network: proto.Clone(network).(*nativev1.NetworkDomain), TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("4", 64), Reference: &nativev1.ChainReference{FinalizedCheckpoint: 10, ContractCodeHash: code, Account: "0:test", TransactionHash: "sha256:" + strings.Repeat("5", 64)}, State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{EncodingVersion: 2, AuthorizationEpoch: 1, AgentId: d.AgentID(), Policy: policy, DelegationAdmissions: []*nativev1.DelegationAdmissionV1{{Digest: "sha256:" + hex.EncodeToString(digest[:]), AdmissionEpoch: 1}}}}}
	epoch := uint64(1)
	r := &reader{snapshot: Snapshot{State: state, CurrentEpoch: &epoch, AdmissionEpochs: map[[32]byte]uint64{digest: 1}, EpochCheckpoint: 10}}
	clock := &fakeClock{at: time.Unix(1800000010, 0)}
	return &fixture{d: d, wire: wire, c: Config{Network: network, ChainPolicy: ChainPolicy{RegistryCodeHashes: []string{code}, MinFinalizedCheckpoint: 10, Locator: locator("0:test")}, Clock: clock}, r: r, clock: clock}
}
func (f *fixture) verifier(t testing.TB) *Verifier {
	t.Helper()
	v, err := NewVerifier(f.c, f.r)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func verify(t *testing.T, v *Verifier, b []byte, p Purpose, want bool) {
	t.Helper()
	_, err := v.VerifyDelegation(context.Background(), b, p)
	if (err == nil) != want {
		t.Fatalf("want accepted=%v, got %v", want, err)
	}
}
func (f *fixture) reencode(t *testing.T) {
	t.Helper()
	b, err := f.d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	f.wire = b
	digest := sha256.Sum256(b)
	f.r.snapshot.State.GetAgent().DelegationAdmissions = []*nativev1.DelegationAdmissionV1{{Digest: "sha256:" + hex.EncodeToString(digest[:]), AdmissionEpoch: f.d.AuthorizationEpoch}}
	f.r.snapshot.AdmissionEpochs = map[[32]byte]uint64{digest: f.d.AuthorizationEpoch}
}

func TestVerificationChecks(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*fixture)
		purpose Purpose
	}{
		{"strict-domain", func(f *fixture) { f.wire[0] ^= 1 }, Relay},
		{"network", func(f *fixture) { f.r.snapshot.State.Network.NetworkId = "other" }, Relay},
		{"finality", func(f *fixture) {
			f.c.ChainPolicy.MinFinalizedCheckpoint = 0
			f.r.snapshot.EpochCheckpoint = 0
			f.r.snapshot.State.Reference.FinalizedCheckpoint = 0
		}, Relay},
		{"stale-checkpoint", func(f *fixture) {
			f.r.snapshot.EpochCheckpoint = 9
			f.r.snapshot.State.Reference.FinalizedCheckpoint = 9
		}, Relay},
		{"registry-code", func(f *fixture) {
			f.r.snapshot.State.Reference.ContractCodeHash = "tvm-cell-sha256:" + strings.Repeat("6", 64)
		}, Relay},
		{"account", func(f *fixture) { f.r.snapshot.State.Reference.Account = "0:other" }, Relay},
		{"reference", func(f *fixture) { f.r.snapshot.State.Reference = nil }, Relay},
		{"typed-state-hash", func(f *fixture) { f.r.snapshot.State.TvmStateHash = "" }, Relay},
		{"transaction-hash", func(f *fixture) { f.r.snapshot.State.Reference.TransactionHash = "" }, Relay},
		{"agent", func(f *fixture) { f.r.snapshot.State.GetAgent().AgentId = "agent_" + strings.Repeat("a", 64) }, Relay},
		{"absent", func(f *fixture) { f.r.snapshot.State = nil }, Relay},
		{"tombstone", func(f *fixture) { f.r.snapshot.State.GetAgent().Tombstoned = true }, Relay},
		{"membership", func(f *fixture) { f.r.snapshot.State.GetAgent().DelegationAdmissions = nil }, Relay},
		{"withdrawn", func(f *fixture) { f.r.snapshot.State.GetAgent().DelegationAdmissions[0].Withdrawn = true }, Relay},
		{"current-epoch", func(f *fixture) {
			*f.r.snapshot.CurrentEpoch = 2
			f.r.snapshot.State.GetAgent().AuthorizationEpoch = 2
		}, Relay},
		{"admission-epoch", func(f *fixture) {
			for key := range f.r.snapshot.AdmissionEpochs {
				f.r.snapshot.AdmissionEpochs[key] = 2
			}
		}, Relay},
		{"missing-admission", func(f *fixture) { f.r.snapshot.AdmissionEpochs = nil }, Relay},
		{"missing-current", func(f *fixture) { f.r.snapshot.CurrentEpoch = nil }, Relay},
		{"mixed-checkpoints", func(f *fixture) { f.r.snapshot.EpochCheckpoint = 11 }, Relay},
		{"policy", func(f *fixture) { f.d.PolicyHash[0] ^= 1; f.reencode(t) }, Relay},
		{"not-before", func(f *fixture) { f.clock.at = time.Unix(int64(f.d.NotBefore)-301, 0) }, Relay},
		{"expired", func(f *fixture) { f.clock.at = time.Unix(int64(f.d.NotAfter), 0) }, Relay},
		{"purpose", func(f *fixture) { f.d.Purposes = Hints; f.reencode(t) }, Relay},
		{"unknown-purpose", func(*fixture) {}, Purpose(3)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			verify(t, f.verifier(t), f.wire, Relay, true)
			f = newFixture(t)
			tc.mutate(f)
			verify(t, f.verifier(t), f.wire, tc.purpose, false)
		})
	}
}

func TestCacheBounds(t *testing.T) {
	f := newFixture(t)
	v := f.verifier(t)
	verify(t, v, f.wire, Relay, true)
	f.clock.advance(299 * time.Second)
	verify(t, v, f.wire, Relay, true)
	if f.r.calls != 1 {
		t.Fatal("refreshed too early")
	}
	f.clock.advance(time.Second)
	verify(t, v, f.wire, Relay, true)
	if f.r.calls != 2 {
		t.Fatal("did not refresh at 300 seconds")
	}
	f.r.err = ErrUnavailable
	f.clock.advance(599 * time.Second)
	verify(t, v, f.wire, Relay, true)
	f.clock.advance(time.Second)
	verify(t, v, f.wire, Relay, false)
	if len(v.passes) != 0 {
		t.Fatal("expired pass retained")
	}
}
func TestFallbackNeverHidesRevocationOrIntegrity(t *testing.T) {
	for _, integrity := range []bool{false, true} {
		f := newFixture(t)
		v := f.verifier(t)
		verify(t, v, f.wire, Relay, true)
		f.clock.advance(300 * time.Second)
		if integrity {
			f.r.err = errors.New("invalid proof")
		} else {
			f.r.snapshot.State.GetAgent().DelegationAdmissions = nil
		}
		verify(t, v, f.wire, Relay, false)
		f.r.err = ErrUnavailable
		verify(t, v, f.wire, Relay, false)
	}
	f := newFixture(t)
	f.r.err = ErrUnavailable
	verify(t, f.verifier(t), f.wire, Relay, false)
}
func TestTimeAndPurposeAreNotCached(t *testing.T) {
	f := newFixture(t)
	f.d.Purposes = Relay
	f.d.NotAfter = f.d.NotBefore + 20
	f.reencode(t)
	v := f.verifier(t)
	verify(t, v, f.wire, Relay, true)
	verify(t, v, f.wire, Hints, false)
	f.clock.advance(10 * time.Second)
	verify(t, v, f.wire, Relay, false)
	f = newFixture(t)
	f.r.after = func() { f.clock.advance(time.Hour) }
	verify(t, f.verifier(t), f.wire, Relay, false)
}
func TestCacheCapacityAndClockRollback(t *testing.T) {
	f := newFixture(t)
	f.c.CacheEntries = 1
	v := f.verifier(t)
	first := append([]byte(nil), f.wire...)
	firstDigest := sha256.Sum256(first)
	f.d.NotAfter++
	f.reencode(t)
	f.r.snapshot.AdmissionEpochs[firstDigest] = f.d.AuthorizationEpoch
	agent := f.r.snapshot.State.GetAgent()
	agent.DelegationAdmissions = append(agent.DelegationAdmissions, &nativev1.DelegationAdmissionV1{
		Digest: "sha256:" + hex.EncodeToString(firstDigest[:]), AdmissionEpoch: f.d.AuthorizationEpoch,
	})
	verify(t, v, first, Relay, true)
	verify(t, v, f.wire, Relay, true)
	if len(v.passes) != 1 {
		t.Fatal("unbounded cache")
	}
	f.clock.advance(-time.Second)
	verify(t, v, f.wire, Relay, false)
	if len(v.passes) != 0 {
		t.Fatal("rollback retained passes")
	}
}
func TestEpochZeroRefused(t *testing.T) {
	f := newFixture(t)
	f.d.AuthorizationEpoch = 0
	f.reencode(t)
	verify(t, f.verifier(t), f.wire, Relay, false)
}

func TestBuilderRequiresCurrentEpochAndPolicy(t *testing.T) {
	f := newFixture(t)
	v := f.verifier(t)
	// A builder checks before commitment, so there is intentionally no membership.
	f.r.snapshot.State.GetAgent().DelegationAdmissions = nil
	if _, err := v.BuildDelegation(context.Background(), f.d); err != nil {
		t.Fatal(err)
	}
	f.d.AuthorizationEpoch = 2
	if _, err := v.BuildDelegation(context.Background(), f.d); err == nil {
		t.Fatal("built future epoch")
	}
	f.d.AuthorizationEpoch = 1
	f.d.PolicyHash[0] ^= 1
	if _, err := v.BuildDelegation(context.Background(), f.d); err == nil {
		t.Fatal("built another policy")
	}
}
func TestPolicyCyclesNeverResurrectOldEpoch(t *testing.T) {
	f := newFixture(t)
	v := f.verifier(t)
	verify(t, v, f.wire, Relay, true)
	original := proto.Clone(f.r.snapshot.State.GetAgent().Policy).(*nativev1.ControllerPolicyV1)
	f.r.snapshot.State.GetAgent().Policy.RecoveryTimelockSeconds = 60
	*f.r.snapshot.CurrentEpoch = 2
	f.r.snapshot.State.GetAgent().AuthorizationEpoch = 2
	f.clock.advance(300 * time.Second)
	verify(t, v, f.wire, Relay, false)
	f.r.snapshot.State.GetAgent().Policy = original
	*f.r.snapshot.CurrentEpoch = 3
	f.r.snapshot.State.GetAgent().AuthorizationEpoch = 3
	verify(t, v, f.wire, Relay, false)
	// Installing identical bytes still advances the epoch.
	*f.r.snapshot.CurrentEpoch = 4
	f.r.snapshot.State.GetAgent().AuthorizationEpoch = 4
	verify(t, v, f.wire, Relay, false)
	// Admitting a future-encoded digest early does not authorize that epoch.
	f.d.AuthorizationEpoch = 5
	f.reencode(t)
	for key := range f.r.snapshot.AdmissionEpochs {
		f.r.snapshot.AdmissionEpochs[key] = 4
	}
	verify(t, v, f.wire, Relay, false)
	*f.r.snapshot.CurrentEpoch = 5
	f.r.snapshot.State.GetAgent().AuthorizationEpoch = 5
	verify(t, v, f.wire, Relay, false)
}

func TestWindowBoundaries(t *testing.T) {
	f := newFixture(t)
	f.clock.at = time.Unix(int64(f.d.NotBefore)-300, 0)
	v := f.verifier(t)
	for _, purpose := range []Purpose{Relay, Hints, Direct} {
		verify(t, v, f.wire, purpose, true)
	}
	f.clock.at = time.Unix(int64(f.d.NotAfter)-1, 0)
	verify(t, v, f.wire, Relay, true)
	f.clock.at = time.Unix(int64(f.d.NotAfter), 0)
	verify(t, v, f.wire, Relay, false)
}
func TestConfigurationBounds(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.CacheEntries = -1 }, func(c *Config) { c.CacheEntries = MaxCacheEntries + 1 },
		func(c *Config) { c.ReadTimeout = -time.Second }, func(c *Config) { c.ReadTimeout = 31 * time.Second },
		func(c *Config) { c.Network = nil }, func(c *Config) { c.ChainPolicy.Locator = nil },
	} {
		f := newFixture(t)
		change(&f.c)
		if _, err := NewVerifier(f.c, f.r); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	f := newFixture(t)
	f.c.Clock = nil
	v := f.verifier(t)
	if _, ok := v.config.Clock.(systemClock); !ok {
		t.Fatal("no real clock by default")
	}
	if _, err := NewVerifier(f.c, nil); err == nil {
		t.Fatal("no resolver")
	}
}

type legacySource struct {
	state *nativev1.NativeStateV1
	found bool
	err   error
}

func (s legacySource) ResolveState(context.Context, string, string) (*nativev1.NativeStateV1, bool, error) {
	return s.state, s.found, s.err
}
func TestRegistryAdapterUsesOneFinalizedState(t *testing.T) {
	f := newFixture(t)
	state := f.r.snapshot.State
	state.Reference.ContractCodeHash = nativecore.RegistryV2CodeHash
	source := legacySource{state: state, found: true}
	adapter, err := NewRegistryResolver(f.c.Network, source)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := adapter.ResolveFinalizedAgent(context.Background(), f.d.AgentID())
	if err != nil || !proto.Equal(snapshot.State, state) || snapshot.CurrentEpoch == nil ||
		*snapshot.CurrentEpoch != 1 || len(snapshot.AdmissionEpochs) != 1 || snapshot.EpochCheckpoint != 10 {
		t.Fatalf("inconsistent finalized snapshot: %+v, %v", snapshot, err)
	}
	state.GetAgent().EncodingVersion = 1
	if _, err := adapter.ResolveFinalizedAgent(context.Background(), f.d.AgentID()); err == nil {
		t.Fatal("schema 1 accepted")
	}
}

func TestCancelledRequestNeverUsesAPass(t *testing.T) {
	f := newFixture(t)
	v := f.verifier(t)
	verify(t, v, f.wire, Relay, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.VerifyDelegation(ctx, f.wire, Relay); err == nil {
		t.Fatal("cancelled request accepted")
	}
}

func TestWithdrawalAndReadmissionAreScopedByEpoch(t *testing.T) {
	f := newFixture(t)
	v := f.verifier(t)
	verify(t, v, f.wire, Relay, true)
	old := append([]byte{}, f.wire...)
	oldDigest := sha256.Sum256(old)
	f.d.NotAfter++
	f.reencode(t)
	sibling := append([]byte{}, f.wire...)
	// Withdrawing the first digest does not revoke its sibling in this epoch.
	f.clock.advance(300 * time.Second)
	verify(t, v, old, Relay, false)
	verify(t, v, sibling, Relay, true)
	// A new admission after an epoch bump cannot revive bytes encoding epoch 1.
	*f.r.snapshot.CurrentEpoch = 2
	f.r.snapshot.State.GetAgent().AuthorizationEpoch = 2
	f.r.snapshot.State.GetAgent().DelegationAdmissions = []*nativev1.DelegationAdmissionV1{{Digest: "sha256:" + hex.EncodeToString(oldDigest[:]), AdmissionEpoch: 2}}
	f.r.snapshot.AdmissionEpochs = map[[32]byte]uint64{oldDigest: 2}
	verify(t, v, old, Relay, false)
	// A future-encoded digest admitted now is not valid in the next epoch under
	// its earlier admission. Only a deliberate new admission can authorize it.
	f.d.AuthorizationEpoch = 3
	f.reencode(t)
	digest := sha256.Sum256(f.wire)
	f.r.snapshot.AdmissionEpochs[digest] = 2
	verify(t, v, f.wire, Relay, false)
	*f.r.snapshot.CurrentEpoch = 3
	f.r.snapshot.State.GetAgent().AuthorizationEpoch = 3
	verify(t, v, f.wire, Relay, false)
	f.r.snapshot.AdmissionEpochs[digest] = 3
	verify(t, v, f.wire, Relay, true)
}
func TestFinalizedSetBounds(t *testing.T) {
	f := newFixture(t)
	f.r.snapshot.State.GetAgent().DelegationAdmissions = append(f.r.snapshot.State.GetAgent().DelegationAdmissions, make([]*nativev1.DelegationAdmissionV1, 384)...)
	verify(t, f.verifier(t), f.wire, Relay, false)
	f = newFixture(t)
	for i := range 129 {
		var digest [32]byte
		digest[0] = byte(i)
		f.r.snapshot.AdmissionEpochs[digest] = 1
	}
	verify(t, f.verifier(t), f.wire, Relay, false)
}

func TestTimeArithmeticDoesNotWrap(t *testing.T) {
	f := newFixture(t)
	f.d.NotBefore = ^uint64(0) - 10
	f.d.NotAfter = ^uint64(0)
	f.reencode(t)
	verify(t, f.verifier(t), f.wire, Relay, false)
	f = newFixture(t)
	f.clock.at = time.Unix(-1, 0)
	verify(t, f.verifier(t), f.wire, Relay, false)
}

// signalledContext exposes entry to the wait without an ordering sleep.
type signalledContext struct {
	context.Context
	entered chan struct{}
}

func (c signalledContext) Done() <-chan struct{} {
	select {
	case c.entered <- struct{}{}:
	default:
	}
	return c.Context.Done()
}
func TestCancellationInterruptsTheSerializationWait(t *testing.T) {
	f := newFixture(t)
	v := f.verifier(t)
	v.gate <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, 1)
	finished := make(chan error, 1)
	go func() {
		_, err := v.VerifyDelegation(signalledContext{Context: ctx, entered: entered}, f.wire, Relay)
		finished <- err
	}()
	<-entered
	cancel()
	if err := <-finished; err == nil {
		t.Fatal("cancelled wait passed")
	}
	if f.r.calls != 0 {
		t.Fatal("cancelled waiter performed a read")
	}
	<-v.gate
	verify(t, v, f.wire, Relay, true)
}

func TestTimeAfterReadAtExpiration(t *testing.T) {
	f := newFixture(t)
	f.clock.at = time.Unix(int64(f.d.NotAfter)-1, 0)
	f.r.after = func() { f.clock.advance(time.Second) }
	verify(t, f.verifier(t), f.wire, Relay, false)
}

func TestRegistryReaderUsesTheOriginalNetworkBeforeNormalization(t *testing.T) {
	f := newFixture(t)
	original := f.r.snapshot.State
	original.Network.GenesisRootHash = "sha256:" + original.Network.GenesisRootHash
	original.Network.GenesisFileHash = "sha256:" + original.Network.GenesisFileHash
	original.Reference.ContractCodeHash = nativecore.RegistryV2CodeHash
	source := legacySource{state: original, found: true}
	adapter, err := NewRegistryResolver(f.c.Network, &source)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(f.c, adapter)
	if err != nil {
		t.Fatal(err)
	}
	verify(t, v, f.wire, Relay, true)
	if original.Network.GenesisRootHash == f.c.Network.GenesisRootHash {
		t.Fatal("mutated the reader's snapshot")
	}
	// A mismatched original tuple must not be laundered by normalization.
	original.Network.GenesisRootHash = "sha256:" + strings.Repeat("a", 64)
	f.clock.advance(300 * time.Second)
	verify(t, v, f.wire, Relay, false)
	source.err = ErrUnavailable
	verify(t, v, f.wire, Relay, false)
}

func BenchmarkVerifyCached(b *testing.B) {
	f := newFixture(b)
	v := f.verifier(b)
	if _, err := v.VerifyDelegation(context.Background(), f.wire, Relay); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := v.VerifyDelegation(context.Background(), f.wire, Relay); err != nil {
			b.Fatal(err)
		}
	}
}

func TestTransportRefusesMixedRegistryRelease(t *testing.T) {
	f := newFixture(t)
	f.c.ChainPolicy.RegistryCodeHashes = append(f.c.ChainPolicy.RegistryCodeHashes, "tvm-cell-sha256:"+strings.Repeat("8", 64))
	if _, err := NewVerifier(f.c, f.r); err == nil {
		t.Fatal("mixed Registry releases accepted")
	}
}

func TestNewFinalizedObservationInvalidatesSiblingPass(t *testing.T) {
	for _, change := range []string{"epoch", "withdrawal", "tombstone"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			v := f.verifier(t)
			old := append([]byte(nil), f.wire...)
			oldDigest := sha256.Sum256(old)
			verify(t, v, old, Relay, true)
			f.d.Purposes = Relay
			state := f.r.snapshot.State
			agent := state.GetAgent()
			state.TvmStateHash = "tvm-cell-sha256:" + strings.Repeat("e", 64)
			state.Reference.FinalizedCheckpoint++
			f.r.snapshot.EpochCheckpoint++
			if change == "epoch" {
				f.d.AuthorizationEpoch++
				agent.AuthorizationEpoch = f.d.AuthorizationEpoch
				*f.r.snapshot.CurrentEpoch = f.d.AuthorizationEpoch
			}
			f.reencode(t)
			if change == "withdrawal" {
				agent.DelegationAdmissions = append(agent.DelegationAdmissions, &nativev1.DelegationAdmissionV1{
					Digest: "sha256:" + hex.EncodeToString(oldDigest[:]), AdmissionEpoch: agent.AuthorizationEpoch, Withdrawn: true,
				})
			}
			agent.Tombstoned = change == "tombstone"
			verify(t, v, f.wire, Relay, change != "tombstone")
			verify(t, v, old, Relay, false)
		})
	}
}

func TestPresenceAndTombstoneAreDistinctFromReadFailure(t *testing.T) {
	f := newFixture(t)
	adapter, err := NewRegistryResolver(f.c.Network, legacySource{found: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = adapter.ResolveFinalizedAgent(t.Context(), f.d.AgentID()); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatal("nil present state treated as absence/outage", err)
	}
	for _, kind := range []string{"absent", "tombstone", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			switch kind {
			case "absent":
				f.r.snapshot.State = nil
			case "tombstone":
				f.r.snapshot.State.GetAgent().Tombstoned = true
			case "malformed":
				f.r.snapshot.State.GetAgent().Policy = nil
			}
			_, err := f.verifier(t).VerifyDelegation(t.Context(), f.wire, Relay)
			if err == nil || errors.Is(err, ErrDelegationRevoked) != (kind != "malformed") {
				t.Fatal(kind, err)
			}
		})
	}
}

func TestVerificationDeadlineStaysAtTheOriginalRead(t *testing.T) {
	f := newFixture(t)
	v := f.verifier(t)
	base := f.clock.Now()
	_, until, err := v.VerifyDelegationUntil(t.Context(), f.wire, Relay)
	if err != nil || !until.Equal(base.Add(RefuseAfter)) {
		t.Fatal(until, err)
	}
	f.clock.advance(299 * time.Second)
	_, cached, err := v.VerifyDelegationUntil(t.Context(), f.wire, Relay)
	if err != nil || !cached.Equal(until) || f.r.calls != 1 {
		t.Fatal(cached, err, f.r.calls)
	}
	f.r.err = ErrUnavailable
	f.clock.advance(300 * time.Second)
	_, stale, err := v.VerifyDelegationUntil(t.Context(), f.wire, Relay)
	if err != nil || !stale.Equal(until) {
		t.Fatal(stale, err)
	}
	f.clock.advance(time.Second)
	if _, _, err = v.VerifyDelegationUntil(t.Context(), f.wire, Relay); !errors.Is(err, ErrUnavailable) {
		t.Fatal("stale boundary accepted", err)
	}
	f.r.err = nil
	readAt := f.clock.Now()
	f.r.after = func() { f.clock.advance(2 * time.Second) }
	_, fresh, err := v.VerifyDelegationUntil(t.Context(), f.wire, Relay)
	if err != nil || !fresh.Equal(readAt.Add(RefuseAfter)) {
		t.Fatal(fresh, err)
	}
}

func TestBuilderRefusesFutureRegistryEpoch(t *testing.T) {
	f := newFixture(t)
	f.d.AuthorizationEpoch++
	if _, err := f.verifier(t).BuildDelegation(t.Context(), f.d); err == nil {
		t.Fatal("builder accepted a future authorization epoch")
	}
}
