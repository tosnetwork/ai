package directory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

const (
	relayDeviceOne = "dev_" + "4444444444444444444444444444444444444444444444444444444444444444"
	relayDeviceTwo = "dev_" + "5555555555555555555555555555555555555555555555555555555555555555"
	relayLocal     = "agent_" + "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

type relayFixture struct {
	t          *testing.T
	key        []byte
	delegation identity.Delegation
	resolver   stubResolver
	journal    *eventlog.Journal
	devices    *eventlog.DeviceLedger
	verifier   RelayVerifier
	root       string
}

func newRelayFixture(t *testing.T) *relayFixture {
	t.Helper()
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	root := filepath.Join(t.TempDir(), "state")
	journal, err := eventlog.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	devices, err := journal.OpenDevices()
	if err != nil {
		t.Fatal(err)
	}
	resolver := liveResolver(t, delegation)
	return &relayFixture{t: t, key: key, delegation: delegation, resolver: resolver, journal: journal,
		devices: devices, root: root,
		verifier: RelayVerifier{Resolver: resolver, Network: testNetwork(), Chain: testChain(),
			Judge: devices, Admitter: devices, Store: journal, LocalAgentID: relayLocal}}
}

// evidence builds one relay evidence for the fixture's Agent: one device,
// a descriptor issued at issued and valid for lifetime seconds.
func (f *relayFixture) evidence(deviceID, material string, issued, lifetime uint64, mutate func(*Descriptor)) []byte {
	f.t.Helper()
	key := endpointKey(f.t, 0x11)
	bundle, err := e2ee.SignBundle(e2ee.Bundle{Network: f.delegation.Network, AgentID: f.delegation.AgentID,
		EndpointID: f.delegation.EndpointID, DeviceID: deviceID, AlgorithmID: e2ee.DefaultCandidateAlgorithmID,
		Material: []byte(material), IssuedAtUnix: issued, ExpiresAtUnix: issued + lifetime}, key)
	if err != nil {
		f.t.Fatal(err)
	}
	set, err := e2ee.EncodeBundleSetJSON([]e2ee.Bundle{bundle})
	if err != nil {
		f.t.Fatal(err)
	}
	setDigest, err := e2ee.SetDigest([]e2ee.Bundle{bundle})
	if err != nil {
		f.t.Fatal(err)
	}
	descriptor := testDescriptor(f.t, f.delegation)
	descriptor.PrekeyBundleDigest = setDigest
	// A relay-only descriptor's route is the delegation's ADNL identity.
	descriptor.HTTPSEndpoint = ""
	descriptor.IssuedAtUnix = issued
	descriptor.ExpiresAtUnix = issued + lifetime
	if mutate != nil {
		mutate(&descriptor)
	}
	descriptor, err = SignDescriptor(descriptor, key)
	if err != nil {
		f.t.Fatal(err)
	}
	descriptorJSON, err := EncodeDescriptorJSON(descriptor)
	if err != nil {
		f.t.Fatal(err)
	}
	delegationJSON, err := identity.EncodeJSON(f.delegation)
	if err != nil {
		f.t.Fatal(err)
	}
	policyJSON, err := EncodeDescriptorPolicyJSON(testPolicy())
	if err != nil {
		f.t.Fatal(err)
	}
	raw, err := relayframe.EncodeEvidence(relayframe.Evidence{Delegation: delegationJSON, Policy: policyJSON,
		Descriptor: descriptorJSON, BundleSet: set})
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *relayFixture) pin(deviceID string) Pin {
	return Pin{EndpointID: f.delegation.EndpointID, DeviceID: deviceID}
}

// snapshot hashes every file under the journal root, so a test can prove a
// call wrote nothing durable.
func (f *relayFixture) snapshot() string {
	f.t.Helper()
	var lines []string
	err := filepath.WalkDir(f.root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			lines = append(lines, "dir "+path)
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		lines = append(lines, path+" "+hex.EncodeToString(sum[:]))
		return nil
	})
	if err != nil {
		f.t.Fatal(err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func at(seconds uint64) time.Time { return time.Unix(int64(seconds), 0) }

func requireCode(t *testing.T, err error, code fault.Code) {
	t.Helper()
	if err == nil || fault.CodeOf(err) != code {
		t.Fatalf("error=%v want code %s", err, code)
	}
}

func TestCheckPeerAcceptsCurrentLocatorFreeEvidence(t *testing.T) {
	f := newRelayFixture(t)
	raw := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, nil)
	peer, err := f.verifier.CheckPeer(agentID, raw, f.pin(relayDeviceOne), at(baseUnix+200))
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if peer.AgentID != agentID || peer.Delegation.EndpointID != f.delegation.EndpointID ||
		len(peer.Bundles) != 1 || peer.Bundles[0].DeviceID != relayDeviceOne || !bytes.Equal(peer.Evidence, raw) ||
		peer.FinalizedCheckpoint != 100 {
		t.Fatalf("peer=%+v", peer)
	}
}

func TestCheckPeerOfAStrangerWritesNothing(t *testing.T) {
	f := newRelayFixture(t)
	before := f.snapshot()
	raw := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, nil)
	if _, err := f.verifier.CheckPeer(agentID, raw, f.pin(relayDeviceOne), at(baseUnix+200)); err != nil {
		t.Fatalf("check: %v", err)
	}
	if _, found, err := f.devices.Record(f.delegation.EndpointID); err != nil || found {
		t.Fatalf("a stranger's set reached the rollback boundary: found=%v err=%v", found, err)
	}
	if admitted, err := f.verifier.Admitted(agentID); err != nil || admitted {
		t.Fatalf("a stranger was admitted: %v %v", admitted, err)
	}
	if after := f.snapshot(); after != before {
		t.Fatalf("CheckPeer wrote durable state:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	// With a boundary on record, a newer stranger set is judged but the
	// recorded set does not move.
	committed := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, nil)
	peer, err := f.verifier.CheckContact(agentID, committed, at(baseUnix+200))
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := f.verifier.CommitPeer(peer, at(baseUnix+200)); err != nil || !fresh {
		t.Fatalf("commit: %v %v", fresh, err)
	}
	record, _, err := f.devices.Record(f.delegation.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	before = f.snapshot()
	newer := f.evidence(relayDeviceTwo, "material two", baseUnix+300, 3600, nil)
	if _, err := f.verifier.CheckPeer(agentID, newer, f.pin(relayDeviceTwo), at(baseUnix+400)); err != nil {
		t.Fatalf("check newer: %v", err)
	}
	if after := f.snapshot(); after != before {
		t.Fatal("CheckPeer of a newer set moved the rollback boundary")
	}
	unchanged, _, err := f.devices.Record(f.delegation.EndpointID)
	if err != nil || unchanged.SetDigest != record.SetDigest || len(unchanged.Tombstones) != 0 {
		t.Fatalf("rollback boundary changed: %+v -> %+v (%v)", record, unchanged, err)
	}
}

func TestCommitPeerWritesOnlyNewerEvidence(t *testing.T) {
	f := newRelayFixture(t)
	first := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, nil)
	peer, err := f.verifier.CheckContact(agentID, first, at(baseUnix+200))
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := f.verifier.CommitPeer(peer, at(baseUnix+200)); err != nil || !fresh {
		t.Fatalf("first commit: %v %v", fresh, err)
	}
	// Identical evidence is not newer.
	before := f.snapshot()
	if fresh, err := f.verifier.CommitPeer(peer, at(baseUnix+210)); err != nil || fresh {
		t.Fatalf("identical commit: %v %v", fresh, err)
	}
	// A different descriptor at the same issue time is not newer either.
	sameMoment := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, func(d *Descriptor) {
		d.MaximumEnvelopeBytes = 32 << 10
	})
	other, err := f.verifier.CheckPeer(agentID, sameMoment, f.pin(relayDeviceOne), at(baseUnix+220))
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := f.verifier.CommitPeer(other, at(baseUnix+220)); err != nil || fresh {
		t.Fatalf("same-moment commit: %v %v", fresh, err)
	}
	if after := f.snapshot(); after != before {
		t.Fatal("a commit of evidence that is not newer wrote durable state")
	}
	// Newer evidence is stored and admitted to the boundary.
	newer := f.evidence(relayDeviceOne, "material renewed", baseUnix+300, 3600, nil)
	renewed, err := f.verifier.CheckPeer(agentID, newer, f.pin(relayDeviceOne), at(baseUnix+400))
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := f.verifier.CommitPeer(renewed, at(baseUnix+400)); err != nil || !fresh {
		t.Fatalf("newer commit: %v %v", fresh, err)
	}
	stored, found, err := f.journal.LoadRelayEvidence(agentID)
	if err != nil || !found || !bytes.Equal(stored, newer) {
		t.Fatalf("stored evidence is not the newer one: found=%v err=%v", found, err)
	}
	// The older evidence is now a rollback and fails CheckPeer.
	_, err = f.verifier.CheckPeer(agentID, first, f.pin(relayDeviceOne), at(baseUnix+500))
	requireCode(t, err, fault.CodeDescriptorExpired)
	if !errors.Is(err, e2ee.ErrSetRollback) {
		t.Fatalf("older evidence was not judged a rollback: %v", err)
	}
}

func TestCheckPeerFailsOnceTheDeviceIsRevoked(t *testing.T) {
	f := newRelayFixture(t)
	first := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, nil)
	peer, err := f.verifier.CheckContact(agentID, first, at(baseUnix+200))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.verifier.CommitPeer(peer, at(baseUnix+200)); err != nil {
		t.Fatal(err)
	}
	// A newer descriptor whose set no longer holds the pinned device.
	replaced := f.evidence(relayDeviceTwo, "material two", baseUnix+300, 3600, nil)
	_, err = f.verifier.CheckPeer(agentID, replaced, f.pin(relayDeviceOne), at(baseUnix+400))
	requireCode(t, err, fault.CodeDeviceRevoked)
	next, err := f.verifier.CheckContact(agentID, replaced, at(baseUnix+400))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.verifier.CommitPeer(next, at(baseUnix+400)); err != nil {
		t.Fatal(err)
	}
	// The stored evidence now fails for the old device's session pin.
	_, err = f.verifier.CheckStored(agentID, f.pin(relayDeviceOne), at(baseUnix+500))
	requireCode(t, err, fault.CodeDeviceRevoked)
}

func TestCheckPeerFailsAtOnceOnEndpointRevocation(t *testing.T) {
	f := newRelayFixture(t)
	raw := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, nil)
	if _, err := f.verifier.CheckPeer(agentID, raw, f.pin(relayDeviceOne), at(baseUnix+200)); err != nil {
		t.Fatal(err)
	}
	// The Agent withdraws the Endpoint delegation in finalized state.
	f.resolver.states[agentID].GetAgent().DelegationDigests = []string{"sha256:" + strings.Repeat("9", 64)}
	_, err := f.verifier.CheckPeer(agentID, raw, f.pin(relayDeviceOne), at(baseUnix+201))
	requireCode(t, err, fault.CodeDelegationUncommitted)
	// A tombstoned Agent fails the same way, and an unreadable finalized
	// state is a local failure to retry, not a verdict on the peer.
	f.resolver.states[agentID].GetAgent().Tombstoned = true
	_, err = f.verifier.CheckPeer(agentID, raw, f.pin(relayDeviceOne), at(baseUnix+202))
	requireCode(t, err, fault.CodeDelegationUncommitted)
	failing := f.verifier
	failing.Resolver = failingResolver{}
	_, err = failing.CheckPeer(agentID, raw, f.pin(relayDeviceOne), at(baseUnix+203))
	requireCode(t, err, fault.CodeInternal)
}

type failingResolver struct{}

func (failingResolver) ResolveAgent(string) (*nativev1.NativeStateV1, bool, error) {
	return nil, false, errors.New("finalized state unavailable")
}

func TestCheckPeerRefusesExpiredEvidence(t *testing.T) {
	f := newRelayFixture(t)
	raw := f.evidence(relayDeviceOne, "material one", baseUnix+100, 600, nil)
	_, err := f.verifier.CheckPeer(agentID, raw, f.pin(relayDeviceOne), at(baseUnix+700))
	requireCode(t, err, fault.CodeDescriptorExpired)
	_, err = f.verifier.CheckPeer(agentID, raw, f.pin(relayDeviceOne), at(baseUnix+86_400))
	requireCode(t, err, fault.CodeDelegationExpired)
	// No stored evidence is the same remedy: fresher evidence is needed.
	_, err = f.verifier.CheckStored(agentID, f.pin(relayDeviceOne), at(baseUnix+200))
	requireCode(t, err, fault.CodeDescriptorExpired)
	if !errors.Is(err, ErrRelayEvidenceUnknown) {
		t.Fatalf("missing evidence error=%v", err)
	}
}

func TestCheckPeerRefusesMalformedOversizedAndMisdirectedEvidence(t *testing.T) {
	f := newRelayFixture(t)
	raw := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, nil)
	now := at(baseUnix + 200)
	cases := []struct {
		name     string
		peer     string
		evidence []byte
		pin      Pin
		code     fault.Code
	}{
		{"empty", agentID, nil, f.pin(relayDeviceOne), fault.CodePayloadMalformed},
		{"oversized", agentID, make([]byte, relayframe.MaxEvidenceBytes+1), f.pin(relayDeviceOne), fault.CodeOversized},
		{"truncated", agentID, raw[:len(raw)-1], f.pin(relayDeviceOne), fault.CodePayloadMalformed},
		{"other Agent", otherAgentID, raw, f.pin(relayDeviceOne), fault.CodeSenderMismatch},
		{"self", relayLocal, raw, f.pin(relayDeviceOne), fault.CodeSenderMismatch},
		{"invalid Agent", "agent_x", raw, f.pin(relayDeviceOne), fault.CodeSenderMismatch},
		{"other Endpoint", agentID, raw, Pin{EndpointID: "mep_" + strings.Repeat("1", 64), DeviceID: relayDeviceOne},
			fault.CodeSenderMismatch},
		{"absent device", agentID, raw, f.pin(relayDeviceTwo), fault.CodeDeviceRevoked},
		{"empty pin", agentID, raw, Pin{}, fault.CodeInternal},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := f.verifier.CheckPeer(test.peer, test.evidence, test.pin, now)
			requireCode(t, err, test.code)
		})
	}
	_, err := f.verifier.CheckPeer(agentID, make([]byte, relayframe.MaxEvidenceBytes+1), f.pin(relayDeviceOne), now)
	if !errors.Is(err, relayframe.ErrRelayEvidenceTooLarge) {
		t.Fatalf("oversized evidence error=%v", err)
	}
	decoded, err := relayframe.DecodeEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	spaced := decoded
	spaced.Descriptor = append([]byte(" "), decoded.Descriptor...)
	if encoded, err := relayframe.EncodeEvidence(spaced); err != nil {
		t.Fatal(err)
	} else {
		_, err = f.verifier.CheckPeer(agentID, encoded, f.pin(relayDeviceOne), now)
		requireCode(t, err, fault.CodeDescriptorUnbound)
	}
	otherPolicy := decoded
	otherPolicy.Policy, _ = EncodeDescriptorPolicyJSON(DescriptorPolicy{MaxEnvelopeBytes: 64 << 10,
		MaxLifetimeSeconds: 3600, AllowHTTPSEndpoint: true})
	if encoded, err := relayframe.EncodeEvidence(otherPolicy); err != nil {
		t.Fatal(err)
	} else {
		_, err = f.verifier.CheckPeer(agentID, encoded, f.pin(relayDeviceOne), now)
		requireCode(t, err, fault.CodeDescriptorUnbound)
	}
}

func TestNewerEvidenceNeedsADifferentDigestAndALaterIssueTime(t *testing.T) {
	a, b := "sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64)
	for _, test := range []struct {
		candidateDigest string
		candidateIssued uint64
		currentDigest   string
		currentIssued   uint64
		newer           bool
	}{
		{b, 11, a, 10, true},
		{a, 11, a, 10, false},
		{b, 10, a, 10, false},
		{b, 9, a, 10, false},
		{a, 10, a, 10, false},
	} {
		if got := NewerEvidence(test.candidateDigest, test.candidateIssued, test.currentDigest, test.currentIssued); got != test.newer {
			t.Fatalf("%+v: newer=%v", test, got)
		}
	}
}

func TestRelayEvidenceSinkKeepsIssueTimesStrictlyIncreasing(t *testing.T) {
	f := newRelayFixture(t)
	dir := filepath.Join(t.TempDir(), "export")
	card := filepath.Join(t.TempDir(), "card.json")
	if err := os.WriteFile(card, []byte(`{"card":"opaque"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	delegationJSON, err := identity.EncodeJSON(f.delegation)
	if err != nil {
		t.Fatal(err)
	}
	sink, err := NewRelayEvidenceSink(dir, card, delegationJSON, testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, found, err := sink.LastRelayDescriptor(); err != nil || found {
		t.Fatalf("fresh sink: found=%v err=%v", found, err)
	}
	put := func(raw []byte) error {
		decoded, err := relayframe.DecodeEvidence(raw)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, err := DecodeDescriptorJSON(decoded.Descriptor)
		if err != nil {
			t.Fatal(err)
		}
		return sink.PutRelayEvidence(descriptor, decoded.Descriptor, decoded.BundleSet)
	}
	first := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, nil)
	if err := put(first); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := put(first); err != nil {
		t.Fatalf("identical evidence must be a no-op: %v", err)
	}
	sameMoment := f.evidence(relayDeviceOne, "material other", baseUnix+100, 3600, nil)
	if err := put(sameMoment); err == nil {
		t.Fatal("evidence at the same issue time replaced the published one")
	}
	if err := put(f.evidence(relayDeviceOne, "material older", baseUnix+50, 3600, nil)); err == nil {
		t.Fatal("older evidence replaced the published one")
	}
	newer := f.evidence(relayDeviceOne, "material newer", baseUnix+200, 3600, nil)
	if err := put(newer); err != nil {
		t.Fatalf("newer: %v", err)
	}
	current, _, issued, err := sink.Current()
	if err != nil || !bytes.Equal(current, newer) || issued != baseUnix+200 {
		t.Fatalf("current evidence: issued=%d err=%v", issued, err)
	}
	contactRaw, err := os.ReadFile(filepath.Join(dir, RelayContactFile))
	if err != nil {
		t.Fatal(err)
	}
	contact, err := relayframe.DecodeContactJSON(contactRaw)
	if err != nil || contact.AgentID != agentID || !bytes.Equal(contact.Evidence, newer) ||
		string(contact.Card) != `{"card":"opaque"}` {
		t.Fatalf("contact export: %+v %v", contact, err)
	}
	// A restarted sink keeps the invariant against what it exported.
	restarted, err := NewRelayEvidenceSink(dir, card, delegationJSON, testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, issued, found, err := restarted.LastRelayDescriptor(); err != nil || !found || issued != baseUnix+200 {
		t.Fatalf("restarted sink: issued=%d found=%v err=%v", issued, found, err)
	}
	decoded, _ := relayframe.DecodeEvidence(first)
	descriptor, _ := DecodeDescriptorJSON(decoded.Descriptor)
	if err := restarted.PutRelayEvidence(descriptor, decoded.Descriptor, decoded.BundleSet); err == nil {
		t.Fatal("a restarted sink accepted older evidence")
	}
	// The sink refuses a policy its delegation does not commit.
	if _, err := NewRelayEvidenceSink(dir, card, delegationJSON, DescriptorPolicy{MaxEnvelopeBytes: 64 << 10,
		MaxLifetimeSeconds: 3600, AllowHTTPSEndpoint: true}); err == nil {
		t.Fatal("sink accepted an uncommitted policy")
	}
}

func TestRelayOnlyPublicationAdvertisesTheADNLIdentityOnly(t *testing.T) {
	f := newRelayFixture(t)
	sink, err := NewRelayEvidenceSink(filepath.Join(t.TempDir(), "export"), filepath.Join(t.TempDir(), "card.json"),
		mustDelegationJSON(t, f.delegation), testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	publisher := &GenerationPublisher{Signer: endpointKey(t, 0x11), Delegation: f.delegation, Policy: testPolicy(),
		Descriptor: testDescriptor(t, f.delegation), PublishInterval: time.Minute, Relay: sink}
	if err := publisher.Validate(); err == nil {
		t.Fatal("a relay-only publisher advertised a placeholder HTTPS endpoint")
	}
	publisher.Descriptor.HTTPSEndpoint = ""
	if err := publisher.Validate(); err != nil {
		t.Fatalf("ADNL-only relay publisher: %v", err)
	}
	publisher.Delegation.ADNLID = ""
	publisher.Descriptor.ADNLID = ""
	if err := publisher.Validate(); err == nil {
		t.Fatal("a relay-only publisher without an ADNL identity was accepted")
	}
}

func mustDelegationJSON(t *testing.T, delegation identity.Delegation) []byte {
	t.Helper()
	raw, err := identity.EncodeJSON(delegation)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
