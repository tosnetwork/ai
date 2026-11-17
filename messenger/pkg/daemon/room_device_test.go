package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// A leaf credential names the device set it was issued in only as
// evidence: a member's prekey renewal changes the set's digest, not its
// device, and the credential stays valid (section 11.8). It is refused once
// the device leaves the Endpoint's current set or is revoked from it.

// renewedEvidence is a node's evidence after a prekey renewal: a fresh
// bundle for the same device, so a set of another digest.
func renewedEvidence(t *testing.T, member roomMember, issued time.Time) []byte {
	t.Helper()
	evidence := evidenceFor(t, member.node, member.node.d.config.DeviceID, uint64(issued.Unix()),
		uint64(issued.Add(40*time.Minute).Unix()))
	_, _, set := evidenceSet(t, evidence)
	if set.Digest == member.set.Digest || set.Digest == member.credential.DeviceSetDigest {
		t.Fatal("the renewal kept the set's digest")
	}
	return evidence
}

func evidenceSet(t *testing.T, evidence []byte) ([]byte, []e2ee.Bundle, e2ee.SetSummary) {
	t.Helper()
	decoded, err := relayframe.DecodeEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := e2ee.DecodeBundleSetJSON(decoded.BundleSet)
	if err != nil {
		t.Fatal(err)
	}
	set, err := e2ee.Summarize(bundles)
	if err != nil {
		t.Fatal(err)
	}
	return evidence, bundles, set
}

// The authority renews its prekeys inside the room: its Commit, under
// evidence of the new set, still applies.
func TestRoomAuthorityPrekeyRenewalKeepsItsCredential(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	scene.clock.set(scene.start.Add(2 * time.Minute))
	renewed := scene.a
	renewed.evidence = renewedEvidence(t, scene.a, scene.start.Add(time.Minute))
	result, membership := scene.authority.commit()
	ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, renewed, scene.authority.commitObject(result, membership), 0)))
	if ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("a Commit after the authority's prekey renewal: %+v", ack)
	}
}

// A member renewed its prekeys before the roster carried its evidence: its
// credential is still learned, and its evidence committed.
func TestRoomMemberPrekeyRenewalKeepsItsCredential(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	scene.clock.set(scene.start.Add(2 * time.Minute))
	entry := rosterEntry(t, scene.c)
	entry.Evidence = renewedEvidence(t, scene.c, scene.start.Add(time.Minute))
	roster := scene.authority.rosterObject(scene.authority.record.Membership(), entry)
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, roster, 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the roster: %+v", ack)
	}
	if _, found := credentialOf(t, b, scene.c.agent()); !found {
		t.Fatal("a member's prekey renewal dropped its credential")
	}
	if _, found, err := b.d.journal.LoadRelayEvidence(scene.c.agent()); err != nil || !found {
		t.Fatalf("the renewed evidence was not committed: %v", err)
	}
}

// A device no longer in the Endpoint's current set is refused: the
// authority's Commit under evidence of a set without its device, and a
// roster entry whose evidence names a set without the member's device.
func TestRoomCredentialOfADeviceThatLeftTheSetIsRefused(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	before, _ := fused(t, b)
	scene.clock.set(scene.start.Add(2 * time.Minute))
	other := "dev_" + strings.Repeat("e", 64)
	moved := scene.a
	moved.evidence = evidenceFor(t, scene.a.node, other, uint64(scene.start.Add(time.Minute).Unix()),
		uint64(scene.start.Add(40*time.Minute).Unix()))
	result, membership := scene.authority.commit()
	response := send(t, b, scene.a.agent(), framesOf(t, moved, scene.authority.commitObject(result, membership), 0))
	if response.Result != carrierapi.ResultRefused || response.Code != carrierapi.CodeEvidenceRefused {
		t.Fatalf("a Commit whose authority's device left the set: %s/%s", response.Result, response.Code)
	}
	requireUnmoved(t, b, before)
	entry := rosterEntry(t, scene.c)
	entry.Evidence = evidenceFor(t, scene.c.node, other, uint64(scene.start.Add(time.Minute).Unix()),
		uint64(scene.start.Add(40*time.Minute).Unix()))
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.authority.rosterObject(membership, entry), 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the roster: %+v", ack)
	}
	if _, found := credentialOf(t, b, scene.c.agent()); found {
		t.Fatal("the credential of a device that left the set was learned")
	}
}

// A device this receiver holds as revoked is refused, even under evidence of
// an older set that still holds it: the roster entry is skipped whole.
func TestRoomRosterEntryOfARevokedDeviceIsSkipped(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	devices := b.d.discovery.devices
	_, original, _ := evidenceSet(t, scene.c.evidence)
	if _, err := devices.AcceptSet(scene.c.delegation.EndpointID, original, scene.start); err != nil {
		t.Fatal(err)
	}
	// C's Endpoint published a set without its device: the device is
	// revoked here and never returns.
	_, successor, _ := evidenceSet(t, evidenceFor(t, scene.c.node, "dev_"+strings.Repeat("e", 64),
		uint64(scene.start.Add(time.Minute).Unix()), uint64(scene.start.Add(40*time.Minute).Unix())))
	if _, err := devices.AcceptSet(scene.c.delegation.EndpointID, successor, scene.start.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if standing, err := devices.Judge(scene.c.delegation.EndpointID, scene.c.node.d.config.DeviceID); err != nil || standing != eventlog.DeviceRevoked {
		t.Fatalf("C's device: %v %v", standing, err)
	}
	scene.clock.set(scene.start.Add(2 * time.Minute))
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.added, 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the roster: %+v", ack)
	}
	if _, found := credentialOf(t, b, scene.c.agent()); found {
		t.Fatal("the credential of a revoked device was learned")
	}
	for _, agentID := range scene.cards[1].of(testRoomID) {
		if agentID == scene.c.agent() {
			t.Fatal("a revoked device's card was admitted")
		}
	}
}
