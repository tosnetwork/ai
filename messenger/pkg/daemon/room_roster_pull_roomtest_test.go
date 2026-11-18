//go:build roomtest

package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// The authority adds a member after the room was idle past every stored
// descriptor's lifetime: each node renewed its own descriptor, but nothing
// carried the renewal, so the authority holds only floors of its members.
// The Add's roster needs every current member's committed evidence, so the
// roster waits on a kind-4 pull to each of them; the pull must be deposited
// and answered, and the Add then commits (sections 2.5, 11.2).
func TestRoomTestAddAfterIdlePullsTheMembersEvidence(t *testing.T) {
	s := newE2ESceneWith(t, shortGenerations)
	s.idleRoomOfThree()
	s.addsDAfterTheIdle()
}

// A member's owner removing the authority from its contacts does not stop
// the member answering the authority's pull: the member keeps the
// authority's evidence floor, which is what admits a kind-4 request.
func TestRoomTestAddAfterIdlePullsAMemberThatRemovedTheAuthority(t *testing.T) {
	s := newE2ESceneWith(t, shortGenerations)
	s.idleRoomOfThree()
	c := s.nodes[nodeC].d.journal
	token := "invite_" + "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
	if _, err := c.AddInvitedContact(s.agent(nodeA), "evt_"+strings.Repeat("e", 64), token, s.clock.now()); err != nil {
		t.Fatalf("C claims an invite of A: %v", err)
	}
	if removed, err := c.RemoveInvitedContact(s.agent(nodeA)); err != nil || !removed {
		t.Fatalf("C's owner removes A: %v %v", removed, err)
	}
	if _, floored, err := c.LoadRelayEvidenceFloor(s.agent(nodeA)); err != nil || !floored {
		t.Fatalf("C keeps no floor of A after the removal: %v", err)
	}
	s.addsDAfterTheIdle()
}

// An Add whose roster waits on a member's evidence that never comes ends
// with the room; after that no evidence request is deposited for it: the
// need ends with the Add, and while it lasted the per-peer request schedule
// never ran faster than one deposit per request interval.
func TestRoomTestAbandonedAddDepositsNoMoreEvidenceRequests(t *testing.T) {
	s := newE2ESceneWith(t, shortGenerations)
	s.idleRoomOfThree()
	a := s.agent(nodeA)
	// No answer to the authority's pull ever arrives.
	s.box.hold = func(envelope mailEnvelope) bool {
		return envelope.to == a && envelope.kind == relayframe.KindEvidence
	}
	importContact(t, s.nodes[nodeA], s.nodes[nodeD])
	s.add(nodeD)
	requested := s.clock.now()
	for step := 0; step < 6; step++ {
		s.at(s.clock.now().Add(relayEvidenceRetry).Sub(s.start))
	}
	generation := s.requestGeneration(nodeA, nodeB)
	if generation == 0 {
		t.Fatal("the authority never deposited an evidence request for the waiting roster")
	}
	if limit := uint32(s.clock.now().Sub(requested)/relayEvidenceRetry) + 1; generation > limit {
		t.Fatalf("%d evidence requests in %v: the pull ran faster than its schedule", generation,
			s.clock.now().Sub(requested))
	}
	record, _ := fused(t, s.nodes[nodeA])
	ended := time.Unix(int64(record.RoomEndsAtUnix), 0)
	s.at(ended.Add(time.Minute).Sub(s.start))
	s.at(ended.Add(2 * time.Minute).Sub(s.start))
	after := s.requestGeneration(nodeA, nodeB)
	for step := 0; step < 6; step++ {
		s.at(s.clock.now().Add(e2eTTL).Sub(s.start))
	}
	if final := s.requestGeneration(nodeA, nodeB); final != after {
		t.Fatalf("evidence requests went on after the Add ended: generation %d, then %d", after, final)
	}
}

// idleRoomOfThree founds the room with B and C, then idles past the
// descriptor lifetime.
func (s *e2eScene) idleRoomOfThree() {
	t := s.t
	t.Helper()
	s.founded()
	s.add(nodeC)
	if added := s.requireInEpoch(nodeB, nodeC); added.RoomEpoch != 3 {
		t.Fatalf("after C's Add: %+v", added)
	}
	s.idlePastTheDescriptorLifetime(nodeA, nodeB, nodeC, nodeD)
}

// addsDAfterTheIdle adds D, whose owner hands A a fresh contact file first
// (B's and C's evidence at A stays retired), and requires the authority's
// pull to B and C to be deposited and answered, and the Add to commit.
func (s *e2eScene) addsDAfterTheIdle() {
	t := s.t
	t.Helper()
	importContact(t, s.nodes[nodeA], s.nodes[nodeD])
	s.add(nodeD)
	s.at(s.clock.now().Add(relayEvidenceRetry).Sub(s.start))
	for _, member := range []int{nodeB, nodeC} {
		if requests, responses := s.evidenceRequestsAnswered(nodeA, member); requests < 1 || responses < 1 {
			pull, _, _ := s.nodes[nodeA].d.journal.LoadRelayPull(s.agent(member))
			t.Fatalf("the authority's evidence pull to node %d: %d requests and %d responses admitted "+
				"(pull record %+v)", member, requests, responses, pull)
		}
	}
	if added := s.requireInEpoch(nodeB, nodeC, nodeD); added.RoomEpoch != 4 || len(added.Members) != 4 {
		t.Fatalf("after D's Add: %+v", added)
	}
}

// idlePastTheDescriptorLifetime renews every node's own descriptor inside
// its replenish window, carries nothing, and moves past the first
// descriptors' expiry, so the authority (the first node) retires its peers'
// evidence to floors.
func (s *e2eScene) idlePastTheDescriptorLifetime(nodes ...int) {
	t := s.t
	t.Helper()
	renewal := s.start.Add(e2eShortGeneration - e2eShortReplenish + time.Minute)
	if !s.clock.now().Before(renewal) {
		t.Fatalf("the scene reached %v before the renewal time %v", s.clock.now(), renewal)
	}
	s.clock.set(renewal)
	for _, index := range nodes {
		s.renewOwnEvidence(index)
	}
	s.at(e2eShortGeneration + time.Minute)
	journal := s.nodes[nodes[0]].d.journal
	for _, peer := range nodes[1:] {
		if _, found, err := journal.LoadRelayEvidence(s.agent(peer)); err != nil || found {
			t.Fatalf("the authority still holds node %d's evidence: %v", peer, err)
		}
		if _, floored, err := journal.LoadRelayEvidenceFloor(s.agent(peer)); err != nil || !floored {
			t.Fatalf("the authority keeps no floor of node %d: %v", peer, err)
		}
	}
}

// requestGeneration is how many evidence requests a node has deposited to
// a peer.
func (s *e2eScene) requestGeneration(from, to int) uint32 {
	s.t.Helper()
	pull, _, err := s.nodes[from].d.journal.LoadRelayPull(s.agent(to))
	if err != nil {
		s.t.Fatal(err)
	}
	return pull.RequestGeneration
}

// The privacy rule of the pull: a node answers a kind-4 request only from a
// peer it admitted on this route before (committed evidence or its floor).
// A stranger, here D, which B never admitted and which is no member of B's
// room, gets the relay acknowledgement only: nothing is verified, written or
// answered, so a pull cannot probe whether a node runs or which rooms it is
// in (section 2.5).
func TestRoomTestEvidenceRequestFromANeverAdmittedPeerIsIgnored(t *testing.T) {
	s := newE2ESceneWith(t, shortGenerations)
	s.founded()
	b, d := s.nodes[nodeB], s.nodes[nodeD]
	if _, found, _ := b.d.journal.LoadRelayEvidenceFloor(s.agent(nodeD)); found {
		t.Fatal("B already holds a floor of D")
	}
	request, _, err := d.d.relay.ownFrame(relayframe.KindEvidence, s.agent(nodeB),
		[]byte{relayframe.EvidenceRequest}, true)
	if err != nil {
		t.Fatal(err)
	}
	if answer := b.d.relay.Deliver(context.Background(), s.agent(nodeD), request); answer.Result != carrierapi.ResultIgnored {
		t.Fatalf("B answered D's request: %+v", answer)
	}
	if _, found, _ := b.d.journal.LoadRelayPull(s.agent(nodeD)); found {
		t.Fatal("D's request was written at B")
	}
	if _, found, _ := b.d.journal.LoadRelayEvidence(s.agent(nodeD)); found {
		t.Fatal("D's evidence was stored at B")
	}
}
