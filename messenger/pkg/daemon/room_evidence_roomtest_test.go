//go:build roomtest

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// The short prekey generation schedule of the evidence-expiry scene: every
// node's descriptor lives 20 minutes and is renewed 5 minutes before it
// expires, so its stored evidence expires at its peers in the middle of the
// room, while the room and every credential still run.
const (
	e2eShortGeneration = 20 * time.Minute
	e2eShortReplenish  = 5 * time.Minute
)

func shortGenerations(publication *PublicationConfig) {
	publication.GenerationLifetimeSeconds = uint64(e2eShortGeneration / time.Second)
	publication.ReplenishBeforeSeconds = uint64(e2eShortReplenish / time.Second)
	publication.CheckIntervalSeconds = 60
}

// renewOwnEvidence runs a node's prekey planner and publisher timers once:
// a generation inside its replenish window is replaced, and the new
// descriptor is published as the node's own relay evidence.
func (s *e2eScene) renewOwnEvidence(index int) {
	t := s.t
	t.Helper()
	prekeys := s.nodes[index].d.prekeys
	if err := prekeys.maintainLocalDevice(); err != nil {
		t.Fatalf("node %d renews its prekeys: %v", index, err)
	}
	if err := prekeys.publishCurrent(context.Background()); err != nil {
		t.Fatalf("node %d publishes its descriptor: %v", index, err)
	}
}

// ownIssuedAt is the issue time of a node's own current descriptor.
func (s *e2eScene) ownIssuedAt(index int) time.Time {
	s.t.Helper()
	_, _, issued, err := s.nodes[index].d.relay.sink.Current()
	if err != nil {
		s.t.Fatalf("node %d's own evidence: %v", index, err)
	}
	return time.Unix(int64(issued), 0)
}

// evidenceRequestsAnswered counts the kind-4 requests a node deposited to a
// peer that the peer admitted, and the responses it got back admitted.
func (s *e2eScene) evidenceRequestsAnswered(from, to int) (requests, responses int) {
	t := s.t
	t.Helper()
	for _, answer := range s.answers {
		envelope := answer.envelope
		if envelope.kind != relayframe.KindEvidence || answer.response.Result != carrierapi.ResultAdmitted {
			continue
		}
		decoded, err := relayframe.Decode(envelope.frame)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case envelope.from == s.agent(from) && envelope.to == s.agent(to) && decoded.Part[0] == relayframe.EvidenceRequest:
			requests++
		case envelope.from == s.agent(to) && envelope.to == s.agent(from) && decoded.Part[0] == relayframe.EvidenceResponse:
			responses++
		}
	}
	return requests, responses
}

// Every member's stored evidence of every other expires in the middle of the
// room: each node renewed its own descriptor before it expired, but no room
// traffic carried the renewal, and the relay timer retired the expired
// records to their floors. A member then composes. Its deposits fail
// CheckPeer, so the member's kind-4 pull runs to every other member, B and C
// included although they are no contacts of each other; each answers with its
// renewed evidence, and the message then goes out and is opened. The
// authority's message the other way runs the same repair (section 2.5,
// 11.2).
func TestRoomTestEvidenceExpiredMidRoomIsPulledAgain(t *testing.T) {
	s := newE2ESceneWith(t, shortGenerations)
	s.founded()
	// No 1:1 traffic runs here: a pending 1:1 copy would start the pull
	// by itself and hide whether room objects do.
	s.addsTwoMembersAcrossCrashes()
	members := []int{nodeA, nodeB, nodeC}
	firstIssued := map[int]time.Time{}
	for _, index := range members {
		firstIssued[index] = s.ownIssuedAt(index)
	}

	// Each node renews its own descriptor inside its replenish window,
	// before the first one expires; nothing carries it in band.
	renewal := s.start.Add(e2eShortGeneration - e2eShortReplenish + time.Minute)
	if !s.clock.now().Before(renewal) {
		t.Fatalf("the scene reached %v before the renewal time %v", s.clock.now(), renewal)
	}
	s.clock.set(renewal)
	for _, index := range members {
		s.renewOwnEvidence(index)
		if issued := s.ownIssuedAt(index); !issued.After(firstIssued[index]) {
			t.Fatalf("node %d's descriptor was not renewed: issued %v, first %v", index, issued, firstIssued[index])
		}
	}

	// Past the first descriptors' expiry the relay timer retires every
	// stored peer evidence to its floor.
	expired := s.start.Add(e2eShortGeneration + time.Minute)
	s.at(expired.Sub(s.start))
	for _, local := range members {
		for _, peer := range members {
			if local == peer {
				continue
			}
			journal := s.nodes[local].d.journal
			if _, found, err := journal.LoadRelayEvidence(s.agent(peer)); err != nil || found {
				t.Fatalf("node %d still holds node %d's evidence: %v", local, peer, err)
			}
			if _, floored, err := journal.LoadRelayEvidenceFloor(s.agent(peer)); err != nil || !floored {
				t.Fatalf("node %d keeps no floor of node %d: %v", local, peer, err)
			}
		}
	}
	if record, _ := fused(t, s.nodes[nodeA]); !s.clock.now().Before(time.Unix(int64(record.RoomEndsAtUnix), 0)) {
		t.Fatal("the room ended before the evidence expired")
	}

	// B composes: its deposits wait on the pull, which goes to A and C.
	fromB, err := s.compose(nodeB, "after the evidence expired", "b")
	if err != nil {
		t.Fatalf("B composes: %v", err)
	}
	s.settle()
	for _, peer := range []int{nodeA, nodeC} {
		if requests, responses := s.evidenceRequestsAnswered(nodeB, peer); requests != 1 || responses != 1 {
			t.Fatalf("B's evidence pull to node %d: %d requests and %d responses admitted", peer, requests, responses)
		}
		if pull, _, err := s.nodes[nodeB].d.journal.LoadRelayPull(s.agent(peer)); err != nil || pull.Requested {
			t.Fatalf("B's pull to node %d after the response: %+v %v", peer, pull, err)
		}
	}
	// The deposits deferred on the evidence are tried again after their wait.
	s.at(s.clock.now().Add(relayEvidenceRetry).Sub(s.start))
	s.requireJournaled(fromB, nodeA, nodeC)
	send, found, err := s.nodes[nodeB].d.journal.RoomApplicationSendFor(testRoomID, idem("b"))
	if err != nil || !found {
		t.Fatalf("B's application record: %v", err)
	}
	for _, member := range send.Members {
		if member.State != eventlog.RoomDeliveryCarried {
			t.Fatalf("B's copy to %s ended %s", member.AgentID, member.State)
		}
	}

	// The authority's message goes out the same way: B's evidence it learned
	// from B's request, C's through its own pull.
	fromA, err := s.compose(nodeA, "the authority after the expiry", "c")
	if err != nil {
		t.Fatalf("A composes: %v", err)
	}
	s.settle()
	s.at(s.clock.now().Add(relayEvidenceRetry).Sub(s.start))
	s.requireJournaled(fromA, nodeB, nodeC)
	if requests, responses := s.evidenceRequestsAnswered(nodeA, nodeC); requests != 1 || responses != 1 {
		t.Fatalf("A's evidence pull to C: %d requests and %d responses admitted", requests, responses)
	}
}
