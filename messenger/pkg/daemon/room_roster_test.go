package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/messenger/pkg/room"
)

// credentialOf reports whether a receiver holds a member's credential.
func credentialOf(t *testing.T, receiver *relayNode, agentID string) (group.LeafCredential, bool) {
	t.Helper()
	ledger, err := receiver.d.journal.OpenRoomMLS()
	if err != nil {
		t.Fatal(err)
	}
	credential, found, err := ledger.RoomCredential(testRoomID, agentID)
	if err != nil {
		t.Fatal(err)
	}
	return credential, found
}

// A roster can never add an Agent the Commits did not: one naming a
// non-member, or the receiver itself, is refused whole.
func TestRoomRosterNamingANonMemberIsRefused(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	before, _ := fused(t, b)
	d := newRoomMember(t, scene.driver, scene.nodes[3], scene.start, scene.start.Add(50*time.Minute))
	membership := scene.authority.record.Membership()
	stranger := scene.authority.rosterObject(membership, rosterEntry(t, scene.c), rosterEntry(t, d))
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, stranger, 0)), fault.CodeNotAuthentic)
	self := scene.authority.rosterObject(membership, rosterEntry(t, scene.b), rosterEntry(t, scene.c))
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, self, 0)), fault.CodeNotAuthentic)
	requireUnmoved(t, b, before)
	if _, found := credentialOf(t, b, scene.c.agent()); found {
		t.Fatal("a refused roster taught a credential")
	}
	// The roster the Commits allow is accepted afterwards.
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.added, 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the added roster: %+v", ack)
	}
}

// A roster whose header names another membership than the committed one of
// its epoch is refused.
func TestRoomRosterHeaderOfAnotherMembershipIsRefused(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	committed := scene.authority.record.Membership()
	forged, err := room.Found(testRoomID, []string{scene.a.agent(), scene.c.agent()})
	if err != nil {
		t.Fatal(err)
	}
	forged.Epoch = committed.Epoch
	if forged.Digest, err = room.Digest(testRoomID, forged.Epoch, forged.Members); err != nil {
		t.Fatal(err)
	}
	body, err := relayframe.EncodeRoster([]relayframe.RosterEntry{rosterEntry(t, scene.c)})
	if err != nil {
		t.Fatal(err)
	}
	object := scene.authority.object(relayframe.RoomRoster, committed.Epoch, scene.authority.record.MLSEpoch, scene.authority.header(forged), body)
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, object, 0)), fault.CodeNotAuthentic)
	if _, found := credentialOf(t, b, scene.c.agent()); found {
		t.Fatal("a roster of another membership taught a credential")
	}
}

// A roster's header is checked like a Commit's: the room's end and the
// relay window.
func TestRoomRosterHeaderNamingAnotherEndIsRefused(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	membership := scene.authority.record.Membership()
	header := scene.authority.header(membership)
	header.EndsAtUnix++
	body, err := relayframe.EncodeRoster([]relayframe.RosterEntry{rosterEntry(t, scene.c)})
	if err != nil {
		t.Fatal(err)
	}
	object := scene.authority.object(relayframe.RoomRoster, membership.Epoch, scene.authority.record.MLSEpoch, header, body)
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, object, 0)), fault.CodeNotAuthentic)
	if _, found := credentialOf(t, b, scene.c.agent()); found {
		t.Fatal("a roster naming another end taught a credential")
	}
}

// Rosters are judged by room epoch: above current is a gap, a second,
// different one for an accepted epoch a conflict with an owner notice, and a
// late one inside the window is accepted and teaches current members.
func TestRoomRosterEpochRules(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	reports := &recordingReports{}
	b.d.observer = reports
	epochThree := scene.authority.record.Membership()
	d := newRoomMember(t, scene.driver, scene.nodes[3], scene.start, scene.start.Add(50*time.Minute))
	result, withD := scene.authority.commit(d)
	ahead := scene.authority.rosterObject(withD, rosterEntry(t, d))
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, ahead, 0)), fault.CodeRoomEpochGap)
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.authority.commitObject(result, withD), 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the Add of D: %+v", ack)
	}
	// Room epoch 4 now; the roster of epoch 3 arrives late and still
	// teaches C, a member now.
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.added, 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("a late roster for current - 1: %+v", ack)
	}
	if _, found := credentialOf(t, b, scene.c.agent()); !found {
		t.Fatal("a late roster taught nothing")
	}
	conflict := scene.authority.rosterObject(epochThree, rosterEntry(t, scene.a), rosterEntry(t, scene.c))
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, conflict, 0)), fault.CodeRoomRosterConflict)
	if reports.count(func(err error) bool { return err != nil && strings.Contains(err.Error(), "room-roster-conflict") }) != 1 {
		t.Fatal("a roster conflict raised no owner notice")
	}
}

// A credential is judged apart from the entry's card and evidence: a stale
// card skips only the card, while an entry whose credential fails is
// skipped whole and the rest of the roster is learned and accepted.
func TestRoomRosterLearnsCredentialsApartFromCardsAndSkipsFailingEntries(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	membership := scene.authority.record.Membership()
	// C's entry carries a card that is not C's (stale rendezvous); its
	// credential still verifies against the leaf.
	stale := rosterEntry(t, scene.c)
	stale.Card = scene.a.card
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.authority.rosterObject(membership, stale), 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("a roster with a stale card: %+v", ack)
	}
	if _, found := credentialOf(t, b, scene.c.agent()); !found {
		t.Fatal("a stale card dropped a verifying credential")
	}
	for _, agentID := range scene.cards[1].of(testRoomID) {
		if agentID == scene.c.agent() {
			t.Fatal("a stale card was admitted")
		}
	}

	// A second scene: C's entry carries a credential for another leaf key
	// than C's leaf in the tree, so it is skipped whole.
	other := newAddedScene(t, roomRetention)
	receiver := other.nodes[1]
	foreign := newRoomMember(t, other.driver, other.nodes[2], other.start, other.start.Add(50*time.Minute))
	entry := rosterEntry(t, foreign)
	if ack := roomAckOf(t, receiver, send(t, receiver, other.a.agent(), framesOf(t, other.a,
		other.authority.rosterObject(other.authority.record.Membership(), entry), 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("a roster whose one entry fails: %+v", ack)
	}
	if _, found := credentialOf(t, receiver, other.c.agent()); found {
		t.Fatal("a credential for another leaf was learned")
	}
	if _, found, err := receiver.d.journal.LoadRelayEvidence(other.c.agent()); err != nil || found {
		t.Fatalf("a skipped entry's evidence was committed: %v %v", found, err)
	}
	if admitted := other.cards[1].of(testRoomID); len(admitted) != 1 {
		t.Fatalf("a skipped entry's card was admitted: %v", admitted)
	}
}

// A roster entry whose credential ends before the room is skipped (D18).
func TestRoomRosterEntryEndingBeforeTheRoomIsSkipped(t *testing.T) {
	scene := newRoomScene(t, 3, roomRetention, 0)
	a := scene.member(t, 0, 40*time.Minute)
	b := scene.member(t, 1, 50*time.Minute)
	c := scene.member(t, 2, 30*time.Minute)
	authority := newTestAuthority(t, scene.driver, a, scene.clock)
	receiver := scene.nodes[1]
	invite(t, b, a, scene.start)
	addB, withB := authority.commit(b)
	roomAckOf(t, receiver, send(t, receiver, a.agent(), framesOf(t, a, authority.welcomeObject(addB, withB, b), 0)))
	// The test authority adds C although C's credential ends first; the
	// receiver judges the credential itself.
	addC, withC := authority.commit(c)
	if ack := roomAckOf(t, receiver, send(t, receiver, a.agent(), framesOf(t, a, authority.commitObject(addC, withC), 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the Add of C: %+v", ack)
	}
	if ack := roomAckOf(t, receiver, send(t, receiver, a.agent(), framesOf(t, a, authority.rosterObject(withC, rosterEntry(t, c)), 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the roster: %+v", ack)
	}
	if _, found := credentialOf(t, receiver, c.agent()); found {
		t.Fatal("a credential ending before the room was learned")
	}
}
