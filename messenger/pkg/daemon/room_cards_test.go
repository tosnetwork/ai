package daemon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// rosterEntriesOf decodes the entries of a staged roster object.
func rosterEntriesOf(t *testing.T, object []byte) []relayframe.RosterEntry {
	t.Helper()
	decoded, err := relayframe.DecodeRoomObject(object)
	if err != nil || decoded.Type != relayframe.RoomRoster {
		t.Fatalf("not a roster: %v", err)
	}
	entries, err := relayframe.DecodeRoster(decoded.Body)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func cardOfNode(t *testing.T, node *relayNode) []byte {
	t.Helper()
	card, err := node.d.relay.sink.Card()
	if err != nil {
		t.Fatal(err)
	}
	return card
}

// requireEntryCards requires a roster to hold exactly the given members,
// each with its own current card.
func requireEntryCards(t *testing.T, entries []relayframe.RosterEntry, members ...*relayNode) {
	t.Helper()
	if len(entries) != len(members) {
		t.Fatalf("the roster has %d entries, want %d", len(entries), len(members))
	}
	for _, member := range members {
		found := false
		for _, entry := range entries {
			if entry.AgentID == member.d.config.AgentID {
				found = true
				if !bytes.Equal(entry.Card, cardOfNode(t, member)) {
					t.Fatalf("the entry of %s carries another card", entry.AgentID)
				}
			}
		}
		if !found {
			t.Fatalf("the roster has no entry of %s", member.d.config.AgentID)
		}
	}
}

// The authority keeps each joiner's card from its room.key-package frame,
// so a third member is added into {A, B}: C's full roster carries A's and
// B's cards, the roster of added members carries C's to B, and B and C
// exchange room messages with each other.
func TestRoomCardsLetTheAuthorityAddAThirdMember(t *testing.T) {
	scene := newOperatorScene(t, 3)
	a, b, c := scene.nodes[0], scene.nodes[1], scene.nodes[2]
	scene.founded(t)
	scene.invited(t, 1)
	scene.joined(t, 1)
	stored, found, err := a.d.journal.RoomMemberCardOf(testRoomID, b.d.config.AgentID)
	if err != nil || !found {
		t.Fatalf("the joiner's card was not kept: %v", err)
	}
	if card, _ := stored.Card(); !bytes.Equal(card, cardOfNode(t, b)) {
		t.Fatal("the kept card is not the joiner's")
	}
	roomAckOf(t, b, deliverObject(t, a, b, outboxObject(t, a, eventlog.RoomObjectWelcome, b.d.config.AgentID)))
	roomAckOf(t, b, deliverObject(t, a, b, outboxObject(t, a, eventlog.RoomObjectRoster, b.d.config.AgentID)))

	scene.invited(t, 2)
	if answer := scene.joined(t, 2); answer.AckOutcome != relayframe.OutcomeAccepted {
		t.Fatalf("C's room.key-package: %+v", answer)
	}
	record, _ := fused(t, a)
	if !record.Membership().Contains(c.d.config.AgentID) || record.RoomEpoch != 3 {
		t.Fatalf("C was not added: %+v", record)
	}
	full := outboxObject(t, a, eventlog.RoomObjectRoster, c.d.config.AgentID)
	requireEntryCards(t, rosterEntriesOf(t, full), a, b)
	heads, err := a.d.journal.RoomMemberQueue(testRoomID, b.d.config.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	var commit, added []byte
	for _, head := range heads {
		if head.MLSEpoch != record.MLSEpoch {
			continue
		}
		object, err := a.d.journal.RoomOutboxObject(head.ObjectDigest)
		if err != nil {
			t.Fatal(err)
		}
		switch head.Type {
		case eventlog.RoomObjectCommit:
			commit = object
		case eventlog.RoomObjectRoster:
			added = object
		}
	}
	if commit == nil || added == nil {
		t.Fatal("B's Commit or roster of added members was not staged")
	}
	requireEntryCards(t, rosterEntriesOf(t, added), c)

	// B applies the Add and learns C; C joins through its Welcome and roster.
	if ack := roomAckOf(t, b, deliverObject(t, a, b, commit)); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("B's Commit: %+v", ack)
	}
	if ack := roomAckOf(t, b, deliverObject(t, a, b, added)); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("B's roster of added members: %+v", ack)
	}
	if ack := roomAckOf(t, c, deliverObject(t, a, c, outboxObject(t, a, eventlog.RoomObjectWelcome, c.d.config.AgentID))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("C's Welcome: %+v", ack)
	}
	if ack := roomAckOf(t, c, deliverObject(t, a, c, full)); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("C's full roster: %+v", ack)
	}
	if got := scene.cards[1].of(testRoomID); len(got) != 2 || got[1] != c.d.config.AgentID {
		t.Fatalf("B admitted the cards %v, want A's from its full roster and then C's", got)
	}

	// B and C, no contacts of the room, exchange messages.
	if _, _, err := scene.compose(t, 1, "hello C", "1"); err != nil {
		t.Fatal(err)
	}
	if answer := deliver(t, b, c, roomFrames(t, b, c.d.config.AgentID)[0].frame); answer.Result != carrierapi.ResultAdmitted {
		t.Fatalf("C refused B's message: %s/%s", answer.Result, answer.Code)
	}
	if _, _, err := scene.compose(t, 2, "hello B", "2"); err != nil {
		t.Fatal(err)
	}
	if answer := deliver(t, c, b, roomFrames(t, c, b.d.config.AgentID)[0].frame); answer.Result != carrierapi.ResultAdmitted {
		t.Fatalf("B refused C's message: %s/%s", answer.Result, answer.Code)
	}
}

// A room.key-package frame whose card names another Agent than the packet
// sender is refused, and nothing is recorded.
func TestRoomKeyPackageWithAnotherAgentsCardIsRefused(t *testing.T) {
	scene := newOperatorScene(t, 3)
	a, b, c := scene.nodes[0], scene.nodes[1], scene.nodes[2]
	scene.founded(t)
	scene.invited(t, 1)
	// A acknowledged a frame carrying B's card already, so B's kind-1
	// frames to A would leave it out; the room.key-package carries it still.
	pull, _, err := b.d.journal.LoadRelayPull(a.d.config.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	pull.AgentID = a.d.config.AgentID
	pull.AckedCardDigest = canon.Digest(cardOfNode(t, b))
	if err := b.d.journal.PutRelayPull(pull, scene.clock.now()); err != nil {
		t.Fatal(err)
	}
	if err := scene.rooms(1).JoinRoom(context.Background(), testRoomID, a.d.config.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	out := onlyFrame(t, b)
	frame, err := relayframe.Decode(out.frame)
	if err != nil || len(frame.Card) == 0 {
		t.Fatalf("the room.key-package frame carries no card: %v", err)
	}
	frame.Card = cardOfNode(t, c)
	forged, err := relayframe.Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	requireRefusedCopy(t, deliver(t, b, a, forged))
	if adds, err := a.d.journal.RoomAdds(testRoomID, scene.clock.now()); err != nil || len(adds) != 1 || adds[0].Ready() {
		t.Fatalf("a KeyPackage with another Agent's card was recorded: %+v %v", adds, err)
	}
	if _, found, err := a.d.journal.RoomMemberCardOf(testRoomID, b.d.config.AgentID); err != nil || found {
		t.Fatalf("another Agent's card was kept: %v", err)
	}
}

// A stored card is replaced only by a newer valid card of the member's
// own frames; an expired stored card holds the next Add's roster back and
// starts the member's evidence pull, and a newer card lets it go.
func TestRoomCardsAreRefreshedNewerOnlyAndExpiredOnesHoldRostersBack(t *testing.T) {
	scene := newOperatorScene(t, 3)
	a, b := scene.nodes[0], scene.nodes[1]
	scene.founded(t)
	scene.invited(t, 1)
	scene.joined(t, 1)
	now := scene.clock.now()
	runtime := scene.rooms(0)
	agent := b.d.config.AgentID
	stored := func() eventlog.RoomMemberCard {
		t.Helper()
		card, found, err := a.d.journal.RoomMemberCardOf(testRoomID, agent)
		if err != nil || !found {
			t.Fatalf("no stored card: %v", err)
		}
		return card
	}
	first := stored()
	// An older card, an invalid one and another Agent's change nothing.
	runtime.refreshMemberCard(agent, relayCardAt(t, agent, first.CreatedAtUnix, first.Sequence, uint64(now.Unix())-60, uint64(now.Add(time.Hour).Unix())), now)
	runtime.refreshMemberCard(agent, []byte("not a card"), now)
	runtime.refreshMemberCard(agent, cardOfNode(t, scene.nodes[2]), now)
	if stored() != first {
		t.Fatal("a card no newer than the stored one replaced it")
	}
	// A newer card that is already expired is refused too.
	runtime.refreshMemberCard(agent, relayCardAt(t, agent, first.CreatedAtUnix+1, 1, uint64(now.Unix())-120, uint64(now.Unix())), now)
	if stored() != first {
		t.Fatal("an expired card replaced the stored one")
	}
	// A newer card, valid for ten minutes, replaces it.
	short := relayCardAt(t, agent, first.CreatedAtUnix+1, 1, uint64(now.Unix())-60, uint64(now.Add(10*time.Minute).Unix()))
	runtime.refreshMemberCard(agent, short, now)
	if card, _ := stored().Card(); !bytes.Equal(card, short) {
		t.Fatal("a newer card did not replace the stored one")
	}
	// B's Welcome and roster are delivered, so B is a member; then the
	// stored card expires before C is added.
	roomAckOf(t, b, deliverObject(t, a, b, outboxObject(t, a, eventlog.RoomObjectWelcome, agent)))
	roomAckOf(t, b, deliverObject(t, a, b, outboxObject(t, a, eventlog.RoomObjectRoster, agent)))
	scene.invited(t, 2)
	scene.clock.set(now.Add(10 * time.Minute))
	before, _ := fused(t, a)
	scene.joined(t, 2)
	if after, _ := fused(t, a); after.MLSEpoch != before.MLSEpoch {
		t.Fatal("an Add was committed with an expired member card")
	}
	if scene.reports[0].count(func(err error) bool { return errors.Is(err, ErrRoomMemberCardUnknown) }) == 0 {
		t.Fatal("the held-back Add was not reported")
	}
	if pull, _, err := a.d.journal.LoadRelayPull(agent); err != nil || !pull.Requested {
		t.Fatalf("the expired card did not start the evidence pull: %+v %v", pull, err)
	}
	// B's next frames carry its renewed card (its card file is renewed): a
	// 1:1 copy, then a room message, each a newer card the authority keeps.
	renewedAt := func(created uint64) []byte {
		card := relayCardAt(t, agent, created, 1, uint64(scene.clock.now().Unix())-60, uint64(scene.clock.now().Add(time.Hour).Unix()))
		if err := os.WriteFile(b.cardPath, card, 0o600); err != nil {
			t.Fatal(err)
		}
		return card
	}
	direct := renewedAt(first.CreatedAtUnix + 2)
	sendText(t, b, a, "a copy carrying the card", "e", scene.clock.now())
	if _, err := b.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	// The sweep also re-deposits B's unacknowledged room.key-package, a
	// duplicate at A.
	copies := framesOfKind(t, b.carrier.take(), relayframe.KindCopy)
	if len(copies) == 0 {
		t.Fatal("no copy was carried")
	}
	for _, copied := range copies {
		deliver(t, b, a, copied.frame)
	}
	if card, _ := stored().Card(); !bytes.Equal(card, direct) {
		t.Fatal("a 1:1 copy's newer card was not kept")
	}
	renewed := renewedAt(first.CreatedAtUnix + 3)
	if _, _, err := scene.compose(t, 1, "a room message carrying the card", "f"); err != nil {
		t.Fatal(err)
	}
	deliver(t, b, a, roomFrames(t, b, a.d.config.AgentID)[0].frame)
	if card, _ := stored().Card(); !bytes.Equal(card, renewed) {
		t.Fatal("a room object's newer card was not kept")
	}
	runtime.maintain()
	if after, _ := fused(t, a); !after.Membership().Contains(scene.nodes[2].d.config.AgentID) {
		t.Fatal("the Add was not committed once the card was renewed")
	}
	added := false
	heads, _ := a.d.journal.RoomMemberQueue(testRoomID, agent)
	for _, head := range heads {
		if head.Type == eventlog.RoomObjectRoster {
			continue
		}
		added = true
	}
	if !added {
		t.Fatal("B got no Commit of the Add")
	}
	full := outboxObject(t, a, eventlog.RoomObjectRoster, scene.nodes[2].d.config.AgentID)
	for _, entry := range rosterEntriesOf(t, full) {
		if entry.AgentID == agent && !bytes.Equal(entry.Card, renewed) {
			t.Fatal("C's roster carries B's old card")
		}
	}
}

// Remove deletes the removed member's card with its credential.
func TestRoomRemoveForgetsTheMembersCard(t *testing.T) {
	scene := newOperatorScene(t, 2)
	a, b := scene.nodes[0], scene.nodes[1]
	scene.founded(t)
	scene.invited(t, 1)
	scene.joined(t, 1)
	if err := scene.rooms(0).RemoveRoomMember(context.Background(), testRoomID, b.d.config.AgentID); err != nil {
		t.Fatal(err)
	}
	if _, found, err := a.d.journal.RoomMemberCardOf(testRoomID, b.d.config.AgentID); err != nil || found {
		t.Fatalf("the removed member's card was kept: %v", err)
	}
	if _, err := a.d.journal.StoreRoomMemberCard(eventlog.RoomMemberCard{RoomID: testRoomID, AgentID: b.d.config.AgentID,
		CardBase64: encodeCard(cardOfNode(t, b)), CreatedAtUnix: 9, Sequence: 1, NotBeforeUnix: 1, NotAfterUnix: 4_000_000_000},
		scene.clock.now()); !errors.Is(err, eventlog.ErrRoomCardMember) {
		t.Fatalf("a removed member's card was stored again: %v", err)
	}
}
