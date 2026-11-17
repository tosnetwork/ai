package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/localapi"
	"github.com/tosnetwork/ai/messenger/pkg/payload"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// The operator tests run the owner's operations on real daemons: every node
// runs the room runtime, the 1:1 Events (room.invite, room.key-package)
// cross through each node's dispatcher and recording carrier, and the
// authority's staged objects are taken from its own outbox. What the
// receivers of #38 and #41 accept is what this sender must produce.

// operatorScene is a set of relay nodes that are each other's contacts and
// all run the room runtime.
type operatorScene struct {
	*roomScene
	reports []*recordingReports
}

func newOperatorScene(t *testing.T, count int) *operatorScene {
	t.Helper()
	driver := openMLSDriver(t)
	start := time.Unix(1_900_000_000, 0)
	digits := [][2]string{{"a", "1"}, {"b", "2"}, {"c", "3"}, {"d", "4"}}[:count]
	nodes := newRelayNodes(t, start, digits...)
	scene := &operatorScene{roomScene: &roomScene{driver: driver, clock: &testClock{at: start}, start: start, nodes: nodes}}
	for _, node := range nodes {
		node.d.now = scene.clock.now
		reports := &recordingReports{}
		node.d.observer = reports
		scene.reports = append(scene.reports, reports)
		cards := &roomCardsCarrier{}
		scene.cards = append(scene.cards, cards)
		if err := node.d.installRoomRuntime(roomRuntimeSettings{driver: driver, cards: cards, skew: 5 * time.Minute,
			retention: roomRetention, gapDelay: testRoomGapDelay}); err != nil {
			t.Fatalf("install the room runtime: %v", err)
		}
	}
	for _, local := range nodes {
		for _, peer := range nodes {
			if local != peer {
				importContact(t, local, peer)
			}
		}
	}
	return scene
}

func (s *operatorScene) rooms(index int) *roomRuntime { return s.nodes[index].d.relay.rooms }

// relayOne sweeps a node's dispatcher and delivers its one copy frame to the
// recipient, returning the recipient's answer.
func relayOne(t *testing.T, from, to *relayNode) carrierapi.Response {
	t.Helper()
	if _, err := from.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	return deliver(t, from, to, onlyFrame(t, from).frame)
}

// founded creates the test room at node 0.
func (s *operatorScene) founded(t *testing.T) eventlog.RoomMLSRecord {
	t.Helper()
	if err := s.rooms(0).CreateRoom(context.Background(), testRoomID); err != nil {
		t.Fatalf("create the room: %v", err)
	}
	record, found := fused(t, s.nodes[0])
	if !found {
		t.Fatal("the founder holds no fused record")
	}
	return record
}

// invited runs rooms.add at the authority and delivers the room.invite.
func (s *operatorScene) invited(t *testing.T, member int) {
	t.Helper()
	authority, joiner := s.nodes[0], s.nodes[member]
	if err := s.rooms(0).AddRoomMember(context.Background(), testRoomID, joiner.d.config.AgentID); err != nil {
		t.Fatalf("add: %v", err)
	}
	if answer := relayOne(t, authority, joiner); answer.AckOutcome != relayframe.OutcomeAccepted {
		t.Fatalf("the room.invite: %+v", answer)
	}
	if _, found, err := joiner.d.journal.PendingRoomJoinFor(testRoomID, authority.d.config.AgentID, s.clock.now()); err != nil || !found {
		t.Fatalf("the invite left no pending join: %v", err)
	}
}

// joined runs rooms.join at the member and delivers its room.key-package,
// which makes the authority's Add Commit.
func (s *operatorScene) joined(t *testing.T, member int) carrierapi.Response {
	t.Helper()
	authority, joiner := s.nodes[0], s.nodes[member]
	if err := s.rooms(member).JoinRoom(context.Background(), testRoomID, authority.d.config.AgentID); err != nil {
		t.Fatalf("join: %v", err)
	}
	return relayOne(t, joiner, authority)
}

// outboxObject returns the authority's one staged object of a type for a
// member.
func outboxObject(t *testing.T, authority *relayNode, kind eventlog.RoomObjectType, member string) []byte {
	t.Helper()
	heads, err := authority.d.journal.RoomOutboxHeads(testRoomID)
	if err != nil {
		t.Fatal(err)
	}
	var found []eventlog.RoomOutboxHead
	for _, head := range heads {
		if _, addressed := head.Member(member); addressed && head.Type == kind {
			found = append(found, head)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d staged objects of type %d for %s", len(found), kind, member)
	}
	object, err := authority.d.journal.RoomOutboxObject(found[len(found)-1].ObjectDigest)
	if err != nil {
		t.Fatal(err)
	}
	return object
}

// deliverObject sends a room object from a node with its own card and
// evidence in part 0.
func deliverObject(t *testing.T, from, to *relayNode, object []byte) carrierapi.Response {
	t.Helper()
	evidence, card, _ := evidenceOf(t, from)
	frames, err := relayframe.SplitRoomObject(object, card, evidence, 0)
	if err != nil {
		t.Fatal(err)
	}
	return send(t, to, from.d.config.AgentID, frames)
}

// compose seals a room message at a node.
func (s *operatorScene) compose(t *testing.T, index int, body, idem string) (string, bool, error) {
	t.Helper()
	record, _ := fused(t, s.nodes[index])
	return s.rooms(index).ComposeRoomMessage(context.Background(), localapi.RoomComposition{RoomID: testRoomID,
		ConversationID: "conv_" + strings.Repeat("c3", 32), MediaType: "text/plain; charset=utf-8", Body: body,
		IdempotencyKey: "idem_" + strings.Repeat(idem, 64), MembershipEpoch: record.RoomEpoch,
		ExpiresAtUnix: uint64(s.clock.now().Add(time.Hour).Unix())})
}

// roomFrames takes the kind-3 frames a node's carrier got for a recipient.
func roomFrames(t *testing.T, node *relayNode, recipient string) []carried {
	t.Helper()
	var frames []carried
	for _, frame := range node.carrier.take() {
		decoded, err := relayframe.Decode(frame.frame)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Kind == relayframe.KindRoom && frame.recipient == recipient {
			frames = append(frames, frame)
		}
	}
	return frames
}

// sequenceOf decodes the room.message a journaled Event carries.
func sequenceOf(t *testing.T, node *relayNode, eventID string) payload.RoomMessage {
	t.Helper()
	entry, found, err := node.d.journal.Lookup(eventID)
	if err != nil || !found {
		t.Fatalf("event %s: found=%v err=%v", eventID, found, err)
	}
	raw, err := entry.Payload()
	if err != nil {
		t.Fatal(err)
	}
	event, err := envelope.DecodeEventJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := payload.Decode(event.Kind, event.Content)
	message, ok := decoded.(payload.RoomMessage)
	if err != nil || !ok {
		t.Fatalf("not a room message: %v", err)
	}
	return message
}

// TestRoomOperatorFoundsAddsAndCarriesMessages drives the owner's
// operations end to end between two daemons: A founds the room, adds B
// through the 1:1 invite and KeyPackage, B installs the Welcome and the full
// roster A staged, and each seals messages the other opens.
func TestRoomOperatorFoundsAddsAndCarriesMessages(t *testing.T) {
	scene := newOperatorScene(t, 2)
	a, b := scene.nodes[0], scene.nodes[1]
	record := scene.founded(t)
	own, found, err := scene.rooms(0).ledger.RoomCredential(testRoomID, a.d.config.AgentID)
	if err != nil || !found {
		t.Fatalf("the founder's credential is not in the room's list: %v", err)
	}
	if record.AuthorityAgentID != a.d.config.AgentID || len(record.Members) != 1 || record.RoomEndsAtUnix != own.ExpiresAtUnix ||
		own.ExpiresAtUnix != a.d.prekeys.planner.delegation.ExpiresAtUnix {
		t.Fatalf("founded room: %+v, credential expires %d", record, own.ExpiresAtUnix)
	}
	if err := scene.rooms(0).CreateRoom(context.Background(), testRoomID); err != nil {
		t.Fatalf("a repeated create: %v", err)
	}

	scene.invited(t, 1)
	if answer := scene.joined(t, 1); answer.AckOutcome != relayframe.OutcomeAccepted {
		t.Fatalf("the room.key-package: %+v", answer)
	}
	after, _ := fused(t, a)
	if after.RoomEpoch != 2 || after.MLSEpoch != 1 || !after.Membership().Contains(b.d.config.AgentID) {
		t.Fatalf("the Add was not committed: %+v", after)
	}
	if adds, err := a.d.journal.RoomAdds(testRoomID, scene.clock.now()); err != nil || len(adds) != 0 {
		t.Fatalf("the add was not finished: %+v %v", adds, err)
	}
	if _, known, err := scene.rooms(0).ledger.RoomCredential(testRoomID, b.d.config.AgentID); err != nil || !known {
		t.Fatalf("the authority did not learn the joiner's credential: %v", err)
	}
	// With no earlier member besides the authority, the Add stages only the
	// joiner's Welcome and full roster.
	if heads, err := a.d.journal.RoomOutboxHeads(testRoomID); err != nil || len(heads) != 2 {
		t.Fatalf("staged objects: %d %v", len(heads), err)
	}
	welcome := outboxObject(t, a, eventlog.RoomObjectWelcome, b.d.config.AgentID)
	if ack := roomAckOf(t, b, deliverObject(t, a, b, welcome)); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("B's Welcome: %+v", ack)
	}
	roster := outboxObject(t, a, eventlog.RoomObjectRoster, b.d.config.AgentID)
	if ack := roomAckOf(t, b, deliverObject(t, a, b, roster)); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("B's full roster: %+v", ack)
	}
	joinedRecord, found := fused(t, b)
	if !found || joinedRecord.MLSEpoch != after.MLSEpoch || joinedRecord.RoomEndsAtUnix != after.RoomEndsAtUnix {
		t.Fatalf("B's room: %+v", joinedRecord)
	}

	// B seals; A opens it.
	first, fresh, err := scene.compose(t, 1, "hello room", "1")
	if err != nil || !fresh {
		t.Fatalf("B composes: fresh=%v %v", fresh, err)
	}
	frames := roomFrames(t, b, a.d.config.AgentID)
	if len(frames) != 1 {
		t.Fatalf("B deposited %d frames to A", len(frames))
	}
	if answer := deliver(t, b, a, frames[0].frame); answer.Result != carrierapi.ResultAdmitted {
		t.Fatalf("A opens B's message: %s/%s", answer.Result, answer.Code)
	}
	if message := sequenceOf(t, a, first); message.Sequence != 1 || message.Body != "hello room" {
		t.Fatalf("A journaled %+v", message)
	}
	send, found, err := b.d.journal.RoomApplicationSendFor(testRoomID, "idem_"+strings.Repeat("1", 64))
	if err != nil || !found || send.Members[0].State != eventlog.RoomDeliveryCarried {
		t.Fatalf("B's application record: %+v %v", send, err)
	}
	// A repeat under the same key is the same Event and no new deposit.
	if again, fresh, err := scene.compose(t, 1, "hello room", "1"); err != nil || fresh || again != first {
		t.Fatalf("a repeated composition: %s fresh=%v %v", again, fresh, err)
	}
	if frames := roomFrames(t, b, a.d.config.AgentID); len(frames) != 0 {
		t.Fatalf("a repeated composition deposited %d frames", len(frames))
	}
	// Another meaning under the same key is a conflict.
	if _, _, err := scene.compose(t, 1, "something else", "1"); !errors.Is(err, eventlog.ErrConflict) {
		t.Fatalf("another composition under a used key: %v", err)
	}
	second, _, err := scene.compose(t, 1, "second", "2")
	if err != nil {
		t.Fatal(err)
	}
	if answer := deliver(t, b, a, roomFrames(t, b, a.d.config.AgentID)[0].frame); answer.Result != carrierapi.ResultAdmitted {
		t.Fatalf("A opens B's second message: %s/%s", answer.Result, answer.Code)
	}
	if message := sequenceOf(t, a, second); message.Sequence != 2 {
		t.Fatalf("the second message has sequence %d", message.Sequence)
	}

	// A seals; B opens it.
	reply, _, err := scene.compose(t, 0, "hello B", "3")
	if err != nil {
		t.Fatal(err)
	}
	if answer := deliver(t, a, b, roomFrames(t, a, b.d.config.AgentID)[0].frame); answer.Result != carrierapi.ResultAdmitted {
		t.Fatalf("B opens A's message: %s/%s", answer.Result, answer.Code)
	}
	if message := sequenceOf(t, b, reply); message.Sequence != 1 {
		t.Fatalf("A's first message has sequence %d", message.Sequence)
	}
}

// TestRoomOperatorRemoveStagesTheCommitOnceToTheRemovedMember removes B:
// the next membership no longer names it, and the removing Commit is staged
// to B once, outside its queue.
func TestRoomOperatorRemoveStagesTheCommitOnceToTheRemovedMember(t *testing.T) {
	scene := newOperatorScene(t, 2)
	a, b := scene.nodes[0], scene.nodes[1]
	scene.founded(t)
	scene.invited(t, 1)
	scene.joined(t, 1)
	before, _ := fused(t, a)
	if err := scene.rooms(0).RemoveRoomMember(context.Background(), testRoomID, b.d.config.AgentID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	after, _ := fused(t, a)
	if after.Membership().Contains(b.d.config.AgentID) || after.RoomEpoch != before.RoomEpoch+1 || after.MLSEpoch != before.MLSEpoch+1 {
		t.Fatalf("after the Remove: %+v", after)
	}
	heads, err := a.d.journal.RoomOutboxHeads(testRoomID)
	if err != nil {
		t.Fatal(err)
	}
	var removing *eventlog.RoomOutboxHead
	for index := range heads {
		if heads[index].MLSEpoch == after.MLSEpoch {
			removing = &heads[index]
		}
	}
	if removing == nil || removing.Type != eventlog.RoomObjectCommit || len(removing.Members) != 1 ||
		removing.Members[0].AgentID != b.d.config.AgentID || !removing.Members[0].Once {
		t.Fatalf("the removing Commit: %+v", removing)
	}
	if _, known, err := scene.rooms(0).ledger.RoomCredential(testRoomID, b.d.config.AgentID); err != nil || known {
		t.Fatalf("the removed member's credential is still listed: %v", err)
	}
	// A member no longer in the room is a no-op.
	if err := scene.rooms(0).RemoveRoomMember(context.Background(), testRoomID, b.d.config.AgentID); err != nil {
		t.Fatalf("a repeated remove: %v", err)
	}
	if again, _ := fused(t, a); again.MLSEpoch != after.MLSEpoch {
		t.Fatal("a repeated remove made another Commit")
	}
	// With no member left to send to, a composition is refused.
	if _, _, err := scene.compose(t, 0, "alone", "4"); !errors.Is(err, errRoomNoOtherMember) {
		t.Fatalf("a composition with no other member: %v", err)
	}
}

// TestRoomOperatorRefusesWhatOnlyTheAuthorityMayDo refuses membership
// changes at a member, adding oneself or a member, and KeyPackages the owner
// never asked for.
func TestRoomOperatorRefusesWhatOnlyTheAuthorityMayDo(t *testing.T) {
	scene := newOperatorScene(t, 3)
	a, b, c := scene.nodes[0], scene.nodes[1], scene.nodes[2]
	scene.founded(t)
	scene.invited(t, 1)
	scene.joined(t, 1)
	welcome := outboxObject(t, a, eventlog.RoomObjectWelcome, b.d.config.AgentID)
	roomAckOf(t, b, deliverObject(t, a, b, welcome))
	roomAckOf(t, b, deliverObject(t, a, b, outboxObject(t, a, eventlog.RoomObjectRoster, b.d.config.AgentID)))

	if err := scene.rooms(1).AddRoomMember(context.Background(), testRoomID, c.d.config.AgentID); !errors.Is(err, ErrRoomNotAuthority) {
		t.Fatalf("a member adds: %v", err)
	}
	if err := scene.rooms(1).RemoveRoomMember(context.Background(), testRoomID, a.d.config.AgentID); !errors.Is(err, ErrRoomNotAuthority) {
		t.Fatalf("a member removes: %v", err)
	}
	if err := scene.rooms(0).AddRoomMember(context.Background(), testRoomID, a.d.config.AgentID); fault.CodeOf(err) != fault.CodePayloadMalformed {
		t.Fatalf("the authority adds itself: %v", err)
	}
	// Adding a member again is a no-op: no invite is sent.
	if err := scene.rooms(0).AddRoomMember(context.Background(), testRoomID, b.d.config.AgentID); err != nil {
		t.Fatalf("adding a member again: %v", err)
	}
	if _, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if frames := a.carrier.take(); len(frames) != 0 {
		t.Fatalf("adding a member again sent %d frames", len(frames))
	}

	// C was never added: its KeyPackage is refused and records nothing.
	before, _ := fused(t, a)
	keyPackage := keyPackageEvent(t, scene, 2)
	if _, err := c.d.sendDirectApplication(context.Background(), a.d.config.AgentID, "room.key-package", keyPackage,
		"idem_"+strings.Repeat("5", 64), uint64(scene.clock.now().Add(time.Hour).Unix())); err != nil {
		t.Fatal(err)
	}
	requireRefusedCopy(t, relayOne(t, c, a))
	if after, _ := fused(t, a); after.MLSEpoch != before.MLSEpoch {
		t.Fatal("an unasked KeyPackage made a Commit")
	}
	if adds, err := a.d.journal.RoomAdds(testRoomID, scene.clock.now()); err != nil || len(adds) != 0 {
		t.Fatalf("an unasked KeyPackage recorded an add: %+v %v", adds, err)
	}
}

// requireRefusedCopy requires a 1:1 copy whose room step failed to have
// been refused and relay-acknowledged, with nothing journaled.
func requireRefusedCopy(t *testing.T, answer carrierapi.Response) {
	t.Helper()
	if answer.Result != carrierapi.ResultRefused || answer.Code != carrierapi.CodeNotAccepted {
		t.Fatalf("answered %s/%s, want refused/not-accepted", answer.Result, answer.Code)
	}
}

// keyPackageEvent is the room.key-package a node would send for the test
// room: a freshly issued leaf of its own.
func keyPackageEvent(t *testing.T, scene *operatorScene, index int) []byte {
	t.Helper()
	leaf, err := scene.rooms(index).issueLeaf(0, scene.clock.now())
	if err != nil {
		t.Fatal(err)
	}
	content, err := payload.Encode(payload.RoomKeyPackage{RoomID: testRoomID, DeviceCredentialJSON: leaf.deviceJSON,
		LeafCredential: leaf.encoded})
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// TestRoomOperatorThirdMemberNeedsTheMembersCards records the open design
// question: a roster entry carries the member's chat card, and the daemon
// holds no peer's card, so the Add of a member into a room that already
// holds another is refused, reported, and left for the next pass.
func TestRoomOperatorThirdMemberNeedsTheMembersCards(t *testing.T) {
	scene := newOperatorScene(t, 3)
	a := scene.nodes[0]
	scene.founded(t)
	scene.invited(t, 1)
	scene.joined(t, 1)
	before, _ := fused(t, a)
	scene.invited(t, 2)
	scene.joined(t, 2)
	if after, _ := fused(t, a); after.MLSEpoch != before.MLSEpoch {
		t.Fatal("an Add whose rosters lack a member's card was committed")
	}
	if scene.reports[0].count(func(err error) bool { return errors.Is(err, ErrRoomMemberCardUnknown) }) == 0 {
		t.Fatal("the missing card was not reported")
	}
	if adds, err := a.d.journal.RoomAdds(testRoomID, scene.clock.now()); err != nil || len(adds) != 1 || !adds[0].Ready() {
		t.Fatalf("the ready add was not kept for the next pass: %+v %v", adds, err)
	}
}

// TestRoomOperatorStopsNearTheRoomEnd applies D18 on the sender side: no
// membership change within the last re-deposit interval before the end
// minus the skew, and no sealing from the end minus the skew.
func TestRoomOperatorStopsNearTheRoomEnd(t *testing.T) {
	scene := newOperatorScene(t, 2)
	b := scene.nodes[1]
	record := scene.founded(t)
	scene.invited(t, 1)
	scene.joined(t, 1)
	end := time.Unix(int64(record.RoomEndsAtUnix), 0)
	lastHandshake := end.Add(-5 * time.Minute).Add(-MinRelayRedepositInterval)
	scene.clock.set(lastHandshake.Add(-time.Second))
	if _, err := scene.rooms(0).inviteExpiry(record, scene.clock.now()); err != nil {
		t.Fatalf("one second before the last handshake: %v", err)
	}
	scene.clock.set(lastHandshake)
	if err := scene.rooms(0).RemoveRoomMember(context.Background(), testRoomID, b.d.config.AgentID); !errors.Is(err, ErrRoomHandshakeTooLate) {
		t.Fatalf("a remove in the last interval: %v", err)
	}
	if err := scene.rooms(0).AddRoomMember(context.Background(), testRoomID, scene.nodes[1].d.config.AgentID); !errors.Is(err, ErrRoomHandshakeTooLate) {
		t.Fatalf("an add in the last interval: %v", err)
	}
	scene.clock.set(end.Add(-5*time.Minute - time.Second))
	if _, _, err := scene.compose(t, 0, "just in time", "6"); err != nil {
		t.Fatalf("a seal one second before the end minus the skew: %v", err)
	}
	scene.clock.set(end.Add(-5 * time.Minute))
	if _, _, err := scene.compose(t, 0, "too late", "7"); fault.CodeOf(err) != fault.CodeRoomEnded {
		t.Fatalf("a seal at the end minus the skew: %v", err)
	}
}

// TestRoomOperatorJoinerCredentialMustLastUntilTheEnd refuses, at the
// authority, a KeyPackage whose leaf credential ends before the room does
// (D18), and records nothing.
func TestRoomOperatorJoinerCredentialMustLastUntilTheEnd(t *testing.T) {
	scene := newOperatorScene(t, 2)
	a, b := scene.nodes[0], scene.nodes[1]
	record := scene.founded(t)
	scene.invited(t, 1)
	short := keyPackageWith(t, scene, 1, func(credential *group.LeafCredential) {
		credential.ExpiresAtUnix = record.RoomEndsAtUnix - 1
	})
	if _, err := b.d.sendDirectApplication(context.Background(), a.d.config.AgentID, "room.key-package", short,
		"idem_"+strings.Repeat("8", 64), uint64(scene.clock.now().Add(time.Hour).Unix())); err != nil {
		t.Fatal(err)
	}
	requireRefusedCopy(t, relayOne(t, b, a))
	if adds, err := a.d.journal.RoomAdds(testRoomID, scene.clock.now()); err != nil || len(adds) != 1 || adds[0].Ready() {
		t.Fatalf("a short credential was recorded: %+v %v", adds, err)
	}
}

// keyPackageWith is keyPackageEvent with the leaf and device credentials
// changed before they are signed.
func keyPackageWith(t *testing.T, scene *operatorScene, index int, mutate func(*group.LeafCredential)) []byte {
	t.Helper()
	node := scene.nodes[index]
	member := newRoomMemberWith(t, scene.driver, node, scene.clock.now(), time.Unix(int64(node.d.prekeys.planner.delegation.ExpiresAtUnix), 0), mutate)
	encoded, err := group.EncodeLeafCredential(member.credential)
	if err != nil {
		t.Fatal(err)
	}
	content, err := payload.Encode(payload.RoomKeyPackage{RoomID: testRoomID, DeviceCredentialJSON: member.deviceJSON,
		LeafCredential: encoded})
	if err != nil {
		t.Fatal(err)
	}
	return content
}
