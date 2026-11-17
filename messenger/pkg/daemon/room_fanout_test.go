package daemon

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// The fan-out tests run the authority's queues against real receivers: the
// authority deposits through its recording carrier, the test hands each
// deposit to the member, and the member's room ack goes back through the
// authority's carrier.delivery-ack.

// newFanoutScene is a room A founded with B's Add committed; the
// authority runs with a short handshake retention.
func newFanoutScene(t *testing.T, count int, retention time.Duration) *operatorScene {
	t.Helper()
	scene := newOperatorSceneWith(t, count, retention)
	scene.founded(t)
	scene.invited(t, 1)
	if answer := scene.joined(t, 1); answer.AckOutcome != relayframe.OutcomeAccepted {
		t.Fatalf("B's room.key-package: %+v", answer)
	}
	return scene
}

// objectsTo takes the kind-3 objects a node deposited to a recipient, as
// whole frame sets per object digest, in deposit order.
func objectsTo(t *testing.T, node *relayNode, recipient string) [][]carried {
	t.Helper()
	frames := takeFrames(t, node, func(frame relayframe.Frame, to string) bool {
		return frame.Kind == relayframe.KindRoom && to == recipient
	})
	var order [][32]byte
	byDigest := map[[32]byte][]carried{}
	for _, frame := range frames {
		decoded, err := relayframe.Decode(frame.frame)
		if err != nil {
			t.Fatal(err)
		}
		if _, seen := byDigest[decoded.ObjectDigest]; !seen {
			order = append(order, decoded.ObjectDigest)
		}
		byDigest[decoded.ObjectDigest] = append(byDigest[decoded.ObjectDigest], frame)
	}
	objects := make([][]carried, 0, len(order))
	for _, digest := range order {
		objects = append(objects, byDigest[digest])
	}
	return objects
}

// handOver delivers one deposited object to its member and returns the
// member's answer to the last part.
func handOver(t *testing.T, from, to *relayNode, object []carried) carrierapi.Response {
	t.Helper()
	frames := make([][]byte, 0, len(object))
	for _, frame := range object {
		frames = append(frames, frame.frame)
	}
	return send(t, to, from.d.config.AgentID, frames)
}

// ackBack hands a member's room ack to the authority.
func ackBack(t *testing.T, authority, member *relayNode, answer carrierapi.Response) carrierapi.Response {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(answer.AckFrameBase64)
	if err != nil || answer.Result != carrierapi.ResultAck {
		t.Fatalf("no room ack: %s/%s %v", answer.Result, answer.Code, err)
	}
	return authority.d.relay.DeliveryAck(context.Background(), member.d.config.AgentID, raw)
}

func memberDelivery(t *testing.T, node *relayNode, kind eventlog.RoomObjectType, member string) (eventlog.RoomMemberDelivery, bool) {
	t.Helper()
	heads, err := node.d.journal.RoomOutboxHeads(testRoomID)
	if err != nil {
		t.Fatal(err)
	}
	for _, head := range heads {
		if head.Type != kind {
			continue
		}
		if delivery, found := head.Member(member); found {
			return delivery, true
		}
	}
	return eventlog.RoomMemberDelivery{}, false
}

// A member's queue holds one object in flight: the Welcome first, its
// roster only after a verified room ack, and both settle delivered.
func TestRoomFanOutDeliversEachMembersQueueInOrderOnVerifiedAcks(t *testing.T) {
	scene := newFanoutScene(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	objects := objectsTo(t, a, agent)
	if len(objects) != 1 {
		t.Fatalf("%d objects in flight to B, want the Welcome alone", len(objects))
	}
	if welcome, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent); welcome.State != eventlog.RoomDeliveryCarried ||
		welcome.Generation != 1 || welcome.NextRedepositAtUnix == 0 {
		t.Fatalf("the Welcome's delivery: %+v", welcome)
	}
	if roster, _ := memberDelivery(t, a, eventlog.RoomObjectRoster, agent); roster.State != eventlog.RoomDeliveryPending {
		t.Fatalf("the roster left before the Welcome's ack: %+v", roster)
	}
	answer := handOver(t, a, b, objects[0])
	if applied := ackBack(t, a, b, answer); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("the Welcome's ack: %+v", applied)
	}
	if _, found := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent); found {
		t.Fatal("the delivered Welcome is still held")
	}
	// The ack released the roster at once.
	objects = objectsTo(t, a, agent)
	if len(objects) != 1 {
		t.Fatalf("%d objects after the Welcome's ack, want the roster", len(objects))
	}
	answer = handOver(t, a, b, objects[0])
	if applied := ackBack(t, a, b, answer); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("the roster's ack: %+v", applied)
	}
	if heads, err := a.d.journal.RoomMemberQueue(testRoomID, agent); err != nil || len(heads) != 0 {
		t.Fatalf("B's queue after both acks: %d %v", len(heads), err)
	}
	// The same ack again changes nothing.
	if again := ackBack(t, a, b, answer); again.Result != carrierapi.ResultIgnored {
		t.Fatalf("a repeated ack: %+v", again)
	}
}

// A room ack settles only its packet sender's own slot, under that
// member's finalized Endpoint key: another member's ack of B's object, and
// an ack signed by another key, settle nothing.
func TestRoomFanOutAppliesOnlyTheMembersOwnVerifiedAck(t *testing.T) {
	scene := newFanoutScene(t, 3, roomRetention)
	a, b, c := scene.nodes[0], scene.nodes[1], scene.nodes[2]
	objects := objectsTo(t, a, b.d.config.AgentID)
	answer := handOver(t, a, b, objects[0])
	raw, _ := base64.StdEncoding.DecodeString(answer.AckFrameBase64)
	frame, err := relayframe.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := relayframe.DecodeRoomAck(frame.Part)
	if err != nil {
		t.Fatal(err)
	}
	// Signed by C's key over B's Endpoint and device: refused.
	forged, err := relayframe.SignRoomAck(ack, c.key)
	if err != nil {
		t.Fatal(err)
	}
	frame.Part, _ = relayframe.EncodeRoomAck(forged)
	encoded, err := relayframe.Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	if refused := a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, encoded); refused.Result != carrierapi.ResultRefused {
		t.Fatalf("an ack signed by another key: %+v", refused)
	}
	// B's genuine ack presented as C's: C is no member, nothing is settled.
	if ignored := a.d.relay.DeliveryAck(context.Background(), c.d.config.AgentID, raw); ignored.Result == carrierapi.ResultApplied {
		t.Fatalf("another Agent's presentation of B's ack: %+v", ignored)
	}
	if welcome, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, b.d.config.AgentID); welcome.State != eventlog.RoomDeliveryCarried {
		t.Fatalf("a refused ack settled the Welcome: %+v", welcome)
	}
	if applied := ackBack(t, a, b, answer); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("B's own ack: %+v", applied)
	}
}

// signedRoomAck is a member's room ack of an object with the given outcome.
func signedRoomAck(t *testing.T, member *relayNode, object []carried, outcome string, code fault.Code, stateless bool) []byte {
	t.Helper()
	first, err := relayframe.Decode(object[0].frame)
	if err != nil {
		t.Fatal(err)
	}
	ack := relayframe.RoomAck{RoomID: testRoomID, ObjectDigest: first.ObjectDigest, RecipientEndpointID: member.d.config.EndpointID,
		RecipientDeviceID: member.d.config.DeviceID, MLSEpoch: 1, EpochAuthenticator: []byte(strings.Repeat("\x07", 32)),
		Outcome: outcome, Code: code, AckedAtUnix: uint64(member.d.clock().Unix())}
	if stateless {
		ack.MLSEpoch, ack.EpochAuthenticator = 0, nil
	}
	signed, err := relayframe.SignRoomAck(ack, member.key)
	if err != nil {
		t.Fatal(err)
	}
	part, err := relayframe.EncodeRoomAck(signed)
	if err != nil {
		t.Fatal(err)
	}
	evidence, _, _ := evidenceOf(t, member)
	frame, err := relayframe.Encode(relayframe.Frame{Kind: relayframe.KindDeliveryAck, PartIndex: 0, PartCount: 1,
		Evidence: evidence, Part: part})
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

// A rejected ack stops the member's queue with an owner notice; a
// stateless rejection of a roster is lost state.
func TestRoomFanOutStopsTheQueueOnARejection(t *testing.T) {
	scene := newFanoutScene(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	welcome := objectsTo(t, a, agent)[0]
	if applied := ackBack(t, a, b, handOver(t, a, b, welcome)); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("the Welcome's ack: %+v", applied)
	}
	roster := objectsTo(t, a, agent)[0]
	lost := signedRoomAck(t, b, roster, relayframe.OutcomeRejected, fault.CodeNotAuthentic, true)
	if applied := a.d.relay.DeliveryAck(context.Background(), agent, lost); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("a stateless rejection of the roster: %+v", applied)
	}
	if scene.reports[0].count(func(err error) bool { return errors.Is(err, ErrRoomMemberLostState) }) != 1 {
		t.Fatal("the lost state was not reported")
	}
	if delivery, _ := memberDelivery(t, a, eventlog.RoomObjectRoster, agent); delivery.State != eventlog.RoomDeliveryRejected && delivery.State != "" {
		t.Fatalf("the roster after the rejection: %+v", delivery)
	}
	// B's queue stopped: an MLS-only refresh is staged but never deposited.
	record, _ := fused(t, a)
	if stopped, err := scene.rooms(0).queueStopped(testRoomID, agent); err != nil || !stopped {
		t.Fatalf("B's queue did not stop (room at MLS epoch %d)", record.MLSEpoch)
	}
}

func mustHeads(t *testing.T, node *relayNode) []eventlog.RoomOutboxHead {
	t.Helper()
	heads, err := node.d.journal.RoomOutboxHeads(testRoomID)
	if err != nil {
		t.Fatal(err)
	}
	return heads
}

// An object not acknowledged is re-deposited at 80 % of the smallest relay
// TTL (10-minute floor), every part under the next generation whose carry
// withdraws the previous one.
func TestRoomFanOutRedepositsUnackedObjectsAndWithdrawsTheLastGeneration(t *testing.T) {
	scene := newFanoutScene(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	first := objectsTo(t, a, agent)[0]
	welcome, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent)
	scene.clock.set(time.Unix(int64(welcome.NextRedepositAtUnix), 0).Add(-time.Second))
	scene.rooms(0).maintain()
	if early := objectsTo(t, a, agent); len(early) != 0 {
		t.Fatal("re-deposited before its time")
	}
	scene.clock.set(time.Unix(int64(welcome.NextRedepositAtUnix), 0))
	scene.rooms(0).maintain()
	again := objectsTo(t, a, agent)
	if len(again) != 1 || len(again[0]) != len(first) {
		t.Fatalf("the re-deposit: %d objects", len(again))
	}
	digest, _ := relayframe.Decode(first[0].frame)
	for index := range again[0] {
		key, _ := relayframe.RoomIdempotencyKey(eventlogDigest(digest.ObjectDigest), agent, 2, uint8(index))
		withdraw, _ := relayframe.RoomIdempotencyKey(eventlogDigest(digest.ObjectDigest), agent, 1, uint8(index))
		if again[0][index].key != key || again[0][index].withdraw != withdraw || first[index].key != withdraw {
			t.Fatalf("part %d: key %s withdraw %s", index, again[0][index].key, again[0][index].withdraw)
		}
	}
	if delivery, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent); delivery.Generation != 2 {
		t.Fatalf("the generation after the re-deposit: %+v", delivery)
	}
	// The second generation's object is byte-identical: B accepts it.
	if applied := ackBack(t, a, b, handOver(t, a, b, again[0])); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("the re-deposited Welcome's ack: %+v", applied)
	}
}

func eventlogDigest(digest [32]byte) string { return hex.EncodeToString(digest[:]) }

// An object not acknowledged within the handshake retention abandons the
// member with retention-exceeded and an owner notice, and its queue stops.
func TestRoomFanOutAbandonsAMemberAtTheRetentionEnd(t *testing.T) {
	scene := newFanoutScene(t, 2, 20*time.Minute)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	objectsTo(t, a, agent)
	welcome := mustHeads(t, a)[0]
	scene.clock.set(time.Unix(int64(welcome.RetainUntilUnix), 0))
	scene.rooms(0).maintain()
	if delivery, found := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent); found &&
		(delivery.State != eventlog.RoomDeliveryAbandoned || delivery.Code != fault.CodeRetentionExceeded) {
		t.Fatalf("the Welcome at the retention end: %+v", delivery)
	}
	if scene.reports[0].count(func(err error) bool { return errors.Is(err, ErrRoomMemberRetention) }) != 1 {
		t.Fatal("the retention end was not reported")
	}
	if objects := objectsTo(t, a, agent); len(objects) != 0 {
		t.Fatalf("a stopped queue deposited %d objects", len(objects))
	}
}

// A deposit the carrier answers with retry (a full mailbox) waits 30 s,
// then doubles; the same generation is deposited again.
func TestRoomFanOutBacksOffAfterRetry(t *testing.T) {
	scene := newOperatorSceneWith(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	retry := carrierapi.Retry()
	a.carrier.mutex.Lock()
	a.carrier.answer = &retry
	a.carrier.mutex.Unlock()
	scene.founded(t)
	scene.invited(t, 1)
	scene.joined(t, 1)
	agent := b.d.config.AgentID
	tried := objectsTo(t, a, agent)
	if len(tried) != 1 {
		t.Fatalf("%d deposits tried", len(tried))
	}
	if welcome, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent); welcome.State != eventlog.RoomDeliveryPending {
		t.Fatalf("a retried deposit was recorded carried: %+v", welcome)
	}
	start := scene.clock.now()
	scene.clock.set(start.Add(handshakeBackoffBase - time.Second))
	scene.rooms(0).maintain()
	if early := objectsTo(t, a, agent); len(early) != 0 {
		t.Fatal("a retried deposit was tried again within the backoff")
	}
	a.carrier.mutex.Lock()
	a.carrier.answer = nil
	a.carrier.mutex.Unlock()
	scene.clock.set(start.Add(handshakeBackoffBase))
	scene.rooms(0).maintain()
	again := objectsTo(t, a, agent)
	if len(again) != 1 || again[0][0].key != tried[0][0].key {
		t.Fatal("the retried generation was not deposited again under the same key")
	}
	if welcome, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent); welcome.State != eventlog.RoomDeliveryCarried || welcome.Generation != 1 {
		t.Fatalf("after the retry: %+v", welcome)
	}
}

// Before every handshake deposit the member's stored evidence passes
// CheckPeer pinned to its leaf credential; a failing member gets nothing
// and its evidence pull starts.
func TestRoomFanOutChecksTheMembersEvidenceBeforeEveryDeposit(t *testing.T) {
	scene := newFanoutScene(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	objectsTo(t, a, agent)
	good, _, err := a.d.journal.LoadRelayEvidence(agent)
	if err != nil {
		t.Fatal(err)
	}
	now := scene.clock.now()
	other := evidenceFor(t, b, "dev_"+strings.Repeat("9", 64), uint64(now.Unix()), uint64(now.Add(30*time.Minute).Unix()))
	if err := a.d.journal.StoreRelayEvidence(agent, other, canon.Digest(good), now); err != nil {
		t.Fatal(err)
	}
	welcome, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent)
	scene.clock.set(time.Unix(int64(welcome.NextRedepositAtUnix), 0))
	scene.rooms(0).maintain()
	if objects := objectsTo(t, a, agent); len(objects) != 0 {
		t.Fatalf("a member whose evidence fails got %d objects", len(objects))
	}
	if pull, _, err := a.d.journal.LoadRelayPull(agent); err != nil || !pull.Requested {
		t.Fatalf("the evidence pull did not start: %+v %v", pull, err)
	}
}

// Removing a member withdraws its in-flight generations and abandons its
// slots; the removing Commit goes once.
func TestRoomFanOutRemoveWithdrawsTheRemovedMembersGenerations(t *testing.T) {
	scene := newFanoutScene(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	welcome := objectsTo(t, a, agent)[0]
	if err := scene.rooms(0).RemoveRoomMember(context.Background(), testRoomID, agent); err != nil {
		t.Fatal(err)
	}
	withdrawn := a.carrier.withdrawals()
	if len(withdrawn) != len(welcome) {
		t.Fatalf("%d withdrawals, want the Welcome's %d parts", len(withdrawn), len(welcome))
	}
	for index, frame := range welcome {
		if withdrawn[index].key != frame.key || withdrawn[index].recipient != agent {
			t.Fatalf("withdrawal %d: %+v", index, withdrawn[index])
		}
	}
	for _, head := range mustHeads(t, a) {
		if delivery, found := head.Member(agent); found && !delivery.Once &&
			(delivery.State == eventlog.RoomDeliveryPending || delivery.State == eventlog.RoomDeliveryCarried) {
			t.Fatalf("the removed member still has a live slot: %+v", delivery)
		}
	}
	if commits := roomObjectFrames(t, a, agent, relayframe.RoomCommit); len(commits) == 0 {
		t.Fatal("the removing Commit was not deposited")
	}
}

// The authority's queues stop at the room's end minus the skew (D18).
func TestRoomFanOutStopsAtTheEndMinusTheSkew(t *testing.T) {
	scene := newFanoutScene(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	objectsTo(t, a, agent)
	record, _ := fused(t, a)
	scene.clock.set(time.Unix(int64(record.RoomEndsAtUnix), 0).Add(-5 * time.Minute))
	scene.rooms(0).maintain()
	if objects := objectsTo(t, a, agent); len(objects) != 0 {
		t.Fatalf("the queue deposited %d objects at the end minus the skew", len(objects))
	}
}

// A handshake object waiting for its first deposit goes before an
// application object to the same member.
func TestRoomFanOutHandshakeGoesBeforeApplication(t *testing.T) {
	scene := newOperatorSceneWith(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	capped := carrierapi.Refusal(carrierapi.CodePeerCap)
	scene.founded(t)
	scene.invited(t, 1)
	a.carrier.mutex.Lock()
	a.carrier.answer = &capped
	a.carrier.mutex.Unlock()
	scene.joined(t, 1)
	// The cap left B's Welcome pending at the head of its queue.
	if welcome, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent); welcome.State != eventlog.RoomDeliveryPending {
		t.Fatalf("the capped Welcome: %+v", welcome)
	}
	a.carrier.mutex.Lock()
	a.carrier.answer = nil
	a.carrier.mutex.Unlock()
	takeFrames(t, a, func(relayframe.Frame, string) bool { return true })
	if _, _, err := scene.compose(t, 0, "behind the handshake", "c"); err != nil {
		t.Fatal(err)
	}
	if frames := roomFrames(t, a, agent); len(frames) != 0 {
		t.Fatal("an application object went before a pending handshake object")
	}
	if delivery := applicationMember(t, a, idem("c"), agent); delivery.State != eventlog.RoomDeliveryPending {
		t.Fatalf("the deferred application object: %+v", delivery)
	}
}
