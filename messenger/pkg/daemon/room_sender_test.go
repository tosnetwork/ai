package daemon

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/payload"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// twoMemberRoom is a room A founded and B joined through the Welcome and
// full roster A staged.
func twoMemberRoom(t *testing.T) *operatorScene {
	t.Helper()
	scene := newOperatorScene(t, 2)
	a, b := scene.nodes[0], scene.nodes[1]
	scene.founded(t)
	scene.invited(t, 1)
	if answer := scene.joined(t, 1); answer.AckOutcome != relayframe.OutcomeAccepted {
		t.Fatalf("the room.key-package: %+v", answer)
	}
	if ack := roomAckOf(t, b, deliverObject(t, a, b, outboxObject(t, a, eventlog.RoomObjectWelcome, b.d.config.AgentID))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("B's Welcome: %+v", ack)
	}
	if ack := roomAckOf(t, b, deliverObject(t, a, b, outboxObject(t, a, eventlog.RoomObjectRoster, b.d.config.AgentID))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("B's full roster: %+v", ack)
	}
	return scene
}

func idem(digit string) string { return "idem_" + strings.Repeat(digit, 64) }

// applicationMember returns one member's delivery of a composition.
func applicationMember(t *testing.T, node *relayNode, key, member string) eventlog.RoomApplicationMember {
	t.Helper()
	send, found, err := node.d.journal.RoomApplicationSendFor(testRoomID, key)
	if err != nil || !found {
		t.Fatalf("application record %s: %v", key, err)
	}
	for _, delivery := range send.Members {
		if delivery.AgentID == member {
			return delivery
		}
	}
	t.Fatalf("the composition is not addressed to %s", member)
	return eventlog.RoomApplicationMember{}
}

// The sender's object binds exactly what a receiver checks: the AAD's room,
// epochs, epoch authenticator, sender and Event, a sequence counting from 1,
// one part under the production cut with the sender's card and evidence.
func TestRoomSenderObjectBindsWhatReceiversCheck(t *testing.T) {
	scene := twoMemberRoom(t)
	a, b := scene.nodes[0], scene.nodes[1]
	eventID, _, err := scene.compose(t, 1, "bound", "1")
	if err != nil {
		t.Fatal(err)
	}
	frames := roomFrames(t, b, a.d.config.AgentID)
	if len(frames) != 1 {
		t.Fatalf("%d frames", len(frames))
	}
	frame, err := relayframe.Decode(frames[0].frame)
	if err != nil || frame.PartCount != 1 || len(frame.Card) == 0 || len(frame.Evidence) == 0 {
		t.Fatalf("the application frame: parts=%d card=%d evidence=%d %v", frame.PartCount, len(frame.Card), len(frame.Evidence), err)
	}
	object, err := relayframe.DecodeRoomObject(frame.Part)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := fused(t, b)
	if object.Type != relayframe.RoomApplication || object.RoomEpoch != record.RoomEpoch || object.MLSEpoch != record.MLSEpoch ||
		object.Header != nil {
		t.Fatalf("the object: %+v", object)
	}
	key, _ := relayframe.RoomIdempotencyKey(eventlog.RoomObjectDigest(frame.Part), a.d.config.AgentID, 1, 0)
	if frames[0].key != key || frames[0].withdraw != "" {
		t.Fatalf("the deposit's keys: %+v", frames[0])
	}
	// A opens it through the receiver of #41, which checks every AAD field.
	if answer := deliver(t, b, a, frames[0].frame); answer.Result != carrierapi.ResultAdmitted {
		t.Fatalf("A refused B's object: %s/%s", answer.Result, answer.Code)
	}
	if message := sequenceOf(t, a, eventID); message.Sequence != 1 || message.Epoch != record.RoomEpoch {
		t.Fatalf("the sealed message: %+v", message)
	}
	if delivery := applicationMember(t, b, idem("1"), a.d.config.AgentID); delivery.State != eventlog.RoomDeliveryCarried ||
		delivery.EvidenceDigest != canon.Digest(frame.Evidence) {
		t.Fatalf("A's delivery: %+v", delivery)
	}
}

// Before every deposit the sender runs CheckPeer on the member's stored
// evidence pinned to its leaf credential: a member whose evidence fails
// gets nothing, the evidence pull starts, and the object stays pending until
// the evidence verifies again.
func TestRoomSenderChecksEachRecipientsEvidenceBeforeTheDeposit(t *testing.T) {
	scene := twoMemberRoom(t)
	a, b := scene.nodes[0], scene.nodes[1]
	good, found, err := a.d.journal.LoadRelayEvidence(b.d.config.AgentID)
	if err != nil || !found {
		t.Fatalf("A holds no evidence of B: %v", err)
	}
	now := scene.clock.now()
	// B's stored evidence now names another device than its credential.
	other := evidenceFor(t, b, "dev_"+strings.Repeat("9", 64), uint64(now.Unix()), uint64(now.Add(30*time.Minute).Unix()))
	if err := a.d.journal.StoreRelayEvidence(b.d.config.AgentID, other, canon.Digest(good), now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := scene.compose(t, 0, "held", "2"); err != nil {
		t.Fatal(err)
	}
	if frames := roomFrames(t, a, b.d.config.AgentID); len(frames) != 0 {
		t.Fatalf("a member whose evidence fails got %d frames", len(frames))
	}
	if delivery := applicationMember(t, a, idem("2"), b.d.config.AgentID); delivery.State != eventlog.RoomDeliveryPending ||
		delivery.NextAttemptAtUnix <= uint64(now.Unix()) {
		t.Fatalf("B's delivery: %+v", delivery)
	}
	if pull, _, err := a.d.journal.LoadRelayPull(b.d.config.AgentID); err != nil || !pull.Requested {
		t.Fatalf("the evidence pull did not start: %+v %v", pull, err)
	}
	// The evidence verifies again; the next pass deposits.
	if err := a.d.journal.StoreRelayEvidence(b.d.config.AgentID, good, canon.Digest(other), now); err != nil {
		t.Fatal(err)
	}
	scene.clock.set(now.Add(relayEvidenceRetry))
	scene.rooms(0).maintain()
	if frames := roomFrames(t, a, b.d.config.AgentID); len(frames) != 1 {
		t.Fatalf("the repaired member got %d frames", len(frames))
	}
	if delivery := applicationMember(t, a, idem("2"), b.d.config.AgentID); delivery.State != eventlog.RoomDeliveryCarried {
		t.Fatalf("B's delivery after the repair: %+v", delivery)
	}
}

// A peer-cap or retry answer leaves the object pending, never dropped; a
// member never reached is abandoned when the object's retention ends.
func TestRoomSenderKeepsCappedObjectsPendingUntilTheirRetentionEnds(t *testing.T) {
	scene := twoMemberRoom(t)
	a, b := scene.nodes[0], scene.nodes[1]
	capped := carrierapi.Refusal(carrierapi.CodePeerCap)
	a.carrier.mutex.Lock()
	a.carrier.answer = &capped
	a.carrier.mutex.Unlock()
	if _, _, err := scene.compose(t, 0, "capped", "3"); err != nil {
		t.Fatal(err)
	}
	if delivery := applicationMember(t, a, idem("3"), b.d.config.AgentID); delivery.State != eventlog.RoomDeliveryPending {
		t.Fatalf("a capped deposit: %+v", delivery)
	}
	retry := carrierapi.Retry()
	a.carrier.mutex.Lock()
	a.carrier.answer = &retry
	a.carrier.mutex.Unlock()
	scene.clock.set(scene.clock.now().Add(relayCapRetry))
	scene.rooms(0).maintain()
	if delivery := applicationMember(t, a, idem("3"), b.d.config.AgentID); delivery.State != eventlog.RoomDeliveryPending {
		t.Fatalf("a deposit answered retry: %+v", delivery)
	}
	if len(roomFrames(t, a, b.d.config.AgentID)) != 2 {
		t.Fatal("the pending deposit was not tried again")
	}
	send, _, _ := a.d.journal.RoomApplicationSendFor(testRoomID, idem("3"))
	scene.clock.set(time.Unix(int64(send.AbandonAtUnix), 0))
	scene.rooms(0).maintain()
	if delivery := applicationMember(t, a, idem("3"), b.d.config.AgentID); delivery.State != eventlog.RoomDeliveryAbandoned ||
		delivery.Code != fault.CodeRetentionExceeded {
		t.Fatalf("a member never reached: %+v", delivery)
	}
	if kept, _, _ := a.d.journal.RoomApplicationSendFor(testRoomID, idem("3")); kept.ObjectBase64 != "" {
		t.Fatal("the object was kept past its retention")
	}
}

// A crash after the sequence was reserved and before the object was
// recorded is finished at the next pass: the same Event is sealed under the
// same sequence, and the receiver opens it. An intent whose room epoch moved
// on is dropped instead.
func TestRoomSenderFinishesASealACrashLeft(t *testing.T) {
	scene := twoMemberRoom(t)
	a, b := scene.nodes[0], scene.nodes[1]
	record, _ := fused(t, b)
	content, err := payload.Encode(payload.RoomMessage{RoomID: testRoomID, Epoch: record.RoomEpoch,
		MediaType: "text/plain; charset=utf-8", Body: "after a crash", Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := scene.clock.now()
	event, err := envelope.NewEvent(envelope.Event{Network: b.d.config.Network(), ConversationID: "conv_" + strings.Repeat("c3", 32),
		SenderAgentID: b.d.config.AgentID, SenderEndpointID: b.d.config.EndpointID, SenderDeviceID: b.d.config.DeviceID,
		RoomID: testRoomID, CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		Kind: "room.message", Content: content})
	if err != nil {
		t.Fatal(err)
	}
	plaintext, _ := envelope.EncodeEventJSON(event)
	intent := eventlog.RoomSealIntent{IdempotencyKey: idem("4"), IntentDigest: canon.Digest([]byte("intent")), EventID: event.EventID,
		EventBase64: base64.StdEncoding.EncodeToString(plaintext), Sequence: 1, RoomEpoch: record.RoomEpoch, ReservedAtUnix: uint64(now.Unix())}
	if err := b.d.journal.ReserveRoomSeal(testRoomID, intent); err != nil {
		t.Fatal(err)
	}
	scene.rooms(1).maintain()
	send, found, err := b.d.journal.RoomApplicationSendFor(testRoomID, idem("4"))
	if err != nil || !found || send.EventID != event.EventID || send.Sequence != 1 {
		t.Fatalf("the finished seal: %+v %v", send, err)
	}
	frames := roomFrames(t, b, a.d.config.AgentID)
	if len(frames) != 1 {
		t.Fatalf("%d frames", len(frames))
	}
	if answer := deliver(t, b, a, frames[0].frame); answer.Result != carrierapi.ResultAdmitted {
		t.Fatalf("A refused the finished seal: %s/%s", answer.Result, answer.Code)
	}
	// The next composition takes the next sequence.
	next, _, err := scene.compose(t, 1, "next", "5")
	if err != nil {
		t.Fatal(err)
	}
	if answer := deliver(t, b, a, roomFrames(t, b, a.d.config.AgentID)[0].frame); answer.Result != carrierapi.ResultAdmitted {
		t.Fatalf("A refused the next message: %s/%s", answer.Result, answer.Code)
	}
	if message := sequenceOf(t, a, next); message.Sequence != 2 {
		t.Fatalf("the next message has sequence %d", message.Sequence)
	}

	// An intent of an earlier room epoch is dropped: its sequence is used.
	stale := intent
	stale.IdempotencyKey, stale.Sequence, stale.RoomEpoch = idem("6"), 3, record.RoomEpoch-1
	if err := b.d.journal.ReserveRoomSeal(testRoomID, stale); err != nil {
		t.Fatal(err)
	}
	scene.rooms(1).maintain()
	if _, found, err := b.d.journal.RoomApplicationSendFor(testRoomID, idem("6")); err != nil || found {
		t.Fatalf("a stale intent was sealed: %v %v", found, err)
	}
	if last, pending, err := b.d.journal.RoomSendState(testRoomID); err != nil || pending != nil || last != 3 {
		t.Fatalf("after the stale intent: last=%d pending=%+v %v", last, pending, err)
	}
}

// A removed member gets the removing Commit once and marks the room removed;
// it then seals nothing more there.
func TestRoomSenderRemovedMemberSealsNothing(t *testing.T) {
	scene := twoMemberRoom(t)
	a, b := scene.nodes[0], scene.nodes[1]
	if err := scene.rooms(0).RemoveRoomMember(context.Background(), testRoomID, b.d.config.AgentID); err != nil {
		t.Fatal(err)
	}
	after, _ := fused(t, a)
	heads, err := a.d.journal.RoomOutboxHeads(testRoomID)
	if err != nil {
		t.Fatal(err)
	}
	for _, head := range heads {
		if head.MLSEpoch != after.MLSEpoch {
			continue
		}
		object, err := a.d.journal.RoomOutboxObject(head.ObjectDigest)
		if err != nil {
			t.Fatal(err)
		}
		deliverObject(t, a, b, object)
	}
	if _, removed, err := b.d.journal.RoomRemovalOf(testRoomID); err != nil || !removed {
		t.Fatalf("the removing Commit was not taken as a removal notice: %v", err)
	}
	if _, _, err := scene.compose(t, 1, "after removal", "7"); fault.CodeOf(err) != fault.CodeNotARoomMember {
		t.Fatalf("a removed member seals: %v", err)
	}
}

// The KeyPackage's DeviceCredential must bind under finalized state: one
// naming another device set than the member's current one is refused at
// the add, the one point the set's digest is compared (section 11.8).
func TestRoomKeyPackageWithAStaleDeviceSetIsRefused(t *testing.T) {
	scene := newOperatorScene(t, 2)
	a, b := scene.nodes[0], scene.nodes[1]
	scene.founded(t)
	scene.invited(t, 1)
	stale := keyPackageWith(t, scene, 1, func(credential *group.LeafCredential) {
		credential.DeviceSetDigest = canon.Digest([]byte("an earlier device set"))
	})
	if _, err := b.d.sendDirectApplication(context.Background(), a.d.config.AgentID, "room.key-package", stale,
		idem("8"), uint64(scene.clock.now().Add(time.Hour).Unix())); err != nil {
		t.Fatal(err)
	}
	requireRefusedCopy(t, relayOne(t, b, a))
	if adds, err := a.d.journal.RoomAdds(testRoomID, scene.clock.now()); err != nil || len(adds) != 1 || adds[0].Ready() {
		t.Fatalf("a stale device set was recorded: %+v %v", adds, err)
	}
}

// The KeyPackage must carry the compact identity naming the leaf
// credential: a KeyPackage of the same signer under another identity is
// refused at intake and records nothing.
func TestRoomKeyPackageUnderAnotherIdentityIsRefused(t *testing.T) {
	scene := newOperatorScene(t, 2)
	a, b := scene.nodes[0], scene.nodes[1]
	scene.founded(t)
	scene.invited(t, 1)
	member := newRoomMember(t, scene.driver, b, scene.clock.now(), time.Unix(int64(b.d.prekeys.planner.delegation.ExpiresAtUnix), 0))
	signer := group.OpenMLSSigner{State: member.identity.State, LeafSignaturePublicKey: member.identity.LeafSignaturePublicKey}
	otherCredential := member.credential
	otherCredential.IssuedAtUnix++
	otherIdentity, err := group.EncodeLeafIdentity(otherCredential)
	if err != nil {
		t.Fatal(err)
	}
	made, err := scene.driver.NewIdentityForSigner(signer, otherIdentity)
	if err != nil {
		t.Fatal(err)
	}
	device, err := group.DecodeDeviceCredentialJSON(member.deviceJSON)
	if err != nil {
		t.Fatal(err)
	}
	device.KeyPackage = made.KeyPackage
	device, err = group.SignDeviceCredential(device, b.key)
	if err != nil {
		t.Fatal(err)
	}
	deviceJSON, _ := group.EncodeDeviceCredentialJSON(device)
	encoded, _ := group.EncodeLeafCredential(member.credential)
	content, err := payload.Encode(payload.RoomKeyPackage{RoomID: testRoomID, DeviceCredentialJSON: deviceJSON, LeafCredential: encoded})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.d.sendDirectApplication(context.Background(), a.d.config.AgentID, "room.key-package", content,
		idem("9"), uint64(scene.clock.now().Add(time.Hour).Unix())); err != nil {
		t.Fatal(err)
	}
	requireRefusedCopy(t, relayOne(t, b, a))
	if adds, err := a.d.journal.RoomAdds(testRoomID, scene.clock.now()); err != nil || len(adds) != 1 || adds[0].Ready() {
		t.Fatalf("a KeyPackage under another identity was recorded: %+v %v", adds, err)
	}
}

// rooms.join needs a live invite of the named authority; a repeat of an
// accepted join sends the same room.key-package again, and joining under
// another authority is refused.
func TestRoomJoinNeedsAnInviteAndRepeatsItsKeyPackage(t *testing.T) {
	scene := newOperatorScene(t, 3)
	a, b, c := scene.nodes[0], scene.nodes[1], scene.nodes[2]
	scene.founded(t)
	if err := scene.rooms(1).JoinRoom(context.Background(), testRoomID, a.d.config.AgentID); fault.CodeOf(err) != fault.CodeAdmissionRequired {
		t.Fatalf("a join without an invite: %v", err)
	}
	scene.invited(t, 1)
	if err := scene.rooms(1).JoinRoom(context.Background(), testRoomID, a.d.config.AgentID); err != nil {
		t.Fatal(err)
	}
	join, accepted, err := b.d.journal.AcceptedRoomJoin(testRoomID, scene.clock.now())
	if err != nil || !accepted {
		t.Fatalf("the join: %v", err)
	}
	if _, found, err := join.LeafCredential(); err != nil || !found {
		t.Fatalf("the join keeps no leaf credential to send again: %v", err)
	}
	if err := scene.rooms(1).JoinRoom(context.Background(), testRoomID, a.d.config.AgentID); err != nil {
		t.Fatalf("a repeated join: %v", err)
	}
	again, _, _ := b.d.journal.AcceptedRoomJoin(testRoomID, scene.clock.now())
	if again.KeyPackageRef != join.KeyPackageRef {
		t.Fatal("a repeated join made another KeyPackage")
	}
	if err := scene.rooms(1).JoinRoom(context.Background(), testRoomID, c.d.config.AgentID); !errors.Is(err, eventlog.ErrRoomJoinConflict) {
		t.Fatalf("a join under another authority: %v", err)
	}
	// The one room.key-package reaches A, which commits the Add.
	if answer := relayOne(t, b, a); answer.AckOutcome != relayframe.OutcomeAccepted {
		t.Fatalf("the room.key-package: %+v", answer)
	}
	if record, _ := fused(t, a); !record.Membership().Contains(b.d.config.AgentID) {
		t.Fatal("the Add was not committed")
	}
}

// The founder's leaf credential is issued for this node's own device in
// its published device set, and verifies as every receiver verifies it.
func TestRoomFounderCredentialNamesThePublishedDevice(t *testing.T) {
	scene := newOperatorScene(t, 1)
	a := scene.nodes[0]
	record := scene.founded(t)
	credential, _, err := scene.rooms(0).ledger.RoomCredential(testRoomID, a.d.config.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	_, _, set := evidenceOf(t, a)
	if credential.DeviceID != a.d.config.DeviceID || credential.DeviceSetDigest != set.Digest ||
		credential.EndpointID != a.d.config.EndpointID {
		t.Fatalf("the founder's credential: %+v", credential)
	}
	if _, err := group.VerifyRoomLeafCredential(a.d.prekeys.planner.delegation, credential, e2ee.SetSummary{EndpointID: set.EndpointID,
		Digest: set.Digest, DeviceIDs: set.DeviceIDs}, record.RoomEndsAtUnix, scene.clock.now()); err != nil {
		t.Fatalf("the founder's credential does not verify: %v", err)
	}
	// A room held here cannot be founded again under another meaning.
	if err := scene.rooms(0).JoinRoom(context.Background(), testRoomID, "agent_"+strings.Repeat("9", 64)); err == nil {
		t.Fatal("joined a room this installation founded")
	}
}

// The KeyPackage's DeviceCredential and leaf credential must agree: a
// DeviceCredential for the same KeyPackage under another window is refused,
// though each credential verifies alone.
func TestRoomKeyPackageWhoseCredentialsDisagreeIsRefused(t *testing.T) {
	scene := newOperatorScene(t, 2)
	a, b := scene.nodes[0], scene.nodes[1]
	scene.founded(t)
	scene.invited(t, 1)
	member := newRoomMember(t, scene.driver, b, scene.clock.now(), time.Unix(int64(b.d.prekeys.planner.delegation.ExpiresAtUnix), 0))
	device, err := group.DecodeDeviceCredentialJSON(member.deviceJSON)
	if err != nil {
		t.Fatal(err)
	}
	device.ExpiresAtUnix--
	if device, err = group.SignDeviceCredential(device, b.key); err != nil {
		t.Fatal(err)
	}
	deviceJSON, _ := group.EncodeDeviceCredentialJSON(device)
	encoded, _ := group.EncodeLeafCredential(member.credential)
	content, err := payload.Encode(payload.RoomKeyPackage{RoomID: testRoomID, DeviceCredentialJSON: deviceJSON, LeafCredential: encoded})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.d.sendDirectApplication(context.Background(), a.d.config.AgentID, "room.key-package", content,
		idem("a"), uint64(scene.clock.now().Add(time.Hour).Unix())); err != nil {
		t.Fatal(err)
	}
	requireRefusedCopy(t, relayOne(t, b, a))
	if adds, err := a.d.journal.RoomAdds(testRoomID, scene.clock.now()); err != nil || len(adds) != 1 || adds[0].Ready() {
		t.Fatalf("disagreeing credentials were recorded: %+v %v", adds, err)
	}
}

// A crash between the recorded KeyPackage and its Add Commit is finished
// by the next maintenance pass, from the journal.
func TestRoomAddRecordedBeforeACrashIsCommittedOnTheNextPass(t *testing.T) {
	scene := newOperatorScene(t, 2)
	a, b := scene.nodes[0], scene.nodes[1]
	record := scene.founded(t)
	now := scene.clock.now()
	if _, _, err := a.d.journal.RecordRoomAdd(testRoomID, b.d.config.AgentID, now.Add(time.Hour/2), now); err != nil {
		t.Fatal(err)
	}
	leaf, err := scene.rooms(1).issueLeaf(record.RoomEndsAtUnix, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.d.journal.RecordRoomAddKeyPackage(testRoomID, b.d.config.AgentID, leaf.deviceJSON, leaf.encoded, now); err != nil {
		t.Fatal(err)
	}
	scene.rooms(0).maintain()
	if after, _ := fused(t, a); !after.Membership().Contains(b.d.config.AgentID) {
		t.Fatal("the recorded add was not committed on the next pass")
	}
	if adds, err := a.d.journal.RoomAdds(testRoomID, now); err != nil || len(adds) != 0 {
		t.Fatalf("the add was not finished: %+v %v", adds, err)
	}
}
