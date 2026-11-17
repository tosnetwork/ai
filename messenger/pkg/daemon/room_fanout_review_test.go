package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// The fan-out review follow-ups of #44: a carrier refusal and a rejection
// stop the member's queue before its head is settled, removal withdrawals
// stay pending until the carrier confirms them, and the fan-out runs under
// the handling lock.

// A carrier refusal other than retry, peer-cap or no-peer-card stops the
// member's queue, with its owner notice, before the head is abandoned: the
// next object does not go out.
func TestRoomFanOutCarrierRefusalStopsTheQueue(t *testing.T) {
	scene := newOperatorSceneWith(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	refused := carrierapi.Refusal(carrierapi.CodeFrameMalformed)
	scene.founded(t)
	scene.invited(t, 1)
	a.carrier.mutex.Lock()
	a.carrier.answer = &refused
	a.carrier.mutex.Unlock()
	scene.joined(t, 1)
	a.carrier.mutex.Lock()
	a.carrier.answer = nil
	a.carrier.mutex.Unlock()
	takeFrames(t, a, func(relayframe.Frame, string) bool { return true })
	scene.rooms(0).maintain()
	if stopped, err := scene.rooms(0).queueStopped(testRoomID, agent); err != nil || !stopped {
		t.Fatalf("a refused Welcome did not stop B's queue: %v", err)
	}
	if objects := objectsTo(t, a, agent); len(objects) != 0 {
		t.Fatalf("after a refused Welcome the queue deposited %d objects", len(objects))
	}
	// The refused Welcome is abandoned rejected; with no other member left
	// to deliver it to, its head is retired.
	if welcome, found := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent); found &&
		(welcome.State != eventlog.RoomDeliveryAbandoned || welcome.Code != fault.CodeRejected) {
		t.Fatalf("the refused Welcome: %+v", welcome)
	}
	if scene.reports[0].count(func(err error) bool { return errors.Is(err, ErrRoomMemberCarrierRefused) }) != 1 {
		t.Fatal("the refusal raised no owner notice")
	}
}

// A rejection is recorded as the queue's stop before its slot is settled:
// a settlement that fails (a crash in between) leaves the queue stopped,
// the ack unapplied, and the repeat of the ack settles it.
func TestRoomFanOutRejectionStopsTheQueueBeforeItIsSettled(t *testing.T) {
	scene := newFanoutScene(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	welcome := objectsTo(t, a, agent)[0]
	rejection := signedRoomAck(t, b, welcome, relayframe.OutcomeRejected, fault.CodeNotAuthentic, false)
	outbox := filepath.Join(a.d.config.StateDir, "room-outbox")
	if err := os.Chmod(outbox, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(outbox, 0o700) })
	if answer := a.d.relay.DeliveryAck(context.Background(), agent, rejection); answer.Result != carrierapi.ResultRetry {
		t.Fatalf("a rejection that could not be settled was answered %+v, want retry", answer)
	}
	if err := os.Chmod(outbox, 0o700); err != nil {
		t.Fatal(err)
	}
	if stopped, err := scene.rooms(0).queueStopped(testRoomID, agent); err != nil || !stopped {
		t.Fatalf("the rejection did not stop the queue before its settlement: %v", err)
	}
	delivery, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent)
	if delivery.State != eventlog.RoomDeliveryCarried {
		t.Fatalf("the unsettled Welcome: %+v", delivery)
	}
	scene.clock.set(time.Unix(int64(delivery.NextRedepositAtUnix), 0))
	scene.rooms(0).maintain()
	if objects := objectsTo(t, a, agent); len(objects) != 0 {
		t.Fatalf("a stopped queue deposited %d objects", len(objects))
	}
	if answer := a.d.relay.DeliveryAck(context.Background(), agent, rejection); answer.Result != carrierapi.ResultApplied {
		t.Fatalf("the repeated rejection: %+v", answer)
	}
	if settled, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent); settled.State != "" && settled.State != eventlog.RoomDeliveryRejected {
		t.Fatalf("the Welcome after the repeated rejection: %+v", settled)
	}
	if scene.reports[0].count(func(err error) bool { return errors.Is(err, ErrRoomMemberRejected) }) != 1 {
		t.Fatal("the rejection's notice was not raised once")
	}
}

// A rejection that carries MLS state stops the member's queue with its
// owner notice, and nothing more is deposited to it.
func TestRoomFanOutRejectionWithStateStopsTheQueue(t *testing.T) {
	scene := newFanoutScene(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	welcome := objectsTo(t, a, agent)[0]
	rejection := signedRoomAck(t, b, welcome, relayframe.OutcomeRejected, fault.CodeNotAuthentic, false)
	if answer := a.d.relay.DeliveryAck(context.Background(), agent, rejection); answer.Result != carrierapi.ResultApplied {
		t.Fatalf("the rejection: %+v", answer)
	}
	if stopped, err := scene.rooms(0).queueStopped(testRoomID, agent); err != nil || !stopped {
		t.Fatalf("a rejection with state did not stop the queue: %v", err)
	}
	if scene.reports[0].count(func(err error) bool { return errors.Is(err, ErrRoomMemberRejected) }) != 1 ||
		scene.reports[0].count(func(err error) bool { return errors.Is(err, ErrRoomMemberLostState) }) != 0 {
		t.Fatal("a rejection with state raised the wrong notice")
	}
	scene.rooms(0).maintain()
	if objects := objectsTo(t, a, agent); len(objects) != 0 {
		t.Fatalf("the roster went out after a rejected Welcome: %d objects", len(objects))
	}
	if roster, _ := memberDelivery(t, a, eventlog.RoomObjectRoster, agent); roster.State != eventlog.RoomDeliveryPending {
		t.Fatalf("the roster behind the rejection: %+v", roster)
	}
}

// withdrawAnswer answers every carrier.withdraw with a chosen response or
// error, after recording it.
type withdrawAnswer struct {
	*recordingCarrier
	response carrierapi.Response
	err      error
}

func (w withdrawAnswer) Withdraw(ctx context.Context, recipient, key string) (carrierapi.Response, error) {
	if _, err := w.recordingCarrier.Withdraw(ctx, recipient, key); err != nil {
		return carrierapi.Response{}, err
	}
	return w.response, w.err
}

func liveSlots(t *testing.T, node *relayNode, agent string) int {
	t.Helper()
	live := 0
	for _, head := range mustHeads(t, node) {
		if delivery, found := head.Member(agent); found && !delivery.Once &&
			(delivery.State == eventlog.RoomDeliveryPending || delivery.State == eventlog.RoomDeliveryCarried) {
			live++
		}
	}
	return live
}

// A removal withdrawal the carrier did not confirm (retry, or a transport
// error) keeps the removed member's slot until a maintenance pass gets the
// confirmation; nothing is deposited to the removed member meanwhile, and
// the Remove is not repeated.
func TestRoomFanOutRemovalWithdrawalsWaitForTheCarriersConfirmation(t *testing.T) {
	for name, failing := range map[string]withdrawAnswer{
		"retry":           {response: carrierapi.Retry()},
		"transport error": {err: errors.New("carrier unreachable")},
	} {
		t.Run(name, func(t *testing.T) {
			scene := newFanoutScene(t, 2, roomRetention)
			a, b := scene.nodes[0], scene.nodes[1]
			agent := b.d.config.AgentID
			welcome := objectsTo(t, a, agent)[0]
			failing.recordingCarrier = a.carrier
			a.d.relay.carrier = failing
			if err := scene.rooms(0).RemoveRoomMember(context.Background(), testRoomID, agent); err != nil {
				t.Fatalf("the Remove: %v", err)
			}
			after, _ := fused(t, a)
			if after.Membership().Contains(agent) {
				t.Fatal("the Remove was not committed")
			}
			// The carried Welcome and the pending roster behind it, whose
			// first generation is withdrawn too, stay.
			if live := liveSlots(t, a, agent); live != 2 {
				t.Fatalf("%d live slots after an unconfirmed withdrawal, want the Welcome's and the roster's", live)
			}
			takeFrames(t, a, func(relayframe.Frame, string) bool { return true })
			delivery, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent)
			scene.clock.set(time.Unix(int64(delivery.NextRedepositAtUnix), 0))
			asked := len(a.carrier.withdrawals())
			scene.rooms(0).maintain()
			if frames := takeFrames(t, a, func(frame relayframe.Frame, to string) bool {
				return frame.Kind == relayframe.KindRoom && to == agent
			}); len(frames) != 0 {
				t.Fatalf("%d frames deposited to the removed member", len(frames))
			}
			if len(a.carrier.withdrawals()) <= asked {
				t.Fatal("the maintenance pass did not retry the withdrawal")
			}
			// The carrier confirms: the slot is settled.
			a.d.relay.carrier = a.carrier
			scene.rooms(0).maintain()
			if live := liveSlots(t, a, agent); live != 0 {
				t.Fatalf("%d live slots after the confirmed withdrawal", live)
			}
			first, _ := relayframe.Decode(welcome[0].frame)
			key, _ := relayframe.RoomIdempotencyKey(eventlogDigest(first.ObjectDigest), agent, 1, 0)
			if withdrawn := a.carrier.withdrawals(); withdrawn[len(withdrawn)-1].recipient != agent || !withdrawnKey(withdrawn, key) {
				t.Fatalf("the confirmed withdrawals: %+v", withdrawn)
			}
			if again, _ := fused(t, a); again.MLSEpoch != after.MLSEpoch {
				t.Fatal("the withdrawal retry made another Commit")
			}
		})
	}
}

func withdrawnKey(withdrawn []carried, key string) bool {
	for _, record := range withdrawn {
		if record.key == key {
			return true
		}
	}
	return false
}

// An unconfirmed withdrawal is retried only until the head's retention
// ends, when its envelopes have expired at the relays: the slot is then
// settled.
func TestRoomFanOutRemovalWithdrawalsEndWithTheRetention(t *testing.T) {
	scene := newFanoutScene(t, 2, 20*time.Minute)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	objectsTo(t, a, agent)
	a.d.relay.carrier = withdrawAnswer{recordingCarrier: a.carrier, response: carrierapi.Retry()}
	if err := scene.rooms(0).RemoveRoomMember(context.Background(), testRoomID, agent); err != nil {
		t.Fatal(err)
	}
	head, _ := func() (eventlog.RoomOutboxHead, bool) {
		for _, head := range mustHeads(t, a) {
			if head.Type == eventlog.RoomObjectWelcome {
				return head, true
			}
		}
		return eventlog.RoomOutboxHead{}, false
	}()
	scene.clock.set(time.Unix(int64(head.RetainUntilUnix), 0).Add(-time.Second))
	scene.rooms(0).maintain()
	if live := liveSlots(t, a, agent); live != 2 {
		t.Fatalf("%d live slots one second before the retention end", live)
	}
	scene.clock.set(time.Unix(int64(head.RetainUntilUnix), 0))
	scene.rooms(0).maintain()
	if live := liveSlots(t, a, agent); live != 0 {
		t.Fatalf("%d live slots at the retention end", live)
	}
}

// A first deposit the carrier answered retry left its generation
// unrecorded, though a part of it may be stored: the Remove withdraws that
// next generation too.
func TestRoomFanOutRemovalWithdrawsAnUnrecordedGeneration(t *testing.T) {
	scene := newOperatorSceneWith(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	retry := carrierapi.Retry()
	scene.founded(t)
	scene.invited(t, 1)
	a.carrier.mutex.Lock()
	a.carrier.answer = &retry
	a.carrier.mutex.Unlock()
	scene.joined(t, 1)
	a.carrier.mutex.Lock()
	a.carrier.answer = nil
	a.carrier.mutex.Unlock()
	tried := objectsTo(t, a, agent)
	if len(tried) != 1 {
		t.Fatalf("%d deposits tried", len(tried))
	}
	if welcome, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent); welcome.Generation != 0 {
		t.Fatalf("the retried Welcome recorded a generation: %+v", welcome)
	}
	if err := scene.rooms(0).RemoveRoomMember(context.Background(), testRoomID, agent); err != nil {
		t.Fatal(err)
	}
	if !withdrawnKey(a.carrier.withdrawals(), tried[0][0].key) {
		t.Fatalf("the unrecorded generation's part 0 (%s) was not withdrawn: %+v", tried[0][0].key, a.carrier.withdrawals())
	}
}

// Every handshake deposit runs under the handling lock, whichever path
// makes it (the maintenance pass, an ack, an Add, a Remove), so a Remove
// cannot interleave with a deposit of the member it removes.
func TestRoomFanOutDepositsUnderTheHandlingLock(t *testing.T) {
	scene := newFanoutScene(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	r := scene.rooms(0)
	unlocked := 0
	a.carrier.onCarry = func(record carried) {
		if r.handling.TryLock() {
			unlocked++
			r.handling.Unlock()
		}
	}
	welcome := objectsTo(t, a, agent)[0]
	delivery, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent)
	// The maintenance pass's re-deposit, through the handshake sweep itself
	// (maintain's Add pass also fans out, under the lock).
	scene.clock.set(time.Unix(int64(delivery.NextRedepositAtUnix), 0))
	r.sweepHandshakes(context.Background())
	again := objectsTo(t, a, agent)
	if len(again) != 1 {
		t.Fatalf("%d re-deposits", len(again))
	}
	// The ack's release of the roster.
	if applied := ackBack(t, a, b, handOver(t, a, b, again[0])); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("the Welcome's ack: %+v", applied)
	}
	if roster := objectsTo(t, a, agent); len(roster) != 1 {
		t.Fatalf("%d objects after the ack", len(roster))
	}
	if unlocked != 0 {
		t.Fatalf("%d handshake deposits ran outside the handling lock", unlocked)
	}
	if again[0][0].key == welcome[0].key {
		t.Fatal("the sweep did not deposit the next generation")
	}
}

// The wait after repeated retry answers doubles from 30 s and stops at
// 5 min.
func TestRoomFanOutBackoffIsCappedAtFiveMinutes(t *testing.T) {
	var backoff fanoutBackoff
	now := time.Unix(1_900_000_000, 0)
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for attempt, wait := range want {
		if until := backoff.failed("k", now); until.Sub(now) != wait {
			t.Fatalf("attempt %d waits %v, want %v", attempt+1, until.Sub(now), wait)
		}
		if backoff.due("k", now.Add(wait-time.Second)) || !backoff.due("k", now.Add(wait)) {
			t.Fatalf("attempt %d is due at the wrong time", attempt+1)
		}
	}
	for attempt := 0; attempt < 32; attempt++ {
		backoff.failed("k", now)
	}
	if until := backoff.failed("k", now); until.Sub(now) != handshakeBackoffCap {
		t.Fatalf("after many retries the wait is %v", until.Sub(now))
	}
}

// The removed member's single Commit is deposited only after its stored
// evidence passes CheckStoredContact; a failing one starts its evidence
// pull and gets nothing until the evidence is good again.
func TestRoomFanOutRemovingCommitChecksTheStoredContact(t *testing.T) {
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
	if _, err := a.d.relay.verifier.CheckStoredContact(agent, now); err == nil {
		t.Fatal("the replaced evidence still passes CheckStoredContact")
	}
	if err := scene.rooms(0).RemoveRoomMember(context.Background(), testRoomID, agent); err != nil {
		t.Fatal(err)
	}
	if commits := roomObjectFrames(t, a, agent, relayframe.RoomCommit); len(commits) != 0 {
		t.Fatalf("the removing Commit went to failing evidence: %d frames", len(commits))
	}
	if pull, _, err := a.d.journal.LoadRelayPull(agent); err != nil || !pull.Requested {
		t.Fatalf("the evidence pull did not start: %+v %v", pull, err)
	}
	if err := a.d.journal.StoreRelayEvidence(agent, good, canon.Digest(other), now); err != nil {
		t.Fatal(err)
	}
	scene.rooms(0).maintain()
	if commits := roomObjectFrames(t, a, agent, relayframe.RoomCommit); len(commits) != 1 {
		t.Fatalf("the removing Commit after the repair: %d frames", len(commits))
	}
}

// A rejection of an object never carried to the member settles nothing and
// stops nothing: only a rejection of a slot in the member's queue stops it.
func TestRoomFanOutRejectionOfAnObjectNeverCarriedStopsNothing(t *testing.T) {
	scene := newFanoutScene(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	welcome := objectsTo(t, a, agent)[0]
	var roster eventlog.RoomOutboxHead
	for _, head := range mustHeads(t, a) {
		if head.Type == eventlog.RoomObjectRoster {
			roster = head
		}
	}
	digest, err := hex.DecodeString(roster.ObjectDigest)
	if err != nil || len(digest) != 32 {
		t.Fatalf("the roster digest: %v", err)
	}
	// B's genuine rejection frame, naming the roster it was never sent.
	frame, err := relayframe.Decode(signedRoomAck(t, b, welcome, relayframe.OutcomeRejected, fault.CodeNotAuthentic, false))
	if err != nil {
		t.Fatal(err)
	}
	ack, err := relayframe.DecodeRoomAck(frame.Part)
	if err != nil {
		t.Fatal(err)
	}
	copy(ack.ObjectDigest[:], digest)
	signed, err := relayframe.SignRoomAck(ack, b.key)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Part, err = relayframe.EncodeRoomAck(signed); err != nil {
		t.Fatal(err)
	}
	raw, err := relayframe.Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	if answer := a.d.relay.DeliveryAck(context.Background(), agent, raw); answer.Result == carrierapi.ResultApplied {
		t.Fatalf("a rejection of a never-carried roster was applied: %+v", answer)
	}
	if stopped, err := scene.rooms(0).queueStopped(testRoomID, agent); err != nil || stopped {
		t.Fatalf("a rejection of a never-carried roster stopped the queue: %v", err)
	}
	if applied := ackBack(t, a, b, handOver(t, a, b, welcome)); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("the Welcome's ack: %+v", applied)
	}
	if objects := objectsTo(t, a, agent); len(objects) != 1 {
		t.Fatalf("%d objects after the Welcome's ack, want the roster", len(objects))
	}
}
