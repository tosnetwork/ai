package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// Parts of a refused object still in flight when the refusal was answered
// are refused without being stored (sections 11.3, 11.5: nothing is stored
// on refusal). The tombstone is keyed by the authenticated packet sender, and
// an accepted part 0 lifts it.

// requireRefusedUnstored hands parts to the receiver and requires each to be
// refused not-accepted, stored nowhere.
func requireRefusedUnstored(t *testing.T, receiver *relayNode, sender string, frames [][]byte) {
	t.Helper()
	for _, frame := range frames {
		decoded, err := relayframe.Decode(frame)
		if err != nil {
			t.Fatal(err)
		}
		answer := receiver.d.relay.Deliver(context.Background(), sender, frame)
		if answer.Result != carrierapi.ResultRefused || answer.Code != carrierapi.CodeNotAccepted {
			t.Fatalf("part %d of a refused object: %s/%s", decoded.PartIndex, answer.Result, answer.Code)
		}
	}
	requireNothingHeld(t, receiver)
}

// The live race: a member's crafted 6-part Commit whose parts 1 and 2 arrive
// before part 0 and parts 3..5 after its refusal. Nothing of it stays.
func TestRoomPartsArrivingAfterARefusedPartZeroAreNotStored(t *testing.T) {
	scene := newJoinedSceneCut(t, roomRetention, refusalPartBytes)
	b := scene.nodes[1]
	frames := splitInto(t, scene, scene.c, relayframe.RoomCommit, 6)
	deliverLaterParts(t, b, scene.c.agent(), frames[:3])
	requireRejected(t, b, b.d.relay.Deliver(context.Background(), scene.c.agent(), frames[0]), fault.CodeNotAuthentic)
	requireNothingHeld(t, b)
	scene.clock.set(scene.clock.now().Add(time.Second))
	requireRefusedUnstored(t, b, scene.c.agent(), frames[3:])
	// Parts of the refused object delivered again are refused all the same.
	requireRefusedUnstored(t, b, scene.c.agent(), frames[1:])
}

// An object refused at completion: a redelivered generation's later parts
// are refused unstored too.
func TestRoomPartsOfAnObjectRefusedAtCompletionAreNotStored(t *testing.T) {
	scene := newJoinedSceneCut(t, roomRetention, refusalPartBytes)
	b := scene.nodes[1]
	// The authority's Commit completes after the room's end plus the skew:
	// refused room-ended at completion.
	frames := splitInto(t, scene, scene.a, relayframe.RoomCommit, 6)
	before, _ := fused(t, b)
	deliverLaterParts(t, b, scene.a.agent(), frames[:5])
	if answer := b.d.relay.Deliver(context.Background(), scene.a.agent(), frames[0]); answer.Result != carrierapi.ResultAdmitted {
		t.Fatalf("part 0: %s/%s", answer.Result, answer.Code)
	}
	scene.clock.set(time.Unix(int64(before.RoomEndsAtUnix), 0).Add(b.d.relay.rooms.skew))
	requireRejected(t, b, b.d.relay.Deliver(context.Background(), scene.a.agent(), frames[5]), fault.CodeRoomEnded)
	requireNothingHeld(t, b)
	if !b.d.relay.rooms.parts.RefusedObject(scene.a.agent(), objectDigestOf(t, frames[0]), scene.clock.now()) {
		t.Fatal("a completion refusal left no tombstone")
	}
	requireRefusedUnstored(t, b, scene.a.agent(), frames[1:])
}

// An older generation's part 0 refused for its evidence while the object
// holds an accepted part 0 refuses only that frame: no tombstone, and the
// object's later parts are still held.
func TestRoomOlderPartZeroRefusedPlantsNoTombstone(t *testing.T) {
	scene := newJoinedSceneCut(t, roomRetention, refusalPartBytes)
	b := scene.nodes[1]
	frames := splitInto(t, scene, scene.a, relayframe.RoomCommit, 6)
	if answer := b.d.relay.Deliver(context.Background(), scene.a.agent(), frames[0]); answer.Result != carrierapi.ResultAdmitted {
		t.Fatalf("part 0: %s/%s", answer.Result, answer.Code)
	}
	now := scene.clock.now()
	older := scene.a
	older.evidence = evidenceFor(t, scene.a.node, scene.a.node.d.config.DeviceID, uint64(scene.start.Add(-55*time.Second).Unix()),
		uint64(now.Add(-10*time.Second).Unix()))
	stale := framesOf(t, older, objectOf(t, frames), refusalPartBytes)[0]
	if answer := b.d.relay.Deliver(context.Background(), scene.a.agent(), stale); answer.Result != carrierapi.ResultRefused ||
		answer.Code != carrierapi.CodeEvidenceRefused {
		t.Fatalf("the older part 0: %s/%s", answer.Result, answer.Code)
	}
	if b.d.relay.rooms.parts.RefusedObject(scene.a.agent(), objectDigestOf(t, frames[0]), scene.clock.now()) {
		t.Fatal("an older part 0 planted a tombstone")
	}
	for index, frame := range frames[1:3] {
		if answer := b.d.relay.Deliver(context.Background(), scene.a.agent(), frame); answer.Result != carrierapi.ResultAdmitted {
			t.Fatalf("part %d after the older part 0: %s/%s", index+1, answer.Result, answer.Code)
		}
	}
	if n := storedParts(t, b); n != 3 {
		t.Fatalf("%d parts stored, want 3", n)
	}
}

// A part 0 refused for its evidence, then the sender's next generation under
// accepted evidence: its part 0 lifts the tombstone and its later parts are
// held again.
func TestRoomAcceptedPartZeroLiftsTheTombstone(t *testing.T) {
	scene := newJoinedSceneCut(t, roomRetention, refusalPartBytes)
	b := scene.nodes[1]
	refused := splitInto(t, scene, scene.c, relayframe.RoomCommit, 6)
	if answer := b.d.relay.Deliver(context.Background(), scene.a.agent(), refused[0]); answer.Code != carrierapi.CodeEvidenceRefused {
		t.Fatalf("part 0 under another Agent's evidence: %s/%s", answer.Result, answer.Code)
	}
	requireRefusedUnstored(t, b, scene.a.agent(), refused[1:2])
	accepted := framesOf(t, scene.a, objectOf(t, refused), refusalPartBytes)
	for index, frame := range accepted[:5] {
		if answer := b.d.relay.Deliver(context.Background(), scene.a.agent(), frame); answer.Result != carrierapi.ResultAdmitted {
			t.Fatalf("part %d of the next generation: %s/%s", index, answer.Result, answer.Code)
		}
	}
	if n := storedParts(t, b); n != 5 {
		t.Fatalf("%d parts stored, want 5", n)
	}
}

// A tombstone is the refused sender's own: another member's refused part 0
// naming an object digest does not refuse the authority's parts of it.
func TestRoomTombstoneIsKeyedByTheAuthenticatedSender(t *testing.T) {
	scene := newJoinedSceneCut(t, roomRetention, refusalPartBytes)
	b := scene.nodes[1]
	frames := splitInto(t, scene, scene.a, relayframe.RoomCommit, 6)
	// C sends the authority's object under its own packet and evidence.
	asC := framesOf(t, scene.c, objectOf(t, frames), refusalPartBytes)
	requireRejected(t, b, b.d.relay.Deliver(context.Background(), scene.c.agent(), asC[0]), fault.CodeNotAuthentic)
	for index, frame := range frames[:5] {
		if answer := b.d.relay.Deliver(context.Background(), scene.a.agent(), frame); answer.Result != carrierapi.ResultAdmitted {
			t.Fatalf("the authority's part %d: %s/%s", index, answer.Result, answer.Code)
		}
	}
}

// objectDigestOf is the object digest a frame names.
func objectDigestOf(t *testing.T, frame []byte) [32]byte {
	t.Helper()
	decoded, err := relayframe.Decode(frame)
	if err != nil {
		t.Fatal(err)
	}
	return decoded.ObjectDigest
}

// objectOf joins an object's frames back into its bytes.
func objectOf(t *testing.T, frames [][]byte) []byte {
	t.Helper()
	var object []byte
	for _, frame := range frames {
		decoded, err := relayframe.Decode(frame)
		if err != nil {
			t.Fatal(err)
		}
		object = append(object, decoded.Part...)
	}
	return object
}

// The answers that refuse a complete object: a relay refusal, an ignored
// object and a rejected room ack; an accepted or duplicate ack, an admitted
// object and a retry refuse nothing.
func TestRoomCompletionAnswersThatRefuseTheObject(t *testing.T) {
	for _, answer := range []struct {
		response carrierapi.Response
		refuses  bool
	}{
		{carrierapi.Refusal(carrierapi.CodeEvidenceRefused), true},
		{carrierapi.Response{Result: carrierapi.ResultIgnored}, true},
		{carrierapi.Response{Result: carrierapi.ResultAck, AckOutcome: relayframe.OutcomeRejected}, true},
		{carrierapi.Response{Result: carrierapi.ResultAck, AckOutcome: relayframe.OutcomeAccepted}, false},
		{carrierapi.Response{Result: carrierapi.ResultAck, AckOutcome: relayframe.OutcomeDuplicate}, false},
		{carrierapi.Response{Result: carrierapi.ResultAdmitted}, false},
		{carrierapi.Retry(), false},
	} {
		if got := refusesObject(answer.response); got != answer.refuses {
			t.Errorf("%s/%s %s refuses the object: %v, want %v", answer.response.Result, answer.response.Code,
				answer.response.AckOutcome, got, answer.refuses)
		}
	}
}
