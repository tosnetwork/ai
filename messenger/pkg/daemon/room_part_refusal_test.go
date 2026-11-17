package daemon

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// On refusal nothing is stored (sections 11.3, 11.5): the later parts of an
// object that arrived before its part 0 are dropped, with the Reassembler's
// entry, when part 0 is refused at intake.

// refusalPartBytes is the test part size of these scenes.
const refusalPartBytes = 4 * relayframe.MinTestPartBytes

// splitInto returns an object of a type whose body makes it cut into the
// given number of parts at the scene's part size, framed under a sender's
// card and evidence.
func splitInto(t *testing.T, scene *joinedScene, sender roomMember, kind uint8, parts int) [][]byte {
	t.Helper()
	before, _ := fused(t, scene.nodes[1])
	for size := refusalPartBytes; size <= parts*refusalPartBytes; size += 256 {
		object := scene.authority.object(kind, before.RoomEpoch, before.MLSEpoch+1, nil, bytes.Repeat([]byte{0x5c}, size))
		if frames := framesOf(t, sender, object, refusalPartBytes); len(frames) == parts {
			return frames
		}
	}
	t.Fatalf("no body cuts into %d parts", parts)
	return nil
}

// deliverLaterParts hands every part but part 0 to the receiver, each held.
func deliverLaterParts(t *testing.T, receiver *relayNode, sender string, frames [][]byte) {
	t.Helper()
	for index, frame := range frames[1:] {
		if answer := receiver.d.relay.Deliver(context.Background(), sender, frame); answer.Result != carrierapi.ResultAdmitted {
			t.Fatalf("part %d answered %s/%s", index+1, answer.Result, answer.Code)
		}
	}
	if n := storedParts(t, receiver); n != len(frames)-1 {
		t.Fatalf("%d parts stored before part 0, want %d", n, len(frames)-1)
	}
}

// requireNothingHeld requires a receiver to store no part and hold no
// incomplete object.
func requireNothingHeld(t *testing.T, receiver *relayNode) {
	t.Helper()
	if n := storedParts(t, receiver); n != 0 {
		t.Fatalf("%d parts of a refused object stay stored", n)
	}
	if usage := receiver.d.relay.rooms.parts.Usage(); usage.Objects != 0 || usage.TotalBytes != 0 {
		t.Fatalf("the Reassembler still holds a refused object: %+v", usage)
	}
}

// A member's crafted 6-part Commit whose parts 1..5 arrive first: part 0 is
// refused not-authentic, and nothing of the object stays.
func TestRoomRefusedPartZeroDropsTheLaterPartsOfANonAuthorityCommit(t *testing.T) {
	scene := newJoinedSceneCut(t, roomRetention, refusalPartBytes)
	b := scene.nodes[1]
	before, _ := fused(t, b)
	frames := splitInto(t, scene, scene.c, relayframe.RoomCommit, 6)
	deliverLaterParts(t, b, scene.c.agent(), frames)
	requireRejected(t, b, b.d.relay.Deliver(context.Background(), scene.c.agent(), frames[0]), fault.CodeNotAuthentic)
	requireNothingHeld(t, b)
	requireUnmoved(t, b, before)
}

// The authority's object whose part 0 carries evidence that fails CheckPeer,
// after its later parts: part 0 is refused and nothing of the object stays.
func TestRoomRefusedPartZeroEvidenceDropsTheLaterParts(t *testing.T) {
	scene := newJoinedSceneCut(t, roomRetention, refusalPartBytes)
	b := scene.nodes[1]
	// Framed under C's card and evidence, sent as the authority's packet.
	frames := splitInto(t, scene, scene.c, relayframe.RoomCommit, 6)
	deliverLaterParts(t, b, scene.a.agent(), frames)
	answer := b.d.relay.Deliver(context.Background(), scene.a.agent(), frames[0])
	if answer.Result != carrierapi.ResultRefused || answer.Code != carrierapi.CodeEvidenceRefused {
		t.Fatalf("part 0 under another Agent's evidence: %s/%s", answer.Result, answer.Code)
	}
	requireNothingHeld(t, b)
}

// Part 0 of a room this installation does not hold, after its later parts:
// refused not-admitted, and nothing of the object stays.
func TestRoomRefusedPartZeroOfAnotherRoomDropsTheLaterParts(t *testing.T) {
	scene := newJoinedSceneCut(t, roomRetention, refusalPartBytes)
	b := scene.nodes[1]
	before, _ := fused(t, b)
	other := "room_" + strings.Repeat("9", 64)
	for size := refusalPartBytes; size <= 6*refusalPartBytes; size += 256 {
		object, err := relayframe.EncodeRoomObject(relayframe.RoomObject{Type: relayframe.RoomCommit, RoomID: other,
			RoomEpoch: before.RoomEpoch, MLSEpoch: before.MLSEpoch + 1, Body: bytes.Repeat([]byte{0x5c}, size)})
		if err != nil {
			t.Fatal(err)
		}
		frames := framesOf(t, scene.a, object, refusalPartBytes)
		if len(frames) != 6 {
			continue
		}
		deliverLaterParts(t, b, scene.a.agent(), frames)
		answer := b.d.relay.Deliver(context.Background(), scene.a.agent(), frames[0])
		if answer.Result != carrierapi.ResultRefused || answer.Code != carrierapi.CodeNotAdmitted {
			t.Fatalf("part 0 of a room not held: %s/%s", answer.Result, answer.Code)
		}
		requireNothingHeld(t, b)
		return
	}
	t.Fatal("no body cuts into 6 parts")
}

// Part 0 arriving after the room's end plus the skew, after its later parts:
// refused room-ended, and nothing of the object stays.
func TestRoomRefusedPartZeroAfterTheEndDropsTheLaterParts(t *testing.T) {
	scene := newJoinedSceneCut(t, roomRetention, refusalPartBytes)
	b := scene.nodes[1]
	before, _ := fused(t, b)
	frames := splitInto(t, scene, scene.a, relayframe.RoomCommit, 6)
	deliverLaterParts(t, b, scene.a.agent(), frames)
	scene.clock.set(time.Unix(int64(before.RoomEndsAtUnix), 0).Add(b.d.relay.rooms.skew))
	requireRejected(t, b, b.d.relay.Deliver(context.Background(), scene.a.agent(), frames[0]), fault.CodeRoomEnded)
	requireNothingHeld(t, b)
}

// A part 0 answered retry refuses nothing: the parts that arrived before it
// stay, and the redelivered part 0 completes the object.
func TestRoomRetriedPartZeroKeepsTheLaterParts(t *testing.T) {
	scene := newJoinedSceneCut(t, roomRetention, refusalPartBytes)
	b := scene.nodes[1]
	frames := splitInto(t, scene, scene.a, relayframe.RoomCommit, 6)
	deliverLaterParts(t, b, scene.a.agent(), frames)
	verifier := b.d.relay.verifier
	resolver := verifier.Resolver
	verifier.Resolver = flakyResolver{inner: resolver, failing: scene.a.agent()}
	if answer := b.d.relay.Deliver(context.Background(), scene.a.agent(), frames[0]); answer.Result != carrierapi.ResultRetry {
		t.Fatalf("part 0 while finalized state is unavailable: %s/%s", answer.Result, answer.Code)
	}
	verifier.Resolver = resolver
	if n := storedParts(t, b); n != len(frames)-1 {
		t.Fatalf("%d parts stored after a retried part 0, want %d", n, len(frames)-1)
	}
}
