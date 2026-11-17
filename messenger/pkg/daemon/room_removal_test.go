package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/messenger/pkg/room"
)

// A verified Commit removing this member marks the room removed with one
// owner notice; from then on the room's handshake objects are not taken.
func TestRoomRemovalNoticeMarksTheRoomAndStopsHandshakes(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	reports := &recordingReports{}
	b.d.observer = reports
	before, _ := fused(t, b)
	removal := removeCommit(t, scene, scene.b)
	for range 2 {
		if response := send(t, b, scene.a.agent(), framesOf(t, scene.a, removal, 0)); response.Result != carrierapi.ResultIgnored {
			t.Fatalf("the removal Commit: %s/%s", response.Result, response.Code)
		}
	}
	marker, removed, err := b.d.journal.RoomRemovalOf(testRoomID)
	if err != nil || !removed || marker.RoomEpoch != before.RoomEpoch+1 || marker.MemberMLSEpoch != before.MLSEpoch {
		t.Fatalf("the removal marker: %+v %v %v", marker, removed, err)
	}
	if n := reports.count(func(err error) bool { return errors.Is(err, ErrRoomRemoved) }); n != 1 {
		t.Fatalf("%d removal notices, want 1", n)
	}
	requireUnmoved(t, b, before)
	// A later handshake object of the room is not taken.
	roster := scene.authority.rosterObject(scene.authority.record.Membership(), rosterEntry(t, scene.c))
	if response := send(t, b, scene.a.agent(), framesOf(t, scene.a, roster, 0)); response.Result != carrierapi.ResultIgnored {
		t.Fatalf("a roster after the removal: %s/%s", response.Result, response.Code)
	}
	requireUnmoved(t, b, before)
}

// An authentic header of an epoch the member already passed that omits it
// is not a removal notice: it is refused not-authentic and marks nothing.
func TestRoomOldHeaderOmittingThisMemberIsNotARemovalNotice(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	before, _ := fused(t, b)
	founding, err := room.Found(testRoomID, []string{scene.a.agent()})
	if err != nil {
		t.Fatal(err)
	}
	result, _ := scene.authority.commit()
	object := scene.authority.object(relayframe.RoomCommit, founding.Epoch, result.Transition.Next.Clock.MLSEpoch,
		scene.authority.header(founding), result.Commit)
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, object, 0)), fault.CodeNotAuthentic)
	if _, removed, err := b.d.journal.RoomRemovalOf(testRoomID); err != nil || removed {
		t.Fatalf("an old header marked the room removed: %v %v", removed, err)
	}
	requireUnmoved(t, b, before)
}

// When the authority removes another member, the receiver forgets it: the
// room's admission of its card, its sequence record, and its incomplete
// parts once no room takes parts from it; its credential left with the
// fused write.
func TestRoomReceiverForgetsAMemberTheAuthorityRemoved(t *testing.T) {
	partBytes := 4 * relayframe.MinTestPartBytes
	scene := newJoinedSceneCut(t, roomRetention, partBytes)
	b := scene.nodes[1]
	now := scene.clock.now()
	if err := b.d.journal.ObserveRoomSequence(testRoomID, scene.c.agent(), 2, now); err != nil {
		t.Fatal(err)
	}
	record := scene.authority.record
	pending := scene.authority.object(relayframe.RoomCommit, record.RoomEpoch, record.MLSEpoch+1, nil, make([]byte, 3*partBytes))
	if response := b.d.relay.Deliver(context.Background(), scene.c.agent(), framesOf(t, scene.c, pending, partBytes)[1]); response.Result != carrierapi.ResultAdmitted {
		t.Fatalf("C's stored part: %s/%s", response.Result, response.Code)
	}
	if storedParts(t, b) != 1 {
		t.Fatal("C's part was not stored")
	}
	removal := removeCommit(t, scene, scene.c)
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, removal, partBytes))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the removal of C: %+v", ack)
	}
	if forgotten := scene.cards[1].forgottenIn(testRoomID); len(forgotten) != 1 || forgotten[0] != scene.c.agent() {
		t.Fatalf("forgotten cards: %v", forgotten)
	}
	if gone, err := b.d.journal.ForgetRoomSender(testRoomID, scene.c.agent()); err != nil || gone {
		t.Fatalf("C's sequence record outlived its removal: %v %v", gone, err)
	}
	if n := storedParts(t, b); n != 0 {
		t.Fatalf("%d of C's parts outlived its removal", n)
	}
	if _, found := credentialOf(t, b, scene.c.agent()); found {
		t.Fatal("C's credential outlived its removal")
	}
}

// The runtime retires a room past end + retention + skew, on its timer and
// at start, with its parts dropped from memory first.
func TestRoomEndedRoomsAreRetiredByTheRuntime(t *testing.T) {
	retention := 10 * time.Minute
	partBytes := 4 * relayframe.MinTestPartBytes
	for _, start := range []bool{false, true} {
		scene := newJoinedSceneCut(t, retention, partBytes)
		b := scene.nodes[1]
		record := scene.authority.record
		pending := scene.authority.object(relayframe.RoomCommit, record.RoomEpoch, record.MLSEpoch+1, nil, make([]byte, 3*partBytes))
		if response := b.d.relay.Deliver(context.Background(), scene.a.agent(), framesOf(t, scene.a, pending, partBytes)[0]); response.Result != carrierapi.ResultAdmitted {
			t.Fatalf("the authority's stored part: %s/%s", response.Result, response.Code)
		}
		end := time.Unix(int64(scene.a.credential.ExpiresAtUnix), 0)
		scene.clock.set(end.Add(retention + 5*time.Minute - time.Second))
		b.d.relay.rooms.maintain()
		if _, found := fused(t, b); !found {
			t.Fatal("a room was retired before its time")
		}
		scene.clock.set(end.Add(retention + 5*time.Minute))
		if start {
			if err := b.d.installRoomRuntime(roomRuntimeSettings{driver: scene.driver, cards: scene.cards[1], skew: 5 * time.Minute,
				retention: retention, partBytes: partBytes}); err != nil {
				t.Fatalf("restart: %v", err)
			}
		} else {
			b.d.relay.rooms.maintain()
		}
		if _, found := fused(t, b); found {
			t.Fatalf("the ended room was not retired (at start %v)", start)
		}
		if n := storedParts(t, b); n != 0 {
			t.Fatalf("%d parts of the retired room are left (at start %v)", n, start)
		}
	}
}

// A device-ledger read that fails for a roster entry retries the roster:
// it does not skip the entry.
func TestRoomRosterRetriesWhenTheDeviceLedgerCannotBeRead(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	path := filepath.Join(b.d.config.StateDir, "devices", scene.c.delegation.EndpointID[len("mep_"):]+".json")
	if err := os.WriteFile(path, []byte("not a device record"), 0o600); err != nil {
		t.Fatal(err)
	}
	if response := send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.added, 0)); response.Result != carrierapi.ResultRetry {
		t.Fatalf("a roster whose member's device standing cannot be read: %s/%s", response.Result, response.Code)
	}
	if _, found := credentialOf(t, b, scene.c.agent()); found {
		t.Fatal("a credential was learned without its device standing")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.added, 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the redelivered roster: %+v", ack)
	}
}
