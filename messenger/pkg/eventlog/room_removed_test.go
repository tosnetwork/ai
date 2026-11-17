package eventlog

import (
	"strings"
	"testing"
	"time"
)

// The removal marker is kept once, needs an epoch above the member's own,
// survives a restart and goes with the room's receive state.
func TestRoomRemovalMarker(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/member"
	journal, ledger := openFused(t, root)
	record := fixture.installFounder(ledger, []byte("opaque founder state"))
	digest := strings.Repeat("cd", 32)
	now := fixture.now
	if _, _, err := journal.MarkRoomRemoved(record.RoomID, record.RoomEpoch, record.MLSEpoch+1, digest, now); err != ErrRoomRemovalEpoch {
		t.Fatalf("a removal at the member's own room epoch: %v", err)
	}
	if _, _, err := journal.MarkRoomRemoved(record.RoomID, record.RoomEpoch+1, record.MLSEpoch, digest, now); err != ErrRoomRemovalEpoch {
		t.Fatalf("a removal at the member's own MLS epoch: %v", err)
	}
	if _, found, err := journal.RoomRemovalOf(record.RoomID); err != nil || found {
		t.Fatalf("a refused removal was recorded: %v %v", found, err)
	}
	fresh, removal, err := journal.MarkRoomRemoved(record.RoomID, record.RoomEpoch+2, record.MLSEpoch+3, digest, now)
	if err != nil || !fresh || removal.MemberMLSEpoch != record.MLSEpoch || removal.RoomEpoch != record.RoomEpoch+2 {
		t.Fatalf("the removal: %+v %v %v", removal, fresh, err)
	}
	if fresh, kept, err := journal.MarkRoomRemoved(record.RoomID, record.RoomEpoch+3, record.MLSEpoch+4, strings.Repeat("ef", 32), now.Add(time.Minute)); err != nil || fresh || kept != removal {
		t.Fatalf("a second notice replaced the first: %+v %v %v", kept, fresh, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, _ = openFused(t, root)
	defer journal.Close()
	if kept, found, err := journal.RoomRemovalOf(record.RoomID); err != nil || !found || kept != removal {
		t.Fatalf("the marker after a restart: %+v %v %v", kept, found, err)
	}
	// It is receive state: deleted with the room's.
	journal.mutex.Lock()
	deleted, err := journal.deleteRoomState(record.RoomID)
	journal.mutex.Unlock()
	if err != nil || deleted == 0 {
		t.Fatalf("delete the room's receive state: %d %v", deleted, err)
	}
	if _, found, err := journal.RoomRemovalOf(record.RoomID); err != nil || found {
		t.Fatalf("the marker outlived the room's receive state: %v %v", found, err)
	}
}
