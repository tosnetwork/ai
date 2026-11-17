package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// heldObjects counts the records of a node's future-epoch buffer.
func heldObjects(t *testing.T, node *relayNode) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(node.d.config.StateDir, "room-epoch-buffer"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			count++
		}
	}
	return count
}

// refreshes makes the authority's next n MLS-only refreshes and returns
// their Commit objects.
func refreshes(scene *joinedScene, n int) [][]byte {
	objects := make([][]byte, 0, n)
	for index := 0; index < n; index++ {
		result, membership := scene.authority.commit()
		objects = append(objects, scene.authority.commitObject(result, membership))
	}
	return objects
}

func applyAt(t *testing.T, scene *joinedScene, objects [][]byte) {
	t.Helper()
	b := scene.nodes[1]
	for _, object := range objects {
		if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, object, 0))); ack.Outcome != relayframe.OutcomeAccepted {
			t.Fatalf("B applies a refresh: %+v", ack)
		}
	}
}

// The past-epoch boundary (review of #41): an object sealed at e = r − 2
// opens, one sealed at e = r − 3 is an epoch-too-old gap.
func TestRoomApplicationPastEpochBoundary(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	a := authoritySealer(t, scene.authority)
	now := scene.clock.now()
	tooOld := a.message(1, "sealed three epochs back", now, sealOptions{})
	applyAt(t, scene, refreshes(scene, 1))
	twoBack := a.message(2, "sealed two epochs back", now, sealOptions{})
	applyAt(t, scene, refreshes(scene, 2))
	before, _ := fused(t, b)
	requireOpened(t, b, deliverApplication(t, b, scene.a, twoBack.object), scene.a.agent(), twoBack, before)
	if response := deliverApplication(t, b, scene.a, tooOld.object); response.Result != carrierapi.ResultIgnored {
		t.Fatalf("e = r - 3 answered %s/%s", response.Result, response.Code)
	}
	requireGap(t, b, scene.a.agent(), eventlog.RoomGapEpochTooOld, 1)
}

// The future-epoch boundary (review of #41): an object sealed at e = r + 4
// is held, one sealed at e = r + 5 is an epoch-too-new gap. The intake's
// window and the buffer's own epoch check are one bound: the buffer check is
// declared redundant in the red controls.
func TestRoomApplicationFutureEpochBoundary(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	a := authoritySealer(t, scene.authority)
	now := scene.clock.now()
	refreshes(scene, 4)
	fourAhead := a.message(1, "sealed four epochs ahead", now, sealOptions{})
	refreshes(scene, 1)
	fiveAhead := a.message(2, "sealed five epochs ahead", now, sealOptions{})
	if response := deliverApplication(t, b, scene.a, fourAhead.object); response.Result != carrierapi.ResultAdmitted {
		t.Fatalf("e = r + 4 answered %s/%s", response.Result, response.Code)
	}
	if count := heldObjects(t, b); count != 1 {
		t.Fatalf("e = r + 4 was not held: %d", count)
	}
	if response := deliverApplication(t, b, scene.a, fiveAhead.object); response.Result != carrierapi.ResultIgnored {
		t.Fatalf("e = r + 5 answered %s/%s", response.Result, response.Code)
	}
	requireGap(t, b, scene.a.agent(), eventlog.RoomGapEpochTooNew, 1)
}

// A buffered object's gap is written before its record is deleted (review
// of #41): a failed gap write keeps the held object, and the next pass
// records the gap and drops it.
func TestRoomApplicationBufferDropKeepsTheObjectUntilItsGapIsWritten(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	a := authoritySealer(t, scene.authority)
	scene.authority.commit()
	held := a.message(1, "its Commit never comes", scene.clock.now(), sealOptions{})
	if response := deliverApplication(t, b, scene.a, held.object); response.Result != carrierapi.ResultAdmitted {
		t.Fatalf("a next-epoch object answered %s/%s", response.Result, response.Code)
	}
	scene.clock.set(scene.clock.now().Add(eventlog.RoomBufferLifetime))
	gaps := filepath.Join(b.d.config.StateDir, "room-gaps")
	if err := os.Chmod(gaps, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(gaps, 0o700) })
	b.d.relay.rooms.maintain()
	if err := os.Chmod(gaps, 0o700); err != nil {
		t.Fatal(err)
	}
	if count := heldObjects(t, b); count != 1 {
		t.Fatalf("a drop whose gap was not written deleted the held object: %d", count)
	}
	if gapsNow := gapsOf(t, b); len(gapsNow) != 0 {
		t.Fatalf("a gap was recorded into an unwritable store: %+v", gapsNow)
	}
	scene.clock.set(scene.clock.now().Add(time.Second))
	b.d.relay.rooms.maintain()
	requireGap(t, b, scene.a.agent(), eventlog.RoomGapBufferExpired, 1)
	if count := heldObjects(t, b); count != 0 {
		t.Fatalf("the dropped object is still held: %d", count)
	}
}
