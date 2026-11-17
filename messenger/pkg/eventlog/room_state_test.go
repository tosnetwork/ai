package eventlog

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

func applicationObject(t *testing.T, mlsEpoch uint64, seed byte, bodyBytes int) []byte {
	t.Helper()
	object, err := relayframe.EncodeRoomObject(relayframe.RoomObject{Type: relayframe.RoomApplication, RoomID: fusedRoom,
		RoomEpoch: 1, MLSEpoch: mlsEpoch, Body: append([]byte{seed}, bytes.Repeat([]byte{0xab}, bodyBytes-1)...)})
	if err != nil {
		t.Fatal(err)
	}
	return object
}

// advanceRefreshes moves a founder room by MLS-only refreshes.
func advanceRefreshes(t *testing.T, fixture *fusedFixture, ledger *RoomMLSLedger, record RoomMLSRecord, count int) RoomMLSRecord {
	t.Helper()
	for index := 0; index < count; index++ {
		ref := canon.Digest([]byte(fmt.Sprintf("refresh %d", record.MLSEpoch+1)))
		var err error
		_, record, err = ledger.Advance(RoomMLSAdvance{Transition: refreshTransition(record, ref), ExpectedStateDigest: record.StateDigest,
			State: []byte(fmt.Sprintf("state %d", record.MLSEpoch+1)), EpochAuthenticator: fusedAuthenticator(byte(record.MLSEpoch + 2))}, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
	}
	return record
}

// The future-epoch buffer keeps exactly r < e <= r + 4, once per digest,
// and opens what the member has reached, in arrival order.
func TestRoomBufferWindowDuplicatesAndOpening(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	// The sender is the authority, whose leaf credential the room knows, so
	// only future epochs are held for it.
	sender := fusedAgent(0)
	if _, err := journal.BufferRoomObject(sender, applicationObject(t, 1, 1, 64), fixture.now); !errors.Is(err, ErrRoomNotJoined) {
		t.Fatalf("buffer before joining: %v", err)
	}
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	if _, err := journal.BufferRoomObject(sender, applicationObject(t, 0, 2, 64), fixture.now); !errors.Is(err, ErrRoomBufferCredentialKnown) {
		t.Fatalf("current epoch, known credential: %v", err)
	}
	for _, epoch := range []uint64{5, 6} {
		if _, err := journal.BufferRoomObject(sender, applicationObject(t, epoch, 2, 64), fixture.now); !errors.Is(err, ErrRoomBufferEpoch) {
			t.Fatalf("epoch %d: %v", epoch, err)
		}
	}
	for epoch := uint64(4); epoch >= 1; epoch-- {
		object := applicationObject(t, epoch, byte(epoch), 64)
		if fresh, err := journal.BufferRoomObject(sender, object, fixture.now.Add(time.Duration(5-epoch)*time.Second)); err != nil || !fresh {
			t.Fatalf("epoch %d: %v %v", epoch, fresh, err)
		}
		if fresh, err := journal.BufferRoomObject(sender, object, fixture.now); err != nil || fresh {
			t.Fatalf("duplicate at epoch %d: %v %v", epoch, fresh, err)
		}
	}
	if _, err := journal.BufferRoomObject(sender, []byte("not a room object"), fixture.now); err == nil {
		t.Fatal("garbage was buffered")
	}
	if openable, _, err := journal.OpenableRoomObjects(fusedRoom); err != nil || len(openable) != 0 {
		t.Fatalf("openable at epoch 0: %d %v", len(openable), err)
	}
	record = advanceRefreshes(t, fixture, ledger, record, 3)
	openable, drops, err := journal.OpenableRoomObjects(fusedRoom)
	if err != nil || len(drops) != 0 || len(openable) != 3 {
		t.Fatalf("openable at epoch 3: %d %d %v", len(openable), len(drops), err)
	}
	// Arrival order: epoch 3 arrived before epoch 2 before epoch 1.
	for index, want := range []uint64{3, 2, 1} {
		if openable[index].MLSEpoch != want || openable[index].SenderAgentID != sender {
			t.Fatalf("openable %d: epoch %d", index, openable[index].MLSEpoch)
		}
	}
	for _, object := range openable {
		if err := journal.ReleaseRoomObject(fusedRoom, object.Digest); err != nil {
			t.Fatal(err)
		}
	}
	// Moving past the epochs it can open drops the epoch-4 object as too old.
	_ = advanceRefreshes(t, fixture, ledger, record, 4)
	drops, err = journal.SweepRoomBuffer(fixture.now)
	if err != nil || len(drops) != 1 || drops[0].Reason != RoomBufferDropTooOld || drops[0].MLSEpoch != 4 {
		t.Fatalf("too-old drop: %+v %v", drops, err)
	}
}

// A sender holds at most 16 objects and 1 MiB of a room's buffer, a room 256
// objects and 8 MiB, and all rooms 32 MiB.
func TestRoomBufferBounds(t *testing.T) {
	if MaxRoomBufferObjects != 256 || MaxRoomBufferBytes != 8<<20 || MaxRoomBufferSenderObjects != 16 ||
		MaxRoomBufferSenderBytes != 1<<20 || MaxRoomBufferTotalBytes != 32<<20 || RoomBufferLookahead != 4 ||
		RoomBufferLifetime != 24*time.Hour+5*time.Minute {
		t.Fatal("a buffer bound differs from section 11.3")
	}
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	fixture.installFounder(ledger, []byte("epoch zero"))
	seed := 0
	next := func(bodyBytes int) []byte {
		seed++
		return applicationObject(t, 1, byte(seed), bodyBytes+seed%2)
	}
	// Sender count share.
	for index := 0; index < MaxRoomBufferSenderObjects; index++ {
		if _, err := journal.BufferRoomObject(fusedAgent(1), next(64), fixture.now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := journal.BufferRoomObject(fusedAgent(1), next(64), fixture.now); !errors.Is(err, ErrRoomBufferSenderFull) {
		t.Fatalf("17th object of a sender: %v", err)
	}
	// Sender byte share: seven maximal objects fit 1 MiB, an eighth does not.
	large := relayframe.MaxRoomApplicationBodyBytes - 1
	for index := 0; index < 7; index++ {
		if _, err := journal.BufferRoomObject(fusedAgent(2), next(large), fixture.now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := journal.BufferRoomObject(fusedAgent(2), next(large), fixture.now); !errors.Is(err, ErrRoomBufferSenderFull) {
		t.Fatalf("a sender's bytes beyond 1 MiB: %v", err)
	}
	// Room bytes: eight senders of seven maximal objects exceed 8 MiB.
	refused := false
	for agent := 3; agent < 12 && !refused; agent++ {
		for index := 0; index < 7; index++ {
			_, err := journal.BufferRoomObject(fusedAgent(agent), next(large), fixture.now)
			if errors.Is(err, ErrRoomBufferRoomFull) {
				refused = true
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if !refused {
		t.Fatal("a room's buffer passed 8 MiB")
	}
	// Total bytes, with the bound lowered to what is held so a test reaches
	// it: an object the room and sender shares still admit is refused.
	entries, err := journal.roomBufferEntries()
	if err != nil {
		t.Fatal(err)
	}
	held := 0
	for _, entry := range entries {
		held += entry.length
	}
	saved := roomBufferTotalCap
	roomBufferTotalCap = held + 10
	defer func() { roomBufferTotalCap = saved }()
	if _, err := journal.BufferRoomObject(fusedAgent(20), next(64), fixture.now); !errors.Is(err, ErrRoomBufferTotalFull) {
		t.Fatalf("total bound: %v", err)
	}
	roomBufferTotalCap = saved
	if _, err := journal.BufferRoomObject(fusedAgent(20), next(64), fixture.now); err != nil {
		t.Fatalf("under the total bound: %v", err)
	}
}

// The room object-count bound: 256 objects from 16 senders fill a room.
func TestRoomBufferRoomObjectCount(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	fixture.installFounder(ledger, []byte("epoch zero"))
	for agent := 0; agent < MaxRoomBufferObjects/MaxRoomBufferSenderObjects; agent++ {
		for index := 0; index < MaxRoomBufferSenderObjects; index++ {
			object := applicationObject(t, 1, byte(index), 64+agent)
			if _, err := journal.BufferRoomObject(fusedAgent(1+agent), object, fixture.now); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := journal.BufferRoomObject(fusedAgent(30), applicationObject(t, 1, 1, 200), fixture.now); !errors.Is(err, ErrRoomBufferRoomFull) {
		t.Fatalf("257th object: %v", err)
	}
}

// A buffered object older than 24 h 5 min is dropped by a sweep; a damaged
// record is dropped when the room opens its buffer.
func TestRoomBufferExpiryAndDamage(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	for epoch := uint64(1); epoch <= 2; epoch++ {
		if _, err := journal.BufferRoomObject(fusedAgent(0), applicationObject(t, epoch, 1, 64), fixture.now); err != nil {
			t.Fatal(err)
		}
	}
	if drops, err := journal.SweepRoomBuffer(fixture.now.Add(RoomBufferLifetime - time.Second)); err != nil || len(drops) != 0 {
		t.Fatalf("early sweep: %+v %v", drops, err)
	}
	entries, err := journal.roomBufferEntries()
	if err != nil || len(entries) != 2 {
		t.Fatal(err)
	}
	if err := journal.replace(filepath.Join(journal.root, roomBufferDir, entries[0].name), []byte(`{"schema":"other"}`)); err != nil {
		t.Fatal(err)
	}
	advanceRefreshes(t, fixture, ledger, record, 1)
	openable, drops, err := journal.OpenableRoomObjects(fusedRoom)
	if err != nil || len(openable) != 0 || len(drops) != 1 || drops[0].Reason != RoomBufferDropDamaged {
		t.Fatalf("damaged record: %d %+v %v", len(openable), drops, err)
	}
	drops, err = journal.SweepRoomBuffer(fixture.now.Add(RoomBufferLifetime))
	if err != nil || len(drops) != 1 || drops[0].Reason != RoomBufferDropExpired {
		t.Fatalf("expiry: %+v %v", drops, err)
	}
}

func objectDigest(label string) string { return RoomObjectDigest([]byte(label)) }

// Commits and Welcomes are judged by MLS epoch: duplicate among the applied,
// apply the next, fork within the window, stale below it, gap above next.
func TestRoomHandshakeJudgement(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	judge := func(epoch uint64, label string) HandshakeVerdict {
		t.Helper()
		verdict, err := journal.JudgeRoomHandshake(fusedRoom, epoch, objectDigest(label))
		if err != nil {
			t.Fatal(err)
		}
		return verdict
	}
	if judge(1, "c1") != HandshakeApply || judge(2, "c2") != HandshakeGap || judge(0, "other at 0") != HandshakeFork {
		t.Fatal("judgement at epoch 0")
	}
	for epoch := uint64(1); epoch <= RoomAppliedWindow+2; epoch++ {
		label := fmt.Sprintf("c%d", epoch)
		ref := canon.Digest([]byte(fmt.Sprintf("refresh %d", epoch)))
		if err := journal.BeginRoomHandshake(fusedRoom, epoch, objectDigest(label), ref); err != nil {
			t.Fatal(err)
		}
		record = advanceRefreshes(t, fixture, ledger, record, 1)
		if err := journal.CompleteRoomHandshake(fusedRoom, epoch, objectDigest(label)); err != nil {
			t.Fatal(err)
		}
	}
	current := record.MLSEpoch
	if judge(current, fmt.Sprintf("c%d", current)) != HandshakeDuplicate {
		t.Fatal("the last applied Commit is not a duplicate")
	}
	if judge(current, "another for the current epoch") != HandshakeFork || judge(current-63, "another in the window") != HandshakeFork {
		t.Fatal("a second Commit for an epoch in the window is not a fork")
	}
	if judge(current-64, "below the window") != HandshakeStale || judge(1, "c1") != HandshakeStale {
		t.Fatal("an object older than the 64 retained is not stale")
	}
	if judge(current+1, "next") != HandshakeApply || judge(current+2, "beyond") != HandshakeGap {
		t.Fatal("next or gap")
	}
	if _, err := journal.JudgeRoomHandshake("room_"+string(bytes.Repeat([]byte("7"), 64)), 1, objectDigest("x")); !errors.Is(err, ErrRoomNotJoined) {
		t.Fatalf("an unjoined room: %v", err)
	}
}

// A crash between the fused write and CompleteRoomHandshake leaves the
// Commit applied: its repeat is a duplicate, not a fork of itself. A crash
// before the fused write leaves it to apply again.
func TestRoomHandshakeIntentSurvivesACrash(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	if err := journal.BeginRoomHandshake(fusedRoom, 1, objectDigest("c1"), canon.Digest([]byte("refresh 1"))); err != nil {
		t.Fatal(err)
	}
	// Crash before the advance: the intent is discarded.
	journal, ledger = reopenFused(t, journal, root)
	if verdict, err := journal.JudgeRoomHandshake(fusedRoom, 1, objectDigest("c1")); err != nil || verdict != HandshakeApply {
		t.Fatalf("before the advance: %v %v", verdict, err)
	}
	if err := journal.BeginRoomHandshake(fusedRoom, 1, objectDigest("c1"), canon.Digest([]byte("refresh 1"))); err != nil {
		t.Fatal(err)
	}
	advanceRefreshes(t, fixture, ledger, record, 1)
	// Crash after the advance, before CompleteRoomHandshake.
	journal, _ = reopenFused(t, journal, root)
	defer journal.Close()
	if verdict, err := journal.JudgeRoomHandshake(fusedRoom, 1, objectDigest("c1")); err != nil || verdict != HandshakeDuplicate {
		t.Fatalf("after the advance: %v %v", verdict, err)
	}
	if verdict, _ := journal.JudgeRoomHandshake(fusedRoom, 1, objectDigest("another c1")); verdict != HandshakeFork {
		t.Fatalf("a second Commit for epoch 1: %v", verdict)
	}
}

func reopenFused(t *testing.T, journal *Journal, root string) (*Journal, *RoomMLSLedger) {
	t.Helper()
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	return openFused(t, root)
}

// Rosters are judged by room epoch within [current - 2, current].
func TestRoomRosterJudgement(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	for index := 1; index <= 3; index++ {
		record, _ = addWithOutput(t, fixture, ledger, record, fusedAgent(index), fmt.Sprintf("add %d", index))
	}
	if record.RoomEpoch != 4 {
		t.Fatalf("room epoch %d", record.RoomEpoch)
	}
	judge := func(epoch uint64, label string) RosterVerdict {
		t.Helper()
		verdict, err := journal.JudgeRoomRoster(fusedRoom, epoch, objectDigest(label))
		if err != nil {
			t.Fatal(err)
		}
		return verdict
	}
	if judge(4, "r4") != RosterAccept || judge(2, "r2") != RosterAccept || judge(1, "r1") != RosterStale || judge(5, "r5") != RosterGap {
		t.Fatal("roster window")
	}
	if err := journal.RecordRoomRoster(fusedRoom, 4, objectDigest("r4")); err != nil {
		t.Fatal(err)
	}
	if judge(4, "r4") != RosterDuplicate || judge(4, "another r4") != RosterConflict {
		t.Fatal("duplicate or conflict")
	}
	if err := journal.RecordRoomRoster(fusedRoom, 4, objectDigest("another r4")); err == nil {
		t.Fatal("a conflicting roster was recorded")
	}
}

// The retained digests are the last 64.
func TestRoomAppliedKeepsTheLast64(t *testing.T) {
	entries := []appliedEntry{}
	for index := 0; index < RoomAppliedWindow+5; index++ {
		entries = appendApplied(entries, appliedEntry{Epoch: uint64(index), Digest: objectDigest(fmt.Sprint(index))})
	}
	if len(entries) != RoomAppliedWindow || entries[0].Epoch != 5 {
		t.Fatalf("%d entries from %d", len(entries), entries[0].Epoch)
	}
	if again := appendApplied(entries, entries[10]); len(again) != RoomAppliedWindow {
		t.Fatal("a repeated digest was added twice")
	}
}

// A received application digest is a duplicate for 24 h 5 min, then
// forgotten; the markers are bounded in total, per room and per sender.
func TestRoomReceivedDigests(t *testing.T) {
	root := t.TempDir() + "/state"
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, root)
	// Only a held room keeps its receive state across a restart.
	fixture.installFounder(ledger, []byte("epoch zero"))
	now := time.Unix(1_900_000_000, 0)
	sender := fusedAgent(1)
	digest := objectDigest("message")
	if seen, err := journal.RoomApplicationSeen(fusedRoom, sender, digest, now); err != nil || seen {
		t.Fatalf("unseen: %v %v", seen, err)
	}
	if fresh, err := journal.MarkRoomApplicationSeen(fusedRoom, sender, digest, now); err != nil || !fresh {
		t.Fatal(err)
	}
	if fresh, err := journal.MarkRoomApplicationSeen(fusedRoom, sender, digest, now.Add(time.Hour)); err != nil || fresh {
		t.Fatal("a repeat was fresh")
	}
	if seen, _ := journal.RoomApplicationSeen(fusedRoom, sender, digest, now.Add(RoomReceivedWindow-time.Second)); !seen {
		t.Fatal("forgotten inside the window")
	}
	if seen, _ := journal.RoomApplicationSeen(fusedRoom, sender, digest, now.Add(RoomReceivedWindow)); seen {
		t.Fatal("kept beyond the window")
	}
	saved := [3]int{roomReceivedCap, roomReceivedRoomCap, roomReceivedSenderCap}
	defer func() { roomReceivedCap, roomReceivedRoomCap, roomReceivedSenderCap = saved[0], saved[1], saved[2] }()
	roomReceivedCap, roomReceivedRoomCap, roomReceivedSenderCap = 6, 4, 2
	mark := func(room, from, label string, at time.Time) error {
		_, err := journal.MarkRoomApplicationSeen(room, from, objectDigest(label), at)
		return err
	}
	// One sender's share.
	for index := 0; index < 2; index++ {
		if err := mark(fusedRoom, sender, fmt.Sprint("a", index), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := mark(fusedRoom, sender, "a2", now); !errors.Is(err, ErrRoomReceivedFull) {
		t.Fatalf("beyond a sender's share: %v", err)
	}
	// A room's share.
	for index := 0; index < 2; index++ {
		if err := mark(fusedRoom, fusedAgent(2), fmt.Sprint("b", index), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := mark(fusedRoom, fusedAgent(3), "c0", now); !errors.Is(err, ErrRoomReceivedFull) {
		t.Fatalf("beyond a room's share: %v", err)
	}
	// The total, across rooms.
	other := "room_" + strings.Repeat("6", 64)
	for index := 0; index < 2; index++ {
		if err := mark(other, fusedAgent(2), fmt.Sprint("d", index), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := mark("room_"+strings.Repeat("7", 64), fusedAgent(2), "e0", now); !errors.Is(err, ErrRoomReceivedFull) {
		t.Fatalf("beyond the total: %v", err)
	}
	// Expired markers are swept at a bound; the counts survive a restart.
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, _ = openFused(t, root)
	defer journal.Close()
	if err := mark(fusedRoom, sender, "a2", now); !errors.Is(err, ErrRoomReceivedFull) {
		t.Fatalf("the counts were lost by a restart: %v", err)
	}
	if err := mark(fusedRoom, sender, "a2", now.Add(RoomReceivedWindow)); err != nil {
		t.Fatalf("expired markers were not swept at the bound: %v", err)
	}
}

// A sequence jump records the missing range, declared only T after it was
// noticed; a late sequence fills it.
func TestRoomSequenceGapsAfterTheDelay(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	now := time.Unix(1_900_000_000, 0)
	sender := fusedAgent(1)
	delay, err := RoomGapDelay(3600)
	if err != nil || delay != time.Hour+5*time.Minute {
		t.Fatalf("T: %s %v", delay, err)
	}
	for _, ttl := range []uint64{0, 86_401} {
		if _, err := RoomGapDelay(ttl); err == nil {
			t.Fatalf("TTL %d accepted", ttl)
		}
	}
	for _, sequence := range []uint64{1, 2, 6} {
		if err := journal.ObserveRoomSequence(fusedRoom, sender, sequence, now); err != nil {
			t.Fatal(err)
		}
	}
	// 4 arrives late; 3 and 5 stay missing.
	if err := journal.ObserveRoomSequence(fusedRoom, sender, 4, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if declared, err := journal.SweepRoomSequences(now.Add(delay-time.Second), delay); err != nil || len(declared) != 0 {
		t.Fatalf("early: %+v %v", declared, err)
	}
	declared, err := journal.SweepRoomSequences(now.Add(delay), delay)
	if err != nil || len(declared) != 2 {
		t.Fatalf("declared: %+v %v", declared, err)
	}
	gaps, err := journal.RoomGaps(fusedRoom, 0)
	if err != nil || len(gaps) != 2 {
		t.Fatalf("gaps: %+v %v", gaps, err)
	}
	ranges := map[[2]uint64]bool{}
	for _, gap := range gaps {
		if gap.Reason != RoomGapNotArrived || gap.SenderAgentID != sender {
			t.Fatalf("gap: %+v", gap)
		}
		ranges[[2]uint64{gap.FirstSequence, gap.LastSequence}] = true
	}
	if !ranges[[2]uint64{3, 3}] || !ranges[[2]uint64{5, 5}] {
		t.Fatalf("ranges: %v", ranges)
	}
	// Zero is a sender that keeps no sequence.
	if err := journal.ObserveRoomSequence(fusedRoom, sender, 0, now); err != nil {
		t.Fatal(err)
	}
}

// An object dropped unopened opens a sender-only gap that the sender's next
// sequence fixes at once; drops before it share the record.
func TestRoomDropGapIsFixedByTheNextSequence(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	now := time.Unix(1_900_000_000, 0)
	sender := fusedAgent(1)
	if err := journal.ObserveRoomSequence(fusedRoom, sender, 1, now); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.RecordRoomDrop(fusedRoom, sender, RoomGapNotArrived, now); err == nil {
		t.Fatal("not-arrived is no drop reason")
	}
	first, err := journal.RecordRoomDrop(fusedRoom, sender, RoomGapEpochTooOld, now)
	if err != nil || first.FirstSequence != 0 || first.Dropped != 1 {
		t.Fatalf("drop: %+v %v", first, err)
	}
	second, err := journal.RecordRoomDrop(fusedRoom, sender, RoomGapBufferFull, now.Add(time.Second))
	if err != nil || second.ID != first.ID || second.Dropped != 2 {
		t.Fatalf("second drop: %+v %v", second, err)
	}
	if err := journal.ObserveRoomSequence(fusedRoom, sender, 4, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	gaps, err := journal.RoomGaps(fusedRoom, 0)
	if err != nil || len(gaps) != 1 || gaps[0].FirstSequence != 2 || gaps[0].LastSequence != 3 {
		t.Fatalf("fixed gap: %+v %v", gaps, err)
	}
	// The range was declared with the drop; nothing waits for the delay.
	if declared, err := journal.SweepRoomSequences(now.Add(48*time.Hour), time.Hour); err != nil || len(declared) != 0 {
		t.Fatalf("a fixed drop range was declared again: %+v %v", declared, err)
	}
}

// Missing ranges and gap records are bounded.
func TestRoomSequenceBounds(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	now := time.Unix(1_900_000_000, 0)
	sender := fusedAgent(1)
	saved := roomGapCap
	roomGapCap = 5
	defer func() { roomGapCap = saved }()
	for index := 0; index <= MaxRoomMissingRanges+3; index++ {
		if err := journal.ObserveRoomSequence(fusedRoom, sender, uint64(2*index+2), now.Add(time.Duration(index))); err != nil {
			t.Fatal(err)
		}
	}
	record, err := journal.readRoomSequence(fusedRoom, sender)
	if err != nil || len(record.Missing) != MaxRoomMissingRanges {
		t.Fatalf("%d missing ranges: %v", len(record.Missing), err)
	}
	gaps, err := journal.RoomGaps(fusedRoom, 0)
	if err != nil || len(gaps) != 4 {
		t.Fatalf("%d gaps declared beyond the range bound: %v", len(gaps), err)
	}
	for index := 0; index < 3; index++ {
		if _, err := journal.SweepRoomSequences(now.Add(time.Duration(index+1)*time.Hour), time.Nanosecond); err != nil {
			t.Fatal(err)
		}
	}
	names, err := journal.roomGapNames(fusedRoom)
	if err != nil || len(names) != 5 {
		t.Fatalf("%d gap records kept, bound 5: %v", len(names), err)
	}
	if _, err := journal.RoomGaps(fusedRoom, MaxRoomGapsPerResponse+1); err == nil {
		t.Fatal("an oversized listing was accepted")
	}
}

// A drop stays open until a jump reveals its range: with reordered
// deliveries the next sequence need not be past the dropped one.
func TestRoomDropStaysOpenUntilAJump(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	now := time.Unix(1_900_000_000, 0)
	sender := fusedAgent(1)
	if err := journal.ObserveRoomSequence(fusedRoom, sender, 1, now); err != nil {
		t.Fatal(err)
	}
	// The object carrying 3 is dropped unopened; 2 arrives after it.
	if _, err := journal.RecordRoomDrop(fusedRoom, sender, RoomGapEpochTooOld, now); err != nil {
		t.Fatal(err)
	}
	if err := journal.ObserveRoomSequence(fusedRoom, sender, 2, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := journal.ObserveRoomSequence(fusedRoom, sender, 4, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	gaps, err := journal.RoomGaps(fusedRoom, 0)
	if err != nil || len(gaps) != 1 || gaps[0].FirstSequence != 3 || gaps[0].LastSequence != 3 {
		t.Fatalf("the drop's range: %+v %v", gaps, err)
	}
}

// A drop whose open record was pruned under the gap bounds still has its
// range declared at the sender's next jump: sequence 1, a drop, the drop
// pruned through other senders' gaps, then sequence 100 declares 2-99.
func TestRoomPrunedDropRangeIsStillDeclared(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	now := time.Unix(1_900_000_000, 0)
	saved := roomGapCap
	roomGapCap = 3
	defer func() { roomGapCap = saved }()
	sender := fusedAgent(1)
	if err := journal.ObserveRoomSequence(fusedRoom, sender, 1, now); err != nil {
		t.Fatal(err)
	}
	drop, err := journal.RecordRoomDrop(fusedRoom, sender, RoomGapBufferFull, now)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		if _, err := journal.RecordRoomDrop(fusedRoom, fusedAgent(2+index), RoomGapBufferFull,
			now.Add(time.Duration(index+1)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if _, found, err := journal.readRoomGap(fusedRoom, drop.ID); err != nil || found {
		t.Fatalf("the open drop was not pruned: %v %v", found, err)
	}
	if err := journal.ObserveRoomSequence(fusedRoom, sender, 100, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	gaps, err := journal.RoomGaps(fusedRoom, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := false
	for _, gap := range gaps {
		if gap.SenderAgentID == sender && gap.FirstSequence == 2 && gap.LastSequence == 99 {
			declared = true
		}
	}
	if !declared {
		t.Fatalf("the range 2-99 of a pruned drop was lost: %+v", gaps)
	}
	record, err := journal.readRoomSequence(fusedRoom, sender)
	if err != nil || record.OpenDrop != "" || len(record.Missing) != 0 || record.Highest != 100 {
		t.Fatalf("sequence record: %+v %v", record, err)
	}
}

// One sender's share of a room's gap records, and the bound across rooms.
func TestRoomGapSharesAndTotal(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	now := time.Unix(1_900_000_000, 0)
	saved := [3]int{roomGapCap, roomGapSenderCap, roomGapTotalCap}
	defer func() { roomGapCap, roomGapSenderCap, roomGapTotalCap = saved[0], saved[1], saved[2] }()
	roomGapCap, roomGapSenderCap, roomGapTotalCap = 6, 3, 8
	drop := func(room string, sender string, at time.Duration) {
		t.Helper()
		// A drop and a jump make one declared gap each time.
		if _, err := journal.RecordRoomDrop(room, sender, RoomGapBufferFull, now.Add(at)); err != nil {
			t.Fatal(err)
		}
		record, err := journal.readRoomSequence(room, sender)
		if err != nil {
			t.Fatal(err)
		}
		if err := journal.ObserveRoomSequence(room, sender, record.Highest+2, now.Add(at)); err != nil {
			t.Fatal(err)
		}
	}
	noisy, quiet := fusedAgent(1), fusedAgent(2)
	drop(fusedRoom, quiet, 0)
	for index := 1; index <= 5; index++ {
		drop(fusedRoom, noisy, time.Duration(index)*time.Second)
	}
	gaps, err := journal.RoomGaps(fusedRoom, 0)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, gap := range gaps {
		counts[gap.SenderAgentID]++
	}
	if counts[noisy] != 3 || counts[quiet] != 1 {
		t.Fatalf("shares: %v", counts)
	}
	other := "room_" + strings.Repeat("6", 64)
	for index := 0; index < 6; index++ {
		drop(other, fusedAgent(3+index), time.Duration(10+index)*time.Second)
	}
	all, err := journal.allRoomGapNames()
	if err != nil || len(all) != 8 {
		t.Fatalf("%d gap records across rooms, bound 8: %v", len(all), err)
	}
}

// The per (room, sender) sequence records are bounded across rooms.
func TestRoomSequenceRecordsAreBounded(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	saved := roomSequenceCap
	roomSequenceCap = 2
	defer func() { roomSequenceCap = saved }()
	now := time.Unix(1_900_000_000, 0)
	for index := 0; index < 2; index++ {
		if err := journal.ObserveRoomSequence(fusedRoom, fusedAgent(index), 1, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := journal.ObserveRoomSequence(fusedRoom, fusedAgent(5), 1, now); !errors.Is(err, ErrRoomSequencesFull) {
		t.Fatalf("beyond the bound: %v", err)
	}
	if err := journal.ObserveRoomSequence(fusedRoom, fusedAgent(0), 2, now); err != nil {
		t.Fatalf("an existing record at the bound: %v", err)
	}
	if removed, err := journal.ForgetRoomSender(fusedRoom, fusedAgent(1)); err != nil || !removed {
		t.Fatalf("forget sender: %v %v", removed, err)
	}
	if err := journal.ObserveRoomSequence(fusedRoom, fusedAgent(5), 1, now); err != nil {
		t.Fatalf("a removed member's record still counted: %v", err)
	}
}

// A room's receive state is deleted once the room is neither held nor
// pending: on request, and at restart for what a crash left.
func TestRoomStateIsForgottenWithTheRoom(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	fixture.installFounder(ledger, []byte("epoch zero"))
	now := time.Unix(1_900_000_000, 0)
	other := "room_" + strings.Repeat("6", 64)
	for _, roomID := range []string{fusedRoom, other} {
		if err := journal.ObserveRoomSequence(roomID, fusedAgent(1), 3, now); err != nil {
			t.Fatal(err)
		}
		if _, err := journal.RecordRoomDrop(roomID, fusedAgent(1), RoomGapBufferFull, now); err != nil {
			t.Fatal(err)
		}
		if _, err := journal.MarkRoomApplicationSeen(roomID, fusedAgent(1), objectDigest(roomID), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := journal.BeginRoomHandshake(fusedRoom, 1, objectDigest("c1"), canon.Digest([]byte("ref"))); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.ForgetRoomState(fusedRoom); !errors.Is(err, ErrRoomStillHeld) {
		t.Fatalf("a held room's state was forgotten: %v", err)
	}
	if deleted, err := journal.ForgetRoomState(other); err != nil || deleted != 3 {
		t.Fatalf("forget: %d %v", deleted, err)
	}
	// What a crash leaves for a room no longer held is deleted at restart.
	if err := journal.ObserveRoomSequence(other, fusedAgent(2), 1, now); err != nil {
		t.Fatal(err)
	}
	journal, _ = reopenFused(t, journal, root)
	defer journal.Close()
	if gaps, err := journal.RoomGaps(fusedRoom, 0); err != nil || len(gaps) != 1 {
		t.Fatalf("the held room lost its state: %d %v", len(gaps), err)
	}
	record, err := journal.readRoomSequence(other, fusedAgent(2))
	if err != nil || record.Highest != 0 {
		t.Fatalf("an orphaned sequence record survived restart: %+v %v", record, err)
	}
}

// A joiner's Welcome, recorded around its install, makes every later copy of
// it a duplicate: after CompleteRoomHandshake, and after a crash before it.
func TestJoinerWelcomeRedepositIsADuplicate(t *testing.T) {
	for _, crash := range []bool{false, true} {
		fixture := newFusedFixture(t)
		root := t.TempDir() + "/state"
		journal, ledger := openFused(t, root)
		membership := fixture.founding()
		welcome := []byte("the joiner's welcome")
		welcomeRef := canon.Digest(welcome)
		digest := RoomObjectDigest(welcome)
		if err := journal.BeginRoomHandshake(fusedRoom, 4, digest, welcomeRef); err != nil {
			t.Fatal(err)
		}
		keyPackageRef := prepareJoin(t, journal, fixture)
		if _, err := ledger.InstallWelcome(RoomMLSInstall{
			Binding: group.State{RoomID: fusedRoom, Clock: group.Clock{RoomEpoch: 1, MLSEpoch: 4}, MembershipDigest: membership.Digest},
			Proof:   fixture.proof(membership), State: []byte("joined"), EpochAuthenticator: fusedAuthenticator(4),
			KeyPackageRef: keyPackageRef, WelcomeRef: welcomeRef,
			Credentials: fixture.credentials(), EndsAtUnix: testRoomEnd,
		}, fixture.now); err != nil {
			t.Fatal(err)
		}
		if crash {
			journal, _ = reopenFused(t, journal, root)
		} else if err := journal.CompleteRoomHandshake(fusedRoom, 4, digest); err != nil {
			t.Fatal(err)
		}
		verdict, err := journal.JudgeRoomHandshake(fusedRoom, 4, digest)
		if err != nil || verdict != HandshakeDuplicate {
			t.Fatalf("crash=%v: re-deposited Welcome %v %v", crash, verdict, err)
		}
		if verdict, _ := journal.JudgeRoomHandshake(fusedRoom, 4, objectDigest("another welcome")); verdict != HandshakeFork {
			t.Fatalf("crash=%v: another object for the Welcome's epoch: %v", crash, verdict)
		}
		journal.Close()
	}
}
