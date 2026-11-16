package eventlog

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
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
	sender := fusedAgent(1)
	if _, err := journal.BufferRoomObject(sender, applicationObject(t, 1, 1, 64), fixture.now); !errors.Is(err, ErrRoomNotJoined) {
		t.Fatalf("buffer before joining: %v", err)
	}
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	for _, epoch := range []uint64{0, 5, 6} {
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
		if _, err := journal.BufferRoomObject(fusedAgent(1), applicationObject(t, epoch, 1, 64), fixture.now); err != nil {
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
// forgotten; the markers are bounded.
func TestRoomReceivedDigests(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	now := time.Unix(1_900_000_000, 0)
	digest := objectDigest("message")
	if seen, err := journal.RoomApplicationSeen(fusedRoom, digest, now); err != nil || seen {
		t.Fatalf("unseen: %v %v", seen, err)
	}
	if fresh, err := journal.MarkRoomApplicationSeen(fusedRoom, digest, now); err != nil || !fresh {
		t.Fatal(err)
	}
	if fresh, err := journal.MarkRoomApplicationSeen(fusedRoom, digest, now.Add(time.Hour)); err != nil || fresh {
		t.Fatal("a repeat was fresh")
	}
	if seen, _ := journal.RoomApplicationSeen(fusedRoom, digest, now.Add(RoomReceivedWindow-time.Second)); !seen {
		t.Fatal("forgotten inside the window")
	}
	if seen, _ := journal.RoomApplicationSeen(fusedRoom, digest, now.Add(RoomReceivedWindow)); seen {
		t.Fatal("kept beyond the window")
	}
	saved := roomReceivedCap
	roomReceivedCap = 2
	defer func() { roomReceivedCap = saved }()
	for index := 0; index < 2; index++ {
		if _, err := journal.MarkRoomApplicationSeen(fusedRoom, objectDigest(fmt.Sprint(index)), now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := journal.MarkRoomApplicationSeen(fusedRoom, objectDigest("third"), now); !errors.Is(err, ErrRoomReceivedFull) {
		t.Fatalf("beyond the bound: %v", err)
	}
	if fresh, err := journal.MarkRoomApplicationSeen(fusedRoom, objectDigest("third"), now.Add(RoomReceivedWindow)); err != nil || !fresh {
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
