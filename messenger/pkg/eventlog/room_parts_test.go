package eventlog

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

type partSenders struct{ allowed map[string]bool }

func (s partSenders) MayHold(sender string) bool          { return s.allowed[sender] }
func (s partSenders) MayHoldInRoom(sender, _ string) bool { return s.allowed[sender] }
func allowSenders(agents ...string) partSenders           { return partSenders{allowed: setOf(agents)} }
func setOf(agents []string) map[string]bool {
	m := map[string]bool{}
	for _, a := range agents {
		m[a] = true
	}
	return m
}
func partTestLimits(partBytes int) relayframe.ReassemblyLimits {
	l := relayframe.DefaultReassemblyLimits()
	l.PartBytes = partBytes
	return l
}

// splitObject builds an MLS-only refresh Commit of bodyBytes and cuts it at
// the test part size.
func splitObject(t *testing.T, seed byte, bodyBytes, partBytes int) ([]relayframe.Frame, [sha256.Size]byte) {
	t.Helper()
	object, err := relayframe.EncodeRoomObject(relayframe.RoomObject{Type: relayframe.RoomCommit, RoomID: fusedRoom,
		RoomEpoch: 1, MLSEpoch: 2, Body: bytes.Repeat([]byte{seed}, bodyBytes)})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := relayframe.SplitRoomObject(object, []byte("card"), []byte("evidence"), partBytes)
	if err != nil {
		t.Fatal(err)
	}
	frames := make([]relayframe.Frame, len(encoded))
	for index, raw := range encoded {
		if frames[index], err = relayframe.Decode(raw); err != nil {
			t.Fatal(err)
		}
	}
	return frames, relayframe.ObjectDigest(object)
}

func openParts(t *testing.T, journal *Journal, senders relayframe.SenderSet, now time.Time) (*RoomParts, RoomPartReplay) {
	t.Helper()
	reassembler, err := relayframe.NewReassembler(partTestLimits(1024), senders)
	if err != nil {
		t.Fatal(err)
	}
	parts, report, err := journal.OpenRoomParts(reassembler, now)
	if err != nil {
		t.Fatal(err)
	}
	return parts, report
}

func storedPartCount(t *testing.T, journal *Journal) int {
	t.Helper()
	count, err := countEntries(filepath.Join(journal.root, roomPartDir))
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func reopen(t *testing.T, journal *Journal, root string) *Journal {
	t.Helper()
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	return reopened
}

// Held parts survive a restart: they are replayed into a new Reassembler and
// the object completes with the part that arrives after it; settling the
// completed object deletes its parts.
func TestRoomPartsSurviveARestartAndCompleteAfterIt(t *testing.T) {
	root := t.TempDir() + "/state"
	journal, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	sender := fusedAgent(1)
	now := time.Unix(1_900_000_000, 0)
	frames, digest := splitObject(t, 1, 2500, 1024)
	if len(frames) != 3 {
		t.Fatalf("%d parts", len(frames))
	}
	parts, _ := openParts(t, journal, allowSenders(sender), now)
	for _, frame := range frames[:2] {
		if result, err := parts.Add(sender, frame, now); err != nil || result.Status != relayframe.PartStored {
			t.Fatalf("add: %+v %v", result, err)
		}
	}
	// A re-delivered part is a duplicate and stays stored once.
	if result, err := parts.Add(sender, frames[1], now); err != nil || result.Status != relayframe.PartDuplicate {
		t.Fatalf("duplicate: %+v %v", result, err)
	}
	if count := storedPartCount(t, journal); count != 2 {
		t.Fatalf("%d stored parts", count)
	}
	journal = reopen(t, journal, root)
	defer journal.Close()
	parts, report := openParts(t, journal, allowSenders(sender), now.Add(time.Hour))
	if report.Replayed != 2 || len(report.Completed) != 0 {
		t.Fatalf("replay: %+v", report)
	}
	result, err := parts.Add(sender, frames[2], now.Add(time.Hour))
	if err != nil || result.Status != relayframe.PartComplete || relayframe.ObjectDigest(result.Object) != digest {
		t.Fatalf("complete: %+v %v", result.Status, err)
	}
	// Until settled, the parts stay, and a sweep leaves them.
	if _, err := parts.Sweep(now.Add(2 * time.Hour)); err != nil || storedPartCount(t, journal) != 3 {
		t.Fatalf("an unsettled object lost its parts: %v", err)
	}
	if err := parts.Settle(sender, digest); err != nil || storedPartCount(t, journal) != 0 {
		t.Fatalf("settle: %v", err)
	}
}

// A crash between the last part and the caller's settlement completes the
// object again on replay.
func TestRoomPartsCompleteAgainAfterACrashBeforeSettlement(t *testing.T) {
	root := t.TempDir() + "/state"
	journal, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	sender := fusedAgent(1)
	now := time.Unix(1_900_000_000, 0)
	frames, digest := splitObject(t, 2, 2500, 1024)
	parts, _ := openParts(t, journal, allowSenders(sender), now)
	for _, frame := range frames {
		if _, err := parts.Add(sender, frame, now); err != nil {
			t.Fatal(err)
		}
	}
	journal = reopen(t, journal, root)
	defer journal.Close()
	parts, report := openParts(t, journal, allowSenders(sender), now)
	if len(report.Completed) != 1 || report.Completed[0].Digest != digest || report.Completed[0].Sender != sender {
		t.Fatalf("replay: %+v", report)
	}
	if err := parts.Settle(sender, digest); err != nil || storedPartCount(t, journal) != 0 {
		t.Fatalf("settle: %v", err)
	}
}

// On replay, parts of an expired object, of a sender no longer admitted, and
// damaged records are deleted.
func TestRoomPartReplayDeletesWhatItCannotHold(t *testing.T) {
	root := t.TempDir() + "/state"
	journal, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	alice, bob := fusedAgent(1), fusedAgent(2)
	now := time.Unix(1_900_000_000, 0)
	parts, _ := openParts(t, journal, allowSenders(alice, bob), now)
	first, _ := splitObject(t, 3, 2500, 1024)
	second, _ := splitObject(t, 4, 2500, 1024)
	if _, err := parts.Add(alice, first[0], now); err != nil {
		t.Fatal(err)
	}
	if _, err := parts.Add(bob, second[0], now.Add(20*time.Hour)); err != nil {
		t.Fatal(err)
	}
	damaged := filepath.Join(journal.root, roomPartDir, roomPartName(roomPartKey{sender: alice, digest: [sha256.Size]byte{9}}, 1))
	if err := os.WriteFile(damaged, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	journal = reopen(t, journal, root)
	defer journal.Close()
	// Alice's object is past 24 h 5 min; Bob is no longer admitted.
	_, report := openParts(t, journal, allowSenders(alice), now.Add(24*time.Hour+5*time.Minute))
	if report.Expired != 1 || report.Refused != 1 || report.Damaged != 1 || report.Replayed != 0 {
		t.Fatalf("replay: %+v", report)
	}
	if count := storedPartCount(t, journal); count != 0 {
		t.Fatalf("%d parts remain", count)
	}
}

// A part that contradicts a held object drops it, on disk too; so does a
// sweep past the lifetime and a removed sender.
func TestRoomPartStoreFollowsEveryDrop(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	sender := fusedAgent(1)
	now := time.Unix(1_900_000_000, 0)
	parts, _ := openParts(t, journal, allowSenders(sender), now)
	frames, _ := splitObject(t, 5, 2500, 1024)
	if _, err := parts.Add(sender, frames[0], now); err != nil {
		t.Fatal(err)
	}
	contradicting := frames[1]
	contradicting.PartCount = 4
	if _, err := parts.Add(sender, contradicting, now); !errors.Is(err, relayframe.ErrReassemblyInconsistent) {
		t.Fatalf("contradicting part: %v", err)
	}
	if count := storedPartCount(t, journal); count != 0 {
		t.Fatalf("a dropped object kept %d parts", count)
	}
	if _, err := parts.Add(sender, frames[0], now); err != nil {
		t.Fatal(err)
	}
	if deleted, err := parts.Sweep(now.Add(24*time.Hour + 5*time.Minute)); err != nil || deleted != 1 || storedPartCount(t, journal) != 0 {
		t.Fatalf("sweep: %d %v", deleted, err)
	}
	if _, err := parts.Add(sender, frames[1], now); err != nil {
		t.Fatal(err)
	}
	if deleted, err := parts.DropSender(sender); err != nil || deleted != 1 || storedPartCount(t, journal) != 0 {
		t.Fatalf("drop sender: %d %v", deleted, err)
	}
}

// The store never holds more than the Reassembler's bounds: a sender's fifth
// incomplete object is refused and nothing of it is written.
func TestRoomPartStoreHoldsNoMoreThanTheReassemblerBounds(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	sender := fusedAgent(1)
	now := time.Unix(1_900_000_000, 0)
	parts, _ := openParts(t, journal, allowSenders(sender), now)
	for seed := byte(10); seed < 14; seed++ {
		frames, _ := splitObject(t, seed, 2500, 1024)
		if _, err := parts.Add(sender, frames[0], now); err != nil {
			t.Fatal(err)
		}
	}
	frames, _ := splitObject(t, 14, 2500, 1024)
	if _, err := parts.Add(sender, frames[0], now); !errors.Is(err, relayframe.ErrReassemblyPeerObjects) {
		t.Fatalf("fifth object: %v", err)
	}
	if count := storedPartCount(t, journal); count != 4 {
		t.Fatalf("%d stored parts", count)
	}
	// A stranger's part is refused and never written.
	if _, err := parts.Add(fusedAgent(9), frames[0], now); !errors.Is(err, relayframe.ErrReassemblyNotAdmitted) {
		t.Fatalf("stranger: %v", err)
	}
	if count := storedPartCount(t, journal); count != 4 {
		t.Fatalf("%d stored parts after a stranger", count)
	}
}

// Newer part-0 evidence replaces the stored evidence, and replay keeps it.
func TestRoomPartNewerEvidenceIsStored(t *testing.T) {
	root := t.TempDir() + "/state"
	journal, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	sender := fusedAgent(1)
	now := time.Unix(1_900_000_000, 0)
	parts, _ := openParts(t, journal, allowSenders(sender), now)
	frames, digest := splitObject(t, 6, 2500, 1024)
	if _, err := parts.Add(sender, frames[0], now); err != nil {
		t.Fatal(err)
	}
	if err := parts.ReplaceFirstPartEvidence(sender, digest, []byte("new card"), []byte("newer evidence")); err != nil {
		t.Fatal(err)
	}
	journal = reopen(t, journal, root)
	defer journal.Close()
	parts, _ = openParts(t, journal, allowSenders(sender), now)
	for _, frame := range frames[1:] {
		result, err := parts.Add(sender, frame, now)
		if err != nil {
			t.Fatal(err)
		}
		if result.Status == relayframe.PartComplete && (string(result.Evidence) != "newer evidence" || string(result.Card) != "new card") {
			t.Fatalf("replayed evidence: %q %q", result.Evidence, result.Card)
		}
	}
}

// A part is stored before the Reassembler sees it: a write failure on the
// completing part leaves the object incomplete in memory and on disk, so the
// retried part completes it.
func TestRoomPartStoreFailureOnTheLastPartLosesNothing(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	sender := fusedAgent(1)
	now := time.Unix(1_900_000_000, 0)
	parts, _ := openParts(t, journal, allowSenders(sender), now)
	frames, digest := splitObject(t, 7, 2500, 1024)
	for _, frame := range frames[:len(frames)-1] {
		if _, err := parts.Add(sender, frame, now); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(journal.root, roomPartDir)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	_, err = parts.Add(sender, frames[len(frames)-1], now)
	if restore := os.Chmod(dir, 0o700); restore != nil {
		t.Fatal(restore)
	}
	if !errors.Is(err, ErrRoomPartStore) {
		t.Fatalf("a failed write was not reported: %v", err)
	}
	if !parts.reassembler.Holds(sender, digest) || storedPartCount(t, journal) != len(frames)-1 {
		t.Fatal("a failed write changed what is held")
	}
	result, err := parts.Add(sender, frames[len(frames)-1], now)
	if err != nil || result.Status != relayframe.PartComplete {
		t.Fatalf("retry: %+v %v", result.Status, err)
	}
}

// A complete object the caller never settles is forgotten, with its parts,
// once the lifetime has passed since it completed.
func TestRoomPartUnsettledObjectsAreBounded(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	sender := fusedAgent(1)
	now := time.Unix(1_900_000_000, 0)
	parts, _ := openParts(t, journal, allowSenders(sender), now)
	frames, _ := splitObject(t, 8, 2500, 1024)
	for _, frame := range frames {
		if _, err := parts.Add(sender, frame, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := parts.Sweep(now.Add(24*time.Hour + 4*time.Minute)); err != nil || storedPartCount(t, journal) != len(frames) {
		t.Fatalf("an unsettled object was dropped early: %v", err)
	}
	if _, err := parts.Sweep(now.Add(24*time.Hour + 5*time.Minute)); err != nil || storedPartCount(t, journal) != 0 || len(parts.unsettled) != 0 {
		t.Fatalf("an unsettled object outlived the lifetime: %v", err)
	}
}

// A part redelivered after its object's lifetime, before any sweep, starts
// the object afresh with that arrival time: a restart replays it instead of
// dropping it as expired.
func TestRoomPartRedeliveredAfterExpirySurvivesARestart(t *testing.T) {
	root := t.TempDir() + "/state"
	journal, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	sender := fusedAgent(1)
	start := time.Unix(1_900_000_000, 0)
	parts, _ := openParts(t, journal, allowSenders(sender), start)
	frames, digest := splitObject(t, 9, 2500, 1024)
	if _, err := parts.Add(sender, frames[0], start); err != nil {
		t.Fatal(err)
	}
	later := start.Add(24*time.Hour + 6*time.Minute)
	if result, err := parts.Add(sender, frames[0], later); err != nil || result.Status != relayframe.PartStored {
		t.Fatalf("redelivery after expiry: %+v %v", result.Status, err)
	}
	journal = reopen(t, journal, root)
	defer journal.Close()
	parts, report := openParts(t, journal, allowSenders(sender), later.Add(time.Hour))
	if report.Replayed != 1 || report.Expired != 0 || !parts.reassembler.Holds(sender, digest) {
		t.Fatalf("the redelivered part was lost by a restart: %+v", report)
	}
}

// A contradicting part the Reassembler refuses while it still holds the
// object (here: its sender is no longer admitted) never replaces the stored
// copy of the held part, so a restart still has it.
func TestRoomPartRefusedContradictionKeepsTheHeldCopy(t *testing.T) {
	root := t.TempDir() + "/state"
	journal, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	sender := fusedAgent(1)
	now := time.Unix(1_900_000_000, 0)
	senders := allowSenders(sender)
	parts, _ := openParts(t, journal, senders, now)
	frames, digest := splitObject(t, 10, 2500, 1024)
	for _, frame := range frames[:2] {
		if _, err := parts.Add(sender, frame, now); err != nil {
			t.Fatal(err)
		}
	}
	other := frames[1]
	other.Part = bytes.Repeat([]byte{0x77}, len(frames[1].Part))
	delete(senders.allowed, sender)
	if _, err := parts.Add(sender, other, now); !errors.Is(err, relayframe.ErrReassemblyNotAdmitted) {
		t.Fatalf("refused part: %v", err)
	}
	if !parts.reassembler.Holds(sender, digest) || storedPartCount(t, journal) != 2 {
		t.Fatal("the refused part changed what is held or stored")
	}
	senders.allowed[sender] = true
	journal = reopen(t, journal, root)
	defer journal.Close()
	parts, report := openParts(t, journal, senders, now)
	if report.Replayed != 2 {
		t.Fatalf("replay after a refused contradiction: %+v", report)
	}
	if result, err := parts.Add(sender, frames[2], now); err != nil || result.Status != relayframe.PartComplete ||
		!bytes.Equal(result.Object[len(frames[0].Part):len(frames[0].Part)+len(frames[1].Part)], frames[1].Part) {
		t.Fatalf("completion with the held copy: %+v %v", result.Status, err)
	}
}
