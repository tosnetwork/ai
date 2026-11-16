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
