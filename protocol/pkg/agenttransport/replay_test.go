package agenttransport

import (
	"errors"
	"testing"
)

func proofAt(issued uint64, nonce byte) Proof { return Proof{IssuedAt: issued, Nonce: [32]byte{nonce}} }

func freshTable(t *testing.T, c ReplayConfig, now uint64) *ReplayTable {
	t.Helper()
	table, err := NewReplayTable(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = table.MarkRecorded(table.NextMark(now)); err != nil {
		t.Fatal(err)
	}
	return table
}

func TestReplayClaimOnce(t *testing.T) {
	table := freshTable(t, ReplayConfig{}, testNow)
	id := [32]byte{1}
	if err := table.Claim(id, proofAt(testNow, 1), testNow); err != nil {
		t.Fatal(err)
	}
	wantClass(t, table.Claim(id, proofAt(testNow, 1), testNow), ErrCredentialInvalid)
	if err := table.Claim([32]byte{2}, proofAt(testNow, 1), testNow); err != nil {
		t.Fatalf("the same nonce under another credential: %v", err)
	}
	wantClass(t, table.Claim(id, proofAt(testNow+ProofWindowSeconds+1, 2), testNow), ErrCredentialInvalid)
	wantClass(t, table.Claim(id, proofAt(testNow-ProofWindowSeconds-1, 3), testNow), ErrCredentialInvalid)
}

func TestReplayTableFailsClosedWhenFull(t *testing.T) {
	table := freshTable(t, ReplayConfig{Entries: 3}, testNow)
	for i := range 3 {
		if err := table.Claim([32]byte{byte(i)}, proofAt(testNow, 1), testNow); err != nil {
			t.Fatal(err)
		}
	}
	if err := table.Claim([32]byte{9}, proofAt(testNow, 1), testNow); !errors.Is(err, ErrReplayTableFull) {
		t.Fatalf("want replay_table_full, got %v", err)
	}
	// No live entry was evicted: every claimed pair is still refused.
	for i := range 3 {
		wantClass(t, table.Claim([32]byte{byte(i)}, proofAt(testNow, 1), testNow+ProofWindowSeconds), ErrCredentialInvalid)
	}
	// Once the entries leave the window they are dropped and space returns.
	if err := table.Claim([32]byte{9}, proofAt(testNow+ProofWindowSeconds+1, 1), testNow+ProofWindowSeconds+1); err != nil {
		t.Fatal(err)
	}
}

func TestReplayPerCredentialBound(t *testing.T) {
	table := freshTable(t, ReplayConfig{}, testNow)
	id := [32]byte{1}
	for i := range MaxReplayPerCredential {
		if err := table.Claim(id, proofAt(testNow, byte(i)), testNow); err != nil {
			t.Fatal(err)
		}
	}
	if err := table.Claim(id, proofAt(testNow, 200), testNow); !errors.Is(err, ErrReplayCredentialFull) {
		t.Fatalf("want the per-credential refusal, got %v", err)
	}
	if err := table.Claim([32]byte{2}, proofAt(testNow, 200), testNow); err != nil {
		t.Fatalf("another credential: %v", err)
	}
	if _, err := NewReplayTable(ReplayConfig{PerCredential: MaxReplayPerCredential + 1}); err == nil {
		t.Fatal("per-credential bound above 64 accepted")
	}
}

func TestReplayNeverEvictsInWindow(t *testing.T) {
	table := freshTable(t, ReplayConfig{}, testNow)
	id := [32]byte{1}
	if err := table.Claim(id, proofAt(testNow, 1), testNow); err != nil {
		t.Fatal(err)
	}
	// Exactly at the window edge the entry is still live.
	wantClass(t, table.Claim(id, proofAt(testNow, 1), testNow+ProofWindowSeconds), ErrCredentialInvalid)
	if _, _, n := table.State(); n != 1 {
		t.Fatalf("entry dropped inside the window: %d entries", n)
	}
	if err := table.Claim([32]byte{2}, proofAt(testNow+ProofWindowSeconds+1, 1), testNow+ProofWindowSeconds+1); err != nil {
		t.Fatal(err)
	}
	if floor, _, n := table.State(); n != 1 || floor != testNow {
		t.Fatalf("drop did not raise the floor: floor %d, %d entries", floor, n)
	}
}

func TestReplayFloorAfterClockRollback(t *testing.T) {
	table := freshTable(t, ReplayConfig{}, testNow)
	id := [32]byte{1}
	if err := table.Claim(id, proofAt(testNow, 1), testNow); err != nil {
		t.Fatal(err)
	}
	later := uint64(testNow + ProofWindowSeconds + 1)
	if err := table.Claim(id, proofAt(later, 2), later); err != nil {
		t.Fatal(err)
	}
	// The clock steps back: the dropped proof is inside the window again but
	// at the floor.
	if err := table.Claim(id, proofAt(testNow, 1), testNow); !errors.Is(err, ErrProofFloor) {
		t.Fatalf("want proof_floor, got %v", err)
	}
	if err := table.Claim(id, proofAt(testNow+1, 3), testNow); err != nil {
		t.Fatalf("just above the floor: %v", err)
	}
}

func TestHighWaterMark(t *testing.T) {
	table, err := NewReplayTable(ReplayConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err = table.Claim([32]byte{1}, proofAt(testNow, 1), testNow); !errors.Is(err, ErrProofMark) {
		t.Fatalf("a table with no recorded mark admitted a proof: %v", err)
	}
	mark := table.NextMark(testNow)
	if mark != testNow+MarkLeadSeconds {
		t.Fatalf("mark %d", mark)
	}
	if err = table.MarkRecorded(mark); err != nil {
		t.Fatal(err)
	}
	// The clock steps back: the next mark never decreases.
	if table.NextMark(testNow-1000) != mark {
		t.Fatal("mark decreased with the clock")
	}
	if err = table.MarkRecorded(mark - 1); err == nil {
		t.Fatal("a decreasing mark was recorded")
	}
	// Bound: below the mark admitted, at the mark refused (recording stalled).
	stalled := mark - MarkLeadSeconds + ProofWindowSeconds + 10
	if err = table.Claim([32]byte{2}, proofAt(mark-1, 1), stalled); err != nil {
		t.Fatalf("just below the mark: %v", err)
	}
	if err = table.Claim([32]byte{2}, proofAt(mark, 2), stalled); !errors.Is(err, ErrProofMark) {
		t.Fatalf("at the mark: %v", err)
	}
	if table.NextMark(^uint64(0)-1) != ^uint64(0) {
		t.Fatal("mark overflowed")
	}
}

// TestRestartRefusesAdmittedProofs is the combined control of section 5.4: a
// proof admitted at clock 1000 with time 1100 stays refused after a rollback
// to 900 and a restart, because the recorded mark stayed at 1140 or above.
func TestRestartRefusesAdmittedProofs(t *testing.T) {
	table := freshTable(t, ReplayConfig{}, 1000)
	id := [32]byte{1}
	if err := table.Claim(id, proofAt(1100, 1), 1000); err != nil {
		t.Fatal(err)
	}
	if err := table.MarkRecorded(table.NextMark(1000)); err != nil {
		t.Fatal(err)
	}
	if err := table.MarkRecorded(table.NextMark(900)); err != nil {
		t.Fatal(err)
	}
	_, recorded, _ := table.State()
	if recorded < 1140 {
		t.Fatalf("recorded mark %d", recorded)
	}
	restarted, err := RestoreReplayTable(ReplayConfig{}, recorded)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.MarkRecorded(restarted.NextMark(1000)); err != nil {
		t.Fatal(err)
	}
	if err = restarted.Claim(id, proofAt(1100, 1), 1000); !errors.Is(err, ErrProofFloor) {
		t.Fatalf("an admitted proof passed after restart: %v", err)
	}
	if wait := restarted.RetryAfter(1000); wait != recorded-1000+1 {
		t.Fatalf("Retry-After %d", wait)
	}
	// Aligned clocks: a fresh proof passes within MarkLeadSeconds of restart.
	fresh := uint64(1000 + MarkLeadSeconds + 1)
	if err = restarted.MarkRecorded(restarted.NextMark(fresh)); err != nil {
		t.Fatal(err)
	}
	if err = restarted.Claim(id, proofAt(fresh, 2), fresh); err != nil {
		t.Fatalf("fresh proof after the restart delay: %v", err)
	}
	if _, err = RestoreReplayTable(ReplayConfig{}, 0); err == nil {
		t.Fatal("a used table restored without its mark")
	}
}
