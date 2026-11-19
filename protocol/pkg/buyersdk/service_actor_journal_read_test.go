package buyersdk

import (
	"os"
	"strings"
	"testing"
)

// Reading one record without opening the journal recovers nothing: a
// record a running agent holds in the sending phase is read as it is and
// its file is left untouched. A journal directory open to others is
// refused.
func TestReadingACallRecordRecoversNothing(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenServiceActorJournal(dir, saNow)
	if err != nil {
		t.Fatal(err)
	}
	record := CallRecord{Schema: callRecordSchema, RequestHash: strings.Repeat("ab", 32), QueryID: 7, PaymentNanoTOS: "500000000",
		Phase: PhasePrepared, ExpiresAtUnix: uint64(saNow.Unix()) + 600}
	if err := journal.Create(record, defaultLimits(), saNow); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.BeginSend(record.RequestHash, defaultLimits(), saNow); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(journal.path(record.RequestHash))
	if err != nil {
		t.Fatal(err)
	}
	read, err := ReadServiceActorCallRecord(dir, record.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(journal.path(record.RequestHash))
	if err != nil {
		t.Fatal(err)
	}
	if read.Phase != PhaseSending || string(before) != string(after) {
		t.Fatalf("the read changed the record: phase %s", read.Phase)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadServiceActorCallRecord(dir, record.RequestHash); err == nil {
		t.Fatal("a journal directory open to the group was read")
	}
	if _, err := ReadServiceActorCallRecord("journal", record.RequestHash); err == nil {
		t.Fatal("a relative journal directory was read")
	}
}
