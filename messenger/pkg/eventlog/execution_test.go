package eventlog

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestToolExecutionKeyIsBoundOnce(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)
	key := "idem_" + strings.Repeat("a", 64)
	first := "act_" + strings.Repeat("1", 64)
	second := "act_" + strings.Repeat("2", 64)

	bound, fresh, err := journal.ClaimToolExecution(key, first, now)
	if err != nil || !fresh || bound != first {
		t.Fatalf("first claim: bound=%q fresh=%v err=%v", bound, fresh, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	journal, err = Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer journal.Close()
	bound, fresh, err = journal.ClaimToolExecution(key, second, now)
	if err != nil || fresh || bound != first {
		t.Fatalf("re-described tool call took the key: bound=%q fresh=%v err=%v", bound, fresh, err)
	}
	claim, found, err := journal.LookupToolExecution(key)
	if err != nil || !found || claim.ActionID != first {
		t.Fatalf("lookup: claim=%+v found=%v err=%v", claim, found, err)
	}
}
