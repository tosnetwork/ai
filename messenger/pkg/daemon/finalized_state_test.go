package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
)

// The finalized read writes the rollback checkpoint into state_dir before
// the daemon opens its journal there. On a fresh directory the journal must
// still open afterwards, or a daemon started with operator resources could
// never start.
func TestAFreshStateDirStillOpensAfterTheCheckpointIsWrittenFirst(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := prepareStateDir(root); err != nil {
		t.Fatalf("prepare a fresh state directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "chain.checkpoint"), []byte("100\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	journal, err := eventlog.Open(root)
	if err != nil {
		t.Fatalf("the journal refused the prepared state directory: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := prepareStateDir(root); err != nil {
		t.Fatalf("preparing an initialized state directory again: %v", err)
	}
}

// Without the preparation the same order fails, which is what the startup
// path did before.
func TestAnUnpreparedStateDirWithOnlyTheCheckpointIsRefused(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "chain.checkpoint"), []byte("100\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if journal, err := eventlog.Open(root); err == nil {
		_ = journal.Close()
		t.Fatal("the journal adopted a root it did not mark")
	}
}
