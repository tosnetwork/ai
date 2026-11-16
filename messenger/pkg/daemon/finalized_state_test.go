package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
)

// writeCheckpoint stands for what the finalized read leaves in state_dir
// when it ran first.
func writeCheckpoint(t *testing.T, config Config) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(config.ChainCheckpointPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(config.ChainCheckpointPath); os.IsNotExist(err) {
		if err := os.WriteFile(config.ChainCheckpointPath, []byte("100\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// The stock command verifies the finalized delegation before it opens the
// daemon. On a fresh state directory the journal must still open after that
// read wrote its checkpoint there.
func TestAFreshStateDirStillOpensAfterTheFinalizedRead(t *testing.T) {
	config := testConfig(t)
	if _, err := os.Stat(config.StateDir); !os.IsNotExist(err) {
		t.Fatalf("the test needs a fresh state directory: %v", err)
	}
	// No chain answers here; the read fails after the preparation.
	_, _ = VerifyFinalizedDelegation(config, time.Now())
	writeCheckpoint(t, config)
	journal, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatalf("the journal refused the state directory after the finalized read: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
}

// Another tool verifies beside a live daemon: the preparation takes no lock.
func TestTheFinalizedReadRunsBesideADaemonThatOwnsTheJournal(t *testing.T) {
	config := testConfig(t)
	journal, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = journal.Close() }()
	if err := prepareStateDir(config.StateDir); err != nil {
		t.Fatalf("preparing a state directory a live journal owns: %v", err)
	}
	if _, err := VerifyFinalizedDelegation(config, time.Now()); err != nil &&
		strings.HasPrefix(err.Error(), "prepare state directory") {
		t.Fatalf("the finalized read failed at the preparation beside a live journal: %v", err)
	}
}

// A root that is already wedged (only the checkpoint, no marker) is still
// refused: the preparation never adopts a non-empty root.
func TestANonEmptyStateDirWithoutTheMarkerIsStillRefused(t *testing.T) {
	config := testConfig(t)
	writeCheckpoint(t, config)
	if err := prepareStateDir(config.StateDir); err == nil {
		t.Fatal("the preparation adopted a non-empty root without the marker")
	}
	if journal, err := eventlog.Open(config.StateDir); err == nil {
		_ = journal.Close()
		t.Fatal("the journal adopted a non-empty root without the marker")
	}
}
