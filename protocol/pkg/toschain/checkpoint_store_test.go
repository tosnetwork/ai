package toschain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointStoreSurvivesRestartAndRejectsRegression(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "checkpoint")
	first, err := newCheckpointStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.checkAndAdvance(42); err != nil {
		t.Fatal(err)
	}
	second, err := newCheckpointStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.checkAndAdvance(41); err == nil {
		t.Fatal("checkpoint regression accepted after restart")
	}
	if err := second.checkAndAdvance(43); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := second.checkAndAdvance(44); err == nil {
		t.Fatal("corrupt checkpoint accepted")
	}
}

// check refuses a lower value and records nothing; raise ignores a lower
// value and records a higher one; neither accepts zero or a corrupt file.
func TestCheckpointStoreCheckAndRaise(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "checkpoint")
	store, err := newCheckpointStore(path)
	if err != nil {
		t.Fatal(err)
	}
	read := func() string {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	if err := store.checkAndAdvance(50); err != nil {
		t.Fatal(err)
	}
	if err := store.check(49); err == nil {
		t.Fatal("check accepted a value below the record")
	}
	if err := store.check(60); err != nil || read() != "50\n" {
		t.Fatalf("check of a higher value: %v, record %q", err, read())
	}
	if err := store.raise(45); err != nil || read() != "50\n" {
		t.Fatalf("raise of a lower value: %v, record %q", err, read())
	}
	if err := store.raise(55); err != nil || read() != "55\n" {
		t.Fatalf("raise of a higher value: %v, record %q", err, read())
	}
	if store.check(0) == nil || store.raise(0) == nil {
		t.Fatal("zero accepted")
	}
	if err := os.WriteFile(path, []byte("corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if store.check(60) == nil || store.raise(60) == nil {
		t.Fatal("a corrupt record accepted")
	}
}
