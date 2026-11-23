package servicebridge

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const serveLockHelperDir = "SERVICEBRIDGE_SERVE_LOCK_HELPER_DIR"

// TestHelperProcessHoldsTheServeLock is not a test: run by the tests below
// as a separate process, it takes the serve lock of the named directory,
// says so, and holds it until killed.
func TestHelperProcessHoldsTheServeLock(t *testing.T) {
	state := os.Getenv(serveLockHelperDir)
	if state == "" {
		t.Skip("helper process only")
	}
	release, err := lockServe(state)
	if err != nil {
		os.Exit(3)
	}
	defer release()
	if err := os.WriteFile(filepath.Join(filepath.Dir(state), "held"), nil, 0o600); err != nil {
		os.Exit(4)
	}
	time.Sleep(time.Hour)
}

func holdServeLockElsewhere(t *testing.T, state string) *exec.Cmd {
	t.Helper()
	helper := exec.Command(os.Args[0], "-test.run=^TestHelperProcessHoldsTheServeLock$")
	helper.Env = append(os.Environ(), serveLockHelperDir+"="+state)
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = helper.Process.Kill()
		_ = helper.Wait()
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(filepath.Dir(state), "held")); err == nil {
			return helper
		}
		if time.Now().After(deadline) {
			t.Fatal("the helper never took the lock")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestOneStateDirectoryIsServedByOneProcessAtATime(t *testing.T) {
	state := privateStateDir(t)
	release, err := lockServe(state)
	if err != nil {
		t.Fatal(err)
	}
	// A second serve in this process is refused...
	if _, err := lockServe(state); !errors.Is(err, ErrNodeServing) {
		t.Fatalf("a second serve lock in one process: %v", err)
	}
	// ...and so is a node opened over it, before anything of it is opened.
	config := NodeConfig{StateDir: state, Provider: &ProviderNode{}}
	if _, err := OpenNode(context.Background(), config, NodeOptions{}); !errors.Is(err, ErrNodeServing) {
		t.Fatalf("a node opened over a served state directory: %v", err)
	}
	release()
	again, err := lockServe(state)
	if err != nil {
		t.Fatalf("the lock was not released: %v", err)
	}
	again()
	info, err := os.Lstat(filepath.Join(state, ServeLockFile))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("the lock file: %v %v", info, err)
	}
}

func TestAnotherProcessServingTheNodeKeepsItFromBeingServedUntilItDies(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	if err := ensurePrivateDirectory(state); err != nil {
		t.Fatal(err)
	}
	helper := holdServeLockElsewhere(t, state)
	if _, err := lockServe(state); !errors.Is(err, ErrNodeServing) {
		t.Fatalf("served beside another process: %v", err)
	}
	// A killed server leaves no lock behind.
	if err := helper.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = helper.Wait()
	release, err := lockServe(state)
	if err != nil {
		t.Fatalf("a killed server's lock outlived it: %v", err)
	}
	release()
}

func TestANodeThatFailsToOpenReleasesTheServeLock(t *testing.T) {
	state := privateStateDir(t)
	// The reader cannot open from an empty configuration: the open fails
	// after the lock was taken.
	if _, err := OpenNode(context.Background(), NodeConfig{StateDir: state, Provider: &ProviderNode{}},
		NodeOptions{}); err == nil || errors.Is(err, ErrNodeServing) {
		t.Fatalf("the open: %v", err)
	}
	release, err := lockServe(state)
	if err != nil {
		t.Fatalf("a failed open kept the lock: %v", err)
	}
	release()
}

func TestTheServeLockIsNotTheSetupLock(t *testing.T) {
	state := privateStateDir(t)
	release, err := lockServe(state)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// init, offer and withdraw run beside a serving node.
	setup, err := lockSetup(state)
	if err != nil {
		t.Fatalf("the setup lock beside a serving node: %v", err)
	}
	setup()
}
