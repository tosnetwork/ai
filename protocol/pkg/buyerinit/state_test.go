package buyerinit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/internal/osguard"
)

// isolated runs f on its own goroutine, so a panic is the test's failure
// and not the whole binary's.
func isolated(t *testing.T, f func()) {
	t.Helper()
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		f()
	}()
	if recovered := <-done; recovered != nil {
		t.Errorf("panicked: %v", recovered)
	}
}

func TestApplyWithoutAConfirmerSendsNothing(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	isolated(t, func() {
		env := w.env(false)
		env.Confirm = nil
		if _, err := Apply(context.Background(), in, env); !errors.Is(err, ErrConfirmationRequired) || w.activations != 0 {
			t.Errorf("without a confirmer: %v", err)
		}
	})
}

func TestInitCreatesNothingItCouldNotRead(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	w.readErr = errors.New("tosctl wallet ls: tosctl failed")
	if _, err := Apply(context.Background(), in, w.env(true)); err == nil || len(w.created) != 0 {
		t.Fatalf("an unreadable wallet: %v, created %v", err, w.created)
	}
	w.readErr = nil
	w.controllerReadErr = errors.New("tosctl agent native-registry controller: tosctl failed")
	if _, err := Apply(context.Background(), in, w.env(true)); err == nil || len(w.created) != 1 {
		t.Fatalf("an unreadable controller: %v, created %v", err, w.created)
	}
}

func TestPlanDoesNotCreateAController(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	if err := w.CreateWallet(context.Background(), "buyer"); err != nil {
		t.Fatal(err)
	}
	w.created = nil
	report, err := Plan(context.Background(), in, w.env(true))
	if err != nil || statuses(report)["controller.create"] != StatusPlanned || len(w.created) != 0 {
		t.Fatalf("plan: %v, created %v, %+v", err, w.created, report.Steps)
	}
}

func TestApplyKeepsTheAgentNonceAcrossAFailedBuild(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	w.registerErr = errors.New("tosctl agent native-registry register-agent: tosctl failed")
	if _, err := Apply(context.Background(), in, w.env(true)); err == nil {
		t.Fatal("a failed build was not reported")
	}
	w.registerErr = nil
	if _, err := Apply(context.Background(), in, w.env(true)); err != nil {
		t.Fatal(err)
	}
	if len(w.nonces) != 2 || w.nonces[0] != w.nonces[1] || w.drawn != 1 {
		t.Fatalf("the re-run built with another nonce: %v, %d drawn", w.nonces, w.drawn)
	}
}

func TestInitRefusesAMissingCustodyOrChain(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	isolated(t, func() {
		for name, mutate := range map[string]func(*Env){
			"no custody": func(e *Env) { e.Custody = nil },
			"no chain":   func(e *Env) { e.Chain = nil },
		} {
			env := w.env(true)
			mutate(&env)
			if _, err := Apply(context.Background(), in, env); err == nil {
				t.Errorf("%s was run", name)
			}
		}
		var none context.Context
		if _, err := Plan(none, in, w.env(true)); err == nil {
			t.Error("a nil context was run")
		}
	})
}

func TestInitRefusesAStateDirectoryThatIsAFile(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	if err := os.WriteFile(in.StateDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), in, w.env(true)); err == nil || len(w.created) != 0 {
		t.Fatalf("a state directory that is a file: %v", err)
	}
	if _, err := Plan(context.Background(), in, w.env(true)); err == nil {
		t.Fatal("a plan accepted a state directory that is a file")
	}
}

func TestApplyRefusesAWalletThatListsAnotherAddressOnline(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	w.onlineAddress = "0:" + strings.Repeat("98", 32)
	if _, err := Apply(context.Background(), in, w.env(true)); err == nil || w.sends != 0 {
		t.Fatalf("a wallet name that resolves to two addresses: %v, %d sends", err, w.sends)
	}
}

func TestApplyRefusesASecondConcurrentInit(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	if err := os.MkdirAll(filepath.Join(in.StateDir, initDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	release, acquired, err := osguard.TryExclusiveFileLock(filepath.Join(in.StateDir, initDirectory, lockFile), 0o600)
	if err != nil || !acquired {
		t.Fatalf("lock: %v %v", acquired, err)
	}
	defer release()
	if _, err := Apply(context.Background(), in, w.env(true)); err == nil || len(w.created) != 0 {
		t.Fatalf("a second init on a locked state directory: %v", err)
	}
}

func TestInitRefusesJournalsAndConfigurationsItCannotTrust(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	if _, err := Apply(context.Background(), in, w.env(true)); err != nil {
		t.Fatal(err)
	}
	path := journalPath(in.StateDir)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	restore := func() {
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, corrupt := range map[string]func(){
		"a journal others can read": func() {
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"another journal schema": func() {
			if err := os.WriteFile(path, []byte(strings.Replace(string(original), JournalSchema, "other.v1", 1)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"an invalid journaled registration": func() {
			if err := os.WriteFile(path, []byte(strings.Replace(string(original), `"destination": "0:`,
				`"destination": "1:`, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"an unknown journal field": func() {
			if err := os.WriteFile(path, []byte(strings.Replace(string(original), `"schema"`, `"x": 1, "schema"`, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		corrupt()
		if _, err := Plan(context.Background(), in, w.env(true)); err == nil {
			t.Errorf("%s was used", name)
		}
		restore()
	}
	if _, err := Plan(context.Background(), in, w.env(true)); err != nil {
		t.Fatalf("the restored journal: %v", err)
	}
	// An existing configuration over its bound is never read.
	other := newWorld(t)
	otherIn := other.input(t)
	if err := os.WriteFile(otherIn.ConfigPath, []byte(strings.Repeat(" ", MaxAgentConfigBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), otherIn, other.env(true)); err == nil || other.sends != 0 {
		t.Fatalf("an oversized existing configuration: %v", err)
	}
	// One others can read is not this account's configuration.
	if err := os.WriteFile(otherIn.ConfigPath, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(otherIn.ConfigPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), otherIn, other.env(true)); err == nil || other.sends != 0 {
		t.Fatalf("a world-readable existing configuration: %v", err)
	}
}
