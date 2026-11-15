package agentpacketrelay

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type depositResult struct {
	outcome DepositOutcome
	err     error
}

func depositAsync(client *Client, envelope []byte) chan depositResult {
	done := make(chan depositResult, 1)
	go func() {
		outcome, err := client.Deposit(context.Background(), envelope)
		done <- depositResult{outcome, err}
	}()
	return done
}

func gatedRelay(t *testing.T, opts ...relayOption) (*testRelay, *memoryBackend, chan struct{}) {
	t.Helper()
	backend := newMemoryBackend()
	gate := make(chan struct{})
	backend.putGate = gate
	store, err := newStore(testLimits(), backend)
	if err != nil {
		t.Fatal(err)
	}
	relay := newTestRelayWithStore(t, store, newClock(), opts...)
	// Runs before the HTTP server closes, so a failing test never leaves a
	// write parked on the gate.
	t.Cleanup(func() { openGate(backend, gate) })
	return relay, backend, gate
}

// openGate lets every later write through and releases the parked ones.
func openGate(backend *memoryBackend, gate chan struct{}) {
	backend.mu.Lock()
	backend.putGate = nil
	backend.mu.Unlock()
	for {
		select {
		case gate <- struct{}{}:
		case <-time.After(100 * time.Millisecond):
			return
		}
	}
}

// waitBusy waits until the store has an operation in flight.
func waitBusy(t *testing.T, s *Store) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		busy := len(s.busy)
		s.mu.Unlock()
		if busy > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no operation became in flight")
}

// TestDepositWaitsForInFlightWrite: while the first deposit of an ID is
// still being written, an identical deposit must not answer 200 (the bytes
// are not durable yet), and when that write fails the retry is judged anew.
func TestDepositWaitsForInFlightWrite(t *testing.T) {
	relay, backend, gate := gatedRelay(t)
	alice := newRecipient(t)
	env := alice.seal(t, testPacket(8), relay.clock.unix()+600)

	first := depositAsync(relay.client, env.envelope)
	waitBusy(t, relay.store)
	second := depositAsync(relay.client, env.envelope)
	select {
	case got := <-second:
		t.Fatalf("an identical deposit answered %+v before the first write was durable", got.outcome)
	case <-time.After(300 * time.Millisecond):
	}
	// The listing does not show an envelope that is still being written.
	if mailbox, err := relay.client.List(context.Background(), alice.agentID); err != nil || len(mailbox.Envelopes) != 0 {
		t.Fatalf("list during the write = %+v, %v", mailbox, err)
	}
	if _, err := relay.client.Download(context.Background(), alice.agentID, env.id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("download during the write = %v", err)
	}
	// The first write fails; the waiting deposit is then judged as new.
	backend.mu.Lock()
	backend.failWrites = true
	backend.mu.Unlock()
	gate <- struct{}{}
	if got := <-first; got.err != nil || got.outcome.StatusCode != http.StatusServiceUnavailable || got.outcome.Result != DepositRetryable {
		t.Fatalf("failed first write = %+v, %v", got.outcome, got.err)
	}
	backend.mu.Lock()
	backend.failWrites = false
	backend.mu.Unlock()
	openGate(backend, gate)
	if got := <-second; got.err != nil || got.outcome.Result != DepositStored {
		t.Fatalf("waiting deposit after the failed write = %+v, %v", got.outcome, got.err)
	}
	checkAccounting(t, relay.store)
}

// TestConcurrentDepositBound refuses a deposit past the in-memory body
// bound with 503 before reading it.
func TestConcurrentDepositBound(t *testing.T) {
	relay, backend, gate := gatedRelay(t, func(c *ServerConfig) { c.MaxConcurrentDeposits = 1 })
	alice := newRecipient(t)
	first := depositAsync(relay.client, alice.seal(t, testPacket(8), relay.clock.unix()+600).envelope)
	waitBusy(t, relay.store)
	got := relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600))
	expectStatus(t, got, http.StatusServiceUnavailable)
	if got.header.Get("Retry-After") == "" {
		t.Fatal("503 without Retry-After")
	}
	// Reads are not bounded by it.
	expectStatus(t, relay.do(http.MethodGet, relay.client.BaseURL()+"/v1/relay", "", nil), http.StatusOK)
	openGate(backend, gate)
	if result := <-first; result.outcome.Result != DepositStored {
		t.Fatalf("first deposit = %+v", result.outcome)
	}
	expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600)), http.StatusCreated)
}

// TestDiskWritesAreAtomic checks, at the moment between the synced write and
// the rename, that the record exists only under tmp/ and that its final
// name does not exist yet.
func TestDiskWritesAreAtomic(t *testing.T) {
	dir := t.TempDir()
	clock := newClock()
	store := openDisk(t, dir, clock)
	defer store.Close()
	relay := newTestRelayWithStore(t, store, clock)
	alice := newRecipient(t)
	env := alice.seal(t, testPacket(100), clock.unix()+600)
	var checked []string
	beforeRename = func(target string) {
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists before its rename: %v", target, err)
		}
		partial, err := os.ReadDir(filepath.Join(dir, dirTemp))
		if err != nil || len(partial) != 1 {
			t.Errorf("tmp holds %d entries before the rename: %v", len(partial), err)
		}
		checked = append(checked, filepath.Base(filepath.Dir(target)))
	}
	defer func() { beforeRename = nil }()
	expectStatus(t, relay.putSealed(env), http.StatusCreated)
	expectStatus(t, relay.ackRaw(alice.agentID, env.id, env.secret[:]), http.StatusNoContent)
	if len(checked) != 2 || checked[0] != dirEnvelopes || checked[1] != dirTombstones {
		t.Fatalf("hook saw %v", checked)
	}
}
