package agentpacketrelay

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	relay, backend, gate := gatedRelay(t, func(c *ServerConfig) {
		c.MaxConcurrentDeposits = 1
		c.MaxConcurrentDepositsPerClient = 1
		c.TrustedProxies = []netipPrefix{mustPrefix(t, "127.0.0.1/32")}
	})
	alice := newRecipient(t)
	first := depositAsync(relay.client, alice.seal(t, testPacket(8), relay.clock.unix()+600).envelope)
	waitBusy(t, relay.store)
	// Another client address: its own share is free, the shared slot is not.
	got := relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600), "X-Forwarded-For", "192.0.2.50")
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

// TestPerClientDepositBound: one client address holds at most its share of
// deposit bodies at once; past it that client gets 429 while another client
// is still served, and the share frees when a deposit ends.
func TestPerClientDepositBound(t *testing.T) {
	relay, backend, gate := gatedRelay(t, func(c *ServerConfig) {
		c.MaxConcurrentDeposits = 16
		c.MaxConcurrentDepositsPerClient = 4
		c.TrustedProxies = []netipPrefix{mustPrefix(t, "127.0.0.1/32")}
	})
	alice := newRecipient(t)
	from := func(addr string) []string { return []string{"X-Forwarded-For", addr} }
	type parked struct{ done chan response }
	park := func(addr string) parked {
		env := alice.seal(t, testPacket(8), relay.clock.unix()+600)
		done := make(chan response, 1)
		go func() { done <- relay.putSealed(env, from(addr)...) }()
		return parked{done}
	}
	var held []parked
	for range 4 {
		held = append(held, park("198.51.100.9"))
	}
	waitFor(t, func() bool {
		relay.server.inflightMu.Lock()
		defer relay.server.inflightMu.Unlock()
		return relay.server.inflight[mustAddr(t, "198.51.100.9")] == 4
	})
	select {
	case got := <-park("198.51.100.9").done:
		expectStatus(t, got, http.StatusTooManyRequests)
	case <-time.After(2 * time.Second):
		t.Fatal("a fifth concurrent deposit from one address was admitted")
	}
	other := park("198.51.100.10")
	waitFor(t, func() bool {
		relay.server.inflightMu.Lock()
		defer relay.server.inflightMu.Unlock()
		return relay.server.inflight[mustAddr(t, "198.51.100.10")] == 1
	})
	openGate(backend, gate)
	for _, p := range append(held, other) {
		expectStatus(t, <-p.done, http.StatusCreated)
	}
	relay.server.inflightMu.Lock()
	left := len(relay.server.inflight)
	relay.server.inflightMu.Unlock()
	if left != 0 {
		t.Fatalf("%d clients still hold deposit slots", left)
	}
	expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600), from("198.51.100.9")...), http.StatusCreated)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestDepositBodyDeadline: a body trickled slower than the minimum rate
// loses its slot when its deadline passes, long before the request read
// timeout, and the slot is free again for the next deposit.
func TestDepositBodyDeadline(t *testing.T) {
	relay := newTestRelay(t, testLimits(), func(c *ServerConfig) {
		c.MaxConcurrentDeposits = 1
		c.MaxConcurrentDepositsPerClient = 1
		c.DepositReadBase = 300 * time.Millisecond
		c.DepositMinBytesPerSecond = 1 << 30
	})
	alice := newRecipient(t)
	conn, err := net.Dial("tcp", strings.TrimPrefix(relay.http.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	env := alice.seal(t, testPacket(8), relay.clock.unix()+600)
	request := "PUT /v1/mailboxes/" + alice.agentID + "/envelopes/" + hex.EncodeToString(env.id[:]) + " HTTP/1.1\r\n" +
		"Host: relay\r\nContent-Type: application/octet-stream\r\nContent-Length: " + strconv.Itoa(len(env.envelope)) + "\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		for index := 0; index < len(env.envelope); index++ {
			if _, err := conn.Write(env.envelope[index : index+1]); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	answer, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("a trickled deposit body held its slot past its deadline")
	}
	if err != nil {
		t.Fatalf("no answer to a trickled body: %v", err)
	}
	body, _ := io.ReadAll(answer.Body)
	answer.Body.Close()
	// Slow is not malformed: 408, which a sender retries, not 400.
	expectStatus(t, response{status: answer.StatusCode, header: answer.Header, body: body}, http.StatusRequestTimeout)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("the trickled body was cut after %s", elapsed)
	}
	conn.Close()
	<-ended
	// The slot is free: a normal deposit is stored.
	waitFor(t, func() bool {
		relay.server.inflightMu.Lock()
		defer relay.server.inflightMu.Unlock()
		return len(relay.server.inflight) == 0 && len(relay.server.bodies) == 0
	})
	expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600)), http.StatusCreated)
}
