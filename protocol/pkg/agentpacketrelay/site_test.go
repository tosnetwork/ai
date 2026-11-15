package agentpacketrelay

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

// fakeListener hands out in-memory connections that report a chosen peer
// address, so per-/48 bounds can be tested with many IPv6 /64s.
type fakeListener struct {
	conns  chan net.Conn
	closed chan struct{}
}

func newFakeListener() *fakeListener {
	return &fakeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (f *fakeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-f.conns:
		return conn, nil
	case <-f.closed:
		return nil, net.ErrClosed
	}
}

func (f *fakeListener) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

func (f *fakeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv6loopback, Port: 1} }

type peerConn struct {
	net.Conn
	peer net.Addr
}

func (p peerConn) RemoteAddr() net.Addr { return p.peer }

// offer hands one connection from peer to the listener and reports whether
// the listener kept it open.
func offer(t *testing.T, inner *fakeListener, accepted chan net.Conn, peer string) bool {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	addr := net.TCPAddrFromAddrPort(netip.MustParseAddrPort(peer))
	inner.conns <- peerConn{Conn: server, peer: addr}
	select {
	case <-accepted:
		return true
	case <-time.After(300 * time.Millisecond):
	}
	// Refused: the listener closed its end, so the client reads EOF.
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("connection from %s neither accepted nor closed: %v", peer, err)
	}
	return false
}

// TestLimitListenerPer48: many /64s inside one IPv6 /48 together hold at
// most that /48's share; another /48 and IPv4 peers are still served.
func TestLimitListenerPer48(t *testing.T) {
	inner := newFakeListener()
	wrapped, err := NewLimitListener(inner, ListenerLimits{MaxConnections: 100, MaxConnectionsPerClient: 2,
		MaxConnectionsPer48: 6})
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	accepted := acceptLoop(t, wrapped)
	kept := 0
	for index := range 20 {
		if offer(t, inner, accepted, fmt.Sprintf("[2001:db8:aa:%x::1]:4000", index)) {
			kept++
		}
	}
	if kept != 6 {
		t.Fatalf("one /48 holds %d connections, want 6", kept)
	}
	// Two per /64 still applies inside the /48's share.
	if !offer(t, inner, accepted, "[2001:db8:bb:1::1]:4000") || !offer(t, inner, accepted, "[2001:db8:bb:1::2]:4000") ||
		offer(t, inner, accepted, "[2001:db8:bb:1::3]:4000") {
		t.Fatal("per-/64 bound inside a fresh /48 not enforced")
	}
	if !offer(t, inner, accepted, "192.0.2.7:4000") {
		t.Fatal("an IPv4 peer was refused")
	}
	listener := wrapped.(*limitListener)
	listener.mu.Lock()
	sites := listener.bySite[netip.MustParseAddr("2001:db8:aa::")]
	listener.mu.Unlock()
	if sites != 6 {
		t.Fatalf("site accounting = %d", sites)
	}
}

// TestLimitListenerPer48Release: closing a connection frees its /48 share.
func TestLimitListenerPer48Release(t *testing.T) {
	inner := newFakeListener()
	wrapped, err := NewLimitListener(inner, ListenerLimits{MaxConnections: 10, MaxConnectionsPerClient: 1,
		MaxConnectionsPer48: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			conn, err := wrapped.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	server, client := net.Pipe()
	defer client.Close()
	inner.conns <- peerConn{Conn: server, peer: net.TCPAddrFromAddrPort(netip.MustParseAddrPort("[2001:db8:cc:1::1]:1"))}
	held := <-accepted
	if offer(t, inner, accepted, "[2001:db8:cc:2::1]:1") {
		t.Fatal("the /48 bound did not hold")
	}
	held.Close()
	if !offer(t, inner, accepted, "[2001:db8:cc:2::1]:1") {
		t.Fatal("closing a connection did not free its /48 share")
	}
}

// TestPer48DepositBound: many /64s inside one IPv6 /48 together hold at
// most that /48's share of deposit bodies; another /48 is still served.
func TestPer48DepositBound(t *testing.T) {
	relay, backend, gate := gatedRelay(t, func(c *ServerConfig) {
		c.MaxConcurrentDeposits = 32
		c.MaxConcurrentDepositsPerClient = 2
		c.MaxConcurrentDepositsPer48 = 4
		c.TrustedProxies = []netipPrefix{mustPrefix(t, "127.0.0.1/32")}
	})
	alice := newRecipient(t)
	park := func(addr string) chan response {
		env := alice.seal(t, testPacket(8), relay.clock.unix()+600)
		done := make(chan response, 1)
		go func() { done <- relay.putSealed(env, "X-Forwarded-For", addr) }()
		return done
	}
	site := mustAddr(t, "2001:db8:aa::")
	var held []chan response
	for index := range 4 {
		held = append(held, park(fmt.Sprintf("2001:db8:aa:%x::1", index)))
	}
	waitFor(t, func() bool {
		relay.server.inflightMu.Lock()
		defer relay.server.inflightMu.Unlock()
		return relay.server.inflightSites[site] == 4
	})
	select {
	case got := <-park("2001:db8:aa:99::1"):
		expectStatus(t, got, http.StatusTooManyRequests)
	case <-time.After(2 * time.Second):
		t.Fatal("a fifth body from one /48 was admitted")
	}
	other := park("2001:db8:bb::1")
	waitFor(t, func() bool {
		relay.server.inflightMu.Lock()
		defer relay.server.inflightMu.Unlock()
		return relay.server.inflightSites[mustAddr(t, "2001:db8:bb::")] == 1
	})
	openGate(backend, gate)
	for _, done := range append(held, other) {
		expectStatus(t, <-done, http.StatusCreated)
	}
	relay.server.inflightMu.Lock()
	left := len(relay.server.inflightSites)
	relay.server.inflightMu.Unlock()
	if left != 0 {
		t.Fatalf("%d sites still hold deposit slots", left)
	}
}

func TestDepositBoundsConfig(t *testing.T) {
	store, err := NewMemoryStore(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []ServerConfig{
		{Store: store, MaxConcurrentDeposits: 8, MaxConcurrentDepositsPerClient: 4, MaxConcurrentDepositsPer48: 2},
		{Store: store, MaxConcurrentDeposits: 8, MaxConcurrentDepositsPer48: 9},
		{Store: store, MaxConcurrentDepositsPerClient: -1},
	} {
		if _, err := NewServer(config); err == nil {
			t.Fatalf("%+v accepted", config)
		}
	}
	server, err := NewServer(ServerConfig{Store: store, MaxConcurrentDeposits: 8})
	if err != nil || server.perClient != 4 || server.per48Bodies != 8 {
		t.Fatalf("clamped defaults = %v, %d, %d", err, server.perClient, server.per48Bodies)
	}
	server, err = NewServer(ServerConfig{Store: store})
	if err != nil || server.perClient != DefaultMaxConcurrentDepositsPerClient || server.per48Bodies != DefaultMaxConcurrentDepositsPer48 {
		t.Fatalf("defaults = %v, %d, %d", err, server.perClient, server.per48Bodies)
	}
}

// TestLimitListenerTrustedProxyPer48: an IPv6 trusted proxy is exempt from
// the /48 bound as well, and counts only against the total.
func TestLimitListenerTrustedProxyPer48(t *testing.T) {
	inner := newFakeListener()
	wrapped, err := NewLimitListener(inner, ListenerLimits{MaxConnections: 3, MaxConnectionsPerClient: 1,
		MaxConnectionsPer48: 1, TrustedProxies: []netipPrefix{mustPrefix(t, "2001:db8:ff::/48")}})
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	accepted := acceptLoop(t, wrapped)
	for range 3 {
		if !offer(t, inner, accepted, "[2001:db8:ff::1]:443") {
			t.Fatal("a trusted IPv6 proxy was held to the per-client or /48 bound")
		}
	}
	if offer(t, inner, accepted, "[2001:db8:ff::1]:443") {
		t.Fatal("the total bound did not hold for a trusted proxy")
	}
}
