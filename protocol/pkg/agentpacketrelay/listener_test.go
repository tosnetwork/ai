package agentpacketrelay

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// acceptLoop accepts until the listener closes and keeps every connection
// open, reporting each on accepted.
func acceptLoop(t *testing.T, listener net.Listener) chan net.Conn {
	t.Helper()
	accepted := make(chan net.Conn, 64)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- conn
		}
	}()
	return accepted
}

// dialFrom connects from a chosen loopback source address.
func dialFrom(t *testing.T, source string, target net.Addr) net.Conn {
	t.Helper()
	dialer := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
	conn, err := dialer.Dial("tcp", target.String())
	if err != nil {
		t.Fatalf("dial from %s: %v", source, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// refused reports whether the server closed the connection without serving
// it.
func refused(t *testing.T, conn net.Conn) bool {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := conn.Read(make([]byte, 1))
	return errors.Is(err, io.EOF) || isReset(err)
}

func isReset(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && !opErr.Timeout()
}

func expectAccepted(t *testing.T, accepted chan net.Conn, n int) []net.Conn {
	t.Helper()
	var out []net.Conn
	for range n {
		select {
		case conn := <-accepted:
			out = append(out, conn)
		case <-time.After(2 * time.Second):
			t.Fatalf("accepted %d of %d connections", len(out), n)
		}
	}
	select {
	case conn := <-accepted:
		t.Fatalf("an extra connection from %v was accepted", conn.RemoteAddr())
	case <-time.After(200 * time.Millisecond):
	}
	return out
}

func newLimited(t *testing.T, limits ListenerLimits) (*limitListener, net.Addr) {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := NewLimitListener(inner, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener.(*limitListener), inner.Addr()
}

// TestLimitListenerPerClient: one address cannot hold more than its share,
// the excess is closed at once instead of queued, other addresses are still
// served, and a closed connection frees its slot.
func TestLimitListenerPerClient(t *testing.T) {
	listener, addr := newLimited(t, ListenerLimits{MaxConnections: 10, MaxConnectionsPerClient: 2})
	accepted := acceptLoop(t, listener)
	dialFrom(t, "127.0.0.1", addr)
	dialFrom(t, "127.0.0.1", addr)
	held := expectAccepted(t, accepted, 2)
	extra := dialFrom(t, "127.0.0.1", addr)
	if !refused(t, extra) {
		t.Fatal("a third connection from one address was not refused")
	}
	other := dialFrom(t, "127.0.0.2", addr)
	expectAccepted(t, accepted, 1)
	if refused(t, other) {
		t.Fatal("another address was refused")
	}
	if open, clients := listener.openConnections(); open != 3 || clients != 2 {
		t.Fatalf("accounting = %d open, %d clients", open, clients)
	}
	held[0].Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if open, _ := listener.openConnections(); open == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closing a connection did not free its slot")
		}
		time.Sleep(5 * time.Millisecond)
	}
	dialFrom(t, "127.0.0.1", addr)
	expectAccepted(t, accepted, 1)
}

// TestLimitListenerTotal: past the total bound every new connection is
// closed at once, and Accept keeps returning for the ones that fit.
func TestLimitListenerTotal(t *testing.T) {
	listener, addr := newLimited(t, ListenerLimits{MaxConnections: 2, MaxConnectionsPerClient: 2})
	accepted := acceptLoop(t, listener)
	dialFrom(t, "127.0.0.2", addr)
	dialFrom(t, "127.0.0.3", addr)
	held := expectAccepted(t, accepted, 2)
	if !refused(t, dialFrom(t, "127.0.0.4", addr)) {
		t.Fatal("a connection past the total bound was not refused")
	}
	held[1].Close()
	time.Sleep(50 * time.Millisecond)
	dialFrom(t, "127.0.0.4", addr)
	expectAccepted(t, accepted, 1)
}

// TestLimitListenerTrustedProxyExempt: a trusted proxy's connections count
// only against the total.
func TestLimitListenerTrustedProxyExempt(t *testing.T) {
	listener, addr := newLimited(t, ListenerLimits{MaxConnections: 4, MaxConnectionsPerClient: 1,
		TrustedProxies: []netip.Prefix{mustPrefix(t, "127.0.0.1/32")}})
	accepted := acceptLoop(t, listener)
	for range 3 {
		dialFrom(t, "127.0.0.1", addr)
	}
	expectAccepted(t, accepted, 3)
	dialFrom(t, "127.0.0.5", addr)
	expectAccepted(t, accepted, 1)
	if !refused(t, dialFrom(t, "127.0.0.1", addr)) {
		t.Fatal("the total bound did not hold for a trusted proxy")
	}
}

// TestLimitListenerCloseUnblocksAccept: with every slot held, closing the
// listener still ends a pending Accept.
func TestLimitListenerCloseUnblocksAccept(t *testing.T) {
	listener, addr := newLimited(t, ListenerLimits{MaxConnections: 1, MaxConnectionsPerClient: 1})
	accepted := acceptLoop(t, listener)
	dialFrom(t, "127.0.0.2", addr)
	expectAccepted(t, accepted, 1)
	// The accept loop is now parked in Accept with the table full.
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, open := <-accepted:
		if open {
			t.Fatal("a connection was accepted after close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return after the listener closed")
	}
}

func TestLimitListenerConfig(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	for _, limits := range []ListenerLimits{{MaxConnections: -1}, {MaxConnectionsPerClient: -1},
		{MaxConnections: 2, MaxConnectionsPerClient: 3}} {
		if _, err := NewLimitListener(inner, limits); err == nil {
			t.Fatalf("%+v accepted", limits)
		}
	}
	if _, err := NewLimitListener(nil, ListenerLimits{}); err == nil {
		t.Fatal("nil listener accepted")
	}
}
