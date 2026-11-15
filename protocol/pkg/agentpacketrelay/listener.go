package agentpacketrelay

import (
	"errors"
	"net"
	"net/netip"
	"sync"
)

// Connection bounds of the relay listener.
const (
	// DefaultMaxConnections bounds all open connections.
	DefaultMaxConnections = 1024
	// DefaultMaxConnectionsPerClient bounds the open connections of one
	// client address (IPv4, or an IPv6 /64). Sixteen covers a client that
	// polls several mailboxes and deposits in parallel; keeping all 1,024
	// slots then takes 64 distinct addresses rather than one.
	DefaultMaxConnectionsPerClient = 16
)

// ListenerLimits bounds the connections a relay listener accepts.
type ListenerLimits struct {
	// MaxConnections bounds all open connections; zero takes
	// DefaultMaxConnections.
	MaxConnections int
	// MaxConnectionsPerClient bounds the open connections of one TCP peer
	// address, aggregated like every client address; zero takes
	// DefaultMaxConnectionsPerClient.
	MaxConnectionsPerClient int
	// TrustedProxies are peers exempt from the per-client bound: every
	// client behind a terminating proxy shares its address, so only the
	// total bound applies to them and the proxy must bound its own clients.
	TrustedProxies []netip.Prefix
}

// limitListener refuses rather than queues: a connection past a bound is
// closed as soon as it is accepted, so a full table never blocks Accept, an
// idle client cannot hold the listener, and closing the listener always
// ends Accept.
type limitListener struct {
	net.Listener
	max       int
	perClient int
	trusted   []netip.Prefix

	mu       sync.Mutex
	open     int
	byClient map[netip.Addr]int
}

// NewLimitListener wraps inner with the connection bounds.
func NewLimitListener(inner net.Listener, limits ListenerLimits) (net.Listener, error) {
	if inner == nil {
		return nil, errors.New("agentpacketrelay: a listener is required")
	}
	maxConnections, perClient := limits.MaxConnections, limits.MaxConnectionsPerClient
	if maxConnections == 0 {
		maxConnections = DefaultMaxConnections
	}
	if perClient == 0 {
		perClient = DefaultMaxConnectionsPerClient
	}
	if maxConnections < 0 || perClient < 0 || perClient > maxConnections {
		return nil, errors.New("agentpacketrelay: connection bounds must be positive, per client at most the total")
	}
	return &limitListener{Listener: inner, max: maxConnections, perClient: perClient,
		trusted: append([]netip.Prefix(nil), limits.TrustedProxies...), byClient: map[netip.Addr]int{}}, nil
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		peer, ok := parseHostAddr(conn.RemoteAddr().String())
		if !ok {
			_ = conn.Close()
			continue
		}
		key, counted := aggregate(peer), !isTrusted(peer, l.trusted)
		l.mu.Lock()
		if l.open >= l.max || (counted && l.byClient[key] >= l.perClient) {
			l.mu.Unlock()
			_ = conn.Close()
			continue
		}
		l.open++
		if counted {
			l.byClient[key]++
		}
		l.mu.Unlock()
		return &limitConn{Conn: conn, release: func() { l.release(key, counted) }}, nil
	}
}

func (l *limitListener) release(key netip.Addr, counted bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.open--
	if counted {
		if l.byClient[key]--; l.byClient[key] <= 0 {
			delete(l.byClient, key)
		}
	}
}

// openConnections reports the accounting, for tests.
func (l *limitListener) openConnections() (int, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.open, len(l.byClient)
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
