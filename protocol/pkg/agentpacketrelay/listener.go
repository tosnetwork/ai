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
	// polls several mailboxes and deposits in parallel.
	DefaultMaxConnectionsPerClient = 16
	// DefaultMaxConnectionsPer48 bounds the open connections of all /64s in
	// one IPv6 /48, the usual assignment to one site: four clients' worth,
	// enough for a few nodes behind one site. Without it one /48 holder
	// would fill the table from 64 of its 65,536 /64s; with it, filling the
	// default 1,024 connections takes 16 distinct /48s or 64 IPv4
	// addresses.
	DefaultMaxConnectionsPer48 = 64
)

// ListenerLimits bounds the connections a relay listener accepts.
type ListenerLimits struct {
	// MaxConnections bounds all open connections; zero takes
	// DefaultMaxConnections.
	MaxConnections int
	// MaxConnectionsPerClient bounds the open connections of one TCP peer
	// address, aggregated like every client address; zero takes
	// DefaultMaxConnectionsPerClient (at most MaxConnections).
	MaxConnectionsPerClient int
	// MaxConnectionsPer48 bounds the open connections of all peers in one
	// IPv6 /48; zero takes DefaultMaxConnectionsPer48 (at most
	// MaxConnections, at least MaxConnectionsPerClient).
	MaxConnectionsPer48 int
	// TrustedProxies are peers exempt from the per-client and per-/48
	// bounds: every client behind a terminating proxy shares its address,
	// so only the total bound applies to them and the proxy must bound its
	// own clients.
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
	per48     int
	trusted   []netip.Prefix

	mu       sync.Mutex
	open     int
	byClient map[netip.Addr]int
	bySite   map[netip.Addr]int
}

// NewLimitListener wraps inner with the connection bounds.
func NewLimitListener(inner net.Listener, limits ListenerLimits) (net.Listener, error) {
	if inner == nil {
		return nil, errors.New("agentpacketrelay: a listener is required")
	}
	maxConnections, perClient, per48 := limits.MaxConnections, limits.MaxConnectionsPerClient, limits.MaxConnectionsPer48
	if maxConnections == 0 {
		maxConnections = DefaultMaxConnections
	}
	if perClient == 0 {
		perClient = min(DefaultMaxConnectionsPerClient, maxConnections)
	}
	if per48 == 0 {
		per48 = max(min(DefaultMaxConnectionsPer48, maxConnections), perClient)
	}
	if maxConnections < 0 || perClient <= 0 || per48 < perClient || per48 > maxConnections {
		return nil, errors.New("agentpacketrelay: connection bounds must satisfy 0 < per client <= per /48 <= total")
	}
	return &limitListener{Listener: inner, max: maxConnections, perClient: perClient, per48: per48,
		trusted: append([]netip.Prefix(nil), limits.TrustedProxies...), byClient: map[netip.Addr]int{},
		bySite: map[netip.Addr]int{}}, nil
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
		site, grouped := site48(peer)
		grouped = grouped && counted
		l.mu.Lock()
		if l.open >= l.max || (counted && l.byClient[key] >= l.perClient) || (grouped && l.bySite[site] >= l.per48) {
			l.mu.Unlock()
			_ = conn.Close()
			continue
		}
		l.open++
		if counted {
			l.byClient[key]++
		}
		if grouped {
			l.bySite[site]++
		}
		l.mu.Unlock()
		return &limitConn{Conn: conn, release: func() { l.release(key, counted, site, grouped) }}, nil
	}
}

func (l *limitListener) release(key netip.Addr, counted bool, site netip.Addr, grouped bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.open--
	if counted {
		if l.byClient[key]--; l.byClient[key] <= 0 {
			delete(l.byClient, key)
		}
	}
	if grouped {
		if l.bySite[site]--; l.bySite[site] <= 0 {
			delete(l.bySite, site)
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
