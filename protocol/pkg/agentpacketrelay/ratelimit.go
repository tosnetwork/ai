package agentpacketrelay

import (
	"errors"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// RateLimit is a token bucket per client address.
type RateLimit struct {
	PerMinute int
	Burst     int
}

// V1 default rates. The read burst is not fixed by V1; 100 lets one poll
// cycle list several mailboxes and download a backlog without stalling.
var (
	DefaultDepositRate = RateLimit{PerMinute: 60, Burst: 32}
	DefaultReadRate    = RateLimit{PerMinute: 600, Burst: 100}
)

// DefaultMaxRateClients bounds the rate-limiter table.
const DefaultMaxRateClients = 1 << 16

func (r RateLimit) validate() error {
	if r.PerMinute <= 0 || r.Burst <= 0 || r.PerMinute > 1<<20 || r.Burst > 1<<20 {
		return errors.New("rate limits must be positive and bounded")
	}
	return nil
}

type bucket struct {
	tokens float64
	last   time.Time
}

// rateLimiter is a bounded table of token buckets. A client whose bucket
// has refilled is indistinguishable from a new one, so such buckets are the
// ones dropped when the table is full. When every bucket is still draining
// the new client is refused: the table never grows without bound and never
// forgets a client that is being limited.
type rateLimiter struct {
	mu      sync.Mutex
	perSec  float64
	burst   float64
	max     int
	buckets map[netip.Addr]*bucket
}

func newRateLimiter(limit RateLimit, maxClients int) *rateLimiter {
	return &rateLimiter{perSec: float64(limit.PerMinute) / 60, burst: float64(limit.Burst), max: maxClients,
		buckets: map[netip.Addr]*bucket{}}
}

// allow takes one token for client, or returns how long until one is free.
func (l *rateLimiter) allow(client netip.Addr, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[client]
	if b == nil {
		if len(l.buckets) >= l.max {
			l.prune(now)
			if len(l.buckets) >= l.max {
				return false, time.Second
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[client] = b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(l.burst, b.tokens+elapsed*l.perSec)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration(math.Ceil((1 - b.tokens) / l.perSec * float64(time.Second)))
	return false, wait
}

func (l *rateLimiter) prune(now time.Time) {
	for key, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.perSec >= l.burst {
			delete(l.buckets, key)
		}
	}
}

// clientAddress returns the client address of a request, aggregated as V1
// requires (IPv4 as is, IPv6 to its /64). The direct peer is the client
// unless it is one of the trusted proxies; then X-Forwarded-For is walked
// from the right and the first address that is not a trusted proxy is the
// client. Without trusted proxies X-Forwarded-For is ignored.
func clientAddress(request *http.Request, trusted []netip.Prefix) (netip.Addr, bool) {
	peer, ok := parseHostAddr(request.RemoteAddr)
	if !ok {
		return netip.Addr{}, false
	}
	client := peer
	if isTrusted(peer, trusted) {
		hops := []string{}
		for _, value := range request.Header.Values("X-Forwarded-For") {
			hops = append(hops, strings.Split(value, ",")...)
		}
		for index := len(hops) - 1; index >= 0; index-- {
			hop, err := netip.ParseAddr(strings.TrimSpace(hops[index]))
			if err != nil {
				// A hop that does not parse ends the walk: everything to
				// its left came from an unknown party.
				break
			}
			client = hop.Unmap().WithZone("")
			if !isTrusted(client, trusted) {
				break
			}
		}
	}
	return aggregate(client), true
}

func parseHostAddr(remote string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap().WithZone(""), true
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, prefix := range trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func aggregate(addr netip.Addr) netip.Addr {
	if addr.Is4() {
		return addr
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return addr
	}
	return prefix.Addr()
}
