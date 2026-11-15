package agentpacketrelay

import (
	"container/list"
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

// Rate-limiter table bounds.
const (
	// DefaultMaxRateClients bounds each rate-limiter table.
	DefaultMaxRateClients = 1 << 16
	// DefaultMaxRateClientsPer48 bounds the buckets of the /64 client
	// addresses inside one IPv6 /48. A /48 holds 65,536 /64s, enough to fill
	// a whole table alone; past this bound its further /64s share one
	// bucket, so one /48 holds at most 257 of the table's entries.
	DefaultMaxRateClientsPer48 = 256
)

func (r RateLimit) validate() error {
	if r.PerMinute <= 0 || r.Burst <= 0 || r.PerMinute > 1<<20 || r.Burst > 1<<20 {
		return errors.New("rate limits must be positive and bounded")
	}
	return nil
}

// rateKey names a bucket: a client address, or (shared) the IPv6 /48 whose
// own buckets are at their bound.
type rateKey struct {
	addr   netip.Addr
	shared bool
}

type bucket struct {
	key    rateKey
	group  netip.Addr // the /48 of an IPv6 client's own bucket; zero otherwise
	tokens float64
	last   time.Time
	elem   *list.Element
}

// rateLimiter is a bounded table of token buckets in least-recently-used
// order. A new client never waits for room: when the table is full the
// least recently used bucket is evicted in constant time. That bucket is
// the one most likely to have refilled; a limited client can lose its
// state only after as many other buckets as the table holds have been
// used more recently, and the per-/48 bound keeps one IPv6 /48 from
// supplying them.
type rateLimiter struct {
	mu       sync.Mutex
	perSec   float64
	burst    float64
	max      int
	perGroup int
	buckets  map[rateKey]*bucket
	order    *list.List // front is the most recently used
	groups   map[netip.Addr]int
}

func newRateLimiter(limit RateLimit, maxClients, perGroup int) *rateLimiter {
	return &rateLimiter{perSec: float64(limit.PerMinute) / 60, burst: float64(limit.Burst), max: maxClients,
		perGroup: perGroup, buckets: map[rateKey]*bucket{}, order: list.New(), groups: map[netip.Addr]int{}}
}

// allow takes one token for client, or returns how long until one is free.
func (l *rateLimiter) allow(client netip.Addr, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := rateKey{addr: client}
	b := l.buckets[key]
	var group netip.Addr
	if b == nil && client.Is6() {
		if prefix, err := client.Prefix(48); err == nil {
			group = prefix.Addr()
			if l.groups[group] >= l.perGroup {
				key, group = rateKey{addr: group, shared: true}, netip.Addr{}
				b = l.buckets[key]
			}
		}
	}
	if b == nil {
		for len(l.buckets) >= l.max {
			l.evictOldest()
		}
		b = &bucket{key: key, group: group, tokens: l.burst, last: now}
		b.elem = l.order.PushFront(b)
		l.buckets[key] = b
		if group.IsValid() {
			l.groups[group]++
		}
	} else {
		l.order.MoveToFront(b.elem)
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

func (l *rateLimiter) evictOldest() {
	oldest := l.order.Back()
	if oldest == nil {
		return
	}
	b := oldest.Value.(*bucket)
	l.order.Remove(oldest)
	delete(l.buckets, b.key)
	if b.group.IsValid() {
		if l.groups[b.group]--; l.groups[b.group] <= 0 {
			delete(l.groups, b.group)
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
