package agentcarrier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

type gate chan struct{}

func (g gate) lock(ctx context.Context) error {
	select {
	case g <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ErrUnavailable
	}
}
func (g gate) unlock() { <-g }

type Lane struct {
	meta             gate
	wait             gate
	notice           string
	config           Config
	disk             *disk
	out              gate
	keys             gate
	poll             gate
	mu               sync.Mutex
	settled, refused map[string]memory
	preferred        string
}
type memory struct {
	Secret [32]byte
	Until  uint64
}
type identity struct {
	Schema string `json:"schema"`
	Agent  string `json:"agent"`
	Kind   Kind   `json:"kind"`
}
type pollRelay struct {
	URL   string `json:"url"`
	Until uint64 `json:"until"`
}
type pollSet struct {
	Identity identity    `json:"identity"`
	Relays   []pollRelay `json:"relays"`
}

func (l *Lane) identity() identity {
	return identity{"tos.service.carrier.lane.v2", l.config.AgentID, l.config.Kind}
}
func validRelays(in []string) bool {
	if len(in) < 1 || len(in) > 4 {
		return false
	}
	seen := map[string]bool{}
	for _, url := range in {
		if agentpacketseal.CheckRelayURL(url) != nil || seen[url] {
			return false
		}
		seen[url] = true
	}
	return true
}
func Open(ctx context.Context, c Config) (l *Lane, err error) {
	if (c.Kind != Rail && c.Kind != Chat) || !validRelays(c.Relays) || c.Verifier == nil || c.Credentials == nil || c.Relay == nil || c.SignCard == nil || c.VerifyCard == nil || c.VerifyPacket == nil || c.Store == nil {
		return nil, ErrConfig
	}
	if _, err = agentpacketseal.AgentDigest(c.AgentID); err != nil || c.AgentID == agentpacketseal.KeyCardAudience {
		return nil, ErrConfig
	}
	d, err := agenttransport.DecodeDelegation(c.Delegation)
	if err != nil || d.AgentID() != c.AgentID || d.Purposes&agenttransport.Relay == 0 {
		return nil, ErrConfig
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.OutboxLimit == 0 {
		c.OutboxLimit = DefaultOutbox
	}
	if c.OutboxLimit < 1 || c.OutboxLimit > MaxOutbox {
		return nil, ErrConfig
	}
	c.Relays = append([]string(nil), c.Relays...)
	c.Delegation = bytes.Clone(c.Delegation)
	if !filepath.IsAbs(c.StateDir) || filepath.Clean(c.StateDir) != c.StateDir {
		return nil, ErrConfig
	}
	if err = privateRoot(c.StateDir); err != nil {
		return nil, err
	}
	disk, err := openDisk(filepath.Join(c.StateDir, string(c.Kind)))
	if err != nil {
		return nil, err
	}
	l = &Lane{config: c, disk: disk, out: make(gate, 1), keys: make(gate, 1), poll: make(gate, 1), wait: make(gate, 1), meta: make(gate, 1), settled: map[string]memory{}, refused: map[string]memory{}}
	defer func() {
		if err != nil {
			if closeErr := disk.close(); closeErr != nil {
				err = ErrStorage
			}
			l = nil
		}
	}()
	if _, err = l.now(); err != nil {
		return l, err
	}
	names, err := disk.names(c.OutboxLimit + MaxKeys + 8)
	if err != nil {
		return l, err
	}
	for _, name := range names {
		if strings.HasPrefix(name, "write-") {
			if len(name) != 38 {
				return l, ErrStorage
			}
			if _, e := hex.DecodeString(name[6:]); e != nil {
				return l, ErrStorage
			}
			info, e := disk.root.Lstat(name)
			if e != nil || !singlePrivate(info) {
				return l, ErrStorage
			}
			if err = disk.remove(name); err != nil {
				return l, err
			}
		}
	}
	var saved inventory
	err = disk.read("identity", &saved)
	if errors.Is(err, os.ErrNotExist) {
		names, err = disk.names(c.OutboxLimit + MaxKeys + 8)
		if err != nil {
			return l, err
		}
		if len(names) != 1 || names[0] != "lock" {
			return l, ErrStorage
		}
		if err = disk.write("identity", inventory{Identity: l.identity(), Keys: []string{}, Deliveries: []string{}}); err != nil {
			return l, err
		}
	} else if err != nil || saved.Identity != l.identity() {
		return l, ErrStorage
	}
	if err = l.audit(); err != nil {
		return l, err
	}
	// Authority failure does not create an alternative key or authority path.
	// Poll and card issuance refuse; outbound deposits can still use strangers.
	if err = l.TrackRelays(ctx, c.Relays, 0); err != nil {
		return l, err
	}
	if authorityErr := l.own(ctx); authorityErr != nil {
		l.mu.Lock()
		l.notice = ErrTransportRevoked.Error()
		l.mu.Unlock()
	}
	return l, nil
}
func (l *Lane) Close() error { return l.disk.close() }
func (l *Lane) now() (uint64, error) {
	n := l.config.Now().Unix()
	if n <= 0 || n > math.MaxInt64-int64((31*24*time.Hour+KeyRetention)/time.Second) {
		return 0, ErrConfig
	}
	return uint64(n), nil
}
func (l *Lane) own(ctx context.Context) error {
	call, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	if _, err := l.config.Verifier.VerifyDelegation(call, l.config.Delegation, agenttransport.Relay); err != nil {
		return ErrTransportRevoked
	}
	return nil
}

// OwnNotice checks current finalized authority without publishing any object.
func (l *Lane) OwnNotice(ctx context.Context) string {
	if l.own(ctx) != nil {
		return ErrTransportRevoked.Error()
	}
	return ""
}
func (l *Lane) audit() error {
	index, err := l.inventory()
	if err != nil {
		return err
	}
	expected := map[string]bool{}
	for _, name := range append(append([]string(nil), index.Keys...), index.Deliveries...) {
		expected[name] = true
	}
	names, err := l.disk.names(l.config.OutboxLimit + MaxKeys + 8)
	if err != nil {
		return err
	}
	for _, name := range names {
		switch {
		case name == "identity" || name == "lock" || name == "relays":
			continue
		case strings.HasPrefix(name, "key-"):
			r, err := l.readKey(name)
			clear(r.Seed)
			if err != nil {
				return err
			}
		case strings.HasPrefix(name, "out-"):
			if _, err := l.decodeDelivery(name); err != nil {
				return err
			}
		default:
			return ErrStorage
		}
		if expected[name] {
			delete(expected, name)
		} else if err := l.disk.remove(name); err != nil {
			return err
		}
	}
	if len(expected) != 0 {
		return ErrStorage
	}
	return nil
}

// TrackRelays retains an owner-selected poll target until at least until. Zero
// selects the normal card-retention horizon. PR9 supplies hint retirement times;
// reductions cannot erase an unexpired target. Peer cards never call this API.
func (l *Lane) TrackRelays(ctx context.Context, urls []string, until uint64) error {
	if !validRelays(urls) {
		return ErrConfig
	}
	if err := l.keys.lock(ctx); err != nil {
		return err
	}
	defer l.keys.unlock()
	return l.trackRelaysLocked(urls, until)
}
func (l *Lane) trackRelaysLocked(urls []string, until uint64) error {
	now, err := l.now()
	if err != nil {
		return err
	}
	horizon := now + uint64((30*24*time.Hour+KeyRetention)/time.Second)
	if until == 0 {
		until = now + uint64((KeyLifetime+KeyRetention)/time.Second)
	}
	if until <= now || until > horizon {
		return ErrConfig
	}
	current, err := l.pollTargets()
	if err != nil {
		return err
	}
	merged := map[string]uint64{}
	for _, v := range current {
		if v.Until > now {
			merged[v.URL] = v.Until
		}
	}
	for _, url := range urls {
		merged[url] = max(merged[url], until)
	}
	if len(merged) > MaxPollRelays {
		return ErrCapacity
	}
	out := pollSet{Identity: l.identity(), Relays: make([]pollRelay, 0, len(merged))}
	for u, t := range merged {
		out.Relays = append(out.Relays, pollRelay{u, t})
	}
	sort.Slice(out.Relays, func(i, j int) bool { return out.Relays[i].URL < out.Relays[j].URL })
	return l.disk.write("relays", out)
}
func (l *Lane) pollTargets() ([]pollRelay, error) {
	var held pollSet
	if err := l.disk.read("relays", &held); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, ErrStorage
	}
	if held.Identity != l.identity() || len(held.Relays) > MaxPollRelays {
		return nil, ErrStorage
	}
	for i, r := range held.Relays {
		if agentpacketseal.CheckRelayURL(r.URL) != nil || r.Until == 0 || (i > 0 && held.Relays[i-1].URL >= r.URL) {
			return nil, ErrStorage
		}
	}
	return held.Relays, nil
}
func deliveryName(id string) string {
	sum := sha256.Sum256(append([]byte("tos.service.carrier.delivery.v2\x00"), id...))
	return "out-" + hex.EncodeToString(sum[:])
}
