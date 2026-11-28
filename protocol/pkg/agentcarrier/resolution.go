package agentcarrier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

// Directory adds only V2 directory operations; cards and in-band packets cannot
// supply these URLs. Last-known targets originate in previously verified hints.
type Directory interface {
	HintIndex(context.Context, string) ([]agentpacketrelay.HintIndexEntry, error)
	HintRecord(context.Context, string, [32]byte) ([]byte, error)
	PublishHint(context.Context, []byte) error
}

var _ Directory = (*agentpacketrelay.V2Client)(nil)

type ResolverConfig struct {
	Directories []string
	Directory   func(string) (Directory, error)
	// Single-relay hints are only an explicit test configuration. The finalized
	// verifier still independently restricts the network to its pinned identities.
	TestSingleRelay bool
}
type Resolver struct {
	lane   *Lane
	config ResolverConfig
	store  *routingStore
}
type peerHints struct {
	Agent      string            `json:"agent"`
	Records    [][]byte          `json:"records"`
	Cards      map[string][]byte `json:"cards"`
	LastRelays []string          `json:"last_relays"`
	Touched    uint64            `json:"touched"`
}

func OpenResolver(l *Lane, c ResolverConfig) (*Resolver, error) {
	if l == nil || c.Directory == nil || !validRelays(c.Directories) || len(c.Directories) < 2 {
		return nil, ErrConfig
	}
	c.Directories = append([]string(nil), c.Directories...)
	s, e := openRoutingStore(filepath.Join(l.config.StateDir, "routes-"+string(l.config.Kind)), l.identity())
	if e != nil {
		return nil, e
	}
	return &Resolver{l, c, s}, nil
}
func (r *Resolver) Close() error { return r.store.Close() }
func (r *Resolver) verify(ctx context.Context, agent string, raw []byte, cards ...[]byte) (Route, error) {
	hint, e := r.lane.config.Verifier.VerifyHint(ctx, raw, r.lane.config.HintPolicy)
	if e != nil {
		return Route{}, ErrNoRoute
	}
	if hint.Record.Hint.Delegation.AgentID() != agent || (!r.config.TestSingleRelay && len(hint.Record.Hint.Relays) < 2) {
		return Route{}, ErrNoRoute
	}
	if len(cards) == 0 {
		cards = [][]byte{nil}
	}
	var route Route
	var chosen agentpacketseal.KeyCard
	for _, card := range cards {
		candidate := Route{HintRecord: bytes.Clone(raw), CardPacket: bytes.Clone(card)}
		resolved, err := r.lane.verifiedRoute(ctx, agent, candidate)
		if err != nil {
			continue
		}
		packet, err := agentpacket.DecodeJSON(resolved.Card)
		if err != nil {
			return Route{}, ErrRefused
		}
		parsed, err := agentpacketseal.DecodeKeyCard(packet.Payload)
		if err != nil {
			return Route{}, ErrRefused
		}
		if route.CardPacket == nil || parsed.NotBeforeUnix > chosen.NotBeforeUnix || (parsed.NotBeforeUnix == chosen.NotBeforeUnix && bytes.Compare(parsed.KeyID[:], chosen.KeyID[:]) > 0) {
			chosen = parsed
			route = Route{HintRecord: bytes.Clone(raw), CardPacket: bytes.Clone(resolved.Card)}
		}
	}
	if route.CardPacket == nil {
		return Route{}, ErrNoRoute
	}
	// Card verification can block. Do not renew the hint pass from its return time.
	now := r.lane.config.Now()
	if !now.Before(hint.FreshUntil) || now.Unix() < 0 || uint64(now.Unix()) >= hint.Record.Hint.ExpiresAt || uint64(now.Unix()) >= hint.Record.Hint.Delegation.NotAfter {
		return Route{}, ErrNoRoute
	}
	return route, nil
}

func (r *Resolver) load(agent string) (peerHints, error) {
	var p peerHints
	e := r.store.read(routingName(agent), &p)
	if errors.Is(e, os.ErrNotExist) {
		return peerHints{Agent: agent, Records: [][]byte{}, Cards: map[string][]byte{}, LastRelays: []string{}}, nil
	}
	if e != nil || p.Agent != agent || p.Cards == nil || len(p.Cards) != len(p.Records) || len(p.Cards) > 4 || len(p.Records) > 4 || len(p.LastRelays) > 16 {
		return p, ErrStorage
	}
	for _, u := range p.LastRelays {
		if !validRelays([]string{u}) {
			return p, ErrStorage
		}
	}
	for _, raw := range p.Records {
		h, e := agenttransport.DecodeHintRecord(raw)
		card, cardErr := agentpacket.DecodeJSON(p.Cards[cacheKey(raw)])
		if e != nil || cardErr != nil || card.SenderAgentID != agent || h.Hint.Delegation.AgentID() != agent {
			return p, ErrStorage
		}
	}
	return p, nil
}
func hintNewer(a, b []byte) bool {
	aa, ea := agenttransport.DecodeHintRecord(a)
	bb, eb := agenttransport.DecodeHintRecord(b)
	if ea != nil || eb != nil {
		return false
	}
	if order, err := agenttransport.CompareHints(aa.Hint, bb.Hint); err == nil {
		return order > 0
	}
	// Independent delegations have no freshness ordering. Digest order is only
	// deterministic iteration; the needed lane and card are verified separately.
	ad, ea := aa.Hint.Delegation.Encode()
	bd, eb := bb.Hint.Delegation.Encode()
	if ea != nil || eb != nil {
		return false
	}
	ah, bh := sha256.Sum256(ad), sha256.Sum256(bd)
	return bytes.Compare(ah[:], bh[:]) > 0
}
func cacheKey(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func (r *Resolver) remember(ctx context.Context, agent string, route Route) error {
	raw := route.HintRecord
	if e := r.store.lock(ctx); e != nil {
		return e
	}
	defer r.store.unlock()
	p, e := r.load(agent)
	if e != nil {
		return e
	}
	h, e := agenttransport.DecodeHintRecord(raw)
	if e != nil {
		return ErrRefused
	}
	d, e := h.Hint.Delegation.Encode()
	if e != nil {
		return ErrRefused
	}
	digest := sha256.Sum256(d)
	kept := [][]byte{bytes.Clone(raw)}
	for _, old := range p.Records {
		record, e := agenttransport.DecodeHintRecord(old)
		if e != nil {
			return ErrStorage
		}
		b, e := record.Hint.Delegation.Encode()
		if e != nil {
			return ErrStorage
		}
		if sha256.Sum256(b) == digest {
			if hintNewer(old, raw) {
				kept[0] = old
			}
			continue
		}
		kept = append(kept, old)
	}
	// Admit the selected delegation first; unrelated stale slots cannot evict it.
	if len(kept) > 4 {
		kept = kept[:4]
	}
	cards := map[string][]byte{}
	for _, record := range kept {
		key := cacheKey(record)
		if bytes.Equal(record, raw) {
			cards[key] = bytes.Clone(route.CardPacket)
		} else {
			cards[key] = bytes.Clone(p.Cards[key])
		}
	}
	p.Cards = cards
	p.Records = kept
	for _, u := range h.Hint.Relays {
		found := false
		for _, old := range p.LastRelays {
			found = found || old == u
		}
		if !found {
			p.LastRelays = append(p.LastRelays, u)
		}
	}
	if len(p.LastRelays) > 16 {
		p.LastRelays = p.LastRelays[len(p.LastRelays)-16:]
	}
	now, e := r.lane.now()
	if e != nil {
		return e
	}
	p.Touched = now
	// The cache is expendable; evict the oldest peer only at its peer bound.
	index, e := r.store.index()
	if e != nil {
		return e
	}
	if len(index.Names) >= MaxRoutingRecords {
		var existing peerHints
		if errors.Is(r.store.read(routingName(agent), &existing), os.ErrNotExist) {
			oldest := ""
			var at uint64
			for _, name := range index.Names {
				var candidate peerHints
				if r.store.read(name, &candidate) != nil {
					return ErrStorage
				}
				if oldest == "" || candidate.Touched < at {
					oldest, at = name, candidate.Touched
				}
			}
			if e = r.store.remove(oldest); e != nil {
				return e
			}
		}
	}
	return r.store.write(routingName(agent), p)
}

// Resolve implements only steps 1..3. Contact data is a hint candidate, never a
// relay URL fallback. Both directory indexes are queried even after one answers.
func (r *Resolver) Resolve(ctx context.Context, agent string, contact Route) (Route, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*CallTimeout)
	defer cancel()
	if _, e := parsePeer(agent); e != nil {
		return Route{}, e
	}
	if e := r.store.lock(ctx); e != nil {
		return Route{}, e
	}
	p, e := r.load(agent)
	r.store.unlock()
	if e != nil {
		return Route{}, e
	}
	sort.Slice(p.Records, func(i, j int) bool { return hintNewer(p.Records[i], p.Records[j]) })
	for _, raw := range p.Records {
		if route, e := r.verify(ctx, agent, raw, p.Cards[cacheKey(raw)], contact.CardPacket); e == nil {
			if !bytes.Equal(route.CardPacket, p.Cards[cacheKey(raw)]) {
				if e = r.remember(ctx, agent, route); e != nil {
					return Route{}, e
				}
			}
			return route, nil
		}
	}
	if route, e := r.verify(ctx, agent, contact.HintRecord, contact.CardPacket); e == nil {
		if e = r.remember(ctx, agent, route); e != nil {
			return Route{}, e
		}
		return route, nil
	}
	merged := [][]byte{}
	queried := map[string]bool{}
	fetch := func(urls []string) {
		for _, url := range urls {
			if ctx.Err() != nil {
				return
			}
			if queried[url] {
				continue
			}
			queried[url] = true
			call, cancel := context.WithTimeout(ctx, CallTimeout)
			client, e := r.config.Directory(url)
			if e == nil {
				var entries []agentpacketrelay.HintIndexEntry
				entries, e = client.HintIndex(call, agent)
				if e == nil && len(entries) <= 4 {
					for _, entry := range entries {
						raw, e := client.HintRecord(call, agent, entry.Digest)
						if e == nil {
							record, e := agenttransport.DecodeHintRecord(raw)
							if e != nil {
								continue
							}
							d, e := record.Hint.Delegation.Encode()
							if e != nil || sha256.Sum256(d) != entry.Digest || record.Hint.IssuedAt != entry.IssuedAt || len(raw) != int(entry.Length) {
								continue
							}
							merged = append(merged, raw)
						}
					}
				}
			}
			cancel()
		}
	}
	fetch(p.LastRelays)
	// Do not stop at the first directory: merge their independently ordered sets.
	fetch(r.config.Directories)
	sort.Slice(merged, func(i, j int) bool { return hintNewer(merged[i], merged[j]) })
	for _, raw := range merged {
		if route, e := r.verify(ctx, agent, raw, contact.CardPacket); e == nil {
			if e = r.remember(ctx, agent, route); e != nil {
				return Route{}, e
			}
			return route, nil
		}
	}
	return Route{}, ErrNoRoute
}
func parsePeer(agent string) ([32]byte, error) { return agentpacketseal.AgentDigest(agent) }
