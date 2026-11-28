package agentcarrier

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

const MaxWithdrawals = 148
const initialRetry = uint16(30)
const maximumRetry = uint16(600)

type relayRetry struct {
	URL     string `json:"url"`
	After   uint64 `json:"after"`
	Backoff uint16 `json:"backoff"`
}
type withdrawal struct {
	Number uint32   `json:"number"`
	Secret [32]byte `json:"secret"`
	Relays []string `json:"relays"`
	Until  uint64   `json:"until"`
}
type schedule struct {
	ID                 string       `json:"id"`
	Packet             [32]byte     `json:"packet"`
	Generation         uint32       `json:"generation"`
	NextGeneration     uint64       `json:"next_generation"`
	ResolveAfter       uint64       `json:"resolve_after"`
	ResolveBackoff     uint16       `json:"resolve_backoff"`
	ResolvedGeneration uint64       `json:"resolved_generation"`
	TTL                uint64       `json:"ttl"`
	Targets            []relayRetry `json:"targets"`
	Withdrawals        []withdrawal `json:"withdrawals"`
}
type Scheduler struct {
	lane     *Lane
	resolver *Resolver
	store    *routingStore
	gate     gate
}
type CarriageView struct {
	State, Code             string
	Copies                  int
	TTLSeconds, NextAttempt uint64
}

func OpenScheduler(l *Lane, r *Resolver) (*Scheduler, error) {
	if l == nil || r == nil || r.lane != l {
		return nil, ErrConfig
	}
	s, e := openRoutingStore(filepath.Join(l.config.StateDir, "scheduler-"+string(l.config.Kind)), l.identity())
	if e != nil {
		return nil, e
	}
	return &Scheduler{l, r, s, make(gate, 1)}, nil
}
func (s *Scheduler) Close() error { return s.store.Close() }
func (s *Scheduler) load(r delivery) (schedule, error) {
	var m schedule
	e := s.store.read(routingName(r.ID), &m)
	if errors.Is(e, os.ErrNotExist) {
		return schedule{ID: r.ID, Packet: sha256.Sum256(r.Packet), ResolveBackoff: initialRetry, TTL: 86400, Targets: []relayRetry{}, Withdrawals: []withdrawal{}}, nil
	}
	if e != nil || m.ID != r.ID || m.Packet != sha256.Sum256(r.Packet) || m.ResolveBackoff < 30 || m.ResolveBackoff > 600 || m.TTL == 0 || m.TTL > 86400 || m.Targets == nil || m.Withdrawals == nil || len(m.Targets) > MaxTargets || len(m.Withdrawals) > MaxWithdrawals {
		return m, ErrStorage
	}
	seen := map[string]bool{}
	for _, t := range m.Targets {
		if !validRelays([]string{t.URL}) || seen[t.URL] || t.Backoff < 30 || t.Backoff > 600 {
			return m, ErrStorage
		}
		seen[t.URL] = true
	}
	for _, w := range m.Withdrawals {
		if w.Number == 0 || w.Secret == ([32]byte{}) || len(w.Relays) > MaxTargets {
			return m, ErrStorage
		}
		for _, url := range w.Relays {
			if !validRelays([]string{url}) {
				return m, ErrStorage
			}
		}
	}
	return m, nil
}
func (s *Scheduler) save(m schedule) error { return s.store.write(routingName(m.ID), m) }
func (s *Scheduler) snapshot(ctx context.Context, id string) (delivery, error) {
	if e := s.lane.out.lock(ctx); e != nil {
		return delivery{}, e
	}
	defer s.lane.out.unlock()
	return s.lane.readDelivery(deliveryName(id))
}
func copies(r delivery) int {
	if len(r.Generations) == 0 {
		return 0
	}
	n := 0
	for _, t := range r.Generations[len(r.Generations)-1].Targets {
		if t.State == "accepted" {
			n++
		}
	}
	return n
}
func due(created, ttl uint64) uint64 { return created + max(uint64(600), ttl*4/5) }
func (s *Scheduler) compact(r *delivery, m *schedule, all bool, now uint64) error {
	keptWithdrawals := []withdrawal{}
	for _, w := range m.Withdrawals {
		if w.Until > now {
			keptWithdrawals = append(keptWithdrawals, w)
		}
	}
	m.Withdrawals = keptWithdrawals
	keep := len(r.Generations) - 1
	if all {
		keep = len(r.Generations)
	}
	for i := 0; i < keep; i++ {
		g := r.Generations[i]
		header, e := agentpacketseal.ParseEnvelope(g.Envelope)
		if e != nil {
			return ErrStorage
		}
		if header.ExpiresAtUnix <= now {
			continue
		}
		exists := false
		for _, w := range m.Withdrawals {
			exists = exists || w.Number == g.Number
		}
		if exists {
			continue
		}
		urls := []string{}
		for _, t := range g.Targets {
			if !slices.Contains(urls, t.URL) {
				urls = append(urls, t.URL)
			}
		}
		if len(urls) > 0 {
			m.Withdrawals = append(m.Withdrawals, withdrawal{g.Number, g.Secret, urls, header.ExpiresAtUnix})
		}
	}
	if len(m.Withdrawals) > MaxWithdrawals {
		return ErrCapacity
	}
	// The compact withdrawal journal is durable before full generations retire.
	if e := s.save(*m); e != nil {
		return e
	}
	for _, g := range r.Generations {
		r.GenerationCounter = max(r.GenerationCounter, g.Number)
	}
	if all {
		r.Generations = []generation{}
	} else if len(r.Generations) > 1 {
		r.Generations = r.Generations[len(r.Generations)-1:]
	}
	return nil
}
func (s *Scheduler) withdraw(ctx context.Context, r delivery, m *schedule, now uint64) error {
	if copies(r) < 2 && r.State != "complete" && r.State != "abandoned" {
		return nil
	}
	p, e := packet(r.Packet)
	if e != nil {
		return ErrStorage
	}
	kept := []withdrawal{}
	budget := 16
	for _, w := range m.Withdrawals {
		if w.Until <= now {
			continue
		}
		remaining := []string{}
		for _, url := range w.Relays {
			if budget == 0 {
				remaining = append(remaining, url)
				continue
			}
			budget--
			client, e := s.lane.config.Relay(url)
			if e == nil {
				e = client.Acknowledge(ctx, p.RecipientAgentID, w.Secret)
			}
			if e != nil {
				remaining = append(remaining, url)
			}
		}
		if len(remaining) > 0 {
			w.Relays = remaining
			kept = append(kept, w)
		}
	}
	m.Withdrawals = kept
	return s.save(*m)
}

// Advance makes at most one bounded pass. A runtime calls it when NextAttempt is
// due; wall-clock sleeps and route backoff never hold the outbox lock.
func (s *Scheduler) Advance(ctx context.Context, id string, contact Route) (CarriageView, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*CallTimeout)
	defer cancel()
	if e := s.gate.lock(ctx); e != nil {
		return CarriageView{}, e
	}
	defer s.gate.unlock()
	r, e := s.snapshot(ctx, id)
	if e != nil {
		return CarriageView{}, e
	}
	m, e := s.load(r)
	if e != nil {
		return CarriageView{}, e
	}
	now, e := s.lane.now()
	if e != nil {
		return CarriageView{}, e
	}
	if r.State == "complete" || r.State == "abandoned" || now >= r.Deadline {
		if e = s.lane.out.lock(ctx); e != nil {
			return CarriageView{}, e
		}
		r, e = s.lane.readDelivery(deliveryName(id))
		if e == nil {
			if now >= r.Deadline && r.State != "complete" {
				r.State = "abandoned"
				r.Code = "retention-exceeded"
			}
			e = s.compact(&r, &m, true, now)
			if e == nil {
				e = s.lane.disk.write(deliveryName(id), r)
			}
		}
		s.lane.out.unlock()
		if e != nil {
			return CarriageView{}, e
		}
		e = s.withdraw(ctx, r, &m, now)
		return CarriageView{State: r.State, Code: r.Code}, e
	}
	if len(r.Generations) > 0 && m.Generation != r.Generations[len(r.Generations)-1].Number {
		g := r.Generations[len(r.Generations)-1]
		m.Generation = g.Number
		m.Targets = []relayRetry{}
		m.NextGeneration = due(g.Created, m.TTL)
	}
	generationDue := m.NextGeneration == 0 || now >= m.NextGeneration
	forced := generationDue && m.ResolvedGeneration != m.NextGeneration
	if now < m.ResolveAfter && !forced {
		return carriage(r, m, now), nil
	}
	// Reserve the resolution attempt before asking any source. Crashes cannot
	// reset backoff to zero, and a due generation overrides a later retry time.
	if generationDue {
		m.ResolvedGeneration = m.NextGeneration
	}
	m.ResolveAfter = now + uint64(m.ResolveBackoff)
	m.ResolveBackoff = min(maximumRetry, m.ResolveBackoff*2)
	if e = s.save(m); e != nil {
		return CarriageView{}, e
	}
	p, e := packet(r.Packet)
	if e != nil {
		return CarriageView{}, ErrStorage
	}
	route, e := s.resolver.Resolve(ctx, p.RecipientAgentID, contact)
	if e != nil {
		if !errors.Is(e, ErrNoRoute) && !errors.Is(e, ErrUnavailable) && !errors.Is(e, ErrPeerRevoked) {
			return CarriageView{}, e
		}
		if m.NextGeneration == 0 || now >= m.NextGeneration {
			m.NextGeneration = now + 600
		}
		if e = s.save(m); e != nil {
			return CarriageView{}, e
		}
		if e = s.lane.out.lock(ctx); e != nil {
			return CarriageView{}, e
		}
		r, e = s.lane.readDelivery(deliveryName(id))
		if e == nil && r.State != "complete" && r.State != "abandoned" {
			r.Code = "no-route"
			e = s.lane.disk.write(deliveryName(id), r)
		}
		s.lane.out.unlock()
		if e != nil {
			return CarriageView{}, e
		}
		return CarriageView{State: r.State, Code: "no-route", Copies: copies(r), NextAttempt: min(m.ResolveAfter, m.NextGeneration)}, nil
	}
	m.ResolveAfter = 0
	m.ResolveBackoff = initialRetry
	if e = s.lane.out.lock(ctx); e != nil {
		return CarriageView{}, e
	}
	r, e = s.lane.readDelivery(deliveryName(id))
	if e == nil && r.State != "complete" && r.State != "abandoned" {
		r.Code = ""
		e = s.lane.disk.write(deliveryName(id), r)
	}
	s.lane.out.unlock()
	if e != nil {
		return CarriageView{}, e
	}
	h, e := agenttransport.DecodeHintRecord(route.HintRecord)
	if e != nil {
		return CarriageView{}, ErrRefused
	}
	ttl := uint64(86400)
	for _, url := range h.Hint.Relays {
		client, err := s.lane.config.Relay(url)
		if err == nil {
			description, err := client.Describe(ctx)
			if err == nil && description.MaxTTLSeconds > 0 && description.MaxTTLSeconds <= 86400 {
				ttl = min(ttl, description.MaxTTLSeconds)
			}
		}
	}
	m.TTL = ttl
	if generationDue && len(r.Generations) > 0 {
		resolved, e := s.lane.verifiedRoute(ctx, p.RecipientAgentID, route)
		if e != nil {
			return CarriageView{}, e
		}
		if e = s.lane.out.lock(ctx); e != nil {
			return CarriageView{}, e
		}
		r, e = s.lane.readDelivery(deliveryName(id))
		if e == nil && r.State != "complete" && r.State != "abandoned" {
			e = s.compact(&r, &m, true, now)
			if e == nil {
				e = s.lane.seal(&r, route, resolved.Key, now)
				if e == nil {
					m.Targets = []relayRetry{}
					m.Generation = r.Generations[len(r.Generations)-1].Number
				}
			}
		}
		s.lane.out.unlock()
		if e != nil {
			return CarriageView{}, e
		}
	}
	for index, url := range h.Hint.Relays {
		r, e = s.snapshot(ctx, id)
		if e != nil {
			return CarriageView{}, e
		}
		if r.State == "complete" || r.State == "abandoned" || copies(r) >= 2 {
			break
		}
		if len(r.Generations) > 0 {
			g := r.Generations[len(r.Generations)-1]
			skip := false
			for _, t := range g.Targets {
				if t.URL == url && (t.State == "accepted" || t.State == "abandoned" || t.State == "conflict") {
					skip = true
				}
			}
			if skip {
				continue
			}
		}
		position := -1
		for i, t := range m.Targets {
			if t.URL == url {
				position = i
				break
			}
		}
		if position < 0 {
			if len(m.Targets) >= MaxTargets {
				return CarriageView{}, ErrCapacity
			}
			m.Targets = append(m.Targets, relayRetry{URL: url, Backoff: initialRetry})
			position = len(m.Targets) - 1
		}
		retry := &m.Targets[position]
		now, e = s.lane.now()
		if e != nil {
			return CarriageView{}, e
		}
		if now < retry.After {
			continue
		}
		retry.After = now + uint64(retry.Backoff)
		retry.Backoff = min(maximumRetry, retry.Backoff*2)
		if e = s.save(m); e != nil {
			return CarriageView{}, e
		}
		result, err := s.lane.Attempt(ctx, id, route, index)
		if errors.Is(err, ErrStorage) {
			return CarriageView{}, err
		}
		if result.RetryAfterSeconds > 0 {
			retry.After = max(retry.After, now+uint64(result.RetryAfterSeconds))
		}
		if e = s.save(m); e != nil {
			return CarriageView{}, e
		}
	}
	r, e = s.snapshot(ctx, id)
	if e != nil {
		return CarriageView{}, e
	}
	if len(r.Generations) > 0 {
		g := r.Generations[len(r.Generations)-1]
		if m.Generation != g.Number {
			m.Generation = g.Number
		}
		m.NextGeneration = due(g.Created, m.TTL)
	}
	m.ResolveAfter = nextCarriageAttempt(r, m, now)
	if e = s.save(m); e != nil {
		return CarriageView{}, e
	}
	if e = s.withdraw(ctx, r, &m, now); e != nil {
		return CarriageView{}, e
	}
	return carriage(r, m, now), nil
}
func nextCarriageAttempt(r delivery, m schedule, now uint64) uint64 {
	next := m.NextGeneration
	done := map[string]bool{}
	if len(r.Generations) > 0 {
		for _, t := range r.Generations[len(r.Generations)-1].Targets {
			done[t.URL] = t.State == "accepted" || t.State == "conflict" || t.State == "abandoned"
		}
	}
	if copies(r) < 2 {
		for _, retry := range m.Targets {
			if !done[retry.URL] && retry.After > now {
				next = min(next, retry.After)
			}
		}
	}
	return next
}
func carriage(r delivery, m schedule, now uint64) CarriageView {
	view := CarriageView{State: r.State, Code: r.Code, Copies: copies(r), TTLSeconds: m.TTL, NextAttempt: nextCarriageAttempt(r, m, now)}
	if view.Code == "" {
		if view.Copies == 1 {
			view.Code = "single-copy"
		} else if view.Copies == 0 {
			view.Code = "carrier-unavailable"
		}
	}
	return view
}
