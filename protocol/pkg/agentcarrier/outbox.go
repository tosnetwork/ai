package agentcarrier

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"math"
	"os"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

const MaxGenerations = 4
const MaxTargets = 16

type target struct {
	URL      string `json:"url"`
	State    string `json:"state"`
	Attempts uint32 `json:"attempts"`
}
type generation struct {
	Number   uint32   `json:"number"`
	Created  uint64   `json:"created"`
	Envelope []byte   `json:"envelope"`
	Secret   [32]byte `json:"secret"`
	Card     []byte   `json:"card"`
	Hint     []byte   `json:"hint"`
	Targets  []target `json:"targets"`
	Stopped  bool     `json:"stopped"`
}
type delivery struct {
	Identity identity `json:"identity"`
	ID       string   `json:"id"`
	Packet   []byte   `json:"packet"`
	Deadline uint64   `json:"deadline"`
	State    string   `json:"state"`
	Code     string   `json:"code"`
	// Reserved for PR9's no-route schedule. Part 1 never advances these fields.
	GenerationCounter uint32       `json:"generation_counter"`
	ResolveAfter      uint64       `json:"resolve_after"`
	ResolveBackoff    uint16       `json:"resolve_backoff"`
	Generations       []generation `json:"generations"`
}

func packet(raw []byte) (agentpacket.Packet, error) {
	if len(raw) == 0 || len(raw) > MaxPacketBytes {
		return agentpacket.Packet{}, ErrRefused
	}
	var shape map[string]any
	if jsonstrict.Decode(raw, &shape) != nil {
		return agentpacket.Packet{}, ErrRefused
	}
	p, err := agentpacket.DecodeJSON(raw)
	if err != nil {
		return p, ErrRefused
	}
	return p, nil
}
func (l *Lane) readDelivery(name string) (delivery, error) {
	indexed, err := l.indexed(name)
	if err != nil || !indexed {
		return delivery{}, ErrStorage
	}
	return l.decodeDelivery(name)
}
func (l *Lane) decodeDelivery(name string) (delivery, error) {
	var r delivery
	if l.disk.read(name, &r) != nil || r.Identity != l.identity() || r.ID == "" || len(r.ID) > 128 || name != deliveryName(r.ID) || len(r.Generations) > MaxGenerations || r.Deadline == 0 || r.Deadline > math.MaxInt64-uint64(KeyRetention/time.Second) {
		return r, ErrStorage
	}
	p, err := packet(r.Packet)
	if err != nil || p.SenderAgentID != l.config.AgentID {
		return r, ErrStorage
	}
	if r.State != "pending" && r.State != "carried" && r.State != "complete" && r.State != "abandoned" {
		return r, ErrStorage
	}
	if r.Code != "" && r.Code != "no-route" && r.Code != "peer-revoked" && r.Code != "retention-exceeded" {
		return r, ErrStorage
	}
	if r.ResolveBackoff != 0 && (r.ResolveBackoff < 30 || r.ResolveBackoff > 600) {
		return r, ErrStorage
	}
	ids := map[[32]byte]bool{}
	for i, g := range r.Generations {
		h, err := agentpacketseal.ParseEnvelope(g.Envelope)
		cardPacket, cardErr := agentpacket.DecodeJSON(g.Card)
		card, decodeErr := agentpacketseal.DecodeKeyCard(cardPacket.Payload)
		hint, hintErr := agenttransport.DecodeHintRecord(g.Hint)
		if err != nil || cardErr != nil || decodeErr != nil || hintErr != nil || hint.Hint.Delegation.AgentID() != p.RecipientAgentID || cardPacket.SenderAgentID != p.RecipientAgentID || h.RecipientAgentID != p.RecipientAgentID || h.RecipientKeyID != card.KeyID || !agentpacketseal.CheckAck(h.EnvelopeID, g.Secret) || ids[h.EnvelopeID] || g.Created == 0 || h.ExpiresAtUnix <= g.Created || h.ExpiresAtUnix-g.Created > 86400 || h.ExpiresAtUnix > r.Deadline || g.Number == 0 || (i > 0 && g.Number <= r.Generations[i-1].Number) || len(g.Targets) > MaxTargets {
			return r, ErrStorage
		}
		ids[h.EnvelopeID] = true
		seen := map[string]bool{}
		for _, t := range g.Targets {
			if agentpacketseal.CheckRelayURL(t.URL) != nil || seen[t.URL] || (t.State != "pending" && t.State != "accepted" && t.State != "abandoned" && t.State != "conflict") {
				return r, ErrStorage
			}
			seen[t.URL] = true
		}
	}
	return r, nil
}

// CheckQueueCapacity reports whether the lane can fit count new entries
// at this instant. Queue repeats the bound when it writes each entry.
func (l *Lane) CheckQueueCapacity(ctx context.Context, count int) error {
	if count <= 0 {
		return ErrConfig
	}
	if err := l.out.lock(ctx); err != nil {
		return err
	}
	defer l.out.unlock()
	index, err := l.inventory()
	if err != nil {
		return err
	}
	if count > l.config.OutboxLimit-len(index.Deliveries) {
		return ErrCapacity
	}
	return nil
}

func (l *Lane) Queue(ctx context.Context, id string, raw []byte, deadline uint64) (DeliveryView, error) {
	if id == "" || len(id) > 128 {
		return DeliveryView{}, ErrConfig
	}
	if err := l.out.lock(ctx); err != nil {
		return DeliveryView{}, err
	}
	defer l.out.unlock()
	p, err := packet(raw)
	if err != nil || p.SenderAgentID != l.config.AgentID {
		return DeliveryView{}, ErrRefused
	}
	now, err := l.now()
	if err != nil {
		return DeliveryView{}, err
	}
	if deadline <= now || deadline-now > 30*86400 {
		return DeliveryView{}, ErrExpired
	}
	old, err := l.readDelivery(deliveryName(id))
	if err == nil {
		if !bytes.Equal(old.Packet, raw) || old.Deadline != deadline {
			return DeliveryView{}, ErrConflict
		}
		return view(old), nil
	}
	indexed, indexErr := l.indexed(deliveryName(id))
	if indexErr != nil || indexed {
		return DeliveryView{}, ErrStorage
	}
	// A corrupt existing record is never treated as an absent delivery.
	if _, statErr := l.disk.root.Lstat(deliveryName(id)); statErr == nil || !errors.Is(statErr, os.ErrNotExist) {
		return DeliveryView{}, ErrStorage
	}
	call, cancel := context.WithTimeout(ctx, CallTimeout)
	err = l.config.VerifyPacket(call, p)
	cancel()
	if err != nil {
		return DeliveryView{}, ErrUnavailable
	}
	names, err := l.disk.names(l.config.OutboxLimit + MaxKeys + 8)
	if err != nil {
		return DeliveryView{}, err
	}
	count := 0
	for _, n := range names {
		if strings.HasPrefix(n, "out-") {
			count++
		}
	}
	if count >= l.config.OutboxLimit {
		return DeliveryView{}, ErrCapacity
	}
	r := delivery{Identity: l.identity(), ID: id, Packet: bytes.Clone(raw), Deadline: deadline, State: "pending", Code: "no-route", Generations: []generation{}}
	fresh, timeErr := l.now()
	if timeErr != nil {
		return DeliveryView{}, timeErr
	}
	if deadline <= fresh {
		return DeliveryView{}, ErrExpired
	}
	if err = l.disk.write(deliveryName(id), r); err != nil {
		return DeliveryView{}, err
	}
	if err = l.index(ctx, deliveryName(id), true); err != nil {
		return DeliveryView{}, err
	}
	return view(r), nil
}
func view(r delivery) DeliveryView { return DeliveryView{r.State, r.Code, len(r.Generations)} }
func (l *Lane) Status(ctx context.Context, id string) (DeliveryView, error) {
	if err := l.out.lock(ctx); err != nil {
		return DeliveryView{}, err
	}
	defer l.out.unlock()
	r, err := l.readDelivery(deliveryName(id))
	return view(r), err
}

type resolvedRoute struct {
	Key             agentpacketseal.RecipientKey
	Relays          []string
	Card            []byte
	FreshUntil      time.Time
	DelegationUntil uint64
	HintUntil       uint64
}

func (l *Lane) verifiedRoute(ctx context.Context, recipient string, route Route) (resolvedRoute, error) {
	if len(route.HintRecord) == 0 {
		return resolvedRoute{}, ErrNoRoute
	}
	// Only the selected lane's cards are used here. Other objects remain opaque;
	// their consuming lane verifies them before using them as identity evidence.
	verified, err := l.config.Verifier.VerifyHint(ctx, route.HintRecord, l.config.HintPolicy)
	if err != nil {
		if errors.Is(err, agenttransport.ErrUnavailable) {
			return resolvedRoute{}, ErrUnavailable
		}
		return resolvedRoute{}, ErrPeerRevoked
	}
	if verified.Record.Hint.Delegation.AgentID() != recipient {
		return resolvedRoute{}, ErrRefused
	}
	candidates := [][]byte{}
	if len(route.CardPacket) > 0 {
		candidates = append(candidates, route.CardPacket)
	}
	kind := agenttransport.RailCard
	if l.config.Kind == Chat {
		kind = agenttransport.ChatCard
	}
	for _, object := range verified.Record.Objects {
		if object.Kind == kind {
			candidates = append(candidates, object.Bytes)
		}
	}
	result := resolvedRoute{Relays: append([]string(nil), verified.Record.Hint.Relays...), FreshUntil: verified.FreshUntil, DelegationUntil: verified.Record.Hint.Delegation.NotAfter, HintUntil: verified.Record.Hint.ExpiresAt}
	var chosen agentpacketseal.KeyCard
	transient := false
	for _, raw := range candidates {
		key, card, err := l.verifyCard(ctx, raw)
		if err != nil {
			transient = transient || !errors.Is(err, ErrRefused)
			continue
		}
		if key.AgentID != recipient {
			return resolvedRoute{}, ErrRefused
		}
		if result.Card == nil || card.NotBeforeUnix > chosen.NotBeforeUnix || (card.NotBeforeUnix == chosen.NotBeforeUnix && bytes.Compare(card.KeyID[:], chosen.KeyID[:]) > 0) {
			chosen = card
			result.Key = key
			result.Card = bytes.Clone(raw)
		}
	}
	if result.Card == nil {
		if transient {
			return resolvedRoute{}, ErrUnavailable
		}
		return resolvedRoute{}, ErrPeerRevoked
	}
	if err := result.validAt(l.config.Now()); err != nil {
		return resolvedRoute{}, err
	}
	return result, nil
}

// validAt is local: it never renews authority with another blocking read.
func (r resolvedRoute) validAt(now time.Time) error {
	if now.Unix() < 0 || !now.Before(r.FreshUntil) {
		return ErrUnavailable
	}
	if uint64(now.Unix()) >= r.DelegationUntil {
		return ErrPeerRevoked
	}
	if uint64(now.Unix()) >= r.HintUntil {
		return ErrNoRoute
	}
	return nil
}
func accepted(g generation) bool {
	for _, t := range g.Targets {
		if t.State == "accepted" {
			return true
		}
	}
	return false
}
func (l *Lane) seal(r *delivery, route Route, key agentpacketseal.RecipientKey, now uint64) error {
	kept := []generation{}
	number := r.GenerationCounter
	for _, g := range r.Generations {
		number = max(number, g.Number)
		h, err := agentpacketseal.ParseEnvelope(g.Envelope)
		if err != nil {
			return ErrStorage
		}
		if h.ExpiresAtUnix > now {
			kept = append(kept, g)
		}
	}
	if len(kept) >= MaxGenerations || number == math.MaxUint32 {
		return ErrCapacity
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return ErrUnavailable
	}
	raw, err := agentpacketseal.Seal(key, secret, r.Packet, min(r.Deadline, now+86400))
	if err != nil {
		return ErrRefused
	}
	r.GenerationCounter = number + 1
	r.Generations = append(kept, generation{Number: number + 1, Created: now, Envelope: raw, Secret: secret, Card: bytes.Clone(route.CardPacket), Hint: bytes.Clone(route.HintRecord), Targets: []target{}})
	r.Code = ""
	return l.disk.write(deliveryName(r.ID), *r)
}

// Attempt deposits at one selected relay from a re-verified hint. It does not
// resolve hints, schedule no-route retries, or run two-copy fanout. PR9 composes
// this primitive. Every attempt, including an ambiguous retry, uses disk bytes.
func (l *Lane) Attempt(ctx context.Context, id string, route Route, index int) (AttemptResult, error) {
	route.HintRecord = bytes.Clone(route.HintRecord)
	route.CardPacket = bytes.Clone(route.CardPacket)
	if err := l.out.lock(ctx); err != nil {
		return AttemptResult{}, err
	}
	defer l.out.unlock()
	r, err := l.readDelivery(deliveryName(id))
	if err != nil {
		return AttemptResult{}, err
	}
	if r.State == "complete" || r.State == "abandoned" {
		return AttemptResult{}, ErrRefused
	}
	now, err := l.now()
	if err != nil {
		return AttemptResult{}, err
	}
	if now >= r.Deadline {
		return AttemptResult{}, ErrExpired
	}
	call, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	p, err := packet(r.Packet)
	if err != nil {
		return AttemptResult{}, ErrStorage
	}
	resolved, err := l.verifiedRoute(call, p.RecipientAgentID, route)
	if err != nil {
		return AttemptResult{}, err
	}
	key, relays := resolved.Key, resolved.Relays
	route.CardPacket = resolved.Card
	if index < 0 || index >= len(relays) {
		return AttemptResult{}, ErrConfig
	}
	if len(r.Generations) == 0 {
		if err = l.seal(&r, route, key, now); err != nil {
			return AttemptResult{}, err
		}
	}
	g := &r.Generations[len(r.Generations)-1]
	header, err := agentpacketseal.ParseEnvelope(g.Envelope)
	if err != nil {
		return AttemptResult{}, ErrStorage
	}
	oldKey, oldCard, oldErr := l.verifyCard(call, g.Card)
	if oldErr != nil && !errors.Is(oldErr, ErrRefused) {
		return AttemptResult{}, ErrUnavailable
	}
	oldValid := oldErr == nil && oldKey.AgentID == p.RecipientAgentID && oldKey.KeyID == header.RecipientKeyID && agentpacketseal.CheckKeyCardTime(oldCard, l.config.Now()) == nil
	if !oldValid || header.ExpiresAtUnix <= now {
		if accepted(*g) && header.ExpiresAtUnix > now {
			g.Stopped = true
			r.Code = "peer-revoked"
			if err = l.disk.write(deliveryName(id), r); err != nil {
				return AttemptResult{}, err
			}
			return AttemptResult{}, ErrPeerRevoked
		}
		if err = l.seal(&r, route, key, now); err != nil {
			return AttemptResult{}, err
		}
		g = &r.Generations[len(r.Generations)-1]
	}
	if g.Stopped {
		return AttemptResult{}, ErrPeerRevoked
	}
	url := relays[index]
	client, err := l.config.Relay(url)
	if err != nil {
		return AttemptResult{}, ErrUnavailable
	}
	description, err := client.Describe(call)
	if err != nil || description.Schema != "tos.service.agent-packet-relay.relay.v2" || description.MaxTTLSeconds == 0 || description.MaxTTLSeconds > 86400 {
		return AttemptResult{}, ErrUnavailable
	}
	position := -1
	for i, t := range g.Targets {
		if t.URL == url {
			position = i
			break
		}
	}
	if position < 0 {
		if len(g.Targets) >= MaxTargets {
			return AttemptResult{}, ErrCapacity
		}
		g.Targets = append(g.Targets, target{URL: url, State: "pending"})
		position = len(g.Targets) - 1
	}
	t := &g.Targets[position]
	if t.State == "accepted" {
		return AttemptResult{Accepted: true, RelayTTLSeconds: description.MaxTTLSeconds}, nil
	}
	if t.State == "abandoned" || t.State == "conflict" {
		return AttemptResult{}, ErrRefused
	}
	var auth Credential
	contact := false
	if l.own(call) == nil {
		auth, contact, err = l.config.Credentials.Contact(call, p.RecipientAgentID, url)
		if err != nil {
			return AttemptResult{}, ErrUnavailable
		}
	}
	if err = l.usableContact(call, &auth, &contact, p.RecipientAgentID, url); err != nil {
		return AttemptResult{}, err
	}
	if t.Attempts == math.MaxUint32 {
		return AttemptResult{}, ErrCapacity
	}
	t.Attempts++
	g.Hint = bytes.Clone(route.HintRecord)
	// The exact envelope and attempt are durable before the transport observes it.
	if err = l.disk.write(deliveryName(id), r); err != nil {
		return AttemptResult{}, err
	}
	if contact && l.own(call) != nil {
		auth = Credential{}
		contact = false
	}
	if err = l.usableContact(call, &auth, &contact, p.RecipientAgentID, url); err != nil {
		return AttemptResult{}, err
	}
	if err = l.sendGuard(call, r, *g, route, auth, contact, url); err != nil {
		return AttemptResult{}, err
	}
	err = client.Deposit(call, bytes.Clone(g.Envelope), auth.wire, auth.holder)
	if contact && fallback(err) {
		if status(err, 403, "credential_revoked") {
			if dropErr := l.config.Credentials.DropContact(call, p.RecipientAgentID, url); dropErr != nil {
				return AttemptResult{}, ErrUnavailable
			}
		}
		if t.Attempts == math.MaxUint32 {
			return AttemptResult{}, ErrCapacity
		}
		t.Attempts++
		if writeErr := l.disk.write(deliveryName(id), r); writeErr != nil {
			return AttemptResult{}, writeErr
		}
		if guardErr := l.sendGuard(call, r, *g, route, Credential{}, false, url); guardErr != nil {
			return AttemptResult{}, guardErr
		}
		err = client.Deposit(call, bytes.Clone(g.Envelope), nil, nil)
	}
	result := AttemptResult{RelayTTLSeconds: description.MaxTTLSeconds, Code: "carrier-unavailable"}
	if delay, ok := agentpacketrelay.RetryAfter(err); ok && delay > 0 {
		result.RetryAfterSeconds = uint32(min(delay, time.Hour) / time.Second)
		if result.RetryAfterSeconds == 0 {
			result.RetryAfterSeconds = 1
		}
	}
	if status(err, 507, "") {
		result.Code = "peer-cap"
	}
	if err == nil || status(err, 410, "") {
		t.State = "accepted"
		r.State = "carried"
		result.Accepted = true
		result.Code = ""
	} else if status(err, 409, "") {
		t.State = "conflict"
		result.Code = "relay-conflict"
	} else if status(err, 422, "") || status(err, 403, "") && !status(err, 403, "credential_revoked") {
		t.State = "abandoned"
		result.Code = "relay-refused"
	}
	if writeErr := l.disk.write(deliveryName(id), r); writeErr != nil {
		return AttemptResult{}, writeErr
	}
	if !result.Accepted {
		return result, ErrUnavailable
	}
	return result, nil
}

// Recheck after local persistence too: filesystem delay must not extend a
// hint, card, credential or business deadline. The exact wire remains unchanged.
func (l *Lane) sendGuard(ctx context.Context, r delivery, g generation, route Route, auth Credential, contact bool, url string) error {
	p, err := packet(r.Packet)
	if err != nil {
		return ErrStorage
	}
	resolved, err := l.verifiedRoute(ctx, p.RecipientAgentID, route)
	if err != nil {
		return err
	}
	if _, _, err = l.verifyCard(ctx, g.Card); err != nil {
		if errors.Is(err, ErrRefused) {
			return ErrPeerRevoked
		}
		return ErrUnavailable
	}
	if l.config.VerifyDeliveryCard != nil {
		if err := l.config.VerifyDeliveryCard(ctx, p, g.Card); err != nil {
			return err
		}
	}
	h, err := agentpacketseal.ParseEnvelope(g.Envelope)
	if err != nil {
		return ErrStorage
	}
	hint, err := agenttransport.DecodeHintRecord(route.HintRecord)
	if err != nil {
		return ErrNoRoute
	}
	now, err := l.now()
	if err != nil {
		return err
	}
	if now >= r.Deadline || h.ExpiresAtUnix <= now {
		return ErrExpired
	}
	if hint.Hint.ExpiresAt <= now {
		return ErrNoRoute
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if contact {
		if err := checkCredential(auth, p.RecipientAgentID, url, agenttransport.OperationDeposit, now, nil); err != nil {
			return err
		}
	}
	return resolved.validAt(l.config.Now())
}
func (l *Lane) usableContact(ctx context.Context, auth *Credential, contact *bool, peer, url string) error {
	if !*contact {
		return nil
	}
	now, err := l.now()
	if err != nil {
		return err
	}
	c, err := agenttransport.DecodeCredential(auth.wire)
	if err != nil {
		return ErrRefused
	}
	until, err := c.NotAfter()
	if err != nil {
		return ErrRefused
	}
	if until <= now {
		if err = l.config.Credentials.DropContact(ctx, peer, url); err != nil {
			return ErrUnavailable
		}
		*auth = Credential{}
		*contact = false
		return nil
	}
	return checkCredential(*auth, peer, url, agenttransport.OperationDeposit, now, nil)
}
func status(err error, n int, code string) bool {
	var e *agentpacketrelay.StatusError
	return errors.As(err, &e) && e.StatusCode == n && (code == "" || e.Code == code)
}
func fallback(err error) bool { return status(err, 507, "") || status(err, 403, "credential_revoked") }
func checkCredential(auth Credential, agent, relay string, op agenttransport.Operation, now uint64, own []byte) error {
	c, err := agenttransport.DecodeCredential(auth.wire)
	if err != nil || c.VerifyChain() != nil {
		return ErrRefused
	}
	d, err := c.Delegation()
	if err != nil || d.AgentID() != agent {
		return ErrRefused
	}
	if own != nil {
		raw, err := c.DelegationBytes()
		if err != nil || !bytes.Equal(raw, own) {
			return ErrRefused
		}
	}
	if len(auth.holder) != 64 || c.CheckScope(now, relay, op) != nil {
		return ErrRefused
	}
	return nil
}

// Complete is called only after the lane authenticated its own delivery receipt.
// Relay acceptance alone never invokes it or claims business execution.
func (l *Lane) Complete(ctx context.Context, id string) error {
	if err := l.out.lock(ctx); err != nil {
		return err
	}
	defer l.out.unlock()
	r, err := l.readDelivery(deliveryName(id))
	if err != nil {
		return err
	}
	r.State = "complete"
	r.Code = ""
	return l.disk.write(deliveryName(id), r)
}
func (l *Lane) Prune(ctx context.Context) error {
	if err := l.out.lock(ctx); err != nil {
		return err
	}
	defer l.out.unlock()
	now, err := l.now()
	if err != nil {
		return err
	}
	names, err := l.disk.names(l.config.OutboxLimit + MaxKeys + 8)
	if err != nil {
		return err
	}
	for _, name := range names {
		if !strings.HasPrefix(name, "out-") {
			continue
		}
		r, err := l.readDelivery(name)
		if err != nil {
			return err
		}
		if now >= r.Deadline+uint64(KeyRetention/time.Second) {
			if err = l.index(ctx, name, false); err != nil {
				return err
			}
			if err = l.disk.remove(name); err != nil {
				return err
			}
		}
	}
	return nil
}
