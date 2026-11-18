package buyeragent

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

// Relay polling (MCP_BUYER_ADAPTER_V1 section 7.3; AGENT_PACKET_RELAY_V1
// sections 8.5, 8.6 and 10).
const (
	// PollInterval is how often each relay of a held key is listed; up to
	// pollJitterPercent of it is added at random.
	PollInterval      = 15 * time.Second
	pollJitterPercent = 20
	// MaxPollBackoff bounds the exponential backoff after a failed listing.
	MaxPollBackoff = 5 * time.Minute
	// MaxRetryAfter bounds how long a relay's Retry-After can hold the
	// poller back.
	MaxRetryAfter = time.Hour
	// RelayCallTimeout bounds each list, download and acknowledgement.
	RelayCallTimeout = 30 * time.Second
	// MaxEnvelopeMemory bounds each mailbox memory; an entry is forgotten
	// at its listed expiry and at the latest envelopeMemoryLifetime after
	// it was recorded. Forgetting one early costs only a repeated download.
	MaxEnvelopeMemory      = 8192
	envelopeMemoryLifetime = 24*time.Hour + 5*time.Minute
	// MaxInboundPacketJSON bounds an opened packet's JSON.
	MaxInboundPacketJSON = 128 << 10
	// MaxOpenMessages bounds the messages a purchase's inbox holds at once;
	// a frame of a further message is refused as inbox-full, left
	// unacknowledged at the relay, and taken on a later pass once the inbox
	// has room.
	MaxOpenMessages = 8
)

// InboundPurchase is what admits a frame to a purchase's inbox: the
// purchase's provider, Capability, Accepted Quote and frame binding.
type InboundPurchase struct {
	ProviderAgentID string
	CapabilityID    string
	QuoteCommitment string
	Binding         railwork.Binding
}

// PurchaseLookup finds the purchase of a request hash. Not found is a
// permanent refusal of the frame; an error is transient.
type PurchaseLookup func(requestHash string) (InboundPurchase, bool, error)

// PollView is the outcome of one polling pass.
type PollView struct {
	// Relays counts the relays listed in this pass.
	Relays int `json:"relays"`
	// Stored counts frames durably stored (a duplicate included), Refused
	// envelopes refused for good, Acknowledged acknowledgements the relays
	// accepted.
	Stored       int `json:"stored"`
	Refused      int `json:"refused"`
	Acknowledged int `json:"acknowledged"`
	// Next is when the next relay is due.
	Next time.Time `json:"next"`
}

// relayPoll is one relay's polling schedule.
type relayPoll struct {
	next    time.Time
	backoff time.Duration
}

// errInboxFull reports a frame of a further message for a purchase whose
// inbox holds MaxOpenMessages messages.
var errInboxFull = errors.New("the purchase's inbox holds the most messages it may")

// Poll runs one polling pass: every relay of every held buyer card whose
// time has come is listed, and each listed envelope is handled under
// relay 8.5:
//   - an envelope already settled here is acknowledged at this relay too;
//   - one this relay served before that could not be opened, or that names
//     a key not held, is skipped until its listed expiry;
//   - otherwise it is downloaded, opened under the held key, decoded,
//     verified against finalized state and admitted to its purchase's
//     inbox, and acknowledged only after the frame is stored durably;
//   - a packet that fails for good after a successful open is
//     acknowledged without storing, so junk does not hold the mailbox.
//
// A failed listing backs that relay off exponentially to MaxPollBackoff,
// longer when it sent Retry-After; a transient failure of one envelope
// leaves it for the next pass. Poll never stops at one failure.
func (c *Carrier) Poll(ctx context.Context, lookup PurchaseLookup) (PollView, []error) {
	view := PollView{}
	if lookup == nil {
		return view, []error{errors.New("polling needs a purchase lookup")}
	}
	keys, cards, err := c.HeldKeys()
	if err != nil {
		return view, []error{err}
	}
	held := map[[agentpacketseal.KeyIDSize]byte]agentpacketseal.PrivateKey{}
	listed := map[string]bool{}
	for index, key := range keys {
		held[key.KeyID] = key
		for _, relay := range cards[index].Relays {
			listed[relay] = true
		}
	}
	relays := make([]string, 0, len(listed))
	for relay := range listed {
		relays = append(relays, relay)
	}
	sort.Strings(relays)
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	for relay := range c.poll {
		if !listed[relay] {
			delete(c.poll, relay)
		}
	}
	var failures []error
	now := c.config.Now()
	for _, relay := range relays {
		state := c.poll[relay]
		if state == nil {
			state = &relayPoll{}
			c.poll[relay] = state
		}
		if now.Before(state.next) {
			continue
		}
		view.Relays++
		entryFailures, err := c.pollRelay(ctx, relay, held, lookup, &view)
		failures = append(failures, entryFailures...)
		if err != nil {
			failures = append(failures, fmt.Errorf("relay %s: %w", relay, err))
			state.backoff = nextBackoff(state.backoff, err)
			state.next = now.Add(state.backoff)
			continue
		}
		state.backoff = 0
		delay, err := c.pollDelay()
		if err != nil {
			failures = append(failures, err)
			delay = PollInterval
		}
		state.next = now.Add(delay)
	}
	for _, state := range c.poll {
		if view.Next.IsZero() || state.next.Before(view.Next) {
			view.Next = state.next
		}
	}
	if view.Next.IsZero() {
		view.Next = now.Add(PollInterval)
	}
	return view, failures
}

// RunPoll polls until ctx ends, each pass when the next relay is due and
// at least every PollInterval; report receives each pass's failures. It
// needs no MCP session.
func (c *Carrier) RunPoll(ctx context.Context, lookup PurchaseLookup, report func([]error)) {
	for {
		view, failures := c.Poll(ctx, lookup)
		if len(failures) != 0 && report != nil {
			report(failures)
		}
		wait := view.Next.Sub(c.config.Now())
		if wait < time.Second {
			wait = time.Second
		}
		if wait > PollInterval {
			wait = PollInterval
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// nextBackoff doubles the backoff from twice PollInterval up to
// MaxPollBackoff, and waits at least the relay's Retry-After, at most
// MaxRetryAfter.
func nextBackoff(previous time.Duration, err error) time.Duration {
	backoff := 2 * PollInterval
	if previous > 0 {
		backoff = 2 * previous
	}
	if backoff > MaxPollBackoff {
		backoff = MaxPollBackoff
	}
	if after, ok := agentpacketrelay.RetryAfter(err); ok && after > backoff {
		backoff = min(after, MaxRetryAfter)
	}
	return backoff
}

// pollDelay is PollInterval plus up to pollJitterPercent of it at random.
func (c *Carrier) pollDelay() (time.Duration, error) {
	var raw [8]byte
	if err := c.config.Random(raw[:]); err != nil {
		return 0, err
	}
	span := uint64(PollInterval) * pollJitterPercent / 100
	return PollInterval + time.Duration(binary.BigEndian.Uint64(raw[:])%(span+1)), nil
}

// pollRelay lists one relay and handles every listed envelope. The error
// is the listing's; the failures are those of single envelopes.
func (c *Carrier) pollRelay(ctx context.Context, relay string, held map[[agentpacketseal.KeyIDSize]byte]agentpacketseal.PrivateKey,
	lookup PurchaseLookup, view *PollView) ([]error, error) {
	client, err := c.config.RelayClient(relay)
	if err != nil {
		return nil, err
	}
	call, cancel := context.WithTimeout(ctx, RelayCallTimeout)
	mailbox, err := client.List(call, c.config.BuyerAgentID)
	cancel()
	if err != nil {
		return nil, err
	}
	if mailbox.AgentID != c.config.BuyerAgentID {
		return nil, errors.New("the relay listed another Agent's mailbox")
	}
	var failures []error
	for _, entry := range mailbox.Envelopes {
		if err := c.receiveEnvelope(ctx, client, relay, entry, held, lookup, view); err != nil {
			failures = append(failures, fmt.Errorf("relay %s envelope %x: %w", relay, entry.EnvelopeID, err))
		}
	}
	return failures, nil
}

// receiveEnvelope handles one listed envelope under relay 8.5. A returned
// error is transient: the envelope is left for the next pass.
func (c *Carrier) receiveEnvelope(ctx context.Context, client RelayClient, relay string, entry agentpacketrelay.MailboxEntry,
	held map[[agentpacketseal.KeyIDSize]byte]agentpacketseal.PrivateKey, lookup PurchaseLookup, view *PollView) error {
	now := c.config.Now()
	forget := time.Unix(int64(entry.ExpiresAtUnix), 0)
	if latest := now.Add(envelopeMemoryLifetime); forget.After(latest) || entry.ExpiresAtUnix > uint64(1)<<62 {
		forget = latest
	}
	id := hex.EncodeToString(entry.EnvelopeID[:])
	if secret, settled := c.settled.get(id, now); settled {
		// Settled at another relay, or acknowledged here before: the
		// acknowledgement goes to every relay that lists the ID.
		return c.acknowledge(ctx, client, entry.EnvelopeID, secret, view)
	}
	servedHere := relay + " " + id
	if _, refused := c.refused.get(servedHere, now); refused {
		return nil
	}
	key, ok := held[entry.RecipientKeyID]
	if !ok {
		// A key never issued or already destroyed (relay 6.5).
		c.refused.put(servedHere, [agentpacketseal.AckSecretSize]byte{}, forget, now)
		return nil
	}
	call, cancel := context.WithTimeout(ctx, RelayCallTimeout)
	raw, err := client.Download(call, c.config.BuyerAgentID, entry.EnvelopeID)
	cancel()
	if err != nil {
		return err
	}
	opened, err := agentpacketseal.Open(key, raw)
	if err != nil || opened.Header.EnvelopeID != entry.EnvelopeID {
		// Steps 1 to 3: not this key's, corrupt, or other bytes than the
		// listed ID. The secret cannot be trusted, so it is never
		// acknowledged; the memory is per relay (8.6).
		c.refused.put(servedHere, [agentpacketseal.AckSecretSize]byte{}, forget, now)
		view.Refused++
		return nil
	}
	if err := c.admitPacket(ctx, opened, lookup); err != nil {
		if !isPermanent(err) {
			return err
		}
		view.Refused++
	} else {
		view.Stored++
	}
	// Stored durably, or refused for good after a successful open: the
	// recovered secret matches the ID, so the envelope is acknowledged.
	c.settled.put(id, opened.AckSecret, forget, now)
	return c.acknowledge(ctx, client, entry.EnvelopeID, opened.AckSecret, view)
}

func (c *Carrier) acknowledge(ctx context.Context, client RelayClient, envelopeID [32]byte,
	secret [agentpacketseal.AckSecretSize]byte, view *PollView) error {
	call, cancel := context.WithTimeout(ctx, RelayCallTimeout)
	defer cancel()
	if err := client.Ack(call, c.config.BuyerAgentID, envelopeID, secret); err != nil {
		return err
	}
	view.Acknowledged++
	return nil
}

// permanentError marks a packet refused for good (relay 8.5 steps 4 and 5).
type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

func permanent(err error) error { return permanentError{err: err} }

func isPermanent(err error) bool {
	var target permanentError
	return errors.As(err, &target)
}

// admitPacket runs relay 8.5 steps 4 to 6 on an opened envelope and the
// buyer's own admission of a result frame: the packet decodes within its
// bound, names this buyer, verifies against finalized state, carries a
// rail result frame of a purchase this buyer holds from that purchase's
// provider for its binding, Capability and Accepted Quote, and is stored
// durably. A permanent error refuses the packet for good.
func (c *Carrier) admitPacket(ctx context.Context, opened agentpacketseal.Opened, lookup PurchaseLookup) error {
	if len(opened.PacketJSON) > MaxInboundPacketJSON {
		return permanent(errors.New("the packet is over its bound"))
	}
	packet, err := agentpacket.DecodeJSON(opened.PacketJSON)
	if err != nil {
		return permanent(err)
	}
	// Open already required the envelope's recipient to be this buyer.
	if packet.RecipientAgentID != c.config.BuyerAgentID {
		return permanent(errors.New("the packet is addressed to another Agent"))
	}
	if err := c.config.Cards.VerifyPacket(ctx, c.config.Verifier, packet); err != nil {
		if errors.Is(err, buyersdk.ErrPacketRefused) {
			return permanent(err)
		}
		return err
	}
	frame, err := railwork.DecodeFrame(packet.Payload)
	if err != nil {
		return permanent(err)
	}
	requestHash := hex.EncodeToString(frame.Binding.RequestHash[:])
	purchase, found, err := lookup(requestHash)
	if err != nil {
		return err
	}
	if !found {
		return permanent(errors.New("the frame names no purchase of this buyer"))
	}
	if frame.Kind != railwork.KindResult || packet.SenderAgentID != purchase.ProviderAgentID || frame.Binding != purchase.Binding {
		return permanent(errors.New("the frame is not a result from the purchase's provider for its request"))
	}
	if err := railwork.CheckPacketFields(packet.CapabilityID, packet.QuoteCommitment, purchase.CapabilityID,
		purchase.QuoteCommitment, railwork.RefusalResultNotAccepted); err != nil {
		return permanent(err)
	}
	if err := c.storeFrame(requestHash, frame, packet.Payload); err != nil {
		// A full inbox is transient: the envelope stays unacknowledged at
		// the relay and is taken on a later pass once the inbox has room.
		if errors.Is(err, railwork.ErrFrameConflict) {
			return permanent(err)
		}
		return err
	}
	return nil
}

func (c *Carrier) inboxDir(requestHash string) string {
	return filepath.Join(c.config.StateDir, "inbox", requestHash)
}

var messageDirPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// storeFrame stores one admitted frame durably under its message digest.
// The same bytes again are a duplicate and succeed; other bytes for a held
// index are a frame conflict.
func (c *Carrier) storeFrame(requestHash string, frame railwork.Frame, raw []byte) error {
	inbox := c.inboxDir(requestHash)
	if err := makePrivateDir(inbox); err != nil {
		return err
	}
	message := filepath.Join(inbox, hex.EncodeToString(frame.MessageDigest[:]))
	if _, err := os.Lstat(message); errors.Is(err, os.ErrNotExist) {
		held, err := c.inboxMessages(requestHash)
		if err != nil {
			return err
		}
		if len(held) >= MaxOpenMessages {
			return errInboxFull
		}
	}
	if err := makePrivateDir(message); err != nil {
		return err
	}
	path := filepath.Join(message, fmt.Sprintf("%02d.frame", frame.Index))
	existing, err := readPrivate(path)
	if err == nil {
		if !bytes.Equal(existing, raw) {
			return railwork.ErrFrameConflict
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writePrivate(path, raw, true)
}

// inboxMessages lists the message directories of a purchase's inbox.
func (c *Carrier) inboxMessages(requestHash string) ([]string, error) {
	entries, err := os.ReadDir(c.inboxDir(requestHash))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, entry := range entries {
		if entry.IsDir() && messageDirPattern.MatchString(entry.Name()) {
			out = append(out, entry.Name())
		}
	}
	return out, nil
}

// makePrivateDir creates an owner-only directory, or checks an existing
// one.
func makePrivateDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return checkPrivateDir(path)
}

// envelopeMemory remembers envelope keys until an expiry, with a bound:
// when full, the entry expiring first is forgotten.
type envelopeMemory struct {
	mu      sync.Mutex
	max     int
	entries map[string]memoryEntry
}

type memoryEntry struct {
	forget time.Time
	secret [agentpacketseal.AckSecretSize]byte
}

func newEnvelopeMemory(max int) *envelopeMemory {
	return &envelopeMemory{max: max, entries: map[string]memoryEntry{}}
}

func (m *envelopeMemory) get(key string, now time.Time) ([agentpacketseal.AckSecretSize]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[key]
	if !ok || !now.Before(entry.forget) {
		delete(m.entries, key)
		return [agentpacketseal.AckSecretSize]byte{}, false
	}
	return entry.secret, true
}

func (m *envelopeMemory) put(key string, secret [agentpacketseal.AckSecretSize]byte, forget, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for held, entry := range m.entries {
		if !now.Before(entry.forget) {
			delete(m.entries, held)
		}
	}
	if _, ok := m.entries[key]; !ok && len(m.entries) >= m.max {
		first := ""
		for held, entry := range m.entries {
			if first == "" || entry.forget.Before(m.entries[first].forget) {
				first = held
			}
		}
		delete(m.entries, first)
	}
	m.entries[key] = memoryEntry{forget: forget, secret: secret}
}
