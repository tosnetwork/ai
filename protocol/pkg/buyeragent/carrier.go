package buyeragent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"google.golang.org/protobuf/proto"
)

var capabilityIDPattern = regexp.MustCompile(`^cap_[0-9a-f]{64}$`)

// Carrier bounds and timing (MCP_BUYER_ADAPTER_V1 sections 3.3 and 7.1;
// AGENT_PACKET_RELAY_V1 sections 6.3 and 9.6).
const (
	// RelayFreshness is how recently a relay must have answered its
	// description for the carriage check to count it.
	RelayFreshness = 10 * time.Minute
	// KeyRetention is how long past a card's not_after its private key is
	// kept: the longest an envelope sealed before expiry can wait.
	KeyRetention = 86400*time.Second + 300*time.Second
	// MaxProviderCardsPerCapability bounds the provider cards kept for one
	// Capability; the one expiring first is dropped.
	MaxProviderCardsPerCapability = 8
	// cardCoverSlack is added to the response deadline a buyer card must
	// cover, for clock skew.
	cardCoverSlack = 300 * time.Second
)

// Carrier errors.
var (
	// ErrNoProviderCard reports that no verified provider key card covers
	// the response window (section 7.1 item 3).
	ErrNoProviderCard = errors.New("no verified provider key card covers the response window")
	// ErrRelaysUnavailable reports that no relay of a card answered its
	// description recently (section 7.1 item 5).
	ErrRelaysUnavailable = errors.New("no relay of the card answered its description in the last 10 minutes")
	// ErrCardWindowTooLong reports a purchase whose buyer card would have to
	// outlive the 30-day card lifetime: the Quote's expiry plus the response
	// SLA plus the result's retention lies too far ahead.
	ErrCardWindowTooLong = errors.New("the purchase needs a buyer key card beyond the 30-day card lifetime")
)

// CardVerifier verifies key cards against finalized state; buyersdk's
// ServiceActorBuyer implements it.
type CardVerifier interface {
	VerifyProviderCard(ctx context.Context, verifier mldsa44.Verifier, source buyersdk.ProviderCardSource,
		capabilityID string, raw []byte) (buyersdk.VerifiedProviderCard, error)
	VerifyAgentCard(ctx context.Context, verifier mldsa44.Verifier, agentID string,
		raw []byte) (agentpacketseal.RecipientKey, agentpacketseal.KeyCard, error)
	// VerifyPacket verifies a delivered packet against finalized state;
	// buyersdk.ErrPacketRefused marks a permanent refusal.
	VerifyPacket(ctx context.Context, verifier mldsa44.Verifier, packet agentpacket.Packet) error
}

// RelayClient is the part of a relay client the carrier uses: the
// description the carriage check reads, the deposit that delivers an
// envelope, and the listing, download and acknowledgement of the buyer's
// mailbox. agentpacketrelay.Client implements it.
type RelayClient interface {
	Describe(ctx context.Context) (agentpacketrelay.RelayDescription, error)
	Deposit(ctx context.Context, envelope []byte) (agentpacketrelay.DepositOutcome, error)
	List(ctx context.Context, agentID string) (agentpacketrelay.Mailbox, error)
	Download(ctx context.Context, agentID string, envelopeID [32]byte) ([]byte, error)
	Ack(ctx context.Context, agentID string, envelopeID [32]byte, secret [agentpacketseal.AckSecretSize]byte) error
}

// CarrierConfig wires a Carrier.
type CarrierConfig struct {
	// StateDir is the agent's owner-private state directory; the carrier
	// keeps its relay keys and provider cards under it.
	StateDir     string
	BuyerAgentID string
	Network      *nativev1.NetworkDomain
	// Controller names the packet controller in custody, and
	// ControllerKeyID is its key ID; buyer cards are signed with it.
	Controller      string
	ControllerKeyID [mldsa44.KeyIDSize]byte
	Signer          mldsa44.Signer
	Verifier        mldsa44.Verifier
	Cards           CardVerifier
	// Relays are the buyer's relay base URLs, 1 to 4 in canonical form;
	// they go into every buyer card.
	Relays []string
	// RelayClient returns the client of a relay base URL, for the buyer's
	// relays and those a provider card names.
	RelayClient func(baseURL string) (RelayClient, error)
	Now         func() time.Time
	// Random fills packet nonces and acknowledgement secrets; nil is
	// crypto/rand.
	Random func([]byte) error
}

// Carrier holds the buyer's relay keys and cards and the verified provider
// cards, and decides carriage (section 7.1). It is safe for concurrent use.
type Carrier struct {
	config CarrierConfig
	mu     sync.Mutex
	// verified caches provider card verifications by Capability and key ID.
	verified map[string]map[string]buyersdk.VerifiedProviderCard
	// answered is when each relay last answered its description.
	answered map[string]time.Time
	// poll is the polling state of each relay; settled and refused are the
	// mailbox memories of relay section 8.6 (receive.go).
	pollMu  sync.Mutex
	poll    map[string]*relayPoll
	settled *envelopeMemory
	refused *envelopeMemory
}

// relayKeyRecord is one relay key: its seed and the buyer card for it.
type relayKeyRecord struct {
	Schema        string `json:"schema"`
	AgentID       string `json:"agent_id"`
	SeedBase64    string `json:"seed_base64"`
	CardBase64    string `json:"card_packet_base64"`
	NotBeforeUnix uint64 `json:"not_before_unix"`
	NotAfterUnix  uint64 `json:"not_after_unix"`
}

// providerCardRecord is one provider card as learned; it is verified again
// before every use.
type providerCardRecord struct {
	Schema       string `json:"schema"`
	CapabilityID string `json:"capability_id"`
	Source       string `json:"source"`
	CardBase64   string `json:"card_packet_base64"`
	NotAfterUnix uint64 `json:"not_after_unix"`
}

const (
	relayKeySchema     = "tos.service.mcp-buyer.relay-key.v1"
	providerCardSchema = "tos.service.mcp-buyer.provider-card.v1"
)

// NewCarrier checks the configuration and prepares the carrier's state
// directories.
func NewCarrier(config CarrierConfig) (*Carrier, error) {
	if !agentIDPattern.MatchString(config.BuyerAgentID) || config.Network == nil || config.Controller == "" ||
		config.ControllerKeyID == ([mldsa44.KeyIDSize]byte{}) || config.Signer == nil || config.Verifier == nil ||
		config.Cards == nil || config.RelayClient == nil {
		return nil, errors.New("invalid buyer carrier configuration")
	}
	if len(config.Relays) == 0 || len(config.Relays) > agentpacketseal.MaxRelays {
		return nil, errors.New("the buyer names 1 to 4 relays")
	}
	relays := append([]string(nil), config.Relays...)
	sort.Strings(relays)
	for index, relay := range relays {
		if err := agentpacketseal.CheckRelayURL(relay); err != nil || (index > 0 && relays[index-1] == relay) {
			return nil, fmt.Errorf("relay %d is not a distinct canonical relay base URL", index)
		}
	}
	config.Relays = relays
	if !filepath.IsAbs(config.StateDir) || filepath.Clean(config.StateDir) != config.StateDir {
		return nil, errors.New("the carrier state directory must be absolute and clean")
	}
	if err := checkPrivateDir(config.StateDir); err != nil {
		return nil, err
	}
	for _, name := range []string{"relay-keys", "provider-cards", "outbox", "inbox", "received"} {
		path := filepath.Join(config.StateDir, name)
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if err := checkPrivateDir(path); err != nil {
			return nil, err
		}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = func(value []byte) error { _, err := rand.Read(value); return err }
	}
	return &Carrier{config: config, verified: map[string]map[string]buyersdk.VerifiedProviderCard{},
		answered: map[string]time.Time{}, poll: map[string]*relayPoll{},
		settled: newEnvelopeMemory(MaxEnvelopeMemory), refused: newEnvelopeMemory(MaxEnvelopeMemory)}, nil
}

func (c *Carrier) keyDir() string  { return filepath.Join(c.config.StateDir, "relay-keys") }
func (c *Carrier) cardDir() string { return filepath.Join(c.config.StateDir, "provider-cards") }

// LearnProviderCard verifies a provider card from any source and keeps it
// for the Capability. A card that does not verify is refused and not kept.
func (c *Carrier) LearnProviderCard(ctx context.Context, source buyersdk.ProviderCardSource, capabilityID string,
	raw []byte) (buyersdk.VerifiedProviderCard, error) {
	if !capabilityIDPattern.MatchString(capabilityID) {
		return buyersdk.VerifiedProviderCard{}, errors.New("invalid Capability ID")
	}
	card, err := c.config.Cards.VerifyProviderCard(ctx, c.config.Verifier, source, capabilityID, raw)
	if err != nil {
		return buyersdk.VerifiedProviderCard{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	directory := filepath.Join(c.cardDir(), capabilityID)
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return buyersdk.VerifiedProviderCard{}, err
	}
	if err := checkPrivateDir(directory); err != nil {
		return buyersdk.VerifiedProviderCard{}, err
	}
	keyID := hex.EncodeToString(card.Key.KeyID[:])
	record := providerCardRecord{Schema: providerCardSchema, CapabilityID: capabilityID, Source: string(source),
		CardBase64: base64.StdEncoding.EncodeToString(raw), NotAfterUnix: card.Card.NotAfterUnix}
	if err := writeJSON(filepath.Join(directory, keyID+".json"), record, false); err != nil {
		return buyersdk.VerifiedProviderCard{}, err
	}
	if c.verified[capabilityID] == nil {
		c.verified[capabilityID] = map[string]buyersdk.VerifiedProviderCard{}
	}
	c.verified[capabilityID][keyID] = card
	return card, c.pruneProviderCardsLocked(capabilityID)
}

// pruneProviderCardsLocked keeps at most MaxProviderCardsPerCapability
// cards, dropping the ones expiring first.
func (c *Carrier) pruneProviderCardsLocked(capabilityID string) error {
	records, err := c.providerCardsLocked(capabilityID)
	if err != nil || len(records) <= MaxProviderCardsPerCapability {
		return err
	}
	sort.Slice(records, func(i, j int) bool { return records[i].record.NotAfterUnix < records[j].record.NotAfterUnix })
	for _, drop := range records[:len(records)-MaxProviderCardsPerCapability] {
		if err := os.Remove(drop.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		delete(c.verified[capabilityID], strings.TrimSuffix(filepath.Base(drop.path), ".json"))
	}
	return nil
}

type storedProviderCard struct {
	path   string
	record providerCardRecord
}

func (c *Carrier) providerCardsLocked(capabilityID string) ([]storedProviderCard, error) {
	directory := filepath.Join(c.cardDir(), capabilityID)
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var cards []storedProviderCard
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		var record providerCardRecord
		if err := readJSON(path, &record); err != nil {
			return nil, err
		}
		if record.Schema != providerCardSchema || record.CapabilityID != capabilityID {
			return nil, errors.New("a stored provider card is not for its Capability")
		}
		cards = append(cards, storedProviderCard{path: path, record: record})
	}
	return cards, nil
}

// ProviderCard returns the provider card to seal to for a Capability: a
// card of providerAgentID, usable now (verified at most 10 minutes ago, or
// verified again here) and valid until at least notAfter. Of several, the
// one with the greatest not_before wins, ties broken by the greatest key
// ID (relay 6.3).
func (c *Carrier) ProviderCard(ctx context.Context, capabilityID, providerAgentID string,
	notAfter time.Time) (buyersdk.VerifiedProviderCard, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	records, err := c.providerCardsLocked(capabilityID)
	if err != nil {
		return buyersdk.VerifiedProviderCard{}, err
	}
	now := c.config.Now()
	var best *buyersdk.VerifiedProviderCard
	for _, stored := range records {
		keyID := strings.TrimSuffix(filepath.Base(stored.path), ".json")
		card, cached := c.verified[capabilityID][keyID]
		if !cached || card.UsableAt(now) != nil {
			raw, err := base64.StdEncoding.Strict().DecodeString(stored.record.CardBase64)
			if err != nil {
				continue
			}
			card, err = c.config.Cards.VerifyProviderCard(ctx, c.config.Verifier,
				buyersdk.ProviderCardSource(stored.record.Source), capabilityID, raw)
			if err != nil {
				delete(c.verified[capabilityID], keyID)
				continue
			}
			if c.verified[capabilityID] == nil {
				c.verified[capabilityID] = map[string]buyersdk.VerifiedProviderCard{}
			}
			c.verified[capabilityID][keyID] = card
		}
		if card.Key.AgentID != providerAgentID || card.UsableAt(now) != nil ||
			card.Card.NotAfterUnix < uint64(notAfter.Unix()) {
			continue
		}
		if best == nil || preferCard(card, *best) {
			selected := card
			best = &selected
		}
	}
	if best == nil {
		return buyersdk.VerifiedProviderCard{}, ErrNoProviderCard
	}
	return *best, nil
}

// preferCard reports whether a is preferred to b under relay 6.3.
func preferCard(a, b buyersdk.VerifiedProviderCard) bool {
	if a.Card.NotBeforeUnix != b.Card.NotBeforeUnix {
		return a.Card.NotBeforeUnix > b.Card.NotBeforeUnix
	}
	return string(a.Key.KeyID[:]) > string(b.Key.KeyID[:])
}

// IssueBuyerCard draws a fresh relay key, signs a buyer card for it valid
// from now until notAfter (at most 30 days) naming the buyer's relays,
// stores the key and card, and verifies the card against finalized state.
// The verification proves that the buyer Agent is finalized and live and
// that the packet controller can sign for it (section 7.1 item 4).
func (c *Carrier) IssueBuyerCard(ctx context.Context, notAfter time.Time) ([]byte, agentpacketseal.KeyCard, error) {
	now := c.config.Now()
	start := uint64(now.Unix())
	end := uint64(notAfter.Unix())
	if limit := start + uint64(agentpacketseal.MaxKeyCardLifetime/time.Second); end > limit {
		end = limit
	}
	if end <= start {
		return nil, agentpacketseal.KeyCard{}, errors.New("a buyer card must end after it starts")
	}
	seed, err := agentpacketseal.GenerateSeed()
	if err != nil {
		return nil, agentpacketseal.KeyCard{}, err
	}
	private, err := agentpacketseal.NewPrivateKey(c.config.BuyerAgentID, seed)
	if err != nil {
		return nil, agentpacketseal.KeyCard{}, err
	}
	public, err := private.PublicKey()
	if err != nil {
		return nil, agentpacketseal.KeyCard{}, err
	}
	card := agentpacketseal.KeyCard{PublicKey: public, KeyID: private.KeyID, NotBeforeUnix: start, NotAfterUnix: end,
		Relays: append([]string(nil), c.config.Relays...)}
	var nonce [32]byte
	copy(nonce[:], private.KeyID[:])
	packet, err := agentpacketseal.KeyCardPacket(c.config.BuyerAgentID, c.config.ControllerKeyID, start, nonce, start, card)
	if err != nil {
		return nil, agentpacketseal.KeyCard{}, err
	}
	signed, err := agentpacket.Sign(ctx, c.config.Signer, c.config.Controller, packet)
	if err != nil {
		return nil, agentpacketseal.KeyCard{}, fmt.Errorf("the packet controller cannot sign a buyer card: %w", err)
	}
	raw, err := agentpacket.EncodeJSON(signed)
	if err != nil {
		return nil, agentpacketseal.KeyCard{}, err
	}
	// The key is stored before the card can reach anyone, so an envelope
	// sealed to it can always be opened.
	record := relayKeyRecord{Schema: relayKeySchema, AgentID: c.config.BuyerAgentID, SeedBase64: base64.StdEncoding.EncodeToString(seed),
		CardBase64: base64.StdEncoding.EncodeToString(raw), NotBeforeUnix: start, NotAfterUnix: end}
	if err := writeJSON(filepath.Join(c.keyDir(), hex.EncodeToString(private.KeyID[:])+".json"), record, true); err != nil {
		return nil, agentpacketseal.KeyCard{}, err
	}
	if _, _, err := c.config.Cards.VerifyAgentCard(ctx, c.config.Verifier, c.config.BuyerAgentID, raw); err != nil {
		return nil, agentpacketseal.KeyCard{}, err
	}
	return raw, card, nil
}

// HeldKeys returns every relay private key the buyer must still keep: until
// its card's not_after plus KeyRetention. The buyer polls every relay of
// these keys' cards.
func (c *Carrier) HeldKeys() ([]agentpacketseal.PrivateKey, []agentpacketseal.KeyCard, error) {
	entries, err := os.ReadDir(c.keyDir())
	if err != nil {
		return nil, nil, err
	}
	now := uint64(c.config.Now().Unix())
	var keys []agentpacketseal.PrivateKey
	var cards []agentpacketseal.KeyCard
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		var record relayKeyRecord
		if err := readJSON(filepath.Join(c.keyDir(), entry.Name()), &record); err != nil {
			return nil, nil, err
		}
		if record.Schema != relayKeySchema || record.AgentID != c.config.BuyerAgentID {
			return nil, nil, errors.New("a stored relay key is not the buyer Agent's")
		}
		if now >= record.NotAfterUnix+uint64(KeyRetention/time.Second) {
			continue
		}
		seed, err := base64.StdEncoding.Strict().DecodeString(record.SeedBase64)
		if err != nil {
			return nil, nil, errors.New("a stored relay key seed is not Base64")
		}
		key, err := agentpacketseal.NewPrivateKey(record.AgentID, seed)
		if err != nil || hex.EncodeToString(key.KeyID[:])+".json" != entry.Name() {
			return nil, nil, errors.New("a stored relay key does not derive its key ID")
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(record.CardBase64)
		if err != nil {
			return nil, nil, errors.New("a stored buyer card is not Base64")
		}
		packet, err := agentpacket.DecodeJSON(raw)
		if err != nil {
			return nil, nil, err
		}
		card, err := agentpacketseal.DecodeKeyCard(packet.Payload)
		if err != nil || card.KeyID != key.KeyID {
			return nil, nil, errors.New("a stored buyer card is not for its key")
		}
		keys, cards = append(keys, key), append(cards, card)
	}
	return keys, cards, nil
}

// DestroyExpiredKeys removes every relay key past its retention (relay
// 6.3: the key MUST be destroyed after not_after + 86,400 + 300).
func (c *Carrier) DestroyExpiredKeys() (int, error) {
	entries, err := os.ReadDir(c.keyDir())
	if err != nil {
		return 0, err
	}
	now := uint64(c.config.Now().Unix())
	removed := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		path := filepath.Join(c.keyDir(), entry.Name())
		var record relayKeyRecord
		if err := readJSON(path, &record); err != nil {
			return removed, err
		}
		if now < record.NotAfterUnix+uint64(KeyRetention/time.Second) {
			continue
		}
		if err := os.Remove(path); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// relaysAnswered requires at least one of relays to have answered its
// description within RelayFreshness, asking the stale ones now.
func (c *Carrier) relaysAnswered(ctx context.Context, relays []string) error {
	now := c.config.Now()
	for _, relay := range relays {
		c.mu.Lock()
		last, seen := c.answered[relay]
		c.mu.Unlock()
		if seen && !now.Before(last) && now.Sub(last) <= RelayFreshness {
			return nil
		}
	}
	for _, relay := range relays {
		client, err := c.config.RelayClient(relay)
		if err != nil {
			continue
		}
		if _, err := client.Describe(ctx); err != nil {
			continue
		}
		c.mu.Lock()
		c.answered[relay] = c.config.Now()
		c.mu.Unlock()
		return nil
	}
	return ErrRelaysUnavailable
}

// CheckCarriage runs the carriage check of section 7.1 for a prepared
// purchase: every item must hold at the moment of the check.
func (c *Carrier) CheckCarriage(ctx context.Context, record buyersdk.CallRecord, archive []byte) error {
	packageBytes, err := base64.StdEncoding.Strict().DecodeString(record.PackageBase64)
	if err != nil {
		return errors.New("the journaled Quote package is not Base64")
	}
	value := &nativev1.QuoteProposalPackageV1{}
	if err := proto.Unmarshal(packageBytes, value); err != nil {
		return errors.New("the journaled Quote package does not decode")
	}
	validated, err := quoteexchange.ValidatePortable(c.config.Network, &nativev1.RequestQuoteProposalRequest{
		CapabilityId: record.CapabilityID, CapabilityVersion: record.CapabilityVersion, BuyerAddress: record.BuyerAddressInReq}, value)
	if err != nil {
		return err
	}
	// Item 1: Agent Packets to the Quote's provider. ValidatePortable has
	// checked that a mode-2 binding names the proposal's provider; the card
	// check below ties that provider to the Capability's finalized owner.
	provider := validated.Proposal.ProviderAgentId
	if validated.TransportBinding.SecurityMode != nativecore.TransportAgentPacket {
		return errors.New("the Quote is not delivered over Agent Packets")
	}
	now := c.config.Now()
	// The buyer card covers the latest response deadline the call can get
	// (the Quote's expiry plus the response SLA) plus the result's retention.
	// A window over the 30-day card lifetime is refused before any read: no
	// successor card would reach the provider in time.
	cover, err := buyerCardWindow(record, validated.Manifest.RetentionSeconds)
	if err != nil {
		return err
	}
	if cover.Sub(now) > agentpacketseal.MaxKeyCardLifetime {
		return ErrCardWindowTooLong
	}
	// Item 2, without the card: the archive fits the binding's bound and
	// the package can be carried.
	limit := int(validated.TransportBinding.MaxRequestBytes)
	if limit > railwork.MaxInlineInputBytes {
		limit = railwork.MaxInlineInputBytes
	}
	if len(archive) == 0 || len(archive) > limit {
		return fmt.Errorf("the source archive of %d bytes exceeds the provider's %d-byte bound", len(archive), limit)
	}
	if err := railwork.CheckCarriablePackage(len(packageBytes), validated.TransportBinding); err != nil {
		return err
	}
	// Item 3: a verified provider card usable now and valid through the
	// response deadline the call would get.
	responseDeadline := now.Add(time.Duration(record.ResponseSLASeconds) * time.Second)
	providerCard, err := c.ProviderCard(ctx, record.CapabilityID, provider, responseDeadline)
	if err != nil {
		return err
	}
	// Item 5: a relay of each side answered recently.
	if err := c.relaysAnswered(ctx, c.config.Relays); err != nil {
		return fmt.Errorf("buyer relays: %w", err)
	}
	if err := c.relaysAnswered(ctx, providerCard.Card.Relays); err != nil {
		return fmt.Errorf("provider relays: %w", err)
	}
	// Item 4, last because it may sign: a buyer card covering the window,
	// verified against finalized state. A held card that already covers it
	// is reused; only otherwise is a new key drawn and a card signed.
	buyerCard, err := c.BuyerCard(ctx, cover)
	if err != nil {
		return err
	}
	// Item 2 with the card: the task for this purchase encodes, with the
	// call fields at their widest.
	widest := ^uint64(0)
	if _, err := railwork.EncodeTask(railwork.Task{Header: railwork.TaskHeader{BuyerAgentID: c.config.BuyerAgentID,
		BuyerWallet: record.BuyerWallet, CapabilityID: record.CapabilityID, CapabilityVersion: record.CapabilityVersion,
		ExecutionID: record.ExecutionID, ExecutionNonce: strings.Repeat("0", 64), RequestID: widest, CallLT: widest,
		CallHash: strings.Repeat("0", 64)}, Package: packageBytes, Archive: archive, BuyerKeyCard: buyerCard}); err != nil {
		return fmt.Errorf("the task for this purchase does not encode: %w", err)
	}
	return nil
}

// buyerCardWindow is the end of the window a buyer card for this purchase
// must cover: the Quote's expiry (the latest time the call can be sent),
// plus the response SLA, plus the result's retention, plus 300 seconds.
func buyerCardWindow(record buyersdk.CallRecord, retentionSeconds uint64) (time.Time, error) {
	if record.ExpiresAtUnix == 0 {
		return time.Time{}, errors.New("the journaled call has no Quote expiry")
	}
	end := record.ExpiresAtUnix
	for _, add := range []uint64{uint64(record.ResponseSLASeconds), retentionSeconds, uint64(cardCoverSlack / time.Second)} {
		next := end + add
		if next < end || next > uint64(1)<<62 {
			return time.Time{}, ErrCardWindowTooLong
		}
		end = next
	}
	return time.Unix(int64(end), 0), nil
}

// BuyerCard returns a buyer card valid now and through notAfter, verified
// against finalized state. A held card that covers the window is reused,
// the one ending last; only when none does is a new key drawn and a card
// signed. A prepare loop therefore adds keys and signatures only when the
// window it needs grows past every held card. A held card naming other
// relays than the configured ones is not reused: the provider would seal
// results to relays the buyer no longer polls.
func (c *Carrier) BuyerCard(ctx context.Context, notAfter time.Time) ([]byte, error) {
	held, err := c.heldBuyerCards()
	if err != nil {
		return nil, err
	}
	now := uint64(c.config.Now().Unix())
	var best *heldBuyerCard
	for index := range held {
		card := held[index].card
		if card.NotBeforeUnix > now || card.NotAfterUnix < uint64(notAfter.Unix()) {
			continue
		}
		if !slices.Equal(card.Relays, c.config.Relays) {
			continue
		}
		if best == nil || card.NotAfterUnix > best.card.NotAfterUnix {
			best = &held[index]
		}
	}
	if best != nil {
		if _, _, err := c.config.Cards.VerifyAgentCard(ctx, c.config.Verifier, c.config.BuyerAgentID, best.raw); err != nil {
			return nil, err
		}
		return best.raw, nil
	}
	raw, _, err := c.IssueBuyerCard(ctx, notAfter)
	return raw, err
}

type heldBuyerCard struct {
	raw  []byte
	card agentpacketseal.KeyCard
}

// heldBuyerCards lists the buyer cards of the stored relay keys, with their
// packet JSON.
func (c *Carrier) heldBuyerCards() ([]heldBuyerCard, error) {
	entries, err := os.ReadDir(c.keyDir())
	if err != nil {
		return nil, err
	}
	var cards []heldBuyerCard
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		var record relayKeyRecord
		if err := readJSON(filepath.Join(c.keyDir(), entry.Name()), &record); err != nil {
			return nil, err
		}
		if record.Schema != relayKeySchema || record.AgentID != c.config.BuyerAgentID {
			return nil, errors.New("a stored relay key is not the buyer Agent's")
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(record.CardBase64)
		if err != nil {
			return nil, errors.New("a stored buyer card is not Base64")
		}
		packet, err := agentpacket.DecodeJSON(raw)
		if err != nil {
			return nil, err
		}
		card, err := agentpacketseal.DecodeKeyCard(packet.Payload)
		if err != nil || hex.EncodeToString(card.KeyID[:])+".json" != entry.Name() {
			return nil, errors.New("a stored buyer card is not for its key")
		}
		cards = append(cards, heldBuyerCard{raw: raw, card: card})
	}
	return cards, nil
}
