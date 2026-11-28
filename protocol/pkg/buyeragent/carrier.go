package buyeragent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentcarrier"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
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
	// ErrNotAgentPackets reports a Quote whose transport binding is not
	// Agent Packets to its provider (section 7.1 item 1).
	ErrNotAgentPackets = errors.New("the Quote is not delivered over Agent Packets")
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
	Relays    []string
	Transport TransportConfig
	Now       func() time.Time
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
	answered    map[string]time.Time
	relay       func(string) (agentcarrier.Relay, error)
	lane        *agentcarrier.Lane
	routes      *agentcarrier.Resolver
	scheduler   *agentcarrier.Scheduler
	publisher   *agentcarrier.Publisher
	credentials *agentcarrier.CredentialManager
	deliveryMu  sync.Mutex
	inboxMu     sync.Mutex
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
	providerCardSchema = "tos.service.mcp-buyer.provider-card.v1"
)

// NewCarrier checks the configuration and prepares the carrier's state
// directories.
func NewCarrier(ctx context.Context, config CarrierConfig) (*Carrier, error) {
	if !agentIDPattern.MatchString(config.BuyerAgentID) || config.Network == nil || config.Controller == "" ||
		config.ControllerKeyID == ([mldsa44.KeyIDSize]byte{}) || config.Signer == nil || config.Verifier == nil ||
		config.Cards == nil || config.Transport.Relay == nil {
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
	for _, name := range []string{"provider-cards", "outbox-v2", "inbox", "received"} {
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
	transport := config.Transport
	config.Transport = TransportConfig{}
	carrier := &Carrier{config: config, relay: transport.Relay,
		verified: map[string]map[string]buyersdk.VerifiedProviderCard{}, answered: map[string]time.Time{}}
	if err := carrier.openTransport(ctx, transport); err != nil {
		return nil, err
	}
	return carrier, nil
}

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
		client, err := c.relay(relay)
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
	return c.checkCarriage(ctx, record, archive, true)
}

// CheckQuoteCarriage runs, for a Quote before any purchase exists, the
// items of section 7.1 that need no source (section 4.4 step 4): the card
// window, items 1, 3, 4 and 5, and item 2 for the package and version. The
// record carries the Quote's package, expiry and request identity and the
// finalized response SLA. Prepare runs the full check again with the task.
func (c *Carrier) CheckQuoteCarriage(ctx context.Context, record buyersdk.CallRecord) error {
	return c.checkCarriage(ctx, record, nil, false)
}

// checkCarriage runs the check; withSource adds the archive bound and the
// task encoding of item 2.
func (c *Carrier) checkCarriage(ctx context.Context, record buyersdk.CallRecord, archive []byte, withSource bool) error {
	packageBytes, err := base64.StdEncoding.Strict().DecodeString(record.PackageBase64)
	if err != nil {
		return errors.New("the journaled Quote package is not Base64")
	}
	value := &nativev1.QuoteProposalPackageV1{}
	if err := proto.Unmarshal(packageBytes, value); err != nil {
		return errors.New("the journaled Quote package does not decode")
	}
	validated, err := validatePortableQuote(c.config.Network, &nativev1.RequestQuoteProposalRequest{
		CapabilityId: record.CapabilityID, CapabilityVersion: record.CapabilityVersion, BuyerAddress: record.BuyerAddressInReq}, value)
	if err != nil {
		return err
	}
	// Item 1: Agent Packets to the Quote's provider. ValidatePortable has
	// checked that a mode-2 binding names the proposal's provider; the card
	// check below ties that provider to the Capability's finalized owner.
	provider := validated.Proposal.ProviderAgentId
	if validated.TransportBinding.SecurityMode != nativecore.TransportAgentPacket {
		return ErrNotAgentPackets
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
	if withSource && (len(archive) == 0 || len(archive) > limit) {
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
	route, err := c.routes.Resolve(ctx, provider, agentcarrier.Route{CardPacket: providerCard.PacketJSON})
	if errors.Is(err, agentcarrier.ErrNoRoute) {
		return fmt.Errorf("%w: %w", ErrRelaysUnavailable, err)
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(route.CardPacket, providerCard.PacketJSON) {
		key, card, err := c.verifyCard(ctx, route.CardPacket, now)
		if err != nil || key.AgentID != provider || card.NotAfterUnix < uint64(responseDeadline.Unix()) {
			return ErrNoProviderCard
		}
	}
	hint, err := agenttransport.DecodeHintRecord(route.HintRecord)
	if err != nil {
		return err
	}
	if err := c.relaysAnswered(ctx, hint.Hint.Relays); err != nil {
		return fmt.Errorf("provider relays: %w", err)
	}
	// Item 4, last because it may sign: a buyer card covering the window,
	// verified against finalized state. A held card that already covers it
	// is reused; only otherwise is a new key drawn and a card signed.
	buyerCard, err := c.BuyerCard(ctx, cover)
	if err != nil {
		return err
	}
	if !withSource {
		return nil
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
	if notAfter.Unix() <= 0 {
		return nil, ErrCardWindowTooLong
	}
	card, err := c.lane.CurrentCardThrough(ctx, uint64(notAfter.Unix()))
	return card.Packet, err
}
