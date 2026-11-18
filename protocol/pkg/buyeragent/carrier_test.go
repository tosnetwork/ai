package buyeragent

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/servicefixture"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal/keycardtest"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"google.golang.org/protobuf/proto"
)

const (
	buyerController    = "buyer-packet"
	providerController = "provider-packet"
	buyerRelay         = "https://buyer-relay.example"
	providerRelay      = "https://provider-relay.example"
)

// fakeChain is the finalized state the fake card verifier reads: live
// Agents and the Capability's owner.
type fakeChain struct {
	mu          sync.Mutex
	agents      map[string]*nativev1.AgentStateV1
	owner       string
	verifyCalls int
	clock       *clock
	// anyCapability makes every Capability ID owned by owner, as a
	// verifier that does not check the ID would.
	anyCapability bool
}

func (c *fakeChain) ResolveAgent(id string) (*nativev1.AgentStateV1, bool, error) {
	agent, found := c.agents[id]
	return agent, found, nil
}

func (c *fakeChain) VerifyProviderCard(ctx context.Context, verifier mldsa44.Verifier, source buyersdk.ProviderCardSource,
	capabilityID string, raw []byte) (buyersdk.VerifiedProviderCard, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.verifyCalls++
	packet, err := agentpacket.DecodeJSON(raw)
	if err != nil || (capabilityID != fxCapability && !c.anyCapability) || packet.SenderAgentID != c.owner {
		return buyersdk.VerifiedProviderCard{}, buyersdk.ErrProviderCard
	}
	now := c.clock.Now()
	key, card, err := agentpacketseal.VerifyKeyCard(ctx, verifier, c, packet, now)
	if err != nil {
		return buyersdk.VerifiedProviderCard{}, err
	}
	return buyersdk.VerifiedProviderCard{Source: source, CapabilityID: capabilityID, PacketJSON: raw, Key: key, Card: card,
		Checkpoint: 1, VerifiedAt: now}, nil
}

func (c *fakeChain) VerifyAgentCard(ctx context.Context, verifier mldsa44.Verifier, agentID string,
	raw []byte) (agentpacketseal.RecipientKey, agentpacketseal.KeyCard, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	packet, err := agentpacket.DecodeJSON(raw)
	if err != nil || packet.SenderAgentID != agentID {
		return agentpacketseal.RecipientKey{}, agentpacketseal.KeyCard{}, buyersdk.ErrAgentCard
	}
	key, card, err := agentpacketseal.VerifyKeyCard(ctx, verifier, c, packet, c.clock.Now())
	if err != nil {
		return key, card, errors.Join(buyersdk.ErrAgentCard, err)
	}
	return key, card, nil
}

// fakeRelay answers its description unless down.
type fakeRelay struct {
	mu    sync.Mutex
	down  map[string]bool
	asked map[string]int
}

func (r *fakeRelay) client(base string) (RelayDescriber, error) {
	return relayClient{relay: r, base: base}, nil
}

type relayClient struct {
	relay *fakeRelay
	base  string
}

func (c relayClient) Describe(context.Context) (agentpacketrelay.RelayDescription, error) {
	c.relay.mu.Lock()
	defer c.relay.mu.Unlock()
	c.relay.asked[c.base]++
	if c.relay.down[c.base] {
		return agentpacketrelay.RelayDescription{}, errors.New("relay unavailable")
	}
	return agentpacketrelay.RelayDescription{MaxTTLSeconds: 86400}, nil
}

// failingSigner refuses every signature, as a locked custody would.
type failingSigner struct{}

func (failingSigner) Sign(context.Context, string, mldsa44.Use, []byte) (mldsa44.Signature, error) {
	return mldsa44.Signature{}, errors.New("custody is locked")
}

type carrierFixture struct {
	carrier *Carrier
	chain   *fakeChain
	relays  *fakeRelay
	clock   *clock
	dir     string
	record  buyersdk.CallRecord
	archive []byte
}

func controllerID(t *testing.T, name string) [mldsa44.KeyIDSize]byte {
	t.Helper()
	id, err := mldsa44.ParseKeyIDText(keycardtest.Keys.KeyID(name))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func newCarrierFixture(t *testing.T, binding nativecore.TransportBindingV1) *carrierFixture {
	t.Helper()
	now := &clock{now: fxNow}
	chain := &fakeChain{owner: fxProvider, clock: now, agents: map[string]*nativev1.AgentStateV1{
		fxProvider:   keycardtest.Agent(fxProvider, providerController),
		fxBuyerAgent: keycardtest.Agent(fxBuyerAgent, buyerController)}}
	relays := &fakeRelay{down: map[string]bool{}, asked: map[string]int{}}
	dir := privateDir(t)
	carrier, err := NewCarrier(CarrierConfig{StateDir: dir, BuyerAgentID: fxBuyerAgent, Network: fxNetwork(),
		Controller: buyerController, ControllerKeyID: controllerID(t, buyerController), Signer: keycardtest.Keys,
		Verifier: keycardtest.Keys, Cards: chain, Relays: []string{buyerRelay}, RelayClient: relays.client, Now: now.Now})
	if err != nil {
		t.Fatal(err)
	}
	request, value := quotePackageWith(t, fxNow, binding)
	raw, err := proto.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	record := buyersdk.CallRecord{RequestHash: strings.Repeat("ab", 32), BuyerWallet: fxBuyer, CapabilityID: fxCapability,
		CapabilityVersion: "1.0.0", PackageBase64: base64.StdEncoding.EncodeToString(raw), BuyerAddressInReq: request.BuyerAddress,
		ExecutionID: strings.Repeat("cd", 32), ResponseSLASeconds: fxResponseSLA}
	return &carrierFixture{carrier: carrier, chain: chain, relays: relays, clock: now, dir: dir, record: record,
		archive: sourceTar(t)}
}

func agentPackets(t *testing.T, maxRequestBytes uint32) nativecore.TransportBindingV1 {
	t.Helper()
	binding, err := nativecore.AgentPacketTransportBinding(fxProvider, maxRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func fxNetwork() *nativev1.NetworkDomain { return servicefixture.Network() }

// providerCardFor is a provider card valid from an hour before now for the
// given lifetime.
func providerCardFor(t *testing.T, agent string, seed byte, start time.Time, lifetime time.Duration) []byte {
	t.Helper()
	return keycardtest.JSON(t, keycardtest.Spec{AgentID: agent, Controller: providerController, Seed: seed,
		NotBeforeUnix: uint64(start.Unix()), NotAfterUnix: uint64(start.Add(lifetime).Unix()),
		Relays: []string{providerRelay}})
}

func (f *carrierFixture) learn(t *testing.T, raw []byte) buyersdk.VerifiedProviderCard {
	t.Helper()
	card, err := f.carrier.LearnProviderCard(context.Background(), buyersdk.ProviderCardFromQuote, fxCapability, raw)
	if err != nil {
		t.Fatal(err)
	}
	return card
}

func TestTheCarriageCheckPassesWithEveryItemHeld(t *testing.T) {
	f := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	f.learn(t, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), 7*24*time.Hour))
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); err != nil {
		t.Fatal(err)
	}
	keys, cards, err := f.carrier.HeldKeys()
	if err != nil || len(keys) != 1 || len(cards) != 1 {
		t.Fatalf("the fresh buyer card's key is not held: %d %v", len(keys), err)
	}
	// The buyer card covers the response deadline plus the retention.
	cover := fxNow.Add(fxResponseSLA*time.Second + 86400*time.Second + cardCoverSlack)
	if cards[0].NotBeforeUnix != uint64(fxNow.Unix()) || cards[0].NotAfterUnix != uint64(cover.Unix()) ||
		len(cards[0].Relays) != 1 || cards[0].Relays[0] != buyerRelay {
		t.Fatalf("buyer card %+v", cards[0])
	}
}

func TestTheCarriageCheckRefusesAQuoteNotDeliveredOverAgentPackets(t *testing.T) {
	https := nativecore.TransportBindingV1{SecurityMode: nativecore.TransportHTTPS, MaxRequestBytes: 1 << 20,
		BaseURL: "https://provider.example"}
	f := newCarrierFixture(t, https)
	f.learn(t, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), 7*24*time.Hour))
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); err == nil {
		t.Fatal("a Quote over HTTPS passed the carriage check")
	}
}

func TestTheCarriageCheckRefusesAnArchiveOverTheProvidersBound(t *testing.T) {
	f := newCarrierFixture(t, agentPackets(t, uint32(len(sourceTar(t))-1)))
	f.learn(t, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), 7*24*time.Hour))
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); err == nil {
		t.Fatal("an archive over max_request_bytes passed")
	}
	g := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	g.learn(t, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), 7*24*time.Hour))
	if err := g.carrier.CheckCarriage(context.Background(), g.record, nil); err == nil {
		t.Fatal("an empty archive passed")
	}
	// A capability version the task cannot carry fails the task encoding.
	bad := g.record
	bad.ExecutionID = "not hex"
	if err := g.carrier.CheckCarriage(context.Background(), bad, g.archive); err == nil {
		t.Fatal("a task that does not encode passed")
	}
}

func TestTheCarriageCheckNeedsAUsableProviderCardForTheResponseWindow(t *testing.T) {
	f := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); !errors.Is(err, ErrNoProviderCard) {
		t.Fatalf("no provider card: %v", err)
	}
	// A card ending before the response deadline cannot carry the task's
	// redeliveries.
	f.learn(t, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), time.Hour+fxResponseSLA*time.Second-time.Second))
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); !errors.Is(err, ErrNoProviderCard) {
		t.Fatalf("a card ending before the response deadline: %v", err)
	}
	f.learn(t, providerCardFor(t, fxProvider, 2, fxNow.Add(-time.Hour), time.Hour+fxResponseSLA*time.Second))
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); err != nil {
		t.Fatalf("a card ending at the response deadline: %v", err)
	}
	// After ten minutes the card is verified again; a card whose Agent is no
	// longer the owner is then unusable.
	calls := f.chain.verifyCalls
	f.clock.advance(buyersdk.ProviderCardReverifyAfter + time.Second)
	f.chain.mu.Lock()
	f.chain.owner = "agent_" + strings.Repeat("66", 32)
	f.chain.mu.Unlock()
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); !errors.Is(err, ErrNoProviderCard) {
		t.Fatalf("a card that no longer verifies: %v", err)
	}
	if f.chain.verifyCalls == calls {
		t.Fatal("a stale verification was used without verifying the card again")
	}
}

func TestAProviderCardOfAnotherAgentIsNeverSealedTo(t *testing.T) {
	f := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	other := "agent_" + strings.Repeat("66", 32)
	f.chain.agents[other] = keycardtest.Agent(other, providerController)
	f.chain.owner = other
	f.learn(t, providerCardFor(t, other, 1, fxNow.Add(-time.Hour), 7*24*time.Hour))
	if _, err := f.carrier.ProviderCard(context.Background(), fxCapability, fxProvider, fxNow); !errors.Is(err, ErrNoProviderCard) {
		t.Fatalf("a card of an Agent other than the Quote's provider was selected: %v", err)
	}
	// The Capability ID names a directory: one that is not a Capability ID
	// is refused before any verifier sees it.
	f.chain.anyCapability = true
	card := providerCardFor(t, other, 2, fxNow.Add(-time.Hour), 7*24*time.Hour)
	if _, err := f.carrier.LearnProviderCard(context.Background(), buyersdk.ProviderCardFromQuote, "../escape", card); err == nil {
		t.Fatal("a card for an invalid Capability ID was learned")
	}
	if _, err := os.Stat(filepath.Join(f.dir, "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a Capability ID escaped the provider card directory")
	}
}

func TestTheNewestUsableProviderCardIsSelected(t *testing.T) {
	f := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	older := f.learn(t, providerCardFor(t, fxProvider, 1, fxNow.Add(-2*time.Hour), 7*24*time.Hour))
	newer := f.learn(t, providerCardFor(t, fxProvider, 2, fxNow.Add(-time.Hour), 7*24*time.Hour))
	card, err := f.carrier.ProviderCard(context.Background(), fxCapability, fxProvider, fxNow)
	if err != nil || card.Key.KeyID != newer.Key.KeyID || card.Key.KeyID == older.Key.KeyID {
		t.Fatalf("selected %x: %v", card.Key.KeyID[:4], err)
	}
	// Equal not_before: the greater key ID wins.
	a := f.learn(t, providerCardFor(t, fxProvider, 3, fxNow, 7*24*time.Hour))
	b := f.learn(t, providerCardFor(t, fxProvider, 4, fxNow, 7*24*time.Hour))
	want := a
	if string(b.Key.KeyID[:]) > string(a.Key.KeyID[:]) {
		want = b
	}
	card, err = f.carrier.ProviderCard(context.Background(), fxCapability, fxProvider, fxNow)
	if err != nil || card.Key.KeyID != want.Key.KeyID {
		t.Fatalf("tie broken to %x: %v", card.Key.KeyID[:4], err)
	}
}

func TestAtMostEightProviderCardsAreKeptPerCapability(t *testing.T) {
	f := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	for seed := byte(1); seed <= MaxProviderCardsPerCapability+2; seed++ {
		f.learn(t, providerCardFor(t, fxProvider, seed, fxNow.Add(-time.Hour), time.Duration(seed)*24*time.Hour))
	}
	entries, err := os.ReadDir(filepath.Join(f.dir, "provider-cards", fxCapability))
	if err != nil || len(entries) != MaxProviderCardsPerCapability {
		t.Fatalf("%d provider cards kept: %v", len(entries), err)
	}
	// The ones expiring first were dropped.
	if _, err := f.carrier.ProviderCard(context.Background(), fxCapability, fxProvider,
		fxNow.Add(2*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func TestTheCarriageCheckNeedsThePacketControllerToSignForALiveBuyerAgent(t *testing.T) {
	f := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	f.learn(t, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), 7*24*time.Hour))
	f.carrier.config.Signer = failingSigner{}
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); err == nil {
		t.Fatal("a check passed although custody could not sign")
	}
	f.carrier.config.Signer = keycardtest.Keys
	f.chain.agents[fxBuyerAgent].Tombstoned = true
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); !errors.Is(err, buyersdk.ErrAgentCard) {
		t.Fatalf("a tombstoned buyer Agent: %v", err)
	}
	f.chain.agents[fxBuyerAgent] = keycardtest.Agent(fxBuyerAgent, "another-controller")
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); !errors.Is(err, buyersdk.ErrAgentCard) {
		t.Fatalf("a packet controller outside the finalized policy: %v", err)
	}
}

func TestTheCarriageCheckNeedsARecentRelayOnEachSide(t *testing.T) {
	f := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	f.learn(t, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), 7*24*time.Hour))
	f.relays.down[buyerRelay] = true
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); !errors.Is(err, ErrRelaysUnavailable) {
		t.Fatalf("no buyer relay answered: %v", err)
	}
	f.relays.down[buyerRelay] = false
	f.relays.down[providerRelay] = true
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); !errors.Is(err, ErrRelaysUnavailable) {
		t.Fatalf("no provider relay answered: %v", err)
	}
	f.relays.down[providerRelay] = false
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); err != nil {
		t.Fatal(err)
	}
	// A relay that answered within ten minutes is not asked again; after
	// that it is.
	asked := f.relays.asked[buyerRelay]
	f.clock.advance(RelayFreshness)
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); err != nil {
		t.Fatal(err)
	}
	if f.relays.asked[buyerRelay] != asked {
		t.Fatal("a relay that answered within ten minutes was asked again")
	}
	f.relays.down[buyerRelay] = true
	f.clock.advance(time.Second)
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); !errors.Is(err, ErrRelaysUnavailable) {
		t.Fatalf("a relay last heard over ten minutes ago counted: %v", err)
	}
}

func TestBuyerCardsAreCappedAtThirtyDaysAndKeysKeptUntilTheirRetention(t *testing.T) {
	f := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	_, card, err := f.carrier.IssueBuyerCard(context.Background(), fxNow.Add(40*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if card.NotAfterUnix != uint64(fxNow.Add(agentpacketseal.MaxKeyCardLifetime).Unix()) {
		t.Fatalf("a card past 30 days was issued: %d", card.NotAfterUnix)
	}
	if _, _, err := f.carrier.IssueBuyerCard(context.Background(), fxNow); err == nil {
		t.Fatal("a card ending at its start was issued")
	}
	end := time.Unix(int64(card.NotAfterUnix), 0)
	f.clock.now = end.Add(KeyRetention - time.Second)
	if keys, _, err := f.carrier.HeldKeys(); err != nil || len(keys) != 1 {
		t.Fatalf("a key inside its retention is not held: %d %v", len(keys), err)
	}
	if removed, err := f.carrier.DestroyExpiredKeys(); err != nil || removed != 0 {
		t.Fatalf("a key inside its retention was destroyed: %d %v", removed, err)
	}
	f.clock.now = end.Add(KeyRetention)
	if keys, _, err := f.carrier.HeldKeys(); err != nil || len(keys) != 0 {
		t.Fatalf("a key past its retention is held: %d %v", len(keys), err)
	}
	if removed, err := f.carrier.DestroyExpiredKeys(); err != nil || removed != 1 {
		t.Fatalf("a key past its retention was not destroyed: %d %v", removed, err)
	}
	if KeyRetention != 86700*time.Second {
		t.Fatal("keys are kept 86,400 + 300 seconds past not_after")
	}
}

func TestACarrierConfigurationIsValidated(t *testing.T) {
	f := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	base := f.carrier.config
	base.StateDir = privateDir(t)
	for name, edit := range map[string]func(*CarrierConfig){
		"no relay": func(c *CarrierConfig) { c.Relays = nil },
		"five relays": func(c *CarrierConfig) {
			c.Relays = []string{"https://a.x", "https://b.x", "https://c.x", "https://d.x", "https://e.x"}
		},
		"duplicate relay":   func(c *CarrierConfig) { c.Relays = []string{buyerRelay, buyerRelay} },
		"plain http relay":  func(c *CarrierConfig) { c.Relays = []string{"http://relay.example"} },
		"no controller key": func(c *CarrierConfig) { c.ControllerKeyID = [mldsa44.KeyIDSize]byte{} },
		"bad buyer agent":   func(c *CarrierConfig) { c.BuyerAgentID = "agent_x" },
		"relative state":    func(c *CarrierConfig) { c.StateDir = "state" },
	} {
		config := base
		edit(&config)
		if _, err := NewCarrier(config); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A relay answer from the future (the clock went back) is not fresh.
func TestARelayAnswerFromTheFutureIsNotFresh(t *testing.T) {
	f := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	f.learn(t, providerCardFor(t, fxProvider, 1, fxNow.Add(-2*time.Hour), 7*24*time.Hour))
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); err != nil {
		t.Fatal(err)
	}
	asked := f.relays.asked[buyerRelay]
	f.clock.advance(-time.Hour)
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); err != nil {
		t.Fatal(err)
	}
	if f.relays.asked[buyerRelay] == asked {
		t.Fatal("an answer recorded after the current time counted as fresh")
	}
}

// A stored relay key that is not the buyer Agent's, or whose file does not
// name its key ID, stops the key listing.
func TestATamperedRelayKeyIsRefused(t *testing.T) {
	f := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	if _, _, err := f.carrier.IssueBuyerCard(context.Background(), fxNow.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(f.dir, "relay-keys"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("%d keys: %v", len(entries), err)
	}
	path := filepath.Join(f.dir, "relay-keys", entries[0].Name())
	renamed := filepath.Join(f.dir, "relay-keys", strings.Repeat("0", 64)+".json")
	if err := os.Rename(path, renamed); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.carrier.HeldKeys(); err == nil {
		t.Fatal("a key file that does not name its key ID was listed")
	}
	var record relayKeyRecord
	if err := readJSON(renamed, &record); err != nil {
		t.Fatal(err)
	}
	record.AgentID = fxProvider
	if err := writeJSON(path, record, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(renamed); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.carrier.HeldKeys(); err == nil {
		t.Fatal("a key of another Agent was listed")
	}
}
