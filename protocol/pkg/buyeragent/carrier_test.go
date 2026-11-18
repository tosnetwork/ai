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

// fakeRelay answers its description unless down, and stores deposits
// unless told to answer a deposit otherwise.
type fakeRelay struct {
	mu    sync.Mutex
	down  map[string]bool
	asked map[string]int
	// deposits are the envelopes each relay accepted, in order; answer
	// overrides the outcome of a deposit at a relay.
	deposits map[string][][]byte
	answer   map[string]agentpacketrelay.DepositResult
	attempts map[string]int
	// crash makes a deposit panic, as a process dying mid-deposit would
	// stop the round.
	crash bool
}

func (r *fakeRelay) client(base string) (RelayClient, error) {
	return relayClient{relay: r, base: base}, nil
}

func (c relayClient) Deposit(_ context.Context, envelope []byte) (agentpacketrelay.DepositOutcome, error) {
	c.relay.mu.Lock()
	defer c.relay.mu.Unlock()
	if c.relay.attempts == nil {
		c.relay.attempts = map[string]int{}
	}
	c.relay.attempts[c.base]++
	if c.relay.crash {
		panic("the agent stopped during a deposit")
	}
	if _, err := agentpacketseal.ParseEnvelope(envelope); err != nil {
		return agentpacketrelay.DepositOutcome{}, agentpacketrelay.ErrInvalidArgument
	}
	if result, set := c.relay.answer[c.base]; set {
		return agentpacketrelay.DepositOutcome{Result: result}, nil
	}
	if c.relay.deposits == nil {
		c.relay.deposits = map[string][][]byte{}
	}
	c.relay.deposits[c.base] = append(c.relay.deposits[c.base], append([]byte(nil), envelope...))
	return agentpacketrelay.DepositOutcome{Result: agentpacketrelay.DepositStored, StatusCode: 201}, nil
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
		ExecutionID: strings.Repeat("cd", 32), ResponseSLASeconds: fxResponseSLA,
		ExpiresAtUnix: value.Proposal.ExpiresAtUnixSeconds}
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
	// The buyer card covers the latest response deadline (the Quote's
	// expiry plus the SLA) plus the retention plus 300 seconds.
	cover := time.Unix(int64(f.record.ExpiresAtUnix), 0).Add(fxResponseSLA*time.Second + 86400*time.Second + cardCoverSlack)
	if cards[0].NotBeforeUnix != uint64(fxNow.Unix()) || cards[0].NotAfterUnix != uint64(cover.Unix()) ||
		len(cards[0].Relays) != 1 || cards[0].Relays[0] != buyerRelay {
		t.Fatalf("buyer card %+v", cards[0])
	}
	if f.record.ExpiresAtUnix != uint64(fxNow.Add(30*time.Minute).Unix()) {
		t.Fatal("the fixture's Quote expires 30 minutes after now")
	}
}

// A held card that covers the window is reused: repeated checks of one
// purchase, or of purchases with the same window, draw no new key and sign
// nothing. A purchase needing a longer window gets a new card.
func TestAHeldBuyerCardThatCoversTheWindowIsReused(t *testing.T) {
	f := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	f.learn(t, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), 7*24*time.Hour))
	signer := &countingSigner{}
	f.carrier.config.Signer = signer
	for round := 0; round < 3; round++ {
		if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); err != nil {
			t.Fatal(err)
		}
	}
	keys, _, err := f.carrier.HeldKeys()
	if err != nil || len(keys) != 1 || signer.calls != 1 {
		t.Fatalf("three checks held %d keys and signed %d times: %v", len(keys), signer.calls, err)
	}
	longer := f.record
	longer.ExpiresAtUnix += 3600
	if err := f.carrier.CheckCarriage(context.Background(), longer, f.archive); err != nil {
		t.Fatal(err)
	}
	if keys, _, _ := f.carrier.HeldKeys(); len(keys) != 2 || signer.calls != 2 {
		t.Fatalf("a longer window reused a card that does not cover it: %d keys, %d signatures", len(keys), signer.calls)
	}
	// A shorter window reuses the card ending last.
	shorter := f.record
	shorter.ExpiresAtUnix -= 600
	if err := f.carrier.CheckCarriage(context.Background(), shorter, f.archive); err != nil || signer.calls != 2 {
		t.Fatalf("a shorter window signed again: %d %v", signer.calls, err)
	}
	// A reused card is still verified against finalized state.
	f.chain.agents[fxBuyerAgent].Tombstoned = true
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); !errors.Is(err, buyersdk.ErrAgentCard) {
		t.Fatalf("a reused card of a tombstoned Agent: %v", err)
	}
	// A held card that has not started yet is not reused.
	f.chain.agents[fxBuyerAgent].Tombstoned = false
	f.clock.advance(-time.Hour)
	if err := f.carrier.CheckCarriage(context.Background(), f.record, f.archive); err != nil || signer.calls != 3 {
		t.Fatalf("a card that starts in the future was reused: %d %v", signer.calls, err)
	}
}

// Every cheap item runs before the buyer card: a purchase that fails one
// signs nothing and draws no key.
func TestNoBuyerCardIsSignedForAPurchaseThatFailsACheapItem(t *testing.T) {
	for name, setup := range map[string]func(f *carrierFixture) (buyersdk.CallRecord, []byte){
		"no provider card": func(f *carrierFixture) (buyersdk.CallRecord, []byte) { return f.record, f.archive },
		"no relay": func(f *carrierFixture) (buyersdk.CallRecord, []byte) {
			f.learn(t, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), 7*24*time.Hour))
			f.relays.down[buyerRelay] = true
			return f.record, f.archive
		},
		"archive over the bound": func(f *carrierFixture) (buyersdk.CallRecord, []byte) {
			f.learn(t, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), 7*24*time.Hour))
			return f.record, make([]byte, nativecore.MaxAgentPacketTransportRequestBytes+1)
		},
		"window too long": func(f *carrierFixture) (buyersdk.CallRecord, []byte) {
			f.learn(t, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), 7*24*time.Hour))
			r := f.record
			r.ResponseSLASeconds = 30 * 24 * 3600
			return r, f.archive
		},
	} {
		f := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
		signer := &countingSigner{}
		f.carrier.config.Signer = signer
		record, archive := setup(f)
		if err := f.carrier.CheckCarriage(context.Background(), record, archive); err == nil {
			t.Fatalf("%s: the check passed", name)
		}
		if keys, _, _ := f.carrier.HeldKeys(); len(keys) != 0 || signer.calls != 0 {
			t.Errorf("%s: %d keys and %d signatures for a failing purchase", name, len(keys), signer.calls)
		}
	}
}

// The buyer card window is the Quote's expiry plus the SLA plus the
// retention plus 300 seconds; one beyond 30 days from now is refused with
// its own error, before anything is read.
func TestAPurchaseWhoseCardWindowExceedsThirtyDaysIsRefused(t *testing.T) {
	f := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	f.learn(t, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), 7*24*time.Hour))
	retention := uint64(86400)
	limit := fxNow.Add(agentpacketseal.MaxKeyCardLifetime)
	// The SLA that puts the window exactly at the 30-day limit.
	atLimit := f.record
	atLimit.ResponseSLASeconds = uint32(limit.Unix() - int64(atLimit.ExpiresAtUnix) - int64(retention) - 300)
	calls := f.chain.verifyCalls
	over := atLimit
	over.ResponseSLASeconds++
	if err := f.carrier.CheckCarriage(context.Background(), over, f.archive); !errors.Is(err, ErrCardWindowTooLong) {
		t.Fatalf("a window one second over 30 days: %v", err)
	}
	if f.chain.verifyCalls != calls {
		t.Fatal("a window over 30 days was refused only after reading finalized state")
	}
	window, err := buyerCardWindow(atLimit, retention)
	if err != nil || !window.Equal(limit) {
		t.Fatalf("window %v %v", window, err)
	}
	if _, err := buyerCardWindow(buyersdk.CallRecord{ExpiresAtUnix: ^uint64(0) - 10, ResponseSLASeconds: 100}, retention); !errors.Is(err, ErrCardWindowTooLong) {
		t.Fatalf("an overflowing window: %v", err)
	}
	if _, err := buyerCardWindow(buyersdk.CallRecord{}, retention); err == nil {
		t.Fatal("a call without a Quote expiry got a window")
	}
}

// countingSigner signs as keycardtest.Keys does and counts the signatures.
type countingSigner struct {
	mu    sync.Mutex
	calls int
}

func (s *countingSigner) Sign(ctx context.Context, controller string, use mldsa44.Use, payload []byte) (mldsa44.Signature, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return keycardtest.Keys.Sign(ctx, controller, use, payload)
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
	if _, err := f.carrier.BuyerCard(context.Background(), fxNow.Add(time.Hour)); err == nil {
		t.Fatal("a card whose file does not name its key ID was reused")
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
	if _, err := f.carrier.BuyerCard(context.Background(), fxNow.Add(time.Hour)); err == nil {
		t.Fatal("a card of another Agent was reused")
	}
}

// withCarrier makes the agent's carriage check the real Carrier, on the
// fixture's clock.
func withCarrier(t *testing.T, f *fixture) (*Carrier, *fakeChain) {
	t.Helper()
	chain := &fakeChain{owner: fxProvider, clock: f.clock, agents: map[string]*nativev1.AgentStateV1{
		fxProvider:   keycardtest.Agent(fxProvider, providerController),
		fxBuyerAgent: keycardtest.Agent(fxBuyerAgent, buyerController)}}
	relays := &fakeRelay{down: map[string]bool{}, asked: map[string]int{}}
	carrier, err := NewCarrier(CarrierConfig{StateDir: privateDir(t), BuyerAgentID: fxBuyerAgent, Network: fxNetwork(),
		Controller: buyerController, ControllerKeyID: controllerID(t, buyerController), Signer: keycardtest.Keys,
		Verifier: keycardtest.Keys, Cards: chain, Relays: []string{buyerRelay}, RelayClient: relays.client, Now: f.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	f.carriage.mu.Lock()
	f.carriage.carrier = carrier
	f.carriage.mu.Unlock()
	return carrier, chain
}

func learnAt(t *testing.T, carrier *Carrier, raw []byte) {
	t.Helper()
	if _, err := carrier.LearnProviderCard(context.Background(), buyersdk.ProviderCardFromQuote, fxCapability, raw); err != nil {
		t.Fatal(err)
	}
}

// confirm presents a requested purchase and confirms it with its code.
func confirm(t *testing.T, f *fixture, view PurchaseView) error {
	t.Helper()
	presentation, err := f.agent.Present(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.agent.Decide(context.Background(), DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm,
		Code: presentation.Code})
	return err
}

// Section 7.1 item 3 through the agent: a purchase is paid only with a
// verified provider card that is usable when the call is sent.
func TestTheAgentPaysOnlyWithAUsableVerifiedProviderCard(t *testing.T) {
	t.Run("usable", func(t *testing.T) {
		f := newFixture(t)
		carrier, _ := withCarrier(t, f)
		learnAt(t, carrier, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), 7*24*time.Hour))
		if err := confirm(t, f, f.requested(t, keyA)); err != nil {
			t.Fatal(err)
		}
		if len(f.buyer.sent()) != 1 {
			t.Fatal("a carriable purchase was not sent")
		}
	})
	t.Run("missing", func(t *testing.T) {
		f := newFixture(t)
		withCarrier(t, f)
		_, err := f.agent.Prepare(context.Background(), PrepareParams{QuoteID: f.quoteID, IdempotencyKey: keyA,
			ArchiveBase64: base64.StdEncoding.EncodeToString(sourceTar(t))})
		if err == nil || codeOf(t, err) != CodeNotCarriable {
			t.Fatalf("a purchase without a provider card was kept: %v", err)
		}
		if len(f.buyer.sent()) != 0 {
			t.Fatal("a purchase without a provider card was sent")
		}
	})
	t.Run("expired", func(t *testing.T) {
		f := newFixture(t)
		carrier, _ := withCarrier(t, f)
		// The card covers the response deadline at prepare, and no longer a
		// minute later, when the human confirms.
		learnAt(t, carrier, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), time.Hour+fxResponseSLA*time.Second+30*time.Second))
		view := f.requested(t, keyA)
		f.clock.advance(time.Minute)
		if err := confirm(t, f, view); err == nil || codeOf(t, err) != CodeNotCarriable {
			t.Fatalf("a purchase whose card no longer covers the window was confirmed: %v", err)
		}
		if len(f.buyer.sent()) != 0 {
			t.Fatal("a purchase with an expiring card was sent")
		}
	})
	t.Run("invalid", func(t *testing.T) {
		f := newFixture(t)
		carrier, chain := withCarrier(t, f)
		f.clock.advance(-6 * time.Minute)
		learnAt(t, carrier, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), 7*24*time.Hour))
		f.clock.advance(6 * time.Minute)
		view := f.requested(t, keyA)
		// The card's Agent stops being the Capability's owner; the next
		// verification, due before the send, refuses the card.
		chain.mu.Lock()
		chain.owner = "agent_" + strings.Repeat("66", 32)
		chain.mu.Unlock()
		f.clock.advance(5 * time.Minute)
		if err := confirm(t, f, view); err == nil || codeOf(t, err) != CodeNotCarriable {
			t.Fatalf("a purchase whose card no longer verifies was confirmed: %v", err)
		}
		if len(f.buyer.sent()) != 0 {
			t.Fatal("a purchase with an invalid card was sent")
		}
	})
}

// A purchase whose buyer card would outlive 30 days is refused at prepare
// with its own code, and again with the same code when prepared again.
func TestAPurchaseNeedingACardBeyondThirtyDaysIsRefusedAtPrepareWithItsOwnCode(t *testing.T) {
	f := newFixture(t)
	carrier, _ := withCarrier(t, f)
	learnAt(t, carrier, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), 7*24*time.Hour))
	f.buyer.responseSLA = 30 * 24 * 3600
	prepare := func() error {
		_, err := f.agent.Prepare(context.Background(), PrepareParams{QuoteID: f.quoteID, IdempotencyKey: keyA,
			ArchiveBase64: base64.StdEncoding.EncodeToString(sourceTar(t))})
		return err
	}
	for round := 0; round < 2; round++ {
		err := prepare()
		if err == nil || codeOf(t, err) != CodeCardWindowTooLong {
			t.Fatalf("round %d: a purchase needing a card beyond 30 days: %v", round, err)
		}
		var known *Error
		if !errors.As(err, &known) || known.Disposition != DispositionNever {
			t.Fatalf("round %d: disposition %+v", round, known)
		}
	}
	if keys, _, _ := carrier.HeldKeys(); len(keys) != 0 || len(f.buyer.sent()) != 0 {
		t.Fatal("a refused purchase drew a key or was sent")
	}
}
