package buyeragent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/servicefixture"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactorindex"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

var (
	fxRegistryHash  = "tvm-cell-sha256:" + strings.Repeat("55", 32)
	fxActorCodeHash = "tvm-cell-sha256:" + strings.Repeat("88", 32)
	fxActor         = "0:" + strings.Repeat("77", 32)
	fxOtherAgent    = "agent_" + strings.Repeat("66", 32)
	// oneOverCardBound is a card one byte over its bound, whose Base64 is
	// no longer than that of a card at the bound.
	oneOverCardBound = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'{'}, quoteexchange.MaxProviderKeyCardBytes+1))
)

// offerChain is a fake finalized chain: each session is one checkpoint of
// the Capabilities, their owner Agents and the actors.
type offerChain struct {
	mu         sync.Mutex
	checkpoint uint64
	states     map[string]*nativev1.NativeStateV1
	actors     map[string]*toschain.ActorAccount
	sessions   int
	beginErr   error
}

func (c *offerChain) BeginSession(context.Context) (serviceactorindex.Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions++
	if c.beginErr != nil {
		return nil, c.beginErr
	}
	return &offerSession{chain: c, checkpoint: c.checkpoint}, nil
}

func (c *offerChain) opened() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessions
}

type offerSession struct {
	chain      *offerChain
	checkpoint uint64
}

func (s *offerSession) Checkpoint() uint64   { return s.checkpoint }
func (s *offerSession) ChainTime() time.Time { return fxNow }

func (s *offerSession) ResolveRegistry(_ context.Context, id string) (*nativev1.NativeStateV1, bool, error) {
	s.chain.mu.Lock()
	defer s.chain.mu.Unlock()
	state, ok := s.chain.states[id]
	if !ok {
		return nil, false, nil
	}
	copied := proto.Clone(state).(*nativev1.NativeStateV1)
	copied.Reference = &nativev1.ChainReference{FinalizedCheckpoint: s.checkpoint, ContractCodeHash: fxRegistryHash,
		TransactionHash: "sha256:" + strings.Repeat("77", 32)}
	return copied, true, nil
}

func (s *offerSession) ReadActor(_ context.Context, address string) (*toschain.ActorAccount, bool, error) {
	s.chain.mu.Lock()
	defer s.chain.mu.Unlock()
	account, ok := s.chain.actors[address]
	return account, ok, nil
}

func (s *offerSession) History(context.Context, string, *toschain.ActorTxID) (*toschain.ActorHistory, error) {
	return nil, errors.New("not used")
}

// fakeHints is a hint source: the hints it lists, an error instead, and the
// manifests it serves.
type fakeHints struct {
	mu        sync.Mutex
	hints     []Hint
	err       error
	manifests map[string][]byte
	queries   []string
}

func (h *fakeHints) Hints(_ context.Context, query string, _ int) ([]Hint, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.queries = append(h.queries, query)
	return append([]Hint(nil), h.hints...), h.err
}

func (h *fakeHints) Manifest(_ context.Context, digest string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	raw, ok := h.manifests[digest]
	if !ok {
		return nil, errors.New("unknown manifest")
	}
	return raw, nil
}

// fakeGateway serves one Quote response.
type fakeGateway struct {
	mu       sync.Mutex
	response *nativev1.RequestQuoteProposalResponse
	err      error
	requests int
}

func (g *fakeGateway) RequestQuoteProposal(context.Context, *nativev1.RequestQuoteProposalRequest) (*nativev1.RequestQuoteProposalResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests++
	return g.response, g.err
}

type offersFixture struct {
	*fixture
	carrier  *carrierFixture
	chain    *offerChain
	offers   *Offers
	store    *ManifestStore
	manifest []byte
	digest   string
	hints    *fakeHints
	gateway  *fakeGateway
}

func fxSettlement() servicefixture.Settlement {
	return servicefixture.Settlement{ActorAccount: bytes.Repeat([]byte{0x77}, 32),
		ActorCodeHash: bytes.Repeat([]byte{0x88}, 32), AttestorKey: mldsa44.KeyIDText(fxKeyID)}
}

// addOffer puts a Capability version, its owner Agent and its actor into
// finalized state.
func (c *offerChain) addOffer(t *testing.T, capabilityID, owner string, manifest nativecore.SoftwareWorkManifestV1) []byte {
	t.Helper()
	network := servicefixture.Network()
	encoded, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	c.states[capabilityID] = &nativev1.NativeStateV1{Network: network, State: &nativev1.NativeStateV1_Capability{
		Capability: &nativev1.CapabilityStateV1{CapabilityId: capabilityID, OwnerAgentId: owner,
			Versions: []*nativev1.CapabilityVersionV1{{Version: manifest.Version, ManifestDigest: digest}}}}}
	c.states[owner] = &nativev1.NativeStateV1{Network: network, State: &nativev1.NativeStateV1_Agent{
		Agent: &nativev1.AgentStateV1{AgentId: owner}}}
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: network,
		CapabilityID: capabilityID, ProviderAgentID: owner, CapabilityVersion: manifest.Version, ManifestDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	terms := servicefixture.Terms(fxKeyID, metadata)
	policy := nativecore.ServiceActorPolicyV1{PolicyVersion: terms.PolicyVersion, PricePerCall: terms.PricePerCall,
		StorageFee: terms.StorageFee, CleanupBounty: terms.CleanupBounty, ResponseSLA: terms.ResponseSLA,
		RefundClaimWindow: terms.RefundClaimWindow, OpenAccess: true, MetadataHash: terms.MetadataHash,
		ProofSchemeHash: terms.ProofSchemeHash, HasAttestor: true, AttestorKeyID: fxKeyID, AttestorKey: fxKey}
	data, err := servicefixture.ActorData("0:"+strings.Repeat("11", 32), policy, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	actor := "0:" + hex.EncodeToString(manifest.Settlement.ActorAccountID)
	c.actors[actor] = &toschain.ActorAccount{Address: actor, CodeHash: fxActorCodeHash, Data: data}
	return encoded
}

func newOffersFixture(t *testing.T) *offersFixture {
	t.Helper()
	f := newFixture(t)
	carrier := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	chain := &offerChain{checkpoint: 41, states: map[string]*nativev1.NativeStateV1{}, actors: map[string]*toschain.ActorAccount{}}
	manifest := chain.addOffer(t, fxCapability, fxProvider, servicefixture.Manifest("1.0.0", fxSettlement()))
	digest := manifestDigest(manifest)
	store, err := NewManifestStore(filepath.Join(privateDir(t), "manifests"))
	if err != nil {
		t.Fatal(err)
	}
	hints := &fakeHints{manifests: map[string][]byte{digest: manifest}}
	gateway := &fakeGateway{}
	offers, err := NewOffers(OffersConfig{Network: servicefixture.Network(), RegistryCodeHash: fxRegistryHash,
		ActorCodeHash: fxActorCodeHash, BuyerWallet: fxBuyer, Sessions: chain, Manifests: store,
		Hints: []HintSource{hints}, Gateway: gateway, Cards: carrier.carrier, Now: carrier.clock.Now, Random: f.random.Read})
	if err != nil {
		t.Fatal(err)
	}
	f.agent.config.Offers = offers
	return &offersFixture{fixture: f, carrier: carrier, chain: chain, offers: offers, store: store, manifest: manifest,
		digest: digest, hints: hints, gateway: gateway}
}

func (f *offersFixture) providerCard(t *testing.T, agent string) []byte {
	t.Helper()
	return providerCardFor(t, agent, 1, fxNow.Add(-time.Hour), 7*24*time.Hour)
}

// offerFileBytes is an offer file for the fixture's Capability version.
func offerFileBytes(t *testing.T, manifest []byte, card []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	file := map[string]any{"schema": OfferFileSchema, "capability_id": fxCapability, "version": "1.0.0",
		"provider_agent_id": fxProvider, "manifest_digest": manifestDigest(manifest),
		"manifest_cbor_base64": base64.StdEncoding.EncodeToString(manifest), "updated_unix": fxNow.Unix()}
	if card != nil {
		file["relay_key_card_base64"] = base64.StdEncoding.EncodeToString(card)
	}
	if mutate != nil {
		mutate(file)
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *offersFixture) quote(t *testing.T, params QuoteParams) QuoteView {
	t.Helper()
	view, err := f.agent.Quote(context.Background(), params)
	if err != nil {
		t.Fatalf("quote: %v", err)
	}
	return view
}

func localParams() QuoteParams {
	return QuoteParams{CapabilityID: fxCapability, CapabilityVersion: "1.0.0"}
}

func TestALocalQuoteIsBuiltAtOneFinalizedCheckpointAndStored(t *testing.T) {
	f := newOffersFixture(t)
	// No hint source holds the manifest: only the offer file does.
	f.hints.manifests = map[string][]byte{}
	params := localParams()
	params.OfferFileBase64 = base64.StdEncoding.EncodeToString(offerFileBytes(t, f.manifest, f.providerCard(t, fxProvider), nil))
	view := f.quote(t, params)
	if f.chain.opened() != 1 {
		t.Fatalf("the quote read %d checkpoints, not one", f.chain.opened())
	}
	if view.Source != QuoteSourceLocal || !view.Carriable || view.NotCarriable != "" || view.ProviderCardRefused ||
		!view.Offer.ProviderCardHeld || view.Offer.Checkpoint != 41 || view.Offer.ProviderAgentID != fxProvider ||
		view.Offer.ManifestDigest != f.digest || view.Offer.Actor != fxActor || view.Offer.PriceNanoTOS != "300000000" ||
		view.Offer.StorageFeeNanoTOS != "200000000" || view.Offer.RetentionSeconds != 86400 ||
		view.Offer.ProviderName != "Deterministic Go test" || view.MaxRequestBytes != nativecore.MaxAgentPacketTransportRequestBytes ||
		view.QuoteExpiresUnix != uint64(fxNow.Add(LocalQuoteTTL).Unix()) {
		t.Fatalf("quote view %+v", view)
	}
	if f.gateway.requests != 0 {
		t.Fatal("a local quote asked the gateway")
	}
	// The stored Quote is the one prepare uses, and the manifest is kept
	// for the buyer's admission at prepare.
	request, value, err := f.agent.loadQuote(view.QuoteID)
	if err != nil || request.BuyerAddress != fxBuyer || value.Proposal.ProviderAgentId != fxProvider {
		t.Fatalf("stored Quote: %v", err)
	}
	if raw, err := f.store.Manifest(context.Background(), f.digest); err != nil || !bytes.Equal(raw, f.manifest) {
		t.Fatalf("the manifest was not stored: %v", err)
	}
	purchase, err := f.agent.Prepare(context.Background(), PrepareParams{QuoteID: view.QuoteID, IdempotencyKey: keyA,
		ArchiveBase64: base64.StdEncoding.EncodeToString(sourceTar(t))})
	if err != nil || purchase.State != StateAwaitingConfirmation || purchase.ProviderAgentID != fxProvider {
		t.Fatalf("prepare from the quote: %+v %v", purchase, err)
	}
}

// gatewayPackage is the fixture's Quote as a gateway would serve it,
// expiring in 10 minutes, with mutate applied to the proposal.
func gatewayPackage(t *testing.T, binding nativecore.TransportBindingV1,
	mutate func(*nativev1.QuoteProposalV1)) *nativev1.QuoteProposalPackageV1 {
	t.Helper()
	_, value := quotePackageWith(t, fxNow, binding)
	value.Proposal.ExpiresAtUnixSeconds = uint64(fxNow.Add(10 * time.Minute).Unix())
	if mutate != nil {
		mutate(value.Proposal)
	}
	return value
}

func gatewayParams() QuoteParams {
	params := localParams()
	params.Source = QuoteSourceGateway
	return params
}

func TestAGatewayQuoteIsCrossCheckedAgainstTheFinalizedOffer(t *testing.T) {
	f := newOffersFixture(t)
	binding := agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes)
	f.gateway.response = &nativev1.RequestQuoteProposalResponse{Package: gatewayPackage(t, binding, nil),
		ProviderKeyCardPacketJson: f.providerCard(t, fxProvider)}
	view := f.quote(t, gatewayParams())
	if view.Source != QuoteSourceGateway || !view.Carriable || !view.Offer.ProviderCardHeld || f.chain.opened() != 1 {
		t.Fatalf("gateway quote %+v (%d checkpoints)", view, f.chain.opened())
	}
	other := servicefixture.Manifest("1.0.0", fxSettlement())
	other.Description = "Another description than the finalized manifest's."
	otherCBOR, otherDigest, err := nativecore.CanonicalSoftwareWorkManifest(other)
	if err != nil {
		t.Fatal(err)
	}
	otherProvider := agentPacketsTo(t, fxOtherAgent)
	https := nativecore.TransportBindingV1{SecurityMode: nativecore.TransportHTTPS, MaxRequestBytes: 1 << 20,
		BaseURL: "https://provider.example"}
	cases := map[string]*nativev1.QuoteProposalPackageV1{
		"provider": gatewayPackage(t, otherProvider, func(p *nativev1.QuoteProposalV1) { p.ProviderAgentId = fxOtherAgent }),
		"manifest": func() *nativev1.QuoteProposalPackageV1 {
			value := gatewayPackage(t, binding, func(p *nativev1.QuoteProposalV1) { p.ManifestDigest = otherDigest })
			value.CanonicalManifestCbor = otherCBOR
			return value
		}(),
		"policy-version": gatewayPackage(t, binding, func(p *nativev1.QuoteProposalV1) { p.PolicyVersion++ }),
		"terms":          gatewayPackage(t, binding, func(p *nativev1.QuoteProposalV1) { p.TermsHash = strings.Repeat("ee", 32) }),
		"price":          gatewayPackage(t, binding, func(p *nativev1.QuoteProposalV1) { p.PriceNanotos = "300000001" }),
		"storage-fee":    gatewayPackage(t, binding, func(p *nativev1.QuoteProposalV1) { p.StorageFeeNanotos = "200000001" }),
		"transport":      gatewayPackage(t, https, nil),
		"expired": gatewayPackage(t, binding, func(p *nativev1.QuoteProposalV1) {
			p.ExpiresAtUnixSeconds = uint64(fxNow.Unix())
		}),
	}
	for name, value := range cases {
		f.gateway.response = &nativev1.RequestQuoteProposalResponse{Package: value}
		_, err := f.agent.Quote(context.Background(), gatewayParams())
		if err == nil || codeOf(t, err) != CodeOfferInvalid {
			t.Errorf("%s: a gateway Quote that differs from the finalized offer: %v", name, err)
		}
	}
	// A gateway that serves no package, or fails, is refused.
	f.gateway.response = &nativev1.RequestQuoteProposalResponse{}
	if _, err := f.agent.Quote(context.Background(), gatewayParams()); err == nil || codeOf(t, err) != CodeOfferInvalid {
		t.Fatalf("an empty gateway answer: %v", err)
	}
	f.gateway.err = errors.New("gateway down")
	if _, err := f.agent.Quote(context.Background(), gatewayParams()); err == nil || codeOf(t, err) != CodeDependencyUnavailable {
		t.Fatalf("a failed gateway: %v", err)
	}
}

func agentPacketsTo(t *testing.T, agent string) nativecore.TransportBindingV1 {
	t.Helper()
	binding, err := nativecore.AgentPacketTransportBinding(agent, nativecore.MaxAgentPacketTransportRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

// A card that comes with a Quote or an offer file is kept only after it
// verifies against finalized state; one that does not is reported, and the
// Quote cannot be carried without a card.
func TestAProviderCardFromAQuoteOrOfferFileIsVerifiedBeforeItIsKept(t *testing.T) {
	f := newOffersFixture(t)
	binding := agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes)
	f.gateway.response = &nativev1.RequestQuoteProposalResponse{Package: gatewayPackage(t, binding, nil),
		ProviderKeyCardPacketJson: f.providerCard(t, fxOtherAgent)}
	view := f.quote(t, gatewayParams())
	if !view.ProviderCardRefused || view.Offer.ProviderCardHeld || view.Carriable || view.NotCarriable != "item_3" {
		t.Fatalf("a gateway card of another Agent: %+v", view)
	}
	params := localParams()
	params.OfferFileBase64 = base64.StdEncoding.EncodeToString(offerFileBytes(t, f.manifest, f.providerCard(t, fxOtherAgent), nil))
	if view = f.quote(t, params); !view.ProviderCardRefused || view.Offer.ProviderCardHeld || view.Carriable {
		t.Fatalf("an offer-file card of another Agent: %+v", view)
	}
	// The provider's own card from the offer file is learned.
	params.OfferFileBase64 = base64.StdEncoding.EncodeToString(offerFileBytes(t, f.manifest, f.providerCard(t, fxProvider), nil))
	if view = f.quote(t, params); view.ProviderCardRefused || !view.Offer.ProviderCardHeld || !view.Carriable {
		t.Fatalf("the provider's offer-file card: %+v", view)
	}
}

func TestAQuoteOfAnOfferFinalizedStateDoesNotConfirmIsRefused(t *testing.T) {
	f := newOffersFixture(t)
	// An offer file whose manifest is not the finalized version's, with no
	// other source of the finalized manifest.
	f.hints.manifests = map[string][]byte{}
	other := servicefixture.Manifest("1.0.0", fxSettlement())
	other.Name = "Another name"
	otherCBOR, _, err := nativecore.CanonicalSoftwareWorkManifest(other)
	if err != nil {
		t.Fatal(err)
	}
	params := localParams()
	params.OfferFileBase64 = base64.StdEncoding.EncodeToString(offerFileBytes(t, otherCBOR, nil, nil))
	if _, err := f.agent.Quote(context.Background(), params); err == nil || codeOf(t, err) != CodeOfferInvalid {
		t.Fatalf("an offer file with another manifest: %v", err)
	}
	f.hints.manifests = map[string][]byte{f.digest: f.manifest}
	// A Capability finalized state does not hold.
	missing := localParams()
	missing.CapabilityID = "cap_" + strings.Repeat("9", 64)
	if _, err := f.agent.Quote(context.Background(), missing); err == nil || codeOf(t, err) != CodeOfferInvalid {
		t.Fatalf("a Capability not in finalized state: %v", err)
	}
	// An actor that does not admit this buyer.
	f.chain.actors[fxActor].Data.Policy.OpenAccess = false
	if _, err := f.agent.Quote(context.Background(), localParams()); err == nil || codeOf(t, err) != CodeOfferInvalid {
		t.Fatalf("an actor closed to this buyer: %v", err)
	}
	f.chain.actors[fxActor].Data.Policy.OpenAccess = true
	// Finalized state that cannot be read is a dependency failure.
	f.chain.beginErr = errors.New("no quorum")
	if _, err := f.agent.Quote(context.Background(), localParams()); err == nil || codeOf(t, err) != CodeDependencyUnavailable {
		t.Fatalf("unreadable finalized state: %v", err)
	}
	if purchases, err := os.ReadDir(f.agent.store.dir("quotes")); err != nil || len(purchases) != 1 {
		t.Fatalf("a refused quote was stored: %d %v", len(purchases), err)
	}
}

func TestQuoteInputsAreValidated(t *testing.T) {
	f := newOffersFixture(t)
	file := func(mutate func(map[string]any)) string {
		return base64.StdEncoding.EncodeToString(offerFileBytes(t, f.manifest, nil, mutate))
	}
	cases := map[string]QuoteParams{
		"capability":       {CapabilityID: "cap_" + strings.Repeat("A", 64), CapabilityVersion: "1.0.0"},
		"empty-version":    {CapabilityID: fxCapability},
		"long-version":     {CapabilityID: fxCapability, CapabilityVersion: strings.Repeat("1", 129)},
		"space-version":    {CapabilityID: fxCapability, CapabilityVersion: "1.0 .0"},
		"high-version":     {CapabilityID: fxCapability, CapabilityVersion: "1.0.\x7f"},
		"source":           {CapabilityID: fxCapability, CapabilityVersion: "1.0.0", Source: "relay"},
		"offer-base64":     {CapabilityID: fxCapability, CapabilityVersion: "1.0.0", OfferFileBase64: file(nil) + "\n"},
		"offer-long":       {CapabilityID: fxCapability, CapabilityVersion: "1.0.0", OfferFileBase64: strings.Repeat("A", base64.StdEncoding.EncodedLen(MaxOfferFileBytes)+4)},
		"offer-schema":     {CapabilityID: fxCapability, CapabilityVersion: "1.0.0", OfferFileBase64: file(func(m map[string]any) { m["schema"] = "tos.openfox.rail-offer.v1" })},
		"offer-unknown":    {CapabilityID: fxCapability, CapabilityVersion: "1.0.0", OfferFileBase64: file(func(m map[string]any) { m["zzz_price"] = "1" })},
		"offer-capability": {CapabilityID: fxCapability, CapabilityVersion: "1.0.0", OfferFileBase64: file(func(m map[string]any) { m["capability_id"] = "cap_" + strings.Repeat("9", 64) })},
		"offer-version":    {CapabilityID: fxCapability, CapabilityVersion: "1.0.0", OfferFileBase64: file(func(m map[string]any) { m["version"] = "2.0.0" })},
		"offer-provider":   {CapabilityID: fxCapability, CapabilityVersion: "1.0.0", OfferFileBase64: file(func(m map[string]any) { m["provider_agent_id"] = "agent_x" })},
		"offer-digest":     {CapabilityID: fxCapability, CapabilityVersion: "1.0.0", OfferFileBase64: file(func(m map[string]any) { m["manifest_digest"] = "sha256:x" })},
		"offer-manifest":   {CapabilityID: fxCapability, CapabilityVersion: "1.0.0", OfferFileBase64: file(func(m map[string]any) { m["manifest_cbor_base64"] = "AA==\n" })},
		"offer-card":       {CapabilityID: fxCapability, CapabilityVersion: "1.0.0", OfferFileBase64: file(func(m map[string]any) { m["relay_key_card_base64"] = oneOverCardBound })},
		"offer-card-long":  {CapabilityID: fxCapability, CapabilityVersion: "1.0.0", OfferFileBase64: file(func(m map[string]any) { m["relay_key_card_base64"] = strings.Repeat("A", 22000) })},
	}
	for name, params := range cases {
		if _, err := f.agent.Quote(context.Background(), params); err == nil || codeOf(t, err) != CodeBadInput {
			t.Errorf("%s: %v", name, err)
		}
	}
	if f.chain.opened() != 0 || f.gateway.requests != 0 {
		t.Fatal("an invalid quote request read finalized state or asked the gateway")
	}
	// Without a gateway only local Quotes are served.
	f.offers.config.Gateway = nil
	if _, err := f.agent.Quote(context.Background(), gatewayParams()); err == nil || codeOf(t, err) != CodeNotConfigured {
		t.Fatalf("a gateway Quote without a gateway: %v", err)
	}
}

func TestAQuoteThatCannotBeCarriedIsReportedWithItsItem(t *testing.T) {
	f := newOffersFixture(t)
	view := f.quote(t, localParams())
	if view.Carriable || view.NotCarriable != "item_3" || view.QuoteID == "" {
		t.Fatalf("a Quote with no provider card: %+v", view)
	}
	f.carrier.learn(t, f.providerCard(t, fxProvider))
	f.carrier.relays.down[providerRelay] = true
	if view = f.quote(t, localParams()); view.Carriable || view.NotCarriable != "item_5" {
		t.Fatalf("a Quote whose provider relays are down: %+v", view)
	}
	if carriageItem(ErrCardWindowTooLong) != "card_window" || carriageItem(ErrNotAgentPackets) != "item_1" ||
		carriageItem(fmt.Errorf("x: %w", buyersdk.ErrAgentCard)) != "item_4" || carriageItem(errors.New("x")) != "other" {
		t.Fatal("carriage items are misnamed")
	}
}

// The quote-time check runs every item that needs no source: a package a
// rail task cannot carry fails it, while prepare's check adds the archive.
func TestTheQuoteCarriageCheckRunsTheSourceIndependentItems(t *testing.T) {
	f := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	f.learn(t, providerCardFor(t, fxProvider, 1, fxNow.Add(-time.Hour), 7*24*time.Hour))
	if err := f.carrier.CheckQuoteCarriage(context.Background(), f.record); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(f.record.PackageBase64)
	if err != nil {
		t.Fatal(err)
	}
	// Bytes the protocol does not define still travel in the task.
	raw = protowire.AppendTag(raw, 99, protowire.BytesType)
	raw = protowire.AppendBytes(raw, bytes.Repeat([]byte{1}, 40_000))
	big := f.record
	big.PackageBase64 = base64.StdEncoding.EncodeToString(raw)
	if err := f.carrier.CheckQuoteCarriage(context.Background(), big); carriageItem(err) != "item_2" {
		t.Fatalf("a package no task can carry: %v", err)
	}
	long := f.record
	long.ExpiresAtUnix += uint64(31 * 24 * 3600)
	if err := f.carrier.CheckQuoteCarriage(context.Background(), long); !errors.Is(err, ErrCardWindowTooLong) {
		t.Fatalf("a window over 30 days: %v", err)
	}
}

func TestSearchReturnsOnlyOffersFinalizedStateConfirms(t *testing.T) {
	f := newOffersFixture(t)
	f.carrier.learn(t, f.providerCard(t, fxProvider))
	f.hints.hints = []Hint{{CapabilityID: fxCapability, Version: "1.0.0"},
		{CapabilityID: "cap_" + strings.Repeat("9", 64), Version: "1.0.0"},
		{CapabilityID: "not a capability", Version: "1.0.0"}}
	failing := &fakeHints{err: errors.New("down")}
	f.offers.config.Hints = append(f.offers.config.Hints, failing)
	view, err := f.agent.Search(context.Background(), SearchParams{Query: "go test", PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Offers) != 1 || view.Dropped != 2 || view.FailedSources != 1 || view.Checkpoint != 41 || view.Next != "" {
		t.Fatalf("search view %+v", view)
	}
	offer := view.Offers[0]
	if offer.CapabilityID != fxCapability || offer.ProviderAgentID != fxProvider || !offer.ProviderCardHeld ||
		offer.ProviderName != "Deterministic Go test" || offer.PaymentNanoTOS == "" || offer.Checkpoint != 41 {
		t.Fatalf("offer %+v", offer)
	}
	if f.chain.opened() != 1 || f.hints.queries[0] != "go test" {
		t.Fatalf("search read %d checkpoints, queries %v", f.chain.opened(), f.hints.queries)
	}
	// Every source failing is a dependency failure; no source at all needs
	// a capability_id.
	f.offers.config.Hints = []HintSource{failing}
	if _, err := f.agent.Search(context.Background(), SearchParams{PageSize: 10}); err == nil ||
		codeOf(t, err) != CodeDependencyUnavailable {
		t.Fatalf("every source failed: %v", err)
	}
	f.offers.config.Hints = nil
	if _, err := f.agent.Search(context.Background(), SearchParams{PageSize: 10}); err == nil || codeOf(t, err) != CodeNotConfigured {
		t.Fatalf("no source: %v", err)
	}
}

// A manifest source that serves bytes of another digest is passed over for
// the next one, so a bad hint source cannot hide an offer.
func TestAManifestSourceWithWrongBytesIsPassedOver(t *testing.T) {
	f := newOffersFixture(t)
	wrong := &fakeHints{manifests: map[string][]byte{f.digest: append(append([]byte(nil), f.manifest...), 0)}}
	f.offers.config.Hints = []HintSource{wrong, f.hints}
	f.hints.hints = []Hint{{CapabilityID: fxCapability, Version: "1.0.0"}}
	view, err := f.agent.Search(context.Background(), SearchParams{PageSize: 10})
	if err != nil || len(view.Offers) != 1 || view.Dropped != 0 {
		t.Fatalf("search %+v: %v", view, err)
	}
}

func TestSearchByCapabilityIDReadsItsFinalizedVersions(t *testing.T) {
	f := newOffersFixture(t)
	f.offers.config.Hints = nil
	f.offers.config.Manifests = f.store
	if _, err := f.store.Put(f.manifest); err != nil {
		t.Fatal(err)
	}
	capability := f.chain.states[fxCapability].GetCapability()
	capability.Versions = append(capability.Versions, &nativev1.CapabilityVersionV1{Version: "0.9.0",
		ManifestDigest: "sha256:" + strings.Repeat("ab", 32), Revoked: true})
	view, err := f.agent.Search(context.Background(), SearchParams{CapabilityID: fxCapability, PageSize: 10})
	if err != nil || len(view.Offers) != 1 || view.Offers[0].CapabilityVersion != "1.0.0" || view.Dropped != 0 {
		t.Fatalf("search by capability %+v: %v", view, err)
	}
	if _, err := f.agent.Search(context.Background(), SearchParams{CapabilityID: "cap_" + strings.Repeat("9", 64),
		PageSize: 10}); err == nil || codeOf(t, err) != CodeNotFound {
		t.Fatalf("an unknown Capability: %v", err)
	}
}

func TestSearchInputsAreValidated(t *testing.T) {
	f := newOffersFixture(t)
	cases := map[string]SearchParams{
		"query-long":    {Query: strings.Repeat("q", MaxQueryBytes+1), PageSize: 10},
		"query-utf8":    {Query: "\xff", PageSize: 10},
		"capability":    {CapabilityID: "cap_1", PageSize: 10},
		"page-zero":     {PageSize: 0},
		"page-large":    {PageSize: MaxSearchPageSize + 1},
		"token-shape":   {PageSize: 10, PageToken: "x"},
		"token-id":      {PageSize: 10, PageToken: "cap_" + strings.Repeat("Z", 64) + "@1.0.0"},
		"token-sep":     {PageSize: 10, PageToken: fxCapability + "#1.0.0"},
		"token-version": {PageSize: 10, PageToken: fxCapability + "@1 0"},
	}
	for name, params := range cases {
		if _, err := f.agent.Search(context.Background(), params); err == nil || codeOf(t, err) != CodeBadInput {
			t.Errorf("%s: %v", name, err)
		}
	}
	if f.chain.opened() != 0 || len(f.hints.queries) != 0 {
		t.Fatal("an invalid search read a source")
	}
	if _, err := f.agent.Search(context.Background(), SearchParams{Query: strings.Repeat("q", MaxQueryBytes), PageSize: MaxSearchPageSize,
		PageToken: fxCapability + "@0.0.1"}); err != nil {
		t.Fatalf("a search at its bounds: %v", err)
	}
}

func bogusHints(from, count int) []Hint {
	hints := make([]Hint, 0, count)
	for index := from; index < from+count; index++ {
		hints = append(hints, Hint{CapabilityID: fmt.Sprintf("cap_%064x", index), Version: "1.0.0"})
	}
	return hints
}

// pages runs a search to its last page and counts the pages.
func pages(t *testing.T, f *offersFixture) int {
	t.Helper()
	token, count := "", 0
	for {
		view, err := f.agent.Search(context.Background(), SearchParams{PageSize: MaxSearchPageSize, PageToken: token})
		if err != nil {
			t.Fatal(err)
		}
		count++
		if view.Next == "" || count > 20 {
			return count
		}
		token = view.Next
	}
}

func TestSearchCandidatesAreBoundedPerSourceAndInTotal(t *testing.T) {
	f := newOffersFixture(t)
	f.hints.hints = bogusHints(0, 150)
	if got := pages(t, f); got != 2 {
		t.Fatalf("one source's 150 hints took %d pages, not the 100 hints of 2", got)
	}
	var sources []HintSource
	for index := 0; index < 5; index++ {
		sources = append(sources, &fakeHints{hints: bogusHints(index*100, 100)})
	}
	f.offers.config.Hints = sources
	if got := pages(t, f); got != MaxCandidates/MaxSearchPageSize {
		t.Fatalf("500 hints took %d pages, not the %d of 400 candidates", got, MaxCandidates/MaxSearchPageSize)
	}
}

func TestTheManifestStoreServesOnlyBytesOfTheirDigest(t *testing.T) {
	f := newOffersFixture(t)
	digest, err := f.store.Put(f.manifest)
	if err != nil || digest != f.digest {
		t.Fatalf("put: %s %v", digest, err)
	}
	if _, err := f.store.Manifest(context.Background(), "sha256:../../"+strings.Repeat("a", 58)); err == nil {
		t.Fatal("a digest naming another path was served")
	}
	path := filepath.Join(f.store.dir, strings.TrimPrefix(digest, "sha256:")+".cbor")
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append([]byte(nil), f.manifest...), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Manifest(context.Background(), digest); err == nil {
		t.Fatal("tampered manifest bytes were served")
	}
	base := privateDir(t)
	if err := os.Mkdir(filepath.Join(base, "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManifestStore(filepath.Join(base, "a") + "/../m"); err == nil {
		t.Fatal("an unclean manifest directory was accepted")
	}
	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManifestStore(open); err == nil {
		t.Fatal("a manifest directory open to others was accepted")
	}
}

func TestOffersConfigurationIsValidated(t *testing.T) {
	f := newOffersFixture(t)
	good := f.offers.config
	cases := map[string]func(*OffersConfig){
		"network":        func(c *OffersConfig) { c.Network = nil },
		"sessions":       func(c *OffersConfig) { c.Sessions = nil },
		"store":          func(c *OffersConfig) { c.Manifests = nil },
		"cards":          func(c *OffersConfig) { c.Cards = nil },
		"registry":       func(c *OffersConfig) { c.RegistryCodeHash = "tvm-cell-sha512:" + strings.Repeat("55", 32) },
		"registry-empty": func(c *OffersConfig) { c.RegistryCodeHash = "" },
		"registry-hex":   func(c *OffersConfig) { c.RegistryCodeHash = "tvm-cell-sha256:" + strings.Repeat("5G", 32) },
		"actor":          func(c *OffersConfig) { c.ActorCodeHash = "tvm-cell-sha256:" + strings.Repeat("8", 63) },
		"wallet":         func(c *OffersConfig) { c.BuyerWallet = "-1:" + strings.Repeat("21", 32) },
		"hint":           func(c *OffersConfig) { c.Hints = []HintSource{nil} },
		"hints": func(c *OffersConfig) {
			c.Hints = make([]HintSource, MaxHintSources+1)
			for index := range c.Hints {
				c.Hints[index] = f.hints
			}
		},
	}
	for name, mutate := range cases {
		config := good
		mutate(&config)
		if _, err := NewOffers(config); err == nil {
			t.Errorf("%s: an invalid configuration was accepted", name)
		}
	}
	// An agent without search and quote refuses both.
	f.agent.config.Offers = nil
	if _, err := f.agent.Search(context.Background(), SearchParams{PageSize: 1}); err == nil || codeOf(t, err) != CodeNotConfigured {
		t.Fatal("an agent without offers searched")
	}
	if _, err := f.agent.Quote(context.Background(), localParams()); err == nil || codeOf(t, err) != CodeNotConfigured {
		t.Fatal("an agent without offers quoted")
	}
}
