package buyeragent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"sort"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"github.com/tosnetwork/ai/protocol/pkg/quoteprovider"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactorindex"
	"google.golang.org/protobuf/proto"
)

// Search and quote bounds (MCP_BUYER_ADAPTER_V1 sections 4.3 and 4.4).
const (
	// MaxQueryBytes bounds a search query.
	MaxQueryBytes = 256
	// MaxSearchPageSize bounds the candidates one search verifies.
	MaxSearchPageSize = 50
	// MaxHintsPerSource bounds the candidates taken from one hint source.
	MaxHintsPerSource = 100
	// MaxCandidates bounds the candidates one search considers.
	MaxCandidates = 400
	// MaxHintSources bounds the configured hint sources.
	MaxHintSources = 8
	// LocalQuoteTTL is how long a locally built Quote is valid. With
	// QuoteClockSkew it bounds how long any Quote may run: a later expiry
	// would hold a budget reservation longer and widen the buyer card's
	// window.
	LocalQuoteTTL = 15 * time.Minute
	// QuoteClockSkew is how far a gateway's clock may run ahead of the
	// agent's. A gateway stamps its own clock plus the 15-minute lifetime,
	// so without a margin a second of drift would refuse every gateway
	// Quote. Five minutes is the clock skew the lifecycle sends already
	// allow (section 11.2).
	QuoteClockSkew = 5 * time.Minute
	// SearchesPerMinute and QuotesPerMinute bound the searches and quotes
	// the agent serves in any minute: each one costs quorum reads, and a
	// search several per candidate.
	SearchesPerMinute = 30
	QuotesPerMinute   = 20
)

// rateWindow admits at most limit events in any window.
type rateWindow struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	times  []time.Time
}

// admit records an event at now unless limit events already fall within
// the window before it. An event stamped after now (a clock stepped back)
// still counts.
func (r *rateWindow) admit(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.times[:0]
	for _, at := range r.times {
		if now.Sub(at) < r.window {
			kept = append(kept, at)
		}
	}
	r.times = kept
	if len(r.times) >= r.limit {
		return false
	}
	r.times = append(r.times, now)
	return true
}

// Quote sources.
const (
	QuoteSourceLocal   = "local"
	QuoteSourceGateway = "gateway"
)

// quoteCaller names the agent as the caller of the Quotes it builds or
// requests.
const quoteCaller = "tos-service-buyer"

// QuoteCarrier is what search and quote need of the carrier: learning a
// provider card from any source (verified before it is kept), the usable
// card of a provider, and the source-independent carriage items.
// *Carrier implements it.
type QuoteCarrier interface {
	LearnProviderCard(ctx context.Context, source buyersdk.ProviderCardSource, capabilityID string,
		raw []byte) (buyersdk.VerifiedProviderCard, error)
	ProviderCard(ctx context.Context, capabilityID, providerAgentID string, notAfter time.Time) (buyersdk.VerifiedProviderCard, error)
	CheckQuoteCarriage(ctx context.Context, record buyersdk.CallRecord) error
}

// OffersConfig wires search and quote.
type OffersConfig struct {
	Network *nativev1.NetworkDomain
	// RegistryCodeHash and ActorCodeHash pin the Native Registry and the
	// Service Actor release, as tvm-cell-sha256:<hex>.
	RegistryCodeHash string
	ActorCodeHash    string
	// BuyerWallet is the raw workchain-0 address the calls are sent from.
	BuyerWallet string
	// Sessions opens one quorum-finalized checkpoint per search or quote.
	Sessions serviceactorindex.Reader
	// Manifests keeps the manifest of every accepted Quote, for prepare.
	Manifests *ManifestStore
	// Hints are the configured hint sources; none means search only by
	// capability_id.
	Hints []HintSource
	// Gateway serves gateway Quotes; nil allows only local Quotes.
	Gateway QuoteGateway
	Cards   QuoteCarrier
	Now     func() time.Time
	Random  func([]byte) error
}

// Offers runs search and quote. Every fact it returns is read at one
// finalized checkpoint; hint sources, offer files and gateways only name
// candidates and supply bytes the finalized digests check.
type Offers struct {
	config   OffersConfig
	searches *rateWindow
	quotes   *rateWindow
}

// NewOffers refuses an incomplete configuration.
func NewOffers(config OffersConfig) (*Offers, error) {
	if config.Network == nil || config.Sessions == nil || config.Manifests == nil || config.Cards == nil ||
		len(config.Hints) > MaxHintSources {
		return nil, errors.New("invalid buyer offers configuration")
	}
	for _, hint := range config.Hints {
		if hint == nil {
			return nil, errors.New("invalid buyer offers configuration")
		}
	}
	if !pinnedCellHash(config.RegistryCodeHash) || !pinnedCellHash(config.ActorCodeHash) {
		return nil, errors.New("the Registry and Service Actor code hashes must be pinned as tvm-cell-sha256:<hex>")
	}
	if address, err := nativecore.StandardAddress(config.BuyerWallet); err != nil || address.Workchain != 0 {
		return nil, errors.New("the buyer wallet must be a raw workchain 0 address")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = func(value []byte) error { _, err := rand.Read(value); return err }
	}
	config.Network = proto.Clone(config.Network).(*nativev1.NetworkDomain)
	config.Hints = append([]HintSource(nil), config.Hints...)
	return &Offers{config: config, searches: &rateWindow{limit: SearchesPerMinute, window: time.Minute},
		quotes: &rateWindow{limit: QuotesPerMinute, window: time.Minute}}, nil
}

func pinnedCellHash(value string) bool {
	const prefix = "tvm-cell-sha256:"
	return len(value) == len(prefix)+64 && value[:len(prefix)] == prefix && hex64Pattern.MatchString(value[len(prefix):])
}

// oneSession hands out one opened finalized checkpoint, so discovery and
// the local Quote read the same state.
type oneSession struct{ session serviceactorindex.Session }

func (o oneSession) BeginSession(context.Context) (serviceactorindex.Session, error) {
	return o.session, nil
}

type oneQuoteSession struct{ session serviceactorindex.Session }

func (o oneQuoteSession) BeginSession(context.Context) (serviceactor.Session, error) {
	return o.session, nil
}

// OfferView is one offer verified at a finalized checkpoint (section 4.3).
// Only the untrusted_* fields carry text a third party wrote.
type OfferView struct {
	Checkpoint               uint64 `json:"checkpoint"`
	CapabilityID             string `json:"capability_id"`
	CapabilityVersion        string `json:"capability_version"`
	ProviderAgentID          string `json:"provider_agent_id"`
	ManifestDigest           string `json:"manifest_digest"`
	Actor                    string `json:"actor"`
	AttestorKeyID            string `json:"attestor_key_id"`
	PolicyVersion            uint32 `json:"policy_version"`
	TermsHash                string `json:"terms_hash"`
	PriceNanoTOS             string `json:"price_nanotos"`
	StorageFeeNanoTOS        string `json:"storage_fee_nanotos"`
	PaymentNanoTOS           string `json:"payment_nanotos"`
	AllowanceNanoTOS         string `json:"execution_allowance_nanotos"`
	CleanupBountyNanoTOS     string `json:"cleanup_bounty_nanotos"`
	ResponseSLASeconds       uint32 `json:"response_sla_seconds"`
	RefundClaimWindowSeconds uint32 `json:"refund_claim_window_seconds"`
	RetentionSeconds         uint64 `json:"retention_seconds"`
	OpenAccess               bool   `json:"open_access"`
	ProviderCardHeld         bool   `json:"provider_card_held"`
	ProviderName             string `json:"untrusted_provider_name"`
	ProviderDescription      string `json:"untrusted_provider_description"`
}

// offerView renders a verified offer with the text of the manifest bytes
// the finalized digest checked.
func (o *Offers) offerView(ctx context.Context, offer *serviceactorindex.Offer, manifestCBOR []byte) (OfferView, error) {
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(manifestCBOR)
	if err != nil {
		return OfferView{}, errors.New("a verified manifest does not decode")
	}
	price, priceOK := new(big.Int).SetString(offer.PriceNanoTOS, 10)
	fee, feeOK := new(big.Int).SetString(offer.StorageFeeNanoTOS, 10)
	if !priceOK || !feeOK {
		return OfferView{}, errors.New("a verified offer carries an invalid amount")
	}
	payment, err := nativecore.MinimumServiceActorCallPayment(price, fee)
	if err != nil {
		return OfferView{}, err
	}
	_, cardErr := o.config.Cards.ProviderCard(ctx, offer.CapabilityID, offer.ProviderAgentID, o.config.Now())
	return OfferView{Checkpoint: offer.Checkpoint, CapabilityID: offer.CapabilityID, CapabilityVersion: offer.CapabilityVersion,
		ProviderAgentID: offer.ProviderAgentID, ManifestDigest: offer.ManifestDigest, Actor: offer.Actor,
		AttestorKeyID: offer.AttestorKeyID, PolicyVersion: offer.PolicyVersion, TermsHash: offer.TermsHash,
		PriceNanoTOS: offer.PriceNanoTOS, StorageFeeNanoTOS: offer.StorageFeeNanoTOS, PaymentNanoTOS: payment.String(),
		AllowanceNanoTOS:     strconv.Itoa(nativecore.ServiceActorAdmissionGasAllowance),
		CleanupBountyNanoTOS: offer.CleanupBountyNano, ResponseSLASeconds: offer.ResponseSLASeconds,
		RefundClaimWindowSeconds: offer.RefundWindowSeconds, RetentionSeconds: manifest.RetentionSeconds,
		OpenAccess: offer.OpenAccess, ProviderCardHeld: cardErr == nil, ProviderName: manifest.Name,
		ProviderDescription: manifest.Description}, nil
}

// SearchParams is a client's search request.
type SearchParams struct {
	Query        string `json:"query,omitempty"`
	CapabilityID string `json:"capability_id,omitempty"`
	PageSize     int    `json:"page_size"`
	PageToken    string `json:"page_token,omitempty"`
}

func (p SearchParams) check() (*serviceactorindex.Candidate, error) {
	if len(p.Query) > MaxQueryBytes || !utf8.ValidString(p.Query) {
		return nil, refusal(CodeBadInput, "query must be valid UTF-8 of at most 256 bytes", nil)
	}
	if p.CapabilityID != "" && !capabilityIDPattern.MatchString(p.CapabilityID) {
		return nil, refusal(CodeBadInput, "capability_id must be cap_ and 64 lowercase hex digits", nil)
	}
	if p.PageSize < 1 || p.PageSize > MaxSearchPageSize {
		return nil, refusal(CodeBadInput, "page_size must be 1 to 50", nil)
	}
	if p.PageToken == "" {
		return nil, nil
	}
	after, ok := parsePageToken(p.PageToken)
	if !ok {
		return nil, refusal(CodeBadInput, "page_token is not a token this agent issued", nil)
	}
	return &after, nil
}

// A page token is the last candidate of the previous page:
// "<capability_id>@<version>".
func pageToken(candidate serviceactorindex.Candidate) string {
	return candidate.CapabilityID + "@" + candidate.Version
}

func parsePageToken(token string) (serviceactorindex.Candidate, bool) {
	const idLength = len("cap_") + 64
	if len(token) < idLength+2 || token[idLength] != '@' {
		return serviceactorindex.Candidate{}, false
	}
	candidate := serviceactorindex.Candidate{CapabilityID: token[:idLength], Version: token[idLength+1:]}
	if !capabilityIDPattern.MatchString(candidate.CapabilityID) || !validVersion(candidate.Version) {
		return serviceactorindex.Candidate{}, false
	}
	return candidate, true
}

// SearchView is one page of verified offers (section 4.3).
type SearchView struct {
	Checkpoint uint64      `json:"checkpoint"`
	Offers     []OfferView `json:"offers"`
	// Dropped counts the candidates of this page that a hint source listed
	// but finalized state did not confirm, and malformed hints.
	Dropped int `json:"dropped_candidates"`
	// FailedSources counts the hint sources that did not answer.
	FailedSources int    `json:"failed_sources"`
	Next          string `json:"next_page_token,omitempty"`
}

// Search lists candidate offers from the hint sources, or every version of
// one Capability, and returns those whose offer verifies for this buyer at
// one finalized checkpoint.
func (o *Offers) Search(ctx context.Context, params SearchParams) (SearchView, error) {
	after, err := params.check()
	if err != nil {
		return SearchView{}, err
	}
	if !o.searches.admit(o.config.Now()) {
		return SearchView{}, refusal(CodeRateLimited, "too many searches in the last minute", nil)
	}
	view := SearchView{Offers: []OfferView{}}
	seen := map[serviceactorindex.Candidate]bool{}
	var candidates []serviceactorindex.Candidate
	add := func(candidate serviceactorindex.Candidate) {
		if !capabilityIDPattern.MatchString(candidate.CapabilityID) || !validVersion(candidate.Version) {
			view.Dropped++
			return
		}
		if !seen[candidate] {
			seen[candidate] = true
			candidates = append(candidates, candidate)
		}
	}
	if params.CapabilityID == "" {
		if len(o.config.Hints) == 0 {
			return SearchView{}, refusal(CodeNotConfigured, "no search source is configured; name a capability_id", nil)
		}
		for _, source := range o.config.Hints {
			hints, err := source.Hints(ctx, params.Query, MaxHintsPerSource)
			if err != nil {
				view.FailedSources++
				continue
			}
			if len(hints) > MaxHintsPerSource {
				hints = hints[:MaxHintsPerSource]
			}
			for _, hint := range hints {
				add(serviceactorindex.Candidate{CapabilityID: hint.CapabilityID, Version: hint.Version})
			}
		}
		if view.FailedSources == len(o.config.Hints) {
			return SearchView{}, refusal(CodeDependencyUnavailable, "no search source answered", nil)
		}
	}
	session, err := o.config.Sessions.BeginSession(ctx)
	if err != nil {
		return SearchView{}, refusal(CodeDependencyUnavailable, "finalized state is unavailable", err)
	}
	view.Checkpoint = session.Checkpoint()
	if params.CapabilityID != "" {
		// The Capability's own finalized versions are the candidates: no
		// hint is needed when the client names the Capability.
		state, found, err := session.ResolveRegistry(ctx, params.CapabilityID)
		if err != nil {
			return SearchView{}, refusal(CodeDependencyUnavailable, "finalized state is unavailable", err)
		}
		if !found || state.GetCapability().GetCapabilityId() != params.CapabilityID {
			return SearchView{}, refusal(CodeNotFound, "no Capability has this capability_id in finalized state", nil)
		}
		for _, version := range state.GetCapability().GetVersions() {
			if version != nil && !version.Revoked {
				add(serviceactorindex.Candidate{CapabilityID: params.CapabilityID, Version: version.Version})
			}
		}
	}
	candidates = boundCandidates(candidates)
	recorder := o.recorder(nil)
	discovery, err := serviceactorindex.NewDiscovery(oneSession{session: session}, o.config.Network, recorder, o.config.ActorCodeHash)
	if err != nil {
		return SearchView{}, err
	}
	page, err := discovery.ListOffers(ctx, candidates, params.PageSize, after, o.config.BuyerWallet)
	if err != nil {
		return SearchView{}, refusal(CodeDependencyUnavailable, "finalized state is unavailable", err)
	}
	for _, result := range page.Results {
		if result.Offer == nil {
			view.Dropped++
			continue
		}
		manifestCBOR, ok := recorder.get(result.Offer.ManifestDigest)
		if !ok {
			view.Dropped++
			continue
		}
		offer, err := o.offerView(ctx, result.Offer, manifestCBOR)
		if err != nil {
			return SearchView{}, err
		}
		view.Offers = append(view.Offers, offer)
	}
	if page.NextAfter != nil {
		view.Next = pageToken(*page.NextAfter)
	}
	return view, nil
}

// boundCandidates sorts the candidates and takes the first MaxCandidates of
// them, before the page token applies, so the pages of one search walk one
// bounded set.
func boundCandidates(candidates []serviceactorindex.Candidate) []serviceactorindex.Candidate {
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].CapabilityID != candidates[j].CapabilityID {
			return candidates[i].CapabilityID < candidates[j].CapabilityID
		}
		return candidates[i].Version < candidates[j].Version
	})
	if len(candidates) > MaxCandidates {
		candidates = candidates[:MaxCandidates]
	}
	return candidates
}

// recorder asks the offer file's manifest first, then the local store,
// then each hint source.
func (o *Offers) recorder(offerManifest []byte) *manifestRecorder {
	recorder := &manifestRecorder{}
	if offerManifest != nil {
		recorder.sources = append(recorder.sources, func(context.Context, string) ([]byte, error) { return offerManifest, nil })
	}
	recorder.sources = append(recorder.sources, o.config.Manifests.Manifest)
	for _, source := range o.config.Hints {
		recorder.sources = append(recorder.sources, source.Manifest)
	}
	return recorder
}

// QuoteParams is a client's quote request.
type QuoteParams struct {
	CapabilityID      string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	// Source is local (the default) or gateway.
	Source string `json:"source,omitempty"`
	// OfferFileBase64 is an offer file's bytes, read by the MCP server from
	// a path under a workspace root.
	OfferFileBase64 string `json:"offer_file_base64,omitempty"`
}

func (p QuoteParams) check() (string, *offerFile, error) {
	if !capabilityIDPattern.MatchString(p.CapabilityID) {
		return "", nil, refusal(CodeBadInput, "capability_id must be cap_ and 64 lowercase hex digits", nil)
	}
	if !validVersion(p.CapabilityVersion) {
		return "", nil, refusal(CodeBadInput, "capability_version must be 1 to 128 bytes of 0x21 to 0x7e", nil)
	}
	source := p.Source
	if source == "" {
		source = QuoteSourceLocal
	}
	if source != QuoteSourceLocal && source != QuoteSourceGateway {
		return "", nil, refusal(CodeBadInput, "source must be local or gateway", nil)
	}
	if p.OfferFileBase64 == "" {
		return source, nil, nil
	}
	raw, err := canonicalBase64(p.OfferFileBase64, MaxOfferFileBytes)
	if err != nil {
		return "", nil, refusal(CodeBadInput, "offer_file_base64 is not canonical standard Base64", err)
	}
	offer, err := decodeOfferFile(raw)
	if err != nil {
		return "", nil, refusal(CodeBadInput, "the offer file breaks the offer-file rules", err)
	}
	if offer.CapabilityID != p.CapabilityID || offer.Version != p.CapabilityVersion {
		return "", nil, refusal(CodeBadInput, "the offer file is for another Capability or version", nil)
	}
	return source, &offer, nil
}

// QuoteView is a Quote the agent verified and stored (section 4.4).
type QuoteView struct {
	QuoteID string `json:"quote_id"`
	// Source says whether the agent built the Quote or validated a
	// gateway's.
	Source           string    `json:"quote_source"`
	Offer            OfferView `json:"offer"`
	QuoteExpiresUnix uint64    `json:"quote_expires_at_unix"`
	MaxRequestBytes  uint32    `json:"max_request_bytes"`
	// ProviderCardRefused reports a provider card that came with the offer
	// file or the gateway Quote and did not verify; it was not kept.
	ProviderCardRefused bool `json:"provider_card_refused"`
	Carriable           bool `json:"carriable"`
	// NotCarriable names the failing item of section 7.1 when Carriable is
	// false: card_window, item_1 to item_5, or other.
	NotCarriable string `json:"not_carriable_item,omitempty"`
}

// Quote verifies the offer at one finalized checkpoint and builds the Quote
// there, or validates a gateway's Quote and checks it field by field
// against that offer. It returns the Quote's package for the agent to
// store; nothing is paid or journaled.
func (o *Offers) Quote(ctx context.Context, params QuoteParams) (*nativev1.RequestQuoteProposalRequest,
	*nativev1.QuoteProposalPackageV1, QuoteView, error) {
	source, file, err := params.check()
	if err != nil {
		return nil, nil, QuoteView{}, err
	}
	if !o.quotes.admit(o.config.Now()) {
		return nil, nil, QuoteView{}, refusal(CodeRateLimited, "too many quotes in the last minute", nil)
	}
	request := &nativev1.RequestQuoteProposalRequest{CapabilityId: params.CapabilityID,
		CapabilityVersion: params.CapabilityVersion, BuyerAddress: o.config.BuyerWallet}
	var value *nativev1.QuoteProposalPackageV1
	var gatewayCard []byte
	if source == QuoteSourceGateway {
		if o.config.Gateway == nil {
			return nil, nil, QuoteView{}, refusal(CodeNotConfigured, "no gateway is configured; ask for a local Quote", nil)
		}
		stamped, err := o.stamped(request)
		if err != nil {
			return nil, nil, QuoteView{}, err
		}
		response, err := o.config.Gateway.RequestQuoteProposal(ctx, stamped)
		if err != nil {
			return nil, nil, QuoteView{}, refusal(CodeDependencyUnavailable, "the gateway did not serve a Quote", err)
		}
		value, gatewayCard = response.GetPackage(), response.GetProviderKeyCardPacketJson()
		if value == nil {
			return nil, nil, QuoteView{}, refusal(CodeOfferInvalid, "the gateway served no Quote package", nil)
		}
	}
	var offerManifest []byte
	if file != nil {
		offerManifest = file.Manifest
	}
	session, err := o.config.Sessions.BeginSession(ctx)
	if err != nil {
		return nil, nil, QuoteView{}, refusal(CodeDependencyUnavailable, "finalized state is unavailable", err)
	}
	recorder := o.recorder(offerManifest)
	discovery, err := serviceactorindex.NewDiscovery(oneSession{session: session}, o.config.Network, recorder, o.config.ActorCodeHash)
	if err != nil {
		return nil, nil, QuoteView{}, err
	}
	offer, err := discovery.DiscoverOffer(ctx, serviceactorindex.Candidate{CapabilityID: params.CapabilityID,
		Version: params.CapabilityVersion}, o.config.BuyerWallet)
	if err != nil {
		return nil, nil, QuoteView{}, discoveryRefusal(err)
	}
	manifestCBOR, ok := recorder.get(offer.ManifestDigest)
	if !ok {
		return nil, nil, QuoteView{}, errors.New("the verified manifest was not recorded")
	}
	if source == QuoteSourceLocal {
		if value, err = o.localQuote(ctx, session, request, offer, manifestCBOR); err != nil {
			return nil, nil, QuoteView{}, err
		}
	}
	now := o.config.Now()
	validated, err := quoteexchange.Validate(o.config.Network, request, value, now)
	if err != nil {
		return nil, nil, QuoteView{}, refusal(CodeOfferInvalid, "the Quote does not validate", err)
	}
	if validated.Proposal.ExpiresAtUnixSeconds > uint64(now.Add(LocalQuoteTTL+QuoteClockSkew).Unix()) {
		return nil, nil, QuoteView{}, refusal(CodeOfferInvalid,
			"the Quote expires later than the 15-minute Quote lifetime and 5 minutes of clock skew", nil)
	}
	if err := crossCheckQuote(validated, offer); err != nil {
		return nil, nil, QuoteView{}, refusal(CodeOfferInvalid, "the Quote differs from the finalized offer", err)
	}
	if _, err := o.config.Manifests.Put(manifestCBOR); err != nil {
		return nil, nil, QuoteView{}, err
	}
	view := QuoteView{Source: source, QuoteExpiresUnix: validated.Proposal.ExpiresAtUnixSeconds,
		MaxRequestBytes: validated.TransportBinding.MaxRequestBytes}
	// A card from either source is verified against finalized state before
	// it is kept; one that does not verify is reported and dropped.
	if file != nil && file.KeyCard != nil {
		if _, err := o.config.Cards.LearnProviderCard(ctx, buyersdk.ProviderCardFromOffer, params.CapabilityID, file.KeyCard); err != nil {
			view.ProviderCardRefused = true
		}
	}
	if len(gatewayCard) > 0 {
		if _, err := o.config.Cards.LearnProviderCard(ctx, buyersdk.ProviderCardFromQuote, params.CapabilityID, gatewayCard); err != nil {
			view.ProviderCardRefused = true
		}
	}
	if view.Offer, err = o.offerView(ctx, offer, manifestCBOR); err != nil {
		return nil, nil, QuoteView{}, err
	}
	packageBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(value)
	if err != nil {
		return nil, nil, QuoteView{}, err
	}
	carriageErr := o.config.Cards.CheckQuoteCarriage(ctx, buyersdk.CallRecord{BuyerWallet: o.config.BuyerWallet,
		CapabilityID: params.CapabilityID, CapabilityVersion: params.CapabilityVersion,
		PackageBase64: base64.StdEncoding.EncodeToString(packageBytes), BuyerAddressInReq: request.BuyerAddress,
		ExpiresAtUnix: validated.Proposal.ExpiresAtUnixSeconds, ResponseSLASeconds: offer.ResponseSLASeconds})
	view.Carriable, view.NotCarriable = carriageErr == nil, carriageItem(carriageErr)
	return request, value, view, nil
}

// stamped is the request with a fresh request context.
func (o *Offers) stamped(request *nativev1.RequestQuoteProposalRequest) (*nativev1.RequestQuoteProposalRequest, error) {
	var nonce [16]byte
	if err := o.config.Random(nonce[:]); err != nil {
		return nil, err
	}
	stamped := proto.Clone(request).(*nativev1.RequestQuoteProposalRequest)
	stamped.Context = gatewayContext("buyer-"+hex.EncodeToString(nonce[:]), quoteCaller, o.config.Now())
	return stamped, nil
}

// localQuote builds the Quote at the session the offer was verified at,
// to the Capability's finalized owner over Agent Packets.
func (o *Offers) localQuote(ctx context.Context, session serviceactorindex.Session, request *nativev1.RequestQuoteProposalRequest,
	offer *serviceactorindex.Offer, manifestCBOR []byte) (*nativev1.QuoteProposalPackageV1, error) {
	binding, err := nativecore.AgentPacketTransportBinding(offer.ProviderAgentID, nativecore.MaxAgentPacketTransportRequestBytes)
	if err != nil {
		return nil, refusal(CodeOfferInvalid, "the provider cannot be reached over Agent Packets", err)
	}
	provider, err := quoteprovider.New(quoteprovider.Config{Sessions: oneQuoteSession{session: session}, Network: o.config.Network,
		RegistryCodeHash: o.config.RegistryCodeHash, ProviderAgentID: offer.ProviderAgentID, ManifestCBOR: manifestCBOR,
		Transport: binding, ProposalTTL: LocalQuoteTTL, CallerID: quoteCaller, Now: o.config.Now, Random: o.config.Random})
	if err != nil {
		if errors.Is(err, railwork.ErrQuoteNotCarriable) {
			return nil, refusal(CodeNotCarriable, "the offer's Quotes cannot be carried to its provider", err)
		}
		return nil, refusal(CodeOfferInvalid, "a Quote cannot be built for the offer", err)
	}
	stamped, err := o.stamped(request)
	if err != nil {
		return nil, err
	}
	value, err := provider.RequestQuoteProposal(ctx, stamped)
	if err != nil {
		return nil, buildRefusal(err)
	}
	return value, nil
}

// discoveryRefusal tells discovery's verdict on finalized state, a
// StepError, from a read that did not complete.
func discoveryRefusal(err error) *Error {
	var step *serviceactor.StepError
	if errors.As(err, &step) {
		return refusal(CodeOfferInvalid, "finalized state does not verify the offer", err)
	}
	return refusal(CodeDependencyUnavailable, "finalized state is unavailable", err)
}

// buildRefusal tells a failed read while building a Quote, an Error with a
// cause, from a verdict on the state read.
func buildRefusal(err error) *Error {
	var read *quoteprovider.Error
	if errors.As(err, &read) && read.Unwrap() != nil {
		return refusal(CodeDependencyUnavailable, "finalized state is unavailable", err)
	}
	return refusal(CodeOfferInvalid, "a Quote cannot be built from finalized state", err)
}

// crossCheckQuote requires a validated Quote to carry exactly the finalized
// offer: the provider, manifest, actor, code, attestor, policy version,
// terms, price and storage fee, over Agent Packets to that provider.
func crossCheckQuote(validated *quoteexchange.Validated, offer *serviceactorindex.Offer) error {
	proposal := validated.Proposal
	switch {
	case proposal.CapabilityId != offer.CapabilityID || proposal.CapabilityVersion != offer.CapabilityVersion:
		return errors.New("the Quote names another Capability version")
	case proposal.ProviderAgentId != offer.ProviderAgentID:
		return errors.New("the Quote names another provider than the Capability's finalized owner")
	case proposal.ManifestDigest != offer.ManifestDigest:
		return errors.New("the Quote names another manifest than the finalized version")
	case validated.Rail.Actor != offer.Actor:
		return errors.New("the Quote names another actor than manifest key 21")
	case proposal.ActorCodeHash != offer.ActorCodeHash:
		return errors.New("the Quote names another actor code than the pinned release")
	case proposal.AttestorKeyId != offer.AttestorKeyID:
		return errors.New("the Quote names another attestor than the actor's")
	case proposal.PolicyVersion != offer.PolicyVersion:
		return errors.New("the Quote names another policy version than the actor's")
	case proposal.TermsHash != offer.TermsHash:
		return errors.New("the Quote names other terms than the actor's current terms")
	case proposal.PriceNanotos != offer.PriceNanoTOS:
		return errors.New("the Quote names another price than the actor's")
	case proposal.StorageFeeNanotos != offer.StorageFeeNanoTOS:
		return errors.New("the Quote names another storage fee than the actor's")
	}
	// Validate has bound an Agent Packet binding's recipient to the
	// proposal's provider, which is the finalized owner above.
	if _, err := validated.TransportBinding.AgentPacketRecipient(); err != nil {
		return ErrNotAgentPackets
	}
	return nil
}

// carriageItem names the item of section 7.1 a carriage error fails.
func carriageItem(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrCardWindowTooLong):
		return "card_window"
	case errors.Is(err, ErrNotAgentPackets):
		return "item_1"
	case errors.Is(err, railwork.ErrQuoteNotCarriable):
		return "item_2"
	case errors.Is(err, ErrNoProviderCard):
		return "item_3"
	case errors.Is(err, buyersdk.ErrAgentCard):
		return "item_4"
	case errors.Is(err, ErrRelaysUnavailable):
		return "item_5"
	}
	return "other"
}

// Search runs a client's search (section 4.3).
func (a *Agent) Search(ctx context.Context, params SearchParams) (SearchView, error) {
	if a.config.Offers == nil {
		return SearchView{}, refusal(CodeNotConfigured, "this agent is not configured for search and quote", nil)
	}
	return a.config.Offers.Search(ctx, params)
}

// Quote runs a client's quote (section 4.4) and stores the Quote for a
// later prepare under its quote ID.
func (a *Agent) Quote(ctx context.Context, params QuoteParams) (QuoteView, error) {
	if a.config.Offers == nil {
		return QuoteView{}, refusal(CodeNotConfigured, "this agent is not configured for search and quote", nil)
	}
	request, value, view, err := a.config.Offers.Quote(ctx, params)
	if err != nil {
		return QuoteView{}, err
	}
	if view.QuoteID, err = a.StoreQuote(request, value); err != nil {
		return QuoteView{}, err
	}
	return view, nil
}
