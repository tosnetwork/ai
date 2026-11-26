package mcpbuyer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
)

// Search and quote tool names (section 4.2).
const (
	ToolSearch = "tos_buyer_search"
	ToolQuote  = "tos_buyer_quote"
)

// ErrOfferFileRefused wraps every reason an offer_file path is refused.
var ErrOfferFileRefused = errors.New("the offer file is refused")

// offerFileMessage is the fixed text of every offer-file refusal; it never
// names the path.
const offerFileMessage = "offer_file must be an absolute path of a regular file of at most 256 KiB under a workspace root"

// LoadOfferFile reads an offer file under a workspace root, without
// following a link in its last element, of at most MaxOfferFileBytes.
func (r Roots) LoadOfferFile(path string) ([]byte, error) {
	real, err := r.resolve(path)
	if err != nil {
		return nil, errors.Join(ErrOfferFileRefused, err)
	}
	raw, err := readBounded(real, buyeragent.MaxOfferFileBytes)
	if err != nil {
		return nil, errors.Join(ErrOfferFileRefused, err)
	}
	return raw, nil
}

func (t *Tools) registerMarket(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{Name: ToolSearch, Title: "Search TOS software-work offers",
		Description: "Lists candidate software-work offers from the buyer agent's configured discovery sources, or every " +
			"version of one capability_id, and returns only those whose offer verifies for this buyer in finalized " +
			"chain state, with price, storage fee, deadlines and the checkpoint they were read at. Candidates finalized " +
			"state does not confirm are dropped and counted. It pays nothing." + untrustedNote,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, t.search)
	mcp.AddTool(server, &mcp.Tool{Name: ToolQuote, Title: "Quote one TOS software-work offer",
		Description: "Verifies one Capability version's offer in finalized chain state and builds its Quote there, or " +
			"validates a gateway's Quote against it, and stores the Quote for " + ToolPrepare + " under the returned " +
			"quote_id. It reports whether the purchase could be carried to the provider. It pays nothing." + untrustedNote,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: false},
	}, t.quote)
}

// Offer is an offer as a tool result shows it.
type Offer struct {
	Asset                    *nativev1.TOSAssetIdentityV1 `json:"asset,omitempty"`
	PriceAtomic              string                       `json:"price_atomic,omitempty"`
	Checkpoint               uint64                       `json:"checkpoint"`
	CapabilityID             string                       `json:"capability_id"`
	CapabilityVersion        string                       `json:"capability_version"`
	ProviderAgentID          string                       `json:"provider_agent_id"`
	ManifestDigest           string                       `json:"manifest_digest"`
	Actor                    string                       `json:"actor"`
	AttestorKeyID            string                       `json:"attestor_key_id"`
	TermsHash                string                       `json:"terms_hash"`
	PriceNanoTOS             string                       `json:"price_nanotos"`
	StorageFeeNanoTOS        string                       `json:"storage_fee_nanotos"`
	PaymentNanoTOS           string                       `json:"payment_nanotos"`
	AllowanceNanoTOS         string                       `json:"execution_allowance_nanotos"`
	CleanupBountyNanoTOS     string                       `json:"cleanup_bounty_nanotos"`
	ResponseSLASeconds       uint32                       `json:"response_sla_seconds"`
	RefundClaimWindowSeconds uint32                       `json:"refund_claim_window_seconds"`
	RetentionSeconds         uint64                       `json:"retention_seconds"`
	OpenAccess               bool                         `json:"open_access"`
	ProviderCardHeld         bool                         `json:"provider_card_held"`
	ProviderName             UntrustedText                `json:"untrusted_provider_name"`
	ProviderDescription      UntrustedText                `json:"untrusted_provider_description"`
}

func offerOf(view buyeragent.OfferView) Offer {
	return Offer{Asset: view.Asset, PriceAtomic: view.PriceAtomic, Checkpoint: view.Checkpoint, CapabilityID: view.CapabilityID, CapabilityVersion: view.CapabilityVersion,
		ProviderAgentID: view.ProviderAgentID, ManifestDigest: view.ManifestDigest, Actor: view.Actor,
		AttestorKeyID: view.AttestorKeyID, TermsHash: view.TermsHash, PriceNanoTOS: view.PriceNanoTOS,
		StorageFeeNanoTOS: view.StorageFeeNanoTOS, PaymentNanoTOS: view.PaymentNanoTOS, AllowanceNanoTOS: view.AllowanceNanoTOS,
		CleanupBountyNanoTOS: view.CleanupBountyNanoTOS, ResponseSLASeconds: view.ResponseSLASeconds,
		RefundClaimWindowSeconds: view.RefundClaimWindowSeconds, RetentionSeconds: view.RetentionSeconds,
		OpenAccess: view.OpenAccess, ProviderCardHeld: view.ProviderCardHeld,
		ProviderName: untrusted(view.ProviderName), ProviderDescription: untrusted(view.ProviderDescription)}
}

// renderOffer writes one offer's server-written lines and its delimited
// untrusted spans.
func renderOffer(b *strings.Builder, d delimiter, o Offer) {
	fmt.Fprintf(b, "Capability %s %s from provider %s, read at finalized checkpoint %d.\n", o.CapabilityID,
		o.CapabilityVersion, o.ProviderAgentID, o.Checkpoint)
	if o.Asset != nil {
		fmt.Fprintf(b, "Token asset %s, wallet code %s (%d decimals): price %s atomic (%s); storage fee %s nanoTOS, funding fees quoted separately at prepare. Actor %s.\n", "0:"+hex.EncodeToString(o.Asset.Master.AccountId), o.Asset.WalletCodeHash, o.Asset.Decimals, o.PriceAtomic, buyeragent.AtomicAmount(o.PriceAtomic, uint8(o.Asset.Decimals)), o.StorageFeeNanoTOS, o.Actor)
	} else {
		fmt.Fprintf(b, "Attached payment %s nanoTOS: price %s, storage fee %s (not refunded), and an allowance of %s whose "+
			"unused part returns. Response SLA %d s, refund window %d s, cleanup bounty %s nanoTOS, result kept %d s. "+
			"Provider key card held: %t.\n", o.PaymentNanoTOS, o.PriceNanoTOS, o.StorageFeeNanoTOS, o.AllowanceNanoTOS,
			o.ResponseSLASeconds, o.RefundClaimWindowSeconds, o.CleanupBountyNanoTOS, o.RetentionSeconds, o.ProviderCardHeld)
	}
	b.WriteString(d.span("Provider name", o.ProviderName))
	b.WriteString(d.span("Provider description", o.ProviderDescription))
}

// SearchInput is tos_buyer_search's input.
type SearchInput struct {
	Query        string `json:"query,omitempty" jsonschema:"words to search the discovery sources for, at most 256 bytes"`
	CapabilityID string `json:"capability_id,omitempty" jsonschema:"list every version of this Capability: cap_ and 64 lowercase hex digits"`
	PageSize     int    `json:"page_size,omitempty" jsonschema:"candidates to verify, 1 to 50; default 20"`
	PageToken    string `json:"page_token,omitempty" jsonschema:"the next_page_token of the previous page"`
}

// SearchResult is the structured content of tos_buyer_search.
type SearchResult struct {
	Checkpoint    uint64     `json:"checkpoint"`
	Offers        []Offer    `json:"offers"`
	Dropped       int        `json:"dropped_candidates"`
	FailedSources int        `json:"failed_sources"`
	Next          string     `json:"next_page_token,omitempty"`
	Error         *ToolError `json:"error,omitempty"`
}

func (t *Tools) search(ctx context.Context, _ *mcp.CallToolRequest, input SearchInput) (*mcp.CallToolResult, SearchResult, error) {
	size := input.PageSize
	if size == 0 {
		size = 20
	}
	var page buyeragent.SearchView
	if err := t.agent.Call(ctx, "search", buyeragent.SearchParams{Query: input.Query, CapabilityID: input.CapabilityID,
		PageSize: size, PageToken: input.PageToken}, &page); err != nil {
		result, toolErr := refused(err)
		return result, SearchResult{Offers: []Offer{}, Error: toolErr}, nil
	}
	out := SearchResult{Checkpoint: page.Checkpoint, Offers: []Offer{}, Dropped: page.Dropped,
		FailedSources: page.FailedSources, Next: page.Next}
	d, err := newDelimiter(t.random)
	if err != nil {
		return nil, SearchResult{}, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d offers verified at finalized checkpoint %d; %d candidates dropped; %d sources did not answer.\n",
		len(page.Offers), page.Checkpoint, page.Dropped, page.FailedSources)
	for _, view := range page.Offers {
		offer := offerOf(view)
		out.Offers = append(out.Offers, offer)
		renderOffer(&b, d, offer)
	}
	if page.Next != "" {
		b.WriteString("More candidates follow: call again with the structured result's next_page_token.\n")
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, out, nil
}

// QuoteInput is tos_buyer_quote's input.
type QuoteInput struct {
	CapabilityID      string `json:"capability_id" jsonschema:"the Capability: cap_ and 64 lowercase hex digits"`
	CapabilityVersion string `json:"capability_version" jsonschema:"the Capability version, 1 to 128 printable ASCII bytes"`
	OfferFile         string `json:"offer_file,omitempty" jsonschema:"absolute path of an offer file under a workspace root"`
	Source            string `json:"source,omitempty" jsonschema:"local (the agent builds the Quote; default) or gateway"`
}

// Quote is a stored Quote as a tool result shows it.
type Quote struct {
	QuoteID             string `json:"quote_id"`
	Source              string `json:"quote_source"`
	Offer               Offer  `json:"offer"`
	QuoteExpiresUnix    uint64 `json:"quote_expires_at_unix"`
	MaxRequestBytes     uint32 `json:"max_request_bytes"`
	ProviderCardRefused bool   `json:"provider_card_refused"`
	Carriable           bool   `json:"carriable"`
	NotCarriable        string `json:"not_carriable_item,omitempty"`
}

// QuoteResult is the structured content of tos_buyer_quote.
type QuoteResult struct {
	Quote *Quote     `json:"quote,omitempty"`
	Error *ToolError `json:"error,omitempty"`
}

func (t *Tools) quote(ctx context.Context, _ *mcp.CallToolRequest, input QuoteInput) (*mcp.CallToolResult, QuoteResult, error) {
	params := buyeragent.QuoteParams{CapabilityID: input.CapabilityID, CapabilityVersion: input.CapabilityVersion,
		Source: input.Source}
	if input.OfferFile != "" {
		raw, err := t.roots.LoadOfferFile(input.OfferFile)
		if err != nil {
			result, toolErr := refused(err)
			return result, QuoteResult{Error: toolErr}, nil
		}
		params.OfferFileBase64 = base64.StdEncoding.EncodeToString(raw)
	}
	var view buyeragent.QuoteView
	if err := t.agent.Call(ctx, "quote", params, &view); err != nil {
		result, toolErr := refused(err)
		return result, QuoteResult{Error: toolErr}, nil
	}
	quote := &Quote{QuoteID: view.QuoteID, Source: view.Source, Offer: offerOf(view.Offer),
		QuoteExpiresUnix: view.QuoteExpiresUnix, MaxRequestBytes: view.MaxRequestBytes,
		ProviderCardRefused: view.ProviderCardRefused, Carriable: view.Carriable, NotCarriable: view.NotCarriable}
	d, err := newDelimiter(t.random)
	if err != nil {
		return nil, QuoteResult{}, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Quote %s (%s), valid until unix %d; nothing is paid. Prepare a purchase from it with %s.\n",
		quote.QuoteID, quote.Source, quote.QuoteExpiresUnix, ToolPrepare)
	if quote.Carriable {
		b.WriteString("The purchase can be carried to the provider.\n")
	} else {
		b.WriteString("The purchase cannot be carried to the provider now (" + quote.NotCarriable + "); prepare will refuse it.\n")
	}
	if quote.ProviderCardRefused {
		b.WriteString("A provider key card that came with the offer did not verify and was not kept.\n")
	}
	renderOffer(&b, d, quote.Offer)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, QuoteResult{Quote: quote}, nil
}
