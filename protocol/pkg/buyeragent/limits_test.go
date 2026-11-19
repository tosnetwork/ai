package buyeragent

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

// A gateway Quote may run at most the local Quote lifetime: a later expiry
// would hold the budget reservation longer and widen the buyer card.
func TestAGatewayQuoteExpiringAfterTheQuoteLifetimeIsRefused(t *testing.T) {
	f := newOffersFixture(t)
	f.carrier.learn(t, f.providerCard(t, fxProvider))
	binding := agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes)
	at := uint64(fxNow.Add(LocalQuoteTTL).Unix())
	f.gateway.response = &nativev1.RequestQuoteProposalResponse{Package: gatewayPackage(t, binding,
		func(p *nativev1.QuoteProposalV1) { p.ExpiresAtUnixSeconds = at })}
	if view := f.quote(t, gatewayParams()); view.QuoteExpiresUnix != at {
		t.Fatalf("a Quote expiring at the lifetime: %+v", view)
	}
	f.gateway.response = &nativev1.RequestQuoteProposalResponse{Package: gatewayPackage(t, binding,
		func(p *nativev1.QuoteProposalV1) { p.ExpiresAtUnixSeconds = at + 1 })}
	if _, err := f.agent.Quote(context.Background(), gatewayParams()); err == nil || codeOf(t, err) != CodeOfferInvalid {
		t.Fatalf("a Quote expiring after the lifetime: %v", err)
	}
	if quotes, err := os.ReadDir(f.agent.store.dir("quotes")); err != nil || len(quotes) != 2 {
		t.Fatalf("the refused Quote was stored: %d %v", len(quotes), err)
	}
}

func rateLimited(t *testing.T, err error) bool {
	t.Helper()
	var known *Error
	if !errors.As(err, &known) {
		return false
	}
	if known.Code == CodeRateLimited && known.Disposition != DispositionSameAfterBackoff {
		t.Fatalf("a rate refusal with disposition %s", known.Disposition)
	}
	return known.Code == CodeRateLimited
}

// Searches and quotes are bounded per minute; a refused input does not
// count, and the bound frees as the minute passes.
func TestSearchAndQuoteAreBoundedPerMinute(t *testing.T) {
	f := newOffersFixture(t)
	search := func(params SearchParams) error {
		_, err := f.agent.Search(context.Background(), params)
		return err
	}
	for index := 0; index < 5; index++ {
		if err := search(SearchParams{PageSize: 0}); err == nil || codeOf(t, err) != CodeBadInput {
			t.Fatalf("an invalid search: %v", err)
		}
	}
	for index := 0; index < SearchesPerMinute; index++ {
		if err := search(SearchParams{PageSize: 1}); err != nil {
			t.Fatalf("search %d: %v", index, err)
		}
	}
	if err := search(SearchParams{PageSize: 1}); !rateLimited(t, err) {
		t.Fatalf("a search over the bound: %v", err)
	}
	// A clock stepped back still sees the searches.
	f.carrier.clock.advance(-30 * time.Second)
	if err := search(SearchParams{PageSize: 1}); !rateLimited(t, err) {
		t.Fatalf("a search after the clock stepped back: %v", err)
	}
	f.carrier.clock.advance(30*time.Second + time.Minute)
	if err := search(SearchParams{PageSize: 1}); err != nil {
		t.Fatalf("a search a minute later: %v", err)
	}

	bad := localParams()
	bad.CapabilityVersion = ""
	for index := 0; index < 5; index++ {
		if _, err := f.agent.Quote(context.Background(), bad); err == nil || codeOf(t, err) != CodeBadInput {
			t.Fatalf("an invalid quote: %v", err)
		}
	}
	for index := 0; index < QuotesPerMinute; index++ {
		if _, err := f.agent.Quote(context.Background(), localParams()); err != nil {
			t.Fatalf("quote %d: %v", index, err)
		}
	}
	if _, err := f.agent.Quote(context.Background(), localParams()); !rateLimited(t, err) {
		t.Fatalf("a quote over the bound: %v", err)
	}
	f.carrier.clock.advance(time.Minute)
	if _, err := f.agent.Quote(context.Background(), localParams()); err != nil {
		t.Fatalf("a quote a minute later: %v", err)
	}
	if !strings.HasPrefix(CodeRateLimited, "MCP_BUYER_") {
		t.Fatal("the rate code is not an adapter code")
	}
}
