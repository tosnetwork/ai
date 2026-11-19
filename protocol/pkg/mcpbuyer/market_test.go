package mcpbuyer

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
)

func TestSearchShowsVerifiedOffersWithProviderTextDelimited(t *testing.T) {
	agent := &fakeAgent{provide: "Runs go test.\x1b[2J"}
	h := connect(t, agent)
	result := h.call(t, ToolSearch, map[string]any{"query": "go test"})
	if result.IsError {
		t.Fatalf("search: %s", text(result))
	}
	calls, params := agent.recorded()
	if len(calls) != 1 || calls[0] != "search" {
		t.Fatalf("calls %v", calls)
	}
	if sent := params[0].(buyeragent.SearchParams); sent.Query != "go test" || sent.PageSize != 20 {
		t.Fatalf("sent %+v", sent)
	}
	var out SearchResult
	structured(t, result, &out)
	if len(out.Offers) != 1 || out.Dropped != 2 || out.FailedSources != 1 || out.Checkpoint != 41 ||
		out.Offers[0].ProviderDescription.Bytes != len("Runs go test.\x1b[2J") ||
		strings.Contains(out.Offers[0].ProviderDescription.Text, "\x1b") {
		t.Fatalf("structured search %+v", out)
	}
	body := text(result)
	if strings.Contains(body, "\x1b") || !strings.Contains(body, "2 candidates dropped") ||
		strings.Count(body, "<<<UNTRUSTED provider data, id=") != 2 {
		t.Fatalf("text:\n%s", body)
	}
}

func TestQuoteSendsTheOfferFileBytesUnderARoot(t *testing.T) {
	agent := &fakeAgent{}
	h := connect(t, agent)
	path := filepath.Join(h.root, "offer.json")
	write(t, path, `{"schema":"tos.openfox.rail-offer.v2"}`)
	result := h.call(t, ToolQuote, map[string]any{"capability_id": "cap_" + strings.Repeat("3", 64),
		"capability_version": "1.0.0", "offer_file": path, "source": "local"})
	if result.IsError {
		t.Fatalf("quote: %s", text(result))
	}
	_, params := agent.recorded()
	sent := params[0].(buyeragent.QuoteParams)
	if sent.OfferFileBase64 != base64.StdEncoding.EncodeToString([]byte(`{"schema":"tos.openfox.rail-offer.v2"}`)) ||
		sent.Source != "local" || sent.CapabilityVersion != "1.0.0" {
		t.Fatalf("sent %+v", sent)
	}
	var out QuoteResult
	structured(t, result, &out)
	if out.Quote == nil || out.Quote.QuoteID != strings.Repeat("cd", 32) || out.Quote.Carriable ||
		out.Quote.NotCarriable != "item_3" || out.Quote.Offer.ProviderName.Text != "build" {
		t.Fatalf("structured quote %+v", out.Quote)
	}
	if !strings.Contains(text(result), "cannot be carried") {
		t.Fatalf("text:\n%s", text(result))
	}
}

func TestAnOfferFileOutsideTheRootsOrOverItsBoundNeverReachesTheAgent(t *testing.T) {
	agent := &fakeAgent{}
	h := connect(t, agent)
	outside := filepath.Join(t.TempDir(), "offer.json")
	write(t, outside, "{}")
	link := filepath.Join(h.root, "link.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(h.root, "large.json")
	write(t, large, strings.Repeat("x", buyeragent.MaxOfferFileBytes+1))
	for name, path := range map[string]string{"outside": outside, "link": link, "large": large, "relative": "offer.json"} {
		result := h.call(t, ToolQuote, map[string]any{"capability_id": "cap_" + strings.Repeat("3", 64),
			"capability_version": "1.0.0", "offer_file": path})
		var out QuoteResult
		structured(t, result, &out)
		if !result.IsError || out.Error == nil || out.Error.Code != buyeragent.CodeBadInput || out.Error.Message != offerFileMessage {
			t.Errorf("%s: %+v %s", name, out.Error, text(result))
		}
		if strings.Contains(text(result), path) {
			t.Errorf("%s: the refusal names the path", name)
		}
	}
	if calls, _ := agent.recorded(); len(calls) != 0 {
		t.Fatalf("the agent was called: %v", calls)
	}
}
