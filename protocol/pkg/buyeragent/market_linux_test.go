package buyeragent

import (
	"encoding/json"
	"testing"
)

// The client account searches and quotes over the socket; the params are
// decoded strictly like every other method's.
func TestSearchAndQuoteAreServedToTheClientAccount(t *testing.T) {
	f := newOffersFixture(t)
	f.hints.hints = []Hint{{CapabilityID: fxCapability, Version: "1.0.0"}}
	client := serve(t, f.fixture, RoleClient)
	searched, answered := call(t, client, "search", map[string]any{"page_size": 5})
	if !answered || !searched.OK {
		t.Fatalf("client search: %+v", searched)
	}
	var page SearchView
	if err := json.Unmarshal(searched.Result.(json.RawMessage), &page); err != nil || len(page.Offers) != 1 {
		t.Fatalf("search page %+v: %v", page, err)
	}
	quoted, answered := call(t, client, "quote", map[string]any{"capability_id": fxCapability, "capability_version": "1.0.0"})
	if !answered || !quoted.OK {
		t.Fatalf("client quote: %+v", quoted)
	}
	var view QuoteView
	if err := json.Unmarshal(quoted.Result.(json.RawMessage), &view); err != nil || view.QuoteID == "" {
		t.Fatalf("quote %+v: %v", view, err)
	}
	if _, _, err := f.agent.loadQuote(view.QuoteID); err != nil {
		t.Fatalf("the socket quote was not stored: %v", err)
	}
	strict, answered := call(t, client, "quote", map[string]any{"capability_id": fxCapability,
		"capability_version": "1.0.0", "price": "1"})
	if !answered || strict.OK || strict.Error == nil || strict.Error.Code != CodeBadInput {
		t.Fatalf("a quote with an unknown field: %+v", strict)
	}
}
