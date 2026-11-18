package buyeragent

import (
	"testing"
)

// The presentation carries what the confirmer must show: the provider, the
// manifest's text as untrusted fields, and the offer terms stored with the
// Quote.
func TestThePresentationCarriesTheOfferTermsAndTheProviderText(t *testing.T) {
	f := newFixture(t)
	view := f.requested(t, keyA)
	presentation, err := f.agent.Present(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	if presentation.ProviderAgentID != fxProvider || presentation.ManifestDigest != f.pkg.Proposal.ManifestDigest {
		t.Fatalf("provider %s, manifest %s", presentation.ProviderAgentID, presentation.ManifestDigest)
	}
	if presentation.ResponseSLASeconds != fxTerms.ResponseSLASeconds ||
		presentation.RefundClaimWindowSeconds != fxTerms.RefundClaimWindowSeconds ||
		presentation.CleanupBountyNanoTOS != fxTerms.CleanupBountyNanoTOS {
		t.Fatalf("terms %+v", presentation)
	}
	if presentation.RetentionSeconds == 0 || presentation.AllowanceNanoTOS != "200000000" ||
		presentation.NowUnix != fxNow.Unix() || presentation.ProviderName == "" {
		t.Fatalf("presentation %+v", presentation)
	}
}

func TestStoreQuoteRefusesTermsOutsideTheBoundsAndConflictingTerms(t *testing.T) {
	f := newFixture(t)
	for _, terms := range []OfferTerms{
		{ResponseSLASeconds: 3_599, RefundClaimWindowSeconds: 7_200, CleanupBountyNanoTOS: "1"},
		{ResponseSLASeconds: 3_600, RefundClaimWindowSeconds: 2_592_001, CleanupBountyNanoTOS: "1"},
		{ResponseSLASeconds: 3_600, RefundClaimWindowSeconds: 7_200, CleanupBountyNanoTOS: "01"},
		{ResponseSLASeconds: 3_600, RefundClaimWindowSeconds: 7_200, CleanupBountyNanoTOS: "-1"},
	} {
		if _, err := f.agent.StoreQuote(f.request, f.pkg, terms); err == nil || codeOf(t, err) != CodeOfferInvalid {
			t.Errorf("terms %+v were stored: %v", terms, err)
		}
	}
	other := fxTerms
	other.RefundClaimWindowSeconds++
	if _, err := f.agent.StoreQuote(f.request, f.pkg, other); err == nil || codeOf(t, err) != CodeConflict {
		t.Fatalf("a stored Quote took other terms: %v", err)
	}
	if id, err := f.agent.StoreQuote(f.request, f.pkg, fxTerms); err != nil || id != f.quoteID {
		t.Fatalf("storing the same Quote again: %s %v", id, err)
	}
}
