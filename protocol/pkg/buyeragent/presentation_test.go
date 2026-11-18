package buyeragent

import (
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
)

// The presentation carries what the confirmer must show: the provider, the
// manifest's text as untrusted fields, and the terms of the journal
// record, which Prepare took from the admitted policy.
func TestThePresentationCarriesTheAdmittedTermsAndTheProviderText(t *testing.T) {
	f := newFixture(t)
	view := f.requested(t, keyA)
	presentation, err := f.agent.Present(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	if presentation.ProviderAgentID != fxProvider || presentation.ManifestDigest != f.pkg.Proposal.ManifestDigest {
		t.Fatalf("provider %s, manifest %s", presentation.ProviderAgentID, presentation.ManifestDigest)
	}
	if presentation.ResponseSLASeconds != fxResponseSLA || presentation.RefundClaimWindowSeconds != fxRefundWindow ||
		presentation.CleanupBountyNanoTOS != fxCleanupBounty {
		t.Fatalf("terms %+v", presentation)
	}
	if presentation.RetentionSeconds == 0 || presentation.AllowanceNanoTOS != "200000000" ||
		presentation.NowUnix != fxNow.Unix() || presentation.ProviderName == "" {
		t.Fatalf("presentation %+v", presentation)
	}
}

// The terms shown follow the journal record and nothing else: changing
// the record's terms changes the presentation, and a record without them
// is never presented.
func TestTheShownTermsComeOnlyFromTheJournalRecord(t *testing.T) {
	f := newFixture(t)
	view := f.requested(t, keyA)
	edit := func(update func(*buyersdk.CallRecord)) {
		t.Helper()
		if _, err := f.buyer.journal.Transition(view.RequestHash, []buyersdk.CallPhase{buyersdk.PhasePrepared},
			func(r *buyersdk.CallRecord) error { update(r); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	edit(func(r *buyersdk.CallRecord) {
		r.ResponseSLASeconds, r.RefundClaimWindowSeconds, r.CleanupBountyNanoTOS = 86_400, 172_800, "1000000000"
	})
	presentation, err := f.agent.Present(view.RequestHash)
	if err != nil || presentation.ResponseSLASeconds != 86_400 || presentation.RefundClaimWindowSeconds != 172_800 ||
		presentation.CleanupBountyNanoTOS != "1000000000" {
		t.Fatalf("the shown terms do not follow the record: %+v %v", presentation, err)
	}
	edit(func(r *buyersdk.CallRecord) { r.ResponseSLASeconds = 0 })
	if _, err := f.agent.Present(view.RequestHash); err == nil || codeOf(t, err) != CodeOfferInvalid {
		t.Fatalf("a record without its admitted terms was presented: %v", err)
	}
}
