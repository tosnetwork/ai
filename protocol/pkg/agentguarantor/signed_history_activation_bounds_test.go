package agentguarantor

import "testing"

// The times an activation may be admitted at, on signed history: no earlier
// than the acceptance it consumes and no later than the activation cutoff,
// which is the coverage start.

// activationAt is the Guarantor-signed activation of the accepted coverage,
// admitted at at and otherwise the history's own.
func (history *signedHistory) activationAt(signed signedOffer, acceptance AuthorizedCoverageAcceptanceReceiptV1,
	at uint64) AuthorizedCoverageActivationEvidenceV1 {
	prior := history.vary
	history.vary.activatedAt = at
	evidence := history.offerActivation(signed, acceptance)
	history.vary = prior
	if evidence.Body.ActivatedAtUnix != at || evidence.StageActionAdmissionEvidence.Body.AdmittedAtUnix != at {
		history.t.Fatalf("the activation is admitted at %d and states %d, want %d",
			evidence.StageActionAdmissionEvidence.Body.AdmittedAtUnix, evidence.Body.ActivatedAtUnix, at)
	}
	return evidence
}

// TestSignedHistoryActivationIsBetweenItsAcceptanceAndTheCoverageStart: V1
// forbids retroactive activation. Activation evidence built in full on a
// signed offer is accepted when it is admitted at the instant of its
// acceptance and when it is admitted at the coverage start, and refused when
// it is admitted a second before the acceptance or a second after the coverage
// start. The four differ in the activation time alone, and each is verified
// ten years later, so the refusal is of the activation and not of its age.
func TestSignedHistoryActivationIsBetweenItsAcceptanceAndTheCoverageStart(t *testing.T) {
	history := offerPhaseHistory(t)
	signed := history.quoteToOffer(true, nil)
	acceptance := history.acceptanceReceipt(signed)
	acceptedAt, startsAt := acceptance.Body.AcceptedAtUnix, signed.offer.CoverageTerms.CoverageStartsAtUnix
	if acceptedAt >= startsAt {
		t.Fatalf("the offer is accepted at %d, not before the coverage starts at %d", acceptedAt, startsAt)
	}
	for _, test := range []struct {
		name string
		at   uint64
		want string
	}{
		{"an activation admitted at the instant of its acceptance", acceptedAt, ""},
		{"an activation admitted a second before its acceptance", acceptedAt - 1,
			"coverage activation is admitted before the acceptance it stands on"},
		{"an activation admitted at the coverage start", startsAt, ""},
		{"an activation admitted a second after the coverage start", startsAt + 1,
			"coverage activation is admitted after the activation cutoff, the coverage start"},
	} {
		evidence := history.activationAt(signed, acceptance, test.at)
		expectVerdict(t, test.name, VerifyCoverageActivationEvidenceV1(evidence, signed.offer, signedOfferAgreementVerifier{signed},
			signed.resolver, history.fenceResolver, nil, signedHistoryTime(startsAt+signedHistoryLater)), test.want)
	}
}
