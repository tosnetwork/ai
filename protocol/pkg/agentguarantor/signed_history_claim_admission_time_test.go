package agentguarantor

import (
	"strings"
	"testing"
)

// When a claim may be received and admitted, on signed history: initial
// ingress closes at the filing cutoff, an admission follows the ingress
// receipt it consumes, and an initial admission is no later than its claim's
// expiry and than the filing cutoff plus the ingress resolution grace. Every
// receipt is complete and signed, is judged ten years later by the unreplaced
// claim admission verifier, and is then sealed and judged as a compact proof.

// claimTimes are the times of one claim's ingress and admission.
type claimTimes struct {
	receivedAt, admittedAt, expiresAt uint64
}

// admitWith receives claim at times.receivedAt and admits it at
// times.admittedAt.
func (history *signedHistory) admitWith(claim AuthorizedCoverageClaimV1, times claimTimes) AuthorizedClaimAdmissionReceiptV1 {
	prior := history.vary
	history.vary.ingressReceivedAt = times.receivedAt
	receipt := history.admit(claim, times.admittedAt)
	history.vary = prior
	if receipt.Body.AdmittedAtUnix != times.admittedAt ||
		receipt.AuthorizedClaimIngressReceipt.Body.ReceivedAtUnix != times.receivedAt {
		history.t.Fatalf("the claim is received at %d and admitted at %d, want %d and %d",
			receipt.AuthorizedClaimIngressReceipt.Body.ReceivedAtUnix, receipt.Body.AdmittedAtUnix, times.receivedAt, times.admittedAt)
	}
	return receipt
}

// claimWith is revision of a claim that expires at times.expiresAt, created
// ten seconds before the earlier of its ingress and its admission and no
// later than the filing cutoff.
func (history *signedHistory) claimWith(revision uint64, predecessor *AuthorizedCoverageClaimV1, times claimTimes) AuthorizedCoverageClaimV1 {
	createdAt := times.receivedAt
	if times.admittedAt < createdAt {
		createdAt = times.admittedAt
	}
	createdAt -= 10
	if cutoff := history.terms.ClaimFilingEndsAtUnix; createdAt > cutoff {
		createdAt = cutoff
	}
	prior := history.vary
	history.vary.claimExpiresAt = times.expiresAt
	claim := history.claim(revision, predecessor, createdAt)
	history.vary = prior
	return claim
}

// initialClaimAdmitted is a fresh history, under terms when given, whose one
// initial claim is received and admitted at times.
func initialClaimAdmitted(t *testing.T, terms *CoverageTermsV1, times claimTimes) (*signedHistory, AuthorizedClaimAdmissionReceiptV1) {
	t.Helper()
	history := newSignedHistory(t)
	withSignedHistorySeam(t, history)
	if terms != nil {
		history.terms, history.offer.CoverageTerms = *terms, *terms
	}
	return history, history.admitWith(history.claimWith(1, nil, times), times)
}

// claimAdmissionVerdicts are the verdicts on receipt of the claim admission
// verifier and of its compact proof, which is sealed at the admission time
// and verified with its signatures. A proof that cannot be sealed has the
// builder's refusal as its verdict.
func (history *signedHistory) claimAdmissionVerdicts(receipt AuthorizedClaimAdmissionReceiptV1) (complete, compact error) {
	later := receipt.Body.AdmittedAtUnix + signedHistoryLater
	complete = history.verifyClaimAdmission(receipt, later)
	proof, err := history.sealClaimAdmission(receipt, receipt.Body.AdmittedAtUnix)
	if err != nil {
		return complete, err
	}
	return complete, ValidateClaimAdmissionReceiptProofV1(proof, history.terms, history.resolver, history.fenceResolver,
		signedHistoryTime(later), true)
}

// expectClaimAdmission reports a verdict of either verifier that is not the
// wanted one.
func expectClaimAdmission(t *testing.T, name string, history *signedHistory, receipt AuthorizedClaimAdmissionReceiptV1, want string) {
	t.Helper()
	complete, compact := history.claimAdmissionVerdicts(receipt)
	expectVerdict(t, name+", by the claim admission verifier", complete, want)
	expectVerdict(t, name+", as a compact proof", compact, want)
}

// TestSignedHistoryInitialClaimIngressClosesAtTheFilingCutoff: an initial
// claim is received no later than claim_filing_ends_at_unix, whatever its own
// expiry. A claim received at the cutoff is accepted by the ingress verifier,
// by the claim admission verifier and as a compact proof; the same claim
// received a second later is refused by each. A revision of an admitted claim
// is not held to the cutoff: received after the cutoff and after the grace,
// it is accepted.
func TestSignedHistoryInitialClaimIngressClosesAtTheFilingCutoff(t *testing.T) {
	const late = "Guarantor initial claim ingress is received after the claim filing cutoff"
	terms := newSignedHistory(t).terms
	cutoff, grace := terms.ClaimFilingEndsAtUnix, terms.ClaimIngressResolutionGraceSeconds
	expiresAt := cutoff + grace + 1000
	for _, test := range []struct {
		name       string
		receivedAt uint64
		want       string
	}{
		{"an initial claim received at the filing cutoff", cutoff, ""},
		{"an initial claim received a second after the filing cutoff", cutoff + 1, late},
	} {
		history, receipt := initialClaimAdmitted(t, nil, claimTimes{test.receivedAt, test.receivedAt, expiresAt})
		bound, err := FindStageActionAuthorityV1(history.terms.StageActionAuthorityBinding, "claim_submission_ingress")
		if err != nil {
			t.Fatal(err)
		}
		expectVerdict(t, test.name+", by the ingress verifier", VerifyClaimSubmissionIngressReceiptV1(
			receipt.AuthorizedClaimIngressReceipt, history.terms, bound, history.resolver, history.fenceResolver,
			signedHistoryTime(test.receivedAt+signedHistoryLater)), test.want)
		expectClaimAdmission(t, test.name, history, receipt, test.want)
	}

	history := newSignedHistory(t)
	withSignedHistorySeam(t, history)
	first := history.claimWith(1, nil, claimTimes{cutoff - 100, cutoff - 100, expiresAt})
	history.admitWith(first, claimTimes{cutoff - 100, cutoff - 100, expiresAt})
	afterGrace := claimTimes{cutoff + grace + 10, cutoff + grace + 10, expiresAt}
	revision := history.admitWith(history.claimWith(2, &first, afterGrace), afterGrace)
	expectClaimAdmission(t, "a revision received and admitted after the filing cutoff and the grace", history, revision, "")
}

// TestSignedHistoryInitialClaimIsAdmittedWithinTheIngressGrace: an ingress
// sequenced by the filing cutoff has claim_ingress_resolution_grace_seconds
// to be admitted, and no longer. An initial claim received at the cutoff and
// admitted exactly at the cutoff plus the grace is accepted; admitted a
// second later it is refused, although its ingress was timely and its claim
// has not expired. Under terms whose cutoff plus grace cannot be computed, no
// initial claim is admitted.
func TestSignedHistoryInitialClaimIsAdmittedWithinTheIngressGrace(t *testing.T) {
	terms := newSignedHistory(t).terms
	cutoff, grace := terms.ClaimFilingEndsAtUnix, terms.ClaimIngressResolutionGraceSeconds
	if grace == 0 {
		t.Fatal("the signed history's terms set no ingress resolution grace")
	}
	expiresAt := cutoff + grace + 1000
	for _, test := range []struct {
		name       string
		admittedAt uint64
		want       string
	}{
		{"an initial claim admitted at the filing cutoff plus the grace", cutoff + grace, ""},
		{"an initial claim admitted a second after the filing cutoff plus the grace", cutoff + grace + 1,
			"Guarantor initial claim admission is admitted after the claim filing cutoff plus the ingress resolution grace"},
	} {
		history, receipt := initialClaimAdmitted(t, nil, claimTimes{cutoff, test.admittedAt, expiresAt})
		expectClaimAdmission(t, test.name, history, receipt, test.want)
	}

	unbounded := terms
	unbounded.ClaimIngressResolutionGraceSeconds = ^uint64(0)
	if err := ValidateCoverageTerms(unbounded); err != nil {
		t.Fatalf("the terms with the largest grace are invalid: %v", err)
	}
	history, receipt := initialClaimAdmitted(t, &unbounded, claimTimes{cutoff, cutoff + grace, expiresAt})
	expectClaimAdmission(t, "an initial claim under terms whose cutoff plus grace overflows", history, receipt,
		"Guarantor terms' claim filing cutoff plus its ingress resolution grace overflows")
}

// TestSignedHistoryInitialClaimIsAdmittedByItsExpiry: an initial claim is
// admitted no later than its own expires_at_unix. Received before it expires
// and admitted at the instant of its expiry it is accepted; admitted a second
// later it is refused, although the filing cutoff and the grace are far off.
func TestSignedHistoryInitialClaimIsAdmittedByItsExpiry(t *testing.T) {
	expiresAt := uint64(signedHistoryStart + 100)
	for _, test := range []struct {
		name       string
		admittedAt uint64
		want       string
	}{
		{"an initial claim admitted at the instant it expires", expiresAt, ""},
		{"an initial claim admitted a second after it expires", expiresAt + 1,
			"Guarantor initial claim admission is admitted after its claim expires"},
	} {
		history, receipt := initialClaimAdmitted(t, nil, claimTimes{expiresAt - 10, test.admittedAt, expiresAt})
		expectClaimAdmission(t, test.name, history, receipt, test.want)
	}
}

// TestSignedHistoryClaimAdmissionFollowsItsIngress: an admission consumes an
// ingress receipt, so it is admitted no earlier than that receipt was
// received. An initial claim and a revision admitted at the instant their
// ingress was received are accepted; each admitted a second before it is
// refused.
func TestSignedHistoryClaimAdmissionFollowsItsIngress(t *testing.T) {
	const early = "Guarantor claim admission is admitted before the ingress receipt it consumes was received"
	receivedAt := uint64(signedHistoryStart + 50)
	expiresAt := newSignedHistory(t).terms.ClaimFilingEndsAtUnix
	for _, test := range []struct {
		name       string
		admittedAt uint64
		want       string
	}{
		{"admitted at the instant its ingress was received", receivedAt, ""},
		{"admitted a second before its ingress was received", receivedAt - 1, early},
	} {
		history, receipt := initialClaimAdmitted(t, nil, claimTimes{receivedAt, test.admittedAt, expiresAt})
		expectClaimAdmission(t, "an initial claim "+test.name, history, receipt, test.want)

		revised := newSignedHistory(t)
		withSignedHistorySeam(t, revised)
		firstTimes := claimTimes{receivedAt - 20, receivedAt - 20, expiresAt}
		first := revised.claimWith(1, nil, firstTimes)
		revised.admitWith(first, firstTimes)
		times := claimTimes{receivedAt, test.admittedAt, expiresAt}
		revision := revised.admitWith(revised.claimWith(2, &first, times), times)
		expectClaimAdmission(t, "a revision "+test.name, revised, revision, test.want)
	}
}

// TestCoverageTermsSetAPositiveIngressResolutionGrace: the accepted terms'
// claim_ingress_resolution_grace_seconds is positive. Terms with a grace of
// one second are valid and have a digest; the same terms with none are
// invalid and have no digest, so no offer, receipt or proof exists over them.
func TestCoverageTermsSetAPositiveIngressResolutionGrace(t *testing.T) {
	const none = "Guarantor terms set no claim ingress resolution grace"
	terms := testCoverageTerms(t)
	terms.ClaimIngressResolutionGraceSeconds = 1
	if err := ValidateCoverageTerms(terms); err != nil {
		t.Errorf("terms with a grace of one second are refused: %v", err)
	}
	if _, err := CoverageTermsDigest(terms); err != nil {
		t.Errorf("terms with a grace of one second have no digest: %v", err)
	}
	terms.ClaimIngressResolutionGraceSeconds = 0
	refusedFor(t, "terms with no grace", ValidateCoverageTerms(terms), none)
	if _, err := CoverageTermsDigest(terms); err == nil || !strings.Contains(err.Error(), none) {
		t.Errorf("terms with no grace: the digest returned %v, want a refusal containing %q", err, none)
	}
}

// TestSignedHistoryOfferedGraceStaysWithinTheClaimProfilesMaximum: the offered
// claim_ingress_resolution_grace_seconds is no greater than the selected claim
// profile's maximum. Against a request that allows a second more than the
// profile publishes, an offer at the profile's maximum is accepted and one a
// second over it is refused, with and without a late contingency.
func TestSignedHistoryOfferedGraceStaysWithinTheClaimProfilesMaximum(t *testing.T) {
	offering := func(over uint64) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) {
			in.requestedTerms = func(requested *RequestedCoverageTermsV1) { requested.MaximumClaimIngressResolutionGraceSeconds++ }
			in.offeredTerms = func(terms *CoverageTermsV1) { terms.ClaimIngressResolutionGraceSeconds += over }
		}
	}
	var cases []signedOfferCase
	for _, late := range []bool{true, false} {
		cases = append(cases,
			signedOfferCase{name: "a grace at the claim profile's maximum", late: late, change: offering(0)},
			signedOfferCase{name: "a grace a second over the claim profile's maximum", late: late, change: offering(1),
				refusal: "Guarantor terms' claim ingress resolution grace exceeds the selected claim profile's maximum"})
	}
	checkSignedOffers(t, cases)
}
