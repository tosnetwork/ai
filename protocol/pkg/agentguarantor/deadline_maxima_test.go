package agentguarantor

import (
	"strings"
	"testing"
	"time"
)

// testRequestedTerms is a valid requested-terms object for testCoverageTerms.
func testRequestedTerms(t *testing.T, terms CoverageTermsV1) RequestedCoverageTermsV1 {
	t.Helper()
	requested := RequestedCoverageTermsV1{SchemaVersion: 1, CoverageCategory: terms.CoverageCategory,
		BenefitKind: terms.BenefitKind, CoverageAsset: terms.CoverageAsset,
		RequestedAggregatePayout: terms.MaximumAggregatePayout, RequestedPerClaim: terms.MaximumPerClaim,
		MaximumClaims: terms.MaximumClaims, RequestedClosureCapacity: terms.ClaimClosureCapacity,
		RequestedCoverageStartsAtUnix: terms.CoverageStartsAtUnix, RequestedCoverageEndsAtUnix: terms.CoverageEndsAtUnix,
		RequestedClaimFilingEndsAtUnix: terms.ClaimFilingEndsAtUnix, MaximumReviewDeadlineSeconds: terms.ReviewDeadlineSeconds,
		MaximumChallengeWindowSeconds:             terms.ChallengeWindowSeconds,
		MaximumNonterminalResolutionWindowSeconds: terms.NonterminalResolutionWindowSeconds,
		MaximumSuccessorDecisionWindowSeconds:     terms.SuccessorDecisionWindowSeconds,
		MaximumPayoutDeadlineSeconds:              terms.PayoutDeadlineSeconds,
		MaximumAdapterRecoveryWindowSeconds:       terms.AdapterRecoveryWindowSeconds,
		MaximumTerminalResolutionDeadlineUnix:     terms.TerminalResolutionDeadlineUnix,
		ClaimTriggerProfile:                       terms.ClaimTriggerProfile, ClaimEvidenceProfile: terms.ClaimEvidenceProfile,
		SelectedAssuranceLevel: terms.SelectedAssuranceLevel, SelectedClaimProfileDigest: terms.SelectedClaimProfileDigest,
		SelectedPayoutAdapterProfile: terms.SelectedPayoutAdapterProfile}
	if err := ValidateRequestedCoverageTerms(requested); err != nil {
		t.Fatalf("test requested terms are invalid: %v", err)
	}
	return requested
}

// testLateTerms is testCoverageTerms with a late-recovery contingency that
// follows the section 13 derivation exactly.
func testLateTerms(t *testing.T) CoverageTermsV1 {
	t.Helper()
	late := testCoverageTerms(t)
	late.LateIngressRecoveryWindowSeconds = 300
	late.LateIngressRecoveryDeadlineUnix = late.TerminalResolutionDeadlineUnix + 300
	late.LateRecoveryTerminalDeadlineUnix = late.LateIngressRecoveryDeadlineUnix + lateRecoveryCandidateClosureSecondsV1(late, 0)
	return late
}

// TestTermsStayWithinTheRequestersDeadlineMaxima: section 13 holds
// "terminal_resolution_deadline_unix is no later than the request's
// maximum_terminal_resolution_deadline_unix, late_recovery_terminal_deadline_unix
// is no later than the request's maximum_late_recovery_terminal_deadline_unix",
// and the window to the request's maximum; a request with zero late maxima
// admits no late-recovery contingency.
func TestTermsStayWithinTheRequestersDeadlineMaxima(t *testing.T) {
	none, late := testCoverageTerms(t), testLateTerms(t)
	noLate := testRequestedTerms(t, none)
	withLate := noLate
	withLate.MaximumLateRecoveryTerminalDeadlineUnix = late.LateRecoveryTerminalDeadlineUnix
	withLate.MaximumLateIngressRecoveryWindowSeconds = late.LateIngressRecoveryWindowSeconds
	if err := ValidateRequestedCoverageTerms(withLate); err != nil {
		t.Fatalf("a request admitting the late contingency is invalid: %v", err)
	}
	const terminal = "terminal resolution deadline exceeds the requester's maximum"
	const lateMax = "late-recovery deadline or window exceeds the requester's maximum"
	cases := map[string]struct {
		terms     CoverageTermsV1
		requested func() RequestedCoverageTermsV1
		want      string
	}{
		"terminal deadline at the maximum": {none, func() RequestedCoverageTermsV1 { return noLate }, ""},
		"terminal deadline one second over": {none, func() RequestedCoverageTermsV1 {
			r := noLate
			r.MaximumTerminalResolutionDeadlineUnix--
			return r
		}, terminal},
		"late deadline at the maximum": {late, func() RequestedCoverageTermsV1 { return withLate }, ""},
		"late deadline one second over": {late, func() RequestedCoverageTermsV1 {
			r := withLate
			r.MaximumLateRecoveryTerminalDeadlineUnix--
			return r
		}, lateMax},
		"late window one second over": {late, func() RequestedCoverageTermsV1 {
			r := withLate
			r.MaximumLateIngressRecoveryWindowSeconds--
			return r
		}, lateMax},
		"late contingency against a request for none": {late, func() RequestedCoverageTermsV1 { return noLate }, lateMax},
	}
	for name, test := range cases {
		err := validateTermsWithinRequestedDeadlinesV1(test.terms, test.requested())
		if test.want == "" && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
			t.Errorf("%s: got %v, want %q", name, err, test.want)
		}
	}
	const invalid = "requested Guarantor deadline maxima are invalid"
	for name, change := range map[string]func(*RequestedCoverageTermsV1){
		"terminal maximum one second before the filing end": func(r *RequestedCoverageTermsV1) {
			r.MaximumTerminalResolutionDeadlineUnix = r.RequestedClaimFilingEndsAtUnix - 1
		},
		"late maximum without a window maximum": func(r *RequestedCoverageTermsV1) {
			r.MaximumLateIngressRecoveryWindowSeconds = 0
		},
		"window maximum without a late maximum": func(r *RequestedCoverageTermsV1) {
			r.MaximumLateRecoveryTerminalDeadlineUnix = 0
		},
		"late maximum at the terminal maximum": func(r *RequestedCoverageTermsV1) {
			r.MaximumLateRecoveryTerminalDeadlineUnix = r.MaximumTerminalResolutionDeadlineUnix
		},
	} {
		requested := withLate
		change(&requested)
		if err := ValidateRequestedCoverageTerms(requested); err == nil || !strings.Contains(err.Error(), invalid) {
			t.Errorf("%s: got %v, want %q", name, err, invalid)
		}
	}
	terminalAtFiling := noLate
	terminalAtFiling.MaximumTerminalResolutionDeadlineUnix = terminalAtFiling.RequestedClaimFilingEndsAtUnix
	if err := ValidateRequestedCoverageTerms(terminalAtFiling); err != nil {
		t.Errorf("a terminal maximum at the filing end was refused: %v", err)
	}
}

// TestCollateralIsNotReleasableBeforeTheFinalDeadline: section 13 requires
// "late_recovery_terminal_deadline_unix + collateral_terms.reorg_window_seconds
// <= collateral_terms.release_not_before_unix"; without a late contingency the
// final deadline is the terminal resolution deadline.
func TestCollateralIsNotReleasableBeforeTheFinalDeadline(t *testing.T) {
	const refused = "collateral may be released before the terms' final deadline"
	withRelease := func(base CoverageTermsV1, offset int64) CoverageTermsV1 {
		final := base.LateRecoveryTerminalDeadlineUnix
		if final == 0 {
			final = base.TerminalResolutionDeadlineUnix
		}
		base.CollateralTerms = &CollateralTermsV1{ReorgWindowSeconds: 60, ReleaseNotBeforeUnix: uint64(int64(final+60) + offset)}
		return base
	}
	none, late := testCoverageTerms(t), testLateTerms(t)
	for name, test := range map[string]struct {
		terms CoverageTermsV1
		want  string
	}{
		"late contingency, release at the final deadline plus reorg":  {withRelease(late, 0), ""},
		"late contingency, release one second earlier":                {withRelease(late, -1), refused},
		"no contingency, release at the terminal deadline plus reorg": {withRelease(none, 0), ""},
		"no contingency, release one second earlier":                  {withRelease(none, -1), refused},
		"late contingency, release before the late deadline only": {func() CoverageTermsV1 {
			terms := late
			terms.CollateralTerms = &CollateralTermsV1{ReorgWindowSeconds: 60,
				ReleaseNotBeforeUnix: terms.TerminalResolutionDeadlineUnix + 60}
			return terms
		}(), refused},
	} {
		err := validateCollateralReleaseAfterFinalDeadlineV1(test.terms)
		if test.want == "" && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
			t.Errorf("%s: got %v, want %q", name, err, test.want)
		}
	}
}

// TestClaimProfilePermitsTheLatePathByItsWindow: section 13 requires "The
// selected claim profile must permit late_recovery_terminal_fallback" and the
// window to be "no greater than both the request and selected claim-profile
// maxima". A profile permits the late path by publishing a positive maximum
// late-ingress window.
func TestClaimProfilePermitsTheLatePathByItsWindow(t *testing.T) {
	none, late := testCoverageTerms(t), testLateTerms(t)
	for name, test := range map[string]struct {
		window uint64
		terms  CoverageTermsV1
		want   bool
	}{
		"no contingency, profile without the late path":   {0, none, true},
		"late contingency, profile without the late path": {0, late, false},
		"window at the profile maximum":                   {300, late, true},
		"window one second over the profile maximum":      {299, late, false},
	} {
		profile := ClaimProfileV1{MaximumLateIngressRecoveryWindowSeconds: test.window}
		if got := claimProfilePermitsLateRecoveryV1(profile, test.terms); got != test.want {
			t.Errorf("%s: permitted=%v, want %v", name, got, test.want)
		}
	}
}

// TestClaimAdmissionProofBodyNamesItsIngressClaim: a compact proof's body
// names the claim, Agreement and obligation of the claim its ingress receipt
// carries, as the complete receipt verifier requires. A receipt sealed with
// another claim ID in its body is refused even though its seal matches.
func TestClaimAdmissionProofBodyNamesItsIngressClaim(t *testing.T) {
	terms := testCoverageTerms(t)
	now := time.Unix(2_000_000_100, 0).UTC()
	revision := loadMeasuredDecisionReceipt(t).AuthorizedClaimAdmissionReceipt
	// sealed seals receipt with its body changed and builds its compact proof;
	// building validates the proof, so a refused binding refuses the build.
	sealed := func(change func(*ClaimAdmissionReceiptBodyV1)) (ClaimAdmissionReceiptProofV1, error) {
		receipt := revision
		change(&receipt.Body)
		sealedAt := time.Unix(int64(receipt.Body.AdmittedAtUnix), 0).UTC()
		seal, descriptor, err := NewClaimAdmissionReceiptSealBodyV1(receipt, terms, sealedAt)
		if err != nil {
			t.Fatal(err)
		}
		bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "claim_revision_admission")
		if err != nil {
			t.Fatal(err)
		}
		authorization := receipt.Authorizations[0]
		authorization.AuthoritySubject, authorization.ValidationTimeUnix = bound.ActionAuthorityID, seal.SealedAtUnix
		return BuildClaimAdmissionReceiptProofV1(receipt, terms, descriptor, seal, authorization)
	}
	consistent, err := sealed(func(*ClaimAdmissionReceiptBodyV1) {})
	if err != nil {
		t.Fatalf("a consistent sealed proof could not be built: %v", err)
	}
	if err := ValidateClaimAdmissionReceiptProofV1(consistent, terms, nil, nil, now, false); err != nil {
		t.Fatalf("a consistent sealed proof was refused: %v", err)
	}
	for name, change := range map[string]func(*ClaimAdmissionReceiptBodyV1){
		"another claim ID":   func(body *ClaimAdmissionReceiptBodyV1) { body.ClaimID = sizeTestDigest("2") },
		"another Agreement":  func(body *ClaimAdmissionReceiptBodyV1) { body.CoverageAgreementBodyDigest = sizeTestDigest("3") },
		"another obligation": func(body *ClaimAdmissionReceiptBodyV1) { body.CoverageObligationID = "obligation:other" },
	} {
		if _, err := sealed(change); err == nil || !strings.Contains(err.Error(), "claim admission compact proof binding is invalid") {
			t.Errorf("%s: got %v, want a binding refusal", name, err)
		}
	}
}
