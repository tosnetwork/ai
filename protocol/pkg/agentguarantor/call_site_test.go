package agentguarantor

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func signedHistoryTime(at uint64) time.Time { return time.Unix(int64(at), 0).UTC() }

// TestActivationPredecessorSeamDefaultsToTheRealVerifier: the activation
// predecessor seam is the real activation verifier unless a test in this
// package replaces it, and it refuses what the real verifier refuses.
func TestActivationPredecessorSeamDefaultsToTheRealVerifier(t *testing.T) {
	if reflect.ValueOf(coverageActivationPredecessorVerifierV1).Pointer() != reflect.ValueOf(VerifyCoverageActivationEvidenceV1).Pointer() {
		t.Fatal("the activation predecessor seam is not the real activation verifier")
	}
	terms := testCoverageTerms(t)
	offer := AuthorizedFirmCoverageOfferV1{CoverageTerms: terms}
	seamErr := coverageActivationPredecessorVerifierV1(AuthorizedCoverageActivationEvidenceV1{}, offer, permissiveAgreementVerifier{},
		allowAuthorityResolver{}, nil, nil, signedHistoryTime(signedHistoryStart))
	realErr := VerifyCoverageActivationEvidenceV1(AuthorizedCoverageActivationEvidenceV1{}, offer, permissiveAgreementVerifier{},
		allowAuthorityResolver{}, nil, nil, signedHistoryTime(signedHistoryStart))
	if seamErr == nil || realErr == nil || seamErr.Error() != realErr.Error() {
		t.Fatalf("the seam and the real verifier differ on an invalid activation: %v / %v", seamErr, realErr)
	}
}

// TestActivationPredecessorSeamIsAssignedOnlyInTests: no non-test file of the
// package assigns the seam beyond its declaration, or copies it.
func TestActivationPredecessorSeamIsAssignedOnlyInTests(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	const declaration = "var coverageActivationPredecessorVerifierV1 = VerifyCoverageActivationEvidenceV1"
	use := regexp.MustCompile(`coverageActivationPredecessorVerifierV1\s*[^\s(]`)
	declarations := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for number, line := range strings.Split(string(source), "\n") {
			if !strings.Contains(line, "coverageActivationPredecessorVerifierV1") || strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if strings.TrimSpace(line) == declaration {
				declarations++
				continue
			}
			if use.MatchString(line) {
				t.Errorf("%s:%d uses the activation predecessor seam other than by calling it: %s", file, number+1, strings.TrimSpace(line))
			}
		}
	}
	if declarations != 1 {
		t.Fatalf("the activation predecessor seam is declared %d times, want once", declarations)
	}
}

// testClaimProfileFor is a claim profile the terms select exactly; the
// terms' selected claim profile digest is set to it.
func testClaimProfileFor(t *testing.T, terms *CoverageTermsV1) ClaimProfileV1 {
	t.Helper()
	capacity := terms.ClaimClosureCapacity
	profile := ClaimProfileV1{ProfileID: "claim-profile:test", ProfileVersion: 1, TriggerProfile: terms.ClaimTriggerProfile,
		EvidenceProfile: terms.ClaimEvidenceProfile, ClaimantAuthorizationProfiles: terms.ClaimantAuthorizationProfiles,
		IngressProfile: terms.ClaimIngressProfile, IngressAuthoritySubjects: terms.ClaimIngressAuthoritySubjects,
		IngressAuthorityQuorumRule: terms.ClaimIngressAuthorityQuorumRule, AdmissionProfile: terms.ClaimAdmissionProfile,
		AdmissionAuthoritySubjects: terms.ClaimAdmissionAuthoritySubjects, AdmissionQuorumRule: terms.ClaimAdmissionQuorumRule,
		DecisionAdmissionProfile: terms.DecisionAdmissionProfile, DecisionAdmissionAuthoritySubjects: terms.DecisionAdmissionAuthoritySubjects,
		DecisionAdmissionQuorumRule: terms.DecisionAdmissionQuorumRule, DecisionProfile: terms.DecisionProfile,
		MaximumClaims: capacity.MaximumClaims, MaximumClaimIngressActions: capacity.MaximumClaimIngressActions,
		MaximumClaimRevisionsPerClaim: capacity.MaximumClaimRevisionsPerClaim, MaximumDecisionAdmissionsPerClaim: capacity.MaximumDecisionAdmissionsPerClaim,
		MaximumClaimStateTransitionsPerClaim: capacity.MaximumClaimStateTransitionsPerClaim,
		MaximumChallengeRoundsPerClaim:       capacity.MaximumChallengeRoundsPerClaim, MaximumNonterminalRoundsPerClaim: capacity.MaximumNonterminalRoundsPerClaim,
		MaximumPayoutLinesPerClaim: capacity.MaximumPayoutLinesPerClaim, MaximumAdmittedClaimEnvelopeBytes: capacity.MaximumAdmittedClaimEnvelopeBytes,
		MaximumClaimIngressReceiptEnvelopeBytes:     capacity.MaximumClaimIngressReceiptEnvelopeBytes,
		MaximumClaimIngressCutProofBytes:            capacity.MaximumClaimIngressCutProofBytes,
		MaximumAcceptanceRequestEnvelopeBytes:       capacity.MaximumAcceptanceRequestEnvelopeBytes,
		MaximumAcceptanceReceiptEnvelopeBytes:       capacity.MaximumAcceptanceReceiptEnvelopeBytes,
		MaximumActivationEvidenceEnvelopeBytes:      capacity.MaximumActivationEvidenceEnvelopeBytes,
		MaximumNonActivationEvidenceEnvelopeBytes:   capacity.MaximumNonActivationEvidenceEnvelopeBytes,
		MaximumCancellationReceiptEnvelopeBytes:     capacity.MaximumCancellationReceiptEnvelopeBytes,
		MaximumClaimFilingCloseReceiptEnvelopeBytes: capacity.MaximumClaimFilingCloseReceiptEnvelopeBytes,
		MaximumTerminalClaimSetEnvelopeBytes:        capacity.MaximumTerminalClaimSetEnvelopeBytes,
		MaximumExposureReleaseRequestBytes:          capacity.MaximumExposureReleaseRequestBytes,
		MaximumExposureReleaseReceiptBytes:          capacity.MaximumExposureReleaseReceiptBytes,
		MaximumCoverageResolutionRequestBytes:       capacity.MaximumCoverageResolutionRequestBytes,
		MaximumCoverageResolutionEnvelopeBytes:      capacity.MaximumCoverageResolutionEnvelopeBytes,
		ContinuationBudgetProfile:                   capacity.ContinuationBudgetProfile,
		PermittedTerminalFallbacks:                  []DeterministicClaimTerminalFallbackV1{capacity.TerminalFallback},
		ReviewDeadlineSeconds:                       terms.ReviewDeadlineSeconds,
		MaximumNonterminalResolutionWindowSeconds:   terms.NonterminalResolutionWindowSeconds,
		MaximumSuccessorDecisionWindowSeconds:       terms.SuccessorDecisionWindowSeconds,
		MaximumLateIngressRecoveryWindowSeconds:     terms.LateIngressRecoveryWindowSeconds,
		PayoutDeadlineSeconds:                       terms.PayoutDeadlineSeconds}
	digest, err := Digest("tos.service.agent-guarantor-claim-profile.v1", profile)
	if err != nil {
		t.Fatal(err)
	}
	terms.SelectedClaimProfileDigest = digest
	return profile
}

// TestServiceProfileRefusesALateWindowOverTheClaimProfileMaximum: through
// ValidateCoverageTermsAgainstServiceProfile, terms whose late-ingress window
// exceeds the selected claim profile's maximum are refused, and terms at the
// maximum are accepted.
func TestServiceProfileRefusesALateWindowOverTheClaimProfileMaximum(t *testing.T) {
	terms := testLateTerms(t)
	claimProfile := testClaimProfileFor(t, &terms)
	profile := ServiceProfileV1{ClaimProfiles: []ClaimProfileV1{claimProfile},
		LifecycleAuthorizationProfile: terms.LifecycleAuthorizationProfile}
	if err := ValidateCoverageTermsAgainstServiceProfile(terms, profile); err != nil {
		t.Fatalf("terms at the claim profile's late window were refused: %v", err)
	}
	tighter := claimProfile
	tighter.MaximumLateIngressRecoveryWindowSeconds--
	over := terms
	profile.ClaimProfiles = []ClaimProfileV1{tighter}
	digest, err := Digest("tos.service.agent-guarantor-claim-profile.v1", tighter)
	if err != nil {
		t.Fatal(err)
	}
	over.SelectedClaimProfileDigest = digest
	if err := ValidateCoverageTermsAgainstServiceProfile(over, profile); err == nil ||
		!strings.Contains(err.Error(), "substitute the selected claim authorization profile") {
		t.Fatalf("a late window one second over the claim profile's maximum was not refused: %v", err)
	}
}

// TestCoverageTermsRefuseCollateralReleasableBeforeTheFinalDeadline: through
// ValidateCoverageTerms, collateralized terms whose release guard is one
// second earlier than the final deadline plus the reorg window are refused.
func TestCoverageTermsRefuseCollateralReleasableBeforeTheFinalDeadline(t *testing.T) {
	terms := testLateTerms(t)
	authority := CollateralAuthorizationBindingV1{AuthorizationProfile: testRef("1", "custody-authority"),
		AuthorizationSubjects: []string{"agent:custodian"}, AuthorizationQuorumRule: "all"}
	transition := CollateralTransitionProfileV1{TransitionKind: "payout", SuccessorDerivationProfile: testRef("2", "successor"),
		AdapterProfile: testRef("3", "custody-adapter"), AdapterRequestContentType: "application/vnd.tos.collateral-request.v1+cbor",
		AdapterRequestProfile: testRef("4", "request"), MaximumAdapterRequestBytes: 4096,
		AdapterEvidenceContentType: "application/vnd.tos.collateral-evidence.v1+cbor", AdapterEvidenceProfile: testRef("5", "evidence"),
		AuthorizationSubjectSource: "custodian", CustodianAuthorizationBinding: &authority,
		PermittedPriorStates: []string{"encumbered", "partially_consumed"}, PermittedResultingStates: []string{"depleted", "partially_consumed"},
		PrerequisiteEvidenceRoles: []string{"terminal-decision"}, AuthorizedClaimDecisionBinding: "required",
		PayoutDestinationBinding: "agreement_fixed"}
	transitionDigest, err := CollateralTransitionProfileDigestV1(transition)
	if err != nil {
		t.Fatal(err)
	}
	disclosure := CollateralControlDisclosureV1{SchemaVersion: 1, CustodyAdapterProfile: transition.AdapterProfile,
		AdapterOperatorSubjects: []string{"agent:custodian"}, CustodianControllerRootSubjects: []string{"root:custodian"},
		DeclaredGuarantorControlRelationship: "control_undetermined"}
	final, reorg := terms.LateRecoveryTerminalDeadlineUnix, uint64(60)
	terms.SelectedAssuranceLevel = AssuranceCollateralAttested
	terms.SelectedCollateralProfileDigest = testDigest("6")
	terms.CollateralObligationID = "obligation:collateral"
	terms.CollateralTerms = &CollateralTermsV1{PositionID: "position:one", SelectedCollateralProfileDigest: terms.SelectedCollateralProfileDigest,
		AssuranceLevel: AssuranceCollateralAttested, Asset: terms.CoverageAsset,
		Amount:                     AtomicAmountV1{Asset: terms.CoverageAsset, AmountAtomic: "1000"},
		CollateralPrincipalSubject: "agent:principal", CustodyAdapterProfile: transition.AdapterProfile,
		CollateralControlDisclosure: disclosure, PositionIdentityProfile: testRef("7", "position"),
		TransitionBindings: []CollateralTransitionBindingV1{{TransitionProfileDigest: transitionDigest, TransitionProfile: transition,
			AuthorizationBinding: authority}}, ContractOrAccountDigest: testDigest("8"),
		ExclusiveAllocationRequired: true, LockByUnix: terms.CoverageStartsAtUnix, LockUntilUnix: final + reorg + 600,
		ReleaseNotBeforeUnix: final + reorg, ReorgWindowSeconds: reorg,
		FinalityProfile: testRef("9", "finality"), MaximumEvidenceAgeSeconds: 60}
	if err := ValidateCoverageTerms(terms); err != nil {
		t.Fatalf("collateralized terms releasable at the final deadline plus the reorg window were refused: %v", err)
	}
	short := terms
	collateral := *terms.CollateralTerms
	collateral.ReleaseNotBeforeUnix--
	short.CollateralTerms = &collateral
	if err := ValidateCoverageTerms(short); err == nil ||
		!strings.Contains(err.Error(), "collateral may be released before the terms' final deadline") {
		t.Fatalf("collateral releasable one second before the final deadline plus the reorg window was not refused: %v", err)
	}
}
