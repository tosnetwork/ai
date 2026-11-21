package agentguarantor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
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

// seamUse is one appearance of a seam identifier in the package's source,
// with the syntax nodes enclosing it, innermost first.
type seamUse struct {
	position string
	parents  []ast.Node
	ident    *ast.Ident
}

// packageSeamUses parses every Go file of the package whose test-ness is
// tests, and returns each use of the identifier name.
func packageSeamUses(t *testing.T, name string, tests bool) []seamUse {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	var uses []seamUse
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") != tests {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		var stack []ast.Node
		ast.Inspect(parsed, func(node ast.Node) bool {
			if node == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			if ident, ok := node.(*ast.Ident); ok && ident.Name == name {
				parents := make([]ast.Node, len(stack))
				for index := range stack {
					parents[index] = stack[len(stack)-1-index]
				}
				uses = append(uses, seamUse{position: fileSet.Position(ident.Pos()).String(), parents: parents, ident: ident})
			}
			stack = append(stack, node)
			return true
		})
	}
	return uses
}

// isPackageVarDeclarationName reports whether use is the declared name of a
// package-level var.
func isPackageVarDeclarationName(use seamUse) bool {
	if len(use.parents) < 3 {
		return false
	}
	spec, isSpec := use.parents[0].(*ast.ValueSpec)
	declaration, isDeclaration := use.parents[1].(*ast.GenDecl)
	_, isFile := use.parents[2].(*ast.File)
	return isSpec && isDeclaration && isFile && declaration.Tok == token.VAR && len(spec.Names) == 1 && spec.Names[0] == use.ident
}

// isCallee reports whether node is exactly the function a call calls.
func isCallee(node ast.Node, parent ast.Node) bool {
	call, ok := parent.(*ast.CallExpr)
	return ok && call.Fun == node
}

// TestActivationPredecessorSeamIsAssignedOnlyInTests: in the package's
// non-test files the seam appears exactly once as its package-level
// declaration, and otherwise only as the function a call calls. Taking its
// address, assigning it, aliasing it or passing it as a value fails here,
// wherever it happens.
func TestActivationPredecessorSeamIsAssignedOnlyInTests(t *testing.T) {
	declarations := 0
	for _, use := range packageSeamUses(t, "coverageActivationPredecessorVerifierV1", false) {
		switch {
		case isPackageVarDeclarationName(use):
			declarations++
			spec := use.parents[0].(*ast.ValueSpec)
			if len(spec.Values) != 1 {
				t.Errorf("%s: the seam is declared without its real default", use.position)
			} else if value, ok := spec.Values[0].(*ast.Ident); !ok || value.Name != "VerifyCoverageActivationEvidenceV1" {
				t.Errorf("%s: the seam's default is not VerifyCoverageActivationEvidenceV1", use.position)
			}
		case len(use.parents) > 0 && isCallee(use.ident, use.parents[0]):
		default:
			t.Errorf("%s: the activation predecessor seam is used other than by calling it", use.position)
		}
	}
	if declarations != 1 {
		t.Fatalf("the activation predecessor seam is declared %d times, want once", declarations)
	}
}

// TestActivationPrerequisiteSeamIsAssignedOnlyInTests: in the package's
// non-test files the prerequisite verifier seam appears once as its
// package-level declaration, and otherwise only as the receiver of a field
// that is called at once (activationPrerequisiteVerifiersV1.collateral(...)).
func TestActivationPrerequisiteSeamIsAssignedOnlyInTests(t *testing.T) {
	declarations := 0
	for _, use := range packageSeamUses(t, "activationPrerequisiteVerifiersV1", false) {
		switch {
		case isPackageVarDeclarationName(use):
			declarations++
		case len(use.parents) > 1:
			selector, isSelector := use.parents[0].(*ast.SelectorExpr)
			if !isSelector || selector.X != use.ident || !isCallee(selector, use.parents[1]) {
				t.Errorf("%s: the activation prerequisite seam is used other than by calling one of its verifiers", use.position)
			}
		default:
			t.Errorf("%s: the activation prerequisite seam is used other than by calling one of its verifiers", use.position)
		}
	}
	if declarations != 1 {
		t.Fatalf("the activation prerequisite seam is declared %d times, want once", declarations)
	}
}

// TestSeamTestsNeverRunInParallel: the verifier seams are package-level
// variables that tests replace and restore, so no test in the package may
// run in parallel with another. Any selector named Parallel fails here,
// called or not: a method value (f := t.Parallel) is as much a way to run in
// parallel as the call.
func TestSeamTestsNeverRunInParallel(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	for _, file := range files {
		parsed, err := parser.ParseFile(fileSet, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok && selector.Sel.Name == "Parallel" {
				t.Errorf("%s: a test of this package runs in parallel while the verifier seams are package variables",
					fileSet.Position(selector.Pos()))
			}
			return true
		})
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
