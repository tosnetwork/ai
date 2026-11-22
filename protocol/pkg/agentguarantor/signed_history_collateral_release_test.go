package agentguarantor

import (
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// The Agreement's earliest-release guard on signed history: a collateral
// release transition, built in full and signed by the custodian, against the
// collateral terms' release_not_before_unix, and the terminal claim set of a
// collateralized coverage against the same guard.

// signedHistoryFinality accepts the Adapter finality of every transition: the
// signed history has no custody Adapter, and the guard is not its concern.
type signedHistoryFinality struct{}

func (signedHistoryFinality) VerifyCollateralAdapterFinalityV1(CollateralAdapterRequestV1, CollateralAdapterEvidenceV1,
	CollateralPositionStateV1, string, time.Time, CollateralTermsV1) error {
	return nil
}

// collateralizedHistoryTerms are the history's terms made collateral-attested:
// the collateral is locked by the coverage start until the final deadline plus
// the reorg window, releasable from then, with a payout and a release
// transition binding under the custodian's authorization.
func collateralizedHistoryTerms(t *testing.T, history *signedHistory) CoverageTermsV1 {
	t.Helper()
	terms := history.terms
	_, collateral := history.offerCollateral(terms, signedOfferFinalDeadline(terms)+signedOfferReorgWindow)
	payout := collateral.TransitionBindings[0]
	release := payout.TransitionProfile
	release.TransitionKind, release.PermittedPriorStates = "release", []string{"encumbered", "locked", "partially_consumed"}
	release.PermittedResultingStates, release.PrerequisiteEvidenceRoles = []string{"released"}, []string{"terminal-claim-set"}
	release.AuthorizedClaimDecisionBinding, release.PayoutDestinationBinding = "forbidden", "forbidden"
	releaseDigest, err := CollateralTransitionProfileDigestV1(release)
	if err != nil {
		t.Fatal(err)
	}
	collateral.TransitionBindings = append(collateral.TransitionBindings, CollateralTransitionBindingV1{
		TransitionProfileDigest: releaseDigest, TransitionProfile: release, AuthorizationBinding: payout.AuthorizationBinding})
	terms.SelectedAssuranceLevel, terms.SelectedCollateralProfileDigest = collateral.AssuranceLevel, collateral.SelectedCollateralProfileDigest
	terms.CollateralObligationID, terms.CollateralTerms = "obligation:collateral", &collateral
	if err := ValidateCoverageTerms(terms); err != nil {
		t.Fatalf("the collateralized signed-history terms are invalid: %v", err)
	}
	return terms
}

// collateralReleasePrerequisite is the evidence item by which a release names
// the authorized terminal claim set it is made against.
func collateralReleasePrerequisite(terms CoverageTermsV1) CanonicalGuarantorEvidenceItemV1 {
	return carriedEvidenceItem(terminalClaimSetContentTypeV1, testDigest("2"), []byte("terminal claim set"),
		terms.ClaimAdmissionProfile.ProfileDigest)
}

// collateralRelease is the custodian-signed evidence of the release of the
// whole collateral position of terms, made against prerequisite: the release
// action admitted at admittedAt under the collateral transition authority,
// and its Adapter evidence finalized at finalizedAt.
func (history *signedHistory) collateralRelease(terms CoverageTermsV1, prerequisite CanonicalGuarantorEvidenceItemV1,
	admittedAt, finalizedAt uint64) AuthorizedCollateralEvidenceV1 {
	t, collateral := history.t, *terms.CollateralTerms
	binding := collateral.TransitionBindings[len(collateral.TransitionBindings)-1]
	if binding.TransitionProfile.TransitionKind != "release" {
		t.Fatal("the collateral terms bind no release transition")
	}
	profile := binding.TransitionProfile
	bindingDigest, err := CollateralTransitionBindingDigestV1(binding)
	if err != nil {
		t.Fatal(err)
	}
	zero := AtomicAmountV1{Asset: collateral.Asset, AmountAtomic: "0"}
	position := CollateralPositionStateV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		CollateralObligationID: terms.CollateralObligationID, PositionID: collateral.PositionID, PositionDigest: testDigest("b"),
		CoverageBindingDigest: testDigest("c"), StateRevision: 3, Status: CollateralEncumbered, Asset: collateral.Asset,
		AllocatedAmount: collateral.Amount, CumulativeConsumed: zero, CumulativeReleased: zero, CumulativeImpaired: zero,
		RemainingAmount: collateral.Amount}
	stateDigest, err := CollateralPositionStateDigestV1(position)
	if err != nil {
		t.Fatal(err)
	}
	prerequisites := CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1, Purpose: "collateral-release", ContextDigest: history.agreement,
		Items: []CanonicalGuarantorEvidenceItemV1{prerequisite}}
	prerequisiteDigest, err := CanonicalGuarantorEvidenceSetDigestV1(prerequisites)
	if err != nil {
		t.Fatal(err)
	}
	request := CollateralAdapterRequestV1{SchemaVersion: 1, AdapterProfile: profile.AdapterProfile,
		AdapterRequestProfile: profile.AdapterRequestProfile, CoverageAgreementBodyDigest: history.agreement,
		CollateralObligationID: terms.CollateralObligationID, CollateralPositionID: collateral.PositionID,
		TransitionBindingDigest: bindingDigest, TransitionKind: "release", ExpectedPositionState: position,
		ExpectedStateDigest: stateDigest, Asset: collateral.Asset, Amount: collateral.Amount,
		PrerequisiteEvidenceSetDigest: prerequisiteDigest, AdapterOperationParameters: []byte{0xa0}}
	requestDigest, err := CollateralAdapterRequestDigestV1(request, binding, collateral)
	if err != nil {
		t.Fatalf("signed-history collateral release request is invalid: %v", err)
	}
	released, err := ApplyCollateralAdapterTransitionV1(request, binding, collateral)
	if err != nil {
		t.Fatal(err)
	}
	releasedDigest, err := CollateralPositionStateDigestV1(released)
	if err != nil {
		t.Fatal(err)
	}
	action := CollateralTransitionActionBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		ObligationID: terms.CollateralObligationID, CollateralPositionID: collateral.PositionID, TransitionBinding: binding,
		TransitionKind: "release", ExpectedStateRevision: position.StateRevision, ExpectedStateDigest: stateDigest,
		Asset: collateral.Asset, Amount: collateral.Amount, PrerequisiteEvidenceSet: prerequisites, AdapterRequest: request}
	canonical, err := Canonical(action)
	if err != nil {
		t.Fatal(err)
	}
	actionBodyDigest, err := Digest("tos.service.agent-guarantor-collateral-transition-action-body.v1", action)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := derivedAuxiliaryStageAuthorityV1(terms.StageActionAuthorityBinding, "collateral_transition", "payout_execution")
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]agentcommerce.SemanticValue{
		"owner_id": agentcommerce.ID(bound.ActionOwnerID), "agent_id": agentcommerce.ID(bound.ActionAgentID),
		"agreement_body_digest": agentcommerce.Digest32(history.agreement), "obligation_id": agentcommerce.ID(terms.CollateralObligationID),
		"collateral_position_id":    agentcommerce.ID(collateral.PositionID),
		"transition_binding_digest": agentcommerce.Digest32(bindingDigest),
		"expected_state_revision":   agentcommerce.U64(position.StateRevision), "transition_kind": agentcommerce.Kind("release")}
	stage := history.stageFor(bound, "application/vnd.tos.service.agent-guarantor-collateral-transition-action.v1+cbor",
		canonical, fields, testDigest("1"), admittedAt+600, admittedAt, "", nil)
	stageAction := stage.AuthorizedAction
	actionDigest, err := agentcommerce.AuthorizedActionDigest(stageAction)
	if err != nil {
		t.Fatal(err)
	}
	adapter := CollateralAdapterEvidenceV1{ContentType: profile.AdapterEvidenceContentType, EvidenceProfile: profile.AdapterEvidenceProfile,
		TransitionBindingDigest: bindingDigest, AdapterProfileDigest: profile.AdapterProfile.ProfileDigest, TransitionKind: "release",
		AdapterRequestDigest: requestDigest, PriorStateRevision: position.StateRevision, ResultingStateRevision: released.StateRevision,
		ExpectedStateDigest: stateDigest, ResultingStateDigest: releasedDigest, Representation: "inline",
		CanonicalEvidenceBytes: []byte("finalized release")}
	adapterDigest, err := CollateralAdapterEvidenceDigestV1(adapter)
	if err != nil {
		t.Fatal(err)
	}
	eligibility := history.eligibility(actionDigest, actionBodyDigest, binding.AuthorizationBinding.AuthorizationSubjects,
		"collateral-evidence", stageAction.ExactRequestDigest, bindingDigest, binding.AuthorizationBinding.AuthorizationProfile,
		bindingDigest, 1, admittedAt)
	eligibilityDigest, err := AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	if err != nil {
		t.Fatal(err)
	}
	body := CollateralEvidenceBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		CollateralObligationID: terms.CollateralObligationID, PositionID: collateral.PositionID, PositionDigest: released.PositionDigest,
		TransitionBindingDigest: bindingDigest, CollateralTransitionActionBodyDigest: actionBodyDigest,
		AdapterProfile: profile.AdapterProfile, EvidenceProfile: profile.AdapterEvidenceProfile,
		EvidenceContentType: profile.AdapterEvidenceContentType, TransitionKind: "release", Amount: collateral.Amount,
		CumulativeConsumed: released.CumulativeConsumed, PriorStateRevision: position.StateRevision,
		ResultingStateRevision: released.StateRevision, ExpectedStateDigest: stateDigest, ResultingStateDigest: releasedDigest,
		CoverageBindingDigest: released.CoverageBindingDigest, FinalityReference: testDigest("d"), FinalizedAtUnix: finalizedAt,
		AdapterRequestDigest: requestDigest, AdapterEvidenceDigest: adapterDigest, AuthorizedActionDigest: actionDigest,
		StableActionID: stageAction.StableActionID, ExactRequestDigest: stageAction.ExactRequestDigest,
		WriterGeneration: stageAction.WriterGeneration, WriterFenceDigest: stageAction.WriterFenceDigest,
		AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	bodyDigest, err := Digest("tos.service.agent-guarantor-collateral-evidence-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	evidence := AuthorizedCollateralEvidenceV1{Body: body, StageActionAdmissionEvidence: stage,
		CollateralTransitionActionBody: action, AdapterEvidence: adapter, ResultingPositionState: released,
		AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObjectAs(
			binding.AuthorizationBinding.AuthorizationSubjects[0], binding.AuthorizationBinding.AuthorizationProfile,
			"collateral-evidence", bodyDigest, "tos.service.agent-guarantor-collateral-evidence-signature.v1", finalizedAt)}}
	if _, err := CollateralEvidenceDigestV1(evidence); err != nil {
		t.Fatalf("signed-history collateral release evidence is malformed: %v", err)
	}
	return evidence
}

// TestSignedHistoryCollateralReleaseRespectsTheReleaseGuard: a collateral
// release transition is admitted, and its Adapter evidence finalized, no
// earlier than the collateral terms' release_not_before_unix, and it names an
// authorized terminal claim set as its prerequisite. The complete
// custodian-signed release admitted and finalized exactly at the guard is
// accepted by the collateral evidence verifier; the same release admitted a
// second before the guard, finalized a second before it, or made against a
// prerequisite that is no terminal claim set, is refused.
func TestSignedHistoryCollateralReleaseRespectsTheReleaseGuard(t *testing.T) {
	history := newSignedHistory(t)
	terms := collateralizedHistoryTerms(t, history)
	bound, err := derivedAuxiliaryStageAuthorityV1(terms.StageActionAuthorityBinding, "collateral_transition", "payout_execution")
	if err != nil {
		t.Fatal(err)
	}
	history.useOfferPhaseFence(bound.OperationActionKind)
	guard := terms.CollateralTerms.ReleaseNotBeforeUnix
	if guard >= history.fence.Body.ExpiresAtUnix {
		t.Fatalf("the release guard %d is not inside the history's Writer Fence, which expires at %d", guard, history.fence.Body.ExpiresAtUnix)
	}
	claimSet := collateralReleasePrerequisite(terms)
	other := claimSet
	other.ContentType = ClaimFilingCloseReceiptMediaTypeV1
	descriptor := *claimSet.ImmutableDescriptor
	descriptor.ContentType = ClaimFilingCloseReceiptMediaTypeV1
	other.ImmutableDescriptor = &descriptor
	for _, test := range []struct {
		name                  string
		prerequisite          CanonicalGuarantorEvidenceItemV1
		admittedAt, finalized uint64
		want                  string
	}{
		{"a release admitted and finalized at the release guard", claimSet, guard, guard, ""},
		{"a release admitted a second before the release guard", claimSet, guard - 1, guard,
			"Guarantor collateral release is admitted before the Agreement's release guard"},
		{"a release finalized a second before the release guard", claimSet, guard, guard - 1,
			"Guarantor collateral release is finalized before the Agreement's release guard"},
		{"a release whose prerequisite is a filing close and no terminal claim set", other, guard, guard,
			"Guarantor collateral release does not name exactly one authorized terminal claim set as its prerequisite"},
	} {
		evidence := history.collateralRelease(terms, test.prerequisite, test.admittedAt, test.finalized)
		err := VerifyCollateralEvidenceV1(evidence, terms, history.resolver, history.fenceResolver, signedHistoryTime(guard),
			signedHistoryFinality{}, false)
		if test.want == "" {
			if err != nil {
				t.Errorf("%s is refused: %v", test.name, err)
			}
			continue
		}
		refusedFor(t, test.name, err, test.want)
	}
}

// TestSignedHistoryTerminalClaimSetRespectsTheCollateralReleaseGuard: the
// terminal claim set of a collateralized coverage allows its release no
// earlier than the collateral terms' release_not_before_unix, so the exposure
// release that follows the set cannot precede the guard. A set that allows its
// release exactly at the guard is accepted; one that allows it a second
// earlier is refused.
func TestSignedHistoryTerminalClaimSetRespectsTheCollateralReleaseGuard(t *testing.T) {
	terms := collateralizedHistoryTerms(t, newSignedHistory(t))
	guard := terms.CollateralTerms.ReleaseNotBeforeUnix
	for _, test := range []struct {
		name        string
		releaseFrom uint64
		want        string
	}{
		{"a set that allows its release at the collateral release guard", guard, ""},
		{"a set that allows its release a second before the collateral release guard", guard - 1,
			"terminal claim set allows its release before the Agreement's collateral release guard"},
	} {
		history, claimID := claimFiledAt(t, 40, &terms)
		denied := history.fallback(claimID, nil, signedHistoryStart+40+terms.ReviewDeadlineSeconds)
		closeAt := denied.Body.ChallengeEndsAtUnix
		history.challengeClose(claimID, closeAt)
		application := history.apply(claimID, history.materialize(claimID, terms), closeAt+10)
		filedAt := terms.ClaimFilingEndsAtUnix + 10
		filing := history.filingClose(filedAt)
		closedAt := filedAt + 10
		if closedAt >= test.releaseFrom {
			t.Fatalf("%s: the coverage closes at %d, not before its release time %d", test.name, closedAt, test.releaseFrom)
		}
		bundle := history.terminalBundle(claimID, application, closedAt)
		history.vary = signedHistoryVariation{closureContext: func(closure *CoverageClosureEvidenceContextV1) {
			closure.ReleaseNotBeforeUnix = test.releaseFrom
		}}
		set := history.terminalSet(filing, []ClaimTerminalResolutionBundleV1{bundle}, closedAt)
		history.vary = signedHistoryVariation{}
		if err := ValidateTerminalClaimSetV1(set); err != nil {
			t.Errorf("%s: the set is already refused by its shape: %v", test.name, err)
		}
		err := history.verifyTerminalSet(set, closedAt)
		if test.want == "" {
			if err != nil {
				t.Errorf("%s is refused: %v", test.name, err)
			}
			continue
		}
		refusedFor(t, test.name, err, test.want)
	}
}
