package agentguarantor

import (
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// Collateral evidence on signed history: a collateral transition built in
// full and signed by the custodian, held to the Agreement's transition
// bindings and collateral obligation; a release against the collateral terms'
// release_not_before_unix and against the terminal claim set it names; and
// the terminal claim set of a collateralized coverage against the same guard.

// signedHistoryFinality accepts the Adapter finality of every transition: the
// signed history has no custody Adapter, and the guard is not its concern.
type signedHistoryFinality struct{}

func (signedHistoryFinality) VerifyCollateralAdapterFinalityV1(CollateralAdapterRequestV1, CollateralAdapterEvidenceV1,
	CollateralPositionStateV1, string, time.Time, CollateralTermsV1) error {
	return nil
}

// collateralizedHistoryTerms are the history's terms made collateral-attested:
// the collateral is locked by the coverage start until the final deadline plus
// the reorg window, releasable from then, with lock, payout and release
// transition bindings under the custodian's authorization.
func collateralizedHistoryTerms(t *testing.T, history *signedHistory) CoverageTermsV1 {
	t.Helper()
	terms := history.terms
	_, collateral := history.offerCollateral(terms, signedOfferFinalDeadline(terms)+signedOfferReorgWindow)
	terms.SelectedAssuranceLevel, terms.SelectedCollateralProfileDigest = collateral.AssuranceLevel, collateral.SelectedCollateralProfileDigest
	terms.CollateralObligationID, terms.CollateralTerms = "obligation:collateral", &collateral
	if err := ValidateCoverageTerms(terms); err != nil {
		t.Fatalf("the collateralized signed-history terms are invalid: %v", err)
	}
	return terms
}

// collateralReleasePrerequisite is the evidence item by which a release names
// the authorized terminal claim set of digest it is made against.
func collateralReleasePrerequisite(terms CoverageTermsV1, digest string) CanonicalGuarantorEvidenceItemV1 {
	return carriedEvidenceItem(terminalClaimSetContentTypeV1, digest, []byte("terminal claim set"),
		terms.ClaimAdmissionProfile.ProfileDigest)
}

// collateralTransition is one transition of a coverage's collateral position:
// its kind, the coverage Agreement it names, the status of the position before
// it, the purpose and the items, in canonical order, of its prerequisite
// evidence set, the time its action is admitted at under the collateral
// transition authority and the time its Adapter evidence is finalized at.
type collateralTransition struct {
	kind, agreement, purpose string
	prior                    CollateralStatus
	prerequisite             []CanonicalGuarantorEvidenceItemV1
	admittedAt, finalizedAt  uint64
}

// collateralEvidence is the custodian-signed evidence of a transition of the
// whole collateral position of terms, under the terms' binding of its kind:
// the action, the Adapter request and evidence, the resulting position, the
// stage admission evidence and the authorization. The history's variation may
// change the binding, the obligation and the prerequisite set; a changed
// binding is then the only binding of the terms the custodian signs under.
func (history *signedHistory) collateralEvidence(terms CoverageTermsV1, in collateralTransition) AuthorizedCollateralEvidenceV1 {
	t, collateral := history.t, *terms.CollateralTerms
	binding, obligation := collateralBindingOf(t, collateral, in.kind), terms.CollateralObligationID
	if history.vary.collateralBinding != nil {
		history.vary.collateralBinding(&binding)
		collateral.TransitionBindings = []CollateralTransitionBindingV1{binding}
	}
	if history.vary.collateralObligation != "" {
		obligation = history.vary.collateralObligation
	}
	profile := binding.TransitionProfile
	bindingDigest, err := CollateralTransitionBindingDigestV1(binding)
	if err != nil {
		t.Fatalf("signed-history collateral transition binding is invalid: %v", err)
	}
	zero := AtomicAmountV1{Asset: collateral.Asset, AmountAtomic: "0"}
	position := CollateralPositionStateV1{SchemaVersion: 1, CoverageAgreementBodyDigest: in.agreement,
		CollateralObligationID: obligation, PositionID: collateral.PositionID, PositionDigest: testDigest("b"),
		CoverageBindingDigest: testDigest("c"), StateRevision: 3, Status: in.prior, Asset: collateral.Asset,
		AllocatedAmount: collateral.Amount, CumulativeConsumed: zero, CumulativeReleased: zero, CumulativeImpaired: zero,
		RemainingAmount: collateral.Amount}
	stateDigest, err := CollateralPositionStateDigestV1(position)
	if err != nil {
		t.Fatal(err)
	}
	prerequisites := CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1, Purpose: in.purpose, ContextDigest: in.agreement,
		Items: in.prerequisite}
	if history.vary.collateralPrerequisites != nil {
		history.vary.collateralPrerequisites(&prerequisites)
	}
	prerequisiteDigest, err := CanonicalGuarantorEvidenceSetDigestV1(prerequisites)
	if err != nil {
		t.Fatalf("signed-history collateral prerequisites are no canonical evidence set: %v", err)
	}
	request := CollateralAdapterRequestV1{SchemaVersion: 1, AdapterProfile: profile.AdapterProfile,
		AdapterRequestProfile: profile.AdapterRequestProfile, CoverageAgreementBodyDigest: in.agreement,
		CollateralObligationID: obligation, CollateralPositionID: collateral.PositionID,
		TransitionBindingDigest: bindingDigest, TransitionKind: in.kind, ExpectedPositionState: position,
		ExpectedStateDigest: stateDigest, Asset: collateral.Asset, Amount: collateral.Amount,
		PrerequisiteEvidenceSetDigest: prerequisiteDigest, AdapterOperationParameters: []byte{0xa0}}
	requestDigest, err := CollateralAdapterRequestDigestV1(request, binding, collateral)
	if err != nil {
		t.Fatalf("signed-history collateral %s request is invalid: %v", in.kind, err)
	}
	resulting, err := ApplyCollateralAdapterTransitionV1(request, binding, collateral)
	if err != nil {
		t.Fatal(err)
	}
	resultingDigest, err := CollateralPositionStateDigestV1(resulting)
	if err != nil {
		t.Fatal(err)
	}
	action := CollateralTransitionActionBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: in.agreement,
		ObligationID: obligation, CollateralPositionID: collateral.PositionID, TransitionBinding: binding,
		TransitionKind: in.kind, ExpectedStateRevision: position.StateRevision, ExpectedStateDigest: stateDigest,
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
		"agreement_body_digest": agentcommerce.Digest32(in.agreement), "obligation_id": agentcommerce.ID(obligation),
		"collateral_position_id":    agentcommerce.ID(collateral.PositionID),
		"transition_binding_digest": agentcommerce.Digest32(bindingDigest),
		"expected_state_revision":   agentcommerce.U64(position.StateRevision), "transition_kind": agentcommerce.Kind(in.kind)}
	stage := history.stageFor(bound, "application/vnd.tos.service.agent-guarantor-collateral-transition-action.v1+cbor",
		canonical, fields, testDigest("1"), in.admittedAt+600, in.admittedAt, "", nil)
	stageAction := stage.AuthorizedAction
	actionDigest, err := agentcommerce.AuthorizedActionDigest(stageAction)
	if err != nil {
		t.Fatal(err)
	}
	adapter := CollateralAdapterEvidenceV1{ContentType: profile.AdapterEvidenceContentType, EvidenceProfile: profile.AdapterEvidenceProfile,
		TransitionBindingDigest: bindingDigest, AdapterProfileDigest: profile.AdapterProfile.ProfileDigest, TransitionKind: in.kind,
		AdapterRequestDigest: requestDigest, PriorStateRevision: position.StateRevision, ResultingStateRevision: resulting.StateRevision,
		ExpectedStateDigest: stateDigest, ResultingStateDigest: resultingDigest, Representation: "inline",
		CanonicalEvidenceBytes: []byte("finalized " + in.kind)}
	adapterDigest, err := CollateralAdapterEvidenceDigestV1(adapter)
	if err != nil {
		t.Fatal(err)
	}
	eligibility := history.eligibility(actionDigest, actionBodyDigest, binding.AuthorizationBinding.AuthorizationSubjects,
		"collateral-evidence", stageAction.ExactRequestDigest, bindingDigest, binding.AuthorizationBinding.AuthorizationProfile,
		bindingDigest, 1, in.admittedAt)
	eligibilityDigest, err := AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	if err != nil {
		t.Fatal(err)
	}
	body := CollateralEvidenceBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: in.agreement,
		CollateralObligationID: obligation, PositionID: collateral.PositionID, PositionDigest: resulting.PositionDigest,
		TransitionBindingDigest: bindingDigest, CollateralTransitionActionBodyDigest: actionBodyDigest,
		AdapterProfile: profile.AdapterProfile, EvidenceProfile: profile.AdapterEvidenceProfile,
		EvidenceContentType: profile.AdapterEvidenceContentType, TransitionKind: in.kind, Amount: collateral.Amount,
		CumulativeConsumed: resulting.CumulativeConsumed, PriorStateRevision: position.StateRevision,
		ResultingStateRevision: resulting.StateRevision, ExpectedStateDigest: stateDigest, ResultingStateDigest: resultingDigest,
		CoverageBindingDigest: resulting.CoverageBindingDigest, FinalityReference: testDigest("d"), FinalizedAtUnix: in.finalizedAt,
		AdapterRequestDigest: requestDigest, AdapterEvidenceDigest: adapterDigest, AuthorizedActionDigest: actionDigest,
		StableActionID: stageAction.StableActionID, ExactRequestDigest: stageAction.ExactRequestDigest,
		WriterGeneration: stageAction.WriterGeneration, WriterFenceDigest: stageAction.WriterFenceDigest,
		AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	bodyDigest, err := Digest("tos.service.agent-guarantor-collateral-evidence-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	evidence := AuthorizedCollateralEvidenceV1{Body: body, StageActionAdmissionEvidence: stage,
		CollateralTransitionActionBody: action, AdapterEvidence: adapter, ResultingPositionState: resulting,
		AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObjectAs(
			binding.AuthorizationBinding.AuthorizationSubjects[0], binding.AuthorizationBinding.AuthorizationProfile,
			"collateral-evidence", bodyDigest, "tos.service.agent-guarantor-collateral-evidence-signature.v1", in.finalizedAt)}}
	if _, err := CollateralEvidenceDigestV1(evidence); err != nil {
		t.Fatalf("signed-history collateral %s evidence is malformed: %v", in.kind, err)
	}
	return evidence
}

// collateralRelease is the custodian-signed evidence of the release of the
// whole encumbered collateral position of terms on the history's coverage
// Agreement, made against the prerequisite items.
func (history *signedHistory) collateralRelease(terms CoverageTermsV1, prerequisite []CanonicalGuarantorEvidenceItemV1,
	admittedAt, finalizedAt uint64) AuthorizedCollateralEvidenceV1 {
	return history.collateralEvidence(terms, collateralTransition{kind: "release", agreement: history.agreement,
		purpose: collateralReleasePrerequisitePurposeV1, prior: CollateralEncumbered, prerequisite: prerequisite,
		admittedAt: admittedAt, finalizedAt: finalizedAt})
}

// collateralReleaseHistory is a signed history whose Writer Fence covers the
// collateral transition action, with its terms made collateral-attested and
// the collateral terms' release guard.
func collateralReleaseHistory(t *testing.T) (*signedHistory, CoverageTermsV1, uint64) {
	t.Helper()
	history := newSignedHistory(t)
	terms := collateralizedHistoryTerms(t, history)
	history.useCollateralFence(terms)
	return history, terms, terms.CollateralTerms.ReleaseNotBeforeUnix
}

// useCollateralFence widens the history's Writer Fence to the collateral
// transition action and checks that the terms' release guard is inside it.
func (history *signedHistory) useCollateralFence(terms CoverageTermsV1) {
	t := history.t
	bound, err := derivedAuxiliaryStageAuthorityV1(terms.StageActionAuthorityBinding, "collateral_transition", "payout_execution")
	if err != nil {
		t.Fatal(err)
	}
	history.useOfferPhaseFence(bound.OperationActionKind)
	if guard := terms.CollateralTerms.ReleaseNotBeforeUnix; guard >= history.fence.Body.ExpiresAtUnix {
		t.Fatalf("the release guard %d is not inside the history's Writer Fence, which expires at %d", guard, history.fence.Body.ExpiresAtUnix)
	}
}

// verifyCollateral is the collateral evidence verifier at at.
func (history *signedHistory) verifyCollateral(evidence AuthorizedCollateralEvidenceV1, terms CoverageTermsV1, at uint64) error {
	return VerifyCollateralEvidenceV1(evidence, terms, history.resolver, history.fenceResolver, signedHistoryTime(at),
		signedHistoryFinality{}, false)
}

// TestSignedHistoryCollateralReleaseRespectsTheReleaseGuard: a collateral
// release transition is admitted, and its Adapter evidence finalized, no
// earlier than the collateral terms' release_not_before_unix, and it names an
// authorized terminal claim set as its prerequisite, and only one. The
// complete custodian-signed release admitted and finalized exactly at the
// guard is accepted by the collateral evidence verifier; the same release
// admitted a second before the guard, finalized a second before it, made
// against a prerequisite that is no terminal claim set, or made against two
// terminal claim sets, which are a canonical evidence set like any other, is
// refused.
func TestSignedHistoryCollateralReleaseRespectsTheReleaseGuard(t *testing.T) {
	history, terms, guard := collateralReleaseHistory(t)
	claimSet := collateralReleasePrerequisite(terms, testDigest("2"))
	secondClaimSet := collateralReleasePrerequisite(terms, testDigest("3"))
	other := claimSet
	other.ContentType = ClaimFilingCloseReceiptMediaTypeV1
	descriptor := *claimSet.ImmutableDescriptor
	descriptor.ContentType = ClaimFilingCloseReceiptMediaTypeV1
	other.ImmutableDescriptor = &descriptor
	one := []CanonicalGuarantorEvidenceItemV1{claimSet}
	for _, test := range []struct {
		name                  string
		prerequisite          []CanonicalGuarantorEvidenceItemV1
		admittedAt, finalized uint64
		want                  string
	}{
		{"a release admitted and finalized at the release guard", one, guard, guard, ""},
		{"a release admitted a second before the release guard", one, guard - 1, guard,
			"Guarantor collateral release is admitted before the Agreement's release guard"},
		{"a release finalized a second before the release guard", one, guard, guard - 1,
			"Guarantor collateral release is finalized before the Agreement's release guard"},
		{"a release whose prerequisite is a filing close and no terminal claim set",
			[]CanonicalGuarantorEvidenceItemV1{other}, guard, guard,
			"Guarantor collateral release does not name exactly one authorized terminal claim set as its prerequisite"},
		{"a release that names two terminal claim sets",
			[]CanonicalGuarantorEvidenceItemV1{claimSet, secondClaimSet}, guard, guard,
			"Guarantor collateral release does not name exactly one authorized terminal claim set as its prerequisite"},
	} {
		evidence := history.collateralRelease(terms, test.prerequisite, test.admittedAt, test.finalized)
		expectVerdict(t, test.name, history.verifyCollateral(evidence, terms, guard), test.want)
	}
}

// TestSignedHistoryCollateralReleaseCommitsItsTerminalClaimSet: the
// prerequisite evidence set of a release has the release purpose and the
// release's coverage Agreement as context, and names its terminal claim set
// through a descriptor of the set's media type and of the item's own envelope
// digest. A release whose set has another purpose or another context, or
// whose descriptor is of another media type or of another object, is refused;
// each differs from the accepted release in that one field of the set, and is
// signed over the changed set.
func TestSignedHistoryCollateralReleaseCommitsItsTerminalClaimSet(t *testing.T) {
	history, terms, guard := collateralReleaseHistory(t)
	one := []CanonicalGuarantorEvidenceItemV1{collateralReleasePrerequisite(terms, testDigest("2"))}
	described := func(change func(*ImmutableEvidenceDescriptorV1)) func(*CanonicalGuarantorEvidenceSetV1) {
		return func(set *CanonicalGuarantorEvidenceSetV1) {
			item := set.Items[0]
			descriptor := *item.ImmutableDescriptor
			change(&descriptor)
			item.ImmutableDescriptor = &descriptor
			set.Items = []CanonicalGuarantorEvidenceItemV1{item}
		}
	}
	for _, test := range []struct {
		name   string
		change func(*CanonicalGuarantorEvidenceSetV1)
		want   string
	}{
		{"a release whose prerequisite set is as the release commits it", nil, ""},
		{"a release whose prerequisite set has the purpose of an activation",
			func(set *CanonicalGuarantorEvidenceSetV1) { set.Purpose = "coverage-activation-collateral" },
			"Guarantor collateral release prerequisites have another purpose than a collateral release"},
		{"a release whose prerequisite set has another Agreement as context",
			func(set *CanonicalGuarantorEvidenceSetV1) { set.ContextDigest = testDigest("9") },
			"Guarantor collateral release prerequisites are of another coverage Agreement than the release"},
		{"a release whose terminal claim set descriptor is of a filing close",
			described(func(descriptor *ImmutableEvidenceDescriptorV1) {
				descriptor.ContentType = ClaimFilingCloseReceiptMediaTypeV1
			}),
			"Guarantor collateral release names its terminal claim set through a descriptor of another media type"},
		{"a release whose terminal claim set descriptor is of another object",
			described(func(descriptor *ImmutableEvidenceDescriptorV1) { descriptor.ContentDigest = testDigest("4") }),
			"Guarantor collateral release names its terminal claim set through a descriptor of another object"},
	} {
		history.vary = signedHistoryVariation{collateralPrerequisites: test.change}
		evidence := history.collateralRelease(terms, one, guard, guard)
		history.vary = signedHistoryVariation{}
		expectVerdict(t, test.name, history.verifyCollateral(evidence, terms, guard), test.want)
	}
}

// otherCustodian makes binding a self-consistent binding under another
// custodian: the transition profile's custodian authorization and the
// binding's own both name it, and the profile digest is recomputed.
func otherCustodian(t *testing.T) func(*CollateralTransitionBindingV1) {
	return func(binding *CollateralTransitionBindingV1) {
		authority := binding.AuthorizationBinding
		authority.AuthorizationSubjects = []string{"agent:other-custodian"}
		binding.AuthorizationBinding, binding.TransitionProfile.CustodianAuthorizationBinding = authority, &authority
		digest, err := CollateralTransitionProfileDigestV1(binding.TransitionProfile)
		if err != nil {
			t.Fatal(err)
		}
		binding.TransitionProfileDigest = digest
	}
}

// TestSignedHistoryCollateralEvidenceIsUnderTheAgreementsBindingAndObligation:
// collateral evidence is of the Agreement's collateral. Its transition is made
// under one of the collateral terms' transition bindings and for the terms'
// collateral obligation. A complete release signed by the terms' custodian
// under the terms' release binding is accepted. The same release made under a
// binding that is well formed on its own but names another custodian, who
// signs it, is refused, as is one that names another obligation. A binding in
// which only the binding's own authorization names the other custodian is not
// well formed and has no digest, so no evidence exists under it.
func TestSignedHistoryCollateralEvidenceIsUnderTheAgreementsBindingAndObligation(t *testing.T) {
	const foreign = "Guarantor collateral transition binding is not one of the Agreement's transition bindings"
	history, terms, guard := collateralReleaseHistory(t)
	one := []CanonicalGuarantorEvidenceItemV1{collateralReleasePrerequisite(terms, testDigest("2"))}
	for _, test := range []struct {
		name string
		vary signedHistoryVariation
		want string
	}{
		{"a release under the terms' release binding for the terms' collateral obligation", signedHistoryVariation{}, ""},
		{"a release under a binding of another custodian", signedHistoryVariation{collateralBinding: otherCustodian(t)}, foreign},
		{"a release for another obligation", signedHistoryVariation{collateralObligation: "obligation:other"},
			"Guarantor collateral evidence is of another obligation than the Agreement's collateral obligation"},
	} {
		history.vary = test.vary
		evidence := history.collateralRelease(terms, one, guard, guard)
		history.vary = signedHistoryVariation{}
		expectVerdict(t, test.name, history.verifyCollateral(evidence, terms, guard), test.want)
	}

	// The Adapter request and the transition it derives are held to the terms'
	// bindings as well, whoever computes them.
	agreed := history.collateralRelease(terms, one, guard, guard).CollateralTransitionActionBody
	history.vary = signedHistoryVariation{collateralBinding: otherCustodian(t)}
	selfChosen := history.collateralRelease(terms, one, guard, guard).CollateralTransitionActionBody
	history.vary = signedHistoryVariation{}
	for _, test := range []struct {
		name   string
		action CollateralTransitionActionBodyV1
		want   string
	}{
		{"the request of a release under the terms' release binding", agreed, ""},
		{"the request of a release under a binding of another custodian", selfChosen, foreign},
	} {
		_, digestErr := CollateralAdapterRequestDigestV1(test.action.AdapterRequest, test.action.TransitionBinding, *terms.CollateralTerms)
		expectVerdict(t, test.name+", digested", digestErr, test.want)
		_, applyErr := ApplyCollateralAdapterTransitionV1(test.action.AdapterRequest, test.action.TransitionBinding, *terms.CollateralTerms)
		expectVerdict(t, test.name+", applied", applyErr, test.want)
	}

	substituted := collateralBindingOf(t, *terms.CollateralTerms, "release")
	substituted.AuthorizationBinding.AuthorizationSubjects = []string{"agent:other-custodian"}
	_, err := CollateralTransitionBindingDigestV1(substituted)
	refusedFor(t, "a binding whose own authorization names another custodian than its profile's", err,
		"collateral transition substituted its custodian authorization")
}

// collateralClosure is a collateralized coverage closed with one denied
// claim: the history, its terms and its terminal claim set.
type collateralClosure struct {
	history *signedHistory
	terms   CoverageTermsV1
	set     AuthorizedTerminalClaimSetEvidenceV1
}

// newCollateralClosure takes one claim of a collateralized coverage to its
// terminal denial, closes filing and creates the terminal claim set at
// createdAt (ten seconds after the filing close when zero), allowing its
// release from releaseFrom. The set states that its claims were terminal ten
// seconds after the filing close, whenever it is created.
func newCollateralClosure(t *testing.T, releaseFrom, createdAt uint64) collateralClosure {
	t.Helper()
	terms := collateralizedHistoryTerms(t, newSignedHistory(t))
	history, claimID := claimFiledAt(t, 40, &terms)
	denied := history.fallback(claimID, nil, signedHistoryStart+40+terms.ReviewDeadlineSeconds)
	closeAt := denied.Body.ChallengeEndsAtUnix
	history.challengeClose(claimID, closeAt)
	application := history.apply(claimID, history.materialize(claimID, terms), closeAt+10)
	filedAt := terms.ClaimFilingEndsAtUnix + 10
	filing := history.filingClose(filedAt)
	if createdAt == 0 {
		createdAt = filedAt + 10
	}
	bundle := history.terminalBundle(claimID, application, createdAt)
	history.vary = signedHistoryVariation{closureTerminalAt: filedAt + 10,
		closureContext: func(closure *CoverageClosureEvidenceContextV1) { closure.ReleaseNotBeforeUnix = releaseFrom }}
	set := history.terminalSet(filing, []ClaimTerminalResolutionBundleV1{bundle}, createdAt)
	history.vary = signedHistoryVariation{}
	if err := ValidateTerminalClaimSetV1(set); err != nil {
		t.Fatalf("the terminal claim set is refused by its shape: %v", err)
	}
	if set.Body.CreatedAtUnix != createdAt || set.Body.ReleaseNotBeforeUnix != releaseFrom {
		t.Fatalf("the terminal claim set is created at %d and allows its release from %d, want %d and %d",
			set.Body.CreatedAtUnix, set.Body.ReleaseNotBeforeUnix, createdAt, releaseFrom)
	}
	return collateralClosure{history: history, terms: terms, set: set}
}

// releaseAgainst is the custodian-signed release of the closure's collateral
// that names set, on the coverage Agreement of digest agreement, admitted and
// finalized at at.
func (closure collateralClosure) releaseAgainst(set AuthorizedTerminalClaimSetEvidenceV1, agreement string,
	at uint64) AuthorizedCollateralEvidenceV1 {
	history, t := closure.history, closure.history.t
	digest, err := TerminalClaimSetDigestV1(set)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := Canonical(set)
	if err != nil {
		t.Fatal(err)
	}
	history.useCollateralFence(closure.terms)
	item := carriedEvidenceItem(terminalClaimSetContentTypeV1, digest, wire, closure.terms.ClaimAdmissionProfile.ProfileDigest)
	return history.collateralEvidence(closure.terms, collateralTransition{kind: "release", agreement: agreement,
		purpose: collateralReleasePrerequisitePurposeV1, prior: CollateralEncumbered,
		prerequisite: []CanonicalGuarantorEvidenceItemV1{item}, admittedAt: at, finalizedAt: at})
}

// verifyRelease is the release verifier on release and set against the
// closure's offer, at the time the release was finalized.
func (closure collateralClosure) verifyRelease(release AuthorizedCollateralEvidenceV1,
	set AuthorizedTerminalClaimSetEvidenceV1) error {
	history := closure.history
	return VerifyCollateralReleaseEvidenceV1(release, set, history.offer, permissiveAgreementVerifier{}, history.resolver,
		history.fenceResolver, signedHistoryNoPayments{}, signedHistoryFinality{}, signedHistoryTime(release.Body.FinalizedAtUnix))
}

// TestSignedHistoryCollateralReleaseStandsOnItsTerminalClaimSet: a verifier
// that holds a release, the terminal claim set it names and the firm offer
// verifies the set and ties the release to it. A release that names the
// coverage's verified terminal claim set, admitted at the time the set allows
// its release, is accepted. It is refused when the set presented is another
// one than the release names, when the set it names does not verify, when the
// release is of another coverage Agreement than the offer's, when it is
// admitted a second before the set allows its release or a second before the
// set was created, and when the evidence presented as a release is a lock.
func TestSignedHistoryCollateralReleaseStandsOnItsTerminalClaimSet(t *testing.T) {
	guard := collateralizedHistoryTerms(t, newSignedHistory(t)).CollateralTerms.ReleaseNotBeforeUnix

	closure := newCollateralClosure(t, guard, 0)
	agreement := closure.history.agreement
	release := closure.releaseAgainst(closure.set, agreement, guard)
	expectVerdict(t, "a release that names the coverage's terminal claim set, admitted when the set allows",
		closure.verifyRelease(release, closure.set), "")

	later := newCollateralClosure(t, guard+10, 0)
	expectVerdict(t, "a release presented with another terminal claim set than it names",
		closure.verifyRelease(release, later.set),
		"Guarantor collateral release names another terminal claim set than the one presented")
	expectVerdict(t, "a release admitted at the later time its terminal claim set allows",
		later.verifyRelease(later.releaseAgainst(later.set, agreement, guard+10), later.set), "")
	expectVerdict(t, "a release admitted a second before its terminal claim set allows",
		later.verifyRelease(later.releaseAgainst(later.set, agreement, guard+9), later.set),
		"Guarantor collateral release precedes its terminal claim set's release time")

	early := newCollateralClosure(t, guard-1, 0)
	expectVerdict(t, "a release that names a terminal claim set that does not verify",
		early.verifyRelease(early.releaseAgainst(early.set, agreement, guard), early.set),
		"Guarantor collateral release stands on an invalid terminal claim set: "+
			"terminal claim set allows its release before the Agreement's collateral release guard")

	expectVerdict(t, "a release of another coverage Agreement than the offer's",
		closure.verifyRelease(closure.releaseAgainst(closure.set, testDigest("9"), guard), closure.set),
		"Guarantor collateral release is of another coverage Agreement than the firm offer's")

	created := newCollateralClosure(t, guard, guard+20)
	expectVerdict(t, "a release admitted at the instant its terminal claim set was created",
		created.verifyRelease(created.releaseAgainst(created.set, agreement, guard+20), created.set), "")
	expectVerdict(t, "a release admitted a second before its terminal claim set was created",
		created.verifyRelease(created.releaseAgainst(created.set, agreement, guard+19), created.set),
		"Guarantor collateral release precedes the creation of its terminal claim set")

	closure.history.useCollateralFence(closure.terms)
	lock := closure.history.collateralEvidence(closure.terms, collateralTransition{kind: "lock", agreement: agreement,
		purpose: "collateral-lock", prior: CollateralLockPending,
		prerequisite: []CanonicalGuarantorEvidenceItemV1{carriedEvidenceItem("application/vnd.tos.collateral-deposit.v1+cbor",
			testDigest("2"), []byte("deposit"), closure.terms.SelectedCollateralProfileDigest)},
		admittedAt: guard, finalizedAt: guard})
	expectVerdict(t, "a lock, verified as collateral evidence", closure.history.verifyCollateral(lock, closure.terms, guard), "")
	expectVerdict(t, "a lock presented as a release", closure.verifyRelease(lock, closure.set),
		"Guarantor collateral release evidence is of another transition kind")
}

// TestSignedHistoryTerminalClaimSetRespectsTheCollateralReleaseGuard: the
// terminal claim set of a collateralized coverage allows its release no
// earlier than the collateral terms' release_not_before_unix, so the exposure
// release that follows the set cannot precede the guard. A set that allows its
// release exactly at the guard is accepted; one that allows it a second
// earlier is refused.
func TestSignedHistoryTerminalClaimSetRespectsTheCollateralReleaseGuard(t *testing.T) {
	guard := collateralizedHistoryTerms(t, newSignedHistory(t)).CollateralTerms.ReleaseNotBeforeUnix
	for _, test := range []struct {
		name        string
		releaseFrom uint64
		want        string
	}{
		{"a set that allows its release at the collateral release guard", guard, ""},
		{"a set that allows its release a second before the collateral release guard", guard - 1,
			"terminal claim set allows its release before the Agreement's collateral release guard"},
	} {
		closure := newCollateralClosure(t, test.releaseFrom, 0)
		if closure.set.Body.CreatedAtUnix >= test.releaseFrom {
			t.Fatalf("%s: the coverage closes at %d, not before its release time %d", test.name,
				closure.set.Body.CreatedAtUnix, test.releaseFrom)
		}
		expectVerdict(t, test.name, closure.history.verifyTerminalSet(closure.set, closure.set.Body.CreatedAtUnix), test.want)
	}
}
