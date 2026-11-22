package agentguarantor

import (
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// amount is value atomic units of the coverage asset.
func (history *signedHistory) amount(value uint64) AtomicAmountV1 {
	return AtomicAmountV1{Asset: history.terms.CoverageAsset, AmountAtomic: strconv.FormatUint(value, 10)}
}

// decide admits an authorized decision for claimID at that approves the
// per-claim maximum in one payout line due dueAfterClose seconds after the
// terminal close: the initial decision of an admitted claim, otherwise the
// successor of the claim's challenged decision. The successor of a challenged
// late-recovery candidate carries the candidate's marker.
func (history *signedHistory) decide(claimID string, dueAfterClose, at uint64) AuthorizedClaimDecisionAdmissionReceiptV1 {
	t, terms := history.t, history.terms
	state := history.claims[claimID]
	claimAdmission := history.latestReceipts[claimID]
	claim := claimAdmission.AuthorizedClaimIngressReceipt.AuthorizedClaim
	decisionPath, priorState, predecessorDecisionDigest := "initial", state.status, ""
	switch state.status {
	case "admitted":
	case "reviewing":
		decisionPath, predecessorDecisionDigest = "successor", state.decision.Body.AuthorizedClaimDecisionDigest
	default:
		t.Fatalf("signed history has no authorized decision from %s", state.status)
	}
	marker := lateRecoveryCandidateMarkerV1(state.transition)
	expiresAt := terms.TerminalResolutionDeadlineUnix
	if marker != "" {
		expiresAt = terms.LateRecoveryTerminalDeadlineUnix
	}
	claimDigest, err := ClaimEnvelopeDigest(claim)
	if err != nil {
		t.Fatal(err)
	}
	items := make([]CanonicalGuarantorEvidenceItemV1, len(claim.EvidenceManifest.Items))
	predicates := make([]string, len(claim.EvidenceManifest.Items))
	for index, item := range claim.EvidenceManifest.Items {
		items[index] = CanonicalGuarantorEvidenceItemV1{ContentType: item.ContentType,
			EvidenceProfileDigest: item.EvidenceProfile.ProfileDigest, EvidenceEnvelopeDigest: item.ContentDigest,
			Representation: "content_addressed", ImmutableDescriptor: &ImmutableEvidenceDescriptorV1{ContentType: item.ContentType,
				ContentDigest: item.ContentDigest, ContentSize: item.ContentSize, RetrievalPolicyDigest: item.DisclosurePolicyDigest}}
		predicates[index] = item.PredicateID
	}
	evidence := CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1, Purpose: "claim-decision-evidence", ContextDigest: claimDigest, Items: items}
	evidenceDigest, err := CanonicalGuarantorEvidenceSetDigestV1(evidence)
	if err != nil {
		t.Fatal(err)
	}
	triggeredDigest, err := TriggeredObligationSetDigestV1(claim.Body.TriggeredObligationSet)
	if err != nil {
		t.Fatal(err)
	}
	approved := terms.MaximumPerClaim
	reserved, err := strconv.ParseUint(approved.AmountAtomic, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	clauses := []string{"clause:benefit"}
	policy := ClaimDecisionPolicyApplicationV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		CoverageObligationID: history.obligation, AuthorizedClaimEnvelopeDigest: claimDigest, DecisionPath: decisionPath,
		BenefitCalculationProfile: terms.BenefitCalculationProfile, TriggeredObligationSetDigest: triggeredDigest,
		EvidenceSetDigest: evidenceDigest, OtherRecoveryDeclarationDigest: claim.Body.OtherRecoveryDeclarationDigest,
		ApplicablePolicyClauseIDs: clauses, PolicyInputProjection: []byte("signed-history-benefit-input"),
		FullEligibleBenefitAmount: approved}
	policyDigest, err := ClaimDecisionPolicyApplicationDigestV1(policy)
	if err != nil {
		t.Fatal(err)
	}
	// A nonterminal decision disputes the claim instead: no amount, no payout
	// line and no application token, and a resolution window in place of the
	// challenge window.
	nonterminal := history.vary.nonterminal
	result, reasonCode, admittedState := DecisionApproved, "benefit-approved", "approved"
	payoutLines := []ClaimPayoutLineV1{{DecisionLineIndex: 1, Amount: approved,
		PayoutDestinationDigest:      terms.PayoutTemplate.SettlementParameters.PayoutDestinationDigest,
		DueAfterTerminalCloseSeconds: dueAfterClose, ExpiresAfterTerminalCloseSeconds: dueAfterClose + terms.AdapterRecoveryWindowSeconds}}
	challengeWindow, resolutionWindow := terms.ChallengeWindowSeconds, uint64(0)
	if nonterminal {
		result, reasonCode, admittedState = DecisionDisputed, "benefit-disputed", "disputed"
		approved, reserved, payoutLines = history.amount(0), 0, nil
		challengeWindow, resolutionWindow = 0, terms.NonterminalResolutionWindowSeconds
	}
	reason := ClaimDecisionReasonV1{SchemaVersion: 1, DecisionProfile: terms.DecisionProfile, Result: result,
		ReasonCode: reasonCode, ApplicablePolicyClauseIDs: clauses, EvidencePredicateIDs: predicates}
	reasonDigest, err := ClaimDecisionReasonDigestV1(reason)
	if err != nil {
		t.Fatal(err)
	}
	sequence := state.decisionSequence + 1
	decisionBody := ClaimDecisionBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		CoverageObligationID: history.obligation, ClaimID: claimID, AuthorizedClaimEnvelopeDigest: claimDigest,
		DecisionSequence: sequence, DecisionRevision: 1, PredecessorAuthorizedClaimDecisionDigest: predecessorDecisionDigest,
		DecisionPath: decisionPath, ExpectedClaimRevision: claim.Body.ClaimRevision, DecisionProfile: terms.DecisionProfile,
		DecisionAuthoritySubjects: append([]string(nil), terms.DecisionAuthoritySubjects...),
		DecisionQuorumRule:        terms.DecisionQuorumRule, Result: result, ApprovedAmount: approved,
		EvidenceSetDigest: evidenceDigest, PolicyApplicationDigest: policyDigest, ReasonDigest: reasonDigest,
		PayoutLines: payoutLines, ChallengeWindowSeconds: challengeWindow, ResolutionWindowSeconds: resolutionWindow,
		DecidedAtUnix: at, ExpiresAtUnix: expiresAt}
	if history.vary.decision != nil {
		history.vary.decision(&decisionBody)
	}
	decisionBodyDigest, err := ClaimDecisionBodyDigestV1(decisionBody, terms)
	if err != nil {
		t.Fatalf("authorized decision body is invalid: %v", err)
	}
	decision := AuthorizedClaimDecisionV1{Body: decisionBody, PolicyApplication: policy, DecisionReason: reason,
		DecisionEvidenceSet: evidence, Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObjectAs(
			signedHistoryGuarantor, terms.DecisionProfile, "claim-decision", decisionBodyDigest,
			"tos.service.agent-guarantor-claim-decision-signature.v1", at)}}
	decisionDigest, err := ClaimDecisionDigestV1(decision)
	if err != nil {
		t.Fatal(err)
	}
	claimAdmissionDigest, err := ClaimAdmissionReceiptDigestV1(claimAdmission)
	if err != nil {
		t.Fatal(err)
	}
	cut := state.frozenCut
	expectedState, expectedRevision := "frozen", state.epochRevision
	if !state.epochFrozen {
		cut = history.revisionCut(claimID, at)
		expectedState = "open"
	}
	if history.vary.cut != nil {
		history.vary.cut(&cut)
	}
	variant := AuthorizedDecisionAdmissionVariantV1{AuthorizedClaimDecisionDigest: decisionDigest,
		AuthorizedClaimAdmissionReceiptDigest: claimAdmissionDigest,
		ClaimRevisionEpochExpectation: ClaimRevisionEpochExpectationV1{SchemaVersion: 1,
			CoverageAgreementBodyDigest: history.agreement, CoverageObligationID: history.obligation, ClaimID: claimID,
			RevisionEpoch: cut.RevisionEpoch, RevisionIngressLogID: cut.ClaimIngressLogID, ExpectedEpochState: expectedState,
			ExpectedEpochStateRevision: expectedRevision, ExpectedClaimRevision: claim.Body.ClaimRevision},
		ExpectedClaimStateRevision: state.stateRevision, ExpectedChallengeRoundsUsed: state.challengeRounds,
		ExpectedNonterminalRoundsUsed: state.nonterminalRounds}
	if state.transition != nil {
		if variant.PredecessorClaimStateTransitionReceiptDigest, err = ClaimStateTransitionReceiptDigestV1(*state.transition); err != nil {
			t.Fatal(err)
		}
		variant.PredecessorDecisionAdmissionReceiptDigest = state.transition.DecisionAdmissionProof.ReceiptEnvelopeDigest
	}
	if history.vary.epoch != nil {
		history.vary.epoch(&variant.ClaimRevisionEpochExpectation)
	}
	actionBody := ClaimDecisionAdmissionActionBodyV1{SchemaVersion: 1, AdmissionMode: "authorized_decision",
		AuthorizedDecisionVariant: &variant}
	request, err := Canonical(actionBody)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "terminal_decision")
	if err != nil {
		t.Fatal(err)
	}
	headDigest, identityDigest, err := AuthorizedDecisionAdmissionSourceIdentityV1(variant, decision)
	if err != nil {
		t.Fatal(err)
	}
	fields := DecisionAdmissionSemanticFieldsV1(bound, actionBody, decision, headDigest, identityDigest)
	stage := history.stage("terminal_decision", "application/vnd.tos.service.agent-guarantor-claim-decision-admission.v1+cbor",
		request, fields, testDigest("1"), expiresAt, at, "", nil)
	action := stage.AuthorizedAction
	actionDigest, err := agentcommerce.AuthorizedActionDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	eligibility := history.eligibility(actionDigest, decisionDigest, terms.DecisionAdmissionAuthoritySubjects,
		"claim-decision-admission-receipt", decisionDigest, terms.DecisionAdmissionProfile.ProfileDigest,
		terms.DecisionAdmissionProfile, terms.CoverageStateDomainDigest, sequence, at)
	eligibilityDigest, err := AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	if err != nil {
		t.Fatal(err)
	}
	endCommitment := history.activation.CoverageEndCommitment
	endDigest, err := CoverageEndCommitmentDigestV1(endCommitment)
	if err != nil {
		t.Fatal(err)
	}
	cutDigest, err := ClaimIngressAdmissionCutProofDigestV1(cut)
	if err != nil {
		t.Fatal(err)
	}
	tokenID, err := DecisionApplicationTokenIDV1(history.agreement, history.obligation, claimID, decisionDigest, sequence, 1)
	if err != nil {
		t.Fatal(err)
	}
	token := DecisionApplicationTokenV1{SchemaVersion: 1, TokenID: tokenID, CoverageAgreementBodyDigest: history.agreement,
		CoverageObligationID: history.obligation, ClaimID: claimID, AuthorizedClaimDecisionDigest: decisionDigest,
		DecisionSequence: sequence, DecisionRevision: 1, ReservedApprovedAmount: approved, TokenRevision: 1, State: "pending"}
	replaced := uint64(0)
	if state.token != nil {
		if replaced, err = strconv.ParseUint(state.token.ReservedApprovedAmount.AmountAtomic, 10, 64); err != nil {
			t.Fatal(err)
		}
	}
	pendingAfter := history.pendingReserve - replaced + reserved
	body := ClaimDecisionAdmissionReceiptBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		CoverageAgreementBodyDigest: history.agreement, CoverageObligationID: history.obligation, ClaimID: claimID,
		AuthorizedClaimDecisionDigest: decisionDigest, AdmissionMode: "authorized_decision",
		AuthorizedClaimAdmissionReceiptDigest: claimAdmissionDigest, ClaimRevisionIngressCutProofDigest: cutDigest,
		LateFilingCloseReceiptDigest: marker, FrozenRevisionEpoch: cut.RevisionEpoch,
		PriorRevisionEpochStateRevision: cut.PriorEpochStateRevision, FrozenRevisionEpochStateRevision: cut.FrozenEpochStateRevision,
		FrozenClaimRevisionIngressHighWater: cut.AdmissionHighWater, FrozenClaimRevisionIngressLogRoot: cut.AdmissionLogRoot,
		PredecessorDecisionAdmissionReceiptDigest:    variant.PredecessorDecisionAdmissionReceiptDigest,
		PredecessorClaimStateTransitionReceiptDigest: variant.PredecessorClaimStateTransitionReceiptDigest,
		DecisionSequence: sequence, DecisionRevision: 1, DecisionPath: decisionPath,
		PriorCoverageRevision: history.coverageRevision, AdmittedCoverageRevision: history.coverageRevision + 1,
		PriorCoverageEndCommitmentDigest: endDigest, ResultingCoverageEndCommitmentDigest: endDigest,
		PriorClaimState: priorState, AdmittedClaimState: admittedState, PriorClaimStateRevision: state.stateRevision,
		AdmittedClaimStateRevision: state.stateRevision + 1, ChallengeRoundsUsedBefore: state.challengeRounds,
		ChallengeRoundsUsedAfter: state.challengeRounds, NonterminalRoundsUsedBefore: state.nonterminalRounds,
		NonterminalRoundsUsedAfter: state.nonterminalRounds, ChallengeStartsAtUnix: at,
		ChallengeEndsAtUnix: at + terms.ChallengeWindowSeconds, ResultingApplicationToken: &token,
		AggregatePendingDecisionReserveBefore: history.amount(history.pendingReserve),
		AggregatePendingDecisionReserveAfter:  history.amount(pendingAfter),
		AuthorizedActionDigest:                actionDigest, StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		WriterGeneration: action.WriterGeneration, WriterFenceDigest: action.WriterFenceDigest, AdmittedAtUnix: at,
		AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	if state.token != nil {
		if body.PriorApplicationTokenDigest, err = DecisionApplicationTokenDigestV1(*state.token); err != nil {
			t.Fatal(err)
		}
		body.PriorApplicationTokenTerminalState = "replaced"
	}
	var resultingToken *DecisionApplicationTokenV1
	if nonterminal {
		body.ChallengeStartsAtUnix, body.ChallengeEndsAtUnix, body.ResultingApplicationToken = 0, 0, nil
		body.ResolutionStartsAtUnix, body.ResolutionDueAtUnix = at, at+resolutionWindow
	} else {
		resultingToken = &token
	}
	if history.vary.admission != nil {
		history.vary.admission(&body)
	}
	bodyDigest, err := Digest("tos.service.agent-guarantor-claim-decision-admission-receipt-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	stage.ActionResolution.SinkReference = bodyDigest
	stage.ActionResolution.EvidenceRefs = []string{decisionDigest, bodyDigest}
	sort.Strings(stage.ActionResolution.EvidenceRefs)
	receipt := AuthorizedClaimDecisionAdmissionReceiptV1{Body: body, StageActionAdmissionEvidence: stage,
		AuthorizedClaimDecision: decision, AuthorizedClaimAdmissionReceipt: claimAdmission, ClaimRevisionIngressCutProof: cut,
		CoverageEndCommitment: endCommitment, PriorPendingApplicationToken: state.token,
		PredecessorClaimStateTransitionReceipt: state.transition, AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObjectAs(signedHistoryGuarantor,
			terms.DecisionAdmissionProfile, "claim-decision-admission-receipt", bodyDigest,
			"tos.service.agent-guarantor-claim-decision-admission-signature.v1", at)}}
	history.coverageRevision++
	history.pendingReserve = pendingAfter
	state.status, state.stateRevision, state.decisionSequence = admittedState, state.stateRevision+1, sequence
	if !state.epochFrozen {
		state.epochFrozen, state.epochRevision, state.frozenCut = true, cut.FrozenEpochStateRevision, cut
	}
	state.decision, state.transition, state.token = &receipt, nil, resultingToken
	history.store(receipt)
	return receipt
}

// laterDeadlines is the history's terms with the terminal resolution deadline
// and both late-recovery deadlines moved seconds later. A test materializes a
// payout under them to present one the history's own terms refuse.
func (history *signedHistory) laterDeadlines(seconds uint64) CoverageTermsV1 {
	terms := history.terms
	terms.TerminalResolutionDeadlineUnix += seconds
	terms.LateIngressRecoveryDeadlineUnix += seconds
	terms.LateRecoveryTerminalDeadlineUnix += seconds
	return terms
}

// materialize derives the payouts of the claim's terminal decision from its
// challenge close, under terms, on the path the decision's admission is on.
func (history *signedHistory) materialize(claimID string, terms CoverageTermsV1) MaterializedPayoutObligationSetV1 {
	t := history.t
	state := history.claims[claimID]
	if state.decision == nil || state.transition == nil || state.transition.Body.TransitionKind != "challenge_close" {
		t.Fatal("signed history materializes payouts only after a challenge close")
	}
	bound, err := FindStageActionAuthorityV1(history.terms.StageActionAuthorityBinding, "decision_application")
	if err != nil {
		t.Fatal(err)
	}
	transitionDigest, err := ClaimStateTransitionReceiptDigestV1(*state.transition)
	if err != nil {
		t.Fatal(err)
	}
	// testDigest("1") is the mandate every stage action of the history carries.
	payouts, err := MaterializeClaimPayout(bound.ActionOwnerID, bound.ActionAgentID, testDigest("1"),
		terms.PayoutTemplate.AgreementObligationID, terms, state.decision.AuthorizedClaimDecision, transitionDigest,
		state.transition.Body.TransitionedAtUnix, history.payoutSequence+1, OnLateRecoveryPathV1(state.decision.Body))
	if err != nil {
		t.Fatalf("payouts do not materialize: %v", err)
	}
	return payouts
}

// applicationAuthorization is the decision-admission authority's signature
// over a decision application receipt body at.
func (history *signedHistory) applicationAuthorization(body ClaimDecisionApplicationReceiptBodyV1, at uint64) ProfileQualifiedObjectAuthorizationV1 {
	bodyDigest, err := Digest("tos.service.agent-guarantor-claim-decision-application-receipt-body.v1", body)
	if err != nil {
		history.t.Fatal(err)
	}
	return history.signObjectAs(signedHistoryGuarantor, history.terms.DecisionAdmissionProfile, "claim-decision-application-receipt",
		bodyDigest, "tos.service.agent-guarantor-claim-decision-application-signature.v1", at)
}

// apply applies the claim's terminal decision at: it consumes the decision's
// pending application token and commits payouts as its materialized set.
func (history *signedHistory) apply(claimID string, payouts MaterializedPayoutObligationSetV1, at uint64) AuthorizedClaimDecisionApplicationReceiptV1 {
	t, terms := history.t, history.terms
	state := history.claims[claimID]
	if state.decision == nil || state.transition == nil || state.token == nil ||
		state.transition.Body.TransitionKind != "challenge_close" {
		t.Fatal("signed history applies a decision only after its challenge close")
	}
	admission, transition, token := *state.decision, *state.transition, *state.token
	decision := admission.AuthorizedClaimDecision
	claim := admission.AuthorizedClaimAdmissionReceipt.AuthorizedClaimIngressReceipt.AuthorizedClaim
	claimDigest, err := ClaimEnvelopeDigest(claim)
	if err != nil {
		t.Fatal(err)
	}
	decisionDigest, err := ClaimDecisionDigestV1(decision)
	if err != nil {
		t.Fatal(err)
	}
	claimAdmissionDigest, err := ClaimAdmissionReceiptDigestV1(admission.AuthorizedClaimAdmissionReceipt)
	if err != nil {
		t.Fatal(err)
	}
	admissionDigest, err := ClaimDecisionAdmissionReceiptDigestV1(admission)
	if err != nil {
		t.Fatal(err)
	}
	transitionDigest, err := ClaimStateTransitionReceiptDigestV1(transition)
	if err != nil {
		t.Fatal(err)
	}
	endDigest, err := CoverageEndCommitmentDigestV1(admission.CoverageEndCommitment)
	if err != nil {
		t.Fatal(err)
	}
	templateDigest, err := agentcommerce.ConditionalSettlementTemplateDigestV1(terms.PayoutTemplate)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := strconv.ParseUint(token.ReservedApprovedAmount.AmountAtomic, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	pendingBefore, pendingAfter := history.amount(history.pendingReserve), history.amount(history.pendingReserve-reserved)
	nextSequence := history.payoutSequence + 1
	requestBody := ClaimDecisionApplicationActionBodyV1{SchemaVersion: 1, AuthorizedClaimDecisionDigest: decisionDigest,
		AuthorizedClaimAdmissionReceiptDigest:               claimAdmissionDigest,
		AuthorizedClaimDecisionAdmissionReceiptDigest:       admissionDigest,
		AuthorizedTerminalClaimStateTransitionReceiptDigest: transitionDigest, DecisionApplicationToken: token,
		ExpectedCoverageEndCommitmentDigest: endDigest, PayoutTemplateDigest: templateDigest,
		ExpectedCurrentCoverageRevision: history.coverageRevision, TargetCoverageRevision: history.coverageRevision + 1,
		ExpectedAggregatePendingDecisionReserve: pendingBefore, TargetAggregatePendingDecisionReserve: pendingAfter,
		ExpectedApplicationTokenRevision: token.TokenRevision, ExpectedClaimStateRevision: state.stateRevision,
		TargetClaimState: transition.Body.ResultingClaimState, ExpectedNextPayoutSequence: nextSequence,
		ExpectedMaterializedPayoutLineDigest: history.payoutLineDigest}
	request, err := Canonical(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "decision_application")
	if err != nil {
		t.Fatal(err)
	}
	fields := ClaimDecisionApplicationSemanticFieldsV1(bound, requestBody, decision, claimDigest)
	stage := history.stage("decision_application", "application/vnd.tos.service.agent-guarantor-decision-application.v1+cbor",
		request, fields, testDigest("1"), terms.LateRecoveryTerminalDeadlineUnix, at, "", nil)
	action := stage.AuthorizedAction
	actionDigest, err := agentcommerce.AuthorizedActionDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	tokenDigest, err := DecisionApplicationTokenDigestV1(token)
	if err != nil {
		t.Fatal(err)
	}
	payoutDigest, err := Digest(PayoutSetDomain, payouts)
	if err != nil {
		t.Fatal(err)
	}
	lineDigest := history.payoutLineDigest
	if count := len(payouts.MaterializedLines); count > 0 {
		if lineDigest, err = Digest("tos.service.agent-guarantor-materialized-payout-line.v1", payouts.MaterializedLines[count-1]); err != nil {
			t.Fatal(err)
		}
	}
	lines := uint64(len(payouts.MaterializedLines))
	body := ClaimDecisionApplicationReceiptBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		CoverageAgreementBodyDigest: history.agreement, CoverageObligationID: history.obligation, ClaimID: claimID,
		AuthorizedClaimDecisionDigest: decisionDigest, ClaimDecisionAdmissionReceiptDigest: admissionDigest,
		TerminalClaimStateTransitionReceiptDigest: transitionDigest, DecisionApplicationTokenID: token.TokenID,
		DecisionApplicationTokenDigest: tokenDigest, PriorApplicationTokenRevision: token.TokenRevision,
		ResultingApplicationTokenRevision: token.TokenRevision + 1, ResultingApplicationTokenState: "consumed",
		MaterializedPayoutObligationSetDigest: payoutDigest, AuthorizedActionDigest: actionDigest,
		StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		WriterGeneration: action.WriterGeneration, WriterFenceDigest: action.WriterFenceDigest,
		PriorCoverageRevision: history.coverageRevision, AppliedCoverageRevision: history.coverageRevision + 1,
		PriorCoverageEndCommitmentDigest: endDigest, ResultingCoverageEndCommitmentDigest: endDigest,
		PriorClaimStateRevision: state.stateRevision, AppliedClaimStateRevision: state.stateRevision,
		PriorNextPayoutSequence: nextSequence, ResultingNextPayoutSequence: nextSequence + lines,
		PriorMaterializedPayoutLineDigest: history.payoutLineDigest, ResultingMaterializedPayoutLineDigest: lineDigest,
		CumulativeApprovedBefore:              history.amount(history.cumulativeApproved),
		CumulativeApprovedAfter:               history.amount(history.cumulativeApproved + reserved),
		AggregatePendingDecisionReserveBefore: pendingBefore, AggregatePendingDecisionReserveAfter: pendingAfter,
		AppliedAtUnix: at}
	bodyDigest, err := Digest("tos.service.agent-guarantor-claim-decision-application-receipt-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	stage.ActionResolution.SinkReference = payoutDigest
	stage.ActionResolution.EvidenceRefs = []string{decisionDigest, admissionDigest, transitionDigest, payoutDigest, bodyDigest}
	sort.Strings(stage.ActionResolution.EvidenceRefs)
	receipt := AuthorizedClaimDecisionApplicationReceiptV1{Body: body, StageActionAdmissionEvidence: stage,
		CoverageEndCommitment: admission.CoverageEndCommitment, AuthorizedTerminalClaimStateTransitionReceipt: transition,
		DecisionApplicationToken: token, MaterializedPayoutObligationSet: payouts,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.applicationAuthorization(body, at)}}
	history.coverageRevision++
	history.pendingReserve -= reserved
	history.cumulativeApproved += reserved
	history.payoutSequence += lines
	history.payoutLineDigest = lineDigest
	state.token = nil
	history.store(receipt)
	return receipt
}

// verifyApplication is the decision application verifier at at.
func (history *signedHistory) verifyApplication(receipt AuthorizedClaimDecisionApplicationReceiptV1, at uint64) error {
	return VerifyClaimDecisionApplicationReceiptV1(receipt, history.terms, permissiveAgreementVerifier{}, history.resolver,
		history.fenceResolver, time.Unix(int64(at), 0).UTC())
}

// applyAtCeiling closes the challenge window of the claim's approved decision
// so that its payout line expires over seconds after ceiling, applies the
// decision and returns the application verifier's verdict on the signed
// receipt.
func (history *signedHistory) applyAtCeiling(claimID string, ceiling, over uint64) error {
	t, terms := history.t, history.terms
	closeAt := ceiling - terms.PayoutDeadlineSeconds - terms.AdapterRecoveryWindowSeconds + over
	closed := history.challengeClose(claimID, closeAt)
	if err := VerifyClaimStateTransitionReceiptV1(closed, terms, permissiveAgreementVerifier{}, history.resolver,
		history.fenceResolver, time.Unix(int64(closeAt), 0).UTC()); err != nil {
		t.Fatalf("the signed challenge close does not verify: %v", err)
	}
	payouts := history.materialize(claimID, history.laterDeadlines(over))
	if len(payouts.MaterializedLines) != 1 || payouts.MaterializedLines[0].ExpiresAtUnix != ceiling+over {
		t.Fatalf("the materialized payout does not expire %d s after the ceiling: %+v", over, payouts.MaterializedLines)
	}
	application := history.apply(claimID, payouts, closeAt+10)
	return history.verifyApplication(application, closeAt+10)
}

// checkpoint returns a function that puts the history's counters and the
// claim's state back to what they are now, so that one signed prefix serves
// several continuations. It holds for continuations that file no claim; the
// receipts they store for the resolver stay stored.
func (history *signedHistory) checkpoint(claimID string) func() {
	saved, claim := *history, *history.claims[claimID]
	return func() {
		state := history.claims[claimID]
		*history = saved
		*state = claim
	}
}

const payoutCeilingRefusal = "decision application payout materialization differs"

// TestSignedHistoryCapsALatePathPayoutAtTheLateRecoveryDeadline: the approved
// successor of a challenged late-recovery candidate carries the candidate's
// marker, and the application verifier derives the late path from it. The
// signed application of that successor is accepted with a payout expiring
// exactly at the late-recovery terminal deadline, which is after the terminal
// resolution deadline, and refused with one expiring a second later.
func TestSignedHistoryCapsALatePathPayoutAtTheLateRecoveryDeadline(t *testing.T) {
	history := newSignedHistory(t)
	withSignedHistorySeam(t, history)
	terms := history.terms
	first := history.claim(1, nil, signedHistoryStart+30)
	history.admit(first, signedHistoryStart+40)
	claimID := first.Body.ClaimID
	lateAt := terms.TerminalResolutionDeadlineUnix + 60
	filing := history.filingClose(lateAt)
	candidate := history.fallback(claimID, &filing, lateAt+10)
	history.challenge(claimID, lateAt+20)
	successor := history.decide(claimID, terms.PayoutDeadlineSeconds, lateAt+30)
	if successor.Body.LateFilingCloseReceiptDigest == "" ||
		successor.Body.LateFilingCloseReceiptDigest != candidate.Body.LateFilingCloseReceiptDigest {
		t.Fatalf("the approved successor does not carry the candidate's marker: %q", successor.Body.LateFilingCloseReceiptDigest)
	}
	if err := history.verifyDecisionAdmission(successor, lateAt+30); err != nil {
		t.Fatalf("the signed approved successor of the late candidate does not verify: %v", err)
	}
	if terms.LateRecoveryTerminalDeadlineUnix <= terms.TerminalResolutionDeadlineUnix {
		t.Fatal("the late-recovery terminal deadline is not after the terminal resolution deadline")
	}
	restore := history.checkpoint(claimID)
	if err := history.applyAtCeiling(claimID, terms.LateRecoveryTerminalDeadlineUnix, 0); err != nil {
		t.Errorf("a late-path payout expiring at the late-recovery terminal deadline was refused: %v", err)
	}
	restore()
	if err := history.applyAtCeiling(claimID, terms.LateRecoveryTerminalDeadlineUnix, 1); err == nil ||
		!strings.Contains(err.Error(), payoutCeilingRefusal) {
		t.Errorf("a late-path payout expiring one second after the late-recovery terminal deadline was not refused for it: %v", err)
	}
}

// TestSignedHistoryCapsAnOrdinaryPayoutAtTheTerminalResolutionDeadline: an
// approved decision off the late-recovery path carries no late filing-close
// digest, so its signed application keeps the terminal resolution deadline as
// the payout ceiling even though the terms have a later late-recovery
// deadline: accepted exactly at it, refused one second after.
func TestSignedHistoryCapsAnOrdinaryPayoutAtTheTerminalResolutionDeadline(t *testing.T) {
	history := newSignedHistory(t)
	withSignedHistorySeam(t, history)
	terms := history.terms
	first := history.claim(1, nil, signedHistoryStart+30)
	history.admit(first, signedHistoryStart+40)
	claimID := first.Body.ClaimID
	approved := history.decide(claimID, terms.PayoutDeadlineSeconds, signedHistoryStart+100)
	if approved.Body.LateFilingCloseReceiptDigest != "" {
		t.Fatalf("an ordinary approved decision carries a late filing-close digest: %q", approved.Body.LateFilingCloseReceiptDigest)
	}
	if err := history.verifyDecisionAdmission(approved, signedHistoryStart+100); err != nil {
		t.Fatalf("the signed ordinary approved decision does not verify: %v", err)
	}
	restore := history.checkpoint(claimID)
	if err := history.applyAtCeiling(claimID, terms.TerminalResolutionDeadlineUnix, 0); err != nil {
		t.Errorf("an ordinary payout expiring at the terminal resolution deadline was refused: %v", err)
	}
	restore()
	if err := history.applyAtCeiling(claimID, terms.TerminalResolutionDeadlineUnix, 1); err == nil ||
		!strings.Contains(err.Error(), payoutCeilingRefusal) {
		t.Errorf("an ordinary payout expiring one second after the terminal resolution deadline was not refused for it: %v", err)
	}
}
