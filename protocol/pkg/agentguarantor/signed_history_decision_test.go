package agentguarantor

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// initialClaimsCut is the filing close's cut of the initial ingress log: every
// initial ingress received by cutoff, each admitted by its initial admission.
func (history *signedHistory) initialClaimsCut(cutoff uint64) ClaimIngressAdmissionCutProofV1 {
	t := history.t
	logID, err := ClaimIngressLogIDV1(history.agreement, history.obligation, "")
	if err != nil {
		t.Fatal(err)
	}
	claimIDs := make([]string, 0, len(history.initialReceipts))
	for claimID := range history.initialReceipts {
		claimIDs = append(claimIDs, claimID)
	}
	sort.Slice(claimIDs, func(i, j int) bool {
		return history.initialReceipts[claimIDs[i]].AuthorizedClaimIngressReceipt.Body.ClaimIngressSequence <
			history.initialReceipts[claimIDs[j]].AuthorizedClaimIngressReceipt.Body.ClaimIngressSequence
	})
	entries := make([]ClaimIngressResolutionEntryV1, 0, len(claimIDs))
	root, err := InitialClaimLogRootV1(ClaimIngressLogRootDomainV1, logID)
	if err != nil {
		t.Fatal(err)
	}
	for _, claimID := range claimIDs {
		admission := history.initialReceipts[claimID]
		ingress := admission.AuthorizedClaimIngressReceipt
		if ingress.Body.ReceivedAtUnix > cutoff {
			continue
		}
		ingressDigest, err := ClaimIngressReceiptDigestV1(ingress)
		if err != nil {
			t.Fatal(err)
		}
		admissionDigest, err := ClaimAdmissionReceiptDigestV1(admission)
		if err != nil {
			t.Fatal(err)
		}
		resolution := admission.StageActionAdmissionEvidence.ActionResolution
		entries = append(entries, ClaimIngressResolutionEntryV1{ClaimIngressSequence: ingress.Body.ClaimIngressSequence,
			ReceivedAtUnix: ingress.Body.ReceivedAtUnix, IngressActionResolution: ingress.StageActionAdmissionEvidence.ActionResolution,
			ClaimIngressReceiptDigest: ingressDigest, ResolutionKind: "claim_admitted",
			ClaimAdmissionActionResolution: &resolution, ClaimAdmissionReceiptDigest: admissionDigest})
		root = ingress.Body.AdmittedClaimIngressLogRoot
	}
	cut := ClaimIngressAdmissionCutProofV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		CoverageObligationID: history.obligation, CutKind: "initial_claims", ClaimIngressLogID: logID, IngressCutoffUnix: cutoff,
		AdmissionHighWater: uint64(len(entries)), AdmissionLogRoot: root, Entries: entries, AdmittedClaimCount: uint64(len(entries))}
	if err := ValidateClaimIngressAdmissionCutProofV1(cut); err != nil {
		t.Fatalf("initial claims cut is invalid: %v", err)
	}
	return cut
}

// revisionCut freezes the claim's open revision epoch: the cut of its
// revision ingress log at cutoff.
func (history *signedHistory) revisionCut(claimID string, cutoff uint64) ClaimIngressAdmissionCutProofV1 {
	t := history.t
	state := history.claims[claimID]
	logID, err := ClaimIngressLogIDV1(history.agreement, history.obligation, claimID)
	if err != nil {
		t.Fatal(err)
	}
	root, err := InitialClaimLogRootV1(ClaimIngressLogRootDomainV1, logID)
	if err != nil {
		t.Fatal(err)
	}
	entries := []ClaimIngressResolutionEntryV1{}
	for _, admission := range history.admissions[claimID][1:] {
		ingress := admission.AuthorizedClaimIngressReceipt
		ingressDigest, err := ClaimIngressReceiptDigestV1(ingress)
		if err != nil {
			t.Fatal(err)
		}
		admissionDigest, err := ClaimAdmissionReceiptDigestV1(admission)
		if err != nil {
			t.Fatal(err)
		}
		resolution := admission.StageActionAdmissionEvidence.ActionResolution
		entries = append(entries, ClaimIngressResolutionEntryV1{ClaimIngressSequence: ingress.Body.ClaimIngressSequence,
			ReceivedAtUnix: ingress.Body.ReceivedAtUnix, IngressActionResolution: ingress.StageActionAdmissionEvidence.ActionResolution,
			ClaimIngressReceiptDigest: ingressDigest, ResolutionKind: "claim_admitted",
			ClaimAdmissionActionResolution: &resolution, ClaimAdmissionReceiptDigest: admissionDigest})
		root = ingress.Body.AdmittedClaimIngressLogRoot
	}
	cut := ClaimIngressAdmissionCutProofV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		CoverageObligationID: history.obligation, CutKind: "claim_revisions", ClaimID: claimID, RevisionEpoch: state.epoch,
		PriorEpochStateRevision: state.epochRevision, FrozenEpochStateRevision: state.epochRevision + 1, ClaimIngressLogID: logID,
		IngressCutoffUnix: cutoff, AdmissionHighWater: uint64(len(entries)), AdmissionLogRoot: root, Entries: entries,
		AdmittedClaimCount: uint64(len(entries))}
	if err := ValidateClaimIngressAdmissionCutProofV1(cut); err != nil {
		t.Fatalf("claim revision cut is invalid: %v", err)
	}
	return cut
}

// filingClose closes claim filing at closedAt with the initial claims cut at
// the Agreement's filing end.
func (history *signedHistory) filingClose(closedAt uint64) AuthorizedClaimFilingCloseReceiptV1 {
	t, terms := history.t, history.terms
	activationDigest, err := CoverageActivationEvidenceDigestV1(history.activation)
	if err != nil {
		t.Fatal(err)
	}
	endCommitment := history.activation.CoverageEndCommitment
	endDigest, err := CoverageEndCommitmentDigestV1(endCommitment)
	if err != nil {
		t.Fatal(err)
	}
	cutoff := terms.ClaimFilingEndsAtUnix
	cut := history.initialClaimsCut(cutoff)
	cutDigest, err := ClaimIngressAdmissionCutProofDigestV1(cut)
	if err != nil {
		t.Fatal(err)
	}
	projection := TransitionEvidenceProjectionV1{SchemaVersion: 1, Purpose: "claim-filing-close",
		CoverageAgreementBodyDigest: history.agreement, ObligationID: history.obligation, TargetState: "frozen",
		EvidenceDigests: []TransitionEvidenceDigestRefV1{{EvidenceRole: "activation", DigestKind: "authorized_envelope",
			ObjectDigest: activationDigest}}}
	projectionDigest, err := TransitionEvidenceProjectionDigestV1(projection)
	if err != nil {
		t.Fatal(err)
	}
	claimLogID := "claim-log:" + history.agreement[len("sha256:"):]
	filingRevision := history.activation.Body.ActivatedClaimFilingStateRevision
	admitted := uint64(len(history.initialReceipts))
	request := ClaimFilingCloseActionBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		CoverageObligationID: history.obligation, ClaimAdmissionLogID: claimLogID, ClaimIngressAdmissionCutProof: cut,
		FilingCloseReason: "normal", FilingCutoffUnix: cutoff, ExpectedCoverageState: "active",
		ExpectedCoverageEndCommitmentDigest: endDigest, CoverageEndReason: "normal_expiry", ActivationEvidenceDigest: activationDigest,
		ExpectedCoverageRevision: history.coverageRevision, TargetCoverageRevision: history.coverageRevision + 1,
		ExpectedClaimFilingStateRevision: filingRevision, TargetClaimFilingState: "frozen",
		ExpectedClaimAdmissionHighWater: admitted, ExpectedClaimAdmissionLogRoot: history.claimLogRoot,
		TransitionEvidenceProjection: projection}
	canonical, err := Canonical(request)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]agentcommerce.SemanticValue{"owner_id": agentcommerce.ID("owner:guarantor"),
		"agent_id": agentcommerce.ID(signedHistoryGuarantor), "agreement_body_digest": agentcommerce.Digest32(history.agreement),
		"obligation_id": agentcommerce.ID(history.obligation), "claim_admission_log_id": agentcommerce.ID(claimLogID),
		"expected_coverage_revision":           agentcommerce.U64(history.coverageRevision),
		"expected_claim_filing_state_revision": agentcommerce.U64(filingRevision),
		"filing_cutoff_unix":                   agentcommerce.U64(cutoff), "target_state": agentcommerce.State("frozen")}
	stage := history.stage("filing_close", "application/vnd.tos.service.agent-guarantor-claim-filing-close-action.v1+cbor",
		canonical, fields, testDigest("1"), terms.LateIngressRecoveryDeadlineUnix, closedAt, "", nil)
	action := stage.AuthorizedAction
	actionDigest, err := agentcommerce.AuthorizedActionDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	// The stage admission signs its body, not the terminal resolution, so the
	// resolution's sink and evidence are set once the receipt digest is known.
	stage.ActionResolution.SinkReference, stage.ActionResolution.EvidenceRefs = actionDigest, []string{actionDigest}
	body := ClaimFilingCloseReceiptBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		CoverageAgreementBodyDigest: history.agreement, CoverageObligationID: history.obligation,
		CoverageStateDomainDigest: terms.CoverageStateDomainDigest, CoverageEndCommitmentDigest: endDigest,
		ClaimAdmissionLogID: claimLogID, ClaimIngressAdmissionCutProofDigest: cutDigest,
		FrozenClaimIngressHighWater: cut.AdmissionHighWater, FrozenClaimIngressLogRoot: cut.AdmissionLogRoot,
		FrozenClaimAdmissionHighWater: admitted, FrozenClaimAdmissionLogRoot: history.claimLogRoot,
		FilingCloseReason: "normal", FilingCutoffUnix: cutoff, PriorCoverageState: "active", CoverageEndReason: "normal_expiry",
		IncidentEligibilityEndsAtUnix: terms.CoverageEndsAtUnix, CoverageEndEvidenceDigest: endCommitment.CoverageEndEvidenceDigest,
		ActivationEvidenceDigest: activationDigest, PriorCoverageRevision: history.coverageRevision,
		ClosedCoverageRevision: history.coverageRevision + 1, PriorClaimFilingState: "open", ResultingClaimFilingState: "frozen",
		PriorClaimFilingStateRevision: filingRevision, ResultingClaimFilingStateRevision: filingRevision + 1,
		TransitionEvidenceProjectionDigest: projectionDigest, AuthorizedActionDigest: actionDigest,
		StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		WriterGeneration: action.WriterGeneration, WriterFenceDigest: action.WriterFenceDigest, ClosedAtUnix: closedAt}
	bodyDigest, err := Digest("tos.service.agent-guarantor-claim-filing-close-receipt-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	activation := history.activation
	receipt := AuthorizedClaimFilingCloseReceiptV1{Body: body, StageActionAdmissionEvidence: stage,
		CoverageEndCommitment: endCommitment, ClaimIngressAdmissionCutProof: cut, AuthorizedActivationEvidence: &activation,
		TransitionEvidenceProjection: projection,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObject("claim-filing-close-receipt", bodyDigest,
			"tos.service.agent-guarantor-claim-filing-close-signature.v1", closedAt)}}
	history.coverageRevision++
	history.store(receipt)
	return receipt
}

// decisionProof seals a decision admission into its compact proof at.
func (history *signedHistory) decisionProof(receipt AuthorizedClaimDecisionAdmissionReceiptV1, at uint64) ClaimDecisionAdmissionReceiptProofV1 {
	t := history.t
	seal, descriptor, err := NewClaimDecisionAdmissionReceiptSealBodyV1(receipt, history.terms, time.Unix(int64(at), 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	sealDigest, err := Digest(ClaimDecisionAdmissionReceiptSealDomainV1, seal)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := FindStageActionAuthorityV1(history.terms.StageActionAuthorityBinding, "terminal_decision")
	if err != nil {
		t.Fatal(err)
	}
	authorization := history.signObjectAs(bound.ActionAuthorityID, history.terms.LifecycleAuthorizationProfile,
		"claim-decision-admission-receipt-seal", sealDigest,
		"tos.service.agent-guarantor-claim-decision-admission-receipt-seal-signature.v1", at)
	proof, err := BuildClaimDecisionAdmissionReceiptProofV1(receipt, history.terms, descriptor, seal, authorization)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

// fallback admits the deterministic fallback for claimID at, from the claim's
// current head: the late-recovery candidate when filing names the late filing
// close, otherwise the fallback at the head's deadline.
func (history *signedHistory) fallback(claimID string, filing *AuthorizedClaimFilingCloseReceiptV1, at uint64) AuthorizedClaimDecisionAdmissionReceiptV1 {
	t, terms := history.t, history.terms
	state := history.claims[claimID]
	claimAdmission := history.latestReceipts[claimID]
	claim := claimAdmission.AuthorizedClaimIngressReceipt.AuthorizedClaim
	fallback := terms.ClaimClosureCapacity.TerminalFallback
	sourceState, decisionPath, priorState := "", "terminal_fallback", state.status
	predecessorDecisionDigest, cutoff := "", uint64(0)
	switch state.status {
	case "admitted":
		sourceState, decisionPath = "initial_reviewing", "initial_terminal_fallback"
		cutoff = claimAdmission.Body.AdmittedAtUnix + terms.ReviewDeadlineSeconds
	case "reviewing":
		sourceState = "reviewing_after_challenge"
		cutoff = state.transition.Body.SuccessorDecisionDueAtUnix
		predecessorDecisionDigest = state.decision.Body.AuthorizedClaimDecisionDigest
	default:
		t.Fatalf("signed history has no fallback from %s", state.status)
	}
	late := filing != nil
	if late {
		decisionPath, cutoff = "late_recovery_terminal_fallback", filing.Body.ClosedAtUnix
	}
	marker := lateRecoveryCandidateMarkerV1(state.transition)
	expiresAt := terms.TerminalResolutionDeadlineUnix
	if late {
		expiresAt = terms.LateIngressRecoveryDeadlineUnix
	} else if marker != "" {
		expiresAt = terms.LateRecoveryTerminalDeadlineUnix
	}
	claimDigest, err := ClaimEnvelopeDigest(claim)
	if err != nil {
		t.Fatal(err)
	}
	items := make([]CanonicalGuarantorEvidenceItemV1, len(claim.EvidenceManifest.Items))
	for index, item := range claim.EvidenceManifest.Items {
		items[index] = CanonicalGuarantorEvidenceItemV1{ContentType: item.ContentType,
			EvidenceProfileDigest: item.EvidenceProfile.ProfileDigest, EvidenceEnvelopeDigest: item.ContentDigest,
			Representation: "content_addressed", ImmutableDescriptor: &ImmutableEvidenceDescriptorV1{ContentType: item.ContentType,
				ContentDigest: item.ContentDigest, ContentSize: item.ContentSize, RetrievalPolicyDigest: item.DisclosurePolicyDigest}}
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
	var reasonRule DeterministicFallbackReasonRuleV1
	for _, rule := range fallback.ReasonRules {
		if rule.OutcomeCase == "deny_zero" {
			reasonRule = rule
		}
	}
	zero := AtomicAmountV1{Asset: terms.CoverageAsset, AmountAtomic: "0"}
	policy := ClaimDecisionPolicyApplicationV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		CoverageObligationID: history.obligation, AuthorizedClaimEnvelopeDigest: claimDigest, DecisionPath: decisionPath,
		BenefitCalculationProfile: terms.BenefitCalculationProfile, TriggeredObligationSetDigest: triggeredDigest,
		EvidenceSetDigest: evidenceDigest, OtherRecoveryDeclarationDigest: claim.Body.OtherRecoveryDeclarationDigest,
		ApplicablePolicyClauseIDs: append([]string(nil), reasonRule.ApplicablePolicyClauseIDs...),
		PolicyInputProjection:     []byte{}, FullEligibleBenefitAmount: zero}
	policyDigest, err := ClaimDecisionPolicyApplicationDigestV1(policy)
	if err != nil {
		t.Fatal(err)
	}
	predicates := make([]string, len(claim.EvidenceManifest.Items))
	for index, item := range claim.EvidenceManifest.Items {
		predicates[index] = item.PredicateID
	}
	reason := ClaimDecisionReasonV1{SchemaVersion: 1, DecisionProfile: fallback.FallbackProfile, Result: DecisionDenied,
		ReasonCode: reasonRule.ReasonCode, ApplicablePolicyClauseIDs: append([]string(nil), reasonRule.ApplicablePolicyClauseIDs...),
		EvidencePredicateIDs: predicates}
	reasonDigest, err := ClaimDecisionReasonDigestV1(reason)
	if err != nil {
		t.Fatal(err)
	}
	sequence := state.decisionSequence + 1
	decision := AuthorizedClaimDecisionV1{Body: ClaimDecisionBodyV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: history.agreement, CoverageObligationID: history.obligation, ClaimID: claimID,
		AuthorizedClaimEnvelopeDigest: claimDigest, DecisionSequence: sequence, DecisionRevision: 1,
		PredecessorAuthorizedClaimDecisionDigest: predecessorDecisionDigest, DecisionPath: decisionPath,
		ExpectedClaimRevision: claim.Body.ClaimRevision, DecisionProfile: fallback.FallbackProfile,
		DecisionAuthoritySubjects: append([]string(nil), fallback.FallbackAuthoritySubjects...),
		DecisionQuorumRule:        fallback.FallbackQuorumRule, Result: DecisionDenied, ApprovedAmount: zero,
		EvidenceSetDigest: evidenceDigest, PolicyApplicationDigest: policyDigest, ReasonDigest: reasonDigest,
		ChallengeWindowSeconds: terms.ChallengeWindowSeconds, DecidedAtUnix: at, ExpiresAtUnix: expiresAt},
		DecisionEvidenceSet: evidence, PolicyApplication: policy, DecisionReason: reason}
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
	fallbackDigest, err := DeterministicClaimTerminalFallbackDigestV1(fallback)
	if err != nil {
		t.Fatal(err)
	}
	variant := DeterministicFallbackAdmissionVariantV1{CoverageAgreementBodyDigest: history.agreement,
		CoverageObligationID: history.obligation, ClaimID: claimID, AuthorizedClaimAdmissionReceiptDigest: claimAdmissionDigest,
		ClaimRevisionEpochExpectation: ClaimRevisionEpochExpectationV1{SchemaVersion: 1,
			CoverageAgreementBodyDigest: history.agreement, CoverageObligationID: history.obligation, ClaimID: claimID,
			RevisionEpoch: cut.RevisionEpoch, RevisionIngressLogID: cut.ClaimIngressLogID, ExpectedEpochState: expectedState,
			ExpectedEpochStateRevision: expectedRevision, ExpectedClaimRevision: claim.Body.ClaimRevision},
		FallbackProfileDigest: fallbackDigest, SourceClaimRevision: claim.Body.ClaimRevision,
		SourceClaimStateRevision: state.stateRevision, SourceClaimState: sourceState,
		ExpectedChallengeRoundsUsed: state.challengeRounds, ExpectedNonterminalRoundsUsed: state.nonterminalRounds,
		TriggerCutoffUnix: cutoff, DecisionSequence: sequence}
	if state.decision != nil {
		if variant.CurrentDecisionAdmissionReceiptDigest, err = ClaimDecisionAdmissionReceiptDigestV1(*state.decision); err != nil {
			t.Fatal(err)
		}
	}
	if state.transition != nil {
		if variant.CurrentClaimStateTransitionReceiptDigest, err = ClaimStateTransitionReceiptDigestV1(*state.transition); err != nil {
			t.Fatal(err)
		}
	}
	if late {
		wire, err := Canonical(*filing)
		if err != nil {
			t.Fatal(err)
		}
		filingDigest, err := ClaimFilingCloseReceiptDigestV1(*filing)
		if err != nil {
			t.Fatal(err)
		}
		variant.LateFilingCloseReceiptDescriptor = &ImmutableEvidenceDescriptorV1{ContentType: ClaimFilingCloseReceiptMediaTypeV1,
			ContentDigest: filingDigest, ContentSize: uint64(len(wire)), RetrievalPolicyDigest: terms.ClaimAdmissionProfile.ProfileDigest}
	}
	actionBody := ClaimDecisionAdmissionActionBodyV1{SchemaVersion: 1, AdmissionMode: "deterministic_fallback",
		DeterministicFallbackVariant: &variant}
	request, err := Canonical(actionBody)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "terminal_decision")
	if err != nil {
		t.Fatal(err)
	}
	headDigest, identityDigest, err := DeterministicFallbackAdmissionSourceIdentityV1(variant)
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
		"claim-decision-admission-receipt", decisionDigest, fallbackDigest, fallback.FallbackProfile,
		terms.CoverageStateDomainDigest, sequence, at)
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
		DecisionSequence: sequence, DecisionRevision: 1, ReservedApprovedAmount: zero, TokenRevision: 1, State: "pending"}
	body := ClaimDecisionAdmissionReceiptBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		CoverageAgreementBodyDigest: history.agreement, CoverageObligationID: history.obligation, ClaimID: claimID,
		AuthorizedClaimDecisionDigest: decisionDigest, AdmissionMode: "deterministic_fallback", FallbackTriggerCutoffUnix: cutoff,
		AuthorizedClaimAdmissionReceiptDigest: claimAdmissionDigest, ClaimRevisionIngressCutProofDigest: cutDigest,
		FrozenRevisionEpoch: cut.RevisionEpoch, PriorRevisionEpochStateRevision: cut.PriorEpochStateRevision,
		FrozenRevisionEpochStateRevision: cut.FrozenEpochStateRevision, FrozenClaimRevisionIngressHighWater: cut.AdmissionHighWater,
		FrozenClaimRevisionIngressLogRoot: cut.AdmissionLogRoot, DecisionSequence: sequence, DecisionRevision: 1,
		DecisionPath: decisionPath, PriorCoverageRevision: history.coverageRevision, AdmittedCoverageRevision: history.coverageRevision + 1,
		PriorCoverageEndCommitmentDigest: endDigest, ResultingCoverageEndCommitmentDigest: endDigest,
		PriorClaimState: priorState, AdmittedClaimState: "denied", PriorClaimStateRevision: state.stateRevision,
		AdmittedClaimStateRevision: state.stateRevision + 1, ChallengeRoundsUsedBefore: state.challengeRounds,
		ChallengeRoundsUsedAfter: state.challengeRounds, NonterminalRoundsUsedBefore: state.nonterminalRounds,
		NonterminalRoundsUsedAfter: state.nonterminalRounds, ChallengeStartsAtUnix: at, ChallengeEndsAtUnix: at + terms.ChallengeWindowSeconds,
		ResultingApplicationToken:             &token,
		AggregatePendingDecisionReserveBefore: zero, AggregatePendingDecisionReserveAfter: zero,
		AuthorizedActionDigest: actionDigest, StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		WriterGeneration: action.WriterGeneration, WriterFenceDigest: action.WriterFenceDigest, AdmittedAtUnix: at,
		AuthorityAdmissionEligibilityProofSetDigest:  eligibilityDigest,
		PredecessorDecisionAdmissionReceiptDigest:    variant.CurrentDecisionAdmissionReceiptDigest,
		PredecessorClaimStateTransitionReceiptDigest: variant.CurrentClaimStateTransitionReceiptDigest}
	if late {
		body.LateFilingCloseReceiptDigest = variant.LateFilingCloseReceiptDescriptor.ContentDigest
	} else {
		body.LateFilingCloseReceiptDigest = marker
	}
	if state.token != nil {
		if body.PriorApplicationTokenDigest, err = DecisionApplicationTokenDigestV1(*state.token); err != nil {
			t.Fatal(err)
		}
		body.PriorApplicationTokenTerminalState = "replaced"
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
	state.status, state.stateRevision, state.decisionSequence = "denied", state.stateRevision+1, sequence
	if !state.epochFrozen {
		state.epochFrozen, state.epochRevision, state.frozenCut = true, cut.FrozenEpochStateRevision, cut
	}
	state.decision, state.transition, state.token = &receipt, nil, &token
	history.store(receipt)
	return receipt
}

// challenge admits the challenge of the claim's current decision at.
func (history *signedHistory) challenge(claimID string, at uint64) AuthorizedClaimStateTransitionReceiptV1 {
	t, terms := history.t, history.terms
	state := history.claims[claimID]
	decision := *state.decision
	decisionDigest, err := ClaimDecisionAdmissionReceiptDigestV1(decision)
	if err != nil {
		t.Fatal(err)
	}
	proof := history.decisionProof(decision, at)
	wire, err := Canonical(decision)
	if err != nil {
		t.Fatal(err)
	}
	mediaType := "application/vnd.tos.service.agent-guarantor-claim-decision-admission.v1+cbor"
	evidence := CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1, Purpose: "claim-challenge-admission", ContextDigest: decisionDigest,
		Items: []CanonicalGuarantorEvidenceItemV1{{ContentType: mediaType,
			EvidenceProfileDigest: terms.DecisionAdmissionProfile.ProfileDigest, EvidenceEnvelopeDigest: decisionDigest,
			Representation: "content_addressed", ImmutableDescriptor: &ImmutableEvidenceDescriptorV1{ContentType: mediaType,
				ContentDigest: decisionDigest, ContentSize: uint64(len(wire)),
				RetrievalPolicyDigest: terms.DecisionAdmissionProfile.ProfileDigest}}}}
	evidenceDigest, err := CanonicalGuarantorEvidenceSetDigestV1(evidence)
	if err != nil {
		t.Fatal(err)
	}
	successorDue := at + terms.SuccessorDecisionWindowSeconds
	projection := TransitionEvidenceProjectionV1{SchemaVersion: 1, Purpose: "claim-state-transition",
		CoverageAgreementBodyDigest: history.agreement, ObligationID: history.obligation, ClaimID: claimID, TargetState: "reviewing",
		EvidenceDigests: []TransitionEvidenceDigestRefV1{{EvidenceRole: "decision_admission", DigestKind: "authorized_envelope",
			ObjectDigest: decisionDigest}}}
	projectionDigest, err := TransitionEvidenceProjectionDigestV1(projection)
	if err != nil {
		t.Fatal(err)
	}
	requestBody := ClaimStateTransitionActionBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		CoverageObligationID: history.obligation, ClaimID: claimID, TransitionKind: "challenge_admission",
		ExpectedClaimStateRevision: state.stateRevision, TargetState: "reviewing", ExpectedChallengeRoundsUsed: state.challengeRounds,
		TargetChallengeRoundsUsed: state.challengeRounds + 1, ExpectedNonterminalRoundsUsed: state.nonterminalRounds,
		TargetNonterminalRoundsUsed: state.nonterminalRounds, SuccessorDecisionDueAtUnix: successorDue,
		AuthorizedClaimDecisionAdmissionReceiptDigest: decisionDigest, TransitionEvidenceProjection: projection,
		TransitionEvidenceSet: evidence}
	request, err := Canonical(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "claim_state_transition")
	if err != nil {
		t.Fatal(err)
	}
	fields := ClaimStateTransitionSemanticFieldsV1(bound, requestBody, evidenceDigest)
	stage := history.stage("claim_state_transition", "application/vnd.tos.service.agent-guarantor-claim-state-transition.v1+cbor",
		request, fields, testDigest("1"), terms.LateRecoveryTerminalDeadlineUnix, at, "", nil)
	action := stage.AuthorizedAction
	actionDigest, err := agentcommerce.AuthorizedActionDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	eligibility := history.eligibility(actionDigest, decisionDigest, terms.DecisionAdmissionAuthoritySubjects,
		"claim-state-transition-receipt", projectionDigest, terms.DecisionAdmissionProfile.ProfileDigest,
		terms.DecisionAdmissionProfile, bound.AdmissionStateDomainDigest, state.stateRevision+1, at)
	eligibilityDigest, err := AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	if err != nil {
		t.Fatal(err)
	}
	body := ClaimStateTransitionReceiptBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		CoverageAgreementBodyDigest: history.agreement, CoverageObligationID: history.obligation, ClaimID: claimID,
		TransitionKind: "challenge_admission", TransitionEvidenceProjectionDigest: projectionDigest, AuthorizedActionDigest: actionDigest,
		StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest, WriterGeneration: action.WriterGeneration,
		WriterFenceDigest: action.WriterFenceDigest, PriorClaimState: state.status, ResultingClaimState: "reviewing",
		PriorClaimStateRevision: state.stateRevision, ResultingClaimStateRevision: state.stateRevision + 1,
		ChallengeRoundsUsedBefore: state.challengeRounds, ChallengeRoundsUsedAfter: state.challengeRounds + 1,
		NonterminalRoundsUsedBefore: state.nonterminalRounds, NonterminalRoundsUsedAfter: state.nonterminalRounds,
		SuccessorDecisionDueAtUnix: successorDue, TransitionedAtUnix: at, AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	bodyDigest, err := Digest("tos.service.agent-guarantor-claim-state-transition-receipt-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	stage.ActionResolution.SinkReference = bodyDigest
	stage.ActionResolution.EvidenceRefs = []string{decisionDigest, projectionDigest, bodyDigest}
	sort.Strings(stage.ActionResolution.EvidenceRefs)
	receipt := AuthorizedClaimStateTransitionReceiptV1{Body: body, StageActionAdmissionEvidence: stage, DecisionAdmissionProof: proof,
		TransitionEvidenceProjection: projection, TransitionEvidenceSet: evidence, AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObjectAs(signedHistoryGuarantor,
			terms.DecisionAdmissionProfile, "claim-state-transition-receipt", bodyDigest,
			"tos.service.agent-guarantor-claim-state-transition-signature.v1", at)}}
	state.status, state.stateRevision, state.challengeRounds = "reviewing", state.stateRevision+1, state.challengeRounds+1
	state.transition = &receipt
	if decision.AuthorizedClaimDecision.Body.DecisionPath != "late_recovery_terminal_fallback" {
		state.epoch, state.epochFrozen, state.epochRevision = state.epoch+1, false, state.epochRevision+1
	}
	return receipt
}

// verifyDecisionAdmission is the decision admission verifier at at.
func (history *signedHistory) verifyDecisionAdmission(receipt AuthorizedClaimDecisionAdmissionReceiptV1, at uint64) error {
	return VerifyClaimDecisionAdmissionReceiptV1(receipt, history.terms, permissiveAgreementVerifier{}, history.resolver,
		history.fenceResolver, time.Unix(int64(at), 0).UTC())
}

// TestSignedHistoryVerifiesTheFallbackAfterAChallengedLateCandidate: claim
// filing closes late; the late-recovery candidate is admitted and challenged;
// at its successor deadline the terminal fallback carrying the candidate's
// marker verifies in full, including the deep receipt binding of its late
// filing-close digest. Without the marker, or with another digest, it is
// refused.
func TestSignedHistoryVerifiesTheFallbackAfterAChallengedLateCandidate(t *testing.T) {
	history := newSignedHistory(t)
	withSignedHistorySeam(t, history)
	first := history.claim(1, nil, signedHistoryStart+30)
	history.admit(first, signedHistoryStart+40)
	second := history.claim(2, &first, signedHistoryStart+50)
	history.admit(second, signedHistoryStart+60)
	claimID := first.Body.ClaimID
	lateAt := history.terms.TerminalResolutionDeadlineUnix + 60
	filing := history.filingClose(lateAt)
	candidate := history.fallback(claimID, &filing, lateAt+10)
	if err := history.verifyDecisionAdmission(candidate, lateAt+10); err != nil {
		t.Fatalf("the signed late-recovery candidate does not verify: %v", err)
	}
	challenged := history.challenge(claimID, lateAt+20)
	if err := VerifyClaimStateTransitionReceiptV1(challenged, history.terms, permissiveAgreementVerifier{}, history.resolver,
		history.fenceResolver, time.Unix(int64(lateAt+20), 0).UTC()); err != nil {
		t.Fatalf("the signed challenge of the late candidate does not verify: %v", err)
	}
	deadline := challenged.Body.SuccessorDecisionDueAtUnix
	timedOut := history.fallback(claimID, nil, deadline)
	if timedOut.Body.LateFilingCloseReceiptDigest == "" ||
		timedOut.Body.LateFilingCloseReceiptDigest != candidate.Body.LateFilingCloseReceiptDigest {
		t.Fatalf("the terminal fallback does not carry the candidate's marker: %q", timedOut.Body.LateFilingCloseReceiptDigest)
	}
	if err := history.verifyDecisionAdmission(timedOut, deadline); err != nil {
		t.Fatalf("the signed terminal fallback after the challenged late candidate does not verify: %v", err)
	}
	for name, marker := range map[string]string{"removed": "", "changed": testDigest("7")} {
		altered := timedOut
		altered.Body.LateFilingCloseReceiptDigest = marker
		if err := history.verifyDecisionAdmission(altered, deadline); err == nil ||
			!strings.Contains(err.Error(), "is not its late-recovery marker") {
			t.Errorf("marker %s: got %v, want a marker refusal", name, err)
		}
	}
}
