package agentguarantor

import (
	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// The cancellation of an activated coverage on signed history: the covered
// party's cancellation request under the terms' cancellation policy and the
// Guarantor-signed receipt of its admission.

// signedOfferCancellable gives the offered terms a cancellation policy with
// one branch, under which the covered party alone may cancel from the
// activation on, admitted within ten minutes of its request.
func signedOfferCancellable(in *signedOfferInputs) {
	in.terms.CancellationPolicy = CoverageCancellationPolicyV1{SchemaVersion: 1, PolicyID: "policy:cancellation",
		Branches: []CoverageCancellationPolicyBranchV1{{CancellationBranch: "covered_party_request",
			PermittedRequesterSubjects: []string{signedHistoryClaimant}, RequestAuthorizationProfile: testRef("7", "cancellation-request"),
			RequestAuthorizationQuorumRule: "all", MaximumAdmissionDelaySeconds: 600}}}
}

// cancellation is the Guarantor-signed receipt of the covered party's
// cancellation of the activated coverage, requested ten seconds before at and
// admitted and effective at.
func (history *signedHistory) cancellation(signed signedOffer, activation AuthorizedCoverageActivationEvidenceV1,
	at uint64) AuthorizedCoverageCancellationReceiptV1 {
	t, offer, terms := history.t, signed.offer, signed.offer.CoverageTerms
	agreementDigest, obligationID := offer.Body.CoverageAgreementBodyDigest, offer.Body.CoverageObligationID
	policyDigest, err := CoverageCancellationPolicyDigestV1(terms.CancellationPolicy)
	if err != nil {
		t.Fatalf("the signed offer's terms carry no valid cancellation policy: %v", err)
	}
	branch := terms.CancellationPolicy.Branches[0]
	requestBody := CoverageCancellationRequestBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		CoverageObligationID: obligationID, CancellationPolicyDigest: policyDigest, CancellationBranch: branch.CancellationBranch,
		RequesterSubject: signedHistoryClaimant, EffectiveNotBeforeUnix: at - 10, EffectiveNotAfterUnix: at + 100,
		CreatedAtUnix: at - 10, ExpiresAtUnix: at + 100}
	requestBodyDigest, err := Digest("tos.service.agent-guarantor-cancellation-request-body.v1", requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request := AuthorizedCoverageCancellationRequestV1{Body: requestBody, CoverageAgreementBody: signed.agreement,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObjectAs(signedHistoryClaimant,
			branch.RequestAuthorizationProfile, "coverage-cancellation-request", requestBodyDigest,
			"tos.service.agent-guarantor-cancellation-request-signature.v1", requestBody.CreatedAtUnix)}}
	requestDigest, err := CoverageCancellationRequestDigestV1(request)
	if err != nil {
		t.Fatalf("signed-history cancellation request is malformed: %v", err)
	}
	activationDigest, err := CoverageActivationEvidenceDigestV1(activation)
	if err != nil {
		t.Fatal(err)
	}
	priorCommitment := activation.CoverageEndCommitment
	priorDigest, err := CoverageEndCommitmentDigestV1(priorCommitment)
	if err != nil {
		t.Fatal(err)
	}
	projection := TransitionEvidenceProjectionV1{SchemaVersion: 1, Purpose: "coverage-cancellation",
		CoverageAgreementBodyDigest: agreementDigest, ObligationID: obligationID, TargetState: "coverage_ended",
		EvidenceDigests: []TransitionEvidenceDigestRefV1{
			{EvidenceRole: "activation_evidence", DigestKind: "authorized_envelope", ObjectDigest: activationDigest},
			{EvidenceRole: "cancellation_request", DigestKind: "authorized_envelope", ObjectDigest: requestDigest},
			{EvidenceRole: "prior_coverage_end_commitment", DigestKind: "canonical_object", ObjectDigest: priorDigest}}}
	sortTransitionEvidenceRefsV1(projection.EvidenceDigests)
	projectionDigest, err := TransitionEvidenceProjectionDigestV1(projection)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "coverage_cancellation")
	if err != nil {
		t.Fatal(err)
	}
	prior := activation.Body.ActivatedCoverageRevision
	canonical, err := Canonical(CoverageCancellationActionBodyV1{SchemaVersion: 1, AuthorizedCancellationRequest: request,
		ExpectedCoverageEndCommitment: priorCommitment, TransitionEvidenceProjection: projection,
		ExpectedCoverageRevision: prior, TargetCoverageRevision: prior + 1, TargetCoverageState: "coverage_ended"})
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]agentcommerce.SemanticValue{
		"owner_id": agentcommerce.ID(bound.ActionOwnerID), "agent_id": agentcommerce.ID(bound.ActionAgentID),
		"agreement_body_digest": agentcommerce.Digest32(agreementDigest), "obligation_id": agentcommerce.ID(obligationID),
		"expected_state_revision": agentcommerce.U64(prior), "target_state": agentcommerce.State("coverage_ended"),
		"evidence_set_digest": agentcommerce.Digest32(projectionDigest)}
	stage := history.stageFor(bound, "application/vnd.tos.service.agent-guarantor-coverage-cancellation-action.v1+cbor",
		canonical, fields, testDigest("1"), at+600, at, "", nil)
	actionDigest, err := agentcommerce.AuthorizedActionDigest(stage.AuthorizedAction)
	if err != nil {
		t.Fatal(err)
	}
	eligibility := history.eligibility(actionDigest, requestDigest, []string{signedHistoryClaimant}, "coverage-cancellation",
		stage.AuthorizedAction.ExactRequestDigest, terms.CoverageStateDomainDigest, terms.LifecycleAuthorizationProfile,
		terms.CoverageStateDomainDigest, 1, at)
	eligibilityDigest, err := AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	if err != nil {
		t.Fatal(err)
	}
	body := CoverageCancellationReceiptBodyV1{SchemaVersion: 1, AuthorityID: bound.ActionAuthorityID,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: obligationID,
		CoverageStateDomainDigest: terms.CoverageStateDomainDigest, PriorCoverageEndCommitmentDigest: priorDigest,
		AuthorizedCancellationRequestDigest: requestDigest, CancellationPolicyDigest: policyDigest,
		CancellationBranch: branch.CancellationBranch, EffectiveAtUnix: at, IncidentEligibilityEndsAtUnix: at,
		ClaimFilingEndsAtUnix: terms.ClaimFilingEndsAtUnix, TransitionEvidenceProjectionDigest: projectionDigest,
		AuthorizedActionDigest: actionDigest, StableActionID: stage.AuthorizedAction.StableActionID,
		ExactRequestDigest: stage.AuthorizedAction.ExactRequestDigest, WriterGeneration: stage.AuthorizedAction.WriterGeneration,
		WriterFenceDigest: stage.AuthorizedAction.WriterFenceDigest, PriorCoverageRevision: prior, EndedCoverageRevision: prior + 1,
		State: "coverage_ended", AdmittedAtUnix: at, AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	bodyDigest, err := Digest("tos.service.agent-guarantor-cancellation-receipt-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	// The stage admission signs its body, not the terminal resolution, whose
	// sink names the receipt body once that body's digest is known.
	stage.ActionResolution.SinkReference, stage.ActionResolution.EvidenceRefs = bodyDigest, []string{bodyDigest}
	receipt := AuthorizedCoverageCancellationReceiptV1{Body: body, StageActionAdmissionEvidence: stage,
		AuthorizedCancellationRequest: request, TransitionEvidenceProjection: projection,
		AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObjectAs(terms.GuarantorAgentID,
			terms.LifecycleAuthorizationProfile, "coverage-cancellation-receipt", bodyDigest,
			"tos.service.agent-guarantor-cancellation-receipt-signature.v1", at)}}
	if _, err := CoverageCancellationReceiptDigestV1(receipt); err != nil {
		t.Fatalf("signed-history cancellation receipt is malformed: %v", err)
	}
	return receipt
}
