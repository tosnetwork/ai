package agentguarantor

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// The accepted-but-never-activated branch on signed history: a signed
// acceptance receipt on the firm offer, non-activation evidence at the
// activation cutoff, and the release of the offer's exposure reservation.

// useOfferPhaseFence replaces the history's Writer Fence with one that is
// already valid when the offer is issued and also covers extra action kinds,
// so stage actions of the acceptance phase verify at their own time.
func (history *signedHistory) useOfferPhaseFence(extraKinds ...string) {
	t := history.t
	body := history.fence.Body
	scope := map[string]struct{}{}
	for _, kind := range append(append([]string(nil), body.Scope...), extraKinds...) {
		scope[kind] = struct{}{}
	}
	body.Scope = body.Scope[:0:0]
	for kind := range scope {
		body.Scope = append(body.Scope, kind)
	}
	sort.Strings(body.Scope)
	body.IssuedAtUnix, body.ExpiresAtUnix = signedOfferIssuedAt-60, signedOfferIssuedAt-60+24*60*60-1
	fence, err := agentcommerce.SignWriterFence(context.Background(), body, nativeTestFake, signedHistoryActionController)
	if err != nil {
		t.Fatal(err)
	}
	history.fence = fence
}

func signedOfferProjection(t *testing.T, purpose, agreementDigest, obligationID, target, role, digest string) (TransitionEvidenceProjectionV1, string) {
	t.Helper()
	projection := TransitionEvidenceProjectionV1{SchemaVersion: 1, Purpose: purpose, CoverageAgreementBodyDigest: agreementDigest,
		ObligationID: obligationID, TargetState: target,
		EvidenceDigests: []TransitionEvidenceDigestRefV1{{EvidenceRole: role, DigestKind: "authorized_envelope", ObjectDigest: digest}}}
	projectionDigest, err := TransitionEvidenceProjectionDigestV1(projection)
	if err != nil {
		t.Fatal(err)
	}
	return projection, projectionDigest
}

// acceptanceReceipt is the Guarantor-signed acceptance receipt of the covered
// party's acceptance of the offer, admitted one second after it was received.
func (history *signedHistory) acceptanceReceipt(signed signedOffer) AuthorizedCoverageAcceptanceReceiptV1 {
	t, offer := history.t, signed.offer
	request := history.acceptanceRequest(signed)
	requestDigest, err := CoverageAcceptanceRequestDigestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := derivedAuxiliaryStageAuthorityV1(offer.CoverageTerms.StageActionAuthorityBinding, "coverage_acceptance",
		"coverage_activation")
	if err != nil {
		t.Fatal(err)
	}
	agreementDigest := request.Body.CoverageAgreementBodyDigest
	projection, projectionDigest := signedOfferProjection(t, "coverage-acceptance", agreementDigest,
		offer.Body.CoverageObligationID, "accepted", "acceptance-request", requestDigest)
	receivedAt, acceptedAt := request.Body.CreatedAtUnix, request.Body.CreatedAtUnix+1
	action := CoverageAcceptanceAdmissionActionBodyV1{SchemaVersion: 1, AuthorizedAcceptanceRequest: request,
		TransitionEvidenceProjection: projection,
		ExpectedReservationRevision:  offer.ExposureAdmissionReceipt.Body.AdmittedPortfolioRevision,
		ExpectedOfferStateRevision:   1, TargetOfferStateRevision: 2, TargetCoverageRevision: 1,
		ExpectedClaimFilingState: "uninitialized", TargetClaimFilingState: "not_open", TargetClaimFilingStateRevision: 1}
	canonical, err := Canonical(action)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]agentcommerce.SemanticValue{
		"owner_id": agentcommerce.ID(bound.ActionOwnerID), "agent_id": agentcommerce.ID(bound.ActionAgentID),
		"agreement_body_digest": agentcommerce.Digest32(agreementDigest), "obligation_id": agentcommerce.ID(offer.Body.CoverageObligationID),
		"expected_state_revision": agentcommerce.U64(1), "target_state": agentcommerce.State("accepted"),
		"evidence_set_digest": agentcommerce.Digest32(projectionDigest)}
	stage := history.stageFor(bound, "application/vnd.tos.service.agent-guarantor-coverage-acceptance-action.v1+cbor",
		canonical, fields, testDigest("1"), offer.Body.ExpiresAtUnix, acceptedAt, "", nil)
	actionDigest, err := agentcommerce.AuthorizedActionDigest(stage.AuthorizedAction)
	if err != nil {
		t.Fatal(err)
	}
	admissionDomain, err := CoverageAcceptanceAdmissionDomainIDV1(bound.AdmissionStateDomainDigest, offer.Body.OfferID)
	if err != nil {
		t.Fatal(err)
	}
	eligibility := history.eligibility(actionDigest, requestDigest, []string{signedHistoryClaimant}, "coverage-acceptance-request",
		stage.AuthorizedAction.ExactRequestDigest, testDigest("2"), offer.CoverageTerms.LifecycleAuthorizationProfile,
		admissionDomain, 1, acceptedAt)
	eligibilityDigest, err := AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	if err != nil {
		t.Fatal(err)
	}
	body := CoverageAcceptanceReceiptBodyV1{SchemaVersion: 1, AuthorityID: bound.ActionAuthorityID,
		CoverageAgreementBodyDigest:               agreementDigest,
		AuthorizedFirmOfferEnvelopeDigest:         request.Body.AuthorizedFirmOfferEnvelopeDigest,
		AuthorizedAcceptanceRequestEnvelopeDigest: requestDigest,
		ExposureAdmissionReceiptDigest:            offer.Body.ExposureAdmissionReceiptDigest, ReservationID: offer.Body.ReservationID,
		TransitionEvidenceProjectionDigest: projectionDigest, AuthorizedActionDigest: actionDigest,
		StableActionID: stage.AuthorizedAction.StableActionID, ExactRequestDigest: stage.AuthorizedAction.ExactRequestDigest,
		WriterGeneration: stage.AuthorizedAction.WriterGeneration, WriterFenceDigest: stage.AuthorizedAction.WriterFenceDigest,
		PriorOfferStateRevision: 1, AcceptedOfferStateRevision: 2, AcceptedCoverageRevision: 1,
		PriorClaimFilingState: "uninitialized", AcceptedClaimFilingState: "not_open", AcceptedClaimFilingStateRevision: 1,
		ReceivedAtUnix: receivedAt, AcceptedAtUnix: acceptedAt, AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	bodyDigest, err := Digest("tos.service.agent-guarantor-acceptance-receipt-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	receipt := AuthorizedCoverageAcceptanceReceiptV1{Body: body, StageActionAdmissionEvidence: stage,
		AuthorizedAcceptanceRequest: request, TransitionEvidenceProjection: projection,
		AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObject("coverage-acceptance-receipt", bodyDigest,
			"tos.service.agent-guarantor-acceptance-receipt-signature.v1", acceptedAt)}}
	if _, err := CoverageAcceptanceReceiptDigestV1(receipt); err != nil {
		t.Fatalf("signed-history acceptance receipt is malformed: %v", err)
	}
	return receipt
}

// nonActivation is the Guarantor-signed evidence that the accepted coverage
// was not activated by its activation cutoff, the coverage start: an empty
// activation admission cut, resolved one second after the cutoff.
func (history *signedHistory) nonActivation(signed signedOffer,
	acceptance AuthorizedCoverageAcceptanceReceiptV1) AuthorizedCoverageNonActivationEvidenceV1 {
	t, offer, terms := history.t, signed.offer, signed.offer.CoverageTerms
	agreementDigest, obligationID := offer.Body.CoverageAgreementBodyDigest, offer.Body.CoverageObligationID
	logID, err := ActivationAdmissionDomainIDV1(agreementDigest)
	if err != nil {
		t.Fatal(err)
	}
	logRoot, err := InitialAdmissionLogRootV1(logID)
	if err != nil {
		t.Fatal(err)
	}
	cut := ActivationAdmissionCutProofV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		ActivationAdmissionLogID: logID, ActivationCutoffUnix: terms.CoverageStartsAtUnix, AdmissionLogRoot: logRoot}
	cutDigest, err := ActivationAdmissionCutProofDigestV1(cut)
	if err != nil {
		t.Fatalf("signed-history activation cut is invalid: %v", err)
	}
	reason := CoverageNonActivationReasonEvidenceV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		CoverageObligationID: obligationID, Reason: "activation_window_expired", ActivationAdmissionCutProofDigest: cutDigest}
	reasonDigest, err := CoverageNonActivationReasonEvidenceDigestV1(reason)
	if err != nil {
		t.Fatal(err)
	}
	projection, projectionDigest := signedOfferProjection(t, "coverage-non-activation", agreementDigest, obligationID,
		"not_activated_confirmed", "activation-cut", cutDigest)
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "coverage_non_activation")
	if err != nil {
		t.Fatal(err)
	}
	resolvedAt := terms.CoverageStartsAtUnix + 1
	canonical, err := Canonical(CoverageNonActivationActionBodyV1{SchemaVersion: 1, AuthorizedAcceptanceReceipt: acceptance,
		ActivationAdmissionCutProof: cut, NonActivationReasonEvidence: reason, TransitionEvidenceProjection: projection,
		ExpectedCoverageRevision: 1, TargetCoverageRevision: 2, TargetCoverageState: "not_activated_confirmed",
		ExpectedClaimFilingState: "not_open", TargetClaimFilingState: "not_open", ExpectedClaimFilingStateRevision: 1,
		TargetClaimFilingStateRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]agentcommerce.SemanticValue{
		"owner_id": agentcommerce.ID(bound.ActionOwnerID), "agent_id": agentcommerce.ID(bound.ActionAgentID),
		"agreement_body_digest": agentcommerce.Digest32(agreementDigest), "obligation_id": agentcommerce.ID(obligationID),
		"expected_state_revision": agentcommerce.U64(1), "target_state": agentcommerce.State("not_activated_confirmed"),
		"evidence_set_digest": agentcommerce.Digest32(projectionDigest)}
	stage := history.stageFor(bound, "application/vnd.tos.service.agent-guarantor-coverage-non-activation-action.v1+cbor",
		canonical, fields, testDigest("1"), resolvedAt+600, resolvedAt, "", nil)
	actionDigest, err := agentcommerce.AuthorizedActionDigest(stage.AuthorizedAction)
	if err != nil {
		t.Fatal(err)
	}
	offerDigest, err := FirmOfferDigest(offer)
	if err != nil {
		t.Fatal(err)
	}
	acceptanceDigest, err := CoverageAcceptanceReceiptDigestV1(acceptance)
	if err != nil {
		t.Fatal(err)
	}
	eligibility := history.eligibility(actionDigest, acceptanceDigest, []string{signedHistoryGuarantor}, "non-activation-evidence",
		stage.AuthorizedAction.ExactRequestDigest, testDigest("2"), terms.LifecycleAuthorizationProfile, testDigest("3"), 1, resolvedAt)
	eligibilityDigest, err := AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	if err != nil {
		t.Fatal(err)
	}
	body := CoverageNonActivationEvidenceBodyV1{SchemaVersion: 1, AuthorityID: bound.ActionAuthorityID,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: obligationID,
		CoverageStateDomainDigest: terms.CoverageStateDomainDigest, AuthorizedFirmOfferEnvelopeDigest: offerDigest,
		AcceptanceReceiptDigest: acceptanceDigest, ExposureReceiptDigest: offer.Body.ExposureAdmissionReceiptDigest,
		Reason: reason.Reason, ActivationCutoffUnix: cut.ActivationCutoffUnix, ActivationAdmissionLogID: logID,
		ActivationAdmissionLogRoot: logRoot, ActivationAdmissionCutProofDigest: cutDigest,
		NonActivationReasonEvidenceDigest: reasonDigest, TransitionEvidenceProjectionDigest: projectionDigest,
		AuthorizedActionDigest: actionDigest, StableActionID: stage.AuthorizedAction.StableActionID,
		ExactRequestDigest: stage.AuthorizedAction.ExactRequestDigest, WriterGeneration: stage.AuthorizedAction.WriterGeneration,
		WriterFenceDigest: stage.AuthorizedAction.WriterFenceDigest, PriorCoverageRevision: 1, ResolvedCoverageRevision: 2,
		PriorClaimFilingState: "not_open", ResultingClaimFilingState: "not_open", PriorClaimFilingStateRevision: 1,
		ResultingClaimFilingStateRevision: 1, ResolvedAtUnix: resolvedAt,
		AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	bodyDigest, err := Digest("tos.service.agent-guarantor-non-activation-evidence-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	evidence := AuthorizedCoverageNonActivationEvidenceV1{Body: body, StageActionAdmissionEvidence: stage,
		AuthorizedAcceptanceReceipt: acceptance, ActivationAdmissionCutProof: cut, NonActivationReasonEvidence: reason,
		TransitionEvidenceProjection: projection, AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObject("non-activation-evidence", bodyDigest,
			"tos.service.agent-guarantor-non-activation-evidence-signature.v1", resolvedAt)}}
	if _, err := CoverageNonActivationEvidenceDigestV1(evidence); err != nil {
		t.Fatalf("signed-history non-activation evidence is malformed: %v", err)
	}
	return evidence
}

// exposureRelease is the Guarantor-signed release of the offer's whole
// reservation after the non-activation, one second after it was resolved.
func (history *signedHistory) exposureRelease(signed signedOffer,
	nonActivation AuthorizedCoverageNonActivationEvidenceV1) AuthorizedNonActivationExposureReleaseReceiptV1 {
	t, offer := history.t, signed.offer
	bound, err := FindStageActionAuthorityV1(offer.CoverageTerms.StageActionAuthorityBinding, "post_acceptance_exposure_release")
	if err != nil {
		t.Fatal(err)
	}
	nonActivationDigest, err := CoverageNonActivationEvidenceDigestV1(nonActivation)
	if err != nil {
		t.Fatal(err)
	}
	releasedAt := nonActivation.Body.ResolvedAtUnix + 1
	canonical, err := Canonical(ExposureReleaseActionBodyV1{ReservationID: offer.Body.ReservationID,
		AgreementDigest: offer.Body.CoverageAgreementBodyDigest, TargetPortfolioRevision: 4,
		TerminalEvidenceSetDigest: nonActivationDigest})
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]agentcommerce.SemanticValue{
		"owner_id": agentcommerce.ID(bound.ActionOwnerID), "agent_id": agentcommerce.ID(bound.ActionAgentID),
		"reservation_id": agentcommerce.Digest32(offer.Body.ReservationID), "target_revision": agentcommerce.U64(4),
		"terminal_evidence_set_digest": agentcommerce.Digest32(nonActivationDigest)}
	stage := history.stageFor(bound, "application/vnd.tos.service.agent-guarantor-exposure-release-action.v1+cbor",
		canonical, fields, testDigest("1"), releasedAt+600, releasedAt, "", nil)
	actionDigest, err := agentcommerce.AuthorizedActionDigest(stage.AuthorizedAction)
	if err != nil {
		t.Fatal(err)
	}
	reserved := offer.ExposureAdmissionReceipt.Body.ReservedExposure
	body := NonActivationExposureReleaseReceiptBodyV1{SchemaVersion: 1, AuthorityID: bound.ActionAuthorityID,
		GuarantorAgentID: offer.Body.GuarantorAgentID, CoverageAgreementBodyDigest: offer.Body.CoverageAgreementBodyDigest,
		CoverageObligationID: offer.Body.CoverageObligationID, ReservationID: offer.Body.ReservationID,
		ExposureAdmissionReceiptDigest: offer.Body.ExposureAdmissionReceiptDigest, NonActivationEvidenceDigest: nonActivationDigest,
		AuthorizedActionDigest: actionDigest, StableActionID: stage.AuthorizedAction.StableActionID,
		ExactRequestDigest: stage.AuthorizedAction.ExactRequestDigest, WriterGeneration: stage.AuthorizedAction.WriterGeneration,
		WriterFenceDigest: stage.AuthorizedAction.WriterFenceDigest, BaseReleaseStateRevision: 3, ReleasedReleaseStateRevision: 4,
		ReleasedExposure: reserved, RemainingReservedExposure: AtomicAmountV1{Asset: reserved.Asset, AmountAtomic: "0"},
		State: "released", ReleasedAtUnix: releasedAt}
	bodyDigest, err := Digest("tos.service.agent-guarantor-non-activation-exposure-release-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	return AuthorizedNonActivationExposureReleaseReceiptV1{Body: body, StageActionAdmissionEvidence: stage,
		AuthorizedExposureAdmissionReceipt: offer.ExposureAdmissionReceipt, AuthorizedNonActivationEvidence: nonActivation,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObject("non-activation-exposure-release-receipt",
			bodyDigest, "tos.service.agent-guarantor-non-activation-exposure-release-signature.v1", releasedAt)}}
}

// TestSignedHistoryNonActivationReleaseIsOfTheOffersReservation: on a signed
// offer that is accepted and then not activated, the acceptance receipt, the
// non-activation evidence and the exposure release each verify in full. The
// same release carrying another exposure receipt, validly signed by the same
// Guarantor for another offer, is refused: it used to be accepted without
// any of its later checks.
func TestSignedHistoryNonActivationReleaseIsOfTheOffersReservation(t *testing.T) {
	history := newSignedHistory(t)
	acceptanceBound, err := derivedAuxiliaryStageAuthorityV1(history.terms.StageActionAuthorityBinding, "coverage_acceptance",
		"coverage_activation")
	if err != nil {
		t.Fatal(err)
	}
	history.useOfferPhaseFence(acceptanceBound.OperationActionKind)
	signed := history.quoteToOffer(true, nil)
	other := history.quoteToOffer(true, func(in *signedOfferInputs) {
		in.requestBody = func(body *CoverageQuoteRequestBodyV1) { body.RequestID = "request:other" }
	})
	if err := other.verify(); err != nil {
		t.Fatalf("the other offer, whose exposure receipt is substituted below, does not verify: %v", err)
	}
	verifier := signedOfferAgreementVerifier{signed}

	acceptance := history.acceptanceReceipt(signed)
	if err := VerifyCoverageAcceptanceReceiptV1(acceptance, signed.offer, verifier, signed.resolver, history.fenceResolver,
		signedHistoryTime(acceptance.Body.AcceptedAtUnix)); err != nil {
		t.Fatalf("the acceptance receipt was refused: %v", err)
	}
	nonActivation := history.nonActivation(signed, acceptance)
	if err := VerifyCoverageNonActivationEvidenceV1(nonActivation, signed.offer, verifier, signed.resolver, history.fenceResolver,
		signedHistoryTime(nonActivation.Body.ResolvedAtUnix)); err != nil {
		t.Fatalf("the non-activation evidence was refused: %v", err)
	}
	release := history.exposureRelease(signed, nonActivation)
	verify := func(release AuthorizedNonActivationExposureReleaseReceiptV1) error {
		return VerifyNonActivationExposureReleaseReceiptV1(release, signed.offer, verifier, signed.resolver, history.fenceResolver,
			signedHistoryTime(release.Body.ReleasedAtUnix))
	}
	if err := verify(release); err != nil {
		t.Fatalf("the exposure release was refused: %v", err)
	}

	const refusal = "non-activation exposure release carries another exposure receipt than the firm offer's"
	substituted := release
	substituted.AuthorizedExposureAdmissionReceipt = other.offer.ExposureAdmissionReceipt
	if err := verify(substituted); err == nil || !strings.Contains(err.Error(), refusal) {
		t.Errorf("a release carrying another offer's exposure receipt: got %v, want a refusal containing %q", err, refusal)
	}
}
