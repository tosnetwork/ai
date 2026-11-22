package agentguarantor

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

func validateEligibilityProofSetAgainstV1(set AuthorityAdmissionEligibilityProofSetV1, actionDigest,
	inputEnvelopeDigest string, subjects []string, objectKind, bodyDigest, scopeDigest string,
	profile agentcommerce.ProfileRefV1, domainID string, sequence, admittedAtUnix uint64) error {
	if err := ValidateAuthorityAdmissionEligibilityProofSetV1(set); err != nil || set.AdmittedActionDigest != actionDigest ||
		set.AdmissionDomainID != domainID || set.AdmissionSequence != sequence || set.AdmissionTimeUnix != admittedAtUnix ||
		len(set.Entries) != len(subjects) || !sortedUnique(subjects, MaxAuthorizations, validID) {
		return errors.New("Guarantor authority eligibility cut does not match the admission")
	}
	wanted := make(map[string]struct{}, len(subjects))
	for _, subject := range subjects {
		wanted[subject] = struct{}{}
	}
	for _, proof := range set.Entries {
		if _, found := wanted[proof.AuthoritySubject]; !found || proof.InputAuthorizedEnvelopeDigest != inputEnvelopeDigest ||
			proof.AuthorizedObjectKind != objectKind || proof.AuthorizedBodyDigest != bodyDigest ||
			proof.RequiredScopeDigest != scopeDigest || proof.AuthorityResolverProfile != profile {
			return errors.New("Guarantor authority eligibility proof is substituted")
		}
		delete(wanted, proof.AuthoritySubject)
	}
	if len(wanted) != 0 {
		return errors.New("Guarantor authority eligibility proof is incomplete")
	}
	return nil
}

// validateClaimRevisionWithinCapacityV1 holds a claim revision number to the
// Agreement's maximum_claim_revisions_per_claim, which counts the initial
// claim. Every bound the closure capacity reserves per claim (ingress actions,
// bundle bytes, revision proofs) is computed from that maximum, so a revision
// past it has no reserved room in the terminal claim set.
func validateClaimRevisionWithinCapacityV1(terms CoverageTermsV1, revision uint64) error {
	maximum := terms.ClaimClosureCapacity.MaximumClaimRevisionsPerClaim
	if maximum == 0 {
		return errors.New("Guarantor terms set no maximum claim revisions per claim")
	}
	if revision == 0 {
		return errors.New("Guarantor claim revision is zero")
	}
	if revision > maximum {
		return errors.New("Guarantor claim revision exceeds the Agreement's maximum claim revisions per claim")
	}
	return nil
}

func VerifyClaimSubmissionIngressReceiptV1(receipt AuthorizedClaimSubmissionIngressReceiptV1, terms CoverageTermsV1,
	bound GuarantorStageActionAuthorityV1, authorityResolver AuthorityKeyResolver,
	fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	body, claim := receipt.Body, receipt.AuthorizedClaim
	if err := validateClaimRevisionWithinCapacityV1(terms, claim.Body.ClaimRevision); err != nil {
		return err
	}
	claimDigest, claimErr := ClaimEnvelopeDigest(claim)
	claimBodyDigest, bodyErr := ClaimBodyDigest(claim.Body)
	stateDomain, stateErr := ClaimIngressStateDomainDigestV1(body.CoverageAgreementBodyDigest, body.CoverageObligationID)
	logClaimID, ingressKind := claim.Body.ClaimID, "revision"
	if claim.Body.ClaimRevision == 1 {
		logClaimID, ingressKind = "", "initial"
	}
	logID, logErr := ClaimIngressLogIDV1(body.CoverageAgreementBodyDigest, body.CoverageObligationID, logClaimID)
	initialRoot, rootErr := InitialClaimLogRootV1(ClaimIngressLogRootDomainV1, logID)
	if body.ClaimIngressSequence > 1 {
		initialRoot = body.PriorClaimIngressLogRoot
	}
	admittedRoot, advanceErr := AdvanceClaimLogRootV1(ClaimIngressLogRootDomainV1, logID, initialRoot,
		body.ClaimIngressSequence, ClaimIngressLogLeafV1{StableActionID: body.StableActionID,
			ExactRequestDigest: body.ExactRequestDigest, ReceivedAtUnix: body.ReceivedAtUnix})
	actionDigest, actionErr := agentcommerce.AuthorizedActionDigest(receipt.StageActionAdmissionEvidence.AuthorizedAction)
	proofDigest, proofErr := AuthorityAdmissionEligibilityProofSetDigestV1(receipt.AuthorityAdmissionEligibilityProofSet)
	if claimErr != nil || bodyErr != nil || stateErr != nil || logErr != nil || rootErr != nil || advanceErr != nil ||
		actionErr != nil || proofErr != nil || body.SchemaVersion != 1 || body.AuthorityID != bound.ActionAuthorityID ||
		body.CoverageAgreementBodyDigest != claim.Body.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != claim.Body.CoverageObligationID || body.ClaimID != claim.Body.ClaimID ||
		body.ClaimRevision != claim.Body.ClaimRevision || body.IngressKind != ingressKind || body.ClaimBodyDigest != claimBodyDigest ||
		body.AuthorizedClaimEnvelopeDigest != claimDigest || body.IngressStateDomainDigest != stateDomain ||
		bound.AdmissionStateDomainDigest != stateDomain || body.ClaimIngressLogID != logID || body.ClaimIngressSequence == 0 ||
		body.PriorClaimIngressLogRoot != initialRoot || body.AdmittedClaimIngressLogRoot != admittedRoot ||
		body.IngressSlotRevision != 1 || body.State != "received" || body.AuthorizedActionDigest != actionDigest ||
		body.StableActionID != receipt.StageActionAdmissionEvidence.AuthorizedAction.StableActionID ||
		body.ExactRequestDigest != receipt.StageActionAdmissionEvidence.AuthorizedAction.ExactRequestDigest ||
		body.WriterGeneration != receipt.StageActionAdmissionEvidence.AuthorizedAction.WriterGeneration ||
		body.WriterFenceDigest != receipt.StageActionAdmissionEvidence.AuthorizedAction.WriterFenceDigest ||
		body.ReceivedAtUnix < claim.Body.CreatedAtUnix || body.ReceivedAtUnix > claim.Body.ExpiresAtUnix ||
		body.AuthorityAdmissionEligibilityProofSetDigest != proofDigest {
		return errors.New("Guarantor claim ingress receipt binding is invalid")
	}
	if err := VerifyClaim(claim, terms, body.CoverageAgreementBodyDigest, body.CoverageObligationID,
		authorityResolver, time.Unix(int64(body.ReceivedAtUnix), 0).UTC()); err != nil {
		return err
	}
	requestBody := ClaimSubmissionIngressActionBodyV1{SchemaVersion: 1, AuthorizedClaim: claim, TargetIngressState: "received"}
	request, err := guarantorCodec.Marshal(requestBody)
	if err != nil {
		return err
	}
	fields := map[string]agentcommerce.SemanticValue{"owner_id": agentcommerce.ID(bound.ActionOwnerID),
		"agent_id": agentcommerce.ID(bound.ActionAgentID), "agreement_body_digest": agentcommerce.Digest32(body.CoverageAgreementBodyDigest),
		"obligation_id": agentcommerce.ID(body.CoverageObligationID), "claim_id": agentcommerce.ID(body.ClaimID),
		"claim_revision": agentcommerce.U64(body.ClaimRevision)}
	if err := VerifyPortableStageActionAdmissionEvidenceV1(receipt.StageActionAdmissionEvidence, bound, request, fields,
		authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	if receipt.StageActionAdmissionEvidence.ActionResolution.SinkReference != claimDigest ||
		!containsString(receipt.StageActionAdmissionEvidence.ActionResolution.EvidenceRefs, claimDigest) {
		return errors.New("Guarantor claim ingress terminal result is substituted")
	}
	if err := validateEligibilityProofSetAgainstV1(receipt.AuthorityAdmissionEligibilityProofSet, actionDigest, claimDigest,
		terms.ClaimIngressAuthoritySubjects, "claim-ingress-receipt", claimDigest, terms.ClaimIngressProfile.ProfileDigest,
		terms.ClaimIngressProfile, logID, body.ClaimIngressSequence, body.ReceivedAtUnix); err != nil {
		return err
	}
	receiptBodyDigest, err := guarantorCodec.Digest("tos.service.agent-guarantor-claim-ingress-receipt-body.v1", body)
	if err != nil {
		return err
	}
	return ValidateAuthorizationQuorumSet(receipt.Authorizations, "claim-ingress-receipt", receiptBodyDigest,
		"tos.service.agent-guarantor-claim-ingress-receipt-signature.v1", terms.ClaimIngressAuthoritySubjects,
		terms.ClaimIngressAuthorityQuorumRule, authorityResolver, now)
}

func extractFirmOfferFromAcceptanceV1(receipt AuthorizedCoverageAcceptanceReceiptV1) (AuthorizedFirmCoverageOfferV1, error) {
	var found *AuthorizedFirmCoverageOfferV1
	for _, wrapper := range receipt.AuthorizedAcceptanceRequest.AuthorizationEvidenceSet.Evidence {
		if wrapper.EvidenceProfileURI != FirmOfferAgreementEvidenceProfileURI {
			continue
		}
		var typed GuarantorFirmOfferAgreementEvidenceV1
		if found != nil || wrapper.EvidenceContentType != FirmOfferAgreementEvidenceContentType ||
			guarantorCodec.Unmarshal(wrapper.Evidence, &typed) != nil {
			return AuthorizedFirmCoverageOfferV1{}, errors.New("Guarantor acceptance has ambiguous firm-offer evidence")
		}
		candidate := typed.AuthorizedFirmOffer
		found = &candidate
	}
	if found == nil {
		return AuthorizedFirmCoverageOfferV1{}, errors.New("Guarantor acceptance has no firm-offer evidence")
	}
	return *found, nil
}

// validateRevisionInitialAdmissionV1 checks what a revision's body alone
// shows about its initial admission: the first revision's predecessor is the
// initial admission, so the initial digest it names must be that
// predecessor's. Every revision's initial digest is also bound by the initial
// admission's proof the revision admission carries.
func validateRevisionInitialAdmissionV1(body ClaimAdmissionReceiptBodyV1) error {
	if body.AdmissionKind == "revision" && body.AdmittedClaimRevision == 2 &&
		body.InitialClaimAdmissionReceiptDigest != body.PredecessorRevisionAdmissionReceiptDigest {
		return errors.New("Guarantor first claim revision names an initial admission other than its predecessor")
	}
	return nil
}

// bindRevisionInitialAdmissionProofV1 is the binding of a claim admission's
// initial-admission proof, checked before any signature: a revision carries
// exactly the compact proof of the initial admission its body names, for the
// same claim, Agreement and obligation; an initial admission carries none.
// The proof's own authorization and seal are verified with the receipt.
func bindRevisionInitialAdmissionProofV1(body ClaimAdmissionReceiptBodyV1, proof *ClaimAdmissionReceiptProofV1) error {
	switch body.AdmissionKind {
	case "initial":
		if proof != nil {
			return errors.New("an initial Guarantor claim admission carries an initial claim admission proof")
		}
		return nil
	case "revision":
		if proof == nil {
			return errors.New("a Guarantor claim revision admission lacks its initial claim admission proof")
		}
		initial := proof.ReceiptBody
		if _, err := ClaimAdmissionReceiptProofDigestV1(*proof); err != nil ||
			proof.ReceiptEnvelopeDigest != body.InitialClaimAdmissionReceiptDigest || initial.AdmissionKind != "initial" ||
			initial.ClaimID != body.ClaimID || initial.CoverageAgreementBodyDigest != body.CoverageAgreementBodyDigest ||
			initial.CoverageObligationID != body.CoverageObligationID {
			return errors.New("a Guarantor claim revision's initial claim admission proof is not the claim's initial admission")
		}
		return nil
	default:
		return errors.New("Guarantor claim admission kind is invalid")
	}
}

func VerifyClaimAdmissionReceiptV1(receipt AuthorizedClaimAdmissionReceiptV1, terms CoverageTermsV1,
	agreementVerifier agentcommerce.AgreementEvidenceVerifier, authorityResolver AuthorityKeyResolver,
	fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	body, ingress := receipt.Body, receipt.AuthorizedClaimIngressReceipt
	if err := validateRevisionInitialAdmissionV1(body); err != nil {
		return err
	}
	if err := validateClaimRevisionWithinCapacityV1(terms, body.AdmittedClaimRevision); err != nil {
		return err
	}
	if err := bindRevisionInitialAdmissionProofV1(body, receipt.InitialClaimAdmissionProof); err != nil {
		return err
	}
	claim := ingress.AuthorizedClaim
	stageName := "claim_revision_admission"
	if claim.Body.ClaimRevision == 1 {
		stageName = "initial_claim_admission"
	}
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, stageName)
	if err != nil {
		return err
	}
	ingressBound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "claim_submission_ingress")
	if err != nil {
		return err
	}
	if err := VerifyClaimSubmissionIngressReceiptV1(ingress, terms, ingressBound, authorityResolver, fenceResolver, now); err != nil {
		return fmt.Errorf("Guarantor claim admission has an invalid ingress predecessor: %w", err)
	}
	ingressDigest, err := ClaimIngressReceiptDigestV1(ingress)
	if err != nil {
		return err
	}
	claimDigest, err := ClaimEnvelopeDigest(claim)
	if err != nil {
		return err
	}
	claimBodyDigest, err := ClaimBodyDigest(claim.Body)
	if err != nil {
		return err
	}
	activation := receipt.AuthorizedClaimIngressReceipt
	_ = activation // keep the sole claim path explicit; activation is carried by the action effect below.
	var actionBody ClaimSubmissionActionBodyV1
	if err := guarantorCodec.Unmarshal(receipt.StageActionAdmissionEvidence.CanonicalRequest, &actionBody); err != nil {
		return errors.New("Guarantor claim admission request cannot be decoded")
	}
	effect := actionBody.AuthorityInstanceEffect
	if !equalCanonical(effect.AuthorizedClaimIngressReceipt, ingress) ||
		!equalCanonical(receipt.AuthorityInstanceRecord, actionBody.AuthorityInstanceRecord) ||
		actionBody.SchemaVersion != 1 || actionBody.AuthorityInstanceID != receipt.AuthorityInstanceRecord.AuthorityInstanceID ||
		receipt.AuthorityInstanceRecord.AuthorityInstanceID != body.AuthorityInstanceID ||
		effect.ExpectedCoverageRevision != body.PriorCoverageRevision ||
		!equalCanonical(effect.ExpectedCoverageEndCommitment, receipt.CoverageEndCommitment) {
		return errors.New("Guarantor claim admission authority-instance effect is substituted")
	}
	offer, err := extractFirmOfferFromAcceptanceV1(effect.AuthorizedCoverageActivationEvidence.AuthorizedAcceptanceReceipt)
	if err != nil {
		return err
	}
	if err := coverageActivationPredecessorVerifierV1(effect.AuthorizedCoverageActivationEvidence, offer, agreementVerifier,
		authorityResolver, fenceResolver, collateralFinalityVerifierFromResolverV1(authorityResolver), now); err != nil {
		return fmt.Errorf("Guarantor claim admission activation predecessor is invalid: %w", err)
	}
	effectBytes, err := guarantorCodec.Marshal(effect)
	if err != nil {
		return err
	}
	effectDigest, err := agentcommerce.DownstreamEffectDescriptorDigest(effectBytes)
	if err != nil {
		return err
	}
	action := receipt.StageActionAdmissionEvidence.AuthorizedAction
	allocation := agentcommerce.AuthorityInstanceAllocationRequest{OwnerID: action.OwnerID, AgentID: action.AgentID,
		PurposeKind: "conditional.claim.submit", MandateDigest: action.MandateDigest,
		ApprovalDigestOrZero: zeroDigestOrEmptyV1(action.ApprovalDigest), DownstreamEffectDescriptorDigest: effectDigest,
		PredecessorAuthorityInstanceID: zeroSHA256DigestV1()}
	allocationDigest, err := agentcommerce.AuthorityInstanceAllocationRequestDigest(allocation)
	if err != nil {
		return err
	}
	instanceID, err := agentcommerce.DeriveAuthorityInstanceID(allocation, receipt.AuthorityInstanceRecord.AllocationSequence)
	if err != nil || receipt.AuthorityInstanceRecord.RequestDigest != allocationDigest ||
		receipt.AuthorityInstanceRecord.AuthorityInstanceID != instanceID || body.AuthorityInstanceAllocationRequestDigest != allocationDigest {
		return errors.New("Guarantor claim authority instance is invalid")
	}
	request, err := guarantorCodec.Marshal(actionBody)
	if err != nil || !bytes.Equal(request, receipt.StageActionAdmissionEvidence.CanonicalRequest) {
		return errors.New("Guarantor claim admission request is noncanonical")
	}
	fields := map[string]agentcommerce.SemanticValue{"owner_id": agentcommerce.ID(bound.ActionOwnerID),
		"agent_id": agentcommerce.ID(bound.ActionAgentID), "agreement_body_digest": agentcommerce.Digest32(body.CoverageAgreementBodyDigest),
		"obligation_id": agentcommerce.ID(body.CoverageObligationID), "authority_instance_id": agentcommerce.Digest32(instanceID),
		"claim_body_digest": agentcommerce.Digest32(claimBodyDigest)}
	if err := VerifyPortableStageActionAdmissionEvidenceV1(receipt.StageActionAdmissionEvidence, bound, request, fields,
		authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	actionDigest, err := agentcommerce.AuthorizedActionDigest(action)
	proofDigest, proofErr := AuthorityAdmissionEligibilityProofSetDigestV1(receipt.AuthorityAdmissionEligibilityProofSet)
	endDigest, endErr := CoverageEndCommitmentDigestV1(receipt.CoverageEndCommitment)
	claimLogID, claimLogErr := ClaimAdmissionLogIDV1(body.CoverageAgreementBodyDigest, body.CoverageObligationID)
	revisionLogID, revisionLogErr := ClaimRevisionLogIDV1(body.CoverageAgreementBodyDigest, body.CoverageObligationID, body.ClaimID)
	if err != nil || proofErr != nil || endErr != nil || claimLogErr != nil || revisionLogErr != nil || body.SchemaVersion != 1 ||
		body.AuthorityID != bound.ActionAuthorityID || body.CoverageAgreementBodyDigest != claim.Body.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != claim.Body.CoverageObligationID || body.ClaimID != claim.Body.ClaimID ||
		body.AuthorizedClaimEnvelopeDigest != claimDigest || body.ClaimSubmissionIngressReceiptDigest != ingressDigest ||
		body.AuthorizedActionDigest != actionDigest || body.StableActionID != action.StableActionID ||
		body.ExactRequestDigest != action.ExactRequestDigest || body.PriorCoverageRevision == 0 ||
		!isNextRevisionV1(body.AdmittedCoverageRevision, body.PriorCoverageRevision) || body.PriorCoverageEndCommitmentDigest != endDigest ||
		body.ResultingCoverageEndCommitmentDigest != endDigest || body.AdmittedClaimRevision != claim.Body.ClaimRevision ||
		body.ClaimAdmissionLogID != claimLogID || body.ClaimRevisionLogID != revisionLogID ||
		body.WriterGeneration != action.WriterGeneration || body.WriterFenceDigest != action.WriterFenceDigest ||
		body.AdmittedAtUnix == 0 || body.AuthorityAdmissionEligibilityProofSetDigest != proofDigest {
		return errors.New("Guarantor claim admission receipt binding is invalid")
	}
	if body.AdmissionKind == "initial" {
		if claim.Body.ClaimRevision != 1 || body.PriorClaimRevision != 0 || body.ClaimAdmissionSequence == 0 ||
			body.ClaimRevisionAdmissionSequence != 1 || body.InitialClaimAdmissionReceiptDigest != "" ||
			body.PredecessorRevisionAdmissionReceiptDigest != "" {
			return errors.New("initial Guarantor claim admission lineage is invalid")
		}
		wantClaimRoot, rootErr := AdvanceClaimLogRootV1(ClaimAdmissionLogRootDomainV1, claimLogID,
			body.PriorClaimAdmissionLogRoot, body.ClaimAdmissionSequence, InitialClaimAdmissionLeafV1{ClaimID: body.ClaimID,
				AdmissionSequence: body.ClaimAdmissionSequence, AuthorizedClaimEnvelopeDigest: claimDigest})
		initialRevisionRoot, initialErr := InitialClaimLogRootV1(ClaimRevisionLogRootDomainV1, revisionLogID)
		wantRevisionRoot, revisionErr := AdvanceClaimLogRootV1(ClaimRevisionLogRootDomainV1, revisionLogID,
			initialRevisionRoot, 1, ClaimRevisionAdmissionLeafV1{ClaimID: body.ClaimID,
				ClaimRevisionAdmissionSequence: 1, AuthorizedClaimEnvelopeDigest: claimDigest})
		if rootErr != nil || initialErr != nil || revisionErr != nil || body.AdmittedClaimAdmissionLogRoot != wantClaimRoot ||
			body.PriorClaimRevisionLogRoot != initialRevisionRoot || body.AdmittedClaimRevisionLogRoot != wantRevisionRoot {
			return errors.New("initial Guarantor claim admission roots are invalid")
		}
	} else if body.AdmissionKind == "revision" {
		if claim.Body.ClaimRevision <= 1 || !isNextRevisionV1(body.AdmittedClaimRevision, body.PriorClaimRevision) ||
			body.ClaimRevisionAdmissionSequence != body.AdmittedClaimRevision || !validDigest(body.InitialClaimAdmissionReceiptDigest) ||
			!validDigest(body.PredecessorRevisionAdmissionReceiptDigest) || body.PriorClaimAdmissionLogRoot != body.AdmittedClaimAdmissionLogRoot {
			return errors.New("revised Guarantor claim admission lineage is invalid")
		}
		wantRevisionRoot, rootErr := AdvanceClaimLogRootV1(ClaimRevisionLogRootDomainV1, revisionLogID,
			body.PriorClaimRevisionLogRoot, body.ClaimRevisionAdmissionSequence, ClaimRevisionAdmissionLeafV1{ClaimID: body.ClaimID,
				ClaimRevisionAdmissionSequence: body.ClaimRevisionAdmissionSequence, AuthorizedClaimEnvelopeDigest: claimDigest,
				PredecessorRevisionAdmissionReceiptDigest: body.PredecessorRevisionAdmissionReceiptDigest})
		if rootErr != nil || wantRevisionRoot != body.AdmittedClaimRevisionLogRoot {
			return errors.New("revised Guarantor claim admission root is invalid")
		}
	} else {
		return errors.New("Guarantor claim admission kind is invalid")
	}
	if err := validateEligibilityProofSetAgainstV1(receipt.AuthorityAdmissionEligibilityProofSet, actionDigest,
		ingressDigest, terms.ClaimAdmissionAuthoritySubjects, "claim-admission-receipt", claimDigest,
		terms.ClaimAdmissionProfile.ProfileDigest, terms.ClaimAdmissionProfile, terms.CoverageStateDomainDigest,
		body.ClaimRevisionAdmissionSequence, body.AdmittedAtUnix); err != nil {
		return err
	}
	receiptBodyDigest, err := guarantorCodec.Digest("tos.service.agent-guarantor-claim-admission-receipt-body.v1", body)
	if err != nil {
		return err
	}
	if err := ValidateAuthorizationQuorumSet(receipt.Authorizations, "claim-admission-receipt", receiptBodyDigest,
		"tos.service.agent-guarantor-claim-admission-receipt-signature.v1", terms.ClaimAdmissionAuthoritySubjects,
		terms.ClaimAdmissionQuorumRule, authorityResolver, now); err != nil {
		return err
	}
	if proof := receipt.InitialClaimAdmissionProof; proof != nil {
		if err := ValidateClaimAdmissionReceiptProofV1(*proof, terms, authorityResolver, fenceResolver, now, true); err != nil {
			return fmt.Errorf("Guarantor claim revision's initial claim admission proof is invalid: %w", err)
		}
	}
	return nil
}

func zeroSHA256DigestV1() string {
	return "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

func zeroDigestOrEmptyV1(value string) string {
	if value == "" {
		return zeroSHA256DigestV1()
	}
	return value
}
