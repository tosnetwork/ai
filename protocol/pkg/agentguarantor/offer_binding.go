package agentguarantor

import (
	"errors"
	"math/big"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// firmOfferIssuanceObjectKindV1 is the authorized object kind of the
// eligibility proofs frozen when a firm offer's exposure is admitted.
const firmOfferIssuanceObjectKindV1 = "firm-offer-issuance"

// FirmOfferAdmissionDomainIDV1 is the admission domain in which a firm
// offer's issuance, and the eligibility proofs frozen with its exposure
// admission, are sequenced. It is derived from the offer ID alone, so a
// holder of the offer can recompute it.
func FirmOfferAdmissionDomainIDV1(offerID string) (string, error) {
	if !validDigest(offerID) {
		return "", errors.New("firm-offer admission domain input is invalid")
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-firm-offer-admission-domain.v1", struct {
		AuthorityInstanceID string `json:"authority_instance_id"`
	}{offerID})
}

// closureCapacityBoundV1 is one count or byte ceiling of a claim closure
// capacity under its wire name.
type closureCapacityBoundV1 struct {
	name  string
	value uint64
}

// closureCapacityBoundsV1 lists every count and byte ceiling of a claim
// closure capacity, in the order they are compared.
func closureCapacityBoundsV1(capacity ClaimClosureCapacityV1) []closureCapacityBoundV1 {
	return []closureCapacityBoundV1{
		{"maximum_claim_ingress_actions", capacity.MaximumClaimIngressActions},
		{"maximum_claims", capacity.MaximumClaims},
		{"maximum_claim_revisions_per_claim", capacity.MaximumClaimRevisionsPerClaim},
		{"maximum_decision_admissions_per_claim", capacity.MaximumDecisionAdmissionsPerClaim},
		{"maximum_claim_state_transitions_per_claim", capacity.MaximumClaimStateTransitionsPerClaim},
		{"maximum_challenge_rounds_per_claim", capacity.MaximumChallengeRoundsPerClaim},
		{"maximum_nonterminal_rounds_per_claim", capacity.MaximumNonterminalRoundsPerClaim},
		{"maximum_payout_lines_per_claim", capacity.MaximumPayoutLinesPerClaim},
		{"maximum_admitted_claim_envelope_bytes", capacity.MaximumAdmittedClaimEnvelopeBytes},
		{"maximum_claim_ingress_receipt_envelope_bytes", capacity.MaximumClaimIngressReceiptEnvelopeBytes},
		{"maximum_claim_ingress_cut_proof_bytes", capacity.MaximumClaimIngressCutProofBytes},
		{"maximum_acceptance_request_envelope_bytes", capacity.MaximumAcceptanceRequestEnvelopeBytes},
		{"maximum_acceptance_receipt_envelope_bytes", capacity.MaximumAcceptanceReceiptEnvelopeBytes},
		{"maximum_activation_evidence_envelope_bytes", capacity.MaximumActivationEvidenceEnvelopeBytes},
		{"maximum_non_activation_evidence_envelope_bytes", capacity.MaximumNonActivationEvidenceEnvelopeBytes},
		{"maximum_cancellation_receipt_envelope_bytes", capacity.MaximumCancellationReceiptEnvelopeBytes},
		{"maximum_claim_filing_close_receipt_envelope_bytes", capacity.MaximumClaimFilingCloseReceiptEnvelopeBytes},
		{"maximum_exposure_release_request_bytes", capacity.MaximumExposureReleaseRequestBytes},
		{"maximum_exposure_release_receipt_bytes", capacity.MaximumExposureReleaseReceiptBytes},
		{"maximum_terminal_claim_set_envelope_bytes", capacity.MaximumTerminalClaimSetEnvelopeBytes},
		{"maximum_coverage_resolution_request_bytes", capacity.MaximumCoverageResolutionRequestBytes},
		{"maximum_coverage_resolution_envelope_bytes", capacity.MaximumCoverageResolutionEnvelopeBytes},
	}
}

// validateOfferedClosureCapacityV1 holds the offered claim closure capacity
// to the requested one: no count or byte ceiling above the request's, the
// requested terminal fallback unchanged, and the same continuation states.
// Each object's computed worst-case bytes and budget durations are validated
// against its own maxima and windows elsewhere and are not compared here.
func validateOfferedClosureCapacityV1(offered, requested ClaimClosureCapacityV1) error {
	offeredBounds, requestedBounds := closureCapacityBoundsV1(offered), closureCapacityBoundsV1(requested)
	for index, bound := range offeredBounds {
		if bound.value > requestedBounds[index].value {
			return errors.New("Guarantor terms' closure capacity " + bound.name + " exceeds the requested capacity")
		}
	}
	if !equalCanonical(offered.TerminalFallback, requested.TerminalFallback) {
		return errors.New("Guarantor terms' terminal fallback differs from the requested fallback")
	}
	if !equalStrings(continuationStateKeysV1(offered), continuationStateKeysV1(requested)) {
		return errors.New("Guarantor terms' continuation states differ from the requested capacity's")
	}
	return nil
}

// continuationStateKeysV1 is the state key of every continuation budget
// entry of a capacity, in entry order.
func continuationStateKeysV1(capacity ClaimClosureCapacityV1) []string {
	keys := make([]string, 0, len(capacity.ContinuationBudgetEntries))
	for _, entry := range capacity.ContinuationBudgetEntries {
		keys = append(keys, entry.ProfileStateKey)
	}
	return keys
}

// validateOfferScheduleV1 enforces the offer's place in the section 12.2
// schedule: the request is created no later than the offer becomes valid,
// the reservation ends no later than the offer, the offer no later than the
// request, and the request no later than the coverage starts. The order of
// valid-from, accept-by, grace and reservation end is part of the offer's
// shape.
func validateOfferScheduleV1(offer AuthorizedFirmCoverageOfferV1) error {
	body, request := offer.Body, offer.AuthorizedQuoteRequest.Body
	if request.CreatedAtUnix > body.ValidFromUnix {
		return errors.New("firm Guarantor offer is valid before its quote request was created")
	}
	if offer.ExposureAdmissionReceipt.Body.ExpiresAtUnix > body.ExpiresAtUnix {
		return errors.New("firm Guarantor offer expires before its exposure reservation")
	}
	if body.ExpiresAtUnix > request.ExpiresAtUnix {
		return errors.New("firm Guarantor offer expires after its quote request")
	}
	if request.ExpiresAtUnix > offer.CoverageTerms.CoverageStartsAtUnix {
		return errors.New("Guarantor quote request expires after the offered coverage starts")
	}
	return nil
}

// CoverageFeeObligationKindV1 is the obligation kind of a coverage premium in
// the coverage Agreement (section 13). The Agreement's kind is an open token;
// the Guarantor profile fixes this value for premiums.
const CoverageFeeObligationKindV1 = "guarantor.fee"

// validateOfferReferencedObligationsV1 requires the coverage, payout-template
// and, when named, collateral obligations of a firm offer to exist in the
// coverage Agreement. The premium obligations are held to the Agreement by
// validateCoveragePremiumV1.
func validateOfferReferencedObligationsV1(offer AuthorizedFirmCoverageOfferV1, agreement agentcommerce.AgentAgreementBody) error {
	referenced := []string{offer.Body.CoverageObligationID, offer.Body.PayoutTemplateObligationID}
	if offer.Body.CollateralObligationID != "" {
		referenced = append(referenced, offer.Body.CollateralObligationID)
	}
	present := make(map[string]struct{}, len(agreement.Obligations))
	for _, obligation := range agreement.Obligations {
		present[obligation.ObligationID] = struct{}{}
	}
	for _, obligationID := range referenced {
		if _, found := present[obligationID]; !found {
			return errors.New("firm Guarantor offer references an absent Agreement obligation")
		}
	}
	return nil
}

// validateCoveragePremiumV1 enforces the premium rule of section 12.1 on the
// coverage Agreement. Every premium obligation the terms name exists once, is
// of the fee kind, has a fixed amount in the maximum fee's asset, is owed by
// the covered party to the Guarantor and depends on the offer's coverage
// obligation; together they do not exceed the request's maximum fee. The named
// set is complete: the Agreement carries no other obligation of the fee kind
// and, whatever its kind, no other value-bearing obligation owed by the
// covered party to the Guarantor. Without the completeness rules a fee could
// be charged under an ID the terms omit and escape the sum.
func validateCoveragePremiumV1(offer AuthorizedFirmCoverageOfferV1, agreement agentcommerce.AgentAgreementBody) error {
	request := offer.AuthorizedQuoteRequest.Body
	maximum, valid := new(big.Int).SetString(request.MaximumFee.AmountAtomic, 10)
	if !valid || validateAmount(request.MaximumFee, false) != nil {
		return errors.New("Guarantor quote request's maximum fee is invalid")
	}
	named := make(map[string]bool, len(offer.CoverageTerms.PremiumObligationIDs))
	for _, obligationID := range offer.CoverageTerms.PremiumObligationIDs {
		named[obligationID] = false
	}
	total := new(big.Int)
	for _, obligation := range agreement.Obligations {
		seen, isNamed := named[obligation.ObligationID]
		if !isNamed {
			if obligation.Kind == CoverageFeeObligationKindV1 {
				return errors.New("coverage Agreement carries a guarantor.fee obligation the Guarantor terms do not name as premium")
			}
			if obligation.Amount != nil && obligation.ObligorAgentID == request.CoveredPartyAgentID &&
				obligation.BeneficiaryAgentID == request.GuarantorAgentID {
				return errors.New("coverage Agreement carries a value transfer from the covered party to the Guarantor that the Guarantor terms do not name as premium")
			}
			continue
		}
		if seen {
			return errors.New("coverage Agreement repeats a premium obligation ID")
		}
		named[obligation.ObligationID] = true
		if obligation.Kind != CoverageFeeObligationKindV1 {
			return errors.New("coverage premium obligation is not of the guarantor.fee kind")
		}
		if obligation.Amount == nil || obligation.Amount.AmountDecimal != "" {
			return errors.New("coverage premium obligation has no fixed atomic amount")
		}
		amount := AtomicAmountV1{Asset: AssetIdentityV1{AssetNamespace: obligation.Amount.AssetNamespace,
			AssetIdentifier: obligation.Amount.AssetIdentifier, Unit: obligation.Amount.Unit},
			AmountAtomic: obligation.Amount.AmountAtomic}
		value, parsed := new(big.Int).SetString(amount.AmountAtomic, 10)
		if !parsed || validateAmount(amount, false) != nil {
			return errors.New("coverage premium obligation has no fixed atomic amount")
		}
		if !sameAsset(amount.Asset, request.MaximumFee.Asset) {
			return errors.New("coverage premium obligation is not in the maximum fee's asset")
		}
		if obligation.ObligorAgentID != request.CoveredPartyAgentID {
			return errors.New("coverage premium obligation is not owed by the covered party")
		}
		if obligation.BeneficiaryAgentID != request.GuarantorAgentID {
			return errors.New("coverage premium obligation is not owed to the Guarantor")
		}
		if !containsString(obligation.DependsOnObligationIDs, offer.Body.CoverageObligationID) {
			return errors.New("coverage premium obligation does not depend on the offer's coverage obligation")
		}
		total.Add(total, value)
	}
	for _, seen := range named {
		if !seen {
			return errors.New("Guarantor terms name a premium obligation the coverage Agreement lacks")
		}
	}
	if total.Cmp(maximum) > 0 {
		return errors.New("total coverage fee exceeds the quote request's maximum fee")
	}
	return nil
}

// firmOfferSelectedServiceProfileV1 returns the service profile a firm offer
// embeds, the head of its artifact's revision lineage, with the digest
// recomputed from those bytes. It does not verify the publication, so the
// profile is authoritative only once that digest is found equal to the one
// the signed quote request and offer body carry.
func firmOfferSelectedServiceProfileV1(artifact GuarantorServiceProfileArtifactV1) (ServiceProfileV1, string, error) {
	if len(artifact.Revisions) == 0 || len(artifact.Revisions) > MaxProfileRevisions {
		return ServiceProfileV1{}, "", errors.New("firm Guarantor offer carries no service profile revision or too many")
	}
	profile := artifact.Revisions[len(artifact.Revisions)-1].ServiceProfile
	digest, err := ServiceProfileDigest(profile)
	if err != nil {
		return ServiceProfileV1{}, "", errors.New("firm Guarantor offer's embedded service profile is invalid")
	}
	return profile, digest, nil
}

// validateOfferedTermsAgainstQuoteRequestV1 holds the offered coverage terms
// to the quote request they answer. Identities, selections, amounts and the
// coverage period are what the requester signed and must be repeated exactly;
// the per-claim timing windows may only be tightened within the requester's
// maxima. requestDigest is the digest of request.
func validateOfferedTermsAgainstQuoteRequestV1(terms CoverageTermsV1, request AuthorizedCoverageQuoteRequestV1,
	requestDigest string) error {
	body, requested := request.Body, request.RequestedTerms
	if terms.QuoteRequestDigest != requestDigest {
		return errors.New("Guarantor terms name another quote request")
	}
	if terms.ServiceProfileDigest != body.ServiceProfileDigest {
		return errors.New("Guarantor terms name another service profile than the quote request")
	}
	if terms.UnderlyingAgreementBodyDigest != body.UnderlyingAgreementBodyDigest {
		return errors.New("Guarantor terms name another underlying Agreement than the quote request")
	}
	if terms.GuarantorAgentID != body.GuarantorAgentID {
		return errors.New("Guarantor terms name another Guarantor than the quote request")
	}
	if terms.CoveredPartyAgentID != body.CoveredPartyAgentID {
		return errors.New("Guarantor terms name another covered party than the quote request")
	}
	if terms.BeneficiaryAgentID != body.BeneficiaryAgentID {
		return errors.New("Guarantor terms name another beneficiary than the quote request")
	}
	if !equalStrings(terms.PermittedClaimantSubjects, body.ClaimantSubjects) {
		return errors.New("Guarantor terms' permitted claimants differ from the quote request's claimant subjects")
	}
	if !equalStrings(terms.CoveredObligationIDs, body.CoveredObligationIDs) {
		return errors.New("Guarantor terms' covered obligations differ from the quote request")
	}
	// A V1 firm offer answers one quote request with version 1 terms, whose
	// coverage identity is derived from the Guarantor and that request. Valid
	// version 1 terms carry no predecessor digest.
	if terms.CoverageVersion != 1 {
		return errors.New("Guarantor terms offered on a quote request are not coverage version 1")
	}
	coverageID, err := CoverageID(terms.GuarantorAgentID, requestDigest)
	if err != nil || terms.CoverageID != coverageID {
		return errors.New("Guarantor terms' coverage ID is not derived from the Guarantor and the quote request")
	}
	if terms.CoverageCategory != requested.CoverageCategory {
		return errors.New("Guarantor terms' coverage category differs from the requested terms")
	}
	if terms.BenefitKind != requested.BenefitKind {
		return errors.New("Guarantor terms' benefit kind differs from the requested terms")
	}
	if !sameAsset(terms.CoverageAsset, requested.CoverageAsset) {
		return errors.New("Guarantor terms' coverage asset differs from the requested terms")
	}
	if terms.SelectedAssuranceLevel != requested.SelectedAssuranceLevel {
		return errors.New("Guarantor terms' assurance level differs from the requested terms")
	}
	if terms.SelectedClaimProfileDigest != requested.SelectedClaimProfileDigest {
		return errors.New("Guarantor terms select another claim profile than the requested terms")
	}
	if terms.SelectedCollateralProfileDigest != requested.SelectedCollateralProfileDigest {
		return errors.New("Guarantor terms select another collateral profile than the requested terms")
	}
	if terms.SelectedPayoutAdapterProfile != requested.SelectedPayoutAdapterProfile {
		return errors.New("Guarantor terms select another payout adapter profile than the requested terms")
	}
	if terms.ClaimTriggerProfile != requested.ClaimTriggerProfile {
		return errors.New("Guarantor terms' claim trigger profile differs from the requested terms")
	}
	if terms.ClaimEvidenceProfile != requested.ClaimEvidenceProfile {
		return errors.New("Guarantor terms' claim evidence profile differs from the requested terms")
	}
	if terms.DecisionProfile != body.SelectedDecisionProfile {
		return errors.New("Guarantor terms' decision profile differs from the quote request's selected decision profile")
	}
	if terms.MaximumAggregatePayout != requested.RequestedAggregatePayout {
		return errors.New("Guarantor terms' maximum aggregate payout differs from the requested aggregate payout")
	}
	if terms.MaximumPerClaim != requested.RequestedPerClaim {
		return errors.New("Guarantor terms' maximum per claim differs from the requested per-claim amount")
	}
	if terms.CoverageStartsAtUnix != requested.RequestedCoverageStartsAtUnix {
		return errors.New("Guarantor terms' coverage start differs from the requested coverage start")
	}
	if terms.CoverageEndsAtUnix != requested.RequestedCoverageEndsAtUnix {
		return errors.New("Guarantor terms' coverage end differs from the requested coverage end")
	}
	if terms.ClaimFilingEndsAtUnix != requested.RequestedClaimFilingEndsAtUnix {
		return errors.New("Guarantor terms' claim filing end differs from the requested claim filing end")
	}
	if err := validateOfferedClosureCapacityV1(terms.ClaimClosureCapacity, requested.RequestedClosureCapacity); err != nil {
		return err
	}
	if !equalProfileRefs(terms.RequiredExtensions, requested.RequiredExtensions) {
		return errors.New("Guarantor terms' required extensions differ from the requested terms")
	}
	if !equalProfileRefs(terms.OptionalExtensions, requested.OptionalExtensions) {
		return errors.New("Guarantor terms' optional extensions differ from the requested terms")
	}
	if terms.ReviewDeadlineSeconds > requested.MaximumReviewDeadlineSeconds {
		return errors.New("Guarantor terms' review deadline exceeds the requester's maximum")
	}
	if terms.ChallengeWindowSeconds > requested.MaximumChallengeWindowSeconds {
		return errors.New("Guarantor terms' challenge window exceeds the requester's maximum")
	}
	if terms.NonterminalResolutionWindowSeconds > requested.MaximumNonterminalResolutionWindowSeconds {
		return errors.New("Guarantor terms' nonterminal resolution window exceeds the requester's maximum")
	}
	if terms.SuccessorDecisionWindowSeconds > requested.MaximumSuccessorDecisionWindowSeconds {
		return errors.New("Guarantor terms' successor decision window exceeds the requester's maximum")
	}
	if terms.PayoutDeadlineSeconds > requested.MaximumPayoutDeadlineSeconds {
		return errors.New("Guarantor terms' payout deadline exceeds the requester's maximum")
	}
	if terms.AdapterRecoveryWindowSeconds > requested.MaximumAdapterRecoveryWindowSeconds {
		return errors.New("Guarantor terms' adapter recovery window exceeds the requester's maximum")
	}
	return validateTermsWithinRequestedDeadlinesV1(terms, requested)
}

// validateAuthorizationProfileV1 requires every authorization of a set to be
// made under profile. The set's signatures and subjects are verified
// elsewhere; this only refuses evidence qualified by another profile.
func validateAuthorizationProfileV1(authorizations []ProfileQualifiedObjectAuthorizationV1, profile ProfileRefV1) bool {
	if len(authorizations) == 0 || len(authorizations) > MaxAuthorizations {
		return false
	}
	for _, authorization := range authorizations {
		if authorization.ProfileURI != profile.ProfileURI || authorization.ProfileVersion != profile.ProfileVersion ||
			authorization.ProfileDigest != profile.ProfileDigest {
			return false
		}
	}
	return true
}

// validateOfferExposureReceiptBindingV1 holds the exposure-admission receipt a
// firm offer embeds to that offer, to the service profile's exposure
// authority and to the quote request it admitted. The receipt's signatures
// are verified by VerifyExposureAdmissionReceiptV1.
func validateOfferExposureReceiptBindingV1(offer AuthorizedFirmCoverageOfferV1, profile ServiceProfileV1,
	requestDigest, termsDigest string) error {
	body, terms, request := offer.Body, offer.CoverageTerms, offer.AuthorizedQuoteRequest.Body
	receipt := offer.ExposureAdmissionReceipt
	descriptor := receipt.Descriptor
	receiptDigest, err := ExposureAdmissionReceiptDigestV1(receipt)
	if err != nil || receiptDigest != body.ExposureAdmissionReceiptDigest ||
		descriptor.CoverageAgreementBodyDigest != body.CoverageAgreementBodyDigest ||
		descriptor.CoverageTermsDigest != termsDigest || descriptor.QuoteRequestDigest != requestDigest ||
		descriptor.ServiceProfileDigest != body.ServiceProfileDigest ||
		receipt.Body.ReservationID != body.ReservationID ||
		receipt.Body.GuarantorAgentID != body.GuarantorAgentID ||
		descriptor.GuarantorAgentID != body.GuarantorAgentID || descriptor.CoverageID != terms.CoverageID ||
		descriptor.CoverageVersion != terms.CoverageVersion ||
		descriptor.ReservationScope.GuarantorAgentID != body.GuarantorAgentID ||
		descriptor.ReservationScope.CoverageAgreementBodyDigest != body.CoverageAgreementBodyDigest ||
		descriptor.ReservationScope.CoverageObligationID != body.CoverageObligationID ||
		descriptor.ReservationScope.CoverageAsset != terms.CoverageAsset ||
		descriptor.ReservationScope.SelectedAssuranceLevel != terms.SelectedAssuranceLevel ||
		descriptor.ReservationScope.MaximumAggregatePayout != terms.MaximumAggregatePayout ||
		descriptor.ReservedExposure != receipt.Body.ReservedExposure ||
		descriptor.ReservedExposure != terms.MaximumAggregatePayout {
		return errors.New("firm Guarantor offer exposure receipt is not bound to the offer")
	}
	if receipt.Body.AuthorityID != profile.ExposureAuthorityID {
		return errors.New("firm Guarantor offer exposure receipt names another authority than the service profile's exposure authority")
	}
	if !validateAuthorizationProfileV1(receipt.Authorizations, profile.ExposureAuthorizationProfile) {
		return errors.New("firm Guarantor offer exposure receipt is not authorized under the service profile's exposure authorization profile")
	}
	if receipt.Body.AdmittedAtUnix != body.ValidFromUnix {
		return errors.New("firm Guarantor offer exposure was not admitted at the offer's valid-from time")
	}
	proofs := receipt.AuthorityAdmissionEligibilityProofSet
	if proofs.AdmittedActionDigest != receipt.Body.AuthorizedActionDigest {
		return errors.New("firm Guarantor offer exposure eligibility proofs admit another action than the receipt's")
	}
	if proofs.AdmissionTimeUnix != receipt.Body.AdmittedAtUnix {
		return errors.New("firm Guarantor offer exposure eligibility proofs are not frozen at the receipt's admission time")
	}
	admissionDomain, domainErr := FirmOfferAdmissionDomainIDV1(body.OfferID)
	if domainErr != nil || proofs.AdmissionDomainID != admissionDomain {
		return errors.New("firm Guarantor offer exposure eligibility proofs are not in the offer's issuance admission domain")
	}
	// The admission checkpoint re-resolves every party the quote request
	// names, once each. The receipt carries no admission sequence, so the
	// set's sequence is held only to its own entries.
	required := map[string]struct{}{request.RequesterAgentID: {}, request.CoveredPartyAgentID: {}, request.BeneficiaryAgentID: {}}
	proven := make(map[string]struct{}, len(proofs.Entries))
	for _, proof := range proofs.Entries {
		if proof.InputAuthorizedEnvelopeDigest != requestDigest {
			return errors.New("firm Guarantor offer exposure eligibility proof admits another input than the quote request")
		}
		if proof.AuthorizedObjectKind != firmOfferIssuanceObjectKindV1 {
			return errors.New("firm Guarantor offer exposure eligibility proof is not for firm-offer issuance")
		}
		if proof.AuthorizedBodyDigest != receipt.Body.ExactRequestDigest {
			return errors.New("firm Guarantor offer exposure eligibility proof binds another request than the receipt's exact request")
		}
		if proof.AuthorityResolverProfile != profile.ExposureAuthorizationProfile {
			return errors.New("firm Guarantor offer exposure eligibility proof was resolved under another profile than the exposure authorization profile")
		}
		if proof.RequiredScopeDigest != profile.AuthorityDomainDigest {
			return errors.New("firm Guarantor offer exposure eligibility proof requires another scope than the service profile's authority domain")
		}
		if _, party := required[proof.AuthoritySubject]; !party {
			return errors.New("firm Guarantor offer exposure eligibility proofs name a subject outside the quote request's parties")
		}
		if _, duplicate := proven[proof.AuthoritySubject]; duplicate {
			return errors.New("firm Guarantor offer exposure eligibility proofs carry more than one proof for a party")
		}
		proven[proof.AuthoritySubject] = struct{}{}
	}
	if len(proven) != len(required) {
		return errors.New("firm Guarantor offer exposure eligibility proofs omit a party of the quote request")
	}
	return nil
}

// validateFirmOfferBindingV1 enforces every rule that ties the parts of a
// firm offer together and needs neither the coverage Agreement, a resolver
// nor the clock: the offered terms against the embedded quote request, the
// offer body against both, the embedded service profile against the request,
// and the exposure receipt against the offer and the profile's exposure
// authority. Every verifier that accepts a firm offer, or evidence standing
// on one, calls it, so the rules cannot be skipped by choosing another entry
// point. Signatures, the profile publication and the underlying Agreement are
// verified by the callers that hold resolvers.
func validateFirmOfferBindingV1(offer AuthorizedFirmCoverageOfferV1) error {
	if err := validateFirmOfferShape(offer); err != nil {
		return err
	}
	request, terms, body := offer.AuthorizedQuoteRequest, offer.CoverageTerms, offer.Body
	requestDigest, err := QuoteRequestDigest(request)
	if err != nil {
		return err
	}
	termsDigest, err := CoverageTermsDigest(terms)
	if err != nil {
		return err
	}
	profile, profileDigest, err := firmOfferSelectedServiceProfileV1(offer.ServiceProfileArtifact)
	if err != nil {
		return err
	}
	if request.Body.ServiceProfileDigest != profileDigest {
		return errors.New("Guarantor quote request names another service profile than the firm offer embeds")
	}
	if request.Body.ServiceIntentDigest != offer.ServiceProfileArtifact.SelectedServiceIntentOperationDigest {
		return errors.New("Guarantor quote request names another service intent than the firm offer's selected publication")
	}
	if err := validateOfferedTermsAgainstQuoteRequestV1(terms, request, requestDigest); err != nil {
		return err
	}
	if body.QuoteRequestDigest != requestDigest || body.CoverageTermsDigest != termsDigest ||
		body.ServiceProfileDigest != profileDigest ||
		body.ServiceIntentDigest != offer.ServiceProfileArtifact.SelectedServiceIntentOperationDigest ||
		body.GuarantorAgentID != request.Body.GuarantorAgentID || body.CoveredPartyAgentID != request.Body.CoveredPartyAgentID ||
		body.BeneficiaryAgentID != request.Body.BeneficiaryAgentID || body.CoverageID != terms.CoverageID ||
		body.CoverageVersion != terms.CoverageVersion ||
		body.UnderlyingAgreementBodyDigest != request.Body.UnderlyingAgreementBodyDigest ||
		!equalStrings(body.CoveredObligationIDs, request.Body.CoveredObligationIDs) ||
		!equalStrings(body.PremiumObligationIDs, terms.PremiumObligationIDs) ||
		body.CollateralObligationID != terms.CollateralObligationID {
		return errors.New("firm Guarantor offer binding is invalid")
	}
	if !equalProfileRefs(body.RequiredExtensions, terms.RequiredExtensions) {
		return errors.New("firm Guarantor offer's required extensions differ from its terms")
	}
	if !equalProfileRefs(body.OptionalExtensions, terms.OptionalExtensions) {
		return errors.New("firm Guarantor offer's optional extensions differ from its terms")
	}
	if body.AcceptanceProcessingGraceSeconds != terms.AcceptanceProcessingGraceSeconds {
		return errors.New("firm Guarantor offer's acceptance processing grace differs from its terms")
	}
	if body.AcceptanceProcessingGraceSeconds > profile.AdmissionLimits.MaximumAcceptanceProcessingGraceSeconds {
		return errors.New("firm Guarantor offer's acceptance processing grace exceeds the service profile's maximum")
	}
	if err := validateOfferScheduleV1(offer); err != nil {
		return err
	}
	if !validateAuthorizationProfileV1(request.Authorizations, NativeAgentAuthorizationProfileV1()) {
		return errors.New(quoteRequestProfileRefusalV1)
	}
	if !validateAuthorizationProfileV1(offer.Authorizations, profile.ExposureAuthorizationProfile) {
		return errors.New("firm Guarantor offer is not authorized under the service profile's exposure authorization profile")
	}
	return validateOfferExposureReceiptBindingV1(offer, profile, requestDigest, termsDigest)
}

// validateFirmOfferAgreementBindingV1 is validateFirmOfferBindingV1 together
// with the rules that need the coverage Agreement body: the offer commits
// that exact body, the obligations it references exist in it, its premium
// obligations are the Agreement's complete fee set within the request's
// maximum fee, and the terms' final deadline is its hard-effect deadline.
func validateFirmOfferAgreementBindingV1(offer AuthorizedFirmCoverageOfferV1, agreement agentcommerce.AgentAgreementBody) error {
	if err := validateFirmOfferBindingV1(offer); err != nil {
		return err
	}
	agreementDigest, err := agentcommerce.AgreementBodyDigest(agreement)
	if err != nil || offer.Body.CoverageAgreementBodyDigest != agreementDigest {
		return errors.New("firm Guarantor offer commits another coverage Agreement body")
	}
	if err := validateOfferReferencedObligationsV1(offer, agreement); err != nil {
		return err
	}
	if err := validateCoveragePremiumV1(offer, agreement); err != nil {
		return err
	}
	return validateCoverageDeadlineAnchorV1(offer.CoverageTerms, agreement.ExpiresAtUnix)
}
