package agentguarantor

import (
	"errors"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// firmOfferIssuanceObjectKindV1 is the authorized object kind of the
// eligibility proofs frozen when a firm offer's exposure is admitted.
const firmOfferIssuanceObjectKindV1 = "firm-offer-issuance"

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
	// coverage identity is derived from the Guarantor and that request.
	if terms.CoverageVersion != 1 || terms.PredecessorTermsDigest != "" {
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
		proven[proof.AuthoritySubject] = struct{}{}
	}
	// The admission checkpoint re-resolves every party the quote request
	// names; a proof for any other subject is not part of that checkpoint.
	required := map[string]struct{}{request.RequesterAgentID: {}, request.CoveredPartyAgentID: {}, request.BeneficiaryAgentID: {}}
	for subject := range required {
		if _, found := proven[subject]; !found {
			return errors.New("firm Guarantor offer exposure eligibility proofs omit a party of the quote request")
		}
	}
	if len(proven) != len(required) {
		return errors.New("firm Guarantor offer exposure eligibility proofs name a subject outside the quote request's parties")
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
	if !validateAuthorizationProfileV1(offer.Authorizations, profile.ExposureAuthorizationProfile) {
		return errors.New("firm Guarantor offer is not authorized under the service profile's exposure authorization profile")
	}
	return validateOfferExposureReceiptBindingV1(offer, profile, requestDigest, termsDigest)
}

// validateFirmOfferAgreementBindingV1 is validateFirmOfferBindingV1 together
// with the rules that need the coverage Agreement body: the offer commits
// that exact body, and the terms' final deadline is its hard-effect deadline.
func validateFirmOfferAgreementBindingV1(offer AuthorizedFirmCoverageOfferV1, agreement agentcommerce.AgentAgreementBody) error {
	if err := validateFirmOfferBindingV1(offer); err != nil {
		return err
	}
	agreementDigest, err := agentcommerce.AgreementBodyDigest(agreement)
	if err != nil || offer.Body.CoverageAgreementBodyDigest != agreementDigest {
		return errors.New("firm Guarantor offer commits another coverage Agreement body")
	}
	return validateCoverageDeadlineAnchorV1(offer.CoverageTerms, agreement.ExpiresAtUnix)
}
