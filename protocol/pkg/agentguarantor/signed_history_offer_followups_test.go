package agentguarantor

import (
	"sort"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// Rules of a firm offer that need the coverage Agreement body (the complete
// fee set and the referenced obligations), the profile a quote request is
// authorized under, the eligibility proofs frozen at acceptance and at
// non-activation, and activation evidence on the signed offer. Every refused
// object is signed over consistent digests and differs from an accepted one
// only in the named field.

// signedOfferAddObligation appends obligation to the Agreement and puts it in
// scope of each named predicate, keeping every predicate's obligation set
// sorted.
func signedOfferAddObligation(agreement *agentcommerce.AgentAgreementBody, obligation agentcommerce.AgreementObligation) {
	agreement.Obligations = append(agreement.Obligations, obligation)
	for index := range agreement.AuthorizationPredicates {
		predicate := &agreement.AuthorizationPredicates[index]
		for _, predicateID := range obligation.AuthorizationPredicateIDs {
			if predicate.PredicateID == predicateID {
				scope := append(append([]string(nil), predicate.ObligationIDs...), obligation.ObligationID)
				sort.Strings(scope)
				predicate.ObligationIDs = scope
			}
		}
	}
}

// signedOfferRenameObligation gives one obligation of the Agreement another
// ID everywhere the Agreement names it, so the Agreement stays valid and no
// longer carries the old ID.
func signedOfferRenameObligation(agreement *agentcommerce.AgentAgreementBody, from, to string) {
	rename := func(identifiers []string) []string {
		renamed := append([]string(nil), identifiers...)
		for index := range renamed {
			if renamed[index] == from {
				renamed[index] = to
			}
		}
		sort.Strings(renamed)
		return renamed
	}
	for index := range agreement.Obligations {
		obligation := &agreement.Obligations[index]
		if obligation.ObligationID == from {
			obligation.ObligationID = to
		}
		if len(obligation.DependsOnObligationIDs) != 0 {
			obligation.DependsOnObligationIDs = rename(obligation.DependsOnObligationIDs)
		}
	}
	for index := range agreement.AuthorizationPredicates {
		agreement.AuthorizationPredicates[index].ObligationIDs = rename(agreement.AuthorizationPredicates[index].ObligationIDs)
	}
}

// TestSignedHistoryCoveragePremiumSetIsComplete: the premium obligations the
// terms name are the coverage Agreement's complete fee set. Each is of the
// guarantor.fee kind and depends on the offer's coverage obligation; the
// Agreement carries no other guarantor.fee obligation and no other
// value-bearing obligation owed by the covered party to the Guarantor. An
// unnamed obligation of 999999999999 units beside a named premium at the
// maximum fee of 100 is refused whatever its kind. The rules need the
// Agreement body, so the intrinsic evidence verifier does not apply them.
func TestSignedHistoryCoveragePremiumSetIsComplete(t *testing.T) {
	const premiumID, coverageID, payoutID = "obligation:premium", "obligation:coverage", "obligation:payout"
	premium := func(change func(*agentcommerce.AgreementObligation)) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) {
			in.agreement = func(agreement *agentcommerce.AgentAgreementBody) {
				for index := range agreement.Obligations {
					if agreement.Obligations[index].ObligationID == premiumID {
						change(&agreement.Obligations[index])
					}
				}
			}
		}
	}
	// extra adds one obligation the terms do not name: a copy of the premium
	// under another ID with 999999999999 units, varied by change.
	extra := func(change func(*agentcommerce.AgreementObligation)) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) {
			in.agreement = func(agreement *agentcommerce.AgentAgreementBody) {
				for _, obligation := range agreement.Obligations {
					if obligation.ObligationID != premiumID {
						continue
					}
					added := obligation
					added.ObligationID = "obligation:unnamed"
					amount := *obligation.Amount
					amount.AmountAtomic = "999999999999"
					added.Amount = &amount
					change(&added)
					signedOfferAddObligation(agreement, added)
					return
				}
			}
		}
	}
	const (
		unnamedFee      = "coverage Agreement carries a guarantor.fee obligation the Guarantor terms do not name as premium"
		unnamedTransfer = "coverage Agreement carries a value transfer from the covered party to the Guarantor that the Guarantor terms do not name as premium"
		notFeeKind      = "coverage premium obligation is not of the guarantor.fee kind"
		notDependent    = "coverage premium obligation does not depend on the offer's coverage obligation"
		billingTerms    = "coverage premium obligation carries billing terms"

		unnamedNoBeneficiary = "coverage Agreement carries a value transfer from the covered party to no named beneficiary that the Guarantor terms do not name as premium"
	)
	// billed gives the premium billing terms whose aggregate cap is limit
	// units of the premium's own asset.
	billed := func(terms agentcommerce.BillingTerms, limit string) func(*agentcommerce.AgreementObligation) {
		return func(obligation *agentcommerce.AgreementObligation) {
			aggregate := *obligation.Amount
			aggregate.AmountAtomic = limit
			terms.MaximumAggregateAmount = aggregate
			obligation.BillingTerms = &terms
		}
	}
	checkOfferBinding(t, []offerBindingCase{
		{name: "one named guarantor.fee premium depending on the coverage obligation", late: true},
		{name: "named premium of the payment kind", late: true,
			change:  premium(func(obligation *agentcommerce.AgreementObligation) { obligation.Kind = "payment" }),
			refusal: notFeeKind, agreementRule: true},
		{name: "unnamed guarantor.fee obligation owed by the covered party to the Guarantor", late: true,
			change:  extra(func(*agentcommerce.AgreementObligation) {}),
			refusal: unnamedFee, agreementRule: true},
		{name: "unnamed guarantor.fee obligation owed by the beneficiary to the Guarantor", late: true,
			change: extra(func(obligation *agentcommerce.AgreementObligation) {
				obligation.ObligorAgentID = "agent:beneficiary"
				obligation.AuthorizationPredicateIDs = []string{"predicate:beneficiary"}
			}),
			refusal: unnamedFee, agreementRule: true},
		{name: "unnamed payment obligation owed by the covered party to the Guarantor", late: true,
			change:  extra(func(obligation *agentcommerce.AgreementObligation) { obligation.Kind = "payment" }),
			refusal: unnamedTransfer, agreementRule: true},
		{name: "unnamed payment obligation owed by the covered party to the beneficiary", late: true,
			change: extra(func(obligation *agentcommerce.AgreementObligation) {
				obligation.Kind, obligation.BeneficiaryAgentID = "payment", "agent:beneficiary"
			})},
		{name: "unnamed obligation of the covered party to the Guarantor that carries no value", late: true,
			change: extra(func(obligation *agentcommerce.AgreementObligation) {
				obligation.Kind = "disclosure"
				obligation.Amount, obligation.SettlementAdapterURI, obligation.SettlementParameters = nil, "", nil
			})},
		{name: "named premium without a dependency", late: true,
			change:  premium(func(obligation *agentcommerce.AgreementObligation) { obligation.DependsOnObligationIDs = nil }),
			refusal: notDependent, agreementRule: true},
		{name: "named premium depending on the payout template obligation only", late: true,
			change: premium(func(obligation *agentcommerce.AgreementObligation) {
				obligation.DependsOnObligationIDs = []string{payoutID}
			}),
			refusal: notDependent, agreementRule: true},
		{name: "named premium depending on the coverage and the payout template obligations", late: true,
			change: premium(func(obligation *agentcommerce.AgreementObligation) {
				obligation.DependsOnObligationIDs = []string{coverageID, payoutID}
			})},
		// The premium's amount stays 100, the maximum fee; billing terms would
		// let it be charged up to their own aggregate cap.
		{name: "named premium billed periodically 10000 times up to 1000000", late: true,
			change: premium(billed(agentcommerce.BillingTerms{BillingKind: "periodic", FirstSequence: 1,
				RecurrenceStartUnix: signedHistoryStart, RecurrenceEndUnix: signedHistoryStart + 3600, RecurrenceCount: 10000,
				RecurrenceIntervalSecs: 1, CancellationCutoffPolicy: "none"}, "1000000")),
			refusal: billingTerms, agreementRule: true},
		{name: "named premium with accumulated billing up to 1000000", late: true,
			change: premium(billed(agentcommerce.BillingTerms{BillingKind: "accumulated", FirstSequence: 1,
				CancellationCutoffPolicy: "none"}, "1000000")),
			refusal: billingTerms, agreementRule: true},
		{name: "named premium with one-time billing capped at its own amount", late: true,
			change: premium(billed(agentcommerce.BillingTerms{BillingKind: "one_time", FirstSequence: 1,
				CancellationCutoffPolicy: "none"}, "100")),
			refusal: billingTerms, agreementRule: true},
		{name: "named premium with a required extension", late: true,
			change: premium(func(obligation *agentcommerce.AgreementObligation) {
				obligation.RequiredExtensions = []string{"tos.test.extension.amount-multiplier.v1"}
			}),
			refusal: "coverage premium obligation carries a required extension", agreementRule: true},
		{name: "named premium with an optional extension", late: true,
			change: premium(func(obligation *agentcommerce.AgreementObligation) {
				obligation.OptionalExtensions = []string{"tos.test.extension.amount-multiplier.v1"}
			})},
		{name: "unnamed payment obligation of the covered party with no beneficiary", late: true,
			change: extra(func(obligation *agentcommerce.AgreementObligation) {
				obligation.Kind, obligation.BeneficiaryAgentID = "payment", ""
			}),
			refusal: unnamedNoBeneficiary, agreementRule: true},
		{name: "unnamed obligation of the covered party with no beneficiary that carries no value", late: true,
			change: extra(func(obligation *agentcommerce.AgreementObligation) {
				obligation.Kind, obligation.BeneficiaryAgentID = "disclosure", ""
				obligation.Amount, obligation.SettlementAdapterURI, obligation.SettlementParameters = nil, "", nil
			})},
	})
}

// TestSignedHistoryOfferReferencedObligationsExistAtAcceptance: the coverage,
// payout-template and collateral obligations a firm offer names exist in the
// coverage Agreement. VerifyFirmOffer and the acceptance request verifier
// both refuse an offer on an Agreement that carries one of them under another
// ID; the intrinsic evidence verifier holds only the Agreement's digest.
func TestSignedHistoryOfferReferencedObligationsExistAtAcceptance(t *testing.T) {
	const absent = "firm Guarantor offer references an absent Agreement obligation"
	renamed := func(from string) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) {
			in.agreement = func(agreement *agentcommerce.AgentAgreementBody) {
				signedOfferRenameObligation(agreement, from, from+"-other")
			}
		}
	}
	collateralized := func(change func(*signedOfferInputs)) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) {
			signedOfferCollateralized(in)
			if change != nil {
				change(in)
			}
		}
	}
	checkOfferBinding(t, []offerBindingCase{
		{name: "Agreement carrying the coverage and payout-template obligations", late: true},
		{name: "Agreement carrying the coverage obligation under another ID", late: true,
			change: renamed("obligation:coverage"), refusal: absent, agreementRule: true},
		{name: "Agreement carrying the payout-template obligation under another ID", late: true,
			change: renamed("obligation:payout"), refusal: absent, agreementRule: true},
		{name: "Agreement carrying the collateral obligation", late: true, change: collateralized(nil)},
		{name: "Agreement carrying the collateral obligation under another ID", late: true,
			change: collateralized(renamed("obligation:collateral")), refusal: absent, agreementRule: true},
	})
}

// TestNativeAgentAuthorizationProfileDigestIsItsDescriptors: the constant
// digest of the fixed native Agent authorization profile is the digest of its
// released descriptor, so the ProfileRef commits the descriptor's content.
func TestNativeAgentAuthorizationProfileDigestIsItsDescriptors(t *testing.T) {
	digest, err := Digest(NativeAgentAuthorizationProfileDescriptorDomain, NativeAgentAuthorizationProfileDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	if digest != NativeAgentAuthorizationProfileDigest {
		t.Fatalf("the native Agent authorization profile descriptor digests to %s, the constant is %s", digest,
			NativeAgentAuthorizationProfileDigest)
	}
	profile := NativeAgentAuthorizationProfileV1()
	if err := agentcommerce.ValidateProfileRefV1(profile); err != nil || profile.ProfileURI != NativeAgentAuthorizationProfileURI ||
		profile.ProfileVersion != 1 || profile.ProfileDigest != digest {
		t.Fatalf("the native Agent authorization ProfileRef %+v is not the descriptor's (%v)", profile, err)
	}
}

// TestSignedHistoryQuoteRequestIsAuthorizedUnderTheNativeAgentProfile: a quote
// request is authorized under the fixed native Agent authorization profile,
// compared by URI, version and digest. Every verifier of a firm offer refuses
// an offer whose embedded request is validly signed by the requester under
// any other profile, and so does the quote request verifier itself.
func TestSignedHistoryQuoteRequestIsAuthorizedUnderTheNativeAgentProfile(t *testing.T) {
	const refusal = "Guarantor quote request is not authorized under the native Agent authorization profile"
	native := NativeAgentAuthorizationProfileV1()
	under := func(profile ProfileRefV1) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) { in.requestProfile = &profile }
	}
	otherDigest, otherVersion := native, native
	otherDigest.ProfileDigest, otherVersion.ProfileVersion = testDigest("f"), 2
	cases := []offerBindingCase{
		{name: "request authorized under the native Agent profile", late: true},
		{name: "request authorized under another profile", late: true,
			change: under(testRef("d", "request-authority")), refusal: refusal},
		{name: "request authorized under the native profile URI with another digest", late: true,
			change: under(otherDigest), refusal: refusal},
		{name: "request authorized under the native profile URI at another version", late: true,
			change: under(otherVersion), refusal: refusal},
	}
	checkOfferBinding(t, cases)

	history := newSignedHistory(t)
	for _, test := range cases {
		signed := history.quoteToOffer(test.late, test.change)
		profile := signed.offer.ServiceProfileArtifact.Revisions[0].ServiceProfile
		err := VerifyQuoteRequest(signed.request, profile, signed.resolver, signed.underlying,
			agentcommerce.AgentSignatureEvidenceVerifier{Resolver: signed.keys}, signedHistoryTime(signedOfferIssuedAt))
		if test.refusal == "" && err != nil {
			t.Errorf("%s: the quote request verifier refused the request: %v", test.name, err)
		}
		if test.refusal != "" && (err == nil || !strings.Contains(err.Error(), test.refusal)) {
			t.Errorf("%s: the quote request verifier returned %v, want a refusal containing %q", test.name, err, test.refusal)
		}
	}
}

// eligibilityCase is one variation of the eligibility proofs frozen with an
// admission and the refusal it must meet; an empty refusal means acceptance.
type eligibilityCase struct {
	name    string
	change  func(*signedOfferEligibility)
	refusal string
}

// signedOfferEligibilityCases are the variations every admission that freezes
// eligibility proofs for the offer's parties must refuse: another input,
// object kind, body, scope or resolver profile, and a subject set that is not
// exactly the required one. prefix names the verifier's refusal.
func signedOfferEligibilityCases(prefix string) []eligibilityCase {
	const (
		substituted = "Guarantor authority eligibility proof is substituted"
		mismatch    = "Guarantor authority eligibility cut does not match the admission"
	)
	return []eligibilityCase{
		{name: "proofs for the required subjects, input, kind, body, scope and profile"},
		{name: "proofs for another input envelope",
			change:  func(proven *signedOfferEligibility) { proven.inputDigest = testDigest("f") },
			refusal: prefix + substituted},
		{name: "proofs for another object kind",
			change:  func(proven *signedOfferEligibility) { proven.kind = "firm-offer-issuance" },
			refusal: prefix + substituted},
		{name: "proofs binding another request body",
			change:  func(proven *signedOfferEligibility) { proven.bodyDigest = testDigest("f") },
			refusal: prefix + substituted},
		{name: "proofs requiring another scope",
			change:  func(proven *signedOfferEligibility) { proven.scopeDigest = testDigest("f") },
			refusal: prefix + substituted},
		{name: "proofs resolved under another profile",
			change:  func(proven *signedOfferEligibility) { proven.profile = testRef("f", "other-authority") },
			refusal: prefix + substituted},
		{name: "proofs omitting the beneficiary",
			change: func(proven *signedOfferEligibility) {
				proven.subjects = []string{signedHistoryClaimant, signedHistoryGuarantor}
			},
			refusal: prefix + mismatch},
		{name: "proofs naming another Agent in place of the beneficiary",
			change: func(proven *signedOfferEligibility) {
				proven.subjects = []string{"agent:other", signedHistoryClaimant, signedHistoryGuarantor}
			},
			refusal: prefix + substituted},
		{name: "proofs naming one Agent more than the required subjects",
			change:  func(proven *signedOfferEligibility) { proven.subjects = append(proven.subjects, "agent:other") },
			refusal: prefix + mismatch},
	}
}

// offerPhaseHistory is a signed history whose Writer Fence is valid from the
// offer's issuance and covers the acceptance action.
func offerPhaseHistory(t *testing.T) *signedHistory {
	t.Helper()
	history := newSignedHistory(t)
	bound, err := derivedAuxiliaryStageAuthorityV1(history.terms.StageActionAuthorityBinding, "coverage_acceptance",
		"coverage_activation")
	if err != nil {
		t.Fatal(err)
	}
	history.useOfferPhaseFence(bound.OperationActionKind)
	return history
}

func expectEligibility(t *testing.T, name, verifier string, err error, refusal string) {
	t.Helper()
	if refusal == "" && err != nil {
		t.Errorf("%s: %s refused: %v", name, verifier, err)
	}
	if refusal != "" && (err == nil || !strings.Contains(err.Error(), refusal)) {
		t.Errorf("%s: %s returned %v, want a refusal containing %q", name, verifier, err, refusal)
	}
}

// TestSignedHistoryAcceptanceReceiptEligibilityProofsBindTheAcceptance: the
// eligibility proofs of an acceptance receipt carry exactly one entry for the
// accepting subject and each authority subject of the coverage Agreement's
// predicates, with the acceptance request as input, coverage acceptance as
// kind, the receipt's exact request as body, the terms' coverage state domain
// as scope and their lifecycle authorization profile as resolver, in the
// offer's acceptance admission domain at the acceptance time. The receipt is
// otherwise complete and signed; the same refusal reaches the non-activation
// and activation verifiers, which stand on the receipt.
func TestSignedHistoryAcceptanceReceiptEligibilityProofsBindTheAcceptance(t *testing.T) {
	history := offerPhaseHistory(t)
	signed := history.quoteToOffer(true, nil)
	verifier := signedOfferAgreementVerifier{signed}
	const prefix = "Guarantor acceptance receipt eligibility proofs: "
	const earlier = "Guarantor acceptance admission authority or CAS proof is substituted"
	cases := append(signedOfferEligibilityCases(prefix),
		eligibilityCase{name: "proofs admitting another action",
			change: func(proven *signedOfferEligibility) { proven.actionDigest = testDigest("f") }, refusal: earlier},
		eligibilityCase{name: "proofs in another admission domain",
			change: func(proven *signedOfferEligibility) { proven.domainID = testDigest("f") }, refusal: earlier},
		eligibilityCase{name: "proofs frozen one second before the acceptance",
			change: func(proven *signedOfferEligibility) { proven.at-- }, refusal: earlier})
	for _, test := range cases {
		receipt := history.acceptanceReceiptWith(signed, test.change)
		at := signedHistoryTime(receipt.Body.AcceptedAtUnix)
		expectEligibility(t, test.name, "the acceptance receipt verifier", VerifyCoverageAcceptanceReceiptV1(receipt,
			signed.offer, verifier, signed.resolver, history.fenceResolver, at), test.refusal)
	}

	// One refused receipt, carried by the evidence of each later branch.
	const refusal = prefix + "Guarantor authority eligibility proof is substituted"
	receipt := history.acceptanceReceiptWith(signed, func(proven *signedOfferEligibility) { proven.scopeDigest = testDigest("f") })
	nonActivation := history.nonActivation(signed, receipt)
	expectEligibility(t, "receipt with proofs requiring another scope", "the non-activation verifier",
		VerifyCoverageNonActivationEvidenceV1(nonActivation, signed.offer, verifier, signed.resolver, history.fenceResolver,
			signedHistoryTime(nonActivation.Body.ResolvedAtUnix)), refusal)
	activation := history.offerActivation(signed, receipt)
	expectEligibility(t, "receipt with proofs requiring another scope", "the activation verifier",
		VerifyCoverageActivationEvidenceV1(activation, signed.offer, verifier, signed.resolver, history.fenceResolver, nil,
			signedHistoryTime(activation.Body.ActivatedAtUnix)), refusal)
}

// TestSignedHistoryNonActivationEligibilityProofsBindTheNonActivation: the
// eligibility proofs of non-activation evidence carry exactly one entry for
// each of the Guarantor, the covered party and the beneficiary, with the
// acceptance receipt as input, coverage non-activation as kind, the
// evidence's exact request as body, the terms' coverage state domain as scope
// and their lifecycle authorization profile as resolver, in the coverage
// Agreement's non-activation admission domain at the resolution time.
func TestSignedHistoryNonActivationEligibilityProofsBindTheNonActivation(t *testing.T) {
	history := offerPhaseHistory(t)
	signed := history.quoteToOffer(true, nil)
	verifier := signedOfferAgreementVerifier{signed}
	acceptance := history.acceptanceReceipt(signed)
	const prefix = "Guarantor non-activation evidence eligibility proofs: "
	const mismatch = prefix + "Guarantor authority eligibility cut does not match the admission"
	cases := append(signedOfferEligibilityCases(prefix),
		eligibilityCase{name: "proofs admitting another action",
			change:  func(proven *signedOfferEligibility) { proven.actionDigest = testDigest("f") },
			refusal: "non-activation action or authority proof is substituted"},
		eligibilityCase{name: "proofs in another admission domain",
			change: func(proven *signedOfferEligibility) { proven.domainID = testDigest("f") }, refusal: mismatch},
		eligibilityCase{name: "proofs frozen one second before the resolution",
			change: func(proven *signedOfferEligibility) { proven.at-- }, refusal: mismatch})
	for _, test := range cases {
		evidence := history.nonActivationWith(signed, acceptance, test.change)
		expectEligibility(t, test.name, "the non-activation verifier", VerifyCoverageNonActivationEvidenceV1(evidence,
			signed.offer, verifier, signed.resolver, history.fenceResolver, signedHistoryTime(evidence.Body.ResolvedAtUnix)),
			test.refusal)
	}

	// The release of the reservation stands on the non-activation evidence.
	const refusal = prefix + "Guarantor authority eligibility proof is substituted"
	evidence := history.nonActivationWith(signed, acceptance,
		func(proven *signedOfferEligibility) { proven.kind = "non-activation-evidence" })
	release := history.exposureRelease(signed, evidence)
	expectEligibility(t, "non-activation with proofs for another object kind", "the exposure release verifier",
		VerifyNonActivationExposureReleaseReceiptV1(release, signed.offer, verifier, signed.resolver, history.fenceResolver,
			signedHistoryTime(release.Body.ReleasedAtUnix)), refusal)
}

// TestSignedHistoryNonActivationDispositionEvidenceIsValidAndCommitted: an
// optional fee-resolution or collateral disposition evidence set that
// non-activation evidence carries is valid and committed by the signed body.
// Evidence signed by the Guarantor over an action that embeds a set failing
// validation, with no digest for it in the body, is refused by the verifier
// and has no envelope digest; it is not treated as carrying no set.
func TestSignedHistoryNonActivationDispositionEvidenceIsValidAndCommitted(t *testing.T) {
	history := offerPhaseHistory(t)
	signed := history.quoteToOffer(true, nil)
	verifier := signedOfferAgreementVerifier{signed}
	acceptance := history.acceptanceReceipt(signed)
	valid := CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1, Purpose: "coverage-non-activation-fee",
		ContextDigest: signed.offer.Body.CoverageAgreementBodyDigest,
		Items: []CanonicalGuarantorEvidenceItemV1{{ContentType: "text/plain", EvidenceProfileDigest: testDigest("1"),
			EvidenceEnvelopeDigest: testDigest("2"), Representation: "inline", CanonicalEnvelopeBytes: []byte("fee refunded")}}}
	validDigest, err := CanonicalGuarantorEvidenceSetDigestV1(valid)
	if err != nil {
		t.Fatalf("the valid disposition evidence set is invalid: %v", err)
	}
	const refusal = "Guarantor non-activation evidence carries an invalid or uncommitted disposition evidence set"
	invalid := CanonicalGuarantorEvidenceSetV1{}
	cases := []struct {
		name    string
		carried nonActivationDisposition
		refusal string
	}{
		{"no disposition evidence", nonActivationDisposition{}, ""},
		{"a valid fee set committed by the body", nonActivationDisposition{fee: &valid, feeDigest: validDigest}, ""},
		{"a valid collateral set committed by the body", nonActivationDisposition{collateral: &valid, collateralDigest: validDigest}, ""},
		{"an invalid fee set with no digest in the body", nonActivationDisposition{fee: &invalid}, refusal},
		{"an invalid collateral set with no digest in the body", nonActivationDisposition{collateral: &invalid}, refusal},
		{"a valid fee set the body does not commit", nonActivationDisposition{fee: &valid}, refusal},
		{"a valid collateral set the body commits under another digest",
			nonActivationDisposition{collateral: &valid, collateralDigest: testDigest("f")}, refusal},
	}
	for _, test := range cases {
		evidence := history.nonActivationCarrying(signed, acceptance, nil, test.carried)
		expectEligibility(t, test.name, "the non-activation verifier", VerifyCoverageNonActivationEvidenceV1(evidence,
			signed.offer, verifier, signed.resolver, history.fenceResolver, signedHistoryTime(evidence.Body.ResolvedAtUnix)),
			test.refusal)
		_, digestErr := CoverageNonActivationEvidenceDigestV1(evidence)
		expectEligibility(t, test.name, "the non-activation envelope digest", digestErr, test.refusal)
	}
}

// offerActivation is the Guarantor-signed activation evidence of the accepted
// coverage, activated one second after the acceptance: the underlying
// Agreement with its authorization evidence, the acceptance receipt, the
// scheduled end commitment and the coverage_activation stage action.
func (history *signedHistory) offerActivation(signed signedOffer,
	acceptance AuthorizedCoverageAcceptanceReceiptV1) AuthorizedCoverageActivationEvidenceV1 {
	return history.offerActivationBy(signed, acceptance, signedHistoryGuarantor, nil)
}

// offerActivationBy is offerActivation signed by signer, whose end commitment
// change varies before it enters the action and the body.
func (history *signedHistory) offerActivationBy(signed signedOffer, acceptance AuthorizedCoverageAcceptanceReceiptV1,
	signer string, change func(*CoverageEndCommitmentV1)) AuthorizedCoverageActivationEvidenceV1 {
	return history.offerActivationProving(signed, acceptance, signer, change, nil)
}

// offerActivationWith is offerActivation whose eligibility proofs proven
// varies before the evidence is signed. By default the proofs re-resolve the
// Guarantor, the covered party and the beneficiary.
func (history *signedHistory) offerActivationWith(signed signedOffer, acceptance AuthorizedCoverageAcceptanceReceiptV1,
	proven func(*signedOfferEligibility)) AuthorizedCoverageActivationEvidenceV1 {
	return history.offerActivationProving(signed, acceptance, signedHistoryGuarantor, nil, proven)
}

func (history *signedHistory) offerActivationProving(signed signedOffer, acceptance AuthorizedCoverageAcceptanceReceiptV1,
	signer string, change func(*CoverageEndCommitmentV1), proven func(*signedOfferEligibility)) AuthorizedCoverageActivationEvidenceV1 {
	t, offer, terms := history.t, signed.offer, signed.offer.CoverageTerms
	agreementDigest, obligationID := offer.Body.CoverageAgreementBodyDigest, offer.Body.CoverageObligationID
	underlying, held := signed.underlying[terms.UnderlyingAgreementBodyDigest]
	if !held {
		t.Fatal("the signed offer does not hold its underlying Agreement")
	}
	underlyingSet := GuarantorAgreementAuthorizationEvidenceSetV1{SchemaVersion: 1, AgreementID: underlying.Body.AgreementID,
		AgreementVersion: underlying.Body.Version, AgreementBodyDigest: terms.UnderlyingAgreementBodyDigest,
		Evidence: underlying.AuthorizationEvidence}
	underlyingSetDigest, err := AgreementAuthorizationEvidenceSetDigestV1(underlyingSet)
	if err != nil {
		t.Fatalf("signed-history underlying evidence set is invalid: %v", err)
	}
	commitment := CoverageEndCommitmentV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		CoverageObligationID: obligationID, CoverageStateDomainDigest: terms.CoverageStateDomainDigest,
		EndBranch: "scheduled", IncidentEligibilityEndsAtUnix: terms.CoverageEndsAtUnix}
	if change != nil {
		change(&commitment)
	}
	endDigest, err := CoverageEndCommitmentDigestV1(commitment)
	if err != nil {
		t.Fatal(err)
	}
	acceptanceDigest, err := CoverageAcceptanceReceiptDigestV1(acceptance)
	if err != nil {
		t.Fatal(err)
	}
	offerDigest, err := FirmOfferDigest(offer)
	if err != nil {
		t.Fatal(err)
	}
	projection, projectionDigest := signedOfferProjection(t, "coverage-activation", agreementDigest, obligationID, "active",
		"acceptance-receipt", acceptanceDigest)
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "coverage_activation")
	if err != nil {
		t.Fatal(err)
	}
	activatedAt := acceptance.Body.AcceptedAtUnix + 1
	if history.vary.activatedAt != 0 {
		activatedAt = history.vary.activatedAt
	}
	prerequisites, prerequisiteDigest := history.vary.activationPrerequisites, ""
	if prerequisites != nil {
		if prerequisiteDigest, err = CanonicalGuarantorEvidenceSetDigestV1(*prerequisites); err != nil {
			t.Fatalf("signed-history activation prerequisites are no canonical evidence set: %v", err)
		}
	}
	canonical, err := Canonical(CoverageActivationActionBodyV1{SchemaVersion: 1, UnderlyingAgreementBody: underlying.Body,
		UnderlyingAuthorizationEvidenceSet: underlyingSet, AuthorizedAcceptanceReceipt: acceptance,
		PrerequisiteEvidenceSet: prerequisites, TargetCoverageEndCommitment: commitment, TransitionEvidenceProjection: projection, ExpectedCoverageRevision: 1,
		TargetCoverageRevision: 2, ExpectedClaimFilingState: "not_open", TargetClaimFilingState: "open",
		ExpectedClaimFilingStateRevision: 1, TargetClaimFilingStateRevision: 2})
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]agentcommerce.SemanticValue{
		"owner_id": agentcommerce.ID(bound.ActionOwnerID), "agent_id": agentcommerce.ID(bound.ActionAgentID),
		"agreement_body_digest": agentcommerce.Digest32(agreementDigest), "obligation_id": agentcommerce.ID(obligationID),
		"expected_state_revision": agentcommerce.U64(1), "target_state": agentcommerce.State("active"),
		"evidence_set_digest": agentcommerce.Digest32(projectionDigest)}
	stage := history.stageFor(bound, "application/vnd.tos.service.agent-guarantor-coverage-activation-action.v1+cbor",
		canonical, fields, testDigest("1"), activatedAt+600, activatedAt, "", nil)
	actionDigest, err := agentcommerce.AuthorizedActionDigest(stage.AuthorizedAction)
	if err != nil {
		t.Fatal(err)
	}
	admissionDomain, err := ActivationAdmissionDomainIDV1(agreementDigest)
	if err != nil {
		t.Fatal(err)
	}
	frozen := signedOfferEligibility{actionDigest: actionDigest, inputDigest: acceptanceDigest,
		subjects: []string{offer.Body.BeneficiaryAgentID, signedHistoryClaimant, signedHistoryGuarantor}, kind: "coverage-activation",
		bodyDigest: stage.AuthorizedAction.ExactRequestDigest, scopeDigest: terms.CoverageStateDomainDigest,
		domainID: admissionDomain, profile: terms.LifecycleAuthorizationProfile, at: activatedAt}
	if proven != nil {
		proven(&frozen)
	}
	eligibility := history.eligibility(frozen.actionDigest, frozen.inputDigest, frozen.subjects, frozen.kind, frozen.bodyDigest,
		frozen.scopeDigest, frozen.profile, frozen.domainID, 1, frozen.at)
	eligibilityDigest, err := AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	if err != nil {
		t.Fatal(err)
	}
	body := CoverageActivationEvidenceBodyV1{SchemaVersion: 1, AuthorityID: bound.ActionAuthorityID,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: obligationID,
		CoverageStateDomainDigest:                terms.CoverageStateDomainDigest,
		AuthorizationEvidenceSetDigest:           acceptance.AuthorizedAcceptanceRequest.Body.CompleteAuthorizationEvidenceSetDigest,
		UnderlyingAgreementBodyDigest:            terms.UnderlyingAgreementBodyDigest,
		UnderlyingAuthorizationEvidenceSetDigest: underlyingSetDigest, AuthorizedFirmOfferEnvelopeDigest: offerDigest,
		AcceptanceReceiptDigest: acceptanceDigest, ExposureReceiptDigest: offer.Body.ExposureAdmissionReceiptDigest,
		PrerequisiteEvidenceSetDigest: prerequisiteDigest,
		SelectedAssuranceLevel:        terms.SelectedAssuranceLevel, SelectedClaimProfileDigest: terms.SelectedClaimProfileDigest,
		TransitionEvidenceProjectionDigest: projectionDigest, AuthorizedActionDigest: actionDigest,
		StableActionID: stage.AuthorizedAction.StableActionID, ExactRequestDigest: stage.AuthorizedAction.ExactRequestDigest,
		WriterGeneration: stage.AuthorizedAction.WriterGeneration, WriterFenceDigest: stage.AuthorizedAction.WriterFenceDigest,
		PriorCoverageRevision: 1, ActivatedCoverageRevision: 2, PriorClaimFilingState: "not_open",
		ActivatedClaimFilingState: "open", PriorClaimFilingStateRevision: 1, ActivatedClaimFilingStateRevision: 2,
		ResultingCoverageEndCommitmentDigest: endDigest, ActivatedAtUnix: activatedAt, CoverageEndsAtUnix: terms.CoverageEndsAtUnix,
		AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	bodyDigest, err := Digest("tos.service.agent-guarantor-activation-evidence-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	evidence := AuthorizedCoverageActivationEvidenceV1{Body: body, StageActionAdmissionEvidence: stage,
		UnderlyingAgreementBody: underlying.Body, AuthorizedAcceptanceReceipt: acceptance, CoverageEndCommitment: commitment,
		UnderlyingAuthorizationEvidenceSet: underlyingSet, PrerequisiteEvidenceSet: prerequisites,
		TransitionEvidenceProjection:          projection,
		AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObjectAs(signer, terms.LifecycleAuthorizationProfile,
			"activation-evidence", bodyDigest, "tos.service.agent-guarantor-activation-evidence-signature.v1", activatedAt)}}
	if _, err := CoverageActivationEvidenceDigestV1(evidence); err != nil {
		t.Fatalf("signed-history activation evidence is malformed: %v", err)
	}
	return evidence
}

// TestSignedHistoryActivationOnTheSignedOffer: on a signed firm offer, with
// and without a late contingency, the covered party's acceptance, the
// Guarantor's acceptance receipt and its activation evidence are built in
// full and the unreplaced activation verifier accepts the activation, with
// the Agreement evidence going through the intrinsic firm-offer verifier and
// the released Agent-signature verifier. Activation evidence built the same
// way on an offer that breaks a firm-offer rule is refused with that rule's
// refusal, as is activation evidence whose end commitment or signer is not
// the offer's.
func TestSignedHistoryActivationOnTheSignedOffer(t *testing.T) {
	history := offerPhaseHistory(t)
	verify := func(signed signedOffer, evidence AuthorizedCoverageActivationEvidenceV1) error {
		return VerifyCoverageActivationEvidenceV1(evidence, signed.offer, signedOfferAgreementVerifier{signed}, signed.resolver,
			history.fenceResolver, nil, signedHistoryTime(evidence.Body.ActivatedAtUnix))
	}
	for _, late := range []bool{true, false} {
		signed := history.quoteToOffer(late, nil)
		activation := history.offerActivation(signed, history.acceptanceReceipt(signed))
		if err := verify(signed, activation); err != nil {
			t.Errorf("activation on the signed offer (late contingency %t) was refused: %v", late, err)
		}
	}

	refused := []struct {
		name    string
		change  func(*signedOfferInputs)
		refusal string
	}{
		{"an unnamed payment of the covered party to the Guarantor",
			func(in *signedOfferInputs) {
				in.agreement = func(agreement *agentcommerce.AgentAgreementBody) {
					for _, obligation := range agreement.Obligations {
						if obligation.ObligationID == "obligation:premium" {
							added := obligation
							added.ObligationID, added.Kind = "obligation:unnamed", "payment"
							signedOfferAddObligation(agreement, added)
							return
						}
					}
				}
			},
			"coverage Agreement carries a value transfer from the covered party to the Guarantor that the Guarantor terms do not name as premium"},
		{"a quote request authorized under another profile",
			func(in *signedOfferInputs) {
				profile := testRef("d", "request-authority")
				in.requestProfile = &profile
			},
			"Guarantor quote request is not authorized under the native Agent authorization profile"},
		{"an Agreement expiring one second after the terms' final deadline",
			func(in *signedOfferInputs) { in.agreementExpiresAt++ }, signedOfferAnchorRefusal},
	}
	for _, test := range refused {
		signed := history.quoteToOffer(true, test.change)
		activation := history.offerActivation(signed, history.acceptanceReceipt(signed))
		if err := verify(signed, activation); err == nil || !strings.Contains(err.Error(), test.refusal) {
			t.Errorf("activation on an offer with %s: got %v, want a refusal containing %q", test.name, err, test.refusal)
		}
	}

	// Activation evidence on the valid offer that is not the offer's own:
	// an end commitment one second short of the terms' coverage end, and a
	// signer that is not the Guarantor. Each is signed over consistent
	// digests.
	signed := history.quoteToOffer(true, nil)
	acceptance := history.acceptanceReceipt(signed)
	shortened := history.offerActivationBy(signed, acceptance, signedHistoryGuarantor,
		func(commitment *CoverageEndCommitmentV1) { commitment.IncidentEligibilityEndsAtUnix-- })
	if err := verify(signed, shortened); err == nil || !strings.Contains(err.Error(), "coverage activation end commitment is substituted") {
		t.Errorf("activation with an end commitment one second before the coverage end: got %v, want an end-commitment refusal", err)
	}
	bySomeoneElse := history.offerActivationBy(signed, acceptance, signedHistoryClaimant, nil)
	if err := verify(signed, bySomeoneElse); err == nil ||
		!strings.Contains(err.Error(), `required Guarantor authority "agent:guarantor" is missing`) {
		t.Errorf("activation signed by the covered party: got %v, want the Guarantor's authorization to be missing", err)
	}

	// The same activation against another offer of the same Guarantor.
	other := history.quoteToOffer(true, func(in *signedOfferInputs) {
		in.requestBody = func(body *CoverageQuoteRequestBodyV1) { body.RequestID = "request:other" }
	})
	activation := history.offerActivation(signed, history.acceptanceReceipt(signed))
	if err := verify(other, activation); err == nil || !strings.Contains(err.Error(), "coverage activation evidence binding is invalid") {
		t.Errorf("activation verified against another offer: got %v, want a binding refusal", err)
	}
}

// TestContinuationBudgetWithinRequestedWindowsStaysWithinRequestedEntries:
// offered and requested closure capacities with the same continuation state
// keys have the same round counts, so their reserved slot counts are equal,
// and with every offered window no greater than the requested maximum every
// offered duration is no greater than the requested entry's. The comparison
// of the windows and of the state keys therefore already bounds the entries.
func TestContinuationBudgetWithinRequestedWindowsStaysWithinRequestedEntries(t *testing.T) {
	windows := [6]uint64{600, 500, 400, 300, 200, 100}
	for challenge := uint64(0); challenge <= 2; challenge++ {
		for nonterminal := uint64(0); nonterminal <= 2; nonterminal++ {
			requested, err := BuildClaimContinuationBudgetEntriesV1(challenge, nonterminal, windows[0], windows[1], windows[2],
				windows[3], windows[4], windows[5])
			if err != nil {
				t.Fatal(err)
			}
			for tightened := range windows {
				offeredWindows := windows
				offeredWindows[tightened]--
				offered, err := BuildClaimContinuationBudgetEntriesV1(challenge, nonterminal, offeredWindows[0], offeredWindows[1],
					offeredWindows[2], offeredWindows[3], offeredWindows[4], offeredWindows[5])
				if err != nil {
					t.Fatal(err)
				}
				if len(offered) != len(requested) {
					t.Fatalf("rounds %d/%d: %d offered entries, %d requested", challenge, nonterminal, len(offered), len(requested))
				}
				for index, entry := range offered {
					want := requested[index]
					if entry.ProfileStateKey != want.ProfileStateKey ||
						entry.RequiredReservedDecisionAdmissionSlots != want.RequiredReservedDecisionAdmissionSlots ||
						entry.RequiredReservedClaimStateTransitionSlots != want.RequiredReservedClaimStateTransitionSlots ||
						entry.MaximumRemainingDecisionPathSeconds > want.MaximumRemainingDecisionPathSeconds ||
						entry.MaximumRemainingClosureSeconds > want.MaximumRemainingClosureSeconds {
						t.Errorf("rounds %d/%d, window %d tightened: offered entry %+v exceeds requested %+v", challenge,
							nonterminal, tightened, entry, want)
					}
				}
			}
			// One more round changes the state keys, which the offer comparison refuses.
			more, err := BuildClaimContinuationBudgetEntriesV1(challenge+1, nonterminal, windows[0], windows[1], windows[2],
				windows[3], windows[4], windows[5])
			if err != nil {
				t.Fatal(err)
			}
			keys := func(entries []ClaimContinuationBudgetEntryV1) []string {
				return continuationStateKeysV1(ClaimClosureCapacityV1{ContinuationBudgetEntries: entries})
			}
			if equalStrings(keys(more), keys(requested)) {
				t.Errorf("rounds %d/%d: one more challenge round keeps the state keys", challenge, nonterminal)
			}
		}
	}
}
