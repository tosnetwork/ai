package agentguarantor

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// The rules that bind a firm offer's terms, body and exposure receipt to the
// quote request and service profile it embeds, each checked through the three
// verifiers a firm offer can reach a third party by: VerifyFirmOffer, the
// intrinsic firm-offer Agreement evidence verifier, and the acceptance
// request verifier. Every refused offer is signed over consistent digests and
// differs from an accepted one only in the named field.

// firmOfferEvidence is the Guarantor's firm-offer Agreement evidence carrying
// the offer, built without verifying it so that a refused offer can be
// carried too. For an accepted offer it equals what
// NewFirmOfferAgreementEvidenceV1 returns.
func (signed signedOffer) firmOfferEvidence(t *testing.T) agentcommerce.AgreementAuthorizationEvidence {
	t.Helper()
	agreementDigest, err := agentcommerce.AgreementBodyDigest(signed.agreement)
	if err != nil {
		t.Fatal(err)
	}
	offerDigest, err := FirmOfferDigest(signed.offer)
	if err != nil {
		t.Fatal(err)
	}
	profile := FirmOfferAgreementEvidenceProfileV1()
	var subject agentcommerce.AgreementAuthoritySubject
	var predicateIDs, targetDigests []string
	for _, predicate := range signed.agreement.AuthorizationPredicates {
		if predicate.EvidenceProfileURI == profile.ProfileURI {
			subject = predicate.AuthoritySubject
			predicateIDs = append(predicateIDs, predicate.PredicateID)
			targetDigests = append(targetDigests, predicate.EvidenceTargetProjectionDigest)
		}
	}
	canonical, err := Canonical(GuarantorFirmOfferAgreementEvidenceV1{SchemaVersion: 1, EvidenceProfile: profile,
		AgreementBodyDigest: agreementDigest, GuarantorAgentID: signed.offer.Body.GuarantorAgentID,
		SatisfiedPredicateTargets:         signed.offer.Body.GuarantorPredicateTargets,
		AuthorizedFirmOfferEnvelopeDigest: offerDigest, AuthorizedFirmOffer: signed.offer})
	if err != nil {
		t.Fatal(err)
	}
	return agentcommerce.AgreementAuthorizationEvidence{AgreementID: signed.agreement.AgreementID,
		AgreementVersion: signed.agreement.Version, AgreementBodyDigest: agreementDigest, AuthoritySubject: subject,
		PredicateIDs: predicateIDs, EvidenceProfileURI: profile.ProfileURI, EvidenceProfileVersion: uint32(profile.ProfileVersion),
		EvidenceProfileDigest: profile.ProfileDigest, EvidenceTargetProjectionDigests: targetDigests,
		EvidenceContentType: FirmOfferAgreementEvidenceContentType, Evidence: canonical}
}

// signedOfferAgreementVerifier is the Agreement evidence verifier of an
// acceptance: firm-offer evidence goes to the intrinsic verifier, every other
// evidence to the released Agent-signature verifier over the pinned keys.
type signedOfferAgreementVerifier struct{ signed signedOffer }

func (verifier signedOfferAgreementVerifier) VerifyAgreementEvidence(evidence agentcommerce.AgreementAuthorizationEvidence,
	at time.Time) error {
	agentSignatures := agentcommerce.AgentSignatureEvidenceVerifier{Resolver: verifier.signed.keys}
	if evidence.EvidenceProfileURI != FirmOfferAgreementEvidenceProfileURI {
		return agentSignatures.VerifyAgreementEvidence(evidence, at)
	}
	return VerifyFirmOfferAgreementEvidenceIntrinsicV1(evidence, verifier.signed.resolver, verifier.signed.keys,
		verifier.signed.underlying, agentSignatures, at)
}

// verifyIntrinsic runs the intrinsic firm-offer Agreement evidence verifier
// on the offer's evidence at the time the offer was issued.
func (signed signedOffer) verifyIntrinsic(t *testing.T) error {
	t.Helper()
	return VerifyFirmOfferAgreementEvidenceIntrinsicV1(signed.firmOfferEvidence(t), signed.resolver, signed.keys,
		signed.underlying, agentcommerce.AgentSignatureEvidenceVerifier{Resolver: signed.keys},
		signedHistoryTime(signedOfferIssuedAt))
}

// acceptanceRequest is the covered party's signed acceptance request of the
// offer: the coverage Agreement body, the complete authorization evidence set
// (the firm-offer evidence and each other party's signed acceptance of its
// predicates), submitted ten seconds after the offer was issued.
func (history *signedHistory) acceptanceRequest(signed signedOffer) AuthorizedCoverageAcceptanceRequestV1 {
	t, agreement := history.t, signed.agreement
	agreementDigest, err := agentcommerce.AgreementBodyDigest(agreement)
	if err != nil {
		t.Fatal(err)
	}
	offerDigest, err := FirmOfferDigest(signed.offer)
	if err != nil {
		t.Fatal(err)
	}
	evidence := []agentcommerce.AgreementAuthorizationEvidence{signed.firmOfferEvidence(t)}
	for _, predicate := range agreement.AuthorizationPredicates {
		if predicate.EvidenceProfileURI != agentcommerce.EvidenceProfileAgentSignature {
			continue
		}
		acceptance, err := agentcommerce.SignAgreementAcceptance(agentcommerce.AgreementAcceptanceBody{
			AgreementID: agreement.AgreementID, AgreementVersion: agreement.Version, AgreementBodyDigest: agreementDigest,
			AcceptingSubject: predicate.AuthoritySubject, PredicateIDs: []string{predicate.PredicateID},
			EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
			ExpiresAtUnix:                   agreement.ExpiresAtUnix}, signedOfferKey(predicate.AuthoritySubject.SubjectIdentifier))
		if err != nil {
			t.Fatal(err)
		}
		signedEvidence, err := agentcommerce.AgentSignatureEvidence(agreement, acceptance)
		if err != nil {
			t.Fatal(err)
		}
		evidence = append(evidence, signedEvidence)
	}
	sort.Slice(evidence, func(i, j int) bool {
		left, _ := Canonical(evidence[i])
		right, _ := Canonical(evidence[j])
		return string(left) < string(right)
	})
	set := GuarantorAgreementAuthorizationEvidenceSetV1{SchemaVersion: 1, AgreementID: agreement.AgreementID,
		AgreementVersion: agreement.Version, AgreementBodyDigest: agreementDigest, Evidence: evidence}
	setDigest, err := AgreementAuthorizationEvidenceSetDigestV1(set)
	if err != nil {
		t.Fatalf("signed-history Agreement evidence set is invalid: %v", err)
	}
	submission := ProfileRefV1{ProfileURI: agentcommerce.EvidenceProfileAgentSignature, ProfileVersion: 1,
		ProfileDigest: agentcommerce.AgentSignatureProfileDigest()}
	body := CoverageAcceptanceRequestBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreementDigest,
		AuthorizedFirmOfferEnvelopeDigest: offerDigest, CompleteAuthorizationEvidenceSetDigest: setDigest,
		AcceptingSubject: signedHistoryClaimant, SubmissionAuthorizationProfile: submission,
		CreatedAtUnix: signedOfferIssuedAt + 10, ExpiresAtUnix: signedOfferIssuedAt + 300}
	bodyDigest, err := Digest("tos.service.agent-guarantor-acceptance-request-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	request := AuthorizedCoverageAcceptanceRequestV1{Body: body, CoverageAgreementBody: agreement, AuthorizationEvidenceSet: set,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObjectAs(signedHistoryClaimant, submission,
			"coverage-acceptance-request", bodyDigest, "tos.service.agent-guarantor-acceptance-request-signature.v1",
			body.CreatedAtUnix)}}
	if _, err := CoverageAcceptanceRequestDigestV1(request); err != nil {
		t.Fatalf("signed-history acceptance request is malformed: %v", err)
	}
	return request
}

// verifyAcceptance runs the acceptance request verifier on the covered
// party's acceptance of the offer, at the time it was submitted. With
// permissive set, the Agreement evidence verifier accepts everything, so a
// refusal can only come from the acceptance verifier's own rules.
func (history *signedHistory) verifyAcceptance(signed signedOffer, permissive bool) error {
	request := history.acceptanceRequest(signed)
	var verifier agentcommerce.AgreementEvidenceVerifier = signedOfferAgreementVerifier{signed}
	if permissive {
		verifier = permissiveAgreementVerifier{}
	}
	return VerifyCoverageAcceptanceRequestV1(request, signed.offer, verifier, signed.resolver,
		signedHistoryTime(request.Body.CreatedAtUnix))
}

// offerBindingCase is one varied offer and the refusal it must meet from
// every verifier; an empty refusal means every verifier must accept it.
type offerBindingCase struct {
	name    string
	late    bool
	change  func(*signedOfferInputs)
	refusal string
	// agreementRule marks a refusal by a rule that needs the coverage
	// Agreement body. The intrinsic evidence verifier has only that body's
	// digest and accepts such an offer; the other two refuse it.
	agreementRule bool
}

// checkOfferBinding signs each case's offer and runs the three verifiers on
// it. Accepted cases are verified in full, with the acceptance's Agreement
// evidence going through the intrinsic verifier. Refused cases give the
// acceptance verifier a permissive Agreement evidence verifier, so the
// refusal is the acceptance verifier's own.
func checkOfferBinding(t *testing.T, cases []offerBindingCase) {
	t.Helper()
	history := newSignedHistory(t)
	expect := func(name, verifier string, err error, refusal string) {
		if refusal == "" && err != nil {
			t.Errorf("%s: %s refused the offer: %v", name, verifier, err)
		}
		if refusal != "" && (err == nil || !strings.Contains(err.Error(), refusal)) {
			t.Errorf("%s: %s returned %v, want a refusal containing %q", name, verifier, err, refusal)
		}
	}
	for _, test := range cases {
		signed := history.quoteToOffer(test.late, test.change)
		expect(test.name, "VerifyFirmOffer", signed.verify(), test.refusal)
		intrinsicRefusal := test.refusal
		if test.agreementRule {
			intrinsicRefusal = ""
		}
		expect(test.name, "the intrinsic evidence verifier", signed.verifyIntrinsic(t), intrinsicRefusal)
		expect(test.name, "the acceptance request verifier", history.verifyAcceptance(signed, test.refusal != ""), test.refusal)
	}
}

// signedOfferCollateralized makes the offered terms collateral-attested: the
// collateral is locked by the coverage start until the final deadline plus the
// reorg window, and the coverage Agreement expires when the lock ends.
func signedOfferCollateralized(in *signedOfferInputs) {
	in.collateralLockUntil = signedOfferFinalDeadline(in.terms) + signedOfferReorgWindow
	in.agreementExpiresAt = in.collateralLockUntil
}

// TestSignedHistoryCollateralIsLockedForTheCoverage: collateralized terms
// lock their collateral no later than the coverage starts and no longer than
// the coverage Agreement lasts. An offer whose collateral is due at the
// coverage start and locked until the Agreement expires is accepted by every
// verifier, and one whose lock ends a second after the Agreement expires is
// refused by the two verifiers that hold the Agreement body. Terms whose lock
// is due a second after the coverage starts are invalid terms: they have no
// digest, so no offer, receipt or proof can be made or verified over them.
func TestSignedHistoryCollateralIsLockedForTheCoverage(t *testing.T) {
	var cases []offerBindingCase
	for _, late := range []bool{true, false} {
		cases = append(cases,
			offerBindingCase{name: "collateral due at the coverage start and locked until the Agreement expires", late: late,
				change: signedOfferCollateralized},
			offerBindingCase{name: "collateral locked a second past the Agreement's expiry", late: late,
				change:  func(in *signedOfferInputs) { signedOfferCollateralized(in); in.agreementExpiresAt-- },
				refusal: "Guarantor collateral lock ends after the coverage Agreement expires", agreementRule: true})
	}
	checkOfferBinding(t, cases)

	const lockedLate = "collateral may be locked after the coverage starts"
	terms := newSignedHistory(t).quoteToOffer(true, signedOfferCollateralized).offer.CoverageTerms
	if terms.CollateralTerms.LockByUnix != terms.CoverageStartsAtUnix {
		t.Fatalf("the offered collateral is due at %d, want the coverage start %d", terms.CollateralTerms.LockByUnix, terms.CoverageStartsAtUnix)
	}
	if err := ValidateCoverageTerms(terms); err != nil {
		t.Errorf("terms whose collateral is due at the coverage start are refused: %v", err)
	}
	if _, err := CoverageTermsDigest(terms); err != nil {
		t.Errorf("terms whose collateral is due at the coverage start have no digest: %v", err)
	}
	late := terms
	collateral := *terms.CollateralTerms
	collateral.LockByUnix++
	late.CollateralTerms = &collateral
	refusedFor(t, "terms whose collateral is due a second after the coverage starts", ValidateCoverageTerms(late), lockedLate)
	_, err := CoverageTermsDigest(late)
	refusedFor(t, "the digest of terms whose collateral is due a second after the coverage starts", err, lockedLate)
}

// TestSignedHistoryOfferIsAcceptedByEveryVerifier: the unvaried signed firm
// offer, with and without a late contingency and with collateral, is accepted
// by VerifyFirmOffer, by the intrinsic evidence verifier and, with its
// complete Agreement authorization, by the acceptance request verifier. Every
// refusal in the tests below is measured against these.
func TestSignedHistoryOfferIsAcceptedByEveryVerifier(t *testing.T) {
	checkOfferBinding(t, []offerBindingCase{
		{name: "unsecured, late contingency", late: true},
		{name: "unsecured, no late contingency"},
		{name: "collateral-attested, late contingency", late: true, change: signedOfferCollateralized},
		{name: "collateral-attested, no late contingency", change: signedOfferCollateralized},
	})
}

// TestSignedHistoryOfferedTermsRepeatTheQuoteRequestIdentities: the offered
// terms name the quote request, service profile, underlying Agreement,
// parties, claimants and covered obligations the request names, and carry
// version 1 with the coverage ID derived from the Guarantor and the request.
func TestSignedHistoryOfferedTermsRepeatTheQuoteRequestIdentities(t *testing.T) {
	terms := func(change func(*CoverageTermsV1)) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) { in.offeredTerms = change }
	}
	request := func(change func(*CoverageQuoteRequestBodyV1)) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) { in.requestBody = change }
	}
	checkOfferBinding(t, []offerBindingCase{
		{name: "terms repeating every identity of the request", late: true},
		{name: "terms naming another quote request digest", late: true,
			change:  terms(func(terms *CoverageTermsV1) { terms.QuoteRequestDigest = testDigest("f") }),
			refusal: "Guarantor terms name another quote request"},
		{name: "terms naming another service profile digest", late: true,
			change:  terms(func(terms *CoverageTermsV1) { terms.ServiceProfileDigest = testDigest("f") }),
			refusal: "Guarantor terms name another service profile than the quote request"},
		{name: "terms naming another underlying Agreement digest", late: true,
			change:  terms(func(terms *CoverageTermsV1) { terms.UnderlyingAgreementBodyDigest = testDigest("f") }),
			refusal: "Guarantor terms name another underlying Agreement than the quote request"},
		{name: "request naming another Guarantor than the terms", late: true,
			change:  request(func(body *CoverageQuoteRequestBodyV1) { body.GuarantorAgentID = "agent:other" }),
			refusal: "Guarantor terms name another Guarantor than the quote request"},
		{name: "terms naming another covered party", late: true,
			change:  terms(func(terms *CoverageTermsV1) { terms.CoveredPartyAgentID = "agent:other" }),
			refusal: "Guarantor terms name another covered party than the quote request"},
		{name: "request naming another beneficiary than the terms", late: true,
			change:  request(func(body *CoverageQuoteRequestBodyV1) { body.BeneficiaryAgentID = "agent:other" }),
			refusal: "Guarantor terms name another beneficiary than the quote request"},
		{name: "request naming one more claimant than the terms permit", late: true,
			change: request(func(body *CoverageQuoteRequestBodyV1) {
				body.ClaimantSubjects = []string{"agent:beneficiary", "agent:covered"}
			}),
			refusal: "Guarantor terms' permitted claimants differ from the quote request's claimant subjects"},
		{name: "request naming one more covered obligation than the terms", late: true,
			change: request(func(body *CoverageQuoteRequestBodyV1) {
				body.CoveredObligationIDs = []string{"obligation:exchange", "obligation:other"}
			}),
			refusal: "Guarantor terms' covered obligations differ from the quote request"},
		{name: "terms at coverage version 2 with a predecessor", late: true,
			change: terms(func(terms *CoverageTermsV1) {
				terms.CoverageVersion, terms.PredecessorTermsDigest = 2, testDigest("f")
			}),
			refusal: "Guarantor terms offered on a quote request are not coverage version 1"},
		{name: "terms with a coverage ID not derived from the request", late: true,
			change:  terms(func(terms *CoverageTermsV1) { terms.CoverageID = testDigest("f") }),
			refusal: "Guarantor terms' coverage ID is not derived from the Guarantor and the quote request"},
	})
}

// TestSignedHistoryOfferedTermsRepeatTheRequestedSelections: the offered
// terms repeat the requested category, benefit kind, asset, assurance level,
// claim, collateral and payout adapter profiles, trigger and evidence
// profiles, and the request's selected decision profile.
func TestSignedHistoryOfferedTermsRepeatTheRequestedSelections(t *testing.T) {
	requested := func(change func(*RequestedCoverageTermsV1)) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) { change(&in.requested) }
	}
	checkOfferBinding(t, []offerBindingCase{
		{name: "terms repeating every requested selection", late: true},
		{name: "request for another coverage category", late: true,
			change:  requested(func(requested *RequestedCoverageTermsV1) { requested.CoverageCategory = "other-category" }),
			refusal: "Guarantor terms' coverage category differs from the requested terms"},
		{name: "request for another benefit kind", late: true,
			change:  requested(func(requested *RequestedCoverageTermsV1) { requested.BenefitKind = BenefitIndemnity }),
			refusal: "Guarantor terms' benefit kind differs from the requested terms"},
		{name: "request in another coverage asset", late: true,
			change: requested(func(requested *RequestedCoverageTermsV1) {
				requested.CoverageAsset.AssetIdentifier = "asset:other"
				requested.RequestedAggregatePayout.Asset = requested.CoverageAsset
				requested.RequestedPerClaim.Asset = requested.CoverageAsset
			}),
			refusal: "Guarantor terms' coverage asset differs from the requested terms"},
		{name: "request for collateral-attested coverage answered unsecured", late: true,
			change: requested(func(requested *RequestedCoverageTermsV1) {
				requested.SelectedAssuranceLevel = AssuranceCollateralAttested
				requested.SelectedCollateralProfileDigest = testDigest("f")
			}),
			refusal: "Guarantor terms' assurance level differs from the requested terms"},
		{name: "request selecting another claim profile", late: true,
			change: requested(func(requested *RequestedCoverageTermsV1) {
				requested.SelectedClaimProfileDigest = testDigest("f")
			}),
			refusal: "Guarantor terms select another claim profile than the requested terms"},
		{name: "collateral-attested terms repeating the requested collateral profile", late: true,
			change: signedOfferCollateralized},
		{name: "request selecting another collateral profile", late: true,
			change: func(in *signedOfferInputs) {
				signedOfferCollateralized(in)
				in.requestedTerms = func(requested *RequestedCoverageTermsV1) {
					requested.SelectedCollateralProfileDigest = testDigest("f")
				}
			},
			refusal: "Guarantor terms select another collateral profile than the requested terms"},
		{name: "request selecting another payout adapter profile", late: true,
			change: requested(func(requested *RequestedCoverageTermsV1) {
				requested.SelectedPayoutAdapterProfile = testRef("f", "other-adapter")
			}),
			refusal: "Guarantor terms select another payout adapter profile than the requested terms"},
		{name: "request for another claim trigger profile", late: true,
			change: requested(func(requested *RequestedCoverageTermsV1) {
				requested.ClaimTriggerProfile = testRef("f", "other-trigger")
			}),
			refusal: "Guarantor terms' claim trigger profile differs from the requested terms"},
		{name: "request for another claim evidence profile", late: true,
			change: requested(func(requested *RequestedCoverageTermsV1) {
				requested.ClaimEvidenceProfile = testRef("f", "other-evidence")
			}),
			refusal: "Guarantor terms' claim evidence profile differs from the requested terms"},
		{name: "request selecting another decision profile", late: true,
			change: func(in *signedOfferInputs) {
				in.requestBody = func(body *CoverageQuoteRequestBodyV1) {
					body.SelectedDecisionProfile = testRef("f", "other-decision")
				}
			},
			refusal: "Guarantor terms' decision profile differs from the quote request's selected decision profile"},
	})
}

// TestSignedHistoryOfferedTermsRepeatTheRequestedAmountsAndPeriod: the
// offered terms carry exactly the requested aggregate and per-claim amounts
// and the requested coverage start, coverage end and claim filing end; one
// atomic unit or one second apart is refused.
func TestSignedHistoryOfferedTermsRepeatTheRequestedAmountsAndPeriod(t *testing.T) {
	requested := func(change func(*RequestedCoverageTermsV1)) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) { change(&in.requested) }
	}
	checkOfferBinding(t, []offerBindingCase{
		{name: "terms at the requested amounts and period", late: true},
		{name: "terms one unit under the requested aggregate payout", late: true,
			change: requested(func(requested *RequestedCoverageTermsV1) {
				requested.RequestedAggregatePayout.AmountAtomic = "1001"
			}),
			refusal: "Guarantor terms' maximum aggregate payout differs from the requested aggregate payout"},
		{name: "terms one unit over the requested aggregate payout", late: true,
			change: requested(func(requested *RequestedCoverageTermsV1) {
				requested.RequestedAggregatePayout.AmountAtomic = "999"
			}),
			refusal: "Guarantor terms' maximum aggregate payout differs from the requested aggregate payout"},
		{name: "terms one unit under the requested per-claim amount", late: true,
			change: requested(func(requested *RequestedCoverageTermsV1) {
				requested.RequestedPerClaim.AmountAtomic = "501"
			}),
			refusal: "Guarantor terms' maximum per claim differs from the requested per-claim amount"},
		{name: "terms one unit over the requested per-claim amount", late: true,
			change: requested(func(requested *RequestedCoverageTermsV1) {
				requested.RequestedPerClaim.AmountAtomic = "499"
			}),
			refusal: "Guarantor terms' maximum per claim differs from the requested per-claim amount"},
		{name: "coverage starting one second after the requested start", late: true,
			change:  requested(func(requested *RequestedCoverageTermsV1) { requested.RequestedCoverageStartsAtUnix-- }),
			refusal: "Guarantor terms' coverage start differs from the requested coverage start"},
		{name: "coverage starting one second before the requested start", late: true,
			change:  requested(func(requested *RequestedCoverageTermsV1) { requested.RequestedCoverageStartsAtUnix++ }),
			refusal: "Guarantor terms' coverage start differs from the requested coverage start"},
		{name: "coverage ending one second before the requested end", late: true,
			change:  requested(func(requested *RequestedCoverageTermsV1) { requested.RequestedCoverageEndsAtUnix++ }),
			refusal: "Guarantor terms' coverage end differs from the requested coverage end"},
		{name: "coverage ending one second after the requested end", late: true,
			change:  requested(func(requested *RequestedCoverageTermsV1) { requested.RequestedCoverageEndsAtUnix-- }),
			refusal: "Guarantor terms' coverage end differs from the requested coverage end"},
		{name: "claim filing ending one second before the requested end", late: true,
			change:  requested(func(requested *RequestedCoverageTermsV1) { requested.RequestedClaimFilingEndsAtUnix++ }),
			refusal: "Guarantor terms' claim filing end differs from the requested claim filing end"},
		{name: "claim filing ending one second after the requested end", late: true,
			change:  requested(func(requested *RequestedCoverageTermsV1) { requested.RequestedClaimFilingEndsAtUnix-- }),
			refusal: "Guarantor terms' claim filing end differs from the requested claim filing end"},
	})
}

// signedOfferShortenedWindow lowers one requested per-claim window maximum by
// a second, so the offered terms' window is one second over it. The requested
// continuation budget is rebuilt for the lowered maxima, as a request's
// closure capacity must fit its own windows.
func signedOfferShortenedWindow(t *testing.T, window func(*RequestedCoverageTermsV1) *uint64) func(*signedOfferInputs) {
	return func(in *signedOfferInputs) {
		requested := &in.requested
		*window(requested)--
		capacity := &requested.RequestedClosureCapacity
		entries, err := BuildClaimContinuationBudgetEntriesV1(capacity.MaximumChallengeRoundsPerClaim,
			capacity.MaximumNonterminalRoundsPerClaim, requested.MaximumReviewDeadlineSeconds,
			requested.MaximumChallengeWindowSeconds, requested.MaximumNonterminalResolutionWindowSeconds,
			requested.MaximumSuccessorDecisionWindowSeconds, requested.MaximumPayoutDeadlineSeconds,
			requested.MaximumAdapterRecoveryWindowSeconds)
		if err != nil {
			t.Fatal(err)
		}
		capacity.ContinuationBudgetEntries = entries
	}
}

// TestSignedHistoryOfferedTermsStayWithinTheRequestedWindows: the offered
// terms' review deadline, challenge window, nonterminal resolution window,
// successor decision window, payout deadline, adapter recovery window and
// claim ingress resolution grace are accepted exactly at the request's maxima
// and refused one second over any one of them; so are the terminal and
// late-recovery deadline maxima.
func TestSignedHistoryOfferedTermsStayWithinTheRequestedWindows(t *testing.T) {
	requested := func(change func(*RequestedCoverageTermsV1)) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) { change(&in.requested) }
	}
	checkOfferBinding(t, []offerBindingCase{
		{name: "every window and deadline at the request's maximum", late: true},
		{name: "review deadline one second over the request's maximum", late: true,
			change: signedOfferShortenedWindow(t, func(requested *RequestedCoverageTermsV1) *uint64 {
				return &requested.MaximumReviewDeadlineSeconds
			}),
			refusal: "Guarantor terms' review deadline exceeds the requester's maximum"},
		{name: "challenge window one second over the request's maximum", late: true,
			change: signedOfferShortenedWindow(t, func(requested *RequestedCoverageTermsV1) *uint64 {
				return &requested.MaximumChallengeWindowSeconds
			}),
			refusal: "Guarantor terms' challenge window exceeds the requester's maximum"},
		{name: "nonterminal resolution window one second over the request's maximum", late: true,
			change: signedOfferShortenedWindow(t, func(requested *RequestedCoverageTermsV1) *uint64 {
				return &requested.MaximumNonterminalResolutionWindowSeconds
			}),
			refusal: "Guarantor terms' nonterminal resolution window exceeds the requester's maximum"},
		{name: "successor decision window one second over the request's maximum", late: true,
			change: signedOfferShortenedWindow(t, func(requested *RequestedCoverageTermsV1) *uint64 {
				return &requested.MaximumSuccessorDecisionWindowSeconds
			}),
			refusal: "Guarantor terms' successor decision window exceeds the requester's maximum"},
		{name: "payout deadline one second over the request's maximum", late: true,
			change: signedOfferShortenedWindow(t, func(requested *RequestedCoverageTermsV1) *uint64 {
				return &requested.MaximumPayoutDeadlineSeconds
			}),
			refusal: "Guarantor terms' payout deadline exceeds the requester's maximum"},
		{name: "adapter recovery window one second over the request's maximum", late: true,
			change: signedOfferShortenedWindow(t, func(requested *RequestedCoverageTermsV1) *uint64 {
				return &requested.MaximumAdapterRecoveryWindowSeconds
			}),
			refusal: "Guarantor terms' adapter recovery window exceeds the requester's maximum"},
		{name: "claim ingress resolution grace one second over the request's maximum", late: true,
			change:  requested(func(requested *RequestedCoverageTermsV1) { requested.MaximumClaimIngressResolutionGraceSeconds-- }),
			refusal: "Guarantor terms' claim ingress resolution grace exceeds the requester's maximum"},
		{name: "terminal resolution deadline one second over the request's maximum", late: true,
			change:  requested(func(requested *RequestedCoverageTermsV1) { requested.MaximumTerminalResolutionDeadlineUnix-- }),
			refusal: signedOfferTerminalRefusal},
		{name: "late-recovery terminal deadline one second over the request's maximum", late: true,
			change:  requested(func(requested *RequestedCoverageTermsV1) { requested.MaximumLateRecoveryTerminalDeadlineUnix-- }),
			refusal: signedOfferLateRefusal},
		{name: "late-ingress window one second over the request's maximum", late: true,
			change:  requested(func(requested *RequestedCoverageTermsV1) { requested.MaximumLateIngressRecoveryWindowSeconds-- }),
			refusal: signedOfferLateRefusal},
	})
}

// TestSignedHistoryOfferFinalDeadlineAnchorHoldsAtAcceptance: an offer whose
// terms' final deadline is one second off the coverage Agreement's expiry is
// refused by VerifyFirmOffer and by the acceptance request verifier, which
// hold the Agreement body. The intrinsic evidence verifier holds only the
// body's digest and cannot apply the rule.
func TestSignedHistoryOfferFinalDeadlineAnchorHoldsAtAcceptance(t *testing.T) {
	var cases []offerBindingCase
	for _, late := range []bool{true, false} {
		cases = append(cases,
			offerBindingCase{name: "Agreement expiring at the final deadline", late: late},
			offerBindingCase{name: "Agreement expiring one second after the final deadline", late: late,
				change:  func(in *signedOfferInputs) { in.agreementExpiresAt++ },
				refusal: signedOfferAnchorRefusal, agreementRule: true},
			offerBindingCase{name: "Agreement expiring one second before the final deadline", late: late,
				change:  func(in *signedOfferInputs) { in.agreementExpiresAt-- },
				refusal: signedOfferAnchorRefusal, agreementRule: true})
	}
	checkOfferBinding(t, cases)
}

// TestSignedHistoryQuoteRequestNamesTheOfferedPublication: the quote request
// names the service profile the offer embeds and the service intent operation
// that published it, and the offer body repeats the request's parties.
func TestSignedHistoryQuoteRequestNamesTheOfferedPublication(t *testing.T) {
	request := func(change func(*CoverageQuoteRequestBodyV1)) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) { in.requestBody = change }
	}
	checkOfferBinding(t, []offerBindingCase{
		{name: "request naming the embedded profile and its publication", late: true},
		{name: "request naming another service intent operation", late: true,
			change:  request(func(body *CoverageQuoteRequestBodyV1) { body.ServiceIntentDigest = testDigest("f") }),
			refusal: "Guarantor quote request names another service intent than the firm offer's selected publication"},
		{name: "request naming another service profile", late: true,
			change:  request(func(body *CoverageQuoteRequestBodyV1) { body.ServiceProfileDigest = testDigest("f") }),
			refusal: "Guarantor quote request names another service profile than the firm offer embeds"},
		{name: "offer body naming another beneficiary than the request", late: true,
			change: func(in *signedOfferInputs) {
				in.offerBody = func(body *FirmCoverageOfferBodyV1) { body.BeneficiaryAgentID = "agent:other" }
			},
			refusal: "firm Guarantor offer binding is invalid"},
	})
}

// TestSignedHistoryOfferExposureReceiptIsTheProfilesAdmission: the exposure
// receipt in a firm offer names the service profile's exposure authority, is
// authorized under its exposure authorization profile as the offer is, was
// admitted at the offer's valid-from time, reserves the terms' maximum
// aggregate payout, and its eligibility proofs bind the receipt's action,
// admission time and exact request, the quote request as input, firm-offer
// issuance as kind, the exposure authorization profile as resolver, and
// exactly the request's parties as subjects.
func TestSignedHistoryOfferExposureReceiptIsTheProfilesAdmission(t *testing.T) {
	other := testRef("f", "other-authority")
	proofs := func(change func(*signedOfferEligibility)) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) { in.eligibility = change }
	}
	checkOfferBinding(t, []offerBindingCase{
		{name: "receipt admitted by the profile's exposure authority", late: true},
		{name: "receipt naming another authority", late: true,
			change: func(in *signedOfferInputs) {
				in.receiptBody = func(body *ProviderExposureAdmissionReceiptBodyV1) { body.AuthorityID = "authority:other" }
			},
			refusal: "exposure receipt names another authority than the service profile's exposure authority"},
		{name: "receipt authorized under another profile", late: true,
			change:  func(in *signedOfferInputs) { in.receiptProfile = &other },
			refusal: "exposure receipt is not authorized under the service profile's exposure authorization profile"},
		{name: "offer authorized under another profile", late: true,
			change:  func(in *signedOfferInputs) { in.offerProfile = &other },
			refusal: "firm Guarantor offer is not authorized under the service profile's exposure authorization profile"},
		{name: "receipt admitted one second before the offer's valid-from time", late: true,
			change:  func(in *signedOfferInputs) { in.admittedAt-- },
			refusal: "exposure was not admitted at the offer's valid-from time"},
		{name: "receipt admitted one second after the offer's valid-from time", late: true,
			change:  func(in *signedOfferInputs) { in.admittedAt++ },
			refusal: "exposure was not admitted at the offer's valid-from time"},
		{name: "receipt reserving one unit under the maximum aggregate payout", late: true,
			change:  func(in *signedOfferInputs) { in.reserved.AmountAtomic = "999" },
			refusal: "exposure receipt is not bound to the offer"},
		{name: "eligibility proofs admitting another action", late: true,
			change:  proofs(func(bound *signedOfferEligibility) { bound.actionDigest = testDigest("f") }),
			refusal: "exposure eligibility proofs admit another action than the receipt's"},
		{name: "eligibility proofs frozen one second before the admission", late: true,
			change:  proofs(func(bound *signedOfferEligibility) { bound.at-- }),
			refusal: "exposure eligibility proofs are not frozen at the receipt's admission time"},
		{name: "eligibility proofs for another input envelope", late: true,
			change:  proofs(func(bound *signedOfferEligibility) { bound.inputDigest = testDigest("f") }),
			refusal: "exposure eligibility proof admits another input than the quote request"},
		{name: "eligibility proofs for another object kind", late: true,
			change:  proofs(func(bound *signedOfferEligibility) { bound.kind = "coverage-acceptance-request" }),
			refusal: "exposure eligibility proof is not for firm-offer issuance"},
		{name: "eligibility proofs binding another request body", late: true,
			change:  proofs(func(bound *signedOfferEligibility) { bound.bodyDigest = testDigest("f") }),
			refusal: "exposure eligibility proof binds another request than the receipt's exact request"},
		{name: "eligibility proofs resolved under another profile", late: true,
			change:  proofs(func(bound *signedOfferEligibility) { bound.profile = other }),
			refusal: "exposure eligibility proof was resolved under another profile than the exposure authorization profile"},
		{name: "eligibility proofs omitting the beneficiary", late: true,
			change:  proofs(func(bound *signedOfferEligibility) { bound.subjects = []string{signedHistoryClaimant} }),
			refusal: "exposure eligibility proofs omit a party of the quote request"},
		{name: "eligibility proofs naming an Agent outside the request", late: true,
			change:  proofs(func(bound *signedOfferEligibility) { bound.subjects = append(bound.subjects, "agent:other") }),
			refusal: "exposure eligibility proofs name a subject outside the quote request's parties"},
	})
}

// TestSignedHistoryFirmOfferIsVerifiedAgainstItsOwnParts: VerifyFirmOffer
// refuses a caller's quote request or coverage Agreement that is not the one
// the offer embeds or commits, and an offer outside its acceptance window;
// every verifier refuses an offer whose service profile artifact carries no
// revision, which no signature of the offer covers.
func TestSignedHistoryFirmOfferIsVerifiedAgainstItsOwnParts(t *testing.T) {
	history := newSignedHistory(t)
	signed := history.quoteToOffer(true, nil)
	other := history.quoteToOffer(true, func(in *signedOfferInputs) {
		in.agreementExpiresAt++
		in.requestBody = func(body *CoverageQuoteRequestBodyV1) { body.RequestID = "request:other" }
	})
	expect := func(name string, err error, refusal string) {
		if refusal == "" && err != nil {
			t.Errorf("%s: the offer was refused: %v", name, err)
		}
		if refusal != "" && (err == nil || !strings.Contains(err.Error(), refusal)) {
			t.Errorf("%s: got %v, want a refusal containing %q", name, err, refusal)
		}
	}
	expect("the offer with its own request and Agreement", signed.verify(), "")
	varied := signed
	varied.request = other.request
	expect("a caller's request that the offer does not embed", varied.verify(), "firm Guarantor offer embeds another quote request")
	varied = signed
	varied.agreement = other.agreement
	expect("a caller's Agreement that the offer does not commit", varied.verify(),
		"firm Guarantor offer commits another coverage Agreement body")

	at := func(unix uint64) error {
		return VerifyFirmOffer(signed.offer, signed.request, signed.agreement, signed.resolver, signed.keys, signed.underlying,
			agentcommerce.AgentSignatureEvidenceVerifier{Resolver: signed.keys}, signedHistoryTime(unix))
	}
	const window = "firm Guarantor offer is outside its acceptance window"
	expect("verified at the offer's valid-from time", at(signed.offer.Body.ValidFromUnix), "")
	expect("verified one second before the accept-by time", at(signed.offer.Body.AcceptByUnix-1), "")
	expect("verified one second before the valid-from time", at(signed.offer.Body.ValidFromUnix-1), window)
	expect("verified at the accept-by time", at(signed.offer.Body.AcceptByUnix), window)

	const revisions = "firm Guarantor offer carries no service profile revision"
	varied = signed
	varied.offer.ServiceProfileArtifact.Revisions = nil
	expect("no profile revision, VerifyFirmOffer", varied.verify(), revisions)
	expect("no profile revision, the intrinsic evidence verifier", varied.verifyIntrinsic(t), revisions)
	expect("no profile revision, the acceptance request verifier", history.verifyAcceptance(varied, true), revisions)
}

// TestSignedHistoryAcceptanceReceiptCarriesTheOfferRefusal: an acceptance
// receipt over an acceptance of an offer whose terms' final deadline is off
// the Agreement's expiry is refused with that rule's refusal, so the rule
// reaches every verifier that stands on an acceptance receipt. The receipt is
// well-formed and otherwise unverified: its stage admission evidence states
// nothing but the acceptance time, which the verifier reads to judge the
// request at, and the refusal comes before any of its own evidence is opened.
func TestSignedHistoryAcceptanceReceiptCarriesTheOfferRefusal(t *testing.T) {
	history := newSignedHistory(t)
	signed := history.quoteToOffer(true, func(in *signedOfferInputs) { in.agreementExpiresAt++ })
	request := history.acceptanceRequest(signed)
	requestDigest, err := CoverageAcceptanceRequestDigestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	acceptedAt := request.Body.CreatedAtUnix + 1
	eligibility := history.eligibility(testDigest("1"), requestDigest, []string{signedHistoryClaimant},
		"coverage-acceptance-request", testDigest("2"), testDigest("3"), signed.offer.CoverageTerms.LifecycleAuthorizationProfile,
		testDigest("4"), 1, acceptedAt)
	eligibilityDigest, err := AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	if err != nil {
		t.Fatal(err)
	}
	receipt := AuthorizedCoverageAcceptanceReceiptV1{Body: CoverageAcceptanceReceiptBodyV1{SchemaVersion: 1,
		AuthorityID: "authority:guarantor", CoverageAgreementBodyDigest: request.Body.CoverageAgreementBodyDigest,
		AuthorizedFirmOfferEnvelopeDigest:         request.Body.AuthorizedFirmOfferEnvelopeDigest,
		AuthorizedAcceptanceRequestEnvelopeDigest: requestDigest,
		ExposureAdmissionReceiptDigest:            signed.offer.Body.ExposureAdmissionReceiptDigest,
		ReservationID:                             signed.offer.Body.ReservationID, TransitionEvidenceProjectionDigest: testDigest("5"),
		AuthorizedActionDigest: testDigest("1"), StableActionID: testDigest("6"), ExactRequestDigest: testDigest("2"),
		WriterGeneration: 1, WriterFenceDigest: testDigest("7"), PriorOfferStateRevision: 1, AcceptedOfferStateRevision: 2,
		AcceptedCoverageRevision: 1, PriorClaimFilingState: "uninitialized", AcceptedClaimFilingState: "not_open",
		AcceptedClaimFilingStateRevision: 1, ReceivedAtUnix: acceptedAt, AcceptedAtUnix: acceptedAt,
		AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest},
		AuthorizedAcceptanceRequest: request, AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObject("coverage-acceptance-receipt", testDigest("8"),
			"tos.service.agent-guarantor-acceptance-receipt-signature.v1", acceptedAt)}}
	receipt.StageActionAdmissionEvidence.Body.AdmittedAtUnix = acceptedAt
	if _, err := CoverageAcceptanceReceiptDigestV1(receipt); err != nil {
		t.Fatalf("signed-history acceptance receipt is malformed: %v", err)
	}
	err = VerifyCoverageAcceptanceReceiptV1(receipt, signed.offer, permissiveAgreementVerifier{}, signed.resolver,
		history.fenceResolver, signedHistoryTime(acceptedAt))
	if err == nil || !strings.Contains(err.Error(), signedOfferAnchorRefusal) {
		t.Fatalf("the acceptance receipt verifier returned %v, want a refusal containing %q", err, signedOfferAnchorRefusal)
	}
}
