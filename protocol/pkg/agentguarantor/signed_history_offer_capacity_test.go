package agentguarantor

import (
	"sort"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// More firm-offer binding rules on signed history, each through the three
// verifiers of checkOfferBinding: the offered closure capacity and extensions
// against the request, the premium obligations against the maximum fee, the
// offer's schedule and grace, and the exposure eligibility proofs' scope,
// domain and one-proof-per-party rule.

// signedOfferRebuildRequestedBudget rebuilds the requested continuation
// budget for the request's own round counts and window maxima, as a request's
// closure capacity must fit its own windows.
func signedOfferRebuildRequestedBudget(t *testing.T, requested *RequestedCoverageTermsV1) {
	t.Helper()
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

// TestSignedHistoryOfferedClosureCapacityStaysWithinTheRequested: every count
// and byte ceiling of the offered claim closure capacity is accepted at or
// below the requested one and refused one over it; the terminal fallback is
// the requested one and the continuation states are the same.
//
// A request's capacity must stay valid, so a few cases move a second field
// with the named one: the computed worst-case bytes that must equal their
// ceiling, the terminal claim set ceiling that may not exceed the exposure
// release receipt ceiling, and the continuation budget of changed rounds. In
// each, the named field is the first one compared.
func TestSignedHistoryOfferedClosureCapacityStaysWithinTheRequested(t *testing.T) {
	requested := func(change func(*RequestedCoverageTermsV1)) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) { change(&in.requested) }
	}
	requestedCapacity := func(change func(*ClaimClosureCapacityV1)) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) { change(&in.requested.RequestedClosureCapacity) }
	}
	offeredCapacity := func(change func(*ClaimClosureCapacityV1)) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) {
			in.offeredTerms = func(terms *CoverageTermsV1) { change(&terms.ClaimClosureCapacity) }
		}
	}
	refusal := func(name string) string {
		return "Guarantor terms' closure capacity " + name + " exceeds the requested capacity"
	}
	otherFallback, err := NewDenyZeroTerminalFallbackV1(testRef("e", "fallback"), []string{"agent:guarantor"}, "all",
		map[string]string{"deny_zero": "other-deny", "no_eligible_benefit": "fallback-no-benefit",
			"aggregate_exhausted": "fallback-cap-exhausted", "aggregate_limited": "fallback-cap-limited", "full_benefit": "fallback-full"})
	if err != nil {
		t.Fatal(err)
	}
	checkOfferBinding(t, []offerBindingCase{
		{name: "capacity equal to the requested capacity", late: true},
		{name: "offered payout lines one under the requested", late: true,
			change: offeredCapacity(func(capacity *ClaimClosureCapacityV1) { capacity.MaximumPayoutLinesPerClaim-- })},
		{name: "offered cut proof bytes one under the requested", late: true,
			change: offeredCapacity(func(capacity *ClaimClosureCapacityV1) { capacity.MaximumClaimIngressCutProofBytes-- })},
		{name: "offered ingress actions one over the requested", late: true,
			change:  offeredCapacity(func(capacity *ClaimClosureCapacityV1) { capacity.MaximumClaimIngressActions++ }),
			refusal: refusal("maximum_claim_ingress_actions")},
		{name: "offered claims one over the requested", late: true,
			change: requested(func(requested *RequestedCoverageTermsV1) {
				requested.MaximumClaims--
				requested.RequestedClosureCapacity.MaximumClaims--
			}),
			refusal: refusal("maximum_claims")},
		{name: "offered revisions per claim one over the requested", late: true,
			change:  requestedCapacity(func(capacity *ClaimClosureCapacityV1) { capacity.MaximumClaimRevisionsPerClaim-- }),
			refusal: refusal("maximum_claim_revisions_per_claim")},
		{name: "offered decision admissions one over the requested", late: true,
			change:  offeredCapacity(func(capacity *ClaimClosureCapacityV1) { capacity.MaximumDecisionAdmissionsPerClaim++ }),
			refusal: refusal("maximum_decision_admissions_per_claim")},
		{name: "offered state transitions one over the requested", late: true,
			change:  offeredCapacity(func(capacity *ClaimClosureCapacityV1) { capacity.MaximumClaimStateTransitionsPerClaim++ }),
			refusal: refusal("maximum_claim_state_transitions_per_claim")},
		{name: "offered challenge rounds one over the requested", late: true,
			change: requested(func(requested *RequestedCoverageTermsV1) {
				requested.RequestedClosureCapacity.MaximumChallengeRoundsPerClaim--
				signedOfferRebuildRequestedBudget(t, requested)
			}),
			refusal: refusal("maximum_challenge_rounds_per_claim")},
		{name: "offered nonterminal rounds one over the requested", late: true,
			change: requested(func(requested *RequestedCoverageTermsV1) {
				requested.RequestedClosureCapacity.MaximumNonterminalRoundsPerClaim--
				signedOfferRebuildRequestedBudget(t, requested)
			}),
			refusal: refusal("maximum_nonterminal_rounds_per_claim")},
		{name: "offered payout lines one over the requested", late: true,
			change:  requestedCapacity(func(capacity *ClaimClosureCapacityV1) { capacity.MaximumPayoutLinesPerClaim-- }),
			refusal: refusal("maximum_payout_lines_per_claim")},
		{name: "offered admitted claim bytes one over the requested", late: true,
			change:  requestedCapacity(func(capacity *ClaimClosureCapacityV1) { capacity.MaximumAdmittedClaimEnvelopeBytes-- }),
			refusal: refusal("maximum_admitted_claim_envelope_bytes")},
		{name: "offered ingress receipt bytes one over the requested", late: true,
			change:  requestedCapacity(func(capacity *ClaimClosureCapacityV1) { capacity.MaximumClaimIngressReceiptEnvelopeBytes-- }),
			refusal: refusal("maximum_claim_ingress_receipt_envelope_bytes")},
		{name: "offered cut proof bytes one over the requested", late: true,
			change:  requestedCapacity(func(capacity *ClaimClosureCapacityV1) { capacity.MaximumClaimIngressCutProofBytes-- }),
			refusal: refusal("maximum_claim_ingress_cut_proof_bytes")},
		{name: "offered acceptance request bytes one over the requested", late: true,
			change: requestedCapacity(func(capacity *ClaimClosureCapacityV1) {
				capacity.MaximumAcceptanceRequestEnvelopeBytes--
				capacity.ComputedWorstCaseAcceptanceRequestEnvelopeBytes--
			}),
			refusal: refusal("maximum_acceptance_request_envelope_bytes")},
		{name: "offered acceptance receipt bytes one over the requested", late: true,
			change: requestedCapacity(func(capacity *ClaimClosureCapacityV1) {
				capacity.MaximumAcceptanceReceiptEnvelopeBytes--
				capacity.ComputedWorstCaseAcceptanceReceiptEnvelopeBytes--
			}),
			refusal: refusal("maximum_acceptance_receipt_envelope_bytes")},
		{name: "offered activation evidence bytes one over the requested", late: true,
			change: requestedCapacity(func(capacity *ClaimClosureCapacityV1) {
				capacity.MaximumActivationEvidenceEnvelopeBytes--
				capacity.ComputedWorstCaseActivationEvidenceEnvelopeBytes--
			}),
			refusal: refusal("maximum_activation_evidence_envelope_bytes")},
		{name: "offered non-activation evidence bytes one over the requested", late: true,
			change: requestedCapacity(func(capacity *ClaimClosureCapacityV1) {
				capacity.MaximumNonActivationEvidenceEnvelopeBytes--
				capacity.ComputedWorstCaseNonActivationEvidenceEnvelopeBytes--
			}),
			refusal: refusal("maximum_non_activation_evidence_envelope_bytes")},
		{name: "offered cancellation receipt bytes one over the requested", late: true,
			change: requestedCapacity(func(capacity *ClaimClosureCapacityV1) {
				capacity.MaximumCancellationReceiptEnvelopeBytes--
				capacity.ComputedWorstCaseCancellationReceiptEnvelopeBytes--
			}),
			refusal: refusal("maximum_cancellation_receipt_envelope_bytes")},
		{name: "offered filing close receipt bytes one over the requested", late: true,
			change: requestedCapacity(func(capacity *ClaimClosureCapacityV1) {
				capacity.MaximumClaimFilingCloseReceiptEnvelopeBytes--
				capacity.ComputedWorstCaseClaimFilingCloseReceiptEnvelopeBytes--
			}),
			refusal: refusal("maximum_claim_filing_close_receipt_envelope_bytes")},
		{name: "offered exposure release request bytes one over the requested", late: true,
			change: requestedCapacity(func(capacity *ClaimClosureCapacityV1) {
				capacity.MaximumExposureReleaseRequestBytes--
				capacity.ComputedWorstCaseExposureReleaseRequestBytes--
			}),
			refusal: refusal("maximum_exposure_release_request_bytes")},
		{name: "offered exposure release receipt bytes one over the requested", late: true,
			change: requestedCapacity(func(capacity *ClaimClosureCapacityV1) {
				capacity.MaximumExposureReleaseReceiptBytes--
				capacity.ComputedWorstCaseExposureReleaseReceiptBytes--
				capacity.MaximumTerminalClaimSetEnvelopeBytes--
				capacity.ComputedWorstCaseTerminalClaimSetBytes--
			}),
			refusal: refusal("maximum_exposure_release_receipt_bytes")},
		{name: "offered terminal claim set bytes one over the requested", late: true,
			change: requestedCapacity(func(capacity *ClaimClosureCapacityV1) {
				capacity.MaximumTerminalClaimSetEnvelopeBytes--
				capacity.ComputedWorstCaseTerminalClaimSetBytes--
			}),
			refusal: refusal("maximum_terminal_claim_set_envelope_bytes")},
		{name: "offered coverage resolution request bytes one over the requested", late: true,
			change: requestedCapacity(func(capacity *ClaimClosureCapacityV1) {
				capacity.MaximumCoverageResolutionRequestBytes--
				capacity.ComputedWorstCaseCoverageResolutionRequestBytes--
			}),
			refusal: refusal("maximum_coverage_resolution_request_bytes")},
		{name: "offered coverage resolution envelope bytes one over the requested", late: true,
			change: offeredCapacity(func(capacity *ClaimClosureCapacityV1) {
				capacity.MaximumCoverageResolutionEnvelopeBytes++
				capacity.ComputedWorstCaseCoverageResolutionEnvelopeBytes++
			}),
			refusal: refusal("maximum_coverage_resolution_envelope_bytes")},
		{name: "request for another terminal fallback", late: true,
			change:  requestedCapacity(func(capacity *ClaimClosureCapacityV1) { capacity.TerminalFallback = otherFallback }),
			refusal: "Guarantor terms' terminal fallback differs from the requested fallback"},
		{name: "request with one more challenge round, so other continuation states", late: true,
			change: requested(func(requested *RequestedCoverageTermsV1) {
				capacity := &requested.RequestedClosureCapacity
				capacity.MaximumChallengeRoundsPerClaim++
				capacity.MaximumDecisionAdmissionsPerClaim, capacity.MaximumClaimStateTransitionsPerClaim = 64, 128
				signedOfferRebuildRequestedBudget(t, requested)
			}),
			refusal: "Guarantor terms' continuation states differ from the requested capacity's"},
	})
}

// TestSignedHistoryOfferedExtensionsRepeatTheRequested: the offered terms
// carry exactly the requested required and optional extensions, and the
// offer body exactly the terms'.
func TestSignedHistoryOfferedExtensionsRepeatTheRequested(t *testing.T) {
	extension := []ProfileRefV1{testRef("f", "extension")}
	checkOfferBinding(t, []offerBindingCase{
		{name: "no extensions anywhere", late: true},
		{name: "one optional extension in the request, the terms and the offer", late: true,
			change: func(in *signedOfferInputs) {
				in.terms.OptionalExtensions, in.requested.OptionalExtensions = extension, extension
			}},
		{name: "request with a required extension the terms lack", late: true,
			change:  func(in *signedOfferInputs) { in.requested.RequiredExtensions = extension },
			refusal: "Guarantor terms' required extensions differ from the requested terms"},
		{name: "request with an optional extension the terms lack", late: true,
			change:  func(in *signedOfferInputs) { in.requested.OptionalExtensions = extension },
			refusal: "Guarantor terms' optional extensions differ from the requested terms"},
		{name: "offer body with a required extension its terms lack", late: true,
			change: func(in *signedOfferInputs) {
				in.offerBody = func(body *FirmCoverageOfferBodyV1) { body.RequiredExtensions = extension }
			},
			refusal: "firm Guarantor offer's required extensions differ from its terms"},
		{name: "offer body with an optional extension its terms lack", late: true,
			change: func(in *signedOfferInputs) {
				in.offerBody = func(body *FirmCoverageOfferBodyV1) { body.OptionalExtensions = extension }
			},
			refusal: "firm Guarantor offer's optional extensions differ from its terms"},
	})
}

// TestSignedHistoryCoveragePremiumStaysWithinTheMaximumFee: the premium
// obligations the terms name exist in the coverage Agreement, each with a
// fixed amount in the maximum fee's asset, owed by the covered party to the
// Guarantor, and their sum is accepted at the request's maximum fee of 100
// and refused one unit over it. The rule needs the Agreement body, so the
// intrinsic evidence verifier does not apply it.
func TestSignedHistoryCoveragePremiumStaysWithinTheMaximumFee(t *testing.T) {
	const premiumID, secondID = "obligation:premium", "obligation:premium-2"
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
	amount := func(value string) func(*agentcommerce.AgreementObligation) {
		return func(obligation *agentcommerce.AgreementObligation) {
			copied := *obligation.Amount
			copied.AmountAtomic = value
			obligation.Amount = &copied
		}
	}
	// installments splits the premium into two obligations of first and
	// second atomic units, both named by the terms.
	installments := func(first, second string) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) {
			in.terms.PremiumObligationIDs = []string{premiumID, secondID}
			in.agreement = func(agreement *agentcommerce.AgentAgreementBody) {
				for index := range agreement.Obligations {
					if agreement.Obligations[index].ObligationID == premiumID {
						amount(first)(&agreement.Obligations[index])
						extra := agreement.Obligations[index]
						extra.ObligationID = secondID
						amount(second)(&extra)
						agreement.Obligations = append(agreement.Obligations, extra)
						break
					}
				}
				for index := range agreement.AuthorizationPredicates {
					if agreement.AuthorizationPredicates[index].PredicateID == "predicate:covered" {
						agreement.AuthorizationPredicates[index].ObligationIDs = []string{premiumID, secondID}
					}
				}
			}
		}
	}
	checkOfferBinding(t, []offerBindingCase{
		{name: "premium at the maximum fee", late: true},
		{name: "premium one unit under the maximum fee", late: true, change: premium(amount("99"))},
		{name: "premium one unit over the maximum fee", late: true, change: premium(amount("101")),
			refusal: "total coverage fee exceeds the quote request's maximum fee", agreementRule: true},
		{name: "two installments summing to the maximum fee", late: true, change: installments("60", "40")},
		{name: "two installments summing to one unit over the maximum fee", late: true, change: installments("60", "41"),
			refusal: "total coverage fee exceeds the quote request's maximum fee", agreementRule: true},
		{name: "premium in another asset", late: true,
			change: premium(func(obligation *agentcommerce.AgreementObligation) {
				copied := *obligation.Amount
				copied.AssetIdentifier = "asset:other"
				obligation.Amount = &copied
			}),
			refusal: "coverage premium obligation is not in the maximum fee's asset", agreementRule: true},
		{name: "premium without an amount", late: true,
			change: premium(func(obligation *agentcommerce.AgreementObligation) {
				obligation.Amount, obligation.SettlementAdapterURI, obligation.SettlementParameters = nil, "", nil
			}),
			refusal: "coverage premium obligation has no fixed atomic amount", agreementRule: true},
		{name: "premium owed by the beneficiary", late: true,
			// An obligation needs its obligor's predicate, so the beneficiary's
			// predicate covers the premium here as well.
			change: func(in *signedOfferInputs) {
				in.agreement = func(agreement *agentcommerce.AgentAgreementBody) {
					for index := range agreement.Obligations {
						if agreement.Obligations[index].ObligationID == premiumID {
							agreement.Obligations[index].ObligorAgentID = "agent:beneficiary"
							agreement.Obligations[index].AuthorizationPredicateIDs = []string{"predicate:beneficiary", "predicate:covered"}
						}
					}
					for index := range agreement.AuthorizationPredicates {
						if agreement.AuthorizationPredicates[index].PredicateID == "predicate:beneficiary" {
							agreement.AuthorizationPredicates[index].ObligationIDs = []string{"obligation:payout", premiumID}
						}
					}
				}
			},
			refusal: "coverage premium obligation is not owed by the covered party", agreementRule: true},
		{name: "premium owed to the beneficiary", late: true,
			change: premium(func(obligation *agentcommerce.AgreementObligation) {
				obligation.BeneficiaryAgentID = "agent:beneficiary"
			}),
			refusal: "coverage premium obligation is not owed to the Guarantor", agreementRule: true},
		// The Agreement's own premium stays named: an Agreement fee the terms
		// omit is a different refusal.
		{name: "terms naming a premium obligation the Agreement lacks beside the one it carries", late: true,
			change: func(in *signedOfferInputs) {
				in.offeredTerms = func(terms *CoverageTermsV1) {
					terms.PremiumObligationIDs = []string{"obligation:absent", premiumID}
				}
			},
			refusal: "Guarantor terms name a premium obligation the coverage Agreement lacks", agreementRule: true},
	})
}

// TestSignedHistoryOfferFitsTheRequestSchedule: the quote request is created
// no later than the offer becomes valid, the reservation ends no later than
// the offer, the offer no later than the request, and the request no later
// than the coverage starts; each is accepted at equality and refused one
// second past it. The offer's grace equals its terms' and stays within the
// published maximum of 60 seconds.
func TestSignedHistoryOfferFitsTheRequestSchedule(t *testing.T) {
	request := func(change func(*CoverageQuoteRequestBodyV1)) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) { in.requestBody = change }
	}
	offer := func(change func(*FirmCoverageOfferBodyV1)) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) { in.offerBody = change }
	}
	checkOfferBinding(t, []offerBindingCase{
		// By default the reservation ends with the offer and the request
		// expires when the coverage starts.
		{name: "reservation ending with the offer, request expiring at the coverage start", late: true},
		{name: "request created at the offer's valid-from time", late: true,
			change: request(func(body *CoverageQuoteRequestBodyV1) { body.CreatedAtUnix = signedOfferIssuedAt })},
		{name: "request created one second after the offer's valid-from time", late: true,
			change:  request(func(body *CoverageQuoteRequestBodyV1) { body.CreatedAtUnix = signedOfferIssuedAt + 1 }),
			refusal: "firm Guarantor offer is valid before its quote request was created"},
		{name: "offer expiring one second before its reservation", late: true,
			change:  offer(func(body *FirmCoverageOfferBodyV1) { body.ExpiresAtUnix-- }),
			refusal: "firm Guarantor offer expires before its exposure reservation"},
		{name: "request expiring with the offer", late: true,
			change: request(func(body *CoverageQuoteRequestBodyV1) { body.ExpiresAtUnix = signedOfferIssuedAt + 360 })},
		{name: "request expiring one second before the offer", late: true,
			change:  request(func(body *CoverageQuoteRequestBodyV1) { body.ExpiresAtUnix = signedOfferIssuedAt + 359 }),
			refusal: "firm Guarantor offer expires after its quote request"},
		{name: "request expiring one second after the coverage starts", late: true,
			change:  request(func(body *CoverageQuoteRequestBodyV1) { body.ExpiresAtUnix = signedHistoryStart + 1 }),
			refusal: "Guarantor quote request expires after the offered coverage starts"},
		{name: "grace one second under the published maximum", late: true,
			change: func(in *signedOfferInputs) { in.terms.AcceptanceProcessingGraceSeconds-- }},
		{name: "grace one second over the published maximum", late: true,
			change:  func(in *signedOfferInputs) { in.terms.AcceptanceProcessingGraceSeconds++ },
			refusal: "firm Guarantor offer's acceptance processing grace exceeds the service profile's maximum"},
		{name: "offer grace one second under its terms' grace", late: true,
			change:  offer(func(body *FirmCoverageOfferBodyV1) { body.AcceptanceProcessingGraceSeconds-- }),
			refusal: "firm Guarantor offer's acceptance processing grace differs from its terms"},
	})
}

// TestSignedHistoryOfferEligibilityProofsAreOnePerPartyInTheOfferDomain: the
// exposure eligibility proofs require the service profile's authority domain
// as scope, are sequenced in the admission domain derived from the offer ID,
// and carry exactly one proof per party of the request: a second proof for
// the covered party, differing only in its finalized state revision, is
// refused.
func TestSignedHistoryOfferEligibilityProofsAreOnePerPartyInTheOfferDomain(t *testing.T) {
	proofs := func(change func(*signedOfferEligibility)) func(*signedOfferInputs) {
		return func(in *signedOfferInputs) { in.eligibility = change }
	}
	checkOfferBinding(t, []offerBindingCase{
		{name: "one proof per party in the offer's domain and the profile's scope", late: true},
		{name: "proofs requiring another scope", late: true,
			change:  proofs(func(bound *signedOfferEligibility) { bound.scopeDigest = testDigest("f") }),
			refusal: "exposure eligibility proof requires another scope than the service profile's authority domain"},
		{name: "proofs in another admission domain", late: true,
			change:  proofs(func(bound *signedOfferEligibility) { bound.domainID = testDigest("f") }),
			refusal: "exposure eligibility proofs are not in the offer's issuance admission domain"},
		{name: "a second proof for the covered party", late: true,
			change: func(in *signedOfferInputs) {
				in.eligibilitySet = func(set *AuthorityAdmissionEligibilityProofSetV1) {
					for _, proof := range set.Entries {
						if proof.AuthoritySubject == signedHistoryClaimant {
							proof.FinalizedAuthorityStateRevision++
							set.Entries = append(set.Entries, proof)
							break
						}
					}
					sort.Slice(set.Entries, func(i, j int) bool {
						left, _ := Canonical(set.Entries[i])
						right, _ := Canonical(set.Entries[j])
						return string(left) < string(right)
					})
				}
			},
			refusal: "exposure eligibility proofs carry more than one proof for a party"},
	})
}

// TestSignedHistoryOfferMayTightenAWindow: an offer whose review deadline is
// one second under the request's maximum is accepted by every verifier.
func TestSignedHistoryOfferMayTightenAWindow(t *testing.T) {
	checkOfferBinding(t, []offerBindingCase{
		{name: "review deadline one second under the request's maximum", late: true,
			change: func(in *signedOfferInputs) {
				in.requested.MaximumReviewDeadlineSeconds++
				signedOfferRebuildRequestedBudget(t, &in.requested)
			}},
		{name: "every window one second under the request's maximum", late: true,
			change: func(in *signedOfferInputs) {
				in.requested.MaximumReviewDeadlineSeconds++
				in.requested.MaximumChallengeWindowSeconds++
				in.requested.MaximumNonterminalResolutionWindowSeconds++
				in.requested.MaximumSuccessorDecisionWindowSeconds++
				in.requested.MaximumPayoutDeadlineSeconds++
				in.requested.MaximumAdapterRecoveryWindowSeconds++
				signedOfferRebuildRequestedBudget(t, &in.requested)
			}},
	})
}
