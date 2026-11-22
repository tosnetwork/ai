package agentguarantor

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// The end of a coverage on signed history: the release of the offer's
// exposure reservation against the terminal claim set, and the coverage
// resolution over that release.

// standInExposureReceipt is a Guarantor-signed exposure admission that
// reserves the maximum aggregate payout on the history's coverage, with the
// given default-liability disposition. It is well formed and signed, but it
// is not issued for a quote: the quote, the profile and the issuance action
// it names are placeholder digests, as the firm offer the claim history
// stands on is a stand-in.
func (history *signedHistory) standInExposureReceipt(disposition string) AuthorizedProviderExposureAdmissionReceiptV1 {
	t, terms := history.t, history.terms
	admittedAt, expiresAt := uint64(signedHistoryStart), uint64(signedHistoryStart+600)
	scope := ProviderExposureReservationScopeV1{SchemaVersion: 1, OwnerID: "owner:guarantor", GuarantorAgentID: signedHistoryGuarantor,
		CoverageAgreementBodyDigest: history.agreement, CoverageObligationID: history.obligation, CoverageAsset: terms.CoverageAsset,
		MaximumAggregatePayout: terms.MaximumAggregatePayout, SelectedAssuranceLevel: terms.SelectedAssuranceLevel,
		PolicyBucketDigest: testDigest("1"), CorrelationBucketDigest: testDigest("2"), DefaultLiabilityDisposition: disposition,
		ReservationExpiresAtUnix: expiresAt}
	scopeDigest, err := ExposureReservationScopeDigestV1(scope)
	if err != nil {
		t.Fatal(err)
	}
	termsDigest, err := CoverageTermsDigest(terms)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := ProviderExposureAdmissionDescriptorV1{SchemaVersion: 1, GuarantorAgentID: signedHistoryGuarantor,
		ServiceProfileDigest: testDigest("3"), QuoteRequestDigest: testDigest("4"), CoverageID: terms.CoverageID,
		CoverageVersion: terms.CoverageVersion, CoverageAgreementBodyDigest: history.agreement, CoverageTermsDigest: termsDigest,
		ReservationScope: scope, ReservationScopeDigest: scopeDigest, ReservedExposure: terms.MaximumAggregatePayout,
		CollateralCredit:   AtomicAmountV1{Asset: terms.CoverageAsset, AmountAtomic: "0"},
		PolicyBucketDigest: scope.PolicyBucketDigest, CorrelationBucketDigest: scope.CorrelationBucketDigest,
		BasePortfolioRevision: 1, ReservationExpiresAtUnix: expiresAt}
	descriptorDigest, err := ExposureAdmissionDescriptorDigestV1(descriptor)
	if err != nil {
		t.Fatalf("stand-in exposure descriptor is malformed: %v", err)
	}
	reservationID, err := ReservationIDV1(signedHistoryGuarantor, testDigest("5"), descriptorDigest)
	if err != nil {
		t.Fatal(err)
	}
	fenceDigest, err := agentcommerce.WriterFenceDigest(history.fence)
	if err != nil {
		t.Fatal(err)
	}
	eligibility := history.eligibility(testDigest("6"), testDigest("4"), []string{signedHistoryGuarantor}, "firm-offer-issuance",
		testDigest("7"), testDigest("8"), terms.LifecycleAuthorizationProfile, testDigest("9"), 1, admittedAt)
	eligibilityDigest, err := AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	if err != nil {
		t.Fatal(err)
	}
	body := ProviderExposureAdmissionReceiptBodyV1{SchemaVersion: 1, AuthorityID: "authority:guarantor",
		GuarantorAgentID: signedHistoryGuarantor, DescriptorDigest: descriptorDigest, AuthorizedActionDigest: testDigest("6"),
		ReservationID: reservationID, StableActionID: testDigest("a"), ExactRequestDigest: testDigest("7"), WriterGeneration: 1,
		WriterFenceDigest: fenceDigest, BasePortfolioRevision: 1, AdmittedPortfolioRevision: 2,
		ReservedExposure: terms.MaximumAggregatePayout, State: "reserved", AdmittedAtUnix: admittedAt, ExpiresAtUnix: expiresAt,
		AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	bodyDigest, err := Digest("tos.service.agent-guarantor-exposure-receipt-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	receipt := AuthorizedProviderExposureAdmissionReceiptV1{Body: body, Descriptor: descriptor,
		AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObject("exposure-admission-receipt", bodyDigest,
			"tos.service.agent-guarantor-exposure-receipt-signature.v1", admittedAt)}}
	if _, err := ExposureAdmissionReceiptDigestV1(receipt); err != nil {
		t.Fatalf("stand-in exposure receipt is malformed: %v", err)
	}
	return receipt
}

// releaseAfterClosure is the Guarantor-signed release, at, of the offer's
// whole reservation against set. It carries the exposure admission carried
// and derives the disposition from it, as the release authority does. change,
// when given, varies the receipt body before the release action and the
// receipt are signed.
func (history *signedHistory) releaseAfterClosure(set AuthorizedTerminalClaimSetEvidenceV1,
	carried AuthorizedProviderExposureAdmissionReceiptV1, at uint64,
	change func(*ExposureReleaseReceiptBodyV1)) AuthorizedExposureReleaseReceiptV1 {
	t, offer := history.t, history.offer
	bound, err := FindStageActionAuthorityV1(history.terms.StageActionAuthorityBinding, "post_acceptance_exposure_release")
	if err != nil {
		t.Fatal(err)
	}
	terminalDigest, err := TerminalClaimSetDigestV1(set)
	if err != nil {
		t.Fatalf("terminal claim set cannot be released against: %v", err)
	}
	exposureDigest, err := ExposureAdmissionReceiptDigestV1(carried)
	if err != nil {
		t.Fatal(err)
	}
	disposition, err := ComputeExposureDispositionV1(carried, set.Body)
	if err != nil {
		t.Fatal(err)
	}
	dispositionDigest, err := ExposureDispositionComputationDigestV1(disposition)
	if err != nil {
		t.Fatal(err)
	}
	reserved := offer.ExposureAdmissionReceipt.Body.ReservedExposure
	body := ExposureReleaseReceiptBodyV1{SchemaVersion: 1, AuthorityID: bound.ActionAuthorityID,
		GuarantorAgentID: offer.Body.GuarantorAgentID, CoverageAgreementBodyDigest: offer.Body.CoverageAgreementBodyDigest,
		CoverageObligationID: offer.Body.CoverageObligationID, ReservationID: offer.Body.ReservationID,
		ExposureAdmissionReceiptDigest: exposureDigest, TerminalClaimSetEvidenceDigest: terminalDigest,
		ExposureDispositionComputationDigest: dispositionDigest, BaseReleaseStateRevision: 2, ReleasedReleaseStateRevision: 3,
		ReleasedExposure: reserved, RemainingReservedExposure: AtomicAmountV1{Asset: reserved.Asset, AmountAtomic: "0"},
		PortfolioDisposition: disposition.PortfolioDisposition, ReturnedToAvailableExposure: disposition.ReturnedToAvailableExposure,
		RealizedLoss: disposition.RealizedLoss, RetainedDefaultedLiability: disposition.RetainedDefaultedLiability,
		State: "released", ReleasedAtUnix: at}
	if change != nil {
		change(&body)
	}
	canonical, err := Canonical(ExposureReleaseActionBodyV1{ReservationID: body.ReservationID,
		AgreementDigest: body.CoverageAgreementBodyDigest, TargetPortfolioRevision: body.ReleasedReleaseStateRevision,
		TerminalEvidenceSetDigest: terminalDigest})
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]agentcommerce.SemanticValue{
		"owner_id": agentcommerce.ID(bound.ActionOwnerID), "agent_id": agentcommerce.ID(bound.ActionAgentID),
		"reservation_id":               agentcommerce.Digest32(body.ReservationID),
		"target_revision":              agentcommerce.U64(body.ReleasedReleaseStateRevision),
		"terminal_evidence_set_digest": agentcommerce.Digest32(terminalDigest)}
	stage := history.stageFor(bound, "application/vnd.tos.service.agent-guarantor-exposure-release-action.v1+cbor",
		canonical, fields, testDigest("1"), at+600, at, "", nil)
	action := stage.AuthorizedAction
	if body.AuthorizedActionDigest, err = agentcommerce.AuthorizedActionDigest(action); err != nil {
		t.Fatal(err)
	}
	body.StableActionID, body.ExactRequestDigest = action.StableActionID, action.ExactRequestDigest
	body.WriterGeneration, body.WriterFenceDigest = action.WriterGeneration, action.WriterFenceDigest
	bodyDigest, err := Digest("tos.service.agent-guarantor-exposure-release-receipt-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	return AuthorizedExposureReleaseReceiptV1{Body: body, StageActionAdmissionEvidence: stage,
		AuthorizedExposureAdmissionReceipt: carried, AuthorizedTerminalClaimSetEvidence: set,
		ExposureDispositionComputation: disposition,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObject("exposure-release-receipt", bodyDigest,
			"tos.service.agent-guarantor-exposure-release-receipt-signature.v1", at)}}
}

// resolveAfterRelease is the Guarantor-signed coverage resolution, at, over
// release: it moves the coverage from the release-pending revision its
// terminal claim set produced to that set's target terminal state. change,
// when given, varies the body before the resolution action and the
// resolution are signed.
func (history *signedHistory) resolveAfterRelease(release AuthorizedExposureReleaseReceiptV1, at uint64,
	change func(*CoverageResolutionBodyV1)) AuthorizedCoverageResolutionV1 {
	t := history.t
	bound, err := FindStageActionAuthorityV1(history.terms.StageActionAuthorityBinding, "coverage_resolution")
	if err != nil {
		t.Fatal(err)
	}
	releaseDigest, err := ExposureReleaseReceiptDigestV1(release)
	if err != nil {
		t.Fatal(err)
	}
	terminal := release.AuthorizedTerminalClaimSetEvidence.Body
	body := CoverageResolutionBodyV1{SchemaVersion: 1, AuthorityID: bound.ActionAuthorityID,
		CoverageAgreementBodyDigest: release.Body.CoverageAgreementBodyDigest, CoverageObligationID: release.Body.CoverageObligationID,
		CoverageEndCommitmentDigest: terminal.CoverageEndCommitmentDigest, ActivationEvidenceDigest: terminal.ActivationEvidenceDigest,
		TerminalClaimSetEvidenceDigest: release.Body.TerminalClaimSetEvidenceDigest, ExposureReleaseReceiptDigest: releaseDigest,
		PriorCoverageRevision:    terminal.ReleasePendingCoverageRevision,
		ResolvedCoverageRevision: terminal.ReleasePendingCoverageRevision + 1,
		TerminalState:            terminal.ResolutionTargetTerminalState, ResolvedAtUnix: at}
	if change != nil {
		change(&body)
	}
	canonical, err := Canonical(CoverageResolutionActionBodyV1{SchemaVersion: 1, ExposureReleaseReceiptDigest: releaseDigest,
		ExpectedRevision: body.PriorCoverageRevision, TargetRevision: body.ResolvedCoverageRevision})
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]agentcommerce.SemanticValue{
		"owner_id": agentcommerce.ID(bound.ActionOwnerID), "agent_id": agentcommerce.ID(bound.ActionAgentID),
		"agreement_body_digest":   agentcommerce.Digest32(body.CoverageAgreementBodyDigest),
		"obligation_id":           agentcommerce.ID(body.CoverageObligationID),
		"expected_state_revision": agentcommerce.U64(body.PriorCoverageRevision),
		"target_state":            agentcommerce.State(body.TerminalState),
		"evidence_set_digest":     agentcommerce.Digest32(releaseDigest)}
	stage := history.stageFor(bound, "application/vnd.tos.service.agent-guarantor-coverage-resolution-action.v1+cbor",
		canonical, fields, testDigest("1"), at+600, at, "", nil)
	action := stage.AuthorizedAction
	if body.AuthorizedActionDigest, err = agentcommerce.AuthorizedActionDigest(action); err != nil {
		t.Fatal(err)
	}
	body.StableActionID, body.ExactRequestDigest = action.StableActionID, action.ExactRequestDigest
	body.WriterGeneration, body.WriterFenceDigest = action.WriterGeneration, action.WriterFenceDigest
	bodyDigest, err := Digest("tos.service.agent-guarantor-resolution-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	return AuthorizedCoverageResolutionV1{Body: body, StageActionAdmissionEvidence: stage,
		AuthorizedExposureReleaseReceipt: release,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObject("coverage-resolution", bodyDigest,
			"tos.service.agent-guarantor-resolution-signature.v1", at)}}
}

// verifyRelease is the exposure release verifier at at.
func (history *signedHistory) verifyRelease(release AuthorizedExposureReleaseReceiptV1, at uint64) error {
	return VerifyExposureReleaseReceiptV1(release, history.offer, permissiveAgreementVerifier{}, history.resolver,
		history.fenceResolver, signedHistoryNoPayments{}, time.Unix(int64(at), 0).UTC())
}

// verifyResolution is the coverage resolution verifier at at.
func (history *signedHistory) verifyResolution(resolution AuthorizedCoverageResolutionV1, at uint64) error {
	return VerifyCoverageResolutionV1(resolution, history.offer, permissiveAgreementVerifier{}, history.resolver,
		history.fenceResolver, signedHistoryNoPayments{}, time.Unix(int64(at), 0).UTC())
}

// refusedFor reports a verdict that is not a refusal carrying want.
func refusedFor(t *testing.T, name string, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%s: got %v, want a refusal containing %q", name, err, want)
	}
}

// TestSignedHistoryExposureReleaseIsOfTheOffersReservationAndClaimSet: after
// the late-path claim ends denied and the coverage closes, the release of the
// offer's reservation verifies in full. The same signed release is refused
// when it carries another exposure admission of the same Guarantor (one with
// another default-liability disposition, from which the disposition would be
// computed), names another obligation, or is released before the claim set
// allows.
func TestSignedHistoryExposureReleaseIsOfTheOffersReservationAndClaimSet(t *testing.T) {
	claim := newLateDeniedClaim(t, false, nil)
	history := claim.history
	bundle := history.terminalBundle(claim.claimID, claim.application, claim.closedAt)
	set := history.terminalSet(claim.filing, []ClaimTerminalResolutionBundleV1{bundle}, claim.closedAt)
	releasedAt := claim.closedAt + 10
	own := history.offer.ExposureAdmissionReceipt
	if err := history.verifyRelease(history.releaseAfterClosure(set, own, releasedAt, nil), releasedAt); err != nil {
		t.Fatalf("the signed exposure release does not verify: %v", err)
	}
	if err := history.verifyRelease(history.releaseAfterClosure(set, own, set.Body.ReleaseNotBeforeUnix, nil),
		releasedAt); err != nil {
		t.Fatalf("an exposure release exactly at the claim set's release time does not verify: %v", err)
	}
	refusedFor(t, "another exposure admission of the same Guarantor",
		history.verifyRelease(history.releaseAfterClosure(set, history.standInExposureReceipt("charge_off"), releasedAt, nil), releasedAt),
		"exposure release carries another exposure receipt than the firm offer's")
	refusedFor(t, "another obligation",
		history.verifyRelease(history.releaseAfterClosure(set, own, releasedAt, func(body *ExposureReleaseReceiptBodyV1) {
			body.CoverageObligationID = "obligation:other"
		}), releasedAt), "exposure release names another coverage than the firm offer's")
	refusedFor(t, "another Guarantor",
		history.verifyRelease(history.releaseAfterClosure(set, own, releasedAt, func(body *ExposureReleaseReceiptBodyV1) {
			body.GuarantorAgentID = "agent:other"
		}), releasedAt), "exposure release names another Guarantor than the firm offer's")
	refusedFor(t, "another authority",
		history.verifyRelease(history.releaseAfterClosure(set, own, releasedAt, func(body *ExposureReleaseReceiptBodyV1) {
			body.AuthorityID = "authority:other"
		}), releasedAt), "exposure release names another authority than the Agreement's release authority")
	refusedFor(t, "released a second before the claim set allows",
		history.verifyRelease(history.releaseAfterClosure(set, own, set.Body.ReleaseNotBeforeUnix-1, nil), releasedAt),
		"exposure release precedes the terminal claim set's release time")
	refusedFor(t, "remaining reserved exposure in another asset",
		history.verifyRelease(history.releaseAfterClosure(set, own, releasedAt, func(body *ExposureReleaseReceiptBodyV1) {
			body.RemainingReservedExposure.Asset.AssetIdentifier += "-other"
		}), releasedAt), "exposure release states its remaining reserved exposure in another asset than the reservation's")
	refusedFor(t, "one atomic unit left reserved",
		history.verifyRelease(history.releaseAfterClosure(set, own, releasedAt, func(body *ExposureReleaseReceiptBodyV1) {
			body.RemainingReservedExposure.AmountAtomic = "1"
		}), releasedAt), "exposure release leaves exposure reserved")
	// A release-state revision at the top of the range has no successor.
	refusedFor(t, "a released revision that wraps to zero",
		history.verifyRelease(history.releaseAfterClosure(set, own, releasedAt, func(body *ExposureReleaseReceiptBodyV1) {
			body.BaseReleaseStateRevision, body.ReleasedReleaseStateRevision = math.MaxUint64, 0
		}), releasedAt), "exposure release receipt binding is invalid")

	// A claim set created after the time it allows its release from: the
	// release is not before the set exists either.
	history.vary = signedHistoryVariation{closureBody: func(body *TerminalClaimSetBodyV1) { body.CreatedAtUnix += 50 }}
	createdLater := history.terminalSet(claim.filing, []ClaimTerminalResolutionBundleV1{bundle}, claim.closedAt)
	history.vary = signedHistoryVariation{}
	created := createdLater.Body.CreatedAtUnix
	if createdLater.Body.ReleaseNotBeforeUnix >= created {
		t.Fatalf("the set allows its release at %d, not before it was created at %d", createdLater.Body.ReleaseNotBeforeUnix, created)
	}
	if err := history.verifyRelease(history.releaseAfterClosure(createdLater, own, created, nil), created); err != nil {
		t.Errorf("an exposure release at the instant its claim set was created is refused: %v", err)
	}
	refusedFor(t, "released a second before its claim set was created",
		history.verifyRelease(history.releaseAfterClosure(createdLater, own, created-1, nil), created),
		"exposure release precedes the creation of its terminal claim set")

	// The offer's own exposure admission, carried byte for byte, whose only
	// authorization is the Guarantor's signature over another body: the
	// release reads the reservation from it, so it is verified, not only
	// compared.
	unsigned := own
	unsigned.Authorizations = []ProfileQualifiedObjectAuthorizationV1{history.signObject("exposure-admission-receipt",
		testDigest("7"), "tos.service.agent-guarantor-exposure-receipt-signature.v1", signedHistoryStart)}
	history.offer.ExposureAdmissionReceipt = unsigned
	refusedFor(t, "the offer's exposure admission authorized over another body",
		history.verifyRelease(history.releaseAfterClosure(set, unsigned, releasedAt, nil), releasedAt),
		"exposure release carries an exposure admission that does not verify")
	history.offer.ExposureAdmissionReceipt = own
}

// TestSignedHistoryCoverageResolutionFollowsItsReleaseAndClaimSet: the
// coverage resolution over the signed release verifies in full, and with it
// the whole closure chain down to the claim. The same signed resolution is
// refused when it names another obligation than its release, resolves another
// revision than the release-pending one the claim set produced, or is
// resolved before the release.
func TestSignedHistoryCoverageResolutionFollowsItsReleaseAndClaimSet(t *testing.T) {
	claim := newLateDeniedClaim(t, true, nil)
	history := claim.history
	bundle := history.terminalBundle(claim.claimID, claim.application, claim.closedAt)
	set := history.terminalSet(claim.filing, []ClaimTerminalResolutionBundleV1{bundle}, claim.closedAt)
	releasedAt := claim.closedAt + 10
	release := history.releaseAfterClosure(set, history.offer.ExposureAdmissionReceipt, releasedAt, nil)
	resolvedAt := releasedAt + 10
	if err := history.verifyResolution(history.resolveAfterRelease(release, resolvedAt, nil), resolvedAt); err != nil {
		t.Fatalf("the signed coverage resolution does not verify: %v", err)
	}
	if err := history.verifyResolution(history.resolveAfterRelease(release, releasedAt, nil), resolvedAt); err != nil {
		t.Fatalf("a coverage resolution at the release time does not verify: %v", err)
	}
	refusedFor(t, "another obligation",
		history.verifyResolution(history.resolveAfterRelease(release, resolvedAt, func(body *CoverageResolutionBodyV1) {
			body.CoverageObligationID = "obligation:other"
		}), resolvedAt), "coverage resolution names another coverage than its exposure release")
	refusedFor(t, "another authority",
		history.verifyResolution(history.resolveAfterRelease(release, resolvedAt, func(body *CoverageResolutionBodyV1) {
			body.AuthorityID = "authority:other"
		}), resolvedAt), "coverage resolution names another authority than the Agreement's resolution authority")
	refusedFor(t, "another prior revision",
		history.verifyResolution(history.resolveAfterRelease(release, resolvedAt, func(body *CoverageResolutionBodyV1) {
			body.PriorCoverageRevision++
			body.ResolvedCoverageRevision++
		}), resolvedAt), "coverage resolution does not follow the terminal claim set's release-pending revision")
	refusedFor(t, "resolved a second before the release",
		history.verifyResolution(history.resolveAfterRelease(release, releasedAt-1, nil), resolvedAt),
		"coverage resolution precedes its exposure release")
}
