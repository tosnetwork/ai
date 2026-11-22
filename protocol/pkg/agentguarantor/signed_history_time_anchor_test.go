package agentguarantor

import (
	"testing"
	"time"
)

// Which time each check is about, on signed history. A receipt is a permanent
// fact once admitted: the time its body states is the time its stage action
// was admitted at, everything that asks whether the event was valid is judged
// at that time, and the verifier's present only bounds it from above, with one
// clock allowance for every receipt, proof and authorization. Every refused
// object is complete and signed and differs from an accepted one in the named
// input alone.

const (
	// signedHistoryAllowance is the clock allowance in seconds.
	signedHistoryAllowance = uint64(stageAdmissionClockAllowanceV1 / time.Second)
	// signedHistoryLater is long after every validity window of a history:
	// the Writer Fence, the underlying Agreement and the coverage Agreement.
	signedHistoryLater = 10 * 365 * 24 * 60 * 60
)

// expectVerdict reports a verdict that is not the wanted one: acceptance when
// want is empty, otherwise a refusal carrying want.
func expectVerdict(t *testing.T, name string, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Errorf("%s is refused: %v", name, err)
		}
		return
	}
	refusedFor(t, name, err, want)
}

// stageAdmittedLater moves the admission of the next stage action of stage 50
// seconds past the time its receipt body states.
func stageAdmittedLater(stage string) signedHistoryVariation {
	return signedHistoryVariation{stageOf: stage, stageAfter: 50}
}

// TestSignedHistoryDecisionProofIsNotSealedBeforeItsAdmission: a compact
// decision proof is sealed once its receipt exists. One sealed at the instant
// of the admission verifies; one sealed a second or fifty seconds before it is
// refused, although every digest of its seal is the receipt's.
func TestSignedHistoryDecisionProofIsNotSealedBeforeItsAdmission(t *testing.T) {
	const early = "claim decision admission compact proof is sealed before the time its receipt states"
	at := uint64(signedHistoryStart + 100)
	history, claimID := claimFiledAt(t, 40, nil)
	receipt := history.decide(claimID, history.terms.PayoutDeadlineSeconds, at)
	for _, test := range []struct {
		name   string
		before uint64
		want   string
	}{
		{"a proof sealed at the instant of its admission", 0, ""},
		{"a proof sealed a second before its admission", 1, early},
		{"a proof sealed 50 s before its admission", 50, early},
	} {
		expectVerdict(t, test.name, history.verifyDecisionProof(history.decisionProof(receipt, at-test.before), at+100), test.want)
	}
}

// TestClaimReviewCutoffRunsOnlyFromAnInitialAdmission: the claim review cutoff
// is computed from an initial admission body. The body of the claim's own
// revision admission, and the initial body restated as a revision, yield no
// cutoff, so no caller can run the cutoff from a revision.
func TestClaimReviewCutoffRunsOnlyFromAnInitialAdmission(t *testing.T) {
	history, claimID := claimRevisedAt(t, 500)
	initial, revision := history.initialReceipts[claimID].Body, history.latestReceipts[claimID].Body
	if initial.AdmissionKind != "initial" || revision.AdmissionKind != "revision" {
		t.Fatalf("the history's admissions are %q and %q, want an initial and a revision", initial.AdmissionKind, revision.AdmissionKind)
	}
	cutoff, found := claimReviewCutoffV1(initial, history.terms)
	if want := initial.AdmittedAtUnix + history.terms.ReviewDeadlineSeconds; !found || cutoff != want {
		t.Errorf("the initial admission's cutoff is %d (found %t), want %d", cutoff, found, want)
	}
	if cutoff, found := claimReviewCutoffV1(revision, history.terms); found || cutoff != 0 {
		t.Errorf("a revision admission yields the cutoff %d (found %t), want none", cutoff, found)
	}
	restated := initial
	restated.AdmissionKind = "revision"
	if cutoff, found := claimReviewCutoffV1(restated, history.terms); found || cutoff != 0 {
		t.Errorf("the initial admission restated as a revision yields the cutoff %d (found %t), want none", cutoff, found)
	}
}

// TestSignedHistoryEveryProofSealHasTheClockAllowance: the seal of a claim
// admission proof and of a decision application proof is held to the
// verifier's present with the same allowance as a decision proof's, and is not
// before the time its receipt states. A verifier the whole allowance behind
// the sealing authority accepts each; one a second further behind refuses it.
// A decision on a claim revision, whose admission carries the initial
// admission's proof, is therefore accepted by a verifier 110 s behind, as the
// same decision on an initial claim is.
func TestSignedHistoryEveryProofSealHasTheClockAllowance(t *testing.T) {
	history, claimID := claimFiledAt(t, 40, nil)
	initial := history.initialReceipts[claimID]
	admittedAt := initial.Body.AdmittedAtUnix
	sealedAt := admittedAt + 10
	claimProof := history.claimAdmissionProof(initial, sealedAt)
	verifyClaimProof := func(at uint64) error {
		return ValidateClaimAdmissionReceiptProofV1(claimProof, history.terms, history.resolver, history.fenceResolver,
			signedHistoryTime(at), true)
	}
	const claimSealedAhead = "claim admission compact proof is sealed after the verifier's present"
	expectVerdict(t, "a claim admission proof sealed the whole allowance after the verifier's present",
		verifyClaimProof(sealedAt-signedHistoryAllowance), "")
	expectVerdict(t, "a claim admission proof sealed a second beyond the allowance",
		verifyClaimProof(sealedAt-signedHistoryAllowance-1), claimSealedAhead)
	_, err := history.sealClaimAdmission(initial, admittedAt)
	expectVerdict(t, "a claim admission proof sealed at the instant of its admission", err, "")
	_, err = history.sealClaimAdmission(initial, admittedAt-1)
	expectVerdict(t, "a claim admission proof sealed a second before its admission", err,
		"claim admission compact proof is sealed before the time its receipt states")

	at := uint64(signedHistoryStart + 100)
	end := history.decide(claimID, history.terms.PayoutDeadlineSeconds, at).Body.ChallengeEndsAtUnix
	history.challengeClose(claimID, end)
	application := history.apply(claimID, history.materialize(claimID, history.terms), end+10)
	applicationSealedAt := end + 20
	applicationProof := history.applicationProof(application, applicationSealedAt)
	verifyApplicationProof := func(at uint64) error {
		return ValidateDecisionApplicationReceiptProofV1(applicationProof, history.terms, history.resolver, signedHistoryTime(at), true)
	}
	expectVerdict(t, "an application proof sealed the whole allowance after the verifier's present",
		verifyApplicationProof(applicationSealedAt-signedHistoryAllowance), "")
	expectVerdict(t, "an application proof sealed a second beyond the allowance",
		verifyApplicationProof(applicationSealedAt-signedHistoryAllowance-1),
		"decision application compact proof is sealed after the verifier's present")
	_, err = history.sealApplication(application, end+10)
	expectVerdict(t, "an application proof sealed at the instant its decision was applied", err, "")
	_, err = history.sealApplication(application, end+9)
	expectVerdict(t, "an application proof sealed a second before its decision was applied", err,
		"decision application compact proof is sealed before the time its receipt states")

	// The same decision, admitted at 510 s, on an initial claim and on a
	// revision admitted at 500 s, verified by a clock 110 s behind.
	const decidedAfter, lag = 510, 110
	initialHistory, initialClaim := claimFiledAt(t, 40, nil)
	revisedHistory, revisedClaim := claimRevisedAt(t, 500)
	for _, test := range []struct {
		name    string
		history *signedHistory
		claimID string
	}{
		{"a decision on an initial claim verified by a clock 110 s behind", initialHistory, initialClaim},
		{"the same decision on a revision verified by a clock 110 s behind", revisedHistory, revisedClaim},
	} {
		decidedAt := uint64(signedHistoryStart + decidedAfter)
		receipt := test.history.decide(test.claimID, test.history.terms.PayoutDeadlineSeconds, decidedAt)
		expectVerdict(t, test.name, test.history.verifyDecisionAdmission(receipt, decidedAt-lag), "")
	}

	// A revision admission whose initial admission proof is sealed ten
	// seconds after the revision was admitted.
	revised, revisedID := claimRevisedAt(t, 500)
	revision := revised.latestReceipts[revisedID]
	laterSeal := revision.Body.AdmittedAtUnix + 10
	laterProof := revised.claimAdmissionProof(revised.initialReceipts[revisedID], laterSeal)
	revision.InitialClaimAdmissionProof = &laterProof
	expectVerdict(t, "a revision whose initial proof is sealed the whole allowance after the verifier's present",
		revised.verifyClaimAdmission(revision, laterSeal-signedHistoryAllowance), "")
	expectVerdict(t, "a revision whose initial proof is sealed a second beyond the allowance",
		revised.verifyClaimAdmission(revision, laterSeal-signedHistoryAllowance-1), claimSealedAhead)
}

// TestSignedHistoryProofSealTimeIsAProtocolTimestamp: the seal time of each
// compact proof lies in the range of a timestamp. A proof whose seal states a
// time past that range, and whose seal authorization names the same time, is
// refused for the seal time before any time is computed from it.
func TestSignedHistoryProofSealTimeIsAProtocolTimestamp(t *testing.T) {
	const outOfRange = uint64(1) << 63
	history, claimID := claimFiledAt(t, 40, nil)
	at := uint64(signedHistoryStart + 100)
	receipt := history.decide(claimID, history.terms.PayoutDeadlineSeconds, at)
	end := receipt.Body.ChallengeEndsAtUnix
	decisionProof := history.decisionProof(receipt, at)
	claimProof := history.claimAdmissionProof(history.initialReceipts[claimID], at)
	history.challengeClose(claimID, end)
	applicationProof := history.applicationProof(history.apply(claimID, history.materialize(claimID, history.terms), end+10), end+10)
	later := signedHistoryTime(end + 100)

	expectVerdict(t, "a decision proof sealed in range", history.verifyDecisionProof(decisionProof, end+100), "")
	decisionProof.SealBody.SealedAtUnix, decisionProof.SealAuthorization.ValidationTimeUnix = outOfRange, outOfRange
	expectVerdict(t, "a decision proof sealed past the range of a timestamp", history.verifyDecisionProof(decisionProof, end+100),
		"claim decision admission compact proof seal time is absent or out of range")

	expectVerdict(t, "a claim admission proof sealed in range",
		ValidateClaimAdmissionReceiptProofV1(claimProof, history.terms, history.resolver, history.fenceResolver, later, true), "")
	claimProof.SealBody.SealedAtUnix, claimProof.SealAuthorization.ValidationTimeUnix = outOfRange, outOfRange
	expectVerdict(t, "a claim admission proof sealed past the range of a timestamp",
		ValidateClaimAdmissionReceiptProofV1(claimProof, history.terms, history.resolver, history.fenceResolver, later, true),
		"claim admission compact proof seal time is absent or out of range")

	expectVerdict(t, "an application proof sealed in range",
		ValidateDecisionApplicationReceiptProofV1(applicationProof, history.terms, history.resolver, later, true), "")
	applicationProof.SealBody.SealedAtUnix, applicationProof.SealAuthorization.ValidationTimeUnix = outOfRange, outOfRange
	expectVerdict(t, "an application proof sealed past the range of a timestamp",
		ValidateDecisionApplicationReceiptProofV1(applicationProof, history.terms, history.resolver, later, true),
		"decision application compact proof seal time is absent or out of range")
}

// TestSignedHistoryAuthorizationAndProfileTimesHaveTheClockAllowance: an
// object authorization and a service profile are held to the verifier's
// present with the allowance every receipt time has: accepted by a verifier
// the whole allowance behind, refused by one a second further behind.
func TestSignedHistoryAuthorizationAndProfileTimesHaveTheClockAllowance(t *testing.T) {
	history := newSignedHistory(t)
	const kind, domain = "test-object", "tos.test.signed-history-object-signature.v1"
	signedAt := uint64(signedHistoryStart + 100)
	authorization := history.signObject(kind, testDigest("1"), domain, signedAt)
	verify := func(at uint64) error {
		return VerifyObjectAuthorization(authorization, kind, testDigest("1"), domain, history.resolver, signedHistoryTime(at))
	}
	expectVerdict(t, "an authorization signed the whole allowance after the verifier's present", verify(signedAt-signedHistoryAllowance), "")
	expectVerdict(t, "an authorization signed a second beyond the allowance", verify(signedAt-signedHistoryAllowance-1),
		"Guarantor authorization validation time is in the future")

	terms := history.terms
	profile := history.offerServiceProfile(terms, testClaimProfileFor(t, &terms), nil)
	expectVerdict(t, "a profile created the whole allowance after the verifier's present",
		ValidateServiceProfile(profile, signedHistoryTime(profile.CreatedAtUnix-signedHistoryAllowance)), "")
	expectVerdict(t, "a profile created a second beyond the allowance",
		ValidateServiceProfile(profile, signedHistoryTime(profile.CreatedAtUnix-signedHistoryAllowance-1)),
		"Guarantor service profile is invalid")
}

// TestSignedHistoryActivationIsJudgedAtItsActivationTime: activation evidence
// built in full on a signed offer is verified by the unreplaced verifier at
// its activation time, when the underlying Agreement's authorization expires,
// when the Writer Fence of its acceptance and activation actions expires, when
// the coverage Agreement expires and ten years later, and is accepted each
// time. An activation admitted when the underlying Agreement's authorization
// has expired, or when its action's Writer Fence has, is refused whenever it
// is verified; one admitted a second before either expiry is accepted ten
// years later.
func TestSignedHistoryActivationIsJudgedAtItsActivationTime(t *testing.T) {
	history := offerPhaseHistory(t)
	verify := func(signed signedOffer, evidence AuthorizedCoverageActivationEvidenceV1, at uint64) error {
		return VerifyCoverageActivationEvidenceV1(evidence, signed.offer, signedOfferAgreementVerifier{signed}, signed.resolver,
			history.fenceResolver, nil, signedHistoryTime(at))
	}
	signed := history.quoteToOffer(true, nil)
	acceptance := history.acceptanceReceipt(signed)
	activation := history.offerActivation(signed, acceptance)
	activatedAt, terms := activation.Body.ActivatedAtUnix, signed.offer.CoverageTerms
	underlying := signed.underlying[terms.UnderlyingAgreementBodyDigest]
	if underlying.Body.ExpiresAtUnix != terms.CoverageEndsAtUnix || history.fence.Body.ExpiresAtUnix <= underlying.Body.ExpiresAtUnix {
		t.Fatalf("the underlying Agreement expires at %d and the fence at %d, want the coverage end %d and a later fence expiry",
			underlying.Body.ExpiresAtUnix, history.fence.Body.ExpiresAtUnix, terms.CoverageEndsAtUnix)
	}
	for _, test := range []struct {
		name string
		at   uint64
	}{
		{"at its activation time", activatedAt},
		{"when the underlying Agreement's authorization expires", underlying.Body.ExpiresAtUnix},
		{"when the Writer Fence expires", history.fence.Body.ExpiresAtUnix},
		{"when the coverage Agreement expires", signed.agreement.ExpiresAtUnix},
		{"ten years later", activatedAt + signedHistoryLater},
	} {
		expectVerdict(t, "activation evidence verified "+test.name, verify(signed, activation, test.at), "")
	}
	expectVerdict(t, "activation evidence verified a second before the allowance reaches its activation time",
		verify(signed, activation, activatedAt-signedHistoryAllowance-1), "coverage activation time is after the verifier's present")

	// The underlying Agreement and its predicate expire a second after the
	// activation, or at it: an Agreement is authorized until its expiry and
	// not at it.
	for _, test := range []struct {
		name         string
		expiresAfter uint64
		want         string
	}{
		{"an activation a second before the underlying Agreement expires", 1, ""},
		{"an activation at the underlying Agreement's expiry", 0, "underlying Agreement is not authorized at the activation time"},
	} {
		varied := history.quoteToOffer(true, func(in *signedOfferInputs) { in.underlyingExpiresAt = activatedAt + test.expiresAfter })
		evidence := history.offerActivation(varied, history.acceptanceReceipt(varied))
		if evidence.Body.ActivatedAtUnix != activatedAt {
			t.Fatalf("%s: the coverage is activated at %d, want %d", test.name, evidence.Body.ActivatedAtUnix, activatedAt)
		}
		expectVerdict(t, test.name+", verified ten years later", verify(varied, evidence, activatedAt+signedHistoryLater), test.want)
	}

	// The activation action's Writer Fence expires a second after the
	// activation, or at it. The acceptance was admitted under the history's
	// longer fence and is the same in both.
	for _, test := range []struct {
		name         string
		expiresAfter uint64
		want         string
	}{
		{"an activation a second before its Writer Fence expires", 1, ""},
		{"an activation at its Writer Fence's expiry", 0, "authorized action does not match the current writer fence"},
	} {
		history.useFenceUntil(activatedAt + test.expiresAfter)
		evidence := history.offerActivation(signed, acceptance)
		expectVerdict(t, test.name+", verified ten years later", verify(signed, evidence, activatedAt+signedHistoryLater), test.want)
	}
}

// TestSignedHistoryStageActionIsJudgedAtItsAdmissionTime: every stage action
// is verified at the time its Action Authority admitted it. A claim admitted a
// second before its Writer Fence expires verifies ten years later; one
// admitted at the fence's expiry is refused. A whole closure chain (filing
// close, terminal claim set, exposure release and coverage resolution) built
// while the fence was current verifies ten years after the fence expired.
func TestSignedHistoryStageActionIsJudgedAtItsAdmissionTime(t *testing.T) {
	admittedAt := uint64(signedHistoryStart + 40)
	for _, test := range []struct {
		name         string
		expiresAfter uint64
		want         string
	}{
		{"a claim admitted a second before its Writer Fence expires", 1, ""},
		{"a claim admitted at its Writer Fence's expiry", 0, "authorized action does not match the current writer fence"},
	} {
		history := newSignedHistory(t)
		withSignedHistorySeam(t, history)
		history.useFenceUntil(admittedAt + test.expiresAfter)
		receipt := history.admit(history.claim(1, nil, admittedAt-10), admittedAt)
		expectVerdict(t, test.name+", verified ten years later", history.verifyClaimAdmission(receipt, admittedAt+signedHistoryLater), test.want)
	}

	claim := newLateDeniedClaim(t, true, nil)
	history := claim.history
	later := claim.closedAt + signedHistoryLater
	if later <= history.fence.Body.ExpiresAtUnix {
		t.Fatalf("the chain is verified at %d, not after its fence expired at %d", later, history.fence.Body.ExpiresAtUnix)
	}
	bundle := history.terminalBundle(claim.claimID, claim.application, claim.closedAt)
	set := history.terminalSet(claim.filing, []ClaimTerminalResolutionBundleV1{bundle}, claim.closedAt)
	release := history.releaseAfterClosure(set, history.offer.ExposureAdmissionReceipt, claim.closedAt+10, nil)
	resolution := history.resolveAfterRelease(release, claim.closedAt+20, nil)
	expectVerdict(t, "a filing close verified ten years later", VerifyClaimFilingCloseReceiptV1(claim.filing, history.offer,
		permissiveAgreementVerifier{}, history.resolver, history.fenceResolver, signedHistoryTime(later)), "")
	expectVerdict(t, "a terminal claim set verified ten years later", history.verifyTerminalSet(set, later), "")
	expectVerdict(t, "an exposure release verified ten years later", history.verifyRelease(release, later), "")
	expectVerdict(t, "a coverage resolution verified ten years later", history.verifyResolution(resolution, later), "")
}

// TestSignedHistoryClaimPhaseReceiptTimesAreTheirStageAdmissionTimes: the time
// a claim ingress receipt, a claim admission, a filing close, a terminal claim
// set, an exposure release and a coverage resolution state is the time their
// stage action was admitted at. Each verifies as built; the same receipt whose
// stage action was admitted 50 s after the time its body states is refused
// for the difference.
func TestSignedHistoryClaimPhaseReceiptTimesAreTheirStageAdmissionTimes(t *testing.T) {
	const differs = " time differs from its stage action admission evidence's"
	admittedAt := uint64(signedHistoryStart + 40)
	for _, test := range []struct {
		name string
		vary signedHistoryVariation
		want string
	}{
		{"a claim admission and its ingress receipt", signedHistoryVariation{}, ""},
		{"an ingress receipt whose stage action was admitted 50 s after it states it received the claim",
			stageAdmittedLater("claim_submission_ingress"), "claim ingress" + differs},
		{"a claim admission whose stage action was admitted 50 s after its body states", stageAdmittedLater("initial_claim_admission"),
			"claim admission" + differs},
	} {
		history := newSignedHistory(t)
		withSignedHistorySeam(t, history)
		history.vary = test.vary
		receipt := history.admit(history.claim(1, nil, admittedAt-10), admittedAt)
		expectVerdict(t, test.name, history.verifyClaimAdmission(receipt, admittedAt+1000), test.want)
	}

	claim := newLateDeniedClaim(t, true, nil)
	history := claim.history
	later := claim.closedAt + 1000
	verifyFiling := func(filing AuthorizedClaimFilingCloseReceiptV1) error {
		return VerifyClaimFilingCloseReceiptV1(filing, history.offer, permissiveAgreementVerifier{}, history.resolver,
			history.fenceResolver, signedHistoryTime(later))
	}
	expectVerdict(t, "a filing close", verifyFiling(claim.filing), "")
	// The second filing close stands for the first, signed again with its
	// stage action admitted later; the history is not built on it.
	revision := history.coverageRevision
	history.coverageRevision = claim.filing.Body.PriorCoverageRevision
	history.vary = stageAdmittedLater("filing_close")
	backdatedFiling := history.filingClose(claim.filing.Body.ClosedAtUnix)
	history.vary = signedHistoryVariation{}
	history.coverageRevision = revision
	expectVerdict(t, "a filing close whose stage action was admitted 50 s after its body states", verifyFiling(backdatedFiling),
		"claim filing close"+differs)

	bundle := history.terminalBundle(claim.claimID, claim.application, claim.closedAt)
	bundles := []ClaimTerminalResolutionBundleV1{bundle}
	set := history.terminalSet(claim.filing, bundles, claim.closedAt)
	expectVerdict(t, "a terminal claim set", history.verifyTerminalSet(set, later), "")
	history.vary = stageAdmittedLater("coverage_closure")
	backdatedSet := history.terminalSet(claim.filing, bundles, claim.closedAt)
	history.vary = signedHistoryVariation{}
	expectVerdict(t, "a terminal claim set whose closure action was admitted 50 s after its body states",
		history.verifyTerminalSet(backdatedSet, later), "terminal claim set creation"+differs)

	own := history.offer.ExposureAdmissionReceipt
	release := history.releaseAfterClosure(set, own, claim.closedAt+10, nil)
	expectVerdict(t, "an exposure release", history.verifyRelease(release, later), "")
	history.vary = stageAdmittedLater("post_acceptance_exposure_release")
	backdatedRelease := history.releaseAfterClosure(set, own, claim.closedAt+10, nil)
	history.vary = signedHistoryVariation{}
	expectVerdict(t, "an exposure release whose stage action was admitted 50 s after its body states",
		history.verifyRelease(backdatedRelease, later), "exposure release"+differs)

	resolution := history.resolveAfterRelease(release, claim.closedAt+20, nil)
	expectVerdict(t, "a coverage resolution", history.verifyResolution(resolution, later), "")
	history.vary = stageAdmittedLater("coverage_resolution")
	backdatedResolution := history.resolveAfterRelease(release, claim.closedAt+20, nil)
	history.vary = signedHistoryVariation{}
	expectVerdict(t, "a coverage resolution whose stage action was admitted 50 s after its body states",
		history.verifyResolution(backdatedResolution, later), "coverage resolution"+differs)
}

// TestSignedHistoryCoveragePhaseReceiptTimesAreTheirStageAdmissionTimes: the
// same anchor for the receipts of the coverage's own lifecycle, each built in
// full on a signed offer and verified by its unreplaced verifier ten years
// later: the acceptance receipt, activation evidence, a cancellation receipt,
// non-activation evidence and the release of a never-activated reservation.
// Each is accepted as built and refused when its stage action was admitted
// 50 s after the time its body states.
func TestSignedHistoryCoveragePhaseReceiptTimesAreTheirStageAdmissionTimes(t *testing.T) {
	const differs = " time differs from its stage action admission evidence's"
	history := offerPhaseHistory(t)
	signed := history.quoteToOffer(true, signedOfferCancellable)
	verifier := signedOfferAgreementVerifier{signed}
	build := func(vary signedHistoryVariation, object func()) {
		history.vary = vary
		object()
		history.vary = signedHistoryVariation{}
	}

	var acceptance, backdatedAcceptance AuthorizedCoverageAcceptanceReceiptV1
	build(signedHistoryVariation{}, func() { acceptance = history.acceptanceReceipt(signed) })
	build(stageAdmittedLater("coverage_acceptance"), func() { backdatedAcceptance = history.acceptanceReceipt(signed) })
	later := signedHistoryTime(acceptance.Body.AcceptedAtUnix + signedHistoryLater)
	verifyAcceptance := func(receipt AuthorizedCoverageAcceptanceReceiptV1) error {
		return VerifyCoverageAcceptanceReceiptV1(receipt, signed.offer, verifier, signed.resolver, history.fenceResolver, later)
	}
	expectVerdict(t, "an acceptance receipt", verifyAcceptance(acceptance), "")
	expectVerdict(t, "an acceptance receipt whose stage action was admitted 50 s after its body states",
		verifyAcceptance(backdatedAcceptance), "coverage acceptance"+differs)

	var activation, backdatedActivation AuthorizedCoverageActivationEvidenceV1
	build(signedHistoryVariation{}, func() { activation = history.offerActivation(signed, acceptance) })
	build(stageAdmittedLater("coverage_activation"), func() { backdatedActivation = history.offerActivation(signed, acceptance) })
	verifyActivation := func(evidence AuthorizedCoverageActivationEvidenceV1) error {
		return VerifyCoverageActivationEvidenceV1(evidence, signed.offer, verifier, signed.resolver, history.fenceResolver, nil, later)
	}
	expectVerdict(t, "activation evidence", verifyActivation(activation), "")
	expectVerdict(t, "activation evidence whose stage action was admitted 50 s after its body states",
		verifyActivation(backdatedActivation), "coverage activation"+differs)

	cancelledAt := activation.Body.ActivatedAtUnix + 100
	var cancellation, backdatedCancellation AuthorizedCoverageCancellationReceiptV1
	build(signedHistoryVariation{}, func() { cancellation = history.cancellation(signed, activation, cancelledAt) })
	build(stageAdmittedLater("coverage_cancellation"), func() {
		backdatedCancellation = history.cancellation(signed, activation, cancelledAt)
	})
	verifyCancellation := func(receipt AuthorizedCoverageCancellationReceiptV1) error {
		return VerifyCoverageCancellationReceiptV1(receipt, activation, verifier, signed.resolver, history.fenceResolver, later)
	}
	expectVerdict(t, "a cancellation receipt", verifyCancellation(cancellation), "")
	expectVerdict(t, "a cancellation receipt whose stage action was admitted 50 s after its body states",
		verifyCancellation(backdatedCancellation), "coverage cancellation"+differs)

	var nonActivation, backdatedNonActivation AuthorizedCoverageNonActivationEvidenceV1
	build(signedHistoryVariation{}, func() { nonActivation = history.nonActivation(signed, acceptance) })
	build(stageAdmittedLater("coverage_non_activation"), func() { backdatedNonActivation = history.nonActivation(signed, acceptance) })
	verifyNonActivation := func(evidence AuthorizedCoverageNonActivationEvidenceV1) error {
		return VerifyCoverageNonActivationEvidenceV1(evidence, signed.offer, verifier, signed.resolver, history.fenceResolver, later)
	}
	expectVerdict(t, "non-activation evidence", verifyNonActivation(nonActivation), "")
	expectVerdict(t, "non-activation evidence whose stage action was admitted 50 s after its body states",
		verifyNonActivation(backdatedNonActivation), "coverage non-activation"+differs)

	var release, backdatedRelease AuthorizedNonActivationExposureReleaseReceiptV1
	build(signedHistoryVariation{}, func() { release = history.exposureRelease(signed, nonActivation) })
	build(stageAdmittedLater("post_acceptance_exposure_release"), func() { backdatedRelease = history.exposureRelease(signed, nonActivation) })
	verifyRelease := func(receipt AuthorizedNonActivationExposureReleaseReceiptV1) error {
		return VerifyNonActivationExposureReleaseReceiptV1(receipt, signed.offer, verifier, signed.resolver, history.fenceResolver, later)
	}
	expectVerdict(t, "the release of a never-activated reservation", verifyRelease(release), "")
	expectVerdict(t, "the release of a never-activated reservation whose stage action was admitted 50 s after its body states",
		verifyRelease(backdatedRelease), "non-activation exposure release"+differs)
}

// TestSignedHistoryActivationEligibilityProofsBindTheActivation: the
// eligibility proofs of activation evidence carry exactly one entry for each
// of the Guarantor, the covered party and the beneficiary, with the
// acceptance receipt as input, coverage activation as kind, the evidence's
// exact request as body, the terms' coverage state domain as scope and their
// lifecycle authorization profile as resolver, for the admitted action, in the
// coverage Agreement's activation admission domain at the activation time. A
// cancellation receipt stands on activation evidence and carries the refusal.
func TestSignedHistoryActivationEligibilityProofsBindTheActivation(t *testing.T) {
	history := offerPhaseHistory(t)
	signed := history.quoteToOffer(true, signedOfferCancellable)
	verifier := signedOfferAgreementVerifier{signed}
	acceptance := history.acceptanceReceipt(signed)
	const prefix = "coverage activation evidence eligibility proofs: "
	const mismatch = prefix + "Guarantor authority eligibility cut does not match the admission"
	cases := append(signedOfferEligibilityCases(prefix),
		eligibilityCase{name: "proofs admitting another action",
			change: func(proven *signedOfferEligibility) { proven.actionDigest = testDigest("f") }, refusal: mismatch},
		eligibilityCase{name: "proofs in another admission domain",
			change: func(proven *signedOfferEligibility) { proven.domainID = testDigest("f") }, refusal: mismatch},
		eligibilityCase{name: "proofs frozen one second before the activation",
			change: func(proven *signedOfferEligibility) { proven.at-- }, refusal: mismatch})
	for _, test := range cases {
		evidence := history.offerActivationWith(signed, acceptance, test.change)
		expectEligibility(t, test.name, "the activation verifier", VerifyCoverageActivationEvidenceV1(evidence, signed.offer,
			verifier, signed.resolver, history.fenceResolver, nil, signedHistoryTime(evidence.Body.ActivatedAtUnix)), test.refusal)
	}

	// One refused activation, carried by the cancellation that stands on it.
	activation := history.offerActivationWith(signed, acceptance, func(proven *signedOfferEligibility) { proven.kind = "activation-evidence" })
	cancelledAt := activation.Body.ActivatedAtUnix + 100
	cancellation := history.cancellation(signed, activation, cancelledAt)
	expectEligibility(t, "activation with proofs for another object kind", "the cancellation verifier",
		VerifyCoverageCancellationReceiptV1(cancellation, activation, verifier, signed.resolver, history.fenceResolver,
			signedHistoryTime(cancelledAt)), prefix+"Guarantor authority eligibility proof is substituted")
}
