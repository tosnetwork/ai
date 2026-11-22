package agentguarantor

import (
	"testing"
	"time"
)

// The claim and decision bindings on signed history: the revision maximum,
// the windows and round counts a decision admission opens, the frozen
// revision epoch it binds to its cut, and the time an authorized decision is
// judged at. Every refused object is complete and signed and differs from an
// accepted one in the named input alone.

const revisionMaximumRefusal = "Guarantor claim revision exceeds the Agreement's maximum claim revisions per claim"

// sealClaimAdmission is claimAdmissionProof that returns the builder's
// verdict instead of failing the test.
func (history *signedHistory) sealClaimAdmission(receipt AuthorizedClaimAdmissionReceiptV1, at uint64) (ClaimAdmissionReceiptProofV1, error) {
	t := history.t
	seal, descriptor, err := NewClaimAdmissionReceiptSealBodyV1(receipt, history.terms, time.Unix(int64(at), 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	sealDigest, err := Digest(ClaimAdmissionReceiptSealDomainV1, seal)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := FindStageActionAuthorityV1(history.terms.StageActionAuthorityBinding, "claim_revision_admission")
	if err != nil {
		t.Fatal(err)
	}
	authorization := history.signObjectAs(bound.ActionAuthorityID, history.terms.LifecycleAuthorizationProfile,
		"claim-admission-receipt-seal", sealDigest, "tos.service.agent-guarantor-claim-admission-receipt-seal-signature.v1",
		seal.SealedAtUnix)
	return BuildClaimAdmissionReceiptProofV1(receipt, history.terms, descriptor, seal, authorization)
}

// TestSignedHistoryRefusesARevisionPastTheAgreementsMaximum: the terms allow
// three revisions of a claim, the initial claim included. The third is
// accepted at ingress, at admission and as a compact proof; the fourth,
// signed in exactly the same way, is refused at each of the three for the
// maximum itself.
func TestSignedHistoryRefusesARevisionPastTheAgreementsMaximum(t *testing.T) {
	history := newSignedHistory(t)
	withSignedHistorySeam(t, history)
	if maximum := history.terms.ClaimClosureCapacity.MaximumClaimRevisionsPerClaim; maximum != 3 {
		t.Fatalf("the signed-history terms allow %d revisions per claim, want 3", maximum)
	}
	ingressBound, err := FindStageActionAuthorityV1(history.terms.StageActionAuthorityBinding, "claim_submission_ingress")
	if err != nil {
		t.Fatal(err)
	}
	verifyIngress := func(receipt AuthorizedClaimAdmissionReceiptV1, at uint64) error {
		return VerifyClaimSubmissionIngressReceiptV1(receipt.AuthorizedClaimIngressReceipt, history.terms, ingressBound,
			history.resolver, history.fenceResolver, time.Unix(int64(at), 0).UTC())
	}
	first := history.claim(1, nil, signedHistoryStart+30)
	history.admit(first, signedHistoryStart+40)
	second := history.claim(2, &first, signedHistoryStart+50)
	secondAdmission := history.admit(second, signedHistoryStart+60)
	third := history.claim(3, &second, signedHistoryStart+70)
	atMaximum := history.admit(third, signedHistoryStart+80)
	if err := verifyIngress(atMaximum, signedHistoryStart+80); err != nil {
		t.Errorf("the ingress of the revision at the maximum is refused: %v", err)
	}
	if err := history.verifyClaimAdmission(atMaximum, signedHistoryStart+80); err != nil {
		t.Errorf("the admission of the revision at the maximum is refused: %v", err)
	}
	if _, err := history.sealClaimAdmission(atMaximum, signedHistoryStart+80); err != nil {
		t.Errorf("the compact proof of the revision at the maximum is refused: %v", err)
	}
	fourth := history.claim(4, &third, signedHistoryStart+90)
	pastMaximum := history.admit(fourth, signedHistoryStart+100)
	// Each verdict is compared whole: the admission verifier wraps an ingress
	// refusal, so an exact match shows which of the three checks refused.
	if err := verifyIngress(pastMaximum, signedHistoryStart+100); err == nil || err.Error() != revisionMaximumRefusal {
		t.Errorf("the ingress of the revision past the maximum: got %v, want %q", err, revisionMaximumRefusal)
	}
	if err := history.verifyClaimAdmission(pastMaximum, signedHistoryStart+100); err == nil || err.Error() != revisionMaximumRefusal {
		t.Errorf("the admission of the revision past the maximum: got %v, want %q", err, revisionMaximumRefusal)
	}
	if _, err := history.sealClaimAdmission(pastMaximum, signedHistoryStart+100); err == nil || err.Error() != revisionMaximumRefusal {
		t.Errorf("the compact proof of the revision past the maximum: got %v, want %q", err, revisionMaximumRefusal)
	}

	// A compact proof whose body admits another revision than the claim it
	// carries is refused before its seal is looked at.
	proof := history.claimAdmissionProof(secondAdmission, signedHistoryStart+100)
	validate := func(proof ClaimAdmissionReceiptProofV1) error {
		return ValidateClaimAdmissionReceiptProofV1(proof, history.terms, history.resolver, history.fenceResolver,
			time.Unix(signedHistoryStart+100, 0).UTC(), true)
	}
	if err := validate(proof); err != nil {
		t.Errorf("the compact proof of the second revision is refused: %v", err)
	}
	proof.ReceiptBody.AdmittedClaimRevision = 3
	refusedFor(t, "a proof body admitting another revision than its claim's", validate(proof),
		"claim admission compact proof admits another revision than its claim's")
}

// decisionCase is one authorized decision admission built on a fresh history
// with one varied input, and the refusal the verifier must give for it. An
// empty want means the admission is accepted.
type decisionCase struct {
	name string
	vary signedHistoryVariation
	// at is the admission time, seconds after the history's start; zero means
	// 100, well inside the review window of a claim admitted at 40 or 60.
	at   uint64
	want string
}

// checkInitialDecisions builds each case's history with a claim of revisions
// revisions, admits the varied initial decision and checks the verdict.
func checkInitialDecisions(t *testing.T, revisions int, cases []decisionCase) {
	t.Helper()
	for _, test := range cases {
		history := newSignedHistory(t)
		withSignedHistorySeam(t, history)
		claim := history.claim(1, nil, signedHistoryStart+30)
		history.admit(claim, signedHistoryStart+40)
		if revisions == 2 {
			revised := history.claim(2, &claim, signedHistoryStart+50)
			history.admit(revised, signedHistoryStart+60)
		}
		at := signedHistoryStart + test.at
		if test.at == 0 {
			at = signedHistoryStart + 100
		}
		history.vary = test.vary
		receipt := history.decide(claim.Body.ClaimID, history.terms.PayoutDeadlineSeconds, at)
		err := history.verifyDecisionAdmission(receipt, at)
		if test.want == "" {
			if err != nil {
				t.Errorf("%s: the signed decision admission is refused: %v", test.name, err)
			}
			continue
		}
		refusedFor(t, test.name, err, test.want)
	}
}

func varyAdmission(change func(*ClaimDecisionAdmissionReceiptBodyV1)) signedHistoryVariation {
	return signedHistoryVariation{admission: change}
}

// TestSignedHistoryDecisionAdmissionOpensExactlyItsWindows: an authorized
// decision admission opens the challenge window of a terminal candidate, or
// the resolution window of a nonterminal decision, exactly at its admission
// time for the Agreement's length, states the decision result's claim state
// and leaves the round counts where it found them. A receipt signed with any
// of these misstated is refused for that field.
func TestSignedHistoryDecisionAdmissionOpensExactlyItsWindows(t *testing.T) {
	const challengeWindow = "claim decision admission challenge window differs from its admission time and the decision's challenge window"
	const resolutionWindow = "claim decision admission resolution window differs from its admission time and the decision's resolution window"
	disputed := func(change func(*ClaimDecisionAdmissionReceiptBodyV1)) signedHistoryVariation {
		return signedHistoryVariation{nonterminal: true, admission: change}
	}
	checkInitialDecisions(t, 1, []decisionCase{
		{name: "an approved decision"},
		{name: "a challenge window ending a second late", want: challengeWindow,
			vary: varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.ChallengeEndsAtUnix++ })},
		{name: "a challenge window starting a second early", want: challengeWindow,
			vary: varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.ChallengeStartsAtUnix-- })},
		{name: "a resolution window on a terminal candidate", want: "terminal-candidate decision admission carries a resolution window",
			vary: varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) {
				body.ResolutionStartsAtUnix, body.ResolutionDueAtUnix = body.AdmittedAtUnix, body.AdmittedAtUnix+600
			})},
		{name: "another claim state than the decision's result", want: "claim decision admission state differs from its decision's result",
			vary: varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.AdmittedClaimState = "denied" })},
		{name: "a consumed challenge round", want: "claim decision admission changes the challenge round count",
			vary: varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.ChallengeRoundsUsedAfter++ })},
		{name: "a consumed nonterminal round", want: "claim decision admission changes the nonterminal round count outside the fallback rule",
			vary: varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.NonterminalRoundsUsedAfter++ })},
		{name: "round counts past the maximum", want: "claim decision admission round count exceeds the Agreement's maximum",
			vary: varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) {
				body.ChallengeRoundsUsedBefore, body.ChallengeRoundsUsedAfter = 2, 2
			})},
		{name: "an initial decision with a consumed round", want: "initial claim decision admission starts with consumed rounds",
			vary: varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) {
				body.ChallengeRoundsUsedBefore, body.ChallengeRoundsUsedAfter = 1, 1
			})},
		{name: "a disputed decision", vary: disputed(nil)},
		{name: "a resolution window due a second late", want: resolutionWindow,
			vary: disputed(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.ResolutionDueAtUnix++ })},
		{name: "a resolution window starting a second early", want: resolutionWindow,
			vary: disputed(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.ResolutionStartsAtUnix-- })},
		{name: "a challenge window on a nonterminal decision", want: "nonterminal decision admission carries a challenge window",
			vary: disputed(func(body *ClaimDecisionAdmissionReceiptBodyV1) {
				body.ChallengeStartsAtUnix, body.ChallengeEndsAtUnix = body.AdmittedAtUnix, body.AdmittedAtUnix+600
			})},
	})
}

// TestSignedHistoryAuthorizedDecisionIsJudgedAtItsAdmissionTime: an
// authorized decision is admitted between its decided-at and expiry times
// and, when it is the claim's initial decision, by the claim review cutoff.
// A decision admitted exactly at its expiry verifies then and long after the
// expiry has passed: the expiry limits admission, not later verification. One
// admitted a second after its expiry, before it was decided, a second after
// the review cutoff or before its claim was admitted is refused.
func TestSignedHistoryAuthorizedDecisionIsJudgedAtItsAdmissionTime(t *testing.T) {
	window := func(decidedBefore, expiresAfter int64) signedHistoryVariation {
		return signedHistoryVariation{decision: func(body *ClaimDecisionBodyV1) {
			at := int64(body.DecidedAtUnix)
			body.DecidedAtUnix, body.ExpiresAtUnix = uint64(at-decidedBefore), uint64(at+expiresAfter)
		}}
	}
	checkInitialDecisions(t, 1, []decisionCase{
		{name: "admitted exactly at its expiry", vary: window(10, 0)},
		{name: "admitted a second after its expiry", vary: window(10, -1), want: "authorized claim decision is admitted after its expiry"},
		{name: "admitted a second before it was decided", vary: window(-1, 600),
			want: "authorized claim decision is admitted before it was decided"},
		{name: "admitted exactly at the claim review cutoff", at: 40 + 600},
		{name: "admitted a second after the claim review cutoff", at: 40 + 601,
			want: "initial claim decision is admitted after the claim review cutoff"},
		{name: "admitted a second before its claim", at: 39, want: "claim decision is admitted before its claim admission"},
	})

	// The decision expired at its admission time; a verifier looking at the
	// receipt long after still accepts it.
	history := newSignedHistory(t)
	withSignedHistorySeam(t, history)
	claim := history.claim(1, nil, signedHistoryStart+30)
	history.admit(claim, signedHistoryStart+40)
	history.vary = window(10, 0)
	admittedAt := uint64(signedHistoryStart + 100)
	receipt := history.decide(claim.Body.ClaimID, history.terms.PayoutDeadlineSeconds, admittedAt)
	if receipt.AuthorizedClaimDecision.Body.ExpiresAtUnix != admittedAt {
		t.Fatalf("the decision expires at %d, want its admission time %d", receipt.AuthorizedClaimDecision.Body.ExpiresAtUnix, admittedAt)
	}
	if err := history.verifyDecisionAdmission(receipt, admittedAt+30_000); err != nil {
		t.Errorf("a decision admitted in time is refused long after its expiry: %v", err)
	}
}

// TestSignedHistoryAuthorizedDecisionBindsItsFrozenEpochToItsCut: an
// authorized decision admission on a revised claim records exactly the cut
// it froze. A receipt whose frozen-epoch fields, epoch expectation or cut
// differ from that is refused for the differing piece.
func TestSignedHistoryAuthorizedDecisionBindsItsFrozenEpochToItsCut(t *testing.T) {
	const fields = "claim decision admission's frozen-epoch fields differ from its cut"
	const open = "claim decision admission must freeze the open revision epoch its head opened"
	epoch := func(change func(*ClaimRevisionEpochExpectationV1)) signedHistoryVariation {
		return signedHistoryVariation{epoch: change}
	}
	checkInitialDecisions(t, 2, []decisionCase{
		{name: "the cut it froze"},
		{name: "another frozen epoch", want: fields,
			vary: varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.FrozenRevisionEpoch++ })},
		{name: "another prior epoch-state revision", want: fields,
			vary: varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.PriorRevisionEpochStateRevision++ })},
		{name: "another frozen epoch-state revision", want: fields,
			vary: varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.FrozenRevisionEpochStateRevision++ })},
		{name: "another frozen ingress high-water", want: fields,
			vary: varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.FrozenClaimRevisionIngressHighWater++ })},
		{name: "another frozen ingress log root", want: fields,
			vary: varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) {
				body.FrozenClaimRevisionIngressLogRoot = testDigest("7")
			})},
		{name: "an expectation that the epoch is already frozen", want: open,
			vary: epoch(func(expectation *ClaimRevisionEpochExpectationV1) { expectation.ExpectedEpochState = "frozen" })},
		{name: "an expectation of another epoch-state revision", want: open,
			vary: epoch(func(expectation *ClaimRevisionEpochExpectationV1) { expectation.ExpectedEpochStateRevision++ })},
		{name: "an expectation of another epoch", want: "claim decision admission revision cut names another epoch than its request",
			vary: epoch(func(expectation *ClaimRevisionEpochExpectationV1) { expectation.RevisionEpoch++ })},
		{name: "a cut on another obligation", want: "claim decision admission revision cut is not the cut of its claim's revision ingress log",
			vary: signedHistoryVariation{cut: func(cut *ClaimIngressAdmissionCutProofV1) { cut.CoverageObligationID = "obligation:other" }}},
	})

	// A cut that admits no revision ingress, for a decision on revision 2.
	history := newSignedHistory(t)
	withSignedHistorySeam(t, history)
	claim := history.claim(1, nil, signedHistoryStart+30)
	history.admit(claim, signedHistoryStart+40)
	revised := history.claim(2, &claim, signedHistoryStart+50)
	history.admit(revised, signedHistoryStart+60)
	claimID := claim.Body.ClaimID
	history.admissions[claimID] = history.admissions[claimID][:1]
	receipt := history.decide(claimID, history.terms.PayoutDeadlineSeconds, signedHistoryStart+100)
	if admitted := receipt.ClaimRevisionIngressCutProof.AdmittedClaimCount; admitted != 0 {
		t.Fatalf("the cut admits %d revision ingresses, want none", admitted)
	}
	refusedFor(t, "a cut that stops short of the decided revision", history.verifyDecisionAdmission(receipt, signedHistoryStart+100),
		"claim decision admission revision cut does not end at the decided claim revision")
}

// lateCandidateChallenged is a claim of two revisions whose late-recovery
// candidate was admitted and challenged. candidateOnFirstRevision admits the
// candidate on the claim's first revision although the second is admitted.
func lateCandidateChallenged(t *testing.T, candidateOnFirstRevision bool) (*signedHistory, string, uint64) {
	t.Helper()
	history := newSignedHistory(t)
	withSignedHistorySeam(t, history)
	first := history.claim(1, nil, signedHistoryStart+30)
	history.admit(first, signedHistoryStart+40)
	second := history.claim(2, &first, signedHistoryStart+50)
	history.admit(second, signedHistoryStart+60)
	claimID := first.Body.ClaimID
	lateAt := history.terms.TerminalResolutionDeadlineUnix + 60
	filing := history.filingClose(lateAt)
	admissions, latest := history.admissions[claimID], history.latestReceipts[claimID]
	if candidateOnFirstRevision {
		history.admissions[claimID], history.latestReceipts[claimID] = admissions[:1], admissions[0]
	}
	history.fallback(claimID, &filing, lateAt+10)
	history.admissions[claimID], history.latestReceipts[claimID] = admissions, latest
	history.challenge(claimID, lateAt+20)
	return history, claimID, lateAt
}

// TestSignedHistoryLateSuccessorReusesItsCandidatesFrozenEpoch: the
// authorized successor of a challenged late-recovery candidate finds revision
// ingress still frozen. It verifies when it reuses the candidate's epoch and
// cut and starts from the challenge's round counts, and is refused when it
// expects an open epoch, decides another claim admission than its candidate,
// restates the round counts or is admitted before the challenge.
func TestSignedHistoryLateSuccessorReusesItsCandidatesFrozenEpoch(t *testing.T) {
	history, claimID, lateAt := lateCandidateChallenged(t, false)
	due := history.terms.PayoutDeadlineSeconds
	restore := history.checkpoint(claimID)
	if err := history.verifyDecisionAdmission(history.decide(claimID, due, lateAt+30), lateAt+30); err != nil {
		t.Fatalf("the signed successor of the challenged late candidate does not verify: %v", err)
	}
	restore()
	if err := history.verifyDecisionAdmission(history.decide(claimID, due, lateAt+20), lateAt+20); err != nil {
		t.Errorf("a successor admitted at the instant of the challenge is refused: %v", err)
	}
	for _, test := range []struct {
		name string
		vary signedHistoryVariation
		at   uint64
		want string
	}{
		{"an expectation of an open epoch", signedHistoryVariation{epoch: func(expectation *ClaimRevisionEpochExpectationV1) {
			expectation.ExpectedEpochState = "open"
		}}, lateAt + 30, "claim decision admission must reuse its head's frozen revision epoch and cut"},
		{"round counts other than the challenge left", varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) {
			body.ChallengeRoundsUsedBefore, body.ChallengeRoundsUsedAfter = 0, 0
		}), lateAt + 30, "successor claim decision admission round counts differ from its predecessor transition"},
		{"admitted a second before the challenge", signedHistoryVariation{}, lateAt + 19,
			"successor claim decision is admitted before its predecessor transition"},
	} {
		restore()
		history.vary = test.vary
		receipt := history.decide(claimID, due, test.at)
		refusedFor(t, test.name, history.verifyDecisionAdmission(receipt, lateAt+30), test.want)
	}

	other, otherClaimID, _ := lateCandidateChallenged(t, true)
	receipt := other.decide(otherClaimID, due, lateAt+30)
	refusedFor(t, "a successor on another claim admission than its candidate's", other.verifyDecisionAdmission(receipt, lateAt+30),
		"late-recovery successor stands on another claim admission than its candidate")
}

// verifyTransition is the claim state transition verifier at at.
func (history *signedHistory) verifyTransition(receipt AuthorizedClaimStateTransitionReceiptV1, at uint64) error {
	return VerifyClaimStateTransitionReceiptV1(receipt, history.terms, permissiveAgreementVerifier{}, history.resolver,
		history.fenceResolver, time.Unix(int64(at), 0).UTC())
}

// TestSignedHistoryTransitionActsInsideItsDecisionsWindow: a challenge is
// admitted from the instant its decision is admitted until the challenge
// window the admission opened ends. One admitted a second before the
// decision is refused. So is one admitted after the Agreement's window on a
// decision admission whose signed body states a longer window: the compact
// proof the challenge carries is held to the same window rule as the
// admission itself. The fallback path's admission is held to it as well.
func TestSignedHistoryTransitionActsInsideItsDecisionsWindow(t *testing.T) {
	decidedAt := uint64(signedHistoryStart + 100)
	decided := func(vary signedHistoryVariation) (*signedHistory, string, AuthorizedClaimDecisionAdmissionReceiptV1) {
		history := newSignedHistory(t)
		withSignedHistorySeam(t, history)
		claim := history.claim(1, nil, signedHistoryStart+30)
		history.admit(claim, signedHistoryStart+40)
		history.vary = vary
		receipt := history.decide(claim.Body.ClaimID, history.terms.PayoutDeadlineSeconds, decidedAt)
		// Every proof is sealed at the decision's admission, so a transition
		// differs from another only in its own time.
		history.vary = signedHistoryVariation{proofSealedAt: decidedAt}
		return history, claim.Body.ClaimID, receipt
	}
	history, claimID, receipt := decided(signedHistoryVariation{})
	end := receipt.Body.ChallengeEndsAtUnix
	restore := history.checkpoint(claimID)
	if err := history.verifyTransition(history.challenge(claimID, decidedAt), end+1000); err != nil {
		t.Errorf("a challenge at the instant of its decision's admission is refused: %v", err)
	}
	restore()
	if err := history.verifyTransition(history.challenge(claimID, end), end+1000); err != nil {
		t.Errorf("a challenge at the end of the challenge window is refused: %v", err)
	}
	restore()
	refusedFor(t, "a challenge a second before its decision's admission",
		history.verifyTransition(history.challenge(claimID, decidedAt-1), end+1000),
		"claim transition precedes the admission of its decision")
	restore()
	refusedFor(t, "a challenge a second after the window", history.verifyTransition(history.challenge(claimID, end+1), end+1000),
		"claim challenge admission is outside its closed window or budget")

	// The same challenge, a second after the Agreement's window, on a decision
	// admission signed with a window 1000 seconds longer.
	longer, longerClaimID, _ := decided(varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) {
		body.ChallengeEndsAtUnix += 1000
	}))
	refusedFor(t, "a challenge inside a window the admission lengthened",
		longer.verifyTransition(longer.challenge(longerClaimID, end+1), end+1000),
		"claim decision admission challenge window differs from its admission time and the decision's challenge window")

	// The deterministic fallback's admission opens the same window.
	for _, test := range []struct {
		name string
		vary signedHistoryVariation
		want string
	}{
		{"the initial terminal fallback", signedHistoryVariation{}, ""},
		{"the initial terminal fallback with a challenge window ending a second late",
			varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.ChallengeEndsAtUnix++ }),
			"claim decision admission challenge window differs from its admission time and the decision's challenge window"},
	} {
		fallback := newSignedHistory(t)
		withSignedHistorySeam(t, fallback)
		claim := fallback.claim(1, nil, signedHistoryStart+30)
		admission := fallback.admit(claim, signedHistoryStart+40)
		cutoff := admission.Body.AdmittedAtUnix + fallback.terms.ReviewDeadlineSeconds
		fallback.vary = test.vary
		err := fallback.verifyDecisionAdmission(fallback.fallback(claim.Body.ClaimID, nil, cutoff), cutoff)
		if test.want == "" {
			if err != nil {
				t.Errorf("%s is refused: %v", test.name, err)
			}
			continue
		}
		refusedFor(t, test.name, err, test.want)
	}
}
