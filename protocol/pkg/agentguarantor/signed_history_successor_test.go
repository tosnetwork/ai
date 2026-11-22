package agentguarantor

import (
	"testing"
)

// What a decision admission is held to beyond its own body, on signed
// history: the decision a compact proof restates, the transition a successor
// follows, the claim review cutoff of an initial terminal fallback where a
// terminal bundle carries them beside the proofs, and the late-recovery
// terminal deadline of everything admitted on the late-recovery path. Every
// refused object is complete and signed and differs from an accepted one in
// the named input alone.

// TestSignedHistoryDecisionProofRestatesItsDecisionsPathAndRevision: the
// receipt body of a compact decision proof names the decision path and the
// decision revision of the decision it admits. A proof whose signed body
// names another path or another revision is refused, alone and inside the
// challenge that embeds it.
func TestSignedHistoryDecisionProofRestatesItsDecisionsPathAndRevision(t *testing.T) {
	at := uint64(signedHistoryStart + 100)
	for _, test := range []struct {
		name string
		vary signedHistoryVariation
		want string
	}{
		{"a proof whose body restates its decision", signedHistoryVariation{}, ""},
		{"a proof whose body names another decision path",
			varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.DecisionPath = "successor" }),
			"claim decision admission compact proof states another decision path than its decision's"},
		{"a proof whose body names another decision revision",
			varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.DecisionRevision = 2 }),
			"claim decision admission compact proof states another decision revision than its decision's"},
	} {
		history, claimID := claimFiledAt(t, 40, nil)
		history.vary = test.vary
		receipt := history.decide(claimID, history.terms.PayoutDeadlineSeconds, at)
		history.vary = signedHistoryVariation{}
		expectVerdict(t, test.name, history.verifyDecisionProof(history.decisionProof(receipt, at), at+100), test.want)
		expectVerdict(t, "the challenge of "+test.name, history.verifyTransition(history.challenge(claimID, at+10), at+100), test.want)
	}
}

// TestSignedHistorySuccessorIsAdmittedByItsPredecessorsCutoff: an authorized
// successor decision is admitted no later than the successor cutoff of the
// transition it follows: accepted exactly at the cutoff, refused a second
// after it.
func TestSignedHistorySuccessorIsAdmittedByItsPredecessorsCutoff(t *testing.T) {
	at := uint64(signedHistoryStart + 100)
	for _, test := range []struct {
		name  string
		after uint64
		want  string
	}{
		{"a successor admitted at its predecessor transition's successor cutoff", 0, ""},
		{"a successor admitted a second after the cutoff", 1,
			"successor claim decision is admitted after its predecessor transition's successor cutoff"},
	} {
		history, claimID := claimFiledAt(t, 40, nil)
		history.decide(claimID, history.terms.PayoutDeadlineSeconds, at)
		due := history.challenge(claimID, at+10).Body.SuccessorDecisionDueAtUnix
		successor := history.decide(claimID, history.terms.PayoutDeadlineSeconds, due+test.after)
		expectVerdict(t, test.name, history.verifyDecisionAdmission(successor, due+test.after), test.want)
	}
}

// fallbackOnlyVerdict takes a claim admitted 40 s after the history's start
// to its terminal denial through the initial terminal fallback alone, admitted
// at under vary, and returns the terminal claim set verifier's verdict on the
// set that bundles it. The set carries compact proofs only.
func fallbackOnlyVerdict(t *testing.T, name string, vary signedHistoryVariation, at uint64) error {
	t.Helper()
	history, claimID := claimFiledAt(t, 40, nil)
	history.vary = vary
	denied := history.fallback(claimID, nil, at)
	history.vary = signedHistoryVariation{}
	closeAt := denied.Body.ChallengeEndsAtUnix
	history.challengeClose(claimID, closeAt)
	application := history.apply(claimID, history.materialize(claimID, history.terms), closeAt+10)
	filedAt := history.terms.ClaimFilingEndsAtUnix + 10
	filing := history.filingClose(filedAt)
	closedAt := filedAt + 10
	bundle := history.terminalBundle(claimID, application, closedAt)
	set := history.terminalSet(filing, []ClaimTerminalResolutionBundleV1{bundle}, closedAt)
	if err := ValidateTerminalClaimSetV1(set); err != nil {
		t.Errorf("%s: the set is already refused by its shape: %v", name, err)
	}
	return history.verifyTerminalSet(set, closedAt)
}

// TestSignedHistoryTerminalBundleHoldsAnInitialFallbackToTheReviewCutoff: a
// compact proof of an initial terminal fallback does not show when its claim
// was admitted, but a terminal bundle carries that admission beside it. The
// set verifies when the fallback was admitted exactly at the claim review
// cutoff and names it, and is refused when the fallback was admitted a second
// before the cutoff or its signed body names a cutoff a second earlier.
func TestSignedHistoryTerminalBundleHoldsAnInitialFallbackToTheReviewCutoff(t *testing.T) {
	const reviewDeadline = 600
	cutoff := uint64(signedHistoryStart + 40 + reviewDeadline)
	if deadline := newSignedHistory(t).terms.ReviewDeadlineSeconds; deadline != reviewDeadline {
		t.Fatalf("the signed-history terms review a claim for %d s, want %d", deadline, reviewDeadline)
	}
	for _, test := range []struct {
		name string
		vary signedHistoryVariation
		at   uint64
		want string
	}{
		{"an initial terminal fallback admitted at the claim review cutoff", signedHistoryVariation{}, cutoff, ""},
		{"an initial terminal fallback admitted a second before the claim review cutoff", signedHistoryVariation{}, cutoff - 1,
			"initial terminal fallback is admitted before the claim review cutoff"},
		{"an initial terminal fallback whose body names a cutoff a second before the claim review cutoff",
			varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.FallbackTriggerCutoffUnix-- }), cutoff,
			"initial terminal fallback names another trigger cutoff than the claim review cutoff"},
	} {
		expectVerdict(t, "the terminal claim set of "+test.name, fallbackOnlyVerdict(t, test.name, test.vary, test.at), test.want)
	}
}

// TestSignedHistoryTerminalBundleHoldsASuccessorToItsPredecessorTransition: a
// terminal bundle carries the challenge a successor follows beside the
// successor's compact proof. The set verifies when the fallback in place of
// the successor was admitted exactly at the challenge's successor cutoff with
// the challenge's resulting round counts, and is refused when that fallback
// was admitted a second before the cutoff, names a cutoff a second earlier, or
// starts from other round counts than the challenge left.
func TestSignedHistoryTerminalBundleHoldsASuccessorToItsPredecessorTransition(t *testing.T) {
	const decidedAfter = 100
	for _, test := range []struct {
		name   string
		vary   signedHistoryVariation
		before uint64
		want   string
	}{
		{"a fallback admitted at its predecessor challenge's successor cutoff", signedHistoryVariation{}, 0, ""},
		{"a fallback admitted a second before its predecessor challenge's successor cutoff", signedHistoryVariation{}, 1,
			"fallback in place of a successor is admitted before its predecessor transition's successor cutoff"},
		{"a fallback whose body names a cutoff a second before its predecessor challenge's successor cutoff",
			varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.FallbackTriggerCutoffUnix-- }), 0,
			"fallback in place of a successor names another trigger cutoff than its predecessor transition's successor cutoff"},
		{"a fallback whose body starts from no consumed challenge round",
			varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) {
				body.ChallengeRoundsUsedBefore, body.ChallengeRoundsUsedAfter = 0, 0
			}), 0, "successor claim decision admission round counts differ from its predecessor transition"},
	} {
		history, claimID := claimFiledAt(t, 40, nil)
		decidedAt := uint64(signedHistoryStart + decidedAfter)
		history.decide(claimID, history.terms.PayoutDeadlineSeconds, decidedAt)
		chain := ordinaryChain{history: history, claimID: claimID, challenge: history.challenge(claimID, decidedAt+10)}
		history.vary = test.vary
		denied := history.fallback(claimID, nil, chain.challenge.Body.SuccessorDecisionDueAtUnix-test.before)
		history.vary = signedHistoryVariation{}
		closeAt := denied.Body.ChallengeEndsAtUnix
		history.challengeClose(claimID, closeAt)
		chain.application = history.apply(claimID, history.materialize(claimID, history.terms), closeAt+10)
		filedAt := history.terms.ClaimFilingEndsAtUnix + 10
		chain.filing = history.filingClose(filedAt)
		chain.closedAt = filedAt + 10
		_, err := chain.verdict(t, test.name)
		expectVerdict(t, "the terminal claim set of "+test.name, err, test.want)
	}
}

// TestSignedHistoryLatePathSuccessorFitsTheLateRecoveryDeadline: everything
// admitted on the late-recovery path closes by the late-recovery terminal
// deadline. The candidate is admitted a second before the late-ingress
// recovery deadline, the last second its decision body allows, and challenged
// at the end of its window, so the fallback in place of its successor closes
// exactly at the deadline when admitted a second after the successor cutoff
// and is accepted, as a receipt and as a compact proof. The same fallback
// admitted one second later, which nothing else bounds, is refused as both.
func TestSignedHistoryLatePathSuccessorFitsTheLateRecoveryDeadline(t *testing.T) {
	const noRoom = "late-recovery successor decision admission leaves no room to close by the late-recovery terminal deadline"
	for _, test := range []struct {
		name  string
		after uint64
		want  string
	}{
		{"the fallback in place of a late successor that closes at the late-recovery terminal deadline", 1, ""},
		{"the same fallback admitted a second later", 2, noRoom},
	} {
		history, claimID := claimFiledAt(t, 40, nil)
		terms := history.terms
		filing := history.filingClose(terms.TerminalResolutionDeadlineUnix + 60)
		candidate := history.fallback(claimID, &filing, terms.LateIngressRecoveryDeadlineUnix-1)
		due := history.challenge(claimID, candidate.Body.ChallengeEndsAtUnix).Body.SuccessorDecisionDueAtUnix
		at := due + test.after
		fallback := history.fallback(claimID, nil, at)
		if closes := due + 1 + lateRecoveryCandidateClosureSecondsV1(terms, terms.ClaimClosureCapacity.MaximumChallengeRoundsPerClaim); closes != terms.LateRecoveryTerminalDeadlineUnix {
			t.Fatalf("%s: a fallback a second after the successor cutoff closes at %d, want the late-recovery terminal deadline %d",
				test.name, closes, terms.LateRecoveryTerminalDeadlineUnix)
		}
		expectVerdict(t, test.name+": the full receipt", history.verifyDecisionAdmission(fallback, at), test.want)
		expectVerdict(t, test.name+": the compact proof", history.verifyDecisionProof(history.decisionProof(fallback, at), at+100), test.want)
	}
}
