package agentguarantor

import (
	"math"
	"testing"
	"time"
)

// The time and round rules of a decision admission on signed history, through
// every object that carries one: the full receipt, its compact proof, the
// transition and the application that embed the proof, and the terminal claim
// set that bundles it. Every refused object is complete and signed and differs
// from an accepted one in the named input alone.

// verifyDecisionProof is the compact decision proof verifier at at.
func (history *signedHistory) verifyDecisionProof(proof ClaimDecisionAdmissionReceiptProofV1, at uint64) error {
	return VerifyClaimDecisionAdmissionReceiptProofV1(proof, history.terms, history.resolver, time.Unix(int64(at), 0).UTC())
}

// decidedBetween moves the next authorized decision's decided-at and expiry
// times to the given offsets from its admission time.
func decidedBetween(decidedAfter, expiresAfter int64) signedHistoryVariation {
	return signedHistoryVariation{decision: func(body *ClaimDecisionBodyV1) {
		at := int64(body.DecidedAtUnix)
		body.DecidedAtUnix, body.ExpiresAtUnix = uint64(at+decidedAfter), uint64(at+expiresAfter)
	}}
}

// claimFiledAt is a fresh history, under terms when given, with one claim
// admitted admittedAfter seconds after the history's start.
func claimFiledAt(t *testing.T, admittedAfter uint64, terms *CoverageTermsV1) (*signedHistory, string) {
	t.Helper()
	history := newSignedHistory(t)
	withSignedHistorySeam(t, history)
	if terms != nil {
		history.terms, history.offer.CoverageTerms = *terms, *terms
	}
	claim := history.claim(1, nil, signedHistoryStart+admittedAfter-10)
	history.admit(claim, signedHistoryStart+admittedAfter)
	return history, claim.Body.ClaimID
}

// ordinaryChain is one claim taken to its terminal denial off the
// late-recovery path, with claim filing closed in time: an authorized initial
// decision that approves it, the challenge of that decision, the terminal
// fallback at the successor deadline, its challenge close and its application.
type ordinaryChain struct {
	history     *signedHistory
	claimID     string
	filing      AuthorizedClaimFilingCloseReceiptV1
	challenge   AuthorizedClaimStateTransitionReceiptV1
	application AuthorizedClaimDecisionApplicationReceiptV1
	closedAt    uint64
}

// newOrdinaryChain admits the claim 40 seconds after the history's start and
// its initial decision, signed under vary, decidedAfter seconds after it.
func newOrdinaryChain(t *testing.T, decidedAfter uint64, vary signedHistoryVariation) ordinaryChain {
	t.Helper()
	history, claimID := claimFiledAt(t, 40, nil)
	return ordinaryChainOn(t, history, claimID, decidedAfter, vary)
}

// claimRevisedAt is a fresh history with one claim admitted 40 seconds after
// the history's start and its second revision admitted revisedAfter seconds
// after the start.
func claimRevisedAt(t *testing.T, revisedAfter uint64) (*signedHistory, string) {
	t.Helper()
	history := newSignedHistory(t)
	withSignedHistorySeam(t, history)
	claim := history.claim(1, nil, signedHistoryStart+30)
	history.admit(claim, signedHistoryStart+40)
	revised := history.claim(2, &claim, signedHistoryStart+revisedAfter-10)
	history.admit(revised, signedHistoryStart+revisedAfter)
	return history, claim.Body.ClaimID
}

// ordinaryChainOn takes the history's admitted claim through an ordinaryChain
// whose initial decision, signed under vary, is admitted decidedAfter seconds
// after the history's start.
func ordinaryChainOn(t *testing.T, history *signedHistory, claimID string, decidedAfter uint64,
	vary signedHistoryVariation) ordinaryChain {
	t.Helper()
	decidedAt := signedHistoryStart + decidedAfter
	history.vary = vary
	history.decide(claimID, history.terms.PayoutDeadlineSeconds, decidedAt)
	history.vary = signedHistoryVariation{}
	chain := ordinaryChain{history: history, claimID: claimID, challenge: history.challenge(claimID, decidedAt+10)}
	denied := history.fallback(claimID, nil, chain.challenge.Body.SuccessorDecisionDueAtUnix)
	closeAt := denied.Body.ChallengeEndsAtUnix
	history.challengeClose(claimID, closeAt)
	chain.application = history.apply(claimID, history.materialize(claimID, history.terms), closeAt+10)
	filedAt := history.terms.ClaimFilingEndsAtUnix + 10
	chain.filing = history.filingClose(filedAt)
	chain.closedAt = filedAt + 10
	return chain
}

// verdict signs the terminal claim set over the chain's filing close and its
// bundle of the complete decision history, and returns the verifier's verdict.
// The set must pass the shape validation: a refusal has to come from the
// bindings or from a carried object.
func (chain ordinaryChain) verdict(t *testing.T, name string) (AuthorizedTerminalClaimSetEvidenceV1, error) {
	t.Helper()
	history := chain.history
	bundle := history.terminalBundle(chain.claimID, chain.application, chain.closedAt)
	bundle.DecisionAdmissionReceiptProofs = []ClaimDecisionAdmissionReceiptProofV1{
		chain.challenge.DecisionAdmissionProof, bundle.DecisionAdmissionReceiptProofs[0]}
	bundle.ClaimStateTransitionReceipts = []AuthorizedClaimStateTransitionReceiptV1{
		chain.challenge, bundle.ClaimStateTransitionReceipts[0]}
	bundle.ResolutionRef = history.terminalRef(bundle)
	set := history.terminalSet(chain.filing, []ClaimTerminalResolutionBundleV1{bundle}, chain.closedAt)
	if err := ValidateTerminalClaimSetV1(set); err != nil {
		t.Errorf("%s: the set is already refused by its shape: %v", name, err)
	}
	return set, history.verifyTerminalSet(set, chain.closedAt)
}

// TestSignedHistoryCompactProofHoldsADecisionToItsOwnAdmissionBounds: an
// authorized decision is admitted between its decided-at and expiry times.
// The full receipt, its compact proof, the challenge close and the
// application that embed the proof, and a terminal claim set that bundles it
// all accept a decision admitted exactly at either bound and refuse one
// admitted a second outside it. A deterministic fallback is decided at its
// admission time, and its proof is refused when the body states another.
func TestSignedHistoryCompactProofHoldsADecisionToItsOwnAdmissionBounds(t *testing.T) {
	const expired = "authorized claim decision is admitted after its expiry"
	const undecided = "authorized claim decision is admitted before it was decided"
	for _, test := range []struct {
		name string
		vary signedHistoryVariation
		want string
	}{
		{"admitted exactly at its expiry", decidedBetween(-10, 0), ""},
		{"admitted a second after its expiry", decidedBetween(-10, -1), expired},
		{"admitted exactly when it was decided", decidedBetween(0, 600), ""},
		{"admitted a second before it was decided", decidedBetween(1, 600), undecided},
	} {
		history, claimID := claimFiledAt(t, 40, nil)
		at := uint64(signedHistoryStart + 100)
		history.vary = test.vary
		receipt := history.decide(claimID, history.terms.PayoutDeadlineSeconds, at)
		history.vary = signedHistoryVariation{}
		end := receipt.Body.ChallengeEndsAtUnix
		later := end + 100
		verdicts := []struct {
			object string
			err    error
		}{{"the full receipt", history.verifyDecisionAdmission(receipt, at)},
			{"the compact proof", history.verifyDecisionProof(history.decisionProof(receipt, at), later)},
			{"the challenge close on the proof", history.verifyTransition(history.challengeClose(claimID, end), later)},
			{"the application on the proof", history.verifyApplication(
				history.apply(claimID, history.materialize(claimID, history.terms), end+10), later)}}
		for _, verdict := range verdicts {
			if test.want == "" {
				if verdict.err != nil {
					t.Errorf("%s: %s is refused: %v", test.name, verdict.object, verdict.err)
				}
				continue
			}
			refusedFor(t, test.name+": "+verdict.object, verdict.err, test.want)
		}
	}

	// The same bounds inside a terminal claim set, which carries proofs only.
	for _, test := range []struct {
		name string
		vary signedHistoryVariation
		want string
	}{
		{"a set whose initial decision was admitted at its expiry", decidedBetween(-10, 0), ""},
		{"a set whose initial decision was admitted a second after its expiry", decidedBetween(-10, -1), expired},
		{"a set whose initial decision was admitted a second before it was decided", decidedBetween(1, 600), undecided},
	} {
		_, err := newOrdinaryChain(t, 100, test.vary).verdict(t, test.name)
		if test.want == "" {
			if err != nil {
				t.Errorf("%s is refused: %v", test.name, err)
			}
			continue
		}
		refusedFor(t, test.name, err, test.want)
	}

	// The proof of a deterministic fallback, and of one whose signed body
	// states an admission time a second after the fallback was decided.
	for _, test := range []struct {
		name string
		vary signedHistoryVariation
		want string
	}{
		{"the initial terminal fallback", signedHistoryVariation{}, ""},
		{"the initial terminal fallback admitted a second after it was decided",
			varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) {
				body.AdmittedAtUnix++
				body.ChallengeStartsAtUnix++
				body.ChallengeEndsAtUnix++
			}), "deterministic fallback decision is not decided at its admission time"},
	} {
		history, claimID := claimFiledAt(t, 40, nil)
		cutoff := uint64(signedHistoryStart + 40 + history.terms.ReviewDeadlineSeconds)
		history.vary = test.vary
		fallback := history.fallback(claimID, nil, cutoff)
		err := history.verifyDecisionProof(history.decisionProof(fallback, cutoff+1), cutoff+100)
		if test.want == "" {
			if err != nil {
				t.Errorf("the compact proof of %s is refused: %v", test.name, err)
			}
			continue
		}
		refusedFor(t, "the compact proof of "+test.name, err, test.want)
	}

	// The full receipt of a fallback whose decision is dated a second before
	// the admission that materialized it.
	early, earlyClaimID := claimFiledAt(t, 40, nil)
	earlyCutoff := uint64(signedHistoryStart + 40 + early.terms.ReviewDeadlineSeconds)
	early.vary = decidedBetween(-1, 600)
	refusedFor(t, "the initial terminal fallback decided a second before its admission",
		early.verifyDecisionAdmission(early.fallback(earlyClaimID, nil, earlyCutoff), earlyCutoff),
		"deterministic fallback decision is not decided at its admission time")

	// A proof whose signed body states no admission time at all.
	history, claimID := claimFiledAt(t, 40, nil)
	at := uint64(signedHistoryStart + 100)
	history.vary = varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) {
		body.AdmittedAtUnix, body.ChallengeStartsAtUnix, body.ChallengeEndsAtUnix = 0, 0, history.terms.ChallengeWindowSeconds
	})
	timeless := history.decide(claimID, history.terms.PayoutDeadlineSeconds, at)
	refusedFor(t, "the compact proof of a decision admission without an admission time",
		history.verifyDecisionProof(history.decisionProof(timeless, at), at+100),
		"claim decision admission time is absent or out of range")
}

// TestSignedHistoryTerminalBundleHoldsAnInitialDecisionToItsClaimAdmission: a
// compact decision proof does not show when its claim was admitted, but a
// terminal bundle carries that admission beside it. The set verifies when the
// claim's initial decision was admitted exactly at the claim review cutoff
// and closes the coverage at the filing close's own revision; it is refused
// when the initial decision was admitted a second after the cutoff or a
// second before the claim.
func TestSignedHistoryTerminalBundleHoldsAnInitialDecisionToItsClaimAdmission(t *testing.T) {
	for _, test := range []struct {
		name         string
		decidedAfter uint64
		want         string
	}{
		{"an initial decision admitted at the claim review cutoff", 40 + 600, ""},
		{"an initial decision admitted a second after the claim review cutoff", 40 + 601,
			"initial claim decision is admitted after the claim review cutoff"},
		{"an initial decision admitted a second before its claim", 39, "claim decision is admitted before its claim admission"},
	} {
		set, err := newOrdinaryChain(t, test.decidedAfter, signedHistoryVariation{}).verdict(t, test.name)
		if test.want != "" {
			refusedFor(t, "the terminal claim set of "+test.name, err, test.want)
			continue
		}
		if err != nil {
			t.Errorf("the terminal claim set of %s is refused: %v", test.name, err)
		}
		if set.Body.PriorCoverageRevision != set.Body.FilingCloseCoverageRevision {
			t.Errorf("the set closes at revision %d, want the filing close's own, %d",
				set.Body.PriorCoverageRevision, set.Body.FilingCloseCoverageRevision)
		}
	}
}

// TestSignedHistoryReviewCutoffRunsFromTheInitialAdmission: the claim review
// cutoff is the claim's initial admission time plus the review deadline, and
// a revision admitted later does not move it. The claim is admitted at 40 s
// and revised at 500 s, so with a 600 s deadline the cutoff is 640 s, not
// 1100 s. An authorized initial decision on the revision is accepted exactly
// at 640 s and refused a second later, as a full receipt and inside a
// terminal bundle; the initial terminal fallback is eligible exactly at 640 s
// and refused a second earlier.
func TestSignedHistoryReviewCutoffRunsFromTheInitialAdmission(t *testing.T) {
	const pastCutoff = "initial claim decision is admitted after the claim review cutoff"
	const cutoffAfter = 40 + 600
	for _, test := range []struct {
		name         string
		decidedAfter uint64
		want         string
	}{
		{"a decision on the revision at the initial admission's cutoff", cutoffAfter, ""},
		{"a decision on the revision a second after the initial admission's cutoff", cutoffAfter + 1, pastCutoff},
	} {
		history, claimID := claimRevisedAt(t, 500)
		at := signedHistoryStart + test.decidedAfter
		receiptErr := history.verifyDecisionAdmission(history.decide(claimID, history.terms.PayoutDeadlineSeconds, at), at)
		bundled, bundledID := claimRevisedAt(t, 500)
		_, setErr := ordinaryChainOn(t, bundled, bundledID, test.decidedAfter, signedHistoryVariation{}).verdict(t, test.name)
		if test.want == "" {
			if receiptErr != nil || setErr != nil {
				t.Errorf("%s is refused: receipt %v, terminal claim set %v", test.name, receiptErr, setErr)
			}
			continue
		}
		refusedFor(t, test.name+": the full receipt", receiptErr, test.want)
		refusedFor(t, test.name+": the terminal claim set", setErr, test.want)
	}
	for _, test := range []struct {
		name          string
		admittedAfter uint64
		want          string
	}{
		{"the initial terminal fallback on the revision at the initial admission's cutoff", cutoffAfter, ""},
		{"the initial terminal fallback on the revision a second before the initial admission's cutoff", cutoffAfter - 1,
			"initial terminal fallback is admitted before the claim review cutoff"},
	} {
		history, claimID := claimRevisedAt(t, 500)
		at := signedHistoryStart + test.admittedAfter
		fallback := history.fallback(claimID, nil, at)
		if fallback.Body.FallbackTriggerCutoffUnix != signedHistoryStart+cutoffAfter {
			t.Fatalf("the fallback's trigger cutoff is %d, want %d", fallback.Body.FallbackTriggerCutoffUnix, uint64(signedHistoryStart+cutoffAfter))
		}
		err := history.verifyDecisionAdmission(fallback, at)
		if test.want == "" {
			if err != nil {
				t.Errorf("%s is refused: %v", test.name, err)
			}
			continue
		}
		refusedFor(t, test.name, err, test.want)
	}
}

// TestSignedHistoryNonterminalResultNeedsARemainingRound: evidence_required
// and disputed are admitted only while a nonterminal round remains, and never
// as the successor of a challenged candidate. Under terms that allow one
// nonterminal round an initial disputed decision verifies as a receipt and as
// a compact proof; under terms that allow none, both refuse it. The approved
// successor of a challenged decision verifies; the disputed one is refused,
// as a receipt for its predecessor and as a compact proof for the token it
// replaces.
func TestSignedHistoryNonterminalResultNeedsARemainingRound(t *testing.T) {
	const noRound = "nonterminal claim decision is admitted with no nonterminal round remaining"
	at := uint64(signedHistoryStart + 100)
	for _, test := range []struct {
		name   string
		rounds uint64
		want   string
	}{
		{"an initial disputed decision with one nonterminal round", 1, ""},
		{"an initial disputed decision with no nonterminal round", 0, noRound},
	} {
		history := newSignedHistory(t)
		terms := history.terms
		entries, err := BuildClaimContinuationBudgetEntriesV1(terms.ClaimClosureCapacity.MaximumChallengeRoundsPerClaim, test.rounds,
			terms.ReviewDeadlineSeconds, terms.ChallengeWindowSeconds, terms.NonterminalResolutionWindowSeconds,
			terms.SuccessorDecisionWindowSeconds, terms.PayoutDeadlineSeconds, terms.AdapterRecoveryWindowSeconds)
		if err != nil {
			t.Fatal(err)
		}
		terms.ClaimClosureCapacity.MaximumNonterminalRoundsPerClaim = test.rounds
		terms.ClaimClosureCapacity.ContinuationBudgetEntries = entries
		if err := ValidateCoverageTerms(terms); err != nil {
			t.Fatalf("%s: the terms are invalid: %v", test.name, err)
		}
		history, claimID := claimFiledAt(t, 40, &terms)
		history.vary = signedHistoryVariation{nonterminal: true}
		receipt := history.decide(claimID, terms.PayoutDeadlineSeconds, at)
		for object, verdict := range map[string]error{
			"the full receipt":  history.verifyDecisionAdmission(receipt, at),
			"the compact proof": history.verifyDecisionProof(history.decisionProof(receipt, at), at+100)} {
			if test.want == "" {
				if verdict != nil {
					t.Errorf("%s: %s is refused: %v", test.name, object, verdict)
				}
				continue
			}
			refusedFor(t, test.name+": "+object, verdict, test.want)
		}
	}

	for _, test := range []struct {
		name               string
		vary               signedHistoryVariation
		receipt, proofWant string
	}{
		{"the approved successor of a challenged decision", signedHistoryVariation{}, "", ""},
		{"the disputed successor of a challenged decision", signedHistoryVariation{nonterminal: true},
			"challenge successor claim decision produces another nonterminal result",
			"nonterminal claim decision admission replaces an application token"},
	} {
		history, claimID := claimFiledAt(t, 40, nil)
		history.decide(claimID, history.terms.PayoutDeadlineSeconds, at)
		history.challenge(claimID, at+10)
		history.vary = test.vary
		successor := history.decide(claimID, history.terms.PayoutDeadlineSeconds, at+20)
		receiptErr := history.verifyDecisionAdmission(successor, at+20)
		proofErr := history.verifyDecisionProof(history.decisionProof(successor, at+20), at+100)
		if test.receipt == "" {
			if receiptErr != nil || proofErr != nil {
				t.Errorf("%s is refused: receipt %v, proof %v", test.name, receiptErr, proofErr)
			}
			continue
		}
		refusedFor(t, test.name+": the full receipt", receiptErr, test.receipt)
		refusedFor(t, test.name+": the compact proof", proofErr, test.proofWant)
	}
}

// TestSignedHistoryOrdinaryDecisionAdmissionFitsTheTerminalResolutionDeadline:
// off the late-recovery path a decision admission leaves room for the complete
// remaining closure of the state it admits before the terminal resolution
// deadline: an approving decision and the initial terminal fallback need the
// closure of a challengeable candidate, a disputed decision the longer one of
// its nonterminal state. Each is accepted when its closure ends exactly at the
// deadline and refused when admitted a second later, as a receipt and as a
// compact proof.
func TestSignedHistoryOrdinaryDecisionAdmissionFitsTheTerminalResolutionDeadline(t *testing.T) {
	const noRoom = "claim decision admission leaves no room to close by the terminal resolution deadline"
	terms := newSignedHistory(t).terms
	candidate := lateRecoveryCandidateClosureSecondsV1(terms, 0)
	if candidate != 3000 || terms.NonterminalResolutionWindowSeconds != 600 || terms.ReviewDeadlineSeconds != 600 {
		t.Fatalf("the signed-history terms close a candidate in %d s, want 3000 with 600 s windows", candidate)
	}
	// The deadline leaves a candidate admitted 7100 s after the start exactly
	// its closure, and a disputed decision admitted at 6500 s exactly its own,
	// which is one nonterminal resolution window longer.
	terms.TerminalResolutionDeadlineUnix = signedHistoryStart + 7100 + candidate
	terms.LateIngressRecoveryDeadlineUnix = terms.TerminalResolutionDeadlineUnix + terms.LateIngressRecoveryWindowSeconds
	terms.LateRecoveryTerminalDeadlineUnix = terms.LateIngressRecoveryDeadlineUnix + candidate
	if err := ValidateCoverageTerms(terms); err != nil {
		t.Fatalf("the terms with the earlier deadline are invalid: %v", err)
	}
	approve := func(history *signedHistory, claimID string, at uint64) AuthorizedClaimDecisionAdmissionReceiptV1 {
		return history.decide(claimID, terms.PayoutDeadlineSeconds, at)
	}
	dispute := func(history *signedHistory, claimID string, at uint64) AuthorizedClaimDecisionAdmissionReceiptV1 {
		history.vary = signedHistoryVariation{nonterminal: true}
		return history.decide(claimID, terms.PayoutDeadlineSeconds, at)
	}
	fallBack := func(history *signedHistory, claimID string, at uint64) AuthorizedClaimDecisionAdmissionReceiptV1 {
		return history.fallback(claimID, nil, at)
	}
	for _, test := range []struct {
		name                   string
		claimAdmitted, decided uint64
		admit                  func(*signedHistory, string, uint64) AuthorizedClaimDecisionAdmissionReceiptV1
		want                   string
	}{
		{"an approving decision whose closure ends at the deadline", 7000, 7100, approve, ""},
		{"an approving decision admitted a second later", 7000, 7101, approve, noRoom},
		{"a disputed decision whose closure ends at the deadline", 6400, 6500, dispute, ""},
		{"a disputed decision admitted a second later", 6400, 6501, dispute, noRoom},
		{"the initial terminal fallback whose closure ends at the deadline", 6500, 7100, fallBack, ""},
		{"the initial terminal fallback admitted a second later", 6501, 7101, fallBack, noRoom},
	} {
		history, claimID := claimFiledAt(t, test.claimAdmitted, &terms)
		at := signedHistoryStart + test.decided
		receipt := test.admit(history, claimID, at)
		for object, verdict := range map[string]error{
			"the full receipt":  history.verifyDecisionAdmission(receipt, at),
			"the compact proof": history.verifyDecisionProof(history.decisionProof(receipt, at), at+100)} {
			if test.want == "" {
				if verdict != nil {
					t.Errorf("%s: %s is refused: %v", test.name, object, verdict)
				}
				continue
			}
			refusedFor(t, test.name+": "+object, verdict, test.want)
		}
	}
}

// TestSignedHistoryReceiptTimeIsItsStageAdmissionTime: the time a decision
// admission, a transition or an application receipt body states is the time
// its stage action was admitted at, lies in the range of a protocol timestamp
// and is not after the verifier's present. A body signed with another time
// than its stage admission evidence (here to move an expired decision back
// inside its validity, a late challenge back inside its window, and an
// application) is refused for the difference.
func TestSignedHistoryReceiptTimeIsItsStageAdmissionTime(t *testing.T) {
	at := uint64(signedHistoryStart + 100)
	const clockAllowance = uint64(stageAdmissionClockAllowanceV1 / time.Second)
	backdated := decidedBetween(-60, -50)
	backdated.receiptAt = at - 50
	for _, test := range []struct {
		name string
		vary signedHistoryVariation
		now  uint64
		want string
	}{
		{"a decision admission verified at its admission time", signedHistoryVariation{}, at, ""},
		{"a decision admission whose body is signed 50 s before its stage admission, at the decision's expiry", backdated, at,
			"claim decision admission time differs from its stage action admission evidence's"},
		{"a decision admission verified by a clock the whole allowance behind", signedHistoryVariation{}, at - clockAllowance, ""},
		{"a decision admission verified by a clock a second further behind", signedHistoryVariation{}, at - clockAllowance - 1,
			"claim decision admission time is after the verifier's present"},
		{"a decision admission time past the range of a timestamp", signedHistoryVariation{receiptAt: 1 << 63}, at,
			"claim decision admission time is absent or out of range"},
	} {
		history, claimID := claimFiledAt(t, 40, nil)
		history.vary = test.vary
		receipt := history.decide(claimID, history.terms.PayoutDeadlineSeconds, at)
		err := history.verifyDecisionAdmission(receipt, test.now)
		if test.want == "" {
			if err != nil {
				t.Errorf("%s is refused: %v", test.name, err)
			}
			continue
		}
		refusedFor(t, test.name, err, test.want)
	}

	history, claimID := claimFiledAt(t, 40, nil)
	end := history.decide(claimID, history.terms.PayoutDeadlineSeconds, at).Body.ChallengeEndsAtUnix
	later := end + 1000
	restore := history.checkpoint(claimID)
	history.vary = signedHistoryVariation{proofSealedAt: at}
	if err := history.verifyTransition(history.challenge(claimID, end), later); err != nil {
		t.Errorf("a challenge at the end of its window is refused: %v", err)
	}
	restore()
	history.vary = signedHistoryVariation{proofSealedAt: at, receiptAt: end}
	refusedFor(t, "a challenge admitted 50 s after its window whose body states the end of the window",
		history.verifyTransition(history.challenge(claimID, end+50), later),
		"claim transition time differs from its stage action admission evidence's")
	restore()
	history.vary = signedHistoryVariation{}
	history.challengeClose(claimID, end)
	restore = history.checkpoint(claimID)
	if err := history.verifyApplication(history.apply(claimID, history.materialize(claimID, history.terms), end+10), later); err != nil {
		t.Errorf("the application of the closed decision is refused: %v", err)
	}
	restore()
	history.vary = signedHistoryVariation{receiptAt: end + 10}
	refusedFor(t, "an application admitted 50 s after the time its body states",
		history.verifyApplication(history.apply(claimID, history.materialize(claimID, history.terms), end+60), later),
		"decision application time differs from its stage action admission evidence's")
}

// TestSignedHistoryLateCandidateProofNamesItsFilingClose: the successor of a
// challenged late-recovery candidate is recognized by the late filing-close
// digest the candidate's admission carries. The compact proof of a candidate
// and the challenge on it verify; a candidate whose signed body omits the
// digest is refused as a proof, and so is the challenge that embeds it.
func TestSignedHistoryLateCandidateProofNamesItsFilingClose(t *testing.T) {
	for _, test := range []struct {
		name string
		vary signedHistoryVariation
		want string
	}{
		{"a late-recovery candidate", signedHistoryVariation{}, ""},
		{"a late-recovery candidate without its late filing-close digest",
			varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) { body.LateFilingCloseReceiptDigest = "" }),
			"late-recovery candidate compact proof names no late filing close"},
	} {
		history, claimID := claimFiledAt(t, 40, nil)
		lateAt := history.terms.TerminalResolutionDeadlineUnix + 60
		filing := history.filingClose(lateAt)
		history.vary = test.vary
		candidate := history.fallback(claimID, &filing, lateAt+10)
		history.vary = signedHistoryVariation{}
		proofErr := history.verifyDecisionProof(history.decisionProof(candidate, lateAt+10), lateAt+100)
		challengeErr := history.verifyTransition(history.challenge(claimID, lateAt+20), lateAt+100)
		if test.want == "" {
			if proofErr != nil || challengeErr != nil {
				t.Errorf("%s is refused: proof %v, challenge %v", test.name, proofErr, challengeErr)
			}
			continue
		}
		refusedFor(t, "the compact proof of "+test.name, proofErr, test.want)
		refusedFor(t, "the challenge of "+test.name, challengeErr, test.want)
	}
}

// TestSignedHistoryRevisionAtTheTopOfTheRangeHasNoSuccessor: a receipt moves a
// revision by exactly one. A decision admission signed over a coverage
// revision at the top of the range and a resulting revision of zero, which is
// what an unchecked increment yields, is refused.
func TestSignedHistoryRevisionAtTheTopOfTheRangeHasNoSuccessor(t *testing.T) {
	at := uint64(signedHistoryStart + 100)
	for _, test := range []struct {
		name string
		vary signedHistoryVariation
		want string
	}{
		{"a coverage revision moved by one", signedHistoryVariation{}, ""},
		{"a coverage revision that wraps to zero", varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) {
			body.PriorCoverageRevision, body.AdmittedCoverageRevision = math.MaxUint64, 0
		}), "claim decision admission receipt binding is invalid"},
	} {
		history, claimID := claimFiledAt(t, 40, nil)
		history.vary = test.vary
		receipt := history.decide(claimID, history.terms.PayoutDeadlineSeconds, at)
		err := history.verifyDecisionAdmission(receipt, at)
		if test.want == "" {
			if err != nil {
				t.Errorf("%s is refused: %v", test.name, err)
			}
			continue
		}
		refusedFor(t, test.name, err, test.want)
	}
}
