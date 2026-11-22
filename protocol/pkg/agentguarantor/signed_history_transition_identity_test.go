package agentguarantor

import (
	"testing"
	"time"
)

// A transition is of the claim and coverage of the decision admission it
// embeds; a decision is applied no earlier than its challenge close; and a
// verifier whose clock runs behind the admitting authority's by no more than
// the stage admission clock allowance still accepts a fresh proof and the
// transition that embeds it. Every refused object is complete and signed and
// differs from an accepted one in the named input alone.

// TestSignedHistoryTransitionIsOfItsDecisionAdmissionsClaim: a challenge whose
// request and receipt body are signed for another claim, another Agreement or
// another obligation than the decision admission it embeds is refused by the
// transition verifier itself.
func TestSignedHistoryTransitionIsOfItsDecisionAdmissionsClaim(t *testing.T) {
	at := uint64(signedHistoryStart + 100)
	request := func(change func(*ClaimStateTransitionActionBodyV1)) signedHistoryVariation {
		return signedHistoryVariation{transitionRequest: change}
	}
	for _, test := range []struct {
		name string
		vary signedHistoryVariation
		want string
	}{
		{"a challenge of its decision's claim", signedHistoryVariation{}, ""},
		{"a challenge signed for another claim", request(func(body *ClaimStateTransitionActionBodyV1) { body.ClaimID = testDigest("6") }),
			"claim transition is of another claim than its decision admission"},
		{"a challenge signed for another Agreement", request(func(body *ClaimStateTransitionActionBodyV1) {
			body.CoverageAgreementBodyDigest = testDigest("9")
		}), "claim transition is on another Agreement than its decision admission"},
		{"a challenge signed for another obligation", request(func(body *ClaimStateTransitionActionBodyV1) {
			body.CoverageObligationID = "obligation:other"
		}), "claim transition is on another obligation than its decision admission"},
	} {
		history, claimID := claimFiledAt(t, 40, nil)
		history.decide(claimID, history.terms.PayoutDeadlineSeconds, at)
		history.vary = test.vary
		err := history.verifyTransition(history.challenge(claimID, at+10), at+100)
		if test.want == "" {
			if err != nil {
				t.Errorf("%s is refused: %v", test.name, err)
			}
			continue
		}
		refusedFor(t, test.name, err, test.want)
	}
}

// TestSignedHistoryApplicationFollowsItsChallengeClose: the full application
// receipt carries the challenge close that made its decision terminal, and is
// applied no earlier than it: accepted at the instant of the close, refused a
// second before.
func TestSignedHistoryApplicationFollowsItsChallengeClose(t *testing.T) {
	at := uint64(signedHistoryStart + 100)
	history, claimID := claimFiledAt(t, 40, nil)
	end := history.decide(claimID, history.terms.PayoutDeadlineSeconds, at).Body.ChallengeEndsAtUnix
	history.challengeClose(claimID, end)
	restore := history.checkpoint(claimID)
	if err := history.verifyApplication(history.apply(claimID, history.materialize(claimID, history.terms), end), end+100); err != nil {
		t.Errorf("an application at the instant of its challenge close is refused: %v", err)
	}
	restore()
	refusedFor(t, "an application a second before its challenge close",
		history.verifyApplication(history.apply(claimID, history.materialize(claimID, history.terms), end-1), end+100),
		"claim decision is applied before its challenge close")
}

// TestSignedHistoryProofAllowsTheStageAdmissionClockSkew: a compact decision
// proof sealed up to the stage admission clock allowance after the verifier's
// present verifies, alone and inside the challenge that embeds it; one sealed
// a second further ahead is refused.
func TestSignedHistoryProofAllowsTheStageAdmissionClockSkew(t *testing.T) {
	const allowance = uint64(stageAdmissionClockAllowanceV1 / time.Second)
	at := uint64(signedHistoryStart + 100)
	history, claimID := claimFiledAt(t, 40, nil)
	receipt := history.decide(claimID, history.terms.PayoutDeadlineSeconds, at)
	sealedAt := at + 10
	proof := history.decisionProof(receipt, sealedAt)
	if err := history.verifyDecisionProof(proof, sealedAt-allowance); err != nil {
		t.Errorf("a proof sealed the whole allowance after the verifier's present is refused: %v", err)
	}
	refusedFor(t, "a proof sealed a second beyond the allowance", history.verifyDecisionProof(proof, sealedAt-allowance-1),
		"claim decision admission compact proof is sealed after the verifier's present")

	// The challenge is admitted when its proof is sealed, so a verifier the
	// whole allowance behind accepts both, and one a second further behind
	// refuses the transition for the proof it embeds.
	history.vary = signedHistoryVariation{proofSealedAt: sealedAt}
	challenge := history.challenge(claimID, sealedAt)
	if err := history.verifyTransition(challenge, sealedAt-allowance); err != nil {
		t.Errorf("a challenge embedding a proof accepted with the allowance is refused: %v", err)
	}
	refusedFor(t, "a challenge embedding a proof sealed a second beyond the allowance",
		history.verifyTransition(challenge, sealedAt-allowance-1),
		"claim decision admission compact proof is sealed after the verifier's present")
}
