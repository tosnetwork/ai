package agentguarantor

import (
	"errors"
	"strings"
	"time"
)

// claimReviewCutoffV1 is the claim-relative review cutoff: the latest
// admission time of an ordinary initial decision and the trigger of the
// initial terminal fallback. It runs from the claim's initial admission, on
// every path, so the ordinary decision and the fallback race on one value and
// a later revision of the claim neither resets nor extends it.
func claimReviewCutoffV1(initialAdmission ClaimAdmissionReceiptBodyV1, terms CoverageTermsV1) (uint64, bool) {
	if initialAdmission.AdmissionKind != "initial" || initialAdmission.AdmittedAtUnix == 0 || terms.ReviewDeadlineSeconds == 0 {
		return 0, false
	}
	return checkedDurationAddV1(initialAdmission.AdmittedAtUnix, terms.ReviewDeadlineSeconds)
}

// initialClaimAdmissionBodyV1 is the body of a claim's initial admission as a
// claim admission receipt carries it: the receipt's own body for an initial
// admission, and for a revision the body in the compact proof of the initial
// admission the revision names. The proof is bound to the revision here; its
// seal and authorization are verified with the claim admission receipt.
func initialClaimAdmissionBodyV1(claimAdmission AuthorizedClaimAdmissionReceiptV1) (ClaimAdmissionReceiptBodyV1, error) {
	if err := bindRevisionInitialAdmissionProofV1(claimAdmission.Body, claimAdmission.InitialClaimAdmissionProof); err != nil {
		return ClaimAdmissionReceiptBodyV1{}, err
	}
	if claimAdmission.InitialClaimAdmissionProof != nil {
		return claimAdmission.InitialClaimAdmissionProof.ReceiptBody, nil
	}
	return claimAdmission.Body, nil
}

// validateDecisionAdmissionOutcomeV1 holds a decision admission receipt body
// to what its admission time and its decision fix, on every path and in a
// compact proof alike:
//
//   - the admitted claim state is the decision result's target state;
//   - a terminal candidate opens exactly the challenge window
//     [admitted_at, admitted_at + challenge_window_seconds] and no resolution
//     window; a nonterminal decision opens exactly the resolution window
//     [admitted_at, admitted_at + resolution_window_seconds] and no challenge
//     window;
//   - admission never changes the challenge round count, changes the
//     nonterminal count only by the one round a deterministic fallback closes,
//     and leaves both within the Agreement's maxima;
//   - a nonterminal result is admitted only while a nonterminal round remains
//     and never in place of a challenged candidate;
//   - off the late-recovery path, the admitted state's complete remaining
//     closure ends by the terminal resolution deadline.
//
// The admission time itself is validated by validateDecisionAdmissionTimeV1,
// which every caller runs first.
//
// The decision's window lengths are held to the terms by the decision body
// validation. Later transitions read the windows and counts from the sealed
// body, so a body that misstates them would move a challenge deadline or
// restore a consumed round.
func validateDecisionAdmissionOutcomeV1(body ClaimDecisionAdmissionReceiptBodyV1, decision ClaimDecisionBodyV1,
	terms CoverageTermsV1) error {
	target, err := decisionTargetStateV1(decision.Result)
	if err != nil {
		return err
	}
	if body.AdmittedClaimState != target {
		return errors.New("claim decision admission state differs from its decision's result")
	}
	switch decision.Result {
	case DecisionApproved, DecisionPartiallyApproved, DecisionDenied:
		if decision.ChallengeWindowSeconds == 0 {
			return errors.New("claim decision admission has no challenge window to open")
		}
		ends, fits := checkedDurationAddV1(body.AdmittedAtUnix, decision.ChallengeWindowSeconds)
		if !fits {
			return errors.New("claim decision admission challenge window overflows")
		}
		if body.ChallengeStartsAtUnix != body.AdmittedAtUnix || body.ChallengeEndsAtUnix != ends {
			return errors.New("claim decision admission challenge window differs from its admission time and the decision's challenge window")
		}
		if body.ResolutionStartsAtUnix != 0 || body.ResolutionDueAtUnix != 0 {
			return errors.New("terminal-candidate decision admission carries a resolution window")
		}
	case DecisionEvidenceRequired, DecisionDisputed:
		if decision.ResolutionWindowSeconds == 0 {
			return errors.New("claim decision admission has no resolution window to open")
		}
		due, fits := checkedDurationAddV1(body.AdmittedAtUnix, decision.ResolutionWindowSeconds)
		if !fits {
			return errors.New("claim decision admission resolution window overflows")
		}
		if body.ResolutionStartsAtUnix != body.AdmittedAtUnix || body.ResolutionDueAtUnix != due {
			return errors.New("claim decision admission resolution window differs from its admission time and the decision's resolution window")
		}
		if body.ChallengeStartsAtUnix != 0 || body.ChallengeEndsAtUnix != 0 {
			return errors.New("nonterminal decision admission carries a challenge window")
		}
	default:
		return errors.New("claim decision result is unknown")
	}
	if body.ChallengeRoundsUsedAfter != body.ChallengeRoundsUsedBefore {
		return errors.New("claim decision admission changes the challenge round count")
	}
	if body.NonterminalRoundsUsedAfter != body.NonterminalRoundsUsedBefore {
		closed, fits := checkedDurationAddV1(body.NonterminalRoundsUsedBefore, 1)
		if body.AdmissionMode != "deterministic_fallback" || !fits || body.NonterminalRoundsUsedAfter != closed {
			return errors.New("claim decision admission changes the nonterminal round count outside the fallback rule")
		}
	}
	if body.ChallengeRoundsUsedAfter > terms.ClaimClosureCapacity.MaximumChallengeRoundsPerClaim ||
		body.NonterminalRoundsUsedAfter > terms.ClaimClosureCapacity.MaximumNonterminalRoundsPerClaim {
		return errors.New("claim decision admission round count exceeds the Agreement's maximum")
	}
	if decision.Result == DecisionEvidenceRequired || decision.Result == DecisionDisputed {
		// A nonterminal result is resolved by a response transition or by the
		// fallback at its deadline, and either consumes a nonterminal round, so
		// one must remain when the result is admitted. Terms that allow no
		// nonterminal round therefore admit only challengeable candidates.
		if body.NonterminalRoundsUsedAfter >= terms.ClaimClosureCapacity.MaximumNonterminalRoundsPerClaim {
			return errors.New("nonterminal claim decision is admitted with no nonterminal round remaining")
		}
		// A decision replaces an application token only as the successor of a
		// challenged candidate, and that successor must itself be a challengeable
		// candidate. The receipt body records the replacement, so a compact proof
		// shows it without the predecessor transition.
		if body.PriorApplicationTokenDigest != "" || body.PriorApplicationTokenTerminalState != "" {
			return errors.New("nonterminal claim decision admission replaces an application token: a challenge successor must be a challengeable candidate")
		}
	}
	return validateOrdinaryDecisionClosureFitsV1(body, decision.Result, terms)
}

// validateOrdinaryDecisionClosureFitsV1 holds a decision admission off the
// late-recovery path to the terminal resolution deadline: the complete
// remaining closure of the state it admits (every remaining window of the
// continuation budget entry for that state and its remaining rounds, then
// payout and Adapter recovery) must end by that deadline. Payout
// materialization caps every payout line there, so a decision admitted later
// could never be applied. The late-recovery path is held to its own deadlines
// where its candidate is admitted.
func validateOrdinaryDecisionClosureFitsV1(body ClaimDecisionAdmissionReceiptBodyV1, result ClaimDecisionResult,
	terms CoverageTermsV1) error {
	if OnLateRecoveryPathV1(body) {
		return nil
	}
	capacity := terms.ClaimClosureCapacity
	// The outcome validation refuses counts past the maxima before it calls
	// this; the guard is repeated so that the subtractions below cannot wrap
	// whoever the caller is.
	if body.ChallengeRoundsUsedAfter > capacity.MaximumChallengeRoundsPerClaim ||
		body.NonterminalRoundsUsedAfter > capacity.MaximumNonterminalRoundsPerClaim {
		return errors.New("claim decision admission round count exceeds the Agreement's maximum")
	}
	challengeRemaining := capacity.MaximumChallengeRoundsPerClaim - body.ChallengeRoundsUsedAfter
	state, nonterminalRemaining := "challengeable_candidate", uint64(0)
	if result == DecisionEvidenceRequired || result == DecisionDisputed {
		state = string(result)
		nonterminalRemaining = capacity.MaximumNonterminalRoundsPerClaim - body.NonterminalRoundsUsedAfter
	}
	for _, entry := range capacity.ContinuationBudgetEntries {
		if !strings.HasPrefix(entry.ProfileStateKey, state+":") || entry.ChallengeRoundsRemaining != challengeRemaining ||
			entry.NonterminalRoundsRemaining != nonterminalRemaining {
			continue
		}
		closesBy, fits := checkedDurationAddV1(body.AdmittedAtUnix, entry.MaximumRemainingClosureSeconds)
		if !fits || closesBy > terms.TerminalResolutionDeadlineUnix {
			return errors.New("claim decision admission leaves no room to close by the terminal resolution deadline")
		}
		return nil
	}
	return errors.New("claim decision admission has no continuation budget entry for the state it admits")
}

// validateDecisionAdmissionTimeV1 holds the admission time of a decision to
// the decision it admits, in the full receipt and in a compact proof alike;
// both values are in either. The time is a protocol timestamp, so it lies in
// the range a signed 64-bit Unix time holds: a larger value would wrap into
// the past when converted and void every bound derived from it. An authorized
// decision is admitted no earlier than it was decided and no later than it
// expires; the expiry limits admission only, and a decision admitted in time
// stays valid evidence after it. A deterministic fallback is materialized by
// its admission, so it is decided at its admission time.
func validateDecisionAdmissionTimeV1(body ClaimDecisionAdmissionReceiptBodyV1, decision ClaimDecisionBodyV1) error {
	if !validUnixTimestampV1(body.AdmittedAtUnix) {
		return errors.New("claim decision admission time is absent or out of range")
	}
	if body.AdmissionMode == "deterministic_fallback" {
		if body.AdmittedAtUnix != decision.DecidedAtUnix {
			return errors.New("deterministic fallback decision is not decided at its admission time")
		}
		return nil
	}
	if body.AdmittedAtUnix < decision.DecidedAtUnix {
		return errors.New("authorized claim decision is admitted before it was decided")
	}
	if body.AdmittedAtUnix > decision.ExpiresAtUnix {
		return errors.New("authorized claim decision is admitted after its expiry")
	}
	return nil
}

// bindReceiptTimeToStageAdmissionV1 anchors the time a receipt body states to
// the stage action admission evidence the receipt carries. The body is signed
// by the receipt's own quorum and the evidence by the Action Authority; both
// record one admission, so they state one time. Without the tie, a body could
// be signed with another time than its action was admitted at, and every
// window and deadline computed from the body's time would move with it. The
// time is in range and not after the verifier's present, with the allowance
// the stage evidence itself is given.
func bindReceiptTimeToStageAdmissionV1(subject string, bodyTimeUnix uint64,
	stage PortableStageActionAdmissionEvidenceV1, now time.Time) error {
	if !validUnixTimestampV1(bodyTimeUnix) {
		return errors.New(subject + " time is absent or out of range")
	}
	if bodyTimeUnix != stage.Body.AdmittedAtUnix {
		return errors.New(subject + " time differs from its stage action admission evidence's")
	}
	if !notAfterVerifierPresentV1(bodyTimeUnix, now) {
		return errors.New(subject + " time is after the verifier's present")
	}
	return nil
}

// notAfterVerifierPresentV1 reports whether a receipt time is no later than
// the verifier's present plus the stage admission clock allowance. Every
// window is computed from the signed time, never from the verifier's clock, so
// the allowance admits an honest fresh receipt to a verifier whose clock runs
// slightly behind and gives a dishonest one nothing.
func notAfterVerifierPresentV1(timeUnix uint64, now time.Time) bool {
	latest := now.UTC().Add(stageAdmissionClockAllowanceV1).Unix()
	return latest >= 0 && timeUnix <= uint64(latest)
}

// bindApplicationTimeToClosingTransitionV1 holds the time a terminal decision
// is applied to the challenge close that made it terminal: not before it. It
// is the one check for the full application receipt, which carries that
// transition, and for a terminal bundle, which carries it beside the
// application proof.
func bindApplicationTimeToClosingTransitionV1(appliedAtUnix uint64, closing ClaimStateTransitionReceiptBodyV1) error {
	if appliedAtUnix < closing.TransitionedAtUnix {
		return errors.New("claim decision is applied before its challenge close")
	}
	return nil
}

// bindTransitionToDecisionAdmissionV1 holds the claim and coverage a
// transition request names to the decision admission the transition embeds.
// The receipt body is held to the request, so a transition signed for another
// claim over this claim's decision is refused here and not only where a
// bundle or a fallback compares it with the claim.
func bindTransitionToDecisionAdmissionV1(request ClaimStateTransitionActionBodyV1,
	admission ClaimDecisionAdmissionReceiptBodyV1) error {
	if request.ClaimID != admission.ClaimID {
		return errors.New("claim transition is of another claim than its decision admission")
	}
	if request.CoverageAgreementBodyDigest != admission.CoverageAgreementBodyDigest {
		return errors.New("claim transition is on another Agreement than its decision admission")
	}
	if request.CoverageObligationID != admission.CoverageObligationID {
		return errors.New("claim transition is on another obligation than its decision admission")
	}
	return nil
}

// isNextRevisionV1 reports whether next is exactly one past prior, for
// revisions and sequences. A prior value at the top of the range has no
// successor: unchecked, its successor would wrap to zero.
func isNextRevisionV1(next, prior uint64) bool {
	successor, fits := checkedAdd(prior, 1)
	return fits && next == successor
}

// bindAuthorizedDecisionAdmissionToPredecessorV1 holds an authorized decision
// admission to the head it follows. Its admission time is not before that
// head; an initial decision is admitted no later than the claim review
// cutoff, where the initial terminal fallback becomes eligible. Its round
// counts start from the head's: zero for an initial decision, the predecessor
// transition's resulting counts for a successor. The successor's upper bound,
// the transition's successor cutoff, is checked with its lineage.
func bindAuthorizedDecisionAdmissionToPredecessorV1(body ClaimDecisionAdmissionReceiptBodyV1,
	claimAdmission, initialAdmission ClaimAdmissionReceiptBodyV1, predecessor *AuthorizedClaimStateTransitionReceiptV1,
	terms CoverageTermsV1) error {
	if err := bindAuthorizedDecisionAdmissionToClaimAdmissionV1(body, claimAdmission, initialAdmission, predecessor == nil, terms); err != nil {
		return err
	}
	if predecessor == nil {
		if body.ChallengeRoundsUsedBefore != 0 || body.NonterminalRoundsUsedBefore != 0 {
			return errors.New("initial claim decision admission starts with consumed rounds")
		}
		return nil
	}
	if body.AdmittedAtUnix < predecessor.Body.TransitionedAtUnix {
		return errors.New("successor claim decision is admitted before its predecessor transition")
	}
	if body.ChallengeRoundsUsedBefore != predecessor.Body.ChallengeRoundsUsedAfter ||
		body.NonterminalRoundsUsedBefore != predecessor.Body.NonterminalRoundsUsedAfter {
		return errors.New("successor claim decision admission round counts differ from its predecessor transition")
	}
	return nil
}

// bindDecisionRevisionEpochV1 binds a decision admission's revision-epoch
// expectation, its revision ingress cut and the receipt body's frozen-epoch
// fields to one another and to the claim revision decided. It is the one
// binding for authorized and fallback admissions; subject names the admission
// in each refusal.
//
// When frozenHead is nil the admission froze the open epoch itself: the
// expectation is open at the cut's prior epoch-state revision and the body
// records exactly the cut. Otherwise the head left revision ingress frozen and
// the admission reuses it: a frozen expectation at the head's epoch and
// epoch-state revision, the head's byte-identical cut and unchanged body
// fields.
//
// On both paths the cut is the cut of this claim's revision ingress log on
// this coverage, at the expectation's epoch, and it ends at the decided claim
// revision: it admits exactly one revision ingress per revision after the
// first. A cut of another claim's log, or one that admits more or fewer
// revisions than the decision selects, would let a decision ignore a revision
// admitted before the freeze. The cut's last admitted entry is not yet held to
// the digest of the claim admission the decision stands on.
func bindDecisionRevisionEpochV1(subject string, body ClaimDecisionAdmissionReceiptBodyV1,
	epoch ClaimRevisionEpochExpectationV1, cut ClaimIngressAdmissionCutProofV1, claimRevision uint64,
	frozenHead *ClaimDecisionAdmissionReceiptBodyV1) error {
	if epoch.RevisionIngressLogID != cut.ClaimIngressLogID {
		return errors.New(subject + " names another revision ingress log than its cut")
	}
	if frozenHead == nil {
		if epoch.ExpectedEpochState != "open" || cut.PriorEpochStateRevision != epoch.ExpectedEpochStateRevision {
			return errors.New(subject + " must freeze the open revision epoch its head opened")
		}
		// The admission froze this cut, so the receipt records exactly it.
		if body.FrozenRevisionEpoch != cut.RevisionEpoch ||
			body.PriorRevisionEpochStateRevision != cut.PriorEpochStateRevision ||
			body.FrozenRevisionEpochStateRevision != cut.FrozenEpochStateRevision ||
			body.FrozenClaimRevisionIngressHighWater != cut.AdmissionHighWater ||
			body.FrozenClaimRevisionIngressLogRoot != cut.AdmissionLogRoot {
			return errors.New(subject + "'s frozen-epoch fields differ from its cut")
		}
	} else {
		head := *frozenHead
		cutDigest, err := ClaimIngressAdmissionCutProofDigestV1(cut)
		if err != nil || epoch.ExpectedEpochState != "frozen" || cutDigest != head.ClaimRevisionIngressCutProofDigest ||
			epoch.RevisionEpoch != head.FrozenRevisionEpoch ||
			epoch.ExpectedEpochStateRevision != head.FrozenRevisionEpochStateRevision ||
			body.FrozenRevisionEpoch != head.FrozenRevisionEpoch ||
			body.PriorRevisionEpochStateRevision != head.PriorRevisionEpochStateRevision ||
			body.FrozenRevisionEpochStateRevision != head.FrozenRevisionEpochStateRevision ||
			body.FrozenClaimRevisionIngressHighWater != head.FrozenClaimRevisionIngressHighWater ||
			body.FrozenClaimRevisionIngressLogRoot != head.FrozenClaimRevisionIngressLogRoot {
			return errors.New(subject + " must reuse its head's frozen revision epoch and cut")
		}
	}
	if cut.RevisionEpoch != epoch.RevisionEpoch {
		return errors.New(subject + " revision cut names another epoch than its request")
	}
	logID, err := ClaimIngressLogIDV1(body.CoverageAgreementBodyDigest, body.CoverageObligationID, body.ClaimID)
	if err != nil || cut.CutKind != "claim_revisions" || cut.ClaimID != body.ClaimID ||
		cut.CoverageAgreementBodyDigest != body.CoverageAgreementBodyDigest ||
		cut.CoverageObligationID != body.CoverageObligationID || cut.ClaimIngressLogID != logID {
		return errors.New(subject + " revision cut is not the cut of its claim's revision ingress log")
	}
	if claimRevision == 0 || cut.AdmittedClaimCount != claimRevision-1 {
		return errors.New(subject + " revision cut does not end at the decided claim revision")
	}
	return nil
}

// bindAuthorizedDecisionAdmissionToClaimAdmissionV1 holds the admission time
// of an authorized decision to the admission of the claim revision it decides:
// not before it and, for the claim's initial decision, no later than the claim
// review cutoff, where the initial terminal fallback becomes eligible. The
// cutoff runs from the claim's initial admission, whichever revision is
// decided. It needs only receipt bodies, so it also runs where a compact
// decision proof travels beside the compact proofs of its claim admissions, in
// a terminal bundle.
func bindAuthorizedDecisionAdmissionToClaimAdmissionV1(body ClaimDecisionAdmissionReceiptBodyV1,
	claimAdmission, initialAdmission ClaimAdmissionReceiptBodyV1, initial bool, terms CoverageTermsV1) error {
	if body.AdmittedAtUnix < claimAdmission.AdmittedAtUnix {
		return errors.New("claim decision is admitted before its claim admission")
	}
	if initial {
		cutoff, fits := claimReviewCutoffV1(initialAdmission, terms)
		if !fits || body.AdmittedAtUnix > cutoff {
			return errors.New("initial claim decision is admitted after the claim review cutoff")
		}
	}
	return nil
}

// bindLateRecoverySuccessorToCandidateV1 holds the authorized successor of a
// challenged late-recovery candidate to the claim admission its candidate
// decided: that challenge leaves revision ingress frozen, so no later revision
// can have been admitted.
func bindLateRecoverySuccessorToCandidateV1(candidate ClaimDecisionAdmissionReceiptBodyV1, claimAdmissionDigest string) error {
	if candidate.AuthorizedClaimAdmissionReceiptDigest != claimAdmissionDigest {
		return errors.New("late-recovery successor stands on another claim admission than its candidate")
	}
	return nil
}
