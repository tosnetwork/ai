package agentguarantor

import "errors"

// claimReviewCutoffV1 is the claim-relative review cutoff: the latest
// admission time of an ordinary initial decision and the trigger of the
// initial terminal fallback. It is derived from the admission of the claim
// revision under review, so the ordinary decision and the fallback race on one
// value.
func claimReviewCutoffV1(claimAdmission ClaimAdmissionReceiptBodyV1, terms CoverageTermsV1) (uint64, bool) {
	if claimAdmission.AdmittedAtUnix == 0 || terms.ReviewDeadlineSeconds == 0 {
		return 0, false
	}
	return checkedDurationAddV1(claimAdmission.AdmittedAtUnix, terms.ReviewDeadlineSeconds)
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
//     and leaves both within the Agreement's maxima.
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
	if body.AdmittedAtUnix == 0 {
		return errors.New("claim decision admission has no admission time")
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
	return nil
}

// bindAuthorizedDecisionAdmissionToPredecessorV1 holds an authorized decision
// admission to the head it follows. Its admission time is not before that
// head; an initial decision is admitted no later than the claim review
// cutoff, where the initial terminal fallback becomes eligible. Its round
// counts start from the head's: zero for an initial decision, the predecessor
// transition's resulting counts for a successor. The successor's upper bound,
// the transition's successor cutoff, is checked with its lineage.
func bindAuthorizedDecisionAdmissionToPredecessorV1(body ClaimDecisionAdmissionReceiptBodyV1,
	claimAdmission ClaimAdmissionReceiptBodyV1, predecessor *AuthorizedClaimStateTransitionReceiptV1,
	terms CoverageTermsV1) error {
	if body.AdmittedAtUnix < claimAdmission.AdmittedAtUnix {
		return errors.New("claim decision is admitted before its claim admission")
	}
	if predecessor == nil {
		cutoff, fits := claimReviewCutoffV1(claimAdmission, terms)
		if !fits || body.AdmittedAtUnix > cutoff {
			return errors.New("initial claim decision is admitted after the claim review cutoff")
		}
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

// validateAuthorizedDecisionAdmissionTimeV1 holds the admission time of an
// authorized decision to the decision's own validity: no earlier than it was
// decided and no later than it expires. The expiry limits admission only; a
// decision admitted in time stays valid evidence after it.
func validateAuthorizedDecisionAdmissionTimeV1(body ClaimDecisionAdmissionReceiptBodyV1, decision ClaimDecisionBodyV1) error {
	if body.AdmittedAtUnix == 0 {
		return errors.New("claim decision admission has no admission time")
	}
	if body.AdmittedAtUnix < decision.DecidedAtUnix {
		return errors.New("authorized claim decision is admitted before it was decided")
	}
	if body.AdmittedAtUnix > decision.ExpiresAtUnix {
		return errors.New("authorized claim decision is admitted after its expiry")
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
