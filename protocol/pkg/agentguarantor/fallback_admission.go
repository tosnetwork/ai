package agentguarantor

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// ClaimFilingCloseReceiptMediaTypeV1 is the media type a late filing-close
// descriptor names.
const ClaimFilingCloseReceiptMediaTypeV1 = GuarantorMediaTypePrefixV1 + "claim-filing-close.v1+cbor"

// DeterministicFallbackAdmissionSourceIdentityV1 returns the source-head and
// identity digests of a fallback request. Both are computed from the request's
// references alone, so producer and verifier derive them before any referenced
// object is available.
func DeterministicFallbackAdmissionSourceIdentityV1(variant DeterministicFallbackAdmissionVariantV1) (string, string, error) {
	epochDigest, epochErr := ClaimRevisionEpochExpectationDigestV1(variant.ClaimRevisionEpochExpectation)
	lateCloseDigest := ""
	var lateErr error
	if descriptor := variant.LateFilingCloseReceiptDescriptor; descriptor != nil {
		lateErr = validateImmutableEvidenceDescriptor(*descriptor)
		lateCloseDigest = descriptor.ContentDigest
	}
	optionalDigest := func(value string) bool { return value == "" || validDigest(value) }
	if epochErr != nil || lateErr != nil || !validDigest(variant.CoverageAgreementBodyDigest) ||
		!validToken(variant.CoverageObligationID, 128) || !validDigest(variant.ClaimID) ||
		!validDigest(variant.AuthorizedClaimAdmissionReceiptDigest) ||
		!optionalDigest(variant.CurrentDecisionAdmissionReceiptDigest) ||
		!optionalDigest(variant.CurrentClaimStateTransitionReceiptDigest) || !validDigest(variant.FallbackProfileDigest) ||
		variant.SourceClaimRevision == 0 || variant.SourceClaimStateRevision == 0 ||
		!validToken(variant.SourceClaimState, 128) || variant.TriggerCutoffUnix == 0 || variant.DecisionSequence == 0 {
		return "", "", errors.New("deterministic fallback source identity is invalid")
	}
	head := ClaimDecisionSourceHeadV1{SchemaVersion: 1,
		AuthorizedClaimAdmissionReceiptDigest:    variant.AuthorizedClaimAdmissionReceiptDigest,
		CurrentDecisionAdmissionReceiptDigest:    variant.CurrentDecisionAdmissionReceiptDigest,
		CurrentClaimStateTransitionReceiptDigest: variant.CurrentClaimStateTransitionReceiptDigest,
		LateFilingCloseReceiptDigest:             lateCloseDigest, ClaimRevisionEpochExpectationDigest: epochDigest}
	headDigest, err := guarantorCodec.Digest("tos.service.agent-guarantor-claim-decision-source-head.v1", head)
	if err != nil {
		return "", "", err
	}
	identity := DeterministicFallbackAdmissionIdentityV1{SchemaVersion: 1,
		FallbackProfileDigest: variant.FallbackProfileDigest, TriggerCutoffUnix: variant.TriggerCutoffUnix,
		ClaimRevisionEpochExpectationDigest: epochDigest}
	identityDigest, err := guarantorCodec.Digest("tos.service.agent-guarantor-fallback-admission-identity.v1", identity)
	return headDigest, identityDigest, err
}

// deterministicFallbackSourceV1 is the source head behind a fallback
// request's references. The claim admission receipt is the admission
// receipt's own top-level copy.
type deterministicFallbackSourceV1 struct {
	currentDecision *ClaimDecisionAdmissionReceiptProofV1
	transition      *AuthorizedClaimStateTransitionReceiptV1
	lateFilingClose *AuthorizedClaimFilingCloseReceiptV1
}

// bindDeterministicFallbackReferencesV1 pairs each reference of a fallback
// request with the single object behind it before any signature is checked.
// Each object is carried at most once, the current-decision proof is carried
// directly only where no transition receipt carries it, and the late
// filing-close receipt is the only object retrieved. Nothing the bound objects
// themselves reference is followed, so the work per receipt is constant.
func bindDeterministicFallbackReferencesV1(receipt AuthorizedClaimDecisionAdmissionReceiptV1,
	variant DeterministicFallbackAdmissionVariantV1, terms CoverageTermsV1,
	authorityResolver AuthorityKeyResolver) (deterministicFallbackSourceV1, error) {
	var source deterministicFallbackSourceV1
	claimDigest, err := ClaimAdmissionReceiptDigestV1(receipt.AuthorizedClaimAdmissionReceipt)
	if err != nil || variant.AuthorizedClaimAdmissionReceiptDigest != claimDigest ||
		receipt.Body.AuthorizedClaimAdmissionReceiptDigest != claimDigest {
		return source, errors.New("claim decision fallback claim admission reference differs from the carried receipt")
	}
	// The head's state revision and round counts as its predecessor produced
	// them; initial_reviewing has no predecessor and no consumed rounds.
	var headStateRevision, headChallengeRounds, headNonterminalRounds uint64
	consumesNonterminalRound := false
	switch variant.SourceClaimState {
	case "initial_reviewing":
		if variant.CurrentDecisionAdmissionReceiptDigest != "" || variant.CurrentClaimStateTransitionReceiptDigest != "" ||
			receipt.CurrentDecisionAdmissionProof != nil || receipt.PredecessorClaimStateTransitionReceipt != nil {
			return source, errors.New("initial fallback carries a predecessor head")
		}
		headStateRevision = variant.SourceClaimStateRevision
	case "disputed", "evidence_required":
		if variant.CurrentClaimStateTransitionReceiptDigest != "" || receipt.PredecessorClaimStateTransitionReceipt != nil {
			return source, errors.New("nonterminal fallback carries a transition head")
		}
		proof := receipt.CurrentDecisionAdmissionProof
		if proof == nil {
			return source, errors.New("nonterminal fallback lacks its current decision admission proof")
		}
		if _, err := ClaimDecisionAdmissionReceiptProofDigestV1(*proof); err != nil ||
			proof.ReceiptEnvelopeDigest != variant.CurrentDecisionAdmissionReceiptDigest {
			return source, errors.New("nonterminal fallback decision proof differs from its reference")
		}
		// No transition has reopened the revision epoch the current decision
		// froze, so the claim admission is still the one that decision saw.
		if proof.ReceiptBody.AuthorizedClaimAdmissionReceiptDigest != claimDigest {
			return source, errors.New("nonterminal fallback decision proof stands on another claim admission")
		}
		source.currentDecision = proof
		headStateRevision = proof.ReceiptBody.AdmittedClaimStateRevision
		headChallengeRounds = proof.ReceiptBody.ChallengeRoundsUsedAfter
		headNonterminalRounds = proof.ReceiptBody.NonterminalRoundsUsedAfter
		consumesNonterminalRound = true
	case "reviewing_after_challenge", "reviewing_after_nonterminal_response":
		if receipt.CurrentDecisionAdmissionProof != nil {
			return source, errors.New("reviewing fallback carries its current decision proof outside its transition receipt")
		}
		transition := receipt.PredecessorClaimStateTransitionReceipt
		if transition == nil {
			return source, errors.New("reviewing fallback lacks its transition receipt")
		}
		transitionDigest, err := ClaimStateTransitionReceiptDigestV1(*transition)
		if err != nil || transitionDigest != variant.CurrentClaimStateTransitionReceiptDigest {
			return source, errors.New("reviewing fallback transition receipt differs from its reference")
		}
		if transition.DecisionAdmissionProof.ReceiptEnvelopeDigest != variant.CurrentDecisionAdmissionReceiptDigest {
			return source, errors.New("reviewing fallback decision reference differs from its transition's proof")
		}
		// The challenge of a late-recovery candidate leaves ingress frozen, so
		// the candidate still stands on the fallback's claim admission.
		if transition.DecisionAdmissionProof.AuthorizedClaimDecision.Body.DecisionPath == "late_recovery_terminal_fallback" &&
			transition.DecisionAdmissionProof.ReceiptBody.AuthorizedClaimAdmissionReceiptDigest != claimDigest {
			return source, errors.New("reviewing fallback's late-recovery candidate stands on another claim admission")
		}
		source.transition = transition
		source.currentDecision = &transition.DecisionAdmissionProof
		headStateRevision = transition.Body.ResultingClaimStateRevision
		headChallengeRounds = transition.Body.ChallengeRoundsUsedAfter
		headNonterminalRounds = transition.Body.NonterminalRoundsUsedAfter
	default:
		return source, errors.New("claim decision fallback source state is not registered")
	}
	if variant.SourceClaimStateRevision != headStateRevision {
		return source, errors.New("claim decision fallback source state revision differs from its head")
	}
	if variant.ExpectedChallengeRoundsUsed != headChallengeRounds ||
		variant.ExpectedNonterminalRoundsUsed != headNonterminalRounds ||
		receipt.Body.ChallengeRoundsUsedBefore != headChallengeRounds ||
		receipt.Body.NonterminalRoundsUsedBefore != headNonterminalRounds {
		return source, errors.New("claim decision fallback round counts differ from its head")
	}
	wantNonterminalAfter := headNonterminalRounds
	if consumesNonterminalRound {
		next, fits := checkedDurationAddV1(headNonterminalRounds, 1)
		if !fits || next > terms.ClaimClosureCapacity.MaximumNonterminalRoundsPerClaim {
			return source, errors.New("claim decision fallback exceeds its reserved nonterminal rounds")
		}
		wantNonterminalAfter = next
	}
	if receipt.Body.ChallengeRoundsUsedAfter != headChallengeRounds ||
		receipt.Body.NonterminalRoundsUsedAfter != wantNonterminalAfter {
		return source, errors.New("claim decision fallback round consumption is invalid")
	}
	if err := bindFallbackRevisionEpochV1(receipt, variant, source); err != nil {
		return source, err
	}
	// A fallback in place of a late-recovery candidate's successor carries the
	// candidate's digest, so its proof shows it may not be challenged again.
	lateMarker := ""
	if variant.SourceClaimState == "reviewing_after_challenge" {
		lateMarker = lateRecoveryCandidateMarkerV1(source.transition)
	}
	descriptor := variant.LateFilingCloseReceiptDescriptor
	if descriptor == nil {
		if receipt.Body.LateFilingCloseReceiptDigest != lateMarker {
			return source, errors.New("fallback admission's late filing-close digest is not its late-recovery marker")
		}
		return source, nil
	}
	if receipt.Body.LateFilingCloseReceiptDigest != descriptor.ContentDigest ||
		lateMarker != "" && lateMarker != descriptor.ContentDigest {
		return source, errors.New("late fallback receipt names a filing-close receipt other than its request")
	}
	filing, err := resolveLateFilingCloseReceiptV1(*descriptor, terms, authorityResolver)
	if err != nil {
		return source, err
	}
	if err := bindLateFilingCloseToClaimAdmissionV1(filing, receipt.AuthorizedClaimAdmissionReceipt); err != nil {
		return source, err
	}
	source.lateFilingClose = &filing
	return source, nil
}

// fallbackReusesFrozenEpochV1 reports whether a fallback's head left revision
// ingress frozen: the current decision of an evidence_required or disputed
// head froze the epoch and no transition followed, and the challenge of a
// late-recovery candidate does not reopen it. Every other head's transition
// opened the next epoch, and initial_reviewing has no frozen epoch yet.
func fallbackReusesFrozenEpochV1(sourceState string, source deterministicFallbackSourceV1) bool {
	switch sourceState {
	case "disputed", "evidence_required":
		return true
	case "reviewing_after_challenge":
		return source.currentDecision != nil &&
			source.currentDecision.AuthorizedClaimDecision.Body.DecisionPath == "late_recovery_terminal_fallback"
	}
	return false
}

// bindFallbackRevisionEpochV1 binds the request's revision-epoch expectation
// and the receipt's cut to the epoch the head left. A head that left ingress
// frozen is reused exactly: frozen expectation, the current decision's
// byte-identical cut and unchanged epoch fields. Every other head is frozen by
// this admission's ordinary open-to-frozen CAS.
func bindFallbackRevisionEpochV1(receipt AuthorizedClaimDecisionAdmissionReceiptV1,
	variant DeterministicFallbackAdmissionVariantV1, source deterministicFallbackSourceV1) error {
	epoch := variant.ClaimRevisionEpochExpectation
	cut := receipt.ClaimRevisionIngressCutProof
	body := receipt.Body
	if epoch.RevisionIngressLogID != cut.ClaimIngressLogID {
		return errors.New("claim decision fallback names another revision ingress log than its cut")
	}
	if !fallbackReusesFrozenEpochV1(variant.SourceClaimState, source) {
		if epoch.ExpectedEpochState != "open" || cut.PriorEpochStateRevision != epoch.ExpectedEpochStateRevision {
			return errors.New("claim decision fallback must freeze the open revision epoch its head opened")
		}
		// The admission froze this cut, so the receipt records exactly it.
		if body.FrozenRevisionEpoch != cut.RevisionEpoch ||
			body.PriorRevisionEpochStateRevision != cut.PriorEpochStateRevision ||
			body.FrozenRevisionEpochStateRevision != cut.FrozenEpochStateRevision ||
			body.FrozenClaimRevisionIngressHighWater != cut.AdmissionHighWater ||
			body.FrozenClaimRevisionIngressLogRoot != cut.AdmissionLogRoot {
			return errors.New("claim decision fallback's frozen-epoch fields differ from its cut")
		}
		return nil
	}
	head := source.currentDecision.ReceiptBody
	cutDigest, err := ClaimIngressAdmissionCutProofDigestV1(cut)
	if err != nil || epoch.ExpectedEpochState != "frozen" || cutDigest != head.ClaimRevisionIngressCutProofDigest ||
		epoch.RevisionEpoch != head.FrozenRevisionEpoch ||
		epoch.ExpectedEpochStateRevision != head.FrozenRevisionEpochStateRevision ||
		body.FrozenRevisionEpoch != head.FrozenRevisionEpoch ||
		body.PriorRevisionEpochStateRevision != head.PriorRevisionEpochStateRevision ||
		body.FrozenRevisionEpochStateRevision != head.FrozenRevisionEpochStateRevision ||
		body.FrozenClaimRevisionIngressHighWater != head.FrozenClaimRevisionIngressHighWater ||
		body.FrozenClaimRevisionIngressLogRoot != head.FrozenClaimRevisionIngressLogRoot {
		return errors.New("claim decision fallback must reuse its head's frozen revision epoch and cut")
	}
	return nil
}

// bindLateFilingCloseToClaimAdmissionV1 requires the late filing close and the
// claim admission to stand on the same coverage and activation: the claim
// admission request carries the activation, and the filing close is later
// verified against the offer its own copy of that activation carries.
func bindLateFilingCloseToClaimAdmissionV1(filing AuthorizedClaimFilingCloseReceiptV1,
	claimAdmission AuthorizedClaimAdmissionReceiptV1) error {
	claim := claimAdmission.AuthorizedClaimIngressReceipt.AuthorizedClaim
	if filing.AuthorizedActivationEvidence == nil {
		return errors.New("late fallback filing receipt lacks activation evidence")
	}
	if filing.Body.CoverageAgreementBodyDigest != claim.Body.CoverageAgreementBodyDigest ||
		filing.Body.CoverageObligationID != claim.Body.CoverageObligationID {
		return errors.New("late fallback filing-close receipt belongs to another coverage")
	}
	var submission ClaimSubmissionActionBodyV1
	if guarantorCodec.Unmarshal(claimAdmission.StageActionAdmissionEvidence.CanonicalRequest, &submission) != nil {
		return errors.New("late fallback claim admission request is undecodable")
	}
	admittedActivation, admittedErr := CoverageActivationEvidenceDigestV1(
		submission.AuthorityInstanceEffect.AuthorizedCoverageActivationEvidence)
	filingActivation, filingErr := CoverageActivationEvidenceDigestV1(*filing.AuthorizedActivationEvidence)
	if admittedErr != nil || filingErr != nil || admittedActivation != filingActivation {
		return errors.New("late fallback filing-close receipt stands on another activation")
	}
	return nil
}

// resolveLateFilingCloseReceiptV1 retrieves the one late filing-close receipt
// a fallback request references. Retrieval is required at every assurance
// level: an absent resolver, a wrong length, noncanonical or undecodable
// bytes, or a digest other than the descriptor's fails closed.
func resolveLateFilingCloseReceiptV1(descriptor ImmutableEvidenceDescriptorV1, terms CoverageTermsV1,
	authorityResolver AuthorityKeyResolver) (AuthorizedClaimFilingCloseReceiptV1, error) {
	var filing AuthorizedClaimFilingCloseReceiptV1
	if validateImmutableEvidenceDescriptor(descriptor) != nil || descriptor.ContentType != ClaimFilingCloseReceiptMediaTypeV1 ||
		descriptor.RetrievalPolicyDigest != terms.ClaimAdmissionProfile.ProfileDigest ||
		descriptor.ContentSize > terms.ClaimClosureCapacity.MaximumClaimFilingCloseReceiptEnvelopeBytes {
		return filing, errors.New("late filing-close descriptor is not the Agreement-bound filing-close reference")
	}
	wire, err := resolveImmutableEvidenceV1(authorityResolver, descriptor, true)
	if err != nil {
		return filing, fmt.Errorf("late filing-close receipt is unavailable: %w", err)
	}
	if guarantorCodec.Unmarshal(wire, &filing) != nil {
		return AuthorizedClaimFilingCloseReceiptV1{}, errors.New("late filing-close receipt is undecodable")
	}
	reencoded, err := guarantorCodec.Marshal(filing)
	if err != nil || !bytes.Equal(wire, reencoded) {
		return AuthorizedClaimFilingCloseReceiptV1{}, errors.New("late filing-close receipt is noncanonical")
	}
	digest, err := ClaimFilingCloseReceiptDigestV1(filing)
	if err != nil || digest != descriptor.ContentDigest {
		return AuthorizedClaimFilingCloseReceiptV1{}, errors.New("late filing-close receipt differs from its descriptor")
	}
	return filing, nil
}

func verifyDeterministicFallbackAdmissionReceiptV1(receipt AuthorizedClaimDecisionAdmissionReceiptV1, terms CoverageTermsV1,
	agreementVerifier agentcommerce.AgreementEvidenceVerifier, authorityResolver AuthorityKeyResolver,
	fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time) error {
	if agreementVerifier == nil {
		return errors.New("deterministic fallback Agreement verifier is absent")
	}
	bound, err := FindStageActionAuthorityV1(terms.StageActionAuthorityBinding, "terminal_decision")
	if err != nil {
		return err
	}
	var actionBody ClaimDecisionAdmissionActionBodyV1
	request := receipt.StageActionAdmissionEvidence.CanonicalRequest
	if guarantorCodec.Unmarshal(request, &actionBody) != nil || actionBody.SchemaVersion != 1 ||
		actionBody.AdmissionMode != "deterministic_fallback" || actionBody.AuthorizedDecisionVariant != nil ||
		actionBody.DeterministicFallbackVariant == nil {
		return errors.New("claim decision fallback request is not the closed tagged variant")
	}
	variant := *actionBody.DeterministicFallbackVariant
	reencoded, err := guarantorCodec.Marshal(actionBody)
	if err != nil || !bytes.Equal(request, reencoded) {
		return errors.New("claim decision fallback request is noncanonical")
	}
	fallbackDigest, err := DeterministicClaimTerminalFallbackDigestV1(terms.ClaimClosureCapacity.TerminalFallback)
	if err != nil || variant.FallbackProfileDigest != fallbackDigest {
		return errors.New("claim decision fallback profile is not Agreement-bound")
	}
	source, err := bindDeterministicFallbackReferencesV1(receipt, variant, terms, authorityResolver)
	if err != nil {
		return err
	}
	claimAdmission := receipt.AuthorizedClaimAdmissionReceipt
	if err := VerifyClaimAdmissionReceiptV1(claimAdmission, terms, agreementVerifier,
		authorityResolver, fenceResolver, now); err != nil {
		return fmt.Errorf("claim decision fallback has an invalid claim admission: %w", err)
	}
	claimReceiptDigest := variant.AuthorizedClaimAdmissionReceiptDigest
	claim := claimAdmission.AuthorizedClaimIngressReceipt.AuthorizedClaim
	sameClaim := func(agreement, obligation, claimID string) bool {
		return agreement == claim.Body.CoverageAgreementBodyDigest && obligation == claim.Body.CoverageObligationID &&
			claimID == claim.Body.ClaimID
	}
	decision := receipt.AuthorizedClaimDecision
	decisionDigest, decisionErr := ClaimDecisionDigestV1(decision)
	cutDigest, cutErr := ClaimIngressAdmissionCutProofDigestV1(receipt.ClaimRevisionIngressCutProof)
	endDigest, endErr := CoverageEndCommitmentDigestV1(receipt.CoverageEndCommitment)
	if decisionErr != nil || cutErr != nil || endErr != nil ||
		variant.SourceClaimRevision != claim.Body.ClaimRevision || variant.ClaimRevisionEpochExpectation.ExpectedClaimRevision != claim.Body.ClaimRevision ||
		!sameClaim(variant.CoverageAgreementBodyDigest, variant.CoverageObligationID, variant.ClaimID) {
		return errors.New("claim decision fallback source claim is substituted")
	}
	lateRecovery := source.lateFilingClose != nil
	lateFilingDigest := ""
	if lateRecovery {
		// Coverage and activation were bound to the claim admission with the
		// references; the filing close is now verified against its offer.
		filing := *source.lateFilingClose
		offer, offerErr := extractFirmOfferFromAcceptanceV1(filing.AuthorizedActivationEvidence.AuthorizedAcceptanceReceipt)
		if offerErr != nil || VerifyClaimFilingCloseReceiptV1(filing, offer, agreementVerifier,
			authorityResolver, fenceResolver, now) != nil {
			return errors.New("late fallback filing-close receipt is invalid")
		}
		lateFilingDigest = variant.LateFilingCloseReceiptDescriptor.ContentDigest
		if filing.Body.ClosedAtUnix <= terms.TerminalResolutionDeadlineUnix ||
			filing.Body.ClosedAtUnix > terms.LateIngressRecoveryDeadlineUnix ||
			filing.ClaimIngressAdmissionCutProof.PendingOrAmbiguousCount != 0 {
			return errors.New("late fallback filing-close timing or ingress cut is invalid")
		}
		timelyClaimFound := false
		for _, entry := range filing.ClaimIngressAdmissionCutProof.Entries {
			if entry.ResolutionKind == "claim_admitted" && entry.ClaimAdmissionReceiptDigest == claimReceiptDigest &&
				entry.ReceivedAtUnix <= filing.Body.FilingCutoffUnix {
				timelyClaimFound = true
				break
			}
		}
		if !timelyClaimFound {
			return errors.New("late fallback does not identify a timely admitted ingress")
		}
	}
	wantPriorState, wantPath := "", "terminal_fallback"
	wantSequence := uint64(0)
	cutoff := uint64(0)
	var ok bool
	var predecessorDecisionDigest string
	var predecessorAdmissionDigest string
	var predecessorTransitionDigest string
	var priorPendingToken *DecisionApplicationTokenV1
	switch variant.SourceClaimState {
	case "initial_reviewing":
		wantPriorState, wantPath, wantSequence = "admitted", "initial_terminal_fallback", 1
		cutoff, ok = checkedDurationAddV1(claimAdmission.Body.AdmittedAtUnix, terms.ReviewDeadlineSeconds)
	case "disputed", "evidence_required":
		current := *source.currentDecision
		if err := VerifyClaimDecisionAdmissionReceiptProofV1(current, terms, authorityResolver, now); err != nil {
			return fmt.Errorf("nonterminal fallback decision proof is invalid: %w", err)
		}
		body := current.ReceiptBody
		if !sameClaim(body.CoverageAgreementBodyDigest, body.CoverageObligationID, body.ClaimID) ||
			body.AdmittedClaimState != variant.SourceClaimState || body.ResolutionDueAtUnix == 0 {
			return errors.New("nonterminal fallback decision head is invalid")
		}
		wantPriorState, wantSequence, cutoff, ok = variant.SourceClaimState, body.DecisionSequence+1,
			body.ResolutionDueAtUnix, true
		predecessorDecisionDigest = body.AuthorizedClaimDecisionDigest
		predecessorAdmissionDigest = current.ReceiptEnvelopeDigest
	case "reviewing_after_challenge", "reviewing_after_nonterminal_response":
		transition := *source.transition
		if err := VerifyClaimStateTransitionReceiptV1(transition, terms, agreementVerifier,
			authorityResolver, fenceResolver, now); err != nil {
			return err
		}
		current := transition.DecisionAdmissionProof
		predecessorAdmissionDigest = current.ReceiptEnvelopeDigest
		predecessorTransitionDigest = variant.CurrentClaimStateTransitionReceiptDigest
		wantKind := "challenge_admission"
		if variant.SourceClaimState == "reviewing_after_nonterminal_response" {
			wantKind = "nonterminal_response_admission"
		}
		if !sameClaim(transition.Body.CoverageAgreementBodyDigest, transition.Body.CoverageObligationID, transition.Body.ClaimID) ||
			transition.Body.TransitionKind != wantKind || transition.Body.ResultingClaimState != "reviewing" ||
			transition.Body.SuccessorDecisionDueAtUnix == 0 {
			return errors.New("reviewing fallback transition head is substituted")
		}
		wantPriorState, wantSequence, cutoff, ok = "reviewing", current.ReceiptBody.DecisionSequence+1,
			transition.Body.SuccessorDecisionDueAtUnix, true
		predecessorDecisionDigest = current.ReceiptBody.AuthorizedClaimDecisionDigest
		if wantKind == "challenge_admission" {
			priorPendingToken = current.ReceiptBody.ResultingApplicationToken
			if priorPendingToken == nil || receipt.PriorPendingApplicationToken == nil ||
				!equalCanonical(*priorPendingToken, *receipt.PriorPendingApplicationToken) {
				return errors.New("reviewing challenge fallback does not replace the current pending token")
			}
		}
	default:
		return errors.New("claim decision fallback source state is not registered")
	}
	if lateRecovery {
		wantPath = "late_recovery_terminal_fallback"
		cutoff = source.lateFilingClose.Body.ClosedAtUnix
		ok = cutoff > terms.TerminalResolutionDeadlineUnix && cutoff <= terms.LateIngressRecoveryDeadlineUnix
	}
	if !ok || decision.Body.DecisionPath != wantPath || variant.DecisionSequence != wantSequence ||
		decision.Body.DecisionSequence != wantSequence || decision.Body.PredecessorAuthorizedClaimDecisionDigest != predecessorDecisionDigest ||
		variant.SourceClaimStateRevision != receipt.Body.PriorClaimStateRevision {
		return errors.New("claim decision fallback source lineage is invalid")
	}
	if !ok || variant.TriggerCutoffUnix != cutoff || receipt.Body.FallbackTriggerCutoffUnix != cutoff ||
		receipt.Body.AdmittedAtUnix < cutoff || lateRecovery &&
		(receipt.Body.AdmittedAtUnix > terms.LateIngressRecoveryDeadlineUnix ||
			receipt.Body.AdmittedAtUnix > terms.LateRecoveryTerminalDeadlineUnix) {
		return errors.New("claim decision fallback trigger cutoff is invalid")
	}
	if lateRecovery {
		if receipt.Body.ChallengeRoundsUsedAfter > terms.ClaimClosureCapacity.MaximumChallengeRoundsPerClaim {
			return errors.New("late fallback challenge counter exceeds its reserved capacity")
		}
		remaining := terms.ClaimClosureCapacity.MaximumChallengeRoundsPerClaim - receipt.Body.ChallengeRoundsUsedAfter
		key := "challengeable_candidate:r=" + new(big.Int).SetUint64(remaining).String()
		var closureSeconds uint64
		for _, entry := range terms.ClaimClosureCapacity.ContinuationBudgetEntries {
			if entry.ProfileStateKey == key {
				closureSeconds = entry.MaximumRemainingClosureSeconds
				break
			}
		}
		terminalAt, fits := checkedDurationAddV1(receipt.Body.AdmittedAtUnix, closureSeconds)
		if closureSeconds == 0 || !fits || terminalAt > terms.LateRecoveryTerminalDeadlineUnix {
			return errors.New("late fallback cannot complete inside its reserved contingency window")
		}
	}
	if err := ValidateClaimDecision(decision, claim, terms, authorityResolver,
		terms.ClaimClosureCapacity.TerminalFallback.FallbackAuthoritySubjects,
		time.Unix(int64(receipt.Body.AdmittedAtUnix), 0).UTC()); err != nil {
		return err
	}
	epoch := variant.ClaimRevisionEpochExpectation
	cut := receipt.ClaimRevisionIngressCutProof
	if epoch.CoverageAgreementBodyDigest != receipt.Body.CoverageAgreementBodyDigest ||
		epoch.CoverageObligationID != receipt.Body.CoverageObligationID || epoch.ClaimID != receipt.Body.ClaimID ||
		cut.CutKind != "claim_revisions" || cut.ClaimID != receipt.Body.ClaimID ||
		cut.RevisionEpoch != epoch.RevisionEpoch || cut.PendingOrAmbiguousCount != 0 {
		return errors.New("claim decision fallback revision epoch cut differs")
	}
	headDigest, identityDigest, err := DeterministicFallbackAdmissionSourceIdentityV1(variant)
	if err != nil {
		return err
	}
	fields := DecisionAdmissionSemanticFieldsV1(bound, actionBody, decision, headDigest, identityDigest)
	if err := VerifyPortableStageActionAdmissionEvidenceV1(receipt.StageActionAdmissionEvidence, bound, request,
		fields, authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	body := receipt.Body
	target, targetErr := decisionTargetStateV1(decision.Body.Result)
	actionDigest, actionErr := agentcommerce.AuthorizedActionDigest(receipt.StageActionAdmissionEvidence.AuthorizedAction)
	proofDigest, proofErr := AuthorityAdmissionEligibilityProofSetDigestV1(receipt.AuthorityAdmissionEligibilityProofSet)
	if targetErr != nil || actionErr != nil || proofErr != nil || body.SchemaVersion != 1 || body.AuthorityID != bound.ActionAuthorityID ||
		body.CoverageAgreementBodyDigest != claim.Body.CoverageAgreementBodyDigest || body.CoverageObligationID != claim.Body.CoverageObligationID ||
		body.ClaimID != claim.Body.ClaimID || body.AuthorizedClaimDecisionDigest != decisionDigest || body.AdmissionMode != "deterministic_fallback" ||
		body.ClaimRevisionIngressCutProofDigest != cutDigest || body.LateFilingCloseReceiptDigest != lateFilingDigest ||
		body.PredecessorDecisionAdmissionReceiptDigest != predecessorAdmissionDigest ||
		body.PredecessorClaimStateTransitionReceiptDigest != predecessorTransitionDigest ||
		body.DecisionSequence != wantSequence || body.DecisionRevision != 1 || body.DecisionPath != wantPath ||
		body.PriorClaimState != wantPriorState || body.AdmittedClaimState != target || body.AdmittedClaimStateRevision != body.PriorClaimStateRevision+1 ||
		body.AdmittedCoverageRevision != body.PriorCoverageRevision+1 || body.PriorCoverageEndCommitmentDigest != endDigest ||
		body.ResultingCoverageEndCommitmentDigest != endDigest || body.AuthorizedActionDigest != actionDigest ||
		body.StableActionID != receipt.StageActionAdmissionEvidence.AuthorizedAction.StableActionID ||
		body.ExactRequestDigest != receipt.StageActionAdmissionEvidence.AuthorizedAction.ExactRequestDigest ||
		body.WriterGeneration != receipt.StageActionAdmissionEvidence.AuthorizedAction.WriterGeneration ||
		body.WriterFenceDigest != receipt.StageActionAdmissionEvidence.AuthorizedAction.WriterFenceDigest ||
		body.AuthorityAdmissionEligibilityProofSetDigest != proofDigest || body.AdmittedAtUnix != decision.Body.DecidedAtUnix {
		return errors.New("claim decision fallback admission receipt binding is invalid")
	}
	if priorPendingToken != nil {
		priorTokenDigest, _ := DecisionApplicationTokenDigestV1(*priorPendingToken)
		if body.PriorApplicationTokenDigest != priorTokenDigest || body.PriorApplicationTokenTerminalState != "replaced" {
			return errors.New("claim decision fallback prior token terminalization is invalid")
		}
	} else if receipt.PriorPendingApplicationToken != nil || body.PriorApplicationTokenDigest != "" ||
		body.PriorApplicationTokenTerminalState != "" {
		return errors.New("claim decision fallback carries an unrelated prior token")
	}
	before, beforeOK := new(big.Int).SetString(body.AggregatePendingDecisionReserveBefore.AmountAtomic, 10)
	after, afterOK := new(big.Int).SetString(body.AggregatePendingDecisionReserveAfter.AmountAtomic, 10)
	approved, approvedOK := new(big.Int).SetString(decision.Body.ApprovedAmount.AmountAtomic, 10)
	maximum, maximumOK := new(big.Int).SetString(terms.MaximumAggregatePayout.AmountAtomic, 10)
	wantAfter := new(big.Int)
	if beforeOK && approvedOK {
		wantAfter.Add(before, approved)
		if priorPendingToken != nil {
			prior, parsed := new(big.Int).SetString(priorPendingToken.ReservedApprovedAmount.AmountAtomic, 10)
			if !parsed || wantAfter.Sub(wantAfter, prior).Sign() < 0 {
				return errors.New("claim decision fallback reserve replacement underflows")
			}
		}
	}
	if !beforeOK || !afterOK || !approvedOK || !maximumOK || after.Cmp(wantAfter) != 0 || after.Cmp(maximum) > 0 {
		return errors.New("claim decision fallback aggregate reserve is invalid")
	}
	if err := validateEligibilityProofSetAgainstV1(receipt.AuthorityAdmissionEligibilityProofSet, actionDigest,
		decisionDigest, terms.DecisionAdmissionAuthoritySubjects,
		"claim-decision-admission-receipt", decisionDigest, fallbackDigest,
		terms.ClaimClosureCapacity.TerminalFallback.FallbackProfile, terms.CoverageStateDomainDigest,
		body.DecisionSequence, body.AdmittedAtUnix); err != nil {
		return err
	}
	bodyDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-claim-decision-admission-receipt-body.v1", body)
	return verifyReceiptAuthorizationSetV1(receipt.Authorizations, "claim-decision-admission-receipt", bodyDigest,
		"tos.service.agent-guarantor-claim-decision-admission-signature.v1", terms.DecisionAdmissionProfile,
		terms.DecisionAdmissionAuthoritySubjects, terms.DecisionAdmissionQuorumRule, authorityResolver, now)
}
