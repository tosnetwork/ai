package agentguarantor

import "errors"

// bindTerminalClaimSetToFilingCloseV1 ties a terminal claim set body to the
// filing-close receipt it carries, to the firm offer and to the Agreement's
// terms, before any signature is checked. The body restates the filing close
// (coverage, reasons, incident cutoff, end evidence, admission log, close
// revision and close time) so that a light verifier can read it without
// opening the receipt; every restated value must be the receipt's, or the set
// could describe one coverage end and carry the proof of another. Its
// coverage revisions and times follow the close: closure happens at or after
// the close revision and moves coverage by exactly one revision, and no claim
// set is terminal before filing closed or created before it was terminal.
func bindTerminalClaimSetToFilingCloseV1(body TerminalClaimSetBodyV1, filing ClaimFilingCloseReceiptBodyV1,
	offer AuthorizedFirmCoverageOfferV1) error {
	if body.CoverageAgreementBodyDigest != filing.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != filing.CoverageObligationID {
		return errors.New("terminal claim set belongs to another coverage than its filing close")
	}
	if body.CoverageAgreementBodyDigest != offer.Body.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != offer.Body.CoverageObligationID {
		return errors.New("terminal claim set belongs to another coverage than the firm offer")
	}
	terms := offer.CoverageTerms
	if body.ClaimAdmissionProfileDigest != terms.ClaimAdmissionProfile.ProfileDigest ||
		!equalStrings(body.ClaimAdmissionAuthoritySubjects, terms.ClaimAdmissionAuthoritySubjects) {
		return errors.New("terminal claim set names another claim admission authority than the Agreement's")
	}
	for _, restated := range []struct {
		field   string
		differs bool
	}{
		{"filing close reason", body.FilingCloseReason != filing.FilingCloseReason},
		{"coverage end reason", body.CoverageEndReason != filing.CoverageEndReason},
		{"incident eligibility end", body.IncidentEligibilityEndsAtUnix != filing.IncidentEligibilityEndsAtUnix},
		{"coverage end evidence", body.CoverageEndEvidenceDigest != filing.CoverageEndEvidenceDigest},
		{"cancellation receipt", body.CoverageCancellationReceiptDigest != filing.CoverageCancellationReceiptDigest},
		{"non-activation evidence", body.NonActivationEvidenceDigest != filing.NonActivationEvidenceDigest},
		{"claim admission log", body.ClaimAdmissionLogID != filing.ClaimAdmissionLogID},
	} {
		if restated.differs {
			return errors.New("terminal claim set restates its filing close's " + restated.field + " differently")
		}
	}
	releasePending, fits := checkedAdd(body.PriorCoverageRevision, 1)
	if body.FilingCloseCoverageRevision == 0 || body.FilingCloseCoverageRevision != filing.ClosedCoverageRevision ||
		!fits || body.ReleasePendingCoverageRevision != releasePending {
		return errors.New("terminal claim set coverage revisions do not follow its filing close")
	}
	if body.PriorCoverageRevision < body.FilingCloseCoverageRevision {
		return errors.New("terminal claim set closes the coverage at a revision before its filing close's")
	}
	if body.FilingClosedAtUnix == 0 || body.FilingClosedAtUnix != filing.ClosedAtUnix ||
		body.CreatedAtUnix < body.AllClaimsTerminalAtUnix {
		return errors.New("terminal claim set times do not follow its filing close")
	}
	if body.AllClaimsTerminalAtUnix < body.FilingClosedAtUnix {
		return errors.New("terminal claim set is terminal before its filing close")
	}
	if body.ReleaseNotBeforeUnix < body.AllClaimsTerminalAtUnix {
		return errors.New("terminal claim set allows its release before all claims were terminal")
	}
	return nil
}

// bindTerminalClaimsToFilingCutV1 ties every bundled claim to the claims
// filing froze. Each bundle's initial admission is on the set's coverage and
// is the admission of exactly one admitted entry of the filing close's ingress
// cut, so a claim admitted on another coverage, or never admitted before the
// close, cannot fill a slot. The initial admissions also recompute the
// coverage-level claim admission log, from its empty root, one leaf per
// claim in admission order, to the root the filing close froze.
func bindTerminalClaimsToFilingCutV1(bundles []ClaimTerminalResolutionBundleV1, body TerminalClaimSetBodyV1,
	filing AuthorizedClaimFilingCloseReceiptV1) error {
	admitted := make(map[string]struct{}, len(filing.ClaimIngressAdmissionCutProof.Entries))
	for _, entry := range filing.ClaimIngressAdmissionCutProof.Entries {
		if entry.ResolutionKind == "claim_admitted" {
			admitted[entry.ClaimAdmissionReceiptDigest] = struct{}{}
		}
	}
	// Each admitted entry serves one bundle: a bundle whose admission the cut
	// does not name, or names for a bundle already matched, is refused below.
	// The set's shape and the filing close already hold the number of bundles
	// to the cut's admitted count.
	logID, err := ClaimAdmissionLogIDV1(body.CoverageAgreementBodyDigest, body.CoverageObligationID)
	if err != nil {
		return err
	}
	root, err := InitialClaimLogRootV1(ClaimAdmissionLogRootDomainV1, logID)
	if err != nil {
		return err
	}
	for _, bundle := range bundles {
		initial := bundle.InitialClaimAdmissionReceiptProof
		admission := initial.ReceiptBody
		if admission.CoverageAgreementBodyDigest != body.CoverageAgreementBodyDigest ||
			admission.CoverageObligationID != body.CoverageObligationID {
			return errors.New("terminal claim belongs to another coverage than its set")
		}
		if _, found := admitted[initial.ReceiptEnvelopeDigest]; !found {
			return errors.New("terminal claim's initial admission is not an admitted entry of the filing cut")
		}
		delete(admitted, initial.ReceiptEnvelopeDigest)
		next, advanceErr := AdvanceClaimLogRootV1(ClaimAdmissionLogRootDomainV1, logID, root, admission.ClaimAdmissionSequence,
			InitialClaimAdmissionLeafV1{ClaimID: admission.ClaimID, AdmissionSequence: admission.ClaimAdmissionSequence,
				AuthorizedClaimEnvelopeDigest: admission.AuthorizedClaimEnvelopeDigest})
		if advanceErr != nil || admission.ClaimAdmissionLogID != logID || admission.PriorClaimAdmissionLogRoot != root ||
			admission.AdmittedClaimAdmissionLogRoot != next {
			return errors.New("terminal claim admissions do not chain from the empty claim admission log")
		}
		root = next
	}
	if root != filing.Body.FrozenClaimAdmissionLogRoot {
		return errors.New("terminal claim admissions do not end at the frozen claim admission log root")
	}
	return nil
}

// bindTerminalClaimDecisionV1 ties the decision objects of one terminal
// bundle to its claim and to each other, before any signature is checked.
// admissions is the bundle's claim admission chain, initial first.
//
// The bundle carries the claim's terminal decision admission last, possibly
// after earlier ones, and the challenge close of that decision as its last
// transition. Every carried decision admission is of this claim, stands on a
// claim admission of this bundle and, where it follows a carried one, is its
// predecessor-linked successor. Every carried transition acts on a carried
// decision admission, and one that is not the last is the transition its
// successor decision names. The terminal decision is the one the last
// admission admitted, on the final claim revision; the application proof
// consumes that admission's token through that closing transition; and the
// claim state the reference states is the closing transition's.
//
// A decision on the late-recovery path names a late filing close. A coverage
// closes filing once, so that digest is the set's own filing close.
//
// A compact decision proof cannot show when its claim was admitted; the bundle
// carries that admission beside it. An authorized decision admission is
// therefore held here to the carried claim admission it stands on: admitted
// not before it and, as the claim's initial decision, by the claim review
// cutoff.
func bindTerminalClaimDecisionV1(bundle ClaimTerminalResolutionBundleV1, admissions []ClaimAdmissionReceiptProofV1,
	filingCloseDigest string, allClaimsTerminalAtUnix uint64, terms CoverageTermsV1) error {
	proofs, transitions := bundle.DecisionAdmissionReceiptProofs, bundle.ClaimStateTransitionReceipts
	if len(admissions) == 0 || len(proofs) == 0 || len(transitions) == 0 || !validDigest(filingCloseDigest) {
		return errors.New("terminal claim omits its admission, decision or state-transition history")
	}
	initial := admissions[0].ReceiptBody
	finalAdmission := admissions[len(admissions)-1]
	claimDigest, err := ClaimEnvelopeDigest(finalAdmission.AuthorizedClaimIngressReceipt.AuthorizedClaim)
	if err != nil {
		return errors.New("terminal claim's final claim cannot be digested")
	}
	carriedAdmissions := make(map[string]ClaimAdmissionReceiptBodyV1, len(admissions))
	for _, admission := range admissions {
		carriedAdmissions[admission.ReceiptEnvelopeDigest] = admission.ReceiptBody
	}
	proofIndex := make(map[string]int, len(proofs))
	for index, proof := range proofs {
		body := proof.ReceiptBody
		if body.ClaimID != initial.ClaimID || body.CoverageAgreementBodyDigest != initial.CoverageAgreementBodyDigest ||
			body.CoverageObligationID != initial.CoverageObligationID {
			return errors.New("terminal claim carries a decision admission of another claim")
		}
		if _, duplicate := proofIndex[proof.ReceiptEnvelopeDigest]; duplicate {
			return errors.New("terminal claim carries one decision admission twice")
		}
		proofIndex[proof.ReceiptEnvelopeDigest] = index
		if index > 0 {
			previous := proofs[index-1]
			sequence, fits := checkedAdd(previous.ReceiptBody.DecisionSequence, 1)
			if !fits || body.DecisionSequence != sequence ||
				body.PredecessorDecisionAdmissionReceiptDigest != previous.ReceiptEnvelopeDigest {
				return errors.New("terminal claim decision admissions are not a predecessor-linked chain")
			}
		}
		claimAdmission, found := carriedAdmissions[body.AuthorizedClaimAdmissionReceiptDigest]
		if !found {
			return errors.New("terminal claim decision admission stands on a claim admission outside its bundle")
		}
		if body.AdmissionMode == "authorized_decision" {
			if err := bindAuthorizedDecisionAdmissionToClaimAdmissionV1(body, claimAdmission, initial,
				proof.AuthorizedClaimDecision.Body.DecisionSequence == 1, terms); err != nil {
				return err
			}
		}
		// The initial terminal fallback races the initial decision on the same
		// cutoff, which the carried initial admission fixes.
		if proof.AuthorizedClaimDecision.Body.DecisionPath == "initial_terminal_fallback" {
			if err := bindInitialFallbackToReviewCutoffV1(body, initial, terms); err != nil {
				return err
			}
		}
		if body.LateFilingCloseReceiptDigest != "" && body.LateFilingCloseReceiptDigest != filingCloseDigest {
			return errors.New("terminal claim's late-path decision names another filing close than its set's")
		}
	}
	terminal := proofs[len(proofs)-1]
	terminalClaimDigest, err := ClaimEnvelopeDigest(terminal.AuthorizedClaim)
	if err != nil || !equalCanonical(terminal.AuthorizedClaimDecision, bundle.TerminalAuthorizedDecision) {
		return errors.New("terminal claim's decision is not the one its terminal decision admission admitted")
	}
	if terminal.ReceiptBody.AuthorizedClaimAdmissionReceiptDigest != finalAdmission.ReceiptEnvelopeDigest ||
		terminalClaimDigest != claimDigest {
		return errors.New("terminal claim's decision stands on another claim admission than its final revision's")
	}
	closingDigest := ""
	for index, transition := range transitions {
		digest, digestErr := ClaimStateTransitionReceiptDigestV1(transition)
		decided, found := proofIndex[transition.DecisionAdmissionProof.ReceiptEnvelopeDigest]
		if digestErr != nil || !found {
			return errors.New("terminal claim carries a transition of a decision outside its bundle")
		}
		if transition.Body.ClaimID != initial.ClaimID {
			return errors.New("terminal claim carries a transition of another claim")
		}
		// One receipt has one sealed proof: the proof a transition embeds is the
		// carried one, byte for byte, not a second sealing of the same receipt.
		if !equalCanonical(transition.DecisionAdmissionProof, proofs[decided]) {
			return errors.New("terminal claim carries a transition whose decision admission proof is not the carried one")
		}
		if index == len(transitions)-1 {
			if transition.Body.TransitionKind != "challenge_close" || decided != len(proofs)-1 {
				return errors.New("terminal claim's last transition does not close its terminal decision")
			}
			closingDigest = digest
			continue
		}
		if decided >= len(proofs)-1 ||
			proofs[decided+1].ReceiptBody.PredecessorClaimStateTransitionReceiptDigest != digest {
			return errors.New("terminal claim carries a transition its successor decision does not name")
		}
		// The successor's compact proof does not carry this transition; the
		// bundle does, so the successor is held to it here as in its full
		// receipt. A late-recovery candidate is triggered by its filing close,
		// not by the transition it follows.
		successor := proofs[decided+1]
		if successor.AuthorizedClaimDecision.Body.DecisionPath != "late_recovery_terminal_fallback" {
			if err := bindSuccessorDecisionAdmissionToTransitionV1(successor.ReceiptBody, transition.Body); err != nil {
				return err
			}
		}
	}
	closing := transitions[len(transitions)-1].Body
	application := bundle.DecisionApplicationReceiptProof.Body
	token := terminal.ReceiptBody.ResultingApplicationToken
	if token == nil || application.ClaimDecisionAdmissionReceiptDigest != terminal.ReceiptEnvelopeDigest ||
		application.TerminalClaimStateTransitionReceiptDigest != closingDigest ||
		application.DecisionApplicationTokenID != token.TokenID {
		return errors.New("terminal claim's application proof applies another admission, transition or token")
	}
	ref := bundle.ResolutionRef
	if string(ref.TerminalClaimState) != closing.ResultingClaimState {
		return errors.New("terminal claim state differs from its closing transition's resulting state")
	}
	if ref.ClaimStateRevision != closing.ResultingClaimStateRevision {
		return errors.New("terminal claim state differs from its closing transition")
	}
	if application.AppliedClaimStateRevision != closing.ResultingClaimStateRevision {
		return errors.New("terminal claim's application proof applies at another claim state revision than its closing transition's")
	}
	if err := bindApplicationTimeToClosingTransitionV1(application.AppliedAtUnix, closing); err != nil {
		return err
	}
	if application.AppliedAtUnix > allClaimsTerminalAtUnix {
		return errors.New("terminal claim's decision is applied after the set became terminal")
	}
	return nil
}

// bindExposureReleaseToOfferV1 ties an exposure release to the firm offer
// whose reservation it releases and to the terminal claim set it consumes.
// The disposition (what returns to capacity, what is realized loss, what
// stays retained) is computed from the carried exposure admission's scope, so
// that admission must be the offer's own, byte for byte, not another one the
// same Guarantor signed with another default-liability disposition.
func bindExposureReleaseToOfferV1(value AuthorizedExposureReleaseReceiptV1, offer AuthorizedFirmCoverageOfferV1,
	bound GuarantorStageActionAuthorityV1) error {
	if !equalCanonical(value.AuthorizedExposureAdmissionReceipt, offer.ExposureAdmissionReceipt) {
		return errors.New("exposure release carries another exposure receipt than the firm offer's")
	}
	body, terminal := value.Body, value.AuthorizedTerminalClaimSetEvidence.Body
	if body.CoverageAgreementBodyDigest != offer.Body.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != offer.Body.CoverageObligationID ||
		body.CoverageAgreementBodyDigest != terminal.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != terminal.CoverageObligationID {
		return errors.New("exposure release names another coverage than the firm offer's")
	}
	if body.GuarantorAgentID != offer.Body.GuarantorAgentID {
		return errors.New("exposure release names another Guarantor than the firm offer's")
	}
	if body.AuthorityID != bound.ActionAuthorityID {
		return errors.New("exposure release names another authority than the Agreement's release authority")
	}
	if body.ReleasedAtUnix == 0 || body.ReleasedAtUnix < terminal.ReleaseNotBeforeUnix {
		return errors.New("exposure release precedes the terminal claim set's release time")
	}
	if body.ReleasedAtUnix < terminal.CreatedAtUnix {
		return errors.New("exposure release precedes the creation of its terminal claim set")
	}
	return nil
}

// bindCoverageResolutionToReleaseV1 ties a coverage resolution to the
// exposure release it carries and to that release's terminal claim set: the
// same coverage, under the bound resolution authority, resolving exactly the
// release-pending revision the claim set produced, no earlier than the
// release.
func bindCoverageResolutionToReleaseV1(body CoverageResolutionBodyV1, release ExposureReleaseReceiptBodyV1,
	terminal TerminalClaimSetBodyV1, bound GuarantorStageActionAuthorityV1) error {
	if body.CoverageAgreementBodyDigest != release.CoverageAgreementBodyDigest ||
		body.CoverageObligationID != release.CoverageObligationID {
		return errors.New("coverage resolution names another coverage than its exposure release")
	}
	if body.AuthorityID != bound.ActionAuthorityID {
		return errors.New("coverage resolution names another authority than the Agreement's resolution authority")
	}
	if body.PriorCoverageRevision != terminal.ReleasePendingCoverageRevision {
		return errors.New("coverage resolution does not follow the terminal claim set's release-pending revision")
	}
	if body.ResolvedAtUnix == 0 || body.ResolvedAtUnix < release.ReleasedAtUnix {
		return errors.New("coverage resolution precedes its exposure release")
	}
	return nil
}
