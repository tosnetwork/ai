package agentguarantor

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// signedHistoryNoPayments is the payment evidence verifier of a history whose
// claims end denied. No payout was executed, so it refuses any payment
// evidence it is shown.
type signedHistoryNoPayments struct{}

func (signedHistoryNoPayments) VerifyPaymentEvidence(agentcommerce.AgreementPaymentRequest,
	agentcommerce.AgreementPaymentEvidence, time.Time) error {
	return testError("the signed history executed no payout")
}

// applicationProof seals a decision application into its compact proof at.
func (history *signedHistory) applicationProof(receipt AuthorizedClaimDecisionApplicationReceiptV1, at uint64) DecisionApplicationReceiptProofV1 {
	proof, err := history.sealApplication(receipt, at)
	if err != nil {
		history.t.Fatal(err)
	}
	return proof
}

// sealApplication is applicationProof that returns the builder's verdict
// instead of failing the test.
func (history *signedHistory) sealApplication(receipt AuthorizedClaimDecisionApplicationReceiptV1, at uint64) (DecisionApplicationReceiptProofV1, error) {
	t := history.t
	seal, descriptor, err := NewDecisionApplicationReceiptSealBodyV1(receipt, history.terms, time.Unix(int64(at), 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	sealDigest, err := Digest(DecisionApplicationReceiptSealDomainV1, seal)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := FindStageActionAuthorityV1(history.terms.StageActionAuthorityBinding, "decision_application")
	if err != nil {
		t.Fatal(err)
	}
	authorization := history.signObjectAs(bound.ActionAuthorityID, history.terms.LifecycleAuthorizationProfile,
		"decision-application-receipt-seal", sealDigest,
		"tos.service.agent-guarantor-decision-application-receipt-seal-signature.v1", at)
	return BuildDecisionApplicationReceiptProofV1(receipt, history.terms, descriptor, seal, authorization)
}

// carriedEvidenceItem names, by content-addressed descriptor, an object whose
// canonical bytes travel elsewhere in the same envelope or are recomputed.
func carriedEvidenceItem(contentType, digest string, wire []byte, policyDigest string) CanonicalGuarantorEvidenceItemV1 {
	return CanonicalGuarantorEvidenceItemV1{ContentType: contentType, EvidenceProfileDigest: policyDigest,
		EvidenceEnvelopeDigest: digest, Representation: "content_addressed",
		ImmutableDescriptor: &ImmutableEvidenceDescriptorV1{ContentType: contentType, ContentDigest: digest,
			ContentSize: uint64(len(wire)), RetrievalPolicyDigest: policyDigest}}
}

// terminalBundle is the terminal resolution bundle of a claim that ended
// denied, sealed at: the proofs of its initial and revision admissions, its
// terminal decision with that decision's admission proof and challenge close,
// the proof of application, and the empty payout set with its no-payout
// marker. The history holds no payout execution evidence, so it bundles no
// claim that ended approved.
func (history *signedHistory) terminalBundle(claimID string, application AuthorizedClaimDecisionApplicationReceiptV1,
	at uint64) ClaimTerminalResolutionBundleV1 {
	t, terms := history.t, history.terms
	state := history.claims[claimID]
	if state.decision == nil || state.transition == nil || state.status != "final_denied" {
		t.Fatalf("signed history bundles only a claim that ended denied, not one in %s", state.status)
	}
	admissions := history.admissions[claimID]
	initialProof := history.claimAdmissionProof(admissions[0], at)
	revisionProofs := make([]ClaimAdmissionReceiptProofV1, 0, len(admissions)-1)
	for _, revision := range admissions[1:] {
		revisionProofs = append(revisionProofs, history.claimAdmissionProof(revision, at))
	}
	decision, transition := state.decision.AuthorizedClaimDecision, *state.transition
	payouts := application.MaterializedPayoutObligationSet
	decisionDigest, err := ClaimDecisionDigestV1(decision)
	if err != nil {
		t.Fatal(err)
	}
	payoutDigest, err := Digest(PayoutSetDomain, payouts)
	if err != nil {
		t.Fatal(err)
	}
	marker := GuarantorNoPayoutMarkerV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement, ClaimID: claimID,
		AuthorizedClaimDecisionDigest: decisionDigest, MaterializedPayoutObligationSetDigest: payoutDigest}
	markerBytes, err := Canonical(marker)
	if err != nil {
		t.Fatal(err)
	}
	markerDigest, err := Digest("tos.service.agent-guarantor-no-payout-marker.v1", marker)
	if err != nil {
		t.Fatal(err)
	}
	zero := history.amount(0)
	terminalPayouts := TerminalPayoutEvidenceSetV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		ClaimID: claimID, AuthorizedClaimDecisionDigest: decisionDigest, MaterializedPayoutObligationSetDigest: payoutDigest,
		Disposition: "not_applicable", ApprovedAmount: decision.Body.ApprovedAmount, PaidAmount: zero, DefaultedAmount: zero,
		OutstandingAmount: zero, PayoutExecutionEvidence: []AuthorizedGuarantorPayoutExecutionEvidenceV1{},
		TerminalSettlementEvidenceSet: CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1, Purpose: "terminal-payout",
			ContextDigest: decisionDigest, Items: []CanonicalGuarantorEvidenceItemV1{carriedEvidenceItem(
				GuarantorNoPayoutMarkerContentTypeV1, markerDigest, markerBytes, terms.SelectedPayoutAdapterProfile.ProfileDigest)}}}
	bundle := ClaimTerminalResolutionBundleV1{InitialClaimAdmissionReceiptProof: initialProof,
		RevisionAdmissionReceiptProofs: revisionProofs, TerminalAuthorizedDecision: decision,
		DecisionAdmissionReceiptProofs:  []ClaimDecisionAdmissionReceiptProofV1{transition.DecisionAdmissionProof},
		DecisionApplicationReceiptProof: history.applicationProof(application, at),
		ClaimStateTransitionReceipts:    []AuthorizedClaimStateTransitionReceiptV1{transition},
		MaterializedPayoutObligationSet: payouts, TerminalPayoutEvidenceSet: terminalPayouts}
	bundle.ResolutionRef = history.terminalRef(bundle)
	return bundle
}

// terminalRef derives a bundle's resolution reference from the objects it
// carries, as the closure sink does. A test that rearranges the signed pieces
// of a bundle derives the reference again, so the rearranged bundle is refused
// for the pieces and not for a stale reference.
func (history *signedHistory) terminalRef(bundle ClaimTerminalResolutionBundleV1) ClaimTerminalResolutionRefV1 {
	t := history.t
	initial, final := bundle.InitialClaimAdmissionReceiptProof, bundle.InitialClaimAdmissionReceiptProof
	if count := len(bundle.RevisionAdmissionReceiptProofs); count > 0 {
		final = bundle.RevisionAdmissionReceiptProofs[count-1]
	}
	claimDigest, err := ClaimEnvelopeDigest(final.AuthorizedClaimIngressReceipt.AuthorizedClaim)
	if err != nil {
		t.Fatal(err)
	}
	decisionDigest, err := ClaimDecisionDigestV1(bundle.TerminalAuthorizedDecision)
	if err != nil {
		t.Fatal(err)
	}
	payoutDigest, err := Digest(PayoutSetDomain, bundle.MaterializedPayoutObligationSet)
	if err != nil {
		t.Fatal(err)
	}
	terminalPayoutDigest, err := TerminalPayoutEvidenceSetDigestV1(bundle.TerminalPayoutEvidenceSet)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.DecisionAdmissionReceiptProofs) == 0 || len(bundle.ClaimStateTransitionReceipts) == 0 {
		t.Fatal("a terminal bundle carries a decision admission proof and a transition")
	}
	closing := bundle.ClaimStateTransitionReceipts[len(bundle.ClaimStateTransitionReceipts)-1]
	transitionDigest, err := ClaimStateTransitionReceiptDigestV1(closing)
	if err != nil {
		t.Fatal(err)
	}
	return ClaimTerminalResolutionRefV1{ClaimAdmissionSequence: initial.ReceiptBody.ClaimAdmissionSequence,
		ClaimID:                            initial.ReceiptBody.ClaimID,
		InitialClaimAdmissionReceiptDigest: initial.ReceiptEnvelopeDigest, FinalClaimRevision: final.ReceiptBody.AdmittedClaimRevision,
		FinalClaimRevisionAdmissionReceiptDigest: final.ReceiptEnvelopeDigest,
		ClaimRevisionAdmissionHighWater:          final.ReceiptBody.ClaimRevisionAdmissionSequence,
		ClaimRevisionAdmissionLogRoot:            final.ReceiptBody.AdmittedClaimRevisionLogRoot,
		ClaimRevisionIngressHighWater:            final.AuthorizedClaimIngressReceipt.Body.ClaimIngressSequence,
		ClaimRevisionIngressLogRoot:              final.AuthorizedClaimIngressReceipt.Body.AdmittedClaimIngressLogRoot,
		TerminalAuthorizedClaimEnvelopeDigest:    claimDigest, TerminalDecisionDigest: decisionDigest,
		TerminalDecisionAdmissionReceiptDigest: bundle.DecisionAdmissionReceiptProofs[len(bundle.DecisionAdmissionReceiptProofs)-1].ReceiptEnvelopeDigest,
		DecisionApplicationReceiptDigest:       bundle.DecisionApplicationReceiptProof.ReceiptEnvelopeDigest,
		TerminalClaimState:                     ClaimStatus("final_" + string(bundle.TerminalAuthorizedDecision.Body.Result)),
		ClaimStateRevision:                     closing.Body.ResultingClaimStateRevision, TerminalClaimStateTransitionReceiptDigest: transitionDigest,
		MaterializedPayoutObligationSetDigest: payoutDigest, TerminalPayoutEvidenceSetDigest: terminalPayoutDigest}
}

// terminalSet closes the coverage at over bundles, the terminal bundles of
// every claim filing froze, in claim admission order. Every bundled claim
// ended denied, so nothing was approved, paid or defaulted.
func (history *signedHistory) terminalSet(filing AuthorizedClaimFilingCloseReceiptV1,
	bundles []ClaimTerminalResolutionBundleV1, at uint64) AuthorizedTerminalClaimSetEvidenceV1 {
	t, terms := history.t, history.terms
	if replaced := history.vary.closureAgreement; replaced != "" {
		// Everything the set itself states names the replaced Agreement; the
		// filing close and the bundles it carries stay the history's.
		own := history.agreement
		history.agreement = replaced
		defer func() { history.agreement = own }()
	}
	filingDigest, err := ClaimFilingCloseReceiptDigestV1(filing)
	if err != nil {
		t.Fatal(err)
	}
	filingBytes, err := Canonical(filing)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest := terms.ClaimAdmissionProfile.ProfileDigest
	refs := make([]ClaimTerminalResolutionRefV1, len(bundles))
	items := []CanonicalGuarantorEvidenceItemV1{carriedEvidenceItem(
		"application/vnd.tos.service.agent-guarantor-claim-filing-close-envelope.v1+cbor", filingDigest, filingBytes, policyDigest)}
	for index, bundle := range bundles {
		refs[index] = bundle.ResolutionRef
		bundleBytes, err := Canonical(bundle)
		if err != nil {
			t.Fatal(err)
		}
		bundleDigest, err := Digest("tos.service.agent-guarantor-claim-terminal-resolution-bundle.v1", bundle)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, carriedEvidenceItem(
			"application/vnd.tos.service.agent-guarantor-claim-terminal-resolution-bundle.v1+cbor", bundleDigest, bundleBytes, policyDigest))
	}
	sort.Slice(items, func(i, j int) bool {
		left, _ := Canonical(items[i])
		right, _ := Canonical(items[j])
		return string(left) < string(right)
	})
	high := uint64(len(bundles))
	refSet := ClaimTerminalResolutionRefSetV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		CoverageObligationID: history.obligation, AdmissionHighWater: high, Refs: refs}
	refSetDigest, err := ClaimTerminalResolutionRefSetDigestV1(refSet)
	if err != nil {
		t.Fatal(err)
	}
	zero := history.amount(0)
	// The set is created when its closure action is admitted, at. By default
	// that is also when its claims became terminal and its release is allowed.
	terminalAt := at
	if history.vary.closureTerminalAt != 0 {
		terminalAt = history.vary.closureTerminalAt
	}
	closureReason, targetState := filing.Body.CoverageEndReason, "closed"
	closure := CoverageClosureEvidenceContextV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		CoverageObligationID: history.obligation, ClaimFilingCloseReceiptDigest: filingDigest,
		CoverageEndCommitmentDigest: filing.Body.CoverageEndCommitmentDigest, FilingCloseReason: filing.Body.FilingCloseReason,
		CoverageEndReason: filing.Body.CoverageEndReason, IncidentEligibilityEndsAtUnix: filing.Body.IncidentEligibilityEndsAtUnix,
		CoverageEndEvidenceDigest: filing.Body.CoverageEndEvidenceDigest, ActivationEvidenceDigest: filing.Body.ActivationEvidenceDigest,
		CoverageClosureReason: closureReason, ResolutionTargetTerminalState: targetState, AdmissionHighWater: high,
		ClaimAdmissionLogRoot: filing.Body.FrozenClaimAdmissionLogRoot, ClaimResolutionSetDigest: refSetDigest,
		CumulativeApprovedAmount: zero, CumulativePaidAmount: zero, CumulativeDefaultedAmount: zero,
		OutstandingApprovedAmount: zero, ReleaseNotBeforeUnix: terminalAt}
	if history.vary.closureContext != nil {
		history.vary.closureContext(&closure)
	}
	closureDigest, err := CoverageClosureEvidenceContextDigestV1(closure)
	if err != nil {
		t.Fatal(err)
	}
	evidence := CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1, Purpose: "coverage-closure", ContextDigest: closureDigest, Items: items}
	evidenceDigest, err := CanonicalGuarantorEvidenceSetDigestV1(evidence)
	if err != nil {
		t.Fatalf("coverage closure evidence set is invalid: %v", err)
	}
	projection := TransitionEvidenceProjectionV1{SchemaVersion: 1, Purpose: "coverage-closure",
		CoverageAgreementBodyDigest: history.agreement, ObligationID: history.obligation, TargetState: "release_pending",
		EvidenceDigests: []TransitionEvidenceDigestRefV1{
			{EvidenceRole: "claim-filing-close", DigestKind: "authorized_envelope", ObjectDigest: filingDigest},
			{EvidenceRole: "claim-resolution-set", DigestKind: "canonical_set", ObjectDigest: refSetDigest},
			{EvidenceRole: "closure-evidence-set", DigestKind: "canonical_set", ObjectDigest: evidenceDigest}}}
	sort.Slice(projection.EvidenceDigests, func(i, j int) bool {
		left, _ := Canonical(projection.EvidenceDigests[i])
		right, _ := Canonical(projection.EvidenceDigests[j])
		return string(left) < string(right)
	})
	projectionDigest, err := TransitionEvidenceProjectionDigestV1(projection)
	if err != nil {
		t.Fatal(err)
	}
	request := CoverageClosureActionBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		CoverageObligationID: history.obligation, ClaimFilingCloseReceiptDigest: filingDigest,
		ExpectedCoverageEndCommitmentDigest: filing.Body.CoverageEndCommitmentDigest, ClaimResolutionBundles: bundles,
		ClaimResolutionRefSet: refSet, ClosureReason: closureReason, ExpectedCoverageRevision: history.coverageRevision,
		TargetCoverageRevision: history.coverageRevision + 1, TargetCoverageState: "release_pending",
		ExpectedClaimSetRevision: 0, TargetClaimSetRevision: 1, CoverageClosureEvidenceContext: closure,
		TerminalPrerequisiteEvidenceSet: evidence, TransitionEvidenceProjection: projection}
	canonical, err := Canonical(request)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]agentcommerce.SemanticValue{"owner_id": agentcommerce.ID("owner:guarantor"),
		"agent_id": agentcommerce.ID(signedHistoryGuarantor), "agreement_body_digest": agentcommerce.Digest32(history.agreement),
		"obligation_id":           agentcommerce.ID(history.obligation),
		"expected_state_revision": agentcommerce.U64(history.coverageRevision), "target_state": agentcommerce.State("release_pending"),
		"evidence_set_digest": agentcommerce.Digest32(evidenceDigest)}
	stage := history.stage("coverage_closure", "application/vnd.tos.service.agent-guarantor-coverage-closure-action.v1+cbor",
		canonical, fields, filingDigest, terms.LateRecoveryTerminalDeadlineUnix, at, "", nil)
	action := stage.AuthorizedAction
	actionDigest, err := agentcommerce.AuthorizedActionDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	stage.ActionResolution.SinkReference, stage.ActionResolution.EvidenceRefs = actionDigest, []string{actionDigest}
	body := TerminalClaimSetBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		CoverageObligationID: history.obligation, ClaimAdmissionProfileDigest: policyDigest,
		ClaimAdmissionAuthoritySubjects: append([]string(nil), terms.ClaimAdmissionAuthoritySubjects...),
		ClaimAdmissionLogID:             filing.Body.ClaimAdmissionLogID, ClaimFilingCloseReceiptDigest: filingDigest,
		CoverageEndCommitmentDigest: filing.Body.CoverageEndCommitmentDigest, FilingCloseReason: closure.FilingCloseReason,
		CoverageEndReason: closure.CoverageEndReason, IncidentEligibilityEndsAtUnix: closure.IncidentEligibilityEndsAtUnix,
		CoverageEndEvidenceDigest:         closure.CoverageEndEvidenceDigest,
		CoverageCancellationReceiptDigest: closure.CoverageCancellationReceiptDigest,
		ActivationEvidenceDigest:          filing.Body.ActivationEvidenceDigest,
		CoverageClosureReason:             closureReason, ResolutionTargetTerminalState: targetState,
		CoverageClosureContextDigest: closureDigest, CoverageClosureEvidenceSetDigest: evidenceDigest,
		TransitionEvidenceProjectionDigest: projectionDigest, FilingCloseCoverageRevision: filing.Body.ClosedCoverageRevision,
		PriorCoverageRevision: history.coverageRevision, ReleasePendingCoverageRevision: history.coverageRevision + 1,
		AdmissionHighWater: high, ClaimAdmissionLogRoot: filing.Body.FrozenClaimAdmissionLogRoot, ClaimResolutions: refs,
		CumulativeApprovedAmount: zero, CumulativePaidAmount: zero, CumulativeDefaultedAmount: zero,
		OutstandingApprovedAmount: zero, ClaimSetRevision: 1, FilingClosedAtUnix: filing.Body.ClosedAtUnix,
		AllClaimsTerminalAtUnix: terminalAt, ReleaseNotBeforeUnix: closure.ReleaseNotBeforeUnix, AuthorizedActionDigest: actionDigest,
		StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		WriterGeneration: action.WriterGeneration, WriterFenceDigest: action.WriterFenceDigest, CreatedAtUnix: at,
		RequiredExtensions: append([]ProfileRefV1(nil), terms.RequiredExtensions...),
		OptionalExtensions: append([]ProfileRefV1(nil), terms.OptionalExtensions...)}
	if history.vary.closureBody != nil {
		history.vary.closureBody(&body)
	}
	bodyDigest, err := Digest("tos.service.agent-guarantor-terminal-claim-set-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	return AuthorizedTerminalClaimSetEvidenceV1{Body: body, StageActionAdmissionEvidence: stage,
		AuthorizedClaimFilingCloseReceipt: filing, ClaimResolutionBundles: bundles, ClaimResolutionRefSet: refSet,
		CoverageClosureEvidenceContext: closure, CoverageClosureEvidenceSet: evidence, TransitionEvidenceProjection: projection,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObject("terminal-claim-set", bodyDigest,
			"tos.service.agent-guarantor-terminal-claim-set-signature.v1", at)}}
}

// verifyTerminalSet is the terminal claim set verifier at at.
func (history *signedHistory) verifyTerminalSet(set AuthorizedTerminalClaimSetEvidenceV1, at uint64) error {
	return VerifyTerminalClaimSetV1(set, history.offer, permissiveAgreementVerifier{}, history.resolver,
		history.fenceResolver, signedHistoryNoPayments{}, time.Unix(int64(at), 0).UTC())
}

// lateDeniedClaim is one claim of three revisions taken to its terminal denial
// on the late-recovery path, with its decision applied.
type lateDeniedClaim struct {
	history     *signedHistory
	claimID     string
	filing      AuthorizedClaimFilingCloseReceiptV1
	application AuthorizedClaimDecisionApplicationReceiptV1
	// closedAt is when the coverage can close: after the application.
	closedAt uint64
}

// newLateDeniedClaim files a claim and two revisions, closes filing late and
// takes the claim to final_denied: through the late-recovery candidate itself
// or, when challenged, through the challenge of that candidate and the
// fallback at the successor deadline, which carries the candidate's marker.
// When foreignInitial is set, the last revision is admitted naming that
// receipt as its initial admission instead of the claim's own. Only a
// revision after the first can do so: the first revision's predecessor is the
// initial admission, and its body alone shows a mismatch.
func newLateDeniedClaim(t *testing.T, challenged bool, foreignInitial *AuthorizedClaimAdmissionReceiptV1) lateDeniedClaim {
	t.Helper()
	history := newSignedHistory(t)
	withSignedHistorySeam(t, history)
	first := history.claim(1, nil, signedHistoryStart+30)
	initial := history.admit(first, signedHistoryStart+40)
	claimID := first.Body.ClaimID
	second := history.claim(2, &first, signedHistoryStart+50)
	history.admit(second, signedHistoryStart+60)
	if foreignInitial != nil {
		history.initialReceipts[claimID] = *foreignInitial
	}
	third := history.claim(3, &second, signedHistoryStart+70)
	history.admit(third, signedHistoryStart+80)
	history.initialReceipts[claimID] = initial
	lateAt := history.terms.TerminalResolutionDeadlineUnix + 60
	filing := history.filingClose(lateAt)
	denied := history.fallback(claimID, &filing, lateAt+10)
	if challenged {
		challenge := history.challenge(claimID, lateAt+20)
		denied = history.fallback(claimID, nil, challenge.Body.SuccessorDecisionDueAtUnix)
	}
	closeAt := denied.Body.ChallengeEndsAtUnix
	history.challengeClose(claimID, closeAt)
	application := history.apply(claimID, history.materialize(claimID, history.terms), closeAt+10)
	return lateDeniedClaim{history: history, claimID: claimID, filing: filing, application: application, closedAt: closeAt + 20}
}

// TestSignedHistoryVerifiesALatePathTerminalClaimSetEndingDenied: claim
// filing closes late and the claim ends denied on the late-recovery path,
// through the candidate itself or through the fallback after the challenged
// candidate. The signed application of that denial verifies, materializing
// no payout, and the terminal claim set over the late filing close and the
// claim's bundle verifies in full with a payment verifier that accepts
// nothing.
func TestSignedHistoryVerifiesALatePathTerminalClaimSetEndingDenied(t *testing.T) {
	for _, test := range []struct {
		name       string
		challenged bool
		path       string
	}{
		{"through the late-recovery candidate", false, "late_recovery_terminal_fallback"},
		{"through the fallback after the challenged candidate", true, "terminal_fallback"},
	} {
		t.Run(test.name, func(t *testing.T) {
			claim := newLateDeniedClaim(t, test.challenged, nil)
			history := claim.history
			if err := history.verifyApplication(claim.application, claim.closedAt); err != nil {
				t.Fatalf("the signed application of the late denial does not verify: %v", err)
			}
			if payouts := claim.application.MaterializedPayoutObligationSet; payouts.MaterializationState != "not_applicable" ||
				len(payouts.Obligations) != 0 {
				t.Fatalf("the late denial materialized a payout: %+v", payouts)
			}
			bundle := history.terminalBundle(claim.claimID, claim.application, claim.closedAt)
			terminal := bundle.DecisionAdmissionReceiptProofs[0]
			if !OnLateRecoveryPathV1(terminal.ReceiptBody) || terminal.AuthorizedClaimDecision.Body.DecisionPath != test.path {
				t.Fatalf("the terminal decision is not the late-path %s: path %q, late filing-close digest %q", test.path,
					terminal.AuthorizedClaimDecision.Body.DecisionPath, terminal.ReceiptBody.LateFilingCloseReceiptDigest)
			}
			if claim.filing.Body.ClosedAtUnix <= history.terms.TerminalResolutionDeadlineUnix {
				t.Fatal("claim filing did not close after the terminal resolution deadline")
			}
			set := history.terminalSet(claim.filing, []ClaimTerminalResolutionBundleV1{bundle}, claim.closedAt)
			if err := history.verifyTerminalSet(set, claim.closedAt); err != nil {
				t.Fatalf("the signed late-path terminal claim set does not verify: %v", err)
			}
		})
	}
}

// TestSignedHistoryTerminalClaimSetRefusesASubstitutedBundle: a terminal claim
// set whose shape, digests, arithmetic and own signatures all hold is refused
// when the admission chain, an admission proof or the application proof
// inside a bundle is not the claim's own.
func TestSignedHistoryTerminalClaimSetRefusesASubstitutedBundle(t *testing.T) {
	refused := func(name string, claim lateDeniedClaim, bundle ClaimTerminalResolutionBundleV1, want string) {
		t.Helper()
		set := claim.history.terminalSet(claim.filing, []ClaimTerminalResolutionBundleV1{bundle}, claim.closedAt)
		if err := ValidateTerminalClaimSetV1(set); err != nil {
			t.Errorf("%s: the substituted set is already refused by its shape: %v", name, err)
			return
		}
		if err := claim.history.verifyTerminalSet(set, claim.closedAt); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, want)
		}
	}
	claim := newLateDeniedClaim(t, false, nil)
	history := claim.history

	sealed := history.terminalBundle(claim.claimID, claim.application, claim.closedAt)
	proof := &sealed.InitialClaimAdmissionReceiptProof
	proof.SealAuthorization = history.signObjectAs("authority:other", history.terms.LifecycleAuthorizationProfile,
		"claim-admission-receipt-seal", proof.SealAuthorization.AuthorizedBodyDigest,
		"tos.service.agent-guarantor-claim-admission-receipt-seal-signature.v1", proof.SealBody.SealedAtUnix)
	refused("an admission proof sealed by another authority", claim, sealed, "claim admission compact proof binding is invalid")

	// The application receipt is signed and sealed in full, as the claim's
	// own, over a body that names another decision.
	forged := claim.application
	forged.Body.AuthorizedClaimDecisionDigest = testDigest("7")
	forged.Authorizations = []ProfileQualifiedObjectAuthorizationV1{
		history.applicationAuthorization(forged.Body, forged.Body.AppliedAtUnix)}
	history.store(forged)
	refused("an application proof naming another decision", claim,
		history.terminalBundle(claim.claimID, forged, claim.closedAt),
		"terminal claim has no exact authorized decision application proof")

	// The same claim admitted a second later is another initial admission of
	// the same claim ID, signed by the same authorities. The claim's last
	// revision names it.
	other := newSignedHistory(t)
	foreign := other.admit(other.claim(1, nil, signedHistoryStart+31), signedHistoryStart+41)
	poisoned := newLateDeniedClaim(t, false, &foreign)
	bundle := poisoned.history.terminalBundle(poisoned.claimID, poisoned.application, poisoned.closedAt)
	if len(bundle.RevisionAdmissionReceiptProofs) != 2 {
		t.Fatalf("the bundle carries %d revision proofs, want 2", len(bundle.RevisionAdmissionReceiptProofs))
	}
	revision := bundle.RevisionAdmissionReceiptProofs[1].ReceiptBody
	if revision.ClaimID != bundle.InitialClaimAdmissionReceiptProof.ReceiptBody.ClaimID ||
		revision.PredecessorRevisionAdmissionReceiptDigest != bundle.RevisionAdmissionReceiptProofs[0].ReceiptEnvelopeDigest ||
		revision.InitialClaimAdmissionReceiptDigest == bundle.InitialClaimAdmissionReceiptProof.ReceiptEnvelopeDigest {
		t.Fatal("the revision does not differ from the claim's chain in its initial admission digest alone")
	}
	refused("a revision naming another initial admission", poisoned, bundle,
		"terminal claim revision names another initial admission or claim")
}
