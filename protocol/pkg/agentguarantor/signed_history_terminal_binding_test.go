package agentguarantor

import (
	"testing"
	"time"
)

// The pieces of a terminal claim set on signed history: the set against its
// filing close and the firm offer, each bundled claim against the filing cut
// and the frozen admission log, and the decision objects of a bundle against
// the claim and each other. Every refused set is signed in full over pieces
// that are themselves signed; it is refused for how the pieces are combined.

// lateChainOptions varies how a lateChain is built.
type lateChainOptions struct {
	// vary applies while the claim history is signed, up to the terminal
	// decision.
	vary signedHistoryVariation
	// agreement, when set, is the Agreement the whole history is signed on.
	agreement string
	// logRoot, when set, is the claim admission log root the first claim is
	// admitted on, instead of the log's empty root.
	logRoot string
	// candidateAt is when the late-recovery candidate is admitted, seconds
	// after the late filing close; zero means 10.
	candidateAt uint64
	// candidateOnSecondRevision admits the candidate on the claim's second
	// revision although the third is admitted.
	candidateOnSecondRevision bool
	// unchallenged ends the claim on the candidate itself.
	unchallenged bool
	// closing applies while the terminal decision's challenge close is
	// signed.
	closing signedHistoryVariation
	// appliedAt is when the terminal decision is applied, given the time of its
	// challenge close; nil means ten seconds after the close.
	appliedAt func(closeAt uint64) uint64
}

// lateChain is one claim of three revisions taken to its terminal denial on
// the late-recovery path with its decision applied, and the signed pieces of
// its decision history: the challenge of the candidate, which carries the
// candidate's proof, and the same challenge admitted a second later.
type lateChain struct {
	history        *signedHistory
	claimID        string
	filing         AuthorizedClaimFilingCloseReceiptV1
	challenge      AuthorizedClaimStateTransitionReceiptV1
	laterChallenge AuthorizedClaimStateTransitionReceiptV1
	application    AuthorizedClaimDecisionApplicationReceiptV1
	closedAt       uint64
}

func newLateChain(t *testing.T, options lateChainOptions) lateChain {
	t.Helper()
	history := newSignedHistory(t)
	withSignedHistorySeam(t, history)
	if options.agreement != "" {
		history.agreement = options.agreement
	}
	if options.logRoot != "" {
		history.claimLogRoot = options.logRoot
	}
	history.vary = options.vary
	first := history.claim(1, nil, signedHistoryStart+30)
	history.admit(first, signedHistoryStart+40)
	claimID := first.Body.ClaimID
	second := history.claim(2, &first, signedHistoryStart+50)
	history.admit(second, signedHistoryStart+60)
	third := history.claim(3, &second, signedHistoryStart+70)
	history.admit(third, signedHistoryStart+80)
	lateAt := history.terms.TerminalResolutionDeadlineUnix + 60
	chain := lateChain{history: history, claimID: claimID, filing: history.filingClose(lateAt)}
	candidateAt := lateAt + 10
	if options.candidateAt != 0 {
		candidateAt = lateAt + options.candidateAt
	}
	admissions, latest := history.admissions[claimID], history.latestReceipts[claimID]
	if options.candidateOnSecondRevision {
		history.admissions[claimID], history.latestReceipts[claimID] = admissions[:2], admissions[1]
	}
	denied := history.fallback(claimID, &chain.filing, candidateAt)
	history.admissions[claimID], history.latestReceipts[claimID] = admissions, latest
	if !options.unchallenged {
		// Both challenges carry the candidate's proof sealed at one time, so
		// they differ only in when they were admitted.
		history.vary.proofSealedAt = candidateAt
		restore := history.checkpoint(claimID)
		chain.laterChallenge = history.challenge(claimID, lateAt+21)
		restore()
		chain.challenge = history.challenge(claimID, lateAt+20)
		history.vary.proofSealedAt = 0
		denied = history.fallback(claimID, nil, chain.challenge.Body.SuccessorDecisionDueAtUnix)
	}
	closeAt := denied.Body.ChallengeEndsAtUnix
	history.vary = options.closing
	history.challengeClose(claimID, closeAt)
	history.vary = signedHistoryVariation{}
	appliedAt := closeAt + 10
	if options.appliedAt != nil {
		appliedAt = options.appliedAt(closeAt)
	}
	chain.application = history.apply(claimID, history.materialize(claimID, history.terms), appliedAt)
	chain.closedAt = closeAt + 20
	return chain
}

// bundle is the chain's honest terminal bundle: the terminal decision's proof
// and its challenge close.
func (chain lateChain) bundle() ClaimTerminalResolutionBundleV1 {
	return chain.history.terminalBundle(chain.claimID, chain.application, chain.closedAt)
}

// verdict signs the terminal claim set over the chain's filing close and
// bundle, after deriving the bundle's reference from what it now carries, and
// returns the verifier's verdict. The set must pass the shape validation: a
// refusal has to come from the bindings.
func (chain lateChain) verdict(t *testing.T, name string, bundle ClaimTerminalResolutionBundleV1) error {
	t.Helper()
	bundle.ResolutionRef = chain.history.terminalRef(bundle)
	return chain.verdictOf(t, name, bundle)
}

func (chain lateChain) verdictOf(t *testing.T, name string, bundle ClaimTerminalResolutionBundleV1) error {
	t.Helper()
	set := chain.history.terminalSet(chain.filing, []ClaimTerminalResolutionBundleV1{bundle}, chain.closedAt)
	if err := ValidateTerminalClaimSetV1(set); err != nil {
		t.Errorf("%s: the set is already refused by its shape: %v", name, err)
	}
	return chain.history.verifyTerminalSet(set, chain.closedAt)
}

// TestSignedHistoryTerminalClaimSetFollowsItsFilingCloseAndOffer: the signed
// terminal claim set restates its filing close and names the firm offer's
// coverage. It verifies as built, and is refused when the set is signed for
// another Agreement than its filing close, verified against an offer for
// another Agreement, or signed with a body that names another claim admission
// authority, restates any value of the filing close differently (each of the
// seven restated values has its own case), closes at another revision than
// the filing close allows, or states times that do not follow the filing
// close, the claims' terminal time or the application of the claim's decision.
func TestSignedHistoryTerminalClaimSetFollowsItsFilingCloseAndOffer(t *testing.T) {
	chain := newLateChain(t, lateChainOptions{})
	history := chain.history
	bundle := chain.bundle()
	if err := chain.verdictOf(t, "the honest set", bundle); err != nil {
		t.Fatalf("the signed terminal claim set does not verify: %v", err)
	}
	body := func(change func(*TerminalClaimSetBodyV1)) signedHistoryVariation {
		return signedHistoryVariation{closureBody: change}
	}
	contextAndBody := func(change func(*CoverageClosureEvidenceContextV1)) signedHistoryVariation {
		return signedHistoryVariation{closureContext: change}
	}
	// The honest set allows its release exactly when all claims are terminal.
	if set := history.terminalSet(chain.filing, []ClaimTerminalResolutionBundleV1{bundle}, chain.closedAt); set.Body.ReleaseNotBeforeUnix != set.Body.AllClaimsTerminalAtUnix {
		t.Fatalf("the honest set allows its release at %d, want the time all claims were terminal, %d",
			set.Body.ReleaseNotBeforeUnix, set.Body.AllClaimsTerminalAtUnix)
	}
	for _, test := range []struct {
		name string
		vary signedHistoryVariation
		want string
	}{
		{"a set signed for another Agreement", signedHistoryVariation{closureAgreement: testDigest("9")},
			"terminal claim set belongs to another coverage than its filing close"},
		{"another claim admission authority", body(func(body *TerminalClaimSetBodyV1) {
			body.ClaimAdmissionAuthoritySubjects = []string{"agent:other"}
		}), "terminal claim set names another claim admission authority than the Agreement's"},
		{"another claim admission log", body(func(body *TerminalClaimSetBodyV1) { body.ClaimAdmissionLogID = "claim-log:other" }),
			"terminal claim set restates its filing close's claim admission log differently"},
		// The closure context states each of the next five values as well, and
		// the set's shape holds the body to its context, so both are signed with
		// the changed value: the set is refused for the filing close alone.
		{"another filing close reason", contextAndBody(func(closure *CoverageClosureEvidenceContextV1) {
			closure.FilingCloseReason = "accepted_cancellation"
		}), "terminal claim set restates its filing close's filing close reason differently"},
		{"another coverage end reason", contextAndBody(func(closure *CoverageClosureEvidenceContextV1) {
			closure.CoverageEndReason = "accepted_cancellation"
		}), "terminal claim set restates its filing close's coverage end reason differently"},
		{"another incident eligibility end", contextAndBody(func(closure *CoverageClosureEvidenceContextV1) {
			closure.IncidentEligibilityEndsAtUnix--
		}), "terminal claim set restates its filing close's incident eligibility end differently"},
		{"another coverage end evidence", contextAndBody(func(closure *CoverageClosureEvidenceContextV1) {
			closure.CoverageEndEvidenceDigest = testDigest("7")
		}), "terminal claim set restates its filing close's coverage end evidence differently"},
		{"a cancellation receipt the filing close does not name", contextAndBody(func(closure *CoverageClosureEvidenceContextV1) {
			closure.CoverageCancellationReceiptDigest = testDigest("7")
		}), "terminal claim set restates its filing close's cancellation receipt differently"},
		{"non-activation evidence the filing close does not name", body(func(body *TerminalClaimSetBodyV1) {
			body.NonActivationEvidenceDigest = testDigest("7")
		}), "terminal claim set restates its filing close's non-activation evidence differently"},
		{"another filing-close revision", body(func(body *TerminalClaimSetBodyV1) { body.FilingCloseCoverageRevision++ }),
			"terminal claim set coverage revisions do not follow its filing close"},
		{"a release-pending revision two past the prior one", body(func(body *TerminalClaimSetBodyV1) {
			body.ReleasePendingCoverageRevision++
		}), "terminal claim set coverage revisions do not follow its filing close"},
		{"closed at the revision before the filing close's", body(func(body *TerminalClaimSetBodyV1) {
			body.PriorCoverageRevision = body.FilingCloseCoverageRevision - 1
			body.ReleasePendingCoverageRevision = body.FilingCloseCoverageRevision
		}), "terminal claim set closes the coverage at a revision before its filing close's"},
		{"another filing-close time", body(func(body *TerminalClaimSetBodyV1) { body.FilingClosedAtUnix++ }),
			"terminal claim set times do not follow its filing close"},
		{"created a second before all claims were terminal", body(func(body *TerminalClaimSetBodyV1) { body.CreatedAtUnix-- }),
			"terminal claim set times do not follow its filing close"},
		{"terminal a second before filing closed", body(func(body *TerminalClaimSetBodyV1) {
			body.AllClaimsTerminalAtUnix = body.FilingClosedAtUnix - 1
		}), "terminal claim set is terminal before its filing close"},
		{"a release allowed a second before all claims were terminal", contextAndBody(func(closure *CoverageClosureEvidenceContextV1) {
			closure.ReleaseNotBeforeUnix--
		}), "terminal claim set allows its release before all claims were terminal"},
		{"terminal a second before the claim's decision was applied", body(func(body *TerminalClaimSetBodyV1) {
			body.AllClaimsTerminalAtUnix = chain.application.Body.AppliedAtUnix - 1
		}), "terminal claim's decision is applied after the set became terminal"},
	} {
		history.vary = test.vary
		refusedFor(t, test.name, chain.verdictOf(t, test.name, bundle), test.want)
		history.vary = signedHistoryVariation{}
	}

	// The same signed set against an offer that names another Agreement.
	set := history.terminalSet(chain.filing, []ClaimTerminalResolutionBundleV1{bundle}, chain.closedAt)
	offer := history.offer
	offer.Body.CoverageAgreementBodyDigest = testDigest("9")
	refusedFor(t, "an offer for another Agreement", VerifyTerminalClaimSetV1(set, offer, permissiveAgreementVerifier{},
		history.resolver, history.fenceResolver, signedHistoryNoPayments{}, time.Unix(int64(chain.closedAt), 0).UTC()),
		"terminal claim set belongs to another coverage than the firm offer")
}

// TestSignedHistoryTerminalClaimIsOneTheFilingCutAdmitted: the bundled
// claim's initial admission is the one the filing close's cut admitted and
// its admission log runs from the empty root to the root the close froze. A
// set is refused when the signed filing cut admits another admission, freezes
// another log root, the claim was admitted on a log that did not start empty,
// or the claim was admitted on another Agreement.
func TestSignedHistoryTerminalClaimIsOneTheFilingCutAdmitted(t *testing.T) {
	notAdmitted := newLateChain(t, lateChainOptions{unchallenged: true, vary: signedHistoryVariation{
		filingCutEntry: func(entry *ClaimIngressResolutionEntryV1) { entry.ClaimAdmissionReceiptDigest = testDigest("7") }}})
	refusedFor(t, "a filing cut that admits another admission", notAdmitted.verdictOf(t, "another admission", notAdmitted.bundle()),
		"terminal claim's initial admission is not an admitted entry of the filing cut")

	otherRoot := newLateChain(t, lateChainOptions{unchallenged: true, vary: signedHistoryVariation{frozenRoot: testDigest("7")}})
	refusedFor(t, "a filing close that froze another log root", otherRoot.verdictOf(t, "another root", otherRoot.bundle()),
		"terminal claim admissions do not end at the frozen claim admission log root")

	notEmpty := newLateChain(t, lateChainOptions{unchallenged: true, logRoot: testDigest("7")})
	refusedFor(t, "a claim admitted on a log that did not start empty", notEmpty.verdictOf(t, "not empty", notEmpty.bundle()),
		"terminal claim admissions do not chain from the empty claim admission log")

	// The whole claim history is signed on another Agreement, and this
	// coverage's filing cut names that claim's initial admission.
	foreign := newLateChain(t, lateChainOptions{unchallenged: true, agreement: testDigest("9")})
	foreignBundle := foreign.bundle()
	foreignInitial := foreignBundle.InitialClaimAdmissionReceiptProof.ReceiptEnvelopeDigest
	host := newLateChain(t, lateChainOptions{unchallenged: true, vary: signedHistoryVariation{
		filingCutEntry: func(entry *ClaimIngressResolutionEntryV1) { entry.ClaimAdmissionReceiptDigest = foreignInitial }}})
	refusedFor(t, "a claim admitted on another Agreement", host.verdictOf(t, "another Agreement", foreignBundle),
		"terminal claim belongs to another coverage than its set")
}

// TestSignedHistoryTerminalBundleTiesItsDecisionPieces: a terminal bundle
// carries the terminal decision's admission proof and challenge close, alone
// or after the claim's earlier decision history. Both forms verify. A bundle
// that combines validly signed decision pieces in any other way is refused
// for the piece that does not fit.
func TestSignedHistoryTerminalBundleTiesItsDecisionPieces(t *testing.T) {
	chain := newLateChain(t, lateChainOptions{})
	history := chain.history
	honest := chain.bundle()
	terminal, closing := honest.DecisionAdmissionReceiptProofs[0], honest.ClaimStateTransitionReceipts[0]
	candidate := chain.challenge.DecisionAdmissionProof
	with := func(change func(*ClaimTerminalResolutionBundleV1)) ClaimTerminalResolutionBundleV1 {
		bundle := honest
		change(&bundle)
		return bundle
	}
	complete := with(func(bundle *ClaimTerminalResolutionBundleV1) {
		bundle.DecisionAdmissionReceiptProofs = []ClaimDecisionAdmissionReceiptProofV1{candidate, terminal}
		bundle.ClaimStateTransitionReceipts = []AuthorizedClaimStateTransitionReceiptV1{chain.challenge, closing}
	})
	if err := chain.verdict(t, "the terminal decision alone", honest); err != nil {
		t.Fatalf("the bundle of the terminal decision alone does not verify: %v", err)
	}
	if err := chain.verdict(t, "the complete decision history", complete); err != nil {
		t.Fatalf("the bundle of the complete decision history does not verify: %v", err)
	}

	otherClaim := newLateChain(t, lateChainOptions{vary: signedHistoryVariation{incident: testDigest("6")}})
	otherCandidate := newLateChain(t, lateChainOptions{candidateAt: 11})
	for _, test := range []struct {
		name   string
		bundle ClaimTerminalResolutionBundleV1
		want   string
	}{
		{"a decision admission of another claim", with(func(bundle *ClaimTerminalResolutionBundleV1) {
			bundle.DecisionAdmissionReceiptProofs = []ClaimDecisionAdmissionReceiptProofV1{
				otherClaim.bundle().DecisionAdmissionReceiptProofs[0], terminal}
		}), "terminal claim carries a decision admission of another claim"},
		{"the terminal decision admission twice", with(func(bundle *ClaimTerminalResolutionBundleV1) {
			bundle.DecisionAdmissionReceiptProofs = []ClaimDecisionAdmissionReceiptProofV1{terminal, terminal}
		}), "terminal claim carries one decision admission twice"},
		{"a candidate the terminal decision does not follow", with(func(bundle *ClaimTerminalResolutionBundleV1) {
			bundle.DecisionAdmissionReceiptProofs = []ClaimDecisionAdmissionReceiptProofV1{
				otherCandidate.challenge.DecisionAdmissionProof, terminal}
		}), "terminal claim decision admissions are not a predecessor-linked chain"},
		{"without the revision the decision stands on", with(func(bundle *ClaimTerminalResolutionBundleV1) {
			bundle.RevisionAdmissionReceiptProofs = bundle.RevisionAdmissionReceiptProofs[:1]
		}), "terminal claim decision admission stands on a claim admission outside its bundle"},
		{"the challenge of a decision the bundle does not carry", with(func(bundle *ClaimTerminalResolutionBundleV1) {
			bundle.ClaimStateTransitionReceipts = []AuthorizedClaimStateTransitionReceiptV1{chain.challenge, closing}
		}), "terminal claim carries a transition of a decision outside its bundle"},
		{"a challenge as the last transition", with(func(bundle *ClaimTerminalResolutionBundleV1) {
			bundle.DecisionAdmissionReceiptProofs = []ClaimDecisionAdmissionReceiptProofV1{candidate, terminal}
			bundle.ClaimStateTransitionReceipts = []AuthorizedClaimStateTransitionReceiptV1{chain.challenge}
		}), "terminal claim's last transition does not close its terminal decision"},
		{"a challenge the terminal decision does not name", with(func(bundle *ClaimTerminalResolutionBundleV1) {
			bundle.DecisionAdmissionReceiptProofs = []ClaimDecisionAdmissionReceiptProofV1{candidate, terminal}
			bundle.ClaimStateTransitionReceipts = []AuthorizedClaimStateTransitionReceiptV1{chain.laterChallenge, closing}
		}), "terminal claim carries a transition its successor decision does not name"},
	} {
		refusedFor(t, test.name, chain.verdict(t, test.name, test.bundle), test.want)
	}

	// A reference that states another claim state revision than the closing
	// transition's: the reference is not derived again.
	stale := honest
	stale.ResolutionRef.ClaimStateRevision++
	refusedFor(t, "a reference with another claim state revision", chain.verdictOf(t, "stale reference", stale),
		"terminal claim state differs from its closing transition")

	// An application receipt signed and sealed in full, as the claim's own,
	// over a body that names another decision admission.
	forged := chain.application
	forged.Body.ClaimDecisionAdmissionReceiptDigest = testDigest("7")
	forged.Authorizations = []ProfileQualifiedObjectAuthorizationV1{
		history.applicationAuthorization(forged.Body, forged.Body.AppliedAtUnix)}
	history.store(forged)
	misapplied := history.terminalBundle(chain.claimID, forged, chain.closedAt)
	refusedFor(t, "an application proof naming another decision admission", chain.verdictOf(t, "misapplied", misapplied),
		"terminal claim's application proof applies another admission, transition or token")

	// The candidate's decision in place of the terminal one, with a payout set
	// and an application signed for it, so every digest of the bundle agrees.
	swapped := chain.application
	candidateDecision, err := ClaimDecisionDigestV1(candidate.AuthorizedClaimDecision)
	if err != nil {
		t.Fatal(err)
	}
	swapped.MaterializedPayoutObligationSet.AuthorizedClaimDecisionDigest = candidateDecision
	swapped.Body.AuthorizedClaimDecisionDigest = candidateDecision
	if swapped.Body.MaterializedPayoutObligationSetDigest, err = Digest(PayoutSetDomain, swapped.MaterializedPayoutObligationSet); err != nil {
		t.Fatal(err)
	}
	swapped.Authorizations = []ProfileQualifiedObjectAuthorizationV1{
		history.applicationAuthorization(swapped.Body, swapped.Body.AppliedAtUnix)}
	history.store(swapped)
	otherDecision := history.terminalBundle(chain.claimID, swapped, chain.closedAt)
	otherDecision.TerminalAuthorizedDecision = candidate.AuthorizedClaimDecision
	refusedFor(t, "another decision than the terminal admission admitted", chain.verdict(t, "swapped decision", otherDecision),
		"terminal claim's decision is not the one its terminal decision admission admitted")
}

// TestSignedHistoryTerminalDecisionStandsOnTheFinalRevisionAndFilingClose: the
// terminal decision of a bundle decides the claim's final revision, and a
// decision on the late-recovery path names the set's own filing close. A set
// whose terminal decision was admitted on an earlier revision, or whose
// late-recovery candidate was signed naming another filing close, is refused.
func TestSignedHistoryTerminalDecisionStandsOnTheFinalRevisionAndFilingClose(t *testing.T) {
	earlier := newLateChain(t, lateChainOptions{unchallenged: true, candidateOnSecondRevision: true})
	refusedFor(t, "a terminal decision on the second of three revisions", earlier.verdictOf(t, "earlier revision", earlier.bundle()),
		"terminal claim's decision stands on another claim admission than its final revision's")

	otherClose := newLateChain(t, lateChainOptions{unchallenged: true, vary: varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) {
		body.LateFilingCloseReceiptDigest = testDigest("7")
	})})
	refusedFor(t, "a late-recovery candidate naming another filing close", otherClose.verdictOf(t, "another close", otherClose.bundle()),
		"terminal claim's late-path decision names another filing close than its set's")
}

// TestSignedHistoryTerminalBundleClosesAndAppliesItsOwnDecision: the closing
// transition of a bundle is this claim's, embeds the carried decision proof
// byte for byte and states the claim state the reference states; the
// application proof applies at the closing transition's claim state revision
// and not before the close. Each bundle below is signed in full and differs
// from the accepted one in the one value its refusal names.
func TestSignedHistoryTerminalBundleClosesAndAppliesItsOwnDecision(t *testing.T) {
	chain := newLateChain(t, lateChainOptions{unchallenged: true})
	history := chain.history
	honest := chain.bundle()
	if err := chain.verdictOf(t, "the honest bundle", honest); err != nil {
		t.Fatalf("the honest bundle does not verify: %v", err)
	}

	atClose := newLateChain(t, lateChainOptions{unchallenged: true, appliedAt: func(closeAt uint64) uint64 { return closeAt }})
	if err := atClose.verdictOf(t, "applied at the close", atClose.bundle()); err != nil {
		t.Errorf("a decision applied at the instant of its challenge close is refused: %v", err)
	}
	early := newLateChain(t, lateChainOptions{unchallenged: true, appliedAt: func(closeAt uint64) uint64 { return closeAt - 1 }})
	refusedFor(t, "a decision applied a second before its challenge close", early.verdictOf(t, "applied early", early.bundle()),
		"claim decision is applied before its challenge close")

	otherClaim := newLateChain(t, lateChainOptions{unchallenged: true, closing: signedHistoryVariation{
		transitionBody: func(body *ClaimStateTransitionReceiptBodyV1) { body.ClaimID = testDigest("6") }}})
	refusedFor(t, "a closing transition signed for another claim", otherClaim.verdictOf(t, "another claim", otherClaim.bundle()),
		"terminal claim carries a transition of another claim")

	otherState := newLateChain(t, lateChainOptions{unchallenged: true, closing: signedHistoryVariation{
		transitionBody: func(body *ClaimStateTransitionReceiptBodyV1) { body.ResultingClaimState = "final_approved" }}})
	refusedFor(t, "a closing transition signed with another resulting state", otherState.verdictOf(t, "another state", otherState.bundle()),
		"terminal claim state differs from its closing transition's resulting state")

	// The terminal decision's receipt sealed a second time: the same receipt
	// and envelope digest, another seal than the one the closing transition
	// embeds.
	resealed := honest
	resealed.DecisionAdmissionReceiptProofs = []ClaimDecisionAdmissionReceiptProofV1{
		history.decisionProof(*history.claims[chain.claimID].decision, chain.closedAt)}
	if resealed.DecisionAdmissionReceiptProofs[0].ReceiptEnvelopeDigest != honest.DecisionAdmissionReceiptProofs[0].ReceiptEnvelopeDigest ||
		equalCanonical(resealed.DecisionAdmissionReceiptProofs[0], honest.DecisionAdmissionReceiptProofs[0]) {
		t.Fatal("the second sealing is not another proof of the same receipt")
	}
	refusedFor(t, "a second sealing of the terminal decision's receipt", chain.verdict(t, "resealed", resealed),
		"terminal claim carries a transition whose decision admission proof is not the carried one")

	// An application receipt signed and sealed in full, as the claim's own,
	// over a body that states another applied claim state revision.
	forged := chain.application
	forged.Body.AppliedClaimStateRevision++
	forged.Authorizations = []ProfileQualifiedObjectAuthorizationV1{
		history.applicationAuthorization(forged.Body, forged.Body.AppliedAtUnix)}
	history.store(forged)
	refusedFor(t, "an application proof at another claim state revision",
		chain.verdictOf(t, "another revision", history.terminalBundle(chain.claimID, forged, chain.closedAt)),
		"terminal claim's application proof applies at another claim state revision than its closing transition's")
}
