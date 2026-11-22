package agentguarantor

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44/mldsa44test"
)

// signedHistory builds and signs, in memory with deterministic test keys, the
// objects of one claim's history from the claim onwards, so the deep
// verifiers run in this package's own tests: the claim, its ingress
// receipts, its initial and revision admissions (the revision carrying the
// initial admission's compact proof), and the later decision objects built
// on them: fallback and authorized decision admissions, challenge and
// challenge-close transitions, the decision application with its materialized
// payouts and, for a claim that ends denied, the terminal claim set.
//
// It holds no payout execution evidence, so it closes no coverage with an
// approved claim.
//
// It does not build the coverage history before the claim. The activation
// evidence a claim admission or a filing close stands on is a structurally
// valid stand-in, and withSignedHistorySeam replaces the activation
// predecessor verifier for the duration of a test. The quote, the exposure
// receipt and the firm offer are signed beside it (signed_history_offer_test.go)
// and verified by VerifyFirmOffer, but the claim history is not built on that
// offer: acceptance and activation verification are covered by the provider's
// end-to-end flow, not here.
type signedHistory struct {
	t             *testing.T
	terms         CoverageTermsV1
	agreement     string
	obligation    string
	offer         AuthorizedFirmCoverageOfferV1
	activation    AuthorizedCoverageActivationEvidenceV1
	fence         agentcommerce.WriterFence
	fenceResolver mldsa44test.ActionAuthorityResolver
	resolver      signedHistoryResolver

	coverageRevision uint64
	claimLogRoot     string
	claimSequence    uint64
	ingressLogs      map[string]signedHistoryLog
	revisionLogs     map[string]signedHistoryLog
	allocation       uint64
	initialReceipts  map[string]AuthorizedClaimAdmissionReceiptV1
	latestReceipts   map[string]AuthorizedClaimAdmissionReceiptV1
	admissions       map[string][]AuthorizedClaimAdmissionReceiptV1
	claims           map[string]*signedHistoryClaim

	// The coverage's decision reserve and payout counters, in atomic units of
	// the coverage asset: what admitted approving decisions reserve until they
	// are applied, what applied decisions approved, and the payout lines
	// materialized so far with the digest of the last one.
	pendingReserve     uint64
	cumulativeApproved uint64
	payoutSequence     uint64
	payoutLineDigest   string

	// vary changes what the builders sign next; see signedHistoryVariation.
	vary signedHistoryVariation
}

// signedHistoryVariation lets a test change one input of an object before the
// history signs it. Every digest downstream of the changed input is
// recomputed, so the varied object is complete and signed and differs from
// the honest one only in what was changed. A nil or zero member changes
// nothing.
type signedHistoryVariation struct {
	// incident is the incident key of the next claim filed; another key makes
	// another claim ID.
	incident string
	// nonterminal makes the next authorized decision dispute the claim instead
	// of approving it; decision changes its body before the Decision Authority
	// signs it.
	nonterminal bool
	decision    func(*ClaimDecisionBodyV1)
	// epoch changes the revision-epoch expectation of the next decision
	// admission request, and cut its revision ingress cut.
	epoch func(*ClaimRevisionEpochExpectationV1)
	cut   func(*ClaimIngressAdmissionCutProofV1)
	// admission changes the next decision admission receipt body before the
	// admission authority signs it.
	admission func(*ClaimDecisionAdmissionReceiptBodyV1)
	// receiptAt is the time the next decision admission, transition or
	// application receipt body states (with the windows and the eligibility
	// proofs that follow it), instead of the time its stage action is admitted
	// at.
	receiptAt uint64
	// transitionBody changes the next transition receipt body before the
	// admission authority signs it.
	transitionBody func(*ClaimStateTransitionReceiptBodyV1)
	// transitionRequest changes the next transition's action request before
	// it is authorized; the receipt body names the claim and coverage the
	// changed request names.
	transitionRequest func(*ClaimStateTransitionActionBodyV1)
	// proofSealedAt is when the decision proof inside the next transitions is
	// sealed, instead of the transition's own time.
	proofSealedAt uint64
	// filingCutEntry changes each admitted entry of the next filing close's
	// ingress cut, and frozenRoot replaces the claim admission log root it
	// freezes.
	filingCutEntry func(*ClaimIngressResolutionEntryV1)
	frozenRoot     string
	// closureAgreement replaces the Agreement the next terminal claim set
	// names in its body, context, references and action; closureContext
	// changes its closure context before the context is digested, and the
	// body restates the changed context; closureBody changes its body last.
	closureAgreement string
	closureContext   func(*CoverageClosureEvidenceContextV1)
	closureBody      func(*TerminalClaimSetBodyV1)
	// closureTerminalAt is the time the next terminal claim set states all its
	// claims became terminal, and allows its release from, instead of the time
	// its closure action is admitted at, which is its creation time.
	closureTerminalAt uint64
	// stageOf and stageAfter move the admission of every stage action of stage
	// stageOf by stageAfter seconds past the time its receipt body states, so
	// the Action Authority's evidence and the receipt's own quorum state two
	// times for one admission.
	stageOf    string
	stageAfter uint64
}

// receiptTime is the time a receipt body states for a stage action admitted
// at, and the time its authority signs it at: the varied receipt time when
// one is set. An authorization cannot be signed at a time out of range, so a
// body stating one is signed at the stage time.
func (history *signedHistory) receiptTime(at uint64) (stated, signedAt uint64) {
	if history.vary.receiptAt == 0 {
		return at, at
	}
	if history.vary.receiptAt > 1<<62 {
		return history.vary.receiptAt, at
	}
	return history.vary.receiptAt, history.vary.receiptAt
}

// signedHistoryClaim is the claim state the decision objects are built on.
type signedHistoryClaim struct {
	status            string
	stateRevision     uint64
	decisionSequence  uint64
	challengeRounds   uint64
	nonterminalRounds uint64
	epoch             uint64
	epochFrozen       bool
	epochRevision     uint64
	frozenCut         ClaimIngressAdmissionCutProofV1
	decision          *AuthorizedClaimDecisionAdmissionReceiptV1
	transition        *AuthorizedClaimStateTransitionReceiptV1
	token             *DecisionApplicationTokenV1
}

type signedHistoryLog struct {
	sequence uint64
	root     string
}

// signedHistoryResolver resolves the test authorities and serves the
// immutable receipts the history stored, by envelope digest.
type signedHistoryResolver struct {
	allowAuthorityResolver
	evidence map[string][]byte
}

func (resolver signedHistoryResolver) ResolveImmutableGuarantorEvidence(descriptor ImmutableEvidenceDescriptorV1) ([]byte, error) {
	wire, found := resolver.evidence[descriptor.ContentDigest]
	if !found {
		return nil, testError("immutable evidence is not held")
	}
	return append([]byte(nil), wire...), nil
}

const (
	signedHistoryActionController = "controller:action-authority"
	signedHistoryGuarantor        = "agent:guarantor"
	signedHistoryClaimant         = "agent:covered"
	signedHistoryStart            = 2_000_000_000
)

var signedHistoryProof = []byte("signed-history-authority-proof")

// withSignedHistorySeam replaces the activation predecessor verifier with one
// that accepts exactly the history's stand-in activation, and restores the
// real verifier when the test ends.
func withSignedHistorySeam(t *testing.T, history *signedHistory) {
	t.Helper()
	real := coverageActivationPredecessorVerifierV1
	t.Cleanup(func() { coverageActivationPredecessorVerifierV1 = real })
	coverageActivationPredecessorVerifierV1 = func(evidence AuthorizedCoverageActivationEvidenceV1, _ AuthorizedFirmCoverageOfferV1,
		_ agentcommerce.AgreementEvidenceVerifier, _ AuthorityKeyResolver, _ agentcommerce.FenceAuthorityResolver,
		_ CollateralAdapterFinalityVerifier, _ time.Time) error {
		if !equalCanonical(evidence, history.activation) {
			return testError("activation evidence is not the signed history's")
		}
		return nil
	}
}

// newSignedHistory sets up the coverage a claim history stands on.
func newSignedHistory(t *testing.T) *signedHistory {
	t.Helper()
	terms := testCoverageTerms(t)
	agreement, obligation := testDigest("d"), "obligation:coverage"
	ingressDomain, err := ClaimIngressStateDomainDigestV1(agreement, obligation)
	if err != nil {
		t.Fatal(err)
	}
	for index := range terms.StageActionAuthorityBinding.Stages {
		if terms.StageActionAuthorityBinding.Stages[index].Stage == "claim_submission_ingress" {
			terms.StageActionAuthorityBinding.Stages[index].AdmissionStateDomainDigest = ingressDomain
		}
	}
	terms.BenefitCalculationProfile = testRef("9", "benefit-calculation")
	terms.LateIngressRecoveryWindowSeconds = 300
	terms.LateIngressRecoveryDeadlineUnix = terms.TerminalResolutionDeadlineUnix + 300
	terms.LateRecoveryTerminalDeadlineUnix = terms.LateIngressRecoveryDeadlineUnix + lateRecoveryCandidateClosureSecondsV1(terms, 0)
	if err := ValidateCoverageTerms(terms); err != nil {
		t.Fatalf("signed-history terms are invalid: %v", err)
	}
	fake := nativeTestFake
	authority := terms.StageActionAuthorityBinding.Stages[0].ActionAuthorityID
	history := &signedHistory{t: t, terms: terms, agreement: agreement, obligation: obligation,
		fenceResolver: mldsa44test.ActionAuthorityResolver{Verifier: fake,
			Keys: map[string][][]byte{authority: {fake.PublicKey(signedHistoryActionController)}}},
		resolver:    signedHistoryResolver{evidence: map[string][]byte{}},
		ingressLogs: map[string]signedHistoryLog{}, revisionLogs: map[string]signedHistoryLog{},
		initialReceipts: map[string]AuthorizedClaimAdmissionReceiptV1{},
		latestReceipts:  map[string]AuthorizedClaimAdmissionReceiptV1{},
		admissions:      map[string][]AuthorizedClaimAdmissionReceiptV1{}, claims: map[string]*signedHistoryClaim{}}
	scope := map[string]struct{}{}
	for _, stage := range terms.StageActionAuthorityBinding.Stages {
		scope[stage.OperationActionKind] = struct{}{}
	}
	kinds := make([]string, 0, len(scope))
	for kind := range scope {
		if kind != "" {
			kinds = append(kinds, kind)
		}
	}
	sort.Strings(kinds)
	history.fence, err = agentcommerce.SignWriterFence(context.Background(), agentcommerce.WriterFenceBody{SchemaVersion: 1,
		OwnerID: terms.StageActionAuthorityBinding.Stages[0].ActionOwnerID,
		AgentID: terms.StageActionAuthorityBinding.Stages[0].ActionAgentID, InstanceID: "instance:signed-history",
		LeaseID: "lease:signed-history", WriterGeneration: 1, IssuedAtUnix: signedHistoryStart,
		ExpiresAtUnix: signedHistoryStart + 24*60*60 - 1, AuthorityID: authority, Scope: kinds}, fake, signedHistoryActionController)
	if err != nil {
		t.Fatal(err)
	}
	history.offer = AuthorizedFirmCoverageOfferV1{CoverageTerms: terms}
	history.offer.Body.GuarantorAgentID = signedHistoryGuarantor
	// The stand-in offer names the history's coverage and carries a signed
	// exposure admission, so the closure objects can be tied to both.
	history.offer.Body.CoverageAgreementBodyDigest, history.offer.Body.CoverageObligationID = agreement, obligation
	history.offer.ExposureAdmissionReceipt = history.standInExposureReceipt("retain")
	history.offer.Body.ReservationID = history.offer.ExposureAdmissionReceipt.Body.ReservationID
	history.activation = history.standInActivation()
	history.coverageRevision = history.activation.Body.ActivatedCoverageRevision
	claimLogID, err := ClaimAdmissionLogIDV1(agreement, obligation)
	if err != nil {
		t.Fatal(err)
	}
	if history.claimLogRoot, err = InitialClaimLogRootV1(ClaimAdmissionLogRootDomainV1, claimLogID); err != nil {
		t.Fatal(err)
	}
	return history
}

// standInActivation is a structurally valid activation evidence on the
// history's coverage, whose acceptance carries the firm offer. Its
// signatures are not checked: the seam stands in for its verification.
func (history *signedHistory) standInActivation() AuthorizedCoverageActivationEvidenceV1 {
	t, terms := history.t, history.terms
	offerEvidence, err := Canonical(GuarantorFirmOfferAgreementEvidenceV1{SchemaVersion: 1,
		AgreementBodyDigest: history.agreement, GuarantorAgentID: signedHistoryGuarantor,
		AuthorizedFirmOfferEnvelopeDigest: testDigest("e"), AuthorizedFirmOffer: history.offer})
	if err != nil {
		t.Fatal(err)
	}
	var acceptance AuthorizedCoverageAcceptanceReceiptV1
	acceptance.AuthorizedAcceptanceRequest.AuthorizationEvidenceSet = GuarantorAgreementAuthorizationEvidenceSetV1{
		SchemaVersion: 1, AgreementBodyDigest: history.agreement,
		Evidence: []agentcommerce.AgreementAuthorizationEvidence{{AgreementBodyDigest: history.agreement,
			EvidenceProfileURI: FirmOfferAgreementEvidenceProfileURI, EvidenceContentType: FirmOfferAgreementEvidenceContentType,
			Evidence: offerEvidence}}}
	commitment := CoverageEndCommitmentV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		CoverageObligationID: history.obligation, CoverageStateDomainDigest: terms.CoverageStateDomainDigest,
		EndBranch: "scheduled", IncidentEligibilityEndsAtUnix: terms.CoverageEndsAtUnix}
	endDigest, err := CoverageEndCommitmentDigestV1(commitment)
	if err != nil {
		t.Fatal(err)
	}
	eligibility := history.eligibility(testDigest("1"), testDigest("2"), []string{signedHistoryGuarantor}, "activation-evidence",
		testDigest("3"), testDigest("4"), terms.LifecycleAuthorizationProfile, testDigest("5"), 1, signedHistoryStart)
	eligibilityDigest, err := AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	if err != nil {
		t.Fatal(err)
	}
	body := CoverageActivationEvidenceBodyV1{SchemaVersion: 1, AuthorityID: "authority:guarantor",
		CoverageAgreementBodyDigest: history.agreement, CoverageObligationID: history.obligation,
		CoverageStateDomainDigest: terms.CoverageStateDomainDigest, AuthorizationEvidenceSetDigest: testDigest("6"),
		UnderlyingAgreementBodyDigest: terms.UnderlyingAgreementBodyDigest, UnderlyingAuthorizationEvidenceSetDigest: testDigest("7"),
		AuthorizedFirmOfferEnvelopeDigest: testDigest("e"), AcceptanceReceiptDigest: testDigest("8"),
		ExposureReceiptDigest: testDigest("9"), SelectedAssuranceLevel: terms.SelectedAssuranceLevel,
		SelectedClaimProfileDigest: terms.SelectedClaimProfileDigest, TransitionEvidenceProjectionDigest: testDigest("a"),
		AuthorizedActionDigest: testDigest("b"), StableActionID: testDigest("c"), ExactRequestDigest: testDigest("d"),
		WriterGeneration: 1, WriterFenceDigest: testDigest("e"), PriorCoverageRevision: 1, ActivatedCoverageRevision: 2,
		PriorClaimFilingState: "not_open", ActivatedClaimFilingState: "open", PriorClaimFilingStateRevision: 1,
		ActivatedClaimFilingStateRevision: 2, ResultingCoverageEndCommitmentDigest: endDigest,
		ActivatedAtUnix: signedHistoryStart, CoverageEndsAtUnix: terms.CoverageEndsAtUnix,
		AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	evidence := AuthorizedCoverageActivationEvidenceV1{Body: body, AuthorizedAcceptanceReceipt: acceptance,
		CoverageEndCommitment: commitment, AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObject("activation-evidence", testDigest("f"),
			"tos.service.agent-guarantor-activation-evidence-signature.v1", signedHistoryStart)}}
	if _, err := CoverageActivationEvidenceDigestV1(evidence); err != nil {
		t.Fatalf("stand-in activation evidence is malformed: %v", err)
	}
	return evidence
}

// signObject is the Guarantor's object authorization over bodyDigest.
func (history *signedHistory) signObject(kind, bodyDigest, domain string, at uint64) ProfileQualifiedObjectAuthorizationV1 {
	return history.signObjectAs(signedHistoryGuarantor, history.terms.LifecycleAuthorizationProfile, kind, bodyDigest, domain, at)
}

func (history *signedHistory) signObjectAs(subject string, profile ProfileRefV1, kind, bodyDigest, domain string,
	at uint64) ProfileQualifiedObjectAuthorizationV1 {
	return testSignAuthorization(history.t, AuthorizationStatementV1{SchemaVersion: 1, AuthoritySubject: subject,
		ProfileURI: profile.ProfileURI, ProfileVersion: profile.ProfileVersion, ProfileDigest: profile.ProfileDigest,
		AuthorizedObjectKind: kind, AuthorizedBodyDigest: bodyDigest, ValidationTimeUnix: at},
		domain, "controller:"+subject, signedHistoryProof)
}

// eligibility is an admission-bound authority eligibility proof set.
func (history *signedHistory) eligibility(actionDigest, inputDigest string, subjects []string, kind, bodyDigest,
	scopeDigest string, profile ProfileRefV1, domainID string, sequence, at uint64) AuthorityAdmissionEligibilityProofSetV1 {
	t := history.t
	raw := []byte("signed-history-finality:" + kind)
	principal, err := Digest("tos.service.agent-guarantor-finalized-authority-principal.v1", raw)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]AuthorityAdmissionEligibilityProofV1, 0, len(subjects))
	for _, subject := range subjects {
		entries = append(entries, AuthorityAdmissionEligibilityProofV1{SchemaVersion: 1,
			InputAuthorizedEnvelopeDigest: inputDigest, AuthoritySubject: subject, AuthorityKeyOrPrincipalDigest: principal,
			AuthorizedObjectKind: kind, AuthorizedBodyDigest: bodyDigest, RequiredScopeDigest: scopeDigest,
			AuthorityResolverProfile: profile, FinalizedAuthorityStateRevision: sequence, FinalizedAuthorityStateRoot: principal,
			ResolverFinalityEvidence: raw, AdmissionDomainID: domainID, AdmissionSequence: sequence, AdmissionTimeUnix: at,
			EligibilityState: "eligible"})
	}
	sort.Slice(entries, func(i, j int) bool {
		left, _ := Canonical(entries[i])
		right, _ := Canonical(entries[j])
		return string(left) < string(right)
	})
	set := AuthorityAdmissionEligibilityProofSetV1{SchemaVersion: 1, AdmittedActionDigest: actionDigest,
		AdmissionDomainID: domainID, AdmissionSequence: sequence, AdmissionTimeUnix: at, Entries: entries}
	if err := ValidateAuthorityAdmissionEligibilityProofSetV1(set); err != nil {
		t.Fatalf("eligibility proof set for %s is invalid: %v", kind, err)
	}
	return set
}

// stage signs one stage action and its portable admission evidence: the
// Agreement-bound action, terminal at the Action Authority, admitted at.
func (history *signedHistory) stage(stage, contentType string, request []byte, fields map[string]agentcommerce.SemanticValue,
	expectedPriorState string, expiresAt, at uint64, sink string, evidenceRefs []string) PortableStageActionAdmissionEvidenceV1 {
	bound, err := FindStageActionAuthorityV1(history.terms.StageActionAuthorityBinding, stage)
	if err != nil {
		history.t.Fatal(err)
	}
	return history.stageFor(bound, contentType, request, fields, expectedPriorState, expiresAt, at, sink, evidenceRefs)
}

// stageFor is stage for a given stage authority, which need not be one of the
// history's terms: an auxiliary authority derived from them, or a stage of
// another offer's terms.
func (history *signedHistory) stageFor(bound GuarantorStageActionAuthorityV1, contentType string, request []byte,
	fields map[string]agentcommerce.SemanticValue, expectedPriorState string, expiresAt, at uint64, sink string,
	evidenceRefs []string) PortableStageActionAdmissionEvidenceV1 {
	t, stage := history.t, bound.Stage
	if history.vary.stageOf == stage {
		at += history.vary.stageAfter
	}
	// An action is authorized under its Writer Fence and expires no later.
	if fenceExpiry := history.fence.Body.ExpiresAtUnix; expiresAt > fenceExpiry {
		expiresAt = fenceExpiry
	}
	operation, err := StageOperationBindingForAuthorityV1(bound)
	if err != nil {
		t.Fatal(err)
	}
	action, err := agentcommerce.BuildAuthorizedAction(bound.ActionOwnerID, bound.ActionAgentID, operation.ActionKind, fields,
		request, history.fence, 1, testDigest("1"), "", expectedPriorState, expiresAt)
	if err != nil {
		t.Fatalf("%s action: %v", stage, err)
	}
	action, err = agentcommerce.SignAuthorizedAction(context.Background(), action, nativeTestFake.KeyID(signedHistoryActionController),
		nativeTestFake, signedHistoryActionController)
	if err != nil {
		t.Fatal(err)
	}
	actionDigest, err := agentcommerce.AuthorizedActionDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	refs := append([]string(nil), evidenceRefs...)
	sort.Strings(refs)
	resolution := agentcommerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: agentcommerce.ActionTerminal, SinkReference: sink, EvidenceRefs: refs, StateRevision: 2}
	body := PortableStageActionAdmissionBodyV1{SchemaVersion: 1, Stage: stage, OperationID: operation.OperationID,
		OperationBindingDigest: bound.OperationBindingDigest, AdmittedAtUnix: at, CanonicalRequestDigest: action.ExactRequestDigest,
		AuthorizedActionDigest: actionDigest, WriterFenceDigest: action.WriterFenceDigest, AdmissionState: "accepted",
		AdmissionStateRevision: resolution.StateRevision}
	bodyDigest, err := Digest("tos.service.agent-guarantor-stage-action-admission.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	profile := history.terms.LifecycleAuthorizationProfile
	statement := AuthorizationStatementV1{SchemaVersion: 1, AuthoritySubject: bound.ActionAuthorityID,
		ProfileURI: profile.ProfileURI, ProfileVersion: profile.ProfileVersion, ProfileDigest: profile.ProfileDigest,
		AuthorizedObjectKind: StageActionAdmissionObjectKind, AuthorizedBodyDigest: bodyDigest, ValidationTimeUnix: at}
	message, err := NativeAuthorizationMessage(StageActionAdmissionSignatureDomain, statement)
	if err != nil {
		t.Fatal(err)
	}
	keyID, signature, err := agentcommerce.SignActionAuthorityMessage(context.Background(), nativeTestFake,
		signedHistoryActionController, message)
	if err != nil {
		t.Fatal(err)
	}
	return PortableStageActionAdmissionEvidenceV1{Body: body, CanonicalRequestContentType: contentType,
		CanonicalRequest: append([]byte(nil), request...), AuthorizedAction: action, WriterFence: history.fence,
		ActionResolution: resolution, ActionAdmissionAuthorization: StageActionAdmissionAuthorizationV1{
			AuthoritySubject: statement.AuthoritySubject, ProfileURI: statement.ProfileURI,
			ProfileVersion: statement.ProfileVersion, ProfileDigest: statement.ProfileDigest,
			AuthorizedObjectKind: statement.AuthorizedObjectKind, AuthorizedBodyDigest: statement.AuthorizedBodyDigest,
			ValidationTimeUnix: statement.ValidationTimeUnix, EvidenceContentType: ActionAuthorityEvidenceContentType,
			Evidence: ActionAuthorityMLDSA44EvidenceV1{KeyID: keyID, Signature: signature,
				HistoricalAuthorityProof: append([]byte(nil), signedHistoryProof...)}}}
}

// useFenceUntil replaces the history's Writer Fence with the same fence
// expiring at expiresAt, so the stage actions built next are authorized under
// a fence whose validity ends there.
func (history *signedHistory) useFenceUntil(expiresAt uint64) {
	body := history.fence.Body
	body.ExpiresAtUnix = expiresAt
	fence, err := agentcommerce.SignWriterFence(context.Background(), body, nativeTestFake, signedHistoryActionController)
	if err != nil {
		history.t.Fatal(err)
	}
	history.fence = fence
}

// incidentKey is the incident the next claim is filed for.
func (history *signedHistory) incidentKey() string {
	if history.vary.incident != "" {
		return history.vary.incident
	}
	return testDigest("5")
}

// claim is a claimant-signed claim on the history's coverage. Revision 1
// starts the claim; a later revision names its predecessor's body.
func (history *signedHistory) claim(revision uint64, predecessor *AuthorizedCoverageClaimV1, createdAt uint64) AuthorizedCoverageClaimV1 {
	t, terms := history.t, history.terms
	manifest := ClaimEvidenceManifestV1{SchemaVersion: 1,
		Items: []ClaimEvidenceDescriptorV1{{PredicateID: "predicate:delivery", EvidenceProfile: testRef("1", "evidence-item"),
			ContentType: "application/octet-stream", ContentDigest: testDigest("2"), ContentSize: 100,
			DisclosurePolicyDigest: testDigest("3")}}, TotalDeclaredBytes: 100}
	manifestDigest, err := ValidateClaimEvidenceManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	recovery := OtherRecoveryDeclarationV1{SchemaVersion: 1, CoverageAgreementBodyDigest: history.agreement,
		CoverageObligationID: history.obligation, UnderlyingAgreementBodyDigest: terms.UnderlyingAgreementBodyDigest,
		ClaimRevision: revision, BeneficiaryAgentID: terms.BeneficiaryAgentID, IncidentKeyDigest: history.incidentKey(),
		CoverageAsset: terms.CoverageAsset, RecoveryItems: []OtherRecoveryItemV1{}, DeclaredAtUnix: createdAt}
	recoveryDigest, err := ValidateOtherRecoveryDeclaration(recovery, manifest)
	if err != nil {
		t.Fatal(err)
	}
	triggered := TriggeredObligationSetV1{SchemaVersion: 1, UnderlyingAgreementBodyDigest: terms.UnderlyingAgreementBodyDigest,
		ObligationIDs: []string{"obligation:exchange"}}
	triggeredDigest, err := TriggeredObligationSetDigestV1(triggered)
	if err != nil {
		t.Fatal(err)
	}
	claimID, err := ClaimID(history.agreement, history.obligation, recovery.IncidentKeyDigest, recovery.BeneficiaryAgentID, triggeredDigest)
	if err != nil {
		t.Fatal(err)
	}
	body := CoverageClaimBodyV1{SchemaVersion: 1, ClaimID: claimID, ClaimRevision: revision,
		CoverageAgreementBodyDigest: history.agreement, CoverageObligationID: history.obligation,
		UnderlyingAgreementBodyDigest: terms.UnderlyingAgreementBodyDigest, TriggeredObligationSet: triggered,
		ClaimantSubject: signedHistoryClaimant, ClaimantAuthorizationProfile: terms.ClaimantAuthorizationProfiles[0],
		BeneficiaryAgentID: terms.BeneficiaryAgentID, IncidentKeyDigest: recovery.IncidentKeyDigest,
		OccurredAtUnix: terms.CoverageStartsAtUnix + 10,
		ClaimedAmount:  AtomicAmountV1{Asset: terms.CoverageAsset, AmountAtomic: "500"}, EvidenceManifestDigest: manifestDigest,
		OtherRecoveryDeclarationDigest: recoveryDigest,
		PayoutDestinationDigest:        terms.PayoutTemplate.SettlementParameters.PayoutDestinationDigest,
		CreatedAtUnix:                  createdAt, ExpiresAtUnix: terms.ClaimFilingEndsAtUnix}
	if predecessor != nil {
		if body.PredecessorClaimDigest, err = ClaimBodyDigest(predecessor.Body); err != nil {
			t.Fatal(err)
		}
	}
	bodyDigest, err := ClaimBodyDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	authorization := history.signObjectAs(signedHistoryClaimant, terms.ClaimantAuthorizationProfiles[0], "coverage-claim",
		bodyDigest, "tos.service.agent-guarantor-claim-signature.v1", createdAt)
	return AuthorizedCoverageClaimV1{Body: body, EvidenceManifest: manifest, OtherRecoveryDeclaration: recovery,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{authorization}}
}

// ingress signs the ingress receipt that received claim at.
func (history *signedHistory) ingress(claim AuthorizedCoverageClaimV1, at uint64) AuthorizedClaimSubmissionIngressReceiptV1 {
	t, terms := history.t, history.terms
	claimDigest, err := ClaimEnvelopeDigest(claim)
	if err != nil {
		t.Fatal(err)
	}
	request, err := Canonical(ClaimSubmissionIngressActionBodyV1{SchemaVersion: 1, AuthorizedClaim: claim, TargetIngressState: "received"})
	if err != nil {
		t.Fatal(err)
	}
	logClaimID, kind := claim.Body.ClaimID, "revision"
	if claim.Body.ClaimRevision == 1 {
		logClaimID, kind = "", "initial"
	}
	logID, err := ClaimIngressLogIDV1(history.agreement, history.obligation, logClaimID)
	if err != nil {
		t.Fatal(err)
	}
	log, found := history.ingressLogs[logID]
	if !found {
		if log.root, err = InitialClaimLogRootV1(ClaimIngressLogRootDomainV1, logID); err != nil {
			t.Fatal(err)
		}
	}
	fields := map[string]agentcommerce.SemanticValue{"owner_id": agentcommerce.ID("owner:guarantor"),
		"agent_id": agentcommerce.ID(signedHistoryGuarantor), "agreement_body_digest": agentcommerce.Digest32(history.agreement),
		"obligation_id": agentcommerce.ID(history.obligation), "claim_id": agentcommerce.ID(claim.Body.ClaimID),
		"claim_revision": agentcommerce.U64(claim.Body.ClaimRevision)}
	stage := history.stage("claim_submission_ingress", "application/vnd.tos.service.agent-guarantor-claim-ingress-action.v1+cbor",
		request, fields, testDigest("1"), claim.Body.ExpiresAtUnix, at, claimDigest, []string{claimDigest})
	action := stage.AuthorizedAction
	sequence := log.sequence + 1
	admittedRoot, err := AdvanceClaimLogRootV1(ClaimIngressLogRootDomainV1, logID, log.root, sequence,
		ClaimIngressLogLeafV1{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest, ReceivedAtUnix: at})
	if err != nil {
		t.Fatal(err)
	}
	actionDigest, err := agentcommerce.AuthorizedActionDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	eligibility := history.eligibility(actionDigest, claimDigest, terms.ClaimIngressAuthoritySubjects, "claim-ingress-receipt",
		claimDigest, terms.ClaimIngressProfile.ProfileDigest, terms.ClaimIngressProfile, logID, sequence, at)
	eligibilityDigest, err := AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	if err != nil {
		t.Fatal(err)
	}
	stateDomain, err := ClaimIngressStateDomainDigestV1(history.agreement, history.obligation)
	if err != nil {
		t.Fatal(err)
	}
	claimBodyDigest, err := ClaimBodyDigest(claim.Body)
	if err != nil {
		t.Fatal(err)
	}
	body := ClaimSubmissionIngressReceiptBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		CoverageAgreementBodyDigest: history.agreement, CoverageObligationID: history.obligation, ClaimID: claim.Body.ClaimID,
		ClaimRevision: claim.Body.ClaimRevision, IngressKind: kind, ClaimBodyDigest: claimBodyDigest,
		AuthorizedClaimEnvelopeDigest: claimDigest, IngressStateDomainDigest: stateDomain, ClaimIngressLogID: logID,
		ClaimIngressSequence: sequence, PriorClaimIngressLogRoot: log.root, AdmittedClaimIngressLogRoot: admittedRoot,
		IngressSlotRevision: 1, State: "received", AuthorizedActionDigest: actionDigest, StableActionID: action.StableActionID,
		ExactRequestDigest: action.ExactRequestDigest, WriterGeneration: action.WriterGeneration,
		WriterFenceDigest: action.WriterFenceDigest, ReceivedAtUnix: at, AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	bodyDigest, err := Digest("tos.service.agent-guarantor-claim-ingress-receipt-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	history.ingressLogs[logID] = signedHistoryLog{sequence: sequence, root: admittedRoot}
	return AuthorizedClaimSubmissionIngressReceiptV1{Body: body, StageActionAdmissionEvidence: stage, AuthorizedClaim: claim,
		AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObject("claim-ingress-receipt", bodyDigest,
			"tos.service.agent-guarantor-claim-ingress-receipt-signature.v1", at)}}
}

// admit receives and admits claim at: the initial admission for revision 1,
// otherwise a revision admission carrying the initial admission's compact
// proof, sealed at.
func (history *signedHistory) admit(claim AuthorizedCoverageClaimV1, at uint64) AuthorizedClaimAdmissionReceiptV1 {
	t, terms := history.t, history.terms
	ingress := history.ingress(claim, at)
	claimDigest, err := ClaimEnvelopeDigest(claim)
	if err != nil {
		t.Fatal(err)
	}
	ingressDigest, err := ClaimIngressReceiptDigestV1(ingress)
	if err != nil {
		t.Fatal(err)
	}
	claimBodyDigest, err := ClaimBodyDigest(claim.Body)
	if err != nil {
		t.Fatal(err)
	}
	effect := ClaimSubmissionAuthorityInstanceEffectV1{SchemaVersion: 1, AuthorizedClaimIngressReceipt: ingress,
		AuthorizedCoverageActivationEvidence: history.activation,
		ExpectedCoverageEndCommitment:        history.activation.CoverageEndCommitment,
		ExpectedCoverageRevision:             history.coverageRevision}
	effectBytes, err := Canonical(effect)
	if err != nil {
		t.Fatal(err)
	}
	effectDigest, err := agentcommerce.DownstreamEffectDescriptorDigest(effectBytes)
	if err != nil {
		t.Fatal(err)
	}
	allocation := agentcommerce.AuthorityInstanceAllocationRequest{OwnerID: "owner:guarantor", AgentID: signedHistoryGuarantor,
		PurposeKind: "conditional.claim.submit", MandateDigest: testDigest("1"), ApprovalDigestOrZero: zeroSHA256DigestV1(),
		DownstreamEffectDescriptorDigest: effectDigest, PredecessorAuthorityInstanceID: zeroSHA256DigestV1()}
	allocationDigest, err := agentcommerce.AuthorityInstanceAllocationRequestDigest(allocation)
	if err != nil {
		t.Fatal(err)
	}
	history.allocation++
	instanceID, err := agentcommerce.DeriveAuthorityInstanceID(allocation, history.allocation)
	if err != nil {
		t.Fatal(err)
	}
	instance := agentcommerce.AuthorityInstanceRecord{RequestDigest: allocationDigest, AllocationSequence: history.allocation,
		AuthorityInstanceID: instanceID, PolicyRevision: 1}
	request, err := Canonical(ClaimSubmissionActionBodyV1{SchemaVersion: 1, AuthorityInstanceID: instanceID,
		AuthorityInstanceRecord: instance, AuthorityInstanceEffect: effect})
	if err != nil {
		t.Fatal(err)
	}
	stageName, kind := "claim_revision_admission", "revision"
	if claim.Body.ClaimRevision == 1 {
		stageName, kind = "initial_claim_admission", "initial"
	}
	fields := map[string]agentcommerce.SemanticValue{"owner_id": agentcommerce.ID("owner:guarantor"),
		"agent_id": agentcommerce.ID(signedHistoryGuarantor), "agreement_body_digest": agentcommerce.Digest32(history.agreement),
		"obligation_id": agentcommerce.ID(history.obligation), "authority_instance_id": agentcommerce.Digest32(instanceID),
		"claim_body_digest": agentcommerce.Digest32(claimBodyDigest)}
	stage := history.stage(stageName, "application/vnd.tos.service.agent-guarantor-claim-admission-action.v1+cbor",
		request, fields, ingressDigest, claim.Body.ExpiresAtUnix, at, claimDigest, []string{claimDigest})
	action := stage.AuthorizedAction
	actionDigest, err := agentcommerce.AuthorizedActionDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	endDigest, err := CoverageEndCommitmentDigestV1(effect.ExpectedCoverageEndCommitment)
	if err != nil {
		t.Fatal(err)
	}
	claimLogID, err := ClaimAdmissionLogIDV1(history.agreement, history.obligation)
	if err != nil {
		t.Fatal(err)
	}
	revisionLogID, err := ClaimRevisionLogIDV1(history.agreement, history.obligation, claim.Body.ClaimID)
	if err != nil {
		t.Fatal(err)
	}
	revisionLog, found := history.revisionLogs[revisionLogID]
	if !found {
		if revisionLog.root, err = InitialClaimLogRootV1(ClaimRevisionLogRootDomainV1, revisionLogID); err != nil {
			t.Fatal(err)
		}
	}
	body := ClaimAdmissionReceiptBodyV1{SchemaVersion: 1, AuthorityID: action.AuthorityID,
		CoverageAgreementBodyDigest: history.agreement, CoverageObligationID: history.obligation, ClaimID: claim.Body.ClaimID,
		AuthorizedClaimEnvelopeDigest: claimDigest, ClaimSubmissionIngressReceiptDigest: ingressDigest,
		AuthorityInstanceID: instanceID, AuthorityInstanceAllocationRequestDigest: allocationDigest,
		AuthorizedActionDigest: actionDigest, StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		PriorCoverageRevision: history.coverageRevision, AdmittedCoverageRevision: history.coverageRevision + 1,
		PriorCoverageEndCommitmentDigest: endDigest, ResultingCoverageEndCommitmentDigest: endDigest,
		PriorClaimRevision: claim.Body.ClaimRevision - 1, AdmittedClaimRevision: claim.Body.ClaimRevision, AdmissionKind: kind,
		ClaimAdmissionLogID: claimLogID, ClaimRevisionLogID: revisionLogID, ClaimRevisionAdmissionSequence: claim.Body.ClaimRevision,
		PriorClaimRevisionLogRoot: revisionLog.root, WriterGeneration: action.WriterGeneration,
		WriterFenceDigest: action.WriterFenceDigest, AdmittedAtUnix: at}
	var initialProof *ClaimAdmissionReceiptProofV1
	if kind == "initial" {
		history.claimSequence++
		body.ClaimAdmissionSequence = history.claimSequence
		body.PriorClaimAdmissionLogRoot = history.claimLogRoot
		if body.AdmittedClaimAdmissionLogRoot, err = AdvanceClaimLogRootV1(ClaimAdmissionLogRootDomainV1, claimLogID,
			history.claimLogRoot, body.ClaimAdmissionSequence, InitialClaimAdmissionLeafV1{ClaimID: claim.Body.ClaimID,
				AdmissionSequence: body.ClaimAdmissionSequence, AuthorizedClaimEnvelopeDigest: claimDigest}); err != nil {
			t.Fatal(err)
		}
		if body.AdmittedClaimRevisionLogRoot, err = AdvanceClaimLogRootV1(ClaimRevisionLogRootDomainV1, revisionLogID,
			revisionLog.root, 1, ClaimRevisionAdmissionLeafV1{ClaimID: claim.Body.ClaimID, ClaimRevisionAdmissionSequence: 1,
				AuthorizedClaimEnvelopeDigest: claimDigest}); err != nil {
			t.Fatal(err)
		}
		history.claimLogRoot = body.AdmittedClaimAdmissionLogRoot
	} else {
		initial := history.initialReceipts[claim.Body.ClaimID]
		predecessor := history.latestReceipts[claim.Body.ClaimID]
		initialDigest, err := ClaimAdmissionReceiptDigestV1(initial)
		if err != nil {
			t.Fatal(err)
		}
		predecessorDigest, err := ClaimAdmissionReceiptDigestV1(predecessor)
		if err != nil {
			t.Fatal(err)
		}
		body.ClaimAdmissionSequence = initial.Body.ClaimAdmissionSequence
		body.InitialClaimAdmissionReceiptDigest, body.PredecessorRevisionAdmissionReceiptDigest = initialDigest, predecessorDigest
		body.PriorClaimAdmissionLogRoot, body.AdmittedClaimAdmissionLogRoot = history.claimLogRoot, history.claimLogRoot
		if body.AdmittedClaimRevisionLogRoot, err = AdvanceClaimLogRootV1(ClaimRevisionLogRootDomainV1, revisionLogID,
			revisionLog.root, body.ClaimRevisionAdmissionSequence, ClaimRevisionAdmissionLeafV1{ClaimID: claim.Body.ClaimID,
				ClaimRevisionAdmissionSequence: body.ClaimRevisionAdmissionSequence, AuthorizedClaimEnvelopeDigest: claimDigest,
				PredecessorRevisionAdmissionReceiptDigest: predecessorDigest}); err != nil {
			t.Fatal(err)
		}
		proof := history.claimAdmissionProof(initial, at)
		initialProof = &proof
	}
	eligibility := history.eligibility(actionDigest, ingressDigest, terms.ClaimAdmissionAuthoritySubjects, "claim-admission-receipt",
		claimDigest, terms.ClaimAdmissionProfile.ProfileDigest, terms.ClaimAdmissionProfile, terms.CoverageStateDomainDigest,
		body.ClaimRevisionAdmissionSequence, at)
	if body.AuthorityAdmissionEligibilityProofSetDigest, err = AuthorityAdmissionEligibilityProofSetDigestV1(eligibility); err != nil {
		t.Fatal(err)
	}
	bodyDigest, err := Digest("tos.service.agent-guarantor-claim-admission-receipt-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	receipt := AuthorizedClaimAdmissionReceiptV1{Body: body, StageActionAdmissionEvidence: stage,
		AuthorizedClaimIngressReceipt: ingress, CoverageEndCommitment: effect.ExpectedCoverageEndCommitment,
		AuthorityInstanceRecord: instance, AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObject("claim-admission-receipt", bodyDigest,
			"tos.service.agent-guarantor-claim-admission-receipt-signature.v1", at)},
		InitialClaimAdmissionProof: initialProof}
	history.coverageRevision++
	history.revisionLogs[revisionLogID] = signedHistoryLog{sequence: body.ClaimRevisionAdmissionSequence,
		root: body.AdmittedClaimRevisionLogRoot}
	if kind == "initial" {
		history.initialReceipts[claim.Body.ClaimID] = receipt
		history.claims[claim.Body.ClaimID] = &signedHistoryClaim{status: "admitted", stateRevision: 1, epoch: 1, epochRevision: 1}
	} else {
		history.claims[claim.Body.ClaimID].stateRevision++
		history.claims[claim.Body.ClaimID].decisionSequence = 0
		history.claims[claim.Body.ClaimID].status = "admitted"
	}
	history.admissions[claim.Body.ClaimID] = append(history.admissions[claim.Body.ClaimID], receipt)
	history.latestReceipts[claim.Body.ClaimID] = receipt
	history.store(receipt)
	return receipt
}

// claimAdmissionProof seals receipt into its compact proof at, under the
// stage authority bound for its admission kind.
func (history *signedHistory) claimAdmissionProof(receipt AuthorizedClaimAdmissionReceiptV1, at uint64) ClaimAdmissionReceiptProofV1 {
	t := history.t
	seal, descriptor, err := NewClaimAdmissionReceiptSealBodyV1(receipt, history.terms, time.Unix(int64(at), 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	sealDigest, err := Digest(ClaimAdmissionReceiptSealDomainV1, seal)
	if err != nil {
		t.Fatal(err)
	}
	stage := "claim_revision_admission"
	if receipt.Body.AdmissionKind == "initial" {
		stage = "initial_claim_admission"
	}
	bound, err := FindStageActionAuthorityV1(history.terms.StageActionAuthorityBinding, stage)
	if err != nil {
		t.Fatal(err)
	}
	authorization := history.signObjectAs(bound.ActionAuthorityID, history.terms.LifecycleAuthorizationProfile,
		"claim-admission-receipt-seal", sealDigest, "tos.service.agent-guarantor-claim-admission-receipt-seal-signature.v1",
		seal.SealedAtUnix)
	proof, err := BuildClaimAdmissionReceiptProofV1(receipt, history.terms, descriptor, seal, authorization)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

// store keeps value's canonical bytes for retrieval by envelope digest.
func (history *signedHistory) store(value any) {
	t := history.t
	wire, err := Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	var digest string
	switch typed := value.(type) {
	case AuthorizedClaimAdmissionReceiptV1:
		digest, err = ClaimAdmissionReceiptDigestV1(typed)
	case AuthorizedClaimDecisionAdmissionReceiptV1:
		digest, err = ClaimDecisionAdmissionReceiptDigestV1(typed)
	case AuthorizedClaimFilingCloseReceiptV1:
		digest, err = ClaimFilingCloseReceiptDigestV1(typed)
	case AuthorizedClaimDecisionApplicationReceiptV1:
		digest, err = ClaimDecisionApplicationReceiptDigestV1(typed)
	default:
		t.Fatalf("signed history cannot store %T", value)
	}
	if err != nil {
		t.Fatal(err)
	}
	history.resolver.evidence[digest] = wire
}

// verifyClaimAdmission is the claim admission verifier at at.
func (history *signedHistory) verifyClaimAdmission(receipt AuthorizedClaimAdmissionReceiptV1, at uint64) error {
	return VerifyClaimAdmissionReceiptV1(receipt, history.terms, permissiveAgreementVerifier{}, history.resolver,
		history.fenceResolver, time.Unix(int64(at), 0).UTC())
}

// TestSignedHistoryVerifiesTheRevisionsInitialProof: a revision admission's
// initial-admission proof is verified in full, including its own ingress
// receipt, authorization quorum and seal. A proof whose body no longer
// matches its seal, or whose seal was signed by another authority, is
// refused even though every binding checked before signatures holds.
func TestSignedHistoryVerifiesTheRevisionsInitialProof(t *testing.T) {
	history := newSignedHistory(t)
	withSignedHistorySeam(t, history)
	first := history.claim(1, nil, signedHistoryStart+30)
	initial := history.admit(first, signedHistoryStart+40)
	if err := history.verifyClaimAdmission(initial, signedHistoryStart+40); err != nil {
		t.Fatalf("the signed initial admission does not verify: %v", err)
	}
	second := history.claim(2, &first, signedHistoryStart+50)
	revision := history.admit(second, signedHistoryStart+60)
	if err := history.verifyClaimAdmission(revision, signedHistoryStart+60); err != nil {
		t.Fatalf("the signed revision admission does not verify: %v", err)
	}
	third := history.claim(3, &second, signedHistoryStart+70)
	thirdRevision := history.admit(third, signedHistoryStart+80)
	if err := history.verifyClaimAdmission(thirdRevision, signedHistoryStart+80); err != nil {
		t.Fatalf("the signed third revision admission does not verify: %v", err)
	}
	const invalid = "initial claim admission proof is invalid"
	changed := func(change func(*ClaimAdmissionReceiptProofV1)) AuthorizedClaimAdmissionReceiptV1 {
		altered := thirdRevision
		proof := *thirdRevision.InitialClaimAdmissionProof
		change(&proof)
		altered.InitialClaimAdmissionProof = &proof
		return altered
	}
	for name, receipt := range map[string]AuthorizedClaimAdmissionReceiptV1{
		"proof body no longer matching its seal": changed(func(proof *ClaimAdmissionReceiptProofV1) {
			proof.ReceiptBody.AdmittedAtUnix++
		}),
		"seal signed by another authority": changed(func(proof *ClaimAdmissionReceiptProofV1) {
			proof.SealAuthorization = history.signObjectAs("authority:other", history.terms.LifecycleAuthorizationProfile,
				"claim-admission-receipt-seal", proof.SealAuthorization.AuthorizedBodyDigest,
				"tos.service.agent-guarantor-claim-admission-receipt-seal-signature.v1", proof.SealBody.SealedAtUnix)
		}),
		"another admission's sealed proof under the initial digest": changed(func(proof *ClaimAdmissionReceiptProofV1) {
			other := history.claimAdmissionProof(revision, signedHistoryStart+80)
			other.ReceiptEnvelopeDigest = proof.ReceiptEnvelopeDigest
			other.ReceiptDescriptor.ContentDigest = proof.ReceiptEnvelopeDigest
			other.ReceiptBody.AdmissionKind = "initial"
			*proof = other
		}),
	} {
		if err := history.verifyClaimAdmission(receipt, signedHistoryStart+80); err == nil || !containsText(err.Error(), invalid) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, invalid)
		}
	}
}

func containsText(value, part string) bool {
	return len(part) == 0 || len(value) >= len(part) && indexText(value, part) >= 0
}

func indexText(value, part string) int {
	for index := 0; index+len(part) <= len(value); index++ {
		if value[index:index+len(part)] == part {
			return index
		}
	}
	return -1
}
