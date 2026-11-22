package agentguarantor

import (
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/codec"
)

// Exact canonical sizes of the fallback receipts built below from the
// measured ML-DSA-44 receipt. They move only with a deliberate wire change.
const (
	measuredFallbackRequestBytes         = 1_210
	measuredFallbackReceiptBytes         = 1_117_410
	measuredEmbeddedFallbackReceiptBytes = 2_564_000
	worstCaseReviewingFallbackBytes      = 1_699_024
	worstCaseNonterminalFallbackBytes    = 1_669_218
	worstCaseFallbackRequestBytes        = 1_782
	// worstCaseInitialClaimAdmissionProofBytes is the initial admission's
	// compact proof a revision admission carries, over a maximum-size claim
	// with full ML-DSA-44 authorization and seal signatures.
	worstCaseInitialClaimAdmissionProofBytes = 186_141
)

// evidenceResolver answers immutable-evidence retrievals from content and
// counts them, so a test can assert exactly which references were followed.
type evidenceResolver struct {
	allowAuthorityResolver
	content map[string][]byte
	calls   *int
}

func (resolver evidenceResolver) ResolveImmutableGuarantorEvidence(descriptor ImmutableEvidenceDescriptorV1) ([]byte, error) {
	*resolver.calls++
	wire, found := resolver.content[descriptor.ContentDigest]
	if !found {
		return nil, errors.New("immutable evidence is not held")
	}
	return wire, nil
}

func newEvidenceResolver() evidenceResolver {
	calls := 0
	return evidenceResolver{content: map[string][]byte{}, calls: &calls}
}

// fallbackShape is a fallback admission receipt and the request variant it
// carries; setRequest re-encodes the variant into the receipt.
type fallbackShape struct {
	receipt AuthorizedClaimDecisionAdmissionReceiptV1
	variant DeterministicFallbackAdmissionVariantV1
}

func (shape *fallbackShape) setRequest(t *testing.T) {
	t.Helper()
	variant := shape.variant
	request, err := Canonical(ClaimDecisionAdmissionActionBodyV1{SchemaVersion: 1,
		AdmissionMode: "deterministic_fallback", DeterministicFallbackVariant: &variant})
	if err != nil {
		t.Fatal(err)
	}
	shape.receipt.StageActionAdmissionEvidence.CanonicalRequest = request
}

// toFallbackShape turns an authorized-decision receipt into the fallback
// admission of the same claim: same claim admission, cut, end commitment,
// eligibility proofs and authorization quorum, with the request replaced by
// the reference-only fallback variant.
func toFallbackShape(t *testing.T, receipt AuthorizedClaimDecisionAdmissionReceiptV1, terms CoverageTermsV1,
	sourceState, path string) fallbackShape {
	t.Helper()
	var authorized ClaimDecisionAdmissionActionBodyV1
	if err := Unmarshal(receipt.StageActionAdmissionEvidence.CanonicalRequest, &authorized); err != nil ||
		authorized.AuthorizedDecisionVariant == nil {
		t.Fatalf("source receipt is not an authorized-decision receipt: %v", err)
	}
	claimDigest, err := ClaimAdmissionReceiptDigestV1(receipt.AuthorizedClaimAdmissionReceipt)
	if err != nil {
		t.Fatal(err)
	}
	fallbackDigest, err := DeterministicClaimTerminalFallbackDigestV1(terms.ClaimClosureCapacity.TerminalFallback)
	if err != nil {
		t.Fatal(err)
	}
	claim := receipt.AuthorizedClaimAdmissionReceipt.AuthorizedClaimIngressReceipt.AuthorizedClaim
	cutoff := receipt.Body.AdmittedAtUnix
	shape := fallbackShape{receipt: receipt, variant: DeterministicFallbackAdmissionVariantV1{
		CoverageAgreementBodyDigest: claim.Body.CoverageAgreementBodyDigest, CoverageObligationID: claim.Body.CoverageObligationID,
		ClaimID: claim.Body.ClaimID, AuthorizedClaimAdmissionReceiptDigest: claimDigest,
		ClaimRevisionEpochExpectation: authorized.AuthorizedDecisionVariant.ClaimRevisionEpochExpectation,
		FallbackProfileDigest:         fallbackDigest, SourceClaimRevision: claim.Body.ClaimRevision,
		SourceClaimStateRevision: receipt.Body.PriorClaimStateRevision, SourceClaimState: sourceState,
		ExpectedChallengeRoundsUsed:   receipt.Body.ChallengeRoundsUsedBefore,
		ExpectedNonterminalRoundsUsed: receipt.Body.NonterminalRoundsUsedBefore, TriggerCutoffUnix: cutoff,
		DecisionSequence: receipt.Body.DecisionSequence}}
	shape.receipt.Body.AuthorizedClaimAdmissionReceiptDigest = claimDigest
	shape.receipt.Body.AdmissionMode = "deterministic_fallback"
	shape.receipt.Body.FallbackTriggerCutoffUnix = cutoff
	shape.receipt.Body.DecisionPath = path
	shape.receipt.AuthorizedClaimDecision.Body.DecisionPath = path
	shape.setRequest(t)
	return shape
}

func measuredInitialFallback(t *testing.T, terms CoverageTermsV1) fallbackShape {
	t.Helper()
	return toFallbackShape(t, loadMeasuredDecisionReceipt(t), terms, "initial_reviewing", "initial_terminal_fallback")
}

func lateFilingDescriptor(terms CoverageTermsV1, digest string, size uint64) ImmutableEvidenceDescriptorV1 {
	return ImmutableEvidenceDescriptorV1{ContentType: ClaimFilingCloseReceiptMediaTypeV1, ContentDigest: digest,
		ContentSize: size, RetrievalPolicyDigest: terms.ClaimAdmissionProfile.ProfileDigest}
}

// worstCaseReviewingLateFallback is the largest released fallback shape:
// late recovery from a reviewing head over the worst-case authorized history
// (maximum claim at every nested copy, transition receipt whose decision proof
// repeats it, prior pending token, every optional body field).
func worstCaseReviewingLateFallback(t *testing.T, terms CoverageTermsV1) fallbackShape {
	t.Helper()
	worst := buildWorstCaseAuthorizedDecisionReceipt(t)
	shape := toFallbackShape(t, worst, terms, "reviewing_after_challenge", "late_recovery_terminal_fallback")
	transition := shape.receipt.PredecessorClaimStateTransitionReceipt
	transitionDigest, err := ClaimStateTransitionReceiptDigestV1(*transition)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := lateFilingDescriptor(terms, sizeTestDigest("f"), terms.ClaimClosureCapacity.MaximumClaimFilingCloseReceiptEnvelopeBytes)
	shape.variant.CurrentDecisionAdmissionReceiptDigest = transition.DecisionAdmissionProof.ReceiptEnvelopeDigest
	shape.variant.CurrentClaimStateTransitionReceiptDigest = transitionDigest
	shape.variant.LateFilingCloseReceiptDescriptor = &descriptor
	shape.receipt.Body.LateFilingCloseReceiptDigest = descriptor.ContentDigest
	// The source head is the transition's resulting state and counts.
	head := transition.Body
	setFallbackHead(&shape, head.ResultingClaimStateRevision, head.ChallengeRoundsUsedAfter, head.NonterminalRoundsUsedAfter, false)
	shape.setRequest(t)
	return shape
}

// setFallbackHead aligns the request and receipt body with the head's state
// revision and round counts; consumes adds the nonterminal round a fallback
// from evidence_required or disputed closes.
func setFallbackHead(shape *fallbackShape, stateRevision, challengeRounds, nonterminalRounds uint64, consumes bool) {
	shape.variant.SourceClaimStateRevision = stateRevision
	shape.receipt.Body.PriorClaimStateRevision = stateRevision
	shape.receipt.Body.AdmittedClaimStateRevision = stateRevision + 1
	shape.variant.ExpectedChallengeRoundsUsed, shape.variant.ExpectedNonterminalRoundsUsed = challengeRounds, nonterminalRounds
	shape.receipt.Body.ChallengeRoundsUsedBefore, shape.receipt.Body.ChallengeRoundsUsedAfter = challengeRounds, challengeRounds
	shape.receipt.Body.NonterminalRoundsUsedBefore, shape.receipt.Body.NonterminalRoundsUsedAfter = nonterminalRounds, nonterminalRounds
	if consumes {
		shape.receipt.Body.NonterminalRoundsUsedAfter = nonterminalRounds + 1
	}
}

// worstCaseNonterminalLateFallback is late recovery from a disputed head: the
// current decision travels as its own compact proof instead of inside a
// transition receipt.
func worstCaseNonterminalLateFallback(t *testing.T, terms CoverageTermsV1) fallbackShape {
	t.Helper()
	shape := worstCaseReviewingLateFallback(t, terms)
	proof := shape.receipt.PredecessorClaimStateTransitionReceipt.DecisionAdmissionProof
	// The disputed decision froze the epoch, so it stands on the same claim
	// admission as the fallback.
	proof.ReceiptBody.AuthorizedClaimAdmissionReceiptDigest = shape.variant.AuthorizedClaimAdmissionReceiptDigest
	proof.ReceiptBody.AdmittedClaimState = "disputed"
	// It also left the epoch frozen with the cut the fallback reuses.
	cutDigest, err := ClaimIngressAdmissionCutProofDigestV1(shape.receipt.ClaimRevisionIngressCutProof)
	if err != nil {
		t.Fatal(err)
	}
	proof.ReceiptBody.ClaimRevisionIngressCutProofDigest = cutDigest
	shape.receipt.PredecessorClaimStateTransitionReceipt = nil
	shape.receipt.PriorPendingApplicationToken = nil
	shape.receipt.CurrentDecisionAdmissionProof = &proof
	shape.variant.SourceClaimState = "disputed"
	shape.variant.CurrentClaimStateTransitionReceiptDigest = ""
	head := proof.ReceiptBody
	setFallbackHead(&shape, head.AdmittedClaimStateRevision, head.ChallengeRoundsUsedAfter, head.NonterminalRoundsUsedAfter, true)
	reuseFrozenEpoch(&shape, head)
	shape.setRequest(t)
	return shape
}

// lateCandidateFilingDigest is the late filing-close digest the challenged
// late-recovery candidate of the test shapes carries.
var lateCandidateFilingDigest = sizeTestDigest("6")

// reviewingAfterLateCandidate is a fallback from a reviewing head whose
// challenged decision was a late-recovery candidate: that challenge left the
// epoch frozen, so the fallback reuses the candidate's epoch and cut, stands
// on its claim admission, and carries its late filing-close digest as the
// one-challenge-round marker.
func reviewingAfterLateCandidate(t *testing.T, reviewing fallbackShape) fallbackShape {
	t.Helper()
	shape := reviewing
	transition := *shape.receipt.PredecessorClaimStateTransitionReceipt
	candidate := &transition.DecisionAdmissionProof
	candidate.AuthorizedClaimDecision.Body.DecisionPath = "late_recovery_terminal_fallback"
	candidate.ReceiptBody.AuthorizedClaimAdmissionReceiptDigest = shape.variant.AuthorizedClaimAdmissionReceiptDigest
	candidate.ReceiptBody.LateFilingCloseReceiptDigest = lateCandidateFilingDigest
	cutDigest, err := ClaimIngressAdmissionCutProofDigestV1(shape.receipt.ClaimRevisionIngressCutProof)
	if err != nil {
		t.Fatal(err)
	}
	candidate.ReceiptBody.ClaimRevisionIngressCutProofDigest = cutDigest
	shape.receipt.Body.LateFilingCloseReceiptDigest = lateCandidateFilingDigest
	transitionDigest, err := ClaimStateTransitionReceiptDigestV1(transition)
	if err != nil {
		t.Fatal(err)
	}
	shape.receipt.PredecessorClaimStateTransitionReceipt = &transition
	shape.variant.CurrentClaimStateTransitionReceiptDigest = transitionDigest
	reuseFrozenEpoch(&shape, transition.DecisionAdmissionProof.ReceiptBody)
	shape.setRequest(t)
	return shape
}

// reuseFrozenEpoch points a fallback at the frozen epoch its head left: a
// frozen expectation of that epoch and state revision and the head's
// unchanged epoch fields. The shapes already carry the head decision's own
// cut.
func reuseFrozenEpoch(shape *fallbackShape, head ClaimDecisionAdmissionReceiptBodyV1) {
	epoch := &shape.variant.ClaimRevisionEpochExpectation
	epoch.ExpectedEpochState = "frozen"
	epoch.RevisionEpoch = head.FrozenRevisionEpoch
	epoch.ExpectedEpochStateRevision = head.FrozenRevisionEpochStateRevision
	body := &shape.receipt.Body
	body.FrozenRevisionEpoch, body.PriorRevisionEpochStateRevision = head.FrozenRevisionEpoch, head.PriorRevisionEpochStateRevision
	body.FrozenRevisionEpochStateRevision = head.FrozenRevisionEpochStateRevision
	body.FrozenClaimRevisionIngressHighWater = head.FrozenClaimRevisionIngressHighWater
	body.FrozenClaimRevisionIngressLogRoot = head.FrozenClaimRevisionIngressLogRoot
}

// checkFallbackFits asserts the bounds every fallback receipt must meet and
// returns its canonical size.
func checkFallbackFits(t *testing.T, name string, shape fallbackShape) int {
	t.Helper()
	request := shape.receipt.StageActionAdmissionEvidence.CanonicalRequest
	if len(request) > MaximumStageRequestBytesV1 {
		t.Fatalf("%s: request %d exceeds the stage request ceiling", name, len(request))
	}
	if text := base64.StdEncoding.EncodedLen(len(request)); text > codec.MaxStringBytes {
		t.Fatalf("%s: request text %d exceeds the shared string bound", name, text)
	}
	encoded, err := Canonical(shape.receipt)
	if err != nil {
		t.Fatalf("%s: fallback receipt refused: %v", name, err)
	}
	decoded, err := DecodeRegisteredObjectV1("claim-decision-admission-receipt", encoded)
	if err != nil {
		t.Fatalf("%s: fallback receipt decode refused: %v", name, err)
	}
	again, err := Canonical(decoded)
	if err != nil || string(again) != string(encoded) {
		t.Fatalf("%s: fallback receipt does not re-encode identically", name)
	}
	if longest := largestNestedString(t, shape.receipt); longest > MaxCanonicalObjectBytes {
		t.Fatalf("%s: longest nested string %d exceeds the Guarantor string bound", name, longest)
	}
	if _, _, err := DeterministicFallbackAdmissionSourceIdentityV1(shape.variant); err != nil {
		t.Fatalf("%s: fallback source identity refused: %v", name, err)
	}
	return len(encoded)
}

func TestMeasuredFallbackReceiptFitsEveryBound(t *testing.T) {
	terms := testCoverageTerms(t)
	shape := measuredInitialFallback(t, terms)
	size := checkFallbackFits(t, "measured initial fallback", shape)
	request := len(shape.receipt.StageActionAdmissionEvidence.CanonicalRequest)
	t.Logf("measured fallback: request %d bytes (%d base64 characters); receipt %d bytes; ceiling %d; margin %d",
		request, base64.StdEncoding.EncodedLen(request), size, MaxCanonicalObjectBytes, MaxCanonicalObjectBytes-size)
	if request != measuredFallbackRequestBytes || size != measuredFallbackReceiptBytes {
		t.Fatalf("measured fallback is request %d / receipt %d bytes, want %d / %d",
			request, size, measuredFallbackRequestBytes, measuredFallbackReceiptBytes)
	}
	if _, err := codec.Marshal(shape.receipt); err == nil {
		t.Fatal("the shared 1 MiB codec encoded the fallback receipt; it should need the Guarantor bound")
	}
}

// TestEmbeddedFallbackRequestShapeIsRefused rebuilds the request shape that
// embedded the claim admission receipt and shows both why it was replaced
// (the smallest receipt carrying it exceeds the object ceiling) and that it no
// longer decodes.
func TestEmbeddedFallbackRequestShapeIsRefused(t *testing.T) {
	terms := testCoverageTerms(t)
	shape := measuredInitialFallback(t, terms)
	model := toJSONModel(t, ClaimDecisionAdmissionActionBodyV1{SchemaVersion: 1,
		AdmissionMode: "deterministic_fallback", DeterministicFallbackVariant: &shape.variant}).(map[string]any)
	variant := model["deterministic_fallback_variant"].(map[string]any)
	delete(variant, "authorized_claim_admission_receipt_digest")
	variant["authorized_claim_admission_receipt"] = toJSONModel(t, shape.receipt.AuthorizedClaimAdmissionReceipt)
	embeddedRequest, err := codec.Bounded{Limits: codec.Limits{CanonicalBytes: 2 * MaxCanonicalObjectBytes,
		JSONBytes: 4 * MaxCanonicalObjectBytes, StringBytes: MaxCanonicalObjectBytes}}.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	receiptModel := toJSONModel(t, shape.receipt).(map[string]any)
	receiptModel["stage_action_admission_evidence"].(map[string]any)["canonical_request"] =
		base64.StdEncoding.EncodeToString(embeddedRequest)
	embeddedReceipt := mustCanonicalSizeOrZero(receiptModel)
	t.Logf("embedded-receipt fallback: request %d bytes (%d base64 characters); smallest receipt %d bytes against the %d-byte ceiling",
		len(embeddedRequest), base64.StdEncoding.EncodedLen(len(embeddedRequest)), embeddedReceipt, MaxCanonicalObjectBytes)
	if embeddedReceipt != measuredEmbeddedFallbackReceiptBytes || embeddedReceipt <= MaxCanonicalObjectBytes ||
		base64.StdEncoding.EncodedLen(len(embeddedRequest)) <= codec.MaxStringBytes {
		t.Fatalf("embedded-receipt fallback is %d bytes, want %d and over the %d-byte ceiling",
			embeddedReceipt, measuredEmbeddedFallbackReceiptBytes, MaxCanonicalObjectBytes)
	}
	small := toJSONModel(t, ClaimDecisionAdmissionActionBodyV1{SchemaVersion: 1,
		AdmissionMode: "deterministic_fallback", DeterministicFallbackVariant: &shape.variant}).(map[string]any)
	small["deterministic_fallback_variant"].(map[string]any)["current_decision_admission_receipt"] = map[string]any{}
	wire, err := Canonical(small)
	if err != nil {
		t.Fatal(err)
	}
	shape.receipt.StageActionAdmissionEvidence.CanonicalRequest = wire
	err = VerifyClaimDecisionAdmissionReceiptV1(shape.receipt, terms, permissiveAgreementVerifier{}, newEvidenceResolver(), nil,
		time.Unix(2_000_000_100, 0).UTC())
	if err == nil || !strings.Contains(err.Error(), "not the closed tagged variant") {
		t.Fatalf("a request carrying an embedded receipt field was not refused at decoding: %v", err)
	}
}

func TestWorstCaseFallbackReceiptsFitWithMargin(t *testing.T) {
	terms := testCoverageTerms(t)
	reviewing := worstCaseReviewingLateFallback(t, terms)
	nonterminal := worstCaseNonterminalLateFallback(t, terms)
	reviewingSize := checkFallbackFits(t, "worst-case reviewing late fallback", reviewing)
	nonterminalSize := checkFallbackFits(t, "worst-case disputed late fallback", nonterminal)
	request := len(reviewing.receipt.StageActionAdmissionEvidence.CanonicalRequest)
	// The claim admission is a revision, which carries the initial
	// admission's proof; its claim is as large as the revision's.
	initial := *reviewing.receipt.AuthorizedClaimAdmissionReceipt.InitialClaimAdmissionProof
	t.Logf("worst-case initial claim admission proof: %d bytes (ingress receipt %d, coverage end %d, "+
		"authority instance %d, eligibility proofs %d, receipt authorizations %d, seal authorization %d, receipt body %d)",
		mustCanonicalSize(t, initial), mustCanonicalSize(t, initial.AuthorizedClaimIngressReceipt),
		mustCanonicalSize(t, initial.CoverageEndCommitment), mustCanonicalSize(t, initial.AuthorityInstanceRecord),
		mustCanonicalSize(t, initial.AuthorityAdmissionEligibilityProofSet), mustCanonicalSize(t, initial.ReceiptAuthorizations),
		mustCanonicalSize(t, initial.SealAuthorization), mustCanonicalSize(t, initial.ReceiptBody))
	if size := mustCanonicalSize(t, initial); size != worstCaseInitialClaimAdmissionProofBytes {
		t.Fatalf("worst-case initial claim admission proof is %d bytes, want %d", size, worstCaseInitialClaimAdmissionProofBytes)
	}
	t.Logf("worst-case fallback: reviewing %d bytes (margin %d, %.1f%%), disputed %d bytes, request %d bytes",
		reviewingSize, MaxCanonicalObjectBytes-reviewingSize,
		100*float64(MaxCanonicalObjectBytes-reviewingSize)/float64(MaxCanonicalObjectBytes), nonterminalSize, request)
	if reviewingSize != worstCaseReviewingFallbackBytes || nonterminalSize != worstCaseNonterminalFallbackBytes ||
		request != worstCaseFallbackRequestBytes {
		t.Fatalf("worst-case fallback is reviewing %d / disputed %d / request %d bytes, want %d / %d / %d",
			reviewingSize, nonterminalSize, request, worstCaseReviewingFallbackBytes,
			worstCaseNonterminalFallbackBytes, worstCaseFallbackRequestBytes)
	}
	// The reviewing shape is the larger, and it must leave at least an eighth
	// of the ceiling for profile variation. The late fallback of a revised
	// claim carries the initial admission's compact proof, and this worst case
	// assumes a maximum-size claim and full ML-DSA-44 signature sets in it.
	if reviewingSize < nonterminalSize || MaxCanonicalObjectBytes-reviewingSize < MaxCanonicalObjectBytes/8 {
		t.Fatalf("worst-case fallback ordering or margin changed: reviewing %d, disputed %d", reviewingSize, nonterminalSize)
	}
}

// claimAdmissionActivation is the activation evidence the receipt's claim
// admission request carries.
func claimAdmissionActivation(t *testing.T, receipt AuthorizedClaimDecisionAdmissionReceiptV1) AuthorizedCoverageActivationEvidenceV1 {
	t.Helper()
	var submission ClaimSubmissionActionBodyV1
	if err := Unmarshal(receipt.AuthorizedClaimAdmissionReceipt.StageActionAdmissionEvidence.CanonicalRequest, &submission); err != nil {
		t.Fatal(err)
	}
	return submission.AuthorityInstanceEffect.AuthorizedCoverageActivationEvidence
}

// fakeFilingCloseReceipt is a canonically encodable filing-close receipt on
// the receipt's coverage and activation; only its binding fields are real.
func fakeFilingCloseReceipt(t *testing.T, receipt AuthorizedClaimDecisionAdmissionReceiptV1, root string) (AuthorizedClaimFilingCloseReceiptV1, []byte, string) {
	t.Helper()
	activation := claimAdmissionActivation(t, receipt)
	initialAdmission := receipt.AuthorizedClaimAdmissionReceipt.Body.InitialClaimAdmissionReceiptDigest
	if receipt.AuthorizedClaimAdmissionReceipt.Body.AdmissionKind == "initial" {
		var err error
		if initialAdmission, err = ClaimAdmissionReceiptDigestV1(receipt.AuthorizedClaimAdmissionReceipt); err != nil {
			t.Fatal(err)
		}
	}
	filing := AuthorizedClaimFilingCloseReceiptV1{Body: ClaimFilingCloseReceiptBodyV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: receipt.Body.CoverageAgreementBodyDigest,
		CoverageObligationID:        receipt.Body.CoverageObligationID, FrozenClaimAdmissionLogRoot: root,
		FilingCutoffUnix: lateFilingCutoffUnix},
		ClaimIngressAdmissionCutProof: ClaimIngressAdmissionCutProofV1{CutKind: "initial_claims",
			Entries: []ClaimIngressResolutionEntryV1{timelyAdmittedEntry(initialAdmission)}},
		AuthorizedActivationEvidence: &activation, Authorizations: receipt.Authorizations[:1]}
	return encodeFilingClose(t, filing)
}

// lateFilingCutoffUnix is the filing cutoff of the fake filing-close receipts.
const lateFilingCutoffUnix = 1_000

// timelyAdmittedEntry is a filing-close cut entry admitting the claim whose
// initial admission is initialAdmission, received before the filing cutoff.
func timelyAdmittedEntry(initialAdmission string) ClaimIngressResolutionEntryV1 {
	return ClaimIngressResolutionEntryV1{ClaimIngressSequence: 1, ReceivedAtUnix: lateFilingCutoffUnix - 1,
		ResolutionKind: "claim_admitted", ClaimAdmissionReceiptDigest: initialAdmission}
}

// TestLateFallbackMatchesTheClaimsInitialAdmission: the filing close's cut
// records each claim's initial admission, so a late fallback for a revised
// claim matches the initial admission its revision admission names, and an
// initial admission matches itself.
func TestLateFallbackMatchesTheClaimsInitialAdmission(t *testing.T) {
	measured := loadMeasuredDecisionReceipt(t)
	revision := measured.AuthorizedClaimAdmissionReceipt
	if revision.Body.AdmissionKind != "revision" || !validDigest(revision.Body.InitialClaimAdmissionReceiptDigest) {
		t.Fatalf("the measured claim admission is not a revision admission: %q", revision.Body.AdmissionKind)
	}
	initial := revision
	initial.Body.AdmissionKind = "initial"
	initial.Body.InitialClaimAdmissionReceiptDigest = ""
	initial.InitialClaimAdmissionProof = nil
	initialDigest, err := ClaimAdmissionReceiptDigestV1(initial)
	if err != nil {
		t.Fatal(err)
	}
	revisionDigest, err := ClaimAdmissionReceiptDigestV1(revision)
	if err != nil {
		t.Fatal(err)
	}
	filingWith := func(entries ...ClaimIngressResolutionEntryV1) AuthorizedClaimFilingCloseReceiptV1 {
		filing, _, _ := fakeFilingCloseReceipt(t, measured, sizeTestDigest("7"))
		filing.ClaimIngressAdmissionCutProof.Entries = entries
		return filing
	}
	late := timelyAdmittedEntry(revision.Body.InitialClaimAdmissionReceiptDigest)
	late.ReceivedAtUnix = lateFilingCutoffUnix + 1
	notAdmitted := timelyAdmittedEntry(revision.Body.InitialClaimAdmissionReceiptDigest)
	notAdmitted.ResolutionKind = "claim_rejected"
	withProof := func(change func(*ClaimAdmissionReceiptProofV1)) AuthorizedClaimAdmissionReceiptV1 {
		changed := revision
		proof := *revision.InitialClaimAdmissionProof
		change(&proof)
		changed.InitialClaimAdmissionProof = &proof
		return changed
	}
	const noIngress = "does not identify a timely admitted ingress"
	const notInitial = "is not the claim's initial admission"
	timely := filingWith(timelyAdmittedEntry(revision.Body.InitialClaimAdmissionReceiptDigest))
	withoutProof := revision
	withoutProof.InitialClaimAdmissionProof = nil
	initialWithProof := initial
	initialWithProof.InitialClaimAdmissionProof = revision.InitialClaimAdmissionProof
	cases := map[string]struct {
		admission AuthorizedClaimAdmissionReceiptV1
		filing    AuthorizedClaimFilingCloseReceiptV1
		want      string
	}{
		"revised claim, its initial admission in the cut": {revision, timely, ""},
		"initial admission, itself in the cut":            {initial, filingWith(timelyAdmittedEntry(initialDigest)), ""},
		"revised claim naming another initial admission": {func() AuthorizedClaimAdmissionReceiptV1 {
			other := revision
			other.Body.InitialClaimAdmissionReceiptDigest = sizeTestDigest("1")
			return other
		}(), timely, notInitial},
		"revised claim without the initial proof": {withoutProof, timely, "lacks its initial claim admission proof"},
		"initial proof of another claim": {withProof(func(p *ClaimAdmissionReceiptProofV1) {
			p.ReceiptBody.ClaimID = sizeTestDigest("2")
		}), timely, notInitial},
		"initial proof on another coverage": {withProof(func(p *ClaimAdmissionReceiptProofV1) {
			p.ReceiptBody.CoverageObligationID = "obligation:other"
		}), timely, notInitial},
		"initial proof of a revision admission": {withProof(func(p *ClaimAdmissionReceiptProofV1) {
			p.ReceiptBody.AdmissionKind = "revision"
		}), timely, notInitial},
		"initial admission carrying an initial proof":      {initialWithProof, filingWith(timelyAdmittedEntry(initialDigest)), "carries an initial claim admission proof"},
		"revised claim matched by its own revision digest": {revision, filingWith(timelyAdmittedEntry(revisionDigest)), noIngress},
		"initial admission received after the cutoff":      {revision, filingWith(late), noIngress},
		"initial admission not admitted":                   {revision, filingWith(notAdmitted), noIngress},
		"empty cut":                                        {revision, filingWith(), noIngress},
	}
	for name, test := range cases {
		err := bindLateFilingCloseToClaimAdmissionV1(test.filing, test.admission)
		if test.want == "" && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, test.want)
		}
	}
	unknown := revision
	unknown.Body.AdmissionKind = "replacement"
	if _, err := initialClaimAdmissionDigestV1(unknown); err == nil {
		t.Error("an unknown admission kind named an initial admission")
	}
}

// withClaimAdmission changes a private copy of the shape's claim admission
// receipt and re-points the request and receipt at it, so only the check
// under test refuses.
func withClaimAdmission(t *testing.T, change func(*AuthorizedClaimAdmissionReceiptV1)) func(*fallbackShape) {
	return func(shape *fallbackShape) {
		admission := shape.receipt.AuthorizedClaimAdmissionReceipt
		change(&admission)
		digest, err := ClaimAdmissionReceiptDigestV1(admission)
		if err != nil {
			t.Fatal(err)
		}
		shape.receipt.AuthorizedClaimAdmissionReceipt = admission
		shape.receipt.Body.AuthorizedClaimAdmissionReceiptDigest = digest
		shape.variant.AuthorizedClaimAdmissionReceiptDigest = digest
		shape.setRequest(t)
	}
}

// testInitialAdmissionProof is a compact proof of the initial admission a
// revision admission names, built from that revision's own parts so its size
// matches a real initial admission's. Only its binding fields are checked
// before signatures.
func testInitialAdmissionProof(revision AuthorizedClaimAdmissionReceiptV1) ClaimAdmissionReceiptProofV1 {
	body := revision.Body
	body.AdmissionKind = "initial"
	body.PriorClaimRevision, body.AdmittedClaimRevision, body.ClaimRevisionAdmissionSequence = 0, 1, 1
	body.InitialClaimAdmissionReceiptDigest, body.PredecessorRevisionAdmissionReceiptDigest = "", ""
	initial := revision.Body.InitialClaimAdmissionReceiptDigest
	return ClaimAdmissionReceiptProofV1{SchemaVersion: 1, ReceiptEnvelopeDigest: initial,
		ReceiptDescriptor: ImmutableEvidenceDescriptorV1{ContentType: GuarantorMediaTypePrefixV1 + "claim-admission.v1+cbor",
			ContentDigest: initial, ContentSize: MaxCanonicalObjectBytes, RetrievalPolicyDigest: sizeTestDigest("6")},
		ReceiptBody: body, AuthorizedClaimIngressReceipt: revision.AuthorizedClaimIngressReceipt,
		CoverageEndCommitment: revision.CoverageEndCommitment, AuthorityInstanceRecord: revision.AuthorityInstanceRecord,
		AuthorityAdmissionEligibilityProofSet: revision.AuthorityAdmissionEligibilityProofSet,
		ReceiptAuthorizations:                 revision.Authorizations,
		SealBody: ClaimAdmissionReceiptSealBodyV1{SchemaVersion: 1, ReceiptEnvelopeDigest: initial,
			ReceiptBodyDigest: sizeTestDigest("1"), AuthorizedActionDigest: body.AuthorizedActionDigest,
			AuthorizedClaimEnvelopeDigest: body.AuthorizedClaimEnvelopeDigest,
			ClaimIngressReceiptDigest:     body.ClaimSubmissionIngressReceiptDigest,
			CoverageEndCommitmentDigest:   sizeTestDigest("2"), AuthorityInstanceRecordDigest: sizeTestDigest("3"),
			EligibilityProofSetDigest: sizeTestDigest("4"), CoverageTermsDigest: sizeTestDigest("5"),
			SealedAtUnix: body.AdmittedAtUnix},
		SealAuthorization: revision.Authorizations[0]}
}

func encodeFilingClose(t *testing.T, filing AuthorizedClaimFilingCloseReceiptV1) (AuthorizedClaimFilingCloseReceiptV1, []byte, string) {
	t.Helper()
	wire, err := Canonical(filing)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ClaimFilingCloseReceiptDigestV1(filing)
	if err != nil {
		t.Fatal(err)
	}
	return filing, wire, digest
}

// withResolvableLateFiling points a late shape at a filing-close receipt the
// resolver holds.
func withResolvableLateFiling(t *testing.T, shape fallbackShape, terms CoverageTermsV1, resolver evidenceResolver) fallbackShape {
	t.Helper()
	_, wire, digest := fakeFilingCloseReceipt(t, shape.receipt, sizeTestDigest("7"))
	resolver.content[digest] = wire
	descriptor := lateFilingDescriptor(terms, digest, uint64(len(wire)))
	shape.variant.LateFilingCloseReceiptDescriptor = &descriptor
	shape.receipt.Body.LateFilingCloseReceiptDigest = digest
	shape.setRequest(t)
	return shape
}

// passedReferenceBinding is the first error after every reference is bound:
// the carried claim admission receipt is then verified, and the measured
// chain does not verify under the logic-test terms.
const passedReferenceBinding = "has an invalid claim admission"

func verifyFallbackShape(shape fallbackShape, terms CoverageTermsV1, resolver AuthorityKeyResolver) error {
	return VerifyClaimDecisionAdmissionReceiptV1(shape.receipt, terms, permissiveAgreementVerifier{}, resolver, nil,
		time.Unix(2_000_000_100, 0).UTC())
}

func TestFallbackReferencesBindExactlyOnce(t *testing.T) {
	terms := testCoverageTerms(t)
	resolver := newEvidenceResolver()
	shapes := map[string]fallbackShape{
		"initial":             measuredInitialFallback(t, terms),
		"reviewing late":      withResolvableLateFiling(t, worstCaseReviewingLateFallback(t, terms), terms, resolver),
		"disputed late":       withResolvableLateFiling(t, worstCaseNonterminalLateFallback(t, terms), terms, resolver),
		"reviewing in window": worstCaseReviewingLateFallback(t, terms),
		"disputed in window":  worstCaseNonterminalLateFallback(t, terms),
	}
	for _, name := range []string{"reviewing in window", "disputed in window"} {
		shape := shapes[name]
		shape.variant.LateFilingCloseReceiptDescriptor = nil
		shape.receipt.Body.LateFilingCloseReceiptDigest = ""
		shape.receipt.Body.DecisionPath, shape.receipt.AuthorizedClaimDecision.Body.DecisionPath = "terminal_fallback", "terminal_fallback"
		shape.setRequest(t)
		shapes[name] = shape
	}
	shapes["reviewing after a late candidate"] = reviewingAfterLateCandidate(t, shapes["reviewing in window"])
	for name, shape := range shapes {
		before := *resolver.calls
		err := verifyFallbackShape(shape, terms, resolver)
		if err == nil || !strings.Contains(err.Error(), passedReferenceBinding) {
			t.Fatalf("%s: a well-formed fallback shape did not pass reference binding: %v", name, err)
		}
		retrieved := *resolver.calls - before
		want := 0
		if shape.variant.LateFilingCloseReceiptDescriptor != nil {
			want = 1
		}
		if retrieved != want {
			t.Fatalf("%s: binding retrieved %d objects, want exactly %d", name, retrieved, want)
		}
	}

	// lateFiling re-points a late shape at a changed filing-close receipt that
	// the resolver holds, so only the binding under test can refuse it.
	lateFiling := func(change func(*AuthorizedClaimFilingCloseReceiptV1)) func(*fallbackShape) {
		return func(shape *fallbackShape) {
			filing, _, _ := fakeFilingCloseReceipt(t, shape.receipt, sizeTestDigest("7"))
			change(&filing)
			_, wire, digest := encodeFilingClose(t, filing)
			resolver.content[digest] = wire
			descriptor := lateFilingDescriptor(terms, digest, uint64(len(wire)))
			shape.variant.LateFilingCloseReceiptDescriptor = &descriptor
			shape.receipt.Body.LateFilingCloseReceiptDigest = digest
			shape.setRequest(t)
		}
	}
	// withProof changes a private copy of the carried current-decision proof.
	withProof := func(change func(*ClaimDecisionAdmissionReceiptProofV1)) func(*fallbackShape) {
		return func(shape *fallbackShape) {
			proof := *shape.receipt.CurrentDecisionAdmissionProof
			change(&proof)
			shape.receipt.CurrentDecisionAdmissionProof = &proof
		}
	}
	// withTransition changes a private copy of the carried transition receipt
	// and re-points the request at it, so only the check under test refuses.
	withTransition := func(change func(*AuthorizedClaimStateTransitionReceiptV1)) func(*fallbackShape) {
		return func(shape *fallbackShape) {
			transition := *shape.receipt.PredecessorClaimStateTransitionReceipt
			change(&transition)
			digest, err := ClaimStateTransitionReceiptDigestV1(transition)
			if err != nil {
				t.Fatal(err)
			}
			shape.receipt.PredecessorClaimStateTransitionReceipt = &transition
			shape.variant.CurrentClaimStateTransitionReceiptDigest = digest
			shape.setRequest(t)
		}
	}
	type mutation struct {
		shape  string
		change func(*fallbackShape)
		want   string
	}
	mutations := map[string]mutation{
		"claim admission reference": {"initial", func(shape *fallbackShape) {
			shape.variant.AuthorizedClaimAdmissionReceiptDigest = sizeTestDigest("1")
			shape.setRequest(t)
		}, "claim admission reference differs"},
		"claim admission body digest": {"initial", func(shape *fallbackShape) {
			shape.receipt.Body.AuthorizedClaimAdmissionReceiptDigest = sizeTestDigest("1")
		}, "claim admission reference differs"},
		"initial carries a transition": {"initial", func(shape *fallbackShape) {
			reviewing := worstCaseReviewingLateFallback(t, terms)
			shape.receipt.PredecessorClaimStateTransitionReceipt = reviewing.receipt.PredecessorClaimStateTransitionReceipt
		}, "initial fallback carries a predecessor head"},
		"initial carries a decision proof": {"initial", func(shape *fallbackShape) {
			shape.receipt.CurrentDecisionAdmissionProof = &ClaimDecisionAdmissionReceiptProofV1{}
		}, "initial fallback carries a predecessor head"},
		"initial names a decision": {"initial", func(shape *fallbackShape) {
			shape.variant.CurrentDecisionAdmissionReceiptDigest = sizeTestDigest("1")
			shape.setRequest(t)
		}, "initial fallback carries a predecessor head"},
		"disputed lacks its proof": {"disputed in window", func(shape *fallbackShape) {
			shape.receipt.CurrentDecisionAdmissionProof = nil
		}, "lacks its current decision admission proof"},
		"disputed proof substituted": {"disputed in window", func(shape *fallbackShape) {
			shape.variant.CurrentDecisionAdmissionReceiptDigest = sizeTestDigest("1")
			shape.setRequest(t)
		}, "decision proof differs from its reference"},
		"disputed carries a transition": {"disputed in window", func(shape *fallbackShape) {
			reviewing := worstCaseReviewingLateFallback(t, terms)
			shape.receipt.PredecessorClaimStateTransitionReceipt = reviewing.receipt.PredecessorClaimStateTransitionReceipt
		}, "nonterminal fallback carries a transition head"},
		"disputed names a transition": {"disputed in window", func(shape *fallbackShape) {
			shape.variant.CurrentClaimStateTransitionReceiptDigest = sizeTestDigest("1")
			shape.setRequest(t)
		}, "nonterminal fallback carries a transition head"},
		"reviewing carries the proof twice": {"reviewing in window", func(shape *fallbackShape) {
			proof := shape.receipt.PredecessorClaimStateTransitionReceipt.DecisionAdmissionProof
			shape.receipt.CurrentDecisionAdmissionProof = &proof
		}, "outside its transition receipt"},
		"reviewing lacks its transition": {"reviewing in window", func(shape *fallbackShape) {
			shape.receipt.PredecessorClaimStateTransitionReceipt = nil
		}, "lacks its transition receipt"},
		"reviewing transition substituted": {"reviewing in window", func(shape *fallbackShape) {
			shape.variant.CurrentClaimStateTransitionReceiptDigest = sizeTestDigest("1")
			shape.setRequest(t)
		}, "transition receipt differs from its reference"},
		"reviewing decision reference substituted": {"reviewing in window", func(shape *fallbackShape) {
			shape.variant.CurrentDecisionAdmissionReceiptDigest = sizeTestDigest("1")
			shape.setRequest(t)
		}, "differs from its transition's proof"},
		"unknown source state": {"initial", func(shape *fallbackShape) {
			shape.variant.SourceClaimState = "approved"
			shape.setRequest(t)
		}, "source state is not registered"},
		"late fallback of a revised claim lacks the initial proof": {"reviewing late", withClaimAdmission(t,
			func(admission *AuthorizedClaimAdmissionReceiptV1) { admission.InitialClaimAdmissionProof = nil }),
			"lacks its initial claim admission proof"},
		"late fallback carries another claim's initial admission": {"reviewing late", withClaimAdmission(t,
			func(admission *AuthorizedClaimAdmissionReceiptV1) {
				proof := *admission.InitialClaimAdmissionProof
				proof.ReceiptBody.ClaimID = sizeTestDigest("2")
				admission.InitialClaimAdmissionProof = &proof
			}), "is not the claim's initial admission"},
		"late fallback's initial proof is not the one its revision names": {"reviewing late", withClaimAdmission(t,
			func(admission *AuthorizedClaimAdmissionReceiptV1) {
				proof := *admission.InitialClaimAdmissionProof
				proof.ReceiptEnvelopeDigest = sizeTestDigest("2")
				proof.ReceiptDescriptor.ContentDigest = proof.ReceiptEnvelopeDigest
				admission.InitialClaimAdmissionProof = &proof
			}), "is not the claim's initial admission"},
		"in-window fallback whose revision lacks its initial proof": {"reviewing in window", withClaimAdmission(t,
			func(admission *AuthorizedClaimAdmissionReceiptV1) { admission.InitialClaimAdmissionProof = nil }),
			"lacks its initial claim admission proof"},
		"late digest without a descriptor": {"reviewing in window", func(shape *fallbackShape) {
			shape.receipt.Body.LateFilingCloseReceiptDigest = sizeTestDigest("1")
		}, "is not its late-recovery marker"},
		"late candidate's successor drops its marker": {"reviewing after a late candidate", func(shape *fallbackShape) {
			shape.receipt.Body.LateFilingCloseReceiptDigest = ""
		}, "is not its late-recovery marker"},
		"late candidate's successor names another marker": {"reviewing after a late candidate", func(shape *fallbackShape) {
			shape.receipt.Body.LateFilingCloseReceiptDigest = sizeTestDigest("1")
		}, "is not its late-recovery marker"},
		"late candidate on another claim admission": {"reviewing after a late candidate", withTransition(func(transition *AuthorizedClaimStateTransitionReceiptV1) {
			transition.DecisionAdmissionProof.ReceiptBody.AuthorizedClaimAdmissionReceiptDigest = sizeTestDigest("1")
		}), "late-recovery candidate stands on another claim admission"},
		"second late recovery naming the candidate's filing close": {"reviewing after a late candidate", func(shape *fallbackShape) {
			descriptor := lateFilingDescriptor(terms, lateCandidateFilingDigest, 1024)
			shape.variant.LateFilingCloseReceiptDescriptor = &descriptor
			shape.receipt.Body.DecisionPath = "late_recovery_terminal_fallback"
			shape.receipt.AuthorizedClaimDecision.Body.DecisionPath = "late_recovery_terminal_fallback"
			shape.setRequest(t)
		}, "late recovery happens once per claim"},
		"second late recovery naming another filing close": {"reviewing after a late candidate", lateFiling(func(*AuthorizedClaimFilingCloseReceiptV1) {}),
			"late recovery happens once per claim"},
		"late recovery from a head already on the late path": {"disputed late", withProof(func(proof *ClaimDecisionAdmissionReceiptProofV1) {
			proof.ReceiptBody.LateFilingCloseReceiptDigest = lateCandidateFilingDigest
		}), "late recovery happens once per claim"},
		"late candidate with a different cut": {"reviewing after a late candidate", func(shape *fallbackShape) {
			shape.receipt.ClaimRevisionIngressCutProof.IngressCutoffUnix++
		}, "must reuse its head's frozen revision epoch and cut"},
		"reuse changes only the prior epoch state revision": {"disputed in window", func(shape *fallbackShape) {
			shape.receipt.Body.PriorRevisionEpochStateRevision++
		}, "must reuse its head's frozen revision epoch and cut"},
		"reuse changes only the frozen log root": {"disputed in window", func(shape *fallbackShape) {
			shape.receipt.Body.FrozenClaimRevisionIngressLogRoot = sizeTestDigest("1")
		}, "must reuse its head's frozen revision epoch and cut"},
		"reuse names another ingress log": {"disputed in window", func(shape *fallbackShape) {
			shape.variant.ClaimRevisionEpochExpectation.RevisionIngressLogID = sizeTestDigest("1")
			shape.setRequest(t)
		}, "names another revision ingress log than its cut"},
		"open path names another ingress log": {"initial", func(shape *fallbackShape) {
			shape.variant.ClaimRevisionEpochExpectation.RevisionIngressLogID = sizeTestDigest("1")
			shape.setRequest(t)
		}, "names another revision ingress log than its cut"},
		"open path frozen epoch": {"initial", func(shape *fallbackShape) {
			shape.receipt.Body.FrozenRevisionEpoch++
		}, "frozen-epoch fields differ from its cut"},
		"open path prior epoch state revision": {"initial", func(shape *fallbackShape) {
			shape.receipt.Body.PriorRevisionEpochStateRevision++
		}, "frozen-epoch fields differ from its cut"},
		"open path frozen epoch state revision": {"initial", func(shape *fallbackShape) {
			shape.receipt.Body.FrozenRevisionEpochStateRevision++
		}, "frozen-epoch fields differ from its cut"},
		"open path frozen high-water": {"reviewing in window", func(shape *fallbackShape) {
			shape.receipt.Body.FrozenClaimRevisionIngressHighWater++
		}, "frozen-epoch fields differ from its cut"},
		"open path frozen log root": {"reviewing in window", func(shape *fallbackShape) {
			shape.receipt.Body.FrozenClaimRevisionIngressLogRoot = sizeTestDigest("1")
		}, "frozen-epoch fields differ from its cut"},
		"late body digest differs": {"reviewing late", func(shape *fallbackShape) {
			shape.receipt.Body.LateFilingCloseReceiptDigest = sizeTestDigest("1")
		}, "other than its request"},
		"late descriptor media type": {"reviewing late", func(shape *fallbackShape) {
			shape.variant.LateFilingCloseReceiptDescriptor.ContentType = GuarantorMediaTypePrefixV1 + "claim.v1+cbor"
			shape.setRequest(t)
		}, "not the Agreement-bound filing-close reference"},
		"late descriptor retrieval policy": {"reviewing late", func(shape *fallbackShape) {
			shape.variant.LateFilingCloseReceiptDescriptor.RetrievalPolicyDigest = sizeTestDigest("1")
			shape.setRequest(t)
		}, "not the Agreement-bound filing-close reference"},
		"late descriptor oversized": {"reviewing late", func(shape *fallbackShape) {
			shape.variant.LateFilingCloseReceiptDescriptor.ContentSize = terms.ClaimClosureCapacity.MaximumClaimFilingCloseReceiptEnvelopeBytes + 1
			shape.setRequest(t)
		}, "not the Agreement-bound filing-close reference"},
		"late content length": {"reviewing late", func(shape *fallbackShape) {
			shape.variant.LateFilingCloseReceiptDescriptor.ContentSize++
			shape.setRequest(t)
		}, "late filing-close receipt is unavailable"},
		"late content missing": {"reviewing late", func(shape *fallbackShape) {
			shape.variant.LateFilingCloseReceiptDescriptor.ContentDigest = sizeTestDigest("2")
			shape.receipt.Body.LateFilingCloseReceiptDigest = sizeTestDigest("2")
			shape.setRequest(t)
		}, "late filing-close receipt is unavailable"},
		"late filing close on another activation": {"reviewing late", lateFiling(func(filing *AuthorizedClaimFilingCloseReceiptV1) {
			activation := *filing.AuthorizedActivationEvidence
			activation.Body.ActivatedAtUnix++
			filing.AuthorizedActivationEvidence = &activation
		}), "stands on another activation"},
		"late filing close on another obligation": {"disputed late", lateFiling(func(filing *AuthorizedClaimFilingCloseReceiptV1) {
			filing.Body.CoverageObligationID = "obligation:other"
		}), "belongs to another coverage"},
		"late filing close without activation": {"reviewing late", lateFiling(func(filing *AuthorizedClaimFilingCloseReceiptV1) {
			filing.AuthorizedActivationEvidence = nil
		}), "lacks activation evidence"},
		"disputed proof on another claim admission": {"disputed in window", withProof(func(proof *ClaimDecisionAdmissionReceiptProofV1) {
			proof.ReceiptBody.AuthorizedClaimAdmissionReceiptDigest = sizeTestDigest("1")
		}), "stands on another claim admission"},
		"disputed state revision": {"disputed in window", func(shape *fallbackShape) {
			shape.variant.SourceClaimStateRevision++
			shape.setRequest(t)
		}, "source state revision differs from its head"},
		"reviewing state revision": {"reviewing in window", func(shape *fallbackShape) {
			shape.variant.SourceClaimStateRevision++
			shape.setRequest(t)
		}, "source state revision differs from its head"},
		"reviewing expected challenge rounds": {"reviewing in window", func(shape *fallbackShape) {
			shape.variant.ExpectedChallengeRoundsUsed++
			shape.setRequest(t)
		}, "round counts differ from its head"},
		"disputed expected nonterminal rounds": {"disputed in window", func(shape *fallbackShape) {
			shape.variant.ExpectedNonterminalRoundsUsed++
			shape.setRequest(t)
		}, "round counts differ from its head"},
		"initial expected rounds": {"initial", func(shape *fallbackShape) {
			shape.variant.ExpectedNonterminalRoundsUsed = 1
			shape.setRequest(t)
		}, "round counts differ from its head"},
		"receipt rounds before": {"reviewing in window", func(shape *fallbackShape) {
			shape.receipt.Body.NonterminalRoundsUsedBefore++
		}, "round counts differ from its head"},
		"disputed does not consume its round": {"disputed in window", func(shape *fallbackShape) {
			shape.receipt.Body.NonterminalRoundsUsedAfter = shape.receipt.Body.NonterminalRoundsUsedBefore
		}, "round consumption is invalid"},
		"reviewing consumes a round": {"reviewing in window", func(shape *fallbackShape) {
			shape.receipt.Body.NonterminalRoundsUsedAfter = shape.receipt.Body.NonterminalRoundsUsedBefore + 1
		}, "round consumption is invalid"},
		"challenge count changes": {"initial", func(shape *fallbackShape) {
			shape.receipt.Body.ChallengeRoundsUsedAfter = shape.receipt.Body.ChallengeRoundsUsedBefore + 1
		}, "round consumption is invalid"},
		"disputed expects an open epoch": {"disputed in window", func(shape *fallbackShape) {
			shape.variant.ClaimRevisionEpochExpectation.ExpectedEpochState = "open"
			shape.setRequest(t)
		}, "must reuse its head's frozen revision epoch and cut"},
		"disputed cut not byte-identical": {"disputed in window", func(shape *fallbackShape) {
			shape.receipt.ClaimRevisionIngressCutProof.IngressCutoffUnix++
		}, "must reuse its head's frozen revision epoch and cut"},
		"disputed names another epoch": {"disputed late", func(shape *fallbackShape) {
			shape.variant.ClaimRevisionEpochExpectation.RevisionEpoch++
			shape.setRequest(t)
		}, "must reuse its head's frozen revision epoch and cut"},
		"disputed names another epoch state revision": {"disputed in window", func(shape *fallbackShape) {
			shape.variant.ClaimRevisionEpochExpectation.ExpectedEpochStateRevision++
			shape.setRequest(t)
		}, "must reuse its head's frozen revision epoch and cut"},
		"disputed moves the frozen high-water": {"disputed in window", func(shape *fallbackShape) {
			shape.receipt.Body.FrozenClaimRevisionIngressHighWater++
		}, "must reuse its head's frozen revision epoch and cut"},
		"disputed refreezes the epoch": {"disputed in window", func(shape *fallbackShape) {
			shape.receipt.Body.FrozenRevisionEpochStateRevision++
		}, "must reuse its head's frozen revision epoch and cut"},
		"late candidate's challenge expects an open epoch": {"reviewing after a late candidate", func(shape *fallbackShape) {
			shape.variant.ClaimRevisionEpochExpectation.ExpectedEpochState = "open"
			shape.setRequest(t)
		}, "must reuse its head's frozen revision epoch and cut"},
		"initial expects a frozen epoch": {"initial", func(shape *fallbackShape) {
			shape.variant.ClaimRevisionEpochExpectation.ExpectedEpochState = "frozen"
			shape.setRequest(t)
		}, "must freeze the open revision epoch"},
		"reviewing expects a frozen epoch": {"reviewing in window", func(shape *fallbackShape) {
			shape.variant.ClaimRevisionEpochExpectation.ExpectedEpochState = "frozen"
			shape.setRequest(t)
		}, "must freeze the open revision epoch"},
		"reviewing reuses an old cut": {"reviewing in window", func(shape *fallbackShape) {
			shape.variant.ClaimRevisionEpochExpectation.ExpectedEpochStateRevision++
			shape.setRequest(t)
		}, "must freeze the open revision epoch"},
		"disputed past its reserved rounds": {"disputed in window", func(shape *fallbackShape) {
			maximum := terms.ClaimClosureCapacity.MaximumNonterminalRoundsPerClaim
			withProof(func(proof *ClaimDecisionAdmissionReceiptProofV1) {
				proof.ReceiptBody.NonterminalRoundsUsedAfter = maximum
			})(shape)
			head := shape.receipt.CurrentDecisionAdmissionProof.ReceiptBody
			setFallbackHead(shape, head.AdmittedClaimStateRevision, head.ChallengeRoundsUsedAfter, head.NonterminalRoundsUsedAfter, true)
			shape.setRequest(t)
		}, "exceeds its reserved nonterminal rounds"},
	}
	for name, test := range mutations {
		shape := shapes[test.shape]
		// Copy every reference-bearing pointer so one mutation cannot leak
		// into another case.
		if descriptor := shape.variant.LateFilingCloseReceiptDescriptor; descriptor != nil {
			copied := *descriptor
			shape.variant.LateFilingCloseReceiptDescriptor = &copied
		}
		test.change(&shape)
		err := verifyFallbackShape(shape, terms, resolver)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, test.want)
		}
	}
}

func TestLateFilingCloseResolutionFailsClosed(t *testing.T) {
	terms := testCoverageTerms(t)
	measured := loadMeasuredDecisionReceipt(t)
	filing, wire, digest := fakeFilingCloseReceipt(t, measured, sizeTestDigest("7"))
	descriptor := lateFilingDescriptor(terms, digest, uint64(len(wire)))

	resolver := newEvidenceResolver()
	resolver.content[digest] = wire
	resolved, err := resolveLateFilingCloseReceiptV1(descriptor, terms, resolver)
	if err != nil || !equalCanonical(resolved, filing) || *resolver.calls != 1 {
		t.Fatalf("a held filing-close receipt did not resolve exactly once: calls=%d err=%v", *resolver.calls, err)
	}

	if _, err := resolveLateFilingCloseReceiptV1(descriptor, terms, allowAuthorityResolver{}); err == nil ||
		!strings.Contains(err.Error(), "no immutable evidence resolver") {
		t.Fatalf("resolution without a resolver did not fail closed: %v", err)
	}

	_, otherWire, otherDigest := fakeFilingCloseReceipt(t, measured, sizeTestDigest("8"))
	cases := map[string]struct {
		content []byte
		want    string
	}{
		"undecodable":     {append([]byte{0xff}, wire[1:]...), "undecodable"},
		"another receipt": {otherWire, "differs from its descriptor"},
	}
	for name, test := range cases {
		resolver := newEvidenceResolver()
		resolver.content[digest] = test.content
		size := descriptor
		size.ContentSize = uint64(len(test.content))
		if _, err := resolveLateFilingCloseReceiptV1(size, terms, resolver); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("%s: got %v, want an error containing %q", name, err, test.want)
		}
	}
	if otherDigest == digest {
		t.Fatal("the substituted filing-close receipt has the same digest")
	}
}

func TestDecisionAuthoritySubjectsFollowTheDecisionPath(t *testing.T) {
	terms := testCoverageTerms(t)
	terms.DecisionAuthoritySubjects = []string{"agent:ordinary-decider"}
	fallback := terms.ClaimClosureCapacity.TerminalFallback.FallbackAuthoritySubjects
	for _, path := range []string{"initial_terminal_fallback", "terminal_fallback", "late_recovery_terminal_fallback"} {
		if got := decisionAuthoritySubjectsForPathV1(terms, path); !equalStrings(got, fallback) {
			t.Fatalf("%s: selected %v, want the fallback set %v", path, got, fallback)
		}
	}
	for _, path := range []string{"initial", "successor"} {
		if got := decisionAuthoritySubjectsForPathV1(terms, path); !equalStrings(got, terms.DecisionAuthoritySubjects) {
			t.Fatalf("%s: selected %v, want the ordinary set", path, got)
		}
	}
}

// TestDecisionProofRefusesMixedModeAndPath covers the check that keeps the
// path-selected authority set honest: a proof cannot pair a fallback path
// with an authorized admission, or the reverse.
func TestDecisionProofRefusesMixedModeAndPath(t *testing.T) {
	terms := testCoverageTerms(t)
	measured := loadMeasuredDecisionReceipt(t)
	base := ClaimDecisionAdmissionReceiptProofV1{SchemaVersion: 1, ReceiptEnvelopeDigest: sizeTestDigest("3"),
		ReceiptDescriptor: ImmutableEvidenceDescriptorV1{ContentType: GuarantorMediaTypePrefixV1 + "claim-decision-admission.v1+cbor",
			ContentDigest: sizeTestDigest("3"), ContentSize: measuredDecisionReceiptBytes},
		ReceiptBody: measured.Body, CoverageEndCommitment: measured.CoverageEndCommitment,
		AuthorizedClaimDecision: measured.AuthorizedClaimDecision,
		AuthorizedClaim:         measured.AuthorizedClaimAdmissionReceipt.AuthorizedClaimIngressReceipt.AuthorizedClaim,
		ReceiptAuthorizations:   measured.Authorizations,
		SealBody: ClaimDecisionAdmissionReceiptSealBodyV1{SchemaVersion: 1, ReceiptEnvelopeDigest: sizeTestDigest("3"),
			SealedAtUnix: measured.Body.AdmittedAtUnix + 1},
		SealAuthorization: measured.Authorizations[0]}
	// Keep the proof's own bindings consistent so the mode/path check is the
	// first one to fail.
	rebind := func(proof ClaimDecisionAdmissionReceiptProofV1) ClaimDecisionAdmissionReceiptProofV1 {
		decisionDigest, err := ClaimDecisionDigestV1(proof.AuthorizedClaimDecision)
		if err != nil {
			t.Fatal(err)
		}
		claimDigest, _ := ClaimEnvelopeDigest(proof.AuthorizedClaim)
		bodyDigest, _ := Digest("tos.service.agent-guarantor-claim-decision-admission-receipt-body.v1", proof.ReceiptBody)
		endDigest, _ := CoverageEndCommitmentDigestV1(proof.CoverageEndCommitment)
		termsDigest, _ := CoverageTermsDigest(terms)
		proof.ReceiptBody.AuthorizedClaimDecisionDigest = decisionDigest
		proof.ReceiptBody.DecisionSequence = proof.AuthorizedClaimDecision.Body.DecisionSequence
		proof.ReceiptBody.ClaimID = proof.AuthorizedClaim.Body.ClaimID
		proof.ReceiptBody.CoverageAgreementBodyDigest = proof.AuthorizedClaim.Body.CoverageAgreementBodyDigest
		proof.ReceiptBody.CoverageObligationID = proof.AuthorizedClaim.Body.CoverageObligationID
		bodyDigest, _ = Digest("tos.service.agent-guarantor-claim-decision-admission-receipt-body.v1", proof.ReceiptBody)
		proof.SealBody.ReceiptBodyDigest = bodyDigest
		proof.SealBody.AuthorizedActionDigest = proof.ReceiptBody.AuthorizedActionDigest
		proof.SealBody.AuthorizedClaimDecisionDigest = decisionDigest
		proof.SealBody.AuthorizedClaimEnvelopeDigest = claimDigest
		proof.SealBody.CoverageEndCommitmentDigest = endDigest
		proof.SealBody.CoverageTermsDigest = termsDigest
		proof.ReceiptDescriptor.RetrievalPolicyDigest = terms.DecisionAdmissionProfile.ProfileDigest
		return proof
	}
	now := time.Unix(int64(base.SealBody.SealedAtUnix)+1, 0).UTC()
	cases := map[string]func(*ClaimDecisionAdmissionReceiptProofV1){
		"fallback path, authorized admission": func(proof *ClaimDecisionAdmissionReceiptProofV1) {
			proof.AuthorizedClaimDecision.Body.DecisionPath = "terminal_fallback"
			proof.ReceiptBody.AdmissionMode = "authorized_decision"
		},
		"ordinary path, fallback admission": func(proof *ClaimDecisionAdmissionReceiptProofV1) {
			proof.AuthorizedClaimDecision.Body.DecisionPath = "initial"
			proof.ReceiptBody.AdmissionMode = "deterministic_fallback"
		},
	}
	for name, change := range cases {
		proof := base
		change(&proof)
		proof = rebind(proof)
		err := VerifyClaimDecisionAdmissionReceiptProofV1(proof, terms, allowAuthorityResolver{}, now)
		if err == nil || !strings.Contains(err.Error(), "mixes its admission mode and decision path") {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	consistent := base
	consistent.AuthorizedClaimDecision.Body.DecisionPath = "terminal_fallback"
	consistent.ReceiptBody.AdmissionMode = "deterministic_fallback"
	consistent = rebind(consistent)
	err := VerifyClaimDecisionAdmissionReceiptProofV1(consistent, terms, allowAuthorityResolver{}, now)
	if err == nil || strings.Contains(err.Error(), "mixes its admission mode") || strings.Contains(err.Error(), "binding is invalid") {
		t.Fatalf("a consistent fallback proof did not get past its bindings to claim verification: %v", err)
	}
}

// TestLateRecoverySuccessorCarriesItsCandidateMarker covers the marker an
// authorized decision may carry in late_filing_close_receipt_digest: exactly
// its challenged late-recovery candidate's digest when it is that candidate's
// successor, and nothing otherwise.
func TestLateRecoverySuccessorCarriesItsCandidateMarker(t *testing.T) {
	terms := testCoverageTerms(t)
	now := time.Unix(2_000_000_100, 0).UTC()
	const refused = "late filing-close digest other than its late-recovery candidate's"
	successor := func() AuthorizedClaimDecisionAdmissionReceiptV1 {
		receipt := buildWorstCaseAuthorizedDecisionReceipt(t)
		receipt.AuthorizedClaimDecision.Body.DecisionPath = "successor"
		return receipt
	}
	lateSuccessor := func() AuthorizedClaimDecisionAdmissionReceiptV1 {
		receipt := successor()
		transition := *receipt.PredecessorClaimStateTransitionReceipt
		transition.DecisionAdmissionProof.AuthorizedClaimDecision.Body.DecisionPath = "late_recovery_terminal_fallback"
		transition.DecisionAdmissionProof.ReceiptBody.LateFilingCloseReceiptDigest = lateCandidateFilingDigest
		receipt.PredecessorClaimStateTransitionReceipt = &transition
		receipt.Body.LateFilingCloseReceiptDigest = lateCandidateFilingDigest
		return receipt
	}
	cases := map[string]struct {
		receipt func() AuthorizedClaimDecisionAdmissionReceiptV1
		refused bool
	}{
		"initial decision with a digest": {func() AuthorizedClaimDecisionAdmissionReceiptV1 {
			receipt := loadMeasuredDecisionReceipt(t)
			receipt.Body.LateFilingCloseReceiptDigest = lateCandidateFilingDigest
			return receipt
		}, true},
		"ordinary successor with a digest": {func() AuthorizedClaimDecisionAdmissionReceiptV1 {
			receipt := successor()
			receipt.Body.LateFilingCloseReceiptDigest = lateCandidateFilingDigest
			return receipt
		}, true},
		"late successor without its marker": {func() AuthorizedClaimDecisionAdmissionReceiptV1 {
			receipt := lateSuccessor()
			receipt.Body.LateFilingCloseReceiptDigest = ""
			return receipt
		}, true},
		"late successor with another marker": {func() AuthorizedClaimDecisionAdmissionReceiptV1 {
			receipt := lateSuccessor()
			receipt.Body.LateFilingCloseReceiptDigest = sizeTestDigest("1")
			return receipt
		}, true},
		"late successor with its marker":      {lateSuccessor, false},
		"ordinary successor without a digest": {successor, false},
	}
	for name, test := range cases {
		err := VerifyClaimDecisionAdmissionReceiptV1(test.receipt(), terms, permissiveAgreementVerifier{},
			allowAuthorityResolver{}, nil, now)
		if test.refused != (err != nil && strings.Contains(err.Error(), refused)) {
			t.Errorf("%s: refused=%v, got %v", name, test.refused, err)
		}
	}
}

// TestLateRecoveryPathAllowsOneChallengeRound: the successor of a challenged
// late-recovery candidate, authorized or fallback, cannot be challenged again,
// while the candidate itself, ordinary decisions and every successor's
// challenge close are unaffected.
func TestLateRecoveryPathAllowsOneChallengeRound(t *testing.T) {
	terms := testCoverageTerms(t)
	now := time.Unix(2_000_000_100, 0).UTC()
	const refused = "targets the late-recovery successor"
	base := *buildWorstCaseAuthorizedDecisionReceipt(t).PredecessorClaimStateTransitionReceipt
	transition := func(kind, path, lateDigest string) AuthorizedClaimStateTransitionReceiptV1 {
		receipt := base
		receipt.Body.TransitionKind = kind
		receipt.DecisionAdmissionProof.AuthorizedClaimDecision.Body.DecisionPath = path
		receipt.DecisionAdmissionProof.ReceiptBody.LateFilingCloseReceiptDigest = lateDigest
		return receipt
	}
	cases := map[string]struct {
		receipt AuthorizedClaimStateTransitionReceiptV1
		refused bool
	}{
		"challenge of the authorized late successor": {transition("challenge_admission", "successor", lateCandidateFilingDigest), true},
		"challenge of the fallback late successor":   {transition("challenge_admission", "terminal_fallback", lateCandidateFilingDigest), true},
		"challenge of the late candidate":            {transition("challenge_admission", "late_recovery_terminal_fallback", lateCandidateFilingDigest), false},
		"challenge of an ordinary successor":         {transition("challenge_admission", "successor", ""), false},
		"challenge of an ordinary fallback":          {transition("challenge_admission", "terminal_fallback", ""), false},
		"challenge close of the late successor":      {transition("challenge_close", "successor", lateCandidateFilingDigest), false},
	}
	for name, test := range cases {
		err := VerifyClaimStateTransitionReceiptV1(test.receipt, terms, permissiveAgreementVerifier{},
			allowAuthorityResolver{}, nil, now)
		if test.refused != (err != nil && strings.Contains(err.Error(), refused)) {
			t.Errorf("%s: refused=%v, got %v", name, test.refused, err)
		}
	}
}

// TestFirstRevisionMustNameItsPredecessorAsInitialAdmission: the first
// revision's predecessor is the initial admission, so a first revision naming
// any other initial admission is refused at admission verification, both as a
// complete receipt and as a compact proof. A later revision carries only its
// predecessor's digest, so this portable step does not apply to it.
func TestFirstRevisionMustNameItsPredecessorAsInitialAdmission(t *testing.T) {
	terms := testCoverageTerms(t)
	now := time.Unix(2_000_000_100, 0).UTC()
	const refused = "names an initial admission other than its predecessor"
	revision := loadMeasuredDecisionReceipt(t).AuthorizedClaimAdmissionReceipt
	if revision.Body.AdmissionKind != "revision" || revision.Body.AdmittedClaimRevision != 2 ||
		revision.Body.InitialClaimAdmissionReceiptDigest != revision.Body.PredecessorRevisionAdmissionReceiptDigest {
		t.Fatalf("the measured claim admission is not a consistent first revision: %+v", revision.Body)
	}
	verify := func(receipt AuthorizedClaimAdmissionReceiptV1) error {
		return VerifyClaimAdmissionReceiptV1(receipt, terms, permissiveAgreementVerifier{}, allowAuthorityResolver{}, nil, now)
	}
	if err := verify(revision); err != nil && strings.Contains(err.Error(), refused) {
		t.Fatalf("a consistent first revision was refused: %v", err)
	}
	other := revision
	other.Body.InitialClaimAdmissionReceiptDigest = sizeTestDigest("1")
	if err := verify(other); err == nil || !strings.Contains(err.Error(), refused) {
		t.Fatalf("a first revision naming another claim's initial admission was not refused: %v", err)
	}
	proof := testInitialAdmissionProof(revision)
	proof.ReceiptBody = other.Body
	if err := ValidateClaimAdmissionReceiptProofV1(proof, terms, allowAuthorityResolver{}, nil, now, false); err == nil ||
		!strings.Contains(err.Error(), refused) {
		t.Fatalf("a first-revision compact proof naming another initial admission was not refused: %v", err)
	}
	later := other.Body
	later.PriorClaimRevision, later.AdmittedClaimRevision, later.ClaimRevisionAdmissionSequence = 2, 3, 3
	if err := validateRevisionInitialAdmissionV1(later); err != nil {
		t.Fatalf("a later revision was held to the first revision's step: %v", err)
	}
}

// TestLateRecoveryClosureReservesOneChallengeRound: the late path allows one
// challenge round, so its closure check uses the one-round budget even when
// more rounds were negotiated, and the zero-round budget once they are used.
func TestLateRecoveryClosureReservesOneChallengeRound(t *testing.T) {
	const maximum, admittedAt = 3, 1_000_000
	entries, err := BuildClaimContinuationBudgetEntriesV1(maximum, 1, 600, 600, 600, 600, 600, 600)
	if err != nil {
		t.Fatal(err)
	}
	closure := map[uint64]uint64{}
	for _, entry := range entries {
		for r := uint64(0); r <= maximum; r++ {
			if entry.ProfileStateKey == "challengeable_candidate:r="+new(big.Int).SetUint64(r).String() {
				closure[r] = entry.MaximumRemainingClosureSeconds
			}
		}
	}
	if !(closure[0] < closure[1] && closure[1] < closure[maximum]) {
		t.Fatalf("budget closures do not grow with remaining rounds: %v", closure)
	}
	terms := testCoverageTerms(t)
	terms.ClaimClosureCapacity.MaximumChallengeRoundsPerClaim = maximum
	terms.ClaimClosureCapacity.ContinuationBudgetEntries = entries
	at := func(used, deadline uint64) error {
		terms.LateRecoveryTerminalDeadlineUnix = deadline
		return lateRecoveryClosureFitsV1(terms, used, admittedAt)
	}
	const refused = "cannot complete inside its reserved contingency window"
	cases := map[string]struct {
		used, deadline uint64
		want           string
	}{
		"no round used, one-round closure exactly fits": {0, admittedAt + closure[1], ""},
		"no round used, one second short":               {0, admittedAt + closure[1] - 1, refused},
		"two rounds used, one-round closure fits":       {maximum - 1, admittedAt + closure[1], ""},
		"every round used, zero-round closure fits":     {maximum, admittedAt + closure[0], ""},
		"every round used, one second short":            {maximum, admittedAt + closure[0] - 1, refused},
		"counter over the negotiated rounds":            {maximum + 1, admittedAt + closure[maximum], "exceeds its reserved capacity"},
		"deadline before admission":                     {0, admittedAt - 1, refused},
		"closure overflows the deadline arithmetic":     {0, ^uint64(0), ""},
	}
	for name, test := range cases {
		err := at(test.used, test.deadline)
		if test.want == "" && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, test.want)
		}
	}
	// A profile negotiating no challenge round keeps the zero-round closure.
	none, err := BuildClaimContinuationBudgetEntriesV1(0, 1, 600, 600, 600, 600, 600, 600)
	if err != nil {
		t.Fatal(err)
	}
	terms.ClaimClosureCapacity.MaximumChallengeRoundsPerClaim = 0
	terms.ClaimClosureCapacity.ContinuationBudgetEntries = none
	terms.LateRecoveryTerminalDeadlineUnix = admittedAt + closure[0]
	if err := lateRecoveryClosureFitsV1(terms, 0, admittedAt); err != nil {
		t.Fatalf("a zero-round profile was refused its zero-round closure: %v", err)
	}
}

// TestFallbackLateMarkerIsOneDerivationForBothBindings: the late filing-close
// digest a fallback without a late filing close must carry is derived once,
// for both the reference binding and the receipt binding of the deep verifier:
// the challenged late candidate's digest for the fallback at that candidate's
// successor deadline, and none for every other head. A unit test cannot reach
// the deep verifier's receipt binding, which runs after the signed claim
// admission check; the signed end-to-end run of this path is in OpenFox.
func TestFallbackLateMarkerIsOneDerivationForBothBindings(t *testing.T) {
	terms := testCoverageTerms(t)
	resolver := newEvidenceResolver()
	inWindow := func(shape fallbackShape) fallbackShape {
		shape.variant.LateFilingCloseReceiptDescriptor = nil
		shape.receipt.Body.LateFilingCloseReceiptDigest = ""
		shape.receipt.Body.DecisionPath, shape.receipt.AuthorizedClaimDecision.Body.DecisionPath = "terminal_fallback", "terminal_fallback"
		shape.setRequest(t)
		return shape
	}
	reviewing := inWindow(worstCaseReviewingLateFallback(t, terms))
	cases := map[string]struct {
		shape fallbackShape
		want  string
	}{
		"after a challenged late candidate": {reviewingAfterLateCandidate(t, reviewing), lateCandidateFilingDigest},
		"after an ordinary challenge":       {reviewing, ""},
		"from a disputed head":              {inWindow(worstCaseNonterminalLateFallback(t, terms)), ""},
		"initial":                           {measuredInitialFallback(t, terms), ""},
	}
	for name, test := range cases {
		source, err := bindDeterministicFallbackReferencesV1(test.shape.receipt, test.shape.variant, terms, resolver)
		if err != nil {
			t.Fatalf("%s: a well-formed fallback did not pass reference binding: %v", name, err)
		}
		if got := fallbackLateRecoveryMarkerV1(test.shape.variant, source); got != test.want ||
			got != test.shape.receipt.Body.LateFilingCloseReceiptDigest {
			t.Errorf("%s: marker %q, receipt carries %q, want %q", name, got,
				test.shape.receipt.Body.LateFilingCloseReceiptDigest, test.want)
		}
	}
}

// TestEveryRevisionAdmissionCarriesItsInitialAdmissionProof: a revision
// admission carries the compact proof of the initial admission it names, so
// any revision, not only the first, binds its initial digest on its own. The
// binding is refused before any signature is checked; an initial admission
// carries no proof.
func TestEveryRevisionAdmissionCarriesItsInitialAdmissionProof(t *testing.T) {
	terms := testCoverageTerms(t)
	now := time.Unix(2_000_000_100, 0).UTC()
	revision := loadMeasuredDecisionReceipt(t).AuthorizedClaimAdmissionReceipt
	verify := func(receipt AuthorizedClaimAdmissionReceiptV1) error {
		return VerifyClaimAdmissionReceiptV1(receipt, terms, permissiveAgreementVerifier{}, allowAuthorityResolver{}, nil, now)
	}
	// A third revision names an initial admission that is not its
	// predecessor; only the carried proof can bind it.
	third := revision
	third.Body.PriorClaimRevision, third.Body.AdmittedClaimRevision, third.Body.ClaimRevisionAdmissionSequence = 2, 3, 3
	third.Body.PredecessorRevisionAdmissionReceiptDigest = sizeTestDigest("8")
	withProof := func(base AuthorizedClaimAdmissionReceiptV1, change func(*ClaimAdmissionReceiptProofV1)) AuthorizedClaimAdmissionReceiptV1 {
		proof := *base.InitialClaimAdmissionProof
		change(&proof)
		base.InitialClaimAdmissionProof = &proof
		return base
	}
	const notInitial = "is not the claim's initial admission"
	initial := revision
	initial.Body.AdmissionKind = "initial"
	initial.Body.InitialClaimAdmissionReceiptDigest, initial.Body.PredecessorRevisionAdmissionReceiptDigest = "", ""
	withoutProof := third
	withoutProof.InitialClaimAdmissionProof = nil
	cases := map[string]struct {
		receipt AuthorizedClaimAdmissionReceiptV1
		want    string
	}{
		"third revision without the proof": {withoutProof, "lacks its initial claim admission proof"},
		"third revision naming another claim's initial admission": {func() AuthorizedClaimAdmissionReceiptV1 {
			other := third
			other.Body.InitialClaimAdmissionReceiptDigest = sizeTestDigest("1")
			return other
		}(), notInitial},
		"third revision carrying another claim's proof": {withProof(third, func(p *ClaimAdmissionReceiptProofV1) {
			p.ReceiptBody.ClaimID = sizeTestDigest("2")
		}), notInitial},
		"third revision carrying a proof on another Agreement": {withProof(third, func(p *ClaimAdmissionReceiptProofV1) {
			p.ReceiptBody.CoverageAgreementBodyDigest = sizeTestDigest("3")
		}), notInitial},
		"third revision carrying a proof on another obligation": {withProof(third, func(p *ClaimAdmissionReceiptProofV1) {
			p.ReceiptBody.CoverageObligationID = "obligation:other"
		}), notInitial},
		"third revision carrying a revision's proof": {withProof(third, func(p *ClaimAdmissionReceiptProofV1) {
			p.ReceiptBody.AdmissionKind = "revision"
		}), notInitial},
		"initial admission carrying a proof": {initial, "an initial Guarantor claim admission carries an initial claim admission proof"},
	}
	for name, test := range cases {
		if err := verify(test.receipt); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, test.want)
		}
	}
	// A consistent third revision passes the binding; it is refused later,
	// at a check that needs the signed history.
	if err := verify(third); err == nil || strings.Contains(err.Error(), "initial claim admission proof") ||
		strings.Contains(err.Error(), "initial admission other than its predecessor") {
		t.Fatalf("a consistent third revision was refused at its initial-admission binding: %v", err)
	}
}

// TestLateRecoveryDeadlinesFollowTheDerivation: section 13 derives
// "late_ingress_recovery_deadline_unix = checked_sub(late_recovery_terminal_deadline_unix,
// late_recovery_candidate_closure_seconds)" and "terminal_resolution_deadline_unix =
// checked_sub(late_ingress_recovery_deadline_unix, late_ingress_recovery_window_seconds)",
// with "late_ingress_recovery_window_seconds is positive", and without the
// contingency "all three late-recovery fields are forbidden". Terms validation
// holds the terms to that exactly.
func TestLateRecoveryDeadlinesFollowTheDerivation(t *testing.T) {
	base := testCoverageTerms(t)
	closure := lateRecoveryCandidateClosureSecondsV1(base, 0)
	if closure == 0 {
		t.Fatal("the test terms reserve no one-round late closure")
	}
	fit := base
	fit.LateIngressRecoveryWindowSeconds = 300
	fit.LateIngressRecoveryDeadlineUnix = fit.TerminalResolutionDeadlineUnix + 300
	fit.LateRecoveryTerminalDeadlineUnix = fit.LateIngressRecoveryDeadlineUnix + closure
	const refused = "late-recovery deadlines differ from the late-ingress window and the one-round late closure"
	cases := map[string]struct {
		change func(*CoverageTermsV1)
		want   string
	}{
		"exact derivation": {func(*CoverageTermsV1) {}, ""},
		"no late-recovery contingency": {func(terms *CoverageTermsV1) {
			terms.LateIngressRecoveryDeadlineUnix, terms.LateRecoveryTerminalDeadlineUnix = 0, 0
			terms.LateIngressRecoveryWindowSeconds = 0
		}, ""},
		"no contingency but a late-ingress window": {func(terms *CoverageTermsV1) {
			terms.LateIngressRecoveryDeadlineUnix, terms.LateRecoveryTerminalDeadlineUnix = 0, 0
		}, "without a late-recovery contingency carry a late-ingress window"},
		"late terminal deadline one second early": {func(terms *CoverageTermsV1) {
			terms.LateRecoveryTerminalDeadlineUnix--
		}, refused},
		"late terminal deadline one second late": {func(terms *CoverageTermsV1) {
			terms.LateRecoveryTerminalDeadlineUnix++
		}, refused},
		"late-ingress window one second short": {func(terms *CoverageTermsV1) {
			terms.LateIngressRecoveryWindowSeconds--
		}, refused},
		"late-ingress window one second long": {func(terms *CoverageTermsV1) {
			terms.LateIngressRecoveryWindowSeconds++
		}, refused},
		"zero late-ingress window with the deadlines set": {func(terms *CoverageTermsV1) {
			terms.LateIngressRecoveryWindowSeconds = 0
			terms.LateIngressRecoveryDeadlineUnix = terms.TerminalResolutionDeadlineUnix
			terms.LateRecoveryTerminalDeadlineUnix = terms.LateIngressRecoveryDeadlineUnix + closure
		}, refused},
		"only the terminal deadline set": {func(terms *CoverageTermsV1) {
			terms.LateIngressRecoveryDeadlineUnix = 0
		}, refused},
		"only the ingress deadline set": {func(terms *CoverageTermsV1) {
			terms.LateRecoveryTerminalDeadlineUnix = 0
		}, refused},
	}
	for name, test := range cases {
		terms := fit
		test.change(&terms)
		err := validateLateRecoveryDeadlinesV1(terms)
		if test.want == "" && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
			t.Errorf("%s: got %v, want %q", name, err, test.want)
		}
	}
	// With several negotiated rounds the reservation is still one round.
	many := fit
	entries, err := BuildClaimContinuationBudgetEntriesV1(3, 1, 600, 600, 600, 600, 600, 600)
	if err != nil {
		t.Fatal(err)
	}
	many.ClaimClosureCapacity.MaximumChallengeRoundsPerClaim = 3
	many.ClaimClosureCapacity.ContinuationBudgetEntries = entries
	oneRound := lateRecoveryCandidateClosureSecondsV1(many, 0)
	many.LateRecoveryTerminalDeadlineUnix = many.LateIngressRecoveryDeadlineUnix + oneRound
	if err := validateLateRecoveryDeadlinesV1(many); err != nil {
		t.Fatalf("terms reserving the one-round closure with three negotiated rounds were refused: %v", err)
	}
	// ValidateCoverageTerms applies the check.
	short := fit
	short.LateRecoveryTerminalDeadlineUnix--
	if err := ValidateCoverageTerms(short); err == nil || !strings.Contains(err.Error(), refused) {
		t.Fatalf("coverage terms one second short of the late closure were not refused: %v", err)
	}
}

// TestCoverageDeadlinesAnchorAtTheHardEffectDeadline: section 13 derives
// "hard_effect_deadline = if unsecured: agreement.expires_at otherwise:
// min(agreement.expires_at, checked_sub(collateral_terms.lock_until_unix,
// collateral_terms.reorg_window_seconds))" and
// "late_recovery_terminal_deadline_unix = hard_effect_deadline"; without the
// late contingency "the ordinary deadline equals hard_effect_deadline".
func TestCoverageDeadlinesAnchorAtTheHardEffectDeadline(t *testing.T) {
	base := testCoverageTerms(t)
	const refused = "final deadline differs from the hard-effect deadline"
	none := base
	late := base
	late.LateIngressRecoveryWindowSeconds = 300
	late.LateIngressRecoveryDeadlineUnix = late.TerminalResolutionDeadlineUnix + 300
	late.LateRecoveryTerminalDeadlineUnix = late.LateIngressRecoveryDeadlineUnix + lateRecoveryCandidateClosureSecondsV1(late, 0)
	collateralized := late
	collateralized.SelectedAssuranceLevel = AssuranceCollateralAttested
	collateralized.CollateralTerms = &CollateralTermsV1{LockUntilUnix: late.LateRecoveryTerminalDeadlineUnix + 60, ReorgWindowSeconds: 60}
	cases := map[string]struct {
		terms     CoverageTermsV1
		expiresAt uint64
		want      string
	}{
		"no contingency, ordinary deadline at the Agreement's expiry": {none, none.TerminalResolutionDeadlineUnix, ""},
		"no contingency, expiry one second later":                     {none, none.TerminalResolutionDeadlineUnix + 1, refused},
		"no contingency, expiry one second earlier":                   {none, none.TerminalResolutionDeadlineUnix - 1, refused},
		"late contingency, late deadline at the Agreement's expiry":   {late, late.LateRecoveryTerminalDeadlineUnix, ""},
		"late contingency, expiry one second later":                   {late, late.LateRecoveryTerminalDeadlineUnix + 1, refused},
		"late contingency anchored at the ordinary deadline":          {late, late.TerminalResolutionDeadlineUnix, refused},
		"collateral lock bounds the anchor":                           {collateralized, collateralized.LateRecoveryTerminalDeadlineUnix + 3600, ""},
		"collateral lock one second short": {func() CoverageTermsV1 {
			short := collateralized
			lock := *short.CollateralTerms
			lock.LockUntilUnix--
			short.CollateralTerms = &lock
			return short
		}(), collateralized.LateRecoveryTerminalDeadlineUnix + 3600, refused},
		// Section 12.2: "collateral_terms.lock_until_unix <= agreement.expires_at".
		"Agreement expiring when the collateral lock ends": {collateralized, collateralized.CollateralTerms.LockUntilUnix, ""},
		"Agreement expiring one second before the collateral lock ends": {collateralized,
			collateralized.CollateralTerms.LockUntilUnix - 1, "Guarantor collateral lock ends after the coverage Agreement expires"},
	}
	for name, test := range cases {
		err := validateCoverageDeadlineAnchorV1(test.terms, test.expiresAt)
		if test.want == "" && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
			t.Errorf("%s: got %v, want %q", name, err, test.want)
		}
	}
}

// TestTerminalClaimSetBindsEveryRevisionToItsInitialAdmission: a terminal
// bundle's admission proofs start with the initial admission, and every
// revision proof names that initial admission and its claim, Agreement and
// obligation, and the proof before it as its predecessor. The binding is
// checked before any signature.
func TestTerminalClaimSetBindsEveryRevisionToItsInitialAdmission(t *testing.T) {
	revision := loadMeasuredDecisionReceipt(t).AuthorizedClaimAdmissionReceipt
	initial := *revision.InitialClaimAdmissionProof
	proofOf := func(body ClaimAdmissionReceiptBodyV1, envelope string) ClaimAdmissionReceiptProofV1 {
		proof := initial
		proof.ReceiptBody, proof.ReceiptEnvelopeDigest = body, envelope
		proof.ReceiptDescriptor.ContentDigest = envelope
		return proof
	}
	second := revision.Body
	second.PredecessorRevisionAdmissionReceiptDigest = initial.ReceiptEnvelopeDigest
	third := second
	third.PriorClaimRevision, third.AdmittedClaimRevision, third.ClaimRevisionAdmissionSequence = 2, 3, 3
	third.PredecessorRevisionAdmissionReceiptDigest = sizeTestDigest("8")
	chain := func(change func(*ClaimAdmissionReceiptBodyV1)) []ClaimAdmissionReceiptProofV1 {
		changed := third
		change(&changed)
		return []ClaimAdmissionReceiptProofV1{initial, proofOf(second, sizeTestDigest("8")), proofOf(changed, sizeTestDigest("9"))}
	}
	const otherInitial = "names another initial admission or claim"
	cases := map[string]struct {
		admissions []ClaimAdmissionReceiptProofV1
		want       string
	}{
		"initial, second and third revision": {chain(func(*ClaimAdmissionReceiptBodyV1) {}), ""},
		"initial only":                       {[]ClaimAdmissionReceiptProofV1{initial}, ""},
		"third revision naming another initial admission": {chain(func(body *ClaimAdmissionReceiptBodyV1) {
			body.InitialClaimAdmissionReceiptDigest = sizeTestDigest("1")
		}), otherInitial},
		"third revision of another claim": {chain(func(body *ClaimAdmissionReceiptBodyV1) {
			body.ClaimID = sizeTestDigest("2")
		}), otherInitial},
		"third revision on another Agreement": {chain(func(body *ClaimAdmissionReceiptBodyV1) {
			body.CoverageAgreementBodyDigest = sizeTestDigest("3")
		}), otherInitial},
		"third revision on another obligation": {chain(func(body *ClaimAdmissionReceiptBodyV1) {
			body.CoverageObligationID = "obligation:other"
		}), otherInitial},
		"third revision with another predecessor": {chain(func(body *ClaimAdmissionReceiptBodyV1) {
			body.PredecessorRevisionAdmissionReceiptDigest = sizeTestDigest("4")
		}), "chain is broken"},
		"a revision first": {[]ClaimAdmissionReceiptProofV1{proofOf(second, sizeTestDigest("8"))},
			"does not start with the initial admission"},
		"empty": {nil, "does not start with the initial admission"},
	}
	for name, test := range cases {
		err := bindTerminalClaimAdmissionChainV1(test.admissions)
		if test.want == "" && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
			t.Errorf("%s: got %v, want %q", name, err, test.want)
		}
	}
}
