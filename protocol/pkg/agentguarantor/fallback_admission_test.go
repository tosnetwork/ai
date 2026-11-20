package agentguarantor

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/codec"
)

// Exact canonical sizes of the fallback receipts built below from the
// measured ML-DSA-44 receipt. They move only with a deliberate wire change.
const (
	measuredFallbackRequestBytes         = 1_210
	measuredFallbackReceiptBytes         = 1_069_384
	measuredEmbeddedFallbackReceiptBytes = 2_451_938
	worstCaseReviewingFallbackBytes      = 1_512_852
	worstCaseNonterminalFallbackBytes    = 1_483_046
	worstCaseFallbackRequestBytes        = 1_782
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

// reviewingAfterLateCandidate is a fallback from a reviewing head whose
// challenged decision was a late-recovery candidate: that challenge left the
// epoch frozen, so the fallback reuses the candidate's epoch and cut.
func reviewingAfterLateCandidate(t *testing.T, reviewing fallbackShape) fallbackShape {
	t.Helper()
	shape := reviewing
	transition := *shape.receipt.PredecessorClaimStateTransitionReceipt
	transition.DecisionAdmissionProof.AuthorizedClaimDecision.Body.DecisionPath = "late_recovery_terminal_fallback"
	cutDigest, err := ClaimIngressAdmissionCutProofDigestV1(shape.receipt.ClaimRevisionIngressCutProof)
	if err != nil {
		t.Fatal(err)
	}
	transition.DecisionAdmissionProof.ReceiptBody.ClaimRevisionIngressCutProofDigest = cutDigest
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
	t.Logf("worst-case fallback: reviewing %d bytes (margin %d, %.1f%%), disputed %d bytes, request %d bytes",
		reviewingSize, MaxCanonicalObjectBytes-reviewingSize,
		100*float64(MaxCanonicalObjectBytes-reviewingSize)/float64(MaxCanonicalObjectBytes), nonterminalSize, request)
	if reviewingSize != worstCaseReviewingFallbackBytes || nonterminalSize != worstCaseNonterminalFallbackBytes ||
		request != worstCaseFallbackRequestBytes {
		t.Fatalf("worst-case fallback is reviewing %d / disputed %d / request %d bytes, want %d / %d / %d",
			reviewingSize, nonterminalSize, request, worstCaseReviewingFallbackBytes,
			worstCaseNonterminalFallbackBytes, worstCaseFallbackRequestBytes)
	}
	// The reviewing shape is the larger, and it must leave at least a fifth of
	// the ceiling for profile variation.
	if reviewingSize < nonterminalSize || MaxCanonicalObjectBytes-reviewingSize < MaxCanonicalObjectBytes/5 {
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
	filing := AuthorizedClaimFilingCloseReceiptV1{Body: ClaimFilingCloseReceiptBodyV1{SchemaVersion: 1,
		CoverageAgreementBodyDigest: receipt.Body.CoverageAgreementBodyDigest,
		CoverageObligationID:        receipt.Body.CoverageObligationID, FrozenClaimAdmissionLogRoot: root},
		AuthorizedActivationEvidence: &activation, Authorizations: receipt.Authorizations[:1]}
	return encodeFilingClose(t, filing)
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
		"late digest without a descriptor": {"reviewing in window", func(shape *fallbackShape) {
			shape.receipt.Body.LateFilingCloseReceiptDigest = sizeTestDigest("1")
		}, "names a late filing-close receipt"},
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
