package agentguarantor

import (
	"strings"
	"testing"
)

// Values a verifier cannot read: an amount that is not a decimal number, an
// object whose digest cannot be computed, a token that cannot be digested.
// Each must be refused where it is met. None may be treated as zero, as an
// absent digest that equals an absent field, or crash the verifier.

// TestSignedHistoryTerminalClaimSetRefusesAnUnreadableApprovedAmount: the
// shape validation of a terminal claim set, which runs before any signature
// is checked, sums the approved amounts of its bundles. A terminal decision
// whose approved amount is empty, not decimal or negative is refused there.
func TestSignedHistoryTerminalClaimSetRefusesAnUnreadableApprovedAmount(t *testing.T) {
	chain := newLateChain(t, lateChainOptions{unchallenged: true})
	history := chain.history
	honest := chain.bundle()
	set := func(bundle ClaimTerminalResolutionBundleV1) AuthorizedTerminalClaimSetEvidenceV1 {
		return history.terminalSet(chain.filing, []ClaimTerminalResolutionBundleV1{bundle}, chain.closedAt)
	}
	if err := ValidateTerminalClaimSetV1(set(honest)); err != nil {
		t.Fatalf("the honest set does not pass the shape validation: %v", err)
	}
	for _, amount := range []string{"", "x", "-1", "0x10", "1e3", " 1", "1.0"} {
		bundle := honest
		bundle.TerminalAuthorizedDecision.Body.ApprovedAmount.AmountAtomic = amount
		bundle.ResolutionRef = history.terminalRef(bundle)
		varied := set(bundle)
		refusedFor(t, "approved amount "+strings.TrimSpace("\""+amount+"\""), ValidateTerminalClaimSetV1(varied),
			"terminal claim approved amount is invalid")
		if err := history.verifyTerminalSet(varied, chain.closedAt); err == nil {
			t.Errorf("approved amount %q: the set verifies", amount)
		}
	}
}

// TestSignedHistoryTerminalClaimSetRefusesAnUndigestableMember: a bundle
// member whose digest cannot be computed is refused, even when the reference
// leaves the matching digest empty. An empty computed digest used to equal
// the empty reference field.
func TestSignedHistoryTerminalClaimSetRefusesAnUndigestableMember(t *testing.T) {
	chain := newLateChain(t, lateChainOptions{unchallenged: true})
	history := chain.history
	honest := chain.bundle()
	const want = "terminal claim bundle member cannot be digested"

	claim := honest
	claim.RevisionAdmissionReceiptProofs = append([]ClaimAdmissionReceiptProofV1(nil), honest.RevisionAdmissionReceiptProofs...)
	final := &claim.RevisionAdmissionReceiptProofs[len(claim.RevisionAdmissionReceiptProofs)-1]
	final.AuthorizedClaimIngressReceipt.AuthorizedClaim.Body.EvidenceManifestDigest = testDigest("7")
	if _, err := ClaimEnvelopeDigest(final.AuthorizedClaimIngressReceipt.AuthorizedClaim); err == nil {
		t.Fatal("the varied claim still has a digest")
	}
	claim.ResolutionRef.TerminalAuthorizedClaimEnvelopeDigest = ""

	payouts := honest
	payouts.TerminalPayoutEvidenceSet.SchemaVersion = 2
	if _, err := TerminalPayoutEvidenceSetDigestV1(payouts.TerminalPayoutEvidenceSet); err == nil {
		t.Fatal("the varied terminal payout evidence set still has a digest")
	}
	payouts.ResolutionRef.TerminalPayoutEvidenceSetDigest = ""

	for name, bundle := range map[string]ClaimTerminalResolutionBundleV1{
		"a final claim without a digest":                  claim,
		"a terminal payout evidence set without a digest": payouts,
	} {
		set := history.terminalSet(chain.filing, []ClaimTerminalResolutionBundleV1{bundle}, chain.closedAt)
		refusedFor(t, name, ValidateTerminalClaimSetV1(set), want)
	}
}

// TestSignedHistoryRefusesAPriorTokenItCannotDigest: the decision that follows
// a challenge replaces the challenged decision's pending application token and
// names that token's digest. It verifies as the authorized successor and as
// the fallback at the successor deadline. When the challenged decision's token
// cannot be digested (its revision is zero) and the follower leaves the digest
// absent, both are refused: an uncomputable digest is not an absent one.
func TestSignedHistoryRefusesAPriorTokenItCannotDigest(t *testing.T) {
	for _, test := range []struct {
		name         string
		undigestable bool
		successor    string
		fallback     string
	}{
		{name: "a pending token"},
		{name: "a token that cannot be digested", undigestable: true,
			successor: "successor prior application token digest differs",
			fallback:  "claim decision fallback prior token terminalization is invalid"},
	} {
		history := newSignedHistory(t)
		withSignedHistorySeam(t, history)
		claim := history.claim(1, nil, signedHistoryStart+30)
		history.admit(claim, signedHistoryStart+40)
		claimID := claim.Body.ClaimID
		if test.undigestable {
			history.vary = varyAdmission(func(body *ClaimDecisionAdmissionReceiptBodyV1) {
				body.ResultingApplicationToken.TokenRevision = 0
			})
		}
		history.decide(claimID, history.terms.PayoutDeadlineSeconds, signedHistoryStart+100)
		history.vary = signedHistoryVariation{}
		challenge := history.challenge(claimID, signedHistoryStart+200)
		due := challenge.Body.SuccessorDecisionDueAtUnix
		restore := history.checkpoint(claimID)
		successor := history.decide(claimID, history.terms.PayoutDeadlineSeconds, signedHistoryStart+300)
		successorVerdict := history.verifyDecisionAdmission(successor, signedHistoryStart+300)
		restore()
		fallback := history.fallback(claimID, nil, due)
		fallbackVerdict := history.verifyDecisionAdmission(fallback, due)
		if !test.undigestable {
			if successorVerdict != nil {
				t.Errorf("%s: the authorized successor is refused: %v", test.name, successorVerdict)
			}
			if fallbackVerdict != nil {
				t.Errorf("%s: the fallback at the successor deadline is refused: %v", test.name, fallbackVerdict)
			}
			continue
		}
		if successor.Body.PriorApplicationTokenDigest != "" || fallback.Body.PriorApplicationTokenDigest != "" {
			t.Fatalf("%s: a follower names a prior token digest", test.name)
		}
		refusedFor(t, test.name+", authorized successor", successorVerdict, test.successor)
		refusedFor(t, test.name+", fallback", fallbackVerdict, test.fallback)
	}
}
