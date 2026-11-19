package purchaseevidence_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/internal/purchasefixture"
	"github.com/tosnetwork/ai/protocol/pkg/purchaseevidence"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

func newPurchase(t *testing.T) *purchasefixture.Purchase {
	t.Helper()
	purchase, err := purchasefixture.New()
	if err != nil {
		t.Fatal(err)
	}
	return purchase
}

func newSession(t *testing.T, purchase *purchasefixture.Purchase, outcome string) *purchasefixture.Session {
	t.Helper()
	session, err := purchase.Session(outcome)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func baseInput(purchase *purchasefixture.Purchase) purchaseevidence.Input {
	return purchaseevidence.Input{Network: purchase.Network, ActorCodeHash: purchasefixture.ActorCodeHash,
		Actor: purchasefixture.Actor, RequestHashes: []string{hex.EncodeToString(purchase.RequestHash[:])}}
}

func bundleInput(purchase *purchasefixture.Purchase, bundle *purchaseevidence.Bundle) purchaseevidence.Input {
	input := baseInput(purchase)
	input.Bundle = bundle
	return input
}

func run(session purchaseevidence.Session, input purchaseevidence.Input) *purchaseevidence.Verdict {
	return purchaseevidence.Verify(context.Background(), session, input)
}

// requirePass fails the test unless the verdict passed.
func requirePass(t *testing.T, verdict *purchaseevidence.Verdict) {
	t.Helper()
	if verdict.Result != purchaseevidence.ResultPass {
		raw, _ := json.MarshalIndent(verdict.Checks, "", " ")
		t.Fatalf("the verdict failed:\n%s", raw)
	}
}

// requireFailed fails the test unless the verdict failed and check id is
// among its failing checks.
func requireFailed(t *testing.T, verdict *purchaseevidence.Verdict, id string) {
	t.Helper()
	if verdict.Result != purchaseevidence.ResultFail {
		t.Fatalf("the verdict passed; want check %s to fail", id)
	}
	for _, check := range verdict.Checks {
		if check.ID == id && !check.OK {
			return
		}
	}
	raw, _ := json.MarshalIndent(verdict.Checks, "", " ")
	t.Fatalf("check %s did not fail:\n%s", id, raw)
}

// respondedWith serves the responded purchase whose finalized
// response_hash is the hash of a Receipt built with edit applied, and
// returns that Receipt.
func respondedWith(t *testing.T, purchase *purchasefixture.Purchase,
	edit func(*railwork.ReceiptBinding, *railwork.Outcome)) (*purchasefixture.Session, []byte) {
	t.Helper()
	binding := railwork.ReceiptBinding{QuoteCommitment: purchase.QuoteCommitment, ExecutionID: purchase.ExecutionID,
		InputDigest: purchase.InputDigest, SourceDigest: purchase.SourceDigest, Price: new(big.Int).Set(purchase.Policy.PricePerCall),
		ProviderAgentID: purchasefixture.ProviderAgentID, ToolchainDigest: purchase.Manifest.ToolchainDigest,
		SandboxDigest: purchase.ManifestDigest}
	outcome := railwork.Outcome{ResultDigest: sha(purchase.Output), ArtifactDigest: sha(purchase.Artifact),
		ReportDigest: sha(purchase.Report), CompletedAtUnix: 1_999_999_000}
	edit(&binding, &outcome)
	root, hash, err := railwork.BuildReceipt(binding, outcome)
	if err != nil {
		t.Fatal(err)
	}
	session := newSession(t, purchase, purchasefixture.Responded)
	session.Transactions[0].ResponseHash = hex.EncodeToString(hash[:])
	return session, root.ToBOC()
}

func hex64(pair string) string { return strings.Repeat(pair, 32) }

func sha(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Every outcome of a request is reported from finalized state with its
// transactions, and a responded request's Receipt, artifact and bundle all
// verify.
func TestVerifyReportsEveryOutcome(t *testing.T) {
	purchase := newPurchase(t)
	for _, outcome := range []string{purchasefixture.Pending, purchasefixture.Responded, purchasefixture.Refunded,
		purchasefixture.Swept, purchasefixture.Refused} {
		t.Run(outcome, func(t *testing.T) {
			verdict := run(newSession(t, purchase, outcome), baseInput(purchase))
			requirePass(t, verdict)
			if len(verdict.Requests) != 1 {
				t.Fatalf("%d requests reported", len(verdict.Requests))
			}
			request := verdict.Requests[0]
			wantState := map[string]string{purchasefixture.Pending: "pending", purchasefixture.Responded: "responded",
				purchasefixture.Refunded: "refunded", purchasefixture.Swept: "swept", purchasefixture.Refused: "refused"}[outcome]
			if request.State != wantState || request.Caller != purchasefixture.Buyer || request.Call.QueryID != "4242" {
				t.Fatalf("report %+v", request)
			}
			switch outcome {
			case purchasefixture.Responded:
				if request.Respond == nil || request.ProviderWallet != purchasefixture.Owner ||
					request.ResponseHash != hex.EncodeToString(purchase.ResponseHash[:]) {
					t.Fatalf("respond not reported: %+v", request)
				}
			case purchasefixture.Refunded:
				if request.Expire == nil || request.ClaimRefund == nil || request.ClaimRefund.Destination != purchasefixture.Buyer ||
					len(request.ClaimRefund.Payouts) != 1 {
					t.Fatalf("refund not reported: %+v", request)
				}
			case purchasefixture.Swept:
				if request.Sweep == nil {
					t.Fatalf("sweep not reported: %+v", request)
				}
			case purchasefixture.Pending:
				if request.PriceNanoTOS != purchase.Policy.PricePerCall.String() ||
					request.StorageFeeNanoTOS != purchase.Policy.StorageFee.String() {
					t.Fatalf("terms not reported: %+v", request)
				}
			}
			if verdict.Actor == nil || !verdict.Actor.CodeHashMatches || verdict.Checkpoint.BlockRoot == "" {
				t.Fatalf("actor or checkpoint not reported: %+v %+v", verdict.Actor, verdict.Checkpoint)
			}
		})
	}
	t.Run("responded with files and bundle", func(t *testing.T) {
		input := bundleInput(purchase, purchase.Bundle(true))
		input.Receipt, input.Artifact = purchase.Receipt, purchase.Artifact
		verdict := run(newSession(t, purchase, purchasefixture.Responded), input)
		requirePass(t, verdict)
		request := verdict.Requests[0]
		if request.Receipt == nil || request.Artifact == nil || len(request.Artifact.Members) != 2 {
			t.Fatalf("files not reported: %+v", request)
		}
		for _, id := range []string{"bundle-binding", "receipt-binding", "artifact-members", "bundle-result"} {
			found := false
			for _, check := range verdict.Checks {
				found = found || check.ID == id && check.OK
			}
			if !found {
				t.Fatalf("check %s did not run", id)
			}
		}
	})
	t.Run("by request ID", func(t *testing.T) {
		input := baseInput(purchase)
		input.RequestHashes, input.RequestIDs = nil, []uint64{0}
		requirePass(t, run(newSession(t, purchase, purchasefixture.Responded), input))
	})
}

// An actor that does not run the pinned release, or that does not read, is
// never verified.
func TestVerifyRefusesAnotherActorRelease(t *testing.T) {
	purchase := newPurchase(t)
	session := newSession(t, purchase, purchasefixture.Responded)
	session.CodeHash = "tvm-cell-sha256:" + strings.Repeat("99", 32)
	requireFailed(t, run(session, baseInput(purchase)), "actor-code-hash")
	session = newSession(t, purchase, purchasefixture.Responded)
	session.ReadErr = errors.New("quorum not reached")
	requireFailed(t, run(session, baseInput(purchase)), "actor-account")
}

// A history that is not complete up to the account's last transaction is
// never replayed.
func TestVerifyRefusesAnIncompleteHistory(t *testing.T) {
	purchase := newPurchase(t)
	session := newSession(t, purchase, purchasefixture.Responded)
	session.HistoryResult = toschain.HistoryAnchorReached
	requireFailed(t, run(session, baseInput(purchase)), "actor-history")
}

// A history that does not reconcile with the actor state is refused.
func TestVerifyRefusesAHistoryThatDoesNotReconcile(t *testing.T) {
	purchase := newPurchase(t)
	session := newSession(t, purchase, purchasefixture.Responded)
	session.Data.NextRequestID = 2
	requireFailed(t, run(session, baseInput(purchase)), "actor-replay")
}

// Getters that disagree with the decoded state are refused.
func TestVerifyRefusesLyingGetters(t *testing.T) {
	purchase := newPurchase(t)
	session := newSession(t, purchase, purchasefixture.Pending)
	session.GetterLie = true
	requireFailed(t, run(session, baseInput(purchase)), "request-getters")
}

// A selector that names no finalized request, or names one twice, fails.
func TestVerifyRefusesAnUnknownRequest(t *testing.T) {
	purchase := newPurchase(t)
	input := baseInput(purchase)
	input.RequestHashes, input.RequestIDs = nil, []uint64{5}
	requireFailed(t, run(newSession(t, purchase, purchasefixture.Responded), input), "request-selected")
	input = baseInput(purchase)
	input.RequestHashes = []string{strings.Repeat("ee", 32)}
	requireFailed(t, run(newSession(t, purchase, purchasefixture.Responded), input), "request-selected")
	input = baseInput(purchase)
	input.RequestIDs = []uint64{0}
	requireFailed(t, run(newSession(t, purchase, purchasefixture.Responded), input), "request-selected")
	input = baseInput(purchase)
	input.RequestHashes, input.RequestIDs = nil, []uint64{0, 0}
	requireFailed(t, run(newSession(t, purchase, purchasefixture.Responded), input), "request-selected")
}

// Two calls carrying one request_hash are not chosen between.
func TestVerifyRefusesAnAmbiguousRequestHash(t *testing.T) {
	purchase := newPurchase(t)
	session := newSession(t, purchase, purchasefixture.Pending)
	failed := session.Transactions[0]
	failed.Kind, failed.Snapshot, failed.ExitCode, failed.LT = toschain.ActorTxFailed, nil, 1928, 20
	failed.Hash = strings.Repeat("0f", 32)
	session.Transactions = append([]toschain.ActorTransaction{failed}, session.Transactions...)
	requireFailed(t, run(session, baseInput(purchase)), "request-selected")
}

// A Receipt must hash to the finalized response_hash of a responded request.
func TestVerifyRefusesAReceiptOfAnotherResponse(t *testing.T) {
	purchase := newPurchase(t)
	input := baseInput(purchase)
	_, other := respondedWith(t, purchase, func(_ *railwork.ReceiptBinding, o *railwork.Outcome) { o.CompletedAtUnix++ })
	input.Receipt = other
	requireFailed(t, run(newSession(t, purchase, purchasefixture.Responded), input), "receipt-response-hash")
	input.Receipt = purchase.Receipt
	requireFailed(t, run(newSession(t, purchase, purchasefixture.Pending), input), "receipt-response-hash")
	input.Receipt = append([]byte(nil), purchase.Receipt...)
	input.Receipt[len(input.Receipt)-1] ^= 1
	requireFailed(t, run(newSession(t, purchase, purchasefixture.Responded), input), "receipt-canonical")
}

// A Receipt whose commitments do not rebuild the call's request_hash binds
// another request, even when it is the attested response.
func TestVerifyRefusesAReceiptOfAnotherRequest(t *testing.T) {
	purchase := newPurchase(t)
	session, receipt := respondedWith(t, purchase, func(b *railwork.ReceiptBinding, _ *railwork.Outcome) { b.ExecutionID[0] ^= 1 })
	input := baseInput(purchase)
	input.Receipt = receipt
	requireFailed(t, run(session, input), "receipt-request-hash")
}

// A Receipt must charge the snapshotted price.
func TestVerifyRefusesAReceiptWithAnotherPrice(t *testing.T) {
	purchase := newPurchase(t)
	session, receipt := respondedWith(t, purchase, func(b *railwork.ReceiptBinding, _ *railwork.Outcome) { b.Price = big.NewInt(1) })
	input := baseInput(purchase)
	input.Receipt = receipt
	requireFailed(t, run(session, input), "receipt-terms")
}

// With a bundle, the Receipt must bind the bundle Quote's provider, source,
// toolchain and manifest.
func TestVerifyRefusesAReceiptThatDoesNotBindTheBundleQuote(t *testing.T) {
	purchase := newPurchase(t)
	session, receipt := respondedWith(t, purchase, func(b *railwork.ReceiptBinding, _ *railwork.Outcome) {
		b.ProviderAgentID = "agent_" + strings.Repeat("66", 32)
	})
	input := bundleInput(purchase, purchase.Bundle(false))
	input.Receipt = receipt
	requireFailed(t, run(session, input), "receipt-binding")
	plain := baseInput(purchase)
	plain.Receipt = receipt
	requirePass(t, run(session, plain))
}

// An artifact must be the one its Receipt binds, member by member.
func TestVerifyRefusesAnArtifactOfAnotherReceipt(t *testing.T) {
	purchase := newPurchase(t)
	input := baseInput(purchase)
	input.Receipt = purchase.Receipt
	input.Artifact = append([]byte(nil), purchase.Artifact...)
	input.Artifact[0] ^= 1
	requireFailed(t, run(newSession(t, purchase, purchasefixture.Responded), input), "artifact-digest")
}

// An artifact whose members differ from the Receipt's member digests fails
// even when its own digest is the Receipt's.
func TestVerifyRefusesAnArtifactWhoseMembersDiffer(t *testing.T) {
	purchase := newPurchase(t)
	session, receipt := respondedWith(t, purchase, func(_ *railwork.ReceiptBinding, o *railwork.Outcome) {
		o.ResultDigest = sha([]byte("another output"))
	})
	input := baseInput(purchase)
	input.Receipt, input.Artifact = receipt, purchase.Artifact
	requireFailed(t, run(session, input), "artifact-members")
}

// A bundle naming another network, actor or release is refused.
func TestVerifyRefusesABundleOfAnotherNetwork(t *testing.T) {
	purchase := newPurchase(t)
	for name, edit := range map[string]func(*purchaseevidence.Bundle){
		"network": func(b *purchaseevidence.Bundle) { b.Network.GenesisFileHash = "sha256:" + strings.Repeat("00", 32) },
		"release": func(b *purchaseevidence.Bundle) { b.ActorCodeHash = "tvm-cell-sha256:" + strings.Repeat("99", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			bundle := purchase.Bundle(false)
			edit(bundle)
			requireFailed(t, run(newSession(t, purchase, purchasefixture.Pending), bundleInput(purchase, bundle)), "bundle-pins")
		})
	}
}

// A bundle whose Quote package does not rebuild its claims is refused.
func TestVerifyRefusesABundleWhoseQuoteDoesNotRebuild(t *testing.T) {
	purchase := newPurchase(t)
	for name, edit := range map[string]func(*purchaseevidence.Bundle){
		"package":    func(b *purchaseevidence.Bundle) { b.Quote.PackageBase64 = "!" },
		"commitment": func(b *purchaseevidence.Bundle) { b.Quote.QuoteCommitment = "tvm-cell-sha256:" + hex64("01") },
		"quote boc":  func(b *purchaseevidence.Bundle) { b.Quote.AcceptedQuoteBOC = "AAAA" },
		"terms":      func(b *purchaseevidence.Bundle) { b.Quote.TermsHash = hex64("02") },
		"price":      func(b *purchaseevidence.Bundle) { b.Quote.PriceNanoTOS = "1" },
		"storage":    func(b *purchaseevidence.Bundle) { b.Quote.StorageFeeNanoTOS = "1" },
		"provider":   func(b *purchaseevidence.Bundle) { b.Offer.ProviderAgentID = "agent_" + hex64("66") },
		"manifest":   func(b *purchaseevidence.Bundle) { b.Offer.ManifestDigest = "sha256:" + hex64("03") },
		"toolchain":  func(b *purchaseevidence.Bundle) { b.Offer.ToolchainDigest = "sha256:" + hex64("04") },
		"version":    func(b *purchaseevidence.Bundle) { b.Offer.CapabilityVersion = "2.0.0" },
	} {
		t.Run(name, func(t *testing.T) {
			bundle := purchase.Bundle(false)
			edit(bundle)
			requireFailed(t, run(newSession(t, purchase, purchasefixture.Pending), bundleInput(purchase, bundle)), "bundle-quote")
		})
	}
}

// A bundle's request_hash must commit to its Quote, execution ID and the
// input commitment of its source digest.
func TestVerifyRefusesABundleWhoseRequestHashDoesNotRebuild(t *testing.T) {
	purchase := newPurchase(t)
	for name, edit := range map[string]func(*purchaseevidence.Bundle){
		"execution": func(b *purchaseevidence.Bundle) { b.Request.ExecutionID = strings.Repeat("05", 32) },
		"source":    func(b *purchaseevidence.Bundle) { b.Request.SourceDigest = "sha256:" + strings.Repeat("06", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			bundle := purchase.Bundle(false)
			edit(bundle)
			requireFailed(t, run(newSession(t, purchase, purchasefixture.Pending), bundleInput(purchase, bundle)), "bundle-request-hash")
		})
	}
}

// A bundle selects only its own buyer wallet's call with its query_id.
func TestVerifyRefusesABundleFromAnotherBuyer(t *testing.T) {
	purchase := newPurchase(t)
	for name, edit := range map[string]func(*purchaseevidence.Bundle){
		"wallet": func(b *purchaseevidence.Bundle) { b.BuyerWallet = "0:" + strings.Repeat("31", 32) },
		"query":  func(b *purchaseevidence.Bundle) { b.Journal.QueryID = "4243" },
	} {
		t.Run(name, func(t *testing.T) {
			bundle := purchase.Bundle(false)
			edit(bundle)
			requireFailed(t, run(newSession(t, purchase, purchasefixture.Pending), bundleInput(purchase, bundle)), "request-selected")
		})
	}
}

// A journal whose call or request ID is not the finalized one is refused.
func TestVerifyRefusesABundleWhoseJournalDiffers(t *testing.T) {
	purchase := newPurchase(t)
	three := uint64(3)
	other := &toschain.ActorTxID{LT: 9, Hash: hex64("07")}
	for name, edit := range map[string]func(*purchaseevidence.Bundle){
		"call":       func(b *purchaseevidence.Bundle) { b.Journal.CallTransaction = other },
		"request id": func(b *purchaseevidence.Bundle) { b.Journal.RequestID = &three },
	} {
		t.Run(name, func(t *testing.T) {
			bundle := purchase.Bundle(false)
			edit(bundle)
			requireFailed(t, run(newSession(t, purchase, purchasefixture.Pending), bundleInput(purchase, bundle)), "bundle-journal")
		})
	}
	bundle := purchase.Bundle(false)
	session := newSession(t, purchase, purchasefixture.Refused)
	requireFailed(t, run(session, bundleInput(purchase, bundle)), "bundle-journal")
	bundle.Journal.RequestID = nil
	requirePass(t, run(session, bundleInput(purchase, bundle)))
}

// The request must verify against the finalized Capability and the Quote.
func TestVerifyRefusesABundleWhoseCapabilityDoesNotBind(t *testing.T) {
	purchase := newPurchase(t)
	session := newSession(t, purchase, purchasefixture.Pending)
	session.Capability.GetCapability().Versions[0].ManifestDigest = "sha256:" + strings.Repeat("08", 32)
	requireFailed(t, run(session, bundleInput(purchase, purchase.Bundle(false))), "bundle-binding")
	session = newSession(t, purchase, purchasefixture.Pending)
	session.Capability.GetCapability().OwnerAgentId = "agent_" + strings.Repeat("66", 32)
	requireFailed(t, run(session, bundleInput(purchase, purchase.Bundle(false))), "bundle-binding")
}

// A bundle's finalized claims must be the finalized state.
func TestVerifyRefusesABundleClaimingAnotherOutcome(t *testing.T) {
	purchase := newPurchase(t)
	session := newSession(t, purchase, purchasefixture.Responded)
	honest := run(session, bundleInput(purchase, purchase.Bundle(true)))
	requirePass(t, honest)
	for name, edit := range map[string]func(*purchaseevidence.Finalized){
		"respond":  func(f *purchaseevidence.Finalized) { f.Request.Respond.Hash = strings.Repeat("09", 32) },
		"response": func(f *purchaseevidence.Finalized) { f.Request.ResponseHash = strings.Repeat("0a", 32) },
		"call":     func(f *purchaseevidence.Finalized) { f.Request.Call.LT++ },
		"sweep":    func(f *purchaseevidence.Finalized) { f.Request.Sweep = &purchaseevidence.TxReport{LT: 12} },
		"later":    func(f *purchaseevidence.Finalized) { f.Checkpoint.Seqno = session.Seqno + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bundle := purchase.Bundle(true)
			raw, _ := json.Marshal(honest.Requests[0])
			finalized := &purchaseevidence.Finalized{Checkpoint: *honest.Checkpoint}
			if err := json.Unmarshal(raw, &finalized.Request); err != nil {
				t.Fatal(err)
			}
			edit(finalized)
			bundle.Finalized = finalized
			requireFailed(t, run(session, bundleInput(purchase, bundle)), "bundle-finalized")
		})
	}
}

// A bundle's accepted result must be the finalized response, and the files
// given must be the bundle's.
func TestVerifyRefusesABundleWhoseResultIsNotTheResponse(t *testing.T) {
	purchase := newPurchase(t)
	bundle := purchase.Bundle(true)
	bundle.Result.ResponseHash = strings.Repeat("0b", 32)
	requireFailed(t, run(newSession(t, purchase, purchasefixture.Responded), bundleInput(purchase, bundle)), "bundle-result")
	bundle = purchase.Bundle(true)
	bundle.Result.Receipt.SHA256 = "sha256:" + strings.Repeat("0c", 32)
	input := bundleInput(purchase, bundle)
	input.Receipt = purchase.Receipt
	requireFailed(t, run(newSession(t, purchase, purchasefixture.Responded), input), "bundle-result")
	bundle = purchase.Bundle(true)
	bundle.Result.Artifact.SHA256 = "sha256:" + strings.Repeat("0d", 32)
	input = bundleInput(purchase, bundle)
	input.Receipt, input.Artifact = purchase.Receipt, purchase.Artifact
	requireFailed(t, run(newSession(t, purchase, purchasefixture.Responded), input), "bundle-result")
	requireFailed(t, run(newSession(t, purchase, purchasefixture.Pending), bundleInput(purchase, purchase.Bundle(true))), "bundle-result")
}

// Inputs a verification cannot judge are refused before any read.
func TestVerifyRefusesInvalidInput(t *testing.T) {
	purchase := newPurchase(t)
	for name, edit := range map[string]func(*purchaseevidence.Input){
		"no selector":          func(i *purchaseevidence.Input) { i.RequestHashes = nil },
		"bad hash":             func(i *purchaseevidence.Input) { i.RequestHashes = []string{"AB"} },
		"bad actor":            func(i *purchaseevidence.Input) { i.Actor = "EQ" },
		"bad code hash":        func(i *purchaseevidence.Input) { i.ActorCodeHash = "sha256:" + strings.Repeat("88", 32) },
		"no network":           func(i *purchaseevidence.Input) { i.Network = nil },
		"artifact alone":       func(i *purchaseevidence.Input) { i.Artifact = purchase.Artifact },
		"receipt for two":      func(i *purchaseevidence.Input) { i.Receipt, i.RequestIDs = purchase.Receipt, []uint64{1} },
		"bundle other request": func(i *purchaseevidence.Input) { i.Bundle = purchase.Bundle(false); i.RequestIDs = []uint64{0} },
		"too many": func(i *purchaseevidence.Input) {
			i.RequestIDs = make([]uint64, purchaseevidence.MaxSelected)
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := baseInput(purchase)
			edit(&input)
			requireFailed(t, run(newSession(t, purchase, purchasefixture.Responded), input), "input")
		})
	}
}

// A bundle is decoded strictly.
func TestDecodeBundleIsStrict(t *testing.T) {
	purchase := newPurchase(t)
	raw, err := json.Marshal(purchase.Bundle(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := purchaseevidence.DecodeBundle(raw); err != nil {
		t.Fatal(err)
	}
	for name, mutated := range map[string][]byte{
		"unknown field": append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"vault_url":"x"}`)...),
		"trailing":      append(append([]byte(nil), raw...), []byte(` {}`)...),
		"schema":        []byte(strings.Replace(string(raw), purchaseevidence.BundleSchema, "tos.other.v1", 1)),
		"duplicate":     append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"actor":"x"}`)...),
		"empty":         nil,
		"oversize":      make([]byte, purchaseevidence.MaxBundleBytes+1),
	} {
		if _, err := purchaseevidence.DecodeBundle(mutated); err == nil {
			t.Fatalf("%s: a malformed bundle decoded", name)
		}
	}
}
