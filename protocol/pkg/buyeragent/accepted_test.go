package buyeragent

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

// The carrier reads back exactly the result it accepted, and refuses a
// damaged store.
func TestTheCarrierReadsBackTheAcceptedResult(t *testing.T) {
	f := newReceiveFixture(t)
	requestHash := f.task.Record.RequestHash
	if _, found, err := f.carrier.AcceptedResult(requestHash); err != nil || found {
		t.Fatalf("before acceptance: %v %v", found, err)
	}
	result := f.result(t, "built", nil)
	f.deliver(t, fxProvider, railwork.KindResult, f.binding, result.message)
	f.poll(t)
	if _, err := f.carrier.ReceiveResult(context.Background(), f.round(result.responseHash, fxNow.Add(2*time.Hour))); err != nil {
		t.Fatal(err)
	}
	accepted, found, err := f.carrier.AcceptedResult(requestHash)
	if err != nil || !found || accepted.ResponseHash != hex.EncodeToString(result.responseHash[:]) ||
		string(accepted.Artifact) != string(result.artifact) || accepted.Receipt.ProviderAgentID != fxProvider {
		t.Fatalf("accepted %+v %v %v", accepted.ResponseHash, found, err)
	}
	if _, _, err := f.carrier.AcceptedResult("../x"); err == nil {
		t.Fatal("a request hash that is not hex was read")
	}
	// A damaged artifact is an error, never a result.
	if err := writePrivate(f.carrier.ArtifactPath(requestHash), []byte("other"), false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.carrier.AcceptedResult(requestHash); err == nil {
		t.Fatal("a damaged artifact was returned")
	}
	if err := writePrivate(f.carrier.ArtifactPath(requestHash), result.artifact, false); err != nil {
		t.Fatal(err)
	}
	// A Receipt that no longer hashes to the accepted response hash too,
	// even one that attests the same artifact.
	state, err := f.carrier.readReceived(requestHash)
	if err != nil {
		t.Fatal(err)
	}
	report := []byte(`{"ok":true}`)
	root, _, err := railwork.BuildReceipt(f.receipt, railwork.Outcome{ResultDigest: digestText([]byte("built")),
		ArtifactDigest: digestText(result.artifact), ReportDigest: digestText(report),
		CompletedAtUnix: uint64(fxNow.Unix()) + 1})
	if err != nil {
		t.Fatal(err)
	}
	otherState := state
	otherState.ReceiptBase64 = base64.StdEncoding.EncodeToString(root.ToBOC())
	if err := writeJSON(f.carrier.receivedPath(requestHash), otherState, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.carrier.AcceptedResult(requestHash); err == nil {
		t.Fatal("a Receipt of another response hash was returned")
	}
}

func receiptOf(t *testing.T, message []byte) []byte {
	t.Helper()
	decoded, err := railwork.DecodeResult(message)
	if err != nil {
		t.Fatal(err)
	}
	return decoded.Receipt
}

// fakeAccepted serves one accepted result.
type fakeAccepted struct {
	result AcceptedResult
	found  bool
	err    error
}

func (f *fakeAccepted) AcceptedResult(string) (AcceptedResult, bool, error) {
	return f.result, f.found, f.err
}

// acceptedFor builds the accepted result a provider would deliver for a
// purchase of the agent fixture.
func acceptedFor(t *testing.T, record buyersdk.CallRecord, purchase PurchaseRecord, output string) AcceptedResult {
	t.Helper()
	executionID, err := decodeHex32(record.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	inputDigest, err := decodeHex32(record.InputDigest)
	if err != nil {
		t.Fatal(err)
	}
	price, _ := new(big.Int).SetString(record.PriceNanoTOS, 10)
	artifact := artifactTar(t, output)
	root, hash, err := railwork.BuildReceipt(railwork.ReceiptBinding{QuoteCommitment: record.QuoteCommitment,
		ExecutionID: executionID, InputDigest: inputDigest, SourceDigest: purchase.SourceDigest, Price: price,
		ProviderAgentID: purchase.ProviderAgentID, ToolchainDigest: purchase.ToolchainDigest,
		SandboxDigest: purchase.ManifestDigest}, railwork.Outcome{ResultDigest: digestText([]byte(output)),
		ArtifactDigest: digestText(artifact), ReportDigest: digestText([]byte(`{"ok":true}`)),
		CompletedAtUnix: uint64(fxNow.Unix())})
	if err != nil {
		t.Fatal(err)
	}
	receipt, _, err := railwork.DecodeReceipt(root.ToBOC())
	if err != nil {
		t.Fatal(err)
	}
	return AcceptedResult{ResponseHash: hex.EncodeToString(hash[:]), ReceiptBOC: root.ToBOC(), Receipt: receipt,
		Artifact: artifact, AcceptedUnix: fxNow.Unix()}
}

// The result method returns only an accepted result that binds the
// purchase; before acceptance it refuses with RESULT_NOT_READY and the
// status.
func TestTheResultMethodReturnsOnlyAnAcceptedBoundResult(t *testing.T) {
	f := newFixture(t)
	accepted := &fakeAccepted{}
	f.agent.config.Accepted = accepted
	view := f.paid(t, keyA)
	out, err := f.agent.Result(view.RequestHash)
	status, isStatus := out.(PurchaseView)
	if codeOf(t, err) != CodeResultNotReady || !isStatus || status.RequestHash != view.RequestHash {
		t.Fatalf("before acceptance: %+v %v", out, err)
	}
	if refusal(CodeResultNotReady, "", nil).Disposition != DispositionSameAfterBackoff {
		t.Fatal("RESULT_NOT_READY is retried after backoff")
	}
	record, err := f.buyer.Journal().Read(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	purchase, err := f.agent.store.readPurchase(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	accepted.result, accepted.found = acceptedFor(t, record, purchase, "built"), true
	out, err = f.agent.Result(view.RequestHash)
	result, ok := out.(AcceptedView)
	if err != nil || !ok || result.ResponseHash != accepted.result.ResponseHash || result.ExitCode != 0 ||
		result.ToolchainDigest != purchase.ToolchainDigest || result.ManifestDigest != purchase.ManifestDigest ||
		result.ArtifactBase64 != base64.StdEncoding.EncodeToString(accepted.result.Artifact) {
		t.Fatalf("an accepted result: %+v %v", out, err)
	}
	// A Receipt of another purchase never reaches the client.
	other := purchase
	other.SourceDigest = "sha256:" + strings.Repeat("99", 32)
	accepted.result = acceptedFor(t, record, other, "built")
	if _, err := f.agent.Result(view.RequestHash); err == nil {
		t.Fatal("a Receipt of another source was returned")
	}
	// An artifact whose members do not match the Receipt is refused.
	accepted.result = acceptedFor(t, record, purchase, "built")
	accepted.result.Artifact = artifactTar(t, "changed")
	if _, err := f.agent.Result(view.RequestHash); err == nil {
		t.Fatal("an artifact that does not match its Receipt was returned")
	}
	accepted.err = errors.New("disk")
	if _, err := f.agent.Result(view.RequestHash); err == nil {
		t.Fatal("a read failure was hidden")
	}
	if _, err := f.agent.Result(strings.Repeat("00", 32)); codeOf(t, err) != CodeNotFound {
		t.Fatalf("an unknown purchase: %v", err)
	}
	f.agent.config.Accepted = nil
	if _, err := f.agent.Result(view.RequestHash); codeOf(t, err) != CodeResultNotReady {
		t.Fatalf("an agent without results: %v", err)
	}
	if !Allowed(RoleClient, "result") || !Allowed(RoleCustody, "result") {
		t.Fatal("both roles read results")
	}
}
