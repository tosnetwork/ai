package buyeragent

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A purchase record is read without opening the agent, only from a state
// directory private to this account.
func TestReadPurchaseRecordNeedsAPrivateStateDirectory(t *testing.T) {
	dir := privateTempDir(t)
	state := store{root: dir}
	if err := state.ensure(); err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("ab", 32)
	if err := state.writePurchase(PurchaseRecord{RequestHash: hash, SourceDigest: "sha256:" + strings.Repeat("01", 32)}); err != nil {
		t.Fatal(err)
	}
	record, err := ReadPurchaseRecord(dir, hash)
	if err != nil || record.SourceDigest != "sha256:"+strings.Repeat("01", 32) {
		t.Fatalf("record %+v %v", record, err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPurchaseRecord(dir, hash); err == nil {
		t.Fatal("a state directory open to the group was read")
	}
	if _, err := ReadPurchaseRecord("state", hash); err == nil {
		t.Fatal("a relative state directory was read")
	}
}

// An accepted result is read without opening a carrier, under the
// carrier's checks, only from a carrier directory private to this account.
func TestReadAcceptedResultNeedsAPrivateCarrierDirectory(t *testing.T) {
	dir := privateTempDir(t)
	received := filepath.Join(dir, "received")
	if err := os.Mkdir(received, 0o700); err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("ab", 32)
	if _, found, err := ReadAcceptedResult(dir, hash); err != nil || found {
		t.Fatalf("a purchase without a result: found %v %v", found, err)
	}
	artifact := artifactTar(t, "ok")
	receipt, responseHash := receiptFor(t, artifact)
	if err := writeJSON(receivedPathAt(dir, hash), receivedRecord{Schema: receivedSchema, RequestHash: hash,
		AcceptedResponseHash: hex.EncodeToString(responseHash[:]), ReceiptBase64: base64.StdEncoding.EncodeToString(receipt),
		AcceptedUnix: 5}, false); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(artifactPathAt(dir, hash), artifact, false); err != nil {
		t.Fatal(err)
	}
	result, found, err := ReadAcceptedResult(dir, hash)
	if err != nil || !found || result.AcceptedUnix != 5 {
		t.Fatalf("result %+v %v %v", result, found, err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadAcceptedResult(dir, hash); err == nil {
		t.Fatal("a carrier directory open to the group was read")
	}
}

// receiptFor is a Receipt binding artifact's digests.
func receiptFor(t *testing.T, artifact []byte) ([]byte, [32]byte) {
	t.Helper()
	output, report, err := railwork.ArtifactMembers(artifact)
	if err != nil {
		t.Fatal(err)
	}
	digest := func(raw []byte) string {
		sum := sha256.Sum256(raw)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	root, hash, err := railwork.BuildReceipt(railwork.ReceiptBinding{QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("02", 32),
		ExecutionID: [32]byte{3}, InputDigest: [32]byte{4}, SourceDigest: "sha256:" + strings.Repeat("05", 32), Price: big.NewInt(9),
		ProviderAgentID: "agent_" + strings.Repeat("06", 32), ToolchainDigest: "sha256:" + strings.Repeat("07", 32),
		SandboxDigest: "sha256:" + strings.Repeat("08", 32)},
		railwork.Outcome{ResultDigest: digest(output), ArtifactDigest: digest(artifact), ReportDigest: digest(report), CompletedAtUnix: 1})
	if err != nil {
		t.Fatal(err)
	}
	return root.ToBOC(), hash
}
