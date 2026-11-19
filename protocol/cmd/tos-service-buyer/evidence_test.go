package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/internal/purchasefixture"
	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/purchaseevidence"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

// Values the agent holds that are no business of a verifier; none may
// appear in an exported bundle.
const (
	secretVault       = "vault-url-carries-the-master-key"
	secretNonce       = "e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0"
	secretConfirm     = "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff"
	secretIdempotency = "idempotency-key-of-the-client-01"
	secretMember      = "private/customer-name.go"
)

// evidenceAgent is an agent state directory holding one responded
// purchase, and its configuration.
type evidenceAgent struct {
	purchase *purchasefixture.Purchase
	session  *purchasefixture.Session
	state    string
	config   string
	hash     string
}

func privateDir(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func newEvidenceAgent(t *testing.T, accepted bool) *evidenceAgent {
	t.Helper()
	purchase, err := purchasefixture.New()
	if err != nil {
		t.Fatal(err)
	}
	session, err := purchase.Session(purchasefixture.Responded)
	if err != nil {
		t.Fatal(err)
	}
	call := session.Transactions[1]
	state := privateDir(t, filepath.Join(t.TempDir(), "state"))
	for _, name := range []string{"journal", "agent/purchases", "carrier/received", "chain"} {
		privateDir(t, filepath.Join(state, name))
	}
	hash := hex.EncodeToString(purchase.RequestHash[:])
	now := purchasefixture.Now
	journal, err := buyersdk.OpenServiceActorJournal(filepath.Join(state, "journal"), now)
	if err != nil {
		t.Fatal(err)
	}
	record := buyersdk.CallRecord{Schema: "tos.service.service-actor-call.v1", RequestHash: hash, QueryID: purchasefixture.QueryID,
		NetworkID: purchase.Network.NetworkId, GenesisRootHash: purchase.Network.GenesisRootHash,
		GenesisFileHash: purchase.Network.GenesisFileHash, BuyerWallet: purchasefixture.Buyer, Actor: purchasefixture.Actor,
		ActorCodeHash: purchasefixture.ActorCodeHash, CapabilityID: purchasefixture.CapabilityID,
		CapabilityVersion: purchasefixture.Version, PackageBase64: base64.StdEncoding.EncodeToString(purchase.PackageBytes),
		BuyerAddressInReq: purchasefixture.Buyer, AcceptedQuoteBOC: purchase.AcceptedQuote, QuoteCommitment: purchase.QuoteCommitment,
		ExecutionID: hex.EncodeToString(purchase.ExecutionID[:]), InputDigest: hex.EncodeToString(purchase.InputDigest[:]),
		TermsHash: purchase.TermsHash, PolicyVersion: purchase.Policy.PolicyVersion, PriceNanoTOS: purchase.Policy.PricePerCall.String(),
		StorageFeeNanoTOS: purchase.Policy.StorageFee.String(), AttestorKeyID: purchase.Package.Proposal.AttestorKeyId,
		PaymentNanoTOS: "500000000", ExpiresAtUnix: uint64(now.Unix()) + 600, Phase: buyersdk.PhasePrepared,
		CreatedUnix: now.Unix() - 2000, UpdatedUnix: now.Unix() - 2000, ResponseSLASeconds: purchase.Policy.ResponseSLA,
		RefundClaimWindowSeconds: purchase.Policy.RefundClaimWindow, CleanupBountyNanoTOS: purchase.Policy.CleanupBounty.String()}
	limits := buyersdk.ServiceActorLimits{Window: 24 * time.Hour, MaxCalls: 10, MaxPerCallNanoTOS: big.NewInt(1_000_000_000),
		MaxWindowNanoTOS: big.NewInt(10_000_000_000)}
	if err := journal.Create(record, limits, now); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Transition(hash, []buyersdk.CallPhase{buyersdk.PhasePrepared}, func(r *buyersdk.CallRecord) error {
		id := uint64(0)
		r.Phase, r.RequestID, r.SentUnix = buyersdk.PhaseAdmitted, &id, now.Unix()-1900
		r.CallTransactionLT, r.CallTransactionHex = call.LT, call.Hash
		r.Lifecycle = []buyersdk.LifecycleSend{{Operation: buyersdk.LifecycleExpire, QueryID: 77, Phase: buyersdk.PhaseRefused,
			SentUnix: now.Unix() - 10, MessageHash: strings.Repeat("ab", 32)}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	purchaseRecord := buyeragent.PurchaseRecord{Schema: "tos.service.mcp-buyer.purchase.v1", RequestHash: hash, QuoteID: "quote-1",
		IdempotencyKey: secretIdempotency, SourceDigest: purchase.SourceDigest, ExecutionNonce: secretNonce, ArchiveBytes: 1024,
		Members: []buyeragent.Member{{Name: secretMember, SizeBytes: 10}}, ConfirmationNonce: secretConfirm,
		CreatedUnix: now.Unix() - 2000, ProviderAgentID: purchasefixture.ProviderAgentID, ManifestDigest: purchase.ManifestDigest,
		ToolchainDigest: purchase.Manifest.ToolchainDigest, ProviderName: "a provider", RetentionSeconds: 86400}
	writeJSONFile(t, filepath.Join(state, "agent", "purchases", hash+".json"), purchaseRecord)
	if accepted {
		writeJSONFile(t, filepath.Join(state, "carrier", "received", hash+".json"), map[string]any{
			"schema": "tos.service.mcp-buyer.received.v1", "request_hash": hash,
			"accepted_response_hash": hex.EncodeToString(purchase.ResponseHash[:]),
			"receipt_boc_base64":     base64.StdEncoding.EncodeToString(purchase.Receipt), "accepted_unix": now.Unix() - 900})
		if err := os.WriteFile(filepath.Join(state, "carrier", "received", hash+".artifact"), purchase.Artifact, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	config := validAgentConfig()
	config["state_dir"] = state
	config["network"] = map[string]any{"network_id": purchase.Network.NetworkId, "genesis_root_hash": purchase.Network.GenesisRootHash,
		"genesis_file_hash": purchase.Network.GenesisFileHash}
	config["actor_code_hash"] = purchasefixture.ActorCodeHash
	config["buyer_wallet"] = purchasefixture.Buyer
	config["buyer_agent_id"] = purchasefixture.BuyerAgentID
	agent := &evidenceAgent{purchase: purchase, session: session, state: state, config: writeAgentConfig(t, config, 0o600), hash: hash}
	previous := evidenceSession
	evidenceSession = func(context.Context, agentConfig) (purchaseevidence.Session, error) { return agent.session, nil }
	t.Cleanup(func() { evidenceSession = previous })
	return agent
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (a *evidenceAgent) export(t *testing.T, outDir string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run([]string{"evidence", "--config", a.config, "--request-hash", a.hash, "--out-dir", outDir}, &out)
	return out.String(), err
}

// evidence exports the journal record, the Quote, the finalized call and
// respond and the accepted result, and the verifier accepts what it wrote:
// the bundle, the Receipt and the artifact pass at the finalized checkpoint.
func TestEvidenceExportsABundleTheVerifierAccepts(t *testing.T) {
	agent := newEvidenceAgent(t, true)
	t.Setenv("VAULT_URL", secretVault)
	outDir := filepath.Join(t.TempDir(), "evidence")
	printed, err := agent.export(t, outDir)
	if err != nil {
		t.Fatalf("%v\n%s", err, printed)
	}
	var output evidenceOutput
	if err := json.Unmarshal([]byte(printed), &output); err != nil || output.Result != purchaseevidence.ResultPass || len(output.Files) != 3 {
		t.Fatalf("output %s", printed)
	}
	read := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	raw := read(purchaseevidence.BundleFile)
	bundle, err := purchaseevidence.DecodeBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Finalized == nil || bundle.Finalized.Request.Respond == nil || bundle.Journal.CallTransaction == nil ||
		bundle.Journal.QueryID != "4242" || len(bundle.Journal.Lifecycle) != 1 || !bundle.Result.Accepted ||
		len(bundle.Result.Members) != 2 || bundle.Request.SourceDigest != agent.purchase.SourceDigest {
		t.Fatalf("bundle %s", raw)
	}
	verdict := purchaseevidence.Verify(context.Background(), agent.session, purchaseevidence.Input{Network: agent.purchase.Network,
		ActorCodeHash: purchasefixture.ActorCodeHash, Actor: bundle.Actor, RequestHashes: []string{bundle.Request.RequestHash},
		Bundle: bundle, Receipt: read(purchaseevidence.ReceiptFile), Artifact: read(purchaseevidence.ArtifactFile)})
	if verdict.Result != purchaseevidence.ResultPass {
		t.Fatalf("the verifier refused the exported bundle: %+v", verdict.Checks)
	}
	info, err := os.Stat(outDir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("out dir mode %v %v", info.Mode(), err)
	}
}

// A bundle holds no secret: not the vault URL, nor the execution or
// confirmation nonce, the idempotency key, the tosctl configuration or the
// source member names.
func TestEvidenceHoldsNoSecret(t *testing.T) {
	agent := newEvidenceAgent(t, true)
	t.Setenv("VAULT_URL", secretVault)
	outDir := filepath.Join(t.TempDir(), "evidence")
	printed, err := agent.export(t, outDir)
	if err != nil {
		t.Fatalf("%v\n%s", err, printed)
	}
	raw, err := os.ReadFile(filepath.Join(outDir, purchaseevidence.BundleFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{secretVault, secretNonce, secretConfirm, secretIdempotency, secretMember, "tosctl.json",
		"/usr/local/bin/tosctl", "buyer-packet", "relay-ca.pem", "quote-1", agent.state} {
		if strings.Contains(string(raw), secret) || strings.Contains(printed, secret) {
			t.Fatalf("the export carries %q", secret)
		}
	}
}

// An accepted result is verified against the purchase before it is
// exported: a stored Receipt that is the finalized response but binds
// another provider than the Quote is never exported.
func TestEvidenceRefusesAResultThatDoesNotBindThePurchase(t *testing.T) {
	agent := newEvidenceAgent(t, true)
	purchase := agent.purchase
	digest := func(raw []byte) string {
		sum := sha256.Sum256(raw)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	root, hash, err := railwork.BuildReceipt(railwork.ReceiptBinding{QuoteCommitment: purchase.QuoteCommitment,
		ExecutionID: purchase.ExecutionID, InputDigest: purchase.InputDigest, SourceDigest: purchase.SourceDigest,
		Price: purchase.Policy.PricePerCall, ProviderAgentID: "agent_" + strings.Repeat("66", 32),
		ToolchainDigest: purchase.Manifest.ToolchainDigest, SandboxDigest: purchase.ManifestDigest},
		railwork.Outcome{ResultDigest: digest(purchase.Output), ArtifactDigest: digest(purchase.Artifact),
			ReportDigest: digest(purchase.Report), CompletedAtUnix: 1_999_999_000})
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, filepath.Join(agent.state, "carrier", "received", agent.hash+".json"), map[string]any{
		"schema": "tos.service.mcp-buyer.received.v1", "request_hash": agent.hash,
		"accepted_response_hash": hex.EncodeToString(hash[:]),
		"receipt_boc_base64":     base64.StdEncoding.EncodeToString(root.ToBOC()), "accepted_unix": 1})
	agent.session.Transactions[0].ResponseHash = hex.EncodeToString(hash[:])
	outDir := filepath.Join(t.TempDir(), "evidence")
	printed, err := agent.export(t, outDir)
	if err == nil || !strings.Contains(printed, "receipt-binding") {
		t.Fatalf("a Receipt of another provider was exported: %v %s", err, printed)
	}
	if _, statErr := os.Lstat(outDir); !os.IsNotExist(statErr) {
		t.Fatal("a refused export left an out dir")
	}
}

// A purchase without an accepted result is exported without result files.
func TestEvidenceExportsAPurchaseWithoutAResult(t *testing.T) {
	agent := newEvidenceAgent(t, false)
	outDir := filepath.Join(t.TempDir(), "evidence")
	if printed, err := agent.export(t, outDir); err != nil {
		t.Fatalf("%v\n%s", err, printed)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil || len(entries) != 1 || entries[0].Name() != purchaseevidence.BundleFile {
		t.Fatalf("entries %v %v", entries, err)
	}
}

// Nothing is written for a purchase that does not verify, into an existing
// directory, or from a journal of another buyer.
func TestEvidenceRefusesWhatItCannotExport(t *testing.T) {
	agent := newEvidenceAgent(t, true)
	existing := t.TempDir()
	if _, err := agent.export(t, existing); err == nil || !strings.Contains(err.Error(), "must not exist") {
		t.Fatalf("an existing out dir: %v", err)
	}
	agent.session.CodeHash = "tvm-cell-sha256:" + strings.Repeat("99", 32)
	outDir := filepath.Join(t.TempDir(), "evidence")
	printed, err := agent.export(t, outDir)
	if err == nil || !strings.Contains(printed, `"result": "fail"`) {
		t.Fatalf("an unverified purchase was exported: %v %s", err, printed)
	}
	if _, statErr := os.Lstat(outDir); !os.IsNotExist(statErr) {
		t.Fatal("an unverified purchase left an out dir")
	}
	other := newEvidenceAgent(t, true)
	config := validAgentConfig()
	config["state_dir"] = other.state
	config["network"] = map[string]any{"network_id": other.purchase.Network.NetworkId,
		"genesis_root_hash": other.purchase.Network.GenesisRootHash, "genesis_file_hash": other.purchase.Network.GenesisFileHash}
	config["actor_code_hash"] = purchasefixture.ActorCodeHash
	config["buyer_agent_id"] = purchasefixture.BuyerAgentID
	other.config = writeAgentConfig(t, config, 0o600)
	if _, err := other.export(t, filepath.Join(t.TempDir(), "evidence")); err == nil ||
		!strings.Contains(err.Error(), "another purchase, network, release or buyer") {
		t.Fatalf("a journal of another buyer was exported: %v", err)
	}
	for name, arguments := range map[string][]string{
		"bad hash":     {"evidence", "--config", agent.config, "--request-hash", "AB", "--out-dir", outDir},
		"relative out": {"evidence", "--config", agent.config, "--request-hash", agent.hash, "--out-dir", "evidence"},
		"positional":   {"evidence", "--config", agent.config, "--request-hash", agent.hash, "--out-dir", outDir, "x"},
		"no purchase": {"evidence", "--config", agent.config, "--request-hash", strings.Repeat("ab", 32), "--out-dir",
			filepath.Join(t.TempDir(), "evidence")},
	} {
		if err := run(arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
