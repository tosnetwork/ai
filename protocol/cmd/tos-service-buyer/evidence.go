package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/osguard"
	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/purchaseevidence"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

// evidenceSession opens the finalized session the export verifies the
// purchase in; tests replace it.
var evidenceSession = openEvidenceSession

// openEvidenceSession opens a quorum-finalized session with the agent's
// own read configuration. Its finality fences are the agent's, in the
// state directory's chain subdirectory, which the agent created: they only
// ever advance, and the export changes nothing else there.
func openEvidenceSession(ctx context.Context, config agentConfig) (purchaseevidence.Session, error) {
	chainDir := filepath.Join(config.StateDir, "chain")
	info, err := os.Lstat(chainDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return nil, errors.New("the agent's chain directory is missing or not private to this account; run evidence as the custody account")
	}
	network := &nativev1.NetworkDomain{NetworkId: config.Network.NetworkID, GenesisRootHash: config.Network.GenesisRootHash,
		GenesisFileHash: config.Network.GenesisFileHash}
	reader, err := openReader(network, config.Endpoints, config.Quorum, config.RegistryCodeFile, config.RegistryCodeHash,
		config.RegistryWorkchain, config.ActorCodeHash, chainDir)
	if err != nil {
		return nil, err
	}
	return reader.Begin(ctx)
}

// evidenceOutput is what evidence prints once the bundle is written.
type evidenceOutput struct {
	OutDir     string                        `json:"out_dir"`
	Files      []purchaseevidence.FileDigest `json:"files"`
	Result     string                        `json:"verification"`
	Checkpoint uint64                        `json:"checkpoint"`
}

// runEvidence is `tos-service-buyer evidence`: run as the custody account,
// it exports one purchase's evidence bundle from the agent's state, after
// verifying it at a finalized checkpoint exactly as a third-party verifier
// would. It reads the configuration, the journal record, the purchase
// record and the accepted result, and writes only a new output directory.
// It never reads VAULT_URL, a key, or the tosctl configuration.
func runEvidence(arguments []string, out io.Writer) error {
	set := flag.NewFlagSet("evidence", flag.ContinueOnError)
	set.SetOutput(usageOutput)
	configPath := set.String("config", "", "absolute path of the agent configuration (owner-private JSON)")
	requestHash := set.String("request-hash", "", "request_hash of the purchase")
	outDir := set.String("out-dir", "", "absolute path of a new directory to write the bundle into")
	timeout := set.Duration("timeout", 2*time.Minute, "overall command timeout")
	if err := set.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if set.NArg() != 0 {
		return errors.New("evidence takes no positional arguments")
	}
	if _, err := hex32(*requestHash); err != nil {
		return fmt.Errorf("--request-hash: %w", err)
	}
	if !filepath.IsAbs(*outDir) || filepath.Clean(*outDir) != *outDir {
		return errors.New("--out-dir must be an absolute, clean path")
	}
	if _, err := os.Lstat(*outDir); !errors.Is(err, os.ErrNotExist) {
		return errors.New("--out-dir must not exist yet; evidence never overwrites")
	}
	config, err := readAgentConfig(*configPath)
	if err != nil {
		return err
	}
	record, err := buyersdk.ReadServiceActorCallRecord(filepath.Join(config.StateDir, "journal"), *requestHash)
	if err != nil {
		return fmt.Errorf("the journal holds no readable record of this purchase: %w", err)
	}
	purchase, err := buyeragent.ReadPurchaseRecord(filepath.Join(config.StateDir, "agent"), *requestHash)
	if err != nil {
		return fmt.Errorf("the agent holds no readable purchase record: %w", err)
	}
	accepted, found, err := buyeragent.ReadAcceptedResult(filepath.Join(config.StateDir, "carrier"), *requestHash)
	if err != nil {
		return fmt.Errorf("the accepted result does not read: %w", err)
	}
	bundle, err := buildBundle(config, record, purchase, accepted, found, time.Now())
	if err != nil {
		return err
	}
	input := purchaseevidence.Input{Network: &nativev1.NetworkDomain{NetworkId: config.Network.NetworkID,
		GenesisRootHash: config.Network.GenesisRootHash, GenesisFileHash: config.Network.GenesisFileHash},
		ActorCodeHash: config.ActorCodeHash, Actor: record.Actor, RequestHashes: []string{record.RequestHash}, Bundle: bundle}
	if found {
		input.Receipt, input.Artifact = accepted.ReceiptBOC, accepted.Artifact
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	session, err := evidenceSession(ctx, config)
	if err != nil {
		return fmt.Errorf("finalized read: %w", err)
	}
	verdict := purchaseevidence.Verify(ctx, session, input)
	if verdict.Result != purchaseevidence.ResultPass || verdict.Checkpoint == nil || len(verdict.Requests) != 1 {
		if err := printJSON(out, verdict); err != nil {
			return err
		}
		return errors.New("the purchase does not verify at the finalized checkpoint; no evidence was written")
	}
	bundle.Finalized = &purchaseevidence.Finalized{Checkpoint: *verdict.Checkpoint, Request: verdict.Requests[0]}
	files, err := writeEvidence(*outDir, bundle, accepted, found)
	if err != nil {
		return err
	}
	return printJSON(out, evidenceOutput{OutDir: *outDir, Files: files, Result: verdict.Result, Checkpoint: verdict.Checkpoint.Seqno})
}

// buildBundle assembles the bundle from the agent's records. Every field is
// named here: nothing from the configuration but the public read pins and
// budget, and from the purchase record only the source digest and size,
// the offer and the retention, never its nonces, keys or member names.
func buildBundle(config agentConfig, record buyersdk.CallRecord, purchase buyeragent.PurchaseRecord,
	accepted buyeragent.AcceptedResult, found bool, now time.Time) (*purchaseevidence.Bundle, error) {
	if record.RequestHash != purchase.RequestHash || record.NetworkID != config.Network.NetworkID ||
		record.GenesisRootHash != config.Network.GenesisRootHash || record.GenesisFileHash != config.Network.GenesisFileHash ||
		record.ActorCodeHash != config.ActorCodeHash || record.BuyerWallet != config.BuyerWallet {
		return nil, errors.New("the journal record belongs to another purchase, network, release or buyer than this agent")
	}
	quorum := config.Quorum
	if quorum == 0 {
		quorum = len(config.Endpoints)/2 + 1
	}
	bundle := &purchaseevidence.Bundle{Schema: purchaseevidence.BundleSchema, Tool: evidenceTool(), ExportedUnix: now.Unix(),
		Network: purchaseevidence.NetworkTuple{NetworkID: record.NetworkID, GenesisRootHash: record.GenesisRootHash,
			GenesisFileHash: record.GenesisFileHash},
		Endpoints: append([]string(nil), config.Endpoints...), Quorum: quorum, RegistryCodeHash: config.RegistryCodeHash,
		ActorCodeHash: record.ActorCodeHash, Actor: record.Actor, BuyerWallet: record.BuyerWallet, BuyerAgentID: config.BuyerAgentID,
		Offer: purchaseevidence.Offer{CapabilityID: record.CapabilityID, CapabilityVersion: record.CapabilityVersion,
			ManifestDigest: purchase.ManifestDigest, ToolchainDigest: purchase.ToolchainDigest,
			ProviderAgentID: purchase.ProviderAgentID, RetentionSeconds: purchase.RetentionSeconds},
		Quote: purchaseevidence.Quote{PackageBase64: record.PackageBase64, RequestBuyerAddress: record.BuyerAddressInReq,
			AcceptedQuoteBOC: record.AcceptedQuoteBOC, QuoteCommitment: record.QuoteCommitment, TermsHash: record.TermsHash,
			PolicyVersion: record.PolicyVersion, PriceNanoTOS: record.PriceNanoTOS, StorageFeeNanoTOS: record.StorageFeeNanoTOS,
			PaymentNanoTOS: record.PaymentNanoTOS, CleanupBountyNanoTOS: record.CleanupBountyNanoTOS,
			ResponseSLASeconds: record.ResponseSLASeconds, RefundClaimWindowSeconds: record.RefundClaimWindowSeconds,
			ExpiresAtUnixSeconds: record.ExpiresAtUnix, AttestorKeyID: record.AttestorKeyID},
		Request: purchaseevidence.Request{RequestHash: record.RequestHash, ExecutionID: record.ExecutionID,
			InputDigest: record.InputDigest, SourceDigest: purchase.SourceDigest, SourceBytes: purchase.ArchiveBytes},
		Journal: purchaseevidence.Journal{Phase: string(record.Phase), QueryID: strconv.FormatUint(record.QueryID, 10),
			CreatedUnix: record.CreatedUnix, SentUnix: record.SentUnix, RequestID: record.RequestID, ExitCode: record.ExitCode},
		Budget: purchaseevidence.Budget{WindowSeconds: config.Budget.WindowSeconds, MaxCalls: config.Budget.MaxCalls,
			MaxPerCallNanoTOS: config.Budget.MaxPerCallNanoTOS, MaxWindowNanoTOS: config.Budget.MaxWindowNanoTOS,
			MaxUnconfirmed: config.Budget.MaxUnconfirmed, MaxLifecycleSends: config.Budget.MaxLifecycleSends}}
	if record.CallTransactionHex != "" {
		bundle.Journal.CallTransaction = &toschain.ActorTxID{LT: record.CallTransactionLT, Hash: record.CallTransactionHex}
	}
	if len(record.Lifecycle) > purchaseevidence.MaxLifecycleEntries {
		return nil, errors.New("the journal record holds more lifecycle sends than a bundle carries")
	}
	for _, send := range record.Lifecycle {
		bundle.Journal.Lifecycle = append(bundle.Journal.Lifecycle, purchaseevidence.LifecycleEntry{Operation: send.Operation,
			QueryID: strconv.FormatUint(send.QueryID, 10), Phase: string(send.Phase), SentUnix: send.SentUnix,
			MessageHash: send.MessageHash})
	}
	if found {
		output, report, err := railwork.ArtifactMembers(accepted.Artifact)
		if err != nil {
			return nil, fmt.Errorf("the accepted artifact does not read: %w", err)
		}
		bundle.Result = purchaseevidence.Result{Accepted: true, AcceptedUnix: accepted.AcceptedUnix, ResponseHash: accepted.ResponseHash,
			Receipt:        fileDigest(purchaseevidence.ReceiptFile, accepted.ReceiptBOC),
			Artifact:       fileDigest(purchaseevidence.ArtifactFile, accepted.Artifact),
			Members:        []purchaseevidence.FileDigest{*fileDigest("output.log", output), *fileDigest("report.json", report)},
			ResultDigest:   accepted.Receipt.ResultDigest,
			ArtifactDigest: accepted.Receipt.ArtifactDigest, ReportDigest: accepted.Receipt.ReportDigest}
	}
	return bundle, nil
}

func fileDigest(name string, raw []byte) *purchaseevidence.FileDigest {
	sum := sha256.Sum256(raw)
	return &purchaseevidence.FileDigest{Name: name, SHA256: "sha256:" + hex.EncodeToString(sum[:]), Bytes: len(raw)}
}

// writeEvidence creates outDir and writes the bundle and, for an accepted
// result, the Receipt and artifact, each a new owner-only file.
func writeEvidence(outDir string, bundle *purchaseevidence.Bundle, accepted buyeragent.AcceptedResult, found bool) ([]purchaseevidence.FileDigest, error) {
	raw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if _, err := purchaseevidence.DecodeBundle(raw); err != nil {
		return nil, fmt.Errorf("the bundle would not decode: %w", err)
	}
	if err := os.Mkdir(outDir, 0o700); err != nil {
		return nil, err
	}
	contents := []struct {
		name string
		raw  []byte
	}{{purchaseevidence.BundleFile, raw}}
	if found {
		contents = append(contents, struct {
			name string
			raw  []byte
		}{purchaseevidence.ReceiptFile, accepted.ReceiptBOC}, struct {
			name string
			raw  []byte
		}{purchaseevidence.ArtifactFile, accepted.Artifact})
	}
	files := make([]purchaseevidence.FileDigest, 0, len(contents))
	for _, content := range contents {
		if err := writeNewFile(filepath.Join(outDir, content.name), content.raw); err != nil {
			return nil, err
		}
		files = append(files, *fileDigest(content.name, content.raw))
	}
	return files, nil
}

func writeNewFile(path string, raw []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// evidenceTool names this build from its embedded build information.
func evidenceTool() purchaseevidence.Tool {
	tool := purchaseevidence.Tool{Name: "tos-service-buyer evidence"}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return tool
	}
	tool.Module, tool.GoVersion = info.Main.Path, info.GoVersion
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			tool.VCSRevision = setting.Value
		case "vcs.modified":
			tool.VCSModified = setting.Value == "true"
		}
	}
	return tool
}
