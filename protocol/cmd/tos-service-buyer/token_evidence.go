package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/purchaseevidence"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// tokenFundingDiscovery is only a source of candidate transaction identities.
// Acceptance is established separately by the verifier's exact-hop reads.
type tokenFundingDiscovery interface {
	TokenWalletHistory(context.Context, string, *toschain.ActorTxID) (*toschain.TokenWalletHistory, error)
}

type tokenExportSession interface {
	purchaseevidence.TokenSession
	tokenFundingDiscovery
}

var _ tokenExportSession = (*toschain.ServiceActorSession)(nil)

// exportTokenEvidence verifies the complete funding path in the same finalized
// session used to select it. No custody material or private read configuration is exported.
func exportTokenEvidence(config agentConfig, record buyersdk.CallRecord, purchase buyeragent.PurchaseRecord, accepted buyeragent.AcceptedResult, found bool, outDir string, timeout time.Duration, out io.Writer) error {
	if record.RequestHash != purchase.RequestHash || record.NetworkID != config.Network.NetworkID || record.GenesisRootHash != config.Network.GenesisRootHash || record.GenesisFileHash != config.Network.GenesisFileHash || record.ActorCodeHash != config.ActorCodeHash || record.BuyerWallet != config.BuyerWallet {
		return errors.New("token journal belongs to another purchase, network, release or buyer")
	}
	pins, _, err := tokenPolicy(config.TokenAssets)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	opened, err := evidenceSession(ctx, config)
	if err != nil {
		return err
	}
	session, ok := opened.(tokenExportSession)
	if !ok {
		return errors.New("finalized reader does not support token evidence")
	}
	actor, requests, err := serviceactor.ResolveTokenRequests(ctx, session, record.Actor)
	if err != nil {
		return err
	}
	var admitted *serviceactor.TokenRequest
	for _, r := range requests {
		if hex.EncodeToString(r.Snapshot.RequestHash[:]) == record.RequestHash {
			if admitted != nil {
				return errors.New("multiple admitted token requests match the journal")
			}
			admitted = r
		}
	}
	if admitted == nil {
		return errors.New("no finalized admitted token request; no evidence written")
	}
	if record.CallTransactionHex != "" && (record.CallTransactionHex != admitted.Call.Hash || record.CallTransactionLT != admitted.Call.LT) {
		return errors.New("journal call differs from finalized token admission")
	}
	sender, err := nativecore.DeriveServiceActorTokenWallet(record.BuyerWallet, actor.Data.Route)
	if err != nil {
		return err
	}
	accounts := []string{record.BuyerWallet, sender, actor.OwnWallet}
	next := admitted.Call
	hops := make([]purchaseevidence.TokenFundingHop, 3)
	for i := 2; i >= 0; i-- {
		tx, err := provenFundingPredecessor(ctx, session, accounts[i], next)
		if err != nil {
			return fmt.Errorf("funding hop %d: %w", i, err)
		}
		hops[i] = purchaseevidence.TokenFundingHop{Account: accounts[i], Transaction: toschain.ActorTxID{LT: tx.LT, Hash: tx.Hash}}
		next = tx
	}
	request, err := serviceRequestFromTokenRecord(record)
	if err != nil {
		return err
	}
	bundle := &purchaseevidence.TokenBundle{Schema: purchaseevidence.TokenBundleSchema, Network: purchaseevidence.NetworkTuple{NetworkID: record.NetworkID, GenesisRootHash: record.GenesisRootHash, GenesisFileHash: record.GenesisFileHash}, Actor: record.Actor, ActorCodeHash: record.ActorCodeHash, BuyerWallet: record.BuyerWallet, QuotePackageBase64: record.PackageBase64, AcceptedQuoteBOC: record.AcceptedQuoteBOC, ServiceRequestBOC: base64.StdEncoding.EncodeToString(request.ToBOCWithOptions(cell.BOCSerializeOptions{})), SourceDigest: purchase.SourceDigest, Funding: hops, Call: toschain.ActorTxID{LT: admitted.Call.LT, Hash: admitted.Call.Hash}}
	verifyInput := purchaseevidence.TokenInput{Network: &nativev1.NetworkDomain{NetworkId: record.NetworkID, GenesisRootHash: record.GenesisRootHash, GenesisFileHash: record.GenesisFileHash}, Actor: record.Actor, ActorCodeHash: record.ActorCodeHash, Pins: pins, RequestHashes: []string{record.RequestHash}, Bundle: bundle}
	if found {
		verifyInput.Receipt = accepted.ReceiptBOC
		verifyInput.Artifact = accepted.Artifact
	}
	verdict := purchaseevidence.VerifyToken(ctx, session, verifyInput)
	if verdict.Result != purchaseevidence.ResultPass || len(verdict.Requests) != 1 {
		if err := printJSON(out, verdict); err != nil {
			return err
		}
		return errors.New("token purchase does not verify; no evidence written")
	}
	raw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if _, err := purchaseevidence.DecodeTokenBundle(raw); err != nil {
		return err
	}
	// This separate versioned manifest carries local policy and build provenance;
	// the portable token bundle remains exactly the verifier's strict schema.
	metadata := struct {
		Schema       string                         `json:"schema"`
		Tool         purchaseevidence.Tool          `json:"tool"`
		ExportedUnix int64                          `json:"exported_unix"`
		Budget       any                            `json:"budget"`
		TokenAssets  []tokenAssetConfig             `json:"token_assets"`
		Verdict      *purchaseevidence.TokenVerdict `json:"verdict"`
		Files        []purchaseevidence.FileDigest  `json:"files"`
	}{Schema: "tos.service.purchase-export.token.v1", Tool: evidenceTool(), ExportedUnix: time.Now().Unix(), Budget: config.Budget, TokenAssets: publicTokenAssets(config.TokenAssets), Verdict: verdict}
	contents := map[string][]byte{purchaseevidence.BundleFile: raw}
	if found {
		contents[purchaseevidence.ReceiptFile] = accepted.ReceiptBOC
		contents[purchaseevidence.ArtifactFile] = accepted.Artifact
	}
	names := []string{purchaseevidence.BundleFile}
	if found {
		names = append(names, purchaseevidence.ReceiptFile, purchaseevidence.ArtifactFile)
	}
	for _, name := range names {
		metadata.Files = append(metadata.Files, *fileDigest(name, contents[name]))
	}
	manifest, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	if err := os.Mkdir(outDir, 0700); err != nil {
		return err
	}
	for _, name := range names {
		if err := writeNewFile(filepath.Join(outDir, name), contents[name]); err != nil {
			return err
		}
	}
	if err := writeNewFile(filepath.Join(outDir, "export.json"), append(manifest, '\n')); err != nil {
		return err
	}
	directory, err := os.Open(outDir)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	files := append(metadata.Files, *fileDigest("export.json", append(manifest, '\n')))
	return printJSON(out, evidenceOutput{OutDir: outDir, Files: files, Result: verdict.Result, Checkpoint: verdict.Checkpoint.Seqno})
}

// fundingPredecessor selects an executed transaction by the exact message consumed
// by the next hop, never by nonce advancement or a matching amount alone.
func fundingPredecessor(history *toschain.TokenWalletHistory, account string, next toschain.TokenActorTransaction) (toschain.TokenActorTransaction, error) {
	var selected toschain.TokenActorTransaction
	if history == nil || history.Result != toschain.HistoryComplete || next.InboundMessageHash == "" || next.Sender != account {
		return selected, errors.New("funding history incomplete or next sender mismatched")
	}
	found := false
	for _, tx := range history.Transactions {
		for _, message := range tx.Outputs {
			if message.Hash == next.InboundMessageHash && !message.Bounced {
				if found || !tx.TookEffect || tx.Bounced || tx.LT == 0 || tx.Hash == "" {
					return selected, errors.New("funding predecessor ambiguous or did not execute")
				}
				selected = tx
				found = true
			}
		}
	}
	if !found {
		return selected, errors.New("funding predecessor absent")
	}
	return selected, nil
}

// serviceRequestFromTokenRecord reproduces the exact request, including the
// accepted-quote cell commitment, before any journal data is exported.
func serviceRequestFromTokenRecord(record buyersdk.CallRecord) (*cell.Cell, error) {
	const prefix = "tvm-cell-sha256:"
	if !strings.HasPrefix(record.QuoteCommitment, prefix) {
		return nil, errors.New("token quote commitment has no cell-hash prefix")
	}
	commitment, err := hex32(strings.TrimPrefix(record.QuoteCommitment, prefix))
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(record.AcceptedQuoteBOC)
	if err != nil || len(raw) > 2<<20 || base64.StdEncoding.EncodeToString(raw) != record.AcceptedQuoteBOC {
		return nil, errors.New("token accepted quote is not bounded canonical base64")
	}
	roots, err := cell.FromBOCMultiRoot(raw)
	if err != nil || len(roots) != 1 || !bytes.Equal(roots[0].Hash(), commitment[:]) {
		return nil, errors.New("token accepted quote differs from its journal commitment")
	}
	execution, err := hex32(record.ExecutionID)
	if err != nil {
		return nil, err
	}
	inputDigest, err := hex32(record.InputDigest)
	if err != nil {
		return nil, err
	}
	request, err := nativecore.BuildServiceRequestCellV1(nativecore.ServiceRequestV1{QuoteCommitment: commitment, ExecutionID: execution, InputDigest: inputDigest})
	if err != nil {
		return nil, err
	}
	expected, err := hex32(record.RequestHash)
	if err != nil || !bytes.Equal(request.Hash(), expected[:]) {
		return nil, errors.New("token request does not reproduce the journal request hash")
	}
	return request, nil
}

// provenFundingPredecessor treats discovery as a hint, then requires the exact
// transaction reached from this session's finalized wallet head. Neither the
// candidate's execution flags nor its outputs substitute for that proof.
func provenFundingPredecessor(ctx context.Context, session tokenExportSession, account string, next toschain.TokenActorTransaction) (toschain.TokenActorTransaction, error) {
	history, err := session.TokenWalletHistory(ctx, account, nil)
	if err != nil {
		return toschain.TokenActorTransaction{}, err
	}
	candidate, err := fundingPredecessor(history, account, next)
	if err != nil {
		return toschain.TokenActorTransaction{}, err
	}
	id := toschain.ActorTxID{LT: candidate.LT, Hash: candidate.Hash}
	proven, err := session.TokenWalletTransaction(ctx, account, id)
	if err != nil {
		return toschain.TokenActorTransaction{}, err
	}
	if proven == nil || proven.LT != id.LT || proven.Hash != id.Hash {
		return toschain.TokenActorTransaction{}, errors.New("funding proof returned another transaction")
	}
	exact := &toschain.TokenWalletHistory{Result: toschain.HistoryComplete, Transactions: []toschain.TokenActorTransaction{*proven}}
	return fundingPredecessor(exact, account, next)
}
