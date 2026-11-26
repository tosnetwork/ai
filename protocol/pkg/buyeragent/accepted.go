package buyeragent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"path/filepath"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

// AcceptedResult is a result the carrier accepted under frames 7.2: the
// Receipt BOC, the decoded Receipt and the artifact.
type AcceptedResult struct {
	AssetMaster  *[32]byte
	ResponseHash string
	ReceiptBOC   []byte
	Receipt      nativecore.SoftwareWorkReceiptV1
	Artifact     []byte
	AcceptedUnix int64
}

// AcceptedResults reads accepted results; Carrier implements it.
type AcceptedResults interface {
	AcceptedResult(requestHash string) (AcceptedResult, bool, error)
}

// AcceptedResult reads the result the carrier accepted for a purchase. The
// stored Receipt must still hash to the accepted response hash and the
// stored artifact to the Receipt's artifact digest, so a damaged store is
// an error, never a result.
func (c *Carrier) AcceptedResult(requestHash string) (AcceptedResult, bool, error) {
	return acceptedResultAt(c.config.StateDir, requestHash)
}

// ReadAcceptedResult reads, without opening a carrier, the result accepted
// for a purchase from the carrier state directory stateDir, under the same
// checks as Carrier.AcceptedResult. It writes nothing, so it is safe while
// the agent that owns the directory runs.
func ReadAcceptedResult(stateDir, requestHash string) (AcceptedResult, bool, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return AcceptedResult{}, false, errors.New("the carrier state directory must be absolute and clean")
	}
	if err := checkPrivateDir(stateDir); err != nil {
		return AcceptedResult{}, false, err
	}
	return acceptedResultAt(stateDir, requestHash)
}

func acceptedResultAt(stateDir, requestHash string) (AcceptedResult, bool, error) {
	if !hex64Pattern.MatchString(requestHash) {
		return AcceptedResult{}, false, errors.New("invalid request hash")
	}
	state, err := readReceivedAt(stateDir, requestHash)
	if err != nil {
		return AcceptedResult{}, false, err
	}
	if state.AcceptedResponseHash == "" {
		return AcceptedResult{}, false, nil
	}
	boc, err := base64.StdEncoding.Strict().DecodeString(state.ReceiptBase64)
	if err != nil {
		return AcceptedResult{}, false, errors.New("the stored Receipt is not Base64")
	}
	receipt, asset, hash, err := railwork.DecodeStoredReceipt(boc)
	if err != nil || hex.EncodeToString(hash[:]) != state.AcceptedResponseHash {
		return AcceptedResult{}, false, errors.New("the stored Receipt does not hash to the accepted response hash")
	}
	artifact, err := readPrivate(artifactPathAt(stateDir, requestHash))
	if err != nil {
		return AcceptedResult{}, false, err
	}
	sum := sha256.Sum256(artifact)
	if receipt.ArtifactDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		return AcceptedResult{}, false, errors.New("the stored artifact does not match its Receipt")
	}
	return AcceptedResult{AssetMaster: asset, ResponseHash: state.AcceptedResponseHash, ReceiptBOC: boc, Receipt: receipt,
		Artifact: artifact, AcceptedUnix: state.AcceptedUnix}, true, nil
}

// AcceptedView is an accepted result as a client receives it: the Receipt's
// fields and digests, every one checked against the purchase, and the
// Receipt and artifact bytes.
type AcceptedView struct {
	TokenFunding *TokenFundingView `json:"token_funding,omitempty"`
	RequestHash  string            `json:"request_hash"`
	Reference    string            `json:"purchase_reference"`
	ResponseHash string            `json:"response_hash"`
	AcceptedUnix int64             `json:"accepted_unix"`
	// The Receipt's fields (SOFTWARE_WORK_RECEIPT_TVM_V1); the agent
	// checked each against the purchase before accepting the result.
	QuoteCommitment string `json:"quote_commitment"`
	ExecutionID     string `json:"execution_id"`
	InputDigest     string `json:"input_digest"`
	SourceDigest    string `json:"source_digest"`
	ToolchainDigest string `json:"toolchain_digest"`
	ManifestDigest  string `json:"manifest_digest"`
	ProviderAgentID string `json:"provider_agent_id"`
	PriceNanoTOS    string `json:"price_nanotos"`
	ResultDigest    string `json:"result_digest"`
	ArtifactDigest  string `json:"artifact_digest"`
	ReportDigest    string `json:"report_digest"`
	CompletedAtUnix uint64 `json:"completed_at_unix"`
	ExitCode        int32  `json:"exit_code"`
	ReceiptBase64   string `json:"receipt_boc_base64"`
	ArtifactBase64  string `json:"artifact_base64"`
}

// Result returns the accepted result of a purchase. Before acceptance it
// refuses with MCP_BUYER_RESULT_NOT_READY and the purchase's status.
func (a *Agent) Result(requestHash string) (any, error) {
	a.mutex.Lock()
	record, purchase, err := a.loadLocked(requestHash)
	if err != nil {
		a.mutex.Unlock()
		return nil, err
	}
	status := a.viewOf(record, purchase)
	a.mutex.Unlock()
	if a.config.Accepted == nil {
		return status, refusal(CodeResultNotReady, "no result has been accepted for this purchase", nil)
	}
	accepted, found, err := a.config.Accepted.AcceptedResult(requestHash)
	if err != nil {
		return nil, err
	}
	if !found {
		return status, refusal(CodeResultNotReady, "no result has been accepted for this purchase", nil)
	}
	// The accepted Receipt binds this purchase; checked again here so a
	// result of another purchase never reaches the client.
	receipt := accepted.Receipt
	asset, err := recordAssetMaster(record)
	if err != nil {
		return nil, err
	}
	if (asset == nil) != (accepted.AssetMaster == nil) || (asset != nil && *asset != *accepted.AssetMaster) {
		return nil, errors.New("the accepted Receipt binds another asset")
	}
	if receipt.QuoteCommitment != record.QuoteCommitment || receipt.ProviderAgentID != purchase.ProviderAgentID ||
		receipt.SourceDigest != purchase.SourceDigest || receipt.SandboxDigest != purchase.ManifestDigest ||
		receipt.ChargedAtomicAmount != priceOfRecord(record) || receipt.ExitCode != 0 {
		return nil, errors.New("the accepted Receipt does not bind this purchase")
	}
	output, report, err := railwork.ArtifactMembers(accepted.Artifact)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(digestOf(output), []byte(receipt.ResultDigest)) || !bytes.Equal(digestOf(report), []byte(receipt.ReportDigest)) {
		return nil, errors.New("the accepted artifact does not match its Receipt")
	}
	return AcceptedView{TokenFunding: tokenFunding(record), RequestHash: requestHash, Reference: PurchaseReference(requestHash),
		ResponseHash: accepted.ResponseHash, AcceptedUnix: accepted.AcceptedUnix,
		QuoteCommitment: receipt.QuoteCommitment, ExecutionID: receipt.ExecutionID, InputDigest: receipt.InputDigest,
		SourceDigest: receipt.SourceDigest, ToolchainDigest: receipt.ToolchainDigest, ManifestDigest: receipt.SandboxDigest,
		ProviderAgentID: receipt.ProviderAgentID, PriceNanoTOS: record.PriceNanoTOS,
		ResultDigest: receipt.ResultDigest, ArtifactDigest: receipt.ArtifactDigest, ReportDigest: receipt.ReportDigest,
		CompletedAtUnix: receipt.CompletedAt, ExitCode: receipt.ExitCode,
		ReceiptBase64:  base64.StdEncoding.EncodeToString(accepted.ReceiptBOC),
		ArtifactBase64: base64.StdEncoding.EncodeToString(accepted.Artifact)}, nil
}

func digestOf(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return []byte("sha256:" + hex.EncodeToString(sum[:]))
}
