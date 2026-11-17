package railwork

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// ReceiptBinding is everything a Receipt must bind for one request, taken
// from finalized state and the Quote, never from the counterparty
// (SOFTWARE_WORK_RECEIPT_TVM_V1; section 7).
type ReceiptBinding struct {
	QuoteCommitment string
	ExecutionID     [32]byte
	InputDigest     [32]byte
	// SourceDigest is the sha256:<hex> digest of the source archive.
	SourceDigest    string
	Price           *big.Int
	ProviderAgentID string
	ToolchainDigest string
	// SandboxDigest is the manifest digest.
	SandboxDigest string
}

// Outcome is the content-addressed outcome of one execution, as the
// provider's runner reports it.
type Outcome struct {
	ResultDigest    string
	ArtifactDigest  string
	ReportDigest    string
	CompletedAtUnix uint64
	ExitCode        int
}

func notAccepted(reason string) error {
	return refuse(RefusalResultNotAccepted, reason)
}

// BuildReceipt builds the SoftwareWorkReceiptV1 of a successful execution
// and its response hash (the Receipt's cell hash).
func BuildReceipt(binding ReceiptBinding, outcome Outcome) (*cell.Cell, [32]byte, error) {
	var responseHash [32]byte
	if binding.Price == nil || binding.Price.Sign() <= 0 {
		return nil, responseHash, fmt.Errorf("%w: the Receipt needs a positive request price", ErrInvalidInput)
	}
	if outcome.ExitCode != 0 || outcome.CompletedAtUnix == 0 {
		return nil, responseHash, fmt.Errorf("%w: only a successful completed execution is attested", ErrInvalidInput)
	}
	root, _, err := nativecore.BuildSoftwareWorkReceiptCellV1(nativecore.SoftwareWorkReceiptV1{
		QuoteCommitment:     binding.QuoteCommitment,
		ExecutionID:         sha256Text(binding.ExecutionID),
		InputDigest:         sha256Text(binding.InputDigest),
		ResultDigest:        outcome.ResultDigest,
		ArtifactDigest:      outcome.ArtifactDigest,
		ReportDigest:        outcome.ReportDigest,
		SourceDigest:        binding.SourceDigest,
		ToolchainDigest:     binding.ToolchainDigest,
		SandboxDigest:       binding.SandboxDigest,
		ChargedAtomicAmount: binding.Price.String(),
		ProviderAgentID:     binding.ProviderAgentID,
		CompletedAt:         outcome.CompletedAtUnix,
		ExitCode:            0,
	})
	if err != nil {
		return nil, responseHash, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	copy(responseHash[:], root.Hash())
	return root, responseHash, nil
}

// DecodeReceipt parses a SoftwareWorkReceiptV1 BOC of at most
// MaxReceiptBytes and returns its fields and cell hash. The BOC must be the
// canonical single-root encoding of its cell (the bytes Cell.ToBOC gives):
// another serialization of the same cell, such as one without the CRC, with
// an index or with trailing bytes, is refused like any other bytes.
func DecodeReceipt(boc []byte) (nativecore.SoftwareWorkReceiptV1, [32]byte, error) {
	var hash [32]byte
	if len(boc) == 0 || len(boc) > MaxReceiptBytes {
		return nativecore.SoftwareWorkReceiptV1{}, hash, notAccepted("the Receipt is outside its bounds")
	}
	// The single-root rule is checked here rather than left to the cell
	// library's FromBOC, so it holds whatever that helper does.
	roots, err := cell.FromBOCMultiRoot(boc)
	if err != nil || len(roots) != 1 || roots[0] == nil {
		return nativecore.SoftwareWorkReceiptV1{}, hash, notAccepted("the Receipt BOC does not decode to exactly one root")
	}
	root := roots[0]
	if !bytes.Equal(root.ToBOC(), boc) {
		return nativecore.SoftwareWorkReceiptV1{}, hash, notAccepted("the Receipt BOC is not the canonical encoding of its cell")
	}
	receipt, err := nativecore.DecodeSoftwareWorkReceiptCellV1(root)
	if err != nil {
		return nativecore.SoftwareWorkReceiptV1{}, hash, refuseWith(RefusalResultNotAccepted, "the Receipt does not decode", err)
	}
	rebuilt, _, err := nativecore.BuildSoftwareWorkReceiptCellV1(receipt)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nativecore.SoftwareWorkReceiptV1{}, hash, notAccepted("the Receipt is not canonical")
	}
	copy(hash[:], root.Hash())
	return receipt, hash, nil
}

// CheckReceiptBinding requires a Receipt to bind exactly the request, the
// charge, the provider, the toolchain and the sandbox, and to describe a
// successful completed execution (section 7.2 item 2).
func CheckReceiptBinding(receipt nativecore.SoftwareWorkReceiptV1, binding ReceiptBinding) error {
	switch {
	case binding.Price == nil || binding.Price.Sign() <= 0:
		return fmt.Errorf("%w: no request price to check the Receipt against", ErrInvalidInput)
	case receipt.QuoteCommitment != binding.QuoteCommitment:
		return notAccepted("the Receipt binds another Quote commitment")
	case receipt.ExecutionID != sha256Text(binding.ExecutionID):
		return notAccepted("the Receipt binds another execution")
	case receipt.InputDigest != sha256Text(binding.InputDigest):
		return notAccepted("the Receipt binds another input")
	case receipt.SourceDigest != binding.SourceDigest:
		return notAccepted("the Receipt binds another source")
	case receipt.ChargedAtomicAmount != binding.Price.String():
		return notAccepted("the Receipt charges other than the request price")
	case receipt.ProviderAgentID != binding.ProviderAgentID:
		return notAccepted("the Receipt names another provider")
	case receipt.ToolchainDigest != binding.ToolchainDigest || receipt.SandboxDigest != binding.SandboxDigest:
		return notAccepted("the Receipt names another toolchain or sandbox than the manifest")
	case receipt.ExitCode != 0 || receipt.CompletedAt == 0:
		return notAccepted("the Receipt is not a successful completed execution")
	}
	return nil
}

// CheckAttestable is the attestor policy in front of the provider's
// attestor: the Receipt is canonical, binds the verified request exactly,
// and describes the runner's actual outcome. It returns the response hash.
func CheckAttestable(boc []byte, binding ReceiptBinding, outcome Outcome) ([32]byte, error) {
	receipt, hash, err := DecodeReceipt(boc)
	if err != nil {
		return [32]byte{}, err
	}
	if err = CheckReceiptBinding(receipt, binding); err != nil {
		return [32]byte{}, err
	}
	if outcome.ExitCode != 0 || receipt.ResultDigest != outcome.ResultDigest ||
		receipt.ArtifactDigest != outcome.ArtifactDigest || receipt.ReportDigest != outcome.ReportDigest ||
		receipt.CompletedAt != outcome.CompletedAtUnix {
		return [32]byte{}, notAccepted("the Receipt does not describe the runner's outcome")
	}
	return hash, nil
}

// CheckResultFrom is the first condition of section 7.2: a result counts
// only from the purchase's provider Agent and for the purchase's frame
// binding. It decodes the result.
func CheckResultFrom(message Message, providerAgentID string, binding Binding) (Result, error) {
	if !agentIDPattern.MatchString(providerAgentID) || binding.ActorAccount == ([32]byte{}) ||
		binding.RequestHash == ([32]byte{}) {
		return Result{}, ErrInvalidInput
	}
	if message.Kind != KindResult {
		return Result{}, notAccepted("the message is not a result")
	}
	if message.SenderAgentID != providerAgentID || message.Binding != binding {
		return Result{}, notAccepted("the result is not from the purchase's provider for its request")
	}
	return DecodeResult(message.Body)
}

// ValidateResult is the buyer's acceptance (section 7.2): the Receipt
// hashes to the finalized attested response hash and to the header's,
// binds the buyer's own request, and the artifact matches every digest the
// Receipt states.
func ValidateResult(result Result, binding ReceiptBinding, finalizedResponseHash [32]byte) error {
	if finalizedResponseHash == ([32]byte{}) {
		return fmt.Errorf("%w: no finalized response hash", ErrInvalidInput)
	}
	receipt, hash, err := DecodeReceipt(result.Receipt)
	if err != nil {
		return err
	}
	if hash != finalizedResponseHash {
		return notAccepted("the Receipt does not hash to the finalized response hash")
	}
	if result.Header.ResponseHash != hex.EncodeToString(hash[:]) {
		return notAccepted("the result names another response hash than its Receipt")
	}
	if err = CheckReceiptBinding(receipt, binding); err != nil {
		return err
	}
	if receipt.ArtifactDigest != sha256Text(sha256.Sum256(result.Artifact)) {
		return notAccepted("the artifact does not match the Receipt")
	}
	output, report, err := ArtifactMembers(result.Artifact)
	if err != nil {
		return err
	}
	if receipt.ResultDigest != sha256Text(sha256.Sum256(output)) ||
		receipt.ReportDigest != sha256Text(sha256.Sum256(report)) {
		return notAccepted("the artifact's output or report does not match the Receipt")
	}
	return nil
}

// ArtifactMembers reads exactly output.log and report.json, each once and
// each a regular file, from a software-work artifact tar.
func ArtifactMembers(artifact []byte) ([]byte, []byte, error) {
	if len(artifact) == 0 || len(artifact) > MaxResultBytes {
		return nil, nil, notAccepted("the artifact is outside its bounds")
	}
	reader := tar.NewReader(bytes.NewReader(artifact))
	members := map[string][]byte{}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > MaxResultBytes {
			return nil, nil, notAccepted("the artifact is not a bounded tar of regular files")
		}
		if header.Name != "output.log" && header.Name != "report.json" {
			return nil, nil, notAccepted("the artifact holds an unexpected member")
		}
		if _, seen := members[header.Name]; seen {
			return nil, nil, notAccepted("the artifact repeats a member")
		}
		// header.Size <= MaxResultBytes, so the one-byte overrun read that
		// detects a short member cannot overflow.
		body, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(body)) != header.Size {
			return nil, nil, notAccepted("an artifact member does not read")
		}
		members[header.Name] = body
	}
	output, okOutput := members["output.log"]
	report, okReport := members["report.json"]
	if !okOutput || !okReport {
		return nil, nil, notAccepted("the artifact lacks its output or report")
	}
	return output, report, nil
}

// CheckAck matches an acknowledgement to a delivered request (section
// 11.2): it must come from the request's buyer, for the request's frame
// binding, naming the delivered response hash. Otherwise it is refused as
// ack-unmatched.
func CheckAck(message Message, buyerAgentID string, binding Binding, responseHash [32]byte) (Ack, error) {
	if !agentIDPattern.MatchString(buyerAgentID) || responseHash == ([32]byte{}) {
		return Ack{}, ErrInvalidInput
	}
	if message.Kind != KindResultAck {
		return Ack{}, refuse(RefusalAckUnmatched, "the message is not an acknowledgement")
	}
	ack, err := DecodeAck(message.Body)
	if err != nil {
		return Ack{}, err
	}
	if message.SenderAgentID != buyerAgentID || message.Binding != binding ||
		ack.Header.ResponseHash != hex.EncodeToString(responseHash[:]) {
		return Ack{}, refuse(RefusalAckUnmatched, "the acknowledgement is not from the request's buyer for its result")
	}
	return ack, nil
}

// CheckResultRequest matches a result request to a request (section 11.2):
// it must come from the request's buyer for the request's frame binding.
// Whether a response exists to deliver and whether retention has ended are
// the provider's own state, refused by the caller as result-request-refused.
func CheckResultRequest(message Message, buyerAgentID string, binding Binding) (ResultRequest, error) {
	if !agentIDPattern.MatchString(buyerAgentID) {
		return ResultRequest{}, ErrInvalidInput
	}
	if message.Kind != KindResultRequest {
		return ResultRequest{}, refuse(RefusalResultRequestRefused, "the message is not a result request")
	}
	request, err := DecodeResultRequest(message.Body)
	if err != nil {
		return ResultRequest{}, err
	}
	if message.SenderAgentID != buyerAgentID || message.Binding != binding {
		return ResultRequest{}, refuse(RefusalResultRequestRefused, "it is not from the request's buyer")
	}
	return request, nil
}
