package railwork

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

// ErrInvalidInput reports an argument a builder or derivation cannot use;
// it is a caller error, never a refusal of a counterparty's message.
var ErrInvalidInput = errors.New("railwork: invalid input")

// Domains hashed into input_digest and execution_id (sections 6.1, 6.2).
const (
	InputDomain       = "tos.openfox.rail-input.v1"
	ExecutionIDDomain = "tos.openfox.rail-execution-id.v1"
)

// InputDigest is the request's input commitment over a source archive's
// raw SHA-256 (section 6.1).
func InputDigest(sourceDigest [32]byte) [32]byte {
	hash := sha256.New()
	hash.Write([]byte(InputDomain))
	hash.Write([]byte{0})
	hash.Write(sourceDigest[:])
	var out [32]byte
	copy(out[:], hash.Sum(nil))
	return out
}

// ExecutionID commits an execution to the Agent the result returns to
// (section 6.2). The paid call carries it, so a task naming another return
// Agent cannot open it.
func ExecutionID(buyerAgentID string, nonce [32]byte) ([32]byte, error) {
	if !agentIDPattern.MatchString(buyerAgentID) {
		return [32]byte{}, fmt.Errorf("%w: the buyer is not an Agent ID", ErrInvalidInput)
	}
	hash := sha256.New()
	hash.Write([]byte(ExecutionIDDomain))
	hash.Write([]byte{0})
	hash.Write([]byte(buyerAgentID))
	hash.Write([]byte{0})
	hash.Write(nonce[:])
	var out [32]byte
	copy(out[:], hash.Sum(nil))
	return out, nil
}

// RequestHash is the call's request_hash: the cell hash of the NSR1
// service request over the Accepted Quote hash, the execution ID and the
// input digest (section 6.3; ACCEPTED_QUOTE_TVM_V1 "Request commitment").
// Every field must be non-zero.
func RequestHash(quoteHash, executionID, inputDigest [32]byte) ([32]byte, error) {
	root, err := nativecore.BuildServiceRequestCellV1(nativecore.ServiceRequestV1{
		QuoteCommitment: quoteHash, ExecutionID: executionID, InputDigest: inputDigest,
	})
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	var out [32]byte
	copy(out[:], root.Hash())
	return out, nil
}

// QuoteCommitment is the Accepted Quote of a proposal on a network: its
// cell hash and its tvm-cell-sha256 text.
func QuoteCommitment(network *nativev1.NetworkDomain, proposal *nativev1.QuoteProposalV1) ([32]byte, string, error) {
	build := nativecore.BuildAcceptedQuoteCommitment
	if proposal != nil && (proposal.Asset != nil || proposal.PriceAtomic != "") {
		build = nativecore.BuildAcceptedTokenQuoteCommitment
	}
	root, text, err := build(network, proposal)
	if err != nil {
		return [32]byte{}, "", fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	var out [32]byte
	copy(out[:], root.Hash())
	if text != "tvm-cell-sha256:"+hex.EncodeToString(out[:]) {
		return [32]byte{}, "", fmt.Errorf("%w: the Accepted Quote commitment does not name its cell", ErrInvalidInput)
	}
	return out, text, nil
}

func rawAddress(account [32]byte) string {
	return "0:" + hex.EncodeToString(account[:])
}

func decodeHex32(text string) ([32]byte, bool) {
	var out [32]byte
	if !hex64Pattern.MatchString(text) {
		return out, false
	}
	if _, err := hex.Decode(out[:], []byte(text)); err != nil {
		return out, false
	}
	return out, true
}
