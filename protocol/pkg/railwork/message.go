package railwork

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

// Schema identifiers (section 13).
const (
	TaskSchema          = "tos.openfox.rail-task.v1"
	ResultSchema        = "tos.openfox.rail-result.v1"
	AckSchema           = "tos.openfox.rail-result-ack.v1"
	ResultRequestSchema = "tos.openfox.rail-result-request.v1"

	// MaxCapabilityVersionBytes bounds a task's capability_version.
	MaxCapabilityVersionBytes = 128

	zeroHex64 = "0000000000000000000000000000000000000000000000000000000000000000"
)

// printableVersion reports whether a capability_version is 1 to 128 bytes of
// printable ASCII 0x21 to 0x7e (section 5.1), the Registry's protocol text.
func printableVersion(version string) bool {
	if version == "" || len(version) > MaxCapabilityVersionBytes {
		return false
	}
	for index := 0; index < len(version); index++ {
		if version[index] < 0x21 || version[index] > 0x7e {
			return false
		}
	}
	return true
}

// responseHashText reports whether a response hash is 64 lowercase hex and
// not all zero (sections 5.2, 5.3).
func responseHashText(value string) bool {
	return hex64Pattern.MatchString(value) && value != zeroHex64
}

var (
	agentIDPattern    = regexp.MustCompile(`^agent_[0-9a-f]{64}$`)
	capabilityPattern = regexp.MustCompile(`^cap_[0-9a-f]{64}$`)
	walletPattern     = regexp.MustCompile(`^0:[0-9a-f]{64}$`)
	hex64Pattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sha256Pattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// quoteCommitmentPattern is an Accepted Quote commitment.
	quoteCommitmentPattern = regexp.MustCompile(`^tvm-cell-sha256:[0-9a-f]{64}$`)
)

// TaskHeader is the canonical header of a task (section 5.1). Every field
// is a claim the provider proves again from finalized state.
type TaskHeader struct {
	Schema            string `json:"schema"`
	BuyerAgentID      string `json:"buyer_agent_id"`
	BuyerWallet       string `json:"buyer_wallet"`
	CapabilityID      string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	PackageBase64     string `json:"package_base64"`
	ExecutionID       string `json:"execution_id"`
	ExecutionNonce    string `json:"execution_nonce"`
	SourceDigest      string `json:"source_digest"`
	RequestID         uint64 `json:"request_id"`
	CallLT            uint64 `json:"call_lt"`
	CallHash          string `json:"call_hash"`
	BuyerKeyCard      string `json:"buyer_key_card_base64,omitempty"`
}

// Task is a task message: its header, the serialized Quote package, the
// source archive, and the buyer's key card packet JSON (empty when absent).
type Task struct {
	Header       TaskHeader
	Package      []byte
	Archive      []byte
	BuyerKeyCard []byte
}

// ResultHeader is the canonical header of a result (section 5.2).
type ResultHeader struct {
	Schema           string `json:"schema"`
	ResponseHash     string `json:"response_hash"`
	ReceiptBOCBase64 string `json:"receipt_boc_base64"`
	ProviderKeyCard  string `json:"provider_key_card_base64,omitempty"`
}

// Result is a result message: the Receipt BOC, the artifact, and the
// provider's key card packet JSON (empty when absent).
type Result struct {
	Header          ResultHeader
	Receipt         []byte
	Artifact        []byte
	ProviderKeyCard []byte
}

// AckHeader is the canonical header of a result acknowledgement (5.3).
type AckHeader struct {
	Schema       string `json:"schema"`
	ResponseHash string `json:"response_hash"`
	BuyerKeyCard string `json:"buyer_key_card_base64,omitempty"`
}

// Ack is a result acknowledgement.
type Ack struct {
	Header       AckHeader
	BuyerKeyCard []byte
}

// ResultRequestHeader is the canonical header of a result request (5.4).
// The request it names is the frame binding.
type ResultRequestHeader struct {
	Schema       string `json:"schema"`
	BuyerKeyCard string `json:"buyer_key_card_base64,omitempty"`
}

// ResultRequest is a result request.
type ResultRequest struct {
	Header       ResultRequestHeader
	BuyerKeyCard []byte
}

type header interface {
	TaskHeader | ResultHeader | AckHeader | ResultRequestHeader
}

func invalidMessage(reason string) error {
	return refuse(RefusalMessageInvalid, reason)
}

// strictBase64 decodes canonical standard Base64 with padding: no line
// breaks, no non-zero pad bits, nothing the encoder would not emit.
func strictBase64(text string) ([]byte, bool) {
	raw, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != text {
		return nil, false
	}
	return raw, true
}

// decodeKeyCard decodes an optional key card field: absent is empty, a
// present card is canonical Base64 of 1 to MaxKeyCardBytes bytes.
func decodeKeyCard(text string) ([]byte, error) {
	if text == "" {
		return nil, nil
	}
	if len(text) > MaxKeyCardBase64 {
		return nil, invalidMessage("the key card exceeds its bound")
	}
	card, ok := strictBase64(text)
	if !ok || len(card) == 0 || len(card) > MaxKeyCardBytes {
		return nil, invalidMessage("the key card is not canonical Base64 of a bounded card")
	}
	return card, nil
}

func encodeKeyCard(card []byte) (string, error) {
	if len(card) > MaxKeyCardBytes {
		return "", invalidMessage("the key card exceeds its bound")
	}
	if len(card) == 0 {
		return "", nil
	}
	return base64.StdEncoding.EncodeToString(card), nil
}

// encodeMessage writes header_length, the canonical header and the body.
// The header must decode back to exactly itself, so an encoder never emits
// a message its decoder refuses.
func encodeMessage[H header](value H, body []byte, bound int) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, invalidMessage("the header does not encode")
	}
	if len(encoded) == 0 || len(encoded) > MaxMessageHeaderBytes {
		return nil, invalidMessage("the header is outside its bounds")
	}
	var back H
	if err = decodeHeader(encoded, &back); err != nil || back != value {
		return nil, invalidMessage("the header has no canonical encoding")
	}
	total := 4 + len(encoded) + len(body)
	if total > bound {
		return nil, invalidMessage("the message exceeds its bound")
	}
	out := binary.BigEndian.AppendUint32(make([]byte, 0, total), uint32(len(encoded)))
	out = append(out, encoded...)
	return append(out, body...), nil
}

// decodeHeader decodes one canonical JSON header: known fields only, one
// value, and bytes equal to the canonical encoding of the decoded value.
func decodeHeader[H header](raw []byte, value *H) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return invalidMessage("the header does not decode")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return invalidMessage("the header has trailing data")
	}
	reencoded, err := json.Marshal(*value)
	if err != nil || !bytes.Equal(reencoded, raw) {
		return invalidMessage("the header is not canonical")
	}
	return nil
}

func decodeMessage[H header](raw []byte, bound int, value *H) ([]byte, error) {
	if len(raw) < 4 || len(raw) > bound {
		return nil, invalidMessage("the message is outside its bounds")
	}
	length := binary.BigEndian.Uint32(raw[:4])
	if length == 0 || length > MaxMessageHeaderBytes || uint64(length) > uint64(len(raw)-4) {
		return nil, invalidMessage("the header length is invalid")
	}
	end := 4 + int(length)
	if err := decodeHeader(raw[4:end], value); err != nil {
		return nil, err
	}
	return raw[end:], nil
}

func sha256Text(value [32]byte) string {
	return "sha256:" + hex.EncodeToString(value[:])
}

func validateTaskHeader(header TaskHeader, archiveBytes int) error {
	switch {
	case header.Schema != TaskSchema:
		return invalidMessage("the task schema is wrong")
	case !agentIDPattern.MatchString(header.BuyerAgentID):
		return invalidMessage("buyer_agent_id is not an Agent ID")
	case !walletPattern.MatchString(header.BuyerWallet):
		return invalidMessage("buyer_wallet is not a workchain-0 raw address")
	case !capabilityPattern.MatchString(header.CapabilityID):
		return invalidMessage("capability_id is not a Capability ID")
	case !printableVersion(header.CapabilityVersion):
		return invalidMessage("capability_version is not 1 to 128 bytes of 0x21 to 0x7e")
	case header.PackageBase64 == "":
		return invalidMessage("package_base64 is empty")
	case len(header.PackageBase64) > MaxPackageBase64:
		return invalidMessage("package_base64 exceeds its bound")
	case !hex64Pattern.MatchString(header.ExecutionID):
		return invalidMessage("execution_id is not 64 lowercase hex")
	case !hex64Pattern.MatchString(header.ExecutionNonce):
		return invalidMessage("execution_nonce is not 64 lowercase hex")
	case !sha256Pattern.MatchString(header.SourceDigest):
		return invalidMessage("source_digest is not a sha256 digest")
	case header.CallLT == 0:
		return invalidMessage("call_lt is zero")
	case !hex64Pattern.MatchString(header.CallHash):
		return invalidMessage("call_hash is not 64 lowercase hex")
	case archiveBytes <= 0 || archiveBytes > MaxInlineInputBytes:
		return invalidMessage("the source archive is outside 1 to 1048576 bytes")
	}
	return nil
}

// EncodeTask builds a task message. It sets the schema, package_base64,
// source_digest and buyer_key_card_base64 from the task's bytes; a header
// that already holds other values for them is refused.
func EncodeTask(task Task) ([]byte, error) {
	header := task.Header
	if header.Schema == "" {
		header.Schema = TaskSchema
	}
	packageText := base64.StdEncoding.EncodeToString(task.Package)
	sourceDigest := sha256Text(sha256.Sum256(task.Archive))
	card, err := encodeKeyCard(task.BuyerKeyCard)
	if err != nil {
		return nil, err
	}
	if (header.PackageBase64 != "" && header.PackageBase64 != packageText) ||
		(header.SourceDigest != "" && header.SourceDigest != sourceDigest) ||
		(header.BuyerKeyCard != "" && header.BuyerKeyCard != card) {
		return nil, invalidMessage("the task header disagrees with the task's bytes")
	}
	if len(task.Package) == 0 || len(task.Package) > MaxPackageBytes {
		return nil, invalidMessage("the task carries no Quote package or one over its bound")
	}
	header.PackageBase64, header.SourceDigest, header.BuyerKeyCard = packageText, sourceDigest, card
	if err = validateTaskHeader(header, len(task.Archive)); err != nil {
		return nil, err
	}
	return encodeMessage(header, task.Archive, MaxTaskMessageBytes)
}

// DecodeTask parses a task message: canonical header, archive within its
// bound and matching source_digest, strict Base64 package and key card.
func DecodeTask(raw []byte) (Task, error) {
	var header TaskHeader
	archive, err := decodeMessage(raw, MaxTaskMessageBytes, &header)
	if err != nil {
		return Task{}, err
	}
	if err = validateTaskHeader(header, len(archive)); err != nil {
		return Task{}, err
	}
	card, err := decodeKeyCard(header.BuyerKeyCard)
	if err != nil {
		return Task{}, err
	}
	if header.SourceDigest != sha256Text(sha256.Sum256(archive)) {
		return Task{}, invalidMessage("the source archive does not match source_digest")
	}
	pkg, ok := strictBase64(header.PackageBase64)
	if !ok || len(pkg) == 0 || len(pkg) > MaxPackageBytes {
		return Task{}, invalidMessage("package_base64 is not canonical Base64 of a package of 1 to MaxPackageBytes bytes")
	}
	return Task{Header: header, Package: pkg, Archive: bytes.Clone(archive), BuyerKeyCard: card}, nil
}

// EncodeResult builds a result message; providerKeyCard may be empty.
func EncodeResult(responseHash [32]byte, receiptBOC, artifact, providerKeyCard []byte) ([]byte, error) {
	if responseHash == ([32]byte{}) {
		return nil, invalidMessage("the response hash is zero")
	}
	if len(receiptBOC) == 0 || len(receiptBOC) > MaxReceiptBytes || len(artifact) == 0 || len(artifact) > MaxResultBytes {
		return nil, invalidMessage("the result is empty or oversized")
	}
	card, err := encodeKeyCard(providerKeyCard)
	if err != nil {
		return nil, err
	}
	header := ResultHeader{
		Schema: ResultSchema, ResponseHash: hex.EncodeToString(responseHash[:]),
		ReceiptBOCBase64: base64.StdEncoding.EncodeToString(receiptBOC), ProviderKeyCard: card,
	}
	return encodeMessage(header, artifact, MaxResultMessageBytes)
}

// DecodeResult parses a result message.
func DecodeResult(raw []byte) (Result, error) {
	var header ResultHeader
	artifact, err := decodeMessage(raw, MaxResultMessageBytes, &header)
	if err != nil {
		return Result{}, err
	}
	switch {
	case header.Schema != ResultSchema:
		return Result{}, invalidMessage("the result schema is wrong")
	case !responseHashText(header.ResponseHash):
		return Result{}, invalidMessage("response_hash is not 64 lowercase hex, or is all zero")
	case len(artifact) == 0 || len(artifact) > MaxResultBytes:
		return Result{}, invalidMessage("the artifact is outside 1 to 1114112 bytes")
	case len(header.ReceiptBOCBase64) > MaxReceiptBase64:
		return Result{}, invalidMessage("receipt_boc_base64 exceeds its bound")
	}
	card, err := decodeKeyCard(header.ProviderKeyCard)
	if err != nil {
		return Result{}, err
	}
	receipt, ok := strictBase64(header.ReceiptBOCBase64)
	if !ok || len(receipt) == 0 || len(receipt) > MaxReceiptBytes {
		return Result{}, invalidMessage("receipt_boc_base64 is not canonical Base64 of a 1 to 512-byte Receipt")
	}
	return Result{Header: header, Receipt: receipt, Artifact: bytes.Clone(artifact), ProviderKeyCard: card}, nil
}

// EncodeAck builds a result acknowledgement; buyerKeyCard may be empty.
func EncodeAck(responseHash [32]byte, buyerKeyCard []byte) ([]byte, error) {
	if responseHash == ([32]byte{}) {
		return nil, invalidMessage("the response hash is zero")
	}
	card, err := encodeKeyCard(buyerKeyCard)
	if err != nil {
		return nil, err
	}
	header := AckHeader{Schema: AckSchema, ResponseHash: hex.EncodeToString(responseHash[:]), BuyerKeyCard: card}
	return encodeMessage(header, nil, MaxAckMessageBytes)
}

// DecodeAck parses a result acknowledgement.
func DecodeAck(raw []byte) (Ack, error) {
	var header AckHeader
	rest, err := decodeMessage(raw, MaxAckMessageBytes, &header)
	if err != nil {
		return Ack{}, err
	}
	switch {
	case len(rest) != 0:
		return Ack{}, invalidMessage("an acknowledgement has a body")
	case header.Schema != AckSchema:
		return Ack{}, invalidMessage("the acknowledgement schema is wrong")
	case !responseHashText(header.ResponseHash):
		return Ack{}, invalidMessage("response_hash is not 64 lowercase hex, or is all zero")
	}
	card, err := decodeKeyCard(header.BuyerKeyCard)
	if err != nil {
		return Ack{}, err
	}
	return Ack{Header: header, BuyerKeyCard: card}, nil
}

// EncodeResultRequest builds a result request; buyerKeyCard may be empty.
func EncodeResultRequest(buyerKeyCard []byte) ([]byte, error) {
	card, err := encodeKeyCard(buyerKeyCard)
	if err != nil {
		return nil, err
	}
	return encodeMessage(ResultRequestHeader{Schema: ResultRequestSchema, BuyerKeyCard: card}, nil,
		MaxResultRequestMessageBytes)
}

// DecodeResultRequest parses a result request.
func DecodeResultRequest(raw []byte) (ResultRequest, error) {
	var header ResultRequestHeader
	rest, err := decodeMessage(raw, MaxResultRequestMessageBytes, &header)
	if err != nil {
		return ResultRequest{}, err
	}
	switch {
	case len(rest) != 0:
		return ResultRequest{}, invalidMessage("a result request has a body")
	case header.Schema != ResultRequestSchema:
		return ResultRequest{}, invalidMessage("the result request schema is wrong")
	}
	card, err := decodeKeyCard(header.BuyerKeyCard)
	if err != nil {
		return ResultRequest{}, err
	}
	return ResultRequest{Header: header, BuyerKeyCard: card}, nil
}
