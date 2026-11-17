package railwork

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const vectorPath = "../../../spec/test-vectors/service-actor-rail-work-frames-v1.json"

type vectorEdit struct {
	Offset int    `json:"offset"`
	Hex    string `json:"hex"`
}

type vectorFrameRef struct {
	Message      string       `json:"message"`
	Index        int          `json:"index"`
	Set          []vectorEdit `json:"set"`
	TruncateTo   *int         `json:"truncate_to"`
	AppendHex    string       `json:"append_hex"`
	ResultSHA256 string       `json:"result_sha256"`
}

type vectorFrame struct {
	Index       int    `json:"index"`
	HeaderHex   string `json:"header_hex"`
	DataOffset  int    `json:"data_offset"`
	DataLength  int    `json:"data_length"`
	FrameSHA256 string `json:"frame_sha256"`
}

type vectorMessage struct {
	Name          string         `json:"name"`
	Kind          int            `json:"kind"`
	RequestID     *uint64        `json:"request_id"`
	Fields        map[string]any `json:"fields"`
	MessageBase64 string         `json:"message_base64"`
	MessageSHA256 string         `json:"message_sha256"`
	HeaderJSON    string         `json:"header_json"`
	BodyLength    int            `json:"body_length"`
	Frames        []vectorFrame  `json:"frames"`
}

type vectorDocument struct {
	Schema    string         `json:"schema"`
	Constants map[string]any `json:"constants"`
	Binding   struct {
		Actor           string `json:"actor"`
		ActorAccountHex string `json:"actor_account_hex"`
		RequestID       uint64 `json:"request_id"`
		QuoteCommitment string `json:"quote_commitment"`
		ExecutionNonce  string `json:"execution_nonce_hex"`
		BuyerAgentID    string `json:"buyer_agent_id"`
		ExecutionIDHex  string `json:"execution_id_hex"`
		SourceDigest    string `json:"source_digest"`
		InputDigestHex  string `json:"input_digest_hex"`
		RequestHashHex  string `json:"request_hash_hex"`
	} `json:"binding"`
	Receipt struct {
		ArtifactBase64   string `json:"artifact_base64"`
		ArtifactDigest   string `json:"artifact_digest"`
		ExecutionIDHex   string `json:"execution_id_hex"`
		InputDigestHex   string `json:"input_digest_hex"`
		OutputLogBase64  string `json:"output_log_base64"`
		ProviderAgentID  string `json:"provider_agent_id"`
		ReceiptBOCBase64 string `json:"receipt_boc_base64"`
		ReportDigest     string `json:"report_digest"`
		ReportJSONBase64 string `json:"report_json_base64"`
		ResponseHashHex  string `json:"response_hash_hex"`
		ResultDigest     string `json:"result_digest"`
		SourceDigest     string `json:"source_digest"`
	} `json:"receipt"`
	Messages       []vectorMessage `json:"messages"`
	NegativeFrames []struct {
		Name  string         `json:"name"`
		Rule  string         `json:"rule"`
		Frame vectorFrameRef `json:"frame"`
	} `json:"negative_frames"`
	NegativeMessages []struct {
		Name   string `json:"name"`
		Kind   int    `json:"kind"`
		Rule   string `json:"rule"`
		Base64 string `json:"base64"`
	} `json:"negative_messages"`
	NegativeJoins []struct {
		Name   string           `json:"name"`
		Rule   string           `json:"rule"`
		Frames []vectorFrameRef `json:"frames"`
	} `json:"negative_joins"`
}

func loadVectors(t *testing.T) *vectorDocument {
	t.Helper()
	raw, err := os.ReadFile(filepath.FromSlash(vectorPath))
	if err != nil {
		t.Fatal(err)
	}
	var document vectorDocument
	if err = json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document.Schema != "tos.service.rail-work-frames.v1.vectors" {
		t.Fatalf("vector schema %q", document.Schema)
	}
	return &document
}

func mustHex32(t *testing.T, text string) [32]byte {
	t.Helper()
	value, ok := decodeHex32(text)
	if !ok {
		t.Fatalf("not hex32: %q", text)
	}
	return value
}

func mustBase64(t *testing.T, text string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var archiveRule = regexp.MustCompile(`^byte i is \((\d+) \+ 7\*i\) mod 256$`)

func vectorArchive(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	rule, _ := fields["archive_rule"].(string)
	size, _ := fields["archive_bytes"].(float64)
	match := archiveRule.FindStringSubmatch(rule)
	if match == nil || size <= 0 {
		t.Fatalf("archive rule %q size %v", rule, size)
	}
	seed, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, int(size))
	for index := range out {
		out[index] = byte((seed + 7*index) % 256)
	}
	return out
}

func (d *vectorDocument) binding(t *testing.T, message vectorMessage) Binding {
	t.Helper()
	requestID := d.Binding.RequestID
	if message.RequestID != nil {
		requestID = *message.RequestID
	}
	return Binding{
		ActorAccount: mustHex32(t, d.Binding.ActorAccountHex), RequestID: requestID,
		RequestHash: mustHex32(t, d.Binding.RequestHashHex),
	}
}

func (d *vectorDocument) messageBytes(t *testing.T, message vectorMessage) []byte {
	t.Helper()
	var raw []byte
	if message.MessageBase64 != "" {
		raw = mustBase64(t, message.MessageBase64)
	} else {
		header := []byte(message.HeaderJSON)
		raw = binary.BigEndian.AppendUint32(nil, uint32(len(header)))
		raw = append(append(raw, header...), vectorArchive(t, message.Fields)...)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != message.MessageSHA256 {
		t.Fatalf("%s: message digest differs from the vector", message.Name)
	}
	return raw
}

// positiveFrames encodes every positive message's frames with this package.
func (d *vectorDocument) positiveFrames(t *testing.T) map[string][][]byte {
	t.Helper()
	out := map[string][][]byte{}
	for _, message := range d.Messages {
		frames, err := EncodeMessageFrames(Kind(message.Kind), d.binding(t, message), d.messageBytes(t, message))
		if err != nil {
			t.Fatalf("%s: %v", message.Name, err)
		}
		out[message.Name] = frames
	}
	return out
}

func applyEdits(t *testing.T, positive map[string][][]byte, ref vectorFrameRef) []byte {
	t.Helper()
	frames, ok := positive[ref.Message]
	if !ok || ref.Index < 0 || ref.Index >= len(frames) {
		t.Fatalf("no positive frame %s/%d", ref.Message, ref.Index)
	}
	raw := bytes.Clone(frames[ref.Index])
	for _, edit := range ref.Set {
		value, err := hex.DecodeString(edit.Hex)
		if err != nil || edit.Offset < 0 || edit.Offset+len(value) > len(raw) {
			t.Fatalf("bad edit %+v", edit)
		}
		copy(raw[edit.Offset:], value)
	}
	if ref.TruncateTo != nil {
		if *ref.TruncateTo < 0 || *ref.TruncateTo > len(raw) {
			t.Fatalf("bad truncation %d", *ref.TruncateTo)
		}
		raw = raw[:*ref.TruncateTo]
	}
	tail, err := hex.DecodeString(ref.AppendHex)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, tail...)
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != ref.ResultSHA256 {
		t.Fatalf("edit of %s/%d does not give the recorded bytes", ref.Message, ref.Index)
	}
	return raw
}

func TestVectorConstantsMatchThePackage(t *testing.T) {
	document := loadVectors(t)
	want := map[string]float64{
		"frame_header_bytes": FrameHeaderBytes, "max_chunk_data": MaxChunkData, "max_chunks": MaxChunks,
		"max_message_header_bytes": MaxMessageHeaderBytes, "max_inline_input_bytes": MaxInlineInputBytes,
		"max_result_bytes": MaxResultBytes, "max_key_card_json_bytes": MaxKeyCardBytes,
		"max_task_message_bytes": MaxTaskMessageBytes, "max_result_message_bytes": MaxResultMessageBytes,
		"max_ack_message_bytes": MaxAckMessageBytes, "max_result_request_message_bytes": MaxResultRequestMessageBytes,
		"frame_version": float64(FrameVersion),
	}
	for name, value := range want {
		if got, ok := document.Constants[name].(float64); !ok || got != value {
			t.Errorf("constant %s: vector %v, package %v", name, document.Constants[name], value)
		}
	}
	if document.Constants["frame_magic_hex"] != fmt.Sprintf("%08x", FrameMagic) {
		t.Errorf("frame magic %v", document.Constants["frame_magic_hex"])
	}
	if MaxKeyCardBase64 != 21848 || MaxTaskMessageBytes != 1114116 || MaxResultMessageBytes != 1179652 ||
		MaxAckMessageBytes != 25948 {
		t.Error("section 10 bounds differ")
	}
}

func TestVectorDerivedValues(t *testing.T) {
	document := loadVectors(t)
	binding := document.Binding
	executionID, err := ExecutionID(binding.BuyerAgentID, mustHex32(t, binding.ExecutionNonce))
	if err != nil || hex.EncodeToString(executionID[:]) != binding.ExecutionIDHex {
		t.Fatalf("execution ID %x err=%v", executionID, err)
	}
	inputDigest := InputDigest(mustHex32(t, strings.TrimPrefix(binding.SourceDigest, "sha256:")))
	if hex.EncodeToString(inputDigest[:]) != binding.InputDigestHex {
		t.Fatalf("input digest %x", inputDigest)
	}
	quote := mustHex32(t, strings.TrimPrefix(binding.QuoteCommitment, "tvm-cell-sha256:"))
	requestHash, err := RequestHash(quote, executionID, inputDigest)
	if err != nil || hex.EncodeToString(requestHash[:]) != binding.RequestHashHex {
		t.Fatalf("request hash %x err=%v", requestHash, err)
	}
	if binding.Actor != "0:"+binding.ActorAccountHex ||
		(Binding{ActorAccount: mustHex32(t, binding.ActorAccountHex)}).Actor() != binding.Actor {
		t.Fatal("actor text")
	}
	receiptInput := InputDigest(mustHex32(t, strings.TrimPrefix(document.Receipt.SourceDigest, "sha256:")))
	if hex.EncodeToString(receiptInput[:]) != document.Receipt.InputDigestHex {
		t.Fatal("receipt input digest")
	}
}

// vectorReceiptBinding is the binding the vector Receipt was built for: its
// request is the task_with_card message, priced by the Receipt itself.
func vectorReceiptBinding(t *testing.T, document *vectorDocument) ReceiptBinding {
	t.Helper()
	receipt, _, err := DecodeReceipt(mustBase64(t, document.Receipt.ReceiptBOCBase64))
	if err != nil {
		t.Fatal(err)
	}
	price, ok := new(big.Int).SetString(receipt.ChargedAtomicAmount, 10)
	if !ok {
		t.Fatal("price")
	}
	return ReceiptBinding{
		QuoteCommitment: document.Binding.QuoteCommitment,
		ExecutionID:     mustHex32(t, document.Receipt.ExecutionIDHex),
		InputDigest:     mustHex32(t, document.Receipt.InputDigestHex),
		SourceDigest:    document.Receipt.SourceDigest, Price: price,
		ProviderAgentID: document.Receipt.ProviderAgentID, ToolchainDigest: receipt.ToolchainDigest,
		SandboxDigest: receipt.SandboxDigest,
	}
}

func TestVectorReceiptAndArtifact(t *testing.T) {
	document := loadVectors(t)
	receipt, hash, err := DecodeReceipt(mustBase64(t, document.Receipt.ReceiptBOCBase64))
	if err != nil || hex.EncodeToString(hash[:]) != document.Receipt.ResponseHashHex {
		t.Fatalf("receipt hash %x err=%v", hash, err)
	}
	if receipt.ArtifactDigest != document.Receipt.ArtifactDigest || receipt.ResultDigest != document.Receipt.ResultDigest ||
		receipt.ReportDigest != document.Receipt.ReportDigest || receipt.SourceDigest != document.Receipt.SourceDigest ||
		receipt.ProviderAgentID != document.Receipt.ProviderAgentID ||
		receipt.ExecutionID != "sha256:"+document.Receipt.ExecutionIDHex ||
		receipt.InputDigest != "sha256:"+document.Receipt.InputDigestHex {
		t.Fatalf("receipt fields %+v", receipt)
	}
	artifact := mustBase64(t, document.Receipt.ArtifactBase64)
	output, report, err := ArtifactMembers(artifact)
	if err != nil || !bytes.Equal(output, mustBase64(t, document.Receipt.OutputLogBase64)) ||
		!bytes.Equal(report, mustBase64(t, document.Receipt.ReportJSONBase64)) {
		t.Fatalf("artifact members err=%v", err)
	}
	binding := vectorReceiptBinding(t, document)
	rebuilt, rebuiltHash, err := BuildReceipt(binding, Outcome{
		ResultDigest: receipt.ResultDigest, ArtifactDigest: receipt.ArtifactDigest, ReportDigest: receipt.ReportDigest,
		CompletedAtUnix: receipt.CompletedAt,
	})
	if err != nil || rebuiltHash != hash || !bytes.Equal(rebuilt.Hash(), hash[:]) {
		t.Fatalf("rebuilt receipt %x err=%v", rebuiltHash, err)
	}
}

// decodeAndReencode decodes a positive message with its kind's decoder and
// encodes it again from the decoded values.
func decodeAndReencode(kind Kind, raw []byte) ([]byte, int, error) {
	switch kind {
	case KindTask:
		task, err := DecodeTask(raw)
		if err != nil {
			return nil, 0, err
		}
		again, err := EncodeTask(Task{Header: task.Header, Package: task.Package, Archive: task.Archive,
			BuyerKeyCard: task.BuyerKeyCard})
		return again, len(task.Archive), err
	case KindResult:
		result, err := DecodeResult(raw)
		if err != nil {
			return nil, 0, err
		}
		hash, ok := decodeHex32(result.Header.ResponseHash)
		if !ok {
			return nil, 0, errors.New("response hash")
		}
		again, err := EncodeResult(hash, result.Receipt, result.Artifact, result.ProviderKeyCard)
		return again, len(result.Artifact), err
	case KindResultAck:
		ack, err := DecodeAck(raw)
		if err != nil {
			return nil, 0, err
		}
		hash, ok := decodeHex32(ack.Header.ResponseHash)
		if !ok {
			return nil, 0, errors.New("response hash")
		}
		again, err := EncodeAck(hash, ack.BuyerKeyCard)
		return again, 0, err
	case KindResultRequest:
		request, err := DecodeResultRequest(raw)
		if err != nil {
			return nil, 0, err
		}
		again, err := EncodeResultRequest(request.BuyerKeyCard)
		return again, 0, err
	default:
		return nil, 0, errors.New("unknown kind")
	}
}

func TestVectorPositiveMessagesDecodeAndReencodeByteIdentically(t *testing.T) {
	document := loadVectors(t)
	if len(document.Messages) != 9 {
		t.Fatalf("%d positive messages", len(document.Messages))
	}
	for _, message := range document.Messages {
		raw := document.messageBytes(t, message)
		again, bodyLength, err := decodeAndReencode(Kind(message.Kind), raw)
		if err != nil {
			t.Errorf("%s: %v", message.Name, err)
			continue
		}
		if !bytes.Equal(again, raw) {
			t.Errorf("%s: re-encoding differs from the vector bytes", message.Name)
		}
		headerLength := binary.BigEndian.Uint32(raw[:4])
		if string(raw[4:4+headerLength]) != message.HeaderJSON || bodyLength != message.BodyLength {
			t.Errorf("%s: header or body length differs", message.Name)
		}
	}
}

func TestVectorPositiveMessagesCarryTheVectorBinding(t *testing.T) {
	document := loadVectors(t)
	artifact := mustBase64(t, document.Receipt.ArtifactBase64)
	for _, message := range document.Messages {
		raw := document.messageBytes(t, message)
		binding := document.binding(t, message)
		switch Kind(message.Kind) {
		case KindTask:
			task, err := DecodeTask(raw)
			if err != nil || task.Header.ExecutionID != document.Binding.ExecutionIDHex ||
				task.Header.RequestID != binding.RequestID || !bytes.Equal(task.Archive, vectorArchive(t, message.Fields)) {
				t.Errorf("%s: task binding err=%v", message.Name, err)
			}
			if card, _ := message.Fields["buyer_key_card_json"].(string); card != string(task.BuyerKeyCard) {
				t.Errorf("%s: buyer card", message.Name)
			}
		case KindResult:
			result, err := DecodeResult(raw)
			if err != nil || !bytes.Equal(result.Artifact, artifact) ||
				result.Header.ReceiptBOCBase64 != document.Receipt.ReceiptBOCBase64 ||
				result.Header.ResponseHash != document.Receipt.ResponseHashHex {
				t.Errorf("%s: result err=%v", message.Name, err)
			}
			if card, _ := message.Fields["provider_key_card_json"].(string); card != string(result.ProviderKeyCard) {
				t.Errorf("%s: provider card", message.Name)
			}
		case KindResultAck:
			ack, err := DecodeAck(raw)
			if err != nil || ack.Header.ResponseHash != document.Receipt.ResponseHashHex {
				t.Errorf("%s: ack err=%v", message.Name, err)
			}
		case KindResultRequest:
			if _, err := DecodeResultRequest(raw); err != nil {
				t.Errorf("%s: %v", message.Name, err)
			}
		}
	}
}

func TestVectorFramesSplitJoinAndAssembleExactly(t *testing.T) {
	document := loadVectors(t)
	for _, message := range document.Messages {
		raw := document.messageBytes(t, message)
		kind, binding := Kind(message.Kind), document.binding(t, message)
		encoded, err := EncodeMessageFrames(kind, binding, raw)
		if err != nil || len(encoded) != len(message.Frames) {
			t.Fatalf("%s: %d frames err=%v", message.Name, len(encoded), err)
		}
		decoded := make([]Frame, 0, len(encoded))
		for index, frameBytes := range encoded {
			want := message.Frames[index]
			digest := sha256.Sum256(frameBytes)
			if want.Index != index || hex.EncodeToString(frameBytes[:FrameHeaderBytes]) != want.HeaderHex ||
				hex.EncodeToString(digest[:]) != want.FrameSHA256 {
				t.Fatalf("%s: frame %d differs from the vector", message.Name, index)
			}
			frame, decodeErr := DecodeFrame(frameBytes)
			if decodeErr != nil || frame.Kind != kind || frame.Binding != binding ||
				!bytes.Equal(frame.Data, raw[want.DataOffset:want.DataOffset+want.DataLength]) {
				t.Fatalf("%s: frame %d decode err=%v", message.Name, index, decodeErr)
			}
			again, encodeErr := EncodeFrame(frame)
			if encodeErr != nil || !bytes.Equal(again, frameBytes) {
				t.Fatalf("%s: frame %d re-encode err=%v", message.Name, index, encodeErr)
			}
			if !IsRailPayload(frameBytes) || CheckRailPayload(frameBytes) != nil {
				t.Fatalf("%s: not a rail payload", message.Name)
			}
			decoded = append(decoded, frame)
		}
		reversed := make([]Frame, 0, len(decoded))
		for index := len(decoded) - 1; index >= 0; index-- {
			reversed = append(reversed, decoded[index])
		}
		joined, err := JoinFrames(reversed)
		if err != nil || !bytes.Equal(joined, raw) {
			t.Fatalf("%s: join err=%v", message.Name, err)
		}
		assembly, err := NewAssembly(document.Binding.BuyerAgentID, reversed[0])
		if err != nil {
			t.Fatalf("%s: %v", message.Name, err)
		}
		complete := len(reversed) == 1
		for _, frame := range reversed[1:] {
			if complete, err = assembly.Add(frame); err != nil {
				t.Fatalf("%s: %v", message.Name, err)
			}
		}
		// A duplicate delivery of the same bytes changes nothing.
		if again, dupErr := assembly.Add(reversed[0]); dupErr != nil || !again {
			t.Fatalf("%s: duplicate err=%v", message.Name, dupErr)
		}
		assembled, err := assembly.Message()
		if !complete || err != nil || !bytes.Equal(assembled.Body, raw) || assembled.Kind != kind ||
			assembled.Binding != binding || assembled.MessageDigest != sha256.Sum256(raw) {
			t.Fatalf("%s: assembly err=%v", message.Name, err)
		}
	}
}

func TestVectorNegativeFramesAreRefused(t *testing.T) {
	document := loadVectors(t)
	positive := document.positiveFrames(t)
	if len(document.NegativeFrames) != 18 {
		t.Fatalf("%d negative frames", len(document.NegativeFrames))
	}
	for _, item := range document.NegativeFrames {
		raw := applyEdits(t, positive, item.Frame)
		if _, err := DecodeFrame(raw); !errors.Is(err, ErrFrameInvalid) {
			t.Errorf("%s (%s): err=%v", item.Name, item.Rule, err)
		}
	}
}

func decodeAny(kind Kind, raw []byte) error {
	var err error
	switch kind {
	case KindTask:
		_, err = DecodeTask(raw)
	case KindResult:
		_, err = DecodeResult(raw)
	case KindResultAck:
		_, err = DecodeAck(raw)
	case KindResultRequest:
		_, err = DecodeResultRequest(raw)
	default:
		err = errors.New("unknown kind")
	}
	return err
}

func TestVectorNegativeMessagesAreRefused(t *testing.T) {
	document := loadVectors(t)
	if len(document.NegativeMessages) != 24 {
		t.Fatalf("%d negative messages", len(document.NegativeMessages))
	}
	for _, item := range document.NegativeMessages {
		if err := decodeAny(Kind(item.Kind), mustBase64(t, item.Base64)); !errors.Is(err, ErrMessageInvalid) {
			t.Errorf("%s (%s): err=%v", item.Name, item.Rule, err)
		}
	}
}

func TestVectorNegativeJoinsAreRefused(t *testing.T) {
	document := loadVectors(t)
	positive := document.positiveFrames(t)
	if len(document.NegativeJoins) != 4 {
		t.Fatalf("%d negative joins", len(document.NegativeJoins))
	}
	for _, item := range document.NegativeJoins {
		frames := make([]Frame, 0, len(item.Frames))
		for _, ref := range item.Frames {
			frame, err := DecodeFrame(applyEdits(t, positive, ref))
			if err != nil {
				t.Fatalf("%s: a member frame does not decode: %v", item.Name, err)
			}
			frames = append(frames, frame)
		}
		if _, err := JoinFrames(frames); !errors.Is(err, ErrJoinInvalid) {
			t.Errorf("%s (%s): err=%v", item.Name, item.Rule, err)
		}
		assemblyErr := func() error {
			assembly, err := NewAssembly(document.Binding.BuyerAgentID, frames[0])
			if err != nil {
				return err
			}
			for _, frame := range frames[1:] {
				if _, err = assembly.Add(frame); err != nil {
					return err
				}
			}
			_, err = assembly.Message()
			return err
		}()
		if !errors.Is(assemblyErr, ErrJoinInvalid) && !errors.Is(assemblyErr, ErrFrameConflict) {
			t.Errorf("%s: assembly err=%v", item.Name, assemblyErr)
		}
	}
}
