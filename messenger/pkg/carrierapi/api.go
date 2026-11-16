// Package carrierapi is the local boundary between the Messenger daemon and
// the process that carries its relay frames (OpenFox's chat RelayTransport).
//
// Three operations cross it, each on a mode-0600 Unix socket:
//
//   - carrier.carry, daemon to carrier: one complete frame and its
//     idempotency key; the carrier signs it into an Agent Packet, seals and
//     deposits it, and answers carried only once a relay accepted it;
//   - carrier.deliver, carrier to daemon: a frame of kind 1 or 4 from a
//     verified packet, with the packet's sender Agent; the daemon answers a
//     kind-2 frame to send back, an admission answer, retry or a refusal;
//   - carrier.delivery-ack, carrier to daemon: a kind-2 frame from a verified
//     packet, with the packet's sender Agent.
//
// The carrier gains no Messenger authority: it never sees plaintext, keys or
// session state, and the daemon re-verifies every frame it is handed.
package carrierapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/internal/localwire"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

const (
	RequestSchema  = "tos.messaging.carrier-request.v1"
	ResponseSchema = "tos.messaging.carrier-response.v1"

	// MaxMessageBytes holds one maximal frame in base64 with its JSON fields.
	MaxMessageBytes uint32 = 320 << 10
)

// Op names one carrier operation.
type Op string

const (
	OpCarry       Op = "carrier.carry"
	OpDeliver     Op = "carrier.deliver"
	OpDeliveryAck Op = "carrier.delivery-ack"
)

// Result is the answer class of one operation.
type Result string

const (
	// ResultCarried: a relay durably accepted the envelope (carry).
	ResultCarried Result = "carried"
	// ResultRetry: nothing durable happened; try the same request again. A
	// carrier leaves the inbound envelope unacknowledged at the relay.
	ResultRetry Result = "retry"
	// ResultRefused: permanently refused with Code; an inbound envelope is
	// relay-acknowledged.
	ResultRefused Result = "refused"
	// ResultAck: the daemon has a durable result for a copy; AckFrame is the
	// kind-2 frame to send back and AckOutcome its outcome (deliver).
	ResultAck Result = "ack"
	// ResultAdmitted: an evidence frame from an admitted peer was committed;
	// the carrier may store the frame's card (deliver).
	ResultAdmitted Result = "admitted"
	// ResultIgnored: an evidence frame from a stranger, or an ack with
	// nothing left to settle. Nothing was written (deliver, delivery-ack).
	ResultIgnored Result = "ignored"
	// ResultApplied: a delivery ack settled or rescheduled a copy.
	ResultApplied Result = "applied"
)

// Code is a fixed refusal. Nothing a frame contains is repeated in it.
type Code string

const (
	CodeInvalidRequest         Code = "invalid-request"
	CodeFrameMalformed         Code = "frame-malformed"
	CodeRelayEvidenceTooLarge  Code = "relay-evidence-too-large"
	CodeKindNotCarried         Code = "kind-not-carried"
	CodeSenderMismatch         Code = "sender-mismatch"
	CodeEvidenceRefused        Code = "evidence-refused"
	CodeNotAccepted            Code = "not-accepted"
	CodeNotAdmitted            Code = "not-admitted"
	CodeNoPeerCard             Code = "no-peer-card"
	CodePeerCap                Code = "peer-cap"
	CodePacketTooLarge         Code = "packet-too-large"
	CodeOperationNotServedHere Code = "operation-not-served"
)

var codes = map[Code]struct{}{
	CodeInvalidRequest: {}, CodeFrameMalformed: {}, CodeRelayEvidenceTooLarge: {}, CodeKindNotCarried: {},
	CodeSenderMismatch: {}, CodeEvidenceRefused: {}, CodeNotAccepted: {}, CodeNotAdmitted: {}, CodeNoPeerCard: {}, CodePeerCap: {},
	CodePacketTooLarge: {}, CodeOperationNotServedHere: {},
}

// Request is one operation.
type Request struct {
	Schema string `json:"schema"`
	Op     Op     `json:"op"`
	// Carry fields.
	RecipientAgentID       string `json:"recipient_agent_id,omitempty"`
	IdempotencyKey         string `json:"idempotency_key,omitempty"`
	WithdrawIdempotencyKey string `json:"withdraw_idempotency_key,omitempty"`
	ExpiresAtUnix          uint64 `json:"expires_at_unix,omitempty"`
	// Deliver and delivery-ack field: the Agent whose controller signed the
	// verified packet the frame arrived in.
	PacketSenderAgentID string `json:"packet_sender_agent_id,omitempty"`
	FrameBase64         string `json:"frame_base64"`
}

// Response is one answer.
type Response struct {
	Schema         string `json:"schema"`
	Result         Result `json:"result"`
	Code           Code   `json:"code,omitempty"`
	AckFrameBase64 string `json:"ack_frame_base64,omitempty"`
	AckOutcome     string `json:"ack_outcome,omitempty"`
}

// Frame returns the request's decoded frame bytes.
func (r Request) Frame() ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(r.FrameBase64)
	if err != nil || len(raw) == 0 || len(raw) > relayframe.MaxFrameBytes {
		return nil, errors.New("carrier request frame is not one bounded base64 frame")
	}
	return raw, nil
}

// AckFrame returns the response's decoded kind-2 frame.
func (r Response) AckFrame() ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(r.AckFrameBase64)
	if err != nil || len(raw) == 0 || len(raw) > relayframe.MaxFrameBytes {
		return nil, errors.New("carrier response ack frame is not one bounded base64 frame")
	}
	return raw, nil
}

// ValidateRequest enforces the fields each operation needs and refuses the
// fields it does not use.
func ValidateRequest(request Request) error {
	if request.Schema != RequestSchema {
		return errors.New("unsupported carrier request schema")
	}
	if _, err := request.Frame(); err != nil {
		return err
	}
	switch request.Op {
	case OpCarry:
		if !ids.Agent.MatchString(request.RecipientAgentID) || !validIdempotencyKey(request.IdempotencyKey) ||
			request.WithdrawIdempotencyKey != "" && (!validIdempotencyKey(request.WithdrawIdempotencyKey) ||
				request.WithdrawIdempotencyKey == request.IdempotencyKey) ||
			request.ExpiresAtUnix == 0 || request.PacketSenderAgentID != "" {
			return errors.New("invalid carrier.carry request")
		}
	case OpDeliver, OpDeliveryAck:
		if !ids.Agent.MatchString(request.PacketSenderAgentID) || request.RecipientAgentID != "" ||
			request.IdempotencyKey != "" || request.WithdrawIdempotencyKey != "" || request.ExpiresAtUnix != 0 {
			return errors.New("invalid carrier inbound request")
		}
	default:
		return errors.New("unknown carrier operation")
	}
	return nil
}

// ValidateResponse enforces the shape of each answer class.
func ValidateResponse(op Op, response Response) error {
	if response.Schema != ResponseSchema {
		return errors.New("unsupported carrier response schema")
	}
	if response.Result == ResultRefused {
		if _, known := codes[response.Code]; !known || response.AckFrameBase64 != "" || response.AckOutcome != "" {
			return errors.New("invalid carrier refusal")
		}
		return nil
	}
	if response.Code != "" {
		return errors.New("carrier answer carries a refusal code")
	}
	if response.Result == ResultRetry {
		if response.AckFrameBase64 != "" || response.AckOutcome != "" {
			return errors.New("invalid carrier retry")
		}
		return nil
	}
	allowed := false
	switch op {
	case OpCarry:
		allowed = response.Result == ResultCarried
	case OpDeliver:
		allowed = response.Result == ResultAck || response.Result == ResultAdmitted || response.Result == ResultIgnored
	case OpDeliveryAck:
		allowed = response.Result == ResultApplied || response.Result == ResultIgnored
	}
	if !allowed {
		return errors.New("carrier answer does not belong to the operation")
	}
	if response.Result == ResultAck {
		if _, err := response.AckFrame(); err != nil {
			return err
		}
		switch response.AckOutcome {
		case relayframe.OutcomeAccepted, relayframe.OutcomeDuplicate, relayframe.OutcomeHeld, relayframe.OutcomeRejected:
		default:
			return errors.New("carrier ack answer has an invalid outcome")
		}
		return nil
	}
	if response.AckFrameBase64 != "" || response.AckOutcome != "" {
		return errors.New("only an ack answer carries an ack frame")
	}
	return nil
}

func validIdempotencyKey(value string) bool {
	if len(value) != len("idem_")+64 || value[:len("idem_")] != "idem_" {
		return false
	}
	for _, character := range value[len("idem_"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// DecodeRequest strictly parses one request body.
func DecodeRequest(raw []byte) (Request, error) {
	var request Request
	if err := decodeStrict(raw, &request); err != nil {
		return Request{}, err
	}
	if err := ValidateRequest(request); err != nil {
		return Request{}, err
	}
	return request, nil
}

// DecodeResponse strictly parses one response body for an operation.
func DecodeResponse(op Op, raw []byte) (Response, error) {
	var response Response
	if err := decodeStrict(raw, &response); err != nil {
		return Response{}, err
	}
	if err := ValidateResponse(op, response); err != nil {
		return Response{}, err
	}
	return response, nil
}

func encodeRequest(request Request) ([]byte, error) {
	request.Schema = RequestSchema
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if len(encoded) > int(MaxMessageBytes) {
		return nil, errors.New("carrier request exceeds its bound")
	}
	return encoded, nil
}

func encodeResponse(op Op, response Response) ([]byte, error) {
	response.Schema = ResponseSchema
	if err := ValidateResponse(op, response); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	if len(encoded) > int(MaxMessageBytes) {
		return nil, errors.New("carrier response exceeds its bound")
	}
	return encoded, nil
}

func decodeStrict(raw []byte, value any) error {
	if len(raw) == 0 || len(raw) > int(MaxMessageBytes) {
		return errors.New("carrier message size is outside its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("carrier message is not strict JSON")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("carrier message has trailing JSON")
	}
	return nil
}

// Refusal builds a refused answer.
func Refusal(code Code) Response {
	return Response{Schema: ResponseSchema, Result: ResultRefused, Code: code}
}

// Retry builds a retry answer.
func Retry() Response { return Response{Schema: ResponseSchema, Result: ResultRetry} }

// readFrame and writeFrame bound every socket message.
func readFrame(reader io.Reader) ([]byte, error) { return localwire.ReadFrame(reader, MaxMessageBytes) }

func writeFrame(writer io.Writer, body []byte) error {
	return localwire.WriteFrame(writer, body, MaxMessageBytes)
}
