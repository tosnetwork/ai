// Package carrierapi is the local boundary between the Messenger daemon and
// the process that carries its relay frames (OpenFox's chat RelayTransport).
//
// Five operations cross it, each on a mode-0600 Unix socket:
//
//   - carrier.carry, daemon to carrier: one complete frame (any kind, a
//     kind-3 room part included) and its idempotency key; the carrier signs
//     it into an Agent Packet, seals and deposits it, and answers carried
//     only once a relay accepted it, with the smallest retention any relay
//     of the recipient's card advertises. The carrier refuses peer-cap when
//     the deposit would take the peer above 24 chat envelopes, or above 16
//     kind-3 envelopes;
//   - carrier.deliver, carrier to daemon: a frame of kind 1, 3 or 4 from a
//     verified packet, with the packet's sender Agent; the daemon answers a
//     kind-2 frame to send back (a copy ack or a room ack), admitted (an
//     admitted evidence frame, or an admitted kind-3 object or stored part:
//     the carrier may store the frame's card), ignored, retry or a refusal;
//   - carrier.delivery-ack, carrier to daemon: a kind-2 frame from a verified
//     packet, with the packet's sender Agent;
//   - carrier.room-cards, daemon to carrier: admit the chat cards a roster
//     taught under a room's admission, or forget a room's admission of some
//     Agents; a card stays stored while any other admission holds it;
//   - carrier.withdraw, daemon to carrier: withdraw the envelope journaled
//     under an idempotency key from every relay that holds it.
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
	// It also holds a room-cards request of every roster entry's card.
	MaxMessageBytes uint32 = 448 << 10

	// MaxRelayTTLSeconds is the Agent Packet relay V1 retention ceiling
	// (24 h); a relay may advertise less, never more.
	MaxRelayTTLSeconds uint64 = 86_400

	// MaxPeerEnvelopes is the carrier's in-flight cap of chat envelopes per
	// peer Agent across its relays; MaxPeerRoomEnvelopes is the share kind 3
	// may hold of it, so at least 8 stay for copies, acks and evidence.
	MaxPeerEnvelopes     = 24
	MaxPeerRoomEnvelopes = 16

	// MaxRoomCards bounds one carrier.room-cards request: every member of a
	// room but the receiver.
	MaxRoomCards = relayframe.MaxRosterEntries
)

// The largest valid request, a room-cards admission of 31 maximal cards,
// fits the message bound.
var _ [MaxMessageBytes - maxRoomCardsRequestBytes]struct{}

// maxRoomCardsRequestBytes bounds a maximal room-cards request: per card the
// base64 card, the Agent ID and the JSON around them, plus the fixed fields.
const maxRoomCardsRequestBytes = MaxRoomCards*(4*((relayframe.MaxCardBytes+2)/3)+128) + 1024

// PeerCapAllows reports whether one more envelope of a frame kind may be
// deposited to a peer that holds peerEnvelopes chat envelopes, of which
// peerRoomEnvelopes are kind 3.
func PeerCapAllows(kind uint8, peerEnvelopes, peerRoomEnvelopes int) bool {
	if peerEnvelopes < 0 || peerRoomEnvelopes < 0 || peerRoomEnvelopes > peerEnvelopes {
		return false
	}
	if peerEnvelopes >= MaxPeerEnvelopes {
		return false
	}
	return kind != relayframe.KindRoom || peerRoomEnvelopes < MaxPeerRoomEnvelopes
}

// Op names one carrier operation.
type Op string

const (
	OpCarry       Op = "carrier.carry"
	OpDeliver     Op = "carrier.deliver"
	OpDeliveryAck Op = "carrier.delivery-ack"
	OpRoomCards   Op = "carrier.room-cards"
	OpWithdraw    Op = "carrier.withdraw"
)

// RoomCardsAction is what a carrier.room-cards request does.
type RoomCardsAction string

const (
	// RoomCardsAdmit stores the given cards under the room's admission,
	// each only after it verifies as its Agent's chat card.
	RoomCardsAdmit RoomCardsAction = "admit"
	// RoomCardsForget drops the room's admission of the given Agents; a card
	// another admission (a contact, a session, another room) holds stays.
	RoomCardsForget RoomCardsAction = "forget"
)

// RoomCard is one chat card a roster taught.
type RoomCard struct {
	AgentID    string `json:"agent_id"`
	CardBase64 string `json:"card_base64"`
}

// Result is the answer class of one operation.
type Result string

const (
	// ResultCarried: a relay durably accepted the envelope (carry).
	// RelayTTLSeconds is then the smallest max_ttl_seconds that the relays of
	// the recipient's card advertise: how long the envelope is held at most.
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
	// ResultApplied: a delivery ack settled or rescheduled a copy
	// (delivery-ack), or the room's card admissions changed (room-cards;
	// RefusedAgentIDs names the cards that did not verify and were skipped).
	ResultApplied Result = "applied"
	// ResultWithdrawn: the envelope under the key is withdrawn, or its
	// withdrawal is journaled and retried by the carrier (withdraw).
	ResultWithdrawn Result = "withdrawn"
)

// Code is a fixed refusal. Nothing a frame contains is repeated in it.
type Code string

const (
	CodeInvalidRequest        Code = "invalid-request"
	CodeFrameMalformed        Code = "frame-malformed"
	CodeRelayEvidenceTooLarge Code = "relay-evidence-too-large"
	CodeKindNotCarried        Code = "kind-not-carried"
	CodeSenderMismatch        Code = "sender-mismatch"
	CodeEvidenceRefused       Code = "evidence-refused"
	CodeNotAccepted           Code = "not-accepted"
	CodeNotAdmitted           Code = "not-admitted"
	CodeNoPeerCard            Code = "no-peer-card"
	CodePeerCap               Code = "peer-cap"
	CodePacketTooLarge        Code = "packet-too-large"
	// CodeOperationNotServedHere: the side does not serve the operation at
	// all; permanent, never retried (see NotServed).
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
	FrameBase64         string `json:"frame_base64,omitempty"`
	// Room-cards fields: the room whose admission the cards are held under,
	// and either the cards to admit or the Agents to forget.
	RoomID          string          `json:"room_id,omitempty"`
	RoomCardsAction RoomCardsAction `json:"room_cards_action,omitempty"`
	RoomCards       []RoomCard      `json:"room_cards,omitempty"`
	ForgetAgentIDs  []string        `json:"forget_agent_ids,omitempty"`
}

// Response is one answer.
type Response struct {
	Schema         string `json:"schema"`
	Result         Result `json:"result"`
	Code           Code   `json:"code,omitempty"`
	AckFrameBase64 string `json:"ack_frame_base64,omitempty"`
	AckOutcome     string `json:"ack_outcome,omitempty"`
	// RelayTTLSeconds is set on a carried answer only, in
	// 1..MaxRelayTTLSeconds.
	RelayTTLSeconds uint64 `json:"relay_ttl_seconds,omitempty"`
	// RefusedAgentIDs is set on a room-cards applied answer only.
	RefusedAgentIDs []string `json:"refused_agent_ids,omitempty"`
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
	switch request.Op {
	case OpRoomCards, OpWithdraw:
		if request.FrameBase64 != "" || request.PacketSenderAgentID != "" || request.ExpiresAtUnix != 0 ||
			request.WithdrawIdempotencyKey != "" {
			return errors.New("invalid carrier control request")
		}
		if request.Op == OpWithdraw {
			if !ids.Agent.MatchString(request.RecipientAgentID) || !validIdempotencyKey(request.IdempotencyKey) ||
				request.RoomID != "" || request.RoomCardsAction != "" || len(request.RoomCards) != 0 || len(request.ForgetAgentIDs) != 0 {
				return errors.New("invalid carrier.withdraw request")
			}
			return nil
		}
		return validateRoomCards(request)
	}
	if request.RoomID != "" || request.RoomCardsAction != "" || len(request.RoomCards) != 0 || len(request.ForgetAgentIDs) != 0 {
		return errors.New("only carrier.room-cards names room cards")
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

// validateRoomCards checks a room-cards request: a room, and either 1..31
// distinct cards to admit or 1..31 distinct Agents to forget.
func validateRoomCards(request Request) error {
	if !ids.Room.MatchString(request.RoomID) || request.RecipientAgentID != "" || request.IdempotencyKey != "" {
		return errors.New("invalid carrier.room-cards request")
	}
	seen := map[string]struct{}{}
	unique := func(agentID string) bool {
		if !ids.Agent.MatchString(agentID) {
			return false
		}
		if _, duplicate := seen[agentID]; duplicate {
			return false
		}
		seen[agentID] = struct{}{}
		return true
	}
	switch request.RoomCardsAction {
	case RoomCardsAdmit:
		if len(request.RoomCards) == 0 || len(request.RoomCards) > MaxRoomCards || len(request.ForgetAgentIDs) != 0 {
			return errors.New("a room-cards admission names 1..31 cards")
		}
		for _, card := range request.RoomCards {
			raw, err := base64.StdEncoding.Strict().DecodeString(card.CardBase64)
			if !unique(card.AgentID) || err != nil || len(raw) == 0 || len(raw) > relayframe.MaxCardBytes {
				return errors.New("invalid room card")
			}
		}
	case RoomCardsForget:
		if len(request.ForgetAgentIDs) == 0 || len(request.ForgetAgentIDs) > MaxRoomCards || len(request.RoomCards) != 0 {
			return errors.New("a room-cards forget names 1..31 Agents")
		}
		for _, agentID := range request.ForgetAgentIDs {
			if !unique(agentID) {
				return errors.New("invalid room card Agent")
			}
		}
	default:
		return errors.New("unknown room-cards action")
	}
	return nil
}

// ValidateResponse enforces the shape of each answer class.
func ValidateResponse(op Op, response Response) error {
	if response.Schema != ResponseSchema {
		return errors.New("unsupported carrier response schema")
	}
	if response.Result == ResultCarried && op == OpCarry {
		if response.Code != "" || response.AckFrameBase64 != "" || response.AckOutcome != "" {
			return errors.New("invalid carrier carried answer")
		}
		return ValidateRelayTTL(response.RelayTTLSeconds)
	}
	if response.RelayTTLSeconds != 0 {
		return errors.New("only a carried answer reports a relay TTL")
	}
	if len(response.RefusedAgentIDs) != 0 {
		if op != OpRoomCards || response.Result != ResultApplied || len(response.RefusedAgentIDs) > MaxRoomCards {
			return errors.New("only a room-cards answer names refused cards")
		}
		for _, agentID := range response.RefusedAgentIDs {
			if !ids.Agent.MatchString(agentID) {
				return errors.New("invalid refused room card")
			}
		}
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
	case OpRoomCards:
		allowed = response.Result == ResultApplied
	case OpWithdraw:
		allowed = response.Result == ResultWithdrawn || response.Result == ResultIgnored
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

// Withdrawn builds a withdrawn answer.
func Withdrawn() Response { return Response{Schema: ResponseSchema, Result: ResultWithdrawn} }

// ErrRelayTTL is a relay TTL outside 1..MaxRelayTTLSeconds.
var ErrRelayTTL = errors.New("carrier relay TTL is outside 1s..24h")

// ValidateRelayTTL checks a reported relay TTL in seconds.
func ValidateRelayTTL(seconds uint64) error {
	if seconds == 0 || seconds > MaxRelayTTLSeconds {
		return ErrRelayTTL
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

// Carried builds a carried answer reporting the recipient card's smallest
// advertised relay TTL.
func Carried(relayTTLSeconds uint64) Response {
	return Response{Schema: ResponseSchema, Result: ResultCarried, RelayTTLSeconds: relayTTLSeconds}
}

// Retry builds a retry answer.
func Retry() Response { return Response{Schema: ResponseSchema, Result: ResultRetry} }

// readFrame and writeFrame bound every socket message.
func readFrame(reader io.Reader) ([]byte, error) { return localwire.ReadFrame(reader, MaxMessageBytes) }

func writeFrame(writer io.Writer, body []byte) error {
	return localwire.WriteFrame(writer, body, MaxMessageBytes)
}
