// Package agentpacketrelay is the Agent Packet Relay V1 mailbox: an HTTP
// service that stores end-to-end-encrypted envelopes for recipient Agents,
// and the client a sender or recipient uses to reach it.
//
// The relay has no authority. It never decrypts, never holds a key, never
// signs and never reads chain state; it checks only the clear envelope header
// with agentpacketseal.ParseEnvelope and deletes an envelope only for the
// party that presents the acknowledgement secret hashing to its ID. Finalized
// TOS state stays the only authority over the packets inside.
package agentpacketrelay

import (
	"encoding/hex"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// Wire schemas of the JSON bodies.
const (
	SchemaMailbox = "tos.service.agent-packet-relay.mailbox.v1"
	SchemaRelay   = "tos.service.agent-packet-relay.relay.v1"
	SchemaError   = "tos.service.agent-packet-relay.error.v1"
)

// Error codes. Each HTTP status the relay answers with an error body has
// exactly one code.
const (
	CodeInvalidRequest     = "invalid_request"
	CodeForbidden          = "forbidden"
	CodeNotFound           = "not_found"
	CodeMethodNotAllowed   = "method_not_allowed"
	CodeConflict           = "conflict"
	CodeGone               = "gone"
	CodeTooLarge           = "too_large"
	CodeExpiryOutOfBounds  = "expiry_out_of_bounds"
	CodeRateLimited        = "rate_limited"
	CodeQuotaExhausted     = "quota_exhausted"
	CodeUnavailable        = "unavailable"
	ContentTypeEnvelope    = "application/octet-stream"
	ContentTypeJSON        = "application/json"
	statusInsufficientSave = 507
)

// codeForStatus is the fixed error code of every error status.
var codeForStatus = map[int]string{
	400:                    CodeInvalidRequest,
	403:                    CodeForbidden,
	404:                    CodeNotFound,
	405:                    CodeMethodNotAllowed,
	409:                    CodeConflict,
	410:                    CodeGone,
	413:                    CodeTooLarge,
	422:                    CodeExpiryOutOfBounds,
	429:                    CodeRateLimited,
	statusInsufficientSave: CodeQuotaExhausted,
	503:                    CodeUnavailable,
}

// V1 bounds that no operator setting can raise.
const (
	// MaxEnvelopeBytes bounds one deposited envelope.
	MaxEnvelopeBytes = agentpacketseal.MaxEnvelopeBytes
	// MaxTTL is the longest an envelope is retained after receipt.
	MaxTTL = 24 * time.Hour
	// ExpirySkew is the clock tolerance on a deposited expires_at_unix
	// beyond MaxTTL.
	ExpirySkew = 5 * time.Minute
	// MaxPerRecipientEnvelopes is the per-recipient count quota ceiling and
	// the largest mailbox listing.
	MaxPerRecipientEnvelopes = 256
	// MaxPerRecipientBytes is the per-recipient byte quota ceiling.
	MaxPerRecipientBytes = 16 << 20
	// MaxPerClientRecipientEnvelopes is the per (client address, recipient)
	// count quota ceiling.
	MaxPerClientRecipientEnvelopes = 64
	// MaxResponseBytes bounds every response body except a downloaded
	// envelope.
	MaxResponseBytes = 64 << 10
	// MinEnvelopeBytes is the smallest envelope ParseEnvelope accepts: the
	// header, the encapsulated key, an 80-byte wrapper around a one-byte
	// packet, and the tag.
	MinEnvelopeBytes = agentpacketseal.EnvelopeHeaderSize + agentpacketseal.EncapsulatedKeySize +
		agentpacketseal.PlaintextHeaderSize + 1 + agentpacketseal.TagSize
)

// MailboxEntry is one listed envelope. Every value is the relay's
// unauthenticated word.
type MailboxEntry struct {
	EnvelopeID     [32]byte
	RecipientKeyID [agentpacketseal.KeyIDSize]byte
	Size           uint32
	ReceivedAtUnix uint64
	// ExpiresAtUnix is the effective expiry: the earlier of the envelope's
	// own expiry and its receipt plus the relay's retention.
	ExpiresAtUnix uint64
}

// Mailbox is a decoded listing.
type Mailbox struct {
	AgentID   string
	Envelopes []MailboxEntry
}

// RelayDescription is the advisory GET /v1/relay document.
type RelayDescription struct {
	MaxEnvelopeBytes         uint64
	MaxTTLSeconds            uint64
	PerRecipientMaxEnvelopes uint64
	PerRecipientMaxBytes     uint64
}

type wireMailbox struct {
	Schema    string             `json:"schema"`
	AgentID   string             `json:"agent_id"`
	Envelopes []wireMailboxEntry `json:"envelopes"`
}

type wireMailboxEntry struct {
	EnvelopeID     string `json:"envelope_id"`
	RecipientKeyID string `json:"recipient_key_id"`
	Size           uint32 `json:"size"`
	ReceivedAtUnix uint64 `json:"received_at_unix"`
	ExpiresAtUnix  uint64 `json:"expires_at_unix"`
}

type wireRelay struct {
	Schema                   string `json:"schema"`
	MaxEnvelopeBytes         uint64 `json:"max_envelope_bytes"`
	MaxTTLSeconds            uint64 `json:"max_ttl_seconds"`
	PerRecipientMaxEnvelopes uint64 `json:"per_recipient_max_envelopes"`
	PerRecipientMaxBytes     uint64 `json:"per_recipient_max_bytes"`
}

type wireError struct {
	Schema string `json:"schema"`
	Code   string `json:"code"`
}

// parseEnvelopeIDText parses the strict 64-lowercase-hex form of a non-zero
// envelope ID.
func parseEnvelopeIDText(value string) ([32]byte, bool) {
	var id [32]byte
	if len(value) != 64 {
		return id, false
	}
	for index := 0; index < len(value); index++ {
		c := value[index]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return id, false
		}
	}
	if _, err := hex.Decode(id[:], []byte(value)); err != nil || id == ([32]byte{}) {
		return [32]byte{}, false
	}
	return id, true
}

// parseAgentText parses the strict agent_<64 lowercase hex> form of a
// non-zero Agent ID.
func parseAgentText(value string) ([agentpacketseal.AgentDigestSize]byte, bool) {
	digest, err := agentpacketseal.AgentDigest(value)
	if err != nil || digest == ([agentpacketseal.AgentDigestSize]byte{}) {
		return [agentpacketseal.AgentDigestSize]byte{}, false
	}
	return digest, true
}
