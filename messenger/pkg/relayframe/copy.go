package relayframe

import (
	"bytes"
	"regexp"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
)

// CopySchema names the kind-1 object: exactly the fields of one sealed device
// copy, length-prefixed so the ciphertext is not base64-encoded twice.
const CopySchema = "tos.messaging.relay-delivery.v1"

// Bounds of a copy object.
const (
	// MinCiphertextBytes and MaxCiphertextBytes repeat the envelope and
	// journal bounds a sealed copy already satisfies.
	MinCiphertextBytes = 32
	MaxCiphertextBytes = 160<<10 + 4<<10
	// MaxSealOverheadBytes is what sealing may add to an Event payload: the
	// journal bound on a ciphertext less its bound on a payload.
	MaxSealOverheadBytes = 4 << 10
	// MaxBootstrapBytes bounds the first-contact bootstrap JSON one copy
	// carries: one sender bundle with maximal material and an initial message
	// at its bound, each in base64 inside the JSON, with the longest network
	// identifier in its most-escaped JSON form (16,951 bytes, measured by the
	// package tests).
	MaxBootstrapBytes = 18 << 10
	// MaxAdmissionTokenBytes repeats the envelope bound on an admission token.
	MaxAdmissionTokenBytes = 256

	idBytes           = 68 // evt_, ses_, mep_ and dev_ followed by 64 hex.
	conversationBytes = 69 // conv_ followed by 64 hex.
	copyFixedBytes    = len(canon.DomainRelayDelivery) + 4*(4+idBytes) + (4 + conversationBytes) +
		4 + 4 + 4 + 8
)

var tokenPattern = regexp.MustCompile(`^[0-9a-zA-Z._~-]+$`)

// Copy is one sealed device copy as it crosses the relay.
type Copy struct {
	EventID             string
	SessionID           string
	RecipientEndpointID string
	RecipientDeviceID   string
	ConversationID      string
	Bootstrap           []byte
	AdmissionToken      string
	Ciphertext          []byte
	ExpiresAtUnix       uint64
}

// EncodeCopy returns the canonical kind-1 object.
func EncodeCopy(value Copy) ([]byte, error) {
	if err := validateCopy(value); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainRelayDelivery)
	for _, field := range []string{value.EventID, value.SessionID, value.RecipientEndpointID,
		value.RecipientDeviceID, value.ConversationID} {
		canon.Text(buffer, field)
	}
	canon.Bytes(buffer, value.Bootstrap)
	canon.Text(buffer, value.AdmissionToken)
	canon.Bytes(buffer, value.Ciphertext)
	canon.Uint64(buffer, value.ExpiresAtUnix)
	return buffer.Bytes(), nil
}

// DecodeCopy strictly parses a kind-1 object.
func DecodeCopy(raw []byte) (Copy, error) {
	if !bytes.HasPrefix(raw, []byte(canon.DomainRelayDelivery)) {
		return Copy{}, ErrFrameMalformed
	}
	reader := byteReader{buffer: raw, offset: len(canon.DomainRelayDelivery)}
	value := Copy{
		EventID:             string(reader.lengthPrefixed(idBytes, ErrFrameMalformed)),
		SessionID:           string(reader.lengthPrefixed(idBytes, ErrFrameMalformed)),
		RecipientEndpointID: string(reader.lengthPrefixed(idBytes, ErrFrameMalformed)),
		RecipientDeviceID:   string(reader.lengthPrefixed(idBytes, ErrFrameMalformed)),
		ConversationID:      string(reader.lengthPrefixed(conversationBytes, ErrFrameMalformed)),
		Bootstrap:           reader.lengthPrefixed(MaxBootstrapBytes, ErrFrameMalformed),
		AdmissionToken:      string(reader.lengthPrefixed(MaxAdmissionTokenBytes, ErrFrameMalformed)),
		Ciphertext:          reader.lengthPrefixed(MaxCiphertextBytes, ErrFrameMalformed),
	}
	value.ExpiresAtUnix = reader.u64()
	if err := reader.done(); err != nil {
		return Copy{}, err
	}
	if len(value.Bootstrap) == 0 {
		value.Bootstrap = nil
	}
	if err := validateCopy(value); err != nil {
		return Copy{}, err
	}
	return value, nil
}

func validateCopy(value Copy) error {
	if !ids.Event.MatchString(value.EventID) || !ids.Session.MatchString(value.SessionID) ||
		!ids.Endpoint.MatchString(value.RecipientEndpointID) || !ids.Device.MatchString(value.RecipientDeviceID) ||
		!ids.Conversation.MatchString(value.ConversationID) || value.ExpiresAtUnix == 0 ||
		len(value.Ciphertext) < MinCiphertextBytes || len(value.Ciphertext) > MaxCiphertextBytes ||
		len(value.Bootstrap) > MaxBootstrapBytes ||
		value.AdmissionToken != "" && (len(value.AdmissionToken) > MaxAdmissionTokenBytes ||
			!tokenPattern.MatchString(value.AdmissionToken)) {
		return ErrFrameMalformed
	}
	return nil
}

// WorstCaseCopyFrameBytes is the largest kind-1 frame, before padding, that a
// copy of an Event payload of payloadBytes can need: the maximal card,
// evidence and contact credential with its holder seed, a maximal bootstrap
// and admission token, and the largest
// ciphertext sealing may produce. It is computed before sealing, so a copy
// that could not cross the relay never spends a message key.
func WorstCaseCopyFrameBytes(payloadBytes int) (int, error) {
	if payloadBytes <= 0 {
		return 0, ErrFrameMalformed
	}
	if payloadBytes > MaxCiphertextBytes-MaxSealOverheadBytes {
		return 0, ErrContentTooLarge
	}
	object := copyFixedBytes + MaxBootstrapBytes + MaxAdmissionTokenBytes + payloadBytes + MaxSealOverheadBytes
	return fixedBytes + MaxCardBytes + MaxEvidenceBytes + MaxCredentialFieldBytes + object, nil
}

// CheckCopyFits refuses, with the peer-visible content-too-large fault, an
// Event payload whose worst-case copy frame exceeds the largest bucket.
func CheckCopyFits(payloadBytes int) error {
	size, err := WorstCaseCopyFrameBytes(payloadBytes)
	if err != nil {
		if err == ErrFrameMalformed {
			return fault.New(fault.CodePayloadMalformed, "relay copy has no payload")
		}
		return fault.New(fault.CodeContentTooLarge, "relay copy exceeds the largest frame")
	}
	if size > MaxFrameBytes {
		return fault.New(fault.CodeContentTooLarge, "relay copy exceeds the largest frame")
	}
	return nil
}

// MaxRelayPayloadBytes is the largest Event payload CheckCopyFits admits.
func MaxRelayPayloadBytes() int {
	return MaxFrameBytes - fixedBytes - MaxCardBytes - MaxEvidenceBytes - MaxCredentialFieldBytes -
		copyFixedBytes - MaxBootstrapBytes - MaxAdmissionTokenBytes - MaxSealOverheadBytes
}
