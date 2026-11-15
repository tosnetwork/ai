package agentpacketseal

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
)

const domainKeyCard = "tos.service.agent-packet-relay.key-card.v1"

// Key card bounds.
const (
	// MaxKeyCardLifetime bounds NotAfter - NotBefore.
	MaxKeyCardLifetime = 30 * 24 * time.Hour
	// ClockSkew is the tolerated clock difference for NotBefore.
	ClockSkew = 5 * time.Minute
	// MaxRelays bounds the relay URLs of one card.
	MaxRelays = 4
	// MaxRelayURLBytes bounds one relay URL.
	MaxRelayURLBytes = 256
	// keyCardFixedSize is the body without its relay list.
	keyCardFixedSize = len(domainKeyCard) + 1 + 6 + PublicKeySize + KeyIDSize + 8 + 8 + 1
	// MaxKeyCardBodyBytes bounds a key card body.
	MaxKeyCardBodyBytes = keyCardFixedSize + MaxRelays*(2+MaxRelayURLBytes)
)

// KeyCardAudience and KeyCardCapability are the fixed recipient and
// Capability of a key card packet. No Agent or Capability can have the
// all-zero digest, so agentpacket.Verify, and therefore every delivery
// receiver, refuses a key card as a delivered packet.
const (
	KeyCardAudience   = "agent_0000000000000000000000000000000000000000000000000000000000000000"
	KeyCardCapability = "cap_0000000000000000000000000000000000000000000000000000000000000000"
)

// ErrKeyCard reports a key card that is malformed, outside its bounds,
// outside its validity window, or not signed by a finalized controller.
var ErrKeyCard = errors.New("agentpacketseal: invalid encryption key card")

// KeyCard is the typed body of an encryption key card: one recipient
// encryption key, its validity window, and the relays the Agent fetches from.
type KeyCard struct {
	PublicKey     []byte
	KeyID         [KeyIDSize]byte
	NotBeforeUnix uint64
	NotAfterUnix  uint64
	// Relays are relay base URLs in strictly ascending byte order. They are
	// a hint chosen by the card's Agent, never authority.
	Relays []string
}

// EncodeKeyCard returns the canonical key card body.
func EncodeKeyCard(card KeyCard) ([]byte, error) {
	if err := checkKeyCard(card); err != nil {
		return nil, err
	}
	out := make([]byte, 0, MaxKeyCardBodyBytes)
	out = append(out, domainKeyCard...)
	out = append(out, 0)
	out = append(out, suiteBytes()...)
	out = append(out, card.PublicKey...)
	out = append(out, card.KeyID[:]...)
	out = binary.BigEndian.AppendUint64(out, card.NotBeforeUnix)
	out = binary.BigEndian.AppendUint64(out, card.NotAfterUnix)
	out = append(out, byte(len(card.Relays)))
	for _, relay := range card.Relays {
		out = binary.BigEndian.AppendUint16(out, uint16(len(relay)))
		out = append(out, relay...)
	}
	return out, nil
}

// DecodeKeyCard parses a canonical key card body and refuses any other
// shape, including a trailing byte.
func DecodeKeyCard(raw []byte) (KeyCard, error) {
	if len(raw) < keyCardFixedSize || len(raw) > MaxKeyCardBodyBytes {
		return KeyCard{}, ErrKeyCard
	}
	offset := len(domainKeyCard)
	if string(raw[:offset]) != domainKeyCard || raw[offset] != 0 {
		return KeyCard{}, ErrKeyCard
	}
	offset++
	if !bytes.Equal(raw[offset:offset+6], suiteBytes()) {
		return KeyCard{}, ErrKeyCard
	}
	offset += 6
	var card KeyCard
	card.PublicKey = append([]byte(nil), raw[offset:offset+PublicKeySize]...)
	offset += PublicKeySize
	copy(card.KeyID[:], raw[offset:offset+KeyIDSize])
	offset += KeyIDSize
	card.NotBeforeUnix = binary.BigEndian.Uint64(raw[offset : offset+8])
	offset += 8
	card.NotAfterUnix = binary.BigEndian.Uint64(raw[offset : offset+8])
	offset += 8
	count := int(raw[offset])
	offset++
	if count == 0 || count > MaxRelays {
		return KeyCard{}, ErrKeyCard
	}
	card.Relays = make([]string, 0, count)
	for index := 0; index < count; index++ {
		if len(raw)-offset < 2 {
			return KeyCard{}, ErrKeyCard
		}
		length := int(binary.BigEndian.Uint16(raw[offset : offset+2]))
		offset += 2
		if length == 0 || length > MaxRelayURLBytes || len(raw)-offset < length {
			return KeyCard{}, ErrKeyCard
		}
		card.Relays = append(card.Relays, string(raw[offset:offset+length]))
		offset += length
	}
	if offset != len(raw) {
		return KeyCard{}, ErrKeyCard
	}
	if err := checkKeyCard(card); err != nil {
		return KeyCard{}, err
	}
	return card, nil
}

func checkKeyCard(card KeyCard) error {
	id, err := KeyID(card.PublicKey)
	if err != nil || id != card.KeyID {
		return ErrKeyCard
	}
	if _, err := hpkePublicKey(card.PublicKey); err != nil {
		return ErrKeyCard
	}
	if card.NotBeforeUnix == 0 || card.NotAfterUnix <= card.NotBeforeUnix ||
		card.NotAfterUnix-card.NotBeforeUnix > uint64(MaxKeyCardLifetime/time.Second) {
		return ErrKeyCard
	}
	if len(card.Relays) == 0 || len(card.Relays) > MaxRelays {
		return ErrKeyCard
	}
	for index, relay := range card.Relays {
		if err := CheckRelayURL(relay); err != nil {
			return err
		}
		if index > 0 && card.Relays[index-1] >= relay {
			return ErrKeyCard
		}
	}
	return nil
}

// CheckRelayURL accepts only a canonical relay base URL: HTTPS, or HTTP to
// a loopback host; a lowercase host; no user information, query, fragment
// or trailing slash; printable ASCII; at most MaxRelayURLBytes.
func CheckRelayURL(relay string) error {
	if len(relay) == 0 || len(relay) > MaxRelayURLBytes {
		return ErrKeyCard
	}
	for index := 0; index < len(relay); index++ {
		if relay[index] <= 0x20 || relay[index] >= 0x7f {
			return ErrKeyCard
		}
	}
	parsed, err := url.Parse(relay)
	if err != nil || parsed.String() != relay || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.Opaque != "" || parsed.Host == "" || strings.ToLower(parsed.Host) != parsed.Host ||
		strings.HasSuffix(parsed.Path, "/") || (parsed.Path != "" && !strings.HasPrefix(parsed.Path, "/")) ||
		parsed.RawPath != "" {
		return ErrKeyCard
	}
	host := parsed.Hostname()
	loopback := host == "127.0.0.1" || host == "localhost" || host == "::1"
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback) {
		return ErrKeyCard
	}
	return nil
}

// CheckKeyCardTime reports whether the card may be sealed to at now.
func CheckKeyCardTime(card KeyCard, now time.Time) error {
	if now.IsZero() || now.Unix() <= 0 {
		return ErrKeyCard
	}
	unix := uint64(now.Unix())
	if card.NotBeforeUnix > unix+uint64(ClockSkew/time.Second) || unix >= card.NotAfterUnix {
		return ErrKeyCard
	}
	return nil
}

// KeyCardPacket returns the unsigned Agent Packet that carries a key card:
// sent by the card's Agent to the fixed audience under the fixed Capability,
// with no Quote commitment. It is signed like any packet, with
// agentpacket.Sign.
func KeyCardPacket(agentID string, signerKeyID [mldsa44.KeyIDSize]byte, sequence uint64, nonce [32]byte,
	createdAtUnix uint64, card KeyCard) (agentpacket.Packet, error) {
	body, err := EncodeKeyCard(card)
	if err != nil {
		return agentpacket.Packet{}, err
	}
	if _, err := AgentDigest(agentID); err != nil || agentID == KeyCardAudience || sequence == 0 ||
		createdAtUnix == 0 || nonce == ([32]byte{}) || signerKeyID == ([mldsa44.KeyIDSize]byte{}) {
		return agentpacket.Packet{}, ErrInvalidInput
	}
	return agentpacket.Packet{
		SenderAgentID: agentID, RecipientAgentID: KeyCardAudience, CapabilityID: KeyCardCapability,
		Sequence: sequence, Nonce: nonce, Payload: body, CreatedAtUnix: createdAtUnix, SenderKeyID: signerKeyID,
	}, nil
}

// VerifyKeyCard checks a signed key card packet: the fixed audience and
// Capability, no Quote commitment, a signature by a controller of the
// finalized live sender Agent, a canonical body, and the validity window at
// now. It returns the recipient key to seal to.
func VerifyKeyCard(ctx context.Context, verifier mldsa44.Verifier, resolver agentpacket.AgentResolver,
	packet agentpacket.Packet, now time.Time) (RecipientKey, KeyCard, error) {
	if packet.RecipientAgentID != KeyCardAudience || packet.CapabilityID != KeyCardCapability ||
		packet.QuoteCommitment != "" {
		return RecipientKey{}, KeyCard{}, ErrKeyCard
	}
	card, err := DecodeKeyCard(packet.Payload)
	if err != nil {
		return RecipientKey{}, KeyCard{}, err
	}
	if err := CheckKeyCardTime(card, now); err != nil {
		return RecipientKey{}, KeyCard{}, err
	}
	if err := agentpacket.VerifySender(ctx, verifier, resolver, packet); err != nil {
		return RecipientKey{}, KeyCard{}, err
	}
	return RecipientKey{AgentID: packet.SenderAgentID, KeyID: card.KeyID, PublicKey: card.PublicKey}, card, nil
}
