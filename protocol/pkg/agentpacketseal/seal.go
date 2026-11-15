// Package agentpacketseal is the reference codec of Agent Packet Relay V1: it
// seals one exact signed Agent Packet V1 JSON to a recipient Agent's
// encryption key with RFC 9180 HPKE, and opens it again. A relay that stores
// sealed envelopes needs only ParseEnvelope; it never holds a key and never
// learns the packet.
//
// Sealing adds confidentiality only. The packet's ML-DSA-44 signature by a
// finalized controller of the sender Agent stays the only sender
// authentication: after Open the recipient runs the unchanged Agent Packet
// decode and verification.
package agentpacketseal

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// The single V1 suite: HPKE base mode with the IANA identifiers of
// MLKEM768-X25519, HKDF-SHA256 and AES-256-GCM.
const (
	KEMID  uint16 = 0x647a
	KDFID  uint16 = 0x0001
	AEADID uint16 = 0x0002
)

// Fixed sizes of the V1 suite.
const (
	// PublicKeySize is the serialized MLKEM768-X25519 public key.
	PublicKeySize = 1216
	// PrivateKeySize is the serialized private key: the 32-byte seed.
	PrivateKeySize = 32
	// EncapsulatedKeySize is the HPKE encapsulated key at the front of a
	// ciphertext.
	EncapsulatedKeySize = 1120
	// TagSize is the AES-256-GCM authentication tag.
	TagSize = 16
	// AckSecretSize is the length of an acknowledgement secret.
	AckSecretSize = 32
	// AgentDigestSize is the digest an Agent ID names.
	AgentDigestSize = 32
	// KeyIDSize is the length of an encryption key ID.
	KeyIDSize = 32
)

// Domain separators. Each is followed by one zero byte on the wire.
const (
	domainKeyID     = "tos.service.agent-packet-relay.key-id.v1"
	domainPlaintext = "tos.service.agent-packet-relay.plaintext.v1"
	domainEnvelope  = "tos.service.agent-packet-relay.envelope.v1"
	domainInfo      = "tos.service.agent-packet-relay.hpke-info.v1"
	domainAck       = "tos.service.agent-packet-relay.ack.v1"
)

// Envelope and plaintext bounds.
const (
	// MaxEnvelopeBytes bounds one complete envelope.
	MaxEnvelopeBytes = 256 << 10
	// EnvelopeHeaderSize is the fixed clear header that precedes the
	// ciphertext; it is the HPKE additional authenticated data.
	EnvelopeHeaderSize = len(domainEnvelope) + 1 + 3*2 + AgentDigestSize + KeyIDSize + 32 + 8 + 4
	// PlaintextHeaderSize precedes the packet JSON inside the ciphertext.
	PlaintextHeaderSize = len(domainPlaintext) + 1 + AckSecretSize + 4
	// MaxPacketJSONBytes is the largest packet JSON whose envelope still
	// fits MaxEnvelopeBytes.
	MaxPacketJSONBytes = MaxEnvelopeBytes - EnvelopeHeaderSize - EncapsulatedKeySize - TagSize - PlaintextHeaderSize
	// MaxPlaintextBytes bounds the plaintext wrapper.
	MaxPlaintextBytes = PlaintextHeaderSize + MaxPacketJSONBytes
	// minCiphertextBytes is the ciphertext of the smallest wrapper.
	minCiphertextBytes = EncapsulatedKeySize + PlaintextHeaderSize + 1 + TagSize
	// maxCiphertextBytes is the ciphertext of the largest wrapper.
	maxCiphertextBytes = MaxEnvelopeBytes - EnvelopeHeaderSize
)

// Errors. They are fixed strings: nothing an envelope contains is repeated.
var (
	ErrEnvelopeMalformed  = errors.New("agentpacketseal: envelope is malformed")
	ErrEnvelopeSuite      = errors.New("agentpacketseal: envelope names an unsupported suite")
	ErrEnvelopeRecipient  = errors.New("agentpacketseal: envelope is addressed to another recipient or key")
	ErrEnvelopeOpen       = errors.New("agentpacketseal: envelope does not decrypt under this key and binding")
	ErrPlaintextMalformed = errors.New("agentpacketseal: plaintext wrapper is malformed")
	ErrAckMismatch        = errors.New("agentpacketseal: acknowledgement secret does not match the envelope")
	ErrInvalidInput       = errors.New("agentpacketseal: invalid seal input")
)

// AgentDigest returns the 32-byte digest an `agent_<64 lowercase hex>` Agent
// ID names, refusing any other spelling.
func AgentDigest(agentID string) ([AgentDigestSize]byte, error) {
	var digest [AgentDigestSize]byte
	const prefix = "agent_"
	if len(agentID) != len(prefix)+2*AgentDigestSize || !strings.HasPrefix(agentID, prefix) {
		return digest, ErrInvalidInput
	}
	raw, err := hex.DecodeString(agentID[len(prefix):])
	if err != nil || len(raw) != AgentDigestSize || hex.EncodeToString(raw) != agentID[len(prefix):] {
		return digest, ErrInvalidInput
	}
	copy(digest[:], raw)
	return digest, nil
}

// AgentID renders a digest as an Agent ID.
func AgentID(digest [AgentDigestSize]byte) string {
	return "agent_" + hex.EncodeToString(digest[:])
}

// KeyID derives the ID of a V1 encryption public key.
func KeyID(publicKey []byte) ([KeyIDSize]byte, error) {
	var id [KeyIDSize]byte
	if len(publicKey) != PublicKeySize {
		return id, ErrInvalidInput
	}
	hash := sha256.New()
	hash.Write([]byte(domainKeyID))
	hash.Write([]byte{0})
	hash.Write(suiteBytes())
	hash.Write(publicKey)
	copy(id[:], hash.Sum(nil))
	return id, nil
}

// KeyIDPrefix is the text prefix of an encryption key ID.
const KeyIDPrefix = "hpke:"

// KeyIDText renders an encryption key ID.
func KeyIDText(id [KeyIDSize]byte) string {
	return KeyIDPrefix + hex.EncodeToString(id[:])
}

// ParseKeyIDText parses the exact text form of an encryption key ID.
func ParseKeyIDText(value string) ([KeyIDSize]byte, error) {
	var id [KeyIDSize]byte
	if len(value) != len(KeyIDPrefix)+2*KeyIDSize || !strings.HasPrefix(value, KeyIDPrefix) {
		return id, ErrInvalidInput
	}
	raw, err := hex.DecodeString(value[len(KeyIDPrefix):])
	if err != nil || len(raw) != KeyIDSize || hex.EncodeToString(raw) != value[len(KeyIDPrefix):] ||
		bytes.Equal(raw, make([]byte, KeyIDSize)) {
		return id, ErrInvalidInput
	}
	copy(id[:], raw)
	return id, nil
}

// AckHash is the envelope ID: the domain-separated SHA-256 of the
// acknowledgement secret.
func AckHash(secret [AckSecretSize]byte) [32]byte {
	hash := sha256.New()
	hash.Write([]byte(domainAck))
	hash.Write([]byte{0})
	hash.Write(secret[:])
	var out [32]byte
	copy(out[:], hash.Sum(nil))
	return out
}

// CheckAck reports whether secret is the acknowledgement secret of the
// envelope ID, in constant time.
func CheckAck(envelopeID [32]byte, secret [AckSecretSize]byte) bool {
	hash := AckHash(secret)
	return subtle.ConstantTimeCompare(hash[:], envelopeID[:]) == 1
}

func suiteBytes() []byte {
	out := make([]byte, 0, 6)
	out = binary.BigEndian.AppendUint16(out, KEMID)
	out = binary.BigEndian.AppendUint16(out, KDFID)
	return binary.BigEndian.AppendUint16(out, AEADID)
}

// EncodePlaintext returns the canonical plaintext wrapper.
func EncodePlaintext(ackSecret [AckSecretSize]byte, packetJSON []byte) ([]byte, error) {
	if len(packetJSON) == 0 || len(packetJSON) > MaxPacketJSONBytes || ackSecret == ([AckSecretSize]byte{}) {
		return nil, ErrInvalidInput
	}
	out := make([]byte, 0, PlaintextHeaderSize+len(packetJSON))
	out = append(out, domainPlaintext...)
	out = append(out, 0)
	out = append(out, ackSecret[:]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(packetJSON)))
	return append(out, packetJSON...), nil
}

// DecodePlaintext parses the canonical plaintext wrapper and refuses any
// other shape, including a trailing byte.
func DecodePlaintext(raw []byte) ([AckSecretSize]byte, []byte, error) {
	var secret [AckSecretSize]byte
	if len(raw) <= PlaintextHeaderSize || len(raw) > MaxPlaintextBytes {
		return secret, nil, ErrPlaintextMalformed
	}
	prefix := len(domainPlaintext) + 1
	if string(raw[:len(domainPlaintext)]) != domainPlaintext || raw[len(domainPlaintext)] != 0 {
		return secret, nil, ErrPlaintextMalformed
	}
	copy(secret[:], raw[prefix:prefix+AckSecretSize])
	length := binary.BigEndian.Uint32(raw[prefix+AckSecretSize : PlaintextHeaderSize])
	if secret == ([AckSecretSize]byte{}) || uint64(length) != uint64(len(raw)-PlaintextHeaderSize) {
		return secret, nil, ErrPlaintextMalformed
	}
	return secret, append([]byte(nil), raw[PlaintextHeaderSize:]...), nil
}

// Header is the clear part of an envelope. Every field is authenticated as
// HPKE additional data, so a relay can read it but not change it.
type Header struct {
	RecipientAgentID string
	RecipientKeyID   [KeyIDSize]byte
	// EnvelopeID is AckHash of the acknowledgement secret inside.
	EnvelopeID    [32]byte
	ExpiresAtUnix uint64
	// CiphertextLength is the length of the encapsulated key plus the AEAD
	// ciphertext that follow the header.
	CiphertextLength uint32
}

func encodeHeader(header Header) ([]byte, error) {
	recipient, err := AgentDigest(header.RecipientAgentID)
	if err != nil || recipient == ([AgentDigestSize]byte{}) || header.RecipientKeyID == ([KeyIDSize]byte{}) || header.EnvelopeID == ([32]byte{}) ||
		header.ExpiresAtUnix == 0 || uint64(header.CiphertextLength) < uint64(minCiphertextBytes) ||
		uint64(header.CiphertextLength) > uint64(maxCiphertextBytes) {
		return nil, ErrInvalidInput
	}
	out := make([]byte, 0, EnvelopeHeaderSize)
	out = append(out, domainEnvelope...)
	out = append(out, 0)
	out = append(out, suiteBytes()...)
	out = append(out, recipient[:]...)
	out = append(out, header.RecipientKeyID[:]...)
	out = append(out, header.EnvelopeID[:]...)
	out = binary.BigEndian.AppendUint64(out, header.ExpiresAtUnix)
	return binary.BigEndian.AppendUint32(out, header.CiphertextLength), nil
}

// Info returns the HPKE info string of one recipient key: the domain, the
// suite, the recipient Agent and its key ID enter the key schedule.
func Info(recipientAgentID string, recipientKeyID [KeyIDSize]byte) ([]byte, error) {
	recipient, err := AgentDigest(recipientAgentID)
	if err != nil || recipient == ([AgentDigestSize]byte{}) || recipientKeyID == ([KeyIDSize]byte{}) {
		return nil, ErrInvalidInput
	}
	out := make([]byte, 0, len(domainInfo)+1+6+AgentDigestSize+KeyIDSize)
	out = append(out, domainInfo...)
	out = append(out, 0)
	out = append(out, suiteBytes()...)
	out = append(out, recipient[:]...)
	return append(out, recipientKeyID[:]...), nil
}

// ParseEnvelope checks an envelope's shape without any key: the domain, the
// suite, every bound, and that the ciphertext length is exact. It is all a
// relay checks. It does not judge expiry against a clock.
func ParseEnvelope(raw []byte) (Header, error) {
	var header Header
	if len(raw) < EnvelopeHeaderSize+minCiphertextBytes || len(raw) > MaxEnvelopeBytes {
		return header, ErrEnvelopeMalformed
	}
	offset := len(domainEnvelope)
	if string(raw[:offset]) != domainEnvelope || raw[offset] != 0 {
		return header, ErrEnvelopeMalformed
	}
	offset++
	if !bytes.Equal(raw[offset:offset+6], suiteBytes()) {
		return header, ErrEnvelopeSuite
	}
	offset += 6
	var recipient [AgentDigestSize]byte
	copy(recipient[:], raw[offset:offset+AgentDigestSize])
	offset += AgentDigestSize
	copy(header.RecipientKeyID[:], raw[offset:offset+KeyIDSize])
	offset += KeyIDSize
	copy(header.EnvelopeID[:], raw[offset:offset+32])
	offset += 32
	header.ExpiresAtUnix = binary.BigEndian.Uint64(raw[offset : offset+8])
	offset += 8
	header.CiphertextLength = binary.BigEndian.Uint32(raw[offset : offset+4])
	header.RecipientAgentID = AgentID(recipient)
	if recipient == ([AgentDigestSize]byte{}) || header.RecipientKeyID == ([KeyIDSize]byte{}) ||
		header.EnvelopeID == ([32]byte{}) || header.ExpiresAtUnix == 0 ||
		uint64(header.CiphertextLength) != uint64(len(raw)-EnvelopeHeaderSize) {
		return Header{}, ErrEnvelopeMalformed
	}
	return header, nil
}

// RecipientKey is a recipient encryption public key with its ID.
type RecipientKey struct {
	AgentID   string
	KeyID     [KeyIDSize]byte
	PublicKey []byte
}

// Seal encrypts one packet JSON and its acknowledgement secret to the
// recipient key. Sealing is randomized: a retry of an ambiguous deposit must
// resend the bytes returned here, never a fresh seal.
func Seal(key RecipientKey, ackSecret [AckSecretSize]byte, packetJSON []byte, expiresAtUnix uint64) ([]byte, error) {
	derived, err := KeyID(key.PublicKey)
	if err != nil || derived != key.KeyID || expiresAtUnix == 0 {
		return nil, ErrInvalidInput
	}
	plaintext, err := EncodePlaintext(ackSecret, packetJSON)
	if err != nil {
		return nil, err
	}
	header, err := encodeHeader(Header{
		RecipientAgentID: key.AgentID, RecipientKeyID: key.KeyID, EnvelopeID: AckHash(ackSecret),
		ExpiresAtUnix: expiresAtUnix, CiphertextLength: uint32(EncapsulatedKeySize + len(plaintext) + TagSize),
	})
	if err != nil {
		return nil, err
	}
	info, err := Info(key.AgentID, key.KeyID)
	if err != nil {
		return nil, err
	}
	publicKey, err := hpkePublicKey(key.PublicKey)
	if err != nil {
		return nil, err
	}
	enc, sender, err := hpke.NewSender(publicKey, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, fmt.Errorf("agentpacketseal: set up the HPKE sender: %w", err)
	}
	ciphertext, err := sender.Seal(header, plaintext)
	if err != nil {
		return nil, fmt.Errorf("agentpacketseal: seal: %w", err)
	}
	if len(enc) != EncapsulatedKeySize || len(ciphertext) != len(plaintext)+TagSize {
		return nil, errors.New("agentpacketseal: the HPKE suite produced unexpected sizes")
	}
	out := make([]byte, 0, len(header)+len(enc)+len(ciphertext))
	out = append(out, header...)
	out = append(out, enc...)
	return append(out, ciphertext...), nil
}

// hpkePublicKey deserializes a V1 public key; a key the KEM refuses is
// refused.
func hpkePublicKey(raw []byte) (hpke.PublicKey, error) {
	if len(raw) != PublicKeySize {
		return nil, ErrInvalidInput
	}
	key, err := hpke.MLKEM768X25519().NewPublicKey(raw)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return key, nil
}

// PrivateKey is a recipient decryption key with the identity it belongs to.
type PrivateKey struct {
	AgentID string
	KeyID   [KeyIDSize]byte
	key     hpke.PrivateKey
}

// NewPrivateKey loads a 32-byte private key seed for an Agent.
func NewPrivateKey(agentID string, seed []byte) (PrivateKey, error) {
	if _, err := AgentDigest(agentID); err != nil || len(seed) != PrivateKeySize {
		return PrivateKey{}, ErrInvalidInput
	}
	key, err := hpke.MLKEM768X25519().NewPrivateKey(seed)
	if err != nil {
		return PrivateKey{}, ErrInvalidInput
	}
	id, err := KeyID(key.PublicKey().Bytes())
	if err != nil {
		return PrivateKey{}, err
	}
	return PrivateKey{AgentID: agentID, KeyID: id, key: key}, nil
}

// GenerateSeed draws a fresh private key seed.
func GenerateSeed() ([]byte, error) {
	key, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("agentpacketseal: generate a key: %w", err)
	}
	seed, err := key.Bytes()
	if err != nil || len(seed) != PrivateKeySize {
		return nil, errors.New("agentpacketseal: serialize a generated key")
	}
	return seed, nil
}

// PublicKey returns the serialized public key.
func (k PrivateKey) PublicKey() ([]byte, error) {
	if k.key == nil {
		return nil, ErrInvalidInput
	}
	return k.key.PublicKey().Bytes(), nil
}

// Opened is what Open recovers. PacketJSON is still unverified: the caller
// must run Agent Packet decode and verification before using it.
type Opened struct {
	Header     Header
	AckSecret  [AckSecretSize]byte
	PacketJSON []byte
}

// Open checks that the envelope is addressed to this key, decrypts it with
// its header as additional data, and checks the acknowledgement secret
// against the envelope ID.
func Open(key PrivateKey, raw []byte) (Opened, error) {
	if key.key == nil {
		return Opened{}, ErrInvalidInput
	}
	header, err := ParseEnvelope(raw)
	if err != nil {
		return Opened{}, err
	}
	if header.RecipientAgentID != key.AgentID || header.RecipientKeyID != key.KeyID {
		return Opened{}, ErrEnvelopeRecipient
	}
	info, err := Info(key.AgentID, key.KeyID)
	if err != nil {
		return Opened{}, err
	}
	aad := raw[:EnvelopeHeaderSize]
	enc := raw[EnvelopeHeaderSize : EnvelopeHeaderSize+EncapsulatedKeySize]
	recipient, err := hpke.NewRecipient(enc, key.key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return Opened{}, ErrEnvelopeOpen
	}
	plaintext, err := recipient.Open(aad, raw[EnvelopeHeaderSize+EncapsulatedKeySize:])
	if err != nil {
		return Opened{}, ErrEnvelopeOpen
	}
	secret, packetJSON, err := DecodePlaintext(plaintext)
	if err != nil {
		return Opened{}, err
	}
	if !CheckAck(header.EnvelopeID, secret) {
		return Opened{}, ErrAckMismatch
	}
	return Opened{Header: header, AckSecret: secret, PacketJSON: packetJSON}, nil
}
