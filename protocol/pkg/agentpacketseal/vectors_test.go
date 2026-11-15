package agentpacketseal

import (
	"bytes"
	"context"
	"crypto/hpke"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/cryptotest"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
)

// vectorPath is the frozen Agent Packet Relay V1 corpus.
var vectorPath = filepath.Join("..", "..", "..", "spec", "test-vectors", "agent-packet-relay-v1.json")

// writeVectorsEnv names the variable that makes TestRelayVectors write the
// corpus instead of comparing with it. Writing is deliberate and never a
// fallback on mismatch.
const writeVectorsEnv = "AGENTPACKETSEAL_WRITE_VECTORS"

// vectorRandomSeed seeds the process-wide deterministic randomness HPKE
// encapsulation draws while the corpus is built.
const vectorRandomSeed = 0x41505231

type vectorDocument struct {
	Schema         string              `json:"schema"`
	Note           string              `json:"note"`
	Toolchain      string              `json:"generator_toolchain"`
	Suite          vectorSuite         `json:"suite"`
	Constants      vectorConstants     `json:"constants"`
	Keys           []vectorKey         `json:"keys"`
	Acks           []vectorAck         `json:"ack_hashes"`
	KeyCards       []vectorKeyCard     `json:"key_card_positive"`
	KeyCardsBad    []vectorNegative    `json:"key_card_negative"`
	KeyCardPacket  vectorCardPacket    `json:"key_card_packet"`
	Plaintexts     []vectorPlaintext   `json:"plaintext_positive"`
	PlaintextsBad  []vectorNegative    `json:"plaintext_negative"`
	Envelopes      []vectorEnvelope    `json:"envelope_positive"`
	EnvelopesBad   []vectorEnvelopeBad `json:"envelope_negative"`
	MutationLegend map[string]string   `json:"mutation_legend"`
}

type vectorSuite struct {
	Mode   uint8  `json:"hpke_mode"`
	KEMID  uint16 `json:"kem_id"`
	KDFID  uint16 `json:"kdf_id"`
	AEADID uint16 `json:"aead_id"`
	KEM    string `json:"kem"`
	KDF    string `json:"kdf"`
	AEAD   string `json:"aead"`
}

type vectorConstants struct {
	MaxEnvelopeBytes    int `json:"max_envelope_bytes"`
	EnvelopeHeaderSize  int `json:"envelope_header_size"`
	PlaintextHeaderSize int `json:"plaintext_header_size"`
	MaxPacketJSONBytes  int `json:"max_packet_json_bytes"`
	EncapsulatedKeySize int `json:"encapsulated_key_size"`
	PublicKeySize       int `json:"public_key_size"`
	PrivateKeySize      int `json:"private_key_size"`
	TagSize             int `json:"aead_tag_size"`
	MaxKeyCardBodyBytes int `json:"max_key_card_body_bytes"`
	MaxKeyCardLifetime  int `json:"max_key_card_lifetime_seconds"`
	ClockSkewSeconds    int `json:"clock_skew_seconds"`
	MaxRelays           int `json:"max_relays"`
	MaxRelayURLBytes    int `json:"max_relay_url_bytes"`
}

type vectorKey struct {
	Name          string `json:"name"`
	PrivateSeed   string `json:"private_key_seed_hex"`
	PublicKey     string `json:"public_key_hex"`
	KeyIDPreimage string `json:"key_id_preimage_hex"`
	KeyID         string `json:"key_id"`
}

type vectorAck struct {
	Secret     string `json:"ack_secret_hex"`
	Preimage   string `json:"preimage_hex"`
	EnvelopeID string `json:"envelope_id_hex"`
}

type vectorKeyCard struct {
	Name      string   `json:"name"`
	Key       string   `json:"key"`
	NotBefore uint64   `json:"not_before_unix"`
	NotAfter  uint64   `json:"not_after_unix"`
	Relays    []string `json:"relays"`
	Body      string   `json:"body_hex"`
}

type vectorNegative struct {
	Name string `json:"name"`
	Hex  string `json:"hex"`
}

type vectorCardPacket struct {
	Audience       string `json:"recipient_agent_id"`
	Capability     string `json:"capability_id"`
	Quote          string `json:"quote_commitment"`
	SignatureUse   string `json:"signature_context"`
	ExampleJSONB64 string `json:"example_packet_json_base64"`
	ExampleNote    string `json:"example_note"`
}

type vectorPlaintext struct {
	Name       string `json:"name"`
	AckSecret  string `json:"ack_secret_hex"`
	PacketJSON string `json:"packet_json_hex"`
	Wrapper    string `json:"wrapper_hex"`
}

type vectorEnvelope struct {
	Name        string `json:"name"`
	Key         string `json:"key"`
	Recipient   string `json:"recipient_agent_id"`
	AckSecret   string `json:"ack_secret_hex"`
	ExpiresAt   uint64 `json:"expires_at_unix"`
	PacketJSON  string `json:"packet_json_hex"`
	Info        string `json:"hpke_info_hex"`
	Header      string `json:"header_aad_hex"`
	Plaintext   string `json:"plaintext_hex"`
	EnvelopeHex string `json:"envelope_hex"`
}

type vectorMutation struct {
	Op     string `json:"op"`
	Offset int    `json:"offset,omitempty"`
	Hex    string `json:"hex,omitempty"`
	Length int    `json:"length,omitempty"`
}

type vectorEnvelopeBad struct {
	Name      string          `json:"name"`
	Base      string          `json:"base"`
	OpenAs    string          `json:"open_with_key"`
	OpenAgent string          `json:"open_as_agent_id"`
	Mutation  *vectorMutation `json:"mutation,omitempty"`
	Envelope  string          `json:"envelope_hex,omitempty"`
	Rejection string          `json:"rejection"`
}

const (
	vectorRecipient = "agent_5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
	vectorSender    = "agent_a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"
	vectorOther     = "agent_3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c"
)

func vectorSeed(name string) []byte {
	seed := make([]byte, PrivateKeySize)
	for index := range seed {
		seed[index] = byte(index) ^ name[index%len(name)]
	}
	return seed
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("vector hex: %v", err)
	}
	return raw
}

// samplePacketJSON is a shape-valid Agent Packet V1 whose signature comes
// from the in-process test stand-in, not ML-DSA-44: the seal layer treats
// the packet as opaque bytes, and real signatures are covered elsewhere.
func samplePacketJSON(t *testing.T, recipient string, payload []byte) []byte {
	t.Helper()
	packet, err := agentpacket.Sign(context.Background(), fakeKeys, "vector-sender", agentpacket.Packet{
		SenderAgentID: vectorSender, RecipientAgentID: recipient, CapabilityID: "cap_" + strings.Repeat("c3", 32),
		Sequence: 7, Nonce: [32]byte{0x4e}, Payload: payload, CreatedAtUnix: 1_767_225_600,
		SenderKeyID: controllerKeyID(t, "vector-sender"),
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := agentpacket.EncodeJSON(packet)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func buildVectors(t *testing.T) vectorDocument {
	t.Helper()
	cryptotest.SetGlobalRandom(t, vectorRandomSeed)
	doc := vectorDocument{
		Schema: "tos.service.agent-packet-relay.v1.vectors",
		Note: "Generated by protocol/pkg/agentpacketseal TestRelayVectors. Positive envelopes are normative in the " +
			"open direction: a conforming implementation opens each to its plaintext. Re-sealing reproduces the " +
			"bytes only under the generator toolchain's deterministic test randomness.",
		Toolchain: "go1.26.11",
		Suite: vectorSuite{Mode: 0, KEMID: KEMID, KDFID: KDFID, AEADID: AEADID, KEM: "MLKEM768-X25519",
			KDF: "HKDF-SHA256", AEAD: "AES-256-GCM"},
		Constants: vectorConstants{MaxEnvelopeBytes: MaxEnvelopeBytes, EnvelopeHeaderSize: EnvelopeHeaderSize,
			PlaintextHeaderSize: PlaintextHeaderSize, MaxPacketJSONBytes: MaxPacketJSONBytes,
			EncapsulatedKeySize: EncapsulatedKeySize, PublicKeySize: PublicKeySize, PrivateKeySize: PrivateKeySize,
			TagSize: TagSize, MaxKeyCardBodyBytes: MaxKeyCardBodyBytes,
			MaxKeyCardLifetime: int(MaxKeyCardLifetime.Seconds()), ClockSkewSeconds: int(ClockSkew.Seconds()),
			MaxRelays: MaxRelays, MaxRelayURLBytes: MaxRelayURLBytes},
		MutationLegend: map[string]string{
			"xor":      "XOR the bytes of hex into the base envelope starting at offset",
			"truncate": "keep only the first length bytes of the base envelope",
			"append":   "append the bytes of hex to the base envelope",
		},
	}
	keys := map[string]PrivateKey{}
	publics := map[string]RecipientKey{}
	for _, name := range []string{"recipient-a", "recipient-b"} {
		seed := vectorSeed(name)
		private, err := NewPrivateKey(vectorRecipient, seed)
		if err != nil {
			t.Fatal(err)
		}
		public, err := private.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = private
		publics[name] = RecipientKey{AgentID: vectorRecipient, KeyID: private.KeyID, PublicKey: public}
		preimage := append(append(append([]byte(domainKeyID), 0), suiteBytes()...), public...)
		doc.Keys = append(doc.Keys, vectorKey{Name: name, PrivateSeed: hex.EncodeToString(seed),
			PublicKey: hex.EncodeToString(public), KeyIDPreimage: hex.EncodeToString(preimage),
			KeyID: KeyIDText(private.KeyID)})
	}
	for _, fill := range []byte{0x01, 0xa7, 0xff} {
		secret := secretOf(fill)
		hash := AckHash(secret)
		doc.Acks = append(doc.Acks, vectorAck{Secret: hex.EncodeToString(secret[:]),
			Preimage:   hex.EncodeToString(append(append([]byte(domainAck), 0), secret[:]...)),
			EnvelopeID: hex.EncodeToString(hash[:])})
	}

	base := KeyCard{PublicKey: publics["recipient-a"].PublicKey, KeyID: publics["recipient-a"].KeyID,
		NotBeforeUnix: 1_767_225_600, NotAfterUnix: 1_767_225_600 + 7*24*3600,
		Relays: []string{"https://relay-a.example", "https://relay-b.example/mailbox"}}
	cards := []struct {
		name string
		key  string
		card KeyCard
	}{
		{"two-relays-seven-days", "recipient-a", base},
		{"one-loopback-relay-thirty-days", "recipient-b", KeyCard{PublicKey: publics["recipient-b"].PublicKey,
			KeyID: publics["recipient-b"].KeyID, NotBeforeUnix: 1_767_225_600,
			NotAfterUnix: 1_767_225_600 + 30*24*3600, Relays: []string{"http://127.0.0.1:8787"}}},
	}
	var baseBody []byte
	for _, item := range cards {
		body, err := EncodeKeyCard(item.card)
		if err != nil {
			t.Fatal(err)
		}
		if baseBody == nil {
			baseBody = body
		}
		doc.KeyCards = append(doc.KeyCards, vectorKeyCard{Name: item.name, Key: item.key,
			NotBefore: item.card.NotBeforeUnix, NotAfter: item.card.NotAfterUnix, Relays: item.card.Relays,
			Body: hex.EncodeToString(body)})
	}
	timesOffset := len(domainKeyCard) + 1 + 6 + PublicKeySize + KeyIDSize
	countOffset := timesOffset + 16
	edit := func(change func([]byte) []byte) string {
		return hex.EncodeToString(change(append([]byte(nil), baseBody...)))
	}
	relayBody := func(relays ...string) string {
		raw := append([]byte(nil), baseBody[:countOffset]...)
		raw = append(raw, byte(len(relays)))
		for _, relay := range relays {
			raw = binary.BigEndian.AppendUint16(raw, uint16(len(relay)))
			raw = append(raw, relay...)
		}
		return hex.EncodeToString(raw)
	}
	doc.KeyCardsBad = []vectorNegative{
		{"trailing-byte", edit(func(b []byte) []byte { return append(b, 0) })},
		{"truncated", edit(func(b []byte) []byte { return b[:len(b)-1] })},
		{"other-domain", edit(func(b []byte) []byte { b[len(domainKeyCard)-1] = '2'; return b })},
		{"unknown-kem", edit(func(b []byte) []byte { b[len(domainKeyCard)+2] ^= 1; return b })},
		{"key-id-of-another-key", edit(func(b []byte) []byte { b[timesOffset-1] ^= 1; return b })},
		{"public-key-byte-flipped", edit(func(b []byte) []byte { b[len(domainKeyCard)+7] ^= 1; return b })},
		{"not-after-equals-not-before", edit(func(b []byte) []byte {
			copy(b[timesOffset+8:timesOffset+16], b[timesOffset:timesOffset+8])
			return b
		})},
		{"lifetime-thirty-days-plus-one-second", edit(func(b []byte) []byte {
			binary.BigEndian.PutUint64(b[timesOffset+8:], base.NotBeforeUnix+30*24*3600+1)
			return b
		})},
		{"zero-not-before", edit(func(b []byte) []byte {
			binary.BigEndian.PutUint64(b[timesOffset:], 0)
			return b
		})},
		{"no-relay", relayBody()},
		{"five-relays", relayBody("https://a.example", "https://b.example", "https://c.example", "https://d.example",
			"https://e.example")},
		{"relays-out-of-order", relayBody("https://relay-b.example/mailbox", "https://relay-a.example")},
		{"duplicate-relay", relayBody("https://relay-a.example", "https://relay-a.example")},
		{"plain-http-relay", relayBody("http://relay-a.example")},
		{"relay-with-query", relayBody("https://relay-a.example?k=v")},
		{"relay-with-trailing-slash", relayBody("https://relay-a.example/")},
		{"relay-uppercase-host", relayBody("https://Relay-a.example")},
		{"relay-with-user-information", relayBody("https://u@relay-a.example")},
		{"relay-with-escaped-space", relayBody("https://relay-a.example/a%20b")},
		{"relay-with-escaped-slash", relayBody("https://relay-a.example/a%2Fb")},
		{"relay-length-overruns-body", edit(func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[countOffset+1:], 0xffff)
			return b
		})},
	}

	cardPacket, err := KeyCardPacket(vectorRecipient, controllerKeyID(t, "vector-recipient"), 1, [32]byte{0xcc},
		1_767_225_600, base)
	if err != nil {
		t.Fatal(err)
	}
	cardPacket, err = agentpacket.Sign(context.Background(), fakeKeys, "vector-recipient", cardPacket)
	if err != nil {
		t.Fatal(err)
	}
	cardJSON, err := agentpacket.EncodeJSON(cardPacket)
	if err != nil {
		t.Fatal(err)
	}
	doc.KeyCardPacket = vectorCardPacket{Audience: KeyCardAudience, Capability: KeyCardCapability, Quote: "",
		SignatureUse:   "TOS-AGENT-PACKET-V1",
		ExampleJSONB64: base64.StdEncoding.EncodeToString(cardJSON),
		ExampleNote: "payload is key_card_positive[0].body_hex; the signature is from the in-process test " +
			"stand-in, not ML-DSA-44, and must not verify under a real verifier"}

	small := samplePacketJSON(t, vectorRecipient, []byte("relay vector payload"))
	frameLike := samplePacketJSON(t, vectorRecipient, bytes.Repeat([]byte{0x4f}, 4096))
	for index, packetJSON := range [][]byte{small, frameLike} {
		secret := secretOf(byte(0x11 * (index + 1)))
		wrapper, err := EncodePlaintext(secret, packetJSON)
		if err != nil {
			t.Fatal(err)
		}
		doc.Plaintexts = append(doc.Plaintexts, vectorPlaintext{Name: []string{"small-packet", "4-kib-payload"}[index],
			AckSecret: hex.EncodeToString(secret[:]), PacketJSON: hex.EncodeToString(packetJSON),
			Wrapper: hex.EncodeToString(wrapper)})
	}
	goodWrapper, err := EncodePlaintext(secretOf(0x11), small)
	if err != nil {
		t.Fatal(err)
	}
	wrapperEdit := func(change func([]byte) []byte) string {
		return hex.EncodeToString(change(append([]byte(nil), goodWrapper...)))
	}
	lengthOffset := len(domainPlaintext) + 1 + AckSecretSize
	doc.PlaintextsBad = []vectorNegative{
		{"trailing-byte", wrapperEdit(func(b []byte) []byte { return append(b, 0) })},
		{"length-one-short", wrapperEdit(func(b []byte) []byte { return b[:len(b)-1] })},
		{"length-field-larger", wrapperEdit(func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[lengthOffset:], uint32(len(small)+1))
			return b
		})},
		{"other-domain", wrapperEdit(func(b []byte) []byte { b[len(domainPlaintext)-1] = '2'; return b })},
		{"missing-separator", wrapperEdit(func(b []byte) []byte { b[len(domainPlaintext)] = 1; return b })},
		{"zero-ack-secret", wrapperEdit(func(b []byte) []byte {
			copy(b[len(domainPlaintext)+1:lengthOffset], make([]byte, AckSecretSize))
			return b
		})},
		{"empty-packet", hex.EncodeToString(goodWrapper[:PlaintextHeaderSize])},
	}

	envelopes := []struct {
		name    string
		key     string
		secret  [AckSecretSize]byte
		packet  []byte
		expires uint64
	}{
		{"small-packet-key-a", "recipient-a", secretOf(0x11), small, 1_767_312_000},
		{"4-kib-payload-key-b", "recipient-b", secretOf(0x22), frameLike, 1_767_312_000},
	}
	for _, item := range envelopes {
		key := publics[item.key]
		sealed, err := Seal(key, item.secret, item.packet, item.expires)
		if err != nil {
			t.Fatal(err)
		}
		info, err := Info(key.AgentID, key.KeyID)
		if err != nil {
			t.Fatal(err)
		}
		wrapper, err := EncodePlaintext(item.secret, item.packet)
		if err != nil {
			t.Fatal(err)
		}
		doc.Envelopes = append(doc.Envelopes, vectorEnvelope{Name: item.name, Key: item.key,
			Recipient: key.AgentID, AckSecret: hex.EncodeToString(item.secret[:]), ExpiresAt: item.expires,
			PacketJSON: hex.EncodeToString(item.packet), Info: hex.EncodeToString(info),
			Header: hex.EncodeToString(sealed[:EnvelopeHeaderSize]), Plaintext: hex.EncodeToString(wrapper),
			EnvelopeHex: hex.EncodeToString(sealed)})
	}

	suiteOffset := len(domainEnvelope) + 1
	recipientOffset := suiteOffset + 6
	keyIDOffset := recipientOffset + AgentDigestSize
	idOffset := keyIDOffset + KeyIDSize
	expiresOffset := idOffset + 32
	lengthField := expiresOffset + 8
	baseName := envelopes[0].name
	baseLength := len(mustHex(t, doc.Envelopes[0].EnvelopeHex))
	flip := func(name string, offset int, rejection string) vectorEnvelopeBad {
		return vectorEnvelopeBad{Name: name, Base: baseName, OpenAs: "recipient-a", OpenAgent: vectorRecipient,
			Mutation: &vectorMutation{Op: "xor", Offset: offset, Hex: "01"}, Rejection: rejection}
	}
	doc.EnvelopesBad = []vectorEnvelopeBad{
		flip("domain-byte", 0, "malformed"),
		flip("domain-separator", suiteOffset-1, "malformed"),
		flip("kem-id", suiteOffset+1, "suite"),
		flip("kdf-id", suiteOffset+3, "suite"),
		flip("aead-id", suiteOffset+5, "suite"),
		flip("recipient-agent", recipientOffset, "recipient"),
		flip("recipient-key-id", keyIDOffset, "recipient"),
		flip("envelope-id", idOffset, "open"),
		flip("expiry", expiresOffset+7, "open"),
		flip("ciphertext-length", lengthField+3, "malformed"),
		flip("encapsulated-key-ml-kem-part", EnvelopeHeaderSize, "open"),
		flip("encapsulated-key-x25519-part", EnvelopeHeaderSize+EncapsulatedKeySize-1, "open"),
		flip("aead-ciphertext", EnvelopeHeaderSize+EncapsulatedKeySize, "open"),
		flip("aead-tag", baseLength-1, "open"),
		{Name: "truncated-by-one", Base: baseName, OpenAs: "recipient-a", OpenAgent: vectorRecipient,
			Mutation: &vectorMutation{Op: "truncate", Length: baseLength - 1}, Rejection: "malformed"},
		{Name: "trailing-byte", Base: baseName, OpenAs: "recipient-a", OpenAgent: vectorRecipient,
			Mutation: &vectorMutation{Op: "append", Hex: "00"}, Rejection: "malformed"},
		{Name: "header-only", Base: baseName, OpenAs: "recipient-a", OpenAgent: vectorRecipient,
			Mutation: &vectorMutation{Op: "truncate", Length: EnvelopeHeaderSize}, Rejection: "malformed"},
		{Name: "other-key-of-the-recipient", Base: baseName, OpenAs: "recipient-b", OpenAgent: vectorRecipient,
			Rejection: "recipient"},
		{Name: "right-key-under-another-agent", Base: baseName, OpenAs: "recipient-a", OpenAgent: vectorOther,
			Rejection: "recipient"},
	}

	// Authenticated envelopes whose contents must still be refused.
	keyA := publics["recipient-a"]
	header := Header{RecipientAgentID: vectorRecipient, RecipientKeyID: keyA.KeyID,
		EnvelopeID: AckHash(secretOf(0x33)), ExpiresAtUnix: 1_767_312_000}
	sealedAck := sealRaw(t, keyA, header, mustWrapper(t, secretOf(0x44), small))
	trailing := append(mustWrapper(t, secretOf(0x33), small), 0)
	sealedTrailing := sealRaw(t, keyA, header, trailing)
	readdressed := sealRaw(t, keyA, header, mustWrapper(t, secretOf(0x33), small))
	other, err := AgentDigest(vectorOther)
	if err != nil {
		t.Fatal(err)
	}
	copy(readdressed[recipientOffset:], other[:])
	keyOther, err := NewPrivateKey(vectorOther, vectorSeed("recipient-a"))
	if err != nil {
		t.Fatal(err)
	}
	if keyOther.KeyID != keyA.KeyID {
		t.Fatal("the same seed derived another key ID")
	}
	doc.EnvelopesBad = append(doc.EnvelopesBad,
		vectorEnvelopeBad{Name: "ack-secret-of-another-envelope-id", OpenAs: "recipient-a", OpenAgent: vectorRecipient,
			Envelope: hex.EncodeToString(sealedAck), Rejection: "ack"},
		vectorEnvelopeBad{Name: "plaintext-trailing-byte", OpenAs: "recipient-a", OpenAgent: vectorRecipient,
			Envelope: hex.EncodeToString(sealedTrailing), Rejection: "plaintext"},
		vectorEnvelopeBad{Name: "readdressed-to-an-agent-holding-the-same-key", OpenAs: "recipient-a",
			OpenAgent: vectorOther, Envelope: hex.EncodeToString(readdressed), Rejection: "open"},
	)
	return doc
}

func mustWrapper(t *testing.T, secret [AckSecretSize]byte, packetJSON []byte) []byte {
	t.Helper()
	wrapper, err := EncodePlaintext(secret, packetJSON)
	if err != nil {
		t.Fatal(err)
	}
	return wrapper
}

func encodeVectors(t *testing.T, doc vectorDocument) []byte {
	t.Helper()
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

// TestRelayVectors rebuilds the corpus and requires the committed file to
// equal it byte for byte, then checks the committed file independently of
// the builder. With AGENTPACKETSEAL_WRITE_VECTORS=1 it writes the file
// instead; a mismatch never rewrites it.
func TestRelayVectors(t *testing.T) {
	built := encodeVectors(t, buildVectors(t))
	if os.Getenv(writeVectorsEnv) == "1" {
		if err := os.WriteFile(vectorPath, built, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", vectorPath)
		return
	}
	committed, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read the frozen corpus: %v", err)
	}
	if !bytes.Equal(committed, built) {
		t.Fatalf("the frozen corpus %s differs from what the generator builds; this is a wire change or a "+
			"toolchain change (the corpus was built with go1.26.11): regenerate only deliberately, in its own "+
			"commit, with %s=1", vectorPath, writeVectorsEnv)
	}
	var doc vectorDocument
	decoder := json.NewDecoder(bytes.NewReader(committed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	checkVectors(t, doc)
}

var rejections = map[string]error{
	"malformed": ErrEnvelopeMalformed,
	"suite":     ErrEnvelopeSuite,
	"recipient": ErrEnvelopeRecipient,
	"open":      ErrEnvelopeOpen,
	"plaintext": ErrPlaintextMalformed,
	"ack":       ErrAckMismatch,
}

// checkVectors verifies the committed corpus in the open direction only, so
// its checks hold for any toolchain.
func checkVectors(t *testing.T, doc vectorDocument) {
	t.Helper()
	if doc.Suite.KEMID != hpke.MLKEM768X25519().ID() || doc.Suite.KDFID != hpke.HKDFSHA256().ID() ||
		doc.Suite.AEADID != hpke.AES256GCM().ID() || doc.Suite.Mode != 0 {
		t.Fatal("corpus suite differs from the HPKE implementation")
	}
	seeds := map[string][]byte{}
	for _, key := range doc.Keys {
		seed := mustHex(t, key.PrivateSeed)
		private, err := NewPrivateKey(vectorRecipient, seed)
		if err != nil {
			t.Fatal(err)
		}
		public, err := private.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		preimage := mustHex(t, key.KeyIDPreimage)
		if hex.EncodeToString(public) != key.PublicKey || KeyIDText(private.KeyID) != key.KeyID ||
			!bytes.HasSuffix(preimage, public) {
			t.Fatalf("key %s does not reproduce", key.Name)
		}
		seeds[key.Name] = seed
	}
	for _, ack := range doc.Acks {
		var secret [AckSecretSize]byte
		copy(secret[:], mustHex(t, ack.Secret))
		hash := AckHash(secret)
		if hex.EncodeToString(hash[:]) != ack.EnvelopeID || !CheckAck(hash, secret) {
			t.Fatalf("ack hash %s does not reproduce", ack.Secret)
		}
	}
	for _, card := range doc.KeyCards {
		decoded, err := DecodeKeyCard(mustHex(t, card.Body))
		if err != nil {
			t.Fatalf("key card %s: %v", card.Name, err)
		}
		if decoded.NotBeforeUnix != card.NotBefore || decoded.NotAfterUnix != card.NotAfter ||
			strings.Join(decoded.Relays, "\n") != strings.Join(card.Relays, "\n") {
			t.Fatalf("key card %s fields differ", card.Name)
		}
		for _, key := range doc.Keys {
			if key.Name == card.Key && (hex.EncodeToString(decoded.PublicKey) != key.PublicKey ||
				KeyIDText(decoded.KeyID) != key.KeyID) {
				t.Fatalf("key card %s names another key", card.Name)
			}
		}
	}
	for _, bad := range doc.KeyCardsBad {
		if _, err := DecodeKeyCard(mustHex(t, bad.Hex)); !errors.Is(err, ErrKeyCard) {
			t.Fatalf("key card negative %s was not refused: %v", bad.Name, err)
		}
	}
	for _, plain := range doc.Plaintexts {
		secret, packetJSON, err := DecodePlaintext(mustHex(t, plain.Wrapper))
		if err != nil || hex.EncodeToString(secret[:]) != plain.AckSecret || hex.EncodeToString(packetJSON) != plain.PacketJSON {
			t.Fatalf("plaintext %s does not reproduce: %v", plain.Name, err)
		}
		if _, err := agentpacket.DecodeJSON(packetJSON); err != nil {
			t.Fatalf("plaintext %s does not carry a strict Agent Packet: %v", plain.Name, err)
		}
	}
	for _, bad := range doc.PlaintextsBad {
		if _, _, err := DecodePlaintext(mustHex(t, bad.Hex)); !errors.Is(err, ErrPlaintextMalformed) {
			t.Fatalf("plaintext negative %s was not refused: %v", bad.Name, err)
		}
	}
	bases := map[string][]byte{}
	for _, envelope := range doc.Envelopes {
		raw := mustHex(t, envelope.EnvelopeHex)
		key, err := NewPrivateKey(envelope.Recipient, seeds[envelope.Key])
		if err != nil {
			t.Fatal(err)
		}
		opened, err := Open(key, raw)
		if err != nil {
			t.Fatalf("envelope %s does not open: %v", envelope.Name, err)
		}
		info, err := Info(envelope.Recipient, key.KeyID)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(opened.PacketJSON) != envelope.PacketJSON ||
			hex.EncodeToString(opened.AckSecret[:]) != envelope.AckSecret ||
			opened.Header.ExpiresAtUnix != envelope.ExpiresAt || hex.EncodeToString(info) != envelope.Info ||
			hex.EncodeToString(raw[:EnvelopeHeaderSize]) != envelope.Header {
			t.Fatalf("envelope %s opens to other contents", envelope.Name)
		}
		// The plaintext is the exact wrapper: open it again with the raw HPKE
		// API to pin the info and additional data independently of Open.
		recipient, err := hpke.NewRecipient(raw[EnvelopeHeaderSize:EnvelopeHeaderSize+EncapsulatedKeySize], key.key,
			hpke.HKDFSHA256(), hpke.AES256GCM(), mustHex(t, envelope.Info))
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := recipient.Open(mustHex(t, envelope.Header), raw[EnvelopeHeaderSize+EncapsulatedKeySize:])
		if err != nil || hex.EncodeToString(plaintext) != envelope.Plaintext {
			t.Fatalf("envelope %s: raw HPKE open differs: %v", envelope.Name, err)
		}
		bases[envelope.Name] = raw
	}
	for _, bad := range doc.EnvelopesBad {
		raw, err := mutateEnvelope(t, bad, bases)
		if err != nil {
			t.Fatalf("envelope negative %s: %v", bad.Name, err)
		}
		key, err := NewPrivateKey(bad.OpenAgent, seeds[bad.OpenAs])
		if err != nil {
			t.Fatal(err)
		}
		want, ok := rejections[bad.Rejection]
		if !ok {
			t.Fatalf("envelope negative %s names unknown rejection %q", bad.Name, bad.Rejection)
		}
		if _, err := Open(key, raw); !errors.Is(err, want) {
			t.Fatalf("envelope negative %s: got %v, want %v", bad.Name, err, want)
		}
	}
}

func mutateEnvelope(t *testing.T, bad vectorEnvelopeBad, bases map[string][]byte) ([]byte, error) {
	t.Helper()
	if bad.Envelope != "" {
		if bad.Mutation != nil || bad.Base != "" {
			return nil, errors.New("a literal negative has no base or mutation")
		}
		return mustHex(t, bad.Envelope), nil
	}
	base, ok := bases[bad.Base]
	if !ok {
		return nil, fmt.Errorf("unknown base %q", bad.Base)
	}
	raw := append([]byte(nil), base...)
	if bad.Mutation == nil {
		return raw, nil
	}
	switch bad.Mutation.Op {
	case "xor":
		mask := mustHex(t, bad.Mutation.Hex)
		if bad.Mutation.Offset < 0 || bad.Mutation.Offset+len(mask) > len(raw) {
			return nil, errors.New("xor outside the envelope")
		}
		for index, value := range mask {
			raw[bad.Mutation.Offset+index] ^= value
		}
		return raw, nil
	case "truncate":
		if bad.Mutation.Length < 0 || bad.Mutation.Length >= len(raw) {
			return nil, errors.New("truncation outside the envelope")
		}
		return raw[:bad.Mutation.Length], nil
	case "append":
		return append(raw, mustHex(t, bad.Mutation.Hex)...), nil
	default:
		return nil, fmt.Errorf("unknown mutation %q", bad.Mutation.Op)
	}
}
