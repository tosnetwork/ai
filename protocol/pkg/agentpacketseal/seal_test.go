package agentpacketseal

import (
	"bytes"
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func seedOf(b byte) []byte { return bytes.Repeat([]byte{b}, PrivateKeySize) }

func agentOf(hexByte string) string { return "agent_" + strings.Repeat(hexByte, 32) }

func secretOf(b byte) [AckSecretSize]byte {
	var secret [AckSecretSize]byte
	for index := range secret {
		secret[index] = b
	}
	return secret
}

func keyPair(t *testing.T, agentID string, seed byte) (PrivateKey, RecipientKey) {
	t.Helper()
	private, err := NewPrivateKey(agentID, seedOf(seed))
	if err != nil {
		t.Fatal(err)
	}
	public, err := private.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return private, RecipientKey{AgentID: agentID, KeyID: private.KeyID, PublicKey: public}
}

// sealRaw seals arbitrary plaintext under an arbitrary header, so that tests
// can build authenticated envelopes whose contents Open must still refuse.
func sealRaw(t *testing.T, key RecipientKey, header Header, plaintext []byte) []byte {
	t.Helper()
	header.CiphertextLength = uint32(EncapsulatedKeySize + len(plaintext) + TagSize)
	encoded, err := encodeHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	info, err := Info(key.AgentID, key.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	public, err := hpkePublicKey(key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	enc, sender, err := hpke.NewSender(public, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := sender.Seal(encoded, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return append(append(encoded, enc...), ciphertext...)
}

func TestSuiteMatchesTheStandardLibrary(t *testing.T) {
	if hpke.MLKEM768X25519().ID() != KEMID || hpke.HKDFSHA256().ID() != KDFID || hpke.AES256GCM().ID() != AEADID {
		t.Fatal("suite identifiers differ from the HPKE implementation")
	}
	private, public := keyPair(t, agentOf("11"), 1)
	if len(public.PublicKey) != PublicKeySize || private.KeyID == ([KeyIDSize]byte{}) {
		t.Fatal("unexpected key shape")
	}
	sealed, err := Seal(public, secretOf(7), []byte("{}"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != EnvelopeHeaderSize+EncapsulatedKeySize+PlaintextHeaderSize+2+TagSize {
		t.Fatalf("envelope is %d bytes", len(sealed))
	}
}

func TestSealOpenRoundTripAndBinding(t *testing.T) {
	recipient := agentOf("11")
	private, public := keyPair(t, recipient, 1)
	packet := []byte(`{"schema":"tos.service.agent-packet.v1"}`)
	sealed, err := Seal(public, secretOf(9), packet, 1_700_000_000)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(private, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.PacketJSON, packet) || opened.AckSecret != secretOf(9) ||
		opened.Header.EnvelopeID != AckHash(secretOf(9)) || opened.Header.ExpiresAtUnix != 1_700_000_000 {
		t.Fatal("opened envelope differs from what was sealed")
	}
	// Every header byte is authenticated: flipping any byte of the header
	// is refused, by shape, suite, recipient or decryption.
	for offset := 0; offset < EnvelopeHeaderSize; offset++ {
		mutated := append([]byte(nil), sealed...)
		mutated[offset] ^= 0x01
		if _, err := Open(private, mutated); err == nil {
			t.Fatalf("header byte %d is not authenticated", offset)
		}
	}
	for _, offset := range []int{EnvelopeHeaderSize, EnvelopeHeaderSize + EncapsulatedKeySize, len(sealed) - 1} {
		mutated := append([]byte(nil), sealed...)
		mutated[offset] ^= 0x80
		if _, err := Open(private, mutated); !errors.Is(err, ErrEnvelopeOpen) {
			t.Fatalf("ciphertext byte %d: %v", offset, err)
		}
	}
	if _, err := Open(private, sealed[:len(sealed)-1]); !errors.Is(err, ErrEnvelopeMalformed) {
		t.Fatalf("truncated: %v", err)
	}
	if _, err := Open(private, append(append([]byte(nil), sealed...), 0)); !errors.Is(err, ErrEnvelopeMalformed) {
		t.Fatalf("trailing byte: %v", err)
	}
	other, _ := keyPair(t, recipient, 2)
	if _, err := Open(other, sealed); !errors.Is(err, ErrEnvelopeRecipient) {
		t.Fatalf("another key of the same Agent: %v", err)
	}
	foreign, err := NewPrivateKey(agentOf("22"), seedOf(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(foreign, sealed); !errors.Is(err, ErrEnvelopeRecipient) {
		t.Fatalf("same key under another Agent: %v", err)
	}
}

// TestHeaderRewriteForAnotherRecipient re-addresses a sealed envelope to
// another Agent that holds the same key seed. The info string binds the
// recipient Agent, so decryption fails even though the key is right.
func TestHeaderRewriteForAnotherRecipient(t *testing.T) {
	_, public := keyPair(t, agentOf("11"), 1)
	sealed, err := Seal(public, secretOf(9), []byte("{}"), 100)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := NewPrivateKey(agentOf("22"), seedOf(1))
	if err != nil {
		t.Fatal(err)
	}
	rewritten := append([]byte(nil), sealed...)
	recipient, err := AgentDigest(agentOf("22"))
	if err != nil {
		t.Fatal(err)
	}
	copy(rewritten[len(domainEnvelope)+1+6:], recipient[:])
	if _, err := Open(foreign, rewritten); !errors.Is(err, ErrEnvelopeOpen) {
		t.Fatalf("re-addressed envelope: %v", err)
	}
}

func TestAuthenticatedButInvalidContentsAreRefused(t *testing.T) {
	recipient := agentOf("11")
	private, public := keyPair(t, recipient, 1)
	header := Header{RecipientAgentID: recipient, RecipientKeyID: public.KeyID, EnvelopeID: AckHash(secretOf(9)),
		ExpiresAtUnix: 100}
	good, err := EncodePlaintext(secretOf(9), []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(private, sealRaw(t, public, header, good)); err != nil {
		t.Fatalf("control: %v", err)
	}
	wrongAck := header
	wrongAck.EnvelopeID = AckHash(secretOf(8))
	if _, err := Open(private, sealRaw(t, public, wrongAck, good)); !errors.Is(err, ErrAckMismatch) {
		t.Fatalf("envelope ID of another secret: %v", err)
	}
	cases := map[string][]byte{
		"trailing byte": append(append([]byte(nil), good...), 0),
		"short length":  append(append([]byte(nil), good[:PlaintextHeaderSize-4]...), 0, 0, 0, 1, '{', '}'),
		"zero secret":   append(append(append([]byte(domainPlaintext), 0), make([]byte, 32)...), 0, 0, 0, 2, '{', '}'),
		"other domain":  append(append([]byte("tos.service.agent-packet-relay.plaintext.v2"), 0), good[len(domainPlaintext)+1:]...),
		"missing nul":   append([]byte(domainPlaintext), good[len(domainPlaintext)+1:]...),
	}
	for name, plaintext := range cases {
		if _, err := Open(private, sealRaw(t, public, header, plaintext)); !errors.Is(err, ErrPlaintextMalformed) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestDecodePlaintextRefusesShortInput(t *testing.T) {
	good, err := EncodePlaintext(secretOf(9), []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"nothing":      nil,
		"empty packet": good[:PlaintextHeaderSize],
		"header only":  append([]byte(domainPlaintext), 0),
	} {
		if _, _, err := DecodePlaintext(raw); !errors.Is(err, ErrPlaintextMalformed) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestPlaintextAndEnvelopeBounds(t *testing.T) {
	if MaxPacketJSONBytes < 128<<10 {
		t.Fatalf("the envelope bound no longer fits a 128 KiB packet: %d", MaxPacketJSONBytes)
	}
	if EnvelopeHeaderSize+EncapsulatedKeySize+TagSize+MaxPlaintextBytes != MaxEnvelopeBytes {
		t.Fatal("the bounds do not add up to the envelope bound")
	}
	private, public := keyPair(t, agentOf("11"), 1)
	largest := bytes.Repeat([]byte{'a'}, MaxPacketJSONBytes)
	sealed, err := Seal(public, secretOf(1), largest, 100)
	if err != nil || len(sealed) != MaxEnvelopeBytes {
		t.Fatalf("largest packet: %d bytes, %v", len(sealed), err)
	}
	if _, err := Open(private, sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := Seal(public, secretOf(1), append(largest, 'a'), 100); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("one byte over: %v", err)
	}
	if _, err := ParseEnvelope(append(sealed, 0)); !errors.Is(err, ErrEnvelopeMalformed) {
		t.Fatalf("over the envelope bound: %v", err)
	}
	for name, input := range map[string]func() ([]byte, error){
		"empty packet": func() ([]byte, error) { return Seal(public, secretOf(1), nil, 100) },
		"zero secret":  func() ([]byte, error) { return Seal(public, [AckSecretSize]byte{}, []byte("{}"), 100) },
		"zero expiry":  func() ([]byte, error) { return Seal(public, secretOf(1), []byte("{}"), 0) },
		"wrong key ID": func() ([]byte, error) {
			bad := public
			bad.KeyID[0] ^= 1
			return Seal(bad, secretOf(1), []byte("{}"), 100)
		},
		"short key": func() ([]byte, error) {
			bad := public
			bad.PublicKey = bad.PublicKey[:PublicKeySize-1]
			return Seal(bad, secretOf(1), []byte("{}"), 100)
		},
		"audience recipient": func() ([]byte, error) {
			bad := public
			bad.AgentID = KeyCardAudience
			return Seal(bad, secretOf(1), []byte("{}"), 100)
		},
		"uppercase recipient": func() ([]byte, error) {
			bad := public
			bad.AgentID = strings.ToUpper(bad.AgentID)
			return Seal(bad, secretOf(1), []byte("{}"), 100)
		},
	} {
		if _, err := input(); err == nil {
			t.Fatalf("%s was sealed", name)
		}
	}
}

func TestParseEnvelopeRefusesEveryFieldOutOfShape(t *testing.T) {
	_, public := keyPair(t, agentOf("11"), 1)
	sealed, err := Seal(public, secretOf(9), []byte("{}"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEnvelope(sealed); err != nil {
		t.Fatal(err)
	}
	suite := len(domainEnvelope) + 1
	recipient := suite + 6
	keyID := recipient + AgentDigestSize
	envelopeID := keyID + KeyIDSize
	expires := envelopeID + 32
	length := expires + 8
	zero := func(offset, size int) []byte {
		mutated := append([]byte(nil), sealed...)
		copy(mutated[offset:offset+size], make([]byte, size))
		return mutated
	}
	unknownSuite := append([]byte(nil), sealed...)
	binary.BigEndian.PutUint16(unknownSuite[suite:], 0x0020)
	longer := append([]byte(nil), sealed...)
	binary.BigEndian.PutUint32(longer[length:], binary.BigEndian.Uint32(sealed[length:])+1)
	cases := map[string]struct {
		raw  []byte
		want error
	}{
		"domain":         {raw: append([]byte("x"), sealed[1:]...), want: ErrEnvelopeMalformed},
		"suite":          {raw: unknownSuite, want: ErrEnvelopeSuite},
		"zero recipient": {raw: zero(recipient, AgentDigestSize), want: ErrEnvelopeMalformed},
		"zero key ID":    {raw: zero(keyID, KeyIDSize), want: ErrEnvelopeMalformed},
		"zero ID":        {raw: zero(envelopeID, 32), want: ErrEnvelopeMalformed},
		"zero expiry":    {raw: zero(expires, 8), want: ErrEnvelopeMalformed},
		"length":         {raw: longer, want: ErrEnvelopeMalformed},
		"header only":    {raw: sealed[:EnvelopeHeaderSize], want: ErrEnvelopeMalformed},
	}
	for name, test := range cases {
		if _, err := ParseEnvelope(test.raw); !errors.Is(err, test.want) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestIdentifiersAreStrict(t *testing.T) {
	for _, bad := range []string{"", "agent_", agentOf("1"), "agent_" + strings.Repeat("A", 64), "agnt_" + strings.Repeat("1", 65)} {
		if _, err := AgentDigest(bad); err == nil {
			t.Fatalf("accepted Agent ID %q", bad)
		}
	}
	_, public := keyPair(t, agentOf("11"), 1)
	text := KeyIDText(public.KeyID)
	if parsed, err := ParseKeyIDText(text); err != nil || parsed != public.KeyID {
		t.Fatal("key ID text does not round-trip")
	}
	for _, bad := range []string{"", strings.ToUpper(text), "mldsa44:" + text[len(KeyIDPrefix):], text + "0",
		KeyIDPrefix + strings.Repeat("0", 64)} {
		if _, err := ParseKeyIDText(bad); err == nil {
			t.Fatalf("accepted key ID %q", bad)
		}
	}
	if !CheckAck(AckHash(secretOf(3)), secretOf(3)) || CheckAck(AckHash(secretOf(3)), secretOf(4)) {
		t.Fatal("acknowledgement check is wrong")
	}
	if _, err := NewPrivateKey(agentOf("11"), seedOf(1)[:31]); err == nil {
		t.Fatal("accepted a short seed")
	}
	if _, err := Open(PrivateKey{}, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("opened with no key")
	}
	seed, err := GenerateSeed()
	if err != nil || len(seed) != PrivateKeySize {
		t.Fatal("seed generation failed")
	}
}
