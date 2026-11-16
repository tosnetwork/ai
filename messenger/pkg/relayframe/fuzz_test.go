package relayframe

import (
	"bytes"
	"testing"
)

func fuzzEvidence() []byte {
	raw, err := EncodeEvidence(Evidence{Delegation: []byte("d"), Policy: []byte("p"), Descriptor: []byte("c"), BundleSet: []byte("s")})
	if err != nil {
		return nil
	}
	return raw
}

// Every frame a decoder accepts re-encodes, and its content is unchanged: the
// encoder pads to the smallest bucket, so its output is a prefix of the
// accepted frame whose remainder is zero padding.
func FuzzDecodeFrame(f *testing.F) {
	if seed, err := Encode(Frame{Kind: KindEvidence, PartCount: 1, Card: []byte("card"), Evidence: fuzzEvidence(),
		Part: []byte{EvidenceRequest}}); err == nil {
		f.Add(seed)
	}
	f.Add(make([]byte, 1<<10))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		frame, err := Decode(raw)
		if err != nil {
			return
		}
		encoded, err := Encode(frame)
		if err != nil {
			t.Fatalf("a decoded frame did not re-encode: %v", err)
		}
		if len(encoded) > len(raw) || !bytes.Equal(encoded, raw[:len(encoded)]) {
			t.Fatal("re-encoding a decoded frame changed its content")
		}
	})
}

func FuzzDecodeEvidence(f *testing.F) {
	f.Add(fuzzEvidence())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		evidence, err := DecodeEvidence(raw)
		if err != nil {
			return
		}
		encoded, err := EncodeEvidence(evidence)
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatalf("decoded evidence is not canonical: %v", err)
		}
	})
}

func FuzzDecodeCopy(f *testing.F) {
	if seed, err := EncodeCopy(Copy{EventID: "evt_" + string(bytes.Repeat([]byte{'1'}, 64)),
		SessionID: "ses_" + string(bytes.Repeat([]byte{'2'}, 64)), RecipientEndpointID: "mep_" + string(bytes.Repeat([]byte{'3'}, 64)),
		RecipientDeviceID: "dev_" + string(bytes.Repeat([]byte{'4'}, 64)), ConversationID: "conv_" + string(bytes.Repeat([]byte{'5'}, 64)),
		Ciphertext: make([]byte, MinCiphertextBytes), ExpiresAtUnix: 1}); err == nil {
		f.Add(seed)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		value, err := DecodeCopy(raw)
		if err != nil {
			return
		}
		encoded, err := EncodeCopy(value)
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatalf("decoded copy is not canonical: %v", err)
		}
	})
}

func FuzzDecodeAck(f *testing.F) {
	f.Add([]byte("tos.messaging.relay-delivery-ack.v1\x00"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		ack, err := DecodeAck(raw)
		if err != nil {
			return
		}
		encoded, err := EncodeAck(ack)
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatalf("decoded ack is not canonical: %v", err)
		}
	})
}

func FuzzDecodeContact(f *testing.F) {
	if seed, err := EncodeContactJSON(Contact{AgentID: "agent_" + string(bytes.Repeat([]byte{'a'}, 64)),
		Evidence: fuzzEvidence(), Card: []byte("card")}); err == nil {
		f.Add(seed)
	}
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		contact, err := DecodeContactJSON(raw)
		if err != nil {
			return
		}
		if _, err := EncodeContactJSON(contact); err != nil {
			t.Fatalf("a decoded contact did not re-encode: %v", err)
		}
	})
}
