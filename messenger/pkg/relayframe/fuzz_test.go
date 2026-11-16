package relayframe

import (
	"bytes"
	"testing"
	"time"
)

func fuzzEvidence() []byte {
	raw, err := EncodeEvidence(Evidence{Delegation: []byte("d"), Policy: []byte("p"), Descriptor: []byte("c"), BundleSet: []byte("s")})
	if err != nil {
		return nil
	}
	return raw
}

// Every frame a decoder accepts is canonical: re-encoding it gives exactly
// the accepted bytes.
func FuzzDecodeFrame(f *testing.F) {
	if seed, err := Encode(Frame{Kind: KindEvidence, PartCount: 1, Card: []byte("card"), Evidence: fuzzEvidence(),
		Part: []byte{EvidenceRequest}}); err == nil {
		f.Add(seed)
	}
	// A split kind-3 object at the smallest test part size: its later parts
	// carry neither card nor evidence and the whole object's digest.
	if object, err := EncodeRoomObject(RoomObject{Type: RoomCommit, RoomID: "room_" + string(bytes.Repeat([]byte{'7'}, 64)),
		RoomEpoch: 2, MLSEpoch: 3, Body: make([]byte, 1500)}); err == nil {
		if frames, err := SplitRoomObject(object, []byte("card"), fuzzEvidence(), MinTestPartBytes); err == nil {
			for _, frame := range frames {
				f.Add(frame)
			}
		}
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
		if !bytes.Equal(encoded, raw) {
			t.Fatal("a decoded frame is not canonical")
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

func fuzzRoomObject() []byte {
	raw, err := EncodeRoomObject(RoomObject{Type: RoomCommit, RoomID: "room_" + string(bytes.Repeat([]byte{'7'}, 64)),
		RoomEpoch: 2, MLSEpoch: 3, Body: []byte("refresh")})
	if err != nil {
		return nil
	}
	return raw
}

// Every room object a decoder accepts is canonical.
func FuzzDecodeRoomObject(f *testing.F) {
	f.Add(fuzzRoomObject())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		object, err := DecodeRoomObject(raw)
		if err != nil {
			return
		}
		encoded, err := EncodeRoomObject(object)
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatalf("a decoded room object is not canonical: %v", err)
		}
	})
}

func FuzzDecodeRoster(f *testing.F) {
	if seed, err := EncodeRoster([]RosterEntry{{AgentID: "agent_" + string(bytes.Repeat([]byte{'a'}, 64)),
		Card: []byte("card"), Evidence: fuzzEvidence()}}); err == nil {
		f.Add(seed)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		entries, err := DecodeRoster(raw)
		if err != nil {
			return
		}
		encoded, err := EncodeRoster(entries)
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatalf("a decoded roster is not canonical: %v", err)
		}
	})
}

func FuzzDecodeRoomAck(f *testing.F) {
	f.Add([]byte("tos.messaging.relay-room-ack.v1\x00"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		ack, err := DecodeRoomAck(raw)
		if err != nil {
			return
		}
		encoded, err := EncodeRoomAck(ack)
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatalf("a decoded room ack is not canonical: %v", err)
		}
	})
}

type fuzzSenders struct{}

func (fuzzSenders) MayHold(sender string) bool { return sender[len(sender)-1] != 'f' }
func (fuzzSenders) MayHoldInRoom(sender, _ string) bool {
	return sender[len(sender)-1] != 'e'
}

// Whatever sequence of kind-3 frames arrives, the reassembler never holds
// more than its bounds, and releases only objects that match their digest.
func FuzzReassembler(f *testing.F) {
	object := fuzzRoomObject()
	if frames, err := SplitRoomObject(object, nil, fuzzEvidence(), 0); err == nil {
		f.Add(frames[0], uint8(0))
	}
	f.Add(make([]byte, 1<<10), uint8(1))
	f.Fuzz(func(t *testing.T, raw []byte, senderSeed uint8) {
		limits := DefaultReassemblyLimits()
		limits.MaxPeerBytes, limits.MaxTotalBytes, limits.MaxObjectBytes = 2<<20, 3<<20, MaxRoomObjectBytes
		reassembler, err := NewReassembler(limits, fuzzSenders{})
		if err != nil {
			t.Fatal(err)
		}
		// Feed the input as up to four frames from a few senders.
		for chunk := 0; chunk < 4 && len(raw) > 0; chunk++ {
			size := len(raw)
			for _, bucket := range Buckets() {
				if bucket <= len(raw) {
					size = bucket
				}
			}
			frame, err := Decode(raw[:size])
			raw = raw[size:]
			if err != nil || frame.Kind != KindRoom {
				continue
			}
			sender := "agent_" + string(bytes.Repeat([]byte{"0123456789abcdef"[(int(senderSeed)+chunk)%16]}, 64))
			result, err := reassembler.Add(sender, frame, time.Unix(1, 0))
			if err == nil && result.Status == PartComplete && ObjectDigest(result.Object) != frame.ObjectDigest {
				t.Fatal("an object was released under another digest")
			}
			usage := reassembler.Usage()
			if usage.TotalBytes > limits.MaxTotalBytes {
				t.Fatal("the global bound was exceeded")
			}
			for _, held := range usage.PeerBytes {
				if held > limits.MaxPeerBytes {
					t.Fatal("a per-peer bound was exceeded")
				}
			}
			for _, count := range usage.PeerCount {
				if count > limits.MaxPeerObjects {
					t.Fatal("a per-peer object bound was exceeded")
				}
			}
		}
	})
}
