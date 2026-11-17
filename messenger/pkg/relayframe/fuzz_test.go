package relayframe

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/room"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
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
	if header := fuzzHeader(); header != nil {
		if welcome, err := EncodeRoomObject(RoomObject{Type: RoomWelcome, RoomID: header.Membership.RoomID, RoomEpoch: 2,
			MLSEpoch: 4, Header: header, Body: []byte("welcome")}); err == nil {
			f.Add(welcome)
		}
	}
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
		Card: []byte("card"), Evidence: fuzzEvidence(), Credential: []byte("leaf credential")}}); err == nil {
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

// fuzzHeader is a valid two-member header for epoch 2 of the fuzz room.
func fuzzHeader() *RoomHeader {
	roomID := "room_" + string(bytes.Repeat([]byte{'7'}, 64))
	members := []string{"agent_" + string(bytes.Repeat([]byte{'1'}, 64)), "agent_" + string(bytes.Repeat([]byte{'2'}, 64))}
	digest, err := room.Digest(roomID, 2, members)
	if err != nil {
		return nil
	}
	authorization, err := room.SignMembershipAuthorization(room.MembershipAuthorization{
		Network: &nativev1.NetworkDomain{NetworkId: "tos-local", GenesisRootHash: string(bytes.Repeat([]byte{'a'}, 64)),
			GenesisFileHash: string(bytes.Repeat([]byte{'b'}, 64))},
		RoomID: roomID, Epoch: 2, MembershipDigest: digest,
		Authority:    room.Authority{AgentID: members[0], EndpointID: "mep_" + string(bytes.Repeat([]byte{'e'}, 64))},
		IssuedAtUnix: 1, ExpiresAtUnix: 2,
	}, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)))
	if err != nil {
		return nil
	}
	return &RoomHeader{Membership: room.Membership{RoomID: roomID, Epoch: 2, Members: members, Digest: digest}, Authorization: authorization,
		EndsAtUnix: 3}
}

// FuzzReassembler builds real objects split at the smallest test part size
// and lets the script choose, for each step, a sender, an object and part,
// a mutation and the time. Whatever arrives, the reassembler never holds more
// than its bounds and releases only exact objects.
func FuzzReassembler(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 2, 0, 0, 4, 0, 0, 6, 0})
	f.Add([]byte{1, 1, 1, 2, 3, 2, 0, 5, 3, 1, 7, 7})
	header := fuzzHeader()
	var objects [][]byte
	var frames [][]Frame
	for index, body := range []int{3_000, 5_000} {
		object, err := EncodeRoomObject(RoomObject{Type: RoomWelcome, RoomID: header.Membership.RoomID, RoomEpoch: 2,
			MLSEpoch: uint64(index + 1), Header: header, Body: bytes.Repeat([]byte{byte(index)}, body)})
		if err != nil {
			f.Fatal(err)
		}
		split, err := SplitRoomObject(object, nil, fuzzEvidence(), MinTestPartBytes)
		if err != nil {
			f.Fatal(err)
		}
		var decoded []Frame
		for _, raw := range split {
			frame, err := Decode(raw)
			if err != nil {
				f.Fatal(err)
			}
			decoded = append(decoded, frame)
		}
		objects = append(objects, object)
		frames = append(frames, decoded)
	}
	senders := []string{"agent_" + string(bytes.Repeat([]byte{'a'}, 64)), "agent_" + string(bytes.Repeat([]byte{'b'}, 64)),
		"agent_" + string(bytes.Repeat([]byte{'e'}, 64)), "agent_" + string(bytes.Repeat([]byte{'f'}, 64))}
	f.Fuzz(func(t *testing.T, script []byte) {
		limits := DefaultReassemblyLimits()
		limits.PartBytes = MinTestPartBytes
		reassembler, err := NewReassembler(limits, fuzzSenders{})
		if err != nil {
			t.Fatal(err)
		}
		for step := 0; step+3 <= len(script) && step < 3*128; step += 3 {
			sender := senders[int(script[step])%len(senders)]
			choice := int(script[step+1]) % len(objects)
			frame := frames[choice][int(script[step+1]/2)%len(frames[choice])]
			frame.Part = append([]byte(nil), frame.Part...)
			switch script[step+2] % 4 {
			case 1:
				frame.Part = frame.Part[:len(frame.Part)-1]
				if len(frame.Part) == 0 {
					continue
				}
			case 2:
				frame.PartCount = frame.PartCount%MaxParts + 1
				if frame.PartIndex >= frame.PartCount || frame.PartCount == 1 {
					continue
				}
			case 3:
				frame.Part[len(frame.Part)/2] ^= 0x5a
			}
			at := time.Unix(1+int64(script[step+2]/4)*6*3600, 0)
			result, err := reassembler.Add(sender, frame, at)
			if err == nil && result.Status == PartComplete && !bytes.Equal(result.Object, objects[choice]) {
				t.Fatal("an object was released that is not the one split")
			}
			usage := reassembler.Usage()
			if usage.TotalBytes > limits.MaxTotalBytes || usage.TotalBytes < 0 {
				t.Fatal("the global bound was broken")
			}
			for _, held := range usage.PeerBytes {
				if held > limits.MaxPeerBytes || held <= 0 {
					t.Fatal("a per-peer byte bound was broken")
				}
			}
			for _, count := range usage.PeerCount {
				if count > limits.MaxPeerObjects || count <= 0 {
					t.Fatal("a per-peer object bound was broken")
				}
			}
		}
	})
}
