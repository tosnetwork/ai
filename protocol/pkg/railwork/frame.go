// Package railwork implements the Service Actor rail work frames
// (spec/docs/SERVICE_ACTOR_RAIL_WORK_FRAMES_V1.md): the binary frame that
// carries one chunk of a rail message inside an Agent Packet, the canonical
// JSON messages a buyer and a provider exchange (task, result, result
// acknowledgement, result request), the values derived from them, and the
// receiver checks that bind them to the paid Service Actor request.
//
// Nothing a frame or message says is trusted: the provider admits work only
// while finalized state shows the paid request pending under the quoted
// terms, and the buyer accepts a result only when its Receipt hashes to the
// finalized attested response hash. This package holds the parts of those
// checks that need no chain access; the finalized-state reads stay with the
// caller.
//
// The package is strict where the specification lets a receiver be: every
// Base64 field, key cards included, must be canonical standard Base64 with
// padding and no line breaks when a message is decoded.
package railwork

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Kind is a frame and message kind.
type Kind uint8

// Frame kinds (section 3.1).
const (
	KindTask          Kind = 1
	KindResult        Kind = 2
	KindResultAck     Kind = 3
	KindResultRequest Kind = 4
)

// String names a kind.
func (k Kind) String() string {
	switch k {
	case KindTask:
		return "task"
	case KindResult:
		return "result"
	case KindResultAck:
		return "result-ack"
	case KindResultRequest:
		return "result-request"
	default:
		return fmt.Sprintf("kind-%d", uint8(k))
	}
}

// Frame layout and size bounds (sections 3 and 10).
const (
	FrameMagic   uint32 = 0x4f465231 // ASCII OFR1
	FrameVersion uint16 = 1
	// FrameHeaderBytes is the fixed frame header.
	FrameHeaderBytes = 4 + 2 + 1 + 32 + 8 + 32 + 32 + 4 + 1 + 1 + 4
	// MaxChunkData is the most data one frame carries.
	MaxChunkData = 60 << 10
	// MaxFrameBytes is the largest frame.
	MaxFrameBytes = FrameHeaderBytes + MaxChunkData
	// MaxChunks bounds the frames of one message.
	MaxChunks = 32
	// MaxMessageHeaderBytes bounds the canonical JSON header of a message.
	MaxMessageHeaderBytes = 64 << 10
	// MaxInlineInputBytes bounds the source archive a task carries.
	MaxInlineInputBytes = 1 << 20
	// MaxResultBytes bounds the artifact a result carries.
	MaxResultBytes = 1<<20 + 64<<10
	// MaxKeyCardBytes bounds a key card packet JSON.
	MaxKeyCardBytes = 16 << 10
	// MaxKeyCardBase64 bounds the Base64 text of a key card.
	MaxKeyCardBase64 = (MaxKeyCardBytes + 2) / 3 * 4
	// MaxReceiptBytes bounds the Receipt BOC a result carries and a buyer
	// accepts (sections 5.2, 7.2). Every field of SoftwareWorkReceiptV1 has
	// a fixed width, so its canonical BOC is at most 384 bytes.
	MaxReceiptBytes = 512
	// MaxReceiptBase64 bounds the Base64 text of a Receipt BOC.
	MaxReceiptBase64 = (MaxReceiptBytes + 2) / 3 * 4
	// MaxPackageBytes bounds the serialized Quote package a task carries
	// (section 5.1); the largest package an OpenFox offer produces is 2,195
	// bytes.
	MaxPackageBytes = 8 << 10
	// MaxPackageBase64 bounds the Base64 text of a Quote package.
	MaxPackageBase64 = (MaxPackageBytes + 2) / 3 * 4

	MaxTaskMessageBytes          = 4 + MaxMessageHeaderBytes + MaxInlineInputBytes
	MaxResultMessageBytes        = 4 + MaxMessageHeaderBytes + MaxResultBytes
	MaxAckMessageBytes           = 4 + 4<<10 + MaxKeyCardBase64
	MaxResultRequestMessageBytes = MaxAckMessageBytes
)

// MessageBound is the largest message of a kind.
func MessageBound(kind Kind) (uint32, error) {
	switch kind {
	case KindTask:
		return MaxTaskMessageBytes, nil
	case KindResult:
		return MaxResultMessageBytes, nil
	case KindResultAck:
		return MaxAckMessageBytes, nil
	case KindResultRequest:
		return MaxResultRequestMessageBytes, nil
	default:
		return 0, refuse(RefusalFrameInvalid, "unknown frame kind")
	}
}

// Binding is the request binding of a frame: the Service Actor's
// workchain-0 account, the actor's request ID and the call's request hash.
type Binding struct {
	ActorAccount [32]byte
	RequestID    uint64
	RequestHash  [32]byte
}

// Actor is the raw address of the bound workchain-0 actor.
func (b Binding) Actor() string {
	return rawAddress(b.ActorAccount)
}

// Frame is one chunk of a rail message.
type Frame struct {
	Kind          Kind
	Binding       Binding
	MessageDigest [32]byte
	TotalLength   uint32
	Index         uint8
	Count         uint8
	Data          []byte
}

// IsRailPayload reports whether a packet payload starts with the frame
// magic and version: the purpose check a receiver applies before any
// verification or write (section 2.1).
func IsRailPayload(raw []byte) bool {
	return len(raw) >= FrameHeaderBytes && binary.BigEndian.Uint32(raw[0:4]) == FrameMagic &&
		binary.BigEndian.Uint16(raw[4:6]) == FrameVersion
}

// CheckRailPayload refuses a payload that is not a rail frame as
// not-a-rail-frame.
func CheckRailPayload(raw []byte) error {
	if !IsRailPayload(raw) {
		return refuse(RefusalNotARailFrame, "the payload lacks the frame magic and version")
	}
	return nil
}

// EncodeFrame returns the binary frame. It refuses any frame DecodeFrame
// would refuse.
func EncodeFrame(frame Frame) ([]byte, error) {
	if err := validateFrame(frame); err != nil {
		return nil, err
	}
	out := make([]byte, 0, FrameHeaderBytes+len(frame.Data))
	out = binary.BigEndian.AppendUint32(out, FrameMagic)
	out = binary.BigEndian.AppendUint16(out, FrameVersion)
	out = append(out, byte(frame.Kind))
	out = append(out, frame.Binding.ActorAccount[:]...)
	out = binary.BigEndian.AppendUint64(out, frame.Binding.RequestID)
	out = append(out, frame.Binding.RequestHash[:]...)
	out = append(out, frame.MessageDigest[:]...)
	out = binary.BigEndian.AppendUint32(out, frame.TotalLength)
	out = append(out, frame.Index, frame.Count)
	// validateFrame bounded the data at MaxChunkData.
	out = binary.BigEndian.AppendUint32(out, uint32(len(frame.Data)))
	return append(out, frame.Data...), nil
}

// DecodeFrame parses one frame and refuses every shape section 3.1 and 3.2
// forbid as frame-invalid.
func DecodeFrame(raw []byte) (Frame, error) {
	if len(raw) < FrameHeaderBytes || len(raw) > MaxFrameBytes {
		return Frame{}, refuse(RefusalFrameInvalid, "the frame is outside its size bounds")
	}
	if binary.BigEndian.Uint32(raw[0:4]) != FrameMagic || binary.BigEndian.Uint16(raw[4:6]) != FrameVersion {
		return Frame{}, refuse(RefusalFrameInvalid, "wrong frame magic or version")
	}
	var frame Frame
	frame.Kind = Kind(raw[6])
	copy(frame.Binding.ActorAccount[:], raw[7:39])
	frame.Binding.RequestID = binary.BigEndian.Uint64(raw[39:47])
	copy(frame.Binding.RequestHash[:], raw[47:79])
	copy(frame.MessageDigest[:], raw[79:111])
	frame.TotalLength = binary.BigEndian.Uint32(raw[111:115])
	frame.Index, frame.Count = raw[115], raw[116]
	length := binary.BigEndian.Uint32(raw[117:121])
	if uint64(length) != uint64(len(raw)-FrameHeaderBytes) {
		return Frame{}, refuse(RefusalFrameInvalid, "the data length field differs from the data")
	}
	frame.Data = bytes.Clone(raw[FrameHeaderBytes:])
	if err := validateFrame(frame); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

func validateFrame(frame Frame) error {
	bound, err := MessageBound(frame.Kind)
	if err != nil {
		return err
	}
	if frame.Binding.ActorAccount == ([32]byte{}) || frame.Binding.RequestHash == ([32]byte{}) ||
		frame.MessageDigest == ([32]byte{}) {
		return refuse(RefusalFrameInvalid, "an all-zero actor account, request hash or message digest")
	}
	if frame.TotalLength == 0 || frame.TotalLength > bound {
		return refuse(RefusalFrameInvalid, "the total length is outside the kind's bound")
	}
	if frame.Count == 0 || frame.Count > MaxChunks || frame.Index >= frame.Count {
		return refuse(RefusalFrameInvalid, "the chunk index or count is outside its bounds")
	}
	if len(frame.Data) == 0 || len(frame.Data) > MaxChunkData {
		return refuse(RefusalFrameInvalid, "the frame data is outside its bounds")
	}
	expected, err := ChunkLength(frame.TotalLength, frame.Index, frame.Count)
	if err != nil {
		return err
	}
	if uint64(expected) != uint64(len(frame.Data)) {
		return refuse(RefusalFrameInvalid, "the chunking is not canonical")
	}
	return nil
}

// ChunkLength is the data length chunk index of a total-byte message split
// into count chunks carries under the one canonical chunking (section 3.2).
func ChunkLength(total uint32, index, count uint8) (uint32, error) {
	want := (uint64(total) + MaxChunkData - 1) / MaxChunkData
	if total == 0 || want != uint64(count) || index >= count {
		return 0, refuse(RefusalFrameInvalid, "the chunk count does not match the total length")
	}
	if index+1 < count {
		return MaxChunkData, nil
	}
	// count >= 1 and total > (count-1)*MaxChunkData by the check above.
	return uint32(uint64(total) - uint64(count-1)*MaxChunkData), nil
}

// SplitMessage chunks one message into its canonical frames.
func SplitMessage(kind Kind, binding Binding, message []byte) ([]Frame, error) {
	bound, err := MessageBound(kind)
	if err != nil {
		return nil, err
	}
	if len(message) == 0 || uint64(len(message)) > uint64(bound) {
		return nil, refuse(RefusalMessageInvalid,
			fmt.Sprintf("a %d-byte %s message is outside the %d-byte bound", len(message), kind, bound))
	}
	if binding.ActorAccount == ([32]byte{}) || binding.RequestHash == ([32]byte{}) {
		return nil, refuse(RefusalFrameInvalid, "an all-zero actor account or request hash")
	}
	count := (len(message) + MaxChunkData - 1) / MaxChunkData
	digest := sha256.Sum256(message)
	frames := make([]Frame, 0, count)
	for index := 0; index < count; index++ {
		start := index * MaxChunkData
		end := min(start+MaxChunkData, len(message))
		frames = append(frames, Frame{
			Kind: kind, Binding: binding, MessageDigest: digest,
			TotalLength: uint32(len(message)), Index: uint8(index), Count: uint8(count),
			Data: bytes.Clone(message[start:end]),
		})
	}
	return frames, nil
}

// EncodeMessageFrames splits a message and encodes every frame, in index
// order.
func EncodeMessageFrames(kind Kind, binding Binding, message []byte) ([][]byte, error) {
	frames, err := SplitMessage(kind, binding, message)
	if err != nil {
		return nil, err
	}
	encoded := make([][]byte, 0, len(frames))
	for _, frame := range frames {
		raw, encodeErr := EncodeFrame(frame)
		if encodeErr != nil {
			return nil, encodeErr
		}
		encoded = append(encoded, raw)
	}
	return encoded, nil
}

func sameMessage(a, b Frame) bool {
	return a.Kind == b.Kind && a.Binding == b.Binding && a.MessageDigest == b.MessageDigest &&
		a.TotalLength == b.TotalLength && a.Count == b.Count
}

// JoinFrames reassembles one complete frame set in any order and checks
// its digest (section 3.3). Any other set is refused as join-invalid, or
// as frame-invalid for a frame that is not valid by itself.
func JoinFrames(frames []Frame) ([]byte, error) {
	if len(frames) == 0 || len(frames) > MaxChunks {
		return nil, refuse(RefusalJoinInvalid, "no complete frame set")
	}
	first := frames[0]
	if err := validateFrame(first); err != nil {
		return nil, err
	}
	ordered := make([][]byte, first.Count)
	for _, frame := range frames {
		if err := validateFrame(frame); err != nil {
			return nil, err
		}
		if !sameMessage(frame, first) {
			return nil, refuse(RefusalJoinInvalid, "the frames belong to different messages")
		}
		if ordered[frame.Index] != nil {
			return nil, refuse(RefusalJoinInvalid, "a frame index repeats")
		}
		ordered[frame.Index] = frame.Data
	}
	message := make([]byte, 0, first.TotalLength)
	for _, chunk := range ordered {
		if chunk == nil {
			return nil, refuse(RefusalJoinInvalid, "the frame set is incomplete")
		}
		message = append(message, chunk...)
	}
	if uint64(len(message)) != uint64(first.TotalLength) || sha256.Sum256(message) != first.MessageDigest {
		return nil, refuse(RefusalJoinInvalid, "the joined message does not match its digest")
	}
	return message, nil
}
