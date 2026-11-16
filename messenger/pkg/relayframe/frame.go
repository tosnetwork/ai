// Package relayframe is the binary codec of Messenger relay carriage: the
// padded frame that rides as the payload of one signed Agent Packet, the
// objects it carries (a device copy, an Endpoint-signed delivery ack, an
// evidence pull), and the locator-free relay identity evidence every frame
// repeats.
//
// The package encodes and bounds bytes; it decides no authority. Whether the
// evidence names a live Endpoint, whether a copy may be opened and whether an
// ack settles a delivery are decided by its callers against finalized state.
package relayframe

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// Frame kinds.
const (
	// KindCopy carries one sealed Messenger device copy.
	KindCopy uint8 = 1
	// KindDeliveryAck carries one Endpoint-signed delivery acknowledgement.
	KindDeliveryAck uint8 = 2
	// KindRoom is reserved for split room handshake objects. This build does
	// not carry rooms and refuses the kind.
	KindRoom uint8 = 3
	// KindEvidence carries a one-byte evidence pull request or response.
	KindEvidence uint8 = 4
)

// Evidence pull object values of a kind-4 frame.
const (
	EvidenceRequest  uint8 = 1
	EvidenceResponse uint8 = 2
)

// Frame bounds.
const (
	// MaxFrameBytes is the largest frame: in base64 inside a packet with
	// maximal fixed fields it still fits the sealed packet bound.
	MaxFrameBytes = 190_464
	// MaxCardBytes bounds the exact key-card packet JSON a frame may carry.
	MaxCardBytes = 9_216
	// MaxEvidenceBytes bounds the relay identity evidence of one frame.
	MaxEvidenceBytes = 18_432
	// MaxParts bounds the parts of one object. Kinds 1, 2 and 4 use one.
	MaxParts = 8

	// domainBytes is the frame separator with its terminating zero byte.
	domainBytes = len(canon.DomainRelayFrame)
	// fixedBytes is everything of a frame except card, evidence, part and
	// padding: separator, kind, part index, part count, object digest and the
	// three length prefixes.
	fixedBytes = domainBytes + 3 + sha256.Size + 2 + 2 + 4
)

// Packet and seal sizes the envelope-size formula is built from.
const (
	// SealOverheadBytes is what sealing adds to the packet JSON: the clear
	// envelope header, the encapsulated key, the AEAD tag and the plaintext
	// wrapper header.
	SealOverheadBytes = agentpacketseal.EnvelopeHeaderSize + agentpacketseal.EncapsulatedKeySize +
		agentpacketseal.TagSize + agentpacketseal.PlaintextHeaderSize
	// MinPacketFixedFieldBytes and MaxPacketFixedFieldBytes bound the packet
	// JSON of a carriage packet minus its base64 payload. The range comes only
	// from the decimal widths of sequence and created_at_unix.
	MinPacketFixedFieldBytes = 5_394
	MaxPacketFixedFieldBytes = 5_432
)

// packetHeadroom is what a maximal frame leaves under the sealed packet bound.
// A negative value would be a compile error below, so a change of either
// bound that broke the 1.1 arithmetic cannot build.
const packetHeadroom = agentpacketseal.MaxPacketJSONBytes - (4*((MaxFrameBytes+2)/3) + MaxPacketFixedFieldBytes)

var _ [packetHeadroom]struct{}

// Buckets are the only frame sizes, ascending.
var buckets = [...]int{1 << 10, 2 << 10, 4 << 10, 8 << 10, 16 << 10, 32 << 10, 64 << 10, 128 << 10, MaxFrameBytes}

// Fixed codec errors. Nothing a frame contains is repeated in them.
var (
	ErrFrameMalformed        = errors.New("relay frame is malformed")
	ErrFrameSize             = errors.New("relay frame size is not a bucket size")
	ErrFramePadding          = errors.New("relay frame padding is not zero")
	ErrFrameKind             = errors.New("relay frame kind is unknown")
	ErrFrameKindUnsupported  = errors.New("relay frame kind is not carried by this build")
	ErrFrameDigest           = errors.New("relay frame object digest mismatch")
	ErrCardTooLarge          = errors.New("relay frame card exceeds its bound")
	ErrCardRequired          = errors.New("relay frame of this kind must carry the sender card")
	ErrEvidenceRequired      = errors.New("relay frame must carry relay identity evidence")
	ErrRelayEvidenceTooLarge = errors.New("relay-evidence-too-large")
	ErrContentTooLarge       = errors.New("relay frame content exceeds the largest bucket")
	ErrFrameNotMinimal       = errors.New("relay frame is not padded to its smallest bucket")
)

// Buckets returns the frame size buckets, ascending.
func Buckets() []int {
	return append([]int(nil), buckets[:]...)
}

// BucketFor returns the smallest bucket that holds n bytes.
func BucketFor(n int) (int, error) {
	if n <= 0 {
		return 0, ErrFrameMalformed
	}
	for _, bucket := range buckets {
		if n <= bucket {
			return bucket, nil
		}
	}
	return 0, ErrContentTooLarge
}

func isBucket(n int) bool {
	for _, bucket := range buckets {
		if n == bucket {
			return true
		}
	}
	return false
}

// Frame is one decoded relay frame. ObjectDigest is computed by Encode and
// checked by Decode; a caller never supplies it.
type Frame struct {
	Kind         uint8
	PartIndex    uint8
	PartCount    uint8
	ObjectDigest [sha256.Size]byte
	Card         []byte
	Evidence     []byte
	Part         []byte
}

// ObjectDigest commits one carried object.
func ObjectDigest(object []byte) [sha256.Size]byte {
	hash := sha256.New()
	hash.Write([]byte(canon.DomainRelayObject))
	hash.Write(object)
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

// UnpaddedSize returns the frame length before padding for the given field
// lengths, refusing lengths outside their bounds.
func UnpaddedSize(cardBytes, evidenceBytes, partBytes int) (int, error) {
	if cardBytes < 0 || evidenceBytes < 0 || partBytes < 0 {
		return 0, ErrFrameMalformed
	}
	if cardBytes > MaxCardBytes {
		return 0, ErrCardTooLarge
	}
	if evidenceBytes > MaxEvidenceBytes {
		return 0, ErrRelayEvidenceTooLarge
	}
	if partBytes > MaxFrameBytes {
		return 0, ErrContentTooLarge
	}
	// Each term is bounded above, so the sum cannot overflow an int, but the
	// total is still checked against the largest bucket.
	total := fixedBytes + cardBytes + evidenceBytes + partBytes
	if total > MaxFrameBytes {
		return 0, ErrContentTooLarge
	}
	return total, nil
}

// Encode validates and pads one single-part frame of kind 1, 2 or 4 to the
// smallest bucket that holds it.
func Encode(frame Frame) ([]byte, error) {
	if err := validateShape(frame.Kind, frame.PartIndex, frame.PartCount); err != nil {
		return nil, err
	}
	if err := validateFields(frame.Kind, frame.Card, frame.Evidence, frame.Part); err != nil {
		return nil, err
	}
	size, err := UnpaddedSize(len(frame.Card), len(frame.Evidence), len(frame.Part))
	if err != nil {
		return nil, err
	}
	bucket, err := BucketFor(size)
	if err != nil {
		return nil, err
	}
	digest := ObjectDigest(frame.Part)
	out := bytes.NewBuffer(make([]byte, 0, bucket))
	out.WriteString(canon.DomainRelayFrame)
	out.WriteByte(frame.Kind)
	out.WriteByte(frame.PartIndex)
	out.WriteByte(frame.PartCount)
	out.Write(digest[:])
	var length [4]byte
	binary.BigEndian.PutUint16(length[:2], uint16(len(frame.Card)))
	out.Write(length[:2])
	out.Write(frame.Card)
	binary.BigEndian.PutUint16(length[:2], uint16(len(frame.Evidence)))
	out.Write(length[:2])
	out.Write(frame.Evidence)
	binary.BigEndian.PutUint32(length[:], uint32(len(frame.Part)))
	out.Write(length[:])
	out.Write(frame.Part)
	if out.Len() != size {
		return nil, ErrFrameMalformed
	}
	out.Write(make([]byte, bucket-size))
	return out.Bytes(), nil
}

// Decode strictly parses one frame: a bucket-sized total, the frame domain, a
// kind this build carries, one part, bounded card and evidence, the object
// digest, and zero padding to the end.
func Decode(raw []byte) (Frame, error) {
	if !isBucket(len(raw)) {
		return Frame{}, ErrFrameSize
	}
	if !bytes.HasPrefix(raw, []byte(canon.DomainRelayFrame)) {
		return Frame{}, ErrFrameMalformed
	}
	reader := byteReader{buffer: raw, offset: domainBytes}
	kind := reader.u8()
	partIndex := reader.u8()
	partCount := reader.u8()
	digestRaw := reader.take(sha256.Size)
	if reader.err != nil {
		return Frame{}, ErrFrameMalformed
	}
	if err := validateShape(kind, partIndex, partCount); err != nil {
		return Frame{}, err
	}
	cardLength := int(reader.u16())
	if reader.err != nil {
		return Frame{}, ErrFrameMalformed
	}
	if cardLength > MaxCardBytes {
		return Frame{}, ErrCardTooLarge
	}
	card := reader.take(cardLength)
	evidenceLength := int(reader.u16())
	if reader.err != nil {
		return Frame{}, ErrFrameMalformed
	}
	if evidenceLength > MaxEvidenceBytes {
		return Frame{}, ErrRelayEvidenceTooLarge
	}
	evidence := reader.take(evidenceLength)
	partLength := reader.u32()
	if reader.err != nil {
		return Frame{}, ErrFrameMalformed
	}
	if uint64(partLength) > uint64(MaxFrameBytes) {
		return Frame{}, ErrFrameMalformed
	}
	part := reader.take(int(partLength))
	if reader.err != nil {
		return Frame{}, ErrFrameMalformed
	}
	// One content has one encoding: padding beyond the smallest bucket that
	// holds it would let two frames of different sizes mean the same thing.
	if bucket, err := BucketFor(reader.offset); err != nil || bucket != len(raw) {
		return Frame{}, ErrFrameNotMinimal
	}
	for _, value := range raw[reader.offset:] {
		if value != 0 {
			return Frame{}, ErrFramePadding
		}
	}
	frame := Frame{Kind: kind, PartIndex: partIndex, PartCount: partCount,
		Card: append([]byte(nil), card...), Evidence: append([]byte(nil), evidence...),
		Part: append([]byte(nil), part...)}
	copy(frame.ObjectDigest[:], digestRaw)
	if err := validateFields(kind, frame.Card, frame.Evidence, frame.Part); err != nil {
		return Frame{}, err
	}
	if ObjectDigest(frame.Part) != frame.ObjectDigest {
		return Frame{}, ErrFrameDigest
	}
	return frame, nil
}

func validateShape(kind, partIndex, partCount uint8) error {
	switch kind {
	case KindCopy, KindDeliveryAck, KindEvidence:
	case KindRoom:
		return ErrFrameKindUnsupported
	default:
		return ErrFrameKind
	}
	if partCount != 1 || partIndex != 0 {
		return ErrFrameMalformed
	}
	return nil
}

func validateFields(kind uint8, card, evidence, part []byte) error {
	if len(card) > MaxCardBytes {
		return ErrCardTooLarge
	}
	if kind == KindEvidence && len(card) == 0 {
		return ErrCardRequired
	}
	if len(evidence) == 0 {
		return ErrEvidenceRequired
	}
	if len(evidence) > MaxEvidenceBytes {
		return ErrRelayEvidenceTooLarge
	}
	if len(part) == 0 {
		return ErrFrameMalformed
	}
	if kind == KindEvidence && (len(part) != 1 || part[0] != EvidenceRequest && part[0] != EvidenceResponse) {
		return ErrFrameMalformed
	}
	return nil
}

// EnvelopeSize is what a relay stores for a frame of the given bucket inside
// a packet whose fields other than the payload take fixedFieldBytes:
// 1,373 + F + 4·⌈B/3⌉.
func EnvelopeSize(bucket, fixedFieldBytes int) (int, error) {
	if !isBucket(bucket) {
		return 0, ErrFrameSize
	}
	if fixedFieldBytes < MinPacketFixedFieldBytes || fixedFieldBytes > MaxPacketFixedFieldBytes {
		return 0, ErrFrameMalformed
	}
	return SealOverheadBytes + fixedFieldBytes + 4*((bucket+2)/3), nil
}

// byteReader is a latched bounds-checked reader over one frame or object.
type byteReader struct {
	buffer []byte
	offset int
	err    error
}

func (r *byteReader) take(count int) []byte {
	if r.err != nil {
		return nil
	}
	if count < 0 || count > len(r.buffer)-r.offset {
		r.err = ErrFrameMalformed
		return nil
	}
	value := r.buffer[r.offset : r.offset+count]
	r.offset += count
	return value
}

func (r *byteReader) u8() uint8 {
	raw := r.take(1)
	if raw == nil {
		return 0
	}
	return raw[0]
}

func (r *byteReader) u16() uint16 {
	raw := r.take(2)
	if raw == nil {
		return 0
	}
	return binary.BigEndian.Uint16(raw)
}

func (r *byteReader) u32() uint32 {
	raw := r.take(4)
	if raw == nil {
		return 0
	}
	return binary.BigEndian.Uint32(raw)
}

func (r *byteReader) u64() uint64 {
	raw := r.take(8)
	if raw == nil {
		return 0
	}
	return binary.BigEndian.Uint64(raw)
}

// lengthPrefixed reads a u32 length and then that many bytes, refusing a
// length above maximum with tooLarge before reading.
func (r *byteReader) lengthPrefixed(maximum int, tooLarge error) []byte {
	length := r.u32()
	if r.err != nil {
		return nil
	}
	if uint64(length) > uint64(maximum) {
		r.err = tooLarge
		return nil
	}
	raw := r.take(int(length))
	if raw == nil {
		return nil
	}
	return append([]byte{}, raw...)
}

func (r *byteReader) done() error {
	if r.err != nil {
		return r.err
	}
	if r.offset != len(r.buffer) {
		return ErrFrameMalformed
	}
	return nil
}
