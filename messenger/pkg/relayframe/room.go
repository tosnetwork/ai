package relayframe

// Room objects: what a kind-3 frame carries, and the fixed cut that splits a
// handshake object into parts.
//
//	room_object =
//	  D("tos.messaging.relay-room-object.v1")   35 bytes
//	  object_type   u8   1 Commit, 2 Welcome, 3 application, 4 roster
//	  room_id       32   the raw digest of the room_ ID
//	  room_epoch    u64
//	  mls_epoch     u64
//	  header_length u16  0 .. 8,192
//	  header             membership and its authorization, or empty
//	  body_length   u32  1 .. 1,048,576
//	  body               the MLS Commit, Welcome or PrivateMessage, or the roster
//
// The cut does not depend on the card or evidence a frame happens to carry,
// so every re-deposit generation has byte-identical parts under one digest
// although part 0 drops its card once acknowledged.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/room"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

// Room object types.
const (
	RoomCommit      uint8 = 1
	RoomWelcome     uint8 = 2
	RoomApplication uint8 = 3
	RoomRoster      uint8 = 4
)

// Room object bounds and the fixed cut.
const (
	// RoomObjectFixedBytes is every byte of a room object but header and body.
	RoomObjectFixedBytes = len(canon.DomainRelayRoomObject) + 1 + sha256.Size + 8 + 8 + 2 + 4
	// MaxRoomHeaderBytes bounds the header.
	MaxRoomHeaderBytes = 8_192
	// MaxRoomBodyBytes bounds the body: an MLS object reaches 1 MiB.
	MaxRoomBodyBytes = 1 << 20
	// MaxRoomObjectBytes is the largest room object.
	MaxRoomObjectBytes = RoomObjectFixedBytes + MaxRoomHeaderBytes + MaxRoomBodyBytes
	// MaxRoomApplicationBodyBytes bounds an application body: a 131,072-byte
	// Event sealed with at most 4,096 bytes of PrivateMessage overhead. It
	// keeps every application object inside part 0, so it is never split.
	MaxRoomApplicationBodyBytes = MaxRoomApplicationPlaintextBytes + 4_096
	// MaxRoomApplicationPlaintextBytes bounds the Event a member seals.
	MaxRoomApplicationPlaintextBytes = 131_072
	// FirstPartBytes is the object bytes in part 0: a maximal frame less the
	// fixed bytes and a maximal card and evidence.
	FirstPartBytes = MaxFrameBytes - fixedBytes - MaxCardBytes - MaxEvidenceBytes
	// LaterPartBytes is the object bytes in every later part.
	LaterPartBytes = MaxFrameBytes - fixedBytes
	// MinTestPartBytes and MaxTestPartBytes bound the test part size P that
	// cuts every part of a handshake object.
	MinTestPartBytes = 1_024
	MaxTestPartBytes = FirstPartBytes
	// MaxRosterEntries bounds a roster: every member but the receiver.
	MaxRosterEntries = 31
	// MaxRoomMembers bounds a relay room's membership.
	MaxRoomMembers = 32
	// MaxRosterCredentialBytes is the roster codec's bound on an entry's leaf
	// credential; the largest valid credential is 473 bytes (section 11.2).
	MaxRosterCredentialBytes = 512
	// MaxRoomHeaderValidBytes is the largest header a valid membership
	// reaches: 32 members and a 128-byte network ID (section 11.1).
	MaxRoomHeaderValidBytes = 1 + MaxRoomMembers*agentIDBytes + 2 + 128 + 2*sha256.Size + agentIDBytes +
		endpointIDBytes + 8 + 8 + ed25519.SignatureSize + 8
	// MaxRoomObjectValidBytes is the largest valid room object.
	MaxRoomObjectValidBytes = RoomObjectFixedBytes + MaxRoomHeaderValidBytes + MaxRoomBodyBytes

	agentIDBytes    = len("agent_") + 64
	endpointIDBytes = len("mep_") + 64
)

// The fixed cut must fit the 8-part limit for the largest object, and an
// application object must fit part 0; a change of a bound that broke either
// cannot build. The valid header and object sizes are those section 11.1
// states, inside the codec bounds.
var (
	_ [FirstPartBytes + (MaxParts-1)*LaterPartBytes - MaxRoomObjectBytes]struct{}
	_ [FirstPartBytes - RoomObjectFixedBytes - MaxRoomApplicationBodyBytes]struct{}
	_ [MaxRoomHeaderValidBytes - 2_661]struct{}
	_ [2_661 - MaxRoomHeaderValidBytes]struct{}
	_ [MaxRoomObjectValidBytes - 1_051_327]struct{}
	_ [1_051_327 - MaxRoomObjectValidBytes]struct{}
	_ [MaxRoomHeaderBytes - MaxRoomHeaderValidBytes]struct{}
)

// Room codec errors.
var (
	ErrRoomObjectMalformed = errors.New("room object is malformed")
	ErrRoomObjectTooLarge  = errors.New("room object exceeds its bound")
	ErrRoomHeaderTooLarge  = errors.New("room object header exceeds its bound")
	ErrRoomTooManyParts    = errors.New("room object needs more parts than a frame allows")
	ErrRoomPartSize        = errors.New("room part size is outside the test range")
	ErrRosterMalformed     = errors.New("room roster is malformed")
	ErrRoomAADMalformed    = errors.New("room authenticated data is malformed")
)

// RoomHeader is the membership a handshake object makes or describes, with
// the authority's authorization of exactly it, and the room's end time.
type RoomHeader struct {
	Membership    room.Membership
	Authorization room.MembershipAuthorization
	// EndsAtUnix is the room's end time (D18): the expires_at of the
	// authority's leaf credential, the same in every header of the room. It
	// is outside the authorization's signed preimage; the authority's
	// Endpoint signs it in that credential, and a receiver requires the two
	// to be equal.
	EndsAtUnix uint64
}

// RoomObject is one decoded room object.
type RoomObject struct {
	Type      uint8
	RoomID    string
	RoomEpoch uint64
	MLSEpoch  uint64
	// Header is nil for an MLS-only refresh Commit and an application object,
	// and set for every other handshake object.
	Header *RoomHeader
	Body   []byte
}

// EncodeRoomObject validates and encodes one room object.
func EncodeRoomObject(object RoomObject) ([]byte, error) {
	if err := validateRoomObject(object); err != nil {
		return nil, err
	}
	header := []byte{}
	if object.Header != nil {
		encoded, err := encodeRoomHeader(object.RoomID, object.RoomEpoch, *object.Header)
		if err != nil {
			return nil, err
		}
		header = encoded
	}
	raw, err := roomIDBytes(object.RoomID)
	if err != nil {
		return nil, err
	}
	out := bytes.NewBuffer(make([]byte, 0, RoomObjectFixedBytes+len(header)+len(object.Body)))
	out.WriteString(canon.DomainRelayRoomObject)
	out.WriteByte(object.Type)
	out.Write(raw)
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], object.RoomEpoch)
	out.Write(number[:])
	binary.BigEndian.PutUint64(number[:], object.MLSEpoch)
	out.Write(number[:])
	binary.BigEndian.PutUint16(number[:2], uint16(len(header)))
	out.Write(number[:2])
	out.Write(header)
	binary.BigEndian.PutUint32(number[:4], uint32(len(object.Body)))
	out.Write(number[:4])
	out.Write(object.Body)
	return out.Bytes(), nil
}

// DecodeRoomObject strictly parses one room object. The header's membership
// digest is recomputed and its authorization is checked to name exactly that
// membership; whether the authorization is the room authority's, and current,
// is the caller's judgement against finalized state.
func DecodeRoomObject(raw []byte) (RoomObject, error) {
	if len(raw) > MaxRoomObjectBytes {
		return RoomObject{}, ErrRoomObjectTooLarge
	}
	if !bytes.HasPrefix(raw, []byte(canon.DomainRelayRoomObject)) {
		return RoomObject{}, ErrRoomObjectMalformed
	}
	reader := byteReader{buffer: raw, offset: len(canon.DomainRelayRoomObject)}
	object := RoomObject{Type: reader.u8()}
	roomRaw := reader.take(sha256.Size)
	object.RoomEpoch = reader.u64()
	object.MLSEpoch = reader.u64()
	headerLength := int(reader.u16())
	if reader.err != nil {
		return RoomObject{}, ErrRoomObjectMalformed
	}
	if headerLength > MaxRoomHeaderBytes {
		return RoomObject{}, ErrRoomHeaderTooLarge
	}
	header := reader.take(headerLength)
	bodyLength := reader.u32()
	if reader.err != nil {
		return RoomObject{}, ErrRoomObjectMalformed
	}
	if bodyLength == 0 || bodyLength > MaxRoomBodyBytes {
		return RoomObject{}, ErrRoomObjectMalformed
	}
	object.Body = append([]byte(nil), reader.take(int(bodyLength))...)
	if reader.err != nil || reader.offset != len(raw) {
		return RoomObject{}, ErrRoomObjectMalformed
	}
	object.RoomID = "room_" + hex.EncodeToString(roomRaw)
	if headerLength > 0 {
		decoded, err := decodeRoomHeader(object.RoomID, object.RoomEpoch, header)
		if err != nil {
			return RoomObject{}, err
		}
		object.Header = &decoded
	}
	if err := validateRoomObject(object); err != nil {
		return RoomObject{}, err
	}
	return object, nil
}

func validateRoomObject(object RoomObject) error {
	if !ids.Room.MatchString(object.RoomID) || object.RoomEpoch == 0 {
		return ErrRoomObjectMalformed
	}
	if len(object.Body) == 0 || len(object.Body) > MaxRoomBodyBytes {
		return ErrRoomObjectMalformed
	}
	switch object.Type {
	case RoomCommit:
		// A Commit that changes the room epoch carries its header; an
		// MLS-only refresh carries none.
	case RoomWelcome, RoomRoster:
		if object.Header == nil {
			return ErrRoomObjectMalformed
		}
	case RoomApplication:
		if object.Header != nil || len(object.Body) > MaxRoomApplicationBodyBytes {
			return ErrRoomObjectMalformed
		}
	default:
		return ErrRoomObjectMalformed
	}
	if object.Header != nil {
		membership := object.Header.Membership
		if membership.RoomID != object.RoomID || membership.Epoch != object.RoomEpoch {
			return ErrRoomObjectMalformed
		}
	}
	if object.Type == RoomRoster {
		if _, err := DecodeRoster(object.Body); err != nil {
			return err
		}
	}
	return nil
}

func roomIDBytes(roomID string) ([]byte, error) {
	if !ids.Room.MatchString(roomID) {
		return nil, ErrRoomObjectMalformed
	}
	raw, err := hex.DecodeString(roomID[len("room_"):])
	if err != nil || len(raw) != sha256.Size {
		return nil, ErrRoomObjectMalformed
	}
	return raw, nil
}

// The header:
//
//	member_count  u8   1 .. 32
//	members            agent_ IDs, 70 bytes each, ascending
//	network_id    u16-prefixed, 1 .. 128 bytes
//	genesis_root  32
//	genesis_file  32
//	authority     agent_ ID (70) and mep_ ID (68)
//	issued_at     u64
//	expires_at    u64
//	signature     64
//	room_ends_at  u64  the room's end time (D18), never zero
//
// Room and epoch come from the object; the membership digest is recomputed.
func encodeRoomHeader(roomID string, roomEpoch uint64, header RoomHeader) ([]byte, error) {
	membership, authorization := header.Membership, header.Authorization
	digest, err := room.Digest(roomID, roomEpoch, membership.Members)
	if err != nil || digest != membership.Digest || len(membership.Members) > MaxRoomMembers {
		return nil, ErrRoomObjectMalformed
	}
	if authorization.RoomID != roomID || authorization.Epoch != roomEpoch || authorization.MembershipDigest != digest {
		return nil, ErrRoomObjectMalformed
	}
	if _, err := room.MembershipAuthorizationSigningBytes(authorization); err != nil {
		return nil, ErrRoomObjectMalformed
	}
	if len(authorization.EndpointSignature) != ed25519.SignatureSize || header.EndsAtUnix == 0 {
		return nil, ErrRoomObjectMalformed
	}
	root, rootErr := hex.DecodeString(authorization.Network.GenesisRootHash)
	file, fileErr := hex.DecodeString(authorization.Network.GenesisFileHash)
	if rootErr != nil || fileErr != nil || len(root) != sha256.Size || len(file) != sha256.Size {
		return nil, ErrRoomObjectMalformed
	}
	out := &bytes.Buffer{}
	out.WriteByte(uint8(len(membership.Members)))
	for index, member := range membership.Members {
		if !ids.Agent.MatchString(member) || (index > 0 && member <= membership.Members[index-1]) {
			return nil, ErrRoomObjectMalformed
		}
		out.WriteString(member)
	}
	var number [8]byte
	binary.BigEndian.PutUint16(number[:2], uint16(len(authorization.Network.NetworkId)))
	out.Write(number[:2])
	out.WriteString(authorization.Network.NetworkId)
	out.Write(root)
	out.Write(file)
	out.WriteString(authorization.Authority.AgentID)
	out.WriteString(authorization.Authority.EndpointID)
	binary.BigEndian.PutUint64(number[:], authorization.IssuedAtUnix)
	out.Write(number[:])
	binary.BigEndian.PutUint64(number[:], authorization.ExpiresAtUnix)
	out.Write(number[:])
	out.Write(authorization.EndpointSignature)
	binary.BigEndian.PutUint64(number[:], header.EndsAtUnix)
	out.Write(number[:])
	if out.Len() > MaxRoomHeaderBytes {
		return nil, ErrRoomHeaderTooLarge
	}
	return out.Bytes(), nil
}

func decodeRoomHeader(roomID string, roomEpoch uint64, raw []byte) (RoomHeader, error) {
	reader := byteReader{buffer: raw}
	count := int(reader.u8())
	if reader.err != nil || count == 0 || count > MaxRoomMembers {
		return RoomHeader{}, ErrRoomObjectMalformed
	}
	members := make([]string, 0, count)
	for index := 0; index < count; index++ {
		member := string(reader.take(agentIDBytes))
		if reader.err != nil || !ids.Agent.MatchString(member) || (index > 0 && member <= members[index-1]) {
			return RoomHeader{}, ErrRoomObjectMalformed
		}
		members = append(members, member)
	}
	networkLength := int(reader.u16())
	if reader.err != nil || networkLength == 0 || networkLength > 128 {
		return RoomHeader{}, ErrRoomObjectMalformed
	}
	network := &nativev1.NetworkDomain{NetworkId: string(reader.take(networkLength))}
	network.GenesisRootHash = hex.EncodeToString(reader.take(sha256.Size))
	network.GenesisFileHash = hex.EncodeToString(reader.take(sha256.Size))
	authority := room.Authority{AgentID: string(reader.take(agentIDBytes)), EndpointID: string(reader.take(endpointIDBytes))}
	issued := reader.u64()
	expires := reader.u64()
	signature := append([]byte(nil), reader.take(ed25519.SignatureSize)...)
	endsAt := reader.u64()
	if err := reader.done(); err != nil {
		return RoomHeader{}, ErrRoomObjectMalformed
	}
	digest, err := room.Digest(roomID, roomEpoch, members)
	if err != nil {
		return RoomHeader{}, ErrRoomObjectMalformed
	}
	header := RoomHeader{
		Membership: room.Membership{RoomID: roomID, Epoch: roomEpoch, Members: members, Digest: digest},
		Authorization: room.MembershipAuthorization{Network: network, RoomID: roomID, Epoch: roomEpoch,
			MembershipDigest: digest, Authority: authority, IssuedAtUnix: issued, ExpiresAtUnix: expires,
			EndpointSignature: signature},
		EndsAtUnix: endsAt,
	}
	// The header is canonical: re-encoding it gives the same bytes.
	again, err := encodeRoomHeader(roomID, roomEpoch, header)
	if err != nil || !bytes.Equal(again, raw) {
		return RoomHeader{}, ErrRoomObjectMalformed
	}
	return header, nil
}

// RosterEntry is one member's chat card, relay identity evidence and leaf
// credential. A roster is rendezvous, not authority: the receiver verifies
// each card, evidence and credential itself and learns only entries that are
// members. The credential is carried opaque here, bounded by the codec; it is
// verified against the finalized delegation and the member's MLS leaf,
// independently of the card and evidence (sections 11.2, 11.8).
type RosterEntry struct {
	AgentID    string
	Card       []byte
	Evidence   []byte
	Credential []byte
}

// EncodeRoster encodes 1 .. 31 entries in ascending Agent order. Each entry is
// the 70-byte Agent ID, the u16-prefixed card, the u16-prefixed evidence and
// the u16-prefixed leaf credential.
func EncodeRoster(entries []RosterEntry) ([]byte, error) {
	if len(entries) == 0 || len(entries) > MaxRosterEntries {
		return nil, ErrRosterMalformed
	}
	out := &bytes.Buffer{}
	var length [2]byte
	for index, entry := range entries {
		if !ids.Agent.MatchString(entry.AgentID) || (index > 0 && entry.AgentID <= entries[index-1].AgentID) {
			return nil, ErrRosterMalformed
		}
		if len(entry.Card) == 0 || len(entry.Card) > MaxCardBytes {
			return nil, ErrRosterMalformed
		}
		if _, err := DecodeEvidence(entry.Evidence); err != nil {
			return nil, ErrRosterMalformed
		}
		if len(entry.Credential) == 0 || len(entry.Credential) > MaxRosterCredentialBytes {
			return nil, ErrRosterMalformed
		}
		out.WriteString(entry.AgentID)
		binary.BigEndian.PutUint16(length[:], uint16(len(entry.Card)))
		out.Write(length[:])
		out.Write(entry.Card)
		binary.BigEndian.PutUint16(length[:], uint16(len(entry.Evidence)))
		out.Write(length[:])
		out.Write(entry.Evidence)
		binary.BigEndian.PutUint16(length[:], uint16(len(entry.Credential)))
		out.Write(length[:])
		out.Write(entry.Credential)
	}
	return out.Bytes(), nil
}

// DecodeRoster strictly parses a roster body.
func DecodeRoster(raw []byte) ([]RosterEntry, error) {
	if len(raw) == 0 || len(raw) > MaxRoomBodyBytes {
		return nil, ErrRosterMalformed
	}
	reader := byteReader{buffer: raw}
	var entries []RosterEntry
	for reader.offset < len(raw) {
		if len(entries) == MaxRosterEntries {
			return nil, ErrRosterMalformed
		}
		agentID := string(reader.take(agentIDBytes))
		cardLength := int(reader.u16())
		if reader.err != nil || cardLength == 0 || cardLength > MaxCardBytes {
			return nil, ErrRosterMalformed
		}
		card := append([]byte(nil), reader.take(cardLength)...)
		evidenceLength := int(reader.u16())
		if reader.err != nil || evidenceLength == 0 || evidenceLength > MaxEvidenceBytes {
			return nil, ErrRosterMalformed
		}
		evidence := append([]byte(nil), reader.take(evidenceLength)...)
		credentialLength := int(reader.u16())
		if reader.err != nil || credentialLength == 0 || credentialLength > MaxRosterCredentialBytes {
			return nil, ErrRosterMalformed
		}
		credential := append([]byte(nil), reader.take(credentialLength)...)
		if reader.err != nil {
			return nil, ErrRosterMalformed
		}
		if !ids.Agent.MatchString(agentID) || (len(entries) > 0 && agentID <= entries[len(entries)-1].AgentID) {
			return nil, ErrRosterMalformed
		}
		if _, err := DecodeEvidence(evidence); err != nil {
			return nil, ErrRosterMalformed
		}
		entries = append(entries, RosterEntry{AgentID: agentID, Card: card, Evidence: evidence, Credential: credential})
	}
	if len(entries) == 0 {
		return nil, ErrRosterMalformed
	}
	return entries, nil
}

// RoomAAD is the MLS authenticated data of one application message. It binds
// the room, the room and MLS epochs it is sealed in, that epoch's MLS epoch
// authenticator, the sender Agent and the Event.
type RoomAAD struct {
	RoomID             string
	RoomEpoch          uint64
	MLSEpoch           uint64
	EpochAuthenticator []byte
	SenderAgentID      string
	EventID            string
}

// RoomAADEpochAuthenticatorBytes is the epoch authenticator length of the
// only MLS suite (its hash length).
const RoomAADEpochAuthenticatorBytes = 32

// EncodeRoomAAD returns the canonical authenticated data.
func EncodeRoomAAD(aad RoomAAD) ([]byte, error) {
	if !ids.Room.MatchString(aad.RoomID) || aad.RoomEpoch == 0 || len(aad.EpochAuthenticator) != RoomAADEpochAuthenticatorBytes ||
		canon.IsZero(aad.EpochAuthenticator) || !ids.Agent.MatchString(aad.SenderAgentID) || !ids.Event.MatchString(aad.EventID) {
		return nil, ErrRoomAADMalformed
	}
	out := bytes.NewBufferString(canon.DomainRoomAAD)
	canon.Text(out, aad.RoomID)
	canon.Uint64(out, aad.RoomEpoch)
	canon.Uint64(out, aad.MLSEpoch)
	canon.Bytes(out, aad.EpochAuthenticator)
	canon.Text(out, aad.SenderAgentID)
	canon.Text(out, aad.EventID)
	return out.Bytes(), nil
}

// MaxRoomAADBytes bounds an encoded room AAD; a valid one (the domain, a room
// ID, two epochs, the authenticator and two IDs, each text with its length
// prefix) is about 290 bytes.
const MaxRoomAADBytes = 512

// DecodeRoomAAD is the strict inverse of EncodeRoomAAD: the domain, each
// field in order with its exact length prefix, no trailing bytes, and the
// values re-encoded to the same bytes, so one AAD has exactly one decoding.
func DecodeRoomAAD(raw []byte) (RoomAAD, error) {
	if len(raw) == 0 || len(raw) > MaxRoomAADBytes || !bytes.HasPrefix(raw, []byte(canon.DomainRoomAAD)) {
		return RoomAAD{}, ErrRoomAADMalformed
	}
	rest := raw[len(canon.DomainRoomAAD):]
	field := func(max int) ([]byte, bool) {
		if len(rest) < 4 {
			return nil, false
		}
		length := binary.BigEndian.Uint32(rest[:4])
		if uint64(length) > uint64(max) || uint64(len(rest)-4) < uint64(length) {
			return nil, false
		}
		value := rest[4 : 4+int(length)]
		rest = rest[4+int(length):]
		return value, true
	}
	number := func() (uint64, bool) {
		if len(rest) < 8 {
			return 0, false
		}
		value := binary.BigEndian.Uint64(rest[:8])
		rest = rest[8:]
		return value, true
	}
	var aad RoomAAD
	roomID, ok := field(MaxRoomAADBytes)
	if !ok {
		return RoomAAD{}, ErrRoomAADMalformed
	}
	aad.RoomID = string(roomID)
	if aad.RoomEpoch, ok = number(); !ok {
		return RoomAAD{}, ErrRoomAADMalformed
	}
	if aad.MLSEpoch, ok = number(); !ok {
		return RoomAAD{}, ErrRoomAADMalformed
	}
	authenticator, ok := field(RoomAADEpochAuthenticatorBytes)
	if !ok {
		return RoomAAD{}, ErrRoomAADMalformed
	}
	aad.EpochAuthenticator = bytes.Clone(authenticator)
	sender, ok := field(MaxRoomAADBytes)
	if !ok {
		return RoomAAD{}, ErrRoomAADMalformed
	}
	aad.SenderAgentID = string(sender)
	eventID, ok := field(MaxRoomAADBytes)
	if !ok || len(rest) != 0 {
		return RoomAAD{}, ErrRoomAADMalformed
	}
	aad.EventID = string(eventID)
	encoded, err := EncodeRoomAAD(aad)
	if err != nil || !bytes.Equal(encoded, raw) {
		return RoomAAD{}, ErrRoomAADMalformed
	}
	return aad, nil
}

// RoomCut returns the part sizes of an object of the given type and length.
// partBytes is 0 for the production cut (part 0 FirstPartBytes, every later
// part LaterPartBytes); a test part size P in MinTestPartBytes ..
// MaxTestPartBytes cuts every part of a handshake object at P, while an
// application object keeps the production cut. An object that needs more
// than MaxParts parts is refused.
func RoomCut(objectType uint8, length, partBytes int) ([]int, error) {
	if length <= RoomObjectFixedBytes || length > MaxRoomObjectBytes {
		return nil, ErrRoomObjectTooLarge
	}
	if partBytes != 0 && (partBytes < MinTestPartBytes || partBytes > MaxTestPartBytes) {
		return nil, ErrRoomPartSize
	}
	first, later := FirstPartBytes, LaterPartBytes
	if partBytes != 0 && objectType != RoomApplication {
		first, later = partBytes, partBytes
	}
	sizes := []int{}
	for remaining, size := length, first; remaining > 0; size = later {
		if len(sizes) == MaxParts {
			return nil, ErrRoomTooManyParts
		}
		if remaining < size {
			size = remaining
		}
		sizes = append(sizes, size)
		remaining -= size
	}
	return sizes, nil
}

// SplitRoomObject cuts an encoded room object into its kind-3 frames. Part 0
// carries the sender's evidence and, while it is unacknowledged, its card;
// later parts carry neither. The parts depend only on the object and the cut,
// never on the card or evidence, so every re-deposit generation carries
// byte-identical parts.
func SplitRoomObject(object, card, evidence []byte, partBytes int) ([][]byte, error) {
	decoded, err := DecodeRoomObject(object)
	if err != nil {
		return nil, err
	}
	sizes, err := RoomCut(decoded.Type, len(object), partBytes)
	if err != nil {
		return nil, err
	}
	digest := ObjectDigest(object)
	frames := make([][]byte, 0, len(sizes))
	offset := 0
	for index, size := range sizes {
		frame := Frame{Kind: KindRoom, PartIndex: uint8(index), PartCount: uint8(len(sizes)),
			ObjectDigest: digest, Part: object[offset : offset+size]}
		if index == 0 {
			frame.Card, frame.Evidence = card, evidence
		}
		encoded, err := Encode(frame)
		if err != nil {
			return nil, err
		}
		frames = append(frames, encoded)
		offset += size
	}
	return frames, nil
}
