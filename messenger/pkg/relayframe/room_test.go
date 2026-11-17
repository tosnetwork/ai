package relayframe_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/messenger/pkg/room"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

const testRoom = "room_" + "7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c"

func roomAgent(index int) string { return fmt.Sprintf("agent_%064x", index+1) }

var roomKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))

func roomHeader(t testing.TB, epoch uint64, members int, networkID string) *relayframe.RoomHeader {
	t.Helper()
	agents := make([]string, members)
	for index := range agents {
		agents[index] = roomAgent(index)
	}
	membership, err := room.Found(testRoom, agents)
	if err != nil {
		t.Fatal(err)
	}
	if epoch != 1 {
		digest, err := room.Digest(testRoom, epoch, agents)
		if err != nil {
			t.Fatal(err)
		}
		membership = room.Membership{RoomID: testRoom, Epoch: epoch, Members: membership.Members, Digest: digest}
	}
	authorization, err := room.SignMembershipAuthorization(room.MembershipAuthorization{
		Network: &nativev1.NetworkDomain{NetworkId: networkID, GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)},
		RoomID:  testRoom, Epoch: epoch, MembershipDigest: membership.Digest,
		Authority:    room.Authority{AgentID: agents[0], EndpointID: "mep_" + strings.Repeat("e", 64)},
		IssuedAtUnix: 1_000, ExpiresAtUnix: 2_000,
	}, roomKey)
	if err != nil {
		t.Fatal(err)
	}
	return &relayframe.RoomHeader{Membership: membership, Authorization: authorization, EndsAtUnix: 2_000_000}
}

func roomObject(t testing.TB, object relayframe.RoomObject) []byte {
	t.Helper()
	raw, err := relayframe.EncodeRoomObject(object)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRoomObjectRoundTripsAndRefusesMalformation(t *testing.T) {
	header := roomHeader(t, 2, 3, "tos-local")
	commit := relayframe.RoomObject{Type: relayframe.RoomCommit, RoomID: testRoom, RoomEpoch: 2, MLSEpoch: 5, Header: header, Body: []byte("commit")}
	raw := roomObject(t, commit)
	decoded, err := relayframe.DecodeRoomObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	if again := roomObject(t, decoded); !bytes.Equal(again, raw) {
		t.Fatal("a room object does not round-trip")
	}
	if decoded.Header.Membership.Digest != header.Membership.Digest || !bytes.Equal(decoded.Header.Authorization.EndpointSignature, header.Authorization.EndpointSignature) {
		t.Fatal("the header lost its membership or authorization")
	}
	if decoded.Header.EndsAtUnix != header.EndsAtUnix {
		t.Fatalf("the header lost the room's end time: %d", decoded.Header.EndsAtUnix)
	}
	// The end time is the header's last field: changing it changes the
	// object, and a zero end time is refused (D18).
	endless := *header
	endless.EndsAtUnix = 0
	if _, err := relayframe.EncodeRoomObject(relayframe.RoomObject{Type: relayframe.RoomCommit, RoomID: testRoom, RoomEpoch: 2, MLSEpoch: 5, Header: &endless, Body: []byte("commit")}); err == nil {
		t.Fatal("a header without an end time encoded")
	}
	// The header ends just before the body length and the body.
	endAt := len(raw) - len(commit.Body) - 4 - 8
	zeroed := append([]byte(nil), raw...)
	copy(zeroed[endAt:endAt+8], make([]byte, 8))
	if _, err := relayframe.DecodeRoomObject(zeroed); err == nil {
		t.Fatal("a header with a zero end time decoded")
	}
	later := append([]byte(nil), raw...)
	later[endAt+7]++
	if moved, err := relayframe.DecodeRoomObject(later); err != nil || moved.Header.EndsAtUnix != header.EndsAtUnix+1 {
		t.Fatalf("the end time is not the header's last field: %v", err)
	}
	// An MLS-only refresh Commit and an application object have no header.
	for _, object := range []relayframe.RoomObject{
		{Type: relayframe.RoomCommit, RoomID: testRoom, RoomEpoch: 2, MLSEpoch: 6, Body: []byte("refresh")},
		{Type: relayframe.RoomApplication, RoomID: testRoom, RoomEpoch: 2, MLSEpoch: 6, Body: make([]byte, relayframe.MaxRoomApplicationBodyBytes)},
	} {
		if _, err := relayframe.DecodeRoomObject(roomObject(t, object)); err != nil {
			t.Fatal(err)
		}
	}
	refusals := []struct {
		name   string
		object relayframe.RoomObject
	}{
		{"Welcome without header", relayframe.RoomObject{Type: relayframe.RoomWelcome, RoomID: testRoom, RoomEpoch: 2, Body: []byte("w")}},
		{"roster without header", relayframe.RoomObject{Type: relayframe.RoomRoster, RoomID: testRoom, RoomEpoch: 2, Body: []byte("r")}},
		{"application with header", relayframe.RoomObject{Type: relayframe.RoomApplication, RoomID: testRoom, RoomEpoch: 2, Header: header, Body: []byte("a")}},
		{"application over its bound", relayframe.RoomObject{Type: relayframe.RoomApplication, RoomID: testRoom, RoomEpoch: 2, Body: make([]byte, relayframe.MaxRoomApplicationBodyBytes+1)}},
		{"body over its bound", relayframe.RoomObject{Type: relayframe.RoomCommit, RoomID: testRoom, RoomEpoch: 2, Body: make([]byte, relayframe.MaxRoomBodyBytes+1)}},
		{"empty body", relayframe.RoomObject{Type: relayframe.RoomCommit, RoomID: testRoom, RoomEpoch: 2}},
		{"header of another epoch", relayframe.RoomObject{Type: relayframe.RoomCommit, RoomID: testRoom, RoomEpoch: 3, Header: header, Body: []byte("c")}},
		{"unknown type", relayframe.RoomObject{Type: 5, RoomID: testRoom, RoomEpoch: 2, Body: []byte("c")}},
		{"zero room epoch", relayframe.RoomObject{Type: relayframe.RoomCommit, RoomID: testRoom, Body: []byte("c")}},
		{"roster body that is no roster", relayframe.RoomObject{Type: relayframe.RoomRoster, RoomID: testRoom, RoomEpoch: 2, Header: header, Body: []byte("not a roster")}},
	}
	for _, refusal := range refusals {
		if _, err := relayframe.EncodeRoomObject(refusal.object); err == nil {
			t.Fatalf("%s: encoded", refusal.name)
		}
	}
	domain := len(canon.DomainRelayRoomObject)
	mutations := []struct {
		name  string
		apply func([]byte) []byte
	}{
		{"trailing byte", func(b []byte) []byte { return append(b, 0) }},
		{"truncated", func(b []byte) []byte { return b[:len(b)-1] }},
		{"other domain", func(b []byte) []byte { b[0] ^= 1; return b }},
		{"unknown type", func(b []byte) []byte { b[domain] = 9; return b }},
		{"header length past the object", func(b []byte) []byte { b[domain+1+32+16] = 0xff; return b }},
		// The header's members are ascending; swapping two breaks it.
		{"members out of order", func(b []byte) []byte {
			first := domain + 1 + 32 + 16 + 2 + 1
			swapped := append([]byte(nil), b...)
			copy(swapped[first:first+70], b[first+70:first+140])
			copy(swapped[first+70:first+140], b[first:first+70])
			return swapped
		}},
	}
	for _, mutation := range mutations {
		if _, err := relayframe.DecodeRoomObject(mutation.apply(append([]byte(nil), raw...))); err == nil {
			t.Fatalf("%s: decoded", mutation.name)
		}
	}
	if _, err := relayframe.DecodeRoomObject(make([]byte, relayframe.MaxRoomObjectBytes+1)); !errors.Is(err, relayframe.ErrRoomObjectTooLarge) {
		t.Fatalf("over-bound object: %v", err)
	}
}

func TestRosterCodec(t *testing.T) {
	entries := []relayframe.RosterEntry{
		{AgentID: roomAgent(1), Card: []byte("card one"), Evidence: evidence(t), Credential: []byte("credential one")},
		{AgentID: roomAgent(2), Card: make([]byte, relayframe.MaxCardBytes), Evidence: evidence(t),
			Credential: bytes.Repeat([]byte{0xc3}, relayframe.MaxRosterCredentialBytes)},
	}
	raw, err := relayframe.EncodeRoster(entries)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := relayframe.DecodeRoster(raw)
	if err != nil || len(decoded) != 2 || decoded[1].AgentID != roomAgent(2) ||
		!bytes.Equal(decoded[1].Credential, entries[1].Credential) || !bytes.Equal(decoded[0].Credential, entries[0].Credential) {
		t.Fatalf("roster: %v", err)
	}
	full := make([]relayframe.RosterEntry, relayframe.MaxRosterEntries+1)
	for index := range full {
		full[index] = relayframe.RosterEntry{AgentID: roomAgent(index), Card: []byte("c"), Evidence: evidence(t), Credential: []byte("l")}
	}
	for name, bad := range map[string][]relayframe.RosterEntry{
		"empty":                 nil,
		"32 entries":            full,
		"out of order":          {entries[1], entries[0]},
		"duplicate":             {entries[0], entries[0]},
		"no card":               {{AgentID: roomAgent(1), Evidence: evidence(t), Credential: []byte("l")}},
		"card over bound":       {{AgentID: roomAgent(1), Card: make([]byte, relayframe.MaxCardBytes+1), Evidence: evidence(t), Credential: []byte("l")}},
		"bad evidence":          {{AgentID: roomAgent(1), Card: []byte("c"), Evidence: []byte("not evidence"), Credential: []byte("l")}},
		"no credential":         {{AgentID: roomAgent(1), Card: []byte("c"), Evidence: evidence(t)}},
		"credential over bound": {{AgentID: roomAgent(1), Card: []byte("c"), Evidence: evidence(t), Credential: make([]byte, relayframe.MaxRosterCredentialBytes+1)}},
	} {
		if _, err := relayframe.EncodeRoster(bad); err == nil {
			t.Fatalf("%s: encoded", name)
		}
	}
	if _, err := relayframe.DecodeRoster(append(raw, 0)); err == nil {
		t.Fatal("trailing roster byte accepted")
	}
	if _, err := relayframe.DecodeRoster(raw[:len(raw)-1]); err == nil {
		t.Fatal("truncated roster accepted")
	}
	// A credential length of zero, or past the codec bound, is refused on
	// decode as well.
	credentialAt := len(raw) - len(entries[1].Credential) - 2
	for name, length := range map[string]uint16{"zero": 0, "over the bound": relayframe.MaxRosterCredentialBytes + 1} {
		bad := append([]byte(nil), raw...)
		bad[credentialAt], bad[credentialAt+1] = byte(length>>8), byte(length)
		if _, err := relayframe.DecodeRoster(bad); err == nil {
			t.Fatalf("a %s credential length decoded", name)
		}
	}
	// The largest roster the arithmetic of section 11.1 allows: 31 entries of
	// maximal card, evidence and a 473-byte leaf credential, 874,107 bytes, and
	// at the codec's 512-byte credential bound 1,209 more; both fit a body.
	if worst := relayframe.MaxRosterEntries * (70 + 6 + relayframe.MaxCardBytes + relayframe.MaxEvidenceBytes + 473); worst != 874_107 || worst > relayframe.MaxRoomBodyBytes {
		t.Fatalf("maximal roster %d", worst)
	}
	if bound := relayframe.MaxRosterEntries * (70 + 6 + relayframe.MaxCardBytes + relayframe.MaxEvidenceBytes + relayframe.MaxRosterCredentialBytes); bound != 874_107+1_209 || bound > relayframe.MaxRoomBodyBytes {
		t.Fatalf("roster codec bound %d", bound)
	}
}

// The cut of section 11.1: part 0 holds 162,744 object bytes and every later
// part 190,392, so the largest object takes six parts, the last 132,546.
func TestRoomCutIsFixed(t *testing.T) {
	if relayframe.FirstPartBytes != 162_744 || relayframe.LaterPartBytes != 190_392 || relayframe.MaxRoomObjectBytes != 1_056_858 || relayframe.RoomObjectFixedBytes != 90 {
		t.Fatalf("cut constants %d %d %d %d", relayframe.FirstPartBytes, relayframe.LaterPartBytes, relayframe.MaxRoomObjectBytes, relayframe.RoomObjectFixedBytes)
	}
	sizes, err := relayframe.RoomCut(relayframe.RoomWelcome, relayframe.MaxRoomObjectBytes, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []int{162_744, 190_392, 190_392, 190_392, 190_392, 132_546}
	if fmt.Sprint(sizes) != fmt.Sprint(want) {
		t.Fatalf("maximal cut %v", sizes)
	}
	for parts, upTo := range []int{0, 162_744, 353_136, 543_528, 733_920, 924_312, 1_114_704} {
		if parts == 0 {
			continue
		}
		if sizes, err := relayframe.RoomCut(relayframe.RoomCommit, min(upTo, relayframe.MaxRoomObjectBytes), 0); err != nil || len(sizes) != parts {
			t.Fatalf("%d bytes: %v %v", upTo, sizes, err)
		}
	}
	// A test part size cuts every part of a handshake object, never an
	// application object, and refuses an object needing more than 8 parts.
	if sizes, err := relayframe.RoomCut(relayframe.RoomWelcome, 5_000, 1_024); err != nil || fmt.Sprint(sizes) != "[1024 1024 1024 1024 904]" {
		t.Fatalf("test cut %v %v", sizes, err)
	}
	if sizes, err := relayframe.RoomCut(relayframe.RoomApplication, 5_000, 1_024); err != nil || len(sizes) != 1 {
		t.Fatalf("application under a test cut %v %v", sizes, err)
	}
	if _, err := relayframe.RoomCut(relayframe.RoomWelcome, 8*1_024+1, 1_024); !errors.Is(err, relayframe.ErrRoomTooManyParts) {
		t.Fatalf("nine parts at P: %v", err)
	}
	for _, p := range []int{1, 1_023, relayframe.FirstPartBytes + 1} {
		if _, err := relayframe.RoomCut(relayframe.RoomWelcome, 5_000, p); !errors.Is(err, relayframe.ErrRoomPartSize) {
			t.Fatalf("P=%d: %v", p, err)
		}
	}
	if _, err := relayframe.RoomCut(relayframe.RoomWelcome, relayframe.MaxRoomObjectBytes+1, 0); !errors.Is(err, relayframe.ErrRoomObjectTooLarge) {
		t.Fatalf("over-bound object: %v", err)
	}
}

// largestObject is the largest valid room object: a 32-member header with a
// 128-byte network ID and a 1 MiB body.
func largestObject(t testing.TB) []byte {
	t.Helper()
	body := make([]byte, relayframe.MaxRoomBodyBytes)
	for index := range body {
		body[index] = byte(index % 251)
	}
	return roomObject(t, relayframe.RoomObject{Type: relayframe.RoomWelcome, RoomID: testRoom, RoomEpoch: 7, MLSEpoch: 9,
		Header: roomHeader(t, 7, relayframe.MaxRoomMembers, strings.Repeat("n", 128)), Body: body})
}

// Every non-final production part is exactly the 190,464-byte bucket, every
// frame is its smallest bucket, and the parts are identical whether or not
// part 0 carries a card.
func TestSplitRoomObjectProductionCut(t *testing.T) {
	object := largestObject(t)
	card := make([]byte, relayframe.MaxCardBytes)
	withCard, err := relayframe.SplitRoomObject(object, card, evidence(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	without, err := relayframe.SplitRoomObject(object, nil, evidence(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(withCard) != 6 || len(without) != 6 {
		t.Fatalf("largest object took %d parts", len(withCard))
	}
	t.Logf("largest valid object %d bytes; frames %v", len(object), frameSizes(withCard))
	// Section 11.1: a 2,661-byte header, 1,051,327 bytes in all.
	if len(object) != 1_051_327 || relayframe.MaxRoomObjectValidBytes != 1_051_327 {
		t.Fatalf("largest valid object %d bytes", len(object))
	}
	if last := len(withCard[5]); last >= relayframe.MaxFrameBytes {
		t.Fatalf("the last part is %d bytes", last)
	}
	digest := relayframe.ObjectDigest(object)
	var joined []byte
	for index := range withCard {
		first, err := relayframe.Decode(withCard[index])
		if err != nil {
			t.Fatal(err)
		}
		second, err := relayframe.Decode(without[index])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.Part, second.Part) || first.ObjectDigest != digest || second.ObjectDigest != digest {
			t.Fatalf("part %d differs between generations", index)
		}
		if index < len(withCard)-1 && (len(withCard[index]) != relayframe.MaxFrameBytes || len(without[index]) != relayframe.MaxFrameBytes) {
			t.Fatalf("non-final part %d is %d bytes", index, len(withCard[index]))
		}
		if index > 0 && !bytes.Equal(withCard[index], without[index]) {
			t.Fatalf("later part %d frame differs", index)
		}
		joined = append(joined, first.Part...)
	}
	if !bytes.Equal(joined, object) {
		t.Fatal("parts do not reassemble the object")
	}
}

func frameSizes(frames [][]byte) []int {
	sizes := make([]int, len(frames))
	for index, frame := range frames {
		sizes[index] = len(frame)
	}
	return sizes
}

func TestSplitRoomObjectTestCutAndApplication(t *testing.T) {
	welcome := roomObject(t, relayframe.RoomObject{Type: relayframe.RoomWelcome, RoomID: testRoom, RoomEpoch: 2, Header: roomHeader(t, 2, 2, "tos-local"), Body: make([]byte, 4_000)})
	frames, err := relayframe.SplitRoomObject(welcome, nil, evidence(t), 1_024)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != (len(welcome)+1_023)/1_024 {
		t.Fatalf("test cut took %d parts", len(frames))
	}
	for _, frame := range frames {
		if _, err := relayframe.BucketFor(len(frame)); err != nil {
			t.Fatal("a test-cut frame is no bucket")
		}
	}
	application := roomObject(t, relayframe.RoomObject{Type: relayframe.RoomApplication, RoomID: testRoom, RoomEpoch: 2, Body: make([]byte, relayframe.MaxRoomApplicationBodyBytes)})
	frames, err = relayframe.SplitRoomObject(application, nil, evidence(t), 1_024)
	if err != nil || len(frames) != 1 {
		t.Fatalf("an application object was split: %d %v", len(frames), err)
	}
	big := roomObject(t, relayframe.RoomObject{Type: relayframe.RoomWelcome, RoomID: testRoom, RoomEpoch: 2, Header: roomHeader(t, 2, 2, "tos-local"), Body: make([]byte, 9_000)})
	if _, err := relayframe.SplitRoomObject(big, nil, evidence(t), 1_024); !errors.Is(err, relayframe.ErrRoomTooManyParts) {
		t.Fatalf("an object of more than 8 parts at P: %v", err)
	}
	if _, err := relayframe.SplitRoomObject([]byte("not an object"), nil, evidence(t), 0); err == nil {
		t.Fatal("a non-object was split")
	}
}

func TestRoomAADBindsEveryField(t *testing.T) {
	base := relayframe.RoomAAD{RoomID: testRoom, RoomEpoch: 2, MLSEpoch: 3, EpochAuthenticator: bytes.Repeat([]byte{1}, 32),
		SenderAgentID: roomAgent(1), EventID: "evt_" + strings.Repeat("e", 64)}
	reference, err := relayframe.EncodeRoomAAD(base)
	if err != nil {
		t.Fatal(err)
	}
	variants := []relayframe.RoomAAD{base, base, base, base, base}
	variants[0].RoomEpoch = 3
	variants[1].MLSEpoch = 4
	variants[2].EpochAuthenticator = bytes.Repeat([]byte{2}, 32)
	variants[3].SenderAgentID = roomAgent(2)
	variants[4].EventID = "evt_" + strings.Repeat("f", 64)
	for index, variant := range variants {
		raw, err := relayframe.EncodeRoomAAD(variant)
		if err != nil || bytes.Equal(raw, reference) {
			t.Fatalf("variant %d does not change the AAD: %v", index, err)
		}
	}
	bad := base
	bad.EpochAuthenticator = make([]byte, 32)
	if _, err := relayframe.EncodeRoomAAD(bad); err == nil {
		t.Fatal("a zero epoch authenticator was accepted")
	}
}

func TestRoomAckSignsAndRefuses(t *testing.T) {
	ack := relayframe.RoomAck{RoomID: testRoom, ObjectDigest: sha256.Sum256([]byte("object")),
		RecipientEndpointID: "mep_" + strings.Repeat("3c", 32), RecipientDeviceID: "dev_" + strings.Repeat("4d", 32),
		MLSEpoch: 4, EpochAuthenticator: bytes.Repeat([]byte{7}, 32), Outcome: relayframe.OutcomeAccepted, AckedAtUnix: 10}
	signed, err := relayframe.SignRoomAck(ack, roomKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := relayframe.EncodeRoomAck(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !relayframe.IsRoomAck(raw) {
		t.Fatal("a room ack is not recognized")
	}
	decoded, err := relayframe.DecodeRoomAck(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayframe.VerifyRoomAck(decoded, roomKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32))
	if err := relayframe.VerifyRoomAck(decoded, other.Public().(ed25519.PublicKey)); !errors.Is(err, relayframe.ErrRoomAckSignature) {
		t.Fatalf("another Endpoint's key: %v", err)
	}
	altered := decoded
	altered.MLSEpoch = 5
	if err := relayframe.VerifyRoomAck(altered, roomKey.Public().(ed25519.PublicKey)); !errors.Is(err, relayframe.ErrRoomAckSignature) {
		t.Fatalf("altered epoch: %v", err)
	}
	// A room ack never decodes as a copy ack, nor the reverse.
	if _, err := relayframe.DecodeAck(raw); err == nil {
		t.Fatal("a room ack decoded as a copy ack")
	}
	for _, bad := range []relayframe.RoomAck{
		{RoomID: testRoom, ObjectDigest: ack.ObjectDigest, RecipientEndpointID: ack.RecipientEndpointID, RecipientDeviceID: ack.RecipientDeviceID, EpochAuthenticator: ack.EpochAuthenticator, Outcome: relayframe.OutcomeHeld, AckedAtUnix: 1},
		{RoomID: testRoom, ObjectDigest: ack.ObjectDigest, RecipientEndpointID: ack.RecipientEndpointID, RecipientDeviceID: ack.RecipientDeviceID, EpochAuthenticator: ack.EpochAuthenticator, Outcome: relayframe.OutcomeRejected, AckedAtUnix: 1},
		{RoomID: testRoom, RecipientEndpointID: ack.RecipientEndpointID, RecipientDeviceID: ack.RecipientDeviceID, EpochAuthenticator: ack.EpochAuthenticator, Outcome: relayframe.OutcomeAccepted, AckedAtUnix: 1},
		{RoomID: testRoom, ObjectDigest: ack.ObjectDigest, RecipientEndpointID: ack.RecipientEndpointID, RecipientDeviceID: ack.RecipientDeviceID, EpochAuthenticator: make([]byte, 32), Outcome: relayframe.OutcomeAccepted, AckedAtUnix: 1},
	} {
		if _, err := relayframe.RoomAckSigningBytes(bad); err == nil {
			t.Fatalf("an invalid room ack was accepted: %+v", bad)
		}
	}
	rejected := ack
	rejected.Outcome, rejected.Code = relayframe.OutcomeRejected, fault.CodeNotAuthentic
	if _, err := relayframe.RoomAckSigningBytes(rejected); err != nil {
		t.Fatalf("a rejected room ack with its code: %v", err)
	}
	if _, err := relayframe.DecodeRoomAck(append(raw, 0)); err == nil {
		t.Fatal("a trailing byte was accepted")
	}
	// A pending joiner refusing its Welcome has no MLS state: its rejection
	// carries no authenticator and MLS epoch 0, and still signs and decodes.
	stateless := ack
	stateless.Outcome, stateless.Code, stateless.MLSEpoch, stateless.EpochAuthenticator = relayframe.OutcomeRejected, fault.CodeNotAuthentic, 0, nil
	signedStateless, err := relayframe.SignRoomAck(stateless, roomKey)
	if err != nil {
		t.Fatalf("a stateless rejection: %v", err)
	}
	statelessRaw, err := relayframe.EncodeRoomAck(signedStateless)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := relayframe.DecodeRoomAck(statelessRaw); err != nil || len(decoded.EpochAuthenticator) != 0 ||
		relayframe.VerifyRoomAck(decoded, roomKey.Public().(ed25519.PublicKey)) != nil {
		t.Fatalf("a stateless rejection does not round-trip: %v", err)
	}
	for name, bad := range map[string]relayframe.RoomAck{
		"accepted without authenticator": func() relayframe.RoomAck { v := ack; v.EpochAuthenticator, v.MLSEpoch = nil, 0; return v }(),
		"duplicate without authenticator": func() relayframe.RoomAck {
			v := ack
			v.Outcome, v.EpochAuthenticator, v.MLSEpoch = relayframe.OutcomeDuplicate, nil, 0
			return v
		}(),
		"stateless rejection with an epoch": func() relayframe.RoomAck { v := stateless; v.MLSEpoch = 3; return v }(),
		"short authenticator":               func() relayframe.RoomAck { v := rejected; v.EpochAuthenticator = []byte{1}; return v }(),
	} {
		if _, err := relayframe.RoomAckSigningBytes(bad); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// members admits a fixed set of senders in a fixed set of rooms.
type members struct {
	anywhere map[string]bool
	inRoom   map[string]bool
}

func (m members) MayHold(sender string) bool               { return m.anywhere[sender] }
func (m members) MayHoldInRoom(sender, roomID string) bool { return m.inRoom[sender+"|"+roomID] }

func admitAll(senders ...string) members {
	m := members{anywhere: map[string]bool{}, inRoom: map[string]bool{}}
	for _, sender := range senders {
		m.anywhere[sender] = true
		m.inRoom[sender+"|"+testRoom] = true
	}
	return m
}

func decodeAll(t testing.TB, frames [][]byte) []relayframe.Frame {
	t.Helper()
	decoded := make([]relayframe.Frame, len(frames))
	for index, raw := range frames {
		frame, err := relayframe.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		decoded[index] = frame
	}
	return decoded
}

func splitFrames(t testing.TB, bodyBytes int, label string) ([]byte, []relayframe.Frame) {
	t.Helper()
	body := bytes.Repeat([]byte(label), bodyBytes/len(label)+1)[:bodyBytes]
	object := roomObject(t, relayframe.RoomObject{Type: relayframe.RoomWelcome, RoomID: testRoom, RoomEpoch: 2,
		Header: roomHeader(t, 2, 2, "tos-local"), Body: body})
	frames, err := relayframe.SplitRoomObject(object, []byte("card"), evidence(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	return object, decodeAll(t, frames)
}

var now = time.Unix(100_000, 0)

func TestReassemblerReleasesAnObjectInAnyOrderOnce(t *testing.T) {
	sender := roomAgent(0)
	reassembler, err := relayframe.NewReassembler(relayframe.DefaultReassemblyLimits(), admitAll(sender))
	if err != nil {
		t.Fatal(err)
	}
	object, frames := splitFrames(t, 600_000, "w")
	// Later parts first: they are checked against the sender set only.
	order := []int{3, 1, 0, 2}
	for position, index := range order {
		result, err := reassembler.Add(sender, frames[index], now)
		if err != nil {
			t.Fatalf("part %d: %v", index, err)
		}
		if position < len(order)-1 && result.Status != relayframe.PartStored {
			t.Fatalf("part %d: status %d", index, result.Status)
		}
		if index == 0 && (result.RoomID != testRoom || string(result.Card) != "card") {
			t.Fatal("part 0 did not report its room and card")
		}
		if position == len(order)-1 {
			if result.Status != relayframe.PartComplete || !bytes.Equal(result.Object, object) || result.ObjectType != relayframe.RoomWelcome {
				t.Fatal("the object was not released")
			}
		}
	}
	if usage := reassembler.Usage(); usage.Objects != 0 || usage.TotalBytes != 0 || len(usage.PeerBytes) != 0 {
		t.Fatalf("a released object is still held: %+v", usage)
	}
	// A repeated part of a held object is a duplicate.
	if _, err := reassembler.Add(sender, frames[1], now); err != nil {
		t.Fatal(err)
	}
	if result, err := reassembler.Add(sender, frames[1], now); err != nil || result.Status != relayframe.PartDuplicate {
		t.Fatalf("repeated part: %v %v", result.Status, err)
	}
	// A single-part object is released at once and never held.
	small := roomObject(t, relayframe.RoomObject{Type: relayframe.RoomCommit, RoomID: testRoom, RoomEpoch: 2, Body: []byte("refresh")})
	single, err := relayframe.SplitRoomObject(small, nil, evidence(t), 0)
	if err != nil || len(single) != 1 {
		t.Fatal(err)
	}
	result, err := reassembler.Add(sender, decodeAll(t, single)[0], now)
	if err != nil || result.Status != relayframe.PartComplete || !bytes.Equal(result.Object, small) {
		t.Fatalf("single part: %v", err)
	}
}

// Each reassembly bound of section 4 refuses, and none of them stores.
func TestReassemblerEnforcesEachBound(t *testing.T) {
	sender, other := roomAgent(0), roomAgent(1)
	t.Run("non-member", func(t *testing.T) {
		reassembler, _ := relayframe.NewReassembler(relayframe.DefaultReassemblyLimits(), admitAll(sender))
		_, frames := splitFrames(t, 300_000, "a")
		if _, err := reassembler.Add(other, frames[1], now); !errors.Is(err, relayframe.ErrReassemblyNotAdmitted) {
			t.Fatalf("a stranger's later part: %v", err)
		}
		if _, err := reassembler.Add(other, frames[0], now); !errors.Is(err, relayframe.ErrReassemblyNotAdmitted) {
			t.Fatalf("a stranger's part 0: %v", err)
		}
		if usage := reassembler.Usage(); usage.Objects != 0 {
			t.Fatal("a stranger's part was held")
		}
	})
	t.Run("member of another room only", func(t *testing.T) {
		set := admitAll(sender)
		set.inRoom = map[string]bool{}
		reassembler, _ := relayframe.NewReassembler(relayframe.DefaultReassemblyLimits(), set)
		// Three parts, so part 0 does not complete the object.
		_, frames := splitFrames(t, 400_000, "b")
		if _, err := reassembler.Add(sender, frames[1], now); err != nil {
			t.Fatalf("a later part before the room is known: %v", err)
		}
		if _, err := reassembler.Add(sender, frames[0], now); !errors.Is(err, relayframe.ErrReassemblyNotAdmitted) {
			t.Fatalf("part 0 in a room the sender is not admitted in: %v", err)
		}
		if usage := reassembler.Usage(); usage.TotalBytes != len(frames[1].Part) {
			t.Fatal("a refused part 0 was held")
		}
	})
	t.Run("membership ends before completion", func(t *testing.T) {
		set := admitAll(sender)
		reassembler, _ := relayframe.NewReassembler(relayframe.DefaultReassemblyLimits(), set)
		_, frames := splitFrames(t, 300_000, "c")
		if _, err := reassembler.Add(sender, frames[0], now); err != nil {
			t.Fatal(err)
		}
		delete(set.inRoom, sender+"|"+testRoom)
		if _, err := reassembler.Add(sender, frames[1], now); !errors.Is(err, relayframe.ErrReassemblyNotAdmitted) {
			t.Fatalf("completion by a former member: %v", err)
		}
		if usage := reassembler.Usage(); usage.Objects != 0 {
			t.Fatal("a refused completion is still held")
		}
	})
	t.Run("inconsistent part count", func(t *testing.T) {
		reassembler, _ := relayframe.NewReassembler(relayframe.DefaultReassemblyLimits(), admitAll(sender))
		_, frames := splitFrames(t, 400_000, "d")
		if _, err := reassembler.Add(sender, frames[0], now); err != nil {
			t.Fatal(err)
		}
		forged := frames[1]
		forged.PartCount = 4
		if _, err := reassembler.Add(sender, forged, now); !errors.Is(err, relayframe.ErrReassemblyInconsistent) {
			t.Fatalf("another part count: %v", err)
		}
		if usage := reassembler.Usage(); usage.Objects != 0 {
			t.Fatal("an inconsistent object was kept")
		}
	})
	t.Run("repeated index with other bytes", func(t *testing.T) {
		reassembler, _ := relayframe.NewReassembler(relayframe.DefaultReassemblyLimits(), admitAll(sender))
		_, frames := splitFrames(t, 400_000, "e")
		if _, err := reassembler.Add(sender, frames[1], now); err != nil {
			t.Fatal(err)
		}
		forged := frames[1]
		forged.Part = append([]byte(nil), forged.Part...)
		forged.Part[0] ^= 1
		if _, err := reassembler.Add(sender, forged, now); !errors.Is(err, relayframe.ErrReassemblyInconsistent) {
			t.Fatalf("other bytes at one index: %v", err)
		}
		if usage := reassembler.Usage(); usage.Objects != 0 {
			t.Fatal("an inconsistent object was kept")
		}
	})
	t.Run("digest mismatch", func(t *testing.T) {
		reassembler, _ := relayframe.NewReassembler(relayframe.DefaultReassemblyLimits(), admitAll(sender))
		_, frames := splitFrames(t, 300_000, "f")
		forged := frames[1]
		forged.Part = append([]byte(nil), forged.Part...)
		forged.Part[len(forged.Part)-1] ^= 1
		if _, err := reassembler.Add(sender, frames[0], now); err != nil {
			t.Fatal(err)
		}
		if _, err := reassembler.Add(sender, forged, now); !errors.Is(err, relayframe.ErrReassemblyDigest) {
			t.Fatalf("digest mismatch: %v", err)
		}
		if usage := reassembler.Usage(); usage.Objects != 0 {
			t.Fatal("a mismatched object was kept")
		}
	})
	t.Run("object bound", func(t *testing.T) {
		reassembler, _ := relayframe.NewReassembler(relayframe.DefaultReassemblyLimits(), admitAll(sender))
		_, frames := splitFrames(t, 300_000, "g")
		// Seven production parts describe at least 1,114,705 bytes.
		forged := frames[1]
		forged.PartCount, forged.PartIndex = 7, 1
		if _, err := reassembler.Add(sender, forged, now); !errors.Is(err, relayframe.ErrReassemblyObjectTooLarge) {
			t.Fatalf("seven parts: %v", err)
		}
	})
	t.Run("fixed cut", func(t *testing.T) {
		reassembler, _ := relayframe.NewReassembler(relayframe.DefaultReassemblyLimits(), admitAll(sender))
		_, frames := splitFrames(t, 600_000, "h")
		short := frames[1]
		short.Part = short.Part[:len(short.Part)-1]
		if _, err := reassembler.Add(sender, short, now); !errors.Is(err, relayframe.ErrReassemblyCut) {
			t.Fatalf("a short non-final part: %v", err)
		}
	})
	t.Run("split application object", func(t *testing.T) {
		reassembler, _ := relayframe.NewReassembler(relayframe.DefaultReassemblyLimits(), admitAll(sender))
		_, frames := splitFrames(t, 300_000, "i")
		forged := frames[0]
		forged.Part = append([]byte(nil), forged.Part...)
		forged.Part[len(canon.DomainRelayRoomObject)] = relayframe.RoomApplication
		if _, err := reassembler.Add(sender, forged, now); !errors.Is(err, relayframe.ErrReassemblyInconsistent) {
			t.Fatalf("a split application object: %v", err)
		}
	})
	t.Run("per-peer objects", func(t *testing.T) {
		reassembler, _ := relayframe.NewReassembler(relayframe.DefaultReassemblyLimits(), admitAll(sender))
		for index := 0; index < 4; index++ {
			_, frames := splitFrames(t, 200_000, fmt.Sprint(index))
			if _, err := reassembler.Add(sender, frames[1], now); err != nil {
				t.Fatal(err)
			}
		}
		_, frames := splitFrames(t, 200_000, "fifth")
		if _, err := reassembler.Add(sender, frames[1], now); !errors.Is(err, relayframe.ErrReassemblyPeerObjects) {
			t.Fatalf("fifth object: %v", err)
		}
	})
	t.Run("per-peer bytes", func(t *testing.T) {
		limits := relayframe.DefaultReassemblyLimits()
		limits.MaxPeerObjects = 64
		reassembler, _ := relayframe.NewReassembler(limits, admitAll(sender))
		held := 0
		var err error
		for index := 0; err == nil; index++ {
			_, frames := splitFrames(t, 1_040_000, fmt.Sprint("p", index))
			for _, frame := range frames[:5] {
				if _, err = reassembler.Add(sender, frame, now); err != nil {
					break
				}
				held += len(frame.Part)
			}
		}
		if !errors.Is(err, relayframe.ErrReassemblyPeerBytes) || reassembler.Usage().PeerBytes[sender] > 4<<20 {
			t.Fatalf("per-peer bytes: %v, %d held", err, reassembler.Usage().PeerBytes[sender])
		}
	})
	t.Run("global bytes", func(t *testing.T) {
		limits := relayframe.DefaultReassemblyLimits()
		limits.MaxPeerObjects = 64
		var senders []string
		for index := 0; index < 8; index++ {
			senders = append(senders, roomAgent(index))
		}
		reassembler, _ := relayframe.NewReassembler(limits, admitAll(senders...))
		var err error
		for _, member := range senders {
			for object := 0; object < 4 && err == nil; object++ {
				_, frames := splitFrames(t, 1_040_000, member[len(member)-4:]+fmt.Sprint(object))
				for _, frame := range frames[:5] {
					if _, err = reassembler.Add(member, frame, now); err != nil {
						break
					}
				}
			}
			if errors.Is(err, relayframe.ErrReassemblyPeerBytes) {
				err = nil
			}
			if err != nil {
				break
			}
		}
		if !errors.Is(err, relayframe.ErrReassemblyTotalBytes) || reassembler.Usage().TotalBytes > 16<<20 {
			t.Fatalf("global bytes: %v, %d held", err, reassembler.Usage().TotalBytes)
		}
	})
	t.Run("wrong-size part against a held object", func(t *testing.T) {
		for _, change := range []string{"part count", "repeated index"} {
			reassembler, _ := relayframe.NewReassembler(relayframe.DefaultReassemblyLimits(), admitAll(sender))
			_, frames := splitFrames(t, 600_000, "w"+change)
			if _, err := reassembler.Add(sender, frames[1], now); err != nil {
				t.Fatal(err)
			}
			// A part of the wrong size, which the cut alone would refuse
			// without touching the held object.
			forged := frames[1]
			forged.Part = forged.Part[:len(forged.Part)-7]
			if change == "part count" {
				forged = frames[2]
				forged.Part = forged.Part[:len(forged.Part)-7]
				forged.PartCount = 5
			}
			if _, err := reassembler.Add(sender, forged, now); !errors.Is(err, relayframe.ErrReassemblyInconsistent) {
				t.Fatalf("%s with a wrong-size part: %v", change, err)
			}
			if usage := reassembler.Usage(); usage.Objects != 0 || usage.TotalBytes != 0 || len(usage.PeerCount) != 0 {
				t.Fatalf("%s: the held object was not dropped and released: %+v", change, usage)
			}
		}
	})
	t.Run("expired objects do not count against the caps", func(t *testing.T) {
		reassembler, _ := relayframe.NewReassembler(relayframe.DefaultReassemblyLimits(), admitAll(sender))
		for index := 0; index < 4; index++ {
			_, frames := splitFrames(t, 200_000, fmt.Sprint("old", index))
			if _, err := reassembler.Add(sender, frames[1], now); err != nil {
				t.Fatal(err)
			}
		}
		_, frames := splitFrames(t, 200_000, "new")
		if _, err := reassembler.Add(sender, frames[1], now.Add(time.Hour)); !errors.Is(err, relayframe.ErrReassemblyPeerObjects) {
			t.Fatalf("a fifth live object: %v", err)
		}
		later := now.Add(24*time.Hour + 5*time.Minute)
		if _, err := reassembler.Add(sender, frames[1], later); err != nil {
			t.Fatalf("a part after the held objects expired: %v", err)
		}
		if usage := reassembler.Usage(); usage.Objects != 1 || usage.PeerCount[sender] != 1 {
			t.Fatalf("expired objects still counted: %+v", usage)
		}
	})
	t.Run("expiry", func(t *testing.T) {
		reassembler, _ := relayframe.NewReassembler(relayframe.DefaultReassemblyLimits(), admitAll(sender))
		_, frames := splitFrames(t, 300_000, "x")
		if _, err := reassembler.Add(sender, frames[0], now); err != nil {
			t.Fatal(err)
		}
		if dropped := reassembler.Sweep(now.Add(24*time.Hour + 4*time.Minute)); dropped != 0 {
			t.Fatal("dropped before its lifetime")
		}
		if dropped := reassembler.Sweep(now.Add(24*time.Hour + 5*time.Minute)); dropped != 1 {
			t.Fatal("an incomplete object outlived its lifetime")
		}
		if usage := reassembler.Usage(); usage.Objects != 0 || usage.TotalBytes != 0 {
			t.Fatal("an expired object is still accounted")
		}
	})
}

func TestReassemblerTestCut(t *testing.T) {
	sender := roomAgent(0)
	limits := relayframe.DefaultReassemblyLimits()
	limits.PartBytes = 1_024
	reassembler, err := relayframe.NewReassembler(limits, admitAll(sender))
	if err != nil {
		t.Fatal(err)
	}
	object := roomObject(t, relayframe.RoomObject{Type: relayframe.RoomWelcome, RoomID: testRoom, RoomEpoch: 2, Header: roomHeader(t, 2, 2, "tos-local"), Body: make([]byte, 4_000)})
	frames, err := relayframe.SplitRoomObject(object, nil, evidence(t), 1_024)
	if err != nil {
		t.Fatal(err)
	}
	var result relayframe.PartResult
	for _, frame := range decodeAll(t, frames) {
		if result, err = reassembler.Add(sender, frame, now); err != nil {
			t.Fatal(err)
		}
	}
	if result.Status != relayframe.PartComplete || !bytes.Equal(result.Object, object) {
		t.Fatal("a test-cut object was not reassembled")
	}
	// The production cut does not fit a reassembler cut at P.
	_, production := splitFrames(t, 300_000, "z")
	if _, err := reassembler.Add(sender, production[1], now); !errors.Is(err, relayframe.ErrReassemblyCut) {
		t.Fatalf("a production part under a test cut: %v", err)
	}
	limits.PartBytes = 5
	if _, err := relayframe.NewReassembler(limits, admitAll(sender)); err == nil {
		t.Fatal("a test part size below its range was accepted")
	}
}
