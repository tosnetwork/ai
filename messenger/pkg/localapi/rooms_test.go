package localapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/room"
)

const (
	privateRoomID = "room_" + "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
	otherRoomID   = "room_" + "6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"
	authorityID   = "agent_" + "abababababababababababababababababababababababababababababababab"
	memberID      = "agent_" + "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	roomIdem      = "idem_" + "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

type recordingRooms struct {
	calls       []string
	composition RoomComposition
	err         error
}

func (r *recordingRooms) CreateRoom(_ context.Context, roomID string) error {
	r.calls = append(r.calls, "create "+roomID)
	return r.err
}
func (r *recordingRooms) AddRoomMember(_ context.Context, roomID, agentID string) error {
	r.calls = append(r.calls, "add "+roomID+" "+agentID)
	return r.err
}
func (r *recordingRooms) RemoveRoomMember(_ context.Context, roomID, agentID string) error {
	r.calls = append(r.calls, "remove "+roomID+" "+agentID)
	return r.err
}
func (r *recordingRooms) JoinRoom(_ context.Context, roomID, authorityAgentID string) error {
	r.calls = append(r.calls, "join "+roomID+" "+authorityAgentID)
	return r.err
}
func (r *recordingRooms) ComposeRoomMessage(_ context.Context, composition RoomComposition) (string, bool, error) {
	r.composition = composition
	return "evt_" + strings.Repeat("e", 64), true, r.err
}

// installPrivateRoom founds a private room in the harness journal whose
// authority is another Agent and whose members include this installation.
func installPrivateRoom(t *testing.T, h *harness, members ...string) eventlog.RoomMLSRecord {
	t.Helper()
	network := testNetwork()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	endpointID, err := identity.DeriveEndpointID(network, authorityID, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	delegation := identity.Delegation{Network: network, AgentID: authorityID, EndpointID: endpointID,
		IdentityPublicKey: key.Public().(ed25519.PublicKey), AllowedProtocolVersions: []uint32{1},
		AllowedOutboundEventClasses: []string{"room"}, NotBeforeUnix: 1, ExpiresAtUnix: 2_000_000_000,
		MaximumSessionLifetimeSeconds: 3600, ContactDescriptorPolicyDigest: "sha256:" + strings.Repeat("c", 64),
		InboxAdmissionPolicyDigest: "sha256:" + strings.Repeat("d", 64)}
	membership, err := room.Found(privateRoomID, append([]string{authorityID}, members...))
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := room.SignMembershipAuthorization(room.MembershipAuthorization{Network: network, RoomID: privateRoomID,
		Epoch: 1, MembershipDigest: membership.Digest, Authority: room.Authority{AgentID: authorityID, EndpointID: endpointID},
		IssuedAtUnix: baseUnix, ExpiresAtUnix: baseUnix + 3600}, key)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := h.journal.OpenRoomMLS()
	if err != nil {
		t.Fatal(err)
	}
	// The room is installed as its own first state: a Welcome install needs
	// the pending join of the room.invite this harness never received.
	record, err := ledger.InstallFounder(eventlog.RoomMLSInstall{
		Binding: group.State{RoomID: privateRoomID, Clock: group.Clock{RoomEpoch: 1}, MembershipDigest: membership.Digest},
		Proof:   eventlog.RoomAuthorityProof{Membership: membership, Authorization: authorization, Delegation: delegation},
		State:   []byte("joined"), EpochAuthenticator: bytes.Repeat([]byte{7}, group.MLSEpochAuthenticatorBytes),
		KeyPackageRef: canon.Digest([]byte("key package")),
		Credentials:   []group.LeafBinding{roomLeafBinding(t, delegation, key, baseUnix-10, testRoomEnd)}, EndsAtUnix: testRoomEnd,
	}, h.clock)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func roomRequests() []Request {
	return []Request{
		{Op: OpCreateRoom, RoomID: otherRoomID},
		{Op: OpAddRoomMember, RoomID: otherRoomID, RoomMemberAgentID: memberID},
		{Op: OpRemoveRoomMember, RoomID: otherRoomID, RoomMemberAgentID: memberID},
		{Op: OpJoinRoom, RoomID: otherRoomID, RoomAuthorityAgentID: authorityID},
	}
}

// D13: creating, adding, removing and joining are owner decisions. The
// runtime is refused even with an owner-shaped signature; the owner's
// signature commits the exact room and member.
func TestRoomManagementIsOwnerOnly(t *testing.T) {
	h := newHarness(t)
	operator := &recordingRooms{}
	h.server.config.RoomOperator = operator
	for _, request := range roomRequests() {
		if Permits(PrincipalRuntime, request.Op) || !Permits(PrincipalOwner, request.Op) || !Deciding(request.Op) {
			t.Fatalf("%s is not an owner-only decision", request.Op)
		}
		if response := h.runtimeAttempt(t, request); response.OK || response.Code != fault.CodeClassNotDelegated {
			t.Fatalf("runtime %s: %+v", request.Op, response)
		}
	}
	if len(operator.calls) != 0 {
		t.Fatalf("a runtime request reached the room runtime: %v", operator.calls)
	}
	for _, request := range roomRequests() {
		if response := h.owner(t, request); !response.OK || response.RoomID != otherRoomID {
			t.Fatalf("owner %s: %+v", request.Op, response)
		}
	}
	want := []string{"create " + otherRoomID, "add " + otherRoomID + " " + memberID, "remove " + otherRoomID + " " + memberID, "join " + otherRoomID + " " + authorityID}
	if strings.Join(operator.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls: %v", operator.calls)
	}
	// A signature over one member does not add another.
	issued := h.callAs(t, PrincipalOwner, Request{Op: OpChallenge})
	signed := Request{Op: OpAddRoomMember, RoomID: otherRoomID, RoomMemberAgentID: memberID}
	signature, err := SignDecision(signed, issued.Challenge, testOwnerKey())
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []Request{
		{Op: OpAddRoomMember, RoomID: otherRoomID, RoomMemberAgentID: authorityID},
		{Op: OpAddRoomMember, RoomID: privateRoomID, RoomMemberAgentID: memberID},
	} {
		changed.Challenge, changed.OwnerSignature = issued.Challenge, signature
		if response := h.callAs(t, PrincipalOwner, changed); response.OK || response.Code != fault.CodeNotAuthentic {
			t.Fatalf("a signature over another decision was accepted: %+v", response)
		}
	}
	// A signature over joining one authority's invite does not accept another's.
	issued = h.callAs(t, PrincipalOwner, Request{Op: OpChallenge})
	join := Request{Op: OpJoinRoom, RoomID: otherRoomID, RoomAuthorityAgentID: authorityID}
	signature, err = SignDecision(join, issued.Challenge, testOwnerKey())
	if err != nil {
		t.Fatal(err)
	}
	other := Request{Op: OpJoinRoom, RoomID: otherRoomID, RoomAuthorityAgentID: memberID, Challenge: issued.Challenge, OwnerSignature: signature}
	if response := h.callAs(t, PrincipalOwner, other); response.OK || response.Code != fault.CodeNotAuthentic {
		t.Fatalf("a signature over another authority was accepted: %+v", response)
	}
	// A typed refusal of the room runtime reaches the owner.
	operator.err = fault.New(fault.CodeNotARoomMember, "no such member")
	if response := h.owner(t, Request{Op: OpRemoveRoomMember, RoomID: otherRoomID, RoomMemberAgentID: memberID}); response.Code != fault.CodeNotARoomMember {
		t.Fatalf("typed refusal: %+v", response)
	}
}

// Without a room runtime the operations are refused as not configured, and
// every request is strictly shaped.
func TestRoomOperationsWithoutARuntimeAndTheirShapes(t *testing.T) {
	h := newHarness(t)
	for _, request := range roomRequests() {
		if response := h.owner(t, request); response.OK || response.Code != fault.CodeClassNotDelegated {
			t.Fatalf("%s without a runtime: %+v", request.Op, response)
		}
	}
	for name, request := range map[string]Request{
		"create no room":     {Op: OpCreateRoom},
		"add no member":      {Op: OpAddRoomMember, RoomID: otherRoomID},
		"join with member":   {Op: OpJoinRoom, RoomID: otherRoomID, RoomAuthorityAgentID: authorityID, RoomMemberAgentID: memberID},
		"join no authority":  {Op: OpJoinRoom, RoomID: otherRoomID},
		"create authority":   {Op: OpCreateRoom, RoomID: otherRoomID, RoomAuthorityAgentID: authorityID},
		"list with room":     {Op: OpListRooms, RoomID: otherRoomID},
		"gaps no room":       {Op: OpRoomGaps},
		"gaps over limit":    {Op: OpRoomGaps, RoomID: otherRoomID, Limit: MaxRoomGapsPerResponse + 1},
		"member elsewhere":   {Op: OpPending, RoomMemberAgentID: memberID},
		"room elsewhere":     {Op: OpPending, RoomID: otherRoomID},
		"create unsigned id": {Op: OpCreateRoom, RoomID: "room_short"},
	} {
		if err := ValidateRequest(request); err == nil && !Deciding(request.Op) {
			t.Fatalf("%s accepted", name)
		} else if err == nil {
			// Deciding operations also need a signature; the shape alone must fail.
			request.Challenge, request.OwnerSignature = strings.Repeat("a", 64), "00"
			if ValidateRequest(request) == nil {
				t.Fatalf("%s accepted", name)
			}
		}
	}
}

// The runtime lists the rooms held here and the pending joins, and reads a
// room's gap records.
func TestRuntimeListsRoomsAndGaps(t *testing.T) {
	h := newHarness(t)
	installPrivateRoom(t, h, senderID, memberID)
	if _, err := h.journal.RecordRoomInvite(otherRoomID, authorityID, "evt_"+strings.Repeat("a", 64), inviteAuthorityBinding(t), h.clock.Add(time.Hour), h.clock); err != nil {
		t.Fatal(err)
	}
	listed := h.call(t, Request{Op: OpListRooms})
	if !listed.OK || len(listed.Rooms) != 2 {
		t.Fatalf("rooms: %+v", listed)
	}
	joined, pending := listed.Rooms[0], listed.Rooms[1]
	if joined.RoomID != privateRoomID || joined.State != "joined" || joined.IsAuthority || joined.AuthorityAgentID != authorityID ||
		joined.RoomEpoch != 1 || len(joined.Members) != 3 {
		t.Fatalf("joined room: %+v", joined)
	}
	if pending.RoomID != otherRoomID || pending.State != "invited" || pending.AuthorityAgentID != authorityID {
		t.Fatalf("pending join: %+v", pending)
	}
	if err := h.journal.ObserveRoomSequence(privateRoomID, memberID, 1, h.clock); err != nil {
		t.Fatal(err)
	}
	if _, err := h.journal.RecordRoomDrop(privateRoomID, memberID, eventlog.RoomGapEpochTooOld, h.clock); err != nil {
		t.Fatal(err)
	}
	if err := h.journal.ObserveRoomSequence(privateRoomID, memberID, 4, h.clock.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	gaps := h.call(t, Request{Op: OpRoomGaps, RoomID: privateRoomID})
	if !gaps.OK || len(gaps.RoomGaps) != 1 || gaps.RoomGaps[0].FirstSequence != 2 || gaps.RoomGaps[0].LastSequence != 3 ||
		gaps.RoomGaps[0].SenderAgentID != memberID || gaps.RoomGaps[0].Reason != string(eventlog.RoomGapEpochTooOld) {
		t.Fatalf("gaps: %+v", gaps)
	}
}

func roomComposition(epoch uint64) Request {
	return Request{Op: OpCompose, ConversationID: convoID, RoomID: privateRoomID, MembershipEpoch: epoch,
		MediaType: "text/plain; charset=utf-8", Body: "to the room", IdempotencyKey: roomIdem, ExpiresAtUnix: baseUnix + 3600}
}

// outbox.compose with the room ID of a private room and no route takes the
// kind-3 path; a pairwise copy of a private room is refused.
func TestComposeToAPrivateRoomTakesTheRoomPath(t *testing.T) {
	h := newHarness(t)
	// A room-wide composition needs a private room held here.
	if response := h.call(t, roomComposition(1)); response.OK || response.Code != fault.CodePayloadMalformed {
		t.Fatalf("no private room: %+v", response)
	}
	installPrivateRoom(t, h, senderID, memberID)
	if response := h.call(t, roomComposition(1)); response.OK || response.Code != fault.CodeClassNotDelegated {
		t.Fatalf("no room runtime: %+v", response)
	}
	operator := &recordingRooms{}
	h.server.config.RoomOperator = operator
	if response := h.call(t, roomComposition(2)); response.OK || response.Code != fault.CodeRoomEpochGap {
		t.Fatalf("stale epoch: %+v", response)
	}
	oversized := roomComposition(1)
	oversized.Body = strings.Repeat("x", 131_073)
	if response := h.call(t, oversized); response.OK || response.Code != fault.CodeContentTooLarge {
		t.Fatalf("oversized: %+v", response)
	}
	response := h.call(t, roomComposition(1))
	if !response.OK || !response.Fresh || response.RoomID != privateRoomID || operator.composition.RoomID != privateRoomID ||
		operator.composition.Body != "to the room" || operator.composition.MembershipEpoch != 1 {
		t.Fatalf("room composition: %+v %+v", response, operator.composition)
	}
	pairwise := roomComposition(1)
	pairwise.SessionID, pairwise.RecipientEndpointID = sessionID, peerMEP
	if response := h.call(t, pairwise); response.OK || response.Code != fault.CodePayloadMalformed {
		t.Fatalf("a pairwise copy of a private room: %+v", response)
	}
}

// A room this installation is not a member of is refused.
func TestComposeToAPrivateRoomNeedsMembership(t *testing.T) {
	h := newHarness(t)
	installPrivateRoom(t, h, memberID)
	h.server.config.RoomOperator = &recordingRooms{}
	if response := h.call(t, roomComposition(1)); response.OK || response.Code != fault.CodeNotARoomMember {
		t.Fatalf("not a member: %+v", response)
	}
}

// roomLeafBinding signs a leaf credential for a delegation and verifies it
// on the room path, which is the only way to obtain a binding.
func roomLeafBinding(t *testing.T, delegation identity.Delegation, key ed25519.PrivateKey, issued, expires uint64) group.LeafBinding {
	t.Helper()
	leaf := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x29}, ed25519.SeedSize))
	device := "dev_" + delegation.AgentID[len("agent_"):]
	credential, err := group.SignLeafCredential(group.LeafCredential{Network: delegation.Network, AgentID: delegation.AgentID,
		EndpointID: delegation.EndpointID, DeviceID: device, DeviceSetDigest: canon.Digest([]byte("set")),
		LeafSignaturePublicKey: leaf.Public().(ed25519.PublicKey), IssuedAtUnix: issued, ExpiresAtUnix: expires}, key)
	if err != nil {
		t.Fatal(err)
	}
	set := e2ee.SetSummary{EndpointID: delegation.EndpointID, Digest: credential.DeviceSetDigest, DeviceIDs: []string{device}}
	binding, err := group.VerifyRoomLeafCredential(delegation, credential, set, expires, time.Unix(int64(issued), 0))
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

// inviteAuthorityBinding is the authority's verified leaf credential a test
// room.invite carries.
func inviteAuthorityBinding(t *testing.T) group.LeafBinding {
	t.Helper()
	network := testNetwork()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	endpointID, err := identity.DeriveEndpointID(network, authorityID, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	delegation := identity.Delegation{Network: network, AgentID: authorityID, EndpointID: endpointID,
		IdentityPublicKey: key.Public().(ed25519.PublicKey), NotBeforeUnix: 1, ExpiresAtUnix: 2_000_000_000}
	return roomLeafBinding(t, delegation, key, baseUnix-10, testRoomEnd)
}

// testRoomEnd is the end of the test room: ten days after the harness clock.
const testRoomEnd = baseUnix + 10*24*3600

// D18 on the send side: a member stops sealing at the room's end minus the
// clock-skew bound, and a room whose credential list is gone (a crash left
// it half retired) sends nothing.
func TestComposeStopsAtTheRoomEndAndInAHalfRetiredRoom(t *testing.T) {
	h := newHarness(t)
	record := installPrivateRoom(t, h, senderID, memberID)
	h.server.config.RoomOperator = &recordingRooms{}
	stop := time.Unix(int64(record.RoomEndsAtUnix), 0).Add(-DefaultRoomClockSkew)
	h.clock = stop.Add(-time.Second)
	if response := h.call(t, roomComposition(1)); !response.OK {
		t.Fatalf("a second before the stop: %+v", response)
	}
	h.clock = stop
	second := roomComposition(1)
	second.IdempotencyKey = "idem_" + strings.Repeat("f", 64)
	if response := h.call(t, second); response.OK || response.Code != fault.CodeRoomEnded {
		t.Fatalf("at the stop: %+v", response)
	}
	h.clock = stop.Add(-time.Hour)
	listPath := filepath.Join(h.root, "room-blobs", "l-"+record.CredentialListDigest[len("sha256:"):]+".json")
	if err := os.Remove(listPath); err != nil {
		t.Fatal(err)
	}
	third := roomComposition(1)
	third.IdempotencyKey = "idem_" + strings.Repeat("d", 64)
	if response := h.call(t, third); response.OK {
		t.Fatalf("a half-retired room sent: %+v", response)
	}
}

// A member removed from the room seals nothing more in it (section 11.4).
func TestComposeIsRefusedInARoomThisInstallationWasRemovedFrom(t *testing.T) {
	h := newHarness(t)
	record := installPrivateRoom(t, h, senderID, memberID)
	h.server.config.RoomOperator = &recordingRooms{}
	if response := h.call(t, roomComposition(1)); !response.OK {
		t.Fatalf("before the removal: %+v", response)
	}
	if fresh, _, err := h.journal.MarkRoomRemoved(record.RoomID, record.RoomEpoch+1, record.MLSEpoch+1,
		strings.Repeat("ab", 32), h.clock); err != nil || !fresh {
		t.Fatalf("mark removed: %v %v", fresh, err)
	}
	second := roomComposition(1)
	second.IdempotencyKey = "idem_" + strings.Repeat("f", 64)
	if response := h.call(t, second); response.OK || response.Code != fault.CodeNotARoomMember {
		t.Fatalf("after the removal: %+v", response)
	}
}
