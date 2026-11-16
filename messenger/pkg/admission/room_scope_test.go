package admission

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/room"
)

const privateRoom = "room_" + "9191919191919191919191919191919191919191919191919191919191919191"

var otherMember = "agent_" + strings.Repeat("3", 64)

// roomGate is a gate whose installation is the authority of a private room:
// epoch 1 holds this installation, the sender and another member; epoch 2
// removes the sender.
func roomGate(t *testing.T, policy ContactPolicy) (*Gate, *eventlog.Journal, *eventlog.RoomMLSLedger) {
	t.Helper()
	gate, journal, _, _ := testGate(t, policy)
	ledger, err := journal.OpenRoomMLS()
	if err != nil {
		t.Fatal(err)
	}
	local := testLocalDelegation(t, policy)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, ed25519.SeedSize))
	at := func(membership room.Membership) eventlog.RoomAuthorityProof {
		authorization, err := room.SignMembershipAuthorization(room.MembershipAuthorization{Network: local.Network,
			RoomID: membership.RoomID, Epoch: membership.Epoch, MembershipDigest: membership.Digest,
			Authority:    room.Authority{AgentID: local.AgentID, EndpointID: local.EndpointID},
			IssuedAtUnix: baseUnix, ExpiresAtUnix: baseUnix + 3600}, key)
		if err != nil {
			t.Fatal(err)
		}
		return eventlog.RoomAuthorityProof{Membership: membership, Authorization: authorization, Delegation: local}
	}
	founded, err := room.Found(privateRoom, []string{localID, senderID, otherMember})
	if err != nil {
		t.Fatal(err)
	}
	now := gate.config.Now()
	record, err := ledger.InstallFounder(eventlog.RoomMLSInstall{
		Binding: group.State{RoomID: privateRoom, Clock: group.Clock{RoomEpoch: 1}, MembershipDigest: founded.Digest},
		Proof:   at(founded), State: []byte("founder state"), EpochAuthenticator: bytes.Repeat([]byte{1}, group.MLSEpochAuthenticatorBytes),
		KeyPackageRef: canon.Digest([]byte("founder key package")),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := founded.Remove([]string{senderID})
	if err != nil {
		t.Fatal(err)
	}
	ref := canon.Digest([]byte("remove the sender"))
	proof := at(removed)
	next := group.State{RoomID: privateRoom, Clock: group.Clock{RoomEpoch: 2, MLSEpoch: 1}, MembershipDigest: removed.Digest, AcceptedCommitRef: ref}
	if _, _, err := ledger.Advance(eventlog.RoomMLSAdvance{
		Transition: group.Transition{Prior: record.Binding(), Next: next, Membership: removed, CommitRef: ref},
		Proof:      &proof, ExpectedStateDigest: record.StateDigest, State: []byte("epoch two"),
		EpochAuthenticator: bytes.Repeat([]byte{2}, group.MLSEpochAuthenticatorBytes),
	}, now); err != nil {
		t.Fatal(err)
	}
	gate.config.RoomMLS = ledger
	return gate, journal, ledger
}

// senderCredential is the sender's leaf DeviceCredential, signed by the
// sender's Endpoint key.
func senderCredential(t *testing.T, issued, expires uint64) group.DeviceCredential {
	t.Helper()
	delegation, _ := testDelegation(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	leaf := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x12}, ed25519.SeedSize))
	credential, err := group.SignDeviceCredential(group.DeviceCredential{Network: delegation.Network, AgentID: senderID,
		EndpointID: delegation.EndpointID, DeviceID: deviceID, DeviceSetDigest: canon.Digest([]byte("set")),
		LeafSignaturePublicKey: leaf.Public().(ed25519.PublicKey), KeyPackage: []byte("key package"),
		IssuedAtUnix: issued, ExpiresAtUnix: expires}, key)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func roomInbound(t *testing.T, epoch uint64, label string) Inbound {
	t.Helper()
	delegation, encoded := testDelegation(t)
	event := testEvent(t, delegation, func(e *envelope.Event) {
		e.RoomID = privateRoom
		e.Content = textBody(t, label)
	})
	request := inbound(event, encoded)
	request.Room = &RoomCarriage{RoomID: privateRoom, RoomEpoch: epoch, PacketSenderAgentID: senderID,
		SenderCredential: senderCredential(t, baseUnix, baseUnix+86_400)}
	return request
}

// D11: an Event naming a joined private room is admitted without the
// allow-list when its packet sender is in the committed membership of the
// epoch it was sealed in, and refused when it is not.
func TestRoomScopedAdmissionFollowsTheCommittedMembership(t *testing.T) {
	gate, _, _ := roomGate(t, allowList(t, TellThem))
	// Sealed in epoch 1, where the sender is a member: admitted although the
	// sender is no contact.
	if decision, err := gate.Admit(roomInbound(t, 1, "epoch one")); err != nil || decision.Outcome != Accepted {
		t.Fatalf("member at its epoch: %+v %v", decision, err)
	}
	// Sealed in epoch 2, which removed the sender.
	if decision, err := gate.Admit(roomInbound(t, 2, "epoch two")); err != nil || decision.Outcome != Rejected || decision.Code != fault.CodeNotARoomMember {
		t.Fatalf("removed member: %+v %v", decision, err)
	}
	// An epoch the room has not reached.
	if decision, _ := gate.Admit(roomInbound(t, 3, "epoch three")); decision.Outcome != Rejected || decision.Code != fault.CodeNotARoomMember {
		t.Fatalf("future epoch: %+v", decision)
	}
}

// The grant stays in the room: the same sender's Event naming no room, or
// carried without room carriage, meets the normal policy.
func TestRoomScopedAdmissionGrantsNoOneToOneAdmission(t *testing.T) {
	gate, _, _ := roomGate(t, allowList(t, TellThem))
	delegation, encoded := testDelegation(t)
	direct := inbound(testEvent(t, delegation, nil), encoded)
	if decision, err := gate.Admit(direct); err != nil || decision.Outcome != Rejected || decision.Code != fault.CodeAdmissionRequired {
		t.Fatalf("a member's 1:1 Event: %+v %v", decision, err)
	}
	uncarried := roomInbound(t, 1, "no carriage")
	uncarried.Room = nil
	if decision, err := gate.Admit(uncarried); err != nil || decision.Outcome != Rejected || decision.Code != fault.CodeAdmissionRequired {
		t.Fatalf("a room Event without room carriage: %+v %v", decision, err)
	}
}

// The carriage must be consistent and the sender's credential current.
func TestRoomScopedAdmissionRefusals(t *testing.T) {
	gate, _, _ := roomGate(t, allowList(t, TellThem))
	cases := []struct {
		name   string
		mutate func(*Inbound)
		code   fault.Code
	}{
		{"another packet sender", func(in *Inbound) { in.Room.PacketSenderAgentID = otherMember }, fault.CodeSenderMismatch},
		{"another room", func(in *Inbound) { in.Room.RoomID = "room_" + strings.Repeat("8", 64) }, fault.CodePayloadMalformed},
		{"expired credential", func(in *Inbound) { in.Room.SenderCredential = senderCredential(t, baseUnix-100, baseUnix+59) }, fault.CodeNotAuthentic},
		{"credential not yet valid", func(in *Inbound) { in.Room.SenderCredential = senderCredential(t, baseUnix+61, baseUnix+86_400) }, fault.CodeNotAuthentic},
		{"forged credential", func(in *Inbound) { in.Room.SenderCredential.EndpointSignature[0] ^= 1 }, fault.CodeNotAuthentic},
		{"another device", func(in *Inbound) { in.Room.SenderCredential.DeviceID = "dev_" + strings.Repeat("9", 64) }, fault.CodeNotAuthentic},
	}
	for index, test := range cases {
		request := roomInbound(t, 1, fmt.Sprintf("refusal %d", index))
		test.mutate(&request)
		decision, err := gate.Admit(request)
		if err != nil || decision.Outcome != Rejected || decision.Code != test.code {
			t.Fatalf("%s: %+v %v", test.name, decision, err)
		}
	}
	// A room this installation has not joined.
	unjoined, _, _, _ := testGate(t, allowList(t, TellThem))
	ledger, err := unjoined.config.Journal.OpenRoomMLS()
	if err != nil {
		t.Fatal(err)
	}
	unjoined.config.RoomMLS = ledger
	if decision, _ := unjoined.Admit(roomInbound(t, 1, "unjoined")); decision.Outcome != Rejected || decision.Code != fault.CodeNotARoomMember {
		t.Fatalf("unjoined room: %+v", decision)
	}
}

// A blocked sender stays blocked inside a room it is a member of.
func TestRoomScopedAdmissionKeepsBlockedSendersOut(t *testing.T) {
	gate, _, _ := roomGate(t, blockList(t, senderID))
	if decision, err := gate.Admit(roomInbound(t, 1, "blocked")); err != nil || decision.Outcome != Rejected {
		t.Fatalf("blocked member: %+v %v", decision, err)
	}
}
