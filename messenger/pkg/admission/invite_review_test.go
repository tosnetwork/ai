package admission

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/payload"
	"github.com/tosnetwork/ai/messenger/pkg/room"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

func issueInvite(t *testing.T, journal *eventlog.Journal, policy ContactPolicy, seed byte) string {
	t.Helper()
	local := testLocalDelegation(t, policy)
	var entropy [32]byte
	copy(entropy[:], bytes.Repeat([]byte{seed}, len(entropy)))
	token, _, err := journal.CreateAdmissionInvite(entropy, local.EndpointID, senderID,
		time.Unix(int64(baseUnix)+600, 0), time.Unix(int64(baseUnix)+30, 0))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// contacts.remove sticks: re-sending the exact claimed Event, before or after
// the invite's expiry, never makes the sender a contact again.
func TestRemovedInvitedContactStaysRemovedWhenTheClaimedEventIsResent(t *testing.T) {
	policy := allowList(t, InviteOrAskOwner)
	gate, journal, delegation, encoded := testGate(t, policy)
	token := issueInvite(t, journal, policy, 0x52)
	request := inbound(testEvent(t, delegation, nil), encoded)
	request.AdmissionToken = token
	if decision, err := gate.Admit(request); err != nil || decision.Outcome != Accepted {
		t.Fatalf("claim: %+v %v", decision, err)
	}
	if removed, err := journal.RemoveInvitedContact(senderID); err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	for _, at := range []uint64{baseUnix + 61, baseUnix + 700} {
		resend := request
		resend.ReceivedAtUnix = at
		decision, err := gate.Admit(resend)
		if err != nil || decision.Outcome != Duplicate {
			t.Fatalf("resent claimed Event at %d: %+v %v", at, decision, err)
		}
		if invited, err := journal.IsInvitedContact(senderID); err != nil || invited {
			t.Fatalf("re-sending the claimed Event at %d re-added the removed contact", at)
		}
	}
}

// The journal refuses to re-add a contact under the invite the owner removed
// it from, even when the claimed Event was never committed.
func TestTombstonedInviteNeverReAddsTheContact(t *testing.T) {
	policy := allowList(t, InviteOrAskOwner)
	_, journal, _, _ := testGate(t, policy)
	token := issueInvite(t, journal, policy, 0x53)
	now := time.Unix(int64(baseUnix)+60, 0)
	event := "evt_" + string(bytes.Repeat([]byte("4"), 64))
	if added, err := journal.AddInvitedContact(senderID, event, token, now); err != nil || !added {
		t.Fatalf("add: %v %v", added, err)
	}
	if removed, err := journal.RemoveInvitedContact(senderID); err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if _, err := journal.AddInvitedContact(senderID, event, token, now); err != eventlog.ErrInvitedContactRemoved {
		t.Fatalf("re-add under a removed invite: %v", err)
	}
	other := issueInvite(t, journal, policy, 0x54)
	if added, err := journal.AddInvitedContact(senderID, event, other, now); err != nil || !added {
		t.Fatalf("a new invite could not make the contact again: %v %v", added, err)
	}
}

// Two Events racing for one token: the loser re-runs the policy without the
// token (invite-or-hold holds it, or admits it once the winner made the sender
// a contact) and is never refused for the spent token.
func TestRacingInviteLoserMeetsThePolicyWithoutTheToken(t *testing.T) {
	policy := allowList(t, InviteOrAskOwner)
	for round := 0; round < 40; round++ {
		gate, journal, delegation, encoded := testGate(t, policy)
		token := issueInvite(t, journal, policy, byte(0x60+round))
		events := []envelope.Event{
			testEvent(t, delegation, func(e *envelope.Event) { e.Content = textBody(t, "first racer") }),
			testEvent(t, delegation, func(e *envelope.Event) { e.Content = textBody(t, "second racer") }),
		}
		decisions := make([]Decision, len(events))
		errs := make([]error, len(events))
		var group sync.WaitGroup
		start := make(chan struct{})
		for index := range events {
			group.Add(1)
			go func(index int) {
				defer group.Done()
				<-start
				request := inbound(events[index], encoded)
				request.AdmissionToken = token
				decisions[index], errs[index] = gate.Admit(request)
			}(index)
		}
		close(start)
		group.Wait()
		accepted := 0
		for index, decision := range decisions {
			if errs[index] != nil {
				t.Fatalf("round %d: %v", round, errs[index])
			}
			switch decision.Outcome {
			case Accepted:
				accepted++
			case Held:
				if decision.Code != fault.CodeApprovalRequired {
					t.Fatalf("round %d: held with %s", round, decision.Code)
				}
			default:
				t.Fatalf("round %d: the racing loser was refused: %+v", round, decision)
			}
		}
		if accepted == 0 {
			t.Fatalf("round %d: no Event won the claim", round)
		}
	}
}

// The loser of a lost claim is refused when the policy without the token
// refuses: require-admission does not hold.
func TestSpentTokenFallsBackToTheRefusingPolicy(t *testing.T) {
	policy := allowList(t, TellThem)
	gate, journal, delegation, encoded := testGate(t, policy)
	token := issueInvite(t, journal, policy, 0x55)
	first := inbound(testEvent(t, delegation, nil), encoded)
	first.AdmissionToken = token
	if decision, err := gate.Admit(first); err != nil || decision.Outcome != Accepted {
		t.Fatalf("claim: %+v %v", decision, err)
	}
	if removed, err := journal.RemoveInvitedContact(senderID); err != nil || !removed {
		t.Fatal("remove")
	}
	second := inbound(testEvent(t, delegation, func(e *envelope.Event) { e.Content = textBody(t, "after removal") }), encoded)
	second.AdmissionToken = token
	decision, err := gate.Admit(second)
	if err != nil || decision.Outcome != Rejected || decision.Code != fault.CodeAdmissionRequired {
		t.Fatalf("spent token under require-admission: %+v %v", decision, err)
	}
}

// A blocked sender stays refused although a claimed invite made it a contact.
func TestBlockedInvitedSenderIsRefused(t *testing.T) {
	policy := blockList(t, senderID)
	gate, journal, delegation, encoded := testGate(t, policy)
	token := issueInvite(t, journal, policy, 0x56)
	event := "evt_" + string(bytes.Repeat([]byte("5"), 64))
	if added, err := journal.AddInvitedContact(senderID, event, token, time.Unix(int64(baseUnix)+60, 0)); err != nil || !added {
		t.Fatalf("add: %v %v", added, err)
	}
	decision, err := gate.Admit(inbound(testEvent(t, delegation, nil), encoded))
	if err != nil || decision.Outcome != Rejected {
		t.Fatalf("blocked invited sender: %+v %v", decision, err)
	}
}

// Deterministically: another Event spends the token between this Event's
// check and its claim. With invite-or-hold the loser is held, not refused;
// once the winner made the sender a contact, it is admitted.
func TestInviteClaimLostToAnotherEventMeetsThePolicy(t *testing.T) {
	for _, winnerAddsContact := range []bool{false, true} {
		policy := allowList(t, InviteOrAskOwner)
		gate, journal, delegation, encoded := testGate(t, policy)
		token := issueInvite(t, journal, policy, 0x57)
		local := testLocalDelegation(t, policy)
		winner := "evt_" + string(bytes.Repeat([]byte("6"), 64))
		at := time.Unix(int64(baseUnix)+60, 0)
		gate.config.beforeInviteClaim = func() {
			gate.config.beforeInviteClaim = nil
			if _, err := journal.ClaimAdmissionInvite(token, local.EndpointID, senderID, winner, at); err != nil {
				t.Errorf("winner claim: %v", err)
			}
			if winnerAddsContact {
				if _, err := journal.AddInvitedContact(senderID, winner, token, at); err != nil {
					t.Errorf("winner contact: %v", err)
				}
			}
		}
		request := inbound(testEvent(t, delegation, nil), encoded)
		request.AdmissionToken = token
		decision, err := gate.Admit(request)
		gate.config.beforeInviteClaim = nil
		want := Held
		if winnerAddsContact {
			want = Accepted
		}
		if err != nil || decision.Outcome != want {
			t.Fatalf("winner adds contact=%v: %+v %v, want %s", winnerAddsContact, decision, err, want)
		}
	}
}

// Only a fresh claim, or the retry of an Event not yet committed, runs the
// contact-add step: with the tombstone gone (as after its sweep), re-sending
// the committed claimed Event still does not re-add a removed contact.
func TestResentCommittedClaimRunsNoContactStep(t *testing.T) {
	policy := allowList(t, InviteOrAskOwner)
	gate, journal, delegation, encoded := testGate(t, policy)
	token := issueInvite(t, journal, policy, 0x58)
	request := inbound(testEvent(t, delegation, nil), encoded)
	request.AdmissionToken = token
	if decision, err := gate.Admit(request); err != nil || decision.Outcome != Accepted {
		t.Fatalf("claim: %+v %v", decision, err)
	}
	if removed, err := journal.RemoveInvitedContact(senderID); err != nil || !removed {
		t.Fatal("remove")
	}
	removeTombstones(t, journal)
	if decision, err := gate.Admit(request); err != nil || decision.Outcome != Duplicate {
		t.Fatalf("resend: %+v %v", decision, err)
	}
	if invited, err := journal.IsInvitedContact(senderID); err != nil || invited {
		t.Fatal("re-sending the committed claimed Event re-added the contact")
	}
}

// removeTombstones deletes the journal's removal tombstones, standing in for
// their sweep, so the contact-add guard is tested on its own.
func removeTombstones(t *testing.T, journal *eventlog.Journal) {
	t.Helper()
	root := reflect.ValueOf(journal).Elem().FieldByName("root").String()
	dir := filepath.Join(root, "invited-contact-tombstones")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("no tombstone to remove: %v", err)
	}
	for _, entry := range entries {
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			t.Fatal(err)
		}
	}
}

// A room.moderation Event that its Apply would refuse (here a member with no
// moderation role) is refused before an invite is claimed for it: the
// sender gains no contact and the invite stays unclaimed.
func TestRefusedModerationClaimsNoInvite(t *testing.T) {
	now := time.Unix(int64(baseUnix)+30, 0)
	policy := allowList(t, InviteOrAskOwner)
	journal, err := eventlog.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	sender, _ := testDelegation(t)
	sender.AllowedOutboundEventClasses = []string{"room", "text"}
	senderRaw, err := identity.EncodeJSON(sender)
	if err != nil {
		t.Fatal(err)
	}
	senderDigest, _ := identity.Digest(sender)
	local, localRaw, localAgent := localState(t, policy)
	localKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, ed25519.SeedSize))
	rooms, _ := journal.OpenRooms()
	membership, err := room.Found(overlayRoom, []string{senderID, localID})
	if err != nil {
		t.Fatal(err)
	}
	authority := room.Authority{AgentID: local.AgentID, EndpointID: local.EndpointID}
	authorization, err := room.SignMembershipAuthorization(room.MembershipAuthorization{
		Network: testNetwork(), RoomID: overlayRoom, Epoch: 1, MembershipDigest: membership.Digest,
		Authority: authority, IssuedAtUnix: baseUnix + 1, ExpiresAtUnix: baseUnix + 3600,
	}, localKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rooms.Advance(membership, authorization, local, now); err != nil {
		t.Fatal(err)
	}
	rolePolicy, err := room.SignRolePolicy(room.RolePolicy{Network: testNetwork(), RoomID: overlayRoom,
		MembershipEpoch: 1, MembershipDigest: membership.Digest, Revision: 1,
		Assignments: []room.RoleAssignment{{AgentID: localID, Role: room.RoleAdministrator}},
		Authority:   authority, IssuedAtUnix: baseUnix + 1, ExpiresAtUnix: baseUnix + 3600}, localKey)
	if err != nil {
		t.Fatal(err)
	}
	roles, _ := journal.OpenRoomRoles()
	if _, err := roles.Advance(rolePolicy, local, now); err != nil {
		t.Fatal(err)
	}
	gate, err := New(Config{Network: testNetwork(), Chain: testChain(),
		Resolver: stubResolver{states: map[string]*nativev1.NativeStateV1{
			senderID: nativeState(&nativev1.AgentStateV1{AgentId: senderID,
				Policy: &nativev1.ControllerPolicyV1{Threshold: 1}, DelegationDigests: []string{senderDigest}}),
			localID: localAgent}}, Journal: journal, Devices: mustDevices(t, journal), Rooms: rooms,
		Policy: policy, LocalDelegationJSON: localRaw, LocalAgentID: local.AgentID,
		LocalEndpointID: local.EndpointID, Now: func() time.Time { return now },
		InstallSalt: bytes.Repeat([]byte{0x5a}, MinInstallSaltBytes)})
	if err != nil {
		t.Fatal(err)
	}
	token := issueInvite(t, journal, policy, 0x59)
	body, _ := payload.Encode(payload.RoomModeration{RoomID: overlayRoom, MembershipEpoch: 1,
		RolePolicyRevision: 1, TargetEventID: "evt_" + strings.Repeat("6", 64), DecisionRevision: 1,
		Action: "hide", Reason: "not mine to decide"})
	moderation := testEvent(t, sender, func(event *envelope.Event) {
		event.RoomID, event.Kind, event.Content = overlayRoom, "room.moderation", body
	})
	request := inbound(moderation, senderRaw)
	request.AdmissionToken = token
	decision, err := gate.Admit(request)
	if err != nil || decision.Outcome != Rejected || decision.Code != fault.CodeNotAuthentic {
		t.Fatalf("a non-moderator's decision: %+v %v", decision, err)
	}
	if invited, err := journal.IsInvitedContact(senderID); err != nil || invited {
		t.Fatal("a refused moderation decision made a contact")
	}
	// The invite is still unclaimed: another Event can still spend it.
	other := "evt_" + strings.Repeat("8", 64)
	if err := journal.CheckAdmissionInvite(token, local.EndpointID, senderID, other, now); err != nil {
		t.Fatalf("the invite was claimed: %v", err)
	}
}

// A later removal's tombstone sweep keeps every tombstone whose invite record
// still exists: replaying a claimed Event that was never committed (a crash
// between the claim and the commit) still does not re-add the removed
// contact.
func TestTombstoneSweepKeepsLiveInvitesTombstones(t *testing.T) {
	policy := allowList(t, InviteOrAskOwner)
	gate, journal, delegation, encoded := testGate(t, policy)
	local := testLocalDelegation(t, policy)
	at := time.Unix(int64(baseUnix)+60, 0)
	tokenX := issueInvite(t, journal, policy, 0x5a)
	request := inbound(testEvent(t, delegation, nil), encoded)
	request.AdmissionToken = tokenX
	// The claim and the contact add happened, the commit did not.
	if claimed, err := journal.ClaimAdmissionInvite(tokenX, local.EndpointID, senderID, request.Event.EventID, at); err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	if _, err := journal.AddInvitedContact(senderID, request.Event.EventID, tokenX, at); err != nil {
		t.Fatal(err)
	}
	other := "agent_" + strings.Repeat("9", 64)
	tokenY := issueInvite(t, journal, policy, 0x5b)
	if _, err := journal.AddInvitedContact(other, "evt_"+strings.Repeat("9", 64), tokenY, at); err != nil {
		t.Fatal(err)
	}
	if removed, err := journal.RemoveInvitedContact(senderID); err != nil || !removed {
		t.Fatal("remove X")
	}
	// Y's removal sweeps the tombstones; X's invite record still exists.
	if removed, err := journal.RemoveInvitedContact(other); err != nil || !removed {
		t.Fatal("remove Y")
	}
	decision, err := gate.Admit(request)
	if err != nil || decision.Outcome != Accepted {
		t.Fatalf("replayed claimed Event: %+v %v", decision, err)
	}
	if invited, err := journal.IsInvitedContact(senderID); err != nil || invited {
		t.Fatal("the swept tombstone let the claimed Event re-add the contact")
	}
}
