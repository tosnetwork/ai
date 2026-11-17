package eventlog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/room"
)

// joinCredential is the joiner's Endpoint-signed DeviceCredential.
func joinCredential(t *testing.T, agentID string, seed byte, issued, expires uint64) ([]byte, string) {
	t.Helper()
	delegation, key := roomDelegation(t, agentID, seed)
	leaf := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed + 1}, ed25519.SeedSize))
	credential, err := group.SignDeviceCredential(group.DeviceCredential{Network: delegation.Network, AgentID: agentID,
		EndpointID: delegation.EndpointID, DeviceID: "dev_" + strings.Repeat("1", 64), DeviceSetDigest: canon.Digest([]byte("set")),
		LeafSignaturePublicKey: leaf.Public().(ed25519.PublicKey), KeyPackage: []byte("key package " + string(seed)),
		IssuedAtUnix: issued, ExpiresAtUnix: expires}, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := group.EncodeDeviceCredentialJSON(credential)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := group.KeyPackageRef(credential)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, ref
}

const inviteEvent = "evt_" + "7777777777777777777777777777777777777777777777777777777777777777"

// A pending join names the invite's authority; the owner's join stages the
// identity, which garbage collection keeps; installing the Welcome ends it.
func TestPendingRoomJoinLifecycle(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	now := fixture.now
	authority := fixture.delegation.AgentID
	if _, err := journal.BeginRoomJoin(fusedRoom, authority, []byte("identity"), []byte("{}"), now); err == nil {
		t.Fatal("joined without an invite")
	}
	if _, err := journal.RecordRoomInvite(fusedRoom, authority, inviteEvent, inviteBinding(t, authority), now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	// Another Agent's invite for the same room coexists until the owner
	// accepts one.
	if _, err := journal.RecordRoomInvite(fusedRoom, fusedAgent(5), inviteEvent, inviteBinding(t, fusedAgent(5)), now.Add(time.Hour), now); err != nil {
		t.Fatalf("invite from another Agent: %v", err)
	}
	credential, ref := joinCredential(t, fusedAgent(1), 0x71, uint64(now.Unix())-10, uint64(now.Add(24*time.Hour).Unix()))
	identity := bytes.Repeat([]byte{0x33}, MLSStateChunkBytes+10)
	join, err := journal.BeginRoomJoin(fusedRoom, authority, identity, credential, now)
	if err != nil || join.State != JoinKeyPackageSent || join.KeyPackageRef != ref || len(join.IdentityStateChunks) != 2 {
		t.Fatalf("join: %+v %v", join, err)
	}
	if _, found, _ := journal.PendingRoomJoinFor(fusedRoom, fusedAgent(5), now); found {
		t.Fatal("accepting one authority kept the other's invite")
	}
	if _, err := journal.RecordRoomInvite(fusedRoom, fusedAgent(5), inviteEvent, inviteBinding(t, fusedAgent(5)), now.Add(time.Hour), now); !errors.Is(err, ErrRoomJoinConflict) {
		t.Fatalf("an invite from another Agent after acceptance: %v", err)
	}
	if again, err := journal.BeginRoomJoin(fusedRoom, authority, identity, credential, now); err != nil || again.KeyPackageRef != ref {
		t.Fatalf("repeated join: %v", err)
	}
	other, _ := joinCredential(t, fusedAgent(1), 0x75, uint64(now.Unix())-10, uint64(now.Add(24*time.Hour).Unix()))
	if _, err := journal.BeginRoomJoin(fusedRoom, authority, identity, other, now); !errors.Is(err, ErrRoomJoinConflict) {
		t.Fatalf("a second KeyPackage: %v", err)
	}
	// Restart: collection keeps the staged identity a pending join names.
	journal, ledger = reopenFused(t, journal, root)
	defer journal.Close()
	if report, err := journal.CollectRoomGarbage(); err != nil || report.FailedClosed || report.Deleted != 0 {
		t.Fatalf("collection: %+v %v", report, err)
	}
	pending, found, err := journal.AcceptedRoomJoin(fusedRoom, now)
	if err != nil || !found || pending.AuthorityAgentID != authority {
		t.Fatalf("pending: %v %v", found, err)
	}
	state, err := journal.RoomJoinIdentityState(pending)
	if err != nil || !bytes.Equal(state, identity) {
		t.Fatalf("identity state: %v", err)
	}
	if err := journal.FinishRoomJoin(fusedRoom); err == nil {
		t.Fatal("a join ended before its Welcome was installed")
	}
	membership := fixture.founding()
	if _, err := ledger.InstallWelcome(RoomMLSInstall{
		Binding: group.State{RoomID: fusedRoom, Clock: group.Clock{RoomEpoch: 1, MLSEpoch: 1}, MembershipDigest: membership.Digest},
		Proof:   fixture.proof(membership), State: []byte("joined state"), EpochAuthenticator: fusedAuthenticator(2),
		KeyPackageRef: ref, WelcomeRef: canon.Digest([]byte("welcome")),
		Credentials: fixture.credentials(), EndsAtUnix: testRoomEnd,
	}, now); err != nil {
		t.Fatal(err)
	}
	if err := journal.FinishRoomJoin(fusedRoom); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := journal.PendingRoomJoinFor(fusedRoom, authority, now); found {
		t.Fatal("the join outlived its Welcome")
	}
	for _, chunk := range pending.IdentityStateChunks {
		path, _ := journal.roomStatePath(fusedRoom, chunk)
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("the ended join's identity chunk was kept")
		}
	}
	if _, err := journal.RecordRoomInvite(fusedRoom, authority, inviteEvent, inviteBinding(t, authority), now.Add(time.Hour), now); !errors.Is(err, ErrRoomAlreadyJoined) {
		t.Fatalf("invite to a joined room: %v", err)
	}
}

// A crash after the Welcome install, before FinishRoomJoin, ends the join on
// the next read; an expired invite ends it too; the joins are bounded.
func TestPendingRoomJoinEndsAndIsBounded(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, _ := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	now := fixture.now
	for index := 0; index < MaxPendingRoomJoins; index++ {
		roomID := "room_" + strings.Repeat("0", 62) + string("0123456789abcdef"[index/16]) + string("0123456789abcdef"[index%16])
		inviter := fusedAgent(10 + index/MaxPendingRoomJoinsPerAuthority)
		if _, err := journal.RecordRoomInvite(roomID, inviter, inviteEvent, inviteBinding(t, inviter), now.Add(time.Minute), now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := journal.RecordRoomInvite(fusedRoom, fusedAgent(1), inviteEvent, inviteBinding(t, fusedAgent(1)), now.Add(time.Hour), now); !errors.Is(err, ErrRoomJoinsFull) {
		t.Fatalf("beyond the bound: %v", err)
	}
	later := now.Add(2 * time.Minute)
	if _, err := journal.RecordRoomInvite(fusedRoom, fusedAgent(1), inviteEvent, inviteBinding(t, fusedAgent(1)), later.Add(time.Hour), later); err != nil {
		t.Fatalf("expired invites still filled the bound: %v", err)
	}
	joins, err := journal.ListPendingRoomJoins(later)
	if err != nil || len(joins) != 1 || joins[0].RoomID != fusedRoom {
		t.Fatalf("live joins: %d %v", len(joins), err)
	}
	credential, _ := joinCredential(t, fusedAgent(2), 0x72, uint64(later.Unix())-1, uint64(later.Add(time.Hour).Unix()))
	if _, err := journal.BeginRoomJoin(fusedRoom, fusedAgent(1), []byte("identity"), credential, later.Add(2*time.Hour)); err == nil {
		t.Fatal("joined with an expired credential")
	}
	if names, _ := filepath.Glob(filepath.Join(journal.root, roomJoinDir, "*.json")); len(names) != 1 {
		t.Fatalf("%d join records", len(names))
	}
}

// A stranger cannot pre-empt the real authority: an invite lives at most
// 7 days, the real authority's invite for the same room coexists with it,
// and one Agent holds at most 8 pending joins.
func TestRoomInvitesCannotBePreempted(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, _ := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	now := fixture.now
	stranger := fusedAgent(5)
	if _, err := journal.RecordRoomInvite(fusedRoom, stranger, inviteEvent, inviteBinding(t, stranger), now.Add(100*365*24*time.Hour), now); err == nil {
		t.Fatal("a far-future invite was recorded")
	}
	if _, err := journal.RecordRoomInvite(fusedRoom, stranger, inviteEvent, inviteBinding(t, stranger), now.Add(MaxRoomInviteLifetime+time.Second), now); err == nil {
		t.Fatal("an invite beyond 7 days was recorded")
	}
	if _, err := journal.RecordRoomInvite(fusedRoom, stranger, inviteEvent, inviteBinding(t, stranger), now.Add(MaxRoomInviteLifetime), now); err != nil {
		t.Fatal(err)
	}
	authority := fixture.delegation.AgentID
	if _, err := journal.RecordRoomInvite(fusedRoom, authority, inviteEvent, inviteBinding(t, authority), now.Add(time.Hour), now); err != nil {
		t.Fatalf("the real authority was pre-empted: %v", err)
	}
	for index := 1; index < MaxPendingRoomJoinsPerAuthority; index++ {
		roomID := "room_" + strings.Repeat("e", 63) + string("0123456789abcdef"[index])
		if _, err := journal.RecordRoomInvite(roomID, stranger, inviteEvent, inviteBinding(t, stranger), now.Add(time.Hour), now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := journal.RecordRoomInvite("room_"+strings.Repeat("f", 64), stranger, inviteEvent, inviteBinding(t, stranger), now.Add(time.Hour), now); !errors.Is(err, ErrRoomJoinsShareFull) {
		t.Fatalf("a ninth pending join of one Agent: %v", err)
	}
	// The stranger's 7-day invite ends; a year later nothing of it is left.
	later := now.Add(365 * 24 * time.Hour)
	if err := journal.SweepRoomJoins(later); err != nil {
		t.Fatal(err)
	}
	if joins, err := journal.ListPendingRoomJoins(later); err != nil || len(joins) != 0 {
		t.Fatalf("%d joins outlived their invites: %v", len(joins), err)
	}
}

// Accepting one authority's invite deletes the room's other invites at
// once, not only when they are next read.
func TestAcceptingAJoinDiscardsTheOthersAtOnce(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, _ := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	now := fixture.now
	authority := fixture.delegation.AgentID
	for _, inviter := range []string{authority, fusedAgent(5), fusedAgent(6)} {
		if _, err := journal.RecordRoomInvite(fusedRoom, inviter, inviteEvent, inviteBinding(t, inviter), now.Add(time.Hour), now); err != nil {
			t.Fatal(err)
		}
	}
	credential, _ := joinCredential(t, fusedAgent(1), 0x73, uint64(now.Unix())-10, uint64(now.Add(24*time.Hour).Unix()))
	if _, err := journal.BeginRoomJoin(fusedRoom, authority, []byte("identity"), credential, now); err != nil {
		t.Fatal(err)
	}
	for _, inviter := range []string{fusedAgent(5), fusedAgent(6)} {
		if _, err := os.Stat(journal.roomJoinPath(fusedRoom, inviter)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the invite of %s was kept on disk: %v", inviter, err)
		}
	}
	if _, err := os.Stat(journal.roomJoinPath(fusedRoom, authority)); err != nil {
		t.Fatalf("the accepted join is missing: %v", err)
	}
}

// One installation holds at most MaxRoomsHeld private rooms, joined or
// being joined.
func TestRoomsHeldAreBounded(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	install := func(index int) error {
		roomID := fmt.Sprintf("room_%064x", index+1)
		membership, err := room.Found(roomID, []string{fusedAgent(0)})
		if err != nil {
			t.Fatal(err)
		}
		_, err = ledger.InstallFounder(RoomMLSInstall{
			Binding: group.State{RoomID: roomID, Clock: group.Clock{RoomEpoch: 1}, MembershipDigest: membership.Digest},
			Proof:   fixture.proof(membership), State: []byte("founder state"), EpochAuthenticator: fusedAuthenticator(1),
			KeyPackageRef: canon.Digest([]byte(fmt.Sprint("key package ", index))),
			Credentials:   fixture.credentials(), EndsAtUnix: testRoomEnd,
		}, fixture.now)
		return err
	}
	for index := 0; index < MaxRoomsHeld; index++ {
		if err := install(index); err != nil {
			t.Fatal(err)
		}
	}
	if err := install(MaxRoomsHeld); !errors.Is(err, ErrRoomsFull) {
		t.Fatalf("a room beyond the bound: %v", err)
	}
	if _, err := journal.RecordRoomInvite(fusedRoom, fusedAgent(5), inviteEvent, inviteBinding(t, fusedAgent(5)), fixture.now.Add(time.Hour), fixture.now); err != nil {
		t.Fatal(err)
	}
	credential, _ := joinCredential(t, fusedAgent(1), 0x74, uint64(fixture.now.Unix())-10, uint64(fixture.now.Add(24*time.Hour).Unix()))
	if _, err := journal.BeginRoomJoin(fusedRoom, fusedAgent(5), []byte("identity"), credential, fixture.now); !errors.Is(err, ErrRoomsFull) {
		t.Fatalf("a join beyond the bound: %v", err)
	}
}
