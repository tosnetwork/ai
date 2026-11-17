package eventlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/messenger/pkg/room"
)

// removeTransition is the authority's Commit removing members.
func removeTransition(t *testing.T, current RoomMLSRecord, removed []string, ref string) (group.Transition, room.Membership) {
	t.Helper()
	membership, err := current.Membership().Remove(removed)
	if err != nil {
		t.Fatal(err)
	}
	next := group.State{RoomID: current.RoomID, Clock: group.Clock{RoomEpoch: membership.Epoch, MLSEpoch: current.MLSEpoch + 1}, MembershipDigest: membership.Digest, AcceptedCommitRef: ref}
	return group.Transition{Prior: current.Binding(), Next: next, Membership: membership, CommitRef: ref}, membership
}

func advanceMembership(t *testing.T, fixture *fusedFixture, ledger *RoomMLSLedger, current RoomMLSRecord, transition group.Transition, membership room.Membership) RoomMLSRecord {
	t.Helper()
	proof := fixture.proof(membership)
	_, next, err := ledger.Advance(RoomMLSAdvance{Transition: transition, Proof: &proof, ExpectedStateDigest: current.StateDigest,
		State: []byte("state at " + transition.CommitRef), EpochAuthenticator: fusedAuthenticator(byte(transition.Next.Clock.MLSEpoch + 1))}, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func credentialPath(t *testing.T, journal *Journal, binding group.LeafBinding) string {
	t.Helper()
	encoded, err := group.EncodeLeafCredential(binding.Credential())
	if err != nil {
		t.Fatal(err)
	}
	path, err := journal.roomBlobPath(credentialBlobPrefix, canon.Digest(encoded))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// The founder's install roots the authority's credential and fixes the room's
// end; a member's credential is learned (records, list, fused write), an
// exact repeat writes nothing, and both survive a restart and a collection.
func TestRoomCredentialsAreLearnedRootedAndRepeated(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	if record.RoomEndsAtUnix != testRoomEnd || !canon.ValidDigest(record.CredentialListDigest) {
		t.Fatalf("the founder's install: %+v", record)
	}
	if credential, found, err := ledger.RoomCredential(fusedRoom, fusedAgent(0)); err != nil || !found || credential.ExpiresAtUnix != testRoomEnd {
		t.Fatalf("authority credential: %v %v", found, err)
	}
	bob := fusedAgent(1)
	transition, membership := addTransition(t, record, []string{bob}, canon.Digest([]byte("add bob")))
	record = advanceMembership(t, fixture, ledger, record, transition, membership)
	if _, found, err := ledger.RoomCredential(fusedRoom, bob); err != nil || found {
		t.Fatalf("Bob's credential before its roster: %v %v", found, err)
	}
	bobBinding := memberBinding(t, bob)
	fresh, learned, err := ledger.LearnRoomCredentials(fusedRoom, []group.LeafBinding{bobBinding}, fixture.now)
	if err != nil || !fresh || learned.CredentialListDigest == record.CredentialListDigest {
		t.Fatalf("learn: %v %v", fresh, err)
	}
	if fresh, again, err := ledger.LearnRoomCredentials(fusedRoom, []group.LeafBinding{bobBinding}, fixture.now); err != nil || fresh || again.CredentialListDigest != learned.CredentialListDigest {
		t.Fatalf("exact repeat: %v %v", fresh, err)
	}
	// Refusals: a non-member's credential and a binding not made by the room
	// path's verification.
	if _, _, err := ledger.LearnRoomCredentials(fusedRoom, []group.LeafBinding{memberBinding(t, fusedAgent(9))}, fixture.now); !errors.Is(err, ErrRoomCredentialMember) {
		t.Fatalf("a non-member's credential: %v", err)
	}
	if _, _, err := ledger.LearnRoomCredentials(fusedRoom, []group.LeafBinding{{}}, fixture.now); err == nil {
		t.Fatal("an unverified binding was learned")
	}
	journal, ledger = reopenFused(t, journal, root)
	defer journal.Close()
	if report, err := journal.CollectRoomGarbage(); err != nil || report.FailedClosed {
		t.Fatalf("collection: %+v %v", report, err)
	}
	credential, found, err := ledger.RoomCredential(fusedRoom, bob)
	if err != nil || !found || credential.AgentID != bob {
		t.Fatalf("Bob's credential after a restart and a collection: %v %v", found, err)
	}
}

// A crash before the fused write leaves unrooted credential records and an
// unrooted list: restart collects them and the credential is not known.
func TestRoomCredentialsStagedWithoutTheFusedWriteAreCollected(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	bob := fusedAgent(1)
	transition, membership := addTransition(t, record, []string{bob}, canon.Digest([]byte("add bob")))
	record = advanceMembership(t, fixture, ledger, record, transition, membership)
	binding := memberBinding(t, bob)
	journal.mutex.Lock()
	_, digest, err := journal.stageLeafCredential(binding)
	if err == nil {
		_, err = journal.stageCredentialList(mergeCredentials(fusedRoom, nil, map[string]string{bob: digest, fusedAgent(0): digest}, record.Members))
	}
	journal.mutex.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	journal, ledger = reopenFused(t, journal, root)
	defer journal.Close()
	if _, err := os.Stat(credentialPath(t, journal, binding)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an unrooted credential survived the restart: %v", err)
	}
	if _, found, err := ledger.RoomCredential(fusedRoom, bob); err != nil || found {
		t.Fatalf("an unrooted credential is known: %v %v", found, err)
	}
	if _, found, err := ledger.RoomCredential(fusedRoom, fusedAgent(0)); err != nil || !found {
		t.Fatalf("the rooted authority credential: %v %v", found, err)
	}
}

// The list is a collection root through the fused record: an unreadable list
// deletes nothing.
func TestRoomCredentialListIsAFailClosedRoot(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	listPath, err := journal.roomBlobPath(credentialListBlobPrefix, record.CredentialListDigest)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.replace(listPath, []byte(`{"schema":"other"}`)); err != nil {
		t.Fatal(err)
	}
	journal.mutex.Lock()
	unnamed, err := journal.stageMLSState(fusedRoom, []byte("an unnamed state"))
	journal.mutex.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	report, err := journal.CollectRoomGarbage()
	if err != nil || !report.FailedClosed || report.Deleted != 0 {
		t.Fatalf("collection over an unreadable list: %+v %v", report, err)
	}
	path, err := journal.roomStatePath(fusedRoom, unnamed[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("collection deleted a record past an unreadable root: %v", err)
	}
	if _, _, err := ledger.RoomCredential(fusedRoom, fusedAgent(0)); err == nil {
		t.Fatal("an unreadable list answered a credential")
	}
}

// Removing a member drops its credential from the list in the same write,
// and collection then deletes its record.
func TestRemoveDeletesTheMembersCredential(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	bob, carol := fusedAgent(1), fusedAgent(2)
	transition, membership := addTransition(t, record, []string{bob, carol}, canon.Digest([]byte("add both")))
	record = advanceMembership(t, fixture, ledger, record, transition, membership)
	bobBinding, carolBinding := memberBinding(t, bob), memberBinding(t, carol)
	_, record, err := ledger.LearnRoomCredentials(fusedRoom, []group.LeafBinding{bobBinding, carolBinding}, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	transition, membership = removeTransition(t, record, []string{bob}, canon.Digest([]byte("remove bob")))
	record = advanceMembership(t, fixture, ledger, record, transition, membership)
	if _, found, err := ledger.RoomCredential(fusedRoom, bob); err != nil || found {
		t.Fatalf("a removed member's credential is still listed: %v %v", found, err)
	}
	if _, found, err := ledger.RoomCredential(fusedRoom, carol); err != nil || !found {
		t.Fatalf("a remaining member's credential: %v %v", found, err)
	}
	journal, _ = reopenFused(t, journal, root)
	defer journal.Close()
	if _, err := os.Stat(credentialPath(t, journal, bobBinding)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the removed member's credential record survived collection: %v", err)
	}
	if _, err := os.Stat(credentialPath(t, journal, carolBinding)); err != nil {
		t.Fatalf("a remaining member's credential record was collected: %v", err)
	}
}

// D18 at install: the credentials hold the authority's, the room's end is its
// expiry, and every credential is a member's.
func TestRoomInstallFixesTheEndToTheAuthorityCredential(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	membership := fixture.founding()
	base := RoomMLSInstall{
		Binding: group.State{RoomID: fusedRoom, Clock: group.Clock{RoomEpoch: 1}, MembershipDigest: membership.Digest},
		Proof:   fixture.proof(membership), State: []byte("s"), EpochAuthenticator: fusedAuthenticator(1),
		KeyPackageRef: canon.Digest([]byte("kp")),
	}
	otherKey := leafBindingFor(t, fixture.delegation, fixture.key, 0x44, testRoomEnd+1)
	cases := map[string]struct {
		credentials []group.LeafBinding
		end         uint64
		want        error
	}{
		"no credentials":                   {nil, testRoomEnd, ErrRoomAuthorityCredential},
		"no end":                           {fixture.credentials(), 0, ErrRoomAuthorityCredential},
		"an end other than the expiry":     {fixture.credentials(), testRoomEnd + 1, ErrRoomCredentialEndsEarly},
		"an end before the expiry":         {fixture.credentials(), testRoomEnd - 1, ErrRoomAuthorityCredential},
		"the expiry of another credential": {[]group.LeafBinding{otherKey}, testRoomEnd, ErrRoomAuthorityCredential},
		"a non-member's credential":        {append(fixture.credentials(), memberBinding(t, fusedAgent(3))), testRoomEnd, ErrRoomCredentialMember},
		"an unverified binding":            {[]group.LeafBinding{{}}, testRoomEnd, ErrRoomCredentialMember},
	}
	for name, test := range cases {
		install := base
		install.Credentials, install.EndsAtUnix = test.credentials, test.end
		if _, err := ledger.InstallFounder(install, fixture.now); !errors.Is(err, test.want) {
			t.Fatalf("%s: %v", name, err)
		}
		if _, found, _ := ledger.Current(fusedRoom); found {
			t.Fatalf("%s: the room was installed", name)
		}
	}
	// A member's credential without the authority's fixes no end.
	pair, err := room.Found(fusedRoom, []string{fusedAgent(0), fusedAgent(3)})
	if err != nil {
		t.Fatal(err)
	}
	withoutAuthority := base
	withoutAuthority.Binding.MembershipDigest = pair.Digest
	withoutAuthority.Proof = fixture.proof(pair)
	withoutAuthority.Credentials, withoutAuthority.EndsAtUnix = []group.LeafBinding{memberBinding(t, fusedAgent(3))}, testRoomEnd
	if _, err := ledger.InstallFounder(withoutAuthority, fixture.now); !errors.Is(err, ErrRoomAuthorityCredential) {
		t.Fatalf("no authority credential: %v", err)
	}
	install := base
	install.Credentials, install.EndsAtUnix = fixture.credentials(), testRoomEnd
	if _, err := ledger.InstallFounder(install, fixture.now); err != nil {
		t.Fatal(err)
	}
}

// The authority's credential a room.invite carried is kept with the pending
// join across a restart, and a Welcome install must carry that same
// credential; the install roots it before the join ends.
func TestPendingJoinKeepsTheInviteCredentialAndTheWelcomeRootsIt(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	authority := fixture.delegation.AgentID
	invited := memberBinding(t, authority)
	if _, err := journal.RecordRoomInvite(fusedRoom, authority, inviteEvent, memberBinding(t, fusedAgent(5)), fixture.now.Add(time.Hour), fixture.now); err == nil {
		t.Fatal("an invite carried another Agent's credential")
	}
	if _, err := journal.RecordRoomInvite(fusedRoom, authority, inviteEvent, group.LeafBinding{}, fixture.now.Add(time.Hour), fixture.now); !errors.Is(err, ErrRoomCredentialUnverified) {
		t.Fatalf("an unverified invite credential: %v", err)
	}
	if _, err := journal.RecordRoomInvite(fusedRoom, authority, inviteEvent, invited, fixture.now.Add(time.Hour), fixture.now); err != nil {
		t.Fatal(err)
	}
	journal, ledger = reopenFused(t, journal, root)
	join, found, err := journal.PendingRoomJoinFor(fusedRoom, authority, fixture.now)
	if err != nil || !found {
		t.Fatalf("pending join after a restart: %v %v", found, err)
	}
	stored, err := join.AuthorityCredential()
	if err != nil || stored.ExpiresAtUnix != invited.Credential().ExpiresAtUnix {
		t.Fatalf("stored authority credential: %v", err)
	}
	ref := acceptJoin(t, journal, fixture, authority)
	membership := fixture.founding()
	welcome := RoomMLSInstall{
		Binding: group.State{RoomID: fusedRoom, Clock: group.Clock{RoomEpoch: 1, MLSEpoch: 1}, MembershipDigest: membership.Digest},
		Proof:   fixture.proof(membership), State: []byte("joined"), EpochAuthenticator: fusedAuthenticator(2),
		KeyPackageRef: ref, WelcomeRef: canon.Digest([]byte("welcome")), EndsAtUnix: testRoomEnd - 1,
		Credentials: []group.LeafBinding{leafBindingFor(t, fixture.delegation, fixture.key, 0x45, testRoomEnd-1)},
	}
	if _, err := ledger.InstallWelcome(welcome, fixture.now); !errors.Is(err, ErrRoomAuthorityCredential) {
		t.Fatalf("a Welcome under another authority credential: %v", err)
	}
	welcome.Credentials, welcome.EndsAtUnix = []group.LeafBinding{invited}, testRoomEnd
	if _, err := ledger.InstallWelcome(welcome, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := journal.FinishRoomJoin(fusedRoom); err != nil {
		t.Fatal(err)
	}
	journal, ledger = reopenFused(t, journal, root)
	defer journal.Close()
	if got, found, err := ledger.RoomCredential(fusedRoom, authority); err != nil || !found || got.ExpiresAtUnix != testRoomEnd {
		t.Fatalf("the authority credential after the join: %v %v", found, err)
	}
	if _, err := os.Stat(credentialPath(t, journal, invited)); err != nil {
		t.Fatalf("the rooted authority credential was collected: %v", err)
	}
}

// An object at the current epoch from a member whose credential is not known
// is held, not offered for opening, until the credential is learned.
func TestRoomBufferHoldsObjectsOfUnknownCredentials(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	bob := fusedAgent(1)
	transition, membership := addTransition(t, record, []string{bob}, canon.Digest([]byte("add bob")))
	record = advanceMembership(t, fixture, ledger, record, transition, membership)
	current := applicationObject(t, record.MLSEpoch, 7, 64)
	if fresh, err := journal.BufferRoomObject(bob, current, fixture.now); err != nil || !fresh {
		t.Fatalf("an unknown credential's current-epoch object: %v %v", fresh, err)
	}
	if openable, _, err := journal.OpenableRoomObjects(fusedRoom); err != nil || len(openable) != 0 {
		t.Fatalf("offered before the credential is known: %d %v", len(openable), err)
	}
	waiting, _, err := journal.RoomObjectsAwaitingCredential(fusedRoom)
	if err != nil || len(waiting) != 1 || waiting[0].SenderAgentID != bob {
		t.Fatalf("awaiting: %+v %v", waiting, err)
	}
	if _, err := journal.BufferRoomObject(fusedAgent(0), applicationObject(t, record.MLSEpoch, 8, 64), fixture.now); !errors.Is(err, ErrRoomBufferCredentialKnown) {
		t.Fatalf("a known credential's current-epoch object: %v", err)
	}
	if _, err := journal.BufferRoomObject(bob, applicationObject(t, record.MLSEpoch-1, 9, 64), fixture.now); !errors.Is(err, ErrRoomBufferEpoch) {
		t.Fatalf("a past-epoch object: %v", err)
	}
	if _, _, err := ledger.LearnRoomCredentials(fusedRoom, []group.LeafBinding{memberBinding(t, bob)}, fixture.now); err != nil {
		t.Fatal(err)
	}
	openable, _, err := journal.OpenableRoomObjects(fusedRoom)
	if err != nil || len(openable) != 1 || openable[0].SenderAgentID != bob {
		t.Fatalf("offered once known: %+v %v", openable, err)
	}
	if waiting, _, err := journal.RoomObjectsAwaitingCredential(fusedRoom); err != nil || len(waiting) != 0 {
		t.Fatalf("still awaiting: %+v %v", waiting, err)
	}
}

// Retirement runs at end + retention + skew, deletes the outbox, receive
// state, list and fused record in that order, and a crash at each step is
// finished by the next retirement; collection then reclaims the rest.
func TestRoomRetirementInOrderAndAfterACrash(t *testing.T) {
	retention, skew := 7*24*time.Hour, 5*time.Minute
	for _, crashAt := range []int{0, 2, 3} {
		fixture := newFusedFixture(t)
		root := t.TempDir() + "/state"
		journal, ledger := openFused(t, root)
		record := fixture.installFounder(ledger, []byte("epoch zero"))
		record, _ = addWithOutput(t, fixture, ledger, record, fusedAgent(1), "add bob")
		if err := journal.ObserveRoomSequence(fusedRoom, fusedAgent(1), 3, fixture.now); err != nil {
			t.Fatal(err)
		}
		if heads, err := journal.RoomOutboxHeads(fusedRoom); err != nil || len(heads) == 0 {
			t.Fatalf("crash %d: outbox before retirement: %d %v", crashAt, len(heads), err)
		}
		retireAt, err := RoomRetireAt(record, retention, skew)
		if err != nil || !retireAt.Equal(time.Unix(testRoomEnd, 0).Add(retention+skew)) {
			t.Fatalf("retire at %v: %v", retireAt, err)
		}
		if _, err := ledger.RetireRoom(fusedRoom, retireAt.Add(-time.Second), retention, skew); !errors.Is(err, ErrRoomNotEnded) {
			t.Fatalf("crash %d: early retirement: %v", crashAt, err)
		}
		if crashAt != 0 {
			step := crashAt
			beforeRoomRetireStep = func(n int) error {
				if n == step {
					return errors.New("crash")
				}
				return nil
			}
			if _, err := ledger.RetireRoom(fusedRoom, retireAt, retention, skew); err == nil {
				t.Fatalf("crash %d: the crash did not stop retirement", crashAt)
			}
			beforeRoomRetireStep = nil
			journal, ledger = reopenFused(t, journal, root)
			if _, found, err := journal.readRoomMLS(fusedRoom); err != nil || !found {
				t.Fatalf("crash %d: the fused record went before the last step: %v %v", crashAt, found, err)
			}
			if heads, err := journal.RoomOutboxHeads(fusedRoom); err != nil || len(heads) != 0 {
				t.Fatalf("crash %d: step 1 did not delete the outbox: %d %v", crashAt, len(heads), err)
			}
		}
		retired, err := ledger.RetireEndedRooms(retireAt, retention, skew)
		if err != nil || len(retired) != 1 || retired[0] != fusedRoom {
			t.Fatalf("crash %d: retirement: %v %v", crashAt, retired, err)
		}
		if _, found, err := ledger.Current(fusedRoom); err != nil || found {
			t.Fatalf("crash %d: the room is still held: %v %v", crashAt, found, err)
		}
		listPath, _ := journal.roomBlobPath(credentialListBlobPrefix, record.CredentialListDigest)
		if _, err := os.Stat(listPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("crash %d: the credential list survived: %v", crashAt, err)
		}
		if names, _ := os.ReadDir(filepath.Join(root, roomSequenceDir)); len(names) != 0 {
			t.Fatalf("crash %d: receive state survived", crashAt)
		}
		report, err := journal.CollectRoomGarbage()
		if err != nil || report.FailedClosed {
			t.Fatalf("crash %d: collection after retirement: %+v %v", crashAt, report, err)
		}
		for _, dir := range []string{roomStateDir, roomObjectChunkDir} {
			if names, _ := os.ReadDir(filepath.Join(root, dir)); len(names) != 0 {
				t.Fatalf("crash %d: %s kept %d records nothing names", crashAt, dir, len(names))
			}
		}
		if names, _ := os.ReadDir(filepath.Join(root, roomBlobDir)); len(names) != 0 {
			t.Fatalf("crash %d: %d blobs survived", crashAt, len(names))
		}
		if retired, err := ledger.RetireEndedRooms(retireAt, retention, skew); err != nil || len(retired) != 0 {
			t.Fatalf("crash %d: a second retirement: %v %v", crashAt, retired, err)
		}
		_ = journal.Close()
	}
}

// acceptJoin is the owner's rooms.join for the fixture room's pending join;
// it returns the KeyPackage reference.
func acceptJoin(t *testing.T, journal *Journal, fixture *fusedFixture, authority string) string {
	t.Helper()
	credential, ref := joinCredential(t, fusedAgent(1), 0x71, uint64(fixture.now.Unix())-10, uint64(fixture.now.Add(24*time.Hour).Unix()))
	if _, err := journal.BeginRoomJoin(fusedRoom, authority, []byte("identity state"), credential, fixture.now); err != nil {
		t.Fatal(err)
	}
	return ref
}

// A fused record without its credential list or its end time is refused on
// write and on read.
func TestFusedRecordNeedsItsCredentialListAndEnd(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	for name, change := range map[string]func(*RoomMLSRecord){
		"no credential list": func(r *RoomMLSRecord) { r.CredentialListDigest = "" },
		"no end":             func(r *RoomMLSRecord) { r.RoomEndsAtUnix = 0 },
	} {
		changed := record
		change(&changed)
		if _, err := encodeRoomMLSRecord(changed); err == nil {
			t.Fatalf("%s: encoded", name)
		}
		raw, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeRoomMLSRecord(raw); err == nil {
			t.Fatalf("%s: decoded", name)
		}
	}
}

// The authority's credential fixed the room's end and is never replaced
// inside the room; a member's credential must last until the end (D18).
func TestLearnedCredentialsKeepTheAuthorityAndLastUntilTheEnd(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	later := leafBindingFor(t, fixture.delegation, fixture.key, 0x46, testRoomEnd+500)
	if _, _, err := ledger.LearnRoomCredentials(fusedRoom, []group.LeafBinding{later}, fixture.now); !errors.Is(err, ErrRoomAuthorityCredential) {
		t.Fatalf("a replacement authority credential: %v", err)
	}
	if stored, _, err := ledger.RoomCredential(fusedRoom, fixture.delegation.AgentID); err != nil || stored.ExpiresAtUnix != testRoomEnd {
		t.Fatalf("the authority credential changed: %v", err)
	}
	// The stored authority credential itself is an exact repeat.
	if fresh, _, err := ledger.LearnRoomCredentials(fusedRoom, fixture.credentials(), fixture.now); err != nil || fresh {
		t.Fatalf("the stored authority credential: %v %v", fresh, err)
	}
	bob := fusedAgent(1)
	transition, membership := addTransition(t, record, []string{bob}, canon.Digest([]byte("add bob")))
	advanceMembership(t, fixture, ledger, record, transition, membership)
	delegation, key := roomDelegation(t, bob, 0x62)
	short := leafBindingFor(t, delegation, key, 0x29, testRoomEnd-100)
	if _, _, err := ledger.LearnRoomCredentials(fusedRoom, []group.LeafBinding{short}, fixture.now); !errors.Is(err, ErrRoomCredentialEndsEarly) {
		t.Fatalf("a member credential ending before the room: %v", err)
	}
	if _, found, _ := ledger.RoomCredential(fusedRoom, bob); found {
		t.Fatal("a short member credential was stored")
	}
	exact := leafBindingFor(t, delegation, key, 0x29, testRoomEnd)
	if fresh, _, err := ledger.LearnRoomCredentials(fusedRoom, []group.LeafBinding{exact}, fixture.now); err != nil || !fresh {
		t.Fatalf("a member credential ending with the room: %v %v", fresh, err)
	}
}

// A Welcome install needs the accepted pending join and consumes exactly the
// KeyPackage that join sent.
func TestWelcomeInstallNeedsTheAcceptedJoinAndItsKeyPackage(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	membership := fixture.founding()
	welcome := RoomMLSInstall{
		Binding: group.State{RoomID: fusedRoom, Clock: group.Clock{RoomEpoch: 1, MLSEpoch: 1}, MembershipDigest: membership.Digest},
		Proof:   fixture.proof(membership), State: []byte("joined"), EpochAuthenticator: fusedAuthenticator(2),
		KeyPackageRef: canon.Digest([]byte("kp")), WelcomeRef: canon.Digest([]byte("welcome")), EndsAtUnix: testRoomEnd,
		Credentials: fixture.credentials(),
	}
	if _, err := ledger.InstallWelcome(welcome, fixture.now); !errors.Is(err, ErrRoomJoinUnknown) {
		t.Fatalf("a Welcome with no pending join: %v", err)
	}
	ref := prepareJoin(t, journal, fixture)
	if _, err := ledger.InstallWelcome(welcome, fixture.now); !errors.Is(err, ErrRoomJoinKeyPackage) {
		t.Fatalf("a Welcome for another KeyPackage: %v", err)
	}
	if _, found, _ := ledger.Current(fusedRoom); found {
		t.Fatal("a refused Welcome installed the room")
	}
	welcome.KeyPackageRef = ref
	if _, err := ledger.InstallWelcome(welcome, fixture.now); err != nil {
		t.Fatal(err)
	}
}

// Retirement deletes the parts of its own room only: another room's parts
// stay.
func TestRoomRetirementKeepsAnotherRoomsParts(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	sender := fusedAgent(1)
	parts, _ := openParts(t, journal, allowSenders(sender), fixture.now)
	other := "room_" + strings.Repeat("6", 64)
	add := func(roomID string, seed byte) {
		t.Helper()
		object, err := relayframe.EncodeRoomObject(relayframe.RoomObject{Type: relayframe.RoomCommit, RoomID: roomID,
			RoomEpoch: 1, MLSEpoch: 2, Body: bytes.Repeat([]byte{seed}, 4_000)})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := relayframe.SplitRoomObject(object, []byte("card"), []byte("evidence"), 1_024)
		if err != nil {
			t.Fatal(err)
		}
		// Every part but the last, so the object stays held.
		for _, raw := range encoded[:len(encoded)-1] {
			frame, err := relayframe.Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parts.Add(sender, frame, fixture.now); err != nil {
				t.Fatal(err)
			}
		}
	}
	add(fusedRoom, 1)
	add(other, 2)
	before := storedPartCount(t, journal)
	if before == 0 {
		t.Fatal("no parts stored")
	}
	retention, skew := 7*24*time.Hour, 5*time.Minute
	at, err := RoomRetireAt(record, retention, skew)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.RetireRoom(fusedRoom, at, retention, skew); err != nil {
		t.Fatal(err)
	}
	after := storedPartCount(t, journal)
	if after == 0 || after*2 != before {
		t.Fatalf("parts before %d, after %d: retirement did not keep exactly the other room's", before, after)
	}
}

// Retirement deletes an object's later parts before its part 0, the only
// part that names the room: a crash in between leaves part 0, and the next
// retirement finds and finishes the object. The fused record is never
// deleted while a part 0 naming the room remains.
func TestRoomRetirementDeletesPartZeroLast(t *testing.T) {
	retention, skew := 7*24*time.Hour, 5*time.Minute
	sender := fusedAgent(1)
	held := func(t *testing.T, journal *Journal, ledger *RoomMLSLedger, fixture *fusedFixture, seed byte) (*RoomParts, []relayframe.Frame) {
		t.Helper()
		parts, _ := openParts(t, journal, allowSenders(sender), fixture.now)
		frames, _ := splitRoomFrames(t, fusedRoom, seed)
		for _, frame := range frames[:len(frames)-1] {
			if _, err := parts.Add(sender, frame, fixture.now); err != nil {
				t.Fatal(err)
			}
		}
		return parts, frames
	}
	for _, crashAt := range []int{roomRetirePartsLater, roomRetirePartsFirst} {
		fixture := newFusedFixture(t)
		root := t.TempDir() + "/state"
		journal, ledger := openFused(t, root)
		record := fixture.installFounder(ledger, []byte("epoch zero"))
		held(t, journal, ledger, fixture, 1)
		at, err := RoomRetireAt(record, retention, skew)
		if err != nil {
			t.Fatal(err)
		}
		step := crashAt
		beforeRoomRetireStep = func(n int) error {
			if n == step {
				return errors.New("crash")
			}
			return nil
		}
		if _, err := ledger.RetireRoom(fusedRoom, at, retention, skew); err == nil {
			t.Fatalf("crash %d: the crash did not stop retirement", crashAt)
		}
		beforeRoomRetireStep = nil
		journal, ledger = reopenFused(t, journal, root)
		left := storedPartCount(t, journal)
		if crashAt == roomRetirePartsLater && left != 1 {
			t.Fatalf("crash after the later parts: %d parts left, want part 0 alone", left)
		}
		if crashAt == roomRetirePartsFirst && left != 0 {
			t.Fatalf("crash after part 0: %d parts left", left)
		}
		if _, found, err := journal.readRoomMLS(fusedRoom); err != nil || !found {
			t.Fatalf("crash %d: the fused record went with parts pending: %v %v", crashAt, found, err)
		}
		if retired, err := ledger.RetireEndedRooms(at, retention, skew); err != nil || len(retired) != 1 {
			t.Fatalf("crash %d: retirement after the restart: %v %v", crashAt, retired, err)
		}
		if left := storedPartCount(t, journal); left != 0 {
			t.Fatalf("crash %d: %d parts survived retirement", crashAt, left)
		}
		_ = journal.Close()
	}
	// A part 0 naming the room that is stored while retirement runs keeps
	// the fused record.
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	parts, _ := held(t, journal, ledger, fixture, 1)
	late, _ := splitRoomFrames(t, fusedRoom, 2)
	at, err := RoomRetireAt(record, retention, skew)
	if err != nil {
		t.Fatal(err)
	}
	beforeRoomRetireStep = func(n int) error {
		if n == roomRetirePartsFirst {
			_, err := parts.Add(sender, late[0], fixture.now)
			return err
		}
		return nil
	}
	defer func() { beforeRoomRetireStep = nil }()
	if _, err := ledger.RetireRoom(fusedRoom, at, retention, skew); err == nil {
		t.Fatal("retirement finished with a part 0 of the room stored")
	}
	if _, found, err := journal.readRoomMLS(fusedRoom); err != nil || !found {
		t.Fatalf("the fused record went with a part 0 remaining: %v %v", found, err)
	}
}

// splitRoomFrames cuts a Commit of a room at the smallest test part size.
func splitRoomFrames(t *testing.T, roomID string, seed byte) ([]relayframe.Frame, []byte) {
	t.Helper()
	object, err := relayframe.EncodeRoomObject(relayframe.RoomObject{Type: relayframe.RoomCommit, RoomID: roomID,
		RoomEpoch: 1, MLSEpoch: 2, Body: bytes.Repeat([]byte{seed}, 4_000)})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := relayframe.SplitRoomObject(object, []byte("card"), []byte("evidence"), 1_024)
	if err != nil {
		t.Fatal(err)
	}
	frames := make([]relayframe.Frame, len(encoded))
	for index, raw := range encoded {
		if frames[index], err = relayframe.Decode(raw); err != nil {
			t.Fatal(err)
		}
	}
	return frames, object
}
