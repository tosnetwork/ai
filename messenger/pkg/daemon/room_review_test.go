package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

// storedParts counts a receiver's stored room parts.
func storedParts(t *testing.T, node *relayNode) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(node.d.config.StateDir, "room-parts"))
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// treeLeaves lists a receiver's MLS tree of the test room.
func treeLeaves(t *testing.T, node *relayNode) int {
	t.Helper()
	leaves, err := node.d.relay.rooms.controller.Members(testRoomID)
	if err != nil {
		t.Fatal(err)
	}
	return len(leaves)
}

// removeCommit is the authority's Commit removing a member, made and kept.
func removeCommit(t *testing.T, scene *joinedScene, who roomMember) []byte {
	t.Helper()
	membership, err := scene.authority.record.Membership().Remove([]string{who.agent()})
	if err != nil {
		t.Fatal(err)
	}
	template := group.Transition{Prior: scene.authority.record.Binding(), Membership: membership,
		Next: group.State{RoomID: testRoomID, Clock: group.Clock{RoomEpoch: membership.Epoch, MLSEpoch: scene.authority.record.MLSEpoch + 1},
			MembershipDigest: membership.Digest}}
	proof := scene.authority.proof(membership)
	result, record, err := scene.authority.controller.Commit(template, &proof,
		[]group.LeafOperation{{Kind: group.LeafRemove, Prior: &who.leaf}},
		func(result eventlog.CommitResult) ([]eventlog.StagedRoomObject, error) {
			clock := result.Transition.Next.Clock
			return []eventlog.StagedRoomObject{{Type: eventlog.RoomObjectCommit, RoomEpoch: clock.RoomEpoch, MLSEpoch: clock.MLSEpoch,
				Object: result.Commit, Recipients: []eventlog.RoomRecipient{{AgentID: who.agent(), Once: true}}}}, nil
		}, scene.clock.now().Add(roomRetention))
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	scene.authority.record = record
	return scene.authority.commitObject(result, membership)
}

// A header-less Commit (an MLS-only refresh by its header) whose MLS content
// adds a leaf is refused: the tree must stay exactly the signed membership,
// one leaf per Agent, or a hidden member would survive later Commits.
func TestRoomHeaderlessCommitAddingALeafIsRefused(t *testing.T) {
	for name, joiner := range map[string]func(*joinedScene) roomMember{
		"a non-member's leaf": func(scene *joinedScene) roomMember { return scene.member(t, 3, 50*time.Minute) },
		"a second leaf of a member": func(scene *joinedScene) roomMember {
			return newRoomMember(t, scene.driver, scene.nodes[2], scene.start, scene.start.Add(50*time.Minute))
		},
	} {
		t.Run(name, func(t *testing.T) {
			scene := newJoinedScene(t, roomRetention)
			b := scene.nodes[1]
			before, _ := fused(t, b)
			state, err := scene.authority.ledger.State(scene.authority.record)
			if err != nil {
				t.Fatal(err)
			}
			leaf := joiner(scene).leaf
			_, body, _, err := scene.driver.Commit(state, []group.LeafOperation{{Kind: group.LeafAdd, Next: &leaf}})
			if err != nil {
				t.Fatal(err)
			}
			record := scene.authority.record
			object := scene.authority.object(relayframe.RoomCommit, record.RoomEpoch, record.MLSEpoch+1, nil, body)
			requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, object, 0)), fault.CodeNotAuthentic)
			requireUnmoved(t, b, before)
			if leaves := treeLeaves(t, b); leaves != len(before.Members) {
				t.Fatalf("the tree holds %d leaves for %d members", leaves, len(before.Members))
			}
		})
	}
}

// A Welcome whose tree holds a leaf its header does not name is refused
// before anything is installed.
func TestRoomWelcomeIntoATreeWiderThanItsHeaderIsRefused(t *testing.T) {
	scene := newRoomScene(t, 3, roomRetention, 0)
	a := scene.member(t, 0, 40*time.Minute)
	b := scene.member(t, 1, 50*time.Minute)
	d := scene.member(t, 2, 50*time.Minute)
	authority := newTestAuthority(t, scene.driver, a, scene.clock)
	receiver := scene.nodes[1]
	invite(t, b, a, scene.start)
	withB, err := authority.record.Membership().Add([]string{b.agent()})
	if err != nil {
		t.Fatal(err)
	}
	state, err := authority.ledger.State(authority.record)
	if err != nil {
		t.Fatal(err)
	}
	bLeaf, dLeaf := b.leaf, d.leaf
	_, _, welcomes, err := scene.driver.Commit(state, []group.LeafOperation{{Kind: group.LeafAdd, Next: &bLeaf}, {Kind: group.LeafAdd, Next: &dLeaf}})
	if err != nil {
		t.Fatal(err)
	}
	object := authority.object(relayframe.RoomWelcome, withB.Epoch, authority.record.MLSEpoch+1, authority.header(withB), welcomes[b.leaf.KeyPackageRef])
	requireStatelessRejection(t, receiver, send(t, receiver, a.agent(), framesOf(t, a, object, 0)), fault.CodeNotAuthentic)
	if _, found := fused(t, receiver); found {
		t.Fatal("a Welcome into a wider tree installed the room")
	}
}

// A verified header is authenticated before its epoch is judged: a removal
// Commit behind a missed membership Commit is a removal notice (no answer),
// and a genuine membership Commit behind one is an epoch gap.
func TestRoomLaterEpochHeadersAreJudgedAfterTheyVerify(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	before, _ := fused(t, b)
	d := scene.member(t, 3, 50*time.Minute)
	scene.authority.commit(d) // not delivered to B
	removal := removeCommit(t, scene, scene.b)
	if response := send(t, b, scene.a.agent(), framesOf(t, scene.a, removal, 0)); response.Result != carrierapi.ResultIgnored {
		t.Fatalf("a removal two room epochs ahead: %s/%s", response.Result, response.Code)
	}
	requireUnmoved(t, b, before)

	other := newJoinedScene(t, roomRetention)
	receiver := other.nodes[1]
	otherBefore, _ := fused(t, receiver)
	other.authority.commit(other.member(t, 3, 50*time.Minute))
	gap := removeCommit(t, other, other.c)
	requireRejected(t, receiver, send(t, receiver, other.a.agent(), framesOf(t, other.a, gap, 0)), fault.CodeRoomEpochGap)
	requireUnmoved(t, receiver, otherBefore)
}

// A header-less Commit naming another room epoch than the member's is
// refused: an MLS-only refresh keeps the room epoch.
func TestRoomHeaderlessCommitMovingTheRoomEpochIsRefused(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	before, _ := fused(t, b)
	result, _ := scene.authority.commit()
	clock := result.Transition.Next.Clock
	object := scene.authority.object(relayframe.RoomCommit, clock.RoomEpoch+1, clock.MLSEpoch, nil, result.Commit)
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, object, 0)), fault.CodeNotAuthentic)
	requireUnmoved(t, b, before)
}

// A Commit older than every retained epoch is dropped silently and
// relay-acknowledged.
func TestRoomStaleCommitIsDroppedSilently(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	before, _ := fused(t, b)
	object := scene.authority.object(relayframe.RoomCommit, before.RoomEpoch, 0, nil, []byte("an old Commit"))
	if response := send(t, b, scene.a.agent(), framesOf(t, scene.a, object, 0)); response.Result != carrierapi.ResultIgnored {
		t.Fatalf("a stale Commit: %s/%s", response.Result, response.Code)
	}
	requireUnmoved(t, b, before)
}

// Another member's part 0 of a handshake object is refused not-authentic at
// intake, before any part of it is stored.
func TestRoomHandshakePartFromANonAuthorityIsRefusedAtIntake(t *testing.T) {
	partBytes := 4 * relayframe.MinTestPartBytes
	scene := newJoinedSceneCut(t, roomRetention, partBytes)
	b := scene.nodes[1]
	record := scene.authority.record
	object := scene.authority.object(relayframe.RoomCommit, record.RoomEpoch, record.MLSEpoch+1, nil, make([]byte, 3*partBytes))
	frames := framesOf(t, scene.c, object, partBytes)
	stored := storedParts(t, b)
	requireRejected(t, b, b.d.relay.Deliver(context.Background(), scene.c.agent(), frames[0]), fault.CodeNotAuthentic)
	if storedParts(t, b) != stored {
		t.Fatal("a non-authority's handshake part was stored")
	}
}

// A later part from a sender no room holds parts from is refused before the
// part store writes anything: with the store unwritable, it is still
// answered not-admitted, not retried.
func TestRoomLaterPartFromAnOutsiderWritesNothing(t *testing.T) {
	scene := newRoomScene(t, 3, roomRetention, relayframe.MinTestPartBytes)
	a := scene.member(t, 0, 40*time.Minute)
	b := scene.member(t, 1, 50*time.Minute)
	stranger := scene.member(t, 2, 50*time.Minute)
	authority := newTestAuthority(t, scene.driver, a, scene.clock)
	receiver := scene.nodes[1]
	invite(t, b, a, scene.start)
	addB, withB := authority.commit(b)
	frames := framesOf(t, stranger, authority.welcomeObject(addB, withB, b), relayframe.MinTestPartBytes)
	dir := filepath.Join(receiver.d.config.StateDir, "room-parts")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	response := receiver.d.relay.Deliver(context.Background(), stranger.agent(), frames[1])
	if response.Result != carrierapi.ResultRefused || response.Code != carrierapi.CodeNotAdmitted {
		t.Fatalf("an outsider's part 1: %s/%s", response.Result, response.Code)
	}
}

// Stored parts of an object past its lifetime are deleted by the running
// daemon's sweep, and so are a complete object's left unsettled that long.
func TestRoomPartSweepDeletesExpiredAndUnsettledParts(t *testing.T) {
	scene := newRoomScene(t, 3, roomRetention, relayframe.MinTestPartBytes)
	a := scene.member(t, 0, 40*time.Minute)
	b := scene.member(t, 1, 50*time.Minute)
	authority := newTestAuthority(t, scene.driver, a, scene.clock)
	receiver := scene.nodes[1]
	invite(t, b, a, scene.start)
	addB, withB := authority.commit(b)
	frames := framesOf(t, a, authority.welcomeObject(addB, withB, b), relayframe.MinTestPartBytes)
	if response := send(t, receiver, a.agent(), frames[:1]); response.Result != carrierapi.ResultAdmitted {
		t.Fatalf("part 0: %s/%s", response.Result, response.Code)
	}
	// A second object completes in the part store but is never settled.
	other := authority.object(relayframe.RoomWelcome, withB.Epoch, 77, authority.header(withB), make([]byte, 2*relayframe.MinTestPartBytes))
	for _, raw := range framesOf(t, a, other, relayframe.MinTestPartBytes) {
		frame, err := relayframe.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := receiver.d.relay.rooms.parts.Add(a.agent(), frame, scene.clock.now()); err != nil {
			t.Fatal(err)
		}
	}
	if storedParts(t, receiver) < 2 {
		t.Fatal("no parts were stored")
	}
	scene.clock.set(scene.start.Add(24*time.Hour + 4*time.Minute))
	receiver.d.relay.rooms.sweepParts()
	if storedParts(t, receiver) == 0 {
		t.Fatal("parts were swept before their lifetime")
	}
	scene.clock.set(scene.start.Add(25 * time.Hour))
	receiver.d.relay.rooms.sweepParts()
	if n := storedParts(t, receiver); n != 0 {
		t.Fatalf("%d stored parts outlived their lifetime", n)
	}
}

// A complete object stored but unsettled at a crash is handled at start, and
// its redelivery is then a duplicate.
func TestRoomPartsCompletedBeforeACrashAreHandledAtStart(t *testing.T) {
	scene := newRoomScene(t, 3, roomRetention, relayframe.MinTestPartBytes)
	a := scene.member(t, 0, 40*time.Minute)
	b := scene.member(t, 1, 50*time.Minute)
	authority := newTestAuthority(t, scene.driver, a, scene.clock)
	receiver := scene.nodes[1]
	invite(t, b, a, scene.start)
	addB, withB := authority.commit(b)
	frames := framesOf(t, a, authority.welcomeObject(addB, withB, b), relayframe.MinTestPartBytes)
	send(t, receiver, a.agent(), frames[:len(frames)-1])
	last, err := relayframe.Decode(frames[len(frames)-1])
	if err != nil {
		t.Fatal(err)
	}
	// The last part is stored and the process stops before handling it.
	if result, err := receiver.d.relay.rooms.parts.Add(a.agent(), last, scene.clock.now()); err != nil || result.Status != relayframe.PartComplete {
		t.Fatalf("last part: %v %v", result.Status, err)
	}
	if _, found := fused(t, receiver); found {
		t.Fatal("joined before the restart")
	}
	if err := receiver.d.installRoomRuntime(roomRuntimeSettings{driver: scene.driver, cards: scene.cards[1], skew: 5 * time.Minute,
		retention: roomRetention, partBytes: relayframe.MinTestPartBytes}); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if _, found := fused(t, receiver); !found {
		t.Fatal("the Welcome completed before the crash was not installed at start")
	}
	if ack := roomAckOf(t, receiver, send(t, receiver, a.agent(), frames)); ack.Outcome != relayframe.OutcomeDuplicate {
		t.Fatalf("the redelivery: %+v", ack)
	}
	if n := storedParts(t, receiver); n != 0 {
		t.Fatalf("%d parts left after the replayed object settled", n)
	}
}

// Part 0's evidence is checked again at completion: the sender's device
// revoked between part 0 and the last part refuses the object.
func TestRoomEvidenceIsCheckedAgainAtCompletion(t *testing.T) {
	scene := newRoomScene(t, 3, roomRetention, relayframe.MinTestPartBytes)
	a := scene.member(t, 0, 40*time.Minute)
	b := scene.member(t, 1, 50*time.Minute)
	authority := newTestAuthority(t, scene.driver, a, scene.clock)
	receiver := scene.nodes[1]
	invite(t, b, a, scene.start)
	addB, withB := authority.commit(b)
	frames := framesOf(t, a, authority.welcomeObject(addB, withB, b), relayframe.MinTestPartBytes)
	send(t, receiver, a.agent(), frames[:1])
	devices := receiver.d.discovery.devices
	_, original, _ := evidenceSet(t, a.evidence)
	if _, err := devices.AcceptSet(a.delegation.EndpointID, original, scene.start); err != nil {
		t.Fatal(err)
	}
	_, successor, _ := evidenceSet(t, evidenceFor(t, a.node, "dev_"+strings.Repeat("e", 64),
		uint64(scene.start.Add(time.Minute).Unix()), uint64(scene.start.Add(40*time.Minute).Unix())))
	if _, err := devices.AcceptSet(a.delegation.EndpointID, successor, scene.start.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	scene.clock.set(scene.start.Add(2 * time.Minute))
	var response carrierapi.Response
	for _, frame := range frames[1:] {
		response = receiver.d.relay.Deliver(context.Background(), a.agent(), frame)
	}
	if response.Result != carrierapi.ResultRefused || response.Code != carrierapi.CodeEvidenceRefused {
		t.Fatalf("the completed Welcome after the device was revoked: %s/%s", response.Result, response.Code)
	}
	if _, found := fused(t, receiver); found {
		t.Fatal("a Welcome whose sender's device was revoked was installed")
	}
}

// A permanent refusal of the credential store answers the roster rejected
// not-authentic, signed; a failed read or write is retried.
func TestRoomRosterLearnRefusalsArePermanentOrRetried(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	in := roomInbound{ctx: context.Background(), sender: scene.a.agent(),
		object: relayframe.RoomObject{Type: relayframe.RoomRoster, RoomID: testRoomID},
		digest: relayframe.ObjectDigest(scene.added), now: scene.clock.now()}
	for _, permanent := range []error{eventlog.ErrRoomAuthorityCredential, eventlog.ErrRoomCredentialEndsEarly,
		eventlog.ErrRoomCredentialMember, eventlog.ErrRoomCredentialUnverified} {
		requireRejected(t, b, b.d.relay.rooms.rosterLearnRefusal(in, permanent), fault.CodeNotAuthentic)
	}
	if response := b.d.relay.rooms.rosterLearnRefusal(in, errors.New("write a credential record")); response.Result != carrierapi.ResultRetry {
		t.Fatalf("a failed write: %s", response.Result)
	}
}

// flakyResolver fails finalized reads of one Agent.
type flakyResolver struct {
	inner   identity.AgentResolver
	failing string
}

func (r flakyResolver) ResolveAgent(agentID string) (*nativev1.NativeStateV1, bool, error) {
	if agentID == r.failing {
		return nil, false, errors.New("finalized state is unavailable")
	}
	return r.inner.ResolveAgent(agentID)
}

// A finalized-state read that fails for a roster member retries the roster;
// it does not skip the member.
func TestRoomRosterRetriesWhenAMembersAuthorityCannotBeRead(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	verifier := b.d.relay.verifier
	resolver := verifier.Resolver
	verifier.Resolver = flakyResolver{inner: resolver, failing: scene.c.agent()}
	if response := send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.added, 0)); response.Result != carrierapi.ResultRetry {
		t.Fatalf("a roster whose member's authority cannot be read: %s/%s", response.Result, response.Code)
	}
	if _, found := credentialOf(t, b, scene.c.agent()); found {
		t.Fatal("a credential was learned without its authority")
	}
	verifier.Resolver = resolver
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.added, 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the redelivered roster: %+v", ack)
	}
	if _, found := credentialOf(t, b, scene.c.agent()); !found {
		t.Fatal("the redelivered roster taught nothing")
	}
}

// Part 0's evidence is checked before any part is stored: a split object's
// part 0 under another Agent's evidence stores nothing.
func TestRoomPartZeroEvidenceIsCheckedBeforeStoring(t *testing.T) {
	scene := newRoomScene(t, 3, roomRetention, relayframe.MinTestPartBytes)
	a := scene.member(t, 0, 40*time.Minute)
	b := scene.member(t, 1, 50*time.Minute)
	c := scene.member(t, 2, 50*time.Minute)
	authority := newTestAuthority(t, scene.driver, a, scene.clock)
	receiver := scene.nodes[1]
	invite(t, b, a, scene.start)
	addB, withB := authority.commit(b)
	frames := framesOf(t, c, authority.welcomeObject(addB, withB, b), relayframe.MinTestPartBytes)
	response := receiver.d.relay.Deliver(context.Background(), a.agent(), frames[0])
	if response.Result != carrierapi.ResultRefused || response.Code != carrierapi.CodeEvidenceRefused {
		t.Fatalf("part 0 under another Agent's evidence: %s/%s", response.Result, response.Code)
	}
	if n := storedParts(t, receiver); n != 0 {
		t.Fatalf("%d parts stored under failing evidence", n)
	}
}

// Only the authority commits or sends rosters, whatever the rest of the
// object says: a Commit C's own leaf made, under C's evidence, and a roster
// whose header C itself authorized are refused and change nothing.
func TestRoomHandshakeObjectsOfAnotherMemberAreRefusedWhole(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	before, _ := fused(t, b)
	state, err := scene.driver.Join(scene.c.identity.State, scene.addC.Welcomes[scene.c.leaf.KeyPackageRef])
	if err != nil {
		t.Fatal(err)
	}
	_, commit, _, err := scene.driver.Commit(state, nil)
	if err != nil {
		t.Fatal(err)
	}
	own := scene.authority.object(relayframe.RoomCommit, before.RoomEpoch, before.MLSEpoch+1, nil, commit)
	requireRejected(t, b, send(t, b, scene.c.agent(), framesOf(t, scene.c, own, 0)), fault.CodeNotAuthentic)
	requireUnmoved(t, b, before)

	impostor := &testAuthority{t: t, member: scene.c, clock: scene.clock}
	membership := scene.authority.record.Membership()
	body, err := relayframe.EncodeRoster([]relayframe.RosterEntry{rosterEntry(t, scene.c)})
	if err != nil {
		t.Fatal(err)
	}
	header := &relayframe.RoomHeader{Membership: membership, Authorization: impostor.authorization(membership, scene.clock.now()),
		EndsAtUnix: before.RoomEndsAtUnix}
	roster := scene.authority.object(relayframe.RoomRoster, membership.Epoch, before.MLSEpoch, header, body)
	requireRejected(t, b, send(t, b, scene.c.agent(), framesOf(t, scene.c, roster, 0)), fault.CodeNotAuthentic)
	if _, found := credentialOf(t, b, scene.c.agent()); found {
		t.Fatal("a roster from a member taught a credential")
	}
}
