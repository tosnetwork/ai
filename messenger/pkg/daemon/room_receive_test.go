package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

const roomRetention = 7 * 24 * time.Hour

// joinedScene is a room A made, B joined through its Welcome and full
// roster, and C was added to: B holds the room at room epoch 3, MLS epoch 2.
type joinedScene struct {
	*roomScene
	authority *testAuthority
	a, b, c   roomMember
	addC      eventlog.CommitResult
	// added is the roster of added members B accepted for room epoch 3.
	added []byte
	// partBytes is the test part size handshake objects are cut at.
	partBytes int
}

func newJoinedScene(t *testing.T, retention time.Duration) *joinedScene {
	t.Helper()
	return newJoinedSceneCut(t, retention, 0)
}

// newJoinedSceneCut is newJoinedScene with every handshake object cut at a
// test part size.
func newJoinedSceneCut(t *testing.T, retention time.Duration, partBytes int) *joinedScene {
	t.Helper()
	scene := newAddedSceneCut(t, retention, partBytes)
	if ack := roomAckOf(t, scene.nodes[1], send(t, scene.nodes[1], scene.a.agent(), framesOf(t, scene.a, scene.added, partBytes))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("B's roster of added members: %+v", ack)
	}
	return scene
}

// newAddedScene stops where B has applied the Add of C and not yet received
// the roster of added members, which the scene holds.
func newAddedScene(t *testing.T, retention time.Duration) *joinedScene {
	t.Helper()
	return newAddedSceneCut(t, retention, 0)
}

func newAddedSceneCut(t *testing.T, retention time.Duration, partBytes int) *joinedScene {
	t.Helper()
	scene := newRoomScene(t, 4, retention, partBytes)
	a := scene.member(t, 0, 40*time.Minute)
	b := scene.member(t, 1, 50*time.Minute)
	c := scene.member(t, 2, 50*time.Minute)
	authority := newTestAuthority(t, scene.driver, a, scene.clock)
	receiver := scene.nodes[1]
	invite(t, b, a, scene.start)
	addB, withB := authority.commit(b)
	ack := roomAckOf(t, receiver, send(t, receiver, a.agent(), framesOf(t, a, authority.welcomeObject(addB, withB, b), partBytes)))
	if ack.Outcome != relayframe.OutcomeAccepted || ack.MLSEpoch != addB.Transition.Next.Clock.MLSEpoch {
		t.Fatalf("B's Welcome: %+v", ack)
	}
	roster := authority.rosterObject(withB, rosterEntry(t, a))
	if ack := roomAckOf(t, receiver, send(t, receiver, a.agent(), framesOf(t, a, roster, partBytes))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("B's full roster: %+v", ack)
	}
	addC, withC := authority.commit(c)
	if ack := roomAckOf(t, receiver, send(t, receiver, a.agent(), framesOf(t, a, authority.commitObject(addC, withC), partBytes))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("B applies the Add of C: %+v", ack)
	}
	added := authority.rosterObject(withC, rosterEntry(t, c))
	return &joinedScene{roomScene: scene, authority: authority, a: a, b: b, c: c, addC: addC, added: added, partBytes: partBytes}
}

// requireRejected decodes a room ack and requires a rejection with code.
func requireRejected(t *testing.T, receiver *relayNode, response carrierapi.Response, code fault.Code) relayframe.RoomAck {
	t.Helper()
	ack := roomAckOf(t, receiver, response)
	if ack.Outcome != relayframe.OutcomeRejected || ack.Code != code {
		t.Fatalf("answered %s/%s, want rejected/%s", ack.Outcome, ack.Code, code)
	}
	return ack
}

// requireUnmoved requires the receiver's room to be exactly as before.
func requireUnmoved(t *testing.T, receiver *relayNode, before eventlog.RoomMLSRecord) {
	t.Helper()
	after, _ := fused(t, receiver)
	if after.StateDigest != before.StateDigest || after.MLSEpoch != before.MLSEpoch || after.RoomEpoch != before.RoomEpoch ||
		after.CredentialListDigest != before.CredentialListDigest {
		t.Fatal("a refused object changed the room")
	}
}

func TestRoomReceiverJoinsAppliesAndLearnsInOrder(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	record, found := fused(t, b)
	if !found || record.RoomEpoch != 3 || record.MLSEpoch != 2 || record.RoomEndsAtUnix != scene.a.credential.ExpiresAtUnix {
		t.Fatalf("B's room: %+v", record)
	}
	ledger, _ := b.d.journal.OpenRoomMLS()
	for _, member := range []roomMember{scene.a, scene.c} {
		credential, found, err := ledger.RoomCredential(testRoomID, member.agent())
		if err != nil || !found || !credential.LeafSignaturePublicKey.Equal(member.credential.LeafSignaturePublicKey) {
			t.Fatalf("B's credential of %s: %v %v", member.agent(), found, err)
		}
	}
	if _, found, err := b.d.journal.AcceptedRoomJoin(testRoomID, scene.clock.now()); err != nil || found {
		t.Fatalf("the pending join outlived its Welcome: %v %v", found, err)
	}
	// The rosters taught A's and C's cards and evidence.
	if admitted := scene.cards[1].of(testRoomID); len(admitted) != 2 {
		t.Fatalf("room cards admitted: %v", admitted)
	}
	// Every admission names the fused record's room end, so the carrier
	// drops it on its own once the room is over (D18).
	ends := scene.cards[1].endsOf(testRoomID)
	if len(ends) == 0 {
		t.Fatal("no room-cards admission was made")
	}
	for _, end := range ends {
		if end != record.RoomEndsAtUnix {
			t.Fatalf("a room-cards admission named end %d, the room ends at %d", end, record.RoomEndsAtUnix)
		}
	}
	for _, member := range []roomMember{scene.a, scene.c} {
		if _, found, err := b.d.journal.LoadRelayEvidence(member.agent()); err != nil || !found {
			t.Fatalf("B committed no evidence of %s: %v", member.agent(), err)
		}
	}
	// An MLS-only refresh keeps the room epoch; its exact repeat is a
	// duplicate, signed again.
	result, membership := scene.authority.commit()
	refresh := scene.authority.commitObject(result, membership)
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, refresh, 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("an MLS-only refresh: %+v", ack)
	}
	ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, refresh, 0)))
	if ack.Outcome != relayframe.OutcomeDuplicate || ack.MLSEpoch != 3 || len(ack.EpochAuthenticator) == 0 {
		t.Fatalf("the exact repeat: %+v", ack)
	}
	if record, _ := fused(t, b); record.MLSEpoch != 3 || record.RoomEpoch != 3 {
		t.Fatalf("after the refresh: %+v", record)
	}
	// So is a redelivered roster.
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.added, 0))); ack.Outcome != relayframe.OutcomeDuplicate {
		t.Fatalf("a redelivered roster: %+v", ack)
	}
}

// A Welcome split at the test part size completes in any part order, and a
// part from anyone but the authority of the accepted join is never held.
func TestRoomReceiverReassemblesASplitWelcome(t *testing.T) {
	scene := newRoomScene(t, 3, roomRetention, relayframe.MinTestPartBytes)
	a := scene.member(t, 0, 40*time.Minute)
	b := scene.member(t, 1, 50*time.Minute)
	c := scene.member(t, 2, 50*time.Minute)
	authority := newTestAuthority(t, scene.driver, a, scene.clock)
	receiver := scene.nodes[1]
	invite(t, b, a, scene.start)
	addB, withB := authority.commit(b)
	frames := framesOf(t, a, authority.welcomeObject(addB, withB, b), relayframe.MinTestPartBytes)
	if len(frames) < 2 {
		t.Fatalf("the Welcome was not split: %d part", len(frames))
	}
	// C is no sender this room's join accepts.
	if response := send(t, receiver, c.agent(), framesOf(t, c, authority.welcomeObject(addB, withB, b), relayframe.MinTestPartBytes)[:1]); response.Code != carrierapi.CodeNotAdmitted {
		t.Fatalf("a stranger's part 0: %s/%s", response.Result, response.Code)
	}
	reversed := make([][]byte, 0, len(frames))
	for index := len(frames) - 1; index >= 0; index-- {
		reversed = append(reversed, frames[index])
	}
	if ack := roomAckOf(t, receiver, send(t, receiver, a.agent(), reversed)); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the reassembled Welcome: %+v", ack)
	}
	if record, found := fused(t, receiver); !found || record.RoomEpoch != withB.Epoch {
		t.Fatalf("B's room after a split Welcome: %+v", record)
	}
}

func TestRoomCommitFromAnotherMemberIsRefusedAndStoresNothing(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	before, _ := fused(t, b)
	result, membership := scene.authority.commit()
	object := scene.authority.commitObject(result, membership)
	// C sends A's Commit under its own evidence: only the authority commits
	// (section 11.5), so it is refused not-authentic.
	requireRejected(t, b, send(t, b, scene.c.agent(), framesOf(t, scene.c, object, 0)), fault.CodeNotAuthentic)
	requireUnmoved(t, b, before)
	// And rosters: only the authority sends them.
	roster := scene.authority.rosterObject(membership, rosterEntry(t, scene.c))
	requireRejected(t, b, send(t, b, scene.c.agent(), framesOf(t, scene.c, roster, 0)), fault.CodeNotAuthentic)
	// The authority's object under another Agent's evidence is refused at
	// part 0: the evidence is pinned to the sender's leaf credential.
	if response := send(t, b, scene.a.agent(), framesOf(t, scene.c, object, 0)); response.Code != carrierapi.CodeEvidenceRefused {
		t.Fatalf("A's Commit under C's evidence: %s/%s", response.Result, response.Code)
	}
	requireUnmoved(t, b, before)
}

// The MLS committer must be the leaf A's verified credential binds: a
// Commit C's leaf made, delivered as A's, is refused before anything moves.
func TestRoomCommitByAnotherLeafIsRefused(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	before, _ := fused(t, b)
	welcome := scene.addC.Welcomes[scene.c.leaf.KeyPackageRef]
	state, err := scene.driver.Join(scene.c.identity.State, welcome)
	if err != nil {
		t.Fatal(err)
	}
	_, commit, _, err := scene.driver.Commit(state, nil)
	if err != nil {
		t.Fatal(err)
	}
	object := scene.authority.object(relayframe.RoomCommit, before.RoomEpoch, before.MLSEpoch+1, nil, commit)
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, object, 0)), fault.CodeNotAuthentic)
	requireUnmoved(t, b, before)
}

// The header authorization is checked in the relay window, issued - skew <=
// now < issued + retention + skew, at both ends, before anything moves.
func TestRoomCommitAuthorizationOutsideTheRelayWindowIsRefused(t *testing.T) {
	retention := 10 * time.Minute
	scene := newJoinedScene(t, retention)
	b := scene.nodes[1]
	d := newRoomMember(t, scene.driver, scene.nodes[3], scene.start, scene.start.Add(50*time.Minute))
	before, _ := fused(t, b)
	result, membership := scene.authority.commit(d)
	late := scene.authority.commitObject(result, membership)
	scene.clock.set(scene.start.Add(retention + 5*time.Minute))
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, late, 0)), fault.CodeNotAuthentic)
	requireUnmoved(t, b, before)
	// The same Commit under an authorization issued more than the skew
	// after now is refused too; at issued - skew it applies.
	scene.clock.set(scene.start.Add(30 * time.Minute))
	early := scene.authority.commitObject(result, membership)
	scene.clock.set(scene.start.Add(25*time.Minute - time.Second))
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, early, 0)), fault.CodeNotAuthentic)
	requireUnmoved(t, b, before)
	scene.clock.set(scene.start.Add(25 * time.Minute))
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, early, 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("a Commit at issued - skew: %+v", ack)
	}
}

// A header naming another end than the room's is refused not-authentic:
// the end is outside the authorization's signature (D18).
func TestRoomCommitHeaderNamingAnotherEndIsRefused(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	d := newRoomMember(t, scene.driver, scene.nodes[3], scene.start, scene.start.Add(50*time.Minute))
	before, _ := fused(t, b)
	result, membership := scene.authority.commit(d)
	header := scene.authority.header(membership)
	header.EndsAtUnix++
	clock := result.Transition.Next.Clock
	object := scene.authority.object(relayframe.RoomCommit, clock.RoomEpoch, clock.MLSEpoch, header, result.Commit)
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, object, 0)), fault.CodeNotAuthentic)
	requireUnmoved(t, b, before)
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.authority.commitObject(result, membership), 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the Commit with the room's end: %+v", ack)
	}
}

// A second, different Commit for an applied MLS epoch is a fork with an
// owner notice; a Commit above current + 1 is an epoch gap.
func TestRoomCommitForkAndGapAreAnswered(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	reports := &recordingReports{}
	b.d.observer = reports
	prior, err := scene.authority.ledger.State(scene.authority.record)
	if err != nil {
		t.Fatal(err)
	}
	result, membership := scene.authority.commit()
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.authority.commitObject(result, membership), 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the refresh: %+v", ack)
	}
	_, other, _, err := scene.driver.Commit(prior, nil)
	if err != nil {
		t.Fatal(err)
	}
	clock := result.Transition.Next.Clock
	fork := scene.authority.object(relayframe.RoomCommit, clock.RoomEpoch, clock.MLSEpoch, nil, other)
	before, _ := fused(t, b)
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, fork, 0)), fault.CodeRoomFork)
	requireUnmoved(t, b, before)
	if reports.count(func(err error) bool { return err != nil }) == 0 {
		t.Fatal("a fork raised no owner notice")
	}
	scene.authority.commit()
	ahead, aheadMembership := scene.authority.commit()
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.authority.commitObject(ahead, aheadMembership), 0)), fault.CodeRoomEpochGap)
	requireUnmoved(t, b, before)
}

// A Commit whose verified header removes this member is not applied to MLS
// and is answered with nothing (section 11.4).
func TestRoomCommitRemovingThisMemberIsNotApplied(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	before, _ := fused(t, b)
	membership, err := scene.authority.record.Membership().Remove([]string{scene.b.agent()})
	if err != nil {
		t.Fatal(err)
	}
	template := group.Transition{Prior: scene.authority.record.Binding(), Membership: membership,
		Next: group.State{RoomID: testRoomID, Clock: group.Clock{RoomEpoch: membership.Epoch, MLSEpoch: scene.authority.record.MLSEpoch + 1},
			MembershipDigest: membership.Digest}}
	proof := scene.authority.proof(membership)
	result, record, err := scene.authority.controller.Commit(template, &proof,
		[]group.LeafOperation{{Kind: group.LeafRemove, Prior: &scene.b.leaf}},
		func(result eventlog.CommitResult) ([]eventlog.StagedRoomObject, error) {
			clock := result.Transition.Next.Clock
			return []eventlog.StagedRoomObject{{Type: eventlog.RoomObjectCommit, RoomEpoch: clock.RoomEpoch, MLSEpoch: clock.MLSEpoch,
				Object: result.Commit, Recipients: []eventlog.RoomRecipient{{AgentID: scene.b.agent(), Once: true}}}}, nil
		}, scene.clock.now().Add(roomRetention))
	if err != nil {
		t.Fatalf("remove B: %v", err)
	}
	scene.authority.record = record
	response := send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.authority.commitObject(result, membership), 0))
	if response.Result != carrierapi.ResultIgnored {
		t.Fatalf("B's removal Commit: %s/%s", response.Result, response.Code)
	}
	requireUnmoved(t, b, before)
}

func TestRoomEndRefusesHandshakesWithOneNotice(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	reports := &recordingReports{}
	b.d.observer = reports
	result, membership := scene.authority.commit()
	object := scene.authority.commitObject(result, membership)
	before, _ := fused(t, b)
	end := time.Unix(int64(scene.a.credential.ExpiresAtUnix), 0)
	scene.clock.set(end.Add(5 * time.Minute))
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, object, 0)), fault.CodeRoomEnded)
	roster := scene.authority.rosterObject(scene.authority.record.Membership(), rosterEntry(t, scene.c))
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, roster, 0)), fault.CodeRoomEnded)
	if notices := reports.count(func(err error) bool { return errors.Is(err, ErrRoomEnded) }); notices != 1 {
		t.Fatalf("%d room-ended notices, want 1", notices)
	}
	requireUnmoved(t, b, before)
	// Before the end the same Commit still applies. (Between the end and
	// end + skew the authority's credential has expired, so nothing of it
	// verifies; senders stop at end - skew.)
	scene.clock.set(end.Add(-time.Second))
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, object, 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("a Commit just before the end: %+v", ack)
	}
}
