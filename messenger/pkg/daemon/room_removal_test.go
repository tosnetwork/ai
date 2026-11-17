package daemon

import (
	"context"
	"errors"
	"fmt"
	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/messenger/pkg/room"
)

// A verified Commit removing this member marks the room removed with one
// owner notice; from then on the room's handshake objects are not taken.
func TestRoomRemovalNoticeMarksTheRoomAndStopsHandshakes(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	reports := &recordingReports{}
	b.d.observer = reports
	before, _ := fused(t, b)
	removal := removeCommit(t, scene, scene.b)
	for range 2 {
		if response := send(t, b, scene.a.agent(), framesOf(t, scene.a, removal, 0)); response.Result != carrierapi.ResultIgnored {
			t.Fatalf("the removal Commit: %s/%s", response.Result, response.Code)
		}
	}
	marker, removed, err := b.d.journal.RoomRemovalOf(testRoomID)
	if err != nil || !removed || marker.RoomEpoch != before.RoomEpoch+1 || marker.MemberMLSEpoch != before.MLSEpoch {
		t.Fatalf("the removal marker: %+v %v %v", marker, removed, err)
	}
	if n := reports.count(func(err error) bool { return errors.Is(err, ErrRoomRemoved) }); n != 1 {
		t.Fatalf("%d removal notices, want 1", n)
	}
	requireUnmoved(t, b, before)
	// A later handshake object of the room is not taken.
	roster := scene.authority.rosterObject(scene.authority.record.Membership(), rosterEntry(t, scene.c))
	if response := send(t, b, scene.a.agent(), framesOf(t, scene.a, roster, 0)); response.Result != carrierapi.ResultIgnored {
		t.Fatalf("a roster after the removal: %s/%s", response.Result, response.Code)
	}
	requireUnmoved(t, b, before)
}

// An authentic header of an epoch the member already passed that omits it
// is not a removal notice: it is refused not-authentic and marks nothing.
func TestRoomOldHeaderOmittingThisMemberIsNotARemovalNotice(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	before, _ := fused(t, b)
	founding, err := room.Found(testRoomID, []string{scene.a.agent()})
	if err != nil {
		t.Fatal(err)
	}
	result, _ := scene.authority.commit()
	object := scene.authority.object(relayframe.RoomCommit, founding.Epoch, result.Transition.Next.Clock.MLSEpoch,
		scene.authority.header(founding), result.Commit)
	requireRejected(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, object, 0)), fault.CodeNotAuthentic)
	if _, removed, err := b.d.journal.RoomRemovalOf(testRoomID); err != nil || removed {
		t.Fatalf("an old header marked the room removed: %v %v", removed, err)
	}
	requireUnmoved(t, b, before)
}

// When the authority removes another member, the receiver forgets it: the
// room's admission of its card, its sequence record, and its incomplete
// parts once no room takes parts from it; its credential left with the
// fused write.
func TestRoomReceiverForgetsAMemberTheAuthorityRemoved(t *testing.T) {
	partBytes := 4 * relayframe.MinTestPartBytes
	scene := newJoinedSceneCut(t, roomRetention, partBytes)
	b := scene.nodes[1]
	now := scene.clock.now()
	if err := b.d.journal.ObserveRoomSequence(testRoomID, scene.c.agent(), 2, now); err != nil {
		t.Fatal(err)
	}
	record := scene.authority.record
	pending := scene.authority.object(relayframe.RoomCommit, record.RoomEpoch, record.MLSEpoch+1, nil, make([]byte, 3*partBytes))
	if response := b.d.relay.Deliver(context.Background(), scene.c.agent(), framesOf(t, scene.c, pending, partBytes)[1]); response.Result != carrierapi.ResultAdmitted {
		t.Fatalf("C's stored part: %s/%s", response.Result, response.Code)
	}
	if storedParts(t, b) != 1 {
		t.Fatal("C's part was not stored")
	}
	removal := removeCommit(t, scene, scene.c)
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, removal, partBytes))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the removal of C: %+v", ack)
	}
	if forgotten := scene.cards[1].forgottenIn(testRoomID); len(forgotten) != 1 || forgotten[0] != scene.c.agent() {
		t.Fatalf("forgotten cards: %v", forgotten)
	}
	if gone, err := b.d.journal.ForgetRoomSender(testRoomID, scene.c.agent()); err != nil || gone {
		t.Fatalf("C's sequence record outlived its removal: %v %v", gone, err)
	}
	if n := storedParts(t, b); n != 0 {
		t.Fatalf("%d of C's parts outlived its removal", n)
	}
	if _, found := credentialOf(t, b, scene.c.agent()); found {
		t.Fatal("C's credential outlived its removal")
	}
}

// The runtime retires a room past end + retention + skew, on its timer and
// at start, with its parts dropped from memory first.
func TestRoomEndedRoomsAreRetiredByTheRuntime(t *testing.T) {
	retention := 10 * time.Minute
	partBytes := 4 * relayframe.MinTestPartBytes
	for _, start := range []bool{false, true} {
		scene := newJoinedSceneCut(t, retention, partBytes)
		b := scene.nodes[1]
		record := scene.authority.record
		pending := scene.authority.object(relayframe.RoomCommit, record.RoomEpoch, record.MLSEpoch+1, nil, make([]byte, 3*partBytes))
		if response := b.d.relay.Deliver(context.Background(), scene.a.agent(), framesOf(t, scene.a, pending, partBytes)[0]); response.Result != carrierapi.ResultAdmitted {
			t.Fatalf("the authority's stored part: %s/%s", response.Result, response.Code)
		}
		end := time.Unix(int64(scene.a.credential.ExpiresAtUnix), 0)
		scene.clock.set(end.Add(retention + 5*time.Minute - time.Second))
		b.d.relay.rooms.maintain()
		if _, found := fused(t, b); !found {
			t.Fatal("a room was retired before its time")
		}
		scene.clock.set(end.Add(retention + 5*time.Minute))
		if start {
			if err := b.d.installRoomRuntime(roomRuntimeSettings{driver: scene.driver, cards: scene.cards[1], skew: 5 * time.Minute,
				retention: retention, partBytes: partBytes}); err != nil {
				t.Fatalf("restart: %v", err)
			}
		} else {
			b.d.relay.rooms.maintain()
		}
		if _, found := fused(t, b); found {
			t.Fatalf("the ended room was not retired (at start %v)", start)
		}
		if n := storedParts(t, b); n != 0 {
			t.Fatalf("%d parts of the retired room are left (at start %v)", n, start)
		}
		if usage := b.d.relay.rooms.parts.Usage(); usage.Objects != 0 {
			t.Fatalf("%d objects of the retired room are left in memory (at start %v)", usage.Objects, start)
		}
	}
}

// A device-ledger read that fails for a roster entry retries the roster:
// it does not skip the entry.
func TestRoomRosterRetriesWhenTheDeviceLedgerCannotBeRead(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	path := filepath.Join(b.d.config.StateDir, "devices", scene.c.delegation.EndpointID[len("mep_"):]+".json")
	if err := os.WriteFile(path, []byte("not a device record"), 0o600); err != nil {
		t.Fatal(err)
	}
	if response := send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.added, 0)); response.Result != carrierapi.ResultRetry {
		t.Fatalf("a roster whose member's device standing cannot be read: %s/%s", response.Result, response.Code)
	}
	if _, found := credentialOf(t, b, scene.c.agent()); found {
		t.Fatal("a credential was learned without its device standing")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.added, 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the redelivered roster: %+v", ack)
	}
}

// applyWithoutForgetting applies the authority's Commit through the
// controller alone: the fused write happens, the forgetting after it does
// not, as a crash between them leaves it.
func applyWithoutForgetting(t *testing.T, scene *joinedScene, raw []byte) {
	t.Helper()
	b := scene.nodes[1]
	r := b.d.relay.rooms
	object, err := relayframe.DecodeRoomObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	now := scene.clock.now()
	peer, err := r.checkSenderEvidence(testRoomID, scene.a.agent(), scene.a.evidence, now)
	if err != nil {
		t.Fatal(err)
	}
	in := roomInbound{ctx: context.Background(), sender: scene.a.agent(), peer: peer, object: object, raw: raw,
		digest: relayframe.ObjectDigest(raw), now: now}
	record, _, err := r.ledger.Current(testRoomID)
	if err != nil {
		t.Fatal(err)
	}
	committer, err := r.authorityBinding(record, in)
	if err != nil {
		t.Fatal(err)
	}
	proof, membership, code := r.commitHeader(record, in)
	if code != "" {
		t.Fatal(code)
	}
	commitRef := canon.Digest(object.Body)
	transition := group.Transition{Prior: record.Binding(),
		Next: group.State{RoomID: testRoomID, Clock: group.Clock{RoomEpoch: object.RoomEpoch, MLSEpoch: object.MLSEpoch},
			MembershipDigest: membership.Digest, AcceptedCommitRef: commitRef},
		Membership: membership, CommitRef: commitRef}
	if err := b.d.journal.BeginRoomHandshake(testRoomID, object.MLSEpoch, in.objectDigest(), commitRef); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.controller.Apply(transition, proof, object.Body, committer); err != nil {
		t.Fatal(err)
	}
}

// A removed member is forgotten even when the step after the fused write
// did not run: a crash between them is repaired at start, and a carrier
// that failed the forget is repaired by the timer's reconciliation.
func TestRoomRemovedMemberIsForgottenAfterACrashOrACarrierFailure(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	applyWithoutForgetting(t, scene, removeCommit(t, scene, scene.c))
	if forgotten := scene.cards[1].forgottenIn(testRoomID); len(forgotten) != 0 {
		t.Fatalf("forgotten before the restart: %v", forgotten)
	}
	if err := b.d.installRoomRuntime(roomRuntimeSettings{driver: scene.driver, cards: scene.cards[1], skew: 5 * time.Minute,
		retention: roomRetention}); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if forgotten := scene.cards[1].forgottenIn(testRoomID); !containsAgent(forgotten, scene.c.agent()) {
		t.Fatalf("C was not forgotten at start: %v", forgotten)
	}

	other := newJoinedScene(t, roomRetention)
	receiver := other.nodes[1]
	other.cards[1].failForgets = 1
	if ack := roomAckOf(t, receiver, send(t, receiver, other.a.agent(), framesOf(t, other.a, removeCommit(t, other, other.c), 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the removal of C: %+v", ack)
	}
	if forgotten := other.cards[1].forgottenIn(testRoomID); len(forgotten) != 0 {
		t.Fatalf("a failed forget was recorded: %v", forgotten)
	}
	receiver.d.relay.rooms.maintain()
	if forgotten := other.cards[1].forgottenIn(testRoomID); !containsAgent(forgotten, other.c.agent()) {
		t.Fatalf("the timer did not repair the failed forget: %v", forgotten)
	}
}

// The removal marker is judged under the handling lock: an object whose
// part 0 was taken before the room was marked removed, completed after, is
// not applied.
func TestRoomRemovalIsJudgedUnderTheHandlingLock(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	r := b.d.relay.rooms
	refresh, membership := scene.authority.commit()
	refreshRaw := scene.authority.commitObject(refresh, membership)
	if response := send(t, b, scene.a.agent(), framesOf(t, scene.a, removeCommit(t, scene, scene.b), 0)); response.Result != carrierapi.ResultIgnored {
		t.Fatalf("the removal: %s/%s", response.Result, response.Code)
	}
	before, _ := fused(t, b)
	digest := relayframe.ObjectDigest(refreshRaw)
	response, settle := r.handleComplete(context.Background(), scene.a.agent(), digest,
		relayframe.PartResult{Status: relayframe.PartComplete, RoomID: testRoomID, ObjectType: relayframe.RoomCommit,
			Evidence: scene.a.evidence, Object: refreshRaw}, scene.clock.now())
	if response.Result != carrierapi.ResultIgnored || !settle {
		t.Fatalf("a Commit completed after the removal: %s/%s", response.Result, response.Code)
	}
	requireUnmoved(t, b, before)
}

// A removed member who is still a sender of another room held or joined
// here keeps its parts; only this room's admission of its card is dropped.
func TestRoomRemovalKeepsAMemberSharedWithAnotherRoom(t *testing.T) {
	partBytes := 4 * relayframe.MinTestPartBytes
	scene := newJoinedSceneCut(t, roomRetention, partBytes)
	b := scene.nodes[1]
	now := scene.clock.now()
	otherRoom := "room_" + strings.Repeat("6", 64)
	joiner := newRoomMember(t, scene.driver, b, scene.start, scene.start.Add(50*time.Minute))
	if _, err := b.d.journal.RecordRoomInvite(otherRoom, scene.c.agent(), "evt_"+strings.Repeat("8", 64), scene.c.binding,
		now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := b.d.journal.BeginRoomJoin(otherRoom, scene.c.agent(), joiner.identity.State, joiner.deviceJSON, now); err != nil {
		t.Fatal(err)
	}
	record := scene.authority.record
	pending := scene.authority.object(relayframe.RoomCommit, record.RoomEpoch, record.MLSEpoch+1, nil, make([]byte, 3*partBytes))
	if response := b.d.relay.Deliver(context.Background(), scene.c.agent(), framesOf(t, scene.c, pending, partBytes)[1]); response.Result != carrierapi.ResultAdmitted {
		t.Fatalf("C's stored part: %s/%s", response.Result, response.Code)
	}
	removal := removeCommit(t, scene, scene.c)
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, removal, partBytes))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the removal of C: %+v", ack)
	}
	if storedParts(t, b) != 1 {
		t.Fatal("the parts of a member shared with another room were dropped")
	}
	if forgotten := scene.cards[1].forgottenIn(otherRoom); len(forgotten) != 0 {
		t.Fatalf("the other room's card admission was forgotten: %v", forgotten)
	}
	if forgotten := scene.cards[1].forgottenIn(testRoomID); !containsAgent(forgotten, scene.c.agent()) {
		t.Fatalf("this room's card admission was kept: %v", forgotten)
	}
}

// Reconciliation forgets only former members: a current member's card
// admission, sequence record and parts are left alone, and a forget already
// sent is not sent again on later ticks.
func TestRoomReconciliationLeavesCurrentMembersAlone(t *testing.T) {
	partBytes := 4 * relayframe.MinTestPartBytes
	scene := newJoinedSceneCut(t, roomRetention, partBytes)
	b := scene.nodes[1]
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, removeCommit(t, scene, scene.c), partBytes))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the removal of C: %+v", ack)
	}
	if err := b.d.journal.ObserveRoomSequence(testRoomID, scene.a.agent(), 2, scene.clock.now()); err != nil {
		t.Fatal(err)
	}
	record := scene.authority.record
	pending := scene.authority.object(relayframe.RoomCommit, record.RoomEpoch, record.MLSEpoch+1, nil, make([]byte, 3*partBytes))
	if response := b.d.relay.Deliver(context.Background(), scene.a.agent(), framesOf(t, scene.a, pending, partBytes)[1]); response.Result != carrierapi.ResultAdmitted {
		t.Fatalf("A's stored part: %s/%s", response.Result, response.Code)
	}
	for range 2 {
		b.d.relay.rooms.maintain()
	}
	if forgotten := scene.cards[1].forgottenIn(testRoomID); len(forgotten) != 1 || forgotten[0] != scene.c.agent() {
		t.Fatalf("forgotten card admissions: %v", forgotten)
	}
	if storedParts(t, b) != 1 {
		t.Fatal("a current member's part was dropped")
	}
	if kept, err := b.d.journal.ForgetRoomSender(testRoomID, scene.a.agent()); err != nil || !kept {
		t.Fatalf("a current member's sequence record was deleted: %v %v", kept, err)
	}
}

// A member removed two room epochs back is still forgotten from the
// journal alone, after a crash left its forgetting undone.
func TestRoomMemberRemovedTwoEpochsBackIsForgotten(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	applyWithoutForgetting(t, scene, removeCommit(t, scene, scene.c))
	d := scene.member(t, 3, 50*time.Minute)
	result, membership := scene.authority.commit(d)
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.authority.commitObject(result, membership), 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the Add of D: %+v", ack)
	}
	if forgotten := scene.cards[1].forgottenIn(testRoomID); len(forgotten) != 0 {
		t.Fatalf("forgotten before the restart: %v", forgotten)
	}
	if err := b.d.installRoomRuntime(roomRuntimeSettings{driver: scene.driver, cards: scene.cards[1], skew: 5 * time.Minute,
		retention: roomRetention}); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if forgotten := scene.cards[1].forgottenIn(testRoomID); len(forgotten) != 1 || forgotten[0] != scene.c.agent() {
		t.Fatalf("C, removed two room epochs back, was not forgotten: %v", forgotten)
	}
}

// Retirement drops the room's admission of every member's card; a carrier
// that fails does not hold the retirement back and is retried.
func TestRoomRetirementDropsTheRoomsCardAdmissions(t *testing.T) {
	retention := 10 * time.Minute
	scene := newJoinedScene(t, retention)
	b := scene.nodes[1]
	scene.cards[1].failForgets = 1
	end := time.Unix(int64(scene.a.credential.ExpiresAtUnix), 0)
	scene.clock.set(end.Add(retention + 5*time.Minute))
	b.d.relay.rooms.maintain()
	if _, found := fused(t, b); found {
		t.Fatal("a failing carrier held the retirement back")
	}
	if forgotten := scene.cards[1].forgottenIn(testRoomID); len(forgotten) != 0 {
		t.Fatalf("forgotten while the carrier failed: %v", forgotten)
	}
	b.d.relay.rooms.maintain()
	forgotten := scene.cards[1].forgottenIn(testRoomID)
	if len(forgotten) != 2 || !containsAgent(forgotten, scene.a.agent()) || !containsAgent(forgotten, scene.c.agent()) {
		t.Fatalf("the retired room's card admissions: %v", forgotten)
	}
}

// The timer's reconciliation repairs a forgetting that never ran, without
// a restart.
func TestRoomTimerReconcilesARemovalWhoseForgettingNeverRan(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	applyWithoutForgetting(t, scene, removeCommit(t, scene, scene.c))
	b.d.relay.rooms.maintain()
	if forgotten := scene.cards[1].forgottenIn(testRoomID); len(forgotten) != 1 || forgotten[0] != scene.c.agent() {
		t.Fatalf("the timer did not forget C: %v", forgotten)
	}
}

// A room's pending forgets larger than one carrier.room-cards request are
// sent in batches of MaxRoomCards; a failed batch stays pending and is sent
// again, while the others settle.
func TestRoomCardForgetsAreSentInBatches(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	r := scene.nodes[1].d.relay.rooms
	agents := make([]string, 40)
	for index := range agents {
		agents[index] = fmt.Sprintf("agent_%064x", index+1)
	}
	r.queueCardForgets(testRoomID, agents)
	scene.cards[1].failForgets = 1
	r.flushCardForgets(context.Background())
	if n := len(scene.cards[1].forgottenIn(testRoomID)); n != len(agents)-carrierapi.MaxRoomCards {
		t.Fatalf("%d forgotten after the first flush, want %d", n, len(agents)-carrierapi.MaxRoomCards)
	}
	r.flushCardForgets(context.Background())
	forgotten := scene.cards[1].forgottenIn(testRoomID)
	if len(forgotten) != len(agents) {
		t.Fatalf("%d forgotten after the retry, want %d", len(forgotten), len(agents))
	}
	r.flushCardForgets(context.Background())
	if n := len(scene.cards[1].forgottenIn(testRoomID)); n != len(agents) {
		t.Fatalf("a settled batch was sent again: %d", n)
	}
}
