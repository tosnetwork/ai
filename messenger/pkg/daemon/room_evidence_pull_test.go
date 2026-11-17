package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// The kind-4 pull of room objects (sections 2.5 and 11.2): a room object
// waiting on a member's stored evidence keeps the member's single evidence
// request outstanding, as a pending 1:1 copy does. The request is
// deposited, the member's response restores the evidence, and the object
// then goes out.

// staleEvidenceAt replaces what a node holds of a peer's evidence with
// expired evidence issued before the peer's own current descriptor, so the
// peer's response is newer and repairs it.
func staleEvidenceAt(t *testing.T, scene *operatorScene, local, peer *relayNode) {
	t.Helper()
	stored, found, err := local.d.journal.LoadRelayEvidence(peer.d.config.AgentID)
	if err != nil || !found {
		t.Fatalf("no stored evidence of the peer: %v", err)
	}
	now := scene.clock.now()
	expired := evidenceFor(t, peer, peer.d.config.DeviceID, uint64(scene.start.Add(-55*time.Second).Unix()),
		uint64(now.Add(-10*time.Second).Unix()))
	if err := local.d.journal.StoreRelayEvidence(peer.d.config.AgentID, expired, canon.Digest(stored), now); err != nil {
		t.Fatal(err)
	}
}

// evidenceRequests takes the kind-4 requests a node deposited to a peer and
// drops every other frame its carrier holds.
func evidenceRequests(t *testing.T, node *relayNode, peer string) []carried {
	t.Helper()
	return evidenceRequestsIn(t, node.carrier.take(), peer)
}

// evidenceRequestsIn selects the kind-4 requests to a peer among frames.
func evidenceRequestsIn(t *testing.T, frames []carried, peer string) []carried {
	t.Helper()
	var requests []carried
	for _, frame := range framesOfKind(t, frames, relayframe.KindEvidence) {
		decoded, err := relayframe.Decode(frame.frame)
		if err != nil {
			t.Fatal(err)
		}
		if frame.recipient == peer && decoded.Part[0] == relayframe.EvidenceRequest {
			requests = append(requests, frame)
		}
	}
	return requests
}

// pullRequested reports whether a node holds its request to a peer
// outstanding.
func pullRequested(t *testing.T, node *relayNode, peer string) bool {
	t.Helper()
	pull, _, err := node.d.journal.LoadRelayPull(peer)
	if err != nil {
		t.Fatal(err)
	}
	return pull.Requested
}

// requireOneRequest runs a node's pull sweep twice and requires exactly one
// kind-4 request to the peer, still outstanding.
func requireOneRequest(t *testing.T, node, peer *relayNode) carried {
	t.Helper()
	node.carrier.take()
	node.d.relay.sweepPulls(context.Background())
	node.d.relay.sweepPulls(context.Background())
	requests := evidenceRequests(t, node, peer.d.config.AgentID)
	if len(requests) != 1 {
		t.Fatalf("%d evidence requests to the member whose evidence fails, want 1", len(requests))
	}
	if !pullRequested(t, node, peer.d.config.AgentID) {
		t.Fatal("the request was ended while a room object waits on the member's evidence")
	}
	return requests[0]
}

// answerPull hands a request to the peer, its response back, and requires
// the request to end.
func answerPull(t *testing.T, node, peer *relayNode, request carried) {
	t.Helper()
	if admitted := deliver(t, node, peer, request.frame); admitted.Result != carrierapi.ResultAdmitted {
		t.Fatalf("the member's answer to the request: %s/%s", admitted.Result, admitted.Code)
	}
	peer.carrier.take()
	peer.d.relay.sweepPulls(context.Background())
	responses := framesOfKind(t, peer.carrier.take(), relayframe.KindEvidence)
	if len(responses) != 1 {
		t.Fatalf("%d evidence responses", len(responses))
	}
	if admitted := deliver(t, peer, node, responses[0].frame); admitted.Result != carrierapi.ResultAdmitted {
		t.Fatalf("the response: %s/%s", admitted.Result, admitted.Code)
	}
	if pullRequested(t, node, peer.d.config.AgentID) {
		t.Fatal("the request outlived its response")
	}
}

// An application object pending on a member's evidence starts the pull, and
// is deposited and opened once the response restored the evidence.
func TestRoomEvidencePullRunsForAPendingApplicationObject(t *testing.T) {
	scene := twoMemberRoom(t)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	staleEvidenceAt(t, scene, a, b)
	eventID, _, err := scene.compose(t, 0, "waits on the evidence", "2")
	if err != nil {
		t.Fatal(err)
	}
	if frames := roomFrames(t, a, agent); len(frames) != 0 {
		t.Fatalf("a member whose evidence fails got %d frames", len(frames))
	}
	request := requireOneRequest(t, a, b)
	answerPull(t, a, b, request)
	scene.clock.set(scene.clock.now().Add(relayEvidenceRetry))
	scene.rooms(0).maintain()
	frames := roomFrames(t, a, agent)
	if len(frames) != 1 {
		t.Fatalf("the repaired member got %d frames", len(frames))
	}
	if delivery := applicationMember(t, a, idem("2"), agent); delivery.State != eventlog.RoomDeliveryCarried {
		t.Fatalf("B's delivery after the repair: %+v", delivery)
	}
	if answer := deliver(t, a, b, frames[0].frame); answer.Result != carrierapi.ResultAdmitted {
		t.Fatalf("B refused the repaired object: %s/%s", answer.Result, answer.Code)
	}
	if _, found, err := b.d.journal.Lookup(eventID); err != nil || !found {
		t.Fatalf("B did not open the message: %v", err)
	}
	// Nothing waits any more: no further request.
	a.d.relay.sweepPulls(context.Background())
	if requests := evidenceRequests(t, a, agent); len(requests) != 0 {
		t.Fatalf("%d requests after the object went out", len(requests))
	}
}

// A request whose member's evidence checks again before it is deposited, the
// object still pending, ends without a kind-4 frame: no request goes to a
// peer no object waits for.
func TestRoomEvidencePullEndsOnceTheMembersEvidenceChecksAgain(t *testing.T) {
	scene := twoMemberRoom(t)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	good, _, err := a.d.journal.LoadRelayEvidence(agent)
	if err != nil {
		t.Fatal(err)
	}
	staleEvidenceAt(t, scene, a, b)
	if _, _, err := scene.compose(t, 0, "waits on the evidence", "3"); err != nil {
		t.Fatal(err)
	}
	if !pullRequested(t, a, agent) {
		t.Fatal("the evidence pull did not start")
	}
	stale, _, err := a.d.journal.LoadRelayEvidence(agent)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.d.journal.StoreRelayEvidence(agent, good, canon.Digest(stale), scene.clock.now()); err != nil {
		t.Fatal(err)
	}
	if delivery := applicationMember(t, a, idem("3"), agent); delivery.State != eventlog.RoomDeliveryPending {
		t.Fatalf("B's delivery: %+v", delivery)
	}
	a.carrier.take()
	a.d.relay.sweepPulls(context.Background())
	if requests := evidenceRequests(t, a, agent); len(requests) != 0 {
		t.Fatalf("%d requests although the member's evidence checks", len(requests))
	}
	if pullRequested(t, a, agent) {
		t.Fatal("the request stayed outstanding although nothing waits on the evidence")
	}
}

// The head of a member's handshake queue waiting for its first deposit
// starts the pull, and goes out once the response restored the evidence.
func TestRoomEvidencePullRunsForAPendingHandshakeHead(t *testing.T) {
	scene := newFanoutScene(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	welcome := objectsTo(t, a, agent)
	if len(welcome) != 1 {
		t.Fatalf("%d objects in flight to B", len(welcome))
	}
	answer := handOver(t, a, b, welcome[0])
	// The Welcome is acknowledged after B's evidence went stale: the
	// roster, next in B's queue, waits on it.
	staleEvidenceAt(t, scene, a, b)
	if applied := ackBack(t, a, b, answer); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("the Welcome's ack: %+v", applied)
	}
	if roster, _ := memberDelivery(t, a, eventlog.RoomObjectRoster, agent); roster.State != eventlog.RoomDeliveryPending {
		t.Fatalf("B's roster: %+v", roster)
	}
	if objects := objectsTo(t, a, agent); len(objects) != 0 {
		t.Fatalf("a member whose evidence fails got %d objects", len(objects))
	}
	request := requireOneRequest(t, a, b)
	answerPull(t, a, b, request)
	scene.rooms(0).maintain()
	rosters := objectsTo(t, a, agent)
	if len(rosters) != 1 {
		t.Fatalf("the repaired member got %d objects", len(rosters))
	}
	if applied := ackBack(t, a, b, handOver(t, a, b, rosters[0])); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("the roster's ack: %+v", applied)
	}
}

// The head of a member's queue due for its re-deposit starts the pull too;
// one carried and not yet due does not.
func TestRoomEvidencePullRunsForAHandshakeHeadDueForItsRedeposit(t *testing.T) {
	scene := newFanoutScene(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	objectsTo(t, a, agent)
	welcome, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent)
	scene.clock.set(time.Unix(int64(welcome.NextRedepositAtUnix), 0).Add(-time.Second))
	staleEvidenceAt(t, scene, a, b)
	// Opened by hand while the head is carried and not due: nothing waits.
	if err := a.d.relay.requestEvidence(agent, scene.clock.now()); err != nil {
		t.Fatal(err)
	}
	a.carrier.take()
	a.d.relay.sweepPulls(context.Background())
	if requests := evidenceRequests(t, a, agent); len(requests) != 0 || pullRequested(t, a, agent) {
		t.Fatalf("%d requests for a head that is not due", len(requests))
	}
	scene.clock.set(time.Unix(int64(welcome.NextRedepositAtUnix), 0))
	scene.rooms(0).maintain()
	if objects := objectsTo(t, a, agent); len(objects) != 0 {
		t.Fatalf("a member whose evidence fails got %d objects", len(objects))
	}
	request := requireOneRequest(t, a, b)
	answerPull(t, a, b, request)
	scene.rooms(0).maintain()
	again := objectsTo(t, a, agent)
	if len(again) != 1 {
		t.Fatalf("the repaired member got %d objects", len(again))
	}
	if delivery, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent); delivery.Generation != 2 {
		t.Fatalf("the Welcome after the repair: %+v", delivery)
	}
}

// A removed member's single Commit waiting on the member's evidence starts
// the pull as well.
func TestRoomEvidencePullRunsForARemovedMembersCommit(t *testing.T) {
	scene := newFanoutScene(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	objectsTo(t, a, agent)
	staleEvidenceAt(t, scene, a, b)
	if err := scene.rooms(0).RemoveRoomMember(context.Background(), testRoomID, agent); err != nil {
		t.Fatal(err)
	}
	if commits := roomObjectFrames(t, a, agent, relayframe.RoomCommit); len(commits) != 0 {
		t.Fatalf("the removing Commit went to a member whose evidence fails: %d frames", len(commits))
	}
	request := requireOneRequest(t, a, b)
	answerPull(t, a, b, request)
	scene.rooms(0).maintain()
	if commits := roomObjectFrames(t, a, agent, relayframe.RoomCommit); len(commits) == 0 {
		t.Fatal("the removing Commit was not deposited after the repair")
	}
}

// A stopped queue deposits nothing more, so its head waits on no evidence:
// the request ends.
func TestRoomEvidencePullEndsForAStoppedQueue(t *testing.T) {
	scene := newFanoutScene(t, 2, roomRetention)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	answer := handOver(t, a, b, objectsTo(t, a, agent)[0])
	staleEvidenceAt(t, scene, a, b)
	if applied := ackBack(t, a, b, answer); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("the Welcome's ack: %+v", applied)
	}
	if !pullRequested(t, a, agent) {
		t.Fatal("the evidence pull did not start")
	}
	if err := a.d.journal.StopRoomMemberQueue(testRoomID, agent, fault.CodeRejected, scene.clock.now()); err != nil {
		t.Fatal(err)
	}
	a.carrier.take()
	a.d.relay.sweepPulls(context.Background())
	if requests := evidenceRequests(t, a, agent); len(requests) != 0 || pullRequested(t, a, agent) {
		t.Fatalf("%d requests for a stopped queue", len(requests))
	}
}

// When the member's evidence cannot be checked (finalized state is
// unavailable), whether an object waits is not known: the request is kept
// as it is, neither sent nor ended, and judged again later.
func TestRoomEvidencePullIsKeptWhileTheMembersEvidenceCannotBeChecked(t *testing.T) {
	scene := twoMemberRoom(t)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	good, _, err := a.d.journal.LoadRelayEvidence(agent)
	if err != nil {
		t.Fatal(err)
	}
	staleEvidenceAt(t, scene, a, b)
	if _, _, err := scene.compose(t, 0, "waits on the evidence", "4"); err != nil {
		t.Fatal(err)
	}
	stale, _, err := a.d.journal.LoadRelayEvidence(agent)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.d.journal.StoreRelayEvidence(agent, good, canon.Digest(stale), scene.clock.now()); err != nil {
		t.Fatal(err)
	}
	verifier := a.d.relay.verifier
	resolver := verifier.Resolver
	verifier.Resolver = flakyResolver{inner: resolver, failing: agent}
	a.carrier.take()
	a.d.relay.sweepPulls(context.Background())
	if requests := evidenceRequests(t, a, agent); len(requests) != 0 {
		t.Fatalf("%d requests while the evidence cannot be checked", len(requests))
	}
	if !pullRequested(t, a, agent) {
		t.Fatal("the request was ended while the evidence could not be checked")
	}
	verifier.Resolver = resolver
	a.d.relay.sweepPulls(context.Background())
	if pullRequested(t, a, agent) {
		t.Fatal("the request outlived the evidence's repair")
	}
}

// A node without private rooms still ends a request no copy waits for.
func TestRelayEvidencePullWithoutRoomsEndsWithoutACopy(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	agent := b.d.config.AgentID
	if err := a.d.relay.requestEvidence(agent, now); err != nil {
		t.Fatal(err)
	}
	a.d.relay.sweepPulls(context.Background())
	if requests := evidenceRequests(t, a, agent); len(requests) != 0 || pullRequested(t, a, agent) {
		t.Fatalf("%d requests without a pending copy", len(requests))
	}
}

// Only the member's own objects count: a request to B ends while the only
// pending object waits for C, even with B's evidence failing too.
func TestRoomEvidencePullCountsOnlyTheMembersOwnObjects(t *testing.T) {
	scene := newOperatorScene(t, 3)
	a, b, c := scene.nodes[0], scene.nodes[1], scene.nodes[2]
	scene.founded(t)
	for _, member := range []int{1, 2} {
		scene.invited(t, member)
		if answer := scene.joined(t, member); answer.AckOutcome != relayframe.OutcomeAccepted {
			t.Fatalf("node %d's room.key-package: %+v", member, answer)
		}
	}
	if record, _ := fused(t, a); len(record.Members) != 3 {
		t.Fatalf("the room holds %d members", len(record.Members))
	}
	staleEvidenceAt(t, scene, a, c)
	if _, _, err := scene.compose(t, 0, "waits for C only", "5"); err != nil {
		t.Fatal(err)
	}
	if delivery := applicationMember(t, a, idem("5"), b.d.config.AgentID); delivery.State != eventlog.RoomDeliveryCarried {
		t.Fatalf("B's delivery: %+v", delivery)
	}
	if delivery := applicationMember(t, a, idem("5"), c.d.config.AgentID); delivery.State != eventlog.RoomDeliveryPending {
		t.Fatalf("C's delivery: %+v", delivery)
	}
	staleEvidenceAt(t, scene, a, b)
	if err := a.d.relay.requestEvidence(b.d.config.AgentID, scene.clock.now()); err != nil {
		t.Fatal(err)
	}
	a.carrier.take()
	a.d.relay.sweepPulls(context.Background())
	frames := a.carrier.take()
	if requests := evidenceRequestsIn(t, frames, b.d.config.AgentID); len(requests) != 0 || pullRequested(t, a, b.d.config.AgentID) {
		t.Fatalf("%d requests to B, whose objects are all carried", len(requests))
	}
	if requests := evidenceRequestsIn(t, frames, c.d.config.AgentID); len(requests) != 1 {
		t.Fatalf("%d requests to C, whose object waits", len(requests))
	}
}

// A removed member's single Commit whose head's retention ended is never
// deposited again (its envelopes would carry an expiry in the past), so it
// does not keep the kind-4 pull to the removed member outstanding.
func TestRoomEvidencePullEndsForARemovedMembersCommitPastItsRetention(t *testing.T) {
	scene := newFanoutScene(t, 2, 2*time.Minute)
	a, b := scene.nodes[0], scene.nodes[1]
	agent := b.d.config.AgentID
	objectsTo(t, a, agent)
	staleEvidenceAt(t, scene, a, b)
	if err := scene.rooms(0).RemoveRoomMember(context.Background(), testRoomID, agent); err != nil {
		t.Fatal(err)
	}
	var latest uint64
	for _, head := range mustHeads(t, a) {
		if delivery, found := head.Member(agent); found && delivery.Once && head.RetainUntilUnix > latest {
			latest = head.RetainUntilUnix
		}
	}
	if latest == 0 {
		t.Fatal("no single Commit to the removed member")
	}
	record, _ := fused(t, a)
	past := time.Unix(int64(latest), 0).Add(time.Minute)
	if scene.rooms(0).sendingStopped(record.RoomEndsAtUnix, past) {
		t.Fatalf("the room's sending stops before the Commit's retention ends (end %d, past %d)", record.RoomEndsAtUnix, past.Unix())
	}
	// Before the retention ends the Commit waits; after it, nothing does.
	if waits, err := scene.rooms(0).waitsOnEvidence(agent, scene.clock.now()); err != nil || !waits {
		t.Fatalf("the removed member's Commit inside its retention: waits=%v %v", waits, err)
	}
	scene.clock.set(past)
	if waits, err := scene.rooms(0).waitsOnEvidence(agent, scene.clock.now()); err != nil || waits {
		t.Fatalf("a removed member's single Commit past its retention keeps the pull outstanding: waits=%v %v", waits, err)
	}
}
