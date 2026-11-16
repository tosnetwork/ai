package eventlog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
)

// addWithOutput makes the authority's Add Commit of one member, publishing a
// Commit to the existing members, a Welcome and a full roster to the joiner
// and a roster of the added member to the others.
func addWithOutput(t *testing.T, fixture *fusedFixture, ledger *RoomMLSLedger, current RoomMLSRecord, joiner string, label string) (RoomMLSRecord, map[RoomObjectType][]byte) {
	t.Helper()
	ref := canon.Digest([]byte(label))
	transition, membership := addTransition(t, current, []string{joiner}, ref)
	proof := fixture.proof(membership)
	var others []RoomRecipient
	for _, member := range current.Members {
		if member != fixture.delegation.AgentID {
			others = append(others, RoomRecipient{AgentID: member})
		}
	}
	objects := map[RoomObjectType][]byte{
		RoomObjectCommit:  []byte(label + " commit"),
		RoomObjectWelcome: []byte(label + " welcome"),
		RoomObjectRoster:  []byte(label + " full roster"),
	}
	staged := []StagedRoomObject{
		{Type: RoomObjectWelcome, RoomEpoch: membership.Epoch, MLSEpoch: transition.Next.Clock.MLSEpoch, Object: objects[RoomObjectWelcome], Recipients: []RoomRecipient{{AgentID: joiner}}},
		{Type: RoomObjectRoster, RoomEpoch: membership.Epoch, MLSEpoch: transition.Next.Clock.MLSEpoch, Object: objects[RoomObjectRoster], Recipients: []RoomRecipient{{AgentID: joiner}}},
	}
	if len(others) > 0 {
		staged = append(staged,
			StagedRoomObject{Type: RoomObjectCommit, RoomEpoch: membership.Epoch, MLSEpoch: transition.Next.Clock.MLSEpoch, Object: objects[RoomObjectCommit], Recipients: others},
			StagedRoomObject{Type: RoomObjectRoster, RoomEpoch: membership.Epoch, MLSEpoch: transition.Next.Clock.MLSEpoch, Object: []byte(label + " added roster"), Recipients: others},
		)
	}
	_, next, err := ledger.Advance(RoomMLSAdvance{
		Transition: transition, Proof: &proof, ExpectedStateDigest: current.StateDigest,
		State: []byte(label + " state"), EpochAuthenticator: fusedAuthenticator(byte(transition.Next.Clock.MLSEpoch + 1)),
		Output: &RoomCommitOutput{Objects: staged, RetainUntil: fixture.now.Add(7 * 24 * time.Hour)},
	}, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	return next, objects
}

func TestRoomOutboxPublishesWithTheAdvanceAndQueuesInEpochOrder(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	bob, carol := fusedAgent(1), fusedAgent(2)
	record, first := addWithOutput(t, fixture, ledger, record, bob, "add bob")
	_, _ = addWithOutput(t, fixture, ledger, record, carol, "add carol")

	// Bob: the Welcome and full roster of epoch 1, then the Add-Carol Commit
	// and the roster of the added member, each Commit or Welcome before its
	// roster.
	queue, err := journal.RoomMemberQueue(fusedRoom, bob)
	if err != nil {
		t.Fatal(err)
	}
	want := []RoomObjectType{RoomObjectWelcome, RoomObjectRoster, RoomObjectCommit, RoomObjectRoster}
	if len(queue) != len(want) {
		t.Fatalf("Bob's queue has %d objects", len(queue))
	}
	for index, head := range queue {
		if head.Type != want[index] {
			t.Fatalf("Bob's queue position %d is type %d, want %d", index, head.Type, want[index])
		}
	}
	welcome, err := journal.RoomOutboxObject(queue[0].ObjectDigest)
	if err != nil || !bytes.Equal(welcome, first[RoomObjectWelcome]) {
		t.Fatalf("Welcome bytes: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	// The queue is rebuilt identically after a restart.
	journal, _ = openFused(t, root)
	defer journal.Close()
	rebuilt, err := journal.RoomMemberQueue(fusedRoom, bob)
	if err != nil || len(rebuilt) != len(queue) {
		t.Fatalf("rebuilt queue: %v", err)
	}
	for index := range rebuilt {
		if rebuilt[index].ObjectDigest != queue[index].ObjectDigest {
			t.Fatal("restart reordered Bob's queue")
		}
	}

	// Carried, then acked: delivered settles the member and retires a head
	// whose every member is settled.
	evidence := canon.Digest([]byte("evidence"))
	head := queue[0]
	if _, err := journal.RoomOutboxAcked(head.ObjectDigest, bob, RoomAckAccepted, "", fixture.now); err == nil {
		t.Fatal("an ack for an object never carried was applied")
	}
	if _, err := journal.RoomOutboxCarried(head.ObjectDigest, bob, 2, evidence, fixture.now.Add(time.Hour), fixture.now); err == nil {
		t.Fatal("a generation that skips ahead was recorded")
	}
	if _, err := journal.RoomOutboxCarried(head.ObjectDigest, bob, 1, evidence, fixture.now.Add(time.Hour), fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.RoomOutboxCarried(head.ObjectDigest, bob, 1, evidence, fixture.now.Add(time.Hour), fixture.now); err != nil {
		t.Fatalf("a repeated generation after a crash: %v", err)
	}
	if _, err := journal.RoomOutboxAcked(head.ObjectDigest, bob, RoomAckDuplicate, "", fixture.now); err != nil {
		t.Fatal(err)
	}
	// The head is retired once its only member settled; a repeated ack then
	// finds no object to settle.
	if _, err := journal.RoomOutboxAcked(head.ObjectDigest, bob, RoomAckDuplicate, "", fixture.now); !errors.Is(err, ErrUnknown) {
		t.Fatalf("a repeated ack after retirement: %v", err)
	}
	if _, err := os.Stat(filepath.Join(journal.root, roomOutboxDir, head.ObjectDigest+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a settled object kept its head")
	}
	// A rejected ack settles the member with the ack's code.
	roster := rebuilt[1]
	if _, err := journal.RoomOutboxCarried(roster.ObjectDigest, bob, 1, evidence, fixture.now.Add(time.Hour), fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.RoomOutboxAcked(roster.ObjectDigest, bob, RoomAckRejected, "", fixture.now); err == nil {
		t.Fatal("a rejected ack without a code was applied")
	}
	if _, err := journal.RoomOutboxAcked(roster.ObjectDigest, bob, RoomAckRejected, fault.CodeNotAuthentic, fixture.now); err != nil {
		t.Fatal(err)
	}
	after, err := journal.RoomMemberQueue(fusedRoom, bob)
	if err != nil || len(after) != 2 || after[0].Type != RoomObjectCommit {
		t.Fatalf("queue after settling the first epoch: %d %v", len(after), err)
	}
	if _, err := journal.RoomOutboxAbandon(after[0].ObjectDigest, bob, fault.CodeRetentionExceeded, fixture.now); err != nil {
		t.Fatal(err)
	}
}

func TestRoomOutboxRemovedMemberGetsTheCommitOnceWithoutAck(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	ref := canon.Digest([]byte("refresh"))
	transition := refreshTransition(record, ref)
	removed := fusedAgent(9)
	_, _, err := ledger.Advance(RoomMLSAdvance{
		Transition: transition, ExpectedStateDigest: record.StateDigest, State: []byte("epoch one"), EpochAuthenticator: fusedAuthenticator(2),
		Output: &RoomCommitOutput{RetainUntil: fixture.now.Add(time.Hour), Objects: []StagedRoomObject{
			{Type: RoomObjectCommit, RoomEpoch: 1, MLSEpoch: 1, Object: []byte("commit"), Recipients: []RoomRecipient{{AgentID: removed, Once: true}, {AgentID: fusedAgent(1)}}},
		}},
	}, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if queue, err := journal.RoomMemberQueue(fusedRoom, removed); err != nil || len(queue) != 0 {
		t.Fatalf("a removed member has a queue: %d %v", len(queue), err)
	}
	digest := RoomObjectDigest([]byte("commit"))
	if _, err := journal.RoomOutboxCarried(digest, removed, 1, canon.Digest([]byte("e")), time.Time{}, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.RoomOutboxCarried(digest, removed, 2, canon.Digest([]byte("e")), time.Time{}, fixture.now); !errors.Is(err, ErrNotPending) {
		t.Fatalf("a second deposit to a removed member: %v", err)
	}
	if _, err := journal.RoomOutboxAcked(digest, removed, RoomAckAccepted, "", fixture.now); err == nil {
		t.Fatal("a removed member's ack was applied")
	}
	if _, err := journal.RoomOutboxCarried(digest, fusedAgent(1), 1, canon.Digest([]byte("e")), time.Time{}, fixture.now); err == nil {
		t.Fatal("a queued member's deposit without a re-deposit time was recorded")
	}
	// Only a Commit goes once to a removed member.
	if _, err := newRoomOutboxHead(fusedRoom, ref, StagedRoomObject{Type: RoomObjectRoster, RoomEpoch: 1, MLSEpoch: 1, Object: []byte("r"), Recipients: []RoomRecipient{{AgentID: removed, Once: true}}}, fixture.now.Add(time.Hour), fixture.now); err == nil {
		t.Fatal("a once-only roster was staged")
	}
	// Application objects never go through the Commit output.
	if _, err := newRoomOutboxHead(fusedRoom, ref, StagedRoomObject{Type: RoomObjectApplication, RoomEpoch: 1, MLSEpoch: 1, Object: []byte("a"), Recipients: []RoomRecipient{{AgentID: removed}}}, fixture.now.Add(time.Hour), fixture.now); err == nil {
		t.Fatal("an application object was staged with a Commit")
	}
}

// Crash between staging and the fused write: the staged output names a
// Commit no fused record accepted, so restart discards it and collects its
// chunks; nothing is published.
func TestRoomCrashBeforeFusedWriteDiscardsStagedOutput(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	ref := canon.Digest([]byte("never written"))
	journal.mutex.Lock()
	_, stageErr := journal.stageRoomOutput(fusedRoom, ref, []StagedRoomObject{
		{Type: RoomObjectCommit, RoomEpoch: 1, MLSEpoch: 1, Object: []byte("lost commit"), Recipients: []RoomRecipient{{AgentID: fusedAgent(1)}}},
	}, fixture.now.Add(time.Hour), fixture.now)
	stagedState, stateErr := journal.stageMLSState(fusedRoom, []byte("next state never committed"))
	journal.mutex.Unlock()
	if stageErr != nil || stateErr != nil {
		t.Fatal(stageErr, stateErr)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	journal, ledger = openFused(t, root)
	defer journal.Close()
	if heads, err := journal.RoomOutboxHeads(fusedRoom); err != nil || len(heads) != 0 {
		t.Fatalf("an unaccepted Commit was published: %d %v", len(heads), err)
	}
	if entries, _ := os.ReadDir(filepath.Join(root, roomStagedDir)); len(entries) != 0 {
		t.Fatal("the staged output survived restart")
	}
	if entries, _ := os.ReadDir(filepath.Join(root, roomObjectChunkDir)); len(entries) != 0 {
		t.Fatal("the discarded Commit's chunks survived restart")
	}
	path, _ := journal.roomStatePath(fusedRoom, stagedState[0])
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an unnamed staged state chunk survived restart")
	}
	current, _, err := ledger.Current(fusedRoom)
	if err != nil || current.StateDigest != record.StateDigest {
		t.Fatalf("the old state does not stand: %v", err)
	}
	if state, err := ledger.State(current); err != nil || string(state) != "epoch zero" {
		t.Fatalf("old state: %q %v", state, err)
	}
}

var errSimulatedCrash = errors.New("simulated crash")

// simulateCrashBeforePublish makes the next Advance with a Commit output stop
// right after its fused write, as a process that died there would.
func simulateCrashBeforePublish(t *testing.T) {
	t.Helper()
	beforeRoomPublish = func() error { return errSimulatedCrash }
	t.Cleanup(func() { beforeRoomPublish = nil })
}

func commitOutput(now time.Time, mlsEpoch uint64, object string) *RoomCommitOutput {
	return &RoomCommitOutput{RetainUntil: now.Add(time.Hour), Objects: []StagedRoomObject{
		{Type: RoomObjectCommit, RoomEpoch: 1, MLSEpoch: mlsEpoch, Object: []byte(object), Recipients: []RoomRecipient{{AgentID: fusedAgent(1)}}},
	}}
}

// Crash between the fused write and publication: restart publishes the
// accepted Commit's output exactly once.
func TestRoomCrashAfterFusedWritePublishesStagedOutputOnce(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	ref := canon.Digest([]byte("written, not published"))
	simulateCrashBeforePublish(t)
	if _, _, err := ledger.Advance(RoomMLSAdvance{Transition: refreshTransition(record, ref), ExpectedStateDigest: record.StateDigest, State: []byte("epoch one"), EpochAuthenticator: fusedAuthenticator(2), Output: commitOutput(fixture.now, 1, "accepted commit")}, fixture.now); !errors.Is(err, errSimulatedCrash) {
		t.Fatalf("advance: %v", err)
	}
	beforeRoomPublish = nil
	if heads, _ := journal.RoomOutboxHeads(fusedRoom); len(heads) != 0 {
		t.Fatal("the crash window published already")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	for restart := 0; restart < 2; restart++ {
		journal, ledger = openFused(t, root)
		heads, err := journal.RoomOutboxHeads(fusedRoom)
		if err != nil || len(heads) != 1 || heads[0].CommitRef != ref {
			t.Fatalf("restart %d: %d heads, %v", restart, len(heads), err)
		}
		object, err := journal.RoomOutboxObject(heads[0].ObjectDigest)
		if err != nil || string(object) != "accepted commit" {
			t.Fatalf("published object: %v", err)
		}
		if current, _, err := ledger.Current(fusedRoom); err != nil || current.AcceptedCommitRef != ref {
			t.Fatalf("the fused write did not stand: %v", err)
		}
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// A new Commit first publishes its room's earlier staged output, so it can
// never overtake the objects of the Commit before it.
func TestRoomAdvancePublishesAnEarlierStagedOutputFirst(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	simulateCrashBeforePublish(t)
	_, record, err := ledger.Advance(RoomMLSAdvance{Transition: refreshTransition(record, canon.Digest([]byte("first"))), ExpectedStateDigest: record.StateDigest, State: []byte("epoch one"), EpochAuthenticator: fusedAuthenticator(2), Output: commitOutput(fixture.now, 1, "first commit")}, fixture.now)
	if !errors.Is(err, errSimulatedCrash) {
		t.Fatalf("first advance: %v", err)
	}
	beforeRoomPublish = nil
	second := refreshTransition(record, canon.Digest([]byte("second")))
	if _, _, err := ledger.Advance(RoomMLSAdvance{Transition: second, ExpectedStateDigest: record.StateDigest, State: []byte("epoch two"), EpochAuthenticator: fusedAuthenticator(3), Output: commitOutput(fixture.now, 2, "second commit")}, fixture.now); err != nil {
		t.Fatal(err)
	}
	queue, err := journal.RoomMemberQueue(fusedRoom, fusedAgent(1))
	if err != nil || len(queue) != 2 || queue[0].MLSEpoch != 1 || queue[1].MLSEpoch != 2 {
		t.Fatalf("queue: %d %v", len(queue), err)
	}
}

// Garbage collection keeps an older Commit and a roster named only by outbox
// heads after the fused record moved on, and deletes unnamed staged records.
func TestRoomGarbageKeepsRecordsNamedOnlyByOutboxHeads(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	record, _ = addWithOutput(t, fixture, ledger, record, fusedAgent(1), "add bob")
	record, _ = addWithOutput(t, fixture, ledger, record, fusedAgent(2), "add carol")
	for index := 0; index < 3; index++ {
		next := refreshTransition(record, canon.Digest([]byte{byte(index)}))
		if _, record, _ = ledger.Advance(RoomMLSAdvance{Transition: next, ExpectedStateDigest: record.StateDigest, State: []byte{byte(index), 1}, EpochAuthenticator: fusedAuthenticator(byte(10 + index))}, fixture.now); record.MLSEpoch != uint64(3+index) {
			t.Fatalf("refresh %d did not advance", index)
		}
	}
	heads, err := journal.RoomOutboxHeads(fusedRoom)
	if err != nil {
		t.Fatal(err)
	}
	// Garbage of each kind no root names.
	orphanObject := filepath.Join(root, roomObjectChunkDir, canon.Digest([]byte("orphan"))[len("sha256:"):]+".json")
	orphanState, _ := journal.roomStatePath(fusedRoom, canon.Digest([]byte("orphan state")))
	orphanBlob := filepath.Join(root, roomBlobDir, delegationBlobPrefix+canon.Digest([]byte("orphan delegation"))[len("sha256:"):]+".json")
	stranger := filepath.Join(root, roomObjectChunkDir, "not-a-chunk.txt")
	for _, path := range []string{orphanObject, orphanState, orphanBlob, stranger} {
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	journal, ledger = openFused(t, root)
	defer journal.Close()
	for _, path := range []string{orphanObject, orphanState, orphanBlob} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unnamed %s survived collection", filepath.Base(path))
		}
	}
	if _, err := os.Stat(stranger); err != nil {
		t.Fatal("collection deleted a file it does not own")
	}
	for _, head := range heads {
		if _, err := journal.RoomOutboxObject(head.ObjectDigest); err != nil {
			t.Fatalf("object of epoch %d named only by its head was collected: %v", head.MLSEpoch, err)
		}
	}
	current, _, err := ledger.Current(fusedRoom)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.State(current); err != nil {
		t.Fatalf("current state collected: %v", err)
	}
	if earlier, found, err := ledger.MembershipAt(fusedRoom, 2); err != nil || !found || len(earlier.Members) != 2 {
		t.Fatalf("retained membership collected: %v %v", found, err)
	}
}

// Collection fails closed: an unreadable root, or an unresolved staged
// output, stops it before it deletes anything.
func TestRoomGarbageDeletesNothingWhenARootIsUnreadable(t *testing.T) {
	for _, damage := range []string{"fused record", "outbox head", "staged output"} {
		t.Run(damage, func(t *testing.T) {
			fixture := newFusedFixture(t)
			root := t.TempDir() + "/state"
			journal, ledger := openFused(t, root)
			record := fixture.installFounder(ledger, []byte("epoch zero"))
			_, _ = addWithOutput(t, fixture, ledger, record, fusedAgent(1), "add bob")
			heads, err := journal.RoomOutboxHeads(fusedRoom)
			if err != nil || len(heads) == 0 {
				t.Fatal(err)
			}
			orphan := filepath.Join(root, roomObjectChunkDir, canon.Digest([]byte("orphan"))[len("sha256:"):]+".json")
			if err := os.WriteFile(orphan, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			var damaged string
			switch damage {
			case "fused record":
				damaged = filepath.Join(root, roomMLSDir, fusedRoom[len("room_"):]+".json")
			case "outbox head":
				damaged = filepath.Join(root, roomOutboxDir, heads[0].ObjectDigest+".json")
			case "staged output":
				damaged = filepath.Join(root, roomStagedDir, canon.Digest([]byte("x"))[len("sha256:"):]+".json")
			}
			if err := os.WriteFile(damaged, []byte("not json"), 0o600); err != nil {
				t.Fatal(err)
			}
			report, err := journal.CollectRoomGarbage()
			if err != nil || !report.FailedClosed || report.Deleted != 0 {
				t.Fatalf("report %+v, %v", report, err)
			}
			if _, err := os.Stat(orphan); err != nil {
				t.Fatal("collection deleted a record while a root was unreadable")
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			// Open runs the same collection and still deletes nothing.
			journal, _ = openFused(t, root)
			defer journal.Close()
			if _, err := os.Stat(orphan); err != nil {
				t.Fatal("restart deleted a record while a root was unreadable")
			}
		})
	}
}

// Object chunks are verified on read like state chunks.
func TestRoomOutboxObjectChunkDamageFailsClosed(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	large := bytes.Repeat([]byte("o"), MaxRoomObjectBytes)
	ref := canon.Digest([]byte("large"))
	if _, _, err := ledger.Advance(RoomMLSAdvance{Transition: refreshTransition(record, ref), ExpectedStateDigest: record.StateDigest, State: []byte("epoch one"), EpochAuthenticator: fusedAuthenticator(2),
		Output: &RoomCommitOutput{RetainUntil: fixture.now.Add(time.Hour), Objects: []StagedRoomObject{
			{Type: RoomObjectCommit, RoomEpoch: 1, MLSEpoch: 1, Object: large, Recipients: []RoomRecipient{{AgentID: fusedAgent(1)}}},
		}}}, fixture.now); err != nil {
		t.Fatal(err)
	}
	heads, err := journal.RoomOutboxHeads(fusedRoom)
	if err != nil || len(heads) != 1 || len(heads[0].Chunks) != MaxRoomObjectChunks {
		t.Fatalf("a maximal object took %d chunks: %v", len(heads[0].Chunks), err)
	}
	if object, err := journal.RoomOutboxObject(heads[0].ObjectDigest); err != nil || !bytes.Equal(object, large) {
		t.Fatalf("maximal object: %v", err)
	}
	if _, err := journal.stageObject(append(large, 'x')); err == nil {
		t.Fatal("an object above the bound was staged")
	}
	// Every chunk intact, but in another order: only the object digest tells.
	distinct := make([]byte, 0, 2*RoomObjectChunkBytes+1)
	distinct = append(distinct, bytes.Repeat([]byte("1"), RoomObjectChunkBytes)...)
	distinct = append(distinct, bytes.Repeat([]byte("2"), RoomObjectChunkBytes)...)
	distinct = append(distinct, '3')
	journal.mutex.Lock()
	chunks, err := journal.stageObject(distinct)
	journal.mutex.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.loadObject(RoomObjectDigest(distinct), uint32(len(distinct)), chunks); err != nil {
		t.Fatalf("intact object: %v", err)
	}
	if _, err := journal.loadObject(RoomObjectDigest(distinct), uint32(len(distinct)), []string{chunks[1], chunks[0], chunks[2]}); !errors.Is(err, ErrRoomChunkDigest) {
		t.Fatalf("reordered chunks: %v", err)
	}
	path, _ := journal.roomObjectChunkPath(heads[0].Chunks[2])
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatal(err)
	}
	other, _ := journal.roomObjectChunkPath(heads[0].Chunks[0])
	raw, _ := os.ReadFile(other)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.RoomOutboxObject(heads[0].ObjectDigest); err == nil {
		t.Fatal("a substituted object chunk was accepted")
	}
}

// A repeated identical ack of a member is a no-op while other members keep the
// head alive; a different outcome for a settled member is refused.
func TestRoomOutboxRepeatedAckIsANoOp(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	output := &RoomCommitOutput{RetainUntil: fixture.now.Add(time.Hour), Objects: []StagedRoomObject{
		{Type: RoomObjectCommit, RoomEpoch: 1, MLSEpoch: 1, Object: []byte("shared commit"), Recipients: []RoomRecipient{{AgentID: fusedAgent(1)}, {AgentID: fusedAgent(2)}}},
	}}
	if _, _, err := ledger.Advance(RoomMLSAdvance{Transition: refreshTransition(record, canon.Digest([]byte("c"))), ExpectedStateDigest: record.StateDigest, State: []byte("epoch one"), EpochAuthenticator: fusedAuthenticator(2), Output: output}, fixture.now); err != nil {
		t.Fatal(err)
	}
	digest := RoomObjectDigest([]byte("shared commit"))
	evidence := canon.Digest([]byte("evidence"))
	for _, member := range []string{fusedAgent(1), fusedAgent(2)} {
		if _, err := journal.RoomOutboxCarried(digest, member, 1, evidence, fixture.now.Add(time.Hour), fixture.now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := journal.RoomOutboxAcked(digest, fusedAgent(1), RoomAckAccepted, "", fixture.now); err != nil {
		t.Fatal(err)
	}
	head, err := journal.RoomOutboxAcked(digest, fusedAgent(1), RoomAckAccepted, "", fixture.now)
	if err != nil {
		t.Fatalf("repeated ack: %v", err)
	}
	if member, _ := head.Member(fusedAgent(1)); member.State != RoomDeliveryDelivered {
		t.Fatalf("member state %s", member.State)
	}
	if _, err := journal.RoomOutboxAcked(digest, fusedAgent(1), RoomAckRejected, fault.CodeNotAuthentic, fixture.now); !errors.Is(err, ErrNotPending) {
		t.Fatalf("a different outcome for a settled member: %v", err)
	}
	if _, err := journal.RoomOutboxAcked(digest, fusedAgent(3), RoomAckAccepted, "", fixture.now); err == nil {
		t.Fatal("an ack from a member the object is not addressed to was applied")
	}
	if queue, err := journal.RoomMemberQueue(fusedRoom, fusedAgent(2)); err != nil || len(queue) != 1 {
		t.Fatalf("the unsettled member's queue: %d %v", len(queue), err)
	}
}
