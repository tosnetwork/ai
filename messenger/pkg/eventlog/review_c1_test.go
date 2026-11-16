package eventlog

import (
	"fmt"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
)

// A repeated stateless rejection reports lost state again: the finding is
// persisted with the member, not only returned by the first ack.
func TestRoomOutboxRepeatedStatelessRejectionStillReportsLostState(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	bob, carol, dave := fusedAgent(1), fusedAgent(2), fusedAgent(3)
	record, _ = addWithOutput(t, fixture, ledger, record, bob, "add bob")
	record, _ = addWithOutput(t, fixture, ledger, record, carol, "add carol")
	_, _ = addWithOutput(t, fixture, ledger, record, dave, "add dave")
	var commit RoomOutboxHead
	queue, err := journal.RoomMemberQueue(fusedRoom, carol)
	if err != nil {
		t.Fatal(err)
	}
	for _, head := range queue {
		if head.Type == RoomObjectCommit && head.MLSEpoch == record.MLSEpoch+1 {
			commit = head
		}
	}
	if commit.ObjectDigest == "" || len(commit.Members) != 2 {
		t.Fatalf("the Commit adding Dave is not addressed to Bob and Carol: %+v", commit)
	}
	evidence := canon.Digest([]byte("evidence"))
	for _, member := range []string{bob, carol} {
		if _, err := journal.RoomOutboxCarried(commit.ObjectDigest, member, 1, evidence, fixture.now.Add(time.Hour), fixture.now); err != nil {
			t.Fatal(err)
		}
	}
	first, err := journal.RoomOutboxAcked(commit.ObjectDigest, carol, RoomAckRejected, fault.CodeNotAuthentic, true, fixture.now)
	if err != nil || !first.LostState {
		t.Fatalf("first stateless rejection: %+v %v", first, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, _ = openFused(t, root)
	defer journal.Close()
	again, err := journal.RoomOutboxAcked(commit.ObjectDigest, carol, RoomAckRejected, fault.CodeNotAuthentic, true, fixture.now)
	if err != nil || !again.LostState {
		t.Fatalf("repeated stateless rejection after restart: %+v %v", again, err)
	}
	if member, _ := again.Head.Member(carol); !member.Stateless || member.State != RoomDeliveryRejected {
		t.Fatalf("stateless rejection not persisted: %+v", member)
	}
}

// Expired presented invites never fill the list: they are swept before the
// bound refuses a new recipient.
func TestPresentedInviteListSweepsExpiredBeforeRefusing(t *testing.T) {
	saved := presentedInviteCap
	presentedInviteCap = 3
	defer func() { presentedInviteCap = saved }()
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	now := time.Unix(10_000, 0)
	for index := 0; index < 3; index++ {
		if _, err := journal.PresentInvite(fusedAgent(10+index), inviteTestToken, now.Add(time.Minute), now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := journal.PresentInvite(fusedAgent(20), inviteTestToken, now.Add(time.Hour), now); err != ErrPresentedInvitesFull {
		t.Fatalf("a full list of live invites: %v", err)
	}
	later := now.Add(2 * time.Minute)
	if _, err := journal.PresentInvite(fusedAgent(20), inviteTestToken, later.Add(time.Hour), later); err != nil {
		t.Fatalf("expired invites still filled the list: %v", err)
	}
	if count, err := countEntries(fmt.Sprintf("%s/%s", journal.root, presentedInviteDir)); err != nil || count != 1 {
		t.Fatalf("after the sweep %d entries remain: %v", count, err)
	}
}
