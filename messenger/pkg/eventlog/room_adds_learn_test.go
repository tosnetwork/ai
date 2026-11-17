package eventlog

import (
	"errors"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/group"
)

// The Add's fused write learns the joiner's credential with the membership
// that adds it: one write, so a crash leaves either neither or both. A
// credential of an Agent the advance does not add, one ending before the
// room, and any on an MLS-only advance are refused and write nothing.
func TestRoomAddLearnsTheJoinerInTheSameFusedWrite(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/authority")
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("founder state"))
	bob := fusedAgent(1)
	transition, membership := addTransition(t, record, []string{bob}, canon.Digest([]byte("add bob")))
	proof := fixture.proof(membership)
	advance := func(learned ...group.LeafBinding) (RoomMLSRecord, error) {
		_, next, err := ledger.Advance(RoomMLSAdvance{Transition: transition, Proof: &proof, ExpectedStateDigest: record.StateDigest,
			State: []byte("state with bob"), EpochAuthenticator: fusedAuthenticator(2), Learned: learned}, fixture.now)
		return next, err
	}
	if _, err := advance(memberBinding(t, fusedAgent(2))); !errors.Is(err, ErrRoomCredentialMember) {
		t.Fatalf("a credential of an Agent the Add does not add: %v", err)
	}
	if _, err := advance(memberBinding(t, fusedAgent(0))); !errors.Is(err, ErrRoomCredentialMember) {
		t.Fatalf("a credential of an earlier member: %v", err)
	}
	delegation, key := roomDelegation(t, bob, 0x62)
	if _, err := advance(leafBindingFor(t, delegation, key, 0x29, testRoomEnd-1)); !errors.Is(err, ErrRoomCredentialEndsEarly) {
		t.Fatalf("a credential ending before the room: %v", err)
	}
	if current, _, err := ledger.Current(fusedRoom); err != nil || current.MLSEpoch != record.MLSEpoch {
		t.Fatalf("a refused advance wrote: %+v %v", current, err)
	}
	if _, _, err := ledger.Advance(RoomMLSAdvance{Transition: refreshTransition(record, canon.Digest([]byte("refresh"))),
		ExpectedStateDigest: record.StateDigest, State: []byte("refreshed"), EpochAuthenticator: fusedAuthenticator(3),
		Learned: []group.LeafBinding{memberBinding(t, bob)}}, fixture.now); err == nil {
		t.Fatal("an MLS-only advance learned a credential")
	}
	next, err := advance(memberBinding(t, bob))
	if err != nil {
		t.Fatal(err)
	}
	if !next.Membership().Contains(bob) {
		t.Fatal("the Add did not add Bob")
	}
	if _, found, err := ledger.RoomCredential(fusedRoom, bob); err != nil || !found {
		t.Fatalf("Bob's credential was not learned with the Add: %v %v", found, err)
	}
	if _, found, err := ledger.RoomCredential(fusedRoom, fusedAgent(0)); err != nil || !found {
		t.Fatalf("the authority's credential left the list: %v %v", found, err)
	}
}

// An expired add whose Agent is a member without a stored credential is
// kept, so its credential is still learned; once learned, the expired add
// is swept.
func TestRoomAddOfAMemberWithoutCredentialOutlivesItsExpiry(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/authority")
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("founder state"))
	bob := fusedAgent(1)
	expires := fixture.now.Add(time.Hour)
	if _, _, err := journal.RecordRoomAdd(fusedRoom, bob, expires, fixture.now); err != nil {
		t.Fatal(err)
	}
	transition, membership := addTransition(t, record, []string{bob}, canon.Digest([]byte("add bob")))
	advanceMembership(t, fixture, ledger, record, transition, membership)
	adds, err := journal.RoomAdds(fusedRoom, expires)
	if err != nil || len(adds) != 1 || adds[0].AgentID != bob {
		t.Fatalf("the expired add of a member without a credential was dropped: %+v %v", adds, err)
	}
	if _, _, err := ledger.LearnRoomCredentials(fusedRoom, []group.LeafBinding{memberBinding(t, bob)}, fixture.now); err != nil {
		t.Fatal(err)
	}
	if adds, err := journal.RoomAdds(fusedRoom, expires); err != nil || len(adds) != 0 {
		t.Fatalf("the expired add was kept after the credential was learned: %+v %v", adds, err)
	}
}
