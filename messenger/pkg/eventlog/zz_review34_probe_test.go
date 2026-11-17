package eventlog

import (
	"errors"
	"testing"
	"time"
)

// The reviewer's probe (ai #34, M1): a stranger's room.invite with a
// far-future expiry must not pre-empt the real authority's invite for the
// same room. The far-future invite is now refused outright, a stranger's
// longest invite (7 days) expires, and the real authority's invite is
// recorded a year later.
func TestReviewRoomInviteExpiryUnboundedPreemption(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, _ := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	now := fixture.now
	attacker := fusedAgent(5)
	if _, err := journal.RecordRoomInvite(fusedRoom, attacker, inviteEvent, inviteBinding(t, attacker), now.Add(100*365*24*time.Hour), now); err == nil {
		t.Fatal("a far-future invite was recorded")
	}
	if _, err := journal.RecordRoomInvite(fusedRoom, attacker, inviteEvent, inviteBinding(t, attacker), now.Add(MaxRoomInviteLifetime), now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(365 * 24 * time.Hour)
	if err := journal.SweepRoomJoins(later); err != nil {
		t.Fatal(err)
	}
	_, err := journal.RecordRoomInvite(fusedRoom, fixture.delegation.AgentID, inviteEvent, inviteBinding(t, fixture.delegation.AgentID), later.Add(time.Hour), later)
	if errors.Is(err, ErrRoomJoinConflict) || err != nil {
		t.Fatalf("a year later the real authority's invite is refused: %v", err)
	}
}
