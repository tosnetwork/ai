package eventlog

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

// A member card is kept only for a member or a live pending add of a room
// held here, replaced only by a newer one, and deleted with the member or
// the room's state.
func TestRoomMemberCardStore(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/authority")
	defer journal.Close()
	now := fixture.now
	card := func(agent string, created, sequence uint64, body string) RoomMemberCard {
		return RoomMemberCard{RoomID: fusedRoom, AgentID: agent, CardBase64: base64.StdEncoding.EncodeToString([]byte(body)),
			CreatedAtUnix: created, Sequence: sequence, NotBeforeUnix: 1, NotAfterUnix: uint64(now.Add(time.Hour).Unix())}
	}
	if _, err := journal.StoreRoomMemberCard(card(fusedAgent(1), 5, 1, "b"), now); !errors.Is(err, ErrRoomNotJoined) {
		t.Fatalf("a card in a room not held: %v", err)
	}
	fixture.installFounder(ledger, []byte("founder state"))
	if _, err := journal.StoreRoomMemberCard(card(fusedAgent(1), 5, 1, "b"), now); !errors.Is(err, ErrRoomCardMember) {
		t.Fatalf("a card of a stranger: %v", err)
	}
	if _, _, err := journal.RecordRoomAdd(fusedRoom, fusedAgent(1), now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if wrote, err := journal.StoreRoomMemberCard(card(fusedAgent(1), 5, 2, "b"), now); err != nil || !wrote {
		t.Fatalf("the pending add's card: %v %v", wrote, err)
	}
	for _, older := range []RoomMemberCard{card(fusedAgent(1), 5, 2, "same"), card(fusedAgent(1), 5, 1, "older"), card(fusedAgent(1), 4, 9, "older")} {
		if wrote, err := journal.StoreRoomMemberCard(older, now); err != nil || wrote {
			t.Fatalf("a card no newer replaced the stored one: %v %v", wrote, err)
		}
	}
	if wrote, err := journal.StoreRoomMemberCard(card(fusedAgent(1), 5, 3, "newer"), now); err != nil || !wrote {
		t.Fatalf("a newer card: %v %v", wrote, err)
	}
	stored, found, err := journal.RoomMemberCardOf(fusedRoom, fusedAgent(1))
	if raw, _ := stored.Card(); err != nil || !found || string(raw) != "newer" || !stored.Valid(now) || stored.Valid(now.Add(time.Hour)) {
		t.Fatalf("the stored card: %+v %v", stored, err)
	}
	// After the add expired, a card of the Agent is a stranger's again.
	if _, err := journal.StoreRoomMemberCard(card(fusedAgent(1), 6, 1, "late"), now.Add(time.Hour)); !errors.Is(err, ErrRoomCardMember) {
		t.Fatalf("a card after the add expired: %v", err)
	}
	if err := journal.ForgetRoomMemberCard(fusedRoom, fusedAgent(1)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := journal.RoomMemberCardOf(fusedRoom, fusedAgent(1)); err != nil || found {
		t.Fatalf("a forgotten card: %v %v", found, err)
	}
	if _, err := journal.StoreRoomMemberCard(card(fusedAgent(0), 1, 1, "own"), now); err != nil {
		t.Fatal(err)
	}
	journal.mutex.Lock()
	_, err = journal.deleteRoomState(fusedRoom)
	journal.mutex.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := journal.RoomMemberCardOf(fusedRoom, fusedAgent(0)); err != nil || found {
		t.Fatalf("a card outlived the room's state: %v %v", found, err)
	}
}
