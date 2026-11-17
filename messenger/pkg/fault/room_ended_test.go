package fault

import "testing"

// room-ended (D18) is a fixed, permanent, peer-visible code without a retry
// hint: the sender learns the room is over and does not retry.
func TestRoomEndedIsPermanentAndVisible(t *testing.T) {
	if CodeRoomEnded != "room-ended" || !Known(CodeRoomEnded) {
		t.Fatalf("room-ended is not classified: %q", CodeRoomEnded)
	}
	if DispositionOf(CodeRoomEnded) != Permanent || !PeerVisible(CodeRoomEnded) {
		t.Fatal("room-ended must be permanent and peer-visible")
	}
	if response := PeerCode(CodeRoomEnded, 30); response.Code != CodeRoomEnded || response.RetryAfterSeconds != 0 {
		t.Fatalf("room-ended reached a peer as %+v", response)
	}
}
