package eventlog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
)

// addCredentials is a joiner's matching DeviceCredential (JSON) and leaf
// credential, as a room.key-package carries them.
func addCredentials(t *testing.T, agentID string, seed byte, issued, expires uint64) ([]byte, []byte) {
	t.Helper()
	delegation, key := roomDelegation(t, agentID, seed)
	leafKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed + 1}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	device, err := group.SignDeviceCredential(group.DeviceCredential{Network: delegation.Network, AgentID: agentID,
		EndpointID: delegation.EndpointID, DeviceID: "dev_" + strings.Repeat("1", 64), DeviceSetDigest: canon.Digest([]byte("set")),
		LeafSignaturePublicKey: leafKey, KeyPackage: []byte("key package " + string(seed)),
		IssuedAtUnix: issued, ExpiresAtUnix: expires}, key)
	if err != nil {
		t.Fatal(err)
	}
	deviceJSON, err := group.EncodeDeviceCredentialJSON(device)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := group.SignLeafCredential(group.LeafCredential{Network: delegation.Network, AgentID: agentID,
		EndpointID: delegation.EndpointID, DeviceID: device.DeviceID, DeviceSetDigest: device.DeviceSetDigest,
		LeafSignaturePublicKey: leafKey, IssuedAtUnix: issued, ExpiresAtUnix: expires}, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := group.EncodeLeafCredential(leaf)
	if err != nil {
		t.Fatal(err)
	}
	return deviceJSON, encoded
}

// The authority's pending adds: one per Agent, only for a room held here
// and an Agent not yet a member, bounded by the room bound with the members,
// one KeyPackage each, expired adds swept, and deleted with the room's
// state.
func TestRoomAddLifecycle(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/authority")
	defer journal.Close()
	now := fixture.now
	expires := now.Add(time.Hour)
	if _, _, err := journal.RecordRoomAdd(fusedRoom, fusedAgent(1), expires, now); !errors.Is(err, ErrRoomNotJoined) {
		t.Fatalf("an add to a room not held: %v", err)
	}
	fixture.installFounder(ledger, []byte("founder state"))
	if _, _, err := journal.RecordRoomAdd(fusedRoom, fusedAgent(0), expires, now); !errors.Is(err, ErrRoomAddMember) {
		t.Fatalf("an add of a member: %v", err)
	}
	if _, _, err := journal.RecordRoomAdd(fusedRoom, fusedAgent(1), now.Add(8*24*time.Hour), now); err == nil {
		t.Fatal("an add outliving the invite bound")
	}
	add, fresh, err := journal.RecordRoomAdd(fusedRoom, fusedAgent(1), expires, now)
	if err != nil || !fresh || add.Ready() {
		t.Fatalf("the add: %+v %v %v", add, fresh, err)
	}
	if again, fresh, err := journal.RecordRoomAdd(fusedRoom, fusedAgent(1), expires.Add(time.Minute), now); err != nil || fresh || again != add {
		t.Fatalf("a repeated add: %+v %v %v", again, fresh, err)
	}

	issued, end := uint64(now.Unix())-10, uint64(now.Add(24*time.Hour).Unix())
	deviceJSON, leaf := addCredentials(t, fusedAgent(1), 0x71, issued, end)
	if _, err := journal.RecordRoomAddKeyPackage(fusedRoom, fusedAgent(2), deviceJSON, leaf, now); !errors.Is(err, ErrRoomAddUnknown) {
		t.Fatalf("a KeyPackage for an Agent never added: %v", err)
	}
	if _, err := journal.RecordRoomAddKeyPackage(fusedRoom, fusedAgent(1), deviceJSON, leaf, expires); !errors.Is(err, ErrRoomAddUnknown) {
		t.Fatalf("a KeyPackage after the add expired: %v", err)
	}
	ready, err := journal.RecordRoomAddKeyPackage(fusedRoom, fusedAgent(1), deviceJSON, leaf, now)
	if err != nil || !ready.Ready() {
		t.Fatalf("the KeyPackage: %+v %v", ready, err)
	}
	if _, _, err := ready.Credentials(); err != nil {
		t.Fatalf("the recorded credentials: %v", err)
	}
	if again, err := journal.RecordRoomAddKeyPackage(fusedRoom, fusedAgent(1), deviceJSON, leaf, now); err != nil || again != ready {
		t.Fatalf("the KeyPackage repeated: %v", err)
	}
	otherDevice, otherLeaf := addCredentials(t, fusedAgent(1), 0x75, issued, end)
	if _, err := journal.RecordRoomAddKeyPackage(fusedRoom, fusedAgent(1), otherDevice, otherLeaf, now); !errors.Is(err, ErrRoomAddConflict) {
		t.Fatalf("a second KeyPackage: %v", err)
	}
	// Another add waits behind the ready one.
	if _, _, err := journal.RecordRoomAdd(fusedRoom, fusedAgent(2), expires, now); err != nil {
		t.Fatal(err)
	}
	adds, err := journal.RoomAdds(fusedRoom, now)
	if err != nil || len(adds) != 2 || adds[0].AgentID != fusedAgent(1) || adds[1].Ready() {
		t.Fatalf("listed adds: %+v %v", adds, err)
	}
	// An expired add is swept when listed.
	if adds, err := journal.RoomAdds(fusedRoom, expires); err != nil || len(adds) != 0 {
		t.Fatalf("expired adds were listed: %+v %v", adds, err)
	}
	if _, _, err := journal.RecordRoomAdd(fusedRoom, fusedAgent(1), expires.Add(time.Hour), expires); err != nil {
		t.Fatal(err)
	}
	if err := journal.FinishRoomAdd(fusedRoom, fusedAgent(1)); err != nil {
		t.Fatal(err)
	}
	if err := journal.FinishRoomAdd(fusedRoom, fusedAgent(1)); err != nil {
		t.Fatalf("finishing a missing add: %v", err)
	}
	if adds, err := journal.RoomAdds(fusedRoom, expires); err != nil || len(adds) != 0 {
		t.Fatalf("a finished add was listed: %+v %v", adds, err)
	}
	// The room's members and live adds never exceed the room bound.
	for index := 1; index < group.MaxPrivateRoomAgents; index++ {
		if _, _, err := journal.RecordRoomAdd(fusedRoom, fusedAgent(index), expires.Add(time.Hour), expires); err != nil {
			t.Fatalf("add %d: %v", index, err)
		}
	}
	if _, _, err := journal.RecordRoomAdd(fusedRoom, fusedAgent(group.MaxPrivateRoomAgents), expires.Add(time.Hour), expires); !errors.Is(err, ErrRoomAddsFull) {
		t.Fatalf("an add above the room bound: %v", err)
	}
	// Adds are per-room state, deleted with the room's.
	journal.mutex.Lock()
	_, err = journal.deleteRoomState(fusedRoom)
	journal.mutex.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if adds, err := journal.RoomAdds(fusedRoom, expires); err != nil || len(adds) != 0 {
		t.Fatalf("adds outlived the room's state: %d %v", len(adds), err)
	}
}

func testSealIntent(t *testing.T, key string, sequence uint64, now time.Time) RoomSealIntent {
	t.Helper()
	return RoomSealIntent{IdempotencyKey: "idem_" + strings.Repeat(key, 64), IntentDigest: canon.Digest([]byte(key)),
		EventID: "evt_" + strings.Repeat(key, 64), EventBase64: base64.StdEncoding.EncodeToString([]byte(`{"event":"` + key + `"}`)),
		Sequence: sequence, RoomEpoch: 1, ReservedAtUnix: uint64(now.Unix())}
}

// A room's sequence is reserved in one write before the seal and never used
// twice; a second composition waits for the first; the application record
// ends the intent; members move pending to carried or abandoned, and the
// object is dropped at its retention end.
func TestRoomApplicationSendLifecycle(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/sender"
	journal, ledger := openFused(t, root)
	now := fixture.now
	first := testSealIntent(t, "1", 1, now)
	if err := journal.ReserveRoomSeal(fusedRoom, first); !errors.Is(err, ErrRoomNotJoined) {
		t.Fatalf("a seal in a room not held: %v", err)
	}
	fixture.installFounder(ledger, []byte("founder state"))
	if err := journal.ReserveRoomSeal(fusedRoom, testSealIntent(t, "1", 2, now)); !errors.Is(err, ErrRoomSequenceOrder) {
		t.Fatalf("a sequence that skips one: %v", err)
	}
	if err := journal.ReserveRoomSeal(fusedRoom, first); err != nil {
		t.Fatal(err)
	}
	if err := journal.ReserveRoomSeal(fusedRoom, first); err != nil {
		t.Fatalf("the reserved intent repeated: %v", err)
	}
	if err := journal.ReserveRoomSeal(fusedRoom, testSealIntent(t, "2", 2, now)); !errors.Is(err, ErrRoomSealPending) {
		t.Fatalf("a second composition during a seal: %v", err)
	}
	// The intent survives a restart.
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, _ = openFused(t, root)
	defer journal.Close()
	last, intent, err := journal.RoomSendState(fusedRoom)
	if err != nil || last != 1 || intent == nil || *intent != first {
		t.Fatalf("after a restart: last=%d intent=%+v %v", last, intent, err)
	}
	object := bytes.Repeat([]byte{0x42}, 400)
	members := []string{fusedAgent(2), fusedAgent(1)}
	send, err := NewRoomApplicationSend(fusedRoom, first, 0, object, members, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRoomApplicationSend(fusedRoom, first, 0, object, members, now, now.Add(25*time.Hour)); err == nil {
		t.Fatal("an object kept beyond the largest relay TTL")
	}
	unreserved := send
	unreserved.IdempotencyKey = "idem_" + strings.Repeat("9", 64)
	if err := journal.RecordRoomApplicationSend(unreserved); err == nil {
		t.Fatal("an application record no seal reserved")
	}
	if err := journal.RecordRoomApplicationSend(send); err != nil {
		t.Fatal(err)
	}
	if _, intent, err := journal.RoomSendState(fusedRoom); err != nil || intent != nil {
		t.Fatalf("the record did not end the intent: %+v %v", intent, err)
	}
	if err := journal.RecordRoomApplicationSend(send); err != nil {
		t.Fatalf("the record repeated: %v", err)
	}
	if found, ok, err := journal.RoomApplicationSendFor(fusedRoom, first.IdempotencyKey); err != nil || !ok ||
		found.Members[0].AgentID != fusedAgent(1) || found.Members[0].State != RoomDeliveryPending {
		t.Fatalf("the record: %+v %v", found, err)
	}
	// The next composition takes the next sequence.
	if err := journal.ReserveRoomSeal(fusedRoom, testSealIntent(t, "2", 2, now)); err != nil {
		t.Fatal(err)
	}
	if err := journal.DropRoomSealIntent(fusedRoom, "idem_"+strings.Repeat("2", 64)); err != nil {
		t.Fatal(err)
	}
	if last, intent, err := journal.RoomSendState(fusedRoom); err != nil || last != 2 || intent != nil {
		t.Fatalf("a dropped intent: last=%d intent=%+v %v", last, intent, err)
	}

	evidence := canon.Digest([]byte("evidence"))
	if _, err := journal.RoomApplicationCarried(fusedRoom, first.IdempotencyKey, fusedAgent(3), evidence, now); err == nil {
		t.Fatal("a deposit to a member the object is not addressed to")
	}
	carried, err := journal.RoomApplicationCarried(fusedRoom, first.IdempotencyKey, fusedAgent(1), evidence, now)
	if err != nil || carried.Members[0].State != RoomDeliveryCarried {
		t.Fatalf("carried: %+v %v", carried, err)
	}
	if _, err := journal.RoomApplicationCarried(fusedRoom, first.IdempotencyKey, fusedAgent(1), evidence, now); err != nil {
		t.Fatalf("carried again: %v", err)
	}
	if _, err := journal.RoomApplicationAbandoned(fusedRoom, first.IdempotencyKey, fusedAgent(1), fault.CodeRejected, now); !errors.Is(err, ErrNotPending) {
		t.Fatalf("abandoning a carried member: %v", err)
	}
	if _, err := journal.RoomApplicationDeferred(fusedRoom, first.IdempotencyKey, fusedAgent(2), now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if pending, err := journal.PendingRoomApplicationSends(); err != nil || len(pending) != 1 {
		t.Fatalf("pending records: %d %v", len(pending), err)
	}
	// At the retention end the pending member is abandoned and the object
	// dropped; the digest and the states stay.
	if abandoned, err := journal.SweepRoomApplicationSends(now.Add(time.Hour - time.Second)); err != nil || abandoned != 0 {
		t.Fatalf("a sweep before the retention end: %d %v", abandoned, err)
	}
	if abandoned, err := journal.SweepRoomApplicationSends(now.Add(time.Hour)); err != nil || abandoned != 1 {
		t.Fatalf("the sweep at the retention end: %d %v", abandoned, err)
	}
	swept, _, err := journal.RoomApplicationSendFor(fusedRoom, first.IdempotencyKey)
	if err != nil || swept.ObjectBase64 != "" || swept.Members[1].State != RoomDeliveryAbandoned ||
		swept.Members[1].Code != fault.CodeRetentionExceeded || swept.ObjectDigest != send.ObjectDigest {
		t.Fatalf("after the sweep: %+v %v", swept, err)
	}
	if pending, err := journal.PendingRoomApplicationSends(); err != nil || len(pending) != 0 {
		t.Fatalf("pending after the sweep: %d %v", len(pending), err)
	}
}

// At the bound of a room's application records the oldest record whose
// object was dropped makes room; with every object still kept, a new seal
// is refused.
func TestRoomApplicationSendsAreBounded(t *testing.T) {
	saved := maxRoomApplicationSends
	maxRoomApplicationSends = 2
	t.Cleanup(func() { maxRoomApplicationSends = saved })
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/sender")
	defer journal.Close()
	fixture.installFounder(ledger, []byte("founder state"))
	now := fixture.now
	seal := func(key string, sequence uint64, at time.Time) error {
		intent := testSealIntent(t, key, sequence, at)
		if err := journal.ReserveRoomSeal(fusedRoom, intent); err != nil {
			return err
		}
		send, err := NewRoomApplicationSend(fusedRoom, intent, 0, []byte("object "+key), []string{fusedAgent(1)}, at, at.Add(time.Hour))
		if err != nil {
			return err
		}
		return journal.RecordRoomApplicationSend(send)
	}
	if err := seal("1", 1, now); err != nil {
		t.Fatal(err)
	}
	if err := seal("2", 2, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := seal("3", 3, now.Add(2*time.Second)); !errors.Is(err, ErrRoomSendsFull) {
		t.Fatalf("a seal at the bound with every object kept: %v", err)
	}
	if err := journal.DropRoomSealIntent(fusedRoom, "idem_"+strings.Repeat("3", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.SweepRoomApplicationSends(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := seal("4", 4, now.Add(time.Hour)); err != nil {
		t.Fatalf("a seal at the bound once an object was dropped: %v", err)
	}
	if _, found, err := journal.RoomApplicationSendFor(fusedRoom, "idem_"+strings.Repeat("1", 64)); err != nil || found {
		t.Fatalf("the oldest dropped record was kept: %v %v", found, err)
	}
}
