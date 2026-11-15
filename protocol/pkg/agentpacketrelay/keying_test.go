package agentpacketrelay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net/http"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// readdress copies an envelope's header under another recipient mailbox,
// keeping its envelope ID, with a random tail of the given length.
func readdress(t *testing.T, envelope []byte, agentID string, tail int) []byte {
	t.Helper()
	digest, err := agentpacketseal.AgentDigest(agentID)
	if err != nil {
		t.Fatal(err)
	}
	out := append([]byte(nil), envelope[:agentpacketseal.EnvelopeHeaderSize]...)
	recipientOffset := agentpacketseal.EnvelopeHeaderSize - (32 + 32 + 32 + 8 + 4)
	copy(out[recipientOffset:], digest[:])
	binary.BigEndian.PutUint32(out[agentpacketseal.EnvelopeHeaderSize-4:], uint32(tail))
	junk := make([]byte, tail)
	if _, err := rand.Read(junk); err != nil {
		t.Fatal(err)
	}
	out = append(out, junk...)
	header, err := agentpacketseal.ParseEnvelope(out)
	if err != nil || header.RecipientAgentID != agentID {
		t.Fatalf("readdressed envelope: %v", err)
	}
	return out
}

// TestCrossMailboxSquat: junk deposited under mailbox Y with mailbox X's
// envelope ID neither blocks, hides nor survives X's genuine envelope. Keys
// are (recipient, envelope ID), so X's deposit, listing, download and
// acknowledgement are independent of Y, and Y's junk is charged to Y only.
func TestCrossMailboxSquat(t *testing.T) {
	relay := newTestRelay(t, testLimits())
	x, y := newRecipient(t), newRecipient(t)
	ctx := context.Background()
	genuine := x.seal(t, testPacket(200), relay.clock.unix()+3600)
	squat := readdress(t, genuine.envelope, y.agentID, len(genuine.envelope)-agentpacketseal.EnvelopeHeaderSize)
	if outcome, err := relay.client.Deposit(ctx, squat); err != nil || outcome.Result != DepositStored {
		t.Fatalf("squat under Y = %+v, %v", outcome, err)
	}
	if outcome, err := relay.client.Deposit(ctx, genuine.envelope); err != nil || outcome.Result != DepositStored {
		t.Fatalf("honest deposit under X after a squat under Y = %+v, %v", outcome, err)
	}
	listX, err := relay.client.List(ctx, x.agentID)
	if err != nil || len(listX.Envelopes) != 1 || listX.Envelopes[0].EnvelopeID != genuine.id {
		t.Fatalf("X's listing = %+v, %v", listX, err)
	}
	raw, err := relay.client.Download(ctx, x.agentID, genuine.id)
	if err != nil || !bytes.Equal(raw, genuine.envelope) {
		t.Fatalf("X's download: %v", err)
	}
	if err := relay.client.Ack(ctx, x.agentID, genuine.id, genuine.secret); err != nil {
		t.Fatalf("X's ack: %v", err)
	}
	// Y's junk is still Y's, under Y's quota, until Y or its expiry removes
	// it; X's tombstone does not touch it.
	listY, err := relay.client.List(ctx, y.agentID)
	if err != nil || len(listY.Envelopes) != 1 || listY.Envelopes[0].EnvelopeID != genuine.id {
		t.Fatalf("Y's listing = %+v, %v", listY, err)
	}
	expectStatus(t, relay.putSealed(genuine), http.StatusGone)
	if outcome, err := relay.client.Deposit(ctx, squat); err != nil || outcome.Result != DepositDuplicate {
		t.Fatalf("squat retry under Y = %+v, %v", outcome, err)
	}
	// The same secret also deletes Y's copy: the ID is the secret's hash in
	// every mailbox.
	expectStatus(t, relay.ackRaw(y.agentID, genuine.id, genuine.secret[:]), http.StatusNoContent)
	if usage := relay.store.Usage(); usage.Envelopes != 0 || usage.Tombstones != 2 {
		t.Fatalf("usage = %+v", usage)
	}
	checkAccounting(t, relay.store)

	// The reverse order: X first, then a squat under Y is stored for Y and
	// does not disturb X.
	second := x.seal(t, testPacket(10), relay.clock.unix()+3600)
	expectStatus(t, relay.putSealed(second), http.StatusCreated)
	if outcome, err := relay.client.Deposit(ctx, readdress(t, second.envelope, y.agentID, 2000)); err != nil ||
		outcome.Result != DepositStored {
		t.Fatalf("squat under Y after X = %+v, %v", outcome, err)
	}
	if raw, err := relay.client.Download(ctx, x.agentID, second.id); err != nil || !bytes.Equal(raw, second.envelope) {
		t.Fatalf("X's envelope after a squat under Y: %v", err)
	}
}

// TestStaleFileRemovedWhenReplacementRefused: an expired envelope the sweep
// has not reached is dropped from the index by a deposit under its key; when
// the replacement is refused by a quota, the stale file must go too, or it
// would stay on disk unaccounted.
func TestStaleFileRemovedWhenReplacementRefused(t *testing.T) {
	limits := testLimits()
	limits.TTL = time.Hour
	backend := newMemoryBackend()
	store, err := newStore(limits, backend)
	if err != nil {
		t.Fatal(err)
	}
	relay := newTestRelayWithStore(t, store, newClock())
	alice := newRecipient(t)
	stale := alice.seal(t, testPacket(100), relay.clock.unix()+2*3600)
	expectStatus(t, relay.putSealed(stale), http.StatusCreated)
	relay.clock.Advance(time.Hour + time.Second)
	// Fill the global byte budget so that a larger replacement under the
	// stale key cannot be admitted.
	store.mu.Lock()
	store.limits.GlobalMaxBytes = int64(len(stale.envelope)) + 1000
	store.mu.Unlock()
	larger := readdress(t, stale.envelope, alice.agentID, len(stale.envelope)-agentpacketseal.EnvelopeHeaderSize+5000)
	expectStatus(t, relay.put(alice.agentID, stale.id, larger), statusInsufficientSave)
	backend.mu.Lock()
	_, left := backend.envelopes[stale.key(t)]
	backend.mu.Unlock()
	if left {
		t.Fatal("the stale envelope file stayed behind after its replacement was refused")
	}
	if usage := store.Usage(); usage != (Usage{}) {
		t.Fatalf("usage = %+v", usage)
	}
	checkAccounting(t, store)
}

// TestStaleFileRemovedOnDisk is the same on the durable store.
func TestStaleFileRemovedOnDisk(t *testing.T) {
	dir := t.TempDir()
	clock := newClock()
	limits := testLimits()
	limits.TTL = time.Hour
	limits.GlobalMaxBytes = MaxEnvelopeBytes
	store, err := OpenDiskStore(dir, limits, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	relay := newTestRelayWithStore(t, store, clock)
	alice := newRecipient(t)
	stale := alice.seal(t, testPacket(200_000), clock.unix()+2*3600)
	expectStatus(t, relay.putSealed(stale), http.StatusCreated)
	clock.Advance(time.Hour + time.Second)
	larger := readdress(t, stale.envelope, alice.agentID, MaxEnvelopeBytes-agentpacketseal.EnvelopeHeaderSize)
	store.mu.Lock()
	store.limits.GlobalMaxBytes = int64(len(stale.envelope)) + 1000
	store.mu.Unlock()
	expectStatus(t, relay.put(alice.agentID, stale.id, larger), statusInsufficientSave)
	backend := store.backend.(*diskBackend)
	if _, err := backend.readRecord(stale.key(t)); err == nil {
		t.Fatal("the stale envelope file stayed on disk after its replacement was refused")
	}
}
