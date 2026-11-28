package daemon

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// credentialingCarrier is a carrier with contact credentials and settlement,
// as the builtin lane is.
type credentialingCarrier struct {
	*recordingCarrier
	mu         sync.Mutex
	credential map[string][]byte
	settled    map[string][]string
}

func (c *credentialingCarrier) ContactCredential(_ context.Context, peer string) ([]byte,
	[relayframe.HolderSeedBytes]byte, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	wire, ok := c.credential[peer]
	return bytes.Clone(wire), [relayframe.HolderSeedBytes]byte{9}, ok, nil
}

func (c *credentialingCarrier) Settled(_ context.Context, recipient string, keys []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.settled[recipient] = append(c.settled[recipient], keys...)
	return nil
}

// A frame to an admitted peer carries this node's contact credential until
// the peer acknowledged a frame that carried it, like the card; a renewed
// credential rides again; and an acknowledged copy is settled at the carrier
// for every generation.
func TestRelayFramesCarryTheContactCredentialUntilAcknowledged(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	carrier := &credentialingCarrier{recordingCarrier: a.carrier,
		credential: map[string][]byte{b.d.config.AgentID: []byte("first contact credential")}, settled: map[string][]string{}}
	a.d.relay.carrier = carrier

	first := sendText(t, a, b, "hello B", "a", now)
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("sweep: %+v %v", summary, err)
	}
	out := onlyFrame(t, a)
	frame, err := relayframe.Decode(out.frame)
	if err != nil || string(frame.Credential) != "first contact credential" || frame.HolderSeed[0] != 9 {
		t.Fatalf("the copy does not carry the credential: %q %v", frame.Credential, err)
	}
	state := copyState(t, a, first, b.d.config.EndpointID, b.d.config.DeviceID)
	if len(state.Generations) != 1 || state.Generations[0].CredentialDigest != canon.Digest([]byte("first contact credential")) {
		t.Fatalf("the generation does not record the credential: %+v", state.Generations)
	}
	answer := deliver(t, a, b, out.frame)
	if applied := a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, ackFrameOf(t, answer)); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("ack: %+v", applied)
	}
	copyID, _ := eventlog.NewDeliveryCopyID(first, b.d.config.EndpointID, b.d.config.DeviceID)
	key, _ := relayframe.CopyIdempotencyKey(copyID, 1)
	carrier.mu.Lock()
	settled := append([]string(nil), carrier.settled[b.d.config.AgentID]...)
	carrier.mu.Unlock()
	if len(settled) != 1 || settled[0] != key {
		t.Fatalf("the acknowledged copy was not settled at the carrier: %v", settled)
	}

	sendText(t, a, b, "again", "c", now)
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("second sweep: %+v %v", summary, err)
	}
	if again, err := relayframe.Decode(onlyFrame(t, a).frame); err != nil || len(again.Credential) != 0 {
		t.Fatalf("an acknowledged credential still rides: %d %v", len(again.Credential), err)
	}

	carrier.mu.Lock()
	carrier.credential[b.d.config.AgentID] = []byte("renewed contact credential")
	carrier.mu.Unlock()
	sendText(t, a, b, "renewed", "d", now)
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("third sweep: %+v %v", summary, err)
	}
	renewed, err := relayframe.Decode(onlyFrame(t, a).frame)
	if err != nil || !strings.HasPrefix(string(renewed.Credential), "renewed") {
		t.Fatalf("a renewed credential does not ride: %q %v", renewed.Credential, err)
	}

	// A peer the carrier issues nothing to gets frames without a credential.
	carrier.mu.Lock()
	delete(carrier.credential, b.d.config.AgentID)
	carrier.mu.Unlock()
	sendText(t, a, b, "stranger lane", "e", now)
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("fourth sweep: %+v %v", summary, err)
	}
	if plain, err := relayframe.Decode(onlyFrame(t, a).frame); err != nil || len(plain.Credential) != 0 {
		t.Fatalf("a frame without an issued credential carries one: %v", err)
	}
}

// journalingCarrier journals the first frame of each key, as the builtin
// lane does: a retry of a key carries that frame, whatever was built since.
type journalingCarrier struct {
	*credentialingCarrier
	journal map[string][]byte
	// retryFirst answers the first deposit of every key with retry.
	retryFirst bool
}

func (c *journalingCarrier) CarryFrame(ctx context.Context, recipient, key, withdraw string, expires uint64,
	frame []byte) (carrierapi.Response, []byte, error) {
	c.mu.Lock()
	sent, known := c.journal[key]
	if !known {
		sent = bytes.Clone(frame)
		c.journal[key] = sent
	}
	retry := c.retryFirst && !known
	c.mu.Unlock()
	response, err := c.Carry(ctx, recipient, key, withdraw, expires, sent)
	if retry {
		return carrierapi.Retry(), sent, err
	}
	return response, sent, err
}

// A credential renewed between two attempts of one key is not marked
// acknowledged: the generation records the credential of the frame actually
// carried, so the renewed one still rides afterwards.
func TestARenewedCredentialBeforeARetryIsNotMarkedAcknowledged(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	carrier := &journalingCarrier{credentialingCarrier: &credentialingCarrier{recordingCarrier: a.carrier,
		credential: map[string][]byte{b.d.config.AgentID: []byte("first contact credential")}, settled: map[string][]string{}},
		journal: map[string][]byte{}, retryFirst: true}
	a.d.relay.carrier = carrier

	first := sendText(t, a, b, "hello B", "a", now)
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 0 {
		t.Fatalf("first attempt: %+v %v", summary, err)
	}
	a.carrier.take()
	carrier.mu.Lock()
	carrier.credential[b.d.config.AgentID] = []byte("renewed contact credential")
	carrier.mu.Unlock()
	later := now.Add(10 * time.Minute)
	a.d.now = func() time.Time { return later }
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("retry: %+v %v", summary, err)
	}
	out := onlyFrame(t, a)
	if frame, err := relayframe.Decode(out.frame); err != nil || string(frame.Credential) != "first contact credential" {
		t.Fatalf("the retry did not carry the journaled frame: %q %v", frame.Credential, err)
	}
	state := copyState(t, a, first, b.d.config.EndpointID, b.d.config.DeviceID)
	if len(state.Generations) != 1 || state.Generations[0].CredentialDigest != canon.Digest([]byte("first contact credential")) {
		t.Fatalf("the generation records a credential that was not sent: %+v", state.Generations)
	}
	b.d.now = func() time.Time { return later }
	answer := deliver(t, a, b, out.frame)
	if applied := a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, ackFrameOf(t, answer)); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("ack: %+v", applied)
	}
	carrier.mu.Lock()
	carrier.retryFirst = false
	carrier.mu.Unlock()
	sendText(t, a, b, "after the ack", "c", later)
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("next copy: %+v %v", summary, err)
	}
	if next, err := relayframe.Decode(onlyFrame(t, a).frame); err != nil || string(next.Credential) != "renewed contact credential" {
		t.Fatalf("the renewed credential no longer rides although it was never sent: %q %v", next.Credential, err)
	}
}

// A copy the recipient rejected for good is settled at the carrier, so its
// generations are not deposited again; descriptor-expired keeps the copy
// pending and unsettled.
func TestATerminallyRejectedCopyIsSettledAtTheCarrier(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	carrier := &credentialingCarrier{recordingCarrier: a.carrier, credential: map[string][]byte{}, settled: map[string][]string{}}
	a.d.relay.carrier = carrier
	rejected := sendText(t, a, b, "one", "a", now)
	expired := sendText(t, a, b, "two", "b", now)
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 2 {
		t.Fatalf("sweep: %+v %v", summary, err)
	}
	a.carrier.take()
	reject := func(eventID string, code fault.Code) eventlog.Delivery {
		t.Helper()
		delivery := copyState(t, a, eventID, b.d.config.EndpointID, b.d.config.DeviceID)
		ciphertext, _ := delivery.Ciphertext()
		ack := relayframe.Ack{EventID: eventID, SessionID: delivery.SessionID, RecipientEndpointID: b.d.config.EndpointID,
			RecipientDeviceID: b.d.config.DeviceID, CiphertextDigest: canon.Digest(ciphertext),
			Outcome: relayframe.OutcomeRejected, Code: code, AcceptedAtUnix: uint64(now.Unix())}
		match := eventlog.RelayAckMatch{SessionID: delivery.SessionID, DeviceID: b.d.config.DeviceID,
			CiphertextDigest: ack.CiphertextDigest}
		if err := a.d.relay.applyAck(b.d.config.AgentID, delivery.Key(), delivery, ack, match, now); err != nil {
			t.Fatal(err)
		}
		return copyState(t, a, eventID, b.d.config.EndpointID, b.d.config.DeviceID)
	}
	if kept := reject(expired, fault.CodeDescriptorExpired); kept.State != eventlog.StatePending {
		t.Fatalf("descriptor-expired: %+v", kept)
	}
	carrier.mu.Lock()
	early := len(carrier.settled[b.d.config.AgentID])
	carrier.mu.Unlock()
	if early != 0 {
		t.Fatal("a descriptor-expired copy was settled")
	}
	if ended := reject(rejected, fault.CodeRejected); ended.State != eventlog.StateAbandoned {
		t.Fatalf("terminal rejection: %+v", ended)
	}
	copyID, _ := eventlog.NewDeliveryCopyID(rejected, b.d.config.EndpointID, b.d.config.DeviceID)
	key, _ := relayframe.CopyIdempotencyKey(copyID, 1)
	carrier.mu.Lock()
	settled := append([]string(nil), carrier.settled[b.d.config.AgentID]...)
	carrier.mu.Unlock()
	if len(settled) != 1 || settled[0] != key {
		t.Fatalf("the rejected copy was not settled at the carrier: %v", settled)
	}
}

// A credential on an ack frame rides on every ack until it is renewed, since
// acks are never acknowledged; the renewed one replaces it on later acks.
func TestAnAckCarriesTheCredentialOnEveryAckUntilRenewed(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	carrier := &credentialingCarrier{recordingCarrier: b.carrier,
		credential: map[string][]byte{a.d.config.AgentID: []byte("receiver credential")}, settled: map[string][]string{}}
	b.d.relay.carrier = carrier
	ackCredential := func(body, idem string) string {
		t.Helper()
		sendText(t, a, b, body, idem, now)
		if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
			t.Fatalf("sweep: %+v %v", summary, err)
		}
		answer := deliver(t, a, b, onlyFrame(t, a).frame)
		ack, err := relayframe.Decode(ackFrameOf(t, answer))
		if err != nil {
			t.Fatal(err)
		}
		if applied := a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, ackFrameOf(t, answer)); applied.Result != carrierapi.ResultApplied {
			t.Fatalf("ack: %+v", applied)
		}
		return string(ack.Credential)
	}
	for index, idem := range []string{"a", "b", "c"} {
		if got := ackCredential("hello", idem); got != "receiver credential" {
			t.Fatalf("ack %d does not carry the credential: %q", index, got)
		}
	}
	carrier.mu.Lock()
	carrier.credential[a.d.config.AgentID] = []byte("renewed receiver credential")
	carrier.mu.Unlock()
	if got := ackCredential("after renewal", "d"); got != "renewed receiver credential" {
		t.Fatalf("the renewed credential does not replace the old one: %q", got)
	}
}
