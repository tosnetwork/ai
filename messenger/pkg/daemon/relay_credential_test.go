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
