package daemon

import (
	"bytes"
	"context"
	"os"
	"sync"
	"testing"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"time"
)

// exactCarrier journals the first frame of each key and refuses other bytes
// under it, as the builtin lane does; CarryFrame carries the journaled frame.
// The first deposit of every key is answered retry.
type exactCarrier struct {
	*recordingCarrier
	mu      sync.Mutex
	journal map[string][]byte
}

func (c *exactCarrier) first(key string, frame []byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sent, known := c.journal[key]
	if !known {
		sent = bytes.Clone(frame)
		c.journal[key] = sent
	}
	return sent, !known
}

func (c *exactCarrier) Carry(ctx context.Context, recipient, key, withdraw string, expires uint64,
	frame []byte) (carrierapi.Response, error) {
	sent, fresh := c.first(key, frame)
	if !bytes.Equal(sent, frame) {
		return carrierapi.Refusal(carrierapi.CodeInvalidRequest), nil
	}
	response, err := c.recordingCarrier.Carry(ctx, recipient, key, withdraw, expires, sent)
	if fresh {
		return carrierapi.Retry(), err
	}
	return response, err
}

func (c *exactCarrier) CarryFrame(ctx context.Context, recipient, key, withdraw string, expires uint64,
	frame []byte) (carrierapi.Response, []byte, error) {
	sent, fresh := c.first(key, frame)
	response, err := c.recordingCarrier.Carry(ctx, recipient, key, withdraw, expires, sent)
	if fresh {
		return carrierapi.Retry(), sent, err
	}
	return response, sent, err
}

// renewCard writes a new chat card for the node, as the lane does when its
// card renews: frames built afterwards carry other bytes.
func renewCard(t *testing.T, node *relayNode) {
	t.Helper()
	card := relayCardAt(t, node.d.config.AgentID, 2, 2, 1_899_900_100,
		1_899_900_100+uint64(agentpacketseal.MaxKeyCardLifetime/time.Second))
	if err := os.WriteFile(node.cardPath, card, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A room message answered retry, then retried after the sender's card
// renewed, carries the frame first journaled for its key and is carried, not
// abandoned as a key with other bytes.
func TestARoomMessageRetriedAfterACardRenewalIsCarried(t *testing.T) {
	scene := twoMemberRoom(t)
	a, b := scene.nodes[0], scene.nodes[1]
	a.d.relay.carrier = &exactCarrier{recordingCarrier: a.carrier, journal: map[string][]byte{}}
	if _, _, err := scene.compose(t, 0, "across a renewal", "4"); err != nil {
		t.Fatal(err)
	}
	if delivery := applicationMember(t, a, idem("4"), b.d.config.AgentID); delivery.State != eventlog.RoomDeliveryPending {
		t.Fatalf("the first attempt: %+v", delivery)
	}
	first := roomFrames(t, a, b.d.config.AgentID)
	renewCard(t, a)
	scene.clock.set(scene.clock.now().Add(roomApplicationRetry))
	scene.rooms(0).maintain()
	if delivery := applicationMember(t, a, idem("4"), b.d.config.AgentID); delivery.State != eventlog.RoomDeliveryCarried {
		t.Fatalf("the retry after the card renewal: %+v", delivery)
	}
	again := roomFrames(t, a, b.d.config.AgentID)
	if len(first) != 1 || len(again) != 1 || !bytes.Equal(first[0].frame, again[0].frame) {
		t.Fatal("the retry did not carry the journaled frame")
	}
}

// A handshake object answered retry, then retried after the authority's card
// renewed, is carried under the same generation, not abandoned with its
// member's queue stopped.
func TestARoomFanOutRetriedAfterACardRenewalIsCarried(t *testing.T) {
	scene := newOperatorScene(t, 2)
	a, b := scene.nodes[0], scene.nodes[1]
	a.d.relay.carrier = &exactCarrier{recordingCarrier: a.carrier, journal: map[string][]byte{}}
	scene.founded(t)
	scene.invited(t, 1)
	scene.joined(t, 1)
	agent := b.d.config.AgentID
	if tried := objectsTo(t, a, agent); len(tried) != 1 {
		t.Fatalf("%d deposits tried", len(tried))
	}
	if welcome, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent); welcome.State != eventlog.RoomDeliveryPending {
		t.Fatalf("a retried deposit: %+v", welcome)
	}
	renewCard(t, a)
	scene.clock.set(scene.clock.now().Add(handshakeBackoffBase))
	scene.rooms(0).maintain()
	if welcome, _ := memberDelivery(t, a, eventlog.RoomObjectWelcome, agent); welcome.State != eventlog.RoomDeliveryCarried ||
		welcome.Generation != 1 {
		t.Fatalf("the retry after the card renewal: %+v", welcome)
	}
}
