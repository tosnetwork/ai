package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/admission"
	"github.com/tosnetwork/ai/messenger/pkg/dispatch"
	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/payload"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// A room-addressed device copy is never sealed or carried on the relay
// route: room content crosses it only as an MLS room object.
func TestRelaySenderRefusesARoomAddressedCopy(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	first := sendText(t, a, b, "establish", "a", now)
	if _, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, ackFrameOf(t, deliver(t, a, b, onlyFrame(t, a).frame)))
	delivered := copyState(t, a, first, b.d.config.EndpointID, b.d.config.DeviceID)

	content, err := payload.Encode(payload.Text{MediaType: "text/plain; charset=utf-8", Body: "room content"})
	if err != nil {
		t.Fatal(err)
	}
	event, err := envelope.NewEvent(envelope.Event{Network: a.d.config.Network(), ConversationID: delivered.ConversationID,
		SenderAgentID: a.d.config.AgentID, SenderEndpointID: a.d.config.EndpointID, SenderDeviceID: a.d.config.DeviceID,
		RoomID:        "room_" + strings.Repeat("c", 64),
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), Kind: "text",
		IdempotencyKey: strings.Repeat("f", 64), Content: content})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.d.dispatch.QueueCopies(event, []dispatch.CopyTarget{{SessionID: delivered.SessionID,
		RecipientEndpointID: b.d.config.EndpointID, RecipientDeviceID: b.d.config.DeviceID}}, event.ExpiresAtUnix); err != nil {
		t.Fatal(err)
	}
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 0 {
		t.Fatalf("sweep: %+v %v", summary, err)
	}
	if frames := a.carrier.take(); len(frames) != 0 {
		t.Fatalf("a room-addressed copy was carried: %d frames", len(frames))
	}
	state := copyState(t, a, event.EventID, b.d.config.EndpointID, b.d.config.DeviceID)
	if state.State == eventlog.StateCarried || state.State == eventlog.StateDelivered || state.LastCode != fault.CodePayloadMalformed {
		t.Fatalf("room-addressed copy: %+v", state)
	}
}

// The receiver refuses a room-addressed Event on the relay route with a
// signed rejection before admission, and only on that route.
func TestRelayReceiverRefusesARoomAddressedEvent(t *testing.T) {
	event := envelope.Event{EventID: "evt_" + strings.Repeat("1", 64), Kind: "text", RoomID: "room_" + strings.Repeat("c", 64)}
	refused, ok := refuseOnRoute(admission.RouteRelay, event)
	if !ok || refused.Outcome != admission.Rejected || refused.Code != fault.CodePayloadMalformed || refused.EventID != event.EventID {
		t.Fatalf("room-addressed Event on the relay route: %+v %v", refused, ok)
	}
	if !fault.PeerVisible(fault.CodePayloadMalformed) {
		t.Fatal("the rejection code would not reach the sender")
	}
	if _, ok := refuseOnRoute(admission.RouteHTTPS, event); ok {
		t.Fatal("a room-addressed Event was refused on another route")
	}
	event.RoomID = ""
	if _, ok := refuseOnRoute(admission.RouteRelay, event); ok {
		t.Fatal("an Event naming no room was refused")
	}
}

// openSealGate lets every copy through, standing in for a sender that skips
// the relay route's own refusal, so the receiver's is tested on its own.
type openSealGate struct{}

func (openSealGate) CheckCopy(context.Context, eventlog.Delivery, bool) error { return nil }

// A first-contact copy naming a room is refused by the receiver with a
// signed payload-malformed rejection before anything is committed: no
// session and no inbound record.
func TestRelayFirstContactRoomAddressedEventIsRefused(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	delegation := a.d.prekeys.planner.delegation
	dispatcher, err := dispatch.New(dispatch.Config{Journal: a.d.journal, Identity: a.d.config.Identity(),
		Network: a.d.config.Network(), Now: a.d.clock, AllowedEventClasses: delegation.AllowedOutboundEventClasses})
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.ConfigureTransport(a.d.prekeys.suite, relaySender{relay: a.d.relay},
		dispatch.SessionBindings{Journal: a.d.journal, Identity: a.d.config.Identity(), Network: a.d.config.Network()}); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.ConfigureSealGate(openSealGate{}); err != nil {
		t.Fatal(err)
	}
	a.d.dispatch = dispatcher
	// The first-contact text fixes the session and bootstrap; it is never
	// delivered, so B has no session when the room-addressed copy arrives.
	first := sendText(t, a, b, "first contact", "a", now)
	target := copyState(t, a, first, b.d.config.EndpointID, b.d.config.DeviceID)
	content, err := payload.Encode(payload.Text{MediaType: "text/plain; charset=utf-8", Body: "room content"})
	if err != nil {
		t.Fatal(err)
	}
	event, err := envelope.NewEvent(envelope.Event{Network: a.d.config.Network(), ConversationID: target.ConversationID,
		SenderAgentID: a.d.config.AgentID, SenderEndpointID: a.d.config.EndpointID, SenderDeviceID: a.d.config.DeviceID,
		RoomID:        "room_" + strings.Repeat("c", 64),
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), Kind: "text",
		IdempotencyKey: strings.Repeat("9", 64), Content: content})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.d.dispatch.QueueCopies(event, []dispatch.CopyTarget{{SessionID: target.SessionID,
		RecipientEndpointID: b.d.config.EndpointID, RecipientDeviceID: b.d.config.DeviceID}}, event.ExpiresAtUnix); err != nil {
		t.Fatal(err)
	}
	if _, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	var roomFrame []byte
	for _, frame := range a.carrier.take() {
		decoded, err := relayframe.Decode(frame.frame)
		if err != nil {
			t.Fatal(err)
		}
		value, err := relayframe.DecodeCopy(decoded.Part)
		if err != nil {
			t.Fatal(err)
		}
		if value.EventID == event.EventID {
			if len(value.Bootstrap) == 0 {
				t.Fatal("the room-addressed copy is not a first contact")
			}
			roomFrame = frame.frame
		}
	}
	if roomFrame == nil {
		t.Fatal("the room-addressed copy was not carried")
	}
	answer := deliver(t, a, b, roomFrame)
	ack, err := relayframe.Decode(ackFrameOf(t, answer))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := relayframe.DecodeAck(ack.Part)
	if err != nil || decoded.Outcome != relayframe.OutcomeRejected || decoded.Code != fault.CodePayloadMalformed {
		t.Fatalf("answer: %+v %v", decoded, err)
	}
	if _, found, err := b.d.journal.SessionState(target.SessionID); err != nil || found {
		t.Fatalf("the refused first contact left a session: %v %v", found, err)
	}
	if _, found, _ := b.d.journal.Lookup(event.EventID); found {
		t.Fatal("the refused first contact was committed")
	}
}
