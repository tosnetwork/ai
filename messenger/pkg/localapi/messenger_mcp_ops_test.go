package localapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
)

// A message is held only when every copy was delivered and a recipient's
// signed acknowledgement said held; a copy this installation's own policy
// holds is still pending here, and a copy ended for good is rejected with its
// code.
func TestMessageStatusReportsHeldOnlyFromTheRecipientsAck(t *testing.T) {
	event := "evt_" + strings.Repeat("1", 64)
	delivered := func(outcome string) eventlog.Delivery {
		return eventlog.Delivery{State: eventlog.StateDelivered, RecipientOutcome: outcome}
	}
	cases := []struct {
		name   string
		copies []eventlog.Delivery
		state  string
		code   fault.Code
	}{
		{"pending", []eventlog.Delivery{{State: eventlog.StatePending}}, MessagePending, ""},
		{"held here by the local owner", []eventlog.Delivery{{State: eventlog.StateHeld}}, MessagePending, ""},
		{"carried", []eventlog.Delivery{{State: eventlog.StateCarried}}, MessageCarried, ""},
		{"one of two delivered", []eventlog.Delivery{delivered(eventlog.RecipientHeld), {State: eventlog.StateCarried}},
			MessageCarried, ""},
		{"accepted", []eventlog.Delivery{delivered(eventlog.RecipientAccepted)}, MessageDelivered, ""},
		{"held by the recipient", []eventlog.Delivery{delivered(eventlog.RecipientAccepted), delivered(eventlog.RecipientHeld)},
			MessageHeld, ""},
		{"rejected", []eventlog.Delivery{delivered(eventlog.RecipientAccepted),
			{State: eventlog.StateAbandoned, LastCode: fault.CodeRejected}}, MessageRejected, fault.CodeRejected},
	}
	for _, test := range cases {
		status := summarizeCopies(event, test.copies)
		if status.State != test.state || status.Code != test.code || status.Copies != len(test.copies) {
			t.Fatalf("%s: %+v", test.name, status)
		}
	}
}

func TestMessageStatusOfAnUnknownEventIsRefused(t *testing.T) {
	h := newHarness(t)
	if response := h.call(t, Request{Op: OpMessageStatus, EventID: "evt_" + strings.Repeat("9", 64)}); response.OK {
		t.Fatalf("an unknown message has a status: %+v", response)
	}
	if err := ValidateRequest(Request{Op: OpMessageStatus, EventID: "evt_x"}); err == nil {
		t.Fatal("a non-canonical event was accepted")
	}
}

type standings map[string]ContactStanding

func (s standings) ContactState(_ context.Context, agentID string) (ContactStanding, error) {
	standing, ok := s[agentID]
	if !ok {
		return ContactStanding{}, errors.New("no standing")
	}
	return standing, nil
}

// contacts.state is a runtime read: it answers the daemon's standing, refuses
// a non-canonical state, and is refused on the owner socket.
func TestContactStateIsARuntimeRead(t *testing.T) {
	h := newHarness(t)
	known := "agent_" + strings.Repeat("5", 64)
	odd := "agent_" + strings.Repeat("6", 64)
	h.server.config.ContactStates = standings{known: {State: ContactHeld, RouteKnown: true}, odd: {State: "friend"}}
	response := h.call(t, Request{Op: OpContactState, RecipientAgentID: known})
	if !response.OK || response.Standing == nil || response.Standing.State != ContactHeld || !response.Standing.RouteKnown {
		t.Fatalf("contacts.state: %+v", response)
	}
	if response := h.call(t, Request{Op: OpContactState, RecipientAgentID: odd}); response.OK {
		t.Fatalf("a non-canonical state was answered: %+v", response)
	}
	if Permits(PrincipalOwner, OpContactState) || Permits(PrincipalOwner, OpMessageStatus) {
		t.Fatal("the owner socket serves a runtime read")
	}
	if err := ValidateRequest(Request{Op: OpContactState, RecipientAgentID: known, Recipient: "alice.tos"}); err == nil {
		t.Fatal("contacts.state accepted a human recipient input")
	}
}

// conversations.list counts the unread events the runtime is offered.
func TestConversationsReportTheirUnreadEvents(t *testing.T) {
	h := newHarness(t)
	self := h.server.config.Dispatcher.LocalIdentity().AgentID
	remote := "agent_" + strings.Repeat("7", 64)
	record, _, err := h.journal.EnsureDirectConversation(self, remote, senderMEP, 10, h.clock, [32]byte{4, 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"one", "two"} {
		event, err := envelope.NewEvent(envelope.Event{Network: testNetwork(), ConversationID: record.ConversationID,
			SenderAgentID: remote, SenderEndpointID: senderMEP, SenderDeviceID: senderDev,
			CreatedAtUnix: baseUnix + 1, Kind: "text", Content: textBody(t, body)})
		if err != nil {
			t.Fatal(err)
		}
		h.receive(t, event)
	}
	listing := h.call(t, Request{Op: OpListConversations})
	if !listing.OK || len(listing.Conversations) != 1 || listing.Conversations[0].Unread != 2 {
		t.Fatalf("listing: %+v", listing)
	}
}
