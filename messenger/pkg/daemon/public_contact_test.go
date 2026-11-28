package daemon

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/admission"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/localapi"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// hintContact stands for the builtin lane's directory lookup: the card and
// relay identity evidence one peer's verified hint discloses.
type hintContact struct {
	mu       sync.Mutex
	peer     string
	card     []byte
	evidence []byte
	learned  [][]byte
}

func (h *hintContact) ResolvePublicContact(_ context.Context, peer string) ([]byte, []byte, error) {
	if peer != h.peer {
		return nil, nil, errNoHint
	}
	return bytes.Clone(h.card), bytes.Clone(h.evidence), nil
}

func (h *hintContact) LearnCard(_ context.Context, peer string, card []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if peer == h.peer {
		h.learned = append(h.learned, bytes.Clone(card))
	}
	return nil
}

var errNoHint = errors.New("no hint for this Agent")

// installHintContact gives a node's relay directory a hint lookup that
// discloses peer's public contact.
func installHintContact(t *testing.T, node, peer *relayNode) *hintContact {
	t.Helper()
	evidence, _, _, err := peer.d.relay.sink.Current()
	if err != nil {
		t.Fatal(err)
	}
	card, err := peer.d.relay.sink.Card()
	if err != nil {
		t.Fatal(err)
	}
	source := &hintContact{peer: peer.d.config.AgentID, card: card, evidence: evidence}
	contacts, ok := node.d.discovery.contacts.(relayDirectory)
	if !ok {
		t.Fatal("the node has no relay directory")
	}
	contacts.public = &publicSlot{}
	contacts.public.set(source)
	node.d.discovery.contacts = contacts
	return source
}

// The recipient's signed ack for one carried copy with the given outcome,
// built by the recipient daemon itself.
func signedAck(t *testing.T, from, to *relayNode, frame []byte, outcome admission.Outcome) []byte {
	t.Helper()
	decoded, err := relayframe.Decode(frame)
	if err != nil {
		t.Fatal(err)
	}
	value, err := relayframe.DecodeCopy(decoded.Part)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := to.d.relay.ackFrame(from.d.config.AgentID, value, ReceiveResult{Outcome: outcome})
	if err != nil {
		t.Fatal(err)
	}
	return ackFrameOf(t, answer)
}

// First contact by Agent ID alone: with no contact file, the sender resolves
// the recipient through the contact its hint discloses, sends, and reports
// the recipient as held only once its signed ack says so, and as a contact
// once a later ack accepts.
func TestFirstContactByAgentIDThroughTheHint(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, b, a)
	// A's own inbox is not open: B is not its contact by policy.
	a.d.config.Admission.Rule, a.d.config.Admission.Unknown = admission.RuleAllowList, admission.AskTheOwner
	peer := b.d.config.AgentID
	if _, err := a.d.SendDirectMessage(context.Background(), peer, "text/plain; charset=utf-8", "no route yet",
		"idem_"+string(bytes.Repeat([]byte("f"), 64)), uint64(now.Add(time.Hour).Unix())); err == nil {
		t.Fatal("a message was queued to an Agent without a contact file or a hint")
	}
	if standing, err := a.d.ContactState(context.Background(), peer); err != nil ||
		standing.State != localapi.ContactStranger || standing.RouteKnown {
		t.Fatalf("before resolution: %+v %v", standing, err)
	}
	hint := installHintContact(t, a, b)
	resolved, err := a.d.ResolveContact(context.Background(), peer, nil)
	if err != nil || resolved.AgentID != peer {
		t.Fatalf("resolve by Agent ID: %+v %v", resolved, err)
	}
	if len(hint.learned) != 1 {
		t.Fatalf("the hint's card was learned %d times", len(hint.learned))
	}
	if standing, err := a.d.ContactState(context.Background(), peer); err != nil ||
		standing.State != localapi.ContactStranger || !standing.RouteKnown {
		t.Fatalf("after resolution: %+v %v", standing, err)
	}

	first := sendText(t, a, b, "hello by Agent ID", "a", now)
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("sweep: %+v %v", summary, err)
	}
	frame := onlyFrame(t, a).frame
	if standing, _ := a.d.ContactState(context.Background(), peer); standing.State != localapi.ContactStranger {
		t.Fatalf("held before any ack: %+v", standing)
	}
	if applied := a.d.relay.DeliveryAck(context.Background(), peer, signedAck(t, a, b, frame, admission.Held)); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("held ack: %+v", applied)
	}
	copies, err := a.d.journal.EventCopies(first)
	if err != nil || len(copies) != 1 || copies[0].State != eventlog.StateDelivered ||
		copies[0].RecipientOutcome != eventlog.RecipientHeld {
		t.Fatalf("the held copy: %+v %v", copies, err)
	}
	if standing, _ := a.d.ContactState(context.Background(), peer); standing.State != localapi.ContactHeld {
		t.Fatalf("after the held ack: %+v", standing)
	}

	sendText(t, a, b, "after the owner admitted", "b", now)
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("second sweep: %+v %v", summary, err)
	}
	accepted := deliver(t, a, b, onlyFrame(t, a).frame)
	if accepted.AckOutcome != relayframe.OutcomeAccepted {
		t.Fatalf("the recipient's answer: %+v", accepted)
	}
	a.d.now = func() time.Time { return now.Add(time.Second) }
	if applied := a.d.relay.DeliveryAck(context.Background(), peer, ackFrameOf(t, accepted)); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("accepted ack: %+v", applied)
	}
	if standing, _ := a.d.ContactState(context.Background(), peer); standing.State != localapi.ContactKnown {
		t.Fatalf("after the accepted ack: %+v", standing)
	}
}

// A hint whose disclosed card or evidence is not the Agent's own is refused,
// and nothing is committed: the same checks a contact file gets.
func TestAHintDisclosingAnotherAgentsContactIsRefused(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"}, [2]string{"5", "6"})
	a, b, c := nodes[0], nodes[1], nodes[2]
	peer := b.d.config.AgentID
	for name, mutate := range map[string]func(*hintContact){
		"a card of another Agent": func(h *hintContact) {
			card, err := c.d.relay.sink.Card()
			if err != nil {
				t.Fatal(err)
			}
			h.card = card
		},
		"evidence of another Agent": func(h *hintContact) {
			evidence, _, _, err := c.d.relay.sink.Current()
			if err != nil {
				t.Fatal(err)
			}
			h.evidence = evidence
		},
	} {
		hint := installHintContact(t, a, b)
		mutate(hint)
		if _, err := a.d.ResolveContact(context.Background(), peer, nil); err == nil {
			t.Fatalf("%s: resolved", name)
		}
		if admitted, err := a.d.discovery.relay.Admitted(peer); err != nil || admitted {
			t.Fatalf("%s: committed (%v %v)", name, admitted, err)
		}
		if len(hint.learned) != 0 {
			t.Fatalf("%s: the card was learned", name)
		}
	}
}
