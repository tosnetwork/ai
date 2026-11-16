package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

const relayInviteToken = "invite_" + "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"

func carriedToken(t *testing.T, frame []byte) string {
	t.Helper()
	decoded, err := relayframe.Decode(frame)
	if err != nil {
		t.Fatal(err)
	}
	value, err := relayframe.DecodeCopy(decoded.Part)
	if err != nil {
		t.Fatal(err)
	}
	return value.AdmissionToken
}

// A presented invite rides sealed on every generation of a delivery to its
// Agent, and only an accepted ack settles it: a duplicate does not.
func TestPresentedInviteRidesEveryGenerationAndSettlesOnlyOnAccepted(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	a.d.relay.interval = DefaultRelayRedepositInterval
	a.carrier.ttl = map[string]uint64{b.d.config.AgentID: 3600}
	importContact(t, a, b)
	importContact(t, b, a)
	if _, err := a.d.journal.PresentInvite(b.d.config.AgentID, relayInviteToken, now.Add(24*time.Hour), now); err != nil {
		t.Fatal(err)
	}
	sendText(t, a, b, "carries the invite", "a", now)
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("first deposit: %+v %v", summary, err)
	}
	first := onlyFrame(t, a)
	a.d.now = func() time.Time { return now.Add(48 * time.Minute) }
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("re-deposit: %+v %v", summary, err)
	}
	second := onlyFrame(t, a)
	for index, frame := range [][]byte{first.frame, second.frame} {
		if token := carriedToken(t, frame); token != relayInviteToken {
			t.Fatalf("generation %d carries %q", index+1, token)
		}
	}
	accepted := deliver(t, a, b, first.frame)
	duplicate := deliver(t, a, b, second.frame)
	if accepted.AckOutcome != relayframe.OutcomeAccepted || duplicate.AckOutcome != relayframe.OutcomeDuplicate {
		t.Fatalf("answers: %+v %+v", accepted, duplicate)
	}
	if applied := a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, ackFrameOf(t, duplicate)); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("duplicate ack: %+v", applied)
	}
	if _, found, err := a.d.journal.PresentedInviteFor(b.d.config.AgentID, a.d.now()); err != nil || !found {
		t.Fatalf("a duplicate ack settled the presented invite: %v %v", found, err)
	}
	a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, ackFrameOf(t, accepted))
	if _, found, err := a.d.journal.PresentedInviteFor(b.d.config.AgentID, a.d.now()); err != nil || found {
		t.Fatalf("an accepted ack left the presented invite: %v %v", found, err)
	}
}
