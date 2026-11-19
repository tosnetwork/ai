//go:build roomtest

package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// A sender whose prekey planner has started its next generation, inside the
// replenish window but before its publisher has published the descriptor
// for it, makes a first contact. The first-contact bootstrap and the frame's
// relay evidence must name the same bundle: the receiver pins the
// bootstrap's bundle and requires it byte-identical in the evidence, so a
// mismatch is refused (evidence-refused) and the first contact is lost.
func TestRoomTestFirstContactInsideThePublicationLagIsAdmitted(t *testing.T) {
	s := newE2ESceneWith(t, shortGenerations)
	a := s.nodes[nodeA]
	renewal := s.start.Add(e2eShortGeneration - e2eShortReplenish + time.Minute)
	s.clock.set(renewal)
	_, published, _, err := a.d.relay.sink.Current()
	if err != nil {
		t.Fatal(err)
	}
	// The planner rotates; the publisher has not run yet.
	if err := a.d.prekeys.maintainLocalDevice(); err != nil {
		t.Fatalf("A's planner: %v", err)
	}
	if _, still, _, err := a.d.relay.sink.Current(); err != nil || still != published {
		t.Fatalf("the scene must hold the publication lag: published %s, now %s (%v)", published, still, err)
	}
	result, err := a.d.SendDirectMessage(context.Background(), s.agent(nodeD), "text/plain; charset=utf-8",
		"first contact inside the publication lag", "idem_"+strings.Repeat("9", 64),
		uint64(s.clock.now().Unix()+3600))
	if err != nil {
		t.Fatalf("A sends: %v", err)
	}
	s.settle()
	for _, answer := range s.answers {
		if answer.envelope.from != s.agent(nodeA) || answer.envelope.to != s.agent(nodeD) ||
			answer.envelope.kind != relayframe.KindCopy {
			continue
		}
		if answer.response.Result == carrierapi.ResultRefused {
			t.Fatalf("D refused A's first contact: %s %s", answer.response.Result, answer.response.Code)
		}
	}
	s.requireJournaled(result.EventID, nodeD)
}

// The receiver's check is not loosened: a first contact whose bootstrap
// names a bundle the frame's evidence does not carry (here an older copy
// re-sent under the sender's newer publication) is still refused.
func TestRoomTestFirstContactNamingABundleOutsideTheEvidenceIsRefused(t *testing.T) {
	s := newE2ESceneWith(t, shortGenerations)
	a, d := s.nodes[nodeA], s.nodes[nodeD]
	toD := func(envelope mailEnvelope) bool {
		return envelope.from == s.agent(nodeA) && envelope.to == s.agent(nodeD) && envelope.kind == relayframe.KindCopy
	}
	s.box.hold = toD
	if _, err := a.d.SendDirectMessage(context.Background(), s.agent(nodeD), "text/plain; charset=utf-8",
		"first contact", "idem_"+strings.Repeat("8", 64), uint64(s.clock.now().Unix()+3600)); err != nil {
		t.Fatalf("A sends: %v", err)
	}
	s.settle()
	held := s.box.held(toD)
	if len(held) != 1 {
		t.Fatalf("%d copies held to D", len(held))
	}
	s.clock.set(s.start.Add(e2eShortGeneration - e2eShortReplenish + time.Minute))
	s.renewOwnEvidence(nodeA)
	newer, _, _, err := a.d.relay.sink.Current()
	if err != nil {
		t.Fatal(err)
	}
	answer := d.d.relay.Deliver(context.Background(), s.agent(nodeA), withEvidence(t, held[0].frame, newer))
	if answer.Result != carrierapi.ResultRefused || answer.Code != carrierapi.CodeEvidenceRefused {
		t.Fatalf("a bootstrap bundle outside the evidence was answered %s %s", answer.Result, answer.Code)
	}
	// The same copy under the evidence it was sent with is admitted: the
	// refusal above is the bundle mismatch alone.
	if original := d.d.relay.Deliver(context.Background(), s.agent(nodeA), held[0].frame); original.Result != carrierapi.ResultAck {
		t.Fatalf("the copy under its own evidence was answered %s %s", original.Result, original.Code)
	}
}
