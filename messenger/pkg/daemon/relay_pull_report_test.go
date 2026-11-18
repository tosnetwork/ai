package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// An evidence response or request the carrier refuses is not dropped
// silently: the response is not sent again for that request, the request
// keeps its retry schedule, and each refusal is reported with the carrier's
// result and code.
func TestARefusedEvidenceResponseAndRequestAreReported(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	reports := &recordingReports{}
	a.d.observer, b.d.observer = reports, reports
	refused := carrierapi.Refusal(carrierapi.CodeNoPeerCard)

	// B owes A a response; its carrier refuses it.
	request, _, err := a.d.relay.ownFrame(relayframe.KindEvidence, b.d.config.AgentID,
		[]byte{relayframe.EvidenceRequest}, true)
	if err != nil {
		t.Fatal(err)
	}
	if admitted := deliver(t, a, b, request); admitted.Result != carrierapi.ResultAdmitted {
		t.Fatalf("request: %+v", admitted)
	}
	b.carrier.answer = &refused
	b.d.relay.sweepPulls(context.Background())
	if pull, _, err := b.d.journal.LoadRelayPull(a.d.config.AgentID); err != nil || pull.ResponsePending {
		t.Fatalf("the refused response is still owed: %+v %v", pull, err)
	}
	requireReported(t, reports, "evidence response", a.d.config.AgentID, string(carrierapi.CodeNoPeerCard))

	// A's own request to B is refused by A's carrier: it stays outstanding
	// on its retry schedule and the refusal is reported.
	a.carrier.answer = &refused
	if err := a.d.relay.demandEvidence(b.d.config.AgentID, now); err != nil {
		t.Fatal(err)
	}
	a.d.relay.sweepPulls(context.Background())
	pull, _, err := a.d.journal.LoadRelayPull(b.d.config.AgentID)
	if err != nil || !pull.Requested || pull.RequestGeneration != 0 ||
		pull.RequestNextAtUnix != uint64(now.Add(relayEvidenceRetry).Unix()) {
		t.Fatalf("the refused request's record: %+v %v", pull, err)
	}
	requireReported(t, reports, "evidence request", b.d.config.AgentID, string(carrierapi.CodeNoPeerCard))
}

func requireReported(t *testing.T, reports *recordingReports, parts ...string) {
	t.Helper()
	reports.mutex.Lock()
	defer reports.mutex.Unlock()
	for _, err := range reports.errs {
		text := err.Error()
		found := true
		for _, part := range parts {
			found = found && strings.Contains(text, part)
		}
		if found {
			return
		}
	}
	t.Fatalf("no report names %q among %v", parts, reports.errs)
}
