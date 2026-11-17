package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/dispatch"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// The relay runtime's sweep (run at start and on the relay timer) retires
// expired relay evidence: the peer's record goes, its floor and admission
// stay; usable evidence is kept.
func TestRelayRuntimeSweepsExpiredEvidence(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	peer := b.d.config.AgentID
	a.d.relay.sweepEvidence()
	if _, found, err := a.d.journal.LoadRelayEvidence(peer); err != nil || !found {
		t.Fatalf("usable evidence was swept: %v %v", found, err)
	}
	later := now.Add(2 * time.Hour)
	a.d.now = func() time.Time { return later }
	a.d.relay.sweepEvidence()
	if _, found, _ := a.d.journal.LoadRelayEvidence(peer); found {
		t.Fatal("expired evidence survived the sweep")
	}
	if _, found, _ := a.d.journal.LoadRelayEvidenceFloor(peer); !found {
		t.Fatal("the swept peer has no floor")
	}
	if admitted, err := a.d.relay.verifier.Admitted(peer); err != nil || !admitted {
		t.Fatalf("the swept peer lost its admission: %v %v", admitted, err)
	}
}

// reinstallRelay restarts a node's relay runtime on a fresh dispatcher, as a
// daemon start does, so the start-time sweep runs.
func reinstallRelay(t *testing.T, node *relayNode) {
	t.Helper()
	d := node.d
	dispatcher, err := dispatch.New(dispatch.Config{Journal: d.journal, Identity: d.config.Identity(),
		Network: d.config.Network(), Now: d.clock, AllowedEventClasses: d.prekeys.planner.delegation.AllowedOutboundEventClasses})
	if err != nil {
		t.Fatal(err)
	}
	d.dispatch = dispatcher
	if err := d.installRelayRuntime(d.relay.sink, node.carrier, MinRelayRedepositInterval, 30*time.Second); err != nil {
		t.Fatalf("restart the relay runtime: %v", err)
	}
}

// The relay runtime sweeps expired evidence when it starts.
func TestRelayRuntimeSweepsExpiredEvidenceAtStart(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	peer := b.d.config.AgentID
	reinstallRelay(t, a)
	if _, found, _ := a.d.journal.LoadRelayEvidence(peer); !found {
		t.Fatal("usable evidence was swept at start")
	}
	later := now.Add(2 * time.Hour)
	a.d.now = func() time.Time { return later }
	reinstallRelay(t, a)
	if _, found, _ := a.d.journal.LoadRelayEvidence(peer); found {
		t.Fatal("expired evidence survived the start")
	}
	if _, found, _ := a.d.journal.LoadRelayEvidenceFloor(peer); !found {
		t.Fatal("the swept peer has no floor")
	}
}

// writeFloor writes a floor record straight into a node's floor store.
func writeFloor(t *testing.T, node *relayNode, agentID string, issued, retired uint64) {
	t.Helper()
	encoded, err := json.Marshal(eventlog.RelayEvidenceFloor{Schema: eventlog.RelayFloorSchema, AgentID: agentID,
		DescriptorDigest: canon.Digest([]byte(agentID)), DescriptorIssuedAtUnix: issued, RetiredAtUnix: retired})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(node.d.config.StateDir, "relay-evidence-floor", agentID[len("agent_"):]+".json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A full floor store never evicts the floor of a peer with a session here:
// that floor is its admission. With no other floor evictable, the expired
// record is kept, and the session peer's kind-4 evidence response is still
// processed.
func TestFullFloorStoreKeepsTheFloorOfASessionPeer(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"}, [2]string{"5", "6"})
	a, b, c := nodes[0], nodes[1], nodes[2]
	importContact(t, a, b)
	importContact(t, b, a)
	sendText(t, a, b, "establish", "a", now)
	if _, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, ackFrameOf(t, deliver(t, a, b, onlyFrame(t, a).frame)))
	peer := b.d.config.AgentID
	// B's evidence was retired long ago: only its floor, past the horizon,
	// stands for it, beside a session.
	if err := os.Remove(filepath.Join(a.d.config.StateDir, "relay-evidence", peer[len("agent_"):]+".json")); err != nil {
		t.Fatal(err)
	}
	old := uint64(now.Add(-8 * 24 * time.Hour).Unix())
	writeFloor(t, a, peer, old, old)
	// Every other slot holds a floor inside its horizon.
	for index := 1; index < eventlog.MaxRelayFloors; index++ {
		writeFloor(t, a, fmt.Sprintf("agent_%064x", index), uint64(now.Add(-time.Hour).Unix()), uint64(now.Unix()))
	}
	// C's stored evidence has expired; retiring it needs a floor slot.
	if err := a.d.journal.StoreRelayEvidence(c.d.config.AgentID, oldEvidence(t, c, now), "", now); err != nil {
		t.Fatal(err)
	}
	a.d.relay.sweepEvidence()
	if _, found, _ := a.d.journal.LoadRelayEvidenceFloor(peer); !found {
		t.Fatal("the floor of a peer with a session was evicted")
	}
	if _, found, _ := a.d.journal.LoadRelayEvidence(c.d.config.AgentID); !found {
		t.Fatal("an expired record was retired without a floor slot")
	}
	frame, _, err := b.d.relay.ownFrame(relayframe.KindEvidence, a.d.config.AgentID, []byte{relayframe.EvidenceResponse}, true)
	if err != nil {
		t.Fatal(err)
	}
	if response := a.d.relay.Deliver(context.Background(), peer, frame); response.Result != carrierapi.ResultAdmitted {
		t.Fatalf("the session peer's evidence response: %s/%s", response.Result, response.Code)
	}
}
