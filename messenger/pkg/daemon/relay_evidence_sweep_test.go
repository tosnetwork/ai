package daemon

import (
	"testing"
	"time"
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
