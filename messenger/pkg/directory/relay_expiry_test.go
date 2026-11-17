package directory

import (
	"testing"
)

// commitAt checks and commits evidence at a time, reporting whether it was
// stored.
func (f *relayFixture) commitAt(evidence []byte, seconds uint64) bool {
	f.t.Helper()
	peer, err := f.verifier.CheckPeer(agentID, evidence, f.pin(relayDeviceOne), at(seconds))
	if err != nil {
		f.t.Fatalf("check: %v", err)
	}
	fresh, err := f.verifier.CommitPeer(peer, at(seconds))
	if err != nil {
		f.t.Fatalf("commit: %v", err)
	}
	return fresh
}

// Only evidence CheckPeer would refuse as expired is swept; the peer stays
// admitted through its floor.
func TestSweepRetiresOnlyExpiredEvidence(t *testing.T) {
	f := newRelayFixture(t)
	evidence := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, nil)
	if !f.commitAt(evidence, baseUnix+200) {
		t.Fatal("first commit")
	}
	if report, err := f.verifier.SweepExpiredEvidence(at(baseUnix + 100 + 3600 - 1)); err != nil || report.Retired != 0 {
		t.Fatalf("a sweep while the evidence is usable: %+v %v", report, err)
	}
	if _, found, _ := f.journal.LoadRelayEvidence(agentID); !found {
		t.Fatal("usable evidence was swept")
	}
	report, err := f.verifier.SweepExpiredEvidence(at(baseUnix + 100 + 3600))
	if err != nil || report.Retired != 1 {
		t.Fatalf("a sweep at the expiry: %+v %v", report, err)
	}
	if _, found, _ := f.journal.LoadRelayEvidence(agentID); found {
		t.Fatal("expired evidence was kept")
	}
	if admitted, err := f.verifier.Admitted(agentID); err != nil || !admitted {
		t.Fatalf("the swept peer lost its admission: %v %v", admitted, err)
	}
	// A repeat sweep has nothing to do.
	if report, err := f.verifier.SweepExpiredEvidence(at(baseUnix + 100 + 3600)); err != nil || report.Retired != 0 {
		t.Fatalf("a repeat sweep: %+v %v", report, err)
	}
}

// The newer-only rule survives a sweep. Expiry is not monotonic in the
// ordering key: here the newer descriptor (issued later) expires first, while
// the older one, with the same device set, is still valid. Once the newer
// record is swept, the older evidence still passes CheckPeer, and only the
// floor refuses it as a rollback; evidence newer than the floor is stored.
func TestSweepKeepsTheRollbackFloor(t *testing.T) {
	f := newRelayFixture(t)
	older := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, nil)
	newer := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, func(d *Descriptor) {
		d.IssuedAtUnix, d.ExpiresAtUnix = baseUnix+300, baseUnix+900
	})
	if !f.commitAt(older, baseUnix+200) || !f.commitAt(newer, baseUnix+400) {
		t.Fatal("the commits")
	}
	if report, err := f.verifier.SweepExpiredEvidence(at(baseUnix + 1000)); err != nil || report.Retired != 1 {
		t.Fatalf("the sweep: %+v %v", report, err)
	}
	if f.commitAt(older, baseUnix+1000) {
		t.Fatal("older evidence was committed over the floor of the swept record")
	}
	if _, found, _ := f.journal.LoadRelayEvidence(agentID); found {
		t.Fatal("a refused rollback wrote a record")
	}
	renewed := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, func(d *Descriptor) {
		d.IssuedAtUnix, d.ExpiresAtUnix = baseUnix+1000, baseUnix+3000
	})
	if !f.commitAt(renewed, baseUnix+1100) {
		t.Fatal("evidence newer than the floor was refused")
	}
	if _, found, _ := f.journal.LoadRelayEvidenceFloor(agentID); found {
		t.Fatal("the floor outlived a newer record")
	}
}

// Evidence is unusable as soon as any part of it expires: a bundle that
// expires before its descriptor makes the record sweepable then.
func TestSweepRetiresEvidenceWhoseBundleExpiredFirst(t *testing.T) {
	f := newRelayFixture(t)
	evidence := f.evidence(relayDeviceOne, "material one", baseUnix+100, 600, func(d *Descriptor) {
		d.ExpiresAtUnix = baseUnix + 100 + 3600
	})
	if !f.commitAt(evidence, baseUnix+200) {
		t.Fatal("commit")
	}
	if report, err := f.verifier.SweepExpiredEvidence(at(baseUnix + 699)); err != nil || report.Retired != 0 {
		t.Fatalf("a sweep before the bundle expired: %+v %v", report, err)
	}
	if report, err := f.verifier.SweepExpiredEvidence(at(baseUnix + 700)); err != nil || report.Retired != 1 {
		t.Fatalf("a sweep once the bundle expired: %+v %v", report, err)
	}
}
