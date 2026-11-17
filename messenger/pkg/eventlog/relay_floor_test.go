package eventlog

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
)

func relayTestAgent(index int) string { return fmt.Sprintf("agent_%064x", index+1) }

func relayTestFloor(issued uint64) RelayEvidenceFloor {
	return RelayEvidenceFloor{DescriptorDigest: canon.Digest([]byte(fmt.Sprint("descriptor", issued))), DescriptorIssuedAtUnix: issued}
}

// Retiring a record frees its slot in the peer bound and leaves a floor;
// a record whose digest changed is not retired.
func TestRelayEvidenceRetirementFreesTheCapAndKeepsAFloor(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	previous := relayPeerCap
	relayPeerCap = 2
	defer func() { relayPeerCap = previous }()
	now := time.Unix(1_900_000_000, 0)
	for index := range 2 {
		if err := journal.StoreRelayEvidence(relayTestAgent(index), []byte(fmt.Sprint("evidence", index)), "", now); err != nil {
			t.Fatal(err)
		}
	}
	if err := journal.StoreRelayEvidence(relayTestAgent(2), []byte("evidence 2"), "", now); !errors.Is(err, ErrRelayPeersFull) {
		t.Fatalf("a third peer at the bound: %v", err)
	}
	if retired, err := journal.RetireRelayEvidence(relayTestAgent(0), canon.Digest([]byte("other")), relayTestFloor(100), time.Hour, now); err != nil || retired {
		t.Fatalf("a record retired under another digest: %v %v", retired, err)
	}
	retired, err := journal.RetireRelayEvidence(relayTestAgent(0), canon.Digest([]byte("evidence0")), relayTestFloor(100), time.Hour, now)
	if err != nil || !retired {
		t.Fatalf("retire: %v %v", retired, err)
	}
	if _, found, err := journal.LoadRelayEvidence(relayTestAgent(0)); err != nil || found {
		t.Fatalf("the retired record is still there: %v %v", found, err)
	}
	if floor, found, err := journal.LoadRelayEvidenceFloor(relayTestAgent(0)); err != nil || !found || floor.DescriptorIssuedAtUnix != 100 {
		t.Fatalf("the floor: %+v %v %v", floor, found, err)
	}
	if err := journal.StoreRelayEvidence(relayTestAgent(2), []byte("evidence 2"), "", now); err != nil {
		t.Fatalf("a new peer after a retirement: %v", err)
	}
	// Newer evidence for the retired peer makes the record the floor again.
	if err := journal.StoreRelayEvidence(relayTestAgent(0), []byte("evidence 0 newer"), "", now); !errors.Is(err, ErrRelayPeersFull) {
		t.Fatalf("the bound counts records only: %v", err)
	}
	if _, err := journal.RetireRelayEvidence(relayTestAgent(1), canon.Digest([]byte("evidence1")), relayTestFloor(150), time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if err := journal.StoreRelayEvidence(relayTestAgent(0), []byte("evidence 0 newer"), "", now); err != nil {
		t.Fatal(err)
	}
	if _, found, err := journal.LoadRelayEvidenceFloor(relayTestAgent(0)); err != nil || found {
		t.Fatalf("a committed record left its floor behind: %v %v", found, err)
	}
}

// A crash between the floor write and the record deletion leaves both; the
// next retirement finishes it.
func TestRelayEvidenceRetirementCrashIsFinishedLater(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	now := time.Unix(1_900_000_000, 0)
	agent := relayTestAgent(0)
	if err := journal.StoreRelayEvidence(agent, []byte("evidence"), "", now); err != nil {
		t.Fatal(err)
	}
	beforeRelayEvidenceDelete = func() error { return errors.New("crash") }
	_, err = journal.RetireRelayEvidence(agent, canon.Digest([]byte("evidence")), relayTestFloor(100), time.Hour, now)
	beforeRelayEvidenceDelete = nil
	if err == nil {
		t.Fatal("the crash did not stop the retirement")
	}
	if _, found, _ := journal.LoadRelayEvidence(agent); !found {
		t.Fatal("the record went before its floor was durable")
	}
	if _, found, _ := journal.LoadRelayEvidenceFloor(agent); !found {
		t.Fatal("the floor was not written first")
	}
	if retired, err := journal.RetireRelayEvidence(agent, canon.Digest([]byte("evidence")), relayTestFloor(100), time.Hour, now); err != nil || !retired {
		t.Fatalf("the retirement after the crash: %v %v", retired, err)
	}
	if _, found, _ := journal.LoadRelayEvidence(agent); found {
		t.Fatal("the record survived the finished retirement")
	}
}

// The floors are bounded: when full, a floor past its horizon makes room,
// and with every floor inside its horizon the record is kept.
func TestRelayEvidenceFloorsAreBoundedByTheirHorizon(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	previous := relayFloorCap
	relayFloorCap = 1
	defer func() { relayFloorCap = previous }()
	now := time.Unix(1_900_000_000, 0)
	for index := range 2 {
		if err := journal.StoreRelayEvidence(relayTestAgent(index), []byte(fmt.Sprint("evidence", index)), "", now); err != nil {
			t.Fatal(err)
		}
	}
	issued := uint64(now.Unix()) - 100
	if retired, err := journal.RetireRelayEvidence(relayTestAgent(0), canon.Digest([]byte("evidence0")), relayTestFloor(issued), time.Hour, now); err != nil || !retired {
		t.Fatalf("the first retirement: %v %v", retired, err)
	}
	retired, err := journal.RetireRelayEvidence(relayTestAgent(1), canon.Digest([]byte("evidence1")), relayTestFloor(issued), time.Hour, now)
	if err != nil || retired {
		t.Fatalf("a retirement with the floors full inside their horizon: %v %v", retired, err)
	}
	if _, found, _ := journal.LoadRelayEvidence(relayTestAgent(1)); !found {
		t.Fatal("a record was retired without a floor")
	}
	later := now.Add(time.Hour)
	if retired, err := journal.RetireRelayEvidence(relayTestAgent(1), canon.Digest([]byte("evidence1")), relayTestFloor(issued+50), time.Hour, later); err != nil || !retired {
		t.Fatalf("a retirement once the old floor passed its horizon: %v %v", retired, err)
	}
	if _, found, _ := journal.LoadRelayEvidenceFloor(relayTestAgent(0)); found {
		t.Fatal("the floor past its horizon was kept")
	}
}
