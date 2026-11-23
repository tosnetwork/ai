package servicebridge

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/execution/pkg/railgate"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

func TestTheDailyCountUsesTheAdmissionTimeAndFallsBackToTheUpdateTime(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	day := int64(AdmissionDay / time.Second)
	records := []ProviderRecord{
		// Admitted inside the day.
		{AdmittedUnix: now.Unix() - 10, UpdatedUnix: now.Unix() - 5},
		// Admitted before the day and updated many times since: counted
		// once at its admission, so not at all.
		{AdmittedUnix: now.Unix() - day - 1, UpdatedUnix: now.Unix()},
		// Written before admitted_unix existed: counted at its update time.
		{UpdatedUnix: now.Unix() - 100},
		{UpdatedUnix: now.Unix() - day},
		// A clock set back: counted.
		{AdmittedUnix: now.Unix() + 3600, UpdatedUnix: now.Unix() + 3600},
	}
	if got := AdmissionsInLastDay(records, now); got != 3 {
		t.Fatalf("counted %d admissions, want 3", got)
	}
	if got := AdmissionsInLastDay(nil, now); got != 0 {
		t.Fatalf("an empty list counted %d", got)
	}
	limit := DailyAdmissionCap{Max: 3}
	err := limit.AllowAdmission(now, records)
	if !errors.Is(err, ErrAdmissionLimited) || !errors.Is(err, ErrAdmissionPaused) {
		t.Fatalf("at the cap: %v", err)
	}
	if err := (DailyAdmissionCap{Max: 4}).AllowAdmission(now, records); err != nil {
		t.Fatalf("under the cap: %v", err)
	}
	if err := (DailyAdmissionCap{}).AllowAdmission(now, nil); err == nil {
		t.Fatal("a cap of zero admitted")
	}
}

// A record written before admitted_unix existed decodes as it is, and a
// record that has the field keeps it through a store.
func TestAProviderRecordWithoutTheAdmissionTimeStillReads(t *testing.T) {
	directory := filepath.Join(privateStateDir(t), "provider")
	if err := ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	old := `{"schema":"tos.openfox.rail-provider-request.v1","state":"acked","buyer_agent_id":"agent_` +
		strings.Repeat("c3", 32) + `","capability_id":"cap","quote_commitment":"` + strings.Repeat("11", 32) +
		`","actor":"0:` + strings.Repeat("77", 32) + `","request_id":3,"request_hash":"` + strings.Repeat("22", 32) +
		`","deliveries":1,"updated_unix":1799990000}`
	if err := os.WriteFile(filepath.Join(directory, strings.Repeat("ab", 32)+".json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	records, err := ReadProviderRecords(filepath.Dir(directory))
	if err != nil || len(records) != 1 || records[0].AdmittedUnix != 0 || records[0].AdmissionTime() != 1_799_990_000 {
		t.Fatalf("an old record: %+v %v", records, err)
	}
	encoded, err := json.Marshal(records[0])
	if err != nil || strings.Contains(string(encoded), "admitted_unix") {
		t.Fatalf("an old record gained an admission time: %s %v", encoded, err)
	}
}

// A record of this release, as stored, reads back with its admission time,
// and the admission count takes that time rather than the update time.
func TestAProviderRecordWithTheAdmissionTimeReadsAsStored(t *testing.T) {
	directory := filepath.Join(privateStateDir(t), "provider")
	if err := ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	stored := `{"schema":"tos.openfox.rail-provider-request.v1","state":"acked","buyer_agent_id":"agent_` +
		strings.Repeat("c3", 32) + `","capability_id":"cap","quote_commitment":"` + strings.Repeat("11", 32) +
		`","actor":"0:` + strings.Repeat("77", 32) + `","request_id":3,"request_hash":"` + strings.Repeat("22", 32) +
		`","deliveries":1,"updated_unix":1799990000,"admitted_unix":1799900000}`
	if err := os.WriteFile(filepath.Join(directory, strings.Repeat("ab", 32)+".json"), []byte(stored), 0o600); err != nil {
		t.Fatal(err)
	}
	records, err := ReadProviderRecords(filepath.Dir(directory))
	if err != nil || len(records) != 1 || records[0].AdmittedUnix != 1_799_900_000 ||
		records[0].AdmissionTime() != 1_799_900_000 {
		t.Fatalf("a record with its admission time: %+v %v", records, err)
	}
	// One day after the admission, though less than a day after the update,
	// the request no longer counts.
	if got := AdmissionsInLastDay(records, time.Unix(1_799_900_000+int64(AdmissionDay/time.Second), 0)); got != 0 {
		t.Fatalf("counted %d admissions a day after the admission", got)
	}
}

type refusingLimiter struct{ calls int }

func (l *refusingLimiter) AllowAdmission(time.Time, []ProviderRecord) error {
	l.calls++
	return errors.New("not now")
}

func TestALimitedTaskIsHeldAndNeverCountedAsAFailedHandling(t *testing.T) {
	state := privateStateDir(t)
	inbox, _ := openTestInbox(t, 2, 4)
	if err := putTask(t, inbox, 1); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(state, "provider")
	if err := ensurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	limiter := &refusingLimiter{}
	var reports []string
	service := &Service{
		Inbox: inbox,
		// No gate is configured: a task the limiter did not stop would fail
		// with the gate's own error instead.
		Provider: &Provider{config: ProviderConfig{
			AgentID: testSeller, Network: testNetwork, CapabilityID: gfCapability, Version: "1.0.0",
			StateDir: state, Directory: directory, Limiter: limiter, Now: time.Now,
		}},
		Report: func(stage string, err error) { reports = append(reports, stage+": "+err.Error()) },
	}
	for round := 0; round < 2*maxHandlingAttempts; round++ {
		if err := service.Dispatch(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if pending, err := inbox.Pending(); err != nil || len(pending) != 1 {
		t.Fatalf("a held task was retired: %d %v", len(pending), err)
	}
	if limiter.calls != 2*maxHandlingAttempts || len(reports) != 2*maxHandlingAttempts {
		t.Fatalf("%d limiter calls and %d reports over %d rounds", limiter.calls, len(reports), 2*maxHandlingAttempts)
	}
	for _, line := range reports {
		if !strings.HasPrefix(line, "admission paused: ") || !strings.Contains(line, "admission limit is reached") {
			t.Fatalf("a held task was reported as %q", line)
		}
	}
}

func TestTheDailyCapHoldsATaskUntilAnAdmissionLeavesTheDay(t *testing.T) {
	ctx := context.Background()
	service := startRealExecutor(t, shortSocketDir(t), &fakeRuntime{}, nil)
	fixture := newGateFixture(t, serviceFixtureStart)
	state := serviceState(t)
	node := openServiceNode(t, fixture, state, ownClient(t, service.socket))
	node.provider.config.Limiter = DailyAdmissionCap{Max: 2}
	start := fixture.clock.Now()
	// Two earlier admissions: one 10 s short of leaving the day, one updated
	// just now but admitted long ago, which does not count.
	earlier := []ProviderRecord{
		{Schema: providerRecordSchema, State: ProviderAcked, Actor: "0:" + strings.Repeat("66", 32), RequestID: 1,
			AdmittedUnix: start.Unix() - int64(AdmissionDay/time.Second) + 10, UpdatedUnix: start.Unix()},
		{Schema: providerRecordSchema, State: ProviderAcked, Actor: "0:" + strings.Repeat("66", 32), RequestID: 2,
			UpdatedUnix: start.Unix() - 60},
		{Schema: providerRecordSchema, State: ProviderAcked, Actor: "0:" + strings.Repeat("66", 32), RequestID: 3,
			AdmittedUnix: start.Unix() - int64(AdmissionDay/time.Second) - 1, UpdatedUnix: start.Unix()},
	}
	for index, record := range earlier {
		name := filepath.Join(state, "provider", strings.Repeat(string(rune('a'+index)), 64)+".json")
		if err := writeJSON(name, record, true); err != nil {
			t.Fatal(err)
		}
	}
	err := node.provider.HandleTask(ctx, fixture.message)
	if !errors.Is(err, ErrAdmissionLimited) || !errors.Is(err, ErrAdmissionPaused) {
		t.Fatalf("at the cap: %v", err)
	}
	if slotCount(t, state) != 0 || service.backend.runs() != 0 {
		t.Fatal("a task held at the cap took a slot or ran")
	}
	// Eleven seconds later the oldest admission has left the day.
	fixture.clock.Set(start.Add(11 * time.Second))
	if err := node.provider.HandleTask(ctx, fixture.message); err != nil {
		t.Fatalf("after the count fell: %v", err)
	}
	records, err := node.provider.Records()
	if err != nil {
		t.Fatal(err)
	}
	var admitted *ProviderRecord
	for index := range records {
		if records[index].RequestHash == hex.EncodeToString(fixture.message.RequestHash[:]) {
			admitted = &records[index]
		}
	}
	if admitted == nil || admitted.AdmittedUnix != start.Unix()+11 {
		t.Fatalf("the admitted record: %+v", admitted)
	}
}

// The limiter fails closed: when the provider records cannot be read, the
// count is unknown and the task is held, never admitted. A limiter that
// would admit anything is configured, so only the read failure can hold.
func TestARecordReadFailureHoldsTheTask(t *testing.T) {
	ctx := context.Background()
	service := startRealExecutor(t, shortSocketDir(t), &fakeRuntime{}, nil)
	fixture := newGateFixture(t, serviceFixtureStart)
	state := serviceState(t)
	node := openServiceNode(t, fixture, state, ownClient(t, service.socket))
	node.provider.config.Limiter = DailyAdmissionCap{Max: 1_000_000}
	broken := filepath.Join(state, "provider", strings.Repeat("e", 64)+".json")
	if err := os.WriteFile(broken, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := node.provider.HandleTask(ctx, fixture.message)
	if !errors.Is(err, ErrAdmissionLimited) || !errors.Is(err, ErrAdmissionPaused) {
		t.Fatalf("with an unreadable record: %v", err)
	}
	if slotCount(t, state) != 0 || service.backend.runs() != 0 {
		t.Fatal("a task was admitted while the records could not be read")
	}
	// With the record readable again the same task is admitted.
	if err := os.Remove(broken); err != nil {
		t.Fatal(err)
	}
	if err := node.provider.HandleTask(ctx, fixture.message); err != nil {
		t.Fatalf("once the records read: %v", err)
	}
}

// admitted_unix is written once, at admission, and later updates move only
// updated_unix.
func TestTheAdmissionTimeIsWrittenOnceAndNeverMoved(t *testing.T) {
	ctx := context.Background()
	service := startRealExecutor(t, shortSocketDir(t), &fakeRuntime{}, nil)
	fixture := newGateFixture(t, serviceFixtureStart)
	node := openServiceNode(t, fixture, serviceState(t), ownClient(t, service.socket))
	admittedAt := fixture.clock.Now().Unix()
	if err := node.provider.HandleTask(ctx, fixture.message); err != nil {
		t.Fatal(err)
	}
	record := node.record(t)
	if record.AdmittedUnix != admittedAt || record.State != ProviderResponding {
		t.Fatalf("after admission: %+v", record)
	}
	fixture.clock.Set(time.Unix(admittedAt+120, 0))
	node.history.finalize(record.ResponseHash)
	if err := node.provider.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	later := node.record(t)
	if later.State != ProviderDelivering || later.UpdatedUnix != admittedAt+120 || later.AdmittedUnix != admittedAt {
		t.Fatalf("after an update: state %s, updated %d, admitted %d", later.State, later.UpdatedUnix,
			later.AdmittedUnix)
	}
	if got := AdmissionsInLastDay([]ProviderRecord{later}, time.Unix(admittedAt+int64(AdmissionDay/time.Second), 0)); got != 0 {
		t.Fatalf("an admission a day old counted %d", got)
	}
	// The provider's common update path (as after an execution ends) moves
	// only updated_unix too.
	fixture.clock.Set(time.Unix(admittedAt+600, 0))
	key := railgate.SlotKey{QuoteCommitment: later.QuoteCommitment, Actor: later.Actor, RequestID: later.RequestID}
	if err := node.provider.store(key, later, false); err != nil {
		t.Fatal(err)
	}
	stored := node.record(t)
	if stored.UpdatedUnix != admittedAt+600 || stored.AdmittedUnix != admittedAt {
		t.Fatalf("after a store: updated %d, admitted %d", stored.UpdatedUnix, stored.AdmittedUnix)
	}
}

type fakeAccountSession struct {
	account toschain.FinalizedAccount
	err     error
	asked   string
}

func (s *fakeAccountSession) Checkpoint() uint64 { return 77 }

func (s *fakeAccountSession) Account(_ context.Context, account string) (toschain.FinalizedAccount, error) {
	s.asked = account
	return s.account, s.err
}

func TestTheWalletBalanceIsReadAtTheSessionCheckpoint(t *testing.T) {
	session := &fakeAccountSession{account: toschain.FinalizedAccount{State: "active", BalanceNano: 5}}
	balance, err := ReadWalletBalance(context.Background(), session, testWallet)
	if err != nil || balance.BalanceNano != 5 || balance.Checkpoint != 77 || balance.State != "active" ||
		session.asked != testWallet {
		t.Fatalf("%+v %v", balance, err)
	}
	session.err = errors.New("no quorum")
	if _, err := ReadWalletBalance(context.Background(), session, testWallet); err == nil {
		t.Fatal("a failed read returned a balance")
	}
	if _, err := ReadWalletBalance(context.Background(), nil, testWallet); err == nil {
		t.Fatal("no session returned a balance")
	}
	session.err, session.asked = nil, ""
	if _, err := ReadWalletBalance(context.Background(), session, ""); err == nil || session.asked != "" {
		t.Fatalf("an empty wallet address was read: %v", err)
	}
}

func TestAZeroWalletFloorIsRefused(t *testing.T) {
	state := privateStateDir(t)
	if _, err := ApplyWalletFloor(state, WalletBalance{}, 0, nil, time.Unix(1_800_000_000, 0)); err == nil {
		t.Fatal("a zero floor was applied")
	}
	if markerBytes(t, state) != nil {
		t.Fatal("a refused floor check wrote a marker")
	}
}

func TestTheWalletFloorPausesAndLiftsOnlyItsOwnPause(t *testing.T) {
	const floor = 2_000_000_000
	now := time.Unix(1_800_000_000, 0)
	low, high := WalletBalance{BalanceNano: floor - 1}, WalletBalance{BalanceNano: floor}
	state := privateStateDir(t)

	// Above the floor with nothing to lift: nothing happens.
	if outcome, err := ApplyWalletFloor(state, high, floor, nil, now); err != nil || outcome.Action != WalletFloorClear ||
		markerBytes(t, state) != nil {
		t.Fatalf("above the floor: %+v %v", outcome, err)
	}
	// Below it: an agent marker with the fixed reason.
	paused, err := ApplyWalletFloor(state, low, floor, nil, now)
	if err != nil || paused.Action != WalletFloorPaused || paused.Pause.Origin != PauseOriginAgent ||
		paused.Pause.Reason != WalletFloorReason || !bytes.Equal(paused.Marker, markerBytes(t, state)) {
		t.Fatalf("below the floor: %+v %v", paused, err)
	}
	if err := (&Provider{config: ProviderConfig{StateDir: state}}).admissionOpen(); !errors.Is(err, ErrAdmissionPaused) {
		t.Fatal("the floor's pause did not hold admission")
	}
	// Still below: held, unchanged.
	if held, err := ApplyWalletFloor(state, low, floor, paused.Marker, now.Add(time.Minute)); err != nil ||
		held.Action != WalletFloorHeld || !bytes.Equal(markerBytes(t, state), paused.Marker) {
		t.Fatalf("still below: %+v %v", held, err)
	}
	// At the floor again: its own marker is lifted.
	if lifted, err := ApplyWalletFloor(state, high, floor, paused.Marker, now); err != nil ||
		lifted.Action != WalletFloorLifted || markerBytes(t, state) != nil {
		t.Fatalf("recovered: %+v %v", lifted, err)
	}
}

// Stacked floor pause: the floor pauses, the operator pauses on top, and the
// balance recovers. The floor does not lift the operator's marker.
func TestTheWalletFloorNeverLiftsAnOperatorPauseOverIt(t *testing.T) {
	const floor = 2_000_000_000
	now := time.Unix(1_800_000_000, 0)
	state := privateStateDir(t)
	paused, err := ApplyWalletFloor(state, WalletBalance{BalanceNano: 1}, floor, nil, now)
	if err != nil || paused.Action != WalletFloorPaused {
		t.Fatal(paused, err)
	}
	if _, _, err := PauseAdmission(state, "incident", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	kept, err := ApplyWalletFloor(state, WalletBalance{BalanceNano: floor}, floor, paused.Marker, now.Add(time.Hour))
	if err != nil || kept.Action != WalletFloorKept {
		t.Fatalf("recovered under an operator pause: %+v %v", kept, err)
	}
	pause, err := ReadAdmissionPause(state)
	if err != nil || pause == nil || pause.Origin != PauseOriginOperator || pause.PausedUnix != now.Unix() {
		t.Fatalf("the operator's marker: %+v %v", pause, err)
	}
	// Below the floor over the operator's marker: held, nothing written.
	before := markerBytes(t, state)
	if held, err := ApplyWalletFloor(state, WalletBalance{}, floor, nil, now); err != nil || held.Action != WalletFloorHeld ||
		!bytes.Equal(markerBytes(t, state), before) {
		t.Fatalf("below the floor over an operator pause: %+v %v", held, err)
	}
	// An unreadable marker is an error and stays.
	writeMarker(t, state, `{"schema":"x"}`)
	if _, err := ApplyWalletFloor(state, WalletBalance{}, floor, nil, now); err == nil {
		t.Fatal("the floor paused over an unreadable marker")
	}
}

// A pause the caller no longer holds as the floor's (a model's pause made
// over the floor's marker) is passed without its bytes and stays when the
// balance recovers.
func TestTheWalletFloorLeavesAPauseItIsNotGivenTheBytesOf(t *testing.T) {
	const floor = 10
	now := time.Unix(1_800_000_000, 0)
	state := privateStateDir(t)
	paused, err := ApplyWalletFloor(state, WalletBalance{BalanceNano: 1}, floor, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	// The model pauses on top: the marker is unchanged and reported as the
	// agent's.
	model, err := PauseAdmissionAs(state, PauseOriginAgent, "mcp: hold", now)
	if err != nil || !model.Already || model.PreviousOrigin != PauseOriginAgent ||
		!bytes.Equal(model.Marker, paused.Marker) {
		t.Fatal(model, err)
	}
	if outcome, err := ApplyWalletFloor(state, WalletBalance{BalanceNano: floor}, floor, nil, now); err != nil ||
		outcome.Action != WalletFloorClear || !bytes.Equal(markerBytes(t, state), paused.Marker) {
		t.Fatalf("the pause was lifted: %+v %v", outcome, err)
	}
}
