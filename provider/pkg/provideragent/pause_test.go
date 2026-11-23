package provideragent

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentsocket"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

func (b *testbed) pause(role agentsocket.Role, reason string) agentapi.PauseView {
	b.t.Helper()
	view, err := b.agent.Pause(role, agentapi.PauseParams{Reason: reason})
	if err != nil {
		b.t.Fatal(err)
	}
	return view.(agentapi.PauseView)
}

func (b *testbed) resume(key string) (agentapi.ResumeView, error) {
	b.t.Helper()
	view, err := b.agent.Resume(context.Background(), agentsocket.RoleClient, agentapi.ResumeParams{IdempotencyKey: key})
	switch typed := view.(type) {
	case agentapi.ResumeView:
		return typed, err
	case json.RawMessage:
		var decoded agentapi.ResumeView
		if decodeErr := json.Unmarshal(typed, &decoded); decodeErr != nil {
			b.t.Fatal(decodeErr)
		}
		return decoded, err
	}
	return agentapi.ResumeView{}, err
}

func (b *testbed) marker() (*servicebridge.AdmissionPause, []byte) {
	b.t.Helper()
	pause, marker, err := servicebridge.ReadAdmissionPauseMarker(b.lib.config.StateDir)
	if err != nil {
		b.t.Fatal(err)
	}
	return pause, marker
}

func (b *testbed) operatorPause() servicebridge.PauseResult {
	b.t.Helper()
	result, err := servicebridge.PauseAdmissionAs(b.lib.config.StateDir, servicebridge.PauseOriginOperator, "incident",
		b.clock.Now().Add(time.Minute))
	if err != nil {
		b.t.Fatal(err)
	}
	return result
}

func TestTheModelResumesItsOwnPauseOnlyWithTheFloorMetAndAPassingPreflight(t *testing.T) {
	bed := newTestbed(t)
	paused := bed.pause(agentsocket.RoleClient, "buyer flood")
	if !paused.Paused || paused.AlreadyPaused || paused.Origin != servicebridge.PauseOriginAgent || paused.RecordedAs != pauseForModel {
		t.Fatalf("pause: %+v", paused)
	}
	if pause, _ := bed.marker(); pause.Reason != "mcp: buyer flood" {
		t.Fatalf("marker reason %q", pause.Reason)
	}
	// Pausing again changes nothing.
	if again := bed.pause(agentsocket.RoleClient, "again"); !again.AlreadyPaused || again.PreviousOrigin != servicebridge.PauseOriginAgent {
		t.Fatalf("pause again: %+v", again)
	}
	_, before := bed.marker()

	bed.lib.set(func(f *fakeLibrary) { f.balance = 1 })
	if _, err := bed.resume(keyA); codeOf(err) != agentapi.CodeNotReady {
		t.Fatalf("under the floor: %v", err)
	}
	bed.lib.set(func(f *fakeLibrary) { f.balance, f.preflightFail = 5_000_000_000, true })
	if _, err := bed.resume(keyA); codeOf(err) != agentapi.CodeNotReady {
		t.Fatalf("a failing preflight: %v", err)
	}
	if _, after := bed.marker(); !bytes.Equal(before, after) {
		t.Fatal("a refused resume changed the marker")
	}
	bed.lib.set(func(f *fakeLibrary) { f.preflightFail = false })
	resumed, err := bed.resume(keyA)
	if err != nil || resumed.Outcome != agentapi.ResumeResumed {
		t.Fatalf("resume: %+v %v", resumed, err)
	}
	if pause, _ := bed.marker(); pause != nil {
		t.Fatal("the marker stayed")
	}
	if origin, err := bed.agent.store.readOrigin(); err != nil || origin != nil {
		t.Fatalf("the origin record stayed: %+v %v", origin, err)
	}
	if view, err := bed.resume(keyB); err != nil || view.Outcome != agentapi.ResumeNotPaused {
		t.Fatalf("resume when not paused: %+v %v", view, err)
	}
}

// A marker whose bytes differ from the record is not the model's.
func TestAMarkerWithOtherBytesThanTheRecordNeedsTheConfirmer(t *testing.T) {
	bed := newTestbed(t)
	bed.pause(agentsocket.RoleClient, "")
	origin, err := bed.agent.store.readOrigin()
	if err != nil {
		t.Fatal(err)
	}
	origin.Marker = append([]byte(nil), origin.Marker...)
	origin.Marker[len(origin.Marker)-2] ^= 1
	if err := bed.agent.store.writeOrigin(*origin); err != nil {
		t.Fatal(err)
	}
	view, err := bed.resume(keyA)
	if err != nil || view.Outcome != agentapi.ResumeConfirmable || view.Action == nil {
		t.Fatalf("resume: %+v %v", view, err)
	}
}

func TestAnOperatorPauseAndAnUnreadableMarkerNeedTheConfirmer(t *testing.T) {
	bed := newTestbed(t)
	bed.operatorPause()
	view, err := bed.resume(keyA)
	if err != nil || view.Outcome != agentapi.ResumeConfirmable || view.Action == nil ||
		view.Action.State != agentapi.StateAwaitingConfirmation {
		t.Fatalf("operator pause: %+v %v", view, err)
	}
	// The human confirms it: the marker confirmed is removed.
	applied := bed.confirm(view.Action.ActionID)
	if applied.State != agentapi.StateApplied {
		t.Fatalf("confirmed resume: %+v", applied)
	}
	if pause, _ := bed.marker(); pause != nil {
		t.Fatal("a confirmed resume left the marker")
	}

	unreadable := filepath.Join(bed.lib.config.StateDir, servicebridge.AdmissionPauseFile)
	if err := os.WriteFile(unreadable, []byte(`{"schema":"tos.openfox.rail-admission-pause.v9"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	view, err = bed.resume(keyB)
	if err != nil || view.Outcome != agentapi.ResumeConfirmable {
		t.Fatalf("unreadable marker: %+v %v", view, err)
	}
	// A v1 marker reads as the operator's.
	if err := os.WriteFile(unreadable, []byte(`{"schema":"tos.openfox.rail-admission-pause.v1","paused_unix":5}`), 0o600); err != nil {
		t.Fatal(err)
	}
	view, err = bed.resume("key-v1v1v1v1v1v1v1v1")
	if err != nil || view.Outcome != agentapi.ResumeConfirmable {
		t.Fatalf("v1 marker: %+v %v", view, err)
	}
}

func TestAStackedOperatorPauseTurnsTheModelsResumeIntoAConfirmableAction(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		bed := newTestbed(t)
		model := bed.pause(agentsocket.RoleClient, "model")
		if stopped {
			bed.agent.Close()
		}
		result := bed.operatorPause()
		if !result.Restamped || result.Pause.Origin != servicebridge.PauseOriginOperator ||
			result.Pause.PausedUnix != model.PausedUnix {
			t.Fatalf("stopped %t: the re-stamp: %+v", stopped, result)
		}
		if stopped {
			bed.open()
		}
		view, err := bed.resume(keyA)
		if err != nil || view.Outcome != agentapi.ResumeConfirmable {
			t.Fatalf("stopped %t: %+v %v", stopped, view, err)
		}
		if pause, _ := bed.marker(); pause == nil || pause.Origin != servicebridge.PauseOriginOperator {
			t.Fatalf("stopped %t: the operator's marker is gone", stopped)
		}
	}
}

func TestAReStampBetweenTheAgentsCheckAndItsRemovalKeepsTheOperatorsMarker(t *testing.T) {
	bed := newTestbed(t)
	bed.pause(agentsocket.RoleClient, "model")
	bed.agent.beforeRemove = func() { bed.operatorPause() }
	if _, err := bed.resume(keyA); codeOf(err) != agentapi.CodeConflict {
		t.Fatalf("resume across a re-stamp: %v", err)
	}
	if pause, _ := bed.marker(); pause == nil || pause.Origin != servicebridge.PauseOriginOperator {
		t.Fatal("the operator's marker was removed")
	}
}

func TestTheWalletFloorPausesAndLiftsOnlyItsOwnPause(t *testing.T) {
	bed := newTestbed(t)
	ctx := context.Background()
	bed.lib.set(func(f *fakeLibrary) { f.balance = 1 })
	if outcome, err := bed.agent.CheckWalletFloor(ctx); err != nil || outcome.Action != servicebridge.WalletFloorPaused {
		t.Fatalf("below the floor: %+v %v", outcome, err)
	}
	// The floor's pause is not the model's to lift and stores no action.
	if view, err := bed.resume(keyA); err != nil || view.Outcome != agentapi.ResumeFloorPause || view.Action != nil {
		t.Fatalf("resume of the floor pause: %+v %v", view, err)
	}
	bed.lib.set(func(f *fakeLibrary) { f.balance = DefaultMinWalletNanoTOS })
	if outcome, err := bed.agent.CheckWalletFloor(ctx); err != nil || outcome.Action != servicebridge.WalletFloorLifted {
		t.Fatalf("at the floor: %+v %v", outcome, err)
	}
	if pause, _ := bed.marker(); pause != nil {
		t.Fatal("the floor's pause stayed")
	}
}

func TestTheWalletFloorNeverLiftsAnOperatorPauseStackedOnIt(t *testing.T) {
	bed := newTestbed(t)
	ctx := context.Background()
	bed.lib.set(func(f *fakeLibrary) { f.balance = 1 })
	if _, err := bed.agent.CheckWalletFloor(ctx); err != nil {
		t.Fatal(err)
	}
	bed.operatorPause()
	bed.lib.set(func(f *fakeLibrary) { f.balance = DefaultMinWalletNanoTOS })
	if outcome, err := bed.agent.CheckWalletFloor(ctx); err != nil || outcome.Action == servicebridge.WalletFloorLifted {
		t.Fatalf("after the balance recovered: %+v %v", outcome, err)
	}
	if pause, _ := bed.marker(); pause == nil || pause.Origin != servicebridge.PauseOriginOperator {
		t.Fatal("the operator's pause was lifted")
	}
}

// A model pause over the floor's marker leaves the marker as it is, moves
// the record to the model, and from then on the floor passes nil and never
// lifts it; the model's own resume does, with the floor met.
func TestAModelPauseOverTheFloorsPauseIsNotLiftedByTheFloor(t *testing.T) {
	bed := newTestbed(t)
	ctx := context.Background()
	bed.lib.set(func(f *fakeLibrary) { f.balance = 1 })
	if _, err := bed.agent.CheckWalletFloor(ctx); err != nil {
		t.Fatal(err)
	}
	_, floorMarker := bed.marker()
	paused := bed.pause(agentsocket.RoleClient, "model")
	if !paused.AlreadyPaused || paused.RecordedAs != pauseForModel {
		t.Fatalf("the model's pause over the floor's: %+v", paused)
	}
	if _, marker := bed.marker(); !bytes.Equal(marker, floorMarker) {
		t.Fatal("the model's pause changed the floor's marker")
	}
	var passed []byte
	bed.agent.withLock(func() { passed, _ = bed.agent.floorMarkerLocked() })
	if passed != nil {
		t.Fatal("the floor is still given the marker's bytes")
	}
	bed.lib.set(func(f *fakeLibrary) { f.balance = DefaultMinWalletNanoTOS })
	if outcome, err := bed.agent.CheckWalletFloor(ctx); err != nil || outcome.Action == servicebridge.WalletFloorLifted {
		t.Fatalf("the floor lifted the model's pause: %+v %v", outcome, err)
	}
	if pause, _ := bed.marker(); pause == nil {
		t.Fatal("the marker is gone")
	}
	if view, err := bed.resume(keyA); err != nil || view.Outcome != agentapi.ResumeResumed {
		t.Fatalf("the model's resume: %+v %v", view, err)
	}
}

func TestTheOperatorsPauseThroughTheAgentIsAnOperatorPause(t *testing.T) {
	bed := newTestbed(t)
	bed.pause(agentsocket.RoleClient, "model")
	view := bed.pause(agentsocket.RoleCustody, "operator")
	if !view.Restamped || view.Origin != servicebridge.PauseOriginOperator {
		t.Fatalf("the custody pause: %+v", view)
	}
	if resumed, err := bed.resume(keyA); err != nil || resumed.Outcome != agentapi.ResumeConfirmable {
		t.Fatalf("the model's resume: %+v %v", resumed, err)
	}
}

func TestAResumeWhoseMarkerChangedAfterConfirmationExpires(t *testing.T) {
	bed := newTestbed(t)
	bed.operatorPause()
	view, err := bed.resume(keyA)
	if err != nil || view.Action == nil {
		t.Fatalf("%+v %v", view, err)
	}
	presentation := bed.present(view.Action.ActionID)
	if presentation.UntrustedReason != "incident" {
		t.Fatalf("the reason shown: %q", presentation.UntrustedReason)
	}
	// The operator pauses again with a fresh stamp after the preview.
	if _, err := servicebridge.ResumeAdmission(bed.lib.config.StateDir); err != nil {
		t.Fatal(err)
	}
	bed.operatorPause()
	decided, err := bed.agent.Decide(context.Background(), agentapi.DecideParams{ActionID: view.Action.ActionID,
		Decision: agentapi.DecisionConfirm, Code: presentation.Code})
	if err != nil || decided.(agentapi.ActionView).State != agentapi.StateExpired {
		t.Fatalf("decide: %+v %v", decided, err)
	}
	if pause, _ := bed.marker(); pause == nil {
		t.Fatal("the new marker was removed")
	}
}
