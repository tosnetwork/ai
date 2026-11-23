package provideragent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentsocket"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

// The crash tests run an agent in a child process of the test binary and
// kill it at a chosen point: the kernel then drops its locks, exactly as
// after a real crash.
const (
	crashRootEnv  = "PROVIDERAGENT_CRASH_ROOT"
	crashStageEnv = "PROVIDERAGENT_CRASH_STAGE"

	stagePresented = "presented"
	stageBeforeLog = "before-record"
	stageAfterSend = "after-send"
	// stageAfterSendClockAhead is stageAfterSend with the agent's clock an
	// hour ahead of the library's: as after a backward step of the host
	// clock between the confirmation and the send's record.
	stageAfterSendClockAhead = "after-send-clock-ahead"
)

func TestMain(m *testing.M) {
	if root := os.Getenv(crashRootEnv); root != "" {
		if err := crashChild(root, os.Getenv(crashStageEnv)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func crashLibrary(root string) *fakeLibrary {
	lib := newLibrary(root)
	lib.recordsDir = filepath.Join(root, "records")
	lib.config.Provider = &servicebridge.ProviderNode{CapabilityID: "cap_" + strings.Repeat("e5", 32), Version: "1.0.0"}
	return lib
}

func mark(root, name string) error {
	return os.WriteFile(filepath.Join(root, name), []byte("x"), 0o600)
}

// crashChild prepares a withdrawal and stops at the stage, then waits to be
// killed.
func crashChild(root, stage string) error {
	lib := crashLibrary(root)
	block := func() {
		if err := mark(root, stage); err != nil {
			panic(err)
		}
		// Sleeping, not blocking forever, so the runtime never ends the
		// process itself: only the parent's kill does.
		time.Sleep(time.Hour)
	}
	switch stage {
	case stageBeforeLog:
		lib.beforeSend = block
	case stageAfterSend, stageAfterSendClockAhead:
		lib.withdrawSend = block
	}
	config := testConfig(root)
	if err := config.check(); err != nil {
		return err
	}
	now := time.Now
	if stage == stageAfterSendClockAhead {
		now = func() time.Time { return time.Now().Add(time.Hour) }
	}
	agent, err := Open(Options{Config: config, Library: lib, Now: now})
	if err != nil {
		return err
	}
	ctx := context.Background()
	view, err := agent.WithdrawPreview(ctx, agentsocket.RoleClient,
		agentapi.WithdrawPreviewParams{AmountNanoTOS: "1000000000", IdempotencyKey: keyA})
	if err != nil {
		return err
	}
	id := view.(agentapi.ActionView).ActionID
	wait := 0
	if _, err := agent.RequestConfirmation(ctx, agentsocket.RoleClient,
		agentapi.RequestConfirmationParams{ActionID: id, WaitSeconds: &wait}); err != nil {
		return err
	}
	presented, err := agent.Present(agentapi.ActionParams{ActionID: id})
	if err != nil {
		return err
	}
	if stage == stagePresented {
		block()
	}
	_, err = agent.Decide(ctx, agentapi.DecideParams{ActionID: id, Decision: agentapi.DecisionConfirm,
		Code: presented.(agentapi.Presentation).Code})
	if err != nil {
		return err
	}
	block()
	return nil
}

// runAndKill runs the child until it reaches the stage and kills it.
func runAndKill(t *testing.T, root, stage string) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^$")
	command.Env = append(os.Environ(), crashRootEnv+"="+root, crashStageEnv+"="+stage)
	var output strings.Builder
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, stage)); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf("the child never reached %s: %s", stage, output.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	var exit *exec.ExitError
	if err := command.Wait(); err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
}

func crashBed(t *testing.T) (string, *fakeLibrary) {
	t.Helper()
	root := shortRoot(t)
	privateDir(t, filepath.Join(root, "rail"))
	privateDir(t, filepath.Join(root, "records"))
	if err := os.WriteFile(filepath.Join(root, "rail.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, crashLibrary(root)
}

func onlyAction(t *testing.T, agent *Agent) agentapi.ActionView {
	t.Helper()
	view, err := agent.Actions(agentsocket.RoleCustody, agentapi.ActionsParams{})
	if err != nil || len(view.(agentapi.ActionsView).Actions) != 1 {
		t.Fatalf("actions: %+v %v", view, err)
	}
	return view.(agentapi.ActionsView).Actions[0]
}

func reopen(t *testing.T, root string, lib *fakeLibrary) *Agent {
	t.Helper()
	config := testConfig(root)
	if err := config.check(); err != nil {
		t.Fatal(err)
	}
	agent, err := Open(Options{Config: config, Library: lib})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(agent.Close)
	return agent
}

func TestAnAgentKilledAfterTheSendNeverSendsAgain(t *testing.T) {
	root, lib := crashBed(t)
	runAndKill(t, root, stageAfterSend)
	agent := reopen(t, root, lib)
	action := onlyAction(t, agent)
	// The record says submitted: the action is resolved from it as
	// ambiguous, never sent again on its old confirmation.
	if action.State != agentapi.StateAmbiguous || lib.withdrawSends != 0 {
		t.Fatalf("after the restart: %+v, sends %d", action, lib.withdrawSends)
	}
	records, err := lib.Withdrawals()
	if err != nil || len(records) != 1 {
		t.Fatalf("records: %+v %v", records, err)
	}
}

func TestAnAgentKilledBeforeTheSendWasRecordedSendsNothing(t *testing.T) {
	root, lib := crashBed(t)
	runAndKill(t, root, stageBeforeLog)
	agent := reopen(t, root, lib)
	action := onlyAction(t, agent)
	if action.State != agentapi.StateFailed || lib.withdrawSends != 0 {
		t.Fatalf("after the restart: %+v, sends %d", action, lib.withdrawSends)
	}
	if records, err := lib.Withdrawals(); err != nil || len(records) != 0 {
		t.Fatalf("records: %+v %v", records, err)
	}
}

// The send's record is found by its query id, not by comparing the record's
// start time with the agent's clock: a record started "before" the action
// entered applying, by a clock that stepped back, is still the send's own.
func TestAWithdrawalSentAcrossABackwardClockStepIsResolvedFromItsRecord(t *testing.T) {
	root, lib := crashBed(t)
	runAndKill(t, root, stageAfterSendClockAhead)
	agent := reopen(t, root, lib)
	action := onlyAction(t, agent)
	if action.State != agentapi.StateAmbiguous || lib.withdrawSends != 0 {
		t.Fatalf("after the restart: %+v, sends %d", action, lib.withdrawSends)
	}
}

// A withdrawal record that existed before the send, of the same amount and
// actor and stamped later than the action by a clock that stepped forward,
// is never taken for the send's own: a crash before the send resolves as
// nothing sent.
func TestAnEarlierWithdrawalRecordIsNeverTakenForTheSend(t *testing.T) {
	root, lib := crashBed(t)
	earlier := servicebridge.WithdrawalRecord{QueryID: 99, Actor: testActor, Destination: testWallet,
		AmountNano: "1000000000", State: servicebridge.WithdrawalFinalized, StartedUnix: time.Now().Add(time.Hour).Unix()}
	lib.saveRecord(earlier)
	runAndKill(t, root, stageBeforeLog)
	agent := reopen(t, root, lib)
	action := onlyAction(t, agent)
	if action.State != agentapi.StateFailed || lib.withdrawSends != 0 {
		t.Fatalf("after the restart: %+v, sends %d", action, lib.withdrawSends)
	}
}

// A resume left applying is resolved from the marker: applied only when the
// marker is gone, failed while it is still in place.
func TestAnApplyingResumeIsResolvedFromTheMarker(t *testing.T) {
	for name, removed := range map[string]bool{"marker in place": false, "marker removed": true} {
		t.Run(name, func(t *testing.T) {
			bed := newTestbed(t)
			bed.operatorPause()
			view, err := bed.resume(keyA)
			if err != nil || view.Action == nil {
				t.Fatalf("resume: %+v %v", view, err)
			}
			bed.agent.withLock(func() {
				var record actionRecord
				if record, err = bed.agent.store.readAction(view.Action.ActionID); err == nil {
					record.State, record.ApplyingUnix = agentapi.StateApplying, bed.clock.Now().Unix()
					err = bed.agent.store.writeAction(record, false)
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			bed.agent.Close()
			if removed {
				if _, err := servicebridge.ResumeAdmission(bed.lib.config.StateDir); err != nil {
					t.Fatal(err)
				}
			}
			bed.open()
			resolved := bed.action(view.Action.ActionID)
			want := agentapi.StateFailed
			if removed {
				want = agentapi.StateApplied
			}
			if resolved.State != want {
				t.Fatalf("resolved %+v, want %s", resolved, want)
			}
			if _, err := readMarkerBytes(bed.lib.config.StateDir); removed == (err == nil) {
				t.Fatalf("the marker after recovery: %v", err)
			}
		})
	}
}

func TestAnAgentKilledBetweenPreviewAndApplyAppliesOnceAfterRestart(t *testing.T) {
	root, lib := crashBed(t)
	runAndKill(t, root, stagePresented)
	agent := reopen(t, root, lib)
	action := onlyAction(t, agent)
	if action.State != agentapi.StateAwaitingConfirmation {
		t.Fatalf("after the restart: %+v", action)
	}
	presented, err := agent.Present(agentapi.ActionParams{ActionID: action.ActionID})
	if err != nil {
		t.Fatal(err)
	}
	decided, err := agent.Decide(context.Background(), agentapi.DecideParams{ActionID: action.ActionID,
		Decision: agentapi.DecisionConfirm, Code: presented.(agentapi.Presentation).Code})
	if err != nil || decided.(agentapi.ActionView).State != agentapi.StateApplied {
		t.Fatalf("decide: %+v %v", decided, err)
	}
	if _, err := agent.Decide(context.Background(), agentapi.DecideParams{ActionID: action.ActionID,
		Decision: agentapi.DecisionConfirm, Code: presented.(agentapi.Presentation).Code}); codeOf(err) != agentapi.CodeConflict {
		t.Fatalf("a second decide: %v", err)
	}
	if records, err := lib.Withdrawals(); err != nil || len(records) != 1 || lib.withdrawSends != 1 {
		t.Fatalf("records: %+v %v, sends %d", records, err, lib.withdrawSends)
	}
}
