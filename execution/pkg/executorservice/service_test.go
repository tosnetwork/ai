package executorservice

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/artifactstore"
	"github.com/tosnetwork/tos-ai/pkg/executor"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
)

func background(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestExecuteReturnsTheOutcomeAndItsVerifiedObjects(t *testing.T) {
	backend := &fakeBackend{output: []byte("ok  \texample.test/work\n")}
	service := startService(t, backend, nil)
	request := job("happy")
	request.RetainUntilUnix = time.Now().Add(time.Hour).Unix()
	result, err := service.client.Execute(background(t), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.RetainUntilUnix != request.RetainUntilUnix {
		t.Fatalf("retained until %d, asked for %d", result.RetainUntilUnix, request.RetainUntilUnix)
	}
	outcome := result.Outcome
	if outcome.ExecutionID != request.ExecutionID || outcome.QuoteCommitment != request.QuoteCommitment ||
		outcome.InputDigest != request.InputDigest || outcome.SourceDigest != digestOf(request.SourceArchive) ||
		outcome.SandboxDigest != request.ManifestDigest || outcome.ToolchainDigest != softwarework.FrozenV1ImageDigest ||
		outcome.ResultDigest != digestOf(backend.output) || outcome.ExitCode != 0 {
		t.Fatalf("outcome = %+v", outcome)
	}
	// The caller's copies are the stored objects, byte for byte.
	if digestOf(result.Artifact) != outcome.Artifact.Digest || digestOf(result.Report) != outcome.Report.Digest {
		t.Fatal("returned objects do not match the outcome digests")
	}
	for digest, returned := range map[string][]byte{outcome.Artifact.Digest: result.Artifact, outcome.Report.Digest: result.Report} {
		stored, err := service.store.Get(context.Background(), digest)
		if err != nil || !bytes.Equal(stored, returned) {
			t.Fatalf("stored object %s differs: %v", digest, err)
		}
	}
	reader := tar.NewReader(bytes.NewReader(result.Artifact))
	header, err := reader.Next()
	if err != nil || header.Name != "output.log" {
		t.Fatalf("artifact entry = %v %v", header, err)
	}
	if log, _ := io.ReadAll(reader); !bytes.Equal(log, backend.output) {
		t.Fatalf("artifact output = %q", log)
	}
	// What ran is the frozen job under exactly the stated limits: nothing
	// in the request chose the image, command, user or network.
	ran := backend.lastRequest()
	frozen := softwarework.FrozenV1Contract()
	wantLimits := softwarework.FrozenV1Limits()
	wantLimits.CPUMillis, wantLimits.MemoryBytes, wantLimits.DiskBytes, wantLimits.OutputBytes, wantLimits.ExecutionTime =
		30_000, 256<<20, 512<<20, 1<<20, 30*time.Second
	if ran.ImageDigest != softwarework.FrozenV1ImageDigest || strings.Join(ran.Entrypoint, " ") != "/usr/local/bin/go test ./... -count=1" ||
		ran.Network != executor.NetworkNone || ran.UserID != frozen.UserID || !ran.ReadOnlyRoot || !ran.NoNewPrivileges ||
		ran.AllowGPU || len(ran.AllowedHosts) != 0 || ran.Limits != wantLimits {
		t.Fatalf("ran = %+v", ran)
	}
	// The retention deadline was recorded: a sweep after it removes the job.
	report, err := service.store.Sweep(context.Background(), time.Unix(request.RetainUntilUnix+1, 0), 8)
	if err != nil || report.DeletedJobs != 1 || report.Pending != 0 {
		t.Fatalf("sweep = %+v %v", report, err)
	}
}

func TestEveryJobGetsABoundedRetentionDeadline(t *testing.T) {
	service := startService(t, &fakeBackend{}, func(config *Config) {
		config.DefaultRetention, config.MaxRetention = time.Hour, 3*time.Hour
	})
	sweepAt := func(second int64) artifactstore.SweepReport {
		t.Helper()
		report, err := service.store.Sweep(context.Background(), time.Unix(second, 0), 8)
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	// No deadline asked for: the server default, never a pending record.
	unstated, err := service.client.Execute(background(t), job("unstated"))
	if err != nil {
		t.Fatal(err)
	}
	completed := int64(unstated.Outcome.CompletedAtUnix)
	if unstated.RetainUntilUnix != completed+3600 {
		t.Fatalf("default deadline = completion%+d", unstated.RetainUntilUnix-completed)
	}
	if report := sweepAt(completed + 3600); report.Pending != 0 || report.Live != 1 || report.DeletedJobs != 0 {
		t.Fatalf("at the default deadline: %+v", report)
	}
	// A deadline past the maximum is clamped to it, and repeating the
	// request does not move it: the bound counts from completion.
	forever := job("forever")
	forever.RetainUntilUnix = math.MaxInt64
	for attempt := 0; attempt < 2; attempt++ {
		pinned, err := service.client.Execute(background(t), forever)
		if err != nil {
			t.Fatal(err)
		}
		if limit := int64(pinned.Outcome.CompletedAtUnix) + 3*3600; pinned.RetainUntilUnix != limit {
			t.Fatalf("attempt %d: deadline = limit%+d", attempt, pinned.RetainUntilUnix-limit)
		}
		completed = int64(pinned.Outcome.CompletedAtUnix)
	}
	// A repeat may extend within the bound and never shortens.
	longer := job("unstated")
	longer.RetainUntilUnix = int64(unstated.Outcome.CompletedAtUnix) + 2*3600
	if extended, err := service.client.Execute(background(t), longer); err != nil || extended.RetainUntilUnix != longer.RetainUntilUnix {
		t.Fatalf("extension: %+v %v", extended.RetainUntilUnix, err)
	}
	if report := sweepAt(int64(unstated.Outcome.CompletedAtUnix) + 3600 + 1); report.DeletedJobs != 0 || report.Live != 2 {
		t.Fatalf("after the extension: %+v", report)
	}
	// One second past the maximum nothing of either job is left.
	if report := sweepAt(completed + 3*3600 + 1); report.DeletedJobs != 2 || report.Live != 0 || report.Pending != 0 {
		t.Fatalf("past the maximum: %+v", report)
	}
}

func TestRetentionBoundsAreValidated(t *testing.T) {
	for name, edit := range map[string]func(*Config){
		"default over maximum": func(c *Config) { c.DefaultRetention, c.MaxRetention = 2*time.Hour, time.Hour },
		"maximum over a year":  func(c *Config) { c.MaxRetention = MaxRetentionHard + time.Second },
		"sub-second default":   func(c *Config) { c.DefaultRetention = time.Millisecond },
		"negative maximum":     func(c *Config) { c.MaxRetention = -time.Hour },
	} {
		root := shortDir(t)
		built, err := assemble(root, socketIn(t, root), &fakeBackend{}, edit)
		if err == nil {
			_ = built.listener.Close()
			_ = built.journal.Close()
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRepeatedRequestReturnsTheRecordedOutcomeWithoutRunningAgain(t *testing.T) {
	backend := &fakeBackend{}
	service := startService(t, backend, nil)
	request := job("repeat")
	first, err := service.client.Execute(background(t), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.client.Execute(background(t), request)
	if err != nil {
		t.Fatal(err)
	}
	if second.Outcome != first.Outcome || !bytes.Equal(second.Artifact, first.Artifact) || !bytes.Equal(second.Report, first.Report) {
		t.Fatalf("repeat differs: %+v vs %+v", second.Outcome, first.Outcome)
	}
	if backend.runs() != 1 {
		t.Fatalf("the job ran %d times", backend.runs())
	}
	// The same identity with other commitments is another request.
	other := request
	other.InputDigest = digestOf([]byte("another input"))
	if _, err := service.client.Execute(background(t), other); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict err = %v", err)
	}
	// So is the same identity under other limits: the limits it ran under
	// are part of what was recorded.
	relimited := request
	relimited.Limits.OutputBytes--
	if _, err := service.client.Execute(background(t), relimited); !errors.Is(err, ErrConflict) {
		t.Fatalf("other limits: err = %v", err)
	}
	if backend.runs() != 1 {
		t.Fatalf("a conflicting repeat ran: %d", backend.runs())
	}
}

func TestLimitsLooserThanThePresetAreRefused(t *testing.T) {
	backend := &fakeBackend{}
	service := startService(t, backend, nil)
	frozen := FrozenLimits()
	for name, edit := range map[string]func(*Limits){
		"cpu above":        func(l *Limits) { l.CPUMillis = frozen.CPUMillis + 1 },
		"memory above":     func(l *Limits) { l.MemoryBytes = frozen.MemoryBytes + 1 },
		"scratch above":    func(l *Limits) { l.ScratchBytes = frozen.ScratchBytes + 1 },
		"output above":     func(l *Limits) { l.OutputBytes = frozen.OutputBytes + 1 },
		"wall clock above": func(l *Limits) { l.WallClockMillis = frozen.WallClockMillis + 1 },
		"zero cpu":         func(l *Limits) { l.CPUMillis = 0 },
		"zero memory":      func(l *Limits) { l.MemoryBytes = 0 },
		"zero scratch":     func(l *Limits) { l.ScratchBytes = 0 },
		"zero output":      func(l *Limits) { l.OutputBytes = 0 },
		"zero wall clock":  func(l *Limits) { l.WallClockMillis = 0 },
	} {
		request := job("limits")
		edit(&request.Limits)
		if _, err := service.client.Execute(background(t), request); !errors.Is(err, ErrLimitsRefused) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if backend.runs() != 0 {
		t.Fatalf("a refused request ran: %d", backend.runs())
	}
	// A refusal claimed nothing: the same identity still runs, and the
	// preset's own bounds are accepted.
	request := job("limits")
	request.Limits = frozen
	if _, err := service.client.Execute(background(t), request); err != nil || backend.runs() != 1 {
		t.Fatalf("frozen bounds: err=%v runs=%d", err, backend.runs())
	}
}

func TestMalformedRequestsAreRefusedBeforeAnythingRuns(t *testing.T) {
	backend := &fakeBackend{}
	service := startService(t, backend, nil)
	valid := job("malformed")
	source := valid.SourceArchive
	edited := func(edit func(header, execute map[string]any)) []byte {
		header := headerFields(valid)
		edit(header, header["execute"].(map[string]any))
		return frameOf(t, header)
	}
	validFrame := frameOf(t, headerFields(valid))
	// One byte over each bound, otherwise well formed, so only the bound
	// itself can refuse it.
	oversize := make([]byte, MaxSourceBytes+1)
	if status := sendRaw(t, service.socket, frameRaw(padded(validFrame[4:], MaxRequestHeaderBytes)), source); status != StatusOK {
		t.Fatalf("header at its bound: status = %s", status)
	}
	valid = job("malformed-after-bound")
	source = valid.SourceArchive
	validFrame = frameOf(t, headerFields(valid))
	describe := frameOf(t, map[string]any{"schema": RequestSchema, "operation": OperationDescribe})
	cases := map[string][][]byte{
		"unknown top-level field":  {edited(func(h, _ map[string]any) { h["image"] = "docker.io/library/busybox" }), source},
		"unknown execute field":    {edited(func(_, e map[string]any) { e["command"] = []string{"/bin/sh"} }), source},
		"unknown limit field":      {edited(func(_, e map[string]any) { e["limits"].(map[string]any)["pids"] = 1 }), source},
		"another schema version":   {edited(func(h, _ map[string]any) { h["schema"] = "tos.ai.executor-service.request.v2" }), source},
		"missing schema":           {edited(func(h, _ map[string]any) { delete(h, "schema") }), source},
		"unknown operation":        {edited(func(h, _ map[string]any) { h["operation"] = "exec" }), source},
		"execute without a body":   {edited(func(h, _ map[string]any) { delete(h, "execute") }), source},
		"describe with a body":     {edited(func(h, _ map[string]any) { h["operation"] = OperationDescribe })},
		"describe with a payload":  {describe, []byte("x")},
		"header is not JSON":       {frameRaw([]byte("not json")), source},
		"data after the header":    {frameRaw(append(validFrame[4:], []byte(` {"schema":"x"}`)...)), source},
		"empty header":             {{0, 0, 0, 0}},
		"oversize header":          {frameRaw(padded(validFrame[4:], MaxRequestHeaderBytes+1)), source},
		"header length over bound": {{0xff, 0xff, 0xff, 0xff}},
		"truncated header":         {validFrame[:len(validFrame)-10]},
		"data after the payload":   {validFrame, source, []byte("x")},
		"truncated payload":        {validFrame, source[:len(source)-1]},
		"payload of other bytes":   {validFrame, bytes.Repeat([]byte("x"), len(source))},
		"zero source bytes":        {edited(func(_, e map[string]any) { e["source_bytes"] = 0 })},
		"empty source": {edited(func(_, e map[string]any) {
			e["source_bytes"], e["source_digest"] = 0, digestOf(nil)
		})},
		"oversize source bytes": {edited(func(_, e map[string]any) { e["source_bytes"] = MaxSourceBytes + 1 }), source},
		"oversize source sent": {edited(func(_, e map[string]any) {
			e["source_bytes"], e["source_digest"] = len(oversize), digestOf(oversize)
		}), oversize},
		"negative source bytes":   {edited(func(_, e map[string]any) { e["source_bytes"] = -1 }), source},
		"negative retention":      {edited(func(_, e map[string]any) { e["retain_until_unix"] = -1 }), source},
		"execution id not digest": {edited(func(_, e map[string]any) { e["execution_id"] = "../../etc/passwd" }), source},
		"uppercase execution id":  {edited(func(_, e map[string]any) { e["execution_id"] = strings.ToUpper(valid.ExecutionID) }), source},
		"quote not a commitment":  {edited(func(_, e map[string]any) { e["quote_commitment"] = valid.ExecutionID }), source},
		"input digest malformed":  {edited(func(_, e map[string]any) { e["input_digest"] = "sha256:00" }), source},
		"source digest malformed": {edited(func(_, e map[string]any) { e["source_digest"] = "md5:00" }), source},
		"manifest digest missing": {edited(func(_, e map[string]any) { e["manifest_digest"] = "" }), source},
		"manifest digest a path":  {edited(func(_, e map[string]any) { e["manifest_digest"] = "/etc/tos-service/manifest.cbor" }), source},
		"limit as a string":       {edited(func(_, e map[string]any) { e["limits"].(map[string]any)["cpu_millis"] = "30000" }), source},
	}
	for name, parts := range cases {
		if status := sendRaw(t, service.socket, parts...); status != StatusInvalidRequest {
			t.Errorf("%s: status = %s", name, status)
		}
	}
	if backend.runs() != 1 {
		t.Fatalf("a malformed request ran: %d", backend.runs())
	}
	// The untouched request is accepted, so each refusal above is due to
	// its one edit, and none of them claimed the identity.
	if status := sendRaw(t, service.socket, validFrame, source); status != StatusOK || backend.runs() != 2 {
		t.Fatalf("valid request: status=%s runs=%d", status, backend.runs())
	}
}

func TestPeerOutsideTheAllowListIsRefused(t *testing.T) {
	backend := &fakeBackend{}
	// The kernel reports this process's real uid; the list names another.
	service := startService(t, backend, func(config *Config) { config.AllowedUID = uid(uint32(os.Getuid()) + 1) })
	if _, err := service.client.Describe(background(t)); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("describe err = %v", err)
	}
	if _, err := service.client.Execute(background(t), job("stranger")); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("execute err = %v", err)
	}
	// A request far larger than the socket buffer is still answered, not
	// read: the refusal does not depend on consuming the peer's bytes.
	large := job("stranger")
	large.SourceArchive = bytes.Repeat([]byte("x"), 4<<20)
	if _, err := service.client.Execute(background(t), large); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("large execute err = %v", err)
	}
	if backend.runs() != 0 {
		t.Fatalf("a refused peer ran a job: %d", backend.runs())
	}
}

func TestServerServesExactlyOneRealCallerIdentity(t *testing.T) {
	for name, allowed := range map[string]*uint32{
		"none":         nil,
		"overflow uid": uid(65534),
		"invalid uid":  uid(^uint32(0)),
	} {
		root := shortDir(t)
		built, err := assemble(root, socketIn(t, root), &fakeBackend{}, func(config *Config) { config.AllowedUID = allowed })
		if err == nil {
			_ = built.listener.Close()
			_ = built.journal.Close()
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBusyAtTheConnectionBound(t *testing.T) {
	service := startService(t, &fakeBackend{}, func(config *Config) { config.MaxConnections = 1 })
	// One connection that has not sent its request yet holds the only slot.
	holder := dialRaw(t, service.socket)
	eventually(t, "the held connection", func() bool {
		service.server.mutex.Lock()
		defer service.server.mutex.Unlock()
		return service.server.connections == 1
	})
	if _, err := service.client.Describe(background(t)); !errors.Is(err, ErrBusy) {
		t.Fatalf("describe at the bound: err = %v", err)
	}
	_ = holder.Close()
	eventually(t, "the slot to be released", func() bool {
		_, err := service.client.Describe(background(t))
		return err == nil
	})
}

func TestBusyAtTheExecutionBoundAndInProgressForTheSameIdentity(t *testing.T) {
	backend := &fakeBackend{started: make(chan struct{}, 4), gate: make(chan struct{})}
	service := startService(t, backend, nil)
	first := job("first")
	done := make(chan error, 1)
	go func() {
		_, err := service.client.Execute(background(t), first)
		done <- err
	}()
	waitStarted(t, backend)
	if _, err := service.client.Execute(background(t), job("second")); !errors.Is(err, ErrBusy) {
		t.Fatalf("second job at the bound: err = %v", err)
	}
	if _, err := service.client.Execute(background(t), first); !errors.Is(err, ErrInProgress) {
		t.Fatalf("same identity while running: err = %v", err)
	}
	// Describe is not an execution and is still answered.
	if description, err := service.client.Describe(background(t)); err != nil || description.MaxExecutions != 1 {
		t.Fatalf("describe while running: %+v %v", description, err)
	}
	close(backend.gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// The busy answer claimed nothing: the second job now runs.
	if _, err := service.client.Execute(background(t), job("second")); err != nil || backend.runs() != 2 {
		t.Fatalf("second job after the first: err=%v runs=%d", err, backend.runs())
	}
}

func TestBusyAtTheInFlightByteBound(t *testing.T) {
	backend := &fakeBackend{}
	service := startService(t, backend, nil)
	request := job("bytes")
	setBudget := func(free uint64) {
		service.server.mutex.Lock()
		service.server.budgetFree = free
		service.server.mutex.Unlock()
	}
	// The source does not fit: refused before it is read, nothing claimed.
	setBudget(uint64(len(request.SourceArchive)) - 1)
	if _, err := service.client.Execute(background(t), request); !errors.Is(err, ErrBusy) || backend.runs() != 0 {
		t.Fatalf("source over budget: err=%v runs=%d", err, backend.runs())
	}
	// The source fits but the objects do not: the job runs and is
	// journaled, the delivery is refused, and asking again returns it.
	setBudget(uint64(len(request.SourceArchive)))
	if _, err := service.client.Execute(background(t), request); !errors.Is(err, ErrBusy) || backend.runs() != 1 {
		t.Fatalf("objects over budget: err=%v runs=%d", err, backend.runs())
	}
	service.server.mutex.Lock()
	free := service.server.budgetFree
	service.server.mutex.Unlock()
	if free != uint64(len(request.SourceArchive)) {
		t.Fatalf("budget after the refused delivery = %d", free)
	}
	setBudget(DefaultInFlightBytes)
	if _, err := service.client.Execute(background(t), request); err != nil || backend.runs() != 1 {
		t.Fatalf("after the budget is free: err=%v runs=%d", err, backend.runs())
	}
	service.server.mutex.Lock()
	free = service.server.budgetFree
	service.server.mutex.Unlock()
	if free != DefaultInFlightBytes {
		t.Fatalf("budget leaked: %d", free)
	}
}

func TestSlowClientsMeetDeadlines(t *testing.T) {
	request := job("slow")
	request.Limits = FrozenLimits()
	frame := frameOf(t, headerFields(request))
	// Each phase is tested with the other phase's deadline far away, so
	// only its own deadline can end the stalled read.
	for _, phase := range []struct {
		name            string
		header, payload time.Duration
		stalls          map[string][][]byte
	}{
		{"header", 200 * time.Millisecond, time.Minute, map[string][][]byte{
			"nothing sent":         nil,
			"half a length prefix": {frame[:2]},
			"half a header":        {frame[:20]},
		}},
		{"payload", time.Minute, 200 * time.Millisecond, map[string][][]byte{
			"half a payload":          {frame, request.SourceArchive[:10]},
			"no end after the source": {frame, request.SourceArchive},
		}},
	} {
		backend := &fakeBackend{}
		service := startService(t, backend, func(config *Config) {
			config.HeaderTimeout, config.PayloadTimeout = phase.header, phase.payload
		})
		for name, parts := range phase.stalls {
			conn := dialRaw(t, service.socket)
			for _, part := range parts {
				if _, err := conn.Write(part); err != nil {
					t.Fatal(err)
				}
			}
			// The write side stays open: only a deadline can end the
			// server's read.
			if status := readStatusOf(t, conn); status != StatusTimeout {
				t.Errorf("%s: %s: status = %s", phase.name, name, status)
			}
			_ = conn.Close()
		}
		if backend.runs() != 0 {
			t.Fatalf("%s: a stalled request ran: %d", phase.name, backend.runs())
		}
	}
}

func TestCallerThatNeverReadsItsResponseCannotHoldAConnection(t *testing.T) {
	backend := &fakeBackend{output: bytes.Repeat([]byte("y"), 8<<20)}
	service := startService(t, backend, func(config *Config) {
		config.MaxConnections = 1
		config.WriteTimeout = 200 * time.Millisecond
	})
	request := job("unread")
	request.Limits = FrozenLimits()
	// An 8 MiB response cannot fit the socket buffer, so the write blocks
	// until the deadline frees the only connection slot.
	stalled := dialRaw(t, service.socket)
	if _, err := stalled.Write(append(frameOf(t, headerFields(request)), request.SourceArchive...)); err != nil {
		t.Fatal(err)
	}
	_ = stalled.CloseWrite()
	eventually(t, "the run", func() bool { return backend.runs() == 1 })
	eventually(t, "the slot held by the stalled reader", func() bool {
		_, err := service.client.Describe(background(t))
		return err == nil
	})
	// Its outcome was journaled all the same.
	if result, err := service.client.Execute(background(t), request); err != nil || backend.runs() != 1 ||
		len(result.Artifact) < 8<<20 {
		t.Fatalf("after the stalled reader: err=%v runs=%d", err, backend.runs())
	}
}

func TestClientDisconnectMidRunStillJournalsTheOutcome(t *testing.T) {
	backend := &fakeBackend{started: make(chan struct{}, 2), gate: make(chan struct{})}
	service := startService(t, backend, nil)
	request := job("disconnect")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := service.client.Execute(ctx, request)
		done <- err
	}()
	waitStarted(t, backend)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled call err = %v", err)
	}
	// The run is the server's: it is still in progress, not cancelled.
	if _, err := service.client.Execute(background(t), request); !errors.Is(err, ErrInProgress) {
		t.Fatalf("after disconnect: err = %v", err)
	}
	close(backend.gate)
	var result ExecuteResult
	eventually(t, "the journaled outcome", func() bool {
		var err error
		result, err = service.client.Execute(background(t), request)
		if err != nil && !errors.Is(err, ErrInProgress) {
			t.Fatalf("after the run: err = %v", err)
		}
		return err == nil
	})
	if backend.runs() != 1 || result.Outcome.ExecutionID != request.ExecutionID {
		t.Fatalf("runs=%d outcome=%+v", backend.runs(), result.Outcome)
	}
}

func TestCrashMidRunLeavesTheIdentityAmbiguous(t *testing.T) {
	root := shortDir(t)
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	socket, marker := socketIn(t, root), filepath.Join(root, "started")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// A real server process, killed while its run is claimed and started.
	helper := exec.Command(executable, "-test.run=^$")
	helper.Env = append(os.Environ(), helperEnv+"=serve-and-hang", helperStateEnv+"="+state,
		helperSocketEnv+"="+socket, helperMarkerEnv+"="+marker)
	var helperOutput bytes.Buffer
	helper.Stderr = &helperOutput
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	defer func() {
		if !killed {
			_ = helper.Process.Kill()
			_ = helper.Wait()
		}
	}()
	client, err := NewClient(ClientConfig{SocketPath: socket, ServerUID: uint32(os.Getuid())})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "the helper server", func() bool {
		_, err := client.Describe(background(t))
		return err == nil
	})
	request := job("crash")
	done := make(chan error, 1)
	go func() {
		_, err := client.Execute(background(t), request)
		done <- err
	}()
	eventually(t, "the run to start in the helper", func() bool {
		_, err := os.Stat(marker)
		return err == nil
	})
	if err := helper.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = helper.Wait()
	killed = true
	if err := <-done; err == nil {
		t.Fatal("the call to the killed server succeeded")
	}
	// The next server on the same state never reruns it.
	backend := &fakeBackend{}
	service := startServiceIn(t, root, backend, nil)
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := service.client.Execute(background(t), request); !errors.Is(err, ErrAmbiguous) {
			t.Fatalf("after the crash: err = %v (helper: %s)", err, helperOutput.String())
		}
	}
	if backend.runs() != 0 {
		t.Fatalf("the crashed execution ran again: %d", backend.runs())
	}
	// Other identities are unaffected.
	if _, err := service.client.Execute(background(t), job("after-crash")); err != nil || backend.runs() != 1 {
		t.Fatalf("another job: err=%v runs=%d", err, backend.runs())
	}
}

func TestFailedExecutionIsNeverRerun(t *testing.T) {
	backend := &fakeBackend{exit: 1}
	service := startService(t, backend, nil)
	request := job("failing")
	if _, err := service.client.Execute(background(t), request); !errors.Is(err, ErrExecutionFailed) {
		t.Fatalf("failing run: err = %v", err)
	}
	backend.mutex.Lock()
	backend.exit = 0
	backend.mutex.Unlock()
	if _, err := service.client.Execute(background(t), request); !errors.Is(err, ErrAmbiguous) || backend.runs() != 1 {
		t.Fatalf("replay: err=%v runs=%d", err, backend.runs())
	}
}

func TestDescribeReportsIdentityPresetAndReadiness(t *testing.T) {
	var ready switchable[error]
	ready.set(nil)
	service := startService(t, &fakeBackend{}, func(config *Config) {
		config.Ready = func(context.Context) error { return ready.get() }
		config.MaxExecutions = 2
	})
	description, err := service.client.Describe(background(t))
	if err != nil {
		t.Fatal(err)
	}
	want := Description{Version: "test-version", Commit: "test-commit",
		ImageDigest: softwarework.FrozenV1ImageDigest, ImageReference: softwarework.FrozenV1ImageReference,
		Limits: Limits{CPUMillis: 120_000, MemoryBytes: 1 << 30, ScratchBytes: 2 << 30, OutputBytes: 16 << 20, WallClockMillis: 180_000},
		PIDs:   64, MaxSourceBytes: 16 << 20, MaxObjectBytes: 64 << 20, MaxExecutions: 2,
		DefaultRetentionSeconds: 7 * 24 * 3600, MaxRetentionSeconds: 31 * 24 * 3600, Ready: true}
	if description != want {
		t.Fatalf("description = %+v, want %+v", description, want)
	}
	ready.set(errors.New("backend is down"))
	if description, err = service.client.Describe(background(t)); err != nil || description.Ready {
		t.Fatalf("not ready: %+v %v", description, err)
	}
}

func TestNewRunIsRefusedBeforeItsIdentityIsClaimed(t *testing.T) {
	var ready switchable[error]
	var free switchable[FreeSpace]
	ready.set(errors.New("backend is down"))
	free.set(FreeSpace{Bytes: 99, Inodes: 10})
	backend := &fakeBackend{}
	service := startService(t, backend, func(config *Config) {
		config.Ready = func(context.Context) error { return ready.get() }
		config.MinFreeBytes, config.MinFreeInodes = 100, 10
		config.FreeSpace = func() (FreeSpace, error) { return free.get(), nil }
	}, artifactstore.WithRecordBound(1))
	deadline := time.Now().Add(time.Hour).Unix()
	request := job("gated")
	request.RetainUntilUnix = deadline
	if _, err := service.client.Execute(background(t), request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("backend not ready: err = %v", err)
	}
	ready.set(nil)
	if _, err := service.client.Execute(background(t), request); !errors.Is(err, ErrStorageFull) {
		t.Fatalf("below the free-space floor: err = %v", err)
	}
	// Bytes at the floor are not enough while inodes are below theirs.
	free.set(FreeSpace{Bytes: 100, Inodes: 9})
	if _, err := service.client.Execute(background(t), request); !errors.Is(err, ErrStorageFull) {
		t.Fatalf("below the inode floor: err = %v", err)
	}
	free.set(FreeSpace{Bytes: 100, Inodes: 10})
	// The only deadline-bearing record the store admits goes to another job.
	holder := job("holder")
	holder.RetainUntilUnix = deadline
	if _, err := service.client.Execute(background(t), holder); err != nil {
		t.Fatal(err)
	}
	if _, err := service.client.Execute(background(t), request); !errors.Is(err, ErrRetentionFull) {
		t.Fatalf("store at its record bound: err = %v", err)
	}
	// A request that states no deadline gets one too, so it needs room.
	if _, err := service.client.Execute(background(t), job("no-deadline")); !errors.Is(err, ErrRetentionFull) {
		t.Fatalf("store at its record bound, no deadline stated: err = %v", err)
	}
	if backend.runs() != 1 {
		t.Fatalf("a refused job ran: %d", backend.runs())
	}
	// None of the refusals spent the identity: once there is room it runs.
	if _, err := service.store.Sweep(context.Background(), time.Unix(deadline+1, 0), 8); err != nil {
		t.Fatal(err)
	}
	if _, err := service.client.Execute(background(t), request); err != nil || backend.runs() != 2 {
		t.Fatalf("after room was made: err=%v runs=%d", err, backend.runs())
	}
}

// TestRetentionRecordIsReservedAtAdmission runs two jobs at once against a
// store with room for one more retained job. The second must be refused
// before it runs: admitted, it would run and then have nowhere to record
// its retention.
func TestRetentionRecordIsReservedAtAdmission(t *testing.T) {
	backend := &fakeBackend{started: make(chan struct{}, 4), gate: make(chan struct{})}
	service := startService(t, backend, func(config *Config) { config.MaxExecutions = 2 }, artifactstore.WithRecordBound(1))
	held := func() int {
		service.server.mutex.Lock()
		defer service.server.mutex.Unlock()
		return service.server.retentionHeld
	}
	first := make(chan error, 1)
	go func() {
		_, err := service.client.Execute(background(t), job("reserved-first"))
		first <- err
	}()
	waitStarted(t, backend)
	// An execution slot is free; the only retention record is spoken for.
	if _, err := service.client.Execute(background(t), job("reserved-second")); !errors.Is(err, ErrRetentionFull) {
		t.Fatalf("second job against the reserved record: err = %v", err)
	}
	if backend.runs() != 1 || held() != 1 {
		t.Fatalf("runs=%d held=%d", backend.runs(), held())
	}
	close(backend.gate)
	if err := <-first; err != nil {
		t.Fatalf("the first job: %v", err)
	}
	// The reservation ends with the run; the record itself now counts.
	if held() != 0 {
		t.Fatalf("held after the run = %d", held())
	}
	if _, err := service.client.Execute(background(t), job("reserved-second")); !errors.Is(err, ErrRetentionFull) || backend.runs() != 1 {
		t.Fatalf("second job at the bound: err=%v runs=%d", err, backend.runs())
	}
	// Once the first job's retention ended and was swept, the refused
	// identity runs: nothing was claimed for it.
	if _, err := service.store.Sweep(context.Background(), time.Now().Add(DefaultMaxRetention+time.Hour), 8); err != nil {
		t.Fatal(err)
	}
	if _, err := service.client.Execute(background(t), job("reserved-second")); err != nil || backend.runs() != 2 || held() != 0 {
		t.Fatalf("after the sweep: err=%v runs=%d held=%d", err, backend.runs(), held())
	}
}

// TestRefusedAdmissionsReleaseTheirRetentionSlot checks that a job refused
// after its slot was held gives the slot back, and that a failed run does.
func TestRefusedAdmissionsReleaseTheirRetentionSlot(t *testing.T) {
	backend := &fakeBackend{started: make(chan struct{}, 4), gate: make(chan struct{}), exit: 1}
	service := startService(t, backend, nil, artifactstore.WithRecordBound(2))
	held := func() int {
		service.server.mutex.Lock()
		defer service.server.mutex.Unlock()
		return service.server.retentionHeld
	}
	first := make(chan error, 1)
	running := job("release-running")
	go func() {
		_, err := service.client.Execute(background(t), running)
		first <- err
	}()
	waitStarted(t, backend)
	// Refused at the execution bound, after the slot was taken.
	if _, err := service.client.Execute(background(t), job("release-busy")); !errors.Is(err, ErrBusy) || held() != 1 {
		t.Fatalf("at the execution bound: err=%v held=%d", err, held())
	}
	close(backend.gate)
	if err := <-first; !errors.Is(err, ErrExecutionFailed) || held() != 0 {
		t.Fatalf("the failed run: err=%v held=%d", err, held())
	}
	backend.mutex.Lock()
	backend.exit = 0
	backend.mutex.Unlock()
	// Both records are still free for two jobs that succeed.
	for _, name := range []string{"release-a", "release-b"} {
		if _, err := service.client.Execute(background(t), job(name)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if held() != 0 {
		t.Fatalf("held at the end = %d", held())
	}
}

// TestEachJobReleasesOnlyItsOwnRetentionSlot runs two jobs at once and ends
// one: the other's slot must still be held, or a third job could be
// admitted against a record that is spoken for.
func TestEachJobReleasesOnlyItsOwnRetentionSlot(t *testing.T) {
	firstGate, secondGate := make(chan struct{}), make(chan struct{})
	backend := &fakeBackend{started: make(chan struct{}, 4), gate: firstGate}
	service := startService(t, backend, func(config *Config) { config.MaxExecutions = 2 }, artifactstore.WithRecordBound(2))
	held := func() int {
		service.server.mutex.Lock()
		defer service.server.mutex.Unlock()
		return service.server.retentionHeld
	}
	results := make(chan error, 2)
	start := func(name string) {
		go func() {
			_, err := service.client.Execute(background(t), job(name))
			results <- err
		}()
		waitStarted(t, backend)
	}
	start("slot-first")
	backend.mutex.Lock()
	backend.gate = secondGate
	backend.mutex.Unlock()
	start("slot-second")
	if held() != 2 {
		t.Fatalf("held with two jobs running = %d", held())
	}
	close(firstGate)
	if err := <-results; err != nil {
		t.Fatal(err)
	}
	// The handler of the finished job returns just after its response.
	eventually(t, "the finished job's connection", func() bool {
		service.server.mutex.Lock()
		defer service.server.mutex.Unlock()
		return service.server.connections == 1
	})
	if held() != 1 {
		t.Fatalf("held with one job still running = %d", held())
	}
	// One record is taken by the finished job, the other is still held:
	// a third job has no room.
	if _, err := service.client.Execute(background(t), job("slot-third")); !errors.Is(err, ErrRetentionFull) || backend.runs() != 2 {
		t.Fatalf("third job: err=%v runs=%d", err, backend.runs())
	}
	close(secondGate)
	if err := <-results; err != nil || held() != 0 {
		t.Fatalf("second job: err=%v held=%d", err, held())
	}
}

func TestRecordedOutcomeWhoseObjectsWereSweptIsReported(t *testing.T) {
	backend := &fakeBackend{}
	service := startService(t, backend, nil)
	request := job("swept")
	request.RetainUntilUnix = 1
	if _, err := service.client.Execute(background(t), request); err != nil {
		t.Fatal(err)
	}
	if report, err := service.store.Sweep(context.Background(), time.Now(), 8); err != nil || report.DeletedObjects != 2 {
		t.Fatalf("sweep = %+v %v", report, err)
	}
	request.RetainUntilUnix = 0
	if _, err := service.client.Execute(background(t), request); !errors.Is(err, ErrObjectsUnavailable) || backend.runs() != 1 {
		t.Fatalf("after the sweep: err=%v runs=%d", err, backend.runs())
	}
}

func TestShutdownWaitsForARunningExecutionToRecordItsOutcome(t *testing.T) {
	backend := &fakeBackend{started: make(chan struct{}, 1), gate: make(chan struct{})}
	service := startService(t, backend, nil)
	request := job("graceful")
	done := make(chan error, 1)
	go func() {
		_, err := service.client.Execute(background(t), request)
		done <- err
	}()
	waitStarted(t, backend)
	stopped := make(chan error, 1)
	go func() { stopped <- service.server.Shutdown(background(t)) }()
	// No new connection is accepted while the run finishes.
	eventually(t, "the listener to close", func() bool {
		_, err := service.client.Describe(background(t))
		return err != nil
	})
	select {
	case err := <-stopped:
		t.Fatalf("shutdown returned before the run ended: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(backend.gate)
	if err := <-stopped; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the running call: %v", err)
	}
}

func TestShutdownPastItsGraceCancelsTheRunAndLeavesItAmbiguous(t *testing.T) {
	root := shortDir(t)
	backend := &fakeBackend{started: make(chan struct{}, 1), gate: make(chan struct{})}
	service := startServiceIn(t, root, backend, nil)
	request := job("forced")
	done := make(chan error, 1)
	go func() {
		_, err := service.client.Execute(background(t), request)
		done <- err
	}()
	waitStarted(t, backend)
	grace, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := service.server.Shutdown(grace); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown: %v", err)
	}
	if err := <-done; !errors.Is(err, ErrExecutionFailed) {
		t.Fatalf("the cancelled call: %v", err)
	}
	service.stop(t)
	replacement := &fakeBackend{}
	restarted := startServiceIn(t, root, replacement, nil)
	if _, err := restarted.client.Execute(background(t), request); !errors.Is(err, ErrAmbiguous) || replacement.runs() != 0 {
		t.Fatalf("after the forced stop: err=%v runs=%d", err, replacement.runs())
	}
}

func TestListenLeavesOnlyTheGroupAbleToReachTheSocket(t *testing.T) {
	root := shortDir(t)
	socket := socketIn(t, root)
	listener, err := Listen(socket, uint32(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	modeAndGroup := func(path string) (os.FileMode, uint32) {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		return info.Mode().Perm(), info.Sys().(*syscall.Stat_t).Gid
	}
	if mode, group := modeAndGroup(socket); mode != 0o660 || group != uint32(os.Getegid()) {
		t.Fatalf("socket mode=%o gid=%d", mode, group)
	}
	if mode, group := modeAndGroup(filepath.Dir(socket)); mode != 0o750 || group != uint32(os.Getegid()) {
		t.Fatalf("directory mode=%o gid=%d", mode, group)
	}
	// A restart replaces its own stale socket (kept here by not unlinking).
	listener.SetUnlinkOnClose(false)
	_ = listener.Close()
	listener, err = Listen(socket, uint32(os.Getegid()))
	if err != nil {
		t.Fatalf("restart over a stale socket: %v", err)
	}
	_ = listener.Close()
	// Anything else at the path, or a directory the server does not own
	// or reaches through a symlink, refuses the start.
	if err := os.WriteFile(socket, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(socket, uint32(os.Getegid())); err == nil {
		t.Fatal("replaced a regular file")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Dir(socket), link); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(filepath.Dir(socket), "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, gid := range map[string]uint32{"overflow gid": 65534, "invalid gid": ^uint32(0)} {
		fresh := socketIn(t, shortDir(t))
		if listener, err := Listen(fresh, gid); err == nil {
			_ = listener.Close()
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Lstat(fresh); err == nil {
			t.Errorf("%s: a socket was left behind", name)
		}
	}
	for name, path := range map[string]string{
		"symlinked directory":        filepath.Join(link, "y.sock"),
		"below a symlink":            filepath.Join(link, "nested", "y.sock"),
		"directory of another user":  "/tmp/tos-ai-executor-service-test.sock",
		"missing directory":          filepath.Join(root, "absent", "y.sock"),
		"relative path":              "s/y.sock",
		"uncanonical path":           filepath.Dir(socket) + "/../s/y.sock",
		"path too long for a socket": filepath.Join(filepath.Dir(socket), strings.Repeat("a", 100)),
	} {
		if os.Getuid() == 0 && name == "directory of another user" {
			continue
		}
		if listener, err := Listen(path, uint32(os.Getegid())); err == nil {
			_ = listener.Close()
			t.Errorf("%s: accepted", name)
		}
	}
}

// fakeService answers every connection with fixed bytes, standing in for a
// server that does not follow the protocol.
func fakeService(t *testing.T, response func() []byte) *Client {
	t.Helper()
	socket := socketIn(t, shortDir(t))
	listener, err := Listen(socket, uint32(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, conn)
			_, _ = conn.Write(response())
			_ = conn.Close()
		}
	}()
	client, err := NewClient(ClientConfig{SocketPath: socket, ServerUID: uint32(os.Getuid())})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestClientTrustsNothingInAResponseThatBreaksTheProtocol(t *testing.T) {
	request := job("client")
	artifact, report := []byte("artifact bytes"), []byte("report bytes")
	type reply struct {
		header   map[string]any
		outcome  softwarework.Outcome
		artifact []byte
		report   []byte
		trailer  []byte
	}
	valid := func() reply {
		return reply{header: map[string]any{"schema": ResponseSchema, "status": "ok", "retain_until_unix": 1_776_003_600},
			outcome: softwarework.Outcome{QuoteCommitment: request.QuoteCommitment, ExecutionID: request.ExecutionID,
				InputDigest: request.InputDigest, ResultDigest: digestOf([]byte("result")),
				Artifact:     artifactstore.Descriptor{Digest: digestOf(artifact), MediaType: softwarework.ArtifactMediaType, SizeBytes: uint64(len(artifact))},
				Report:       artifactstore.Descriptor{Digest: digestOf(report), MediaType: softwarework.ReportMediaType, SizeBytes: uint64(len(report))},
				SourceDigest: digestOf(request.SourceArchive), ToolchainDigest: softwarework.FrozenV1ImageDigest,
				SandboxDigest: request.ManifestDigest, CompletedAtUnix: 1_776_000_000},
			artifact: artifact, report: report}
	}
	var current reply
	client := fakeService(t, func() []byte {
		header := current.header
		if _, set := header["outcome"]; !set {
			header["outcome"] = current.outcome
		}
		encoded, err := json.Marshal(header)
		if err != nil {
			panic(err)
		}
		wire := frameRaw(encoded)
		wire = append(wire, current.artifact...)
		wire = append(wire, current.report...)
		return append(wire, current.trailer...)
	})
	current = valid()
	if result, err := client.Execute(background(t), request); err != nil || !bytes.Equal(result.Artifact, artifact) ||
		!bytes.Equal(result.Report, report) || result.RetainUntilUnix != 1_776_003_600 {
		t.Fatalf("well-formed response: %v", err)
	}
	for name, edit := range map[string]func(*reply){
		"artifact bytes altered":      func(r *reply) { r.artifact = []byte("artifact bytez") },
		"report bytes altered":        func(r *reply) { r.report = []byte("report bytez") },
		"data after the report":       func(r *reply) { r.trailer = []byte("x") },
		"truncated report":            func(r *reply) { r.report = r.report[:3] },
		"another execution":           func(r *reply) { r.outcome.ExecutionID = digestOf([]byte("another")) },
		"another quote":               func(r *reply) { r.outcome.QuoteCommitment = "tvm-cell-" + digestOf([]byte("another")) },
		"another input":               func(r *reply) { r.outcome.InputDigest = digestOf([]byte("another")) },
		"another source":              func(r *reply) { r.outcome.SourceDigest = digestOf([]byte("another")) },
		"another sandbox":             func(r *reply) { r.outcome.SandboxDigest = digestOf([]byte("another")) },
		"another toolchain":           func(r *reply) { r.outcome.ToolchainDigest = digestOf([]byte("another image")) },
		"no retention deadline":       func(r *reply) { delete(r.header, "retain_until_unix") },
		"failed exit code":            func(r *reply) { r.outcome.ExitCode = 1 },
		"no completion time":          func(r *reply) { r.outcome.CompletedAtUnix = 0 },
		"another artifact media type": func(r *reply) { r.outcome.Artifact.MediaType = softwarework.ReportMediaType },
		"another report media type":   func(r *reply) { r.outcome.Report.MediaType = softwarework.ArtifactMediaType },
		"artifact over the bound":     func(r *reply) { r.outcome.Artifact.SizeBytes = MaxObjectBytes + 1 },
		"report over the bound":       func(r *reply) { r.outcome.Report.SizeBytes = MaxObjectBytes + 1 },
		"another schema":              func(r *reply) { r.header["schema"] = "tos.ai.executor-service.response.v2" },
		"unknown field":               func(r *reply) { r.header["note"] = "x" },
		"unknown status":              func(r *reply) { r.header["status"] = "fine" },
		"no outcome":                  func(r *reply) { r.header["outcome"] = nil },
		"a description instead":       func(r *reply) { r.header["describe"] = Description{} },
	} {
		current = valid()
		edit(&current)
		if _, err := client.Execute(background(t), request); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// A header frame over the bound is refused by its length alone.
	described, err := json.Marshal(map[string]any{"schema": ResponseSchema, "status": "ok", "describe": Description{Ready: true}})
	if err != nil {
		t.Fatal(err)
	}
	size := MaxResponseHeaderBytes
	sized := fakeService(t, func() []byte { return frameRaw(padded(described, size)) })
	if description, err := sized.Describe(background(t)); err != nil || !description.Ready {
		t.Fatalf("response header at its bound: err = %v", err)
	}
	size++
	if _, err := sized.Describe(background(t)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("oversize response header: err = %v", err)
	}
}

func TestClientRefusesASocketServedByAnotherUID(t *testing.T) {
	service := startService(t, &fakeBackend{}, nil)
	impostor, err := NewClient(ClientConfig{SocketPath: service.socket, ServerUID: uint32(os.Getuid()) + 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := impostor.Describe(background(t)); !errors.Is(err, ErrServerIdentity) {
		t.Fatalf("describe err = %v", err)
	}
	if _, err := impostor.Execute(background(t), job("impostor")); !errors.Is(err, ErrServerIdentity) || service.backend.runs() != 0 {
		t.Fatalf("execute err = %v", err)
	}
}

func TestClientBoundsACallWhoseContextHasNoDeadline(t *testing.T) {
	// A listener that accepts and then says nothing.
	socket := socketIn(t, shortDir(t))
	listener, err := Listen(socket, uint32(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	client, err := NewClient(ClientConfig{SocketPath: socket, ServerUID: uint32(os.Getuid()), Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 2)
	go func() {
		_, err := client.Describe(context.Background())
		finished <- err
	}()
	go func() {
		_, err := client.Execute(context.Background(), job("silent"))
		finished <- err
	}()
	for call := 0; call < 2; call++ {
		select {
		case err := <-finished:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("silent service: err = %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a call without a deadline was not bounded")
		}
	}
	// The caller's own deadline wins over the client's.
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	patient, err := NewClient(ClientConfig{SocketPath: socket, ServerUID: uint32(os.Getuid()), Timeout: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := patient.Describe(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caller deadline: err = %v", err)
	}
	if _, err := NewClient(ClientConfig{SocketPath: socket, Timeout: -time.Second}); err == nil {
		t.Fatal("accepted a negative timeout")
	}
}

// TestConcurrentIdenticalRequestsNeverReadAsAmbiguous races many copies of
// one request. Exactly one of them runs; every other one must be told the
// run is in progress or be given its outcome. "Ambiguous" would tell a
// caller that a healthy execution is spent.
func TestConcurrentIdenticalRequestsNeverReadAsAmbiguous(t *testing.T) {
	backend := &fakeBackend{}
	service := startService(t, backend, func(config *Config) { config.MaxConnections = 32 })
	const rounds, callers = 150, 12
	for round := 0; round < rounds; round++ {
		request := job(fmt.Sprintf("race-%d", round))
		start := make(chan struct{})
		results := make(chan error, callers)
		for caller := 0; caller < callers; caller++ {
			go func() {
				<-start
				_, err := service.client.Execute(background(t), request)
				results <- err
			}()
		}
		close(start)
		succeeded := 0
		for caller := 0; caller < callers; caller++ {
			switch err := <-results; {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrInProgress):
			default:
				t.Fatalf("round %d: a concurrent identical request got %v", round, err)
			}
		}
		if succeeded == 0 {
			t.Fatalf("round %d: no request got the outcome", round)
		}
		if _, err := service.client.Execute(background(t), request); err != nil {
			t.Fatalf("round %d: after the race: %v", round, err)
		}
	}
	if backend.runs() != rounds {
		t.Fatalf("%d rounds ran %d jobs", rounds, backend.runs())
	}
}

// TestRunThatEndsDuringARepeatedRequestIsAnsweredWithItsOutcome pins the
// narrowest interleaving: a repeated request reads the journal while the run
// is still claimed, and the run records its outcome and ends before the
// request looks for it. The answer must be the outcome, not "ambiguous".
func TestRunThatEndsDuringARepeatedRequestIsAnsweredWithItsOutcome(t *testing.T) {
	backend := &fakeBackend{started: make(chan struct{}, 1), gate: make(chan struct{})}
	service := startService(t, backend, nil)
	request := job("ends-during-repeat")
	first := make(chan error, 1)
	go func() {
		_, err := service.client.Execute(background(t), request)
		first <- err
	}()
	waitStarted(t, backend)
	// The flight is registered before its claim, so wait for the claim
	// itself: the repeated request below must see it in the journal.
	record := filepath.Join(service.state, "journal", request.ExecutionID[len("sha256:"):]+".json")
	eventually(t, "the journal claim", func() bool {
		_, err := os.Stat(record)
		return err == nil
	})
	// Hide the flight from the repeat's first check, so it goes on to read
	// the journal while the run is still claimed; the run then records its
	// outcome and ends before the repeat looks for the flight again.
	service.server.mutex.Lock()
	running := service.server.flights[request.ExecutionID]
	delete(service.server.flights, request.ExecutionID)
	service.server.mutex.Unlock()
	if running == nil {
		t.Fatal("the run has no flight")
	}
	hooked := false
	service.server.afterAmbiguousRead = func() {
		hooked = true
		close(backend.gate)
		<-running.done
	}
	runner, err := softwarework.NewRunner(service.server.config.Executor, service.store, service.journal,
		mustContract(t, request), softwarework.BindLimits())
	if err != nil {
		t.Fatal(err)
	}
	status, outcome, _, started := service.server.execute(runner, softwarework.Request{QuoteCommitment: request.QuoteCommitment,
		ExecutionID: request.ExecutionID, InputDigest: request.InputDigest,
		SourceDigest: digestOf(request.SourceArchive), SourceArchive: request.SourceArchive}, 0)
	if !hooked || status != StatusOK || started || outcome.ExecutionID != request.ExecutionID {
		t.Fatalf("hooked=%v status=%s started=%v", hooked, status, started)
	}
	if err := <-first; err != nil || backend.runs() != 1 {
		t.Fatalf("the run itself: err=%v runs=%d", err, backend.runs())
	}
}

func mustContract(t *testing.T, request ExecuteRequest) softwarework.Contract {
	t.Helper()
	contract, err := softwarework.ManifestContract(request.ManifestDigest, request.Limits.manifest())
	if err != nil {
		t.Fatal(err)
	}
	return contract
}

func TestClientRefusesASourceOutsideTheInputBound(t *testing.T) {
	service := startService(t, &fakeBackend{}, nil)
	for name, source := range map[string][]byte{"empty": nil, "over the bound": make([]byte, MaxSourceBytes+1)} {
		request := job("bound")
		request.SourceArchive = source
		var status *StatusError
		if _, err := service.client.Execute(background(t), request); err == nil || errors.As(err, &status) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// The bound itself is accepted end to end.
	request := job("bound")
	request.Limits = FrozenLimits()
	request.SourceArchive = make([]byte, MaxSourceBytes)
	if _, err := service.client.Execute(background(t), request); err != nil {
		t.Fatalf("source at the bound: %v", err)
	}
}
