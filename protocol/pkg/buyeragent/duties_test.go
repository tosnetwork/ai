package buyeragent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
)

// paid prepares, confirms and sends a purchase.
func (f *fixture) paid(t *testing.T, key string) PurchaseView {
	t.Helper()
	view := f.requested(t, key)
	presentation, err := f.agent.Present(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.agent.Decide(context.Background(), DecideParams{RequestHash: view.RequestHash,
		Decision: DecisionConfirm, Code: presentation.Code}); err != nil {
		t.Fatal(err)
	}
	return view
}

func (f *fixture) setStatus(status serviceactor.Status) {
	f.buyer.mu.Lock()
	f.buyer.status = status
	f.buyer.mu.Unlock()
}

// Each finalized status gets its operation (section 11.2): overdue
// expires, refundable claims, lapsed sweeps; any other status sends
// nothing.
func TestDutiesSendTheOperationTheStatusRequires(t *testing.T) {
	f := newFixture(t)
	view := f.paid(t, keyA)
	ctx := context.Background()
	for _, status := range []serviceactor.Status{serviceactor.StatusPending, serviceactor.StatusResponded} {
		f.setStatus(status)
		if failures := f.agent.Duties(ctx); len(failures) != 0 {
			t.Fatal(failures)
		}
	}
	if sent := f.buyer.sentLifecycle(); len(sent) != 0 {
		t.Fatalf("a %v request got sends: %v", serviceactor.StatusResponded, sent)
	}
	want := []string{}
	for status, operation := range map[serviceactor.Status]string{serviceactor.StatusOverdue: buyersdk.LifecycleExpire,
		serviceactor.StatusRefundable: buyersdk.LifecycleClaimRefund, serviceactor.StatusLapsed: buyersdk.LifecycleSweep} {
		f.setStatus(status)
		if failures := f.agent.Duties(ctx); len(failures) != 0 {
			t.Fatal(failures)
		}
		want = append(want, view.RequestHash+" "+operation)
	}
	sent := f.buyer.sentLifecycle()
	if len(sent) != len(want) {
		t.Fatalf("sent %v, want the three operations", sent)
	}
	for _, operation := range want {
		found := false
		for _, entry := range sent {
			found = found || entry == operation
		}
		if !found {
			t.Fatalf("%s was not sent: %v", operation, sent)
		}
	}
}

// A sent operation waits for finalized history and is sent again only
// after the retry interval; a send custody never started does not count.
func TestASentOperationIsNotRepeatedBeforeTheRetry(t *testing.T) {
	f := newFixture(t)
	view := f.paid(t, keyA)
	ctx := context.Background()
	f.setStatus(serviceactor.StatusOverdue)
	first, err := f.agent.RefundNow(ctx, view.RequestHash)
	if err != nil || !first.Sent || first.Operation != buyersdk.LifecycleExpire {
		t.Fatalf("first: %+v %v", first, err)
	}
	again, err := f.agent.RefundNow(ctx, view.RequestHash)
	if err != nil || again.Sent || !again.Waiting {
		t.Fatalf("a repeat inside the retry interval: %+v %v", again, err)
	}
	f.clock.advance(LifecycleRetry)
	later, err := f.agent.RefundNow(ctx, view.RequestHash)
	if err != nil || !later.Sent {
		t.Fatalf("after the retry interval: %+v %v", later, err)
	}
	if sent := f.buyer.sentLifecycle(); len(sent) != 2 {
		t.Fatalf("sends %v", sent)
	}
	if LifecycleRetry != 10*time.Minute {
		t.Fatalf("the retry interval is %v", LifecycleRetry)
	}
}

func TestLifecycleSendsAreBoundedPerWindow(t *testing.T) {
	f := newFixture(t)
	// The default bound is 2 * MaxCalls + 8 (section 6).
	if want := 2*testLimits().MaxCalls + 8; f.agent.config.MaxLifecycleSends != want {
		t.Fatalf("the default lifecycle bound is %d, not %d", f.agent.config.MaxLifecycleSends, want)
	}
	view := f.paid(t, keyA)
	f.agent.config.MaxLifecycleSends = 1
	f.setStatus(serviceactor.StatusOverdue)
	ctx := context.Background()
	if _, err := f.agent.RefundNow(ctx, view.RequestHash); err != nil {
		t.Fatal(err)
	}
	f.setStatus(serviceactor.StatusRefundable)
	if _, err := f.agent.RefundNow(ctx, view.RequestHash); err == nil || codeOf(t, err) != CodeOverBudget {
		t.Fatalf("a send over the lifecycle bound: %v", err)
	}
	f.clock.advance(testLimits().Window)
	if out, err := f.agent.RefundNow(ctx, view.RequestHash); err != nil || !out.Sent {
		t.Fatalf("after the window: %+v %v", out, err)
	}
}

func TestFailedAndAmbiguousLifecycleSendsAreReported(t *testing.T) {
	f := newFixture(t)
	view := f.paid(t, keyA)
	ctx := context.Background()
	f.setStatus(serviceactor.StatusOverdue)
	f.buyer.lifecycleErr = buyersdk.ErrCallNotStarted
	if _, err := f.agent.RefundNow(ctx, view.RequestHash); err == nil || codeOf(t, err) != CodeDependencyUnavailable {
		t.Fatalf("a send custody never started: %v", err)
	}
	f.buyer.lifecycleErr = errors.New("tosctl exited after submitting")
	_, err := f.agent.RefundNow(ctx, view.RequestHash)
	if err == nil || codeOf(t, err) != CodeAmbiguous {
		t.Fatalf("an ambiguous send: %v", err)
	}
	var known *Error
	errors.As(err, &known)
	if known.Disposition != DispositionResolveBeforeRetry {
		t.Fatalf("disposition %s", known.Disposition)
	}
	f.buyer.lifecycleErr = nil
	if out, err := f.agent.RefundNow(ctx, view.RequestHash); err != nil || !out.Waiting {
		t.Fatalf("an ambiguous send was repeated at once: %+v %v", out, err)
	}
	f.buyer.resolveErr = errors.New("no quorum")
	if _, err := f.agent.RefundNow(ctx, view.RequestHash); err == nil || codeOf(t, err) != CodeDependencyUnavailable {
		t.Fatalf("an unresolved request: %v", err)
	}
}

func TestNothingIsDueBeforeTheCallIsSent(t *testing.T) {
	f := newFixture(t)
	view := f.prepare(t, keyA, sourceTar(t))
	f.setStatus(serviceactor.StatusOverdue)
	out, err := f.agent.RefundNow(context.Background(), view.RequestHash)
	if err != nil || out.Sent || out.Status != string(buyersdk.PhasePrepared) {
		t.Fatalf("an unsent purchase: %+v %v", out, err)
	}
	if failures := f.agent.Duties(context.Background()); len(failures) != 0 || len(f.buyer.sentLifecycle()) != 0 {
		t.Fatalf("duties for an unsent purchase: %v %v", failures, f.buyer.sentLifecycle())
	}
	if _, err := f.agent.RefundNow(context.Background(), strings.Repeat("0", 64)); err == nil || codeOf(t, err) != CodeNotFound {
		t.Fatalf("an unknown purchase: %v", err)
	}
}

// The duty loop needs no session: started once, it carries the refund on
// its own.
func TestRunDutiesCarriesTheRefundWithoutASession(t *testing.T) {
	f := newFixture(t)
	f.paid(t, keyA)
	f.setStatus(serviceactor.StatusOverdue)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		f.agent.RunDuties(ctx, 10*time.Millisecond, nil)
		close(done)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for len(f.buyer.sentLifecycle()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the duty loop sent nothing")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}
