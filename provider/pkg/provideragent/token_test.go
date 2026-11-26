package provideragent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentsocket"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

type tokenLibraryTest struct {
	Library
	sends  int
	state  string
	digest string
	safety func()
}

func (l *tokenLibraryTest) TokenAction(_ context.Context, in servicebridge.TokenActionInput, yes bool, digest string) (*servicebridge.TokenActionRecord, error) {
	if l.state != "" {
		return &servicebridge.TokenActionRecord{State: l.state}, nil
	}
	if l.digest == "" {
		l.digest = "frozen-preview"
	}
	r := &servicebridge.TokenActionRecord{Input: in, State: "preview", Preview: servicebridge.TokenPreview{Digest: l.digest}}
	if !yes {
		return r, servicebridge.ErrConfirmationRequired
	}
	if digest != l.digest {
		return r, errors.New("preview changed")
	}
	l.sends++
	l.state = "paying"
	r.State = l.state
	return r, nil
}
func (l *tokenLibraryTest) TokenOffer(context.Context, string) (*serviceactor.TokenAdmission, error) {
	return nil, errors.New("not offered")
}
func (l *tokenLibraryTest) TokenSafety(context.Context) error {
	if l.safety != nil {
		l.safety()
	}
	return nil
}
func (l *tokenLibraryTest) TokenStatus(context.Context, string) (*servicebridge.TokenStatus, error) {
	return &servicebridge.TokenStatus{}, nil
}
func TestTokenAgentRequiresHumanConfirmationAndReconcilesWithoutResending(t *testing.T) {
	bed := newTestbed(t)
	l := &tokenLibraryTest{Library: bed.lib}
	bed.agent.lib = l
	p := agentapi.TokenPreviewParams{Actor: testActor, Operation: "withdraw-revenue", TokenAmount: "100", IdempotencyKey: keyA}
	value, err := bed.agent.TokenPreview(context.Background(), agentsocket.RoleClient, p)
	if err != nil {
		t.Fatal(err)
	}
	view := value.(agentapi.ActionView)
	if view.State != agentapi.StateAwaitingConfirmation || l.sends != 0 {
		t.Fatal("preview signed")
	}
	// Ordinary clients cannot use the confirmer methods.
	if agentapi.Allowed(agentsocket.RoleClient, agentapi.MethodDecide) {
		t.Fatal("client may confirm")
	}
	result := bed.confirm(view.ActionID)
	if result.State != agentapi.StateAmbiguous || l.sends != 1 {
		t.Fatalf("%+v sends=%d", result, l.sends)
	}
	l.state = "delivered"
	_, err = bed.agent.Actions(agentsocket.RoleClient, agentapi.ActionsParams{})
	if err != nil {
		t.Fatal(err)
	}
	if bed.action(view.ActionID).State != agentapi.StateApplied || l.sends != 1 {
		t.Fatal("paying was not observed to delivery")
	}
	value, err = bed.agent.TokenPreview(context.Background(), agentsocket.RoleClient, p)
	if err != nil || value.(agentapi.ActionView).ActionID != view.ActionID || l.sends != 1 {
		t.Fatal("same action repeated")
	}
}
func TestTokenAgentChangedPreviewAndDeclineCannotSign(t *testing.T) {
	for _, changed := range []bool{true, false} {
		bed := newTestbed(t)
		l := &tokenLibraryTest{Library: bed.lib}
		bed.agent.lib = l
		value, err := bed.agent.TokenPreview(context.Background(), agentsocket.RoleClient, agentapi.TokenPreviewParams{Actor: testActor, Operation: "recover-surplus", TokenAmount: "100", IdempotencyKey: keyA})
		if err != nil {
			t.Fatal(err)
		}
		id := value.(agentapi.ActionView).ActionID
		if changed {
			l.digest = "changed"
			if bed.confirm(id).State != agentapi.StateExpired {
				t.Fatal("changed preview applied")
			}
		} else {
			presented := bed.present(id)
			_, err = bed.agent.Decide(context.Background(), agentapi.DecideParams{ActionID: id, Decision: agentapi.DecisionDecline})
			_ = presented
			if err != nil {
				t.Fatal(err)
			}
		}
		if l.sends != 0 {
			t.Fatal("unapproved token action signed")
		}
	}
}
func TestTokenAgentRevalidatesDirectSocketInputs(t *testing.T) {
	bed := newTestbed(t)
	bed.agent.lib = &tokenLibraryTest{Library: bed.lib}
	for _, raw := range []string{`{"actor":"wrong","operation":"withdraw-revenue","token_amount":"100","idempotency_key":"abcdefghijklmnop"}`, `{"actor":"` + testActor + `","operation":"withdraw-revenue","token_amount":"-1","idempotency_key":"abcdefghijklmnop"}`, `{"actor":"` + testActor + `","operation":"recheck-payout","id":"18446744073709551616","idempotency_key":"abcdefghijklmnop"}`, `{"actor":"` + testActor + `","operation":"evil","idempotency_key":"abcdefghijklmnop"}`} {
		_, err := bed.agent.Handle(context.Background(), agentsocket.RoleClient, agentapi.MethodTokenPreview, json.RawMessage(raw))
		if codeOf(err) != agentapi.CodeBadInput {
			t.Fatalf("%s: %v", raw, err)
		}
	}
}

func TestTokenRuntimePollsSafetyWithoutANativeOffer(t *testing.T) {
	bed := newTestbed(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := make(chan struct{}, 1)
	bed.agent.lib = &tokenLibraryTest{Library: bed.lib, safety: func() { called <- struct{}{}; cancel() }}
	runtime := &Runtime{agent: bed.agent, options: RuntimeOptions{Interval: time.Second}}
	runtime.runBounds(ctx)
	select {
	case <-called:
	default:
		t.Fatal("token safety not polled")
	}
}
