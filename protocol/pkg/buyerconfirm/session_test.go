package buyerconfirm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
)

// fakeAgent answers pending and present with one purchase and records
// every decide.
type fakeAgent struct {
	decisions []buyeragent.DecideParams
	presented int
	refuse    error
}

func (f *fakeAgent) Call(_ context.Context, method string, params, result any) error {
	answer := any(nil)
	switch method {
	case "pending":
		p := presentation()
		answer = buyeragent.PurchasesView{Purchases: []buyeragent.PurchaseView{p.Purchase}}
	case "present":
		f.presented++
		answer = presentation()
	case "decide":
		decision := params.(buyeragent.DecideParams)
		f.decisions = append(f.decisions, decision)
		if f.refuse != nil {
			return f.refuse
		}
		view := presentation().Purchase
		view.State = buyeragent.StateSubmitted
		answer = view
	default:
		return errors.New("unexpected method " + method)
	}
	raw, err := json.Marshal(answer)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, result)
}

func session(agent *fakeAgent, typed string) (*Session, *bytes.Buffer) {
	var out bytes.Buffer
	return &Session{Agent: agent, In: bufio.NewReaderSize(strings.NewReader(typed), 16), Out: &out,
		Sensitive: DefaultSensitive}, &out
}

func TestATypedCodeConfirmsAndOtherInputDoesNot(t *testing.T) {
	ctx := context.Background()
	agent := &fakeAgent{}
	s, out := session(agent, "  1234-5678-9abc-def0  \n")
	if shown, err := s.RunOnce(ctx); err != nil || shown != 1 {
		t.Fatalf("shown %d: %v", shown, err)
	}
	if len(agent.decisions) != 1 || agent.decisions[0].Decision != buyeragent.DecisionConfirm ||
		agent.decisions[0].Code != "1234-5678-9abc-def0" || agent.decisions[0].RequestHash != presentation().Purchase.RequestHash {
		t.Fatalf("decisions %+v", agent.decisions)
	}
	if !strings.Contains(out.String(), "Confirmation code:  1234-5678-9abc-def0") || !strings.Contains(out.String(), "is now submitted") {
		t.Fatalf("output:\n%s", out.String())
	}

	agent = &fakeAgent{}
	s, _ = session(agent, "decline\n")
	if _, err := s.RunOnce(ctx); err != nil || len(agent.decisions) != 1 ||
		agent.decisions[0].Decision != buyeragent.DecisionDecline || agent.decisions[0].Code != "" {
		t.Fatalf("decline: %+v %v", agent.decisions, err)
	}

	agent = &fakeAgent{}
	s, out = session(agent, "\n")
	if _, err := s.RunOnce(ctx); err != nil || len(agent.decisions) != 0 || !strings.Contains(out.String(), "Skipped") {
		t.Fatalf("an empty line decided: %+v %v", agent.decisions, err)
	}
}

func TestAnOverlongLineOrAClosedTerminalDecidesNothing(t *testing.T) {
	ctx := context.Background()
	agent := &fakeAgent{}
	s, out := session(agent, strings.Repeat("1", MaxDecisionBytes+1)+"\n")
	if _, err := s.RunOnce(ctx); err != nil || len(agent.decisions) != 0 || !strings.Contains(out.String(), "too long") {
		t.Fatalf("an overlong line decided: %+v %v", agent.decisions, err)
	}
	agent = &fakeAgent{}
	s, _ = session(agent, "1234")
	if _, err := s.RunOnce(ctx); !errors.Is(err, ErrInputClosed) || len(agent.decisions) != 0 {
		t.Fatalf("a closed terminal decided: %+v %v", agent.decisions, err)
	}
}

func TestARefusedDecisionIsShownEscaped(t *testing.T) {
	agent := &fakeAgent{refuse: &buyeragent.Error{Code: buyeragent.CodeBadInput, Message: "the code does not match\x1b[2J"}}
	s, out := session(agent, "0000-0000-0000-0000\n")
	if _, err := s.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Not paid: MCP_BUYER_BAD_INPUT: the code does not match") ||
		strings.Contains(out.String(), "\x1b") {
		t.Fatalf("output:\n%q", out.String())
	}
}
