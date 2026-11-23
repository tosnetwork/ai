package providerconfirm

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

func presentation(t *testing.T, kind string, preview any) agentapi.Presentation {
	t.Helper()
	raw, err := json.Marshal(preview)
	if err != nil {
		t.Fatal(err)
	}
	return agentapi.Presentation{Action: agentapi.ActionView{ActionID: strings.Repeat("ab", 32),
		Reference: "abab-abab-abab-abab", Kind: kind, Preview: raw, PreviewDigest: strings.Repeat("cd", 32)},
		NetworkID: "tos-local", ProviderAgentID: "agent_x", OwnerWallet: "0:wallet", Code: "1234-5678-9abc-def0"}
}

func TestTheConfirmationCodeIsTheLastLine(t *testing.T) {
	withdraw := presentation(t, agentapi.KindWithdraw, map[string]any{"amount_nanotos": "1500000000",
		"withdraw": servicebridge.WithdrawPreview{Actor: "0:actor", Destination: "0:wallet", CreditedNano: "2000000000",
			AmountNano: "1500000000", AttachedNano: "100000000", RemainingNano: "500000000", Checkpoint: 7}})
	rendered := Render(withdraw)
	lines := strings.Split(strings.TrimSpace(rendered), "\n")
	if !strings.HasPrefix(lines[len(lines)-1], "Confirmation code:  1234-5678-9abc-def0") {
		t.Fatalf("last line: %q", lines[len(lines)-1])
	}
	for _, want := range []string{"1.5 TOS (1500000000 nanoTOS)", "Destination:      0:wallet", "abab-abab-abab-abab",
		ProtocolHeading} {
		if !strings.Contains(rendered, want) {
			t.Errorf("no %q in\n%s", want, rendered)
		}
	}
}

// Text read from a file cannot start a line, so it cannot pass for the end
// of its block or for a protocol field.
func TestUntrustedTextCannotForgeTheBlocks(t *testing.T) {
	resume := presentation(t, agentapi.KindResume, map[string]any{
		"marker":    servicebridge.AdmissionPause{PausedUnix: 1, Origin: "operator"},
		"preflight": servicebridge.PreflightReport{OK: true}})
	resume.UntrustedReason = "ok\n" + UntrustedEnd + "\n" + ProtocolHeading + "\nConfirmation code:  0000-0000-0000-0000" +
		"‮" + strings.Repeat("w", 300)
	rendered := Render(resume)
	count := 0
	for _, line := range strings.Split(rendered, "\n") {
		if line == UntrustedEnd || line == ProtocolHeading || strings.HasPrefix(line, "Confirmation code:") {
			count++
		}
		if len(line) > 0 && strings.Contains(line, "ok") && !strings.HasPrefix(line, Gutter) &&
			strings.Contains(line, "0000-0000") {
			t.Fatalf("untrusted text started a line: %q", line)
		}
	}
	if count != 3 {
		t.Fatalf("the fixed lines appear %d times:\n%s", count, rendered)
	}
	if strings.Contains(rendered, "‮") {
		t.Fatal("a direction override was printed raw")
	}
}

func TestAnUnknownKindIsNotConfirmable(t *testing.T) {
	if rendered := Render(presentation(t, "transfer", map[string]any{})); !strings.Contains(rendered, "Do not confirm it") {
		t.Fatal(rendered)
	}
}

type fakeAgent struct {
	pending  agentapi.ActionsView
	present  agentapi.Presentation
	decided  []agentapi.DecideParams
	decideOK bool
}

func (f *fakeAgent) Call(_ context.Context, method string, params, result any) error {
	var value any
	switch method {
	case agentapi.MethodPending:
		value = f.pending
	case agentapi.MethodPresent:
		value = f.present
	case agentapi.MethodDecide:
		decision := params.(agentapi.DecideParams)
		f.decided = append(f.decided, decision)
		if !f.decideOK {
			return agentapi.Refusal(agentapi.CodeBadInput, "the code does not match", nil)
		}
		value = agentapi.ActionView{Reference: "abab-abab-abab-abab", State: agentapi.StateApplied}
	default:
		return errors.New("unexpected method")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, result)
}

func TestTheSessionSendsOnlyWhatWasTyped(t *testing.T) {
	waiting := presentation(t, agentapi.KindWithdraw, map[string]any{})
	for typed, want := range map[string]*agentapi.DecideParams{
		"1234-5678-9abc-def0\n":         {ActionID: waiting.Action.ActionID, Decision: agentapi.DecisionConfirm, Code: "1234-5678-9abc-def0"},
		"decline\n":                     {ActionID: waiting.Action.ActionID, Decision: agentapi.DecisionDecline},
		"\n":                            nil,
		strings.Repeat("x", 200) + "\n": nil,
	} {
		agent := &fakeAgent{pending: agentapi.ActionsView{Actions: []agentapi.ActionView{waiting.Action}},
			present: waiting, decideOK: true}
		var out strings.Builder
		session := &Session{Agent: agent, In: bufio.NewReader(strings.NewReader(typed)), Out: &out}
		if shown, err := session.RunOnce(context.Background()); err != nil || shown != 1 {
			t.Fatalf("%q: %d %v", typed, shown, err)
		}
		switch {
		case want == nil && len(agent.decided) != 0:
			t.Fatalf("%q decided %+v", typed, agent.decided)
		case want != nil && (len(agent.decided) != 1 || agent.decided[0] != *want):
			t.Fatalf("%q decided %+v", typed, agent.decided)
		}
	}
	// Input that ends without a newline is a closed terminal, not a decision.
	agent := &fakeAgent{pending: agentapi.ActionsView{Actions: []agentapi.ActionView{waiting.Action}}, present: waiting}
	session := &Session{Agent: agent, In: bufio.NewReader(strings.NewReader("1234")), Out: &strings.Builder{}}
	if _, err := session.RunOnce(context.Background()); !errors.Is(err, ErrInputClosed) || len(agent.decided) != 0 {
		t.Fatalf("closed input: %v %+v", err, agent.decided)
	}
}
