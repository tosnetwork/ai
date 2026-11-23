package providerconfirm

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
)

// Agent is the agent socket as the confirmer uses it.
type Agent interface {
	Call(ctx context.Context, method string, params, result any) error
}

// MaxDecisionBytes bounds one typed decision line.
const MaxDecisionBytes = 128

// ErrInputClosed reports that the terminal closed while a decision was
// awaited; nothing was decided.
var ErrInputClosed = errors.New("the terminal closed before a decision was typed")

// Session shows each waiting action on the confirmer's terminal and sends
// the human's decision. In and Out are that terminal.
type Session struct {
	Agent Agent
	In    *bufio.Reader
	Out   io.Writer
}

// RunOnce handles every action waiting now and returns how many it showed.
func (s *Session) RunOnce(ctx context.Context) (int, error) {
	var pending agentapi.ActionsView
	if err := s.Agent.Call(ctx, agentapi.MethodPending, agentapi.Empty{}, &pending); err != nil {
		return 0, err
	}
	if len(pending.Actions) == 0 {
		fmt.Fprintln(s.Out, "No action is waiting for a decision.")
		return 0, nil
	}
	shown := 0
	for _, waiting := range pending.Actions {
		var presentation agentapi.Presentation
		if err := s.Agent.Call(ctx, agentapi.MethodPresent, agentapi.ActionParams{ActionID: waiting.ActionID},
			&presentation); err != nil {
			fmt.Fprintf(s.Out, "Action %s could not be presented: %s\n", field(waiting.Reference), describe(err))
			continue
		}
		shown++
		fmt.Fprint(s.Out, "\n"+Render(presentation))
		if err := s.decide(ctx, presentation); err != nil {
			return shown, err
		}
	}
	return shown, nil
}

// Watch runs RunOnce every interval until ctx ends.
func (s *Session) Watch(ctx context.Context, interval time.Duration) error {
	for {
		if _, err := s.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			if errors.Is(err, ErrInputClosed) {
				return err
			}
			fmt.Fprintf(s.Out, "The provider agent did not answer: %s\n", describe(err))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

func (s *Session) decide(ctx context.Context, presentation agentapi.Presentation) error {
	fmt.Fprint(s.Out, "\nType the confirmation code to confirm, \"decline\" to decline, or press Enter to skip: ")
	typed, err := s.readLine()
	if err != nil {
		return err
	}
	params := agentapi.DecideParams{ActionID: presentation.Action.ActionID}
	switch {
	case typed == "":
		fmt.Fprintln(s.Out, "Skipped; nothing was decided.")
		return nil
	case typed == "decline":
		params.Decision = agentapi.DecisionDecline
	default:
		params.Decision, params.Code = agentapi.DecisionConfirm, typed
	}
	var result agentapi.ActionView
	if err := s.Agent.Call(ctx, agentapi.MethodDecide, params, &result); err != nil {
		fmt.Fprintf(s.Out, "Not confirmed: %s\n", describe(err))
		return nil
	}
	fmt.Fprintf(s.Out, "Action %s is now %s.\n", field(result.Reference), field(result.State))
	if result.FailureMessage != "" {
		fmt.Fprintf(s.Out, "  %s\n", field(result.FailureMessage))
	}
	return nil
}

// readLine reads one newline-terminated decision line of at most
// MaxDecisionBytes. A longer line is consumed and refused as no decision;
// input that ends without a newline is a closed terminal, never a decision.
func (s *Session) readLine() (string, error) {
	var line []byte
	for {
		chunk, err := s.In.ReadSlice('\n')
		line = append(line, chunk...)
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			if len(line) > MaxDecisionBytes+1 {
				line = line[:MaxDecisionBytes+1]
			}
			continue
		case err != nil:
			return "", ErrInputClosed
		}
		if len(line) > MaxDecisionBytes+1 {
			fmt.Fprintln(s.Out, "That line is too long; nothing was decided.")
			return "", nil
		}
		return strings.TrimSpace(string(line[:len(line)-1])), nil
	}
}

func describe(err error) string {
	var known *agentapi.Error
	if errors.As(err, &known) {
		return field(known.Code + ": " + known.Message)
	}
	return field(err.Error())
}
