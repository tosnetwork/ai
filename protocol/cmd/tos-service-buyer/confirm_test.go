package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/buyerconfirm"
)

// Under `go test` standard input is not a terminal, so confirm refuses
// before it reaches any agent socket.
func TestConfirmRefusesAStandardInputThatIsNotATerminal(t *testing.T) {
	err := run([]string{"confirm", "--agent-socket", "/nonexistent/agent.sock"}, &bytes.Buffer{})
	if !errors.Is(err, buyerconfirm.ErrNotATerminal) && !errors.Is(err, buyerconfirm.ErrNoControlling) {
		t.Fatalf("confirm without a terminal: %v", err)
	}
	if err := run([]string{"confirm", "--interval", "10ms"}, &bytes.Buffer{}); err == nil {
		t.Fatal("an interval below 1s was accepted")
	}
}
