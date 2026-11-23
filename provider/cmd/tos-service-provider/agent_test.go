package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheAdapterVerbsRefuseBadInvocations(t *testing.T) {
	root := t.TempDir()
	open := filepath.Join(root, "agent.json")
	if err := os.WriteFile(open, []byte(`{"schema":"tos.service.mcp-provider.agent-config.v1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		arguments []string
		code      int
		reason    string
	}{
		"agent without a configuration": {[]string{"agent"}, exitUsage, "--config"},
		"agent with a relative path":    {[]string{"agent", "--config", "agent.json"}, exitFailed, "absolute"},
		"agent with a readable file":    {[]string{"agent", "--config", open}, exitFailed, "private"},
		"confirm without a socket":      {[]string{"confirm"}, exitUsage, "--agent-socket"},
		"confirm with a bad interval": {[]string{"confirm", "--agent-socket", "/run/x.sock", "--interval", "1ms"},
			exitUsage, "--interval"},
		// A plain file stands for any socket path that is not the custody
		// account's own agent socket.
		"confirm with a socket path that is not a socket": {[]string{"confirm", "--agent-socket", open},
			exitFailed, "agent socket"},
	} {
		var out, errOut bytes.Buffer
		code := run(context.Background(), test.arguments, streams{out: &out, err: &errOut})
		if code != test.code || !strings.Contains(errOut.String(), test.reason) {
			t.Errorf("%s: exit %d: %s", name, code, errOut.String())
		}
	}
}

// The confirmer reads decisions from a terminal only: standard input that is
// a file is refused before the agent is contacted.
func TestTheConfirmerRefusesAStandardInputThatIsNotATerminal(t *testing.T) {
	root, err := os.MkdirTemp("", "pt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	socket := filepath.Join(root, "agent.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	stdin, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	actual := os.Stdin
	os.Stdin = stdin
	t.Cleanup(func() { os.Stdin = actual })
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"confirm", "--agent-socket", socket},
		streams{out: &out, err: &errOut})
	if code != exitFailed || !strings.Contains(errOut.String(), "terminal") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
}
