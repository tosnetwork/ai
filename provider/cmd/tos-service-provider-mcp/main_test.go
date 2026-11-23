package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The MCP server links no custody code (spec section 10.1): of this
// module, its binary reaches only the socket API, the generic socket
// package and the MCP layer. The rail node library, the provider agent,
// the confirmer, execution/ and the buyer's packages are all absent.
func TestTheServerLinksNoCustodyCode(t *testing.T) {
	for _, goos := range []string{"linux", "windows", "darwin"} {
		command := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", ".")
		command.Env = append(os.Environ(), "GOOS="+goos, "GOWORK=off")
		listing, err := command.Output()
		if err != nil {
			t.Fatalf("go list (%s): %v", goos, err)
		}
		allowed := map[string]bool{
			"github.com/tosnetwork/ai/provider/cmd/tos-service-provider-mcp": true,
			"github.com/tosnetwork/ai/provider/pkg/mcpprovider":              true,
			"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi":   true,
			"github.com/tosnetwork/ai/protocol/pkg/agentsocket":              true,
			"github.com/tosnetwork/ai/protocol/internal/jsonstrict":          true,
			"github.com/tosnetwork/ai/protocol/internal/osguard":             true,
		}
		for _, path := range strings.Fields(string(listing)) {
			if strings.HasPrefix(path, "github.com/tosnetwork/") && !allowed[path] {
				t.Errorf("%s: the MCP server links %s", goos, path)
			}
		}
	}
}

func TestTheServerRefusesABadDeployment(t *testing.T) {
	root, err := os.MkdirTemp("", "pmc")
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
	export := filepath.Join(root, "export")
	if err := os.Mkdir(export, 0o700); err != nil {
		t.Fatal(err)
	}
	base := []string{"--agent-socket", socket, "--agent-state-dir", filepath.Join(root, "state"),
		"--rail-config", filepath.Join(root, "rail.json"), "--export-dir", export}
	for name, test := range map[string]struct {
		arguments []string
		env       map[string]string
		reason    string
	}{
		"VAULT_URL in the environment": {base, map[string]string{"VAULT_URL": "file:///vault"}, "vault"},
		"the rail's vault variable": {append(append([]string{}, base...), "--vault-url-env", "RAIL_VAULT"),
			map[string]string{"RAIL_VAULT": "x"}, "vault"},
		"a relative socket": {[]string{"--agent-socket", "agent.sock", "--agent-state-dir", "/x", "--rail-config", "/y",
			"--export-dir", export}, nil, "absolute"},
		// Every path here belongs to this account, as a custody account's
		// would to the agent: the state directory is missing, so it cannot
		// be checked.
		"an unchecked state directory": {base, nil, "cannot be checked"},
		"a positional argument":        {append(append([]string{}, base...), "extra"), nil, "positional"},
	} {
		for key, value := range test.env {
			t.Setenv(key, value)
		}
		err := run(context.Background(), test.arguments, &mcp.InMemoryTransport{})
		if err == nil || !strings.Contains(err.Error(), test.reason) {
			t.Errorf("%s: %v", name, err)
		}
		for key := range test.env {
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
	// With the state directory and rail configuration present but this
	// account the socket's owner, the server is the custody account.
	if os.Geteuid() == 0 {
		t.Skip("root opens every path")
	}
	closed := filepath.Join(root, "closed")
	if err := os.Mkdir(closed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(closed, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(closed, "rail.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(closed, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })
	err = run(context.Background(), []string{"--agent-socket", socket, "--agent-state-dir", filepath.Join(closed, "state"),
		"--rail-config", filepath.Join(closed, "rail.json"), "--export-dir", export}, &mcp.InMemoryTransport{})
	if err == nil || !strings.Contains(err.Error(), "owns the agent socket") {
		t.Fatalf("the custody account: %v", err)
	}
}
