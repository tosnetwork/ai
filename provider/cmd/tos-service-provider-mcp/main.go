// Command tos-service-provider-mcp is the stdio MCP server of the MCP
// provider adapter (spec/docs/MCP_PROVIDER_ADAPTER_V1.md). An MCP client
// starts it as a child process in the developer account. It holds no key,
// no vault credential and no journal; every request goes to the provider
// agent's socket, and no tool can publish an offer, move funds or lift an
// operator's pause: only the human, in the confirmer, can.
//
// stdout carries the MCP protocol only; diagnostics go to stderr.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tosnetwork/ai/provider/pkg/mcpprovider"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
)

func main() {
	if err := run(context.Background(), os.Args[1:], &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "tos-service-provider-mcp:", err)
		os.Exit(1)
	}
}

// clientTimeout bounds one agent call; the longest is a confirmation
// request that waits up to 300 seconds, and each tool sets its own
// shorter bound.
const clientTimeout = 6 * time.Minute

func run(ctx context.Context, arguments []string, transport mcp.Transport) error {
	set := flag.NewFlagSet("tos-service-provider-mcp", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	socket := set.String("agent-socket", "", "absolute path of the provider agent socket")
	stateDir := set.String("agent-state-dir", "", "absolute path of the provider agent's state directory, which this "+
		"account must not be able to open")
	railConfig := set.String("rail-config", "", "absolute path of the rail configuration, which this account must "+
		"not be able to open")
	exportDir := set.String("export-dir", "", "absolute path of the directory the offer file is exported to")
	vaultEnv := set.String("vault-url-env", "", "the rail configuration's vault_url_env, when it is not VAULT_URL; "+
		"this server refuses to start while it is set")
	if err := set.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if set.NArg() != 0 {
		return errors.New("tos-service-provider-mcp takes no positional arguments")
	}
	if err := mcpprovider.CheckDeployment(mcpprovider.Deployment{Environ: os.Environ(), VaultEnvs: []string{*vaultEnv},
		AgentSocket: *socket, AgentStateDir: *stateDir, RailConfig: *railConfig, UID: uint32(os.Geteuid())}); err != nil {
		return err
	}
	export, err := mcpprovider.NewExportDir(*exportDir)
	if err != nil {
		return err
	}
	client, err := agentapi.NewClient(*socket, clientTimeout)
	if err != nil {
		return err
	}
	tools, err := mcpprovider.NewTools(mcpprovider.Config{Agent: client, ExportDir: export})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return mcpprovider.NewServer(tools).Run(ctx, transport)
}
