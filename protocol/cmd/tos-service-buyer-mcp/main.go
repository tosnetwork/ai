// Command tos-service-buyer-mcp is the stdio MCP server of the MCP buyer
// adapter (spec/docs/MCP_BUYER_ADAPTER_V1.md). An MCP client starts it as
// a child process in the developer account. It holds no key, no vault
// credential and no journal; every request goes to the buyer agent's
// socket, and no tool can pay: only the human, in the confirmer, can.
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
	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
	"github.com/tosnetwork/ai/protocol/pkg/mcpbuyer"
)

// rootsFlag collects repeated --workspace-root values.
type rootsFlag []string

func (r *rootsFlag) String() string { return "" }

func (r *rootsFlag) Set(value string) error {
	*r = append(*r, value)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tos-service-buyer-mcp:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	set := flag.NewFlagSet("tos-service-buyer-mcp", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	socket := set.String("agent-socket", "", "absolute path of the buyer agent socket")
	stateDir := set.String("agent-state-dir", "", "absolute path of the buyer agent's state directory, which this account must not be able to read")
	var roots rootsFlag
	set.Var(&roots, "workspace-root", "a directory sources may be taken from; repeatable")
	if err := set.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if set.NArg() != 0 {
		return errors.New("tos-service-buyer-mcp takes no positional arguments")
	}
	if err := mcpbuyer.CheckDeployment(mcpbuyer.Deployment{Environ: os.Environ(), AgentStateDir: *stateDir,
		AgentSocket: *socket}); err != nil {
		return err
	}
	resolved, err := mcpbuyer.NewRoots(roots)
	if err != nil {
		return err
	}
	// The longest call is a payment request that waits up to 300 seconds.
	client, err := buyeragent.NewClient(*socket, 6*time.Minute)
	if err != nil {
		return err
	}
	tools, err := mcpbuyer.NewTools(mcpbuyer.Config{Agent: client, Roots: resolved})
	if err != nil {
		return err
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "tos-service-buyer-mcp", Title: "TOS buyer", Version: "1.0.0"}, nil)
	tools.Register(server)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.Run(ctx, &mcp.StdioTransport{})
}
