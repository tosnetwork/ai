// Command tos-messenger-mcp is the stdio MCP server through which an MCP
// client writes to and reads from other Agents (MESSENGER_TRANSPORT_V2.md
// 13). An MCP client starts it as a child process. It holds no key and no
// credential and opens no relay connection: every request goes to the
// Messenger daemon's runtime socket, and it refuses to run on the owner's.
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
	"github.com/tosnetwork/ai/messenger/pkg/localapi"
	"github.com/tosnetwork/ai/messenger/pkg/mcpmessenger"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tos-messenger-mcp:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	set := flag.NewFlagSet("tos-messenger-mcp", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	socket := set.String("runtime-socket", "", "absolute path of the Messenger daemon's runtime socket")
	if err := set.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if set.NArg() != 0 {
		return errors.New("tos-messenger-mcp takes no positional arguments")
	}
	client, err := localapi.NewClient(*socket, 30*time.Second)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := mcpmessenger.CheckRuntimeSocket(ctx, client); err != nil {
		return err
	}
	tools, err := mcpmessenger.NewTools(mcpmessenger.Config{Daemon: client})
	if err != nil {
		return err
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "tos-messenger-mcp", Title: "TOS Messenger", Version: "1.0.0"}, nil)
	tools.Register(server)
	return server.Run(ctx, &mcp.StdioTransport{})
}
