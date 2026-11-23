package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/buyerconfirm"
	"github.com/tosnetwork/ai/provider/pkg/provideragent"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
	"github.com/tosnetwork/ai/provider/pkg/providerconfirm"
)

// runAgent is `tos-service-provider agent`: the provider agent of the MCP
// provider adapter, in the custody account. It runs the node as `serve`
// does and serves the agent socket to the MCP server and the confirmer.
func runAgent(ctx context.Context, set *flag.FlagSet, arguments []string, std streams) error {
	var path string
	set.StringVar(&path, "config", "", "owner-private provider agent configuration (JSON)")
	if done, err := parse(set, arguments, "config"); done || err != nil {
		return err
	}
	config, err := provideragent.ReadConfig(path)
	if err != nil {
		return err
	}
	logLine := func(line string) { fmt.Fprintln(std.err, line) }
	library := provideragent.Rail{Path: config.RailConfig, Report: logLine}
	rail, err := library.Config()
	if err != nil {
		return err
	}
	vaultURL := ""
	if rail.TOSCTL.VaultURLEnv != "" {
		vaultURL = os.Getenv(rail.TOSCTL.VaultURLEnv)
	}
	agent, err := provideragent.Open(provideragent.Options{Config: config, Library: library, VaultURL: vaultURL,
		Log: logLine})
	if err != nil {
		return err
	}
	defer agent.Close()
	server, err := agent.Listen(provideragent.ServerOptions{})
	if err != nil {
		return err
	}
	runtime, err := provideragent.NewRuntime(ctx, agent, server, provideragent.RuntimeOptions{})
	if err != nil {
		return errors.Join(err, server.Close())
	}
	if err := printJSON(std.out, map[string]any{"agent": true, "socket": server.Path(),
		"rail_state_dir_served": agent.RailStateDir()}); err != nil {
		return errors.Join(err, server.Close())
	}
	return runtime.Run(ctx)
}

// runConfirm is `tos-service-provider confirm`: the human's confirmer. It
// runs as the custody account, on a terminal that account logged in on, and
// refuses any other channel before it contacts the agent (section 5.2).
func runConfirm(ctx context.Context, set *flag.FlagSet, arguments []string, std streams) error {
	var socket string
	var watch bool
	var interval time.Duration
	set.StringVar(&socket, "agent-socket", "", "absolute path of the provider agent socket")
	set.BoolVar(&watch, "watch", false, "keep showing actions as clients ask for decisions")
	set.DurationVar(&interval, "interval", 5*time.Second, "how often --watch asks the agent, 1s to 1m")
	if done, err := parse(set, arguments, "agent-socket"); done || err != nil {
		return err
	}
	if interval < time.Second || interval > time.Minute {
		return usagef("--interval must be 1s to 1m")
	}
	client, err := agentapi.NewClient(socket, 2*time.Minute)
	if err != nil {
		return err
	}
	// The decision goes only to the agent of this custody account: a
	// socket another account owns is refused before anything is sent.
	if err := providerconfirm.CheckAgentSocket(socket); err != nil {
		return err
	}
	tty, err := buyerconfirm.OpenTerminal(os.Stdin)
	if err != nil {
		return err
	}
	defer tty.Close()
	session := &providerconfirm.Session{Agent: client, In: bufio.NewReader(tty), Out: tty}
	if watch {
		return session.Watch(ctx, interval)
	}
	_, err = session.RunOnce(ctx)
	return err
}
