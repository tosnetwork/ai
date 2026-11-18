package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
	"github.com/tosnetwork/ai/protocol/pkg/buyerconfirm"
)

// patternsFlag collects repeated --sensitive patterns.
type patternsFlag []string

func (p *patternsFlag) String() string { return "" }

func (p *patternsFlag) Set(value string) error {
	*p = append(*p, value)
	return nil
}

// runConfirm is `tos-service-buyer confirm`: the human's confirmer. It
// runs as the custody account, on a terminal that account logged in on,
// and refuses any other channel before it contacts the agent
// (MCP_BUYER_ADAPTER_V1 section 5).
func runConfirm(arguments []string) error {
	set := flag.NewFlagSet("confirm", flag.ContinueOnError)
	set.SetOutput(usageOutput)
	socket := set.String("agent-socket", "", "absolute path of the buyer agent socket")
	watch := set.Bool("watch", false, "keep showing purchases as clients ask for decisions")
	interval := set.Duration("interval", 5*time.Second, "how often --watch asks the agent, 1s to 1m")
	var extra patternsFlag
	set.Var(&extra, "sensitive", "an extra member-name pattern to highlight; repeatable")
	if err := set.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if set.NArg() != 0 {
		return errors.New("confirm takes no positional arguments")
	}
	if *interval < time.Second || *interval > time.Minute {
		return errors.New("--interval must be 1s to 1m")
	}
	tty, err := buyerconfirm.OpenTerminal(os.Stdin)
	if err != nil {
		return err
	}
	defer tty.Close()
	client, err := buyeragent.NewClient(*socket, 2*time.Minute)
	if err != nil {
		return err
	}
	patterns := append(append([]string(nil), buyerconfirm.DefaultSensitive...), extra...)
	session := &buyerconfirm.Session{Agent: client, In: bufio.NewReader(tty), Out: tty, Sensitive: patterns}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *watch {
		return session.Watch(ctx, *interval)
	}
	_, err = session.RunOnce(ctx)
	return err
}
