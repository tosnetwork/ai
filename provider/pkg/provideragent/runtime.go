package provideragent

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

// ServiceInterval is how often the node runs its duties and the agent its
// bound checks, as `serve` does.
const ServiceInterval = 5 * time.Second

// ServedNode is an opened node: *servicebridge.Node is one.
type ServedNode interface {
	Serve(ctx context.Context, interval time.Duration, started func() error) error
	Close() error
}

// SocketServer is the agent socket as the runtime drives it.
type SocketServer interface {
	Serve(ctx context.Context) error
}

// RuntimeOptions adjust the runtime; a deployment leaves them zero.
type RuntimeOptions struct {
	Interval  time.Duration
	OpenNode  func(ctx context.Context, config servicebridge.NodeConfig, options servicebridge.NodeOptions) (ServedNode, error)
	LockServe func(stateDir string) (func(), error)
}

// Runtime runs the node, the agent's bound checks and the socket together:
// serving does not depend on an MCP session, and a socket failure stops
// everything, as a `serve` restart would.
type Runtime struct {
	agent        *Agent
	server       SocketServer
	options      RuntimeOptions
	node         ServedNode
	releaseServe func()
}

func openServedNode(ctx context.Context, config servicebridge.NodeConfig, options servicebridge.NodeOptions) (ServedNode, error) {
	return servicebridge.OpenNode(ctx, config, options)
}

// NewRuntime opens the node as `serve` does when the offer is published.
// Before it is, the runtime holds the node's serve lock, so neither `serve`
// nor a second agent can open the node while this agent runs. Either way a
// node another process serves refuses the start.
func NewRuntime(ctx context.Context, agent *Agent, server SocketServer, options RuntimeOptions) (*Runtime, error) {
	if options.Interval <= 0 {
		options.Interval = ServiceInterval
	}
	if options.OpenNode == nil {
		options.OpenNode = openServedNode
	}
	if options.LockServe == nil {
		options.LockServe = servicebridge.LockServe
	}
	runtime := &Runtime{agent: agent, server: server, options: options}
	rail, err := agent.lib.Config()
	if err != nil {
		return nil, err
	}
	if rail.Provider == nil {
		runtime.releaseServe, err = options.LockServe(rail.StateDir)
		return runtime, err
	}
	runtime.node, err = options.OpenNode(ctx, rail, agent.nodeOptions())
	return runtime, err
}

// nodeOptions wire the agent's daily admission cap and its report ring.
func (a *Agent) nodeOptions() servicebridge.NodeOptions {
	return servicebridge.NodeOptions{Report: a.Report,
		AdmissionLimiter: servicebridge.DailyAdmissionCap{Max: a.config.MaxAdmissionsPerDay}}
}

// Run serves until ctx ends or the socket fails.
func (r *Runtime) Run(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var wait sync.WaitGroup
	var nodeErr error
	wait.Add(2)
	go func() {
		defer wait.Done()
		nodeErr = r.runNode(ctx)
		if nodeErr != nil {
			cancel()
		}
	}()
	go func() {
		defer wait.Done()
		r.runBounds(ctx)
	}()
	serveErr := r.server.Serve(ctx)
	cancel()
	wait.Wait()
	if r.releaseServe != nil {
		r.releaseServe()
		r.releaseServe = nil
	}
	if parent.Err() != nil && nodeErr == nil {
		return nil
	}
	return errors.Join(serveErr, nodeErr)
}

// runBounds runs the wallet floor check now and once per interval.
func (r *Runtime) runBounds(ctx context.Context) {
	ticker := time.NewTicker(r.options.Interval)
	defer ticker.Stop()
	for {
		if token, ok := r.agent.lib.(TokenLibrary); ok {
			checkCtx, cancel := context.WithTimeout(ctx, preflightTimeout)
			err := token.TokenSafety(checkCtx)
			cancel()
			if err != nil && ctx.Err() == nil {
				r.agent.Report("token safety", err)
			}
		}
		if _, err := r.agent.CheckWalletFloor(ctx); err != nil && ctx.Err() == nil {
			r.agent.Report("wallet floor", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runNode serves the node; before the offer it waits for the provider
// section a confirmed offer writes, then opens the node in the serve lock's
// place. A node that stops for any reason but ctx is reopened at the next
// interval. Another process serving the node stops the agent.
func (r *Runtime) runNode(ctx context.Context) error {
	for {
		if r.node == nil {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(r.options.Interval):
			}
			rail, err := r.agent.lib.Config()
			if err != nil || rail.Provider == nil {
				if err != nil {
					r.agent.Report("rail configuration", err)
				}
				continue
			}
			if r.releaseServe != nil {
				r.releaseServe()
				r.releaseServe = nil
			}
			r.node, err = r.options.OpenNode(ctx, rail, r.agent.nodeOptions())
			if errors.Is(err, servicebridge.ErrNodeServing) {
				return err
			}
			if err != nil {
				r.agent.Report("open the node", err)
				r.node = nil
				continue
			}
		}
		r.agent.serving.Store(true)
		err := r.node.Serve(ctx, r.options.Interval, nil)
		r.agent.serving.Store(false)
		closeErr := r.node.Close()
		r.node = nil
		if ctx.Err() != nil {
			return nil
		}
		if failure := errors.Join(err, closeErr); failure != nil {
			r.agent.Report("serve", failure)
		}
	}
}
