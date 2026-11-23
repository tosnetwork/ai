// Package provideragent is the provider agent of the MCP provider adapter
// (spec/docs/MCP_PROVIDER_ADAPTER_V1.md): the long-running process of the
// custody account that runs the rail node as `serve` does, serves the
// agent socket to the MCP server and the confirmer, keeps the action store
// and the pause-origin record, and applies an action only after a human
// confirmed it on the custody side.
package provideragent

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentsocket"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

// Options open an agent.
type Options struct {
	Config  Config
	Library Library
	// VaultURL is the vault credential the node uses; it is only redacted
	// here, never sent.
	VaultURL string
	Now      func() time.Time
	Random   func([]byte) error
	// Log receives every serving problem the ring keeps, redacted, for the
	// agent's standard error.
	Log func(line string)
}

// Agent is the provider agent.
type Agent struct {
	config   Config
	lib      Library
	vaultURL string
	now      func() time.Time
	random   func([]byte) error
	log      func(string)
	store    store
	// rail is the rail configuration as read at open: the node's identity
	// and state directory, which no later change of the file moves.
	rail servicebridge.NodeConfig

	// mutex guards the action store, the pause-origin record and the
	// memory-only counters; changed is closed and replaced at every action
	// change so waiters wake.
	mutex   sync.Mutex
	changed chan struct{}
	// previewSlot serializes the agent's library offer and withdraw calls:
	// every client preview, and an apply's fresh preview together with its
	// send. Two calls with one key therefore never both run the library and
	// store two actions, and since each library call takes the state
	// directory's run lock without waiting, the agent's own calls never make
	// each other fail with ErrSetupBusy. Its capacity is one.
	previewSlot chan struct{}
	// pauses serializes the agent's pause, resume and floor decisions.
	pauses sync.Mutex
	rates  *rates
	ring   *ring
	// serving reports whether the node is open and serving.
	serving atomic.Bool

	releaseDirectory func()
	// ctx bounds the apply runs, which outlive the decide call that starts
	// them; Close cancels it and waits for them.
	ctx      context.Context
	cancel   context.CancelFunc
	applying sync.WaitGroup

	// beforeRemove, when set, runs between the agent's check of a marker
	// and its compare-and-remove; tests re-stamp the marker there.
	beforeRemove func()
}

// Open checks the configuration and the rail configuration, takes the
// state directory's lock and resolves every action a crash left applying.
func Open(options Options) (*Agent, error) {
	if options.Library == nil {
		return nil, errors.New("the provider agent needs the rail library")
	}
	config := options.Config
	rail, err := options.Library.Config()
	if err != nil {
		return nil, fmt.Errorf("the rail configuration: %w", err)
	}
	if err := checkRailConfig(config.RailConfig, rail, config.StateDir, config.SocketDir); err != nil {
		return nil, err
	}
	if err := ensurePrivateDir(config.StateDir); err != nil {
		return nil, err
	}
	release, err := tryLock(filepath.Join(config.StateDir, directoryLock))
	if errors.Is(err, errLockHeld) {
		return nil, errors.New("another provider agent uses this state directory")
	}
	if err != nil {
		return nil, err
	}
	agent := &Agent{config: config, lib: options.Library, vaultURL: options.VaultURL, now: options.Now,
		random: options.Random, log: options.Log, store: store{root: config.StateDir}, rail: rail, changed: make(chan struct{}),
		previewSlot: make(chan struct{}, 1), rates: newRates(config.MaxWithdrawPreviewsPerDay), ring: &ring{},
		releaseDirectory: release}
	if agent.now == nil {
		agent.now = time.Now
	}
	if agent.random == nil {
		agent.random = func(value []byte) error {
			_, err := rand.Read(value)
			return err
		}
	}
	agent.ctx, agent.cancel = context.WithCancel(context.Background())
	if err := agent.store.ensure(); err != nil {
		agent.Close()
		return nil, err
	}
	if err := agent.recoverApplying(); err != nil {
		agent.Close()
		return nil, err
	}
	return agent, nil
}

// Close stops the apply runs and releases the state directory's lock.
func (a *Agent) Close() {
	a.cancel()
	a.applying.Wait()
	if a.releaseDirectory != nil {
		a.releaseDirectory()
		a.releaseDirectory = nil
	}
}

// previewWait bounds how long a client preview waits for the preview slot,
// so that, with the 20-second bound on the preview itself, the method still
// answers within 30 seconds.
const previewWait = 5 * time.Second

// holdPreviews takes the preview slot, waiting at most until ctx ends.
func (a *Agent) holdPreviews(ctx context.Context) (func(), error) {
	select {
	case a.previewSlot <- struct{}{}:
		return func() { <-a.previewSlot }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// RailStateDir is the node's state directory.
func (a *Agent) RailStateDir() string { return a.rail.StateDir }

// notifyLocked wakes every waiter; the caller holds a.mutex.
func (a *Agent) notifyLocked() {
	close(a.changed)
	a.changed = make(chan struct{})
}

func (a *Agent) withLock(fn func()) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	fn()
}

// redactor builds the client's redaction from the current rail
// configuration, which gains the provider's paths once the offer is
// published, and the configuration read at open.
func (a *Agent) redactor() *redactor {
	rail, err := a.lib.Config()
	if err != nil {
		rail = a.rail
	}
	redact := newRedactor(rail, a.config, a.config.RailConfig, a.vaultURL)
	if err == nil {
		// Paths of the configuration read at open stay redacted too.
		redact.paths = append(redact.paths, newRedactor(a.rail, a.config, a.config.RailConfig, "").paths...)
	}
	return redact
}

// out renders a result for role: the custody account sees it as it is, the
// client account its redacted view.
func (a *Agent) out(role agentsocket.Role, value any) (any, error) {
	if role == agentsocket.RoleCustody {
		return value, nil
	}
	return a.redactor().view(value)
}

// Report records one serving problem: on standard error by the caller, and
// in the in-memory ring that status shows, redacted.
func (a *Agent) Report(stage string, err error) {
	if err == nil {
		return
	}
	line := time.Now().UTC().Format(time.RFC3339) + " " + stage + ": " + err.Error()
	line = a.redactor().text(strings.Join(strings.Fields(line), " "))
	a.ring.add(line)
	if a.log != nil {
		a.log(line)
	}
}

// ring keeps the last lines of the serving report in memory.
type ring struct {
	mutex sync.Mutex
	lines []string
}

const ringSize = 256

func (r *ring) add(line string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if len(line) > 1024 {
		line = line[:1024]
	}
	r.lines = append(r.lines, line)
	if len(r.lines) > ringSize {
		r.lines = append([]string(nil), r.lines[len(r.lines)-ringSize:]...)
	}
}

func (r *ring) last(count int) []string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	start := len(r.lines) - count
	if start < 0 {
		start = 0
	}
	return append([]string{}, r.lines[start:]...)
}

// Rate groups and their per-minute bounds (section 4.2).
const (
	rateRead      = "status_records"
	rateDescribe  = "describe_export"
	ratePreflight = "preflight"
	ratePause     = "pause_resume"
	ratePreview   = "previews"
)

var perMinute = map[string]int{rateRead: 30, rateDescribe: 20, ratePreflight: 6, ratePause: 10, ratePreview: 10}

// rates counts the client's calls, in memory only.
type rates struct {
	mutex            sync.Mutex
	calls            map[string][]time.Time
	withdrawals      []time.Time
	withdrawalPerDay int
}

func newRates(withdrawalsPerDay int) *rates {
	return &rates{calls: map[string][]time.Time{}, withdrawalPerDay: withdrawalsPerDay}
}

func keep(times []time.Time, since time.Time) []time.Time {
	kept := times[:0]
	for _, at := range times {
		if at.After(since) {
			kept = append(kept, at)
		}
	}
	return kept
}

// take counts one call of group at now, or refuses it over the bound. With
// withdrawal set it also counts against the daily withdrawal previews.
func (r *rates) take(group string, now time.Time, withdrawal bool) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	calls := keep(r.calls[group], now.Add(-time.Minute))
	if len(calls) >= perMinute[group] {
		r.calls[group] = calls
		return agentapi.Refusal(agentapi.CodeRateLimited, "too many calls of this kind in the last minute", nil)
	}
	if withdrawal {
		r.withdrawals = keep(r.withdrawals, now.Add(-24*time.Hour))
		if len(r.withdrawals) >= r.withdrawalPerDay {
			r.calls[group] = calls
			return agentapi.Refusal(agentapi.CodeRateLimited, "the daily bound on withdrawal previews is reached", nil)
		}
		r.withdrawals = append(r.withdrawals, now)
	}
	r.calls[group] = append(calls, now)
	return nil
}

func (r *rates) withdrawalsToday(now time.Time) int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.withdrawals = keep(r.withdrawals, now.Add(-24*time.Hour))
	return len(r.withdrawals)
}

// limit applies the rate bound to the client account; the custody account,
// the operator, is not bounded.
func (a *Agent) limit(role agentsocket.Role, group string, withdrawal bool) error {
	if role == agentsocket.RoleCustody {
		return nil
	}
	return a.rates.take(group, a.now(), withdrawal)
}
