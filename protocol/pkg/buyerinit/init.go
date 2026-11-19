// Package buyerinit is `tos-service-buyer init`: it creates the buyer's
// identity on the TOS chain through the pinned tosctl, in a plan step that
// sends nothing and an apply step that journals and resumes every chain
// message (MCP_BUYER_ADAPTER_V1 section 3.2). It never sees key material:
// tosctl creates and holds the wallet and controller keys.
package buyerinit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/osguard"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

// Values init attaches or needs, in nanoTOS.
const (
	// RegistrationValueNano funds the Agent registration message.
	RegistrationValueNano uint64 = 2_000_000_000
	// ActivationMinimumNano is the least balance tosctl deploys a wallet
	// with.
	ActivationMinimumNano uint64 = 100_000_000
	// walletFeeMarginNano covers the wallet's own fees for the sends.
	walletFeeMarginNano uint64 = 50_000_000
)

// Send timing. tosctl signs a wallet message valid for walletMessageLifetime
// from the moment it signs, which is at most maxSendTime after the step is
// stamped: every send runs under that deadline and tosctl is killed at it.
// So sendResolutionWindow after the stamp, an absent message can no longer
// be included, and a slow tosctl cannot sign later than the window allows.
// tosctl's wallet send reports no valid_until of its own to use instead.
const (
	maxSendTime           = 3 * time.Minute
	walletMessageLifetime = 2 * time.Minute
	sendResolutionWindow  = maxSendTime + walletMessageLifetime
)

var (
	// ErrConfirmationRequired is a send the human did not confirm.
	ErrConfirmationRequired = errors.New("buyerinit: the send was not confirmed; nothing was sent")
	// ErrOutcomeUnknown is a send that is neither finalized nor known to
	// be lost; nothing is re-sent until it is.
	ErrOutcomeUnknown = errors.New("buyerinit: the outcome of an earlier send is not known yet")
	// ErrInputChanged is an input that differs from the one an Agent was
	// already registered with.
	ErrInputChanged = errors.New("buyerinit: an identity input changed after the Agent was registered")
	// ErrNeedsFunding is a wallet that cannot pay the next step.
	ErrNeedsFunding = errors.New("buyerinit: the wallet needs funding")
	// ErrWrongAccount is init run as root or as the developer account.
	ErrWrongAccount = errors.New("buyerinit: init runs only as the custody account")
)

// Custody is the tosctl side; buyersdk.TOSCTLInitCustody implements it.
type Custody interface {
	CheckEndpoints(ctx context.Context) error
	Domain(ctx context.Context) (buyersdk.RegistryDomain, error)
	Wallet(ctx context.Context, name string, online bool) (buyersdk.CustodyWallet, error)
	CreateWallet(ctx context.Context, name string) error
	ActivateWallet(ctx context.Context, name string) error
	Controller(ctx context.Context, name string) (buyersdk.ControllerKey, error)
	NewController(ctx context.Context, name string) (buyersdk.ControllerKey, error)
	RegisterAgent(ctx context.Context, policyPath, nonce, signer string) (buyersdk.SignedAgentRegistration, error)
	SendRegistration(ctx context.Context, wallet string, valueNano uint64, registration buyersdk.SignedAgentRegistration) error
}

// Session is one quorum-finalized checkpoint.
type Session interface {
	Checkpoint() uint64
	ChainTime() time.Time
	Account(ctx context.Context, account string) (toschain.FinalizedAccount, error)
	ResolveRegistry(ctx context.Context, objectID string) (*nativev1.NativeStateV1, bool, error)
}

// Chain opens finalized sessions and vets endpoints.
type Chain interface {
	Begin(ctx context.Context) (Session, error)
	Endpoints() []string
	CheckEndpointGenesis(ctx context.Context, endpoint string) error
}

// Input is what the custody account chooses.
type Input struct {
	// ConfigPath is the agent configuration init writes.
	ConfigPath string
	// StateDir is the agent's state directory; the init journal lives in
	// its init subdirectory.
	StateDir  string
	SocketDir string
	// ClientUID is the developer account the MCP server runs as.
	ClientUID        uint32
	NetworkLabel     string
	GlobalConfig     string
	Endpoints        []string
	Quorum           int
	RegistryCodeFile string
	ActorCodeHash    string
	ManifestDir      string
	TOSCTLBinary     string
	TOSCTLSHA256     string
	TOSCTLConfig     string
	Wallet           string
	Controller       string
	Relays           []string
	RelayCAFile      string
	Budget           BudgetConfig
}

// Env is what init needs from its surroundings.
type Env struct {
	Custody Custody
	Chain   Chain
	// UID is the effective uid init runs as.
	UID func() int
	// Confirm asks the human to confirm one chain send; nil refuses.
	Confirm func(prompt string) (bool, error)
	// Yes confirms every send without asking.
	Yes          bool
	Now          func() time.Time
	Sleep        func(ctx context.Context, d time.Duration) error
	PollInterval time.Duration
	WaitBudget   time.Duration
	Nonce        func() (string, error)
	Report       func(line string)
}

// Step outcomes.
const (
	StatusDone    = "done"
	StatusAlready = "already_done"
	StatusPlanned = "planned"
)

// StepReport is one line of the report.
type StepReport struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// ReportSchema names the init report.
const ReportSchema = "tos.service.mcp-buyer.init-report.v1"

// Report is what init did or, in a plan, would do.
type Report struct {
	Schema        string       `json:"schema"`
	Mode          string       `json:"mode"`
	Complete      bool         `json:"complete"`
	ConfigPath    string       `json:"config_path"`
	WalletAddress string       `json:"wallet_address,omitempty"`
	BalanceNano   string       `json:"finalized_balance_nanotos,omitempty"`
	FundingNano   string       `json:"funding_needed_nanotos,omitempty"`
	ControllerKey string       `json:"packet_controller_key_id,omitempty"`
	AgentID       string       `json:"buyer_agent_id,omitempty"`
	Steps         []StepReport `json:"steps"`
}

// Check is what Plan and Apply check first, for a caller that opens custody
// before running them: the account and every input.
func Check(in Input, uid int) error {
	if err := checkAccount(uid, in.ClientUID); err != nil {
		return err
	}
	return checkInput(in)
}

// checkInput validates every input before anything runs.
func checkInput(in Input) error {
	var problems []string
	for name, path := range map[string]string{"--config": in.ConfigPath, "--state-dir": in.StateDir,
		"--socket-dir": in.SocketDir, "--global-config": in.GlobalConfig, "--registry-code-boc": in.RegistryCodeFile,
		"--manifest-dir": in.ManifestDir, "--tosctl": in.TOSCTLBinary, "--tosctl-config": in.TOSCTLConfig} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			problems = append(problems, name+" must be an absolute clean path")
		}
	}
	if in.RelayCAFile != "" && (!filepath.IsAbs(in.RelayCAFile) || filepath.Clean(in.RelayCAFile) != in.RelayCAFile) {
		problems = append(problems, "--relay-ca-file must be an absolute clean path")
	}
	if filepath.Dir(in.ConfigPath) == in.StateDir || strings.HasPrefix(in.ConfigPath, in.StateDir+"/") {
		problems = append(problems, "--config must not be inside the agent state directory")
	}
	if in.ClientUID == 0 {
		problems = append(problems, "--client-uid must name the developer account, not root")
	}
	if !buyersdk.TOSCTLNamePattern.MatchString(in.Wallet) || !buyersdk.TOSCTLNamePattern.MatchString(in.Controller) {
		problems = append(problems, "--wallet and --packet-controller must be tosctl names")
	}
	if len(in.TOSCTLSHA256) != 64 || strings.ToLower(in.TOSCTLSHA256) != in.TOSCTLSHA256 {
		problems = append(problems, "--tosctl-sha256 must be 64 lowercase hex digits")
	}
	if _, err := hex.DecodeString(in.TOSCTLSHA256); err != nil {
		problems = append(problems, "--tosctl-sha256 must be hex")
	}
	if !strings.HasPrefix(in.ActorCodeHash, "tvm-cell-sha256:") || len(in.ActorCodeHash) != len("tvm-cell-sha256:")+64 {
		problems = append(problems, "--actor-code-hash must be tvm-cell-sha256:<64 hex>")
	}
	if len(in.Endpoints) < 3 || len(in.Endpoints) > 8 {
		problems = append(problems, "--rpc must name 3 to 8 endpoints")
	}
	if in.Quorum <= len(in.Endpoints)/2 || in.Quorum > len(in.Endpoints) {
		problems = append(problems, "--quorum must be a strict majority of the endpoints")
	}
	if _, err := canonicalRelays(in.Relays); err != nil {
		problems = append(problems, err.Error())
	}
	if err := checkBudget(in.Budget); err != nil {
		problems = append(problems, err.Error())
	}
	// The agent verifies relays against the pinned CA only, so an https
	// relay without one could never be reached.
	for _, relay := range in.Relays {
		if strings.HasPrefix(relay, "https://") && in.RelayCAFile == "" {
			problems = append(problems, "an https --relay needs --relay-ca-file")
			break
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New("buyerinit: " + strings.Join(problems, "; "))
	}
	return nil
}

// canonicalRelays sorts the relay base URLs and requires 1 to 4 distinct
// canonical ones, the buyer card's bound.
func canonicalRelays(relays []string) ([]string, error) {
	if len(relays) == 0 || len(relays) > agentpacketseal.MaxRelays {
		return nil, errors.New("--relay must name 1 to 4 relays")
	}
	sorted := append([]string(nil), relays...)
	sort.Strings(sorted)
	for index, relay := range sorted {
		if err := agentpacketseal.CheckRelayURL(relay); err != nil {
			return nil, fmt.Errorf("--relay %q is not a canonical relay base URL", relay)
		}
		if index > 0 && sorted[index-1] == relay {
			return nil, fmt.Errorf("--relay %q is named twice", relay)
		}
	}
	return sorted, nil
}

// checkBudget applies the bounds of section 6.
func checkBudget(budget BudgetConfig) error {
	perCall, ok := new(big.Int).SetString(budget.MaxPerCallNanoTOS, 10)
	if !ok || perCall.String() != budget.MaxPerCallNanoTOS {
		return errors.New("--max-per-call-nanotos must be a canonical decimal")
	}
	window, ok := new(big.Int).SetString(budget.MaxWindowNanoTOS, 10)
	if !ok || window.String() != budget.MaxWindowNanoTOS {
		return errors.New("--max-window-nanotos must be a canonical decimal")
	}
	if !perCall.IsUint64() || !window.IsUint64() {
		return errors.New("the budget amounts must fit 64 bits, as the tosctl path carries")
	}
	limits := buyersdk.ServiceActorLimits{Window: time.Duration(budget.WindowSeconds) * time.Second,
		MaxCalls: budget.MaxCalls, MaxPerCallNanoTOS: perCall, MaxWindowNanoTOS: window,
		MaxPrepared: budget.MaxUnconfirmed}
	if budget.WindowSeconds <= 0 || budget.WindowSeconds > 31*24*3600 || !limits.Valid() || budget.MaxUnconfirmed < 1 {
		return errors.New("the budget must have a window of at most 31 days, 1 to 100000 calls, a positive per-call " +
			"limit within the window limit, and 1 to max-calls unconfirmed purchases")
	}
	if budget.MaxLifecycleSends < 0 || budget.DutyIntervalSecond < 0 || budget.DutyIntervalSecond > 60 {
		return errors.New("--max-lifecycle-sends must not be negative and --duty-interval must be 0 to 60 seconds")
	}
	return nil
}

// checkAccount refuses root and the developer account: the keys and the
// journal belong to the custody account alone (section 2.1).
func checkAccount(uid int, client uint32) error {
	if uid == 0 {
		return fmt.Errorf("%w: it refuses to run as root", ErrWrongAccount)
	}
	if uid == int(client) {
		return fmt.Errorf("%w: it refuses to run as the developer account (uid %d)", ErrWrongAccount, client)
	}
	return nil
}

func (e *Env) fill() {
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.UID == nil {
		e.UID = os.Geteuid
	}
	if e.Sleep == nil {
		e.Sleep = func(ctx context.Context, d time.Duration) error {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	if e.PollInterval == 0 {
		e.PollInterval = 5 * time.Second
	}
	if e.WaitBudget == 0 {
		e.WaitBudget = 3 * time.Minute
	}
	if e.Nonce == nil {
		e.Nonce = func() (string, error) {
			value := make([]byte, 32)
			if _, err := rand.Read(value); err != nil {
				return "", err
			}
			return hex.EncodeToString(value), nil
		}
	}
	if e.Report == nil {
		e.Report = func(string) {}
	}
}

// run carries one plan or apply.
type run struct {
	ctx      context.Context
	in       Input
	env      Env
	apply    bool
	journal  *Journal
	report   *Report
	planned  bool
	saveable bool
}

func (r *run) note(id, status, format string, arguments ...any) {
	line := StepReport{ID: id, Status: status, Detail: fmt.Sprintf(format, arguments...)}
	r.report.Steps = append(r.report.Steps, line)
	if status == StatusPlanned {
		r.planned = true
	}
	r.env.Report(line.ID + ": " + line.Status + ": " + line.Detail)
}

func (r *run) save() error {
	if !r.saveable {
		return nil
	}
	return saveJournal(r.in.StateDir, r.journal, r.env.Now())
}

// Plan prints every change init would make and sends nothing: it creates no
// directory, key or file and writes no journal.
func Plan(ctx context.Context, in Input, env Env) (*Report, error) {
	return execute(ctx, in, env, false)
}

// Apply makes the changes, journaling each chain step before it is sent and
// resolving every earlier send from finalized state before anything new is
// sent.
func Apply(ctx context.Context, in Input, env Env) (*Report, error) {
	return execute(ctx, in, env, true)
}

func execute(ctx context.Context, in Input, env Env, apply bool) (*Report, error) {
	env.fill()
	mode := "plan"
	if apply {
		mode = "apply"
	}
	report := &Report{Schema: ReportSchema, Mode: mode, ConfigPath: in.ConfigPath, Steps: []StepReport{}}
	if ctx == nil || env.Custody == nil || env.Chain == nil {
		return report, errors.New("buyerinit: no context, custody or chain")
	}
	if err := checkAccount(env.UID(), in.ClientUID); err != nil {
		return report, err
	}
	if err := checkInput(in); err != nil {
		return report, err
	}
	relays, err := canonicalRelays(in.Relays)
	if err != nil {
		return report, err
	}
	r := &run{ctx: ctx, in: in, env: env, apply: apply, report: report}
	if apply {
		// One apply at a time per state directory, from before the journal
		// is read: two runs that both read "no Agent yet" would draw two
		// nonces and register two Agents.
		if err := ensurePrivateDir(in.StateDir); err != nil {
			return report, err
		}
		if err := ensurePrivateDir(filepath.Join(in.StateDir, initDirectory)); err != nil {
			return report, err
		}
		release, acquired, err := osguard.TryExclusiveFileLock(filepath.Join(in.StateDir, initDirectory, lockFile), 0o600)
		if err != nil {
			return report, err
		}
		if !acquired {
			return report, errors.New("buyerinit: another init holds this state directory")
		}
		defer release()
		r.saveable = true
	} else if _, err := os.Lstat(in.StateDir); err == nil {
		if err := checkPrivateDir(in.StateDir); err != nil {
			return report, err
		}
	}
	r.journal, err = loadJournal(in.StateDir)
	if err != nil {
		return report, err
	}
	// A configuration that already names an Agent with no journal beside
	// it is never answered with a second registration.
	if !r.journal.registered() {
		if raw, readErr := readPrivateFile(in.ConfigPath, MaxAgentConfigBytes); readErr == nil {
			existing, decodeErr := DecodeAgentConfig(raw)
			if decodeErr != nil || existing.BuyerAgentID != "" {
				return report, fmt.Errorf("%w: %s already configures a buyer Agent but this state directory holds no "+
					"init journal for it; init will not register a second Agent", ErrInputChanged, in.ConfigPath)
			}
		} else if !errors.Is(readErr, os.ErrNotExist) {
			return report, readErr
		}
	}
	config, err := r.establish(relays)
	if err != nil {
		return report, err
	}
	if config == nil {
		return report, nil
	}
	if !apply {
		r.note("config.write", StatusPlanned, "the agent configuration %s will be written (0600) naming Agent %s",
			in.ConfigPath, config.BuyerAgentID)
		return report, nil
	}
	if err := writeAgentConfig(in.ConfigPath, *config); err != nil {
		return report, err
	}
	r.note("config.write", StatusDone, "wrote the agent configuration %s (0600); it reads back strictly", in.ConfigPath)
	report.Complete = true
	return report, nil
}

// establish runs every step up to the configuration. It returns nil
// configuration, with the report filled, when a plan has nothing further it
// can know.
func (r *run) establish(relays []string) (*AgentConfig, error) {
	ctx, in, custody := r.ctx, r.in, r.env.Custody
	r.note("tosctl.pin", StatusDone, "tosctl %s is pinned to SHA-256 %s", in.TOSCTLBinary, in.TOSCTLSHA256)
	domain, err := custody.Domain(ctx)
	if err != nil {
		return nil, fmt.Errorf("buyerinit: derive the identity domain: %w", err)
	}
	network := &nativev1.NetworkDomain{NetworkId: in.NetworkLabel, GenesisRootHash: domain.GenesisRootHash,
		GenesisFileHash: domain.GenesisFileHash}
	code, err := os.ReadFile(in.RegistryCodeFile)
	if err != nil || len(code) == 0 || len(code) > 1<<20 {
		return nil, errors.New("buyerinit: the registry code file cannot be read within 1 MiB")
	}
	locator, err := nativecore.NewLocator(network, 0, strings.Join(strings.Fields(string(code)), ""), domain.CodeHash)
	if err != nil {
		return nil, fmt.Errorf("buyerinit: the registry code file does not hold the Native Registry code this tosctl "+
			"signs for (%s): %w", domain.CodeHash, err)
	}
	if err := r.checkEndpoints(); err != nil {
		return nil, err
	}
	r.note("network.domain", StatusDone, "network %q (genesis root %s, file %s), registry code %s; every RPC endpoint "+
		"serves that genesis and tosctl submits only through them", in.NetworkLabel, domain.GenesisRootHash,
		domain.GenesisFileHash, domain.CodeHash)

	wallet, err := r.ensureWallet()
	if err != nil || wallet == nil {
		return nil, err
	}
	controller, err := r.ensureController()
	if err != nil || controller == nil {
		return nil, err
	}
	identity := Identity{NetworkID: in.NetworkLabel, GenesisRootHash: domain.GenesisRootHash,
		GenesisFileHash: domain.GenesisFileHash, RegistryCodeHash: domain.CodeHash, Wallet: in.Wallet,
		WalletAddress: wallet.Address, Controller: in.Controller, ControllerKeyID: controller.Text()}
	if r.journal.Identity != identity {
		if r.journal.registered() {
			return nil, fmt.Errorf("%w: the journal registered with %+v, these inputs give %+v; restore the "+
				"earlier inputs or use another state directory", ErrInputChanged, r.journal.Identity, identity)
		}
		r.journal = &Journal{Schema: JournalSchema, Identity: identity}
	}
	if err := r.save(); err != nil {
		return nil, err
	}
	agentID, err := r.ensureAgent(wallet, controller, locator)
	if err != nil || agentID == "" {
		return nil, err
	}
	r.report.AgentID = agentID
	return &AgentConfig{Schema: AgentConfigSchema, StateDir: in.StateDir, SocketDir: in.SocketDir,
		ClientUID: in.ClientUID, Network: NetworkConfig{NetworkID: network.NetworkId,
			GenesisRootHash: network.GenesisRootHash, GenesisFileHash: network.GenesisFileHash},
		Endpoints: append([]string(nil), in.Endpoints...), Quorum: in.Quorum, RegistryCodeFile: in.RegistryCodeFile,
		RegistryCodeHash: domain.CodeHash, ActorCodeHash: in.ActorCodeHash, ManifestDir: in.ManifestDir,
		BuyerWallet: wallet.Address, BuyerAgentID: agentID,
		Tosctl: TosctlConfig{Binary: in.TOSCTLBinary, SHA256: in.TOSCTLSHA256, ConfigPath: in.TOSCTLConfig,
			Wallet: in.Wallet, Controller: in.Controller},
		PacketControllerKeyID: controller.Text(), Relays: relays, RelayCAFile: in.RelayCAFile, Budget: in.Budget}, nil
}

// checkEndpoints requires every configured endpoint to serve the network's
// genesis, and tosctl to submit through none but them.
func (r *run) checkEndpoints() error {
	for index, endpoint := range r.env.Chain.Endpoints() {
		if err := r.env.Chain.CheckEndpointGenesis(r.ctx, endpoint); err != nil {
			return fmt.Errorf("buyerinit: RPC endpoint %d does not serve the network's genesis: %w", index, err)
		}
	}
	if err := r.env.Custody.CheckEndpoints(r.ctx); err != nil {
		return fmt.Errorf("buyerinit: %w", err)
	}
	return nil
}

// ensureWallet selects the configured wallet or creates it. A plan stops
// here when the wallet does not exist yet: its address is unknown.
func (r *run) ensureWallet() (*buyersdk.CustodyWallet, error) {
	ctx, name := r.ctx, r.in.Wallet
	wallet, err := r.env.Custody.Wallet(ctx, name, false)
	switch {
	case err == nil:
		r.note("wallet.select", StatusAlready, "wallet %q is %s", name, wallet.Address)
	case !errors.Is(err, buyersdk.ErrTOSCTLAbsent):
		return nil, fmt.Errorf("buyerinit: wallet %q could not be read (check VAULT_URL and the tosctl "+
			"configuration): %w", name, err)
	case !r.apply:
		r.note("wallet.create", StatusPlanned, "wallet %q (%s, workchain 0) will be created in the tosctl vault and "+
			"configuration; nothing is sent", name, buyersdk.BuyerWalletVersion)
		r.planRest()
		return nil, nil
	default:
		if err := r.env.Custody.CreateWallet(ctx, name); err != nil {
			return nil, fmt.Errorf("buyerinit: create wallet %q: %w", name, err)
		}
		if wallet, err = r.env.Custody.Wallet(ctx, name, false); err != nil {
			return nil, fmt.Errorf("buyerinit: wallet %q does not read back as created: %w", name, err)
		}
		r.note("wallet.create", StatusDone, "created wallet %q (%s): %s", name, buyersdk.BuyerWalletVersion,
			wallet.Address)
	}
	r.report.WalletAddress = wallet.Address
	return &wallet, nil
}

// ensureController selects the packet controller or creates it.
func (r *run) ensureController() (*buyersdk.ControllerKey, error) {
	ctx, name := r.ctx, r.in.Controller
	key, err := r.env.Custody.Controller(ctx, name)
	switch {
	case err == nil:
		r.note("controller.select", StatusAlready, "packet controller %q is in the vault with key id %s", name, key.Text())
	case !errors.Is(err, buyersdk.ErrTOSCTLAbsent):
		return nil, fmt.Errorf("buyerinit: controller %q could not be read (check VAULT_URL and the tosctl "+
			"configuration): %w", name, err)
	case !r.apply:
		r.note("controller.create", StatusPlanned, "packet controller %q (ML-DSA-44) will be created in the tosctl "+
			"vault; nothing is sent", name)
		r.planRest()
		return nil, nil
	default:
		created, err := r.env.Custody.NewController(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("buyerinit: create controller %q: %w", name, err)
		}
		// What was created is read back, so the key registered is the key
		// stored.
		if key, err = r.env.Custody.Controller(ctx, name); err != nil || key.KeyID != created.KeyID {
			return nil, fmt.Errorf("buyerinit: controller %q does not read back as created", name)
		}
		r.note("controller.create", StatusDone, "created packet controller %q with key id %s", name, key.Text())
	}
	r.report.ControllerKey = key.Text()
	return &key, nil
}

// planRest lists the steps a plan cannot detail yet.
func (r *run) planRest() {
	r.note("wallet.activate", StatusPlanned, "if the wallet is not active: once it holds at least %d nanoTOS, it "+
		"will be activated (its deployment spends fees from its own balance); funding it is your step",
		fundingNeed(false))
	r.note("agent.register", StatusPlanned, "an Agent registration (policy: controller %q alone, weight 1, every "+
		"purpose) will be signed in custody and sent from wallet %q attaching %d nanoTOS; init then waits for the "+
		"Agent in finalized state", r.in.Controller, r.in.Wallet, RegistrationValueNano)
	r.note("relay.cards", StatusAlready, "relays %s; the agent issues its key card per purchase window when it "+
		"first needs one (section 3.3), so init creates no relay key", strings.Join(r.in.Relays, ", "))
	r.note("config.write", StatusPlanned, "the agent configuration %s will be written (0600)", r.in.ConfigPath)
}

// fundingNeed is the balance the remaining sends need.
func fundingNeed(active bool) uint64 {
	need := RegistrationValueNano + walletFeeMarginNano
	if !active {
		need += ActivationMinimumNano
	}
	return need
}

// begin opens a finalized session.
func (r *run) begin() (Session, error) {
	session, err := r.env.Chain.Begin(r.ctx)
	if err != nil {
		return nil, fmt.Errorf("buyerinit: no finalized checkpoint by strict majority: %w", err)
	}
	return session, nil
}

// ensureAgent activates the wallet if needed, then builds, sends and awaits
// the Agent registration. It returns "" when a plan stops before sending.
func (r *run) ensureAgent(wallet *buyersdk.CustodyWallet, controller *buyersdk.ControllerKey,
	locator *nativecore.Locator) (string, error) {
	session, err := r.begin()
	if err != nil {
		return "", err
	}
	account, err := session.Account(r.ctx, wallet.Address)
	if err != nil {
		return "", fmt.Errorf("buyerinit: read wallet %s: %w", wallet.Address, err)
	}
	r.report.BalanceNano = fmt.Sprint(account.BalanceNano)
	r.note("wallet.balance", StatusDone, "wallet %s is %s with a finalized balance of %d nanoTOS at checkpoint %d",
		wallet.Address, account.State, account.BalanceNano, session.Checkpoint())
	if account.State == "frozen" {
		return "", fmt.Errorf("buyerinit: wallet %s is frozen", wallet.Address)
	}
	agentDone := false
	if r.journal.Registration != nil {
		found, err := r.agentEffect(r.journal.Registration.AgentID, controller.Text())(session)
		if err != nil {
			return "", err
		}
		agentDone = found
	}
	if !agentDone {
		if need := fundingNeed(account.Active()); account.BalanceNano < need {
			r.report.FundingNano = fmt.Sprint(need - account.BalanceNano)
			if r.apply {
				return "", fmt.Errorf("%w: wallet %s holds %d nanoTOS; the remaining steps need %d: send at least %d "+
					"nanoTOS to it and run init apply again", ErrNeedsFunding, wallet.Address, account.BalanceNano, need,
					need-account.BalanceNano)
			}
			r.note("wallet.fund", StatusPlanned, "fund wallet %s with at least %d more nanoTOS (your step)",
				wallet.Address, need-account.BalanceNano)
		}
		if !account.Active() || r.journal.Activation.sent() {
			if err := r.chainStep("wallet.activate", "the activation of wallet "+wallet.Address, &r.journal.Activation, 0,
				func(s Session) (bool, error) {
					value, err := s.Account(r.ctx, wallet.Address)
					return value.Active(), err
				}, func(ctx context.Context) error { return r.env.Custody.ActivateWallet(ctx, r.in.Wallet) }); err != nil {
				return "", err
			}
		}
	}
	if r.journal.Registration == nil {
		if !r.apply {
			r.planRegistration()
			return "", nil
		}
		if err := r.buildRegistration(controller, locator); err != nil {
			return "", err
		}
	}
	registration := *r.journal.Registration
	if !agentDone && r.apply {
		// The registration is sent only from a wallet whose messages expire,
		// so a send absent past its window can no longer land.
		online, err := r.env.Custody.Wallet(r.ctx, r.in.Wallet, true)
		if err != nil {
			return "", fmt.Errorf("buyerinit: read the type of wallet %q: %w", r.in.Wallet, err)
		}
		if online.Address != wallet.Address || !buyersdk.ExpiringWalletTypes[online.Type] {
			return "", fmt.Errorf("buyerinit: wallet %q is a %q wallet; its messages must expire (V3R2, V4R2 or "+
				"V5R1) so a lost send cannot land later; nothing was sent", r.in.Wallet, online.Type)
		}
	}
	if err := r.chainStep("agent.register", "the registration of Agent "+registration.AgentID, &r.journal.Agent,
		RegistrationValueNano, r.agentEffect(registration.AgentID, controller.Text()), func(ctx context.Context) error {
			return r.env.Custody.SendRegistration(ctx, r.in.Wallet, RegistrationValueNano, registration)
		}); err != nil {
		return "", err
	}
	if !r.apply {
		return "", nil
	}
	r.note("relay.cards", StatusAlready, "relays %s; the agent issues its key card per purchase window when it "+
		"first needs one (section 3.3), so init creates no relay key", strings.Join(r.in.Relays, ", "))
	return registration.AgentID, nil
}

func (r *run) planRegistration() {
	r.note("agent.register", StatusPlanned, "an Agent registration (policy: controller %q alone, weight 1, every "+
		"purpose) will be signed in custody and sent from wallet %q attaching %d nanoTOS; init then waits for the "+
		"Agent in finalized state", r.in.Controller, r.in.Wallet, RegistrationValueNano)
	r.note("relay.cards", StatusAlready, "relays %s; the agent issues its key card per purchase window when it "+
		"first needs one (section 3.3), so init creates no relay key", strings.Join(r.in.Relays, ", "))
}

// buildRegistration draws the nonce durably, has tosctl sign the
// registration and journals it before anything is sent.
func (r *run) buildRegistration(controller *buyersdk.ControllerKey, locator *nativecore.Locator) error {
	if r.journal.AgentNonce == "" {
		nonce, err := r.env.Nonce()
		if err != nil {
			return err
		}
		r.journal.AgentNonce = nonce
		if err := r.save(); err != nil {
			return err
		}
	}
	policy, err := buyersdk.BuyerAgentPolicy(*controller)
	if err != nil {
		return err
	}
	policyPath := filepath.Join(r.in.StateDir, initDirectory, policyFile)
	if err := writePrivateFile(policyPath, policy); err != nil {
		return err
	}
	registration, err := r.env.Custody.RegisterAgent(r.ctx, policyPath, r.journal.AgentNonce, r.in.Controller)
	if err != nil {
		return fmt.Errorf("buyerinit: build the Agent registration: %w", err)
	}
	located, err := locator.Locate(registration.AgentID)
	if err != nil || located.Address != registration.Destination {
		return errors.New("buyerinit: tosctl built a registration for another address than the one the Agent ID " +
			"derives under the network and registry code; nothing was sent")
	}
	r.journal.Registration = &registration
	return r.save()
}

// agentEffect reports whether the Agent is live in finalized state under a
// policy holding the packet controller.
func (r *run) agentEffect(agentID, keyID string) func(Session) (bool, error) {
	return func(session Session) (bool, error) {
		state, found, err := session.ResolveRegistry(r.ctx, agentID)
		if err != nil {
			return false, fmt.Errorf("buyerinit: read Agent %s: %w", agentID, err)
		}
		if !found {
			return false, nil
		}
		agent := state.GetAgent()
		if agent == nil || agent.GetAgentId() != agentID {
			return false, fmt.Errorf("buyerinit: the registry object at %s is not that Agent", agentID)
		}
		if agent.GetTombstoned() {
			return false, fmt.Errorf("buyerinit: Agent %s is revoked", agentID)
		}
		for _, held := range agent.GetPolicy().GetControllers() {
			if held.GetKeyId() == keyID {
				return true, nil
			}
		}
		return false, fmt.Errorf("buyerinit: Agent %s is registered but its policy does not hold packet key %s",
			agentID, keyID)
	}
}
