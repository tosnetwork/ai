package buyerinit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

func TestPlanSendsNothingAndCreatesNothing(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	report, err := Plan(context.Background(), in, w.env(true))
	if err != nil {
		t.Fatal(err)
	}
	got := statuses(report)
	for _, id := range []string{"wallet.create", "wallet.activate", "agent.register", "config.write"} {
		if got[id] != StatusPlanned {
			t.Errorf("%s is %q, not planned: %+v", id, got[id], report.Steps)
		}
	}
	if len(w.created) != 0 || w.sends != 0 || w.activations != 0 {
		t.Fatalf("a plan changed custody: created %v, %d sends, %d activations", w.created, w.sends, w.activations)
	}
	if _, err := os.Lstat(in.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a plan created the state directory: %v", err)
	}
	if _, err := os.Lstat(in.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a plan wrote the configuration")
	}
	if report.Complete {
		t.Fatal("a plan reported completion")
	}
}

func TestPlanOfAnExistingWalletShowsItsBalanceFundingAndTheAttachedValue(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	w.fundingDefault = 1_000_000_000
	if err := w.CreateWallet(context.Background(), "buyer"); err != nil {
		t.Fatal(err)
	}
	w.controllers["packet"] = controllerKey("packet")
	w.created = nil
	report, err := Plan(context.Background(), in, w.env(true))
	if err != nil {
		t.Fatal(err)
	}
	got := statuses(report)
	if got["wallet.fund"] != StatusPlanned || got["wallet.activate"] != StatusPlanned || got["agent.register"] != StatusPlanned {
		t.Fatalf("steps %+v", report.Steps)
	}
	if report.BalanceNano != "1000000000" || report.FundingNano != "1150000000" || report.WalletAddress == "" ||
		report.ControllerKey != controllerKey("packet").Text() {
		t.Fatalf("report %+v", report)
	}
	found := false
	for _, step := range report.Steps {
		if step.ID == "agent.register" && strings.Contains(step.Detail, "attaching 2000000000 nanoTOS") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the plan does not state the attached value: %+v", report.Steps)
	}
	if w.sends != 0 || w.activations != 0 || len(w.created) != 0 {
		t.Fatal("a plan sent or created something")
	}
	if _, err := os.Lstat(in.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a plan created the state directory")
	}
}

func TestApplyCreatesRegistersAndWritesTheStrictConfig(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	report, err := Apply(context.Background(), in, w.env(true))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Complete || w.sends != 1 || w.activations != 1 || len(w.created) != 2 {
		t.Fatalf("report %+v, %d sends, %d activations, created %v", report, w.sends, w.activations, w.created)
	}
	raw, err := os.ReadFile(in.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	config, err := DecodeAgentConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if config.BuyerAgentID != report.AgentID || config.BuyerWallet != w.wallets["buyer"].Address ||
		config.PacketControllerKeyID != controllerKey("packet").Text() || config.Network.GenesisRootHash != w.domain.GenesisRootHash ||
		config.RegistryCodeHash != w.domain.CodeHash || config.Relays[0] != "https://relay-a.example" ||
		config.Tosctl.SHA256 != in.TOSCTLSHA256 || config.ClientUID != 1000 || config.Quorum != 2 {
		t.Fatalf("config %+v", config)
	}
	for path, mode := range map[string]os.FileMode{in.ConfigPath: 0o600, in.StateDir: 0o700,
		filepath.Join(in.StateDir, "init"): 0o700, journalPath(in.StateDir): 0o600,
		filepath.Join(in.StateDir, "init", "agent-policy.json"): 0o600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Errorf("%s: %v %v, want %v", path, info.Mode().Perm(), err, mode)
		}
	}
	again, err := Apply(context.Background(), in, w.env(true))
	if err != nil {
		t.Fatal(err)
	}
	if w.sends != 1 || w.activations != 1 || len(w.created) != 2 || again.AgentID != report.AgentID {
		t.Fatalf("a re-run sent again: %d sends, %d activations, created %v", w.sends, w.activations, w.created)
	}
	if got := statuses(again); got["agent.register"] != StatusAlready || got["wallet.select"] != StatusAlready {
		t.Fatalf("re-run steps %+v", again.Steps)
	}
	// The configuration is strict: an unknown field or another schema is
	// refused.
	if _, err := DecodeAgentConfig([]byte(strings.Replace(string(raw), `"schema"`, `"extra": 1, "schema"`, 1))); err == nil {
		t.Fatal("an unknown field was accepted")
	}
	if _, err := DecodeAgentConfig([]byte(strings.Replace(string(raw), AgentConfigSchema, "other.v1", 1))); err == nil {
		t.Fatal("another schema was accepted")
	}
	if _, err := DecodeAgentConfig(append(raw, []byte(strings.Repeat(" ", MaxAgentConfigBytes))...)); err == nil {
		t.Fatal("a configuration over its bound was accepted")
	}
}

func TestInitRefusesRootAndTheDeveloperAccount(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	for name, uid := range map[string]int{"root": 0, "the developer account": 1000} {
		env := w.env(true)
		env.UID = func() int { return uid }
		for mode, run := range map[string]func(context.Context, Input, Env) (*Report, error){"plan": Plan, "apply": Apply} {
			if _, err := run(context.Background(), in, env); !errors.Is(err, ErrWrongAccount) {
				t.Errorf("%s as %s: %v", mode, name, err)
			}
		}
	}
	if len(w.created) != 0 || w.sends != 0 {
		t.Fatal("custody was touched")
	}
}

func TestApplyAsksBeforeEverySend(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	env := w.env(false)
	if _, err := Apply(context.Background(), in, env); !errors.Is(err, ErrConfirmationRequired) || w.activations != 0 {
		t.Fatalf("without a confirmer: %v, %d activations", err, w.activations)
	}
	var prompts []string
	env.Confirm = func(prompt string) (bool, error) { prompts = append(prompts, prompt); return false, nil }
	if _, err := Apply(context.Background(), in, env); !errors.Is(err, ErrConfirmationRequired) || w.activations != 0 {
		t.Fatalf("declined: %v", err)
	}
	env.Confirm = func(prompt string) (bool, error) { prompts = append(prompts, prompt); return true, nil }
	report, err := Apply(context.Background(), in, env)
	if err != nil || !report.Complete || w.sends != 1 {
		t.Fatalf("confirmed: %v", err)
	}
	if last := prompts[len(prompts)-1]; !strings.Contains(last, "attaching 2000000000 nanoTOS") {
		t.Fatalf("the registration prompt does not state its value: %q", last)
	}
	fresh := newWorld(t)
	failing := fresh.env(false)
	failing.Confirm = func(string) (bool, error) { return true, errors.New("no terminal") }
	if _, err := Apply(context.Background(), fresh.input(t), failing); err == nil || err.Error() != "no terminal" ||
		fresh.activations != 0 {
		t.Fatalf("a failed confirmation: %v", err)
	}
}

func TestApplyResumesAnAmbiguousSendFromFinalizedStateAndNeverResends(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	// The registration is broadcast, tosctl reports an error, and it lands
	// only after the wait budget.
	w.sendError = errors.New("tosctl wallet send: tosctl failed")
	w.landDelay = 2 * time.Minute
	if _, err := Apply(context.Background(), in, w.env(true)); !errors.Is(err, ErrOutcomeUnknown) || w.sends != 1 {
		t.Fatalf("an unseen send: %v, %d sends", err, w.sends)
	}
	journal, err := loadJournal(in.StateDir)
	if err != nil || journal.Agent.State != stepSending || journal.Registration == nil {
		t.Fatalf("the journal does not record the send in flight: %+v %v", journal, err)
	}
	// The re-run finds it still absent inside its window, waits instead of
	// sending, and sees it land.
	w.sendError = nil
	report, err := Apply(context.Background(), in, w.env(true))
	if err != nil || !report.Complete || w.sends != 1 || statuses(report)["agent.register"] != StatusDone {
		t.Fatalf("resume: %v, %d sends, %+v", err, w.sends, report.Steps)
	}
}

func TestApplyResendsOnlyAfterTheWindowPassesOnChainTime(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	w.lose = true
	w.sendError = errors.New("tosctl wallet send: tosctl failed")
	if _, err := Apply(context.Background(), in, w.env(true)); !errors.Is(err, ErrOutcomeUnknown) || w.sends != 1 {
		t.Fatalf("a lost send: %v", err)
	}
	// Inside the window nothing is re-sent, even after waiting.
	if _, err := Apply(context.Background(), in, w.env(true)); !errors.Is(err, ErrOutcomeUnknown) || w.sends != 1 {
		t.Fatalf("inside the window: %v, %d sends", err, w.sends)
	}
	w.now = w.now.Add(sendResolutionWindow)
	w.lose, w.sendError = false, nil
	report, err := Apply(context.Background(), in, w.env(true))
	if err != nil || !report.Complete || w.sends != 2 {
		t.Fatalf("past the window: %v, %d sends", err, w.sends)
	}
	journal, _ := loadJournal(in.StateDir)
	if journal.Agent.Attempts != 2 || journal.Agent.State != stepFinalized {
		t.Fatalf("journal %+v", journal.Agent)
	}
}

func TestApplyReturnsANotStartedSendToPending(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	w.sendError = buyersdk.ErrCallNotStarted
	if _, err := Apply(context.Background(), in, w.env(true)); !errors.Is(err, buyersdk.ErrCallNotStarted) {
		t.Fatalf("a refused send: %v", err)
	}
	journal, _ := loadJournal(in.StateDir)
	if journal.Agent.State != stepPending || journal.Agent.Attempts != 1 {
		t.Fatalf("journal %+v", journal.Agent)
	}
	w.sendError = nil
	if report, err := Apply(context.Background(), in, w.env(true)); err != nil || !report.Complete || w.sends != 1 {
		t.Fatalf("after the refusal: %v %d", err, w.sends)
	}
}

func TestApplyRefusesAChangedIdentityOnceRegistered(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	if _, err := Apply(context.Background(), in, w.env(true)); err != nil {
		t.Fatal(err)
	}
	changed := in
	changed.Controller = "packet-2"
	if _, err := Apply(context.Background(), changed, w.env(true)); !errors.Is(err, ErrInputChanged) || w.sends != 1 {
		t.Fatalf("a changed controller: %v, %d sends", err, w.sends)
	}
}

func TestApplyRefusesAConfiguredAgentWithoutAJournal(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	if _, err := Apply(context.Background(), in, w.env(true)); err != nil {
		t.Fatal(err)
	}
	fresh := in
	fresh.StateDir = in.StateDir + "-new"
	if _, err := Apply(context.Background(), fresh, w.env(true)); !errors.Is(err, ErrInputChanged) || w.sends != 1 {
		t.Fatalf("a second registration under an existing configuration: %v, %d sends", err, w.sends)
	}
	if err := os.WriteFile(in.ConfigPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), fresh, w.env(true)); !errors.Is(err, ErrInputChanged) {
		t.Fatalf("an unreadable existing configuration: %v", err)
	}
}

func TestApplyRefusesARegistrationForAnotherAddress(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	w.registrationAddress = "0:" + strings.Repeat("99", 32)
	if _, err := Apply(context.Background(), in, w.env(true)); err == nil || w.sends != 0 {
		t.Fatalf("a registration for another address: %v, %d sends", err, w.sends)
	}
	journal, _ := loadJournal(in.StateDir)
	if journal.Registration != nil {
		t.Fatal("the refused registration was journaled")
	}
}

func TestApplyRefusesAWalletWhoseMessagesDoNotExpire(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	for _, kind := range []string{"V1R3", ""} {
		w.walletType = kind
		if _, err := Apply(context.Background(), in, w.env(true)); err == nil || w.sends != 0 {
			t.Fatalf("a %q wallet: %v, %d sends", kind, err, w.sends)
		}
	}
}

func TestApplyStopsForFundingBeforeAnySend(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	// The activation's 0.1 TOS, the registration's 2 TOS and a 0.05 TOS
	// fee margin, stated here rather than derived from the code under test.
	const undeployedNeed, activeNeed = 2_150_000_000, 2_050_000_000
	w.fundingDefault = undeployedNeed - 1
	if _, err := Apply(context.Background(), in, w.env(true)); !errors.Is(err, ErrNeedsFunding) || w.activations != 0 {
		t.Fatalf("an undeployed wallet one nanoTOS short: %v, %d activations", err, w.activations)
	}
	w.fundingDefault = undeployedNeed
	if _, err := Apply(context.Background(), in, w.env(true)); err != nil {
		t.Fatalf("exactly funded: %v", err)
	}
	other := newWorld(t)
	otherIn := other.input(t)
	if err := other.CreateWallet(context.Background(), "buyer"); err != nil {
		t.Fatal(err)
	}
	other.accounts[other.wallets["buyer"].Address] = toschain.FinalizedAccount{State: "active", BalanceNano: activeNeed - 1}
	if _, err := Apply(context.Background(), otherIn, other.env(true)); !errors.Is(err, ErrNeedsFunding) || other.sends != 0 {
		t.Fatalf("an active wallet one nanoTOS short: %v", err)
	}
	other.accounts[other.wallets["buyer"].Address] = toschain.FinalizedAccount{State: "frozen", BalanceNano: 1 << 40}
	if _, err := Apply(context.Background(), otherIn, other.env(true)); err == nil || other.sends != 0 {
		t.Fatalf("a frozen wallet: %v", err)
	}
}

func TestInitRefusesEndpointsOffTheNetwork(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	w.genesisErr = errors.New("another genesis")
	if _, err := Plan(context.Background(), in, w.env(true)); err == nil {
		t.Fatal("an endpoint of another network was accepted")
	}
	w.genesisErr, w.custodyErr = nil, errors.New("tosctl would submit through https://x.example/jsonRPC")
	if _, err := Apply(context.Background(), in, w.env(true)); err == nil || len(w.created) != 0 {
		t.Fatalf("a tosctl endpoint off the verified set: %v", err)
	}
}

func TestInitRefusesRegistryCodeOfAnotherRelease(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	w.domain.CodeHash = "tvm-cell-sha256:" + strings.Repeat("ee", 32)
	if _, err := Plan(context.Background(), in, w.env(true)); err == nil {
		t.Fatal("registry code of another release was accepted")
	}
}

func TestInitRefusesAStateDirectoryOthersCanRead(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	if err := os.Mkdir(in.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(in.StateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for mode, run := range map[string]func(context.Context, Input, Env) (*Report, error){"plan": Plan, "apply": Apply} {
		if _, err := run(context.Background(), in, w.env(true)); err == nil {
			t.Errorf("%s accepted a 0755 state directory", mode)
		}
	}
}

func TestApplyRefusesAControllerThatDoesNotReadBack(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	custody := &swappingCustody{world: w}
	env := w.env(true)
	env.Custody = custody
	if _, err := Apply(context.Background(), in, env); err == nil || w.sends != 0 {
		t.Fatalf("a controller that reads back as another key: %v", err)
	}
}

// swappingCustody reports a created controller as another key on read
// back.
type swappingCustody struct{ *world }

func (s *swappingCustody) NewController(ctx context.Context, name string) (buyersdk.ControllerKey, error) {
	key, err := s.world.NewController(ctx, name)
	s.world.controllers[name] = controllerKey(name + "-swapped")
	return key, err
}

func TestAgentEffectRefusesContradictions(t *testing.T) {
	w := newWorld(t)
	r := &run{ctx: context.Background()}
	agentID := "agent_" + strings.Repeat("41", 32)
	key := controllerKey("packet").Text()
	land := func(state *nativev1.AgentStateV1) Session {
		w.agents[agentID] = agentLanding{at: w.now, state: state}
		s, _ := w.Begin(context.Background())
		return s
	}
	policy := &nativev1.ControllerPolicyV1{Controllers: []*nativev1.ControllerV1{{KeyId: key}}}
	if done, err := r.agentEffect(agentID, key)(land(&nativev1.AgentStateV1{AgentId: agentID, Policy: policy})); !done || err != nil {
		t.Fatalf("the live Agent: %v %v", done, err)
	}
	for name, state := range map[string]*nativev1.AgentStateV1{
		"another Agent": {AgentId: "agent_" + strings.Repeat("42", 32), Policy: policy},
		"a revoked one": {AgentId: agentID, Policy: policy, Tombstoned: true},
		"another key": {AgentId: agentID, Policy: &nativev1.ControllerPolicyV1{Controllers: []*nativev1.ControllerV1{
			{KeyId: controllerKey("other").Text()}}}},
	} {
		if _, err := r.agentEffect(agentID, key)(land(state)); err == nil {
			t.Errorf("%s was taken as the registration", name)
		}
	}
	s, _ := w.Begin(context.Background())
	delete(w.agents, agentID)
	if done, err := r.agentEffect(agentID, key)(s); done || err != nil {
		t.Fatalf("an absent Agent: %v %v", done, err)
	}
	capability := &capabilitySession{Session: s}
	if _, err := r.agentEffect(agentID, key)(capability); err == nil {
		t.Fatal("a Capability was taken as the Agent")
	}
}

type capabilitySession struct{ Session }

func (c *capabilitySession) ResolveRegistry(context.Context, string) (*nativev1.NativeStateV1, bool, error) {
	return &nativev1.NativeStateV1{State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{}}}, true, nil
}

func TestInitInputIsValidatedBeforeAnythingRuns(t *testing.T) {
	w := newWorld(t)
	valid := w.input(t)
	for name, mutate := range map[string]func(*Input){
		"a relative config":     func(in *Input) { in.ConfigPath = "agent.json" },
		"an unclean state dir":  func(in *Input) { in.StateDir = in.StateDir + "/." },
		"a relative CA file":    func(in *Input) { in.RelayCAFile = "ca.pem" },
		"an https relay, no CA": func(in *Input) { in.RelayCAFile = "" },
		"one https relay, no CA": func(in *Input) {
			in.Relays, in.RelayCAFile = []string{"http://127.0.0.1:8080", "https://relay-a.example"}, ""
		},
		"a config in the state":   func(in *Input) { in.ConfigPath = filepath.Join(in.StateDir, "agent.json") },
		"a nested config":         func(in *Input) { in.ConfigPath = filepath.Join(in.StateDir, "a", "agent.json") },
		"client uid zero":         func(in *Input) { in.ClientUID = 0 },
		"a flag wallet":           func(in *Input) { in.Wallet = "--all" },
		"a flag controller":       func(in *Input) { in.Controller = "-x" },
		"a short pin":             func(in *Input) { in.TOSCTLSHA256 = "71" },
		"an upper pin":            func(in *Input) { in.TOSCTLSHA256 = strings.Repeat("AB", 32) },
		"a non-hex pin":           func(in *Input) { in.TOSCTLSHA256 = strings.Repeat("zz", 32) },
		"a bare actor hash":       func(in *Input) { in.ActorCodeHash = strings.Repeat("61", 32) },
		"a short actor hash":      func(in *Input) { in.ActorCodeHash = "tvm-cell-sha256:61" },
		"another actor prefix":    func(in *Input) { in.ActorCodeHash = "tvm-cell-sha512:" + strings.Repeat("61", 32) },
		"two endpoints":           func(in *Input) { in.Endpoints = in.Endpoints[:2]; in.Quorum = 2 },
		"nine endpoints":          func(in *Input) { in.Endpoints = make([]string, 9); in.Quorum = 5 },
		"a minority quorum":       func(in *Input) { in.Quorum = 1 },
		"a quorum over endpoints": func(in *Input) { in.Quorum = 4 },
		"no relay":                func(in *Input) { in.Relays = nil },
		"five relays": func(in *Input) {
			in.Relays = []string{"https://r1.example", "https://r2.example", "https://r3.example", "https://r4.example",
				"https://r5.example"}
		},
		"a repeated relay":     func(in *Input) { in.Relays = []string{"https://r1.example", "https://r1.example"} },
		"a plain-http relay":   func(in *Input) { in.Relays = []string{"http://r1.example"} },
		"a padded per-call":    func(in *Input) { in.Budget.MaxPerCallNanoTOS = "01" },
		"a non-decimal window": func(in *Input) { in.Budget.MaxWindowNanoTOS = "1e9" },
		"a padded window":      func(in *Input) { in.Budget.MaxWindowNanoTOS = "010000000000" },
		"a 65-bit window":      func(in *Input) { in.Budget.MaxWindowNanoTOS = "18446744073709551616" },
		"a per-call over the window": func(in *Input) {
			in.Budget.MaxPerCallNanoTOS = "20000000000"
		},
		"a 32-day window":          func(in *Input) { in.Budget.WindowSeconds = 32 * 86_400 },
		"no window":                func(in *Input) { in.Budget.WindowSeconds = 0 },
		"no calls":                 func(in *Input) { in.Budget.MaxCalls = 0 },
		"no unconfirmed":           func(in *Input) { in.Budget.MaxUnconfirmed = 0 },
		"unconfirmed over calls":   func(in *Input) { in.Budget.MaxUnconfirmed = 101 },
		"negative lifecycle":       func(in *Input) { in.Budget.MaxLifecycleSends = -1 },
		"a long duty interval":     func(in *Input) { in.Budget.DutyIntervalSecond = 61 },
		"a negative duty interval": func(in *Input) { in.Budget.DutyIntervalSecond = -1 },
	} {
		in := valid
		in.Endpoints = append([]string(nil), valid.Endpoints...)
		in.Relays = append([]string(nil), valid.Relays...)
		mutate(&in)
		if err := checkInput(in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := checkInput(valid); err != nil {
		t.Fatal(err)
	}
	// A loopback http relay is reached without TLS, so it needs no CA.
	loopback := valid
	loopback.Relays, loopback.RelayCAFile = []string{"http://127.0.0.1:8080"}, ""
	if err := checkInput(loopback); err != nil {
		t.Fatalf("a loopback http relay without a CA: %v", err)
	}
	if _, err := Apply(context.Background(), Input{}, w.env(true)); err == nil || len(w.created) != 0 {
		t.Fatal("an empty input ran")
	}
}
