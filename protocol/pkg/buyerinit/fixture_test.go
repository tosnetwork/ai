package buyerinit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

// world is a fake chain and a fake tosctl custody over one clock. Nothing
// in it reaches a network, a vault or a real chain.
type world struct {
	t       *testing.T
	now     time.Time
	locator *nativecore.Locator
	domain  buyersdk.RegistryDomain

	wallets     map[string]buyersdk.CustodyWallet
	walletType  string
	controllers map[string]buyersdk.ControllerKey
	// accounts are finalized accounts by address; a missing one is
	// uninitialized with fundingDefault.
	accounts       map[string]toschain.FinalizedAccount
	fundingDefault uint64
	// agents land in finalized state at their landing time.
	agents map[string]agentLanding
	// registrationAddress overrides the destination tosctl reports.
	registrationAddress string
	// onlineAddress overrides the address an online listing reports.
	onlineAddress string
	// registerErr fails the registration build; nonces records the nonce
	// of every build; drawn counts the nonces init drew.
	registerErr error
	// readErr and controllerReadErr fail the custody reads as an
	// unreachable vault does.
	readErr           error
	controllerReadErr error
	nonces            []string
	drawn             int

	// sendError is returned by SendRegistration; landDelay is how long
	// after a send the Agent appears; lose drops the message.
	sendError error
	landDelay time.Duration
	lose      bool

	custodyErr  error
	genesisErr  error
	checkpoint  uint64
	sends       int
	activations int
	created     []string
}

type agentLanding struct {
	at    time.Time
	state *nativev1.AgentStateV1
}

func newWorld(t *testing.T) *world {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "nativecore", "testdata", "native_registry_v1_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		CodeHash string `json:"contract_code_hash"`
		Code     string `json:"contract_code_boc_base64"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	domain := buyersdk.RegistryDomain{NetworkLabel: "tos:global-id:7", GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
		GenesisFileHash: "sha256:" + strings.Repeat("22", 32), CodeHash: vectors.CodeHash}
	locator, err := nativecore.NewLocator(&nativev1.NetworkDomain{NetworkId: domain.NetworkLabel,
		GenesisRootHash: domain.GenesisRootHash, GenesisFileHash: domain.GenesisFileHash}, 0, vectors.Code, vectors.CodeHash)
	if err != nil {
		t.Fatal(err)
	}
	return &world{t: t, now: time.Unix(1_800_000_000, 0), locator: locator, domain: domain,
		wallets: map[string]buyersdk.CustodyWallet{}, walletType: "V4R2", controllers: map[string]buyersdk.ControllerKey{},
		accounts: map[string]toschain.FinalizedAccount{}, fundingDefault: 3_000_000_000,
		agents: map[string]agentLanding{}, checkpoint: 100}
}

func (w *world) registryCode(t *testing.T, directory string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "nativecore", "testdata", "native_registry_v1_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Code string `json:"contract_code_boc_base64"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "registry.boc.base64")
	if err := os.WriteFile(path, []byte(vectors.Code+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Custody.

func (w *world) CheckEndpoints(context.Context) error { return w.custodyErr }

func (w *world) Domain(context.Context) (buyersdk.RegistryDomain, error) { return w.domain, nil }

func (w *world) Wallet(_ context.Context, name string, online bool) (buyersdk.CustodyWallet, error) {
	if w.readErr != nil {
		return buyersdk.CustodyWallet{}, w.readErr
	}
	wallet, ok := w.wallets[name]
	if !ok {
		return buyersdk.CustodyWallet{}, buyersdk.ErrTOSCTLAbsent
	}
	if online {
		wallet.Type = w.walletType
		if w.onlineAddress != "" {
			wallet.Address = w.onlineAddress
		}
	}
	return wallet, nil
}

func (w *world) CreateWallet(_ context.Context, name string) error {
	if _, ok := w.wallets[name]; ok {
		return errors.New("exists")
	}
	digest := sha256.Sum256([]byte("wallet:" + name))
	w.wallets[name] = buyersdk.CustodyWallet{Name: name, Address: "0:" + hex.EncodeToString(digest[:])}
	w.created = append(w.created, "wallet:"+name)
	return nil
}

func (w *world) ActivateWallet(_ context.Context, name string) error {
	w.activations++
	address := w.wallets[name].Address
	account := w.account(address)
	account.State = "active"
	w.accounts[address] = account
	return nil
}

func controllerKey(name string) buyersdk.ControllerKey {
	public := make([]byte, mldsa44.PublicKeySize)
	copy(public, name)
	id, _ := mldsa44.KeyID(public)
	return buyersdk.ControllerKey{Name: name, KeyID: id, PublicKey: public}
}

func (w *world) Controller(_ context.Context, name string) (buyersdk.ControllerKey, error) {
	if w.controllerReadErr != nil {
		return buyersdk.ControllerKey{}, w.controllerReadErr
	}
	key, ok := w.controllers[name]
	if !ok {
		return buyersdk.ControllerKey{}, buyersdk.ErrTOSCTLAbsent
	}
	return key, nil
}

func (w *world) NewController(_ context.Context, name string) (buyersdk.ControllerKey, error) {
	key := controllerKey(name)
	w.controllers[name] = key
	w.created = append(w.created, "controller:"+name)
	return key, nil
}

func (w *world) RegisterAgent(_ context.Context, policyPath, nonce, signer string) (buyersdk.SignedAgentRegistration, error) {
	if _, err := os.Stat(policyPath); err != nil {
		return buyersdk.SignedAgentRegistration{}, err
	}
	w.nonces = append(w.nonces, nonce)
	if w.registerErr != nil {
		return buyersdk.SignedAgentRegistration{}, w.registerErr
	}
	digest := sha256.Sum256([]byte(nonce + signer))
	agentID := "agent_" + hex.EncodeToString(digest[:])
	located, err := w.locator.Locate(agentID)
	if err != nil {
		return buyersdk.SignedAgentRegistration{}, err
	}
	if w.registrationAddress != "" {
		located.Address = w.registrationAddress
	}
	return buyersdk.SignedAgentRegistration{AgentID: agentID, Destination: located.Address,
		ActionHash: strings.Repeat("51", 32), StateInitBOC: "te6cckEBAQEAAgAAAEysuc0=", BodyBOC: "te6cckEBAQEAAgAAAEysuc0="}, nil
}

func (w *world) SendRegistration(_ context.Context, wallet string, value uint64, registration buyersdk.SignedAgentRegistration) error {
	if errors.Is(w.sendError, buyersdk.ErrCallNotStarted) {
		return w.sendError
	}
	if !w.account(w.wallets[wallet].Address).Active() {
		w.t.Errorf("a registration was sent from an inactive wallet")
		return buyersdk.ErrCallNotStarted
	}
	w.sends++
	if value != RegistrationValueNano || wallet != "buyer" {
		w.t.Errorf("sent %d from %s", value, wallet)
	}
	if !w.lose {
		key := w.controllers["packet"]
		w.agents[registration.AgentID] = agentLanding{at: w.now.Add(w.landDelay), state: &nativev1.AgentStateV1{
			AgentId: registration.AgentID, Policy: &nativev1.ControllerPolicyV1{Controllers: []*nativev1.ControllerV1{
				{KeyId: key.Text(), Weight: 1}}}}}
	}
	return w.sendError
}

func (w *world) account(address string) toschain.FinalizedAccount {
	if account, ok := w.accounts[address]; ok {
		return account
	}
	return toschain.FinalizedAccount{State: "uninitialized", BalanceNano: w.fundingDefault}
}

// Chain.

type session struct {
	w          *world
	checkpoint uint64
	time       time.Time
}

func (w *world) Begin(context.Context) (Session, error) {
	w.checkpoint++
	return &session{w: w, checkpoint: w.checkpoint, time: w.now}, nil
}

func (w *world) Endpoints() []string { return []string{"https://a.example/jsonRPC"} }

func (w *world) CheckEndpointGenesis(context.Context, string) error { return w.genesisErr }

func (s *session) Checkpoint() uint64   { return s.checkpoint }
func (s *session) ChainTime() time.Time { return s.time }

func (s *session) Account(_ context.Context, address string) (toschain.FinalizedAccount, error) {
	return s.w.account(address), nil
}

func (s *session) ResolveRegistry(_ context.Context, objectID string) (*nativev1.NativeStateV1, bool, error) {
	landing, ok := s.w.agents[objectID]
	if !ok || s.time.Before(landing.at) {
		return nil, false, nil
	}
	return &nativev1.NativeStateV1{State: &nativev1.NativeStateV1_Agent{Agent: landing.state}}, true, nil
}

// env wires the world into init, with a clock that sleeping advances.
func (w *world) env(yes bool) Env {
	return Env{Custody: w, Chain: w, UID: func() int { return 4242 }, Yes: yes,
		Now:          func() time.Time { return w.now },
		Sleep:        func(_ context.Context, d time.Duration) error { w.now = w.now.Add(d); return nil },
		PollInterval: 10 * time.Second, WaitBudget: time.Minute,
		Nonce: func() (string, error) {
			w.drawn++
			return strings.Repeat(fmt.Sprintf("%02x", w.drawn), 32), nil
		}}
}

// input is a valid input under a fresh custody directory.
func (w *world) input(t *testing.T) Input {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return Input{ConfigPath: filepath.Join(root, "agent-config.json"), StateDir: filepath.Join(root, "state"),
		SocketDir: filepath.Join(root, "socket"), ClientUID: 1000, NetworkLabel: "tos:global-id:7",
		GlobalConfig: "/etc/tos/global.config.json",
		Endpoints:    []string{"https://a.example", "https://b.example", "https://c.example"}, Quorum: 2,
		RegistryCodeFile: w.registryCode(t, root), ActorCodeHash: "tvm-cell-sha256:" + strings.Repeat("61", 32),
		ManifestDir: filepath.Join(root, "manifests"), TOSCTLBinary: "/opt/tosctl/tosctl",
		TOSCTLSHA256: strings.Repeat("71", 32), TOSCTLConfig: filepath.Join(root, "tosctl-config.json"),
		Wallet: "buyer", Controller: "packet", Relays: []string{"https://relay-b.example", "https://relay-a.example"},
		RelayCAFile: filepath.Join(root, "relay-ca.pem"),
		Budget: BudgetConfig{WindowSeconds: 86_400, MaxCalls: 100, MaxPerCallNanoTOS: "1000000000",
			MaxWindowNanoTOS: "10000000000", MaxUnconfirmed: 4}}
}

func statuses(report *Report) map[string]string {
	result := map[string]string{}
	for _, step := range report.Steps {
		result[step.ID] = step.Status
	}
	return result
}
