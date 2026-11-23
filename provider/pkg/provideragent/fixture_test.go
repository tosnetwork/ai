package provideragent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentsocket"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

const (
	testAgentID  = "agent_" + "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	testWallet   = "0:" + "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	testActor    = "0:" + "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
	testOther    = "0:" + "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"
	testEndpoint = "https://reader:s3cret@rpc.example.test:8443/token-abc123/api"
	testVault    = "https://vault.example.test/v1/secret-vault-token"
	testClient   = 424242
)

// fakeLibrary stands for the rail node library. Every send it is asked for
// is counted; previews return what the fields say at the time of the call.
type fakeLibrary struct {
	mutex    sync.Mutex
	railPath string
	config   servicebridge.NodeConfig

	preflightFail bool
	balance       uint64
	balanceErr    error

	credited    uint64
	withdrawErr error
	// withdrawActor is the actor a withdrawal preview names.
	withdrawActor string
	// beforeSend runs when a send is asked for, before anything is recorded;
	// withdrawSend runs after the record is written. Either may block.
	beforeSend    func()
	withdrawSend  func()
	withdrawSends int
	withdrawals   []servicebridge.WithdrawalRecord
	// recordsDir, when set, keeps the withdrawal records as files, so a
	// second process reads what the first recorded.
	recordsDir string

	offerPreview *servicebridge.OfferPreview
	offerPlanned []string
	offerErr     error
	offerSends   int

	status     *servicebridge.ProviderStatus
	records    []servicebridge.ProviderRecord
	offerBytes []byte
	describe   *OfferDescription
}

func (f *fakeLibrary) Config() (servicebridge.NodeConfig, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.config, nil
}

func (f *fakeLibrary) Status(context.Context, time.Time) (*servicebridge.ProviderStatus, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.config.Provider == nil {
		return nil, errNotOffered
	}
	if f.status == nil {
		return &servicebridge.ProviderStatus{Schema: servicebridge.ProviderStatusSchema}, nil
	}
	copied := *f.status
	copied.Requests = append([]servicebridge.RequestStatus(nil), f.status.Requests...)
	return &copied, nil
}

func (f *fakeLibrary) Preflight(context.Context) *servicebridge.PreflightReport {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	report := &servicebridge.PreflightReport{OK: true, Checks: []servicebridge.PreflightCheck{
		{ID: "state_dir.private", Status: servicebridge.CheckPass, Message: "state_dir " + f.config.StateDir + " is private"},
		{ID: "rpc.quorum", Status: servicebridge.CheckPass, Message: "quorum of " + testEndpoint},
		{ID: admissionCheckID, Status: servicebridge.CheckWarn, Message: "paused"},
	}}
	if f.preflightFail {
		report.OK = false
		report.Checks[1].Status = servicebridge.CheckFail
	}
	return report
}

func (f *fakeLibrary) Offer(_ context.Context, in servicebridge.OfferInput) (*servicebridge.OfferResult, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.offerErr != nil {
		return &servicebridge.OfferResult{Steps: []servicebridge.SetupStep{{ID: "x", Status: "failed",
			Detail: "tosctl said: " + testEndpoint}}}, f.offerErr
	}
	preview := *f.offerPreview
	preview.Terms, preview.Version = in.Terms, in.Version
	steps := []servicebridge.SetupStep{}
	for _, id := range f.offerPlanned {
		steps = append(steps, servicebridge.SetupStep{ID: id, Status: servicebridge.SetupPlanned, Detail: "planned"})
	}
	result := &servicebridge.OfferResult{Preview: &preview, Steps: steps}
	if !in.Yes {
		return result, servicebridge.ErrConfirmationRequired
	}
	f.offerSends++
	f.config.Provider = &servicebridge.ProviderNode{CapabilityID: preview.CapabilityID, Version: in.Version}
	result.Confirmed = true
	return result, nil
}

func (f *fakeLibrary) Withdraw(_ context.Context, in servicebridge.WithdrawInput) (*servicebridge.WithdrawResult, error) {
	if in.Yes && f.beforeSend != nil {
		f.beforeSend()
	}
	f.mutex.Lock()
	result := &servicebridge.WithdrawResult{}
	if f.withdrawErr != nil {
		defer f.mutex.Unlock()
		return result, f.withdrawErr
	}
	amount := in.AmountNano
	if in.All {
		amount = f.credited
	}
	switch {
	case f.credited == 0:
		f.mutex.Unlock()
		return result, servicebridge.ErrNothingToWithdraw
	case amount > f.credited:
		f.mutex.Unlock()
		return result, servicebridge.ErrWithdrawOverCredit
	}
	actor := f.withdrawActor
	if actor == "" {
		actor = testActor
	}
	result.Preview = &servicebridge.WithdrawPreview{Actor: actor, Destination: testWallet,
		CreditedNano: fmt.Sprint(f.credited), AmountNano: fmt.Sprint(amount), AttachedNano: "100000000",
		RemainingNano: fmt.Sprint(f.credited - amount), Checkpoint: 9}
	if !in.Yes {
		f.mutex.Unlock()
		return result, servicebridge.ErrConfirmationRequired
	}
	f.withdrawSends++
	record := servicebridge.WithdrawalRecord{QueryID: uint64(f.withdrawSends), Actor: actor, Destination: testWallet,
		AmountNano: fmt.Sprint(amount), State: servicebridge.WithdrawalSubmitted, StartedUnix: time.Now().Unix()}
	f.withdrawals = append(f.withdrawals, record)
	f.saveRecord(record)
	send := f.withdrawSend
	f.mutex.Unlock()
	if send != nil {
		send()
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.credited -= amount
	record.State = servicebridge.WithdrawalFinalized
	f.withdrawals[len(f.withdrawals)-1] = record
	f.saveRecord(record)
	result.Confirmed, result.Withdrawal = true, &record
	return result, nil
}

func (f *fakeLibrary) saveRecord(record servicebridge.WithdrawalRecord) {
	if f.recordsDir == "" {
		return
	}
	raw, err := json.Marshal(record)
	if err == nil {
		err = os.WriteFile(filepath.Join(f.recordsDir, fmt.Sprintf("%020d.json", record.QueryID)), raw, 0o600)
	}
	if err != nil {
		panic(err)
	}
}

func (f *fakeLibrary) Withdrawals() ([]servicebridge.WithdrawalRecord, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.recordsDir == "" {
		return append([]servicebridge.WithdrawalRecord(nil), f.withdrawals...), nil
	}
	entries, err := os.ReadDir(f.recordsDir)
	if err != nil {
		return nil, err
	}
	var out []servicebridge.WithdrawalRecord
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(f.recordsDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var record servicebridge.WithdrawalRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].QueryID < out[j].QueryID })
	return out, nil
}

func (f *fakeLibrary) ProviderRecords() ([]servicebridge.ProviderRecord, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return append([]servicebridge.ProviderRecord(nil), f.records...), nil
}

func (f *fakeLibrary) WalletBalance(context.Context) (servicebridge.WalletBalance, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.balanceErr != nil {
		return servicebridge.WalletBalance{}, f.balanceErr
	}
	return servicebridge.WalletBalance{Wallet: testWallet, State: "active", BalanceNano: f.balance, Checkpoint: 9}, nil
}

func (f *fakeLibrary) DescribeOffer(context.Context, string) (*OfferDescription, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.config.Provider == nil {
		return nil, errNotOffered
	}
	if f.describe == nil {
		return nil, servicebridge.ErrOfferMismatch
	}
	copied := *f.describe
	return &copied, nil
}

func (f *fakeLibrary) OfferFile(string) ([]byte, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.config.Provider == nil {
		return nil, errNotOffered
	}
	return f.offerBytes, nil
}

func (f *fakeLibrary) set(fn func(*fakeLibrary)) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	fn(f)
}

// testbed is one agent over a fake library, with its directories.
type testbed struct {
	t         *testing.T
	root      string
	lib       *fakeLibrary
	config    Config
	agent     *Agent
	clock     *testClock
	server    *agentsocket.Server
	peerUID   uint32
	peerMutex sync.Mutex
}

type testClock struct {
	mutex sync.Mutex
	now   time.Time
}

func (c *testClock) Now() time.Time {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.now = c.now.Add(d)
}

func privateDir(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// shortRoot is a short temporary directory, since a Unix socket path is
// bounded.
func shortRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("", "pa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func testConfig(root string) Config {
	return Config{Schema: ConfigSchema, RailConfig: filepath.Join(root, "rail.json"),
		StateDir: filepath.Join(root, "agent"), SocketDir: filepath.Join(root, "sock"), ClientUID: testClient,
		Offer: OfferInputs{ExecutorSocket: filepath.Join(root, "exec", "executor.sock"),
			OfferPath: filepath.Join(root, "rail", "setup", "offer.json")},
		Bounds: OfferBounds{MinPriceNanoTOS: "1000000", MaxPriceNanoTOS: "10000000000",
			MaxStorageFeeNanoTOS: "1000000000", MaxCleanupBountyNanoTOS: "500000000",
			MinResponseSLASeconds: 3600, MaxResponseSLASeconds: 86400, MinRefundClaimWindowSeconds: 3600,
			MaxRefundClaimWindowSeconds: 86400, MinRetentionSeconds: 3600, MaxRetentionSeconds: 604800}}
}

func newLibrary(root string) *fakeLibrary {
	return &fakeLibrary{railPath: filepath.Join(root, "rail.json"), balance: 5_000_000_000, credited: 3_000_000_000,
		config: servicebridge.NodeConfig{StateDir: filepath.Join(root, "rail"), AgentID: testAgentID,
			WalletAddress: testWallet, RPCEndpoints: []string{testEndpoint, "https://b.example.test", "https://c.example.test"},
			Network: servicebridge.NetworkConfig{NetworkID: "tos-local-test"},
			TOSCTL:  servicebridge.TOSCTLConfig{Binary: filepath.Join(root, "bin", "tosctl"), VaultURLEnv: "VAULT_URL"}},
		offerPreview: &servicebridge.OfferPreview{OwnerWallet: testWallet, ProviderAgentID: testAgentID, Actor: testActor,
			CapabilityID: "cap_" + strings.Repeat("e5", 32), ManifestDigest: "sha256:" + strings.Repeat("f6", 32),
			TotalAttachedNano: "2000000000", Note: "fixed library note"},
		offerPlanned: []string{"actor.deploy", "capability.register", "actor.policy"}}
}

// newTestbed opens an agent over a fresh fake library.
func newTestbed(t *testing.T) *testbed {
	t.Helper()
	root := shortRoot(t)
	return openTestbed(t, root, newLibrary(root))
}

func openTestbed(t *testing.T, root string, lib *fakeLibrary) *testbed {
	t.Helper()
	privateDir(t, filepath.Join(root, "rail"))
	if err := os.WriteFile(filepath.Join(root, "rail.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	socketDir := filepath.Join(root, "sock")
	if err := os.MkdirAll(socketDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socketDir, os.ModeSetgid|0o750); err != nil {
		t.Fatal(err)
	}
	config := testConfig(root)
	if err := config.check(); err != nil {
		t.Fatal(err)
	}
	bed := &testbed{t: t, root: root, lib: lib, config: config,
		clock: &testClock{now: time.Unix(1_800_000_000, 0)}}
	bed.open()
	return bed
}

func (b *testbed) open() {
	b.t.Helper()
	agent, err := Open(Options{Config: b.config, Library: b.lib, VaultURL: testVault, Now: b.clock.Now})
	if err != nil {
		b.t.Fatal(err)
	}
	b.agent = agent
	b.t.Cleanup(agent.Close)
}

// listen serves the agent's socket; every connection is attributed to the
// uid set with as.
func (b *testbed) listen() {
	b.t.Helper()
	server, err := b.agent.Listen(ServerOptions{CustodyUID: 1000, AgentGID: uint32(os.Getegid()) + 1,
		Peer: func(*net.UnixConn) (uint32, error) {
			b.peerMutex.Lock()
			defer b.peerMutex.Unlock()
			return b.peerUID, nil
		}})
	if err != nil {
		b.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(ctx)
	}()
	b.t.Cleanup(func() {
		cancel()
		<-done
	})
	b.server = server
}

const (
	asCustody = 1000
	asClient  = testClient
	asOther   = 777
)

// call sends one request over the socket as uid.
func (b *testbed) call(uid uint32, method string, params, result any) error {
	b.t.Helper()
	b.peerMutex.Lock()
	b.peerUID = uid
	b.peerMutex.Unlock()
	client, err := agentapi.NewClient(b.server.Path(), 10*time.Second)
	if err != nil {
		b.t.Fatal(err)
	}
	return client.Call(context.Background(), method, params, result)
}

func codeOf(err error) string {
	var known *agentapi.Error
	if errors.As(err, &known) {
		return known.Code
	}
	if err == nil {
		return ""
	}
	return "untyped: " + err.Error()
}

func validOffer(key string) agentapi.OfferPreviewParams {
	return agentapi.OfferPreviewParams{PriceNanoTOS: "2000000000", StorageFeeNanoTOS: "300000000",
		CleanupBountyNanoTOS: "100000000", ResponseSLASeconds: 7200, RefundClaimWindowSeconds: 7200,
		IdempotencyKey: key}
}

// confirm presents an action and decides it with its code, as the human
// does in the confirmer.
func (b *testbed) confirm(id string) agentapi.ActionView {
	b.t.Helper()
	presentation := b.present(id)
	view, err := b.agent.Decide(context.Background(), agentapi.DecideParams{ActionID: id,
		Decision: agentapi.DecisionConfirm, Code: presentation.Code})
	if err != nil {
		b.t.Fatalf("decide: %v", err)
	}
	return view.(agentapi.ActionView)
}

func (b *testbed) present(id string) agentapi.Presentation {
	b.t.Helper()
	wait := 0
	if _, err := b.agent.RequestConfirmation(context.Background(), agentsocket.RoleClient,
		agentapi.RequestConfirmationParams{ActionID: id, WaitSeconds: &wait}); err != nil {
		b.t.Fatalf("request confirmation: %v", err)
	}
	presented, err := b.agent.Present(agentapi.ActionParams{ActionID: id})
	if err != nil {
		b.t.Fatalf("present: %v", err)
	}
	return presented.(agentapi.Presentation)
}

func (b *testbed) action(id string) agentapi.ActionView {
	b.t.Helper()
	var record actionRecord
	var err error
	b.agent.withLock(func() { record, err = b.agent.loadLocked(id) })
	if err != nil {
		b.t.Fatal(err)
	}
	view, err := b.agent.actionView(agentsocket.RoleCustody, record)
	if err != nil {
		b.t.Fatal(err)
	}
	return view
}

func asView(t *testing.T, value any, err error) agentapi.ActionView {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	switch typed := value.(type) {
	case agentapi.ActionView:
		return typed
	case json.RawMessage:
		var view agentapi.ActionView
		if err := json.Unmarshal(typed, &view); err != nil {
			t.Fatal(err)
		}
		return view
	}
	t.Fatalf("not an action view: %T", value)
	return agentapi.ActionView{}
}
