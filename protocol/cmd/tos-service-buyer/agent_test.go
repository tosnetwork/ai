package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
)

// fakeRuntime records what the runtime starts and stops.
type fakeRuntime struct {
	mu        sync.Mutex
	interval  time.Duration
	duties    bool
	polling   bool
	lookedUp  string
	closed    bool
	stopped   chan struct{}
	serveErr  error
	serveDone chan struct{}
}

func (f *fakeRuntime) RunDuties(ctx context.Context, interval time.Duration, report func([]error)) {
	f.mu.Lock()
	f.duties, f.interval = true, interval
	f.mu.Unlock()
	report([]error{errors.New("a duty failure")})
	<-ctx.Done()
	f.stopped <- struct{}{}
}

func (f *fakeRuntime) LookupPurchase(requestHash string) (buyeragent.InboundPurchase, bool, error) {
	f.mu.Lock()
	f.lookedUp = requestHash
	f.mu.Unlock()
	return buyeragent.InboundPurchase{}, false, nil
}

func (f *fakeRuntime) Close() {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
}

func (f *fakeRuntime) RunPoll(ctx context.Context, lookup buyeragent.PurchaseLookup, report func([]error)) {
	f.mu.Lock()
	f.polling = true
	f.mu.Unlock()
	_, _, _ = lookup("probe")
	<-ctx.Done()
	f.stopped <- struct{}{}
}

func (f *fakeRuntime) Serve(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case <-f.serveDone:
		return f.serveErr
	}
}

// The agent runs its duty round and the relay poller beside the socket,
// with the agent's purchase lookup; all stop together, and the agent is
// closed.
func TestTheAgentRunsDutiesAndThePollerUntilItStops(t *testing.T) {
	fake := &fakeRuntime{stopped: make(chan struct{}, 2), serveDone: make(chan struct{})}
	config := agentConfig{}
	config.Budget.DutyIntervalSecond = 30
	runtime := &agentRuntime{agent: fake, carrier: fake, server: fake, config: config}
	ctx, cancel := context.WithCancel(context.Background())
	var reports sync.Map
	done := make(chan error, 1)
	go func() {
		done <- runtime.run(ctx, func(round string, failures []error) { reports.Store(round, len(failures)) })
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		fake.mu.Lock()
		started := fake.duties && fake.polling && fake.lookedUp == "probe"
		fake.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the duty round and the poller did not both start")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("a stopped agent: %v", err)
	}
	if len(fake.stopped) != 2 || !fake.closed || fake.interval != 30*time.Second {
		t.Fatalf("stopped %d, closed %v, interval %v", len(fake.stopped), fake.closed, fake.interval)
	}
	if count, _ := reports.Load("duty"); count != 1 {
		t.Fatal("a duty failure was not reported")
	}
	// A failing socket stops the loops and returns its error.
	failing := &fakeRuntime{stopped: make(chan struct{}, 2), serveDone: make(chan struct{}), serveErr: errors.New("socket gone")}
	close(failing.serveDone)
	runtime = &agentRuntime{agent: failing, carrier: failing, server: failing, config: config}
	go func() { done <- runtime.run(context.Background(), func(string, []error) {}) }()
	select {
	case err := <-done:
		if err == nil || err.Error() != "socket gone" {
			t.Fatalf("a failing socket: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a failing socket left the agent running")
	}
	if len(failing.stopped) != 2 || !failing.closed {
		t.Fatal("a failing socket left the loops running")
	}
}

// validAgentConfig is a configuration that passes readAgentConfig.
func validAgentConfig() map[string]any {
	return map[string]any{
		"schema": AgentConfigSchema, "state_dir": "/srv/buyer/state", "socket_dir": "/srv/buyer/socket", "client_uid": 1001,
		"network": map[string]any{"network_id": "tos-test", "genesis_root_hash": strings.Repeat("1", 64),
			"genesis_file_hash": strings.Repeat("2", 64)},
		"rpc_endpoints":          []string{"https://a.example", "https://b.example", "https://c.example"},
		"quorum":                 2,
		"registry_code_boc_file": "/srv/buyer/registry.boc", "registry_code_hash": "tvm-cell-sha256:" + strings.Repeat("3", 64),
		"registry_workchain": 0, "actor_code_hash": "tvm-cell-sha256:" + strings.Repeat("4", 64),
		"manifest_dir": "/srv/buyer/manifests", "buyer_wallet": "0:" + strings.Repeat("5", 64),
		"buyer_agent_id": "agent_" + strings.Repeat("6", 64),
		"tosctl": map[string]any{"binary": "/usr/local/bin/tosctl", "sha256": strings.Repeat("7", 64),
			"config_path": "/srv/buyer/tosctl.json", "wallet": "buyer", "packet_controller": "buyer-packet"},
		"packet_controller_key_id": "mldsa44:" + strings.Repeat("8", 64),
		"relays":                   []string{"https://relay.example"},
		"relay_ca_file":            "/srv/buyer/relay-ca.pem",
		"budget": map[string]any{"window_seconds": 86400, "max_calls": 10, "max_per_call_nanotos": "1000000000",
			"max_window_nanotos": "10000000000", "max_unconfirmed": 4, "max_lifecycle_sends_per_window": 28,
			"duty_interval_seconds": 60},
	}
}

func writeAgentConfig(t *testing.T, value any, mode os.FileMode) string {
	t.Helper()
	raw, ok := value.([]byte)
	if !ok {
		var err error
		if raw, err = json.Marshal(value); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheAgentConfigurationIsReadStrictly(t *testing.T) {
	config, err := readAgentConfig(writeAgentConfig(t, validAgentConfig(), 0o600))
	if err != nil || config.ClientUID != 1001 || config.Tosctl.Controller != "buyer-packet" || config.Budget.MaxUnconfirmed != 4 {
		t.Fatalf("a valid configuration: %+v %v", config, err)
	}
	for name, edit := range map[string]func(map[string]any){
		"an unknown field":        func(c map[string]any) { c["allowed_wallets"] = []string{"x"} },
		"an unknown nested field": func(c map[string]any) { c["budget"].(map[string]any)["max_total"] = 1 },
		"another schema":          func(c map[string]any) { c["schema"] = "other" },
		"no client uid":           func(c map[string]any) { delete(c, "client_uid") },
		"two endpoints":           func(c map[string]any) { c["rpc_endpoints"] = []string{"https://a", "https://b"} },
		"no majority":             func(c map[string]any) { c["quorum"] = 1 },
		"quorum over endpoints":   func(c map[string]any) { c["quorum"] = 4 },
		"no relays":               func(c map[string]any) { c["relays"] = []string{} },
		"no wallet name":          func(c map[string]any) { c["tosctl"].(map[string]any)["wallet"] = "" },
		"a wallet name with a space": func(c map[string]any) {
			c["tosctl"].(map[string]any)["wallet"] = "buyer wallet"
		},
		"no controller key id":               func(c map[string]any) { delete(c, "packet_controller_key_id") },
		"no budget window":                   func(c map[string]any) { c["budget"].(map[string]any)["window_seconds"] = 0 },
		"a duty interval over 1m":            func(c map[string]any) { c["budget"].(map[string]any)["duty_interval_seconds"] = 61 },
		"no network":                         func(c map[string]any) { delete(c, "network") },
		"no buyer agent":                     func(c map[string]any) { delete(c, "buyer_agent_id") },
		"an https relay without a pinned CA": func(c map[string]any) { delete(c, "relay_ca_file") },
	} {
		value := validAgentConfig()
		edit(value)
		if _, err := readAgentConfig(writeAgentConfig(t, value, 0o600)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	raw, err := json.Marshal(validAgentConfig())
	if err != nil {
		t.Fatal(err)
	}
	for name, bytes := range map[string][]byte{
		"trailing data":   append(append([]byte(nil), raw...), []byte(" {}")...),
		"a duplicate key": append([]byte(`{"client_uid":1,`), raw[1:]...),
	} {
		if _, err := readAgentConfig(writeAgentConfig(t, bytes, 0o600)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := readAgentConfig(writeAgentConfig(t, validAgentConfig(), 0o640)); err == nil {
		t.Error("a configuration readable by the group was accepted")
	}
	if _, err := readAgentConfig("relative.json"); err == nil {
		t.Error("a relative configuration path was accepted")
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(writeAgentConfig(t, validAgentConfig(), 0o600), link); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentConfig(link); err == nil {
		t.Error("a linked configuration was accepted")
	}
}

// The agent refuses to start without the vault, or with a tosctl
// configuration others can read.
func TestTheAgentRefusesAnExposedVault(t *testing.T) {
	path := writeAgentConfig(t, validAgentConfig(), 0o600)
	config, err := readAgentConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openAgent(t.Context(), config, ""); err == nil || !strings.Contains(err.Error(), "VAULT_URL") {
		t.Fatalf("no vault: %v", err)
	}
	exposed := filepath.Join(t.TempDir(), "tosctl.json")
	if err := os.WriteFile(exposed, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	config.Tosctl.ConfigPath = exposed
	if _, err := openAgent(t.Context(), config, "vault://x"); err == nil || !strings.Contains(err.Error(), "tosctl configuration") {
		t.Fatalf("a readable tosctl configuration: %v", err)
	}
}

// Relay clients trust only the pinned CA certificates, never the system
// pool.
func TestRelayClientsTrustOnlyThePinnedCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	pinned := filepath.Join(t.TempDir(), "ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(pinned, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	transport, err := relayTransport(pinned)
	if err != nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("transport: %v", err)
	}
	response, err := (&http.Client{Transport: transport}).Get(server.URL)
	if err != nil {
		t.Fatalf("the pinned CA was not trusted: %v", err)
	}
	response.Body.Close()
	unpinned, err := relayTransport("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&http.Client{Transport: unpinned}).Get(server.URL); err == nil {
		t.Fatal("a certificate outside the pinned CAs was trusted")
	}
	junk := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := relayTransport(junk); err == nil {
		t.Fatal("a CA file without a certificate was accepted")
	}
	clients := &relayClients{transport: transport, clients: map[string]*agentpacketrelay.V2Client{}}
	first, err := clients.client("https://relay.example")
	if err != nil {
		t.Fatal(err)
	}
	if again, err := clients.client("https://relay.example"); err != nil || again != first {
		t.Fatal("a relay client was not kept")
	}
	if _, err := clients.client("http://relay.example"); err == nil {
		t.Fatal("a plain HTTP relay that is not loopback was accepted")
	}
}

func TestBuyerRelayDescriptionUsesOnlyV2(t *testing.T) {
	for _, available := range []bool{true, false} {
		name := "v2-refusal"
		if available {
			name = "v2-available"
		}
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			var paths []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				paths = append(paths, r.URL.Path)
				mu.Unlock()
				if r.URL.Path != "/v2/relay" || !available {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", agentpacketrelay.ContentTypeJSON)
				if err := json.NewEncoder(w).Encode(agentpacketrelay.V2Description{
					Schema: "tos.service.agent-packet-relay.relay.v2", MaxEnvelopeBytes: 262144,
					MaxTTLSeconds: 3600, PerRecipientMaxEnvelopes: 256, PerRecipientMaxBytes: 8 << 20,
					StrangerMaxEnvelopes: 32, StrangerMaxBytes: 2 << 20, MaxWaitSeconds: 25, Directory: true,
				}); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			clients := &relayClients{transport: server.Client().Transport, clients: map[string]*agentpacketrelay.V2Client{}}
			client, err := clients.client(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Describe(t.Context())
			mu.Lock()
			defer mu.Unlock()
			if len(paths) != 1 || paths[0] != "/v2/relay" {
				t.Fatalf("buyer contacted %v, want only /v2/relay", paths)
			}
			if (err == nil) != available {
				t.Fatalf("V2 description result: %v", err)
			}
		})
	}
}
