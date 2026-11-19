package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/buyerinit"
)

func TestInitCommandRefusesBeforeRunningTOSCTL(t *testing.T) {
	var out bytes.Buffer
	for name, arguments := range map[string][]string{
		"no mode":      {"init"},
		"another mode": {"init", "send"},
		"a positional": {"init", "plan", "extra"},
	} {
		if err := run(arguments, &out); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := run([]string{"init", "plan", "--yes"}, &out); err == nil ||
		!strings.Contains(err.Error(), "--yes applies to init apply only") {
		t.Fatalf("--yes in a plan: %v", err)
	}
	// A uid that would truncate to another account is refused as such.
	if err := run([]string{"init", "plan", "--client-uid", "4294968296"}, &out); err == nil ||
		!strings.Contains(err.Error(), "--client-uid is out of range") {
		t.Fatalf("a uid wider than 31 bits: %v", err)
	}
	// As the developer account: refused before tosctl, which is absent
	// here, could even be pinned.
	own := strconv.Itoa(os.Geteuid())
	err := run([]string{"init", "apply", "--client-uid", own, "--tosctl", "/nonexistent/tosctl"}, &out)
	if !errors.Is(err, buyerinit.ErrWrongAccount) {
		t.Fatalf("init as the developer account: %v", err)
	}
	if err := run([]string{"init", "plan", "--client-uid", "1", "--rpc", "https://a.example"}, &out); err == nil ||
		!strings.Contains(err.Error(), "--rpc must name 3 to 8 endpoints") {
		t.Fatalf("an invalid input reached tosctl: %v", err)
	}
}

// TestTheAgentReadsTheConfigurationInitWrites encodes init's configuration
// with every field set and requires the agent's strict reader to accept it
// with the same values, so the writer and the reader cannot drift apart.
func TestTheAgentReadsTheConfigurationInitWrites(t *testing.T) {
	written := buyerinit.AgentConfig{Schema: buyerinit.AgentConfigSchema, StateDir: "/srv/buyer/state",
		SocketDir: "/srv/buyer/socket", ClientUID: 1000, Network: buyerinit.NetworkConfig{NetworkID: "tos:global-id:7",
			GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)},
		Endpoints: []string{"https://a.example", "https://b.example", "https://c.example"}, Quorum: 2,
		RegistryCodeFile: "/srv/buyer/registry.boc", RegistryCodeHash: "tvm-cell-sha256:" + strings.Repeat("33", 32),
		ActorCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32), ManifestDir: "/srv/buyer/manifests",
		BuyerWallet: "0:" + strings.Repeat("55", 32), BuyerAgentID: "agent_" + strings.Repeat("66", 32),
		Tosctl: buyerinit.TosctlConfig{Binary: "/opt/tosctl", SHA256: strings.Repeat("77", 32),
			ConfigPath: "/srv/buyer/tosctl.json", Wallet: "buyer", Controller: "packet"},
		PacketControllerKeyID: "mldsa44:" + strings.Repeat("88", 32), Relays: []string{"https://relay.example"},
		RelayCAFile: "/srv/buyer/ca.pem", Budget: buyerinit.BudgetConfig{WindowSeconds: 86_400, MaxCalls: 100,
			MaxPerCallNanoTOS: "1000000000", MaxWindowNanoTOS: "10000000000", MaxUnconfirmed: 4, MaxLifecycleSends: 9,
			DutyIntervalSecond: 30},
		GatewayURL: "https://gateway.example", GatewayCAFile: "/srv/buyer/gateway-ca.pem",
		GatewayTokenFile: "/srv/buyer/gateway.token", CatalogDir: "/srv/buyer/catalog"}
	raw, err := json.Marshal(written)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "agent-config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	read, err := readAgentConfig(path)
	if err != nil {
		t.Fatalf("the agent refuses init's configuration: %v", err)
	}
	back, err := json.Marshal(read)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(raw) {
		t.Fatalf("the agent reads another configuration than init wrote:\n%s\n%s", raw, back)
	}
	decoded, err := buyerinit.DecodeAgentConfig(back)
	if err != nil || !reflect.DeepEqual(decoded, written) {
		t.Fatalf("init's decoder does not take the agent's view back: %v", err)
	}
}

func TestInitConfirmationIsExactlyYes(t *testing.T) {
	for answer, want := range map[string]bool{"yes\n": true, "yes": true, "yes\r\n": true, "y\n": false, "YES\n": false,
		" yes\n": false, "": false, "no\n": false} {
		var prompt bytes.Buffer
		confirmed, err := confirmOn(bufio.NewReader(strings.NewReader(answer)), &prompt)("Send it?")
		if err != nil || confirmed != want {
			t.Errorf("%q: %v %v", answer, confirmed, err)
		}
		if !strings.Contains(prompt.String(), "Send it? Type yes to send") {
			t.Errorf("prompt %q", prompt.String())
		}
	}
}
