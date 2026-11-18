package buyersdk

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44/mldsa44test"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

// TestInitCustodyUsesTheRealPinnedTOSCTL runs every init command that needs
// no chain against the real helper named by TOS_SERVICE_TOSCTL and
// TOS_SERVICE_TOSCTL_SHA256, in a temporary vault: the identity domain,
// controller creation and lookup, wallet creation and listing, and the
// Agent registration. It fails, rather than skips, without the helper: these
// are the answers whose exact shape and failure phrases every other test
// stands in for.
func TestInitCustodyUsesTheRealPinnedTOSCTL(t *testing.T) {
	binary, pin := os.Getenv(mldsa44test.BinaryEnvironment), os.Getenv(mldsa44test.SHA256Environment)
	if binary == "" || pin == "" {
		t.Fatalf("set %s and %s to the pinned tosctl helper", mldsa44test.BinaryEnvironment,
			mldsa44test.SHA256Environment)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	vault := "file://" + filepath.Join(directory, "vault.json") + "?master_key=" + hex.EncodeToString(master)
	configPath := filepath.Join(directory, "tosctl-config.json")
	generate := exec.Command(binary, "config", "generate", "--output="+configPath)
	generate.Env, generate.Dir = []string{"VAULT_URL=" + vault}, "/"
	if output, err := generate.CombinedOutput(); err != nil {
		t.Fatalf("tosctl config generate: %v\n%s", err, output)
	}
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	root, file := strings.Repeat("\x11", 32), strings.Repeat("\x22", 32)
	global := filepath.Join(directory, "global.config.json")
	if err := os.WriteFile(global, []byte(`{"validator":{"zero_state":{"root_hash":"`+
		base64.StdEncoding.EncodeToString([]byte(root))+`","file_hash":"`+
		base64.StdEncoding.EncodeToString([]byte(file))+`"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config := TOSCTLInitCustodyConfig{BinaryPath: binary, BinarySHA256: pin, ConfigPath: configPath, VaultURL: vault,
		GlobalConfig: global, NetworkLabel: "tos:global-id:7", Endpoints: vetter{}}
	wrong := config
	wrong.BinarySHA256 = strings.Repeat("0", 64)
	if _, err := NewTOSCTLInitCustody(wrong); err == nil {
		t.Fatal("a helper with another SHA-256 was accepted")
	}
	custody, err := NewTOSCTLInitCustody(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	leaks := func(err error) bool {
		return strings.Contains(err.Error(), hex.EncodeToString(master)) || strings.Contains(err.Error(), directory)
	}

	domain, err := custody.Domain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if domain.GenesisRootHash != "sha256:"+hex.EncodeToString([]byte(root)) ||
		domain.GenesisFileHash != "sha256:"+hex.EncodeToString([]byte(file)) {
		t.Fatalf("domain = %+v", domain)
	}

	// Controllers: absent is told apart by the real phrase, and creating
	// an existing one is refused, not answered as absent.
	if _, err := custody.Controller(ctx, "buyer-packet"); !errors.Is(err, ErrTOSCTLAbsent) || leaks(err) {
		t.Fatalf("an absent controller is not ErrTOSCTLAbsent: %v", err)
	}
	created, err := custody.NewController(ctx, "buyer-packet")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := custody.Controller(ctx, "buyer-packet")
	if err != nil || stored.KeyID != created.KeyID || !strings.HasPrefix(created.Text(), "mldsa44:") {
		t.Fatalf("the controller does not read back as created: %v", err)
	}
	if _, err := custody.NewController(ctx, "buyer-packet"); err == nil || errors.Is(err, ErrTOSCTLAbsent) || leaks(err) {
		t.Fatalf("creating an existing controller: %v", err)
	}

	// Wallets: absent, created in the configuration, listed by address.
	if _, err := custody.Wallet(ctx, "buyer", false); !errors.Is(err, ErrTOSCTLAbsent) {
		t.Fatalf("an absent wallet: %v", err)
	}
	if err := custody.CreateWallet(ctx, "buyer"); err != nil {
		t.Fatal(err)
	}
	wallet, err := custody.Wallet(ctx, "buyer", false)
	if err != nil || !isRawAddress(wallet.Address) {
		t.Fatalf("the created wallet: %+v %v", wallet, err)
	}
	if err := custody.CreateWallet(ctx, "buyer"); err == nil || leaks(err) {
		t.Fatalf("a second wallet of one name: %v", err)
	}

	// The registration reads the chain, which this test has none of: it
	// fails without broadcasting and without quoting the vault. Its answer
	// shape is covered with a recorded answer.
	policy, err := BuyerAgentPolicy(created)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(directory, "policy.json")
	if err := os.WriteFile(policyPath, policy, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := custody.RegisterAgent(ctx, policyPath, strings.Repeat("ab", 32), "buyer-packet"); !errors.Is(err, ErrTOSCTLFailed) || leaks(err) {
		t.Fatalf("a registration without a chain: %v", err)
	}
	// The release registry code is the code this helper signs for.
	raw, err := os.ReadFile(filepath.Join("..", "nativecore", "testdata", "native_registry_v1_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		CodeHash string `json:"contract_code_hash"`
		Code     string `json:"contract_code_boc_base64"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil || vectors.CodeHash != domain.CodeHash {
		t.Fatalf("the release registry code hash %s is not the helper's %s: %v", vectors.CodeHash, domain.CodeHash, err)
	}
	if err := os.WriteFile(global+".open", []byte(initConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(global+".open", 0o644); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*TOSCTLInitCustodyConfig){
		"no endpoint vetter":       func(c *TOSCTLInitCustodyConfig) { c.Endpoints = nil },
		"a relative global config": func(c *TOSCTLInitCustodyConfig) { c.GlobalConfig = "global.json" },
		"a flag network label":     func(c *TOSCTLInitCustodyConfig) { c.NetworkLabel = "--yes" },
		"a spaced network label":   func(c *TOSCTLInitCustodyConfig) { c.NetworkLabel = "tos global" },
		"no network label":         func(c *TOSCTLInitCustodyConfig) { c.NetworkLabel = "" },
		"a long network label":     func(c *TOSCTLInitCustodyConfig) { c.NetworkLabel = strings.Repeat("a", 65) },
		"a short timeout":          func(c *TOSCTLInitCustodyConfig) { c.Timeout = time.Millisecond },
		"a long timeout":           func(c *TOSCTLInitCustodyConfig) { c.Timeout = time.Hour },
		"a readable configuration": func(c *TOSCTLInitCustodyConfig) { c.ConfigPath = global + ".open" },
	} {
		bad := config
		mutate(&bad)
		if _, err := NewTOSCTLInitCustody(bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := nativecore.NewLocator(&nativev1.NetworkDomain{NetworkId: config.NetworkLabel,
		GenesisRootHash: domain.GenesisRootHash, GenesisFileHash: domain.GenesisFileHash}, 0, vectors.Code,
		vectors.CodeHash); err != nil {
		t.Fatal(err)
	}
}
