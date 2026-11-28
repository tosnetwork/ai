package buyersdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

// scriptedCustody answers every tosctl run with output and err, and records
// the argument vectors.
func scriptedCustody(t *testing.T, config string, endpoints vetter, output string, err error) (*TOSCTLInitCustody, *[][]string) {
	t.Helper()
	calls := &[][]string{}
	answer := func(_ context.Context, args ...string) ([]byte, error) {
		*calls = append(*calls, args)
		return []byte(output), err
	}
	path := filepath.Join(t.TempDir(), "tosctl-config.json")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return &TOSCTLInitCustody{configPath: path, globalConfig: "/etc/global.json", label: "tos:global-id:7",
		runner: &execRunner{config: []byte(config)}, endpoints: endpoints, run: answer, runPath: answer,
		runLive: answer}, calls
}

func TestInitWalletCreationReloadsOnlyAPrivateConfiguration(t *testing.T) {
	custody, _ := scriptedCustody(t, initConfig, initEndpoints, "", nil)
	changed := `{"chain_rpc":{"urls":["https://a.example"]},"wallets":{}}`
	if err := os.WriteFile(custody.configPath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := custody.CreateWallet(context.Background(), "buyer"); err != nil || string(custody.runner.config) != changed {
		t.Fatalf("the changed configuration was not taken up: %v", err)
	}
	if err := os.Chmod(custody.configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := custody.CreateWallet(context.Background(), "buyer"); err == nil {
		t.Fatal("a configuration others can read was taken up")
	}
	if err := os.WriteFile(custody.configPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(custody.configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := custody.CreateWallet(context.Background(), "buyer"); err == nil || string(custody.runner.config) != changed {
		t.Fatal("an empty configuration was taken up")
	}
}

var exitFailure = errors.New("exit status 1")

const initConfig = `{"chain_rpc":{"urls":["https://a.example"]}}`

var initEndpoints = vetter{endpoints: []string{"https://a.example/jsonRPC"}}

func domainAnswer(mutate func(map[string]any)) string {
	label := sha256.Sum256([]byte("tos:global-id:7"))
	answer := map[string]any{"network_label": "tos:global-id:7", "genesis_root": strings.Repeat("11", 32),
		"genesis_file": strings.Repeat("22", 32), "network_hash": hex.EncodeToString(label[:]),
		"code_hash": strings.TrimPrefix(nativecore.RegistryV2CodeHash, "tvm-cell-sha256:")}
	if mutate != nil {
		mutate(answer)
	}
	raw, _ := json.Marshal(answer)
	return string(raw)
}

func TestInitDomainAnswersForTheLabel(t *testing.T) {
	custody, calls := scriptedCustody(t, initConfig, initEndpoints, domainAnswer(nil), nil)
	domain, err := custody.Domain(context.Background())
	if err != nil || domain.GenesisRootHash != "sha256:"+strings.Repeat("11", 32) ||
		domain.CodeHash != nativecore.RegistryV2CodeHash {
		t.Fatalf("domain %+v %v", domain, err)
	}
	if got := strings.Join((*calls)[0], " "); got != "agent native-registry domain --global-config /etc/global.json "+
		"--network-label tos:global-id:7 --format json" {
		t.Fatalf("argv %s", got)
	}
	for name, mutate := range map[string]func(map[string]any){
		"another label":        func(a map[string]any) { a["network_label"] = "tos:global-id:8" },
		"another label hash":   func(a map[string]any) { a["network_hash"] = strings.Repeat("44", 32) },
		"a short genesis root": func(a map[string]any) { a["genesis_root"] = "11" },
		"an upper genesis file": func(a map[string]any) {
			a["genesis_file"] = strings.Repeat("AA", 32)
		},
		"a bad code hash":          func(a map[string]any) { a["code_hash"] = "zz" },
		"another registry release": func(a map[string]any) { a["code_hash"] = strings.Repeat("33", 32) },
		"an extra field":           func(a map[string]any) { a["extra"] = 1 },
	} {
		custody, _ := scriptedCustody(t, initConfig, initEndpoints, domainAnswer(mutate), nil)
		if _, err := custody.Domain(context.Background()); !errors.Is(err, ErrTOSCTLAnswer) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func controllerJSON(t *testing.T, name string, mutate func(map[string]any)) (string, [mldsa44.KeyIDSize]byte) {
	t.Helper()
	public := make([]byte, mldsa44.PublicKeySize)
	public[0] = 7
	id, err := mldsa44.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	answer := map[string]any{"name": name, "suite": "ML-DSA-44", "key_id": hex.EncodeToString(id[:]),
		"public_key": hex.EncodeToString(public)}
	if mutate != nil {
		mutate(answer)
	}
	raw, _ := json.Marshal(answer)
	return string(raw), id
}

func TestInitControllerAnswerIsBoundToItsName(t *testing.T) {
	answer, id := controllerJSON(t, "packet", nil)
	custody, calls := scriptedCustody(t, initConfig, initEndpoints, answer, nil)
	key, err := custody.Controller(context.Background(), "packet")
	if err != nil || key.KeyID != id || key.Name != "packet" {
		t.Fatalf("controller %+v %v", key, err)
	}
	if _, err := custody.NewController(context.Background(), "packet"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join((*calls)[1], " "); got != "agent native-registry new-controller --name packet --format json" {
		t.Fatalf("argv %s", got)
	}
	for name, mutate := range map[string]func(map[string]any){
		"another name":        func(a map[string]any) { a["name"] = "other" },
		"another suite":       func(a map[string]any) { a["suite"] = "Ed25519" },
		"a short public key":  func(a map[string]any) { a["public_key"] = "07" },
		"another key id":      func(a map[string]any) { a["key_id"] = strings.Repeat("00", 32) },
		"a non-hex key":       func(a map[string]any) { a["public_key"] = "zz" },
		"a missing key field": func(a map[string]any) { delete(a, "public_key"); a["publickey"] = "" },
	} {
		answer, _ := controllerJSON(t, "packet", mutate)
		custody, _ := scriptedCustody(t, initConfig, initEndpoints, answer, nil)
		if _, err := custody.Controller(context.Background(), "packet"); !errors.Is(err, ErrTOSCTLAnswer) {
			t.Errorf("%s: %v", name, err)
		}
	}
	before := len(*calls)
	if _, err := custody.Controller(context.Background(), "-bad"); err == nil || len(*calls) != before {
		t.Error("a controller name that is a flag reached tosctl")
	}
}

func TestInitAbsentIsOnlyTheFinalFailureLine(t *testing.T) {
	absent, _ := scriptedCustody(t, initConfig, initEndpoints,
		"Loading vault\ncommand failed: secret native-registry-p [E100: Not found]\n", exitFailure)
	if _, err := absent.Controller(context.Background(), "p"); !errors.Is(err, ErrTOSCTLAbsent) {
		t.Fatalf("an absent controller: %v", err)
	}
	earlier, _ := scriptedCustody(t, initConfig, initEndpoints,
		"warning: [E100: Not found] in cache\ncommand failed: vault unreachable\n", exitFailure)
	if _, err := earlier.Controller(context.Background(), "p"); errors.Is(err, ErrTOSCTLAbsent) ||
		!errors.Is(err, ErrTOSCTLFailed) {
		t.Fatalf("a phrase on an earlier line was taken as the failure: %v", err)
	}
	unprefixed, _ := scriptedCustody(t, initConfig, initEndpoints, "[E100: Not found]\n", exitFailure)
	if _, err := unprefixed.Controller(context.Background(), "p"); errors.Is(err, ErrTOSCTLAbsent) {
		t.Fatal("a line that is not tosctl's failure line was taken as absent")
	}
	secret, _ := scriptedCustody(t, initConfig, initEndpoints, "command failed: master_key=deadbeef\n", exitFailure)
	if _, err := secret.Controller(context.Background(), "p"); err == nil || strings.Contains(err.Error(), "deadbeef") {
		t.Fatalf("tosctl diagnostics reached the error: %v", err)
	}
}

func TestInitWalletIsTheListedWorkchainZeroAddress(t *testing.T) {
	raw := "0:" + strings.Repeat("21", 32)
	list := func(entries string) *TOSCTLInitCustody {
		custody, _ := scriptedCustody(t, initConfig, initEndpoints, entries, nil)
		return custody
	}
	entry := func(name, address string) string {
		return `{"name":"` + name + `","address":` + address + `,"balance":null,"state":null,"wallet_type":"V4R2","seqno":null}`
	}
	wallet, err := list("["+entry("other", `"`+raw+`"`)+","+entry("buyer", `"`+raw+`"`)+"]").
		Wallet(context.Background(), "buyer", false)
	if err != nil || wallet.Address != raw || wallet.Type != "V4R2" {
		t.Fatalf("wallet %+v %v", wallet, err)
	}
	if _, err := list("["+entry("other", `"`+raw+`"`)+"]").Wallet(context.Background(), "buyer", false); !errors.Is(err, ErrTOSCTLAbsent) {
		t.Fatalf("an unlisted wallet: %v", err)
	}
	if _, err := list("["+entry("buyer", "null")+"]").Wallet(context.Background(), "buyer", false); !errors.Is(err, ErrTOSCTLAnswer) {
		t.Fatalf("a wallet whose key is not in the vault: %v", err)
	}
	master := `"-1:` + strings.Repeat("21", 32) + `"`
	if _, err := list("["+entry("buyer", master)+"]").Wallet(context.Background(), "buyer", false); !errors.Is(err, ErrTOSCTLAnswer) {
		t.Fatalf("a masterchain wallet: %v", err)
	}
	if _, err := list(`[{"name":"buyer","address":"`+raw+`","colour":1}]`).Wallet(context.Background(), "buyer", false); !errors.Is(err, ErrTOSCTLAnswer) {
		t.Fatalf("an unknown field: %v", err)
	}
	invalid, invalidCalls := scriptedCustody(t, initConfig, initEndpoints, "[]", nil)
	if _, err := invalid.Wallet(context.Background(), "a b", false); err == nil || len(*invalidCalls) != 0 {
		t.Fatal("an invalid wallet name reached tosctl")
	}
	listing, listed := scriptedCustody(t, initConfig, initEndpoints, "["+entry("buyer", `"`+raw+`"`)+"]", nil)
	if _, err := listing.Wallet(context.Background(), "buyer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := listing.Wallet(context.Background(), "buyer", true); err != nil {
		t.Fatal(err)
	}
	if offline, online := strings.Join((*listed)[0], " "), strings.Join((*listed)[1], " "); offline !=
		"wallet ls --format json --offline" || online != "wallet ls --format json" {
		t.Fatalf("argv %s / %s", offline, online)
	}
	custody, calls := scriptedCustody(t, initConfig, initEndpoints, "", nil)
	if err := custody.CreateWallet(context.Background(), "buyer"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join((*calls)[0], " "); got != "wallet create -n buyer -v V4R2 -w 0" {
		t.Fatalf("argv %s", got)
	}
	if err := custody.CreateWallet(context.Background(), "--all"); err == nil {
		t.Fatal("an invalid wallet name was created")
	}
}

func registrationAnswer(mutate func(map[string]any)) string {
	destination := "0:" + strings.Repeat("31", 32)
	answer := map[string]any{"kind": "register-agent", "object_id": strings.Repeat("41", 32), "destination": destination,
		"final_target": destination, "action_hash": strings.Repeat("51", 32), "generation": 0, "sequence": 0,
		"state_init_boc": "te6cckEBAQEAAgAAAEysuc0=", "body_boc": "te6cckEBAQEAAgAAAEysuc0="}
	if mutate != nil {
		mutate(answer)
	}
	raw, _ := json.Marshal(answer)
	return string(raw)
}

func TestInitRegistrationAnswerIsAnAgentRegistration(t *testing.T) {
	custody, calls := scriptedCustody(t, initConfig, initEndpoints, registrationAnswer(nil), nil)
	nonce := strings.Repeat("ab", 32)
	registration, err := custody.RegisterAgent(context.Background(), "/state/policy.json", nonce, "packet")
	if err != nil || registration.AgentID != "agent_"+strings.Repeat("41", 32) {
		t.Fatalf("registration %+v %v", registration, err)
	}
	if got := strings.Join((*calls)[0], " "); got != "agent native-registry register-agent --global-config "+
		"/etc/global.json --network-label tos:global-id:7 --policy /state/policy.json --nonce "+nonce+
		" --signer packet --format json" {
		t.Fatalf("argv %s", got)
	}
	for name, mutate := range map[string]func(map[string]any){
		"another kind":          func(a map[string]any) { a["kind"] = "register-capability" },
		"a forwarded target":    func(a map[string]any) { a["final_target"] = "0:" + strings.Repeat("32", 32) },
		"a short object id":     func(a map[string]any) { a["object_id"] = "41" },
		"a friendly address":    func(a map[string]any) { a["destination"] = "EQ"; a["final_target"] = "EQ" },
		"an upper action hash":  func(a map[string]any) { a["action_hash"] = strings.Repeat("AB", 32) },
		"a short action hash":   func(a map[string]any) { a["action_hash"] = "51" },
		"no StateInit":          func(a map[string]any) { a["state_init_boc"] = "" },
		"an unpadded body":      func(a map[string]any) { a["body_boc"] = "te6cckEBAQEAAgAAAEysuc0" },
		"a non-canonical body":  func(a map[string]any) { a["body_boc"] = "te6cckEBAQEAAgAAAEysuc1=" },
		"an unknown answer key": func(a map[string]any) { a["note"] = "x" },
	} {
		custody, _ := scriptedCustody(t, initConfig, initEndpoints, registrationAnswer(mutate), nil)
		if _, err := custody.RegisterAgent(context.Background(), "/state/policy.json", nonce, "packet"); !errors.Is(err, ErrTOSCTLAnswer) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, request := range map[string][3]string{
		"a relative policy": {"policy.json", nonce, "packet"},
		"a short nonce":     {"/state/policy.json", "ab", "packet"},
		"a flag signer":     {"/state/policy.json", nonce, "--yes"},
	} {
		if _, err := custody.RegisterAgent(context.Background(), request[0], request[1], request[2]); err == nil {
			t.Errorf("%s was built", name)
		}
	}
}

func TestInitRegistrationSendIsBoundAndClassified(t *testing.T) {
	custody, _ := scriptedCustody(t, initConfig, initEndpoints, registrationAnswer(nil), nil)
	registration, err := custody.RegisterAgent(context.Background(), "/p.json", strings.Repeat("ab", 32), "packet")
	if err != nil {
		t.Fatal(err)
	}
	sent, calls := scriptedCustody(t, initConfig, initEndpoints, "Transfer summary:\nOK Transfer sent\n", nil)
	if err := sent.SendRegistration(context.Background(), "buyer", 2_000_000_000, registration); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join((*calls)[0], " "); got != "wallet send --from buyer --to "+registration.Destination+
		" --amount-nanotos 2000000000 --body-boc "+registration.BodyBOC+" --state-init-boc "+
		registration.StateInitBOC+" --yes" {
		t.Fatalf("argv %s", got)
	}
	silent, _ := scriptedCustody(t, initConfig, initEndpoints, "", nil)
	if err := silent.SendRegistration(context.Background(), "buyer", 2_000_000_000, registration); err == nil ||
		errors.Is(err, ErrCallNotStarted) {
		t.Fatalf("a send without a transfer report: %v", err)
	}
	for _, phrase := range []string{"Wrong amount value 2 TOS", "wallet 'buyer' is uninitialized", "wallet 'buyer' is frozen"} {
		refused, _ := scriptedCustody(t, initConfig, initEndpoints, "command failed: "+phrase+"\n", exitFailure)
		if err := refused.SendRegistration(context.Background(), "buyer", 2_000_000_000, registration); !errors.Is(err, ErrCallNotStarted) {
			t.Errorf("%q is a refusal before broadcasting: %v", phrase, err)
		}
	}
	// A broadcast whose inclusion was not seen, and a generic "not found"
	// that can follow the broadcast (an RPC or vault error), are ambiguous:
	// the step waits for finalized state instead of returning to pending.
	for _, line := range []string{"Transaction timeout expired", "getAccountState [E100: Not found]"} {
		after, _ := scriptedCustody(t, initConfig, initEndpoints, "command failed: "+line+"\n", exitFailure)
		if err := after.SendRegistration(context.Background(), "buyer", 2_000_000_000, registration); err == nil ||
			errors.Is(err, ErrCallNotStarted) {
			t.Errorf("%q is not ambiguous: %v", line, err)
		}
	}
	unverified, calls := scriptedCustody(t, initConfig, vetter{endpoints: []string{"https://b.example/jsonRPC"}}, "OK Transfer sent", nil)
	if err := unverified.SendRegistration(context.Background(), "buyer", 2_000_000_000, registration); !errors.Is(err, ErrCallNotStarted) || len(*calls) != 0 {
		t.Fatalf("a send through an unverified endpoint: %v %d", err, len(*calls))
	}
	wrongNetwork, calls := scriptedCustody(t, initConfig, vetter{endpoints: initEndpoints.endpoints,
		bad: map[string]bool{"https://a.example/jsonRPC": true}}, "OK Transfer sent", nil)
	if err := wrongNetwork.SendRegistration(context.Background(), "buyer", 2_000_000_000, registration); !errors.Is(err, ErrCallNotStarted) || len(*calls) != 0 {
		t.Fatalf("a send through an endpoint of another network: %v %d", err, len(*calls))
	}
	for name, send := range map[string]func() error{
		"no value":      func() error { return sent.SendRegistration(context.Background(), "buyer", 0, registration) },
		"a flag wallet": func() error { return sent.SendRegistration(context.Background(), "--to", 1, registration) },
		"no registration": func() error {
			return sent.SendRegistration(context.Background(), "buyer", 1, SignedAgentRegistration{})
		},
		"an unverified net": func() error { return unverified.ActivateWallet(context.Background(), "buyer") },
	} {
		if err := send(); !errors.Is(err, ErrCallNotStarted) {
			t.Errorf("%s: %v", name, err)
		}
	}
	activate, calls := scriptedCustody(t, initConfig, initEndpoints, "OK Wallet 'buyer' activated", nil)
	if err := activate.ActivateWallet(context.Background(), "buyer"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join((*calls)[0], " "); got != "wallet activate -n buyer" {
		t.Fatalf("argv %s", got)
	}
	if err := activate.ActivateWallet(context.Background(), "--all"); !errors.Is(err, ErrCallNotStarted) || len(*calls) != 1 {
		t.Fatalf("activating every wallet: %v", err)
	}
	// A run that never started is reported as not started, so the step
	// returns to pending instead of waiting on a message never sent.
	unstarted, _ := scriptedCustody(t, initConfig, initEndpoints, "", ErrCallNotStarted)
	if err := unstarted.SendRegistration(context.Background(), "buyer", 1, registration); !errors.Is(err, ErrCallNotStarted) {
		t.Fatalf("an unstarted tosctl: %v", err)
	}
}

func TestBuyerAgentPolicyIsOneControllerOfEveryPurpose(t *testing.T) {
	public := make([]byte, mldsa44.PublicKeySize)
	policy, err := BuyerAgentPolicy(ControllerKey{PublicKey: public})
	if err != nil {
		t.Fatal(err)
	}
	if string(policy) != `{"controllers":[{"public_key":"`+hex.EncodeToString(public)+`","purposes":15,"weight":1}],`+
		`"recovery_threshold":1,"recovery_timelock":3600,"threshold":1}` {
		t.Fatalf("policy %s", policy)
	}
	if _, err := BuyerAgentPolicy(ControllerKey{PublicKey: public[:10]}); err == nil {
		t.Fatal("a short public key made a policy")
	}
}
