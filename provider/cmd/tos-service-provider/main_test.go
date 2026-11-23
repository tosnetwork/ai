package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

// invoke runs one command line through the program's entry point.
func invoke(t *testing.T, arguments ...string) (stdout, stderr string, code int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out, diagnostics bytes.Buffer
	code = run(ctx, arguments, streams{out: &out, err: &diagnostics})
	return out.String(), diagnostics.String(), code
}

var (
	fixtureAgent      = "agent_" + strings.Repeat("ab", 32)
	fixtureActor      = "0:" + strings.Repeat("77", 32)
	fixtureCodeHash   = "tvm-cell-sha256:" + strings.Repeat("88", 32)
	fixtureAttestor   = "mldsa44:" + strings.Repeat("99", 32)
	fixtureCapability = "cap_" + strings.Repeat("33", 32)
)

// railDocument is a rail configuration as the earlier agent runtime's
// `earning service init` and `offer` wrote it, with ROOT standing for the
// directory that holds it. The test below that names it shows that this
// program operates such a directory unchanged.
const railDocument = `{
  "network": {
    "network_id": "tos:global-id:7",
    "genesis_root_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "genesis_file_hash": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
  },
  "chain_global_config_file": "ROOT/global.config.json",
  "rpc_endpoints": [
    "http://127.0.0.1:1",
    "http://127.0.0.1:2",
    "http://127.0.0.1:3"
  ],
  "quorum": 2,
  "registry_code_boc_file": "ROOT/registry-code.boc",
  "registry_code_hash": "tvm-cell-sha256:4444444444444444444444444444444444444444444444444444444444444444",
  "actor_code_hash": "tvm-cell-sha256:8888888888888888888888888888888888888888888888888888888888888888",
  "state_dir": "ROOT/state",
  "agent_id": "agent_abababababababababababababababababababababababababababababababab",
  "packet_controller": "openfox-packet",
  "packet_key_id": "mldsa44:5555555555555555555555555555555555555555555555555555555555555555",
  "tosctl": {
    "binary": "ROOT/tosctl",
    "sha256": "6666666666666666666666666666666666666666666666666666666666666666",
    "config_path": "ROOT/tosctl.json",
    "vault_url_env": "VAULT_URL"
  },
  "wallet_name": "provider",
  "wallet_address": "0:1111111111111111111111111111111111111111111111111111111111111111",
  "direct_peers": {
    "agent_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd": "ROOT/buyer.sock"
  },
  "receiver_socket": "ROOT/state/rail-receiver.sock",
  "provider": {
    "capability_id": "cap_3333333333333333333333333333333333333333333333333333333333333333",
    "version": "1.0.0",
    "manifest_file": "ROOT/state/setup/manifest.cbor",
    "attestor_controller": "service-attestor",
    "respond_budget_seconds": 120,
    "executor_socket": "ROOT/executor.sock",
    "offer_file": "ROOT/state/setup/offer.json"
  }
}
`

// providerRecord is one request record as the earlier runtime's `serve`
// stored it.
const providerRecord = `{
  "schema": "tos.openfox.rail-provider-request.v1",
  "state": "acked",
  "buyer_agent_id": "agent_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
  "capability_id": "cap_3333333333333333333333333333333333333333333333333333333333333333",
  "quote_commitment": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
  "actor": "0:7777777777777777777777777777777777777777777777777777777777777777",
  "request_id": 7,
  "request_hash": "9999999999999999999999999999999999999999999999999999999999999999",
  "response_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "deliveries": 1,
  "updated_unix": 1795000000
}
`

// providerDirectory lays out a provider directory under a fresh root and
// returns the rail configuration path and the state directory. edit, when
// given, changes the configuration document before it is written.
func providerDirectory(t *testing.T, edit func(document map[string]any)) (rail, state string) {
	t.Helper()
	root := t.TempDir()
	state = filepath.Join(root, "state")
	for _, directory := range []string{state, filepath.Join(state, "setup"), filepath.Join(state, "provider")} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manifest, _, _, err := servicebridge.BuildManifest(servicebridge.ManifestInput{
		ProviderAgentID: fixtureAgent, Actor: fixtureActor, ActorCodeHash: fixtureCodeHash,
		Attestor: fixtureAttestor, Version: "1.0.0", RetentionSeconds: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(state, "setup", "manifest.cbor"), manifest)
	write(filepath.Join(state, "provider", strings.Repeat("9", 64)+".json"), []byte(providerRecord))
	document := strings.ReplaceAll(railDocument, "ROOT", root)
	if edit != nil {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(document), &decoded); err != nil {
			t.Fatal(err)
		}
		edit(decoded)
		encoded, err := json.MarshalIndent(decoded, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		document = string(encoded)
	}
	rail = filepath.Join(root, "rail.json")
	write(rail, []byte(document))
	return rail, state
}

func TestTheProgramOffersTheProviderVerbs(t *testing.T) {
	// The provider verbs of the earlier runtime's `earning service`, which
	// this program keeps by name.
	for _, verb := range []string{
		"init", "offer", "preflight", "serve", "status", "pause", "resume", "withdraw", "manifest", "metadata",
	} {
		if commands[verb] == nil {
			t.Errorf("no %s command", verb)
		}
		if !strings.Contains(usage, "  "+verb+" ") {
			t.Errorf("the usage text does not describe %s", verb)
		}
	}
	// Buying is another program's work.
	for _, verb := range []string{"buy", "purchases"} {
		if _, _, code := invoke(t, verb); code != exitUsage {
			t.Errorf("%s: exit %d", verb, code)
		}
	}
}

func TestArgumentHandlingOfEveryVerb(t *testing.T) {
	for verb := range commands {
		for name, test := range map[string]struct {
			arguments []string
			code      int
			stderr    string
		}{
			"a positional argument": {[]string{verb, "positional"}, exitUsage, "takes no positional argument"},
			"an unknown flag":       {[]string{verb, "--no-such-flag"}, exitUsage, "flag provided but not defined"},
			"help":                  {[]string{verb, "-h"}, exitDone, "Usage of " + programName + " " + verb},
			"a flag without value":  {[]string{verb, "--rail-config"}, exitUsage, ""},
		} {
			if verb == "manifest" || verb == "metadata" {
				// These take no rail configuration.
				if name == "a flag without value" {
					continue
				}
			}
			stdout, stderr, code := invoke(t, test.arguments...)
			if code != test.code || !strings.Contains(stderr, test.stderr) || stdout != "" {
				t.Errorf("%s %s: exit %d, stdout %q, stderr %q", verb, name, code, stdout, stderr)
			}
		}
	}
	for name, test := range map[string]struct {
		arguments []string
		code      int
		stdout    string
		stderr    string
	}{
		"no command":         {nil, exitUsage, "", "usage: " + programName},
		"an unknown command": {[]string{"sell"}, exitUsage, "", `unknown command "sell"`},
		"help":               {[]string{"help"}, exitDone, "exit codes: 0 done", ""},
		"--help":             {[]string{"--help"}, exitDone, "usage: " + programName, ""},
		"-h":                 {[]string{"-h"}, exitDone, "usage: " + programName, ""},
	} {
		stdout, stderr, code := invoke(t, test.arguments...)
		if code != test.code || !strings.Contains(stdout, test.stdout) || !strings.Contains(stderr, test.stderr) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, stdout, stderr)
		}
		// Help is plain text, and a refusal prints nothing on stdout.
		if (code == exitDone && json.Valid([]byte(stdout))) || (code == exitUsage && stdout != "") {
			t.Errorf("%s: stdout %q", name, stdout)
		}
	}
}

func TestInitRefusesMalformedArgumentsBeforeDoingAnything(t *testing.T) {
	root := t.TempDir()
	rail := filepath.Join(root, "rail.json")
	base := []string{
		"init", "--rail-config", rail, "--state-dir", filepath.Join(root, "state"),
		"--rpc", "http://127.0.0.1:1", "--rpc", "http://127.0.0.1:2", "--rpc", "http://127.0.0.1:3",
		"--global-config", filepath.Join(root, "global.json"), "--network-label", "tos:global-id:7",
		"--tosctl", filepath.Join(root, "tosctl"), "--tosctl-config", filepath.Join(root, "tosctl.json"),
		"--wallet", "provider", "--registry-code-boc", filepath.Join(root, "registry.boc"),
		"--actor-code-hash", fixtureCodeHash,
	}
	peer := "--direct-peer"
	for name, test := range map[string]struct {
		extra []string
		code  int
	}{
		"a direct peer without a socket": {[]string{peer, fixtureAgent}, exitUsage},
		"a direct peer named twice":      {[]string{peer, "agent_x=/a", peer, "agent_x=/b"}, exitUsage},
		"an empty direct peer":           {[]string{peer, ""}, exitUsage},
		"a direct peer with a bad Agent": {[]string{peer, "agent_zz=/run/peer.sock"}, exitFailed},
		"a relative direct peer socket":  {[]string{peer, fixtureAgent + "=peer.sock"}, exitFailed},
		"a malformed tosctl pin":         {[]string{"--tosctl-sha256", "abc"}, exitFailed},
		"a quorum that is not a number":  {[]string{"--quorum", "two"}, exitUsage},
		"a missing tosctl binary to pin": {[]string{"--relay-url", "http://127.0.0.1:9"}, exitFailed},
		"a relative relay CA file":       {[]string{"--relay-ca-file", "ca.pem"}, exitFailed},
		"both relay trust choices":       {[]string{"--relay-ca-file", "/ca.pem", "--relay-system-roots"}, exitFailed},
		"too many endpoints":             {repeatFlag("--rpc", "http://127.0.0.1:4", maxRepeats), exitUsage},
		// This program carries packets over direct sockets and relays only
		// and does not buy: the flags of the other carriers and of the buyer
		// section do not exist.
		"the fallback packet socket": {[]string{"--messenger-socket", "/run/m.sock"}, exitUsage},
		"a chat carrier socket":      {[]string{"--messenger-carrier-socket", "/run/c.sock"}, exitUsage},
		"a buyer section":            {[]string{"--allow-provider", fixtureAgent}, exitUsage},
	} {
		stdout, stderr, code := invoke(t, append(append([]string(nil), base...), test.extra...)...)
		if code != test.code || stderr == "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, stdout, stderr)
		}
		if _, err := os.Stat(rail); err == nil {
			t.Fatalf("%s: a configuration was written", name)
		}
	}
	_, stderr, code := invoke(t, "init")
	if code != exitUsage || !strings.Contains(stderr, "required flag(s) --rail-config, --state-dir, --rpc,") {
		t.Fatalf("init without its inputs: exit %d, %q", code, stderr)
	}
	_, stderr, code = invoke(t, base[:len(base)-2]...)
	if code != exitUsage || !strings.Contains(stderr, "required flag(s) --actor-code-hash not set") {
		t.Fatalf("init without one input: exit %d, %q", code, stderr)
	}
}

func repeatFlag(name, value string, count int) []string {
	var arguments []string
	for index := 0; index < count; index++ {
		arguments = append(arguments, name, value)
	}
	return arguments
}

func TestInitContinuesWithThePacketControllerTheConfigurationRecords(t *testing.T) {
	rail, state := providerDirectory(t, nil)
	if got, err := packetController(rail, state); err != nil || got != "openfox-packet" {
		t.Fatalf("an existing configuration's packet controller was not kept: %q, %v", got, err)
	}
	fresh := filepath.Join(t.TempDir(), "state")
	if got, err := packetController(filepath.Join(t.TempDir(), "absent.json"), fresh); err != nil ||
		got != defaultPacketController {
		t.Fatalf("a new node's packet controller: %q, %v", got, err)
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatalf("looking up the packet controller created the state directory: %v", err)
	}
	if got, err := packetController("relative.json", "relative-state"); err != nil || got != defaultPacketController {
		t.Fatalf("an unreadable configuration's packet controller: %q, %v", got, err)
	}
}

// setupJournal is the setup journal an earlier runtime's `init` writes
// before the rail configuration: its identity names the packet controller.
const setupJournal = `{
  "schema": "tos.openfox.rail-setup.v1",
  "updated_unix": 1900000000,
  "init": {
    "identity": {
      "network_id": "tos:global-id:1",
      "genesis_root_hash": "` + "1111111111111111111111111111111111111111111111111111111111111111" + `",
      "genesis_file_hash": "` + "2222222222222222222222222222222222222222222222222222222222222222" + `",
      "registry_code_hash": "` + "3333333333333333333333333333333333333333333333333333333333333333" + `",
      "packet_controller": "openfox-packet",
      "packet_key_id": "` + "4444444444444444444444444444444444444444444444444444444444444444" + `"
    },
    "tosctl_sha256": "` + "5555555555555555555555555555555555555555555555555555555555555555" + `",
    "agent_nonce": "7",
    "agent": {"state": "pending"}
  }
}
`

// An earlier init that stopped after writing its journal and before its
// rail configuration is continued with the controller the journal records,
// not the default; a journal that cannot be read stops init instead of
// letting it pick a controller.
func TestInitContinuesWithThePacketControllerTheJournalRecords(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	for _, directory := range []string{state, filepath.Join(state, "setup")} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	journal := filepath.Join(state, "setup", "journal.json")
	if err := os.WriteFile(journal, []byte(setupJournal), 0o600); err != nil {
		t.Fatal(err)
	}
	absent := filepath.Join(root, "rail.json")
	if got, err := packetController(absent, state); err != nil || got != "openfox-packet" {
		t.Fatalf("the journal's packet controller was not kept: %q, %v", got, err)
	}
	// The journal outranks a configuration that names another controller:
	// it is what init compares the identity against.
	rail, _ := providerDirectory(t, func(document map[string]any) { document["packet_controller"] = "other" })
	if got, err := packetController(rail, state); err != nil || got != "openfox-packet" {
		t.Fatalf("with a configuration naming another controller: %q, %v", got, err)
	}
	if err := os.Chmod(journal, 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := packetController(absent, state); err == nil {
		t.Fatalf("an unreadable journal gave the packet controller %q", got)
	}
	// Through the command: init stops before it does anything, prints
	// nothing on standard output and ends with one reason line.
	initCommand := []string{"init", "--rail-config", absent, "--state-dir", state, "--rpc", "http://127.0.0.1:1",
		"--rpc", "http://127.0.0.1:2", "--rpc", "http://127.0.0.1:3", "--global-config", filepath.Join(root, "g.json"),
		"--network-label", "1", "--tosctl", filepath.Join(root, "tosctl"), "--tosctl-config",
		filepath.Join(root, "c.json"), "--wallet", "w", "--registry-code-boc", filepath.Join(root, "r.boc"),
		"--actor-code-hash", fixtureCodeHash}
	stdout, stderr, code := invoke(t, initCommand...)
	if code != exitFailed || stdout != "" || !strings.Contains(stderr, "setup journal") || !endsWithOneReason(stderr) {
		t.Fatalf("init with an unreadable journal: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	// A journal of another schema is refused the same way.
	if err := os.Chmod(journal, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal, []byte(`{"schema": "another"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = invoke(t, initCommand...)
	if code != exitFailed || stdout != "" || !strings.Contains(stderr, "another schema") || !endsWithOneReason(stderr) {
		t.Fatalf("init with a journal of another schema: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if _, err := os.Stat(absent); !os.IsNotExist(err) {
		t.Fatalf("init wrote a rail configuration: %v", err)
	}
	// The flag's help names the order of the lookup.
	_, help, _ := invoke(t, "init", "-h")
	if !strings.Contains(help, "the setup journal under --state-dir records, else the one the rail "+
		"configuration records, else "+defaultPacketController) {
		t.Errorf("init -h does not describe the packet controller lookup: %q", help)
	}
}

// endsWithOneReason reports whether stderr ends with the program's reason
// line and holds no other.
func endsWithOneReason(stderr string) bool {
	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	reasons := 0
	for _, line := range lines {
		if strings.HasPrefix(line, programName+": ") {
			reasons++
		}
	}
	return reasons == 1 && strings.HasPrefix(lines[len(lines)-1], programName+": ") && strings.HasSuffix(stderr, "\n")
}

// Every command that does not succeed ends standard error with exactly one
// line `tos-service-provider: <reason>`, also when it prints the usage or a
// flag list first, so an agent reads the reason from the last line.
func TestAFailureEndsWithOneReasonLine(t *testing.T) {
	rail, state := providerDirectory(t, nil)
	absent := filepath.Join(t.TempDir(), "absent.json")
	for name, test := range map[string]struct {
		arguments []string
		code      int
		reason    string
	}{
		"no command":           {nil, exitUsage, programName + ": no command given"},
		"an unknown command":   {[]string{"sell"}, exitUsage, programName + `: unknown command "sell"`},
		"an unknown flag":      {[]string{"status", "--no-such-flag"}, exitUsage, programName + ": flag provided"},
		"a positional":         {[]string{"pause", "now"}, exitUsage, programName + ": " + programName + " pause takes"},
		"a missing flag":       {[]string{"serve"}, exitUsage, programName + ": required flag(s) --rail-config"},
		"a missing config":     {[]string{"status", "--rail-config", absent}, exitFailed, programName + ": "},
		"a refused withdrawal": {[]string{"withdraw", "--rail-config", absent, "--all"}, exitFailed, programName + ": "},
		"a not ready node":     {[]string{"preflight", "--rail-config", absent}, exitNotReady, programName + ": preflight"},
		"an offer at price 0": {[]string{"offer", "--rail-config", rail, "--price", "0", "--storage-fee", "0.2",
			"--cleanup-bounty", "0.1", "--response-sla", "3600", "--refund-claim-window", "3600",
			"--executor-socket", filepath.Join(state, "absent.sock")}, exitFailed, programName + ": "},
	} {
		_, stderr, code := invoke(t, test.arguments...)
		lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
		if code != test.code || !endsWithOneReason(stderr) || !strings.HasPrefix(lines[len(lines)-1], test.reason) {
			t.Errorf("%s: exit %d, stderr %q", name, code, stderr)
		}
	}
	// The usage that explains a refused command line comes before the reason.
	_, stderr, _ := invoke(t, "sell")
	if !strings.HasPrefix(stderr, "usage: "+programName) || !strings.Contains(stderr, "exit codes: ") {
		t.Errorf("an unknown command: stderr %q", stderr)
	}
	if got := reasonLine(errors.Join(errors.New("first"), errors.New("second"))); got != "first; second" {
		t.Errorf("a reason over two lines: %q", got)
	}
}

func TestOfferRefusesMalformedArguments(t *testing.T) {
	rail := filepath.Join(t.TempDir(), "rail.json")
	base := []string{
		"offer", "--rail-config", rail, "--storage-fee", "0.2", "--cleanup-bounty", "0.1",
		"--response-sla", "3600", "--refund-claim-window", "3600",
	}
	for _, price := range []string{"-0.1", "1e2", "0.1234567891", "free", "", "99999999999999999999"} {
		_, stderr, code := invoke(t, append(append([]string(nil), base...), "--price", price)...)
		if code != exitUsage || !strings.Contains(stderr, "--price") {
			t.Errorf("price %q: exit %d, %q", price, code, stderr)
		}
	}
	_, stderr, code := invoke(t, base...)
	if code != exitUsage || !strings.Contains(stderr, "required flag(s) --price not set") {
		t.Fatalf("offer without a price: exit %d, %q", code, stderr)
	}
	for name, extra := range map[string][]string{
		"a response SLA over 32 bits": {"--price", "1", "--response-sla", "4294967296"},
		"a negative refund window":    {"--price", "1", "--refund-claim-window", "-1"},
		"a malformed deploy funding":  {"--price", "1", "--deploy-funding", "1.2.3"},
		"a malformed storage fee":     {"--price", "1", "--storage-fee", "lots"},
		"a malformed cleanup bounty":  {"--price", "1", "--cleanup-bounty", "0.1e1"},
		"a malformed retention":       {"--price", "1", "--retention-seconds", "-5"},
		"a malformed respond budget":  {"--price", "1", "--respond-budget-seconds", "soon"},
		"a test profile with a value": {"--price", "1", "--test-profile-actor=perhaps"},
	} {
		stdout, stderr, code := invoke(t, append(append([]string(nil), base...), extra...)...)
		if code != exitUsage || stdout != "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, stdout, stderr)
		}
	}
	// Well-formed arguments reach the configuration, which does not exist:
	// the hint names this program's own init.
	stdout, stderr, code := invoke(t, append(append([]string(nil), base...), "--price", "1")...)
	if code != exitFailed || !strings.Contains(stderr, "run `"+programName+" init` first") ||
		!isReport(stdout, servicebridge.OfferResultSchema) {
		t.Fatalf("offer without a configuration: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	// A price of zero is well formed; the library refuses it, after the
	// configuration is read: exit 1 with the report, not exit 2.
	existing, state := providerDirectory(t, nil)
	stdout, stderr, code = invoke(t, "offer", "--rail-config", existing, "--price", "0", "--storage-fee", "0.2",
		"--cleanup-bounty", "0.1", "--response-sla", "3600", "--refund-claim-window", "3600", "--executor-socket",
		filepath.Join(state, "absent.sock"))
	if code != exitFailed || !strings.Contains(stderr, "price") || !isReport(stdout, servicebridge.OfferResultSchema) {
		t.Fatalf("offer at price 0: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

// isReport reports whether stdout is exactly one JSON document of schema.
func isReport(stdout, schema string) bool {
	var report struct {
		Schema string `json:"schema"`
	}
	decoder := json.NewDecoder(strings.NewReader(stdout))
	if decoder.Decode(&report) != nil || report.Schema != schema {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func TestWithdrawTakesExactlyOneOfAmountAndAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")
	for name, test := range map[string]struct {
		arguments []string
		code      int
		stderr    string
	}{
		"neither":                  {[]string{}, exitUsage, "exactly one of --amount and --all"},
		"both":                     {[]string{"--amount", "1", "--all"}, exitUsage, "exactly one of --amount and --all"},
		"zero":                     {[]string{"--amount", "0", "--yes"}, exitUsage, servicebridge.ErrWithdrawZero.Error()},
		"a negative amount":        {[]string{"--amount", "-1", "--yes"}, exitUsage, "--amount"},
		"an exponent":              {[]string{"--amount", "1e9", "--yes"}, exitUsage, "--amount"},
		"ten fractional digits":    {[]string{"--amount", "0.0000000001", "--yes"}, exitUsage, "--amount"},
		"a word":                   {[]string{"--amount", "abc", "--yes"}, exitUsage, "--amount"},
		"an overflowing amount":    {[]string{"--amount", "99999999999999999999", "--yes"}, exitUsage, "--amount"},
		"acknowledge with amount":  {[]string{"--acknowledge", "7", "--amount", "1"}, exitUsage, "neither --amount nor --all"},
		"acknowledge with all":     {[]string{"--acknowledge", "7", "--all"}, exitUsage, "neither --amount nor --all"},
		"a note alone":             {[]string{"--all", "--note", "x"}, exitUsage, "--note belongs to --acknowledge"},
		"acknowledge of nothing":   {[]string{"--acknowledge", "0", "--note", "x"}, exitFailed, "query id"},
		"acknowledge not a number": {[]string{"--acknowledge", "seven"}, exitUsage, "invalid value"},
	} {
		_, stderr, code := invoke(t, append([]string{"withdraw", "--rail-config", path}, test.arguments...)...)
		if code != test.code || !strings.Contains(stderr, test.stderr) {
			t.Errorf("%s: exit %d, %q", name, code, stderr)
		}
	}
	// An acknowledgement reaches the configuration, not a withdrawal.
	if _, stderr, code := invoke(t, "withdraw", "--rail-config", path, "--acknowledge", "7", "--note", "x"); code !=
		exitFailed || strings.Contains(stderr, "exactly one of") {
		t.Errorf("--acknowledge was taken for a withdrawal: exit %d, %q", code, stderr)
	}
	// A well-formed request reaches the configuration, and prints a report
	// even though it fails.
	stdout, _, code := invoke(t, "withdraw", "--rail-config", path, "--amount", "1.5")
	var report servicebridge.WithdrawResult
	if code != exitFailed || json.Unmarshal([]byte(stdout), &report) != nil ||
		report.Schema != servicebridge.WithdrawResultSchema || report.Confirmed {
		t.Fatalf("exit %d, report %q", code, stdout)
	}
}

func TestPreflightPrintsItsReportAndExitsWithItsOwnCode(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.json")
	for _, flagName := range []string{"--rail-config", "--config"} {
		stdout, stderr, code := invoke(t, "preflight", flagName, missing)
		var report servicebridge.PreflightReport
		if err := json.Unmarshal([]byte(stdout), &report); err != nil {
			t.Fatalf("%s: the report is not JSON: %v: %s", flagName, err, stdout)
		}
		if code != exitNotReady || report.OK || report.Schema != servicebridge.PreflightSchema ||
			len(report.Checks) == 0 || report.Checks[0].Status != servicebridge.CheckFail ||
			!strings.Contains(stderr, errNotReady.Error()) {
			t.Fatalf("%s: exit %d, report %+v, stderr %q", flagName, code, report, stderr)
		}
	}
	for name, arguments := range map[string][]string{
		"no configuration":         {"preflight"},
		"two different files":      {"preflight", "--rail-config", missing, "--config", missing + ".other"},
		"an empty configuration":   {"preflight", "--rail-config", ""},
		"a positional file":        {"preflight", missing},
		"an empty alias and value": {"preflight", "--config", "", "--rail-config", ""},
	} {
		if stdout, _, code := invoke(t, arguments...); code != exitUsage || stdout != "" {
			t.Errorf("%s: exit %d, stdout %q", name, code, stdout)
		}
	}
	// The same file named twice is one file.
	if _, _, code := invoke(t, "preflight", "--rail-config", missing, "--config", missing); code != exitNotReady {
		t.Errorf("one file named twice: exit %d", code)
	}
}

func TestPauseAndResumeDriveTheAdmissionMarker(t *testing.T) {
	rail, state := providerDirectory(t, nil)
	answer := func(arguments ...string) map[string]any {
		t.Helper()
		stdout, stderr, code := invoke(t, arguments...)
		if code != exitDone {
			t.Fatalf("%v: exit %d: %s", arguments, code, stderr)
		}
		var decoded map[string]any
		if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
			t.Fatalf("%v: %v: %s", arguments, err, stdout)
		}
		return decoded
	}
	if got := answer("pause", "--rail-config", rail, "--reason", "drain"); got["paused"] != true ||
		got["already_paused"] != false || got["reason"] != "drain" {
		t.Fatalf("pause: %v", got)
	}
	if pause, err := servicebridge.ReadAdmissionPause(state); err != nil || pause == nil || pause.Reason != "drain" {
		t.Fatalf("the marker was not written: %+v %v", pause, err)
	}
	if got := answer("pause", "--rail-config", rail); got["already_paused"] != true || got["reason"] != "drain" {
		t.Fatalf("a second pause: %v", got)
	}
	// The readiness report names this program's command, not another's.
	stdout, _, _ := invoke(t, "preflight", "--rail-config", rail)
	if !strings.Contains(stdout, "run `"+programName+" resume` to admit again") {
		t.Fatalf("the preflight hint does not name this program: %s", stdout)
	}
	if got := answer("resume", "--rail-config", rail); got["paused"] != false || got["was_paused"] != true {
		t.Fatalf("resume: %v", got)
	}
	if pause, err := servicebridge.ReadAdmissionPause(state); err != nil || pause != nil {
		t.Fatalf("the marker survived resume: %+v %v", pause, err)
	}
	if got := answer("resume", "--rail-config", rail); got["was_paused"] != false {
		t.Fatalf("a second resume: %v", got)
	}
	// A note over the bound, or one that is not a single line, is refused
	// and nothing is paused.
	for name, reason := range map[string]string{"too long": strings.Repeat("x", 257), "two lines": "a\nb"} {
		if _, _, code := invoke(t, "pause", "--rail-config", rail, "--reason", reason); code != exitFailed {
			t.Errorf("a reason that is %s: exit %d", name, code)
		}
	}
	if pause, err := servicebridge.ReadAdmissionPause(state); err != nil || pause != nil {
		t.Fatalf("a refused pause left a marker: %+v %v", pause, err)
	}
}

func TestStatusReportsTheLocalViewWhateverTheChainDoes(t *testing.T) {
	rail, _ := providerDirectory(t, nil)
	stdout, stderr, code := invoke(t, "status", "--rail-config", rail, "--offline")
	var status servicebridge.ProviderStatus
	if err := json.Unmarshal([]byte(stdout), &status); err != nil || code != exitDone {
		t.Fatalf("exit %d, %v: %s%s", code, err, stdout, stderr)
	}
	if status.Schema != servicebridge.ProviderStatusSchema || len(status.Requests) != 1 ||
		status.Requests[0].RequestID != 7 {
		t.Fatalf("status: %+v", status)
	}
	// The registry code file is absent, so the finalized reader cannot be
	// opened: the local view is still printed and the failure reported.
	stdout, stderr, code = invoke(t, "status", "--rail-config", rail)
	status = servicebridge.ProviderStatus{}
	if err := json.Unmarshal([]byte(stdout), &status); err != nil || code != exitDone {
		t.Fatalf("exit %d, %v: %s%s", code, err, stdout, stderr)
	}
	if status.Actor == nil || status.Actor.Read || !strings.Contains(status.Actor.Error, "open the finalized reader") ||
		len(status.Requests) != 1 {
		t.Fatalf("the reader failure is not in actor.error: %+v", status.Actor)
	}
	stdout, _, code = invoke(t, "status", "--rail-config", rail, "--offline", "--records")
	var records []servicebridge.RequestStatus
	if err := json.Unmarshal([]byte(stdout), &records); err != nil || code != exitDone || len(records) != 1 {
		t.Fatalf("--records: exit %d, %v: %s", code, err, stdout)
	}
	for name, arguments := range map[string][]string{
		"no configuration":       {"status"},
		"a relative path":        {"status", "--rail-config", "rail.json"},
		"an absent file":         {"status", "--rail-config", filepath.Join(t.TempDir(), "absent.json")},
		"an offline flag value":  {"status", "--rail-config", rail, "--offline=perhaps"},
		"an empty configuration": {"status", "--rail-config", ""},
	} {
		if stdout, _, code := invoke(t, arguments...); code == exitDone || stdout != "" {
			t.Errorf("%s: exit %d, stdout %q", name, code, stdout)
		}
	}
}

func TestManifestAndMetadata(t *testing.T) {
	out := t.TempDir()
	arguments := []string{
		"manifest", "--provider-agent", fixtureAgent, "--actor", fixtureActor, "--code-hash", fixtureCodeHash,
		"--attestor", fixtureAttestor, "--out-dir", out,
	}
	stdout, stderr, code := invoke(t, arguments...)
	var built struct {
		Digest    string   `json:"manifest_digest"`
		Path      string   `json:"path"`
		NextSteps []string `json:"next_steps"`
	}
	if err := json.Unmarshal([]byte(stdout), &built); err != nil || code != exitDone {
		t.Fatalf("exit %d, %v: %s%s", code, err, stdout, stderr)
	}
	want, digest, _, err := servicebridge.BuildManifest(servicebridge.ManifestInput{
		ProviderAgentID: fixtureAgent, Actor: fixtureActor, ActorCodeHash: fixtureCodeHash,
		Attestor: fixtureAttestor, Version: "1.0.0", RetentionSeconds: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(built.Path)
	if err != nil || !bytes.Equal(written, want) || built.Digest != digest ||
		built.Path != filepath.Join(out, strings.TrimPrefix(digest, "sha256:")+".cbor") {
		t.Fatalf("manifest: %+v, %v", built, err)
	}
	if info, err := os.Stat(built.Path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the manifest file is not owner-only: %v %v", info, err)
	}
	if steps := strings.Join(built.NextSteps, "\n"); !strings.Contains(steps, programName+" metadata ") {
		t.Fatalf("the next steps do not name this program: %v", built.NextSteps)
	}
	for name, replace := range map[string][2]string{
		"a relative directory":  {out, "relative"},
		"an unclean directory":  {out, out + "/../x"},
		"an absent directory":   {out, filepath.Join(out, "absent")},
		"a malformed Agent":     {fixtureAgent, "agent_zz"},
		"a malformed actor":     {fixtureActor, "1:77"},
		"a malformed code hash": {fixtureCodeHash, "sha256:88"},
		"a malformed attestor":  {fixtureAttestor, "ed25519:99"},
	} {
		changed := append([]string(nil), arguments...)
		for index := range changed {
			if changed[index] == replace[0] {
				changed[index] = replace[1]
			}
		}
		if stdout, _, code := invoke(t, changed...); code == exitDone || stdout != "" {
			t.Errorf("%s: exit %d, stdout %q", name, code, stdout)
		}
	}
	if _, _, code := invoke(t, append(append([]string(nil), arguments...), "--retention-seconds", "0")...); code !=
		exitFailed {
		t.Errorf("a zero retention: exit %d", code)
	}
	if _, stderr, code := invoke(t, "manifest"); code != exitUsage || !strings.Contains(stderr, "--out-dir") {
		t.Errorf("manifest without a directory: exit %d, %q", code, stderr)
	}

	metadata := []string{
		"metadata", "--network-id", "tos:global-id:7", "--genesis-root-hash", "sha256:" + strings.Repeat("11", 32),
		"--genesis-file-hash", "sha256:" + strings.Repeat("22", 32), "--capability-id", fixtureCapability,
		"--provider-agent", fixtureAgent, "--manifest-digest", digest,
	}
	stdout, stderr, code = invoke(t, metadata...)
	var hashed map[string]string
	if err := json.Unmarshal([]byte(stdout), &hashed); err != nil || code != exitDone {
		t.Fatalf("exit %d, %v: %s%s", code, err, stdout, stderr)
	}
	expected, err := servicebridge.MetadataHash(&nativev1.NetworkDomain{
		NetworkId: "tos:global-id:7", GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
		GenesisFileHash: "sha256:" + strings.Repeat("22", 32),
	}, fixtureCapability, fixtureAgent, "1.0.0", digest)
	if err != nil || hashed["metadata_hash"] != expected || expected == "" {
		t.Fatalf("metadata hash %v, want %q (%v)", hashed, expected, err)
	}
	if stdout, _, code := invoke(t, "metadata"); code != exitFailed || stdout != "" {
		t.Errorf("metadata without inputs: exit %d, stdout %q", code, stdout)
	}
	if stdout, _, code := invoke(t, append(metadata[:len(metadata)-1], "sha256:zz")...); code != exitFailed ||
		stdout != "" {
		t.Errorf("a malformed digest: exit %d, stdout %q", code, stdout)
	}
}
