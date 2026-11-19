package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/internal/purchasefixture"
	"github.com/tosnetwork/ai/protocol/pkg/purchaseevidence"
)

// fakeChain replaces the chain session for one test.
func fakeChain(t *testing.T, session purchaseevidence.Session, err error) *readConfig {
	t.Helper()
	var seen readConfig
	previous := openSession
	openSession = func(_ context.Context, config readConfig) (*opened, error) {
		seen = config
		if err != nil {
			return nil, err
		}
		return &opened{session: session, close: func() {},
			endpoints: []purchaseevidence.EndpointReport{{URL: config.endpoints[0], GenesisOK: true}}}, nil
	}
	t.Cleanup(func() { openSession = previous })
	return &seen
}

func writeFile(t *testing.T, dir, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// globalConfig is a global config naming the fixture network's genesis.
func globalConfig(t *testing.T, purchase *purchasefixture.Purchase) []byte {
	t.Helper()
	encode := func(digest string) string {
		raw, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(raw)
	}
	raw, err := json.Marshal(map[string]any{"@type": "config.global", "dht": map[string]any{},
		"validator": map[string]any{"@type": "validator.config.global", "zero_state": map[string]any{
			"workchain": -1, "shard": -9223372036854775808, "seqno": 0,
			"root_hash": encode(purchase.Network.GenesisRootHash), "file_hash": encode(purchase.Network.GenesisFileHash)}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type fixtureFiles struct {
	dir, global, registry, evidence, receipt, artifact string
}

func files(t *testing.T, purchase *purchasefixture.Purchase) fixtureFiles {
	t.Helper()
	dir := t.TempDir()
	bundle, err := json.Marshal(purchase.Bundle(true))
	if err != nil {
		t.Fatal(err)
	}
	return fixtureFiles{dir: dir, global: writeFile(t, dir, "global.json", globalConfig(t, purchase)),
		registry: writeFile(t, dir, "registry.boc", []byte("te6cc\n")), evidence: writeFile(t, dir, "evidence.json", bundle),
		receipt: writeFile(t, dir, "receipt.boc", purchase.Receipt), artifact: writeFile(t, dir, "artifact.tar", purchase.Artifact)}
}

func (f fixtureFiles) arguments(purchase *purchasefixture.Purchase, extra ...string) []string {
	return append([]string{"--global-config", f.global, "--network-id", purchase.Network.NetworkId,
		"--rpc", "https://a.example/jsonRPC,https://b.example/jsonRPC,https://c.example/jsonRPC",
		"--registry-code-boc", f.registry, "--registry-code-hash", "tvm-cell-sha256:" + strings.Repeat("66", 32),
		"--actor-code-hash", purchasefixture.ActorCodeHash}, extra...)
}

func newFixture(t *testing.T) *purchasefixture.Purchase {
	t.Helper()
	purchase, err := purchasefixture.New()
	if err != nil {
		t.Fatal(err)
	}
	return purchase
}

// The verifier reads the evidence bundle, the Receipt and the artifact,
// verifies them at one finalized checkpoint read at a quorum of every
// endpoint, and prints a strict verdict and a summary.
func TestVerifierPassesAnHonestPurchase(t *testing.T) {
	purchase := newFixture(t)
	session, err := purchase.Session(purchasefixture.Responded)
	if err != nil {
		t.Fatal(err)
	}
	seen := fakeChain(t, session, nil)
	f := files(t, purchase)
	var stdout, stderr bytes.Buffer
	code := run(f.arguments(purchase, "--evidence", f.evidence, "--receipt", f.receipt, "--artifact", f.artifact), &stdout, &stderr)
	if code != exitPass {
		t.Fatalf("exit %d:\n%s\n%s", code, stdout.String(), stderr.String())
	}
	if seen.quorum != 3 || len(seen.endpoints) != 3 || seen.network.GenesisRootHash != purchase.Network.GenesisRootHash ||
		seen.network.GenesisFileHash != purchase.Network.GenesisFileHash || seen.registryCode != "te6cc" {
		t.Fatalf("the chain was opened with %+v", *seen)
	}
	var verdict purchaseevidence.Verdict
	if err := jsonstrict.Decode(stdout.Bytes(), &verdict); err != nil {
		t.Fatalf("the verdict is not strict JSON of its schema: %v", err)
	}
	if verdict.Schema != purchaseevidence.VerdictSchema || verdict.Result != purchaseevidence.ResultPass || len(verdict.Inputs) != 5 ||
		verdict.Requests[0].Receipt == nil || verdict.Reads == nil || verdict.Tool == nil {
		t.Fatalf("verdict %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "verdict: PASS") || !strings.Contains(stderr.String(), "respond ") {
		t.Fatalf("summary %s", stderr.String())
	}
}

// Without a bundle the verifier needs the actor and a selector; a failed
// read or a failed check is a failing verdict, and unusable inputs are a
// usage error.
func TestVerifierExitStatus(t *testing.T) {
	purchase := newFixture(t)
	session, err := purchase.Session(purchasefixture.Pending)
	if err != nil {
		t.Fatal(err)
	}
	f := files(t, purchase)
	hash := hex.EncodeToString(purchase.RequestHash[:])
	fakeChain(t, session, nil)
	var stdout, stderr bytes.Buffer
	if code := run(f.arguments(purchase, "--actor", purchasefixture.Actor, "--request-hash", hash), &stdout, &stderr); code != exitPass {
		t.Fatalf("pending request: exit %d %s", code, stderr.String())
	}
	stdout.Reset()
	if code := run(f.arguments(purchase, "--actor", purchasefixture.Actor, "--request-hash", hash, "--receipt", f.receipt),
		&stdout, &stderr); code != exitFail || !strings.Contains(stdout.String(), `"result": "fail"`) {
		t.Fatalf("a Receipt for a pending request: exit %d %s", code, stdout.String())
	}
	fakeChain(t, nil, errors.New("quorum not reached"))
	stdout.Reset()
	if code := run(f.arguments(purchase, "--actor", purchasefixture.Actor, "--request-id", "0"), &stdout, &stderr); code != exitFail ||
		!strings.Contains(stdout.String(), "finalized-read") {
		t.Fatalf("a failed read: exit %d %s", code, stdout.String())
	}
	for name, arguments := range map[string][]string{
		"no actor":          f.arguments(purchase, "--request-id", "0"),
		"bad request id":    f.arguments(purchase, "--actor", purchasefixture.Actor, "--request-id", "01"),
		"two networks":      f.arguments(purchase, "--actor", purchasefixture.Actor, "--request-id", "0", "--network-domain", f.global),
		"no network id":     {"--global-config", f.global, "--rpc", "https://a.example", "--registry-code-boc", f.registry},
		"missing file":      f.arguments(purchase, "--evidence", filepath.Join(f.dir, "absent.json")),
		"oversized receipt": f.arguments(purchase, "--evidence", f.evidence, "--receipt", f.artifact),
		"not a bundle":      f.arguments(purchase, "--evidence", f.global),
		"positional":        f.arguments(purchase, "extra"),
		"minority quorum":   f.arguments(purchase, "--actor", purchasefixture.Actor, "--request-id", "0", "--quorum", "1"),
		"quorum over all":   f.arguments(purchase, "--actor", purchasefixture.Actor, "--request-id", "0", "--quorum", "4"),
	} {
		if code := run(arguments, &stdout, &stderr); code != exitUsage {
			t.Fatalf("%s: exit %d", name, code)
		}
	}
}

// The verifier links no buyer runtime, custody sender or wallet: it cannot
// sign, send or read a buyer's state, whatever its flags say.
func TestVerifierLinksNoCustodyOrBuyerRuntime(t *testing.T) {
	command := exec.Command("go", "list", "-deps", ".")
	command.Env = append(os.Environ(), "GOWORK=off")
	raw, err := command.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, forbidden := range []string{"buyersdk", "buyeragent", "buyerinit", "buyerconfirm", "mcpbuyer",
		"chainactionpublisher", "nativewallet", "providersdk"} {
		for _, line := range strings.Split(string(raw), "\n") {
			if line == "github.com/tosnetwork/ai/protocol/pkg/"+forbidden {
				t.Fatalf("the verifier links %s", line)
			}
		}
	}
}

// The genesis identity comes from the global config's masterchain zero
// state, and a network-domain file is decoded strictly.
func TestVerifierReadsTheGenesisFromTheGlobalConfig(t *testing.T) {
	purchase := newFixture(t)
	network, err := networkFromGlobalConfig(globalConfig(t, purchase), purchase.Network.NetworkId)
	if err != nil {
		t.Fatal(err)
	}
	if network.GenesisRootHash != purchase.Network.GenesisRootHash || network.GenesisFileHash != purchase.Network.GenesisFileHash {
		t.Fatalf("network %+v", network)
	}
	for name, raw := range map[string]string{
		"not global": `{"@type":"other","validator":{"@type":"validator.config.global","zero_state":{"workchain":-1,"root_hash":"` +
			strings.Repeat("A", 43) + `=","file_hash":"` + strings.Repeat("A", 43) + `="}}}`,
		"basechain":     `{"@type":"config.global","validator":{"@type":"validator.config.global","zero_state":{"workchain":0,"root_hash":"` + strings.Repeat("A", 43) + `=","file_hash":"` + strings.Repeat("A", 43) + `="}}}`,
		"short hash":    `{"@type":"config.global","validator":{"@type":"validator.config.global","zero_state":{"workchain":-1,"root_hash":"AAAA","file_hash":"AAAA"}}}`,
		"not json":      `{`,
		"empty network": "",
	} {
		if _, err := networkFromGlobalConfig([]byte(raw), purchase.Network.NetworkId); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	dir := t.TempDir()
	domain := writeFile(t, dir, "domain.json", []byte(`{"network_id":"tos-testnet","genesis_root_hash":"`+
		purchase.Network.GenesisRootHash+`","genesis_file_hash":"`+purchase.Network.GenesisFileHash+`","extra":1}`))
	var inputs []purchaseevidence.FileDigest
	if _, err := readNetwork(&options{networkDomain: domain}, &inputs); err == nil {
		t.Fatal("a network-domain file with an unknown field was accepted")
	}
}
