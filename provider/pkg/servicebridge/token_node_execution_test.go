package servicebridge

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tosnetwork/ai/execution/pkg/railgate"
	"github.com/tosnetwork/ai/execution/pkg/softwarework"
)

type tokenNodeFixture struct {
	Checkpoint   uint64     `json:"checkpoint"`
	Utime        int64      `json:"utime"`
	Config       NodeConfig `json:"config"`
	Manifest     string     `json:"manifest"`
	RegistryCode string     `json:"registry_code"`
	Message      Message    `json:"message"`
	Responses    []struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
		Result json.RawMessage `json:"result"`
	} `json:"responses"`
}

type tokenRetryRunner struct{ calls atomic.Int32 }

var errTokenTestRunner = errors.New("test runner reached")

func (r *tokenRetryRunner) Execute(context.Context, softwarework.Request) (softwarework.Outcome, error) {
	r.calls.Add(1)
	return softwarework.Outcome{}, errTokenTestRunner
}

func frozenTokenNode(t *testing.T, initialMode string) (*Node, Message, *tokenRetryRunner, func(string)) {
	t.Helper()
	raw, err := os.ReadFile("testdata/token-execution-local.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != "fedc977bb52680b766a32a7094aa4b85de3c4be1c9ef0c7c867f5ff5b0ea3836" {
		t.Fatal("public fixture changed")
	}
	z, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.LimitReader(z, 2<<20))
	if err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	var fixture tokenNodeFixture
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	key := func(method string, params json.RawMessage) string {
		var p any
		if err := json.Unmarshal(params, &p); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(p)
		return method + string(b)
	}
	answers := map[string]json.RawMessage{}
	for _, row := range fixture.Responses {
		answers[key(row.Method, row.Params)] = row.Result
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			ID     any             `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		k := key(q.Method, q.Params)
		result, found := answers[k]
		if !found {
			t.Errorf("unexpected read %s", k)
			http.Error(w, "unrecorded request", 400)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result}); err != nil {
			t.Error(err)
		}
	})
	config := fixture.Config
	for range 3 {
		s := httptest.NewServer(handler)
		t.Cleanup(s.Close)
		config.RPCEndpoints = append(config.RPCEndpoints, s.URL)
	}
	dir := t.TempDir()
	config.StateDir = filepath.Join(dir, "state")
	config.ReceiverSocket = filepath.Join(config.StateDir, "receiver.sock")
	config.DirectPeers = map[string]string{fixture.Message.SenderAgentID: filepath.Join(dir, "peer.sock")}
	config.Token.MonitorReport = filepath.Join(dir, "monitor.json")
	config.RegistryCodeBOC = filepath.Join(dir, "registry.boc.base64")
	config.Provider.ManifestFile = filepath.Join(dir, "manifest.cbor")
	config.Token.Actors[0].ManifestFile = config.Provider.ManifestFile
	manifest, err := base64.StdEncoding.DecodeString(fixture.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string][]byte{config.RegistryCodeBOC: []byte(fixture.RegistryCode), config.Provider.ManifestFile: manifest, filepath.Join(dir, "custody.json"): []byte("{}")} {
		if err = os.WriteFile(name, value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binaryRaw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	binary = filepath.Join(dir, "unused-helper")
	if err = os.WriteFile(binary, binaryRaw, 0700); err != nil {
		t.Fatal(err)
	}
	binarySum := sha256.Sum256(binaryRaw)
	config.TOSCTL.Binary = binary
	config.TOSCTL.SHA256 = hex.EncodeToString(binarySum[:])
	config.TOSCTL.ConfigPath = filepath.Join(dir, "custody.json")
	config.TOSCTL.VaultURLEnv = "TOKEN_NODE_TEST_VAULT"
	t.Setenv(config.TOSCTL.VaultURLEnv, "file://"+filepath.Join(dir, "unused-vault"))
	monitor := func(mode string) {
		assets := []string{}
		utime := fixture.Utime
		if mode == "alarm" {
			assets = append(assets, config.Token.Actors[0].AssetID)
		}
		if mode == "stale" {
			utime -= 301
		}
		b, err := json.Marshal(map[string]any{"schema": "tos-settlement-report/1", "checkpoint": map[string]any{"height": fixture.Checkpoint, "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "utime": utime}, "provider_pause_assets": assets})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(config.Token.MonitorReport, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	monitor(initialMode)
	runner := &tokenRetryRunner{}
	node, err := OpenNode(context.Background(), config, NodeOptions{Runner: runner, Artifacts: fixedArtifact(nil), Now: func() time.Time { return time.Unix(fixture.Utime, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := node.Close(); err != nil {
			t.Error(err)
		}
	})
	return node, fixture.Message, runner, monitor
}

func TestNodeInstallsTokenWorkSafetyAtTheExecutionGate(t *testing.T) {
	for _, mode := range []string{"alarm", "stale"} {
		t.Run(mode, func(t *testing.T) {
			node, message, _, monitor := frozenTokenNode(t, mode)
			claim, _, err := node.Provider.claimFor(message)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = node.Provider.config.Gate.Admit(context.Background(), claim); !errors.Is(err, railgate.ErrExecutionGuard) {
				t.Fatalf("%s node admitted work with an unsafe monitor: %v", mode, err)
			}
			monitor("clear")
			slot, _, err := node.Provider.config.Gate.Admit(context.Background(), claim)
			if err != nil {
				t.Fatal(err)
			}
			monitor(mode)
			called := false
			err = node.Provider.config.Gate.Run(context.Background(), slot, claim, func(context.Context, *railgate.Verified) error { called = true; return nil })
			if !errors.Is(err, railgate.ErrExecutionGuard) || called {
				t.Fatalf("%s execution not fenced: callback=%v err=%v", mode, called, err)
			}
			monitor("clear")
			if err = node.Provider.config.Gate.Run(context.Background(), slot, claim, func(context.Context, *railgate.Verified) error { called = true; return nil }); err != nil || !called {
				t.Fatalf("clear report did not release admitted work: %v", err)
			}
		})
	}
}

func TestHandleTaskRetriesAnAdmittedSlotWithoutAProviderRecord(t *testing.T) {
	node, message, runner, _ := frozenTokenNode(t, "clear")
	claim, _, err := node.Provider.claimFor(message)
	if err != nil {
		t.Fatal(err)
	}
	slot, _, err := node.Provider.config.Gate.Admit(context.Background(), claim)
	if err != nil {
		t.Fatal(err)
	}
	if err = node.Provider.HandleTask(context.Background(), message); err == nil || runner.calls.Load() != 1 {
		t.Fatalf("admitted task did not retry execution: calls=%d err=%v", runner.calls.Load(), err)
	}
	record, found, err := node.Provider.load(slot.Key())
	if err != nil || !found || record.State != ProviderFailed {
		t.Fatalf("runner failure was not retained: %v %v %s", err, found, record.State)
	}
	if err = node.Provider.HandleTask(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	if runner.calls.Load() != 1 {
		t.Fatal("recorded task executed twice")
	}
}
