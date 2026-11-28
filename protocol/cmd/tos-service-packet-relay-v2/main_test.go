package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestV2ConfigIsStrictAndHasNoLegacyMode(t *testing.T) {
	dir := t.TempDir()
	valid := config{Listen: "127.0.0.1:0", URL: "https://127.0.0.1", StateDir: filepath.Join(dir, "state"), Checkpoint: filepath.Join(dir, "checkpoint"), Network: &nativev1.NetworkDomain{NetworkId: "test"}}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"positive": string(raw), "unknown": strings.TrimSuffix(string(raw), "}") + `,"v1_store":"old"}`, "duplicate": strings.Replace(string(raw), `"listen":"127.0.0.1:0"`, `"listen":"127.0.0.1:0","listen":"127.0.0.2:0"`, 1), "trailing": string(raw) + ` {}`} {
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := readConfig(path)
		if (err == nil) != (name == "positive") {
			t.Fatal(name, err)
		}
	}
	if err := run(context.Background(), nil); err == nil {
		t.Fatal("missing config started a relay")
	}
}

func TestV2CommandServesOnlyV2AndShutsDown(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	code := cell.BeginCell().EndCell()
	c := config{Listen: "127.0.0.1:0", URL: "https://127.0.0.1", StateDir: filepath.Join(dir, "v2"), Checkpoint: filepath.Join(dir, "checkpoint"), GlobalEntries: 1024, GlobalBytes: 64 << 20, Mode: agenttransport.TestNetworkLegacyEpochZero, Network: &nativev1.NetworkDomain{NetworkId: "tos:global-id:3", GenesisRootHash: "65735247a371030abe811aeac0afe357301ce90e161450d26f88b4beb5b4c366", GenesisFileHash: "c3860fe196a2a1b5e4e74a9cf9448624a353ce68a8c4c5f6413347586d688769"}, CodeBase64: base64.StdEncoding.EncodeToString(code.ToBOC()), CodeHash: "tvm-cell-sha256:" + hex.EncodeToString(code.Hash())}
	for range 3 {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
		t.Cleanup(server.Close)
		c.Endpoints = append(c.Endpoints, server.URL)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() { done <- serve(ctx, c, func(a net.Addr) { ready <- a }) }()
	var address net.Addr
	select {
	case address = <-ready:
	case err := <-done:
		t.Fatal("service failed before ready", err)
	case <-time.After(30 * time.Second):
		t.Fatal("service did not start")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	for path, want := range map[string]int{"/v1/relay": 404, "/v2/mailboxes/agent_" + strings.Repeat("1", 64) + "/envelopes": 401} {
		res, err := client.Get("http://" + address.String() + path)
		if err != nil {
			t.Fatal(err)
		}
		if err = res.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != want {
			t.Fatal(path, res.StatusCode)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("shutdown did not drain")
	}
	raw, err := os.ReadFile(filepath.Join(c.StateDir, "FORMAT"))
	if err != nil || !strings.Contains(string(raw), "store.v2") {
		t.Fatal("wrong store", string(raw), err)
	}
}

func TestV2ConfiguredRetentionIsBoundedBeforeConversion(t *testing.T) {
	for _, seconds := range []uint64{0, 1, 3600, 10800, 86400, 86401, ^uint64(0)} {
		c := config{GlobalEntries: 1024, GlobalBytes: 64 << 20, TTLSeconds: &seconds}
		limits, err := c.limits()
		valid := seconds > 0 && seconds <= 86400
		if (err == nil) != valid {
			t.Fatal(seconds, err)
		}
		if valid && limits.Base.TTL != time.Duration(seconds)*time.Second {
			t.Fatal("retention drift", seconds, limits.Base.TTL)
		}
	}
}
