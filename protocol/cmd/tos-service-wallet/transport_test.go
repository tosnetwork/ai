package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

func commandTransportConfig() transportConfig {
	return transportConfig{Mode: agenttransport.TestNetworkLegacyEpochZero, Network: &nativev1.NetworkDomain{NetworkId: "tos:global-id:3", GenesisRootHash: "65735247a371030abe811aeac0afe357301ce90e161450d26f88b4beb5b4c366", GenesisFileHash: "c3860fe196a2a1b5e4e74a9cf9448624a353ce68a8c4c5f6413347586d688769"}}
}
func TestTransportCommandNetworkGatePrecedesSideEffects(t *testing.T) {
	for _, name := range []string{"production", "unknown", "mode", "epoch"} {
		t.Run(name, func(t *testing.T) {
			config := commandTransportConfig()
			if name == "production" {
				config.Network.NetworkId = "tos:global-id:1"
			}
			if name == "unknown" {
				config.Network.GenesisRootHash = strings.Repeat("9", 64)
			}
			if name == "mode" {
				config.Mode = agenttransport.Production
			}
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.json")
			raw, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(configPath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			journal := filepath.Join(dir, "never-created")
			args := []string{"--transport-config", configPath, "--journal", journal}
			if name == "epoch" {
				args = append(args, "--authorization-epoch", "1")
			}
			var out, review bytes.Buffer
			err = transportCommand(t.Context(), args, strings.NewReader(""), &out, &review)
			if err == nil {
				t.Fatal("network gate accepted")
			}
			if name == "production" || name == "unknown" {
				if !strings.Contains(err.Error(), "allowlist") {
					t.Fatal("refused for unrelated reason:", err)
				}
			} else if !strings.Contains(err.Error(), "test-network-legacy-epoch-zero") {
				t.Fatal("refused for unrelated reason:", err)
			}
			if _, err = os.Stat(journal); !os.IsNotExist(err) {
				t.Fatal("network refusal touched operation directory")
			}
			if out.Len() != 0 || review.Len() != 0 {
				t.Fatal("network refusal printed delegation or prompted")
			}
		})
	}
}
func TestTransportConfigStrictAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	for _, raw := range []string{`{"unexpected":true}`, `{"mode":"one","mode":"two"}`, `{} {}`, strings.Repeat("x", (1<<20)+1)} {
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		var config transportConfig
		if err := loadTransportConfig(path, &config); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	var config transportConfig
	if err := loadTransportConfig(path, &config); err == nil {
		t.Fatal("public config accepted")
	}
}
func TestTransportCommandLimits(t *testing.T) {
	for _, args := range [][]string{{"--purposes", "0"}, {"--purposes", "256"}, {"--max-credential-seconds", "4294967296"}, {"--timeout", "31m"}, {"unexpected"}} {
		var out bytes.Buffer
		if err := transportCommand(context.Background(), args, strings.NewReader(""), &out, &out); err == nil {
			t.Fatal("invalid command accepted")
		}
	}
}
