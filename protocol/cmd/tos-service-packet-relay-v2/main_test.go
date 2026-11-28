package main

import (
	"context"
	"encoding/json"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
