package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestV2ConfigIsStrictAndHasNoLegacyMode(t *testing.T) {
	for _, body := range []string{`{}`, `{"listen":"127.0.0.1:0","v1_store":"old"}`, `{"listen":"127.0.0.1:0","listen":"127.0.0.2:0"}`, `{} {}`} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readConfig(path); err == nil {
			t.Fatal("incomplete/legacy config accepted")
		}
	}
	if err := run(context.Background(), nil); err == nil {
		t.Fatal("missing config started a relay")
	}
}
