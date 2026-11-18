package main

import (
	"context"
	"errors"
	"testing"
)

type fixedManifest struct {
	raw []byte
	err error
}

func (f fixedManifest) Manifest(context.Context, string) ([]byte, error) { return f.raw, f.err }

// The buyer's manifest sources are asked in order: the configured
// directory, then the agent's store of quoted manifests.
func TestManifestSourcesAreAskedInOrder(t *testing.T) {
	missing := fixedManifest{err: errors.New("absent")}
	sources := manifestSources{missing, fixedManifest{raw: []byte{1}}, fixedManifest{raw: []byte{2}}}
	if raw, err := sources.Manifest(context.Background(), "sha256:x"); err != nil || len(raw) != 1 || raw[0] != 1 {
		t.Fatalf("manifest %v %v", raw, err)
	}
	if _, err := (manifestSources{missing}).Manifest(context.Background(), "sha256:x"); err == nil {
		t.Fatal("no source held the manifest, yet one was returned")
	}
}
