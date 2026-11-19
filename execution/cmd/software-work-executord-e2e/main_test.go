//go:build e2eexec

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/execution/pkg/executor"
	"github.com/tosnetwork/ai/execution/pkg/softwarework"
)

func archiveOf(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, name := range []string{"src/build.sh", "src/main.go"} {
		body, ok := members[name]
		if !ok {
			continue
		}
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func frozen() executor.ContainerRequest {
	return executor.ContainerRequest{ImageDigest: softwarework.FrozenV1ImageDigest, WorkspaceArchive: true}
}

// The stand-in refuses to start unless it is named as the stand-in.
func TestTheStandInRefusesToStartUnnamed(t *testing.T) {
	err := run([]string{"--socket", "/tmp/x.sock", "--state-dir", t.TempDir(), "--allow-uid", "2004"})
	if err == nil || !strings.Contains(err.Error(), "stand-in") {
		t.Fatalf("an unnamed start: %v", err)
	}
}

// It lists members deterministically and never runs anything in the
// archive: a script that would write a marker leaves none.
func TestTheStandInReadsTheArchiveAndRunsNothing(t *testing.T) {
	marker := t.TempDir() + "/ran"
	archive := archiveOf(t, map[string]string{"src/build.sh": "#!/bin/sh\ntouch " + marker + "\n", "src/main.go": "package main\n"})
	first, err := standIn{}.RunIsolated(context.Background(), frozen(), archive)
	if err != nil || first.ExitCode != 0 {
		t.Fatalf("%+v %v", first, err)
	}
	second, err := standIn{}.RunIsolated(context.Background(), frozen(), archive)
	if err != nil || !bytes.Equal(first.Output, second.Output) {
		t.Fatal("the stand-in is not deterministic")
	}
	if !strings.Contains(string(first.Output), `"src/main.go" 13`) || !strings.Contains(string(first.Output), "members 2") {
		t.Fatalf("output %q", first.Output)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the stand-in ran a script from the archive")
	}
	// Only the frozen job is served.
	other := frozen()
	other.ImageDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := (standIn{}).RunIsolated(context.Background(), other, archive); err == nil {
		t.Fatal("another image was served")
	}
	// A corrupt archive fails the job rather than the service.
	if result, err := (standIn{}).RunIsolated(context.Background(), frozen(), []byte("not a tar")); err != nil || result.ExitCode == 0 {
		t.Fatalf("a corrupt archive: %+v %v", result, err)
	}
}
