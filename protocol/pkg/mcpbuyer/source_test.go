//go:build !windows

package mcpbuyer

import (
	"archive/tar"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func rootsFor(t *testing.T, paths ...string) Roots {
	t.Helper()
	roots, err := NewRoots(paths)
	if err != nil {
		t.Fatal(err)
	}
	return roots
}

func TestADirectoryUnderARootIsPackedCanonically(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "project")
	write(t, filepath.Join(source, "src", "main.go"), "package main\n")
	write(t, filepath.Join(source, "go.mod"), "module x\n")
	archive, err := rootsFor(t, root).LoadSource(source, buyeragent.MaxArchiveBytes)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := buyeragent.CheckSourceArchive(archive, buyeragent.MaxArchiveBytes)
	if err != nil {
		t.Fatalf("the agent refuses the packed archive: %v", err)
	}
	var names []string
	for _, member := range checked.Members {
		names = append(names, member.Name)
	}
	if len(names) != 3 || names[0] != "go.mod" || names[1] != "src/" || names[2] != "src/main.go" {
		t.Fatalf("members %v", names)
	}
}

// Only paths whose real path lies under a root are read; a symlink that
// leaves the root does not count as inside it.
func TestASourceOutsideEveryRootIsRefused(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	write(t, filepath.Join(outside, "secret.txt"), "key")
	roots := rootsFor(t, root)
	for _, path := range []string{outside, filepath.Join(root, "..", filepath.Base(outside)), "relative/path"} {
		if _, err := roots.LoadSource(path, buyeragent.MaxArchiveBytes); !errors.Is(err, ErrSourceRefused) {
			t.Errorf("%s was read: %v", path, err)
		}
	}
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := roots.LoadSource(link, buyeragent.MaxArchiveBytes); !errors.Is(err, ErrSourceRefused) {
		t.Errorf("a symlink leaving the root was followed: %v", err)
	}
	// A directory reached through a linked directory: only its real path
	// shows that it lies outside the root.
	write(t, filepath.Join(outside, "inner", "key.pem"), "key")
	if _, err := roots.LoadSource(filepath.Join(link, "inner"), buyeragent.MaxArchiveBytes); !errors.Is(err, ErrSourceRefused) {
		t.Errorf("a directory behind a symlinked directory was packed: %v", err)
	}
	sibling := root + "-sibling"
	if err := os.Mkdir(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(sibling)
	if _, err := roots.LoadSource(sibling, buyeragent.MaxArchiveBytes); !errors.Is(err, ErrSourceRefused) {
		t.Errorf("a sibling sharing the root's prefix was read: %v", err)
	}
}

func TestLinksAndSpecialFilesInADirectoryAreRefused(t *testing.T) {
	root := t.TempDir()
	withLink := filepath.Join(root, "with-link")
	write(t, filepath.Join(withLink, "a.go"), "x")
	if err := os.Symlink("a.go", filepath.Join(withLink, "b.go")); err != nil {
		t.Fatal(err)
	}
	withFIFO := filepath.Join(root, "with-fifo")
	write(t, filepath.Join(withFIFO, "a.go"), "x")
	if err := syscall.Mkfifo(filepath.Join(withFIFO, "pipe"), 0o644); err != nil {
		t.Fatal(err)
	}
	roots := rootsFor(t, root)
	for _, source := range []string{withLink, withFIFO} {
		if _, err := roots.LoadSource(source, buyeragent.MaxArchiveBytes); !errors.Is(err, ErrSourceRefused) {
			t.Errorf("%s was packed: %v", filepath.Base(source), err)
		}
	}
	unsafe := filepath.Join(root, "unsafe")
	write(t, filepath.Join(unsafe, "has space.go"), "x")
	if _, err := roots.LoadSource(unsafe, buyeragent.MaxArchiveBytes); !errors.Is(err, ErrSourceRefused) {
		t.Errorf("a name outside the safe charset was packed: %v", err)
	}
}

// A supplied tar is repacked canonically: owner names, modes, times and
// padding of the original never reach the agent.
func TestASuppliedTarIsRepackedCanonically(t *testing.T) {
	root := t.TempDir()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, header := range []*tar.Header{
		{Name: "src/", Typeflag: tar.TypeDir, Mode: 0o700, Uname: "someone", ModTime: time.Unix(1_700_000_000, 0)},
		{Name: "src/main.go", Typeflag: tar.TypeReg, Mode: 0o4777, Size: 5, Uname: "SECRET", Gname: "SECRET",
			ModTime: time.Unix(1_700_000_000, 0)},
	} {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			writer.Write([]byte("hello"))
		}
	}
	writer.Close()
	path := filepath.Join(root, "source.tar")
	write(t, path, buffer.String())
	archive, err := rootsFor(t, root).LoadSource(path, buyeragent.MaxArchiveBytes)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := buyeragent.PackSourceArchive([]buyeragent.SourceFile{{Name: "src", Directory: true},
		{Name: "src/main.go", Content: []byte("hello")}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(archive, canonical) {
		t.Fatal("the supplied tar was not repacked to the canonical bytes")
	}
	var linked bytes.Buffer
	writer = tar.NewWriter(&linked)
	writer.WriteHeader(&tar.Header{Name: "a.go", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	writer.Close()
	linkedPath := filepath.Join(root, "linked.tar")
	write(t, linkedPath, linked.String())
	if _, err := rootsFor(t, root).LoadSource(linkedPath, buyeragent.MaxArchiveBytes); !errors.Is(err, ErrSourceRefused) {
		t.Fatalf("a tar with a symlink entry was repacked: %v", err)
	}
}

func TestASourceOverTheBoundIsRefused(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "big")
	write(t, filepath.Join(source, "a.bin"), string(make([]byte, 600_000)))
	write(t, filepath.Join(source, "b.bin"), string(make([]byte, 600_000)))
	if _, err := rootsFor(t, root).LoadSource(source, buyeragent.MaxArchiveBytes); !errors.Is(err, ErrSourceRefused) {
		t.Fatalf("a source over 1 MiB was packed: %v", err)
	}
	// A supplied tar is read up to the archive bound and no further: one
	// with a small member and padding past 1 MiB is refused unread.
	var padded bytes.Buffer
	writer := tar.NewWriter(&padded)
	writer.WriteHeader(&tar.Header{Name: "a.go", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
	writer.Write([]byte("x"))
	writer.Close()
	padded.Write(make([]byte, buyeragent.MaxArchiveBytes))
	path := filepath.Join(root, "padded.tar")
	write(t, path, padded.String())
	if _, err := rootsFor(t, root).LoadSource(path, buyeragent.MaxArchiveBytes); !errors.Is(err, ErrSourceRefused) {
		t.Fatalf("a tar over the bound was read: %v", err)
	}
}
