package containerdbackend

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/execution/pkg/executor"
)

func TestWorkspaceExtractionRejectsTraversalLinksDuplicatesAndOverflow(t *testing.T) {
	archive := func(entries ...tar.Header) []byte {
		var buffer bytes.Buffer
		writer := tar.NewWriter(&buffer)
		for index := range entries {
			header := entries[index]
			if err := writer.WriteHeader(&header); err != nil {
				t.Fatal(err)
			}
			if header.Size > 0 {
				_, _ = writer.Write(bytes.Repeat([]byte{'x'}, int(header.Size)))
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}
	cases := [][]byte{
		archive(tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Size: 1}),
		archive(tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}),
		archive(tar.Header{Name: "same", Typeflag: tar.TypeReg}, tar.Header{Name: "same", Typeflag: tar.TypeReg}),
		archive(tar.Header{Name: "large", Typeflag: tar.TypeReg, Size: 9}),
	}
	root := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for index, value := range cases {
		if _, _, err := prepareWorkspace(root, "0123456789abcdef", value, 8); err == nil {
			t.Fatalf("unsafe workspace case %d accepted", index)
		}
	}
}

func TestWorkspaceExtractionProducesReadOnlyTree(t *testing.T) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	body := []byte("package work")
	if err := writer.WriteHeader(&tar.Header{Name: "src/work.go", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write(body)
	_ = writer.Close()
	root := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, cleanup, err := prepareWorkspace(root, "0123456789abcdef", buffer.Bytes(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	info, err := os.Stat(filepath.Join(directory, "src", "work.go"))
	if err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("workspace file mode=%v err=%v", info.Mode(), err)
	}
	if info, err = os.Stat(directory); err != nil || info.Mode().Perm() != 0o555 {
		t.Fatalf("workspace root mode=%v err=%v", info.Mode(), err)
	}
}

// rawTarBlock is one 512-byte USTAR header written by hand, for entries
// the standard writer refuses to produce.
func rawTarBlock(name string, typeflag byte, size int) []byte {
	block := make([]byte, 512)
	copy(block, name)
	copy(block[100:], "0000644\x00")
	copy(block[108:], "0000000\x00")
	copy(block[116:], "0000000\x00")
	copy(block[124:], fmt.Sprintf("%011o\x00", size))
	copy(block[136:], "00000000000\x00")
	copy(block[148:], "        ")
	block[156] = typeflag
	copy(block[257:], "ustar\x0000")
	sum := 0
	for _, value := range block {
		sum += int(value)
	}
	copy(block[148:], fmt.Sprintf("%06o\x00 ", sum))
	return block
}

func paddedBlocks(data []byte) []byte {
	if remainder := len(data) % 512; remainder != 0 {
		data = append(data, make([]byte, 512-remainder)...)
	}
	return data
}

func paxRecords(records map[string]string, order ...string) []byte {
	var encoded []byte
	for _, key := range order {
		body := " " + key + "=" + records[key] + "\n"
		length := len(body) + 1
		for len(strconv.Itoa(length))+len(body) != length {
			length = len(strconv.Itoa(length)) + len(body)
		}
		encoded = append(encoded, []byte(strconv.Itoa(length)+body)...)
	}
	return encoded
}

// paxEntry is an extended header carrying records, then a regular entry
// with data.
func paxEntry(name string, records []byte, data []byte) []byte {
	archive := rawTarBlock("PaxHeaders/"+name, 'x', len(records))
	archive = append(archive, paddedBlocks(append([]byte(nil), records...))...)
	archive = append(archive, rawTarBlock(name, '0', len(data))...)
	return append(archive, paddedBlocks(append([]byte(nil), data...))...)
}

func workspaceEntries(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, workspaceRootName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestWorkspaceExtractionRefusesArchivesThatExpand(t *testing.T) {
	const realSize = 1 << 30
	end := make([]byte, 1024)
	// A sparse entry in the PAX format: a few hundred bytes that the
	// standard reader presents as a 1 GiB file of zeros.
	sparseMap := paddedBlocks([]byte("1\n" + strconv.Itoa(realSize-1) + "\n1\n"))
	sparse := paxEntry("big", paxRecords(map[string]string{"GNU.sparse.major": "1", "GNU.sparse.minor": "0",
		"GNU.sparse.name": "big", "GNU.sparse.realsize": strconv.Itoa(realSize)},
		"GNU.sparse.major", "GNU.sparse.minor", "GNU.sparse.name", "GNU.sparse.realsize"), append(sparseMap, 'x'))
	sparse = append(sparse, end...)
	header, err := tar.NewReader(bytes.NewReader(sparse)).Next()
	if err != nil || header.Size != realSize || header.Typeflag != tar.TypeReg {
		t.Fatalf("the fixture is not read as a sparse 1 GiB regular file: %+v %v", header, err)
	}
	// The same trick with a real size small enough to pass every byte
	// bound: sparse metadata alone refuses it.
	smallMap := paddedBlocks([]byte("1\n9\n1\n"))
	smallSparse := append(paxEntry("small", paxRecords(map[string]string{"GNU.sparse.major": "1", "GNU.sparse.minor": "0",
		"GNU.sparse.name": "small", "GNU.sparse.realsize": "10"},
		"GNU.sparse.major", "GNU.sparse.minor", "GNU.sparse.name", "GNU.sparse.realsize"), append(smallMap, 'x')), end...)
	if header, err = tar.NewReader(bytes.NewReader(smallSparse)).Next(); err != nil || header.Size != 10 {
		t.Fatalf("the small fixture is not read as a sparse file: %+v %v", header, err)
	}
	// An entry whose stated size is larger than the archive that holds it.
	claimed := append(paxEntry("claimed", paxRecords(map[string]string{"size": strconv.Itoa(realSize)}, "size"), []byte("x")), end...)
	if header, err = tar.NewReader(bytes.NewReader(claimed)).Next(); err != nil || header.Size != realSize {
		t.Fatalf("the claimed-size fixture is not read with its claimed size: %+v %v", header, err)
	}
	// Few entries, each implying thousands of directories.
	var flood bytes.Buffer
	writer := tar.NewWriter(&flood)
	for entry := 0; len(flood.Bytes()) < 1<<20 && entry < 64; entry++ {
		name := strings.Repeat(fmt.Sprintf("%d/", entry), 1000) + "f"
		if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for name, check := range map[string]struct {
		archive []byte
		message string
	}{
		"sparse entry":            {sparse, "containerd workspace contains a sparse entry"},
		"small sparse entry":      {smallSparse, "containerd workspace contains a sparse entry"},
		"size beyond the archive": {claimed, "containerd workspace exceeds disk limit"},
		"directory flood":         {flood.Bytes(), "containerd workspace has too many entries"},
	} {
		root := filepath.Join(t.TempDir(), "runtime")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		_, _, err := prepareWorkspace(root, "0123456789abcdef", check.archive, 2<<30)
		if err == nil || err.Error() != check.message {
			t.Errorf("%s: err = %v", name, err)
		}
		// Refused before anything is written: the archive is checked
		// as a whole before even the workspace root is created.
		if _, err := os.Lstat(filepath.Join(root, workspaceRootName)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: the workspace root was created: %v", name, err)
		}
	}
}

func TestWorkspaceExtractionAcceptsAnArchiveAtItsOwnSize(t *testing.T) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	body := bytes.Repeat([]byte("x"), 4096)
	for _, name := range []string{"a/b/c/one.go", "a/b/two.go", "three.go"} {
		if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		_, _ = writer.Write(body)
	}
	_ = writer.Close()
	root := filepath.Join(t.TempDir(), "runtime")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, cleanup, err := prepareWorkspace(root, "0123456789abcdef", buffer.Bytes(), 2<<30)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(directory, "a", "b", "c", "one.go")); err != nil || info.Size() != 4096 {
		t.Fatalf("extracted file: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if left := workspaceEntries(t, root); len(left) != 0 {
		t.Fatalf("cleanup left %v", left)
	}
}

func TestWorkspaceDirectoryMustBePrivateAndEmpty(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(root, "fresh")
	if err := validateWorkspaceDir(fresh); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(fresh); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("created directory: %v", err)
	}
	// An empty workspace root from an earlier clean run is fine.
	if err := os.Mkdir(filepath.Join(fresh, workspaceRootName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkspaceDir(fresh); err != nil {
		t.Fatal(err)
	}
	residue := filepath.Join(root, "residue")
	if err := os.MkdirAll(filepath.Join(residue, workspaceRootName, "0123456789abcdef"), 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(root, "foreign")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "note"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(root, "shared")
	if err := os.Mkdir(shared, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(fresh, link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"interrupted workspace": residue, "foreign file": foreign,
		"group-readable": shared, "symlink": link, "below a symlink": filepath.Join(link, "inner")} {
		if err := validateWorkspaceDir(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The configuration refuses a workspace directory that is not a
	// canonical path of its own.
	valid := Config{SocketPath: "/run/x/containerd.sock", Namespace: "tos-test", Snapshotter: "overlayfs",
		Runtime: "io.containerd.runc.v2", FIFODir: "/run/x/fifos", MaxActive: 1,
		PolicyLimits:   executor.Limits{CPUMillis: 1000, MemoryBytes: 64 << 20, DiskBytes: 64 << 20, PIDs: 16, ExecutionTime: time.Second, OutputBytes: 1024},
		ImageReference: "example.test/image@sha256:" + strings.Repeat("a", 64), ImageDigest: "sha256:" + strings.Repeat("a", 64),
		ImagePlatform: "linux/amd64"}
	valid = withConfigDefaults(valid)
	if err := validateConfig(valid); err != nil {
		t.Fatal(err)
	}
	valid.WorkspaceDir = "/var/lib/x/staging"
	if err := validateConfig(valid); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"relative": "staging", "uncanonical": "/var/lib/x/../x/staging", "the FIFO directory": "/run/x/fifos"} {
		valid.WorkspaceDir = path
		if err := validateConfig(valid); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
