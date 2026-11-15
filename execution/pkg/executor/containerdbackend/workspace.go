package containerdbackend

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// maxWorkspaceNodes bounds the files and directories one workspace creates,
// directories implied by a nested path included. A tar entry occupies at
// least one 512-byte block, so this is also the most entries an archive at
// the hard input bound can hold.
const maxWorkspaceNodes = MaxInputBytesHard / 512
const workspaceRootName = "workspaces"

// prepareWorkspace extracts a deliberately small tar subset into a new,
// runtime-owned directory. Links, devices, sparse files, duplicate paths and
// path traversal are rejected so a workload can never select a host path.
// The whole archive is checked before the directory exists, so a refused
// archive writes nothing.
func prepareWorkspace(root, identity string, archive []byte, maximum uint64) (string, func() error, error) {
	if !runtimeIdentifier.MatchString(identity) || maximum == 0 || uint64(len(archive)) > maximum {
		return "", nil, errors.New("invalid containerd workspace archive")
	}
	if err := walkWorkspaceTar("", archive, maximum); err != nil {
		return "", nil, err
	}
	workspaceRoot := filepath.Join(root, workspaceRootName)
	if err := ensurePrivateDirectory(workspaceRoot); err != nil {
		return "", nil, errors.New("invalid containerd workspace root")
	}
	directory := filepath.Join(workspaceRoot, identity)
	if err := os.Mkdir(directory, 0o700); err != nil {
		return "", nil, errors.New("create containerd workspace")
	}
	cleanup := func() error { return removeWorkspace(directory) }
	if err := walkWorkspaceTar(directory, archive, maximum); err != nil {
		_ = cleanup()
		return "", nil, err
	}
	if err := makeWorkspaceReadOnly(directory); err != nil {
		_ = cleanup()
		return "", nil, err
	}
	return directory, cleanup, nil
}

func removeWorkspace(directory string) error {
	_ = filepath.Walk(directory, func(current string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() {
			_ = os.Chmod(current, 0o700)
		}
		return nil
	})
	return os.RemoveAll(directory)
}

// walkWorkspaceTar checks every entry of archive and, when root is not
// empty, extracts it there. An uncompressed archive cannot hold more file
// bytes than its own length, so an entry set that claims more (a sparse map
// expands a few bytes into gigabytes of zeros) is refused, as is any entry
// that carries sparse metadata at all.
func walkWorkspaceTar(root string, archive []byte, maximum uint64) error {
	if uint64(len(archive)) < maximum {
		maximum = uint64(len(archive))
	}
	reader := tar.NewReader(bytes.NewReader(archive))
	seen := make(map[string]struct{})
	nodes := make(map[string]struct{})
	var total uint64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return errors.New("invalid containerd workspace tar")
		}
		name, err := safeWorkspaceName(header.Name)
		if err != nil {
			return err
		}
		if _, duplicate := seen[name]; duplicate {
			return errors.New("duplicate containerd workspace path")
		}
		seen[name] = struct{}{}
		for record := range header.PAXRecords {
			if strings.HasPrefix(record, "GNU.sparse.") {
				return errors.New("containerd workspace contains a sparse entry")
			}
		}
		// Every path component is a node the extraction creates.
		// A known node's parents are known, so the walk stops there.
		for end := len(name); end > 0; end = strings.LastIndexByte(name[:end], '/') {
			if _, known := nodes[name[:end]]; known {
				break
			}
			nodes[name[:end]] = struct{}{}
		}
		if len(nodes) > maxWorkspaceNodes {
			return errors.New("containerd workspace has too many entries")
		}
		target := filepath.Join(root, filepath.FromSlash(name))
		switch header.Typeflag {
		case tar.TypeDir:
			if root == "" {
				continue
			}
			if err := os.MkdirAll(target, 0o700); err != nil {
				return errors.New("create containerd workspace directory")
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || uint64(header.Size) > maximum-total {
				return errors.New("containerd workspace exceeds disk limit")
			}
			total += uint64(header.Size)
			if root == "" {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return errors.New("create containerd workspace parent")
			}
			file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
			if err != nil {
				return errors.New("create containerd workspace file")
			}
			_, copyErr := io.CopyN(file, reader, header.Size)
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil {
				return errors.New("write containerd workspace file")
			}
			mode := os.FileMode(0o444)
			if header.FileInfo().Mode()&0o111 != 0 {
				mode = 0o555
			}
			if err := os.Chmod(target, mode); err != nil {
				return errors.New("protect containerd workspace file")
			}
		default:
			return fmt.Errorf("unsupported containerd workspace tar entry %q", name)
		}
	}
}

func safeWorkspaceName(value string) (string, error) {
	if value == "" || strings.IndexByte(value, 0) >= 0 || strings.HasPrefix(value, "/") || len(value) > 4096 {
		return "", errors.New("invalid containerd workspace path")
	}
	cleaned := path.Clean(value)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned != strings.TrimSuffix(value, "/") {
		return "", errors.New("invalid containerd workspace path")
	}
	return cleaned, nil
}

func makeWorkspaceReadOnly(root string) error {
	return filepath.Walk(root, func(current string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("containerd workspace contains a symlink")
		}
		if info.IsDir() {
			return os.Chmod(current, 0o555)
		}
		return nil
	})
}
