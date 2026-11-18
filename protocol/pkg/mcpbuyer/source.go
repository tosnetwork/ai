// Package mcpbuyer is the stdio MCP server of the MCP buyer adapter
// (spec/docs/MCP_BUYER_ADAPTER_V1.md sections 2 and 4). It runs in the
// developer account, holds no key and no journal, and forwards every
// request to the buyer agent's socket. Every check it makes is a
// convenience: the agent makes them all again on the bytes it receives.
package mcpbuyer

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
)

// ErrSourceRefused wraps every reason a source path is refused.
var ErrSourceRefused = errors.New("the source is refused")

func sourceError(message string) error { return errors.Join(ErrSourceRefused, errors.New(message)) }

// Roots are the workspace roots a source path must lie under, resolved to
// real paths once.
type Roots []string

// NewRoots resolves each root to its real path. A root must be an absolute
// directory.
func NewRoots(paths []string) (Roots, error) {
	if len(paths) == 0 {
		return nil, errors.New("at least one workspace root is required")
	}
	var roots Roots
	for _, root := range paths {
		if !filepath.IsAbs(root) {
			return nil, errors.New("a workspace root must be an absolute path")
		}
		real, err := filepath.EvalSymlinks(root)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(real)
		if err != nil || !info.IsDir() {
			return nil, errors.New("a workspace root must be a directory")
		}
		roots = append(roots, real)
	}
	return roots, nil
}

// resolve returns the real path of source when it lies under a root.
func (r Roots) resolve(source string) (string, error) {
	if !filepath.IsAbs(source) {
		return "", sourceError("source_path must be absolute")
	}
	real, err := filepath.EvalSymlinks(source)
	if err != nil {
		return "", sourceError("source_path does not exist")
	}
	for _, root := range r {
		relative, err := filepath.Rel(root, real)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return real, nil
		}
	}
	return "", sourceError("source_path is outside every workspace root")
}

// LoadSource packs source_path into the canonical source archive
// (section 4.5). A directory is packed from its regular files and
// directories, names relative to it; a symlink, device, FIFO or socket
// anywhere in it refuses the request. A regular file is read as a tar,
// whose regular files and directories are repacked canonically; any other
// entry type refuses it. The archive is at most maxBytes.
func (r Roots) LoadSource(source string, maxBytes int) ([]byte, error) {
	real, err := r.resolve(source)
	if err != nil {
		return nil, err
	}
	if maxBytes <= 0 || maxBytes > buyeragent.MaxArchiveBytes {
		maxBytes = buyeragent.MaxArchiveBytes
	}
	info, err := os.Lstat(real)
	if err != nil {
		return nil, sourceError("source_path cannot be read")
	}
	var files []buyeragent.SourceFile
	switch {
	case info.IsDir():
		files, err = walkDirectory(real, maxBytes)
	case info.Mode().IsRegular():
		files, err = readTar(real, maxBytes)
	default:
		return nil, sourceError("source_path is neither a directory nor a regular file")
	}
	if err != nil {
		return nil, err
	}
	archive, err := buyeragent.PackSourceArchive(files)
	if err != nil {
		return nil, errors.Join(ErrSourceRefused, err)
	}
	if len(archive) > maxBytes {
		return nil, sourceError("the packed source archive exceeds its bound")
	}
	return archive, nil
}

func walkDirectory(root string, maxBytes int) ([]buyeragent.SourceFile, error) {
	var files []buyeragent.SourceFile
	total := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return sourceError("a source entry cannot be read")
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return sourceError("a source entry has no relative name")
		}
		name := filepath.ToSlash(relative)
		switch mode := entry.Type(); {
		case mode.IsDir():
			files = append(files, buyeragent.SourceFile{Name: name, Directory: true})
			return nil
		case mode.IsRegular():
		default:
			return sourceError("the source holds a symlink, device, FIFO or socket")
		}
		content, err := readBounded(path, maxBytes-total)
		if err != nil {
			return err
		}
		total += len(content)
		files = append(files, buyeragent.SourceFile{Name: name, Content: content})
		return nil
	})
	return files, err
}

// readBounded reads a regular file of at most limit bytes without following
// a link.
func readBounded(path string, limit int) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return nil, sourceError("a source file cannot be opened")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, sourceError("a source file is not a regular file")
	}
	if limit < 0 {
		return nil, sourceError("the source exceeds the archive bound")
	}
	// The read itself is bounded, so a file that grows after the stat
	// cannot make the server hold more than the bound.
	content, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(content) > limit {
		return nil, sourceError("the source exceeds the archive bound")
	}
	return content, nil
}

func readTar(path string, maxBytes int) ([]buyeragent.SourceFile, error) {
	raw, err := readBounded(path, 4*maxBytes)
	if err != nil {
		return nil, err
	}
	reader := tar.NewReader(bytes.NewReader(raw))
	var files []buyeragent.SourceFile
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, sourceError("the source tar does not parse")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			files = append(files, buyeragent.SourceFile{Name: header.Name, Directory: true})
		case tar.TypeReg:
			if header.Size < 0 || header.Size > int64(maxBytes) {
				return nil, sourceError("a source tar member exceeds the archive bound")
			}
			content, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
			if err != nil || int64(len(content)) != header.Size {
				return nil, sourceError("a source tar member is truncated")
			}
			files = append(files, buyeragent.SourceFile{Name: header.Name, Content: content})
		default:
			return nil, sourceError("the source tar holds an entry that is not a regular file or a directory")
		}
	}
}
