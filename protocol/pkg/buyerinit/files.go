package buyerinit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tosnetwork/ai/protocol/internal/osguard"
)

// ensurePrivateDir creates a custody-owned 0700 directory, or checks an
// existing one: a directory, not a link, owned by this account and closed
// to group and others.
func ensurePrivateDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create %s: %w", path, err)
	}
	return checkPrivateDir(path)
}

func checkPrivateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return fmt.Errorf("%s must be a directory private to the custody account (0700)", path)
	}
	return nil
}

// readPrivateFile reads a custody-owned 0600 regular file of at most
// maximum bytes. A missing file is os.ErrNotExist.
func readPrivateFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return nil, fmt.Errorf("%s must be a regular file private to the custody account (0600)", path)
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maximum)
	}
	return os.ReadFile(path)
}

// writePrivateFile replaces path with raw atomically: a synced 0600 file
// in the same directory renamed over it, then the directory synced.
func writePrivateFile(path string, raw []byte) error {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("%s exists and is not a regular file", path)
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".init-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	parent, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
