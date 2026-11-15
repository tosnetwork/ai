package toschain

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tosnetwork/ai/protocol/internal/osguard"
)

// checkpointStore is a process-independent monotonic finality fence.
// The lock and fsync make a successful advance durable before state is served.
type checkpointStore struct{ path string }

func newCheckpointStore(path string) (*checkpointStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("Native checkpoint path must be absolute and clean")
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Native checkpoint directory must be owner-private")
	}
	if !osguard.CurrentUserOwns(info) {
		return nil, errors.New("Native checkpoint directory must be owner-private")
	}
	return &checkpointStore{path: path}, nil
}

// checkAndAdvance refuses a value below the recorded checkpoint and
// otherwise records it.
func (s *checkpointStore) checkAndAdvance(value uint64) error {
	return s.apply(value, true, true)
}

// check refuses a value below the recorded checkpoint and records nothing.
func (s *checkpointStore) check(value uint64) error {
	return s.apply(value, true, false)
}

// raise records value when it is above the recorded checkpoint and leaves a
// higher record unchanged; the record never decreases.
func (s *checkpointStore) raise(value uint64) error {
	return s.apply(value, false, true)
}

// apply reads the recorded checkpoint under the cross-process lock. A value
// below it is refused when refuseLower is set and ignored otherwise; a
// higher value is written and synced only when record is set.
func (s *checkpointStore) apply(value uint64, refuseLower, record bool) error {
	return osguard.WithExclusiveFileLock(s.path, 0o600, func() error {
		file, err := os.OpenFile(s.path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return errors.New("Native checkpoint must be an owner-private regular file")
		}
		if _, err := file.Seek(0, 0); err != nil {
			return err
		}
		raw, err := io.ReadAll(file)
		if err != nil {
			return err
		}
		var previous uint64
		if text := strings.TrimSpace(string(raw)); text != "" {
			previous, err = strconv.ParseUint(text, 10, 64)
			if err != nil || previous == 0 {
				return errors.New("Native checkpoint file is corrupt")
			}
		}
		if value == 0 {
			return errors.New("Native finalized checkpoint is zero")
		}
		if value < previous {
			if refuseLower {
				return fmt.Errorf("Native finalized checkpoint regressed from %d to %d", previous, value)
			}
			return nil
		}
		if value == previous || !record {
			return nil
		}
		if err := file.Truncate(0); err != nil {
			return err
		}
		if _, err := file.Seek(0, 0); err != nil {
			return err
		}
		if _, err := file.WriteString(strconv.FormatUint(value, 10) + "\n"); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		directory, err := os.Open(filepath.Dir(s.path))
		if err != nil {
			return err
		}
		defer directory.Close()
		return directory.Sync()
	})
}
