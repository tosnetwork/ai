package agentcarrier

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/internal/osguard"
)

type disk struct {
	root     *os.Root
	mu       sync.Mutex
	poisoned bool
	release  func()
	cut      func(string) error
}
type sealedRecord struct {
	Schema string          `json:"schema"`
	Sum    string          `json:"sum"`
	Data   json.RawMessage `json:"data"`
}

func privateRoot(path string) error {
	if !osguard.OwnerPrivateStorageSupported() || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrConfig
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, current), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err = os.Mkdir(current, 0700); err != nil {
				return ErrStorage
			}
			parent, openErr := os.Open(filepath.Dir(current))
			if openErr != nil {
				return ErrStorage
			}
			if syncErr := errors.Join(parent.Sync(), parent.Close()); syncErr != nil {
				return ErrStorage
			}
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrStorage
		}
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0700 || !osguard.CurrentUserOwns(info) {
		return ErrStorage
	}
	return nil
}
func openDisk(path string) (*disk, error) {
	if err := privateRoot(path); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, ErrStorage
	}
	release, acquired, err := osguard.TryExclusiveFileLock(filepath.Join(path, "lock"), 0600)
	if err != nil || !acquired {
		if closeErr := root.Close(); closeErr != nil {
			return nil, ErrStorage
		}
		return nil, ErrStorage
	}
	info, err := root.Lstat("lock")
	if err != nil || !singlePrivate(info) {
		release()
		if closeErr := root.Close(); closeErr != nil {
			return nil, ErrStorage
		}
		return nil, ErrStorage
	}
	return &disk{root: root, release: release}, nil
}
func (d *disk) close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.release == nil {
		return nil
	}
	d.release()
	d.release = nil
	return d.root.Close()
}
func (d *disk) read(name string, out any) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.poisoned || d.release == nil {
		return ErrStorage
	}
	before, err := d.root.Lstat(name)
	if err != nil {
		return err
	}
	if !singlePrivate(before) {
		return ErrStorage
	}
	f, err := d.root.Open(name)
	if err != nil {
		return ErrStorage
	}
	info, statErr := f.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(f, MaxRecordBytes+1))
	closeErr := f.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !singlePrivate(info) || !os.SameFile(before, info) || len(raw) > MaxRecordBytes {
		return ErrStorage
	}
	var record sealedRecord
	if jsonstrict.Decode(raw, &record) != nil || record.Schema != "tos.service.carrier.checked.v2" || len(record.Data) == 0 {
		return ErrStorage
	}
	sum := sha256.Sum256(record.Data)
	if record.Sum != hex.EncodeToString(sum[:]) || jsonstrict.Decode(record.Data, out) != nil {
		return ErrStorage
	}
	return nil
}
func (d *disk) write(name string, value any) (err error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return ErrStorage
	}
	sum := sha256.Sum256(raw)
	encoded, err := json.Marshal(sealedRecord{"tos.service.carrier.checked.v2", hex.EncodeToString(sum[:]), raw})
	if err != nil || len(encoded) > MaxRecordBytes {
		return ErrCapacity
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.poisoned || d.release == nil {
		return ErrStorage
	}
	// Every uncertain write poisons this instance; restart re-reads checked files.
	defer func() {
		if err != nil {
			d.poisoned = true
			err = ErrStorage
		}
	}()
	if info, e := d.root.Lstat(name); e == nil {
		if !singlePrivate(info) {
			return ErrStorage
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return ErrStorage
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	temp := "write-" + hex.EncodeToString(nonce[:])
	f, err := d.root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	pending := true
	defer func() {
		if pending {
			err = errors.Join(err, d.root.Remove(temp))
		}
	}()
	_, writeErr := io.Copy(f, bytes.NewReader(encoded))
	syncErr := f.Sync()
	closeErr := f.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if d.cut != nil {
		if err = d.cut("synced"); err != nil {
			return err
		}
	}
	if err = d.root.Rename(temp, name); err != nil {
		return err
	}
	pending = false
	if d.cut != nil {
		if err = d.cut("renamed"); err != nil {
			return err
		}
	}
	dir, err := d.root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
func (d *disk) remove(name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.poisoned || d.release == nil {
		return ErrStorage
	}
	if err := d.root.Remove(name); err != nil {
		return ErrStorage
	}
	dir, err := d.root.Open(".")
	if err != nil {
		d.poisoned = true
		return ErrStorage
	}
	if err = errors.Join(dir.Sync(), dir.Close()); err != nil {
		d.poisoned = true
		return ErrStorage
	}
	return nil
}
func (d *disk) names(limit int) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.poisoned || d.release == nil {
		return nil, ErrStorage
	}
	f, err := d.root.Open(".")
	if err != nil {
		return nil, ErrStorage
	}
	entries, readErr := f.ReadDir(limit + 1)
	closeErr := f.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || len(entries) > limit {
		return nil, ErrCapacity
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out, nil
}
