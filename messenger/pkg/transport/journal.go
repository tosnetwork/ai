package transport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tosnetwork/ai/protocol/pkg/agentcarrier"
)

// journalDir is this package's directory inside the lane's state directory,
// beside agentcarrier's own, which never reads it.
const journalDir = "messenger-carry"

// maxCarriedBytes bounds one journal record: a maximal packet in JSON and its
// fields.
const maxCarriedBytes = agentcarrier.MaxRecordBytes

var errJournalFull = errors.New("messenger transport journal is full")

// carried is one signed packet under its idempotency key: the exact bytes the
// lane carries for it, so a retry or restart never signs the key twice.
type carried struct {
	Key       string `json:"key"`
	Recipient string `json:"recipient"`
	Packet    []byte `json:"packet"`
	Deadline  uint64 `json:"deadline"`
	Withdraw  string `json:"withdraw,omitempty"`
	Settled   bool   `json:"settled,omitempty"`
}

// journal is a private directory of one record per key, each written
// atomically and read strictly.
type journal struct {
	mu    sync.Mutex
	root  string
	cards string
}

func openJournal(stateDir string) (*journal, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return nil, ErrConfig
	}
	base := filepath.Join(stateDir, journalDir)
	j := &journal{root: filepath.Join(base, "records"), cards: filepath.Join(base, cardsDir)}
	for _, dir := range []string{base, j.root, j.cards} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			return nil, errors.New("messenger transport journal directory must be private")
		}
	}
	return j, nil
}

func (j *journal) close() error { return nil }

func recordName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:]) + ".json"
}

func (j *journal) get(key string) (carried, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.read(recordName(key), key)
}

func (j *journal) read(name, key string) (carried, bool, error) {
	file, err := os.OpenFile(filepath.Join(j.root, name), os.O_RDONLY|noFollow, 0)
	if errors.Is(err, os.ErrNotExist) {
		return carried{}, false, nil
	}
	if err != nil {
		return carried{}, false, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxCarriedBytes+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(raw) > maxCarriedBytes {
		return carried{}, false, errors.New("messenger transport journal record is unreadable")
	}
	var record carried
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.Key == "" || len(record.Key) > 128 ||
		(key != "" && record.Key != key) || recordName(record.Key) != name || len(record.Packet) == 0 ||
		record.Deadline == 0 {
		return carried{}, false, errors.New("messenger transport journal record is invalid")
	}
	return record, true, nil
}

func (j *journal) put(record carried) error {
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > maxCarriedBytes {
		return errors.New("messenger transport journal record exceeds its bound")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	name := recordName(record.Key)
	if _, err := os.Lstat(filepath.Join(j.root, name)); errors.Is(err, os.ErrNotExist) {
		entries, err := os.ReadDir(j.root)
		if err != nil {
			return err
		}
		if len(entries) >= maxTrackedDelivery {
			return errJournalFull
		}
	}
	return writePrivate(filepath.Join(j.root, name), raw)
}

func (j *journal) remove(key string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	err := os.Remove(filepath.Join(j.root, recordName(key)))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (j *journal) list() ([]carried, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	entries, err := os.ReadDir(j.root)
	if err != nil {
		return nil, err
	}
	if len(entries) > maxTrackedDelivery {
		return nil, errors.New("messenger transport journal exceeds its bound")
	}
	records := make([]carried, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".tmp-") {
			continue
		}
		record, found, err := j.read(name, "")
		if err != nil || !found {
			return nil, errors.New("messenger transport journal holds an invalid record")
		}
		records = append(records, record)
	}
	return records, nil
}

// writePrivate replaces path with data, mode 0600, through a synced
// temporary file in the same directory.
func writePrivate(path string, data []byte) error {
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	done := false
	defer func() {
		if !done {
			if removeErr := os.Remove(name); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return
			}
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if _, err := temporary.Write(data); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if err := temporary.Sync(); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	done = true
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
