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
	"strconv"
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

// Bounds of the records carried for strangers: acknowledgements of copies
// from peers this installation has not admitted. They have their own share
// and a cap per peer, so a flood of strangers' copies cannot take the
// capacity this installation's own sends need.
const (
	maxStrangerAcks        = maxTrackedDelivery / 8
	maxStrangerAcksPerPeer = 8
)

// Record classes.
const (
	classOwn         = ""
	classStrangerAck = "stranger-ack"
)

// carried is one signed packet under its idempotency key: the exact bytes the
// lane carries for it, so a retry or restart never signs the key twice.
type carried struct {
	Key       string `json:"key"`
	Recipient string `json:"recipient"`
	Packet    []byte `json:"packet"`
	Deadline  uint64 `json:"deadline"`
	Withdraw  string `json:"withdraw,omitempty"`
	Settled   bool   `json:"settled,omitempty"`
	Class     string `json:"class,omitempty"`
}

// indexed is what the bounds need of one record.
type indexed struct {
	recipient string
	class     string
}

// journal is a private directory of one record per key, each written
// atomically and read strictly. A record is created exclusively: a key is
// signed once, and a second writer of the same key reads the first's bytes.
type journal struct {
	mu    sync.Mutex
	root  string
	cards string
	// sequencePath persists the last packet sequence signed, so sequences
	// stay increasing across restarts and clock steps.
	sequencePath string
	lastSequence uint64
	index        map[string]indexed
	strangers    int
	// perPeer holds, per stranger, the deadlines of its acknowledgement
	// records by record name.
	perPeer map[string]map[string]uint64
	// keys serializes get, sign and create of one key.
	keys keyLocks
}

func openJournal(stateDir string) (*journal, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return nil, ErrConfig
	}
	base := filepath.Join(stateDir, journalDir)
	j := &journal{root: filepath.Join(base, "records"), cards: filepath.Join(base, cardsDir),
		sequencePath: filepath.Join(base, "sequence"), index: map[string]indexed{}, perPeer: map[string]map[string]uint64{}}
	for _, dir := range []string{base, j.root, j.cards} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			return nil, errors.New("messenger transport journal directory must be private")
		}
	}
	// Temporary files of a write interrupted by a crash are not records.
	for _, dir := range []string{base, j.root, j.cards} {
		if err := sweepTemporary(dir); err != nil {
			return nil, err
		}
	}
	if err := j.loadSequence(); err != nil {
		return nil, err
	}
	records, err := j.scan()
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		j.track(recordName(record.Key), record)
	}
	return j, nil
}

func (j *journal) close() error { return nil }

// sweepTemporary removes the temporary files writePrivate and writeExclusive
// leave behind when a process dies mid-write.
func sweepTemporary(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".tmp-") || !entry.Type().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func recordName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:]) + ".json"
}

func (j *journal) track(name string, record carried) {
	if _, known := j.index[name]; known {
		return
	}
	j.index[name] = indexed{recipient: record.Recipient, class: record.Class}
	if record.Class == classStrangerAck {
		j.strangers++
		deadlines := j.perPeer[record.Recipient]
		if deadlines == nil {
			deadlines = map[string]uint64{}
			j.perPeer[record.Recipient] = deadlines
		}
		deadlines[name] = record.Deadline
	}
}

// liveStrangerAcks counts a stranger's acknowledgements not yet past their
// deadline: the per-peer cap bounds what is in flight to one stranger, while
// the strangers' share bounds every record the lane still holds.
func (j *journal) liveStrangerAcks(peer string, now uint64) int {
	live := 0
	for _, deadline := range j.perPeer[peer] {
		if deadline > now {
			live++
		}
	}
	return live
}

func (j *journal) untrack(name string) {
	entry, known := j.index[name]
	if !known {
		return
	}
	delete(j.index, name)
	if entry.class == classStrangerAck {
		j.strangers--
		delete(j.perPeer[entry.recipient], name)
		if len(j.perPeer[entry.recipient]) == 0 {
			delete(j.perPeer, entry.recipient)
		}
	}
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
		record.Deadline == 0 || (record.Class != classOwn && record.Class != classStrangerAck) {
		return carried{}, false, errors.New("messenger transport journal record is invalid")
	}
	return record, true, nil
}

// create writes a new record unless one exists for its key, and returns the
// record the journal holds: the new one, or the existing one, whose bytes win.
func (j *journal) create(record carried, now uint64) (carried, error) {
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > maxCarriedBytes {
		return carried{}, errors.New("messenger transport journal record exceeds its bound")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	name := recordName(record.Key)
	if existing, found, err := j.read(name, record.Key); err != nil || found {
		if found {
			j.track(name, existing)
		}
		return existing, err
	}
	if len(j.index) >= maxTrackedDelivery {
		return carried{}, errJournalFull
	}
	if record.Class == classStrangerAck &&
		(j.strangers >= maxStrangerAcks || j.liveStrangerAcks(record.Recipient, now) >= maxStrangerAcksPerPeer) {
		return carried{}, errJournalFull
	}
	created, err := writeExclusive(filepath.Join(j.root, name), raw)
	if err != nil {
		if created {
			// The record is in place although its directory sync failed:
			// it counts, as a reopen would count it.
			j.track(name, record)
		}
		return carried{}, err
	}
	if !created {
		existing, found, err := j.read(name, record.Key)
		if err != nil || !found {
			return carried{}, errors.New("messenger transport journal record vanished")
		}
		j.track(name, existing)
		return existing, nil
	}
	j.track(name, record)
	return record, nil
}

// update rewrites an existing record (its settled mark).
func (j *journal) update(record carried) error {
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > maxCarriedBytes {
		return errors.New("messenger transport journal record exceeds its bound")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	name := recordName(record.Key)
	if _, found, err := j.read(name, record.Key); err != nil || !found {
		return errors.Join(errors.New("messenger transport journal has no such record"), err)
	}
	return writePrivate(filepath.Join(j.root, name), raw)
}

func (j *journal) remove(key string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	name := recordName(key)
	err := os.Remove(filepath.Join(j.root, name))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	j.untrack(name)
	return nil
}

func (j *journal) list() ([]carried, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.scan()
}

// scan reads every record; temporary files of an interrupted write are not
// records and are not counted.
func (j *journal) scan() ([]carried, error) {
	entries, err := os.ReadDir(j.root)
	if err != nil {
		return nil, err
	}
	records := make([]carried, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".tmp-") {
			continue
		}
		if len(records) == maxTrackedDelivery {
			return nil, errors.New("messenger transport journal exceeds its bound")
		}
		record, found, err := j.read(name, "")
		if err != nil || !found {
			return nil, errors.New("messenger transport journal holds an invalid record")
		}
		records = append(records, record)
	}
	return records, nil
}

// nextSequence returns a packet sequence above every one signed before, also
// across restarts: the clock in nanoseconds, or the last sequence plus one
// when the clock is behind it. It is persisted before it is used.
func (j *journal) nextSequence(nowNano uint64) (uint64, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	next, overflow := addUint64(j.lastSequence, 1)
	if overflow {
		return 0, errors.New("messenger transport packet sequences are exhausted")
	}
	next = max(next, nowNano)
	if err := writePrivate(j.sequencePath, []byte(strconv.FormatUint(next, 10))); err != nil {
		return 0, err
	}
	j.lastSequence = next
	return next, nil
}

func (j *journal) loadSequence() error {
	raw, err := readBounded(j.sequencePath, 32)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	value, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil {
		return errors.New("messenger transport sequence file is invalid")
	}
	j.lastSequence = value
	return nil
}

func addUint64(a, b uint64) (uint64, bool) {
	sum := a + b
	return sum, sum < a
}

// keyLocks is a mutex per key, held only while the key is in use.
type keyLocks struct {
	mu    sync.Mutex
	locks map[string]*keyLock
}

type keyLock struct {
	mu    sync.Mutex
	users int
}

func (k *keyLocks) lock(key string) func() {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*keyLock{}
	}
	entry := k.locks[key]
	if entry == nil {
		entry = &keyLock{}
		k.locks[key] = entry
	}
	entry.users++
	k.mu.Unlock()
	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		k.mu.Lock()
		if entry.users--; entry.users == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}

// writeExclusive creates path with data unless it exists: the synced
// temporary file is linked into place, which fails on an existing path.
func writeExclusive(path string, data []byte) (bool, error) {
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return false, err
	}
	name := temporary.Name()
	defer func() {
		if removeErr := os.Remove(name); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return false, errors.Join(err, temporary.Close())
	}
	if _, err := temporary.Write(data); err != nil {
		return false, errors.Join(err, temporary.Close())
	}
	if err := temporary.Sync(); err != nil {
		return false, errors.Join(err, temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Link(name, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return true, err
	}
	return true, errors.Join(directory.Sync(), directory.Close())
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
