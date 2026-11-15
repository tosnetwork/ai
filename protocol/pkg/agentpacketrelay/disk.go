package agentpacketrelay

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// On-disk layout of a state directory:
//
//	FORMAT                         the layout marker, exactly diskFormat
//	LOCK                           held with an exclusive advisory lock while open
//	envelopes/<agent hex>-<id hex>  one envelope record per stored envelope
//	tombstones/<agent hex>-<id hex> one tombstone record per acknowledged envelope
//	tmp/                           partial writes; emptied on open
//
// Every record is written to tmp/, synced, renamed into place, and the
// target directory is synced, so a record name never refers to a partial
// write. Every record carries a SHA-256 over its contents and must agree
// with its file name; a record that does not, any unknown file, or a wrong
// FORMAT makes OpenDiskStore refuse the directory rather than guess.
const (
	diskFormat       = "tos.service.agent-packet-relay.store.v1\n"
	envelopeMagic    = "APRSENV1"
	tombstoneMagic   = "APRSTMB1"
	envelopeMetaSize = len(envelopeMagic) + 8 + 8 + 16 + 1 + 32
	tombstoneSize    = len(tombstoneMagic) + agentpacketseal.AgentDigestSize + 32 + 8 + 32
	dirEnvelopes     = "envelopes"
	dirTombstones    = "tombstones"
	dirTemp          = "tmp"
)

// beforeRename, when set by a test, runs after a record is written and
// synced and before it is renamed into place.
var beforeRename func(target string)

type diskBackend struct {
	root string
	lock *os.File
}

// OpenDiskStore opens (creating when empty) the durable store in dir and
// loads its index. Expired entries, partial writes and envelopes whose
// tombstone survived a crash are removed; any corrupt or unknown entry is
// an error. Only one process may hold a state directory.
func OpenDiskStore(dir string, limits Limits, now time.Time) (*Store, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(dir) {
		return nil, errors.New("agentpacketrelay: state directory must be an absolute path")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("agentpacketrelay: create state directory: %w", err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, "LOCK"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("agentpacketrelay: open state lock: %w", err)
	}
	if err := lockFile(lock); err != nil {
		lock.Close()
		return nil, fmt.Errorf("agentpacketrelay: state directory is in use by another process: %w", err)
	}
	backend := &diskBackend{root: dir, lock: lock}
	store, err := backend.load(limits, uint64(max(now.Unix(), 0)))
	if err != nil {
		lock.Close()
		return nil, err
	}
	return store, nil
}

func (d *diskBackend) load(limits Limits, now uint64) (*Store, error) {
	if err := d.checkFormat(); err != nil {
		return nil, err
	}
	for _, name := range []string{dirEnvelopes, dirTombstones, dirTemp} {
		if err := os.MkdirAll(filepath.Join(d.root, name), 0o700); err != nil {
			return nil, fmt.Errorf("agentpacketrelay: create %s: %w", name, err)
		}
	}
	if err := d.clearTemp(); err != nil {
		return nil, err
	}
	store, err := newStore(limits, d)
	if err != nil {
		return nil, err
	}
	stones, err := os.ReadDir(filepath.Join(d.root, dirTombstones))
	if err != nil {
		return nil, fmt.Errorf("agentpacketrelay: read tombstones: %w", err)
	}
	for _, entry := range stones {
		key, ok := fileKey(entry)
		if !ok {
			return nil, fmt.Errorf("%w: unexpected entry tombstones/%s", errStoreCorrupt, entry.Name())
		}
		stone, err := d.readTombstone(key)
		if err != nil {
			return nil, err
		}
		if stone.expires <= now {
			if err := d.deleteTombstone(key); err != nil {
				return nil, err
			}
			continue
		}
		store.addTombstone(key, stone)
	}
	envelopes, err := os.ReadDir(filepath.Join(d.root, dirEnvelopes))
	if err != nil {
		return nil, fmt.Errorf("agentpacketrelay: read envelopes: %w", err)
	}
	for _, entry := range envelopes {
		key, ok := fileKey(entry)
		if !ok {
			return nil, fmt.Errorf("%w: unexpected entry envelopes/%s", errStoreCorrupt, entry.Name())
		}
		rec, err := d.readRecord(key)
		if err != nil {
			return nil, err
		}
		if _, acknowledged := store.tombstones[key]; acknowledged || rec.expires <= now {
			if err := d.deleteEnvelope(key); err != nil {
				return nil, err
			}
			continue
		}
		rec.committed = true
		store.addRecord(&rec)
	}
	return store, nil
}

func (d *diskBackend) checkFormat() error {
	path := filepath.Join(d.root, "FORMAT")
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		entries, readErr := os.ReadDir(d.root)
		if readErr != nil {
			return fmt.Errorf("agentpacketrelay: read state directory: %w", readErr)
		}
		for _, entry := range entries {
			if entry.Name() != "LOCK" {
				return fmt.Errorf("%w: state directory has no FORMAT marker but is not empty", errStoreCorrupt)
			}
		}
		return d.writeAtomic(d.root, "FORMAT", []byte(diskFormat))
	}
	if err != nil {
		return fmt.Errorf("agentpacketrelay: read FORMAT: %w", err)
	}
	if string(raw) != diskFormat {
		return fmt.Errorf("%w: unknown state directory format", errStoreCorrupt)
	}
	return nil
}

func (d *diskBackend) clearTemp() error {
	dir := filepath.Join(d.root, dirTemp)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("agentpacketrelay: read tmp: %w", err)
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%w: unexpected entry tmp/%s", errStoreCorrupt, entry.Name())
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			return fmt.Errorf("agentpacketrelay: remove partial write: %w", err)
		}
	}
	return syncDir(dir)
}

// keyFileName is the file name of a key: the Agent digest and the envelope
// ID, each as 64 lowercase hex, joined by a dash.
func keyFileName(key entryKey) string {
	return hex.EncodeToString(key.agent[:]) + "-" + hex.EncodeToString(key.id[:])
}

// fileKey accepts only a regular file named by keyFileName of a non-zero
// Agent digest and a non-zero envelope ID.
func fileKey(entry fs.DirEntry) (entryKey, bool) {
	if !entry.Type().IsRegular() {
		return entryKey{}, false
	}
	agentHex, idHex, ok := strings.Cut(entry.Name(), "-")
	if !ok {
		return entryKey{}, false
	}
	agent, agentOK := parseEnvelopeIDText(agentHex)
	id, idOK := parseEnvelopeIDText(idHex)
	if !agentOK || !idOK {
		return entryKey{}, false
	}
	return entryKey{agent: agent, id: id}, true
}

func (d *diskBackend) envelopePath(key entryKey) string {
	return filepath.Join(d.root, dirEnvelopes, keyFileName(key))
}

func (d *diskBackend) tombstonePath(key entryKey) string {
	return filepath.Join(d.root, dirTombstones, keyFileName(key))
}

// writeAtomic writes data to dir/name through tmp/: write, sync, rename,
// sync the directory.
func (d *diskBackend) writeAtomic(dir, name string, data []byte) error {
	tempDir := filepath.Join(d.root, dirTemp)
	if err := os.MkdirAll(tempDir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(tempDir, "write-*")
	if err != nil {
		return err
	}
	tempName := file.Name()
	_, writeErr := file.Write(data)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr == nil && beforeRename != nil {
		beforeRename(filepath.Join(dir, name))
	}
	if writeErr == nil {
		writeErr = os.Rename(tempName, filepath.Join(dir, name))
	}
	if writeErr != nil {
		_ = os.Remove(tempName)
		return writeErr
	}
	return syncDir(dir)
}

func encodeEnvelopeRecord(rec record, envelope []byte) []byte {
	out := make([]byte, 0, envelopeMetaSize+len(envelope))
	out = append(out, envelopeMagic...)
	out = binary.BigEndian.AppendUint64(out, rec.received)
	out = binary.BigEndian.AppendUint64(out, rec.expires)
	client := rec.client.As16()
	out = append(out, client[:]...)
	if rec.client.Is4() {
		out = append(out, 4)
	} else {
		out = append(out, 6)
	}
	hash := sha256.New()
	hash.Write(out)
	hash.Write(envelope)
	out = hash.Sum(out)
	return append(out, envelope...)
}

func (d *diskBackend) putEnvelope(rec record, envelope []byte) error {
	return d.writeAtomic(filepath.Join(d.root, dirEnvelopes), keyFileName(rec.key()), encodeEnvelopeRecord(rec, envelope))
}

// readFileBounded reads at most limit bytes and fails on more.
func readFileBounded(path string, limit int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, errStoreCorrupt
	}
	return raw, nil
}

// decodeEnvelopeRecord checks a record against the key its file name gives
// and returns its index entry and the envelope bytes.
func decodeEnvelopeRecord(key entryKey, raw []byte) (record, []byte, error) {
	if len(raw) < envelopeMetaSize || string(raw[:len(envelopeMagic)]) != envelopeMagic {
		return record{}, nil, errStoreCorrupt
	}
	meta := envelopeMetaSize - 32
	envelope := raw[envelopeMetaSize:]
	hash := sha256.New()
	hash.Write(raw[:meta])
	hash.Write(envelope)
	if [32]byte(hash.Sum(nil)) != [32]byte(raw[meta:envelopeMetaSize]) {
		return record{}, nil, errStoreCorrupt
	}
	offset := len(envelopeMagic)
	received := binary.BigEndian.Uint64(raw[offset:])
	expires := binary.BigEndian.Uint64(raw[offset+8:])
	client := netip.AddrFrom16([16]byte(raw[offset+16 : offset+32]))
	switch raw[offset+32] {
	case 4:
		if !client.Is4In6() {
			return record{}, nil, errStoreCorrupt
		}
		client = client.Unmap()
	case 6:
	default:
		return record{}, nil, errStoreCorrupt
	}
	header, err := agentpacketseal.ParseEnvelope(envelope)
	if err != nil || header.EnvelopeID != key.id || received == 0 || expires <= received ||
		expires > header.ExpiresAtUnix {
		return record{}, nil, errStoreCorrupt
	}
	agent, err := agentpacketseal.AgentDigest(header.RecipientAgentID)
	if err != nil || agent != key.agent {
		return record{}, nil, errStoreCorrupt
	}
	return record{agent: agent, keyID: header.RecipientKeyID, id: key.id, size: int64(len(envelope)), received: received,
		expires: expires, client: client, sum: sha256.Sum256(envelope)}, envelope, nil
}

func (d *diskBackend) readRecord(key entryKey) (record, error) {
	raw, err := readFileBounded(d.envelopePath(key), envelopeMetaSize+MaxEnvelopeBytes)
	if err != nil {
		return record{}, fmt.Errorf("%w: envelopes/%s: %v", errStoreCorrupt, keyFileName(key), err)
	}
	rec, _, err := decodeEnvelopeRecord(key, raw)
	if err != nil {
		return record{}, fmt.Errorf("%w: envelopes/%s", errStoreCorrupt, keyFileName(key))
	}
	return rec, nil
}

func (d *diskBackend) getEnvelope(key entryKey) ([]byte, error) {
	raw, err := readFileBounded(d.envelopePath(key), envelopeMetaSize+MaxEnvelopeBytes)
	if err != nil {
		return nil, err
	}
	_, envelope, err := decodeEnvelopeRecord(key, raw)
	if err != nil {
		return nil, err
	}
	return envelope, nil
}

func encodeTombstone(key entryKey, stone tombstone) []byte {
	out := make([]byte, 0, tombstoneSize)
	out = append(out, tombstoneMagic...)
	out = append(out, stone.agent[:]...)
	out = append(out, key.id[:]...)
	out = binary.BigEndian.AppendUint64(out, stone.expires)
	sum := sha256.Sum256(out)
	return append(out, sum[:]...)
}

func (d *diskBackend) putTombstone(key entryKey, stone tombstone) error {
	if stone.agent != key.agent {
		return errors.New("agentpacketrelay: tombstone names another mailbox than its key")
	}
	return d.writeAtomic(filepath.Join(d.root, dirTombstones), keyFileName(key), encodeTombstone(key, stone))
}

func (d *diskBackend) readTombstone(key entryKey) (tombstone, error) {
	name := keyFileName(key)
	raw, err := readFileBounded(d.tombstonePath(key), tombstoneSize)
	if err != nil || len(raw) != tombstoneSize || string(raw[:len(tombstoneMagic)]) != tombstoneMagic ||
		sha256.Sum256(raw[:tombstoneSize-32]) != [32]byte(raw[tombstoneSize-32:]) {
		return tombstone{}, fmt.Errorf("%w: tombstones/%s", errStoreCorrupt, name)
	}
	offset := len(tombstoneMagic)
	var stone tombstone
	copy(stone.agent[:], raw[offset:offset+agentpacketseal.AgentDigestSize])
	offset += agentpacketseal.AgentDigestSize
	if stone.agent != key.agent || [32]byte(raw[offset:offset+32]) != key.id {
		return tombstone{}, fmt.Errorf("%w: tombstones/%s names another key", errStoreCorrupt, name)
	}
	stone.expires = binary.BigEndian.Uint64(raw[offset+32:])
	if stone.expires == 0 {
		return tombstone{}, fmt.Errorf("%w: tombstones/%s", errStoreCorrupt, name)
	}
	return stone, nil
}

func removeSynced(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func (d *diskBackend) deleteEnvelope(key entryKey) error { return removeSynced(d.envelopePath(key)) }

func (d *diskBackend) deleteTombstone(key entryKey) error { return removeSynced(d.tombstonePath(key)) }

func (d *diskBackend) close() error { return d.lock.Close() }

func syncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := handle.Sync()
	if closeErr := handle.Close(); syncErr == nil {
		syncErr = closeErr
	}
	return syncErr
}
