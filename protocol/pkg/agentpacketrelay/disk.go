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
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// On-disk layout of a state directory:
//
//	FORMAT              the layout marker, exactly diskFormat
//	LOCK                held with an exclusive advisory lock while open
//	envelopes/<id hex>  one envelope record per stored envelope
//	tombstones/<id hex> one tombstone record per acknowledged ID
//	tmp/                partial writes; emptied on open
//
// Every record is written to tmp/, synced, renamed into place, and the
// target directory is synced, so a record name never refers to a partial
// write. Every record carries a SHA-256 over its contents; a record that
// fails it, any unknown file, or a wrong FORMAT makes OpenDiskStore refuse
// the directory rather than guess.
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
		id, ok := fileID(entry)
		if !ok {
			return nil, fmt.Errorf("%w: unexpected entry tombstones/%s", errStoreCorrupt, entry.Name())
		}
		stone, err := d.readTombstone(id)
		if err != nil {
			return nil, err
		}
		if stone.expires <= now {
			if err := d.deleteTombstone(id); err != nil {
				return nil, err
			}
			continue
		}
		store.addTombstone(id, stone)
	}
	envelopes, err := os.ReadDir(filepath.Join(d.root, dirEnvelopes))
	if err != nil {
		return nil, fmt.Errorf("agentpacketrelay: read envelopes: %w", err)
	}
	for _, entry := range envelopes {
		id, ok := fileID(entry)
		if !ok {
			return nil, fmt.Errorf("%w: unexpected entry envelopes/%s", errStoreCorrupt, entry.Name())
		}
		rec, err := d.readRecord(id)
		if err != nil {
			return nil, err
		}
		if _, acknowledged := store.tombstones[id]; acknowledged || rec.expires <= now {
			if err := d.deleteEnvelope(id); err != nil {
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

// fileID accepts only a regular file named by a canonical non-zero ID.
func fileID(entry fs.DirEntry) ([32]byte, bool) {
	if !entry.Type().IsRegular() {
		return [32]byte{}, false
	}
	return parseEnvelopeIDText(entry.Name())
}

func (d *diskBackend) envelopePath(id [32]byte) string {
	return filepath.Join(d.root, dirEnvelopes, hex.EncodeToString(id[:]))
}

func (d *diskBackend) tombstonePath(id [32]byte) string {
	return filepath.Join(d.root, dirTombstones, hex.EncodeToString(id[:]))
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
	return d.writeAtomic(filepath.Join(d.root, dirEnvelopes), hex.EncodeToString(rec.id[:]),
		encodeEnvelopeRecord(rec, envelope))
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

// decodeEnvelopeRecord checks a record and returns its index entry and the
// envelope bytes.
func decodeEnvelopeRecord(id [32]byte, raw []byte) (record, []byte, error) {
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
	if err != nil || header.EnvelopeID != id || received == 0 || expires <= received ||
		expires > header.ExpiresAtUnix {
		return record{}, nil, errStoreCorrupt
	}
	agent, err := agentpacketseal.AgentDigest(header.RecipientAgentID)
	if err != nil {
		return record{}, nil, errStoreCorrupt
	}
	return record{agent: agent, keyID: header.RecipientKeyID, id: id, size: int64(len(envelope)), received: received,
		expires: expires, client: client, sum: sha256.Sum256(envelope)}, envelope, nil
}

func (d *diskBackend) readRecord(id [32]byte) (record, error) {
	raw, err := readFileBounded(d.envelopePath(id), envelopeMetaSize+MaxEnvelopeBytes)
	if err != nil {
		return record{}, fmt.Errorf("%w: envelopes/%x: %v", errStoreCorrupt, id, err)
	}
	rec, _, err := decodeEnvelopeRecord(id, raw)
	if err != nil {
		return record{}, fmt.Errorf("%w: envelopes/%x", errStoreCorrupt, id)
	}
	return rec, nil
}

func (d *diskBackend) getEnvelope(id [32]byte) ([]byte, error) {
	raw, err := readFileBounded(d.envelopePath(id), envelopeMetaSize+MaxEnvelopeBytes)
	if err != nil {
		return nil, err
	}
	_, envelope, err := decodeEnvelopeRecord(id, raw)
	if err != nil {
		return nil, err
	}
	return envelope, nil
}

func encodeTombstone(id [32]byte, stone tombstone) []byte {
	out := make([]byte, 0, tombstoneSize)
	out = append(out, tombstoneMagic...)
	out = append(out, stone.agent[:]...)
	out = append(out, id[:]...)
	out = binary.BigEndian.AppendUint64(out, stone.expires)
	sum := sha256.Sum256(out)
	return append(out, sum[:]...)
}

func (d *diskBackend) putTombstone(id [32]byte, stone tombstone) error {
	return d.writeAtomic(filepath.Join(d.root, dirTombstones), hex.EncodeToString(id[:]), encodeTombstone(id, stone))
}

func (d *diskBackend) readTombstone(id [32]byte) (tombstone, error) {
	raw, err := readFileBounded(d.tombstonePath(id), tombstoneSize)
	if err != nil || len(raw) != tombstoneSize || string(raw[:len(tombstoneMagic)]) != tombstoneMagic ||
		sha256.Sum256(raw[:tombstoneSize-32]) != [32]byte(raw[tombstoneSize-32:]) {
		return tombstone{}, fmt.Errorf("%w: tombstones/%x", errStoreCorrupt, id)
	}
	offset := len(tombstoneMagic)
	var stone tombstone
	copy(stone.agent[:], raw[offset:offset+agentpacketseal.AgentDigestSize])
	offset += agentpacketseal.AgentDigestSize
	if [32]byte(raw[offset:offset+32]) != id {
		return tombstone{}, fmt.Errorf("%w: tombstones/%x names another ID", errStoreCorrupt, id)
	}
	stone.expires = binary.BigEndian.Uint64(raw[offset+32:])
	if stone.agent == (agentDigest{}) || stone.expires == 0 {
		return tombstone{}, fmt.Errorf("%w: tombstones/%x", errStoreCorrupt, id)
	}
	return stone, nil
}

func removeSynced(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func (d *diskBackend) deleteEnvelope(id [32]byte) error { return removeSynced(d.envelopePath(id)) }

func (d *diskBackend) deleteTombstone(id [32]byte) error { return removeSynced(d.tombstonePath(id)) }

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
