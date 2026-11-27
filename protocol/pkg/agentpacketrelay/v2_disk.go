package agentpacketrelay

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

	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/internal/osguard"
)

const v2Format = "tos.service.agent-packet-relay.store.v2\n"
const maxV2RecordBytes = MaxEnvelopeBytes*4/3 + 4096

type v2Disk struct {
	root         string
	release      func()
	beforeRename func(string) error
	beforeSync   func(string) error
}

func openV2Disk(path string) (*v2Disk, bool, error) {
	if !osguard.OwnerPrivateStorageSupported() || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, false, errors.New("V2 store needs an absolute owner-private path on a supported host")
	}
	for parent := path; ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0) {
				return nil, false, errors.New("V2 store has an untrusted ancestor")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, false, err
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	var created []string
	for p := path; ; p = filepath.Dir(p) {
		_, err := os.Lstat(p)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, false, err
		}
		created = append(created, p)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, false, err
	}
	// File/record sync alone does not make a freshly created root's name
	// durable in its parent. Persist every new directory link before use.
	for _, p := range append(created, path) {
		if err := syncDir(filepath.Dir(p)); err != nil {
			return nil, false, err
		}
	}

	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return nil, false, errors.New("V2 store must be owner-private")
	}
	lock := filepath.Join(path, "LOCK")
	if err = privateV2File(lock, true); err != nil {
		return nil, false, err
	}
	release, acquired, err := osguard.TryExclusiveFileLock(lock, 0o600)
	if err != nil {
		return nil, false, err
	}
	if !acquired {
		return nil, false, errors.New("V2 store is already open")
	}
	d := &v2Disk{root: path, release: release}
	entries, err := os.ReadDir(path)
	if err != nil {
		release()
		return nil, false, err
	}
	fresh := true
	for _, entry := range entries {
		if entry.Name() != "LOCK" {
			fresh = false
		}
	}
	if fresh {
		return d, true, nil
	}
	format, err := readV2File(filepath.Join(path, "FORMAT"), 128)
	if err != nil || string(format) != v2Format {
		release()
		return nil, false, errors.New("V2 store format missing or invalid; never reuse a V1 directory")
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "FORMAT", "REPLAY", "LOCK":
			if !entry.Type().IsRegular() {
				release()
				return nil, false, errors.New("invalid V2 root entry")
			}
		case "records", "controls", "tmp":
			if !entry.IsDir() {
				release()
				return nil, false, errors.New("invalid V2 directory")
			}
		default:
			release()
			return nil, false, errors.New("unknown V2 store entry")
		}
	}
	return d, false, nil
}
func privateV2File(path string, absent bool) error {
	info, err := os.Lstat(path)
	if absent && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) || !singleV2Link(info) {
		return errors.New("V2 record must be owner-private, regular and single-linked")
	}
	return nil
}
func readV2File(path string, limit int) ([]byte, error) {
	if err := privateV2File(path, false); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, errors.New("V2 record exceeds its bound")
	}
	return data, nil
}
func (d *v2Disk) prepare(fresh bool) error {
	for _, name := range []string{"records", "controls", "tmp"} {
		path := filepath.Join(d.root, name)
		if fresh {
			if err := os.MkdirAll(path, 0o700); err != nil {
				return err
			}
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
			return errors.New("invalid V2 private subdirectory")
		}
	}
	return syncDir(d.root)
}
func (d *v2Disk) write(name string, data []byte) (result error) {
	f, err := os.CreateTemp(filepath.Join(d.root, "tmp"), "write-")
	if err != nil {
		return err
	}
	// A failed periodic mark must not accumulate private temporary files.
	// Process crashes bypass this defer; startup validates and removes those.
	defer func() {
		if err := os.Remove(f.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}()
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if d.beforeRename != nil {
		if err = d.beforeRename(name); err != nil {
			return err
		}
	}
	target := filepath.Join(d.root, name)
	if err = os.Rename(f.Name(), target); err != nil {
		return err
	}
	if d.beforeSync != nil {
		if err = d.beforeSync(name); err != nil {
			return err
		}
	}
	return syncDir(filepath.Dir(target))
}
func (d *v2Disk) remove(name string) error {
	err := os.Remove(filepath.Join(d.root, name))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(filepath.Join(d.root, name)))
}
func (d *v2Disk) clearTemp() error {
	entries, err := os.ReadDir(filepath.Join(d.root, "tmp"))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(d.root, "tmp", entry.Name())
		if !strings.HasPrefix(entry.Name(), "write-") || privateV2File(path, false) != nil {
			return errors.New("invalid V2 partial record")
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	return syncDir(filepath.Join(d.root, "tmp"))
}

type v2Wrapped struct {
	Payload json.RawMessage `json:"payload"`
	SHA256  string          `json:"sha256"`
}

func encodeV2(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte("tos.service.relay-record.v2\x00"), raw...))
	return json.Marshal(v2Wrapped{raw, hex.EncodeToString(sum[:])})
}
func decodeV2(raw []byte, value any) error {
	var wrapper v2Wrapped
	if err := jsonstrict.Decode(raw, &wrapper); err != nil {
		return errors.New("invalid V2 checked record")
	}
	sum := sha256.Sum256(append([]byte("tos.service.relay-record.v2\x00"), wrapper.Payload...))
	if wrapper.SHA256 != hex.EncodeToString(sum[:]) {
		return errors.New("V2 checksum mismatch")
	}
	if err := jsonstrict.Decode(wrapper.Payload, value); err != nil {
		return errors.New("invalid V2 payload")
	}
	// Writer has exactly one JSON representation. Reject missing/duplicate fields
	// and alternate encodings rather than interpreting a damaged record's defaults.
	canonicalPayload, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonicalPayload, wrapper.Payload) {
		return errors.New("noncanonical V2 payload")
	}
	canonical, err := json.Marshal(wrapper)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errors.New("noncanonical V2 record")
	}
	return nil
}
