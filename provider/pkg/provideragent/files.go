package provideragent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// maxStateFile bounds one agent state file.
const maxStateFile = 4 << 20

func cleanAbsolute(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }

// checkPrivateDir requires an existing directory of the agent's account,
// not a link, closed to group and others.
func checkPrivateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !ownedByMe(info) {
		return fmt.Errorf("%s must be a directory private to the agent's account", filepath.Base(path))
	}
	return nil
}

// ensurePrivateDir creates an owner-only directory or checks an existing
// one.
func ensurePrivateDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return checkPrivateDir(path)
}

// checkPrivateFile requires a regular file of the agent's account that
// group and others can neither read nor write.
func checkPrivateFile(path, name string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("the %s cannot be read: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownedByMe(info) {
		return fmt.Errorf("the %s must be a regular file private to the agent's account (mode 0600)", name)
	}
	return nil
}

// readPrivate reads an owner-private regular file of bounded size.
func readPrivate(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownedByMe(info) || info.Size() > maxStateFile {
		return nil, errors.New("an agent state file is not an owner-private regular file")
	}
	return os.ReadFile(path)
}

// decodeStrict decodes one JSON value, refusing unknown fields and trailing
// data.
func decodeStrict(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// decodeStrictNoDuplicates is decodeStrict that also refuses a duplicate
// object key at any depth, which the standard decoder would silently
// resolve to the last value.
func decodeStrictNoDuplicates(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanDuplicates(decoder, 0); err != nil {
		return err
	}
	return decodeStrict(raw, value)
}

func scanDuplicates(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("nested too deeply")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("an object key is not a string")
			}
			if seen[name] {
				return fmt.Errorf("duplicate key %q", name)
			}
			seen[name] = true
			if err := scanDuplicates(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanDuplicates(decoder, depth+1); err != nil {
				return err
			}
		}
	}
	_, err = decoder.Token()
	return err
}

func readJSON(path string, value any) error {
	raw, err := readPrivate(path)
	if err != nil {
		return err
	}
	if err := decodeStrict(raw, value); err != nil {
		return fmt.Errorf("agent state file %s does not decode: %w", filepath.Base(path), err)
	}
	return nil
}

// writePrivate atomically replaces path with an owner-only file holding
// value, synced before and after the rename. With exclusive set it refuses
// to replace an existing file.
func writePrivate(path string, value []byte, exclusive bool) error {
	if len(value) > maxStateFile {
		return errors.New("an agent state file would exceed its bound")
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".tmp-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0o600); err != nil {
		return errors.Join(err, file.Close())
	}
	if _, err := file.Write(value); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return err
	}
	if exclusive {
		// A hard link fails when the target exists, so two writers never
		// both create the same record.
		if err := os.Link(name, path); err != nil {
			return err
		}
	} else if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDir(directory)
}

func syncDir(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(handle.Sync(), handle.Close())
}

func writeJSON(path string, value any, exclusive bool) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(path, append(raw, '\n'), exclusive)
}

// removeSynced removes path and syncs its directory; a missing file is no
// error.
func removeSynced(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(path))
}
