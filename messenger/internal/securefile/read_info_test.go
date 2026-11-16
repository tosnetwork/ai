package securefile

import (
	"os"
	"path/filepath"
	"testing"
)

// The returned FileInfo is the opened file's: its mode is what was read.
func TestReadBoundedRegularInfoDescribesTheOpenedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("value"), 0o640); err != nil {
		t.Fatal(err)
	}
	raw, info, err := ReadBoundedRegularInfo(path, 16)
	if err != nil || string(raw) != "value" || info == nil || info.Mode().Perm() != 0o640 || info.Size() != 5 {
		t.Fatalf("read: %q %v %v", raw, info, err)
	}
	if _, _, err := ReadBoundedRegularInfo(path, 4); err == nil {
		t.Fatal("a file over its limit was read")
	}
}
