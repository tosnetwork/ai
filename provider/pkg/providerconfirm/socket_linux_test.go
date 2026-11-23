//go:build linux

package providerconfirm

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// The confirmer talks only to a socket its own account owns: one owned by
// another uid, a link to a socket, a plain file and a missing path are each
// refused before any call.
func TestTheConfirmerChecksTheAgentSocketsOwner(t *testing.T) {
	root, err := os.MkdirTemp("", "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	path := filepath.Join(root, "agent.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := CheckAgentSocket(path); err != nil {
		t.Fatalf("this account's socket: %v", err)
	}
	if err := checkSocketOwner(path, uint32(os.Geteuid())+1); !errors.Is(err, ErrSocketNotCustody) {
		t.Fatalf("another account's socket: %v", err)
	}
	link := filepath.Join(root, "link.sock")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(root, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, refused := range []string{link, plain, filepath.Join(root, "none")} {
		if err := CheckAgentSocket(refused); err == nil {
			t.Errorf("%s was accepted", filepath.Base(refused))
		}
	}
}
