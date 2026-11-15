//go:build linux

package executorservice

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// peerUID is the kernel-attested uid of the process that connected (or, on
// the client side, that listens). It is read from the socket itself and
// cannot be claimed by the peer.
func peerUID(conn *net.UnixConn) (uint32, error) {
	if conn == nil {
		return 0, errors.New("executor service peer credential is unavailable")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, errors.New("executor service peer credential is unavailable")
	}
	var credential *unix.Ucred
	var credentialErr error
	if err := raw.Control(func(descriptor uintptr) {
		credential, credentialErr = unix.GetsockoptUcred(int(descriptor), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credentialErr != nil || credential == nil {
		return 0, errors.New("executor service peer credential is unavailable")
	}
	return credential.Uid, nil
}

// Listen creates the service socket at path for callers in group gid.
//
// The parent directory must already exist and be a real directory owned by
// the server identity; an earlier socket of the same owner at path is
// replaced, anything else there refuses the start.
// Listen leaves it mode 0750 owner:gid and the socket mode 0660 owner:gid, so
// only the owner and members of that one group can reach the socket at all;
// the uid allow-list is then enforced per connection. The directory is kept
// owner-only while the socket is created and opened only once the socket has
// its final mode, so there is no moment at which another user can connect to
// a wider socket.
func Listen(path string, gid uint32) (*net.UnixListener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		return nil, errors.New("executor service socket path must be canonical, absolute and short")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ownedByServer(info) {
		return nil, errors.New("executor service socket directory must be a directory owned by the server")
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return nil, errors.New("executor service socket directory path contains a symlink")
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return nil, errors.New("protect executor service socket directory")
	}
	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSocket == 0 || !ownedByServer(existing) {
			return nil, errors.New("executor service socket path is occupied")
		}
		if err := os.Remove(path); err != nil {
			return nil, errors.New("remove stale executor service socket")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("inspect executor service socket path")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, errors.New("listen on executor service socket")
	}
	if err := openToGroup(path, parent, gid); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func openToGroup(path, parent string, gid uint32) error {
	if err := os.Lchown(path, os.Geteuid(), int(gid)); err != nil {
		return errors.New("set executor service socket group")
	}
	if err := os.Chmod(path, 0o660); err != nil {
		return errors.New("set executor service socket mode")
	}
	if err := os.Lchown(parent, os.Geteuid(), int(gid)); err != nil {
		return errors.New("set executor service socket directory group")
	}
	if err := os.Chmod(parent, 0o750); err != nil {
		return errors.New("set executor service socket directory mode")
	}
	return nil
}

func ownedByServer(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
