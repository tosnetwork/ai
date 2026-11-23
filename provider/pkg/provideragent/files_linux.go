//go:build linux

package provideragent

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// ownedByMe reports whether the file belongs to this process's effective
// uid.
func ownedByMe(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

// errLockHeld reports a lock another open file holds.
var errLockHeld = errors.New("the lock is held")

// tryLock takes the exclusive lock of an owner-only lock file without
// waiting. The kernel drops it when the process dies.
func tryLock(path string) (func(), error) {
	descriptor, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("open a lock file of the agent state directory")
	}
	lock := os.NewFile(uintptr(descriptor), path)
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.Join(errors.New("a lock file of the agent state directory is not an owner-only regular file"),
			lock.Close())
	}
	if err := unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.Join(errLockHeld, lock.Close())
	}
	return func() {
		_ = unix.Flock(descriptor, unix.LOCK_UN)
		_ = lock.Close()
	}, nil
}
