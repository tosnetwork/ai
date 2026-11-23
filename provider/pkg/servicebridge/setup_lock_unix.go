//go:build !windows

package servicebridge

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// acquireRunLock takes the exclusive lock of an owner-only lock file without
// waiting. busy is returned when another open of the file holds it, in this
// process or another.
func acquireRunLock(path string, busy error) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("servicebridge: open a state directory lock file")
	}
	lock := os.NewFile(uintptr(descriptor), path)
	if info, statErr := lock.Stat(); lockFileProblem(info, statErr) {
		_ = lock.Close()
		return nil, errors.New("servicebridge: a state directory lock file is not an owner-only regular file")
	}
	if err := unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, busy
	}
	return lock, nil
}

func releaseRunLock(lock *os.File) {
	_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	_ = lock.Close()
}
