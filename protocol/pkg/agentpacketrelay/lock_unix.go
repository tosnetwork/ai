//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package agentpacketrelay

import (
	"os"
	"syscall"
)

// lockFile takes a non-blocking exclusive advisory lock; the kernel drops it
// when the process dies, so a crash never leaves the directory locked.
func lockFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
