//go:build linux

package buyerconfirm

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// OpenTerminal checks the confirmer's terminal (section 5.1) and returns it,
// reopened by its own path for reading the decision and writing the
// presentation. Nothing is read from anywhere else.
func OpenTerminal(stdin *os.File) (*os.File, error) {
	fd := int(stdin.Fd())
	facts := terminalFacts{EffectiveUID: uint32(os.Geteuid())}
	if _, err := unix.IoctlGetTermios(fd, unix.TCGETS); err == nil {
		facts.StdinIsTerminal = true
	}
	var stdinStat unix.Stat_t
	if err := unix.Fstat(fd, &stdinStat); err == nil {
		facts.StdinIsCharDevice = stdinStat.Mode&unix.S_IFMT == unix.S_IFCHR
		facts.StdinOwner = stdinStat.Uid
		facts.StdinDevice = stdinStat.Rdev
	}
	terminalSession, sessionErr := unix.IoctlGetInt(fd, unix.TIOCGSID)
	ownSession, ownErr := unix.Getsid(0)
	facts.StdinIsControlling = sessionErr == nil && ownErr == nil && terminalSession == ownSession
	var reopened *os.File
	if facts.StdinIsTerminal && facts.StdinIsCharDevice {
		// The path names the device standard input holds, for example
		// /dev/pts/N; O_NOCTTY keeps the open from changing the session.
		file, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", fd), os.O_RDWR|unix.O_NOCTTY, 0)
		if err == nil {
			var reopenedStat unix.Stat_t
			if unix.Fstat(int(file.Fd()), &reopenedStat) == nil {
				facts.ReopenedDevice = reopenedStat.Rdev
			}
			reopened = file
		}
	}
	if err := checkTerminal(facts); err != nil {
		if reopened != nil {
			reopened.Close()
		}
		return nil, err
	}
	return reopened, nil
}
