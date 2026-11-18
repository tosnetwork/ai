//go:build linux

package buyerconfirm

import (
	"os"

	"golang.org/x/sys/unix"
)

// OpenTerminal checks the confirmer's terminal (section 5.1) and returns
// the controlling terminal, opened for reading the decision and writing
// the presentation. Nothing is read from anywhere else.
func OpenTerminal(stdin *os.File) (*os.File, error) {
	facts := terminalFacts{EffectiveUID: uint32(os.Geteuid())}
	if _, err := unix.IoctlGetTermios(int(stdin.Fd()), unix.TCGETS); err == nil {
		facts.StdinIsTerminal = true
	}
	var stdinStat unix.Stat_t
	if err := unix.Fstat(int(stdin.Fd()), &stdinStat); err == nil {
		facts.StdinDevice = stdinStat.Rdev
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		facts.HasControllingTerminal = true
		var ttyStat unix.Stat_t
		if err := unix.Fstat(int(tty.Fd()), &ttyStat); err == nil {
			facts.ControllingIsCharDevice = ttyStat.Mode&unix.S_IFMT == unix.S_IFCHR
			facts.ControllingOwner = ttyStat.Uid
			facts.ControllingDevice = ttyStat.Rdev
		}
	}
	if err := checkTerminal(facts); err != nil {
		if tty != nil {
			tty.Close()
		}
		return nil, err
	}
	return tty, nil
}
