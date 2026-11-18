//go:build linux

package buyerconfirm

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// A pipe on standard input is refused by the real check.
func TestOpenTerminalRefusesAPipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if tty, err := OpenTerminal(reader); !errors.Is(err, ErrNotATerminal) {
		if tty != nil {
			tty.Close()
		}
		t.Fatalf("a pipe was accepted as the confirmer's terminal: %v", err)
	}
}

// A pseudo-terminal this process opened is a terminal, but not this
// process's controlling terminal, so it is refused like a terminal a
// developer-account program allocated.
func TestOpenTerminalRefusesAPseudoTerminalItDidNotLogInOn(t *testing.T) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminals here: %v", err)
	}
	defer master.Close()
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer slave.Close()
	tty, err := OpenTerminal(slave)
	if tty != nil {
		tty.Close()
	}
	if !errors.Is(err, ErrNoControlling) && !errors.Is(err, ErrStdinNotTerminal) {
		t.Fatalf("a pseudo-terminal that is not the controlling terminal: %v", err)
	}
}
