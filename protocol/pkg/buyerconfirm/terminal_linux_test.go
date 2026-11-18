//go:build linux

package buyerconfirm

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// childEnvironment marks the re-executed test binary that runs
// OpenTerminal on a pseudo-terminal the parent set up.
const childEnvironment = "BUYERCONFIRM_TERMINAL_CHILD"

// TestTerminalChild is not a test of its own. The terminal tests run it in
// a child process whose session and standard input they arrange, and it
// reports OpenTerminal's answer on descriptor 3.
func TestTerminalChild(t *testing.T) {
	if os.Getenv(childEnvironment) != "1" {
		t.Skip("runs only as the child of the terminal tests")
	}
	report := os.NewFile(3, "report")
	defer report.Close()
	tty, err := OpenTerminal(os.Stdin)
	if err != nil {
		fmt.Fprint(report, "refused: "+err.Error())
		return
	}
	defer tty.Close()
	if _, err := fmt.Fprint(tty, "presentation\n"); err != nil {
		fmt.Fprint(report, "write failed: "+err.Error())
		return
	}
	fmt.Fprint(report, "accepted")
}

// openPseudoTerminal returns a fresh pseudo-terminal pair owned by this
// account.
func openPseudoTerminal(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminals here: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		master.Close()
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		t.Fatal(err)
	}
	return master, slave
}

// runChild runs TestTerminalChild with a fresh pseudo-terminal as standard
// input, output and error, in a new session that takes the terminal as its
// controlling terminal when controlling is true. It returns the child's
// report.
func runChild(t *testing.T, controlling bool) string {
	t.Helper()
	master, slave := openPseudoTerminal(t)
	defer master.Close()
	reportReader, reportWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reportReader.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestTerminalChild$", "-test.count=1")
	child.Env = append(os.Environ(), childEnvironment+"=1")
	child.Stdin, child.Stdout, child.Stderr = slave, slave, slave
	child.ExtraFiles = []*os.File{reportWriter}
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: controlling, Ctty: 0}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	slave.Close()
	reportWriter.Close()
	// The child's terminal output goes to the master; drain it so the
	// child never blocks on a full terminal buffer.
	go io.Copy(io.Discard, master)
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		child.Process.Kill()
		t.Fatal("the terminal child did not finish")
	}
	var report bytes.Buffer
	if _, err := io.Copy(&report, reportReader); err != nil {
		t.Fatal(err)
	}
	return report.String()
}

// The controlling terminal of the confirmer's own session, owned by its own
// account, is accepted, and the presentation can be written to it. This is
// the deployment the spec requires: a separate login of the custody
// account.
func TestOpenTerminalAcceptsTheControllingTerminalOfItsOwnSession(t *testing.T) {
	if report := runChild(t, true); report != "accepted" {
		t.Fatalf("a custody-owned controlling terminal was refused: %q", report)
	}
}

// The same terminal, held by a process in a session it does not control,
// is refused: it is not the confirmer's controlling terminal.
func TestOpenTerminalRefusesATerminalThatIsNotTheSessionsOwn(t *testing.T) {
	report := runChild(t, false)
	if !strings.HasPrefix(report, "refused: ") || !strings.Contains(report, ErrNoControlling.Error()) {
		t.Fatalf("a terminal outside the session: %q", report)
	}
}

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
	// /dev/null is a character device but no terminal: only the terminal
	// probe refuses it as one.
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if tty, err := OpenTerminal(null); !errors.Is(err, ErrNotATerminal) {
		if tty != nil {
			tty.Close()
		}
		t.Fatalf("%s was taken for a terminal: %v", os.DevNull, err)
	}
}
