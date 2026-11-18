package buyerconfirm

import "errors"

// terminalFacts are what the terminal check decides on, gathered from the
// kernel by OpenTerminal. Everything describes standard input itself: the
// generic /dev/tty node is owned by root on Linux and says nothing about the
// real terminal behind it.
type terminalFacts struct {
	// StdinIsTerminal: standard input answers terminal ioctls.
	StdinIsTerminal bool
	// StdinIsCharDevice, StdinOwner and StdinDevice come from fstat of
	// standard input: the real terminal device, for example /dev/pts/N.
	StdinIsCharDevice bool
	StdinOwner        uint32
	StdinDevice       uint64
	// StdinIsControlling: the terminal's session (TIOCGSID) is this
	// process's session, so standard input is the controlling terminal of
	// the session the confirmer runs in.
	StdinIsControlling bool
	// ReopenedDevice is the device of the terminal reopened by its path for
	// the presentation and the decision; it must be standard input's.
	ReopenedDevice uint64
	// EffectiveUID is the confirmer's own uid, the custody account.
	EffectiveUID uint32
}

// Terminal refusals.
var (
	ErrNotATerminal    = errors.New("the confirmer reads decisions only from a terminal, never from a pipe or file")
	ErrNoControlling   = errors.New("standard input is not the controlling terminal of the confirmer's session")
	ErrForeignTerminal = errors.New("the confirmer's terminal is not owned by the custody account; open it from a separate login of that account")
	ErrTerminalChanged = errors.New("the terminal reopened for the confirmer is not standard input")
)

// checkTerminal applies section 5.1: standard input is a terminal device,
// it is the controlling terminal of the confirmer's own session, it is owned
// by the custody account, and the terminal reopened for reading and writing
// is that same device. A pseudo-terminal that a developer-account terminal
// emulator, multiplexer or `script` allocated is owned by the developer
// account, so this refuses the common ways a developer-account process
// could type into the confirmer.
func checkTerminal(facts terminalFacts) error {
	switch {
	case !facts.StdinIsTerminal:
		return ErrNotATerminal
	case !facts.StdinIsCharDevice:
		return ErrNotATerminal
	case !facts.StdinIsControlling:
		return ErrNoControlling
	case facts.StdinOwner != facts.EffectiveUID:
		return ErrForeignTerminal
	case facts.ReopenedDevice != facts.StdinDevice:
		return ErrTerminalChanged
	}
	return nil
}
