package buyerconfirm

import "errors"

// terminalFacts are what the terminal check decides on, gathered from the
// kernel by openTerminal.
type terminalFacts struct {
	// StdinIsTerminal: standard input answers terminal ioctls.
	StdinIsTerminal bool
	// HasControllingTerminal: /dev/tty opened, so the process has one.
	HasControllingTerminal bool
	// ControllingIsCharDevice and ControllingOwner describe /dev/tty.
	ControllingIsCharDevice bool
	ControllingOwner        uint32
	// StdinDevice and ControllingDevice are the device numbers of
	// standard input and of the controlling terminal.
	StdinDevice       uint64
	ControllingDevice uint64
	// EffectiveUID is the confirmer's own uid, the custody account.
	EffectiveUID uint32
}

// Terminal refusals.
var (
	ErrNotATerminal     = errors.New("the confirmer reads decisions only from a terminal, never from a pipe or file")
	ErrNoControlling    = errors.New("the confirmer needs a controlling terminal")
	ErrForeignTerminal  = errors.New("the confirmer's terminal is not owned by the custody account; open it from a separate login of that account")
	ErrStdinNotTerminal = errors.New("standard input is not the confirmer's controlling terminal")
)

// checkTerminal applies section 5.1: standard input is a terminal, the
// process has a controlling terminal, that terminal is owned by the
// custody account, and standard input is that terminal. A pseudo-terminal
// that a developer-account terminal emulator, multiplexer or `script`
// allocated is owned by the developer account, so this refuses the common
// ways a developer-account process could type into the confirmer.
func checkTerminal(facts terminalFacts) error {
	switch {
	case !facts.StdinIsTerminal:
		return ErrNotATerminal
	case !facts.HasControllingTerminal || !facts.ControllingIsCharDevice:
		return ErrNoControlling
	case facts.ControllingOwner != facts.EffectiveUID:
		return ErrForeignTerminal
	case facts.StdinDevice != facts.ControllingDevice:
		return ErrStdinNotTerminal
	}
	return nil
}
