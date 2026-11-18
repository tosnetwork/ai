package buyerconfirm

import (
	"errors"
	"testing"
)

// The terminal rules of section 5.1, one failure at a time.
func TestTheTerminalCheckRefusesEveryUnsafeChannel(t *testing.T) {
	good := terminalFacts{StdinIsTerminal: true, HasControllingTerminal: true, ControllingIsCharDevice: true,
		ControllingOwner: 1001, StdinDevice: 0x8801, ControllingDevice: 0x8801, EffectiveUID: 1001}
	if err := checkTerminal(good); err != nil {
		t.Fatalf("a custody-owned controlling terminal was refused: %v", err)
	}
	cases := map[string]struct {
		edit func(*terminalFacts)
		want error
	}{
		"a pipe or file on stdin":   {func(f *terminalFacts) { f.StdinIsTerminal = false }, ErrNotATerminal},
		"no controlling terminal":   {func(f *terminalFacts) { f.HasControllingTerminal = false }, ErrNoControlling},
		"a controlling non-device":  {func(f *terminalFacts) { f.ControllingIsCharDevice = false }, ErrNoControlling},
		"a developer-owned pty":     {func(f *terminalFacts) { f.ControllingOwner = 1000 }, ErrForeignTerminal},
		"stdin from another tty":    {func(f *terminalFacts) { f.StdinDevice = 0x8802 }, ErrStdinNotTerminal},
		"a root-owned terminal":     {func(f *terminalFacts) { f.ControllingOwner = 0 }, ErrForeignTerminal},
		"the developer's own login": {func(f *terminalFacts) { f.EffectiveUID = 1000 }, ErrForeignTerminal},
	}
	for name, c := range cases {
		facts := good
		c.edit(&facts)
		if err := checkTerminal(facts); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}
