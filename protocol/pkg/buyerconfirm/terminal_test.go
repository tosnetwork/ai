package buyerconfirm

import (
	"errors"
	"testing"
)

// The terminal rules of section 5.1, one failure at a time.
func TestTheTerminalCheckRefusesEveryUnsafeChannel(t *testing.T) {
	good := terminalFacts{StdinIsTerminal: true, StdinIsCharDevice: true, StdinOwner: 1001, StdinDevice: 0x8805,
		StdinIsControlling: true, ReopenedDevice: 0x8805, EffectiveUID: 1001}
	if err := checkTerminal(good); err != nil {
		t.Fatalf("a custody-owned controlling terminal was refused: %v", err)
	}
	cases := map[string]struct {
		edit func(*terminalFacts)
		want error
	}{
		"a pipe or file on stdin":           {func(f *terminalFacts) { f.StdinIsTerminal = false }, ErrNotATerminal},
		"a terminal that is no char device": {func(f *terminalFacts) { f.StdinIsCharDevice = false }, ErrNotATerminal},
		"not the session's terminal":        {func(f *terminalFacts) { f.StdinIsControlling = false }, ErrNoControlling},
		"a developer-owned pty":             {func(f *terminalFacts) { f.StdinOwner = 1000 }, ErrForeignTerminal},
		"a root-owned terminal":             {func(f *terminalFacts) { f.StdinOwner = 0 }, ErrForeignTerminal},
		"the developer's own login":         {func(f *terminalFacts) { f.EffectiveUID = 1000 }, ErrForeignTerminal},
		"a reopened other device":           {func(f *terminalFacts) { f.ReopenedDevice = 0x8806 }, ErrTerminalChanged},
	}
	for name, c := range cases {
		facts := good
		c.edit(&facts)
		if err := checkTerminal(facts); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}
