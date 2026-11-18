package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/buyerinit"
)

func TestInitCommandRefusesBeforeRunningTOSCTL(t *testing.T) {
	var out bytes.Buffer
	for name, arguments := range map[string][]string{
		"no mode":      {"init"},
		"another mode": {"init", "send"},
		"a positional": {"init", "plan", "extra"},
	} {
		if err := run(arguments, &out); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := run([]string{"init", "plan", "--yes"}, &out); err == nil ||
		!strings.Contains(err.Error(), "--yes applies to init apply only") {
		t.Fatalf("--yes in a plan: %v", err)
	}
	// A uid that would truncate to another account is refused as such.
	if err := run([]string{"init", "plan", "--client-uid", "4294968296"}, &out); err == nil ||
		!strings.Contains(err.Error(), "--client-uid is out of range") {
		t.Fatalf("a uid wider than 31 bits: %v", err)
	}
	// As the developer account: refused before tosctl, which is absent
	// here, could even be pinned.
	own := strconv.Itoa(os.Geteuid())
	err := run([]string{"init", "apply", "--client-uid", own, "--tosctl", "/nonexistent/tosctl"}, &out)
	if !errors.Is(err, buyerinit.ErrWrongAccount) {
		t.Fatalf("init as the developer account: %v", err)
	}
	if err := run([]string{"init", "plan", "--client-uid", "1", "--rpc", "https://a.example"}, &out); err == nil ||
		!strings.Contains(err.Error(), "--rpc must name 3 to 8 endpoints") {
		t.Fatalf("an invalid input reached tosctl: %v", err)
	}
}

func TestInitConfirmationIsExactlyYes(t *testing.T) {
	for answer, want := range map[string]bool{"yes\n": true, "yes": true, "yes\r\n": true, "y\n": false, "YES\n": false,
		" yes\n": false, "": false, "no\n": false} {
		var prompt bytes.Buffer
		confirmed, err := confirmOn(bufio.NewReader(strings.NewReader(answer)), &prompt)("Send it?")
		if err != nil || confirmed != want {
			t.Errorf("%q: %v %v", answer, confirmed, err)
		}
		if !strings.Contains(prompt.String(), "Send it? Type yes to send") {
			t.Errorf("prompt %q", prompt.String())
		}
	}
}
