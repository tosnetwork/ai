package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

func TestExitCodes(t *testing.T) {
	for name, test := range map[string]struct {
		err  error
		code int
	}{
		"done":                    {nil, exitDone},
		"a failure":               {errors.New("failed"), exitFailed},
		"refused arguments":       {usagef("refused"), exitUsage},
		"wrapped refusal":         {fmt.Errorf("init: %w", usagef("refused")), exitUsage},
		"not ready":               {errNotReady, exitNotReady},
		"a preview":               {servicebridge.ErrConfirmationRequired, exitNotConfirmed},
		"a wrapped preview":       {fmt.Errorf("offer: %w", servicebridge.ErrConfirmationRequired), exitNotConfirmed},
		"a preview joined a fail": {errors.Join(servicebridge.ErrConfirmationRequired, errors.New("print")), exitNotConfirmed},
		"a pending withdrawal":    {servicebridge.ErrWithdrawalPending, exitFailed},
	} {
		if got := exitCode(test.err); got != test.code {
			t.Errorf("%s: exit %d, want %d", name, got, test.code)
		}
	}
}

// This program carries rail packets over direct sockets and relays only. A
// configuration that has a chat section, or names the fallback packet
// socket, is refused by every command that reads it, with the library's
// errors, and nothing is changed.
func TestAConfigurationOfAnotherCarrierIsRefused(t *testing.T) {
	for name, test := range map[string]struct {
		edit func(document map[string]any)
		want error
	}{
		"a chat section": {func(document map[string]any) {
			document["chat"] = map[string]any{"messenger_carrier_socket": "/run/messenger/carrier.sock"}
		}, servicebridge.ErrNoRelayLane},
		"the fallback packet socket": {func(document map[string]any) {
			document["messenger_socket"] = "/run/messenger/packets.sock"
		}, servicebridge.ErrNoFallbackTransport},
	} {
		rail, state := providerDirectory(t, test.edit)
		before, err := os.ReadFile(rail)
		if err != nil {
			t.Fatal(err)
		}
		for _, arguments := range [][]string{
			{"serve"}, {"status", "--offline"}, {"status"}, {"pause"}, {"resume"},
			// The executor socket is named so that the command, were it not
			// refused, would not ask the host's own executor service.
			{"offer", "--price", "0.1", "--storage-fee", "0.2", "--cleanup-bounty", "0.1", "--response-sla", "3600",
				"--refund-claim-window", "3600", "--executor-socket", filepath.Join(state, "absent.sock")},
			{"withdraw", "--all"}, {"withdraw", "--all", "--yes"},
			{"withdraw", "--acknowledge", "7", "--note", "checked", "--yes"},
			{"init", "--state-dir", state, "--rpc", "http://127.0.0.1:1", "--rpc", "http://127.0.0.1:2",
				"--rpc", "http://127.0.0.1:3", "--global-config", filepath.Join(state, "global.json"),
				"--network-label", "tos:global-id:7", "--tosctl", filepath.Join(state, "tosctl"),
				"--tosctl-config", filepath.Join(state, "tosctl.json"), "--wallet", "provider",
				"--registry-code-boc", filepath.Join(state, "registry.boc"), "--actor-code-hash", fixtureCodeHash,
				"--yes"},
		} {
			arguments = append([]string{arguments[0], "--rail-config", rail}, arguments[1:]...)
			stdout, stderr, code := invoke(t, arguments...)
			if code != exitFailed || !strings.Contains(stderr, test.want.Error()) || stdout != "" {
				t.Errorf("%s: %v: exit %d, stdout %q, stderr %q", name, arguments, code, stdout, stderr)
			}
		}
		// The readiness report says the same in its own form.
		stdout, _, code := invoke(t, "preflight", "--rail-config", rail)
		if code != exitNotReady || !strings.Contains(stdout, strings.TrimPrefix(test.want.Error(), "servicebridge: ")) {
			t.Errorf("%s: preflight: exit %d: %s", name, code, stdout)
		}
		if pause, err := servicebridge.ReadAdmissionPause(state); err != nil || pause != nil {
			t.Errorf("%s: a refused pause left a marker: %+v %v", name, pause, err)
		}
		if after, err := os.ReadFile(rail); err != nil || !bytes.Equal(before, after) {
			t.Errorf("%s: the configuration changed: %v", name, err)
		}
	}
}

func TestCommandsNeedAProviderSection(t *testing.T) {
	rail, _ := providerDirectory(t, func(document map[string]any) { delete(document, "provider") })
	for _, verb := range []string{"serve", "status", "pause", "resume"} {
		stdout, stderr, code := invoke(t, verb, "--rail-config", rail)
		if code != exitFailed || !strings.Contains(stderr, "no provider section") || stdout != "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", verb, code, stdout, stderr)
		}
	}
}

// A provider directory that the earlier runtime's `earning service init`,
// `offer` and `serve` wrote is operated by this program as it is: the same
// --rail-config file, the same state directory, the same records.
func TestAnExistingProviderDirectoryWorksUnchanged(t *testing.T) {
	rail, state := providerDirectory(t, nil)
	before, err := os.ReadFile(rail)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(before, []byte(`"packet_controller": "openfox-packet"`)) {
		t.Fatal("the fixture is not a configuration of the earlier runtime")
	}
	stdout, stderr, code := invoke(t, "status", "--rail-config", rail, "--offline")
	var status servicebridge.ProviderStatus
	if err := json.Unmarshal([]byte(stdout), &status); err != nil || code != exitDone {
		t.Fatalf("status: exit %d, %v: %s%s", code, err, stdout, stderr)
	}
	if len(status.Requests) != 1 || status.Requests[0].RequestHash != strings.Repeat("9", 64) ||
		status.Admission.Paused {
		t.Fatalf("status does not show the stored request: %+v", status)
	}
	if _, stderr, code := invoke(t, "pause", "--rail-config", rail); code != exitDone {
		t.Fatalf("pause: exit %d: %s", code, stderr)
	}
	stdout, _, _ = invoke(t, "status", "--rail-config", rail, "--offline")
	status = servicebridge.ProviderStatus{}
	if err := json.Unmarshal([]byte(stdout), &status); err != nil || !status.Admission.Paused {
		t.Fatalf("status after pause: %v: %s", err, stdout)
	}
	if _, stderr, code := invoke(t, "resume", "--rail-config", rail); code != exitDone {
		t.Fatalf("resume: exit %d: %s", code, stderr)
	}
	// Preflight reads the configuration and the state directory as they
	// are; what fails is only what this fixture does not have (a tosctl, a
	// chain, an executor).
	stdout, _, code = invoke(t, "preflight", "--rail-config", rail)
	var report servicebridge.PreflightReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil || code != exitNotReady {
		t.Fatalf("preflight: exit %d, %v: %s", code, err, stdout)
	}
	passed := map[string]bool{}
	for _, check := range report.Checks {
		passed[check.ID] = check.Status == servicebridge.CheckPass
	}
	for _, id := range []string{"config.parse", "state_dir.private", "admission.pause", "manifest.local"} {
		if !passed[id] {
			t.Errorf("preflight check %s did not pass: %s", id, stdout)
		}
	}
	// serve accepts the configuration and stops at the first thing the
	// fixture lacks, the registry code file.
	stdout, stderr, code = invoke(t, "serve", "--rail-config", rail)
	if code != exitFailed || !strings.Contains(stderr, "read the Native Registry code BOC") || stdout != "" {
		t.Fatalf("serve: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	// A re-run of init continues with the packet controller the directory
	// was made with.
	if got, err := packetController(rail, state); err != nil || got != "openfox-packet" {
		t.Fatalf("init would use packet controller %q: %v", got, err)
	}
	if after, err := os.ReadFile(rail); err != nil || !bytes.Equal(before, after) {
		t.Fatalf("the configuration changed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(state, "provider", strings.Repeat("9", 64)+".json")); err != nil {
		t.Fatalf("the stored request is gone: %v", err)
	}
}

// No message of a command names another program's command line.
func TestMessagesNameThisProgram(t *testing.T) {
	rail, _ := providerDirectory(t, nil)
	if _, _, code := invoke(t, "pause", "--rail-config", rail); code != exitDone {
		t.Fatal("pause failed")
	}
	absent := filepath.Join(t.TempDir(), "absent.json")
	var all strings.Builder
	for _, arguments := range [][]string{
		{"preflight", "--rail-config", rail}, {"preflight", "--rail-config", absent},
		{"status", "--rail-config", rail, "--offline"}, {"withdraw", "--rail-config", absent, "--all"},
		{"offer", "--rail-config", absent, "--price", "0.1", "--storage-fee", "0.2", "--cleanup-bounty", "0.1",
			"--response-sla", "3600", "--refund-claim-window", "3600"},
		{"help"}, {"init", "-h"}, {"offer", "-h"}, {"serve", "-h"}, {"withdraw", "-h"},
	} {
		stdout, stderr, _ := invoke(t, arguments...)
		all.WriteString(stdout)
		all.WriteString(stderr)
	}
	text := all.String()
	if !strings.Contains(text, "`"+programName+" resume`") || !strings.Contains(text, "`"+programName+" init`") {
		t.Fatalf("the hints do not name this program:\n%s", text)
	}
	for _, other := range []string{"earning service", "OpenFox"} {
		if strings.Contains(text, other) {
			t.Errorf("a message names %q:\n%s", other, text)
		}
	}
}

// binary builds the program for a test that runs it as a process.
func binary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), programName)
	if output, err := exec.Command("go", "build", "-o", path, ".").CombinedOutput(); err != nil {
		t.Fatalf("build the program: %v: %s", err, output)
	}
	return path
}

// The process itself ends with the documented exit codes, prints JSON only
// on standard output and never prints the vault URL it was started with.
func TestTheProcessExitCodesAndOutput(t *testing.T) {
	program := binary(t)
	rail, _ := providerDirectory(t, nil)
	absent := filepath.Join(t.TempDir(), "absent.json")
	const secret = "file:///vault?master_key=0123456789abcdef0123456789abcdef"
	for name, test := range map[string]struct {
		arguments []string
		code      int
		json      bool
	}{
		"no command":               {nil, exitUsage, false},
		"an unknown command":       {[]string{"sell"}, exitUsage, false},
		"help":                     {[]string{"help"}, exitDone, false},
		"pause":                    {[]string{"pause", "--rail-config", rail}, exitDone, true},
		"status":                   {[]string{"status", "--rail-config", rail}, exitDone, true},
		"resume":                   {[]string{"resume", "--rail-config", rail}, exitDone, true},
		"a preflight that fails":   {[]string{"preflight", "--rail-config", rail}, exitNotReady, true},
		"a withdrawal that fails":  {[]string{"withdraw", "--rail-config", absent, "--all"}, exitFailed, true},
		"a withdrawal of nothing":  {[]string{"withdraw", "--rail-config", rail, "--amount", "0"}, exitUsage, false},
		"serve without a registry": {[]string{"serve", "--rail-config", rail}, exitFailed, false},
		"serve without a file":     {[]string{"serve", "--rail-config", absent}, exitFailed, false},
	} {
		command := exec.Command(program, test.arguments...)
		command.Env = append(os.Environ(), "VAULT_URL="+secret)
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if code != test.code {
			t.Errorf("%s: exit %d, want %d: %s", name, code, test.code, stderr.String())
		}
		if test.json && !json.Valid(stdout.Bytes()) {
			t.Errorf("%s: standard output is not JSON: %q", name, stdout.String())
		}
		if !test.json && name != "help" && stdout.Len() != 0 {
			t.Errorf("%s: standard output is not empty: %q", name, stdout.String())
		}
		if code != exitDone && !strings.HasPrefix(stderr.String(), programName+": ") &&
			!strings.Contains(stderr.String(), "\n"+programName+": ") {
			t.Errorf("%s: the failure is not reported on standard error: %q", name, stderr.String())
		}
		for _, output := range []string{stdout.String(), stderr.String()} {
			if strings.Contains(output, "master_key") || strings.Contains(output, secret) {
				t.Errorf("%s: the vault URL was printed: %q", name, output)
			}
		}
	}
}
