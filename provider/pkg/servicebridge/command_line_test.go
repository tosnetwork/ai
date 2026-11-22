package servicebridge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// useCommandLine sets the command line for one test and restores the
// default afterwards.
func useCommandLine(t *testing.T, value CommandLine) {
	t.Helper()
	if err := SetCommandLine(value); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := SetCommandLine(DefaultCommandLine()); err != nil {
			t.Fatal(err)
		}
	})
}

func checkMessage(t *testing.T, checks map[string]PreflightCheck, id, want string) {
	t.Helper()
	if !strings.Contains(checks[id].Message, want) {
		t.Errorf("%s does not say %q: %q", id, want, checks[id].Message)
	}
}

// pausedWithoutManifest runs the preflight of a paused node whose manifest
// file is gone: the two checks whose messages name a command.
func pausedWithoutManifest(t *testing.T) map[string]PreflightCheck {
	t.Helper()
	f := newPreflightFixture(t)
	if _, _, err := PauseAdmission(f.config.StateDir, "", pfChainNow); err != nil {
		t.Fatal(err)
	}
	f.config.Provider.ManifestFile += ".absent"
	_, checks := f.run(t)
	return checks
}

// Until a program names itself, every message reads as it always did.
func TestTheDefaultCommandLineKeepsTheEarlierText(t *testing.T) {
	if got := currentCommandLine(); got != DefaultCommandLine() || got.Service != "openfox earning service" ||
		got.Buy != "openfox earning service buy" || got.Program != "OpenFox" || got.Scratch != "openfox" {
		t.Fatalf("default command line: %+v", got)
	}
	checks := pausedWithoutManifest(t)
	checkMessage(t, checks, "admission.pause", "run `openfox earning service resume` to admit again")
	checkMessage(t, checks, "manifest.local", "build it with `openfox earning service manifest`")

	failure := &TOSCTLError{Label: "wallet ls", Status: "exit status 1", Reason: TOSCTLFailureUnsafeDirectory}
	if want := "servicebridge: tosctl wallet ls failed: exit status 1 (" + string(TOSCTLFailureUnsafeDirectory) +
		")"; failure.Error() != want || !strings.Contains(want, "the user running OpenFox or by root") {
		t.Fatalf("unsafe directory failure:\n got %q\nwant %q", failure.Error(), want)
	}
	other := &TOSCTLError{Label: "wallet send", Status: "exit status 1", Reason: TOSCTLFailureBalance}
	if !strings.HasSuffix(other.Error(), "("+string(TOSCTLFailureBalance)+")") {
		t.Fatalf("another failure class changed: %q", other.Error())
	}

	// init: both next steps, and the transport hint of a program that
	// registered a fallback transport, as the tests' program has.
	f := newSetupFixture(t)
	f.init.MessengerSocket = ""
	result := f.mustInit(t)
	steps := strings.Join(result.NextSteps, "\n")
	for _, want := range []string{
		"add a packet transport: run init again with --direct-peer agent_<hex>=<socket> (the peer's Agent id " +
			"and receiver socket), --relay-url <https URL> or --messenger-socket <socket>",
		"provider: openfox earning service offer --rail-config " + f.init.RailConfigPath + " --price <TOS> ...",
		"buyer: openfox earning service buy --rail-config " + f.init.RailConfigPath +
			" --offer <file> --source <archive>",
	} {
		if !strings.Contains(steps, want) {
			t.Errorf("init next steps lack %q:\n%s", want, steps)
		}
	}
	note := ""
	for _, step := range result.Steps {
		if step.ID == "transport" {
			note = step.Detail
		}
	}
	if want := "no packet transport is configured: serve and buy refuse to start until this command is run " +
		"again with --direct-peer, --relay-url or --messenger-socket"; note != want {
		t.Errorf("transport note:\n got %q\nwant %q", note, want)
	}

	// offer: the two hints that send the owner back to init, and the next
	// steps of a finished offer.
	if _, err := RunOffer(t.Context(), OfferInput{RailConfigPath: f.init.RailConfigPath + ".absent"},
		SetupEnv{}); err == nil || !strings.HasSuffix(err.Error(), "; run `openfox earning service init` first") {
		t.Errorf("offer without a configuration: %v", err)
	}
	f.init.MessengerSocket = "/run/messenger/packets.sock"
	f.mustInit(t)
	offered := f.mustOffer(t)
	if len(offered.NextSteps) != 2 ||
		offered.NextSteps[0] != "openfox earning service preflight --rail-config "+f.init.RailConfigPath ||
		offered.NextSteps[1] != "openfox earning service serve --rail-config "+f.init.RailConfigPath {
		t.Errorf("offer next steps: %q", offered.NextSteps)
	}
}

// A program that names itself is named in every one of those messages, and
// no schema name moves with it.
func TestAProgramNamesItsOwnCommandLine(t *testing.T) {
	useCommandLine(t, CommandLine{Service: "rail-node", Program: "rail-node", Scratch: "rail-node"})
	withoutExtensions(t)
	checks := pausedWithoutManifest(t)
	checkMessage(t, checks, "admission.pause", "run `rail-node resume` to admit again")
	checkMessage(t, checks, "manifest.local", "build it with `rail-node manifest`")

	failure := &TOSCTLError{Label: "wallet ls", Status: "exit status 1", Reason: TOSCTLFailureUnsafeDirectory}
	if !strings.Contains(failure.Error(), "owned by the user running rail-node or by root") ||
		strings.Contains(failure.Error(), "OpenFox") {
		t.Fatalf("unsafe directory failure: %q", failure.Error())
	}
	// The class is still the fixed value failures are compared by.
	if tosctlFailure(failure) != TOSCTLFailureUnsafeDirectory {
		t.Fatal("the failure class changed with the command line")
	}

	f := newSetupFixture(t)
	f.init.MessengerSocket = ""
	result := f.mustInit(t)
	steps := strings.Join(result.NextSteps, "\n")
	if want := "add a packet transport: run init again with --direct-peer agent_<hex>=<socket> (the peer's Agent " +
		"id and receiver socket) or --relay-url <https URL>\nprovider: rail-node offer --rail-config " +
		f.init.RailConfigPath + " --price <TOS> ..."; steps != want {
		t.Errorf("init next steps:\n got %q\nwant %q", steps, want)
	}
	for _, step := range result.Steps {
		if step.ID == "transport" && !strings.HasSuffix(step.Detail, "again with --direct-peer or --relay-url") {
			t.Errorf("transport note: %q", step.Detail)
		}
	}
	if result.Schema != "tos.openfox.rail-init.v1" || PreflightSchema != "tos.openfox.provider-preflight" {
		t.Fatal("a schema name moved with the command line")
	}
	if _, err := RunOffer(t.Context(), OfferInput{RailConfigPath: f.init.RailConfigPath + ".absent"},
		SetupEnv{}); err == nil || !strings.HasSuffix(err.Error(), "; run `rail-node init` first") {
		t.Errorf("offer without a configuration: %v", err)
	}

	// A program with a buy command of its own is named in the buyer step.
	useCommandLine(t, CommandLine{Service: "rail-node", Buy: "rail-buyer buy", Program: "Rail", Scratch: "rail"})
	again := f.mustInit(t)
	if steps := strings.Join(again.NextSteps, "\n"); !strings.Contains(steps,
		"buyer: rail-buyer buy --rail-config "+f.init.RailConfigPath+" --offer <file> --source <archive>") {
		t.Errorf("init next steps lack the buyer step: %s", steps)
	}
}

// The remaining messages that name a command do so under a program's own
// command line too: the hint of an unreadable pause marker, the hint of a
// configuration that lacks what init records, and both offer next steps.
func TestTheOtherCommandHintsNameTheProgram(t *testing.T) {
	useCommandLine(t, CommandLine{Service: "rail-node", Program: "rail-node", Scratch: "rail-node"})

	pf := newPreflightFixture(t)
	writeFixtureFile(t, filepath.Join(pf.config.StateDir, AdmissionPauseFile), []byte("not a pause marker"), 0o600)
	_, checks := pf.run(t)
	checkMessage(t, checks, "admission.pause", "the node treats it as paused: remove it with `rail-node resume`")

	f := newSetupFixture(t)
	f.mustInit(t)
	original, err := os.ReadFile(f.init.RailConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err = json.Unmarshal(original, &config); err != nil {
		t.Fatal(err)
	}
	config["agent_id"] = ""
	stripped, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, f.init.RailConfigPath, stripped, 0o600)
	if _, err = RunOffer(t.Context(), f.offer, f.env()); err == nil || !strings.HasSuffix(err.Error(),
		"lacks the Agent, wallet address or chain global configuration `init` records; run `rail-node init` first") {
		t.Errorf("offer under a configuration without the Agent: %v", err)
	}

	writeFixtureFile(t, f.init.RailConfigPath, original, 0o600)
	offered := f.mustOffer(t)
	if len(offered.NextSteps) != 2 ||
		offered.NextSteps[0] != "rail-node preflight --rail-config "+f.init.RailConfigPath ||
		offered.NextSteps[1] != "rail-node serve --rail-config "+f.init.RailConfigPath {
		t.Errorf("offer next steps: %q", offered.NextSteps)
	}
}

func TestSetCommandLineRefusesTextThatCouldBreakAMessageOrAFileName(t *testing.T) {
	good := CommandLine{Service: "rail-node", Buy: "rail-node buy", Program: "Rail Node", Scratch: "rail-node"}
	for name, change := range map[string]func(*CommandLine){
		"an empty service":             func(c *CommandLine) { c.Service = "" },
		"an empty program":             func(c *CommandLine) { c.Program = "" },
		"an empty scratch prefix":      func(c *CommandLine) { c.Scratch = "" },
		"a service over the bound":     func(c *CommandLine) { c.Service = strings.Repeat("a", 65) },
		"a program over the bound":     func(c *CommandLine) { c.Program = strings.Repeat("a", 65) },
		"a buy command over the bound": func(c *CommandLine) { c.Buy = strings.Repeat("a", 65) },
		"a scratch prefix over bound":  func(c *CommandLine) { c.Scratch = strings.Repeat("a", 33) },
		"a backtick":                   func(c *CommandLine) { c.Service = "rail`node" },
		"a line break":                 func(c *CommandLine) { c.Program = "rail\nnode" },
		"a leading space":              func(c *CommandLine) { c.Service = " rail-node" },
		"a leading hyphen":             func(c *CommandLine) { c.Buy = "-rail" },
		"a path in the scratch":        func(c *CommandLine) { c.Scratch = "../rail" },
		"an upper case scratch":        func(c *CommandLine) { c.Scratch = "Rail" },
		"a scratch pattern character":  func(c *CommandLine) { c.Scratch = "rail*" },
		"a non-ASCII program":          func(c *CommandLine) { c.Program = "ráil" },
	} {
		value := good
		change(&value)
		if err := SetCommandLine(value); err == nil {
			t.Errorf("%s was accepted", name)
		}
		if currentCommandLine() != DefaultCommandLine() {
			t.Fatalf("%s changed the command line", name)
		}
	}
	useCommandLine(t, good)
	if currentCommandLine() != good {
		t.Fatal("a well-formed command line was not set")
	}
	longest := CommandLine{
		Service: strings.Repeat("a", 64), Program: strings.Repeat("b", 64), Scratch: strings.Repeat("c", 32),
	}
	if err := SetCommandLine(longest); err != nil || serviceCommand("init") != strings.Repeat("a", 64)+" init" {
		t.Fatalf("the longest command line: %v", err)
	}
}

// The preflight scratch directory carries the program's prefix.
func TestThePreflightScratchDirectoryCarriesTheProgramsPrefix(t *testing.T) {
	for _, prefix := range []string{"openfox", "rail-node"} {
		if prefix != "openfox" {
			useCommandLine(t, CommandLine{Service: "rail-node", Program: "rail-node", Scratch: prefix})
		}
		f := newPreflightFixture(t)
		open, opened := f.env.OpenChain, ""
		f.env.OpenChain = func(config NodeConfig, checkpointDir string) (PreflightChain, error) {
			opened = checkpointDir
			return open(config, checkpointDir)
		}
		f.run(t)
		if !strings.HasPrefix(filepath.Base(opened), prefix+"-preflight-") {
			t.Errorf("the scratch directory of %q is %q", prefix, opened)
		}
	}
}
