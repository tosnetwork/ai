package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/tosnetwork/ai/execution/pkg/softwarework"
)

// unitFileEnv names the shipped unit file. Setting it, together with the
// live containerd socket, selects the test that runs the daemon under that
// file's own sandbox; like the other live tests it then fails, rather than
// skips, when it cannot run as root. collectionUnitFileEnv and
// collectionBinaryEnv name the shipped collection unit and a build of the
// command it runs; the selected test requires both.
const (
	unitFileEnv           = "TOS_AI_EXECUTORD_UNIT_FILE"
	collectionUnitFileEnv = "TOS_AI_EXECUTORD_GC_UNIT_FILE"
	collectionBinaryEnv   = "TOS_AI_EXECUTORD_GC_BINARY"
)

// unitTestOnlyKeys are the [Service] settings the test replaces with its
// own, because they name the installed service's paths or would restart a
// unit the test wants to see fail. Every other setting is applied exactly
// as shipped.
var unitTestOnlyKeys = map[string]bool{
	"ExecStart": true, "EnvironmentFile": true, "RuntimeDirectory": true, "StateDirectory": true,
	"ReadWritePaths": true, "Restart": true, "RestartSec": true,
}

// shippedProperties turns the [Service] settings of a unit file into
// systemd-run properties, leaving out only the test-local ones.
func shippedProperties(t *testing.T, unitFile string, atLeast int) []string {
	t.Helper()
	settings, err := serviceSettings(unitFile)
	if err != nil {
		t.Fatal(err)
	}
	var properties []string
	for _, setting := range settings {
		if !unitTestOnlyKeys[setting[0]] {
			properties = append(properties, "--property="+setting[0]+"="+setting[1])
		}
	}
	if len(properties) < atLeast {
		t.Fatalf("only %d settings were read from %s", len(properties), unitFile)
	}
	return properties
}

// daemonHelper runs the daemon's own entry point inside the test binary, so
// the transient unit executes the code under test.
func daemonHelper() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return run(ctx, os.Args[1:], os.Stderr)
}

// serviceSettings returns the [Service] settings of a unit file in order,
// with continuation lines joined.
func serviceSettings(path string) ([][2]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var settings [][2]string
	section, pending := "", ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if pending == "" && (line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";")) {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			pending += strings.TrimSuffix(line, "\\") + " "
			continue
		}
		line, pending = pending+line, ""
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("unit line without a value: %q", line)
		}
		if section == "[Service]" {
			settings = append(settings, [2]string{strings.TrimSpace(key), strings.TrimSpace(value)})
		}
	}
	return settings, scanner.Err()
}

func TestServiceSettingsAreReadFromTheShippedUnit(t *testing.T) {
	settings, err := serviceSettings(filepath.Join("..", "..", "deploy", "provider", "tos-service-executor.service"))
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, setting := range settings {
		values[setting[0]] = setting[1]
	}
	// The collection unit runs the existing command against the same state.
	collection, err := serviceSettings(filepath.Join("..", "..", "deploy", "provider", "tos-service-executor-gc.service"))
	if err != nil {
		t.Fatal(err)
	}
	collected := map[string]string{}
	for _, setting := range collection {
		collected[setting[0]] = setting[1]
	}
	if strings.Join(strings.Fields(collected["ExecStart"]), " ") != "/usr/local/libexec/tos-service/software-work-execute artifacts-gc --state-dir "+
		"/var/lib/tos-service-executor --limit 128" || collected["ReadWritePaths"] != "/var/lib/tos-service-executor" ||
		collected["Type"] != "oneshot" || collected["CapabilityBoundingSet"] != "" || collected["ProtectSystem"] != "strict" {
		t.Fatalf("collection unit = %+v", collected)
	}
	// The sandbox the live test must reproduce is really in the file, and
	// the command line is the one the daemon parses.
	for _, key := range []string{"CapabilityBoundingSet", "SystemCallFilter", "ProtectSystem", "PrivateNetwork",
		"RestrictAddressFamilies", "MemoryDenyWriteExecute", "RestrictNamespaces", "NoNewPrivileges", "MemoryMax",
		"TasksMax", "ProtectProc", "UMask", "Type"} {
		if values[key] == "" {
			t.Errorf("the unit has no %s", key)
		}
	}
	arguments := strings.Fields(values["ExecStart"])
	if len(arguments) < 2 || filepath.Base(arguments[0]) != "software-work-executord" {
		t.Fatalf("ExecStart = %q", values["ExecStart"])
	}
	for index, argument := range arguments {
		switch argument {
		case "${TOS_EXECUTOR_SOCKET_GID}":
			arguments[index] = "992"
		case "${TOS_EXECUTOR_ALLOWED_UID}":
			arguments[index] = "994"
		}
	}
	parsed, err := parseOptions(arguments[1:], &bytes.Buffer{})
	if err != nil {
		t.Fatalf("the unit's command line does not parse: %v", err)
	}
	if parsed.socket != "/run/tos-service-executor/executor.sock" || parsed.stateDir != "/var/lib/tos-service-executor" ||
		parsed.fifoDir != "/run/tos-service-executor-private/fifos" || parsed.allowedUID != 994 || parsed.socketGID != 992 {
		t.Fatalf("parsed = %+v", parsed)
	}
	if values["RuntimeDirectory"] != "tos-service-executor tos-service-executor-private" ||
		values["StateDirectory"] != "tos-service-executor" {
		t.Fatalf("directories = %q %q", values["RuntimeDirectory"], values["StateDirectory"])
	}
}

// TestLiveServiceUnderTheShippedUnitSandbox starts the daemon in a transient
// unit that carries every [Service] setting of the shipped unit file except
// its paths, and runs a real job through the socket as an unprivileged uid.
// A sandbox setting the code cannot live under fails here, not on a host.
func TestLiveServiceUnderTheShippedUnitSandbox(t *testing.T) {
	unitFile, containerdSocket := os.Getenv(unitFileEnv), os.Getenv(liveSocketEnv)
	if unitFile == "" || containerdSocket == "" {
		t.Skip("no unit file and private containerd are configured; run make test-privileged on a provisioned host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the unit sandbox test must run as root")
	}
	collectionUnit, collectionBinary := os.Getenv(collectionUnitFileEnv), os.Getenv(collectionBinaryEnv)
	if collectionUnit == "" || collectionBinary == "" {
		t.Fatal("the unit sandbox test needs the collection unit file and a build of its command")
	}
	name := "tos-executord-unit-test-" + strconv.Itoa(os.Getpid())
	// The binaries live where the sandboxed unit can execute them: not
	// under a home or temporary directory, which it cannot see.
	binaries := filepath.Join("/var/lib", name+"-bin")
	if err := os.Mkdir(binaries, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(binaries)
	defer os.RemoveAll(filepath.Join("/var/lib", name))
	binary := filepath.Join(binaries, "executord")
	copyTestBinary(t, binary)
	socket := filepath.Join("/run", name, "executor.sock")
	command := []string{"--quiet", "--collect", "--unit=" + name,
		"--setenv=" + liveHelperEnv + "=daemon",
		"--property=RuntimeDirectory=" + name + " " + name + "-private",
		"--property=StateDirectory=" + name}
	shipped := shippedProperties(t, unitFile, 30)
	applied := len(shipped)
	command = append(command, shipped...)
	command = append(command, binary,
		"--socket", socket, "--socket-gid", strconv.Itoa(liveSocketGroup), "--allow-uid", strconv.Itoa(liveAllowedUID),
		"--containerd-socket", containerdSocket,
		"--fifo-dir", filepath.Join("/run", name+"-private", "fifos"),
		"--state-dir", filepath.Join("/var/lib", name),
		"--min-free-bytes", "1048576", "--min-free-inodes", "1024")
	journal := func() string {
		output, _ := exec.Command("journalctl", "--no-pager", "--output=cat", "--unit="+name).CombinedOutput()
		return string(output)
	}
	defer func() {
		_ = exec.Command("systemctl", "stop", name).Run()
		_ = exec.Command("systemctl", "reset-failed", name).Run()
	}()
	// The unit is Type=notify: this returns once the daemon reported ready.
	if output, err := exec.Command("systemd-run", command...).CombinedOutput(); err != nil {
		t.Fatalf("the daemon did not start under the unit's sandbox: %v: %s\n%s", err, output, journal())
	}
	caller := exec.Command(binary, "-test.run=^$")
	// A deadline in the past makes the job collectable at once, so the
	// collection unit below has something to delete.
	caller.Env = []string{liveHelperEnv + "=call", liveHelperSocketEnv + "=" + socket, liveHelperRetainEnv + "=1"}
	caller.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: liveAllowedUID, Gid: liveSocketGroup}}
	var stderr bytes.Buffer
	caller.Stderr = &stderr
	output, err := caller.Output()
	if err != nil {
		t.Fatalf("the caller failed: %v: %s\nservice log:\n%s", err, stderr.String(), journal())
	}
	var report liveCallerReport
	if err := json.Unmarshal(output, &report); err != nil {
		t.Fatalf("the caller printed %q", output)
	}
	if report.Refused != "" {
		t.Fatalf("the job was answered %s under the unit's sandbox\nservice log:\n%s", report.Refused, journal())
	}
	if !report.Description.Ready || report.Outcome.ExitCode != 0 ||
		report.Outcome.ToolchainDigest != softwarework.FrozenV1ImageDigest ||
		!strings.Contains(report.OutputLog, "ok") || !strings.Contains(report.OutputLog, "example.test/live") || !report.RepeatSame {
		t.Fatalf("the real run did not pass: %+v", report)
	}
	t.Logf("under the shipped unit's sandbox (%d settings): output.log=%q artifact=%d bytes", applied, report.OutputLog, report.ArtifactLen)
	// The collection unit, under its own shipped sandbox, sweeps the store
	// of the daemon that is still running.
	collector := filepath.Join(binaries, "software-work-execute")
	copyFile(t, collectionBinary, collector)
	stateDir := filepath.Join("/var/lib", name)
	sweep := []string{"--quiet", "--collect", "--wait", "--pipe", "--unit=" + name + "-gc", "--property=ReadWritePaths=" + stateDir}
	sweep = append(sweep, shippedProperties(t, collectionUnit, 25)...)
	sweep = append(sweep, collector, "artifacts-gc", "--state-dir", stateDir, "--limit", "128")
	var sweepErrors bytes.Buffer
	sweepCommand := exec.Command("systemd-run", sweep...)
	sweepCommand.Stderr = &sweepErrors
	swept, err := sweepCommand.Output()
	if err != nil {
		collectorLog, _ := exec.Command("journalctl", "--no-pager", "--output=cat", "--unit="+name+"-gc").CombinedOutput()
		t.Fatalf("collection under its unit's sandbox: %v: %s%s\n%s", err, swept, sweepErrors.String(), collectorLog)
	}
	var sweepReport struct {
		DeletedJobs    int `json:"deleted_jobs"`
		DeletedObjects int `json:"deleted_objects"`
	}
	if err := json.Unmarshal(swept, &sweepReport); err != nil || sweepReport.DeletedJobs != 1 || sweepReport.DeletedObjects != 2 {
		t.Fatalf("collection report = %s (%v)", swept, err)
	}
	t.Logf("collection under its shipped unit's sandbox: %s", bytes.TrimSpace(swept))
	if objects, err := os.ReadDir(filepath.Join(stateDir, "artifacts", "objects")); err != nil || len(objects) != 0 {
		t.Fatalf("objects after the collection: %v %v", objects, err)
	}
	// A clean stop: the unit must not end in the failed state.
	if output, err := exec.Command("systemctl", "stop", name).CombinedOutput(); err != nil {
		t.Fatalf("stop: %v: %s", err, output)
	}
	if staged, err := os.ReadDir(filepath.Join(stateDir, workspaceDirectory, "workspaces")); err != nil || len(staged) != 0 {
		t.Fatalf("staged workspaces after the run: %v %v", staged, err)
	}
	t.Logf("service log:\n%s", journal())
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	content, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, content, 0o755); err != nil {
		t.Fatal(err)
	}
}
