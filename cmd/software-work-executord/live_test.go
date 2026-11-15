package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tosnetwork/tos-ai/pkg/executorservice"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
)

const (
	// liveSocketEnv names the private containerd socket of a provisioned
	// host. Setting it selects the live test, which then must run as root:
	// it fails, rather than skips, when it cannot.
	liveSocketEnv = "TOS_AI_EXECUTORD_LIVE_CONTAINERD_SOCKET"

	liveHelperEnv       = "TOS_AI_EXECUTORD_TEST_HELPER"
	liveHelperSocketEnv = "TOS_AI_EXECUTORD_TEST_SOCKET"

	liveSocketGroup = 61000
	liveAllowedUID  = 61001
	liveOtherUID    = 61002
)

func TestMain(m *testing.M) {
	if os.Getenv(liveHelperEnv) == "call" {
		os.Exit(liveCaller())
	}
	os.Exit(m.Run())
}

// liveCallerReport is what the unprivileged caller saw.
type liveCallerReport struct {
	Refused         string                      `json:"refused,omitempty"`
	Description     executorservice.Description `json:"description"`
	Outcome         softwarework.Outcome        `json:"outcome"`
	ArtifactLen     int                         `json:"artifact_len"`
	ReportJSON      string                      `json:"report_json"`
	OutputLog       string                      `json:"output_log"`
	RepeatSame      bool                        `json:"repeat_same"`
	RetainUntilUnix int64                       `json:"retain_until_unix"`
}

// TestLiveServiceRunsARealJobForAnUnprivilegedCaller runs the daemon's own
// assembly as root on the real private containerd and calls it from a
// process with no privilege at all: the caller holds only the socket.
func TestLiveServiceRunsARealJobForAnUnprivilegedCaller(t *testing.T) {
	containerdSocket := os.Getenv(liveSocketEnv)
	if containerdSocket == "" {
		t.Skip("no private containerd is configured; run make test-privileged on a provisioned host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the live executor service test must run as root")
	}
	// The runtime shim bind-mounts the workspace from the FIFO directory,
	// so the directory lives where the host's mount namespace sees it.
	root, err := os.MkdirTemp("/run", "tos-executord-live-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "socket"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The caller's binary lives apart from the runtime directory, which
	// is commonly mounted noexec.
	callerDirectory, err := os.MkdirTemp("", "tos-executord-caller-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(callerDirectory)
	if err := os.Chmod(callerDirectory, 0o711); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(callerDirectory, "caller")
	copyTestBinary(t, helper)
	socket := filepath.Join(root, "socket", "executor.sock")
	// The state directory, and with it the staged workspace, is on disk.
	stateParent, err := os.MkdirTemp("/var/tmp", "tos-executord-live-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stateParent)
	stateDir := filepath.Join(stateParent, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	parsed := options{socket: socket, socketGID: liveSocketGroup, allowedUID: liveAllowedUID,
		containerdSocket: containerdSocket, fifoDir: filepath.Join(root, "fifos"), stateDir: stateDir,
		maxExecutions: 1, minFreeBytes: 1 << 20, minFreeInodes: 1 << 10,
		defaultRetention: time.Hour, maxRetention: 2 * time.Hour, stopGrace: defaultStopGrace}
	var logMutex sync.Mutex
	var serviceLog strings.Builder
	logf := func(format string, arguments ...any) {
		logMutex.Lock()
		defer logMutex.Unlock()
		fmt.Fprintf(&serviceLog, format+"\n", arguments...)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	ready := make(chan struct{})
	served := make(chan error, 1)
	go func() {
		served <- serve(ctx, parsed, logf, func() error {
			close(ready)
			return nil
		})
	}()
	select {
	case <-ready:
	case err := <-served:
		t.Fatalf("the service did not start: %v", err)
	case <-time.After(time.Minute):
		t.Fatal("the service did not become ready")
	}
	callAs := func(uid uint32) liveCallerReport {
		command := exec.Command(helper, "-test.run=^$")
		command.Env = []string{liveHelperEnv + "=call", liveHelperSocketEnv + "=" + socket}
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: liveSocketGroup}}
		var stderr bytes.Buffer
		command.Stderr = &stderr
		output, err := command.Output()
		if err != nil {
			t.Fatalf("caller as uid %d: %v: %s", uid, err, stderr.String())
		}
		var report liveCallerReport
		if err := json.Unmarshal(output, &report); err != nil {
			t.Fatalf("caller as uid %d printed %q", uid, output)
		}
		return report
	}
	report := callAs(liveAllowedUID)
	t.Logf("caller uid %d saw: description=%+v", liveAllowedUID, report.Description)
	t.Logf("outcome=%+v", report.Outcome)
	t.Logf("artifact bytes=%d report=%s", report.ArtifactLen, report.ReportJSON)
	t.Logf("output.log=%q", report.OutputLog)
	if report.Refused != "" {
		t.Fatalf("the allowed caller was refused: %s", report.Refused)
	}
	if !report.Description.Ready || report.Description.ImageDigest != softwarework.FrozenV1ImageDigest {
		t.Fatalf("description = %+v", report.Description)
	}
	if report.Outcome.ExitCode != 0 || report.Outcome.ToolchainDigest != softwarework.FrozenV1ImageDigest ||
		report.Outcome.SandboxDigest != softwarework.FrozenV1ManifestDigest ||
		!strings.Contains(report.OutputLog, "ok") || !strings.Contains(report.OutputLog, "example.test/live") {
		t.Fatalf("the real run did not pass: %+v %q", report.Outcome, report.OutputLog)
	}
	// The request asked for no deadline; the service gave its default.
	if report.RetainUntilUnix != int64(report.Outcome.CompletedAtUnix)+3600 {
		t.Fatalf("retained until %d for a job completed at %d", report.RetainUntilUnix, report.Outcome.CompletedAtUnix)
	}
	// The source was staged on the state filesystem and removed again.
	if staged, err := os.ReadDir(filepath.Join(stateDir, workspaceDirectory, "workspaces")); err != nil || len(staged) != 0 {
		t.Fatalf("staged workspaces after the run: %v %v", staged, err)
	}
	if !report.RepeatSame {
		t.Fatal("the repeated request did not return the recorded outcome")
	}
	// Another unprivileged uid that can reach the socket is refused.
	if refused := callAs(liveOtherUID); refused.Refused != string(executorservice.StatusNotAllowed) {
		t.Fatalf("another uid: %+v", refused)
	}
	// The caller cannot read the service's state at all.
	probe := exec.Command("/usr/bin/test", "-r", filepath.Join(parsed.stateDir, "journal"))
	probe.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: liveAllowedUID, Gid: liveSocketGroup}}
	if probe.Run() == nil {
		t.Fatal("the caller can read the service's state directory")
	}
	stop()
	if err := <-served; err != nil {
		t.Fatalf("serve: %v", err)
	}
	logMutex.Lock()
	t.Logf("service log:\n%s", serviceLog.String())
	logMutex.Unlock()
}

// liveCaller is the unprivileged side: it knows the socket path and nothing
// else about the host.
func liveCaller() int {
	report, err := liveCall()
	var status *executorservice.StatusError
	if errors.As(err, &status) {
		report, err = liveCallerReport{Refused: string(status.Status)}, nil
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return 1
	}
	fmt.Println(string(encoded))
	return 0
}

func liveCall() (liveCallerReport, error) {
	if os.Geteuid() == 0 {
		return liveCallerReport{}, errors.New("the live caller must not be root")
	}
	client, err := executorservice.NewClient(executorservice.ClientConfig{SocketPath: os.Getenv(liveHelperSocketEnv)})
	if err != nil {
		return liveCallerReport{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	description, err := client.Describe(ctx)
	if err != nil {
		return liveCallerReport{}, err
	}
	archive, err := liveModule()
	if err != nil {
		return liveCallerReport{}, err
	}
	// A fresh identity per run, so the test can be repeated on one host.
	identity := fmt.Sprintf("live %d", time.Now().UnixNano())
	request := executorservice.ExecuteRequest{
		ExecutionID:     liveDigest("execution " + identity),
		QuoteCommitment: "tvm-cell-" + liveDigest("quote "+identity),
		InputDigest:     liveDigest("input " + identity),
		ManifestDigest:  softwarework.FrozenV1ManifestDigest,
		Limits: executorservice.Limits{CPUMillis: 60_000, MemoryBytes: 512 << 20, ScratchBytes: 1 << 30,
			OutputBytes: 1 << 20, WallClockMillis: 120_000},
		SourceArchive: archive,
	}
	result, err := client.Execute(ctx, request)
	if err != nil {
		return liveCallerReport{}, err
	}
	repeated, err := client.Execute(ctx, request)
	if err != nil {
		return liveCallerReport{}, err
	}
	report := liveCallerReport{Description: description, Outcome: result.Outcome, ArtifactLen: len(result.Artifact),
		ReportJSON: string(result.Report), RetainUntilUnix: result.RetainUntilUnix,
		RepeatSame: repeated.Outcome == result.Outcome && bytes.Equal(repeated.Artifact, result.Artifact)}
	reader := tar.NewReader(bytes.NewReader(result.Artifact))
	for {
		header, err := reader.Next()
		if err != nil {
			break
		}
		if header.Name == "output.log" {
			log, _ := io.ReadAll(reader)
			report.OutputLog = string(log)
		}
	}
	return report, nil
}

func liveModule() ([]byte, error) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, file := range []struct{ name, body string }{
		{"go.mod", "module example.test/live\n\ngo 1.26.5\n"},
		{"live_test.go", "package live\n\nimport \"testing\"\n\nfunc TestLive(t *testing.T) {\n\tif 6*7 != 42 {\n\t\tt.Fatal(\"arithmetic\")\n\t}\n}\n"},
	} {
		header := &tar.Header{Name: file.name, Mode: 0o444, Size: int64(len(file.body)), Format: tar.FormatUSTAR}
		if err := writer.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := writer.Write([]byte(file.body)); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func liveDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func copyTestBinary(t *testing.T, target string) {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destination, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		t.Fatal(err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
}
