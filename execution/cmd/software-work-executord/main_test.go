package main

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/execution/pkg/executorservice"
)

func validArguments() []string {
	return []string{"--socket", "/run/tos-service-executor/executor.sock", "--socket-gid", "992", "--allow-uid", "994",
		"--containerd-socket", "/run/tos-service-containerd/containerd.sock",
		"--fifo-dir", "/run/tos-service-executor-private/fifos", "--state-dir", "/var/lib/tos-service-executor"}
}

func TestOptionsNeedExactlyOneNumericCallerUID(t *testing.T) {
	parsed, err := parseOptions(validArguments(), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	want := options{socket: "/run/tos-service-executor/executor.sock", socketGID: 992, allowedUID: 994,
		containerdSocket: "/run/tos-service-containerd/containerd.sock", fifoDir: "/run/tos-service-executor-private/fifos",
		stateDir: "/var/lib/tos-service-executor", maxExecutions: 1, minFreeBytes: 4 << 30, minFreeInodes: 1 << 18,
		defaultRetention: 7 * 24 * time.Hour, maxRetention: 31 * 24 * time.Hour, stopGrace: 200 * time.Second}
	if parsed != want {
		t.Fatalf("parsed = %+v, want %+v", parsed, want)
	}
	replaced := func(flag, value string) []string {
		arguments := validArguments()
		for index, argument := range arguments {
			if argument == flag {
				arguments[index+1] = value
				return arguments
			}
		}
		return append(arguments, flag, value)
	}
	if parsed, err = parseOptions(replaced("--allow-uid", "0"), &bytes.Buffer{}); err != nil || parsed.allowedUID != 0 {
		t.Fatalf("an explicit uid 0: %+v %v", parsed.allowedUID, err)
	}
	if parsed, err = parseOptions(replaced("--max-retention", "168h"), &bytes.Buffer{}); err != nil || parsed.maxRetention != 7*24*time.Hour {
		t.Fatalf("maximum equal to the default: %v", err)
	}
	for name, arguments := range map[string][]string{
		// An unset EnvironmentFile variable expands to the empty string.
		"empty uid":                replaced("--allow-uid", ""),
		"a list of uids":           replaced("--allow-uid", "994,995"),
		"a user name":              replaced("--allow-uid", "openfox"),
		"wildcard":                 replaced("--allow-uid", "*"),
		"negative uid":             replaced("--allow-uid", "-1"),
		"uid with a space":         replaced("--allow-uid", " 994"),
		"leading zero":             replaced("--allow-uid", "0994"),
		"uid over 32 bits":         replaced("--allow-uid", "4294967296"),
		"uid of eleven digits":     replaced("--allow-uid", "99999999999"),
		"hexadecimal uid":          replaced("--allow-uid", "0x3e2"),
		"overflow uid":             replaced("--allow-uid", "65534"),
		"invalid uid":              replaced("--allow-uid", "4294967295"),
		"the former list flag":     append(validArguments(), "--allow-uids", "994"),
		"empty socket gid":         replaced("--socket-gid", ""),
		"socket group by name":     replaced("--socket-gid", "openfox"),
		"overflow socket gid":      replaced("--socket-gid", "65534"),
		"invalid socket gid":       replaced("--socket-gid", "4294967295"),
		"relative socket":          replaced("--socket", "executor.sock"),
		"uncanonical state":        replaced("--state-dir", "/var/lib/../lib/tos-service-executor"),
		"missing fifo dir":         replaced("--fifo-dir", ""),
		"no executions":            replaced("--max-executions", "0"),
		"too many executions":      replaced("--max-executions", "9"),
		"no free-space floor":      replaced("--min-free-bytes", "0"),
		"no free-inode floor":      replaced("--min-free-inodes", "0"),
		"default over maximum":     replaced("--default-retention", "745h"),
		"maximum over a year":      replaced("--max-retention", "8785h"),
		"no default retention":     replaced("--default-retention", "0s"),
		"negative retention":       replaced("--default-retention", "-1h"),
		"no stop grace":            replaced("--stop-grace", "0s"),
		"excessive stop grace":     replaced("--stop-grace", "1h"),
		"positional argument":      append(validArguments(), "serve"),
		"unknown flag":             append(validArguments(), "--image", "docker.io/library/busybox"),
		"missing caller uid":       validArguments()[:4],
		"no containerd by default": validArguments()[:6],
	} {
		if _, err := parseOptions(arguments, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRunRefusesToStartWithoutACallerUID(t *testing.T) {
	var stderr bytes.Buffer
	arguments := validArguments()
	arguments[5] = ""
	if code := run(context.Background(), arguments, &stderr); code != exitUsage ||
		!strings.Contains(stderr.String(), "never accepts any local user") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestStateDirectoryMustBePrivateAndOwned(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := requirePrivateOwnedDirectory(private); err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(root, "shared")
	if err := os.Mkdir(shared, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(private, "inner")
	if err := os.Mkdir(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := requirePrivateOwnedDirectory(inner); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"group-readable": shared, "symlink": link, "file": file,
		"missing": filepath.Join(root, "absent"), "below a symlink": filepath.Join(link, "inner"), "of another user": "/"} {
		if os.Geteuid() == 0 && name == "of another user" {
			continue
		}
		if err := requirePrivateOwnedDirectory(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// serve refuses such a directory before it opens anything.
	parsed, err := parseOptions(validArguments(), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	parsed.stateDir = shared
	if err := serve(context.Background(), parsed, func(string, ...any) {}, nil); err == nil ||
		err.Error() != "state directory must be private and owned" {
		t.Fatalf("serve on a shared state directory: %v", err)
	}
}

func TestFreeSpaceMeasuresBytesAndInodesOfTheStateFilesystem(t *testing.T) {
	free, err := freeSpace(t.TempDir())
	if err != nil || free.Bytes == 0 || free.Inodes == 0 {
		t.Fatalf("free=%+v err=%v", free, err)
	}
	if _, err := freeSpace(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("measured a missing path")
	}
	for name, check := range map[string]struct {
		blockSize, blocks, inodes, freeInodes uint64
		want                                  executorservice.FreeSpace
	}{
		"plain":                {4096, 10, 100, 7, executorservice.FreeSpace{Bytes: 40960, Inodes: 7}},
		"no inodes left":       {4096, 10, 100, 0, executorservice.FreeSpace{Bytes: 40960, Inodes: 0}},
		"inodes on demand":     {4096, 10, 0, 0, executorservice.FreeSpace{Bytes: 40960, Inodes: math.MaxUint64}},
		"byte count overflows": {1 << 20, 1 << 50, 100, 7, executorservice.FreeSpace{Bytes: math.MaxUint64, Inodes: 7}},
	} {
		if got := spaceOf(check.blockSize, check.blocks, check.inodes, check.freeInodes); got != check.want {
			t.Errorf("%s: %+v, want %+v", name, got, check.want)
		}
	}
}

func TestReadinessIsSentToTheServiceManager(t *testing.T) {
	directory, err := os.MkdirTemp("", "xn")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	address := &net.UnixAddr{Name: filepath.Join(directory, "notify"), Net: "unixgram"}
	manager, err := net.ListenUnixgram("unixgram", address)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	t.Setenv("NOTIFY_SOCKET", address.Name)
	if err := notifyReady(); err != nil {
		t.Fatal(err)
	}
	_ = manager.SetReadDeadline(time.Now().Add(5 * time.Second))
	message := make([]byte, 64)
	n, err := manager.Read(message)
	if err != nil || string(message[:n]) != "READY=1" {
		t.Fatalf("message=%q err=%v", message[:n], err)
	}
	// Without a service manager there is nothing to notify, and a
	// relative name is never dialed.
	t.Setenv("NOTIFY_SOCKET", "")
	if err := notifyReady(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NOTIFY_SOCKET", "notify")
	if err := notifyReady(); err == nil {
		t.Fatal("dialed a relative notification socket")
	}
}

func TestDiagnosticIsOneBoundedEscapedLine(t *testing.T) {
	line := diagnostic("run", errors.New("unsupported entry \"a\nexecute: peer_uid=0 status=ok\x1b[2J\""))
	if strings.ContainsAny(line, "\n\r\x1b") || !strings.HasPrefix(line, `backend run failed: "unsupported entry `) ||
		!strings.Contains(line, `\nexecute: peer_uid=0`) {
		t.Fatalf("line = %q", line)
	}
	long := diagnostic("run", errors.New(strings.Repeat("\n", 1<<20)))
	// Each escaped byte is at most four characters.
	if len(long) > 4*maxDiagnosticBytes+64 || strings.Contains(long, "\n") {
		t.Fatalf("a megabyte cause produced %d bytes", len(long))
	}
	if diagnostic("readiness", nil) != `backend readiness failed: "unknown"` {
		t.Fatalf("nil cause: %s", diagnostic("readiness", nil))
	}
}
