package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validArguments() []string {
	return []string{"--socket", "/run/tos-service-executor/executor.sock", "--socket-gid", "992", "--allow-uids", "994",
		"--containerd-socket", "/run/tos-service-containerd/containerd.sock",
		"--fifo-dir", "/run/tos-service-executor-private/fifos", "--state-dir", "/var/lib/tos-service-executor"}
}

func TestOptionsNeedAnExplicitNumericAllowList(t *testing.T) {
	parsed, err := parseOptions(validArguments(), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed.allowedUIDs, []uint32{994}) || parsed.socketGID != 992 || parsed.maxExecutions != 1 ||
		parsed.minFreeBytes != defaultMinFreeBytes || parsed.stopGrace != defaultStopGrace {
		t.Fatalf("parsed = %+v", parsed)
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
	if parsed, err = parseOptions(replaced("--allow-uids", "994,1000,0"), &bytes.Buffer{}); err != nil ||
		!reflect.DeepEqual(parsed.allowedUIDs, []uint32{994, 1000, 0}) {
		t.Fatalf("uid list = %+v %v", parsed.allowedUIDs, err)
	}
	for name, arguments := range map[string][]string{
		// An unset EnvironmentFile variable expands to the empty string.
		"empty allow-list":      replaced("--allow-uids", ""),
		"allow-list of a name":  replaced("--allow-uids", "openfox"),
		"wildcard allow-list":   replaced("--allow-uids", "*"),
		"negative uid":          replaced("--allow-uids", "-1"),
		"uid with a space":      replaced("--allow-uids", "994, 995"),
		"trailing comma":        replaced("--allow-uids", "994,"),
		"duplicate uid":         replaced("--allow-uids", "994,994"),
		"leading zero":          replaced("--allow-uids", "0994"),
		"uid over 32 bits":      replaced("--allow-uids", "4294967296"),
		"uid of eleven digits":  replaced("--allow-uids", "99999999999"),
		"hexadecimal uid":       replaced("--allow-uids", "0x3e2"),
		"too many uids":         replaced("--allow-uids", "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17"),
		"empty socket gid":      replaced("--socket-gid", ""),
		"socket group by name":  replaced("--socket-gid", "openfox"),
		"relative socket":       replaced("--socket", "executor.sock"),
		"uncanonical state":     replaced("--state-dir", "/var/lib/../lib/tos-service-executor"),
		"missing fifo dir":      replaced("--fifo-dir", ""),
		"no executions":         replaced("--max-executions", "0"),
		"too many executions":   replaced("--max-executions", "9"),
		"no free-space floor":   replaced("--min-free-bytes", "0"),
		"no stop grace":         replaced("--stop-grace", "0s"),
		"excessive stop grace":  replaced("--stop-grace", "1h"),
		"positional argument":   append(validArguments(), "serve"),
		"unknown flag":          append(validArguments(), "--image", "docker.io/library/busybox"),
		"missing allow-list":    validArguments()[:4],
		"containerd by default": validArguments()[:6],
	} {
		if _, err := parseOptions(arguments, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Sixteen uids, the bound itself, are accepted.
	if _, err := parseOptions(replaced("--allow-uids", "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16"), &bytes.Buffer{}); err != nil {
		t.Fatalf("allow-list at its bound: %v", err)
	}
}

func TestRunRefusesToStartWithoutAnAllowList(t *testing.T) {
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

func TestFreeBytesMeasuresTheStateFilesystem(t *testing.T) {
	free, err := freeBytes(t.TempDir())
	if err != nil || free == 0 {
		t.Fatalf("free=%d err=%v", free, err)
	}
	if _, err := freeBytes(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("measured a missing path")
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
