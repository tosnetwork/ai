package executorservice

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// privilegedEnv selects the authoritative privileged suite (make
// test-privileged). In that suite a test that cannot become root fails; in
// the ordinary suite, which must run unprivileged, it is skipped and the
// allow-list is covered against this process's own kernel credential.
const privilegedEnv = "TOS_AI_PRIVILEGED_TESTS"

func requirePrivileged(t *testing.T) {
	t.Helper()
	if os.Getenv(privilegedEnv) == "" {
		t.Skip("not the privileged suite; run make test-privileged")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the privileged suite must run as root")
	}
}

// TestRealCallersAreAdmittedByTheirKernelUID runs the server as root and
// real callers under other uids, so the decision rests on what the kernel
// reports for each of them and on the socket's own permissions.
func TestRealCallersAreAdmittedByTheirKernelUID(t *testing.T) {
	requirePrivileged(t)
	const (
		socketGroup = 61000
		allowedUID  = 61001
		otherUID    = 61002
		otherGroup  = 61003
	)
	root := shortDir(t)
	// Callers must be able to reach the socket directory and run the
	// helper; everything else under root stays private.
	if err := os.Chmod(root, 0o711); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(root, "helper")
	copyExecutable(t, helper)
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := socketIn(t, root)
	bound, err := assemble(state, socket, &fakeBackend{}, func(config *Config) { config.AllowedUID = uid(allowedUID) })
	if err != nil {
		t.Fatal(err)
	}
	// assemble listens for this process's group; the real deployment
	// names the callers' group.
	_ = bound.listener.Close()
	listener, err := Listen(socket, socketGroup)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- bound.server.Serve(listener) }()
	defer func() {
		_ = bound.server.Shutdown(background(t))
		_ = bound.journal.Close()
		if err := <-served; err != nil {
			t.Errorf("serve: %v", err)
		}
	}()
	describeAs := func(uid, gid uint32) string {
		command := exec.Command(helper, "-test.run=^$")
		command.Env = []string{helperEnv + "=describe", helperSocketEnv + "=" + socket}
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
		output, err := command.Output()
		if err != nil {
			t.Fatalf("helper as uid %d: %v", uid, err)
		}
		return strings.TrimSpace(string(output))
	}
	for _, check := range []struct {
		name     string
		uid, gid uint32
		want     string
	}{
		{"the allowed uid in the socket group", allowedUID, socketGroup, "ok"},
		{"another uid in the socket group", otherUID, socketGroup, string(StatusNotAllowed)},
		// The socket's own mode keeps out a caller outside the group,
		// even one whose uid is on the list.
		{"the allowed uid outside the socket group", allowedUID, otherGroup, "no_answer"},
		{"another uid outside the socket group", otherUID, otherGroup, "no_answer"},
	} {
		if got := describeAs(check.uid, check.gid); got != check.want {
			t.Errorf("%s: %s, want %s", check.name, got, check.want)
		}
	}
	// As root the group change itself would succeed for these, so only
	// the check refuses them.
	for name, gid := range map[string]uint32{"overflow gid": 65534, "invalid gid": ^uint32(0)} {
		if refused, err := Listen(socketIn(t, shortDir(t)), gid); err == nil {
			_ = refused.Close()
			t.Errorf("%s: accepted", name)
		}
	}
	// Root is not the allowed uid either: being root is not being allowed.
	client, err := NewClient(ClientConfig{SocketPath: socket})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Describe(background(t)); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("root outside the list: err = %v", err)
	}
}

// copyExecutable puts this test binary where another uid can run it.
func copyExecutable(t *testing.T, target string) {
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
