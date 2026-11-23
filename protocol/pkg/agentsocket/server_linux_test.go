//go:build linux

package agentsocket

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	badInput = NewError("BAD", "NEVER", "bad input", nil)
	denied   = NewError("DENIED", "NEVER", "denied", nil)
	internal = NewError("INTERNAL", "NEVER", "internal", nil)
)

func socketDir(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("", "as")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	dir := filepath.Join(root, "sock")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, os.ModeSetgid|0o750); err != nil {
		t.Fatal(err)
	}
	return dir
}

func config(dir string, peer uint32) Config {
	return Config{Schema: "test.v1", SocketDir: dir, ClientUID: 20, CustodyUID: 10, AgentGID: uint32(os.Getegid()) + 1,
		Methods: map[string]map[Role]bool{"ping": {RoleClient: true, RoleCustody: true}, "secret": {RoleCustody: true}},
		Handle: func(_ context.Context, role Role, method string, params json.RawMessage) (any, error) {
			var empty struct{}
			if err := DecodeParams(params, &empty); err != nil {
				return nil, badInput
			}
			return map[string]any{"method": method, "role": int(role)}, nil
		},
		ErrorOf: func(error) *Error { return badInput },
		Codes:   Codes{BadInput: badInput, PermissionDenied: denied, Internal: internal},
		Peer:    func(*net.UnixConn) (uint32, error) { return peer, nil }}
}

func serve(t *testing.T, config Config) *Server {
	t.Helper()
	server, err := Listen(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return server
}

func send(t *testing.T, path, line string) string {
	t.Helper()
	connection, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write([]byte(line)); err != nil {
		return ""
	}
	// The request ends here: a line without its newline is then refused at
	// once instead of at the read deadline.
	_ = connection.(*net.UnixConn).CloseWrite()
	answer, _ := bufio.NewReader(connection).ReadString('\n')
	return answer
}

func TestRolesAndEnvelope(t *testing.T) {
	if RoleFor(10, 10, 20) != RoleCustody || RoleFor(20, 10, 20) != RoleClient || RoleFor(30, 10, 20) != RoleNone ||
		RoleFor(10, 10, 10) != RoleNone {
		t.Fatal("RoleFor maps a uid to the wrong role")
	}
	client := serve(t, config(socketDir(t), 20))
	for line, want := range map[string]string{
		`{"schema":"test.v1","method":"ping","params":{}}` + "\n":                                                     `"ok":true`,
		`{"schema":"test.v1","method":"secret","params":{}}` + "\n":                                                   `"DENIED"`,
		`{"schema":"test.v2","method":"ping","params":{}}` + "\n":                                                     `"BAD"`,
		`{"schema":"test.v1","method":"ping","params":null}` + "\n":                                                   `"BAD"`,
		`{"schema":"test.v1","method":"ping","params":{},"x":1}` + "\n":                                               `"BAD"`,
		`{"schema":"test.v1","method":"nothing","params":{}}` + "\n":                                                  `"BAD"`,
		`{"schema":"test.v1","method":"ping","params":{}}`:                                                            `"BAD"`,
		`{"schema":"test.v1","method":"ping","params":{"pad":"` + strings.Repeat("p", MaxRequestBytes) + `"}}` + "\n": `"BAD"`,
	} {
		if answer := send(t, client.Path(), line); !strings.Contains(answer, want) {
			t.Errorf("%.60q: %q", line, answer)
		}
	}
	// Another account's connection is closed before a byte is read.
	other := serve(t, config(socketDir(t), 30))
	if answer := send(t, other.Path(), `{"schema":"test.v1","method":"ping","params":{}}`+"\n"); answer != "" {
		t.Fatalf("another account was answered: %q", answer)
	}
}

func TestTheSocketDirectoryIsChecked(t *testing.T) {
	dir := socketDir(t)
	plain := config(dir, 20)
	plain.AgentGID = uint32(os.Getegid())
	if _, err := Listen(plain); err == nil {
		t.Fatal("a socket directory of the agent's own group was accepted")
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(config(dir, 20)); err == nil {
		t.Fatal("a socket directory that is not setgid was accepted")
	}
	inside := config(socketDir(t), 20)
	inside.PrivateDirs = []string{filepath.Dir(inside.SocketDir)}
	if _, err := Listen(inside); err == nil {
		t.Fatal("a socket directory inside a state directory was accepted")
	}
	same := config(socketDir(t), 20)
	same.ClientUID = same.CustodyUID
	if _, err := Listen(same); err == nil {
		t.Fatal("a client uid equal to the agent's was accepted")
	}
}
