//go:build linux

package buyeragent

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// socketDir returns a directory a socket server accepts: the test
// account's own, setgid, mode 2750, outside the state directory. A test
// runs as one account, so the directory's group stands for the shared
// group and the agent's private group is taken to be another one.
func socketDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	actual := privateGroup
	privateGroup = func() uint32 { return uint32(os.Getegid()) + 1 }
	t.Cleanup(func() { privateGroup = actual })
	return dir
}

// The socket directory must be setgid and belong to the shared group, not
// the agent's own, or the client account could never reach the socket.
func TestTheSocketDirectoryMustCarryTheSharedGroup(t *testing.T) {
	f := newFixture(t)
	self := uint32(os.Getuid())
	plain := socketDir(t)
	if err := os.Chmod(plain, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(ServerConfig{Agent: f.agent, SocketDir: plain, CustodyUID: self, ClientUID: self + 1}); err == nil ||
		!strings.Contains(err.Error(), "setgid") {
		t.Fatalf("a socket directory without setgid: %v", err)
	}
	private := socketDir(t)
	privateGroup = func() uint32 { return uint32(os.Getegid()) }
	if _, err := Listen(ServerConfig{Agent: f.agent, SocketDir: private, CustodyUID: self, ClientUID: self + 1}); err == nil ||
		!strings.Contains(err.Error(), "shares") {
		t.Fatalf("a socket directory of the agent's own group: %v", err)
	}
}

// serve starts a server whose custody and client uids are chosen so the
// test process is seen in the given role. The kernel always reports the
// test's real uid; the configuration decides what that uid is.
func serve(t *testing.T, f *fixture, role Role) *Server {
	t.Helper()
	self := uint32(os.Geteuid())
	config := ServerConfig{Agent: f.agent, SocketDir: socketDir(t)}
	switch role {
	case RoleCustody:
		config.CustodyUID, config.ClientUID = self, self+1
	case RoleClient:
		config.CustodyUID, config.ClientUID = self+1, self
	default:
		config.CustodyUID, config.ClientUID = self+1, self+2
	}
	server, err := Listen(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return server
}

// exchange sends one request line and reads the answer; ok is false when
// the server closed the connection without answering.
func exchange(t *testing.T, server *Server, raw []byte) (Response, bool) {
	t.Helper()
	connection, err := net.Dial("unix", server.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := connection.Write(raw); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		// A server that refuses the peer may close before the write ends.
		if !strings.Contains(err.Error(), "broken pipe") && !strings.Contains(err.Error(), "reset") {
			t.Fatal(err)
		}
	}
	line, err := bufio.NewReader(connection).ReadBytes('\n')
	if err != nil {
		return Response{}, false
	}
	var response struct {
		Schema string          `json:"schema"`
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  *Error          `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatalf("answer %q: %v", line, err)
	}
	return Response{Schema: response.Schema, OK: response.OK, Result: response.Result, Error: response.Error}, true
}

func call(t *testing.T, server *Server, method string, params any) (Response, bool) {
	t.Helper()
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(Request{Schema: APISchema, Method: method, Params: encoded})
	if err != nil {
		t.Fatal(err)
	}
	return exchange(t, server, append(raw, '\n'))
}

func TestTheRoleTableKeepsDecisionsWithTheCustodyAccount(t *testing.T) {
	for _, method := range []string{"present", "decide", "pending"} {
		if Allowed(RoleClient, method) {
			t.Errorf("a client may call %s", method)
		}
		if !Allowed(RoleCustody, method) {
			t.Errorf("the custody account may not call %s", method)
		}
	}
	for _, method := range []string{"prepare", "request_payment"} {
		if !Allowed(RoleClient, method) || Allowed(RoleCustody, method) {
			t.Errorf("%s is not client-only", method)
		}
	}
	for method := range methodRoles {
		if Allowed(RoleNone, method) {
			t.Errorf("an unknown peer may call %s", method)
		}
	}
	if RoleFor(10, 10, 20) != RoleCustody || RoleFor(20, 10, 20) != RoleClient || RoleFor(30, 10, 20) != RoleNone ||
		RoleFor(10, 10, 10) != RoleNone {
		t.Fatal("RoleFor maps a uid to the wrong role")
	}
}

// The kernel-reported uid decides the role: the same request is answered
// for the custody account and refused for the client account.
func TestSocketRolesComeFromPeerCredentials(t *testing.T) {
	f := newFixture(t)
	view := f.requested(t, keyA)
	client := serve(t, f, RoleClient)
	for _, method := range []string{"present", "decide", "pending"} {
		params := map[string]any{"request_hash": view.RequestHash}
		switch method {
		case "decide":
			params["decision"] = "confirm"
			params["code"] = "0000-0000-0000-0000"
		case "pending":
			params = map[string]any{}
		}
		response, answered := call(t, client, method, params)
		if !answered || response.OK || response.Error == nil || response.Error.Code != CodePermissionDenied {
			t.Fatalf("a client called %s: %+v", method, response)
		}
	}
	if purchase, _ := f.agent.store.readPurchase(view.RequestHash); purchase.ConfirmationNonce != "" {
		t.Fatal("a client request drew a nonce")
	}
	status, answered := call(t, client, "status", map[string]any{"request_hash": view.RequestHash})
	if !answered || !status.OK {
		t.Fatalf("client status: %+v", status)
	}
	if raw := string(status.Result.(json.RawMessage)); strings.Contains(raw, "confirmation_code") || strings.Contains(raw, "confirmation_nonce") {
		t.Fatalf("client status: %+v", status)
	}
	custody := serve(t, f, RoleCustody)
	presented, answered := call(t, custody, "present", map[string]any{"request_hash": view.RequestHash})
	if !answered || !presented.OK {
		t.Fatalf("the custody account could not present: %+v", presented)
	}
	var presentation Presentation
	if err := json.Unmarshal(presented.Result.(json.RawMessage), &presentation); err != nil || presentation.Code == "" {
		t.Fatalf("presentation: %v", err)
	}
	decided, answered := call(t, custody, "decide", map[string]any{"request_hash": view.RequestHash,
		"decision": "confirm", "code": presentation.Code})
	if !answered || !decided.OK || len(f.buyer.sent()) != 1 {
		t.Fatalf("the custody decision did not pay: %+v", decided)
	}
}

// A panic while serving one request becomes a fixed internal error on that
// connection; the agent keeps serving, and its lock is free afterwards.
// The handler itself turns a panic into the fixed internal error. The test
// calls it on its own goroutine, so a handler without the recover fails
// this test by name instead of ending the test binary.
func TestTheHandlerTurnsAPanicIntoAnInternalError(t *testing.T) {
	f := newFixture(t)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	ends := make([]*net.UnixConn, 2)
	for index, fd := range pair {
		file := os.NewFile(uintptr(fd), "socketpair")
		connection, err := net.FileConn(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		ends[index] = connection.(*net.UnixConn)
		defer ends[index].Close()
	}
	request, err := json.Marshal(Request{Schema: APISchema, Method: "prepare", Params: json.RawMessage(
		`{"quote_id":"` + f.quoteID + `","idempotency_key":"` + keyA + `","archive_base64":"` +
			base64.StdEncoding.EncodeToString(sourceTar(t)) + `"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ends[0].Write(append(request, '\n')); err != nil {
		t.Fatal(err)
	}
	f.buyer.panics.Store(true)
	server := &Server{agent: f.agent}
	response := server.answer(context.Background(), RoleClient, ends[1])
	if response.OK || response.Error == nil || response.Error.Code != CodeInternal ||
		response.Error.Message != "the agent failed while handling the request" {
		t.Fatalf("a panicking request was answered with %+v", response)
	}
}

func TestAPanicInARequestFailsOnlyThatConnection(t *testing.T) {
	f := newFixture(t)
	server := serve(t, f, RoleClient)
	archive := base64.StdEncoding.EncodeToString(sourceTar(t))
	f.buyer.panics.Store(true)
	crashed, answered := call(t, server, "prepare", map[string]any{"quote_id": f.quoteID, "idempotency_key": keyA,
		"archive_base64": archive})
	if !answered || crashed.OK || crashed.Error == nil || crashed.Error.Code != CodeInternal ||
		crashed.Error.Message != "the agent failed while handling the request" {
		t.Fatalf("a panicking request was answered with %+v", crashed)
	}
	f.buyer.panics.Store(false)
	listed, answered := call(t, server, "purchases", map[string]any{"page_size": 10})
	if !answered || !listed.OK {
		t.Fatalf("the agent stopped serving after a panic: %+v", listed)
	}
	prepared, answered := call(t, server, "prepare", map[string]any{"quote_id": f.quoteID, "idempotency_key": keyA,
		"archive_base64": archive})
	if !answered || !prepared.OK {
		t.Fatalf("the agent's lock or state was left broken by a panic: %+v", prepared)
	}
}

// A client that holds every connection it may open cannot keep the
// confirmer out: the custody account has its own pool.
func TestAClientCannotTakeTheConfirmersConnections(t *testing.T) {
	f := newFixture(t)
	self := uint32(os.Geteuid())
	server, err := Listen(ServerConfig{Agent: f.agent, SocketDir: socketDir(t), CustodyUID: self, ClientUID: self + 1})
	if err != nil {
		t.Fatal(err)
	}
	const clients = ClientConnections + 8
	var seen atomic.Int32
	// The first connections are reported as the client account and every
	// later one as the custody account.
	server.peer = func(*net.UnixConn) (uint32, error) {
		if seen.Add(1) <= clients {
			return self + 1, nil
		}
		return self, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	var idle []net.Conn
	for index := 0; index < clients; index++ {
		connection, err := net.Dial("unix", server.Path())
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, connection)
	}
	defer func() {
		for _, connection := range idle {
			connection.Close()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for len(server.client) < ClientConnections || seen.Load() < clients {
		if time.Now().After(deadline) {
			t.Fatalf("the clients took %d of %d slots", len(server.client), ClientConnections)
		}
		time.Sleep(10 * time.Millisecond)
	}
	response, answered := call(t, server, "pending", map[string]any{})
	if !answered || !response.OK {
		t.Fatalf("the confirmer was locked out by idle clients: %+v", response)
	}
}

// A peer of any other uid is refused before the server reads a byte.
func TestAnUnknownPeerIsRefusedBeforeItsRequestIsRead(t *testing.T) {
	f := newFixture(t)
	server := serve(t, f, RoleNone)
	if response, answered := call(t, server, "status", map[string]any{"request_hash": strings.Repeat("0", 64)}); answered {
		t.Fatalf("an unknown peer was answered: %+v", response)
	}
}

func TestTheSocketDecodesRequestsStrictly(t *testing.T) {
	f := newFixture(t)
	server := serve(t, f, RoleClient)
	for name, raw := range map[string]string{
		"unknown envelope field": `{"schema":"` + APISchema + `","method":"status","params":{"request_hash":"` + strings.Repeat("0", 64) + `"},"extra":1}`,
		"unknown params field":   `{"schema":"` + APISchema + `","method":"status","params":{"request_hash":"` + strings.Repeat("0", 64) + `","x":1}}`,
		"duplicate key":          `{"schema":"` + APISchema + `","method":"status","method":"decide","params":{}}`,
		"other schema":           `{"schema":"other","method":"status","params":{"request_hash":"` + strings.Repeat("0", 64) + `"}}`,
		"unknown method":         `{"schema":"` + APISchema + `","method":"pay","params":{}}`,
		"missing params":         `{"schema":"` + APISchema + `","method":"status"}`,
		"trailing value":         `{"schema":"` + APISchema + `","method":"status","params":{}} {}`,
	} {
		response, answered := exchange(t, server, []byte(raw+"\n"))
		if !answered || response.OK || response.Error == nil || response.Error.Code != CodeBadInput {
			t.Errorf("%s: %+v", name, response)
		}
	}
	huge := `{"schema":"` + APISchema + `","method":"prepare","params":{"quote_id":"` + f.quoteID +
		`","idempotency_key":"` + keyA + `","archive_base64":"` + strings.Repeat("A", MaxRequestBytes) + `"}}` + "\n"
	if response, answered := exchange(t, server, []byte(huge)); answered && (response.OK || response.Error.Code != CodeBadInput) {
		t.Errorf("an oversized request: %+v", response)
	}
	if records, _ := f.buyer.journal.Records(); len(records) != 0 {
		t.Fatal("a refused request journaled a call")
	}
	archive := base64.StdEncoding.EncodeToString(sourceTar(t))
	prepared, answered := call(t, server, "prepare", map[string]any{"quote_id": f.quoteID, "idempotency_key": keyA,
		"archive_base64": archive})
	if !answered || !prepared.OK {
		t.Fatalf("a valid prepare over the socket: %+v", prepared)
	}
}

func TestListenRefusesUnsafeDeployments(t *testing.T) {
	f := newFixture(t)
	self := uint32(os.Geteuid())
	// The world-open and in-state directories satisfy every other check
	// (setgid, shared group), so the check each case names is the one that
	// refuses it.
	open := socketDir(t)
	if err := os.Chmod(open, 0o777|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(f.state, "socket")
	if err := os.Mkdir(inside, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(inside, 0o750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	named := map[string]string{
		"world-open socket dir":   "unwritable by group and closed to others",
		"socket dir in the state": "must not be the state directory or inside it",
	}
	cases := map[string]ServerConfig{
		"client equals custody":   {Agent: f.agent, SocketDir: socketDir(t), CustodyUID: self, ClientUID: self},
		"no client uid":           {Agent: f.agent, SocketDir: socketDir(t), CustodyUID: self},
		"world-open socket dir":   {Agent: f.agent, SocketDir: open, CustodyUID: self, ClientUID: self + 1},
		"socket dir in the state": {Agent: f.agent, SocketDir: inside, CustodyUID: self, ClientUID: self + 1},
		"the state dir itself":    {Agent: f.agent, SocketDir: f.state, CustodyUID: self, ClientUID: self + 1},
		"relative socket dir":     {Agent: f.agent, SocketDir: "relative", CustodyUID: self, ClientUID: self + 1},
	}
	for name, config := range cases {
		server, err := Listen(config)
		if err == nil {
			server.Close()
			t.Errorf("%s was accepted", name)
			continue
		}
		if want, ok := named[name]; ok && !strings.Contains(err.Error(), want) {
			t.Errorf("%s was refused by another check: %v", name, err)
		}
	}
	notSocket := socketDir(t)
	if err := os.WriteFile(filepath.Join(notSocket, SocketName), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if server, err := Listen(ServerConfig{Agent: f.agent, SocketDir: notSocket, CustodyUID: self, ClientUID: self + 1}); err == nil {
		server.Close()
		t.Error("a regular file at the socket path was replaced")
	}
	server, err := Listen(ServerConfig{Agent: f.agent, SocketDir: socketDir(t), CustodyUID: self, ClientUID: self + 1})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	info, err := os.Stat(server.Path())
	if err != nil || info.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v: %v", info.Mode().Perm(), err)
	}
}
