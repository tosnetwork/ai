package executorservice

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tosnetwork/ai/execution/pkg/artifactstore"
	"github.com/tosnetwork/ai/execution/pkg/executor"
	"github.com/tosnetwork/ai/execution/pkg/softwarework"
)

const (
	helperEnv       = "TOS_AI_EXECUTORSERVICE_TEST_HELPER"
	helperStateEnv  = "TOS_AI_EXECUTORSERVICE_TEST_STATE"
	helperSocketEnv = "TOS_AI_EXECUTORSERVICE_TEST_SOCKET"
	helperMarkerEnv = "TOS_AI_EXECUTORSERVICE_TEST_MARKER"
)

// TestMain doubles as the helper process of the tests that need a real
// second process: a server that is killed mid-run, and a caller running
// under another uid.
func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "":
		os.Exit(m.Run())
	case "serve-and-hang":
		os.Exit(helperServeAndHang())
	case "describe":
		os.Exit(helperDescribe())
	default:
		os.Exit(2)
	}
}

// fakeBackend stands in for the container runtime behind the real policy
// executor, so every request still passes the frozen policy.
type fakeBackend struct {
	mutex   sync.Mutex
	calls   int
	last    executor.ContainerRequest
	output  []byte
	exit    int
	started chan struct{}
	gate    chan struct{}
}

func (f *fakeBackend) RunIsolated(ctx context.Context, request executor.ContainerRequest, _ []byte) (executor.Result, error) {
	f.mutex.Lock()
	f.calls++
	f.last = request
	gate, output, exit, started := f.gate, f.output, f.exit, f.started
	f.mutex.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return executor.Result{}, ctx.Err()
		}
	}
	if output == nil {
		output = []byte("ok\n")
	}
	return executor.Result{ExitCode: exit, Output: output,
		Usage: executor.Usage{CPUMillis: 1, PeakMemory: 1024, DiskWritten: 10, Duration: time.Millisecond}}, nil
}

func (f *fakeBackend) runs() int {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.calls
}

func (f *fakeBackend) lastRequest() executor.ContainerRequest {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.last
}

// assembly is a server wired the way the daemon wires it, on a fake runtime.
type assembly struct {
	server   *Server
	listener *net.UnixListener
	store    *artifactstore.Store
	journal  *softwarework.Journal
}

func assemble(state, socket string, backend executor.ContainerdClient, edit func(*Config), options ...artifactstore.Option) (*assembly, error) {
	bound, err := executor.NewPolicyExecutor(softwarework.FrozenV1Policy(), backend)
	if err != nil {
		return nil, err
	}
	store, err := artifactstore.Open(filepath.Join(state, "artifacts"), artifactstore.MaxObjectBytesHard, options...)
	if err != nil {
		return nil, err
	}
	journal, err := softwarework.OpenJournal(filepath.Join(state, "journal"))
	if err != nil {
		return nil, err
	}
	self := uint32(os.Getuid())
	config := Config{AllowedUID: &self, Executor: bound, Store: store, Journal: journal,
		Ready:    func(context.Context) error { return nil },
		Identity: Identity{Version: "test-version", Commit: "test-commit"}}
	if edit != nil {
		edit(&config)
	}
	server, err := NewServer(config)
	if err != nil {
		_ = journal.Close()
		return nil, err
	}
	listener, err := Listen(socket, uint32(os.Getegid()))
	if err != nil {
		_ = journal.Close()
		return nil, err
	}
	return &assembly{server: server, listener: listener, store: store, journal: journal}, nil
}

type harness struct {
	*assembly
	backend *fakeBackend
	client  *Client
	socket  string
	state   string
	stopped sync.Once
}

// shortDir is a private directory with a path short enough for a socket.
func shortDir(t *testing.T) string {
	t.Helper()
	created, err := os.MkdirTemp("", "xs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(created) })
	resolved, err := filepath.EvalSymlinks(created)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func socketIn(t *testing.T, root string) string {
	t.Helper()
	directory := filepath.Join(root, "s")
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	return filepath.Join(directory, "x.sock")
}

func startService(t *testing.T, backend *fakeBackend, edit func(*Config), options ...artifactstore.Option) *harness {
	t.Helper()
	return startServiceIn(t, shortDir(t), backend, edit, options...)
}

func startServiceIn(t *testing.T, root string, backend *fakeBackend, edit func(*Config), options ...artifactstore.Option) *harness {
	t.Helper()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	socket := socketIn(t, root)
	built, err := assemble(state, socket, backend, edit, options...)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ClientConfig{SocketPath: socket, ServerUID: uint32(os.Getuid())})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- built.server.Serve(built.listener) }()
	result := &harness{assembly: built, backend: backend, client: client, socket: socket, state: state}
	t.Cleanup(func() {
		result.stop(t)
		if err := <-served; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return result
}

// stop shuts the server down and releases the state directory.
func (h *harness) stop(t *testing.T) {
	t.Helper()
	h.stopped.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = h.server.Shutdown(ctx)
		if err := h.journal.Close(); err != nil {
			t.Errorf("close journal: %v", err)
		}
	})
}

var tightLimits = Limits{CPUMillis: 30_000, MemoryBytes: 256 << 20, ScratchBytes: 512 << 20, OutputBytes: 1 << 20, WallClockMillis: 30_000}

func sourceArchive(name string) []byte {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	body := []byte("module example.test/" + name + "\n\ngo 1.26.5\n")
	if err := writer.WriteHeader(&tar.Header{Name: "go.mod", Mode: 0o444, Size: int64(len(body)), Format: tar.FormatUSTAR}); err != nil {
		panic(err)
	}
	if _, err := writer.Write(body); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

// job is a well-formed request whose every identity derives from name.
func job(name string) ExecuteRequest {
	return ExecuteRequest{ExecutionID: digestOf([]byte("execution " + name)),
		QuoteCommitment: "tvm-cell-" + digestOf([]byte("quote "+name)), InputDigest: digestOf([]byte("input " + name)),
		ManifestDigest: digestOf([]byte("published manifest")), Limits: tightLimits, SourceArchive: sourceArchive(name)}
}

// headerFields is the wire header of request as loose JSON, for tests that
// send what the client never would.
func headerFields(request ExecuteRequest) map[string]any {
	return map[string]any{"schema": RequestSchema, "operation": OperationExecute, "execute": map[string]any{
		"execution_id": request.ExecutionID, "quote_commitment": request.QuoteCommitment,
		"input_digest": request.InputDigest, "manifest_digest": request.ManifestDigest,
		"limits": map[string]any{"cpu_millis": request.Limits.CPUMillis, "memory_bytes": request.Limits.MemoryBytes,
			"scratch_bytes": request.Limits.ScratchBytes, "output_bytes": request.Limits.OutputBytes,
			"wall_clock_millis": request.Limits.WallClockMillis},
		"retain_until_unix": request.RetainUntilUnix, "source_digest": digestOf(request.SourceArchive),
		"source_bytes": len(request.SourceArchive)}}
}

func frameOf(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return frameRaw(encoded)
}

func frameRaw(header []byte) []byte {
	frame := make([]byte, 4, 4+len(header))
	binary.BigEndian.PutUint32(frame, uint32(len(header)))
	return append(frame, header...)
}

// padded extends a JSON header with insignificant whitespace to size bytes.
func padded(header []byte, size int) []byte {
	return append(append([]byte(nil), header...), bytes.Repeat([]byte(" "), size-len(header))...)
}

func dialRaw(t *testing.T, socket string) *net.UnixConn {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// readStatusOf reads the response header of a raw connection.
func readStatusOf(t *testing.T, conn *net.UnixConn) Status {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	raw, err := readHeader(conn, MaxResponseHeaderBytes)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	var response responseHeader
	if err := decodeStrict(raw, &response); err != nil || response.Schema != ResponseSchema {
		t.Fatalf("response does not decode: %v %s", err, raw)
	}
	if response.Status != StatusOK && response.Error != statusMessages[response.Status] {
		t.Fatalf("status %s carries message %q", response.Status, response.Error)
	}
	return response.Status
}

// sendRaw writes the parts, half-closes and returns the answered status.
func sendRaw(t *testing.T, socket string, parts ...[]byte) Status {
	t.Helper()
	conn := dialRaw(t, socket)
	for _, part := range parts {
		// The server may refuse before reading everything; the answer
		// is still read below.
		if _, err := conn.Write(part); err != nil {
			break
		}
	}
	_ = conn.CloseWrite()
	return readStatusOf(t, conn)
}

func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitStarted(t *testing.T, backend *fakeBackend) {
	t.Helper()
	select {
	case <-backend.started:
	case <-time.After(10 * time.Second):
		t.Fatal("the run did not start")
	}
}

// switchable is a value a test flips while the server reads it.
type switchable[T any] struct{ value atomic.Pointer[T] }

func (s *switchable[T]) set(value T) { s.value.Store(&value) }
func (s *switchable[T]) get() T      { return *s.value.Load() }

// helperServeAndHang serves with a runtime that never returns, marking the
// moment a run has been claimed and started so the parent can kill it there.
func helperServeAndHang() int {
	marker := os.Getenv(helperMarkerEnv)
	built, err := assemble(os.Getenv(helperStateEnv), os.Getenv(helperSocketEnv), hangingBackend{marker: marker}, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintln(os.Stderr, built.server.Serve(built.listener))
	return 1
}

type hangingBackend struct{ marker string }

func (h hangingBackend) RunIsolated(context.Context, executor.ContainerRequest, []byte) (executor.Result, error) {
	if err := os.WriteFile(h.marker, []byte("started"), 0o600); err != nil {
		os.Exit(3)
	}
	select {}
}

// helperDescribe calls describe as whatever uid the parent gave this
// process and prints one word for the result.
func helperDescribe() int {
	client, err := NewClient(ClientConfig{SocketPath: os.Getenv(helperSocketEnv)})
	if err != nil {
		fmt.Println("client_error")
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = client.Describe(ctx)
	var status *StatusError
	switch {
	case err == nil:
		fmt.Println("ok")
	case errors.As(err, &status):
		fmt.Println(string(status.Status))
	default:
		fmt.Println("no_answer")
	}
	return 0
}

func uid(value uint32) *uint32 { return &value }
