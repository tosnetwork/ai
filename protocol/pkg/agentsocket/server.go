// Package agentsocket is the local Unix socket between an MCP adapter's
// custody-side agent and the processes that call it: the MCP server in the
// developer account and the confirmer in the custody account. It decides
// each caller's role from the kernel-reported peer uid only, reads one
// strict JSON request of bounded size per connection, and admits a bounded
// number of connections per role, so a client holding all of its
// connections never locks the confirmer out.
//
// It carries no method of its own: the agent supplies its schema, its role
// table, its error codes and the handler.
package agentsocket

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/internal/osguard"
)

// Socket bounds.
const (
	// MaxRequestBytes bounds one request object.
	MaxRequestBytes = 2 << 20
	// SocketName is the socket's file name inside the socket directory.
	SocketName = "agent.sock"
	// DefaultClientConnections and DefaultCustodyConnections are the
	// separate connection pools of the two roles.
	DefaultClientConnections  = 12
	DefaultCustodyConnections = 4
	// maxUnauthenticated bounds connections whose peer is not yet looked
	// up; the lookup takes no input from the peer, so none is held long.
	maxUnauthenticated = 64

	readTimeout = 30 * time.Second
	// defaultWriteTimeout bounds writing one answer.
	defaultWriteTimeout = 30 * time.Second
)

// Role is what a socket peer may do, decided only from its kernel-reported
// uid.
type Role int

const (
	// RoleNone is refused before its request is read.
	RoleNone Role = iota
	// RoleClient is the developer account the MCP server runs as.
	RoleClient
	// RoleCustody is the agent's own account, where the confirmer runs.
	RoleCustody
)

// RoleFor maps a peer uid to its role. The custody uid is the agent's own;
// the client uid is configured and differs from it.
func RoleFor(peerUID, custodyUID, clientUID uint32) Role {
	switch {
	case custodyUID == clientUID:
		return RoleNone
	case peerUID == custodyUID:
		return RoleCustody
	case peerUID == clientUID:
		return RoleClient
	}
	return RoleNone
}

// Request is one socket request.
type Request struct {
	Schema string          `json:"schema"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// Response is one socket response. A refusal may carry a result too, for
// example the record the refusal is about.
type Response struct {
	Schema string `json:"schema"`
	OK     bool   `json:"ok"`
	Result any    `json:"result,omitempty"`
	Error  *Error `json:"error,omitempty"`
}

// Error is a refusal sent to a caller. Message is fixed text chosen by the
// agent; it never carries untrusted text, a path or an endpoint.
type Error struct {
	Code        string `json:"code"`
	Disposition string `json:"disposition"`
	Message     string `json:"message"`
	cause       error
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Unwrap returns the underlying error, which is never sent to a caller.
func (e *Error) Unwrap() error { return e.cause }

// NewError builds a refusal with its cause kept for the agent's own use.
func NewError(code, disposition, message string, cause error) *Error {
	return &Error{Code: code, Disposition: disposition, Message: message, cause: cause}
}

// Codes are the refusals the socket itself sends before any method runs.
type Codes struct {
	BadInput         *Error
	PermissionDenied *Error
	Internal         *Error
}

// Handler runs one method of an admitted peer. The request's schema, method
// and role are already checked.
type Handler func(ctx context.Context, role Role, method string, params json.RawMessage) (any, error)

// Config configures the socket server.
type Config struct {
	// Schema names the request and response objects.
	Schema string
	// SocketDir holds only the socket. It must be owned by the agent's
	// account, setgid, of a group other than the agent's own, and closed to
	// others; group read and search let the client account reach the socket.
	SocketDir string
	// PrivateDirs are directories the socket directory must be neither of
	// nor inside: the agent's state directories.
	PrivateDirs []string
	// ClientUID is the developer account's uid; it must differ from the
	// agent's own.
	ClientUID uint32
	// CustodyUID is the agent's own uid. Zero means the process's effective
	// uid, which is the only value a deployment uses.
	CustodyUID uint32
	// AgentGID is the agent's own private group. Zero means the process's
	// effective gid, which is the only value a deployment uses.
	AgentGID uint32
	// Methods maps each method to the roles that may call it.
	Methods map[string]map[Role]bool
	Handle  Handler
	// ErrorOf maps a handler error to the refusal sent; it must return
	// fixed text only.
	ErrorOf func(error) *Error
	Codes   Codes
	// ClientConnections and CustodyConnections bound each role's
	// connections; zero takes the defaults.
	ClientConnections  int
	CustodyConnections int
	// WriteTimeout bounds writing one answer; zero takes 30 seconds.
	WriteTimeout time.Duration
	// Peer replaces the kernel peer lookup. Only tests set it, to play both
	// roles from one account; a deployment leaves it nil.
	Peer func(*net.UnixConn) (uint32, error)
}

// Server serves the agent socket.
type Server struct {
	config     Config
	listener   *net.UnixListener
	path       string
	custodyUID uint32
	// unauthenticated bounds connections before the peer lookup; client and
	// custody bound each role's connections after it.
	unauthenticated chan struct{}
	client          chan struct{}
	custody         chan struct{}
	peer            func(*net.UnixConn) (uint32, error)
	wait            sync.WaitGroup
}

// Listen checks the deployment and binds the socket. It refuses a client
// uid equal to the agent's, a root agent, and a socket directory that is a
// link, not the agent's, not setgid to a shared group, open to others, or
// one of the private directories or inside one.
func Listen(config Config) (*Server, error) {
	if config.Schema == "" || config.Handle == nil || config.ErrorOf == nil || len(config.Methods) == 0 ||
		config.Codes.BadInput == nil || config.Codes.PermissionDenied == nil || config.Codes.Internal == nil {
		return nil, errors.New("the socket server needs a schema, methods, a handler and its error codes")
	}
	custody := config.CustodyUID
	if custody == 0 {
		custody = uint32(os.Geteuid())
	}
	if custody == 0 {
		return nil, errors.New("the agent must not run as root")
	}
	if config.ClientUID == 0 || config.ClientUID == custody {
		return nil, errors.New("the client uid must be configured, must not be root and must differ from the agent's uid")
	}
	if !filepath.IsAbs(config.SocketDir) || filepath.Clean(config.SocketDir) != config.SocketDir {
		return nil, errors.New("the socket directory must be absolute and clean")
	}
	group := config.AgentGID
	if group == 0 {
		group = uint32(os.Getegid())
	}
	if err := checkSocketDir(config.SocketDir, config.PrivateDirs, group); err != nil {
		return nil, err
	}
	path := filepath.Join(config.SocketDir, SocketName)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 || !osguard.CurrentUserOwns(info) {
			return nil, errors.New("the socket path holds something other than the agent's socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o660); err != nil {
		return nil, errors.Join(err, listener.Close())
	}
	clients, custodians := config.ClientConnections, config.CustodyConnections
	if clients <= 0 {
		clients = DefaultClientConnections
	}
	if custodians <= 0 {
		custodians = DefaultCustodyConnections
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = defaultWriteTimeout
	}
	peer := config.Peer
	if peer == nil {
		peer = PeerUID
	}
	return &Server{config: config, listener: listener, path: path, custodyUID: custody,
		unauthenticated: make(chan struct{}, maxUnauthenticated), client: make(chan struct{}, clients),
		custody: make(chan struct{}, custodians), peer: peer}, nil
}

// checkSocketDir requires a directory of the agent's own account that
// others cannot enter and nobody but the agent can write, setgid to a group
// that is not the agent's own, and that is not a private directory or
// inside one.
func checkSocketDir(dir string, private []string, agentGID uint32) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || !osguard.CurrentUserOwns(info) || info.Mode().Perm()&0o027 != 0 {
		return errors.New("the socket directory must be the agent's own, unwritable by group and closed to others")
	}
	if err := checkSocketGroup(info, agentGID); err != nil {
		return err
	}
	for _, privateDir := range private {
		if privateDir == "" {
			continue
		}
		relative, err := filepath.Rel(privateDir, dir)
		if err != nil {
			return err
		}
		if relative != ".." && !strings.HasPrefix(relative, "../") {
			return errors.New("the socket directory must not be a state directory or inside one")
		}
	}
	return nil
}

// Path is the socket path.
func (s *Server) Path() string { return s.path }

// Serve accepts connections until ctx ends or the listener closes.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.listener.Close()
	}()
	for {
		connection, err := s.listener.AcceptUnix()
		if err != nil {
			s.wait.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case s.unauthenticated <- struct{}{}:
		default:
			_ = connection.Close()
			continue
		}
		s.wait.Add(1)
		go func() {
			defer s.wait.Done()
			defer connection.Close()
			role, release, admitted := s.admit(connection)
			if !admitted {
				return
			}
			defer release()
			s.handle(ctx, role, connection)
		}()
	}
}

// admit looks up the peer and takes a connection slot of its role. It
// admits nothing for an unknown peer or a full pool; the connection is then
// closed without a byte being read.
func (s *Server) admit(connection *net.UnixConn) (Role, func(), bool) {
	defer func() { <-s.unauthenticated }()
	uid, err := s.peer(connection)
	if err != nil {
		return RoleNone, nil, false
	}
	role := RoleFor(uid, s.custodyUID, s.config.ClientUID)
	pool := s.client
	switch role {
	case RoleCustody:
		pool = s.custody
	case RoleNone:
		return RoleNone, nil, false
	}
	select {
	case pool <- struct{}{}:
		return role, func() { <-pool }, true
	default:
		return RoleNone, nil, false
	}
}

// Close stops the server.
func (s *Server) Close() error { return s.listener.Close() }

// handle serves one request of an admitted peer.
func (s *Server) handle(ctx context.Context, role Role, connection *net.UnixConn) {
	response := s.answer(ctx, role, connection)
	_ = connection.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout))
	encoded, err := json.Marshal(response)
	if err != nil {
		encoded, err = json.Marshal(Response{Schema: s.config.Schema, Error: s.config.Codes.Internal})
		if err != nil {
			return
		}
	}
	_, _ = connection.Write(append(encoded, '\n'))
}

// answer reads and serves one request. A panic while doing so becomes a
// fixed internal error for this connection only: the agent keeps serving
// the other connections.
func (s *Server) answer(ctx context.Context, role Role, connection *net.UnixConn) (response Response) {
	defer func() {
		if recovered := recover(); recovered != nil {
			response = Response{Schema: s.config.Schema, Error: s.config.Codes.Internal}
		}
	}()
	_ = connection.SetReadDeadline(time.Now().Add(readTimeout))
	reader := bufio.NewReaderSize(io.LimitReader(connection, MaxRequestBytes+1), 64<<10)
	line, err := reader.ReadSlice('\n')
	for errors.Is(err, bufio.ErrBufferFull) {
		var more []byte
		more, err = reader.ReadSlice('\n')
		line = append(append([]byte(nil), line...), more...)
	}
	if len(line) > MaxRequestBytes || err != nil {
		return Response{Schema: s.config.Schema, Error: s.config.Codes.BadInput}
	}
	return s.dispatch(ctx, role, line[:len(line)-1])
}

// dispatch decodes the envelope strictly, applies the role table and runs
// the method.
func (s *Server) dispatch(ctx context.Context, role Role, raw []byte) Response {
	var request Request
	if err := jsonstrict.Decode(raw, &request); err != nil || request.Schema != s.config.Schema {
		return Response{Schema: s.config.Schema, Error: s.config.Codes.BadInput}
	}
	roles, known := s.config.Methods[request.Method]
	if !known {
		return Response{Schema: s.config.Schema, Error: s.config.Codes.BadInput}
	}
	if !roles[role] {
		return Response{Schema: s.config.Schema, Error: s.config.Codes.PermissionDenied}
	}
	result, err := s.config.Handle(ctx, role, request.Method, request.Params)
	if err != nil {
		return Response{Schema: s.config.Schema, Result: result, Error: s.config.ErrorOf(err)}
	}
	return Response{Schema: s.config.Schema, OK: true, Result: result}
}

// DecodeParams decodes a method's params strictly: unknown fields,
// duplicate keys and trailing data are refused.
func DecodeParams(raw json.RawMessage, value any) error {
	if len(raw) == 0 {
		return errors.New("params are missing")
	}
	return jsonstrict.Decode(raw, value)
}
