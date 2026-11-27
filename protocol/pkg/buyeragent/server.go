package buyeragent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// APISchema names the agent socket's request and response objects.
const APISchema = "tos.service.mcp-buyer.agent-api.v1"

// Socket bounds.
const (
	// MaxRequestBytes bounds one request object.
	MaxRequestBytes = 2 << 20
	// SocketName is the socket's file name inside the socket directory.
	SocketName = "agent.sock"

	// ClientConnections and CustodyConnections are separate pools, so a
	// client holding every one of its connections (a payment request waits
	// up to 300 seconds) can never lock the confirmer out.
	ClientConnections  = 12
	CustodyConnections = 4
	// maxUnauthenticated bounds connections whose peer is not yet looked
	// up; the lookup takes no input from the peer, so none is held long.
	maxUnauthenticated = 64

	readTimeout  = 30 * time.Second
	writeTimeout = 30 * time.Second
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

// methodRoles lists, for each method, the roles that may call it
// (MCP_BUYER_ADAPTER_V1 section 2.3). Only the custody account may present
// or decide.
var methodRoles = map[string]map[Role]bool{
	"search":             {RoleClient: true, RoleCustody: true},
	"quote":              {RoleClient: true, RoleCustody: true},
	"token_lock_preview": {RoleClient: true, RoleCustody: true},
	"prepare":            {RoleClient: true},
	"withdraw":           {RoleClient: true, RoleCustody: true},
	"request_payment":    {RoleClient: true},
	"status":             {RoleClient: true, RoleCustody: true},
	"purchases":          {RoleClient: true, RoleCustody: true},
	"refund_now":         {RoleClient: true, RoleCustody: true},
	"result":             {RoleClient: true, RoleCustody: true},
	"pending":            {RoleCustody: true},
	"present":            {RoleCustody: true},
	"decide":             {RoleCustody: true},
}

// Allowed reports whether role may call method.
func Allowed(role Role, method string) bool { return methodRoles[method][role] }

// Request is one socket request.
type Request struct {
	Schema string          `json:"schema"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// Response is one socket response.
type Response struct {
	Schema string `json:"schema"`
	OK     bool   `json:"ok"`
	Result any    `json:"result,omitempty"`
	Error  *Error `json:"error,omitempty"`
}

// ServerConfig configures the socket server.
type ServerConfig struct {
	Agent *Agent
	// SocketDir holds only the socket. It must be owned by the agent's
	// account and closed to others; group read and search let the client
	// account reach the socket.
	SocketDir string
	// ClientUID is the developer account's uid; it must differ from the
	// agent's own.
	ClientUID uint32
	// CustodyUID is the agent's own uid. Zero means the process's
	// effective uid, which is the only value a deployment uses.
	CustodyUID uint32
}

// Server serves the agent socket.
type Server struct {
	agent      *Agent
	listener   *net.UnixListener
	path       string
	custodyUID uint32
	clientUID  uint32
	// unauthenticated bounds connections before the peer lookup; client and
	// custody bound each role's connections after it.
	unauthenticated chan struct{}
	client          chan struct{}
	custody         chan struct{}
	// peer returns a connection's kernel-reported uid; tests replace it to
	// play both roles from one account.
	peer func(*net.UnixConn) (uint32, error)
	wait sync.WaitGroup
}

// Listen checks the deployment and binds the socket. It refuses a client
// uid equal to the agent's, a root agent, a socket directory that is a link,
// not the agent's, or writable or readable by others.
func Listen(config ServerConfig) (*Server, error) {
	if config.Agent == nil {
		return nil, errors.New("the socket server needs an agent")
	}
	custody := config.CustodyUID
	if custody == 0 {
		custody = uint32(os.Geteuid())
	}
	if custody == 0 {
		return nil, errors.New("the buyer agent must not run as root")
	}
	if config.ClientUID == 0 || config.ClientUID == custody {
		return nil, errors.New("the client uid must be configured and must differ from the agent's uid")
	}
	if !filepath.IsAbs(config.SocketDir) || filepath.Clean(config.SocketDir) != config.SocketDir {
		return nil, errors.New("the socket directory must be absolute and clean")
	}
	if err := checkSocketDir(config.SocketDir, config.Agent.config.StateDir); err != nil {
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
		listener.Close()
		return nil, err
	}
	return &Server{agent: config.Agent, listener: listener, path: path, custodyUID: custody,
		clientUID: config.ClientUID, unauthenticated: make(chan struct{}, maxUnauthenticated),
		client: make(chan struct{}, ClientConnections), custody: make(chan struct{}, CustodyConnections),
		peer: peerUID}, nil
}

// checkSocketDir requires a directory of the agent's own account that
// others cannot enter and nobody but the agent can write, and that is not
// the state directory or inside it.
func checkSocketDir(dir, stateDir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || !osguard.CurrentUserOwns(info) || info.Mode().Perm()&0o027 != 0 {
		return errors.New("the socket directory must be the agent's own, unwritable by group and closed to others")
	}
	if err := checkSocketGroup(info); err != nil {
		return err
	}
	relative, err := filepath.Rel(stateDir, dir)
	if err != nil {
		return err
	}
	if relative != ".." && !strings.HasPrefix(relative, "../") {
		return errors.New("the socket directory must not be the state directory or inside it")
	}
	return nil
}

// Path is the socket path.
func (s *Server) Path() string { return s.path }

// Serve accepts connections until ctx ends or the listener closes.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.listener.Close()
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
			connection.Close()
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
	role := RoleFor(uid, s.custodyUID, s.clientUID)
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
	_ = connection.SetWriteDeadline(time.Now().Add(writeTimeout))
	encoded, err := json.Marshal(response)
	if err != nil {
		encoded, _ = json.Marshal(failure(refusal(CodeInternal, "the agent could not encode its answer", err)))
	}
	_, _ = connection.Write(append(encoded, '\n'))
}

// answer reads and serves one request. A panic while doing so becomes a
// fixed internal error for this connection only: the agent keeps serving
// the other connections and keeps its refund duties.
func (s *Server) answer(ctx context.Context, role Role, connection *net.UnixConn) (response Response) {
	defer func() {
		if recovered := recover(); recovered != nil {
			response = failure(refusal(CodeInternal, "the agent failed while handling the request", nil))
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
	switch {
	case len(line) > MaxRequestBytes:
		return failure(refusal(CodeBadInput, "the request exceeds the 2 MiB bound", nil))
	case err != nil:
		return failure(refusal(CodeBadInput, "the request is not one newline-terminated JSON object", err))
	}
	return s.dispatch(ctx, role, line[:len(line)-1])
}

func failure(err error) Response {
	return Response{Schema: APISchema, Error: asError(err)}
}

func decodeParams(raw json.RawMessage, value any) error {
	if len(raw) == 0 {
		return refusal(CodeBadInput, "params are missing", nil)
	}
	if err := jsonstrict.Decode(raw, value); err != nil {
		return refusal(CodeBadInput, "params do not decode strictly", err)
	}
	return nil
}

// dispatch decodes the envelope strictly, applies the role table and runs
// the method.
func (s *Server) dispatch(ctx context.Context, role Role, raw []byte) Response {
	var request Request
	if err := jsonstrict.Decode(raw, &request); err != nil {
		return failure(refusal(CodeBadInput, "the request does not decode strictly", err))
	}
	if request.Schema != APISchema {
		return failure(refusal(CodeBadInput, "the request names another schema", nil))
	}
	if _, known := methodRoles[request.Method]; !known {
		return failure(refusal(CodeBadInput, "unknown method", nil))
	}
	if !Allowed(role, request.Method) {
		return failure(refusal(CodePermissionDenied, "this account may not call this method", nil))
	}
	result, err := s.call(ctx, request)
	if err != nil {
		response := failure(err)
		response.Result = result
		return response
	}
	return Response{Schema: APISchema, OK: true, Result: result}
}

func (s *Server) call(ctx context.Context, request Request) (any, error) {
	agent := s.agent
	switch request.Method {
	case "search":
		var params SearchParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return agent.Search(ctx, params)
	case "quote":
		var params QuoteParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return agent.Quote(ctx, params)
	case "token_lock_preview":
		var params TokenLockPreviewParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return agent.PreviewTokenLock(ctx, params)
	case "prepare":
		var params PrepareParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return agent.Prepare(ctx, params)
	case "withdraw":
		var params RequestHashParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return agent.Withdraw(params.RequestHash)
	case "request_payment":
		var params RequestPaymentParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return agent.RequestPayment(ctx, params)
	case "status":
		var params RequestHashParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return agent.Status(params.RequestHash)
	case "purchases":
		var params PurchasesParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return agent.Purchases(params)
	case "refund_now":
		var params RequestHashParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return agent.RefundNow(ctx, params.RequestHash)
	case "result":
		var params RequestHashParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return agent.Result(params.RequestHash)
	case "pending":
		var params struct{}
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return agent.Pending()
	case "present":
		var params RequestHashParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return agent.Present(params.RequestHash)
	case "decide":
		var params DecideParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return agent.Decide(ctx, params)
	}
	return nil, refusal(CodeBadInput, fmt.Sprintf("unknown method %q", request.Method), nil)
}
