package carrierapi

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"path/filepath"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/localwire"
)

// DefaultTimeout bounds one operation, connect included.
const DefaultTimeout = 30 * time.Second

// Client calls one carrier socket.
type Client struct {
	path    string
	timeout time.Duration
}

// NewClient returns a client for an absolute, clean socket path.
func NewClient(path string, timeout time.Duration) (*Client, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("carrier socket path must be absolute and clean")
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < time.Second || timeout > 5*time.Minute {
		return nil, errors.New("carrier timeout is outside 1s..5m")
	}
	return &Client{path: path, timeout: timeout}, nil
}

// Carry asks the carrier to deposit one frame.
func (c *Client) Carry(ctx context.Context, recipientAgentID, idempotencyKey, withdrawKey string,
	expiresAtUnix uint64, frame []byte) (Response, error) {
	return c.do(ctx, Request{Op: OpCarry, RecipientAgentID: recipientAgentID, IdempotencyKey: idempotencyKey,
		WithdrawIdempotencyKey: withdrawKey, ExpiresAtUnix: expiresAtUnix,
		FrameBase64: base64.StdEncoding.EncodeToString(frame)})
}

// Deliver hands the daemon a verified kind-1 or kind-4 frame.
func (c *Client) Deliver(ctx context.Context, packetSenderAgentID string, frame []byte) (Response, error) {
	return c.do(ctx, Request{Op: OpDeliver, PacketSenderAgentID: packetSenderAgentID,
		FrameBase64: base64.StdEncoding.EncodeToString(frame)})
}

// DeliveryAck hands the daemon a verified kind-2 frame.
func (c *Client) DeliveryAck(ctx context.Context, packetSenderAgentID string, frame []byte) (Response, error) {
	return c.do(ctx, Request{Op: OpDeliveryAck, PacketSenderAgentID: packetSenderAgentID,
		FrameBase64: base64.StdEncoding.EncodeToString(frame)})
}

func (c *Client) do(ctx context.Context, request Request) (Response, error) {
	if c == nil || ctx == nil {
		return Response{}, errors.New("no carrier client")
	}
	body, err := encodeRequest(request)
	if err != nil {
		return Response{}, err
	}
	deadline := time.Now().Add(c.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	dialer := net.Dialer{Deadline: deadline}
	connection, err := dialer.DialContext(ctx, "unix", c.path)
	if err != nil {
		return Response{}, errors.New("connect carrier socket")
	}
	defer connection.Close()
	if err := connection.SetDeadline(deadline); err != nil {
		return Response{}, errors.New("bound carrier operation")
	}
	if err := writeFrame(connection, body); err != nil {
		return Response{}, errors.New("write carrier request")
	}
	raw, err := readFrame(bufio.NewReader(connection))
	if err != nil {
		return Response{}, errors.New("read carrier response")
	}
	return DecodeResponse(request.Op, raw)
}

// Handler serves the operations one side owns. A side answers an operation
// it does not serve with operation-not-served.
type Handler interface {
	Carry(ctx context.Context, request Request, frame []byte) Response
	Deliver(ctx context.Context, packetSenderAgentID string, frame []byte) Response
	DeliveryAck(ctx context.Context, packetSenderAgentID string, frame []byte) Response
}

// MaxConcurrentHandlers bounds the requests one server handles at once. A
// carrier and a daemon exchange a few frames per peer at a time; further
// connections wait in the listener backlog rather than each holding a
// goroutine and a frame buffer.
const MaxConcurrentHandlers = 16

// Server serves one carrier socket.
type Server struct {
	handler Handler
	timeout time.Duration
	slots   chan struct{}
}

// NewServer returns a server for a handler.
func NewServer(handler Handler, timeout time.Duration) (*Server, error) {
	if handler == nil {
		return nil, errors.New("carrier server needs a handler")
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < time.Second || timeout > 5*time.Minute {
		return nil, errors.New("carrier timeout is outside 1s..5m")
	}
	return &Server{handler: handler, timeout: timeout, slots: make(chan struct{}, MaxConcurrentHandlers)}, nil
}

// Listen creates the private mode-0600 socket.
func Listen(path string) (net.Listener, error) { return localwire.Listen(path) }

// Serve handles same-user connections, one request each, until the
// listener closes.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s == nil || ctx == nil || listener == nil {
		return errors.New("carrier server needs a context and listener")
	}
	for {
		select {
		case s.slots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		connection, err := listener.Accept()
		if err != nil {
			<-s.slots
			return err
		}
		go func() {
			defer func() { <-s.slots }()
			s.serveConnection(ctx, connection)
		}()
	}
}

func (s *Server) serveConnection(ctx context.Context, connection net.Conn) {
	defer connection.Close()
	if localwire.VerifyPeer(connection) != nil {
		return
	}
	if err := connection.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		return
	}
	body, err := readFrame(bufio.NewReader(connection))
	if err != nil {
		return
	}
	// The handler's work is bounded by the same budget as the connection.
	bounded, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	op, response := s.Handle(bounded, body)
	encoded, err := encodeResponse(op, response)
	if err != nil {
		encoded, err = encodeResponse(op, Retry())
		if err != nil {
			return
		}
	}
	_ = writeFrame(connection, encoded)
}

// Handle processes one unframed request body, for in-process use and tests.
func (s *Server) Handle(ctx context.Context, raw []byte) (Op, Response) {
	if s == nil || ctx == nil {
		return OpDeliver, Retry()
	}
	request, err := DecodeRequest(raw)
	if err != nil {
		return OpDeliver, Refusal(CodeInvalidRequest)
	}
	frame, err := request.Frame()
	if err != nil {
		return request.Op, Refusal(CodeInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return request.Op, Retry()
	}
	var response Response
	switch request.Op {
	case OpCarry:
		response = s.handler.Carry(ctx, request, frame)
	case OpDeliver:
		response = s.handler.Deliver(ctx, request.PacketSenderAgentID, frame)
	case OpDeliveryAck:
		response = s.handler.DeliveryAck(ctx, request.PacketSenderAgentID, frame)
	default:
		return request.Op, Refusal(CodeInvalidRequest)
	}
	response.Schema = ResponseSchema
	if err := ValidateResponse(request.Op, response); err != nil {
		return request.Op, Retry()
	}
	return request.Op, response
}

// NotServed is the answer of a side for an operation the other side owns.
func NotServed() Response { return Refusal(CodeOperationNotServedHere) }
