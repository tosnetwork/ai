package agentsocket

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"time"
)

// MaxResponseBytes bounds one answer the client reads.
const MaxResponseBytes = 16 << 20

// ClientCodes are the refusals the client itself reports.
type ClientCodes struct {
	// BadInput: the request would exceed the socket's bound.
	BadInput *Error
	// Unavailable: the socket does not answer.
	Unavailable *Error
	// Internal: the answer does not decode.
	Internal *Error
}

// Client calls the agent socket. Authority is never the client's to claim:
// the agent decides each caller's role from the kernel-reported uid.
type Client struct {
	path    string
	schema  string
	timeout time.Duration
	codes   ClientCodes
}

// NewClient names the agent socket. timeout bounds one call and must cover
// the longest wait a request asks for.
func NewClient(socketPath, schema string, timeout time.Duration, codes ClientCodes) (*Client, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath {
		return nil, errors.New("the agent socket path must be absolute and clean")
	}
	if schema == "" || codes.BadInput == nil || codes.Unavailable == nil || codes.Internal == nil {
		return nil, errors.New("the agent client needs a schema and its error codes")
	}
	if timeout <= 0 || timeout > 10*time.Minute {
		return nil, errors.New("the agent call timeout must be positive and at most 10 minutes")
	}
	return &Client{path: socketPath, schema: schema, timeout: timeout, codes: codes}, nil
}

func withCause(code *Error, cause error) *Error {
	return &Error{Code: code.Code, Disposition: code.Disposition, Message: code.Message, cause: cause}
}

// Call sends one request and decodes the result into result. An agent
// refusal is returned as *Error; when the agent also sent a result with the
// refusal, it is decoded too.
func (c *Client) Call(ctx context.Context, method string, params, result any) error {
	encoded, err := json.Marshal(params)
	if err != nil {
		return withCause(c.codes.BadInput, err)
	}
	request, err := json.Marshal(Request{Schema: c.schema, Method: method, Params: encoded})
	if err != nil {
		return withCause(c.codes.BadInput, err)
	}
	if len(request) >= MaxRequestBytes {
		return c.codes.BadInput
	}
	deadline := time.Now().Add(c.timeout)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	dialer := net.Dialer{Deadline: deadline}
	connection, err := dialer.DialContext(ctx, "unix", c.path)
	if err != nil {
		return withCause(c.codes.Unavailable, err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(deadline)
	if _, err := connection.Write(append(request, '\n')); err != nil {
		return withCause(c.codes.Unavailable, err)
	}
	line, err := bufio.NewReaderSize(io.LimitReader(connection, MaxResponseBytes+1), 64<<10).ReadBytes('\n')
	if err != nil {
		return withCause(c.codes.Unavailable, err)
	}
	var response struct {
		Schema string          `json:"schema"`
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  *Error          `json:"error"`
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil || response.Schema != c.schema {
		return withCause(c.codes.Internal, err)
	}
	if len(response.Result) != 0 && result != nil {
		if err := json.Unmarshal(response.Result, result); err != nil {
			return withCause(c.codes.Internal, err)
		}
	}
	if !response.OK {
		if response.Error == nil {
			return c.codes.Internal
		}
		return response.Error
	}
	return nil
}
