package buyeragent

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

// MaxResponseBytes bounds one answer the client reads. The largest answer
// is a page of purchases with their member lists.
const MaxResponseBytes = 16 << 20

// Client calls the agent socket. Authority is never the client's to claim:
// the agent decides each caller's role from the kernel-reported uid.
type Client struct {
	path    string
	timeout time.Duration
}

// NewClient names the agent socket. timeout bounds one call and must cover
// the longest wait a request asks for.
func NewClient(socketPath string, timeout time.Duration) (*Client, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath {
		return nil, errors.New("the agent socket path must be absolute and clean")
	}
	if timeout <= 0 || timeout > 10*time.Minute {
		return nil, errors.New("the agent call timeout must be positive and at most 10 minutes")
	}
	return &Client{path: socketPath, timeout: timeout}, nil
}

// Call sends one request and decodes the result into result. An agent
// refusal is returned as *Error; when the agent also sent a result with the
// refusal, it is decoded too.
func (c *Client) Call(ctx context.Context, method string, params, result any) error {
	encoded, err := json.Marshal(params)
	if err != nil {
		return err
	}
	request, err := json.Marshal(Request{Schema: APISchema, Method: method, Params: encoded})
	if err != nil {
		return err
	}
	if len(request) >= MaxRequestBytes {
		return refusal(CodeBadInput, "the request exceeds the 2 MiB bound", nil)
	}
	deadline := time.Now().Add(c.timeout)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	dialer := net.Dialer{Deadline: deadline}
	connection, err := dialer.DialContext(ctx, "unix", c.path)
	if err != nil {
		return refusal(CodeAgentUnavailable, "the buyer agent socket does not answer", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(deadline)
	if _, err := connection.Write(append(request, '\n')); err != nil {
		return refusal(CodeAgentUnavailable, "the buyer agent socket does not answer", err)
	}
	line, err := bufio.NewReaderSize(io.LimitReader(connection, MaxResponseBytes+1), 64<<10).ReadBytes('\n')
	if err != nil {
		return refusal(CodeAgentUnavailable, "the buyer agent closed the connection without an answer", err)
	}
	var response struct {
		Schema string          `json:"schema"`
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  *Error          `json:"error"`
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil || response.Schema != APISchema {
		return refusal(CodeInternal, "the buyer agent sent an answer that does not decode", err)
	}
	if len(response.Result) != 0 && result != nil {
		if err := json.Unmarshal(response.Result, result); err != nil {
			return refusal(CodeInternal, "the buyer agent sent a result that does not decode", err)
		}
	}
	if !response.OK {
		if response.Error == nil {
			return refusal(CodeInternal, "the buyer agent refused without an error", nil)
		}
		return response.Error
	}
	return nil
}
