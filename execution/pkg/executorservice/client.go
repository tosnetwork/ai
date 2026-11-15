package executorservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"path/filepath"
	"time"

	"github.com/tosnetwork/ai/execution/pkg/softwarework"
)

// StatusError is a request the service answered with a status other than
// StatusOK. Compare with errors.Is against the Err values below.
type StatusError struct {
	Status Status
}

func (e *StatusError) Error() string {
	if message, known := statusMessages[e.Status]; known {
		return "executor service: " + message
	}
	return "executor service: unknown status"
}

// Is matches any StatusError of the same status.
func (e *StatusError) Is(target error) bool {
	other, ok := target.(*StatusError)
	return ok && other.Status == e.Status
}

var (
	ErrNotAllowed         error = &StatusError{StatusNotAllowed}
	ErrInvalidRequest     error = &StatusError{StatusInvalidRequest}
	ErrLimitsRefused      error = &StatusError{StatusLimitsRefused}
	ErrTimeout            error = &StatusError{StatusTimeout}
	ErrBusy               error = &StatusError{StatusBusy}
	ErrInProgress         error = &StatusError{StatusInProgress}
	ErrAmbiguous          error = &StatusError{StatusAmbiguous}
	ErrConflict           error = &StatusError{StatusConflict}
	ErrExecutionFailed    error = &StatusError{StatusExecutionFailed}
	ErrUnavailable        error = &StatusError{StatusUnavailable}
	ErrStorageFull        error = &StatusError{StatusStorageFull}
	ErrRetentionFull      error = &StatusError{StatusRetentionFull}
	ErrObjectsUnavailable error = &StatusError{StatusObjectsUnavailable}
)

// ErrProtocol reports a response that is malformed, oversize, of another
// version, or that does not match the request or its own digests. Nothing
// in such a response is trusted.
var ErrProtocol = errors.New("executor service: the response violates the protocol")

// ErrServerIdentity reports a socket served by another uid than expected.
var ErrServerIdentity = errors.New("executor service: the socket is served by an unexpected uid")

// ClientConfig names the service socket and who must be serving it.
type ClientConfig struct {
	// SocketPath is the canonical absolute path of the service socket.
	SocketPath string
	// ServerUID is the uid the listening process must have, checked from
	// the kernel's peer credential on every connection. The zero value is
	// root, the production service identity.
	ServerUID uint32
	// Timeout bounds a call whose context has no deadline of its own, so a
	// stalled service cannot hold a caller forever. Zero selects
	// DefaultClientTimeout; a context deadline always takes precedence.
	Timeout time.Duration
}

// DefaultClientTimeout covers the frozen wall clock of a job with room for
// staging, cleanup and the transfer of its objects.
const DefaultClientTimeout = 10 * time.Minute

// Client calls the executor service. It holds no connection; every call
// opens one. It is safe for concurrent use.
type Client struct {
	config ClientConfig
}

func NewClient(config ClientConfig) (*Client, error) {
	if !filepath.IsAbs(config.SocketPath) || filepath.Clean(config.SocketPath) != config.SocketPath {
		return nil, errors.New("executor service: the socket path must be canonical and absolute")
	}
	if config.Timeout < 0 {
		return nil, errors.New("executor service: the client timeout must not be negative")
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultClientTimeout
	}
	return &Client{config: config}, nil
}

// ExecuteRequest is one frozen software-work job. Every field is required
// except RetainUntilUnix.
type ExecuteRequest struct {
	// ExecutionID keys the at-most-once journal (sha256:<64 hex>).
	ExecutionID string
	// QuoteCommitment and InputDigest are bound into the outcome.
	QuoteCommitment string
	InputDigest     string
	// ManifestDigest is the published manifest the sandbox is bound to.
	ManifestDigest string
	// Limits are the manifest's limits; none may be zero or looser than
	// the frozen preset.
	Limits Limits
	// RetainUntilUnix is the last unix second the service should keep its
	// copy of the job's objects. Zero asks for the service default; the
	// service never keeps them past its maximum after completion.
	RetainUntilUnix int64
	// SourceArchive is the deterministic USTAR source archive.
	SourceArchive []byte
}

// ExecuteResult is a recorded outcome with the caller's own copy of its
// objects, each verified against the digest the outcome names.
type ExecuteResult struct {
	Outcome  softwarework.Outcome
	Artifact []byte
	Report   []byte
	// RetainUntilUnix is the last unix second the service keeps its own
	// copy of the objects for this request: the requested deadline, the
	// service default when none was requested, never later than the
	// service maximum after completion.
	RetainUntilUnix int64
}

// Describe returns the service identity, frozen image and limits, and
// whether its backend is ready.
func (c *Client) Describe(ctx context.Context) (Description, error) {
	ctx, cancel := c.bounded(ctx)
	defer cancel()
	conn, stop, err := c.dial(ctx)
	if err != nil {
		return Description{}, err
	}
	defer stop()
	response, err := exchange(conn, requestHeader{Schema: RequestSchema, Operation: OperationDescribe}, nil)
	if err != nil {
		return Description{}, contextError(ctx, err)
	}
	if response.Describe == nil || response.Outcome != nil || response.RetainUntilUnix != 0 || requireEOF(conn) != nil {
		return Description{}, ErrProtocol
	}
	return *response.Describe, nil
}

// Execute runs request, or returns its recorded outcome if it already ran.
// The outcome must name the frozen image as its toolchain; anything else is
// ErrProtocol.
//
// It returns a *StatusError for every answer other than success: ErrBusy
// and ErrUnavailable claimed nothing and may be retried; ErrInProgress means
// the execution is running and the same request, sent again later, returns
// its outcome; ErrAmbiguous and ErrExecutionFailed mean the execution id is
// spent and must never be attested. If ctx ends or the connection drops
// after the request was sent, the run is not cancelled: send the same
// request again to learn its outcome.
func (c *Client) Execute(ctx context.Context, request ExecuteRequest) (ExecuteResult, error) {
	if len(request.SourceArchive) == 0 || len(request.SourceArchive) > MaxSourceBytes {
		return ExecuteResult{}, errors.New("executor service: the source archive is empty or over the input bound")
	}
	sourceDigest := digestOf(request.SourceArchive)
	ctx, cancel := c.bounded(ctx)
	defer cancel()
	conn, stop, err := c.dial(ctx)
	if err != nil {
		return ExecuteResult{}, err
	}
	defer stop()
	response, err := exchange(conn, requestHeader{Schema: RequestSchema, Operation: OperationExecute,
		Execute: &executeHeader{ExecutionID: request.ExecutionID, QuoteCommitment: request.QuoteCommitment,
			InputDigest: request.InputDigest, ManifestDigest: request.ManifestDigest, Limits: request.Limits,
			RetainUntilUnix: request.RetainUntilUnix, SourceDigest: sourceDigest,
			SourceBytes: uint64(len(request.SourceArchive))}}, request.SourceArchive)
	if err != nil {
		return ExecuteResult{}, contextError(ctx, err)
	}
	if response.Outcome == nil || response.Describe != nil || response.RetainUntilUnix <= 0 {
		return ExecuteResult{}, ErrProtocol
	}
	outcome := *response.Outcome
	// The outcome must be a success of exactly this request before any of
	// its bytes are read.
	if outcome.ExecutionID != request.ExecutionID || outcome.QuoteCommitment != request.QuoteCommitment ||
		outcome.InputDigest != request.InputDigest || outcome.SourceDigest != sourceDigest ||
		outcome.SandboxDigest != request.ManifestDigest || outcome.ToolchainDigest != softwarework.FrozenV1ImageDigest ||
		outcome.ExitCode != 0 || outcome.CompletedAtUnix == 0 ||
		outcome.Artifact.MediaType != softwarework.ArtifactMediaType || outcome.Report.MediaType != softwarework.ReportMediaType ||
		outcome.Artifact.SizeBytes > MaxObjectBytes || outcome.Report.SizeBytes > MaxObjectBytes {
		return ExecuteResult{}, ErrProtocol
	}
	artifact := make([]byte, outcome.Artifact.SizeBytes)
	report := make([]byte, outcome.Report.SizeBytes)
	if _, err := io.ReadFull(conn, artifact); err != nil {
		return ExecuteResult{}, contextError(ctx, ErrProtocol)
	}
	if _, err := io.ReadFull(conn, report); err != nil {
		return ExecuteResult{}, contextError(ctx, ErrProtocol)
	}
	if requireEOF(conn) != nil || digestOf(artifact) != outcome.Artifact.Digest || digestOf(report) != outcome.Report.Digest {
		return ExecuteResult{}, contextError(ctx, ErrProtocol)
	}
	return ExecuteResult{Outcome: outcome, Artifact: artifact, Report: report, RetainUntilUnix: response.RetainUntilUnix}, nil
}

// bounded gives a call without a deadline the client's own.
func (c *Client) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	if c == nil || ctx == nil {
		return ctx, func() {}
	}
	if _, set := ctx.Deadline(); set {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.config.Timeout)
}

// dial connects and proves the listener's uid. stop closes the connection
// and detaches it from ctx.
func (c *Client) dial(ctx context.Context) (*net.UnixConn, func(), error) {
	if c == nil || ctx == nil {
		return nil, nil, errors.New("executor service: invalid client call")
	}
	var dialer net.Dialer
	raw, err := dialer.DialContext(ctx, "unix", c.config.SocketPath)
	if err != nil {
		return nil, nil, contextError(ctx, errors.New("executor service: connect to the service socket"))
	}
	conn, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return nil, nil, errors.New("executor service: connect to the service socket")
	}
	if uid, err := peerUID(conn); err != nil || uid != c.config.ServerUID {
		_ = conn.Close()
		return nil, nil, ErrServerIdentity
	}
	// Closing the connection when ctx ends unblocks any read or write.
	detach := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return conn, func() {
		detach()
		_ = conn.Close()
	}, nil
}

// exchange sends one request and reads the response header. The service may
// refuse a request before reading all of it, so a failed write still reads
// the answer that explains it.
func exchange(conn *net.UnixConn, header requestHeader, payload []byte) (responseHeader, error) {
	frame, err := encodeHeader(header, MaxRequestHeaderBytes)
	if err != nil {
		return responseHeader{}, errors.New("executor service: the request header is oversize")
	}
	_, writeErr := conn.Write(frame)
	if writeErr == nil && len(payload) != 0 {
		_, writeErr = conn.Write(payload)
	}
	if writeErr == nil {
		writeErr = conn.CloseWrite()
	}
	raw, err := readHeader(conn, MaxResponseHeaderBytes)
	if err != nil {
		if writeErr != nil {
			return responseHeader{}, errors.New("executor service: the request could not be sent")
		}
		return responseHeader{}, ErrProtocol
	}
	var response responseHeader
	if err := decodeStrict(raw, &response); err != nil || response.Schema != ResponseSchema {
		return responseHeader{}, ErrProtocol
	}
	if response.Status != StatusOK {
		if _, known := statusMessages[response.Status]; !known {
			return responseHeader{}, ErrProtocol
		}
		return responseHeader{}, &StatusError{Status: response.Status}
	}
	return response, nil
}

// contextError prefers the context's own error once it has ended, since the
// connection is closed on its behalf.
func contextError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}

func digestOf(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
