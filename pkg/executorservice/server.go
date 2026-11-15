package executorservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/tosnetwork/tos-ai/internal/nilcheck"
	"github.com/tosnetwork/tos-ai/pkg/artifactstore"
	"github.com/tosnetwork/tos-ai/pkg/executor"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
)

const (
	DefaultMaxConnections = 8
	MaxConnectionsHard    = 64
	DefaultMaxExecutions  = 1
	MaxExecutionsHard     = 8
	// MinInFlightBytes is the smallest byte budget that can carry one
	// request and one response at their bounds.
	MinInFlightBytes     = uint64(MaxSourceBytes) + 2*MaxObjectBytes
	DefaultInFlightBytes = uint64(256 << 20)
	MaxInFlightBytesHard = uint64(1 << 30)

	// overflowID is what the kernel reports for a uid or gid that has no
	// mapping in this user namespace, and invalidID is the "unchanged"
	// marker of chown; neither names a real identity.
	overflowID = uint32(65534)
	invalidID  = ^uint32(0)

	// DefaultRetention is how long a job's objects are kept when its
	// request states no deadline, and DefaultMaxRetention the longest any
	// request can keep them, both counted from the job's completion.
	DefaultRetention    = 7 * 24 * time.Hour
	DefaultMaxRetention = 31 * 24 * time.Hour
	MaxRetentionHard    = 366 * 24 * time.Hour

	DefaultHeaderTimeout  = 10 * time.Second
	DefaultPayloadTimeout = 30 * time.Second
	DefaultWriteTimeout   = 60 * time.Second
	DefaultReadyTimeout   = 10 * time.Second
	maxTimeout            = 10 * time.Minute
	// refusalWriteTimeout bounds the reply to a peer that is refused before
	// its request is read.
	refusalWriteTimeout = time.Second
)

// Identity names the server build in a Description.
type Identity struct {
	Version string
	Commit  string
}

// Config assembles a Server. The executor, store and journal are the ones a
// one-shot run of the frozen job would open; the server owns them for its
// lifetime.
type Config struct {
	// AllowedUID is the one peer uid served; nil is refused. The service
	// keeps no per-caller separation (execution identities, retention and
	// slots are shared), so it serves exactly one caller identity and has
	// no "any local user" mode.
	AllowedUID *uint32
	// Executor must already be bound to the frozen policy.
	Executor executor.Executor
	Store    *artifactstore.Store
	Journal  *softwarework.Journal
	// Ready is the backend readiness probe; it gates new runs and is
	// reported by describe.
	Ready    func(context.Context) error
	Identity Identity

	// MaxConnections bounds requests handled at once, MaxExecutions jobs
	// running at once and MaxInFlightBytes the source and object bytes held
	// for all of them. Zero selects the default.
	MaxConnections   int
	MaxExecutions    int
	MaxInFlightBytes uint64

	// HeaderTimeout and PayloadTimeout bound reading a request,
	// WriteTimeout writing a response and ReadyTimeout one readiness probe.
	// Zero selects the default.
	HeaderTimeout  time.Duration
	PayloadTimeout time.Duration
	WriteTimeout   time.Duration
	ReadyTimeout   time.Duration

	// MinFreeBytes and MinFreeInodes are what the state filesystem, which
	// also holds the staged workspaces, must keep free for a new run to be
	// accepted, as measured by FreeSpace. A floor needs the probe.
	MinFreeBytes  uint64
	MinFreeInodes uint64
	FreeSpace     func() (FreeSpace, error)

	// DefaultRetention and MaxRetention bound how long a job's objects are
	// kept after it completes. A service job always gets a deadline. Zero
	// selects the default.
	DefaultRetention time.Duration
	MaxRetention     time.Duration

	// Logf receives one line per refused or completed request. Lines hold
	// only validated digests, the peer uid and server-side error text.
	Logf func(format string, arguments ...any)
}

// FreeSpace is what an unprivileged writer could still use on a filesystem.
type FreeSpace struct {
	Bytes  uint64
	Inodes uint64
}

// Server serves the executor operation on one Unix socket.
type Server struct {
	config  Config
	allowed uint32
	base    context.Context
	cancel  context.CancelFunc

	mutex       sync.Mutex
	listener    *net.UnixListener
	closing     bool
	connections int
	flights     map[string]*flight
	budgetFree  uint64
	// retentionHeld counts retention records promised to admitted jobs
	// that have not written theirs yet.
	retentionHeld int
	handlers      sync.WaitGroup
	runs          sync.WaitGroup

	// afterAmbiguousRead, set only by tests, runs between a journal read
	// that found a claim without an outcome and the check whether that
	// claim is a run in progress.
	afterAmbiguousRead func()
}

// flight is one running execution. Its result is set before done closes.
type flight struct {
	done     chan struct{}
	status   Status
	outcome  softwarework.Outcome
	retained int64
}

func NewServer(config Config) (*Server, error) {
	if config.AllowedUID == nil {
		return nil, errors.New("executor service needs its one allowed uid")
	}
	// A peer whose uid has no mapping in this user namespace is reported
	// as the overflow uid, so allowing it would allow callers of unknown
	// identity.
	if *config.AllowedUID == overflowID || *config.AllowedUID == invalidID {
		return nil, errors.New("executor service allowed uid is the overflow or invalid uid")
	}
	if nilcheck.IsNil(config.Executor) || config.Store == nil || config.Journal == nil || config.Ready == nil {
		return nil, errors.New("executor service needs an executor, store, journal and readiness probe")
	}
	if (config.MinFreeBytes != 0 || config.MinFreeInodes != 0) != (config.FreeSpace != nil) {
		return nil, errors.New("executor service free-space floor needs both a floor and a probe")
	}
	if config.DefaultRetention == 0 {
		config.DefaultRetention = DefaultRetention
	}
	if config.MaxRetention == 0 {
		config.MaxRetention = DefaultMaxRetention
	}
	if config.DefaultRetention < time.Second || config.DefaultRetention > config.MaxRetention ||
		config.MaxRetention > MaxRetentionHard {
		return nil, errors.New("executor service retention is outside its limits")
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = DefaultMaxConnections
	}
	if config.MaxExecutions == 0 {
		config.MaxExecutions = DefaultMaxExecutions
	}
	if config.MaxInFlightBytes == 0 {
		config.MaxInFlightBytes = DefaultInFlightBytes
	}
	if config.MaxConnections < 0 || config.MaxConnections > MaxConnectionsHard ||
		config.MaxExecutions < 0 || config.MaxExecutions > MaxExecutionsHard ||
		config.MaxInFlightBytes < MinInFlightBytes || config.MaxInFlightBytes > MaxInFlightBytesHard {
		return nil, errors.New("executor service bounds are outside their limits")
	}
	for _, timeout := range []*time.Duration{&config.HeaderTimeout, &config.PayloadTimeout, &config.WriteTimeout, &config.ReadyTimeout} {
		if *timeout < 0 || *timeout > maxTimeout {
			return nil, errors.New("executor service timeouts are outside their limits")
		}
	}
	if config.HeaderTimeout == 0 {
		config.HeaderTimeout = DefaultHeaderTimeout
	}
	if config.PayloadTimeout == 0 {
		config.PayloadTimeout = DefaultPayloadTimeout
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = DefaultWriteTimeout
	}
	if config.ReadyTimeout == 0 {
		config.ReadyTimeout = DefaultReadyTimeout
	}
	if config.Logf == nil {
		config.Logf = func(string, ...any) {}
	}
	allowed := *config.AllowedUID
	config.AllowedUID = nil
	base, cancel := context.WithCancel(context.Background())
	return &Server{config: config, allowed: allowed, base: base, cancel: cancel,
		flights: make(map[string]*flight, config.MaxExecutions), budgetFree: config.MaxInFlightBytes}, nil
}

// Serve accepts connections until Shutdown. It returns nil after a Shutdown
// and the accept error otherwise.
func (s *Server) Serve(listener *net.UnixListener) error {
	if s == nil || listener == nil {
		return errors.New("invalid executor service listener")
	}
	s.mutex.Lock()
	if s.listener != nil {
		s.mutex.Unlock()
		return errors.New("executor service is already serving")
	}
	if s.closing {
		// Shutdown came first: there is nothing to serve.
		s.mutex.Unlock()
		_ = listener.Close()
		return nil
	}
	s.listener = listener
	s.mutex.Unlock()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			s.mutex.Lock()
			closing := s.closing
			s.mutex.Unlock()
			if closing {
				return nil
			}
			return errors.New("executor service accept failed")
		}
		s.mutex.Lock()
		admitted := !s.closing && s.connections < s.config.MaxConnections
		if admitted {
			s.connections++
			s.handlers.Add(1)
		}
		s.mutex.Unlock()
		if !admitted {
			// The reply is far smaller than the socket buffer, so this
			// never holds the accept loop.
			s.respond(conn, refusalWriteTimeout, responseHeader{Status: StatusBusy}, nil, nil)
			_ = conn.Close()
			continue
		}
		go func() {
			defer s.handlers.Done()
			defer func() {
				s.mutex.Lock()
				s.connections--
				s.mutex.Unlock()
			}()
			defer conn.Close()
			s.handle(conn)
		}()
	}
}

// Shutdown stops accepting and waits for running executions to record their
// outcome. If ctx ends first the remaining executions are cancelled, which
// leaves their identities ambiguous, and Shutdown waits for the backend to
// clean them up before returning ctx's error.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || ctx == nil {
		return errors.New("invalid executor service shutdown")
	}
	s.mutex.Lock()
	s.closing = true
	listener := s.listener
	s.mutex.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	finished := make(chan struct{})
	go func() {
		s.runs.Wait()
		s.handlers.Wait()
		close(finished)
	}()
	select {
	case <-finished:
		s.cancel()
		return nil
	case <-ctx.Done():
		s.cancel()
		s.runs.Wait()
		return ctx.Err()
	}
}

func (s *Server) handle(conn *net.UnixConn) {
	uid, err := peerUID(conn)
	if err != nil {
		s.config.Logf("refused: peer credential unavailable")
		s.respond(conn, refusalWriteTimeout, responseHeader{Status: StatusNotAllowed}, nil, nil)
		return
	}
	if uid != s.allowed {
		s.config.Logf("refused: peer_uid=%d is not allowed", uid)
		s.respond(conn, refusalWriteTimeout, responseHeader{Status: StatusNotAllowed}, nil, nil)
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(s.config.HeaderTimeout))
	raw, err := readHeader(conn, MaxRequestHeaderBytes)
	if err != nil {
		s.refuse(conn, uid, readStatus(err))
		return
	}
	var header requestHeader
	if err := decodeStrict(raw, &header); err != nil || header.Schema != RequestSchema {
		s.refuse(conn, uid, StatusInvalidRequest)
		return
	}
	switch {
	case header.Operation == OperationDescribe && header.Execute == nil:
		if err := requireEOF(conn); err != nil {
			s.refuse(conn, uid, readStatus(err))
			return
		}
		description := s.describe()
		s.respond(conn, s.config.WriteTimeout, responseHeader{Status: StatusOK, Describe: &description}, nil, nil)
	case header.Operation == OperationExecute && header.Execute != nil:
		s.handleExecute(conn, uid, *header.Execute)
	default:
		s.refuse(conn, uid, StatusInvalidRequest)
	}
}

func (s *Server) refuse(conn *net.UnixConn, uid uint32, status Status) {
	s.config.Logf("refused: peer_uid=%d status=%s", uid, status)
	s.respond(conn, s.config.WriteTimeout, responseHeader{Status: status}, nil, nil)
}

// readStatus classifies a failed request read: a deadline is the peer's
// slowness, anything else a malformed request.
func readStatus(err error) Status {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return StatusTimeout
	}
	return StatusInvalidRequest
}

func (s *Server) describe() Description {
	ctx, cancel := context.WithTimeout(s.base, s.config.ReadyTimeout)
	defer cancel()
	return Description{
		Version: s.config.Identity.Version, Commit: s.config.Identity.Commit,
		ImageDigest: softwarework.FrozenV1ImageDigest, ImageReference: softwarework.FrozenV1ImageReference,
		Limits: FrozenLimits(), PIDs: softwarework.FrozenV1Limits().PIDs,
		MaxSourceBytes: MaxSourceBytes, MaxObjectBytes: MaxObjectBytes,
		MaxExecutions:           s.config.MaxExecutions,
		DefaultRetentionSeconds: uint64(s.config.DefaultRetention / time.Second),
		MaxRetentionSeconds:     uint64(s.config.MaxRetention / time.Second),
		Ready:                   s.config.Ready(ctx) == nil,
	}
}

func (s *Server) handleExecute(conn *net.UnixConn, uid uint32, header executeHeader) {
	// Everything the header states is checked before a single payload byte
	// is read or reserved.
	if !sha256Pattern.MatchString(header.ExecutionID) || !quotePattern.MatchString(header.QuoteCommitment) ||
		!sha256Pattern.MatchString(header.InputDigest) || !sha256Pattern.MatchString(header.SourceDigest) ||
		header.RetainUntilUnix < 0 || header.SourceBytes == 0 || header.SourceBytes > MaxSourceBytes {
		s.refuse(conn, uid, StatusInvalidRequest)
		return
	}
	contract, err := softwarework.ManifestContract(header.ManifestDigest, header.Limits.manifest())
	var looser *softwarework.LimitError
	if errors.As(err, &looser) {
		s.refuse(conn, uid, StatusLimitsRefused)
		return
	}
	if err != nil {
		s.refuse(conn, uid, StatusInvalidRequest)
		return
	}
	if !s.reserve(header.SourceBytes) {
		s.refuse(conn, uid, StatusBusy)
		return
	}
	sourceHeld := true
	defer func() {
		if sourceHeld {
			s.release(header.SourceBytes)
		}
	}()
	_ = conn.SetReadDeadline(time.Now().Add(s.config.PayloadTimeout))
	source := make([]byte, header.SourceBytes)
	if _, err := io.ReadFull(conn, source); err != nil {
		s.refuse(conn, uid, readStatus(err))
		return
	}
	if err := requireEOF(conn); err != nil {
		s.refuse(conn, uid, readStatus(err))
		return
	}
	if digest := sha256.Sum256(source); "sha256:"+hex.EncodeToString(digest[:]) != header.SourceDigest {
		s.refuse(conn, uid, StatusInvalidRequest)
		return
	}
	// The limits come with the request here, so they are part of what the
	// execution identity is bound to.
	runner, err := softwarework.NewRunner(s.config.Executor, s.config.Store, s.config.Journal, contract, softwarework.BindLimits())
	if err != nil {
		s.refuse(conn, uid, StatusUnavailable)
		return
	}
	request := softwarework.Request{QuoteCommitment: header.QuoteCommitment, ExecutionID: header.ExecutionID,
		InputDigest: header.InputDigest, SourceDigest: header.SourceDigest, SourceArchive: source}
	status, outcome, retained, started := s.execute(runner, request, header.RetainUntilUnix)
	if started {
		// The run owns the source reservation and releases it when it ends.
		sourceHeld = false
	}
	if status != StatusOK {
		s.config.Logf("execute: peer_uid=%d execution_id=%s status=%s", uid, header.ExecutionID, status)
		s.respond(conn, s.config.WriteTimeout, responseHeader{Status: status}, nil, nil)
		return
	}
	if sourceHeld {
		s.release(header.SourceBytes)
		sourceHeld = false
	}
	s.deliver(conn, uid, outcome, retained)
}

// execute answers request from the journal when it is recorded and runs it
// otherwise. It returns the retention deadline given to the job's objects,
// and started reports that a run took over the source reservation.
func (s *Server) execute(runner *softwarework.Runner, request softwarework.Request, requested int64) (Status, softwarework.Outcome, int64, bool) {
	refuse := func(status Status) (Status, softwarework.Outcome, int64, bool) {
		return status, softwarework.Outcome{}, 0, false
	}
	if s.flying(request.ExecutionID) {
		return refuse(StatusInProgress)
	}
	outcome, recorded, err := runner.Recorded(request)
	if errors.Is(err, softwarework.ErrAmbiguous) {
		// A claim without an outcome is also what a run in progress looks
		// like, and a request that passed the check above may have read
		// the journal just after another one claimed it. A flight is
		// registered before its claim and removed after its outcome is
		// journaled, so if one is flying now this run is in progress, and
		// if none is the journal read below is final.
		if s.afterAmbiguousRead != nil {
			s.afterAmbiguousRead()
		}
		if s.flying(request.ExecutionID) {
			return refuse(StatusInProgress)
		}
		outcome, recorded, err = runner.Recorded(request)
	}
	if err != nil {
		return refuse(s.runnerStatus(request.ExecutionID, err, StatusUnavailable))
	}
	if recorded {
		// A repeated request may extend the retention of the recorded
		// objects within the same bound; it never shortens it and never
		// runs anything.
		retained, status := s.retain(outcome, requested)
		if status != StatusOK {
			return refuse(status)
		}
		return StatusOK, outcome, retained, false
	}
	// A new run. Every reason to refuse it is checked before the execution
	// identity is claimed, because a claim without an outcome is ambiguous
	// for good.
	ctx, cancel := context.WithTimeout(s.base, s.config.ReadyTimeout)
	err = s.config.Ready(ctx)
	cancel()
	if err != nil {
		s.config.Logf("execute: execution_id=%s backend not ready: %v", request.ExecutionID, err)
		return refuse(StatusUnavailable)
	}
	if s.config.FreeSpace != nil {
		free, err := s.config.FreeSpace()
		if err != nil {
			return refuse(StatusUnavailable)
		}
		if free.Bytes < s.config.MinFreeBytes || free.Inodes < s.config.MinFreeInodes {
			return refuse(StatusStorageFull)
		}
	}
	// Every service job is given a deadline, so there must be room for one,
	// counting the jobs that were admitted before this one and have not
	// recorded theirs yet. The slot is held from here until the run has
	// retained its objects or ended without doing so; without it two jobs
	// admitted against the last free record would both run and the second
	// could not be retained.
	s.mutex.Lock()
	s.retentionHeld++
	needed := s.retentionHeld
	s.mutex.Unlock()
	admitted := false
	defer func() {
		if !admitted {
			s.releaseRetention()
		}
	}()
	if err := s.config.Store.CheckCapacity(s.base, needed); errors.Is(err, artifactstore.ErrRetentionFull) {
		return refuse(StatusRetentionFull)
	} else if err != nil {
		return refuse(StatusUnavailable)
	}
	s.mutex.Lock()
	if s.closing {
		s.mutex.Unlock()
		return refuse(StatusUnavailable)
	}
	if _, running := s.flights[request.ExecutionID]; running {
		s.mutex.Unlock()
		return refuse(StatusInProgress)
	}
	if len(s.flights) >= s.config.MaxExecutions {
		s.mutex.Unlock()
		return refuse(StatusBusy)
	}
	admitted = true
	current := &flight{done: make(chan struct{})}
	s.flights[request.ExecutionID] = current
	s.runs.Add(1)
	s.mutex.Unlock()
	// The run belongs to the server, not to the connection that asked for
	// it: a caller that goes away cannot cancel it, so its outcome is
	// always journaled and a repeated request finds it.
	go func() {
		defer s.runs.Done()
		current.status, current.outcome, current.retained = s.run(runner, request, requested)
		// The job's record is in the store now, or the job will never
		// have one: either way its held slot is no longer needed.
		s.releaseRetention()
		s.release(uint64(len(request.SourceArchive)))
		s.mutex.Lock()
		delete(s.flights, request.ExecutionID)
		s.mutex.Unlock()
		close(current.done)
	}()
	<-current.done
	return current.status, current.outcome, current.retained, true
}

func (s *Server) releaseRetention() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.retentionHeld > 0 {
		s.retentionHeld--
	}
}

func (s *Server) flying(executionID string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	_, running := s.flights[executionID]
	return running
}

func (s *Server) run(runner *softwarework.Runner, request softwarework.Request, requested int64) (Status, softwarework.Outcome, int64) {
	outcome, err := runner.Execute(s.base, request)
	if err != nil {
		return s.runnerStatus(request.ExecutionID, err, StatusExecutionFailed), softwarework.Outcome{}, 0
	}
	retained, status := s.retain(outcome, requested)
	if status != StatusOK {
		return status, softwarework.Outcome{}, 0
	}
	return StatusOK, outcome, retained
}

func (s *Server) runnerStatus(executionID string, err error, fallback Status) Status {
	switch {
	case errors.Is(err, softwarework.ErrAmbiguous):
		return StatusAmbiguous
	case errors.Is(err, softwarework.ErrConflict):
		return StatusConflict
	case errors.Is(err, softwarework.ErrRequestMismatch):
		return StatusInvalidRequest
	}
	s.config.Logf("execute: execution_id=%s %s: %v", executionID, fallback, err)
	return fallback
}

// retentionDeadline is the last second the job's objects are kept: what the
// request asked for, the server default when it asked for nothing, and never
// later than the server maximum. Both are counted from the job's completion,
// so repeating a request cannot push the deadline out indefinitely.
func (s *Server) retentionDeadline(completedAt uint64, requested int64) (int64, bool) {
	maximum := uint64(s.config.MaxRetention / time.Second)
	if completedAt == 0 || completedAt > math.MaxInt64-maximum {
		return 0, false
	}
	latest := int64(completedAt + maximum)
	switch {
	case requested == 0:
		return int64(completedAt + uint64(s.config.DefaultRetention/time.Second)), true
	case requested > latest:
		return latest, true
	}
	return requested, true
}

// retain gives the job's objects their deadline and returns it. The outcome
// is already journaled, so a failure here is answered by asking again.
func (s *Server) retain(outcome softwarework.Outcome, requested int64) (int64, Status) {
	deadline, ok := s.retentionDeadline(outcome.CompletedAtUnix, requested)
	if !ok {
		return 0, StatusUnavailable
	}
	err := s.config.Store.Retain(s.base, outcome.ExecutionID, time.Unix(deadline, 0),
		[]string{outcome.Artifact.Digest, outcome.Report.Digest})
	switch {
	case err == nil:
		return deadline, StatusOK
	case errors.Is(err, artifactstore.ErrRetentionFull):
		return 0, StatusRetentionFull
	case errors.Is(err, artifactstore.ErrRetentionBusy):
		return 0, StatusUnavailable
	}
	s.config.Logf("execute: execution_id=%s retention: %v", outcome.ExecutionID, err)
	return 0, StatusObjectsUnavailable
}

// deliver sends the outcome with its two objects, read back from the store
// and held against the byte budget while they are written.
func (s *Server) deliver(conn *net.UnixConn, uid uint32, outcome softwarework.Outcome, retained int64) {
	if outcome.Artifact.SizeBytes > MaxObjectBytes || outcome.Report.SizeBytes > MaxObjectBytes {
		s.refuse(conn, uid, StatusObjectsUnavailable)
		return
	}
	// Each size is at most MaxObjectBytes, so the sum cannot overflow.
	total := outcome.Artifact.SizeBytes + outcome.Report.SizeBytes
	if !s.reserve(total) {
		s.refuse(conn, uid, StatusBusy)
		return
	}
	defer s.release(total)
	artifact, artifactErr := s.config.Store.Get(s.base, outcome.Artifact.Digest)
	report, reportErr := s.config.Store.Get(s.base, outcome.Report.Digest)
	if artifactErr != nil || reportErr != nil ||
		uint64(len(artifact)) != outcome.Artifact.SizeBytes || uint64(len(report)) != outcome.Report.SizeBytes {
		s.refuse(conn, uid, StatusObjectsUnavailable)
		return
	}
	s.config.Logf("execute: peer_uid=%d execution_id=%s status=%s", uid, outcome.ExecutionID, StatusOK)
	s.respond(conn, s.config.WriteTimeout, responseHeader{Status: StatusOK, Outcome: &outcome, RetainUntilUnix: retained}, artifact, report)
}

// respond writes one response under a write deadline. A peer that does not
// read it loses it; the journal still holds the outcome.
func (s *Server) respond(conn *net.UnixConn, timeout time.Duration, header responseHeader, artifact, report []byte) {
	header.Schema = ResponseSchema
	if header.Status != StatusOK {
		header.Error = statusMessages[header.Status]
	}
	frame, err := encodeHeader(header, MaxResponseHeaderBytes)
	if err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	for _, part := range [][]byte{frame, artifact, report} {
		if len(part) == 0 {
			continue
		}
		if _, err := conn.Write(part); err != nil {
			return
		}
	}
	_ = conn.CloseWrite()
}

// reserve takes n bytes from the in-flight budget, or reports that the
// budget cannot carry them now.
func (s *Server) reserve(n uint64) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if n > s.budgetFree {
		return false
	}
	s.budgetFree -= n
	return true
}

func (s *Server) release(n uint64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if n > s.config.MaxInFlightBytes-s.budgetFree {
		s.budgetFree = s.config.MaxInFlightBytes
		return
	}
	s.budgetFree += n
}
