// Package softwarework binds the frozen software-work contract to the bounded
// executor and immutable artifact store. It deliberately does not decide
// whether a Quote or a Service Actor request is canonical; that authority
// remains finalized TOS state at the future public worker boundary.
package softwarework

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/tosnetwork/ai/execution/pkg/artifactstore"
	"github.com/tosnetwork/ai/execution/pkg/executor"
)

var quoteCommitmentPattern = regexp.MustCompile(`^tvm-cell-sha256:[0-9a-f]{64}$`)

const (
	ArtifactMediaType = "application/vnd.tos.service.software-artifact.v1+tar"
	ReportMediaType   = "application/vnd.tos.service.test-report.v1+json"
)

type Contract struct {
	ManifestDigest   string
	ToolchainDigest  string
	SandboxDigest    string
	Executable       string
	Arguments        []string
	WorkingDirectory string
	Limits           executor.Limits
	UserID           uint32
	GroupID          uint32
}

type Request struct {
	QuoteCommitment string
	ExecutionID     string
	InputDigest     string
	SourceDigest    string
	SourceArchive   []byte
}

type Outcome struct {
	QuoteCommitment string                   `json:"quote_commitment"`
	ExecutionID     string                   `json:"execution_id"`
	InputDigest     string                   `json:"input_digest"`
	ResultDigest    string                   `json:"result_digest"`
	Artifact        artifactstore.Descriptor `json:"artifact"`
	Report          artifactstore.Descriptor `json:"report"`
	SourceDigest    string                   `json:"source_digest"`
	ToolchainDigest string                   `json:"toolchain_digest"`
	SandboxDigest   string                   `json:"sandbox_digest"`
	ExitCode        int                      `json:"exit_code"`
	CompletedAtUnix uint64                   `json:"completed_at_unix"`
}

// ErrAmbiguous reports an execution identity that was claimed without a
// recorded outcome: a run may have happened, so it is never run again.
var ErrAmbiguous = errors.New("software-work execution outcome is ambiguous")

// ErrRequestMismatch reports a request whose fields are malformed or do not
// match the commitments it carries; nothing was claimed for it.
var ErrRequestMismatch = errors.New("software-work request does not match its commitments")

// ErrConflict reports an execution identity already bound to a request with
// other commitments.
var ErrConflict = errors.New("execution identity conflicts with another request")

type Runner struct {
	executor executor.Executor
	store    *artifactstore.Store
	journal  *Journal
	contract Contract
	now      func() time.Time
	// bindLimits makes the limits part of the request fingerprint.
	bindLimits bool
}

// RunnerOption adjusts a Runner built by NewRunner.
type RunnerOption func(*Runner)

// BindLimits makes the contract's limits part of what an execution identity
// is bound to: a repeated request under other limits is a conflict instead
// of an answer from the journal. A caller whose limits are fixed by the
// manifest digest does not need it; one that takes limits per request does.
func BindLimits() RunnerOption {
	return func(r *Runner) { r.bindLimits = true }
}

func NewRunner(boundExecutor executor.Executor, store *artifactstore.Store, journal *Journal, contract Contract, options ...RunnerOption) (*Runner, error) {
	if boundExecutor == nil || store == nil || journal == nil || validateContract(contract) != nil {
		return nil, errors.New("invalid software-work runner configuration")
	}
	contract.Arguments = append([]string(nil), contract.Arguments...)
	runner := &Runner{executor: boundExecutor, store: store, journal: journal, contract: contract, now: time.Now}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("invalid software-work runner configuration")
		}
		option(runner)
	}
	return runner, nil
}

func (r *Runner) Execute(ctx context.Context, request Request) (Outcome, error) {
	if r == nil || r.executor == nil || r.store == nil || r.journal == nil || ctx == nil {
		return Outcome{}, errors.New("invalid software-work execution request")
	}
	if err := validateRequest(r.contract, request); err != nil {
		return Outcome{}, err
	}
	fingerprint := r.fingerprint(request)
	lease, record, err := r.journal.Claim(request.ExecutionID, fingerprint)
	if err != nil {
		return Outcome{}, err
	}
	if !lease {
		if record.State == "complete" {
			return record.Outcome, nil
		}
		return Outcome{}, ErrAmbiguous
	}
	spec := executor.Spec{
		ImageDigest: r.contract.ToolchainDigest, Entrypoint: append([]string{r.contract.Executable}, r.contract.Arguments...),
		WorkingDirectory: r.contract.WorkingDirectory, WorkspaceArchive: true,
		Environment: map[string]string{
			"GOROOT": "/usr/local/go", "HOME": "/workspace",
			"GOCACHE": "/workspace/go-cache", "GOTMPDIR": "/workspace",
			"TMPDIR": "/workspace", "CGO_ENABLED": "0", "GOMAXPROCS": "2",
		},
		ReadOnlyRoot: true, Network: executor.NetworkNone, UserID: r.contract.UserID, GroupID: r.contract.GroupID,
		NoNewPrivileges: true, Limits: r.contract.Limits,
	}
	result, err := r.executor.Execute(ctx, request.ExecutionID, spec, request.SourceArchive)
	if err != nil {
		return Outcome{}, err
	}
	if result.ExitCode != 0 {
		return Outcome{}, errors.New("software-work objective success condition failed")
	}
	completed := r.now().UTC()
	resultDigest := digest(result.Output)
	reportBytes, err := json.Marshal(struct {
		Schema          string         `json:"schema"`
		ExecutionID     string         `json:"execution_id"`
		ResultDigest    string         `json:"result_digest"`
		ExitCode        int            `json:"exit_code"`
		Usage           executor.Usage `json:"usage"`
		CompletedAtUnix uint64         `json:"completed_at_unix"`
	}{"tos.service.software-work-report.v1", request.ExecutionID, resultDigest, result.ExitCode, result.Usage, uint64(completed.Unix())})
	if err != nil {
		return Outcome{}, errors.New("encode software-work report")
	}
	// Both objects are bound to this execution as they are committed, so a
	// sweep keeps them until the caller retains the job with a deadline.
	report, err := r.store.PutFor(ctx, request.ExecutionID, ReportMediaType, bytes.NewReader(reportBytes))
	if err != nil {
		return Outcome{}, err
	}
	artifactBytes, err := buildArtifact(result.Output, reportBytes)
	if err != nil {
		return Outcome{}, err
	}
	artifact, err := r.store.PutFor(ctx, request.ExecutionID, ArtifactMediaType, bytes.NewReader(artifactBytes))
	if err != nil {
		return Outcome{}, err
	}
	outcome := Outcome{
		QuoteCommitment: request.QuoteCommitment, ExecutionID: request.ExecutionID, InputDigest: request.InputDigest,
		ResultDigest: resultDigest, Artifact: artifact, Report: report, SourceDigest: request.SourceDigest,
		ToolchainDigest: r.contract.ToolchainDigest, SandboxDigest: r.contract.SandboxDigest,
		ExitCode: result.ExitCode, CompletedAtUnix: uint64(completed.Unix()),
	}
	if err := r.journal.Complete(request.ExecutionID, fingerprint, outcome); err != nil {
		return Outcome{}, err
	}
	return outcome, nil
}

// Recorded reports what the journal already holds for request without
// claiming it, so a long-running caller can answer a repeated request while
// its execution slots are busy. It returns the recorded outcome and true for
// a completed execution, false when the identity was never claimed,
// ErrAmbiguous for a claim without an outcome and ErrConflict for an identity
// bound to other commitments.
func (r *Runner) Recorded(request Request) (Outcome, bool, error) {
	if r == nil || r.journal == nil {
		return Outcome{}, false, errors.New("invalid software-work execution request")
	}
	if err := validateRequest(r.contract, request); err != nil {
		return Outcome{}, false, err
	}
	record, found, err := r.journal.lookup(request.ExecutionID, r.fingerprint(request))
	if err != nil || !found {
		return Outcome{}, false, err
	}
	if record.State != "complete" {
		return Outcome{}, false, ErrAmbiguous
	}
	return record.Outcome, true, nil
}

func validateContract(value Contract) error {
	if !executionIDPattern.MatchString(value.ManifestDigest) || !executionIDPattern.MatchString(value.ToolchainDigest) ||
		value.SandboxDigest != value.ManifestDigest || value.Executable == "" || len(value.Arguments) == 0 ||
		len(value.Arguments) > 64 || !strings.HasPrefix(value.Executable, "/") || path.Clean(value.Executable) != value.Executable ||
		forbiddenExecutable(value.Executable) || value.WorkingDirectory != "/workspace/source" || value.UserID == 0 || value.GroupID == 0 ||
		value.Limits.CPUMillis == 0 || value.Limits.MemoryBytes == 0 || value.Limits.DiskBytes == 0 || value.Limits.PIDs == 0 ||
		value.Limits.ExecutionTime <= 0 || value.Limits.OutputBytes == 0 || value.Limits.GPUDeviceCount != 0 {
		return errors.New("invalid software-work contract")
	}
	for _, argument := range value.Arguments {
		if argument == "" || len(argument) > 512 || strings.IndexByte(argument, 0) >= 0 {
			return errors.New("invalid software-work contract")
		}
	}
	return nil
}

func forbiddenExecutable(value string) bool {
	switch path.Base(value) {
	case "sh", "bash", "dash", "zsh", "fish", "ksh", "cmd", "powershell", "pwsh":
		return true
	default:
		return false
	}
}

func validateRequest(contract Contract, value Request) error {
	if !quoteCommitmentPattern.MatchString(value.QuoteCommitment) || !executionIDPattern.MatchString(value.ExecutionID) ||
		!executionIDPattern.MatchString(value.InputDigest) || !executionIDPattern.MatchString(value.SourceDigest) ||
		digest(value.SourceArchive) != value.SourceDigest || uint64(len(value.SourceArchive)) > contract.Limits.DiskBytes {
		return ErrRequestMismatch
	}
	return nil
}

func (r *Runner) fingerprint(request Request) string {
	return requestFingerprint(r.contract, request, r.bindLimits)
}

// requestFingerprint is what an execution identity is bound to. Without
// bound limits its encoding has no limits field at all, so identities
// journaled before the option existed keep their fingerprint.
func requestFingerprint(contract Contract, request Request, bindLimits bool) string {
	var limits *[6]uint64
	if bindLimits {
		limits = &[6]uint64{contract.Limits.CPUMillis, contract.Limits.MemoryBytes, contract.Limits.DiskBytes,
			uint64(contract.Limits.PIDs), uint64(contract.Limits.ExecutionTime), contract.Limits.OutputBytes}
	}
	encoded, _ := json.Marshal(struct {
		Manifest  string     `json:"manifest"`
		Quote     string     `json:"quote"`
		Execution string     `json:"execution"`
		Input     string     `json:"input"`
		Source    string     `json:"source"`
		Limits    *[6]uint64 `json:"limits,omitempty"`
	}{contract.ManifestDigest, request.QuoteCommitment, request.ExecutionID, request.InputDigest, request.SourceDigest, limits})
	return digest(encoded)
}

func digest(value []byte) string {
	hash := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func buildArtifact(output, report []byte) ([]byte, error) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, entry := range []struct {
		name string
		body []byte
	}{{"output.log", output}, {"report.json", report}} {
		header := &tar.Header{Name: entry.name, Mode: 0o444, Size: int64(len(entry.body)), ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
		if err := writer.WriteHeader(header); err != nil {
			return nil, errors.New("encode software-work artifact")
		}
		if _, err := writer.Write(entry.body); err != nil {
			return nil, errors.New("encode software-work artifact")
		}
	}
	if err := writer.Close(); err != nil {
		return nil, errors.New("encode software-work artifact")
	}
	return buffer.Bytes(), nil
}
