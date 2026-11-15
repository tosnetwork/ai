// Package executorservice is the privilege boundary between an unprivileged
// provider node and the root-only private containerd: a server that runs the
// frozen software-work job on behalf of an allowed local uid, and the client
// that node uses to reach it over a Unix socket.
//
// The boundary carries one operation and no paths. A request names an
// execution by digests, states limits that may only tighten the frozen
// preset and an optional retention deadline the server bounds, and carries
// the source archive bytes; the response carries the
// outcome and the artifact and report bytes. The image, command, mounts,
// network and devices are fixed by the server and cannot be chosen by a
// caller.
//
// Wire format, one request per connection:
//
//	request  = length(4, big endian) header-JSON source-bytes EOF
//	response = length(4, big endian) header-JSON artifact-bytes report-bytes EOF
//
// The client half-closes its side after the source bytes; the server closes
// the connection after the response. Both headers are decoded strictly:
// an unknown field, trailing data, an oversize frame or another schema is
// refused.
package executorservice

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/tosnetwork/tos-ai/pkg/artifactstore"
	"github.com/tosnetwork/tos-ai/pkg/softwarework"
)

const (
	// RequestSchema and ResponseSchema version the two headers. A peer that
	// speaks another version is refused, never interpreted.
	RequestSchema  = "tos.ai.executor-service.request.v1"
	ResponseSchema = "tos.ai.executor-service.response.v1"

	OperationDescribe = "describe"
	OperationExecute  = "execute"

	// MaxRequestHeaderBytes and MaxResponseHeaderBytes bound the JSON
	// headers; both hold only fixed-size digests and integers.
	MaxRequestHeaderBytes  = 4 << 10
	MaxResponseHeaderBytes = 16 << 10
	// MaxSourceBytes is the input bound of the frozen policy.
	MaxSourceBytes = 16 << 20
	// MaxObjectBytes bounds each returned object; it is the artifact
	// store's own object bound.
	MaxObjectBytes = artifactstore.MaxObjectBytesHard
)

// Status is the outcome class of one request. Every status other than
// StatusOK carries a fixed message and no caller data.
type Status string

const (
	// StatusOK: the response carries what was asked for.
	StatusOK Status = "ok"
	// StatusNotAllowed: the peer uid is not the allowed uid. Nothing was
	// read from the connection.
	StatusNotAllowed Status = "not_allowed"
	// StatusInvalidRequest: the request is malformed, oversize, of another
	// version, has trailing data or does not match its own digests.
	StatusInvalidRequest Status = "invalid_request"
	// StatusLimitsRefused: a limit is zero or looser than the frozen preset.
	StatusLimitsRefused Status = "limits_refused"
	// StatusTimeout: the peer was too slow sending the request.
	StatusTimeout Status = "timeout"
	// StatusBusy: a connection, execution or byte bound is reached. Nothing
	// was claimed; retry later.
	StatusBusy Status = "busy"
	// StatusInProgress: this execution is running now. Nothing new was
	// started; ask again for its outcome. Every request for a running
	// execution id gets this answer, whatever its other fields are.
	StatusInProgress Status = "in_progress"
	// StatusAmbiguous: the execution was claimed and has no recorded
	// outcome. It may have run; it is never run again.
	StatusAmbiguous Status = "ambiguous"
	// StatusConflict: the execution id is bound to other commitments or
	// other limits.
	StatusConflict Status = "conflict"
	// StatusExecutionFailed: the run started and did not produce a recorded
	// success. The execution id is ambiguous from now on.
	StatusExecutionFailed Status = "execution_failed"
	// StatusUnavailable: the backend (daemon or pinned image), journal or
	// store cannot serve now.
	// Nothing new was claimed.
	StatusUnavailable Status = "unavailable"
	// StatusStorageFull: the state filesystem is below its free-byte or
	// free-inode floor. Nothing was claimed.
	StatusStorageFull Status = "storage_full"
	// StatusRetentionFull: the store cannot give another job a retention
	// deadline; sweep expired jobs.
	StatusRetentionFull Status = "retention_full"
	// StatusObjectsUnavailable: the outcome is recorded but its objects are
	// no longer stored (their retention ended).
	StatusObjectsUnavailable Status = "objects_unavailable"
)

var statusMessages = map[Status]string{
	StatusNotAllowed:         "the peer is not allowed to use this executor",
	StatusInvalidRequest:     "the request is malformed",
	StatusLimitsRefused:      "a limit is zero or looser than the frozen preset",
	StatusTimeout:            "the request was not received in time",
	StatusBusy:               "the executor is at a concurrency or byte bound",
	StatusInProgress:         "the execution is in progress",
	StatusAmbiguous:          "the execution outcome is ambiguous and is never rerun",
	StatusConflict:           "the execution identity is bound to another request",
	StatusExecutionFailed:    "the execution did not produce a recorded success",
	StatusUnavailable:        "the executor cannot serve now",
	StatusStorageFull:        "the executor storage is below its free-space floor",
	StatusRetentionFull:      "the artifact store cannot retain another job",
	StatusObjectsUnavailable: "the recorded objects are no longer stored",
}

// Limits are the per-job limits in the published manifest's units. Each
// must be non-zero and no looser than the frozen preset.
type Limits struct {
	CPUMillis       uint64 `json:"cpu_millis"`
	MemoryBytes     uint64 `json:"memory_bytes"`
	ScratchBytes    uint64 `json:"scratch_bytes"`
	OutputBytes     uint64 `json:"output_bytes"`
	WallClockMillis uint64 `json:"wall_clock_millis"`
}

func (l Limits) manifest() softwarework.ManifestLimits {
	return softwarework.ManifestLimits{CPUMillis: l.CPUMillis, MemoryBytes: l.MemoryBytes,
		ScratchBytes: l.ScratchBytes, OutputBytes: l.OutputBytes, WallClockMillis: l.WallClockMillis}
}

// FrozenLimits is the frozen preset: the loosest limits a request may state.
func FrozenLimits() Limits {
	frozen := softwarework.FrozenV1ManifestLimits()
	return Limits{CPUMillis: frozen.CPUMillis, MemoryBytes: frozen.MemoryBytes, ScratchBytes: frozen.ScratchBytes,
		OutputBytes: frozen.OutputBytes, WallClockMillis: frozen.WallClockMillis}
}

// Description is what a caller can learn about the service without access
// to any root-only path.
type Description struct {
	// Version and Commit identify the server build.
	Version string `json:"version"`
	Commit  string `json:"commit"`
	// ImageDigest and ImageReference name the only image a job runs in.
	ImageDigest    string `json:"image_digest"`
	ImageReference string `json:"image_reference"`
	// Limits and PIDs are the frozen preset every request is held to.
	Limits Limits `json:"limits"`
	PIDs   uint32 `json:"pids"`
	// MaxSourceBytes and MaxObjectBytes are the payload bounds.
	MaxSourceBytes uint64 `json:"max_source_bytes"`
	MaxObjectBytes uint64 `json:"max_object_bytes"`
	// MaxExecutions is how many jobs run at once.
	MaxExecutions int `json:"max_executions"`
	// DefaultRetentionSeconds is how long after completion a job's objects
	// are kept when its request states no deadline, MaxRetentionSeconds
	// the longest any request can keep them.
	DefaultRetentionSeconds uint64 `json:"default_retention_seconds"`
	MaxRetentionSeconds     uint64 `json:"max_retention_seconds"`
	// Ready reports whether the container backend answered its readiness
	// probe for this request.
	Ready bool `json:"ready"`
}

type requestHeader struct {
	Schema    string         `json:"schema"`
	Operation string         `json:"operation"`
	Execute   *executeHeader `json:"execute,omitempty"`
}

type executeHeader struct {
	ExecutionID     string `json:"execution_id"`
	QuoteCommitment string `json:"quote_commitment"`
	InputDigest     string `json:"input_digest"`
	ManifestDigest  string `json:"manifest_digest"`
	Limits          Limits `json:"limits"`
	RetainUntilUnix int64  `json:"retain_until_unix"`
	SourceDigest    string `json:"source_digest"`
	SourceBytes     uint64 `json:"source_bytes"`
}

type responseHeader struct {
	Schema   string                `json:"schema"`
	Status   Status                `json:"status"`
	Error    string                `json:"error,omitempty"`
	Describe *Description          `json:"describe,omitempty"`
	Outcome  *softwarework.Outcome `json:"outcome,omitempty"`
	// RetainUntilUnix is the deadline this request gave the outcome's
	// objects, after the server's default and maximum were applied.
	RetainUntilUnix int64 `json:"retain_until_unix,omitempty"`
}

var (
	sha256Pattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	quotePattern  = regexp.MustCompile(`^tvm-cell-sha256:[0-9a-f]{64}$`)
)

var (
	errFrameSize = errors.New("executor service frame is empty or oversize")
	errFrameJSON = errors.New("executor service header does not decode strictly")
)

// readHeader reads one length-prefixed header of at most maximum bytes.
func readHeader(reader io.Reader, maximum uint32) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length == 0 || length > maximum {
		return nil, errFrameSize
	}
	header := make([]byte, length)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	return header, nil
}

// encodeHeader frames value; it refuses a header over maximum rather than
// send one the peer must refuse.
func encodeHeader(value any, maximum uint32) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || uint64(len(encoded)) > uint64(maximum) {
		return nil, errFrameSize
	}
	frame := make([]byte, 4, 4+len(encoded))
	binary.BigEndian.PutUint32(frame, uint32(len(encoded)))
	return append(frame, encoded...), nil
}

// decodeStrict decodes exactly one JSON value with no unknown field and
// nothing after it.
func decodeStrict(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errFrameJSON
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errFrameJSON
	}
	return nil
}

// requireEOF reports whether the stream ends here; one more byte is
// trailing data.
func requireEOF(reader io.Reader) error {
	var one [1]byte
	n, err := reader.Read(one[:])
	if n != 0 {
		return errors.New("executor service stream has trailing data")
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("executor service stream did not end")
	}
	return err
}
