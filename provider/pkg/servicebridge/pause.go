package servicebridge

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// AdmissionPauseFile is the owner-only marker in state_dir that stops the
// provider from admitting new requests. Work already admitted is unaffected:
// it executes, responds and delivers, or falls to the buyer's refund path.
const AdmissionPauseFile = "admission-paused"

// AdmissionPauseLockFile is the lock file in state_dir under which every
// pause, re-stamp and removal of the marker runs.
const AdmissionPauseLockFile = "admission-pause.lock"

// The marker's schemas. Every write is v2; a v1 marker, written before the
// marker carried its origin, is still read, as an operator pause.
const (
	admissionPauseSchemaV1 = "tos.openfox.rail-admission-pause.v1"
	admissionPauseSchema   = "tos.openfox.rail-admission-pause.v2"
)

// Who wrote a pause marker. An operator pause is the owner's own stop, made
// with the program (`tos-service-provider pause`) or asked of the provider
// agent from the owner's account; an agent pause is one the provider agent
// wrote on its own or for the model it serves. Only an agent marker is ever
// lifted by the agent, and only by ResumeAdmissionIf against its exact bytes.
const (
	PauseOriginOperator = "operator"
	PauseOriginAgent    = "agent"
)

// maxPauseReason bounds the note so the marker stays small.
const maxPauseReason = 256

// maxPauseMarker bounds what is read of a marker file.
const maxPauseMarker = 4 << 10

// pauseLockWait bounds how long a pause, re-stamp or removal waits for
// another one to finish. Each holds the lock only for one read and one
// write of a small file.
var pauseLockWait = 5 * time.Second

var pauseStampPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ErrAdmissionPaused reports that a task was not admitted because the owner
// paused admission. The task message is kept pending, not counted as a
// failed handling, so it is admitted after a resume if the request is still
// admissible then.
var ErrAdmissionPaused = errors.New("servicebridge: new admissions are paused by the owner")

// ErrPauseMarkerChanged reports a compare-and-remove that found another
// marker than the one it was given: someone paused again or re-stamped the
// marker since it was read. The marker on disk is left in place.
var ErrPauseMarkerChanged = errors.New("servicebridge: the admission pause marker is not the one expected; " +
	"it was left in place and admission stays paused")

// ErrPauseBusy reports that another pause, re-stamp or removal held the
// marker's lock for longer than a pause waits.
var ErrPauseBusy = errors.New("servicebridge: another pause or resume of this state directory is in progress; " +
	"nothing was changed")

var errPauseLockHeld = errors.New("servicebridge: the admission pause lock is held")

// AdmissionPause is the content of the pause marker. Origin and Stamp are
// empty only in a v1 marker as stored; ReadAdmissionPause reports a v1
// marker with Origin PauseOriginOperator.
type AdmissionPause struct {
	Schema     string `json:"schema"`
	PausedUnix int64  `json:"paused_unix"`
	Reason     string `json:"reason,omitempty"`
	// Origin is PauseOriginOperator or PauseOriginAgent.
	Origin string `json:"origin,omitempty"`
	// Stamp is 16 random bytes in lowercase hex, drawn at every write, so
	// two markers of the same time, origin and reason still differ.
	Stamp string `json:"stamp,omitempty"`
}

// PauseResult is what a pause did.
type PauseResult struct {
	// Pause is the marker on disk after the call, and Marker its exact bytes.
	Pause  *AdmissionPause
	Marker []byte
	// Already reports that a marker existed before the call.
	Already bool
	// PreviousOrigin is that marker's origin when Already is true.
	PreviousOrigin string
	// Restamped reports that an operator pause replaced an agent marker.
	Restamped bool
}

func pausePath(stateDir string) (string, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return "", errors.New("servicebridge: state_dir must be clean and absolute")
	}
	return filepath.Join(stateDir, AdmissionPauseFile), nil
}

// ReadAdmissionPause reports whether admission is paused. A marker that
// exists but cannot be read or decoded is an error; callers that decide
// admission treat that error as paused.
func ReadAdmissionPause(stateDir string) (*AdmissionPause, error) {
	pause, _, err := ReadAdmissionPauseMarker(stateDir)
	return pause, err
}

// ReadAdmissionPauseMarker is ReadAdmissionPause that also returns the
// marker's exact bytes, which a later ResumeAdmissionIf compares against.
// It is nil, nil, nil when no marker exists.
func ReadAdmissionPauseMarker(stateDir string) (*AdmissionPause, []byte, error) {
	path, err := pausePath(stateDir)
	if err != nil {
		return nil, nil, err
	}
	data, err := readPrivateFile(path, maxPauseMarker)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("servicebridge: the admission pause marker is unreadable: %w", err)
	}
	pause, err := decodeAdmissionPause(data)
	if err != nil {
		return nil, nil, err
	}
	return pause, data, nil
}

// decodeAdmissionPause strictly decodes a marker of a schema this release
// knows. A marker of another schema is refused with a message that names the
// likely cause: a program of another release than the one that wrote it.
func decodeAdmissionPause(data []byte) (*AdmissionPause, error) {
	var probe struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, errors.New("servicebridge: the admission pause marker is invalid: it is not a JSON object")
	}
	if probe.Schema == "" {
		return nil, errors.New("servicebridge: the admission pause marker is invalid: it names no schema")
	}
	if probe.Schema != admissionPauseSchemaV1 && probe.Schema != admissionPauseSchema {
		shown := probe.Schema
		if len(shown) > 80 || strings.ContainsFunc(shown, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
			shown = "(not printable)"
		}
		return nil, fmt.Errorf("servicebridge: the admission pause marker is invalid: its schema %q is not one this "+
			"program knows (it reads %s and %s); a program of another release wrote it, so run the program of the "+
			"same release as the node and the provider agent; admission stays paused", shown,
			admissionPauseSchemaV1, admissionPauseSchema)
	}
	var pause AdmissionPause
	if err := decodeStrict(data, &pause); err != nil {
		return nil, errors.New("servicebridge: the admission pause marker is invalid: " + err.Error())
	}
	if pause.PausedUnix <= 0 || len(pause.Reason) > maxPauseReason {
		return nil, errors.New("servicebridge: the admission pause marker is invalid")
	}
	switch pause.Schema {
	case admissionPauseSchemaV1:
		// A v1 marker carries neither field; one that does is not a v1
		// marker this program wrote.
		if pause.Origin != "" || pause.Stamp != "" {
			return nil, errors.New("servicebridge: the admission pause marker is invalid: a v1 marker has no " +
				"origin or stamp")
		}
		pause.Origin = PauseOriginOperator
	default:
		// An origin this release does not know is unreadable, not an
		// operator or agent pause: admission stays paused and only the
		// operator lifts it.
		if pause.Origin != PauseOriginOperator && pause.Origin != PauseOriginAgent {
			return nil, errors.New("servicebridge: the admission pause marker is invalid: its origin is neither " +
				"operator nor agent")
		}
		if !pauseStampPattern.MatchString(pause.Stamp) {
			return nil, errors.New("servicebridge: the admission pause marker is invalid: its stamp is not 32 " +
				"lowercase hex digits")
		}
	}
	return &pause, nil
}

func decodeStrict(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("it does not decode as a marker of its schema")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("it has trailing data")
	}
	return nil
}

func newPauseStamp() (string, error) {
	var stamp [16]byte
	if _, err := rand.Read(stamp[:]); err != nil {
		return "", errors.New("servicebridge: draw the admission pause stamp")
	}
	return hex.EncodeToString(stamp[:]), nil
}

func encodePause(pause *AdmissionPause) ([]byte, error) {
	data, err := json.Marshal(pause)
	if err != nil {
		return nil, errors.New("servicebridge: encode the admission pause marker")
	}
	return data, nil
}

func checkPauseReason(reason string) error {
	if len(reason) > maxPauseReason || strings.ContainsAny(reason, "\x00\n\r") {
		return errors.New("servicebridge: the pause reason must be one line of at most 256 bytes")
	}
	return nil
}

// lockPause takes the marker's lock, waiting at most pauseLockWait for
// another pause or removal to finish.
func lockPause(stateDir string) (release func(), err error) {
	if err = checkPrivateDirectory(stateDir); err != nil {
		return nil, err
	}
	path := filepath.Join(stateDir, AdmissionPauseLockFile)
	deadline := time.Now().Add(pauseLockWait)
	for {
		lock, lockErr := acquireRunLock(path, errPauseLockHeld)
		if lockErr == nil {
			return func() { releaseRunLock(lock) }, nil
		}
		if !errors.Is(lockErr, errPauseLockHeld) {
			return nil, lockErr
		}
		if time.Now().After(deadline) {
			return nil, ErrPauseBusy
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// pauseHookAfterRead runs, in tests only, while a pause or removal holds the
// lock, between its read of the marker and its write or removal.
var pauseHookAfterRead func()

// PauseAdmission durably writes an operator pause, as PauseAdmissionAs with
// PauseOriginOperator. already reports that a marker existed before.
func PauseAdmission(stateDir, reason string, now time.Time) (pause *AdmissionPause, already bool, err error) {
	result, err := PauseAdmissionAs(stateDir, PauseOriginOperator, reason, now)
	if err != nil {
		return nil, false, err
	}
	return result.Pause, result.Already, nil
}

// PauseAdmissionAs durably pauses admission with the given origin, under
// the marker's lock:
//
//   - with no marker, it writes a new one of that origin;
//   - an operator pause over an agent marker replaces it atomically with an
//     operator marker that keeps the first paused_unix, carries the new
//     reason (the old one when the new one is empty) and a new stamp, so the
//     agent can no longer lift it;
//   - every other pause over an existing marker changes nothing;
//   - over a marker that cannot be read it refuses and changes nothing:
//     admission stays paused.
func PauseAdmissionAs(stateDir, origin, reason string, now time.Time) (PauseResult, error) {
	if origin != PauseOriginOperator && origin != PauseOriginAgent {
		return PauseResult{}, errors.New("servicebridge: a pause origin is operator or agent")
	}
	if err := checkPauseReason(reason); err != nil {
		return PauseResult{}, err
	}
	path, err := pausePath(stateDir)
	if err != nil {
		return PauseResult{}, err
	}
	if now.Unix() <= 0 {
		return PauseResult{}, errors.New("servicebridge: the clock is before the epoch")
	}
	release, err := lockPause(stateDir)
	if err != nil {
		return PauseResult{}, err
	}
	defer release()
	existing, existingBytes, err := ReadAdmissionPauseMarker(stateDir)
	if err != nil {
		return PauseResult{}, fmt.Errorf("%w; it was left unchanged and admission stays paused", err)
	}
	if pauseHookAfterRead != nil {
		pauseHookAfterRead()
	}
	if existing != nil {
		result := PauseResult{Pause: existing, Marker: existingBytes, Already: true, PreviousOrigin: existing.Origin}
		if origin != PauseOriginOperator || existing.Origin != PauseOriginAgent {
			return result, nil
		}
		stamp, stampErr := newPauseStamp()
		if stampErr != nil {
			return PauseResult{}, stampErr
		}
		restamped := &AdmissionPause{
			Schema: admissionPauseSchema, PausedUnix: existing.PausedUnix, Reason: reason,
			Origin: PauseOriginOperator, Stamp: stamp,
		}
		if reason == "" {
			restamped.Reason = existing.Reason
		}
		data, encodeErr := encodePause(restamped)
		if encodeErr != nil {
			return PauseResult{}, encodeErr
		}
		if writeErr := replaceSynced(path, data); writeErr != nil {
			return PauseResult{}, writeErr
		}
		result.Pause, result.Marker, result.Restamped = restamped, data, true
		return result, nil
	}
	stamp, err := newPauseStamp()
	if err != nil {
		return PauseResult{}, err
	}
	pause := &AdmissionPause{
		Schema: admissionPauseSchema, PausedUnix: now.Unix(), Reason: reason, Origin: origin, Stamp: stamp,
	}
	data, err := encodePause(pause)
	if err != nil {
		return PauseResult{}, err
	}
	if err := writeSynced(path, data); err != nil {
		if errors.Is(err, os.ErrExist) {
			// A writer that does not take the lock (a program of an earlier
			// release) paused in between; its marker stands.
			current, currentBytes, readErr := ReadAdmissionPauseMarker(stateDir)
			if readErr != nil {
				return PauseResult{}, readErr
			}
			if current == nil {
				return PauseResult{}, errors.New("servicebridge: the admission pause marker changed during the pause")
			}
			return PauseResult{Pause: current, Marker: currentBytes, Already: true, PreviousOrigin: current.Origin}, nil
		}
		return PauseResult{}, err
	}
	return PauseResult{Pause: pause, Marker: data}, nil
}

// ResumeAdmission removes the pause marker durably, whatever it holds: it is
// the operator's own resume. wasPaused is false when no marker existed.
func ResumeAdmission(stateDir string) (wasPaused bool, err error) {
	return resumeAdmission(stateDir, nil)
}

// ResumeAdmissionIf removes the pause marker only if the file still holds
// exactly expected, the bytes the caller read or wrote. Under the marker's
// lock it compares and removes, so a pause or re-stamp made after the
// caller read the marker makes it fail with ErrPauseMarkerChanged and leaves
// that marker in place. wasPaused is false when no marker exists.
func ResumeAdmissionIf(stateDir string, expected []byte) (wasPaused bool, err error) {
	if len(expected) == 0 || len(expected) > maxPauseMarker {
		return false, errors.New("servicebridge: a conditional resume names the marker bytes it expects")
	}
	return resumeAdmission(stateDir, expected)
}

func resumeAdmission(stateDir string, expected []byte) (bool, error) {
	path, err := pausePath(stateDir)
	if err != nil {
		return false, err
	}
	release, err := lockPause(stateDir)
	if err != nil {
		return false, err
	}
	defer release()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("servicebridge: stat the admission pause marker")
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("servicebridge: the admission pause marker is not a regular file")
	}
	if expected != nil {
		current, readErr := readPrivateFile(path, maxPauseMarker)
		if readErr != nil {
			return false, fmt.Errorf("servicebridge: the admission pause marker is unreadable: %w; it was left in "+
				"place", readErr)
		}
		if !bytes.Equal(current, expected) {
			return false, ErrPauseMarkerChanged
		}
	}
	if pauseHookAfterRead != nil {
		pauseHookAfterRead()
	}
	if err := os.Remove(path); err != nil {
		return false, errors.New("servicebridge: remove the admission pause marker")
	}
	return true, syncDirectory(stateDir)
}
