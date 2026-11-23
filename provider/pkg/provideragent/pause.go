package provideragent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/tosnetwork/ai/protocol/pkg/agentsocket"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

// modelReasonPrefix marks the model's pause reason in the marker.
const modelReasonPrefix = "mcp: "

// admissionCheckID is the preflight check of the pause marker itself, which
// a resume does not require to pass.
const admissionCheckID = "admission.pause"

// checkReason allows one line of at most 200 bytes of printable ASCII.
func checkReason(reason string) error {
	if len(reason) > agentapi.MaxPauseReasonBytes {
		return agentapi.Refusal(agentapi.CodeBadInput, "reason must be at most 200 bytes", nil)
	}
	for _, b := range []byte(reason) {
		if b < 0x20 || b > 0x7e {
			return agentapi.Refusal(agentapi.CodeBadInput, "reason must be one line of printable ASCII", nil)
		}
	}
	return nil
}

// markerOrigin decodes the origin a marker's bytes name; it is empty for
// bytes this release cannot read.
func markerOrigin(marker []byte) string {
	var probe struct {
		Schema string `json:"schema"`
		Origin string `json:"origin"`
	}
	if json.Unmarshal(marker, &probe) != nil || probe.Schema != "tos.openfox.rail-admission-pause.v2" {
		return ""
	}
	return probe.Origin
}

// Pause is the pause method (section 4.11). From the client it writes an
// agent marker recorded as the model's; from the custody account it is the
// operator's pause, which re-stamps an agent marker as the operator's.
func (a *Agent) Pause(role agentsocket.Role, params agentapi.PauseParams) (any, error) {
	if err := checkReason(params.Reason); err != nil {
		return nil, err
	}
	if err := a.limit(role, ratePause, false); err != nil {
		return nil, err
	}
	a.pauses.Lock()
	defer a.pauses.Unlock()
	if role == agentsocket.RoleCustody {
		result, err := servicebridge.PauseAdmissionAs(a.rail.StateDir, servicebridge.PauseOriginOperator, params.Reason,
			a.now())
		if err != nil {
			return nil, pauseRefusal(err)
		}
		return pauseView(result, ""), nil
	}
	reason := modelReasonPrefix + params.Reason
	if params.Reason == "" {
		reason = modelReasonPrefix + "paused by the model"
	}
	result, err := servicebridge.PauseAdmissionAs(a.rail.StateDir, servicebridge.PauseOriginAgent, reason, a.now())
	if err != nil {
		return nil, pauseRefusal(err)
	}
	recorded := ""
	a.withLock(func() {
		origin, readErr := a.store.readOrigin()
		switch {
		case readErr != nil:
			err = readErr
		case !result.Already:
			// The record is written before the pause is reported. A crash
			// between the marker and the record leaves a marker the agent
			// does not recognize, which the model then cannot lift.
			err = a.store.writeOrigin(pauseOrigin{Marker: result.Marker, Why: pauseForModel, WrittenUnix: a.now().Unix()})
			recorded = pauseForModel
		case origin != nil && bytes.Equal(origin.Marker, result.Marker) && result.Pause.Origin == servicebridge.PauseOriginAgent:
			// A model pause over the floor's own marker leaves the marker as
			// it is and moves its record to the model, so the floor no
			// longer lifts it when the balance recovers.
			if origin.Why != pauseForModel {
				origin.Why = pauseForModel
				err = a.store.writeOrigin(*origin)
			}
			recorded = pauseForModel
		}
	})
	if err != nil {
		return nil, err
	}
	return pauseView(result, recorded), nil
}

func pauseRefusal(err error) error {
	if errors.Is(err, servicebridge.ErrPauseBusy) {
		return agentapi.Refusal(agentapi.CodeConflict, "another pause or resume is in progress; nothing was changed", err)
	}
	return agentapi.Refusal(agentapi.CodeNotReady, "the pause marker cannot be written or read; admission stays as it was "+
		"or paused", err)
}

func pauseView(result servicebridge.PauseResult, recorded string) agentapi.PauseView {
	view := agentapi.PauseView{Paused: true, AlreadyPaused: result.Already, Restamped: result.Restamped,
		RecordedAs: recorded}
	if result.Pause != nil {
		view.Origin, view.PausedUnix = result.Pause.Origin, result.Pause.PausedUnix
	}
	if result.Already {
		view.PreviousOrigin = result.PreviousOrigin
	}
	return view
}

// readMarkerBytes reads the marker's raw bytes, readable or not by this
// release, so a confirmed resume can remove exactly what was confirmed.
func readMarkerBytes(stateDir string) ([]byte, error) {
	path := filepath.Join(stateDir, servicebridge.AdmissionPauseFile)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4<<10 {
		return nil, errors.New("the pause marker is not a small regular file")
	}
	return os.ReadFile(path)
}

// passesApartFromAdmission reports whether every preflight check other than
// the pause marker's own passed or only warned.
func passesApartFromAdmission(report *servicebridge.PreflightReport) bool {
	if report == nil || len(report.Checks) == 0 {
		return false
	}
	for _, check := range report.Checks {
		if check.ID != admissionCheckID && check.Status == servicebridge.CheckFail {
			return false
		}
	}
	return true
}

// Resume is the resume method (section 4.11). The model's own pause is
// lifted at once when its marker is byte for byte the recorded one, the
// wallet floor is met and the preflight passes; any other pause becomes a
// confirmable action, except the floor's own, which the agent lifts.
func (a *Agent) Resume(ctx context.Context, role agentsocket.Role, params agentapi.ResumeParams) (any, error) {
	if !idempotencyKeyPattern.MatchString(params.IdempotencyKey) {
		return nil, agentapi.Refusal(agentapi.CodeBadInput, "idempotency_key must be 16 to 64 of [A-Za-z0-9_-]", nil)
	}
	if err := a.limit(role, ratePause, false); err != nil {
		return nil, err
	}
	a.pauses.Lock()
	defer a.pauses.Unlock()
	pause, marker, readErr := servicebridge.ReadAdmissionPauseMarker(a.rail.StateDir)
	if readErr == nil && pause == nil {
		return agentapi.ResumeView{Outcome: agentapi.ResumeNotPaused}, nil
	}
	var origin *pauseOrigin
	var err error
	a.withLock(func() { origin, err = a.store.readOrigin() })
	if err != nil {
		return nil, err
	}
	recorded := readErr == nil && origin != nil && bytes.Equal(origin.Marker, marker) &&
		pause.Origin == servicebridge.PauseOriginAgent && markerOrigin(marker) == servicebridge.PauseOriginAgent
	if recorded && origin.Why == pauseForWalletFloor {
		return agentapi.ResumeView{Outcome: agentapi.ResumeFloorPause}, nil
	}
	if recorded && origin.Why == pauseForModel {
		return a.resumeModelPause(ctx, role, marker)
	}
	if readErr != nil {
		marker, err = readMarkerBytes(a.rail.StateDir)
		if err != nil || len(marker) == 0 {
			return nil, agentapi.Refusal(agentapi.CodeNotReady, "the pause marker cannot be read; the operator "+
				"resumes with the program", err)
		}
	}
	return a.confirmableResume(ctx, role, params.IdempotencyKey, marker, pause, origin)
}

// resumeModelPause lifts the model's own pause directly, by compare-and-
// remove against the recorded bytes.
func (a *Agent) resumeModelPause(ctx context.Context, role agentsocket.Role, marker []byte) (any, error) {
	readCtx, cancel := context.WithTimeout(ctx, chainReadTimeout)
	defer cancel()
	balance, err := a.lib.WalletBalance(readCtx)
	if err != nil {
		return nil, chainRefusal(err)
	}
	view := agentapi.ResumeView{}
	if view.Balance, err = json.Marshal(balance); err != nil {
		return nil, err
	}
	if balance.BalanceNano < a.config.minWallet {
		rendered, renderErr := a.out(role, view)
		if renderErr != nil {
			return nil, renderErr
		}
		return rendered, agentapi.Refusal(agentapi.CodeNotReady, "the owner wallet is below the configured floor", nil)
	}
	preflightCtx, cancelPreflight := context.WithTimeout(ctx, preflightTimeout)
	defer cancelPreflight()
	report := a.lib.Preflight(preflightCtx)
	if view.Preflight, err = json.Marshal(report); err != nil {
		return nil, err
	}
	if !passesApartFromAdmission(report) {
		rendered, renderErr := a.out(role, view)
		if renderErr != nil {
			return nil, renderErr
		}
		return rendered, agentapi.Refusal(agentapi.CodeNotReady, "a preflight check failed; the report is attached", nil)
	}
	if a.beforeRemove != nil {
		a.beforeRemove()
	}
	// A second safeguard: the agent removes directly only bytes that name
	// the agent as their origin, whatever its record holds.
	if markerOrigin(marker) != servicebridge.PauseOriginAgent {
		return nil, agentapi.Refusal(agentapi.CodeConflict, "the marker is not an agent marker; it was left in place", nil)
	}
	if _, err := servicebridge.ResumeAdmissionIf(a.rail.StateDir, marker); err != nil {
		if errors.Is(err, servicebridge.ErrPauseMarkerChanged) {
			return nil, agentapi.Refusal(agentapi.CodeConflict, "the marker changed since it was read; it was left in "+
				"place", err)
		}
		return nil, pauseRefusal(err)
	}
	a.withLock(func() { err = a.store.clearOrigin() })
	if err != nil {
		return nil, err
	}
	view.Outcome = agentapi.ResumeResumed
	return a.out(role, view)
}

// resumePreview is the preview of a confirmable resume.
type resumePreview struct {
	MarkerBase64 string                         `json:"marker_base64"`
	MarkerSHA256 string                         `json:"marker_sha256"`
	Marker       *servicebridge.AdmissionPause  `json:"marker,omitempty"`
	RecordedAs   string                         `json:"recorded_as,omitempty"`
	Preflight    *servicebridge.PreflightReport `json:"preflight"`
}

func (a *Agent) confirmableResume(ctx context.Context, role agentsocket.Role, key string, marker []byte,
	pause *servicebridge.AdmissionPause, origin *pauseOrigin) (any, error) {
	sum := sha256.Sum256(marker)
	inputs := map[string]string{"marker_sha256": hex.EncodeToString(sum[:])}
	preflightCtx, cancel := context.WithTimeout(ctx, preflightTimeout)
	defer cancel()
	preview := resumePreview{MarkerBase64: base64.StdEncoding.EncodeToString(marker),
		MarkerSHA256: inputs["marker_sha256"], Marker: pause}
	if origin != nil && bytes.Equal(origin.Marker, marker) {
		preview.RecordedAs = origin.Why
	}
	action, err := a.storeAction(agentapi.KindResume, key, inputs, func() (any, any, error) {
		preview.Preflight = a.lib.Preflight(preflightCtx)
		return preview, nil, nil
	})
	if err != nil {
		return nil, err
	}
	view, err := a.actionView(role, action)
	if err != nil {
		return nil, err
	}
	return agentapi.ResumeView{Outcome: agentapi.ResumeConfirmable, Action: &view}, nil
}

// floorMarkerLocked is the marker bytes the wallet floor may lift: those of
// the agent's own floor pause, while its record still holds it as the
// floor's and the bytes name the agent. A model's pause over the floor's
// marker moved the record to the model, so nil is passed and the floor
// leaves it. The caller holds a.mutex.
func (a *Agent) floorMarkerLocked() ([]byte, error) {
	origin, err := a.store.readOrigin()
	if err != nil || origin == nil || origin.Why != pauseForWalletFloor ||
		markerOrigin(origin.Marker) != servicebridge.PauseOriginAgent {
		return nil, err
	}
	return origin.Marker, nil
}

// CheckWalletFloor runs one wallet floor check (section 2.5): below the
// floor it writes the agent's floor pause and records it; at or above the
// floor it lifts only that pause, by compare-and-remove.
func (a *Agent) CheckWalletFloor(ctx context.Context) (servicebridge.WalletFloorOutcome, error) {
	readCtx, cancel := context.WithTimeout(ctx, chainReadTimeout)
	defer cancel()
	balance, err := a.lib.WalletBalance(readCtx)
	if err != nil {
		return servicebridge.WalletFloorOutcome{}, err
	}
	a.pauses.Lock()
	defer a.pauses.Unlock()
	var floorMarker []byte
	a.withLock(func() { floorMarker, err = a.floorMarkerLocked() })
	if err != nil {
		return servicebridge.WalletFloorOutcome{}, err
	}
	outcome, err := servicebridge.ApplyWalletFloor(a.rail.StateDir, balance, a.config.minWallet, floorMarker, a.now())
	if err != nil {
		return outcome, err
	}
	a.withLock(func() {
		switch outcome.Action {
		case servicebridge.WalletFloorPaused:
			err = a.store.writeOrigin(pauseOrigin{Marker: outcome.Marker, Why: pauseForWalletFloor,
				WrittenUnix: a.now().Unix()})
		case servicebridge.WalletFloorLifted:
			err = a.store.clearOrigin()
		default:
			err = a.dropStaleOriginLocked()
		}
	})
	return outcome, err
}

// dropStaleOriginLocked removes a pause-origin record whose marker is gone
// or was replaced: it can never match again. The caller holds a.mutex.
func (a *Agent) dropStaleOriginLocked() error {
	origin, err := a.store.readOrigin()
	if err != nil || origin == nil {
		return err
	}
	current, err := readMarkerBytes(a.rail.StateDir)
	if errors.Is(err, os.ErrNotExist) || (err == nil && !bytes.Equal(current, origin.Marker)) {
		return a.store.clearOrigin()
	}
	return nil
}
