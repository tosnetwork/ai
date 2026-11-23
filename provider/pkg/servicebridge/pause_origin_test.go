package servicebridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// v1Marker is a marker exactly as the release before the origin field wrote
// it: json.Marshal of {schema, paused_unix, reason}.
const v1Marker = `{"schema":"tos.openfox.rail-admission-pause.v1","paused_unix":1800000000,"reason":"maintenance"}`

func writeMarker(t *testing.T, state, content string) []byte {
	t.Helper()
	if err := os.WriteFile(filepath.Join(state, AdmissionPauseFile), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return []byte(content)
}

func markerBytes(t *testing.T, state string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(state, AdmissionPauseFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestAV1MarkerReadsAsAnOperatorPause(t *testing.T) {
	state := privateStateDir(t)
	written := writeMarker(t, state, v1Marker)
	pause, data, err := ReadAdmissionPauseMarker(state)
	if err != nil || pause == nil || pause.Origin != PauseOriginOperator || pause.Stamp != "" ||
		pause.PausedUnix != 1_800_000_000 || pause.Reason != "maintenance" || !bytes.Equal(data, written) {
		t.Fatalf("a v1 marker: %+v %q %v", pause, data, err)
	}
	// Neither pause changes an operator marker, and the agent's pause
	// reports whose it is.
	for _, origin := range []string{PauseOriginAgent, PauseOriginOperator} {
		result, pauseErr := PauseAdmissionAs(state, origin, "other", time.Unix(1_900_000_000, 0))
		if pauseErr != nil || !result.Already || result.Restamped || result.PreviousOrigin != PauseOriginOperator ||
			!bytes.Equal(markerBytes(t, state), written) {
			t.Fatalf("a %s pause over a v1 marker: %+v %v", origin, result, pauseErr)
		}
	}
	// The status and the provider see it as paused.
	if err := (&Provider{config: ProviderConfig{StateDir: state}}).admissionOpen(); !errors.Is(err, ErrAdmissionPaused) {
		t.Fatalf("a v1 marker opened admission: %v", err)
	}
	// A compare-and-remove against its bytes removes it.
	if removed, err := ResumeAdmissionIf(state, written); err != nil || !removed {
		t.Fatalf("a v1 marker was not removed by its bytes: %v %v", removed, err)
	}
	// A v1 marker carries no origin or stamp.
	writeMarker(t, state, `{"schema":"tos.openfox.rail-admission-pause.v1","paused_unix":1,"origin":"agent",`+
		`"stamp":"00000000000000000000000000000000"}`)
	if _, err := ReadAdmissionPause(state); err == nil {
		t.Fatal("a v1 marker with an origin was read")
	}
}

func TestEveryWriteIsAV2MarkerWithItsOriginAndAFreshStamp(t *testing.T) {
	state := privateStateDir(t)
	stamps := map[string]bool{}
	for _, origin := range []string{PauseOriginAgent, PauseOriginOperator, PauseOriginAgent} {
		result, err := PauseAdmissionAs(state, origin, "why", time.Unix(1_800_000_000, 0))
		if err != nil || result.Already {
			t.Fatal(result, err)
		}
		var stored map[string]any
		if err := json.Unmarshal(markerBytes(t, state), &stored); err != nil {
			t.Fatal(err)
		}
		if stored["schema"] != admissionPauseSchema || stored["origin"] != origin ||
			!pauseStampPattern.MatchString(stored["stamp"].(string)) || stored["paused_unix"] != float64(1_800_000_000) {
			t.Fatalf("the %s marker: %v", origin, stored)
		}
		if !bytes.Equal(result.Marker, markerBytes(t, state)) {
			t.Fatal("the result's bytes are not the file's")
		}
		stamps[stored["stamp"].(string)] = true
		if _, err := ResumeAdmission(state); err != nil {
			t.Fatal(err)
		}
	}
	if len(stamps) != 3 {
		t.Fatalf("three writes drew %d stamps", len(stamps))
	}
	if _, err := PauseAdmissionAs(state, "model", "", time.Unix(1_800_000_000, 0)); err == nil {
		t.Fatal("an origin other than operator or agent was written")
	}
}

func TestAMarkerThisReleaseDoesNotKnowHoldsAdmissionAndIsNeverReplaced(t *testing.T) {
	stamp := strings.Repeat("ab", 16)
	for name, content := range map[string]string{
		"a later schema": `{"schema":"tos.openfox.rail-admission-pause.v3","paused_unix":1800000000,"origin":"agent",` +
			`"stamp":"` + stamp + `","holder":"x"}`,
		"an unknown origin": `{"schema":"tos.openfox.rail-admission-pause.v2","paused_unix":1800000000,` +
			`"origin":"model","stamp":"` + stamp + `"}`,
		"no origin":     `{"schema":"tos.openfox.rail-admission-pause.v2","paused_unix":1800000000,"stamp":"` + stamp + `"}`,
		"a short stamp": `{"schema":"tos.openfox.rail-admission-pause.v2","paused_unix":1800000000,"origin":"agent","stamp":"ab"}`,
		"an unknown field": `{"schema":"tos.openfox.rail-admission-pause.v2","paused_unix":1800000000,"origin":"agent",` +
			`"stamp":"` + stamp + `","extra":1}`,
		"trailing data": `{"schema":"tos.openfox.rail-admission-pause.v2","paused_unix":1800000000,"origin":"agent",` +
			`"stamp":"` + stamp + `"} {}`,
		"no schema": `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			state := privateStateDir(t)
			written := writeMarker(t, state, content)
			_, err := ReadAdmissionPause(state)
			if err == nil || !strings.Contains(err.Error(), "pause marker is invalid") {
				t.Fatalf("read: %v", err)
			}
			if name == "a later schema" && !strings.Contains(err.Error(), "program of the same release") {
				t.Fatalf("the message does not say what to do: %v", err)
			}
			provider := &Provider{config: ProviderConfig{StateDir: state}}
			if err := provider.admissionOpen(); !errors.Is(err, ErrAdmissionPaused) {
				t.Fatalf("admission opened: %v", err)
			}
			for _, origin := range []string{PauseOriginOperator, PauseOriginAgent} {
				_, pauseErr := PauseAdmissionAs(state, origin, "", time.Unix(1_900_000_000, 0))
				if pauseErr == nil || !strings.Contains(pauseErr.Error(), "admission stays paused") {
					t.Fatalf("a %s pause over it: %v", origin, pauseErr)
				}
			}
			if !bytes.Equal(markerBytes(t, state), written) {
				t.Fatal("the marker was changed")
			}
		})
	}
}

func TestAnOperatorPauseReStampsAnAgentPauseKeepingItsFirstTime(t *testing.T) {
	state := privateStateDir(t)
	first := time.Unix(1_800_000_000, 0)
	agent, err := PauseAdmissionAs(state, PauseOriginAgent, "mcp: drain", first)
	if err != nil || agent.Already {
		t.Fatal(agent, err)
	}
	// The agent's own second pause changes nothing.
	again, err := PauseAdmissionAs(state, PauseOriginAgent, "mcp: again", first.Add(time.Minute))
	if err != nil || !again.Already || again.Restamped || again.PreviousOrigin != PauseOriginAgent ||
		!bytes.Equal(markerBytes(t, state), agent.Marker) {
		t.Fatalf("a second agent pause: %+v %v", again, err)
	}
	operator, err := PauseAdmissionAs(state, PauseOriginOperator, "", first.Add(time.Hour))
	if err != nil || !operator.Already || !operator.Restamped || operator.PreviousOrigin != PauseOriginAgent {
		t.Fatalf("the operator's pause: %+v %v", operator, err)
	}
	pause, data, err := ReadAdmissionPauseMarker(state)
	if err != nil || pause.Origin != PauseOriginOperator || pause.PausedUnix != first.Unix() ||
		pause.Stamp == agent.Pause.Stamp || pause.Reason != "mcp: drain" || !bytes.Equal(data, operator.Marker) {
		t.Fatalf("the re-stamped marker: %+v %v", pause, err)
	}
	// The agent can no longer lift it by the bytes it wrote.
	if removed, err := ResumeAdmissionIf(state, agent.Marker); !errors.Is(err, ErrPauseMarkerChanged) || removed {
		t.Fatalf("the agent lifted an operator marker: %v %v", removed, err)
	}
	if !bytes.Equal(markerBytes(t, state), operator.Marker) {
		t.Fatal("a failed compare-and-remove changed the marker")
	}
	// A further operator pause changes nothing; an operator reason replaces
	// the agent's on a re-stamp.
	if again, err := PauseAdmissionAs(state, PauseOriginOperator, "x", first.Add(2*time.Hour)); err != nil ||
		!again.Already || again.Restamped || !bytes.Equal(markerBytes(t, state), operator.Marker) {
		t.Fatalf("a second operator pause: %+v %v", again, err)
	}
	if _, err := ResumeAdmission(state); err != nil {
		t.Fatal(err)
	}
	if _, err := PauseAdmissionAs(state, PauseOriginAgent, "mcp: a", first); err != nil {
		t.Fatal(err)
	}
	if restamped, err := PauseAdmissionAs(state, PauseOriginOperator, "incident", first); err != nil ||
		restamped.Pause.Reason != "incident" {
		t.Fatalf("the operator's reason: %+v %v", restamped, err)
	}
}

func TestACompareAndRemoveRemovesOnlyTheExpectedMarker(t *testing.T) {
	state := privateStateDir(t)
	if removed, err := ResumeAdmissionIf(state, []byte("{}")); err != nil || removed {
		t.Fatalf("with no marker: %v %v", removed, err)
	}
	for _, expected := range [][]byte{nil, {}, bytes.Repeat([]byte("x"), maxPauseMarker+1)} {
		if _, err := ResumeAdmissionIf(state, expected); err == nil {
			t.Fatalf("expected bytes of length %d were accepted", len(expected))
		}
	}
	result, err := PauseAdmissionAs(state, PauseOriginAgent, "", time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	other := append([]byte(nil), result.Marker...)
	other[len(other)-3] ^= 1
	if removed, err := ResumeAdmissionIf(state, other); !errors.Is(err, ErrPauseMarkerChanged) || removed {
		t.Fatalf("other bytes removed the marker: %v %v", removed, err)
	}
	if removed, err := ResumeAdmissionIf(state, result.Marker); err != nil || !removed {
		t.Fatalf("the expected bytes: %v %v", removed, err)
	}
	if markerBytes(t, state) != nil {
		t.Fatal("the marker survived")
	}
	// The operator's resume removes whatever marker there is.
	if _, err := PauseAdmissionAs(state, PauseOriginAgent, "", time.Unix(1_800_000_000, 0)); err != nil {
		t.Fatal(err)
	}
	if was, err := ResumeAdmission(state); err != nil || !was {
		t.Fatalf("the operator's resume: %v %v", was, err)
	}
}

// A re-stamp made between the agent's read of the marker and its removal
// makes the removal fail, and the operator's marker stays.
func TestAReStampBetweenTheAgentsReadAndItsRemovalKeepsTheOperatorsMarker(t *testing.T) {
	state := privateStateDir(t)
	agent, err := PauseAdmissionAs(state, PauseOriginAgent, "mcp: x", time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	// The agent reads the marker and decides to lift it...
	_, read, err := ReadAdmissionPauseMarker(state)
	if err != nil || !bytes.Equal(read, agent.Marker) {
		t.Fatal(err)
	}
	// ...the operator pauses meanwhile...
	if _, _, err := PauseAdmission(state, "", time.Unix(1_800_000_100, 0)); err != nil {
		t.Fatal(err)
	}
	// ...and the agent's removal fails.
	if removed, err := ResumeAdmissionIf(state, read); !errors.Is(err, ErrPauseMarkerChanged) || removed {
		t.Fatalf("the removal went through: %v %v", removed, err)
	}
	if pause, err := ReadAdmissionPause(state); err != nil || pause == nil || pause.Origin != PauseOriginOperator {
		t.Fatalf("the operator's marker is gone: %+v %v", pause, err)
	}
}

// The compare and the removal are one step under the marker's lock: an
// operator pause that arrives between them waits, and writes its marker
// after the removal instead of being removed by it.
func TestTheMarkerLockSerializesAPauseWithACompareAndRemove(t *testing.T) {
	state := privateStateDir(t)
	agent, err := PauseAdmissionAs(state, PauseOriginAgent, "", time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	pauseHookAfterRead = func() {
		pauseHookAfterRead = nil
		go func() {
			_, _, pauseErr := PauseAdmission(state, "incident", time.Unix(1_800_000_100, 0))
			finished <- pauseErr
		}()
		// Without the lock the operator's pause would re-stamp the marker
		// here, and the removal below would remove the operator's marker.
		select {
		case pauseErr := <-finished:
			finished <- pauseErr
		case <-time.After(300 * time.Millisecond):
		}
	}
	t.Cleanup(func() { pauseHookAfterRead = nil })
	if removed, err := ResumeAdmissionIf(state, agent.Marker); err != nil || !removed {
		t.Fatalf("the removal: %v %v", removed, err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	pause, err := ReadAdmissionPause(state)
	if err != nil || pause == nil || pause.Origin != PauseOriginOperator || pause.Reason != "incident" {
		t.Fatalf("the operator's pause was lost: %+v %v", pause, err)
	}
}

func TestAPauseThatCannotTakeTheLockChangesNothing(t *testing.T) {
	state := privateStateDir(t)
	lock, err := acquireRunLock(filepath.Join(state, AdmissionPauseLockFile), errPauseLockHeld)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseRunLock(lock)
	saved := pauseLockWait
	pauseLockWait = 50 * time.Millisecond
	t.Cleanup(func() { pauseLockWait = saved })
	if _, err := PauseAdmissionAs(state, PauseOriginOperator, "", time.Unix(1_800_000_000, 0)); !errors.Is(err,
		ErrPauseBusy) {
		t.Fatalf("a pause without the lock: %v", err)
	}
	if markerBytes(t, state) != nil {
		t.Fatal("a pause without the lock wrote a marker")
	}
	writeMarker(t, state, v1Marker)
	for _, resume := range []func() (bool, error){
		func() (bool, error) { return ResumeAdmission(state) },
		func() (bool, error) { return ResumeAdmissionIf(state, []byte(v1Marker)) },
	} {
		if _, err := resume(); !errors.Is(err, ErrPauseBusy) {
			t.Fatalf("a resume without the lock: %v", err)
		}
	}
	if !bytes.Equal(markerBytes(t, state), []byte(v1Marker)) {
		t.Fatal("a resume without the lock removed the marker")
	}
}

func TestTheStatusReportsTheMarkersOrigin(t *testing.T) {
	config, _ := statusNode(t)
	state := config.StateDir
	statusFor := func(t *testing.T, _ string) *ProviderStatus {
		t.Helper()
		status, err := ReadProviderStatus(context.Background(), config, nil, time.Unix(1_800_000_100, 0))
		if err != nil {
			t.Fatal(err)
		}
		return status
	}
	result, err := PauseAdmissionAs(state, PauseOriginAgent, "mcp: x", time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	status := statusFor(t, state)
	if !status.Admission.Paused || status.Admission.Origin != PauseOriginAgent ||
		status.Admission.Stamp != result.Pause.Stamp {
		t.Fatalf("status: %+v", status.Admission)
	}
	if _, err := ResumeAdmission(state); err != nil {
		t.Fatal(err)
	}
	writeMarker(t, state, v1Marker)
	status = statusFor(t, state)
	if status.Admission.Origin != PauseOriginOperator || status.Admission.Stamp != "" {
		t.Fatalf("status of a v1 marker: %+v", status.Admission)
	}
}
