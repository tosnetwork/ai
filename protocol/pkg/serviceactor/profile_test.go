package serviceactor

import (
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

// The window lower bound follows the code the actor runs: ten minutes is
// admitted only against the pinned test-profile code, and refused against
// the release code and any other code.
func TestTenMinuteWindowsFollowTheActorCode(t *testing.T) {
	release, test := nativecore.ServiceActorReleaseCodeHash, nativecore.ServiceActorTestProfileCodeHash
	const tenMinutes, hour = nativecore.ServiceActorTestProfileMinimumWindowSeconds, nativecore.ServiceActorMinimumWindowSeconds
	cases := []struct {
		name           string
		code           [32]byte
		sla, window    uint32
		wantAdmitted   bool
		wantRefusalMsg string
	}{
		{"release, ten-minute SLA", release, tenMinutes, hour, false, "response_sla"},
		{"release, ten-minute refund window", release, hour, tenMinutes, false, "refund_claim_window"},
		{"release, both ten minutes", release, tenMinutes, tenMinutes, false, "response_sla"},
		{"release, one hour", release, hour, hour, true, ""},
		{"other code, ten minutes", testCode, tenMinutes, tenMinutes, false, "response_sla"},
		{"test, both ten minutes", test, tenMinutes, tenMinutes, true, ""},
		{"test, one hour", test, hour, hour, true, ""},
		{"test, SLA one second short", test, tenMinutes - 1, tenMinutes, false, "response_sla"},
		{"test, refund window one second short", test, tenMinutes, tenMinutes - 1, false, "refund_claim_window"},
		{"test, SLA above the maximum", test, nativecore.ServiceActorMaximumWindowSeconds + 1, tenMinutes, false, "response_sla"},
	}
	for _, c := range cases {
		f := newFixtureFor(t, c.code, c.sla, c.window)
		_, err := VerifyAdmission(f.evidence, c.code, &f.rail, f.proposal, testBuyer)
		if c.wantAdmitted {
			if err != nil {
				t.Errorf("%s: want admitted, got %v", c.name, err)
			}
			continue
		}
		wantStep(t, c.name, err, "admission", 7)
		if err != nil && !strings.Contains(err.Error(), c.wantRefusalMsg) {
			t.Errorf("%s: want a %s refusal, got %v", c.name, c.wantRefusalMsg, err)
		}
	}
}

// A test-profile actor is admitted only by a buyer that pins the test-profile
// code: a buyer pinning the release refuses it at the code hash step, before
// any window is looked at.
func TestATestProfileActorIsRefusedByAReleasePin(t *testing.T) {
	f := newFixtureFor(t, nativecore.ServiceActorTestProfileCodeHash,
		nativecore.ServiceActorTestProfileMinimumWindowSeconds, nativecore.ServiceActorTestProfileMinimumWindowSeconds)
	_, err := VerifyAdmission(f.evidence, nativecore.ServiceActorReleaseCodeHash, &f.rail, f.proposal, testBuyer)
	wantStep(t, "release pin", err, "binding", 3)
}

func TestCheckPolicyBoundsUsesTheGivenCode(t *testing.T) {
	f := newFixtureFor(t, testCode, 600, 600)
	policy := f.evidence.Actor.Data.Policy
	if err := CheckPolicyBounds(policy, nativecore.ServiceActorReleaseCodeHash); err == nil {
		t.Error("ten-minute windows passed the release bounds")
	}
	if err := CheckPolicyBounds(policy, nativecore.ServiceActorTestProfileCodeHash); err != nil {
		t.Errorf("ten-minute windows failed the test-profile bounds: %v", err)
	}
}
