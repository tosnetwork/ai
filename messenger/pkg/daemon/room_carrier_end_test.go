package daemon

import (
	"testing"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/group"
)

// The carrier's sweep slack is the largest clock-skew bound a daemon may be
// configured with, so the carrier never drops a room's card admissions
// before the daemon stops using the room; and the longest room the carrier
// accepts is the longest leaf credential (D18).
func TestCarrierRoomEndSlackIsTheLargestDaemonClockSkew(t *testing.T) {
	admission := testConfig(t).Admission
	admission.MaxClockSkewSeconds = carrierapi.RoomEndSlackSeconds
	if err := admission.Validate(); err != nil {
		t.Fatalf("a clock-skew bound equal to the carrier's slack was refused: %v", err)
	}
	admission.MaxClockSkewSeconds = carrierapi.RoomEndSlackSeconds + 1
	if err := admission.Validate(); err == nil {
		t.Fatal("a clock-skew bound beyond the carrier's slack was accepted")
	}
	if carrierapi.MaxRoomLifetimeSeconds != group.MaxCredentialLifetimeSeconds {
		t.Fatalf("the carrier's longest room %d differs from the longest leaf credential %d",
			carrierapi.MaxRoomLifetimeSeconds, group.MaxCredentialLifetimeSeconds)
	}
}
