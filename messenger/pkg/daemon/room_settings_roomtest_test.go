//go:build roomtest

package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/messenger/pkg/room"
)

func roomTestConfig(t *testing.T, set func(*RelayCarriageConfig)) Config {
	t.Helper()
	config := relayConfig(t)
	config.RelayCarriage.MLSDriverPath = "/usr/bin/tos-openmls-driver"
	set(config.RelayCarriage)
	return config
}

func uint64Of[T int | uint64](value T) *uint64 {
	converted := uint64(value)
	return &converted
}

// A roomtest build accepts each test setting inside its bounds, refuses it
// outside them and without private rooms, and hands the values to the room
// runtime.
func TestRoomTestBuildBoundsTheRoomTestSettings(t *testing.T) {
	accepted := map[string]func(*RelayCarriageConfig){
		"smallest part":       func(r *RelayCarriageConfig) { r.RoomPartBytes = uint64Of(relayframe.MinTestPartBytes) },
		"largest part":        func(r *RelayCarriageConfig) { r.RoomPartBytes = uint64Of(relayframe.MaxTestPartBytes) },
		"shortest retention":  func(r *RelayCarriageConfig) { r.RoomHandshakeRetentionSeconds = uint64Of(1) },
		"longest retention":   func(r *RelayCarriageConfig) { r.RoomHandshakeRetentionSeconds = uint64Of(7 * 24 * 3600) },
		"shortest authorized": func(r *RelayCarriageConfig) { r.RoomAuthorizationSeconds = uint64Of(60) },
		"longest authorized":  func(r *RelayCarriageConfig) { r.RoomAuthorizationSeconds = uint64Of(24 * 3600) },
	}
	for name, set := range accepted {
		if err := roomTestConfig(t, set).Validate(); err != nil {
			t.Fatalf("%s refused: %v", name, err)
		}
	}
	refused := map[string]struct {
		set     func(*RelayCarriageConfig)
		message string
	}{
		"part below the floor":     {func(r *RelayCarriageConfig) { r.RoomPartBytes = uint64Of(relayframe.MinTestPartBytes - 1) }, "room_part_bytes"},
		"part above the ceiling":   {func(r *RelayCarriageConfig) { r.RoomPartBytes = uint64Of(relayframe.MaxTestPartBytes + 1) }, "room_part_bytes"},
		"zero part":                {func(r *RelayCarriageConfig) { r.RoomPartBytes = uint64Of(0) }, "room_part_bytes"},
		"zero retention":           {func(r *RelayCarriageConfig) { r.RoomHandshakeRetentionSeconds = uint64Of(0) }, "room_handshake_retention_seconds"},
		"retention above 7 days":   {func(r *RelayCarriageConfig) { r.RoomHandshakeRetentionSeconds = uint64Of(7*24*3600 + 1) }, "room_handshake_retention_seconds"},
		"authorization below 1 m":  {func(r *RelayCarriageConfig) { r.RoomAuthorizationSeconds = uint64Of(59) }, "room_authorization_seconds"},
		"authorization above 24 h": {func(r *RelayCarriageConfig) { r.RoomAuthorizationSeconds = uint64Of(24*3600 + 1) }, "room_authorization_seconds"},
		"part without rooms": {func(r *RelayCarriageConfig) {
			r.MLSDriverPath, r.RoomPartBytes = "", uint64Of(relayframe.MinTestPartBytes)
		}, "needs mls_driver_path"},
		"retention without rooms": {func(r *RelayCarriageConfig) {
			r.MLSDriverPath, r.RoomHandshakeRetentionSeconds = "", uint64Of(60)
		}, "needs mls_driver_path"},
		"authorization without rooms": {func(r *RelayCarriageConfig) {
			r.MLSDriverPath, r.RoomAuthorizationSeconds = "", uint64Of(60)
		}, "needs mls_driver_path"},
	}
	for name, test := range refused {
		if err := roomTestConfig(t, test.set).Validate(); err == nil || !strings.Contains(err.Error(), test.message) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	config := roomTestConfig(t, func(r *RelayCarriageConfig) {
		r.RoomPartBytes, r.RoomHandshakeRetentionSeconds = uint64Of(2_048), uint64Of(1_800)
		r.RoomAuthorizationSeconds, r.OwnRelayMaxTTLSeconds = uint64Of(120), 900
	})
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	stated, err := config.RelayCarriage.RoomSettings()
	if err != nil || !stated.TestSettings || stated.PartBytes != 2_048 || stated.HandshakeRetention != 30*time.Minute ||
		stated.Authorization != 2*time.Minute || stated.OwnRelayMaxTTLSeconds != 900 {
		t.Fatalf("the stated room settings: %+v %v", stated, err)
	}
	if line, err := config.RoomSettingsLine(); err != nil || line != "room_settings build=roomtest private_rooms=on "+
		"room_part_bytes=2048 room_handshake_retention_seconds=1800 room_authorization_seconds=120 own_relay_max_ttl_seconds=900 test_settings=true" {
		t.Fatalf("the roomtest room settings line: %q %v", line, err)
	}
	d := &Daemon{config: config}
	settings, err := d.configuredRoomSettings(nil, nil)
	if err != nil || settings.partBytes != 2_048 || settings.retention != 30*time.Minute ||
		settings.authorization != 2*time.Minute || settings.gapDelay != 20*time.Minute || settings.skew != 5*time.Minute {
		t.Fatalf("the room runtime's settings: %+v %v", settings, err)
	}
	// Unset settings keep the production values in a roomtest build too.
	plain := roomTestConfig(t, func(*RelayCarriageConfig) {})
	if stated, err := plain.RelayCarriage.RoomSettings(); err != nil || stated.TestSettings || stated.PartBytes != 0 ||
		stated.HandshakeRetention != room.RoomHandshakeRetention || stated.Authorization != room.MaxMembershipAuthorizationWindow {
		t.Fatalf("unset room settings: %+v %v", stated, err)
	}
}
