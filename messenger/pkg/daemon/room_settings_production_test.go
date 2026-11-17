//go:build !roomtest

package daemon

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/room"
)

// roomTestSettingCases name each room test setting with a value inside its
// test bounds: a production build must refuse each of them whatever the
// value, zero included.
func roomTestSettingCases() map[string]func(*RelayCarriageConfig, uint64) {
	return map[string]func(*RelayCarriageConfig, uint64){
		"room_part_bytes":                  func(r *RelayCarriageConfig, v uint64) { r.RoomPartBytes = &v },
		"room_handshake_retention_seconds": func(r *RelayCarriageConfig, v uint64) { r.RoomHandshakeRetentionSeconds = &v },
		"room_authorization_seconds":       func(r *RelayCarriageConfig, v uint64) { r.RoomAuthorizationSeconds = &v },
	}
}

// A production build refuses a configuration naming any room test setting,
// with an error naming it, through Validate, through DecodeConfig and at
// the room runtime's own derivation of its settings.
func TestProductionBuildRefusesRoomTestSettings(t *testing.T) {
	production := relayConfig(t)
	production.RelayCarriage.MLSDriverPath = "/usr/bin/tos-openmls-driver"
	if err := production.Validate(); err != nil {
		t.Fatalf("a production room configuration: %v", err)
	}
	settings, err := production.RelayCarriage.RoomSettings()
	if err != nil || settings.PartBytes != 0 || settings.HandshakeRetention != room.RoomHandshakeRetention ||
		settings.Authorization != room.MaxMembershipAuthorizationWindow || settings.TestSettings ||
		settings.OwnRelayMaxTTLSeconds != 86_400 {
		t.Fatalf("production room settings: %+v %v", settings, err)
	}
	for name, set := range roomTestSettingCases() {
		for _, value := range []uint64{0, 1_024, 3_600} {
			config := relayConfig(t)
			config.RelayCarriage.MLSDriverPath = "/usr/bin/tos-openmls-driver"
			set(config.RelayCarriage, value)
			err := config.Validate()
			if !errors.Is(err, ErrRoomTestSettingRefused) || !strings.Contains(err.Error(), name) {
				t.Fatalf("%s=%d: Validate answered %v", name, value, err)
			}
			raw, marshalErr := json.Marshal(config)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if !strings.Contains(string(raw), `"`+name+`":`) {
				t.Fatalf("%s is not named in the encoded configuration", name)
			}
			if _, err := DecodeConfig(raw); !errors.Is(err, ErrRoomTestSettingRefused) || !strings.Contains(err.Error(), name) {
				t.Fatalf("%s=%d: DecodeConfig answered %v", name, value, err)
			}
			d := &Daemon{config: config}
			if _, err := d.configuredRoomSettings(nil, nil); !errors.Is(err, ErrRoomTestSettingRefused) {
				t.Fatalf("%s=%d: the runtime's settings answered %v", name, value, err)
			}
		}
	}
	// The stated line names the production build, with and without rooms.
	if line, err := production.RoomSettingsLine(); err != nil || line != "room_settings build=production private_rooms=on "+
		"room_part_bytes=0 room_handshake_retention_seconds=604800 room_authorization_seconds=86400 own_relay_max_ttl_seconds=86400 test_settings=false" {
		t.Fatalf("the production room settings line: %q %v", line, err)
	}
	if line, err := relayConfig(t).RoomSettingsLine(); err != nil || line != "room_settings build=production private_rooms=off" {
		t.Fatalf("the production line without rooms: %q %v", line, err)
	}
	// The own relays' TTL is a production setting: it is accepted and
	// derives the gap delay.
	production.RelayCarriage.OwnRelayMaxTTLSeconds = 3_600
	d := &Daemon{config: production}
	derived, err := d.configuredRoomSettings(nil, nil)
	if err != nil || derived.gapDelay != time.Hour+5*time.Minute || derived.partBytes != 0 ||
		derived.retention != room.RoomHandshakeRetention || derived.authorization != room.MaxMembershipAuthorizationWindow {
		t.Fatalf("the production runtime settings: %+v %v", derived, err)
	}
}
