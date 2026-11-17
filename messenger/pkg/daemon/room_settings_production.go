//go:build !roomtest

package daemon

// roomTestSettingsAllowed is false in a production build: a configuration
// naming room_part_bytes, room_handshake_retention_seconds or
// room_authorization_seconds is refused (sections 11.1 and 11.3).
const roomTestSettingsAllowed = false

// RoomBuildVariant names this build in the room settings a record states.
const RoomBuildVariant = "production"
