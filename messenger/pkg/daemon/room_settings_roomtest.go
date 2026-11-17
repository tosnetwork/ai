//go:build roomtest

package daemon

// roomTestSettingsAllowed is true only in a build with the roomtest tag,
// which accepts the room test settings within their bounds (sections 11.1
// and 11.3). Such a build is for tests and live test records only.
const roomTestSettingsAllowed = true
