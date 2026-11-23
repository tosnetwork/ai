//go:build windows

package mcpprovider

// Windows has no O_NOFOLLOW. The server's deployment check refuses to start
// off Linux (it reads the agent socket's owner), so this only lets the
// package build.
const noFollow = 0
