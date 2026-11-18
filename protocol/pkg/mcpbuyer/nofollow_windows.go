//go:build windows

package mcpbuyer

// Windows has no O_NOFOLLOW; the walk already refuses links by their
// directory entry type.
const noFollow = 0
