//go:build !windows

package mcpbuyer

import "syscall"

const noFollow = syscall.O_NOFOLLOW
