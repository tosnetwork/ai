//go:build !windows

package mcpprovider

import "syscall"

const noFollow = syscall.O_NOFOLLOW
