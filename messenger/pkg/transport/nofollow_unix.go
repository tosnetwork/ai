//go:build unix

package transport

import "syscall"

// noFollow refuses to open a journal record through a symbolic link.
const noFollow = syscall.O_NOFOLLOW
