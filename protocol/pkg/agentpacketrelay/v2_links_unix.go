//go:build !windows

package agentpacketrelay

import (
	"os"
	"syscall"
)

func singleV2Link(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
