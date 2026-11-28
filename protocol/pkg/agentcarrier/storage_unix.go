//go:build !windows

package agentcarrier

import (
	"github.com/tosnetwork/ai/protocol/internal/osguard"
	"os"
	"syscall"
)

func singlePrivate(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Nlink == 1 && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && osguard.CurrentUserOwns(info)
}
