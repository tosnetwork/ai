//go:build !linux

package buyeragent

import (
	"errors"
	"net"
	"os"
)

// checkSocketGroup cannot read a group off Linux; the socket is refused.
func checkSocketGroup(os.FileInfo) error {
	return errors.New("the socket directory's group is checked on Linux only")
}

// peerUID has no implementation off Linux, so every peer is refused: the
// agent authorizes only by kernel-reported credentials.
func peerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("peer credentials are supported on Linux only")
}
