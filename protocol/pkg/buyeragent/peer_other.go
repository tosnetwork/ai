//go:build !linux

package buyeragent

import (
	"errors"
	"net"
)

// peerUID has no implementation off Linux, so every peer is refused: the
// agent authorizes only by kernel-reported credentials.
func peerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("peer credentials are supported on Linux only")
}
