//go:build !linux

package agentsocket

import (
	"errors"
	"net"
	"os"
)

// checkSocketGroup cannot read a group off Linux; the socket is refused.
func checkSocketGroup(os.FileInfo, uint32) error {
	return errors.New("the socket directory's group is checked on Linux only")
}

// SocketOwner cannot read an owner off Linux; every socket is refused.
func SocketOwner(string) (uint32, error) {
	return 0, errors.New("socket owners are read on Linux only")
}

// PeerUID has no implementation off Linux, so every peer is refused: the
// agent authorizes only by kernel-reported credentials.
func PeerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("peer credentials are supported on Linux only")
}
