//go:build linux

package buyeragent

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the connecting process's uid as the kernel recorded it
// at connect time (SO_PEERCRED); nothing the peer sends can change it.
func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credentials *unix.Ucred
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credentialErr != nil {
		return 0, credentialErr
	}
	if credentials == nil {
		return 0, errors.New("no peer credentials")
	}
	return credentials.Uid, nil
}
