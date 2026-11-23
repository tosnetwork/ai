//go:build linux

package agentsocket

import (
	"errors"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// checkSocketGroup requires the socket directory to be setgid and to belong
// to a group other than the agent's own, so the socket the agent creates in
// it belongs to the group the client account shares. Without that the
// socket would carry the agent's private group and the client account could
// never connect.
func checkSocketGroup(info os.FileInfo, agentGID uint32) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("the socket directory's group cannot be read")
	}
	if info.Mode()&os.ModeSetgid == 0 {
		return errors.New("the socket directory must be setgid (mode 2750) so the socket belongs to the group " +
			"the client account shares")
	}
	if stat.Gid == agentGID {
		return errors.New("the socket directory must belong to the group the client account shares, not the " +
			"agent's own group")
	}
	return nil
}

// PeerUID returns the connecting process's uid as the kernel recorded it at
// connect time (SO_PEERCRED); nothing the peer sends can change it.
func PeerUID(connection *net.UnixConn) (uint32, error) {
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
