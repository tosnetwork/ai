//go:build !linux

package executorservice

import (
	"errors"
	"net"
)

// Without a kernel-attested peer credential there is no caller identity to
// check, so the service refuses to run rather than accept any local user.
func peerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("executor service peer credential is unsupported on this platform")
}

// Listen is supported on Linux only.
func Listen(string, uint32) (*net.UnixListener, error) {
	return nil, errors.New("executor service is unsupported on this platform")
}
