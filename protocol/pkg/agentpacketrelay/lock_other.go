//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package agentpacketrelay

import (
	"errors"
	"os"
)

// lockFile refuses platforms without the advisory lock the store relies on
// to keep a second process out of its state directory.
func lockFile(*os.File) error {
	return errors.New("the durable relay store is not supported on this platform")
}
