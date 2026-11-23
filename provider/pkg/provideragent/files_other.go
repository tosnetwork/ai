//go:build !linux

package provideragent

import (
	"errors"
	"os"
)

// ownedByMe cannot read an owner off Linux: no file is accepted, so the
// agent refuses to start there.
func ownedByMe(os.FileInfo) bool { return false }

var errLockHeld = errors.New("the lock is held")

// tryLock has no implementation off Linux; the agent runs on Linux only.
func tryLock(string) (func(), error) {
	return nil, errors.New("the provider agent runs on Linux only")
}
