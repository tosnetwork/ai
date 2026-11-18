//go:build !linux

package buyerconfirm

import (
	"errors"
	"os"
)

// OpenTerminal refuses off Linux, where the buyer agent and its custody do
// not run.
func OpenTerminal(*os.File) (*os.File, error) {
	return nil, errors.New("the confirmer runs on Linux only")
}
