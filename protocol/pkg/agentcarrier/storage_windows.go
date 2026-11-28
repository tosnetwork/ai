//go:build windows

package agentcarrier

import "os"

func singlePrivate(os.FileInfo) bool { return false }
