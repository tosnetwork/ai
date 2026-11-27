//go:build windows

package agentpacketrelay

import "os"

func singleV2Link(os.FileInfo) bool { return false }
