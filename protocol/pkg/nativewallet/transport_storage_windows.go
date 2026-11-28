//go:build windows

package nativewallet

import "os"

func singleTransportLink(os.FileInfo) bool { return false }
