//go:build !windows

package agentpacketrelay

import (
	"os"
	"syscall"
	"testing"
)

type v2OwnerInfo struct {
	os.FileInfo
	stat syscall.Stat_t
	mode os.FileMode
}

func (i v2OwnerInfo) Sys() any          { return &i.stat }
func (i v2OwnerInfo) Mode() os.FileMode { return i.mode }
func (i v2OwnerInfo) IsDir() bool       { return i.mode.IsDir() }

func TestV2AncestorOwnerCannotReplaceStore(t *testing.T) {
	info, err := os.Stat(v2Temp(t))
	if err != nil {
		t.Fatal(err)
	}
	own := v2OwnerInfo{FileInfo: info, stat: syscall.Stat_t{Uid: uint32(os.Geteuid())}, mode: os.ModeDir | 0o755}
	if !trustedV2Ancestor(own) {
		t.Fatal("current owner refused")
	}
	root := own
	root.stat.Uid = 0
	root.mode = os.ModeDir | os.ModeSticky | 0o777
	if !trustedV2Ancestor(root) {
		t.Fatal("root-owned sticky temporary directory refused")
	}
	foreign := own
	foreign.stat.Uid = 1
	if os.Geteuid() == 1 {
		foreign.stat.Uid = 2
	}
	if trustedV2Ancestor(foreign) {
		t.Fatal("foreign owner could replace the store's directory")
	}
	foreign.mode = os.ModeDir | os.ModeSticky | 0o777
	if trustedV2Ancestor(foreign) {
		t.Fatal("sticky bit does not stop its owner replacing a child")
	}
}
