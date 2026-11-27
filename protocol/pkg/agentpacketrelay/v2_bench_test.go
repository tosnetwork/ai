package agentpacketrelay

import (
	"path/filepath"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

// Fixed-size restart input measures index reconstruction, not credential signing.
// The named quota and replay tests independently establish each admission bound.
func BenchmarkV2Restart512(b *testing.B) {
	path := filepath.Join(v2Temp(b), "v2")
	limits := DefaultV2Limits(1024, 64<<20)
	s := v2Open(b, path, limits, testStart)
	now := uint64(testStart.Unix())
	for box := range 2 {
		r := newRecipient(b)
		for lane := range 4 {
			var id [16]byte
			id[0] = byte(lane + 1)
			wire, holder := v2Credential(b, r, agenttransport.LaneCaveat(id))
			checked := v2Checked(b, wire, holder, r.agentID, now, byte(lane))
			for range 64 {
				if got := v2Deposit(b, s, r, r.seal(b, testPacket(1), now+3600), v2Loopback(box*4+lane+1), now, &checked); got != depositCreated {
					b.Fatal(got)
				}
			}
		}
	}
	v2Close(b, s)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		opened := v2Open(b, path, limits, testStart)
		if got := opened.Usage().ContactEntries; got != 512 {
			b.Fatal(got)
		}
		v2Close(b, opened)
	}
}
