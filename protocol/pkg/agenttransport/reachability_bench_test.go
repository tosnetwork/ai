package agenttransport

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func BenchmarkVerifyMaxHintRecord(b *testing.B) {
	f, h, key := hintSample(b)
	h.Relays = make([]string, 4)
	for i := range h.Relays {
		h.Relays[i] = "https://" + string(rune('d'-i)) + strings.Repeat("x", 256-len("https://d.invalid")) + ".invalid"
	}
	h.Direct = []DirectEntry{{Kind: 1, Port: 30001, InboundClass: 1, IPv4: [4]byte{8, 8, 8, 8}}, {Kind: 1, Port: 30002, InboundClass: 2, IPv4: [4]byte{9, 9, 9, 9}}}
	objects := []HintObject{{RailCard, cardJSON(b, f.d.AgentID(), MaxHintCardBytes)}, {ChatCard, cardJSON(b, f.d.AgentID(), MaxHintCardBytes)}, {MessengerEvidence, bytes.Repeat([]byte{1}, MaxHintEvidenceBytes)}}
	raw := signRecord(b, h, objects, key)
	v := f.verifier(b)
	if _, err := v.VerifyHint(context.Background(), raw, HintPolicy{}); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := v.VerifyHint(context.Background(), raw, HintPolicy{}); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkVerifyDirectHello(b *testing.B) {
	f, h, expected, key := directSample(b, HelloResponder)
	raw := helloWire(b, h, key)
	v := f.verifier(b)
	if _, err := v.VerifyHello(context.Background(), raw, expected); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := v.VerifyHello(context.Background(), raw, expected); err != nil {
			b.Fatal(err)
		}
	}
}
