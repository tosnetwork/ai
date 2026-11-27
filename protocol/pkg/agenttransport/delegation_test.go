package agenttransport

import (
	"crypto/ed25519"
	"testing"
)

func sample() Delegation {
	key := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	d := Delegation{AuthorizationEpoch: 1, Purposes: 7, NotBefore: 1800000000, NotAfter: 1800003600, MaxCredentialSeconds: 600}
	copy(d.TransportKey[:], key)
	return d
}

func TestCodec(t *testing.T) {
	d := sample()
	b, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 167 {
		t.Fatal(len(b))
	}
	got, err := DecodeDelegation(b)
	if err != nil || got != d {
		t.Fatalf("decode: %v", err)
	}
	for _, bad := range [][]byte{nil, b[:166], append(append([]byte{}, b...), 0)} {
		if _, err := DecodeDelegation(bad); err == nil {
			t.Fatal("accepted wrong size")
		}
	}
}
