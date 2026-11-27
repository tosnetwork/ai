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

func TestSmallestLifetimeLimits(t *testing.T) {
	d := sample()
	d.NotAfter = d.NotBefore + 1
	d.MaxCredentialSeconds = 1
	b, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeDelegation(b); err != nil {
		t.Fatal(err)
	}
}

func FuzzDecodeDelegation(f *testing.F) {
	b, err := sample().Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte{})
	f.Add(append(append([]byte{}, b...), 0))
	f.Fuzz(func(t *testing.T, wire []byte) {
		d, err := DecodeDelegation(wire)
		if err != nil {
			return
		}
		encoded, err := d.Encode()
		if err != nil || string(encoded) != string(wire) {
			t.Fatalf("accepted noncanonical encoding: %v", err)
		}
	})
}
