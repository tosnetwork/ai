package group

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

// A decoded leaf credential is canonical: it re-encodes to exactly its input.
func FuzzDecodeLeafCredential(f *testing.F) {
	endpoint := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	leaf := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, ed25519.SeedSize))
	if signed, err := SignLeafCredential(LeafCredential{
		Network: &nativev1.NetworkDomain{NetworkId: "tos-local", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)},
		AgentID: "agent_" + strings.Repeat("c", 64), EndpointID: "mep_" + strings.Repeat("d", 64), DeviceID: "dev_" + strings.Repeat("e", 64),
		DeviceSetDigest: canon.Digest([]byte("set")), LeafSignaturePublicKey: leaf.Public().(ed25519.PublicKey),
		IssuedAtUnix: 100, ExpiresAtUnix: 1000}, endpoint); err == nil {
		if raw, err := EncodeLeafCredential(signed); err == nil {
			f.Add(raw)
		}
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		credential, err := DecodeLeafCredential(raw)
		if err != nil {
			return
		}
		encoded, err := EncodeLeafCredential(credential)
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatalf("a decoded leaf credential is not canonical: %v", err)
		}
		if _, err := EncodeLeafIdentity(credential); err != nil {
			t.Fatalf("a decoded credential has no identity: %v", err)
		}
	})
}
