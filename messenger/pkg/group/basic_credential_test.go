package group

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/messenger/internal/canon"
)

// A BasicCredential identity decodes to exactly the fields it encodes, and
// any other byte string is refused.
func TestBasicCredentialIdentityRoundTripsStrictly(t *testing.T) {
	delegation, key := mlsAuthority(t)
	credential := mlsCredential(t, delegation, key, "dev_"+strings.Repeat("7", 64), canon.Digest([]byte("set")))
	raw, err := BasicCredentialIdentity(credential)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBasicCredentialIdentity(raw)
	if err != nil || decoded.AgentID != credential.AgentID || decoded.EndpointID != credential.EndpointID ||
		decoded.DeviceID != credential.DeviceID || decoded.DeviceSetDigest != credential.DeviceSetDigest ||
		!bytes.Equal(decoded.LeafSignaturePublicKey, credential.LeafSignaturePublicKey) ||
		decoded.Network.NetworkId != credential.Network.NetworkId || decoded.Network.GenesisRootHash != credential.Network.GenesisRootHash {
		t.Fatalf("decoded: %+v %v", decoded, err)
	}
	for name, bad := range map[string][]byte{
		"trailing":  append(append([]byte(nil), raw...), 0),
		"truncated": raw[:len(raw)-1],
		"empty":     nil,
		"suite":     append(append([]byte(nil), raw[:len(raw)-1]...), 2),
	} {
		if _, err := DecodeBasicCredentialIdentity(bad); err == nil {
			t.Fatalf("%s identity accepted", name)
		}
	}
}
