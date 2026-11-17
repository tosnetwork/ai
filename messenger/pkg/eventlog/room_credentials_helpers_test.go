package eventlog

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
)

// testRoomEnd is the end of every test room: the expiry of the test leaf
// credentials.
const testRoomEnd = 2_000_000

// leafBindingFor signs a leaf credential for a delegation and verifies it on
// the room path, which is the only way to obtain a binding.
func leafBindingFor(t *testing.T, delegation identity.Delegation, key ed25519.PrivateKey, leafSeed byte, expires uint64) group.LeafBinding {
	t.Helper()
	leaf := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{leafSeed}, ed25519.SeedSize))
	device := "dev_" + delegation.AgentID[len("agent_"):]
	credential, err := group.SignLeafCredential(group.LeafCredential{Network: delegation.Network, AgentID: delegation.AgentID,
		EndpointID: delegation.EndpointID, DeviceID: device, DeviceSetDigest: canon.Digest([]byte("set")),
		LeafSignaturePublicKey: leaf.Public().(ed25519.PublicKey), IssuedAtUnix: 1, ExpiresAtUnix: expires}, key)
	if err != nil {
		t.Fatal(err)
	}
	set := e2ee.SetSummary{EndpointID: delegation.EndpointID, Digest: credential.DeviceSetDigest, DeviceIDs: []string{device}}
	binding, err := group.VerifyRoomLeafCredential(delegation, credential, set, expires, time.Unix(1_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

// memberBinding is a verified binding of a test Agent: the fixture's
// delegation for fusedAgent(0), the room's authority, and a delegation of its
// own for any other Agent.
func memberBinding(t *testing.T, agentID string) group.LeafBinding {
	t.Helper()
	seed := byte(0x62)
	if agentID == fusedAgent(0) {
		seed = 0x61
	}
	delegation, key := roomDelegation(t, agentID, seed)
	return leafBindingFor(t, delegation, key, 0x29, testRoomEnd)
}

// inviteBinding is the authority credential a test room.invite carries.
func inviteBinding(t *testing.T, agentID string) group.LeafBinding {
	t.Helper()
	return memberBinding(t, agentID)
}

// credentials are the credentials a fixture install holds: the authority's.
func (f *fusedFixture) credentials() []group.LeafBinding {
	f.t.Helper()
	return []group.LeafBinding{memberBinding(f.t, f.delegation.AgentID)}
}
