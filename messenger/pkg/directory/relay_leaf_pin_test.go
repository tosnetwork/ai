package directory

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
)

func (f *relayFixture) leafCredential(deviceID string, issued, expires uint64) group.LeafCredential {
	f.t.Helper()
	leaf := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x29}, ed25519.SeedSize))
	return group.LeafCredential{Network: f.delegation.Network, AgentID: f.delegation.AgentID, EndpointID: f.delegation.EndpointID,
		DeviceID: deviceID, DeviceSetDigest: canon.Digest([]byte("set")), LeafSignaturePublicKey: leaf.Public().(ed25519.PublicKey),
		IssuedAtUnix: issued, ExpiresAtUnix: expires}
}

// A member's pin is its leaf's Endpoint and device: CheckPeer passes on
// evidence that still holds that device and fails once a newer descriptor
// removed it, exactly as for a session pin.
func TestLeafPinPinsCheckPeerToTheMembersLeaf(t *testing.T) {
	f := newRelayFixture(t)
	credential := f.leafCredential(relayDeviceOne, baseUnix, baseUnix+86_400)
	pin, err := LeafPin(agentID, credential, at(baseUnix+200))
	if err != nil || pin.EndpointID != f.delegation.EndpointID || pin.DeviceID != relayDeviceOne || pin.Bundle != nil {
		t.Fatalf("pin: %+v %v", pin, err)
	}
	current := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, nil)
	if _, err := f.verifier.CheckPeer(agentID, current, pin, at(baseUnix+200)); err != nil {
		t.Fatalf("current leaf: %v", err)
	}
	removed := f.evidence(relayDeviceTwo, "material two", baseUnix+300, 3600, nil)
	_, err = f.verifier.CheckPeer(agentID, removed, pin, at(baseUnix+400))
	requireCode(t, err, fault.CodeDeviceRevoked)

}

// An expired, not yet valid or foreign credential pins nothing.
func TestLeafPinRefusesExpiredOrForeignCredentials(t *testing.T) {
	f := newRelayFixture(t)
	credential := f.leafCredential(relayDeviceOne, baseUnix, baseUnix+100)
	_, err := LeafPin(agentID, credential, at(baseUnix+100))
	requireCode(t, err, fault.CodeNotAuthentic)
	_, err = LeafPin(agentID, credential, at(baseUnix-1))
	requireCode(t, err, fault.CodeNotAuthentic)
	_, err = LeafPin(relayLocal, credential, at(baseUnix+50))
	requireCode(t, err, fault.CodeSenderMismatch)
}
