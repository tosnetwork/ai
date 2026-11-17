package directory

import (
	"strings"
	"testing"

	"github.com/tosnetwork/ai/messenger/pkg/fault"
)

// A roster entry's evidence supplies a member's delegation and device set
// even when it is stale: an expired descriptor still names its device set,
// while CheckPeer refuses it.
func TestCheckLeafAuthorityReadsStaleEvidence(t *testing.T) {
	f := newRelayFixture(t)
	evidence := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, nil)
	later := at(baseUnix + 100 + 3600 + 60)
	_, err := f.verifier.CheckPeer(agentID, evidence, f.pin(relayDeviceOne), later)
	requireCode(t, err, fault.CodeDescriptorExpired)
	authority, err := f.verifier.CheckLeafAuthority(agentID, evidence, f.pin(relayDeviceOne), later)
	if err != nil {
		t.Fatalf("stale evidence: %v", err)
	}
	if authority.Delegation.AgentID != agentID || authority.DeviceSet.EndpointID != f.delegation.EndpointID ||
		len(authority.DeviceSet.DeviceIDs) != 1 || authority.DeviceSet.DeviceIDs[0] != relayDeviceOne {
		t.Fatalf("authority: %+v", authority)
	}
	if fresh, err := f.verifier.CheckPeer(agentID, evidence, f.pin(relayDeviceOne), at(baseUnix+200)); err != nil ||
		fresh.Delegation.EndpointID != authority.Delegation.EndpointID {
		t.Fatalf("the same evidence while fresh: %v", err)
	}
}

// Everything but freshness is still judged: the pinned device must be in the
// signed set, the descriptor must be the Endpoint's signed binding, the
// Agent must be the evidence's, and the delegation must be finalized now.
func TestCheckLeafAuthorityRefusesWhatCheckPeerRefusesBesidesFreshness(t *testing.T) {
	f := newRelayFixture(t)
	evidence := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, nil)
	now := at(baseUnix + 200)
	_, err := f.verifier.CheckLeafAuthority(agentID, evidence, f.pin(relayDeviceTwo), now)
	requireCode(t, err, fault.CodeDeviceRevoked)
	_, err = f.verifier.CheckLeafAuthority(relayLocal, evidence, f.pin(relayDeviceOne), now)
	requireCode(t, err, fault.CodeSenderMismatch)
	unbound := f.evidence(relayDeviceOne, "material one", baseUnix+100, 3600, func(d *Descriptor) {
		d.DelegationDigest = "sha256:" + strings.Repeat("1", 64)
	})
	_, err = f.verifier.CheckLeafAuthority(agentID, unbound, f.pin(relayDeviceOne), now)
	requireCode(t, err, fault.CodeDescriptorUnbound)
	// Past the delegation's window nothing verifies, stale or not.
	_, err = f.verifier.CheckLeafAuthority(agentID, evidence, f.pin(relayDeviceOne), at(f.delegation.ExpiresAtUnix))
	if err == nil {
		t.Fatal("evidence of an expired delegation supplied an authority")
	}
	// Not yet issued at now is refused.
	future := f.evidence(relayDeviceOne, "material one", baseUnix+500, 3600, nil)
	_, err = f.verifier.CheckLeafAuthority(agentID, future, f.pin(relayDeviceOne), at(baseUnix+200))
	requireCode(t, err, fault.CodeDescriptorUnbound)
}
