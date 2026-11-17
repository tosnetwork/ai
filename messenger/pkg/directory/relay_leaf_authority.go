package directory

import (
	"bytes"
	"errors"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// LeafAuthority is what a room member's leaf credential is verified against
// (section 11.8): the member's delegation, verified as finalized now, and the
// device set the member's Endpoint signed.
type LeafAuthority struct {
	Delegation identity.Delegation
	DeviceSet  e2ee.SetSummary
}

// CheckLeafAuthority reads a room member's authority from relay identity
// evidence without judging the evidence's freshness. A roster entry's leaf
// credential is judged independently of its rendezvous data (section 11.2):
// an entry whose evidence is stale still contributes a credential that
// verifies, and only the stale card or evidence is skipped. So, unlike
// CheckPeer:
//
//   - the delegation is still verified against finalized state now, so an
//     Endpoint withdrawn on chain, or a delegation past its window, fails;
//   - the descriptor must be the Endpoint's signed binding of that
//     delegation and its committed policy, judged at its own issue time, so
//     an expired descriptor still names its device set;
//   - the device set must be exactly the one the descriptor commits, hold one
//     device, and contain the pinned Endpoint and device;
//   - nothing about the rollback boundary is judged or written.
//
// It writes nothing. Every failure is a *fault.Fault.
func (v RelayVerifier) CheckLeafAuthority(peerAgentID string, evidence []byte, pin Pin, now time.Time) (LeafAuthority, error) {
	if v.Resolver == nil || v.Network == nil {
		return LeafAuthority{}, fault.New(fault.CodeInternal, "relay evidence verifier is incomplete")
	}
	if peerAgentID == v.LocalAgentID {
		return LeafAuthority{}, fault.New(fault.CodeSenderMismatch, "relay evidence names this installation")
	}
	if now.IsZero() || now.Unix() < 0 {
		return LeafAuthority{}, fault.New(fault.CodeInternal, "invalid relay evidence time")
	}
	if err := validatePin(pin); err != nil {
		return LeafAuthority{}, err
	}
	if pin.Bundle != nil {
		return LeafAuthority{}, fault.New(fault.CodeInternal, "a leaf authority is pinned by Endpoint and device only")
	}
	decoded, err := relayframe.DecodeEvidence(evidence)
	if err != nil {
		return LeafAuthority{}, fault.Wrap(fault.CodePayloadMalformed, err)
	}
	delegation, _, err := identity.VerifyWithCheckpoint(v.Resolver, v.Network, v.Chain, decoded.Delegation, now)
	if err != nil {
		return LeafAuthority{}, classifyDelegation(decoded.Delegation, v.Resolver, now, err)
	}
	if delegation.AgentID != peerAgentID || delegation.EndpointID != pin.EndpointID {
		return LeafAuthority{}, fault.New(fault.CodeSenderMismatch, "relay evidence names another Agent or Endpoint")
	}
	policy, err := DecodeDescriptorPolicyJSON(decoded.Policy)
	if err != nil {
		return LeafAuthority{}, fault.Wrap(fault.CodeDescriptorUnbound, err)
	}
	if canonical, encodeErr := EncodeDescriptorPolicyJSON(policy); encodeErr != nil || !bytes.Equal(canonical, decoded.Policy) {
		return LeafAuthority{}, fault.New(fault.CodeDescriptorUnbound, "relay evidence policy is not canonical")
	}
	descriptor, err := DecodeDescriptorJSON(decoded.Descriptor)
	if err != nil {
		return LeafAuthority{}, fault.Wrap(fault.CodeDescriptorUnbound, err)
	}
	if canonical, encodeErr := EncodeDescriptorJSON(descriptor); encodeErr != nil || !bytes.Equal(canonical, decoded.Descriptor) {
		return LeafAuthority{}, fault.New(fault.CodeDescriptorUnbound, "relay evidence descriptor is not canonical")
	}
	if descriptor.IssuedAtUnix == 0 || descriptor.IssuedAtUnix > uint64(now.Unix()) {
		return LeafAuthority{}, fault.New(fault.CodeDescriptorUnbound, "relay evidence descriptor is not yet issued")
	}
	// The binding and the Endpoint signature are judged at the descriptor's
	// own issue time, so an expired descriptor still names its device set;
	// the delegation itself was verified as finalized now above.
	issued := time.Unix(int64(descriptor.IssuedAtUnix), 0)
	if err := Bind(delegation, descriptor, policy, issued); err != nil {
		return LeafAuthority{}, fault.Wrap(fault.CodeDescriptorUnbound, err)
	}
	bundles, err := e2ee.DecodeBundleSetJSON(decoded.BundleSet)
	if err != nil {
		return LeafAuthority{}, fault.Wrap(fault.CodeDescriptorUnbound, err)
	}
	if canonical, encodeErr := e2ee.EncodeBundleSetJSON(bundles); encodeErr != nil || !bytes.Equal(canonical, decoded.BundleSet) {
		return LeafAuthority{}, fault.New(fault.CodeDescriptorUnbound, "relay evidence bundle set is not canonical")
	}
	if len(bundles) != 1 {
		return LeafAuthority{}, fault.New(fault.CodeDescriptorUnbound, "relay evidence must carry exactly one device")
	}
	// The set is the one the signed descriptor commits, so its device list is
	// the Endpoint's own statement.
	if err := e2ee.MatchesDescriptorDigest(descriptor.PrekeyBundleDigest, bundles); err != nil {
		return LeafAuthority{}, fault.Wrap(fault.CodeDescriptorUnbound, err)
	}
	if bundles[0].EndpointID != delegation.EndpointID {
		return LeafAuthority{}, fault.New(fault.CodeDescriptorUnbound, "relay evidence device set belongs to another Endpoint")
	}
	if !containsPinned(bundles, pin) {
		return LeafAuthority{}, fault.New(fault.CodeDeviceRevoked, "relay evidence does not contain the pinned device")
	}
	summary, err := e2ee.Summarize(bundles)
	if err != nil {
		return LeafAuthority{}, fault.Wrap(fault.CodeDescriptorUnbound, err)
	}
	if summary.EndpointID != pin.EndpointID {
		return LeafAuthority{}, fault.Wrap(fault.CodeDescriptorUnbound, errors.New("relay evidence device set names another Endpoint"))
	}
	return LeafAuthority{Delegation: delegation, DeviceSet: summary}, nil
}
