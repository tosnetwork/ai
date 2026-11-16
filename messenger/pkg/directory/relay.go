package directory

import (
	"bytes"
	"errors"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

// Relay identity evidence on the relay route.
//
// A locator says how to reach a peer over a network route. On the relay
// route the route is the peer's chat card, so the four other objects of the
// refresh chain are verified without one: CheckPeer is the read-only check
// both sides run, and CommitPeer is the only step that writes, and only for
// a peer the caller has admitted.

// Pin is what evidence must keep naming. For an established session it is
// the session's pinned peer Endpoint and device; on first contact it is the
// bootstrap's sender bundle, which must be in the set byte for byte.
type Pin struct {
	EndpointID string
	DeviceID   string
	Bundle     *e2ee.Bundle
}

// RelayPeer is evidence that passed CheckPeer at one time.
type RelayPeer struct {
	AgentID             string
	Delegation          identity.Delegation
	Policy              DescriptorPolicy
	Descriptor          Descriptor
	DescriptorDigest    string
	Bundles             []e2ee.Bundle
	Evidence            []byte
	FinalizedCheckpoint uint64
}

// SetJudge is the read side of the rollback boundary: it judges a set
// against the stored record and writes nothing.
type SetJudge interface {
	JudgeSet(endpointID string, bundles []e2ee.Bundle, now time.Time) (e2ee.Succession, error)
}

// EvidenceStore keeps the last committed evidence of each admitted peer.
// StoreRelayEvidence replaces the stored value only if it still has the
// digest the caller read, so a slower concurrent commit cannot overwrite a
// newer one.
type EvidenceStore interface {
	LoadRelayEvidence(agentID string) ([]byte, bool, error)
	StoreRelayEvidence(agentID string, evidence []byte, previousDigest string, now time.Time) error
}

// RelayVerifier holds what CheckPeer and CommitPeer read and write.
type RelayVerifier struct {
	Resolver     identity.AgentResolver
	Network      *nativev1.NetworkDomain
	Chain        identity.ChainPolicy
	Judge        SetJudge
	Admitter     PublishedSetAdmitter
	Store        EvidenceStore
	LocalAgentID string
}

// ErrRelayEvidenceUnknown reports a peer with no committed evidence.
var ErrRelayEvidenceUnknown = errors.New("no committed relay evidence for this peer")

// CheckPeer verifies a peer's relay identity evidence, read-only:
//
//  1. the delegation, re-read from finalized state on every call, is still
//     committed by the live Agent, inside its window, and its Endpoint is the
//     pinned one;
//  2. the policy reproduces the digest the delegation commits;
//  3. the descriptor is signed by that Endpoint, bound to the delegation and
//     unexpired;
//  4. the bundle set reproduces the descriptor's digest, holds exactly one
//     device, and contains the pinned device (or the pinned bundle);
//  5. the set is not a rollback against the stored boundary, judged without
//     writing.
//
// Every failure is a *fault.Fault whose code says what the sender can do.
func (v RelayVerifier) CheckPeer(peerAgentID string, evidence []byte, pin Pin, now time.Time) (RelayPeer, error) {
	if v.Resolver == nil || v.Judge == nil || v.Network == nil {
		return RelayPeer{}, fault.New(fault.CodeInternal, "relay evidence verifier is incomplete")
	}
	if !ids.Agent.MatchString(peerAgentID) {
		return RelayPeer{}, fault.New(fault.CodeSenderMismatch, "invalid relay peer Agent identifier")
	}
	if peerAgentID == v.LocalAgentID {
		return RelayPeer{}, fault.New(fault.CodeSenderMismatch, "relay evidence names this installation")
	}
	if now.IsZero() || now.Unix() < 0 {
		return RelayPeer{}, fault.New(fault.CodeInternal, "invalid relay evidence time")
	}
	if err := validatePin(pin); err != nil {
		return RelayPeer{}, err
	}
	decoded, err := relayframe.DecodeEvidence(evidence)
	if err != nil {
		if errors.Is(err, relayframe.ErrRelayEvidenceTooLarge) {
			return RelayPeer{}, fault.Wrap(fault.CodeOversized, err)
		}
		return RelayPeer{}, fault.Wrap(fault.CodePayloadMalformed, err)
	}
	// 1. Finalized authority, read again on every call.
	delegation, checkpoint, err := identity.VerifyWithCheckpoint(v.Resolver, v.Network, v.Chain, decoded.Delegation, now)
	if err != nil {
		return RelayPeer{}, classifyDelegation(decoded.Delegation, v.Resolver, now, err)
	}
	if delegation.AgentID != peerAgentID {
		return RelayPeer{}, fault.New(fault.CodeSenderMismatch, "relay evidence names another Agent")
	}
	if delegation.EndpointID != pin.EndpointID {
		return RelayPeer{}, fault.New(fault.CodeSenderMismatch, "relay evidence names another Endpoint than the pinned one")
	}
	// 2. Policy.
	policy, err := DecodeDescriptorPolicyJSON(decoded.Policy)
	if err != nil {
		return RelayPeer{}, fault.Wrap(fault.CodeDescriptorUnbound, err)
	}
	if canonical, encodeErr := EncodeDescriptorPolicyJSON(policy); encodeErr != nil || !bytes.Equal(canonical, decoded.Policy) {
		return RelayPeer{}, fault.New(fault.CodeDescriptorUnbound, "relay evidence policy is not canonical")
	}
	policyDigest, err := policy.Digest()
	if err != nil || policyDigest != delegation.ContactDescriptorPolicyDigest {
		return RelayPeer{}, fault.New(fault.CodeDescriptorUnbound, "relay evidence policy is not the committed one")
	}
	// 3. Descriptor.
	descriptor, err := DecodeDescriptorJSON(decoded.Descriptor)
	if err != nil {
		return RelayPeer{}, fault.Wrap(fault.CodeDescriptorUnbound, err)
	}
	if canonical, encodeErr := EncodeDescriptorJSON(descriptor); encodeErr != nil || !bytes.Equal(canonical, decoded.Descriptor) {
		return RelayPeer{}, fault.New(fault.CodeDescriptorUnbound, "relay evidence descriptor is not canonical")
	}
	if uint64(now.Unix()) >= descriptor.ExpiresAtUnix {
		return RelayPeer{}, fault.New(fault.CodeDescriptorExpired, "relay evidence descriptor is expired")
	}
	if err := Bind(delegation, descriptor, policy, now); err != nil {
		return RelayPeer{}, fault.Wrap(fault.CodeDescriptorUnbound, err)
	}
	descriptorDigest, err := DescriptorDigest(descriptor)
	if err != nil {
		return RelayPeer{}, fault.Wrap(fault.CodeDescriptorUnbound, err)
	}
	// 4. Bundle set, one device.
	bundles, err := e2ee.DecodeBundleSetJSON(decoded.BundleSet)
	if err != nil {
		return RelayPeer{}, fault.Wrap(fault.CodeDescriptorUnbound, err)
	}
	if canonical, encodeErr := e2ee.EncodeBundleSetJSON(bundles); encodeErr != nil || !bytes.Equal(canonical, decoded.BundleSet) {
		return RelayPeer{}, fault.New(fault.CodeDescriptorUnbound, "relay evidence bundle set is not canonical")
	}
	if len(bundles) != 1 {
		return RelayPeer{}, fault.New(fault.CodeDescriptorUnbound, "relay evidence must carry exactly one device")
	}
	for _, bundle := range bundles {
		if seconds := uint64(now.Unix()); seconds >= bundle.ExpiresAtUnix {
			return RelayPeer{}, fault.New(fault.CodeDescriptorExpired, "relay evidence prekey bundle is expired")
		}
	}
	if err := e2ee.BindBundleSet(delegation, bundles, descriptor.PrekeyBundleDigest, now); err != nil {
		return RelayPeer{}, fault.Wrap(fault.CodeDescriptorUnbound, err)
	}
	if !containsPinned(bundles, pin) {
		return RelayPeer{}, fault.New(fault.CodeDeviceRevoked, "relay evidence no longer contains the pinned device")
	}
	// 5. Rollback, judged and not written.
	if _, err := v.Judge.JudgeSet(delegation.EndpointID, bundles, now); err != nil {
		switch {
		case errors.Is(err, e2ee.ErrSetRollback):
			return RelayPeer{}, fault.Wrap(fault.CodeDescriptorExpired, err)
		case errors.Is(err, e2ee.ErrSetEquivocation):
			return RelayPeer{}, fault.Wrap(fault.CodeDescriptorUnbound, err)
		default:
			return RelayPeer{}, fault.Wrap(fault.CodeDeviceRevoked, err)
		}
	}
	return RelayPeer{AgentID: peerAgentID, Delegation: delegation, Policy: policy, Descriptor: descriptor,
		DescriptorDigest: descriptorDigest, Bundles: cloneBundles(bundles),
		Evidence: append([]byte(nil), evidence...), FinalizedCheckpoint: checkpoint}, nil
}

// CheckContact verifies imported evidence whose pin is the evidence's own
// Endpoint and single device: an imported contact has no session yet.
func (v RelayVerifier) CheckContact(peerAgentID string, evidence []byte, now time.Time) (RelayPeer, error) {
	pin, err := evidencePin(evidence)
	if err != nil {
		return RelayPeer{}, err
	}
	return v.CheckPeer(peerAgentID, evidence, pin, now)
}

// CheckStored runs CheckPeer on the evidence last committed for a peer.
func (v RelayVerifier) CheckStored(peerAgentID string, pin Pin, now time.Time) (RelayPeer, error) {
	raw, err := v.stored(peerAgentID)
	if err != nil {
		return RelayPeer{}, err
	}
	return v.CheckPeer(peerAgentID, raw, pin, now)
}

// CheckStoredContact runs CheckContact on the evidence last committed for a
// peer, for a sender that holds no session to pin yet.
func (v RelayVerifier) CheckStoredContact(peerAgentID string, now time.Time) (RelayPeer, error) {
	raw, err := v.stored(peerAgentID)
	if err != nil {
		return RelayPeer{}, err
	}
	return v.CheckContact(peerAgentID, raw, now)
}

// Admitted reports whether a peer has committed evidence: it was imported
// from a contact file or admitted by Messenger on this route before.
func (v RelayVerifier) Admitted(peerAgentID string) (bool, error) {
	if v.Store == nil {
		return false, fault.New(fault.CodeInternal, "relay evidence store is not configured")
	}
	if !ids.Agent.MatchString(peerAgentID) {
		return false, fault.New(fault.CodeSenderMismatch, "invalid relay peer Agent identifier")
	}
	_, found, err := v.Store.LoadRelayEvidence(peerAgentID)
	if err != nil {
		return false, fault.Wrap(fault.CodeInternal, err)
	}
	return found, nil
}

func (v RelayVerifier) stored(peerAgentID string) ([]byte, error) {
	if v.Store == nil {
		return nil, fault.New(fault.CodeInternal, "relay evidence store is not configured")
	}
	if !ids.Agent.MatchString(peerAgentID) {
		return nil, fault.New(fault.CodeSenderMismatch, "invalid relay peer Agent identifier")
	}
	raw, found, err := v.Store.LoadRelayEvidence(peerAgentID)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, err)
	}
	if !found {
		return nil, fault.Wrap(fault.CodeDescriptorExpired, ErrRelayEvidenceUnknown)
	}
	return raw, nil
}

// CommitPeer is the only durable step. It admits the peer's set to the
// rollback boundary and stores the evidence only when the evidence is newer
// than what is stored, and is otherwise a no-op. The caller runs it only
// under the admission rule: after Messenger answered accepted, duplicate or
// held for the frame, for an established peer, or on contact import.
func (v RelayVerifier) CommitPeer(peer RelayPeer, now time.Time) (bool, error) {
	if v.Store == nil || v.Admitter == nil {
		return false, fault.New(fault.CodeInternal, "relay evidence commit is not configured")
	}
	if !ids.Agent.MatchString(peer.AgentID) || peer.AgentID == v.LocalAgentID ||
		peer.Delegation.AgentID != peer.AgentID || len(peer.Evidence) == 0 || len(peer.Bundles) == 0 {
		return false, fault.New(fault.CodeInternal, "relay evidence commit needs a checked peer")
	}
	if now.IsZero() || now.Unix() < 0 {
		return false, fault.New(fault.CodeInternal, "invalid relay evidence commit time")
	}
	previous, found, err := v.Store.LoadRelayEvidence(peer.AgentID)
	if err != nil {
		return false, fault.Wrap(fault.CodeInternal, err)
	}
	previousDigest := ""
	if found {
		storedDigest, storedIssued, parseErr := EvidenceDescriptor(previous)
		if parseErr != nil {
			return false, fault.Wrap(fault.CodeInternal, parseErr)
		}
		if !NewerEvidence(peer.DescriptorDigest, peer.Descriptor.IssuedAtUnix, storedDigest, storedIssued) {
			return false, nil
		}
		previousDigest = relayframe.EvidenceDigest(previous)
	}
	if _, err := v.Admitter.AdmitPublishedSet(peer.Delegation, peer.Descriptor.PrekeyBundleDigest, peer.Bundles, now); err != nil {
		return false, fault.Wrap(fault.CodeDescriptorUnbound, err)
	}
	if err := v.Store.StoreRelayEvidence(peer.AgentID, peer.Evidence, previousDigest, now); err != nil {
		return false, fault.Wrap(fault.CodeInternal, err)
	}
	return true, nil
}

// NewerEvidence is the single definition of "newer": a different descriptor
// digest and a later descriptor issue time. Both conditions are needed, so
// identical evidence and evidence re-signed for the same moment are never
// newer, and clock skew cannot make a retry loop.
func NewerEvidence(candidateDigest string, candidateIssuedAt uint64, currentDigest string, currentIssuedAt uint64) bool {
	return candidateDigest != currentDigest && candidateIssuedAt > currentIssuedAt
}

// EvidenceDescriptor returns the descriptor digest and issue time of
// evidence bytes without verifying them; it is used to compare evidence this
// installation already verified or produced itself.
func EvidenceDescriptor(evidence []byte) (string, uint64, error) {
	decoded, err := relayframe.DecodeEvidence(evidence)
	if err != nil {
		return "", 0, err
	}
	descriptor, err := DecodeDescriptorJSON(decoded.Descriptor)
	if err != nil {
		return "", 0, err
	}
	digest, err := DescriptorDigest(descriptor)
	if err != nil {
		return "", 0, err
	}
	return digest, descriptor.IssuedAtUnix, nil
}

func evidencePin(evidence []byte) (Pin, error) {
	decoded, err := relayframe.DecodeEvidence(evidence)
	if err != nil {
		if errors.Is(err, relayframe.ErrRelayEvidenceTooLarge) {
			return Pin{}, fault.Wrap(fault.CodeOversized, err)
		}
		return Pin{}, fault.Wrap(fault.CodePayloadMalformed, err)
	}
	bundles, err := e2ee.DecodeBundleSetJSON(decoded.BundleSet)
	if err != nil || len(bundles) != 1 {
		return Pin{}, fault.New(fault.CodeDescriptorUnbound, "relay evidence must carry exactly one device")
	}
	return Pin{EndpointID: bundles[0].EndpointID, DeviceID: bundles[0].DeviceID}, nil
}

func validatePin(pin Pin) error {
	if !ids.Endpoint.MatchString(pin.EndpointID) || !ids.Device.MatchString(pin.DeviceID) {
		return fault.New(fault.CodeInternal, "relay evidence pin is incomplete")
	}
	if pin.Bundle != nil && (pin.Bundle.EndpointID != pin.EndpointID || pin.Bundle.DeviceID != pin.DeviceID) {
		return fault.New(fault.CodeInternal, "relay evidence pin bundle names another device")
	}
	return nil
}

func containsPinned(bundles []e2ee.Bundle, pin Pin) bool {
	var wanted []byte
	if pin.Bundle != nil {
		encoded, err := e2ee.EncodeBundleJSON(*pin.Bundle)
		if err != nil {
			return false
		}
		wanted = encoded
	}
	for _, bundle := range bundles {
		if bundle.EndpointID != pin.EndpointID || bundle.DeviceID != pin.DeviceID {
			continue
		}
		if wanted == nil {
			return true
		}
		encoded, err := e2ee.EncodeBundleJSON(bundle)
		if err == nil && bytes.Equal(encoded, wanted) {
			return true
		}
	}
	return false
}

// classifyDelegation turns a delegation verification failure into a sender
// remedy. A finalized-state read failure says nothing about the peer and is
// retried; a delegation the Agent no longer commits, or one outside its
// window, needs the peer to act.
func classifyDelegation(raw []byte, resolver identity.AgentResolver, now time.Time, cause error) error {
	delegation, err := identity.DecodeJSON(raw)
	if err != nil {
		return fault.Wrap(fault.CodePayloadMalformed, cause)
	}
	if _, _, err := resolver.ResolveAgent(delegation.AgentID); err != nil {
		return fault.Wrap(fault.CodeInternal, cause)
	}
	if identity.CheckWindow(delegation, now) != nil {
		return fault.Wrap(fault.CodeDelegationExpired, cause)
	}
	return fault.Wrap(fault.CodeDelegationUncommitted, cause)
}
