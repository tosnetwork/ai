package directory

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
)

// PublicGeneration is the durable public-only output of an exact device
// collection. The publication coordinator needs no answering secret.
type PublicGeneration struct {
	SetDigest string
	JSON      []byte
	IssuedAt  uint64
	ExpiresAt uint64
}

// LocatorPublisher is the final authority-changing publication boundary.
type LocatorPublisher interface {
	PublishLocator(context.Context, identity.Delegation, Locator, crypto.Signer) (int, error)
}

// GenerationPublisher composes immutable HTTPS objects and the native DHT
// locator without owning the Endpoint key. Repeated calls are byte-identical;
// the native DHT adapter refreshes the outer cache envelope around that same
// inner signed locator.
type GenerationPublisher struct {
	Objects         HTTPSPublicationSink
	Locators        LocatorPublisher
	Signer          crypto.Signer
	Delegation      identity.Delegation
	Policy          DescriptorPolicy
	Descriptor      Descriptor
	PublishInterval time.Duration
	// Relay, when set, receives every published descriptor with its prekey
	// set as this node's relay identity evidence. With no HTTPS objects and
	// no locator publisher the generation is published to Relay only: the
	// relay route needs no locator.
	Relay RelayEvidencePublication
}

// RelayEvidencePublication receives this node's own relay identity evidence.
// Last reports the descriptor most recently published, so the publisher can
// keep issue times strictly increasing across restarts.
type RelayEvidencePublication interface {
	LastRelayDescriptor() (digest string, issuedAtUnix uint64, found bool, err error)
	PutRelayEvidence(descriptor Descriptor, descriptorJSON, bundleSetJSON []byte) error
}

func (p *GenerationPublisher) Validate() error {
	if p == nil || p.Signer == nil || (p.Objects == nil) != (p.Locators == nil) ||
		p.Objects == nil && p.Relay == nil {
		return errors.New("generation publication is not configured")
	}
	if p.PublishInterval < time.Minute || p.PublishInterval > time.Hour {
		return errors.New("generation publication interval is outside its bound")
	}
	activationStep := time.Duration(p.Policy.MaxLifetimeSeconds/2) * time.Second
	if activationStep < time.Minute || p.PublishInterval > activationStep {
		return errors.New("generation publication interval cannot cover the descriptor renewal window")
	}
	public, ok := p.Signer.Public().(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize || !bytes.Equal(public, p.Delegation.IdentityPublicKey) {
		return errors.New("generation publisher signer is not the delegated Endpoint key")
	}
	policyDigest, err := p.Policy.Digest()
	if err != nil || policyDigest != p.Delegation.ContactDescriptorPolicyDigest {
		return errors.New("generation publisher policy does not match its delegation")
	}
	delegationDigest, err := identity.Digest(p.Delegation)
	if err != nil || p.Descriptor.Network == nil || p.Descriptor.AgentID != p.Delegation.AgentID ||
		p.Descriptor.EndpointID != p.Delegation.EndpointID || p.Descriptor.DelegationDigest != delegationDigest ||
		p.Descriptor.ADNLID != p.Delegation.ADNLID ||
		p.Descriptor.InboxAdmissionPolicyDigest != p.Delegation.InboxAdmissionPolicyDigest ||
		p.Descriptor.Network.NetworkId != p.Delegation.Network.NetworkId ||
		p.Descriptor.Network.GenesisRootHash != p.Delegation.Network.GenesisRootHash ||
		p.Descriptor.Network.GenesisFileHash != p.Delegation.Network.GenesisFileHash {
		return errors.New("generation publisher descriptor does not match its delegation")
	}
	descriptor := p.Descriptor
	descriptor.PrekeyBundleDigest = "sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"
	descriptor.IssuedAtUnix = p.Delegation.NotBeforeUnix
	descriptor.ExpiresAtUnix = descriptor.IssuedAtUnix + 1
	if err := ValidateDescriptor(descriptor, false); err != nil {
		return err
	}
	return p.Policy.Permits(descriptor)
}

func (p *GenerationPublisher) Publish(ctx context.Context, generation PublicGeneration, now time.Time) (HTTPSActivation, int, error) {
	if ctx == nil {
		return HTTPSActivation{}, 0, errors.New("generation publication needs a context")
	}
	if err := p.Validate(); err != nil {
		return HTTPSActivation{}, 0, err
	}
	if now.IsZero() || now.Unix() < 0 || generation.IssuedAt == 0 || generation.ExpiresAt <= generation.IssuedAt ||
		uint64(now.Unix()) < generation.IssuedAt || uint64(now.Unix()) >= generation.ExpiresAt {
		return HTTPSActivation{}, 0, errors.New("public generation is outside its publication window")
	}
	activationStep := p.Policy.MaxLifetimeSeconds / 2
	descriptorIssued := uint64(now.Unix()) / activationStep * activationStep
	if descriptorIssued < generation.IssuedAt {
		descriptorIssued = generation.IssuedAt
	}
	descriptorExpiry := generation.ExpiresAt
	if maximum := descriptorIssued + p.Policy.MaxLifetimeSeconds; descriptorExpiry > maximum {
		descriptorExpiry = maximum
	}
	if descriptorExpiry > p.Delegation.ExpiresAtUnix {
		descriptorExpiry = p.Delegation.ExpiresAtUnix
	}
	if descriptorExpiry <= uint64(now.Unix()) {
		return HTTPSActivation{}, 0, errors.New("descriptor window cannot cover publication time")
	}
	descriptor := p.Descriptor
	descriptor.IssuedAtUnix = descriptorIssued
	descriptor.ExpiresAtUnix = descriptorExpiry
	if p.Objects == nil {
		activation, err := p.publishRelayOnly(descriptor, generation, now)
		return activation, 0, err
	}
	locatorIssued := descriptorIssued
	locatorExpiry := locatorIssued + MaxLocatorLifetimeSeconds
	if locatorExpiry > descriptorExpiry {
		locatorExpiry = descriptorExpiry
	}
	activation, err := ActivateHTTPSPublication(ctx, p.Objects, p.Signer, p.Delegation, p.Policy,
		HTTPSActivationPlan{Descriptor: descriptor, LocatorIssuedAt: locatorIssued, LocatorExpiresAt: locatorExpiry},
		generation.SetDigest, append([]byte(nil), generation.JSON...), now)
	if err != nil {
		return HTTPSActivation{}, 0, err
	}
	stored, err := p.Locators.PublishLocator(ctx, p.Delegation, activation.Locator, p.Signer)
	if err != nil {
		return HTTPSActivation{}, 0, err
	}
	if p.Relay != nil {
		if err := p.Relay.PutRelayEvidence(activation.Descriptor, activation.DescriptorJSON,
			append([]byte(nil), generation.JSON...)); err != nil {
			return HTTPSActivation{}, 0, err
		}
	}
	return activation, stored, nil
}

// publishRelayOnly signs the descriptor for the relay route, where no HTTPS
// object or locator exists, and hands it to the relay sink. The publisher
// invariant holds here: a descriptor with different content always has a
// strictly later issue time than the one published before it, so successive
// evidences are totally ordered by "newer".
func (p *GenerationPublisher) publishRelayOnly(descriptor Descriptor, generation PublicGeneration,
	now time.Time) (HTTPSActivation, error) {
	bundles, canonicalPrekeys, err := canonicalPrekeyObject(generation.JSON)
	if err != nil {
		return HTTPSActivation{}, err
	}
	if !bytes.Equal(generation.JSON, canonicalPrekeys) {
		return HTTPSActivation{}, errors.New("prekey object is not in canonical publication order")
	}
	if err := e2ee.BindBundleSet(p.Delegation, bundles, generation.SetDigest, now); err != nil {
		return HTTPSActivation{}, err
	}
	descriptor.PrekeyBundleDigest = generation.SetDigest
	descriptor.EndpointSignature = nil
	lastDigest, lastIssued, found, err := p.Relay.LastRelayDescriptor()
	if err != nil {
		return HTTPSActivation{}, err
	}
	signed, err := SignDescriptorWith(descriptor, p.Signer)
	if err != nil {
		return HTTPSActivation{}, err
	}
	digest, err := DescriptorDigest(signed)
	if err != nil {
		return HTTPSActivation{}, err
	}
	if found && digest != lastDigest && signed.IssuedAtUnix <= lastIssued {
		if lastIssued == ^uint64(0) || lastIssued+1 > uint64(now.Unix()) || lastIssued+1 >= descriptor.ExpiresAtUnix {
			return HTTPSActivation{}, errors.New("relay descriptor issue time cannot advance yet")
		}
		descriptor.IssuedAtUnix = lastIssued + 1
		signed, err = SignDescriptorWith(descriptor, p.Signer)
		if err != nil {
			return HTTPSActivation{}, err
		}
		digest, err = DescriptorDigest(signed)
		if err != nil {
			return HTTPSActivation{}, err
		}
	}
	if err := Bind(p.Delegation, signed, p.Policy, now); err != nil {
		return HTTPSActivation{}, err
	}
	descriptorJSON, err := EncodeDescriptorJSON(signed)
	if err != nil {
		return HTTPSActivation{}, err
	}
	if err := p.Relay.PutRelayEvidence(signed, descriptorJSON, append([]byte(nil), generation.JSON...)); err != nil {
		return HTTPSActivation{}, err
	}
	return HTTPSActivation{Descriptor: signed, DescriptorJSON: descriptorJSON, DescriptorDigest: digest}, nil
}
