package quoteexchange

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"strings"
	"time"
)

type ValidatedToken struct {
	Proposal         *nativev1.QuoteProposalV1
	Manifest         nativecore.SoftwareWorkManifestV1
	Rail             nativecore.ServiceActorTokenQuoteRailV1
	TransportBinding nativecore.TransportBindingV1
}

// ValidateTokenPortable checks immutable preimages without changing the native rail.
func ValidateTokenPortable(network *nativev1.NetworkDomain, request *nativev1.RequestQuoteProposalRequest, value *nativev1.QuoteProposalPackageV1) (*ValidatedToken, error) {
	return validateTokenPortable(network, request, value)
}

// ValidateToken additionally requires a currently usable quote.
func ValidateToken(network *nativev1.NetworkDomain, request *nativev1.RequestQuoteProposalRequest, value *nativev1.QuoteProposalPackageV1, now time.Time) (*ValidatedToken, error) {
	result, err := validateTokenPortable(network, request, value)
	if err != nil {
		return nil, err
	}
	if now.IsZero() || now.Unix() < 0 || result.Proposal.ExpiresAtUnixSeconds <= uint64(now.Unix()) || result.Proposal.ExpiresAtUnixSeconds > uint64(now.Add(time.Hour).Unix()) {
		return nil, errors.New("invalid token Quote expiry")
	}
	return result, nil
}

func validateTokenPortable(network *nativev1.NetworkDomain, request *nativev1.RequestQuoteProposalRequest,
	value *nativev1.QuoteProposalPackageV1) (*ValidatedToken, error) {
	if network == nil || request == nil || value == nil || value.Proposal == nil ||
		request.CapabilityId == "" || request.CapabilityVersion == "" || request.BuyerAddress == "" ||
		value.Proposal.CapabilityId != request.CapabilityId || value.Proposal.CapabilityVersion != request.CapabilityVersion ||
		value.Proposal.ProposalId == "" || len(value.Proposal.ProposalId) > 256 ||
		strings.TrimSpace(value.Proposal.ProposalId) != value.Proposal.ProposalId ||
		value.Proposal.ExpiresAtUnixSeconds == 0 {
		return nil, errors.New("invalid Quote Proposal package identity")
	}
	total := len(value.CanonicalManifestCbor) + len(value.TransportBindingBoc)
	if total <= 0 || total > MaxPackageBytes {
		return nil, errors.New("Quote Proposal package is outside size bounds")
	}
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(value.CanonicalManifestCbor)
	if err != nil {
		return nil, errors.New("Quote Proposal carries a non-canonical manifest")
	}
	canonical, manifestDigest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil || !bytes.Equal(canonical, value.CanonicalManifestCbor) || manifestDigest != value.Proposal.ManifestDigest ||
		manifest.Version != value.Proposal.CapabilityVersion {
		return nil, errors.New("Quote Proposal manifest preimage mismatch")
	}
	rail, err := nativecore.ParseServiceActorTokenQuoteRail(value.Proposal)
	if err != nil {
		return nil, fmt.Errorf("Quote Proposal rail: %w", err)
	}
	// Manifest key 21 is the owner Agent's statement of the settling actor;
	// the proposal must name exactly that actor, code and attestor.
	settlement := manifest.Settlement
	if settlement.ActorWorkchain != 0 || rail.Actor != "0:"+hex.EncodeToString(settlement.ActorAccountID) ||
		!bytes.Equal(rail.ActorCodeHash[:], settlement.ActorCodeHash) || value.Proposal.AttestorKeyId != settlement.AttestorKey {
		return nil, errors.New("Quote Proposal rail differs from manifest key 21")
	}
	if len(manifest.SupportedAssets) != 1 || manifest.Settlement.Rail != nativecore.ServiceActorTokenRail {
		return nil, errors.New("manifest does not select token settlement")
	}
	asset := manifest.SupportedAssets[0]
	if asset.Decimals == nil || rail.Asset.Decimals != uint32(*asset.Decimals) || !bytes.Equal(rail.Asset.Master.AccountId, asset.MasterAccountID) || rail.Asset.WalletCodeHash != "tvm-cell-sha256:"+hex.EncodeToString(asset.WalletCodeHash) {
		return nil, errors.New("Quote asset differs from manifest")
	}
	transportCell, err := canonicalCell(value.TransportBindingBoc)
	if err != nil || "sha256:"+hexHash(transportCell) != value.Proposal.TransportBindingDigest {
		return nil, errors.New("Quote Proposal transport preimage mismatch")
	}
	transport, err := nativecore.DecodeTransportBindingCellV1(transportCell)
	if err != nil {
		return nil, errors.New("Quote Proposal transport binding is invalid")
	}
	if transport.SecurityMode == nativecore.TransportAgentPacket {
		// Agent Packets go to the Capability owner Agent and to nobody else.
		recipient, err := transport.AgentPacketRecipient()
		if err != nil || recipient != value.Proposal.ProviderAgentId {
			return nil, errors.New("Quote Proposal Agent Packet transport names another Agent than the provider")
		}
	}
	if _, _, err := nativecore.BuildAcceptedTokenQuoteCommitment(network, value.Proposal); err != nil {
		return nil, errors.New("Quote Proposal fields are not canonically encodable")
	}
	return &ValidatedToken{Proposal: value.Proposal, Manifest: manifest, Rail: rail, TransportBinding: transport}, nil
}
