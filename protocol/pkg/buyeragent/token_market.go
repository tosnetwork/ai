package buyeragent

import (
	"context"
	"encoding/hex"
	"math/big"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactorindex"
	"google.golang.org/protobuf/proto"
)

// These adapters carry only common package metadata for token proposals. The
// native Rail is deliberately empty: token amounts never acquire native units.
func validatePortableQuote(network *nativev1.NetworkDomain, request *nativev1.RequestQuoteProposalRequest, value *nativev1.QuoteProposalPackageV1) (*quoteexchange.Validated, error) {
	if value != nil && value.Proposal != nil && (value.Proposal.Asset != nil || value.Proposal.PriceAtomic != "") {
		token, err := quoteexchange.ValidateTokenPortable(network, request, value)
		if err != nil {
			return nil, err
		}
		return &quoteexchange.Validated{Proposal: token.Proposal, Manifest: token.Manifest, TransportBinding: token.TransportBinding}, nil
	}
	return quoteexchange.ValidatePortable(network, request, value)
}
func validateQuote(network *nativev1.NetworkDomain, request *nativev1.RequestQuoteProposalRequest, value *nativev1.QuoteProposalPackageV1, now time.Time) (*quoteexchange.Validated, error) {
	if value != nil && value.Proposal != nil && (value.Proposal.Asset != nil || value.Proposal.PriceAtomic != "") {
		token, err := quoteexchange.ValidateToken(network, request, value, now)
		if err != nil {
			return nil, err
		}
		return &quoteexchange.Validated{Proposal: token.Proposal, Manifest: token.Manifest, TransportBinding: token.TransportBinding}, nil
	}
	return quoteexchange.Validate(network, request, value, now)
}

func tokenManifest(m nativecore.SoftwareWorkManifestV1) bool {
	return m.Settlement.Rail == nativecore.ServiceActorTokenRail
}

func quoteActor(v *quoteexchange.Validated) string {
	if tokenManifest(v.Manifest) && v.Proposal.Actor != nil {
		return "0:" + hex.EncodeToString(v.Proposal.Actor.AccountId)
	}
	return v.Rail.Actor
}
func (o *Offers) checkTokenBudget(offer *serviceactorindex.Offer) error {
	if offer.Asset == nil {
		return nil
	}
	master := "0:" + hex.EncodeToString(offer.Asset.Master.AccountId)
	key := buyersdk.TokenAssetBudgetKey(master, offer.Asset.WalletCodeHash, uint8(offer.Asset.Decimals))
	limits, ok := o.config.TokenAssets[key]
	if !ok {
		return refusal(CodeOverBudget, "this asset has no configured funding budget", nil)
	}
	price, ok := new(big.Int).SetString(offer.PriceAtomic, 10)
	if !ok || limits.MaxPerCallAtomic == nil || price.Cmp(limits.MaxPerCallAtomic) > 0 {
		return refusal(CodeOverBudget, "the atomic price exceeds this asset's funding budget", nil)
	}
	return nil
}
func (o *Offers) tokenOfferView(ctx context.Context, offer *serviceactorindex.Offer, manifest nativecore.SoftwareWorkManifestV1) (OfferView, error) {
	if err := o.checkTokenBudget(offer); err != nil {
		return OfferView{}, err
	}
	_, cardErr := o.config.Cards.ProviderCard(ctx, offer.CapabilityID, offer.ProviderAgentID, o.config.Now())
	return OfferView{Checkpoint: offer.Checkpoint, CapabilityID: offer.CapabilityID, CapabilityVersion: offer.CapabilityVersion, ProviderAgentID: offer.ProviderAgentID, ManifestDigest: offer.ManifestDigest, Actor: offer.Actor, AttestorKeyID: offer.AttestorKeyID, PolicyVersion: offer.PolicyVersion, TermsHash: offer.TermsHash, Asset: proto.Clone(offer.Asset).(*nativev1.TOSAssetIdentityV1), PriceAtomic: offer.PriceAtomic, StorageFeeNanoTOS: offer.StorageFeeNanoTOS, CleanupBountyNanoTOS: offer.CleanupBountyNano, ResponseSLASeconds: offer.ResponseSLASeconds, RefundClaimWindowSeconds: offer.RefundWindowSeconds, RetentionSeconds: manifest.RetentionSeconds, OpenAccess: offer.OpenAccess, ProviderCardHeld: cardErr == nil, ProviderName: manifest.Name, ProviderDescription: manifest.Description}, nil
}
