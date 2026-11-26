package quoteprovider

import (
	"context"
	"encoding/hex"
	"errors"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
)

type tokenSession interface {
	serviceactor.TokenSession
	GetTokenAcceptingTokens(context.Context, string) (bool, error)
}

type manifestBytes []byte

func (m manifestBytes) Manifest(context.Context, string) ([]byte, error) {
	return append([]byte(nil), m...), nil
}

func (p *Provider) requestTokenQuote(ctx context.Context, session serviceactor.Session, request *nativev1.RequestQuoteProposalRequest) (*nativev1.QuoteProposalPackageV1, error) {
	token, ok := session.(tokenSession)
	if !ok {
		return nil, errors.New("token Quote requires a finalized token session")
	}
	evidence, err := serviceactor.GatherTokenEvidence(ctx, token, p.config.Network, manifestBytes(p.config.ManifestCBOR), request.CapabilityId, p.version, p.config.TokenPins, true)
	if err != nil {
		return nil, err
	}
	var code [32]byte
	copy(code[:], p.settlement.ActorCodeHash)
	admission, err := serviceactor.VerifyTokenAdmission(evidence, code, nil, nil, request.BuyerAddress)
	if err != nil {
		return nil, err
	}
	accepting, err := token.GetTokenAcceptingTokens(ctx, admission.Binding.Actor)
	if err != nil {
		return nil, err
	}
	if !accepting {
		return nil, errors.New("token actor is not accepting tokens")
	}
	transport, digest, err := nativecore.BuildTransportBindingCellV1(p.config.Transport)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 16)
	if err := p.config.Random(nonce); err != nil {
		return nil, errors.New("generate token Quote identity")
	}
	policy, recognized := admission.Policy, admission.Recognition.Record
	proposal := &nativev1.QuoteProposalV1{ProposalId: "provider-" + hex.EncodeToString(nonce), CapabilityId: request.CapabilityId, CapabilityVersion: p.version, ProviderAgentId: p.config.ProviderAgentID, ManifestDigest: p.manifestDigest, TransportBindingDigest: digest, ExpiresAtUnixSeconds: uint64(p.config.Now().Add(p.config.ProposalTTL).Unix()), Actor: &nativev1.TOSAccountAddressV1{Workchain: 0, AccountId: append([]byte(nil), p.settlement.ActorAccountID...)}, ActorCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(p.settlement.ActorCodeHash), PolicyVersion: policy.PolicyVersion, TermsHash: hex.EncodeToString(admission.TermsHash[:]), PriceAtomic: policy.PricePerCall.String(), StorageFeeNanotos: policy.StorageFee.String(), AttestorKeyId: p.settlement.AttestorKey, Asset: &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{Workchain: 0, AccountId: append([]byte(nil), evidence.Manifest.SupportedAssets[0].MasterAccountID...), CodeHash: "tvm-cell-sha256:" + hex.EncodeToString(recognized.MinterCodeHash[:])}, WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(recognized.WalletCodeHash[:]), Decimals: uint32(recognized.Decimals)}}
	value := &nativev1.QuoteProposalPackageV1{Proposal: proposal, CanonicalManifestCbor: append([]byte(nil), p.config.ManifestCBOR...), TransportBindingBoc: transport.ToBOC()}
	if _, err := quoteexchange.ValidateToken(p.config.Network, request, value, p.config.Now()); err != nil {
		return nil, errors.New("constructed token Quote failed validation")
	}
	if err := railwork.CheckCarriableQuote(value, p.config.Transport); err != nil {
		return nil, err
	}
	return value, nil
}
