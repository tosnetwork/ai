package serviceactorindex

import (
	"context"
	"encoding/hex"
	"errors"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
)

type tokenDiscoverySession interface {
	serviceactor.TokenSession
	GetTokenAcceptingTokens(context.Context, string) (bool, error)
}

func (d *Discovery) discoverTokenAt(ctx context.Context, session Session, candidate Candidate, buyer string) (*Offer, error) {
	token, ok := session.(tokenDiscoverySession)
	if !ok {
		return nil, errors.New("token discovery needs a finalized token session")
	}
	evidence, err := serviceactor.GatherTokenEvidence(ctx, token, d.network, d.manifest, candidate.CapabilityID, candidate.Version, d.tokenPins, true)
	if err != nil {
		return nil, err
	}
	admission, err := serviceactor.VerifyTokenAdmission(evidence, d.codeHash, nil, nil, buyer)
	if err != nil {
		return nil, &serviceactor.StepError{Procedure: "admission", Step: 5, Reason: err.Error()}
	}
	accepting, err := token.GetTokenAcceptingTokens(ctx, admission.Binding.Actor)
	if err != nil {
		return nil, err
	}
	if !accepting {
		return nil, &serviceactor.StepError{Procedure: "admission", Step: 5, Reason: "token actor is not accepting tokens"}
	}
	p, r := admission.Policy, admission.Recognition.Record
	capability := evidence.Capability.GetCapability()
	asset := &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{Workchain: 0, AccountId: append([]byte(nil), evidence.Manifest.SupportedAssets[0].MasterAccountID...), CodeHash: "tvm-cell-sha256:" + hex.EncodeToString(r.MinterCodeHash[:])}, WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(r.WalletCodeHash[:]), Decimals: uint32(r.Decimals)}
	return &Offer{Checkpoint: evidence.Checkpoint, CapabilityID: capability.CapabilityId, CapabilityVersion: evidence.Version, ProviderAgentID: capability.OwnerAgentId, ManifestDigest: evidence.ManifestDigest, Actor: admission.Binding.Actor, ActorCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(admission.Binding.ActorCodeHash[:]), AttestorKeyID: mldsa44.KeyIDText(admission.Binding.AttestorKeyID), PolicyVersion: p.PolicyVersion, TermsHash: hex.EncodeToString(admission.TermsHash[:]), Asset: asset, PriceAtomic: p.PricePerCall.String(), StorageFeeNanoTOS: p.StorageFee.String(), CleanupBountyNano: p.CleanupBounty.String(), ResponseSLASeconds: p.ResponseSLA, RefundWindowSeconds: p.RefundClaimWindow, OpenAccess: p.OpenAccess}, nil
}
