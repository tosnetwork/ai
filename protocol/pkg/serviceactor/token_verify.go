package serviceactor

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math"
	"math/big"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"google.golang.org/protobuf/proto"
)

// TokenEvidence keeps actor cells and recognition from one named session.
// Existing-request verification uses the immutable executed admission, never
// the latest recognition status as authority over money already admitted.
type TokenEvidence struct {
	Evidence
	Actor       *toschain.TokenActorAccount
	Recognition *toschain.TokenAssetRecognition
}

type TokenSession interface {
	registrySession
	ReadTokenActor(context.Context, string) (*toschain.TokenActorAccount, bool, error)
	ReadTokenAsset(context.Context, string, []toschain.TokenAssetPin) (*toschain.TokenAssetRecognition, error)
}

func GatherTokenEvidence(ctx context.Context, session TokenSession, network *nativev1.NetworkDomain, sources ManifestSource, capabilityID, version string, pins []toschain.TokenAssetPin, admission bool) (*TokenEvidence, error) {
	common, err := gatherRegistryEvidence(ctx, session, network, sources, capabilityID, version)
	if err != nil {
		return nil, err
	}
	evidence := &TokenEvidence{Evidence: *common}
	if common.Manifest.Settlement.Rail != nativecore.ServiceActorTokenRail {
		return nil, errors.New("manifest does not select the token rail")
	}
	actor := "0:" + hex.EncodeToString(common.Manifest.Settlement.ActorAccountID)
	evidence.Actor, _, err = session.ReadTokenActor(ctx, actor)
	if err != nil {
		return nil, err
	}
	if evidence.Actor == nil || evidence.Actor.Data == nil {
		return nil, errors.New("token actor is not deployed")
	}
	if admission {
		master, ok := evidence.Actor.Data.Route.Master.RawStandard()
		if !ok {
			return nil, errors.New("invalid token route master")
		}
		evidence.Recognition, err = session.ReadTokenAsset(ctx, master, pins)
		if err != nil {
			return nil, err
		}
	}
	return evidence, nil
}

func VerifyTokenBinding(e *TokenEvidence, pinnedCodeHash [32]byte, rail *nativecore.ServiceActorTokenQuoteRailV1, proposal *nativev1.QuoteProposalV1, destination string, acceptance ...*Acceptance) (*Binding, error) {
	if e == nil {
		return nil, stepError("binding", 1, "missing token evidence")
	}
	var atCall *Acceptance
	if len(acceptance) > 1 {
		return nil, errors.New("ambiguous token acceptance proof")
	}
	if len(acceptance) == 1 {
		atCall = acceptance[0]
	}
	capability, err := verifyRegistryBinding(&e.Evidence, proposal, atCall)
	if err != nil {
		return nil, err
	}
	if !proto.Equal(e.Agent.Network, e.Network) {
		return nil, stepError("binding", 1, "owner Agent belongs to another network")
	}
	settlement := e.Manifest.Settlement
	if settlement.Rail != nativecore.ServiceActorTokenRail || settlement.ActorWorkchain != 0 || len(settlement.ActorAccountID) != 32 {
		return nil, stepError("binding", 2, "manifest does not select a basechain token actor")
	}
	actor := "0:" + hex.EncodeToString(settlement.ActorAccountID)
	if destination != actor || (rail != nil && rail.Actor != actor) {
		return nil, stepError("binding", 2, "token actor destination mismatch")
	}
	if e.Actor == nil || e.Actor.Data == nil || e.Actor.Address != actor {
		return nil, stepError("binding", 3, "token actor missing from finalized checkpoint")
	}
	code, err := digestBytes(e.Actor.CodeHash, "tvm-cell-sha256:")
	if err != nil || code != pinnedCodeHash || !bytes.Equal(settlement.ActorCodeHash, pinnedCodeHash[:]) || (rail != nil && rail.ActorCodeHash != pinnedCodeHash) {
		return nil, stepError("binding", 3, "token actor release hashes differ")
	}
	if pinnedCodeHash != nativecore.ServiceActorTokenReleaseCodeHash && pinnedCodeHash != nativecore.ServiceActorTokenTestProfileCodeHash {
		return nil, stepError("binding", 3, "token actor release is not supported")
	}
	key, err := mldsa44.ParseKeyIDText(settlement.AttestorKey)
	if err != nil || (rail != nil && rail.AttestorKeyID != key) {
		return nil, stepError("binding", 4, "token attestor differs from manifest")
	}
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: e.Network, CapabilityID: capability.CapabilityId, ProviderAgentID: capability.OwnerAgentId, CapabilityVersion: e.Version, ManifestDigest: e.ManifestDigest})
	if err != nil {
		return nil, err
	}
	if err = verifyTokenAsset(e, rail, false); err != nil {
		return nil, err
	}
	return &Binding{Actor: actor, ActorCodeHash: code, AttestorKeyID: key, AttestorText: settlement.AttestorKey, MetadataHash: metadata, Owner: e.Actor.Data.Owner}, nil
}

func verifyTokenAsset(e *TokenEvidence, rail *nativecore.ServiceActorTokenQuoteRailV1, recognition bool) error {
	if e == nil || e.Actor == nil || e.Actor.Data == nil || len(e.Manifest.SupportedAssets) != 1 {
		return errors.New("missing token asset evidence")
	}
	asset := e.Manifest.SupportedAssets[0]
	route := e.Actor.Data.Route
	master, ok := route.Master.RawStandard()
	if !ok || route.Master.Workchain != 0 || asset.Kind != nativecore.TOSTokenAsset || asset.Decimals == nil || len(asset.MasterAccountID) != 32 || master != "0:"+hex.EncodeToString(asset.MasterAccountID) {
		return errors.New("manifest token master differs from actor route")
	}

	if route.WalletCode == nil || !bytes.Equal(route.WalletCode.Hash(), route.WalletCodeHash[:]) || !bytes.Equal(asset.WalletCodeHash, route.WalletCodeHash[:]) {
		return errors.New("manifest token wallet code differs from route")
	}
	if rail != nil && (rail.Asset == nil || rail.Asset.Master == nil || master != "0:"+hex.EncodeToString(rail.Asset.Master.AccountId) || rail.Asset.WalletCodeHash != "tvm-cell-sha256:"+hex.EncodeToString(route.WalletCodeHash[:]) || rail.Asset.Decimals != uint32(*asset.Decimals)) {
		return errors.New("Quote asset differs from manifest or route")
	}
	if recognition {
		r := e.Recognition
		if r == nil || r.Checkpoint != e.Checkpoint || r.Record.Status != 1 || r.Record.Master != master || r.Record.WalletCodeHash != route.WalletCodeHash || r.Record.Decimals != *asset.Decimals {
			return errors.New("token recognition differs from pinned admission identity or checkpoint")
		}
		if rail != nil && rail.Asset.Master.CodeHash != "tvm-cell-sha256:"+hex.EncodeToString(r.Record.MinterCodeHash[:]) {
			return errors.New("Quote minter code differs from recognized release")
		}
	}
	return nil
}

// TokenAdmission is the current policy and terms after an atomic recognition read.
type TokenAdmission struct {
	Binding     *Binding
	Policy      nativecore.ServiceActorTokenPolicyV1
	Terms       nativecore.ServiceActorTokenTermsV1
	TermsHash   [32]byte
	Recognition *toschain.TokenAssetRecognition
}

func VerifyTokenAdmission(e *TokenEvidence, pinnedCodeHash [32]byte, rail *nativecore.ServiceActorTokenQuoteRailV1, proposal *nativev1.QuoteProposalV1, buyer string) (*TokenAdmission, error) {
	destination := ""
	if e != nil {
		destination = "0:" + hex.EncodeToString(e.Manifest.Settlement.ActorAccountID)
	}
	binding, err := VerifyTokenBinding(e, pinnedCodeHash, rail, proposal, destination)
	if err != nil {
		return nil, err
	}
	if err = verifyTokenAsset(e, rail, true); err != nil {
		return nil, err
	}
	d := e.Actor.Data
	p := d.Policy
	if err = nativecore.ValidateServiceActorTokenLiveState(d); err != nil {
		return nil, err
	}
	if !d.Active || !p.HasAttestor || p.AttestorKeyID != binding.AttestorKeyID {
		return nil, errors.New("token actor is inactive or its attestor differs")
	}
	key, err := mldsa44.KeyID(p.AttestorKey)
	if err != nil || key != p.AttestorKeyID {
		return nil, errors.New("invalid token attestor key")
	}
	if p.MetadataHash != binding.MetadataHash || p.ProofSchemeHash != nativecore.ServiceActorSoftwareWorkProofScheme {
		return nil, errors.New("token actor metadata or proof scheme differs")
	}
	if p.PricePerCall == nil || p.StorageFee == nil || p.CleanupBounty == nil || p.MaxTokenLiability == nil || p.MaxTokenLiability.Sign() <= 0 {
		return nil, errors.New("invalid token policy amounts")
	}
	boundsCode := pinnedCodeHash
	if pinnedCodeHash == nativecore.ServiceActorTokenTestProfileCodeHash {
		boundsCode = nativecore.ServiceActorTestProfileCodeHash
	}
	if err = CheckPolicyBounds(p.ServiceActorPolicyV1, boundsCode); err != nil {
		return nil, err
	}
	if d.LiveCount >= 1436 || d.Accounting.ReturnedCount >= 1436 || d.Accounting.ReturnsInFlight >= 448 || d.NextRequestID == math.MaxUint64 {
		return nil, errors.New("token actor is not accepting calls")
	}
	if buyer != "" {
		caller, err := nativecore.StandardAddress(buyer)
		if err != nil || caller.Workchain != 0 {
			return nil, errors.New("token buyer must be on workchain 0")
		}
		if !p.OpenAccess && !(p.HasAuthorizedCaller && p.AuthorizedCaller.Equal(caller)) {
			return nil, errors.New("token buyer is not authorized")
		}
		h, err := caller.SliceHash()
		if err != nil {
			return nil, err
		}
		if d.CallerLiveCounts[h] >= 1000 || d.CallerReturnedCounts[h] >= 16 {
			return nil, errors.New("token buyer capacity reached")
		}
	}
	liability := new(big.Int)
	for _, v := range []*big.Int{d.Accounting.Ledger.PendingLiability, d.Accounting.Ledger.RefundableLiability, d.Accounting.Ledger.ReturnedLiability, d.Accounting.Ledger.InFlight} {
		liability.Add(liability, v)
	}
	liability.Add(liability, p.PricePerCall)
	if e.Recognition.Record.MaxLiabilityPerActor == nil || liability.Cmp(p.MaxTokenLiability) > 0 || liability.Cmp(e.Recognition.Record.MaxLiabilityPerActor) > 0 || liability.Cmp(nativecore.MaxServiceActorCoins) >= 0 {
		return nil, errors.New("token exposure cap exceeded")
	}
	reserve := new(big.Int).Add(d.Accounting.LockedStorageFees, d.Accounting.LockedOutcomeFees)
	reserve.Add(reserve, big.NewInt(nativecore.ServiceActorMinimumOperatingReserve))
	if reserve.Cmp(new(big.Int).SetUint64(e.Actor.BalanceNano)) > 0 {
		return nil, errors.New("token actor operating reserve is unfunded")
	}
	terms := nativecore.ServiceActorTokenTermsV1{ServiceActorTermsV1: nativecore.TermsOfPolicy(p.ServiceActorPolicyV1), AssetWalletCodeHash: d.Route.WalletCodeHash}
	master := e.Manifest.SupportedAssets[0].MasterAccountID
	copy(terms.AssetMasterHash[:], master)
	cell, err := nativecore.BuildServiceActorTokenTerms(terms)
	if err != nil {
		return nil, err
	}
	var hash [32]byte
	copy(hash[:], cell.Hash())
	if rail != nil && (hash != rail.TermsHash || rail.PolicyVersion != p.PolicyVersion || rail.PriceAtomic.Cmp(p.PricePerCall) != 0 || rail.StorageFee.Cmp(p.StorageFee) != 0) {
		return nil, errors.New("token Quote terms or price differ from current policy")
	}
	return &TokenAdmission{Binding: binding, Policy: p, Terms: terms, TermsHash: hash, Recognition: e.Recognition}, nil
}

// TokenExistingRequest verifies immutable admitted terms, not the current policy.
type TokenExistingRequest struct {
	Binding    *Binding
	Call       toschain.TokenActorTransaction
	Snapshot   nativecore.ServiceActorTokenRequestSnapshotV1
	Checkpoint uint64
}

func VerifyTokenExistingRequest(e *TokenEvidence, code [32]byte, rail *nativecore.ServiceActorTokenQuoteRailV1, proposal *nativev1.QuoteProposalV1, call toschain.TokenActorTransaction, buyer string, requestHash [32]byte, acceptance ...*Acceptance) (*TokenExistingRequest, error) {
	if e == nil || rail == nil || proposal == nil {
		return nil, errors.New("token request needs its admission and Quote")
	}
	parsed, err := nativecore.ParseServiceActorTokenQuoteRail(proposal)
	if err != nil {
		return nil, err
	}
	if rail.PriceAtomic == nil || parsed.Actor != rail.Actor || parsed.TermsHash != rail.TermsHash || parsed.PriceAtomic.Cmp(rail.PriceAtomic) != 0 {
		return nil, errors.New("token rail does not describe its Quote")
	}
	rail = &parsed
	binding, err := VerifyTokenBinding(e, code, rail, proposal, rail.Actor, acceptance...)
	if err != nil {
		return nil, err
	}
	// A finalized SAT1 from the pinned release proves the contract's admission
	// checks. Current asset status is deliberately not consulted for an existing
	// liability. The caller separately pins the immutable Quote asset identity.
	if !call.TookEffect || call.Notification == nil || call.Sender != e.Actor.OwnWallet || call.Notification.From != buyer || call.Notification.AmountAtomic != rail.PriceAtomic.String() || call.Notification.Payload == nil || call.Notification.Payload.RequestHash != requestHash || call.Notification.Payload.ExpectedTermsHash != rail.TermsHash {
		return nil, errors.New("token funding notification is not authenticated to this Quote")
	}
	var snapshot *nativecore.ServiceActorTokenRequestSnapshotV1
	for _, log := range call.Logs {
		if log.Snapshot != nil {
			if snapshot != nil {
				return nil, errors.New("duplicate token admission snapshot")
			}
			snapshot = log.Snapshot
		}
	}
	if snapshot == nil || snapshot.Caller.Text() != buyer || snapshot.RequestHash != requestHash {
		return nil, errors.New("token admission snapshot differs from notification")
	}
	t := snapshot.Terms
	termsCell, err := nativecore.BuildServiceActorTokenTerms(t)
	if err != nil || !bytes.Equal(termsCell.Hash(), snapshot.TermsHash[:]) {
		return nil, errors.New("invalid token admission snapshot terms")
	}
	if !t.HasAttestor || t.AttestorKeyID != binding.AttestorKeyID || snapshot.TermsHash != rail.TermsHash || t.PolicyVersion != rail.PolicyVersion || t.PricePerCall.Cmp(rail.PriceAtomic) != 0 || t.StorageFee.Cmp(rail.StorageFee) != 0 || t.MetadataHash != binding.MetadataHash || t.ProofSchemeHash != nativecore.ServiceActorSoftwareWorkProofScheme || !bytes.Equal(t.AssetMasterHash[:], rail.Asset.Master.AccountId) || hex.EncodeToString(t.AssetWalletCodeHash[:]) != rail.Asset.WalletCodeHash[len("tvm-cell-sha256:"):] {
		return nil, errors.New("token admission terms differ from immutable Quote")
	}
	if snapshot.ResponseDeadline != uint64(call.Now)+uint64(t.ResponseSLA) || snapshot.RefundClaimDeadline < snapshot.ResponseDeadline || snapshot.RefundClaimDeadline-snapshot.ResponseDeadline != uint64(t.RefundClaimWindow) {
		return nil, errors.New("token admission deadlines differ")
	}
	return &TokenExistingRequest{Binding: binding, Call: call, Snapshot: *snapshot, Checkpoint: e.Checkpoint}, nil
}
