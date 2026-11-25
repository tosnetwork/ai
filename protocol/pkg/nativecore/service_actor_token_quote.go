package nativecore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

const TOSTokenAsset = "tos-token"

func validateSoftwareWorkAsset(manifest SoftwareWorkManifestV1) error {
	if len(manifest.SupportedAssets) != 1 {
		return errors.New("manifest requires exactly one settlement asset")
	}
	asset := manifest.SupportedAssets[0]
	switch asset.Kind {
	case NativeTOSAsset:
		if asset.MasterAccountID != nil || asset.WalletCodeHash != nil || asset.Decimals != nil || manifest.Settlement.Rail != ServiceActorRail {
			return errors.New("native manifest carries token identity or rail")
		}
		if bytes.Equal(manifest.Settlement.ActorCodeHash, ServiceActorTokenReleaseCodeHash[:]) || bytes.Equal(manifest.Settlement.ActorCodeHash, ServiceActorTokenTestProfileCodeHash[:]) {
			return errors.New("native manifest names token actor code")
		}
	case TOSTokenAsset:
		if len(asset.MasterAccountID) != 32 || bytes.Equal(asset.MasterAccountID, make([]byte, 32)) || len(asset.WalletCodeHash) != 32 || bytes.Equal(asset.WalletCodeHash, make([]byte, 32)) || asset.Decimals == nil || manifest.Settlement.Rail != ServiceActorTokenRail {
			return errors.New("token manifest has an invalid asset or rail")
		}
		if bytes.Equal(manifest.Settlement.ActorCodeHash, ServiceActorReleaseCodeHash[:]) || bytes.Equal(manifest.Settlement.ActorCodeHash, ServiceActorTestProfileCodeHash[:]) {
			return errors.New("token manifest names native actor code")
		}
	default:
		return errors.New("unsupported manifest asset")
	}
	return nil
}

// ServiceActorTokenQuoteRailV1 binds atomic units to an exact, independently pinned asset.
type ServiceActorTokenQuoteRailV1 struct {
	Actor                   string
	ActorCodeHash           [32]byte
	PolicyVersion           uint32
	TermsHash               [32]byte
	PriceAtomic, StorageFee *big.Int
	AttestorKeyID           [32]byte
	Asset                   *nativev1.TOSAssetIdentityV1
}

// ValidateTokenAssetIdentity validates the schema independently of recognition.
// Recognition and release pins must additionally be proven at the admission checkpoint.
func ValidateTokenAssetIdentity(asset *nativev1.TOSAssetIdentityV1) error {
	if asset == nil || asset.Master == nil || asset.Master.Workchain != 0 || len(asset.Master.AccountId) != 32 || bytes.Equal(asset.Master.AccountId, make([]byte, 32)) || asset.Decimals > 255 || len(asset.ProtoReflect().GetUnknown()) != 0 || len(asset.Master.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("invalid token asset identity")
	}
	if _, err := digestBytes(asset.Master.CodeHash, "tvm-cell-sha256:", false); err != nil {
		return errors.New("invalid token minter code hash")
	}
	if _, err := digestBytes(asset.WalletCodeHash, "tvm-cell-sha256:", false); err != nil {
		return errors.New("invalid token wallet code hash")
	}
	return nil
}

func ParseServiceActorTokenQuoteRail(proposal *nativev1.QuoteProposalV1) (ServiceActorTokenQuoteRailV1, error) {
	var rail ServiceActorTokenQuoteRailV1
	if proposal == nil || len(proposal.ProtoReflect().GetUnknown()) != 0 || proposal.PriceNanotos != "" || proposal.Actor == nil || proposal.Actor.Workchain != 0 || len(proposal.Actor.AccountId) != 32 {
		return rail, errors.New("token Quote requires only asset and price_atomic on workchain 0")
	}
	if err := ValidateTokenAssetIdentity(proposal.Asset); err != nil {
		return rail, err
	}
	code, err := digestBytes(proposal.ActorCodeHash, "tvm-cell-sha256:", false)
	if err != nil {
		return rail, err
	}
	copy(rail.ActorCodeHash[:], code)
	if rail.ActorCodeHash == ServiceActorReleaseCodeHash || rail.ActorCodeHash == ServiceActorTestProfileCodeHash {
		return rail, errors.New("token Quote names native actor code")
	}
	rail.Actor = "0:" + hex.EncodeToString(proposal.Actor.AccountId)
	rail.PolicyVersion = proposal.PolicyVersion
	if !lowerHex64Pattern.MatchString(proposal.TermsHash) {
		return rail, errors.New("invalid token terms hash")
	}
	terms, _ := hex.DecodeString(proposal.TermsHash)
	copy(rail.TermsHash[:], terms)
	if rail.TermsHash == ([32]byte{}) {
		return rail, errors.New("zero token terms hash")
	}
	if rail.PriceAtomic, err = parsePositiveNanoTOS(proposal.PriceAtomic); err != nil {
		return rail, err
	}
	if rail.StorageFee, err = parsePositiveNanoTOS(proposal.StorageFeeNanotos); err != nil {
		return rail, err
	}
	if rail.AttestorKeyID, err = mldsa44.ParseKeyIDText(proposal.AttestorKeyId); err != nil {
		return rail, err
	}
	rail.Asset = proto.Clone(proposal.Asset).(*nativev1.TOSAssetIdentityV1)
	return rail, nil
}

// BuildAcceptedTokenQuoteCommitment produces schema 3 without changing native schema 1.
func BuildAcceptedTokenQuoteCommitment(network *nativev1.NetworkDomain, proposal *nativev1.QuoteProposalV1) (*cell.Cell, string, error) {
	domain, err := domainCell(network)
	if err != nil {
		return nil, "", err
	}
	if proposal == nil || proposal.ExpiresAtUnixSeconds == 0 || !validProtocolText(proposal.CapabilityVersion, 128) {
		return nil, "", errors.New("invalid token Quote context")
	}
	capability, kind, err := objectID(proposal.CapabilityId)
	if err != nil || kind != 2 {
		return nil, "", errors.New("invalid token Quote Capability")
	}
	provider, kind, err := objectID(proposal.ProviderAgentId)
	if err != nil || kind != 1 {
		return nil, "", errors.New("invalid token Quote provider")
	}
	manifest, err := digestBytes(proposal.ManifestDigest, "sha256:", false)
	if err != nil {
		return nil, "", err
	}
	transport, err := digestBytes(proposal.TransportBindingDigest, "sha256:", false)
	if err != nil {
		return nil, "", err
	}
	rail, err := ParseServiceActorTokenQuoteRail(proposal)
	if err != nil {
		return nil, "", err
	}
	actor, err := StandardAddress(rail.Actor)
	if err != nil {
		return nil, "", err
	}
	master, err := StandardAddress("0:" + hex.EncodeToString(rail.Asset.Master.AccountId))
	if err != nil {
		return nil, "", err
	}
	minterCode, _ := digestBytes(rail.Asset.Master.CodeHash, "tvm-cell-sha256:", false)
	walletCode, _ := digestBytes(rail.Asset.WalletCodeHash, "tvm-cell-sha256:", false)
	asset := cell.BeginCell().MustStoreSlice(master.Bits, master.BitLen).MustStoreSlice(minterCode, 256).MustStoreSlice(walletCode, 256).MustStoreUInt(uint64(rail.Asset.Decimals), 8).EndCell()
	versionHash := sha256.Sum256([]byte(proposal.CapabilityVersion))
	version := cell.BeginCell().MustStoreSlice(versionHash[:], 256).MustStoreSlice(manifest, 256).MustStoreSlice(transport, 256).MustStoreUInt(proposal.ExpiresAtUnixSeconds, 64).MustStoreRef(stringCell(proposal.CapabilityVersion)).EndCell()
	identity := cell.BeginCell().MustStoreSlice(capability, 256).MustStoreSlice(provider, 256).MustStoreRef(version).EndCell()
	terms := cell.BeginCell().MustStoreSlice(rail.TermsHash[:], 256)
	if err = storeServiceActorCoins(terms, rail.PriceAtomic); err != nil {
		return nil, "", err
	}
	if err = storeServiceActorCoins(terms, rail.StorageFee); err != nil {
		return nil, "", err
	}
	railCell := cell.BeginCell().MustStoreSlice(actor.Bits, actor.BitLen).MustStoreSlice(rail.ActorCodeHash[:], 256).MustStoreUInt(uint64(rail.PolicyVersion), 32).MustStoreRef(terms.EndCell()).MustStoreRef(asset).EndCell()
	authority := cell.BeginCell().MustStoreSlice(rail.AttestorKeyID[:], 256).EndCell()
	root := cell.BeginCell().MustStoreUInt(acceptedQuoteMagic, 32).MustStoreUInt(3, 16).MustStoreRef(domain).MustStoreRef(identity).MustStoreRef(railCell).MustStoreRef(authority).EndCell()
	return root, digestString(root.Hash()), nil
}

// DecodeAcceptedTokenQuoteV1 checks every field, canonical encoding and the complete domain.
func DecodeAcceptedTokenQuoteV1(root *cell.Cell, network *nativev1.NetworkDomain) (*AcceptedQuoteTermsV1, error) {
	s, err := beginOrdinary(root, "token Quote")
	if err != nil {
		return nil, err
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != acceptedQuoteMagic {
		return nil, errors.New("invalid token Quote magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != 3 {
		return nil, errors.New("unsupported token Quote schema")
	}
	expected, err := domainCell(network)
	if err != nil {
		return nil, err
	}
	domain, err := loadRefCell(s, "token Quote domain")
	if err != nil || !bytes.Equal(domain.Hash(), expected.Hash()) {
		return nil, errors.New("token Quote domain mismatch")
	}
	identity, err := loadRefCell(s, "token Quote identity")
	if err != nil {
		return nil, err
	}
	railCell, err := loadRefCell(s, "token Quote rail")
	if err != nil {
		return nil, err
	}
	authority, err := loadRefCell(s, "token Quote authority")
	if err != nil {
		return nil, err
	}
	if err = exhausted(s, "token Quote root"); err != nil {
		return nil, err
	}
	i, err := beginOrdinary(identity, "token Quote identity")
	if err != nil {
		return nil, err
	}
	capability, err := loadHash(i)
	if err != nil {
		return nil, err
	}
	provider, err := loadHash(i)
	if err != nil {
		return nil, err
	}
	version, err := loadRefCell(i, "token Quote version")
	if err != nil {
		return nil, err
	}
	if err = exhausted(i, "token Quote identity"); err != nil {
		return nil, err
	}
	v, err := beginOrdinary(version, "token Quote version")
	if err != nil {
		return nil, err
	}
	versionHash, err := loadHash(v)
	if err != nil {
		return nil, err
	}
	manifest, err := loadHash(v)
	if err != nil {
		return nil, err
	}
	transport, err := loadHash(v)
	if err != nil {
		return nil, err
	}
	expires, err := v.LoadUInt(64)
	if err != nil {
		return nil, err
	}
	versionTextCell, err := loadRefCell(v, "token Quote version text")
	if err != nil {
		return nil, err
	}
	if err = exhausted(v, "token Quote version"); err != nil {
		return nil, err
	}
	versionText, err := decodeProtocolText(versionTextCell, 128)
	if err != nil || sha256.Sum256([]byte(versionText)) != versionHash {
		return nil, errors.New("token Quote version mismatch")
	}
	r, err := beginOrdinary(railCell, "token Quote rail")
	if err != nil {
		return nil, err
	}
	actor, err := loadMsgAddressInt(r)
	if err != nil {
		return nil, err
	}
	actorRaw, ok := actor.RawStandard()
	if !ok || actor.Workchain != 0 {
		return nil, errors.New("invalid token Quote actor")
	}
	code, err := loadHash(r)
	if err != nil {
		return nil, err
	}
	policy, err := r.LoadUInt(32)
	if err != nil {
		return nil, err
	}
	terms, err := loadRefCell(r, "token Quote terms")
	if err != nil {
		return nil, err
	}
	asset, err := loadRefCell(r, "token Quote asset")
	if err != nil {
		return nil, err
	}
	if err = exhausted(r, "token Quote rail"); err != nil {
		return nil, err
	}
	t, err := beginOrdinary(terms, "token Quote terms")
	if err != nil {
		return nil, err
	}
	hash, err := loadHash(t)
	if err != nil {
		return nil, err
	}
	price, err := loadServiceActorCoins(t)
	if err != nil {
		return nil, err
	}
	fee, err := loadServiceActorCoins(t)
	if err != nil {
		return nil, err
	}
	if err = exhausted(t, "token Quote terms"); err != nil {
		return nil, err
	}
	a, err := beginOrdinary(asset, "token Quote asset")
	if err != nil {
		return nil, err
	}
	master, err := loadMsgAddressInt(a)
	if err != nil {
		return nil, err
	}
	masterRaw, ok := master.RawStandard()
	if !ok || master.Workchain != 0 {
		return nil, errors.New("invalid token Quote master")
	}
	minter, err := loadHash(a)
	if err != nil {
		return nil, err
	}
	wallet, err := loadHash(a)
	if err != nil {
		return nil, err
	}
	decimals, err := a.LoadUInt(8)
	if err != nil {
		return nil, err
	}
	if err = exhausted(a, "token Quote asset"); err != nil {
		return nil, err
	}
	auth, err := beginOrdinary(authority, "token Quote authority")
	if err != nil {
		return nil, err
	}
	key, err := loadHash(auth)
	if err != nil {
		return nil, err
	}
	if err = exhausted(auth, "token Quote authority"); err != nil {
		return nil, err
	}
	actorID, _ := hex.DecodeString(actorRaw[2:])
	masterID, _ := hex.DecodeString(masterRaw[2:])
	proposal := &nativev1.QuoteProposalV1{CapabilityId: "cap_" + hex.EncodeToString(capability[:]), CapabilityVersion: versionText, ProviderAgentId: "agent_" + hex.EncodeToString(provider[:]), ManifestDigest: "sha256:" + hex.EncodeToString(manifest[:]), TransportBindingDigest: "sha256:" + hex.EncodeToString(transport[:]), ExpiresAtUnixSeconds: expires, Actor: &nativev1.TOSAccountAddressV1{Workchain: 0, AccountId: actorID}, ActorCodeHash: digestString(code[:]), PolicyVersion: uint32(policy), TermsHash: hex.EncodeToString(hash[:]), PriceAtomic: price.String(), StorageFeeNanotos: fee.String(), AttestorKeyId: mldsa44.KeyIDText(key), Asset: &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{Workchain: 0, AccountId: masterID, CodeHash: digestString(minter[:])}, WalletCodeHash: digestString(wallet[:]), Decimals: uint32(decimals)}}
	rebuilt, _, err := BuildAcceptedTokenQuoteCommitment(network, proposal)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nil, errors.New("token Quote is not canonical")
	}
	return &AcceptedQuoteTermsV1{Network: proto.Clone(network).(*nativev1.NetworkDomain), Proposal: proposal}, nil
}
