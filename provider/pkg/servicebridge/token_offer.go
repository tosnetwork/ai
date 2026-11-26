package servicebridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

// ExportTokenOffer revalidates the published binding and encodes the existing
// public offer-file format. The bytes are a projection, never registry authority.
func ExportTokenOffer(ctx context.Context, c NodeConfig, address string, env TokenEnv) ([]byte, error) {
	env.fill()
	if c.Token == nil {
		return nil, errors.New("no token provider")
	}
	a, err := c.Token.Actor(address)
	if err != nil {
		return nil, err
	}
	s, err := env.Begin(ctx, c, a)
	if err != nil {
		return nil, err
	}
	if _, err = tokenOfferAtSession(ctx, c, a, s); err != nil {
		return nil, err
	}
	info, err := os.Lstat(a.ManifestFile)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("token manifest outside bounds")
	}
	raw, err := os.ReadFile(a.ManifestFile)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	state, found, err := s.ResolveRegistry(ctx, a.CapabilityID)
	if err != nil {
		return nil, err
	}
	if !found || state.GetCapability() == nil {
		return nil, errors.New("Capability missing")
	}
	digest := "sha256:" + hex.EncodeToString(sum[:])
	matched := false
	for _, v := range state.GetCapability().Versions {
		if v.Version == a.Version && !v.Revoked && v.ManifestDigest == digest {
			matched = true
		}
	}
	if !matched {
		return nil, errors.New("manifest changed during offer export")
	}
	return EncodeOfferFile(Offer{CapabilityID: a.CapabilityID, Version: a.Version, ProviderAgentID: c.AgentID, ManifestDigest: digest, ManifestCBOR: raw}, s.ChainTime())
}

// BuildTokenManifest shares the software-work profile and the canonical T7
// encoder, with an explicit asset identity instead of a native price label.
func BuildTokenManifest(in ManifestInput, pin toschain.TokenAssetPin) ([]byte, string, nativecore.SoftwareWorkManifestV1, error) {
	code, err := hex.DecodeString(strings.TrimPrefix(in.ActorCodeHash, "tvm-cell-sha256:"))
	if err != nil || len(code) != 32 {
		return nil, "", nativecore.SoftwareWorkManifestV1{}, errors.New("invalid token actor release")
	}
	var hash [32]byte
	copy(hash[:], code)
	if hash != nativecore.ServiceActorTokenReleaseCodeHash && hash != nativecore.ServiceActorTokenTestProfileCodeHash {
		return nil, "", nativecore.SoftwareWorkManifestV1{}, errors.New("unsupported token manifest release")
	}
	nativeInput := in
	nativeInput.ActorCodeHash = "tvm-cell-sha256:" + hex.EncodeToString(nativecore.ServiceActorReleaseCodeHash[:])
	_, _, m, err := BuildManifest(nativeInput)
	if err != nil {
		return nil, "", m, err
	}
	master, err := nativecore.StandardAddress(pin.Master)
	if err != nil || master.Workchain != 0 {
		return nil, "", m, errors.New("invalid token manifest master")
	}
	wallet, err := hex.DecodeString(strings.TrimPrefix(pin.WalletCodeHash, "tvm-cell-sha256:"))
	if err != nil || len(wallet) != 32 {
		return nil, "", m, errors.New("invalid token manifest wallet code")
	}
	decimal := pin.Decimals
	m.SupportedAssets = []nativecore.SoftwareWorkAssetV1{{Kind: nativecore.TOSTokenAsset, MasterAccountID: master.Address, WalletCodeHash: wallet, Decimals: &decimal}}
	m.Settlement.Rail = nativecore.ServiceActorTokenRail
	m.Settlement.ActorCodeHash = code
	raw, digest, err := nativecore.CanonicalSoftwareWorkManifest(m)
	return raw, digest, m, err
}
