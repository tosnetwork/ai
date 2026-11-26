package serviceactorindex

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/internal/servicefixture"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type tokenDiscoveryReader struct {
	session *tokenDiscoveryFake
	opens   int
}

func (r *tokenDiscoveryReader) BeginSession(context.Context) (Session, error) {
	r.opens++
	return r.session, nil
}

type tokenDiscoveryFake struct {
	*registrySession
	account     *toschain.TokenActorAccount
	recognition *toschain.TokenAssetRecognition
	accepting   bool
	assetErr    error
	seenPins    []toschain.TokenAssetPin
}

func (s *tokenDiscoveryFake) ReadTokenActor(context.Context, string) (*toschain.TokenActorAccount, bool, error) {
	return s.account, true, nil
}
func (s *tokenDiscoveryFake) ReadTokenAsset(_ context.Context, _ string, pins []toschain.TokenAssetPin) (*toschain.TokenAssetRecognition, error) {
	s.seenPins = append([]toschain.TokenAssetPin(nil), pins...)
	if len(pins) == 0 {
		return nil, errors.New("asset not pinned")
	}
	return s.recognition, s.assetErr
}
func (s *tokenDiscoveryFake) GetTokenAcceptingTokens(context.Context, string) (bool, error) {
	return s.accepting, nil
}

func tokenDiscoveryFixture(t *testing.T) (*tokenDiscoveryReader, manifests, Candidate, toschain.TokenAssetPin) {
	t.Helper()
	chain, sources, candidates := offerFixture(t, 1)
	candidate := candidates[0]
	cap := chain.states[candidate.CapabilityID].GetCapability()
	oldDigest := cap.Versions[0].ManifestDigest
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(sources[oldDigest])
	if err != nil {
		t.Fatal(err)
	}
	code := nativecore.ServiceActorTokenReleaseCodeHash
	manifest.Settlement.Rail = nativecore.ServiceActorTokenRail
	manifest.Settlement.ActorCodeHash = code[:]
	walletCode := cell.BeginCell().MustStoreUInt(1, 8).EndCell()
	var walletHash [32]byte
	copy(walletHash[:], walletCode.Hash())
	masterID := bytes.Repeat([]byte{0xab}, 32)
	decimals := uint8(6)
	manifest.SupportedAssets = []nativecore.SoftwareWorkAssetV1{{Kind: nativecore.TOSTokenAsset, MasterAccountID: masterID, WalletCodeHash: walletHash[:], Decimals: &decimals}}
	raw, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sources[digest] = raw
	cap.Versions[0].ManifestDigest = digest
	p := policy()
	p.MetadataHash, err = nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: servicefixture.Network(), CapabilityID: candidate.CapabilityID, ProviderAgentID: cap.OwnerAgentId, CapabilityVersion: candidate.Version, ManifestDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	master, err := nativecore.StandardAddress("0:" + hex.EncodeToString(masterID))
	if err != nil {
		t.Fatal(err)
	}
	route := nativecore.ServiceActorTokenAssetRouteV1{Master: master, WalletCodeHash: walletHash, WalletCode: walletCode, BridgeConfigParam: 79}
	dataCell, err := nativecore.BuildServiceActorTokenInitialData(owner, nativecore.ServiceActorTokenPolicyV1{ServiceActorPolicyV1: p, MaxTokenLiability: big.NewInt(1_000_000_000_000)}, route)
	if err != nil {
		t.Fatal(err)
	}
	data, err := nativecore.DecodeServiceActorTokenData(dataCell)
	if err != nil {
		t.Fatal(err)
	}
	data.Active = true
	address := "0:" + hex.EncodeToString(manifest.Settlement.ActorAccountID)
	own, err := nativecore.DeriveServiceActorTokenWallet(address, route)
	if err != nil {
		t.Fatal(err)
	}
	s := &tokenDiscoveryFake{registrySession: &registrySession{chain: chain, checkpoint: 9}, account: &toschain.TokenActorAccount{Address: address, CodeHash: "tvm-cell-sha256:" + hex.EncodeToString(code[:]), OwnWallet: own, Data: data, BalanceNano: 2_000_000_000}, recognition: &toschain.TokenAssetRecognition{Checkpoint: 9, Record: toschain.SettlementAssetV1{Master: master.Text(), Status: 1, WalletCodeHash: walletHash, Decimals: 6, MaxLiabilityPerActor: big.NewInt(1_000_000_000_000)}}, accepting: true}
	for i := range s.recognition.Record.MinterCodeHash {
		s.recognition.Record.MinterCodeHash[i] = 0xcd
	}
	return &tokenDiscoveryReader{session: s}, sources, candidate, toschain.TokenAssetPin{Master: master.Text(), WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(walletHash[:]), Decimals: 6}
}
func TestTokenDiscoveryUsesOneCheckpointAndKeepsAtomicUnits(t *testing.T) {
	r, sources, candidate, pin := tokenDiscoveryFixture(t)
	code := "tvm-cell-sha256:" + hex.EncodeToString(nativecore.ServiceActorTokenReleaseCodeHash[:])
	d, err := NewDiscovery(r, servicefixture.Network(), sources, code, pin)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := d.DiscoverOffer(context.Background(), candidate, buyer)
	if err != nil {
		t.Fatal(err)
	}
	if r.opens != 1 || offer.Checkpoint != 9 || offer.PriceAtomic != "300000000" || offer.PriceNanoTOS != "" || offer.Asset == nil || offer.Asset.Master.CodeHash != "tvm-cell-sha256:"+strings.Repeat("cd", 32) || len(r.session.seenPins) != 1 {
		t.Fatalf("offer=%+v opens=%d", offer, r.opens)
	}
}
func TestTokenDiscoveryRefusesSuspensionNonAcceptanceAndUnpinnedAssets(t *testing.T) {
	for _, which := range []string{"suspended", "not accepting", "unrecognized checkpoint", "no pin", "read failure"} {
		t.Run(which, func(t *testing.T) {
			r, sources, candidate, pin := tokenDiscoveryFixture(t)
			pins := []toschain.TokenAssetPin{pin}
			switch which {
			case "suspended":
				r.session.recognition.Record.Status = 2
			case "not accepting":
				r.session.accepting = false
			case "unrecognized checkpoint":
				r.session.recognition.Checkpoint++
			case "no pin":
				pins = nil
			case "read failure":
				r.session.assetErr = errors.New("read failed")
			}
			d, err := NewDiscovery(r, servicefixture.Network(), sources, "tvm-cell-sha256:"+hex.EncodeToString(nativecore.ServiceActorTokenReleaseCodeHash[:]), pins...)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = d.DiscoverOffer(context.Background(), candidate, buyer); err == nil {
				t.Fatal("unsafe token offer accepted")
			}
		})
	}
}
