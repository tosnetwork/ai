package buyeragent

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/internal/servicefixture"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactorindex"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type tokenOffersChain struct {
	*offerChain
	account     *toschain.TokenActorAccount
	recognition *toschain.TokenAssetRecognition
	accepting   bool
}

func (c *tokenOffersChain) BeginSession(ctx context.Context) (serviceactorindex.Session, error) {
	base, err := c.offerChain.BeginSession(ctx)
	if err != nil {
		return nil, err
	}
	return &tokenOffersSession{offerSession: base.(*offerSession), chain: c}, nil
}

type tokenOffersSession struct {
	*offerSession
	chain *tokenOffersChain
}

func (s *tokenOffersSession) ReadTokenActor(context.Context, string) (*toschain.TokenActorAccount, bool, error) {
	return s.chain.account, true, nil
}
func (s *tokenOffersSession) ReadTokenAsset(_ context.Context, _ string, pins []toschain.TokenAssetPin) (*toschain.TokenAssetRecognition, error) {
	if len(pins) == 0 {
		return nil, errors.New("asset not pinned")
	}
	return s.chain.recognition, nil
}
func (s *tokenOffersSession) GetTokenAcceptingTokens(context.Context, string) (bool, error) {
	return s.chain.accepting, nil
}

func tokenOffersFixture(t *testing.T) (*offersFixture, *tokenOffersChain) {
	t.Helper()
	f := newOffersFixture(t)
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Settlement.Rail = nativecore.ServiceActorTokenRail
	code := nativecore.ServiceActorTokenReleaseCodeHash
	manifest.Settlement.ActorCodeHash = code[:]
	wallet := cell.BeginCell().MustStoreUInt(1, 8).EndCell()
	var hash [32]byte
	copy(hash[:], wallet.Hash())
	id := bytes.Repeat([]byte{0xab}, 32)
	decimal := uint8(6)
	manifest.SupportedAssets = []nativecore.SoftwareWorkAssetV1{{Kind: nativecore.TOSTokenAsset, MasterAccountID: id, WalletCodeHash: hash[:], Decimals: &decimal}}
	raw, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	f.chain.states[fxCapability].GetCapability().Versions[0].ManifestDigest = digest
	policy := f.chain.actors[fxActor].Data.Policy
	policy.MetadataHash, err = nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: servicefixture.Network(), CapabilityID: fxCapability, ProviderAgentID: fxProvider, CapabilityVersion: "1.0.0", ManifestDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	master, err := nativecore.StandardAddress("0:" + hex.EncodeToString(id))
	if err != nil {
		t.Fatal(err)
	}
	route := nativecore.ServiceActorTokenAssetRouteV1{Master: master, WalletCode: wallet, WalletCodeHash: hash, BridgeConfigParam: 79}
	root, err := nativecore.BuildServiceActorTokenInitialData("0:"+strings.Repeat("11", 32), nativecore.ServiceActorTokenPolicyV1{ServiceActorPolicyV1: policy, MaxTokenLiability: big.NewInt(1_000_000_000_000)}, route)
	if err != nil {
		t.Fatal(err)
	}
	data, err := nativecore.DecodeServiceActorTokenData(root)
	if err != nil {
		t.Fatal(err)
	}
	data.Active = true
	own, err := nativecore.DeriveServiceActorTokenWallet(fxActor, route)
	if err != nil {
		t.Fatal(err)
	}
	chain := &tokenOffersChain{offerChain: f.chain, account: &toschain.TokenActorAccount{Address: fxActor, CodeHash: "tvm-cell-sha256:" + hex.EncodeToString(code[:]), OwnWallet: own, Data: data, BalanceNano: 2_000_000_000}, recognition: &toschain.TokenAssetRecognition{Checkpoint: 41, Record: toschain.SettlementAssetV1{Master: master.Text(), Status: 1, Decimals: 6, WalletCodeHash: hash, MaxLiabilityPerActor: big.NewInt(1_000_000_000_000)}}, accepting: true}
	for i := range chain.recognition.Record.MinterCodeHash {
		chain.recognition.Record.MinterCodeHash[i] = 0xcd
	}
	f.manifest, f.digest = raw, digest
	f.hints.manifests[digest] = raw
	f.offers.config.ActorCodeHash = chain.account.CodeHash
	f.offers.config.Sessions = chain
	f.offers.config.TokenPins = []toschain.TokenAssetPin{{Master: master.Text(), WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(hash[:]), Decimals: 6}}
	k := buyersdk.TokenAssetBudgetKey(master.Text(), "tvm-cell-sha256:"+hex.EncodeToString(hash[:]), 6)
	f.offers.config.TokenAssets = map[string]buyersdk.TokenAssetLimits{k: {MaxPerCallAtomic: big.NewInt(1_000_000_000), MaxWindowAtomic: big.NewInt(10_000_000_000)}}
	return f, chain
}
func TestTokenLocalQuoteKeepsAssetAtomicPriceAndOneCheckpoint(t *testing.T) {
	f, c := tokenOffersFixture(t)
	request, pkg, view, err := f.offers.Quote(context.Background(), localParams())
	if err != nil {
		t.Fatal(err)
	}
	if c.opened() != 1 || view.Offer.Asset == nil || view.Offer.PriceAtomic != "300000000" || view.Offer.PriceNanoTOS != "" || view.Offer.PaymentNanoTOS != "" {
		t.Fatalf("offer=%+v sessions=%d", view.Offer, c.opened())
	}
	if _, err := validatePortableQuote(servicefixture.Network(), request, pkg); err != nil {
		t.Fatal(err)
	}
	if _, err = f.agent.StoreQuote(request, pkg); err != nil {
		t.Fatal(err)
	}
	pkg.Proposal.PriceAtomic = "299999999"
	validated, err := validatePortableQuote(servicefixture.Network(), request, pkg)
	if err != nil {
		t.Fatal(err)
	}
	offer := &serviceactorindex.Offer{CapabilityID: fxCapability, CapabilityVersion: "1.0.0", ProviderAgentID: fxProvider, ManifestDigest: f.digest, Actor: fxActor, ActorCodeHash: c.account.CodeHash, AttestorKeyID: pkg.Proposal.AttestorKeyId, PolicyVersion: pkg.Proposal.PolicyVersion, TermsHash: pkg.Proposal.TermsHash, Asset: pkg.Proposal.Asset, PriceAtomic: "300000000", StorageFeeNanoTOS: pkg.Proposal.StorageFeeNanotos}
	if err := crossCheckQuote(validated, offer); err == nil {
		t.Fatal("changed atomic price accepted")
	}
}
func TestTokenQuoteRefusesUnbudgetedSuspendedUnpinnedAndNonAccepting(t *testing.T) {
	for _, which := range []string{"budget", "suspended", "pin", "accepting"} {
		t.Run(which, func(t *testing.T) {
			f, c := tokenOffersFixture(t)
			switch which {
			case "budget":
				f.offers.config.TokenAssets = nil
			case "suspended":
				c.recognition.Record.Status = 2
			case "pin":
				f.offers.config.TokenPins = nil
			case "accepting":
				c.accepting = false
			}
			if _, _, _, err := f.offers.Quote(context.Background(), localParams()); err == nil {
				t.Fatal("unsafe token quote accepted")
			}
		})
	}
}
