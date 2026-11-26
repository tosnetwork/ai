package quoteprovider

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

type tokenSource struct {
	session *tokenProviderSession
	opens   int
}

func (s *tokenSource) BeginSession(context.Context) (serviceactor.Session, error) {
	s.opens++
	return s.session, nil
}

type tokenProviderSession struct {
	session
	token       *toschain.TokenActorAccount
	recognition *toschain.TokenAssetRecognition
	accepting   bool
	pinsSeen    []toschain.TokenAssetPin
}

func (s *tokenProviderSession) ResolveRegistry(ctx context.Context, id string) (*nativev1.NativeStateV1, bool, error) {
	if id == s.a.state.GetCapability().OwnerAgentId {
		return &nativev1.NativeStateV1{Network: proto.Clone(s.a.state.Network).(*nativev1.NetworkDomain), Reference: proto.Clone(s.a.state.Reference).(*nativev1.ChainReference), State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: id}}}, true, nil
	}
	return s.session.ResolveRegistry(ctx, id)
}
func (s *tokenProviderSession) ReadTokenActor(context.Context, string) (*toschain.TokenActorAccount, bool, error) {
	return s.token, true, nil
}
func (s *tokenProviderSession) ReadTokenAsset(_ context.Context, _ string, pins []toschain.TokenAssetPin) (*toschain.TokenAssetRecognition, error) {
	s.pinsSeen = pins
	if len(pins) == 0 {
		return nil, errors.New("unpinned asset")
	}
	return s.recognition, nil
}
func (s *tokenProviderSession) GetTokenAcceptingTokens(context.Context, string) (bool, error) {
	return s.accepting, nil
}
func tokenProviderFixture(t *testing.T) (*Provider, *tokenSource, *nativev1.RequestQuoteProposalRequest) {
	t.Helper()
	p, a, request, network, _ := setup(t)
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(p.config.ManifestCBOR)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Settlement.Rail = nativecore.ServiceActorTokenRail
	code := nativecore.ServiceActorTokenReleaseCodeHash
	manifest.Settlement.ActorCodeHash = code[:]
	key := bytes.Repeat([]byte{0x5a}, mldsa44.PublicKeySize)
	keyID, err := mldsa44.KeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Settlement.AttestorKey = mldsa44.KeyIDText(keyID)
	manifest.ExecutionSignerAuthorization = nativecore.SettlementAttestorAuthorization(manifest.Settlement.AttestorKey)
	walletCode := cell.BeginCell().MustStoreUInt(1, 8).EndCell()
	var walletHash [32]byte
	copy(walletHash[:], walletCode.Hash())
	masterID := bytes.Repeat([]byte{0xab}, 32)
	decimal := uint8(6)
	manifest.SupportedAssets = []nativecore.SoftwareWorkAssetV1{{Kind: nativecore.TOSTokenAsset, MasterAccountID: masterID, WalletCodeHash: walletHash[:], Decimals: &decimal}}
	raw, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	a.state.GetCapability().Versions[0].ManifestDigest = digest
	policy := a.policy
	policy.AttestorKey = key
	policy.AttestorKeyID = keyID
	policy.MetadataHash, err = nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: network, CapabilityID: request.CapabilityId, ProviderAgentID: p.config.ProviderAgentID, CapabilityVersion: p.version, ManifestDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	master, err := nativecore.StandardAddress("0:" + hex.EncodeToString(masterID))
	if err != nil {
		t.Fatal(err)
	}
	route := nativecore.ServiceActorTokenAssetRouteV1{Master: master, WalletCode: walletCode, WalletCodeHash: walletHash, BridgeConfigParam: 79}
	root, err := nativecore.BuildServiceActorTokenInitialData("0:"+strings.Repeat("11", 32), nativecore.ServiceActorTokenPolicyV1{ServiceActorPolicyV1: policy, MaxTokenLiability: big.NewInt(1_000_000_000_000)}, route)
	if err != nil {
		t.Fatal(err)
	}
	data, err := nativecore.DecodeServiceActorTokenData(root)
	if err != nil {
		t.Fatal(err)
	}
	data.Active = true
	actor := "0:" + hex.EncodeToString(manifest.Settlement.ActorAccountID)
	own, err := nativecore.DeriveServiceActorTokenWallet(actor, route)
	if err != nil {
		t.Fatal(err)
	}
	s := &tokenProviderSession{session: session{a}, token: &toschain.TokenActorAccount{Address: actor, CodeHash: "tvm-cell-sha256:" + hex.EncodeToString(code[:]), Data: data, OwnWallet: own, BalanceNano: 2_000_000_000}, recognition: &toschain.TokenAssetRecognition{Checkpoint: 10, Record: toschain.SettlementAssetV1{Master: master.Text(), Status: 1, Decimals: 6, WalletCodeHash: walletHash, MaxLiabilityPerActor: big.NewInt(1_000_000_000_000)}}, accepting: true}
	for i := range s.recognition.Record.MinterCodeHash {
		s.recognition.Record.MinterCodeHash[i] = 0xcd
	}
	source := &tokenSource{session: s}
	config := p.config
	config.Sessions = source
	config.ManifestCBOR = raw
	config.TokenPins = []toschain.TokenAssetPin{{Master: master.Text(), WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(walletHash[:]), Decimals: 6}}
	p, err = New(config)
	if err != nil {
		t.Fatal(err)
	}
	return p, source, request
}
func TestTokenProviderDerivesAssetAndPriceAtOneCheckpoint(t *testing.T) {
	p, s, r := tokenProviderFixture(t)
	value, err := p.RequestQuoteProposal(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = quoteexchange.ValidateToken(p.config.Network, r, value, p.config.Now()); err != nil {
		t.Fatal(err)
	}
	if s.opens != 1 || len(s.session.pinsSeen) != 1 || value.Proposal.PriceAtomic != "300000000" || value.Proposal.PriceNanotos != "" || value.Proposal.Asset.Decimals != 6 || value.Proposal.Asset.Master.CodeHash != "tvm-cell-sha256:"+strings.Repeat("cd", 32) {
		t.Fatalf("proposal=%+v opens=%d", value.Proposal, s.opens)
	}
}
func TestTokenProviderRefusesSuspendedUnpinnedAndNotAccepting(t *testing.T) {
	for _, which := range []string{"suspended", "no pin", "not accepting", "checkpoint"} {
		t.Run(which, func(t *testing.T) {
			p, s, r := tokenProviderFixture(t)
			switch which {
			case "suspended":
				s.session.recognition.Record.Status = 2
			case "no pin":
				p.config.TokenPins = nil
			case "not accepting":
				s.session.accepting = false
			case "checkpoint":
				s.session.recognition.Checkpoint++
			}
			if _, err := p.RequestQuoteProposal(context.Background(), r); err == nil {
				t.Fatal("unsafe token Quote served")
			}
		})
	}
}
