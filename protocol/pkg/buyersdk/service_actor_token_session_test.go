package buyersdk

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

type tokenBuildSessionFixture struct {
	snapshot    TokenBuildSnapshot
	drift       string
	reads       int
	recognition bool
}

func (s *tokenBuildSessionFixture) Checkpoint() uint64 {
	if s.reads > 0 && s.drift == "sequence" {
		return uint64(s.snapshot.ReadAt.Seqno) + 1
	}
	return uint64(s.snapshot.ReadAt.Seqno)
}
func (s *tokenBuildSessionFixture) ChainTime() time.Time {
	v := int64(s.snapshot.ReadAt.GenUtime)
	if s.reads > 0 && s.drift == "time" {
		v++
	}
	return time.Unix(v, 0)
}
func (s *tokenBuildSessionFixture) BlockHashes() (string, string) {
	v := "sha256:" + s.snapshot.ReadAt.RootHash
	if s.reads > 0 && s.drift == "root" {
		v = "sha256:changed"
	}
	return v, "sha256:file"
}
func (s *tokenBuildSessionFixture) ResolveTokenActor(_ context.Context, _ string, _ []toschain.TokenAssetPin, recognition bool) (*toschain.ResolvedTokenActor, error) {
	s.recognition = recognition
	r, f := s.BlockHashes()
	var recognized *toschain.TokenAssetRecognition
	if recognition && s.snapshot.Asset != nil {
		a := s.snapshot.Asset
		recognized = &toschain.TokenAssetRecognition{Record: toschain.SettlementAssetV1{Master: s.snapshot.AssetPin.Master, Status: a.Status, WalletCodeHash: a.WalletCodeHash, Decimals: a.Decimals, MaxLiabilityPerActor: a.MaxLiabilityPerActor}}
	}
	return &toschain.ResolvedTokenActor{Recognition: recognized, Account: &toschain.TokenActorAccount{Address: s.snapshot.Actor, CodeHash: "tvm-cell-sha256:" + hex.EncodeToString(nativecore.ServiceActorTokenTestProfileCodeHash[:]), BalanceNano: s.snapshot.Balance.Uint64(), Data: s.snapshot.Data, OwnWallet: s.snapshot.OwnWallet}, Checkpoint: s.Checkpoint(), BlockRoot: r, BlockFile: f}, nil
}
func (s *tokenBuildSessionFixture) GetTokenFundingPrices(context.Context, string) ([6]*big.Int, error) {
	s.reads++
	return s.snapshot.FundingPrices, nil
}
func (s *tokenBuildSessionFixture) GetTokenAcceptingTokens(context.Context, string) (bool, error) {
	return true, nil
}
func (s *tokenBuildSessionFixture) ReadTokenWalletTerms(context.Context, uint32) (toschain.TokenWalletTerms, error) {
	return toschain.TokenWalletTerms{GasConsumption: s.snapshot.WalletTerms.GasConsumption, MinimumStorage: s.snapshot.WalletTerms.MinimumStorage}, nil
}
func (s *tokenBuildSessionFixture) ReadTokenForwardPrices(context.Context) (toschain.TokenForwardPrices, error) {
	p := s.snapshot.ForwardPrices
	return toschain.TokenForwardPrices{LumpPrice: p.LumpPrice, BitPrice: p.BitPrice, CellPrice: p.CellPrice, FirstFraction: p.FirstFraction}, nil
}
func (s *tokenBuildSessionFixture) ReadTokenGlobalID(context.Context) (int32, error) { return 0, nil }
func (s *tokenBuildSessionFixture) ReadTokenWallet(context.Context, string, nativecore.ServiceActorTokenAssetRouteV1) (*toschain.TokenWalletAccount, bool, error) {
	return &toschain.TokenWalletAccount{BalanceAtomic: s.snapshot.SenderTokenBalance}, true, nil
}

func TestTokenAtSessionRejectsCheckpointDrift(t *testing.T) {
	snapshot, request := loadTokenFixture(t, "revoke-attestor")
	for _, drift := range []string{"", "sequence", "time", "root"} {
		t.Run(drift, func(t *testing.T) {
			s := &tokenBuildSessionFixture{snapshot: snapshot, drift: drift}
			result, err := PrepareTokenAtSession(context.Background(), s, snapshot.Actor, nil, request, nil)
			if drift != "" {
				if err == nil {
					t.Fatal("mixed-checkpoint build was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Operation != request.Operation || result.ReadAt.Seqno != snapshot.ReadAt.Seqno || s.reads != 1 || s.recognition {
				t.Fatal("adapter did not use one payout snapshot")
			}
		})
	}
}

func TestTokenAtSessionCallUsesRecognitionAndWalletAtCheckpoint(t *testing.T) {
	snapshot, request := loadTokenFixture(t, "call")
	// The pinned CLI fixture supplies a getter hash independently from its policy;
	// the live adapter derives the hash from the actual typed state instead.
	terms, err := nativecore.ServiceActorTokenTermsHash(nativecore.TokenTermsOfPolicy(snapshot.Data.Policy, snapshot.Data.Route))
	if err != nil {
		t.Fatal(err)
	}
	request.ExpectedTermsHash = terms
	s := &tokenBuildSessionFixture{snapshot: snapshot}
	pin := toschain.TokenAssetPin{Master: snapshot.AssetPin.Master, WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(snapshot.AssetPin.WalletCodeHash[:]), Decimals: snapshot.AssetPin.Decimals}
	result, err := PrepareTokenAtSession(context.Background(), s, snapshot.Actor, []toschain.TokenAssetPin{pin}, request, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Operation != "call" || !s.recognition || s.reads != 1 {
		t.Fatal("call did not resolve its recognized asset in the same session")
	}
	pin.Decimals++
	if _, err = PrepareTokenAtSession(context.Background(), &tokenBuildSessionFixture{snapshot: snapshot}, snapshot.Actor, []toschain.TokenAssetPin{pin}, request, nil); err == nil {
		t.Fatal("independent client pin mismatch was accepted")
	}
}

func TestTokenAtSessionRejectsNilSession(t *testing.T) {
	var session *toschain.ServiceActorSession
	if _, err := PrepareTokenAtSession(context.Background(), session, "", nil, TokenBuildRequest{}, nil); err == nil {
		t.Fatal("typed nil session accepted")
	}
}
