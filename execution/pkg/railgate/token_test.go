package railgate

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type tokenFX struct {
	*fxSession
	account    *toschain.TokenActorAccount
	tx         toschain.TokenActorTransaction
	incomplete bool
	begins     int
}

func (s *tokenFX) BeginSession(context.Context) (Session, error) { s.begins++; return s, nil }
func (s *tokenFX) ReadTokenActor(context.Context, string) (*toschain.TokenActorAccount, bool, error) {
	return s.account, true, nil
}
func (s *tokenFX) ReadTokenAsset(context.Context, string, []toschain.TokenAssetPin) (*toschain.TokenAssetRecognition, error) {
	return nil, errors.New("existing liability must not depend on new admission recognition")
}
func (s *tokenFX) TokenHistory(context.Context, string, *toschain.ActorTxID) (*toschain.TokenActorHistory, error) {
	result := toschain.HistoryComplete
	if s.incomplete {
		result = toschain.HistoryAnchorReached
	}
	return &toschain.TokenActorHistory{Result: result, Head: s.account.LastTransaction, Transactions: []toschain.TokenActorTransaction{s.tx}}, nil
}

func tokenFixture(t *testing.T) (*Verifier, Claim, *tokenFX) {
	t.Helper()
	f := newFixture(t)
	raw, err := f.chain.BeginSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := &tokenFX{fxSession: raw.(*fxSession)}
	m := fxManifest()
	m.Settlement.Rail = nativecore.ServiceActorTokenRail
	code := nativecore.ServiceActorTokenTestProfileCodeHash
	m.Settlement.ActorCodeHash = code[:]
	master, err := nativecore.StandardAddress("0:" + strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	walletCode := cell.BeginCell().MustStoreUInt(1, 8).EndCell()
	var walletHash [32]byte
	copy(walletHash[:], walletCode.Hash())
	decimals := uint8(6)
	m.SupportedAssets = []nativecore.SoftwareWorkAssetV1{{Kind: nativecore.TOSTokenAsset, MasterAccountID: master.Address, WalletCodeHash: walletHash[:], Decimals: &decimals}}
	encoded, digest, err := nativecore.CanonicalSoftwareWorkManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: fxNetwork, CapabilityID: fxCapability, ProviderAgentID: fxAgent, CapabilityVersion: "1.0.0", ManifestDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	terms := nativecore.ServiceActorTokenTermsV1{ServiceActorTermsV1: fxTerms(metadata), AssetWalletCodeHash: walletHash}
	copy(terms.AssetMasterHash[:], master.Address)
	tc, err := nativecore.BuildServiceActorTokenTerms(terms)
	if err != nil {
		t.Fatal(err)
	}
	var th [32]byte
	copy(th[:], tc.Hash())
	p := f.pkg.Proposal
	p.ManifestDigest = digest
	p.ActorCodeHash = "tvm-cell-sha256:" + hex.EncodeToString(code[:])
	p.TermsHash = hex.EncodeToString(th[:])
	p.PriceAtomic = p.PriceNanotos
	p.PriceNanotos = ""
	p.Asset = &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{AccountId: master.Address, CodeHash: "tvm-cell-sha256:" + strings.Repeat("ef", 32)}, WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(walletHash[:]), Decimals: 6}
	f.pkg.CanonicalManifestCbor = encoded
	quote, _, err := nativecore.BuildAcceptedTokenQuoteCommitment(fxNetwork, p)
	if err != nil {
		t.Fatal(err)
	}
	var qh [32]byte
	copy(qh[:], quote.Hash())
	request, err := nativecore.BuildServiceRequestCellV1(nativecore.ServiceRequestV1{QuoteCommitment: qh, ExecutionID: f.claim.ExecutionID, InputDigest: f.claim.InputDigest})
	if err != nil {
		t.Fatal(err)
	}
	var rh [32]byte
	copy(rh[:], request.Hash())
	now := uint32(fxNow.Unix()) - 100
	snap := nativecore.ServiceActorTokenRequestSnapshotV1{RequestID: 0, Caller: f.snapshot.Caller, RequestHash: rh, TermsHash: th, Terms: terms, ResponseDeadline: uint64(now) + uint64(terms.ResponseSLA), RefundClaimDeadline: uint64(now) + uint64(terms.ResponseSLA) + uint64(terms.RefundClaimWindow)}
	policy := f.policy
	policy.MetadataHash = metadata
	route := nativecore.ServiceActorTokenAssetRouteV1{Master: master, WalletCodeHash: walletHash, WalletCode: walletCode, BridgeConfigParam: 79}
	dataCell, err := nativecore.BuildServiceActorTokenInitialData(fxOwner, nativecore.ServiceActorTokenPolicyV1{ServiceActorPolicyV1: policy, MaxTokenLiability: big.NewInt(1000000000000)}, route)
	if err != nil {
		t.Fatal(err)
	}
	data, err := nativecore.DecodeServiceActorTokenData(dataCell)
	if err != nil {
		t.Fatal(err)
	}
	nd := fxData(t, policy, 1, map[uint64]nativecore.ServiceActorRequestSnapshotV1{0: {RequestID: 0, Caller: snap.Caller, RequestHash: rh, TermsHash: th, Terms: terms.ServiceActorTermsV1, ResponseDeadline: snap.ResponseDeadline, RefundClaimDeadline: snap.RefundClaimDeadline}}, nil)
	data.Active = true
	data.NextRequestID = 1
	data.Pending = nd.Pending
	data.PendingCount = 1
	data.LiveCount = 1
	own, err := nativecore.DeriveServiceActorTokenWallet(fxActor, route)
	if err != nil {
		t.Fatal(err)
	}
	s.account = &toschain.TokenActorAccount{Address: fxActor, CodeHash: p.ActorCodeHash, OwnWallet: own, Data: data, LastTransaction: f.claim.Call}
	s.tx = toschain.TokenActorTransaction{LT: f.call.LT, Hash: f.call.Hash, Now: now, TookEffect: true, Kind: toschain.ActorTxCall, Sender: own, Notification: &toschain.TokenActorNotification{From: fxBuyer, AmountAtomic: p.PriceAtomic, Payload: &nativecore.TokenCallPayloadV1{RequestHash: rh, ExpectedTermsHash: th}}, Logs: []nativecore.ServiceActorTokenLogV1{{Snapshot: &snap}}}
	s.capability.GetCapability().Versions[0].ManifestDigest = digest
	v, err := NewVerifier(VerifierConfig{Reader: s, TokenPins: []toschain.TokenAssetPin{{Master: master.Text(), WalletCodeHash: p.Asset.WalletCodeHash, MinterCodeHash: p.Asset.Master.CodeHash, Decimals: 6}}, CheckExecution: func(context.Context, Session) error { return nil }, Manifests: fxManifests{digest: encoded}, Network: fxNetwork, ActorCodeHash: p.ActorCodeHash, ProviderAgentID: fxAgent, CapabilityID: fxCapability, Version: "1.0.0", ExecutionBudget: 180 * time.Second, RespondBudget: 120 * time.Second, Now: func() time.Time { return fxNow }})
	if err != nil {
		t.Fatal(err)
	}
	return v, f.claim, s
}

func TestTokenGateProvesTheRequestAndRechecksItsExecutionGuard(t *testing.T) {
	v, c, s := tokenFixture(t)
	got, err := v.Verify(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if got.AssetMaster == nil || got.Price.String() != "300000000" || s.begins != 1 {
		t.Fatalf("verified %+v, sessions %d", got, s.begins)
	}
	v.config.CheckExecution = func(context.Context, Session) error { return errors.New("asset alarm") }
	if err = v.Recheck(context.Background(), c, got); err == nil {
		t.Fatal("alarmed execution passed recheck")
	}
}
func TestTokenGateRefusesUnprovenOrChangedRequests(t *testing.T) {
	for name, edit := range map[string]func(*Verifier, *Claim, *tokenFX){
		"missing safety guard":    func(v *Verifier, _ *Claim, _ *tokenFX) { v.config.CheckExecution = nil },
		"unrecognized pin":        func(v *Verifier, _ *Claim, _ *tokenFX) { v.config.TokenPins[0].Decimals++ },
		"incomplete history":      func(_ *Verifier, _ *Claim, s *tokenFX) { s.incomplete = true },
		"different exact call":    func(_ *Verifier, c *Claim, _ *tokenFX) { c.Call.LT++ },
		"unfunded request":        func(_ *Verifier, _ *Claim, s *tokenFX) { s.tx.TookEffect = false },
		"wrong sender":            func(_ *Verifier, _ *Claim, s *tokenFX) { s.tx.Sender = fxBuyer },
		"wrong atomic amount":     func(_ *Verifier, _ *Claim, s *tokenFX) { s.tx.Notification.AmountAtomic = "1" },
		"response window elapsed": func(_ *Verifier, _ *Claim, s *tokenFX) { s.chainTime = fxNow.Add(24 * time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			v, c, s := tokenFixture(t)
			edit(v, &c, s)
			if _, err := v.Verify(context.Background(), c); err == nil {
				t.Fatal("unproven token request admitted")
			}
		})
	}
}
