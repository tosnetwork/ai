package serviceactor

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func tokenBindingFixture(t *testing.T) (*TokenEvidence, *nativev1.QuoteProposalV1, nativecore.ServiceActorTokenQuoteRailV1, toschain.TokenActorTransaction) {
	t.Helper()
	code := nativecore.ServiceActorTokenReleaseCodeHash
	f := newFixtureFor(t, testCode, 3600, 3600)
	f.evidence.Manifest.Settlement.ActorCodeHash = code[:]
	f.evidence.Actor.CodeHash = "tvm-cell-sha256:" + hex.EncodeToString(code[:])
	f.proposal.ActorCodeHash = f.evidence.Actor.CodeHash
	walletCode := cell.BeginCell().MustStoreUInt(1, 8).EndCell()
	var walletHash [32]byte
	copy(walletHash[:], walletCode.Hash())
	master := msgAddress(t, "0:"+strings.Repeat("ab", 32))
	decimal := uint8(6)
	f.evidence.Manifest.Settlement.Rail = nativecore.ServiceActorTokenRail
	f.evidence.Manifest.SupportedAssets = []nativecore.SoftwareWorkAssetV1{{Kind: nativecore.TOSTokenAsset, MasterAccountID: mustTokenMaster(t, master), WalletCodeHash: walletHash[:], Decimals: &decimal}}
	f.rehashManifest(t)
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: f.evidence.Network, CapabilityID: testCapability, ProviderAgentID: testOwnerAgent, CapabilityVersion: f.evidence.Version, ManifestDigest: f.evidence.ManifestDigest})
	if err != nil {
		t.Fatal(err)
	}
	policy := nativecore.ServiceActorTokenPolicyV1{ServiceActorPolicyV1: f.evidence.Actor.Data.Policy, MaxTokenLiability: big.NewInt(1000000000000)}
	policy.MetadataHash = metadata
	route := nativecore.ServiceActorTokenAssetRouteV1{Master: master, WalletCodeHash: walletHash, WalletCode: walletCode, BridgeConfigParam: 79}
	root, err := nativecore.BuildServiceActorTokenInitialData(testOwner, policy, route)
	if err != nil {
		t.Fatal(err)
	}
	data, err := nativecore.DecodeServiceActorTokenData(root)
	if err != nil {
		t.Fatal(err)
	}
	data.Active = true
	own, err := nativecore.DeriveServiceActorTokenWallet(testActor, route)
	if err != nil {
		t.Fatal(err)
	}
	account := &toschain.TokenActorAccount{Address: testActor, CodeHash: f.evidence.Actor.CodeHash, OwnWallet: own, BalanceNano: 2000000000, Data: data}
	e := &TokenEvidence{Evidence: *f.evidence, Actor: account, Recognition: &toschain.TokenAssetRecognition{Checkpoint: 42, Record: toschain.SettlementAssetV1{Master: master.Text(), Status: 1, Decimals: 6, WalletCodeHash: walletHash, MaxLiabilityPerActor: big.NewInt(1000000000000)}}}
	f.proposal.PriceAtomic = f.proposal.PriceNanotos
	f.proposal.PriceNanotos = ""
	f.proposal.Asset = &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{AccountId: mustTokenMaster(t, master), CodeHash: "tvm-cell-sha256:" + strings.Repeat("cd", 32)}, WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(walletHash[:]), Decimals: 6}
	for i := range e.Recognition.Record.MinterCodeHash {
		e.Recognition.Record.MinterCodeHash[i] = 0xcd
	}
	terms := nativecore.ServiceActorTokenTermsV1{ServiceActorTermsV1: nativecore.TermsOfPolicy(policy.ServiceActorPolicyV1), AssetWalletCodeHash: walletHash}
	copy(terms.AssetMasterHash[:], mustTokenMaster(t, master))
	tc, err := nativecore.BuildServiceActorTokenTerms(terms)
	if err != nil {
		t.Fatal(err)
	}
	f.proposal.TermsHash = hex.EncodeToString(tc.Hash())
	rail, err := nativecore.ParseServiceActorTokenQuoteRail(f.proposal)
	if err != nil {
		t.Fatal(err)
	}
	var termsHash [32]byte
	copy(termsHash[:], tc.Hash())
	snap := nativecore.ServiceActorTokenRequestSnapshotV1{RequestID: 1, Caller: msgAddress(t, testBuyer), RequestHash: testRequest, ResponseDeadline: 1000000 + 3600, RefundClaimDeadline: 1000000 + 7200, TermsHash: termsHash, Terms: terms}
	call := toschain.TokenActorTransaction{LT: 100, Hash: strings.Repeat("aa", 32), Now: 1000000, TookEffect: true, Sender: own, Notification: &toschain.TokenActorNotification{From: testBuyer, AmountAtomic: policy.PricePerCall.String(), Payload: &nativecore.TokenCallPayloadV1{RequestHash: testRequest, ExpectedTermsHash: termsHash}}, Logs: []nativecore.ServiceActorTokenLogV1{{Snapshot: &snap}}}
	return e, f.proposal, rail, call
}
func mustTokenMaster(t *testing.T, a nativecore.MsgAddressV1) []byte {
	t.Helper()
	raw := strings.TrimPrefix(a.Text(), "0:")
	b, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTokenAdmissionChecksPinnedAssetAndCheckpoint(t *testing.T) {
	e, p, r, _ := tokenBindingFixture(t)
	if _, err := VerifyTokenAdmission(e, nativecore.ServiceActorTokenReleaseCodeHash, &r, p, testBuyer); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*TokenEvidence){
		"status":        func(e *TokenEvidence) { e.Recognition.Record.Status = 2 },
		"master":        func(e *TokenEvidence) { e.Recognition.Record.Master = testBuyer },
		"wallet":        func(e *TokenEvidence) { e.Recognition.Record.WalletCodeHash[0] ^= 1 },
		"decimals":      func(e *TokenEvidence) { e.Recognition.Record.Decimals = 9 },
		"checkpoint":    func(e *TokenEvidence) { e.Recognition.Checkpoint = 43 },
		"inactive":      func(e *TokenEvidence) { e.Actor.Data.Active = false },
		"owner-network": func(e *TokenEvidence) { e.Agent.Network = nil },
	} {
		t.Run(name, func(t *testing.T) {
			e, p, r, _ := tokenBindingFixture(t)
			edit(e)
			if _, err := VerifyTokenAdmission(e, nativecore.ServiceActorTokenReleaseCodeHash, &r, p, testBuyer); err == nil {
				t.Fatal("mismatched token admission accepted")
			}
		})
	}
}
func TestTokenExistingUsesSnapshotDespiteCurrentSuspensionAndPolicy(t *testing.T) {
	e, p, r, call := tokenBindingFixture(t)
	e.Recognition.Record.Status = 2
	e.Actor.Data.Active = false
	e.Actor.Data.Policy.PricePerCall = big.NewInt(99)
	e.Actor.Data.Policy.MetadataHash = [32]byte{}
	if _, err := VerifyTokenExistingRequest(e, nativecore.ServiceActorTokenReleaseCodeHash, &r, p, call, testBuyer, testRequest, tokenAcceptanceFor(call)); err != nil {
		t.Fatal(err)
	}
	// A changed snapshot or unauthenticated notification cannot inherit that rule.
	call.Logs[0].Snapshot.Terms.AssetWalletCodeHash[0] ^= 1
	if _, err := VerifyTokenExistingRequest(e, nativecore.ServiceActorTokenReleaseCodeHash, &r, p, call, testBuyer, testRequest, tokenAcceptanceFor(call)); err == nil {
		t.Fatal("forged immutable terms accepted")
	}
}
func TestTokenExistingRefusesMalformedPublicRailWithoutPanic(t *testing.T) {
	e, p, r, call := tokenBindingFixture(t)
	r.PriceAtomic = nil
	if _, err := VerifyTokenExistingRequest(e, nativecore.ServiceActorTokenReleaseCodeHash, &r, p, call, testBuyer, testRequest, tokenAcceptanceFor(call)); err == nil {
		t.Fatal("nil amount accepted")
	}
}

func tokenAcceptanceFor(call toschain.TokenActorTransaction) *Acceptance {
	return &Acceptance{Call: toschain.ActorTxID{LT: call.LT, Hash: call.Hash}}
}

// TestTokenExistingBindsTheAcceptanceProofToTheCall requires, as the native
// rail does, a liveness proof for exactly this call. A proof for an earlier
// call would let a revocation between the two calls pass.
func TestTokenExistingBindsTheAcceptanceProofToTheCall(t *testing.T) {
	verify := func(e *TokenEvidence, p *nativev1.QuoteProposalV1, r nativecore.ServiceActorTokenQuoteRailV1, call toschain.TokenActorTransaction, acceptance ...*Acceptance) error {
		_, err := VerifyTokenExistingRequest(e, nativecore.ServiceActorTokenReleaseCodeHash, &r, p, call, testBuyer, testRequest, acceptance...)
		return err
	}
	e, p, r, call := tokenBindingFixture(t)
	earlier := &Acceptance{Call: toschain.ActorTxID{LT: call.LT - 50, Hash: strings.Repeat("bb", 32)}}
	for name, acceptance := range map[string][]*Acceptance{
		"absent":       nil,
		"nil":          {nil},
		"two":          {tokenAcceptanceFor(call), tokenAcceptanceFor(call)},
		"earlier call": {earlier},
		"same LT":      {{Call: toschain.ActorTxID{LT: call.LT, Hash: strings.Repeat("bb", 32)}}},
		"same hash":    {{Call: toschain.ActorTxID{LT: call.LT + 1, Hash: call.Hash}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verify(e, p, r, call, acceptance...); err == nil {
				t.Fatal("a liveness proof for another call was accepted")
			}
		})
	}
	// The version is revoked between the earlier call and this one.
	var version *nativev1.CapabilityVersionV1
	for _, v := range e.Capability.GetCapability().Versions {
		if v.Version == e.Version {
			version = v
		}
	}
	if version == nil {
		t.Fatal("fixture version missing")
	}
	version.Revoked = true
	revocation := &toschain.RegistryTransitionTx{LT: call.LT - 20, Hash: strings.Repeat("cc", 32)}
	earlier.VersionRevocation = revocation
	if err := verify(e, p, r, call, earlier); err == nil {
		t.Fatal("a proof for an earlier call admitted a call after the revocation")
	}
	before := tokenAcceptanceFor(call)
	before.VersionRevocation = revocation
	if err := verify(e, p, r, call, before); err == nil {
		t.Fatal("a call after the revocation was admitted")
	}
	after := tokenAcceptanceFor(call)
	after.VersionRevocation = &toschain.RegistryTransitionTx{LT: call.LT + 20, Hash: strings.Repeat("cc", 32)}
	if err := verify(e, p, r, call, after); err != nil {
		t.Fatalf("a revocation after the call refused the existing request: %v", err)
	}
}

func TestOtherAssetNotificationCannotFundThePinnedActor(t *testing.T) {
	e, p, r, call := tokenBindingFixture(t)
	// Same release, decimals, buyer, amount and payload; only the asset master
	// differs. Derive its wallet for this actor instead of inventing a sender.
	other := e.Actor.Data.Route
	other.Master = msgAddress(t, "0:"+strings.Repeat("ac", 32))
	otherWallet, err := nativecore.DeriveServiceActorTokenWallet(testActor, other)
	if err != nil {
		t.Fatal(err)
	}
	if otherWallet == e.Actor.OwnWallet {
		t.Fatal("distinct assets share a wallet")
	}
	if _, err = VerifyTokenExistingRequest(e, nativecore.ServiceActorTokenReleaseCodeHash, &r, p, call, testBuyer, testRequest, tokenAcceptanceFor(call)); err != nil {
		t.Fatal(err)
	}
	call.Sender = otherWallet
	if _, err = VerifyTokenExistingRequest(e, nativecore.ServiceActorTokenReleaseCodeHash, &r, p, call, testBuyer, testRequest, tokenAcceptanceFor(call)); err == nil || !strings.Contains(err.Error(), "funding notification is not authenticated") {
		t.Fatalf("foreign notification admitted: %v", err)
	}
	// An ordinary foreign notification has no SAT1 and creates no request. Even
	// attaching a forged SAT1 cannot turn it into this actor's accepted call.
	foreign := call
	foreign.Kind = "notification"
	foreign.Logs = nil
	history := &toschain.TokenActorHistory{Result: toschain.HistoryComplete, Head: e.Actor.LastTransaction, Transactions: []toschain.TokenActorTransaction{foreign}}
	requests, err := ReplayTokenRequests(e.Actor, history, time.Unix(int64(call.Now), 0))
	if err != nil || len(requests) != 0 {
		t.Fatalf("foreign notification created a request: %v %v", requests, err)
	}
}
