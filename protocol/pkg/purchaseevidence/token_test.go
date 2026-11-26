package purchaseevidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/servicefixture"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

type tokenEvidenceFixture struct {
	network *nativev1.NetworkDomain
	account *toschain.TokenActorAccount
	history *toschain.TokenActorHistory
	states  map[string]*nativev1.NativeStateV1
	wallets map[string]*toschain.TokenWalletHistory
	bundle  *TokenBundle
	pins    []toschain.TokenAssetPin
	now     time.Time
	reads   []string
	// walletBound is the anchored walk's bound (0: the production 10,000);
	// walletVisited counts wallet transactions the walks passed or returned.
	walletBound   int
	walletVisited int
}

func (s *tokenEvidenceFixture) Checkpoint() uint64   { return 42 }
func (s *tokenEvidenceFixture) ChainTime() time.Time { return s.now }
func (s *tokenEvidenceFixture) BlockHashes() (string, string) {
	return strings.Repeat("a", 64), strings.Repeat("b", 64)
}
func (s *tokenEvidenceFixture) ReadTokenActor(_ context.Context, a string) (*toschain.TokenActorAccount, bool, error) {
	s.reads = append(s.reads, "actor@42")
	return s.account, a == s.account.Address, nil
}
func (s *tokenEvidenceFixture) TokenHistory(_ context.Context, a string, _ *toschain.ActorTxID) (*toschain.TokenActorHistory, error) {
	s.reads = append(s.reads, "history@42")
	return s.history, nil
}
func (s *tokenEvidenceFixture) ResolveRegistry(_ context.Context, id string) (*nativev1.NativeStateV1, bool, error) {
	s.reads = append(s.reads, "registry@42")
	v, ok := s.states[id]
	return v, ok, nil
}
func (s *tokenEvidenceFixture) RegistryTransition(context.Context, string, nativecore.RegistryTransitionKind, string) (*toschain.RegistryTransitionTx, error) {
	return nil, toschain.ErrRegistryTransitionUnproven
}
func (s *tokenEvidenceFixture) ReadTokenAsset(context.Context, string, []toschain.TokenAssetPin) (*toschain.TokenAssetRecognition, error) {
	return nil, errors.New("existing liabilities must not read current recognition")
}
func (s *tokenEvidenceFixture) ReadTokenWallet(_ context.Context, owner string, route nativecore.ServiceActorTokenAssetRouteV1) (*toschain.TokenWalletAccount, bool, error) {
	s.reads = append(s.reads, "wallet@42")
	wallet, err := nativecore.DeriveServiceActorTokenWallet(owner, route)
	if err != nil {
		return nil, false, err
	}
	_, ok := s.wallets[wallet]
	return &toschain.TokenWalletAccount{Address: wallet, Owner: owner, Master: route.Master.Text(), CodeHash: "tvm-cell-sha256:" + hex.EncodeToString(route.WalletCodeHash[:])}, ok, nil
}

// TokenWalletTransaction emulates the session's anchored walk: wallet
// transactions are newest first, and at most walletBound newer transactions
// may be passed before the named one. Older history is never visited.
func (s *tokenEvidenceFixture) TokenWalletTransaction(_ context.Context, a string, id toschain.ActorTxID) (*toschain.TokenActorTransaction, error) {
	s.reads = append(s.reads, "wallet-anchored@42")
	v, ok := s.wallets[a]
	if !ok {
		return nil, errors.New("missing wallet history")
	}
	bound := s.walletBound
	if bound == 0 {
		bound = 10_000
	}
	for passed, tx := range v.Transactions {
		s.walletVisited++
		if tx.LT == id.LT && tx.Hash == id.Hash {
			found := tx
			return &found, nil
		}
		if tx.LT <= id.LT {
			return nil, toschain.ErrHistoryAnchorMissing
		}
		if passed+1 > bound {
			return nil, toschain.ErrHistoryBoundExceeded
		}
	}
	return nil, toschain.ErrHistoryAnchorMissing
}
func tokenTestAddress(t *testing.T, value string) nativecore.MsgAddressV1 {
	t.Helper()
	a, err := nativecore.StandardAddress("0:" + strings.Repeat(value, 32))
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func tokenTestBOC(c *cell.Cell) string {
	return base64.StdEncoding.EncodeToString(c.ToBOCWithOptions(cell.BOCSerializeOptions{}))
}
func newTokenEvidenceFixture(t *testing.T) *tokenEvidenceFixture {
	t.Helper()
	actor, owner, buyer, master := tokenTestAddress(t, "11"), tokenTestAddress(t, "22"), tokenTestAddress(t, "33"), tokenTestAddress(t, "44")
	network := servicefixture.Network()
	actorID, err := hex.DecodeString(strings.TrimPrefix(actor.Text(), "0:"))
	if err != nil {
		t.Fatal(err)
	}
	masterID, err := hex.DecodeString(strings.TrimPrefix(master.Text(), "0:"))
	if err != nil {
		t.Fatal(err)
	}
	var masterHash [32]byte
	copy(masterHash[:], masterID)
	code := cell.BeginCell().MustStoreUInt(7, 8).EndCell()
	var walletHash [32]byte
	copy(walletHash[:], code.Hash())
	route := nativecore.ServiceActorTokenAssetRouteV1{Master: master, WalletCodeHash: walletHash, WalletCode: code, BridgeConfigParam: 79}
	own, err := nativecore.DeriveServiceActorTokenWallet(actor.Text(), route)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := nativecore.DeriveServiceActorTokenWallet(buyer.Text(), route)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x55}, mldsa44.PublicKeySize)
	keyID, err := mldsa44.KeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	manifest := servicefixture.Manifest("1.0.0", servicefixture.Settlement{ActorAccount: actorID, ActorCodeHash: nativecore.ServiceActorTokenReleaseCodeHash[:], AttestorKey: mldsa44.KeyIDText(keyID)})
	decimals := uint8(6)
	manifest.Settlement.Rail = nativecore.ServiceActorTokenRail
	manifest.SupportedAssets = []nativecore.SoftwareWorkAssetV1{{Kind: nativecore.TOSTokenAsset, MasterAccountID: masterID, WalletCodeHash: walletHash[:], Decimals: &decimals}}
	transport, transportHash, err := nativecore.BuildTransportBindingCellV1(nativecore.TransportBindingV1{SecurityMode: nativecore.TransportHTTPS, MaxRequestBytes: 1 << 20, BaseURL: "https://provider.example"})
	if err != nil {
		t.Fatal(err)
	}
	manifest.EndpointCommitment = transportHash
	manifestCBOR, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	capabilityID := "cap_" + strings.Repeat("66", 32)
	providerID := "agent_" + strings.Repeat("77", 32)
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: network, CapabilityID: capabilityID, ProviderAgentID: providerID, CapabilityVersion: "1.0.0", ManifestDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	terms := nativecore.ServiceActorTokenTermsV1{ServiceActorTermsV1: servicefixture.Terms(keyID, metadata), AssetMasterHash: masterHash, AssetWalletCodeHash: walletHash}
	tc, err := nativecore.BuildServiceActorTokenTerms(terms)
	if err != nil {
		t.Fatal(err)
	}
	var termsHash [32]byte
	copy(termsHash[:], tc.Hash())
	minterHash := "tvm-cell-sha256:" + strings.Repeat("88", 32)
	proposal := &nativev1.QuoteProposalV1{ProposalId: "token-proposal", CapabilityId: capabilityID, CapabilityVersion: "1.0.0", ProviderAgentId: providerID, ManifestDigest: digest, TransportBindingDigest: transportHash, ExpiresAtUnixSeconds: 1001000, Actor: &nativev1.TOSAccountAddressV1{AccountId: actorID}, ActorCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(nativecore.ServiceActorTokenReleaseCodeHash[:]), PolicyVersion: terms.PolicyVersion, TermsHash: hex.EncodeToString(termsHash[:]), PriceAtomic: terms.PricePerCall.String(), StorageFeeNanotos: terms.StorageFee.String(), AttestorKeyId: mldsa44.KeyIDText(keyID), Asset: &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{AccountId: masterID, CodeHash: minterHash}, WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(walletHash[:]), Decimals: 6}}
	quote, _, err := nativecore.BuildAcceptedTokenQuoteCommitment(network, proposal)
	if err != nil {
		t.Fatal(err)
	}
	var qh [32]byte
	copy(qh[:], quote.Hash())
	source := sha256.Sum256([]byte("source archive"))
	input := railwork.InputDigest(source)
	execution := sha256.Sum256([]byte("token execution"))
	req, err := nativecore.BuildServiceRequestCellV1(nativecore.ServiceRequestV1{QuoteCommitment: qh, ExecutionID: execution, InputDigest: input})
	if err != nil {
		t.Fatal(err)
	}
	var requestHash [32]byte
	copy(requestHash[:], req.Hash())
	snapshot := nativecore.ServiceActorTokenRequestSnapshotV1{RequestID: 1, Caller: buyer, RequestHash: requestHash, ResponseDeadline: 1000000 + uint64(terms.ResponseSLA), RefundClaimDeadline: 1000000 + uint64(terms.ResponseSLA) + uint64(terms.RefundClaimWindow), TermsHash: termsHash, Terms: terms}
	pending := nativecore.ServiceActorPendingRequestV1{Caller: buyer, RequestHash: requestHash, TermsHash: termsHash, Price: terms.PricePerCall, StorageFee: terms.StorageFee, CleanupBounty: terms.CleanupBounty, ResponseDeadline: snapshot.ResponseDeadline, RefundClaimDeadline: snapshot.RefundClaimDeadline}
	data := &nativecore.ServiceActorTokenDataV1{Owner: owner, Route: route, Pending: map[uint64]nativecore.ServiceActorPendingRequestV1{1: pending}, Refunds: map[uint64]nativecore.ServiceActorRefundV1{}, Payouts: map[uint64]nativecore.ServiceActorTokenPayoutV1{}, Returned: map[uint64]nativecore.ServiceActorTokenReturnedV1{}}
	call := toschain.TokenActorTransaction{LT: 4, Hash: strings.Repeat("04", 32), Now: 1000000, TookEffect: true, Sender: own, InboundMessageHash: strings.Repeat("d4", 32), QueryID: 19, Notification: &toschain.TokenActorNotification{QueryID: 19, From: buyer.Text(), AmountAtomic: terms.PricePerCall.String(), Payload: &nativecore.TokenCallPayloadV1{RequestHash: requestHash, ExpectedTermsHash: termsHash}}, Logs: []nativecore.ServiceActorTokenLogV1{{Snapshot: &snapshot}}}
	transfer, err := nativecore.BuildServiceActorTokenFundingTransfer(19, terms.PricePerCall, actor.Text(), buyer.Text(), big.NewInt(2000000000), requestHash, termsHash)
	if err != nil {
		t.Fatal(err)
	}
	wtx := []toschain.TokenActorTransaction{
		{LT: 1, Hash: strings.Repeat("01", 32), Now: 1000000, TookEffect: true, Outputs: []toschain.TokenActorOutput{{Hash: strings.Repeat("d2", 32), Destination: sender}}},
		{LT: 2, Hash: strings.Repeat("02", 32), Now: 1000000, TookEffect: true, Sender: buyer.Text(), InboundMessageHash: strings.Repeat("d2", 32), BodyBOC: tokenTestBOC(transfer), Outputs: []toschain.TokenActorOutput{{Hash: strings.Repeat("d3", 32), Destination: own}}},
		{LT: 3, Hash: strings.Repeat("03", 32), Now: 1000000, TookEffect: true, Sender: sender, InboundMessageHash: strings.Repeat("d3", 32), Outputs: []toschain.TokenActorOutput{{Hash: strings.Repeat("d4", 32), Destination: actor.Text()}}},
	}
	wallets := map[string]*toschain.TokenWalletHistory{}
	accounts := []string{buyer.Text(), sender, own}
	hops := make([]TokenFundingHop, 3)
	for i, account := range accounts {
		wallets[account] = &toschain.TokenWalletHistory{Result: toschain.HistoryComplete, Transactions: []toschain.TokenActorTransaction{wtx[i]}}
		hops[i] = TokenFundingHop{Account: account, Transaction: toschain.ActorTxID{LT: wtx[i].LT, Hash: wtx[i].Hash}}
	}
	account := &toschain.TokenActorAccount{Address: actor.Text(), OwnWallet: own, CodeHash: proposal.ActorCodeHash, Data: data, LastTransaction: toschain.ActorTxID{LT: call.LT, Hash: call.Hash}}
	reference := func() *nativev1.ChainReference { return &nativev1.ChainReference{FinalizedCheckpoint: 42} }
	states := map[string]*nativev1.NativeStateV1{
		capabilityID: {Network: network, Reference: reference(), State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{CapabilityId: capabilityID, OwnerAgentId: providerID, Versions: []*nativev1.CapabilityVersionV1{{Version: "1.0.0", ManifestDigest: digest}}}}},
		providerID:   {Network: network, Reference: reference(), State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: providerID}}},
	}
	pkg, err := proto.MarshalOptions{Deterministic: true}.Marshal(&nativev1.QuoteProposalPackageV1{Proposal: proposal, CanonicalManifestCbor: manifestCBOR, TransportBindingBoc: transport.ToBOC()})
	if err != nil {
		t.Fatal(err)
	}
	bundle := &TokenBundle{Schema: TokenBundleSchema, Network: NetworkTuple{network.NetworkId, network.GenesisRootHash, network.GenesisFileHash}, Actor: actor.Text(), ActorCodeHash: proposal.ActorCodeHash, BuyerWallet: buyer.Text(), QuotePackageBase64: base64.StdEncoding.EncodeToString(pkg), AcceptedQuoteBOC: tokenTestBOC(quote), ServiceRequestBOC: tokenTestBOC(req), SourceDigest: "sha256:" + hex.EncodeToString(source[:]), Funding: hops, Call: account.LastTransaction}
	pin := toschain.TokenAssetPin{Master: master.Text(), Bridge: "-1:" + strings.Repeat("99", 32), BridgeConfigParam: 79, Decimals: 6, SourceChainID: 1, BridgeCodeHash: "tvm-cell-sha256:" + strings.Repeat("aa", 32), MinterCodeHash: minterHash, WalletCodeHash: proposal.Asset.WalletCodeHash}
	pin.SourceToken[19] = 1
	return &tokenEvidenceFixture{network: network, account: account, history: &toschain.TokenActorHistory{Result: toschain.HistoryComplete, Head: account.LastTransaction, Transactions: []toschain.TokenActorTransaction{call}}, states: states, wallets: wallets, bundle: bundle, pins: []toschain.TokenAssetPin{pin}, now: time.Unix(1000100, 0)}
}
func (s *tokenEvidenceFixture) input() TokenInput {
	return TokenInput{Network: s.network, Actor: s.account.Address, ActorCodeHash: s.account.CodeHash, Pins: s.pins, Bundle: s.bundle}
}
func TestTokenEvidenceBindsThreeFundingHopsAtOneCheckpoint(t *testing.T) {
	s := newTokenEvidenceFixture(t)
	v := VerifyToken(context.Background(), s, s.input())
	if v.Result != ResultPass {
		t.Fatalf("%+v", v.Checks)
	}
	if len(v.Requests) != 1 || v.Requests[0].State != serviceactor.StatusPending {
		t.Fatalf("%+v", v)
	}
	for _, read := range s.reads {
		if !strings.HasSuffix(read, "@42") {
			t.Fatal(read)
		}
	}
}
func TestTokenEvidenceRefusesEachBrokenLinkAndAsset(t *testing.T) {
	for name, edit := range map[string]func(*tokenEvidenceFixture){
		"payer-hop": func(s *tokenEvidenceFixture) {
			s.wallets[s.bundle.Funding[0].Account].Transactions[0].Outputs[0].Hash = strings.Repeat("00", 32)
		},
		"sender-hop": func(s *tokenEvidenceFixture) {
			s.wallets[s.bundle.Funding[1].Account].Transactions[0].Outputs[0].Hash = strings.Repeat("00", 32)
		},
		"recipient-hop": func(s *tokenEvidenceFixture) {
			s.wallets[s.bundle.Funding[2].Account].Transactions[0].Outputs[0].Hash = strings.Repeat("00", 32)
		},
		"funding-excess-destination": func(s *tokenEvidenceFixture) {
			call := s.history.Transactions[0]
			snap := call.Logs[0].Snapshot
			body, err := nativecore.BuildServiceActorTokenFundingTransfer(call.QueryID, snap.Terms.PricePerCall, s.account.Address, s.account.Address, big.NewInt(2000000000), snap.RequestHash, snap.TermsHash)
			if err != nil {
				t.Fatal(err)
			}
			s.wallets[s.bundle.Funding[1].Account].Transactions[0].BodyBOC = tokenTestBOC(body)
		},
		"sender-auth": func(s *tokenEvidenceFixture) {
			s.wallets[s.bundle.Funding[1].Account].Transactions[0].Sender = s.account.Address
		},
		"aborted-wallet": func(s *tokenEvidenceFixture) {
			s.wallets[s.bundle.Funding[1].Account].Transactions[0].TookEffect = false
		},
		"wallet-anchor-beyond-bound": func(s *tokenEvidenceFixture) {
			w := s.wallets[s.bundle.Funding[1].Account]
			newer := []toschain.TokenActorTransaction{{LT: 101, Hash: strings.Repeat("65", 32), TookEffect: true}, {LT: 100, Hash: strings.Repeat("64", 32), TookEffect: true}}
			w.Transactions = append(newer, w.Transactions...)
			s.walletBound = 1
		},
		"wallet-anchor-missing": func(s *tokenEvidenceFixture) {
			s.bundle.Funding[1].Transaction.Hash = strings.Repeat("66", 32)
		},
		"wallet-anchor-lt-missing": func(s *tokenEvidenceFixture) {
			s.bundle.Funding[1].Transaction.LT = 7
		},
		"master-pin": func(s *tokenEvidenceFixture) { s.pins[0].Master = s.bundle.BuyerWallet },
		"wallet-pin": func(s *tokenEvidenceFixture) {
			s.pins[0].WalletCodeHash = "tvm-cell-sha256:" + strings.Repeat("bb", 32)
		},
		"decimals-pin": func(s *tokenEvidenceFixture) { s.pins[0].Decimals = 9 },
		"minter-pin": func(s *tokenEvidenceFixture) {
			s.pins[0].MinterCodeHash = "tvm-cell-sha256:" + strings.Repeat("bb", 32)
		},
		"actor-release": func(s *tokenEvidenceFixture) { s.account.CodeHash = "tvm-cell-sha256:" + strings.Repeat("bb", 32) },
		"checkpoint": func(s *tokenEvidenceFixture) {
			for _, v := range s.states {
				v.Reference.FinalizedCheckpoint = 43
			}
		},
		"terms":   func(s *tokenEvidenceFixture) { s.history.Transactions[0].Logs[0].Snapshot.TermsHash[0] ^= 1 },
		"request": func(s *tokenEvidenceFixture) { s.bundle.SourceDigest = "sha256:" + strings.Repeat("bb", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			s := newTokenEvidenceFixture(t)
			edit(s)
			if v := VerifyToken(context.Background(), s, s.input()); v.Result != ResultFail {
				t.Fatal("forged token evidence accepted")
			}
		})
	}
}
func TestTokenEvidenceStrictBundleAndNoBundleClaim(t *testing.T) {
	s := newTokenEvidenceFixture(t)
	raw, err := json.Marshal(s.bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeTokenBundle(raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(raw, []byte("{}")...), bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1), bytes.Replace(raw, []byte(TokenBundleSchema), []byte("other"), 1)} {
		if _, err = DecodeTokenBundle(bad); err == nil {
			t.Fatal("malformed token bundle accepted")
		}
	}
	in := s.input()
	in.Bundle = nil
	in.RequestIDs = []uint64{1}
	v := VerifyToken(context.Background(), s, in)
	if v.Result != ResultPass || len(v.NotClaimed) <= len(notClaimed) {
		t.Fatalf("%+v", v)
	}
	in.Receipt = []byte{1}
	if v = VerifyToken(context.Background(), s, in); v.Result != ResultFail {
		t.Fatal("unbound receipt accepted")
	}
}

func (s *tokenEvidenceFixture) respond(t *testing.T, edit func(*nativecore.SoftwareWorkTokenReceiptV1)) []byte {
	t.Helper()
	reqCell, err := tokenEvidenceCell(s.bundle.ServiceRequestBOC)
	if err != nil {
		t.Fatal(err)
	}
	request, err := nativecore.DecodeServiceRequestCellV1(reqCell)
	if err != nil {
		t.Fatal(err)
	}
	pkgRaw, err := base64.StdEncoding.DecodeString(s.bundle.QuotePackageBase64)
	if err != nil {
		t.Fatal(err)
	}
	pkg := &nativev1.QuoteProposalPackageV1{}
	if err = proto.Unmarshal(pkgRaw, pkg); err != nil {
		t.Fatal(err)
	}
	q, _, err := nativecore.BuildAcceptedTokenQuoteCommitment(s.network, pkg.Proposal)
	if err != nil {
		t.Fatal(err)
	}
	receipt := nativecore.SoftwareWorkTokenReceiptV1{SoftwareWorkReceiptV1: nativecore.SoftwareWorkReceiptV1{QuoteCommitment: "tvm-cell-sha256:" + hex.EncodeToString(q.Hash()), ExecutionID: "sha256:" + hex.EncodeToString(request.ExecutionID[:]), InputDigest: "sha256:" + hex.EncodeToString(request.InputDigest[:]), SourceDigest: s.bundle.SourceDigest, ToolchainDigest: "sha256:" + strings.Repeat("33", 32), SandboxDigest: pkg.Proposal.ManifestDigest, ProviderAgentID: pkg.Proposal.ProviderAgentId, ChargedAtomicAmount: pkg.Proposal.PriceAtomic, ResultDigest: "sha256:" + strings.Repeat("41", 32), ArtifactDigest: "sha256:" + strings.Repeat("42", 32), ReportDigest: "sha256:" + strings.Repeat("43", 32), CompletedAt: 1000001}}
	copy(receipt.AssetMaster[:], pkg.Proposal.Asset.Master.AccountId)
	if edit != nil {
		edit(&receipt)
	}
	invalidExit := receipt.ExitCode
	if invalidExit != 0 {
		receipt.ExitCode = 0
	}
	root, _, err := nativecore.BuildSoftwareWorkTokenReceiptCellV1(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if invalidExit != 0 {
		parse, e := root.BeginParse()
		if e != nil {
			t.Fatal(e)
		}
		header, e := parse.LoadSlice(112)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = parse.LoadInt(32); e != nil {
			t.Fatal(e)
		}
		builder := cell.BeginCell().MustStoreSlice(header, 112).MustStoreInt(int64(invalidExit), 32)
		for parse.RefsNum() > 0 {
			ref, e := parse.LoadRefCell()
			if e != nil {
				t.Fatal(e)
			}
			builder.MustStoreRef(ref)
		}
		root = builder.EndCell()
	}
	delete(s.account.Data.Pending, 1)
	tx := toschain.TokenActorTransaction{LT: 5, Hash: strings.Repeat("05", 32), Now: 1000002, TookEffect: true, Sender: s.account.Data.Owner.Text(), Opcode: nativecore.ServiceActorTokenRespondOpcode, RequestID: 1, Signed: true, ResponseHash: hex.EncodeToString(root.Hash())}
	s.history.Transactions = append(s.history.Transactions, tx)
	s.account.LastTransaction = toschain.ActorTxID{LT: tx.LT, Hash: tx.Hash}
	s.history.Head = s.account.LastTransaction
	return root.ToBOC()
}
func TestTokenEvidenceReceiptBindsFinalizedSchemaTwoResponse(t *testing.T) {
	s := newTokenEvidenceFixture(t)
	receipt := s.respond(t, nil)
	in := s.input()
	in.Receipt = receipt
	v := VerifyToken(context.Background(), s, in)
	if v.Result != ResultPass || v.Requests[0].State != serviceactor.StatusResponded {
		t.Fatalf("%+v", v.Checks)
	}
}
func TestTokenEvidenceReceiptRejectsEveryChangedContextEvenWhenFinalized(t *testing.T) {
	for name, edit := range map[string]func(*nativecore.SoftwareWorkTokenReceiptV1){
		"asset":     func(r *nativecore.SoftwareWorkTokenReceiptV1) { r.AssetMaster[0] ^= 1 },
		"charge":    func(r *nativecore.SoftwareWorkTokenReceiptV1) { r.ChargedAtomicAmount = "1" },
		"execution": func(r *nativecore.SoftwareWorkTokenReceiptV1) { r.ExecutionID = "sha256:" + strings.Repeat("a1", 32) },
		"input":     func(r *nativecore.SoftwareWorkTokenReceiptV1) { r.InputDigest = "sha256:" + strings.Repeat("a1", 32) },
		"sandbox":   func(r *nativecore.SoftwareWorkTokenReceiptV1) { r.SandboxDigest = "sha256:" + strings.Repeat("a1", 32) },
		"toolchain": func(r *nativecore.SoftwareWorkTokenReceiptV1) {
			r.ToolchainDigest = "sha256:" + strings.Repeat("a1", 32)
		},
		"source": func(r *nativecore.SoftwareWorkTokenReceiptV1) { r.SourceDigest = "sha256:" + strings.Repeat("a1", 32) },
		"provider": func(r *nativecore.SoftwareWorkTokenReceiptV1) {
			r.ProviderAgentID = "agent_" + strings.Repeat("a1", 32)
		},
		"failed execution":  func(r *nativecore.SoftwareWorkTokenReceiptV1) { r.ExitCode = 2 },
		"future completion": func(r *nativecore.SoftwareWorkTokenReceiptV1) { r.CompletedAt = 1000010 },
	} {
		t.Run(name, func(t *testing.T) {
			s := newTokenEvidenceFixture(t)
			receipt := s.respond(t, edit)
			in := s.input()
			in.Receipt = receipt
			if v := VerifyToken(context.Background(), s, in); v.Result != ResultFail {
				t.Fatal("mismatched finalized Receipt accepted")
			}
		})
	}
}

func TestTokenEvidenceReceiptRejectsAlternativeBOCAndMultipleRoots(t *testing.T) {
	s := newTokenEvidenceFixture(t)
	receipt := s.respond(t, nil)
	root, err := cell.FromBOC(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{root.ToBOCWithOptions(cell.BOCSerializeOptions{}), append(append([]byte(nil), receipt...), 0)} {
		in := s.input()
		in.Receipt = bad
		if v := VerifyToken(context.Background(), s, in); v.Result != ResultFail {
			t.Fatal("noncanonical Receipt file accepted")
		}
	}
}

// TestTokenEvidenceProvesHopsOfLongHistoryWallets gives each funding wallet
// more than the history bound of older transactions and a few newer ones.
// The anchored walks prove each named hop without reading the older history.
func TestTokenEvidenceProvesHopsOfLongHistoryWallets(t *testing.T) {
	s := newTokenEvidenceFixture(t)
	const older, newer = 10_001, 5
	shift := uint64(older + newer*10)
	for i := range s.bundle.Funding {
		hop := &s.bundle.Funding[i]
		w := s.wallets[hop.Account]
		hopTx := w.Transactions[0]
		hopTx.LT += shift
		hop.Transaction.LT = hopTx.LT
		var history []toschain.TokenActorTransaction
		for j := newer; j > 0; j-- {
			lt := hopTx.LT + uint64(j)*4
			history = append(history, toschain.TokenActorTransaction{LT: lt, Hash: fmt.Sprintf("%064x", lt), TookEffect: true})
		}
		history = append(history, hopTx)
		for j := 1; j <= older; j++ {
			lt := hopTx.LT - uint64(j)*4
			history = append(history, toschain.TokenActorTransaction{LT: lt, Hash: fmt.Sprintf("%064x", lt), TookEffect: true})
		}
		w.Transactions = history
		if len(w.Transactions) <= 10_000 {
			t.Fatal("the wallet history must exceed the history bound")
		}
	}
	call := &s.history.Transactions[0]
	call.LT += shift + 4
	s.account.LastTransaction = toschain.ActorTxID{LT: call.LT, Hash: call.Hash}
	s.history.Head = s.account.LastTransaction
	s.bundle.Call = s.account.LastTransaction
	v := VerifyToken(context.Background(), s, s.input())
	if v.Result != ResultPass {
		t.Fatalf("long-history wallets broke the evidence: %+v", v.Checks)
	}
	if limit := len(s.bundle.Funding) * (newer + 1); s.walletVisited > limit {
		t.Fatalf("anchored walks visited %d wallet transactions, want at most %d", s.walletVisited, limit)
	}
}

// TestTokenEvidenceActorWithUnreturnedRefusalsStillVerifies puts legal SAF1
// refusals that name payout id 0 into the actor's history: a zero-amount
// transfer refused with 1902, and a refusal at the funding-return cap. Anyone
// with a token wallet can cause either; neither may make the actor's evidence
// fail.
func TestTokenEvidenceActorWithUnreturnedRefusalsStillVerifies(t *testing.T) {
	s := newTokenEvidenceFixture(t)
	call := s.history.Transactions[0]
	buyer, err := nativecore.StandardAddress(s.bundle.BuyerWallet)
	if err != nil {
		t.Fatal(err)
	}
	stranger := tokenTestAddress(t, "5a")
	capHash := sha256.Sum256([]byte("refused at the funding-return cap"))
	refusal := func(lt uint64, from nativecore.MsgAddressV1, amount int64, reason uint16, payload *nativecore.TokenCallPayloadV1) toschain.TokenActorTransaction {
		value := big.NewInt(amount)
		return toschain.TokenActorTransaction{LT: lt, Hash: fmt.Sprintf("%064x", lt), Now: call.Now - 1, Kind: "funding_refused", TookEffect: true, Sender: s.account.OwnWallet, QueryID: lt, Notification: &toschain.TokenActorNotification{QueryID: lt, From: from.Text(), AmountAtomic: value.String(), Payload: payload}, Logs: []nativecore.ServiceActorTokenLogV1{{Funding: &nativecore.ServiceActorTokenFundingLogV1{QueryID: lt, From: from, Amount: value, Reason: reason, PayoutID: 0}}}}
	}
	s.history.Transactions = []toschain.TokenActorTransaction{
		refusal(2, stranger, 0, 1902, nil),
		refusal(3, buyer, 1000, 1907, &nativecore.TokenCallPayloadV1{RequestHash: capHash}),
		call,
	}
	if v := VerifyToken(context.Background(), s, s.input()); v.Result != ResultPass || len(v.Requests) != 1 || v.Requests[0].State != serviceactor.StatusPending {
		t.Fatalf("legal refusals broke the actor's evidence: %+v", v.Checks)
	}
	in := s.input()
	in.Bundle = nil
	in.RequestHashes = []string{hex.EncodeToString(capHash[:])}
	v := VerifyToken(context.Background(), s, in)
	if v.Result != ResultPass || len(v.FundingRefusals) != 1 || v.FundingRefusals[0].State != "surplus" || v.FundingRefusals[0].PayoutID != 0 || v.FundingRefusals[0].Reason != 1907 {
		t.Fatalf("refusal at the cap was not reported as surplus: %+v %+v", v.Checks, v.FundingRefusals)
	}
}
