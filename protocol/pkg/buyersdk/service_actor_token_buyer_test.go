package buyersdk

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

type tokenBuyerTestSession struct {
	*saSession
	builder          *tokenBuildSessionFixture
	token            *toschain.TokenActorAccount
	recognition      *toschain.TokenAssetRecognition
	history          *toschain.TokenActorHistory
	accepting        bool
	walletSeqnoError error
}

func (s *tokenBuyerTestSession) WalletSeqno(ctx context.Context, wallet string) (uint32, error) {
	if s.walletSeqnoError != nil {
		return 0, s.walletSeqnoError
	}
	return s.saSession.WalletSeqno(ctx, wallet)
}
func (s *tokenBuyerTestSession) BlockHashes() (string, string) { return s.builder.BlockHashes() }
func (s *tokenBuyerTestSession) ResolveTokenActor(ctx context.Context, a string, p []toschain.TokenAssetPin, recognized bool) (*toschain.ResolvedTokenActor, error) {
	r, err := s.builder.ResolveTokenActor(ctx, a, p, recognized)
	if r != nil {
		r.Account = s.token
		r.Checkpoint = s.Checkpoint()
		if recognized {
			r.Recognition = s.recognition
		}
	}
	return r, err
}
func (s *tokenBuyerTestSession) GetTokenFundingPrices(ctx context.Context, a string) ([6]*big.Int, error) {
	return s.builder.GetTokenFundingPrices(ctx, a)
}
func (s *tokenBuyerTestSession) GetTokenAcceptingTokens(context.Context, string) (bool, error) {
	return s.accepting, nil
}
func (s *tokenBuyerTestSession) ReadTokenWalletTerms(ctx context.Context, id uint32) (toschain.TokenWalletTerms, error) {
	return s.builder.ReadTokenWalletTerms(ctx, id)
}
func (s *tokenBuyerTestSession) ReadTokenForwardPrices(ctx context.Context) (toschain.TokenForwardPrices, error) {
	return s.builder.ReadTokenForwardPrices(ctx)
}
func (s *tokenBuyerTestSession) ReadTokenGlobalID(context.Context) (int32, error) { return 0, nil }
func (s *tokenBuyerTestSession) ReadTokenWallet(ctx context.Context, a string, r nativecore.ServiceActorTokenAssetRouteV1) (*toschain.TokenWalletAccount, bool, error) {
	return s.builder.ReadTokenWallet(ctx, a, r)
}
func (s *tokenBuyerTestSession) ReadTokenActor(context.Context, string) (*toschain.TokenActorAccount, bool, error) {
	return s.token, true, nil
}
func (s *tokenBuyerTestSession) ReadTokenAsset(context.Context, string, []toschain.TokenAssetPin) (*toschain.TokenAssetRecognition, error) {
	return s.recognition, nil
}
func (s *tokenBuyerTestSession) TokenHistory(context.Context, string, *toschain.ActorTxID) (*toschain.TokenActorHistory, error) {
	return s.history, nil
}

type tokenBuyerTestReader struct {
	s     *tokenBuyerTestSession
	opens int
}

func (r *tokenBuyerTestReader) BeginBuyerSession(context.Context) (ServiceActorSession, error) {
	r.opens++
	return r.s, nil
}

type tokenBuyerTestSender struct {
	buyer            *ServiceActorBuyer
	sent             int
	failure          error
	preflightFailure error
	preflights       int
}

func (s *tokenBuyerTestSender) PreflightToken(_ context.Context, p *TokenPreparedMessage) error {
	s.preflights++
	if s.preflightFailure != nil {
		return s.preflightFailure
	}
	records, err := s.buyer.config.Journal.Records()
	if err != nil {
		return err
	}
	for _, r := range records {
		if sameTokenMessage(r.PreparedTokenMessage, p) && r.Phase == PhaseSending {
			return errors.New("broadcast reservation preceded preflight")
		}
		for _, send := range r.Lifecycle {
			if sameTokenMessage(send.PreparedTokenMessage, p) && send.Phase == PhaseSending {
				return errors.New("lifecycle broadcast reservation preceded preflight")
			}
		}
	}
	return s.preflightFailure
}
func (s *tokenBuyerTestSender) SendToken(_ context.Context, p *TokenPreparedMessage) error {
	records, err := s.buyer.config.Journal.Records()
	if err != nil {
		return err
	}
	found := false
	for _, r := range records {
		if r.PreparedTokenMessage != nil && sameTokenMessage(r.PreparedTokenMessage, p) {
			found = r.Phase == PhaseSending
		}
		for _, send := range r.Lifecycle {
			if sameTokenMessage(send.PreparedTokenMessage, p) {
				found = send.Phase == PhaseSending
			}
		}

	}
	if !found {
		return errors.New("custody started before durable token reservation")
	}
	s.sent++
	return s.failure
}

func newTokenBuyerFixture(t *testing.T) (*buyerFixture, *tokenBuyerTestReader, *tokenBuyerTestSender) {
	t.Helper()
	snapshot, _ := loadTokenFixture(t, "call")
	wallet := snapshot.Data.Route.WalletCode
	hash := snapshot.Data.Route.WalletCodeHash
	master := snapshot.Data.Route.Master
	code := nativecore.ServiceActorTokenReleaseCodeHash
	decimal := snapshot.AssetPin.Decimals
	f := newBuyerFixtureWith(t, defaultLimits(), func(m *nativecore.SoftwareWorkManifestV1) {
		m.Settlement.Rail = nativecore.ServiceActorTokenRail
		m.Settlement.ActorCodeHash = code[:]
		raw, _ := hex.DecodeString(strings.TrimPrefix(master.Text(), "0:"))
		m.SupportedAssets = []nativecore.SoftwareWorkAssetV1{{Kind: nativecore.TOSTokenAsset, MasterAccountID: raw, WalletCodeHash: hash[:], Decimals: &decimal}}
	}, nativecore.TransportBindingV1{SecurityMode: nativecore.TransportHTTPS, MaxRequestBytes: 1 << 20, BaseURL: "https://provider.example"})
	route := nativecore.ServiceActorTokenAssetRouteV1{Master: master, WalletCode: wallet, WalletCodeHash: hash, BridgeConfigParam: 79}
	root, err := nativecore.BuildServiceActorTokenInitialData(saOwner, nativecore.ServiceActorTokenPolicyV1{ServiceActorPolicyV1: f.policy, MaxTokenLiability: big.NewInt(1_000_000_000_000)}, route)
	if err != nil {
		t.Fatal(err)
	}
	data, err := nativecore.DecodeServiceActorTokenData(root)
	if err != nil {
		t.Fatal(err)
	}
	data.Active = true
	own, err := nativecore.DeriveServiceActorTokenWallet(saActor, route)
	if err != nil {
		t.Fatal(err)
	}
	base, err := f.chain.BeginBuyerSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Actor = saActor
	snapshot.ReadAt.Seqno = uint32(base.Checkpoint())
	snapshot.ReadAt.GenUtime = uint32(saNow.Unix())
	snapshot.Data = data
	snapshot.OwnWallet = own
	snapshot.Balance = big.NewInt(5_000_000_000)
	snapshot.AssetPin = &TokenAssetPin{Master: master.Text(), WalletCodeHash: hash, Decimals: decimal}
	snapshot.Asset = &TokenRecognizedAsset{Status: 1, WalletCodeHash: hash, Decimals: decimal, MaxLiabilityPerActor: big.NewInt(1_000_000_000_000)}
	snapshot.SenderTokenBalance = big.NewInt(1_000_000_000_000)
	snapshot.OwnWalletBalance = new(big.Int)
	account := &toschain.TokenActorAccount{Address: saActor, CodeHash: "tvm-cell-sha256:" + hex.EncodeToString(code[:]), OwnWallet: own, BalanceNano: 5_000_000_000, Data: data}
	session := &tokenBuyerTestSession{saSession: base.(*saSession), builder: &tokenBuildSessionFixture{snapshot: snapshot}, token: account, recognition: &toschain.TokenAssetRecognition{Checkpoint: base.Checkpoint(), Record: toschain.SettlementAssetV1{Master: master.Text(), Status: 1, WalletCodeHash: hash, Decimals: decimal, MaxLiabilityPerActor: big.NewInt(1_000_000_000_000)}}, accepting: true}
	for i := range session.recognition.Record.MinterCodeHash {
		session.recognition.Record.MinterCodeHash[i] = 0xcd
	}
	reader := &tokenBuyerTestReader{s: session}
	sender := &tokenBuyerTestSender{}
	config := f.buyer.config
	config.Reader = reader
	config.ActorCodeHash = account.CodeHash
	config.TokenSender = sender
	config.TokenPins = []toschain.TokenAssetPin{{Master: master.Text(), WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(hash[:]), Decimals: decimal}}
	config.Limits.MaxPerCallNanoTOS = big.NewInt(3_000_000_000_000)
	config.Limits.MaxWindowNanoTOS = big.NewInt(10_000_000_000_000)
	config.Limits.TokenAssets = map[string]TokenAssetLimits{TokenAssetBudgetKey(master.Text(), config.TokenPins[0].WalletCodeHash, decimal): {MaxPerCallAtomic: big.NewInt(500_000_000), MaxWindowAtomic: big.NewInt(900_000_000)}}
	f.buyer, err = NewServiceActorBuyer(config)
	if err != nil {
		t.Fatal(err)
	}
	sender.buyer = f.buyer
	p := f.pkg.Proposal
	p.ActorCodeHash = account.CodeHash
	p.PriceAtomic = p.PriceNanotos
	p.PriceNanotos = ""
	raw, _ := hex.DecodeString(strings.TrimPrefix(master.Text(), "0:"))
	p.Asset = &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{AccountId: raw, CodeHash: "tvm-cell-sha256:" + strings.Repeat("cd", 32)}, WalletCodeHash: config.TokenPins[0].WalletCodeHash, Decimals: uint32(decimal)}
	terms, err := nativecore.ServiceActorTokenTermsHash(nativecore.TokenTermsOfPolicy(data.Policy, route))
	if err != nil {
		t.Fatal(err)
	}
	p.TermsHash = hex.EncodeToString(terms[:])
	return f, reader, sender
}

func TestTokenBuyerDurableCallAndAmbiguityNeverResend(t *testing.T) {
	f, reader, sender := newTokenBuyerFixture(t)
	r, err := f.buyer.Prepare(context.Background(), f.request, f.pkg, digest32(1), digest32(2))
	if err != nil {
		t.Fatal(err)
	}
	if reader.opens != 1 || r.PriceNanoTOS != "" || r.PreparedTokenMessage == nil || r.PriceAtomic != "300000000" {
		t.Fatalf("token preparation =%+v opens=%d", r, reader.opens)
	}
	sender.failure = errors.New("lost reply")
	sent, err := f.buyer.Call(context.Background(), r.RequestHash)
	if err == nil || sent.Phase != PhaseAmbiguous || sender.sent != 1 {
		t.Fatalf("call=%+v err=%v sends=%d", sent, err, sender.sent)
	}
	if _, err = f.buyer.Call(context.Background(), r.RequestHash); err == nil || sender.sent != 1 {
		t.Fatal("ambiguous token call resent")
	}
}

func TestTokenBuyerReadmitsAndPreservesTheConfirmedFunding(t *testing.T) {
	for _, kind := range []string{"suspended", "not accepting", "funding"} {
		t.Run(kind, func(t *testing.T) {
			f, reader, sender := newTokenBuyerFixture(t)
			r, err := f.buyer.Prepare(context.Background(), f.request, f.pkg, digest32(1), digest32(2))
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "suspended":
				reader.s.recognition.Record.Status = 2
			case "not accepting":
				reader.s.accepting = false
			case "funding":
				for _, price := range reader.s.builder.snapshot.FundingPrices {
					price.Mul(price, big.NewInt(1000))
				}
			}
			if _, err = f.buyer.Call(context.Background(), r.RequestHash); err == nil {
				t.Fatal("changed admission or funding accepted")
			}
			after, err := f.buyer.config.Journal.Read(r.RequestHash)
			if err != nil || after.Phase != PhasePrepared || sender.sent != 0 {
				t.Fatal("refusal handed call to custody")
			}
		})
	}
}

func landTokenBuyerCall(t *testing.T, f *buyerFixture, reader *tokenBuyerTestReader, r CallRecord) {
	t.Helper()
	s := reader.s
	terms := nativecore.TokenTermsOfPolicy(s.token.Data.Policy, s.token.Data.Route)
	var rh, th [32]byte
	raw, err := hex.DecodeString(r.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	copy(rh[:], raw)
	raw, err = hex.DecodeString(r.TermsHash)
	if err != nil {
		t.Fatal(err)
	}
	copy(th[:], raw)
	caller, err := nativecore.StandardAddress(r.BuyerWallet)
	if err != nil {
		t.Fatal(err)
	}
	now := uint32(saNow.Unix() - 10)
	snapshot := nativecore.ServiceActorTokenRequestSnapshotV1{RequestID: 1, Caller: caller, RequestHash: rh, TermsHash: th, Terms: terms, ResponseDeadline: uint64(now) + uint64(terms.ResponseSLA), RefundClaimDeadline: uint64(now) + uint64(terms.ResponseSLA) + uint64(terms.RefundClaimWindow)}
	tx := toschain.TokenActorTransaction{LT: 100, Hash: strings.Repeat("a1", 32), Now: now, TookEffect: true, Sender: s.token.OwnWallet, Notification: &toschain.TokenActorNotification{QueryID: r.QueryID, From: r.BuyerWallet, AmountAtomic: r.PriceAtomic, Payload: &nativecore.TokenCallPayloadV1{RequestHash: rh, ExpectedTermsHash: th}}, Logs: []nativecore.ServiceActorTokenLogV1{{Snapshot: &snapshot}}}
	s.history = &toschain.TokenActorHistory{Result: toschain.HistoryComplete, Transactions: []toschain.TokenActorTransaction{tx}}
	s.token.Data.Pending[1] = nativecore.ServiceActorPendingRequestV1{Caller: caller, Price: terms.PricePerCall, StorageFee: terms.StorageFee, CleanupBounty: terms.CleanupBounty, RequestHash: rh, TermsHash: th, ResponseDeadline: snapshot.ResponseDeadline, RefundClaimDeadline: snapshot.RefundClaimDeadline}
}

func TestTokenBuyerResolvesOnlyTheMatchingFinalizedAdmission(t *testing.T) {
	f, reader, _ := newTokenBuyerFixture(t)
	r, err := f.buyer.Prepare(context.Background(), f.request, f.pkg, digest32(1), digest32(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.buyer.Call(context.Background(), r.RequestHash); err != nil {
		t.Fatal(err)
	}
	landTokenBuyerCall(t, f, reader, r)
	report, err := f.buyer.Resolve(context.Background(), r.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	if report.Phase != PhaseAdmitted || report.Status != "pending" || report.RequestID == nil || *report.RequestID != 1 {
		t.Fatalf("report=%+v", report)
	}
	reader.s.recognition.Record.Status = 2
	report, err = f.buyer.Resolve(context.Background(), r.RequestHash)
	if err != nil || report.Phase != PhaseAdmitted {
		t.Fatal("new recognition rewrote existing liability", report, err)
	}
	reader.s.history.Result = toschain.HistoryAnchorReached
	if _, err = f.buyer.Resolve(context.Background(), r.RequestHash); err == nil {
		t.Fatal("incomplete history accepted")
	}
}

func TestTokenBuyerLifecycleReservesFundingBeforeCustodyAndDoesNotRepeat(t *testing.T) {
	f, reader, sender := newTokenBuyerFixture(t)
	r, err := f.buyer.Prepare(context.Background(), f.request, f.pkg, digest32(1), digest32(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.buyer.Call(context.Background(), r.RequestHash); err != nil {
		t.Fatal(err)
	}
	landTokenBuyerCall(t, f, reader, r)
	report, err := f.buyer.Resolve(context.Background(), r.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(int64(report.ResponseDeadline)+1, 0)
	reader.s.wallet.chainTime = now
	reader.s.builder.snapshot.ReadAt.GenUtime = uint32(now.Unix())
	f.buyer.config.Now = func() time.Time { return now }
	updated, err := f.buyer.SendLifecycle(context.Background(), r.RequestHash, "expire")
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Lifecycle) != 1 || updated.Lifecycle[0].Phase != PhaseSubmitted || updated.Lifecycle[0].PreparedTokenMessage == nil || sender.sent != 2 {
		t.Fatalf("lifecycle=%+v sends=%d", updated.Lifecycle, sender.sent)
	}
	if _, err = f.buyer.SendLifecycle(context.Background(), r.RequestHash, "expire"); !errors.Is(err, ErrLifecycleUnsettled) || sender.sent != 2 {
		t.Fatal("unsettled lifecycle sent twice", err, sender.sent)
	}
}

func TestTokenBuyerUsesTheLapsedActionAtTheRefundDeadline(t *testing.T) {
	f, reader, sender := newTokenBuyerFixture(t)
	r, err := f.buyer.Prepare(context.Background(), f.request, f.pkg, digest32(1), digest32(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.buyer.Call(context.Background(), r.RequestHash); err != nil {
		t.Fatal(err)
	}
	landTokenBuyerCall(t, f, reader, r)
	report, err := f.buyer.Resolve(context.Background(), r.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(int64(report.RefundClaimDeadline), 0)
	reader.s.wallet.chainTime = now
	reader.s.builder.snapshot.ReadAt.GenUtime = uint32(now.Unix())
	f.buyer.config.Now = func() time.Time { return now }
	report, err = f.buyer.Resolve(context.Background(), r.RequestHash)
	if err != nil || report.Status != "lapsed" || report.RequiredAction != "sweep_expired_request" {
		t.Fatalf("deadline outcome: %+v %v", report, err)
	}
	updated, err := f.buyer.SendLifecycle(context.Background(), r.RequestHash, LifecycleSweep)
	if err != nil || len(updated.Lifecycle) != 1 || updated.Lifecycle[0].PreparedTokenMessage.Operation != LifecycleSweep || sender.sent != 2 {
		t.Fatalf("sweep outcome: %+v %v", updated, err)
	}
}

func TestTokenBuyerSurplusIsTerminalAndCountsAsSpentWithinTheWindow(t *testing.T) {
	for _, reason := range []uint16{1929, 1935} {
		t.Run(fmt.Sprint(reason), func(t *testing.T) {
			f, reader, sender := newTokenBuyerFixture(t)
			r, err := f.buyer.Prepare(context.Background(), f.request, f.pkg, digest32(1), digest32(2))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.buyer.Call(context.Background(), r.RequestHash); err != nil {
				t.Fatal(err)
			}
			landTokenBuyerCall(t, f, reader, r)
			call := reader.s.history.Transactions[0]
			caller, err := nativecore.StandardAddress(r.BuyerWallet)
			if err != nil {
				t.Fatal(err)
			}
			amount, ok := new(big.Int).SetString(r.PriceAtomic, 10)
			if !ok {
				t.Fatal("invalid price")
			}
			call.Logs = []nativecore.ServiceActorTokenLogV1{{Funding: &nativecore.ServiceActorTokenFundingLogV1{QueryID: r.QueryID, From: caller, Amount: amount, Reason: reason, PayoutID: 0}}}
			reader.s.history.Transactions = []toschain.TokenActorTransaction{call}
			delete(reader.s.token.Data.Pending, 1)
			report, err := f.buyer.Resolve(context.Background(), r.RequestHash)
			if err != nil || report.Phase != PhaseFundingSurplus || report.Status != "surplus" || report.RequiredAction != "" || report.RequestID != nil || report.PayoutID != nil || report.ReturnedID != nil {
				t.Fatalf("surplus outcome: %+v %v", report, err)
			}
			key := TokenAssetBudgetKey(r.AssetMaster, r.AssetWalletCodeHash, r.AssetDecimals)
			reserved, err := f.buyer.Journal().ReservedToken(f.buyer.Limits(), saNow)
			if err != nil || reserved[key] == nil || reserved[key].String() != r.PriceAtomic {
				t.Fatalf("spent principal disappeared: %v %v", reserved, err)
			}
			later := saNow.Add(f.buyer.Limits().Window + time.Second)
			reserved, err = f.buyer.Journal().ReservedToken(f.buyer.Limits(), later)
			if err != nil || len(reserved) != 0 {
				t.Fatalf("terminal surplus held budget forever: %v %v", reserved, err)
			}
			if _, err = f.buyer.Call(context.Background(), r.RequestHash); err == nil || sender.sent != 1 {
				t.Fatal("surplus call was resent")
			}
		})
	}
}

func TestTokenBuyerRetriesAfterAPreflightFailure(t *testing.T) {
	f, _, sender := newTokenBuyerFixture(t)
	r, err := f.buyer.Prepare(context.Background(), f.request, f.pkg, digest32(1), digest32(2))
	if err != nil {
		t.Fatal(err)
	}
	sender.preflightFailure = errors.New("temporary build-only failure")
	if _, err = f.buyer.Call(context.Background(), r.RequestHash); !errors.Is(err, sender.preflightFailure) {
		t.Fatalf("preflight failure: %v", err)
	}
	stored, err := f.buyer.Journal().Read(r.RequestHash)
	if err != nil || stored.Phase != PhasePrepared || sender.sent != 0 {
		t.Fatalf("preflight changed the reservation: %+v %v", stored, err)
	}
	sender.preflightFailure = nil
	sent, err := f.buyer.Call(context.Background(), r.RequestHash)
	if err != nil || sent.Phase != PhaseSubmitted || sender.sent != 1 {
		t.Fatalf("retry did not submit: %+v %v", sent, err)
	}
}

func TestTokenLifecycleRetriesAfterAPreflightFailure(t *testing.T) {
	f, reader, sender := newTokenBuyerFixture(t)
	r, err := f.buyer.Prepare(context.Background(), f.request, f.pkg, digest32(1), digest32(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.buyer.Call(context.Background(), r.RequestHash); err != nil {
		t.Fatal(err)
	}
	landTokenBuyerCall(t, f, reader, r)
	report, err := f.buyer.Resolve(context.Background(), r.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(int64(report.ResponseDeadline)+1, 0)
	reader.s.wallet.chainTime = now
	reader.s.builder.snapshot.ReadAt.GenUtime = uint32(now.Unix())
	f.buyer.config.Now = func() time.Time { return now }
	sender.preflightFailure = errors.New("temporary lifecycle build-only failure")
	if _, err = f.buyer.SendLifecycle(context.Background(), r.RequestHash, LifecycleExpire); !errors.Is(err, sender.preflightFailure) {
		t.Fatalf("preflight failure: %v", err)
	}
	stored, err := f.buyer.Journal().Read(r.RequestHash)
	if err != nil || len(stored.Lifecycle) != 0 || sender.sent != 1 {
		t.Fatalf("preflight created a send: %+v %v", stored, err)
	}
	sender.preflightFailure = nil
	sent, err := f.buyer.SendLifecycle(context.Background(), r.RequestHash, LifecycleExpire)
	if err != nil || len(sent.Lifecycle) != 1 || sent.Lifecycle[0].Phase != PhaseSubmitted || sender.sent != 2 {
		t.Fatalf("retry did not submit: %+v %v", sent, err)
	}
}

func TestTokenLifecycleRetriesOnlyAfterFinalizedExpiryWithoutAConsumedSeqno(t *testing.T) {
	for _, scenario := range []string{"before", "at bound", "after", "seqno changed", "missing bound", "wallet read failed"} {
		t.Run(scenario, func(t *testing.T) {
			f, reader, sender := newTokenBuyerFixture(t)
			r, err := f.buyer.Prepare(context.Background(), f.request, f.pkg, digest32(1), digest32(2))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.buyer.Call(context.Background(), r.RequestHash); err != nil {
				t.Fatal(err)
			}
			landTokenBuyerCall(t, f, reader, r)
			report, err := f.buyer.Resolve(context.Background(), r.RequestHash)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(int64(report.ResponseDeadline)+1, 0)
			reader.s.wallet.chainTime = now
			reader.s.wallet.seqno = 5
			reader.s.builder.snapshot.ReadAt.GenUtime = uint32(now.Unix())
			f.buyer.config.Now = func() time.Time { return now }
			sender.failure = errors.New("submission answer lost")
			ambiguous, err := f.buyer.SendLifecycle(context.Background(), r.RequestHash, LifecycleExpire)
			if err == nil || len(ambiguous.Lifecycle) != 1 || ambiguous.Lifecycle[0].Phase != PhaseAmbiguous {
				t.Fatalf("not ambiguous: %+v %v", ambiguous, err)
			}
			first := ambiguous.Lifecycle[0]
			if first.WalletSeqno != 5 || first.ValidUntilBoundUnix != LifecycleValidUntilBound(now) {
				t.Fatalf("missing signing bounds: %+v", first)
			}
			sender.failure = nil
			later := time.Unix(first.ValidUntilBoundUnix+1, 0)
			switch scenario {
			case "before":
				later = time.Unix(first.ValidUntilBoundUnix-1, 0)
			case "at bound":
				later = time.Unix(first.ValidUntilBoundUnix, 0)
			case "seqno changed":
				reader.s.wallet.seqno = 6
			case "missing bound":
				if _, err = f.buyer.Journal().Transition(r.RequestHash, []CallPhase{PhaseAdmitted}, func(record *CallRecord) error { record.Lifecycle[0].ValidUntilBoundUnix = 0; return nil }); err != nil {
					t.Fatal(err)
				}
			case "wallet read failed":
				reader.s.walletSeqnoError = errors.New("wallet checkpoint unavailable")
			}
			reader.s.wallet.chainTime = later
			reader.s.builder.snapshot.ReadAt.GenUtime = uint32(later.Unix())
			now = later
			retried, err := f.buyer.SendLifecycle(context.Background(), r.RequestHash, LifecycleExpire)
			if scenario == "after" {
				if err != nil || sender.sent != 3 || len(retried.Lifecycle) != 2 || retried.Lifecycle[0].Phase != PhaseRefused || retried.Lifecycle[1].Phase != PhaseSubmitted || retried.Lifecycle[0].QueryID == retried.Lifecycle[1].QueryID {
					t.Fatalf("expired retry: %+v %v sends=%d", retried, err, sender.sent)
				}
			} else if err == nil || sender.sent != 2 {
				t.Fatalf("unproved retry: %+v %v sends=%d", retried, err, sender.sent)
			}
		})
	}
}

func TestTokenBuyerRefusesDecimalsThatDoNotFitInAByte(t *testing.T) {
	if d, err := tokenAssetDecimals(255); err != nil || d != 255 {
		t.Fatalf("byte boundary: %d %v", d, err)
	}
	for _, d := range []uint32{256, 511, 1<<32 - 1} {
		if _, err := tokenAssetDecimals(d); err == nil {
			t.Fatalf("decimals %d silently narrowed", d)
		}
	}
}
