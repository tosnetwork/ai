package servicebridge

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type tokenWorld struct {
	now               int64
	walletSeq         uint32
	walletTxs         []toschain.WalletTransaction
	builtBody         string
	builtBOC          string
	builds            int
	runnerUnavailable bool
	walletMismatch    bool
	walletUnavailable bool
	deferActor        bool
	refusedCode       int32
	accounts          map[string]*toschain.TokenActorAccount
	anchors           []toschain.ActorTxID

	states       map[string]*nativev1.NativeStateV1
	c            NodeConfig
	account      *toschain.TokenActorAccount
	history      *toschain.TokenActorHistory
	walletNano   uint64
	walletAtomic int64
	sends        int
	begins       int
	failSend     bool
	change       bool
}

func (w *tokenWorld) Checkpoint() uint64 { return 100 }
func (w *tokenWorld) ChainTime() time.Time {
	if w.now != 0 {
		return time.Unix(w.now, 0)
	}
	return time.Unix(1800000000, 0)
}
func (w *tokenWorld) BlockHashes() (string, string) {
	return "sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("b", 64)
}
func (w *tokenWorld) accountAt(actor string) *toschain.TokenActorAccount {
	if w.accounts != nil {
		return w.accounts[actor]
	}
	return w.account
}
func (w *tokenWorld) ReadTokenActor(_ context.Context, actor string) (*toschain.TokenActorAccount, bool, error) {
	a := w.accountAt(actor)
	return a, a != nil, nil
}
func (w *tokenWorld) ResolveTokenActor(_ context.Context, actor string, _ []toschain.TokenAssetPin, _ bool) (*toschain.ResolvedTokenActor, error) {
	r, f := w.BlockHashes()
	return &toschain.ResolvedTokenActor{Account: w.accountAt(actor), Checkpoint: 100, BlockRoot: r, BlockFile: f}, nil
}
func (w *tokenWorld) ReadTokenWallet(_ context.Context, actor string, _ nativecore.ServiceActorTokenAssetRouteV1) (*toschain.TokenWalletAccount, bool, error) {
	if w.walletUnavailable {
		return nil, false, errors.New("own token wallet unavailable")
	}
	a := w.accountAt(actor)
	return &toschain.TokenWalletAccount{Address: a.OwnWallet, Owner: a.Address, Master: a.Data.Route.Master.Text(), CodeHash: "tvm-cell-sha256:" + hex.EncodeToString(a.Data.Route.WalletCodeHash[:]), BalanceNano: w.walletNano, BalanceAtomic: big.NewInt(w.walletAtomic)}, true, nil
}
func (w *tokenWorld) ReadTokenAsset(context.Context, string, []toschain.TokenAssetPin) (*toschain.TokenAssetRecognition, error) {
	var minter [32]byte
	raw, _ := hex.DecodeString(strings.TrimPrefix(w.c.Token.Pins[0].MinterCodeHash, "tvm-cell-sha256:"))
	copy(minter[:], raw)
	return &toschain.TokenAssetRecognition{Checkpoint: 100, Record: toschain.SettlementAssetV1{Master: w.account.Data.Route.Master.Text(), Status: 1, Decimals: 6, WalletCodeHash: w.account.Data.Route.WalletCodeHash, MinterCodeHash: minter, MaxLiabilityPerActor: mustTokenUnits(w.c.Token.Actors[0].MaxLiabilityAtomic)}}, nil
}
func (w *tokenWorld) ResolveRegistry(_ context.Context, id string) (*nativev1.NativeStateV1, bool, error) {
	v, ok := w.states[id]
	return v, ok, nil
}
func (w *tokenWorld) GetTokenFundingPrices(context.Context, string) ([6]*big.Int, error) {
	return [6]*big.Int{big.NewInt(200000000), big.NewInt(20000000), big.NewInt(20000000), big.NewInt(20000000), big.NewInt(20000000), big.NewInt(400000000)}, nil
}
func (w *tokenWorld) GetTokenAcceptingTokens(context.Context, string) (bool, error) { return true, nil }
func (w *tokenWorld) ReadTokenWalletTerms(context.Context, uint32) (toschain.TokenWalletTerms, error) {
	return toschain.TokenWalletTerms{}, nil
}
func (w *tokenWorld) ReadTokenForwardPrices(context.Context) (toschain.TokenForwardPrices, error) {
	return toschain.TokenForwardPrices{}, nil
}
func (w *tokenWorld) ReadTokenGlobalID(context.Context) (int32, error) { return 3, nil }
func (w *tokenWorld) TokenHistory(_ context.Context, _ string, anchor *toschain.ActorTxID) (*toschain.TokenActorHistory, error) {
	h := *w.history
	if anchor != nil {
		w.anchors = append(w.anchors, *anchor)
		h.Result = toschain.HistoryAnchorReached
		h.Transactions = nil
		for _, tx := range w.history.Transactions {
			if tx.LT > anchor.LT {
				h.Transactions = append(h.Transactions, tx)
			}
		}
	}
	return &h, nil
}
func (w *tokenWorld) WalletSeqno(context.Context, string) (uint32, error) { return w.walletSeq, nil }
func (w *tokenWorld) WalletLastTransaction(context.Context, string) (toschain.ActorTxID, error) {
	return toschain.ActorTxID{LT: 1, Hash: strings.Repeat("e", 64)}, nil
}
func (w *tokenWorld) WalletHistory(context.Context, string, toschain.ActorTxID) (*toschain.WalletHistory, error) {
	return &toschain.WalletHistory{Transactions: w.walletTxs}, nil
}
func (w *tokenWorld) env() TokenEnv {
	return TokenEnv{CheckCustody: func(context.Context, NodeConfig, TokenSession) error { return nil }, Begin: func(context.Context, NodeConfig, TokenActorConfig) (TokenSession, error) { w.begins++; return w, nil }, SetupEnv: SetupEnv{Now: w.ChainTime, Runner: func(TOSCTLConfig, string) (TOSCTLRunner, error) {
		if w.runnerUnavailable {
			return nil, errors.New("runner unavailable")
		}
		return w, nil
	}}}
}

func (w *tokenWorld) Run(_ context.Context, call TOSCTLCall) ([]byte, error) {
	if call.Label == "wallet ls" {
		payer := w.c.WalletAddress
		if w.walletMismatch {
			payer = "0:" + strings.Repeat("99", 32)
		}
		return json.Marshal([]map[string]any{{"name": w.c.WalletName, "address": payer, "state": "active", "balance": "10.0000", "wallet_type": "V3R2"}})
	}
	var body string
	if call.Label == "wallet build token" {
		var dest string
		var value uint64
		for i, arg := range call.Args {
			switch arg {
			case "--body-boc":
				body = call.Args[i+1]
			case "--to":
				dest = call.Args[i+1]
			case "--amount-nanotos":
				n, ok := new(big.Int).SetString(call.Args[i+1], 10)
				if !ok {
					return nil, errors.New("amount")
				}
				value = n.Uint64()
			}
		}
		root, e := decodeCellBOCText(body)
		if e != nil {
			return nil, e
		}
		key := w.currentKey(hex.EncodeToString(root.Hash()))
		var r TokenActionRecord
		if readJSON(tokenRecordPath(w.c, key), 1<<20, &r) != nil || r.State != "building" {
			return nil, errors.New("signing preceded durable preparation")
		}
		to, e := address.ParseRawAddr(dest)
		if e != nil {
			return nil, e
		}
		amount, e := tlb.FromNano(new(big.Int).SetUint64(value), 9)
		if e != nil {
			return nil, e
		}
		internal, e := tlb.ToCell(&tlb.InternalMessage{IHRDisabled: true, Bounce: true, DstAddr: to, Amount: amount, Body: root})
		if e != nil {
			return nil, e
		}
		signed := cell.BeginCell().MustStoreSlice(make([]byte, 64), 512).MustStoreInt(3, 32).MustStoreUInt(0, 32).MustStoreUInt(uint64(w.ChainTime().Unix()+120), 32).MustStoreUInt(uint64(w.walletSeq), 32).MustStoreUInt(3, 8).MustStoreRef(internal).EndCell()
		payer, e := address.ParseRawAddr(w.c.WalletAddress)
		if e != nil {
			return nil, e
		}
		external, e := tlb.ToCell(&tlb.ExternalMessage{DstAddr: payer, Body: signed})
		if e != nil {
			return nil, e
		}
		w.builtBody = body
		w.builtBOC = base64.StdEncoding.EncodeToString(external.ToBOC())
		w.builds++
		return json.Marshal(map[string]any{"version": "tosctl.wallet-prepared-send.v1", "wallet": w.c.WalletName, "payer": w.c.WalletAddress, "destination": dest, "amount_nanotos": value, "body_hash": "tvm-cell-sha256:" + hex.EncodeToString(root.Hash()), "state_init_hash": "", "message_boc_base64": w.builtBOC})
	}
	if call.Label != "wallet broadcast token" {
		return nil, errors.New("unexpected custody command")
	}
	body = w.builtBody
	root, err := decodeCellBOCText(body)
	if err != nil {
		return nil, err
	}
	in, err := nativecore.DecodeServiceActorTokenInbound(root)
	if err != nil {
		return nil, err
	}
	key := w.currentKey(takeTokenBodyHash(root.Hash()))
	var record TokenActionRecord
	if err = readJSON(tokenRecordPath(w.c, key), 1<<20, &record); err != nil {
		return nil, errors.New("send preceded durable journal")
	}
	if record.State != "submitted" {
		return nil, errors.New("journal did not fence signing")
	}
	if record.Delivery == nil || record.Delivery.ValidUntil != uint32(w.ChainTime().Unix()+120) {
		return nil, errors.New("broadcast without signed fence")
	}
	w.sends++
	if w.failSend {
		return nil, errors.New("broadcast outcome unknown")
	}
	w.walletTxs = append(w.walletTxs, toschain.WalletTransaction{LT: uint64(2 + w.sends), ExternalMessageHash: record.Delivery.MessageHash, Out: []toschain.WalletOutMessage{{Destination: record.Input.Actor, QueryID: in.QueryID, Known: true}}})
	w.walletSeq++
	savedAccount := w.account
	w.account = w.accountAt(record.Input.Actor)
	defer func() { w.account = savedAccount }()
	if w.deferActor {
		return []byte(`{}`), nil
	}
	tx := toschain.TokenActorTransaction{LT: uint64(10 + w.sends), Hash: strings.Repeat("c", 64), Now: uint32(w.ChainTime().Unix()), Sender: w.c.WalletAddress, QueryID: in.QueryID, Opcode: in.Opcode, TookEffect: true, BodyBOC: body}
	if w.refusedCode != 0 {
		tx.TookEffect = false
		tx.ExitCode = w.refusedCode
	}
	if in.Opcode == nativecore.ServiceActorTokenRecoverOpcode || in.Opcode == nativecore.ServiceActorTokenRecheckOpcode {
		q := w.account.Data.NextPayoutID
		w.account.Data.NextPayoutID++
		provided := cell.BeginCell().MustStoreUInt(0x52544231, 32).MustStoreUInt(q, 64).EndCell()
		tx.Outputs = []toschain.TokenActorOutput{{Destination: w.account.OwnWallet, Bounce: true, BodyBOC: base64.StdEncoding.EncodeToString(provided.ToBOC())}}
	}
	if in.Opcode == nativecore.ServiceActorTokenWithdrawOpcode && in.TokenAmount != nil && in.TokenAmount.Sign() > 0 {
		owner := w.account.Data.Owner
		reported := cell.BeginCell().MustStoreUInt(0x52545231, 32).MustStoreUInt(7, 64).MustStoreBigCoins(in.TokenAmount).MustStoreSlice(owner.Bits, owner.BitLen).MustStoreSlice(owner.Bits, owner.BitLen).MustStoreBigCoins(big.NewInt(20000000)).MustStoreBigCoins(big.NewInt(0)).MustStoreBoolBit(false).EndCell()
		tx.Outputs = []toschain.TokenActorOutput{{Destination: w.account.OwnWallet, Bounce: true, BodyBOC: base64.StdEncoding.EncodeToString(reported.ToBOC())}}
		w.account.Data.Payouts[7] = nativecore.ServiceActorTokenPayoutV1{Kind: 3, Recipient: owner, Amount: in.TokenAmount}
	}
	w.history.Transactions = append(w.history.Transactions, tx)
	w.account.LastTransaction = toschain.ActorTxID{LT: tx.LT, Hash: tx.Hash}
	w.history.Head = w.account.LastTransaction
	if in.Policy != nil && tx.TookEffect {
		version := w.account.Data.Policy.PolicyVersion + 1
		hasAttestor, key, keyBytes := w.account.Data.Policy.HasAttestor, w.account.Data.Policy.AttestorKeyID, w.account.Data.Policy.AttestorKey
		w.account.Data.Policy = *in.Policy
		w.account.Data.Policy.HasAttestor, w.account.Data.Policy.AttestorKeyID = hasAttestor, key
		w.account.Data.Policy.AttestorKey = keyBytes
		w.account.Data.Policy.PolicyVersion = version
		w.account.Data.Active = in.Active
	}
	return []byte(`{}`), nil
}
func takeTokenBodyHash(hash []byte) string { return hex.EncodeToString(hash) }
func (w *tokenWorld) currentKey(bodyHash string) string {
	entries, _ := os.ReadDir(filepath.Join(w.c.StateDir, "token-actions"))
	for _, entry := range entries {
		var r TokenActionRecord
		if readJSON(filepath.Join(w.c.StateDir, "token-actions", entry.Name()), 1<<20, &r) == nil && r.BodyHash == bodyHash {
			return r.Input.IdempotencyKey
		}
	}
	return "missing"
}
func newTokenWorld(t *testing.T) *tokenWorld {
	t.Helper()
	raw, err := os.ReadFile("../../../spec/test-vectors/service-actor-token-conformance-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Actor string `json:"actor"`
		Data  string `json:"deploy_data_boc_base64"`
		Code  string `json:"contract_code_hash"`
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	b, err := base64.StdEncoding.DecodeString(v.Data)
	if err != nil {
		t.Fatal(err)
	}
	root, err := decodeCellBOCText(base64.StdEncoding.EncodeToString(b))
	if err != nil {
		t.Fatal(err)
	}
	d, err := nativecore.DecodeServiceActorTokenData(root)
	if err != nil {
		t.Fatal(err)
	}
	d.Active = true
	d.Accounting.WithdrawableTOSRevenue = big.NewInt(2000000000)
	d.Accounting.Ledger.WithdrawableTokenRevenue = big.NewInt(10000)
	own, err := nativecore.DeriveServiceActorTokenWallet(v.Actor, d.Route)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	if err = os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	pin := toschain.TokenAssetPin{Master: d.Route.Master.Text(), WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(d.Route.WalletCodeHash[:]), MinterCodeHash: "tvm-cell-sha256:" + strings.Repeat("11", 32), BridgeCodeHash: "tvm-cell-sha256:" + strings.Repeat("22", 32), Bridge: "-1:" + strings.Repeat("33", 32), BridgeConfigParam: d.Route.BridgeConfigParam, Decimals: 6, SourceChainID: 1}
	pin.SourceToken[19] = 1
	a := TokenActorConfig{Address: v.Actor, CodeHash: v.Code, AssetID: "asset-a", Master: pin.Master, CapabilityID: "cap_" + strings.Repeat("44", 32), Version: "1.0.0", ManifestFile: filepath.Join(state, "manifest.cbor"), MinPriceAtomic: "1", MaxPriceAtomic: "1000000000000", MaxLiabilityAtomic: "1000000000000000000000000000000", MaxStorageFeeNanoTOS: "10000000000", MaxCleanupBountyNanoTOS: "1000000000", MinActorFreeNanoTOS: "100000000", MinWalletNanoTOS: "200000000"}
	c := NodeConfig{StateDir: state, WalletName: "owner", WalletAddress: d.Owner.Text(), Token: &TokenProviderConfig{Pins: []toschain.TokenAssetPin{pin}, Actors: []TokenActorConfig{a}, MonitorReport: filepath.Join(state, "report.json")}}
	if err = c.Token.Validate(); err != nil {
		t.Fatal(err)
	}
	w := &tokenWorld{c: c, account: &toschain.TokenActorAccount{Address: v.Actor, CodeHash: v.Code, Data: d, OwnWallet: own, BalanceNano: 10000000000}, history: &toschain.TokenActorHistory{Result: toschain.HistoryComplete}, walletNano: 1000000000, walletAtomic: 1}
	w.report(t, nil)
	return w
}
func (w *tokenWorld) report(t *testing.T, assets []string) {
	t.Helper()
	if assets == nil {
		assets = []string{}
	}
	if err := writeJSON(w.c.Token.MonitorReport, map[string]any{"schema": "tos-settlement-report/1", "checkpoint": map[string]any{"height": 100, "utime": 1800000000, "hash": strings.Repeat("a", 64)}, "provider_pause_assets": assets, "alarms": []any{}}, false); err != nil {
		t.Fatal(err)
	}
}
func (w *tokenWorld) action(operation string) TokenActionInput {
	return TokenActionInput{Actor: w.account.Address, Operation: operation, IdempotencyKey: "token-operation-test-0001"}
}
func (w *tokenWorld) preview(t *testing.T, in TokenActionInput) *TokenActionRecord {
	t.Helper()
	r, err := RunTokenAction(context.Background(), w.c, in, false, "", w.env())
	if !errors.Is(err, ErrConfirmationRequired) {
		t.Fatal(err)
	}
	return r
}
func TestTokenProviderWithdrawsBothRevenuesAndNeverResendsUnknown(t *testing.T) {
	for _, kind := range []string{"token", "tos", "both"} {
		t.Run(kind, func(t *testing.T) {
			w := newTokenWorld(t)
			in := w.action("withdraw-revenue")
			if kind != "tos" {
				in.TokenAmount = "100"
			}
			if kind != "token" {
				in.TOSAmount = "100000000"
			}
			p := w.preview(t, in)
			if w.sends != 0 {
				t.Fatal("preview sent")
			}
			w.failSend = true
			r, err := RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env())
			if err == nil || r.State != "submitted" || w.sends != 1 {
				t.Fatalf("%+v %v", r, err)
			}
			_, _ = RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env())
			if w.sends != 1 {
				t.Fatal("unknown withdrawal resubmitted")
			}
		})
	}
}
func TestTokenProviderChangedPreviewAndVisibleRefusalsSignNothing(t *testing.T) {
	for _, kind := range []string{"preview", "owner", "credit", "floor", "wallet-floor", "liability", "unused", "alarm"} {
		t.Run(kind, func(t *testing.T) {
			w := newTokenWorld(t)
			in := w.action("withdraw-revenue")
			in.TokenAmount = "100"
			p := w.preview(t, in)
			switch kind {
			case "preview":
				w.account.Data.Accounting.Ledger.WithdrawableTokenRevenue = big.NewInt(9000)
			case "owner":
				w.c.WalletAddress = "0:" + strings.Repeat("99", 32)
			case "credit":
				w.account.Data.Accounting.Ledger.WithdrawableTokenRevenue = big.NewInt(50)
			case "floor":
				in.TOSAmount = "10000000000"
			case "wallet-floor":
				in = w.action("resume")
				w.walletNano = 0
			case "liability":
				in = w.action("update-policy")
				in.Policy = &TokenPolicyInput{PriceAtomic: "999999999999999999", StorageFeeNanoTOS: "200000000", CleanupBountyNanoTOS: "100000000", MaxLiabilityAtomic: "10000", ResponseSLA: 3600, RefundClaimWindow: 3600}
			case "unused":
				in.TOSAmount = "-1"
			case "alarm":
				in = w.action("resume")
				w.report(t, []string{"asset-a"})
			}
			if _, err := RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env()); err == nil || errors.Is(err, ErrConfirmationRequired) {
				t.Fatal("unsafe token action accepted")
			}
			if w.sends != 0 {
				t.Fatal("refusal signed")
			}
		})
	}
}
func TestTokenProviderAutoPauseIsSignedOwnedAndAssetScoped(t *testing.T) {
	w := newTokenWorld(t)
	w.report(t, []string{"another-asset"})
	if err := CheckTokenSafety(context.Background(), w.c, w.env()); err != nil {
		t.Fatal(err)
	}
	if w.sends != 0 {
		t.Fatal("foreign asset alarm paused actor")
	}
	w.report(t, []string{"asset-a"})
	_ = CheckTokenSafety(context.Background(), w.c, w.env())
	if w.sends != 1 || w.account.Data.Active {
		t.Fatalf("sends=%d active=%t", w.sends, w.account.Data.Active)
	}
	if err := CheckTokenSafety(context.Background(), w.c, w.env()); err != nil {
		t.Fatal(err)
	}
	if w.sends != 1 {
		t.Fatal("inactive actor signed again")
	}
}
func TestTokenProviderPendingPauseCoalescesAndMonitorFailureRefusesResume(t *testing.T) {
	w := newTokenWorld(t)
	w.failSend = true
	w.report(t, []string{"asset-a"})
	for i := 0; i < 3; i++ {
		if err := CheckTokenSafety(context.Background(), w.c, w.env()); err == nil || errors.Is(err, ErrConfirmationRequired) {
			t.Fatal("unresolved pause hidden")
		}
	}
	if w.sends != 1 {
		t.Fatal("emergency pause submitted repeatedly")
	}
	w2 := newTokenWorld(t)
	if err := os.WriteFile(w2.c.Token.MonitorReport, []byte(`{"schema":"bad"}`), 0600); err != nil {
		t.Fatal(err)
	}
	in := w2.action("resume")
	if _, err := RunTokenAction(context.Background(), w2.c, in, false, "", w2.env()); err == nil || errors.Is(err, ErrConfirmationRequired) {
		t.Fatal("invalid monitor permitted resume")
	}
}
func TestTokenProviderTOSFloorPreservesCustomerLocks(t *testing.T) {
	w := newTokenWorld(t)
	w.account.Data.Accounting.LockedStorageFees = big.NewInt(8000000000)
	w.account.Data.Accounting.LockedOutcomeFees = big.NewInt(0)
	in := w.action("withdraw-revenue")
	in.TOSAmount = "950000000"
	if _, err := RunTokenAction(context.Background(), w.c, in, false, "", w.env()); err == nil || errors.Is(err, ErrConfirmationRequired) {
		t.Fatal("withdrawal consumed customer backing")
	}
}

func TestTokenProviderRecoveryPolicyAndAbandonUseProtocolPrechecks(t *testing.T) {
	for _, op := range []string{"recover-surplus", "recheck-payout", "abandon-payout", "update-policy"} {
		t.Run(op, func(t *testing.T) {
			w := newTokenWorld(t)
			in := w.action(op)
			switch op {
			case "recover-surplus":
				in.TokenAmount = "1" // Mock balance is below attributed: no invented surplus.
			case "recheck-payout", "abandon-payout":
				in.ID = 1 // No such payout in finalized cells.
			case "update-policy":
				in.Policy = &TokenPolicyInput{PriceAtomic: "1000", StorageFeeNanoTOS: "300000000", CleanupBountyNanoTOS: "100000000", MaxLiabilityAtomic: "1000000", ResponseSLA: 3600, RefundClaimWindow: 3600}
			}
			p, err := RunTokenAction(context.Background(), w.c, in, false, "", w.env())
			if op == "update-policy" {
				if !errors.Is(err, ErrConfirmationRequired) || p == nil {
					t.Fatal(err)
				}
				if _, err = RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env()); err != nil {
					t.Fatal(err)
				}
				if w.sends != 1 {
					t.Fatal("confirmed policy not signed")
				}
			}
			if op != "update-policy" && (err == nil || w.sends != 0) {
				t.Fatal("visible recovery refusal reached signing")
			}
		})
	}
}
func TestTokenProviderActorAndWalletFloorsAreSeparate(t *testing.T) {
	for _, which := range []string{"actor", "wallet"} {
		t.Run(which, func(t *testing.T) {
			w := newTokenWorld(t)
			a := w.c.Token.Actors[0]
			okActor, okWallet, err := tokenFloors(context.Background(), w.c, a, w)
			if err != nil || !okActor || !okWallet {
				t.Fatal("positive floor control", err)
			}
			if which == "actor" {
				w.account.BalanceNano = 1000000000
			} else {
				w.walletNano = 1
			}
			okActor, okWallet, err = tokenFloors(context.Background(), w.c, a, w)
			if err != nil {
				t.Fatal(err)
			}
			if which == "actor" && (okActor || !okWallet) || which == "wallet" && (!okActor || okWallet) {
				t.Fatal("one floor changed the other")
			}
			if _, err = RunTokenAction(context.Background(), w.c, w.action("resume"), false, "", w.env()); err == nil || errors.Is(err, ErrConfirmationRequired) {
				t.Fatal("floor breach permitted active offer")
			}
		})
	}
}
func TestTokenProviderJournalRefusesInputReuseAndWriteFailure(t *testing.T) {
	w := newTokenWorld(t)
	in := w.action("withdraw-revenue")
	in.TokenAmount = "100"
	p := w.preview(t, in)
	w.failSend = true
	_, _ = RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env())
	in.TokenAmount = "101"
	if _, err := RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env()); err == nil || w.sends != 1 {
		t.Fatal("idempotency key rebound")
	}
	w2 := newTokenWorld(t)
	in = w2.action("withdraw-revenue")
	in.TokenAmount = "100"
	p = w2.preview(t, in)
	path := tokenRecordPath(w2.c, in.IdempotencyKey)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := RunTokenAction(context.Background(), w2.c, in, true, p.Preview.Digest, w2.env()); err == nil || w2.sends != 0 {
		t.Fatal("journal failure reached custody")
	}
}

func TestTokenProviderOfferUsesAtomicRegistryAssetAndFloorChecks(t *testing.T) {
	w := newTokenWorld(t)
	raw, err := os.ReadFile("../../../spec/test-vectors/service-actor-token-conformance-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Attested struct {
			Actor string `json:"actor"`
			Data  string `json:"deploy_data_boc_base64"`
		} `json:"attested"`
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	root, err := decodeCellBOCText(v.Attested.Data)
	if err != nil {
		t.Fatal(err)
	}
	d, err := nativecore.DecodeServiceActorTokenData(root)
	if err != nil {
		t.Fatal(err)
	}
	w.account.Data = d
	d.Active = true
	w.account.Address = v.Attested.Actor
	w.c.Token.Actors[0].Address = w.account.Address
	w.c.WalletAddress = d.Owner.Text()
	w.c.AgentID = "agent_" + strings.Repeat("55", 32)
	w.c.Network = NetworkConfig{NetworkID: "token-test", GenesisRootHash: "sha256:" + strings.Repeat("66", 32), GenesisFileHash: "sha256:" + strings.Repeat("77", 32)}
	w.account.OwnWallet, err = nativecore.DeriveServiceActorTokenWallet(w.account.Address, d.Route)
	if err != nil {
		t.Fatal(err)
	}
	d.Policy.MaxTokenLiability = mustTokenUnits(w.c.Token.Actors[0].MaxLiabilityAtomic)
	d.Policy.ProofSchemeHash = nativecore.ServiceActorSoftwareWorkProofScheme
	a := w.c.Token.Actors[0]
	manifest, digest, _, err := BuildTokenManifest(ManifestInput{Actor: a.Address, ActorCodeHash: a.CodeHash, ProviderAgentID: w.c.AgentID, Attestor: "mldsa44:" + hex.EncodeToString(d.Policy.AttestorKeyID[:]), Version: a.Version, RetentionSeconds: 86400}, w.c.Token.Pins[0])
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(a.ManifestFile, manifest, 0600); err != nil {
		t.Fatal(err)
	}
	d.Policy.MetadataHash, err = nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: networkOf(w.c), CapabilityID: a.CapabilityID, ProviderAgentID: w.c.AgentID, CapabilityVersion: a.Version, ManifestDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	w.states = map[string]*nativev1.NativeStateV1{
		a.CapabilityID: {Network: networkOf(w.c), Reference: &nativev1.ChainReference{FinalizedCheckpoint: 100}, State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{CapabilityId: a.CapabilityID, OwnerAgentId: w.c.AgentID, Versions: []*nativev1.CapabilityVersionV1{{Version: a.Version, ManifestDigest: digest}}}}},
		w.c.AgentID:    {Network: networkOf(w.c), Reference: &nativev1.ChainReference{FinalizedCheckpoint: 100}, State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: w.c.AgentID}}},
	}
	before := w.begins
	if _, err = TokenOffer(context.Background(), w.c, a.Address, w.env()); err != nil {
		t.Fatal(err)
	}
	if w.begins != before+1 {
		t.Fatal("offer combined checkpoints")
	}
	encoded, err := ExportTokenOffer(context.Background(), w.c, a.Address, w.env())
	if err != nil {
		t.Fatal(err)
	}
	offer, err := DecodeOfferFile(encoded)
	if err != nil || offer.ManifestDigest != digest {
		t.Fatal("token offer export", err)
	}
	w.walletNano = 0
	if _, err = TokenOffer(context.Background(), w.c, a.Address, w.env()); err == nil || errors.Is(err, ErrConfirmationRequired) {
		t.Fatal("offer advertised below wallet floor")
	}
	w.walletNano = 1000000000
	w.report(t, []string{"asset-a"})
	if _, err = TokenOffer(context.Background(), w.c, a.Address, w.env()); err == nil || errors.Is(err, ErrConfirmationRequired) {
		t.Fatal("alarmed offer advertised")
	}
}

func TestTokenProviderWithdrawalFollowsDeliveryAndSettledRetryIsReadOnly(t *testing.T) {
	w := newTokenWorld(t)
	in := w.action("withdraw-revenue")
	in.TokenAmount = "100"
	p := w.preview(t, in)
	if _, err := RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env()); err != nil {
		t.Fatal(err)
	}
	r, err := RunTokenAction(context.Background(), w.c, in, false, "", w.env())
	if err != nil || r.State != "paying" || r.PayoutID != 7 {
		t.Fatalf("%+v %v", r, err)
	}
	owner := w.account.Data.Owner
	body := cell.BeginCell().MustStoreUInt(0x52544431, 32).MustStoreUInt(7, 64).MustStoreBigCoins(big.NewInt(100)).MustStoreSlice(owner.Bits, owner.BitLen).EndCell()
	sender, err := nativecore.DeriveServiceActorTokenWallet(owner.Text(), w.account.Data.Route)
	if err != nil {
		t.Fatal(err)
	}
	tx := toschain.TokenActorTransaction{LT: 20, Hash: strings.Repeat("d", 64), Now: 1800000000, TookEffect: true, Sender: sender, BodyBOC: base64.StdEncoding.EncodeToString(body.ToBOC())}
	w.history.Transactions = append(w.history.Transactions, tx)
	w.account.LastTransaction = toschain.ActorTxID{LT: tx.LT, Hash: tx.Hash}
	w.history.Head = w.account.LastTransaction
	delete(w.account.Data.Payouts, 7)
	for i := 0; i < 2; i++ {
		r, err = RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env())
		if err != nil || r.State != "delivered" || w.sends != 1 {
			t.Fatalf("%+v err=%v sends=%d", r, err, w.sends)
		}
	}
}

func TestTokenProviderRecoveryAndAbandonCanResolveAnOpenWithdrawal(t *testing.T) {
	for _, op := range []string{"abandon-payout", "recheck-payout"} {
		t.Run(op, func(t *testing.T) {
			w := newTokenWorld(t)
			in := w.action("withdraw-revenue")
			in.TokenAmount = "100"
			p := w.preview(t, in)
			if _, err := RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env()); err != nil {
				t.Fatal(err)
			}
			recovery := w.action(op)
			recovery.IdempotencyKey = "token-recovery-test-0002"
			recovery.ID = 7
			if op == "recheck-payout" {
				q := w.account.Data.Payouts[7]
				q.Kind = 1
				w.account.Data.Payouts[7] = q
			}
			preview := w.preview(t, recovery)
			if _, err := RunTokenAction(context.Background(), w.c, recovery, true, preview.Preview.Digest, w.env()); err != nil || w.sends != 2 {
				t.Fatalf("recovery blocked: %v sends=%d", err, w.sends)
			}
			if op == "abandon-payout" {
				r, err := RunTokenAction(context.Background(), w.c, recovery, false, "", w.env())
				if err != nil || r.State != "abandoned" {
					t.Fatalf("%+v %v", r, err)
				}
			}
		})
	}
}
func TestTokenProviderMonitorRefusesMissingStaleAndDuplicateHooks(t *testing.T) {
	for _, raw := range []string{
		`{"schema":"tos-settlement-report/1","checkpoint":{"height":100,"hash":"` + strings.Repeat("a", 64) + `","utime":1799999000},"provider_pause_assets":[]}`,
		`{"schema":"tos-settlement-report/1","checkpoint":{"height":100,"hash":"` + strings.Repeat("a", 64) + `","utime":1800000000}}`,
		`{"schema":"tos-settlement-report/1","checkpoint":{"height":100,"hash":"` + strings.Repeat("a", 64) + `","utime":1800000000},"provider_pause_assets":[],"provider_pause_assets":[]}`,
	} {
		w := newTokenWorld(t)
		if err := os.WriteFile(w.c.Token.MonitorReport, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if err := CheckTokenSafety(context.Background(), w.c, w.env()); err == nil || w.sends != 0 {
			t.Fatal("malformed monitor accepted")
		}
		if _, err := RunTokenAction(context.Background(), w.c, w.action("resume"), false, "", w.env()); err == nil || errors.Is(err, ErrConfirmationRequired) {
			t.Fatal("missing monitor permitted resume")
		}
	}
}

func TestTokenProviderSurplusRecoveryUsesWalletBalanceAndBalanceOutcome(t *testing.T) {
	w := newTokenWorld(t)
	w.walletAtomic = 100000
	in := w.action("recover-surplus")
	in.TokenAmount = "100"
	p := w.preview(t, in)
	if _, err := RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env()); err != nil {
		t.Fatal(err)
	}
	// The wallet's finalized balance response can refuse a recovery after the
	// initial call executed. Execution of the owner call alone is not success.
	tx := toschain.TokenActorTransaction{LT: 20, Hash: strings.Repeat("d", 64), TookEffect: true, Logs: []nativecore.ServiceActorTokenLogV1{{Balance: &nativecore.ServiceActorTokenBalanceLogV1{QueryID: mustTokenBalanceQuery(t, w), Purpose: 0, Result: 1936}}}}
	w.history.Transactions = append(w.history.Transactions, tx)
	w.account.LastTransaction = toschain.ActorTxID{LT: tx.LT, Hash: tx.Hash}
	w.history.Head = w.account.LastTransaction
	r, err := RunTokenAction(context.Background(), w.c, in, false, "", w.env())
	if err != nil || r.State != "failed" || w.sends != 1 {
		t.Fatalf("%+v %v", r, err)
	}
}
func mustTokenQuery(t *testing.T, w *tokenWorld, in TokenActionInput) uint64 {
	t.Helper()
	var r TokenActionRecord
	if err := readJSON(tokenRecordPath(w.c, in.IdempotencyKey), 1<<20, &r); err != nil {
		t.Fatal(err)
	}
	return r.QueryID
}

func TestTokenProviderConfirmedResumeReconcilesItsAutomaticPause(t *testing.T) {
	w := newTokenWorld(t)
	w.report(t, []string{"asset-a"})
	_ = CheckTokenSafety(context.Background(), w.c, w.env())
	if w.account.Data.Active || w.sends != 1 {
		t.Fatal("pause did not execute")
	}
	w.report(t, nil)
	in := w.action("resume")
	p := w.preview(t, in)
	if _, err := RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env()); err != nil || !w.account.Data.Active || w.sends != 2 {
		t.Fatalf("resume blocked by finalized automatic pause: %v", err)
	}
}

func mustTokenBalanceQuery(t *testing.T, w *tokenWorld) uint64 {
	t.Helper()
	for i := len(w.history.Transactions) - 1; i >= 0; i-- {
		if id, e := tokenQueryID(w.history.Transactions[i], w.account.OwnWallet); e == nil {
			return id
		}
	}
	t.Fatal("missing provide_balance")
	return 0
}
