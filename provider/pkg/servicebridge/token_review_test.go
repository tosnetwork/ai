package servicebridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func TestTokenProviderBalanceQueryUsesContractVector(t *testing.T) {
	for _, logged := range []bool{true, false} {
		t.Run(fmt.Sprint(logged), func(t *testing.T) {
			w := newTokenWorld(t)
			w.walletAtomic = 100000
			raw, e := os.ReadFile("../../../spec/test-vectors/service-actor-token-conformance-vectors.json")
			if e != nil {
				t.Fatal(e)
			}
			var v struct {
				SAB []string `json:"sab1_surplus"`
			}
			if e = json.Unmarshal(raw, &v); e != nil {
				t.Fatal(e)
			}
			b, e := decodeCellBOCText(v.SAB[0])
			if e != nil {
				t.Fatal(e)
			}
			log, e := nativecore.DecodeServiceActorTokenLog(b)
			if e != nil || log.Balance == nil {
				t.Fatalf("%+v %v", log, e)
			}
			balance := log.Balance
			w.account.Data.NextPayoutID = balance.QueryID
			in := w.action("recover-surplus")
			in.TokenAmount = "100"
			p := w.preview(t, in)
			r, e := RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env())
			if e != nil {
				t.Fatal(e)
			}
			if r.QueryID == balance.QueryID || mustTokenBalanceQuery(t, w) != balance.QueryID {
				t.Fatal("fixture mixed inbound and generated query domains")
			}
			owner := w.account.Data.Owner
			out := cell.BeginCell().MustStoreUInt(0x52545231, 32).MustStoreUInt(balance.PayoutID, 64).MustStoreBigCoins(big.NewInt(100)).MustStoreSlice(owner.Bits, owner.BitLen).MustStoreSlice(owner.Bits, owner.BitLen).MustStoreBigCoins(big.NewInt(20)).MustStoreBigCoins(big.NewInt(0)).MustStoreBoolBit(false).EndCell()

			reply := cell.BeginCell().MustStoreUInt(0x52544232, 32).MustStoreUInt(balance.QueryID, 64).MustStoreBigCoins(balance.Balance).EndCell()
			logs := []nativecore.ServiceActorTokenLogV1{*log}
			if !logged {
				logs = nil
			}
			w.addTokenTx(toschain.TokenActorTransaction{Now: uint32(w.ChainTime().Unix()), Sender: w.account.OwnWallet, BodyBOC: base64.StdEncoding.EncodeToString(reply.ToBOC()), Logs: logs, Outputs: []toschain.TokenActorOutput{{Destination: w.account.OwnWallet, Bounce: true, BodyBOC: base64.StdEncoding.EncodeToString(out.ToBOC())}}})

			w.account.Data.Payouts[balance.PayoutID] = nativecore.ServiceActorTokenPayoutV1{Kind: 6, Recipient: owner, Amount: big.NewInt(100)}
			r, e = RunTokenAction(context.Background(), w.c, in, false, "", w.env())
			if e != nil || r.State != "paying" || r.PayoutID != balance.PayoutID {
				t.Fatalf("%+v %v", r, e)
			}
			// A cached call makes later resolution start at that exact LT/hash.
			call := *r.Transaction
			delivery := cell.BeginCell().MustStoreUInt(0x52544431, 32).MustStoreUInt(balance.PayoutID, 64).MustStoreBigCoins(big.NewInt(100)).MustStoreSlice(owner.Bits, owner.BitLen).EndCell()
			sender, e := nativecore.DeriveServiceActorTokenWallet(owner.Text(), w.account.Data.Route)
			if e != nil {
				t.Fatal(e)
			}
			w.addTokenTx(toschain.TokenActorTransaction{Now: uint32(w.ChainTime().Unix()), Sender: sender, BodyBOC: base64.StdEncoding.EncodeToString(delivery.ToBOC())})
			delete(w.account.Data.Payouts, balance.PayoutID)
			r, e = RunTokenAction(context.Background(), w.c, in, false, "", w.env())
			if e != nil || r.State != "delivered" {
				t.Fatalf("%+v %v", r, e)
			}
			if len(w.anchors) < 2 || w.anchors[len(w.anchors)-1] != call {
				t.Fatal("resolution did not use the exact cached call anchor")
			}
		})
	}
}

func TestTokenProviderBalanceQueryBounceAndSupersession(t *testing.T) {
	for _, bounce := range []bool{true, false} {
		t.Run(map[bool]string{true: "bounce", false: "superseded"}[bounce], func(t *testing.T) {
			w := newTokenWorld(t)
			w.walletAtomic = 100000
			in := w.action("recover-surplus")
			in.TokenAmount = "100"
			p := w.preview(t, in)
			if _, e := RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env()); e != nil {
				t.Fatal(e)
			}
			q := mustTokenBalanceQuery(t, w)
			if bounce {
				w.now = 1800000001
				b := cell.BeginCell().MustStoreUInt(0xffffffff, 32).MustStoreUInt(0x52544231, 32).MustStoreUInt(q, 64).EndCell()
				w.addTokenTx(toschain.TokenActorTransaction{Now: 1800000001, Bounced: true, Sender: w.account.OwnWallet, BodyBOC: base64.StdEncoding.EncodeToString(b.ToBOC())})
			} else {
				// Another caller opens a new query after the old query's TTL.
				w.now = 1800003600
				request, e := nativecore.BuildServiceActorTokenIDBody(nativecore.ServiceActorTokenRecheckOpcode, 99, 7)
				if e != nil {
					t.Fatal(e)
				}
				b := cell.BeginCell().MustStoreUInt(0x52544231, 32).MustStoreUInt(q+1, 64).EndCell()
				w.addTokenTx(toschain.TokenActorTransaction{Now: 1800003600, Sender: "0:" + strings.Repeat("99", 32), Opcode: nativecore.ServiceActorTokenRecheckOpcode, RequestID: 7, BodyBOC: base64.StdEncoding.EncodeToString(request.ToBOC()), Outputs: []toschain.TokenActorOutput{{Destination: w.account.OwnWallet, Bounce: true, BodyBOC: base64.StdEncoding.EncodeToString(b.ToBOC())}}})
			}
			r, e := RunTokenAction(context.Background(), w.c, in, false, "", w.env())
			want := "failed"
			if !bounce {
				want = "superseded"
			}
			if e != nil || r.State != want {
				t.Fatalf("%+v %v", r, e)
			}
		})
	}
}
func TestTokenProviderPauseRetriesOnlyProvenNonDelivery(t *testing.T) {
	for _, failure := range []string{"runner", "wallet", "expiry", "preparation-crash"} {
		t.Run(failure, func(t *testing.T) {
			w := newTokenWorld(t)
			w.report(t, []string{"asset-a"})
			switch failure {
			case "runner":
				w.runnerUnavailable = true
			case "wallet":
				w.walletMismatch = true
			case "expiry":
				w.failSend = true
			case "preparation-crash":
				in := w.action("pause")
				p := w.preview(t, in)
				p.State = "building"
				if e := writeJSON(tokenRecordPath(w.c, in.IdempotencyKey), p, true); e != nil {
					t.Fatal(e)
				}
				// This read does not prepare again and cannot sign after an interruption.
				w.walletUnavailable = true
				env := w.env()
				env.Begin = func(context.Context, NodeConfig, TokenActorConfig) (TokenSession, error) {
					return nil, errors.New("checkpoint unavailable")
				}
				r, e := RunTokenAction(context.Background(), w.c, in, false, "", env)
				if e != nil || r.State != "never_sent" || w.builds != 0 {
					t.Fatalf("%+v %v", r, e)
				}
			}
			_ = CheckTokenSafety(context.Background(), w.c, w.env())
			if failure == "expiry" {
				if w.sends != 1 {
					t.Fatal("missing first broadcast attempt")
				}
				_ = CheckTokenSafety(context.Background(), w.c, w.env())
				if w.sends != 1 {
					t.Fatal("valid unknown message resent")
				}
				w.now = 1800000121
			} else if failure != "preparation-crash" && w.builds != 0 {
				t.Fatal("signed before custody checks")
			}
			w.runnerUnavailable = false
			w.walletMismatch = false
			w.failSend = false
			_ = CheckTokenSafety(context.Background(), w.c, w.env())
			if w.account.Data.Active {
				t.Fatal("recoverable custody error disabled automatic pause")
			}
			if failure == "expiry" {
				entries, e := os.ReadDir(filepath.Join(w.c.StateDir, "token-actions"))
				if e != nil || len(entries) != 1 {
					t.Fatal("missing retry receipt")
				}
				var r TokenActionRecord
				if e = readJSON(filepath.Join(w.c.StateDir, "token-actions", entries[0].Name()), 1<<20, &r); e != nil || len(r.PreviousDeliveries) != 1 || r.PreviousDeliveries[0].Proof == nil {
					t.Fatalf("non-delivery proof not retained: %+v %v", r, e)
				}
				proof := r.PreviousDeliveries[0].Proof
				if proof.State != "expired" || proof.Checkpoint != 100 || proof.ChainTime <= int64(r.PreviousDeliveries[0].ValidUntil) {
					t.Fatal("retry lacked a finalized expiry receipt")
				}
			}

		})
	}
}
func TestTokenProviderPauseNeedsNoTokenWalletAndRaisesRefusal(t *testing.T) {
	w := newTokenWorld(t)
	w.walletUnavailable = true
	w.c.Token.Pins[0].WalletCodeHash = "tvm-cell-sha256:" + strings.Repeat("90", 32)
	w.report(t, []string{"asset-a"})
	_ = CheckTokenSafety(context.Background(), w.c, w.env())
	if w.sends != 1 || w.account.Data.Active {
		t.Fatal("missing own wallet prevented pause")
	}
	w2 := newTokenWorld(t)
	w2.refusedCode = 1903
	w2.report(t, []string{"asset-a"})
	_ = CheckTokenSafety(context.Background(), w2.c, w2.env())
	e := CheckTokenSafety(context.Background(), w2.c, w2.env())
	if !errors.Is(e, ErrTokenPauseRefused) || errors.Is(e, ErrOutcomeUnknown) || !strings.Contains(e.Error(), "1903") {
		t.Fatalf("refusal not alarmed: %v", e)
	}
}
func TestTokenProviderPauseIsAssetScopedAndPreservesPolicy(t *testing.T) {
	w := newTokenWorld(t)
	w.c.Token.Actors[0].AssetID = "usdt"
	other := *w.account
	data := *w.account.Data
	other.Data = &data
	other.Address = "0:" + strings.Repeat("88", 32)
	master, e := nativecore.StandardAddress("0:" + strings.Repeat("77", 32))
	if e != nil {
		t.Fatal(e)
	}
	other.Data.Route.Master = master
	other.OwnWallet, e = nativecore.DeriveServiceActorTokenWallet(other.Address, other.Data.Route)
	if e != nil {
		t.Fatal(e)
	}
	pin := w.c.Token.Pins[0]
	pin.Master = master.Text()
	w.c.Token.Pins = append(w.c.Token.Pins, pin)
	config := w.c.Token.Actors[0]
	config.Address = other.Address
	config.Master = master.Text()
	config.AssetID = "usdc"
	w.c.Token.Actors = append(w.c.Token.Actors, config)
	w.accounts = map[string]*toschain.TokenActorAccount{w.account.Address: w.account, other.Address: &other}

	raw, e := os.ReadFile("../../../spec/test-vectors/service-actor-token-conformance-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Attested struct {
			Data string `json:"deploy_data_boc_base64"`
		} `json:"attested"`
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	root, e := decodeCellBOCText(fixture.Attested.Data)
	if e != nil {
		t.Fatal(e)
	}
	attested, e := nativecore.DecodeServiceActorTokenData(root)
	if e != nil {
		t.Fatal(e)
	}
	w.account.Data.Policy.HasAttestor = attested.Policy.HasAttestor
	w.account.Data.Policy.AttestorKeyID = attested.Policy.AttestorKeyID
	w.account.Data.Policy.AttestorKey = attested.Policy.AttestorKey
	w.account.Data.AttestorKeys = attested.AttestorKeys
	w.account.Data.Policy.OpenAccess = false
	w.account.Data.Policy.RateLimitPerDay = 7
	w.account.Data.Policy.MetadataHash[0] ^= 1
	w.account.Data.Policy.ProofSchemeHash[0] ^= 1
	caller, e := nativecore.StandardAddress("0:" + strings.Repeat("66", 32))
	if e != nil {
		t.Fatal(e)
	}
	w.account.Data.Policy.HasAuthorizedCaller = true
	w.account.Data.Policy.AuthorizedCaller = caller
	before := w.account.Data.Policy
	w.report(t, []string{"usdt"})
	if err := CheckTokenSafety(context.Background(), w.c, w.env()); err != nil {
		t.Fatalf("asset-specific pause failed: %v", err)
	}
	if w.account.Data.Active || !other.Data.Active || w.sends != 1 {
		t.Fatal("asset-specific pause affected USDC or failed to pause USDT")
	}
	// Unconfigured or malformed labels must not prevent another asset's work.
	w.report(t, []string{"usdt", "foreign.asset:/pool-1", strings.Repeat("x", 161)})
	if err := tokenWorkSafety(w.c, "usdc", w, w.ChainTime()); err != nil {
		t.Fatalf("USDC execution stopped by USDT alarm: %v", err)
	}
	if err := tokenWorkSafety(w.c, "usdt", w, w.ChainTime()); err == nil {
		t.Fatal("USDT execution ignored its alarm")
	}
	after := w.account.Data.Policy
	after.PolicyVersion = before.PolicyVersion
	if !reflect.DeepEqual(before, after) {
		t.Fatal("pause changed another policy field")
	}
}

func tokenHumanPolicy(w *tokenWorld) TokenActionInput {
	in := w.action("update-policy")
	in.IdempotencyKey = "human-policy-change-0001"
	in.Policy = &TokenPolicyInput{PriceAtomic: "2000", StorageFeeNanoTOS: "500000000", CleanupBountyNanoTOS: "100000000", MaxLiabilityAtomic: "100000", ResponseSLA: 3600, RefundClaimWindow: 3600}
	return in
}
func TestTokenProviderPauseWaitsForHumanPolicyAndKeepsNewFields(t *testing.T) {
	w := newTokenWorld(t)
	in := tokenHumanPolicy(w)
	p := w.preview(t, in)
	w.deferActor = true
	if _, e := RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env()); e != nil {
		t.Fatal(e)
	}
	w.report(t, []string{"asset-a"})
	if e := CheckTokenSafety(context.Background(), w.c, w.env()); e == nil || w.sends != 1 || w.builds != 1 {
		t.Fatalf("pause did not wait: sends=%d builds=%d %v", w.sends, w.builds, e)
	}
	body, e := decodeCellBOCText(w.builtBody)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := nativecore.DecodeServiceActorTokenInbound(body)
	if e != nil {
		t.Fatal(e)
	}
	version := w.account.Data.Policy.PolicyVersion + 1
	w.account.Data.Policy = *parsed.Policy
	w.account.Data.Policy.PolicyVersion = version
	w.addTokenTx(toschain.TokenActorTransaction{Now: 1800000001, Sender: w.c.WalletAddress, QueryID: parsed.QueryID, Opcode: parsed.Opcode, BodyBOC: w.builtBody})
	w.deferActor = false
	_ = CheckTokenSafety(context.Background(), w.c, w.env())
	if w.account.Data.Active || w.account.Data.Policy.PricePerCall.String() != "2000" || w.sends != 2 {
		t.Fatal("pause overwrote the finalized human policy")
	}
}
func TestTokenProviderPauseExpiresHumanPolicyBeforeReplacingIt(t *testing.T) {
	w := newTokenWorld(t)
	in := tokenHumanPolicy(w)
	p := w.preview(t, in)
	w.failSend = true
	_, _ = RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env())
	w.report(t, []string{"asset-a"})
	_ = CheckTokenSafety(context.Background(), w.c, w.env())
	if w.sends != 1 {
		t.Fatal("pause bypassed in-flight policy")
	}
	w.now = 1800000121
	w.failSend = false
	_ = CheckTokenSafety(context.Background(), w.c, w.env())
	if w.account.Data.Active || w.sends != 2 {
		t.Fatal("pause did not follow proven policy expiry")
	}
}
func TestTokenProviderHumanPreviewCannotUndoALaterPause(t *testing.T) {
	w := newTokenWorld(t)
	in := tokenHumanPolicy(w)
	p := w.preview(t, in)
	w.report(t, []string{"asset-a"})
	_ = CheckTokenSafety(context.Background(), w.c, w.env())
	w.report(t, nil)
	if _, e := RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env()); e == nil || w.sends != 1 || w.account.Data.Active {
		t.Fatal("stale human policy undid the pause")
	}
}
func TestTokenProviderWarningsAreBoundToConfirmation(t *testing.T) {
	w := newTokenWorld(t)
	in := w.action("abandon-payout")
	in.ID = 7
	w.account.Data.Payouts[7] = nativecore.ServiceActorTokenPayoutV1{Kind: 3, Recipient: w.account.Data.Owner, Amount: big.NewInt(100), CreatedAt: 1800000000 - 2592000 + 1}
	p := w.preview(t, in)
	if len(p.Preview.Warnings) == 0 {
		t.Fatal("too-early warning lost")
	}
	w.now = 1800000002
	p2 := w.preview(t, in)
	if len(p2.Preview.Warnings) != 0 || p.Preview.Message.BodyBOC != p2.Preview.Message.BodyBOC || p.Preview.Digest == p2.Preview.Digest {
		t.Fatal("warnings not bound independently of the message bytes")
	}
}

func TestTokenProviderPauseNeverExpiresAnEmittedInternalMessage(t *testing.T) {
	for _, rewrapped := range []bool{false, true} {
		t.Run(fmt.Sprint(rewrapped), func(t *testing.T) {
			w := newTokenWorld(t)
			w.deferActor = true
			w.report(t, []string{"asset-a"})
			_ = CheckTokenSafety(context.Background(), w.c, w.env())
			if w.sends != 1 {
				t.Fatal("initial pause was not sent")
			}
			if rewrapped {
				w.walletTxs[0].ExternalMessageHash = strings.Repeat("ef", 32)
			}
			w.now = 1800000121
			e := CheckTokenSafety(context.Background(), w.c, w.env())
			if e == nil || w.sends != 1 || w.builds != 1 {
				t.Fatal("accepted wallet external was mistaken for non-delivery")
			}
		})
	}
}

func TestTokenProviderInactivePauseFinalizesItsJournal(t *testing.T) {
	w := newTokenWorld(t)
	w.report(t, []string{"asset-a"})
	_ = CheckTokenSafety(context.Background(), w.c, w.env())
	w.report(t, nil)
	if e := CheckTokenSafety(context.Background(), w.c, w.env()); e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(filepath.Join(w.c.StateDir, "token-actions"))
	if e != nil || len(entries) != 1 {
		t.Fatalf("journal %v", e)
	}
	var r TokenActionRecord
	if e = readJSON(filepath.Join(w.c.StateDir, "token-actions", entries[0].Name()), 1<<20, &r); e != nil || r.State != "finalized" || r.Call == nil {
		t.Fatalf("%+v %v", r, e)
	}
}
func TestTokenProviderNullMonitorHookRefusesLocallyButDoesNotPauseOnChain(t *testing.T) {
	w := newTokenWorld(t)
	var report map[string]any
	if e := readJSON(w.c.Token.MonitorReport, 1<<20, &report); e != nil {
		t.Fatal(e)
	}
	report["provider_pause_assets"] = nil
	if e := writeJSON(w.c.Token.MonitorReport, report, false); e != nil {
		t.Fatal(e)
	}
	if e := CheckTokenSafety(context.Background(), w.c, w.env()); e == nil || w.sends != 0 || !w.account.Data.Active {
		t.Fatal("malformed monitoring did not retain the documented fail-open on-chain posture")
	}
}
