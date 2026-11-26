package servicebridge

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// The returned entry is 7, while its claim/sweep has payout id 8. A recheck
// restores entry 7 even when the best-effort outcome log is absent.
func tokenRecheckedWorld(t *testing.T, kind uint8) *tokenWorld {
	t.Helper()
	w := newTokenWorld(t)
	d := w.account.Data
	d.Pending = map[uint64]nativecore.ServiceActorPendingRequestV1{}
	d.Refunds = map[uint64]nativecore.ServiceActorRefundV1{}
	d.Payouts = map[uint64]nativecore.ServiceActorTokenPayoutV1{}
	d.Returned = map[uint64]nativecore.ServiceActorTokenReturnedV1{}
	caller := d.Owner
	var master [32]byte
	copy(master[:], d.Route.Master.Address)
	terms := nativecore.ServiceActorTokenTermsV1{ServiceActorTermsV1: nativecore.ServiceActorTermsV1{PricePerCall: big.NewInt(1000), StorageFee: big.NewInt(200), CleanupBounty: big.NewInt(10), ResponseSLA: 10, RefundClaimWindow: 20}, AssetMasterHash: master, AssetWalletCodeHash: d.Route.WalletCodeHash}
	root, err := nativecore.BuildServiceActorTokenTerms(terms)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := nativecore.ServiceActorTokenRequestSnapshotV1{RequestID: 1, Caller: caller, ResponseDeadline: 1799999810, RefundClaimDeadline: 1799999830, Terms: terms}
	snapshot.RequestHash[0] = 1
	copy(snapshot.TermsHash[:], root.Hash())
	w.addTokenTx(toschain.TokenActorTransaction{Now: 1799999800, Sender: w.account.OwnWallet, Notification: &toschain.TokenActorNotification{AmountAtomic: "1000", From: caller.Text(), Payload: &nativecore.TokenCallPayloadV1{RequestHash: snapshot.RequestHash, ExpectedTermsHash: snapshot.TermsHash}}, Logs: []nativecore.ServiceActorTokenLogV1{{Snapshot: &snapshot}}})
	boc := func(c *cell.Cell) string { return base64.StdEncoding.EncodeToString(c.ToBOC()) }
	idBody := func(op uint32, id uint64) *cell.Cell {
		b, e := nativecore.BuildServiceActorTokenIDBody(op, 2, id)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	transfer := func(id uint64) []toschain.TokenActorOutput {
		b := cell.BeginCell().MustStoreUInt(0x52545231, 32).MustStoreUInt(id, 64).MustStoreBigCoins(big.NewInt(1000)).MustStoreSlice(caller.Bits, caller.BitLen).MustStoreSlice(caller.Bits, caller.BitLen).MustStoreBigCoins(big.NewInt(20)).MustStoreBigCoins(big.NewInt(0)).MustStoreBoolBit(false).EndCell()
		return []toschain.TokenActorOutput{{Destination: w.account.OwnWallet, Bounce: true, BodyBOC: boc(b)}}
	}
	w.addTokenTx(toschain.TokenActorTransaction{Now: 1799999811, Opcode: nativecore.ServiceActorTokenExpireOpcode, RequestID: 1, Sender: caller.Text(), BodyBOC: boc(idBody(nativecore.ServiceActorTokenExpireOpcode, 1))})
	if kind == 5 {
		b, e := nativecore.BuildServiceActorTokenClaimBody(nativecore.ServiceActorTokenClaimRefundOpcode, 3, 1, caller.Text())
		if e != nil {
			t.Fatal(e)
		}
		w.addTokenTx(toschain.TokenActorTransaction{Now: 1799999812, Opcode: nativecore.ServiceActorTokenClaimRefundOpcode, RequestID: 1, Sender: caller.Text(), Destination: caller.Text(), BodyBOC: boc(b), Outputs: transfer(7)})
	} else {
		w.addTokenTx(toschain.TokenActorTransaction{Now: 1799999831, Opcode: nativecore.ServiceActorTokenSweepOpcode, RequestID: 1, Sender: caller.Text(), BodyBOC: boc(idBody(nativecore.ServiceActorTokenSweepOpcode, 1)), Outputs: transfer(7)})
	}
	refused := cell.BeginCell().MustStoreUInt(0x52544631, 32).MustStoreUInt(7, 64).MustStoreBigCoins(big.NewInt(1000)).EndCell()
	w.addTokenTx(toschain.TokenActorTransaction{Now: 1799999832, Sender: w.account.OwnWallet, BodyBOC: boc(refused)})
	op := uint32(nativecore.ServiceActorTokenClaimReturnedOpcode)
	b, err := nativecore.BuildServiceActorTokenClaimBody(op, 4, 7, caller.Text())
	if err != nil {
		t.Fatal(err)
	}
	if kind == 7 {
		op = nativecore.ServiceActorTokenSweepReturnedOpcode
		b = idBody(op, 7)
	}
	w.addTokenTx(toschain.TokenActorTransaction{Now: 1799999834, Opcode: op, RequestID: 7, Sender: caller.Text(), Destination: caller.Text(), BodyBOC: boc(b), Outputs: transfer(8)})
	d.NextPayoutID = 9
	d.Payouts[8] = nativecore.ServiceActorTokenPayoutV1{Kind: kind, RequestID: 7, Recipient: caller, Requester: caller, Amount: big.NewInt(1000), OutcomeFeeLock: big.NewInt(0)}
	return w
}
func (w *tokenWorld) addTokenTx(tx toschain.TokenActorTransaction) {
	tx.LT = uint64(len(w.history.Transactions) + 1)
	if n := len(w.history.Transactions); n > 0 && tx.LT <= w.history.Transactions[n-1].LT {
		tx.LT = w.history.Transactions[n-1].LT + 1
	}
	tx.Hash = fmt.Sprintf("%064x", tx.LT)
	tx.TookEffect = true
	w.history.Transactions = append(w.history.Transactions, tx)
	w.account.LastTransaction = toschain.ActorTxID{LT: tx.LT, Hash: tx.Hash}
	w.history.Head = w.account.LastTransaction
}
func TestTokenProviderRecheckUsesOriginalReturnedID(t *testing.T) {
	for _, kind := range []uint8{5, 7} {
		for _, noLog := range []bool{false, true} {
			t.Run(fmt.Sprintf("kind-%d/noLog-%t", kind, noLog), func(t *testing.T) {
				w := tokenRecheckedWorld(t, kind)
				in := w.action("recheck-payout")
				in.ID = 8
				p := w.preview(t, in)
				if _, err := RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env()); err != nil {
					t.Fatal(err)
				}
				delete(w.account.Data.Payouts, 8)
				w.account.Data.Returned[7] = nativecore.ServiceActorTokenReturnedV1{Caller: w.account.Data.Owner, Amount: big.NewInt(1000), ReturnDeadline: 1800000100}
				w.addTokenTx(toschain.TokenActorTransaction{Now: 1800000000, Logs: []nativecore.ServiceActorTokenLogV1{{Balance: &nativecore.ServiceActorTokenBalanceLogV1{QueryID: mustTokenBalanceQuery(t, w), Purpose: 1, Target: 8, PayoutID: 8}}}})

				if noLog {
					tx := &w.history.Transactions[len(w.history.Transactions)-1]
					query := mustTokenBalanceQuery(t, w)
					body := cell.BeginCell().MustStoreUInt(0x52544232, 32).MustStoreUInt(query, 64).MustStoreBigCoins(big.NewInt(10000)).EndCell()
					tx.Logs = nil
					tx.Sender = w.account.OwnWallet
					tx.BodyBOC = base64.StdEncoding.EncodeToString(body.ToBOC())
				}
				r, err := RunTokenAction(context.Background(), w.c, in, false, "", w.env())
				if err != nil || r.State != "returned" || w.sends != 1 {
					t.Fatalf("%+v %v sends=%d", r, err, w.sends)
				}
				status, err := ReadTokenStatus(context.Background(), w.c, w.account.Address, w.env())
				if err != nil || status.Requests[1] != "returned" {
					t.Fatalf("%+v %v", status, err)
				}
				delete(w.account.Data.Returned, 7)
				w.account.Data.Returned[8] = nativecore.ServiceActorTokenReturnedV1{Caller: w.account.Data.Owner, Amount: big.NewInt(1000)}
				if _, err := RunTokenAction(context.Background(), w.c, in, false, "", w.env()); err == nil {
					t.Fatal("wrong returned id accepted")
				}
			})
		}
	}
}

func TestTokenProviderRecoveryToolsRefuseBusyBalanceQueries(t *testing.T) {
	for _, op := range []string{"recover-surplus", "recheck-payout", "abandon-payout"} {
		t.Run(op, func(t *testing.T) {
			w := newTokenWorld(t)
			w.walletAtomic = 100000
			in := w.action(op)
			if op == "recover-surplus" {
				in.TokenAmount = "100"
			} else {
				in.ID = 7
				kind := uint8(1)
				if op == "abandon-payout" {
					kind = 3
				}
				w.account.Data.Payouts[7] = nativecore.ServiceActorTokenPayoutV1{Kind: kind, Amount: big.NewInt(1000), Recipient: w.account.Data.Owner}
			}
			_ = w.preview(t, in)
			for _, age := range []uint32{0, 3599} {
				w.account.Data.Accounting.BalanceQuery = nativecore.ServiceActorTokenBalanceQueryV1{Active: true, QueryID: 9, CreatedAt: uint32(w.ChainTime().Unix()) - age}
				_, err := RunTokenAction(context.Background(), w.c, in, false, "", w.env())
				if err == nil || errors.Is(err, ErrConfirmationRequired) || !strings.Contains(err.Error(), "1943") || w.sends != 0 {
					t.Fatalf("busy query age %d reached custody: %v", age, err)
				}
			}
			w.account.Data.Accounting.BalanceQuery.CreatedAt = uint32(w.ChainTime().Unix()) - 3600
			_ = w.preview(t, in)
		})
	}
}

func TestTokenProviderStatusLapsesPendingAndRefundableAfterDeadline(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprint(expired), func(t *testing.T) {
			w := tokenRecheckedWorld(t, 5)
			count := 1
			if expired {
				count = 2
			}
			w.history.Transactions = w.history.Transactions[:count]
			last := w.history.Transactions[count-1]
			w.account.LastTransaction = toschain.ActorTxID{LT: last.LT, Hash: last.Hash}
			w.history.Head = w.account.LastTransaction
			d := w.account.Data
			d.Payouts = map[uint64]nativecore.ServiceActorTokenPayoutV1{}
			snapshot := w.history.Transactions[0].Logs[0].Snapshot
			if expired {
				d.Refunds[1] = nativecore.ServiceActorRefundV1{Caller: snapshot.Caller, Price: snapshot.Terms.PricePerCall, RefundClaimDeadline: snapshot.RefundClaimDeadline}
			} else {
				d.Pending[1] = nativecore.ServiceActorPendingRequestV1{Caller: snapshot.Caller, Price: snapshot.Terms.PricePerCall, StorageFee: snapshot.Terms.StorageFee, CleanupBounty: snapshot.Terms.CleanupBounty, RequestHash: snapshot.RequestHash, TermsHash: snapshot.TermsHash, ResponseDeadline: snapshot.ResponseDeadline, RefundClaimDeadline: snapshot.RefundClaimDeadline}
			}
			before := w.begins
			status, err := ReadTokenStatus(context.Background(), w.c, w.account.Address, w.env())
			if err != nil || status.Requests[1] != "lapsed" || w.begins != before+1 {
				t.Fatalf("%+v %v", status, err)
			}
		})
	}
}

func TestTokenProviderRecheckUsesReturnedCallerByKind(t *testing.T) {
	for _, kind := range []uint8{1, 2, 4, 5, 7} {
		for _, noLog := range []bool{false, true} {
			t.Run(fmt.Sprintf("kind-%d/noLog-%t", kind, noLog), func(t *testing.T) {
				w := newTokenWorld(t)
				caller, e := nativecore.StandardAddress("0:" + strings.Repeat("71", 32))
				if e != nil {
					t.Fatal(e)
				}
				destination, e := nativecore.StandardAddress("0:" + strings.Repeat("72", 32))
				if e != nil {
					t.Fatal(e)
				}
				cleaner, e := nativecore.StandardAddress("0:" + strings.Repeat("73", 32))
				if e != nil {
					t.Fatal(e)
				}
				recipient, requester := caller, cleaner
				switch kind {
				case 1, 5:
					recipient, requester = destination, caller
				case 4:
					requester = caller
				}
				returnedID, requestID := uint64(8), uint64(1)
				switch kind {
				case 5, 7:
					returnedID, requestID = 7, 7
				case 4:
					requestID = 0
				}
				w.account.Data.Payouts = map[uint64]nativecore.ServiceActorTokenPayoutV1{8: {Kind: kind, RequestID: requestID, Recipient: recipient, Requester: requester, Amount: big.NewInt(1000), CreatedAt: 1797408000, OutcomeFeeLock: big.NewInt(20)}}
				w.account.Data.NextPayoutID = 9
				in := w.action("recheck-payout")
				in.ID = 8
				p := w.preview(t, in)
				if _, e = RunTokenAction(context.Background(), w.c, in, true, p.Preview.Digest, w.env()); e != nil {
					t.Fatal(e)
				}
				query := mustTokenBalanceQuery(t, w)
				reply := cell.BeginCell().MustStoreUInt(0x52544232, 32).MustStoreUInt(query, 64).MustStoreBigCoins(big.NewInt(10000)).EndCell()
				logs := []nativecore.ServiceActorTokenLogV1{{Balance: &nativecore.ServiceActorTokenBalanceLogV1{QueryID: query, Purpose: 1, Target: 8, PayoutID: 8}}}
				if noLog {
					logs = nil
				}
				delete(w.account.Data.Payouts, 8)
				w.account.Data.Returned[returnedID] = nativecore.ServiceActorTokenReturnedV1{Caller: caller, Amount: big.NewInt(1000), ReturnDeadline: 1800000100}
				w.addTokenTx(toschain.TokenActorTransaction{Now: 1800000000, Sender: w.account.OwnWallet, BodyBOC: base64.StdEncoding.EncodeToString(reply.ToBOC()), Logs: logs})
				r, e := RunTokenAction(context.Background(), w.c, in, false, "", w.env())
				if e != nil || r.State != "returned" {
					t.Fatalf("kind %d recipient=%s requester=%s: %+v %v", kind, recipient.Text(), requester.Text(), r, e)
				}
				// A wrong owner is still refused, even when its amount and id match.
				entry := w.account.Data.Returned[returnedID]
				entry.Caller = destination
				if kind == 1 || kind == 5 {
					entry.Caller = recipient
				}
				if kind == 2 || kind == 7 {
					entry.Caller = requester
				}
				w.account.Data.Returned[returnedID] = entry
				if _, e = RunTokenAction(context.Background(), w.c, in, false, "", w.env()); e == nil {
					t.Fatal("unrelated returned caller accepted")
				}
				entry.Caller = caller
				w.account.Data.Returned[returnedID] = entry
				// The resolved recheck must release subsequent owner operations.
				next := w.action("resume")
				next.IdempotencyKey = "after-recheck-resume-0002"
				preview := w.preview(t, next)
				if _, e = RunTokenAction(context.Background(), w.c, next, true, preview.Preview.Digest, w.env()); e != nil || w.sends != 2 {
					t.Fatalf("resolved recheck blocked owner: %v", e)
				}
			})
		}
	}
}
