package serviceactor

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type tokenReplayFixture struct {
	account  *toschain.TokenActorAccount
	history  *toschain.TokenActorHistory
	snapshot nativecore.ServiceActorTokenRequestSnapshotV1
	caller   nativecore.MsgAddressV1
}

func tokenReplayAddress(t *testing.T, value byte) nativecore.MsgAddressV1 {
	t.Helper()
	a, err := nativecore.StandardAddress("0:" + strings.Repeat(fmt.Sprintf("%02x", value), 32))
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func tokenReplayBOC(c *cell.Cell) string {
	return base64.StdEncoding.EncodeToString(c.ToBOCWithOptions(cell.BOCSerializeOptions{}))
}
func newTokenReplayFixture(t *testing.T) *tokenReplayFixture {
	t.Helper()
	caller, owner, master := tokenReplayAddress(t, 1), tokenReplayAddress(t, 2), tokenReplayAddress(t, 3)
	code := cell.BeginCell().EndCell()
	var codeHash, masterID [32]byte
	copy(codeHash[:], code.Hash())
	copy(masterID[:], master.Address)
	terms := nativecore.ServiceActorTokenTermsV1{ServiceActorTermsV1: nativecore.ServiceActorTermsV1{PricePerCall: big.NewInt(1000), StorageFee: big.NewInt(200), CleanupBounty: big.NewInt(10), ResponseSLA: 10, RefundClaimWindow: 20}, AssetMasterHash: masterID, AssetWalletCodeHash: codeHash}
	root, err := nativecore.BuildServiceActorTokenTerms(terms)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := nativecore.ServiceActorTokenRequestSnapshotV1{RequestID: 1, Caller: caller, RequestHash: sha256.Sum256([]byte("request")), ResponseDeadline: 110, RefundClaimDeadline: 130, Terms: terms}
	copy(snapshot.TermsHash[:], root.Hash())
	data := &nativecore.ServiceActorTokenDataV1{Owner: owner, Route: nativecore.ServiceActorTokenAssetRouteV1{Master: master, WalletCodeHash: codeHash, WalletCode: code, BridgeConfigParam: 83}, Pending: map[uint64]nativecore.ServiceActorPendingRequestV1{}, Refunds: map[uint64]nativecore.ServiceActorRefundV1{}, Payouts: map[uint64]nativecore.ServiceActorTokenPayoutV1{}, Returned: map[uint64]nativecore.ServiceActorTokenReturnedV1{}}
	data.Pending[1] = nativecore.ServiceActorPendingRequestV1{Caller: caller, Price: big.NewInt(1000), StorageFee: big.NewInt(200), CleanupBounty: big.NewInt(10), RequestHash: snapshot.RequestHash, TermsHash: snapshot.TermsHash, ResponseDeadline: 110, RefundClaimDeadline: 130}
	account := &toschain.TokenActorAccount{Address: tokenReplayAddress(t, 4).Text(), OwnWallet: tokenReplayAddress(t, 5).Text(), Data: data}
	tx := toschain.TokenActorTransaction{LT: 1, Hash: strings.Repeat("1", 64), Now: 100, TookEffect: true, Sender: account.OwnWallet, Notification: &toschain.TokenActorNotification{AmountAtomic: "1000", From: caller.Text(), Payload: &nativecore.TokenCallPayloadV1{RequestHash: snapshot.RequestHash, ExpectedTermsHash: snapshot.TermsHash}}, Logs: []nativecore.ServiceActorTokenLogV1{{Snapshot: &snapshot}}}
	return &tokenReplayFixture{account: account, history: &toschain.TokenActorHistory{Result: toschain.HistoryComplete, Transactions: []toschain.TokenActorTransaction{tx}}, snapshot: snapshot, caller: caller}
}
func (f *tokenReplayFixture) add(tx toschain.TokenActorTransaction) {
	if previous := f.history.Transactions[len(f.history.Transactions)-1].Now; tx.Now <= previous {
		tx.Now = previous + 1
	}
	tx.LT = uint64(len(f.history.Transactions) + 1)
	tx.Hash = fmt.Sprintf("%064x", tx.LT)
	tx.TookEffect = true
	f.history.Transactions = append(f.history.Transactions, tx)
}
func (f *tokenReplayFixture) replay(t *testing.T, now int64, want Status) {
	t.Helper()
	requests, err := ReplayTokenRequests(f.account, f.history, time.Unix(now, 0))
	if err != nil {
		t.Fatal(err)
	}
	if requests[1] == nil || requests[1].Status != want {
		t.Fatalf("status = %+v, want %s", requests[1], want)
	}
}
func (f *tokenReplayFixture) expire(t *testing.T) {
	t.Helper()
	body, err := nativecore.BuildServiceActorTokenIDBody(nativecore.ServiceActorTokenExpireOpcode, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.add(toschain.TokenActorTransaction{Now: 111, Opcode: nativecore.ServiceActorTokenExpireOpcode, RequestID: 1, Sender: f.caller.Text(), BodyBOC: tokenReplayBOC(body)})
	delete(f.account.Data.Pending, 1)
	f.account.Data.Refunds[1] = nativecore.ServiceActorRefundV1{Caller: f.caller, Price: big.NewInt(1000), RefundClaimDeadline: 130}
}
func (f *tokenReplayFixture) claim(t *testing.T, returned bool) {
	t.Helper()
	op, id, payout := nativecore.ServiceActorTokenClaimRefundOpcode, uint64(1), uint64(7)
	if returned {
		op, id, payout = nativecore.ServiceActorTokenClaimReturnedOpcode, 7, 8
	}
	body, err := nativecore.BuildServiceActorTokenClaimBody(op, 3, id, f.caller.Text())
	if err != nil {
		t.Fatal(err)
	}
	transfer := cell.BeginCell().MustStoreUInt(0x52545231, 32).MustStoreUInt(payout, 64).MustStoreBigCoins(big.NewInt(1000)).MustStoreSlice(f.caller.Bits, f.caller.BitLen).MustStoreSlice(f.caller.Bits, f.caller.BitLen).MustStoreBigCoins(big.NewInt(20)).MustStoreBigCoins(big.NewInt(0)).MustStoreBoolBit(false).EndCell()
	f.add(toschain.TokenActorTransaction{Now: 112, Opcode: op, RequestID: id, Sender: f.caller.Text(), Destination: f.caller.Text(), BodyBOC: tokenReplayBOC(body), Outputs: []toschain.TokenActorOutput{{Destination: f.account.OwnWallet, Bounce: true, BodyBOC: tokenReplayBOC(transfer)}}})
	delete(f.account.Data.Refunds, 1)
	delete(f.account.Data.Returned, 7)
	kind := uint8(1)
	if returned {
		kind = 5
	}
	f.account.Data.Payouts[payout] = nativecore.ServiceActorTokenPayoutV1{Kind: kind, Amount: big.NewInt(1000), Recipient: f.caller}
}
func (f *tokenReplayFixture) report(t *testing.T, op uint32, id uint64, sender string) {
	t.Helper()
	b := cell.BeginCell().MustStoreUInt(uint64(op), 32).MustStoreUInt(id, 64).MustStoreBigCoins(big.NewInt(1000))
	if op == 0x52544431 {
		b.MustStoreSlice(f.caller.Bits, f.caller.BitLen)
	}
	f.add(toschain.TokenActorTransaction{Now: 113, Sender: sender, BodyBOC: tokenReplayBOC(b.EndCell())})
}
func TestTokenReplayPendingDeadlinesAndRefundable(t *testing.T) {
	for _, tc := range []struct {
		now  int64
		want Status
	}{{105, StatusPending}, {110, StatusOverdue}, {130, StatusLapsed}} {
		t.Run(string(tc.want), func(t *testing.T) { newTokenReplayFixture(t).replay(t, tc.now, tc.want) })
	}
	f := newTokenReplayFixture(t)
	f.expire(t)
	f.replay(t, 115, StatusRefundable)
}
func TestTokenReplayClaimNeedsAuthenticatedDelivery(t *testing.T) {
	f := newTokenReplayFixture(t)
	f.expire(t)
	f.claim(t, false)
	f.replay(t, 115, StatusPaying)
	f.report(t, 0x52544431, 7, tokenReplayAddress(t, 9).Text())
	f.replay(t, 115, StatusPaying)
	wallet, err := nativecore.DeriveServiceActorTokenWallet(f.caller.Text(), f.account.Data.Route)
	if err != nil {
		t.Fatal(err)
	}
	f.report(t, 0x52544431, 7, wallet)
	delete(f.account.Data.Payouts, 7)
	f.replay(t, 115, StatusRefunded)
}
func TestTokenReplayRefusedThenReturnedClaimDelivered(t *testing.T) {
	f := newTokenReplayFixture(t)
	f.expire(t)
	f.claim(t, false)
	f.report(t, 0x52544631, 7, f.account.OwnWallet)
	delete(f.account.Data.Payouts, 7)
	f.account.Data.Returned[7] = nativecore.ServiceActorTokenReturnedV1{Caller: f.caller, Amount: big.NewInt(1000)}
	f.replay(t, 115, StatusReturned)
	f.claim(t, true)
	f.replay(t, 115, StatusPaying)
	wallet, err := nativecore.DeriveServiceActorTokenWallet(f.caller.Text(), f.account.Data.Route)
	if err != nil {
		t.Fatal(err)
	}
	f.report(t, 0x52544431, 8, wallet)
	delete(f.account.Data.Payouts, 8)
	f.replay(t, 115, StatusRefunded)
}
func TestTokenReplaySourceBounceRestoresRefund(t *testing.T) {
	f := newTokenReplayFixture(t)
	f.expire(t)
	f.claim(t, false)
	b := cell.BeginCell().MustStoreUInt(0xffffffff, 32).MustStoreUInt(0x52545231, 32).MustStoreUInt(7, 64).MustStoreBigCoins(big.NewInt(1000)).EndCell()
	f.add(toschain.TokenActorTransaction{Now: 113, Sender: f.account.OwnWallet, Bounced: true, BodyBOC: tokenReplayBOC(b)})
	delete(f.account.Data.Payouts, 7)
	f.account.Data.Refunds[1] = nativecore.ServiceActorRefundV1{Caller: f.caller, Price: big.NewInt(1000), RefundClaimDeadline: 130}
	f.replay(t, 115, StatusRefundable)
}
func TestTokenReplayMismatchLogAndIncompleteHistory(t *testing.T) {
	t.Run("outcome mismatch", func(t *testing.T) {
		f := newTokenReplayFixture(t)
		f.expire(t)
		f.claim(t, false)
		f.add(toschain.TokenActorTransaction{Now: 113, Logs: []nativecore.ServiceActorTokenLogV1{{Outcome: &nativecore.ServiceActorTokenOutcomeLogV1{PayoutID: 7, Kind: 1, RequestID: 1, Recipient: f.caller, Amount: big.NewInt(999), Outcome: 0}}}})
		if _, err := ReplayTokenRequests(f.account, f.history, time.Unix(115, 0)); err == nil {
			t.Fatal("accepted mismatched SAO1")
		}
	})
	for _, kind := range []string{"incomplete", "head", "funding sender"} {
		t.Run(kind, func(t *testing.T) {
			f := newTokenReplayFixture(t)
			switch kind {
			case "incomplete":
				f.history.Result = toschain.HistoryResult("unavailable")
			case "head":
				f.history.Head.LT = 9
			case "funding sender":
				f.history.Transactions[0].Sender = f.caller.Text()
			}
			if _, err := ReplayTokenRequests(f.account, f.history, time.Unix(115, 0)); err == nil {
				t.Fatal("accepted invalid history")
			}
		})
	}
}

func TestTokenReplayRespondedAndSweptAreDistinctTerminalStates(t *testing.T) {
	t.Run("responded", func(t *testing.T) {
		f := newTokenReplayFixture(t)
		f.add(toschain.TokenActorTransaction{Now: 105, Opcode: nativecore.ServiceActorTokenRespondOpcode, RequestID: 1, Sender: f.account.Data.Owner.Text(), ResponseHash: strings.Repeat("ab", 32)})
		delete(f.account.Data.Pending, 1)
		f.replay(t, 106, StatusResponded)
	})
	for _, throughReturned := range []bool{false, true} {
		t.Run(fmt.Sprintf("sweep-returned-%t", throughReturned), func(t *testing.T) {
			f := newTokenReplayFixture(t)
			f.expire(t)
			body, err := nativecore.BuildServiceActorTokenIDBody(nativecore.ServiceActorTokenSweepOpcode, 3, 1)
			if err != nil {
				t.Fatal(err)
			}
			transfer := func(id uint64) *cell.Cell {
				return cell.BeginCell().MustStoreUInt(0x52545231, 32).MustStoreUInt(id, 64).MustStoreBigCoins(big.NewInt(1000)).MustStoreSlice(f.caller.Bits, f.caller.BitLen).MustStoreSlice(f.caller.Bits, f.caller.BitLen).MustStoreBigCoins(big.NewInt(20)).MustStoreBigCoins(big.NewInt(0)).MustStoreBoolBit(false).EndCell()
			}
			f.add(toschain.TokenActorTransaction{Now: 131, Opcode: nativecore.ServiceActorTokenSweepOpcode, RequestID: 1, Sender: f.caller.Text(), BodyBOC: tokenReplayBOC(body), Outputs: []toschain.TokenActorOutput{{Destination: f.account.OwnWallet, Bounce: true, BodyBOC: tokenReplayBOC(transfer(7))}}})
			delete(f.account.Data.Refunds, 1)
			f.account.Data.Payouts[7] = nativecore.ServiceActorTokenPayoutV1{Kind: 2, RequestID: 1, Amount: big.NewInt(1000), Recipient: f.caller}
			f.replay(t, 132, StatusPaying)
			id := uint64(7)
			if throughReturned {
				f.report(t, 0x52544631, 7, f.account.OwnWallet)
				f.history.Transactions[len(f.history.Transactions)-1].Now = 132
				delete(f.account.Data.Payouts, 7)
				f.account.Data.Returned[7] = nativecore.ServiceActorTokenReturnedV1{Caller: f.caller, Amount: big.NewInt(1000)}
				f.replay(t, 133, StatusReturned)
				b, err := nativecore.BuildServiceActorTokenIDBody(nativecore.ServiceActorTokenSweepReturnedOpcode, 4, 7)
				if err != nil {
					t.Fatal(err)
				}
				f.add(toschain.TokenActorTransaction{Now: 134, Opcode: nativecore.ServiceActorTokenSweepReturnedOpcode, RequestID: 7, Sender: f.caller.Text(), BodyBOC: tokenReplayBOC(b), Outputs: []toschain.TokenActorOutput{{Destination: f.account.OwnWallet, Bounce: true, BodyBOC: tokenReplayBOC(transfer(8))}}})
				delete(f.account.Data.Returned, 7)
				f.account.Data.Payouts[8] = nativecore.ServiceActorTokenPayoutV1{Kind: 7, RequestID: 7, Amount: big.NewInt(1000), Recipient: f.caller}
				id = 8
				f.replay(t, 135, StatusPaying)
			}
			wallet, err := nativecore.DeriveServiceActorTokenWallet(f.caller.Text(), f.account.Data.Route)
			if err != nil {
				t.Fatal(err)
			}
			f.report(t, 0x52544431, id, wallet)
			f.history.Transactions[len(f.history.Transactions)-1].Now = 136
			delete(f.account.Data.Payouts, id)
			f.replay(t, 137, StatusSwept)
		})
	}
}

// TestTokenReplayRecipientMismatchSkipsOnlyThatReport checks that a delivery
// report naming another recipient is skipped locally: the rest of the same
// transaction, here its actor-authenticated outcome logs, is still replayed.
func TestTokenReplayRecipientMismatchSkipsOnlyThatReport(t *testing.T) {
	setup := func(t *testing.T, log nativecore.ServiceActorTokenOutcomeLogV1) *tokenReplayFixture {
		t.Helper()
		f := newTokenReplayFixture(t)
		f.expire(t)
		f.claim(t, false)
		wallet, err := nativecore.DeriveServiceActorTokenWallet(f.caller.Text(), f.account.Data.Route)
		if err != nil {
			t.Fatal(err)
		}
		other := tokenReplayAddress(t, 9)
		body := cell.BeginCell().MustStoreUInt(0x52544431, 32).MustStoreUInt(7, 64).MustStoreBigCoins(big.NewInt(1000)).MustStoreSlice(other.Bits, other.BitLen).EndCell()
		f.add(toschain.TokenActorTransaction{Now: 113, Sender: wallet, BodyBOC: tokenReplayBOC(body), Logs: []nativecore.ServiceActorTokenLogV1{{Outcome: &log}}})
		return f
	}
	t.Run("a consistent log in the same transaction still applies", func(t *testing.T) {
		f := setup(t, nativecore.ServiceActorTokenOutcomeLogV1{PayoutID: 7, Kind: 1, RequestID: 1, Recipient: tokenReplayAddress(t, 1), Amount: big.NewInt(1000), Outcome: 0})
		delete(f.account.Data.Payouts, 7)
		f.replay(t, 115, StatusRefunded)
	})
	t.Run("an inconsistent log in the same transaction is still refused", func(t *testing.T) {
		f := setup(t, nativecore.ServiceActorTokenOutcomeLogV1{PayoutID: 7, Kind: 1, RequestID: 1, Recipient: tokenReplayAddress(t, 9), Amount: big.NewInt(1000), Outcome: 0})
		if _, err := ReplayTokenRequests(f.account, f.history, time.Unix(115, 0)); err == nil {
			t.Fatal("an outcome log differing from its payout was skipped with the report")
		}
	})
}
