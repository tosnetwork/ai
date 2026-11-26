package serviceactor

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func fundingFixture(t *testing.T) *tokenReplayFixture {
	t.Helper()
	f := newTokenReplayFixture(t)
	delete(f.account.Data.Pending, 1)
	f.history.Transactions[0].Notification.QueryID = 9
	// 1902: an amount other than the price, a refusal the contract returns.
	f.history.Transactions[0].Logs = []nativecore.ServiceActorTokenLogV1{{Funding: &nativecore.ServiceActorTokenFundingLogV1{QueryID: 9, From: f.caller, Amount: big.NewInt(1000), Reason: 1902, PayoutID: 7}}}
	f.account.Data.Payouts[7] = nativecore.ServiceActorTokenPayoutV1{Kind: 4, Recipient: f.caller, Amount: big.NewInt(1000)}
	return f
}
func TestTokenFundingRefusalNeverConfusesPayingWithDelivered(t *testing.T) {
	f := fundingFixture(t)
	check := func(want string) {
		t.Helper()
		v, err := ResolveTokenFundingRefusals(f.account, f.history)
		if err != nil || len(v) != 1 || v[0].State != want {
			t.Fatalf("funding=%+v err=%v want=%s", v, err, want)
		}
	}
	check("paying")
	delete(f.account.Data.Payouts, 7)
	f.account.Data.Returned[7] = nativecore.ServiceActorTokenReturnedV1{Caller: f.caller, Amount: big.NewInt(1000)}
	check("returned")
	wallet, err := nativecore.DeriveServiceActorTokenWallet(f.caller.Text(), f.account.Data.Route)
	if err != nil {
		t.Fatal(err)
	}
	f.report(t, 0x52544431, 7, tokenReplayAddress(t, 9).Text())
	check("returned")
	f.report(t, 0x52544431, 7, wallet)
	delete(f.account.Data.Returned, 7)
	check("funding_returned")
}
func TestTokenFundingRefusalCanBeClaimedAfterReturning(t *testing.T) {
	f := fundingFixture(t)
	delete(f.account.Data.Payouts, 7)
	f.account.Data.Returned[7] = nativecore.ServiceActorTokenReturnedV1{Caller: f.caller, Amount: big.NewInt(1000)}
	f.claim(t, true)
	v, err := ResolveTokenFundingRefusals(f.account, f.history)
	if err != nil || v[0].State != "paying" {
		t.Fatalf("%+v %v", v, err)
	}
	wallet, err := nativecore.DeriveServiceActorTokenWallet(f.caller.Text(), f.account.Data.Route)
	if err != nil {
		t.Fatal(err)
	}
	f.report(t, 0x52544431, 8, wallet)
	delete(f.account.Data.Payouts, 8)
	v, err = ResolveTokenFundingRefusals(f.account, f.history)
	if err != nil || v[0].State != "funding_returned" {
		t.Fatalf("%+v %v", v, err)
	}
}
func TestTokenFundingUncorrelatedOrDisappearedLiabilityRefuses(t *testing.T) {
	for _, kind := range []string{"sender", "disappeared", "amount"} {
		t.Run(kind, func(t *testing.T) {
			f := fundingFixture(t)
			switch kind {
			case "sender":
				f.history.Transactions[0].Sender = f.caller.Text()
			case "disappeared":
				delete(f.account.Data.Payouts, 7)
			case "amount":
				f.account.Data.Payouts[7] = nativecore.ServiceActorTokenPayoutV1{Kind: 4, Recipient: f.caller, Amount: big.NewInt(999)}
			}
			if _, err := ResolveTokenFundingRefusals(f.account, f.history); err == nil {
				t.Fatal("unproven funding accepted")
			}
		})
	}
}

func TestTokenUnderfundedRefusalIsSurplusNotARefundPromise(t *testing.T) {
	f := fundingFixture(t)
	log := f.history.Transactions[0].Logs[0].Funding
	log.Reason = 1929
	log.PayoutID = 0
	delete(f.account.Data.Payouts, 7)
	v, err := ResolveTokenFundingRefusals(f.account, f.history)
	if err != nil || len(v) != 1 || v[0].State != "surplus" || v[0].PayoutID != 0 {
		t.Fatalf("%+v %v", v, err)
	}
	log.PayoutID = 7
	if _, err = ResolveTokenFundingRefusals(f.account, f.history); err == nil {
		t.Fatal("underfunded refusal promised a payout")
	}
}

// setFunding replaces the fixture's refusal log and its authenticated
// notification together, so only the SAF1 rule under test differs.
func (f *tokenReplayFixture) setFunding(from nativecore.MsgAddressV1, amount *big.Int, reason uint16, payout uint64) {
	tx := &f.history.Transactions[0]
	tx.Notification.From = from.Text()
	tx.Notification.AmountAtomic = amount.String()
	tx.Logs = []nativecore.ServiceActorTokenLogV1{{Funding: &nativecore.ServiceActorTokenFundingLogV1{QueryID: tx.Notification.QueryID, From: from, Amount: amount, Reason: reason, PayoutID: payout}}}
	delete(f.account.Data.Payouts, 7)
	if payout != 0 {
		f.account.Data.Payouts[payout] = nativecore.ServiceActorTokenPayoutV1{Kind: 4, Recipient: from, Amount: amount}
	}
}

// TestTokenFundingRefusalWithoutReturnIsSurplus covers every case of section
// 7.1 step 6 in which the contract logs a valid reason with payout id 0. A
// zero-amount transfer or a flood at the funding-return cap must not make the
// actor's history unverifiable.
func TestTokenFundingRefusalWithoutReturnIsSurplus(t *testing.T) {
	offChain, err := nativecore.StandardAddress("-1:" + "01010101010101010101010101010101010101010101010101010101010101" + "01")
	if err != nil {
		t.Fatal(err)
	}
	coinsBound := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 120), big.NewInt(1))
	for name, tc := range map[string]struct {
		from   func(*tokenReplayFixture) nativecore.MsgAddressV1
		amount *big.Int
		reason uint16
	}{
		"zero amount":                {amount: big.NewInt(0), reason: 1902},
		"zero amount, inactive":      {amount: big.NewInt(0), reason: 1901},
		"funding-return cap":         {amount: big.NewInt(1000), reason: 1907},
		"exhausted payout id":        {amount: big.NewInt(1000), reason: 1926},
		"sender off workchain 0":     {amount: big.NewInt(1000), reason: 1934, from: func(*tokenReplayFixture) nativecore.MsgAddressV1 { return offChain }},
		"return outside Coins":       {amount: coinsBound, reason: 1927},
		"underfunded":                {amount: big.NewInt(1000), reason: 1929},
		"underfunded, zero amount":   {amount: big.NewInt(0), reason: 1929},
		"malformed payload, at cap":  {amount: big.NewInt(1000), reason: 1939},
		"attestor keys full, at cap": {amount: big.NewInt(1000), reason: 1944},
	} {
		t.Run(name, func(t *testing.T) {
			f := fundingFixture(t)
			from := f.caller
			if tc.from != nil {
				from = tc.from(f)
			}
			f.setFunding(from, tc.amount, tc.reason, 0)
			v, err := ResolveTokenFundingRefusals(f.account, f.history)
			if err != nil || len(v) != 1 || v[0].State != "surplus" || v[0].PayoutID != 0 || v[0].Reason != tc.reason || v[0].AmountAtomic != tc.amount.String() {
				t.Fatalf("refusal without a return: %+v %v", v, err)
			}
			if _, err = ReplayTokenRequests(f.account, f.history, time.Unix(200, 0)); err != nil {
				t.Fatalf("request replay refused a legal SAF1: %v", err)
			}
		})
	}
}

// TestTokenFundingRefusesCombinationsTheContractCannotEmit keeps the resolver
// rules of section 9: a reason outside the admission set, and a payout id on
// a refusal the contract never returns.
func TestTokenFundingRefusesCombinationsTheContractCannotEmit(t *testing.T) {
	offChain, err := nativecore.StandardAddress("-1:" + "0202020202020202020202020202020202020202020202020202020202020202")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		offChain bool
		amount   int64
		reason   uint16
		payout   uint64
	}{
		"throw-only code, no payout":        {amount: 1000, reason: 1921},
		"throw-only code, with payout":      {amount: 1000, reason: 1921, payout: 7},
		"unknown code":                      {amount: 1000, reason: 1999},
		"cell underflow code":               {amount: 1000, reason: 9},
		"result code":                       {amount: 1000, reason: 1936},
		"underfunded with payout":           {amount: 1000, reason: 1929, payout: 7},
		"off-workchain reason with payout":  {amount: 1000, reason: 1934, payout: 7},
		"zero amount with payout":           {amount: 0, reason: 1902, payout: 7},
		"off-workchain sender with payout":  {offChain: true, amount: 1000, reason: 1902, payout: 7},
		"off-workchain sender, 1923 return": {offChain: true, amount: 1000, reason: 1923, payout: 7},
	} {
		t.Run(name, func(t *testing.T) {
			f := fundingFixture(t)
			from := f.caller
			if tc.offChain {
				from = offChain
			}
			f.setFunding(from, big.NewInt(tc.amount), tc.reason, tc.payout)
			if v, err := ResolveTokenFundingRefusals(f.account, f.history); err == nil {
				t.Fatalf("impossible SAF1 accepted: %+v", v)
			}
		})
	}
	t.Run("negative amount", func(t *testing.T) {
		f := fundingFixture(t)
		f.setFunding(f.caller, big.NewInt(-1), 1902, 0)
		if _, err := ResolveTokenFundingRefusals(f.account, f.history); err == nil {
			t.Fatal("negative amount accepted")
		}
	})
	t.Run("payout id 0 differs from the notification", func(t *testing.T) {
		f := fundingFixture(t)
		f.setFunding(f.caller, big.NewInt(0), 1902, 0)
		f.history.Transactions[0].Notification.AmountAtomic = "1"
		if _, err := ResolveTokenFundingRefusals(f.account, f.history); err == nil {
			t.Fatal("uncorrelated zero-amount refusal accepted")
		}
	})
}

// TestTokenFundingFrozenVectorsThroughTheResolver runs the contract's frozen
// SAF1 vectors through the resolver, not only the decoder.
func TestTokenFundingFrozenVectorsThroughTheResolver(t *testing.T) {
	raw, err := os.ReadFile("../../../spec/test-vectors/service-actor-token-conformance-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Refused     []string `json:"saf1_refused_amount"`
		Underfunded []string `json:"saf1_underfunded"`
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Refused) != 1 || len(vectors.Underfunded) != 1 {
		t.Fatal("frozen SAF1 vectors changed")
	}
	for name, tc := range map[string]struct {
		boc       string
		wantState string
	}{
		"saf1_refused_amount_0": {vectors.Refused[0], "paying"},
		"saf1_underfunded_0":    {vectors.Underfunded[0], "surplus"},
	} {
		t.Run(name, func(t *testing.T) {
			bytes, err := base64.StdEncoding.DecodeString(tc.boc)
			if err != nil {
				t.Fatal(err)
			}
			root, err := cell.FromBOC(bytes)
			if err != nil {
				t.Fatal(err)
			}
			log, err := nativecore.DecodeServiceActorTokenFundingLog(root)
			if err != nil {
				t.Fatal(err)
			}
			f := fundingFixture(t)
			tx := &f.history.Transactions[0]
			tx.Notification.QueryID = log.QueryID
			f.setFunding(log.From, log.Amount, log.Reason, log.PayoutID)
			tx.Logs[0].Funding.QueryID = log.QueryID
			v, err := ResolveTokenFundingRefusals(f.account, f.history)
			if err != nil || len(v) != 1 || v[0].State != tc.wantState || v[0].PayoutID != log.PayoutID || v[0].Reason != log.Reason || v[0].AmountAtomic != log.Amount.String() {
				t.Fatalf("frozen vector through the resolver: %+v %v", v, err)
			}
		})
	}
}
