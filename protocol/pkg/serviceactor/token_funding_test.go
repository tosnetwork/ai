package serviceactor

import (
	"math/big"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

func fundingFixture(t *testing.T) *tokenReplayFixture {
	t.Helper()
	f := newTokenReplayFixture(t)
	delete(f.account.Data.Pending, 1)
	f.history.Transactions[0].Notification.QueryID = 9
	f.history.Transactions[0].Logs = []nativecore.ServiceActorTokenLogV1{{Funding: &nativecore.ServiceActorTokenFundingLogV1{QueryID: 9, From: f.caller, Amount: big.NewInt(1000), Reason: 1921, PayoutID: 7}}}
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
