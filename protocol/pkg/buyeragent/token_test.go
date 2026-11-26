package buyeragent

import (
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
)

func tokenPreviewRecord() buyersdk.CallRecord {
	return buyersdk.CallRecord{AssetMaster: "0:" + strings.Repeat("12", 32), AssetWalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("34", 32), AssetDecimals: 6, PriceAtomic: "1234567", PreparedTokenMessage: &buyersdk.TokenPreparedMessage{Destination: "0:" + strings.Repeat("56", 32), ValueNanotos: "100000000", BodyHash: strings.Repeat("ab", 32), Details: map[string]string{"forward_tos_amount": "90000000", "minimum_forward": "45000000"}}}
}

func TestTokenFundingPreviewKeepsExactUnitsAndDestinations(t *testing.T) {
	r := tokenPreviewRecord()
	f := tokenFunding(r)
	if f == nil || f.AssetMaster != r.AssetMaster || f.AmountAtomic != "1234567" || f.ReceivedAtomic != f.AmountAtomic || f.TokenWallet != r.PreparedTokenMessage.Destination || f.ForwardNanoTOS != "90000000" || f.MinimumForwardNanoTOS != "45000000" || f.WalletValueNanoTOS != "100000000" {
		t.Fatalf("preview: %+v", f)
	}
	if tokenFunding(buyersdk.CallRecord{}) != nil {
		t.Fatal("native record acquired token units")
	}
}

func TestTokenFundingDocumentIsBoundByConfirmation(t *testing.T) {
	r := tokenPreviewRecord()
	p := PurchaseRecord{}
	var nonce [ConfirmationNonceBytes]byte
	original := ConfirmationCode(nonce, fieldsOf(r, p))
	edits := []func(*buyersdk.CallRecord){func(r *buyersdk.CallRecord) { r.PriceAtomic = "1234568" }, func(r *buyersdk.CallRecord) { r.AssetMaster = "0:" + strings.Repeat("78", 32) }, func(r *buyersdk.CallRecord) { r.PreparedTokenMessage.Details["forward_tos_amount"] = "90000001" }, func(r *buyersdk.CallRecord) { r.PreparedTokenMessage.ValueNanotos = "100000001" }, func(r *buyersdk.CallRecord) { r.PreparedTokenMessage.BodyHash = strings.Repeat("cd", 32) }}
	for i, edit := range edits {
		r = tokenPreviewRecord()
		edit(&r)
		if ConfirmationCode(nonce, fieldsOf(r, p)) == original {
			t.Fatalf("edit %d reused the confirmation", i)
		}
	}
}

func TestAtomicAmountUsesExactIntegerDecimals(t *testing.T) {
	for _, c := range []struct {
		n    string
		d    uint8
		want string
	}{{"1234567", 6, "1.234567"}, {"1", 6, "0.000001"}, {"1000000", 6, "1.000000"}, {"123", 0, "123"}, {"1329227995784915872903807060280344575", 6, "1329227995784915872903807060280.344575"}} {
		if got := AtomicAmount(c.n, c.d); got != c.want {
			t.Fatalf("%s/%d: %s", c.n, c.d, got)
		}
	}
}

func TestTokenReceiptBindingUsesAtomicPriceAndExactAsset(t *testing.T) {
	r := tokenPreviewRecord()
	r.ExecutionID = strings.Repeat("ab", 32)
	r.InputDigest = strings.Repeat("cd", 32)
	binding, err := receiptBinding(r, PurchaseRecord{})
	if err != nil || binding.AssetMaster == nil || binding.AssetMaster[0] != 0x12 || binding.Price.String() != r.PriceAtomic {
		t.Fatalf("token receipt binding: %+v %v", binding, err)
	}
}

func TestTokenDutiesKeepReturnedAndPayingDistinctFromSettlement(t *testing.T) {
	for _, c := range []struct {
		status serviceactor.Status
		want   string
	}{{serviceactor.StatusReturned, "claim-returned"}, {serviceactor.StatusPaying, "recheck-payout"}, {serviceactor.StatusRefundable, "claim-refund"}, {serviceactor.StatusOverdue, "expire"}, {serviceactor.StatusLapsed, "sweep-expired-request"}, {serviceactor.StatusResponded, ""}} {
		if got := tokenLifecycleFor(c.status); got != c.want {
			t.Fatalf("%s: %s", c.status, got)
		}
	}
}

func TestTokenSurplusIsShownAsTerminalRatherThanAdmitted(t *testing.T) {
	if got := stateOf(buyersdk.CallRecord{Phase: buyersdk.PhaseFundingSurplus}, PurchaseRecord{}, time.Unix(1, 0)); got != StateFundingSurplus {
		t.Fatalf("surplus state: %s", got)
	}
}
