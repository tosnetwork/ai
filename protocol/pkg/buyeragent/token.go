package buyeragent

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"strings"

	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
)

// TokenFundingView describes the exact transfer independently of its native fees.
// Asset identity, rather than a display name, selects the budget.
type TokenFundingView struct {
	AssetMaster           string `json:"asset_master"`
	WalletCodeHash        string `json:"wallet_code_hash"`
	Decimals              uint8  `json:"decimals"`
	AmountAtomic          string `json:"amount_atomic"`
	ReceivedAtomic        string `json:"received_atomic"`
	ForwardNanoTOS        string `json:"forward_nanotos"`
	MinimumForwardNanoTOS string `json:"minimum_forward_nanotos"`
	WalletValueNanoTOS    string `json:"wallet_value_nanotos"`
	TokenWallet           string `json:"token_wallet"`
}

func tokenFunding(record buyersdk.CallRecord) *TokenFundingView {
	if record.PreparedTokenMessage == nil {
		return nil
	}
	p := record.PreparedTokenMessage
	return &TokenFundingView{AssetMaster: record.AssetMaster, WalletCodeHash: record.AssetWalletCodeHash,
		Decimals: record.AssetDecimals, AmountAtomic: record.PriceAtomic, ReceivedAtomic: record.PriceAtomic,
		ForwardNanoTOS: p.Details["forward_tos_amount"], MinimumForwardNanoTOS: p.Details["minimum_forward"],
		WalletValueNanoTOS: p.ValueNanotos, TokenWallet: p.Destination}
}

// The receipt and terms already bind the token amount. Binding the exact
// funding document as well prevents a fee change from reusing a human's code.
func tokenConfirmation(record buyersdk.CallRecord) string {
	if record.PreparedTokenMessage == nil {
		return ""
	}
	raw, _ := json.Marshal(struct {
		Funding  *TokenFundingView
		BodyHash string
	}{tokenFunding(record), record.PreparedTokenMessage.BodyHash})
	return string(raw)
}

// AtomicAmount renders by integer arithmetic only; no floating-point conversion
// or cross-asset conversion participates in a preview or a budget.
func AtomicAmount(atomic string, decimals uint8) string {
	value, ok := new(big.Int).SetString(atomic, 10)
	if !ok || value.Sign() < 0 {
		return "invalid atomic amount"
	}
	scale := new(big.Int).Exp(big.NewInt(10), new(big.Int).SetUint64(uint64(decimals)), nil)
	whole, fraction := new(big.Int).QuoRem(value, scale, new(big.Int))
	if decimals == 0 {
		return whole.String()
	}
	digits := fraction.String()
	for len(digits) < int(decimals) {
		digits = "0" + digits
	}
	return whole.String() + "." + digits
}

// TokenBudgetView keeps each asset's reservation and limits separate.
type TokenBudgetView struct {
	AssetKey         string `json:"asset_key"`
	MaxPerCallAtomic string `json:"max_per_call_atomic"`
	MaxWindowAtomic  string `json:"max_window_atomic"`
	ReservedAtomic   string `json:"reserved_atomic"`
}

func (a *Agent) tokenBudgets(limits buyersdk.ServiceActorLimits) ([]TokenBudgetView, error) {
	reserved, err := a.config.Buyer.Journal().ReservedToken(limits, a.now())
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(limits.TokenAssets))
	for key := range limits.TokenAssets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var result []TokenBudgetView
	for _, key := range keys {
		limit := limits.TokenAssets[key]
		amount := "0"
		if v := reserved[key]; v != nil {
			amount = v.String()
		}
		result = append(result, TokenBudgetView{AssetKey: key, MaxPerCallAtomic: limit.MaxPerCallAtomic.String(), MaxWindowAtomic: limit.MaxWindowAtomic.String(), ReservedAtomic: amount})
	}
	return result, nil
}

func priceOfRecord(record buyersdk.CallRecord) string {
	if record.PreparedTokenMessage != nil {
		return record.PriceAtomic
	}
	return record.PriceNanoTOS
}

func recordAssetMaster(record buyersdk.CallRecord) (*[32]byte, error) {
	if record.PreparedTokenMessage == nil {
		return nil, nil
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(record.AssetMaster, "0:"))
	if err != nil || len(raw) != 32 || !strings.HasPrefix(record.AssetMaster, "0:") {
		return nil, errors.New("invalid stored token asset")
	}
	var out [32]byte
	copy(out[:], raw)
	return &out, nil
}
