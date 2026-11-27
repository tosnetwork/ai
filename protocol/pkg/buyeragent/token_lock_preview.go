package buyeragent

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
)

type TokenLockPreviewParams struct {
	QuoteID       string `json:"quote_id"`
	NominalAtomic string `json:"nominal_atomic"`
}

// PreviewTokenLock is read-only: no quote, budget reservation or message changes.
// The source amount is distinct from the exact price of already-minted tokens.
func (a *Agent) PreviewTokenLock(ctx context.Context, p TokenLockPreviewParams) (buyersdk.TokenLockPreview, error) {
	var result buyersdk.TokenLockPreview
	if !hex64Pattern.MatchString(p.QuoteID) || len(p.NominalAtomic) > 37 {
		return result, errors.New("invalid token lock preview")
	}
	nominal, ok := new(big.Int).SetString(p.NominalAtomic, 10)
	if !ok || nominal.Sign() <= 0 || nominal.BitLen() > 120 || nominal.String() != p.NominalAtomic {
		return result, errors.New("invalid nominal atomic amount")
	}
	if !a.sourcePreviews.admit(a.now()) {
		return result, errors.New("token lock preview rate exceeded")
	}
	request, value, err := a.loadQuote(p.QuoteID)
	if err != nil {
		return result, err
	}
	v, err := quoteexchange.ValidateToken(a.config.Network, request, value, a.now())
	if err != nil {
		return result, err
	}
	if v.Rail.Asset.Decimals > 255 {
		return result, errors.New("invalid token decimals")
	}
	master := "0:" + hex.EncodeToString(v.Rail.Asset.Master.AccountId)
	policy, configured := a.config.TokenIssuers[master]
	if !configured {
		return result, errors.New("no owner-pinned issuer policy for this asset; source fees are unknown")
	}
	key := buyersdk.TokenAssetBudgetKey(master, v.Rail.Asset.WalletCodeHash, uint8(v.Rail.Asset.Decimals))
	limits := a.config.Buyer.Limits()
	budget, allowed := limits.TokenAssets[key]
	if !allowed {
		return result, errors.New("no funding budget for this asset")
	}
	reserved, err := a.config.Buyer.Journal().ReservedToken(limits, a.now())
	if err != nil {
		return result, err
	}
	held := reserved[key]
	if held == nil {
		held = new(big.Int)
	}
	return buyersdk.PreviewTokenLock(ctx, policy, master, v.Rail.Actor, nominal, v.Rail.PriceAtomic, held, budget)
}
