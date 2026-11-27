package buyersdk

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/tosnetwork/ai/protocol/pkg/tokenissuer"
)

// TokenLockPreview separates source amounts from exact TOS actor funding.
// The source fee is charged once, at the lock; it is never deducted again from
// a transfer of already-minted tokens to an actor.
type TokenLockPreview struct {
	AssetMaster           string               `json:"asset_master"`
	Actor                 string               `json:"actor"`
	NominalAtomic         string               `json:"nominal_atomic"`
	IssuerFeeAtomic       string               `json:"issuer_fee_atomic"`
	MintedAtomic          string               `json:"minted_atomic"`
	BudgetDebitAtomic     string               `json:"budget_debit_atomic"`
	ActorPriceAtomic      string               `json:"actor_price_atomic"`
	MaxPerCallAtomic      string               `json:"max_per_call_atomic"`
	RemainingWindowAtomic string               `json:"remaining_window_atomic"`
	Observation           tokenissuer.Snapshot `json:"observation"`
	Warning               string               `json:"warning,omitempty"`
}

func PreviewTokenLock(ctx context.Context, policy tokenissuer.Policy, master, actor string, nominal, actorPrice, reserved *big.Int, limits TokenAssetLimits) (TokenLockPreview, error) {
	var preview TokenLockPreview
	if !rawTokenPreviewAddress(master) || !rawTokenPreviewAddress(actor) || actorPrice == nil || actorPrice.Sign() <= 0 || actorPrice.BitLen() > 120 || reserved == nil || reserved.Sign() < 0 || limits.MaxPerCallAtomic == nil || limits.MaxWindowAtomic == nil {
		return preview, errors.New("invalid token lock preview or asset budget")
	}
	reader, err := tokenissuer.NewReader(policy, nil)
	if err != nil {
		return preview, err
	}
	observation, err := reader.Read(ctx, policy.Bridge)
	if err != nil {
		return preview, err
	}
	return previewTokenLockAt(observation, master, actor, nominal, actorPrice, reserved, limits)
}

// previewTokenLockAt prices the issuer reader's checked observation.
// It reserves no budget and never builds a transfer.
func previewTokenLockAt(observation tokenissuer.Snapshot, master, actor string, nominal, actorPrice, reserved *big.Int, limits TokenAssetLimits) (TokenLockPreview, error) {
	var result TokenLockPreview
	if !rawTokenPreviewAddress(master) || !rawTokenPreviewAddress(actor) || actorPrice == nil || actorPrice.Sign() <= 0 || actorPrice.BitLen() > 120 || reserved == nil || reserved.Sign() < 0 || reserved.BitLen() > 120 || limits.MaxPerCallAtomic == nil || limits.MaxWindowAtomic == nil || limits.MaxPerCallAtomic.Sign() <= 0 || limits.MaxWindowAtomic.Cmp(limits.MaxPerCallAtomic) < 0 || limits.MaxWindowAtomic.BitLen() > 120 {
		return result, errors.New("invalid token lock preview or asset budget")
	}
	received, fee, err := observation.Received(nominal)
	if err != nil {
		return result, err
	}
	remaining := new(big.Int).Sub(limits.MaxWindowAtomic, reserved)
	if received.Cmp(limits.MaxPerCallAtomic) > 0 || received.Cmp(remaining) > 0 {
		return result, errors.New("minted amount exceeds this asset's remaining funding budget")
	}
	result = TokenLockPreview{AssetMaster: master, Actor: actor, NominalAtomic: nominal.String(), IssuerFeeAtomic: fee.String(), MintedAtomic: received.String(), BudgetDebitAtomic: received.String(), ActorPriceAtomic: actorPrice.String(), Observation: observation, MaxPerCallAtomic: limits.MaxPerCallAtomic.String(), RemainingWindowAtomic: remaining.String()}
	if fee.Sign() > 0 {
		result.Warning = fmt.Sprintf("The nominal source amount %s mints %s after the issuer fee. If used as actor funding instead of its exact quoted price %s, a differing amount is refused and returned. Funding the nominal price requires sufficient already-minted tokens. TOS transfers are exact: no issuer fee is deducted again.", nominal.String(), received.String(), actorPrice.String())
	}
	return result, nil
}

func rawTokenPreviewAddress(address string) bool {
	_, err := tokenRaw(address, true)
	return err == nil
}
