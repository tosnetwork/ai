package servicebridge

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
)

type TokenStatus struct {
	AdmissionHeld  bool              `json:"admission_held"`
	Actor          string            `json:"actor"`
	AssetID        string            `json:"asset_id"`
	Master         string            `json:"master"`
	Checkpoint     uint64            `json:"checkpoint"`
	Active         bool              `json:"active"`
	ActorFloorMet  bool              `json:"actor_floor_met"`
	WalletFloorMet bool              `json:"wallet_floor_met"`
	TokenRevenue   string            `json:"token_revenue_atomic"`
	TOSRevenue     string            `json:"tos_revenue_nanotos"`
	Paying         int               `json:"paying"`
	Returned       int               `json:"returned"`
	Requests       map[uint64]string `json:"requests"`
}

func tokenFloors(ctx context.Context, c NodeConfig, a TokenActorConfig, s TokenSession) (bool, bool, error) {
	resolved, err := s.ResolveTokenActor(ctx, a.Address, c.Token.Pins, false)
	if err != nil {
		return false, false, err
	}
	if resolved == nil || resolved.Account == nil || resolved.Account.Data == nil {
		return false, false, errors.New("token actor unavailable")
	}
	account := resolved.Account
	d := account.Data
	if account.CodeHash != a.CodeHash || d.Owner.Text() != c.WalletAddress || d.Route.Master.Text() != a.Master {
		return false, false, errors.New("token actor ownership or route mismatch")
	}
	wallet, found, err := s.ReadTokenWallet(ctx, a.Address, d.Route)
	if err != nil {
		return false, false, err
	}
	if !found || wallet == nil || wallet.Address != account.OwnWallet || wallet.Owner != a.Address || wallet.Master != a.Master || wallet.CodeHash != "tvm-cell-sha256:"+hex.EncodeToString(d.Route.WalletCodeHash[:]) {
		return false, false, errors.New("token wallet identity mismatch")
	}
	floor := new(big.Int).Add(d.Accounting.LockedStorageFees, d.Accounting.LockedOutcomeFees)
	floor.Add(floor, big.NewInt(nativecore.ServiceActorMinimumOperatingReserve))
	floor.Add(floor, mustTokenUnits(a.MinActorFreeNanoTOS))
	return new(big.Int).SetUint64(account.BalanceNano).Cmp(floor) >= 0, new(big.Int).SetUint64(wallet.BalanceNano).Cmp(mustTokenUnits(a.MinWalletNanoTOS)) >= 0, nil
}
func ReadTokenStatus(ctx context.Context, c NodeConfig, address string, env TokenEnv) (*TokenStatus, error) {
	env.fill()
	if c.Token == nil {
		return nil, errors.New("no token provider")
	}
	a, err := c.Token.Actor(address)
	if err != nil {
		return nil, err
	}
	s, err := env.Begin(ctx, c, a)
	if err != nil {
		return nil, err
	}
	account, requests, err := serviceactor.ResolveTokenRequests(ctx, s, address)
	if err != nil {
		return nil, err
	}
	actorFloor, walletFloor, err := tokenFloors(ctx, c, a, s)
	if err != nil {
		return nil, err
	}
	result := &TokenStatus{AdmissionHeld: !actorFloor || !walletFloor, Actor: address, AssetID: a.AssetID, Master: a.Master, Checkpoint: s.Checkpoint(), Active: account.Data.Active, ActorFloorMet: actorFloor, WalletFloorMet: walletFloor, TokenRevenue: account.Data.Accounting.Ledger.WithdrawableTokenRevenue.String(), TOSRevenue: account.Data.Accounting.WithdrawableTOSRevenue.String(), Paying: len(account.Data.Payouts), Returned: len(account.Data.Returned), Requests: map[uint64]string{}}
	for id, r := range requests {
		result.Requests[id] = string(r.Status)
	}
	return result, nil
}
