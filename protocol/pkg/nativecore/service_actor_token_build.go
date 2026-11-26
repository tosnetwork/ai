package nativecore

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// BuildServiceActorTokenInitialData creates the contract's empty deployment
// state. It cannot be used to overwrite nonempty persistent state.
func BuildServiceActorTokenInitialData(owner string, p ServiceActorTokenPolicyV1, r ServiceActorTokenAssetRouteV1) (*cell.Cell, error) {
	own, err := StandardAddress(owner)
	if err != nil {
		return nil, err
	}
	if err = validateTokenStoredAddress(r.Master, true); err != nil {
		return nil, err
	}
	if _, ok := r.Master.RawStandard(); !ok || r.Master.Workchain != 0 {
		return nil, errors.New("token route master is not canonical on workchain zero")
	}
	if err := ValidateServiceActorTokenWalletCodeGraph(r.WalletCode); err != nil {
		return nil, err
	}
	if !bytes.Equal(r.WalletCodeHash[:], r.WalletCode.Hash()) {
		return nil, errors.New("token route code hash differs from wallet code")
	}
	if r.BridgeConfigParam != 79 && r.BridgeConfigParam != 81 && r.BridgeConfigParam != 82 && r.BridgeConfigParam != 83 {
		return nil, errors.New("token route bridge parameter outside allowed slots")
	}
	keyID := p.AttestorKeyID
	if p.HasAttestor {
		derived, e := mldsa44.KeyID(p.AttestorKey)
		if e != nil || derived != keyID {
			return nil, errors.New("token attestor key does not match its id")
		}
	} else if keyID != [32]byte{} || len(p.AttestorKey) != 0 {
		return nil, errors.New("token policy carries a key without an attestor")
	}
	c := cell.BeginCell().MustStoreSlice(p.MetadataHash[:], 256).MustStoreSlice(p.ProofSchemeHash[:], 256).MustStoreBoolBit(p.HasAttestor).MustStoreSlice(keyID[:], 256).MustStoreBoolBit(p.HasAttestor)
	if p.HasAttestor {
		if err = c.StoreRef(storedBytesCell(p.AttestorKey)); err != nil {
			return nil, err
		}
	}
	policy := cell.BeginCell().MustStoreUInt(uint64(p.PolicyVersion), 32)
	for _, v := range []*big.Int{p.PricePerCall, p.StorageFee, p.CleanupBounty} {
		if err = storeServiceActorCoins(policy, v); err != nil {
			return nil, err
		}
	}
	policy.MustStoreUInt(uint64(p.ResponseSLA), 32).MustStoreUInt(uint64(p.RefundClaimWindow), 32).MustStoreBoolBit(p.OpenAccess).MustStoreBoolBit(p.HasAuthorizedCaller)
	caller := p.AuthorizedCaller
	if caller.BitLen == 0 {
		if p.HasAuthorizedCaller {
			return nil, errors.New("authorized token caller is missing")
		}
		caller = own
	}
	if err = validateTokenStoredAddress(caller, false); err != nil {
		return nil, err
	}
	if !tokenCoinsValid(p.MaxTokenLiability) {
		return nil, errors.New("token liability cap outside bounds")
	}
	suffixBits := uint(32 + 4 + len(p.MaxTokenLiability.Bytes())*8)
	if policy.BitsUsed()+caller.BitLen+suffixBits > 1023 {
		return nil, errors.New("token policy exceeds cell capacity")
	}
	if err = policy.StoreSlice(caller.Bits, caller.BitLen); err != nil {
		return nil, err
	}
	policy.MustStoreUInt(uint64(p.RateLimitPerDay), 32)
	if err = storeServiceActorCoins(policy, p.MaxTokenLiability); err != nil {
		return nil, err
	}
	policy.MustStoreRef(c.EndCell())
	route := cell.BeginCell().MustStoreSlice(r.Master.Bits, r.Master.BitLen).MustStoreSlice(r.WalletCodeHash[:], 256).MustStoreRef(r.WalletCode).MustStoreUInt(uint64(r.BridgeConfigParam), 32).EndCell()
	ledger := cell.BeginCell().MustStoreUInt(0, 20).EndCell()
	query := cell.BeginCell().MustStoreUInt(0, 64).MustStoreUInt(0, 64).MustStoreUInt(0, 64).MustStoreUInt(0, 44).EndCell()
	accounting := cell.BeginCell().MustStoreUInt(0, 64).MustStoreUInt(0, 64).MustStoreUInt(0, 20).MustStoreRef(ledger).MustStoreRef(query).MustStoreRef(route).EndCell()
	requests := cell.BeginCell().MustStoreUInt(0, 4).EndCell()
	payouts := cell.BeginCell().MustStoreUInt(0, 3).EndCell()
	return cell.BeginCell().MustStoreSlice(own.Bits, own.BitLen).MustStoreBoolBit(true).MustStoreUInt(0, 64).MustStoreUInt(0, 32).MustStoreUInt(0, 32).MustStoreUInt(1, 64).MustStoreRef(policy.EndCell()).MustStoreRef(accounting).MustStoreRef(requests).MustStoreRef(payouts).EndCell(), nil
}
func BuildServiceActorTokenRequestSnapshot(p ServiceActorTokenRequestSnapshotV1) (*cell.Cell, error) {
	if err := validateTokenStoredAddress(p.Caller, true); err != nil {
		return nil, err
	}
	if p.Caller.BitLen > 543 {
		return nil, errors.New("token snapshot exceeds cell capacity")
	}
	terms, err := BuildServiceActorTokenTerms(p.Terms)
	if err != nil {
		return nil, err
	}
	if !p.Caller.IsInternal() {
		return nil, errors.New("token snapshot caller is not internal")
	}
	b := cell.BeginCell().MustStoreUInt(ServiceActorTokenRequestSnapshotTag, 32).MustStoreUInt(p.RequestID, 64).MustStoreSlice(p.Caller.Bits, p.Caller.BitLen).MustStoreSlice(p.RequestHash[:], 256).MustStoreUInt(p.ResponseDeadline, 64).MustStoreUInt(p.RefundClaimDeadline, 64).MustStoreRef(terms).EndCell()
	if _, err = DecodeServiceActorTokenRequestSnapshot(b); err != nil {
		return nil, err
	}
	return b, nil
}
func BuildServiceActorTokenFundingLog(p ServiceActorTokenFundingLogV1) (*cell.Cell, error) {
	if err := validateTokenStoredAddress(p.From, true); err != nil {
		return nil, err
	}
	if !p.From.IsInternal() {
		return nil, errors.New("funding caller is not internal")
	}
	b := cell.BeginCell().MustStoreUInt(ServiceActorTokenFundingLogTag, 32).MustStoreUInt(p.QueryID, 64).MustStoreSlice(p.From.Bits, p.From.BitLen)
	if err := storeServiceActorCoins(b, p.Amount); err != nil {
		return nil, err
	}
	result := b.MustStoreUInt(uint64(p.Reason), 16).MustStoreUInt(p.PayoutID, 64).EndCell()
	if _, err := DecodeServiceActorTokenFundingLog(result); err != nil {
		return nil, err
	}
	return result, nil
}
func BuildServiceActorTokenOutcomeLog(p ServiceActorTokenOutcomeLogV1) (*cell.Cell, error) {
	if err := validateTokenStoredAddress(p.Recipient, true); err != nil {
		return nil, err
	}
	if p.Kind < 1 || p.Kind > 7 || p.Outcome > 5 || !p.Recipient.IsInternal() {
		return nil, errors.New("invalid token outcome fields")
	}
	b := cell.BeginCell().MustStoreUInt(ServiceActorTokenOutcomeLogTag, 32).MustStoreUInt(p.PayoutID, 64).MustStoreUInt(uint64(p.Kind), 3).MustStoreUInt(p.RequestID, 64).MustStoreSlice(p.Recipient.Bits, p.Recipient.BitLen)
	if err := storeServiceActorCoins(b, p.Amount); err != nil {
		return nil, err
	}
	return b.MustStoreUInt(uint64(p.Outcome), 3).EndCell(), nil
}
func BuildServiceActorTokenBalanceLog(p ServiceActorTokenBalanceLogV1) (*cell.Cell, error) {
	if p.Purpose > 1 {
		return nil, errors.New("token balance purpose outside bounds")
	}
	b := cell.BeginCell().MustStoreUInt(ServiceActorTokenBalanceLogTag, 32).MustStoreUInt(p.QueryID, 64).MustStoreUInt(uint64(p.Purpose), 1).MustStoreUInt(p.Target, 64)
	for _, v := range []*big.Int{p.Balance, p.Surplus} {
		if err := storeServiceActorCoins(b, v); err != nil {
			return nil, err
		}
	}
	result := b.MustStoreUInt(uint64(p.Result), 16).MustStoreUInt(p.PayoutID, 64).EndCell()
	if _, err := DecodeServiceActorTokenBalanceLog(result); err != nil {
		return nil, err
	}
	return result, nil
}
