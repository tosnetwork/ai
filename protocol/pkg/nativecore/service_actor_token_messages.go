package nativecore

import (
	"errors"
	"math/big"

	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	ServiceActorTokenCallOpcode          uint32 = 0x53544301
	ServiceActorTokenRespondOpcode       uint32 = 0x53544302
	ServiceActorTokenExpireOpcode        uint32 = 0x53544303
	ServiceActorTokenClaimRefundOpcode   uint32 = 0x53544304
	ServiceActorTokenSweepOpcode         uint32 = 0x53544305
	ServiceActorTokenUpdatePolicyOpcode  uint32 = 0x53544306
	ServiceActorTokenRotateKeyOpcode     uint32 = 0x53544307
	ServiceActorTokenRevokeOpcode        uint32 = 0x53544308
	ServiceActorTokenWithdrawOpcode      uint32 = 0x53544309
	ServiceActorTokenClaimReturnedOpcode uint32 = 0x5354430a
	ServiceActorTokenRecoverOpcode       uint32 = 0x5354430b
	ServiceActorTokenAbandonOpcode       uint32 = 0x5354430c
	ServiceActorTokenSweepReturnedOpcode uint32 = 0x5354430d
	ServiceActorTokenRecheckOpcode       uint32 = 0x5354430f
	ServiceActorTokenTransferOpcode      uint32 = 0x0f8a7ea5
)

func tokenMessage(opcode uint32, queryID uint64, write func(*cell.Builder) error) (*cell.Cell, error) {
	b := cell.BeginCell()
	if err := b.StoreUInt(uint64(opcode), 32); err != nil {
		return nil, err
	}
	if err := b.StoreUInt(queryID, 64); err != nil {
		return nil, err
	}
	if write != nil {
		if err := write(b); err != nil {
			return nil, err
		}
	}
	return b.EndCell(), nil
}
func tokenAddress(b *cell.Builder, raw string, basechain bool) error {
	a, err := StandardAddress(raw)
	if err != nil {
		return err
	}
	if basechain && a.Workchain != 0 {
		return errors.New("token destination must be canonical on workchain 0")
	}
	return b.StoreSlice(a.Bits, a.BitLen)
}

// BuildServiceActorTokenCallPayload builds the exact referenced funding payload.
func BuildServiceActorTokenCallPayload(requestHash, termsHash [32]byte) (*cell.Cell, error) {
	b := cell.BeginCell()
	if err := b.StoreUInt(uint64(ServiceActorTokenCallOpcode), 32); err != nil {
		return nil, err
	}
	if err := b.StoreSlice(requestHash[:], 256); err != nil {
		return nil, err
	}
	if err := b.StoreSlice(termsHash[:], 256); err != nil {
		return nil, err
	}
	return b.EndCell(), nil
}

// BuildServiceActorTokenFundingTransfer builds an ordinary transfer with one referenced token_call.
func BuildServiceActorTokenFundingTransfer(queryID uint64, amount *big.Int, actor, response string, forward *big.Int, requestHash, termsHash [32]byte) (*cell.Cell, error) {
	if amount == nil || amount.Sign() <= 0 || forward == nil || forward.Sign() <= 0 {
		return nil, errors.New("a funding transfer needs positive token and forward amounts")
	}
	payload, err := BuildServiceActorTokenCallPayload(requestHash, termsHash)
	if err != nil {
		return nil, err
	}
	return tokenMessage(ServiceActorTokenTransferOpcode, queryID, func(b *cell.Builder) error {
		if err := storeServiceActorCoins(b, amount); err != nil {
			return err
		}
		if err := tokenAddress(b, actor, true); err != nil {
			return err
		}
		if err := tokenAddress(b, response, true); err != nil {
			return err
		}
		if err := b.StoreBoolBit(false); err != nil {
			return err
		}
		if err := storeServiceActorCoins(b, forward); err != nil {
			return err
		}
		if err := b.StoreBoolBit(true); err != nil {
			return err
		}
		return b.StoreRef(payload)
	})
}

// BuildServiceActorTokenRespondBody includes a signature only when its caller supplies one.
func BuildServiceActorTokenRespondBody(queryID, id uint64, responseHash [32]byte, signature []byte) (*cell.Cell, error) {
	if len(signature) != 0 && len(signature) != mldsa44.SignatureSize {
		return nil, errors.New("token response signature has the wrong length")
	}
	return tokenMessage(ServiceActorTokenRespondOpcode, queryID, func(b *cell.Builder) error {
		if err := b.StoreUInt(id, 64); err != nil {
			return err
		}
		if err := b.StoreSlice(responseHash[:], 256); err != nil {
			return err
		}
		if len(signature) != 0 {
			return b.StoreRef(storedBytesCell(signature))
		}
		return nil
	})
}

// BuildServiceActorTokenIDBody builds the lifecycle messages containing one id.
func BuildServiceActorTokenIDBody(opcode uint32, queryID, id uint64) (*cell.Cell, error) {
	switch opcode {
	case ServiceActorTokenExpireOpcode, ServiceActorTokenSweepOpcode, ServiceActorTokenSweepReturnedOpcode, ServiceActorTokenAbandonOpcode, ServiceActorTokenRecheckOpcode:
	default:
		return nil, errors.New("opcode is not a token lifecycle id message")
	}
	return tokenMessage(opcode, queryID, func(b *cell.Builder) error { return b.StoreUInt(id, 64) })
}
func BuildServiceActorTokenClaimBody(opcode uint32, queryID, id uint64, destination string) (*cell.Cell, error) {
	if opcode != ServiceActorTokenClaimRefundOpcode && opcode != ServiceActorTokenClaimReturnedOpcode {
		return nil, errors.New("opcode is not a token claim message")
	}
	return tokenMessage(opcode, queryID, func(b *cell.Builder) error {
		if err := b.StoreUInt(id, 64); err != nil {
			return err
		}
		return tokenAddress(b, destination, true)
	})
}
func BuildServiceActorTokenRevokeBody(queryID uint64) (*cell.Cell, error) {
	return tokenMessage(ServiceActorTokenRevokeOpcode, queryID, nil)
}
func BuildServiceActorTokenRotateBody(queryID uint64, publicKey []byte) (*cell.Cell, error) {
	if _, err := mldsa44.KeyID(publicKey); err != nil {
		return nil, err
	}
	return tokenMessage(ServiceActorTokenRotateKeyOpcode, queryID, func(b *cell.Builder) error { return b.StoreRef(storedBytesCell(publicKey)) })
}
func BuildServiceActorTokenWithdrawBody(queryID uint64, tokens, tos *big.Int) (*cell.Cell, error) {
	return tokenMessage(ServiceActorTokenWithdrawOpcode, queryID, func(b *cell.Builder) error {
		if err := storeServiceActorCoins(b, tokens); err != nil {
			return err
		}
		return storeServiceActorCoins(b, tos)
	})
}
func BuildServiceActorTokenRecoverBody(queryID uint64, amount *big.Int) (*cell.Cell, error) {
	return tokenMessage(ServiceActorTokenRecoverOpcode, queryID, func(b *cell.Builder) error { return storeServiceActorCoins(b, amount) })
}

// BuildServiceActorTokenPolicyBody uses the owner as the filler address when no caller is authorized.
func BuildServiceActorTokenPolicyBody(queryID uint64, policy ServiceActorTokenPolicyV1, active bool, owner string) (*cell.Cell, error) {
	return tokenMessage(ServiceActorTokenUpdatePolicyOpcode, queryID, func(b *cell.Builder) error {
		for _, v := range []*big.Int{policy.PricePerCall, policy.StorageFee, policy.CleanupBounty} {
			if err := storeServiceActorCoins(b, v); err != nil {
				return err
			}
		}
		if err := b.StoreUInt(uint64(policy.ResponseSLA), 32); err != nil {
			return err
		}
		if err := b.StoreUInt(uint64(policy.RefundClaimWindow), 32); err != nil {
			return err
		}
		if err := b.StoreBoolBit(active); err != nil {
			return err
		}
		if err := b.StoreBoolBit(policy.OpenAccess); err != nil {
			return err
		}
		if err := b.StoreBoolBit(policy.HasAuthorizedCaller); err != nil {
			return err
		}
		caller := owner
		if policy.HasAuthorizedCaller {
			var ok bool
			caller, ok = policy.AuthorizedCaller.RawStandard()
			if !ok {
				return errors.New("authorized caller must be canonical")
			}
		}
		if err := tokenAddress(b, caller, false); err != nil {
			return err
		}
		if err := b.StoreUInt(uint64(policy.RateLimitPerDay), 32); err != nil {
			return err
		}
		if err := storeServiceActorCoins(b, policy.MaxTokenLiability); err != nil {
			return err
		}
		meta := cell.BeginCell()
		if err := meta.StoreSlice(policy.MetadataHash[:], 256); err != nil {
			return err
		}
		if err := meta.StoreSlice(policy.ProofSchemeHash[:], 256); err != nil {
			return err
		}
		return b.StoreRef(meta.EndCell())
	})
}

// ServiceActorTokenReportedTransferV1 is the actor's one-cell payout request.
type ServiceActorTokenReportedTransferV1 struct {
	QueryID                           uint64
	Amount                            *big.Int
	Destination, ResponseDestination  MsgAddressV1
	ReportTOSAmount, ForwardTOSAmount *big.Int
}

// DecodeServiceActorTokenReportedTransfer refuses anything outside the actor's exact payout shape.
func DecodeServiceActorTokenReportedTransfer(body *cell.Cell) (ServiceActorTokenReportedTransferV1, error) {
	var r ServiceActorTokenReportedTransferV1
	s, err := beginOrdinary(body, "token reported transfer")
	if err != nil {
		return r, err
	}
	op, err := s.LoadUInt(32)
	if err != nil || op != 0x52545231 {
		return r, errors.New("not a token reported transfer")
	}
	if r.QueryID, err = s.LoadUInt(64); err != nil {
		return r, err
	}
	if r.Amount, err = loadServiceActorCoins(s); err != nil {
		return r, err
	}
	if r.Amount.Sign() == 0 {
		return r, errors.New("reported transfer amount must be positive")
	}
	if r.Destination, err = loadMsgAddressInt(s); err != nil {
		return r, err
	}
	if raw, ok := r.Destination.RawStandard(); !ok || r.Destination.Workchain != 0 || raw == "" {
		return r, errors.New("reported transfer destination is not canonical on workchain 0")
	}
	if r.ResponseDestination, err = loadMsgAddressInt(s); err != nil {
		return r, err
	}
	if _, ok := r.ResponseDestination.RawStandard(); !ok {
		return r, errors.New("reported transfer response is not canonical")
	}
	if r.ReportTOSAmount, err = loadServiceActorCoins(s); err != nil {
		return r, err
	}
	if r.ForwardTOSAmount, err = loadServiceActorCoins(s); err != nil {
		return r, err
	}
	if r.ForwardTOSAmount.Sign() != 0 {
		return r, errors.New("actor payout must not forward a notification")
	}
	referenced, err := s.LoadBoolBit()
	if err != nil || referenced {
		return r, errors.New("actor payout payload must be empty and inline")
	}
	return r, exhausted(s, "token reported transfer")
}
