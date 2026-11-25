package nativecore

import (
	"errors"
	"math/big"

	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type ServiceActorTokenInboundV1 struct {
	ServiceActorInboundV1
	TokenAmount, TOSAmount    *big.Int
	From, ResponseDestination MsgAddressV1
	ForwardTOSAmount          *big.Int
	ForwardPayload            *cell.Cell
	Signature                 []byte
	Policy                    *ServiceActorTokenPolicyV1
	Active                    bool
}

// DecodeServiceActorTokenInbound strictly decodes an ordinary body. Stale or
// bounced transport messages are not evidence of an executed lifecycle action.
func DecodeServiceActorTokenInbound(value *cell.Cell) (ServiceActorTokenInboundV1, error) {
	var p ServiceActorTokenInboundV1
	s, err := beginOrdinary(value, "token actor inbound")
	if err != nil {
		return p, err
	}
	op, err := s.LoadUInt(32)
	if err != nil {
		return p, err
	}
	p.Opcode = uint32(op)
	if p.QueryID, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	switch p.Opcode {
	case 0x53544302:
		if p.RequestID, err = s.LoadUInt(64); err != nil {
			return p, err
		}
		if p.ResponseHash, err = loadHash(s); err != nil {
			return p, err
		}
		if s.RefsNum() > 0 {
			signature, e := loadRefCell(s, "token response signature")
			if e != nil {
				return p, e
			}
			p.Signature, e = readStoredBytes(signature, mldsa44.SignatureSize)
			if e != nil {
				return p, e
			}
			p.Signed = true
		}
	case 0x53544303, 0x53544305, 0x5354430c, 0x5354430d, 0x5354430f:
		if p.RequestID, err = s.LoadUInt(64); err != nil {
			return p, err
		}
	case 0x53544304, 0x5354430a:
		if p.RequestID, err = s.LoadUInt(64); err != nil {
			return p, err
		}
		if p.Destination, err = loadMsgAddressInt(s); err != nil {
			return p, err
		}
	case 0x53544306:
		policy := &ServiceActorTokenPolicyV1{}
		p.Policy = policy
		for _, f := range []**big.Int{&policy.PricePerCall, &policy.StorageFee, &policy.CleanupBounty} {
			if *f, err = loadServiceActorCoins(s); err != nil {
				return p, err
			}
		}
		n, e := s.LoadUInt(32)
		if e != nil {
			return p, e
		}
		policy.ResponseSLA = uint32(n)
		n, e = s.LoadUInt(32)
		if e != nil {
			return p, e
		}
		policy.RefundClaimWindow = uint32(n)
		if p.Active, err = s.LoadBoolBit(); err != nil {
			return p, err
		}
		if policy.OpenAccess, err = s.LoadBoolBit(); err != nil {
			return p, err
		}
		if policy.HasAuthorizedCaller, err = s.LoadBoolBit(); err != nil {
			return p, err
		}
		if policy.AuthorizedCaller, err = loadMsgAddress(s); err != nil {
			return p, err
		}
		n, e = s.LoadUInt(32)
		if e != nil {
			return p, e
		}
		policy.RateLimitPerDay = uint32(n)
		if policy.MaxTokenLiability, err = loadServiceActorCoins(s); err != nil {
			return p, err
		}
		ref, e := loadRefCell(s, "token update policy commitments")
		if e != nil {
			return p, e
		}
		c, e := beginOrdinary(ref, "token update policy commitments")
		if e != nil {
			return p, e
		}
		if policy.MetadataHash, err = loadHash(c); err != nil {
			return p, err
		}
		if policy.ProofSchemeHash, err = loadHash(c); err != nil {
			return p, err
		}
		if err = exhausted(c, "token update policy commitments"); err != nil {
			return p, err
		}
	case 0x53544307:
		ref, e := loadRefCell(s, "token rotate attestor key")
		if e != nil {
			return p, e
		}
		p.Signature, e = readStoredBytes(ref, mldsa44.PublicKeySize)
		if e != nil {
			return p, e
		}
	case 0x53544308:
	case 0x53544309:
		if p.TokenAmount, err = loadServiceActorCoins(s); err != nil {
			return p, err
		}
		if p.TOSAmount, err = loadServiceActorCoins(s); err != nil {
			return p, err
		}
	case 0x5354430b:
		if p.TokenAmount, err = loadServiceActorCoins(s); err != nil {
			return p, err
		}
	case 0x7362d09c:
		if p.TokenAmount, err = loadServiceActorCoins(s); err != nil {
			return p, err
		}
		if p.From, err = loadMsgAddress(s); err != nil {
			return p, err
		}
		remaining := s.BitsLeft()
		raw, e := s.LoadSlice(remaining)
		if e != nil {
			return p, e
		}
		b := cell.BeginCell()
		if e = b.StoreSlice(raw, remaining); e != nil {
			return p, e
		}
		for s.RefsNum() > 0 {
			ref, e := s.LoadRefCell()
			if e != nil {
				return p, e
			}
			if e = b.StoreRef(ref); e != nil {
				return p, e
			}
		}
		p.ForwardPayload = b.EndCell()
	case 0x52544431:
		if p.TokenAmount, err = loadServiceActorCoins(s); err != nil {
			return p, err
		}
		if p.Destination, err = loadMsgAddressInt(s); err != nil {
			return p, err
		}
	case 0x52544631, 0x52545232, 0x52544232:
		if p.TokenAmount, err = loadServiceActorCoins(s); err != nil {
			return p, err
		}
	case 0x52544331, 0x52544231, 0xd53276db:
	default:
		return p, errors.New("unknown token actor inbound opcode")
	}
	return p, exhausted(s, "token actor inbound")
}

type ServiceActorTokenFundingTransferV1 struct {
	QueryID                          uint64
	Amount                           *big.Int
	Destination, ResponseDestination MsgAddressV1
	CustomPayload                    *cell.Cell
	ForwardTOSAmount                 *big.Int
	Payload                          TokenCallPayloadV1
}

func DecodeServiceActorTokenFundingTransfer(value *cell.Cell) (ServiceActorTokenFundingTransferV1, error) {
	var p ServiceActorTokenFundingTransferV1
	s, err := beginOrdinary(value, "token funding transfer")
	if err != nil {
		return p, err
	}
	op, err := s.LoadUInt(32)
	if err != nil || op != 0x0f8a7ea5 {
		return p, errors.New("token funding transfer opcode mismatch")
	}
	if p.QueryID, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	if p.Amount, err = loadServiceActorCoins(s); err != nil {
		return p, err
	}
	if p.Destination, err = loadMsgAddress(s); err != nil {
		return p, err
	}
	if p.ResponseDestination, err = loadMsgAddress(s); err != nil {
		return p, err
	}
	custom, err := s.LoadBoolBit()
	if err != nil {
		return p, err
	}
	if custom {
		return p, errors.New("token funding transfer carries custom payload")
	}
	if p.ForwardTOSAmount, err = loadServiceActorCoins(s); err != nil {
		return p, err
	}
	if p.Amount.Sign() <= 0 || p.ForwardTOSAmount.Sign() <= 0 {
		return p, errors.New("token funding transfer needs positive amounts")
	}
	if _, ok := p.Destination.RawStandard(); !ok || p.Destination.Workchain != 0 {
		return p, errors.New("token funding destination is not canonical on workchain zero")
	}
	if _, ok := p.ResponseDestination.RawStandard(); !ok || p.ResponseDestination.Workchain != 0 {
		return p, errors.New("token funding response destination is not canonical on workchain zero")
	}
	n := s.BitsLeft()
	bits, err := s.LoadSlice(n)
	if err != nil {
		return p, err
	}
	b := cell.BeginCell()
	if err = b.StoreSlice(bits, n); err != nil {
		return p, err
	}
	for s.RefsNum() > 0 {
		r, e := s.LoadRefCell()
		if e != nil {
			return p, e
		}
		if e = b.StoreRef(r); e != nil {
			return p, e
		}
	}
	p.Payload, err = DecodeServiceActorTokenForwardPayload(b.EndCell())
	return p, err
}

type ServiceActorTokenOutcomeInputV1 struct {
	Opcode    uint32
	QueryID   uint64
	Amount    *big.Int
	Recipient MsgAddressV1
}

// DecodeServiceActorTokenOutcomeInput validates the complete ordinary wallet
// outcome body before a resolver binds it to an authenticated transaction sender.
func DecodeServiceActorTokenOutcomeInput(value *cell.Cell) (ServiceActorTokenOutcomeInputV1, error) {
	var out ServiceActorTokenOutcomeInputV1
	p, err := DecodeServiceActorTokenInbound(value)
	if err != nil {
		return out, err
	}
	switch p.Opcode {
	case 0x52544431:
		if _, ok := p.Destination.RawStandard(); !ok || p.Destination.Workchain != 0 {
			return out, errors.New("token delivery recipient is not canonical on workchain zero")
		}
	case 0x52544631, 0x52545232, 0x52544232:
	default:
		return out, errors.New("not a token wallet outcome input")
	}
	return ServiceActorTokenOutcomeInputV1{Opcode: p.Opcode, QueryID: p.QueryID, Amount: p.TokenAmount, Recipient: p.Destination}, nil
}
