package nativecore

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	ServiceActorTokenRequestSnapshotTag = 0x53415431
	ServiceActorTokenFundingLogTag      = 0x53414631
	ServiceActorTokenOutcomeLogTag      = 0x53414f31
	ServiceActorTokenBalanceLogTag      = 0x53414231
)

type ServiceActorTokenTermsV1 struct {
	ServiceActorTermsV1
	AssetMasterHash, AssetWalletCodeHash [32]byte
}
type ServiceActorTokenRequestSnapshotV1 struct {
	RequestID                             uint64
	Caller                                MsgAddressV1
	RequestHash                           [32]byte
	ResponseDeadline, RefundClaimDeadline uint64
	TermsHash                             [32]byte
	Terms                                 ServiceActorTokenTermsV1
}
type ServiceActorTokenFundingLogV1 struct {
	QueryID  uint64
	From     MsgAddressV1
	Amount   *big.Int
	Reason   uint16
	PayoutID uint64
}
type ServiceActorTokenOutcomeLogV1 struct {
	PayoutID  uint64
	Kind      uint8
	RequestID uint64
	Recipient MsgAddressV1
	Amount    *big.Int
	Outcome   uint8
}
type ServiceActorTokenBalanceLogV1 struct {
	QueryID          uint64
	Purpose          uint8
	Target           uint64
	Balance, Surplus *big.Int
	Result           uint16
	PayoutID         uint64
}
type ServiceActorTokenLogV1 struct {
	Tag      uint32
	Snapshot *ServiceActorTokenRequestSnapshotV1
	Funding  *ServiceActorTokenFundingLogV1
	Outcome  *ServiceActorTokenOutcomeLogV1
	Balance  *ServiceActorTokenBalanceLogV1
}
type TokenCallPayloadV1 struct{ RequestHash, ExpectedTermsHash [32]byte }

func BuildServiceActorTokenTerms(terms ServiceActorTokenTermsV1) (*cell.Cell, error) {
	zero := terms.AttestorKeyID == [32]byte{}
	if terms.HasAttestor == zero {
		return nil, errors.New("token terms attestor flag and key id disagree")
	}
	tail := cell.BeginCell().MustStoreSlice(terms.MetadataHash[:], 256).MustStoreSlice(terms.ProofSchemeHash[:], 256).MustStoreBoolBit(terms.HasAttestor).MustStoreSlice(terms.AttestorKeyID[:], 256).EndCell()
	b := cell.BeginCell().MustStoreUInt(uint64(terms.PolicyVersion), 32)
	for _, v := range []*big.Int{terms.PricePerCall, terms.StorageFee, terms.CleanupBounty} {
		if err := storeServiceActorCoins(b, v); err != nil {
			return nil, err
		}
	}
	return b.MustStoreUInt(uint64(terms.ResponseSLA), 32).MustStoreUInt(uint64(terms.RefundClaimWindow), 32).MustStoreSlice(terms.AssetMasterHash[:], 256).MustStoreSlice(terms.AssetWalletCodeHash[:], 256).MustStoreRef(tail).EndCell(), nil
}
func DecodeServiceActorTokenTerms(value *cell.Cell) (ServiceActorTokenTermsV1, error) {
	var t ServiceActorTokenTermsV1
	s, err := beginOrdinary(value, "token terms")
	if err != nil {
		return t, err
	}
	n, err := s.LoadUInt(32)
	if err != nil {
		return t, err
	}
	t.PolicyVersion = uint32(n)
	for _, f := range []**big.Int{&t.PricePerCall, &t.StorageFee, &t.CleanupBounty} {
		if *f, err = loadServiceActorCoins(s); err != nil {
			return t, err
		}
	}
	n, err = s.LoadUInt(32)
	if err != nil {
		return t, err
	}
	t.ResponseSLA = uint32(n)
	n, err = s.LoadUInt(32)
	if err != nil {
		return t, err
	}
	t.RefundClaimWindow = uint32(n)
	if t.AssetMasterHash, err = loadHash(s); err != nil {
		return t, err
	}
	if t.AssetWalletCodeHash, err = loadHash(s); err != nil {
		return t, err
	}
	tail, err := loadRefCell(s, "token terms tail")
	if err != nil {
		return t, err
	}
	if err = exhausted(s, "token terms"); err != nil {
		return t, err
	}
	c, err := beginOrdinary(tail, "token terms tail")
	if err != nil {
		return t, err
	}
	if t.MetadataHash, err = loadHash(c); err != nil {
		return t, err
	}
	if t.ProofSchemeHash, err = loadHash(c); err != nil {
		return t, err
	}
	if t.HasAttestor, err = c.LoadBoolBit(); err != nil {
		return t, err
	}
	if t.AttestorKeyID, err = loadHash(c); err != nil {
		return t, err
	}
	if err = exhausted(c, "token terms tail"); err != nil {
		return t, err
	}
	canonical, err := BuildServiceActorTokenTerms(t)
	if err != nil {
		return t, err
	}
	if !bytes.Equal(canonical.Hash(), value.Hash()) {
		return t, errors.New("token terms are not canonical")
	}
	return t, nil
}
func BuildServiceActorTokenTermsCell(t ServiceActorTokenTermsV1) (*cell.Cell, error) {
	return BuildServiceActorTokenTerms(t)
}
func DecodeServiceActorTokenTermsCell(c *cell.Cell) (ServiceActorTokenTermsV1, error) {
	return DecodeServiceActorTokenTerms(c)
}
func ServiceActorTokenTermsHash(t ServiceActorTokenTermsV1) ([32]byte, error) {
	var h [32]byte
	c, e := BuildServiceActorTokenTerms(t)
	if e != nil {
		return h, e
	}
	copy(h[:], c.Hash())
	return h, nil
}
func TokenTermsOfPolicy(policy ServiceActorTokenPolicyV1, route ServiceActorTokenAssetRouteV1) ServiceActorTokenTermsV1 {
	var master [32]byte
	if _, ok := route.Master.RawStandard(); ok && route.Master.Workchain == 0 {
		copy(master[:], route.Master.Address)
	}
	return ServiceActorTokenTermsV1{ServiceActorTermsV1: TermsOfPolicy(policy.ServiceActorPolicyV1), AssetMasterHash: master, AssetWalletCodeHash: route.WalletCodeHash}
}
func DecodeServiceActorTokenRequestSnapshot(value *cell.Cell) (ServiceActorTokenRequestSnapshotV1, error) {
	var p ServiceActorTokenRequestSnapshotV1
	s, err := beginOrdinary(value, "token request snapshot")
	if err != nil {
		return p, err
	}
	tag, err := s.LoadUInt(32)
	if err != nil || tag != ServiceActorTokenRequestSnapshotTag {
		return p, errors.New("token request snapshot tag is not SAT1")
	}
	if p.RequestID, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	if p.Caller, err = loadMsgAddressInt(s); err != nil {
		return p, err
	}
	if p.RequestHash, err = loadHash(s); err != nil {
		return p, err
	}
	if p.ResponseDeadline, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	if p.RefundClaimDeadline, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	terms, err := loadRefCell(s, "token request terms")
	if err != nil {
		return p, err
	}
	if err = exhausted(s, "token request snapshot"); err != nil {
		return p, err
	}
	if p.Terms, err = DecodeServiceActorTokenTerms(terms); err != nil {
		return p, err
	}
	copy(p.TermsHash[:], terms.Hash())
	if p.ResponseDeadline > math.MaxUint64-uint64(p.Terms.RefundClaimWindow) || p.ResponseDeadline+uint64(p.Terms.RefundClaimWindow) != p.RefundClaimDeadline {
		return p, errors.New("token snapshot deadlines disagree with refund claim window")
	}
	return p, nil
}
func ServiceActorTokenResponseDomainHash(globalID int32, actor string, p ServiceActorTokenRequestSnapshotV1, responseHash [32]byte) ([32]byte, error) {
	return ServiceActorResponseDomainHash(globalID, actor, ServiceActorRequestSnapshotV1{RequestID: p.RequestID, Caller: p.Caller, RequestHash: p.RequestHash, ResponseDeadline: p.ResponseDeadline, RefundClaimDeadline: p.RefundClaimDeadline, TermsHash: p.TermsHash, Terms: p.Terms.ServiceActorTermsV1}, responseHash)
}
func DecodeServiceActorTokenFundingLog(value *cell.Cell) (ServiceActorTokenFundingLogV1, error) {
	var p ServiceActorTokenFundingLogV1
	s, err := beginOrdinary(value, "token funding log")
	if err != nil {
		return p, err
	}
	tag, err := s.LoadUInt(32)
	if err != nil || tag != ServiceActorTokenFundingLogTag {
		return p, errors.New("token funding log tag is not SAF1")
	}
	if p.QueryID, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	if p.From, err = loadMsgAddressInt(s); err != nil {
		return p, err
	}
	if p.Amount, err = loadServiceActorCoins(s); err != nil {
		return p, err
	}
	n, err := s.LoadUInt(16)
	if err != nil {
		return p, err
	}
	p.Reason = uint16(n)
	if p.PayoutID, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	if err = exhausted(s, "token funding log"); err != nil {
		return p, err
	}
	info, err := ServiceActorTokenRefusalInfo(p.Reason)
	if err != nil || !info.Reason {
		return p, errors.New("funding refusal reason is outside admission set")
	}
	if p.Reason == 1929 && p.PayoutID != 0 {
		return p, errors.New("underfunded refusal carries a payout id")
	}
	return p, nil
}
func DecodeServiceActorTokenOutcomeLog(value *cell.Cell) (ServiceActorTokenOutcomeLogV1, error) {
	var p ServiceActorTokenOutcomeLogV1
	s, err := beginOrdinary(value, "token outcome log")
	if err != nil {
		return p, err
	}
	tag, err := s.LoadUInt(32)
	if err != nil || tag != ServiceActorTokenOutcomeLogTag {
		return p, errors.New("token outcome log tag is not SAO1")
	}
	if p.PayoutID, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	n, err := s.LoadUInt(3)
	if err != nil || n == 0 {
		return p, errors.New("token outcome kind outside 1..7")
	}
	p.Kind = uint8(n)
	if p.RequestID, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	if p.Recipient, err = loadMsgAddressInt(s); err != nil {
		return p, err
	}
	if p.Amount, err = loadServiceActorCoins(s); err != nil {
		return p, err
	}
	n, err = s.LoadUInt(3)
	if err != nil {
		return p, errors.New("token outcome field is missing")
	}
	if n > 5 {
		return p, errors.New("token outcome outside 0..5")
	}
	p.Outcome = uint8(n)
	return p, exhausted(s, "token outcome log")
}
func DecodeServiceActorTokenBalanceLog(value *cell.Cell) (ServiceActorTokenBalanceLogV1, error) {
	var p ServiceActorTokenBalanceLogV1
	s, err := beginOrdinary(value, "token balance log")
	if err != nil {
		return p, err
	}
	tag, err := s.LoadUInt(32)
	if err != nil || tag != ServiceActorTokenBalanceLogTag {
		return p, errors.New("token balance log tag is not SAB1")
	}
	if p.QueryID, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	n, err := s.LoadUInt(1)
	if err != nil {
		return p, err
	}
	p.Purpose = uint8(n)
	if p.Target, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	if p.Balance, err = loadServiceActorCoins(s); err != nil {
		return p, err
	}
	if p.Surplus, err = loadServiceActorCoins(s); err != nil {
		return p, err
	}
	n, err = s.LoadUInt(16)
	if err != nil {
		return p, err
	}
	p.Result = uint16(n)
	if p.PayoutID, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	if err = exhausted(s, "token balance log"); err != nil {
		return p, err
	}
	if p.Result != 0 && p.Result != 1936 {
		return p, errors.New("balance result outside 0 or 1936")
	}
	if p.Result == 0 && p.PayoutID == 0 || p.Result == 1936 && p.PayoutID != 0 {
		return p, errors.New("balance result and payout id disagree")
	}
	if p.Purpose == 0 && p.Target != 0 {
		return p, errors.New("surplus balance log carries a target")
	}
	return p, nil
}
func DecodeServiceActorTokenLog(value *cell.Cell) (*ServiceActorTokenLogV1, error) {
	s, err := beginOrdinary(value, "token actor log")
	if err != nil {
		return nil, err
	}
	tag, err := s.LoadUInt(32)
	if err != nil {
		return nil, err
	}
	r := &ServiceActorTokenLogV1{Tag: uint32(tag)}
	switch r.Tag {
	case ServiceActorTokenRequestSnapshotTag:
		p, e := DecodeServiceActorTokenRequestSnapshot(value)
		r.Snapshot = &p
		err = e
	case ServiceActorTokenFundingLogTag:
		p, e := DecodeServiceActorTokenFundingLog(value)
		r.Funding = &p
		err = e
	case ServiceActorTokenOutcomeLogTag:
		p, e := DecodeServiceActorTokenOutcomeLog(value)
		r.Outcome = &p
		err = e
	case ServiceActorTokenBalanceLogTag:
		p, e := DecodeServiceActorTokenBalanceLog(value)
		r.Balance = &p
		err = e
	default:
		err = errors.New("unknown token actor log tag")
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}
func DecodeServiceActorTokenCallPayload(value *cell.Cell) (TokenCallPayloadV1, error) {
	var p TokenCallPayloadV1
	s, err := beginOrdinary(value, "token call payload")
	if err != nil {
		return p, err
	}
	tag, err := s.LoadUInt(32)
	if err != nil || tag != 0x53544301 {
		return p, errors.New("token call payload tag mismatch")
	}
	if p.RequestHash, err = loadHash(s); err != nil {
		return p, err
	}
	if p.ExpectedTermsHash, err = loadHash(s); err != nil {
		return p, err
	}
	return p, exhausted(s, "token call payload")
}
func DecodeServiceActorTokenForwardPayload(value *cell.Cell) (result TokenCallPayloadV1, err error) {
	defer func() {
		if err != nil {
			failure, lookupErr := ServiceActorTokenRefusalInfo(1939)
			if lookupErr != nil {
				err = lookupErr
				return
			}
			err = fmt.Errorf("%w: %v", failure, err)
		}
	}()
	var p TokenCallPayloadV1
	s, err := beginOrdinary(value, "token forward payload")
	if err != nil {
		return p, err
	}
	referenced, err := s.LoadBoolBit()
	if err != nil {
		return p, fmt.Errorf("token payload missing: %w", err)
	}
	var payload *cell.Cell
	if referenced {
		payload, err = loadRefCell(s, "token call payload")
		if err != nil {
			return p, err
		}
		if err = exhausted(s, "token forward payload"); err != nil {
			return p, err
		}
	} else {
		b := cell.BeginCell()
		bitCount := s.BitsLeft()
		bits, err := s.LoadSlice(bitCount)
		if err != nil {
			return p, err
		}
		if err = b.StoreSlice(bits, bitCount); err != nil {
			return p, err
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
		payload = b.EndCell()
	}
	return DecodeServiceActorTokenCallPayload(payload)
}
