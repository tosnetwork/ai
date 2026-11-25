package nativecore

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	ServiceActorTokenRail               = "tos.service.service-actor-token.v1"
	ServiceActorTokenMaxLiveGlobal      = 1500
	ServiceActorTokenMaxReturnedEntries = 3512
	ServiceActorTokenMaxPayoutEntries   = 5532
	ServiceActorTokenMaxAttestorKeys    = 4
)

var ServiceActorTokenReleaseCodeHash = [32]byte{0x4e, 0x79, 0x7e, 0xcf, 0xfa, 0x62, 0x61, 0x48, 0x31, 0xf5, 0x3f, 0x03, 0xdb, 0xf9, 0x4d, 0x85, 0x1b, 0x6e, 0x64, 0x18, 0xfa, 0x3e, 0x84, 0xd0, 0x5a, 0xf8, 0xba, 0x57, 0x5d, 0xf7, 0x08, 0x5a}
var ServiceActorTokenTestProfileCodeHash = [32]byte{0xed, 0xf7, 0x27, 0xb8, 0xbb, 0x61, 0x78, 0x6e, 0x33, 0xe3, 0xe0, 0x0d, 0xc5, 0x7f, 0xa1, 0xdb, 0x41, 0xf8, 0xee, 0xb6, 0xcb, 0xdd, 0xc0, 0x38, 0x2b, 0x3e, 0x8d, 0xaf, 0x22, 0x7e, 0x4c, 0x89}

type ServiceActorTokenPolicyV1 struct {
	ServiceActorPolicyV1
	MaxTokenLiability *big.Int
}
type ServiceActorTokenAssetRouteV1 struct {
	Master            MsgAddressV1
	WalletCodeHash    [32]byte
	WalletCode        *cell.Cell
	BridgeConfigParam uint32
}
type ServiceActorTokenLedgerV1 struct {
	PendingLiability, RefundableLiability, ReturnedLiability, InFlight, WithdrawableTokenRevenue *big.Int
}
type ServiceActorTokenBalanceQueryV1 struct {
	Active              bool
	QueryID             uint64
	Purpose             uint8
	CreatedAt           uint32
	Floor               uint64
	DeliveredSinceFloor *big.Int
	RecheckTarget       uint64
	Amount              *big.Int
	Requester           MsgAddressV1
}
type ServiceActorTokenAccountingV1 struct {
	WithdrawableTOSRevenue, LockedStorageFees, LockedOutcomeFees *big.Int
	CallDay, CallsToday                                          uint32
	RevenuePayoutsInFlight                                       uint8
	ReturnedCount                                                uint32
	ReturnsInFlight                                              uint16
	SurplusPayoutsInFlight, AttestorKeyCount                     uint8
	Ledger                                                       ServiceActorTokenLedgerV1
	BalanceQuery                                                 ServiceActorTokenBalanceQueryV1
}
type ServiceActorTokenAttestorKeyV1 struct {
	Refs uint32
	Key  []byte
}
type ServiceActorTokenPayoutV1 struct {
	Kind                       uint8
	RequestID                  uint64
	Recipient, Requester       MsgAddressV1
	Amount                     *big.Int
	CreatedAt                  uint32
	RecipientWallet, OwnWallet MsgAddressV1
	OutcomeFeeLock             *big.Int
	UndoSource                 uint8
	UndoPending                *ServiceActorPendingRequestV1
	UndoRefund                 *ServiceActorRefundV1
}
type ServiceActorTokenReturnedV1 struct {
	Caller                 MsgAddressV1
	Amount                 *big.Int
	Paying, ReturnDeadline uint64
}
type ServiceActorTokenDataV1 struct {
	Owner                   MsgAddressV1
	Active                  bool
	NextRequestID           uint64
	PendingCount, LiveCount uint32
	NextPayoutID            uint64
	Policy                  ServiceActorTokenPolicyV1
	Accounting              ServiceActorTokenAccountingV1
	Route                   ServiceActorTokenAssetRouteV1
	Pending                 map[uint64]ServiceActorPendingRequestV1
	Refunds                 map[uint64]ServiceActorRefundV1
	CallerLiveCounts        map[[32]byte]uint32
	AttestorKeys            map[[32]byte]ServiceActorTokenAttestorKeyV1
	Payouts                 map[uint64]ServiceActorTokenPayoutV1
	Returned                map[uint64]ServiceActorTokenReturnedV1
	CallerReturnedCounts    map[[32]byte]uint32
}

// DecodeServiceActorTokenData decodes the entire typed account state. No getter
// summary can substitute for these cells when deriving a request outcome.
func DecodeServiceActorTokenData(value *cell.Cell) (*ServiceActorTokenDataV1, error) {
	s, err := beginOrdinary(value, "token actor data")
	if err != nil {
		return nil, err
	}
	d := &ServiceActorTokenDataV1{}
	if d.Owner, err = loadMsgAddress(s); err != nil {
		return nil, err
	}
	if d.Active, err = s.LoadBoolBit(); err != nil {
		return nil, err
	}
	if d.NextRequestID, err = s.LoadUInt(64); err != nil {
		return nil, err
	}
	n, err := s.LoadUInt(32)
	if err != nil {
		return nil, err
	}
	d.PendingCount = uint32(n)
	n, err = s.LoadUInt(32)
	if err != nil {
		return nil, err
	}
	d.LiveCount = uint32(n)
	if d.NextPayoutID, err = s.LoadUInt(64); err != nil {
		return nil, err
	}
	policy, err := loadRefCell(s, "token actor policy")
	if err != nil {
		return nil, err
	}
	accounting, err := loadRefCell(s, "token actor accounting")
	if err != nil {
		return nil, err
	}
	requests, err := loadRefCell(s, "token actor requests")
	if err != nil {
		return nil, err
	}
	payouts, err := loadRefCell(s, "token actor payouts")
	if err != nil {
		return nil, err
	}
	if err = exhausted(s, "token actor data"); err != nil {
		return nil, err
	}
	if d.Policy, err = decodeTokenPolicy(policy); err != nil {
		return nil, err
	}
	if d.Accounting, d.Route, err = decodeTokenAccounting(accounting); err != nil {
		return nil, err
	}
	if err = decodeTokenRequests(requests, d); err != nil {
		return nil, err
	}
	if err = decodeTokenPayoutDicts(payouts, d); err != nil {
		return nil, err
	}
	return d, nil
}
func decodeTokenPolicy(value *cell.Cell) (ServiceActorTokenPolicyV1, error) {
	var p ServiceActorTokenPolicyV1
	s, err := beginOrdinary(value, "token actor policy")
	if err != nil {
		return p, err
	}
	n, err := s.LoadUInt(32)
	if err != nil {
		return p, err
	}
	p.PolicyVersion = uint32(n)
	for _, f := range []**big.Int{&p.PricePerCall, &p.StorageFee, &p.CleanupBounty} {
		if *f, err = loadServiceActorCoins(s); err != nil {
			return p, err
		}
	}
	n, err = s.LoadUInt(32)
	if err != nil {
		return p, err
	}
	p.ResponseSLA = uint32(n)
	n, err = s.LoadUInt(32)
	if err != nil {
		return p, err
	}
	p.RefundClaimWindow = uint32(n)
	if p.OpenAccess, err = s.LoadBoolBit(); err != nil {
		return p, err
	}
	if p.HasAuthorizedCaller, err = s.LoadBoolBit(); err != nil {
		return p, err
	}
	if p.AuthorizedCaller, err = loadMsgAddress(s); err != nil {
		return p, err
	}
	n, err = s.LoadUInt(32)
	if err != nil {
		return p, err
	}
	p.RateLimitPerDay = uint32(n)
	if p.MaxTokenLiability, err = loadServiceActorCoins(s); err != nil {
		return p, err
	}
	ref, err := loadRefCell(s, "token policy commitments")
	if err != nil {
		return p, err
	}
	if err = exhausted(s, "token actor policy"); err != nil {
		return p, err
	}
	c, err := beginOrdinary(ref, "token policy commitments")
	if err != nil {
		return p, err
	}
	if p.MetadataHash, err = loadHash(c); err != nil {
		return p, err
	}
	if p.ProofSchemeHash, err = loadHash(c); err != nil {
		return p, err
	}
	if p.HasAttestor, err = c.LoadBoolBit(); err != nil {
		return p, err
	}
	if p.AttestorKeyID, err = loadHash(c); err != nil {
		return p, err
	}
	if p.AttestorKey, err = loadAttestorCommitment(c, p.HasAttestor, p.AttestorKeyID, "token policy"); err != nil {
		return p, err
	}
	return p, exhausted(c, "token policy commitments")
}
func decodeTokenAccounting(value *cell.Cell) (ServiceActorTokenAccountingV1, ServiceActorTokenAssetRouteV1, error) {
	var a ServiceActorTokenAccountingV1
	var route ServiceActorTokenAssetRouteV1
	s, err := beginOrdinary(value, "token accounting")
	if err != nil {
		return a, route, err
	}
	for _, f := range []**big.Int{&a.WithdrawableTOSRevenue, &a.LockedStorageFees, &a.LockedOutcomeFees} {
		if *f, err = loadServiceActorCoins(s); err != nil {
			return a, route, err
		}
	}
	n, err := s.LoadUInt(32)
	if err != nil {
		return a, route, err
	}
	a.CallDay = uint32(n)
	n, err = s.LoadUInt(32)
	if err != nil {
		return a, route, err
	}
	a.CallsToday = uint32(n)
	n, err = s.LoadUInt(8)
	if err != nil {
		return a, route, err
	}
	a.RevenuePayoutsInFlight = uint8(n)
	n, err = s.LoadUInt(32)
	if err != nil {
		return a, route, err
	}
	a.ReturnedCount = uint32(n)
	n, err = s.LoadUInt(16)
	if err != nil {
		return a, route, err
	}
	a.ReturnsInFlight = uint16(n)
	n, err = s.LoadUInt(8)
	if err != nil {
		return a, route, err
	}
	a.SurplusPayoutsInFlight = uint8(n)
	n, err = s.LoadUInt(8)
	if err != nil {
		return a, route, err
	}
	a.AttestorKeyCount = uint8(n)
	ledger, err := loadRefCell(s, "token ledger")
	if err != nil {
		return a, route, err
	}
	query, err := loadRefCell(s, "token balance query")
	if err != nil {
		return a, route, err
	}
	routeCell, err := loadRefCell(s, "token asset route")
	if err != nil {
		return a, route, err
	}
	if err = exhausted(s, "token accounting"); err != nil {
		return a, route, err
	}
	l, err := beginOrdinary(ledger, "token ledger")
	if err != nil {
		return a, route, err
	}
	for _, f := range []**big.Int{&a.Ledger.PendingLiability, &a.Ledger.RefundableLiability, &a.Ledger.ReturnedLiability, &a.Ledger.InFlight, &a.Ledger.WithdrawableTokenRevenue} {
		if *f, err = loadServiceActorCoins(l); err != nil {
			return a, route, err
		}
	}
	if err = exhausted(l, "token ledger"); err != nil {
		return a, route, err
	}
	if a.BalanceQuery, err = decodeTokenBalanceQuery(query); err != nil {
		return a, route, err
	}
	route, err = decodeTokenAssetRoute(routeCell)
	return a, route, err
}
func decodeTokenBalanceQuery(value *cell.Cell) (ServiceActorTokenBalanceQueryV1, error) {
	var q ServiceActorTokenBalanceQueryV1
	s, err := beginOrdinary(value, "token balance query")
	if err != nil {
		return q, err
	}
	if q.Active, err = s.LoadBoolBit(); err != nil {
		return q, err
	}
	if q.QueryID, err = s.LoadUInt(64); err != nil {
		return q, err
	}
	n, err := s.LoadUInt(1)
	if err != nil {
		return q, err
	}
	q.Purpose = uint8(n)
	n, err = s.LoadUInt(32)
	if err != nil {
		return q, err
	}
	q.CreatedAt = uint32(n)
	if q.Floor, err = s.LoadUInt(64); err != nil {
		return q, err
	}
	if q.DeliveredSinceFloor, err = loadServiceActorCoins(s); err != nil {
		return q, err
	}
	if q.RecheckTarget, err = s.LoadUInt(64); err != nil {
		return q, err
	}
	if q.Amount, err = loadServiceActorCoins(s); err != nil {
		return q, err
	}
	if q.Requester, err = loadMsgAddress(s); err != nil {
		return q, err
	}
	if err = exhausted(s, "token balance query"); err != nil {
		return q, err
	}
	if !q.Active && (q.QueryID != 0 || q.Purpose != 0 || q.CreatedAt != 0 || q.Floor != 0 || q.DeliveredSinceFloor.Sign() != 0 || q.RecheckTarget != 0 || q.Amount.Sign() != 0 || q.Requester.Kind != msgAddressNone) {
		return q, errors.New("inactive balance query is not empty")
	}
	if q.Active && q.Purpose == 0 && q.RecheckTarget != 0 {
		return q, errors.New("surplus query has a target")
	}
	return q, nil
}
func decodeTokenAssetRoute(value *cell.Cell) (ServiceActorTokenAssetRouteV1, error) {
	var r ServiceActorTokenAssetRouteV1
	s, err := beginOrdinary(value, "token asset route")
	if err != nil {
		return r, err
	}
	if r.Master, err = loadMsgAddressInt(s); err != nil {
		return r, err
	}
	if r.WalletCodeHash, err = loadHash(s); err != nil {
		return r, err
	}
	if r.WalletCode, err = loadRefCell(s, "token wallet code"); err != nil {
		return r, err
	}
	n, err := s.LoadUInt(32)
	if err != nil {
		return r, err
	}
	r.BridgeConfigParam = uint32(n)
	if err = exhausted(s, "token asset route"); err != nil {
		return r, err
	}
	if err := ValidateServiceActorTokenWalletCodeGraph(r.WalletCode); err != nil {
		return r, err
	}
	if !bytes.Equal(r.WalletCodeHash[:], r.WalletCode.Hash()) {
		return r, errors.New("token wallet code hash disagrees with its cell")
	}
	return r, nil
}
func decodeTokenRequests(value *cell.Cell, d *ServiceActorTokenDataV1) error {
	s, err := beginOrdinary(value, "token requests")
	if err != nil {
		return err
	}
	pending, err := walkHashmapE(s, 64, ServiceActorTokenMaxLiveGlobal, "token pending")
	if err != nil {
		return err
	}
	refunds, err := walkHashmapE(s, 64, ServiceActorTokenMaxLiveGlobal, "token refunds")
	if err != nil {
		return err
	}
	counts, err := walkHashmapE(s, 256, ServiceActorTokenMaxLiveGlobal, "token live counts")
	if err != nil {
		return err
	}
	keys, err := walkHashmapE(s, 256, ServiceActorTokenMaxAttestorKeys, "token attestor keys")
	if err != nil {
		return err
	}
	if err = exhausted(s, "token requests"); err != nil {
		return err
	}
	d.Pending = make(map[uint64]ServiceActorPendingRequestV1, len(pending))
	d.Refunds = make(map[uint64]ServiceActorRefundV1, len(refunds))
	d.CallerLiveCounts = make(map[[32]byte]uint32, len(counts))
	d.AttestorKeys = make(map[[32]byte]ServiceActorTokenAttestorKeyV1, len(keys))
	for _, leaf := range pending {
		ref, e := loadDictRefValue(leaf.value, "token pending")
		if e != nil {
			return e
		}
		entry, e := decodeTokenPending(ref)
		if e != nil {
			return e
		}
		d.Pending[new(big.Int).SetBytes(leaf.key).Uint64()] = entry
	}
	for _, leaf := range refunds {
		ref, e := loadDictRefValue(leaf.value, "token refund")
		if e != nil {
			return e
		}
		entry, e := decodeServiceActorRefund(ref)
		if e != nil {
			return e
		}
		id := new(big.Int).SetBytes(leaf.key).Uint64()
		if _, ok := d.Pending[id]; ok {
			return errors.New("token request both pending and refundable")
		}
		d.Refunds[id] = entry
	}
	for _, leaf := range counts {
		n, e := leaf.value.LoadUInt(32)
		if e != nil {
			return e
		}
		if e = exhausted(leaf.value, "token live count"); e != nil {
			return e
		}
		if n == 0 || n > ServiceActorMaxLivePerCaller {
			return errors.New("token caller live count outside bounds")
		}
		var key [32]byte
		copy(key[:], leaf.key)
		d.CallerLiveCounts[key] = uint32(n)
	}
	for _, leaf := range keys {
		n, e := leaf.value.LoadUInt(32)
		if e != nil {
			return e
		}
		keyCell, e := loadRefCell(leaf.value, "token attestor key")
		if e != nil {
			return e
		}
		if e = exhausted(leaf.value, "token attestor entry"); e != nil {
			return e
		}
		if n == 0 || n > ServiceActorTokenMaxLiveGlobal {
			return errors.New("token key reference count outside bounds")
		}
		key, e := readStoredBytes(keyCell, mldsa44.PublicKeySize)
		if e != nil {
			return e
		}
		id, e := mldsa44.KeyID(key)
		if e != nil {
			return e
		}
		if !bytes.Equal(id[:], leaf.key) {
			return errors.New("token stored key does not derive its dictionary key")
		}
		d.AttestorKeys[id] = ServiceActorTokenAttestorKeyV1{Refs: uint32(n), Key: key}
	}
	return nil
}
func decodeTokenPending(value *cell.Cell) (ServiceActorPendingRequestV1, error) {
	var p ServiceActorPendingRequestV1
	s, err := beginOrdinary(value, "token pending request")
	if err != nil {
		return p, err
	}
	if p.Caller, err = loadMsgAddressInt(s); err != nil {
		return p, err
	}
	for _, f := range []**big.Int{&p.Price, &p.StorageFee, &p.CleanupBounty} {
		if *f, err = loadServiceActorCoins(s); err != nil {
			return p, err
		}
	}
	if p.ResponseDeadline, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	if p.RefundClaimDeadline, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	n, err := s.LoadUInt(32)
	if err != nil {
		return p, err
	}
	p.PolicyVersion = uint32(n)
	ref, err := loadRefCell(s, "token pending commitments")
	if err != nil {
		return p, err
	}
	if err = exhausted(s, "token pending request"); err != nil {
		return p, err
	}
	c, err := beginOrdinary(ref, "token pending commitments")
	if err != nil {
		return p, err
	}
	if p.RequestHash, err = loadHash(c); err != nil {
		return p, err
	}
	if p.TermsHash, err = loadHash(c); err != nil {
		return p, err
	}
	if p.HasAttestor, err = c.LoadBoolBit(); err != nil {
		return p, err
	}
	if p.AttestorKeyID, err = loadHash(c); err != nil {
		return p, err
	}
	present, err := c.LoadBoolBit()
	if err != nil {
		return p, err
	}
	if present {
		return p, errors.New("token pending request carries an inline attestor key")
	}
	if p.HasAttestor == (p.AttestorKeyID == [32]byte{}) {
		return p, errors.New("token pending attestor flag and id disagree")
	}
	return p, exhausted(c, "token pending commitments")
}
func decodeTokenPayoutDicts(value *cell.Cell, d *ServiceActorTokenDataV1) error {
	s, err := beginOrdinary(value, "token payout dictionaries")
	if err != nil {
		return err
	}
	payouts, err := walkHashmapE(s, 64, ServiceActorTokenMaxPayoutEntries, "token payouts")
	if err != nil {
		return err
	}
	returned, err := walkHashmapE(s, 64, ServiceActorTokenMaxReturnedEntries, "token returned")
	if err != nil {
		return err
	}
	counts, err := walkHashmapE(s, 256, ServiceActorTokenMaxReturnedEntries, "token returned counts")
	if err != nil {
		return err
	}
	if err = exhausted(s, "token payout dictionaries"); err != nil {
		return err
	}
	d.Payouts = make(map[uint64]ServiceActorTokenPayoutV1, len(payouts))
	d.Returned = make(map[uint64]ServiceActorTokenReturnedV1, len(returned))
	d.CallerReturnedCounts = make(map[[32]byte]uint32, len(counts))
	for _, leaf := range payouts {
		ref, e := loadDictRefValue(leaf.value, "token payout")
		if e != nil {
			return e
		}
		p, e := decodeTokenPayout(ref)
		if e != nil {
			return e
		}
		d.Payouts[new(big.Int).SetBytes(leaf.key).Uint64()] = p
	}
	for _, leaf := range returned {
		ref, e := loadDictRefValue(leaf.value, "token returned")
		if e != nil {
			return e
		}
		p, e := decodeTokenReturned(ref)
		if e != nil {
			return e
		}
		d.Returned[new(big.Int).SetBytes(leaf.key).Uint64()] = p
	}
	for _, leaf := range counts {
		n, e := leaf.value.LoadUInt(32)
		if e != nil {
			return e
		}
		if n == 0 {
			return errors.New("token returned count is zero")
		}
		if e = exhausted(leaf.value, "token returned count"); e != nil {
			return e
		}
		var key [32]byte
		copy(key[:], leaf.key)
		d.CallerReturnedCounts[key] = uint32(n)
	}
	return nil
}
func decodeTokenPayout(value *cell.Cell) (ServiceActorTokenPayoutV1, error) {
	var p ServiceActorTokenPayoutV1
	s, err := beginOrdinary(value, "token payout")
	if err != nil {
		return p, err
	}
	n, err := s.LoadUInt(3)
	if err != nil || n < 1 || n > 7 {
		return p, errors.New("token payout kind outside 1..7")
	}
	p.Kind = uint8(n)
	if p.RequestID, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	if p.Recipient, err = loadMsgAddressInt(s); err != nil {
		return p, err
	}
	if p.Requester, err = loadMsgAddressInt(s); err != nil {
		return p, err
	}
	if p.Amount, err = loadServiceActorCoins(s); err != nil {
		return p, err
	}
	n, err = s.LoadUInt(32)
	if err != nil {
		return p, err
	}
	p.CreatedAt = uint32(n)
	ref, err := loadRefCell(s, "token payout auth")
	if err != nil {
		return p, err
	}
	if err = exhausted(s, "token payout"); err != nil {
		return p, err
	}
	a, err := beginOrdinary(ref, "token payout auth")
	if err != nil {
		return p, err
	}
	if p.RecipientWallet, err = loadMsgAddressInt(a); err != nil {
		return p, err
	}
	if p.OwnWallet, err = loadMsgAddressInt(a); err != nil {
		return p, err
	}
	if p.OutcomeFeeLock, err = loadServiceActorCoins(a); err != nil {
		return p, err
	}
	undo, err := loadRefCell(a, "token payout undo")
	if err != nil {
		return p, err
	}
	if err = exhausted(a, "token payout auth"); err != nil {
		return p, err
	}
	u, err := beginOrdinary(undo, "token payout undo")
	if err != nil {
		return p, err
	}
	n, err = u.LoadUInt(2)
	if err != nil || n > 2 {
		return p, errors.New("token payout undo source outside bounds")
	}
	p.UndoSource = uint8(n)
	if n != 0 {
		entry, e := loadRefCell(u, "token payout undo entry")
		if e != nil {
			return p, e
		}
		if n == 1 {
			r, e := decodeTokenPending(entry)
			if e != nil {
				return p, e
			}
			p.UndoPending = &r
		} else {
			r, e := decodeServiceActorRefund(entry)
			if e != nil {
				return p, e
			}
			p.UndoRefund = &r
		}
	}
	if err = exhausted(u, "token payout undo"); err != nil {
		return p, err
	}
	if p.Kind == 1 && p.UndoSource != 2 || p.Kind == 2 && p.UndoSource == 0 || p.Kind != 1 && p.Kind != 2 && p.UndoSource != 0 {
		return p, errors.New("token payout kind and undo source disagree")
	}
	return p, nil
}
func decodeTokenReturned(value *cell.Cell) (ServiceActorTokenReturnedV1, error) {
	var p ServiceActorTokenReturnedV1
	s, err := beginOrdinary(value, "token returned entry")
	if err != nil {
		return p, err
	}
	if p.Caller, err = loadMsgAddressInt(s); err != nil {
		return p, err
	}
	if p.Amount, err = loadServiceActorCoins(s); err != nil {
		return p, err
	}
	if p.Paying, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	if p.ReturnDeadline, err = s.LoadUInt(64); err != nil {
		return p, err
	}
	return p, exhausted(s, "token returned entry")
}

// DeriveServiceActorTokenWallet reproduces the route's wallet StateInit.
func DeriveServiceActorTokenWallet(owner string, route ServiceActorTokenAssetRouteV1) (string, error) {
	o, err := StandardAddress(owner)
	if err != nil {
		return "", err
	}
	if o.Workchain != 0 {
		return "", errors.New("token wallet owner is not on workchain zero")
	}
	if err = validateTokenStoredAddress(route.Master, true); err != nil {
		return "", err
	}
	if _, ok := route.Master.RawStandard(); !ok || route.Master.Workchain != 0 {
		return "", errors.New("token master is not canonical on workchain zero")
	}
	if err := ValidateServiceActorTokenWalletCodeGraph(route.WalletCode); err != nil {
		return "", err
	}
	if !bytes.Equal(route.WalletCodeHash[:], route.WalletCode.Hash()) {
		return "", errors.New("token wallet code hash mismatch")
	}
	settlement := cell.BeginCell()
	for _, n := range []uint{161, 192, 1, 128, 1} {
		if err = settlement.StoreSlice(make([]byte, (n+7)/8), n); err != nil {
			return "", err
		}
	}
	data := cell.BeginCell()
	if err = storeServiceActorCoins(data, new(big.Int)); err != nil {
		return "", err
	}
	if err = data.StoreSlice(o.Bits, o.BitLen); err != nil {
		return "", err
	}
	if err = data.StoreSlice(route.Master.Bits, route.Master.BitLen); err != nil {
		return "", err
	}
	if err = data.StoreRef(route.WalletCode); err != nil {
		return "", err
	}
	if err = data.StoreRef(settlement.EndCell()); err != nil {
		return "", err
	}
	if err = data.StoreUInt(0, 16); err != nil {
		return "", err
	}
	if err = data.StoreBoolBit(false); err != nil {
		return "", err
	}
	init := cell.BeginCell().MustStoreBoolBit(false).MustStoreBoolBit(false).MustStoreBoolBit(true).MustStoreRef(route.WalletCode).MustStoreBoolBit(true).MustStoreRef(data.EndCell()).MustStoreBoolBit(false).EndCell()
	return fmt.Sprintf("0:%x", init.Hash()), nil
}

func tokenCoinsValid(values ...*big.Int) bool {
	for _, v := range values {
		if v == nil || v.Sign() < 0 || v.Cmp(MaxServiceActorCoins) >= 0 {
			return false
		}
	}
	return true
}

// ValidateServiceActorTokenLiveState checks ledgers against the bounded decoded
// dictionaries, including undo entries that remain live while a payout is paying.
func ValidateServiceActorTokenLiveState(d *ServiceActorTokenDataV1) error {
	if d == nil {
		return errors.New("token actor state is missing")
	}
	if len(d.Pending) > ServiceActorTokenMaxLiveGlobal || len(d.Refunds) > ServiceActorTokenMaxLiveGlobal || len(d.Payouts) > ServiceActorTokenMaxPayoutEntries || len(d.Returned) > ServiceActorTokenMaxReturnedEntries || len(d.AttestorKeys) > ServiceActorTokenMaxAttestorKeys || len(d.CallerLiveCounts) > ServiceActorTokenMaxLiveGlobal || len(d.CallerReturnedCounts) > ServiceActorTokenMaxReturnedEntries {
		return errors.New("token actor dictionary bound exceeded")
	}
	a := d.Accounting
	q := a.BalanceQuery
	if q.Active && (q.QueryID == 0 || q.QueryID >= d.NextPayoutID || q.Floor != q.QueryID || !q.Requester.IsInternal() || !tokenCoinsValid(q.Amount, q.DeliveredSinceFloor) || q.Purpose == 0 && (q.RecheckTarget != 0 || q.Amount.Sign() == 0) || q.Purpose == 1 && (q.RecheckTarget == 0 || q.Amount.Sign() != 0) || q.Purpose > 1) {
		return errors.New("active token balance query inconsistent")
	}
	l := a.Ledger
	if !tokenCoinsValid(a.WithdrawableTOSRevenue, a.LockedStorageFees, a.LockedOutcomeFees, l.PendingLiability, l.RefundableLiability, l.ReturnedLiability, l.InFlight, l.WithdrawableTokenRevenue) {
		return errors.New("token ledger amount outside bounds")
	}
	if d.NextPayoutID == 0 || d.LiveCount > ServiceActorTokenMaxLiveGlobal || a.RevenuePayoutsInFlight > 4 || a.ReturnsInFlight > 512 || a.SurplusPayoutsInFlight > 4 || a.AttestorKeyCount > 4 {
		return errors.New("token actor counter outside bounds")
	}
	pending, refundable, returned, inflight, storage, locks := new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	liveCounts := map[[32]byte]uint32{}
	returnedCounts := map[[32]byte]uint32{}
	keyRefs := map[[32]byte]uint32{}
	requestIDs := map[uint64]bool{}
	var pendingCount, liveCount uint32
	var revenueCount, surplusCount, returnCount uint32
	addLive := func(id uint64, caller MsgAddressV1, fee *big.Int, isPending bool, keyID [32]byte, hasKey bool) error {
		if hasKey && keyID == [32]byte{} || !hasKey && keyID != [32]byte{} {
			return errors.New("token pending attestor flag and id disagree")
		}
		if id >= d.NextRequestID || requestIDs[id] {
			return errors.New("token request identity inconsistent")
		}
		requestIDs[id] = true
		if !tokenCoinsValid(fee) {
			return errors.New("token storage fee invalid")
		}
		storage.Add(storage, fee)
		h, e := caller.SliceHash()
		if e != nil {
			return e
		}
		liveCounts[h]++
		liveCount++
		if isPending {
			pendingCount++
			if hasKey {
				keyRefs[keyID]++
			}
		}
		return nil
	}
	for id, p := range d.Pending {
		if !tokenCoinsValid(p.Price) {
			return errors.New("token pending price invalid")
		}
		pending.Add(pending, p.Price)
		if err := addLive(id, p.Caller, p.StorageFee, true, p.AttestorKeyID, p.HasAttestor); err != nil {
			return err
		}
	}
	for id, p := range d.Refunds {
		if !tokenCoinsValid(p.Price) {
			return errors.New("token refund price invalid")
		}
		refundable.Add(refundable, p.Price)
		if err := addLive(id, p.Caller, p.StorageFee, false, [32]byte{}, false); err != nil {
			return err
		}
	}
	for id, p := range d.Payouts {
		if id == 0 || id >= d.NextPayoutID || !tokenCoinsValid(p.Amount, p.OutcomeFeeLock) {
			return errors.New("token payout identity or amount invalid")
		}
		inflight.Add(inflight, p.Amount)
		locks.Add(locks, p.OutcomeFeeLock)
		switch p.Kind {
		case 1, 2:
			if p.UndoSource == 1 && p.UndoPending != nil {
				u := p.UndoPending
				if !tokenCoinsValid(u.Price) || u.Price.Cmp(p.Amount) != 0 {
					return errors.New("token payout amount differs from undo")
				}
				if err := addLive(p.RequestID, u.Caller, u.StorageFee, true, u.AttestorKeyID, u.HasAttestor); err != nil {
					return err
				}
			} else if p.UndoSource == 2 && p.UndoRefund != nil {
				u := p.UndoRefund
				if !tokenCoinsValid(u.Price) || u.Price.Cmp(p.Amount) != 0 {
					return errors.New("token payout amount differs from undo")
				}
				if err := addLive(p.RequestID, u.Caller, u.StorageFee, false, [32]byte{}, false); err != nil {
					return err
				}
			} else {
				return errors.New("token payout has no live undo")
			}
		case 3:
			revenueCount++
		case 4:
			returnCount++
		case 5, 7:
			r, ok := d.Returned[p.RequestID]
			if !ok || r.Paying != id || !tokenCoinsValid(r.Amount) || r.Amount.Cmp(p.Amount) != 0 {
				return errors.New("token returned payout disagrees with entry")
			}
		case 6:
			surplusCount++
		default:
			return errors.New("token payout kind invalid")
		}
	}
	for id, p := range d.Returned {
		if id == 0 || id >= d.NextPayoutID || !tokenCoinsValid(p.Amount) {
			return errors.New("token returned identity or amount invalid")
		}
		h, e := p.Caller.SliceHash()
		if e != nil {
			return e
		}
		returnedCounts[h]++
		if p.Paying == 0 {
			returned.Add(returned, p.Amount)
		} else {
			pay, ok := d.Payouts[p.Paying]
			if !ok || (pay.Kind != 5 && pay.Kind != 7) || pay.RequestID != id {
				return errors.New("token returned entry names no matching payout")
			}
		}
	}
	if pendingCount != d.PendingCount || liveCount != d.LiveCount || uint64(len(d.Returned)) != uint64(a.ReturnedCount) || revenueCount != uint32(a.RevenuePayoutsInFlight) || returnCount != uint32(a.ReturnsInFlight) || surplusCount != uint32(a.SurplusPayoutsInFlight) || len(d.AttestorKeys) != int(a.AttestorKeyCount) {
		return errors.New("token actor counters disagree with dictionaries")
	}
	for _, p := range [][2]*big.Int{{pending, l.PendingLiability}, {refundable, l.RefundableLiability}, {returned, l.ReturnedLiability}, {inflight, l.InFlight}, {storage, a.LockedStorageFees}, {locks, a.LockedOutcomeFees}} {
		if p[0].Cmp(p[1]) != 0 {
			return errors.New("token actor ledger disagrees with dictionaries")
		}
	}
	if len(liveCounts) != len(d.CallerLiveCounts) || len(returnedCounts) != len(d.CallerReturnedCounts) || len(keyRefs) != len(d.AttestorKeys) {
		return errors.New("token actor index count mismatch")
	}
	for key, n := range liveCounts {
		if d.CallerLiveCounts[key] != n {
			return errors.New("token actor caller live count mismatch")
		}
	}
	for key, n := range returnedCounts {
		if d.CallerReturnedCounts[key] != n {
			return errors.New("token actor caller returned count mismatch")
		}
	}
	for key, n := range keyRefs {
		entry := d.AttestorKeys[key]
		derived, err := mldsa44.KeyID(entry.Key)
		if err != nil || derived != key {
			return errors.New("token key store identity mismatch")
		}
		if entry.Refs != n {
			return errors.New("token actor key refs mismatch")
		}
	}
	return nil
}

// validateTokenStoredAddress checks the wire bits and their decoded metadata
// before an encoder uses a caller-provided address value.
func validateTokenStoredAddress(a MsgAddressV1, internal bool) error {
	if a.BitLen > 591 {
		return errors.New("token address exceeds its wire bound")
	}
	b := cell.BeginCell()
	if err := b.StoreSlice(a.Bits, a.BitLen); err != nil {
		return err
	}
	decoded, err := DecodeMsgAddressCell(b.EndCell())
	if err != nil {
		return err
	}
	if decoded.Kind != a.Kind || decoded.Workchain != a.Workchain || decoded.AddressBits != a.AddressBits || decoded.AnycastDepth != a.AnycastDepth || !bytes.Equal(decoded.Address, a.Address) || !bytes.Equal(decoded.AnycastPrefix, a.AnycastPrefix) {
		return errors.New("token address metadata differs from its bits")
	}
	if internal && !decoded.IsInternal() {
		return errors.New("token address is not internal")
	}
	return nil
}

// ValidateServiceActorTokenWalletCodeGraph requires complete ordinary code,
// bounded before hashing or using it as an address-derivation preimage.
func ValidateServiceActorTokenWalletCodeGraph(root *cell.Cell) error {
	if root == nil {
		return errors.New("missing token wallet code")
	}
	seen := make(map[*cell.Cell]struct{})
	work := []*cell.Cell{root}
	for len(work) > 0 {
		last := len(work) - 1
		current := work[last]
		work = work[:last]
		if current == nil || current.IsLazy() || current.GetType() != cell.OrdinaryCellType {
			return errors.New("token wallet code graph must be complete and ordinary")
		}
		if _, exists := seen[current]; exists {
			continue
		}
		seen[current] = struct{}{}
		if len(seen) > 8192 {
			return errors.New("token wallet code graph exceeds cell budget")
		}
		for index := 0; index < int(current.RefsNum()); index++ {
			ref, err := current.PeekRef(index)
			if err != nil {
				return err
			}
			work = append(work, ref)
		}
	}
	return nil
}
