package nativecore

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func tokenTestCoins(t *testing.T, b *cell.Builder, values ...*big.Int) {
	t.Helper()
	for _, v := range values {
		if e := storeServiceActorCoins(b, v); e != nil {
			t.Fatal(e)
		}
	}
}
func tokenTestPendingCell(t *testing.T, p ServiceActorPendingRequestV1) *cell.Cell {
	t.Helper()
	c := cell.BeginCell().MustStoreSlice(p.RequestHash[:], 256).MustStoreSlice(p.TermsHash[:], 256).MustStoreBoolBit(p.HasAttestor).MustStoreSlice(p.AttestorKeyID[:], 256).MustStoreBoolBit(false).EndCell()
	b := cell.BeginCell().MustStoreSlice(p.Caller.Bits, p.Caller.BitLen)
	tokenTestCoins(t, b, p.Price, p.StorageFee, p.CleanupBounty)
	return b.MustStoreUInt(p.ResponseDeadline, 64).MustStoreUInt(p.RefundClaimDeadline, 64).MustStoreUInt(uint64(p.PolicyVersion), 32).MustStoreRef(c).EndCell()
}
func tokenTestRefundCell(t *testing.T, p ServiceActorRefundV1) *cell.Cell {
	t.Helper()
	b := cell.BeginCell().MustStoreSlice(p.Caller.Bits, p.Caller.BitLen)
	tokenTestCoins(t, b, p.Price, p.StorageFee, p.CleanupBounty)
	return b.MustStoreUInt(p.RefundClaimDeadline, 64).EndCell()
}
func tokenTestPayoutCell(t *testing.T, p ServiceActorTokenPayoutV1) *cell.Cell {
	t.Helper()
	u := cell.BeginCell().MustStoreUInt(uint64(p.UndoSource), 2)
	if p.UndoSource == 1 {
		u.MustStoreRef(tokenTestPendingCell(t, *p.UndoPending))
	} else if p.UndoSource == 2 {
		u.MustStoreRef(tokenTestRefundCell(t, *p.UndoRefund))
	}
	a := cell.BeginCell().MustStoreSlice(p.RecipientWallet.Bits, p.RecipientWallet.BitLen).MustStoreSlice(p.OwnWallet.Bits, p.OwnWallet.BitLen)
	tokenTestCoins(t, a, p.OutcomeFeeLock)
	a.MustStoreRef(u.EndCell())
	b := cell.BeginCell().MustStoreUInt(uint64(p.Kind), 3).MustStoreUInt(p.RequestID, 64).MustStoreSlice(p.Recipient.Bits, p.Recipient.BitLen).MustStoreSlice(p.Requester.Bits, p.Requester.BitLen)
	tokenTestCoins(t, b, p.Amount)
	return b.MustStoreUInt(uint64(p.CreatedAt), 32).MustStoreRef(a.EndCell()).EndCell()
}
func tokenTestRefDict(t *testing.T, values map[uint64]*cell.Cell) *cell.Dictionary {
	t.Helper()
	dict := cell.NewDict(64)
	for id, v := range values {
		if e := dict.SetIntKey(new(big.Int).SetUint64(id), cell.BeginCell().MustStoreRef(v).EndCell()); e != nil {
			t.Fatal(e)
		}
	}
	return dict
}
func tokenTestCountDict(t *testing.T, values map[[32]byte]uint32) *cell.Dictionary {
	t.Helper()
	d := cell.NewDict(256)
	for k, n := range values {
		if e := d.SetIntKey(new(big.Int).SetBytes(k[:]), cell.BeginCell().MustStoreUInt(uint64(n), 32).EndCell()); e != nil {
			t.Fatal(e)
		}
	}
	return d
}
func tokenTestStateCell(t *testing.T, d *ServiceActorTokenDataV1) *cell.Cell {
	t.Helper()
	initial, e := BuildServiceActorTokenInitialData(d.Owner.Text(), d.Policy, d.Route)
	if e != nil {
		t.Fatal(e)
	}
	rs := initial.MustBeginParse()
	policy, _ := rs.LoadRefCell()
	ac, _ := rs.LoadRefCell()
	as := ac.MustBeginParse()
	_, _ = as.LoadRefCell()
	_, _ = as.LoadRefCell()
	route, _ := as.LoadRefCell()
	l := d.Accounting.Ledger
	ledger := cell.BeginCell()
	tokenTestCoins(t, ledger, l.PendingLiability, l.RefundableLiability, l.ReturnedLiability, l.InFlight, l.WithdrawableTokenRevenue)
	q := d.Accounting.BalanceQuery
	query := cell.BeginCell().MustStoreBoolBit(q.Active).MustStoreUInt(q.QueryID, 64).MustStoreUInt(uint64(q.Purpose), 1).MustStoreUInt(uint64(q.CreatedAt), 32).MustStoreUInt(q.Floor, 64)
	tokenTestCoins(t, query, q.DeliveredSinceFloor)
	query.MustStoreUInt(q.RecheckTarget, 64)
	tokenTestCoins(t, query, q.Amount)
	query.MustStoreSlice(q.Requester.Bits, q.Requester.BitLen)
	a := d.Accounting
	accounting := cell.BeginCell()
	tokenTestCoins(t, accounting, a.WithdrawableTOSRevenue, a.LockedStorageFees, a.LockedOutcomeFees)
	accounting.MustStoreUInt(uint64(a.CallDay), 32).MustStoreUInt(uint64(a.CallsToday), 32).MustStoreUInt(uint64(a.RevenuePayoutsInFlight), 8).MustStoreUInt(uint64(a.ReturnedCount), 32).MustStoreUInt(uint64(a.ReturnsInFlight), 16).MustStoreUInt(uint64(a.SurplusPayoutsInFlight), 8).MustStoreUInt(uint64(a.AttestorKeyCount), 8).MustStoreRef(ledger.EndCell()).MustStoreRef(query.EndCell()).MustStoreRef(route)
	pm := map[uint64]*cell.Cell{}
	for id, p := range d.Pending {
		pm[id] = tokenTestPendingCell(t, p)
	}
	fm := map[uint64]*cell.Cell{}
	for id, p := range d.Refunds {
		fm[id] = tokenTestRefundCell(t, p)
	}
	km := cell.NewDict(256)
	for id, k := range d.AttestorKeys {
		if e := km.SetIntKey(new(big.Int).SetBytes(id[:]), cell.BeginCell().MustStoreUInt(uint64(k.Refs), 32).MustStoreRef(storedBytesCell(k.Key)).EndCell()); e != nil {
			t.Fatal(e)
		}
	}
	requests := cell.BeginCell().MustStoreDict(tokenTestRefDict(t, pm)).MustStoreDict(tokenTestRefDict(t, fm)).MustStoreDict(tokenTestCountDict(t, d.CallerLiveCounts)).MustStoreDict(km).EndCell()
	pay := map[uint64]*cell.Cell{}
	for id, p := range d.Payouts {
		pay[id] = tokenTestPayoutCell(t, p)
	}
	ret := map[uint64]*cell.Cell{}
	for id, r := range d.Returned {
		b := cell.BeginCell().MustStoreSlice(r.Caller.Bits, r.Caller.BitLen)
		tokenTestCoins(t, b, r.Amount)
		ret[id] = b.MustStoreUInt(r.Paying, 64).MustStoreUInt(r.ReturnDeadline, 64).EndCell()
	}
	payouts := cell.BeginCell().MustStoreDict(tokenTestRefDict(t, pay)).MustStoreDict(tokenTestRefDict(t, ret)).MustStoreDict(tokenTestCountDict(t, d.CallerReturnedCounts)).EndCell()
	return cell.BeginCell().MustStoreSlice(d.Owner.Bits, d.Owner.BitLen).MustStoreBoolBit(d.Active).MustStoreUInt(d.NextRequestID, 64).MustStoreUInt(uint64(d.PendingCount), 32).MustStoreUInt(uint64(d.LiveCount), 32).MustStoreUInt(d.NextPayoutID, 64).MustStoreRef(policy).MustStoreRef(accounting.EndCell()).MustStoreRef(requests).MustStoreRef(payouts).EndCell()
}
func tokenTestEmptyState(t *testing.T) *ServiceActorTokenDataV1 {
	t.Helper()
	v := tokenVectorJSON(t, "service-actor-token-conformance-vectors.json")
	d, e := DecodeServiceActorTokenData(tokenVectorCell(t, v["deploy_data_boc_base64"].(string)))
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func tokenTestCaller(t *testing.T, d *ServiceActorTokenDataV1) (MsgAddressV1, [32]byte) {
	t.Helper()
	caller := d.Owner
	id, e := caller.SliceHash()
	if e != nil {
		t.Fatal(e)
	}
	return caller, id
}
func tokenTestPayout(t *testing.T, d *ServiceActorTokenDataV1, kind uint8) ServiceActorTokenPayoutV1 {
	t.Helper()
	caller, _ := tokenTestCaller(t, d)
	v := tokenVectorJSON(t, "service-actor-token-conformance-vectors.json")
	own, e := DeriveServiceActorTokenWallet(v["actor"].(string), d.Route)
	if e != nil {
		t.Fatal(e)
	}
	dest, e := DeriveServiceActorTokenWallet(caller.Text(), d.Route)
	if e != nil {
		t.Fatal(e)
	}
	ownAddr, e := StandardAddress(own)
	if e != nil {
		t.Fatal(e)
	}
	destAddr, e := StandardAddress(dest)
	if e != nil {
		t.Fatal(e)
	}
	return ServiceActorTokenPayoutV1{Kind: kind, Recipient: caller, Requester: caller, Amount: big.NewInt(1000), CreatedAt: 1700000000, RecipientWallet: destAddr, OwnWallet: ownAddr, OutcomeFeeLock: big.NewInt(10)}
}
func tokenTestRefund(caller MsgAddressV1) ServiceActorRefundV1 {
	return ServiceActorRefundV1{Caller: caller, Price: big.NewInt(1000), StorageFee: big.NewInt(200000000), CleanupBounty: big.NewInt(100000000), RefundClaimDeadline: 1700007200}
}
func TestServiceActorTokenDecodedPayingAndReturnedStates(t *testing.T) {
	for kind := uint8(1); kind <= 7; kind++ {
		t.Run(fmt.Sprintf("kind_%d", kind), func(t *testing.T) {
			d := tokenTestEmptyState(t)
			caller, key := tokenTestCaller(t, d)
			p := tokenTestPayout(t, d, kind)
			d.NextRequestID = 1
			d.NextPayoutID = 3
			d.Accounting.Ledger.InFlight = big.NewInt(1000)
			d.Accounting.LockedOutcomeFees = big.NewInt(10)
			switch kind {
			case 1, 2:
				r := tokenTestRefund(caller)
				p.UndoSource = 2
				p.UndoRefund = &r
				d.LiveCount = 1
				d.CallerLiveCounts[key] = 1
				d.Accounting.LockedStorageFees = big.NewInt(200000000)
			case 3:
				d.Accounting.RevenuePayoutsInFlight = 1
			case 4:
				d.Accounting.ReturnsInFlight = 1
			case 5, 7:
				p.RequestID = 1
				d.Returned[1] = ServiceActorTokenReturnedV1{Caller: caller, Amount: big.NewInt(1000), Paying: 2, ReturnDeadline: 1702592000}
				d.Accounting.ReturnedCount = 1
				d.CallerReturnedCounts[key] = 1
			case 6:
				d.Accounting.SurplusPayoutsInFlight = 1
			}
			d.Payouts[2] = p
			decoded, e := DecodeServiceActorTokenData(tokenTestStateCell(t, d))
			if e != nil {
				t.Fatal(e)
			}
			if e = ValidateServiceActorTokenLiveState(decoded); e != nil {
				t.Fatal(e)
			}
			if decoded.Payouts[2].Kind != kind || decoded.Accounting.Ledger.InFlight.String() != "1000" {
				t.Fatal("paying state not reproduced")
			}
		})
	}
	t.Run("returned_unpaid", func(t *testing.T) {
		d := tokenTestEmptyState(t)
		caller, key := tokenTestCaller(t, d)
		d.NextPayoutID = 2
		d.Returned[1] = ServiceActorTokenReturnedV1{Caller: caller, Amount: big.NewInt(1000), ReturnDeadline: 1702592000}
		d.Accounting.ReturnedCount = 1
		d.CallerReturnedCounts[key] = 1
		d.Accounting.Ledger.ReturnedLiability = big.NewInt(1000)
		decoded, e := DecodeServiceActorTokenData(tokenTestStateCell(t, d))
		if e != nil {
			t.Fatal(e)
		}
		if e = ValidateServiceActorTokenLiveState(decoded); e != nil {
			t.Fatal(e)
		}
		if decoded.Returned[1].Paying != 0 {
			t.Fatal("returned state became paying")
		}
	})
}
func TestServiceActorTokenStateInconsistenciesRefused(t *testing.T) {
	for _, kind := range []string{"ledger", "count", "missing_returned", "nil_undo", "byte_counter_wrap", "oversized_map"} {
		t.Run(kind, func(t *testing.T) {
			d := tokenTestEmptyState(t)
			caller, _ := tokenTestCaller(t, d)
			d.NextPayoutID = 300
			p := tokenTestPayout(t, d, 3)
			switch kind {
			case "ledger":
				d.Accounting.Ledger.InFlight = big.NewInt(1)
			case "count":
				d.Accounting.ReturnedCount = 1
			case "missing_returned":
				p.Kind = 5
				p.RequestID = 1
				d.Payouts[1] = p
			case "nil_undo":
				p.Kind = 1
				p.UndoSource = 2
				p.UndoRefund = &ServiceActorRefundV1{Caller: caller}
				d.Payouts[1] = p
			case "byte_counter_wrap":
				for id := uint64(1); id <= 257; id++ {
					d.Payouts[id] = p
				}
				d.Accounting.RevenuePayoutsInFlight = 1
				d.Accounting.Ledger.InFlight = big.NewInt(257000)
				d.Accounting.LockedOutcomeFees = big.NewInt(2570)
			case "oversized_map":
				for id := uint64(0); id <= ServiceActorTokenMaxPayoutEntries; id++ {
					d.Payouts[id] = p
				}
			}
			e := ValidateServiceActorTokenLiveState(d)
			if e == nil {
				t.Fatal("inconsistent token actor state accepted")
			}
			if kind == "oversized_map" && !strings.Contains(e.Error(), "dictionary bound") {
				t.Fatalf("oversized dictionary was not rejected before traversal: %v", e)
			}
		})
	}
}
func TestServiceActorTokenWalletOutcomeInputs(t *testing.T) {
	owner := tokenTestEmptyState(t).Owner
	for _, op := range []uint64{0x52544431, 0x52544631, 0x52545232, 0x52544232} {
		t.Run(fmt.Sprintf("%x", op), func(t *testing.T) {
			b := cell.BeginCell().MustStoreUInt(op, 32).MustStoreUInt(7, 64)
			tokenTestCoins(t, b, big.NewInt(9))
			if op == 0x52544431 {
				b.MustStoreSlice(owner.Bits, owner.BitLen)
			}
			good := b.EndCell()
			input, e := DecodeServiceActorTokenOutcomeInput(good)
			if e != nil || input.QueryID != 7 || input.Amount.String() != "9" {
				t.Fatalf("outcome decode %v %+v", e, input)
			}
			trail := good.MustBeginParse().ToBuilder().MustStoreBoolBit(false).EndCell()
			if _, e = DecodeServiceActorTokenOutcomeInput(trail); e == nil {
				t.Fatal("trailing outcome input accepted")
			}
		})
	}
}

func TestServiceActorTokenAssetRouteHashRefused(t *testing.T) {
	d := tokenTestEmptyState(t)
	r := d.Route
	bad := r.WalletCodeHash
	bad[0] ^= 1
	c := cell.BeginCell().MustStoreSlice(r.Master.Bits, r.Master.BitLen).MustStoreSlice(bad[:], 256).MustStoreRef(r.WalletCode).MustStoreUInt(uint64(r.BridgeConfigParam), 32).EndCell()
	if _, e := decodeTokenAssetRoute(c); e == nil {
		t.Fatal("route with mismatching wallet code hash accepted")
	}
}

func TestServiceActorTokenPendingAttestorStore(t *testing.T) {
	v := tokenVectorJSON(t, "service-actor-token-conformance-vectors.json")["attested"].(map[string]any)
	d, e := DecodeServiceActorTokenData(tokenVectorCell(t, v["deploy_data_boc_base64"].(string)))
	if e != nil {
		t.Fatal(e)
	}
	caller, key := tokenTestCaller(t, d)
	d.NextRequestID = 1
	d.PendingCount = 1
	d.LiveCount = 1
	d.Pending[0] = ServiceActorPendingRequestV1{Caller: caller, Price: big.NewInt(1000), StorageFee: big.NewInt(200000000), CleanupBounty: big.NewInt(100000000), ResponseDeadline: 1700003600, RefundClaimDeadline: 1700007200, HasAttestor: true, AttestorKeyID: d.Policy.AttestorKeyID}
	d.AttestorKeys[d.Policy.AttestorKeyID] = ServiceActorTokenAttestorKeyV1{Refs: 1, Key: d.Policy.AttestorKey}
	d.CallerLiveCounts[key] = 1
	d.Accounting.AttestorKeyCount = 1
	d.Accounting.Ledger.PendingLiability = big.NewInt(1000)
	d.Accounting.LockedStorageFees = big.NewInt(200000000)
	got, e := DecodeServiceActorTokenData(tokenTestStateCell(t, d))
	if e != nil {
		t.Fatal(e)
	}
	if e = ValidateServiceActorTokenLiveState(got); e != nil {
		t.Fatal(e)
	}
	if len(got.Pending[0].AttestorKey) != 0 || len(got.AttestorKeys[d.Policy.AttestorKeyID].Key) != 1312 {
		t.Fatal("pending did not use the shared key store")
	}
	entry := got.AttestorKeys[d.Policy.AttestorKeyID]
	entry.Refs = 2
	got.AttestorKeys[d.Policy.AttestorKeyID] = entry
	if e = ValidateServiceActorTokenLiveState(got); e == nil {
		t.Fatal("wrong attestor reference count accepted")
	}
}

func TestServiceActorTokenFundingTransferShape(t *testing.T) {
	v := tokenVectorJSON(t, "service-actor-token-conformance-vectors.json")
	positive := tokenVectorCell(t, v["funding_transfer_body_boc_base64"].(string))
	good, e := DecodeServiceActorTokenFundingTransfer(positive)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"custom_payload", "zero_amount", "zero_forward", "wrong_destination_workchain", "response_none", "trailing_bit", "trailing_ref"} {
		t.Run(name, func(t *testing.T) {
			amount := new(big.Int).Set(good.Amount)
			forward := new(big.Int).Set(good.ForwardTOSAmount)
			dest, response := good.Destination, good.ResponseDestination
			if name == "zero_amount" {
				amount.SetInt64(0)
			}
			if name == "zero_forward" {
				forward.SetInt64(0)
			}
			if name == "wrong_destination_workchain" {
				dest, e = StandardAddress("-1:" + fmt.Sprintf("%x", dest.Address))
				if e != nil {
					t.Fatal(e)
				}
			}
			b := cell.BeginCell().MustStoreUInt(0x0f8a7ea5, 32).MustStoreUInt(good.QueryID, 64)
			tokenTestCoins(t, b, amount)
			b.MustStoreSlice(dest.Bits, dest.BitLen)
			if name == "response_none" {
				b.MustStoreUInt(0, 2)
			} else {
				b.MustStoreSlice(response.Bits, response.BitLen)
			}
			b.MustStoreBoolBit(name == "custom_payload")
			if name == "custom_payload" {
				b.MustStoreRef(cell.BeginCell().EndCell())
			}
			tokenTestCoins(t, b, forward)
			payload, e := BuildServiceActorTokenCallPayload(good.Payload.RequestHash, good.Payload.ExpectedTermsHash)
			if e != nil {
				t.Fatal(e)
			}
			b.MustStoreBoolBit(true).MustStoreRef(payload)
			if name == "trailing_bit" {
				b.MustStoreBoolBit(false)
			}
			if name == "trailing_ref" {
				b.MustStoreRef(cell.BeginCell().EndCell())
			}
			if _, e = DecodeServiceActorTokenFundingTransfer(b.EndCell()); e == nil {
				t.Fatal("malformed funding transfer accepted")
			}
		})
	}
}

func TestServiceActorTokenEncoderRejectsForgedAddresses(t *testing.T) {
	d := tokenTestEmptyState(t)
	v := tokenVectorJSON(t, "service-actor-token-conformance-vectors.json")
	snapshot, e := DecodeServiceActorTokenRequestSnapshot(tokenVectorCell(t, v["sat1"].([]any)[0].(string)))
	if e != nil {
		t.Fatal(e)
	}
	bad := snapshot
	bad.Caller.BitLen = 10000
	if _, e = BuildServiceActorTokenRequestSnapshot(bad); e == nil {
		t.Fatal("oversized snapshot caller accepted")
	}
	bad = snapshot
	bad.Caller.Bits = nil
	if _, e = BuildServiceActorTokenRequestSnapshot(bad); e == nil {
		t.Fatal("truncated snapshot caller bits accepted")
	}
	route := d.Route
	route.Master.Address = append([]byte(nil), route.Master.Address...)
	route.Master.Address[0] ^= 1
	if _, e = DeriveServiceActorTokenWallet(d.Owner.Text(), route); e == nil {
		t.Fatal("forged route metadata accepted")
	}
	variable := cell.BeginCell().MustStoreUInt(3, 2).MustStoreBoolBit(false).MustStoreUInt(511, 9).MustStoreInt(0, 32).MustStoreSlice(make([]byte, 64), 511).EndCell()
	addr, e := DecodeMsgAddressCell(variable)
	if e != nil {
		t.Fatal(e)
	}
	bad = snapshot
	bad.Caller = addr
	if _, e = BuildServiceActorTokenRequestSnapshot(bad); e == nil {
		t.Fatal("snapshot exceeding cell capacity accepted")
	}
}

func TestServiceActorTokenWalletCodeGraphBound(t *testing.T) {
	var serial uint64
	var tree func(int) *cell.Cell
	tree = func(count int) *cell.Cell {
		serial++
		b := cell.BeginCell().MustStoreUInt(serial, 32)
		if count > 1 {
			left := (count - 1) / 2
			if left > 0 {
				b.MustStoreRef(tree(left))
			}
			right := count - 1 - left
			if right > 0 {
				b.MustStoreRef(tree(right))
			}
		}
		return b.EndCell()
	}
	if err := ValidateServiceActorTokenWalletCodeGraph(tree(8192)); err != nil {
		t.Fatalf("at bound: %v", err)
	}
	if err := ValidateServiceActorTokenWalletCodeGraph(tree(8193)); err == nil {
		t.Fatal("over-bound code accepted")
	}
	if err := ValidateServiceActorTokenWalletCodeGraph(cell.BeginCell().MustStoreRef(libraryCell(t)).EndCell()); err == nil {
		t.Fatal("incomplete exotic code accepted")
	}
	if err := ValidateServiceActorTokenWalletCodeGraph(nil); err == nil {
		t.Fatal("nil code accepted")
	}
}

func TestServiceActorTokenRouteRequiresCompleteCode(t *testing.T) {
	source := tokenVectorJSON(t, "service-actor-token-conformance-vectors.json")
	initial := tokenVectorCell(t, source["deploy_data_boc_base64"].(string))
	data, err := DecodeServiceActorTokenData(initial)
	if err != nil {
		t.Fatal(err)
	}
	route := data.Route
	route.WalletCode = cell.BeginCell().MustStoreRef(libraryCell(t)).EndCell()
	copy(route.WalletCodeHash[:], route.WalletCode.Hash())
	if _, err := BuildServiceActorTokenInitialData(data.Owner.Text(), data.Policy, route); err == nil {
		t.Fatal("initial data accepted incomplete code")
	}
	if _, err := DeriveServiceActorTokenWallet(data.Owner.Text(), route); err == nil {
		t.Fatal("wallet derivation accepted incomplete code")
	}
	replace := func(root *cell.Cell, index int, value *cell.Cell) *cell.Cell {
		s := root.MustBeginParse()
		b := cell.BeginCell().MustStoreSlice(s.MustLoadSlice(s.BitsLeft()), root.BitsSize())
		for pos := 0; s.RefsNum() > 0; pos++ {
			ref := s.MustLoadRef().MustToCell()
			if pos == index {
				ref = value
			}
			b.MustStoreRef(ref)
		}
		return b.EndCell()
	}
	routeCell := cell.BeginCell().MustStoreSlice(route.Master.Bits, route.Master.BitLen).MustStoreSlice(route.WalletCodeHash[:], 256).MustStoreUInt(uint64(route.BridgeConfigParam), 32).MustStoreRef(route.WalletCode).EndCell()
	accounting, err := initial.PeekRef(1)
	if err != nil {
		t.Fatal(err)
	}
	malformed := replace(initial, 1, replace(accounting, 2, routeCell))
	if _, err := DecodeServiceActorTokenData(malformed); err == nil {
		t.Fatal("decoded route accepted incomplete code")
	}
}
