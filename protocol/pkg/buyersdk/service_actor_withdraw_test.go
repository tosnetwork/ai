package buyersdk

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"
)

// A withdrawn call is never sent, frees its reservation, and only a call
// that is still prepared can be withdrawn.
func TestWithdrawnCallsAreNeverSentAndHoldNoReservation(t *testing.T) {
	ctx := context.Background()
	limits := defaultLimits()
	limits.MaxCalls = 1
	f := newBuyerFixture(t, limits)
	first, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(1), digest32(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(3), digest32(4)); err == nil {
		t.Fatal("a second call within the call limit was prepared")
	}
	withdrawn, err := f.buyer.Withdraw(first.RequestHash)
	if err != nil || withdrawn.Phase != PhaseWithdrawn {
		t.Fatalf("withdraw: %+v %v", withdrawn, err)
	}
	if _, err := f.buyer.Call(ctx, first.RequestHash); err == nil {
		t.Fatal("a withdrawn call was sent")
	}
	if len(f.sender.sends) != 0 {
		t.Fatalf("a withdrawn call reached custody %d times", len(f.sender.sends))
	}
	if _, err := f.buyer.Withdraw(first.RequestHash); err == nil {
		t.Fatal("a withdrawn call was withdrawn again")
	}
	total, calls, err := f.buyer.Journal().Reserved(limits, saNow)
	if err != nil || calls != 0 || total.Sign() != 0 {
		t.Fatalf("a withdrawn call still reserves %v in %d calls: %v", total, calls, err)
	}
	second, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(3), digest32(4))
	if err != nil {
		t.Fatalf("a withdrawn call kept its reservation: %v", err)
	}
	if _, err := f.buyer.Call(ctx, second.RequestHash); err != nil {
		t.Fatal(err)
	}
	if _, err := f.buyer.Withdraw(second.RequestHash); err == nil {
		t.Fatal("a call handed to custody was withdrawn")
	}
	report, err := f.buyer.Resolve(ctx, first.RequestHash)
	if err != nil || report.Phase != PhaseWithdrawn {
		t.Fatalf("resolve of a withdrawn call: %+v %v", report, err)
	}
}

// MaxPrepared bounds the unexpired prepared calls, not the sent ones.
func TestPreparedCallsAreCappedSeparately(t *testing.T) {
	ctx := context.Background()
	limits := defaultLimits()
	limits.MaxPrepared = 2
	f := newBuyerFixture(t, limits)
	first, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(1), digest32(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(3), digest32(4)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(5), digest32(6)); !errors.Is(err, ErrTooManyPrepared) {
		t.Fatalf("a third prepared call was admitted: %v", err)
	}
	if _, err := f.buyer.Call(ctx, first.RequestHash); err != nil {
		t.Fatal(err)
	}
	if _, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(5), digest32(6)); err != nil {
		t.Fatalf("a sent call still counted as waiting: %v", err)
	}
	total, calls, err := f.buyer.Journal().Reserved(limits, saNow)
	if err != nil || calls != 3 || total.Cmp(big.NewInt(3*700_000_000)) != 0 {
		t.Fatalf("reserved %v in %d calls: %v", total, calls, err)
	}
	records, err := f.buyer.Journal().Records()
	if err != nil || len(records) != 3 {
		t.Fatalf("records: %d %v", len(records), err)
	}
}

func TestLimitsRefuseAPreparedCapAboveTheCallCap(t *testing.T) {
	limits := defaultLimits()
	limits.MaxPrepared = limits.MaxCalls + 1
	if limits.Valid() {
		t.Fatal("a prepared cap above the call cap was accepted")
	}
	limits.MaxPrepared = -1
	if limits.Valid() {
		t.Fatal("a negative prepared cap was accepted")
	}
	limits.MaxPrepared = 0
	limits.Window = 32 * 24 * time.Hour
	if limits.Valid() {
		t.Fatal("an over-long window was accepted")
	}
}
