package buyersdk

import (
	"context"
	"testing"
)

// A panic after the record entered sending leaves the call possibly
// submitted. The record must be ambiguous, as a restart would make it, so
// the running process resolves it from finalized history and never sends
// it again.
func TestAPanicDuringTheSendLeavesTheCallAmbiguousAndResolvable(t *testing.T) {
	f := newBuyerFixture(t, defaultLimits())
	ctx := context.Background()
	record, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(1), digest32(2))
	if err != nil {
		t.Fatal(err)
	}
	f.sender.panics = true
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the planted panic did not reach the caller")
			}
		}()
		_, _ = f.buyer.Call(ctx, record.RequestHash)
	}()
	stored, err := f.buyer.Journal().Read(record.RequestHash)
	if err != nil || stored.Phase != PhaseAmbiguous {
		t.Fatalf("after a panic in the send the record is %s: %v", stored.Phase, err)
	}
	f.sender.panics = false
	if _, err := f.buyer.Call(ctx, record.RequestHash); err == nil || len(f.sender.sends) != 1 {
		t.Fatalf("a call that may have been submitted was sent again: %d sends, %v", len(f.sender.sends), err)
	}
	f.land(t, record, 0, true)
	report, err := f.buyer.Resolve(ctx, record.RequestHash)
	if err != nil || report.Phase != PhaseAdmitted {
		t.Fatalf("the ambiguous call did not resolve: %+v %v", report, err)
	}
}
