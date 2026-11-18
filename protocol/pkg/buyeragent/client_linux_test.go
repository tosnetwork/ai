//go:build linux

package buyeragent

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTheClientCarriesResultsAndRefusals(t *testing.T) {
	f := newFixture(t)
	view := f.requested(t, keyA)
	custody := serve(t, f, RoleCustody)
	client, err := NewClient(custody.Path(), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var pending PurchasesView
	if err := client.Call(ctx, "pending", struct{}{}, &pending); err != nil || len(pending.Purchases) != 1 ||
		pending.Purchases[0].RequestHash != view.RequestHash {
		t.Fatalf("pending: %+v %v", pending, err)
	}
	var presentation Presentation
	if err := client.Call(ctx, "present", RequestHashParams{RequestHash: view.RequestHash}, &presentation); err != nil ||
		presentation.Code == "" || presentation.ResponseSLASeconds != fxResponseSLA {
		t.Fatalf("present: %+v %v", presentation, err)
	}
	var refused PurchaseView
	err = client.Call(ctx, "decide", DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm,
		Code: "0000-0000-0000-0000"}, &refused)
	var known *Error
	if !errors.As(err, &known) || known.Code != CodeBadInput || refused.RequestHash != view.RequestHash {
		t.Fatalf("a refusal and its result: %+v %v", refused, err)
	}
	clientSide := serve(t, f, RoleClient)
	other, err := NewClient(clientSide.Path(), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Call(ctx, "present", RequestHashParams{RequestHash: view.RequestHash}, &presentation); !errors.As(err, &known) ||
		known.Code != CodePermissionDenied {
		t.Fatalf("the client account presented: %v", err)
	}
	gone, err := NewClient(filepath.Join(t.TempDir(), "none.sock"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := gone.Call(ctx, "pending", struct{}{}, nil); !errors.As(err, &known) || known.Code != CodeAgentUnavailable ||
		known.Disposition != DispositionSameAfterBackoff {
		t.Fatalf("a missing socket: %v", err)
	}
	if _, err := NewClient("relative.sock", time.Second); err == nil {
		t.Fatal("a relative socket path was accepted")
	}
	if err := client.Call(ctx, "prepare", PrepareParams{ArchiveBase64: strings.Repeat("A", MaxRequestBytes)}, nil); err == nil {
		t.Fatal("an oversized request was sent")
	}
}
