package provideragent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentsocket"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

const (
	keyA = "key-aaaaaaaaaaaaaaaa"
	keyB = "key-bbbbbbbbbbbbbbbb"
)

func (b *testbed) offered() {
	b.lib.set(func(f *fakeLibrary) {
		f.config.Provider = &servicebridge.ProviderNode{CapabilityID: "cap_" + strings.Repeat("e5", 32), Version: "1.0.0"}
	})
}

func (b *testbed) offerPreview(params agentapi.OfferPreviewParams) agentapi.ActionView {
	b.t.Helper()
	view, err := b.agent.OfferPreview(context.Background(), agentsocket.RoleClient, params)
	return asView(b.t, view, err)
}

func (b *testbed) withdrawPreview(params agentapi.WithdrawPreviewParams) agentapi.ActionView {
	b.t.Helper()
	view, err := b.agent.WithdrawPreview(context.Background(), agentsocket.RoleClient, params)
	return asView(b.t, view, err)
}

func TestAnOfferIsPreviewedConfirmedAndAppliedOnce(t *testing.T) {
	bed := newTestbed(t)
	preview := bed.offerPreview(validOffer(keyA))
	if preview.State != agentapi.StateAwaitingConfirmation || preview.Kind != agentapi.KindOffer ||
		preview.ExpiresUnix != bed.clock.Now().Add(10*time.Minute).Unix() || bed.lib.offerSends != 0 {
		t.Fatalf("preview: %+v, sends %d", preview, bed.lib.offerSends)
	}
	// The same key with the same inputs returns the same action; with other
	// inputs it is refused.
	again := bed.offerPreview(validOffer(keyA))
	if again.ActionID != preview.ActionID {
		t.Fatal("a repeated preview stored a second action")
	}
	other := validOffer(keyA)
	other.PriceNanoTOS = "3000000000"
	if _, err := bed.agent.OfferPreview(context.Background(), agentsocket.RoleClient, other); codeOf(err) != agentapi.CodeConflict {
		t.Fatalf("a key reused with other inputs: %v", err)
	}
	applied := bed.confirm(preview.ActionID)
	if applied.State != agentapi.StateApplied || bed.lib.offerSends != 1 {
		t.Fatalf("applied: %+v, sends %d", applied, bed.lib.offerSends)
	}
	// Published: a further preview is refused.
	if _, err := bed.agent.OfferPreview(context.Background(), agentsocket.RoleClient, validOffer(keyB)); codeOf(err) != agentapi.CodeAlreadyOffered {
		t.Fatalf("a preview after the offer: %v", err)
	}
	// The applied action cannot be confirmed again.
	if _, err := bed.agent.Present(agentapi.ActionParams{ActionID: preview.ActionID}); codeOf(err) != agentapi.CodeConflict {
		t.Fatalf("an applied action was presented: %v", err)
	}
	if bed.lib.offerSends != 1 {
		t.Fatal("an offer was sent twice")
	}
}

func TestAnOfferPreviewOutsideTheBoundsIsRefused(t *testing.T) {
	bed := newTestbed(t)
	for name, mutate := range map[string]func(*agentapi.OfferPreviewParams){
		"price below the bound":        func(p *agentapi.OfferPreviewParams) { p.PriceNanoTOS = "999999" },
		"price above the bound":        func(p *agentapi.OfferPreviewParams) { p.PriceNanoTOS = "10000000001" },
		"zero price":                   func(p *agentapi.OfferPreviewParams) { p.PriceNanoTOS = "0" },
		"price over 2^64-1":            func(p *agentapi.OfferPreviewParams) { p.PriceNanoTOS = "18446744073709551616" },
		"leading zero":                 func(p *agentapi.OfferPreviewParams) { p.PriceNanoTOS = "02000000000" },
		"storage fee above the bound":  func(p *agentapi.OfferPreviewParams) { p.StorageFeeNanoTOS = "1000000001" },
		"storage fee below contract":   func(p *agentapi.OfferPreviewParams) { p.StorageFeeNanoTOS = "100000000" },
		"bounty above the bound":       func(p *agentapi.OfferPreviewParams) { p.CleanupBountyNanoTOS = "500000001" },
		"sla below the bound":          func(p *agentapi.OfferPreviewParams) { p.ResponseSLASeconds = 3599 },
		"window above the bound":       func(p *agentapi.OfferPreviewParams) { p.RefundClaimWindowSeconds = 86401 },
		"retention below the bound":    func(p *agentapi.OfferPreviewParams) { p.RetentionSeconds = 3599 },
		"retention above the bound":    func(p *agentapi.OfferPreviewParams) { p.RetentionSeconds = 604801 },
		"version with a space":         func(p *agentapi.OfferPreviewParams) { p.CapabilityVersion = "1 0" },
		"version too long":             func(p *agentapi.OfferPreviewParams) { p.CapabilityVersion = strings.Repeat("v", 129) },
		"short idempotency key":        func(p *agentapi.OfferPreviewParams) { p.IdempotencyKey = "short" },
		"idempotency key with a slash": func(p *agentapi.OfferPreviewParams) { p.IdempotencyKey = "key/aaaaaaaaaaaaaaaa" },
	} {
		params := validOffer(keyA)
		mutate(&params)
		if _, err := bed.agent.OfferPreview(context.Background(), agentsocket.RoleClient, params); codeOf(err) != agentapi.CodeBadInput {
			t.Errorf("%s: %v", name, err)
		}
	}
	if bed.lib.offerSends != 0 {
		t.Fatal("a refused preview sent")
	}
}

func TestAWithdrawalOfAllMovesExactlyTheConfirmedAmount(t *testing.T) {
	bed := newTestbed(t)
	bed.offered()
	preview := bed.withdrawPreview(agentapi.WithdrawPreviewParams{All: true, IdempotencyKey: keyA})
	var stored withdrawPreview
	if err := json.Unmarshal(preview.Preview, &stored); err != nil || stored.AmountNanoTOS != "3000000000" {
		t.Fatalf("the preview: %s %v", preview.Preview, err)
	}
	// A later credit stays for a later withdrawal: the send moves the
	// confirmed amount.
	bed.lib.set(func(f *fakeLibrary) { f.credited = 4_000_000_000 })
	applied := bed.confirm(preview.ActionID)
	if applied.State != agentapi.StateApplied || bed.lib.withdrawSends != 1 ||
		bed.lib.withdrawals[0].AmountNano != "3000000000" || bed.lib.credited != 1_000_000_000 {
		t.Fatalf("applied %+v; records %+v", applied, bed.lib.withdrawals)
	}
}

func TestAWithdrawalWhoseStateMovedExpiresAndSendsNothing(t *testing.T) {
	for name, move := range map[string]func(*fakeLibrary){
		"credit fell below the amount": func(f *fakeLibrary) { f.credited = 1_000_000_000 },
		"the actor changed":            func(f *fakeLibrary) { f.withdrawActor = testOther },
		"nothing credited":             func(f *fakeLibrary) { f.credited = 0 },
		// The comparison does not rely on the library's own refusal.
		"less credit reported than the amount": func(f *fakeLibrary) { f.reportCredited = "1999999999" },
	} {
		t.Run(name, func(t *testing.T) {
			bed := newTestbed(t)
			bed.offered()
			preview := bed.withdrawPreview(agentapi.WithdrawPreviewParams{AmountNanoTOS: "2000000000", IdempotencyKey: keyA})
			bed.lib.set(move)
			applied := bed.confirm(preview.ActionID)
			if applied.State != agentapi.StateExpired || applied.FailureCode != agentapi.CodeExpired || bed.lib.withdrawSends != 0 {
				t.Fatalf("%+v, sends %d", applied, bed.lib.withdrawSends)
			}
		})
	}
}

func TestAnOfferWhosePreviewChangedExpiresAndSendsNothing(t *testing.T) {
	for name, move := range map[string]func(*fakeLibrary){
		"another owner wallet": func(f *fakeLibrary) { f.offerPreview.OwnerWallet = testOther },
		"another actor":        func(f *fakeLibrary) { f.offerPreview.Actor = testOther },
		"another step planned": func(f *fakeLibrary) { f.offerPlanned = append(f.offerPlanned, "extra") },
	} {
		t.Run(name, func(t *testing.T) {
			bed := newTestbed(t)
			preview := bed.offerPreview(validOffer(keyA))
			bed.lib.set(func(f *fakeLibrary) {
				copied := *f.offerPreview
				f.offerPreview = &copied
				move(f)
			})
			applied := bed.confirm(preview.ActionID)
			if applied.State != agentapi.StateExpired || bed.lib.offerSends != 0 {
				t.Fatalf("%+v, sends %d", applied, bed.lib.offerSends)
			}
		})
	}
}

func TestWithdrawalPreviewRefusals(t *testing.T) {
	bed := newTestbed(t)
	if _, err := bed.agent.WithdrawPreview(context.Background(), agentsocket.RoleClient,
		agentapi.WithdrawPreviewParams{All: true, IdempotencyKey: keyA}); codeOf(err) != agentapi.CodeNotOffered {
		t.Fatalf("before the offer: %v", err)
	}
	bed.offered()
	for name, test := range map[string]struct {
		params agentapi.WithdrawPreviewParams
		setup  func(*fakeLibrary)
		code   string
	}{
		"zero":            {agentapi.WithdrawPreviewParams{AmountNanoTOS: "0", IdempotencyKey: keyA}, nil, agentapi.CodeBadInput},
		"both":            {agentapi.WithdrawPreviewParams{AmountNanoTOS: "1", All: true, IdempotencyKey: keyA}, nil, agentapi.CodeBadInput},
		"neither":         {agentapi.WithdrawPreviewParams{IdempotencyKey: keyA}, nil, agentapi.CodeBadInput},
		"over the credit": {agentapi.WithdrawPreviewParams{AmountNanoTOS: "3000000001", IdempotencyKey: keyA}, nil, agentapi.CodeNothingToDo},
		"nothing credited": {agentapi.WithdrawPreviewParams{All: true, IdempotencyKey: keyA},
			func(f *fakeLibrary) { f.credited = 0 }, agentapi.CodeNothingToDo},
		"an undecided earlier withdrawal": {agentapi.WithdrawPreviewParams{All: true, IdempotencyKey: keyA},
			func(f *fakeLibrary) { f.withdrawErr = servicebridge.ErrWithdrawalPending }, agentapi.CodeAmbiguous},
	} {
		bed.lib.set(func(f *fakeLibrary) { f.credited, f.withdrawErr = 3_000_000_000, nil })
		if test.setup != nil {
			bed.lib.set(test.setup)
		}
		if _, err := bed.agent.WithdrawPreview(context.Background(), agentsocket.RoleClient, test.params); codeOf(err) != test.code {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestConfirmationCodes(t *testing.T) {
	bed := newTestbed(t)
	bed.offered()
	preview := bed.withdrawPreview(agentapi.WithdrawPreviewParams{AmountNanoTOS: "1000000000", IdempotencyKey: keyA})
	presentation := bed.present(preview.ActionID)
	// The code is in the custody presentation only: no client answer about
	// the action carries it or the nonce.
	clientView, err := bed.agent.Actions(agentsocket.RoleClient, agentapi.ActionsParams{ActionID: preview.ActionID})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(clientView)
	if err != nil {
		t.Fatal(err)
	}
	var record actionRecord
	bed.agent.withLock(func() { record, err = bed.agent.loadLocked(preview.ActionID) })
	if err != nil || record.ConfirmationNonce == "" {
		t.Fatalf("no nonce stored: %v", err)
	}
	for _, secret := range []string{presentation.Code, strings.ReplaceAll(presentation.Code, "-", ""), record.ConfirmationNonce} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("a client answer carries %q", secret)
		}
	}
	// A second presentation within the lifetime shows the same code.
	if again := bed.present(preview.ActionID); again.Code != presentation.Code {
		t.Fatal("a second presentation rotated the code")
	}
	// Two wrong codes leave it waiting; the third cancels it.
	for attempt := 1; attempt <= MaxCodeFailures; attempt++ {
		_, err := bed.agent.Decide(context.Background(), agentapi.DecideParams{ActionID: preview.ActionID,
			Decision: agentapi.DecisionConfirm, Code: "0000-0000-0000-0000"})
		want := agentapi.CodeBadInput
		if attempt == MaxCodeFailures {
			want = agentapi.CodeDeclined
		}
		if codeOf(err) != want {
			t.Fatalf("wrong code %d: %v", attempt, err)
		}
	}
	if state := bed.action(preview.ActionID).State; state != agentapi.StateCancelled || bed.lib.withdrawSends != 0 {
		t.Fatalf("after three wrong codes: %s, sends %d", state, bed.lib.withdrawSends)
	}
	// The right code no longer confirms anything.
	if _, err := bed.agent.Decide(context.Background(), agentapi.DecideParams{ActionID: preview.ActionID,
		Decision: agentapi.DecisionConfirm, Code: presentation.Code}); codeOf(err) != agentapi.CodeConflict {
		t.Fatalf("the right code after cancellation: %v", err)
	}
}

func TestDeclinedCancelledAndExpiredActionsNeverApply(t *testing.T) {
	bed := newTestbed(t)
	bed.offered()
	declined := bed.withdrawPreview(agentapi.WithdrawPreviewParams{AmountNanoTOS: "1", IdempotencyKey: keyA})
	presentation := bed.present(declined.ActionID)
	if view, err := bed.agent.Decide(context.Background(), agentapi.DecideParams{ActionID: declined.ActionID,
		Decision: agentapi.DecisionDecline}); err != nil || view.(agentapi.ActionView).State != agentapi.StateDeclined {
		t.Fatalf("decline: %v %v", view, err)
	}
	if _, err := bed.agent.Decide(context.Background(), agentapi.DecideParams{ActionID: declined.ActionID,
		Decision: agentapi.DecisionConfirm, Code: presentation.Code}); codeOf(err) != agentapi.CodeConflict {
		t.Fatalf("confirm after decline: %v", err)
	}

	cancelled := bed.withdrawPreview(agentapi.WithdrawPreviewParams{AmountNanoTOS: "2", IdempotencyKey: keyB})
	presentation = bed.present(cancelled.ActionID)
	if _, err := bed.agent.Cancel(agentsocket.RoleClient, agentapi.ActionParams{ActionID: cancelled.ActionID}); err != nil {
		t.Fatal(err)
	}
	// Cancel is idempotent: a repeat after a lost answer gets the same
	// answer. Any other later state is refused.
	if view, err := bed.agent.Cancel(agentsocket.RoleClient, agentapi.ActionParams{ActionID: cancelled.ActionID}); err != nil ||
		view.(agentapi.ActionView).State != agentapi.StateCancelled {
		t.Fatalf("a second cancel: %v %v", view, err)
	}
	if _, err := bed.agent.Cancel(agentsocket.RoleClient, agentapi.ActionParams{ActionID: declined.ActionID}); codeOf(err) != agentapi.CodeConflict {
		t.Fatalf("cancel of a declined action: %v", err)
	}
	if _, err := bed.agent.Decide(context.Background(), agentapi.DecideParams{ActionID: cancelled.ActionID,
		Decision: agentapi.DecisionConfirm, Code: presentation.Code}); codeOf(err) != agentapi.CodeConflict {
		t.Fatalf("confirm after cancel: %v", err)
	}

	expired := bed.withdrawPreview(agentapi.WithdrawPreviewParams{AmountNanoTOS: "3", IdempotencyKey: "key-cccccccccccccccc"})
	presentation = bed.present(expired.ActionID)
	bed.clock.Advance(agentapi.ActionLifetime)
	if _, err := bed.agent.Decide(context.Background(), agentapi.DecideParams{ActionID: expired.ActionID,
		Decision: agentapi.DecisionConfirm, Code: presentation.Code}); codeOf(err) != agentapi.CodeConflict {
		t.Fatalf("confirm after expiry: %v", err)
	}
	if state := bed.action(expired.ActionID).State; state != agentapi.StateExpired {
		t.Fatalf("expired action: %s", state)
	}
	if bed.lib.withdrawSends != 0 {
		t.Fatal("an action that was not confirmed applied")
	}
}

func TestAtMostFourActionsAwaitConfirmation(t *testing.T) {
	bed := newTestbed(t)
	bed.offered()
	for index := 0; index < agentapi.MaxAwaitingConfirmation; index++ {
		bed.withdrawPreview(agentapi.WithdrawPreviewParams{AmountNanoTOS: "1",
			IdempotencyKey: "key-" + strings.Repeat(string(rune('a'+index)), 16)})
	}
	if _, err := bed.agent.WithdrawPreview(context.Background(), agentsocket.RoleClient,
		agentapi.WithdrawPreviewParams{AmountNanoTOS: "1", IdempotencyKey: "key-zzzzzzzzzzzzzzzz"}); codeOf(err) != agentapi.CodeOverLimit {
		t.Fatalf("a fifth action: %v", err)
	}
}

func TestRateBounds(t *testing.T) {
	bed := newTestbed(t)
	for index := 0; index < perMinute[ratePreflight]; index++ {
		if _, err := bed.agent.Preflight(context.Background(), agentsocket.RoleClient); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := bed.agent.Preflight(context.Background(), agentsocket.RoleClient); codeOf(err) != agentapi.CodeRateLimited {
		t.Fatalf("a seventh preflight in a minute: %v", err)
	}
	// The operator is not bounded.
	if _, err := bed.agent.Preflight(context.Background(), agentsocket.RoleCustody); err != nil {
		t.Fatal(err)
	}
	bed.clock.Advance(time.Minute + time.Second)
	if _, err := bed.agent.Preflight(context.Background(), agentsocket.RoleClient); err != nil {
		t.Fatalf("after a minute: %v", err)
	}
	// A request refused for its input does not count.
	for index := 0; index < 3*perMinute[ratePause]; index++ {
		if _, err := bed.agent.Pause(agentsocket.RoleClient, agentapi.PauseParams{Reason: "bad\nreason"}); codeOf(err) != agentapi.CodeBadInput {
			t.Fatal(err)
		}
	}
	if _, err := bed.agent.Pause(agentsocket.RoleClient, agentapi.PauseParams{}); err != nil {
		t.Fatalf("refused inputs were counted: %v", err)
	}
	// The daily withdrawal previews.
	bed.offered()
	bed.agent.rates = newRates(2)
	for index := 0; index < 2; index++ {
		bed.withdrawPreview(agentapi.WithdrawPreviewParams{AmountNanoTOS: "1",
			IdempotencyKey: "key-" + strings.Repeat(string(rune('k'+index)), 16)})
	}
	bed.clock.Advance(2 * time.Minute)
	if _, err := bed.agent.WithdrawPreview(context.Background(), agentsocket.RoleClient,
		agentapi.WithdrawPreviewParams{AmountNanoTOS: "1", IdempotencyKey: "key-xxxxxxxxxxxxxxxx"}); codeOf(err) != agentapi.CodeRateLimited {
		t.Fatalf("a third withdrawal preview in a day: %v", err)
	}
}

func TestTheNodeIsOpenedWithTheDailyCap(t *testing.T) {
	bed := newTestbed(t)
	limiter, ok := bed.agent.nodeOptions().AdmissionLimiter.(servicebridge.DailyAdmissionCap)
	if !ok || limiter.Max != DefaultMaxAdmissionsPerDay {
		t.Fatalf("the node's limiter: %#v", bed.agent.nodeOptions().AdmissionLimiter)
	}
	if bed.agent.nodeOptions().Report == nil {
		t.Fatal("the node reports nowhere")
	}
}

func TestCanonicalJSON(t *testing.T) {
	encoded, err := canonicalJSON(map[string]any{"b": " <&>", "a": []any{1, "x\n\x01"}, "é": true, "Z": nil})
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"Z\":null,\"a\":[1,\"x\\n\\u0001\"],\"b\":\" <&>\",\"é\":true}"; string(encoded) != want {
		t.Fatalf("got %s", encoded)
	}
	if _, err := canonicalJSON(map[string]any{"n": 1.5}); err == nil {
		t.Fatal("a fraction was accepted")
	}
	if _, err := canonicalJSON(map[string]any{"n": uint64(1) << 60}); err == nil {
		t.Fatal("an unsafe integer was accepted")
	}
}
