package buyeragent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/internal/servicefixture"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
)

const (
	keyA = "key-aaaaaaaaaaaaaaaa"
	keyB = "key-bbbbbbbbbbbbbbbb"
)

// Every field of a prepare request is re-checked by the agent, whatever
// the MCP server checked (MCP_BUYER_ADAPTER_V1 section 2.3).
func TestPrepareRevalidatesEveryClientField(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	good := base64.StdEncoding.EncodeToString(sourceTar(t))
	cases := []struct {
		name   string
		params PrepareParams
		code   string
	}{
		{"short quote id", PrepareParams{QuoteID: "ab", IdempotencyKey: keyA, ArchiveBase64: good}, CodeBadInput},
		{"upper-case quote id", PrepareParams{QuoteID: strings.ToUpper(f.quoteID), IdempotencyKey: keyA, ArchiveBase64: good}, CodeBadInput},
		{"short key", PrepareParams{QuoteID: f.quoteID, IdempotencyKey: "short", ArchiveBase64: good}, CodeBadInput},
		{"key charset", PrepareParams{QuoteID: f.quoteID, IdempotencyKey: "key with spaces 123", ArchiveBase64: good}, CodeBadInput},
		{"long key", PrepareParams{QuoteID: f.quoteID, IdempotencyKey: strings.Repeat("k", 65), ArchiveBase64: good}, CodeBadInput},
		{"empty archive", PrepareParams{QuoteID: f.quoteID, IdempotencyKey: keyA}, CodeBadInput},
		{"line-broken base64", PrepareParams{QuoteID: f.quoteID, IdempotencyKey: keyA, ArchiveBase64: good[:8] + "\n" + good[8:]}, CodeBadInput},
		{"oversized base64", PrepareParams{QuoteID: f.quoteID, IdempotencyKey: keyA,
			ArchiveBase64: strings.Repeat("A", maxArchiveBase64+4)}, CodeBadInput},
		{"unknown quote", PrepareParams{QuoteID: strings.Repeat("0", 64), IdempotencyKey: keyA, ArchiveBase64: good}, CodeNotFound},
		{"unsafe member", PrepareParams{QuoteID: f.quoteID, IdempotencyKey: keyA,
			ArchiveBase64: base64.StdEncoding.EncodeToString(rawTar(t, entry{name: "../x.go", body: "x"}))}, CodeBadInput},
	}
	for _, c := range cases {
		_, err := f.agent.Prepare(ctx, c.params)
		if err == nil || codeOf(t, err) != c.code {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	records, err := f.buyer.journal.Records()
	if err != nil || len(records) != 0 {
		t.Fatalf("refused prepares left %d journal records: %v", len(records), err)
	}
}

func TestPrepareIsIdempotentPerKeyAndRefusesAReusedKey(t *testing.T) {
	f := newFixture(t)
	first := f.prepare(t, keyA, sourceTar(t))
	again := f.prepare(t, keyA, sourceTar(t))
	if again.RequestHash != first.RequestHash || first.State != StateAwaitingConfirmation {
		t.Fatalf("a retry made another purchase: %s %s", first.RequestHash, again.RequestHash)
	}
	other := buildTar(t, entry{name: "b.go", body: "y"})
	if _, err := f.agent.Prepare(context.Background(), PrepareParams{QuoteID: f.quoteID, IdempotencyKey: keyA,
		ArchiveBase64: base64.StdEncoding.EncodeToString(other)}); err == nil || codeOf(t, err) != CodeConflict {
		t.Fatalf("a reused key with another source was accepted: %v", err)
	}
	second := f.prepare(t, keyB, sourceTar(t))
	if second.RequestHash == first.RequestHash {
		t.Fatal("a new key reused the request hash")
	}
	records, err := f.buyer.journal.Records()
	if err != nil || len(records) != 2 {
		t.Fatalf("journal records: %d %v", len(records), err)
	}
}

// A crash after the key is stored but before the purchase record leaves a
// retry that derives the same request hash and completes the purchase.
func TestPrepareResumesAfterACrashBeforeThePurchaseRecord(t *testing.T) {
	f := newFixture(t)
	first := f.prepare(t, keyA, sourceTar(t))
	if err := os.Remove(f.agent.store.purchasePath(first.RequestHash)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.agent.store.archivePath(first.RequestHash)); err != nil {
		t.Fatal(err)
	}
	again := f.prepare(t, keyA, sourceTar(t))
	if again.RequestHash != first.RequestHash {
		t.Fatalf("the retry derived %s, not %s", again.RequestHash, first.RequestHash)
	}
	if _, err := os.Stat(f.agent.store.archivePath(first.RequestHash)); err != nil {
		t.Fatalf("the archive copy was not restored: %v", err)
	}
	records, err := f.buyer.journal.Records()
	if err != nil || len(records) != 1 {
		t.Fatalf("journal records: %d %v", len(records), err)
	}
}

func TestPrepareCapsThePurchasesWaitingForADecision(t *testing.T) {
	f := newFixture(t)
	for index := 0; index < testLimits().MaxPrepared; index++ {
		f.prepare(t, keyA[:len(keyA)-1]+string(rune('a'+index)), sourceTar(t))
	}
	_, err := f.agent.Prepare(context.Background(), PrepareParams{QuoteID: f.quoteID, IdempotencyKey: keyB,
		ArchiveBase64: base64.StdEncoding.EncodeToString(sourceTar(t))})
	if err == nil || codeOf(t, err) != CodeOverBudget {
		t.Fatalf("a purchase over the waiting cap was prepared: %v", err)
	}
}

func TestAnUncarriablePurchaseIsWithdrawnAndNeverPaid(t *testing.T) {
	f := newFixture(t)
	f.carriage.set(errors.New("no verified provider key card"))
	_, err := f.agent.Prepare(context.Background(), PrepareParams{QuoteID: f.quoteID, IdempotencyKey: keyA,
		ArchiveBase64: base64.StdEncoding.EncodeToString(sourceTar(t))})
	if err == nil || codeOf(t, err) != CodeNotCarriable {
		t.Fatalf("an uncarriable purchase was kept: %v", err)
	}
	records, err := f.buyer.journal.Records()
	if err != nil || len(records) != 1 || records[0].Phase != buyersdk.PhaseWithdrawn {
		t.Fatalf("the journal holds %+v: %v", records, err)
	}
	if _, err := f.agent.Prepare(context.Background(), PrepareParams{QuoteID: f.quoteID, IdempotencyKey: keyA,
		ArchiveBase64: base64.StdEncoding.EncodeToString(sourceTar(t))}); err == nil || codeOf(t, err) != CodeNotCarriable {
		t.Fatalf("a retry of an uncarriable purchase was accepted: %v", err)
	}
}

// Only the confirmer's fetch draws a nonce; asking for payment does not,
// and a valid presentation keeps its code until it expires.
func TestOnlyTheConfirmerFetchDrawsTheNonce(t *testing.T) {
	f := newFixture(t)
	view := f.requested(t, keyA)
	purchase, err := f.agent.store.readPurchase(view.RequestHash)
	if err != nil || purchase.ConfirmationNonce != "" || purchase.RequestedUnix == 0 {
		t.Fatalf("asking for payment drew a nonce: %+v %v", purchase, err)
	}
	if _, err := f.agent.RequestPayment(context.Background(), RequestPaymentParams{RequestHash: view.RequestHash}); err != nil {
		t.Fatal(err)
	}
	if purchase, _ = f.agent.store.readPurchase(view.RequestHash); purchase.ConfirmationNonce != "" {
		t.Fatal("asking again drew a nonce")
	}
	first, err := f.agent.Present(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.agent.Present(view.RequestHash)
	if err != nil || again.Code != first.Code {
		t.Fatalf("a second fetch within the lifetime changed the code: %v", err)
	}
	f.clock.advance(ConfirmationLifetime)
	later, err := f.agent.Present(view.RequestHash)
	if err != nil || later.Code == first.Code {
		t.Fatalf("an expired presentation kept its code: %v", err)
	}
	unrequested := f.prepare(t, keyB, sourceTar(t))
	if _, err := f.agent.Present(unrequested.RequestHash); err == nil || codeOf(t, err) != CodeConflict {
		t.Fatalf("a purchase nobody asked to pay was presented: %v", err)
	}
}

// No view a client can obtain carries the code or its nonce.
func TestClientViewsNeverCarryTheCode(t *testing.T) {
	f := newFixture(t)
	view := f.requested(t, keyA)
	presentation, err := f.agent.Present(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	purchase, err := f.agent.store.readPurchase(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	status, _ := f.agent.Status(view.RequestHash)
	list, _ := f.agent.Purchases(PurchasesParams{PageSize: 10})
	waited, _ := f.agent.RequestPayment(context.Background(), RequestPaymentParams{RequestHash: view.RequestHash})
	for _, value := range []any{status, list, waited, view} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{presentation.Code, strings.ReplaceAll(presentation.Code, "-", ""), purchase.ConfirmationNonce} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("a client view carries %q: %s", secret, raw)
			}
		}
	}
}

func TestDecideRecomputesTheCodeAndPaysAtMostOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	view := f.requested(t, keyA)
	presentation, err := f.agent.Present(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	wrong := []byte(strings.ReplaceAll(presentation.Code, "-", ""))
	if wrong[0] == '0' {
		wrong[0] = '1'
	} else {
		wrong[0] = '0'
	}
	if _, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm,
		Code: string(wrong)}); err == nil || codeOf(t, err) != CodeBadInput {
		t.Fatalf("a wrong code was accepted: %v", err)
	}
	if len(f.buyer.sent()) != 0 {
		t.Fatal("a wrong code sent the call")
	}
	typed := strings.ToUpper(presentation.Code)
	paid, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm, Code: typed})
	if err != nil || paid.State != StateSubmitted {
		t.Fatalf("the right code did not pay: %+v %v", paid, err)
	}
	if _, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm,
		Code: presentation.Code}); err == nil || codeOf(t, err) != CodeConflict {
		t.Fatalf("a spent code confirmed again: %v", err)
	}
	if sends := f.buyer.sent(); len(sends) != 1 || sends[0] != view.RequestHash {
		t.Fatalf("sends: %v", sends)
	}
}

// A matching code is spent before the send, so a call that custody never
// started needs a new presentation and a new code.
func TestASpentCodeCannotConfirmARetry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	view := f.requested(t, keyA)
	presentation, err := f.agent.Present(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	f.buyer.callNext, f.buyer.callErr = buyersdk.PhasePrepared, buyersdk.ErrCallNotStarted
	if _, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm,
		Code: presentation.Code}); err == nil || codeOf(t, err) != CodeDependencyUnavailable {
		t.Fatalf("a send custody never started: %v", err)
	}
	f.buyer.callNext, f.buyer.callErr = "", nil
	if _, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm,
		Code: presentation.Code}); err == nil || codeOf(t, err) != CodeConflict {
		t.Fatalf("a spent code confirmed a retry: %v", err)
	}
	if sends := f.buyer.sent(); len(sends) != 1 {
		t.Fatalf("sends: %v", sends)
	}
	fresh, err := f.agent.Present(view.RequestHash)
	if err != nil || fresh.Code == presentation.Code {
		t.Fatalf("a new presentation reused the spent code: %v", err)
	}
	if _, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm,
		Code: fresh.Code}); err != nil {
		t.Fatalf("a fresh code did not pay: %v", err)
	}
}

// The code a human types must come from this presentation's nonce: a code
// computed from the public fields alone, or from an earlier nonce, fails.
func TestACodeFromAnotherNonceConfirmsNothing(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	view := f.requested(t, keyA)
	record, err := f.buyer.journal.Read(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	purchase, err := f.agent.store.readPurchase(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	guessed := ConfirmationCode([ConfirmationNonceBytes]byte{}, fieldsOf(record, purchase))
	first, err := f.agent.Present(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.advance(ConfirmationLifetime)
	if _, err := f.agent.Present(view.RequestHash); err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{guessed, first.Code} {
		if _, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm,
			Code: code}); err == nil {
			t.Fatalf("code %s from another nonce confirmed", code)
		}
	}
	if len(f.buyer.sent()) != 0 {
		t.Fatal("a stale code sent the call")
	}
}

func TestThreeWrongCodesWithdrawThePurchase(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	view := f.requested(t, keyA)
	presentation, err := f.agent.Present(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	// The spec fixes the lockout at three wrong codes (section 5.3).
	if MaxCodeFailures != 3 {
		t.Fatalf("the lockout is %d wrong codes, not 3", MaxCodeFailures)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		_, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm,
			Code: "0000-0000-0000-0000"})
		want := CodeBadInput
		if attempt == 3 {
			want = CodeDeclined
		}
		if err == nil || codeOf(t, err) != want {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	if _, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm,
		Code: presentation.Code}); err == nil {
		t.Fatal("the right code confirmed after the lockout")
	}
	status, err := f.agent.Status(view.RequestHash)
	if err != nil || status.State != StateWithdrawn || status.Phase != string(buyersdk.PhaseWithdrawn) {
		t.Fatalf("status after lockout: %+v %v", status, err)
	}
	if len(f.buyer.sent()) != 0 {
		t.Fatal("a locked-out purchase was sent")
	}
}

func TestAnExpiredCodeAndAMissingPresentationConfirmNothing(t *testing.T) {
	// The spec fixes a code's lifetime at 10 minutes and its nonce at 128
	// bits (section 5.3).
	if ConfirmationLifetime != 10*time.Minute || ConfirmationNonceBytes != 16 {
		t.Fatalf("lifetime %v and nonce %d bytes differ from the spec", ConfirmationLifetime, ConfirmationNonceBytes)
	}
	f := newFixture(t)
	ctx := context.Background()
	view := f.requested(t, keyA)
	if _, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm,
		Code: "0000-0000-0000-0000"}); err == nil || codeOf(t, err) != CodeConflict {
		t.Fatalf("a decision without a presentation was taken: %v", err)
	}
	presentation, err := f.agent.Present(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.advance(ConfirmationLifetime)
	if _, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm,
		Code: presentation.Code}); err == nil || codeOf(t, err) != CodeConflict {
		t.Fatalf("an expired code confirmed: %v", err)
	}
	if len(f.buyer.sent()) != 0 {
		t.Fatal("an expired code sent the call")
	}
}

func TestDeclineWithdrawsAndIsReportedAsDeclined(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	view := f.requested(t, keyA)
	if _, err := f.agent.Present(view.RequestHash); err != nil {
		t.Fatal(err)
	}
	if _, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionDecline,
		Code: "0000-0000-0000-0000"}); err == nil || codeOf(t, err) != CodeBadInput {
		t.Fatalf("a decline with a code was accepted: %v", err)
	}
	declined, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionDecline})
	if err != nil || declined.State != StateDeclined {
		t.Fatalf("decline: %+v %v", declined, err)
	}
	waited, err := f.agent.RequestPayment(ctx, RequestPaymentParams{RequestHash: view.RequestHash})
	if err != nil || waited.State != StateDeclined {
		t.Fatalf("a client sees %+v %v", waited, err)
	}
	if _, err := f.agent.Withdraw(view.RequestHash); err == nil || codeOf(t, err) != CodeConflict {
		t.Fatalf("a declined purchase was withdrawn again: %v", err)
	}
}

func TestCarriageIsRecheckedBeforeTheSend(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	view := f.requested(t, keyA)
	presentation, err := f.agent.Present(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	f.carriage.set(errors.New("the provider card expired"))
	if _, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm,
		Code: presentation.Code}); err == nil || codeOf(t, err) != CodeNotCarriable {
		t.Fatalf("an uncarriable purchase was confirmed: %v", err)
	}
	if len(f.buyer.sent()) != 0 {
		t.Fatal("an uncarriable purchase was sent")
	}
}

func TestATamperedArchiveCopyIsNeverSent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	view := f.requested(t, keyA)
	presentation, err := f.agent.Present(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	other := buildTar(t, entry{name: "evil.go", body: "x"})
	if err := writePrivate(f.agent.store.archivePath(view.RequestHash), other, false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm,
		Code: presentation.Code}); err == nil {
		t.Fatal("a purchase whose archive copy changed was confirmed")
	}
	if len(f.buyer.sent()) != 0 {
		t.Fatal("a tampered archive was sent")
	}
}

func TestAnAmbiguousSendIsReportedForResolution(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	view := f.requested(t, keyA)
	presentation, err := f.agent.Present(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	f.buyer.callNext, f.buyer.callErr = buyersdk.PhaseAmbiguous, errors.New("custody timed out")
	result, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm,
		Code: presentation.Code})
	if err == nil || codeOf(t, err) != CodeAmbiguous || result.State != StateAmbiguous {
		t.Fatalf("an ambiguous send: %+v %v", result, err)
	}
	var known *Error
	errors.As(err, &known)
	if known.Disposition != DispositionResolveBeforeRetry {
		t.Fatalf("disposition %s", known.Disposition)
	}
}

func TestRequestPaymentWaitsForTheHumansDecision(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	view := f.requested(t, keyA)
	done := make(chan PurchaseView, 1)
	go func() {
		waited, err := f.agent.RequestPayment(ctx, RequestPaymentParams{RequestHash: view.RequestHash, WaitSeconds: 30})
		if err != nil {
			t.Error(err)
		}
		done <- waited
	}()
	time.Sleep(50 * time.Millisecond)
	presentation, err := f.agent.Present(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.agent.Decide(ctx, DecideParams{RequestHash: view.RequestHash, Decision: DecisionConfirm,
		Code: presentation.Code}); err != nil {
		t.Fatal(err)
	}
	select {
	case waited := <-done:
		if waited.State != StateSubmitted {
			t.Fatalf("the waiting client saw %s", waited.State)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the waiting client never saw the decision")
	}
	if _, err := f.agent.RequestPayment(ctx, RequestPaymentParams{RequestHash: view.RequestHash, WaitSeconds: 301}); err == nil {
		t.Fatal("a wait above 300 seconds was accepted")
	}
}

func TestConfirmationCodeBindsTheNonceAndEveryField(t *testing.T) {
	fields := ConfirmationFields{NetworkID: "tos-test", BuyerWallet: fxBuyer, Actor: "0:" + strings.Repeat("77", 32),
		RequestHash: strings.Repeat("ab", 32), TermsHash: strings.Repeat("cd", 32),
		QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("ef", 32), PaymentNanoTOS: "700000000",
		SourceDigest: "sha256:" + strings.Repeat("01", 32)}
	nonce := [ConfirmationNonceBytes]byte{1, 2, 3}
	var preimage []byte
	preimage = append(preimage, "tos.service.mcp-buyer.confirmation.v2"...)
	preimage = append(preimage, 0)
	preimage = append(preimage, nonce[:]...)
	preimage = append(preimage, strings.Join([]string{fields.NetworkID, fields.BuyerWallet, fields.Actor, fields.RequestHash,
		fields.TermsHash, fields.QuoteCommitment, fields.PaymentNanoTOS, fields.SourceDigest}, "\x00")...)
	sum := sha256.Sum256(preimage)
	digits := hex.EncodeToString(sum[:8])
	want := digits[0:4] + "-" + digits[4:8] + "-" + digits[8:12] + "-" + digits[12:16]
	if got := ConfirmationCode(nonce, fields); got != want {
		t.Fatalf("code %s, want %s", got, want)
	}
	other := nonce
	other[0] = 9
	if ConfirmationCode(other, fields) == want {
		t.Fatal("the code does not bind the nonce")
	}
	for index := 0; index < 8; index++ {
		changed := fields
		target := []*string{&changed.NetworkID, &changed.BuyerWallet, &changed.Actor, &changed.RequestHash,
			&changed.TermsHash, &changed.QuoteCommitment, &changed.PaymentNanoTOS, &changed.SourceDigest}[index]
		*target += "x"
		if ConfirmationCode(nonce, changed) == want {
			t.Fatalf("the code does not bind field %d", index)
		}
	}
	if !codesMatch(want, strings.ToUpper(strings.ReplaceAll(want, "-", ""))) || codesMatch(want, want+"0") ||
		codesMatch(want, "") || codesMatch(want, strings.Repeat("z", 16)) {
		t.Fatal("typed-code normalization is wrong")
	}
	if PurchaseReference(fields.RequestHash) != "abab-abab-abab-abab" {
		t.Fatalf("reference %s", PurchaseReference(fields.RequestHash))
	}
}

func TestOpenRefusesUnsafeStateAndASecondAgent(t *testing.T) {
	f := newFixture(t)
	if _, err := Open(Config{StateDir: f.state, BuyerAgentID: fxBuyerAgent, Network: servicefixture.Network(),
		Buyer: f.buyer, Carriage: f.carriage}); err == nil {
		t.Fatal("a second agent opened the same state directory")
	}
	open := t.TempDir()
	if err := os.Chmod(open, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{StateDir: open, BuyerAgentID: fxBuyerAgent, Network: servicefixture.Network(),
		Buyer: f.buyer, Carriage: f.carriage}); err == nil {
		t.Fatal("a state directory open to the group was accepted")
	}
	limits := testLimits()
	limits.MaxPrepared = 0
	unbounded := &fakeBuyer{t: t, network: f.buyer.network, journal: f.buyer.journal, limits: limits, now: f.clock.Now}
	if _, err := Open(Config{StateDir: privateDir(t), BuyerAgentID: fxBuyerAgent, Network: servicefixture.Network(),
		Buyer: unbounded, Carriage: f.carriage}); err == nil {
		t.Fatal("limits without a prepared cap were accepted")
	}
	if _, err := Open(Config{StateDir: filepath.Join(privateDir(t), "..", "x"), BuyerAgentID: fxBuyerAgent,
		Network: servicefixture.Network(), Buyer: f.buyer, Carriage: f.carriage}); err == nil {
		t.Fatal("an unclean state path was accepted")
	}
}
