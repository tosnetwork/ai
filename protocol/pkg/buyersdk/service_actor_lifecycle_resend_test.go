package buyersdk

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// deadlineLifecycle records the deadline custody was given.
type deadlineLifecycle struct {
	fakeLifecycle
	mu        sync.Mutex
	deadlines []time.Time
}

func (d *deadlineLifecycle) SendLifecycle(ctx context.Context, intent LifecycleIntent) (LifecycleSubmission, error) {
	deadline, _ := ctx.Deadline()
	d.mu.Lock()
	d.deadlines = append(d.deadlines, deadline)
	d.mu.Unlock()
	return d.fakeLifecycle.SendLifecycle(ctx, intent)
}

// The message custody signs in the announced fixtures: seqno 5, valid for
// two minutes from saNow.
var (
	announcedHash       = strings.Repeat("c5", 32)
	announcedValidUntil = saNow.Add(2 * time.Minute)
)

// ambiguousExpire admits a call and leaves one ambiguous expire send at
// wallet seqno 5 whose report custody lost.
func ambiguousExpire(t *testing.T) (*buyerFixture, *deadlineLifecycle, CallRecord, LifecycleSend) {
	t.Helper()
	return ambiguousExpireWith(t, LifecycleSubmission{})
}

// announcedExpire is ambiguousExpire with custody's report of the signed
// message.
func announcedExpire(t *testing.T) (*buyerFixture, *deadlineLifecycle, CallRecord, LifecycleSend) {
	t.Helper()
	return ambiguousExpireWith(t, LifecycleSubmission{Announced: true, Seqno: 5,
		ValidUntilUnix: announcedValidUntil.Unix(), MessageHash: announcedHash})
}

func ambiguousExpireWith(t *testing.T, submission LifecycleSubmission) (*buyerFixture, *deadlineLifecycle, CallRecord, LifecycleSend) {
	t.Helper()
	f := newBuyerFixture(t, defaultLimits())
	lifecycle := &deadlineLifecycle{}
	f.buyer.config.Lifecycle = lifecycle
	record := admitted(t, f)
	f.chain.wallet.seqno = 5
	lifecycle.err, lifecycle.submission = errors.New("tosctl exited after submitting"), submission
	sent, err := f.buyer.SendLifecycle(context.Background(), record.RequestHash, LifecycleExpire)
	if err == nil || len(sent.Lifecycle) != 1 || sent.Lifecycle[0].Phase != PhaseAmbiguous {
		t.Fatalf("fixture send: %+v %v", sent.Lifecycle, err)
	}
	lifecycle.err, lifecycle.submission = nil, LifecycleSubmission{}
	stored, err := f.buyer.Journal().Read(record.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	return f, lifecycle, stored, stored.Lifecycle[0]
}

func (f *buyerFixture) at(at time.Time, seqno uint32) {
	f.chain.mu.Lock()
	defer f.chain.mu.Unlock()
	f.chain.wallet.chainTime, f.chain.wallet.seqno = at, seqno
}

// walletTx appends a finalized transaction to the buyer wallet's history.
func (f *buyerFixture) walletTx(transaction toschain.WalletTransaction) {
	f.chain.mu.Lock()
	defer f.chain.mu.Unlock()
	history := f.chain.wallet.history()
	transaction.LT = history[0].LT + 1
	transaction.Hash = strings.Repeat("b", 63) + string(rune('0'+len(history)))
	f.chain.wallet.txs = append([]toschain.WalletTransaction{transaction}, history...)
}

// lifecycleTx appends a finalized transaction from sender to the actor.
func (f *buyerFixture) lifecycleTx(transaction toschain.ActorTransaction) {
	f.chain.mu.Lock()
	defer f.chain.mu.Unlock()
	transaction.LT = f.chain.history[0].LT + 1
	transaction.Hash = strings.Repeat("e", 63) + string(rune('0'+len(f.chain.history)))
	f.chain.history = append([]toschain.ActorTransaction{transaction}, f.chain.history...)
}

func expectUnsettled(t *testing.T, f *buyerFixture, lifecycle *deadlineLifecycle, record CallRecord, why string) {
	t.Helper()
	before := len(lifecycle.intents)
	updated, err := f.buyer.SendLifecycle(context.Background(), record.RequestHash, LifecycleExpire)
	if !errors.Is(err, ErrLifecycleUnsettled) {
		t.Fatalf("%s: the operation was not held back: %v", why, err)
	}
	stored, readErr := f.buyer.Journal().Read(record.RequestHash)
	if readErr != nil || len(stored.Lifecycle) != len(record.Lifecycle) || len(lifecycle.intents) != before ||
		len(updated.Lifecycle) != len(record.Lifecycle) {
		t.Fatalf("%s: a held-back send reached the journal or custody: %+v", why, stored.Lifecycle)
	}
}

func expectSent(t *testing.T, f *buyerFixture, lifecycle *deadlineLifecycle, record CallRecord, why string) {
	t.Helper()
	before := len(lifecycle.intents)
	updated, err := f.buyer.SendLifecycle(context.Background(), record.RequestHash, LifecycleExpire)
	if err != nil || len(lifecycle.intents) != before+1 || len(updated.Lifecycle) != len(record.Lifecycle)+1 {
		t.Fatalf("%s: the settled operation was not sent again: %+v %v", why, updated.Lifecycle, err)
	}
}

func TestALifecycleSendRecordsTheWalletStateAndCustodysReport(t *testing.T) {
	_, lifecycle, _, sent := ambiguousExpire(t)
	if sent.WalletSeqno != 5 || sent.SentUnix != saNow.Unix() || sent.Announced ||
		sent.ValidUntilBoundUnix != 0 ||
		sent.WalletAnchorLT != saWalletAnchor.LT || sent.WalletAnchorHash != saWalletAnchor.Hash {
		t.Fatalf("journaled %+v", sent)
	}

	// Custody execution remains bounded even when no expiry was reported.
	if len(lifecycle.deadlines) != 1 || !lifecycle.deadlines[0].Equal(saNow.Add(LifecycleSendTimeout)) {
		t.Fatalf("custody deadline %v", lifecycle.deadlines)
	}
	_, _, _, announced := announcedExpire(t)
	if !announced.Announced || announced.SignedSeqno != 5 || announced.ValidUntilUnix != announcedValidUntil.Unix() ||
		announced.MessageHash != announcedHash || announced.ValidUntilBoundUnix != announcedValidUntil.Unix() {
		t.Fatalf("custody's report was not journaled: %+v", announced)
	}
}

// Without a signed expiry report, neither an unchanged seqno nor an old
// inferred bound proves the message can no longer execute.
func TestAnUnannouncedSendCannotSettleByAnAssumedLifetime(t *testing.T) {
	f, lifecycle, record, sent := ambiguousExpire(t)
	bound := saNow.Add(10 * time.Minute)
	// A transaction of another sender with the send's query_id is not the
	// send.
	f.lifecycleTx(toschain.ActorTransaction{Kind: toschain.ActorTxExpire, Sender: saOwner, QueryID: sent.QueryID})
	f.at(saNow.Add(LifecycleSendTimeout), 5)
	expectUnsettled(t, f, lifecycle, record, "before the validity bound")
	f.at(bound, 5)
	expectUnsettled(t, f, lifecycle, record, "at the validity bound")
	f.at(bound.Add(24*time.Hour), 6)
	expectUnsettled(t, f, lifecycle, record, "a day past the bound with the seqno moved")
	f.at(bound.Add(time.Second), 5)
	expectUnsettled(t, f, lifecycle, record, "no reported expiry even with unchanged seqno")
	record, err := f.buyer.Journal().Transition(record.RequestHash, []CallPhase{PhaseAdmitted}, func(r *CallRecord) error {
		r.Lifecycle[0].ValidUntilBoundUnix = bound.Unix()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	expectUnsettled(t, f, lifecycle, record, "an old inferred bound is not a signed expiry")
}

// Rule 2 for a reported send uses its signed expiry and seqno.
func TestAReportedSendExpiresAtItsSignedValidUntil(t *testing.T) {
	f, lifecycle, record, sent := announcedExpire(t)
	if announcedValidUntil.Unix() != sent.ValidUntilBoundUnix {
		t.Fatal("the recorded bound must equal the signed expiry")
	}
	record, err := f.buyer.Journal().Transition(record.RequestHash, []CallPhase{PhaseAdmitted}, func(r *CallRecord) error {
		r.Lifecycle[0].ValidUntilBoundUnix = announcedValidUntil.Add(time.Hour).Unix()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	f.at(announcedValidUntil, 5)
	expectUnsettled(t, f, lifecycle, record, "at the signed valid_until")
	f.at(announcedValidUntil.Add(time.Second), 5)
	expectSent(t, f, lifecycle, record, "past the signed valid_until, before the fallback bound")
}

// Rule 3: a different message consumed the signed seqno, so the send can
// never execute, and it is settled at once, before its valid_until.
func TestASendWhoseSeqnoAnotherMessageConsumedIsSettledAtOnce(t *testing.T) {
	f, lifecycle, record, _ := announcedExpire(t)
	f.walletTx(toschain.WalletTransaction{ExternalMessageHash: strings.Repeat("0d", 32),
		Out: []toschain.WalletOutMessage{{Destination: saActor, QueryID: 99, Known: true}}})
	f.at(saNow, 5)
	expectUnsettled(t, f, lifecycle, record, "the seqno not yet consumed")
	f.at(saNow, 6)
	expectSent(t, f, lifecycle, record, "another message consumed the signed seqno")
}

// Rule 3: the send's exact message executed in the wallet. If it sent this
// send's message to the actor, rule 1 settles it once the actor's
// transaction is finalized; if it sent nothing for this send, it is settled.
func TestASendWhoseMessageTheWalletExecutedWaitsForTheActor(t *testing.T) {
	f, lifecycle, record, sent := announcedExpire(t)
	f.walletTx(toschain.WalletTransaction{ExternalMessageHash: announcedHash,
		Out: []toschain.WalletOutMessage{{Destination: saActor, QueryID: sent.QueryID, Known: true}}})
	f.at(saNow.Add(time.Hour), 6)
	expectUnsettled(t, f, lifecycle, record, "the message is on its way to the actor")
	f.lifecycleTx(toschain.ActorTransaction{Kind: toschain.ActorTxExpire, Sender: saBuyer, QueryID: sent.QueryID})
	expectSent(t, f, lifecycle, record, "the actor executed it")

	for name, out := range map[string][]toschain.WalletOutMessage{
		"no out-message":       nil,
		"another query_id":     {{Destination: saActor, QueryID: sent.QueryID + 1, Known: true}},
		"another destination":  {{Destination: saOwner, QueryID: sent.QueryID, Known: true}},
		"a body with no query": {{Destination: saActor}},
	} {
		g, glifecycle, grecord, _ := announcedExpire(t)
		g.walletTx(toschain.WalletTransaction{ExternalMessageHash: announcedHash, Out: out})
		g.at(saNow, 6)
		expectSent(t, g, glifecycle, grecord, name)
	}
}

// Rule 1: a send that history shows executed is settled at once, whatever
// its outcome, so a claim_refund refused with 1921 is retried.
func TestAnExecutedLifecycleSendIsSettled(t *testing.T) {
	for name, transaction := range map[string]func(query uint64) toschain.ActorTransaction{
		"executed": func(query uint64) toschain.ActorTransaction {
			return toschain.ActorTransaction{Kind: toschain.ActorTxExpire, Sender: saBuyer, QueryID: query}
		},
		"refused with 1921": func(query uint64) toschain.ActorTransaction {
			body := cell.BeginCell().MustStoreUInt(nativecore.ServiceActorExpireOpcode, 32).MustStoreUInt(query, 64).EndCell()
			return toschain.ActorTransaction{Kind: toschain.ActorTxFailed, Sender: saBuyer, ExitCode: 1921,
				BodyBOC: base64.StdEncoding.EncodeToString(body.ToBOC())}
		},
	} {
		f, lifecycle, record, sent := ambiguousExpire(t)
		f.lifecycleTx(transaction(sent.QueryID))
		f.at(saNow, 6)
		expectSent(t, f, lifecycle, record, name)
	}
}

func TestOnlyEarlierSendsOfTheSameOperationHoldASendBack(t *testing.T) {
	f, _, record, _ := ambiguousExpire(t)
	// Another operation is not held back by the ambiguous expire.
	if _, err := f.buyer.SendLifecycle(context.Background(), record.RequestHash, LifecycleSweep); err != nil {
		t.Fatalf("another operation was held back: %v", err)
	}
	// A send custody never started holds nothing back.
	g := newBuyerFixture(t, defaultLimits())
	glifecycle := &deadlineLifecycle{}
	g.buyer.config.Lifecycle = glifecycle
	grecord := admitted(t, g)
	glifecycle.err = ErrCallNotStarted
	if _, err := g.buyer.SendLifecycle(context.Background(), grecord.RequestHash, LifecycleExpire); !errors.Is(err, ErrCallNotStarted) {
		t.Fatal(err)
	}
	glifecycle.err = nil
	if _, err := g.buyer.SendLifecycle(context.Background(), grecord.RequestHash, LifecycleExpire); err != nil {
		t.Fatalf("a send custody never started held the next back: %v", err)
	}
}

// An entry that can prove nothing holds the send back, and a history that
// cannot be read stops it.
func TestAnEarlierSendThatProvesNothingHoldsTheSendBack(t *testing.T) {
	edit := func(f *buyerFixture, record CallRecord, change func(*CallRecord)) CallRecord {
		t.Helper()
		edited, err := f.buyer.Journal().Transition(record.RequestHash, []CallPhase{PhaseAdmitted}, func(r *CallRecord) error {
			change(r)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return edited
	}
	f, lifecycle, record, _ := ambiguousExpire(t)
	edited := edit(f, record, func(r *CallRecord) { r.Lifecycle[0].ValidUntilBoundUnix = 0 })
	f.at(saNow.Add(24*time.Hour), 5)
	expectUnsettled(t, f, lifecycle, edited, "no fallback bound")

	g, glifecycle, grecord, _ := announcedExpire(t)
	edited = edit(g, grecord, func(r *CallRecord) { r.CallTransactionHex = "" })
	g.at(saNow, 6)
	expectUnsettled(t, g, glifecycle, edited, "no call transaction to anchor the actor history")

	h, hlifecycle, hrecord, _ := announcedExpire(t)
	edited = edit(h, hrecord, func(r *CallRecord) { r.CallTransactionLT++ })
	h.at(saNow, 6)
	if _, err := h.buyer.SendLifecycle(context.Background(), edited.RequestHash, LifecycleExpire); !errors.Is(err, ErrCallNotStarted) {
		t.Fatalf("an actor history without the call anchor did not stop the send: %v", err)
	}
	if len(hlifecycle.intents) != 1 {
		t.Fatal("a send went to custody without an anchored actor history")
	}

	for name, change := range map[string]func(*CallRecord){
		"no wallet anchor": func(r *CallRecord) { r.Lifecycle[0].WalletAnchorLT = 0 },
		"no message hash":  func(r *CallRecord) { r.Lifecycle[0].MessageHash = "" },
	} {
		k, klifecycle, krecord, _ := announcedExpire(t)
		edited = edit(k, krecord, change)
		k.at(saNow, 6)
		expectUnsettled(t, k, klifecycle, edited, name)
	}

	m, mlifecycle, mrecord, _ := announcedExpire(t)
	m.chain.wallet.historyErr = errors.New("quorum unavailable")
	m.at(saNow, 6)
	if _, err := m.buyer.SendLifecycle(context.Background(), mrecord.RequestHash, LifecycleExpire); !errors.Is(err, ErrCallNotStarted) {
		t.Fatalf("an unreadable wallet history did not stop the send: %v", err)
	}
	if len(mlifecycle.intents) != 1 {
		t.Fatal("a send went to custody without the wallet history")
	}
}

func TestAWalletReadFailureOrAConcurrentSendStopsTheSend(t *testing.T) {
	f := newBuyerFixture(t, defaultLimits())
	lifecycle := &deadlineLifecycle{}
	f.buyer.config.Lifecycle = lifecycle
	record := admitted(t, f)
	f.chain.wallet.seqnoErr = errors.New("quorum unavailable")
	if _, err := f.buyer.SendLifecycle(context.Background(), record.RequestHash, LifecycleExpire); !errors.Is(err, ErrCallNotStarted) {
		t.Fatalf("a send without the wallet seqno: %v", err)
	}
	f.chain.wallet.seqnoErr = nil
	f.chain.wallet.lastErr = errors.New("quorum unavailable")
	if _, err := f.buyer.SendLifecycle(context.Background(), record.RequestHash, LifecycleExpire); !errors.Is(err, ErrCallNotStarted) {
		t.Fatalf("a send without the wallet anchor: %v", err)
	}
	f.chain.wallet.lastErr = nil
	// A send journaled between the settlement check and the journal write
	// stops this one.
	f.chain.wallet.onSeqno = func() {
		f.chain.wallet.onSeqno = nil
		if _, err := f.buyer.Journal().Transition(record.RequestHash, []CallPhase{PhaseAdmitted}, func(r *CallRecord) error {
			r.Lifecycle = append(r.Lifecycle, LifecycleSend{Operation: LifecycleSweep, QueryID: 77, Phase: PhasePrepared})
			return nil
		}); err != nil {
			t.Error(err)
		}
	}
	if _, err := f.buyer.SendLifecycle(context.Background(), record.RequestHash, LifecycleExpire); !errors.Is(err, ErrLifecycleUnsettled) {
		t.Fatalf("a send raced by another journal write: %v", err)
	}
	if len(lifecycle.intents) != 0 {
		t.Fatal("a stopped send reached custody")
	}
}
