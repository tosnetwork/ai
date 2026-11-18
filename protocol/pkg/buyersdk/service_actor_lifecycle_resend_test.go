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

func (d *deadlineLifecycle) SendLifecycle(ctx context.Context, intent LifecycleIntent) error {
	deadline, _ := ctx.Deadline()
	d.mu.Lock()
	d.deadlines = append(d.deadlines, deadline)
	d.mu.Unlock()
	return d.fakeLifecycle.SendLifecycle(ctx, intent)
}

// ambiguousExpire admits a call and leaves one ambiguous expire send at
// wallet seqno 5.
func ambiguousExpire(t *testing.T) (*buyerFixture, *deadlineLifecycle, CallRecord, LifecycleSend) {
	t.Helper()
	f := newBuyerFixture(t, defaultLimits())
	lifecycle := &deadlineLifecycle{}
	f.buyer.config.Lifecycle = lifecycle
	record := admitted(t, f)
	f.chain.wallet.seqno = 5
	lifecycle.err = errors.New("tosctl exited after submitting")
	sent, err := f.buyer.SendLifecycle(context.Background(), record.RequestHash, LifecycleExpire)
	if err == nil || len(sent.Lifecycle) != 1 || sent.Lifecycle[0].Phase != PhaseAmbiguous {
		t.Fatalf("fixture send: %+v %v", sent.Lifecycle, err)
	}
	lifecycle.err = nil
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

func TestALifecycleSendRecordsTheWalletSeqnoAndItsValidityBound(t *testing.T) {
	_, lifecycle, _, sent := ambiguousExpire(t)
	if sent.WalletSeqno != 5 || sent.SentUnix != saNow.Unix() ||
		sent.ValidUntilBoundUnix != saNow.Add(10*time.Minute).Unix() {
		t.Fatalf("journaled %+v", sent)
	}
	if LifecycleValidUntilBound(saNow) != saNow.Unix()+600 {
		t.Fatal("the bound is the custody timeout plus the wallet message lifetime plus clock skew")
	}
	// Custody can sign only until the deadline the bound counts from.
	if len(lifecycle.deadlines) != 1 || !lifecycle.deadlines[0].Equal(saNow.Add(LifecycleSendTimeout)) {
		t.Fatalf("custody deadline %v", lifecycle.deadlines)
	}
}

// Rule 2: an unchanged seqno past the message's validity proves it never
// executes; before that, or with the seqno moved, the send is held back.
func TestAnUnsettledLifecycleSendIsNotRepeated(t *testing.T) {
	f, lifecycle, record, sent := ambiguousExpire(t)
	bound := time.Unix(sent.ValidUntilBoundUnix, 0)
	// A transaction of another sender with the send's query_id is not the
	// send.
	f.lifecycleTx(toschain.ActorTransaction{Kind: toschain.ActorTxExpire, Sender: saOwner, QueryID: sent.QueryID})
	f.at(saNow.Add(LifecycleSendTimeout), 5)
	expectUnsettled(t, f, lifecycle, record, "before the validity bound")
	f.at(bound, 5)
	expectUnsettled(t, f, lifecycle, record, "at the validity bound")
	f.at(bound.Add(time.Second), 6)
	expectUnsettled(t, f, lifecycle, record, "past the bound with the seqno moved")
	f.at(bound.Add(time.Second), 5)
	expectSent(t, f, lifecycle, record, "past the bound with the seqno unchanged")
}

// Rule 3: with the seqno moved, the send is settled only when history since
// the call shows no transaction of the wallet that could be it, after the
// delivery allowance.
func TestAMovedSeqnoSettlesOnlyByAbsenceFromHistoryAfterTheDeliveryAllowance(t *testing.T) {
	f, lifecycle, record, sent := ambiguousExpire(t)
	late := time.Unix(sent.ValidUntilBoundUnix, 0).Add(LifecycleDeliveryAllowance)
	f.at(late, 6)
	expectUnsettled(t, f, lifecycle, record, "at the end of the delivery allowance")
	// A failed transaction of the wallet whose body shows no query_id
	// could be the send.
	f.lifecycleTx(toschain.ActorTransaction{Kind: toschain.ActorTxFailed, Sender: saBuyer, ExitCode: 9,
		BodyBOC: base64.StdEncoding.EncodeToString(cell.BeginCell().MustStoreUInt(7, 3).EndCell().ToBOC())})
	f.at(late.Add(time.Second), 6)
	expectUnsettled(t, f, lifecycle, record, "an undecodable wallet transaction in history")

	g, glifecycle, grecord, gsent := ambiguousExpire(t)
	// Another sender's transaction and the wallet's own other sends do not
	// count.
	g.lifecycleTx(toschain.ActorTransaction{Kind: toschain.ActorTxExpire, Sender: saOwner, QueryID: gsent.QueryID})
	g.lifecycleTx(toschain.ActorTransaction{Kind: toschain.ActorTxSweep, Sender: saBuyer, QueryID: gsent.QueryID + 1})
	g.at(time.Unix(gsent.ValidUntilBoundUnix, 0).Add(LifecycleDeliveryAllowance+time.Second), 6)
	expectSent(t, g, glifecycle, grecord, "absent from history after the allowance")
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
	f, lifecycle, record, _ := ambiguousExpire(t)
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
	_ = lifecycle
}

// An entry without a validity bound, or a call without its transaction, can
// prove nothing, and the send is held back.
func TestAnEarlierSendThatProvesNothingHoldsTheSendBack(t *testing.T) {
	f, lifecycle, record, _ := ambiguousExpire(t)
	edited, err := f.buyer.Journal().Transition(record.RequestHash, []CallPhase{PhaseAdmitted}, func(r *CallRecord) error {
		r.Lifecycle[0].ValidUntilBoundUnix = 0
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	f.at(saNow.Add(24*time.Hour), 5)
	expectUnsettled(t, f, lifecycle, edited, "no validity bound")

	g, glifecycle, grecord, gsent := ambiguousExpire(t)
	edited, err = g.buyer.Journal().Transition(grecord.RequestHash, []CallPhase{PhaseAdmitted}, func(r *CallRecord) error {
		r.CallTransactionHex = ""
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	g.at(time.Unix(gsent.ValidUntilBoundUnix, 0).Add(LifecycleDeliveryAllowance+time.Second), 6)
	expectUnsettled(t, g, glifecycle, edited, "no call transaction to anchor the history")

	h, hlifecycle, hrecord, hsent := ambiguousExpire(t)
	edited, err = h.buyer.Journal().Transition(hrecord.RequestHash, []CallPhase{PhaseAdmitted}, func(r *CallRecord) error {
		r.CallTransactionLT++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	h.at(time.Unix(hsent.ValidUntilBoundUnix, 0).Add(LifecycleDeliveryAllowance+time.Second), 6)
	if _, err := h.buyer.SendLifecycle(context.Background(), edited.RequestHash, LifecycleExpire); !errors.Is(err, ErrCallNotStarted) {
		t.Fatalf("a history without the call anchor did not stop the send: %v", err)
	}
	if len(hlifecycle.intents) != 1 {
		t.Fatal("a send went to custody without an anchored history")
	}
}

func TestASeqnoReadFailureOrAConcurrentSendStopsTheSend(t *testing.T) {
	f := newBuyerFixture(t, defaultLimits())
	lifecycle := &deadlineLifecycle{}
	f.buyer.config.Lifecycle = lifecycle
	record := admitted(t, f)
	f.chain.wallet.seqnoErr = errors.New("quorum unavailable")
	if _, err := f.buyer.SendLifecycle(context.Background(), record.RequestHash, LifecycleExpire); !errors.Is(err, ErrCallNotStarted) {
		t.Fatalf("a send without the wallet seqno: %v", err)
	}
	f.chain.wallet.seqnoErr = nil
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
