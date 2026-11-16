package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// The wait before the next generation is 80 % of the reported relay TTL,
// floored at the minimum interval and capped by the configured one.
func TestRedepositDelayFollowsTheReportedRelayTTL(t *testing.T) {
	for _, test := range []struct {
		interval time.Duration
		ttl      uint64
		want     time.Duration
	}{
		{DefaultRelayRedepositInterval, 3600, 48 * time.Minute},               // test relays
		{DefaultRelayRedepositInterval, 10800, 2*time.Hour + 24*time.Minute},  // production relays
		{DefaultRelayRedepositInterval, 86400, 19*time.Hour + 12*time.Minute}, // protocol maximum
		{DefaultRelayRedepositInterval, 750, MinRelayRedepositInterval},       // exactly the floor
		{DefaultRelayRedepositInterval, 600, MinRelayRedepositInterval},       // floored
		{DefaultRelayRedepositInterval, 1, MinRelayRedepositInterval},         // floored
		{time.Hour, 10800, time.Hour},                                         // capped by the configuration
		{MinRelayRedepositInterval, 86400, MinRelayRedepositInterval},         // a test interval
		{DefaultRelayRedepositInterval, 3601, 48 * time.Minute},               // whole seconds, rounded down
	} {
		got, err := (&relayRuntime{interval: test.interval}).redepositDelay(test.ttl)
		if err != nil || got != test.want {
			t.Errorf("interval %s ttl %d: %s %v, want %s", test.interval, test.ttl, got, err, test.want)
		}
	}
	for _, ttl := range []uint64{0, carrierapi.MaxRelayTTLSeconds + 1, ^uint64(0)} {
		if _, err := (&relayRuntime{interval: DefaultRelayRedepositInterval}).redepositDelay(ttl); !errors.Is(err, carrierapi.ErrRelayTTL) {
			t.Errorf("ttl %d: err = %v", ttl, err)
		}
	}
}

// With 1 h test relays a carried copy is deposited again 48 minutes after its
// deposit, before every relay drops it, and the new generation withdraws the
// old one.
func TestRelayCopyIsRedepositedBeforeAOneHourTTL(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	a.d.relay.interval = DefaultRelayRedepositInterval
	a.carrier.ttl = map[string]uint64{b.d.config.AgentID: 3600}
	importContact(t, a, b)
	importContact(t, b, a)
	eventID := sendText(t, a, b, "while B is away", "a", now)
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("first deposit: %+v %v", summary, err)
	}
	a.carrier.take()
	state := copyState(t, a, eventID, b.d.config.EndpointID, b.d.config.DeviceID)
	due := now.Add(48 * time.Minute)
	if state.State != eventlog.StateCarried || state.NextRedepositAtUnix != uint64(due.Unix()) {
		t.Fatalf("first generation: state=%s next=%d, want %d", state.State, state.NextRedepositAtUnix, due.Unix())
	}
	if !due.Before(now.Add(time.Hour)) {
		t.Fatal("the re-deposit is not scheduled before the relay TTL")
	}

	// One second early: nothing is due.
	a.d.now = func() time.Time { return due.Add(-time.Second) }
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 0 {
		t.Fatalf("early sweep: %+v %v", summary, err)
	}
	if frames := a.carrier.take(); len(frames) != 0 {
		t.Fatalf("early sweep carried %d frames", len(frames))
	}

	// At 48 minutes generation 2 is carried and withdraws generation 1.
	a.d.now = func() time.Time { return due }
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("re-deposit sweep: %+v %v", summary, err)
	}
	second := onlyFrame(t, a)
	delivery := copyState(t, a, eventID, b.d.config.EndpointID, b.d.config.DeviceID)
	firstKey, _ := relayframe.CopyIdempotencyKey(delivery.DeliveryID, 1)
	secondKey, _ := relayframe.CopyIdempotencyKey(delivery.DeliveryID, 2)
	if second.key != secondKey || second.withdraw != firstKey || delivery.Generation != 2 {
		t.Fatalf("second generation: key=%s withdraw=%s generation=%d", second.key, second.withdraw, delivery.Generation)
	}
	// The copy expires an hour after it was sent, before a third generation
	// would be due, so none is scheduled.
	if delivery.State != eventlog.StateCarried || delivery.NextRedepositAtUnix != 0 {
		t.Fatalf("after the second generation: state=%s next=%d", delivery.State, delivery.NextRedepositAtUnix)
	}
	// B, back online, applies the second generation once.
	if answer := deliver(t, a, b, second.frame); answer.Result != carrierapi.ResultAck ||
		answer.AckOutcome != relayframe.OutcomeAccepted {
		t.Fatalf("second generation at B: %+v", answer)
	}
}

// Each peer's copies follow the TTL the carrier reports for that peer's card
// (the smallest of its relays), and a later generation follows the latest
// report.
func TestRelayRedepositIsScheduledPerPeerCard(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"}, [2]string{"5", "6"})
	a, b, c := nodes[0], nodes[1], nodes[2]
	a.d.relay.interval = DefaultRelayRedepositInterval
	// B's card names a 1 h test relay beside a 3 h one; C's only 3 h relays.
	a.carrier.ttl = map[string]uint64{b.d.config.AgentID: 3600, c.d.config.AgentID: 10800}
	for _, peer := range []*relayNode{b, c} {
		importContact(t, a, peer)
		importContact(t, peer, a)
	}
	expires := uint64(now.Add(24 * time.Hour).Unix())
	send := func(to *relayNode, idem string) string {
		t.Helper()
		result, err := a.d.SendDirectMessage(context.Background(), to.d.config.AgentID, "text/plain; charset=utf-8",
			"retained", "idem_"+strings.Repeat(idem, 64), expires)
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		return result.EventID
	}
	toB, toC := send(b, "a"), send(c, "b")
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 2 {
		t.Fatalf("first deposits: %+v %v", summary, err)
	}
	a.carrier.take()
	next := func(eventID string, peer *relayNode) uint64 {
		t.Helper()
		return copyState(t, a, eventID, peer.d.config.EndpointID, peer.d.config.DeviceID).NextRedepositAtUnix
	}
	if got, want := next(toB, b), uint64(now.Add(48*time.Minute).Unix()); got != want {
		t.Fatalf("copy to B due at %d, want %d", got, want)
	}
	if got, want := next(toC, c), uint64(now.Add(2*time.Hour+24*time.Minute).Unix()); got != want {
		t.Fatalf("copy to C due at %d, want %d", got, want)
	}

	// B's card later names a 30-minute relay: only B's copy is due, and its
	// next generation follows the new report.
	later := now.Add(48 * time.Minute)
	a.d.now = func() time.Time { return later }
	a.carrier.ttl[b.d.config.AgentID] = 1800
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("re-deposits: %+v %v", summary, err)
	}
	if out := onlyFrame(t, a); out.recipient != b.d.config.AgentID {
		t.Fatal("a copy not yet due was deposited again")
	}
	if got, want := next(toB, b), uint64(later.Add(24*time.Minute).Unix()); got != want {
		t.Fatalf("copy to B due at %d after the new report, want %d", got, want)
	}
	if got, want := next(toC, c), uint64(now.Add(2*time.Hour+24*time.Minute).Unix()); got != want {
		t.Fatalf("copy to C rescheduled to %d, want %d", got, want)
	}
}

// A carried answer without a valid TTL records nothing: the same generation
// is tried again, and the carrier answers it without a new deposit.
func TestACarriedAnswerWithoutAValidTTLIsRetried(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	eventID := sendText(t, a, b, "ttl", "a", now)
	observer := &recorder{}
	a.d.observer = observer
	for index, ttl := range []uint64{0, carrierapi.MaxRelayTTLSeconds + 1} {
		at := now.Add(time.Duration(index) * time.Minute)
		a.d.now = func() time.Time { return at }
		a.carrier.answer = &carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultCarried,
			RelayTTLSeconds: ttl}
		if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 0 {
			t.Fatalf("ttl %d: %+v %v", ttl, summary, err)
		}
		state := copyState(t, a, eventID, b.d.config.EndpointID, b.d.config.DeviceID)
		if state.State == eventlog.StateCarried || state.NextRedepositAtUnix != 0 {
			t.Fatalf("ttl %d recorded: state=%s next=%d", ttl, state.State, state.NextRedepositAtUnix)
		}
	}
	if attempts := a.carrier.take(); len(attempts) != 2 {
		t.Fatalf("carry attempts: %d, want 2", len(attempts))
	}
	// An older carrier shows on the owner surface, once per process.
	reported := 0
	for _, stage := range observer.failures {
		if stage == "relay carrier reported no valid relay TTL" {
			reported++
		}
	}
	if reported != 1 {
		t.Fatalf("missing-TTL reports: %d, want 1 (%v)", reported, observer.failures)
	}
	a.carrier.answer = nil
	// The retry still has generation 1's key.
	a.d.now = func() time.Time { return now.Add(2 * time.Minute) }
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("retry: %+v %v", summary, err)
	}
	delivery := copyState(t, a, eventID, b.d.config.EndpointID, b.d.config.DeviceID)
	key, _ := relayframe.CopyIdempotencyKey(delivery.DeliveryID, 1)
	if out := onlyFrame(t, a); out.key != key || out.withdraw != "" || delivery.Generation != 1 {
		t.Fatalf("retried generation: key=%s withdraw=%q generation=%d", out.key, out.withdraw, delivery.Generation)
	}
}

// The single outstanding evidence request follows the same TTL rule.
func TestEvidenceRequestIsRedepositedBeforeAOneHourTTL(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	a.d.relay.interval = DefaultRelayRedepositInterval
	a.carrier.ttl = map[string]uint64{b.d.config.AgentID: 3600}
	importContact(t, a, b)
	importContact(t, b, a)
	sendText(t, a, b, "pending", "a", now)
	stored, _, err := a.d.journal.LoadRelayEvidence(b.d.config.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.d.journal.StoreRelayEvidence(b.d.config.AgentID, oldEvidence(t, b, now), canon.Digest(stored), now); err != nil {
		t.Fatal(err)
	}
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Deferred != 1 {
		t.Fatalf("stale evidence: %+v %v", summary, err)
	}
	a.d.relay.sweepPulls(context.Background())
	if requests := framesOfKind(t, a.carrier.take(), relayframe.KindEvidence); len(requests) != 1 {
		t.Fatalf("evidence requests: %d", len(requests))
	}
	pull, _, err := a.d.journal.LoadRelayPull(b.d.config.AgentID)
	if want := uint64(now.Add(48 * time.Minute).Unix()); err != nil || pull.RequestGeneration != 1 || pull.RequestNextAtUnix != want {
		t.Fatalf("request schedule: %+v %v, want next %d", pull, err, want)
	}
	due := now.Add(48 * time.Minute)
	a.d.now = func() time.Time { return due }
	a.d.relay.sweepPulls(context.Background())
	requests := framesOfKind(t, a.carrier.take(), relayframe.KindEvidence)
	firstKey, _ := relayframe.EvidenceRequestKey(b.d.config.AgentID, 1)
	if len(requests) != 1 || requests[0].withdraw != firstKey {
		t.Fatalf("second request: %+v", requests)
	}
}
