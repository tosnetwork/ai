package agentcarrier

import (
	"bytes"
	"errors"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

func schedulerFixture(t *testing.T, f *fixture) (*Scheduler, *Resolver, map[string]*fakeDirectory) {
	t.Helper()
	r, dirs := resolverFixture(t, f)
	raw := directoryRecord(t, f, f.peerRoute())
	addDirectoryHint(t, dirs[relayTwo], raw)
	s, e := OpenScheduler(f.lane, r)
	if e != nil {
		t.Fatal(e)
	}
	return s, r, dirs
}
func TestTwoCopiesRetrySameEnvelopeAcrossRestart(t *testing.T) {
	f := newFixture(t)
	s, r, _ := schedulerFixture(t, f)
	defer func() {
		if e := s.Close(); e != nil {
			t.Error(e)
		}
	}()
	if _, e := f.lane.Queue(t.Context(), "copies", f.message(f.alice, f.bob), start+86400); e != nil {
		t.Fatal(e)
	}
	f.relays[relayTwo].outcomes = []error{ErrUnavailable}
	first, e := s.Advance(t.Context(), "copies", Route{})
	if e != nil || first.Copies != 1 || first.Code != "single-copy" || first.NextAttempt != start+30 {
		t.Fatal(first, e)
	}
	if len(f.relays[relayOne].deposits) != 1 || len(f.relays[relayTwo].deposits) != 1 {
		t.Fatal("first pass did not try both relays")
	}
	wire := bytes.Clone(f.relays[relayOne].deposits[0])
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = OpenScheduler(f.lane, r)
	if e != nil {
		t.Fatal(e)
	}
	f.clock.n.Store(int64(start + 29))
	if _, e = s.Advance(t.Context(), "copies", Route{}); e != nil {
		t.Fatal(e)
	}
	if len(f.relays[relayTwo].deposits) != 1 {
		t.Fatal("restart reset backoff")
	}
	f.relays[relayTwo].error = nil
	f.clock.n.Store(int64(start + 30))
	second, e := s.Advance(t.Context(), "copies", Route{})
	if e != nil || second.Copies != 2 {
		t.Fatal(second, e)
	}
	if len(f.relays[relayOne].deposits) != 1 || len(f.relays[relayTwo].deposits) != 2 || !bytes.Equal(wire, f.relays[relayTwo].deposits[1]) {
		t.Fatal("second copy resealed or re-deposited the accepted copy")
	}
	f.clock.n.Store(int64(start + 31))
	if _, e = s.Advance(t.Context(), "copies", Route{}); e != nil {
		t.Fatal(e)
	}
	if len(f.relays[relayTwo].deposits) != 2 {
		t.Fatal("two copies did not end this generation")
	}
}
func TestAcknowledgedDuringOutageNeverGetsASecondCopy(t *testing.T) {
	f := newFixture(t)
	s, _, _ := schedulerFixture(t, f)
	defer func() {
		if e := s.Close(); e != nil {
			t.Error(e)
		}
	}()
	if _, e := f.lane.Queue(t.Context(), "ack", f.message(f.alice, f.bob), start+86400); e != nil {
		t.Fatal(e)
	}
	f.relays[relayTwo].outcomes = []error{ErrUnavailable}
	if _, e := s.Advance(t.Context(), "ack", Route{}); e != nil {
		t.Fatal(e)
	}
	if e := f.lane.Complete(t.Context(), "ack"); e != nil {
		t.Fatal(e)
	}
	f.relays[relayTwo].error = nil
	f.clock.n.Store(int64(start + 600))
	view, e := s.Advance(t.Context(), "ack", Route{})
	if e != nil || view.State != "complete" {
		t.Fatal(view, e)
	}
	if len(f.relays[relayTwo].deposits) != 1 {
		t.Fatal("acknowledged delivery got another deposit")
	}
}
func TestNoRouteBackoffAndDueGenerationAreDurable(t *testing.T) {
	f := newFixture(t)
	s, r, dirs := schedulerFixture(t, f)
	defer func() {
		if e := s.Close(); e != nil {
			t.Error(e)
		}
	}()
	dirs[relayTwo].records = map[[32]byte][]byte{}
	if _, e := f.lane.Queue(t.Context(), "route", f.message(f.alice, f.bob), start+2000); e != nil {
		t.Fatal(e)
	}
	for i, at := range []uint64{0, 30, 90, 210, 450, 600, 1200} {
		f.clock.n.Store(int64(start + at))
		before := dirs[relayOne].reads
		view, e := s.Advance(t.Context(), "route", Route{})
		if e != nil || view.Code != "no-route" || dirs[relayOne].reads != before+1 {
			t.Fatal(i, at, view, e, dirs[relayOne].reads-before)
		}
		if i == 0 {
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			s, e = OpenScheduler(f.lane, r)
			if e != nil {
				t.Fatal(e)
			}
		}
		f.clock.n.Store(int64(start + at + 1))
		if _, e = s.Advance(t.Context(), "route", Route{}); e != nil {
			t.Fatal(e)
		}
		if dirs[relayOne].reads != before+1 {
			t.Fatal("resolution ignored backoff", at)
		}
	}
	raw := directoryRecord(t, f, f.peerRoute())
	addDirectoryHint(t, dirs[relayTwo], raw)
	f.clock.n.Store(int64(start + 1800))
	view, e := s.Advance(t.Context(), "route", Route{})
	if e != nil || view.Copies != 2 {
		t.Fatal("republished peer never resumed pending delivery", view, e)
	}
	f.clock.n.Store(int64(start + 2000))
	view, e = s.Advance(t.Context(), "route", Route{})
	if e != nil || view.State != "abandoned" || view.Code != "retention-exceeded" {
		t.Fatal(view, e)
	}
}
func TestGenerationWithdrawalAndCounterSurviveManyDeposits(t *testing.T) {
	f := newFixture(t)
	s, _, _ := schedulerFixture(t, f)
	defer func() {
		if e := s.Close(); e != nil {
			t.Error(e)
		}
	}()
	if _, e := f.lane.Queue(t.Context(), "generations", f.message(f.alice, f.bob), start+86400); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 6; i++ {
		f.clock.n.Store(int64(start + uint64(i)*2880))
		view, e := s.Advance(t.Context(), "generations", Route{})
		if e != nil || view.Copies != 2 {
			t.Fatal(i, view, e)
		}
		r, e := s.snapshot(t.Context(), "generations")
		if e != nil || len(r.Generations) != 1 || r.Generations[0].Number != uint32(i+1) {
			t.Fatal("generation counter or compaction", i, len(r.Generations), r.GenerationCounter, e)
		}
		h, e := agentpacketseal.ParseEnvelope(r.Generations[0].Envelope)
		if e != nil || h.ExpiresAtUnix != start+86400 {
			t.Fatal(h, e)
		}
	}
	if len(f.relays[relayOne].deposits) != 6 || len(f.relays[relayTwo].deposits) != 6 {
		t.Fatal("generation stopped at the old full-envelope retention cap")
	}
}
func TestPermanentRelayRefusalIsNotRetriedInThisGeneration(t *testing.T) {
	f := newFixture(t)
	s, _, _ := schedulerFixture(t, f)
	defer func() {
		if e := s.Close(); e != nil {
			t.Error(e)
		}
	}()
	if _, e := f.lane.Queue(t.Context(), "refusal", f.message(f.alice, f.bob), start+86400); e != nil {
		t.Fatal(e)
	}
	f.relays[relayOne].outcomes = []error{&agentpacketrelay.StatusError{StatusCode: 422}}
	if _, e := s.Advance(t.Context(), "refusal", Route{}); e != nil {
		t.Fatal(e)
	}
	f.clock.n.Store(int64(start + 600))
	if _, e := s.Advance(t.Context(), "refusal", Route{}); e != nil && !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if len(f.relays[relayOne].deposits) != 1 {
		t.Fatal("permanent refusal retried")
	}
}
