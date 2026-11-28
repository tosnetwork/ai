package agentcarrier

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
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

func TestTwoCopiesStopBeforeAThirdRelayAndJournalBeforeTransport(t *testing.T) {
	f := newFixture(t)
	s, _, dirs := schedulerFixture(t, f)
	defer func() {
		if e := s.Close(); e != nil {
			t.Error(e)
		}
	}()
	const third = "https://127.0.0.1:19003"
	f.relays[third] = newRelay()
	route := f.peerRoute()
	record, e := agenttransport.DecodeHintRecord(route.HintRecord)
	if e != nil {
		t.Fatal(e)
	}
	record.Hint.Relays = []string{relayOne, relayTwo, third}
	raw, e := f.verifier.BuildHintRecord(t.Context(), record.Hint, []agenttransport.HintObject{{Kind: agenttransport.RailCard, Bytes: route.CardPacket}}, f.bob.transport, agenttransport.PublishOptions{})
	if e != nil {
		t.Fatal(e)
	}
	dirs[relayTwo].records = map[[32]byte][]byte{}
	addDirectoryHint(t, dirs[relayTwo], raw)
	if _, e = f.lane.Queue(t.Context(), "three", f.message(f.alice, f.bob), start+86400); e != nil {
		t.Fatal(e)
	}
	for _, url := range []string{relayOne, relayTwo, third} {
		url := url
		f.relays[url].before = func(_ []byte) {
			var m schedule
			if e := s.store.read(routingName("three"), &m); e != nil {
				t.Fatal(e)
			}
			found := false
			for _, retry := range m.Targets {
				if retry.URL == url && retry.After >= start+30 {
					found = true
				}
			}
			if !found {
				t.Fatal("retry not journalled before transport", url)
			}
		}
	}
	view, e := s.Advance(t.Context(), "three", Route{})
	if e != nil || view.Copies != 2 || len(f.relays[third].deposits) != 0 {
		t.Fatal("not exactly two copies", view, e)
	}
}

func TestDriverKeepsResolvingNoRouteUntilHintOrDeadline(t *testing.T) {
	for _, republish := range []bool{false, true} {
		t.Run(strconv.FormatBool(republish), func(t *testing.T) {
			f := newFixture(t)
			s, _, dirs := schedulerFixture(t, f)
			defer func() {
				if e := s.Close(); e != nil {
					t.Error(e)
				}
			}()
			dirs[relayTwo].records = map[[32]byte][]byte{}
			if _, e := f.lane.Queue(t.Context(), "driver", f.message(f.alice, f.bob), start+2000); e != nil {
				t.Fatal(e)
			}
			waits := []uint64{}
			complete := false
			s.wait = func(ctx context.Context, d time.Duration) error {
				if e := ctx.Err(); e != nil {
					return e
				}
				if d <= 0 || d > 600*time.Second {
					t.Fatal("unbounded retry", d)
				}
				waits = append(waits, uint64(d/time.Second))
				if len(waits) > 12 {
					t.Fatal("driver is not making progress")
				}
				if republish && len(f.relays[relayOne].deposits) > 0 && !complete {
					if e := f.lane.Complete(ctx, "driver"); e != nil {
						return e
					}
					complete = true
				}
				f.clock.n.Add(int64(d / time.Second))
				if republish && f.clock.n.Load() >= int64(start+600) {
					addDirectoryHint(t, dirs[relayTwo], directoryRecord(t, f, f.peerRoute()))
				}
				return nil
			}
			view, e := s.RunDelivery(t.Context(), "driver", nil)
			if e != nil {
				t.Fatal(e)
			}
			expected := []uint64{30, 60, 120, 240, 150}
			if len(waits) < len(expected) || !slices.Equal(waits[:len(expected)], expected) {
				t.Fatal("retry schedule or due-generation override", waits)
			}
			if republish {
				if view.State != "complete" || len(f.relays[relayOne].deposits) != 1 || len(f.relays[relayTwo].deposits) != 1 {
					t.Fatal("hint recovery or receipt did not stop retries", view)
				}
			} else if view.State != "abandoned" || view.Code != "retention-exceeded" || f.clock.n.Load() != int64(start+2000) {
				t.Fatal("deadline did not end no-route", view, f.clock.Now())
			}
		})
	}
}

func TestTTLIncreaseCannotExtendCopiesAlreadyAccepted(t *testing.T) {
	f := newFixture(t)
	s, _, _ := schedulerFixture(t, f)
	defer func() {
		if e := s.Close(); e != nil {
			t.Error(e)
		}
	}()
	if _, e := f.lane.Queue(t.Context(), "ttl", f.message(f.alice, f.bob), start+86400); e != nil {
		t.Fatal(e)
	}
	f.relays[relayTwo].outcomes = []error{ErrUnavailable}
	if _, e := s.Advance(t.Context(), "ttl", Route{}); e != nil {
		t.Fatal(e)
	}
	f.relays[relayTwo].error = nil
	f.relays[relayOne].ttl = 10800
	f.relays[relayTwo].ttl = 10800
	f.clock.n.Store(int64(start + 30))
	view, e := s.Advance(t.Context(), "ttl", Route{})
	if e != nil || view.Copies != 2 || view.TTLSeconds != 3600 || view.NextAttempt != start+2880 {
		t.Fatal("description change extended an earlier acceptance", view, e)
	}
	f.clock.n.Store(int64(start + 2880))
	view, e = s.Advance(t.Context(), "ttl", Route{})
	if e != nil || view.Copies != 2 || view.TTLSeconds != 10800 || view.NextAttempt != start+2880+8640 {
		t.Fatal("new generation did not adopt its new retention", view, e)
	}
}
