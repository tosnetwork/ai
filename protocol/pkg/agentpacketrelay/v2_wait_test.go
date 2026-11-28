package agentpacketrelay

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"testing"
	"time"
)

func waitStarted(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		t.Fatal("wait registration never reached")
	}
}
func waitDone(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		t.Fatal("waiting request did not finish")
	}
}
func installWaitClock(t testing.TB, f *v2HTTPFixture, started chan<- struct{}, ticks <-chan time.Time) {
	f.s.waitTimer = func(d time.Duration) (<-chan time.Time, func()) {
		if d != 25*time.Second {
			t.Errorf("unexpected wait duration: %s", d)
		}
		started <- struct{}{}
		return ticks, func() {}
	}
}
func TestV2LongPollWakeTimeoutAndSingleWaiter(t *testing.T) {
	for _, kind := range []string{"deposit", "timeout", "cancel", "expiry", "revocation", "close"} {
		t.Run(kind, func(t *testing.T) {
			f := newV2HTTP(t)
			ticks := make(chan time.Time, 1)
			started := make(chan struct{}, 1)
			installWaitClock(t, f, started, ticks)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			request, w := fWaitRequest(t, f, ctx, "25")
			done := make(chan struct{})
			go func() { defer close(done); f.s.ServeHTTP(v2DeadlineWriter{w}, request) }()
			waitStarted(t, started)
			second, w2 := fWaitRequest(t, f, t.Context(), "25")
			f.s.ServeHTTP(v2DeadlineWriter{w2}, second)
			if w2.Code != 429 {
				t.Fatal("second waiter admitted", w2.Code)
			}
			switch kind {
			case "deposit":
				e := f.r.seal(t, testPacket(1), unixNow(f.clock.Now())+3600)
				f.serve(t, "PUT", f.mail()+"/"+hex.EncodeToString(e.id[:]), e.envelope, false, 201)
			case "timeout":
				ticks <- testStart
			case "cancel":
				cancel()
			case "expiry":
				f.clock.at = f.clock.at.Add(3600 * time.Second)
				ticks <- testStart
			case "revocation":
				c, err := agenttransport.DecodeCredential(f.wire)
				if err != nil {
					t.Fatal(err)
				}
				chains, err := c.ChainValues()
				if err != nil {
					t.Fatal(err)
				}
				raw, err := EncodeRevocations([]Revocation{{chains[1], unixNow(f.clock.Now()) + 3600}})
				if err != nil {
					t.Fatal(err)
				}
				f.serve(t, "POST", "/v2/mailboxes/"+f.r.agentID+"/revocations", raw, true, 204)
			case "close":
				v2Close(t, f.s.store)
			}
			waitDone(t, done)
			want := 200
			if kind == "cancel" || kind == "close" {
				want = 503
			}
			if kind == "expiry" || kind == "revocation" {
				want = 403
			}
			if w.Code != want {
				t.Fatal(kind, w.Code, w.Body.String())
			}
			if kind == "deposit" && !bytes.Contains(w.Body.Bytes(), []byte(`"lane":"stranger"`)) {
				t.Fatal("woken list lost its envelope")
			}
			if len(f.s.store.waiters) != 0 {
				t.Fatal("waiting slot leaked")
			}
		})
	}
}
func TestV2LongPollHeadersAreStrict(t *testing.T) {
	f := newV2HTTP(t)
	for _, value := range []string{"", "0", "26", "01", "+1", "1,2"} {
		request, w := fWaitRequest(t, f, t.Context(), value)
		f.s.ServeHTTP(v2DeadlineWriter{w}, request)
		if w.Code != 400 {
			t.Fatal(value, w.Code)
		}
	}
	request, w := fWaitRequest(t, f, t.Context(), "1")
	request.Header.Add("TOS-Relay-Wait", "1")
	f.s.ServeHTTP(v2DeadlineWriter{w}, request)
	if w.Code != 400 {
		t.Fatal("duplicate wait header accepted")
	}
}
func TestV2WaitRegistrationBoundsAndRearms(t *testing.T) {
	f := newV2HTTP(t)
	f.s.store.controlLimits.Waiters = 1
	a, _ := parseAgentText(f.r.agentID)
	_, ch, err := f.s.store.waitSnapshot(t.Context(), a, unixNow(f.clock.Now()), nil)
	if err != nil || ch == nil {
		t.Fatal(err)
	}
	other := a
	other[0] ^= 1
	if _, _, err = f.s.store.waitSnapshot(t.Context(), other, unixNow(f.clock.Now()), nil); !errors.Is(err, errWaitFull) {
		t.Fatal("global waiter bound lost", err)
	}
	f.s.store.mu.Lock()
	f.s.store.notifyLocked(f.r.agentID)
	f.s.store.mu.Unlock()
	_, next, err := f.s.store.waitSnapshot(t.Context(), a, unixNow(f.clock.Now()), ch)
	if err != nil || next == nil || next == ch {
		t.Fatal("empty wake did not rearm", err)
	}
	f.s.store.endWait(a, next)
	if len(f.s.store.waiters) != 0 {
		t.Fatal("waiter was not freed")
	}
}

func TestV2WaitRegistryCommitNotificationAndBusyBound(t *testing.T) {
	f := newV2HTTP(t)
	a, _ := parseAgentText(f.r.agentID)
	now := unixNow(f.clock.Now())
	_, ch, err := f.s.store.waitSnapshot(t.Context(), a, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.s.store.waitSnapshot(t.Context(), a, now, nil); !errors.Is(err, errWaitBusy) {
		t.Fatal("second waiter replaced the first", err)
	}
	e := f.r.seal(t, testPacket(1), now+3600)
	v2Deposit(t, f.s.store, f.r, e, v2Loopback(1), now, nil)
	select {
	case <-ch:
	default:
		t.Fatal("committed deposit did not wake the registered reader")
	}
	f.s.store.endWait(a, ch)
}
func TestV2LongPollRechecksNativeWithdrawal(t *testing.T) {
	f := newV2HTTP(t)
	started := make(chan struct{}, 1)
	ticks := make(chan time.Time, 1)
	installWaitClock(t, f, started, ticks)
	request, w := fWaitRequest(t, f, t.Context(), "25")
	done := make(chan struct{})
	go func() { defer close(done); f.s.ServeHTTP(v2DeadlineWriter{w}, request) }()
	waitStarted(t, started)
	f.source.state.GetAgent().DelegationDigests = nil
	f.clock.at = f.clock.at.Add(300 * time.Second)
	ticks <- testStart
	waitDone(t, done)
	if w.Code != 403 {
		t.Fatal("withdrawn delegation read after waiting", w.Code, w.Body.String())
	}
}
