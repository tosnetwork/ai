package agentpacketrelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

func TestV2LongPollCredentialExpiresDuringFinalRead(t *testing.T) {
	f := newV2HTTP(t)
	base := f.clock.Now()
	c, err := agenttransport.DecodeCredential(f.wire)
	if err != nil {
		t.Fatal(err)
	}
	f.wire, err = agenttransport.IssueCredential(mustDelegation(t, c), v2TestKey("http-transport"), f.holder.Public().(ed25519.PublicKey), []agenttransport.Caveat{agenttransport.NotBeforeCaveat(unixNow(base) - 1), agenttransport.NotAfterCaveat(unixNow(base) + 301), agenttransport.OperationsCaveat(agenttransport.OperationList), agenttransport.RelayCaveat(f.s.relay)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.verifier.VerifyDelegation(t.Context(), mustDelegation(t, c), agenttransport.Relay); err != nil {
		t.Fatal(err)
	}
	f.clock.at = base.Add(299 * time.Second)
	if err := f.s.store.Replay().Record(unixNow(f.clock.Now())); err != nil {
		t.Fatal(err)
	}
	before := f.source.reads
	f.s.waitTimer = func(d time.Duration) (<-chan time.Time, func()) {
		if d != 25*time.Second {
			t.Fatal(d)
		}
		// The wake brings a real entry; the final refresh then crosses expiry.
		e := f.r.seal(t, testPacket(1), unixNow(base)+3600)
		f.serve(t, "PUT", f.mail()+"/"+hex.EncodeToString(e.id[:]), e.envelope, false, 201)
		f.clock.at = base.Add(300 * time.Second)
		f.source.after = func() { f.clock.at = base.Add(302 * time.Second) }
		ticks := make(chan time.Time, 1)
		ticks <- f.clock.Now()
		return ticks, func() {}
	}
	request, w := fWaitRequest(t, f, context.Background(), "25")
	f.s.ServeHTTP(v2DeadlineWriter{w}, request)
	if f.source.reads <= before {
		t.Fatal("no final refresh", w.Code, w.Body.String(), f.clock.Now())
	}
	if w.Code != 403 || !bytes.Contains(w.Body.Bytes(), []byte("credential_scope")) || bytes.Contains(w.Body.Bytes(), []byte("envelopes")) {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestV2HintIndexCommitRefusesEarlierStalePass(t *testing.T) {
	f := newV2HTTP(t)
	base := f.clock.Now()
	path := "/v2/hints/" + f.r.agentID
	for _, tag := range []byte{0, 1} {
		raw, _ := directoryHint(t, f, tag)
		f.serve(t, "PUT", path, raw, false, 204)
	}
	verifier, err := NewV2FinalizedVerifier(f.config, f.source)
	if err != nil {
		t.Fatal(err)
	}
	f.s.verifier = verifier
	records, err := f.s.store.hintSnapshot(t.Context(), f.r.agentID, nil)
	if err != nil || len(records) != 2 {
		t.Fatal(len(records), err)
	}
	for i, record := range records {
		f.clock.at = base.Add(time.Duration(i) * 299 * time.Second)
		if _, err = f.s.verifier.VerifyHint(t.Context(), record.Raw, f.s.hintPolicy); err != nil {
			t.Fatal(err)
		}
	}
	f.clock.at = base.Add(599 * time.Second)
	f.source.err = agenttransport.ErrUnavailable
	before := f.source.reads
	f.source.after = func() {
		if f.source.reads == before+2 {
			f.clock.at = base.Add(601 * time.Second)
		}
	}
	w := f.serve(t, "GET", path, nil, false, 503)
	if f.source.reads != before+2 || !f.clock.Now().Equal(base.Add(601*time.Second)) {
		t.Fatal("reproduction did not cross the first deadline", f.source.reads-before, f.clock.Now())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("chain_unavailable")) {
		t.Fatal(w.Body.String())
	}
	if len(f.s.store.hints[f.r.agentID]) != 2 {
		t.Fatal("outage evicted hints")
	}
}
