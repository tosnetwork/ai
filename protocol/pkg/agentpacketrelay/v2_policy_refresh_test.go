package agentpacketrelay

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"google.golang.org/protobuf/proto"
)

func TestV2PolicyTombstoneRevertsToDefaults(t *testing.T) {
	for _, age := range []time.Duration{300 * time.Second, 601 * time.Second} {
		t.Run(age.String(), func(t *testing.T) {
			f := newV2HTTP(t)
			f.serve(t, "PUT", "/v2/mailboxes/"+f.r.agentID+"/policy", (MailboxPolicy{unixNow(f.clock.Now()), 0, 0}).Encode(), true, 204)
			f.source.state.GetAgent().Tombstoned = true
			f.clock.at = f.clock.at.Add(age)
			budget, err := f.s.policyBudget(t.Context(), f.r.agentID)
			if err != nil || budget.Count != f.s.store.limits.StrangerMaxEnvelopes || budget.Bytes != f.s.store.limits.StrangerMaxBytes {
				t.Fatal("tombstoned policy survived", budget, err)
			}
			if _, err = os.Stat(filepath.Join(f.path, policyName(f.r.agentID))); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("revoked policy remains on disk", err)
			}
		})
	}
}

func TestV2PolicyOutageUsesOnlyTheBoundedVerifierPass(t *testing.T) {
	f := newV2HTTP(t)
	f.serve(t, "PUT", "/v2/mailboxes/"+f.r.agentID+"/policy", (MailboxPolicy{unixNow(f.clock.Now()), 0, 0}).Encode(), true, 204)
	f.source.err = agenttransport.ErrUnavailable
	for _, age := range []int64{300, 599, 600, 601} {
		f.clock.at = testStart.Add(time.Duration(age) * time.Second)
		budget, err := f.s.policyBudget(t.Context(), f.r.agentID)
		if age < 600 {
			if err != nil || budget.Count != 0 {
				t.Fatal(age, budget, err)
			}
		} else if !errors.Is(err, agenttransport.ErrUnavailable) {
			t.Fatal("unavailable evidence was reused after 600 seconds", age, budget, err)
		}
	}
}

func waitPolicyEvent(t testing.TB, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		t.Fatal("policy refresh did not reach its barrier")
	}
}

func TestV2StalledPolicyRefreshDoesNotLockOtherMailboxes(t *testing.T) {
	f := newV2HTTP(t)
	f.serve(t, "PUT", "/v2/mailboxes/"+f.r.agentID+"/policy", (MailboxPolicy{unixNow(f.clock.Now()), 0, 0}).Encode(), true, 204)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	f.clock.at = f.clock.at.Add(300 * time.Second)
	f.source.after = func() { close(entered); <-release }
	go func() { defer close(done); _, _ = f.s.policyBudget(t.Context(), f.r.agentID) }()
	defer func() { close(release); waitPolicyEvent(t, done) }()
	waitPolicyEvent(t, entered)
	other := newRecipient(t)
	e := other.seal(t, testPacket(1), unixNow(f.clock.Now())+3600)
	request := f.request(t, "PUT", "/v2/mailboxes/"+other.agentID+"/envelopes/"+hex.EncodeToString(e.id[:]), e.envelope, false)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	w := httptest.NewRecorder()
	f.s.ServeHTTP(v2DeadlineWriter{w}, request.WithContext(ctx))
	if w.Code != 201 {
		t.Fatal("a stalled finalized read blocked an unrelated mailbox", w.Code, w.Body.String())
	}
}

func TestV2PolicyRefreshDiscardsAReplacedSnapshot(t *testing.T) {
	for _, change := range []string{"issued-at", "digest"} {
		t.Run(change, func(t *testing.T) {
			f := newV2HTTP(t)
			issued := unixNow(f.clock.Now())
			path := "/v2/mailboxes/" + f.r.agentID + "/policy"
			f.serve(t, "PUT", path, (MailboxPolicy{issued, 0, 0}).Encode(), true, 204)
			source2 := &v2Source{state: proto.Clone(f.source.state).(*nativev1.NativeStateV1)}
			second := *f
			verifier, err := NewV2FinalizedVerifier(f.config, source2)
			if err != nil {
				t.Fatal(err)
			}
			second.s, err = NewV2Server(V2ServerConfig{Store: f.s.store, URL: v2TestURL, Verifier: verifier, Now: f.clock.Now})
			if err != nil {
				t.Fatal(err)
			}
			if change == "issued-at" {
				issued++
			} else {
				c, err := agenttransport.DecodeCredential(f.wire)
				if err != nil {
					t.Fatal(err)
				}
				d, err := c.Delegation()
				if err != nil {
					t.Fatal(err)
				}
				key := v2TestKey("refresh-replacement")
				copy(d.TransportKey[:], key.Public().(ed25519.PublicKey))
				raw, err := d.Encode()
				if err != nil {
					t.Fatal(err)
				}
				hash := sha256.Sum256(raw)
				source2.state.GetAgent().DelegationAdmissions = []*nativev1.DelegationAdmissionV1{{Digest: "sha256:" + hex.EncodeToString(hash[:]), AdmissionEpoch: 1}}
				blocks, err := c.Blocks()
				if err != nil {
					t.Fatal(err)
				}
				second.wire, err = agenttransport.IssueCredential(raw, key, f.holder.Public().(ed25519.PublicKey), blocks[0].Caveats)
				if err != nil {
					t.Fatal(err)
				}
			}
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			f.source.state.GetAgent().Tombstoned = true
			f.clock.at = f.clock.at.Add(300 * time.Second)
			if err := f.s.store.Replay().Record(unixNow(f.clock.Now())); err != nil {
				t.Fatal(err)
			}
			f.source.after = func() { close(entered); <-release }
			var refreshErr error
			go func() { defer close(done); _, refreshErr = f.s.policyBudget(t.Context(), f.r.agentID) }()
			released := false
			defer func() {
				if !released {
					close(release)
				}
				waitPolicyEvent(t, done)
			}()
			waitPolicyEvent(t, entered)
			count, byteLimit := uint16(16), uint32(1<<20)
			if change == "digest" {
				count, byteLimit = 0, 0
			}
			second.serve(t, "PUT", path, (MailboxPolicy{issued, count, byteLimit}).Encode(), true, 204)
			close(release)
			released = true
			waitPolicyEvent(t, done)
			if !errors.Is(refreshErr, ErrStoreUnavailable) {
				t.Fatal("stale verification result was not discarded", refreshErr)
			}
			budget, err := second.s.policyBudget(t.Context(), f.r.agentID)
			if err != nil || budget.Count != int(count) {
				t.Fatal("stale refresh removed the replacement", budget, err)
			}
		})
	}
}

func TestV2PolicySnapshotIdentityIncludesIssuedAt(t *testing.T) {
	f := newV2HTTP(t)
	f.serve(t, "PUT", "/v2/mailboxes/"+f.r.agentID+"/policy", (MailboxPolicy{unixNow(f.clock.Now()), 0, 0}).Encode(), true, 204)
	f.s.store.mu.Lock()
	defer f.s.store.mu.Unlock()
	expected := f.s.store.policies[f.r.agentID]
	if !f.s.store.samePolicyLocked(f.r.agentID, &expected) {
		t.Fatal("unchanged identity refused")
	}
	expected.Policy.IssuedAt++
	if f.s.store.samePolicyLocked(f.r.agentID, &expected) {
		t.Fatal("issuance time omitted from identity")
	}
}
