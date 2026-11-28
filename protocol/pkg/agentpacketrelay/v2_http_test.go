package agentpacketrelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

type v2HTClock struct{ at time.Time }

func (c *v2HTClock) Now() time.Time { return c.at }

type v2Source struct {
	state *nativev1.NativeStateV1
	err   error
	reads int
	after func()
}

func (s *v2Source) ResolveState(ctx context.Context, _, _ string) (*nativev1.NativeStateV1, bool, error) {
	s.reads++
	if s.after != nil {
		s.after()
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, false, errors.New("missing bounded read")
	}
	return s.state, s.state != nil, s.err
}

type v2Locator string

func (l v2Locator) Locate(string, string) (string, error) { return string(l), nil }

type v2HTTPFixture struct {
	s      *V2Server
	r      recipient
	wire   []byte
	holder ed25519.PrivateKey
	clock  *v2HTClock
	source *v2Source
	config agenttransport.Config
	path   string
	nonce  byte
}

func newV2HTTP(t testing.TB) *v2HTTPFixture {
	t.Helper()
	r := newRecipient(t)
	clock := &v2HTClock{testStart}
	public := make([]byte, mldsa44.PublicKeySize)
	public[0] = 1
	id, err := mldsa44.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, Controllers: []*nativev1.ControllerV1{{KeyId: mldsa44.KeyIDText(id), Mldsa44PublicKey: public, Weight: 1, PurposeMask: 15, Recovery: true}}}
	cell, err := nativecore.PolicyCell(policy)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := agentpacketseal.AgentDigest(r.agentID)
	if err != nil {
		t.Fatal(err)
	}
	d := agenttransport.Delegation{AgentDigest: digest, Purposes: 7, NotBefore: uint64(testStart.Unix()) - 1, NotAfter: uint64(testStart.Unix()) + 86400, MaxCredentialSeconds: 86400}
	copy(d.PolicyHash[:], cell.Hash())
	signer := v2TestKey("http-transport")
	holder := v2TestKey("http-holder")
	copy(d.TransportKey[:], signer.Public().(ed25519.PublicKey))
	raw, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := agenttransport.IssueCredential(raw, signer, holder.Public().(ed25519.PublicKey), []agenttransport.Caveat{agenttransport.NotBeforeCaveat(uint64(testStart.Unix()) - 1), agenttransport.NotAfterCaveat(uint64(testStart.Unix()) + 3600), agenttransport.OperationsCaveat(agenttransport.OperationList | agenttransport.OperationFetch | agenttransport.OperationDeposit | agenttransport.OperationPublish | agenttransport.OperationRevoke), agenttransport.RelayCaveat(v2TestURL)})
	if err != nil {
		t.Fatal(err)
	}
	network := &nativev1.NetworkDomain{NetworkId: "tos:global-id:3", GenesisRootHash: "65735247a371030abe811aeac0afe357301ce90e161450d26f88b4beb5b4c366", GenesisFileHash: "c3860fe196a2a1b5e4e74a9cf9448624a353ce68a8c4c5f6413347586d688769"}
	hash := sha256.Sum256(raw)
	code := "tvm-cell-sha256:" + strings.Repeat("3", 64)
	source := &v2Source{state: &nativev1.NativeStateV1{Network: network, TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("4", 64), Reference: &nativev1.ChainReference{FinalizedCheckpoint: 10, ContractCodeHash: code, Account: "0:test", TransactionHash: "sha256:" + strings.Repeat("5", 64)}, State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: r.agentID, Policy: policy, DelegationDigests: []string{"sha256:" + hex.EncodeToString(hash[:])}}}}}
	config := agenttransport.Config{Mode: agenttransport.TestNetworkLegacyEpochZero, Network: network, ChainPolicy: agenttransport.ChainPolicy{RegistryCodeHashes: []string{code}, Locator: v2Locator("0:test")}, Clock: clock}
	verifier, err := NewV2FinalizedVerifier(config, source)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(v2Temp(t), "v2")
	store := v2Open(t, path, DefaultV2Limits(1024, 64<<20), testStart)
	server, err := NewV2Server(V2ServerConfig{Store: store, URL: v2TestURL, Verifier: verifier, Now: clock.Now, DepositRate: RateLimit{PerMinute: 100000, Burst: 100000}, ReadRate: RateLimit{PerMinute: 100000, Burst: 100000}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v2Close(t, server.store) })
	return &v2HTTPFixture{s: server, r: r, wire: wire, holder: holder, clock: clock, source: source, config: config, path: path}
}
func (f *v2HTTPFixture) request(t testing.TB, method, path string, body []byte, auth bool) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	if method == "PUT" || method == "POST" {
		req.Header.Set("Content-Type", ContentTypeEnvelope)
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	if auth {
		c, err := agenttransport.DecodeCredential(f.wire)
		if err != nil {
			t.Fatal(err)
		}
		f.nonce++
		proof, err := agenttransport.SignRequest(c, f.holder, agenttransport.ProofRequest{RelayURL: f.s.relay, Method: method, Path: path, Body: body}, unixNow(f.clock.Now()), [32]byte{f.nonce})
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("TOS-Relay-Credential", agenttransport.EncodeCredentialHeader(f.wire))
		req.Header.Set("TOS-Relay-Proof", proof.Header())
	}
	return req
}
func (f *v2HTTPFixture) serve(t testing.TB, method, path string, body []byte, auth bool, want int) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	f.s.ServeHTTP(v2DeadlineWriter{w}, f.request(t, method, path, body, auth))
	if w.Code != want {
		t.Fatalf("%s %s: %d %s; want %d", method, path, w.Code, w.Body.String(), want)
	}
	return w
}
func (f *v2HTTPFixture) mail() string { return "/v2/mailboxes/" + f.r.agentID + "/envelopes" }
func TestV2HTTPClosedReadsAndNoV1Route(t *testing.T) {
	f := newV2HTTP(t)
	e := f.r.seal(t, testPacket(1), unixNow(f.clock.Now())+3600)
	path := f.mail() + "/" + hex.EncodeToString(e.id[:])
	f.serve(t, "PUT", path, e.envelope, false, 201)
	f.serve(t, "GET", f.mail(), nil, false, 401)
	f.serve(t, "GET", path, nil, false, 401)
	f.serve(t, "GET", strings.Replace(f.mail(), "/v2/", "/v1/", 1), nil, false, 404)
	w := f.serve(t, "GET", f.mail(), nil, true, 200)
	if !strings.Contains(w.Body.String(), `"lane":"stranger"`) {
		t.Fatal("missing lane")
	}
	f.serve(t, "GET", path, nil, true, 200)
	req := f.request(t, "GET", f.mail(), nil, true)
	w = httptest.NewRecorder()
	f.s.ServeHTTP(v2DeadlineWriter{w}, req)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	f.s.ServeHTTP(v2DeadlineWriter{w}, req.Clone(t.Context()))
	if w.Code != 403 {
		t.Fatal("same proof replayed", w.Code)
	}
	other := newRecipient(t)
	f.serve(t, "GET", "/v2/mailboxes/"+other.agentID+"/envelopes", nil, true, 403)
	// The existing anonymous server sees its own empty store, never V2 data.
	v1store, err := NewMemoryStore(DefaultLimits(1024, 64<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer v1store.Close()
	v1, err := NewServer(ServerConfig{Store: v1store})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	v1.ServeHTTP(v2DeadlineWriter{w}, httptest.NewRequest("GET", strings.Replace(f.mail(), "/v2/", "/v1/", 1), nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), hex.EncodeToString(e.id[:])) {
		t.Fatal("V1 reached V2")
	}
}
func TestV2HTTPFinalizedCacheBoundAndStrangersContinue(t *testing.T) {
	f := newV2HTTP(t)
	f.serve(t, "GET", f.mail(), nil, true, 200)
	f.source.err = agenttransport.ErrUnavailable
	f.clock.at = f.clock.at.Add(300 * time.Second)
	if err := f.s.store.Replay().Record(unixNow(f.clock.Now())); err != nil {
		t.Fatal(err)
	}
	f.serve(t, "GET", f.mail(), nil, true, 200)
	f.clock.at = f.clock.at.Add(299 * time.Second)
	if err := f.s.store.Replay().Record(unixNow(f.clock.Now())); err != nil {
		t.Fatal(err)
	}
	f.serve(t, "GET", f.mail(), nil, true, 200)
	f.clock.at = f.clock.at.Add(time.Second)
	if err := f.s.store.Replay().Record(unixNow(f.clock.Now())); err != nil {
		t.Fatal(err)
	}
	w := f.serve(t, "GET", f.mail(), nil, true, 503)
	if !strings.Contains(w.Body.String(), "chain_unavailable") {
		t.Fatal(w.Body.String())
	}
	// Fetch has no listing recheck: the middleware must refuse it before
	// revealing even whether an envelope exists.
	f.serve(t, "GET", f.mail()+"/"+strings.Repeat("1", 64), nil, true, 503)
	e := f.r.seal(t, testPacket(1), unixNow(f.clock.Now())+3600)
	f.serve(t, "PUT", f.mail()+"/"+hex.EncodeToString(e.id[:]), e.envelope, false, 201)
}
func TestV2MaximalListingAndOversizeBug(t *testing.T) {
	f := newV2HTTP(t)
	entries := make([]v2WireEntry, 256)
	for i := range entries {
		lane := "contact"
		if i < 64 {
			lane = "stranger"
		}
		entries[i] = v2WireEntry{strings.Repeat("f", 64), "hpke:" + strings.Repeat("f", 64), MaxEnvelopeBytes, math.MaxUint64, math.MaxUint64, lane}
	}
	listing := v2WireMailbox{SchemaV2Mailbox, f.r.agentID, entries}
	raw, err := json.Marshal(listing)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > MaxV2ListingBytes || len(raw) <= MaxResponseBytes {
		t.Fatalf("maximal listing %d violates intended bounds", len(raw))
	}
	w := httptest.NewRecorder()
	v2WriteJSON(w, 200, listing, MaxV2ListingBytes)
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), raw) {
		t.Fatal("listing lost entries")
	}
	w = httptest.NewRecorder()
	v2WriteJSON(w, 200, listing, MaxResponseBytes)
	if w.Code != 500 {
		t.Fatal("other response bound was raised")
	}
	w = httptest.NewRecorder()
	listing.Envelopes = append(listing.Envelopes, make([]v2WireEntry, 1000)...)
	v2WriteJSON(w, 200, listing, MaxV2ListingBytes)
	if w.Code != 500 || strings.Contains(w.Body.String(), "envelopes") {
		t.Fatal("oversize listing was truncated or served")
	}
	t.Logf("maximal legal listing: %d bytes", len(raw))
}
func TestV2HTTPPolicyDurabilityTimestampAndRevocation(t *testing.T) {
	f := newV2HTTP(t)
	path := "/v2/mailboxes/" + f.r.agentID + "/policy"
	now := unixNow(f.clock.Now())
	for _, stamp := range []uint64{math.MaxUint64, now + 301} {
		f.serve(t, "PUT", path, (MailboxPolicy{stamp, 0, 0}).Encode(), true, 400)
	}
	f.serve(t, "PUT", path, (MailboxPolicy{now + 300, 0, 0}).Encode(), true, 204)
	e := f.r.seal(t, testPacket(1), now+3600)
	w := f.serve(t, "PUT", f.mail()+"/"+hex.EncodeToString(e.id[:]), e.envelope, false, 507)
	if !strings.Contains(w.Body.String(), `"lane":"stranger"`) {
		t.Fatal(w.Body.String())
	}
	v2Close(t, f.s.store)
	f.s.store = v2Open(t, f.path, DefaultV2Limits(1024, 64<<20), f.clock.Now())
	budget, err := f.s.policyBudget(t.Context(), f.r.agentID)
	if err != nil || budget.Count != 0 {
		t.Fatal("policy lost on restart", budget, err)
	}
	f.source.state.GetAgent().DelegationDigests = nil
	f.clock.at = f.clock.at.Add(300 * time.Second)
	budget, err = f.s.policyBudget(t.Context(), f.r.agentID)
	if err != nil || budget.Count != 32 {
		t.Fatal("revoked policy remains", budget, err)
	}
}

type v2RoundTrip func(*http.Request) (*http.Response, error)

func (f v2RoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestV2ClientAcceptsOnlyListingExceptionAndNoFallback(t *testing.T) {
	f := newV2HTTP(t)
	entries := make([]v2WireEntry, 256)
	for i := range entries {
		lane := "contact"
		if i < 64 {
			lane = "stranger"
		}
		hash := sha256.Sum256([]byte{byte(i)})
		entries[i] = v2WireEntry{hex.EncodeToString(hash[:]), "hpke:" + strings.Repeat("f", 64), 65536, math.MaxUint64 - 1, math.MaxUint64, lane}
	}
	raw, err := json.Marshal(v2WireMailbox{SchemaV2Mailbox, f.r.agentID, entries})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= MaxResponseBytes || len(raw) > MaxV2ListingBytes {
		t.Fatal("listing did not cross the original limit", len(raw))
	}
	calls := 0
	transport := v2RoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if !strings.HasPrefix(r.URL.Path, "/v2/") {
			t.Fatal("fallback path", r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{ContentTypeJSON}}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})
	client, err := NewV2Client(v2TestURL, transport, f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.List(t.Context(), f.r.agentID, f.wire, f.holder)
	if err != nil || len(got) != 256 || calls != 1 {
		t.Fatal("maximal legal listing refused", len(got), calls, err)
	}
	// Every other response retains its smaller bound; no V1 schema is accepted.
	if _, _, err = client.exchange(t.Context(), "PUT", "/v2/mailboxes/"+f.r.agentID+"/policy", nil, nil, nil); err == nil {
		t.Fatal("listing bound leaked into policy")
	}
	raw = bytes.Replace(raw, []byte(SchemaV2Mailbox), []byte(SchemaMailbox), 1)
	before := calls
	if _, err = client.List(t.Context(), f.r.agentID, f.wire, f.holder); err == nil || calls != before+1 {
		t.Fatal("V1 response accepted or retried", err)
	}
	raw = bytes.Repeat([]byte("x"), MaxV2ListingBytes+1)
	if _, err = client.List(t.Context(), f.r.agentID, f.wire, f.holder); err == nil {
		t.Fatal("oversize response accepted")
	}
}
func TestV2HTTPInvalidCredentialsNeverBecomeStrangers(t *testing.T) {
	f := newV2HTTP(t)
	e := f.r.seal(t, testPacket(1), unixNow(f.clock.Now())+3600)
	path := f.mail() + "/" + hex.EncodeToString(e.id[:])
	for _, kind := range []string{"bad", "missing-proof", "duplicate", "bad-body"} {
		t.Run(kind, func(t *testing.T) {
			req := f.request(t, "PUT", path, e.envelope, true)
			switch kind {
			case "bad":
				req.Header.Set("TOS-Relay-Credential", "bad")
			case "missing-proof":
				req.Header.Del("TOS-Relay-Proof")
			case "duplicate":
				req.Header.Add("TOS-Relay-Proof", req.Header.Get("TOS-Relay-Proof"))
			case "bad-body":
				tampered := bytes.Clone(e.envelope)
				tampered[len(tampered)-1] ^= 1
				req.Body = io.NopCloser(bytes.NewReader(tampered))
			}
			w := httptest.NewRecorder()
			f.s.ServeHTTP(v2DeadlineWriter{w}, req)
			if w.Code != 403 || f.s.store.Usage().StrangerEntries != 0 {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}
func TestV2HTTPRestartSecondRelayAndClockRollback(t *testing.T) {
	f := newV2HTTP(t)
	req := f.request(t, "GET", f.mail(), nil, true)
	w := httptest.NewRecorder()
	f.s.ServeHTTP(v2DeadlineWriter{w}, req)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	other, err := NewV2Server(V2ServerConfig{Store: f.s.store, URL: "https://127.0.0.2", Verifier: f.s.verifier, Now: f.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	other.ServeHTTP(v2DeadlineWriter{w}, req.Clone(t.Context()))
	if w.Code != 403 {
		t.Fatal("second relay accepted same proof", w.Code)
	}
	f.clock.at = f.clock.at.Add(-time.Minute)
	if err := f.s.store.Replay().Record(unixNow(f.clock.Now())); err != nil {
		t.Fatal(err)
	}
	v2Close(t, f.s.store)
	f.s.store = v2Open(t, f.path, DefaultV2Limits(1024, 64<<20), f.clock.Now())
	f.clock.at = testStart
	w = httptest.NewRecorder()
	f.s.ServeHTTP(v2DeadlineWriter{w}, req.Clone(t.Context()))
	if w.Code != 503 || !strings.Contains(w.Body.String(), "proof_floor") || w.Header().Get("Retry-After") != "141" {
		t.Fatal(w.Code, w.Body.String(), w.Header())
	}
}

func TestV2HTTPPolicyReadFailureDoesNotOpenClosedMailbox(t *testing.T) {
	for _, failure := range []error{agenttransport.ErrUnavailable, errors.New("integrity failure")} {
		f := newV2HTTP(t)
		f.serve(t, "PUT", "/v2/mailboxes/"+f.r.agentID+"/policy", (MailboxPolicy{unixNow(f.clock.Now()), 0, 0}).Encode(), true, 204)
		f.source.err = failure
		f.clock.at = f.clock.at.Add(601 * time.Second)
		budget, err := f.s.policyBudget(t.Context(), f.r.agentID)
		if err != nil || budget.Count != 0 {
			t.Fatal("read failure lifted a closed policy", budget, err)
		}
	}
}
func TestV2HTTPReplayFullAndHighWaterStatuses(t *testing.T) {
	f := newV2HTTP(t)
	table, err := agenttransport.NewReplayTable(agenttransport.ReplayConfig{Entries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err = table.MarkRecorded(unixNow(f.clock.Now()) + 140); err != nil {
		t.Fatal(err)
	}
	f.s.store.replay.table = table
	f.serve(t, "GET", f.mail(), nil, true, 200)
	w := f.serve(t, "GET", f.mail(), nil, true, 503)
	if !strings.Contains(w.Body.String(), "replay_table_full") {
		t.Fatal(w.Body.String())
	}
	f.clock.at = f.clock.at.Add(140 * time.Second)
	w = f.serve(t, "GET", f.mail(), nil, true, 503)
	if !strings.Contains(w.Body.String(), "replay_table_full") {
		t.Fatal("proof beyond durable mark admitted", w.Body.String())
	}
}

func TestV2HTTPPolicyBoundAndUncertainWrite(t *testing.T) {
	t.Run("bound", func(t *testing.T) {
		f := newV2HTTP(t)
		for i := range MaxV2Policies {
			f.s.store.policies[fmt.Sprint(i)] = v2PolicyRecord{}
		}
		f.serve(t, "PUT", "/v2/mailboxes/"+f.r.agentID+"/policy", (MailboxPolicy{unixNow(f.clock.Now()), 0, 0}).Encode(), true, 503)
	})
	t.Run("uncertain-write", func(t *testing.T) {
		f := newV2HTTP(t)
		f.s.store.disk.beforeSync = func(name string) error {
			if strings.HasPrefix(name, "controls/") {
				return errors.New("injected directory-sync failure")
			}
			return nil
		}
		f.serve(t, "PUT", "/v2/mailboxes/"+f.r.agentID+"/policy", (MailboxPolicy{unixNow(f.clock.Now()), 0, 0}).Encode(), true, 503)
		if !f.s.store.poisoned {
			t.Fatal("uncertain write left store usable")
		}
		v2Close(t, f.s.store)
		f.s.store = v2Open(t, f.path, DefaultV2Limits(1024, 64<<20), f.clock.Now())
		budget, err := f.s.policyBudget(t.Context(), f.r.agentID)
		if err != nil || budget.Count != 0 {
			t.Fatal("disk-authoritative policy lost after uncertain write", budget, err)
		}
	})
}
func TestV2PolicyCodecStrictAndLowerOnly(t *testing.T) {
	p := MailboxPolicy{1800000000, 32, 2 << 20}
	raw := p.Encode()
	decoded, err := DecodeMailboxPolicy(raw)
	if err != nil || decoded != p {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), 0), raw[:len(raw)-1], bytes.Repeat([]byte{0}, len(raw))} {
		if _, err := DecodeMailboxPolicy(bad); err == nil {
			t.Fatal("malformed policy accepted")
		}
	}
	limits := DefaultV2Limits(1024, 64<<20)
	for _, bad := range []MailboxPolicy{{1800000301, 0, 0}, {math.MaxUint64, 0, 0}, {1800000000, 33, 0}, {1800000000, 0, (2 << 20) + 1}} {
		if bad.valid(limits, 1800000000) {
			t.Fatal("policy widens limits", bad)
		}
	}
}

func TestV2RotatedOwnerCanReplaceFuturePolicyWithEarlierTimestamp(t *testing.T) {
	f := newV2HTTP(t)
	now := unixNow(f.clock.Now())
	path := "/v2/mailboxes/" + f.r.agentID + "/policy"
	f.serve(t, "PUT", path, (MailboxPolicy{now + 300, 0, 0}).Encode(), true, 204)
	c, err := agenttransport.DecodeCredential(f.wire)
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.Delegation()
	if err != nil {
		t.Fatal(err)
	}
	key := v2TestKey("rotated-http-transport")
	copy(d.TransportKey[:], key.Public().(ed25519.PublicKey))
	raw, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	f.source.state.GetAgent().DelegationDigests = []string{"sha256:" + hex.EncodeToString(hash[:])}
	blocks, err := c.Blocks()
	if err != nil {
		t.Fatal(err)
	}
	f.wire, err = agenttransport.IssueCredential(raw, key, f.holder.Public().(ed25519.PublicKey), blocks[0].Caveats)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.at = f.clock.at.Add(300 * time.Second)
	if err = f.s.store.Replay().Record(unixNow(f.clock.Now())); err != nil {
		t.Fatal(err)
	}
	f.serve(t, "PUT", path, (MailboxPolicy{now + 299, 16, 1 << 20}).Encode(), true, 204)
	budget, err := f.s.policyBudget(t.Context(), f.r.agentID)
	if err != nil || budget.Count != 16 {
		t.Fatal("revoked timestamp blocked the new owner", budget, err)
	}
}

func TestV2TLSClientRoundTripNeverUsesV1(t *testing.T) {
	f := newV2HTTP(t)
	server := httptest.NewTLSServer(f.s)
	defer server.Close()
	f.s.relay = server.URL
	c, err := agenttransport.DecodeCredential(f.wire)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.DelegationBytes()
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := c.Blocks()
	if err != nil {
		t.Fatal(err)
	}
	caveats := blocks[0].Caveats
	for i := range caveats {
		if caveats[i].Type == agenttransport.CaveatRelay {
			caveats[i] = agenttransport.RelayCaveat(server.URL)
		}
	}
	f.wire, err = agenttransport.IssueCredential(raw, v2TestKey("http-transport"), f.holder.Public().(ed25519.PublicKey), caveats)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewV2Client(server.URL, server.Client().Transport, f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	e := f.r.seal(t, testPacket(1), unixNow(f.clock.Now())+3600)
	if err = client.Deposit(t.Context(), e.envelope, nil, nil); err != nil {
		t.Fatal(err)
	}
	entries, err := client.List(t.Context(), f.r.agentID, f.wire, f.holder)
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	got, err := client.Fetch(t.Context(), f.r.agentID, e.id, f.wire, f.holder)
	if err != nil || !bytes.Equal(got, e.envelope) {
		t.Fatal("fetch mismatch", err)
	}
	if err = client.Acknowledge(t.Context(), f.r.agentID, e.secret); err != nil {
		t.Fatal(err)
	}
	entries, err = client.List(t.Context(), f.r.agentID, f.wire, f.holder)
	if err != nil || len(entries) != 0 {
		t.Fatal("ACK failed", entries, err)
	}
}

func TestV2HTTPLaneFloodLeavesContactReservation(t *testing.T) {
	f := newV2HTTP(t)
	now := unixNow(f.clock.Now())
	for i := range 64 {
		e := f.r.seal(t, testPacket(1), now+3600)
		path := f.mail() + "/" + hex.EncodeToString(e.id[:])
		req := f.request(t, "PUT", path, e.envelope, false)
		req.RemoteAddr = fmt.Sprintf("127.0.0.%d:1234", i+1)
		w := httptest.NewRecorder()
		f.s.ServeHTTP(v2DeadlineWriter{w}, req)
		want := 201
		if i >= 32 {
			want = 507
		}
		if w.Code != want {
			t.Fatal("mailbox flood", i, w.Code, w.Body.String())
		}
		if want == 507 && !strings.Contains(w.Body.String(), `"lane":"stranger"`) {
			t.Fatal(w.Body.String())
		}
	}
	e := f.r.seal(t, testPacket(1), now+3600)
	f.serve(t, "PUT", f.mail()+"/"+hex.EncodeToString(e.id[:]), e.envelope, true, 201)
	template := f.r.seal(t, testPacket(1), now+3600)
	original, _ := agentpacketseal.AgentDigest(f.r.agentID)
	offset := bytes.Index(template.envelope, original[:])
	if offset < 0 {
		t.Fatal("missing clear Agent header")
	}
	for i := range 10000 {
		body := bytes.Clone(template.envelope)
		agent := sha256.Sum256([]byte(fmt.Sprint("v2-http-flood-", i)))
		copy(body[offset:offset+32], agent[:])
		path := "/v2/mailboxes/agent_" + hex.EncodeToString(agent[:]) + "/envelopes/" + hex.EncodeToString(template.id[:])
		req := f.request(t, "PUT", path, body, false)
		req.RemoteAddr = fmt.Sprintf("127.%d.%d.%d:1234", 1+(i>>16), (i>>8)&255, i&255)
		w := httptest.NewRecorder()
		f.s.ServeHTTP(v2DeadlineWriter{w}, req)
		want := 201
		if i >= 224 {
			want = 507
		}
		if w.Code != want {
			t.Fatal("global flood", i, w.Code, w.Body.String())
		}
	}
	if f.s.store.Usage().StrangerEntries != 256 {
		t.Fatal(f.s.store.Usage())
	}
	e = f.r.seal(t, testPacket(1), now+3600)
	f.serve(t, "PUT", f.mail()+"/"+hex.EncodeToString(e.id[:]), e.envelope, true, 201)
}
func TestV2HTTPTombstoneFloodSurvivesRestart(t *testing.T) {
	f := newV2HTTP(t)
	now := unixNow(f.clock.Now())
	for i := range 256 {
		e := f.r.seal(t, testPacket(1), now+3600)
		path := f.mail() + "/" + hex.EncodeToString(e.id[:])
		req := f.request(t, "PUT", path, e.envelope, false)
		req.RemoteAddr = fmt.Sprintf("127.0.0.%d:1234", 1+i/64)
		w := httptest.NewRecorder()
		f.s.ServeHTTP(v2DeadlineWriter{w}, req)
		if w.Code != 201 {
			t.Fatal(i, w.Code, w.Body.String())
		}
		f.serve(t, "POST", path+"/ack", e.secret[:], false, 204)
	}
	if f.s.store.Usage().StrangerEntries != 256 || f.s.store.Usage().StrangerBytes != 0 {
		t.Fatal(f.s.store.Usage())
	}
	for round := range 2 {
		e := f.r.seal(t, testPacket(1), unixNow(f.clock.Now())+3600)
		path := f.mail() + "/" + hex.EncodeToString(e.id[:])
		req := f.request(t, "PUT", path, e.envelope, false)
		req.RemoteAddr = "127.0.0.99:1234"
		w := httptest.NewRecorder()
		f.s.ServeHTTP(v2DeadlineWriter{w}, req)
		if w.Code != 507 {
			t.Fatal("tombstones freed stranger share", w.Code)
		}
		f.serve(t, "PUT", path, e.envelope, true, 201)
		if round == 0 {
			v2Close(t, f.s.store)
			f.clock.at = f.clock.at.Add(141 * time.Second)
			f.s.store = v2Open(t, f.path, DefaultV2Limits(1024, 64<<20), f.clock.Now())
		}
	}
}

func TestV2HTTPRechecksCredentialAfterFinalizedRead(t *testing.T) {
	f := newV2HTTP(t)
	c, err := agenttransport.DecodeCredential(f.wire)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.DelegationBytes()
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := c.Blocks()
	if err != nil {
		t.Fatal(err)
	}
	caveats := blocks[0].Caveats
	for i := range caveats {
		if caveats[i].Type == agenttransport.CaveatNotAfter {
			caveats[i] = agenttransport.NotAfterCaveat(unixNow(f.clock.Now()) + 5)
		}
	}
	f.wire, err = agenttransport.IssueCredential(raw, v2TestKey("http-transport"), f.holder.Public().(ed25519.PublicKey), caveats)
	if err != nil {
		t.Fatal(err)
	}
	f.source.after = func() { f.clock.at = f.clock.at.Add(10 * time.Second) }
	f.serve(t, "GET", f.mail()+"/"+strings.Repeat("1", 64), nil, true, 403)
}

func TestV2HTTPProofBindsConfiguredRelayWithoutRelayCaveat(t *testing.T) {
	f := newV2HTTP(t)
	c, err := agenttransport.DecodeCredential(f.wire)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.DelegationBytes()
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := c.Blocks()
	if err != nil {
		t.Fatal(err)
	}
	var caveats []agenttransport.Caveat
	for _, caveat := range blocks[0].Caveats {
		if caveat.Type != agenttransport.CaveatRelay {
			caveats = append(caveats, caveat)
		}
	}
	f.wire, err = agenttransport.IssueCredential(raw, v2TestKey("http-transport"), f.holder.Public().(ed25519.PublicKey), caveats)
	if err != nil {
		t.Fatal(err)
	}
	req := f.request(t, "GET", f.mail(), nil, true)
	store := v2Open(t, filepath.Join(v2Temp(t), "second"), DefaultV2Limits(1024, 64<<20), testStart)
	defer v2Close(t, store)
	second, err := NewV2Server(V2ServerConfig{Store: store, URL: "https://127.0.0.2", Verifier: f.s.verifier, Now: f.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	second.ServeHTTP(v2DeadlineWriter{w}, req)
	if w.Code != 403 {
		t.Fatal("proof moved between relays", w.Code, w.Body.String())
	}
}

type v2CountingBody struct{ reads int }

func (b *v2CountingBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *v2CountingBody) Close() error             { return nil }
func TestV2HTTPRejectsOversizeBeforeReadingAndBoundsSlots(t *testing.T) {
	f := newV2HTTP(t)
	e := f.r.seal(t, testPacket(1), unixNow(f.clock.Now())+3600)
	req := f.request(t, "PUT", f.mail()+"/"+hex.EncodeToString(e.id[:]), e.envelope, false)
	body := &v2CountingBody{}
	req.Body = body
	req.ContentLength = MaxEnvelopeBytes + 1
	req.Header.Set("Content-Length", strconv.Itoa(MaxEnvelopeBytes+1))
	w := httptest.NewRecorder()
	f.s.ServeHTTP(v2DeadlineWriter{w}, req)
	if w.Code != 413 || body.reads != 0 {
		t.Fatal("oversize read started", w.Code, body.reads)
	}
	var held []netip.Addr
	defer func() {
		for _, client := range held {
			f.s.release(client)
		}
	}()
	for i := range DefaultMaxConcurrentDeposits {
		client := v2Loopback(1 + i/4)
		if status := f.s.take(client); status != 0 {
			t.Fatal("premature slot refusal", i, status)
		}
		held = append(held, client)
	}
	if status := f.s.take(v2Loopback(1)); status != 429 {
		t.Fatal("per-client bound", status)
	}
	if status := f.s.take(v2Loopback(100)); status != 503 {
		t.Fatal("global bound", status)
	}
}
func TestV2ExpiredPoliciesAreReclaimedWithoutAVisitor(t *testing.T) {
	f := newV2HTTP(t)
	f.serve(t, "PUT", "/v2/mailboxes/"+f.r.agentID+"/policy", (MailboxPolicy{unixNow(f.clock.Now()), 0, 0}).Encode(), true, 204)
	f.clock.at = f.clock.at.Add(86400 * time.Second)
	if err := f.s.store.Sweep(f.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if len(f.s.store.policies) != 0 {
		t.Fatal("expired policy consumes a permanent record")
	}
	entries, err := os.ReadDir(filepath.Join(f.path, "controls"))
	if err != nil || len(entries) != 0 {
		t.Fatal("expired policy stays on disk", err)
	}
}

func TestV2ProductionAndUnknownNetworksNeverEnable(t *testing.T) {
	f := newV2HTTP(t)
	c := f.config
	c.Mode = agenttransport.Production
	if _, err := NewV2FinalizedVerifier(c, f.source); err == nil {
		t.Fatal("production enabled without registry epochs")
	}
	for _, mode := range []agenttransport.NetworkMode{agenttransport.Production, agenttransport.TestNetworkLegacyEpochZero, agenttransport.TestNetworkEpochAware} {
		c := f.config
		c.Mode = mode
		c.Network = &nativev1.NetworkDomain{NetworkId: "tos:global-id:1", GenesisRootHash: f.config.Network.GenesisRootHash, GenesisFileHash: f.config.Network.GenesisFileHash}
		if _, err := NewV2FinalizedVerifier(c, f.source); err == nil {
			t.Fatal("unapproved network enabled", mode)
		}
	}
}

func TestV2ClientRejectsCompressedResponses(t *testing.T) {
	f := newV2HTTP(t)
	raw, err := json.Marshal(v2WireMailbox{SchemaV2Mailbox, f.r.agentID, []v2WireEntry{}})
	if err != nil {
		t.Fatal(err)
	}
	transport := v2RoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("request permits transparent decompression")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{ContentTypeJSON}, "Content-Encoding": []string{"gzip"}}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})
	client, err := NewV2Client(v2TestURL, transport, f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.List(t.Context(), f.r.agentID, f.wire, f.holder); err == nil {
		t.Fatal("coded response bypassed raw bounds")
	}
}
func TestV2HTTPRefusesUninterpretedBodyHeaders(t *testing.T) {
	f := newV2HTTP(t)
	for _, kind := range []string{"type", "duplicate", "encoding"} {
		t.Run(kind, func(t *testing.T) {
			e := f.r.seal(t, testPacket(1), unixNow(f.clock.Now())+3600)
			req := f.request(t, "PUT", f.mail()+"/"+hex.EncodeToString(e.id[:]), e.envelope, false)
			switch kind {
			case "type":
				req.Header.Set("Content-Type", ContentTypeJSON)
			case "duplicate":
				req.Header.Add("Content-Type", ContentTypeEnvelope)
			case "encoding":
				req.Header.Set("Content-Encoding", "gzip")
			}
			w := httptest.NewRecorder()
			f.s.ServeHTTP(v2DeadlineWriter{w}, req)
			if w.Code != 400 || f.s.store.Usage().StrangerEntries != 0 {
				t.Fatal(kind, w.Code, w.Body.String())
			}
		})
	}
}

func TestV2StoreFailureIsNotAChainOutage(t *testing.T) {
	f := newV2HTTP(t)
	f.s.store.poisoned = true
	e := f.r.seal(t, testPacket(1), unixNow(f.clock.Now())+3600)
	w := f.serve(t, "PUT", f.mail()+"/"+hex.EncodeToString(e.id[:]), e.envelope, false, 503)
	if !strings.Contains(w.Body.String(), `"code":"unavailable"`) {
		t.Fatal("store failure classified as chain outage", w.Body.String())
	}
}

// In-memory requests have no socket deadline. Explicitly model support in the
// fixture; a real unsupported writer must fail before reading any body.
type v2DeadlineWriter struct{ *httptest.ResponseRecorder }

func (v2DeadlineWriter) SetReadDeadline(time.Time) error { return nil }
func TestV2HTTPRefusesBodiesWithoutAReadDeadline(t *testing.T) {
	f := newV2HTTP(t)
	e := f.r.seal(t, testPacket(1), unixNow(f.clock.Now())+3600)
	req := f.request(t, "PUT", f.mail()+"/"+hex.EncodeToString(e.id[:]), e.envelope, false)
	body := &v2CountingBody{}
	req.Body = body
	w := httptest.NewRecorder()
	f.s.ServeHTTP(w, req)
	if w.Code != 503 || body.reads != 0 {
		t.Fatal("unsupported read deadline accepted", w.Code, body.reads)
	}
}

type v2RPCSource struct {
	chain   *toschain.Adapter
	source  *v2Source
	network *nativev1.NetworkDomain
}

func (s v2RPCSource) ResolveState(ctx context.Context, id, hash string) (*nativev1.NativeStateV1, bool, error) {
	if err := s.chain.CheckNetworkGenesis(ctx, "sha256:"+s.network.GenesisRootHash, "sha256:"+s.network.GenesisFileHash); err != nil {
		return nil, false, err
	}
	return s.source.ResolveState(ctx, id, hash)
}
func TestV2HTTPStoppedEndpointsBecomeUnavailableAt600Seconds(t *testing.T) {
	f := newV2HTTP(t)
	root, err := hex.DecodeString(f.config.Network.GenesisRootHash)
	if err != nil {
		t.Fatal(err)
	}
	file, err := hex.DecodeString(f.config.Network.GenesisFileHash)
	if err != nil {
		t.Fatal(err)
	}
	var servers []*httptest.Server
	var endpoints []string
	for range 3 {
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var request struct {
				ID json.RawMessage `json:"id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				return
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": map[string]any{"@type": "blocks.masterchainInfo", "init": map[string]any{"root_hash": base64.StdEncoding.EncodeToString(root), "file_hash": base64.StdEncoding.EncodeToString(file)}}}); err != nil {
				t.Error(err)
			}
		}))
		servers = append(servers, peer)
		endpoints = append(endpoints, peer.URL)
		t.Cleanup(peer.Close)
	}
	adapter, err := toschain.New(toschain.Config{Network: f.config.Network.NetworkId, Endpoints: endpoints, Quorum: 2, Now: f.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewV2FinalizedVerifier(f.config, v2RPCSource{adapter, f.source, f.config.Network})
	if err != nil {
		t.Fatal(err)
	}
	f.s.verifier = verifier
	f.serve(t, "GET", f.mail(), nil, true, 200)
	for _, peer := range servers {
		peer.Close()
	}
	f.clock.at = f.clock.at.Add(300 * time.Second)
	if err = f.s.store.Replay().Record(unixNow(f.clock.Now())); err != nil {
		t.Fatal(err)
	}
	f.serve(t, "GET", f.mail(), nil, true, 200)
	f.clock.at = f.clock.at.Add(300 * time.Second)
	if err = f.s.store.Replay().Record(unixNow(f.clock.Now())); err != nil {
		t.Fatal(err)
	}
	w := f.serve(t, "GET", f.mail(), nil, true, 503)
	if !strings.Contains(w.Body.String(), "chain_unavailable") {
		t.Fatal(w.Body.String())
	}
	e := f.r.seal(t, testPacket(1), unixNow(f.clock.Now())+3600)
	f.serve(t, "PUT", f.mail()+"/"+hex.EncodeToString(e.id[:]), e.envelope, false, 201)
}

func TestV2HTTPMethodRefusalsNameTheSupportedMethod(t *testing.T) {
	f := newV2HTTP(t)
	e := f.r.seal(t, testPacket(1), unixNow(f.clock.Now())+3600)
	path := f.mail() + "/" + hex.EncodeToString(e.id[:])
	for route, allow := range map[string]string{f.mail(): "GET", path: "GET, PUT", path + "/ack": "POST", "/v2/mailboxes/" + f.r.agentID + "/policy": "PUT"} {
		w := f.serve(t, "DELETE", route, nil, false, 405)
		if w.Header().Get("Allow") != allow {
			t.Fatal(route, w.Header())
		}
	}
}
