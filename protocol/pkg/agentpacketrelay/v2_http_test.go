package agentpacketrelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

type v2HTClock struct{ at time.Time }

func (c *v2HTClock) Now() time.Time { return c.at }

type v2Source struct {
	state *nativev1.NativeStateV1
	err   error
	reads int
}

func (s *v2Source) ResolveState(ctx context.Context, _, _ string) (*nativev1.NativeStateV1, bool, error) {
	s.reads++
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
	wire, err := agenttransport.IssueCredential(raw, signer, holder.Public().(ed25519.PublicKey), []agenttransport.Caveat{agenttransport.NotBeforeCaveat(uint64(testStart.Unix()) - 1), agenttransport.NotAfterCaveat(uint64(testStart.Unix()) + 3600), agenttransport.OperationsCaveat(agenttransport.OperationList | agenttransport.OperationFetch | agenttransport.OperationDeposit | agenttransport.OperationPublish), agenttransport.RelayCaveat(v2TestURL)})
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
	f.s.ServeHTTP(w, f.request(t, method, path, body, auth))
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
	f.s.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	f.s.ServeHTTP(w, req.Clone(t.Context()))
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
	v1.ServeHTTP(w, httptest.NewRequest("GET", strings.Replace(f.mail(), "/v2/", "/v1/", 1), nil))
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
	if _, _, err = client.exchange(t.Context(), "PUT", f.mail()+"/policy", nil, nil, nil); err == nil {
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
				req.Body = io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), len(e.envelope))))
			}
			w := httptest.NewRecorder()
			f.s.ServeHTTP(w, req)
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
	f.s.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	other := *f.s
	other.relay = "https://127.0.0.2"
	w = httptest.NewRecorder()
	other.ServeHTTP(w, req.Clone(t.Context()))
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
	f.s.ServeHTTP(w, req.Clone(t.Context()))
	if w.Code != 503 || !strings.Contains(w.Body.String(), "proof_floor") || w.Header().Get("Retry-After") != "141" {
		t.Fatal(w.Code, w.Body.String(), w.Header())
	}
}
