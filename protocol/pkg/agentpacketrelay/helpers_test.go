package agentpacketrelay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// testStart is the fake clock's origin; nothing depends on the real date.
var testStart = time.Unix(1_800_000_000, 0)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *fakeClock { return &fakeClock{now: testStart} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *fakeClock) unix() uint64 { return uint64(c.Now().Unix()) }

// recipient is a test recipient Agent with an encryption key.
type recipient struct {
	agentID string
	key     agentpacketseal.PrivateKey
	public  agentpacketseal.RecipientKey
}

func newRecipient(t testing.TB) recipient {
	t.Helper()
	var digest [32]byte
	if _, err := rand.Read(digest[:]); err != nil {
		t.Fatal(err)
	}
	agentID := agentpacketseal.AgentID(digest)
	seed, err := agentpacketseal.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	key, err := agentpacketseal.NewPrivateKey(agentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return recipient{agentID: agentID, key: key,
		public: agentpacketseal.RecipientKey{AgentID: agentID, KeyID: key.KeyID, PublicKey: public}}
}

type sealed struct {
	envelope []byte
	secret   [32]byte
	id       [32]byte
	packet   []byte
}

func (r recipient) seal(t testing.TB, packet []byte, expires uint64) sealed {
	t.Helper()
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	envelope, err := agentpacketseal.Seal(r.public, secret, packet, expires)
	if err != nil {
		t.Fatal(err)
	}
	return sealed{envelope: envelope, secret: secret, id: agentpacketseal.AckHash(secret), packet: packet}
}

func testPacket(n int) []byte {
	return []byte(`{"test":"` + strings.Repeat("p", n) + `"}`)
}

func testLimits() Limits {
	return DefaultLimits(10_000, 1<<30)
}

type testRelay struct {
	t      testing.TB
	clock  *fakeClock
	store  *Store
	server *Server
	http   *httptest.Server
	client *Client
}

type relayOption func(*ServerConfig)

func newTestRelay(t testing.TB, limits Limits, opts ...relayOption) *testRelay {
	t.Helper()
	store, err := NewMemoryStore(limits)
	if err != nil {
		t.Fatal(err)
	}
	return newTestRelayWithStore(t, store, newClock(), opts...)
}

func newTestRelayWithStore(t testing.TB, store *Store, clock *fakeClock, opts ...relayOption) *testRelay {
	t.Helper()
	config := ServerConfig{Store: store, Now: clock.Now,
		DepositRate: RateLimit{PerMinute: 1 << 20, Burst: 1 << 20}, ReadRate: RateLimit{PerMinute: 1 << 20, Burst: 1 << 20}}
	for _, opt := range opts {
		opt(&config)
	}
	server, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	t.Cleanup(httpServer.Close)
	client, err := NewClient(ClientConfig{BaseURL: httpServer.URL + config.BasePath, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return &testRelay{t: t, clock: clock, store: store, server: server, http: httpServer, client: client}
}

func (r *testRelay) envelopeURL(agentID string, id [32]byte) string {
	return r.client.BaseURL() + "/v1/mailboxes/" + agentID + "/envelopes/" + hex.EncodeToString(id[:])
}

type response struct {
	status int
	header http.Header
	body   []byte
}

// do sends one raw request. contentType "" sends none.
func (r *testRelay) do(method, target, contentType string, body []byte, headers ...string) response {
	r.t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(context.Background(), method, target, reader)
	if err != nil {
		r.t.Fatal(err)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	for index := 0; index+1 < len(headers); index += 2 {
		request.Header.Add(headers[index], headers[index+1])
	}
	httpResponse, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		r.t.Fatal(err)
	}
	defer httpResponse.Body.Close()
	raw, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		r.t.Fatal(err)
	}
	return response{status: httpResponse.StatusCode, header: httpResponse.Header, body: raw}
}

func (r *testRelay) put(agentID string, id [32]byte, envelope []byte, headers ...string) response {
	r.t.Helper()
	return r.do(http.MethodPut, r.envelopeURL(agentID, id), ContentTypeEnvelope, envelope, headers...)
}

func (r *testRelay) putSealed(s sealed, headers ...string) response {
	r.t.Helper()
	header, err := agentpacketseal.ParseEnvelope(s.envelope)
	if err != nil {
		r.t.Fatal(err)
	}
	return r.put(header.RecipientAgentID, s.id, s.envelope, headers...)
}

func (r *testRelay) ackRaw(agentID string, id [32]byte, secret []byte) response {
	r.t.Helper()
	return r.do(http.MethodPost, r.envelopeURL(agentID, id)+"/ack", ContentTypeEnvelope, secret)
}

// expectStatus checks the status and, for an error, the fixed V1 error body.
func expectStatus(t testing.TB, got response, want int) {
	t.Helper()
	if got.status != want {
		t.Fatalf("status = %d, want %d (body %q)", got.status, want, got.body)
	}
	code, isError := codeForStatus[want]
	if !isError {
		return
	}
	if ct := got.header.Get("Content-Type"); ct != ContentTypeJSON {
		t.Fatalf("error content type = %q", ct)
	}
	var wire wireError
	if err := strictJSON(got.body, &wire); err != nil || wire.Schema != SchemaError || wire.Code != code {
		t.Fatalf("error body = %q (%v), want code %q", got.body, err, code)
	}
	if want == http.StatusTooManyRequests && got.header.Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
}

func decodeList(t testing.TB, got response) wireMailbox {
	t.Helper()
	expectStatus(t, got, http.StatusOK)
	var wire wireMailbox
	decoder := json.NewDecoder(bytes.NewReader(got.body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		t.Fatalf("list body %q: %v", got.body, err)
	}
	return wire
}

func mustAddr(t testing.TB, value string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

type (
	netipAddr   = netip.Addr
	netipPrefix = netip.Prefix
)

func mustPrefix(t testing.TB, value string) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		t.Fatal(err)
	}
	return prefix
}

// key returns the store key of a sealed envelope: its recipient mailbox and
// envelope ID.
func (s sealed) key(t testing.TB) entryKey {
	t.Helper()
	header, err := agentpacketseal.ParseEnvelope(s.envelope)
	if err != nil {
		t.Fatal(err)
	}
	return keyFor(t, header.RecipientAgentID, s.id)
}

func keyFor(t testing.TB, agentID string, id [32]byte) entryKey {
	t.Helper()
	digest, err := agentpacketseal.AgentDigest(agentID)
	if err != nil {
		t.Fatal(err)
	}
	return entryKey{agent: digest, id: id}
}
