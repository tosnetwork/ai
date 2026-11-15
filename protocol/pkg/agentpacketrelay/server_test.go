package agentpacketrelay

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

const day = uint64(86_400)

// TestRoundTrip seals to a recipient key, deposits through the client, lists,
// downloads, opens as the recipient, acknowledges, and checks the tombstone.
func TestRoundTrip(t *testing.T) {
	relay := newTestRelay(t, testLimits())
	alice := newRecipient(t)
	ctx := context.Background()
	first := alice.seal(t, testPacket(100), relay.clock.unix()+3600)
	second := alice.seal(t, testPacket(5000), relay.clock.unix()+7200)

	outcome, err := relay.client.Deposit(ctx, first.envelope)
	if err != nil || outcome.Result != DepositStored || outcome.StatusCode != http.StatusCreated || !outcome.Accepted() || outcome.Err != nil {
		t.Fatalf("first deposit = %+v, %v", outcome, err)
	}
	relay.clock.Advance(time.Second)
	if outcome, err := relay.client.Deposit(ctx, second.envelope); err != nil || outcome.Result != DepositStored {
		t.Fatalf("second deposit = %+v, %v", outcome, err)
	}
	if outcome, err := relay.client.Deposit(ctx, first.envelope); err != nil || outcome.Result != DepositDuplicate ||
		outcome.StatusCode != http.StatusOK || !outcome.Accepted() {
		t.Fatalf("identical re-deposit = %+v, %v", outcome, err)
	}

	mailbox, err := relay.client.List(ctx, alice.agentID)
	if err != nil || len(mailbox.Envelopes) != 2 {
		t.Fatalf("list = %+v, %v", mailbox, err)
	}
	entry := mailbox.Envelopes[0]
	if entry.EnvelopeID != first.id || entry.RecipientKeyID != alice.key.KeyID || int(entry.Size) != len(first.envelope) ||
		entry.ReceivedAtUnix != relay.clock.unix()-1 || entry.ExpiresAtUnix != relay.clock.unix()-1+3600 {
		t.Fatalf("first entry = %+v", entry)
	}
	if mailbox.Envelopes[1].EnvelopeID != second.id {
		t.Fatal("entries are not ordered by receipt")
	}

	for _, want := range []sealed{first, second} {
		raw, err := relay.client.Download(ctx, alice.agentID, want.id)
		if err != nil || !bytes.Equal(raw, want.envelope) {
			t.Fatalf("download: %v", err)
		}
		opened, err := agentpacketseal.Open(alice.key, raw)
		if err != nil || !bytes.Equal(opened.PacketJSON, want.packet) || opened.AckSecret != want.secret {
			t.Fatalf("open: %v", err)
		}
		if err := relay.client.Ack(ctx, alice.agentID, want.id, opened.AckSecret); err != nil {
			t.Fatalf("ack: %v", err)
		}
		if err := relay.client.Ack(ctx, alice.agentID, want.id, opened.AckSecret); err != nil {
			t.Fatalf("repeated ack is not idempotent: %v", err)
		}
	}
	mailbox, err = relay.client.List(ctx, alice.agentID)
	if err != nil || len(mailbox.Envelopes) != 0 {
		t.Fatalf("list after ack = %+v, %v", mailbox, err)
	}
	if _, err := relay.client.Download(ctx, alice.agentID, first.id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("download after ack = %v", err)
	}
	if outcome, err := relay.client.Deposit(ctx, first.envelope); err != nil || outcome.Result != DepositAcknowledged ||
		outcome.StatusCode != http.StatusGone || !outcome.Accepted() {
		t.Fatalf("re-deposit after ack = %+v, %v", outcome, err)
	}
	usage := relay.store.Usage()
	if usage.Envelopes != 0 || usage.Tombstones != 2 || usage.Bytes != 0 {
		t.Fatalf("usage = %+v", usage)
	}
	description, err := relay.client.Describe(ctx)
	if err != nil || description.MaxEnvelopeBytes != MaxEnvelopeBytes || description.MaxTTLSeconds != day ||
		description.PerRecipientMaxEnvelopes != 256 || description.PerRecipientMaxBytes != 16<<20 {
		t.Fatalf("describe = %+v, %v", description, err)
	}
}

func TestDepositStatusCodes(t *testing.T) {
	relay := newTestRelay(t, testLimits())
	alice, bob := newRecipient(t), newRecipient(t)
	now := relay.clock.unix()
	env := alice.seal(t, testPacket(64), now+600)

	t.Run("wrong content type", func(t *testing.T) {
		expectStatus(t, relay.do(http.MethodPut, relay.envelopeURL(alice.agentID, env.id), "application/json", env.envelope), 400)
		expectStatus(t, relay.do(http.MethodPut, relay.envelopeURL(alice.agentID, env.id), "", env.envelope), 400)
	})
	t.Run("recipient differs from path", func(t *testing.T) {
		expectStatus(t, relay.put(bob.agentID, env.id, env.envelope), 400)
	})
	t.Run("envelope ID differs from path", func(t *testing.T) {
		other := env.id
		other[0] ^= 1
		expectStatus(t, relay.put(alice.agentID, other, env.envelope), 400)
	})
	t.Run("malformed envelope", func(t *testing.T) {
		mutated := append([]byte(nil), env.envelope...)
		mutated[0] ^= 1
		expectStatus(t, relay.put(alice.agentID, env.id, mutated), 400)
		expectStatus(t, relay.put(alice.agentID, env.id, env.envelope[:len(env.envelope)-1]), 400)
		expectStatus(t, relay.put(alice.agentID, env.id, append(append([]byte(nil), env.envelope...), 0)), 400)
		expectStatus(t, relay.put(alice.agentID, env.id, []byte{}), 400)
	})
	t.Run("expiry bounds", func(t *testing.T) {
		expired := alice.seal(t, testPacket(8), now)
		expectStatus(t, relay.putSealed(expired), 422)
		tooFar := alice.seal(t, testPacket(8), now+day+300+1)
		expectStatus(t, relay.putSealed(tooFar), 422)
		edge := alice.seal(t, testPacket(8), now+day+300)
		expectStatus(t, relay.putSealed(edge), 201)
		list := decodeList(t, relay.do(http.MethodGet, relay.client.BaseURL()+"/v1/mailboxes/"+alice.agentID+"/envelopes", "", nil))
		found := false
		for _, entry := range list.Envelopes {
			if entry.EnvelopeID == hex.EncodeToString(edge.id[:]) {
				found = true
				if entry.ExpiresAtUnix != now+day {
					t.Fatalf("effective expiry = %d, want receipt + 24 h", entry.ExpiresAtUnix)
				}
			}
		}
		if !found {
			t.Fatal("edge envelope not listed")
		}
	})
	t.Run("stored, duplicate, conflict", func(t *testing.T) {
		expectStatus(t, relay.putSealed(env), 201)
		expectStatus(t, relay.putSealed(env), 200)
		// Different bytes under the same ID: the same header with another
		// ciphertext.
		junk := append([]byte(nil), env.envelope...)
		junk[len(junk)-1] ^= 1
		expectStatus(t, relay.put(alice.agentID, env.id, junk), 409)
		raw, err := relay.client.Download(context.Background(), alice.agentID, env.id)
		if err != nil || !bytes.Equal(raw, env.envelope) {
			t.Fatal("a conflicting deposit changed the stored envelope")
		}
	})
	t.Run("tombstone refuses any bytes", func(t *testing.T) {
		expectStatus(t, relay.ackRaw(alice.agentID, env.id, env.secret[:]), 204)
		expectStatus(t, relay.putSealed(env), 410)
		junk := append([]byte(nil), env.envelope...)
		junk[len(junk)-1] ^= 1
		expectStatus(t, relay.put(alice.agentID, env.id, junk), 410)
	})
	t.Run("size refused before the body is read", func(t *testing.T) {
		reads := 0
		body := readerFunc(func(p []byte) (int, error) {
			reads++
			return 0, io.ErrUnexpectedEOF
		})
		for _, length := range []int64{MaxEnvelopeBytes + 1, 1 << 40} {
			request := httptest.NewRequest(http.MethodPut, relay.envelopeURL(alice.agentID, env.id), body)
			request.ContentLength = length
			request.Header.Set("Content-Length", strconv.FormatInt(length, 10))
			request.Header.Set("Content-Type", ContentTypeEnvelope)
			recorder := httptest.NewRecorder()
			relay.server.ServeHTTP(recorder, request)
			expectStatus(t, recorderResponse(recorder), 413)
		}
		// No Content-Length (a chunked body) is refused the same way.
		request := httptest.NewRequest(http.MethodPut, relay.envelopeURL(alice.agentID, env.id), body)
		request.ContentLength = -1
		request.TransferEncoding = []string{"chunked"}
		request.Header.Set("Content-Type", ContentTypeEnvelope)
		recorder := httptest.NewRecorder()
		relay.server.ServeHTTP(recorder, request)
		expectStatus(t, recorderResponse(recorder), 413)
		if reads != 0 {
			t.Fatalf("the relay read an oversized body %d times", reads)
		}
	})
	t.Run("oversized body over the wire", func(t *testing.T) {
		big := make([]byte, MaxEnvelopeBytes+1)
		expectStatus(t, relay.put(alice.agentID, env.id, big), 413)
	})
	t.Run("maximal envelope", func(t *testing.T) {
		maximal := alice.seal(t, bytes.Repeat([]byte("m"), agentpacketseal.MaxPacketJSONBytes), now+600)
		if len(maximal.envelope) != MaxEnvelopeBytes {
			t.Fatalf("maximal envelope = %d bytes", len(maximal.envelope))
		}
		expectStatus(t, relay.putSealed(maximal), 201)
	})
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func recorderResponse(recorder *httptest.ResponseRecorder) response {
	result := recorder.Result()
	body, _ := io.ReadAll(result.Body)
	return response{status: result.StatusCode, header: result.Header, body: body}
}

func TestPathsMethodsAndQueries(t *testing.T) {
	relay := newTestRelay(t, testLimits())
	alice := newRecipient(t)
	env := alice.seal(t, testPacket(8), relay.clock.unix()+600)
	expectStatus(t, relay.putSealed(env), 201)
	base := relay.client.BaseURL()
	idHex := hex.EncodeToString(env.id[:])
	upper := "agent_" + strings.ToUpper(alice.agentID[len("agent_"):])
	zeroAgent := "agent_" + strings.Repeat("0", 64)

	notFound := []string{
		base + "/",
		base + "/v1",
		base + "/v1/",
		base + "/v2/relay",
		base + "/v1/relay/",
		base + "/v1/mailboxes/" + alice.agentID,
		base + "/v1/mailboxes/" + alice.agentID + "/envelopes/",
		base + "/v1/mailboxes/" + upper + "/envelopes",
		base + "/v1/mailboxes/" + zeroAgent + "/envelopes",
		base + "/v1/mailboxes/" + alice.agentID[:len(alice.agentID)-1] + "/envelopes",
		base + "/v1/mailboxes/" + alice.agentID + "/envelopes/" + strings.ToUpper(idHex),
		base + "/v1/mailboxes/" + alice.agentID + "/envelopes/" + strings.Repeat("0", 64),
		base + "/v1/mailboxes/" + alice.agentID + "/envelopes/" + idHex[:63],
		base + "/v1/mailboxes/" + alice.agentID + "/envelopes/" + idHex + "/",
		base + "/v1/mailboxes/" + alice.agentID + "/envelopes/" + idHex + "/ack/",
		base + "/v1/mailboxes/" + alice.agentID + "/envelopes/" + idHex + "/nack",
		base + "/v1/mailboxes/" + alice.agentID + "/envelopes/%" + idHex[:2] + idHex[2:],
		base + "/v1/mailboxes/agent_%35" + alice.agentID[7:] + "/envelopes",
		base + "/v1//mailboxes/" + alice.agentID + "/envelopes",
	}
	for _, target := range notFound {
		expectStatus(t, relay.do(http.MethodGet, target, "", nil), 404)
	}
	// A percent-escaped spelling of a valid ID is never normalized.
	escaped := base + "/v1/mailboxes/" + alice.agentID + "/envelopes/%" + hex.EncodeToString([]byte(idHex[:1])) + idHex[1:]
	expectStatus(t, relay.do(http.MethodGet, escaped, "", nil), 404)

	for _, target := range []string{
		base + "/v1/relay?",
		base + "/v1/relay?x=1",
		base + "/v1/mailboxes/" + alice.agentID + "/envelopes?secret=1",
		base + "/v1/mailboxes/" + alice.agentID + "/envelopes/" + idHex + "?",
	} {
		expectStatus(t, relay.do(http.MethodGet, target, "", nil), 400)
	}
	expectStatus(t, relay.do(http.MethodPost, relay.envelopeURL(alice.agentID, env.id)+"/ack?x", ContentTypeEnvelope, env.secret[:]), 400)

	type methodCase struct {
		method, target, allow string
	}
	for _, c := range []methodCase{
		{http.MethodPost, base + "/v1/relay", "GET"},
		{http.MethodHead, base + "/v1/relay", "GET"},
		{http.MethodPut, base + "/v1/mailboxes/" + alice.agentID + "/envelopes", "GET"},
		{http.MethodDelete, relay.envelopeURL(alice.agentID, env.id), "GET, PUT"},
		{http.MethodPost, relay.envelopeURL(alice.agentID, env.id), "GET, PUT"},
		{http.MethodGet, relay.envelopeURL(alice.agentID, env.id) + "/ack", "POST"},
		{http.MethodDelete, relay.envelopeURL(alice.agentID, env.id) + "/ack", "POST"},
	} {
		got := relay.do(c.method, c.target, "", nil)
		if c.method == http.MethodHead {
			if got.status != 405 || got.header.Get("Allow") != c.allow {
				t.Fatalf("HEAD = %d", got.status)
			}
			continue
		}
		expectStatus(t, got, 405)
		if got.header.Get("Allow") != c.allow {
			t.Fatalf("%s %s Allow = %q", c.method, c.target, got.header.Get("Allow"))
		}
	}
	// The stored envelope is untouched by all of the above.
	if raw, err := relay.client.Download(context.Background(), alice.agentID, env.id); err != nil || !bytes.Equal(raw, env.envelope) {
		t.Fatalf("download = %v", err)
	}
	// An empty mailbox lists as an empty array, not null.
	bob := newRecipient(t)
	got := relay.do(http.MethodGet, base+"/v1/mailboxes/"+bob.agentID+"/envelopes", "", nil)
	if list := decodeList(t, got); list.Schema != SchemaMailbox || list.AgentID != bob.agentID || list.Envelopes == nil ||
		len(list.Envelopes) != 0 || !bytes.Contains(got.body, []byte(`"envelopes":[]`)) {
		t.Fatalf("empty list = %q", got.body)
	}
	if got.header.Get("Content-Type") != ContentTypeJSON {
		t.Fatal("list content type")
	}
	// Download of another mailbox's envelope ID is 404.
	expectStatus(t, relay.do(http.MethodGet, relay.envelopeURL(bob.agentID, env.id), "", nil), 404)
}

func TestBasePath(t *testing.T) {
	relay := newTestRelay(t, testLimits(), func(c *ServerConfig) { c.BasePath = "/relay/a" })
	alice := newRecipient(t)
	env := alice.seal(t, testPacket(8), relay.clock.unix()+600)
	if outcome, err := relay.client.Deposit(context.Background(), env.envelope); err != nil || outcome.Result != DepositStored {
		t.Fatalf("deposit under a base path = %+v, %v", outcome, err)
	}
	expectStatus(t, relay.do(http.MethodGet, relay.http.URL+"/v1/relay", "", nil), 404)
	for _, bad := range []string{"relay", "/relay/", "/a//b", "/a%20b"} {
		if _, err := NewServer(ServerConfig{Store: relay.store, BasePath: bad}); err == nil {
			t.Fatalf("base path %q accepted", bad)
		}
	}
}

func TestAcknowledge(t *testing.T) {
	relay := newTestRelay(t, testLimits())
	alice, bob := newRecipient(t), newRecipient(t)
	env := alice.seal(t, testPacket(8), relay.clock.unix()+600)
	expectStatus(t, relay.putSealed(env), 201)

	wrong := env.secret
	wrong[31] ^= 1
	expectStatus(t, relay.ackRaw(alice.agentID, env.id, wrong[:]), 403)
	expectStatus(t, relay.ackRaw(alice.agentID, env.id, env.secret[:31]), 400)
	expectStatus(t, relay.ackRaw(alice.agentID, env.id, append(env.secret[:], 0)), 400)
	expectStatus(t, relay.ackRaw(alice.agentID, env.id, nil), 400)
	expectStatus(t, relay.do(http.MethodPost, relay.envelopeURL(alice.agentID, env.id)+"/ack", "application/json", env.secret[:]), 400)
	// The envelope ID itself is not the secret.
	expectStatus(t, relay.ackRaw(alice.agentID, env.id, env.id[:]), 403)
	// The right secret under another mailbox does not delete it.
	expectStatus(t, relay.ackRaw(bob.agentID, env.id, env.secret[:]), 404)
	// An unknown ID with its own matching secret is 404.
	unknown := alice.seal(t, testPacket(8), relay.clock.unix()+600)
	expectStatus(t, relay.ackRaw(alice.agentID, unknown.id, unknown.secret[:]), 404)
	if _, err := relay.client.Download(context.Background(), alice.agentID, env.id); err != nil {
		t.Fatalf("a failed acknowledgement deleted the envelope: %v", err)
	}

	expectStatus(t, relay.ackRaw(alice.agentID, env.id, env.secret[:]), 204)
	expectStatus(t, relay.ackRaw(alice.agentID, env.id, env.secret[:]), 204)
	expectStatus(t, relay.ackRaw(alice.agentID, env.id, wrong[:]), 403)
	expectStatus(t, relay.ackRaw(bob.agentID, env.id, env.secret[:]), 404)

	// Chunked bodies are bounded the same way.
	request, err := http.NewRequest(http.MethodPost, relay.envelopeURL(alice.agentID, env.id)+"/ack",
		io.MultiReader(bytes.NewReader(env.secret[:]), bytes.NewReader(make([]byte, 1<<20))))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", ContentTypeEnvelope)
	request.ContentLength = -1
	httpResponse, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	httpResponse.Body.Close()
	if httpResponse.StatusCode != 400 {
		t.Fatalf("chunked oversized ack = %d", httpResponse.StatusCode)
	}

	// Past the effective expiry the tombstone is gone: 404.
	relay.clock.Advance(601 * time.Second)
	expectStatus(t, relay.ackRaw(alice.agentID, env.id, env.secret[:]), 404)
}

func TestTTLExpiryAndSweep(t *testing.T) {
	limits := testLimits()
	limits.TTL = time.Hour
	relay := newTestRelay(t, limits)
	alice := newRecipient(t)
	now := relay.clock.unix()
	short := alice.seal(t, testPacket(8), now+600)
	long := alice.seal(t, testPacket(8), now+day)
	acked := alice.seal(t, testPacket(8), now+1800)
	for _, env := range []sealed{short, long, acked} {
		expectStatus(t, relay.putSealed(env), 201)
	}
	expectStatus(t, relay.ackRaw(alice.agentID, acked.id, acked.secret[:]), 204)

	list, err := relay.client.List(context.Background(), alice.agentID)
	if err != nil || len(list.Envelopes) != 2 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	for _, entry := range list.Envelopes {
		want := now + 600
		if entry.EnvelopeID == long.id {
			want = now + 3600 // the operator TTL caps the envelope's own expiry
		}
		if entry.ExpiresAtUnix != want {
			t.Fatalf("expiry = %d, want %d", entry.ExpiresAtUnix, want)
		}
	}

	relay.clock.Advance(600 * time.Second)
	// Expired but not yet swept: invisible everywhere.
	list, err = relay.client.List(context.Background(), alice.agentID)
	if err != nil || len(list.Envelopes) != 1 || list.Envelopes[0].EnvelopeID != long.id {
		t.Fatalf("list at short expiry = %+v, %v", list, err)
	}
	expectStatus(t, relay.do(http.MethodGet, relay.envelopeURL(alice.agentID, short.id), "", nil), 404)
	expectStatus(t, relay.ackRaw(alice.agentID, short.id, short.secret[:]), 404)
	if usage := relay.store.Usage(); usage.Envelopes != 2 || usage.Tombstones != 1 {
		t.Fatalf("usage before sweep = %+v", usage)
	}
	if err := relay.store.Sweep(relay.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if usage := relay.store.Usage(); usage.Envelopes != 1 || usage.Tombstones != 1 || usage.Bytes != int64(len(long.envelope)) {
		t.Fatalf("usage after sweep = %+v", usage)
	}
	// The tombstone lasts until the acknowledged envelope's effective expiry.
	expectStatus(t, relay.putSealed(acked), 410)
	relay.clock.Advance(1200 * time.Second)
	if err := relay.store.Sweep(relay.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if usage := relay.store.Usage(); usage.Tombstones != 0 {
		t.Fatalf("tombstone survived its expiry: %+v", usage)
	}
	relay.clock.Advance(1800 * time.Second)
	expectStatus(t, relay.do(http.MethodGet, relay.envelopeURL(alice.agentID, long.id), "", nil), 404)
	if err := relay.store.Sweep(relay.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if usage := relay.store.Usage(); usage != (Usage{}) {
		t.Fatalf("usage after the last sweep = %+v", usage)
	}
	// An expired envelope's ID is free again: a deposit still within its
	// own expiry is stored anew.
	expectStatus(t, relay.putSealed(long), 201)
}

func TestQuotas(t *testing.T) {
	t.Run("per recipient count", func(t *testing.T) {
		limits := testLimits()
		limits.PerRecipientMaxEnvelopes = 3
		relay := newTestRelay(t, limits)
		alice, bob := newRecipient(t), newRecipient(t)
		var kept []sealed
		for range 3 {
			env := alice.seal(t, testPacket(8), relay.clock.unix()+600)
			expectStatus(t, relay.putSealed(env), 201)
			kept = append(kept, env)
		}
		expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600)), 507)
		// Another recipient is unaffected; nothing was evicted.
		expectStatus(t, relay.putSealed(bob.seal(t, testPacket(8), relay.clock.unix()+600)), 201)
		if list, err := relay.client.List(context.Background(), alice.agentID); err != nil || len(list.Envelopes) != 3 {
			t.Fatalf("list = %+v, %v", list, err)
		}
		// An identical retry of a stored envelope is still 200 when full.
		expectStatus(t, relay.putSealed(kept[0]), 200)
		// Acknowledgement frees the slot.
		expectStatus(t, relay.ackRaw(alice.agentID, kept[0].id, kept[0].secret[:]), 204)
		expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600)), 201)
	})
	t.Run("per recipient bytes", func(t *testing.T) {
		limits := testLimits()
		limits.PerRecipientMaxBytes = MaxEnvelopeBytes
		relay := newTestRelay(t, limits)
		alice := newRecipient(t)
		big := alice.seal(t, testPacket(200_000), relay.clock.unix()+600)
		expectStatus(t, relay.putSealed(big), 201)
		expectStatus(t, relay.putSealed(alice.seal(t, testPacket(70_000), relay.clock.unix()+600)), 507)
		expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600)), 201)
	})
	t.Run("per client and recipient", func(t *testing.T) {
		limits := testLimits()
		limits.PerClientRecipientMaxEnvelopes = 2
		relay := newTestRelay(t, limits, func(c *ServerConfig) {
			c.TrustedProxies = []netipPrefix{mustPrefix(t, "127.0.0.0/8")}
		})
		alice, bob := newRecipient(t), newRecipient(t)
		from := func(addr string) []string { return []string{"X-Forwarded-For", addr} }
		for range 2 {
			expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600), from("192.0.2.1")...), 201)
		}
		expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600), from("192.0.2.1")...), 507)
		// Same client, other recipient; other client, same recipient.
		expectStatus(t, relay.putSealed(bob.seal(t, testPacket(8), relay.clock.unix()+600), from("192.0.2.1")...), 201)
		expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600), from("192.0.2.2")...), 201)
		// IPv6 addresses in one /64 are one client.
		expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600), from("2001:db8:1:2::1")...), 201)
		expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600), from("2001:db8:1:2:ffff::9")...), 201)
		expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600), from("2001:db8:1:2::77")...), 507)
		expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600), from("2001:db8:1:3::1")...), 201)
	})
	t.Run("global count includes tombstones", func(t *testing.T) {
		limits := testLimits()
		limits.GlobalMaxEntries = 2
		relay := newTestRelay(t, limits)
		alice, bob := newRecipient(t), newRecipient(t)
		first := alice.seal(t, testPacket(8), relay.clock.unix()+600)
		expectStatus(t, relay.putSealed(first), 201)
		expectStatus(t, relay.ackRaw(alice.agentID, first.id, first.secret[:]), 204)
		expectStatus(t, relay.putSealed(bob.seal(t, testPacket(8), relay.clock.unix()+600)), 201)
		late := alice.seal(t, testPacket(8), relay.clock.unix()+3600)
		expectStatus(t, relay.putSealed(late), 507)
		relay.clock.Advance(601 * time.Second)
		// Expired entries no longer hold quota once swept.
		if err := relay.store.Sweep(relay.clock.Now()); err != nil {
			t.Fatal(err)
		}
		expectStatus(t, relay.putSealed(late), 201)
	})
	t.Run("global bytes", func(t *testing.T) {
		limits := testLimits()
		limits.GlobalMaxBytes = MaxEnvelopeBytes
		relay := newTestRelay(t, limits)
		alice, bob := newRecipient(t), newRecipient(t)
		expectStatus(t, relay.putSealed(alice.seal(t, testPacket(200_000), relay.clock.unix()+600)), 201)
		expectStatus(t, relay.putSealed(bob.seal(t, testPacket(70_000), relay.clock.unix()+600)), 507)
	})
	t.Run("limits validation", func(t *testing.T) {
		good := testLimits()
		for name, mutate := range map[string]func(*Limits){
			"no global entries":        func(l *Limits) { l.GlobalMaxEntries = 0 },
			"no global bytes":          func(l *Limits) { l.GlobalMaxBytes = 0 },
			"recipient count too high": func(l *Limits) { l.PerRecipientMaxEnvelopes = 257 },
			"recipient bytes too high": func(l *Limits) { l.PerRecipientMaxBytes = 16<<20 + 1 },
			"client count too high":    func(l *Limits) { l.PerClientRecipientMaxEnvelopes = 65 },
			"TTL too long":             func(l *Limits) { l.TTL = 24*time.Hour + time.Second },
			"TTL zero":                 func(l *Limits) { l.TTL = 0 },
		} {
			limits := good
			mutate(&limits)
			if limits.Validate() == nil {
				t.Errorf("%s accepted", name)
			}
		}
		if good.Validate() != nil {
			t.Fatal("default limits refused")
		}
	})
}

func TestRateLimit(t *testing.T) {
	relay := newTestRelay(t, testLimits(), func(c *ServerConfig) {
		c.DepositRate = RateLimit{PerMinute: 60, Burst: 3}
		c.ReadRate = RateLimit{PerMinute: 600, Burst: 2}
		c.TrustedProxies = []netipPrefix{mustPrefix(t, "127.0.0.1/32")}
	})
	alice := newRecipient(t)
	from := func(addr string) []string { return []string{"X-Forwarded-For", addr} }
	for range 3 {
		expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600), from("198.51.100.1")...), 201)
	}
	limited := relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600), from("198.51.100.1")...)
	expectStatus(t, limited, 429)
	if limited.header.Get("Retry-After") != "1" {
		t.Fatalf("Retry-After = %q", limited.header.Get("Retry-After"))
	}
	// Rejected requests also consume tokens; a malformed one is still 429.
	expectStatus(t, relay.put(alice.agentID, [32]byte{1}, []byte("x"), from("198.51.100.1")...), 429)
	// Another client and the read class are separate buckets.
	expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600), from("198.51.100.2")...), 201)
	listURL := relay.client.BaseURL() + "/v1/mailboxes/" + alice.agentID + "/envelopes"
	expectStatus(t, relay.do(http.MethodGet, listURL, "", nil, from("198.51.100.1")...), 200)
	expectStatus(t, relay.do(http.MethodGet, listURL, "", nil, from("198.51.100.1")...), 200)
	expectStatus(t, relay.do(http.MethodGet, listURL, "", nil, from("198.51.100.1")...), 429)
	expectStatus(t, relay.do(http.MethodGet, listURL+"?x", "", nil, from("198.51.100.1")...), 429)
	relay.clock.Advance(time.Second)
	expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600), from("198.51.100.1")...), 201)
	expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600), from("198.51.100.1")...), 429)
}

// TestRateLimiterEvictsLeastRecentlyUsed: a full table admits a new client
// by evicting the least recently used bucket, never by refusing, and keeps
// the state of the more recently used ones.
func TestRateLimiterEvictsLeastRecentlyUsed(t *testing.T) {
	limiter := newRateLimiter(RateLimit{PerMinute: 60, Burst: 1}, 2, DefaultMaxRateClientsPer48)
	now := testStart
	a, b, c := mustAddr(t, "192.0.2.1"), mustAddr(t, "192.0.2.2"), mustAddr(t, "192.0.2.3")
	for _, addr := range []netipAddr{a, b} {
		if ok, _ := limiter.allow(addr, now); !ok {
			t.Fatal("first request refused")
		}
	}
	// a is used again (and limited), so b is now the least recently used.
	if ok, _ := limiter.allow(a, now); ok {
		t.Fatal("burst not enforced")
	}
	if ok, _ := limiter.allow(c, now); !ok {
		t.Fatal("a new client was refused instead of evicting a bucket")
	}
	if len(limiter.buckets) != 2 || limiter.order.Len() != 2 {
		t.Fatalf("table size = %d / %d", len(limiter.buckets), limiter.order.Len())
	}
	if _, held := limiter.buckets[rateKey{addr: b}]; held {
		t.Fatal("the least recently used bucket was not the one evicted")
	}
	// a kept its limited state across the eviction.
	if ok, _ := limiter.allow(a, now); ok {
		t.Fatal("a limited client lost its state to an eviction of another bucket")
	}
}

// TestRateLimiterPer48: one IPv6 /48 cannot fill the table with its /64s;
// past the bound its further /64s share one bucket, and other prefixes are
// unaffected.
func TestRateLimiterPer48(t *testing.T) {
	limiter := newRateLimiter(RateLimit{PerMinute: 60, Burst: 1}, 1000, 4)
	now := testStart
	for index := range 20 {
		addr := mustAddr(t, fmt.Sprintf("2001:db8:aa:%x::", index))
		ok, _ := limiter.allow(addr, now)
		// Four own buckets, then the shared bucket admits one request and
		// is empty for the rest.
		if want := index <= 4; ok != want {
			t.Fatalf("/64 number %d: allowed %v, want %v", index, ok, want)
		}
	}
	if len(limiter.buckets) != 5 {
		t.Fatalf("one /48 holds %d buckets", len(limiter.buckets))
	}
	if ok, _ := limiter.allow(mustAddr(t, "2001:db8:bb::"), now); !ok {
		t.Fatal("another /48 was limited by the first one")
	}
	// The /48's own /64s keep their own buckets.
	if ok, _ := limiter.allow(mustAddr(t, "2001:db8:aa:1::"), now.Add(time.Second)); !ok {
		t.Fatal("an own /64 bucket did not refill")
	}
	// Evicting an own bucket frees its place in the /48 bound.
	small := newRateLimiter(RateLimit{PerMinute: 60, Burst: 1}, 2, 1)
	small.allow(mustAddr(t, "2001:db8:cc:1::"), now)
	small.allow(mustAddr(t, "192.0.2.1"), now)
	small.allow(mustAddr(t, "192.0.2.2"), now) // evicts the /64
	if small.groups[mustAddr(t, "2001:db8:cc::")] != 0 {
		t.Fatal("an evicted bucket still counts against its /48")
	}
	if _, shared := small.buckets[rateKey{addr: mustAddr(t, "2001:db8:cc::"), shared: true}]; shared {
		t.Fatal("unexpected shared bucket")
	}
	small.allow(mustAddr(t, "2001:db8:cc:2::"), now)
	if _, own := small.buckets[rateKey{addr: mustAddr(t, "2001:db8:cc:2::")}]; !own {
		t.Fatal("a /64 did not get its own bucket after the /48 count was freed")
	}
}

func TestClientAddress(t *testing.T) {
	trusted := []netipPrefix{mustPrefix(t, "10.0.0.0/8")}
	cases := []struct {
		remote string
		xff    []string
		trust  bool
		want   string
	}{
		{"192.0.2.9:4000", nil, true, "192.0.2.9"},
		{"192.0.2.9:4000", []string{"203.0.113.5"}, true, "192.0.2.9"}, // untrusted peer: header ignored
		{"192.0.2.9:4000", []string{"203.0.113.5"}, false, "192.0.2.9"},
		{"10.1.1.1:4000", []string{"203.0.113.5"}, true, "203.0.113.5"},
		{"10.1.1.1:4000", []string{"203.0.113.5"}, false, "10.1.1.1"}, // no trusted proxies configured
		{"10.1.1.1:4000", []string{"198.51.100.7, 203.0.113.5, 10.2.2.2"}, true, "203.0.113.5"},
		{"10.1.1.1:4000", []string{"198.51.100.7", "10.2.2.2"}, true, "198.51.100.7"},
		{"10.1.1.1:4000", []string{"garbage, 10.2.2.2"}, true, "10.2.2.2"},
		{"10.1.1.1:4000", nil, true, "10.1.1.1"},
		{"[2001:db8:aa:bb:1:2:3:4]:4000", nil, true, "2001:db8:aa:bb::"},
		{"[::ffff:192.0.2.1]:4000", nil, true, "192.0.2.1"},
		{"10.1.1.1:4000", []string{"2001:db8:aa:bb:1:2:3:4"}, true, "2001:db8:aa:bb::"},
	}
	for _, c := range cases {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.RemoteAddr = c.remote
		for _, value := range c.xff {
			request.Header.Add("X-Forwarded-For", value)
		}
		var proxies []netipPrefix
		if c.trust {
			proxies = trusted
		}
		got, ok := clientAddress(request, proxies)
		if !ok || got.String() != c.want {
			t.Errorf("%s %v trust=%v: got %v, want %s", c.remote, c.xff, c.trust, got, c.want)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "not-an-address"
	if _, ok := clientAddress(request, nil); ok {
		t.Fatal("unparsable peer accepted")
	}
}

// TestNoBodyEchoed checks that no error response repeats request bytes.
func TestNoBodyEchoed(t *testing.T) {
	relay := newTestRelay(t, testLimits())
	alice := newRecipient(t)
	marker := []byte("SECRET-MARKER-0123456789")
	body := append(bytes.Repeat([]byte{0}, 200), marker...)
	got := relay.put(alice.agentID, [32]byte{7}, body)
	if bytes.Contains(got.body, marker) || got.status != 400 {
		t.Fatalf("response echoed request bytes or wrong status %d", got.status)
	}
	got = relay.ackRaw(alice.agentID, [32]byte{7}, marker)
	if bytes.Contains(got.body, marker) {
		t.Fatal("ack response echoed request bytes")
	}
}

// TestExpectContinueRefusedBeforeBody speaks raw HTTP/1.1 with Expect:
// 100-continue: an oversized deposit is refused without the body ever being
// sent.
func TestExpectContinueRefusedBeforeBody(t *testing.T) {
	relay := newTestRelay(t, testLimits())
	alice := newRecipient(t)
	conn, err := net.Dial("tcp", strings.TrimPrefix(relay.http.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	request := "PUT /v1/mailboxes/" + alice.agentID + "/envelopes/" + strings.Repeat("ab", 32) + " HTTP/1.1\r\n" +
		"Host: relay\r\nContent-Type: application/octet-stream\r\nContent-Length: 262145\r\nExpect: 100-continue\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(buffer[:n]), "HTTP/1.1 413") {
		t.Fatalf("response = %q", buffer[:n])
	}
}
