package agentpacketrelay

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientConfig(t *testing.T) {
	for _, base := range []string{
		"http://relay.example", "http://10.0.0.1:8095", "https://Relay.example", "https://relay.example/",
		"https://relay.example?x", "https://user@relay.example", "ftp://relay.example", "", "https://relay.example/a%20b",
	} {
		if _, err := NewClient(ClientConfig{BaseURL: base}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("base %q accepted", base)
		}
	}
	for _, base := range []string{"https://relay.example", "https://relay.example:8443/relay", "http://127.0.0.1:8095", "http://localhost", "http://[::1]:9"} {
		if _, err := NewClient(ClientConfig{BaseURL: base}); err != nil {
			t.Errorf("base %q refused: %v", base, err)
		}
	}
	proxy, _ := url.Parse("http://127.0.0.1:3128")
	if _, err := NewClient(ClientConfig{BaseURL: "https://relay.example", Proxy: proxy, Transport: http.DefaultTransport}); err == nil {
		t.Fatal("proxy and transport together accepted")
	}
	if _, err := NewClient(ClientConfig{BaseURL: "https://relay.example", Proxy: &url.URL{Scheme: "socks5", Host: "x:1"}}); err == nil {
		t.Fatal("non-HTTP proxy accepted")
	}
	if _, err := NewClient(ClientConfig{BaseURL: "https://relay.example", Timeout: -1}); err == nil {
		t.Fatal("negative timeout accepted")
	}
}

// fakeRelay answers every request with a fixed handler and counts hits.
func fakeRelay(t *testing.T, handler http.HandlerFunc) (*Client, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	client, err := NewClient(ClientConfig{BaseURL: server.URL, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return client, &hits
}

func errorBody(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", ContentTypeJSON)
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"schema":%q,"code":%q}`, SchemaError, code)
}

func TestDepositOutcomeClassification(t *testing.T) {
	alice := newRecipient(t)
	env := alice.seal(t, testPacket(8), uint64(testStart.Unix())+600)
	cases := []struct {
		status     int
		retryAfter string
		want       DepositResult
		code       string
	}{
		{201, "", DepositStored, ""},
		{200, "", DepositDuplicate, ""},
		{410, "", DepositAcknowledged, ""},
		{409, "", DepositConflict, CodeConflict},
		{400, "", DepositRejected, CodeInvalidRequest},
		{404, "", DepositRejected, CodeNotFound},
		{413, "", DepositRejected, CodeTooLarge},
		{422, "", DepositRejected, CodeExpiryOutOfBounds},
		{429, "7", DepositRetryable, CodeRateLimited},
		{507, "", DepositRetryable, CodeQuotaExhausted},
		{503, "", DepositRetryable, CodeUnavailable},
		{500, "", DepositRetryable, ""},
		{302, "", DepositRetryable, ""},
		{204, "", DepositRetryable, ""},
		{403, "", DepositRetryable, CodeForbidden},
		{408, "", DepositRetryable, CodeRequestTimeout},
	}
	for _, c := range cases {
		client, _ := fakeRelay(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut || r.Header.Get("Content-Type") != ContentTypeEnvelope ||
				r.ContentLength != int64(len(env.envelope)) || r.URL.RawQuery != "" ||
				r.URL.Path != "/v1/mailboxes/"+alice.agentID+"/envelopes/"+hex.EncodeToString(env.id[:]) {
				t.Errorf("unexpected request %s %s", r.Method, r.URL)
			}
			if c.retryAfter != "" {
				w.Header().Set("Retry-After", c.retryAfter)
			}
			if c.status == 302 {
				w.Header().Set("Location", "http://127.0.0.1:1/elsewhere")
			}
			if c.code != "" {
				errorBody(w, c.status, c.code)
				return
			}
			w.WriteHeader(c.status)
		})
		outcome, err := client.Deposit(context.Background(), env.envelope)
		if err != nil || outcome.Result != c.want || outcome.StatusCode != c.status || outcome.Code != c.code {
			t.Errorf("status %d: outcome %+v, %v", c.status, outcome, err)
		}
		if outcome.Accepted() != (c.want == DepositStored || c.want == DepositDuplicate || c.want == DepositAcknowledged) {
			t.Errorf("status %d: Accepted = %v", c.status, outcome.Accepted())
		}
		if (outcome.Err == nil) != outcome.Accepted() {
			t.Errorf("status %d: Err = %v", c.status, outcome.Err)
		}
		if c.retryAfter != "" && outcome.RetryAfter != 7*time.Second {
			t.Errorf("RetryAfter = %v", outcome.RetryAfter)
		}
	}
	// A code that is not the fixed code of its status is not believed.
	client, _ := fakeRelay(t, func(w http.ResponseWriter, r *http.Request) { errorBody(w, 409, CodeGone) })
	if outcome, _ := client.Deposit(context.Background(), env.envelope); outcome.Code != "" || outcome.Result != DepositConflict {
		t.Fatalf("mismatched code believed: %+v", outcome)
	}
	// A huge Retry-After is capped.
	client, _ = fakeRelay(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "999999")
		errorBody(w, 429, CodeRateLimited)
	})
	if outcome, _ := client.Deposit(context.Background(), env.envelope); outcome.RetryAfter != 5*time.Minute {
		t.Fatalf("Retry-After not capped: %v", outcome.RetryAfter)
	}
	// Connection failure and timeout are retryable outcomes, not errors.
	dead, err := NewClient(ClientConfig{BaseURL: "http://127.0.0.1:1", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := dead.Deposit(context.Background(), env.envelope); err != nil || outcome.Result != DepositRetryable ||
		outcome.StatusCode != 0 || outcome.Err == nil {
		t.Fatalf("connection failure = %+v, %v", outcome, err)
	}
	slow, _ := fakeRelay(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(3 * time.Second) })
	if outcome, err := slow.Deposit(context.Background(), env.envelope); err != nil || outcome.Result != DepositRetryable {
		t.Fatalf("timeout = %+v, %v", outcome, err)
	}
	// Local refusals send nothing.
	client, hits := fakeRelay(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) })
	if _, err := client.Deposit(context.Background(), env.envelope[:100]); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("malformed envelope = %v", err)
	}
	//nolint:staticcheck // a nil context is the input under test
	if _, err := client.Deposit(nil, env.envelope); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nil context = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("a refused deposit reached the relay")
	}
}

func TestClientRefusesRedirects(t *testing.T) {
	var followed atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed.Add(1)
		w.Header().Set("Content-Type", ContentTypeJSON)
		fmt.Fprintf(w, `{"schema":%q,"agent_id":"x","envelopes":[]}`, SchemaMailbox)
	}))
	defer target.Close()
	alice := newRecipient(t)
	client, _ := fakeRelay(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	})
	env := alice.seal(t, testPacket(8), uint64(testStart.Unix())+600)
	if outcome, _ := client.Deposit(context.Background(), env.envelope); outcome.Result != DepositRetryable || outcome.StatusCode != 307 {
		t.Fatalf("redirected deposit = %+v", outcome)
	}
	if _, err := client.List(context.Background(), alice.agentID); err == nil {
		t.Fatal("redirected list succeeded")
	}
	if _, err := client.Download(context.Background(), alice.agentID, env.id); err == nil {
		t.Fatal("redirected download succeeded")
	}
	if err := client.Ack(context.Background(), alice.agentID, env.id, env.secret); err == nil {
		t.Fatal("redirected ack succeeded")
	}
	if followed.Load() != 0 {
		t.Fatalf("the client followed %d redirects", followed.Load())
	}
}

func TestClientProxyIsExplicit(t *testing.T) {
	var proxied atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	// The environment names a proxy; the client must ignore it.
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	alice := newRecipient(t)
	env := alice.seal(t, testPacket(8), uint64(testStart.Unix())+600)
	direct, err := NewClient(ClientConfig{BaseURL: "https://relay.invalid", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if outcome, _ := direct.Deposit(context.Background(), env.envelope); outcome.Result != DepositRetryable || outcome.StatusCode != 0 {
		t.Fatalf("direct deposit to an unresolvable host = %+v", outcome)
	}
	if proxied.Load() != 0 {
		t.Fatal("the client used the environment proxy")
	}
	// An explicit proxy is used, loopback targets included.
	proxyURL, _ := url.Parse(proxy.URL)
	via, err := NewClient(ClientConfig{BaseURL: "http://127.0.0.1:1", Proxy: proxyURL, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if outcome, _ := via.Deposit(context.Background(), env.envelope); outcome.StatusCode != http.StatusBadGateway {
		t.Fatalf("proxied deposit = %+v", outcome)
	}
	if proxied.Load() != 1 {
		t.Fatalf("explicit proxy hits = %d", proxied.Load())
	}
}

func TestClientStrictList(t *testing.T) {
	alice := newRecipient(t)
	id := strings.Repeat("ab", 32)
	id2 := strings.Repeat("cd", 32)
	key := "hpke:" + strings.Repeat("11", 32)
	entry := func(envelopeID string, received uint64) string {
		return fmt.Sprintf(`{"envelope_id":%q,"recipient_key_id":%q,"size":6804,"received_at_unix":%d,"expires_at_unix":%d}`,
			envelopeID, key, received, received+100)
	}
	listing := func(agent string, entries ...string) string {
		return fmt.Sprintf(`{"schema":%q,"agent_id":%q,"envelopes":[%s]}`, SchemaMailbox, agent, strings.Join(entries, ","))
	}
	good := listing(alice.agentID, entry(id, 10), entry(id2, 10), entry(id, 11))
	serve := func(body, contentType string) *Client {
		client, _ := fakeRelay(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentType)
			io.WriteString(w, body)
		})
		return client
	}
	mailbox, err := serve(good, ContentTypeJSON).List(context.Background(), alice.agentID)
	if err != nil || len(mailbox.Envelopes) != 3 || mailbox.Envelopes[2].ReceivedAtUnix != 11 {
		t.Fatalf("good listing = %+v, %v", mailbox, err)
	}
	if _, err := serve(good, "application/json; charset=utf-8").List(context.Background(), alice.agentID); err != nil {
		t.Fatalf("media type parameters refused: %v", err)
	}
	bob := newRecipient(t)
	bad := map[string]string{
		"unknown field":   strings.Replace(good, `"envelopes"`, `"extra":1,"envelopes"`, 1),
		"entry field":     strings.Replace(good, `"size"`, `"note":"x","size"`, 1),
		"wrong schema":    strings.Replace(good, SchemaMailbox, SchemaRelay, 1),
		"other agent":     listing(bob.agentID, entry(id, 10)),
		"null envelopes":  fmt.Sprintf(`{"schema":%q,"agent_id":%q,"envelopes":null}`, SchemaMailbox, alice.agentID),
		"missing list":    fmt.Sprintf(`{"schema":%q,"agent_id":%q}`, SchemaMailbox, alice.agentID),
		"duplicate":       listing(alice.agentID, entry(id, 10), entry(id, 10)),
		"out of order":    listing(alice.agentID, entry(id, 11), entry(id2, 10)),
		"id order":        listing(alice.agentID, entry(id2, 10), entry(id, 10)),
		"upper hex id":    listing(alice.agentID, entry(strings.ToUpper(id), 10)),
		"zero id":         listing(alice.agentID, entry(strings.Repeat("0", 64), 10)),
		"bad key id":      strings.Replace(good, key, "hpke:"+strings.Repeat("0", 64), 1),
		"size too small":  strings.Replace(good, `"size":6804`, `"size":100`, 1),
		"size too large":  strings.Replace(good, `"size":6804`, `"size":262145`, 1),
		"expiry order":    listing(alice.agentID, strings.Replace(entry(id, 10), `"expires_at_unix":110`, `"expires_at_unix":10`, 1)),
		"trailing data":   good + "{}",
		"not JSON":        "nope",
		"too many":        listing(alice.agentID, manyEntries(257, key)...),
		"wrong type size": strings.Replace(good, `"size":6804`, `"size":"6804"`, 1),
	}
	for name, body := range bad {
		if _, err := serve(body, ContentTypeJSON).List(context.Background(), alice.agentID); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := serve(good, "text/plain").List(context.Background(), alice.agentID); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("wrong content type accepted")
	}
	huge := strings.Replace(good, `"schema"`, `"pad":"`+strings.Repeat("x", MaxResponseBytes)+`","schema"`, 1)
	if _, err := serve(huge, ContentTypeJSON).List(context.Background(), alice.agentID); !errors.Is(err, ErrInvalidResponse) {
		t.Fatal("oversized listing accepted")
	}
	// A valid listing padded with whitespace past 64 KiB and sent without a
	// Content-Length is still refused: the bound is on bytes, not on what
	// decodes.
	padded := good + strings.Repeat(" ", MaxResponseBytes)
	chunked, _ := fakeRelay(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, padded)
	})
	if _, err := chunked.List(context.Background(), alice.agentID); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("whitespace-padded oversized listing = %v", err)
	}
	if _, err := serve(good+strings.Repeat(" ", 1000), ContentTypeJSON).List(context.Background(), alice.agentID); err != nil {
		t.Fatalf("whitespace-padded listing within the bound refused: %v", err)
	}
	if _, err := serve(good, ContentTypeJSON).List(context.Background(), "agent_XYZ"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal("invalid Agent ID sent")
	}
}

// A description's max_ttl_seconds drives clients' re-deposit schedule, so
// only a value a V1 relay can have is accepted.
func TestClientDescribeBoundsTTL(t *testing.T) {
	describe := func(ttl string) (RelayDescription, error) {
		client, _ := fakeRelay(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", ContentTypeJSON)
			fmt.Fprintf(w, `{"schema":%q,"max_envelope_bytes":262144,"max_ttl_seconds":%s,`+
				`"per_recipient_max_envelopes":256,"per_recipient_max_bytes":16777216}`, SchemaRelay, ttl)
		})
		return client.Describe(context.Background())
	}
	for _, ttl := range []uint64{1, 3600, 10800, 86400} {
		description, err := describe(fmt.Sprint(ttl))
		if err != nil || description.MaxTTLSeconds != ttl {
			t.Fatalf("ttl %d: %+v, %v", ttl, description, err)
		}
	}
	for _, ttl := range []string{"0", "86401", "18446744073709551615", "-1", `"3600"`} {
		if _, err := describe(ttl); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("ttl %s: err = %v", ttl, err)
		}
	}
}

func manyEntries(n int, key string) []string {
	out := make([]string, n)
	for index := range n {
		out[index] = fmt.Sprintf(`{"envelope_id":"%064x","recipient_key_id":%q,"size":6804,"received_at_unix":%d,"expires_at_unix":%d}`,
			index+1, key, 10, 100)
	}
	return out
}

func TestClientStrictDownloadAndAck(t *testing.T) {
	alice, bob := newRecipient(t), newRecipient(t)
	env := alice.seal(t, testPacket(8), uint64(testStart.Unix())+600)
	other := alice.seal(t, testPacket(8), uint64(testStart.Unix())+600)
	serve := func(status int, contentType string, body []byte) *Client {
		client, _ := fakeRelay(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentType)
			w.WriteHeader(status)
			w.Write(body)
		})
		return client
	}
	ctx := context.Background()
	if raw, err := serve(200, ContentTypeEnvelope, env.envelope).Download(ctx, alice.agentID, env.id); err != nil || !bytes.Equal(raw, env.envelope) {
		t.Fatalf("good download: %v", err)
	}
	for name, client := range map[string]*Client{
		"other envelope":  serve(200, ContentTypeEnvelope, other.envelope),
		"malformed":       serve(200, ContentTypeEnvelope, env.envelope[:500]),
		"content type":    serve(200, ContentTypeJSON, env.envelope),
		"oversized":       serve(200, ContentTypeEnvelope, make([]byte, MaxEnvelopeBytes+1)),
		"trailing byte":   serve(200, ContentTypeEnvelope, append(append([]byte(nil), env.envelope...), 0)),
		"empty":           serve(200, ContentTypeEnvelope, nil),
		"other recipient": serve(200, ContentTypeEnvelope, bob.seal(t, testPacket(8), uint64(testStart.Unix())+600).envelope),
	} {
		if _, err := client.Download(ctx, alice.agentID, env.id); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	notFound := serve(404, ContentTypeJSON, []byte(`{"schema":"`+SchemaError+`","code":"not_found"}`))
	if _, err := notFound.Download(ctx, alice.agentID, env.id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404 download = %v", err)
	}
	var statusErr *StatusError
	if err := notFound.Ack(ctx, alice.agentID, env.id, env.secret); !errors.As(err, &statusErr) || statusErr.Code != CodeNotFound ||
		!errors.Is(err, ErrNotFound) || !errors.Is(err, ErrRejected) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("404 ack = %v", err)
	}
	// 408 is retryable: ErrRequestTimeout, never ErrRejected.
	slow := serve(408, ContentTypeJSON, []byte(`{"schema":"`+SchemaError+`","code":"request_timeout"}`))
	if err := slow.Ack(ctx, alice.agentID, env.id, env.secret); !errors.As(err, &statusErr) ||
		statusErr.Code != CodeRequestTimeout || !errors.Is(err, ErrRequestTimeout) || errors.Is(err, ErrRejected) {
		t.Fatalf("408 ack = %v", err)
	}
	forbidden := serve(403, ContentTypeJSON, []byte(`{"schema":"`+SchemaError+`","code":"forbidden"}`))
	if err := forbidden.Ack(ctx, alice.agentID, env.id, env.secret); !errors.Is(err, ErrForbidden) {
		t.Fatalf("403 ack = %v", err)
	}
	limited, _ := fakeRelay(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3")
		errorBody(w, 429, CodeRateLimited)
	})
	err := limited.Ack(ctx, alice.agentID, env.id, env.secret)
	if wait, ok := RetryAfter(err); !errors.Is(err, ErrRateLimited) || !ok || wait != 3*time.Second {
		t.Fatalf("429 ack = %v (%v)", err, wait)
	}
	if err := serve(200, ContentTypeEnvelope, nil).Ack(ctx, alice.agentID, env.id, env.secret); err == nil {
		t.Fatal("ack accepted a status other than 204")
	}
	unavailable := serve(507, ContentTypeJSON, nil)
	if _, err := unavailable.List(ctx, alice.agentID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("507 list = %v", err)
	}
	if err := serve(204, "", nil).Ack(ctx, alice.agentID, env.id, env.secret); err != nil {
		t.Fatalf("204 ack = %v", err)
	}
	// The ack request carries the secret only in the body.
	client, _ := fakeRelay(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.RawQuery != "" || !bytes.Equal(body, env.secret[:]) ||
			strings.Contains(r.URL.String(), hex.EncodeToString(env.secret[:])) ||
			r.URL.Path != "/v1/mailboxes/"+alice.agentID+"/envelopes/"+hex.EncodeToString(env.id[:])+"/ack" {
			t.Errorf("ack request %s %s", r.Method, r.URL)
		}
		w.WriteHeader(204)
	})
	if err := client.Ack(ctx, alice.agentID, env.id, env.secret); err != nil {
		t.Fatal(err)
	}
}
