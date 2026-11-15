package agentpacketrelay

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// exposition is a parsed scrape: each series ("name" or
// `name{label="value",...}`) to its value.
type exposition map[string]uint64

var (
	metricLine = regexp.MustCompile(`^([a-z_]+)(\{[a-z0-9_]+="[a-z0-9]+"(,[a-z0-9_]+="[a-z0-9]+")*\})? ([0-9]+)$`)
	helpLine   = regexp.MustCompile(`^# HELP ([a-z_]+) [^\n]+$`)
	typeLine   = regexp.MustCompile(`^# TYPE ([a-z_]+) (counter|gauge)$`)
)

// allowedLabels is every label value a series may carry: fixed enums only.
var allowedLabels = map[string]map[string]bool{
	"route": {"other": true, "relay": true, "list": true, "download": true, "deposit": true, "ack": true},
	"code": {"200": true, "201": true, "204": true, "400": true, "403": true, "404": true, "405": true,
		"408": true, "409": true, "410": true, "413": true, "422": true, "429": true, "503": true, "507": true,
		"other": true},
	"bound": {"global": true, "client": true, "per48": true},
}

// parseExposition checks the text exposition format strictly: every family
// has HELP then TYPE before its samples, counters end in _total, no series
// repeats, and every label value is a fixed enum.
func parseExposition(t testing.TB, text string) exposition {
	t.Helper()
	out := exposition{}
	types := map[string]string{}
	helped := map[string]bool{}
	if !strings.HasSuffix(text, "\n") {
		t.Fatal("exposition does not end with a newline")
	}
	for number, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if match := helpLine.FindStringSubmatch(line); match != nil {
			if helped[match[1]] {
				t.Fatalf("line %d: second HELP for %s", number+1, match[1])
			}
			helped[match[1]] = true
			continue
		}
		if match := typeLine.FindStringSubmatch(line); match != nil {
			if !helped[match[1]] || types[match[1]] != "" {
				t.Fatalf("line %d: TYPE for %s without one preceding HELP", number+1, match[1])
			}
			if (match[2] == "counter") != strings.HasSuffix(match[1], "_total") {
				t.Fatalf("line %d: %s is a %s", number+1, match[1], match[2])
			}
			types[match[1]] = match[2]
			continue
		}
		match := metricLine.FindStringSubmatch(line)
		if match == nil {
			t.Fatalf("line %d is not a sample: %q", number+1, line)
		}
		if types[match[1]] == "" {
			t.Fatalf("line %d: sample of %s before its TYPE", number+1, match[1])
		}
		if labels := strings.Trim(match[2], "{}"); labels != "" {
			for _, pair := range strings.Split(labels, ",") {
				name, value, _ := strings.Cut(pair, "=")
				if !allowedLabels[name][strings.Trim(value, `"`)] {
					t.Fatalf("line %d: label %s outside the fixed enums", number+1, pair)
				}
			}
		}
		series := match[1] + match[2]
		if _, seen := out[series]; seen {
			t.Fatalf("line %d: series %s repeats", number+1, series)
		}
		value, err := strconv.ParseUint(match[4], 10, 64)
		if err != nil {
			t.Fatalf("line %d: %v", number+1, err)
		}
		out[series] = value
	}
	return out
}

func requestsSeries(route string, code int) string {
	return fmt.Sprintf(`packet_relay_requests_total{route="%s",code="%d"}`, route, code)
}

// scrape reads the handler as a scraper does and returns the raw text.
func scrape(t testing.TB, metrics *Metrics, store *Store) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	metrics.Handler(store).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != MetricsContentType {
		t.Fatalf("scrape = %d %q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	return recorder.Body.String()
}

func withMetrics(metrics *Metrics) relayOption {
	return func(c *ServerConfig) { c.Metrics = metrics }
}

// expectCounts checks the named series against want and every other request
// series against zero, so a request counted twice or in the wrong place
// fails.
func expectCounts(t testing.TB, got exposition, want map[string]uint64) {
	t.Helper()
	for series, value := range got {
		if !strings.HasPrefix(series, "packet_relay_requests_total") {
			continue
		}
		if value != want[series] {
			t.Errorf("%s = %d, want %d", series, value, want[series])
		}
	}
	for series, value := range want {
		if got[series] != value {
			t.Errorf("%s = %d, want %d", series, got[series], value)
		}
	}
}

// TestMetricsCountEveryAnswer drives every status the handler answers on
// its real path and checks each lands under its route class and code.
func TestMetricsCountEveryAnswer(t *testing.T) {
	metrics := NewMetrics()
	limits := testLimits()
	limits.PerRecipientMaxEnvelopes = 2
	backend := newMemoryBackend()
	store, err := newStore(limits, backend)
	if err != nil {
		t.Fatal(err)
	}
	relay := newTestRelayWithStore(t, store, newClock(), withMetrics(metrics))
	alice, bob := newRecipient(t), newRecipient(t)
	now := relay.clock.unix()
	env := alice.seal(t, testPacket(64), now+600)
	listURL := relay.client.BaseURL() + "/v1/mailboxes/" + alice.agentID + "/envelopes"

	expectStatus(t, relay.do(http.MethodGet, relay.client.BaseURL()+"/v1/relay", "", nil), 200)
	expectStatus(t, relay.putSealed(env), 201)
	expectStatus(t, relay.putSealed(env), 200)
	junk := append([]byte(nil), env.envelope...)
	junk[len(junk)-1] ^= 1
	expectStatus(t, relay.put(alice.agentID, env.id, junk), 409)
	expectStatus(t, relay.do(http.MethodPut, relay.envelopeURL(alice.agentID, env.id), "application/json", env.envelope), 400)
	expectStatus(t, relay.put(alice.agentID, env.id, make([]byte, MaxEnvelopeBytes+1)), 413)
	expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), now)), 422)
	second := alice.seal(t, testPacket(8), now+600)
	expectStatus(t, relay.putSealed(second), 201)
	expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), now+600)), 507)
	decodeList(t, relay.do(http.MethodGet, listURL, "", nil))
	expectStatus(t, relay.do(http.MethodGet, relay.envelopeURL(alice.agentID, env.id), "", nil), 200)
	expectStatus(t, relay.do(http.MethodGet, relay.envelopeURL(bob.agentID, env.id), "", nil), 404)
	wrong := env.secret
	wrong[0] ^= 1
	expectStatus(t, relay.ackRaw(alice.agentID, env.id, wrong[:]), 403)
	expectStatus(t, relay.ackRaw(alice.agentID, env.id, env.secret[:31]), 400)
	expectStatus(t, relay.ackRaw(bob.agentID, env.id, env.secret[:]), 404)
	expectStatus(t, relay.ackRaw(alice.agentID, env.id, env.secret[:]), 204)
	expectStatus(t, relay.putSealed(env), 410)
	expectStatus(t, relay.do(http.MethodGet, relay.client.BaseURL()+"/v1/nothing", "", nil), 404)
	expectStatus(t, relay.do(http.MethodDelete, relay.envelopeURL(alice.agentID, env.id), "", nil), 405)
	// Refused before the route is matched, still counted under its route.
	expectStatus(t, relay.do(http.MethodGet, listURL+"?x", "", nil), 400)
	request := httptest.NewRequest(http.MethodPut, relay.envelopeURL(alice.agentID, env.id), strings.NewReader("x"))
	request.RemoteAddr = "not an address"
	recorder := httptest.NewRecorder()
	relay.server.ServeHTTP(recorder, request)
	expectStatus(t, recorderResponse(recorder), 400)
	// A store failure: 503, and one store failure.
	backend.mu.Lock()
	backend.failWrites = true
	backend.mu.Unlock()
	expectStatus(t, relay.ackRaw(alice.agentID, second.id, second.secret[:]), 503)

	got := parseExposition(t, scrape(t, metrics, store))
	expectCounts(t, got, map[string]uint64{
		requestsSeries("relay", 200):    1,
		requestsSeries("deposit", 201):  2,
		requestsSeries("deposit", 200):  1,
		requestsSeries("deposit", 409):  1,
		requestsSeries("deposit", 400):  2,
		requestsSeries("deposit", 413):  1,
		requestsSeries("deposit", 422):  1,
		requestsSeries("deposit", 507):  1,
		requestsSeries("deposit", 410):  1,
		requestsSeries("list", 200):     1,
		requestsSeries("list", 400):     1,
		requestsSeries("download", 200): 1,
		requestsSeries("download", 404): 1,
		requestsSeries("ack", 403):      1,
		requestsSeries("ack", 400):      1,
		requestsSeries("ack", 404):      1,
		requestsSeries("ack", 204):      1,
		requestsSeries("ack", 503):      1,
		requestsSeries("other", 404):    1,
		requestsSeries("other", 405):    1,
	})
	if want := uint64(len(env.envelope) + len(second.envelope)); got["packet_relay_deposit_bytes_total"] != want {
		t.Errorf("deposit bytes = %d, want %d", got["packet_relay_deposit_bytes_total"], want)
	}
	if got["packet_relay_store_failures_total"] != 1 {
		t.Errorf("store failures = %d", got["packet_relay_store_failures_total"])
	}
	usage := store.Usage()
	if got["packet_relay_stored_envelopes"] != uint64(usage.Envelopes) || got["packet_relay_stored_envelopes"] != 1 ||
		got["packet_relay_stored_tombstones"] != 1 || got["packet_relay_stored_entries"] != 2 ||
		got["packet_relay_stored_bytes"] != uint64(len(second.envelope)) {
		t.Errorf("store gauges = %v, usage %+v", got, usage)
	}
	if got["packet_relay_global_max_entries"] != uint64(limits.GlobalMaxEntries) ||
		got["packet_relay_global_max_bytes"] != uint64(limits.GlobalMaxBytes) {
		t.Error("limit gauges differ from the store limits")
	}
	assertNoIdentifiers(t, scrape(t, metrics, store), alice.agentID, bob.agentID, hex.EncodeToString(env.id[:]),
		hex.EncodeToString(second.id[:]), "127.0.0.1", "not an address")
}

// assertNoIdentifiers fails if a scrape carries any identifier a test used,
// in any spelling a label could take.
func assertNoIdentifiers(t testing.TB, text string, identifiers ...string) {
	t.Helper()
	for _, identifier := range identifiers {
		for _, form := range []string{identifier, strings.TrimPrefix(identifier, "agent_"), strings.ToUpper(identifier)} {
			if len(form) >= 8 && strings.Contains(text, form) {
				t.Fatalf("the scrape carries %q", form)
			}
		}
	}
	// Even a fragment of an identifier cannot hide in a label: every label
	// value is a fixed enum (checked by parseExposition) and every value a
	// number.
	if regexp.MustCompile(`[0-9a-f]{16}`).MatchString(text) {
		t.Fatal("the scrape carries a hex string")
	}
}

// TestMetricsRateLimitAndBodyBounds: 429 from the rate limiter and from
// the per-client body bound, 503 from the shared body bound and 408 from a
// trickled body are each counted under deposit or list.
func TestMetricsRateLimitAndBodyBounds(t *testing.T) {
	t.Run("rate limit", func(t *testing.T) {
		metrics := NewMetrics()
		relay := newTestRelay(t, testLimits(), withMetrics(metrics), func(c *ServerConfig) {
			c.DepositRate = RateLimit{PerMinute: 60, Burst: 1}
			c.ReadRate = RateLimit{PerMinute: 60, Burst: 1}
		})
		alice := newRecipient(t)
		expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600)), 201)
		expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600)), 429)
		listURL := relay.client.BaseURL() + "/v1/mailboxes/" + alice.agentID + "/envelopes"
		decodeList(t, relay.do(http.MethodGet, listURL, "", nil))
		expectStatus(t, relay.do(http.MethodGet, listURL, "", nil), 429)
		expectCounts(t, parseExposition(t, scrape(t, metrics, relay.store)), map[string]uint64{
			requestsSeries("deposit", 201): 1, requestsSeries("deposit", 429): 1,
			requestsSeries("list", 200): 1, requestsSeries("list", 429): 1,
		})
	})
	t.Run("body bounds", func(t *testing.T) {
		metrics := NewMetrics()
		relay, backend, gate := gatedRelay(t, withMetrics(metrics), func(c *ServerConfig) {
			c.MaxConcurrentDeposits = 2
			c.MaxConcurrentDepositsPerClient = 1
			c.MaxConcurrentDepositsPer48 = 1
			c.TrustedProxies = []netipPrefix{mustPrefix(t, "127.0.0.1/32")}
		})
		alice := newRecipient(t)
		from := func(addr string) []string { return []string{"X-Forwarded-For", addr} }
		held := alice.seal(t, testPacket(8), relay.clock.unix()+600)
		done := make(chan response, 2)
		go func() { done <- relay.putSealed(held, from("198.51.100.1")...) }()
		waitBusy(t, relay.store)
		other := alice.seal(t, testPacket(8), relay.clock.unix()+600)
		go func() { done <- relay.putSealed(other, from("198.51.100.2")...) }()
		waitFor(t, func() bool { return len(relay.server.bodies) == 2 })
		// The same client again: past its own share, 429.
		expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600), from("198.51.100.1")...), 429)
		// A third client: every shared slot is held, 503.
		expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600), from("198.51.100.3")...), 503)
		openGate(backend, gate)
		expectStatus(t, <-done, 201)
		expectStatus(t, <-done, 201)
		got := parseExposition(t, scrape(t, metrics, relay.store))
		expectCounts(t, got, map[string]uint64{
			requestsSeries("deposit", 201): 2, requestsSeries("deposit", 429): 1, requestsSeries("deposit", 503): 1,
		})
		if got["packet_relay_store_failures_total"] != 0 {
			t.Fatal("a full body table was counted as a store failure")
		}
	})
	t.Run("trickled body", func(t *testing.T) {
		metrics := NewMetrics()
		relay := newTestRelay(t, testLimits(), withMetrics(metrics), func(c *ServerConfig) {
			c.DepositReadBase = 200 * time.Millisecond
			c.DepositMinBytesPerSecond = 1 << 30
		})
		alice := newRecipient(t)
		env := alice.seal(t, testPacket(8), relay.clock.unix()+600)
		conn, err := net.Dial("tcp", strings.TrimPrefix(relay.http.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		head := "PUT /v1/mailboxes/" + alice.agentID + "/envelopes/" + hex.EncodeToString(env.id[:]) + " HTTP/1.1\r\n" +
			"Host: relay\r\nContent-Type: application/octet-stream\r\nContent-Length: " + strconv.Itoa(len(env.envelope)) + "\r\n\r\n"
		if _, err := io.WriteString(conn, head+string(env.envelope[:1])); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		answer, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, answer.Body)
		answer.Body.Close()
		if answer.StatusCode != http.StatusRequestTimeout {
			t.Fatalf("trickled body = %d", answer.StatusCode)
		}
		waitFor(t, func() bool {
			return parseExposition(t, scrape(t, metrics, relay.store))[requestsSeries("deposit", 408)] == 1
		})
	})
}

// TestMetricsConnectionBounds counts each bound's refusals and the open
// connection gauge on the real listener.
func TestMetricsConnectionBounds(t *testing.T) {
	t.Run("global and client", func(t *testing.T) {
		metrics := NewMetrics()
		inner, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		wrapped, err := NewLimitListener(inner, ListenerLimits{MaxConnections: 2, MaxConnectionsPerClient: 1, Metrics: metrics})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { wrapped.Close() })
		accepted := acceptLoop(t, wrapped)
		dialFrom(t, "127.0.0.1", inner.Addr())
		held := expectAccepted(t, accepted, 1)
		if !refused(t, dialFrom(t, "127.0.0.1", inner.Addr())) {
			t.Fatal("a second connection from one address was kept")
		}
		dialFrom(t, "127.0.0.2", inner.Addr())
		expectAccepted(t, accepted, 1)
		if !refused(t, dialFrom(t, "127.0.0.3", inner.Addr())) {
			t.Fatal("a connection past the total was kept")
		}
		got := parseExposition(t, scrape(t, metrics, nil))
		if got[`packet_relay_connections_refused_total{bound="global"}`] != 1 ||
			got[`packet_relay_connections_refused_total{bound="client"}`] != 1 ||
			got[`packet_relay_connections_refused_total{bound="per48"}`] != 0 || got["packet_relay_open_connections"] != 2 {
			t.Fatalf("connection metrics = %v", got)
		}
		if _, ok := got["packet_relay_stored_entries"]; ok {
			t.Fatal("store gauges without a store")
		}
		held[0].Close()
		waitFor(t, func() bool { return parseExposition(t, scrape(t, metrics, nil))["packet_relay_open_connections"] == 1 })
		assertNoIdentifiers(t, scrape(t, metrics, nil), "127.0.0.1", "127.0.0.2", "127.0.0.3")
	})
	t.Run("per /48", func(t *testing.T) {
		metrics := NewMetrics()
		inner := newFakeListener()
		wrapped, err := NewLimitListener(inner, ListenerLimits{MaxConnections: 100, MaxConnectionsPerClient: 1,
			MaxConnectionsPer48: 2, Metrics: metrics})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { wrapped.Close() })
		accepted := acceptLoop(t, wrapped)
		for index, want := range []bool{true, true, false} {
			if got := offer(t, inner, accepted, fmt.Sprintf("[2001:db8:7:%x::1]:1000", index)); got != want {
				t.Fatalf("/64 %d accepted = %v", index, got)
			}
		}
		got := parseExposition(t, scrape(t, metrics, nil))
		if got[`packet_relay_connections_refused_total{bound="per48"}`] != 1 ||
			got[`packet_relay_connections_refused_total{bound="client"}`] != 0 ||
			got[`packet_relay_connections_refused_total{bound="global"}`] != 0 {
			t.Fatalf("per-48 refusals = %v", got)
		}
		assertNoIdentifiers(t, scrape(t, metrics, nil), "2001:db8:7", "2001:0db8")
	})
}

// TestMetricsHandlerRoutes: only GET /metrics is served.
func TestMetricsHandlerRoutes(t *testing.T) {
	handler := NewMetrics().Handler(nil)
	for _, c := range []struct {
		method, target string
		want           int
	}{
		{http.MethodGet, "/metrics", 200}, {http.MethodPost, "/metrics", 405}, {http.MethodHead, "/metrics", 405},
		{http.MethodGet, "/", 404}, {http.MethodGet, "/metrics/", 404}, {http.MethodGet, "/metrics?x=1", 404},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(c.method, c.target, nil))
		if recorder.Code != c.want {
			t.Errorf("%s %s = %d, want %d", c.method, c.target, recorder.Code, c.want)
		}
	}
	// Every series exists from the first scrape, at zero.
	got := parseExposition(t, scrape(t, NewMetrics(), nil))
	if len(got) != int(routeClassCount)*(len(metricStatusCodes)+1)+int(boundCount)+4 {
		t.Fatalf("a fresh scrape has %d series", len(got))
	}
	for series, value := range got {
		if value != 0 {
			t.Fatalf("fresh %s = %d", series, value)
		}
	}
}

// TestMetricsRace: concurrent deposits, lists, acknowledgements, refused
// connections and scrapes; under -race the counters are data-race free, and
// at the end they add up exactly.
func TestMetricsRace(t *testing.T) {
	metrics := NewMetrics()
	store, err := NewMemoryStore(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	config := ServerConfig{Store: store, Metrics: metrics, MaxConcurrentDepositsPerClient: DefaultMaxConcurrentDeposits,
		DepositRate: RateLimit{PerMinute: 1 << 20, Burst: 1 << 20}, ReadRate: RateLimit{PerMinute: 1 << 20, Burst: 1 << 20}}
	server, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := NewLimitListener(inner, ListenerLimits{MaxConnections: 64, MaxConnectionsPerClient: 64, Metrics: metrics})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewUnstartedServer(server)
	httpServer.Listener = listener
	httpServer.Start()
	t.Cleanup(httpServer.Close)
	client, err := NewClient(ClientConfig{BaseURL: httpServer.URL, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	relay := &testRelay{t: t, clock: newClock(), store: store, server: server, http: httpServer, client: client}
	const workers, rounds = 8, 10
	var wg sync.WaitGroup
	errs := make(chan error, workers*rounds*3+64)
	stop := make(chan struct{})
	var scrapes sync.WaitGroup
	scrapes.Add(1)
	go func() {
		defer scrapes.Done()
		for {
			select {
			case <-stop:
				return
			default:
				parseExposition(t, scrape(t, metrics, store))
			}
		}
	}()
	agents := make([]recipient, workers)
	for index := range agents {
		agents[index] = newRecipient(t)
	}
	for worker := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			agent := agents[worker]
			for range rounds {
				env := agent.seal(t, testPacket(32), uint64(time.Now().Unix())+600)
				if got := relay.putSealed(env); got.status != 201 {
					errs <- fmt.Errorf("deposit = %d", got.status)
				}
				if got := relay.do(http.MethodGet, client.BaseURL()+"/v1/mailboxes/"+agent.agentID+"/envelopes", "", nil); got.status != 200 {
					errs <- fmt.Errorf("list = %d", got.status)
				}
				if got := relay.ackRaw(agent.agentID, env.id, env.secret[:]); got.status != 204 {
					errs <- fmt.Errorf("ack = %d", got.status)
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	scrapes.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	got := parseExposition(t, scrape(t, metrics, store))
	total := uint64(workers * rounds)
	expectCounts(t, got, map[string]uint64{
		requestsSeries("deposit", 201): total, requestsSeries("list", 200): total, requestsSeries("ack", 204): total,
	})
	if got["packet_relay_stored_envelopes"] != 0 || got["packet_relay_stored_tombstones"] != total {
		t.Fatalf("store gauges = %d envelopes, %d tombstones", got["packet_relay_stored_envelopes"], got["packet_relay_stored_tombstones"])
	}
}
