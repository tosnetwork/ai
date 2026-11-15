package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
)

func TestMetricsListenRestrictedToLoopback(t *testing.T) {
	base := []string{"-state-dir", "/var/lib/relay", "-global-max-entries", "1000", "-global-max-bytes", "1073741824"}
	opts, err := parseOptions(base, io.Discard)
	if err != nil || opts.metricsListen != "" {
		t.Fatalf("metrics are on by default: %q, %v", opts.metricsListen, err)
	}
	for _, listen := range []string{"127.0.0.1:9095", "[::1]:9095", "localhost:9095", "127.0.0.2:0"} {
		if _, err := parseOptions(append(append([]string(nil), base...), "-metrics-listen", listen), io.Discard); err != nil {
			t.Errorf("%s refused: %v", listen, err)
		}
	}
	for _, listen := range []string{"0.0.0.0:9095", ":9095", "192.0.2.1:9095", "203.0.113.7:9095", "[::]:9095",
		"[2001:db8::1]:9095", "example.com:9095", "127.0.0.1", "127.0.0.1:", "[::ffff:192.0.2.1]:9095"} {
		_, err := parseOptions(append(append([]string(nil), base...), "-metrics-listen", listen), io.Discard)
		if err == nil {
			t.Errorf("-metrics-listen %s accepted", listen)
		} else if !strings.Contains(err.Error(), "metrics-listen") {
			t.Errorf("-metrics-listen %s: unclear error %v", listen, err)
		}
	}
	// The daemon refuses to start, before opening its state directory.
	dir := filepath.Join(t.TempDir(), "never-created")
	err = run(context.Background(), []string{"-listen", "127.0.0.1:0", "-state-dir", dir, "-global-max-entries", "100",
		"-global-max-bytes", "67108864", "-metrics-listen", "0.0.0.0:0"}, io.Discard, nil)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("daemon with a public metrics address = %v", err)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Fatal("a refused metrics address still opened the state directory")
	}
}

type metricsDaemon struct {
	*daemon
	metrics net.Addr
}

func startMetricsDaemon(t *testing.T, args ...string) *metricsDaemon {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready, metricsReady := make(chan net.Addr, 1), make(chan net.Addr, 1)
	d := &metricsDaemon{daemon: &daemon{cancel: cancel, done: make(chan error, 1), output: &bytes.Buffer{}}}
	go func() {
		d.done <- runWithMetrics(ctx, args, d.output, func(addr net.Addr) { ready <- addr },
			func(addr net.Addr) { metricsReady <- addr })
	}()
	for d.addr == nil || d.metrics == nil {
		select {
		case d.addr = <-ready:
		case d.metrics = <-metricsReady:
		case err := <-d.done:
			t.Fatalf("daemon exited: %v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("daemon did not start")
		}
	}
	return d
}

func scrapeDaemon(t *testing.T, addr net.Addr) string {
	t.Helper()
	response, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + addr.String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != agentpacketrelay.MetricsContentType {
		t.Fatalf("scrape = %d %q, %v", response.StatusCode, response.Header.Get("Content-Type"), err)
	}
	return string(body)
}

// metricValue reads one series from a scrape; a missing series fails.
func metricValue(t *testing.T, text, series string) uint64 {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if value, ok := strings.CutPrefix(line, series+" "); ok {
			parsed, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				t.Fatalf("%s: %v", line, err)
			}
			return parsed
		}
	}
	t.Fatalf("series %s missing", series)
	return 0
}

// TestDaemonMetrics: with -metrics-listen the daemon serves the counters on
// their own loopback listener, counts real traffic and carries no
// identifier; the relay listener does not serve them.
func TestDaemonMetrics(t *testing.T) {
	d := startMetricsDaemon(t, "-listen", "127.0.0.1:0", "-state-dir", t.TempDir(), "-global-max-entries", "100",
		"-global-max-bytes", "67108864", "-max-connections", "8", "-max-connections-per-client", "2",
		"-metrics-listen", "127.0.0.1:0")
	defer d.stop(t)
	oneShot := &http.Transport{DisableKeepAlives: true}
	client, err := agentpacketrelay.NewClient(agentpacketrelay.ClientConfig{BaseURL: "http://" + d.addr.String(), Transport: oneShot})
	if err != nil {
		t.Fatal(err)
	}
	agentID, envelope := sealFor(t)
	if outcome, err := client.Deposit(context.Background(), envelope); err != nil || outcome.Result != agentpacketrelay.DepositStored {
		t.Fatalf("deposit = %+v, %v", outcome, err)
	}
	if mailbox, err := client.List(context.Background(), agentID); err != nil || len(mailbox.Envelopes) != 1 {
		t.Fatalf("list = %+v, %v", mailbox, err)
	}
	// The relay listener serves no metrics.
	relayMetrics, err := oneShot.RoundTrip(mustRequest(t, "http://"+d.addr.String()+"/metrics"))
	if err != nil {
		t.Fatal(err)
	}
	relayMetrics.Body.Close()
	if relayMetrics.StatusCode != http.StatusNotFound {
		t.Fatalf("relay listener /metrics = %d", relayMetrics.StatusCode)
	}
	waitMetric(t, d.metrics, "packet_relay_open_connections", 0)
	// Two idle keep-alive connections fill this address's share; a third is
	// refused by the per-client bound.
	for range 2 {
		conn, err := net.Dial("tcp", d.addr.String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		keepAliveGet(t, conn, "/v1/relay")
	}
	extra, err := net.Dial("tcp", d.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = extra.Read(make([]byte, 1))

	waitMetric(t, d.metrics, "packet_relay_open_connections", 2)
	text := scrapeDaemon(t, d.metrics)
	for series, want := range map[string]uint64{
		`packet_relay_requests_total{route="deposit",code="201"}`: 1,
		`packet_relay_requests_total{route="list",code="200"}`:    1,
		`packet_relay_requests_total{route="relay",code="200"}`:   2,
		`packet_relay_requests_total{route="deposit",code="507"}`: 0,
		`packet_relay_requests_total{route="other",code="404"}`:   1,
		`packet_relay_connections_refused_total{bound="client"}`:  1,
		`packet_relay_connections_refused_total{bound="global"}`:  0,
		`packet_relay_connections_refused_total{bound="per48"}`:   0,
		"packet_relay_deposit_bytes_total":                        uint64(len(envelope)),
		"packet_relay_stored_envelopes":                           1,
		"packet_relay_stored_entries":                             1,
		"packet_relay_stored_bytes":                               uint64(len(envelope)),
		"packet_relay_global_max_entries":                         100,
		"packet_relay_global_max_bytes":                           67108864,
		"packet_relay_store_failures_total":                       0,
		"packet_relay_sweep_failures_total":                       0,
	} {
		if got := metricValue(t, text, series); got != want {
			t.Errorf("%s = %d, want %d", series, got, want)
		}
	}
	_, port, err := net.SplitHostPort(d.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, identifier := range []string{agentID, agentID[len("agent_"):], "127.0.0.1", d.addr.String(), " " + port + "\n"} {
		if strings.Contains(text, identifier) {
			t.Fatalf("the scrape carries %q", identifier)
		}
	}
	// Only GET /metrics is served on the metrics listener.
	post, err := http.Post("http://"+d.metrics.String()+"/metrics", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics = %d", post.StatusCode)
	}
	other, err := http.Get("http://" + d.metrics.String() + "/v1/relay")
	if err != nil {
		t.Fatal(err)
	}
	other.Body.Close()
	if other.StatusCode != http.StatusNotFound {
		t.Fatalf("metrics listener /v1/relay = %d", other.StatusCode)
	}
	if !strings.Contains(d.output.String(), "agent packet relay metrics listening") {
		t.Fatal("the metrics listener was not logged")
	}
}

// waitMetric waits until a series reaches want: connection accounting is
// released when the server side closes, a moment after the client sees the
// answer.
func waitMetric(t *testing.T, addr net.Addr, series string, want uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for metricValue(t, scrapeDaemon(t, addr), series) != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not reach %d", series, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func mustRequest(t *testing.T, target string) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

// TestDaemonWithoutMetrics: without the flag no metrics listener opens.
func TestDaemonWithoutMetrics(t *testing.T) {
	d := startDaemon(t, "-listen", "127.0.0.1:0", "-state-dir", t.TempDir(), "-global-max-entries", "100",
		"-global-max-bytes", "67108864")
	d.stop(t)
	if strings.Contains(d.output.String(), "metrics") {
		t.Fatalf("a daemon without -metrics-listen logged metrics: %s", d.output.String())
	}
}

// TestDaemonSweepFailureCounted: an expiry sweep that cannot remove an
// expired envelope is counted.
func TestDaemonSweepFailureCounted(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	state := t.TempDir()
	d := startMetricsDaemon(t, "-listen", "127.0.0.1:0", "-state-dir", state, "-global-max-entries", "100",
		"-global-max-bytes", "67108864", "-ttl", "1s", "-sweep-interval", "1s", "-metrics-listen", "127.0.0.1:0")
	defer d.stop(t)
	client, err := agentpacketrelay.NewClient(agentpacketrelay.ClientConfig{BaseURL: "http://" + d.addr.String()})
	if err != nil {
		t.Fatal(err)
	}
	_, envelope := sealFor(t)
	if outcome, err := client.Deposit(context.Background(), envelope); err != nil || outcome.Result != agentpacketrelay.DepositStored {
		t.Fatalf("deposit = %+v, %v", outcome, err)
	}
	envelopes := filepath.Join(state, "envelopes")
	if err := os.Chmod(envelopes, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(envelopes, 0o700) })
	deadline := time.Now().Add(10 * time.Second)
	for metricValue(t, scrapeDaemon(t, d.metrics), "packet_relay_sweep_failures_total") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a failed sweep was not counted")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := os.Chmod(envelopes, 0o700); err != nil {
		t.Fatal(err)
	}
}
