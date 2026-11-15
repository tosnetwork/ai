package agentpacketrelay

import (
	"net/http"
	"strconv"
	"sync/atomic"
)

// Metrics counts what a relay answered and refused, for its operator. Every
// series is labelled only by a fixed enum (route class, status code,
// connection bound): no Agent ID, envelope ID, client address, prefix or
// other per-request value is ever recorded, and the counters are a fixed
// set of atomics, so counting allocates nothing per client and never grows
// with traffic. Counters are monotonic for the process lifetime.
type Metrics struct {
	requests      [routeClassCount][len(metricStatusCodes) + 1]atomic.Uint64
	refused       [boundCount]atomic.Uint64
	depositBytes  atomic.Uint64
	storeFailures atomic.Uint64
	sweepFailures atomic.Uint64
	open          atomic.Int64
}

// NewMetrics returns a zeroed set of counters.
func NewMetrics() *Metrics { return &Metrics{} }

// routeClass is the fixed label a request is counted under.
type routeClass int

const (
	classOther routeClass = iota
	classRelay
	classList
	classDownload
	classDeposit
	classAck
	routeClassCount
)

var routeClassNames = [routeClassCount]string{
	classOther: "other", classRelay: "relay", classList: "list", classDownload: "download",
	classDeposit: "deposit", classAck: "ack",
}

// classify names the operation a request asks for; a path that does not
// exist, or an existing path with another method, is "other".
func classify(kind route, method string) routeClass {
	switch {
	case kind == routeRelay && method == http.MethodGet:
		return classRelay
	case kind == routeList && method == http.MethodGet:
		return classList
	case kind == routeEnvelope && method == http.MethodGet:
		return classDownload
	case kind == routeEnvelope && method == http.MethodPut:
		return classDeposit
	case kind == routeAck && method == http.MethodPost:
		return classAck
	default:
		return classOther
	}
}

// metricStatusCodes are every status the relay handler answers. Anything
// else (none today) is counted under code="other".
var metricStatusCodes = [...]int{
	http.StatusOK, http.StatusCreated, http.StatusNoContent,
	http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed,
	http.StatusRequestTimeout, http.StatusConflict, http.StatusGone, http.StatusRequestEntityTooLarge,
	http.StatusUnprocessableEntity, http.StatusTooManyRequests, http.StatusServiceUnavailable,
	statusInsufficientSave,
}

func statusIndex(status int) int {
	for index, code := range metricStatusCodes {
		if code == status {
			return index
		}
	}
	return len(metricStatusCodes)
}

// connectionBound names the listener bound that refused a connection.
type connectionBound int

const (
	boundGlobal connectionBound = iota
	boundClient
	bound48
	boundCount
)

var boundNames = [boundCount]string{boundGlobal: "global", boundClient: "client", bound48: "per48"}

func (m *Metrics) observe(class routeClass, status int) {
	m.requests[class][statusIndex(status)].Add(1)
}

// RecordSweepFailure counts one failed expiry sweep.
func (m *Metrics) RecordSweepFailure() { m.sweepFailures.Add(1) }

// statusWriter records the first status written, for counting. Unwrap lets
// http.ResponseController reach the connection beneath.
type statusWriter struct {
	http.ResponseWriter
	status     int
	class      routeClass
	classified bool
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// connWriter returns the server's own writer beneath a statusWriter, so
// http.MaxBytesReader can still mark an oversized request's connection for
// closing exactly as without counting.
func connWriter(w http.ResponseWriter) http.ResponseWriter {
	if counted, ok := w.(*statusWriter); ok {
		return counted.ResponseWriter
	}
	return w
}

// MetricsContentType is the Prometheus text exposition format.
const MetricsContentType = "text/plain; version=0.0.4; charset=utf-8"

// Handler serves the counters at GET /metrics in the Prometheus text
// exposition format, with the stored-entry gauges of store when it is not
// nil. The gauges come from the store's own accounting under one lock; a
// scrape never reads the disk.
func (m *Metrics) Handler(store *Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/metrics" || request.URL.RawQuery != "" {
			http.NotFound(w, request)
			return
		}
		if request.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body := m.appendText(make([]byte, 0, 8<<10), store)
		header := w.Header()
		header.Set("Content-Type", MetricsContentType)
		header.Set("Content-Length", strconv.Itoa(len(body)))
		header.Set("Cache-Control", "no-store")
		header.Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
}

func appendFamily(out []byte, name, kind, help string) []byte {
	out = append(out, "# HELP "+name+" "+help+"\n# TYPE "+name+" "+kind+"\n"...)
	return out
}

func appendSample(out []byte, name, labels string, value uint64) []byte {
	out = append(out, name...)
	if labels != "" {
		out = append(out, '{')
		out = append(out, labels...)
		out = append(out, '}')
	}
	out = append(out, ' ')
	out = strconv.AppendUint(out, value, 10)
	return append(out, '\n')
}

func nonNegative[T int | int64](value T) uint64 {
	if value < 0 {
		return 0
	}
	return uint64(value)
}

// appendText writes every series, zeros included, so each one exists from
// the first scrape.
func (m *Metrics) appendText(out []byte, store *Store) []byte {
	const requests = "packet_relay_requests_total"
	out = appendFamily(out, requests, "counter", "Requests answered, by route class and status code.")
	for class := range routeClassCount {
		for index := range len(metricStatusCodes) + 1 {
			code := "other"
			if index < len(metricStatusCodes) {
				code = strconv.Itoa(metricStatusCodes[index])
			}
			out = appendSample(out, requests, `route="`+routeClassNames[class]+`",code="`+code+`"`,
				m.requests[class][index].Load())
		}
	}
	const refused = "packet_relay_connections_refused_total"
	out = appendFamily(out, refused, "counter", "Connections closed at accept, by the bound that refused them.")
	for bound := range boundCount {
		out = appendSample(out, refused, `bound="`+boundNames[bound]+`"`, m.refused[bound].Load())
	}
	out = appendFamily(out, "packet_relay_deposit_bytes_total", "counter", "Envelope bytes of deposits answered 201.")
	out = appendSample(out, "packet_relay_deposit_bytes_total", "", m.depositBytes.Load())
	out = appendFamily(out, "packet_relay_store_failures_total", "counter", "Requests answered 503 after a logged store failure.")
	out = appendSample(out, "packet_relay_store_failures_total", "", m.storeFailures.Load())
	out = appendFamily(out, "packet_relay_sweep_failures_total", "counter", "Failed expiry sweeps.")
	out = appendSample(out, "packet_relay_sweep_failures_total", "", m.sweepFailures.Load())
	out = appendFamily(out, "packet_relay_open_connections", "gauge", "Connections the relay listener holds open.")
	out = appendSample(out, "packet_relay_open_connections", "", nonNegative(m.open.Load()))
	if store != nil {
		usage := store.Usage()
		out = appendFamily(out, "packet_relay_stored_envelopes", "gauge", "Envelopes stored.")
		out = appendSample(out, "packet_relay_stored_envelopes", "", nonNegative(usage.Envelopes))
		out = appendFamily(out, "packet_relay_stored_tombstones", "gauge", "Tombstones stored.")
		out = appendSample(out, "packet_relay_stored_tombstones", "", nonNegative(usage.Tombstones))
		out = appendFamily(out, "packet_relay_stored_entries", "gauge", "Envelopes plus tombstones, against the global entry limit.")
		out = appendSample(out, "packet_relay_stored_entries", "", nonNegative(usage.Envelopes)+nonNegative(usage.Tombstones))
		out = appendFamily(out, "packet_relay_stored_bytes", "gauge", "Stored envelope bytes, against the global byte limit.")
		out = appendSample(out, "packet_relay_stored_bytes", "", nonNegative(usage.Bytes))
		limits := store.Limits()
		out = appendFamily(out, "packet_relay_global_max_entries", "gauge", "Configured global entry limit.")
		out = appendSample(out, "packet_relay_global_max_entries", "", nonNegative(limits.GlobalMaxEntries))
		out = appendFamily(out, "packet_relay_global_max_bytes", "gauge", "Configured global byte limit.")
		out = appendSample(out, "packet_relay_global_max_bytes", "", nonNegative(limits.GlobalMaxBytes))
	}
	return out
}
