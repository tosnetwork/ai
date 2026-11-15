package agentpacketrelay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// ServerConfig configures the relay HTTP API.
type ServerConfig struct {
	// Store holds the envelopes. Required.
	Store *Store
	// BasePath is the path of the relay base URL: empty, or beginning with
	// "/" and not ending with "/".
	BasePath string
	// DepositRate and ReadRate are per client address; zero values take
	// DefaultDepositRate and DefaultReadRate.
	DepositRate RateLimit
	ReadRate    RateLimit
	// MaxRateClients bounds each rate-limiter table; zero takes
	// DefaultMaxRateClients.
	MaxRateClients int
	// TrustedProxies are the peers whose X-Forwarded-For is believed. Empty
	// means the TCP peer is always the client.
	TrustedProxies []netip.Prefix
	// Now is the clock; nil takes time.Now.
	Now func() time.Time
	// Logger receives persistence failures only; nil discards them. Request
	// bodies, paths and client addresses are never logged.
	Logger *slog.Logger
}

// Server is the relay HTTP API of Agent Packet Relay V1.
type Server struct {
	store    *Store
	base     string
	deposits *rateLimiter
	reads    *rateLimiter
	trusted  []netip.Prefix
	now      func() time.Time
	logger   *slog.Logger
}

// NewServer checks the configuration and returns the handler.
func NewServer(config ServerConfig) (*Server, error) {
	if config.Store == nil {
		return nil, errors.New("agentpacketrelay: a store is required")
	}
	if config.BasePath != "" && (!strings.HasPrefix(config.BasePath, "/") || strings.HasSuffix(config.BasePath, "/") ||
		strings.ContainsAny(config.BasePath, "%?#") || strings.Contains(config.BasePath, "//")) {
		return nil, errors.New("agentpacketrelay: base path must be empty or /segment[/segment...] with no trailing slash")
	}
	deposit, read := config.DepositRate, config.ReadRate
	if deposit == (RateLimit{}) {
		deposit = DefaultDepositRate
	}
	if read == (RateLimit{}) {
		read = DefaultReadRate
	}
	if err := deposit.validate(); err != nil {
		return nil, fmt.Errorf("agentpacketrelay: deposit rate: %w", err)
	}
	if err := read.validate(); err != nil {
		return nil, fmt.Errorf("agentpacketrelay: read rate: %w", err)
	}
	maxClients := config.MaxRateClients
	if maxClients == 0 {
		maxClients = DefaultMaxRateClients
	}
	if maxClients < 0 {
		return nil, errors.New("agentpacketrelay: rate-limiter table bound must be positive")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Server{store: config.Store, base: config.BasePath, deposits: newRateLimiter(deposit, maxClients),
		reads: newRateLimiter(read, maxClients), trusted: append([]netip.Prefix(nil), config.TrustedProxies...),
		now: now, logger: logger}, nil
}

type route int

const (
	routeNone route = iota
	routeRelay
	routeList
	routeEnvelope
	routeAck
)

// parseRoute matches the escaped request path exactly: no normalization, no
// percent-escapes, no trailing slash, canonical Agent and envelope IDs.
func (s *Server) parseRoute(escapedPath string) (route, agentDigest, string, [32]byte) {
	var none [32]byte
	rest, ok := strings.CutPrefix(escapedPath, s.base+"/v1/")
	if !ok {
		return routeNone, agentDigest{}, "", none
	}
	if rest == "relay" {
		return routeRelay, agentDigest{}, "", none
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 3 || len(parts) > 5 || parts[0] != "mailboxes" || parts[2] != "envelopes" {
		return routeNone, agentDigest{}, "", none
	}
	agent, ok := parseAgentText(parts[1])
	if !ok {
		return routeNone, agentDigest{}, "", none
	}
	if len(parts) == 3 {
		return routeList, agent, parts[1], none
	}
	id, ok := parseEnvelopeIDText(parts[3])
	if !ok {
		return routeNone, agentDigest{}, "", none
	}
	if len(parts) == 4 {
		return routeEnvelope, agent, parts[1], id
	}
	if parts[4] != "ack" {
		return routeNone, agentDigest{}, "", none
	}
	return routeAck, agent, parts[1], id
}

// ServeHTTP answers one request. Order: client address, rate limit (429),
// query string (400), path (404), method (405), then the operation.
func (s *Server) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	now := s.now()
	client, ok := clientAddress(request, s.trusted)
	if !ok {
		s.fail(w, http.StatusBadRequest, 0)
		return
	}
	limiter := s.reads
	if request.Method == http.MethodPut {
		limiter = s.deposits
	}
	if allowed, wait := limiter.allow(client, now); !allowed {
		s.fail(w, http.StatusTooManyRequests, wait)
		return
	}
	if request.URL.RawQuery != "" || request.URL.ForceQuery || strings.Contains(request.RequestURI, "?") {
		s.fail(w, http.StatusBadRequest, 0)
		return
	}
	kind, agent, agentText, id := s.parseRoute(request.URL.EscapedPath())
	allow := ""
	switch kind {
	case routeRelay, routeList:
		allow = http.MethodGet
	case routeEnvelope:
		allow = "GET, PUT"
	case routeAck:
		allow = http.MethodPost
	default:
		s.fail(w, http.StatusNotFound, 0)
		return
	}
	switch {
	case kind == routeRelay && request.Method == http.MethodGet:
		s.describe(w)
	case kind == routeList && request.Method == http.MethodGet:
		s.list(w, agent, agentText, now)
	case kind == routeEnvelope && request.Method == http.MethodGet:
		s.download(w, agent, id, now)
	case kind == routeEnvelope && request.Method == http.MethodPut:
		s.deposit(w, request, agentText, id, client, now)
	case kind == routeAck && request.Method == http.MethodPost:
		s.ack(w, request, agent, id, now)
	default:
		w.Header().Set("Allow", allow)
		s.fail(w, http.StatusMethodNotAllowed, 0)
	}
}

func unixNow(now time.Time) uint64 { return uint64(max(now.Unix(), 0)) }

func (s *Server) deposit(w http.ResponseWriter, request *http.Request, agentText string, id [32]byte,
	client netip.Addr, now time.Time,
) {
	// Size first, before any byte of the body is read.
	if request.Header.Get("Content-Length") == "" || request.ContentLength < 0 || len(request.TransferEncoding) > 0 ||
		request.ContentLength > MaxEnvelopeBytes {
		s.fail(w, http.StatusRequestEntityTooLarge, 0)
		return
	}
	if request.Header.Get("Content-Type") != ContentTypeEnvelope {
		s.fail(w, http.StatusBadRequest, 0)
		return
	}
	body, err := io.ReadAll(io.LimitReader(http.MaxBytesReader(w, request.Body, MaxEnvelopeBytes+1), MaxEnvelopeBytes+1))
	if err != nil || int64(len(body)) != request.ContentLength {
		s.fail(w, http.StatusBadRequest, 0)
		return
	}
	header, err := agentpacketseal.ParseEnvelope(body)
	if err != nil || header.RecipientAgentID != agentText || header.EnvelopeID != id {
		s.fail(w, http.StatusBadRequest, 0)
		return
	}
	unix := unixNow(now)
	ttl := uint64(s.store.limits.TTL / time.Second)
	if header.ExpiresAtUnix <= unix || header.ExpiresAtUnix > unix+uint64(MaxTTL/time.Second)+uint64(ExpirySkew/time.Second) {
		s.fail(w, http.StatusUnprocessableEntity, 0)
		return
	}
	status, err := s.store.deposit(request.Context(), depositInput{header: header, envelope: body, client: client,
		now: unix, expires: min(header.ExpiresAtUnix, unix+ttl)})
	if err != nil {
		s.unavailable(w, "deposit", err)
		return
	}
	switch status {
	case depositCreated:
		s.empty(w, http.StatusCreated)
	case depositDuplicate:
		s.empty(w, http.StatusOK)
	case depositGone:
		s.fail(w, http.StatusGone, 0)
	case depositConflict:
		s.fail(w, http.StatusConflict, 0)
	case depositQuota:
		s.fail(w, statusInsufficientSave, 0)
	default:
		s.unavailable(w, "deposit", fmt.Errorf("unknown deposit status %d", status))
	}
}

func (s *Server) ack(w http.ResponseWriter, request *http.Request, agent agentDigest, id [32]byte, now time.Time) {
	if request.Header.Get("Content-Type") != ContentTypeEnvelope ||
		(request.ContentLength >= 0 && request.ContentLength != agentpacketseal.AckSecretSize) {
		s.fail(w, http.StatusBadRequest, 0)
		return
	}
	body, err := io.ReadAll(io.LimitReader(http.MaxBytesReader(w, request.Body, agentpacketseal.AckSecretSize+1),
		agentpacketseal.AckSecretSize+1))
	if err != nil || len(body) != agentpacketseal.AckSecretSize {
		s.fail(w, http.StatusBadRequest, 0)
		return
	}
	if !agentpacketseal.CheckAck(id, [agentpacketseal.AckSecretSize]byte(body)) {
		s.fail(w, http.StatusForbidden, 0)
		return
	}
	status, err := s.store.ack(request.Context(), agent, id, unixNow(now))
	if err != nil {
		s.unavailable(w, "acknowledge", err)
		return
	}
	switch status {
	case ackDeleted, ackTombstone:
		s.empty(w, http.StatusNoContent)
	case ackNotFound:
		s.fail(w, http.StatusNotFound, 0)
	default:
		s.unavailable(w, "acknowledge", fmt.Errorf("unknown acknowledgement status %d", status))
	}
}

func (s *Server) download(w http.ResponseWriter, agent agentDigest, id [32]byte, now time.Time) {
	raw, err := s.store.get(agent, id, unixNow(now))
	if errors.Is(err, errEnvelopeAbsent) {
		s.fail(w, http.StatusNotFound, 0)
		return
	}
	if err != nil {
		s.unavailable(w, "download", err)
		return
	}
	header := w.Header()
	header.Set("Content-Type", ContentTypeEnvelope)
	header.Set("Content-Length", strconv.Itoa(len(raw)))
	setCommonHeaders(header)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) list(w http.ResponseWriter, agent agentDigest, agentText string, now time.Time) {
	entries, err := s.store.list(agent, unixNow(now))
	if err != nil {
		s.unavailable(w, "list", err)
		return
	}
	wire := wireMailbox{Schema: SchemaMailbox, AgentID: agentText, Envelopes: make([]wireMailboxEntry, 0, len(entries))}
	for _, entry := range entries {
		wire.Envelopes = append(wire.Envelopes, wireMailboxEntry{EnvelopeID: hex.EncodeToString(entry.EnvelopeID[:]),
			RecipientKeyID: agentpacketseal.KeyIDText(entry.RecipientKeyID), Size: entry.Size,
			ReceivedAtUnix: entry.ReceivedAtUnix, ExpiresAtUnix: entry.ExpiresAtUnix})
	}
	s.json(w, http.StatusOK, wire)
}

func (s *Server) describe(w http.ResponseWriter) {
	limits := s.store.limits
	s.json(w, http.StatusOK, wireRelay{Schema: SchemaRelay, MaxEnvelopeBytes: MaxEnvelopeBytes,
		MaxTTLSeconds:            uint64(limits.TTL / time.Second),
		PerRecipientMaxEnvelopes: uint64(limits.PerRecipientMaxEnvelopes),
		PerRecipientMaxBytes:     uint64(limits.PerRecipientMaxBytes)})
}

func setCommonHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
}

func (s *Server) json(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil || len(body) > MaxResponseBytes {
		s.unavailable(w, "encode response", fmt.Errorf("response of %d bytes: %v", len(body), err))
		return
	}
	header := w.Header()
	header.Set("Content-Type", ContentTypeJSON)
	header.Set("Content-Length", strconv.Itoa(len(body)))
	setCommonHeaders(header)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *Server) empty(w http.ResponseWriter, status int) {
	setCommonHeaders(w.Header())
	if status != http.StatusNoContent {
		w.Header().Set("Content-Length", "0")
	}
	w.WriteHeader(status)
}

// fail answers an error status with its fixed code. No request byte is
// echoed.
func (s *Server) fail(w http.ResponseWriter, status int, retryAfter time.Duration) {
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", strconv.FormatInt(max(int64((retryAfter+time.Second-1)/time.Second), 1), 10))
	}
	s.json(w, status, wireError{Schema: SchemaError, Code: codeForStatus[status]})
}

func (s *Server) unavailable(w http.ResponseWriter, operation string, err error) {
	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		s.logger.Error("relay store failure", "operation", operation, "error", err)
	}
	s.json(w, http.StatusServiceUnavailable, wireError{Schema: SchemaError, Code: CodeUnavailable})
}
