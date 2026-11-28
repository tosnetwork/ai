package agentpacketrelay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

const MaxV2ListingBytes = 80 << 10
const SchemaV2Mailbox = "tos.service.agent-packet-relay.mailbox.v2"
const SchemaV2Error = "tos.service.agent-packet-relay.error.v2"

// V2Server never constructs a V1 server or accepts a V1 store. URL is the
// configured canonical external URL, never the request's Host header.
type V2ServerConfig struct {
	Store                 *V2Store
	URL                   string
	Verifier              *agenttransport.Verifier
	Now                   func() time.Time
	TrustedProxies        []netip.Prefix
	DepositRate, ReadRate RateLimit
}
type V2Server struct {
	store           *V2Store
	verifier        *agenttransport.Verifier
	base, relay     string
	now             func() time.Time
	trusted         []netip.Prefix
	deposits, reads *rateLimiter
	bodies          chan struct{}
	mu              sync.Mutex
	clients         map[netip.Addr]int
	sites           map[netip.Addr]int
}

func NewV2Server(c V2ServerConfig) (*V2Server, error) {
	if c.Store == nil || c.Store.Replay() == nil || c.Verifier == nil {
		return nil, errors.New("V2 needs its durable store and finalized verifier")
	}
	if err := agentpacketseal.CheckRelayURL(c.URL); err != nil {
		return nil, err
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, err
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.DepositRate == (RateLimit{}) {
		c.DepositRate = DefaultDepositRate
	}
	if c.ReadRate == (RateLimit{}) {
		c.ReadRate = DefaultReadRate
	}
	if err := c.DepositRate.validate(); err != nil {
		return nil, err
	}
	if err := c.ReadRate.validate(); err != nil {
		return nil, err
	}
	return &V2Server{store: c.Store, verifier: c.Verifier, base: u.EscapedPath(), relay: c.URL, now: c.Now, trusted: append([]netip.Prefix(nil), c.TrustedProxies...), deposits: newRateLimiter(c.DepositRate, DefaultMaxRateClients, DefaultMaxRateClientsPer48), reads: newRateLimiter(c.ReadRate, DefaultMaxRateClients, DefaultMaxRateClientsPer48), bodies: make(chan struct{}, DefaultMaxConcurrentDeposits), clients: map[netip.Addr]int{}, sites: map[netip.Addr]int{}}, nil
}

// NewV2FinalizedVerifier uses the existing finalized reader; production and
// unknown genesis tuples remain refused by the transport's pinned constructors.
func NewV2FinalizedVerifier(c agenttransport.Config, source agenttransport.FinalizedStateReader) (*agenttransport.Verifier, error) {
	if source == nil {
		return nil, errors.New("finalized source required")
	}
	adapter, err := agenttransport.NewLegacyTestNetworkResolver(c.Mode, c.Network, v2FinalizedSource{source})
	if err != nil {
		return nil, err
	}
	return agenttransport.NewVerifier(c, adapter)
}

type v2HTTPError struct {
	Schema string `json:"schema"`
	Code   string `json:"code"`
	Lane   string `json:"lane,omitempty"`
}
type v2WireEntry struct {
	EnvelopeID     string `json:"envelope_id"`
	RecipientKeyID string `json:"recipient_key_id"`
	Size           uint32 `json:"size"`
	ReceivedAtUnix uint64 `json:"received_at_unix"`
	ExpiresAtUnix  uint64 `json:"expires_at_unix"`
	Lane           string `json:"lane"`
}
type v2WireMailbox struct {
	Schema    string        `json:"schema"`
	AgentID   string        `json:"agent_id"`
	Envelopes []v2WireEntry `json:"envelopes"`
}

func v2WriteJSON(w http.ResponseWriter, status int, v any, bound int) {
	body, err := json.Marshal(v)
	if err != nil || len(body) > bound {
		status = 500
		body = []byte(`{"schema":"tos.service.agent-packet-relay.error.v2","code":"internal_error"}`)
	}
	setCommonHeaders(w.Header())
	w.Header().Set("Content-Type", ContentTypeJSON)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
func v2Fail(w http.ResponseWriter, status int, code string) {
	v2WriteJSON(w, status, v2HTTPError{Schema: SchemaV2Error, Code: code}, MaxResponseBytes)
}
func v2Empty(w http.ResponseWriter, status int) {
	setCommonHeaders(w.Header())
	if status != 204 {
		w.Header().Set("Content-Length", "0")
	}
	w.WriteHeader(status)
}
func (s *V2Server) route(path string) (string, string, [32]byte) {
	var zero [32]byte
	rest, ok := strings.CutPrefix(path, s.base+"/v2/mailboxes/")
	if !ok {
		return "", "", zero
	}
	p := strings.Split(rest, "/")
	if len(p) < 2 || len(p) > 4 {
		return "", "", zero
	}
	if _, ok := parseAgentText(p[0]); !ok {
		return "", "", zero
	}
	if len(p) == 2 && p[1] == "policy" {
		return "policy", p[0], zero
	}
	if p[1] != "envelopes" {
		return "", "", zero
	}
	if len(p) == 2 {
		return "list", p[0], zero
	}
	id, ok := parseEnvelopeIDText(p[2])
	if !ok {
		return "", "", zero
	}
	if len(p) == 3 {
		return "envelope", p[0], id
	}
	if p[3] == "ack" {
		return "ack", p[0], id
	}
	return "", "", zero
}
func (s *V2Server) take(client netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	site, grouped := site48(client)
	if s.clients[client] >= DefaultMaxConcurrentDepositsPerClient || (grouped && s.sites[site] >= DefaultMaxConcurrentDepositsPer48) {
		return false
	}
	select {
	case s.bodies <- struct{}{}:
	default:
		return false
	}
	s.clients[client]++
	if grouped {
		s.sites[site]++
	}
	return true
}
func (s *V2Server) release(client netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	<-s.bodies
	decrementV2(s.clients, client)
	if site, ok := site48(client); ok {
		decrementV2(s.sites, site)
	}
}
func (s *V2Server) readBody(w http.ResponseWriter, r *http.Request, maxBytes int) ([]byte, bool) {
	if len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Encoding") != "" || r.ContentLength < 0 || r.ContentLength > int64(maxBytes) || r.Header.Get("Content-Type") != ContentTypeEnvelope {
		v2Fail(w, 400, CodeInvalidRequest)
		return nil, false
	}
	deadline := DefaultDepositReadBase + time.Duration(r.ContentLength)*time.Second/DefaultDepositMinBytesPerSecond
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(deadline)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		v2Fail(w, 503, CodeUnavailable)
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBytes)+1))
	if errors.Is(err, os.ErrDeadlineExceeded) {
		w.Header().Set("Connection", "close")
		v2Fail(w, 408, CodeRequestTimeout)
		return nil, false
	}
	if err != nil || int64(len(body)) != r.ContentLength {
		v2Fail(w, 400, CodeInvalidRequest)
		return nil, false
	}
	return body, true
}
func (s *V2Server) authorize(w http.ResponseWriter, r *http.Request, agent string, op agenttransport.Operation, body []byte, optional bool) (*agenttransport.CheckedRequest, bool) {
	cv, pv := r.Header.Values("TOS-Relay-Credential"), r.Header.Values("TOS-Relay-Proof")
	if len(cv) == 0 && len(pv) == 0 {
		if optional {
			return nil, true
		}
		v2Fail(w, 401, "credential_required")
		return nil, false
	}
	if len(cv) != 1 || len(pv) != 1 {
		v2Fail(w, 403, "credential_invalid")
		return nil, false
	}
	checked, err := agenttransport.CheckRequest(agenttransport.Request{AgentID: agent, Operation: op, Proof: agenttransport.ProofRequest{RelayURL: s.relay, Method: r.Method, Path: r.URL.EscapedPath(), Body: body}, CredentialValue: cv[0], ProofValue: pv[0], Now: unixNow(s.now())})
	if err == nil {
		_, err = checkedV2Lane(checked)
	}
	if err != nil {
		code := "credential_invalid"
		if errors.Is(err, agenttransport.ErrCredentialScope) {
			code = "credential_scope"
		}
		v2Fail(w, 403, code)
		return nil, false
	}
	if err = s.store.Replay().Claim(checked, unixNow(s.now())); err != nil {
		switch {
		case errors.Is(err, agenttransport.ErrProofFloor):
			w.Header().Set("Retry-After", strconv.FormatUint(s.store.Replay().RetryAfter(checked.Proof.IssuedAt), 10))
			v2Fail(w, 503, "proof_floor")
		case errors.Is(err, agenttransport.ErrReplayTableFull):
			v2Fail(w, 503, "replay_table_full")
		case errors.Is(err, agenttransport.ErrReplayCredentialFull):
			w.Header().Set("Retry-After", "121")
			v2Fail(w, 429, CodeRateLimited)
		default:
			v2Fail(w, 403, "credential_invalid")
		}
		return nil, false
	}
	raw, err := checked.Credential.DelegationBytes()
	if err == nil {
		_, err = s.verifier.VerifyDelegation(r.Context(), raw, agenttransport.Relay)
	}
	if err != nil {
		if errors.Is(err, agenttransport.ErrUnavailable) || errors.Is(err, context.DeadlineExceeded) {
			v2Fail(w, 503, "chain_unavailable")
		} else {
			v2Fail(w, 403, "credential_revoked")
		}
		return nil, false
	}
	// A bounded finalized read can cross a credential/proof boundary.
	if err = checked.Credential.CheckScope(unixNow(s.now()), s.relay, op); err == nil {
		err = agenttransport.CheckProofWindow(checked.Proof.IssuedAt, unixNow(s.now()))
	}
	if err != nil {
		v2Fail(w, 403, "credential_scope")
		return nil, false
	}
	return &checked, true
}
func (s *V2Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	client, ok := clientAddress(r, s.trusted)
	if !ok {
		v2Fail(w, 400, CodeInvalidRequest)
		return
	}
	limiter := s.reads
	if r.Method == http.MethodPut {
		limiter = s.deposits
	}
	if allowed, wait := limiter.allow(client, s.now()); !allowed {
		w.Header().Set("Retry-After", strconv.FormatInt(max(1, int64(wait/time.Second)+1), 10))
		v2Fail(w, 429, CodeRateLimited)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || strings.Contains(r.RequestURI, "?") {
		v2Fail(w, 400, CodeInvalidRequest)
		return
	}
	kind, agent, id := s.route(r.URL.EscapedPath())
	method := r.Method
	allowed := (kind == "list" && method == "GET") || (kind == "envelope" && (method == "GET" || method == "PUT")) || (kind == "ack" && method == "POST") || (kind == "policy" && method == "PUT")
	if kind == "" {
		v2Fail(w, 404, CodeNotFound)
		return
	}
	if !allowed {
		v2Fail(w, 405, CodeMethodNotAllowed)
		return
	}
	if r.Header.Get("TOS-Relay-Wait") != "" {
		v2Fail(w, 400, CodeInvalidRequest)
		return
	} // Long polling is the next relay change.
	var body []byte
	if method == "PUT" || method == "POST" {
		if !s.take(client) {
			w.Header().Set("Retry-After", "1")
			v2Fail(w, 503, CodeUnavailable)
			return
		}
		defer s.release(client)
		limit := MaxEnvelopeBytes
		if kind == "ack" {
			limit = agentpacketseal.AckSecretSize
		}
		if kind == "policy" {
			limit = maxV2PolicyBytes
		}
		var ok bool
		body, ok = s.readBody(w, r, limit)
		if !ok {
			return
		}
	} else if r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		v2Fail(w, 400, CodeInvalidRequest)
		return
	}
	if kind == "ack" {
		s.ackV2(w, r, agent, id, body)
		return
	}
	op := agenttransport.OperationList
	if kind == "policy" {
		op = agenttransport.OperationPublish
	} else if kind == "envelope" {
		if method == "GET" {
			op = agenttransport.OperationFetch
		} else {
			op = agenttransport.OperationDeposit
		}
	}
	checked, ok := s.authorize(w, r, agent, op, body, method == "PUT" && kind == "envelope")
	if !ok {
		return
	}
	digest, _ := parseAgentText(agent)
	now := unixNow(s.now())
	switch {
	case kind == "policy":
		s.setPolicy(w, r, agent, body, *checked)
	case kind == "list":
		entries, err := s.store.list(r.Context(), digest, now)
		if err != nil {
			v2Fail(w, 503, CodeUnavailable)
			return
		}
		listing := v2WireMailbox{SchemaV2Mailbox, agent, make([]v2WireEntry, 0, len(entries))}
		for _, e := range entries {
			listing.Envelopes = append(listing.Envelopes, v2WireEntry{hex.EncodeToString(e.EnvelopeID[:]), agentpacketseal.KeyIDText(e.RecipientKeyID), e.Size, e.ReceivedAtUnix, e.ExpiresAtUnix, e.Lane})
		}
		v2WriteJSON(w, 200, listing, MaxV2ListingBytes)
	case method == "GET":
		raw, err := s.store.get(r.Context(), digest, id, now)
		if errors.Is(err, errEnvelopeAbsent) {
			v2Fail(w, 404, CodeNotFound)
			return
		}
		if err != nil {
			v2Fail(w, 503, CodeUnavailable)
			return
		}
		setCommonHeaders(w.Header())
		w.Header().Set("Content-Type", ContentTypeEnvelope)
		w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
		w.WriteHeader(200)
		_, _ = w.Write(raw)
	default:
		header, err := agentpacketseal.ParseEnvelope(body)
		if err != nil || header.RecipientAgentID != agent || header.EnvelopeID != id {
			v2Fail(w, 400, CodeInvalidRequest)
			return
		}
		if header.ExpiresAtUnix <= now || (header.ExpiresAtUnix > now && header.ExpiresAtUnix-now > uint64((MaxTTL+ExpirySkew)/time.Second)) {
			v2Fail(w, 422, CodeExpiryOutOfBounds)
			return
		}
		stranger, err := s.policyBudget(r.Context(), agent)
		if err != nil {
			v2Fail(w, 503, "chain_unavailable")
			return
		}
		status, err := s.store.deposit(r.Context(), depositInput{header, body, client, now, min(header.ExpiresAtUnix, now+uint64(s.store.limits.Base.TTL/time.Second))}, checked, stranger)
		if err != nil {
			if errors.Is(err, agenttransport.ErrCredentialScope) {
				v2Fail(w, 403, "credential_scope")
			} else {
				v2Fail(w, 503, CodeUnavailable)
			}
			return
		}
		switch status {
		case depositCreated:
			v2Empty(w, 201)
		case depositDuplicate:
			v2Empty(w, 200)
		case depositConflict:
			v2Fail(w, 409, CodeConflict)
		case depositGone:
			v2Fail(w, 410, CodeGone)
		case depositQuota:
			lane := "stranger"
			if checked != nil {
				lane = "contact"
			}
			v2WriteJSON(w, 507, v2HTTPError{SchemaV2Error, CodeQuotaExhausted, lane}, MaxResponseBytes)
		}
	}
}
func (s *V2Server) ackV2(w http.ResponseWriter, r *http.Request, agent string, id [32]byte, body []byte) {
	if len(body) != agentpacketseal.AckSecretSize {
		v2Fail(w, 400, CodeInvalidRequest)
		return
	}
	if !agentpacketseal.CheckAck(id, [32]byte(body)) {
		v2Fail(w, 403, CodeForbidden)
		return
	}
	digest, _ := parseAgentText(agent)
	status, err := s.store.ack(r.Context(), digest, id, unixNow(s.now()))
	if err != nil {
		v2Fail(w, 503, CodeUnavailable)
		return
	}
	if status == ackNotFound {
		v2Fail(w, 404, CodeNotFound)
		return
	}
	v2Empty(w, 204)
}

// Only transport-level outage errors allow the verifier's bounded cached pass.
// A malformed answer, contradiction or corrupt checkpoint never does.
type v2FinalizedSource struct {
	agenttransport.FinalizedStateReader
}

func (s v2FinalizedSource) ResolveState(ctx context.Context, id, hash string) (*nativev1.NativeStateV1, bool, error) {
	state, found, err := s.FinalizedStateReader.ResolveState(ctx, id, hash)
	if errors.Is(err, toschain.ErrEndpointsUnavailable) || errors.Is(err, context.DeadlineExceeded) {
		return nil, false, agenttransport.ErrUnavailable
	}
	return state, found, err
}
