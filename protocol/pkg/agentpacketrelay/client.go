package agentpacketrelay

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// DefaultClientTimeout bounds one client request, connection set-up and the
// complete response body included.
const DefaultClientTimeout = 30 * time.Second

// maxRetryAfter caps a relay's Retry-After so a hostile relay cannot park a
// client forever.
const maxRetryAfter = 5 * time.Minute

// Client errors. A relay's error status is returned as *StatusError, which
// matches the sentinel of its status with errors.Is.
var (
	// ErrInvalidArgument is a local refusal: nothing was sent.
	ErrInvalidArgument = errors.New("agentpacketrelay: invalid client argument")
	// ErrInvalidResponse is a relay answer that breaks V1 (wrong status,
	// content type, size, schema, or an envelope that does not match the
	// request).
	ErrInvalidResponse = errors.New("agentpacketrelay: relay response violates Agent Packet Relay V1")
	ErrNotFound        = errors.New("agentpacketrelay: relay reports not found")
	ErrForbidden       = errors.New("agentpacketrelay: relay reports the acknowledgement secret does not match")
	ErrRateLimited     = errors.New("agentpacketrelay: relay rate limit reached")
	ErrUnavailable     = errors.New("agentpacketrelay: relay unavailable")
	// ErrRequestTimeout is 408: the request body arrived too slowly. It is
	// retryable and is not ErrRejected.
	ErrRequestTimeout = errors.New("agentpacketrelay: relay timed out reading the request")
	ErrRejected       = errors.New("agentpacketrelay: relay rejected the request")
)

// StatusError is a relay error status with its fixed code. RetryAfter is the
// relay's Retry-After hint (zero when absent), capped at five minutes.
type StatusError struct {
	StatusCode int
	Code       string
	RetryAfter time.Duration
}

func (e *StatusError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("agentpacketrelay: relay answered HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("agentpacketrelay: relay answered HTTP %d (%s)", e.StatusCode, e.Code)
}

// Is maps the status onto the client sentinels.
func (e *StatusError) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.StatusCode == http.StatusNotFound
	case ErrForbidden:
		return e.StatusCode == http.StatusForbidden
	case ErrRateLimited:
		return e.StatusCode == http.StatusTooManyRequests
	case ErrUnavailable:
		return e.StatusCode >= 500
	case ErrRequestTimeout:
		return e.StatusCode == http.StatusRequestTimeout
	case ErrRejected:
		return e.StatusCode >= 400 && e.StatusCode < 500 && e.StatusCode != http.StatusTooManyRequests &&
			e.StatusCode != http.StatusRequestTimeout
	}
	return false
}

// RetryAfter returns the relay's Retry-After hint carried by err, if any.
func RetryAfter(err error) (time.Duration, bool) {
	var status *StatusError
	if errors.As(err, &status) && status.RetryAfter > 0 {
		return status.RetryAfter, true
	}
	return 0, false
}

// DepositResult classifies one deposit attempt at one relay.
type DepositResult int

const (
	// DepositStored is 201: the relay stored the envelope durably.
	DepositStored DepositResult = iota + 1
	// DepositDuplicate is 200: the relay already held these exact bytes.
	DepositDuplicate
	// DepositAcknowledged is 410: the envelope was stored and has already
	// been acknowledged by its recipient.
	DepositAcknowledged
	// DepositConflict is 409: the relay holds different bytes under this
	// envelope ID. Never acceptance and never retried at this relay.
	DepositConflict
	// DepositRetryable is every outcome the sender retries later with the
	// same bytes: a timeout, a connection error, 408 (the body arrived too
	// slowly), 429, 507, 503, any other 5xx, a redirect, or any status V1
	// does not define for a deposit.
	DepositRetryable
	// DepositRejected is 400, 404, 413 or 422: the relay refused these exact
	// bytes, and resending them unchanged to this relay will be refused
	// again unless the clock or the relay changes.
	DepositRejected
)

func (r DepositResult) String() string {
	switch r {
	case DepositStored:
		return "stored"
	case DepositDuplicate:
		return "duplicate"
	case DepositAcknowledged:
		return "acknowledged"
	case DepositConflict:
		return "conflict"
	case DepositRetryable:
		return "retryable"
	case DepositRejected:
		return "rejected"
	}
	return "unknown"
}

// DepositOutcome is the result of one deposit attempt.
type DepositOutcome struct {
	Result DepositResult
	// StatusCode is the HTTP status, or zero when no response arrived.
	StatusCode int
	// Code is the relay's error code, when it sent a valid error body.
	Code string
	// RetryAfter is the relay's Retry-After hint (zero when absent),
	// capped at five minutes.
	RetryAfter time.Duration
	// Err describes a failure; nil for 200, 201 and 410.
	Err error
}

// Accepted reports durable acceptance: 200, 201 or 410. A transport Send
// returns nil only after at least one relay accepted.
func (o DepositOutcome) Accepted() bool {
	return o.Result == DepositStored || o.Result == DepositDuplicate || o.Result == DepositAcknowledged
}

// ClientConfig configures a client for one relay base URL.
type ClientConfig struct {
	// BaseURL is the relay base URL exactly as a key card names it; it must
	// pass agentpacketseal.CheckRelayURL (HTTPS, or HTTP to 127.0.0.1,
	// localhost or ::1).
	BaseURL string
	// Timeout bounds each request including its response body. Zero means
	// DefaultClientTimeout.
	Timeout time.Duration
	// Proxy is the only proxy the client uses. Nil means direct
	// connections; the HTTP_PROXY, HTTPS_PROXY and NO_PROXY environment
	// variables are never consulted. Must be nil when Transport is set.
	Proxy *url.URL
	// Transport replaces the default transport (for example to pin a CA
	// pool). The caller then owns its proxy and TLS policy. Redirects are
	// refused whatever the transport.
	Transport http.RoundTripper
}

// Client talks to one relay. It is safe for concurrent use.
type Client struct {
	base string
	http *http.Client
}

// NewClient checks the configuration and returns a client.
func NewClient(config ClientConfig) (*Client, error) {
	// V1 forbids any percent-escape in a relay URL path; the "%" check also
	// covers escapes that decode to characters needing no escape, which
	// leave the parsed URL without a raw path.
	if err := agentpacketseal.CheckRelayURL(config.BaseURL); err != nil || strings.Contains(config.BaseURL, "%") {
		return nil, fmt.Errorf("%w: relay base URL is not a canonical HTTPS or loopback HTTP base URL", ErrInvalidArgument)
	}
	if config.Timeout < 0 || (config.Proxy != nil && config.Transport != nil) {
		return nil, fmt.Errorf("%w: invalid timeout or both proxy and transport set", ErrInvalidArgument)
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = DefaultClientTimeout
	}
	transport := config.Transport
	if transport == nil {
		var proxy func(*http.Request) (*url.URL, error)
		if config.Proxy != nil {
			if config.Proxy.Scheme != "http" && config.Proxy.Scheme != "https" || config.Proxy.Host == "" {
				return nil, fmt.Errorf("%w: proxy must be an http or https URL", ErrInvalidArgument)
			}
			proxy = http.ProxyURL(config.Proxy)
		}
		transport = &http.Transport{
			Proxy:                  proxy,
			DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    10 * time.Second,
			ResponseHeaderTimeout:  timeout,
			MaxIdleConns:           16,
			MaxIdleConnsPerHost:    4,
			IdleConnTimeout:        90 * time.Second,
			MaxResponseHeaderBytes: 16 << 10,
			ForceAttemptHTTP2:      true,
		}
	}
	return &Client{base: config.BaseURL, http: &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// BaseURL returns the relay base URL.
func (c *Client) BaseURL() string { return c.base }

func (c *Client) envelopesPath(agentID string) string {
	return c.base + "/v1/mailboxes/" + agentID + "/envelopes"
}

func (c *Client) envelopePath(agentID string, envelopeID [32]byte) string {
	return c.envelopesPath(agentID) + "/" + hex.EncodeToString(envelopeID[:])
}

// Deposit PUTs one envelope at the mailbox its header names. The envelope
// must pass agentpacketseal.ParseEnvelope; otherwise the error is
// ErrInvalidArgument and nothing is sent. Every relay or network outcome is
// reported in the DepositOutcome, never as the error.
func (c *Client) Deposit(ctx context.Context, envelope []byte) (DepositOutcome, error) {
	if ctx == nil {
		return DepositOutcome{}, fmt.Errorf("%w: nil context", ErrInvalidArgument)
	}
	header, err := agentpacketseal.ParseEnvelope(envelope)
	if err != nil {
		return DepositOutcome{}, fmt.Errorf("%w: envelope does not parse", ErrInvalidArgument)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.envelopePath(header.RecipientAgentID, header.EnvelopeID), bytes.NewReader(envelope))
	if err != nil {
		return DepositOutcome{}, fmt.Errorf("%w: build request: %v", ErrInvalidArgument, err)
	}
	request.Header.Set("Content-Type", ContentTypeEnvelope)
	request.ContentLength = int64(len(envelope))
	response, err := c.http.Do(request)
	if err != nil {
		return DepositOutcome{Result: DepositRetryable, Err: fmt.Errorf("agentpacketrelay: deposit: %w", err)}, nil
	}
	defer response.Body.Close()
	outcome := DepositOutcome{StatusCode: response.StatusCode}
	switch response.StatusCode {
	case http.StatusCreated:
		outcome.Result = DepositStored
	case http.StatusOK:
		outcome.Result = DepositDuplicate
	case http.StatusGone:
		outcome.Result = DepositAcknowledged
	}
	if outcome.Accepted() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, MaxResponseBytes))
		return outcome, nil
	}
	statusErr := readStatusError(response)
	outcome.Code, outcome.RetryAfter, outcome.Err = statusErr.Code, statusErr.RetryAfter, statusErr
	switch response.StatusCode {
	case http.StatusConflict:
		outcome.Result = DepositConflict
	case http.StatusBadRequest, http.StatusNotFound, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		outcome.Result = DepositRejected
	case http.StatusRequestTimeout:
		// The body arrived too slowly: the same bytes may succeed later.
		outcome.Result = DepositRetryable
	default:
		outcome.Result = DepositRetryable
	}
	return outcome, nil
}

// List fetches and strictly decodes the mailbox of agentID.
func (c *Client) List(ctx context.Context, agentID string) (Mailbox, error) {
	if ctx == nil {
		return Mailbox{}, fmt.Errorf("%w: nil context", ErrInvalidArgument)
	}
	if _, ok := parseAgentText(agentID); !ok {
		return Mailbox{}, fmt.Errorf("%w: invalid Agent ID", ErrInvalidArgument)
	}
	body, err := c.get(ctx, c.envelopesPath(agentID), ContentTypeJSON, MaxResponseBytes)
	if err != nil {
		return Mailbox{}, err
	}
	return decodeMailbox(body, agentID)
}

// Download fetches one envelope and checks that it parses and that its
// header names agentID and envelopeID. The bytes are still unauthenticated:
// the recipient opens them with agentpacketseal.Open.
func (c *Client) Download(ctx context.Context, agentID string, envelopeID [32]byte) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidArgument)
	}
	if _, ok := parseAgentText(agentID); !ok || envelopeID == ([32]byte{}) {
		return nil, fmt.Errorf("%w: invalid Agent ID or envelope ID", ErrInvalidArgument)
	}
	body, err := c.get(ctx, c.envelopePath(agentID, envelopeID), ContentTypeEnvelope, MaxEnvelopeBytes)
	if err != nil {
		return nil, err
	}
	header, err := agentpacketseal.ParseEnvelope(body)
	if err != nil || header.RecipientAgentID != agentID || header.EnvelopeID != envelopeID {
		return nil, fmt.Errorf("%w: downloaded envelope does not parse or names another mailbox or ID", ErrInvalidResponse)
	}
	return body, nil
}

// Ack presents the acknowledgement secret for one envelope. A nil error is
// 204: the envelope is deleted, or was already acknowledged.
func (c *Client) Ack(ctx context.Context, agentID string, envelopeID [32]byte, secret [agentpacketseal.AckSecretSize]byte) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidArgument)
	}
	if _, ok := parseAgentText(agentID); !ok || envelopeID == ([32]byte{}) {
		return fmt.Errorf("%w: invalid Agent ID or envelope ID", ErrInvalidArgument)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.envelopePath(agentID, envelopeID)+"/ack",
		bytes.NewReader(secret[:]))
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrInvalidArgument, err)
	}
	request.Header.Set("Content-Type", ContentTypeEnvelope)
	request.ContentLength = agentpacketseal.AckSecretSize
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("agentpacketrelay: acknowledge: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, MaxResponseBytes))
		return nil
	}
	return readStatusError(response)
}

// Describe fetches the advisory relay description.
func (c *Client) Describe(ctx context.Context) (RelayDescription, error) {
	if ctx == nil {
		return RelayDescription{}, fmt.Errorf("%w: nil context", ErrInvalidArgument)
	}
	body, err := c.get(ctx, c.base+"/v1/relay", ContentTypeJSON, MaxResponseBytes)
	if err != nil {
		return RelayDescription{}, err
	}
	var wire wireRelay
	if err := strictJSON(body, &wire); err != nil || wire.Schema != SchemaRelay {
		return RelayDescription{}, fmt.Errorf("%w: relay description", ErrInvalidResponse)
	}
	return RelayDescription{MaxEnvelopeBytes: wire.MaxEnvelopeBytes, MaxTTLSeconds: wire.MaxTTLSeconds,
		PerRecipientMaxEnvelopes: wire.PerRecipientMaxEnvelopes, PerRecipientMaxBytes: wire.PerRecipientMaxBytes}, nil
}

// get performs a GET that must answer 200 with the given content type and a
// body of at most limit bytes.
func (c *Client) get(ctx context.Context, target, contentType string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrInvalidArgument, err)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("agentpacketrelay: request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, readStatusError(response)
	}
	if mediaType(response.Header.Get("Content-Type")) != contentType || response.ContentLength > limit {
		return nil, fmt.Errorf("%w: unexpected content type or length", ErrInvalidResponse)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("agentpacketrelay: read response: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w: response exceeds %d bytes", ErrInvalidResponse, limit)
	}
	return body, nil
}

// readStatusError builds the error of a non-success response. The body is
// read only up to the 64 KiB bound and its code is used only when it is a
// valid V1 error body whose code is the fixed code of the status.
func readStatusError(response *http.Response) *StatusError {
	statusErr := &StatusError{StatusCode: response.StatusCode}
	if seconds, err := strconv.ParseUint(strings.TrimSpace(response.Header.Get("Retry-After")), 10, 32); err == nil {
		statusErr.RetryAfter = min(time.Duration(seconds)*time.Second, maxRetryAfter)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(body) > MaxResponseBytes || mediaType(response.Header.Get("Content-Type")) != ContentTypeJSON {
		return statusErr
	}
	var wire wireError
	if strictJSON(body, &wire) == nil && wire.Schema == SchemaError && codeForStatus[response.StatusCode] == wire.Code {
		statusErr.Code = wire.Code
	}
	return statusErr
}

func mediaType(value string) string {
	if index := strings.IndexByte(value, ';'); index >= 0 {
		value = value[:index]
	}
	return strings.ToLower(strings.TrimSpace(value))
}

// strictJSON decodes exactly one JSON value with no unknown fields and no
// trailing data.
func strictJSON(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

// decodeMailbox decodes a listing strictly: the schema, the requested Agent,
// at most 256 entries, canonical IDs, sizes inside the envelope bounds,
// received <= expires, and the V1 order (received_at_unix, then envelope ID,
// strictly ascending, so no duplicates).
func decodeMailbox(body []byte, agentID string) (Mailbox, error) {
	var wire wireMailbox
	if err := strictJSON(body, &wire); err != nil || wire.Schema != SchemaMailbox || wire.AgentID != agentID ||
		wire.Envelopes == nil || len(wire.Envelopes) > MaxPerRecipientEnvelopes {
		return Mailbox{}, fmt.Errorf("%w: mailbox listing", ErrInvalidResponse)
	}
	out := Mailbox{AgentID: agentID, Envelopes: make([]MailboxEntry, 0, len(wire.Envelopes))}
	for index, raw := range wire.Envelopes {
		id, ok := parseEnvelopeIDText(raw.EnvelopeID)
		keyID, keyErr := agentpacketseal.ParseKeyIDText(raw.RecipientKeyID)
		if !ok || keyErr != nil || uint64(raw.Size) < uint64(MinEnvelopeBytes) || uint64(raw.Size) > uint64(MaxEnvelopeBytes) ||
			raw.ReceivedAtUnix == 0 || raw.ExpiresAtUnix <= raw.ReceivedAtUnix {
			return Mailbox{}, fmt.Errorf("%w: mailbox entry %d", ErrInvalidResponse, index)
		}
		entry := MailboxEntry{EnvelopeID: id, RecipientKeyID: keyID, Size: raw.Size,
			ReceivedAtUnix: raw.ReceivedAtUnix, ExpiresAtUnix: raw.ExpiresAtUnix}
		if index > 0 && !entryBefore(out.Envelopes[index-1], entry) {
			return Mailbox{}, fmt.Errorf("%w: mailbox entries out of order or duplicated", ErrInvalidResponse)
		}
		out.Envelopes = append(out.Envelopes, entry)
	}
	return out, nil
}

func entryBefore(a, b MailboxEntry) bool {
	if a.ReceivedAtUnix != b.ReceivedAtUnix {
		return a.ReceivedAtUnix < b.ReceivedAtUnix
	}
	return bytes.Compare(a.EnvelopeID[:], b.EnvelopeID[:]) < 0
}
