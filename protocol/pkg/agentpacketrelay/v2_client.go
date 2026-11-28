package agentpacketrelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

// V2Client never retries, follows a redirect or asks a V1 endpoint. Its only
// routing input is a validated V2 relay URL supplied by the caller's hint path.
type V2Client struct {
	base, path string
	http       *http.Client
	now        func() time.Time
}

func NewV2Client(base string, transport http.RoundTripper, now func() time.Time) (*V2Client, error) {
	if err := agentpacketseal.CheckRelayURL(base); err != nil {
		return nil, err
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	if transport == nil {
		standard, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("explicit V2 transport required")
		}
		transport = standard.Clone()
	}
	return &V2Client{base, u.EscapedPath(), &http.Client{Transport: transport, Timeout: DefaultClientTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, now}, nil
}
func (c *V2Client) exchange(ctx context.Context, method, path string, body, credential []byte, holder ed25519.PrivateKey) (int, []byte, error) {
	if !strings.HasPrefix(path, c.path+"/v2/mailboxes/") || strings.ContainsAny(path, "?#%") {
		return 0, nil, errors.New("invalid V2 path")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+strings.TrimPrefix(path, c.path), bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if method == "PUT" || method == "POST" {
		req.Header.Set("Content-Type", ContentTypeEnvelope)
	}
	if len(credential) > 0 {
		chain, err := agenttransport.DecodeCredential(credential)
		if err != nil {
			return 0, nil, err
		}
		if err = chain.VerifyChain(); err != nil {
			return 0, nil, err
		}
		var nonce [32]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return 0, nil, err
		}
		proof, err := agenttransport.SignRequest(chain, holder, agenttransport.ProofRequest{RelayURL: c.base, Method: method, Path: path, Body: body}, unixNow(c.now()), nonce)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("TOS-Relay-Credential", agenttransport.EncodeCredentialHeader(credential))
		req.Header.Set("TOS-Relay-Proof", proof.Header())
	}
	res, err := c.http.Do(req)
	if err != nil {
		return 0, nil, errors.New("V2 relay exchange failed")
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 || (res.StatusCode == 200 && method == "GET") {
		want := ContentTypeJSON
		if res.StatusCode == 200 && method == "GET" {
			kind, _, _ := (&V2Server{base: c.path}).route(path)
			if kind == "envelope" {
				want = ContentTypeEnvelope
			}
		}
		if res.Header.Get("Content-Type") != want {
			return 0, nil, errors.New("invalid V2 content type")
		}
	}
	bound := MaxResponseBytes
	if res.StatusCode == 200 && method == "GET" {
		kind, _, _ := (&V2Server{base: c.path}).route(path)
		if kind == "list" {
			bound = MaxV2ListingBytes
		} else if kind == "envelope" {
			bound = MaxEnvelopeBytes
		}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, int64(bound)+1))
	if err != nil || len(raw) > bound {
		return 0, nil, errors.New("invalid V2 response length")
	}
	if res.StatusCode == 204 && len(raw) != 0 {
		return 0, nil, errors.New("invalid empty V2 response")
	}
	if res.StatusCode >= 300 {
		var answer v2HTTPError
		if jsonstrict.Decode(raw, &answer) != nil || answer.Schema != SchemaV2Error || !v2StatusCode(res.StatusCode, answer.Code, answer.Lane) {
			return 0, nil, errors.New("invalid V2 error response")
		}
		return res.StatusCode, nil, &StatusError{StatusCode: res.StatusCode, Code: answer.Code}
	}
	return res.StatusCode, raw, nil
}
func v2StatusCode(status int, code, lane string) bool {
	if lane != "" && status != 507 {
		return false
	}
	switch status {
	case 401:
		return code == "credential_required"
	case 403:
		return code == "credential_invalid" || code == "credential_scope" || code == "credential_revoked" || code == CodeForbidden
	case 503:
		return code == "chain_unavailable" || code == "replay_table_full" || code == "proof_floor" || code == CodeUnavailable
	case 500:
		return code == "internal_error"
	case 507:
		return code == CodeQuotaExhausted && (lane == "stranger" || lane == "contact")
	default:
		return codeForStatus[status] != "" && codeForStatus[status] == code
	}
}
func (c *V2Client) List(ctx context.Context, agent string, credential []byte, holder ed25519.PrivateKey) ([]V2MailboxEntry, error) {
	if _, ok := parseAgentText(agent); !ok {
		return nil, errors.New("invalid Agent")
	}
	status, raw, err := c.exchange(ctx, "GET", c.path+"/v2/mailboxes/"+agent+"/envelopes", nil, credential, holder)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, errors.New("unexpected V2 listing status")
	}
	var listing v2WireMailbox
	if jsonstrict.Decode(raw, &listing) != nil || listing.Schema != SchemaV2Mailbox || listing.AgentID != agent || listing.Envelopes == nil || len(listing.Envelopes) > 256 {
		return nil, errors.New("invalid V2 mailbox listing")
	}
	out := make([]V2MailboxEntry, 0, len(listing.Envelopes))
	seen := make(map[[32]byte]bool)
	for _, e := range listing.Envelopes {
		id, ok := parseEnvelopeIDText(e.EnvelopeID)
		key, err := agentpacketseal.ParseKeyIDText(e.RecipientKeyID)
		if !ok || seen[id] || err != nil || e.Size < uint32(MinEnvelopeBytes) || e.Size > MaxEnvelopeBytes || e.ReceivedAtUnix == 0 || e.ExpiresAtUnix <= e.ReceivedAtUnix || (e.Lane != "contact" && e.Lane != "stranger") {
			return nil, errors.New("invalid V2 mailbox entry")
		}
		seen[id] = true
		out = append(out, V2MailboxEntry{id, key, e.Size, e.ReceivedAtUnix, e.ExpiresAtUnix, e.Lane})
	}
	return out, nil
}

// Policy bytes have one exact encoding, independently of JSON storage.
func (c *V2Client) PublishPolicy(ctx context.Context, agent string, p MailboxPolicy, credential []byte, holder ed25519.PrivateKey) error {
	if _, ok := parseAgentText(agent); !ok {
		return errors.New("invalid Agent")
	}
	status, _, err := c.exchange(ctx, "PUT", c.path+"/v2/mailboxes/"+agent+"/policy", p.Encode(), credential, holder)
	if err != nil {
		return err
	}
	if status != 200 && status != 204 {
		return errors.New("unexpected policy status")
	}
	return nil
}

func (c *V2Client) Deposit(ctx context.Context, envelope, credential []byte, holder ed25519.PrivateKey) error {
	header, err := agentpacketseal.ParseEnvelope(envelope)
	if err != nil {
		return err
	}
	path := c.path + "/v2/mailboxes/" + header.RecipientAgentID + "/envelopes/" + hex.EncodeToString(header.EnvelopeID[:])
	status, body, err := c.exchange(ctx, "PUT", path, envelope, credential, holder)
	if err != nil {
		return err
	}
	if (status != 200 && status != 201) || len(body) != 0 {
		return errors.New("invalid V2 deposit response")
	}
	return nil
}
func (c *V2Client) Fetch(ctx context.Context, agent string, id [32]byte, credential []byte, holder ed25519.PrivateKey) ([]byte, error) {
	if _, ok := parseAgentText(agent); !ok {
		return nil, errors.New("invalid Agent")
	}
	status, body, err := c.exchange(ctx, "GET", c.path+"/v2/mailboxes/"+agent+"/envelopes/"+hex.EncodeToString(id[:]), nil, credential, holder)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, errors.New("invalid V2 fetch status")
	}
	header, err := agentpacketseal.ParseEnvelope(body)
	if err != nil || header.RecipientAgentID != agent || header.EnvelopeID != id {
		return nil, errors.New("invalid V2 fetched envelope")
	}
	return body, nil
}
func (c *V2Client) Acknowledge(ctx context.Context, agent string, secret [32]byte) error {
	if _, ok := parseAgentText(agent); !ok {
		return errors.New("invalid Agent")
	}
	id := agentpacketseal.AckHash(secret)
	status, body, err := c.exchange(ctx, "POST", c.path+"/v2/mailboxes/"+agent+"/envelopes/"+hex.EncodeToString(id[:])+"/ack", secret[:], nil, nil)
	if err != nil {
		return err
	}
	if status != 204 || len(body) != 0 {
		return errors.New("invalid V2 acknowledgement response")
	}
	return nil
}
