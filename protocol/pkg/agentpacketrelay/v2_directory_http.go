package agentpacketrelay

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

func requestBudget(r *http.Request) time.Duration {
	if len(r.Header.Values("TOS-Relay-Wait")) > 0 {
		return 40 * time.Second
	}
	return 30 * time.Second
}
func parseWait(r *http.Request, kind string) (int, error) {
	values := r.Header.Values("TOS-Relay-Wait")
	if len(values) == 0 {
		return 0, nil
	}
	if len(values) != 1 || kind != "list" || r.Method != "GET" {
		return 0, errors.New("invalid wait header")
	}
	n, err := strconv.Atoi(values[0])
	if err != nil || n < 1 || n > 25 || strconv.Itoa(n) != values[0] {
		return 0, errors.New("invalid wait header")
	}
	return n, nil
}
func realWaitTimer(d time.Duration) (<-chan time.Time, func()) {
	timer := time.NewTimer(d)
	return timer.C, func() { timer.Stop() }
}
func (s *V2Server) recheck(ctx context.Context, agent string, checked agenttransport.CheckedRequest) error {
	if err := checked.Credential.CheckScope(unixNow(s.now()), s.relay, agenttransport.OperationList); err != nil {
		return err
	}
	if err := s.store.checkRevoked(ctx, agent, checked, unixNow(s.now())); err != nil {
		return err
	}
	raw, err := checked.Credential.DelegationBytes()
	if err != nil {
		return err
	}
	_, err = s.verifier.VerifyDelegation(ctx, raw, agenttransport.Relay)
	return err
}
func (s *V2Server) authorityFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, agenttransport.ErrUnavailable) || errors.Is(err, context.DeadlineExceeded):
		v2Fail(w, 503, "chain_unavailable")
	case errors.Is(err, ErrStoreUnavailable) || errors.Is(err, context.Canceled):
		v2Fail(w, 503, CodeUnavailable)
	case errors.Is(err, agenttransport.ErrCredentialScope):
		v2Fail(w, 403, "credential_scope")
	default:
		v2Fail(w, 403, "credential_revoked")
	}
}
func (s *V2Server) listV2(w http.ResponseWriter, r *http.Request, agent agentDigest, text string, checked agenttransport.CheckedRequest, wait int) {
	var entries []V2MailboxEntry
	if wait > 0 {
		var ch chan struct{}
		var err error
		entries, ch, err = s.store.waitSnapshot(r.Context(), agent, unixNow(s.now()), nil)
		if err != nil {
			if errors.Is(err, errWaitBusy) {
				w.Header().Set("Retry-After", "1")
				v2Fail(w, 429, CodeRateLimited)
			} else {
				v2Fail(w, 503, CodeUnavailable)
			}
			return
		}
		if ch != nil {
			defer func() { s.store.endWait(agent, ch) }()
			ticks, stop := s.waitTimer(time.Duration(wait) * time.Second)
			defer stop()
			for len(entries) == 0 {
				expired := false
				select {
				case <-r.Context().Done():
					v2Fail(w, 503, CodeUnavailable)
					return
				case <-ticks:
					expired = true
				case <-ch:
				}
				if err = s.recheck(r.Context(), text, checked); err != nil {
					s.authorityFailure(w, err)
					return
				}
				if expired {
					break
				}
				entries, ch, err = s.store.waitSnapshot(r.Context(), agent, unixNow(s.now()), ch)
				if err != nil {
					v2Fail(w, 503, CodeUnavailable)
					return
				}
			}
		}
	}
	// One final authorization and atomic local-revocation check also covers a
	// credential expiring, or being revoked, while its request was waiting.
	if err := s.recheck(r.Context(), text, checked); err != nil {
		s.authorityFailure(w, err)
		return
	}
	entries, err := s.store.list(r.Context(), agent, unixNow(s.now()), checked)
	if err != nil {
		s.authorityFailure(w, err)
		return
	}
	listing := v2WireMailbox{SchemaV2Mailbox, text, make([]v2WireEntry, 0, len(entries))}
	for _, e := range entries {
		listing.Envelopes = append(listing.Envelopes, v2WireEntry{hex.EncodeToString(e.EnvelopeID[:]), agentpacketseal.KeyIDText(e.RecipientKeyID), e.Size, e.ReceivedAtUnix, e.ExpiresAtUnix, e.Lane})
	}
	v2WriteJSON(w, 200, listing, MaxV2ListingBytes)
}
func (s *V2Server) controlAnswer(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		v2Empty(w, 204)
	case errors.Is(err, errControlQuota):
		v2Fail(w, 507, CodeQuotaExhausted)
	case errors.Is(err, ErrRevocation) || errors.Is(err, agenttransport.ErrHint):
		if errors.Is(err, agenttransport.ErrUnavailable) {
			v2Fail(w, 503, "chain_unavailable")
		} else if errors.Is(err, agenttransport.ErrDelegationRevoked) {
			v2Fail(w, 403, "credential_revoked")
		} else {
			v2Fail(w, 400, CodeInvalidRequest)
		}
	case errors.Is(err, errHintConflict):
		v2Fail(w, 409, "hint_conflict")
	case errors.Is(err, ErrCredentialRevoked):
		v2Fail(w, 403, "credential_revoked")
	case errors.Is(err, agenttransport.ErrCredentialScope):
		v2Fail(w, 403, "credential_scope")
	default:
		v2Fail(w, 503, CodeUnavailable)
	}
}
func (s *V2Server) serveHints(w http.ResponseWriter, r *http.Request, kind, agent string, digest [32]byte, body []byte) {
	if len(r.Header.Values("TOS-Relay-Credential")) > 0 || len(r.Header.Values("TOS-Relay-Proof")) > 0 {
		v2Fail(w, 400, CodeInvalidRequest)
		return
	}
	if r.Method == "PUT" {
		s.controlAnswer(w, s.putHint(r.Context(), agent, body))
		return
	}
	var only *[32]byte
	if kind == "hint-record" {
		only = &digest
	}
	records, err := s.liveHints(r.Context(), agent, only)
	if err != nil {
		s.authorityFailure(w, err)
		return
	}
	if len(records) == 0 {
		v2Fail(w, 404, CodeNotFound)
		return
	}
	// Recheck the first records after the bounded multi-record read; a later
	// record's slow refresh must not extend an earlier cached pass beyond 600 s.
	for _, record := range records {
		if _, err = s.verifier.VerifyHint(r.Context(), record.Raw, s.hintPolicy); err != nil {
			s.authorityFailure(w, err)
			return
		}
	}
	var raw []byte
	if kind == "hint-record" {
		raw = records[0].Raw
	} else {
		entries := make([]HintIndexEntry, 0, len(records))
		for _, record := range records {
			entries = append(entries, HintIndexEntry{record.Meta.Digest, record.Meta.IssuedAt, record.Meta.Length})
		}
		raw, err = EncodeHintIndex(entries)
		if err != nil {
			v2Fail(w, 500, "internal_error")
			return
		}
	}
	setCommonHeaders(w.Header())
	w.Header().Set("Content-Type", ContentTypeEnvelope)
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}
func (s *V2Server) describeV2(w http.ResponseWriter) {
	l := s.store.limits
	value := struct {
		Schema        string `json:"schema"`
		Envelope      int    `json:"max_envelope_bytes"`
		TTL           uint64 `json:"max_ttl_seconds"`
		Count         int    `json:"per_recipient_max_envelopes"`
		Bytes         int64  `json:"per_recipient_max_bytes"`
		Strangers     int    `json:"stranger_max_envelopes"`
		StrangerBytes int64  `json:"stranger_max_bytes"`
		Wait          int    `json:"max_wait_seconds"`
		Directory     bool   `json:"directory"`
	}{"tos.service.agent-packet-relay.relay.v2", MaxEnvelopeBytes, uint64(l.Base.TTL / time.Second), l.Base.PerRecipientMaxEnvelopes, l.Base.PerRecipientMaxBytes, l.StrangerMaxEnvelopes, l.StrangerMaxBytes, 25, s.directory}
	v2WriteJSON(w, 200, value, MaxResponseBytes)
}
