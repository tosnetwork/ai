package agentpacketrelay

import (
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"path/filepath"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

const v2PolicyDomain = "tos.service.relay-mailbox-policy.v1\x00"
const maxV2PolicyBytes = len(v2PolicyDomain) + 8 + 2 + 4
const MaxV2Policies = 4096

type MailboxPolicy struct {
	IssuedAt      uint64 `json:"issued_at"`
	StrangerCount uint16 `json:"stranger_count"`
	StrangerBytes uint32 `json:"stranger_bytes"`
}

func (p MailboxPolicy) Encode() []byte {
	out := append([]byte(nil), v2PolicyDomain...)
	out = binary.BigEndian.AppendUint64(out, p.IssuedAt)
	out = binary.BigEndian.AppendUint16(out, p.StrangerCount)
	return binary.BigEndian.AppendUint32(out, p.StrangerBytes)
}
func DecodeMailboxPolicy(raw []byte) (MailboxPolicy, error) {
	if len(raw) != maxV2PolicyBytes || string(raw[:len(v2PolicyDomain)]) != v2PolicyDomain {
		return MailboxPolicy{}, errors.New("invalid mailbox policy")
	}
	b := raw[len(v2PolicyDomain):]
	return MailboxPolicy{binary.BigEndian.Uint64(b), binary.BigEndian.Uint16(b[8:]), binary.BigEndian.Uint32(b[10:])}, nil
}
func (p MailboxPolicy) valid(l V2Limits, now uint64) bool {
	return p.StrangerCount <= uint16(l.StrangerMaxEnvelopes) && uint64(p.StrangerBytes) <= uint64(l.StrangerMaxBytes) && !(p.IssuedAt > now && p.IssuedAt-now > 300)
}

type v2PolicyRecord struct {
	Version    string        `json:"version"`
	Agent      string        `json:"agent"`
	Policy     MailboxPolicy `json:"policy"`
	Delegation []byte        `json:"delegation"`
}

func policyName(agent string) string {
	digest, _ := parseAgentText(agent)
	return "controls/" + hexAgent(digest)
}
func hexAgent(a agentDigest) string {
	const h = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range a {
		out[2*i] = h[b>>4]
		out[2*i+1] = h[b&15]
	}
	return string(out)
}
func (s *V2Store) loadPolicies(now uint64) error {
	entries, err := boundedV2Dir(filepath.Join(s.disk.root, "controls"), MaxV2Policies)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		raw, err := readV2File(filepath.Join(s.disk.root, "controls", entry.Name()), 4096)
		if err != nil {
			return err
		}
		var record v2PolicyRecord
		if err = decodeV2(raw, &record); err != nil {
			return err
		}
		if _, ok := parseAgentText(record.Agent); !ok || record.Version != "tos.service.relay-policy-record.v2" || policyName(record.Agent) != "controls/"+entry.Name() {
			return errors.New("invalid policy record identity")
		}
		d, err := agenttransport.DecodeDelegation(record.Delegation)
		if err != nil || d.AgentID() != record.Agent || !record.Policy.valid(s.limits, record.Policy.IssuedAt) {
			return errors.New("invalid stored mailbox policy")
		}
		if d.NotAfter <= now {
			if err = s.disk.remove(policyName(record.Agent)); err != nil {
				return err
			}
			continue
		}
		s.policies[record.Agent] = record
	}
	return nil
}

// Caller holds the store gate. An unavailable read never lifts a closed policy.
// Only positive revocation/expiry evidence voids it; the next publication may
// then use an earlier timestamp than the revoked key's policy.
func (s *V2Server) currentPolicy(ctx context.Context, agent string) (*v2PolicyRecord, error) {
	p, ok := s.store.policies[agent]
	if !ok {
		return nil, nil
	}
	_, err := s.verifier.VerifyDelegation(ctx, p.Delegation, agenttransport.Relay)
	if err == nil || !errors.Is(err, agenttransport.ErrDelegationRevoked) {
		return &p, nil
	}
	if err = s.store.disk.remove(policyName(agent)); err != nil {
		s.store.poisoned = true
		return nil, ErrStoreUnavailable
	}
	delete(s.store.policies, agent)
	return nil, nil
}
func (s *V2Server) policyBudget(ctx context.Context, agent string) (v2Usage, error) {
	if err := s.store.mu.lock(ctx); err != nil {
		return v2Usage{}, err
	}
	defer s.store.mu.Unlock()
	if err := s.store.available(); err != nil {
		return v2Usage{}, err
	}
	p, err := s.currentPolicy(ctx, agent)
	if err != nil {
		return v2Usage{}, err
	}
	if p != nil {
		return v2Usage{int(p.Policy.StrangerCount), int64(p.Policy.StrangerBytes)}, nil
	}
	return v2Usage{s.store.limits.StrangerMaxEnvelopes, s.store.limits.StrangerMaxBytes}, nil
}
func (s *V2Server) setPolicy(w http.ResponseWriter, r *http.Request, agent string, body []byte, checked agenttransport.CheckedRequest) {
	p, err := DecodeMailboxPolicy(body)
	if err != nil || !p.valid(s.store.limits, unixNow(s.now())) {
		v2Fail(w, 400, CodeInvalidRequest)
		return
	}
	if err = s.store.mu.lock(r.Context()); err != nil {
		v2Fail(w, 503, CodeUnavailable)
		return
	}
	defer s.store.mu.Unlock()
	if err = s.store.available(); err != nil {
		v2Fail(w, 503, CodeUnavailable)
		return
	}
	old, err := s.currentPolicy(r.Context(), agent)
	if err != nil {
		v2Fail(w, 503, CodeUnavailable)
		return
	}
	if old != nil && p.IssuedAt <= old.Policy.IssuedAt {
		v2Empty(w, 200)
		return
	}
	if old == nil && len(s.store.policies) >= MaxV2Policies {
		v2Fail(w, 503, CodeUnavailable)
		return
	}
	raw, err := checked.Credential.DelegationBytes()
	if err != nil {
		v2Fail(w, 403, "credential_invalid")
		return
	}
	record := v2PolicyRecord{"tos.service.relay-policy-record.v2", agent, p, raw}
	encoded, err := encodeV2(record)
	if err == nil {
		err = s.store.disk.write(policyName(agent), encoded)
	}
	if err != nil {
		s.store.poisoned = true
		v2Fail(w, 503, CodeUnavailable)
		return
	}
	s.store.policies[agent] = record
	v2Empty(w, 204)
}

// RunV2Maintenance owns the replay writer and expiry sweeper until cancellation.
func RunV2Maintenance(ctx context.Context, store *V2Store, now func() time.Time, onFailure func()) {
	if now == nil {
		now = time.Now
	}
	done := make(chan struct{})
	go func() { defer close(done); store.Replay().Run(ctx, now, onFailure) }()
	defer func() { <-done }()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := store.Sweep(now()); err != nil && onFailure != nil {
				onFailure()
			}
		}
	}
}
