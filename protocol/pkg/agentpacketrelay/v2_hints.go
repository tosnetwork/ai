package agentpacketrelay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"sort"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

type v2HintMeta struct {
	Digest, Sum         [32]byte
	IssuedAt, ExpiresAt uint64
	Length              uint32
	Delegation          []byte
}
type v2HintRecord struct {
	Version string `json:"version"`
	Agent   string `json:"agent"`
	Raw     []byte `json:"raw"`
}

func hintName(agent string, digest [32]byte) string {
	a, _ := parseAgentText(agent)
	return "controls/h-" + hexAgent(a) + "-" + hexAgent(digest)
}
func hintMetadata(agent string, raw []byte) (v2HintMeta, error) {
	record, err := agenttransport.DecodeHintRecord(raw)
	if err != nil || record.Hint.Delegation.AgentID() != agent {
		return v2HintMeta{}, agenttransport.ErrHint
	}
	d, err := record.Hint.Delegation.Encode()
	if err != nil {
		return v2HintMeta{}, err
	}
	return v2HintMeta{sha256.Sum256(d), sha256.Sum256(raw), record.Hint.IssuedAt, record.Hint.ExpiresAt, uint32(len(raw)), d}, nil
}
func (s *V2Store) removeHintLocked(agent string, digest [32]byte, expected [32]byte) error {
	existing, ok := s.hints[agent][digest]
	if !ok || existing.Sum != expected {
		return nil
	}
	if err := s.disk.remove(hintName(agent, digest)); err != nil {
		s.poisoned = true
		return ErrStoreUnavailable
	}
	delete(s.hints[agent], digest)
	if len(s.hints[agent]) == 0 {
		delete(s.hints, agent)
	}
	return nil
}
func (s *V2Store) readHintLocked(agent string, meta v2HintMeta) ([]byte, error) {
	raw, err := readV2File(filepath.Join(s.disk.root, hintName(agent, meta.Digest)), 64<<10)
	if err != nil {
		return nil, err
	}
	var record v2HintRecord
	if err = decodeV2(raw, &record); err != nil {
		return nil, err
	}
	actual, err := hintMetadata(agent, record.Raw)
	if err != nil || record.Version != "tos.service.relay-hint.v2" || record.Agent != agent || actual.Sum != meta.Sum || actual.Digest != meta.Digest {
		return nil, ErrStoreUnavailable
	}
	return record.Raw, nil
}

type v2HintSnapshot struct {
	Meta       v2HintMeta
	Raw        []byte
	FreshUntil time.Time
}

func (s *V2Store) hintSnapshot(ctx context.Context, agent string, only *[32]byte) ([]v2HintSnapshot, error) {
	if err := s.mu.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	out := make([]v2HintSnapshot, 0, 4)
	for digest, meta := range s.hints[agent] {
		if only != nil && digest != *only {
			continue
		}
		raw, err := s.readHintLocked(agent, meta)
		if err != nil {
			s.poisoned = true
			return nil, ErrStoreUnavailable
		}
		out = append(out, v2HintSnapshot{Meta: meta, Raw: raw})
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].Meta.Digest[:], out[j].Meta.Digest[:]) < 0 })
	return out, nil
}
func (s *V2Server) liveHints(ctx context.Context, agent string, only *[32]byte) ([]v2HintSnapshot, error) {
	records, err := s.store.hintSnapshot(ctx, agent, only)
	if err != nil {
		return nil, err
	}
	out := make([]v2HintSnapshot, 0, len(records))
	for _, record := range records {
		now := unixNow(s.now())
		d, err := agenttransport.DecodeDelegation(record.Meta.Delegation)
		if err != nil {
			return nil, ErrStoreUnavailable
		}
		expired := record.Meta.ExpiresAt <= now || d.NotAfter <= now
		if !expired {
			var verified agenttransport.VerifiedHint
			verified, err = s.verifier.VerifyHint(ctx, record.Raw, s.hintPolicy)
			record.FreshUntil = verified.FreshUntil
		}
		if expired || errors.Is(err, agenttransport.ErrDelegationRevoked) {
			if lockErr := s.store.mu.lock(ctx); lockErr != nil {
				return nil, lockErr
			}
			removeErr := s.store.removeHintLocked(agent, record.Meta.Digest, record.Meta.Sum)
			s.store.mu.Unlock()
			if removeErr != nil {
				return nil, removeErr
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

var errHintConflict = errors.New("equal-time hint differs")

func (s *V2Server) putHint(ctx context.Context, agent string, raw []byte) error {
	verified, err := s.verifier.VerifyHint(ctx, raw, s.hintPolicy)
	if err != nil {
		return err
	}
	if verified.Record.Hint.Delegation.AgentID() != agent {
		return agenttransport.ErrCredentialScope
	}
	namesRelay := s.directory
	for _, relay := range verified.Record.Hint.Relays {
		if relay == s.relay {
			namesRelay = true
		}
	}
	if !namesRelay {
		return agenttransport.ErrCredentialScope
	}
	meta, err := hintMetadata(agent, raw)
	if err != nil {
		return err
	}
	if _, err = s.liveHints(ctx, agent, nil); err != nil {
		return err
	}
	if err = s.store.mu.lock(ctx); err != nil {
		return err
	}
	defer s.store.mu.Unlock()
	if err = s.store.available(); err != nil {
		return err
	}
	if !s.now().Before(verified.FreshUntil) {
		return agenttransport.ErrUnavailable
	}
	now := unixNow(s.now())
	if meta.ExpiresAt <= now || (meta.IssuedAt > now && meta.IssuedAt-now > 300) {
		return agenttransport.ErrHint
	}
	existing, ok := s.store.hints[agent][meta.Digest]
	if ok {
		if existing.IssuedAt > meta.IssuedAt {
			return nil
		}
		if existing.IssuedAt == meta.IssuedAt {
			if existing.Sum != meta.Sum {
				return errHintConflict
			}
			return nil
		}
	}
	if !ok && len(s.store.hints[agent]) >= 4 {
		return errControlQuota
	}
	if len(s.store.hints[agent]) == 0 && len(s.store.hints) >= s.store.controlLimits.DirectoryAgents {
		return errControlQuota
	}
	encoded, err := encodeV2(v2HintRecord{"tos.service.relay-hint.v2", agent, bytes.Clone(raw)})
	if err != nil {
		return err
	}
	if err = s.store.disk.write(hintName(agent, meta.Digest), encoded); err != nil {
		s.store.poisoned = true
		return ErrStoreUnavailable
	}
	if s.store.hints[agent] == nil {
		s.store.hints[agent] = map[[32]byte]v2HintMeta{}
	}
	s.store.hints[agent][meta.Digest] = meta
	return nil
}
func (s *V2Store) sweepHintsLocked(now uint64) error {
	for agent, records := range s.hints {
		for digest, meta := range records {
			d, err := agenttransport.DecodeDelegation(meta.Delegation)
			if err != nil {
				return ErrStoreUnavailable
			}
			if meta.ExpiresAt <= now || d.NotAfter <= now {
				if err = s.removeHintLocked(agent, digest, meta.Sum); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
