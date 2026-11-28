package agentpacketrelay

import (
	"bytes"
	"context"
	"errors"
	"sort"

	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

const DefaultDirectoryAgents = 16384
const DefaultRevocationEntries = 65536
const maxDirectoryAgents = 262144
const maxRevocationEntries = 1048576
const maxRevocationFileBytes = 256 << 10

type v2ControlLimits struct {
	DirectoryAgents   int
	RevocationEntries int
	Waiters           int
}

func controlLimits(options V2OpenOptions) (v2ControlLimits, error) {
	l := v2ControlLimits{options.DirectoryAgents, options.RevocationEntries, options.MaxWaiters}
	if l.DirectoryAgents == 0 {
		l.DirectoryAgents = DefaultDirectoryAgents
	}
	if l.RevocationEntries == 0 {
		l.RevocationEntries = DefaultRevocationEntries
	}
	if l.Waiters == 0 {
		l.Waiters = 512
	}
	if l.DirectoryAgents < 1 || l.DirectoryAgents > maxDirectoryAgents || l.RevocationEntries < 1 || l.RevocationEntries > maxRevocationEntries || l.Waiters < 1 || l.Waiters > 4096 {
		return l, errors.New("invalid V2 control table limits")
	}
	return l, nil
}

type v2RevocationRecord struct {
	Version string       `json:"version"`
	Agent   string       `json:"agent"`
	Entries []Revocation `json:"entries"`
}

func revocationName(agent string) string {
	digest, _ := parseAgentText(agent)
	return "controls/r-" + hexAgent(digest)
}
func checkedChains(checked agenttransport.CheckedRequest) ([][32]byte, error) {
	if _, err := checkedReplayIdentity(checked); err != nil {
		return nil, err
	}
	return checked.Credential.ChainValues()
}
func (s *V2Store) revokedLocked(agent string, chains [][32]byte, now uint64) bool {
	for _, chain := range chains {
		if s.revocations[agent][chain] > now {
			return true
		}
	}
	return false
}
func (s *V2Store) checkRevoked(ctx context.Context, agent string, checked agenttransport.CheckedRequest, now uint64) error {
	chains, err := checkedChains(checked)
	if err != nil {
		return err
	}
	if err = s.mu.lock(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if err = s.available(); err != nil {
		return err
	}
	if s.revokedLocked(agent, chains, now) {
		return ErrCredentialRevoked
	}
	return nil
}
func sortedRevocations(entries map[[32]byte]uint64) []Revocation {
	out := make([]Revocation, 0, len(entries))
	for chain, until := range entries {
		out = append(out, Revocation{chain, until})
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].Chain[:], out[j].Chain[:]) < 0 })
	return out
}
func (s *V2Store) writeRevocationsLocked(agent string, entries map[[32]byte]uint64) error {
	var err error
	if len(entries) == 0 {
		err = s.disk.remove(revocationName(agent))
	} else {
		var raw []byte
		raw, err = encodeV2(v2RevocationRecord{"tos.service.relay-revocations.v2", agent, sortedRevocations(entries)})
		if err == nil {
			if len(raw) > maxRevocationFileBytes {
				return ErrStoreUnavailable
			}
			err = s.disk.write(revocationName(agent), raw)
		}
	}
	if err != nil {
		s.poisoned = true
		return ErrStoreUnavailable
	}
	s.revocationCount -= len(s.revocations[agent])
	if len(entries) == 0 {
		delete(s.revocations, agent)
	} else {
		s.revocations[agent] = entries
	}
	s.revocationCount += len(entries)
	s.notifyLocked(agent)
	return nil
}
func (s *V2Store) revoke(ctx context.Context, agent string, entries []Revocation, checked agenttransport.CheckedRequest, now uint64) error {
	if len(entries) < 1 || len(entries) > 32 {
		return ErrRevocation
	}
	for _, entry := range entries {
		if !validRevocationTime(entry.Until, now) {
			return ErrRevocation
		}
	}
	chains, err := checkedChains(checked)
	if err != nil {
		return err
	}
	if err = s.mu.lock(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if err = s.available(); err != nil {
		return err
	}
	if s.revokedLocked(agent, chains, now) {
		return ErrCredentialRevoked
	}
	updated := make(map[[32]byte]uint64)
	for chain, until := range s.revocations[agent] {
		if until > now {
			updated[chain] = until
		}
	}
	for _, entry := range entries {
		if entry.Until > now {
			updated[entry.Chain] = max(updated[entry.Chain], entry.Until)
		}
	}
	if len(updated) > 1024 || s.revocationCount-len(s.revocations[agent])+len(updated) > s.controlLimits.RevocationEntries {
		return errControlQuota
	}
	return s.writeRevocationsLocked(agent, updated)
}
func (s *V2Store) sweepRevocationsLocked(now uint64) error {
	for agent, current := range s.revocations {
		updated := make(map[[32]byte]uint64)
		for chain, until := range current {
			if until > now {
				updated[chain] = until
			}
		}
		if len(updated) != len(current) {
			if err := s.writeRevocationsLocked(agent, updated); err != nil {
				return err
			}
		}
	}
	return nil
}

var errControlQuota = errors.New("V2 control quota exhausted")
