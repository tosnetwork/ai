package agentpacketrelay

import (
	"bytes"
	"errors"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"path/filepath"
	"strings"
)

func (s *V2Store) loadControls(now uint64) error {
	limit := MaxV2Policies + 4*s.controlLimits.DirectoryAgents + s.controlLimits.RevocationEntries
	entries, err := boundedV2Dir(filepath.Join(s.disk.root, "controls"), limit)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case strings.HasPrefix(name, "r-"):
			err = s.loadRevocations(name, now)
		case strings.HasPrefix(name, "h-"):
			err = s.loadHint(name, now)
		case len(name) == 64:
			err = s.loadPolicy(name, now)
		default:
			err = errors.New("unknown V2 control record")
		}
		if err != nil {
			return err
		}
	}
	return nil
}
func (s *V2Store) loadRevocations(name string, now uint64) error {
	raw, err := readV2File(filepath.Join(s.disk.root, "controls", name), maxRevocationFileBytes)
	if err != nil {
		return err
	}
	var record v2RevocationRecord
	if err = decodeV2(raw, &record); err != nil {
		return err
	}
	if _, ok := parseAgentText(record.Agent); !ok || record.Version != "tos.service.relay-revocations.v2" || revocationName(record.Agent) != "controls/"+name || len(record.Entries) == 0 || len(record.Entries) > 1024 {
		return errors.New("invalid revocation record")
	}
	kept := map[[32]byte]uint64{}
	for i, e := range record.Entries {
		if i > 0 && bytes.Compare(record.Entries[i-1].Chain[:], e.Chain[:]) >= 0 {
			return errors.New("noncanonical revocations")
		}
		if e.Until > now {
			kept[e.Chain] = e.Until
		}
	}
	if s.revocationCount+len(kept) > s.controlLimits.RevocationEntries {
		return errControlQuota
	}
	s.revocations[record.Agent] = kept
	s.revocationCount += len(kept)
	if len(kept) != len(record.Entries) {
		return s.writeRevocationsLocked(record.Agent, kept)
	}
	return nil
}
func (s *V2Store) loadHint(name string, now uint64) error {
	raw, err := readV2File(filepath.Join(s.disk.root, "controls", name), 64<<10)
	if err != nil {
		return err
	}
	var record v2HintRecord
	if err = decodeV2(raw, &record); err != nil {
		return err
	}
	meta, err := hintMetadata(record.Agent, record.Raw)
	if err != nil || record.Version != "tos.service.relay-hint.v2" || hintName(record.Agent, meta.Digest) != "controls/"+name {
		return errors.New("invalid hint record")
	}
	d, decodeErr := agenttransport.DecodeDelegation(meta.Delegation)
	if decodeErr != nil {
		return decodeErr
	}
	if meta.ExpiresAt <= now || d.NotAfter <= now {
		return s.disk.remove("controls/" + name)
	}
	if len(s.hints[record.Agent]) >= 4 || (len(s.hints[record.Agent]) == 0 && len(s.hints) >= s.controlLimits.DirectoryAgents) {
		return errControlQuota
	}
	if s.hints[record.Agent] == nil {
		s.hints[record.Agent] = map[[32]byte]v2HintMeta{}
	}
	s.hints[record.Agent][meta.Digest] = meta
	return nil
}
