package eventlog

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
)

const (
	relayEvidenceDir = "relay-evidence"
	relayPullDir     = "relay-pull"

	// RelayEvidenceSchema is the on-disk record of one peer's committed relay
	// identity evidence.
	RelayEvidenceSchema = "tos.messaging.relay-evidence-record.v1"
	// RelayPullSchema is the on-disk record of one peer's evidence pull and
	// card acknowledgement state.
	RelayPullSchema = "tos.messaging.relay-pull-record.v1"

	// MaxRelayPeers bounds the peers with committed relay evidence. At the
	// bound a new peer is refused; no stored peer is evicted to make room.
	MaxRelayPeers = 4096
	// maxRelayEvidenceBytes repeats the frame evidence bound.
	maxRelayEvidenceBytes = 18_432
)

// relayPeerCap is MaxRelayPeers; a test lowers it to reach the bound.
var relayPeerCap = MaxRelayPeers

// ErrRelayPeersFull reports the relay evidence store at its bound.
var ErrRelayPeersFull = errors.New("relay evidence store holds its maximum number of peers")

// ErrRelayEvidenceConflict reports a commit whose read is no longer current.
var ErrRelayEvidenceConflict = errors.New("stored relay evidence changed since it was read")

type relayEvidenceRecord struct {
	Schema         string `json:"schema"`
	AgentID        string `json:"agent_id"`
	EvidenceBase64 string `json:"evidence_base64"`
	EvidenceDigest string `json:"evidence_digest"`
	UpdatedAtUnix  uint64 `json:"updated_at_unix"`
}

// LoadRelayEvidence returns the evidence last committed for a peer.
func (j *Journal) LoadRelayEvidence(agentID string) ([]byte, bool, error) {
	if err := j.usable(); err != nil {
		return nil, false, err
	}
	if !ids.Agent.MatchString(agentID) {
		return nil, false, errors.New("invalid relay evidence Agent identifier")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.readRelayEvidence(agentID)
}

// StoreRelayEvidence replaces a peer's committed evidence. previousDigest is
// the digest of the evidence the caller read, or empty when it read none; a
// mismatch is ErrRelayEvidenceConflict and nothing is written.
func (j *Journal) StoreRelayEvidence(agentID string, evidence []byte, previousDigest string, now time.Time) error {
	if err := j.usable(); err != nil {
		return err
	}
	if !ids.Agent.MatchString(agentID) {
		return errors.New("invalid relay evidence Agent identifier")
	}
	if len(evidence) == 0 || len(evidence) > maxRelayEvidenceBytes {
		return errors.New("relay evidence size is outside its bound")
	}
	if previousDigest != "" && !canon.ValidDigest(previousDigest) {
		return errors.New("invalid previous relay evidence digest")
	}
	if now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid relay evidence time")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	current, found, err := j.readRelayEvidence(agentID)
	if err != nil {
		return err
	}
	switch {
	case found && canon.Digest(current) != previousDigest:
		return ErrRelayEvidenceConflict
	case !found && previousDigest != "":
		return ErrRelayEvidenceConflict
	}
	if !found {
		entries, err := os.ReadDir(filepath.Join(j.root, relayEvidenceDir))
		if err != nil {
			return errors.New("read relay evidence store")
		}
		count := 0
		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
				count++
			}
		}
		if count >= relayPeerCap {
			return ErrRelayPeersFull
		}
	}
	encoded, err := json.Marshal(relayEvidenceRecord{Schema: RelayEvidenceSchema, AgentID: agentID,
		EvidenceBase64: base64.StdEncoding.EncodeToString(evidence), EvidenceDigest: canon.Digest(evidence),
		UpdatedAtUnix: uint64(now.Unix())})
	if err != nil {
		return err
	}
	if err := j.replace(j.relayEvidencePath(agentID), encoded); err != nil {
		return err
	}
	// The record is the floor again (relay_floor.go).
	return j.dropRelayFloor(agentID)
}

func (j *Journal) readRelayEvidence(agentID string) ([]byte, bool, error) {
	raw, err := readRecordBytes(j.relayEvidencePath(agentID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var record relayEvidenceRecord
	if err := json.Unmarshal(raw, &record); err != nil || record.Schema != RelayEvidenceSchema ||
		record.AgentID != agentID {
		return nil, false, errors.New("invalid relay evidence record")
	}
	evidence, err := base64.StdEncoding.Strict().DecodeString(record.EvidenceBase64)
	if err != nil || len(evidence) == 0 || len(evidence) > maxRelayEvidenceBytes ||
		canon.Digest(evidence) != record.EvidenceDigest {
		return nil, false, errors.New("invalid relay evidence record")
	}
	return evidence, true, nil
}

func (j *Journal) relayEvidencePath(agentID string) string {
	return filepath.Join(j.root, relayEvidenceDir, agentID[len("agent_"):]+".json")
}

// RelayPull is one peer's evidence pull state: at most one outstanding
// request, the last response this node sent it, and the newest own chat card
// the peer acknowledged a frame of.
type RelayPull struct {
	Schema    string `json:"schema"`
	AgentID   string `json:"agent_id"`
	Requested bool   `json:"request_outstanding"`
	// RequestGeneration counts deposits of the outstanding request; each
	// re-deposit is a new generation with a fresh carrier key.
	RequestGeneration uint32 `json:"request_generation,omitempty"`
	RequestNextAtUnix uint64 `json:"request_next_at_unix,omitempty"`
	RequestLastAtUnix uint64 `json:"request_last_at_unix,omitempty"`
	// ResponsePending marks a request from this admitted peer that is owed
	// one response; the response is sent by the pull sweep, rate-limited.
	ResponsePending    bool   `json:"response_pending,omitempty"`
	ResponseDescriptor string `json:"response_descriptor_digest,omitempty"`
	ResponseAtUnix     uint64 `json:"response_at_unix,omitempty"`
	AckedCardDigest    string `json:"acked_card_digest,omitempty"`
	UpdatedAtUnix      uint64 `json:"updated_at_unix"`
}

// LoadRelayPull returns a peer's pull state, or a fresh empty record.
func (j *Journal) LoadRelayPull(agentID string) (RelayPull, bool, error) {
	if err := j.usable(); err != nil {
		return RelayPull{}, false, err
	}
	if !ids.Agent.MatchString(agentID) {
		return RelayPull{}, false, errors.New("invalid relay pull Agent identifier")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.readRelayPull(agentID)
}

// ListRelayPulls returns every peer with an outstanding request or an owed
// response.
func (j *Journal) ListRelayPulls() ([]RelayPull, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	entries, err := os.ReadDir(filepath.Join(j.root, relayPullDir))
	if err != nil {
		return nil, errors.New("read relay pull store")
	}
	var pulls []RelayPull
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".json" || len(name) != 64+len(".json") {
			continue
		}
		pull, found, err := j.readRelayPull("agent_" + name[:64])
		if err != nil || !found || !pull.Requested && !pull.ResponsePending {
			continue
		}
		pulls = append(pulls, pull)
	}
	return pulls, nil
}

// PutRelayPull durably replaces a peer's pull state.
func (j *Journal) PutRelayPull(pull RelayPull, now time.Time) error {
	if err := j.usable(); err != nil {
		return err
	}
	if !ids.Agent.MatchString(pull.AgentID) {
		return errors.New("invalid relay pull Agent identifier")
	}
	if now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid relay pull time")
	}
	if pull.Requested && pull.RequestNextAtUnix == 0 {
		return errors.New("an outstanding relay pull needs a schedule")
	}
	if pull.ResponseDescriptor != "" && !canon.ValidDigest(pull.ResponseDescriptor) ||
		pull.AckedCardDigest != "" && !canon.ValidDigest(pull.AckedCardDigest) {
		return errors.New("invalid relay pull digest")
	}
	pull.Schema = RelayPullSchema
	pull.UpdatedAtUnix = uint64(now.Unix())
	encoded, err := json.Marshal(pull)
	if err != nil {
		return err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.replace(filepath.Join(j.root, relayPullDir, pull.AgentID[len("agent_"):]+".json"), encoded)
}

func (j *Journal) readRelayPull(agentID string) (RelayPull, bool, error) {
	raw, err := readRecordBytes(filepath.Join(j.root, relayPullDir, agentID[len("agent_"):]+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return RelayPull{Schema: RelayPullSchema, AgentID: agentID}, false, nil
	}
	if err != nil {
		return RelayPull{}, false, err
	}
	var pull RelayPull
	if err := json.Unmarshal(raw, &pull); err != nil || pull.Schema != RelayPullSchema || pull.AgentID != agentID {
		return RelayPull{}, false, errors.New("invalid relay pull record")
	}
	return pull, true, nil
}

// EventCommittedInSession reports whether an inbound Event was already
// opened and committed under a session. It is what lets a receiver answer an
// older duplicate without handing its ciphertext to the ratchet.
func (j *Journal) EventCommittedInSession(sessionID, eventID string) (bool, error) {
	if err := j.usable(); err != nil {
		return false, err
	}
	if !sessionPattern.MatchString(sessionID) || !eventPattern.MatchString(eventID) {
		return false, errors.New("invalid committed Event lookup")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	record, err := readRecord(j.path(eventID))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return record.SessionID == sessionID && record.Crypto == CryptoCommitted, nil
}
