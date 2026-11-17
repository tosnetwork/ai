package eventlog

// Expiry of committed relay evidence.
//
// The relay evidence store holds at most MaxRelayPeers peers and evicts
// none, so a peer whose evidence expired would hold its slot forever and,
// once the store filled with such peers, every new contact and room member
// would be refused. The caller (directory.RelayVerifier) therefore retires a
// record once its evidence can no longer pass CheckPeer.
//
// The stored record is also the floor of the newer-only rule: a peer's
// evidence is replaced only by evidence with a later descriptor issue time.
// Expiry is not monotonic in that ordering key (an older descriptor may have
// a longer lifetime than a newer one), so deleting the record outright would
// let older evidence that is still unexpired be committed again. Retirement
// keeps a floor instead: the retired descriptor's digest and issue time
// only. A floor admits the peer as the record did, and the caller judges a
// commit with no record against it. A floor is safe to drop once its issue
// time plus the largest descriptor lifetime has passed, because by then all
// evidence at or below it has expired; floors are dropped only past that
// horizon, only when the floor store needs room, and never the floor of a
// contact or of a peer with a session here, whose admission it is. Floors live apart from
// the records, so retiring a record frees its slot in MaxRelayPeers.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
)

const (
	relayFloorDir = "relay-evidence-floor"
	// RelayFloorSchema is the on-disk record of one retired peer's floor.
	RelayFloorSchema = "tos.messaging.relay-evidence-floor.v1"
	// MaxRelayFloors bounds the retired peers' floors.
	MaxRelayFloors = MaxRelayPeers
)

// relayFloorCap is MaxRelayFloors; a test lowers it to reach the bound.
var relayFloorCap = MaxRelayFloors

// beforeRelayEvidenceDelete, when set by a test, runs between a retirement's
// floor write and its record deletion: the crash window a restart repeats.
var beforeRelayEvidenceDelete func() error

// RelayEvidenceFloor is the ordering key of a retired peer's last committed
// evidence: its descriptor digest and descriptor issue time.
type RelayEvidenceFloor struct {
	Schema                 string `json:"schema"`
	AgentID                string `json:"agent_id"`
	DescriptorDigest       string `json:"descriptor_digest"`
	DescriptorIssuedAtUnix uint64 `json:"descriptor_issued_at_unix"`
	RetiredAtUnix          uint64 `json:"retired_at_unix"`
}

func (j *Journal) relayFloorPath(agentID string) string {
	return filepath.Join(j.root, relayFloorDir, agentID[len("agent_"):]+".json")
}

// LoadRelayEvidenceFloor returns a retired peer's floor.
func (j *Journal) LoadRelayEvidenceFloor(agentID string) (RelayEvidenceFloor, bool, error) {
	if err := j.usable(); err != nil {
		return RelayEvidenceFloor{}, false, err
	}
	if !ids.Agent.MatchString(agentID) {
		return RelayEvidenceFloor{}, false, errors.New("invalid relay evidence Agent identifier")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.readRelayFloor(agentID)
}

// ListRelayEvidencePeers returns the peers with committed evidence.
func (j *Journal) ListRelayEvidencePeers() ([]string, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.relayAgentsIn(relayEvidenceDir)
}

// RetireRelayEvidence retires a peer's committed evidence, which the caller
// judged unusable: the floor is written first, then the record is deleted,
// each durably. It reports false, writing nothing, when the record is gone
// or no longer has evidenceDigest (a newer commit won), or when the floor
// store is full of floors still inside their horizon: the record is then
// kept, which is always safe. horizon is the largest descriptor lifetime: a
// floor older than it may be dropped to make room.
//
// contacts are the configured contacts of this installation. A floor whose
// peer is a contact (configured, or made by a claimed invite) or has a
// session here is never evicted to make room: the floor is that peer's
// admission, which its kind-4 evidence responses need.
func (j *Journal) RetireRelayEvidence(agentID, evidenceDigest string, floor RelayEvidenceFloor, horizon time.Duration,
	contacts map[string]struct{}, now time.Time) (bool, error) {
	if err := j.usable(); err != nil {
		return false, err
	}
	if !ids.Agent.MatchString(agentID) || !canon.ValidDigest(evidenceDigest) || !canon.ValidDigest(floor.DescriptorDigest) ||
		floor.DescriptorIssuedAtUnix == 0 || horizon <= 0 || now.IsZero() || now.Unix() <= 0 {
		return false, errors.New("invalid relay evidence retirement")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	current, found, err := j.readRelayEvidence(agentID)
	if err != nil {
		return false, err
	}
	if !found || canon.Digest(current) != evidenceDigest {
		return false, nil
	}
	existing, held, err := j.readRelayFloor(agentID)
	if err != nil {
		return false, err
	}
	// A floor only ever rises.
	if !held || floor.DescriptorIssuedAtUnix > existing.DescriptorIssuedAtUnix {
		if !held {
			room, err := j.makeRelayFloorRoom(horizon, contacts, now)
			if err != nil || !room {
				return false, err
			}
		}
		record := RelayEvidenceFloor{Schema: RelayFloorSchema, AgentID: agentID, DescriptorDigest: floor.DescriptorDigest,
			DescriptorIssuedAtUnix: floor.DescriptorIssuedAtUnix, RetiredAtUnix: uint64(now.Unix())}
		encoded, err := json.Marshal(record)
		if err != nil {
			return false, err
		}
		if err := j.replace(j.relayFloorPath(agentID), encoded); err != nil {
			return false, err
		}
	}
	if beforeRelayEvidenceDelete != nil {
		if err := beforeRelayEvidenceDelete(); err != nil {
			return false, err
		}
	}
	path := j.relayEvidencePath(agentID)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, errors.New("delete relay evidence")
	}
	return true, syncDirectory(filepath.Dir(path))
}

// makeRelayFloorRoom ensures the floor store can take one more floor,
// dropping the oldest evictable floor if it is full: one past its horizon
// whose peer is no contact and has no session here. It reports false when
// no floor can go. The journal mutex is held.
func (j *Journal) makeRelayFloorRoom(horizon time.Duration, contacts map[string]struct{}, now time.Time) (bool, error) {
	agents, err := j.relayAgentsIn(relayFloorDir)
	if err != nil {
		return false, err
	}
	if len(agents) < relayFloorCap {
		return true, nil
	}
	floors := make([]RelayEvidenceFloor, 0, len(agents))
	for _, agentID := range agents {
		floor, found, err := j.readRelayFloor(agentID)
		if err != nil {
			return false, err
		}
		if found {
			floors = append(floors, floor)
		}
	}
	sort.Slice(floors, func(a, b int) bool { return floors[a].DescriptorIssuedAtUnix < floors[b].DescriptorIssuedAtUnix })
	seconds := uint64(horizon / time.Second)
	var sessionPeers map[string]struct{}
	for _, floor := range floors {
		// Floors are in issue order: once one is inside its horizon, so are
		// all after it.
		if floor.DescriptorIssuedAtUnix > ^uint64(0)-seconds || floor.DescriptorIssuedAtUnix+seconds > uint64(now.Unix()) {
			return false, nil
		}
		if _, contact := contacts[floor.AgentID]; contact {
			continue
		}
		_, invited, err := readInvitedContact(j.agentRecordPath(invitedContactDir, floor.AgentID), floor.AgentID)
		if err != nil {
			return false, err
		}
		if invited {
			continue
		}
		if sessionPeers == nil {
			if sessionPeers, err = j.sessionPeers(); err != nil {
				return false, err
			}
		}
		if _, session := sessionPeers[floor.AgentID]; session {
			continue
		}
		if err := os.Remove(j.relayFloorPath(floor.AgentID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, errors.New("delete relay evidence floor")
		}
		return true, syncDirectory(filepath.Join(j.root, relayFloorDir))
	}
	return false, nil
}

// sessionPeers lists the peer Agents of every session held here. An
// unreadable session fails the listing, so no floor is evicted on a guess.
// The journal mutex is held.
func (j *Journal) sessionPeers() (map[string]struct{}, error) {
	entries, err := os.ReadDir(filepath.Join(j.root, sessionDir))
	if err != nil {
		return nil, errors.New("read sessions")
	}
	peers := map[string]struct{}{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".json" || !sessionPattern.MatchString("ses_"+strings.TrimSuffix(name, ".json")) {
			continue
		}
		record, err := readSession(filepath.Join(j.root, sessionDir, name))
		if err != nil {
			return nil, err
		}
		if record.Authority != nil {
			peers[record.Authority.PeerAgentID] = struct{}{}
		}
	}
	return peers, nil
}

// dropRelayFloor deletes a peer's floor once newer evidence is committed;
// the record is the floor again. The journal mutex is held.
func (j *Journal) dropRelayFloor(agentID string) error {
	path := j.relayFloorPath(agentID)
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("delete relay evidence floor")
	}
	return syncDirectory(filepath.Dir(path))
}

func (j *Journal) readRelayFloor(agentID string) (RelayEvidenceFloor, bool, error) {
	raw, err := readRecordBytes(j.relayFloorPath(agentID))
	if errors.Is(err, os.ErrNotExist) {
		return RelayEvidenceFloor{}, false, nil
	}
	if err != nil {
		return RelayEvidenceFloor{}, false, err
	}
	var floor RelayEvidenceFloor
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&floor); err != nil || floor.Schema != RelayFloorSchema || floor.AgentID != agentID ||
		!canon.ValidDigest(floor.DescriptorDigest) || floor.DescriptorIssuedAtUnix == 0 || floor.RetiredAtUnix == 0 {
		return RelayEvidenceFloor{}, false, errors.New("invalid relay evidence floor")
	}
	return floor, true, nil
}

// relayAgentsIn lists the Agents of a per-peer relay directory. The journal
// mutex is held.
func (j *Journal) relayAgentsIn(dir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(j.root, dir))
	if err != nil {
		return nil, errors.New("read relay evidence store")
	}
	agents := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".json" || len(name) != 64+len(".json") {
			continue
		}
		if agentID := "agent_" + name[:64]; ids.Agent.MatchString(agentID) {
			agents = append(agents, agentID)
		}
	}
	sort.Strings(agents)
	return agents, nil
}
