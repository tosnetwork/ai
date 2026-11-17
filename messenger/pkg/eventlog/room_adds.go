package eventlog

// The authority's pending adds (section 11.2).
//
// An owner's rooms.add decides that an Agent joins a room this installation
// is the authority of. The decision is journaled before the room.invite is
// sent, so the KeyPackage that answers it is taken only for an Agent the
// owner added: a room.key-package for any other Agent, or after the add
// expired, is refused. The KeyPackage the joiner sent is recorded with the
// add, and the Add Commit is made from that record, so a crash between the
// two is finished from the journal: an add whose Agent the room already
// holds as a member is finished without a second Commit.
//
// An add names no other record, so it is no garbage-collection root. It is
// per-room state and is deleted with the room's other receive state when
// the room retires or is no longer held.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/payload"
)

const (
	roomAddDir    = "room-adds"
	roomAddSchema = "tos.messaging.room-add.v1"
)

// Pending add refusals.
var (
	// ErrRoomAddMember reports an Agent the room already holds as a member.
	ErrRoomAddMember = errors.New("the Agent is already a member of the room")
	// ErrRoomAddsFull reports a room whose members and pending adds already
	// reach the relay room bound.
	ErrRoomAddsFull = errors.New("the room's members and pending adds reach the room bound")
	// ErrRoomAddUnknown reports a KeyPackage for an Agent the owner did not
	// add, or whose add expired.
	ErrRoomAddUnknown = errors.New("no live pending add for the Agent")
	// ErrRoomAddConflict reports a second, different KeyPackage for one add.
	ErrRoomAddConflict = errors.New("the pending add already holds another KeyPackage")
	errRoomAddValue    = errors.New("invalid pending room add record")
)

// RoomAdd is one owner decision to add an Agent to a room.
type RoomAdd struct {
	Schema        string `json:"schema"`
	RoomID        string `json:"room_id"`
	AgentID       string `json:"agent_id"`
	DecidedAtUnix uint64 `json:"decided_at_unix"`
	// ExpiresAtUnix is the invite's expiry: a KeyPackage after it is refused.
	ExpiresAtUnix uint64 `json:"expires_at_unix"`
	// The joiner's answer, once it arrived: its DeviceCredential, its leaf
	// credential and the KeyPackage reference, verified by the caller.
	DeviceCredentialBase64 string `json:"device_credential_base64,omitempty"`
	LeafCredentialBase64   string `json:"leaf_credential_base64,omitempty"`
	KeyPackageRef          string `json:"key_package_ref,omitempty"`
	KeyPackageAtUnix       uint64 `json:"key_package_at_unix,omitempty"`
}

// Ready reports whether the joiner's KeyPackage arrived.
func (a RoomAdd) Ready() bool { return a.KeyPackageRef != "" }

// Credentials returns the joiner's DeviceCredential and leaf credential.
func (a RoomAdd) Credentials() (group.DeviceCredential, group.LeafCredential, error) {
	if !a.Ready() {
		return group.DeviceCredential{}, group.LeafCredential{}, errRoomAddValue
	}
	deviceJSON, err := base64.StdEncoding.Strict().DecodeString(a.DeviceCredentialBase64)
	if err != nil || len(deviceJSON) == 0 || len(deviceJSON) > MaxRoomJoinCredentialBytes {
		return group.DeviceCredential{}, group.LeafCredential{}, errRoomAddValue
	}
	device, err := group.DecodeDeviceCredentialJSON(deviceJSON)
	if err != nil {
		return group.DeviceCredential{}, group.LeafCredential{}, errRoomAddValue
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(a.LeafCredentialBase64)
	if err != nil || len(raw) == 0 || len(raw) > group.MaxLeafCredentialBytes {
		return group.DeviceCredential{}, group.LeafCredential{}, errRoomAddValue
	}
	leaf, err := group.DecodeLeafCredential(raw)
	if err != nil {
		return group.DeviceCredential{}, group.LeafCredential{}, errRoomAddValue
	}
	if device.AgentID != a.AgentID || leaf.AgentID != a.AgentID {
		return group.DeviceCredential{}, group.LeafCredential{}, errRoomAddValue
	}
	ref, err := group.KeyPackageRef(device)
	if err != nil || ref != a.KeyPackageRef {
		return group.DeviceCredential{}, group.LeafCredential{}, errRoomAddValue
	}
	return device, leaf, nil
}

// RecordRoomAdd journals the owner's decision to add an Agent to a room this
// installation holds. A live add for the Agent is returned as it is (not
// fresh); an expired one is replaced. The room's members and live adds
// together never exceed the relay room bound.
func (j *Journal) RecordRoomAdd(roomID, agentID string, expires, now time.Time) (RoomAdd, bool, error) {
	if err := j.usable(); err != nil {
		return RoomAdd{}, false, err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(agentID) || now.IsZero() || now.Unix() <= 0 {
		return RoomAdd{}, false, errors.New("invalid room add")
	}
	if expires.Unix() <= now.Unix() || uint64(expires.Unix()-now.Unix()) > payload.MaxRoomInviteLifetimeSeconds {
		return RoomAdd{}, false, errors.New("invalid room add lifetime")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	record, found, err := j.readRoomMLS(roomID)
	if err != nil {
		return RoomAdd{}, false, err
	}
	if !found {
		return RoomAdd{}, false, ErrRoomNotJoined
	}
	if containsString(record.Members, agentID) {
		return RoomAdd{}, false, ErrRoomAddMember
	}
	adds, err := j.liveRoomAdds(roomID, now)
	if err != nil {
		return RoomAdd{}, false, err
	}
	for _, add := range adds {
		if add.AgentID == agentID {
			return add, false, nil
		}
	}
	// len(record.Members) is at most MaxPrivateRoomAgents and adds holds at
	// most one record per Agent of a bounded directory, so the sum cannot
	// overflow.
	if len(record.Members)+len(adds) >= group.MaxPrivateRoomAgents {
		return RoomAdd{}, false, ErrRoomAddsFull
	}
	add := RoomAdd{Schema: roomAddSchema, RoomID: roomID, AgentID: agentID, DecidedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(expires.Unix())}
	if err := j.writeRoomAdd(add); err != nil {
		return RoomAdd{}, false, err
	}
	return add, true, nil
}

// RecordRoomAddKeyPackage records the KeyPackage that answers a live add,
// after the caller verified it against finalized state. The exact repeat is
// a no-op; another KeyPackage for the same add is refused.
func (j *Journal) RecordRoomAddKeyPackage(roomID, agentID string, deviceJSON, leafCredential []byte, now time.Time) (RoomAdd, error) {
	if err := j.usable(); err != nil {
		return RoomAdd{}, err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(agentID) || now.IsZero() || now.Unix() <= 0 {
		return RoomAdd{}, errors.New("invalid room add KeyPackage")
	}
	if len(deviceJSON) == 0 || len(deviceJSON) > MaxRoomJoinCredentialBytes ||
		len(leafCredential) == 0 || len(leafCredential) > group.MaxLeafCredentialBytes {
		return RoomAdd{}, errors.New("invalid room add credentials")
	}
	device, err := group.DecodeDeviceCredentialJSON(deviceJSON)
	if err != nil {
		return RoomAdd{}, err
	}
	ref, err := group.KeyPackageRef(device)
	if err != nil {
		return RoomAdd{}, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	add, found, err := j.readRoomAdd(roomID, agentID)
	if err != nil {
		return RoomAdd{}, err
	}
	if !found || uint64(now.Unix()) >= add.ExpiresAtUnix {
		return RoomAdd{}, ErrRoomAddUnknown
	}
	if add.Ready() {
		if add.KeyPackageRef == ref {
			return add, nil
		}
		return RoomAdd{}, ErrRoomAddConflict
	}
	add.DeviceCredentialBase64 = base64.StdEncoding.EncodeToString(deviceJSON)
	add.LeafCredentialBase64 = base64.StdEncoding.EncodeToString(leafCredential)
	add.KeyPackageRef = ref
	add.KeyPackageAtUnix = uint64(now.Unix())
	if _, _, err := add.Credentials(); err != nil {
		return RoomAdd{}, err
	}
	if err := j.writeRoomAdd(add); err != nil {
		return RoomAdd{}, err
	}
	return add, nil
}

// RoomAdds returns a room's live pending adds, the ready ones first in the
// order their KeyPackages arrived. Expired adds are deleted.
func (j *Journal) RoomAdds(roomID string, now time.Time) ([]RoomAdd, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	if !ids.Room.MatchString(roomID) || now.IsZero() {
		return nil, errors.New("invalid room add lookup")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	adds, err := j.liveRoomAdds(roomID, now)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(adds, func(a, b int) bool {
		if adds[a].Ready() != adds[b].Ready() {
			return adds[a].Ready()
		}
		if adds[a].KeyPackageAtUnix != adds[b].KeyPackageAtUnix {
			return adds[a].KeyPackageAtUnix < adds[b].KeyPackageAtUnix
		}
		return adds[a].AgentID < adds[b].AgentID
	})
	return adds, nil
}

// FinishRoomAdd deletes an add once its Agent is a member, or once the
// owner's decision can no longer be carried out. Deleting a missing add is a
// no-op.
func (j *Journal) FinishRoomAdd(roomID, agentID string) error {
	if err := j.usable(); err != nil {
		return err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(agentID) {
		return errors.New("invalid room add")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.deleteRoomAdd(roomID, agentID)
}

// liveRoomAdds reads a room's adds and deletes the expired ones. The journal
// mutex is held.
func (j *Journal) liveRoomAdds(roomID string, now time.Time) ([]RoomAdd, error) {
	dir := filepath.Join(j.root, roomAddDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, errors.New("read pending room adds")
	}
	prefix := roomID[len("room_"):] + "-"
	var adds []RoomAdd
	for _, entry := range entries {
		name := entry.Name()
		if isTransitionTemp(name) || !strings.HasPrefix(name, prefix) {
			continue
		}
		stem, ok := strings.CutSuffix(strings.TrimPrefix(name, prefix), ".json")
		agentID := "agent_" + stem
		if !ok || entry.IsDir() || !ids.Agent.MatchString(agentID) {
			return nil, errors.New("unexpected entry in the pending room adds")
		}
		add, found, err := j.readRoomAdd(roomID, agentID)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		if uint64(now.Unix()) >= add.ExpiresAtUnix {
			// An add whose Agent is a member without a stored credential
			// is kept past its expiry, so its credential is still learned.
			orphan, err := j.memberWithoutCredential(roomID, agentID)
			if err != nil {
				return nil, err
			}
			if !orphan {
				if err := j.deleteRoomAdd(roomID, agentID); err != nil {
					return nil, err
				}
				continue
			}
		}
		adds = append(adds, add)
	}
	return adds, nil
}

// memberWithoutCredential reports whether an Agent is a member of a room
// held here whose leaf credential the room's list does not hold. The
// journal mutex is held.
func (j *Journal) memberWithoutCredential(roomID, agentID string) (bool, error) {
	record, found, err := j.readRoomMLS(roomID)
	if err != nil || !found || !containsString(record.Members, agentID) {
		return false, err
	}
	_, known, err := j.roomCredential(roomID, agentID)
	if err != nil {
		return false, err
	}
	return !known, nil
}

func (j *Journal) roomAddPath(roomID, agentID string) string {
	return filepath.Join(j.root, roomAddDir, roomID[len("room_"):]+"-"+agentID[len("agent_"):]+".json")
}

func (j *Journal) readRoomAdd(roomID, agentID string) (RoomAdd, bool, error) {
	raw, err := readRecordBytes(j.roomAddPath(roomID, agentID))
	if errors.Is(err, os.ErrNotExist) {
		return RoomAdd{}, false, nil
	}
	if err != nil {
		return RoomAdd{}, false, err
	}
	var add RoomAdd
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&add); err != nil || add.RoomID != roomID || add.AgentID != agentID {
		return RoomAdd{}, false, errRoomAddValue
	}
	if err := validateRoomAdd(add); err != nil {
		return RoomAdd{}, false, err
	}
	return add, true, nil
}

func validateRoomAdd(add RoomAdd) error {
	if add.Schema != roomAddSchema || !ids.Room.MatchString(add.RoomID) || !ids.Agent.MatchString(add.AgentID) ||
		add.DecidedAtUnix == 0 || add.ExpiresAtUnix <= add.DecidedAtUnix ||
		add.ExpiresAtUnix-add.DecidedAtUnix > payload.MaxRoomInviteLifetimeSeconds {
		return errRoomAddValue
	}
	if !add.Ready() {
		if add.DeviceCredentialBase64 != "" || add.LeafCredentialBase64 != "" || add.KeyPackageAtUnix != 0 {
			return errRoomAddValue
		}
		return nil
	}
	if !canon.ValidDigest(add.KeyPackageRef) || add.KeyPackageAtUnix < add.DecidedAtUnix {
		return errRoomAddValue
	}
	_, _, err := add.Credentials()
	return err
}

func (j *Journal) writeRoomAdd(add RoomAdd) error {
	if err := validateRoomAdd(add); err != nil {
		return err
	}
	encoded, err := json.Marshal(add)
	if err != nil {
		return err
	}
	return j.replace(j.roomAddPath(add.RoomID, add.AgentID), encoded)
}

func (j *Journal) deleteRoomAdd(roomID, agentID string) error {
	path := j.roomAddPath(roomID, agentID)
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("delete pending room add")
	}
	return syncDirectory(filepath.Dir(path))
}
