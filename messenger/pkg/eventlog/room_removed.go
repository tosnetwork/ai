package eventlog

// The removal notice of a private room (sections 11.3, 11.4).
//
// The authority sends a removed member its removing Commit once, outside the
// member's queue. The member does not apply it to MLS: it verifies the
// Commit's header (the authority's authorization, in the relay window, of a
// membership above the member's own epoch that no longer names it) and marks
// the room removed. From then on it accepts no handshake object of the room
// and seals nothing in it; objects sealed in the epochs it was a member of
// may still be opened. The marker is per-room receive state: it is deleted
// with the room's other receive state when the room is retired or no longer
// held, and it names no other record, so it is no garbage-collection root.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/ids"
)

const (
	roomRemovedDir    = "room-removed"
	roomRemovedSchema = "tos.messaging.room-removed.v1"
)

// ErrRoomRemovalEpoch reports a removal notice that names no epoch above the
// member's own.
var ErrRoomRemovalEpoch = errors.New("a removal notice names no epoch above the member's own")

// RoomRemoval is the marker of a room this installation was removed from.
type RoomRemoval struct {
	Schema string `json:"schema"`
	RoomID string `json:"room_id"`
	// RoomEpoch and MLSEpoch are the removing Commit's.
	RoomEpoch uint64 `json:"room_epoch"`
	MLSEpoch  uint64 `json:"mls_epoch"`
	// ObjectDigest is the relay object digest of the removing Commit.
	ObjectDigest string `json:"object_digest"`
	// MemberMLSEpoch is the member's own MLS epoch when it was removed: the
	// last epoch it can open objects of.
	MemberMLSEpoch uint64 `json:"member_mls_epoch"`
	RemovedAtUnix  uint64 `json:"removed_at_unix"`
}

func (j *Journal) roomRemovedPath(roomID string) string {
	return filepath.Join(j.root, roomRemovedDir, roomID[len("room_"):]+".json")
}

// MarkRoomRemoved records that a verified Commit removed this installation
// from a room it holds. The Commit's room and MLS epochs must lie above the
// member's own. The first notice is kept: a later one reports false and
// writes nothing.
func (j *Journal) MarkRoomRemoved(roomID string, roomEpoch, mlsEpoch uint64, objectDigest string, now time.Time) (bool, RoomRemoval, error) {
	if err := j.usable(); err != nil {
		return false, RoomRemoval{}, err
	}
	if !ids.Room.MatchString(roomID) || !validObjectDigest(objectDigest) || now.IsZero() || now.Unix() <= 0 {
		return false, RoomRemoval{}, errors.New("invalid room removal")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	record, found, err := j.readRoomMLS(roomID)
	if err != nil {
		return false, RoomRemoval{}, err
	}
	if !found {
		return false, RoomRemoval{}, ErrRoomNotJoined
	}
	if existing, marked, err := j.readRoomRemoval(roomID); err != nil {
		return false, RoomRemoval{}, err
	} else if marked {
		return false, existing, nil
	}
	if roomEpoch <= record.RoomEpoch || mlsEpoch <= record.MLSEpoch {
		return false, RoomRemoval{}, ErrRoomRemovalEpoch
	}
	removal := RoomRemoval{Schema: roomRemovedSchema, RoomID: roomID, RoomEpoch: roomEpoch, MLSEpoch: mlsEpoch,
		ObjectDigest: objectDigest, MemberMLSEpoch: record.MLSEpoch, RemovedAtUnix: uint64(now.Unix())}
	encoded, err := json.Marshal(removal)
	if err != nil {
		return false, RoomRemoval{}, err
	}
	if err := j.replace(j.roomRemovedPath(roomID), encoded); err != nil {
		return false, RoomRemoval{}, err
	}
	return true, removal, nil
}

// RoomRemovalOf returns the removal marker of a room, if this installation
// was removed from it.
func (j *Journal) RoomRemovalOf(roomID string) (RoomRemoval, bool, error) {
	if err := j.usable(); err != nil {
		return RoomRemoval{}, false, err
	}
	if !ids.Room.MatchString(roomID) {
		return RoomRemoval{}, false, errors.New("invalid room")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.readRoomRemoval(roomID)
}

// readRoomRemoval reads and checks a removal marker. The journal mutex is
// held.
func (j *Journal) readRoomRemoval(roomID string) (RoomRemoval, bool, error) {
	raw, err := readRecordBytes(j.roomRemovedPath(roomID))
	if errors.Is(err, os.ErrNotExist) {
		return RoomRemoval{}, false, nil
	}
	if err != nil {
		return RoomRemoval{}, false, err
	}
	var removal RoomRemoval
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&removal); err != nil || removal.Schema != roomRemovedSchema || removal.RoomID != roomID ||
		removal.RoomEpoch == 0 || removal.MLSEpoch == 0 || !validObjectDigest(removal.ObjectDigest) || removal.RemovedAtUnix == 0 ||
		removal.MLSEpoch <= removal.MemberMLSEpoch {
		return RoomRemoval{}, false, errors.New("invalid room removal record")
	}
	return removal, true, nil
}
