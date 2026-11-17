package eventlog

// A stopped handshake queue (sections 11.3, 11.7).
//
// The authority stops a member's queue on a rejected room ack, a lost-state
// rejection or the end of the handshake retention. The settled outbox head
// that caused it is retired once every member settled it, so the stop is
// kept as its own marker: one per (room, member), naming the code. It is
// per-room state, deleted with the room's other state; it names no other
// record, so it is no garbage-collection root.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
)

const (
	roomStopDir    = "room-queue-stops"
	roomStopSchema = "tos.messaging.room-queue-stop.v1"
)

// RoomQueueStop is the marker of a member's stopped queue.
type RoomQueueStop struct {
	Schema        string     `json:"schema"`
	RoomID        string     `json:"room_id"`
	AgentID       string     `json:"agent_id"`
	Code          fault.Code `json:"code"`
	StoppedAtUnix uint64     `json:"stopped_at_unix"`
}

// StopRoomMemberQueue records that a member's queue stopped. The first stop
// is kept.
func (j *Journal) StopRoomMemberQueue(roomID, agentID string, code fault.Code, now time.Time) error {
	if err := j.usable(); err != nil {
		return err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(agentID) || !fault.Known(code) || now.Unix() <= 0 {
		return errors.New("invalid room queue stop")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	if _, found, err := j.readRoomStop(roomID, agentID); err != nil || found {
		return err
	}
	encoded, err := json.Marshal(RoomQueueStop{Schema: roomStopSchema, RoomID: roomID, AgentID: agentID, Code: code,
		StoppedAtUnix: uint64(now.Unix())})
	if err != nil {
		return err
	}
	return j.replace(j.roomStopPath(roomID, agentID), encoded)
}

// RoomMemberQueueStop returns the stop of a member's queue, if it stopped.
func (j *Journal) RoomMemberQueueStop(roomID, agentID string) (RoomQueueStop, bool, error) {
	if err := j.usable(); err != nil {
		return RoomQueueStop{}, false, err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(agentID) {
		return RoomQueueStop{}, false, errors.New("invalid room queue stop lookup")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.readRoomStop(roomID, agentID)
}

func (j *Journal) roomStopPath(roomID, agentID string) string {
	return filepath.Join(j.root, roomStopDir, roomID[len("room_"):]+"-"+agentID[len("agent_"):]+".json")
}

func (j *Journal) readRoomStop(roomID, agentID string) (RoomQueueStop, bool, error) {
	raw, err := readRecordBytes(j.roomStopPath(roomID, agentID))
	if errors.Is(err, os.ErrNotExist) {
		return RoomQueueStop{}, false, nil
	}
	if err != nil {
		return RoomQueueStop{}, false, err
	}
	var stop RoomQueueStop
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stop); err != nil || stop.Schema != roomStopSchema || stop.RoomID != roomID ||
		stop.AgentID != agentID || !fault.Known(stop.Code) || stop.StoppedAtUnix == 0 {
		return RoomQueueStop{}, false, errors.New("invalid room queue stop record")
	}
	return stop, true, nil
}
