package eventlog

// Forgetting a room's receive state.
//
// The sequence, gap, applied-digest, received-digest, future-epoch and
// removal records of a room exist only while this installation holds the room or
// has a pending join for it. When the fused record goes (the member left or
// was removed), ForgetRoomState deletes them; restart deletes what a crash
// left behind for a room that is neither held nor pending. When a member is
// removed, ForgetRoomSender deletes that member's sequence record, so a
// removed member's state does not count against the bounds.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/tosnetwork/ai/messenger/internal/ids"
)

// ErrRoomStillHeld reports a room whose state cannot be forgotten because
// this installation still holds it or has a pending join for it.
var ErrRoomStillHeld = errors.New("the room is still held or pending")

// roomStateDirs are the per-room receive stores, each with file names that
// begin with the room's hex.
var roomStateDirs = []string{roomSequenceDir, roomGapDir, roomAppliedDir, roomReceivedDir, roomBufferDir, roomRemovedDir,
	roomAddDir, roomSendDir, roomApplicationDir, roomCardDir}

// ForgetRoomState deletes a room's receive state once the room is neither
// held nor pending here. It reports how many records it deleted.
func (j *Journal) ForgetRoomState(roomID string) (int, error) {
	if err := j.usable(); err != nil {
		return 0, err
	}
	if !ids.Room.MatchString(roomID) {
		return 0, errors.New("invalid room")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	held, err := j.roomHeldOrPending(roomID)
	if err != nil {
		return 0, err
	}
	if held {
		return 0, ErrRoomStillHeld
	}
	return j.deleteRoomState(roomID)
}

// ForgetRoomSender deletes the sequence record of a member removed from a
// room. Its gap records stay, as history the runtime may still read.
func (j *Journal) ForgetRoomSender(roomID, sender string) (bool, error) {
	if err := j.usable(); err != nil {
		return false, err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(sender) {
		return false, errors.New("invalid room sender")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	path := filepath.Join(j.root, roomSequenceDir, roomSequenceName(roomID, sender))
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, errors.New("delete room sequence")
	}
	return true, syncDirectory(filepath.Dir(path))
}

// sweepOrphanedRoomState deletes the receive state of every room that is
// neither held nor pending, for example after a crash between a room's end
// and ForgetRoomState. A name that belongs to no room is left alone. The
// journal mutex is held.
func (j *Journal) sweepOrphanedRoomState() error {
	rooms := map[string]struct{}{}
	for _, dir := range roomStateDirs {
		entries, err := os.ReadDir(filepath.Join(j.root, dir))
		if err != nil {
			return errors.New("read room receive state")
		}
		for _, entry := range entries {
			roomHex, _, _ := strings.Cut(strings.TrimSuffix(entry.Name(), ".json"), "-")
			if roomID := "room_" + roomHex; ids.Room.MatchString(roomID) {
				rooms[roomID] = struct{}{}
			}
		}
	}
	for roomID := range rooms {
		held, err := j.roomHeldOrPending(roomID)
		if err != nil {
			return err
		}
		if !held {
			if _, err := j.deleteRoomState(roomID); err != nil {
				return err
			}
		}
	}
	return nil
}

// roomHeldOrPending reports whether a fused record or a pending join names
// the room. The journal mutex is held.
func (j *Journal) roomHeldOrPending(roomID string) (bool, error) {
	if _, found, err := j.readRoomMLS(roomID); err != nil || found {
		return found, err
	}
	keys, err := j.roomJoinKeys()
	if err != nil {
		return false, err
	}
	for _, key := range keys {
		if key.room == roomID {
			return true, nil
		}
	}
	return false, nil
}

// deleteRoomState removes every receive-state record of a room. The
// journal mutex is held.
func (j *Journal) deleteRoomState(roomID string) (int, error) {
	prefix := roomID[len("room_"):]
	deleted := 0
	for _, dir := range roomStateDirs {
		path := filepath.Join(j.root, dir)
		entries, err := os.ReadDir(path)
		if err != nil {
			return deleted, errors.New("read room receive state")
		}
		removed := false
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !(name == prefix+".json" || strings.HasPrefix(name, prefix+"-")) {
				continue
			}
			if err := os.Remove(filepath.Join(path, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return deleted, errors.New("delete room receive state")
			}
			deleted++
			removed = true
		}
		if removed {
			if err := syncDirectory(path); err != nil {
				return deleted, err
			}
		}
	}
	j.received = nil
	return deleted, nil
}
