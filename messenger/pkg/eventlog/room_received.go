package eventlog

// Received application digests of private rooms (section 11.3).
//
// An application object arrives once per relay that held it and again if a
// relay replays it. Its relay object digest, seen within the last 24 h
// 5 min, is relay-acknowledged and dropped before Open, so it never spends a
// ratchet step. One marker per (room, digest) records when it was first
// seen; markers older than the window are swept.
//
// The spec states the window, not a count; the count is bounded here so the
// markers cannot grow without limit. At the bound, expired markers are swept
// first; if the live ones still fill it, MarkRoomApplicationSeen fails and
// the caller answers retry, so nothing is dropped unrecorded.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
)

const (
	roomReceivedDir    = "room-received"
	roomReceivedSchema = "tos.messaging.room-received.v1"
	// RoomReceivedWindow is how long a received application digest is kept.
	RoomReceivedWindow = 24*time.Hour + 5*time.Minute
	// MaxRoomReceivedDigests bounds the live markers of every room.
	MaxRoomReceivedDigests = 1 << 16
)

// ErrRoomReceivedFull reports that the live markers fill their bound.
var ErrRoomReceivedFull = errors.New("received room application digests reached their bound")

// roomReceivedCap is MaxRoomReceivedDigests; tests lower it.
var roomReceivedCap = MaxRoomReceivedDigests

type roomReceivedRecord struct {
	Schema     string `json:"schema"`
	RoomID     string `json:"room_id"`
	Digest     string `json:"object_digest"`
	SeenAtUnix uint64 `json:"seen_at_unix"`
}

func (j *Journal) roomReceivedPath(roomID, digest string) string {
	return filepath.Join(j.root, roomReceivedDir, roomID[len("room_"):]+"-"+digest+".json")
}

// RoomApplicationSeen reports whether an application object's digest was
// seen within the window. An expired marker is deleted and reported unseen.
func (j *Journal) RoomApplicationSeen(roomID, digest string, now time.Time) (bool, error) {
	if err := j.usable(); err != nil {
		return false, err
	}
	if !ids.Room.MatchString(roomID) || !validObjectDigest(digest) || now.IsZero() || now.Unix() <= 0 {
		return false, errors.New("invalid received room digest lookup")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	path := j.roomReceivedPath(roomID, digest)
	record, found, err := readRoomReceived(path, roomID, digest)
	if err != nil || !found {
		return false, err
	}
	if receivedExpired(record, now) {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, errors.New("delete expired received room digest")
		}
		return false, syncDirectory(filepath.Dir(path))
	}
	return true, nil
}

// MarkRoomApplicationSeen records an application object's digest. A digest
// already seen within the window keeps its first time; the call reports
// whether it was new.
func (j *Journal) MarkRoomApplicationSeen(roomID, digest string, now time.Time) (bool, error) {
	if err := j.usable(); err != nil {
		return false, err
	}
	if !ids.Room.MatchString(roomID) || !validObjectDigest(digest) || now.IsZero() || now.Unix() <= 0 {
		return false, errors.New("invalid received room digest")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	path := j.roomReceivedPath(roomID, digest)
	record, found, err := readRoomReceived(path, roomID, digest)
	if err != nil {
		return false, err
	}
	if found && !receivedExpired(record, now) {
		return false, nil
	}
	if !found {
		count, err := countEntries(filepath.Join(j.root, roomReceivedDir))
		if err != nil {
			return false, err
		}
		if count >= roomReceivedCap {
			if _, err := j.sweepRoomReceived(now); err != nil {
				return false, err
			}
			if count, err = countEntries(filepath.Join(j.root, roomReceivedDir)); err != nil {
				return false, err
			}
			if count >= roomReceivedCap {
				return false, ErrRoomReceivedFull
			}
		}
	}
	encoded, err := json.Marshal(roomReceivedRecord{Schema: roomReceivedSchema, RoomID: roomID, Digest: digest, SeenAtUnix: uint64(now.Unix())})
	if err != nil {
		return false, err
	}
	if err := j.replace(path, encoded); err != nil {
		return false, err
	}
	return true, nil
}

// SweepRoomReceived deletes every marker older than the window.
func (j *Journal) SweepRoomReceived(now time.Time) (int, error) {
	if err := j.usable(); err != nil {
		return 0, err
	}
	if now.IsZero() {
		return 0, errors.New("invalid received room digest sweep")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.sweepRoomReceived(now)
}

// sweepRoomReceived deletes expired markers and damaged ones (a damaged
// marker only forgets a duplicate filter entry). An unexpected name fails
// the sweep. The journal mutex is held.
func (j *Journal) sweepRoomReceived(now time.Time) (int, error) {
	dir := filepath.Join(j.root, roomReceivedDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, errors.New("read received room digests")
	}
	removed := 0
	for _, entry := range entries {
		name := entry.Name()
		if isTransitionTemp(name) {
			continue
		}
		stem, ok := strings.CutSuffix(name, ".json")
		roomHex, digest, cut := strings.Cut(stem, "-")
		if !ok || !cut || entry.IsDir() || !ids.Room.MatchString("room_"+roomHex) || !validObjectDigest(digest) {
			return removed, errors.New("unexpected entry in the received room digests")
		}
		record, found, err := readRoomReceived(filepath.Join(dir, name), "room_"+roomHex, digest)
		if err == nil && (!found || !receivedExpired(record, now)) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, errors.New("delete received room digest")
		}
		removed++
	}
	if removed > 0 {
		return removed, syncDirectory(dir)
	}
	return 0, nil
}

func receivedExpired(record roomReceivedRecord, now time.Time) bool {
	return now.Unix() >= 0 && uint64(now.Unix()) >= record.SeenAtUnix+uint64(RoomReceivedWindow/time.Second)
}

func readRoomReceived(path, roomID, digest string) (roomReceivedRecord, bool, error) {
	raw, err := readRecordBytes(path)
	if errors.Is(err, os.ErrNotExist) {
		return roomReceivedRecord{}, false, nil
	}
	if err != nil {
		return roomReceivedRecord{}, false, err
	}
	var record roomReceivedRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.Schema != roomReceivedSchema || record.RoomID != roomID ||
		record.Digest != digest || record.SeenAtUnix == 0 || !canon.HashPattern.MatchString(record.Digest) {
		return roomReceivedRecord{}, false, errors.New("invalid received room digest record")
	}
	return record, true, nil
}
