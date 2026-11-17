package eventlog

// Received application digests of private rooms (section 11.3).
//
// An application object arrives once per relay that held it and again if a
// relay replays it. Its relay object digest, seen within the last 24 h
// 5 min, is relay-acknowledged and dropped before Open, so it never spends a
// ratchet step. One marker per (room, sender, digest) records when it was
// first seen; markers older than the window are swept.
//
// The markers are bounded in total, per room and per sender in a room, so
// one sender or one room cannot exhaust the others' share. The counts are
// kept in memory, built by one directory scan on first use and kept current
// by every write, so a marker costs no directory scan. At a bound, expired
// markers are swept first; if the live ones still fill it, the marker is not
// written and the caller answers retry, so nothing is dropped unrecorded.
// The caller marks a digest only after the sender is authenticated as a
// member, so a stranger never takes a member's share.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/ids"
)

const (
	roomReceivedDir    = "room-received"
	roomReceivedSchema = "tos.messaging.room-received.v2"
	// RoomReceivedWindow is how long a received application digest is kept.
	RoomReceivedWindow = 24*time.Hour + 5*time.Minute
	// MaxRoomReceivedDigests bounds the live markers of every room.
	MaxRoomReceivedDigests = 1 << 16
	// MaxRoomReceivedPerRoom and MaxRoomReceivedPerSender are a room's share
	// and one sender's share in a room.
	MaxRoomReceivedPerRoom   = 1 << 14
	MaxRoomReceivedPerSender = 1 << 11
)

// ErrRoomReceivedFull reports that the live markers fill a bound.
var ErrRoomReceivedFull = errors.New("received room application digests reached their bound")

// The bounds the store enforces; tests lower them.
var (
	roomReceivedCap       = MaxRoomReceivedDigests
	roomReceivedRoomCap   = MaxRoomReceivedPerRoom
	roomReceivedSenderCap = MaxRoomReceivedPerSender
)

type roomReceivedRecord struct {
	Schema        string `json:"schema"`
	RoomID        string `json:"room_id"`
	SenderAgentID string `json:"sender_agent_id"`
	Digest        string `json:"object_digest"`
	SeenAtUnix    uint64 `json:"seen_at_unix"`
}

// roomReceivedIndex counts the markers on disk.
type roomReceivedIndex struct {
	total     int
	perRoom   map[string]int
	perSender map[[2]string]int
}

func (index *roomReceivedIndex) add(roomID, sender string, delta int) {
	index.total += delta
	index.perRoom[roomID] += delta
	index.perSender[[2]string{roomID, sender}] += delta
}

func (j *Journal) roomReceivedPath(roomID, sender, digest string) string {
	return filepath.Join(j.root, roomReceivedDir, roomID[len("room_"):]+"-"+sender[len("agent_"):]+"-"+digest+".json")
}

// RoomApplicationSeen reports whether a sender's application object digest
// was seen within the window. An expired marker is deleted and reported
// unseen.
func (j *Journal) RoomApplicationSeen(roomID, sender, digest string, now time.Time) (bool, error) {
	if err := j.usable(); err != nil {
		return false, err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(sender) || !validObjectDigest(digest) || now.IsZero() || now.Unix() <= 0 {
		return false, errors.New("invalid received room digest lookup")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	index, err := j.receivedIndex()
	if err != nil {
		return false, err
	}
	path := j.roomReceivedPath(roomID, sender, digest)
	record, found, err := readRoomReceived(path, roomID, sender, digest)
	if err != nil || !found {
		return false, err
	}
	if receivedExpired(record, now) {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, errors.New("delete expired received room digest")
		}
		index.add(roomID, sender, -1)
		return false, syncDirectory(filepath.Dir(path))
	}
	return true, nil
}

// MarkRoomApplicationSeen records a sender's application object digest. A
// digest already seen within the window keeps its first time; the call
// reports whether it was new.
func (j *Journal) MarkRoomApplicationSeen(roomID, sender, digest string, now time.Time) (bool, error) {
	if err := j.usable(); err != nil {
		return false, err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(sender) || !validObjectDigest(digest) || now.IsZero() || now.Unix() <= 0 {
		return false, errors.New("invalid received room digest")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	index, err := j.receivedIndex()
	if err != nil {
		return false, err
	}
	path := j.roomReceivedPath(roomID, sender, digest)
	record, found, err := readRoomReceived(path, roomID, sender, digest)
	if err != nil {
		return false, err
	}
	if found && !receivedExpired(record, now) {
		return false, nil
	}
	if !found {
		full := func(index *roomReceivedIndex) bool {
			return index.total >= roomReceivedCap || index.perRoom[roomID] >= roomReceivedRoomCap ||
				index.perSender[[2]string{roomID, sender}] >= roomReceivedSenderCap
		}
		if full(index) {
			if _, err := j.sweepRoomReceived(now); err != nil {
				return false, err
			}
			if index, err = j.receivedIndex(); err != nil {
				return false, err
			}
			if full(index) {
				return false, ErrRoomReceivedFull
			}
		}
	}
	encoded, err := json.Marshal(roomReceivedRecord{Schema: roomReceivedSchema, RoomID: roomID, SenderAgentID: sender,
		Digest: digest, SeenAtUnix: uint64(now.Unix())})
	if err != nil {
		return false, err
	}
	if err := j.replace(path, encoded); err != nil {
		return false, err
	}
	if !found {
		index.add(roomID, sender, 1)
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

// receivedIndex returns the in-memory counts, scanning the directory once.
// The journal mutex is held.
func (j *Journal) receivedIndex() (*roomReceivedIndex, error) {
	if j.received != nil {
		return j.received, nil
	}
	names, err := j.roomReceivedNames()
	if err != nil {
		return nil, err
	}
	index := &roomReceivedIndex{perRoom: map[string]int{}, perSender: map[[2]string]int{}}
	for _, name := range names {
		index.add(name.room, name.sender, 1)
	}
	j.received = index
	return index, nil
}

type roomReceivedName struct{ file, room, sender, digest string }

// roomReceivedNames lists the markers by name. An unexpected name fails the
// listing: the bounds count names, so an unknown one is never uncounted.
// The journal mutex is held.
func (j *Journal) roomReceivedNames() ([]roomReceivedName, error) {
	entries, err := os.ReadDir(filepath.Join(j.root, roomReceivedDir))
	if err != nil {
		return nil, errors.New("read received room digests")
	}
	names := make([]roomReceivedName, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if isTransitionTemp(name) {
			continue
		}
		stem, ok := strings.CutSuffix(name, ".json")
		fields := strings.Split(stem, "-")
		if !ok || entry.IsDir() || len(fields) != 3 || !ids.Room.MatchString("room_"+fields[0]) ||
			!ids.Agent.MatchString("agent_"+fields[1]) || !validObjectDigest(fields[2]) {
			return nil, errors.New("unexpected entry in the received room digests")
		}
		names = append(names, roomReceivedName{file: name, room: "room_" + fields[0], sender: "agent_" + fields[1], digest: fields[2]})
	}
	return names, nil
}

// sweepRoomReceived deletes expired markers and damaged ones (a damaged
// marker only forgets a duplicate filter entry); the counts are rebuilt on
// next use. The journal mutex is held.
func (j *Journal) sweepRoomReceived(now time.Time) (int, error) {
	names, err := j.roomReceivedNames()
	if err != nil {
		return 0, err
	}
	dir := filepath.Join(j.root, roomReceivedDir)
	removed := 0
	for _, name := range names {
		record, found, err := readRoomReceived(filepath.Join(dir, name.file), name.room, name.sender, name.digest)
		if err == nil && (!found || !receivedExpired(record, now)) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name.file)); err != nil && !errors.Is(err, os.ErrNotExist) {
			j.received = nil
			return removed, errors.New("delete received room digest")
		}
		removed++
	}
	j.received = nil
	if removed > 0 {
		return removed, syncDirectory(dir)
	}
	return 0, nil
}

func receivedExpired(record roomReceivedRecord, now time.Time) bool {
	return now.Unix() >= 0 && uint64(now.Unix()) >= record.SeenAtUnix+uint64(RoomReceivedWindow/time.Second)
}

func readRoomReceived(path, roomID, sender, digest string) (roomReceivedRecord, bool, error) {
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
		record.SenderAgentID != sender || record.Digest != digest || record.SeenAtUnix == 0 {
		return roomReceivedRecord{}, false, errors.New("invalid received room digest record")
	}
	return record, true, nil
}
