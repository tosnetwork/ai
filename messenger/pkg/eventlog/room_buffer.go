package eventlog

// The future-epoch buffer of a private room (section 11.3).
//
// An application object sealed in MLS epoch e reaches a member at epoch r in
// any order relative to the Commits between them. For r < e <= r + 4 the
// member keeps it here, durably, and opens it in arrival order once the
// Commits up to e are applied. The buffer is bounded per room (256 objects,
// 8 MiB), per sender within a room (16 objects, 1 MiB) and in total
// (32 MiB); an object outside the window, beyond a bound, or held longer than
// 24 h 5 min is dropped and counted as a gap by the caller.
//
// Every bound is judged from the directory listing alone: a record's name
// carries its room, arrival time, sender, MLS epoch, object length and
// digest, and reading a record checks that its contents match its name. The
// buffer names no other record, so it is no garbage-collection root.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

const (
	roomBufferDir    = "room-epoch-buffer"
	roomBufferSchema = "tos.messaging.room-epoch-buffer.v1"

	// RoomBufferLookahead is k: an object up to k MLS epochs ahead is kept.
	RoomBufferLookahead = 4
	// MaxRoomBufferObjects and MaxRoomBufferBytes bound one room's buffer.
	MaxRoomBufferObjects = 256
	MaxRoomBufferBytes   = 8 << 20
	// MaxRoomBufferSenderObjects and MaxRoomBufferSenderBytes bound one
	// sender's share of a room's buffer.
	MaxRoomBufferSenderObjects = 16
	MaxRoomBufferSenderBytes   = 1 << 20
	// MaxRoomBufferTotalBytes bounds every room's buffer together.
	MaxRoomBufferTotalBytes = 32 << 20
	// RoomBufferLifetime is how long a buffered object waits for its Commit.
	RoomBufferLifetime = 24*time.Hour + 5*time.Minute
	// MaxRoomBufferedObjectBytes is the largest application object: it is
	// never split, so it fits part 0.
	MaxRoomBufferedObjectBytes = relayframe.RoomObjectFixedBytes + relayframe.MaxRoomApplicationBodyBytes
)

// roomBufferTotalCap is MaxRoomBufferTotalBytes; a test lowers it to reach
// the total bound without writing 32 MiB.
var roomBufferTotalCap = MaxRoomBufferTotalBytes

// Buffer refusals. Each is a drop the caller counts as a gap.
var (
	ErrRoomBufferEpoch      = errors.New("room object is outside the future-epoch window")
	ErrRoomBufferRoomFull   = errors.New("room future-epoch buffer is full")
	ErrRoomBufferSenderFull = errors.New("sender's share of the room future-epoch buffer is full")
	ErrRoomBufferTotalFull  = errors.New("future-epoch buffers reached the total bound")
	// ErrRoomNotJoined reports a room this installation holds no fused
	// record of.
	ErrRoomNotJoined = errors.New("this installation has not joined the room")
)

// BufferedRoomObject is one object waiting for its epoch.
type BufferedRoomObject struct {
	RoomID        string
	SenderAgentID string
	MLSEpoch      uint64
	// Digest is the relay object digest, lowercase hex.
	Digest    string
	ArrivedAt time.Time
	Object    []byte
}

// RoomBufferDropReason says why a buffered object was dropped.
type RoomBufferDropReason string

const (
	// RoomBufferDropExpired: it waited longer than RoomBufferLifetime.
	RoomBufferDropExpired RoomBufferDropReason = "buffer-expired"
	// RoomBufferDropTooOld: the member moved past the epochs it can open.
	RoomBufferDropTooOld RoomBufferDropReason = "epoch-too-old"
	// RoomBufferDropLeft: the room is no longer held here.
	RoomBufferDropLeft RoomBufferDropReason = "room-left"
	// RoomBufferDropDamaged: its record did not verify.
	RoomBufferDropDamaged RoomBufferDropReason = "record-damaged"
)

// BufferedRoomDrop is one object a sweep dropped unopened.
type BufferedRoomDrop struct {
	RoomID        string
	SenderAgentID string
	MLSEpoch      uint64
	Reason        RoomBufferDropReason
}

type roomBufferRecord struct {
	Schema        string `json:"schema"`
	RoomID        string `json:"room_id"`
	SenderAgentID string `json:"sender_agent_id"`
	MLSEpoch      uint64 `json:"mls_epoch"`
	Digest        string `json:"object_digest"`
	ArrivedAtNano int64  `json:"arrived_at_unix_nano"`
	ObjectBase64  string `json:"object_base64"`
}

type roomBufferEntry struct {
	name      string
	roomID    string
	sender    string
	mlsEpoch  uint64
	length    int
	digest    string
	arrivedAt time.Time
}

func roomBufferName(entry roomBufferEntry) string {
	return fmt.Sprintf("%s-%019d-%s-%d-%d-%s.json", entry.roomID[len("room_"):], entry.arrivedAt.UnixNano(),
		entry.sender[len("agent_"):], entry.mlsEpoch, entry.length, entry.digest)
}

func parseRoomBufferName(name string) (roomBufferEntry, bool) {
	stem, ok := strings.CutSuffix(name, ".json")
	if !ok {
		return roomBufferEntry{}, false
	}
	fields := strings.Split(stem, "-")
	if len(fields) != 6 || !ids.Room.MatchString("room_"+fields[0]) || !ids.Agent.MatchString("agent_"+fields[2]) ||
		!canon.HashPattern.MatchString(fields[5]) || len(fields[1]) != 19 {
		return roomBufferEntry{}, false
	}
	nanos, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || nanos <= 0 {
		return roomBufferEntry{}, false
	}
	epoch, err := strconv.ParseUint(fields[3], 10, 64)
	if err != nil || strconv.FormatUint(epoch, 10) != fields[3] {
		return roomBufferEntry{}, false
	}
	length, err := strconv.Atoi(fields[4])
	if err != nil || length <= 0 || length > MaxRoomBufferedObjectBytes || strconv.Itoa(length) != fields[4] {
		return roomBufferEntry{}, false
	}
	return roomBufferEntry{name: name, roomID: "room_" + fields[0], sender: "agent_" + fields[2], mlsEpoch: epoch,
		length: length, digest: fields[5], arrivedAt: time.Unix(0, nanos)}, true
}

// BufferRoomObject keeps an application object sealed in a future MLS epoch.
// It reports false for an object already buffered. The window is judged
// against this installation's current MLS epoch r: r < e <= r + 4.
func (j *Journal) BufferRoomObject(sender string, object []byte, now time.Time) (bool, error) {
	if err := j.usable(); err != nil {
		return false, err
	}
	if !ids.Agent.MatchString(sender) || now.IsZero() || now.UnixNano() <= 0 {
		return false, errors.New("invalid buffered room object")
	}
	if len(object) == 0 || len(object) > MaxRoomBufferedObjectBytes {
		return false, errors.New("invalid buffered room object length")
	}
	decoded, err := relayframe.DecodeRoomObject(object)
	if err != nil || decoded.Type != relayframe.RoomApplication {
		return false, errors.New("only an application room object is buffered")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	record, found, err := j.readRoomMLS(decoded.RoomID)
	if err != nil {
		return false, err
	}
	if !found {
		return false, ErrRoomNotJoined
	}
	r := record.MLSEpoch
	if decoded.MLSEpoch <= r || decoded.MLSEpoch-r > RoomBufferLookahead {
		return false, ErrRoomBufferEpoch
	}
	entries, err := j.roomBufferEntries()
	if err != nil {
		return false, err
	}
	digest := RoomObjectDigest(object)
	roomObjects, roomBytes, senderObjects, senderBytes, total := 0, 0, 0, 0, 0
	for _, entry := range entries {
		total += entry.length
		if entry.roomID != decoded.RoomID {
			continue
		}
		if entry.digest == digest {
			return false, nil
		}
		roomObjects++
		roomBytes += entry.length
		if entry.sender == sender {
			senderObjects++
			senderBytes += entry.length
		}
	}
	switch {
	case senderObjects+1 > MaxRoomBufferSenderObjects || senderBytes+len(object) > MaxRoomBufferSenderBytes:
		return false, ErrRoomBufferSenderFull
	case roomObjects+1 > MaxRoomBufferObjects || roomBytes+len(object) > MaxRoomBufferBytes:
		return false, ErrRoomBufferRoomFull
	case total+len(object) > roomBufferTotalCap:
		return false, ErrRoomBufferTotalFull
	}
	entry := roomBufferEntry{roomID: decoded.RoomID, sender: sender, mlsEpoch: decoded.MLSEpoch, length: len(object), digest: digest, arrivedAt: now}
	encoded, err := json.Marshal(roomBufferRecord{Schema: roomBufferSchema, RoomID: decoded.RoomID, SenderAgentID: sender,
		MLSEpoch: decoded.MLSEpoch, Digest: digest, ArrivedAtNano: now.UnixNano(), ObjectBase64: base64.StdEncoding.EncodeToString(object)})
	if err != nil {
		return false, err
	}
	if err := j.replace(filepath.Join(j.root, roomBufferDir, roomBufferName(entry)), encoded); err != nil {
		return false, err
	}
	return true, nil
}

// OpenableRoomObjects returns, in arrival order, the buffered objects of a
// room whose epoch the member has reached (e <= r) and can still open
// (e >= r - 2). Each is verified against its name; the caller opens it and
// then releases it. A record that does not verify is deleted and returned
// as a drop, so one damaged record cannot block the room.
func (j *Journal) OpenableRoomObjects(roomID string) ([]BufferedRoomObject, []BufferedRoomDrop, error) {
	if err := j.usable(); err != nil {
		return nil, nil, err
	}
	if !ids.Room.MatchString(roomID) {
		return nil, nil, errors.New("invalid room")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	record, found, err := j.readRoomMLS(roomID)
	if err != nil {
		return nil, nil, err
	}
	if !found {
		return nil, nil, ErrRoomNotJoined
	}
	entries, err := j.roomBufferEntries()
	if err != nil {
		return nil, nil, err
	}
	var openable []BufferedRoomObject
	var drops []BufferedRoomDrop
	var damaged []string
	for _, entry := range entries {
		if entry.roomID != roomID || entry.mlsEpoch > record.MLSEpoch || !withinPastEpochs(entry.mlsEpoch, record.MLSEpoch) {
			continue
		}
		object, err := j.readRoomBufferRecord(entry)
		if err != nil {
			damaged = append(damaged, entry.name)
			drops = append(drops, BufferedRoomDrop{RoomID: entry.roomID, SenderAgentID: entry.sender, MLSEpoch: entry.mlsEpoch, Reason: RoomBufferDropDamaged})
			continue
		}
		openable = append(openable, object)
	}
	if err := j.removeRoomBufferNames(damaged); err != nil {
		return nil, nil, err
	}
	return openable, drops, nil
}

// withinPastEpochs reports e >= r - 2: an epoch the member still holds
// secrets of (max_past_epochs 2).
func withinPastEpochs(e, r uint64) bool {
	return e >= r || r-e <= RetainedRoomEpochs-1
}

// ReleaseRoomObject deletes a buffered object the caller opened or refused.
// A digest no longer buffered is no error.
func (j *Journal) ReleaseRoomObject(roomID, digest string) error {
	if err := j.usable(); err != nil {
		return err
	}
	if !ids.Room.MatchString(roomID) || !canon.HashPattern.MatchString(digest) {
		return errors.New("invalid buffered room object")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	entries, err := j.roomBufferEntries()
	if err != nil {
		return err
	}
	var names []string
	for _, entry := range entries {
		if entry.roomID == roomID && entry.digest == digest {
			names = append(names, entry.name)
		}
	}
	return j.removeRoomBufferNames(names)
}

// SweepRoomBuffer drops every buffered object that waited RoomBufferLifetime
// or longer, whose epoch the member has moved past the epochs it can open,
// or whose room is no longer held here. Every drop is returned for the
// caller's gap records.
func (j *Journal) SweepRoomBuffer(now time.Time) ([]BufferedRoomDrop, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, errors.New("invalid room buffer sweep time")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	entries, err := j.roomBufferEntries()
	if err != nil {
		return nil, err
	}
	epochs := map[string]uint64{}
	held := map[string]bool{}
	var drops []BufferedRoomDrop
	var names []string
	for _, entry := range entries {
		if _, read := held[entry.roomID]; !read {
			record, found, err := j.readRoomMLS(entry.roomID)
			if err != nil {
				return nil, err
			}
			held[entry.roomID] = found
			epochs[entry.roomID] = record.MLSEpoch
		}
		reason := RoomBufferDropReason("")
		switch {
		case !held[entry.roomID]:
			reason = RoomBufferDropLeft
		case now.Sub(entry.arrivedAt) >= RoomBufferLifetime:
			reason = RoomBufferDropExpired
		case entry.mlsEpoch < epochs[entry.roomID] && !withinPastEpochs(entry.mlsEpoch, epochs[entry.roomID]):
			reason = RoomBufferDropTooOld
		default:
			continue
		}
		names = append(names, entry.name)
		drops = append(drops, BufferedRoomDrop{RoomID: entry.roomID, SenderAgentID: entry.sender, MLSEpoch: entry.mlsEpoch, Reason: reason})
	}
	if err := j.removeRoomBufferNames(names); err != nil {
		return nil, err
	}
	return drops, nil
}

// roomBufferEntries lists the buffer in arrival order. A name that is not a
// buffer record fails the listing: the bounds are judged from names, so an
// unknown name is never silently uncounted. The journal mutex is held.
func (j *Journal) roomBufferEntries() ([]roomBufferEntry, error) {
	entries, err := os.ReadDir(filepath.Join(j.root, roomBufferDir))
	if err != nil {
		return nil, errors.New("read room future-epoch buffer")
	}
	listed := make([]roomBufferEntry, 0, len(entries))
	for _, entry := range entries {
		if isTransitionTemp(entry.Name()) {
			continue
		}
		parsed, ok := parseRoomBufferName(entry.Name())
		if !ok || entry.IsDir() {
			return nil, errors.New("unexpected entry in the room future-epoch buffer")
		}
		listed = append(listed, parsed)
	}
	sort.Slice(listed, func(a, b int) bool {
		if !listed[a].arrivedAt.Equal(listed[b].arrivedAt) {
			return listed[a].arrivedAt.Before(listed[b].arrivedAt)
		}
		return listed[a].name < listed[b].name
	})
	return listed, nil
}

func (j *Journal) readRoomBufferRecord(entry roomBufferEntry) (BufferedRoomObject, error) {
	invalid := errors.New("invalid room future-epoch buffer record")
	raw, err := readRecordBytes(filepath.Join(j.root, roomBufferDir, entry.name))
	if err != nil {
		return BufferedRoomObject{}, err
	}
	var record roomBufferRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.Schema != roomBufferSchema {
		return BufferedRoomObject{}, invalid
	}
	object, err := base64.StdEncoding.Strict().DecodeString(record.ObjectBase64)
	if err != nil || len(object) != entry.length || RoomObjectDigest(object) != entry.digest ||
		record.RoomID != entry.roomID || record.SenderAgentID != entry.sender || record.MLSEpoch != entry.mlsEpoch ||
		record.Digest != entry.digest || record.ArrivedAtNano != entry.arrivedAt.UnixNano() {
		return BufferedRoomObject{}, invalid
	}
	decoded, err := relayframe.DecodeRoomObject(object)
	if err != nil || decoded.Type != relayframe.RoomApplication || decoded.RoomID != entry.roomID || decoded.MLSEpoch != entry.mlsEpoch {
		return BufferedRoomObject{}, invalid
	}
	return BufferedRoomObject{RoomID: entry.roomID, SenderAgentID: entry.sender, MLSEpoch: entry.mlsEpoch,
		Digest: entry.digest, ArrivedAt: entry.arrivedAt, Object: object}, nil
}

func (j *Journal) removeRoomBufferNames(names []string) error {
	if len(names) == 0 {
		return nil
	}
	dir := filepath.Join(j.root, roomBufferDir)
	for _, name := range names {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("delete buffered room object")
		}
	}
	return syncDirectory(dir)
}
