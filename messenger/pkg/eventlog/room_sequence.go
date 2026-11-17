package eventlog

// Per-sender room sequences and room.gap records (section 11.3).
//
// Application objects are deposited once and never acknowledged, so loss is
// detected, not repaired: every RoomMessage carries a per (room, sender)
// sequence from 1. A member keeps the highest sequence it holds of each
// sender and the ranges it is missing. A missing range is declared lost, as
// a room.gap record the runtime reads through rooms.gaps, when it has not
// arrived T after a later sequence did (T is the largest relay TTL of this
// node's own chat relays plus 5 minutes: a missing envelope can only still
// be waiting at one of them), or at once when an object of that sender was
// dropped. An object dropped unopened reveals no sequence, so its gap record
// names only the sender until the sender's next sequence fixes the range.
// Loss at a sender's tail is noticed at that sender's next message.

import (
	"bytes"
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
)

const (
	roomSequenceDir    = "room-sequences"
	roomGapDir         = "room-gaps"
	roomSequenceSchema = "tos.messaging.room-sequence.v1"
	roomGapSchema      = "tos.messaging.room-gap.v1"

	// RoomGapGrace is added to the largest own-relay TTL to make T.
	RoomGapGrace = 5 * time.Minute
	// MaxRoomMissingRanges bounds the undeclared missing ranges of one
	// sender; a range beyond it is declared at once.
	MaxRoomMissingRanges = 64
	// MaxRoomGaps bounds the gap records kept per room; the oldest go first.
	MaxRoomGaps = 1024
	// MaxRoomGapsPerSender is one sender's share of a room's gap records.
	MaxRoomGapsPerSender = 128
	// MaxRoomGapsTotal bounds the gap records of every room together.
	MaxRoomGapsTotal = 16384
	// MaxRoomSequenceRecords bounds the per (room, sender) sequence records
	// of every room together: 128 rooms of 32 members.
	MaxRoomSequenceRecords = 4096
	// MaxRoomGapsPerResponse bounds one rooms.gaps listing.
	MaxRoomGapsPerResponse = 64
)

// roomGapCap, roomGapSenderCap and roomGapTotalCap are MaxRoomGaps,
// MaxRoomGapsPerSender and MaxRoomGapsTotal; tests lower them to reach the
// bounds cheaply.
var (
	roomGapCap       = MaxRoomGaps
	roomGapSenderCap = MaxRoomGapsPerSender
	roomGapTotalCap  = MaxRoomGapsTotal
	// roomSequenceCap is MaxRoomSequenceRecords.
	roomSequenceCap = MaxRoomSequenceRecords
)

// ErrRoomSequencesFull reports that the per-sender sequence records of
// every room reached their bound.
var ErrRoomSequencesFull = errors.New("room sequence records reached their bound")

// RoomGapReason says why a sequence range was declared lost.
type RoomGapReason string

const (
	// RoomGapNotArrived: the range had not arrived T after a later sequence.
	RoomGapNotArrived RoomGapReason = "not-arrived"
	// RoomGapEpochTooOld: dropped, sealed in an epoch below current - 2.
	RoomGapEpochTooOld RoomGapReason = "epoch-too-old"
	// RoomGapEpochTooNew: dropped, sealed more than 4 epochs ahead.
	RoomGapEpochTooNew RoomGapReason = "epoch-too-new"
	// RoomGapBufferFull: dropped, the future-epoch buffer or the sender's
	// share was full.
	RoomGapBufferFull RoomGapReason = "buffer-full"
	// RoomGapBufferExpired: dropped after waiting 24 h 5 min for its epoch.
	RoomGapBufferExpired RoomGapReason = "buffer-expired"
	// RoomGapBehindRatchet: more than the out-of-order tolerance behind the
	// sender's ratchet.
	RoomGapBehindRatchet RoomGapReason = "behind-ratchet"
	// RoomGapRecordDamaged: a buffered object's record did not verify.
	RoomGapRecordDamaged RoomGapReason = "record-damaged"
)

var roomGapReasons = map[RoomGapReason]struct{}{
	RoomGapNotArrived: {}, RoomGapEpochTooOld: {}, RoomGapEpochTooNew: {}, RoomGapBufferFull: {},
	RoomGapBufferExpired: {}, RoomGapBehindRatchet: {}, RoomGapRecordDamaged: {},
}

// RoomGap is one room.gap record. First and Last are zero while the range
// is unknown (an object dropped unopened, its sender not heard from since).
type RoomGap struct {
	ID             string        `json:"gap_id"`
	RoomID         string        `json:"room_id"`
	SenderAgentID  string        `json:"sender_agent_id"`
	FirstSequence  uint64        `json:"first_missing_sequence,omitempty"`
	LastSequence   uint64        `json:"last_missing_sequence,omitempty"`
	Reason         RoomGapReason `json:"reason"`
	Dropped        uint32        `json:"dropped_objects,omitempty"`
	DeclaredAtUnix uint64        `json:"declared_at_unix"`
}

type roomGapRecord struct {
	Schema string `json:"schema"`
	RoomGap
}

type missingRange struct {
	First      uint64 `json:"first"`
	Last       uint64 `json:"last"`
	NoticedAtN int64  `json:"noticed_at_unix_nano"`
}

type roomSequenceRecord struct {
	Schema        string         `json:"schema"`
	RoomID        string         `json:"room_id"`
	SenderAgentID string         `json:"sender_agent_id"`
	Highest       uint64         `json:"highest_sequence"`
	Missing       []missingRange `json:"missing"`
	// OpenDrop names the sender-only gap record that the next sequence fixes.
	OpenDrop string `json:"open_drop_gap_id,omitempty"`
}

// RoomGapDelay returns T for the largest max_ttl_seconds of this node's own
// chat relays.
func RoomGapDelay(maxOwnRelayTTLSeconds uint64) (time.Duration, error) {
	if maxOwnRelayTTLSeconds == 0 || maxOwnRelayTTLSeconds > 86_400 {
		return 0, errors.New("own relay TTL is outside 1s..24h")
	}
	return time.Duration(maxOwnRelayTTLSeconds)*time.Second + RoomGapGrace, nil
}

// ObserveRoomSequence records that a member holds sequence of sender. Zero
// means a sender that keeps no sequence and records nothing. A jump records
// the skipped range as missing, or fixes the range of an open sender-only
// gap at once; a late sequence fills its missing range.
func (j *Journal) ObserveRoomSequence(roomID, sender string, sequence uint64, now time.Time) error {
	if err := j.usable(); err != nil {
		return err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(sender) || now.IsZero() || now.UnixNano() <= 0 {
		return errors.New("invalid room sequence")
	}
	if sequence == 0 {
		return nil
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	record, err := j.readRoomSequence(roomID, sender)
	if err != nil {
		return err
	}
	switch {
	case sequence > record.Highest:
		if sequence-record.Highest > 1 {
			skipped := missingRange{First: record.Highest + 1, Last: sequence - 1, NoticedAtN: now.UnixNano()}
			if record.OpenDrop != "" {
				if err := j.fixRoomGap(roomID, record.OpenDrop, skipped.First, skipped.Last); err != nil {
					return err
				}
				// Only a jump reveals the dropped object's range; a
				// contiguous sequence leaves the drop open.
				record.OpenDrop = ""
			} else {
				record.Missing = append(record.Missing, skipped)
			}
		}
		record.Highest = sequence
	default:
		record.Missing = fillMissing(record.Missing, sequence)
	}
	for len(record.Missing) > MaxRoomMissingRanges {
		oldest := record.Missing[0]
		if _, err := j.writeRoomGap(RoomGap{RoomID: roomID, SenderAgentID: sender, FirstSequence: oldest.First,
			LastSequence: oldest.Last, Reason: RoomGapNotArrived}, now); err != nil {
			return err
		}
		record.Missing = record.Missing[1:]
	}
	return j.writeRoomSequence(record)
}

// RecordRoomDrop declares a gap for an object of sender that was dropped
// unopened. Drops before the sender's next sequence share one sender-only
// record, which that sequence fixes.
func (j *Journal) RecordRoomDrop(roomID, sender string, reason RoomGapReason, now time.Time) (RoomGap, error) {
	if err := j.usable(); err != nil {
		return RoomGap{}, err
	}
	if _, known := roomGapReasons[reason]; !known || reason == RoomGapNotArrived {
		return RoomGap{}, errors.New("invalid room drop reason")
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(sender) || now.IsZero() || now.UnixNano() <= 0 {
		return RoomGap{}, errors.New("invalid room drop")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	record, err := j.readRoomSequence(roomID, sender)
	if err != nil {
		return RoomGap{}, err
	}
	if record.OpenDrop != "" {
		gap, found, err := j.readRoomGap(roomID, record.OpenDrop)
		if err != nil {
			return RoomGap{}, err
		}
		if found {
			if gap.Dropped < ^uint32(0) {
				gap.Dropped++
			}
			return gap, j.storeRoomGap(gap)
		}
	}
	gap, err := j.writeRoomGap(RoomGap{RoomID: roomID, SenderAgentID: sender, Reason: reason, Dropped: 1}, now)
	if err != nil {
		return RoomGap{}, err
	}
	record.OpenDrop = gap.ID
	return gap, j.writeRoomSequence(record)
}

// SweepRoomSequences declares every missing range that has not arrived
// delay after it was noticed. It returns the gaps it declared.
func (j *Journal) SweepRoomSequences(now time.Time, delay time.Duration) ([]RoomGap, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	if now.IsZero() || delay <= 0 {
		return nil, errors.New("invalid room sequence sweep")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	dir := filepath.Join(j.root, roomSequenceDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, errors.New("read room sequences")
	}
	var declared []RoomGap
	for _, entry := range entries {
		if isTransitionTemp(entry.Name()) {
			continue
		}
		roomID, sender, ok := parseRoomSequenceName(entry.Name())
		if !ok || entry.IsDir() {
			return nil, errors.New("unexpected entry in the room sequences")
		}
		record, err := j.readRoomSequence(roomID, sender)
		if err != nil {
			return nil, err
		}
		kept := record.Missing[:0:0]
		for _, missing := range record.Missing {
			if now.Sub(time.Unix(0, missing.NoticedAtN)) < delay {
				kept = append(kept, missing)
				continue
			}
			gap, err := j.writeRoomGap(RoomGap{RoomID: roomID, SenderAgentID: sender, FirstSequence: missing.First,
				LastSequence: missing.Last, Reason: RoomGapNotArrived}, now)
			if err != nil {
				return nil, err
			}
			declared = append(declared, gap)
		}
		if len(kept) != len(record.Missing) {
			record.Missing = kept
			if err := j.writeRoomSequence(record); err != nil {
				return nil, err
			}
		}
	}
	return declared, nil
}

// RoomGaps returns a room's gap records, newest first, at most limit.
func (j *Journal) RoomGaps(roomID string, limit int) ([]RoomGap, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	if !ids.Room.MatchString(roomID) || limit < 0 || limit > MaxRoomGapsPerResponse {
		return nil, errors.New("invalid room gap listing")
	}
	if limit == 0 {
		limit = MaxRoomGapsPerResponse
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	names, err := j.roomGapNames(roomID)
	if err != nil {
		return nil, err
	}
	gaps := make([]RoomGap, 0, limit)
	for index := len(names) - 1; index >= 0 && len(gaps) < limit; index-- {
		gap, found, err := j.readRoomGap(roomID, gapIDOf(names[index]))
		if err != nil {
			return nil, err
		}
		if found {
			gaps = append(gaps, gap)
		}
	}
	return gaps, nil
}

// fillMissing removes one late sequence from the missing ranges.
func fillMissing(ranges []missingRange, sequence uint64) []missingRange {
	out := make([]missingRange, 0, len(ranges)+1)
	for _, missing := range ranges {
		if sequence < missing.First || sequence > missing.Last {
			out = append(out, missing)
			continue
		}
		if sequence > missing.First {
			out = append(out, missingRange{First: missing.First, Last: sequence - 1, NoticedAtN: missing.NoticedAtN})
		}
		if sequence < missing.Last {
			out = append(out, missingRange{First: sequence + 1, Last: missing.Last, NoticedAtN: missing.NoticedAtN})
		}
	}
	return out
}

func roomSequenceName(roomID, sender string) string {
	return roomID[len("room_"):] + "-" + sender[len("agent_"):] + ".json"
}

func parseRoomSequenceName(name string) (string, string, bool) {
	stem, ok := strings.CutSuffix(name, ".json")
	roomHex, senderHex, cut := strings.Cut(stem, "-")
	if !ok || !cut || !ids.Room.MatchString("room_"+roomHex) || !ids.Agent.MatchString("agent_"+senderHex) {
		return "", "", false
	}
	return "room_" + roomHex, "agent_" + senderHex, true
}

func (j *Journal) readRoomSequence(roomID, sender string) (roomSequenceRecord, error) {
	empty := roomSequenceRecord{Schema: roomSequenceSchema, RoomID: roomID, SenderAgentID: sender, Missing: []missingRange{}}
	raw, err := readRecordBytes(filepath.Join(j.root, roomSequenceDir, roomSequenceName(roomID, sender)))
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return roomSequenceRecord{}, err
	}
	var record roomSequenceRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || validateRoomSequence(record, roomID, sender) != nil {
		return roomSequenceRecord{}, errors.New("invalid room sequence record")
	}
	return record, nil
}

func validateRoomSequence(record roomSequenceRecord, roomID, sender string) error {
	if record.Schema != roomSequenceSchema || record.RoomID != roomID || record.SenderAgentID != sender ||
		len(record.Missing) > MaxRoomMissingRanges+1 {
		return errors.New("invalid room sequence record")
	}
	for _, missing := range record.Missing {
		if missing.First == 0 || missing.Last < missing.First || missing.Last >= record.Highest || missing.NoticedAtN <= 0 {
			return errors.New("invalid room missing range")
		}
	}
	if record.OpenDrop != "" && !validGapID(record.OpenDrop) {
		return errors.New("invalid open room drop")
	}
	return nil
}

func (j *Journal) writeRoomSequence(record roomSequenceRecord) error {
	if err := validateRoomSequence(record, record.RoomID, record.SenderAgentID); err != nil {
		return err
	}
	path := filepath.Join(j.root, roomSequenceDir, roomSequenceName(record.RoomID, record.SenderAgentID))
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		count, err := countEntries(filepath.Join(j.root, roomSequenceDir))
		if err != nil {
			return err
		}
		if count >= roomSequenceCap {
			return ErrRoomSequencesFull
		}
	} else if err != nil {
		return errors.New("read room sequence")
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return j.replace(filepath.Join(j.root, roomSequenceDir, roomSequenceName(record.RoomID, record.SenderAgentID)), encoded)
}

// A gap ID orders the records of a room by declaration: the declaration
// time in nanoseconds, then the sender.
func newGapID(now time.Time, sender string) string {
	return fmt.Sprintf("%019d-%s", now.UnixNano(), sender[len("agent_"):])
}

func validGapID(id string) bool {
	nanos, senderHex, cut := strings.Cut(id, "-")
	if !cut || len(nanos) != 19 || !ids.Agent.MatchString("agent_"+senderHex) {
		return false
	}
	value, err := strconv.ParseInt(nanos, 10, 64)
	return err == nil && value > 0
}

func (j *Journal) roomGapPath(roomID, id string) string {
	return filepath.Join(j.root, roomGapDir, roomID[len("room_"):]+"-"+id+".json")
}

func gapIDOf(name string) string {
	stem := strings.TrimSuffix(name, ".json")
	_, id, _ := strings.Cut(stem, "-")
	return id
}

// writeRoomGap stores a new gap record and prunes the room's oldest beyond
// MaxRoomGaps. The journal mutex is held.
func (j *Journal) writeRoomGap(gap RoomGap, now time.Time) (RoomGap, error) {
	gap.ID = newGapID(now, gap.SenderAgentID)
	// Two gaps of one sender in the same nanosecond get distinct IDs.
	for {
		if _, err := os.Lstat(j.roomGapPath(gap.RoomID, gap.ID)); errors.Is(err, os.ErrNotExist) {
			break
		} else if err != nil {
			return RoomGap{}, errors.New("read room gap")
		}
		now = now.Add(time.Nanosecond)
		gap.ID = newGapID(now, gap.SenderAgentID)
	}
	gap.DeclaredAtUnix = uint64(now.Unix())
	if err := j.storeRoomGap(gap); err != nil {
		return RoomGap{}, err
	}
	if err := j.pruneRoomGaps(gap.RoomID, gap.SenderAgentID); err != nil {
		return RoomGap{}, err
	}
	return gap, nil
}

// pruneRoomGaps keeps the gap records bounded, oldest first: one sender's
// share of a room (so a noisy sender cannot evict the others' records), the
// room's bound, and the bound across rooms. The journal mutex is held.
func (j *Journal) pruneRoomGaps(roomID, sender string) error {
	all, err := j.allRoomGapNames()
	if err != nil {
		return err
	}
	var room, own []string
	for _, entry := range all {
		if entry.room != roomID {
			continue
		}
		room = append(room, entry.name)
		if strings.HasSuffix(entry.id, sender[len("agent_"):]) {
			own = append(own, entry.name)
		}
	}
	doomed := map[string]struct{}{}
	for index := 0; index < len(own)-roomGapSenderCap; index++ {
		doomed[own[index]] = struct{}{}
	}
	kept := 0
	for _, name := range room {
		if _, gone := doomed[name]; !gone {
			kept++
		}
	}
	for _, name := range room {
		if kept <= roomGapCap {
			break
		}
		if _, gone := doomed[name]; !gone {
			doomed[name] = struct{}{}
			kept--
		}
	}
	total := len(all) - len(doomed)
	for _, entry := range all {
		if total <= roomGapTotalCap {
			break
		}
		if _, gone := doomed[entry.name]; !gone {
			doomed[entry.name] = struct{}{}
			total--
		}
	}
	if len(doomed) == 0 {
		return nil
	}
	for name := range doomed {
		if err := os.Remove(filepath.Join(j.root, roomGapDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("prune room gaps")
		}
	}
	return syncDirectory(filepath.Join(j.root, roomGapDir))
}

type roomGapEntry struct{ name, room, id string }

// allRoomGapNames lists every room's gap records, oldest declaration first
// (the ID leads with the declaration time). The journal mutex is held.
func (j *Journal) allRoomGapNames() ([]roomGapEntry, error) {
	entries, err := os.ReadDir(filepath.Join(j.root, roomGapDir))
	if err != nil {
		return nil, errors.New("read room gaps")
	}
	var listed []roomGapEntry
	for _, entry := range entries {
		name := entry.Name()
		if isTransitionTemp(name) {
			continue
		}
		roomHex, rest, cut := strings.Cut(strings.TrimSuffix(name, ".json"), "-")
		if !cut || entry.IsDir() || !strings.HasSuffix(name, ".json") || !canon.HashPattern.MatchString(roomHex) || !validGapID(rest) {
			return nil, errors.New("unexpected entry in the room gaps")
		}
		listed = append(listed, roomGapEntry{name: name, room: "room_" + roomHex, id: rest})
	}
	sort.Slice(listed, func(a, b int) bool { return listed[a].id < listed[b].id })
	return listed, nil
}

func (j *Journal) storeRoomGap(gap RoomGap) error {
	if err := validateRoomGap(gap); err != nil {
		return err
	}
	encoded, err := json.Marshal(roomGapRecord{Schema: roomGapSchema, RoomGap: gap})
	if err != nil {
		return err
	}
	return j.replace(j.roomGapPath(gap.RoomID, gap.ID), encoded)
}

// fixRoomGap gives an open sender-only gap the range the sender's next
// sequence revealed. A gap already pruned is no error.
func (j *Journal) fixRoomGap(roomID, id string, first, last uint64) error {
	gap, found, err := j.readRoomGap(roomID, id)
	if err != nil || !found {
		return err
	}
	gap.FirstSequence, gap.LastSequence = first, last
	return j.storeRoomGap(gap)
}

func (j *Journal) readRoomGap(roomID, id string) (RoomGap, bool, error) {
	if !validGapID(id) {
		return RoomGap{}, false, errors.New("invalid room gap identifier")
	}
	raw, err := readRecordBytes(j.roomGapPath(roomID, id))
	if errors.Is(err, os.ErrNotExist) {
		return RoomGap{}, false, nil
	}
	if err != nil {
		return RoomGap{}, false, err
	}
	var record roomGapRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.Schema != roomGapSchema || record.RoomID != roomID ||
		record.ID != id || validateRoomGap(record.RoomGap) != nil {
		return RoomGap{}, false, errors.New("invalid room gap record")
	}
	return record.RoomGap, true, nil
}

func validateRoomGap(gap RoomGap) error {
	if !ids.Room.MatchString(gap.RoomID) || !ids.Agent.MatchString(gap.SenderAgentID) || !validGapID(gap.ID) ||
		!strings.HasSuffix(gap.ID, gap.SenderAgentID[len("agent_"):]) || gap.DeclaredAtUnix == 0 {
		return errors.New("invalid room gap")
	}
	if _, known := roomGapReasons[gap.Reason]; !known {
		return errors.New("invalid room gap reason")
	}
	if (gap.FirstSequence == 0) != (gap.LastSequence == 0) || gap.LastSequence < gap.FirstSequence {
		return errors.New("invalid room gap range")
	}
	if gap.Reason == RoomGapNotArrived && (gap.FirstSequence == 0 || gap.Dropped != 0) {
		return errors.New("a gap of messages that did not arrive names its range")
	}
	return nil
}

// roomGapNames lists a room's gap record names in declaration order.
func (j *Journal) roomGapNames(roomID string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(j.root, roomGapDir))
	if err != nil {
		return nil, errors.New("read room gaps")
	}
	prefix := roomID[len("room_"):] + "-"
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if isTransitionTemp(name) {
			continue
		}
		roomHex, rest, cut := strings.Cut(strings.TrimSuffix(name, ".json"), "-")
		if !cut || entry.IsDir() || !strings.HasSuffix(name, ".json") || !canon.HashPattern.MatchString(roomHex) || !validGapID(rest) {
			return nil, errors.New("unexpected entry in the room gaps")
		}
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}
