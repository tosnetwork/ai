package eventlog

// Applied handshake digests of a private room (section 11.3).
//
// Commits and Welcomes are ordered and fork-checked by MLS epoch, rosters by
// room epoch. A receiver keeps the relay object digests of the last 64
// Commits and Welcomes it applied, keyed by the MLS epoch each produced, and
// of the last 64 rosters it accepted, keyed by the room epoch each
// describes. JudgeRoomHandshake and JudgeRoomRoster apply the receive rules
// to them and to the fused record's current epochs.
//
// The fused record is the commit point of an applied Commit or Welcome, and
// this record is a separate file, so the two are joined by an intent: the
// receiver records BeginRoomHandshake (epoch, object digest and the Commit or
// Welcome reference the fused record will carry) before it advances, and
// CompleteRoomHandshake after. A crash in between is resolved on the next
// judgement: if the fused record carries the intent's reference at the
// intent's epoch the object was applied and its digest joins the list;
// otherwise the intent is discarded and the redelivered object applies
// normally. So an applied object is never judged a fork of itself.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
)

const (
	roomAppliedDir    = "room-applied"
	roomAppliedSchema = "tos.messaging.room-applied.v1"
	// RoomAppliedWindow is how many applied Commits and Welcomes, and how
	// many accepted rosters, a member keeps the digests of.
	RoomAppliedWindow = 64
	// RoomRosterWindow is how many room epochs back a roster may describe:
	// [current - 2, current], the memberships kept for D11.
	RoomRosterWindow = RetainedRoomEpochs - 1
)

// HandshakeVerdict is the receive rule a Commit or Welcome falls under.
type HandshakeVerdict int

const (
	// HandshakeApply: the next MLS epoch; verify and apply it.
	HandshakeApply HandshakeVerdict = iota + 1
	// HandshakeDuplicate: among the last 64 applied; answer duplicate.
	HandshakeDuplicate
	// HandshakeFork: another object for an MLS epoch within the window;
	// answer room-fork.
	HandshakeFork
	// HandshakeStale: older than the window; drop silently and
	// relay-acknowledge.
	HandshakeStale
	// HandshakeGap: above current + 1; answer room-epoch-gap (unless the
	// caller finds a verified Commit removing this member).
	HandshakeGap
)

// RosterVerdict is the receive rule a roster falls under.
type RosterVerdict int

const (
	// RosterAccept: inside [current - 2, current] and new; check and learn it.
	RosterAccept RosterVerdict = iota + 1
	// RosterDuplicate: among the last 64 accepted; answer duplicate.
	RosterDuplicate
	// RosterConflict: a different roster for the same room epoch was
	// accepted; answer room-roster-conflict with an owner notice.
	RosterConflict
	// RosterStale: older than current - 2; drop silently.
	RosterStale
	// RosterGap: above current; answer room-epoch-gap.
	RosterGap
)

type appliedEntry struct {
	Epoch  uint64 `json:"epoch"`
	Digest string `json:"object_digest"`
}

type handshakeIntent struct {
	MLSEpoch uint64 `json:"mls_epoch"`
	Digest   string `json:"object_digest"`
	// Ref is the Commit reference or processed Welcome reference the fused
	// record carries once the object is applied.
	Ref string `json:"ref"`
}

type roomAppliedRecord struct {
	Schema     string           `json:"schema"`
	RoomID     string           `json:"room_id"`
	Handshakes []appliedEntry   `json:"handshakes"`
	Rosters    []appliedEntry   `json:"rosters"`
	Intent     *handshakeIntent `json:"intent,omitempty"`
}

func validObjectDigest(digest string) bool { return canon.HashPattern.MatchString(digest) }

// JudgeRoomHandshake applies the receive order to a Commit or Welcome
// producing mlsEpoch. A joiner's first Welcome has no fused record yet and
// goes through the pending-join path instead: this returns ErrRoomNotJoined.
func (j *Journal) JudgeRoomHandshake(roomID string, mlsEpoch uint64, objectDigest string) (HandshakeVerdict, error) {
	if err := j.usable(); err != nil {
		return 0, err
	}
	if !ids.Room.MatchString(roomID) || !validObjectDigest(objectDigest) {
		return 0, errors.New("invalid room handshake judgement")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	fused, found, err := j.readRoomMLS(roomID)
	if err != nil {
		return 0, err
	}
	record, err := j.reconcileRoomApplied(roomID, fused, found)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, ErrRoomNotJoined
	}
	for _, entry := range record.Handshakes {
		if entry.Digest == objectDigest {
			return HandshakeDuplicate, nil
		}
	}
	current := fused.MLSEpoch
	if current != ^uint64(0) && mlsEpoch == current+1 {
		return HandshakeApply, nil
	}
	if mlsEpoch > current {
		return HandshakeGap, nil
	}
	// The window is the epochs of the retained digests; a member that has
	// applied none yet has only its current epoch.
	low := current
	for _, entry := range record.Handshakes {
		if entry.Epoch < low {
			low = entry.Epoch
		}
	}
	if mlsEpoch >= low {
		return HandshakeFork, nil
	}
	return HandshakeStale, nil
}

// BeginRoomHandshake records the intent to apply one Commit or Welcome. It
// replaces any earlier intent, which a judgement already resolved.
func (j *Journal) BeginRoomHandshake(roomID string, mlsEpoch uint64, objectDigest, ref string) error {
	if err := j.usable(); err != nil {
		return err
	}
	if !ids.Room.MatchString(roomID) || !validObjectDigest(objectDigest) || !canon.ValidDigest(ref) {
		return errors.New("invalid room handshake intent")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	record, _, err := j.readRoomApplied(roomID)
	if err != nil {
		return err
	}
	record.Intent = &handshakeIntent{MLSEpoch: mlsEpoch, Digest: objectDigest, Ref: ref}
	return j.writeRoomApplied(record)
}

// CompleteRoomHandshake records an applied Commit or Welcome once the fused
// record carries it, and clears the intent. A repeat is a no-op.
func (j *Journal) CompleteRoomHandshake(roomID string, mlsEpoch uint64, objectDigest string) error {
	if err := j.usable(); err != nil {
		return err
	}
	if !ids.Room.MatchString(roomID) || !validObjectDigest(objectDigest) {
		return errors.New("invalid applied room handshake")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	fused, found, err := j.readRoomMLS(roomID)
	if err != nil {
		return err
	}
	if !found || fused.MLSEpoch < mlsEpoch {
		return errors.New("the fused record has not applied this handshake")
	}
	record, _, err := j.readRoomApplied(roomID)
	if err != nil {
		return err
	}
	record.Handshakes = appendApplied(record.Handshakes, appliedEntry{Epoch: mlsEpoch, Digest: objectDigest})
	if record.Intent != nil && record.Intent.Digest == objectDigest {
		record.Intent = nil
	}
	return j.writeRoomApplied(record)
}

// JudgeRoomRoster applies the roster rules to a roster describing room epoch
// roomEpoch, against the receiver's current room epoch.
func (j *Journal) JudgeRoomRoster(roomID string, roomEpoch uint64, objectDigest string) (RosterVerdict, error) {
	if err := j.usable(); err != nil {
		return 0, err
	}
	if !ids.Room.MatchString(roomID) || roomEpoch == 0 || !validObjectDigest(objectDigest) {
		return 0, errors.New("invalid room roster judgement")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	fused, found, err := j.readRoomMLS(roomID)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, ErrRoomNotJoined
	}
	record, _, err := j.readRoomApplied(roomID)
	if err != nil {
		return 0, err
	}
	for _, entry := range record.Rosters {
		if entry.Digest == objectDigest {
			return RosterDuplicate, nil
		}
	}
	current := fused.RoomEpoch
	if roomEpoch > current {
		return RosterGap, nil
	}
	if current-roomEpoch > RoomRosterWindow {
		return RosterStale, nil
	}
	for _, entry := range record.Rosters {
		if entry.Epoch == roomEpoch {
			return RosterConflict, nil
		}
	}
	return RosterAccept, nil
}

// RecordRoomRoster records an accepted roster. Learning a roster's entries
// is idempotent, so a crash before this write only repeats the learning.
func (j *Journal) RecordRoomRoster(roomID string, roomEpoch uint64, objectDigest string) error {
	if err := j.usable(); err != nil {
		return err
	}
	if !ids.Room.MatchString(roomID) || roomEpoch == 0 || !validObjectDigest(objectDigest) {
		return errors.New("invalid accepted room roster")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	record, _, err := j.readRoomApplied(roomID)
	if err != nil {
		return err
	}
	for _, entry := range record.Rosters {
		if entry.Epoch == roomEpoch && entry.Digest != objectDigest {
			return errors.New("another roster was accepted for this room epoch")
		}
	}
	record.Rosters = appendApplied(record.Rosters, appliedEntry{Epoch: roomEpoch, Digest: objectDigest})
	return j.writeRoomApplied(record)
}

// reconcileRoomApplied resolves an intent left by a crash. The journal
// mutex is held.
func (j *Journal) reconcileRoomApplied(roomID string, fused RoomMLSRecord, found bool) (roomAppliedRecord, error) {
	record, _, err := j.readRoomApplied(roomID)
	if err != nil || record.Intent == nil {
		return record, err
	}
	intent := *record.Intent
	record.Intent = nil
	if found && fused.MLSEpoch == intent.MLSEpoch && (fused.AcceptedCommitRef == intent.Ref || fused.WelcomeRef == intent.Ref) {
		record.Handshakes = appendApplied(record.Handshakes, appliedEntry{Epoch: intent.MLSEpoch, Digest: intent.Digest})
	}
	return record, j.writeRoomApplied(record)
}

// appendApplied adds an entry once, keeping the newest RoomAppliedWindow.
func appendApplied(entries []appliedEntry, entry appliedEntry) []appliedEntry {
	for _, existing := range entries {
		if existing.Digest == entry.Digest {
			return entries
		}
	}
	entries = append(entries, entry)
	if len(entries) > RoomAppliedWindow {
		entries = append([]appliedEntry(nil), entries[len(entries)-RoomAppliedWindow:]...)
	}
	return entries
}

func (j *Journal) roomAppliedPath(roomID string) string {
	return filepath.Join(j.root, roomAppliedDir, roomID[len("room_"):]+".json")
}

func (j *Journal) readRoomApplied(roomID string) (roomAppliedRecord, bool, error) {
	empty := roomAppliedRecord{Schema: roomAppliedSchema, RoomID: roomID, Handshakes: []appliedEntry{}, Rosters: []appliedEntry{}}
	raw, err := readRecordBytes(j.roomAppliedPath(roomID))
	if errors.Is(err, os.ErrNotExist) {
		return empty, false, nil
	}
	if err != nil {
		return roomAppliedRecord{}, false, err
	}
	var record roomAppliedRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || validateRoomApplied(record, roomID) != nil {
		return roomAppliedRecord{}, false, errors.New("invalid applied room handshake record")
	}
	return record, true, nil
}

func validateRoomApplied(record roomAppliedRecord, roomID string) error {
	if record.Schema != roomAppliedSchema || record.RoomID != roomID ||
		len(record.Handshakes) > RoomAppliedWindow || len(record.Rosters) > RoomAppliedWindow {
		return errors.New("invalid applied room handshake record")
	}
	for _, list := range [][]appliedEntry{record.Handshakes, record.Rosters} {
		seen := map[string]struct{}{}
		for _, entry := range list {
			if !validObjectDigest(entry.Digest) {
				return errors.New("invalid applied room digest")
			}
			if _, duplicate := seen[entry.Digest]; duplicate {
				return errors.New("duplicate applied room digest")
			}
			seen[entry.Digest] = struct{}{}
		}
	}
	if record.Intent != nil && (!validObjectDigest(record.Intent.Digest) || !canon.ValidDigest(record.Intent.Ref)) {
		return errors.New("invalid room handshake intent")
	}
	return nil
}

func (j *Journal) writeRoomApplied(record roomAppliedRecord) error {
	if err := validateRoomApplied(record, record.RoomID); err != nil {
		return err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return j.replace(j.roomAppliedPath(record.RoomID), encoded)
}
