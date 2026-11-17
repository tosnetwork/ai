package eventlog

// Retirement of an ended private room (D18, section 11.8).
//
// A room ends at its authority's leaf-credential expiry. Members refuse its
// objects from end + skew; the authority's re-deposits stop then too. Once
// end + handshake retention + skew has passed, no object of the room can
// still be owed to anyone, and the room is retired here, in this order:
//
//  1. its room-outbox heads and staged outputs, its part-store entries, its
//     future-epoch buffer and its receive state (sequences, gaps, applied
//     and received digests);
//  2. its credential list;
//  3. its fused record, last, as the commit point, with a directory fsync.
//
// A crash between steps leaves the fused record, so the next retirement of
// that room (RetireEndedRooms at restart) repeats the steps, each of which is
// a no-op when already done. Ordinary garbage collection then reclaims the
// state chunks, credentials, memberships, delegations and object chunks that
// nothing names. Until the room is retired again, a collection that finds the
// fused record without its list fails closed and deletes nothing.
//
// Parts are stored by (sender, object digest), not by room: a part names its
// room only in part 0, inside the object. Parts whose part 0 names the room
// are deleted; a later part whose part 0 never arrived expires with the part
// store's own lifetime. A caller holding the parts in memory (RoomParts)
// drops the room's objects there as well.

import (
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
)

// ErrRoomNotEnded reports a room whose retirement time has not come.
var ErrRoomNotEnded = errors.New("the room's retirement time has not come")

// beforeRoomRetireStep, when set by a test, runs before retirement step n
// (2 or 3) and stops it if it returns an error: the crash windows a restart
// must finish.
var beforeRoomRetireStep func(step int) error

// RoomRetireAt returns when a room is retired: its end plus the handshake
// retention plus the clock-skew bound.
func RoomRetireAt(record RoomMLSRecord, retention, skew time.Duration) (time.Time, error) {
	if retention <= 0 || skew < 0 || record.RoomEndsAtUnix == 0 || record.RoomEndsAtUnix > math.MaxInt64/2 {
		return time.Time{}, errors.New("invalid room retirement parameters")
	}
	end := time.Unix(int64(record.RoomEndsAtUnix), 0)
	extra := retention + skew
	if extra < retention {
		return time.Time{}, errors.New("room retirement time overflows")
	}
	at := end.Add(extra)
	if at.Before(end) {
		return time.Time{}, errors.New("room retirement time overflows")
	}
	return at, nil
}

// RetireRoom retires one room whose retirement time has passed. It reports
// false when the room is not held here (already retired).
func (l *RoomMLSLedger) RetireRoom(roomID string, now time.Time, retention, skew time.Duration) (bool, error) {
	if l == nil {
		return false, errors.New("no fused room ledger")
	}
	if err := l.journal.usable(); err != nil {
		return false, err
	}
	if !ids.Room.MatchString(roomID) || now.IsZero() {
		return false, errors.New("invalid room retirement")
	}
	l.journal.mutex.Lock()
	record, found, err := l.journal.readRoomMLS(roomID)
	l.journal.mutex.Unlock()
	if err != nil || !found {
		return false, err
	}
	at, err := RoomRetireAt(record, retention, skew)
	if err != nil {
		return false, err
	}
	if now.Before(at) {
		return false, ErrRoomNotEnded
	}
	return true, l.journal.retireRoom(record)
}

// RetireEndedRooms retires every held room whose retirement time has passed,
// including one a crash left half retired. The daemon runs it at start,
// before garbage collection, and periodically. It returns the rooms retired.
func (l *RoomMLSLedger) RetireEndedRooms(now time.Time, retention, skew time.Duration) ([]string, error) {
	if l == nil {
		return nil, errors.New("no fused room ledger")
	}
	if err := l.journal.usable(); err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, errors.New("invalid room retirement time")
	}
	l.journal.mutex.Lock()
	roomIDs, err := l.journal.fusedRoomIDs()
	l.journal.mutex.Unlock()
	if err != nil {
		return nil, err
	}
	var retired []string
	for _, roomID := range roomIDs {
		done, err := l.RetireRoom(roomID, now, retention, skew)
		if errors.Is(err, ErrRoomNotEnded) {
			continue
		}
		if err != nil {
			return retired, err
		}
		if done {
			retired = append(retired, roomID)
		}
	}
	return retired, nil
}

// retireRoom runs the three steps for a room whose fused record was read.
func (j *Journal) retireRoom(record RoomMLSRecord) error {
	roomID := record.RoomID
	// Step 1: the room's outbox, parts, buffer and receive state.
	if err := j.deleteRoomPartsOf(roomID); err != nil {
		return err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	if err := j.deleteRoomOutbox(roomID); err != nil {
		return err
	}
	if _, err := j.deleteRoomState(roomID); err != nil {
		return err
	}
	// Step 2: the credential list.
	if beforeRoomRetireStep != nil {
		if err := beforeRoomRetireStep(2); err != nil {
			return err
		}
	}
	listPath, err := j.roomBlobPath(credentialListBlobPrefix, record.CredentialListDigest)
	if err != nil {
		return err
	}
	if err := os.Remove(listPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("delete room credential list")
	}
	if err := syncDirectory(filepath.Dir(listPath)); err != nil {
		return err
	}
	// Step 3: the fused record, last, as the commit point.
	if beforeRoomRetireStep != nil {
		if err := beforeRoomRetireStep(3); err != nil {
			return err
		}
	}
	path := filepath.Join(j.root, roomMLSDir, roomID[len("room_"):]+".json")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("delete fused room record")
	}
	return syncDirectory(filepath.Dir(path))
}

// deleteRoomOutbox removes the room's outbox heads and staged outputs. An
// unreadable head or staged output fails the step: it might be this room's.
// The journal mutex is held.
func (j *Journal) deleteRoomOutbox(roomID string) error {
	heads, err := j.readRoomHeads()
	if err != nil {
		return err
	}
	removed := false
	for _, head := range heads {
		if head.RoomID != roomID {
			continue
		}
		path, err := j.roomHeadPath(head.ObjectDigest)
		if err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("delete room outbox head")
		}
		removed = true
	}
	if removed {
		if err := syncDirectory(filepath.Join(j.root, roomOutboxDir)); err != nil {
			return err
		}
	}
	dir := filepath.Join(j.root, roomStagedDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errors.New("read staged room outputs")
	}
	removed = false
	for _, entry := range entries {
		if isTransitionTemp(entry.Name()) {
			continue
		}
		staged, err := j.readRoomStaged(filepath.Join(dir, entry.Name()))
		if err != nil {
			return err
		}
		if staged.RoomID != roomID {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("delete staged room output")
		}
		removed = true
	}
	if removed {
		return syncDirectory(dir)
	}
	return nil
}

// deleteRoomPartsOf removes every stored part of an object whose part 0
// names the room. It takes the journal mutex itself.
func (j *Journal) deleteRoomPartsOf(roomID string) error {
	parts, _, err := j.listRoomParts()
	if err != nil {
		return err
	}
	roomHex := roomID[len("room_"):]
	doomed := map[roomPartKey]struct{}{}
	for _, part := range parts {
		if part.frame.PartIndex == 0 && partNamesRoom(part.frame.Part, roomHex) {
			doomed[part.key] = struct{}{}
		}
	}
	var names []string
	for _, part := range parts {
		if _, gone := doomed[part.key]; gone {
			names = append(names, part.name)
		}
	}
	return j.removeRoomPartNames(names)
}

// partNamesRoom reports whether the first part of a room object names the
// room: the object begins with its domain, its type byte and the raw room
// digest.
func partNamesRoom(part []byte, roomHex string) bool {
	start := len(canon.DomainRelayRoomObject) + 1
	if len(part) < start+32 || string(part[:len(canon.DomainRelayRoomObject)]) != canon.DomainRelayRoomObject {
		return false
	}
	return hex.EncodeToString(part[start:start+32]) == roomHex
}
