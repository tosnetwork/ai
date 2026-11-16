package eventlog

// Restart recovery and garbage collection of private-room records.
//
// The roots are every fused room record and every room-outbox head: an older
// Commit stays re-depositable after the authority has moved on, and a roster
// or Commit whose fused record has been superseded is named only by its head.
// A staged state, delegation, membership or object chunk that no root names
// is deleted; nothing was published from it and the old state stands.
//
// Collection fails closed. If any root, or any staged Commit output that was
// not resolved, cannot be read, nothing is deleted: an unreadable root might
// be the only one naming a chunk, and deleting that chunk would turn a
// repairable record into a lost room.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/tosnetwork/ai/messenger/internal/canon"
)

// RoomGarbageReport says what one collection did.
type RoomGarbageReport struct {
	// FailedClosed is set when an unreadable root or staged output stopped
	// the collection before it deleted anything.
	FailedClosed bool
	// Deleted counts the unnamed staged records removed.
	Deleted int
	// Unresolved names the staged Commit outputs that stopped collection.
	Unresolved []string
}

// recoverRooms runs at Open, before any room operation: it publishes or
// discards every staged Commit output, then collects unnamed records.
func (j *Journal) recoverRooms() error {
	_, err := j.collectRoomGarbage()
	return err
}

// CollectRoomGarbage resolves staged Commit outputs and deletes every staged
// record no root names. Open runs it; it is exported so its fail-closed rule
// can be checked directly.
func (j *Journal) CollectRoomGarbage() (RoomGarbageReport, error) {
	if err := j.usable(); err != nil {
		return RoomGarbageReport{}, err
	}
	return j.collectRoomGarbage()
}

func (j *Journal) collectRoomGarbage() (RoomGarbageReport, error) {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	unresolved, err := j.resolveRoomStaged("")
	if err != nil {
		return RoomGarbageReport{}, err
	}
	if err := j.retireOrphanedSettledHeads(); err != nil {
		return RoomGarbageReport{}, err
	}
	if len(unresolved) > 0 {
		return RoomGarbageReport{FailedClosed: true, Unresolved: unresolved}, nil
	}
	named, ok, err := j.namedRoomRecords()
	if err != nil {
		return RoomGarbageReport{}, err
	}
	if !ok {
		return RoomGarbageReport{FailedClosed: true}, nil
	}
	report := RoomGarbageReport{}
	for _, area := range []struct {
		dir  string
		keep func(name string) (bool, bool)
	}{
		{roomStateDir, named.keepState},
		{roomBlobDir, named.keepBlob},
		{roomObjectChunkDir, named.keepObjectChunk},
	} {
		entries, err := os.ReadDir(filepath.Join(j.root, area.dir))
		if err != nil {
			return report, errors.New("read staged room directory")
		}
		removed := false
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || isTransitionTemp(name) {
				continue
			}
			// A name that is not a staged record of this area is left alone:
			// collection only deletes what it can prove is its own garbage.
			recognized, keep := area.keep(name)
			if !recognized || keep {
				continue
			}
			if err := os.Remove(filepath.Join(j.root, area.dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return report, errors.New("delete unnamed staged room record")
			}
			report.Deleted++
			removed = true
		}
		if removed {
			if err := syncDirectory(filepath.Join(j.root, area.dir)); err != nil {
				return report, err
			}
		}
	}
	return report, nil
}

type namedRoomSet struct {
	state        map[string]struct{}
	delegations  map[string]struct{}
	memberships  map[string]struct{}
	objectChunks map[string]struct{}
}

// namedRoomRecords reads every root and returns what they name. ok is false
// when a root could not be read. The journal mutex is held.
func (j *Journal) namedRoomRecords() (namedRoomSet, bool, error) {
	named := namedRoomSet{
		state: map[string]struct{}{}, delegations: map[string]struct{}{},
		memberships: map[string]struct{}{}, objectChunks: map[string]struct{}{},
	}
	roomIDs, err := j.fusedRoomIDs()
	if err != nil {
		return named, false, nil
	}
	for _, roomID := range roomIDs {
		record, found, err := j.readRoomMLS(roomID)
		if err != nil || !found {
			return named, false, nil
		}
		for _, chunk := range record.StateChunks {
			path, err := j.roomStatePath(roomID, chunk)
			if err != nil {
				return named, false, nil
			}
			named.state[filepath.Base(path)] = struct{}{}
		}
		named.delegations[record.DelegationDigest] = struct{}{}
		for _, digest := range record.PriorMemberships {
			named.memberships[digest] = struct{}{}
		}
	}
	entries, err := os.ReadDir(filepath.Join(j.root, roomOutboxDir))
	if err != nil {
		return named, false, errors.New("read room outbox")
	}
	for _, entry := range entries {
		if isTransitionTemp(entry.Name()) {
			continue
		}
		head, err := j.readRoomHead(filepath.Join(j.root, roomOutboxDir, entry.Name()))
		if err != nil {
			return named, false, nil
		}
		for _, chunk := range head.Chunks {
			named.objectChunks[chunk] = struct{}{}
		}
	}
	return named, true, nil
}

func (n namedRoomSet) keepState(name string) (bool, bool) {
	stem, ok := strings.CutSuffix(name, ".json")
	if !ok {
		return false, false
	}
	roomHex, chunkHex, ok := strings.Cut(stem, "-")
	if !ok || !canon.HashPattern.MatchString(roomHex) || !canon.HashPattern.MatchString(chunkHex) {
		return false, false
	}
	_, keep := n.state[name]
	return true, keep
}

func (n namedRoomSet) keepBlob(name string) (bool, bool) {
	stem, ok := strings.CutSuffix(name, ".json")
	if !ok {
		return false, false
	}
	if value, ok := strings.CutPrefix(stem, delegationBlobPrefix); ok && canon.HashPattern.MatchString(value) {
		_, keep := n.delegations["sha256:"+value]
		return true, keep
	}
	if value, ok := strings.CutPrefix(stem, membershipBlobPrefix); ok && canon.HashPattern.MatchString(value) {
		_, keep := n.memberships["sha256:"+value]
		return true, keep
	}
	return false, false
}

func (n namedRoomSet) keepObjectChunk(name string) (bool, bool) {
	stem, ok := strings.CutSuffix(name, ".json")
	if !ok || !canon.HashPattern.MatchString(stem) {
		return false, false
	}
	_, keep := n.objectChunks["sha256:"+stem]
	return true, keep
}
