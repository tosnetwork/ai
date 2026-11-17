package eventlog

// The durable part store of split kind-3 room objects.
//
// relayframe.Reassembler holds the parts of incomplete objects in memory and
// enforces every reassembly bound of section 4: who may hold parts, the
// object bound, 4 incomplete objects and 4 MiB per sender, 16 MiB in total,
// and the 24 h 5 min lifetime. A part is relay-acknowledged once it is
// stored, so a part only in memory would be lost by a restart and its object
// could complete only after the sender's next re-deposit of every part.
//
// RoomParts pairs the Reassembler with this store. Every part the
// Reassembler holds is written here before the caller acknowledges it; on
// start every stored part is added again, with its own arrival time and in
// arrival order, into a new Reassembler, which re-applies every bound and so
// rebuilds the same state. The store never holds more than the Reassembler
// does: a part it refuses on replay is deleted, an object it drops (a
// contradicting part, a digest mismatch, expiry, a removed sender) has its
// parts deleted, and a complete object's parts are deleted once the caller
// settles it. Parts the caller has not settled survive a crash and complete
// again on replay, so a complete object is never lost between its last part
// and the caller's durable handling of it.
//
// The store names no other record, so it is no garbage-collection root.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

const (
	roomPartDir    = "room-parts"
	roomPartSchema = "tos.messaging.room-part.v1"
)

// ErrRoomPartStore reports a part the store could not make durable. The
// caller answers retry and does not relay-acknowledge the envelope; the
// re-delivered part is a duplicate in memory and is written then.
var ErrRoomPartStore = errors.New("room part could not be stored")

type roomPartRecord struct {
	Schema         string `json:"schema"`
	SenderAgentID  string `json:"sender_agent_id"`
	ObjectDigest   string `json:"object_digest"`
	PartIndex      uint8  `json:"part_index"`
	PartCount      uint8  `json:"part_count"`
	ArrivedAtNano  int64  `json:"arrived_at_unix_nano"`
	CardBase64     string `json:"card_base64,omitempty"`
	EvidenceBase64 string `json:"evidence_base64,omitempty"`
	PartBase64     string `json:"part_base64"`
}

type roomPartKey struct {
	sender string
	digest [sha256.Size]byte
}

// storedRoomPart is a decoded record with its frame.
type storedRoomPart struct {
	name    string
	key     roomPartKey
	arrived time.Time
	frame   relayframe.Frame
}

// RoomPartCompletion is a complete object the caller has to handle and then
// settle.
type RoomPartCompletion struct {
	Sender string
	Digest [sha256.Size]byte
	Result relayframe.PartResult
}

// RoomPartReplay reports what OpenRoomParts rebuilt.
type RoomPartReplay struct {
	// Replayed counts the stored parts the new Reassembler holds again.
	Replayed int
	// Refused counts stored parts the Reassembler refused (a bound, a sender
	// no longer admitted) or that belonged to an object it dropped; they are
	// deleted.
	Refused int
	// Expired counts parts of objects older than the lifetime; deleted.
	Expired int
	// Damaged counts records that did not decode; deleted.
	Damaged int
	// Completed are objects all of whose parts were stored: the crash fell
	// between the last part and the caller's settlement. The caller handles
	// each and settles it.
	Completed []RoomPartCompletion
}

// RoomParts is the durable side of one Reassembler. It is safe for
// concurrent use.
type RoomParts struct {
	journal     *Journal
	reassembler *relayframe.Reassembler
	mutex       sync.Mutex
	// unsettled are complete objects whose stored parts the caller has not
	// settled yet, with the time they completed. A sweep leaves their parts
	// alone until the lifetime has passed since completion.
	unsettled map[roomPartKey]time.Time
}

// OpenRoomParts binds an empty Reassembler to the part store and replays
// every stored part into it. Parts are added with their own arrival times,
// oldest first, so the Reassembler judges each against the state that
// existed when it arrived; what it refuses is deleted. Finally every object
// past the lifetime at now is dropped.
func (j *Journal) OpenRoomParts(reassembler *relayframe.Reassembler, now time.Time) (*RoomParts, RoomPartReplay, error) {
	if err := j.usable(); err != nil {
		return nil, RoomPartReplay{}, err
	}
	if reassembler == nil || now.IsZero() || now.Unix() <= 0 {
		return nil, RoomPartReplay{}, errors.New("invalid room part store binding")
	}
	if usage := reassembler.Usage(); usage.Objects != 0 {
		return nil, RoomPartReplay{}, errors.New("the room part store replays into an empty reassembler only")
	}
	parts := &RoomParts{journal: j, reassembler: reassembler, unsettled: map[roomPartKey]time.Time{}}
	parts.mutex.Lock()
	defer parts.mutex.Unlock()
	report, err := parts.replay(now)
	if err != nil {
		return nil, RoomPartReplay{}, err
	}
	return parts, report, nil
}

func (p *RoomParts) replay(now time.Time) (RoomPartReplay, error) {
	report := RoomPartReplay{}
	stored, damaged, err := p.journal.listRoomParts()
	if err != nil {
		return report, err
	}
	report.Damaged = len(damaged)
	if err := p.journal.removeRoomPartNames(damaged); err != nil {
		return report, err
	}
	lifetime := p.reassembler.Lifetime()
	first := map[roomPartKey]time.Time{}
	for _, part := range stored {
		if earliest, seen := first[part.key]; !seen || part.arrived.Before(earliest) {
			first[part.key] = part.arrived
		}
	}
	sort.Slice(stored, func(a, b int) bool {
		if !stored[a].arrived.Equal(stored[b].arrived) {
			return stored[a].arrived.Before(stored[b].arrived)
		}
		return stored[a].name < stored[b].name
	})
	var stale []string
	for _, part := range stored {
		if now.Sub(first[part.key]) >= lifetime {
			stale = append(stale, part.name)
			report.Expired++
			continue
		}
		result, err := p.reassembler.Add(part.key.sender, part.frame, part.arrived)
		switch {
		case err != nil:
			stale = append(stale, part.name)
			report.Refused++
		case result.Status == relayframe.PartComplete:
			p.unsettled[part.key] = now
			report.Completed = append(report.Completed, RoomPartCompletion{Sender: part.key.sender, Digest: part.key.digest, Result: result})
			report.Replayed++
		default:
			report.Replayed++
		}
	}
	if err := p.journal.removeRoomPartNames(stale); err != nil {
		return report, err
	}
	// Objects the Reassembler dropped while replaying (a contradicting part,
	// a digest mismatch, its own expiry) leave parts nobody holds.
	dropped, err := p.deleteUnheld()
	if err != nil {
		return report, err
	}
	report.Refused += dropped
	if expired := p.reassembler.Sweep(now); expired > 0 {
		count, err := p.deleteUnheld()
		if err != nil {
			return report, err
		}
		report.Expired += count
	}
	return report, nil
}

// Add offers one kind-3 frame from an authenticated packet sender. A part
// the Reassembler holds, fresh or duplicate, is durable before Add returns,
// so the caller may relay-acknowledge it. A complete object stays stored
// until Settle. When the Reassembler dropped an object, its stored parts
// are deleted.
func (p *RoomParts) Add(sender string, frame relayframe.Frame, now time.Time) (relayframe.PartResult, error) {
	if p == nil {
		return relayframe.PartResult{}, errors.New("no room part store")
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	key := roomPartKey{sender: sender, digest: frame.ObjectDigest}
	split := frame.PartCount > 1 && frame.PartIndex < frame.PartCount && ids.Agent.MatchString(sender)
	// A part of a split object is stored before the Reassembler sees it, so
	// a part the Reassembler holds, or an object it completes, is never only
	// in memory: a store failure leaves the Reassembler unchanged and the
	// caller answers retry.
	wrote, conflict := false, false
	if split {
		// An object the Reassembler no longer holds (never held, dropped, or
		// past its lifetime, which Add would expire first) starts afresh: its
		// stale stored parts go, so a redelivered part is stored with this
		// arrival time and a restart does not replay it as expired.
		p.reassembler.Sweep(now)
		if _, settled := p.unsettled[key]; !settled && !p.reassembler.Holds(sender, frame.ObjectDigest) {
			if err := p.journal.removeRoomObjectParts(key); err != nil {
				return relayframe.PartResult{}, err
			}
		}
		var err error
		// A stored part with other bytes is never overwritten before the
		// Reassembler has judged the new one: refused, it must leave the
		// held part's copy in place.
		if wrote, conflict, err = p.journal.storeRoomPart(sender, frame, now, false); err != nil {
			return relayframe.PartResult{}, err
		}
	}
	result, err := p.reassembler.Add(sender, frame, now)
	if err != nil {
		if !split {
			return relayframe.PartResult{}, err
		}
		_, settled := p.unsettled[key]
		switch {
		case settled:
			// A complete object awaiting settlement keeps its parts.
		case !p.reassembler.Holds(sender, frame.ObjectDigest):
			// The object was dropped, or never held: none of it is kept.
			if removeErr := p.journal.removeRoomObjectParts(key); removeErr != nil {
				return relayframe.PartResult{}, removeErr
			}
		case wrote:
			// The object is still held without this part: only the part
			// just written goes.
			if removeErr := p.journal.removeRoomPartNames([]string{roomPartName(key, frame.PartIndex)}); removeErr != nil {
				return relayframe.PartResult{}, removeErr
			}
		}
		return relayframe.PartResult{}, err
	}
	if conflict {
		// Accepted although a stored copy differed (a stale record): the
		// Reassembler's view wins and is stored.
		if _, _, err := p.journal.storeRoomPart(sender, frame, now, true); err != nil {
			return relayframe.PartResult{}, err
		}
	}
	if result.Status == relayframe.PartComplete && split {
		p.unsettled[key] = now
	}
	return result, nil
}

// Settle deletes the stored parts of a complete object the caller has
// handled durably (applied, refused or dropped).
func (p *RoomParts) Settle(sender string, digest [sha256.Size]byte) error {
	if p == nil || !ids.Agent.MatchString(sender) {
		return errors.New("invalid room part settlement")
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	key := roomPartKey{sender: sender, digest: digest}
	if err := p.journal.removeRoomObjectParts(key); err != nil {
		return err
	}
	delete(p.unsettled, key)
	return nil
}

// Sweep drops every incomplete object past the lifetime and deletes its
// stored parts. It returns how many stored parts it deleted.
func (p *RoomParts) Sweep(now time.Time) (int, error) {
	if p == nil || now.IsZero() {
		return 0, errors.New("invalid room part sweep")
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.reassembler.Sweep(now)
	// A complete object the caller never settled is bounded too: after the
	// lifetime it is forgotten like an incomplete one.
	for key, completed := range p.unsettled {
		if now.Sub(completed) >= p.reassembler.Lifetime() {
			delete(p.unsettled, key)
		}
	}
	return p.deleteUnheld()
}

// DropSender drops every incomplete object of a sender, for example a
// removed member, with its stored parts, and forgets its unsettled ones.
func (p *RoomParts) DropSender(sender string) (int, error) {
	if p == nil || !ids.Agent.MatchString(sender) {
		return 0, errors.New("invalid room part sender")
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.reassembler.DropSender(sender)
	for key := range p.unsettled {
		if key.sender == sender {
			delete(p.unsettled, key)
		}
	}
	return p.deleteUnheld()
}

// Usage reports what the part store holds in memory: the Reassembler's
// incomplete objects and part bytes.
func (p *RoomParts) Usage() relayframe.Usage {
	if p == nil {
		return relayframe.Usage{}
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.reassembler.Usage()
}

// DropRoom drops the incomplete objects of a retired room from memory, and
// forgets its complete objects left unsettled; their stored parts are
// deleted. Retirement deletes the room's stored parts itself
// (deleteRoomPartsOf); this keeps the Reassembler, which holds them in
// memory, from completing an object of a room that is gone.
func (p *RoomParts) DropRoom(roomID string) (int, error) {
	if p == nil || !ids.Room.MatchString(roomID) {
		return 0, errors.New("invalid room part room")
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.reassembler.DropRoom(roomID)
	stored, _, err := p.journal.listRoomParts()
	if err != nil {
		return 0, err
	}
	roomHex := roomID[len("room_"):]
	for _, part := range stored {
		if part.frame.PartIndex == 0 && partNamesRoom(part.frame.Part, roomHex) {
			delete(p.unsettled, part.key)
		}
	}
	return p.deleteUnheld()
}

// ReplaceFirstPartEvidence keeps newer part-0 evidence (and card) of an
// incomplete object, in memory and in the stored part 0.
func (p *RoomParts) ReplaceFirstPartEvidence(sender string, digest [sha256.Size]byte, card, evidence []byte) error {
	if p == nil {
		return errors.New("no room part store")
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if err := p.reassembler.ReplaceFirstPartEvidence(sender, digest, card, evidence); err != nil {
		return err
	}
	return p.journal.replaceRoomPartEvidence(roomPartKey{sender: sender, digest: digest}, card, evidence)
}

// deleteUnheld deletes stored parts of objects the Reassembler no longer
// holds, except complete objects the caller has not settled. The mutex is
// held.
func (p *RoomParts) deleteUnheld() (int, error) {
	stored, damaged, err := p.journal.listRoomParts()
	if err != nil {
		return 0, err
	}
	names := append([]string(nil), damaged...)
	for _, part := range stored {
		if _, settled := p.unsettled[part.key]; settled {
			continue
		}
		if !p.reassembler.Holds(part.key.sender, part.key.digest) {
			names = append(names, part.name)
		}
	}
	if err := p.journal.removeRoomPartNames(names); err != nil {
		return 0, err
	}
	return len(names), nil
}

func roomPartName(key roomPartKey, index uint8) string {
	return fmt.Sprintf("%s-%s-%d.json", key.sender[len("agent_"):], hex.EncodeToString(key.digest[:]), index)
}

func parseRoomPartName(name string) (roomPartKey, uint8, bool) {
	stem, ok := strings.CutSuffix(name, ".json")
	if !ok {
		return roomPartKey{}, 0, false
	}
	fields := strings.Split(stem, "-")
	if len(fields) != 3 || !ids.Agent.MatchString("agent_"+fields[0]) || len(fields[1]) != 2*sha256.Size {
		return roomPartKey{}, 0, false
	}
	raw, err := hex.DecodeString(fields[1])
	if err != nil || hex.EncodeToString(raw) != fields[1] {
		return roomPartKey{}, 0, false
	}
	index, err := strconv.ParseUint(fields[2], 10, 8)
	if err != nil || index >= relayframe.MaxParts || strconv.FormatUint(index, 10) != fields[2] {
		return roomPartKey{}, 0, false
	}
	key := roomPartKey{sender: "agent_" + fields[0]}
	copy(key.digest[:], raw)
	return key, uint8(index), true
}

// storeRoomPart writes one part and reports whether it wrote, and whether
// a stored part with other bytes was found. An identical stored part is left
// as it is and a damaged one is replaced; a different valid one is replaced
// only when overwrite is set, and otherwise reported as a conflict.
func (j *Journal) storeRoomPart(sender string, frame relayframe.Frame, arrived time.Time, overwrite bool) (bool, bool, error) {
	if !ids.Agent.MatchString(sender) || frame.PartCount < 2 || frame.PartIndex >= frame.PartCount || arrived.IsZero() {
		return false, false, ErrRoomPartStore
	}
	key := roomPartKey{sender: sender, digest: frame.ObjectDigest}
	path := filepath.Join(j.root, roomPartDir, roomPartName(key, frame.PartIndex))
	j.mutex.Lock()
	defer j.mutex.Unlock()
	if existing, err := readRoomPart(path, filepath.Base(path)); err == nil {
		if bytes.Equal(existing.frame.Part, frame.Part) && existing.frame.PartCount == frame.PartCount {
			return false, false, nil
		}
		if !overwrite {
			return false, true, nil
		}
	}
	record := roomPartRecord{
		Schema: roomPartSchema, SenderAgentID: sender, ObjectDigest: hex.EncodeToString(frame.ObjectDigest[:]),
		PartIndex: frame.PartIndex, PartCount: frame.PartCount, ArrivedAtNano: arrived.UnixNano(),
		PartBase64: base64.StdEncoding.EncodeToString(frame.Part),
	}
	if frame.PartIndex == 0 {
		record.CardBase64 = base64.StdEncoding.EncodeToString(frame.Card)
		record.EvidenceBase64 = base64.StdEncoding.EncodeToString(frame.Evidence)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return false, false, ErrRoomPartStore
	}
	if err := j.replace(path, encoded); err != nil {
		return false, false, errors.Join(ErrRoomPartStore, err)
	}
	return true, false, nil
}

// replaceRoomPartEvidence rewrites the stored part 0 of an object with newer
// evidence and card, keeping its bytes and arrival time.
func (j *Journal) replaceRoomPartEvidence(key roomPartKey, card, evidence []byte) error {
	path := filepath.Join(j.root, roomPartDir, roomPartName(key, 0))
	j.mutex.Lock()
	defer j.mutex.Unlock()
	raw, err := readRecordBytes(path)
	if err != nil {
		return errors.Join(ErrRoomPartStore, err)
	}
	record, err := decodeRoomPartRecord(raw)
	if err != nil {
		return errors.Join(ErrRoomPartStore, err)
	}
	record.CardBase64 = base64.StdEncoding.EncodeToString(card)
	record.EvidenceBase64 = base64.StdEncoding.EncodeToString(evidence)
	if _, err := roomPartFrame(record); err != nil {
		return errors.Join(ErrRoomPartStore, err)
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return ErrRoomPartStore
	}
	return j.replace(path, encoded)
}

// listRoomParts reads every stored part. A record that does not decode, or
// does not match its name, is returned by name as damaged.
func (j *Journal) listRoomParts() ([]storedRoomPart, []string, error) {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	dir := filepath.Join(j.root, roomPartDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, errors.New("read room part store")
	}
	var parts []storedRoomPart
	var damaged []string
	for _, entry := range entries {
		name := entry.Name()
		if isTransitionTemp(name) {
			continue
		}
		if entry.IsDir() {
			return nil, nil, errors.New("unexpected directory in the room part store")
		}
		part, err := readRoomPart(filepath.Join(dir, name), name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			// A part that cannot be read is dropped like a refused one: its
			// sender re-deposits the whole object (section 4).
			damaged = append(damaged, name)
			continue
		}
		parts = append(parts, part)
	}
	return parts, damaged, nil
}

func readRoomPart(path, name string) (storedRoomPart, error) {
	key, index, ok := parseRoomPartName(name)
	if !ok {
		return storedRoomPart{}, errors.New("invalid room part name")
	}
	raw, err := readRecordBytes(path)
	if err != nil {
		return storedRoomPart{}, err
	}
	record, err := decodeRoomPartRecord(raw)
	if err != nil {
		return storedRoomPart{}, err
	}
	frame, err := roomPartFrame(record)
	if err != nil {
		return storedRoomPart{}, err
	}
	if record.SenderAgentID != key.sender || frame.ObjectDigest != key.digest || record.PartIndex != index {
		return storedRoomPart{}, errors.New("room part record does not match its name")
	}
	return storedRoomPart{name: name, key: key, arrived: time.Unix(0, record.ArrivedAtNano), frame: frame}, nil
}

func decodeRoomPartRecord(raw []byte) (roomPartRecord, error) {
	var record roomPartRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.Schema != roomPartSchema {
		return roomPartRecord{}, errors.New("invalid room part record")
	}
	return record, nil
}

// roomPartFrame rebuilds the frame of a record and checks its shape: a part
// of a split object, card and evidence in part 0 only, every field inside
// its frame bound.
func roomPartFrame(record roomPartRecord) (relayframe.Frame, error) {
	invalid := errors.New("invalid room part record")
	if !ids.Agent.MatchString(record.SenderAgentID) || record.PartCount < 2 || record.PartCount > relayframe.MaxParts ||
		record.PartIndex >= record.PartCount || record.ArrivedAtNano <= 0 {
		return relayframe.Frame{}, invalid
	}
	digest, err := hex.DecodeString(record.ObjectDigest)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != record.ObjectDigest {
		return relayframe.Frame{}, invalid
	}
	decode := func(value string, maximum int) ([]byte, error) {
		raw, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(raw) > maximum {
			return nil, invalid
		}
		return raw, nil
	}
	part, err := decode(record.PartBase64, relayframe.MaxPartBytes)
	if err != nil || len(part) == 0 {
		return relayframe.Frame{}, invalid
	}
	card, err := decode(record.CardBase64, relayframe.MaxCardBytes)
	if err != nil {
		return relayframe.Frame{}, err
	}
	evidence, err := decode(record.EvidenceBase64, relayframe.MaxEvidenceBytes)
	if err != nil {
		return relayframe.Frame{}, err
	}
	if record.PartIndex == 0 && len(evidence) == 0 || record.PartIndex != 0 && (len(card) != 0 || len(evidence) != 0) {
		return relayframe.Frame{}, invalid
	}
	frame := relayframe.Frame{Kind: relayframe.KindRoom, PartIndex: record.PartIndex, PartCount: record.PartCount,
		Card: card, Evidence: evidence, Part: part}
	copy(frame.ObjectDigest[:], digest)
	return frame, nil
}

// removeRoomObjectParts deletes every stored part of one object.
func (j *Journal) removeRoomObjectParts(key roomPartKey) error {
	names := make([]string, 0, relayframe.MaxParts)
	for index := uint8(0); index < relayframe.MaxParts; index++ {
		names = append(names, roomPartName(key, index))
	}
	return j.removeRoomPartNames(names)
}

// removeRoomPartNames deletes stored parts by name and syncs the directory
// once; a name already gone is no error.
func (j *Journal) removeRoomPartNames(names []string) error {
	if len(names) == 0 {
		return nil
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	dir := filepath.Join(j.root, roomPartDir)
	removed := false
	for _, name := range names {
		if filepath.Base(name) != name || isTransitionTemp(name) {
			return errors.New("invalid room part name")
		}
		err := os.Remove(filepath.Join(dir, name))
		if err == nil {
			removed = true
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return errors.New("delete room part")
		}
	}
	if removed {
		return syncDirectory(dir)
	}
	return nil
}
