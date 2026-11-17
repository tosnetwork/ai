package eventlog

// The application sender journal of a private room (sections 11.1, 11.7).
//
// A member seals a room message in its current epoch and deposits the one
// application object once to every other member of that epoch. Two records
// make that crash safe without touching the fused record:
//
//   - the room's sender state holds the last RoomMessage sequence this
//     installation used in the room and, while a seal is in progress, the
//     intent: the exact Event and the sequence reserved for it. Reserving is
//     one write, so a sequence is never used for two Events;
//   - the application record of one composition holds the sealed object, its
//     epochs, and one delivery state per member (pending, carried or
//     abandoned). Writing it is what ends the intent.
//
// A crash after the seal and before the application record loses only a
// ciphertext nobody received: the intent still holds the Event, which is
// sealed again under the same sequence (a later ratchet generation, the same
// Event ID). An intent whose room epoch has moved on is dropped instead, and
// its sequence becomes a gap at the receivers.
//
// The object is kept until AbandonAtUnix, at most a day after sealing (the
// largest relay TTL): a member not reached by then is abandoned, and only the
// digest and the states remain. Both records are per-room state, deleted
// with the room's other receive state when the room retires or is no longer
// held; neither names a chunk, so neither is a garbage-collection root.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
)

const (
	roomSendDir        = "room-send"
	roomApplicationDir = "room-application-outbox"

	roomSendSchema        = "tos.messaging.room-send.v1"
	roomApplicationSchema = "tos.messaging.room-application-send.v1"

	// MaxRoomApplicationRetention bounds how long an application object is
	// kept for deposit after sealing: the largest relay TTL of relay V1.
	MaxRoomApplicationRetention = 24 * time.Hour
	// MaxRoomApplicationSends bounds a room's application records. At the
	// bound the oldest record whose object was already dropped is deleted;
	// if every record still holds its object, a new seal is refused.
	MaxRoomApplicationSends = 4096
	// MaxRoomApplicationObjectBytes is the largest application object: it is
	// never split, so it fits part 0 of the production cut.
	MaxRoomApplicationObjectBytes = 162_744
	// maxRoomSealEventBytes bounds the stored Event of an intent: the room
	// plaintext bound.
	maxRoomSealEventBytes = 131_072
)

// maxRoomApplicationSends is MaxRoomApplicationSends; a test lowers it.
var maxRoomApplicationSends = MaxRoomApplicationSends

// Application sender refusals.
var (
	// ErrRoomSealPending reports a seal of another composition in progress.
	ErrRoomSealPending = errors.New("another room seal is in progress")
	// ErrRoomSequenceOrder reports a reserved sequence that does not follow
	// the last one used.
	ErrRoomSequenceOrder = errors.New("the room sequence does not follow the last one used")
	// ErrRoomSendsFull reports a room whose application records all still
	// hold their objects at the bound.
	ErrRoomSendsFull = errors.New("the room's application records reached their bound")
	errRoomSendValue = errors.New("invalid room application sender record")
)

// RoomSealIntent is a seal in progress: the Event and its reserved sequence.
type RoomSealIntent struct {
	IdempotencyKey string `json:"idempotency_key"`
	IntentDigest   string `json:"intent_digest"`
	EventID        string `json:"event_id"`
	EventBase64    string `json:"event_base64"`
	Sequence       uint64 `json:"sequence"`
	RoomEpoch      uint64 `json:"room_epoch"`
	ReservedAtUnix uint64 `json:"reserved_at_unix"`
}

// Event returns the intent's canonical Event JSON.
func (i RoomSealIntent) Event() ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(i.EventBase64)
	if err != nil || len(raw) == 0 || len(raw) > maxRoomSealEventBytes {
		return nil, errRoomSendValue
	}
	return raw, nil
}

type roomSendState struct {
	Schema       string          `json:"schema"`
	RoomID       string          `json:"room_id"`
	LastSequence uint64          `json:"last_sequence"`
	Sealing      *RoomSealIntent `json:"sealing,omitempty"`
}

// RoomApplicationMember is one member's delivery of an application object.
type RoomApplicationMember struct {
	AgentID           string            `json:"agent_id"`
	State             RoomDeliveryState `json:"state"`
	NextAttemptAtUnix uint64            `json:"next_attempt_at_unix,omitempty"`
	DepositedAtUnix   uint64            `json:"deposited_at_unix,omitempty"`
	EvidenceDigest    string            `json:"evidence_digest,omitempty"`
	Code              fault.Code        `json:"code,omitempty"`
}

// RoomApplicationSend is the record of one sealed application object.
type RoomApplicationSend struct {
	Schema         string `json:"schema"`
	RoomID         string `json:"room_id"`
	IdempotencyKey string `json:"idempotency_key"`
	IntentDigest   string `json:"intent_digest"`
	EventID        string `json:"event_id"`
	Sequence       uint64 `json:"sequence"`
	RoomEpoch      uint64 `json:"room_epoch"`
	MLSEpoch       uint64 `json:"mls_epoch"`
	ObjectDigest   string `json:"object_digest"`
	// ObjectBase64 is the object until AbandonAtUnix, then empty.
	ObjectBase64  string                  `json:"object_base64,omitempty"`
	SealedAtUnix  uint64                  `json:"sealed_at_unix"`
	AbandonAtUnix uint64                  `json:"abandon_at_unix"`
	Members       []RoomApplicationMember `json:"members"`
}

// Object returns the sealed object while it is kept.
func (s RoomApplicationSend) Object() ([]byte, bool, error) {
	if s.ObjectBase64 == "" {
		return nil, false, nil
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s.ObjectBase64)
	if err != nil || len(raw) == 0 || len(raw) > MaxRoomApplicationObjectBytes || RoomObjectDigest(raw) != s.ObjectDigest {
		return nil, false, errRoomSendValue
	}
	return raw, true, nil
}

// Pending reports whether any member still waits for its deposit.
func (s RoomApplicationSend) Pending() bool {
	for _, member := range s.Members {
		if member.State == RoomDeliveryPending {
			return true
		}
	}
	return false
}

// RoomSendState returns the last sequence used in a room and the seal in
// progress, if any.
func (j *Journal) RoomSendState(roomID string) (uint64, *RoomSealIntent, error) {
	if err := j.usable(); err != nil {
		return 0, nil, err
	}
	if !ids.Room.MatchString(roomID) {
		return 0, nil, errors.New("invalid room")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	state, err := j.readRoomSendState(roomID)
	if err != nil {
		return 0, nil, err
	}
	return state.LastSequence, state.Sealing, nil
}

// ReserveRoomSeal reserves the next sequence of a room for one Event, in one
// write, before the Event is sealed. The exact repeat of the reserved intent
// is a no-op; a different composition waits until the seal in progress is
// recorded or dropped.
func (j *Journal) ReserveRoomSeal(roomID string, intent RoomSealIntent) error {
	if err := j.usable(); err != nil {
		return err
	}
	if !ids.Room.MatchString(roomID) {
		return errors.New("invalid room")
	}
	if err := validateSealIntent(intent); err != nil {
		return err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	if _, found, err := j.readRoomMLS(roomID); err != nil {
		return err
	} else if !found {
		return ErrRoomNotJoined
	}
	state, err := j.readRoomSendState(roomID)
	if err != nil {
		return err
	}
	if state.Sealing != nil {
		if *state.Sealing == intent {
			return nil
		}
		return ErrRoomSealPending
	}
	if state.LastSequence == math.MaxUint64 || intent.Sequence != state.LastSequence+1 {
		return ErrRoomSequenceOrder
	}
	state.LastSequence = intent.Sequence
	state.Sealing = &intent
	return j.writeRoomSendState(state)
}

// DropRoomSealIntent ends a seal in progress that will not be completed,
// for example because the room epoch moved on. Its sequence stays used.
func (j *Journal) DropRoomSealIntent(roomID, idempotencyKey string) error {
	if err := j.usable(); err != nil {
		return err
	}
	if !ids.Room.MatchString(roomID) || !outboundIdempotencyPattern.MatchString(idempotencyKey) {
		return errors.New("invalid room seal")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	state, err := j.readRoomSendState(roomID)
	if err != nil {
		return err
	}
	if state.Sealing == nil || state.Sealing.IdempotencyKey != idempotencyKey {
		return nil
	}
	state.Sealing = nil
	return j.writeRoomSendState(state)
}

// RecordRoomApplicationSend writes the record of a sealed object and then
// ends the intent that reserved its sequence. Writing the same record again
// (a retry after a crash between the two writes) only ends the intent.
func (j *Journal) RecordRoomApplicationSend(send RoomApplicationSend) error {
	if err := j.usable(); err != nil {
		return err
	}
	if err := validateRoomApplicationSend(send); err != nil {
		return err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	state, err := j.readRoomSendState(send.RoomID)
	if err != nil {
		return err
	}
	existing, found, err := j.readRoomApplicationSend(send.RoomID, send.IdempotencyKey)
	if err != nil {
		return err
	}
	if found {
		if existing.ObjectDigest != send.ObjectDigest || existing.EventID != send.EventID {
			return ErrConflict
		}
	} else {
		if state.Sealing == nil || state.Sealing.IdempotencyKey != send.IdempotencyKey ||
			state.Sealing.Sequence != send.Sequence || state.Sealing.EventID != send.EventID {
			return errors.New("the application record matches no reserved seal")
		}
		if err := j.makeRoomApplicationSlot(send.RoomID); err != nil {
			return err
		}
		if err := j.writeRoomApplicationSend(send); err != nil {
			return err
		}
	}
	if state.Sealing != nil && state.Sealing.IdempotencyKey == send.IdempotencyKey {
		state.Sealing = nil
		return j.writeRoomSendState(state)
	}
	return nil
}

// RoomApplicationSendFor returns the record of one composition of a room.
func (j *Journal) RoomApplicationSendFor(roomID, idempotencyKey string) (RoomApplicationSend, bool, error) {
	if err := j.usable(); err != nil {
		return RoomApplicationSend{}, false, err
	}
	if !ids.Room.MatchString(roomID) || !outboundIdempotencyPattern.MatchString(idempotencyKey) {
		return RoomApplicationSend{}, false, errors.New("invalid room application lookup")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.readRoomApplicationSend(roomID, idempotencyKey)
}

// PendingRoomApplicationSends returns every application record of the
// installation with a member still pending, oldest first.
func (j *Journal) PendingRoomApplicationSends() ([]RoomApplicationSend, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	all, err := j.readRoomApplicationSends("")
	if err != nil {
		return nil, err
	}
	var pending []RoomApplicationSend
	for _, send := range all {
		if send.Pending() {
			pending = append(pending, send)
		}
	}
	return pending, nil
}

// RoomApplicationCarried records that a relay accepted the object for a
// pending member. A member already carried is a no-op.
func (j *Journal) RoomApplicationCarried(roomID, idempotencyKey, agentID, evidenceDigest string, now time.Time) (RoomApplicationSend, error) {
	if !canon.ValidDigest(evidenceDigest) {
		return RoomApplicationSend{}, errors.New("invalid room application evidence digest")
	}
	return j.updateRoomApplicationMember(roomID, idempotencyKey, agentID, now, func(member *RoomApplicationMember, seconds uint64) error {
		switch member.State {
		case RoomDeliveryCarried:
			return errRoomNoChange
		case RoomDeliveryPending:
		default:
			return ErrNotPending
		}
		member.State = RoomDeliveryCarried
		member.DepositedAtUnix = seconds
		member.EvidenceDigest = evidenceDigest
		member.NextAttemptAtUnix = 0
		return nil
	})
}

// RoomApplicationDeferred records when a pending member's deposit is tried
// again.
func (j *Journal) RoomApplicationDeferred(roomID, idempotencyKey, agentID string, until, now time.Time) (RoomApplicationSend, error) {
	if until.Unix() <= now.Unix() {
		return RoomApplicationSend{}, errors.New("invalid room application retry time")
	}
	return j.updateRoomApplicationMember(roomID, idempotencyKey, agentID, now, func(member *RoomApplicationMember, _ uint64) error {
		if member.State != RoomDeliveryPending {
			return ErrNotPending
		}
		member.NextAttemptAtUnix = uint64(until.Unix())
		return nil
	})
}

// RoomApplicationAbandoned settles a pending member that will not get the
// object, with the code that says why.
func (j *Journal) RoomApplicationAbandoned(roomID, idempotencyKey, agentID string, code fault.Code, now time.Time) (RoomApplicationSend, error) {
	if !fault.Known(code) {
		return RoomApplicationSend{}, errors.New("abandoning a room application object needs a known code")
	}
	return j.updateRoomApplicationMember(roomID, idempotencyKey, agentID, now, func(member *RoomApplicationMember, _ uint64) error {
		if member.State != RoomDeliveryPending {
			return ErrNotPending
		}
		member.State = RoomDeliveryAbandoned
		member.Code = code
		member.NextAttemptAtUnix = 0
		return nil
	})
}

// SweepRoomApplicationSends abandons, at AbandonAtUnix, every member still
// pending and drops the object, keeping the digest and the states. It
// reports how many members it abandoned.
func (j *Journal) SweepRoomApplicationSends(now time.Time) (int, error) {
	if err := j.usable(); err != nil {
		return 0, err
	}
	if now.IsZero() || now.Unix() <= 0 {
		return 0, errors.New("invalid room application sweep time")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	all, err := j.readRoomApplicationSends("")
	if err != nil {
		return 0, err
	}
	abandoned := 0
	for _, send := range all {
		if send.ObjectBase64 == "" || uint64(now.Unix()) < send.AbandonAtUnix {
			continue
		}
		for index := range send.Members {
			if send.Members[index].State == RoomDeliveryPending {
				send.Members[index].State = RoomDeliveryAbandoned
				send.Members[index].Code = fault.CodeRetentionExceeded
				send.Members[index].NextAttemptAtUnix = 0
				abandoned++
			}
		}
		send.ObjectBase64 = ""
		if err := j.writeRoomApplicationSend(send); err != nil {
			return abandoned, err
		}
	}
	return abandoned, nil
}

// updateRoomApplicationMember applies one member transition.
func (j *Journal) updateRoomApplicationMember(roomID, idempotencyKey, agentID string, now time.Time,
	change func(*RoomApplicationMember, uint64) error) (RoomApplicationSend, error) {
	if err := j.usable(); err != nil {
		return RoomApplicationSend{}, err
	}
	if !ids.Room.MatchString(roomID) || !outboundIdempotencyPattern.MatchString(idempotencyKey) ||
		!ids.Agent.MatchString(agentID) || now.IsZero() || now.Unix() <= 0 {
		return RoomApplicationSend{}, errors.New("invalid room application member")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	send, found, err := j.readRoomApplicationSend(roomID, idempotencyKey)
	if err != nil {
		return RoomApplicationSend{}, err
	}
	if !found {
		return RoomApplicationSend{}, ErrUnknown
	}
	index := -1
	for i := range send.Members {
		if send.Members[i].AgentID == agentID {
			index = i
		}
	}
	if index < 0 {
		return RoomApplicationSend{}, errors.New("room application object is not addressed to this member")
	}
	if err := change(&send.Members[index], uint64(now.Unix())); err != nil {
		if errors.Is(err, errRoomNoChange) {
			return send, nil
		}
		return RoomApplicationSend{}, err
	}
	if err := j.writeRoomApplicationSend(send); err != nil {
		return RoomApplicationSend{}, err
	}
	return send, nil
}

// makeRoomApplicationSlot keeps a room under MaxRoomApplicationSends: at the
// bound the oldest record without an object is deleted. The journal mutex
// is held.
func (j *Journal) makeRoomApplicationSlot(roomID string) error {
	all, err := j.readRoomApplicationSends(roomID)
	if err != nil {
		return err
	}
	if len(all) < maxRoomApplicationSends {
		return nil
	}
	for _, send := range all {
		if send.ObjectBase64 == "" {
			path := j.roomApplicationPath(send.RoomID, send.IdempotencyKey)
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return errors.New("delete room application record")
			}
			return syncDirectory(filepath.Dir(path))
		}
	}
	return ErrRoomSendsFull
}

func (j *Journal) roomSendPath(roomID string) string {
	return filepath.Join(j.root, roomSendDir, roomID[len("room_"):]+".json")
}

// roomApplicationPath names a composition by a digest of its room and
// idempotency key, so a lookup never scans the room's records.
func (j *Journal) roomApplicationPath(roomID, idempotencyKey string) string {
	sum := sha256.Sum256([]byte(roomID + "\x00" + idempotencyKey))
	return filepath.Join(j.root, roomApplicationDir, roomID[len("room_"):]+"-"+hex.EncodeToString(sum[:])+".json")
}

func (j *Journal) readRoomSendState(roomID string) (roomSendState, error) {
	empty := roomSendState{Schema: roomSendSchema, RoomID: roomID}
	raw, err := readRecordBytes(j.roomSendPath(roomID))
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return roomSendState{}, err
	}
	var state roomSendState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || state.Schema != roomSendSchema || state.RoomID != roomID {
		return roomSendState{}, errRoomSendValue
	}
	if state.Sealing != nil {
		if err := validateSealIntent(*state.Sealing); err != nil || state.Sealing.Sequence != state.LastSequence {
			return roomSendState{}, errRoomSendValue
		}
	}
	return state, nil
}

func (j *Journal) writeRoomSendState(state roomSendState) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return j.replace(j.roomSendPath(state.RoomID), encoded)
}

func (j *Journal) readRoomApplicationSend(roomID, idempotencyKey string) (RoomApplicationSend, bool, error) {
	raw, err := readRecordBytes(j.roomApplicationPath(roomID, idempotencyKey))
	if errors.Is(err, os.ErrNotExist) {
		return RoomApplicationSend{}, false, nil
	}
	if err != nil {
		return RoomApplicationSend{}, false, err
	}
	send, err := decodeRoomApplicationSend(raw)
	if err != nil || send.RoomID != roomID || send.IdempotencyKey != idempotencyKey {
		return RoomApplicationSend{}, false, errRoomSendValue
	}
	return send, true, nil
}

// readRoomApplicationSends reads the records of one room, or of every room
// for an empty roomID, oldest first. The journal mutex is held.
func (j *Journal) readRoomApplicationSends(roomID string) ([]RoomApplicationSend, error) {
	dir := filepath.Join(j.root, roomApplicationDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, errors.New("read room application records")
	}
	prefix := ""
	if roomID != "" {
		prefix = roomID[len("room_"):] + "-"
	}
	var sends []RoomApplicationSend
	for _, entry := range entries {
		name := entry.Name()
		if isTransitionTemp(name) || !strings.HasPrefix(name, prefix) {
			continue
		}
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			return nil, errors.New("unexpected entry in the room application records")
		}
		raw, err := readRecordBytes(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		send, err := decodeRoomApplicationSend(raw)
		if err != nil || filepath.Base(j.roomApplicationPath(send.RoomID, send.IdempotencyKey)) != name {
			return nil, errRoomSendValue
		}
		sends = append(sends, send)
	}
	sort.SliceStable(sends, func(a, b int) bool {
		if sends[a].SealedAtUnix != sends[b].SealedAtUnix {
			return sends[a].SealedAtUnix < sends[b].SealedAtUnix
		}
		return sends[a].ObjectDigest < sends[b].ObjectDigest
	})
	return sends, nil
}

func decodeRoomApplicationSend(raw []byte) (RoomApplicationSend, error) {
	var send RoomApplicationSend
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&send); err != nil {
		return RoomApplicationSend{}, errRoomSendValue
	}
	if err := validateRoomApplicationSend(send); err != nil {
		return RoomApplicationSend{}, err
	}
	return send, nil
}

func (j *Journal) writeRoomApplicationSend(send RoomApplicationSend) error {
	if err := validateRoomApplicationSend(send); err != nil {
		return err
	}
	encoded, err := json.Marshal(send)
	if err != nil {
		return err
	}
	return j.replace(j.roomApplicationPath(send.RoomID, send.IdempotencyKey), encoded)
}

func validateSealIntent(intent RoomSealIntent) error {
	if !outboundIdempotencyPattern.MatchString(intent.IdempotencyKey) || !canon.ValidDigest(intent.IntentDigest) ||
		!ids.Event.MatchString(intent.EventID) || intent.Sequence == 0 || intent.RoomEpoch == 0 || intent.ReservedAtUnix == 0 {
		return errRoomSendValue
	}
	_, err := intent.Event()
	return err
}

func validateRoomApplicationSend(send RoomApplicationSend) error {
	if send.Schema != roomApplicationSchema || !ids.Room.MatchString(send.RoomID) ||
		!outboundIdempotencyPattern.MatchString(send.IdempotencyKey) || !canon.ValidDigest(send.IntentDigest) ||
		!ids.Event.MatchString(send.EventID) || send.Sequence == 0 || send.RoomEpoch == 0 ||
		!validObjectDigest(send.ObjectDigest) || send.SealedAtUnix == 0 || send.AbandonAtUnix <= send.SealedAtUnix ||
		send.AbandonAtUnix-send.SealedAtUnix > uint64(MaxRoomApplicationRetention/time.Second) {
		return errRoomSendValue
	}
	if _, _, err := send.Object(); err != nil {
		return err
	}
	if len(send.Members) == 0 || len(send.Members) >= group.MaxPrivateRoomAgents {
		return errRoomSendValue
	}
	seen := make(map[string]struct{}, len(send.Members))
	for _, member := range send.Members {
		if !ids.Agent.MatchString(member.AgentID) {
			return errRoomSendValue
		}
		if _, duplicate := seen[member.AgentID]; duplicate {
			return errRoomSendValue
		}
		seen[member.AgentID] = struct{}{}
		switch member.State {
		case RoomDeliveryPending:
			if member.DepositedAtUnix != 0 || member.EvidenceDigest != "" || member.Code != "" {
				return errRoomSendValue
			}
		case RoomDeliveryCarried:
			if member.DepositedAtUnix == 0 || !canon.ValidDigest(member.EvidenceDigest) || member.Code != "" ||
				member.NextAttemptAtUnix != 0 {
				return errRoomSendValue
			}
		case RoomDeliveryAbandoned:
			if !fault.Known(member.Code) || member.NextAttemptAtUnix != 0 {
				return errRoomSendValue
			}
		default:
			return errRoomSendValue
		}
	}
	return nil
}

// NewRoomApplicationSend builds the record of a freshly sealed object
// addressed to the given members, every one pending.
func NewRoomApplicationSend(roomID string, intent RoomSealIntent, mlsEpoch uint64, object []byte, members []string,
	sealed, abandonAt time.Time) (RoomApplicationSend, error) {
	if len(object) == 0 || len(object) > MaxRoomApplicationObjectBytes {
		return RoomApplicationSend{}, errors.New("invalid room application object")
	}
	sorted := append([]string(nil), members...)
	sort.Strings(sorted)
	deliveries := make([]RoomApplicationMember, 0, len(sorted))
	for _, agentID := range sorted {
		deliveries = append(deliveries, RoomApplicationMember{AgentID: agentID, State: RoomDeliveryPending})
	}
	send := RoomApplicationSend{Schema: roomApplicationSchema, RoomID: roomID, IdempotencyKey: intent.IdempotencyKey,
		IntentDigest: intent.IntentDigest, EventID: intent.EventID, Sequence: intent.Sequence, RoomEpoch: intent.RoomEpoch,
		MLSEpoch: mlsEpoch, ObjectDigest: RoomObjectDigest(object), ObjectBase64: base64.StdEncoding.EncodeToString(object),
		SealedAtUnix: uint64(sealed.Unix()), AbandonAtUnix: uint64(abandonAt.Unix()), Members: deliveries}
	if err := validateRoomApplicationSend(send); err != nil {
		return RoomApplicationSend{}, err
	}
	return send, nil
}
