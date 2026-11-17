package eventlog

// The authority's member chat cards (sections 11.1, 11.2, 11.8).
//
// A roster entry carries the member's chat card, and the authority builds
// every roster. The daemon keeps a member's card itself, taken from the
// part 0 of that member's own frames after admission: the joiner's
// room.key-package first, then any later frame whose card is newer. The
// caller checks only the card's shape, its Agent and its validity window;
// the card's signature is each receiving member's carrier's to verify when
// it admits the card (carrier.room-cards), so an unverifiable card is never
// used by anyone. One record per (room, member) of a room held here, for a
// current member or a pending add: at most 32 per room and 64 rooms. The
// records are per-room state, deleted with the room, and a removed member's
// is deleted with its credential.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/ids"
)

const (
	roomCardDir    = "room-member-cards"
	roomCardSchema = "tos.messaging.room-member-card.v1"
	// maxRoomCardBytes is the largest chat card a frame carries.
	maxRoomCardBytes = 9_216
)

// ErrRoomCardMember reports a card of an Agent that is neither a member of
// the room nor a pending add there.
var ErrRoomCardMember = errors.New("the card's Agent is no member or pending add of the room")

var errRoomCardValue = errors.New("invalid room member card record")

// RoomMemberCard is the stored chat card of one member of one room.
type RoomMemberCard struct {
	Schema     string `json:"schema"`
	RoomID     string `json:"room_id"`
	AgentID    string `json:"agent_id"`
	CardBase64 string `json:"card_base64"`
	// CreatedAtUnix and Sequence are the card packet's, which order cards:
	// a card is newer when it is later in that order.
	CreatedAtUnix uint64 `json:"created_at_unix"`
	Sequence      uint64 `json:"sequence"`
	// NotBeforeUnix and NotAfterUnix are the card's validity window.
	NotBeforeUnix uint64 `json:"not_before_unix"`
	NotAfterUnix  uint64 `json:"not_after_unix"`
	StoredAtUnix  uint64 `json:"stored_at_unix"`
}

// Card returns the card bytes.
func (c RoomMemberCard) Card() ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(c.CardBase64)
	if err != nil || len(raw) == 0 || len(raw) > maxRoomCardBytes {
		return nil, errRoomCardValue
	}
	return raw, nil
}

// Valid reports whether the card's window holds now.
func (c RoomMemberCard) Valid(now time.Time) bool {
	seconds := now.Unix()
	return seconds > 0 && uint64(seconds) >= c.NotBeforeUnix && uint64(seconds) < c.NotAfterUnix
}

// newerThan reports whether c is later than other in card order.
func (c RoomMemberCard) newerThan(other RoomMemberCard) bool {
	if c.CreatedAtUnix != other.CreatedAtUnix {
		return c.CreatedAtUnix > other.CreatedAtUnix
	}
	return c.Sequence > other.Sequence
}

// StoreRoomMemberCard keeps a member's card when the room holds no card of
// it yet or this one is newer. It reports whether it wrote. The Agent must
// be a member of the room or a live pending add there.
func (j *Journal) StoreRoomMemberCard(card RoomMemberCard, now time.Time) (bool, error) {
	if err := j.usable(); err != nil {
		return false, err
	}
	if now.IsZero() || now.Unix() <= 0 {
		return false, errors.New("invalid room card time")
	}
	card.Schema = roomCardSchema
	card.StoredAtUnix = uint64(now.Unix())
	if err := validateRoomCard(card); err != nil {
		return false, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	record, found, err := j.readRoomMLS(card.RoomID)
	if err != nil {
		return false, err
	}
	if !found {
		return false, ErrRoomNotJoined
	}
	if !containsString(record.Members, card.AgentID) {
		add, pending, err := j.readRoomAdd(card.RoomID, card.AgentID)
		if err != nil {
			return false, err
		}
		if !pending || uint64(now.Unix()) >= add.ExpiresAtUnix {
			return false, ErrRoomCardMember
		}
	}
	existing, held, err := j.readRoomCard(card.RoomID, card.AgentID)
	if err != nil {
		return false, err
	}
	if held && !card.newerThan(existing) {
		return false, nil
	}
	encoded, err := json.Marshal(card)
	if err != nil {
		return false, err
	}
	if err := j.replace(j.roomCardPath(card.RoomID, card.AgentID), encoded); err != nil {
		return false, err
	}
	return true, nil
}

// RoomMemberCardOf returns the stored card of a member, if any.
func (j *Journal) RoomMemberCardOf(roomID, agentID string) (RoomMemberCard, bool, error) {
	if err := j.usable(); err != nil {
		return RoomMemberCard{}, false, err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(agentID) {
		return RoomMemberCard{}, false, errors.New("invalid room card lookup")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.readRoomCard(roomID, agentID)
}

// ForgetRoomMemberCard deletes a member's card, with its credential, when
// the member is removed. Deleting a missing card is a no-op.
func (j *Journal) ForgetRoomMemberCard(roomID, agentID string) error {
	if err := j.usable(); err != nil {
		return err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(agentID) {
		return errors.New("invalid room card")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	path := j.roomCardPath(roomID, agentID)
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("delete room member card")
	}
	return syncDirectory(filepath.Dir(path))
}

func (j *Journal) roomCardPath(roomID, agentID string) string {
	return filepath.Join(j.root, roomCardDir, roomID[len("room_"):]+"-"+agentID[len("agent_"):]+".json")
}

func (j *Journal) readRoomCard(roomID, agentID string) (RoomMemberCard, bool, error) {
	raw, err := readRecordBytes(j.roomCardPath(roomID, agentID))
	if errors.Is(err, os.ErrNotExist) {
		return RoomMemberCard{}, false, nil
	}
	if err != nil {
		return RoomMemberCard{}, false, err
	}
	var card RoomMemberCard
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&card); err != nil || card.RoomID != roomID || card.AgentID != agentID {
		return RoomMemberCard{}, false, errRoomCardValue
	}
	if err := validateRoomCard(card); err != nil {
		return RoomMemberCard{}, false, err
	}
	return card, true, nil
}

func validateRoomCard(card RoomMemberCard) error {
	if card.Schema != roomCardSchema || !ids.Room.MatchString(card.RoomID) || !ids.Agent.MatchString(card.AgentID) ||
		card.CreatedAtUnix == 0 || card.Sequence == 0 || card.NotBeforeUnix == 0 || card.NotAfterUnix <= card.NotBeforeUnix ||
		card.StoredAtUnix == 0 {
		return errRoomCardValue
	}
	_, err := card.Card()
	return err
}
