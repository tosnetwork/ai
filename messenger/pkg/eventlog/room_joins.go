package eventlog

// Pending joins of private rooms (section 11.2).
//
// A room.invite from a room's authority, received over the 1:1 session,
// records a pending join keyed by (room, authority), so invites for one room
// from several Agents coexist and a stranger's invite cannot pre-empt the
// real authority's. An invite lives at most 7 days, and one Agent holds at
// most 8 pending joins, so no sender can fill the list. The owner's
// rooms.join names the authority it accepts; accepting one discards the
// others for that room. When the owner calls
// rooms.join, the daemon makes an MLS identity and one-time KeyPackage,
// stages the identity's private state here (as state chunks, so its size
// never pushes a record past its bound) and records the KeyPackage
// reference and the Endpoint-signed DeviceCredential it sends back as
// room.key-package. Only that authority's Welcome is accepted for the room,
// and only while the join is pending. Installing the Welcome consumes the
// KeyPackage in the fused record; the join then ends.
//
// The record names staged identity chunks, so every pending join is a
// garbage-collection root (room_gc.go). A join whose KeyPackage a fused
// record already consumed (a crash between the install and FinishRoomJoin)
// is ended by the next read.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/payload"
)

const (
	roomJoinDir    = "room-joins"
	roomJoinSchema = "tos.messaging.room-join.v1"
	// MaxPendingRoomJoins bounds the invites this installation holds and has
	// not yet joined.
	MaxPendingRoomJoins = 64
	// MaxPendingRoomJoinsPerAuthority bounds one inviting Agent's share.
	MaxPendingRoomJoinsPerAuthority = 8
	// MaxRoomInviteLifetime bounds how long a pending invite is kept.
	MaxRoomInviteLifetime = payload.MaxRoomInviteLifetimeSeconds * time.Second
	// MaxRoomJoinCredentialBytes bounds the stored DeviceCredential JSON.
	MaxRoomJoinCredentialBytes = 96 << 10
)

// PendingJoinState is how far a pending join has got.
type PendingJoinState string

const (
	// JoinInvited: a room.invite arrived; the owner has not joined.
	JoinInvited PendingJoinState = "invited"
	// JoinKeyPackageSent: the owner joined; the KeyPackage went to the
	// authority and its Welcome is awaited.
	JoinKeyPackageSent PendingJoinState = "key-package-sent"
)

// Pending join refusals.
var (
	ErrRoomAlreadyJoined   = errors.New("this installation already holds the room")
	ErrRoomJoinConflict    = errors.New("the room's pending join names another authority or KeyPackage")
	ErrRoomJoinsFull       = errors.New("pending room joins reached their bound")
	ErrRoomJoinsShareFull  = errors.New("the inviting Agent holds the most pending room joins")
	ErrRoomJoinUnknown     = errors.New("no pending join for the room")
	ErrRoomJoinExpired     = errors.New("the room invite has expired")
	ErrRoomJoinNotInvited  = errors.New("the room's pending join is not awaiting the owner")
	ErrRoomJoinKeyPackage  = errors.New("the stored DeviceCredential does not name the KeyPackage")
	errRoomJoinRecordValue = errors.New("invalid pending room join record")
)

// PendingRoomJoin is one room this installation was invited to.
type PendingRoomJoin struct {
	Schema              string           `json:"schema"`
	RoomID              string           `json:"room_id"`
	AuthorityAgentID    string           `json:"authority_agent_id"`
	InviteEventID       string           `json:"invite_event_id"`
	InviteExpiresAtUnix uint64           `json:"invite_expires_at_unix"`
	InvitedAtUnix       uint64           `json:"invited_at_unix"`
	State               PendingJoinState `json:"state"`
	KeyPackageRef       string           `json:"key_package_ref,omitempty"`
	IdentityStateDigest string           `json:"identity_state_digest,omitempty"`
	IdentityStateChunks []string         `json:"identity_state_chunk_digests,omitempty"`
	CredentialBase64    string           `json:"device_credential_base64,omitempty"`
	CredentialExpiresAt uint64           `json:"credential_expires_at_unix,omitempty"`
	JoinedAtUnix        uint64           `json:"joined_at_unix,omitempty"`
}

// Credential returns the DeviceCredential a joined pending join sent.
func (p PendingRoomJoin) Credential() (group.DeviceCredential, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(p.CredentialBase64)
	if err != nil || len(raw) == 0 || len(raw) > MaxRoomJoinCredentialBytes {
		return group.DeviceCredential{}, errRoomJoinRecordValue
	}
	return group.DecodeDeviceCredentialJSON(raw)
}

// expiresAt is when the pending join is dropped: the invite's expiry while
// the owner has not joined, the credential's once the KeyPackage was sent
// (the authority may deliver the Welcome late, within its retention).
func (p PendingRoomJoin) expiresAt() uint64 {
	if p.State == JoinKeyPackageSent {
		return p.CredentialExpiresAt
	}
	return p.InviteExpiresAtUnix
}

// RecordRoomInvite records a room.invite from an Agent naming itself the
// room's authority. A later invite from the same Agent for the same room
// refreshes an unjoined one. Once the owner accepted one authority's invite,
// invites from others for that room are refused.
func (j *Journal) RecordRoomInvite(roomID, authorityAgentID, inviteEventID string, expires, now time.Time) (PendingRoomJoin, error) {
	if err := j.usable(); err != nil {
		return PendingRoomJoin{}, err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(authorityAgentID) || !ids.Event.MatchString(inviteEventID) ||
		now.IsZero() || now.Unix() <= 0 || !expires.After(now) || expires.Sub(now) > MaxRoomInviteLifetime {
		return PendingRoomJoin{}, errors.New("invalid room invite")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	if _, found, err := j.readRoomMLS(roomID); err != nil {
		return PendingRoomJoin{}, err
	} else if found {
		return PendingRoomJoin{}, ErrRoomAlreadyJoined
	}
	if err := j.sweepRoomJoins(now); err != nil {
		return PendingRoomJoin{}, err
	}
	if accepted, found, err := j.acceptedRoomJoin(roomID); err != nil {
		return PendingRoomJoin{}, err
	} else if found {
		if accepted.AuthorityAgentID != authorityAgentID {
			return PendingRoomJoin{}, ErrRoomJoinConflict
		}
		return accepted, nil
	}
	_, found, err := j.readRoomJoin(roomID, authorityAgentID)
	if err != nil {
		return PendingRoomJoin{}, err
	}
	if !found {
		keys, err := j.roomJoinKeys()
		if err != nil {
			return PendingRoomJoin{}, err
		}
		share := 0
		for _, key := range keys {
			if key.authority == authorityAgentID {
				share++
			}
		}
		if share >= MaxPendingRoomJoinsPerAuthority {
			return PendingRoomJoin{}, ErrRoomJoinsShareFull
		}
		if len(keys) >= MaxPendingRoomJoins {
			return PendingRoomJoin{}, ErrRoomJoinsFull
		}
	}
	join := PendingRoomJoin{Schema: roomJoinSchema, RoomID: roomID, AuthorityAgentID: authorityAgentID,
		InviteEventID: inviteEventID, InviteExpiresAtUnix: uint64(expires.Unix()), InvitedAtUnix: uint64(now.Unix()),
		State: JoinInvited}
	return join, j.writeRoomJoin(join)
}

// BeginRoomJoin records the owner's acceptance of one authority's invite:
// the identity's private state (staged as chunks first), the KeyPackage
// reference and the signed DeviceCredential sent as room.key-package. The
// record write is the commit point; the room's other invites are then
// discarded. A repeat with the same KeyPackage is a no-op.
func (j *Journal) BeginRoomJoin(roomID, authorityAgentID string, identityState []byte, credentialJSON []byte, now time.Time) (PendingRoomJoin, error) {
	if err := j.usable(); err != nil {
		return PendingRoomJoin{}, err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(authorityAgentID) || now.IsZero() || now.Unix() <= 0 {
		return PendingRoomJoin{}, errors.New("invalid room join")
	}
	if err := validateOpaqueMLS(identityState); err != nil {
		return PendingRoomJoin{}, err
	}
	if len(credentialJSON) == 0 || len(credentialJSON) > MaxRoomJoinCredentialBytes {
		return PendingRoomJoin{}, errors.New("invalid room join credential")
	}
	credential, err := group.DecodeDeviceCredentialJSON(credentialJSON)
	if err != nil {
		return PendingRoomJoin{}, err
	}
	ref, err := group.KeyPackageRef(credential)
	if err != nil {
		return PendingRoomJoin{}, err
	}
	if uint64(now.Unix()) < credential.IssuedAtUnix || uint64(now.Unix()) >= credential.ExpiresAtUnix {
		return PendingRoomJoin{}, errors.New("the room join credential is outside its validity window")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	if _, found, err := j.readRoomMLS(roomID); err != nil {
		return PendingRoomJoin{}, err
	} else if found {
		return PendingRoomJoin{}, ErrRoomAlreadyJoined
	}
	if accepted, found, err := j.acceptedRoomJoin(roomID); err != nil {
		return PendingRoomJoin{}, err
	} else if found {
		if accepted.AuthorityAgentID == authorityAgentID && accepted.KeyPackageRef == ref {
			return accepted, j.discardOtherRoomJoins(roomID, authorityAgentID)
		}
		return PendingRoomJoin{}, ErrRoomJoinConflict
	}
	join, found, err := j.readRoomJoin(roomID, authorityAgentID)
	if err != nil {
		return PendingRoomJoin{}, err
	}
	if !found {
		return PendingRoomJoin{}, ErrRoomJoinUnknown
	}
	if uint64(now.Unix()) >= join.InviteExpiresAtUnix {
		return PendingRoomJoin{}, ErrRoomJoinExpired
	}
	consumed, err := (&RoomMLSLedger{journal: j}).keyPackageConsumed(ref)
	if err != nil {
		return PendingRoomJoin{}, err
	}
	if consumed {
		return PendingRoomJoin{}, ErrKeyPackageConsumed
	}
	if held, err := j.roomsHeld(roomID); err != nil {
		return PendingRoomJoin{}, err
	} else if held >= MaxRoomsHeld {
		return PendingRoomJoin{}, ErrRoomsFull
	}
	chunks, err := j.stageMLSState(roomID, identityState)
	if err != nil {
		return PendingRoomJoin{}, err
	}
	join.State = JoinKeyPackageSent
	join.KeyPackageRef = ref
	join.IdentityStateDigest = canon.Digest(identityState)
	join.IdentityStateChunks = chunks
	join.CredentialBase64 = base64.StdEncoding.EncodeToString(credentialJSON)
	join.CredentialExpiresAt = credential.ExpiresAtUnix
	join.JoinedAtUnix = uint64(now.Unix())
	if err := j.writeRoomJoin(join); err != nil {
		return PendingRoomJoin{}, err
	}
	return join, j.discardOtherRoomJoins(roomID, authorityAgentID)
}

// PendingRoomJoinFor returns the live pending join of one room and
// authority. An expired join is dropped; one whose KeyPackage a fused record
// consumed has ended.
func (j *Journal) PendingRoomJoinFor(roomID, authorityAgentID string, now time.Time) (PendingRoomJoin, bool, error) {
	if err := j.usable(); err != nil {
		return PendingRoomJoin{}, false, err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(authorityAgentID) || now.IsZero() {
		return PendingRoomJoin{}, false, errors.New("invalid pending room join lookup")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.liveRoomJoin(roomID, authorityAgentID, now)
}

// AcceptedRoomJoin returns the room's live join the owner accepted: the only
// authority whose Welcome is taken for the room.
func (j *Journal) AcceptedRoomJoin(roomID string, now time.Time) (PendingRoomJoin, bool, error) {
	if err := j.usable(); err != nil {
		return PendingRoomJoin{}, false, err
	}
	if !ids.Room.MatchString(roomID) || now.IsZero() {
		return PendingRoomJoin{}, false, errors.New("invalid accepted room join lookup")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	accepted, found, err := j.acceptedRoomJoin(roomID)
	if err != nil || !found {
		return PendingRoomJoin{}, false, err
	}
	return j.liveRoomJoin(roomID, accepted.AuthorityAgentID, now)
}

// RoomJoinIdentityState reassembles the identity state an accepted join
// staged, verifying every chunk and the state digest.
func (j *Journal) RoomJoinIdentityState(join PendingRoomJoin) ([]byte, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	if join.State != JoinKeyPackageSent {
		return nil, ErrRoomJoinNotInvited
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.loadMLSState(join.RoomID, join.IdentityStateDigest, join.IdentityStateChunks)
}

// FinishRoomJoin ends a room's joins once the accepted one's Welcome is
// installed. It is refused unless the fused record consumed that join's
// KeyPackage, so a join is never ended by anything but its own Welcome. A
// room with no joins left is no error.
func (j *Journal) FinishRoomJoin(roomID string) error {
	if err := j.usable(); err != nil {
		return err
	}
	if !ids.Room.MatchString(roomID) {
		return errors.New("invalid room")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	accepted, found, err := j.acceptedRoomJoin(roomID)
	if err != nil || !found {
		return err
	}
	fused, joined, err := j.readRoomMLS(roomID)
	if err != nil {
		return err
	}
	if !joined || accepted.KeyPackageRef == "" || fused.KeyPackageRef != accepted.KeyPackageRef {
		return errors.New("the room's Welcome has not been installed")
	}
	keys, err := j.roomJoinKeys()
	if err != nil {
		return err
	}
	for _, key := range keys {
		if key.room != roomID {
			continue
		}
		join, found, err := j.readRoomJoin(key.room, key.authority)
		if err != nil {
			return err
		}
		if found {
			if err := j.deleteRoomJoin(join, fused.StateChunks); err != nil {
				return err
			}
		}
	}
	return nil
}

// ListPendingRoomJoins returns every live pending join, by room and
// authority.
func (j *Journal) ListPendingRoomJoins(now time.Time) ([]PendingRoomJoin, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, errors.New("invalid pending room join listing")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	if err := j.sweepRoomJoins(now); err != nil {
		return nil, err
	}
	keys, err := j.roomJoinKeys()
	if err != nil {
		return nil, err
	}
	joins := make([]PendingRoomJoin, 0, len(keys))
	for _, key := range keys {
		join, found, err := j.readRoomJoin(key.room, key.authority)
		if err != nil {
			return nil, err
		}
		if found {
			joins = append(joins, join)
		}
	}
	return joins, nil
}

// SweepRoomJoins drops every expired, ended or superseded pending join.
func (j *Journal) SweepRoomJoins(now time.Time) error {
	if err := j.usable(); err != nil {
		return err
	}
	if now.IsZero() {
		return errors.New("invalid pending room join sweep")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.sweepRoomJoins(now)
}

func (j *Journal) sweepRoomJoins(now time.Time) error {
	keys, err := j.roomJoinKeys()
	if err != nil {
		return err
	}
	for _, key := range keys {
		if _, _, err := j.liveRoomJoin(key.room, key.authority, now); err != nil {
			return err
		}
	}
	return nil
}

// liveRoomJoin reads a join and ends it if it expired, its KeyPackage was
// consumed (the room is joined), or the owner accepted another authority's
// invite for the room. The journal mutex is held.
func (j *Journal) liveRoomJoin(roomID, authorityAgentID string, now time.Time) (PendingRoomJoin, bool, error) {
	join, found, err := j.readRoomJoin(roomID, authorityAgentID)
	if err != nil || !found {
		return PendingRoomJoin{}, false, err
	}
	fused, joined, err := j.readRoomMLS(roomID)
	if err != nil {
		return PendingRoomJoin{}, false, err
	}
	var keep []string
	if joined {
		keep = fused.StateChunks
	}
	superseded := false
	if join.State == JoinInvited {
		accepted, found, err := j.acceptedRoomJoin(roomID)
		if err != nil {
			return PendingRoomJoin{}, false, err
		}
		superseded = found && accepted.AuthorityAgentID != authorityAgentID
	}
	if joined || superseded || now.Unix() < 0 || uint64(now.Unix()) >= join.expiresAt() {
		return PendingRoomJoin{}, false, j.deleteRoomJoin(join, keep)
	}
	return join, true, nil
}

// acceptedRoomJoin returns the room's key-package-sent join, if any. The
// journal mutex is held.
func (j *Journal) acceptedRoomJoin(roomID string) (PendingRoomJoin, bool, error) {
	keys, err := j.roomJoinKeys()
	if err != nil {
		return PendingRoomJoin{}, false, err
	}
	for _, key := range keys {
		if key.room != roomID {
			continue
		}
		join, found, err := j.readRoomJoin(key.room, key.authority)
		if err != nil {
			return PendingRoomJoin{}, false, err
		}
		if found && join.State == JoinKeyPackageSent {
			return join, true, nil
		}
	}
	return PendingRoomJoin{}, false, nil
}

// discardOtherRoomJoins drops the room's invites from every authority but
// the accepted one. The journal mutex is held.
func (j *Journal) discardOtherRoomJoins(roomID, accepted string) error {
	keys, err := j.roomJoinKeys()
	if err != nil {
		return err
	}
	for _, key := range keys {
		if key.room != roomID || key.authority == accepted {
			continue
		}
		join, found, err := j.readRoomJoin(key.room, key.authority)
		if err != nil {
			return err
		}
		if found {
			if err := j.deleteRoomJoin(join, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// deleteRoomJoin removes a join record, then the identity chunks it named
// that the room's fused state does not share. A chunk left by a crash is
// collected at restart. The journal mutex is held.
func (j *Journal) deleteRoomJoin(join PendingRoomJoin, keep []string) error {
	path := j.roomJoinPath(join.RoomID, join.AuthorityAgentID)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("delete pending room join")
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	j.deleteSupersededState(join.RoomID, join.IdentityStateChunks, keep)
	return nil
}

type roomJoinKey struct{ room, authority string }

func (j *Journal) roomJoinPath(roomID, authorityAgentID string) string {
	return filepath.Join(j.root, roomJoinDir, roomID[len("room_"):]+"-"+authorityAgentID[len("agent_"):]+".json")
}

// roomJoinKeys lists the pending joins by (room, authority), refusing any
// name that is not one.
func (j *Journal) roomJoinKeys() ([]roomJoinKey, error) {
	entries, err := os.ReadDir(filepath.Join(j.root, roomJoinDir))
	if err != nil {
		return nil, errors.New("read pending room joins")
	}
	var keys []roomJoinKey
	for _, entry := range entries {
		name := entry.Name()
		if isTransitionTemp(name) {
			continue
		}
		stem, ok := strings.CutSuffix(name, ".json")
		roomHex, authorityHex, cut := strings.Cut(stem, "-")
		if !ok || !cut || entry.IsDir() || !ids.Room.MatchString("room_"+roomHex) || !ids.Agent.MatchString("agent_"+authorityHex) {
			return nil, errors.New("unexpected entry in the pending room joins")
		}
		keys = append(keys, roomJoinKey{room: "room_" + roomHex, authority: "agent_" + authorityHex})
	}
	sort.Slice(keys, func(a, b int) bool {
		if keys[a].room != keys[b].room {
			return keys[a].room < keys[b].room
		}
		return keys[a].authority < keys[b].authority
	})
	return keys, nil
}

func (j *Journal) readRoomJoin(roomID, authorityAgentID string) (PendingRoomJoin, bool, error) {
	raw, err := readRecordBytes(j.roomJoinPath(roomID, authorityAgentID))
	if errors.Is(err, os.ErrNotExist) {
		return PendingRoomJoin{}, false, nil
	}
	if err != nil {
		return PendingRoomJoin{}, false, err
	}
	var join PendingRoomJoin
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&join); err != nil || join.RoomID != roomID || join.AuthorityAgentID != authorityAgentID {
		return PendingRoomJoin{}, false, errRoomJoinRecordValue
	}
	if err := validateRoomJoin(join); err != nil {
		return PendingRoomJoin{}, false, err
	}
	return join, true, nil
}

func validateRoomJoin(join PendingRoomJoin) error {
	if join.Schema != roomJoinSchema || !ids.Room.MatchString(join.RoomID) || !ids.Agent.MatchString(join.AuthorityAgentID) ||
		!ids.Event.MatchString(join.InviteEventID) || join.InvitedAtUnix == 0 || join.InviteExpiresAtUnix <= join.InvitedAtUnix ||
		join.InviteExpiresAtUnix-join.InvitedAtUnix > payload.MaxRoomInviteLifetimeSeconds {
		return errRoomJoinRecordValue
	}
	switch join.State {
	case JoinInvited:
		if join.KeyPackageRef != "" || join.IdentityStateDigest != "" || len(join.IdentityStateChunks) != 0 ||
			join.CredentialBase64 != "" || join.CredentialExpiresAt != 0 || join.JoinedAtUnix != 0 {
			return errRoomJoinRecordValue
		}
	case JoinKeyPackageSent:
		if !canon.ValidDigest(join.KeyPackageRef) || !canon.ValidDigest(join.IdentityStateDigest) ||
			len(join.IdentityStateChunks) == 0 || len(join.IdentityStateChunks) > MaxMLSStateChunks || join.JoinedAtUnix == 0 {
			return errRoomJoinRecordValue
		}
		for _, chunk := range join.IdentityStateChunks {
			if !canon.ValidDigest(chunk) {
				return errRoomJoinRecordValue
			}
		}
		credential, err := join.Credential()
		if err != nil {
			return errRoomJoinRecordValue
		}
		ref, err := group.KeyPackageRef(credential)
		if err != nil || ref != join.KeyPackageRef {
			return ErrRoomJoinKeyPackage
		}
		if credential.ExpiresAtUnix != join.CredentialExpiresAt {
			return errRoomJoinRecordValue
		}
	default:
		return errRoomJoinRecordValue
	}
	return nil
}

func (j *Journal) writeRoomJoin(join PendingRoomJoin) error {
	if err := validateRoomJoin(join); err != nil {
		return err
	}
	encoded, err := json.Marshal(join)
	if err != nil {
		return err
	}
	return j.replace(j.roomJoinPath(join.RoomID, join.AuthorityAgentID), encoded)
}

// roomsHeld counts the private rooms other than roomID that this
// installation holds (a fused record) or is joining (an accepted join). The
// journal mutex is held.
func (j *Journal) roomsHeld(roomID string) (int, error) {
	rooms := map[string]struct{}{}
	fused, err := j.fusedRoomIDs()
	if err != nil {
		return 0, err
	}
	for _, id := range fused {
		rooms[id] = struct{}{}
	}
	keys, err := j.roomJoinKeys()
	if err != nil {
		return 0, err
	}
	for _, key := range keys {
		join, found, err := j.readRoomJoin(key.room, key.authority)
		if err != nil {
			return 0, err
		}
		if found && join.State == JoinKeyPackageSent {
			rooms[key.room] = struct{}{}
		}
	}
	delete(rooms, roomID)
	return len(rooms), nil
}
