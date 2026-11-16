package eventlog

// Pending joins of private rooms (section 11.2).
//
// A room.invite from a room's authority, received over the 1:1 session,
// records a pending join naming that authority. When the owner calls
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
)

const (
	roomJoinDir    = "room-joins"
	roomJoinSchema = "tos.messaging.room-join.v1"
	// MaxPendingRoomJoins bounds the rooms this installation may be invited
	// to and not yet have joined.
	MaxPendingRoomJoins = 64
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

// RecordRoomInvite records a room.invite from a room's authority. A later
// invite for the same room from the same authority refreshes an unjoined
// one; one from another authority is refused while a join is pending.
func (j *Journal) RecordRoomInvite(roomID, authorityAgentID, inviteEventID string, expires, now time.Time) (PendingRoomJoin, error) {
	if err := j.usable(); err != nil {
		return PendingRoomJoin{}, err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(authorityAgentID) || !ids.Event.MatchString(inviteEventID) ||
		now.IsZero() || now.Unix() <= 0 || !expires.After(now) {
		return PendingRoomJoin{}, errors.New("invalid room invite")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	if _, found, err := j.readRoomMLS(roomID); err != nil {
		return PendingRoomJoin{}, err
	} else if found {
		return PendingRoomJoin{}, ErrRoomAlreadyJoined
	}
	existing, found, err := j.readRoomJoin(roomID)
	if err != nil {
		return PendingRoomJoin{}, err
	}
	if found && uint64(now.Unix()) < existing.expiresAt() {
		if existing.AuthorityAgentID != authorityAgentID {
			return PendingRoomJoin{}, ErrRoomJoinConflict
		}
		if existing.State != JoinInvited {
			return existing, nil
		}
	} else if found {
		// An expired join is ended, with any identity it staged, before a
		// new invite replaces it.
		if err := j.deleteRoomJoin(existing, nil); err != nil {
			return PendingRoomJoin{}, err
		}
		found = false
	}
	if !found {
		count, err := countEntries(filepath.Join(j.root, roomJoinDir))
		if err != nil {
			return PendingRoomJoin{}, err
		}
		if count >= MaxPendingRoomJoins {
			if err := j.sweepRoomJoins(now); err != nil {
				return PendingRoomJoin{}, err
			}
			if count, err = countEntries(filepath.Join(j.root, roomJoinDir)); err != nil {
				return PendingRoomJoin{}, err
			}
			if count >= MaxPendingRoomJoins {
				return PendingRoomJoin{}, ErrRoomJoinsFull
			}
		}
	}
	join := PendingRoomJoin{Schema: roomJoinSchema, RoomID: roomID, AuthorityAgentID: authorityAgentID,
		InviteEventID: inviteEventID, InviteExpiresAtUnix: uint64(expires.Unix()), InvitedAtUnix: uint64(now.Unix()),
		State: JoinInvited}
	return join, j.writeRoomJoin(join)
}

// BeginRoomJoin records the owner's join: the identity's private state
// (staged as chunks first), the KeyPackage reference and the signed
// DeviceCredential sent as room.key-package. The record write is the commit
// point; a repeat with the same KeyPackage is a no-op.
func (j *Journal) BeginRoomJoin(roomID string, identityState []byte, credentialJSON []byte, now time.Time) (PendingRoomJoin, error) {
	if err := j.usable(); err != nil {
		return PendingRoomJoin{}, err
	}
	if !ids.Room.MatchString(roomID) || now.IsZero() || now.Unix() <= 0 {
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
	join, found, err := j.readRoomJoin(roomID)
	if err != nil {
		return PendingRoomJoin{}, err
	}
	if !found {
		return PendingRoomJoin{}, ErrRoomJoinUnknown
	}
	if join.State == JoinKeyPackageSent {
		if join.KeyPackageRef == ref {
			return join, nil
		}
		return PendingRoomJoin{}, ErrRoomJoinConflict
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
	return join, j.writeRoomJoin(join)
}

// PendingRoomJoinFor returns a room's live pending join. An expired join is
// dropped; one whose KeyPackage a fused record consumed has ended.
func (j *Journal) PendingRoomJoinFor(roomID string, now time.Time) (PendingRoomJoin, bool, error) {
	if err := j.usable(); err != nil {
		return PendingRoomJoin{}, false, err
	}
	if !ids.Room.MatchString(roomID) || now.IsZero() {
		return PendingRoomJoin{}, false, errors.New("invalid pending room join lookup")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.liveRoomJoin(roomID, now)
}

// RoomJoinIdentityState reassembles the identity state a joined pending join
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

// FinishRoomJoin ends a pending join once its Welcome is installed. It is
// refused unless the fused record consumed the join's KeyPackage, so a join
// is never ended by anything but its own Welcome. A join already ended is no
// error.
func (j *Journal) FinishRoomJoin(roomID string) error {
	if err := j.usable(); err != nil {
		return err
	}
	if !ids.Room.MatchString(roomID) {
		return errors.New("invalid room")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	join, found, err := j.readRoomJoin(roomID)
	if err != nil || !found {
		return err
	}
	fused, joined, err := j.readRoomMLS(roomID)
	if err != nil {
		return err
	}
	if !joined || join.KeyPackageRef == "" || fused.KeyPackageRef != join.KeyPackageRef {
		return errors.New("the room's Welcome has not been installed")
	}
	return j.deleteRoomJoin(join, fused.StateChunks)
}

// ListPendingRoomJoins returns every live pending join, by room.
func (j *Journal) ListPendingRoomJoins(now time.Time) ([]PendingRoomJoin, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, errors.New("invalid pending room join listing")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	roomIDs, err := j.roomJoinIDs()
	if err != nil {
		return nil, err
	}
	joins := make([]PendingRoomJoin, 0, len(roomIDs))
	for _, roomID := range roomIDs {
		join, found, err := j.liveRoomJoin(roomID, now)
		if err != nil {
			return nil, err
		}
		if found {
			joins = append(joins, join)
		}
	}
	return joins, nil
}

// SweepRoomJoins drops every expired or ended pending join.
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
	roomIDs, err := j.roomJoinIDs()
	if err != nil {
		return err
	}
	for _, roomID := range roomIDs {
		if _, _, err := j.liveRoomJoin(roomID, now); err != nil {
			return err
		}
	}
	return nil
}

// liveRoomJoin reads a join and ends it if it expired or its KeyPackage was
// consumed. The journal mutex is held.
func (j *Journal) liveRoomJoin(roomID string, now time.Time) (PendingRoomJoin, bool, error) {
	join, found, err := j.readRoomJoin(roomID)
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
	if joined || now.Unix() < 0 || uint64(now.Unix()) >= join.expiresAt() {
		return PendingRoomJoin{}, false, j.deleteRoomJoin(join, keep)
	}
	return join, true, nil
}

// deleteRoomJoin removes a join record, then the identity chunks it named
// that the room's fused state does not share. A chunk left by a crash is
// collected at restart. The journal mutex is held.
func (j *Journal) deleteRoomJoin(join PendingRoomJoin, keep []string) error {
	path := j.roomJoinPath(join.RoomID)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("delete pending room join")
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	j.deleteSupersededState(join.RoomID, join.IdentityStateChunks, keep)
	return nil
}

func (j *Journal) roomJoinPath(roomID string) string {
	return filepath.Join(j.root, roomJoinDir, roomID[len("room_"):]+".json")
}

func (j *Journal) roomJoinIDs() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(j.root, roomJoinDir))
	if err != nil {
		return nil, errors.New("read pending room joins")
	}
	var roomIDs []string
	for _, entry := range entries {
		name := entry.Name()
		if isTransitionTemp(name) {
			continue
		}
		stem, ok := strings.CutSuffix(name, ".json")
		if !ok || entry.IsDir() || !ids.Room.MatchString("room_"+stem) {
			return nil, errors.New("unexpected entry in the pending room joins")
		}
		roomIDs = append(roomIDs, "room_"+stem)
	}
	sort.Strings(roomIDs)
	return roomIDs, nil
}

func (j *Journal) readRoomJoin(roomID string) (PendingRoomJoin, bool, error) {
	raw, err := readRecordBytes(j.roomJoinPath(roomID))
	if errors.Is(err, os.ErrNotExist) {
		return PendingRoomJoin{}, false, nil
	}
	if err != nil {
		return PendingRoomJoin{}, false, err
	}
	var join PendingRoomJoin
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&join); err != nil || join.RoomID != roomID {
		return PendingRoomJoin{}, false, errRoomJoinRecordValue
	}
	if err := validateRoomJoin(join); err != nil {
		return PendingRoomJoin{}, false, err
	}
	return join, true, nil
}

func validateRoomJoin(join PendingRoomJoin) error {
	if join.Schema != roomJoinSchema || !ids.Room.MatchString(join.RoomID) || !ids.Agent.MatchString(join.AuthorityAgentID) ||
		!ids.Event.MatchString(join.InviteEventID) || join.InvitedAtUnix == 0 || join.InviteExpiresAtUnix <= join.InvitedAtUnix {
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
	return j.replace(j.roomJoinPath(join.RoomID), encoded)
}
