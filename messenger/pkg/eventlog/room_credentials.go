package eventlog

// The leaf credentials of a private room's members (section 11.8).
//
// Each member's verified leaf credential is a content-addressed record named
// by its digest, SHA-256 of the canonical credential bytes: the digest its
// 128-byte leaf identity names. The room's credential list is a second
// content-addressed record holding, per member Agent, the digest of that
// member's credential. The fused room record names the list by digest, so the
// list is a garbage-collection root through it: collection keeps every
// credential a list names, and an unreadable list deletes nothing.
//
// Learning credentials takes three steps, all before the roster's room ack is
// signed: the credential records, then the new list, then the fused write
// naming the list. A crash before the fused write leaves unrooted records that
// restart collects; the unacknowledged roster is delivered again. An exact
// repeat (the same list digest) writes nothing.
//
// The ledger stores only credentials it is handed as a group.LeafBinding,
// which group.VerifyRoomLeafCredential alone constructs: every stored
// credential was verified on the room path. Stored credentials are re-verified
// by their user at every use, because the delegation they verify against is
// finalized state that can change.

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/group"
)

const (
	roomCredentialSchema     = "tos.messaging.room-leaf-credential.v1"
	roomCredentialListSchema = "tos.messaging.room-credential-list.v1"

	credentialBlobPrefix     = "c-"
	credentialListBlobPrefix = "l-"
)

// Credential store refusals.
var (
	// ErrRoomCredentialMember reports a credential of an Agent that is not a
	// current member of the room.
	ErrRoomCredentialMember = errors.New("the leaf credential names no current member of the room")
	// ErrRoomCredentialUnverified reports a binding that was not made by the
	// room path's verification.
	ErrRoomCredentialUnverified = errors.New("the leaf credential was not verified on the room path")
	// ErrRoomAuthorityCredential reports an install whose credentials hold no
	// credential of the room's authority, or whose end time is not that
	// credential's expiry (D18).
	ErrRoomAuthorityCredential = errors.New("the room's end is not its authority's leaf credential expiry")
)

// roomCredentialEntry names one member's credential.
type roomCredentialEntry struct {
	AgentID string `json:"agent_id"`
	Digest  string `json:"credential_digest"`
}

// roomCredentialList is the per-room list: one entry per member Agent (one
// device per Agent over the relay, D3), in ascending Agent order.
type roomCredentialList struct {
	Schema  string                `json:"schema"`
	RoomID  string                `json:"room_id"`
	Entries []roomCredentialEntry `json:"entries"`
}

func validateCredentialList(list roomCredentialList) error {
	if list.Schema != roomCredentialListSchema || !ids.Room.MatchString(list.RoomID) ||
		len(list.Entries) == 0 || len(list.Entries) > group.MaxPrivateRoomAgents {
		return errors.New("invalid room credential list")
	}
	for index, entry := range list.Entries {
		if !ids.Agent.MatchString(entry.AgentID) || !canon.ValidDigest(entry.Digest) ||
			(index > 0 && entry.AgentID <= list.Entries[index-1].AgentID) {
			return errors.New("invalid room credential list entry")
		}
	}
	return nil
}

// encodeCredentialList returns the canonical bytes of a list: the data its
// digest is taken over.
func encodeCredentialList(list roomCredentialList) ([]byte, error) {
	if err := validateCredentialList(list); err != nil {
		return nil, err
	}
	return json.Marshal(list)
}

// stageLeafCredential writes a verified credential under its digest and
// returns the digest. The journal mutex is held.
func (j *Journal) stageLeafCredential(binding group.LeafBinding) (string, string, error) {
	if err := binding.Validate(); err != nil {
		return "", "", ErrRoomCredentialUnverified
	}
	credential := binding.Credential()
	encoded, err := group.EncodeLeafCredential(credential)
	if err != nil {
		return "", "", ErrRoomCredentialUnverified
	}
	// The binding's identity names exactly these bytes.
	if err := group.CheckLeaf(credential, binding.Identity(), binding.SignatureKey()); err != nil {
		return "", "", ErrRoomCredentialUnverified
	}
	path, err := j.roomBlobPath(credentialBlobPrefix, canon.Digest(encoded))
	if err != nil {
		return "", "", err
	}
	digest, err := j.writeChunk(path, roomCredentialSchema, encoded)
	if err != nil {
		return "", "", err
	}
	return credential.AgentID, digest, nil
}

// loadLeafCredential reads a stored credential, verifying its digest and its
// canonical encoding. The journal mutex is held.
func (j *Journal) loadLeafCredential(digest string) (group.LeafCredential, error) {
	path, err := j.roomBlobPath(credentialBlobPrefix, digest)
	if err != nil {
		return group.LeafCredential{}, err
	}
	raw, err := readChunk(path, roomCredentialSchema, digest)
	if err != nil {
		return group.LeafCredential{}, err
	}
	return group.DecodeLeafCredential(raw)
}

// stageCredentialList writes a list and returns its digest. The journal
// mutex is held.
func (j *Journal) stageCredentialList(list roomCredentialList) (string, error) {
	encoded, err := encodeCredentialList(list)
	if err != nil {
		return "", err
	}
	path, err := j.roomBlobPath(credentialListBlobPrefix, canon.Digest(encoded))
	if err != nil {
		return "", err
	}
	return j.writeChunk(path, roomCredentialListSchema, encoded)
}

// loadCredentialList reads a room's list, verifying its digest, schema and
// room. The journal mutex is held.
func (j *Journal) loadCredentialList(roomID, digest string) (roomCredentialList, error) {
	path, err := j.roomBlobPath(credentialListBlobPrefix, digest)
	if err != nil {
		return roomCredentialList{}, err
	}
	raw, err := readChunk(path, roomCredentialListSchema, digest)
	if err != nil {
		return roomCredentialList{}, err
	}
	var list roomCredentialList
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&list); err != nil || validateCredentialList(list) != nil || list.RoomID != roomID {
		return roomCredentialList{}, errors.New("invalid room credential list")
	}
	again, err := encodeCredentialList(list)
	if err != nil || !bytes.Equal(again, raw) {
		return roomCredentialList{}, errors.New("room credential list is not canonical")
	}
	return list, nil
}

// mergeCredentials returns the list with each new entry set for its Agent,
// keeping only Agents of members. A member's later credential replaces its
// earlier one: the member's leaf names one credential at a time.
func mergeCredentials(roomID string, current []roomCredentialEntry, learned map[string]string, members []string) roomCredentialList {
	byAgent := make(map[string]string, len(current)+len(learned))
	for _, entry := range current {
		byAgent[entry.AgentID] = entry.Digest
	}
	for agentID, digest := range learned {
		byAgent[agentID] = digest
	}
	entries := make([]roomCredentialEntry, 0, len(byAgent))
	for agentID, digest := range byAgent {
		if containsString(members, agentID) {
			entries = append(entries, roomCredentialEntry{AgentID: agentID, Digest: digest})
		}
	}
	sort.Slice(entries, func(a, b int) bool { return entries[a].AgentID < entries[b].AgentID })
	return roomCredentialList{Schema: roomCredentialListSchema, RoomID: roomID, Entries: entries}
}

// stageInstallCredentials writes the credentials of a first install and the
// list naming them, and checks D18: the list holds the authority's credential
// and the room's end is its expiry. The journal mutex is held.
func (j *Journal) stageInstallCredentials(roomID string, authority roomAuthorityRef, members []string, bindings []group.LeafBinding, endsAtUnix uint64) (string, error) {
	if len(bindings) == 0 || len(bindings) > group.MaxPrivateRoomAgents || endsAtUnix == 0 {
		return "", ErrRoomAuthorityCredential
	}
	learned := make(map[string]string, len(bindings))
	authorityFound := false
	for _, binding := range bindings {
		credential := binding.Credential()
		if !containsString(members, credential.AgentID) {
			return "", ErrRoomCredentialMember
		}
		if _, duplicate := learned[credential.AgentID]; duplicate {
			return "", errors.New("two leaf credentials for one member")
		}
		agentID, digest, err := j.stageLeafCredential(binding)
		if err != nil {
			return "", err
		}
		learned[agentID] = digest
		if credential.AgentID == authority.agentID && credential.EndpointID == authority.endpointID {
			if credential.ExpiresAtUnix != endsAtUnix {
				return "", ErrRoomAuthorityCredential
			}
			authorityFound = true
		}
	}
	if !authorityFound {
		return "", ErrRoomAuthorityCredential
	}
	return j.stageCredentialList(mergeCredentials(roomID, nil, learned, members))
}

type roomAuthorityRef struct{ agentID, endpointID string }

// LearnRoomCredentials records verified leaf credentials of current members
// of a room: the credential records, then the new list, then the fused write
// naming it. It reports false, writing nothing, when the list is unchanged
// (an exact repeat). It must complete before the roster that delivered the
// credentials is acknowledged.
func (l *RoomMLSLedger) LearnRoomCredentials(roomID string, bindings []group.LeafBinding, now time.Time) (bool, RoomMLSRecord, error) {
	if l == nil {
		return false, RoomMLSRecord{}, errors.New("no fused room ledger")
	}
	if err := l.journal.usable(); err != nil {
		return false, RoomMLSRecord{}, err
	}
	if !ids.Room.MatchString(roomID) || len(bindings) == 0 || len(bindings) > group.MaxPrivateRoomAgents {
		return false, RoomMLSRecord{}, errors.New("invalid room credentials")
	}
	at := now
	if err := validMLSTime(at); err != nil {
		return false, RoomMLSRecord{}, err
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	current, found, err := l.read(roomID)
	if err != nil {
		return false, RoomMLSRecord{}, err
	}
	if !found {
		return false, RoomMLSRecord{}, ErrRoomNotJoined
	}
	list, err := l.journal.loadCredentialList(roomID, current.CredentialListDigest)
	if err != nil {
		return false, RoomMLSRecord{}, err
	}
	learned := make(map[string]string, len(bindings))
	for _, binding := range bindings {
		if !containsString(current.Members, binding.Credential().AgentID) {
			return false, RoomMLSRecord{}, ErrRoomCredentialMember
		}
		agentID, digest, err := l.journal.stageLeafCredential(binding)
		if err != nil {
			return false, RoomMLSRecord{}, err
		}
		learned[agentID] = digest
	}
	digest, err := l.journal.stageCredentialList(mergeCredentials(roomID, list.Entries, learned, current.Members))
	if err != nil {
		return false, RoomMLSRecord{}, err
	}
	if digest == current.CredentialListDigest {
		return false, current, nil
	}
	next := current
	next.CredentialListDigest = digest
	next.UpdatedAtUnix = uint64(at.Unix())
	encoded, err := encodeRoomMLSRecord(next)
	if err != nil {
		return false, RoomMLSRecord{}, err
	}
	if err := l.journal.replace(l.path(roomID), encoded); err != nil {
		return false, RoomMLSRecord{}, err
	}
	return true, next, nil
}

// RoomCredential returns the stored leaf credential of a room member, if
// known. The caller re-verifies it against finalized state before use.
func (l *RoomMLSLedger) RoomCredential(roomID, agentID string) (group.LeafCredential, bool, error) {
	if l == nil {
		return group.LeafCredential{}, false, errors.New("no fused room ledger")
	}
	if err := l.journal.usable(); err != nil {
		return group.LeafCredential{}, false, err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(agentID) {
		return group.LeafCredential{}, false, errors.New("invalid room credential lookup")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	return l.journal.roomCredential(roomID, agentID)
}

// roomCredential is RoomCredential with the journal mutex held.
func (j *Journal) roomCredential(roomID, agentID string) (group.LeafCredential, bool, error) {
	record, found, err := j.readRoomMLS(roomID)
	if err != nil {
		return group.LeafCredential{}, false, err
	}
	if !found {
		return group.LeafCredential{}, false, ErrRoomNotJoined
	}
	list, err := j.loadCredentialList(roomID, record.CredentialListDigest)
	if err != nil {
		return group.LeafCredential{}, false, err
	}
	for _, entry := range list.Entries {
		if entry.AgentID != agentID {
			continue
		}
		credential, err := j.loadLeafCredential(entry.Digest)
		if err != nil {
			return group.LeafCredential{}, false, err
		}
		if credential.AgentID != agentID {
			return group.LeafCredential{}, false, errors.New("stored leaf credential names another Agent")
		}
		return credential, true, nil
	}
	return group.LeafCredential{}, false, nil
}

// credentialAgents returns the Agents whose credentials the room's list
// holds. The journal mutex is held.
func (j *Journal) credentialAgents(record RoomMLSRecord) (map[string]bool, error) {
	list, err := j.loadCredentialList(record.RoomID, record.CredentialListDigest)
	if err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(list.Entries))
	for _, entry := range list.Entries {
		known[entry.AgentID] = true
	}
	return known, nil
}

// keepCredentialBlob reports whether a blob name is a credential record or a
// credential list, and whether a root names it.
func (n namedRoomSet) keepCredentialBlob(stem string) (bool, bool) {
	if value, ok := strings.CutPrefix(stem, credentialBlobPrefix); ok && canon.HashPattern.MatchString(value) {
		_, keep := n.credentials["sha256:"+value]
		return true, keep
	}
	if value, ok := strings.CutPrefix(stem, credentialListBlobPrefix); ok && canon.HashPattern.MatchString(value) {
		_, keep := n.credentialLists["sha256:"+value]
		return true, keep
	}
	return false, false
}

// retainMemberCredentials returns the digest of the room's list kept to the
// members of the next epoch, staging a new list when a member left. The
// journal mutex is held.
func (j *Journal) retainMemberCredentials(current RoomMLSRecord, members []string) (string, error) {
	list, err := j.loadCredentialList(current.RoomID, current.CredentialListDigest)
	if err != nil {
		return "", err
	}
	kept := mergeCredentials(current.RoomID, list.Entries, nil, members)
	if len(kept.Entries) == len(list.Entries) {
		return current.CredentialListDigest, nil
	}
	return j.stageCredentialList(kept)
}

// requireJoinAuthorityCredential checks a Welcome install against the
// room's accepted pending join: the install's credential of the authority
// must be the one the join's room.invite carried. A room with no accepted
// join is left to the caller's pending-join path. The journal mutex is held.
func (j *Journal) requireJoinAuthorityCredential(roomID string, authority roomAuthorityRef, bindings []group.LeafBinding) error {
	join, found, err := j.acceptedRoomJoin(roomID)
	if err != nil || !found {
		return err
	}
	if join.AuthorityAgentID != authority.agentID {
		return ErrRoomJoinConflict
	}
	stored, err := join.AuthorityCredential()
	if err != nil {
		return err
	}
	want, err := group.EncodeLeafCredential(stored)
	if err != nil {
		return err
	}
	for _, binding := range bindings {
		credential := binding.Credential()
		if credential.AgentID != authority.agentID {
			continue
		}
		got, err := group.EncodeLeafCredential(credential)
		if err != nil || !bytes.Equal(got, want) || credential.EndpointID != authority.endpointID {
			return ErrRoomAuthorityCredential
		}
		return nil
	}
	return ErrRoomAuthorityCredential
}
