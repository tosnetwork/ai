package eventlog

// The room outbox is the authority's sender journal for handshake objects:
// Commits, Welcomes and rosters. An object's bytes are stored once, as chunk
// records (room_chunks.go), and a head record per object holds its identity
// and one delivery state per recipient member.
//
// A Commit's output must not outlive or predate the state advance it belongs
// to. The driver output is therefore staged first, as one staged-output record
// keyed by the Commit reference that names the would-be heads, together with
// their object chunks; then the fused room record is written, naming that
// Commit reference; only then are the heads published. A crash before the
// fused write leaves a staged output no fused record accepts, which restart
// discards. A crash after it leaves one the fused record accepts, which restart
// publishes. Either way each object is published once or not at all.

import (
	"bytes"
	"encoding/json"
	"errors"
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
	roomOutboxDir = "room-outbox"
	roomStagedDir = "room-staged"

	roomOutboxHeadSchema   = "tos.messaging.room-outbox-head.v1"
	roomStagedOutputSchema = "tos.messaging.room-staged-output.v1"

	// MaxStagedRoomObjects bounds the objects of one Commit: the Commit, one
	// Welcome, a full roster per joiner and one roster of the added members.
	MaxStagedRoomObjects = 2 + 2*group.MaxPrivateRoomAgents
	// MaxRoomObjectRecipients bounds the members one object is addressed to:
	// every other member, and once a removed member.
	MaxRoomObjectRecipients = group.MaxPrivateRoomAgents
)

// RoomObjectType is the object type of a room object (the room-object codec's
// object_type).
type RoomObjectType uint8

const (
	RoomObjectCommit      RoomObjectType = 1
	RoomObjectWelcome     RoomObjectType = 2
	RoomObjectApplication RoomObjectType = 3
	RoomObjectRoster      RoomObjectType = 4
)

func (t RoomObjectType) handshake() bool {
	return t == RoomObjectCommit || t == RoomObjectWelcome || t == RoomObjectRoster
}

// queueRank orders the objects of one MLS epoch in a member's queue: the
// Commit or Welcome that makes the epoch, then the roster that describes it.
func (t RoomObjectType) queueRank() int {
	if t == RoomObjectRoster {
		return 1
	}
	return 0
}

// RoomDeliveryState is one member's state for one outbox object.
type RoomDeliveryState string

const (
	RoomDeliveryPending   RoomDeliveryState = "pending"
	RoomDeliveryCarried   RoomDeliveryState = "carried"
	RoomDeliveryDelivered RoomDeliveryState = "delivered"
	RoomDeliveryRejected  RoomDeliveryState = "rejected"
	RoomDeliveryAbandoned RoomDeliveryState = "abandoned"
)

// RoomAckOutcome is the outcome a verified room ack reports.
type RoomAckOutcome string

const (
	RoomAckAccepted  RoomAckOutcome = "accepted"
	RoomAckDuplicate RoomAckOutcome = "duplicate"
	RoomAckRejected  RoomAckOutcome = "rejected"
)

// RoomRecipient is one member an object is addressed to. Once marks the
// removed member of a Remove Commit, which gets the Commit in a single
// deposit with no ack and no place in its queue.
type RoomRecipient struct {
	AgentID string
	Once    bool
}

// StagedRoomObject is one object of a Commit's output, as the caller built it.
type StagedRoomObject struct {
	Type       RoomObjectType
	RoomEpoch  uint64
	MLSEpoch   uint64
	Object     []byte
	Recipients []RoomRecipient
}

// RoomMemberDelivery is one member's delivery of one outbox object.
type RoomMemberDelivery struct {
	AgentID             string            `json:"agent_id"`
	Once                bool              `json:"once,omitempty"`
	State               RoomDeliveryState `json:"state"`
	Generation          uint32            `json:"generation,omitempty"`
	LastDepositAtUnix   uint64            `json:"last_deposit_at_unix,omitempty"`
	NextRedepositAtUnix uint64            `json:"next_redeposit_at_unix,omitempty"`
	EvidenceDigest      string            `json:"evidence_digest,omitempty"`
	AckOutcome          RoomAckOutcome    `json:"ack_outcome,omitempty"`
	Code                fault.Code        `json:"code,omitempty"`
	SettledAtUnix       uint64            `json:"settled_at_unix,omitempty"`
}

func (d RoomMemberDelivery) settled() bool {
	switch d.State {
	case RoomDeliveryDelivered, RoomDeliveryRejected, RoomDeliveryAbandoned:
		return true
	case RoomDeliveryCarried:
		return d.Once
	default:
		return false
	}
}

// RoomOutboxHead is the head record of one outbox object.
type RoomOutboxHead struct {
	Schema          string               `json:"schema"`
	ObjectDigest    string               `json:"object_digest"`
	Type            RoomObjectType       `json:"object_type"`
	RoomID          string               `json:"room_id"`
	RoomEpoch       uint64               `json:"room_epoch"`
	MLSEpoch        uint64               `json:"mls_epoch"`
	CommitRef       string               `json:"commit_ref"`
	Length          uint32               `json:"object_length"`
	Chunks          []string             `json:"chunk_digests"`
	CreatedAtUnix   uint64               `json:"created_at_unix"`
	RetainUntilUnix uint64               `json:"retain_until_unix"`
	Members         []RoomMemberDelivery `json:"members"`
}

// Member returns one member's delivery of this object.
func (h RoomOutboxHead) Member(agentID string) (RoomMemberDelivery, bool) {
	for _, member := range h.Members {
		if member.AgentID == agentID {
			return member, true
		}
	}
	return RoomMemberDelivery{}, false
}

type roomStagedOutput struct {
	Schema       string           `json:"schema"`
	RoomID       string           `json:"room_id"`
	CommitRef    string           `json:"commit_ref"`
	StagedAtUnix uint64           `json:"staged_at_unix"`
	Heads        []RoomOutboxHead `json:"heads"`
}

// ErrRoomStagedOutput reports a room whose previous Commit output has not been
// resolved yet. A new Commit waits until it is published or discarded.
var ErrRoomStagedOutput = errors.New("room has an unresolved staged Commit output")

// stageRoomOutput writes a Commit's objects and the staged-output record that
// names them. The journal mutex is held.
func (j *Journal) stageRoomOutput(roomID, commitRef string, objects []StagedRoomObject, retainUntil, now time.Time) ([]RoomOutboxHead, error) {
	if !ids.Room.MatchString(roomID) || !canon.ValidDigest(commitRef) {
		return nil, errors.New("invalid staged room output binding")
	}
	if len(objects) == 0 || len(objects) > MaxStagedRoomObjects {
		return nil, errors.New("invalid staged room object count")
	}
	if retainUntil.Unix() <= now.Unix() {
		return nil, errors.New("invalid room handshake retention")
	}
	heads := make([]RoomOutboxHead, 0, len(objects))
	seen := make(map[string]struct{}, len(objects))
	for _, object := range objects {
		head, err := newRoomOutboxHead(roomID, commitRef, object, retainUntil, now)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[head.ObjectDigest]; duplicate {
			return nil, errors.New("a Commit output names one object twice")
		}
		seen[head.ObjectDigest] = struct{}{}
		chunks, err := j.stageObject(object.Object)
		if err != nil {
			return nil, err
		}
		head.Chunks = chunks
		heads = append(heads, head)
	}
	staged := roomStagedOutput{Schema: roomStagedOutputSchema, RoomID: roomID, CommitRef: commitRef, StagedAtUnix: uint64(now.Unix()), Heads: heads}
	encoded, err := json.Marshal(staged)
	if err != nil {
		return nil, err
	}
	path, err := j.roomStagedPath(commitRef)
	if err != nil {
		return nil, err
	}
	if err := j.replace(path, encoded); err != nil {
		return nil, err
	}
	return heads, nil
}

func newRoomOutboxHead(roomID, commitRef string, object StagedRoomObject, retainUntil, now time.Time) (RoomOutboxHead, error) {
	if !object.Type.handshake() {
		return RoomOutboxHead{}, errors.New("only handshake objects are staged with a Commit")
	}
	if object.RoomEpoch == 0 || len(object.Object) == 0 || len(object.Object) > MaxRoomObjectBytes {
		return RoomOutboxHead{}, errors.New("invalid staged room object")
	}
	if len(object.Recipients) == 0 || len(object.Recipients) > MaxRoomObjectRecipients {
		return RoomOutboxHead{}, errors.New("invalid staged room object recipients")
	}
	members := make([]RoomMemberDelivery, 0, len(object.Recipients))
	seen := make(map[string]struct{}, len(object.Recipients))
	for _, recipient := range object.Recipients {
		if !ids.Agent.MatchString(recipient.AgentID) {
			return RoomOutboxHead{}, errors.New("invalid staged room object recipient")
		}
		if recipient.Once && object.Type != RoomObjectCommit {
			return RoomOutboxHead{}, errors.New("only a Commit goes once to a removed member")
		}
		if _, duplicate := seen[recipient.AgentID]; duplicate {
			return RoomOutboxHead{}, errors.New("duplicate staged room object recipient")
		}
		seen[recipient.AgentID] = struct{}{}
		members = append(members, RoomMemberDelivery{AgentID: recipient.AgentID, Once: recipient.Once, State: RoomDeliveryPending})
	}
	sort.Slice(members, func(a, b int) bool { return members[a].AgentID < members[b].AgentID })
	return RoomOutboxHead{
		Schema: roomOutboxHeadSchema, ObjectDigest: RoomObjectDigest(object.Object), Type: object.Type,
		RoomID: roomID, RoomEpoch: object.RoomEpoch, MLSEpoch: object.MLSEpoch, CommitRef: commitRef,
		Length: uint32(len(object.Object)), CreatedAtUnix: uint64(now.Unix()), RetainUntilUnix: uint64(retainUntil.Unix()),
		Members: members,
	}, nil
}

// publishStaged turns one staged output into outbox heads and removes it.
//
// Removing the staged record is what marks the output published. Until it is
// removed the output is republished idempotently: a head already present is
// kept as it is, a missing one is created. A head is never retired while its
// staged record exists (updateRoomMember), so a missing head always means "not
// yet written", never "settled and retired", and every member gets each object
// once whichever step fails. Once the record is removed, heads of the output
// that every member already settled are retired. The journal mutex is held.
func (j *Journal) publishStaged(staged roomStagedOutput) error {
	for _, head := range staged.Heads {
		path, err := j.roomHeadPath(head.ObjectDigest)
		if err != nil {
			return err
		}
		existing, err := j.readRoomHead(path)
		if err == nil {
			if existing.CommitRef != head.CommitRef || existing.RoomID != head.RoomID || existing.Type != head.Type {
				return errors.New("a published room object conflicts with its staged head")
			}
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := j.writeRoomHead(head); err != nil {
			return err
		}
	}
	path, err := j.roomStagedPath(staged.CommitRef)
	if err != nil {
		return err
	}
	if err := removeStagedRecord(path); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	for _, head := range staged.Heads {
		headPath, err := j.roomHeadPath(head.ObjectDigest)
		if err != nil {
			return err
		}
		current, err := j.readRoomHead(headPath)
		if err != nil {
			continue
		}
		if current.allSettled() {
			if err := os.Remove(headPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return errors.New("retire settled room object")
			}
		}
	}
	return syncDirectory(filepath.Join(j.root, roomOutboxDir))
}

// removeStagedRecord is the one place a staged output is removed; tests
// replace it to fail the removal.
var removeStagedRecord = func(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("remove published room output")
	}
	return nil
}

// requireRoomStagedResolved publishes or discards the staged outputs before
// a room moves or answers a repeat, and refuses while any staged output is
// unreadable: an unreadable record names no room, and it may be the output of
// the Commit this room accepted, which must be published before anything
// later. The journal mutex is held.
func (j *Journal) requireRoomStagedResolved(roomID string) error {
	unresolved, err := j.resolveRoomStaged(roomID)
	if err != nil {
		return err
	}
	if len(unresolved) > 0 {
		return &StagedOutputError{Paths: unresolved}
	}
	return nil
}

// StagedRoomOutputGuidance is what an operator does about a staged output
// that blocks every room.
const StagedRoomOutputGuidance = "inspect it; remove it only if no room's fused record (room-mls/*.json, accepted_commit_ref) names its CommitRef, which is sha256: and the file name without .json"

// StagedOutputError names the staged Commit outputs that could not be read
// or resolved. While any exists no room commits or answers a repeat, because
// an unreadable output names no room and may be the one a room accepted. It
// matches ErrRoomStagedOutput.
type StagedOutputError struct {
	Paths []string
}

func (e *StagedOutputError) Error() string {
	return "room has an unresolved staged Commit output: " + strings.Join(e.Paths, ", ") + "; " + StagedRoomOutputGuidance
}

func (e *StagedOutputError) Is(target error) bool { return target == ErrRoomStagedOutput }

// UnresolvedStagedRoomOutputs lists, by full path, the staged Commit outputs
// that cannot be read or resolved, for the owner-visible maintenance report.
func (j *Journal) UnresolvedStagedRoomOutputs() ([]string, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.resolveRoomStaged("")
}

// retireOrphanedSettledHeads retires every head that every member settled
// and whose staged record is gone. A crash between removing the staged record
// and retiring its settled heads leaves such heads; nothing else would retire
// them, and as collection roots they would keep their objects forever. The
// journal mutex is held.
func (j *Journal) retireOrphanedSettledHeads() error {
	entries, err := os.ReadDir(filepath.Join(j.root, roomOutboxDir))
	if err != nil {
		return errors.New("read room outbox")
	}
	removed := false
	for _, entry := range entries {
		if isTransitionTemp(entry.Name()) {
			continue
		}
		path := filepath.Join(j.root, roomOutboxDir, entry.Name())
		head, err := j.readRoomHead(path)
		if err != nil || !head.allSettled() {
			continue
		}
		pending, err := j.stagedOutputPending(head.CommitRef)
		if err != nil || pending {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("retire settled room object")
		}
		removed = true
	}
	if removed {
		return syncDirectory(filepath.Join(j.root, roomOutboxDir))
	}
	return nil
}

func (h RoomOutboxHead) allSettled() bool {
	for _, member := range h.Members {
		if !member.settled() {
			return false
		}
	}
	return true
}

// stagedOutputPending reports whether any staged output names this head's
// Commit. The journal mutex is held.
func (j *Journal) stagedOutputPending(commitRef string) (bool, error) {
	path, err := j.roomStagedPath(commitRef)
	if err != nil {
		return false, err
	}
	if _, err := os.Lstat(path); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, errors.New("read staged room output")
	}
	return false, nil
}

// resolveRoomStaged publishes or discards every staged output of a room (or
// of every room when roomID is empty) by the fused record's accepted Commit
// reference. It returns the paths of staged outputs that could not be read or
// judged; those are left in place. The journal mutex is held.
func (j *Journal) resolveRoomStaged(roomID string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(j.root, roomStagedDir))
	if err != nil {
		return nil, errors.New("read staged room output directory")
	}
	var unreadable []string
	for _, entry := range entries {
		if isTransitionTemp(entry.Name()) {
			continue
		}
		path := filepath.Join(j.root, roomStagedDir, entry.Name())
		staged, err := j.readRoomStaged(path)
		if err != nil {
			unreadable = append(unreadable, path)
			continue
		}
		if roomID != "" && staged.RoomID != roomID {
			continue
		}
		record, found, err := j.readRoomMLS(staged.RoomID)
		if err != nil {
			unreadable = append(unreadable, path)
			continue
		}
		if found && record.AcceptedCommitRef == staged.CommitRef {
			if err := j.publishStaged(staged); err != nil {
				return unreadable, err
			}
			continue
		}
		if err := removeStagedRecord(path); err != nil {
			return unreadable, errors.New("discard staged room output")
		}
	}
	if err := syncDirectory(filepath.Join(j.root, roomStagedDir)); err != nil {
		return unreadable, err
	}
	return unreadable, nil
}

// RoomOutboxHeads returns every outbox head of a room, ordered by MLS epoch
// and then the Commit or Welcome before the roster.
func (j *Journal) RoomOutboxHeads(roomID string) ([]RoomOutboxHead, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	if !ids.Room.MatchString(roomID) {
		return nil, errors.New("invalid room identifier")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	heads, err := j.readRoomHeads()
	if err != nil {
		return nil, err
	}
	var selected []RoomOutboxHead
	for _, head := range heads {
		if head.RoomID == roomID {
			selected = append(selected, head)
		}
	}
	sortRoomHeads(selected)
	return selected, nil
}

// RoomMemberQueue returns one member's unsettled handshake objects of a room
// in delivery order: by MLS epoch, the Commit or Welcome that makes each epoch
// before its roster. A removed member's single-deposit Commit is not part of
// any queue.
func (j *Journal) RoomMemberQueue(roomID, agentID string) ([]RoomOutboxHead, error) {
	if !ids.Agent.MatchString(agentID) {
		return nil, errors.New("invalid member identifier")
	}
	heads, err := j.RoomOutboxHeads(roomID)
	if err != nil {
		return nil, err
	}
	var queue []RoomOutboxHead
	for _, head := range heads {
		member, found := head.Member(agentID)
		if found && !member.Once && !member.settled() {
			queue = append(queue, head)
		}
	}
	return queue, nil
}

// RoomOutboxObject returns the bytes of an outbox object, verified against
// every chunk digest and the object digest.
func (j *Journal) RoomOutboxObject(objectDigest string) ([]byte, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	path, err := j.roomHeadPath(objectDigest)
	if err != nil {
		return nil, err
	}
	head, err := j.readRoomHead(path)
	if err != nil {
		return nil, err
	}
	return j.loadObject(head.ObjectDigest, head.Length, head.Chunks)
}

// RoomOutboxCarried records that a relay accepted deposit generation of an
// object to a member. The same generation may be recorded again (a retry
// after a crash); one that skips ahead is refused.
func (j *Journal) RoomOutboxCarried(objectDigest, agentID string, generation uint32, evidenceDigest string, nextRedeposit, now time.Time) (RoomOutboxHead, error) {
	if generation == 0 || !canon.ValidDigest(evidenceDigest) {
		return RoomOutboxHead{}, errors.New("invalid room object generation")
	}
	return j.updateRoomMember(objectDigest, agentID, now, func(member *RoomMemberDelivery, seconds uint64) error {
		if member.State != RoomDeliveryPending && member.State != RoomDeliveryCarried {
			return ErrNotPending
		}
		if member.Once && member.State == RoomDeliveryCarried {
			return ErrNotPending
		}
		if generation != member.Generation && (member.Generation == ^uint32(0) || generation != member.Generation+1) {
			return errors.New("room object generation does not follow the recorded one")
		}
		if !member.Once && nextRedeposit.Unix() <= now.Unix() {
			return errors.New("invalid room object re-deposit time")
		}
		member.State = RoomDeliveryCarried
		member.Generation = generation
		member.LastDepositAtUnix = seconds
		member.EvidenceDigest = evidenceDigest
		member.NextRedepositAtUnix = 0
		if !member.Once {
			member.NextRedepositAtUnix = uint64(nextRedeposit.Unix())
		} else {
			member.SettledAtUnix = seconds
		}
		return nil
	})
}

// RoomAckResult says what an applied room ack meant beyond its outcome.
type RoomAckResult struct {
	Head RoomOutboxHead
	// LostState is set when a member answered a Commit or roster with a
	// rejection that carries no MLS state: it lost its group state. The member
	// is settled rejected and the caller raises an owner notice.
	LostState bool
}

// RoomOutboxAcked applies a verified room ack. agentID is the authenticated
// packet sender whose own Endpoint signed the ack: an ack settles only that
// member's own slot, so a member can stop only its own queue.
//
// Accepted or duplicate settle the member as delivered; rejected settles it
// with the ack's code. A stateless rejection (no epoch authenticator, MLS
// epoch 0) is what a pending joiner sends to refuse its Welcome. For a Commit
// or roster it means the member lost its MLS state: it is applied as a
// rejection and reported as LostState.
func (j *Journal) RoomOutboxAcked(objectDigest, agentID string, outcome RoomAckOutcome, code fault.Code, stateless bool, now time.Time) (RoomAckResult, error) {
	switch outcome {
	case RoomAckAccepted, RoomAckDuplicate:
		if code != "" {
			return RoomAckResult{}, errors.New("a delivered room ack carries no code")
		}
		if stateless {
			return RoomAckResult{}, errors.New("only a rejection may carry no MLS state")
		}
	case RoomAckRejected:
		if !fault.Known(code) {
			return RoomAckResult{}, errors.New("a rejected room ack needs a known code")
		}
	default:
		return RoomAckResult{}, errors.New("unknown room ack outcome")
	}
	lost := false
	head, err := j.updateRoomMemberOf(objectDigest, agentID, now, func(head RoomOutboxHead, member *RoomMemberDelivery, seconds uint64) error {
		if member.Once {
			return errors.New("a removed member's Commit is not acknowledged")
		}
		if member.settled() {
			if member.AckOutcome == outcome && member.Code == code {
				return errRoomNoChange
			}
			return ErrNotPending
		}
		if member.State != RoomDeliveryCarried {
			return errors.New("a room ack for an object never carried")
		}
		lost = stateless && head.Type != RoomObjectWelcome
		member.AckOutcome = outcome
		member.Code = code
		member.NextRedepositAtUnix = 0
		member.SettledAtUnix = seconds
		if outcome == RoomAckRejected {
			member.State = RoomDeliveryRejected
		} else {
			member.State = RoomDeliveryDelivered
		}
		return nil
	})
	if err != nil {
		return RoomAckResult{}, err
	}
	return RoomAckResult{Head: head, LostState: lost}, nil
}

// RoomOutboxAbandon settles a member that can no longer be reached, for
// example after the handshake retention ran out (retention-exceeded).
func (j *Journal) RoomOutboxAbandon(objectDigest, agentID string, code fault.Code, now time.Time) (RoomOutboxHead, error) {
	if !fault.Known(code) {
		return RoomOutboxHead{}, errors.New("abandoning a room object needs a known code")
	}
	return j.updateRoomMember(objectDigest, agentID, now, func(member *RoomMemberDelivery, seconds uint64) error {
		if member.settled() {
			return ErrNotPending
		}
		member.State = RoomDeliveryAbandoned
		member.Code = code
		member.NextRedepositAtUnix = 0
		member.SettledAtUnix = seconds
		return nil
	})
}

var errRoomNoChange = errors.New("room outbox member is unchanged")

// updateRoomMember applies one member transition and writes the head, or
// deletes it once every member is settled: the head is a garbage-collection
// root only while some member may still need the object.
func (j *Journal) updateRoomMember(objectDigest, agentID string, now time.Time, change func(*RoomMemberDelivery, uint64) error) (RoomOutboxHead, error) {
	return j.updateRoomMemberOf(objectDigest, agentID, now, func(_ RoomOutboxHead, member *RoomMemberDelivery, seconds uint64) error {
		return change(member, seconds)
	})
}

// updateRoomMemberOf is updateRoomMember for a change that needs the head.
func (j *Journal) updateRoomMemberOf(objectDigest, agentID string, now time.Time, change func(RoomOutboxHead, *RoomMemberDelivery, uint64) error) (RoomOutboxHead, error) {
	if err := j.usable(); err != nil {
		return RoomOutboxHead{}, err
	}
	if !ids.Agent.MatchString(agentID) {
		return RoomOutboxHead{}, errors.New("invalid member identifier")
	}
	if now.IsZero() || now.Unix() <= 0 {
		return RoomOutboxHead{}, errors.New("invalid room outbox time")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	path, err := j.roomHeadPath(objectDigest)
	if err != nil {
		return RoomOutboxHead{}, err
	}
	head, err := j.readRoomHead(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return RoomOutboxHead{}, ErrUnknown
		}
		return RoomOutboxHead{}, err
	}
	index := -1
	for i := range head.Members {
		if head.Members[i].AgentID == agentID {
			index = i
		}
	}
	if index < 0 {
		return RoomOutboxHead{}, errors.New("room object is not addressed to this member")
	}
	if err := change(head, &head.Members[index], uint64(now.Unix())); err != nil {
		if errors.Is(err, errRoomNoChange) {
			return head, nil
		}
		return RoomOutboxHead{}, err
	}
	// A settled head is retired only once its staged output is gone: while the
	// staged record exists, restart would read a missing head as unpublished
	// and deposit the object again.
	pending, err := j.stagedOutputPending(head.CommitRef)
	if err != nil {
		return RoomOutboxHead{}, err
	}
	if !head.allSettled() || pending {
		if err := j.writeRoomHead(head); err != nil {
			return RoomOutboxHead{}, err
		}
		return head, nil
	}
	if err := os.Remove(path); err != nil {
		return RoomOutboxHead{}, errors.New("retire settled room object")
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return RoomOutboxHead{}, err
	}
	return head, nil
}

func sortRoomHeads(heads []RoomOutboxHead) {
	sort.SliceStable(heads, func(a, b int) bool {
		if heads[a].MLSEpoch != heads[b].MLSEpoch {
			return heads[a].MLSEpoch < heads[b].MLSEpoch
		}
		if heads[a].Type.queueRank() != heads[b].Type.queueRank() {
			return heads[a].Type.queueRank() < heads[b].Type.queueRank()
		}
		return heads[a].ObjectDigest < heads[b].ObjectDigest
	})
}

func (j *Journal) roomHeadPath(objectDigest string) (string, error) {
	if !canon.HashPattern.MatchString(objectDigest) {
		return "", errors.New("invalid room object digest")
	}
	return filepath.Join(j.root, roomOutboxDir, objectDigest+".json"), nil
}

func (j *Journal) roomStagedPath(commitRef string) (string, error) {
	value, err := digestHex(commitRef)
	if err != nil {
		return "", err
	}
	return filepath.Join(j.root, roomStagedDir, value+".json"), nil
}

func (j *Journal) writeRoomHead(head RoomOutboxHead) error {
	if err := validateRoomHead(head); err != nil {
		return err
	}
	encoded, err := json.Marshal(head)
	if err != nil {
		return err
	}
	path, err := j.roomHeadPath(head.ObjectDigest)
	if err != nil {
		return err
	}
	return j.replace(path, encoded)
}

func (j *Journal) readRoomHead(path string) (RoomOutboxHead, error) {
	raw, err := readRecordBytes(path)
	if err != nil {
		return RoomOutboxHead{}, err
	}
	var head RoomOutboxHead
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&head); err != nil {
		return RoomOutboxHead{}, errors.New("invalid room outbox head")
	}
	if err := validateRoomHead(head); err != nil {
		return RoomOutboxHead{}, err
	}
	if filepath.Base(path) != head.ObjectDigest+".json" {
		return RoomOutboxHead{}, errors.New("room outbox head names another object")
	}
	return head, nil
}

// readRoomHeads reads every head. Any unreadable head fails the listing,
// because a missing head could be a member's next Commit. The journal mutex
// is held.
func (j *Journal) readRoomHeads() ([]RoomOutboxHead, error) {
	entries, err := os.ReadDir(filepath.Join(j.root, roomOutboxDir))
	if err != nil {
		return nil, errors.New("read room outbox")
	}
	heads := make([]RoomOutboxHead, 0, len(entries))
	for _, entry := range entries {
		if isTransitionTemp(entry.Name()) {
			continue
		}
		head, err := j.readRoomHead(filepath.Join(j.root, roomOutboxDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		heads = append(heads, head)
	}
	return heads, nil
}

func (j *Journal) readRoomStaged(path string) (roomStagedOutput, error) {
	raw, err := readRecordBytes(path)
	if err != nil {
		return roomStagedOutput{}, err
	}
	var staged roomStagedOutput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&staged); err != nil || staged.Schema != roomStagedOutputSchema ||
		!ids.Room.MatchString(staged.RoomID) || !canon.ValidDigest(staged.CommitRef) ||
		len(staged.Heads) == 0 || len(staged.Heads) > MaxStagedRoomObjects {
		return roomStagedOutput{}, errors.New("invalid staged room output")
	}
	expected, err := j.roomStagedPath(staged.CommitRef)
	if err != nil || expected != path {
		return roomStagedOutput{}, errors.New("staged room output names another Commit")
	}
	for _, head := range staged.Heads {
		if err := validateRoomHead(head); err != nil {
			return roomStagedOutput{}, err
		}
		if head.RoomID != staged.RoomID || head.CommitRef != staged.CommitRef {
			return roomStagedOutput{}, errors.New("staged room head names another Commit")
		}
	}
	return staged, nil
}

func validateRoomHead(head RoomOutboxHead) error {
	if head.Schema != roomOutboxHeadSchema || !canon.HashPattern.MatchString(head.ObjectDigest) || !head.Type.handshake() ||
		!ids.Room.MatchString(head.RoomID) || head.RoomEpoch == 0 || !canon.ValidDigest(head.CommitRef) {
		return errors.New("invalid room outbox head")
	}
	if head.Length == 0 || head.Length > MaxRoomObjectBytes || len(head.Chunks) == 0 || len(head.Chunks) > MaxRoomObjectChunks ||
		uint64(len(head.Chunks)) != (uint64(head.Length)+RoomObjectChunkBytes-1)/RoomObjectChunkBytes {
		return errors.New("invalid room outbox head chunks")
	}
	for _, chunk := range head.Chunks {
		if !canon.ValidDigest(chunk) {
			return errors.New("invalid room outbox head chunk")
		}
	}
	if head.CreatedAtUnix == 0 || head.RetainUntilUnix <= head.CreatedAtUnix {
		return errors.New("invalid room outbox head times")
	}
	if len(head.Members) == 0 || len(head.Members) > MaxRoomObjectRecipients {
		return errors.New("invalid room outbox head members")
	}
	for index, member := range head.Members {
		if !ids.Agent.MatchString(member.AgentID) || (index > 0 && member.AgentID <= head.Members[index-1].AgentID) {
			return errors.New("invalid room outbox head member")
		}
		if member.Once && head.Type != RoomObjectCommit {
			return errors.New("invalid room outbox single-deposit member")
		}
		switch member.State {
		case RoomDeliveryPending:
			if member.Generation != 0 {
				return errors.New("invalid pending room delivery")
			}
		case RoomDeliveryCarried, RoomDeliveryDelivered, RoomDeliveryRejected:
			if member.Generation == 0 || !canon.ValidDigest(member.EvidenceDigest) {
				return errors.New("invalid carried room delivery")
			}
		case RoomDeliveryAbandoned:
		default:
			return errors.New("invalid room delivery state")
		}
		if member.Code != "" && !fault.Known(member.Code) {
			return errors.New("invalid room delivery code")
		}
		switch member.AckOutcome {
		case "", RoomAckAccepted, RoomAckDuplicate, RoomAckRejected:
		default:
			return errors.New("invalid room delivery ack outcome")
		}
	}
	return nil
}
