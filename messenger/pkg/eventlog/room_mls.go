package eventlog

// The fused room and MLS record is the single commit point of a private room.
//
// A room advance used to be two writes, the membership epoch and the opaque
// MLS state, each refusing a repeat; a crash between them stranded the room in
// an epoch only one of them knew. The fused record holds both clocks, the
// membership, its authorization and the commit references in one small file,
// and names by digest everything large: the MLS state chunks, the authority
// delegation and the memberships of the two earlier room epochs. Those are
// staged first (room_chunks.go), so the rename of this one record either
// happens, and the whole advance stands, or does not, and the old one does.
//
// The record is capped at MaxRoomMLSRecordBytes on write and on read. A
// record near the general 768 KiB bound would become unreadable as soon as a
// field was added; this one leaves that bound almost entirely unused.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/room"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

const (
	roomMLSDir = "room-mls"

	// RoomMLSRecordSchema is the on-disk schema of the fused record.
	RoomMLSRecordSchema = "tos.messaging.room-mls-record.v1"
	// MaxRoomMLSRecordBytes caps one encoded fused record.
	MaxRoomMLSRecordBytes = 8192
	// MaxMLSStateBytes bounds the opaque MLS state, as the driver does.
	MaxMLSStateBytes = 512 << 10
	// RetainedRoomEpochs is how many epochs a member keeps the epoch
	// authenticator and the membership of: the current one and the two before
	// it, which is as far back as it can still open (max_past_epochs 2).
	RetainedRoomEpochs = 3
)

// beforeRoomPublish, when set by a test, runs between the fused write and the
// publication of a Commit's output: the crash window restart recovery closes.
var beforeRoomPublish func() error

// roomMLSRecordCap is the cap the codec enforces. It is MaxRoomMLSRecordBytes;
// tests lower it to show that both the write and the read path refuse a record
// above it, which a valid record at the real cap cannot reach.
var roomMLSRecordCap = MaxRoomMLSRecordBytes

var (
	ErrMLSRollback        = errors.New("MLS state regressed")
	ErrMLSGap             = errors.New("MLS state skipped an epoch")
	ErrMLSFork            = errors.New("MLS commit is not a child of the accepted state")
	ErrKeyPackageConsumed = errors.New("MLS KeyPackage was already consumed")
	ErrWelcomeReplay      = errors.New("MLS Welcome was already processed")
	// ErrRoomMLSRecordTooLarge reports a fused record above its cap.
	ErrRoomMLSRecordTooLarge = errors.New("fused room record exceeds its bound")
	// ErrNotRoomAuthority reports a membership change authorized by anyone
	// but the room's recorded authority.
	ErrNotRoomAuthority = errors.New("only the current room authority may advance membership")
	// ErrRoomKind reports an operation of one room ledger on a room the other
	// ledger holds. A private MLS room and a logical room never share an ID.
	ErrRoomKind = errors.New("room is held by the other room ledger")
)

// EpochAuthenticator is the RFC 9420 epoch authenticator of one MLS epoch.
type EpochAuthenticator struct {
	MLSEpoch         uint64 `json:"mls_epoch"`
	AuthenticatorHex string `json:"authenticator_hex"`
}

type roomAuthorizationRecord struct {
	NetworkID            string `json:"network_id"`
	GenesisRootHash      string `json:"genesis_root_hash"`
	GenesisFileHash      string `json:"genesis_file_hash"`
	Epoch                uint64 `json:"epoch"`
	MembershipDigest     string `json:"membership_digest"`
	AgentID              string `json:"agent_id"`
	EndpointID           string `json:"messaging_endpoint_id"`
	IssuedAtUnix         uint64 `json:"issued_at_unix"`
	ExpiresAtUnix        uint64 `json:"expires_at_unix"`
	EndpointSignatureHex string `json:"endpoint_signature_hex"`
}

// RoomMLSRecord is the fused record of one private room.
type RoomMLSRecord struct {
	Schema           string   `json:"schema"`
	RoomID           string   `json:"room_id"`
	RoomEpoch        uint64   `json:"room_epoch"`
	MLSEpoch         uint64   `json:"mls_epoch"`
	MembershipDigest string   `json:"membership_digest"`
	Members          []string `json:"members"`
	// PriorMemberships names the staged memberships of the earlier retained
	// room epochs, newest first.
	PriorMemberships    []string                `json:"prior_membership_digests,omitempty"`
	AuthorityAgentID    string                  `json:"authority_agent_id"`
	AuthorityEndpointID string                  `json:"authority_messaging_endpoint_id"`
	Authorization       roomAuthorizationRecord `json:"authorization"`
	PriorCommitRef      string                  `json:"prior_commit_ref,omitempty"`
	AcceptedCommitRef   string                  `json:"accepted_commit_ref,omitempty"`
	StateDigest         string                  `json:"state_digest"`
	StateChunks         []string                `json:"state_chunk_digests"`
	DelegationDigest    string                  `json:"delegation_digest"`
	KeyPackageRef       string                  `json:"consumed_key_package_ref"`
	WelcomeRef          string                  `json:"processed_welcome_ref,omitempty"`
	// EpochAuthenticators are those of the current and earlier retained MLS
	// epochs, newest first.
	EpochAuthenticators []EpochAuthenticator `json:"epoch_authenticators"`
	UpdatedAtUnix       uint64               `json:"updated_at_unix"`
}

// Binding returns the public application binding of the record's MLS state.
func (r RoomMLSRecord) Binding() group.State {
	return group.State{RoomID: r.RoomID, Clock: group.Clock{RoomEpoch: r.RoomEpoch, MLSEpoch: r.MLSEpoch}, MembershipDigest: r.MembershipDigest, AcceptedCommitRef: r.AcceptedCommitRef}
}

// Membership returns the committed membership of the current room epoch.
func (r RoomMLSRecord) Membership() room.Membership {
	return room.Membership{RoomID: r.RoomID, Epoch: r.RoomEpoch, Members: append([]string(nil), r.Members...), Digest: r.MembershipDigest}
}

// Authority returns the room's single serializer.
func (r RoomMLSRecord) Authority() room.Authority {
	return room.Authority{AgentID: r.AuthorityAgentID, EndpointID: r.AuthorityEndpointID}
}

// MembershipAuthorization returns the authorization of the current epoch.
func (r RoomMLSRecord) MembershipAuthorization() (room.MembershipAuthorization, error) {
	return r.Authorization.decode(r.RoomID)
}

// EpochAuthenticatorAt returns the retained epoch authenticator of an MLS
// epoch, if the record still holds it.
func (r RoomMLSRecord) EpochAuthenticatorAt(mlsEpoch uint64) ([]byte, bool) {
	for _, entry := range r.EpochAuthenticators {
		if entry.MLSEpoch == mlsEpoch {
			value, err := hex.DecodeString(entry.AuthenticatorHex)
			if err != nil || len(value) != group.MLSEpochAuthenticatorBytes {
				return nil, false
			}
			return value, true
		}
	}
	return nil, false
}

func encodeAuthorization(value room.MembershipAuthorization) roomAuthorizationRecord {
	record := roomAuthorizationRecord{
		Epoch: value.Epoch, MembershipDigest: value.MembershipDigest,
		AgentID: value.Authority.AgentID, EndpointID: value.Authority.EndpointID,
		IssuedAtUnix: value.IssuedAtUnix, ExpiresAtUnix: value.ExpiresAtUnix,
		EndpointSignatureHex: hex.EncodeToString(value.EndpointSignature),
	}
	if value.Network != nil {
		record.NetworkID = value.Network.NetworkId
		record.GenesisRootHash = value.Network.GenesisRootHash
		record.GenesisFileHash = value.Network.GenesisFileHash
	}
	return record
}

func (a roomAuthorizationRecord) decode(roomID string) (room.MembershipAuthorization, error) {
	signature, err := hex.DecodeString(a.EndpointSignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return room.MembershipAuthorization{}, errors.New("invalid stored room authorization signature")
	}
	return room.MembershipAuthorization{
		Network:          &nativev1.NetworkDomain{NetworkId: a.NetworkID, GenesisRootHash: a.GenesisRootHash, GenesisFileHash: a.GenesisFileHash},
		RoomID:           roomID,
		Epoch:            a.Epoch,
		MembershipDigest: a.MembershipDigest,
		Authority:        room.Authority{AgentID: a.AgentID, EndpointID: a.EndpointID},
		IssuedAtUnix:     a.IssuedAtUnix, ExpiresAtUnix: a.ExpiresAtUnix,
		EndpointSignature: signature,
	}, nil
}

// RoomAuthorityProof is what makes a room epoch: the membership, the
// authority's authorization of exactly it, and the authority's delegation.
// The caller has already judged the authorization current under the route's
// window; the ledger checks its binding and signature, never its time.
type RoomAuthorityProof struct {
	Membership    room.Membership
	Authorization room.MembershipAuthorization
	Delegation    identity.Delegation
}

func (p RoomAuthorityProof) verify() ([]byte, error) {
	if err := room.VerifyMembershipAuthorizationBinding(p.Membership, p.Authorization, p.Delegation); err != nil {
		return nil, err
	}
	if len(p.Membership.Members) > group.MaxPrivateRoomAgents {
		return nil, errors.New("private room exceeds its Agent bound")
	}
	encoded, err := json.Marshal(p.Delegation)
	if err != nil {
		return nil, errors.New("encode room authority delegation")
	}
	if len(encoded) > MaxRoomDelegationBytes {
		return nil, errors.New("room authority delegation exceeds its bound")
	}
	return encoded, nil
}

// RoomMLSInstall installs the first state of a private room at this
// installation: the founder's own group, or a joiner's group from a Welcome.
type RoomMLSInstall struct {
	Binding            group.State
	Proof              RoomAuthorityProof
	State              []byte
	EpochAuthenticator []byte
	KeyPackageRef      string
	// WelcomeRef is the digest of the processed Welcome; empty for a founder.
	WelcomeRef string
}

// RoomMLSAdvance moves a room by exactly one MLS epoch. Proof is required
// exactly when the room epoch changes.
type RoomMLSAdvance struct {
	Transition          group.Transition
	Proof               *RoomAuthorityProof
	ExpectedStateDigest string
	State               []byte
	EpochAuthenticator  []byte
	// Output is the authority's Commit output. It is staged under the Commit
	// reference before the fused write and published right after it, all
	// under one hold of the journal, so it is published once or discarded.
	Output *RoomCommitOutput
}

// RoomCommitOutput is what the authority publishes for one Commit.
type RoomCommitOutput struct {
	Objects     []StagedRoomObject
	RetainUntil time.Time
}

// RoomMLSLedger holds the fused records of private rooms.
type RoomMLSLedger struct{ journal *Journal }

// OpenRoomMLS returns the fused room ledger of this installation.
func (j *Journal) OpenRoomMLS() (*RoomMLSLedger, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	return &RoomMLSLedger{journal: j}, nil
}

// InstallFounder records the founder's first state of a room it created. The
// founder's own KeyPackage is consumed so its private material is never reused
// as a join token.
func (l *RoomMLSLedger) InstallFounder(install RoomMLSInstall, now time.Time) (RoomMLSRecord, error) {
	if install.WelcomeRef != "" || install.Binding.Clock.MLSEpoch != 0 || install.Binding.AcceptedCommitRef != "" {
		return RoomMLSRecord{}, errors.New("a founder state is MLS epoch zero with no Welcome")
	}
	return l.install(install, now)
}

// InstallWelcome records a joiner's state from a processed Welcome, consuming
// its one-time KeyPackage and recording the Welcome, in one write.
func (l *RoomMLSLedger) InstallWelcome(install RoomMLSInstall, now time.Time) (RoomMLSRecord, error) {
	if !canon.ValidDigest(install.WelcomeRef) {
		return RoomMLSRecord{}, errors.New("invalid processed Welcome reference")
	}
	return l.install(install, now)
}

func (l *RoomMLSLedger) install(install RoomMLSInstall, now time.Time) (RoomMLSRecord, error) {
	if l == nil {
		return RoomMLSRecord{}, errors.New("no fused room ledger")
	}
	if err := l.journal.usable(); err != nil {
		return RoomMLSRecord{}, err
	}
	if err := validMLSTime(now); err != nil {
		return RoomMLSRecord{}, err
	}
	binding := install.Binding
	if !ids.Room.MatchString(binding.RoomID) || binding.Clock.RoomEpoch == 0 || !canon.ValidDigest(install.KeyPackageRef) ||
		(binding.AcceptedCommitRef != "" && !canon.ValidDigest(binding.AcceptedCommitRef)) {
		return RoomMLSRecord{}, errors.New("invalid initial MLS binding")
	}
	membership := install.Proof.Membership
	if membership.RoomID != binding.RoomID || membership.Epoch != binding.Clock.RoomEpoch || membership.Digest != binding.MembershipDigest {
		return RoomMLSRecord{}, errors.New("initial MLS binding names another membership")
	}
	delegationJSON, err := install.Proof.verify()
	if err != nil {
		return RoomMLSRecord{}, err
	}
	if err := validateOpaqueMLS(install.State); err != nil {
		return RoomMLSRecord{}, err
	}
	authenticator, err := validEpochAuthenticator(install.EpochAuthenticator)
	if err != nil {
		return RoomMLSRecord{}, err
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	if err := l.journal.refuseLegacyRoom(binding.RoomID); err != nil {
		return RoomMLSRecord{}, err
	}
	consumed, err := l.keyPackageConsumed(install.KeyPackageRef)
	if err != nil {
		return RoomMLSRecord{}, err
	}
	existing, found, err := l.read(binding.RoomID)
	if err != nil {
		return RoomMLSRecord{}, err
	}
	if found {
		if install.WelcomeRef != "" && existing.WelcomeRef == install.WelcomeRef {
			return RoomMLSRecord{}, ErrWelcomeReplay
		}
		if existing.KeyPackageRef == install.KeyPackageRef {
			return RoomMLSRecord{}, ErrKeyPackageConsumed
		}
		return RoomMLSRecord{}, ErrMLSFork
	}
	if consumed {
		return RoomMLSRecord{}, ErrKeyPackageConsumed
	}
	record := RoomMLSRecord{
		Schema: RoomMLSRecordSchema, RoomID: binding.RoomID,
		RoomEpoch: binding.Clock.RoomEpoch, MLSEpoch: binding.Clock.MLSEpoch,
		MembershipDigest: membership.Digest, Members: append([]string(nil), membership.Members...),
		AuthorityAgentID:    install.Proof.Authorization.Authority.AgentID,
		AuthorityEndpointID: install.Proof.Authorization.Authority.EndpointID,
		Authorization:       encodeAuthorization(install.Proof.Authorization),
		AcceptedCommitRef:   binding.AcceptedCommitRef,
		KeyPackageRef:       install.KeyPackageRef, WelcomeRef: install.WelcomeRef,
		EpochAuthenticators: []EpochAuthenticator{{MLSEpoch: binding.Clock.MLSEpoch, AuthenticatorHex: hex.EncodeToString(authenticator)}},
		UpdatedAtUnix:       uint64(now.Unix()),
	}
	return l.commit(record, nil, install.State, delegationJSON)
}

// Advance installs exactly one MLS child of the durable state. An exact
// repeat of the accepted advance (same membership digest, authorization and
// commit reference) is a no-op reported as not fresh; another child of the
// same parent is a fork, never "last arrival wins".
func (l *RoomMLSLedger) Advance(advance RoomMLSAdvance, now time.Time) (bool, RoomMLSRecord, error) {
	if l == nil {
		return false, RoomMLSRecord{}, errors.New("no fused room ledger")
	}
	if err := l.journal.usable(); err != nil {
		return false, RoomMLSRecord{}, err
	}
	if err := validMLSTime(now); err != nil {
		return false, RoomMLSRecord{}, err
	}
	transition := advance.Transition
	// An exact repeat of the accepted advance is answered before the
	// transition is judged: after a crash the caller no longer holds the
	// prior binding it was made from, only the Commit it is repeating.
	if repeat, current, err := l.repeat(transition, advance.Proof); err != nil || repeat {
		return false, current, err
	}
	if err := group.ValidateTransition(transition); err != nil {
		return false, RoomMLSRecord{}, err
	}
	roomChange := transition.Next.Clock.RoomEpoch != transition.Prior.Clock.RoomEpoch
	var delegationJSON []byte
	if roomChange {
		if advance.Proof == nil {
			return false, RoomMLSRecord{}, errors.New("a room epoch change needs its authorization")
		}
		proof := *advance.Proof
		if proof.Membership.RoomID != transition.Membership.RoomID || proof.Membership.Epoch != transition.Membership.Epoch || proof.Membership.Digest != transition.Next.MembershipDigest {
			return false, RoomMLSRecord{}, errors.New("authorization names another membership than the transition")
		}
		encoded, err := proof.verify()
		if err != nil {
			return false, RoomMLSRecord{}, err
		}
		delegationJSON = encoded
	} else if advance.Proof != nil {
		return false, RoomMLSRecord{}, errors.New("an MLS-only advance carries no authorization")
	}
	if !canon.ValidDigest(advance.ExpectedStateDigest) {
		return false, RoomMLSRecord{}, errors.New("invalid prior MLS state digest")
	}
	if err := validateOpaqueMLS(advance.State); err != nil {
		return false, RoomMLSRecord{}, err
	}
	authenticator, err := validEpochAuthenticator(advance.EpochAuthenticator)
	if err != nil {
		return false, RoomMLSRecord{}, err
	}
	if advance.Output != nil && transition.Next.Clock.MLSEpoch == 0 {
		return false, RoomMLSRecord{}, errors.New("invalid Commit output epoch")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	// A previous Commit's output is published or discarded before anything
	// moves, so a later Commit never overtakes an earlier one's objects.
	if err := l.journal.requireRoomStagedResolved(transition.Next.RoomID); err != nil {
		return false, RoomMLSRecord{}, err
	}
	current, found, err := l.read(transition.Next.RoomID)
	if err != nil {
		return false, RoomMLSRecord{}, err
	}
	if !found {
		return false, RoomMLSRecord{}, errors.New("MLS room has no installed state")
	}
	if current.IsRepeatOf(transition, advance.Proof) {
		return false, current, nil
	}
	if current.StateDigest != advance.ExpectedStateDigest {
		return false, RoomMLSRecord{}, ErrMLSFork
	}
	binding := current.Binding()
	switch next := transition.Next.Clock.MLSEpoch; {
	case next == binding.Clock.MLSEpoch:
		return false, RoomMLSRecord{}, ErrMLSFork
	case next < binding.Clock.MLSEpoch:
		return false, RoomMLSRecord{}, ErrMLSRollback
	case binding.Clock.MLSEpoch == ^uint64(0) || next != binding.Clock.MLSEpoch+1:
		return false, RoomMLSRecord{}, ErrMLSGap
	}
	if !sameGroupState(binding, transition.Prior) {
		return false, RoomMLSRecord{}, ErrMLSFork
	}
	next := current
	next.RoomEpoch = transition.Next.Clock.RoomEpoch
	next.MLSEpoch = transition.Next.Clock.MLSEpoch
	next.PriorCommitRef = current.AcceptedCommitRef
	next.AcceptedCommitRef = transition.CommitRef
	next.UpdatedAtUnix = uint64(now.Unix())
	next.EpochAuthenticators = retainAuthenticators(EpochAuthenticator{MLSEpoch: next.MLSEpoch, AuthenticatorHex: hex.EncodeToString(authenticator)}, current.EpochAuthenticators)
	if roomChange {
		proof := *advance.Proof
		if proof.Authorization.Authority.AgentID != current.AuthorityAgentID || proof.Authorization.Authority.EndpointID != current.AuthorityEndpointID {
			return false, RoomMLSRecord{}, ErrNotRoomAuthority
		}
		next.MembershipDigest = proof.Membership.Digest
		next.Members = append([]string(nil), proof.Membership.Members...)
		next.Authorization = encodeAuthorization(proof.Authorization)
		next.PriorMemberships = retainMemberships(current.MembershipDigest, current.PriorMemberships)
	}
	var staged []RoomOutboxHead
	if advance.Output != nil {
		for _, object := range advance.Output.Objects {
			if object.MLSEpoch != next.MLSEpoch {
				return false, RoomMLSRecord{}, errors.New("a Commit output object names another MLS epoch")
			}
		}
		staged, err = l.journal.stageRoomOutput(next.RoomID, transition.CommitRef, advance.Output.Objects, advance.Output.RetainUntil, now)
		if err != nil {
			return false, RoomMLSRecord{}, err
		}
	}
	// commit stages the membership being left behind before the write that
	// names it, so a member can still judge the epochs it can open.
	written, err := l.commit(next, &current, advance.State, delegationJSON)
	if err != nil {
		return false, RoomMLSRecord{}, err
	}
	if advance.Output != nil {
		if beforeRoomPublish != nil {
			if err := beforeRoomPublish(); err != nil {
				return true, written, err
			}
		}
		output := roomStagedOutput{Schema: roomStagedOutputSchema, RoomID: next.RoomID, CommitRef: transition.CommitRef, StagedAtUnix: uint64(now.Unix()), Heads: staged}
		if err := l.journal.publishStaged(output); err != nil {
			return true, written, err
		}
	}
	return true, written, nil
}

// Ratchet replaces the private MLS state without changing the public binding,
// as every Seal and Open does. expectedStateDigest is the compare-and-swap
// token from Current, so two concurrent operations from the same state cannot
// overwrite each other.
func (l *RoomMLSLedger) Ratchet(roomID, expectedStateDigest string, state []byte, now time.Time) (bool, RoomMLSRecord, error) {
	if l == nil {
		return false, RoomMLSRecord{}, errors.New("no fused room ledger")
	}
	if err := l.journal.usable(); err != nil {
		return false, RoomMLSRecord{}, err
	}
	if !ids.Room.MatchString(roomID) || !canon.ValidDigest(expectedStateDigest) {
		return false, RoomMLSRecord{}, errors.New("invalid MLS ratchet binding")
	}
	if err := validMLSTime(now); err != nil {
		return false, RoomMLSRecord{}, err
	}
	if err := validateOpaqueMLS(state); err != nil {
		return false, RoomMLSRecord{}, err
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	current, found, err := l.read(roomID)
	if err != nil {
		return false, RoomMLSRecord{}, err
	}
	if !found {
		return false, RoomMLSRecord{}, errors.New("MLS room has no installed state")
	}
	if current.StateDigest != expectedStateDigest {
		return false, RoomMLSRecord{}, ErrMLSFork
	}
	if canon.Digest(state) == current.StateDigest {
		return false, current, nil
	}
	next := current
	next.UpdatedAtUnix = uint64(now.Unix())
	written, err := l.commit(next, &current, state, nil)
	if err != nil {
		return false, RoomMLSRecord{}, err
	}
	return true, written, nil
}

// Current returns the verified fused record of a room.
func (l *RoomMLSLedger) Current(roomID string) (RoomMLSRecord, bool, error) {
	if l == nil {
		return RoomMLSRecord{}, false, errors.New("no fused room ledger")
	}
	if err := l.journal.usable(); err != nil {
		return RoomMLSRecord{}, false, err
	}
	if !ids.Room.MatchString(roomID) {
		return RoomMLSRecord{}, false, errors.New("invalid MLS room")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	return l.read(roomID)
}

// State reassembles the opaque MLS state a record names, verifying every
// chunk digest and the state digest.
func (l *RoomMLSLedger) State(record RoomMLSRecord) ([]byte, error) {
	if l == nil {
		return nil, errors.New("no fused room ledger")
	}
	if err := l.journal.usable(); err != nil {
		return nil, err
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	return l.journal.loadMLSState(record.RoomID, record.StateDigest, record.StateChunks)
}

// Delegation returns the authority delegation a record names.
func (l *RoomMLSLedger) Delegation(record RoomMLSRecord) (identity.Delegation, error) {
	if l == nil {
		return identity.Delegation{}, errors.New("no fused room ledger")
	}
	if err := l.journal.usable(); err != nil {
		return identity.Delegation{}, err
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	raw, err := l.journal.loadDelegation(record.DelegationDigest)
	if err != nil {
		return identity.Delegation{}, err
	}
	return decodeRoomAuthorityDelegation(raw)
}

// MembershipAt returns the committed membership of a retained room epoch:
// the current one or one of the two before it.
func (l *RoomMLSLedger) MembershipAt(roomID string, roomEpoch uint64) (room.Membership, bool, error) {
	record, found, err := l.Current(roomID)
	if err != nil || !found {
		return room.Membership{}, false, err
	}
	if roomEpoch == record.RoomEpoch {
		return record.Membership(), true, nil
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	for _, digest := range record.PriorMemberships {
		membership, err := l.journal.loadMembership(digest)
		if err != nil {
			return room.Membership{}, false, err
		}
		if membership.RoomID != roomID {
			return room.Membership{}, false, errors.New("retained membership names another room")
		}
		if membership.Epoch == roomEpoch {
			return membership, true, nil
		}
	}
	return room.Membership{}, false, nil
}

// repeat reports whether a transition repeats the room's accepted advance.
func (l *RoomMLSLedger) repeat(transition group.Transition, proof *RoomAuthorityProof) (bool, RoomMLSRecord, error) {
	if !ids.Room.MatchString(transition.Next.RoomID) {
		return false, RoomMLSRecord{}, errors.New("invalid MLS room")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	current, found, err := l.read(transition.Next.RoomID)
	if err != nil || !found {
		return false, RoomMLSRecord{}, err
	}
	if current.IsRepeatOf(transition, proof) {
		// A retry of an advance whose publication failed publishes it now;
		// a repeat is answered only once its output is published.
		if err := l.journal.requireRoomStagedResolved(transition.Next.RoomID); err != nil {
			return false, RoomMLSRecord{}, err
		}
		return true, current, nil
	}
	return false, RoomMLSRecord{}, nil
}

// IsRepeatOf reports whether a transition is exactly the advance this record
// already accepted: the same membership digest, authorization and Commit
// reference. Such a repeat is a no-op answered duplicate.
func (current RoomMLSRecord) IsRepeatOf(transition group.Transition, proof *RoomAuthorityProof) bool {
	if current.AcceptedCommitRef == "" || current.AcceptedCommitRef != transition.CommitRef || current.MembershipDigest != transition.Next.MembershipDigest ||
		current.RoomEpoch != transition.Next.Clock.RoomEpoch || current.MLSEpoch != transition.Next.Clock.MLSEpoch {
		return false
	}
	if proof == nil {
		return true
	}
	stored, err := current.MembershipAuthorization()
	if err != nil {
		return false
	}
	return sameAuthorization(stored, proof.Authorization)
}

func sameAuthorization(a, b room.MembershipAuthorization) bool {
	return encodeAuthorization(a) == encodeAuthorization(b) && a.RoomID == b.RoomID
}

// commit stages what the record names, writes the record and then deletes
// the state chunks it superseded. The journal mutex is held.
func (l *RoomMLSLedger) commit(record RoomMLSRecord, previous *RoomMLSRecord, state, delegationJSON []byte) (RoomMLSRecord, error) {
	chunks, err := l.journal.stageMLSState(record.RoomID, state)
	if err != nil {
		return RoomMLSRecord{}, err
	}
	record.StateDigest = canon.Digest(state)
	record.StateChunks = chunks
	if delegationJSON != nil {
		digest, err := l.journal.stageDelegation(delegationJSON)
		if err != nil {
			return RoomMLSRecord{}, err
		}
		record.DelegationDigest = digest
	}
	if previous != nil && record.RoomEpoch != previous.RoomEpoch {
		if err := l.journal.stageMembership(previous.Membership()); err != nil {
			return RoomMLSRecord{}, err
		}
	}
	encoded, err := encodeRoomMLSRecord(record)
	if err != nil {
		return RoomMLSRecord{}, err
	}
	if err := l.journal.replace(l.path(record.RoomID), encoded); err != nil {
		return RoomMLSRecord{}, err
	}
	if previous != nil {
		l.journal.deleteSupersededState(record.RoomID, previous.StateChunks, record.StateChunks)
	}
	return record, nil
}

// deleteSupersededState removes the state chunks the record just written no
// longer names. A chunk the new state shares is kept. A failed removal is left
// for the restart collection, which deletes every chunk no root names.
func (j *Journal) deleteSupersededState(roomID string, previous, current []string) {
	keep := make(map[string]struct{}, len(current))
	for _, digest := range current {
		keep[digest] = struct{}{}
	}
	for _, digest := range previous {
		if _, kept := keep[digest]; kept {
			continue
		}
		path, err := j.roomStatePath(roomID, digest)
		if err != nil {
			continue
		}
		_ = os.Remove(path)
	}
}

func encodeRoomMLSRecord(record RoomMLSRecord) ([]byte, error) {
	if err := validateRoomMLSRecord(record); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if len(encoded) > roomMLSRecordCap {
		return nil, ErrRoomMLSRecordTooLarge
	}
	return encoded, nil
}

func decodeRoomMLSRecord(raw []byte) (RoomMLSRecord, error) {
	if len(raw) > roomMLSRecordCap+1 {
		return RoomMLSRecord{}, ErrRoomMLSRecordTooLarge
	}
	trimmed := bytes.TrimSuffix(raw, []byte("\n"))
	if len(trimmed) > roomMLSRecordCap {
		return RoomMLSRecord{}, ErrRoomMLSRecordTooLarge
	}
	var record RoomMLSRecord
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return RoomMLSRecord{}, errors.New("invalid fused room record")
	}
	if decoder.More() {
		return RoomMLSRecord{}, errors.New("invalid fused room record")
	}
	if err := validateRoomMLSRecord(record); err != nil {
		return RoomMLSRecord{}, err
	}
	return record, nil
}

// validateRoomMLSRecord checks everything a record states about itself: its
// shape, that its digest reproduces from its members, that its authorization
// names its membership and authority, and the reference fields. It does not
// read the records it names.
func validateRoomMLSRecord(record RoomMLSRecord) error {
	if record.Schema != RoomMLSRecordSchema || !ids.Room.MatchString(record.RoomID) || record.RoomEpoch == 0 {
		return errors.New("invalid fused room record binding")
	}
	if len(record.Members) == 0 || len(record.Members) > group.MaxPrivateRoomAgents {
		return errors.New("invalid fused room record membership")
	}
	digest, err := room.Digest(record.RoomID, record.RoomEpoch, record.Members)
	if err != nil || digest != record.MembershipDigest {
		return errors.New("fused room record's digest does not match its members")
	}
	if (room.Authority{AgentID: record.AuthorityAgentID, EndpointID: record.AuthorityEndpointID}).Validate() != nil ||
		!containsString(record.Members, record.AuthorityAgentID) {
		return errors.New("fused room record's authority is not a current member")
	}
	if record.Authorization.Epoch != record.RoomEpoch || record.Authorization.MembershipDigest != record.MembershipDigest ||
		record.Authorization.AgentID != record.AuthorityAgentID || record.Authorization.EndpointID != record.AuthorityEndpointID {
		return errors.New("fused room record's authorization names another membership")
	}
	if _, err := record.Authorization.decode(record.RoomID); err != nil {
		return err
	}
	if len(record.PriorMemberships) > RetainedRoomEpochs-1 {
		return errors.New("fused room record retains too many memberships")
	}
	for _, ref := range record.PriorMemberships {
		if !canon.ValidDigest(ref) || ref == record.MembershipDigest {
			return errors.New("invalid retained membership reference")
		}
	}
	for _, ref := range []string{record.PriorCommitRef, record.AcceptedCommitRef, record.WelcomeRef} {
		if ref != "" && !canon.ValidDigest(ref) {
			return errors.New("invalid fused room record reference")
		}
	}
	if !canon.ValidDigest(record.StateDigest) || !canon.ValidDigest(record.DelegationDigest) || !canon.ValidDigest(record.KeyPackageRef) {
		return errors.New("invalid fused room record reference")
	}
	if len(record.StateChunks) == 0 || len(record.StateChunks) > MaxMLSStateChunks {
		return errors.New("invalid fused room record state chunks")
	}
	for _, chunk := range record.StateChunks {
		if !canon.ValidDigest(chunk) {
			return errors.New("invalid fused room record state chunk")
		}
	}
	if len(record.EpochAuthenticators) == 0 || len(record.EpochAuthenticators) > RetainedRoomEpochs || record.EpochAuthenticators[0].MLSEpoch != record.MLSEpoch {
		return errors.New("invalid fused room record epoch authenticators")
	}
	for index, entry := range record.EpochAuthenticators {
		value, err := hex.DecodeString(entry.AuthenticatorHex)
		if err != nil || len(value) != group.MLSEpochAuthenticatorBytes || canon.IsZero(value) {
			return errors.New("invalid fused room record epoch authenticator")
		}
		if index > 0 && entry.MLSEpoch >= record.EpochAuthenticators[index-1].MLSEpoch {
			return errors.New("fused room record epoch authenticators are out of order")
		}
	}
	if record.UpdatedAtUnix == 0 {
		return errors.New("invalid fused room record time")
	}
	return nil
}

// read returns a room's fused record, verified: its own consistency, then
// that its delegation reproduces the named digest, then the authorization's
// binding and signature under that delegation. The journal mutex is held.
func (l *RoomMLSLedger) read(roomID string) (RoomMLSRecord, bool, error) {
	record, found, err := l.journal.readRoomMLS(roomID)
	if err != nil || !found {
		return RoomMLSRecord{}, found, err
	}
	raw, err := l.journal.loadDelegation(record.DelegationDigest)
	if err != nil {
		return RoomMLSRecord{}, false, err
	}
	delegation, err := decodeRoomAuthorityDelegation(raw)
	if err != nil {
		return RoomMLSRecord{}, false, err
	}
	authorization, err := record.MembershipAuthorization()
	if err != nil {
		return RoomMLSRecord{}, false, err
	}
	if err := room.VerifyMembershipAuthorizationBinding(record.Membership(), authorization, delegation); err != nil {
		return RoomMLSRecord{}, false, errors.New("fused room record's authorization does not verify")
	}
	return record, true, nil
}

// readRoomMLS reads and self-checks a fused record without the records it
// names. The journal mutex is held.
func (j *Journal) readRoomMLS(roomID string) (RoomMLSRecord, bool, error) {
	if !ids.Room.MatchString(roomID) {
		return RoomMLSRecord{}, false, errors.New("invalid MLS room")
	}
	path := filepath.Join(j.root, roomMLSDir, roomID[len("room_"):]+".json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return RoomMLSRecord{}, false, nil
	}
	if err != nil {
		return RoomMLSRecord{}, false, errors.New("read fused room record")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return RoomMLSRecord{}, false, errors.New("invalid fused room record file")
	}
	if info.Size() > int64(roomMLSRecordCap)+1 {
		return RoomMLSRecord{}, false, ErrRoomMLSRecordTooLarge
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return RoomMLSRecord{}, false, errors.New("read fused room record")
	}
	record, err := decodeRoomMLSRecord(raw)
	if err != nil {
		return RoomMLSRecord{}, false, err
	}
	if record.RoomID != roomID {
		return RoomMLSRecord{}, false, errors.New("fused room record describes another room")
	}
	return record, true, nil
}

func (l *RoomMLSLedger) path(roomID string) string {
	return filepath.Join(l.journal.root, roomMLSDir, roomID[len("room_"):]+".json")
}

// keyPackageConsumed reports whether any room at this installation consumed
// the KeyPackage. A KeyPackage is one-time across the installation, not within
// one group, so every fused record is read, and an unreadable one fails the
// check closed. The journal mutex is held.
func (l *RoomMLSLedger) keyPackageConsumed(ref string) (bool, error) {
	roomIDs, err := l.journal.fusedRoomIDs()
	if err != nil {
		return false, err
	}
	for _, roomID := range roomIDs {
		record, found, err := l.journal.readRoomMLS(roomID)
		if err != nil || !found {
			return false, errors.New("invalid fused room record")
		}
		if record.KeyPackageRef == ref {
			return true, nil
		}
	}
	return false, nil
}

// fusedRoomIDs lists the rooms with a fused record, refusing any file name in
// the directory that is not one.
func (j *Journal) fusedRoomIDs() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(j.root, roomMLSDir))
	if err != nil {
		return nil, errors.New("read fused room directory")
	}
	roomIDs := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if isTransitionTemp(name) {
			continue
		}
		if entry.IsDir() || filepath.Ext(name) != ".json" {
			return nil, errors.New("unexpected entry in the fused room directory")
		}
		roomID := "room_" + name[:len(name)-len(".json")]
		if !ids.Room.MatchString(roomID) {
			return nil, errors.New("unexpected entry in the fused room directory")
		}
		roomIDs = append(roomIDs, roomID)
	}
	return roomIDs, nil
}

func isTransitionTemp(name string) bool {
	return len(name) > len(".transition-") && name[:len(".transition-")] == ".transition-"
}

// refuseLegacyRoom refuses a fused install for a room the logical room
// ledger already holds. The journal mutex is held.
func (j *Journal) refuseLegacyRoom(roomID string) error {
	_, err := os.Lstat(filepath.Join(j.root, roomDir, roomID[len("room_"):]+".json"))
	if err == nil {
		return ErrRoomKind
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errors.New("read room record")
	}
	return nil
}

func retainAuthenticators(current EpochAuthenticator, previous []EpochAuthenticator) []EpochAuthenticator {
	retained := []EpochAuthenticator{current}
	for _, entry := range previous {
		if len(retained) == RetainedRoomEpochs {
			break
		}
		retained = append(retained, entry)
	}
	return retained
}

func retainMemberships(current string, previous []string) []string {
	retained := []string{current}
	for _, digest := range previous {
		if len(retained) == RetainedRoomEpochs-1 {
			break
		}
		retained = append(retained, digest)
	}
	return retained
}

func validEpochAuthenticator(value []byte) ([]byte, error) {
	if len(value) != group.MLSEpochAuthenticatorBytes || canon.IsZero(value) {
		return nil, errors.New("invalid MLS epoch authenticator")
	}
	return value, nil
}

func validMLSTime(now time.Time) error {
	if now.IsZero() || now.Unix() <= 0 {
		return errors.New("invalid MLS persistence time")
	}
	return nil
}

func validateOpaqueMLS(state []byte) error {
	if len(state) == 0 || len(state) > MaxMLSStateBytes || canon.IsZero(state) {
		return errors.New("invalid opaque MLS state")
	}
	return nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func sameGroupState(a, b group.State) bool {
	return a.RoomID == b.RoomID && a.Clock == b.Clock && a.MembershipDigest == b.MembershipDigest && a.AcceptedCommitRef == b.AcceptedCommitRef
}
