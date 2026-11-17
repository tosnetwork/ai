package eventlog

// RoomMLSController is the crash-consistency boundary between the MLS driver
// and the fused room ledger. Driver output is never returned to the caller
// until the state it produced is durable: a Commit's objects are published by
// the same journal write that advances the room, and a Seal's ciphertext is
// returned only after its sender ratchet step is recorded. A message or Commit
// whose sender is not the expected member is refused before anything is
// written, so content cannot spend a ratchet step under another's name.
//
// The controller serves relay rooms only, so every leaf it handles carries
// the 128-byte compact identity of section 11.2: the founder's own leaf, every
// leaf a Commit adds, updates or removes, and the leaf a caller expects as a
// committer or sender. Any other identity is refused before the driver runs.

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/group"
)

// ErrMLSSenderMismatch reports a Commit or message whose MLS sender is not
// the member the caller authenticated at the transport.
var ErrMLSSenderMismatch = errors.New("MLS sender is not the authenticated member")

type RoomMLSController struct {
	ledger  *RoomMLSLedger
	driver  group.AttributedDriver
	inspect group.StateInspector
	now     func() time.Time
}

// NewRoomMLSController binds a driver that attributes messages and exposes
// its state binding.
func NewRoomMLSController(ledger *RoomMLSLedger, driver group.AttributedDriver, now func() time.Time) (*RoomMLSController, error) {
	inspector, ok := driver.(group.StateInspector)
	if ledger == nil || driver == nil || !ok || driver.CipherSuite() != group.MLSCipherSuite {
		return nil, errors.New("invalid room MLS controller dependencies")
	}
	if now == nil {
		now = time.Now
	}
	return &RoomMLSController{ledger: ledger, driver: driver, inspect: inspector, now: now}, nil
}

// CommitResult is the driver output of one Commit, with the completed
// transition whose reference is the digest of the exact Commit bytes.
type CommitResult struct {
	Transition group.Transition
	Commit     []byte
	Welcomes   map[string][]byte
}

// ErrRoomLeafIdentity reports a leaf whose identity is not the 128-byte
// compact binding a relay room leaf carries.
var ErrRoomLeafIdentity = errors.New("relay room leaf identity is not the 128-byte compact binding")

// CreateRoom provisions the founder's group and installs its first state.
// own is the founder's leaf as its leaf credential expects it; the founder's
// KeyPackage must carry exactly that identity and signature key.
func (c *RoomMLSController) CreateRoom(binding group.State, proof RoomAuthorityProof, identityState, ownKeyPackage, groupID []byte, keyPackageRef string, own group.LeafBinding) (RoomMLSRecord, error) {
	provisioner, ok := c.driver.(group.ProvisioningDriver)
	if !ok {
		return RoomMLSRecord{}, errors.New("MLS driver cannot provision groups")
	}
	if err := own.Validate(); err != nil {
		return RoomMLSRecord{}, ErrRoomLeafIdentity
	}
	if err := c.driver.ValidateKeyPackage(ownKeyPackage, own.Identity(), own.SignatureKey()); err != nil {
		return RoomMLSRecord{}, err
	}
	state, err := provisioner.CreateGroup(identityState, ownKeyPackage, groupID)
	if err != nil {
		return RoomMLSRecord{}, err
	}
	info, err := c.checkState(state, groupID, binding.Clock.MLSEpoch)
	if err != nil {
		return RoomMLSRecord{}, err
	}
	// The founder's own credential fixes the room's end (D18).
	return c.ledger.InstallFounder(RoomMLSInstall{Binding: binding, Proof: proof, State: state, EpochAuthenticator: info.EpochAuthenticator,
		KeyPackageRef: keyPackageRef, Credentials: []group.LeafBinding{own}, EndsAtUnix: own.Credential().ExpiresAtUnix}, c.now())
}

// Join processes a Welcome and installs the joined state, consuming the
// one-time KeyPackage and recording the Welcome in the same write. authority
// is the authority's leaf as the credential its room.invite carried expects
// it (section 11.3): a Welcome authored by any other leaf is refused before
// anything is written, and the install roots that credential in the room's
// list, whose expiry is the room's end (D18).
func (c *RoomMLSController) Join(binding group.State, proof RoomAuthorityProof, expectedGroupID, identityState, welcome []byte, keyPackageRef string, authority group.LeafBinding) (RoomMLSRecord, error) {
	if len(welcome) == 0 || len(welcome) > group.MaxOpenMLSMessageBytes {
		return RoomMLSRecord{}, errors.New("invalid MLS Welcome")
	}
	if err := authority.Validate(); err != nil {
		return RoomMLSRecord{}, ErrRoomLeafIdentity
	}
	state, sender, err := c.driver.JoinAttributed(identityState, welcome)
	if err != nil {
		return RoomMLSRecord{}, err
	}
	if !authority.Matches(sender) {
		return RoomMLSRecord{}, ErrMLSSenderMismatch
	}
	leaves, err := c.relayMembers(state)
	if err != nil {
		return RoomMLSRecord{}, err
	}
	// The tree the Welcome installs must hold exactly the signed membership,
	// one leaf per Agent: a leaf the header does not name would be a member
	// the ledger and its owner never see.
	if err := checkTreeMembership(leaves, proof.Membership.Members); err != nil {
		return RoomMLSRecord{}, err
	}
	info, err := c.checkState(state, expectedGroupID, binding.Clock.MLSEpoch)
	if err != nil {
		return RoomMLSRecord{}, err
	}
	return c.ledger.InstallWelcome(RoomMLSInstall{Binding: binding, Proof: proof, State: state, EpochAuthenticator: info.EpochAuthenticator,
		KeyPackageRef: keyPackageRef, WelcomeRef: canon.Digest(welcome), Credentials: []group.LeafBinding{authority},
		EndsAtUnix: authority.Credential().ExpiresAtUnix}, c.now())
}

// Commit makes the authority's next Commit. template carries both commit
// reference fields empty: the reference is the digest of the exact Commit
// bytes, which exist only after the driver made them. build turns the driver
// output into the objects to publish (the Commit, Welcome and rosters); they
// are staged and published with the advance, and retained until retainUntil.
func (c *RoomMLSController) Commit(template group.Transition, proof *RoomAuthorityProof, operations []group.LeafOperation, build func(CommitResult) ([]StagedRoomObject, error), retainUntil time.Time) (CommitResult, RoomMLSRecord, error) {
	if template.CommitRef != "" || template.Next.AcceptedCommitRef != "" {
		return CommitResult{}, RoomMLSRecord{}, errors.New("MLS commit template already has a reference")
	}
	if build == nil {
		return CommitResult{}, RoomMLSRecord{}, errors.New("a Commit needs its output builder")
	}
	if err := checkRelayLeafOperations(operations); err != nil {
		return CommitResult{}, RoomMLSRecord{}, err
	}
	record, state, err := c.current(template.Prior.RoomID)
	if err != nil {
		return CommitResult{}, RoomMLSRecord{}, err
	}
	if !sameGroupState(record.Binding(), template.Prior) {
		return CommitResult{}, RoomMLSRecord{}, ErrMLSFork
	}
	priorInfo, err := c.inspect.Inspect(state)
	if err != nil {
		return CommitResult{}, RoomMLSRecord{}, err
	}
	nextState, commit, welcomes, err := c.driver.Commit(state, operations)
	if err != nil {
		return CommitResult{}, RoomMLSRecord{}, err
	}
	template.CommitRef = canon.Digest(commit)
	template.Next.AcceptedCommitRef = template.CommitRef
	info, err := c.checkState(nextState, priorInfo.GroupID, template.Next.Clock.MLSEpoch)
	if err != nil {
		return CommitResult{}, RoomMLSRecord{}, err
	}
	result := CommitResult{Transition: template, Commit: commit, Welcomes: welcomes}
	objects, err := build(result)
	if err != nil {
		return CommitResult{}, RoomMLSRecord{}, err
	}
	_, written, err := c.ledger.Advance(RoomMLSAdvance{
		Transition: template, Proof: proof, ExpectedStateDigest: record.StateDigest,
		State: nextState, EpochAuthenticator: info.EpochAuthenticator,
		Output: &RoomCommitOutput{Objects: objects, RetainUntil: retainUntil},
	}, c.now())
	if err != nil {
		return CommitResult{}, RoomMLSRecord{}, err
	}
	return result, written, nil
}

// Apply applies the authority's Commit. expectedCommitter is the authority's
// leaf as its verified leaf credential expects it (identity and signature
// key); a Commit made by any other leaf is refused without a write. An exact
// repeat of the accepted Commit is a no-op reported as not fresh, without
// calling the driver.
func (c *RoomMLSController) Apply(transition group.Transition, proof *RoomAuthorityProof, commit []byte, expectedCommitter group.LeafBinding) (bool, RoomMLSRecord, error) {
	if len(commit) == 0 || len(commit) > group.MaxOpenMLSMessageBytes || canon.Digest(commit) != transition.CommitRef {
		return false, RoomMLSRecord{}, errors.New("MLS commit reference mismatch")
	}
	if err := expectedCommitter.Validate(); err != nil {
		return false, RoomMLSRecord{}, ErrRoomLeafIdentity
	}
	record, state, err := c.current(transition.Prior.RoomID)
	if err != nil {
		return false, RoomMLSRecord{}, err
	}
	if record.IsRepeatOf(transition, proof) {
		return false, record, nil
	}
	if err := group.ValidateTransition(transition); err != nil {
		return false, RoomMLSRecord{}, err
	}
	if !sameGroupState(record.Binding(), transition.Prior) {
		return false, RoomMLSRecord{}, ErrMLSFork
	}
	priorInfo, err := c.inspect.Inspect(state)
	if err != nil {
		return false, RoomMLSRecord{}, err
	}
	next, committer, err := c.driver.ApplyAttributed(state, commit)
	if err != nil {
		return false, RoomMLSRecord{}, err
	}
	if !expectedCommitter.Matches(committer) {
		return false, RoomMLSRecord{}, ErrMLSSenderMismatch
	}
	// The authority's Commit may add or replace leaves; a tree holding any
	// identity but the compact binding is not a relay room's, and would
	// refuse every later members listing, so it is refused before it is
	// written.
	leaves, err := c.relayMembers(next)
	if err != nil {
		return false, RoomMLSRecord{}, err
	}
	// The tree the Commit leaves must hold exactly the membership it is
	// signed for (the record's own for an MLS-only refresh), one leaf per
	// Agent: a Commit cannot add a leaf the signed membership does not name.
	expected := record.Members
	if transition.Next.Clock.RoomEpoch != transition.Prior.Clock.RoomEpoch {
		expected = transition.Membership.Members
	}
	if err := checkTreeMembership(leaves, expected); err != nil {
		return false, RoomMLSRecord{}, err
	}
	info, err := c.checkState(next, priorInfo.GroupID, transition.Next.Clock.MLSEpoch)
	if err != nil {
		return false, RoomMLSRecord{}, err
	}
	return c.ledger.Advance(RoomMLSAdvance{Transition: transition, Proof: proof, ExpectedStateDigest: record.StateDigest, State: next, EpochAuthenticator: info.EpochAuthenticator}, c.now())
}

// Seal encrypts one application message in the current epoch. The ciphertext
// is returned only after the sender ratchet step is durable.
func (c *RoomMLSController) Seal(roomID string, aad, plaintext []byte) ([]byte, RoomMLSRecord, error) {
	record, state, err := c.current(roomID)
	if err != nil {
		return nil, RoomMLSRecord{}, err
	}
	priorInfo, err := c.inspect.Inspect(state)
	if err != nil {
		return nil, RoomMLSRecord{}, err
	}
	next, message, err := c.driver.Seal(state, aad, plaintext)
	if err != nil {
		return nil, RoomMLSRecord{}, err
	}
	if _, err := c.checkState(next, priorInfo.GroupID, record.MLSEpoch); err != nil {
		return nil, RoomMLSRecord{}, err
	}
	changed, written, err := c.ledger.Ratchet(roomID, record.StateDigest, next, c.now())
	if err != nil {
		return nil, RoomMLSRecord{}, err
	}
	if !changed {
		return nil, RoomMLSRecord{}, errors.New("MLS send did not advance private state")
	}
	return message, written, nil
}

// Open decrypts one application message of the current or a retained past
// epoch. expectedSender is the leaf of the member the transport
// authenticated, as its verified leaf credential expects it; a message sealed
// by any other leaf, or by that identity under another signature key, is
// refused without a write.
func (c *RoomMLSController) Open(roomID string, aad, message []byte, expectedSender group.LeafBinding) ([]byte, RoomMLSRecord, error) {
	if err := expectedSender.Validate(); err != nil {
		return nil, RoomMLSRecord{}, ErrRoomLeafIdentity
	}
	record, state, err := c.current(roomID)
	if err != nil {
		return nil, RoomMLSRecord{}, err
	}
	priorInfo, err := c.inspect.Inspect(state)
	if err != nil {
		return nil, RoomMLSRecord{}, err
	}
	next, plaintext, sender, err := c.driver.OpenAttributed(state, aad, message)
	if err != nil {
		return nil, RoomMLSRecord{}, err
	}
	if !expectedSender.Matches(sender) {
		return nil, RoomMLSRecord{}, ErrMLSSenderMismatch
	}
	if _, err := c.checkState(next, priorInfo.GroupID, record.MLSEpoch); err != nil {
		return nil, RoomMLSRecord{}, err
	}
	changed, written, err := c.ledger.Ratchet(roomID, record.StateDigest, next, c.now())
	if err != nil {
		return nil, RoomMLSRecord{}, err
	}
	if !changed {
		return nil, RoomMLSRecord{}, errors.New("MLS receive did not advance private state")
	}
	return plaintext, written, nil
}

// OpenedRoomMessage is an application message the driver opened whose
// ratchet step is not durable yet. Its AAD is the message's own authenticated
// data, authenticated by the open, for the caller to judge. Discarding the
// value spends nothing: the driver returned the next state and nothing
// stored it.
type OpenedRoomMessage struct {
	RoomID    string
	Plaintext []byte
	AAD       []byte
	Sender    group.MLSMember
	// prior is the state digest the message was opened against; next the
	// state the open made.
	prior string
	next  []byte
}

// ErrRoomMessageNotOpened reports a message the driver ran on and refused to
// open: not this group's, not of an epoch the member holds, a generation
// already used or beyond the ratchet's tolerance, or tampered with. Any other
// error is a driver or journal that could not run.
var ErrRoomMessageNotOpened = errors.New("the MLS driver did not open the room message")

// ErrRoomOpenedMessage reports an opened message that cannot be committed:
// the zero value, or one whose room moved on since it was opened.
var ErrRoomOpenedMessage = errors.New("the opened room message cannot be committed")

// OpenReadback decrypts one application message of the current or a retained
// past epoch without being told its authenticated data (the room AAD binds
// the Event ID, which a receiver learns only by opening). expectedSender is
// the leaf of the member the transport authenticated, as its verified leaf
// credential expects it; a message sealed by any other leaf, or by that
// identity under another signature key, is refused. Nothing is written: the
// caller judges the AAD and the Event, and only then commits the step with
// CommitOpened, so a message refused after the open spends no ratchet step.
func (c *RoomMLSController) OpenReadback(roomID string, message []byte, expectedSender group.LeafBinding) (OpenedRoomMessage, error) {
	if err := expectedSender.Validate(); err != nil {
		return OpenedRoomMessage{}, ErrRoomLeafIdentity
	}
	if len(message) == 0 || len(message) > group.MaxOpenMLSMessageBytes {
		return OpenedRoomMessage{}, errors.New("invalid MLS application message")
	}
	record, state, err := c.current(roomID)
	if err != nil {
		return OpenedRoomMessage{}, err
	}
	priorInfo, err := c.inspect.Inspect(state)
	if err != nil {
		return OpenedRoomMessage{}, err
	}
	next, plaintext, aad, sender, err := c.driver.OpenAttributedReadback(state, message)
	if errors.Is(err, group.ErrOpenMLSRefused) {
		return OpenedRoomMessage{}, fmt.Errorf("%w: %w", ErrRoomMessageNotOpened, err)
	}
	if err != nil {
		return OpenedRoomMessage{}, err
	}
	if !expectedSender.Matches(sender) {
		return OpenedRoomMessage{}, ErrMLSSenderMismatch
	}
	if _, err := c.checkState(next, priorInfo.GroupID, record.MLSEpoch); err != nil {
		return OpenedRoomMessage{}, err
	}
	return OpenedRoomMessage{RoomID: roomID, Plaintext: plaintext, AAD: aad, Sender: sender,
		prior: record.StateDigest, next: next}, nil
}

// CommitOpened makes an opened message's ratchet step durable. It refuses a
// message opened against a state the room no longer holds (ErrMLSFork from
// the ledger), so a step is never applied on top of another.
func (c *RoomMLSController) CommitOpened(opened OpenedRoomMessage) (RoomMLSRecord, error) {
	if opened.prior == "" || len(opened.next) == 0 {
		return RoomMLSRecord{}, ErrRoomOpenedMessage
	}
	changed, written, err := c.ledger.Ratchet(opened.RoomID, opened.prior, opened.next, c.now())
	if err != nil {
		return RoomMLSRecord{}, err
	}
	if !changed {
		return RoomMLSRecord{}, errors.New("MLS receive did not advance private state")
	}
	return written, nil
}

// Members lists the leaves of a room's current MLS tree (leaf index, identity
// and signature key) without changing anything. A receiver learning roster
// entries and building per-member pins reads them here (section 11.8). Every
// leaf of a relay room carries the compact identity; a tree holding any other
// is refused.
func (c *RoomMLSController) Members(roomID string) ([]group.MLSMember, error) {
	_, state, err := c.current(roomID)
	if err != nil {
		return nil, err
	}
	return c.relayMembers(state)
}

// relayMembers lists a state's leaves and refuses a tree outside the relay
// room bound or holding an identity that is not the compact binding.
func (c *RoomMLSController) relayMembers(state []byte) ([]group.MLSMember, error) {
	members, err := c.driver.Members(state)
	if err != nil {
		return nil, err
	}
	if len(members) == 0 || len(members) > MaxRoomLeaves {
		return nil, errors.New("relay room tree is outside its leaf bound")
	}
	for _, member := range members {
		if _, err := group.DecodeLeafIdentity(member.Identity); err != nil {
			return nil, ErrRoomLeafIdentity
		}
	}
	return members, nil
}

// ErrRoomTreeMembership reports an MLS tree whose leaves are not exactly the
// signed membership, one leaf per Agent. It is a leaf identity refusal.
var ErrRoomTreeMembership = fmt.Errorf("%w: the MLS tree is not the signed membership, one leaf per Agent", ErrRoomLeafIdentity)

// checkTreeMembership requires the Agents of a tree's compact leaf
// identities to be exactly agents, each with one leaf (D3).
func checkTreeMembership(leaves []group.MLSMember, agents []string) error {
	seen := make(map[string]struct{}, len(leaves))
	for _, leaf := range leaves {
		identity, err := group.DecodeLeafIdentity(leaf.Identity)
		if err != nil {
			return ErrRoomLeafIdentity
		}
		if _, duplicate := seen[identity.AgentID]; duplicate {
			return ErrRoomTreeMembership
		}
		seen[identity.AgentID] = struct{}{}
	}
	if len(seen) != len(agents) {
		return ErrRoomTreeMembership
	}
	for _, agentID := range agents {
		if _, held := seen[agentID]; !held {
			return ErrRoomTreeMembership
		}
	}
	return nil
}

// MaxRoomLeaves is the leaf bound of a relay room: 32 Agents, one device
// each (D3).
const MaxRoomLeaves = group.MaxPrivateRoomAgents

// checkRelayLeafOperations refuses a leaf operation whose leaf carries any
// identity but the compact binding, before the driver runs.
func checkRelayLeafOperations(operations []group.LeafOperation) error {
	for _, operation := range operations {
		for _, leaf := range []*group.Leaf{operation.Prior, operation.Next} {
			if leaf == nil {
				continue
			}
			if _, err := group.DecodeLeafIdentity(leaf.CredentialIdentity); err != nil {
				return ErrRoomLeafIdentity
			}
		}
	}
	return nil
}

func (c *RoomMLSController) checkState(state, expectedGroupID []byte, expectedEpoch uint64) (group.MLSStateInfo, error) {
	if len(expectedGroupID) == 0 {
		return group.MLSStateInfo{}, errors.New("missing expected MLS group id")
	}
	info, err := c.inspect.Inspect(state)
	if err != nil {
		return group.MLSStateInfo{}, err
	}
	if !bytes.Equal(info.GroupID, expectedGroupID) || info.Epoch != expectedEpoch {
		return group.MLSStateInfo{}, errors.New("MLS state does not match room binding")
	}
	if len(info.EpochAuthenticator) != group.MLSEpochAuthenticatorBytes {
		return group.MLSStateInfo{}, errors.New("MLS state reports no epoch authenticator")
	}
	return info, nil
}

func (c *RoomMLSController) current(roomID string) (RoomMLSRecord, []byte, error) {
	record, found, err := c.ledger.Current(roomID)
	if err != nil {
		return RoomMLSRecord{}, nil, err
	}
	if !found {
		return RoomMLSRecord{}, nil, errors.New("MLS room has no installed state")
	}
	state, err := c.ledger.State(record)
	return record, state, err
}
