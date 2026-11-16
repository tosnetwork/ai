package eventlog

// RoomMLSController is the crash-consistency boundary between the MLS driver
// and the fused room ledger. Driver output is never returned to the caller
// until the state it produced is durable: a Commit's objects are published by
// the same journal write that advances the room, and a Seal's ciphertext is
// returned only after its sender ratchet step is recorded. A message or Commit
// whose sender is not the expected member is refused before anything is
// written, so content cannot spend a ratchet step under another's name.

import (
	"bytes"
	"errors"
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

// CreateRoom provisions the founder's group and installs its first state.
func (c *RoomMLSController) CreateRoom(binding group.State, proof RoomAuthorityProof, identityState, ownKeyPackage, groupID []byte, keyPackageRef string) (RoomMLSRecord, error) {
	provisioner, ok := c.driver.(group.ProvisioningDriver)
	if !ok {
		return RoomMLSRecord{}, errors.New("MLS driver cannot provision groups")
	}
	state, err := provisioner.CreateGroup(identityState, ownKeyPackage, groupID)
	if err != nil {
		return RoomMLSRecord{}, err
	}
	info, err := c.checkState(state, groupID, binding.Clock.MLSEpoch)
	if err != nil {
		return RoomMLSRecord{}, err
	}
	return c.ledger.InstallFounder(RoomMLSInstall{Binding: binding, Proof: proof, State: state, EpochAuthenticator: info.EpochAuthenticator, KeyPackageRef: keyPackageRef}, c.now())
}

// Join processes a Welcome and installs the joined state, consuming the
// one-time KeyPackage and recording the Welcome in the same write.
func (c *RoomMLSController) Join(binding group.State, proof RoomAuthorityProof, expectedGroupID, identityState, welcome []byte, keyPackageRef string) (RoomMLSRecord, error) {
	if len(welcome) == 0 || len(welcome) > group.MaxOpenMLSMessageBytes {
		return RoomMLSRecord{}, errors.New("invalid MLS Welcome")
	}
	state, err := c.driver.Join(identityState, welcome)
	if err != nil {
		return RoomMLSRecord{}, err
	}
	info, err := c.checkState(state, expectedGroupID, binding.Clock.MLSEpoch)
	if err != nil {
		return RoomMLSRecord{}, err
	}
	return c.ledger.InstallWelcome(RoomMLSInstall{Binding: binding, Proof: proof, State: state, EpochAuthenticator: info.EpochAuthenticator, KeyPackageRef: keyPackageRef, WelcomeRef: canon.Digest(welcome)}, c.now())
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

// Apply applies the authority's Commit. expectedCommitter is the
// BasicCredential identity of the authority's leaf; a Commit made by any
// other leaf is refused without a write. An exact repeat of the accepted
// Commit is a no-op reported as not fresh, without calling the driver.
func (c *RoomMLSController) Apply(transition group.Transition, proof *RoomAuthorityProof, commit, expectedCommitter []byte) (bool, RoomMLSRecord, error) {
	if len(commit) == 0 || len(commit) > group.MaxOpenMLSMessageBytes || canon.Digest(commit) != transition.CommitRef {
		return false, RoomMLSRecord{}, errors.New("MLS commit reference mismatch")
	}
	if len(expectedCommitter) == 0 || len(expectedCommitter) > group.MaxOpenMLSIdentityBytes {
		return false, RoomMLSRecord{}, errors.New("invalid expected MLS committer")
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
	if !bytes.Equal(committer, expectedCommitter) {
		return false, RoomMLSRecord{}, ErrMLSSenderMismatch
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
// epoch. expectedSender is the BasicCredential identity of the member the
// transport authenticated; a message sealed by any other leaf is refused
// without a write.
func (c *RoomMLSController) Open(roomID string, aad, message, expectedSender []byte) ([]byte, RoomMLSRecord, error) {
	if len(expectedSender) == 0 || len(expectedSender) > group.MaxOpenMLSIdentityBytes {
		return nil, RoomMLSRecord{}, errors.New("invalid expected MLS sender")
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
	if !bytes.Equal(sender, expectedSender) {
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
