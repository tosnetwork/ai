package daemon

// The room operator is the owner's half of private rooms over the relay
// (sections 11.2, 11.4, 11.8, D13, D18): create, add, remove and join, each
// reached only by a verified owner decision through localapi.RoomOperator.
//
// Every leaf credential this installation issues is made the same way: a
// fresh leaf signature key from the driver, the credential naming it and
// this node's device as its published evidence shows it, signed by the
// Endpoint, then the KeyPackage under the 128-byte compact identity naming
// the credential, and the DeviceCredential of that KeyPackage with the same
// window. The window is at most 30 days and ends no later than the
// delegation, so a founder's credential fixes the room's end (D18) and a
// joiner's lasts as long as it may.
//
// The authority's Add is made from the journal: rooms.add records the
// owner's decision and sends the room.invite; the joiner's room.key-package
// is verified and recorded against that decision; the Add Commit is then
// made from the record, staging the Commit, the Welcome and the rosters
// under its CommitRef in the fused write. A crash anywhere is finished from
// the record.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/admission"
	"github.com/tosnetwork/ai/messenger/pkg/directory"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/payload"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/messenger/pkg/room"
)

// roomLeafMaker is the part of the MLS driver that makes a leaf before its
// identity exists: the signer first, then the KeyPackage naming the
// credential that names the signer's key (section 11.8).
type roomLeafMaker interface {
	NewLeafSigner() (group.OpenMLSSigner, error)
	NewIdentityForSigner(signer group.OpenMLSSigner, identity []byte) (group.OpenMLSIdentity, error)
}

// Room operator refusals the owner sees.
var (
	// ErrRoomNotAuthority refuses a membership change of a room this
	// installation is not the authority of.
	ErrRoomNotAuthority = errors.New("this installation is not the room's authority")
	// ErrRoomHandshakeTooLate refuses a Commit, Welcome or roster within the
	// last re-deposit interval before the room's end minus the skew (D18):
	// it could not be delivered and acknowledged before senders stop.
	ErrRoomHandshakeTooLate = errors.New("the room ends too soon for a new membership change")
	// ErrRoomMemberCardUnknown holds back an Add whose roster needs a
	// member's chat card this installation holds no valid copy of; the
	// member's evidence pull, which carries its card, is started.
	ErrRoomMemberCardUnknown = errors.New("the chat card of a room member is not held here")
)

// defaultRoomAuthorization is how long a MembershipAuthorization the
// authority signs lives (section 11.3; production 24 h).
const defaultRoomAuthorization = room.MaxMembershipAuthorizationWindow

// localLeaf is a leaf this installation issued: the leaf credential, the
// verified binding, the identity's private state, the DeviceCredential of its
// KeyPackage and the leaf an Add would carry.
type localLeaf struct {
	credential group.LeafCredential
	encoded    []byte
	binding    group.LeafBinding
	identity   group.OpenMLSIdentity
	device     group.DeviceCredential
	deviceJSON []byte
	leaf       group.Leaf
}

// ownEvidence returns this node's current relay evidence, its chat card, and
// the device set that evidence publishes.
func (r *roomRuntime) ownEvidence() ([]byte, []byte, e2ee.SetSummary, error) {
	evidence, _, _, err := r.relay.sink.Current()
	if err != nil {
		return nil, nil, e2ee.SetSummary{}, err
	}
	card, err := r.relay.sink.Card()
	if err != nil {
		return nil, nil, e2ee.SetSummary{}, err
	}
	decoded, err := relayframe.DecodeEvidence(evidence)
	if err != nil {
		return nil, nil, e2ee.SetSummary{}, err
	}
	bundles, err := e2ee.DecodeBundleSetJSON(decoded.BundleSet)
	if err != nil {
		return nil, nil, e2ee.SetSummary{}, err
	}
	set, err := e2ee.Summarize(bundles)
	if err != nil {
		return nil, nil, e2ee.SetSummary{}, err
	}
	return evidence, card, set, nil
}

// endpointSign signs a preimage with the Endpoint signer and checks the
// signature under the delegation's Endpoint key.
func (r *roomRuntime) endpointSign(preimage []byte) ([]byte, error) {
	public, ok := r.relay.signer.Public().(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("the Endpoint signer is not Ed25519")
	}
	signature, err := r.relay.signer.Sign(rand.Reader, preimage, crypto.Hash(0))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(public, preimage, signature) {
		return nil, errors.New("sign with the Endpoint key")
	}
	return signature, nil
}

// issueLeaf makes a fresh leaf credential and KeyPackage of this node,
// valid from now for at most 30 days and not past the delegation, and
// verifies it as a receiver would against the given room end (zero: its own
// expiry).
func (r *roomRuntime) issueLeaf(roomEndsAtUnix uint64, now time.Time) (localLeaf, error) {
	delegation := r.daemon.prekeys.planner.delegation
	_, _, set, err := r.ownEvidence()
	if err != nil {
		return localLeaf{}, err
	}
	issued := uint64(now.Unix())
	if now.Unix() <= 0 || delegation.ExpiresAtUnix <= issued {
		return localLeaf{}, errors.New("the delegation does not outlast now")
	}
	// issued is a positive Unix time, so adding 30 days cannot overflow.
	expires := min(issued+group.MaxCredentialLifetimeSeconds, delegation.ExpiresAtUnix)
	signer, err := r.leafs.NewLeafSigner()
	if err != nil {
		return localLeaf{}, err
	}
	credential := group.LeafCredential{Network: delegation.Network, AgentID: r.daemon.config.AgentID,
		EndpointID: r.daemon.config.EndpointID, DeviceID: r.daemon.config.DeviceID, DeviceSetDigest: set.Digest,
		LeafSignaturePublicKey: signer.LeafSignaturePublicKey, IssuedAtUnix: issued, ExpiresAtUnix: expires}
	preimage, err := group.LeafCredentialSigningBytes(credential)
	if err != nil {
		return localLeaf{}, err
	}
	if credential.EndpointSignature, err = r.endpointSign(preimage); err != nil {
		return localLeaf{}, err
	}
	end := roomEndsAtUnix
	if end == 0 {
		end = credential.ExpiresAtUnix
	}
	binding, err := group.VerifyRoomLeafCredential(delegation, credential, set, end, now)
	if err != nil {
		return localLeaf{}, err
	}
	encoded, err := group.EncodeLeafCredential(credential)
	if err != nil {
		return localLeaf{}, err
	}
	identityBytes, err := group.EncodeLeafIdentity(credential)
	if err != nil {
		return localLeaf{}, err
	}
	made, err := r.leafs.NewIdentityForSigner(signer, identityBytes)
	if err != nil {
		return localLeaf{}, err
	}
	device := group.DeviceCredential{Network: delegation.Network, AgentID: credential.AgentID, EndpointID: credential.EndpointID,
		DeviceID: credential.DeviceID, DeviceSetDigest: credential.DeviceSetDigest,
		LeafSignaturePublicKey: signer.LeafSignaturePublicKey, KeyPackage: made.KeyPackage,
		IssuedAtUnix: credential.IssuedAtUnix, ExpiresAtUnix: credential.ExpiresAtUnix}
	devicePreimage, err := group.CredentialSigningBytes(device)
	if err != nil {
		return localLeaf{}, err
	}
	if device.EndpointSignature, err = r.endpointSign(devicePreimage); err != nil {
		return localLeaf{}, err
	}
	leaf, err := group.LeafFromCredentials(device, credential)
	if err != nil {
		return localLeaf{}, err
	}
	deviceJSON, err := group.EncodeDeviceCredentialJSON(device)
	if err != nil {
		return localLeaf{}, err
	}
	return localLeaf{credential: credential, encoded: encoded, binding: binding, identity: made, device: device,
		deviceJSON: deviceJSON, leaf: leaf}, nil
}

// authorize signs the MembershipAuthorization of a membership this
// installation is the authority of, valid from now for the authorization
// lifetime and not past the delegation.
func (r *roomRuntime) authorize(membership room.Membership, now time.Time) (eventlog.RoomAuthorityProof, error) {
	delegation := r.daemon.prekeys.planner.delegation
	issued := uint64(now.Unix())
	// The lifetime is at most 24 h of seconds, so the sum cannot overflow.
	expires := min(issued+uint64(r.authorization/time.Second), delegation.ExpiresAtUnix)
	if now.Unix() <= 0 || expires <= issued {
		return eventlog.RoomAuthorityProof{}, errors.New("the delegation does not outlast now")
	}
	value := room.MembershipAuthorization{Network: delegation.Network, RoomID: membership.RoomID, Epoch: membership.Epoch,
		MembershipDigest: membership.Digest,
		Authority:        room.Authority{AgentID: r.daemon.config.AgentID, EndpointID: r.daemon.config.EndpointID},
		IssuedAtUnix:     issued, ExpiresAtUnix: expires}
	preimage, err := room.MembershipAuthorizationSigningBytes(value)
	if err != nil {
		return eventlog.RoomAuthorityProof{}, err
	}
	if value.EndpointSignature, err = r.endpointSign(preimage); err != nil {
		return eventlog.RoomAuthorityProof{}, err
	}
	if err := room.VerifyMembershipAuthorization(membership, value, delegation, now); err != nil {
		return eventlog.RoomAuthorityProof{}, err
	}
	return eventlog.RoomAuthorityProof{Membership: membership, Authorization: value, Delegation: delegation}, nil
}

// CreateRoom founds a private room under an owner-chosen room ID with this
// installation as its single member and authority. The founder's leaf
// credential fixes the room's end. A repeat for a room this installation
// already founded is a no-op.
func (r *roomRuntime) CreateRoom(_ context.Context, roomID string) error {
	if !ids.Room.MatchString(roomID) {
		return fault.New(fault.CodePayloadMalformed, "invalid room identifier")
	}
	r.handling.Lock()
	defer r.handling.Unlock()
	now := r.now()
	if record, found, err := r.ledger.Current(roomID); err != nil {
		return err
	} else if found {
		if record.AuthorityAgentID == r.daemon.config.AgentID && record.RoomEpoch == 1 &&
			len(record.Members) == 1 && record.Members[0] == r.daemon.config.AgentID {
			return nil
		}
		return fault.New(fault.CodeRoomFork, "the room is already held here")
	}
	if _, pending, err := r.daemon.journal.AcceptedRoomJoin(roomID, now); err != nil {
		return err
	} else if pending {
		return fault.New(fault.CodeRoomFork, "this installation is joining the room")
	}
	own, err := r.issueLeaf(0, now)
	if err != nil {
		return err
	}
	founding, err := room.Found(roomID, []string{r.daemon.config.AgentID})
	if err != nil {
		return fault.Wrap(fault.CodePayloadMalformed, err)
	}
	proof, err := r.authorize(founding, now)
	if err != nil {
		return err
	}
	groupID, err := group.MLSGroupID(r.daemon.config.Network(), roomID)
	if err != nil {
		return err
	}
	binding := group.State{RoomID: roomID, Clock: group.Clock{RoomEpoch: 1}, MembershipDigest: founding.Digest}
	_, err = r.controller.CreateRoom(binding, proof, own.identity.State, own.identity.KeyPackage, groupID,
		own.leaf.KeyPackageRef, own.binding)
	if errors.Is(err, eventlog.ErrRoomsFull) {
		return fault.Wrap(fault.CodeQuotaExceeded, err)
	}
	return err
}

// authorityRecord returns a room's fused record when this installation is
// its authority and the room still takes membership changes (D18).
func (r *roomRuntime) authorityRecord(roomID string, now time.Time) (eventlog.RoomMLSRecord, error) {
	if !ids.Room.MatchString(roomID) {
		return eventlog.RoomMLSRecord{}, fault.New(fault.CodePayloadMalformed, "invalid room identifier")
	}
	record, found, err := r.ledger.Current(roomID)
	if err != nil {
		return eventlog.RoomMLSRecord{}, err
	}
	if !found {
		return eventlog.RoomMLSRecord{}, fault.New(fault.CodeNotARoomMember, "the room is not held here")
	}
	if record.AuthorityAgentID != r.daemon.config.AgentID {
		return eventlog.RoomMLSRecord{}, fault.Wrap(fault.CodeNotAuthentic, ErrRoomNotAuthority)
	}
	if r.handshakeStopped(record.RoomEndsAtUnix, now) {
		return eventlog.RoomMLSRecord{}, fault.Wrap(fault.CodeRoomEnded, ErrRoomHandshakeTooLate)
	}
	return record, nil
}

// handshakeStopped reports whether now lies within the last re-deposit
// interval d before the room's end minus the skew: from then on the
// authority makes no new Commit, Welcome or roster (D18).
func (r *roomRuntime) handshakeStopped(endsAtUnix uint64, now time.Time) bool {
	if endsAtUnix == 0 || endsAtUnix > uint64(1<<62) {
		return true
	}
	last := time.Unix(int64(endsAtUnix), 0).Add(-r.skew).Add(-r.relay.interval)
	return !now.Before(last)
}

// inviteExpiry is when a room.invite of this authority expires: at most
// the payload's bound, and never past the last moment the Add could still be
// committed (D18).
func (r *roomRuntime) inviteExpiry(record eventlog.RoomMLSRecord, now time.Time) (time.Time, error) {
	latest := time.Unix(int64(record.RoomEndsAtUnix), 0).Add(-r.skew).Add(-r.relay.interval)
	expires := now.Add(time.Duration(payload.MaxRoomInviteLifetimeSeconds) * time.Second)
	if latest.Before(expires) {
		expires = latest
	}
	if !expires.After(now) {
		return time.Time{}, fault.Wrap(fault.CodeRoomEnded, ErrRoomHandshakeTooLate)
	}
	return expires, nil
}

// AddRoomMember records the owner's decision to add an Agent and sends it
// the room.invite, which carries this authority's leaf credential, over the
// 1:1 session. The Add Commit follows the joiner's room.key-package. A
// repeat sends the same invite again under the same idempotency key.
func (r *roomRuntime) AddRoomMember(ctx context.Context, roomID, agentID string) error {
	if !ids.Agent.MatchString(agentID) {
		return fault.New(fault.CodePayloadMalformed, "invalid member identifier")
	}
	if agentID == r.daemon.config.AgentID {
		return fault.New(fault.CodePayloadMalformed, "the authority is a member of its room already")
	}
	now := r.now()
	r.handling.Lock()
	record, err := r.authorityRecord(roomID, now)
	if err != nil {
		r.handling.Unlock()
		return err
	}
	expires, err := r.inviteExpiry(record, now)
	if err != nil {
		r.handling.Unlock()
		return err
	}
	add, _, err := r.daemon.journal.RecordRoomAdd(roomID, agentID, expires, now)
	r.handling.Unlock()
	switch {
	case err == nil:
	case errors.Is(err, eventlog.ErrRoomAddMember):
		return nil
	case errors.Is(err, eventlog.ErrRoomAddsFull):
		return fault.Wrap(fault.CodeQuotaExceeded, err)
	default:
		return err
	}
	credential, found, err := r.ledger.RoomCredential(roomID, r.daemon.config.AgentID)
	if err != nil {
		return err
	}
	if !found {
		return fault.New(fault.CodeInternal, "the authority's own leaf credential is not in the room's list")
	}
	encoded, err := group.EncodeLeafCredential(credential)
	if err != nil {
		return err
	}
	content, err := payload.Encode(payload.RoomInvite{RoomID: roomID, InviteeAgentID: agentID, Purpose: roomInvitePurpose,
		ExpiresAtUnix: add.ExpiresAtUnix, AuthorityLeafCredential: encoded})
	if err != nil {
		return err
	}
	key := roomOperationKey("room.invite", roomID, agentID, add.DecidedAtUnix)
	_, err = r.daemon.sendDirectApplication(ctx, agentID, "room.invite", content, key, add.ExpiresAtUnix)
	return err
}

// roomInvitePurpose is the purpose a room.invite of this runtime names.
const roomInvitePurpose = "private room over the relay"

// roomOperationKey is the idempotency key of one owner room operation's 1:1
// Event, so a repeat of the operation reuses the journaled Event.
func roomOperationKey(kind, roomID, agentID string, at uint64) string {
	buffer := bytes.NewBufferString(canon.DomainOutboundIntent)
	canon.Text(buffer, kind)
	canon.Text(buffer, roomID)
	canon.Text(buffer, agentID)
	canon.Uint64(buffer, at)
	sum := sha256.Sum256(buffer.Bytes())
	return "idem_" + hex.EncodeToString(sum[:])
}

// JoinRoom accepts one authority's pending room.invite: it issues this
// installation's leaf credential, records the join (discarding the room's
// invites from other Agents) and sends the room.key-package to the
// authority. A repeat of an accepted join sends the same room.key-package
// again.
func (r *roomRuntime) JoinRoom(ctx context.Context, roomID, authorityAgentID string) error {
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(authorityAgentID) {
		return fault.New(fault.CodePayloadMalformed, "invalid room join")
	}
	now := r.now()
	join, accepted, err := r.daemon.journal.AcceptedRoomJoin(roomID, now)
	if err != nil {
		return err
	}
	if !accepted {
		invited, found, err := r.daemon.journal.PendingRoomJoinFor(roomID, authorityAgentID, now)
		if err != nil {
			return err
		}
		if !found {
			return fault.Wrap(fault.CodeAdmissionRequired, eventlog.ErrRoomJoinUnknown)
		}
		authority, err := invited.AuthorityCredential()
		if err != nil {
			return err
		}
		// The member's credential must last until the room's end, which is
		// the authority credential's expiry (D18).
		own, err := r.issueLeaf(authority.ExpiresAtUnix, now)
		if err != nil {
			return err
		}
		join, err = r.daemon.journal.BeginRoomJoinWithLeaf(roomID, authorityAgentID, own.identity.State, own.deviceJSON,
			own.encoded, now)
		if err != nil {
			return joinRefusal(err)
		}
	} else if join.AuthorityAgentID != authorityAgentID {
		return fault.Wrap(fault.CodeRoomFork, eventlog.ErrRoomJoinConflict)
	}
	leafCredential, found, err := join.LeafCredential()
	if err != nil {
		return err
	}
	if !found {
		return fault.New(fault.CodeInternal, "the accepted join holds no leaf credential to send")
	}
	device, err := join.Credential()
	if err != nil {
		return err
	}
	deviceJSON, err := group.EncodeDeviceCredentialJSON(device)
	if err != nil {
		return err
	}
	content, err := payload.Encode(payload.RoomKeyPackage{RoomID: roomID, DeviceCredentialJSON: deviceJSON,
		LeafCredential: leafCredential})
	if err != nil {
		return err
	}
	key := roomOperationKey("room.key-package", roomID, authorityAgentID, join.JoinedAtUnix)
	_, err = r.daemon.sendDirectApplication(ctx, authorityAgentID, "room.key-package", content, key, device.ExpiresAtUnix)
	return err
}

func joinRefusal(err error) error {
	switch {
	case errors.Is(err, eventlog.ErrRoomJoinUnknown), errors.Is(err, eventlog.ErrRoomJoinExpired):
		return fault.Wrap(fault.CodeAdmissionRequired, err)
	case errors.Is(err, eventlog.ErrRoomJoinConflict), errors.Is(err, eventlog.ErrRoomAlreadyJoined):
		return fault.Wrap(fault.CodeRoomFork, err)
	case errors.Is(err, eventlog.ErrRoomsFull):
		return fault.Wrap(fault.CodeQuotaExceeded, err)
	default:
		return err
	}
}

// roomKeyPackageStep returns the write a received room.key-package adds to
// its Event's commit: the KeyPackage verified against finalized state and
// the owner's pending add, then recorded with the add. A failing check
// refuses the Event and stores nothing.
func (d *Daemon) roomKeyPackageStep(route admission.Route, event envelope.Event, sender verifiedPeer, now time.Time) inviteStep {
	if route != admission.RouteRelay || event.Kind != "room.key-package" || d.relay == nil || d.relay.rooms == nil {
		return nil
	}
	r := d.relay.rooms
	return func() error {
		value, err := payload.Decode(event.Kind, event.Content)
		if err != nil {
			return fault.Wrap(fault.CodePayloadMalformed, err)
		}
		keyPackage, ok := value.(payload.RoomKeyPackage)
		if !ok {
			return fault.New(fault.CodePayloadMalformed, "not a room KeyPackage")
		}
		if _, err := r.verifyKeyPackage(keyPackage, event.SenderAgentID, sender, now); err != nil {
			return err
		}
		// The joiner's card is judged before anything is recorded.
		card, err := joinerCardOf(keyPackage.RoomID, event.SenderAgentID, sender.Card, now)
		if err != nil {
			return err
		}
		_, err = d.journal.RecordRoomAddKeyPackage(keyPackage.RoomID, event.SenderAgentID, keyPackage.DeviceCredentialJSON,
			keyPackage.LeafCredential, now)
		switch {
		case err == nil:
			// The joiner's card came in part 0 of this frame, bound to the
			// authenticated packet sender.
			return r.storeJoinerCard(card, now)
		case errors.Is(err, eventlog.ErrRoomAddUnknown):
			return fault.Wrap(fault.CodeNotAuthentic, err)
		case errors.Is(err, eventlog.ErrRoomAddConflict):
			return fault.Wrap(fault.CodeRoomFork, err)
		default:
			return err
		}
	}
}

// verifyKeyPackage checks a joiner's room.key-package (section 11.2): the
// room is this authority's and the owner added the sender; the
// DeviceCredential binds under finalized state (BindDeviceCredential, the
// device set compared once, at the add); the leaf credential matches it,
// verifies on the room path and lasts until the room's end (D18); and the
// KeyPackage's identity is the compact binding naming that credential.
func (r *roomRuntime) verifyKeyPackage(keyPackage payload.RoomKeyPackage, senderAgentID string, sender verifiedPeer,
	now time.Time) (group.Leaf, error) {
	record, found, err := r.ledger.Current(keyPackage.RoomID)
	if err != nil {
		return group.Leaf{}, err
	}
	if !found || record.AuthorityAgentID != r.daemon.config.AgentID {
		return group.Leaf{}, fault.New(fault.CodeNotAuthentic, "the KeyPackage names a room this installation is not the authority of")
	}
	if record.Membership().Contains(senderAgentID) {
		return group.Leaf{}, fault.New(fault.CodeNotAuthentic, "the KeyPackage's sender is already a member")
	}
	if sender.Delegation.AgentID != senderAgentID {
		return group.Leaf{}, fault.New(fault.CodeNotAuthentic, "the KeyPackage is not its sender's")
	}
	device, err := group.DecodeDeviceCredentialJSON(keyPackage.DeviceCredentialJSON)
	if err != nil {
		return group.Leaf{}, fault.Wrap(fault.CodePayloadMalformed, err)
	}
	leafCredential, err := group.DecodeLeafCredential(keyPackage.LeafCredential)
	if err != nil {
		return group.Leaf{}, fault.Wrap(fault.CodePayloadMalformed, err)
	}
	set, err := e2ee.Summarize(sender.Bundles)
	if err != nil {
		return group.Leaf{}, fault.Wrap(fault.CodeNotAuthentic, err)
	}
	if err := group.BindDeviceCredential(sender.Delegation, device, set, now); err != nil {
		return group.Leaf{}, fault.Wrap(fault.CodeNotAuthentic, err)
	}
	if err := group.MatchLeafToDeviceCredential(leafCredential, device); err != nil {
		return group.Leaf{}, fault.Wrap(fault.CodeNotAuthentic, err)
	}
	if _, err := group.VerifyRoomLeafCredential(sender.Delegation, leafCredential, set, record.RoomEndsAtUnix, now); err != nil {
		return group.Leaf{}, fault.Wrap(fault.CodeNotAuthentic, err)
	}
	leaf, err := group.LeafFromCredentials(device, leafCredential)
	if err != nil {
		return group.Leaf{}, fault.Wrap(fault.CodeNotAuthentic, err)
	}
	if err := r.driver.ValidateKeyPackage(leaf.KeyPackage, leaf.CredentialIdentity, leaf.LeafSignaturePublicKey); err != nil {
		return group.Leaf{}, fault.Wrap(fault.CodeNotAuthentic, err)
	}
	return leaf, nil
}

// afterRoomEvent runs what a committed room.key-package starts: the Add
// Commit of its room, made from the journal.
func (d *Daemon) afterRoomEvent(route admission.Route, event envelope.Event, outcome admission.Outcome) {
	if route != admission.RouteRelay || event.Kind != "room.key-package" || d.relay == nil || d.relay.rooms == nil ||
		(outcome != admission.Accepted && outcome != admission.Duplicate) {
		return
	}
	value, err := payload.Decode(event.Kind, event.Content)
	if err != nil {
		return
	}
	if keyPackage, ok := value.(payload.RoomKeyPackage); ok {
		d.relay.rooms.commitReadyAdds(keyPackage.RoomID)
	}
}

// commitReadyAdds makes the Add Commit of every add of a room whose
// KeyPackage arrived, one joiner per Commit, in arrival order. A failure is
// reported to the owner and tried again on the next maintenance pass.
func (r *roomRuntime) commitReadyAdds(roomID string) {
	// The Adds are committed under the handling lock; their objects go
	// out after it, under the room's fan-out mutex.
	r.commitReadyAddsLocked(roomID)
	r.fanOutRoom(context.Background(), roomID)
}

// commitReadyAddsLocked commits the ready adds of a room under the
// handling lock.
func (r *roomRuntime) commitReadyAddsLocked(roomID string) {
	r.handling.Lock()
	defer r.handling.Unlock()
	now := r.now()
	adds, err := r.daemon.journal.RoomAdds(roomID, now)
	if err != nil {
		r.daemon.report("room add "+roomID, err)
		return
	}
	for _, add := range adds {
		if !add.Ready() {
			continue
		}
		if err := r.commitAdd(add, now); err != nil {
			r.daemon.report("room add "+roomID, err)
			return
		}
	}
}

// commitAddsEverywhere is the maintenance pass over every room this
// installation is the authority of.
func (r *roomRuntime) commitAddsEverywhere() {
	records, err := r.ledger.List()
	if err != nil {
		r.daemon.report("room adds", err)
		return
	}
	for _, record := range records {
		if record.AuthorityAgentID == r.daemon.config.AgentID {
			r.commitReadyAdds(record.RoomID)
		}
	}
}

// commitAdd makes one Add Commit from a ready add, learns the joiner's
// credential and finishes the add. The caller holds the handling lock. An
// add whose Agent is already a member (a crash after the Commit) is only
// learned and finished.
func (r *roomRuntime) commitAdd(add eventlog.RoomAdd, now time.Time) error {
	record, err := r.authorityRecord(add.RoomID, now)
	if err != nil {
		if fault.CodeOf(err) == fault.CodeRoomEnded {
			return r.daemon.journal.FinishRoomAdd(add.RoomID, add.AgentID)
		}
		return err
	}
	device, credential, err := add.Credentials()
	if err != nil {
		return err
	}
	// The joiner's stored evidence, pinned to the Endpoint and device its
	// leaf credential names, is what the Commit's fan-out will deposit
	// under; the credential is judged against that evidence's delegation.
	pin, err := directory.LeafPin(add.AgentID, credential, now)
	if err != nil {
		r.daemon.report("room add "+add.RoomID, err)
		return r.daemon.journal.FinishRoomAdd(add.RoomID, add.AgentID)
	}
	peer, err := r.relay.verifier.CheckStored(add.AgentID, pin, now)
	if err != nil {
		return err
	}
	set, err := e2ee.Summarize(peer.Bundles)
	if err != nil {
		return err
	}
	// The credential is verified again now: the time between its arrival
	// and the Commit may have revoked its device or ended its window.
	binding, err := group.VerifyRoomLeafCredential(peer.Delegation, credential, set, record.RoomEndsAtUnix, now)
	if err != nil {
		r.daemon.report("room add "+add.RoomID, err)
		return r.daemon.journal.FinishRoomAdd(add.RoomID, add.AgentID)
	}
	if !record.Membership().Contains(add.AgentID) {
		leaf, err := group.LeafFromCredentials(device, credential)
		if err != nil {
			return err
		}
		if err := r.stageAdd(record, add.AgentID, leaf, binding, now); err != nil {
			return err
		}
	}
	// The Add's fused write learned the credential with the membership; a
	// member left without it by an earlier write learns it here, as an
	// exact repeat otherwise.
	if _, _, err := r.ledger.LearnRoomCredentials(add.RoomID, []group.LeafBinding{binding}, now); err != nil {
		return err
	}
	return r.daemon.journal.FinishRoomAdd(add.RoomID, add.AgentID)
}

// stageAdd commits the Add of one joiner: the next membership and its
// authorization, the MLS Add, the joiner's leaf credential, and the objects
// staged under the CommitRef, all named by one fused write: the Commit to every earlier member but the authority, the
// Welcome to the joiner, the joiner's full roster, and the roster of the
// added member to the earlier members (section 11.2).
func (r *roomRuntime) stageAdd(record eventlog.RoomMLSRecord, joiner string, leaf group.Leaf,
	binding group.LeafBinding, now time.Time) error {
	credential := binding.Credential()
	earlier := r.othersOf(record.Members)
	membership, err := record.Membership().Add([]string{joiner})
	if err != nil {
		return fault.Wrap(fault.CodePayloadMalformed, err)
	}
	proof, err := r.authorize(membership, now)
	if err != nil {
		return err
	}
	header := &relayframe.RoomHeader{Membership: membership, Authorization: proof.Authorization, EndsAtUnix: record.RoomEndsAtUnix}
	full, err := r.rosterOf(record.RoomID, membership.Members, joiner, credential)
	if err != nil {
		return err
	}
	// The roster of the added member goes to the earlier members only, so
	// it is built only when there is one.
	var added []byte
	if len(earlier) > 0 {
		if added, err = r.rosterOf(record.RoomID, []string{joiner}, "", credential); err != nil {
			return err
		}
	}
	template := group.Transition{Prior: record.Binding(), Membership: membership,
		Next: group.State{RoomID: record.RoomID, Clock: group.Clock{RoomEpoch: membership.Epoch, MLSEpoch: record.MLSEpoch + 1},
			MembershipDigest: membership.Digest}}
	operations := []group.LeafOperation{{Kind: group.LeafAdd, Next: &leaf}}
	build := func(result eventlog.CommitResult) ([]eventlog.StagedRoomObject, error) {
		clock := result.Transition.Next.Clock
		welcome, made := result.Welcomes[leaf.KeyPackageRef]
		if !made {
			return nil, errors.New("the Add Commit made no Welcome for the joiner")
		}
		var objects []eventlog.StagedRoomObject
		if len(earlier) > 0 {
			commit, err := r.object(relayframe.RoomCommit, record.RoomID, clock, header, result.Commit)
			if err != nil {
				return nil, err
			}
			objects = append(objects, staged(eventlog.RoomObjectCommit, clock, commit, earlier, false))
		}
		welcomeObject, err := r.object(relayframe.RoomWelcome, record.RoomID, clock, header, welcome)
		if err != nil {
			return nil, err
		}
		objects = append(objects, staged(eventlog.RoomObjectWelcome, clock, welcomeObject, []string{joiner}, false))
		fullObject, err := r.object(relayframe.RoomRoster, record.RoomID, clock, header, full)
		if err != nil {
			return nil, err
		}
		objects = append(objects, staged(eventlog.RoomObjectRoster, clock, fullObject, []string{joiner}, false))
		if len(earlier) > 0 {
			addedObject, err := r.object(relayframe.RoomRoster, record.RoomID, clock, header, added)
			if err != nil {
				return nil, err
			}
			objects = append(objects, staged(eventlog.RoomObjectRoster, clock, addedObject, earlier, false))
		}
		return objects, nil
	}
	// The joiner's credential is learned in the same fused write as the
	// membership that adds it (section 11.8).
	_, _, err = r.controller.CommitLearning(template, &proof, operations, build, now.Add(r.retention),
		[]group.LeafBinding{binding})
	return err
}

// RemoveRoomMember removes a member: the next membership without it and its
// authorization, the MLS Remove of its leaf, and the Commit staged to every
// remaining member but the authority and once to the removed member
// (section 11.4). A member no longer in the room is a no-op.
func (r *roomRuntime) RemoveRoomMember(ctx context.Context, roomID, agentID string) error {
	if !ids.Agent.MatchString(agentID) {
		return fault.New(fault.CodePayloadMalformed, "invalid member identifier")
	}
	if agentID == r.daemon.config.AgentID {
		return fault.New(fault.CodePayloadMalformed, "the authority cannot remove itself")
	}
	// The Remove is committed under the handling lock. The withdrawals of
	// the removed member's in-flight generations and the removing Commit's
	// deposit follow under the room's fan-out mutex, after the handling
	// lock is released. The Remove is committed by then: withdrawals the
	// carrier did not confirm are retried by the fan-out, never by another
	// Remove.
	removed, err := r.removeLocked(roomID, agentID)
	if err != nil || !removed {
		return err
	}
	lock := r.roomFanoutLock(roomID)
	lock.Lock()
	defer lock.Unlock()
	if !r.withdrawFromRemoved(ctx, roomID, agentID, r.now()) {
		r.daemon.report("room "+roomID+" member "+agentID, ErrRoomWithdrawalsPending)
	}
	r.fanOut(ctx, roomID)
	return nil
}

// removeLocked commits a Remove under the handling lock and reports whether
// it removed a member.
func (r *roomRuntime) removeLocked(roomID, agentID string) (bool, error) {
	r.handling.Lock()
	defer r.handling.Unlock()
	now := r.now()
	record, err := r.authorityRecord(roomID, now)
	if err != nil {
		return false, err
	}
	if err := r.daemon.journal.FinishRoomAdd(roomID, agentID); err != nil {
		return false, err
	}
	if !record.Membership().Contains(agentID) {
		return false, nil
	}
	leaves, err := r.controller.Members(roomID)
	if err != nil {
		return false, err
	}
	leaf, found := memberLeaf(leaves, agentID)
	if !found {
		return false, fault.New(fault.CodeInternal, "the member has no leaf in the room's tree")
	}
	membership, err := record.Membership().Remove([]string{agentID})
	if err != nil {
		return false, fault.Wrap(fault.CodePayloadMalformed, err)
	}
	proof, err := r.authorize(membership, now)
	if err != nil {
		return false, err
	}
	header := &relayframe.RoomHeader{Membership: membership, Authorization: proof.Authorization, EndsAtUnix: record.RoomEndsAtUnix}
	remaining := r.othersOf(membership.Members)
	template := group.Transition{Prior: record.Binding(), Membership: membership,
		Next: group.State{RoomID: roomID, Clock: group.Clock{RoomEpoch: membership.Epoch, MLSEpoch: record.MLSEpoch + 1},
			MembershipDigest: membership.Digest}}
	operations := []group.LeafOperation{{Kind: group.LeafRemove, Prior: &group.Leaf{CredentialIdentity: leaf.Identity}}}
	build := func(result eventlog.CommitResult) ([]eventlog.StagedRoomObject, error) {
		clock := result.Transition.Next.Clock
		commit, err := r.object(relayframe.RoomCommit, roomID, clock, header, result.Commit)
		if err != nil {
			return nil, err
		}
		recipients := make([]eventlog.RoomRecipient, 0, len(remaining)+1)
		for _, member := range remaining {
			recipients = append(recipients, eventlog.RoomRecipient{AgentID: member})
		}
		recipients = append(recipients, eventlog.RoomRecipient{AgentID: agentID, Once: true})
		return []eventlog.StagedRoomObject{{Type: eventlog.RoomObjectCommit, RoomEpoch: clock.RoomEpoch, MLSEpoch: clock.MLSEpoch,
			Object: commit, Recipients: recipients}}, nil
	}
	if _, _, err = r.controller.Commit(template, &proof, operations, build, now.Add(r.retention)); err != nil {
		return false, err
	}
	// The removed member's card goes with its credential.
	if err := r.daemon.journal.ForgetRoomMemberCard(roomID, agentID); err != nil {
		return false, err
	}
	return true, nil
}

// othersOf returns the members other than this installation, ascending.
func (r *roomRuntime) othersOf(members []string) []string {
	others := make([]string, 0, len(members))
	for _, member := range members {
		if member != r.daemon.config.AgentID {
			others = append(others, member)
		}
	}
	sort.Strings(others)
	return others
}

// object encodes one room object of the authority's.
func (r *roomRuntime) object(kind uint8, roomID string, clock group.Clock, header *relayframe.RoomHeader, body []byte) ([]byte, error) {
	return relayframe.EncodeRoomObject(relayframe.RoomObject{Type: kind, RoomID: roomID, RoomEpoch: clock.RoomEpoch,
		MLSEpoch: clock.MLSEpoch, Header: header, Body: body})
}

func staged(kind eventlog.RoomObjectType, clock group.Clock, object []byte, recipients []string, once bool) eventlog.StagedRoomObject {
	list := make([]eventlog.RoomRecipient, 0, len(recipients))
	for _, recipient := range recipients {
		list = append(list, eventlog.RoomRecipient{AgentID: recipient, Once: once})
	}
	return eventlog.StagedRoomObject{Type: kind, RoomEpoch: clock.RoomEpoch, MLSEpoch: clock.MLSEpoch, Object: object, Recipients: list}
}

// rosterOf builds the roster body of the given members except skip: each
// entry carries the member's chat card, its relay evidence and its leaf
// credential, in ascending Agent order. joinerCredential is the credential
// of the joiner the Add is about, which the room's list does not hold yet.
func (r *roomRuntime) rosterOf(roomID string, members []string, skip string, joinerCredential group.LeafCredential) ([]byte, error) {
	entries := make([]relayframe.RosterEntry, 0, len(members))
	for _, member := range members {
		if member == skip {
			continue
		}
		credential := joinerCredential
		if member != joinerCredential.AgentID {
			stored, found, err := r.ledger.RoomCredential(roomID, member)
			if err != nil {
				return nil, err
			}
			if !found {
				return nil, fault.New(fault.CodeInternal, "a member's leaf credential is not in the room's list")
			}
			credential = stored
		}
		encoded, err := group.EncodeLeafCredential(credential)
		if err != nil {
			return nil, err
		}
		card, evidence, err := r.rendezvousOf(roomID, member)
		if err != nil {
			return nil, err
		}
		entries = append(entries, relayframe.RosterEntry{AgentID: member, Card: card, Evidence: evidence, Credential: encoded})
	}
	sort.Slice(entries, func(a, b int) bool { return entries[a].AgentID < entries[b].AgentID })
	return relayframe.EncodeRoster(entries)
}

// rendezvousOf returns a member's chat card and relay evidence for a roster
// entry: this installation's own, or the member's stored card and committed
// relay evidence. A member whose stored card is missing or expired gets no
// entry yet: its evidence pull starts and the roster waits, so no roster
// goes out with an expired card.
func (r *roomRuntime) rendezvousOf(roomID, member string) ([]byte, []byte, error) {
	now := r.now()
	if member == r.daemon.config.AgentID {
		evidence, card, _, err := r.ownEvidence()
		return card, evidence, err
	}
	card, err := r.storedMemberCard(roomID, member, now)
	if err != nil {
		return nil, nil, err
	}
	evidence, found, err := r.daemon.journal.LoadRelayEvidence(member)
	if err != nil {
		return nil, nil, err
	}
	if !found {
		// No object waits on this evidence yet: the roster is not built
		// until it arrives. The demand keeps the pull outstanding while the
		// Commit is retried, and lets it end once the Commit is made or
		// abandoned.
		if requestErr := r.relay.demandEvidence(member, now); requestErr != nil {
			r.daemon.report("relay evidence request", requestErr)
		}
		return nil, nil, fault.New(fault.CodeDescriptorExpired, "a member's relay evidence is not held here")
	}
	return card, evidence, nil
}
