package daemon

// Handshake objects of a private room on the receive side (sections 11.2,
// 11.3, 11.5, 11.8, D18): the authority's Commits, a joiner's Welcome and
// rosters. Each is judged by the receive order before anything moves, its
// header authorization is checked in the relay-route window against the
// authority's delegation as finalized now, its MLS committer or author must
// be the leaf the authority's verified leaf credential binds, and it is
// answered by a signed room ack only once its handling is durable.

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/directory"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/messenger/pkg/room"
)

// handleCommit applies the authority's Commit, in the order of section 11.3:
// sender, judgement, header, committer, then one fused write.
func (r *roomRuntime) handleCommit(in roomInbound) carrierapi.Response {
	roomID := in.object.RoomID
	record, found, err := r.ledger.Current(roomID)
	if err != nil {
		return carrierapi.Retry()
	}
	if !found {
		// A Commit reaches only a member; a pending joiner gets its Welcome
		// first, so this one has nothing to apply it to.
		return ignored()
	}
	// Only the room's single authority commits (section 11.5). The intake
	// refuses another member's part 0 already; this holds for an object a
	// restart replays.
	if in.sender != record.AuthorityAgentID {
		return r.roomAck(in, answerRejected(fault.CodeNotAuthentic))
	}
	digest := in.objectDigest()
	verdict, err := r.daemon.journal.JudgeRoomHandshake(roomID, in.object.MLSEpoch, digest)
	if err != nil {
		return carrierapi.Retry()
	}
	switch verdict {
	case eventlog.HandshakeDuplicate:
		return r.roomAck(in, answerDuplicate)
	case eventlog.HandshakeFork:
		r.daemon.report("room "+roomID, errors.New("a second Commit for an applied MLS epoch: the room is forked"))
		return r.roomAck(in, answerRejected(fault.CodeRoomFork))
	case eventlog.HandshakeStale:
		return ignored()
	case eventlog.HandshakeGap, eventlog.HandshakeApply:
	default:
		return carrierapi.Retry()
	}
	committer, err := r.authorityBinding(record, in)
	if err != nil {
		return r.roomAck(in, answerRejected(fault.CodeNotAuthentic))
	}
	// The header is authenticated before its epoch is judged, so a genuine
	// header of a later epoch is told apart from a forged one.
	proof, membership, code := r.commitHeader(record, in)
	if code != "" {
		return r.roomAck(in, answerRejected(code))
	}
	// A Commit whose verified header removes this member, at any epoch above
	// its own, is a removal notice and is not applied to MLS (sections 11.3,
	// 11.4): the removed member gets it once, outside its queue, marks the
	// room removed and answers nothing.
	if !membership.Contains(r.daemon.config.AgentID) {
		return r.removalNotice(in, digest)
	}
	if verdict == eventlog.HandshakeGap {
		return r.roomAck(in, answerRejected(fault.CodeRoomEpochGap))
	}
	// Only the next MLS epoch is applied: it moves the room epoch by exactly
	// one, or (an MLS-only refresh) not at all.
	if code := commitEpoch(record, in); code != "" {
		return r.roomAck(in, answerRejected(code))
	}
	commitRef := canon.Digest(in.object.Body)
	transition := group.Transition{Prior: record.Binding(),
		Next: group.State{RoomID: roomID, Clock: group.Clock{RoomEpoch: in.object.RoomEpoch, MLSEpoch: in.object.MLSEpoch},
			MembershipDigest: membership.Digest, AcceptedCommitRef: commitRef},
		Membership: membership, CommitRef: commitRef}
	if err := r.daemon.journal.BeginRoomHandshake(roomID, in.object.MLSEpoch, digest, commitRef); err != nil {
		return carrierapi.Retry()
	}
	fresh, _, err := r.controller.Apply(transition, proof, in.object.Body, committer)
	if err != nil {
		return r.applyRefusal(in, err)
	}
	// The members the Commit removed are forgotten here (section 11.4): the
	// fused write already dropped their credentials.
	r.forgetRemoved(in, record.Members, membership.Members)
	if err := r.daemon.journal.CompleteRoomHandshake(roomID, in.object.MLSEpoch, digest); err != nil {
		// The fused write stands; the next judgement resolves the intent.
		r.daemon.report("room handshake record", err)
		return carrierapi.Retry()
	}
	r.commitMemberPeer(roomID, in.peer, in.now)
	// Buffered objects of the epoch the Commit reached are opened now, in
	// arrival order (section 11.3).
	r.releaseBuffered(roomID, false, in.now)
	if !fresh {
		return r.roomAck(in, answerDuplicate)
	}
	return r.roomAck(in, answerAccepted)
}

// removalNotice marks the room removed for a verified Commit that removes
// this member and raises the owner notice once. Nothing is answered: the
// removed member's Commit is outside its queue and is never acked.
func (r *roomRuntime) removalNotice(in roomInbound, digest string) carrierapi.Response {
	fresh, _, err := r.daemon.journal.MarkRoomRemoved(in.object.RoomID, in.object.RoomEpoch, in.object.MLSEpoch, digest, in.now)
	if err != nil {
		if errors.Is(err, eventlog.ErrRoomRemovalEpoch) {
			return r.roomAck(in, answerRejected(fault.CodeNotAuthentic))
		}
		r.daemon.report("room removal", err)
		return carrierapi.Retry()
	}
	if fresh {
		r.daemon.report("room "+in.object.RoomID, ErrRoomRemoved)
	}
	return ignored()
}

// forgetRemoved forgets the members an applied Commit removed. A crash
// before it, or a failure inside it, is repaired by reconcileRemoved.
func (r *roomRuntime) forgetRemoved(in roomInbound, before, after []string) {
	var removed []string
	for _, agentID := range before {
		if !containsAgent(after, agentID) && agentID != r.daemon.config.AgentID {
			removed = append(removed, agentID)
		}
	}
	if len(removed) == 0 {
		return
	}
	r.forgetMembers(in.object.RoomID, removed)
}

// forgetMembers forgets members removed from a room: their sequence
// records, their incomplete parts when no room held here still takes parts
// from them, and the room's admission of their cards, which is queued and
// sent to the carrier outside the handling lock (flushCardForgets; a card
// another admission holds stays). Each step is idempotent receive-side
// bookkeeping, not authority, so a failure is reported and repeated by the
// next reconciliation or flush. The caller holds the handling lock.
func (r *roomRuntime) forgetMembers(roomID string, removed []string) {
	for _, agentID := range removed {
		if _, err := r.daemon.journal.ForgetRoomSender(roomID, agentID); err != nil {
			r.daemon.report("room removed member", err)
		}
		if !(roomSenders{runtime: r}).MayHold(agentID) {
			if _, err := r.parts.DropSender(agentID); err != nil {
				r.daemon.report("room removed member", err)
			}
		}
	}
	r.queueCardForgets(roomID, removed)
}

// applyRefusal answers an MLS step that refused a Commit or Welcome. A
// refusal the ledger or controller names is permanent; anything else (the
// driver could not run) is retried, with nothing acknowledged.
func (r *roomRuntime) applyRefusal(in roomInbound, err error) carrierapi.Response {
	switch {
	case errors.Is(err, eventlog.ErrMLSSenderMismatch), errors.Is(err, eventlog.ErrRoomLeafIdentity),
		errors.Is(err, eventlog.ErrNotRoomAuthority), errors.Is(err, eventlog.ErrRoomAuthorityCredential):
		return r.roomAck(in, answerRejected(fault.CodeNotAuthentic))
	case errors.Is(err, eventlog.ErrMLSFork), errors.Is(err, eventlog.ErrMLSRollback):
		r.daemon.report("room "+in.object.RoomID, errors.New("a Commit is not a child of the applied state: the room is forked"))
		return r.roomAck(in, answerRejected(fault.CodeRoomFork))
	case errors.Is(err, eventlog.ErrMLSGap):
		return r.roomAck(in, answerRejected(fault.CodeRoomEpochGap))
	default:
		r.daemon.report("room handshake", err)
		return carrierapi.Retry()
	}
}

// authorityBinding is the authority's leaf as its stored leaf credential,
// re-verified now against the delegation and device set its checked
// evidence established, expects it: the only committer or roster sender a
// member accepts (section 11.5).
func (r *roomRuntime) authorityBinding(record eventlog.RoomMLSRecord, in roomInbound) (group.LeafBinding, error) {
	credential, found, err := r.ledger.RoomCredential(record.RoomID, record.AuthorityAgentID)
	if err != nil {
		return group.LeafBinding{}, err
	}
	if !found {
		return group.LeafBinding{}, errors.New("the room authority's leaf credential is not known")
	}
	if in.peer.AgentID != record.AuthorityAgentID || in.peer.Delegation.EndpointID != record.AuthorityEndpointID {
		return group.LeafBinding{}, errors.New("the evidence is not the room authority's")
	}
	return memberBinding(in.peer, credential, record.RoomEndsAtUnix, in.now)
}

// commitHeader authenticates a Commit's header: a Commit that changes the
// room epoch carries the membership it makes, authorized by the room's
// authority in the relay window, with the room's end, for a room epoch above
// the member's; an MLS-only refresh carries none. It returns the proof for
// the fused write and the membership the Commit makes, or the refusal code.
// Whether the epoch is the next one is judged after, on the apply path.
func (r *roomRuntime) commitHeader(record eventlog.RoomMLSRecord, in roomInbound) (*eventlog.RoomAuthorityProof, room.Membership, fault.Code) {
	header := in.object.Header
	if header == nil {
		return nil, record.Membership(), ""
	}
	proof, code := r.headerProof(record.AuthorityAgentID, record.AuthorityEndpointID, record.RoomEndsAtUnix, in)
	if code != "" {
		return nil, room.Membership{}, code
	}
	// The object's room epoch is the header membership's (the codec binds
	// them); a header never names an epoch the member already holds.
	if in.object.RoomEpoch <= record.RoomEpoch {
		return nil, room.Membership{}, fault.CodeNotAuthentic
	}
	return &proof, header.Membership, ""
}

// commitEpoch requires an applied Commit to move the room epoch by exactly
// one when it carries a header, and to keep it otherwise.
func commitEpoch(record eventlog.RoomMLSRecord, in roomInbound) fault.Code {
	if in.object.Header == nil {
		if in.object.RoomEpoch != record.RoomEpoch {
			return fault.CodeNotAuthentic
		}
		return ""
	}
	if record.RoomEpoch == ^uint64(0) || in.object.RoomEpoch != record.RoomEpoch+1 {
		return fault.CodeNotAuthentic
	}
	return ""
}

// headerProof checks a handshake header (section 11.1, 11.3, D18): the end
// time is the room's, the authorization is the named authority's, its
// signature verifies against the delegation as finalized now, and it lies in
// the relay window issued - skew <= now < issued + retention + skew. It is
// the check every Install and Advance is preceded by.
func (r *roomRuntime) headerProof(authorityAgentID, authorityEndpointID string, endsAtUnix uint64,
	in roomInbound) (eventlog.RoomAuthorityProof, fault.Code) {
	header := in.object.Header
	if header == nil || header.EndsAtUnix != endsAtUnix {
		return eventlog.RoomAuthorityProof{}, fault.CodeNotAuthentic
	}
	authority := header.Authorization.Authority
	if authority.AgentID != authorityAgentID || authority.EndpointID != authorityEndpointID ||
		in.peer.Delegation.AgentID != authorityAgentID || in.peer.Delegation.EndpointID != authorityEndpointID {
		return eventlog.RoomAuthorityProof{}, fault.CodeNotAuthentic
	}
	if err := room.VerifyMembershipAuthorizationRelay(header.Membership, header.Authorization, in.peer.Delegation,
		in.now, r.retention, r.skew); err != nil {
		return eventlog.RoomAuthorityProof{}, fault.CodeNotAuthentic
	}
	return eventlog.RoomAuthorityProof{Membership: header.Membership, Authorization: header.Authorization,
		Delegation: in.peer.Delegation}, ""
}

// handleWelcome handles a Welcome. A member that already holds the room
// judges it by the receive order (a redelivered Welcome is a duplicate); a
// joiner takes it only through its accepted pending join (section 11.3).
func (r *roomRuntime) handleWelcome(in roomInbound) carrierapi.Response {
	roomID := in.object.RoomID
	record, found, err := r.ledger.Current(roomID)
	if err != nil {
		return carrierapi.Retry()
	}
	if found {
		if in.sender != record.AuthorityAgentID {
			return r.roomAck(in, answerRejected(fault.CodeNotAuthentic))
		}
		verdict, err := r.daemon.journal.JudgeRoomHandshake(roomID, in.object.MLSEpoch, in.objectDigest())
		if err != nil {
			return carrierapi.Retry()
		}
		switch verdict {
		case eventlog.HandshakeDuplicate:
			return r.roomAck(in, answerDuplicate)
		case eventlog.HandshakeStale:
			return ignored()
		case eventlog.HandshakeFork:
			r.daemon.report("room "+roomID, errors.New("a second Welcome for an applied MLS epoch: the room is forked"))
			return r.roomAck(in, answerRejected(fault.CodeRoomFork))
		case eventlog.HandshakeGap:
			return r.roomAck(in, answerRejected(fault.CodeRoomEpochGap))
		case eventlog.HandshakeApply:
			// A member never takes a Welcome into a room it holds.
			return r.roomAck(in, answerRejected(fault.CodeNotAuthentic))
		default:
			return carrierapi.Retry()
		}
	}
	return r.joinWelcome(in)
}

// joinWelcome installs a joiner's Welcome through its accepted pending join.
// The Welcome is authenticated with the authority's leaf credential the
// room.invite carried, re-verified now: there is no bootstrap exception.
func (r *roomRuntime) joinWelcome(in roomInbound) carrierapi.Response {
	roomID := in.object.RoomID
	join, found, err := r.daemon.journal.AcceptedRoomJoin(roomID, in.now)
	if err != nil {
		return carrierapi.Retry()
	}
	if !found || join.AuthorityAgentID != in.sender {
		// No join the owner accepted names this sender: nothing is stored
		// and nothing is signed for it.
		return ignored()
	}
	credential, err := join.AuthorityCredential()
	if err != nil {
		return carrierapi.Retry()
	}
	// The room's end is the authority credential's expiry (D18); the intake
	// refused the Welcome already if it has passed.
	end := credential.ExpiresAtUnix
	authority, err := memberBinding(in.peer, credential, end, in.now)
	if err != nil {
		return r.statelessRejection(in, fault.CodeNotAuthentic)
	}
	header := in.object.Header
	if header == nil || !header.Membership.Contains(r.daemon.config.AgentID) {
		return r.statelessRejection(in, fault.CodeNotAuthentic)
	}
	// The header's end is outside the authorization's signature; it must be
	// the one the authority's Endpoint signed in its leaf credential, which a
	// relay cannot change, so a relay can only cause a refusal.
	proof, code := r.headerProof(join.AuthorityAgentID, credential.EndpointID, end, in)
	if code != "" {
		return r.statelessRejection(in, code)
	}
	identityState, err := r.daemon.journal.RoomJoinIdentityState(join)
	if err != nil {
		return carrierapi.Retry()
	}
	groupID, err := group.MLSGroupID(r.daemon.config.Network(), roomID)
	if err != nil {
		return carrierapi.Retry()
	}
	digest := in.objectDigest()
	welcomeRef := canon.Digest(in.object.Body)
	if err := r.daemon.journal.BeginRoomHandshake(roomID, in.object.MLSEpoch, digest, welcomeRef); err != nil {
		return carrierapi.Retry()
	}
	binding := group.State{RoomID: roomID, Clock: group.Clock{RoomEpoch: in.object.RoomEpoch, MLSEpoch: in.object.MLSEpoch},
		MembershipDigest: header.Membership.Digest}
	if _, err := r.controller.Join(binding, proof, groupID, identityState, in.object.Body, join.KeyPackageRef, authority); err != nil {
		switch {
		case errors.Is(err, eventlog.ErrMLSSenderMismatch), errors.Is(err, eventlog.ErrRoomLeafIdentity),
			errors.Is(err, eventlog.ErrRoomAuthorityCredential), errors.Is(err, eventlog.ErrRoomJoinConflict):
			return r.statelessRejection(in, fault.CodeNotAuthentic)
		case errors.Is(err, eventlog.ErrWelcomeReplay):
			return r.roomAck(in, answerDuplicate)
		default:
			r.daemon.report("room join", err)
			return carrierapi.Retry()
		}
	}
	// The install rooted the authority's credential; only now does the
	// pending join end.
	if err := r.daemon.journal.FinishRoomJoin(roomID); err != nil {
		r.daemon.report("room join", err)
		return carrierapi.Retry()
	}
	if err := r.daemon.journal.CompleteRoomHandshake(roomID, in.object.MLSEpoch, digest); err != nil {
		r.daemon.report("room handshake record", err)
		return carrierapi.Retry()
	}
	r.commitMemberPeer(roomID, in.peer, in.now)
	return r.roomAck(in, answerAccepted)
}

// handleRoster accepts a roster from the room's authority (section 11.2):
// judged by room epoch, its header checked against the committed membership
// of that epoch, every entry a member of it other than this one, and each
// still-current member's leaf credential learned independently of the
// entry's card and evidence, before the room ack is signed (section 11.8).
func (r *roomRuntime) handleRoster(in roomInbound) carrierapi.Response {
	roomID := in.object.RoomID
	record, found, err := r.ledger.Current(roomID)
	if err != nil {
		return carrierapi.Retry()
	}
	if !found {
		// A roster follows the Welcome in the authority's queue; before it
		// there is nothing to learn it into.
		return ignored()
	}
	if in.sender != record.AuthorityAgentID {
		return r.roomAck(in, answerRejected(fault.CodeNotAuthentic))
	}
	epoch := in.object.RoomEpoch
	digest := in.objectDigest()
	verdict, err := r.daemon.journal.JudgeRoomRoster(roomID, epoch, digest)
	if err != nil {
		return carrierapi.Retry()
	}
	switch verdict {
	case eventlog.RosterDuplicate:
		return r.roomAck(in, answerDuplicate)
	case eventlog.RosterConflict:
		r.daemon.report("room "+roomID, errors.New("a second, different roster for one room epoch: room-roster-conflict"))
		return r.roomAck(in, answerRejected(fault.CodeRoomRosterConflict))
	case eventlog.RosterStale:
		return ignored()
	case eventlog.RosterGap:
		return r.roomAck(in, answerRejected(fault.CodeRoomEpochGap))
	case eventlog.RosterAccept:
	default:
		return carrierapi.Retry()
	}
	if _, err := r.authorityBinding(record, in); err != nil {
		return r.roomAck(in, answerRejected(fault.CodeNotAuthentic))
	}
	if _, code := r.headerProof(record.AuthorityAgentID, record.AuthorityEndpointID, record.RoomEndsAtUnix, in); code != "" {
		return r.roomAck(in, answerRejected(code))
	}
	committed, held, err := r.ledger.MembershipAt(roomID, epoch)
	if err != nil {
		return carrierapi.Retry()
	}
	if !held || committed.Digest != in.object.Header.Membership.Digest {
		return r.roomAck(in, answerRejected(fault.CodeNotAuthentic))
	}
	entries, err := relayframe.DecodeRoster(in.object.Body)
	if err != nil {
		return r.roomAck(in, answerRejected(fault.CodePayloadMalformed))
	}
	// A roster is rendezvous, not authority: it can never add an Agent the
	// Commits did not.
	for _, entry := range entries {
		if entry.AgentID == r.daemon.config.AgentID || !committed.Contains(entry.AgentID) {
			return r.roomAck(in, answerRejected(fault.CodeNotAuthentic))
		}
	}
	learned, err := r.learnRoster(in, record, entries)
	if err != nil {
		return r.rosterLearnRefusal(in, err)
	}
	if err := r.daemon.journal.RecordRoomRoster(roomID, epoch, digest); err != nil {
		// Learning is idempotent; the redelivered roster learns it again.
		return carrierapi.Retry()
	}
	r.admitRosterRendezvous(in, record.RoomEndsAtUnix, learned)
	// The roster taught credentials: the objects held for them are opened,
	// and those of senders it did not teach are refused (section 11.8).
	r.releaseBuffered(roomID, true, in.now)
	return r.roomAck(in, answerAccepted)
}

// rosterRendezvous is what a roster entry contributes besides its leaf
// credential: the checked evidence and the card, each kept only if it
// passed its own check.
type rosterRendezvous struct {
	peers []directory.RelayPeer
	cards []carrierapi.RoomCard
}

// learnRoster verifies each entry of a still-current member and learns the
// credentials that verify, durably, before the room ack. An entry whose
// credential fails is skipped whole; a credential that verifies is learned
// even when the entry's card or evidence is stale, and only those are
// skipped (section 11.2).
func (r *roomRuntime) learnRoster(in roomInbound, record eventlog.RoomMLSRecord, entries []relayframe.RosterEntry) (rosterRendezvous, error) {
	leaves, err := r.controller.Members(record.RoomID)
	if err != nil {
		return rosterRendezvous{}, err
	}
	var bindings []group.LeafBinding
	var rendezvous rosterRendezvous
	for _, entry := range entries {
		// Only members still in the room now are learned (D11): a late
		// roster degrades gracefully.
		if !containsAgent(record.Members, entry.AgentID) {
			continue
		}
		binding, ok, err := r.entryBinding(record, entry, leaves, in)
		if err != nil {
			// A finalized-state or ledger read failed: nothing about the
			// entry is known, so the roster is retried, not learned without it.
			return rosterRendezvous{}, err
		}
		if !ok {
			continue
		}
		bindings = append(bindings, binding)
		credential := binding.Credential()
		if pin, err := directory.LeafPin(entry.AgentID, credential, in.now); err == nil {
			if peer, err := r.relay.verifier.CheckPeer(entry.AgentID, entry.Evidence, pin, in.now); err == nil {
				rendezvous.peers = append(rendezvous.peers, peer)
			}
		}
		if checkCardShape(entry.Card, entry.AgentID) == nil {
			rendezvous.cards = append(rendezvous.cards,
				carrierapi.RoomCard{AgentID: entry.AgentID, CardBase64: encodeCard(entry.Card)})
		}
	}
	if len(bindings) == 0 {
		return rendezvous, nil
	}
	if _, _, err := r.ledger.LearnRoomCredentials(record.RoomID, bindings, in.now); err != nil {
		return rosterRendezvous{}, err
	}
	return rendezvous, nil
}

// rosterLearnRefusal answers a roster whose learning failed. A refusal the
// credential store names is permanent and answered rejected not-authentic,
// signed, so the authority's queue stops; anything else (a read or write
// that failed) is retried, with nothing acknowledged.
func (r *roomRuntime) rosterLearnRefusal(in roomInbound, err error) carrierapi.Response {
	switch {
	case errors.Is(err, eventlog.ErrRoomAuthorityCredential), errors.Is(err, eventlog.ErrRoomCredentialEndsEarly),
		errors.Is(err, eventlog.ErrRoomCredentialMember), errors.Is(err, eventlog.ErrRoomCredentialUnverified):
		return r.roomAck(in, answerRejected(fault.CodeNotAuthentic))
	case errors.Is(err, eventlog.ErrRoomNotJoined):
		return ignored()
	default:
		r.daemon.report("room roster", err)
		return carrierapi.Retry()
	}
}

// entryBinding verifies one roster entry's leaf credential (section 11.8):
// the credential's digest, Agent, Endpoint and device are the member leaf's
// compact identity, its leaf key is that leaf's, its signature verifies
// under the member's delegation as finalized now, its device is in the
// device set that Endpoint signed and not revoked here, and its window lasts
// until the room's end. The entry's evidence supplies only the delegation
// and the device set, judged without its freshness.
//
// It reports an error only for a read that failed (finalized state, the
// device ledger), which says nothing about the entry; a verification
// failure skips the entry.
func (r *roomRuntime) entryBinding(record eventlog.RoomMLSRecord, entry relayframe.RosterEntry, leaves []group.MLSMember,
	in roomInbound) (group.LeafBinding, bool, error) {
	credential, err := group.DecodeLeafCredential(entry.Credential)
	if err != nil || credential.AgentID != entry.AgentID {
		return group.LeafBinding{}, false, nil
	}
	leaf, found := memberLeaf(leaves, entry.AgentID)
	if !found || group.CheckLeaf(credential, leaf.Identity, leaf.SignatureKey) != nil {
		return group.LeafBinding{}, false, nil
	}
	authority, err := r.relay.verifier.CheckLeafAuthority(entry.AgentID, entry.Evidence,
		directory.Pin{EndpointID: credential.EndpointID, DeviceID: credential.DeviceID}, in.now)
	if err != nil {
		if fault.CodeOf(err) == fault.CodeInternal {
			return group.LeafBinding{}, false, err
		}
		return group.LeafBinding{}, false, nil
	}
	standing, err := r.daemon.discovery.devices.Judge(credential.EndpointID, credential.DeviceID)
	if err != nil {
		return group.LeafBinding{}, false, err
	}
	if standing == eventlog.DeviceRevoked {
		return group.LeafBinding{}, false, nil
	}
	binding, err := group.VerifyRoomLeafCredential(authority.Delegation, credential, authority.DeviceSet, record.RoomEndsAtUnix, in.now)
	if err != nil || !binding.Matches(leaf) {
		return group.LeafBinding{}, false, nil
	}
	return binding, true, nil
}

// memberLeaf finds the one leaf of the tree whose compact identity names an
// Agent; relay rooms carry one device per Agent (D3), so a second is refused.
func memberLeaf(leaves []group.MLSMember, agentID string) (group.MLSMember, bool) {
	var found *group.MLSMember
	for index := range leaves {
		identity, err := group.DecodeLeafIdentity(leaves[index].Identity)
		if err != nil || identity.AgentID != agentID {
			continue
		}
		if found != nil {
			return group.MLSMember{}, false
		}
		found = &leaves[index]
	}
	if found == nil {
		return group.MLSMember{}, false
	}
	return group.MLSMember{Index: found.Index, Identity: bytes.Clone(found.Identity),
		SignatureKey: bytes.Clone(found.SignatureKey)}, true
}

// admitRosterRendezvous commits the evidence and admits the cards a roster
// taught, after the credentials are durable. Neither is authority, so a
// failure here is reported and the roster still stands: the kind-4 pull
// repairs evidence, and part 0 of later room traffic renews cards. The
// admission carries the fused record's room end, so the carrier drops it on
// its own once the room is over (D18), even if no forget ever reaches it.
func (r *roomRuntime) admitRosterRendezvous(in roomInbound, roomEndsAtUnix uint64, learned rosterRendezvous) {
	for _, peer := range learned.peers {
		r.commitMemberPeer(in.object.RoomID, peer, in.now)
	}
	if len(learned.cards) == 0 {
		return
	}
	// The caller holds the handling lock: the admission is sent after it.
	r.queueCardAdmission(roomCardAdmission{roomID: in.object.RoomID, roomEndsAtUnix: roomEndsAtUnix, cards: learned.cards})
}
