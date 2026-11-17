package daemon

// The authority's handshake fan-out (sections 11.2, 11.3, 11.4, 11.7, D10,
// D18).
//
// Every Commit, Welcome and roster staged under a CommitRef is delivered to
// each recipient member through that member's own queue, in epoch order,
// with at most one object in flight: the next is deposited only after a
// verified room ack of the previous, accepted or duplicate. A rejected ack,
// a lost-state rejection or the end of the handshake retention stops the
// member's queue with an owner notice. An object is re-deposited at 80 % of
// the smallest TTL of the member's card (10-minute floor), every part
// together under a new generation whose carry withdraws the previous one,
// until it is acknowledged or the retention ends. A removed member gets its
// removing Commit once, outside its queue. Before every deposit the
// member's stored evidence passes CheckPeer pinned to its leaf credential;
// a deposit the carrier answers with retry (a full mailbox, 507, included)
// waits 30 s, doubling to 5 min.

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/directory"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

const (
	// handshakeBackoffBase and handshakeBackoffCap bound the wait after a
	// deposit the carrier answered with retry (section 2.5).
	handshakeBackoffBase = 30 * time.Second
	handshakeBackoffCap  = 5 * time.Minute
)

// Owner notices of the fan-out.
var (
	// ErrRoomMemberRejected is raised when a member's verified room ack
	// rejected a handshake object: its queue stops.
	ErrRoomMemberRejected = errors.New("a room member rejected a handshake object; its queue stopped")
	// ErrRoomMemberLostState is raised when a member answered a Commit or
	// roster with a rejection that carries no MLS state.
	ErrRoomMemberLostState = errors.New("a room member lost its MLS state; its queue stopped and it should be removed")
	// ErrRoomMemberRetention is raised when a member did not acknowledge a
	// handshake object within the handshake retention.
	ErrRoomMemberRetention = errors.New("a room member did not acknowledge a handshake object within the retention; its queue stopped and it should be removed")
	// ErrRoomMemberCarrierRefused is raised when the carrier refused a
	// handshake deposit to a member for good (not retry, peer-cap or a
	// missing card): its queue stops.
	ErrRoomMemberCarrierRefused = errors.New("the carrier refused a handshake object for a room member; its queue stopped")
	// ErrRoomWithdrawalsPending is raised when a Remove's withdrawals of
	// the removed member's in-flight generations were not all confirmed:
	// the fan-out retries them.
	ErrRoomWithdrawalsPending = errors.New("withdrawals to a removed room member are not confirmed yet; they are retried")
)

// fanoutBackoff is the in-memory wait of deposits the carrier answered
// with retry, per (object, member). A restart starts the waits afresh.
type fanoutBackoff struct {
	mutex sync.Mutex
	waits map[string]backoffState
}

type backoffState struct {
	attempts int
	until    time.Time
}

func (b *fanoutBackoff) due(key string, now time.Time) bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	state, found := b.waits[key]
	return !found || !now.Before(state.until)
}

func (b *fanoutBackoff) failed(key string, now time.Time) time.Time {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if b.waits == nil {
		b.waits = map[string]backoffState{}
	}
	state := b.waits[key]
	wait := handshakeBackoffBase
	for step := 0; step < state.attempts && wait < handshakeBackoffCap; step++ {
		wait *= 2
	}
	if wait > handshakeBackoffCap {
		wait = handshakeBackoffCap
	}
	if state.attempts < 16 {
		state.attempts++
	}
	state.until = now.Add(wait)
	b.waits[key] = state
	return state.until
}

func (b *fanoutBackoff) clear(key string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	delete(b.waits, key)
}

// sweepHandshakes deposits what every queue of every room this
// installation is the authority of has due. It runs under the handling
// lock, as every other path into fanOut does, so no deposit interleaves
// with a Remove, an Add or an ack.
func (r *roomRuntime) sweepHandshakes(ctx context.Context) {
	r.handling.Lock()
	defer r.handling.Unlock()
	records, err := r.ledger.List()
	if err != nil {
		r.daemon.report("room fan-out", err)
		return
	}
	for _, record := range records {
		if record.AuthorityAgentID == r.daemon.config.AgentID {
			r.fanOut(ctx, record)
		}
	}
}

// fanOut serves one room: each removed member's single Commit, the
// withdrawals still owed to removed members, and the head of every member's
// queue. The caller holds the handling lock.
func (r *roomRuntime) fanOut(ctx context.Context, record eventlog.RoomMLSRecord) {
	now := r.now()
	heads, err := r.daemon.journal.RoomOutboxHeads(record.RoomID)
	if err != nil {
		r.daemon.report("room fan-out "+record.RoomID, err)
		return
	}
	members := map[string]struct{}{}
	for _, head := range heads {
		for _, member := range head.Members {
			if !member.Once {
				members[member.AgentID] = struct{}{}
			}
		}
	}
	// A member no longer in the room gets nothing more: the withdrawals of
	// its in-flight generations are retried until the carrier confirms them
	// (section 11.4), also past the room's end.
	for member := range members {
		if !containsAgent(record.Members, member) {
			r.withdrawFromRemoved(ctx, record.RoomID, member, now)
			delete(members, member)
		}
	}
	// D18: the authority's queues stop at the room's end minus the skew.
	if r.sendingStopped(record.RoomEndsAtUnix, now) {
		return
	}
	for _, head := range heads {
		for _, member := range head.Members {
			if member.Once && member.State == eventlog.RoomDeliveryPending {
				r.depositHandshake(ctx, record, head, member, now)
			}
		}
	}
	for member := range members {
		if stopped, err := r.queueStopped(record.RoomID, member); err != nil || stopped {
			continue
		}
		queue, err := r.daemon.journal.RoomMemberQueue(record.RoomID, member)
		if err != nil {
			r.daemon.report("room fan-out "+record.RoomID, err)
			continue
		}
		if len(queue) == 0 {
			continue
		}
		head := queue[0]
		delivery, _ := head.Member(member)
		if uint64(now.Unix()) >= head.RetainUntilUnix {
			// The stop is recorded before the slot is settled, so the
			// stop outlives the head's retirement; without it the slot
			// stays for the next pass.
			if !r.stopQueue(record.RoomID, member, fault.CodeRetentionExceeded, ErrRoomMemberRetention, now) {
				continue
			}
			if _, err := r.daemon.journal.RoomOutboxAbandon(head.ObjectDigest, member, fault.CodeRetentionExceeded, now); err != nil {
				r.daemon.report("room fan-out "+record.RoomID, err)
			}
			continue
		}
		switch delivery.State {
		case eventlog.RoomDeliveryPending:
			r.depositHandshake(ctx, record, head, delivery, now)
		case eventlog.RoomDeliveryCarried:
			if delivery.NextRedepositAtUnix != 0 && uint64(now.Unix()) >= delivery.NextRedepositAtUnix {
				r.depositHandshake(ctx, record, head, delivery, now)
			}
		}
	}
}

// queueStopped reports whether a member's queue stopped (a rejection, lost
// state or the retention end), from its durable marker.
func (r *roomRuntime) queueStopped(roomID, member string) (bool, error) {
	_, stopped, err := r.daemon.journal.RoomMemberQueueStop(roomID, member)
	return stopped, err
}

// stopQueue records a member's stopped queue and raises the owner notice
// once. It reports whether the queue is stopped durably: a caller settles
// the slot that stopped it only then, so a crash or a failed write never
// leaves a settled head without its stop.
func (r *roomRuntime) stopQueue(roomID, member string, code fault.Code, notice error, now time.Time) bool {
	stopped, err := r.queueStopped(roomID, member)
	if err != nil {
		r.daemon.report("room fan-out "+roomID, err)
		return false
	}
	if stopped {
		return true
	}
	if err := r.daemon.journal.StopRoomMemberQueue(roomID, member, code, now); err != nil {
		r.daemon.report("room fan-out "+roomID, err)
		return false
	}
	r.daemon.report("room "+roomID+" member "+member, notice)
	return true
}

// handshakeKey names one (object, member) for the backoff.
func handshakeKey(digest, member string) string { return digest + "\x00" + member }

// pendingHandshakeTo reports whether the head of a member's handshake queue
// waits for its first deposit: handshake objects go before application
// objects in every per-peer queue (section 11.2).
func (r *roomRuntime) pendingHandshakeTo(roomID, member string) bool {
	record, found, err := r.ledger.Current(roomID)
	if err != nil || !found || record.AuthorityAgentID != r.daemon.config.AgentID {
		return false
	}
	queue, err := r.daemon.journal.RoomMemberQueue(roomID, member)
	if err != nil {
		return false
	}
	// Only the queue's head is ever deposited: it goes first when it waits
	// for its first deposit.
	if len(queue) == 0 {
		return false
	}
	delivery, found := queue[0].Member(member)
	return found && delivery.State == eventlog.RoomDeliveryPending
}

// depositHandshake deposits every part of one object to one member under
// its next generation. The member's stored evidence passes CheckPeer pinned
// to its leaf credential first; a removed member's, whose credential left
// the room's list with the removing write, is checked against its own
// Endpoint and device. The generation is recorded carried only once every
// part was carried; a retry answer keeps it for the same generation later.
func (r *roomRuntime) depositHandshake(ctx context.Context, record eventlog.RoomMLSRecord, head eventlog.RoomOutboxHead,
	delivery eventlog.RoomMemberDelivery, now time.Time) {
	member := delivery.AgentID
	key := handshakeKey(head.ObjectDigest, member)
	if !r.backoff.due(key, now) {
		return
	}
	if delivery.Generation == ^uint32(0) {
		return
	}
	// The next generation is the recorded one plus one: a crash, or a part
	// the carrier asked to retry, before the generation was recorded
	// repeats it under the same keys, and the carrier reuses its envelopes.
	generation := delivery.Generation + 1
	if delivery.Once {
		if _, err := r.relay.verifier.CheckStoredContact(member, now); err != nil {
			r.evidenceFailed(member, err, now)
			return
		}
	} else {
		credential, known, err := r.ledger.RoomCredential(record.RoomID, member)
		if err != nil || !known {
			return
		}
		pin, err := directory.LeafPin(member, credential, now)
		if err != nil {
			return
		}
		if _, err := r.relay.verifier.CheckStored(member, pin, now); err != nil {
			r.evidenceFailed(member, err, now)
			return
		}
	}
	object, err := r.daemon.journal.RoomOutboxObject(head.ObjectDigest)
	if err != nil {
		r.daemon.report("room fan-out "+record.RoomID, err)
		return
	}
	evidence, card, _, err := r.ownEvidence()
	if err != nil {
		return
	}
	frames, err := relayframe.SplitRoomObject(object, card, evidence, r.partBytes)
	if err != nil {
		r.daemon.report("room fan-out "+record.RoomID, err)
		return
	}
	smallest := uint64(carrierapi.MaxRelayTTLSeconds)
	for index, frame := range frames {
		partKey, err := relayframe.RoomIdempotencyKey(head.ObjectDigest, member, generation, uint8(index))
		if err != nil {
			return
		}
		withdraw := ""
		if generation > 1 {
			if withdraw, err = relayframe.RoomIdempotencyKey(head.ObjectDigest, member, generation-1, uint8(index)); err != nil {
				return
			}
		}
		response, err := r.relay.carrier.Carry(ctx, member, partKey, withdraw, head.RetainUntilUnix, frame)
		if err != nil || response.Result == carrierapi.ResultRetry ||
			(response.Result != carrierapi.ResultCarried && response.Code == carrierapi.CodePeerCap) ||
			(response.Result != carrierapi.ResultCarried && response.Code == carrierapi.CodeNoPeerCard) {
			// Nothing is lost: the same generation is deposited again,
			// and the carrier reuses the envelopes it already holds.
			r.backoff.failed(key, now)
			return
		}
		if response.Result != carrierapi.ResultCarried {
			// A refusal for good: a queued member's queue stops, with its
			// notice, before the head is abandoned, so the next object
			// does not go out behind it. The removed member's single
			// Commit has no queue; its refusal is reported.
			if delivery.Once {
				r.daemon.report("room "+record.RoomID+" member "+member, ErrRoomMemberCarrierRefused)
			} else if !r.stopQueue(record.RoomID, member, fault.CodeRejected, ErrRoomMemberCarrierRefused, now) {
				return
			}
			if _, err := r.daemon.journal.RoomOutboxAbandon(head.ObjectDigest, member, fault.CodeRejected, now); err != nil {
				r.daemon.report("room fan-out "+record.RoomID, err)
			}
			return
		}
		if carrierapi.ValidateRelayTTL(response.RelayTTLSeconds) == nil && response.RelayTTLSeconds < smallest {
			smallest = response.RelayTTLSeconds
		}
	}
	r.backoff.clear(key)
	delay, err := r.relay.redepositDelay(smallest)
	if err != nil {
		return
	}
	if _, err := r.daemon.journal.RoomOutboxCarried(head.ObjectDigest, member, generation, canon.Digest(evidence),
		now.Add(delay), now); err != nil {
		r.daemon.report("room fan-out "+record.RoomID, err)
	}
}

// evidenceFailed starts the member's evidence pull when its stored
// evidence failed CheckPeer; the deposit waits for the repair.
func (r *roomRuntime) evidenceFailed(member string, err error, now time.Time) {
	if fault.CodeOf(err) == fault.CodeInternal {
		return
	}
	if requestErr := r.relay.requestEvidence(member, now); requestErr != nil {
		r.daemon.report("relay evidence request", requestErr)
	}
}

// roomAckReceived applies a member's room ack (section 11.7): the ack's
// Endpoint and device must be the member's own, as its leaf credential and
// the frame's evidence pinned to it show, and its signature must verify
// under that Endpoint's finalized key. Only the packet sender's own slot is
// settled. A rejection stops the member's queue with an owner notice.
func (r *roomRuntime) roomAckReceived(ctx context.Context, sender string, frame relayframe.Frame) carrierapi.Response {
	ack, err := relayframe.DecodeRoomAck(frame.Part)
	if err != nil {
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
	}
	record, found, err := r.ledger.Current(ack.RoomID)
	if err != nil {
		return carrierapi.Retry()
	}
	if !found || record.AuthorityAgentID != r.daemon.config.AgentID {
		return carrierapi.Response{Result: carrierapi.ResultIgnored}
	}
	now := r.now()
	credential, known, err := r.ledger.RoomCredential(ack.RoomID, sender)
	if err != nil {
		return carrierapi.Retry()
	}
	if !known {
		return carrierapi.Response{Result: carrierapi.ResultIgnored}
	}
	pin, err := directory.LeafPin(sender, credential, now)
	if err != nil {
		return carrierapi.Refusal(carrierapi.CodeSenderMismatch)
	}
	peer, err := r.relay.verifier.CheckPeer(sender, frame.Evidence, pin, now)
	if err != nil {
		if fault.CodeOf(err) == fault.CodeInternal {
			return carrierapi.Retry()
		}
		return carrierapi.Refusal(carrierapi.CodeEvidenceRefused)
	}
	if peer.Delegation.AgentID != sender || peer.Delegation.EndpointID != ack.RecipientEndpointID ||
		credential.EndpointID != ack.RecipientEndpointID || credential.DeviceID != ack.RecipientDeviceID {
		return carrierapi.Refusal(carrierapi.CodeSenderMismatch)
	}
	if err := relayframe.VerifyRoomAck(ack, peer.Delegation.IdentityPublicKey); err != nil {
		return carrierapi.Refusal(carrierapi.CodeSenderMismatch)
	}
	if ack.AckedAtUnix > uint64(now.Add(maxAckSkew).Unix()) {
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
	}
	digest := hex.EncodeToString(ack.ObjectDigest[:])
	stateless := len(ack.EpochAuthenticator) == 0
	// The settlement, the stop and the next deposit are serialized with
	// every other fan-out path.
	r.handling.Lock()
	defer r.handling.Unlock()
	if ack.Outcome == relayframe.OutcomeRejected {
		// The stop is written before the slot is settled: a settled
		// rejection never leaves the queue running.
		stops, lost, err := r.rejectionStops(ack.RoomID, digest, sender, stateless)
		if err != nil {
			return carrierapi.Retry()
		}
		notice := ErrRoomMemberRejected
		if lost {
			notice = ErrRoomMemberLostState
		}
		if stops && !r.stopQueue(ack.RoomID, sender, ack.Code, notice, now) {
			return carrierapi.Retry()
		}
	}
	_, err = r.daemon.journal.RoomOutboxAcked(digest, sender, eventlog.RoomAckOutcome(ack.Outcome), ack.Code, stateless, now)
	switch {
	case err == nil:
	case errors.Is(err, eventlog.ErrUnknown), errors.Is(err, eventlog.ErrNotPending):
		return carrierapi.Response{Result: carrierapi.ResultIgnored}
	case ack.Outcome == relayframe.OutcomeRejected:
		// The stop holds; the repeat of the ack settles the slot.
		return carrierapi.Retry()
	default:
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
	}
	if ack.Outcome != relayframe.OutcomeRejected {
		// The member's next object is due now.
		r.fanOut(ctx, record)
	}
	return carrierapi.Response{Result: carrierapi.ResultApplied}
}

// rejectionStops reports whether a member's rejection of an object stops
// its queue: only when it settles a slot of that member's queue. An ack of
// an unknown object, of a removed member's single Commit or of an object
// never carried to the member stops nothing and is answered by the
// settlement itself. lost reports a stateless rejection of a Commit or
// roster: lost state.
func (r *roomRuntime) rejectionStops(roomID, digest, member string, stateless bool) (stops, lost bool, err error) {
	heads, err := r.daemon.journal.RoomOutboxHeads(roomID)
	if err != nil {
		return false, false, err
	}
	for _, head := range heads {
		if head.ObjectDigest != digest {
			continue
		}
		delivery, found := head.Member(member)
		if !found || delivery.Once ||
			delivery.State != eventlog.RoomDeliveryCarried && delivery.State != eventlog.RoomDeliveryRejected {
			return false, false, nil
		}
		return true, stateless && head.Type != eventlog.RoomObjectWelcome, nil
	}
	return false, false, nil
}

// withdrawFromRemoved withdraws the in-flight handshake generations to a
// removed member and abandons its slots (section 11.4); the removing
// Commit, addressed once, is left to its single deposit. Both the recorded
// generation and the next one are withdrawn: a deposit cut short by a
// retry answer leaves parts of a generation that was never recorded. A slot
// is abandoned only once the carrier confirmed every withdrawal (withdrawn,
// or ignored for a key it does not hold); otherwise it stays, nothing more
// is deposited to the member, and the next fan-out pass tries again, until
// the head's retention ends, the expiry every one of its envelopes carries.
// It reports whether every slot is settled. The caller holds the handling
// lock.
func (r *roomRuntime) withdrawFromRemoved(ctx context.Context, roomID, member string, now time.Time) bool {
	heads, err := r.daemon.journal.RoomOutboxHeads(roomID)
	if err != nil {
		r.daemon.report("room fan-out "+roomID, err)
		return false
	}
	settled := true
	for _, head := range heads {
		delivery, found := head.Member(member)
		if !found || delivery.Once {
			continue
		}
		if delivery.State != eventlog.RoomDeliveryPending && delivery.State != eventlog.RoomDeliveryCarried {
			continue
		}
		if uint64(now.Unix()) < head.RetainUntilUnix && !r.withdrawGenerations(ctx, head, delivery) {
			settled = false
			continue
		}
		if _, err := r.daemon.journal.RoomOutboxAbandon(head.ObjectDigest, member, fault.CodeNotARoomMember, now); err != nil &&
			!errors.Is(err, eventlog.ErrNotPending) {
			r.daemon.report("room fan-out "+roomID, err)
			settled = false
		}
	}
	return settled
}

// withdrawGenerations withdraws every part of a slot's recorded generation
// and of the next, reporting whether the carrier confirmed each one.
func (r *roomRuntime) withdrawGenerations(ctx context.Context, head eventlog.RoomOutboxHead, delivery eventlog.RoomMemberDelivery) bool {
	sizes, err := relayframe.RoomCut(uint8(head.Type), int(head.Length), r.partBytes)
	if err != nil {
		r.daemon.report("room fan-out "+head.RoomID, err)
		return false
	}
	confirmed := true
	for _, generation := range []uint32{delivery.Generation, delivery.Generation + 1} {
		// Generation 0 is never deposited, and the next of the largest
		// generation wraps to it.
		if generation == 0 {
			continue
		}
		for index := range sizes {
			key, err := relayframe.RoomIdempotencyKey(head.ObjectDigest, delivery.AgentID, generation, uint8(index))
			if err != nil {
				r.daemon.report("room fan-out "+head.RoomID, err)
				return false
			}
			response, err := r.relay.carrier.Withdraw(ctx, delivery.AgentID, key)
			if err != nil || response.Result != carrierapi.ResultWithdrawn && response.Result != carrierapi.ResultIgnored {
				confirmed = false
			}
		}
	}
	return confirmed
}
