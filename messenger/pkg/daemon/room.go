package daemon

// The room runtime is the daemon half of private rooms over the relay
// (section 11). It sits beside relayRuntime and owns kind 3: every part of a
// room object goes through the durable part store and its Reassembler, every
// part 0 has its relay identity evidence checked against the sender's
// verified leaf credential, and a complete object is handled in the receive
// order of section 11.3 before it is answered.
//
// This file is the intake: the part store, the sender set, the part-0
// evidence check and the answers. room_handshake.go handles Commits,
// Welcomes and rosters.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/directory"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/messenger/pkg/room"
)

// roomCarrier is the part of the carrier a room receiver calls besides
// carrier.carry: the card admissions a roster teaches.
type roomCarrier interface {
	RoomCards(ctx context.Context, roomID string, cards []carrierapi.RoomCard) (carrierapi.Response, error)
	// ForgetRoomCards drops the room's admission of removed members' cards;
	// a card another admission (a contact, a session, another room) holds
	// stays with the carrier.
	ForgetRoomCards(ctx context.Context, roomID string, agentIDs []string) (carrierapi.Response, error)
}

// roomRuntime receives private room objects.
type roomRuntime struct {
	relay      *relayRuntime
	daemon     *Daemon
	ledger     *eventlog.RoomMLSLedger
	controller *eventlog.RoomMLSController
	parts      *eventlog.RoomParts
	cards      roomCarrier
	// skew is the daemon's clock-skew bound: the room end (D18) and the
	// relay authorization window (D16) are applied with it at both ends.
	skew time.Duration
	// retention is the handshake retention the relay authorization window
	// adds to an authorization's issue time.
	retention time.Duration

	// handling serializes the handling of complete objects, so the judgement,
	// the MLS step and the applied-digest record of one object are never
	// interleaved with another's.
	handling sync.Mutex

	// noticed holds the rooms whose end was already raised to the owner by
	// this process: one notice per room, not one per refused object.
	noticedMutex sync.Mutex
	noticed      map[string]struct{}
}

// ErrRoomRemoved is the owner notice of a room this installation was removed
// from (section 11.4).
var ErrRoomRemoved = errors.New("this installation was removed from the private room; it accepts and sends nothing more there")

// roomRuntimeSettings are the values the room runtime is built with.
type roomRuntimeSettings struct {
	driver    group.AttributedDriver
	cards     roomCarrier
	skew      time.Duration
	retention time.Duration
	partBytes int
}

// installRoomRuntime builds the room runtime on an installed relay runtime:
// the fused ledger, the MLS controller around the driver, and the part store,
// which replays every stored part into a fresh Reassembler. Complete objects
// a crash left unsettled are handled again before the runtime serves.
func (d *Daemon) installRoomRuntime(settings roomRuntimeSettings) error {
	if d == nil || d.relay == nil || d.journal == nil || d.discovery == nil || d.discovery.relay == nil ||
		d.discovery.devices == nil {
		return errors.New("room runtime needs the relay runtime and its verifier")
	}
	if settings.driver == nil || settings.cards == nil {
		return errors.New("room runtime needs an MLS driver and a carrier")
	}
	if settings.skew <= 0 || settings.skew > room.MaxRoomAuthorizationSkew {
		return errors.New("room clock skew is outside 1s..1h")
	}
	if settings.retention <= 0 || settings.retention > room.RoomHandshakeRetention {
		return errors.New("room handshake retention is outside its bound")
	}
	ledger, err := d.journal.OpenRoomMLS()
	if err != nil {
		return err
	}
	controller, err := eventlog.NewRoomMLSController(ledger, settings.driver, d.clock)
	if err != nil {
		return err
	}
	runtime := &roomRuntime{relay: d.relay, daemon: d, ledger: ledger, controller: controller, cards: settings.cards,
		skew: settings.skew, retention: settings.retention, noticed: map[string]struct{}{}}
	// Rooms past their retirement time are retired before anything else,
	// a crash's half-retired room included, and only then is garbage
	// collected, so the retired rooms' records are reclaimed (section 11.8).
	if _, err := ledger.RetireEndedRooms(d.clock(), settings.retention, settings.skew); err != nil {
		return err
	}
	if report, err := d.journal.CollectRoomGarbage(); err != nil {
		return err
	} else if report.FailedClosed {
		d.report("room garbage collection", errors.New("a room root is unreadable; nothing was collected"))
	}
	limits := relayframe.DefaultReassemblyLimits()
	limits.PartBytes = settings.partBytes
	reassembler, err := relayframe.NewReassembler(limits, roomSenders{runtime: runtime})
	if err != nil {
		return err
	}
	parts, replay, err := d.journal.OpenRoomParts(reassembler, d.clock())
	if err != nil {
		return err
	}
	runtime.parts = parts
	// A crash or a failed carrier call may have left a removed member
	// remembered; it is forgotten before the runtime serves.
	runtime.reconcileRemoved()
	d.relay.rooms = runtime
	for _, completed := range replay.Completed {
		runtime.handleReplayed(completed)
	}
	return nil
}

func (r *roomRuntime) now() time.Time { return r.daemon.clock() }

// roomSenders is the Reassembler's sender set: parts are held only from a
// current member of a room this installation holds, or from the authority
// of a room it asked to join. A read failure holds nothing.
type roomSenders struct{ runtime *roomRuntime }

func (s roomSenders) MayHold(sender string) bool {
	if sender == s.runtime.daemon.config.AgentID {
		return false
	}
	records, err := s.runtime.ledger.List()
	if err != nil {
		return false
	}
	for _, record := range records {
		if containsAgent(record.Members, sender) {
			return true
		}
	}
	joins, err := s.runtime.daemon.journal.ListPendingRoomJoins(s.runtime.now())
	if err != nil {
		return false
	}
	for _, join := range joins {
		if join.State == eventlog.JoinKeyPackageSent && join.AuthorityAgentID == sender {
			return true
		}
	}
	return false
}

func (s roomSenders) MayHoldInRoom(sender, roomID string) bool {
	if sender == s.runtime.daemon.config.AgentID {
		return false
	}
	record, found, err := s.runtime.ledger.Current(roomID)
	if err != nil {
		return false
	}
	if found {
		return containsAgent(record.Members, sender)
	}
	join, found, err := s.runtime.daemon.journal.AcceptedRoomJoin(roomID, s.runtime.now())
	return err == nil && found && join.AuthorityAgentID == sender
}

func containsAgent(members []string, agentID string) bool {
	for _, member := range members {
		if member == agentID {
			return true
		}
	}
	return false
}

// senderCredential is the leaf credential the sender's evidence is pinned
// to in a room: the stored credential of a member of a room held here, or
// the authority credential of the accepted join of a room being joined. A
// member whose credential is not known yet has none.
func (r *roomRuntime) senderCredential(roomID, sender string, now time.Time) (group.LeafCredential, bool, error) {
	_, held, err := r.ledger.Current(roomID)
	if err != nil {
		return group.LeafCredential{}, false, err
	}
	if held {
		return r.ledger.RoomCredential(roomID, sender)
	}
	join, found, err := r.daemon.journal.AcceptedRoomJoin(roomID, now)
	if err != nil || !found || join.AuthorityAgentID != sender {
		return group.LeafCredential{}, false, err
	}
	credential, err := join.AuthorityCredential()
	if err != nil {
		return group.LeafCredential{}, false, err
	}
	return credential, true, nil
}

// checkSenderEvidence runs CheckPeer (read-only) on part-0 evidence, pinned
// to the Endpoint and device of the sender's verified leaf credential.
func (r *roomRuntime) checkSenderEvidence(roomID, sender string, evidence []byte, now time.Time) (directory.RelayPeer, error) {
	credential, found, err := r.senderCredential(roomID, sender, now)
	if err != nil {
		return directory.RelayPeer{}, fault.Wrap(fault.CodeInternal, err)
	}
	if !found {
		return directory.RelayPeer{}, fault.New(fault.CodeNotAuthentic, "the sender's leaf credential is not known in the room")
	}
	pin, err := directory.LeafPin(sender, credential, now)
	if err != nil {
		return directory.RelayPeer{}, err
	}
	return r.relay.verifier.CheckPeer(sender, evidence, pin, now)
}

// evidenceRefusal answers a part-0 evidence failure: a finalized-state read
// failure is retried, anything else relay-acknowledged with a refusal.
func evidenceRefusal(err error) carrierapi.Response {
	if fault.CodeOf(err) == fault.CodeInternal {
		return carrierapi.Retry()
	}
	return carrierapi.Refusal(carrierapi.CodeEvidenceRefused)
}

// partRefusal maps a part-store or reassembly refusal to its answer. A part
// the store could not make durable is retried; every reassembly refusal is
// relay-acknowledged and nothing else.
func partRefusal(err error) carrierapi.Response {
	switch {
	case errors.Is(err, eventlog.ErrRoomPartStore):
		return carrierapi.Retry()
	case errors.Is(err, relayframe.ErrReassemblyNotAdmitted):
		return carrierapi.Refusal(carrierapi.CodeNotAdmitted)
	case errors.Is(err, relayframe.ErrFrameMalformed), errors.Is(err, relayframe.ErrFrameDigest),
		errors.Is(err, relayframe.ErrReassemblyCut):
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
	case errors.Is(err, relayframe.ErrReassemblyObjectTooLarge), errors.Is(err, relayframe.ErrReassemblyPeerObjects),
		errors.Is(err, relayframe.ErrReassemblyPeerBytes), errors.Is(err, relayframe.ErrReassemblyTotalBytes),
		errors.Is(err, relayframe.ErrReassemblyInconsistent), errors.Is(err, relayframe.ErrReassemblyDigest):
		return carrierapi.Refusal(carrierapi.CodeNotAccepted)
	default:
		// A write the store could not make, or a read it could not do, is
		// retried: nothing was relay-acknowledged.
		return carrierapi.Retry()
	}
}

// deliver handles one kind-3 frame from a verified packet's sender.
func (r *roomRuntime) deliver(ctx context.Context, sender string, frame relayframe.Frame) carrierapi.Response {
	if ctx == nil {
		return carrierapi.Retry()
	}
	now := r.now()
	var firstPeer *directory.RelayPeer
	if frame.PartIndex == 0 {
		// Part 0 names its room, so its evidence is checked before any part
		// of it is held: a sender whose evidence fails stores nothing.
		roomID, kind, err := relayframe.RoomObjectPrefix(frame.Part)
		if err != nil {
			return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
		}
		if !(roomSenders{runtime: r}).MayHoldInRoom(sender, roomID) {
			return carrierapi.Refusal(carrierapi.CodeNotAdmitted)
		}
		// The room's end is judged first: at it the sender's credential has
		// expired too, and the refusal is room-ended, not its evidence.
		ended := roomInbound{ctx: ctx, sender: sender, object: relayframe.RoomObject{Type: kind, RoomID: roomID},
			digest: frame.ObjectDigest, now: now}
		if response, refused := r.endedRoom(ended); refused {
			return response
		}
		if response, refused := r.removedRoom(ended); refused {
			return response
		}
		// Only the room's authority sends handshake objects (section 11.5):
		// another member's part 0 is refused before anything of it is held.
		if response, refused := r.nonAuthority(ended); refused {
			return response
		}
		peer, err := r.checkSenderEvidence(roomID, sender, frame.Evidence, now)
		if err != nil {
			return evidenceRefusal(err)
		}
		firstPeer = &peer
	}
	// A later part names no room, but its sender must still be one parts are
	// held from at all, judged before the part store writes anything.
	if frame.PartIndex != 0 && !(roomSenders{runtime: r}).MayHold(sender) {
		return carrierapi.Refusal(carrierapi.CodeNotAdmitted)
	}
	result, err := r.parts.Add(sender, frame, now)
	if err != nil {
		return partRefusal(err)
	}
	if frame.PartIndex == 0 && result.Status == relayframe.PartDuplicate {
		// Several generations deliver part 0; the newest evidence is kept.
		if err := r.keepNewerEvidence(sender, frame, result); err != nil {
			r.daemon.report("room part evidence", err)
		}
	}
	if result.Status != relayframe.PartComplete {
		if firstPeer != nil {
			r.commitMemberPeer(result.RoomID, *firstPeer, now)
		}
		return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultAdmitted}
	}
	response, settle := r.handleComplete(ctx, sender, frame.ObjectDigest, result, now)
	if settle {
		if err := r.parts.Settle(sender, frame.ObjectDigest); err != nil {
			r.daemon.report("room part settlement", err)
		}
	}
	return response
}

// keepNewerEvidence replaces the held part-0 evidence when a later
// generation delivered newer evidence for the same part 0.
func (r *roomRuntime) keepNewerEvidence(sender string, frame relayframe.Frame, result relayframe.PartResult) error {
	held, heldIssued, err := directory.EvidenceDescriptor(result.Evidence)
	if err != nil {
		return err
	}
	offered, offeredIssued, err := directory.EvidenceDescriptor(frame.Evidence)
	if err != nil {
		return err
	}
	if !directory.NewerEvidence(offered, offeredIssued, held, heldIssued) {
		return nil
	}
	return r.parts.ReplaceFirstPartEvidence(sender, frame.ObjectDigest, frame.Card, frame.Evidence)
}

// commitMemberPeer runs CommitPeer (newer only) on a sender's checked
// evidence once the sender is a member of the room as this installation
// holds it: a roster is rendezvous, and evidence is committed only after the
// Commit or Welcome that made its Agent a member is applied (section 11.2).
func (r *roomRuntime) commitMemberPeer(roomID string, peer directory.RelayPeer, now time.Time) {
	record, found, err := r.ledger.Current(roomID)
	if err != nil {
		r.daemon.report("room evidence commit", err)
		return
	}
	if !found || !containsAgent(record.Members, peer.AgentID) {
		return
	}
	committed, err := r.relay.verifier.CommitPeer(peer, now)
	if err != nil {
		r.daemon.report("room evidence commit", err)
		return
	}
	if committed {
		r.relay.wake(peer.AgentID)
	}
}

// handleReplayed handles a complete object a restart found with all its
// parts stored but unsettled: the crash fell between its last part and its
// durable handling. Its answer has nowhere to go; the sender re-deposits
// and the redelivery is answered by the receive order (a duplicate).
func (r *roomRuntime) handleReplayed(completed eventlog.RoomPartCompletion) {
	now := r.now()
	response, settle := r.handleComplete(context.Background(), completed.Sender, completed.Digest, completed.Result, now)
	if response.Result == carrierapi.ResultRetry || !settle {
		return
	}
	if err := r.parts.Settle(completed.Sender, completed.Digest); err != nil {
		r.daemon.report("room part settlement", err)
	}
}

// handleComplete handles one complete object. It reports the answer and
// whether the object's stored parts may be settled: everything but a retry
// is durable handling.
func (r *roomRuntime) handleComplete(ctx context.Context, sender string, digest [sha256.Size]byte,
	result relayframe.PartResult, now time.Time) (carrierapi.Response, bool) {
	object, err := relayframe.DecodeRoomObject(result.Object)
	if err != nil {
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed), true
	}
	if object.RoomID != result.RoomID || relayframe.ObjectDigest(result.Object) != digest {
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed), true
	}
	if response, refused := r.endedRoom(roomInbound{ctx: ctx, sender: sender, object: object, digest: digest, now: now}); refused {
		return response, response.Result != carrierapi.ResultRetry
	}
	// Part 0's held evidence is checked again at completion: the newest
	// generation's, against the credential as the room stands now.
	peer, err := r.checkSenderEvidence(object.RoomID, sender, result.Evidence, now)
	if err != nil {
		response := evidenceRefusal(err)
		return response, response.Result != carrierapi.ResultRetry
	}
	r.handling.Lock()
	defer r.handling.Unlock()
	in := roomInbound{ctx: ctx, sender: sender, peer: peer, object: object, raw: result.Object, digest: digest, now: now}
	// The removal marker is judged under the handling lock: a removal
	// handled while this object waited for the lock stops it here.
	if response, refused := r.removedRoom(in); refused {
		return response, response.Result != carrierapi.ResultRetry
	}
	var response carrierapi.Response
	switch object.Type {
	case relayframe.RoomCommit:
		response = r.handleCommit(in)
	case relayframe.RoomWelcome:
		response = r.handleWelcome(in)
	case relayframe.RoomRoster:
		response = r.handleRoster(in)
	case relayframe.RoomApplication:
		response = r.handleApplication(in)
	default:
		response = carrierapi.Refusal(carrierapi.CodeFrameMalformed)
	}
	return response, response.Result != carrierapi.ResultRetry
}

// roomInbound is one complete object with what its intake established.
type roomInbound struct {
	ctx    context.Context
	sender string
	peer   directory.RelayPeer
	object relayframe.RoomObject
	raw    []byte
	digest [sha256.Size]byte
	now    time.Time
}

// objectDigest is the relay object digest as the journal keys it.
func (in roomInbound) objectDigest() string { return eventlog.RoomObjectDigest(in.raw) }

// handleApplication answers an application object. Opening application
// objects (the e/r rules, D11, the future-epoch buffer and the gap notices)
// is the next part of the room runtime; until then one is refused and
// relay-acknowledged, which a sender records as a gap.
func (r *roomRuntime) handleApplication(roomInbound) carrierapi.Response {
	return carrierapi.Refusal(carrierapi.CodeNotAccepted)
}

// endedRoom refuses an object of a room that has ended (D18): at now >= end
// + skew a member refuses the room's Commits, Welcomes, rosters and
// application objects with room-ended, relay-acknowledges them and raises
// one owner notice. The end is the fused record's; for a room being joined,
// the expiry of the authority credential the accepted join holds, judged
// only for that authority's objects. A handshake object is answered with a
// rejected room ack (stateless for a pending joiner's Welcome); an
// application object is relay-acknowledged and nothing else.
func (r *roomRuntime) endedRoom(in roomInbound) (carrierapi.Response, bool) {
	roomID := in.object.RoomID
	record, held, err := r.ledger.Current(roomID)
	if err != nil {
		return carrierapi.Retry(), true
	}
	end := record.RoomEndsAtUnix
	if !held {
		join, found, err := r.daemon.journal.AcceptedRoomJoin(roomID, in.now)
		if err != nil {
			return carrierapi.Retry(), true
		}
		if !found || join.AuthorityAgentID != in.sender {
			return carrierapi.Response{}, false
		}
		credential, err := join.AuthorityCredential()
		if err != nil {
			return carrierapi.Retry(), true
		}
		end = credential.ExpiresAtUnix
	}
	if !r.roomEnded(end, in.now) {
		return carrierapi.Response{}, false
	}
	r.noticeEnded(roomID)
	switch {
	case in.object.Type == relayframe.RoomApplication:
		return carrierapi.Refusal(carrierapi.CodeNotAccepted), true
	case !held:
		return r.statelessRejection(in, fault.CodeRoomEnded), true
	default:
		return r.roomAck(in, answerRejected(fault.CodeRoomEnded)), true
	}
}

// nonAuthority refuses part 0 of a Commit, Welcome or roster whose sender is
// not the authority of the room this installation holds, with a signed
// rejected not-authentic (the sender is a member). A room being joined has
// only its accepted join's authority as a sender, which the sender set
// already requires.
func (r *roomRuntime) nonAuthority(in roomInbound) (carrierapi.Response, bool) {
	if in.object.Type == relayframe.RoomApplication {
		return carrierapi.Response{}, false
	}
	record, held, err := r.ledger.Current(in.object.RoomID)
	if err != nil {
		return carrierapi.Retry(), true
	}
	if !held || in.sender == record.AuthorityAgentID {
		return carrierapi.Response{}, false
	}
	return r.roomAck(in, answerRejected(fault.CodeNotAuthentic)), true
}

// maintain is the room runtime's share of the relay maintenance timer:
// expired parts go, removed members are forgotten, and ended rooms are
// retired.
func (r *roomRuntime) maintain() {
	r.sweepParts()
	r.reconcileRemoved()
	r.retireEnded()
}

// reconcileRemoved brings what the receiver derived from a room's members
// back to its durable membership: every Agent of a retained earlier
// membership (the two room epochs before the current one) that is not a
// member now is forgotten again, as forgetMembers does after the Commit
// that removed it. That step runs once, after the fused write, so a crash
// before it, or a carrier that failed it, would leave a removed member's
// card admitted for the room; this repeats it from the journal alone. Every
// step is idempotent. It runs at start and on the relay timer.
func (r *roomRuntime) reconcileRemoved() {
	r.handling.Lock()
	defer r.handling.Unlock()
	records, err := r.ledger.List()
	if err != nil {
		r.daemon.report("room removed members", err)
		return
	}
	for _, record := range records {
		var removed []string
		for back := uint64(1); back < eventlog.RetainedRoomEpochs && back < record.RoomEpoch; back++ {
			earlier, held, err := r.ledger.MembershipAt(record.RoomID, record.RoomEpoch-back)
			if err != nil {
				r.daemon.report("room removed members", err)
				return
			}
			if !held {
				continue
			}
			for _, agentID := range earlier.Members {
				if !containsAgent(record.Members, agentID) && !containsAgent(removed, agentID) && agentID != r.daemon.config.AgentID {
					removed = append(removed, agentID)
				}
			}
		}
		if len(removed) > 0 {
			r.forgetMembers(context.Background(), record.RoomID, removed)
		}
	}
}

// sweepParts drops incomplete room objects past their lifetime, with their
// stored parts, and forgets complete objects left unsettled that long.
func (r *roomRuntime) sweepParts() {
	if _, err := r.parts.Sweep(r.now()); err != nil {
		r.daemon.report("room part sweep", err)
	}
}

// retireEnded retires every room past end + retention + skew (D18). The
// room's objects are first dropped from the part store's memory, while
// their part 0 still names the room; retirement then deletes the stored
// parts, buffer, receive state, credential list and, last, the fused record,
// and a collection reclaims what nothing names any more.
func (r *roomRuntime) retireEnded() {
	r.handling.Lock()
	defer r.handling.Unlock()
	now := r.now()
	records, err := r.ledger.List()
	if err != nil {
		r.daemon.report("room retirement", err)
		return
	}
	due := false
	for _, record := range records {
		at, err := eventlog.RoomRetireAt(record, r.retention, r.skew)
		if err != nil || now.Before(at) {
			continue
		}
		due = true
		if _, err := r.parts.DropRoom(record.RoomID); err != nil {
			r.daemon.report("room retirement", err)
			return
		}
	}
	if !due {
		return
	}
	retired, err := r.ledger.RetireEndedRooms(now, r.retention, r.skew)
	if err != nil {
		r.daemon.report("room retirement", err)
		return
	}
	if len(retired) == 0 {
		return
	}
	if report, err := r.daemon.journal.CollectRoomGarbage(); err != nil {
		r.daemon.report("room garbage collection", err)
	} else if report.FailedClosed {
		r.daemon.report("room garbage collection", errors.New("a room root is unreadable; nothing was collected"))
	}
}

// removedRoom answers an object of a room this installation was removed
// from: it accepts no handshake object there any more (section 11.4), and
// nothing of it is held or answered.
func (r *roomRuntime) removedRoom(in roomInbound) (carrierapi.Response, bool) {
	_, removed, err := r.daemon.journal.RoomRemovalOf(in.object.RoomID)
	if err != nil {
		return carrierapi.Retry(), true
	}
	if !removed || in.object.Type == relayframe.RoomApplication {
		return carrierapi.Response{}, false
	}
	return ignored(), true
}

// roomEnded reports now >= end + skew (D18), with checked arithmetic: an end
// the arithmetic cannot hold has ended.
func (r *roomRuntime) roomEnded(endsAtUnix uint64, now time.Time) bool {
	skew := uint64(r.skew / time.Second)
	if endsAtUnix == 0 || skew > ^uint64(0)-endsAtUnix || now.Unix() < 0 {
		return true
	}
	return uint64(now.Unix()) >= endsAtUnix+skew
}

// ErrRoomEnded is the owner notice of a room that ended (D18).
var ErrRoomEnded = errors.New("the private room has ended; its objects are refused room-ended")

// noticeEnded raises the room-ended owner notice once per room.
func (r *roomRuntime) noticeEnded(roomID string) {
	r.noticedMutex.Lock()
	_, raised := r.noticed[roomID]
	r.noticed[roomID] = struct{}{}
	r.noticedMutex.Unlock()
	if !raised {
		r.daemon.report("room "+roomID, ErrRoomEnded)
	}
}

// roomAnswer is the outcome a room ack reports.
type roomAnswer struct {
	outcome string
	code    fault.Code
}

var (
	answerAccepted  = roomAnswer{outcome: relayframe.OutcomeAccepted}
	answerDuplicate = roomAnswer{outcome: relayframe.OutcomeDuplicate}
)

func answerRejected(code fault.Code) roomAnswer {
	return roomAnswer{outcome: relayframe.OutcomeRejected, code: code}
}

// roomAck signs this member's room ack for a handshake object, with its MLS
// epoch and epoch authenticator after handling the object, and wraps it in a
// kind-2 frame for the sender.
func (r *roomRuntime) roomAck(in roomInbound, answer roomAnswer) carrierapi.Response {
	record, found, err := r.ledger.Current(in.object.RoomID)
	if err != nil {
		return carrierapi.Retry()
	}
	if !found {
		// Only a pending joiner refusing its Welcome acks without state.
		if in.object.Type != relayframe.RoomWelcome || answer.outcome != relayframe.OutcomeRejected {
			return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultIgnored}
		}
		return r.signRoomAck(in, answer, 0, nil)
	}
	authenticator, held := record.EpochAuthenticatorAt(record.MLSEpoch)
	if !held {
		return carrierapi.Retry()
	}
	return r.signRoomAck(in, answer, record.MLSEpoch, authenticator)
}

// statelessRejection is the only room ack without MLS state: a pending
// joiner refusing its Welcome.
func (r *roomRuntime) statelessRejection(in roomInbound, code fault.Code) carrierapi.Response {
	if in.object.Type != relayframe.RoomWelcome {
		return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultIgnored}
	}
	return r.signRoomAck(in, answerRejected(code), 0, nil)
}

func (r *roomRuntime) signRoomAck(in roomInbound, answer roomAnswer, mlsEpoch uint64, authenticator []byte) carrierapi.Response {
	code := answer.code
	if answer.outcome == relayframe.OutcomeRejected && (code == "" || !fault.Known(code)) {
		code = fault.CodeRejected
	}
	ack, err := relayframe.SignRoomAck(relayframe.RoomAck{RoomID: in.object.RoomID, ObjectDigest: in.digest,
		RecipientEndpointID: r.daemon.config.EndpointID, RecipientDeviceID: r.daemon.config.DeviceID,
		MLSEpoch: mlsEpoch, EpochAuthenticator: authenticator, Outcome: answer.outcome, Code: code,
		AckedAtUnix: uint64(in.now.Unix())}, r.relay.signer)
	if err != nil {
		r.daemon.report("room ack", err)
		return carrierapi.Retry()
	}
	object, err := relayframe.EncodeRoomAck(ack)
	if err != nil {
		r.daemon.report("room ack", err)
		return carrierapi.Retry()
	}
	frame, _, err := r.relay.ownFrame(relayframe.KindDeliveryAck, in.sender, object, false)
	if err != nil {
		r.daemon.report("room ack", err)
		return carrierapi.Retry()
	}
	return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultAck,
		AckFrameBase64: base64.StdEncoding.EncodeToString(frame), AckOutcome: answer.outcome}
}

// ignored relay-acknowledges an object without an answer.
func ignored() carrierapi.Response {
	return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultIgnored}
}

// memberBinding verifies a member's leaf credential on the room path
// against the authority its checked evidence established: the delegation as
// finalized now and the device set its Endpoint signed (section 11.8).
func memberBinding(peer directory.RelayPeer, credential group.LeafCredential, roomEndsAtUnix uint64,
	now time.Time) (group.LeafBinding, error) {
	set, err := e2ee.Summarize(peer.Bundles)
	if err != nil {
		return group.LeafBinding{}, err
	}
	return group.VerifyRoomLeafCredential(peer.Delegation, credential, set, roomEndsAtUnix, now)
}

// encodeCard is a chat card as carrier.room-cards carries it.
func encodeCard(card []byte) string { return base64.StdEncoding.EncodeToString(card) }
