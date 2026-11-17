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
	"sort"
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
	// RoomCards admits the cards under the room's admission, which the
	// carrier drops on its own at the room's end plus its slack.
	RoomCards(ctx context.Context, roomID string, roomEndsAtUnix uint64, cards []carrierapi.RoomCard) (carrierapi.Response, error)
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
	// driver is the MLS driver; leafs is its part that makes a leaf before
	// its identity, used to issue this installation's leaf credentials.
	driver group.AttributedDriver
	leafs  roomLeafMaker
	// authorization is how long a MembershipAuthorization this installation
	// signs as a room's authority lives.
	authorization time.Duration
	// partBytes is the test part size handshake objects are cut at; zero is
	// the production cut.
	partBytes int
	// backoff holds the waits of handshake deposits the carrier answered
	// with retry.
	backoff fanoutBackoff
	// skew is the daemon's clock-skew bound: the room end (D18) and the
	// relay authorization window (D16) are applied with it at both ends.
	skew time.Duration
	// retention is the handshake retention the relay authorization window
	// adds to an authorization's issue time.
	retention time.Duration
	// gapDelay is T of section 11.3: a missing sequence not arrived that
	// long after a later one did is declared lost.
	gapDelay time.Duration

	// handling serializes the handling of complete objects, so the judgement,
	// the MLS step and the applied-digest record of one object are never
	// interleaved with another's; the owner's membership changes and seals
	// take it too. No carrier call is ever made while it is held. Lock
	// order: handling may be taken before a room's fan-out mutex, never
	// while one is held.
	handling sync.Mutex

	// fanouts holds each room's fan-out mutex (roomFanoutLock), guarded by
	// fanoutsMutex. A room's fan-out mutex serializes that room's handshake
	// deposits, the settlement of its room acks and the withdrawals to its
	// removed members; it is the only lock held across those carrier calls,
	// and handling is never taken while it is held.
	fanoutsMutex sync.Mutex
	fanouts      map[string]*sync.Mutex

	// noticed holds the rooms whose end was already raised to the owner by
	// this process: one notice per room, not one per refused object.
	noticedMutex sync.Mutex
	noticed      map[string]struct{}
	// forkNoticed holds the rooms whose room-fork-suspected notice this
	// process already raised.
	forkNoticed map[string]struct{}

	// cardsMutex guards the card-forget bookkeeping. Forgets are queued
	// under the handling lock and sent to the carrier outside it
	// (flushCardForgets): pending holds what is still to be sent, retried
	// until it succeeds; forgotten holds what this process already sent,
	// so the timer's reconciliation does not send it again.
	cardsMutex sync.Mutex
	pending    map[string]map[string]struct{}
	forgotten  map[string]map[string]struct{}
	// admissions holds the card admissions rosters taught, queued under
	// the handling lock and sent outside it (flushCardAdmissions).
	admissions []roomCardAdmission
	// cardFlush serializes the flushes of card admissions and forgets, so
	// an admission is never sent concurrently with a forget, and each
	// admission is judged against the membership as it is when it is sent.
	// It is taken without the handling lock and never with a fan-out mutex.
	cardFlush sync.Mutex

	// betweenFanoutReads, when set, runs inside fanOut between its read of
	// the outbox heads and its read of the room, so a test can commit an
	// Add in between. It is nil outside tests.
	betweenFanoutReads func()
}

// roomCardAdmission is one carrier.room-cards admission a roster taught.
type roomCardAdmission struct {
	roomID         string
	roomEndsAtUnix uint64
	cards          []carrierapi.RoomCard
}

// maxQueuedCardAdmissions bounds the admissions waiting for a flush; each
// handled roster flushes its own, so the queue holds at most a few.
const maxQueuedCardAdmissions = 64

// ErrRoomRemoved is the owner notice of a room this installation was removed
// from (section 11.4).
var ErrRoomRemoved = errors.New("this installation was removed from the private room; it accepts and sends nothing more there")

// roomRuntimeSettings are the values the room runtime is built with.
type roomRuntimeSettings struct {
	driver    group.AttributedDriver
	cards     roomCarrier
	skew      time.Duration
	retention time.Duration
	gapDelay  time.Duration
	partBytes int
	// authorization is the lifetime of the MembershipAuthorizations this
	// installation signs; zero is the production 24 h.
	authorization time.Duration
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
	leafs, ok := settings.driver.(roomLeafMaker)
	if !ok {
		return errors.New("room runtime needs an MLS driver that makes leaf signers")
	}
	if settings.authorization == 0 {
		settings.authorization = defaultRoomAuthorization
	}
	if settings.authorization < time.Minute || settings.authorization > room.MaxMembershipAuthorizationWindow {
		return errors.New("room authorization lifetime is outside 1m..24h")
	}
	if settings.skew <= 0 || settings.skew > room.MaxRoomAuthorizationSkew {
		return errors.New("room clock skew is outside 1s..1h")
	}
	if settings.retention <= 0 || settings.retention > room.RoomHandshakeRetention {
		return errors.New("room handshake retention is outside its bound")
	}
	if settings.gapDelay <= eventlog.RoomGapGrace || settings.gapDelay > maxRoomGapDelay {
		return errors.New("room gap delay is outside its bound")
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
		driver: settings.driver, leafs: leafs, authorization: settings.authorization, partBytes: settings.partBytes,
		skew: settings.skew, retention: settings.retention, gapDelay: settings.gapDelay, noticed: map[string]struct{}{},
		forkNoticed: map[string]struct{}{}, pending: map[string]map[string]struct{}{}, forgotten: map[string]map[string]struct{}{},
		fanouts: map[string]*sync.Mutex{}}
	// Rooms past their retirement time are retired before anything else,
	// a crash's half-retired room included, and only then is garbage
	// collected, so the retired rooms' records are reclaimed (section 11.8).
	if err := runtime.queueRetiringCardForgets(d.clock()); err != nil {
		return err
	}
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
	// A seal a crash left unfinished is finished before new compositions.
	runtime.resumeSeals()
	runtime.flushCardAdmissions(context.Background())
	runtime.flushCardForgets(context.Background())
	return nil
}

func (r *roomRuntime) now() time.Time { return r.daemon.clock() }

// maxRoomGapDelay is the largest T: the relay V1 TTL ceiling plus the
// grace.
const maxRoomGapDelay = time.Duration(carrierapi.MaxRelayTTLSeconds)*time.Second + eventlog.RoomGapGrace

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

// objectEvidence checks a room object's part-0 evidence (read-only) and
// reports whether it was pinned to the sender's verified leaf credential.
// Handshake objects always are. An application object of a current member
// whose credential is not known yet (its roster has not arrived, section
// 11.8) has no credential to pin to: its evidence is checked against its own
// Endpoint and device, the object can only be held in the future-epoch
// buffer, and it is opened only once the credential is learned, against the
// stored evidence pinned to that credential.
func (r *roomRuntime) objectEvidence(roomID string, kind uint8, sender string, evidence []byte, now time.Time) (directory.RelayPeer, bool, error) {
	_, found, err := r.senderCredential(roomID, sender, now)
	if err != nil {
		return directory.RelayPeer{}, false, fault.Wrap(fault.CodeInternal, err)
	}
	if found {
		peer, err := r.checkSenderEvidence(roomID, sender, evidence, now)
		return peer, err == nil, err
	}
	_, held, err := r.ledger.Current(roomID)
	if err != nil {
		return directory.RelayPeer{}, false, fault.Wrap(fault.CodeInternal, err)
	}
	if kind != relayframe.RoomApplication || !held {
		return directory.RelayPeer{}, false, fault.New(fault.CodeNotAuthentic, "the sender's leaf credential is not known in the room")
	}
	peer, err := r.relay.verifier.CheckContact(sender, evidence, now)
	return peer, false, err
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
		// of it is held: a sender whose evidence fails stores nothing, and
		// the later parts that arrived first are dropped with it.
		roomID, kind, err := relayframe.RoomObjectPrefix(frame.Part)
		if err != nil {
			return r.refuseObject(sender, frame, carrierapi.Refusal(carrierapi.CodeFrameMalformed))
		}
		if !(roomSenders{runtime: r}).MayHoldInRoom(sender, roomID) {
			return r.refuseObject(sender, frame, carrierapi.Refusal(carrierapi.CodeNotAdmitted))
		}
		// The room's end is judged first: at it the sender's credential has
		// expired too, and the refusal is room-ended, not its evidence.
		ended := roomInbound{ctx: ctx, sender: sender, object: relayframe.RoomObject{Type: kind, RoomID: roomID},
			digest: frame.ObjectDigest, now: now}
		if response, refused := r.endedRoom(ended); refused {
			return r.refuseObject(sender, frame, response)
		}
		if response, refused := r.removedRoom(ended); refused {
			return r.refuseObject(sender, frame, response)
		}
		// Only the room's authority sends handshake objects (section 11.5):
		// another member's part 0 is refused before anything of it is held.
		if response, refused := r.nonAuthority(ended); refused {
			return r.refuseObject(sender, frame, response)
		}
		peer, pinned, err := r.objectEvidence(roomID, kind, sender, frame.Evidence, now)
		if err != nil {
			return r.refuseObject(sender, frame, evidenceRefusal(err))
		}
		if pinned {
			firstPeer = &peer
		}
	}
	// A later part names no room, but its sender must still be one parts are
	// held from at all, judged before the part store writes anything.
	if frame.PartIndex != 0 && !(roomSenders{runtime: r}).MayHold(sender) {
		return r.refuseObject(sender, frame, carrierapi.Refusal(carrierapi.CodeNotAdmitted))
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
	if frame.PartIndex == 0 && firstPeer != nil {
		// A member's newer card renews the authority's stored one.
		r.refreshMemberCard(sender, frame.Card, now)
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
	// Card admissions a roster taught and card forgets a removal queued are
	// sent now, outside the handling lock.
	r.flushCardAdmissions(ctx)
	r.flushCardForgets(ctx)
	return response
}

// refuseObject answers an intake refusal of one of a sender's parts. Nothing
// of a refused object is stored (sections 11.3, 11.5): the parts of it that
// arrived before, and the Reassembler's entry, are dropped before the
// refusal is relay-acknowledged. A retry refuses nothing and drops nothing;
// a drop the store could not make is retried, so the redelivered part is
// judged, and its object dropped, again.
func (r *roomRuntime) refuseObject(sender string, frame relayframe.Frame, response carrierapi.Response) carrierapi.Response {
	if response.Result == carrierapi.ResultRetry {
		return response
	}
	if err := r.parts.Refuse(sender, frame.ObjectDigest); err != nil {
		r.daemon.report("room part refusal", err)
		return carrierapi.Retry()
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
	peer, pinned, err := r.objectEvidence(object.RoomID, object.Type, sender, result.Evidence, now)
	if err != nil {
		response := evidenceRefusal(err)
		return response, response.Result != carrierapi.ResultRetry
	}
	r.handling.Lock()
	defer r.handling.Unlock()
	in := roomInbound{ctx: ctx, sender: sender, peer: peer, pinned: pinned, object: object, raw: result.Object, digest: digest, now: now}
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
	// pinned says the evidence that established peer was pinned to the
	// sender's verified leaf credential. Only an application object of a
	// member whose credential is not known yet arrives unpinned.
	pinned bool
	object relayframe.RoomObject
	raw    []byte
	digest [sha256.Size]byte
	now    time.Time
}

// objectDigest is the relay object digest as the journal keys it.
func (in roomInbound) objectDigest() string { return eventlog.RoomObjectDigest(in.raw) }

// endedRoom refuses an object of a room that has ended (D18): at now >= end
// + skew a member refuses the room's Commits, Welcomes, rosters and
// application objects with room-ended, relay-acknowledges them and raises
// one owner notice. The end is the fused record's; for a room being joined,
// the expiry of the authority credential the accepted join holds, judged
// only for that authority's objects. A handshake object is answered with a
// rejected room ack (stateless for a pending joiner's Welcome); an
// application object of a held room is recorded as a gap of its sender
// (room-ended) and then relay-acknowledged.
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
		// Senders stop at end - skew, so an application object arriving now
		// was sealed before the end: it is lost to its receivers, and a member
		// records it as a gap of its sender (sections 11.3, 11.8). The record
		// is written before the object is relay-acknowledged.
		if held {
			if _, err := r.daemon.journal.RecordRoomDrop(roomID, in.sender, eventlog.RoomGapRoomEnded, in.now); err != nil {
				r.daemon.report("room gap", err)
				return carrierapi.Retry(), true
			}
		}
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
// expired parts go, removed members are forgotten, ended rooms are retired,
// and the application receive state is swept (buffer, sequences, received
// digests) with the held objects tried again.
func (r *roomRuntime) maintain() {
	r.sweepParts()
	r.reconcileRemoved()
	r.retireEnded()
	r.sweepApplications()
	r.commitAddsEverywhere()
	// Handshake objects go before application objects.
	r.sweepHandshakes(context.Background())
	r.sweepApplicationSends(context.Background())
	r.flushCardAdmissions(context.Background())
	r.flushCardForgets(context.Background())
}

// queueRoomCardForgets queues the forget of every member's card admission
// of a room being retired: the room's admissions end with it. The forgets
// are sent after the handling lock, and a failed one is retried without
// holding retirement's journal steps back.
func (r *roomRuntime) queueRoomCardForgets(record eventlog.RoomMLSRecord) {
	var members []string
	for _, agentID := range record.Members {
		if agentID != r.daemon.config.AgentID {
			members = append(members, agentID)
		}
	}
	r.queueCardForgets(record.RoomID, members)
}

// queueRetiringCardForgets queues the card forgets of every room due for
// retirement at now, before the start-time retirement removes its record.
func (r *roomRuntime) queueRetiringCardForgets(now time.Time) error {
	records, err := r.ledger.List()
	if err != nil {
		return err
	}
	for _, record := range records {
		at, err := eventlog.RoomRetireAt(record, r.retention, r.skew)
		if err != nil || now.Before(at) {
			continue
		}
		r.queueRoomCardForgets(record)
	}
	return nil
}

// queueCardForgets records card admissions of a room to drop at the
// carrier, skipping those this process already dropped. The caller holds
// the handling lock; nothing here calls the carrier.
func (r *roomRuntime) queueCardForgets(roomID string, agentIDs []string) {
	r.cardsMutex.Lock()
	defer r.cardsMutex.Unlock()
	for _, agentID := range agentIDs {
		if _, done := r.forgotten[roomID][agentID]; done {
			continue
		}
		if r.pending[roomID] == nil {
			r.pending[roomID] = map[string]struct{}{}
		}
		r.pending[roomID][agentID] = struct{}{}
	}
}

// queueCardAdmission queues the admission of the cards a roster taught; it
// is sent outside the handling lock. A full queue drops the admission with
// a report: the cards are not authority, and part 0 of later room traffic
// renews them.
func (r *roomRuntime) queueCardAdmission(admission roomCardAdmission) {
	r.cardsMutex.Lock()
	defer r.cardsMutex.Unlock()
	if len(r.admissions) >= maxQueuedCardAdmissions {
		r.daemon.report("room cards", errors.New("too many room card admissions wait for the carrier; one was dropped"))
		return
	}
	r.admissions = append(r.admissions, admission)
}

// flushCardAdmissions sends the queued card admissions to the carrier, in
// the order they were queued, never under the handling lock and serialized
// with the forgets. Each admission is judged again under that serialization:
// only cards of Agents in the room's current membership with no forget
// pending are sent, so an admission a roster queued before a removal can
// never re-admit the removed member after its forget. One the carrier did
// not apply stays queued, in order, for the next flush.
func (r *roomRuntime) flushCardAdmissions(ctx context.Context) {
	r.cardFlush.Lock()
	defer r.cardFlush.Unlock()
	r.cardsMutex.Lock()
	admissions := r.admissions
	r.admissions = nil
	r.cardsMutex.Unlock()
	var kept []roomCardAdmission
	for index, admission := range admissions {
		cards, err := r.admissibleCards(admission)
		if err != nil {
			r.daemon.report("room cards", err)
			kept = append(kept, admissions[index:]...)
			break
		}
		if len(cards) == 0 {
			continue
		}
		response, err := r.cards.RoomCards(ctx, admission.roomID, admission.roomEndsAtUnix, cards)
		if err == nil && response.Result != carrierapi.ResultApplied {
			err = errors.New("the carrier did not apply the room's card admissions")
		}
		if err != nil {
			r.daemon.report("room cards", err)
			kept = append(kept, admissions[index:]...)
			break
		}
	}
	if len(kept) == 0 {
		return
	}
	r.cardsMutex.Lock()
	defer r.cardsMutex.Unlock()
	// What waits goes back ahead of what was queued meanwhile, within the
	// bound; the newest past it are dropped with a report.
	queued := append(kept, r.admissions...)
	if len(queued) > maxQueuedCardAdmissions {
		r.daemon.report("room cards", errors.New("too many room card admissions wait for the carrier; the newest were dropped"))
		queued = queued[:maxQueuedCardAdmissions]
	}
	r.admissions = queued
}

// admissibleCards returns the cards of an admission whose Agents are still
// members of the room with no card forget pending; a room no longer held
// admits none.
func (r *roomRuntime) admissibleCards(admission roomCardAdmission) ([]carrierapi.RoomCard, error) {
	record, found, err := r.ledger.Current(admission.roomID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	r.cardsMutex.Lock()
	defer r.cardsMutex.Unlock()
	pending := r.pending[admission.roomID]
	cards := make([]carrierapi.RoomCard, 0, len(admission.cards))
	for _, card := range admission.cards {
		if _, forgetting := pending[card.AgentID]; forgetting || !containsAgent(record.Members, card.AgentID) {
			continue
		}
		cards = append(cards, card)
	}
	return cards, nil
}

// flushCardForgets sends the queued card forgets to the carrier, one
// carrier.room-cards forget per room, never under the handling lock. A
// forget the carrier applied moves to the forgotten set; one that failed
// stays pending and is sent again by the next flush. A room's pending set
// larger than one request allows is sent in batches of MaxRoomCards.
func (r *roomRuntime) flushCardForgets(ctx context.Context) {
	r.cardFlush.Lock()
	defer r.cardFlush.Unlock()
	r.cardsMutex.Lock()
	batches := make(map[string][]string, len(r.pending))
	for roomID, agents := range r.pending {
		for agentID := range agents {
			batches[roomID] = append(batches[roomID], agentID)
		}
	}
	r.cardsMutex.Unlock()
	for roomID, agentIDs := range batches {
		sort.Strings(agentIDs)
		// One carrier.room-cards request names at most MaxRoomCards Agents;
		// a larger set goes in batches, each settled on its own.
		for start := 0; start < len(agentIDs); start += carrierapi.MaxRoomCards {
			end := min(start+carrierapi.MaxRoomCards, len(agentIDs))
			r.forgetCardBatch(ctx, roomID, agentIDs[start:end])
		}
	}
}

// forgetCardBatch sends one batch of card forgets. Applied, its Agents move
// to the forgotten set; failed, they stay pending for the next flush.
func (r *roomRuntime) forgetCardBatch(ctx context.Context, roomID string, agentIDs []string) {
	response, err := r.cards.ForgetRoomCards(ctx, roomID, agentIDs)
	if err == nil && response.Result != carrierapi.ResultApplied {
		err = errors.New("the carrier did not drop the room's admission of removed members")
	}
	if err != nil {
		r.daemon.report("room cards", err)
		return
	}
	r.cardsMutex.Lock()
	defer r.cardsMutex.Unlock()
	for _, agentID := range agentIDs {
		delete(r.pending[roomID], agentID)
		if r.forgotten[roomID] == nil {
			r.forgotten[roomID] = map[string]struct{}{}
		}
		r.forgotten[roomID][agentID] = struct{}{}
	}
	if len(r.pending[roomID]) == 0 {
		delete(r.pending, roomID)
	}
}

// pruneCardForgets drops the forgotten set of rooms no longer held here,
// once nothing of theirs is pending, so the sets stay bounded by the rooms
// held.
func (r *roomRuntime) pruneCardForgets(held map[string]struct{}) {
	r.cardsMutex.Lock()
	defer r.cardsMutex.Unlock()
	for roomID := range r.forgotten {
		if _, still := held[roomID]; still {
			continue
		}
		if len(r.pending[roomID]) == 0 {
			delete(r.forgotten, roomID)
		}
	}
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
	held := make(map[string]struct{}, len(records))
	for _, record := range records {
		held[record.RoomID] = struct{}{}
	}
	r.pruneCardForgets(held)
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
			r.forgetMembers(record.RoomID, removed)
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
		r.queueRoomCardForgets(record)
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
