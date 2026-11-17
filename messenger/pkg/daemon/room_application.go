package daemon

// Application objects of a private room on the receive side (sections 11.1,
// 11.2, 11.3, 11.4, 11.8, D11, D18). An object sealed in MLS epoch e reaches a
// member at epoch r:
//
//   - e = r from a member whose leaf credential is known, and r - 2 <= e < r:
//     opened now;
//   - r < e <= r + 4, or e = r from a member whose credential is not known
//     yet: held in the future-epoch buffer and opened in arrival order once
//     the Commits up to e are applied or the roster teaching the credential
//     arrives;
//   - anything else, a full buffer or sender share, or a buffered object older
//     than 24 h 5 min: dropped, relay-acknowledged and recorded as a gap.
//
// Opening uses the driver's explicit readback open, so the message's own
// authenticated data comes back with the plaintext; it must bind this room,
// the object's room and MLS epochs, this member's epoch authenticator of that
// MLS epoch, the packet sender and the opened Event. The open writes nothing:
// the next state is committed only together with the Event, after the AAD,
// the Event and D11 admission all passed. A message refused after the open is
// discarded with the state the driver returned, so it spends no ratchet step
// and marks nothing.
//
// The order of the durable steps, all inside the admission's commit, is: the
// Event is journaled, its sequence observed, its digest marked received, and
// last the ratchet step written. Each step repeats as a no-op, so a crash or a
// failed step before the mark is healed by the redelivery (opened again
// against the unspent state, a duplicate Event); a crash after the mark leaves
// the redelivery dropped as seen, with the Event already journaled. No crash
// leaves a spent ratchet step whose Event is not journaled.

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/admission"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/directory"
	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/payload"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// ErrRoomForkSuspected is the owner notice of a room where a current member's
// authenticated application object did not open, or opened as another leaf's:
// this member's MLS state may have diverged from the sender's (section 11.3).
var ErrRoomForkSuspected = errors.New("a current member's room message did not open here: the room may be forked (room-fork-suspected)")

// handleApplication applies the e/r rules to one application object. The
// caller holds the handling lock.
func (r *roomRuntime) handleApplication(in roomInbound) carrierapi.Response {
	roomID := in.object.RoomID
	record, held, err := r.ledger.Current(roomID)
	if err != nil {
		return carrierapi.Retry()
	}
	if !held {
		// A room being joined has no state to open or hold the object in.
		return ignored()
	}
	digest := in.objectDigest()
	// A digest seen within 24 h 5 min (a second relay, a replay) is dropped
	// before anything opens it, so it never spends a ratchet step.
	seen, err := r.daemon.journal.RoomApplicationSeen(roomID, in.sender, digest, in.now)
	if err != nil {
		return carrierapi.Retry()
	}
	if seen {
		return ignored()
	}
	removal, removed, err := r.daemon.journal.RoomRemovalOf(roomID)
	if err != nil {
		return carrierapi.Retry()
	}
	e, current := in.object.MLSEpoch, record.MLSEpoch
	switch {
	case removed && e > removal.MemberMLSEpoch:
		// A removed member reads the epochs it was a member of, no later one
		// (section 11.4).
		return r.dropApplication(in, eventlog.RoomGapEpochTooNew)
	case e > current && e-current > eventlog.RoomBufferLookahead:
		return r.dropApplication(in, eventlog.RoomGapEpochTooNew)
	case e < current && current-e > eventlog.RetainedRoomEpochs-1:
		return r.dropApplication(in, eventlog.RoomGapEpochTooOld)
	case e > current:
		return r.holdApplication(in)
	}
	_, known, err := r.ledger.RoomCredential(roomID, in.sender)
	if err != nil {
		return carrierapi.Retry()
	}
	if !known {
		if e == current {
			return r.holdApplication(in)
		}
		// The roster of an Agent's epoch is delivered before any later
		// Commit, so a sender of an epoch this member moved past whose
		// credential is unknown had none that verified, or was removed since:
		// its object cannot be authenticated (sections 11.5, 11.8).
		return refusedNotAuthentic()
	}
	return r.openApplication(in, record)
}

// refusedNotAuthentic answers an application object whose sender is not
// authenticated: refused and relay-acknowledged, nothing stored. Application
// objects get no room ack (section 11.7).
func refusedNotAuthentic() carrierapi.Response {
	return carrierapi.Refusal(carrierapi.CodeNotAccepted)
}

// dropApplication drops an application object unopened and records the gap
// of its sender before the object is relay-acknowledged, so nothing is
// dropped unrecorded; a record that cannot be written is retried.
func (r *roomRuntime) dropApplication(in roomInbound, reason eventlog.RoomGapReason) carrierapi.Response {
	if _, err := r.daemon.journal.RecordRoomDrop(in.object.RoomID, in.sender, reason, in.now); err != nil {
		r.daemon.report("room gap", err)
		return carrierapi.Retry()
	}
	return ignored()
}

// holdApplication keeps an application object in the future-epoch buffer. A
// full buffer or sender share is a buffer-full gap. An object held under
// pinned evidence renews the sender's evidence and card (section 11.2);
// one whose sender's credential is not known yet renews nothing.
func (r *roomRuntime) holdApplication(in roomInbound) carrierapi.Response {
	_, err := r.daemon.journal.BufferRoomObject(in.sender, in.raw, in.now)
	switch {
	case err == nil:
	case errors.Is(err, eventlog.ErrRoomBufferSenderFull), errors.Is(err, eventlog.ErrRoomBufferRoomFull),
		errors.Is(err, eventlog.ErrRoomBufferTotalFull):
		return r.dropApplication(in, eventlog.RoomGapBufferFull)
	case errors.Is(err, eventlog.ErrRoomBufferCredentialKnown):
		record, held, err := r.ledger.Current(in.object.RoomID)
		if err != nil || !held {
			return carrierapi.Retry()
		}
		return r.openApplication(in, record)
	case errors.Is(err, eventlog.ErrRoomBufferEpoch):
		return r.dropApplication(in, eventlog.RoomGapEpochTooNew)
	case errors.Is(err, eventlog.ErrRoomNotJoined):
		return ignored()
	default:
		r.daemon.report("room buffer", err)
		return carrierapi.Retry()
	}
	if !in.pinned {
		return ignored()
	}
	r.commitMemberPeer(in.object.RoomID, in.peer, in.now)
	return admittedAnswer()
}

func admittedAnswer() carrierapi.Response {
	return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultAdmitted}
}

// openApplication opens an application object of a member whose leaf
// credential is known, judges it, and commits it. The caller holds the
// handling lock and has checked that the digest was not seen.
func (r *roomRuntime) openApplication(in roomInbound, record eventlog.RoomMLSRecord) carrierapi.Response {
	roomID := in.object.RoomID
	credential, known, err := r.ledger.RoomCredential(roomID, in.sender)
	if err != nil {
		return carrierapi.Retry()
	}
	if !known {
		return refusedNotAuthentic()
	}
	peer := in.peer
	if !in.pinned {
		// The evidence was checked before the credential was known; it is
		// checked again, pinned to the credential's Endpoint and device.
		peer, err = r.checkSenderEvidence(roomID, in.sender, in.peer.Evidence, in.now)
		if err != nil {
			if fault.CodeOf(err) == fault.CodeInternal {
				return carrierapi.Retry()
			}
			return refusedNotAuthentic()
		}
	}
	// The expected sender is the credential re-verified now (it is never the
	// caller's choice), and the same credential goes to D11 below.
	binding, err := memberBinding(peer, credential, record.RoomEndsAtUnix, in.now)
	if err != nil {
		return refusedNotAuthentic()
	}
	opened, err := r.controller.OpenReadback(roomID, in.object.Body, binding)
	switch {
	case err == nil:
	case errors.Is(err, eventlog.ErrMLSSenderMismatch), errors.Is(err, eventlog.ErrRoomMessageNotOpened):
		// An authenticated current member's object that does not open here,
		// or opens as another leaf's.
		return r.forkSuspected(roomID)
	case errors.Is(err, eventlog.ErrRoomLeafIdentity):
		return refusedNotAuthentic()
	default:
		r.daemon.report("room message", err)
		return carrierapi.Retry()
	}
	// From here on every refusal discards opened: nothing was written.
	event, err := envelope.DecodeEventJSON(opened.Plaintext)
	if err != nil {
		return refusedNotAuthentic()
	}
	if !r.aadBinds(opened.AAD, in, record, event) {
		return refusedNotAuthentic()
	}
	delegationJSON, err := identity.EncodeJSON(peer.Delegation)
	if err != nil {
		return carrierapi.Retry()
	}
	inbound := admission.Inbound{Event: event, DelegationJSON: delegationJSON, Route: admission.RouteRelay,
		ReceivedAtUnix: uint64(in.now.Unix()),
		Room: &admission.RoomCarriage{RoomID: roomID, RoomEpoch: in.object.RoomEpoch, PacketSenderAgentID: in.sender,
			SenderCredential: binding.Credential()}}
	digest := in.objectDigest()
	decision, err := r.daemon.admission.AdmitWithCommit(inbound, func(entry eventlog.Entry) (bool, error) {
		fresh, _, err := r.daemon.journal.Accept(entry)
		if err != nil {
			return false, err
		}
		if err := r.observeSequence(roomID, in.sender, event, in.now); err != nil {
			return false, err
		}
		// The sender is authenticated as the member: only now is the digest
		// marked. A full store answers retry with the Event journaled; the
		// redelivery opens again against the unspent state.
		if _, err := r.daemon.journal.MarkRoomApplicationSeen(roomID, in.sender, digest, in.now); err != nil {
			return false, err
		}
		if _, err := r.controller.CommitOpened(opened); err != nil {
			return false, err
		}
		return fresh, nil
	})
	if err != nil {
		r.daemon.report("room message", err)
		return carrierapi.Retry()
	}
	switch decision.Outcome {
	case admission.Accepted, admission.Duplicate, admission.Held:
		r.commitMemberPeer(roomID, peer, in.now)
		return admittedAnswer()
	default:
		return carrierapi.Refusal(carrierapi.CodeNotAccepted)
	}
}

// aadBinds requires the message's own authenticated data, decoded strictly,
// to name the object's room and room epoch, its MLS epoch and this member's
// epoch authenticator of that epoch, the packet sender and the opened Event
// (section 11.1). The authenticated data is the sender's own, authenticated
// by the open, so it ties the plaintext to the object that carried it.
func (r *roomRuntime) aadBinds(raw []byte, in roomInbound, record eventlog.RoomMLSRecord, event envelope.Event) bool {
	aad, err := relayframe.DecodeRoomAAD(raw)
	if err != nil {
		return false
	}
	authenticator, held := record.EpochAuthenticatorAt(in.object.MLSEpoch)
	return held && aad.RoomID == in.object.RoomID && aad.RoomEpoch == in.object.RoomEpoch &&
		aad.MLSEpoch == in.object.MLSEpoch && bytes.Equal(aad.EpochAuthenticator, authenticator) &&
		aad.SenderAgentID == in.sender && aad.EventID == event.EventID
}

// observeSequence records the sequence of an admitted room.message of the
// room; other kinds carry none.
func (r *roomRuntime) observeSequence(roomID, sender string, event envelope.Event, now time.Time) error {
	if event.Kind != "room.message" {
		return nil
	}
	decoded, err := payload.Decode(event.Kind, event.Content)
	if err != nil {
		return err
	}
	message, ok := decoded.(payload.RoomMessage)
	if !ok || message.RoomID != roomID {
		return nil
	}
	return r.daemon.journal.ObserveRoomSequence(roomID, sender, message.Sequence, now)
}

// forkSuspected raises the room-fork-suspected owner notice, once per room
// in this process, and relay-acknowledges the object. It records no gap: the
// object revealed no sequence, and the sender's next message that opens
// records the missing one, declared lost T after it (section 11.3).
func (r *roomRuntime) forkSuspected(roomID string) carrierapi.Response {
	r.noticedMutex.Lock()
	_, raised := r.forkNoticed[roomID]
	r.forkNoticed[roomID] = struct{}{}
	r.noticedMutex.Unlock()
	if !raised {
		r.daemon.report("room "+roomID, ErrRoomForkSuspected)
	}
	return ignored()
}

// releaseBuffered opens the buffered objects of a room that became openable
// (their epoch reached, their sender's credential known), in arrival order,
// and releases each once it is handled. After a roster was accepted, the
// objects whose sender's credential is still unknown are refused
// not-authentic and released (section 11.8). A buffered object has no frame
// evidence any more: it is opened against the sender's stored evidence,
// pinned to the credential. When that evidence does not check, the object
// stays held for a later pass (a roster, a Commit or the maintenance timer,
// after a kind-4 pull or a later part 0 renewed it); its 24 h 5 min lifetime
// then ends as a buffer-expired gap. The caller holds the handling lock.
func (r *roomRuntime) releaseBuffered(roomID string, rosterArrived bool, now time.Time) {
	record, held, err := r.ledger.Current(roomID)
	if err != nil || !held || r.roomEnded(record.RoomEndsAtUnix, now) {
		if err != nil {
			r.daemon.report("room buffer", err)
		}
		return
	}
	openable, drops, err := r.daemon.journal.OpenableRoomObjects(roomID)
	if err != nil {
		r.daemon.report("room buffer", err)
		return
	}
	r.recordBufferDrops(drops, now)
	for _, buffered := range openable {
		response, release := r.openBuffered(buffered, now)
		if !release {
			if response.Result == carrierapi.ResultRetry {
				// A read or write failed: the rest wait, in order, for the
				// next pass.
				return
			}
			continue
		}
		if err := r.daemon.journal.ReleaseRoomObject(roomID, buffered.Digest); err != nil {
			r.daemon.report("room buffer", err)
			return
		}
	}
	if !rosterArrived {
		return
	}
	awaiting, drops, err := r.daemon.journal.RoomObjectsAwaitingCredential(roomID)
	if err != nil {
		r.daemon.report("room buffer", err)
		return
	}
	r.recordBufferDrops(drops, now)
	for _, buffered := range awaiting {
		if err := r.daemon.journal.ReleaseRoomObject(roomID, buffered.Digest); err != nil {
			r.daemon.report("room buffer", err)
			return
		}
	}
}

// openBuffered handles one buffered object and reports whether it is done
// with (handled, refused or dropped) and may be released.
func (r *roomRuntime) openBuffered(buffered eventlog.BufferedRoomObject, now time.Time) (carrierapi.Response, bool) {
	object, err := relayframe.DecodeRoomObject(buffered.Object)
	if err != nil || object.Type != relayframe.RoomApplication || object.RoomID != buffered.RoomID {
		return refusedNotAuthentic(), true
	}
	credential, known, err := r.ledger.RoomCredential(buffered.RoomID, buffered.SenderAgentID)
	if err != nil {
		return carrierapi.Retry(), false
	}
	if !known {
		return carrierapi.Response{}, false
	}
	pin, err := directory.LeafPin(buffered.SenderAgentID, credential, now)
	if err != nil {
		return refusedNotAuthentic(), true
	}
	peer, err := r.relay.verifier.CheckStored(buffered.SenderAgentID, pin, now)
	if err != nil {
		if fault.CodeOf(err) == fault.CodeInternal {
			return carrierapi.Retry(), false
		}
		return carrierapi.Response{}, false
	}
	in := roomInbound{ctx: context.Background(), sender: buffered.SenderAgentID, peer: peer, pinned: true, object: object,
		raw: buffered.Object, digest: relayframe.ObjectDigest(buffered.Object), now: now}
	response := r.handleApplication(in)
	return response, response.Result != carrierapi.ResultRetry
}

// recordBufferDrops records the gap of every buffered object a listing or a
// sweep dropped unopened. An object of a room no longer held has no receive
// state to record it in.
func (r *roomRuntime) recordBufferDrops(drops []eventlog.BufferedRoomDrop, now time.Time) {
	for _, drop := range drops {
		var reason eventlog.RoomGapReason
		switch drop.Reason {
		case eventlog.RoomBufferDropExpired:
			reason = eventlog.RoomGapBufferExpired
		case eventlog.RoomBufferDropTooOld:
			reason = eventlog.RoomGapEpochTooOld
		case eventlog.RoomBufferDropDamaged:
			reason = eventlog.RoomGapRecordDamaged
		case eventlog.RoomBufferDropLeft:
			continue
		default:
			r.daemon.report("room buffer", errors.New("a buffered object was dropped for an unknown reason"))
			continue
		}
		if _, err := r.daemon.journal.RecordRoomDrop(drop.RoomID, drop.SenderAgentID, reason, now); err != nil {
			r.daemon.report("room gap", err)
		}
	}
}

// sweepApplications is the application share of the maintenance timer:
// buffered objects past their lifetime or their epochs become gaps, missing
// sequences not arrived T after a later one are declared lost, expired
// received digests go, and held objects whose release waited are tried again.
func (r *roomRuntime) sweepApplications() {
	r.handling.Lock()
	defer r.handling.Unlock()
	now := r.now()
	drops, err := r.daemon.journal.SweepRoomBuffer(now)
	if err != nil {
		r.daemon.report("room buffer sweep", err)
	} else {
		r.recordBufferDrops(drops, now)
	}
	if _, err := r.daemon.journal.SweepRoomSequences(now, r.gapDelay); err != nil {
		r.daemon.report("room sequence sweep", err)
	}
	if _, err := r.daemon.journal.SweepRoomReceived(now); err != nil {
		r.daemon.report("room received sweep", err)
	}
	records, err := r.ledger.List()
	if err != nil {
		r.daemon.report("room buffer", err)
		return
	}
	for _, record := range records {
		r.releaseBuffered(record.RoomID, false, now)
	}
}
