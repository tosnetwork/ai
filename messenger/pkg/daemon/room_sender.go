package daemon

// The application sender of a private room (sections 11.1, 11.2, 11.7).
//
// A composition is sealed in the member's current epoch as the canonical
// Event of a room.message whose sequence counts per (room, sender) from 1,
// with the MLS authenticated data binding the room, the room and MLS epochs,
// the sealing epoch's authenticator, the sender Agent and the Event ID. The
// object is never split and is deposited once to every other member of the
// sealing epoch. Each deposit runs CheckPeer on the member's stored evidence
// pinned to its verified leaf credential first; a member failing it gets
// nothing now, the kind-4 pull starts, and the deposit is tried again until
// the object's retention ends, when the member is abandoned.

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/directory"
	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/localapi"
	"github.com/tosnetwork/ai/messenger/pkg/payload"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// roomApplicationRetry is the wait before a deposit the carrier or the
// member's evidence deferred is tried again.
const roomApplicationRetry = 30 * time.Second

// errRoomNoOtherMember refuses a composition in a room that has no member
// to send it to.
var errRoomNoOtherMember = errors.New("the room has no other member to send to")

// ComposeRoomMessage seals one room message to the room in its current
// epoch and deposits it to every other member. A repeat under the same
// idempotency key returns the first Event and deposits nothing new; another
// composition under the same key is a conflict.
func (r *roomRuntime) ComposeRoomMessage(ctx context.Context, composition localapi.RoomComposition) (string, bool, error) {
	if ctx == nil {
		return "", false, errors.New("no request context")
	}
	key := composition.IdempotencyKey
	if !strings.HasPrefix(key, "idem_") || !canon.ValidDigest("sha256:"+strings.TrimPrefix(key, "idem_")) {
		return "", false, fault.New(fault.CodePayloadMalformed, "a room composition needs an idempotency key")
	}
	if !ids.Room.MatchString(composition.RoomID) {
		return "", false, fault.New(fault.CodePayloadMalformed, "invalid room identifier")
	}
	intentDigest := roomCompositionDigest(r.daemon.config.AgentID, composition)
	r.handling.Lock()
	send, fresh, err := r.sealComposition(composition, intentDigest)
	r.handling.Unlock()
	if err != nil {
		return "", false, err
	}
	r.depositApplication(ctx, send)
	return send.EventID, fresh, nil
}

// roomCompositionDigest binds what a composition means, so a retry under
// its key is recognised and another composition under it is refused.
func roomCompositionDigest(sender string, composition localapi.RoomComposition) string {
	buffer := bytes.NewBufferString(canon.DomainOutboundIntent)
	for _, value := range []string{sender, "room.message", composition.RoomID, composition.ConversationID,
		composition.ReplyToEventID, composition.MediaType, composition.Body, composition.IdempotencyKey} {
		canon.Text(buffer, value)
	}
	canon.Uint64(buffer, composition.MembershipEpoch)
	canon.Uint64(buffer, composition.ExpiresAtUnix)
	return canon.Digest(buffer.Bytes())
}

// sealComposition returns the application record of a composition, sealing
// it first if it is new. The caller holds the handling lock.
func (r *roomRuntime) sealComposition(composition localapi.RoomComposition, intentDigest string) (eventlog.RoomApplicationSend, bool, error) {
	roomID, key := composition.RoomID, composition.IdempotencyKey
	journal := r.daemon.journal
	if existing, found, err := journal.RoomApplicationSendFor(roomID, key); err != nil {
		return eventlog.RoomApplicationSend{}, false, err
	} else if found {
		if existing.IntentDigest != intentDigest {
			return eventlog.RoomApplicationSend{}, false, fault.Wrap(fault.CodePayloadMalformed, eventlog.ErrConflict)
		}
		return existing, false, nil
	}
	now := r.now()
	last, intent, err := journal.RoomSendState(roomID)
	if err != nil {
		return eventlog.RoomApplicationSend{}, false, err
	}
	if intent != nil && intent.IdempotencyKey != key {
		// A crash left another composition's seal unfinished: it is
		// finished, or dropped, before this one takes a sequence.
		if _, err := r.resumeSeal(roomID, *intent, now); err != nil && !isRoomEpochGap(err) {
			return eventlog.RoomApplicationSend{}, false, err
		}
		if last, intent, err = journal.RoomSendState(roomID); err != nil {
			return eventlog.RoomApplicationSend{}, false, err
		}
	}
	if intent != nil && intent.IdempotencyKey == key {
		if intent.IntentDigest != intentDigest {
			return eventlog.RoomApplicationSend{}, false, fault.Wrap(fault.CodePayloadMalformed, eventlog.ErrConflict)
		}
		send, err := r.resumeSeal(roomID, *intent, now)
		return send, true, err
	}
	record, err := r.sendingRecord(roomID, now)
	if err != nil {
		return eventlog.RoomApplicationSend{}, false, err
	}
	if composition.MembershipEpoch != record.RoomEpoch {
		return eventlog.RoomApplicationSend{}, false, fault.New(fault.CodeRoomEpochGap, "the composition names another room epoch than the current one")
	}
	if len(r.othersOf(record.Members)) == 0 {
		return eventlog.RoomApplicationSend{}, false, fault.Wrap(fault.CodePayloadMalformed, errRoomNoOtherMember)
	}
	// last is checked against the maximum before it is incremented, in the
	// journal and here.
	if last == ^uint64(0) {
		return eventlog.RoomApplicationSend{}, false, fault.Wrap(fault.CodeQuotaExceeded, eventlog.ErrRoomSequenceOrder)
	}
	sequence := last + 1
	content, err := payload.Encode(payload.RoomMessage{RoomID: roomID, Epoch: record.RoomEpoch, MediaType: composition.MediaType,
		Body: composition.Body, Sequence: sequence})
	if err != nil {
		return eventlog.RoomApplicationSend{}, false, fault.Wrap(fault.CodePayloadMalformed, err)
	}
	event, err := envelope.NewEvent(envelope.Event{Network: r.daemon.config.Network(), ConversationID: composition.ConversationID,
		SenderAgentID: r.daemon.config.AgentID, SenderEndpointID: r.daemon.config.EndpointID,
		SenderDeviceID: r.daemon.config.DeviceID, RoomID: roomID, ReplyToEventID: composition.ReplyToEventID,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: composition.ExpiresAtUnix, Kind: "room.message",
		IdempotencyKey: strings.TrimPrefix(key, "idem_"), Content: content})
	if err != nil {
		return eventlog.RoomApplicationSend{}, false, fault.Wrap(fault.CodePayloadMalformed, err)
	}
	plaintext, err := envelope.EncodeEventJSON(event)
	if err != nil {
		return eventlog.RoomApplicationSend{}, false, err
	}
	// The plaintext bound is checked before the seal, so no ratchet step is
	// spent on an Event the room cannot carry.
	if len(plaintext) > relayframe.MaxRoomApplicationPlaintextBytes {
		return eventlog.RoomApplicationSend{}, false, fault.New(fault.CodeContentTooLarge, "the room message exceeds the room plaintext bound")
	}
	reserved := eventlog.RoomSealIntent{IdempotencyKey: key, IntentDigest: intentDigest, EventID: event.EventID,
		EventBase64: base64.StdEncoding.EncodeToString(plaintext), Sequence: sequence, RoomEpoch: record.RoomEpoch, ReservedAtUnix: uint64(now.Unix())}
	if err := journal.ReserveRoomSeal(roomID, reserved); err != nil {
		return eventlog.RoomApplicationSend{}, false, err
	}
	send, err := r.resumeSeal(roomID, reserved, now)
	return send, true, err
}

func isRoomEpochGap(err error) bool { return fault.CodeOf(err) == fault.CodeRoomEpochGap }

// sendingRecord returns the fused record of a room this installation may
// seal in now: a member, not removed, before the room's end minus the skew
// (D18).
func (r *roomRuntime) sendingRecord(roomID string, now time.Time) (eventlog.RoomMLSRecord, error) {
	record, found, err := r.ledger.Current(roomID)
	if err != nil {
		return eventlog.RoomMLSRecord{}, err
	}
	if !found || !record.Membership().Contains(r.daemon.config.AgentID) {
		return eventlog.RoomMLSRecord{}, fault.New(fault.CodeNotARoomMember, "this installation is not a member of the room")
	}
	if _, removed, err := r.daemon.journal.RoomRemovalOf(roomID); err != nil {
		return eventlog.RoomMLSRecord{}, err
	} else if removed {
		return eventlog.RoomMLSRecord{}, fault.New(fault.CodeNotARoomMember, "this installation was removed from the room")
	}
	if r.sendingStopped(record.RoomEndsAtUnix, now) {
		return eventlog.RoomMLSRecord{}, fault.New(fault.CodeRoomEnded, "the room has ended")
	}
	return record, nil
}

// sendingStopped reports whether now is at or past the room's end minus the
// skew, when every member's sealing stops (D18).
func (r *roomRuntime) sendingStopped(endsAtUnix uint64, now time.Time) bool {
	if endsAtUnix == 0 || endsAtUnix > uint64(1<<62) {
		return true
	}
	return !now.Before(time.Unix(int64(endsAtUnix), 0).Add(-r.skew))
}

// resumeSeal seals the reserved Event in the room's current epoch and
// records the object, which ends the intent. An intent whose room epoch has
// moved on is dropped: its sequence becomes a gap at the receivers. The
// caller holds the handling lock.
func (r *roomRuntime) resumeSeal(roomID string, intent eventlog.RoomSealIntent, now time.Time) (eventlog.RoomApplicationSend, error) {
	journal := r.daemon.journal
	record, err := r.sendingRecord(roomID, now)
	if err != nil {
		if code := fault.CodeOf(err); code == fault.CodeNotARoomMember || code == fault.CodeRoomEnded {
			if dropErr := journal.DropRoomSealIntent(roomID, intent.IdempotencyKey); dropErr != nil {
				return eventlog.RoomApplicationSend{}, dropErr
			}
		}
		return eventlog.RoomApplicationSend{}, err
	}
	if record.RoomEpoch != intent.RoomEpoch {
		if err := journal.DropRoomSealIntent(roomID, intent.IdempotencyKey); err != nil {
			return eventlog.RoomApplicationSend{}, err
		}
		return eventlog.RoomApplicationSend{}, fault.New(fault.CodeRoomEpochGap, "the room epoch moved on before the message was sealed")
	}
	plaintext, err := intent.Event()
	if err != nil {
		return eventlog.RoomApplicationSend{}, err
	}
	authenticator, held := record.EpochAuthenticatorAt(record.MLSEpoch)
	if !held {
		return eventlog.RoomApplicationSend{}, errors.New("the room holds no authenticator of its current epoch")
	}
	aad, err := relayframe.EncodeRoomAAD(relayframe.RoomAAD{RoomID: roomID, RoomEpoch: record.RoomEpoch, MLSEpoch: record.MLSEpoch,
		EpochAuthenticator: authenticator, SenderAgentID: r.daemon.config.AgentID, EventID: intent.EventID})
	if err != nil {
		return eventlog.RoomApplicationSend{}, err
	}
	ciphertext, sealedRecord, err := r.controller.Seal(roomID, aad, plaintext)
	if err != nil {
		return eventlog.RoomApplicationSend{}, err
	}
	if sealedRecord.MLSEpoch != record.MLSEpoch || sealedRecord.RoomEpoch != record.RoomEpoch {
		return eventlog.RoomApplicationSend{}, errors.New("the room moved while the message was sealed")
	}
	object, err := relayframe.EncodeRoomObject(relayframe.RoomObject{Type: relayframe.RoomApplication, RoomID: roomID,
		RoomEpoch: record.RoomEpoch, MLSEpoch: record.MLSEpoch, Body: ciphertext})
	if err != nil {
		return eventlog.RoomApplicationSend{}, fault.Wrap(fault.CodeContentTooLarge, err)
	}
	if len(object) > relayframe.FirstPartBytes {
		return eventlog.RoomApplicationSend{}, fault.New(fault.CodeContentTooLarge, "the sealed room message exceeds one part")
	}
	// The fan-out uses the sealing epoch's membership (section 11.4).
	send, err := eventlog.NewRoomApplicationSend(roomID, intent, record.MLSEpoch, object, r.othersOf(record.Members),
		now, now.Add(eventlog.MaxRoomApplicationRetention))
	if err != nil {
		return eventlog.RoomApplicationSend{}, err
	}
	if err := journal.RecordRoomApplicationSend(send); err != nil {
		return eventlog.RoomApplicationSend{}, err
	}
	return send, nil
}

// resumeSeals finishes, at start and on the timer, every seal a crash left
// unfinished.
func (r *roomRuntime) resumeSeals() {
	records, err := r.ledger.List()
	if err != nil {
		r.daemon.report("room seal", err)
		return
	}
	for _, record := range records {
		r.handling.Lock()
		_, intent, err := r.daemon.journal.RoomSendState(record.RoomID)
		if err == nil && intent != nil {
			if existing, found, lookupErr := r.daemon.journal.RoomApplicationSendFor(record.RoomID, intent.IdempotencyKey); lookupErr != nil {
				err = lookupErr
			} else if found {
				err = r.daemon.journal.RecordRoomApplicationSend(existing)
			} else {
				_, err = r.resumeSeal(record.RoomID, *intent, r.now())
				if isRoomEpochGap(err) || fault.CodeOf(err) == fault.CodeNotARoomMember || fault.CodeOf(err) == fault.CodeRoomEnded {
					err = nil
				}
			}
		}
		r.handling.Unlock()
		if err != nil {
			r.daemon.report("room seal "+record.RoomID, err)
		}
	}
}

// depositApplication deposits an application object to every member still
// pending whose retry time has come.
func (r *roomRuntime) depositApplication(ctx context.Context, send eventlog.RoomApplicationSend) {
	object, kept, err := send.Object()
	if err != nil {
		r.daemon.report("room message "+send.RoomID, err)
		return
	}
	if !kept {
		return
	}
	now := r.now()
	for _, member := range send.Members {
		if member.State != eventlog.RoomDeliveryPending || member.NextAttemptAtUnix > uint64(now.Unix()) {
			continue
		}
		if err := r.depositApplicationTo(ctx, send, object, member.AgentID, now); err != nil {
			r.daemon.report("room message "+send.RoomID, err)
		}
	}
}

// depositApplicationTo deposits the object to one member: CheckPeer on the
// member's stored evidence pinned to its verified leaf credential, then one
// kind-3 frame carrying this node's card and evidence.
func (r *roomRuntime) depositApplicationTo(ctx context.Context, send eventlog.RoomApplicationSend, object []byte,
	member string, now time.Time) error {
	journal := r.daemon.journal
	later := func(until time.Time) error {
		_, err := journal.RoomApplicationDeferred(send.RoomID, send.IdempotencyKey, member, until, now)
		return err
	}
	credential, known, err := r.ledger.RoomCredential(send.RoomID, member)
	if err != nil {
		return err
	}
	if !known {
		// The member's roster has not taught its credential yet.
		return later(now.Add(roomApplicationRetry))
	}
	pin, err := directory.LeafPin(member, credential, now)
	if err != nil {
		_, abandonErr := journal.RoomApplicationAbandoned(send.RoomID, send.IdempotencyKey, member, fault.CodeNotAuthentic, now)
		return abandonErr
	}
	if _, err := r.relay.verifier.CheckStored(member, pin, now); err != nil {
		if fault.CodeOf(err) != fault.CodeInternal {
			if requestErr := r.relay.requestEvidence(member, now); requestErr != nil {
				r.daemon.report("relay evidence request", requestErr)
			}
		}
		return later(now.Add(relayEvidenceRetry))
	}
	evidence, card, _, err := r.ownEvidence()
	if err != nil {
		return later(now.Add(roomApplicationRetry))
	}
	frames, err := relayframe.SplitRoomObject(object, card, evidence, 0)
	if err != nil {
		return err
	}
	if len(frames) != 1 {
		return errors.New("an application object was cut into more than one part")
	}
	key, err := relayframe.RoomIdempotencyKey(send.ObjectDigest, member, 1, 0)
	if err != nil {
		return err
	}
	response, err := r.relay.carrier.Carry(ctx, member, key, "", send.AbandonAtUnix, frames[0])
	if err != nil {
		return later(now.Add(roomApplicationRetry))
	}
	switch response.Result {
	case carrierapi.ResultCarried:
		_, err := journal.RoomApplicationCarried(send.RoomID, send.IdempotencyKey, member, canon.Digest(evidence), now)
		return err
	case carrierapi.ResultRetry:
		// A relay mailbox that is full (507) answers retry, as does an
		// unreachable relay: the object stays pending.
		return later(now.Add(roomApplicationRetry))
	default:
		switch response.Code {
		case carrierapi.CodePeerCap:
			// The cap leaves the object pending, never dropped.
			return later(now.Add(relayCapRetry))
		case carrierapi.CodeNoPeerCard:
			return later(now.Add(relayEvidenceRetry))
		default:
			_, err := journal.RoomApplicationAbandoned(send.RoomID, send.IdempotencyKey, member, fault.CodeRejected, now)
			return err
		}
	}
}

// sweepApplicationSends is the application sender's share of the relay
// maintenance timer: unfinished seals are finished, members past the
// object's retention are abandoned, and every pending deposit due is tried.
func (r *roomRuntime) sweepApplicationSends(ctx context.Context) {
	r.resumeSeals()
	if _, err := r.daemon.journal.SweepRoomApplicationSends(r.now()); err != nil {
		r.daemon.report("room messages", err)
	}
	pending, err := r.daemon.journal.PendingRoomApplicationSends()
	if err != nil {
		r.daemon.report("room messages", err)
		return
	}
	for _, send := range pending {
		r.depositApplication(ctx, send)
	}
}
