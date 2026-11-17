package daemon

// A room.invite received over the relay route records a pending join
// (sections 11.2, 11.6). The invite carries the authority's own leaf
// credential, which the joiner later authenticates the Welcome's sender
// with, so it is verified on the room path before anything is stored: it
// must decode strictly, name the invite's sender Agent and an Endpoint and
// device of its delegation as finalized now, the delegation's network and
// genesis, and a window that has not ended, signed by that Endpoint.
// Admission has already run the base check; this adds the device set and
// produces the binding the pending join keeps.

import (
	"errors"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/admission"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/payload"
)

// inviteStep is the write a received room.invite adds to its Event's
// commit, after admission admitted it: the room-path check and then the
// pending join, before the Event's own commit, so a crash between them is
// healed by the exact retry, which records it again. A failing check
// returns a fault, so the Event is refused, relay-acknowledged, and nothing
// is stored; it runs after the contact policy, so a sender the policy never
// admitted learns nothing from it.
type inviteStep func() error

// roomInviteStep returns the step of a room.invite received on the relay
// route, or nil for any other Event or an installation without the room
// runtime.
func (d *Daemon) roomInviteStep(route admission.Route, event envelope.Event, sender verifiedPeer, now time.Time) inviteStep {
	if route != admission.RouteRelay || event.Kind != "room.invite" || d.relay == nil || d.relay.rooms == nil {
		return nil
	}
	return func() error {
		binding, invite, err := d.verifyRoomInvite(event, sender, now)
		if err != nil {
			return err
		}
		expires := time.Unix(int64(invite.ExpiresAtUnix), 0)
		_, err = d.journal.RecordRoomInvite(invite.RoomID, event.SenderAgentID, event.EventID, binding, expires, now)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, eventlog.ErrRoomAlreadyJoined):
			// The room is held already; the invite changes nothing.
			return nil
		case errors.Is(err, eventlog.ErrRoomJoinConflict):
			// The owner accepted another authority's invite for this room.
			return fault.New(fault.CodeNotAuthentic, "the room's accepted join names another authority")
		case errors.Is(err, eventlog.ErrRoomJoinsFull), errors.Is(err, eventlog.ErrRoomJoinsShareFull):
			// Expired invites were swept first; the live ones fill the bound.
			return fault.New(fault.CodeQuotaExceeded, "pending room joins reached their bound")
		default:
			return err
		}
	}
}

// verifyRoomInvite checks a room.invite on the room path and returns the
// authority's leaf binding the pending join keeps.
func (d *Daemon) verifyRoomInvite(event envelope.Event, sender verifiedPeer, now time.Time) (group.LeafBinding, payload.RoomInvite, error) {
	decoded, err := payload.Decode(event.Kind, event.Content)
	if err != nil {
		return group.LeafBinding{}, payload.RoomInvite{}, fault.Wrap(fault.CodePayloadMalformed, err)
	}
	invite, ok := decoded.(payload.RoomInvite)
	if !ok || invite.InviteeAgentID != d.config.AgentID || invite.ValidateLifetime(event.CreatedAtUnix) != nil ||
		invite.ExpiresAtUnix > uint64(1<<63-1) {
		return group.LeafBinding{}, payload.RoomInvite{}, fault.New(fault.CodePayloadMalformed, "the room invite is not this installation's")
	}
	credential, err := group.DecodeLeafCredential(invite.AuthorityLeafCredential)
	if err != nil || credential.AgentID != event.SenderAgentID || sender.Delegation.AgentID != event.SenderAgentID {
		return group.LeafBinding{}, payload.RoomInvite{}, fault.New(fault.CodeNotAuthentic, "the invite's leaf credential is not its sender's")
	}
	set, err := e2ee.Summarize(sender.Bundles)
	if err != nil {
		return group.LeafBinding{}, payload.RoomInvite{}, fault.Wrap(fault.CodeNotAuthentic, err)
	}
	// Before any Welcome the room's end is this credential's own expiry, so
	// its window is judged against it (D18).
	binding, err := group.VerifyRoomLeafCredential(sender.Delegation, credential, set, credential.ExpiresAtUnix, now)
	if err != nil {
		return group.LeafBinding{}, payload.RoomInvite{}, fault.Wrap(fault.CodeNotAuthentic, err)
	}
	return binding, invite, nil
}
