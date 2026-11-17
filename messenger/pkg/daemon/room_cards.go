package daemon

// Member chat cards at the authority (sections 11.1, 11.2, 11.8).
//
// The authority builds every roster, and a roster entry carries the member's
// chat card. The daemon keeps each member's card from the part 0 of that
// member's own frames after admission: the joiner's room.key-package frame
// first (the joiner always includes its card there), then any later admitted
// frame of the member whose card is newer. Only the card's shape, its Agent
// and its validity window are checked here; the card's signature is each
// receiving member's carrier's to verify when it admits the card
// (carrier.room-cards), so a card that does not verify is never used.

import (
	"errors"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// errRoomCardInvalid refuses a card that is not a key card of the frame's
// sender inside its validity window.
var errRoomCardInvalid = errors.New("the chat card is not a valid key card of its sender")

// memberCardOf checks a chat card from a member's frame: one canonical key
// card packet sent by that Agent to the key-card audience, inside its
// validity window now. It returns the record the room keeps.
func memberCardOf(roomID, agentID string, card []byte, now time.Time) (eventlog.RoomMemberCard, error) {
	if err := checkCardShape(card, agentID); err != nil {
		return eventlog.RoomMemberCard{}, errRoomCardInvalid
	}
	packet, err := agentpacket.DecodeJSON(card)
	if err != nil || packet.RecipientAgentID != agentpacketseal.KeyCardAudience ||
		packet.CapabilityID != agentpacketseal.KeyCardCapability || packet.QuoteCommitment != "" {
		return eventlog.RoomMemberCard{}, errRoomCardInvalid
	}
	body, err := agentpacketseal.DecodeKeyCard(packet.Payload)
	if err != nil || agentpacketseal.CheckKeyCardTime(body, now) != nil {
		return eventlog.RoomMemberCard{}, errRoomCardInvalid
	}
	return eventlog.RoomMemberCard{RoomID: roomID, AgentID: agentID, CardBase64: encodeCard(card),
		CreatedAtUnix: packet.CreatedAtUnix, Sequence: packet.Sequence, NotBeforeUnix: body.NotBeforeUnix,
		NotAfterUnix: body.NotAfterUnix}, nil
}

// joinerCardOf checks the card of a joiner's room.key-package frame. A
// missing or invalid card refuses the KeyPackage: the joiner always sends
// it, and the rosters of the Add need it.
func joinerCardOf(roomID, agentID string, card []byte, now time.Time) (eventlog.RoomMemberCard, error) {
	if len(card) == 0 {
		return eventlog.RoomMemberCard{}, fault.New(fault.CodePayloadMalformed, "the room.key-package frame carries no chat card")
	}
	record, err := memberCardOf(roomID, agentID, card, now)
	if err != nil {
		return eventlog.RoomMemberCard{}, fault.Wrap(fault.CodeNotAuthentic, err)
	}
	return record, nil
}

// storeJoinerCard keeps a joiner's checked card once its KeyPackage is
// recorded with the add.
func (r *roomRuntime) storeJoinerCard(card eventlog.RoomMemberCard, now time.Time) error {
	if _, err := r.daemon.journal.StoreRoomMemberCard(card, now); err != nil {
		if errors.Is(err, eventlog.ErrRoomCardMember) {
			return fault.Wrap(fault.CodeNotAuthentic, err)
		}
		return err
	}
	return nil
}

// refreshMemberCard keeps a newer card from an admitted frame of a member,
// in every room this installation is the authority of that holds the
// sender as a member or a pending add. An invalid card changes nothing.
func (r *roomRuntime) refreshMemberCard(sender string, card []byte, now time.Time) {
	if len(card) == 0 || sender == r.daemon.config.AgentID {
		return
	}
	records, err := r.ledger.List()
	if err != nil {
		r.daemon.report("room member card", err)
		return
	}
	for _, record := range records {
		if record.AuthorityAgentID != r.daemon.config.AgentID {
			continue
		}
		value, err := memberCardOf(record.RoomID, sender, card, now)
		if err != nil {
			return
		}
		if _, err := r.daemon.journal.StoreRoomMemberCard(value, now); err != nil && !errors.Is(err, eventlog.ErrRoomCardMember) {
			r.daemon.report("room member card", err)
		}
	}
}

// storedMemberCard returns a member's stored card while it is valid. A
// missing or expired card starts the member's evidence pull, whose kind-4
// frames carry its card, and the roster waits.
func (r *roomRuntime) storedMemberCard(roomID, member string, now time.Time) ([]byte, error) {
	stored, found, err := r.daemon.journal.RoomMemberCardOf(roomID, member)
	if err != nil {
		return nil, err
	}
	if found && stored.Valid(now) {
		return stored.Card()
	}
	if err := r.relay.requestEvidence(member, now); err != nil {
		r.daemon.report("relay evidence request", err)
	}
	return nil, fault.Wrap(fault.CodeNoRouteAdvertised, ErrRoomMemberCardUnknown)
}
