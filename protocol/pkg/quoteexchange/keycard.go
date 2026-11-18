package quoteexchange

import (
	"errors"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// MaxProviderKeyCardBytes bounds the provider key card packet JSON that a
// Quote Proposal response may carry next to its package. It equals the key
// card bound of the rail frames, so a card a gateway serves always fits the
// frames that carry cards.
const MaxProviderKeyCardBytes = 16 << 10

// ErrProviderKeyCard reports a Quote-carried provider key card that is not a
// well-formed, currently valid key card of the proposal's provider Agent.
var ErrProviderKeyCard = errors.New("Quote Proposal provider key card is malformed, expired or not the provider's")

// CheckProviderKeyCard checks the shape of a provider key card a Quote
// Proposal response carries: a bounded Agent Packet JSON that is a key card
// packet (fixed audience and Capability, no Quote commitment), sent by the
// proposal's provider Agent, with a canonical body whose validity window
// contains now.
//
// It checks no signature and reads no state. The card stays
// non-authoritative: a buyer seals to it only after verifying it against
// finalized state and the Capability's finalized owner.
func CheckProviderKeyCard(raw []byte, providerAgentID string, now time.Time) error {
	if len(raw) == 0 || len(raw) > MaxProviderKeyCardBytes || providerAgentID == "" {
		return ErrProviderKeyCard
	}
	packet, err := agentpacket.DecodeJSON(raw)
	if err != nil {
		return ErrProviderKeyCard
	}
	if packet.RecipientAgentID != agentpacketseal.KeyCardAudience ||
		packet.CapabilityID != agentpacketseal.KeyCardCapability || packet.QuoteCommitment != "" ||
		packet.SenderAgentID != providerAgentID {
		return ErrProviderKeyCard
	}
	card, err := agentpacketseal.DecodeKeyCard(packet.Payload)
	if err != nil {
		return ErrProviderKeyCard
	}
	if err := agentpacketseal.CheckKeyCardTime(card, now); err != nil {
		return ErrProviderKeyCard
	}
	return nil
}
