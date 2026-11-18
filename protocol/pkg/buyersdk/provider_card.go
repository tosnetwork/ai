package buyersdk

import (
	"context"
	"errors"
	"fmt"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"google.golang.org/protobuf/proto"
)

// ProviderCardSource names where a provider key card came from. Every
// source is untrusted; a card from any of them is verified the same way.
type ProviderCardSource string

const (
	// ProviderCardFromOffer is a card from an offer file the user or a
	// catalog supplied.
	ProviderCardFromOffer ProviderCardSource = "offer_file"
	// ProviderCardFromQuote is a card a gateway served next to a Quote
	// package (RequestQuoteProposalResponse.provider_key_card_packet_json).
	ProviderCardFromQuote ProviderCardSource = "quote"
	// ProviderCardFromResult is a card carried in a result of the same
	// purchase.
	ProviderCardFromResult ProviderCardSource = "result"
)

// ProviderCardReverifyAfter is how long a verification lets a card be
// sealed to (AGENT_PACKET_RELAY_V1 section 6.3): a card is re-verified
// against finalized state no more than 10 minutes before each sealing.
const ProviderCardReverifyAfter = 10 * time.Minute

// ErrProviderCard reports a provider key card that cannot be sealed to.
var ErrProviderCard = errors.New("the provider key card cannot be used")

// VerifiedProviderCard is a provider key card verified for one Capability
// at one finalized checkpoint.
type VerifiedProviderCard struct {
	Source       ProviderCardSource
	CapabilityID string
	// PacketJSON is the card packet as received.
	PacketJSON []byte
	Key        agentpacketseal.RecipientKey
	Card       agentpacketseal.KeyCard
	Checkpoint uint64
	VerifiedAt time.Time
}

// UsableAt reports whether the card may be sealed to at now: inside its own
// validity window, and verified no more than ProviderCardReverifyAfter
// earlier. A card that is not usable is verified again, never used.
func (c VerifiedProviderCard) UsableAt(now time.Time) error {
	if c.VerifiedAt.IsZero() || now.Before(c.VerifiedAt) || now.Sub(c.VerifiedAt) > ProviderCardReverifyAfter {
		return fmt.Errorf("%w: it must be verified again against finalized state", ErrProviderCard)
	}
	if err := agentpacketseal.CheckKeyCardTime(c.Card, now); err != nil {
		return fmt.Errorf("%w: it is outside its validity window", ErrProviderCard)
	}
	return nil
}

// VerifyProviderCard verifies a provider key card for a Capability, from
// whatever source: the card must be a key card signed by a controller of a
// finalized, live Agent (agentpacketseal.VerifyKeyCard), valid now, and that
// Agent must be the Capability's finalized owner, read at the same
// checkpoint and never taken from the card's source
// (AGENT_PACKET_RELAY_V1 section 6.4).
func (b *ServiceActorBuyer) VerifyProviderCard(ctx context.Context, verifier mldsa44.Verifier, source ProviderCardSource,
	capabilityID string, raw []byte) (VerifiedProviderCard, error) {
	switch source {
	case ProviderCardFromOffer, ProviderCardFromQuote, ProviderCardFromResult:
	default:
		return VerifiedProviderCard{}, fmt.Errorf("%w: unknown card source %q", ErrProviderCard, source)
	}
	if ctx == nil || verifier == nil || capabilityID == "" {
		return VerifiedProviderCard{}, errors.New("invalid provider key card verification request")
	}
	if len(raw) == 0 || len(raw) > quoteexchange.MaxProviderKeyCardBytes {
		return VerifiedProviderCard{}, fmt.Errorf("%w: it is empty or over %d bytes", ErrProviderCard, quoteexchange.MaxProviderKeyCardBytes)
	}
	packet, err := agentpacket.DecodeJSON(raw)
	if err != nil {
		return VerifiedProviderCard{}, fmt.Errorf("%w: it is not an Agent Packet", ErrProviderCard)
	}
	session, err := b.config.Reader.BeginBuyerSession(ctx)
	if err != nil {
		return VerifiedProviderCard{}, err
	}
	state, found, err := session.ResolveRegistry(ctx, capabilityID)
	if err != nil {
		return VerifiedProviderCard{}, err
	}
	capability := state.GetCapability()
	if !found || capability == nil || !proto.Equal(state.Network, b.config.Network) ||
		capability.CapabilityId != capabilityID || capability.Tombstoned || capability.OwnerAgentId == "" {
		return VerifiedProviderCard{}, fmt.Errorf("%w: the Capability is not live in finalized state", ErrProviderCard)
	}
	if packet.SenderAgentID != capability.OwnerAgentId {
		return VerifiedProviderCard{}, fmt.Errorf("%w: it is not a card of the Capability's finalized owner", ErrProviderCard)
	}
	now := b.config.Now()
	key, card, err := agentpacketseal.VerifyKeyCard(ctx, verifier,
		sessionAgents{ctx: ctx, session: session, network: b.config.Network}, packet, now)
	if err != nil {
		return VerifiedProviderCard{}, fmt.Errorf("%w: %v", ErrProviderCard, err)
	}
	return VerifiedProviderCard{Source: source, CapabilityID: capabilityID, PacketJSON: append([]byte(nil), raw...),
		Key: key, Card: card, Checkpoint: session.Checkpoint(), VerifiedAt: now}, nil
}

// sessionAgents resolves Agents at one finalized buyer checkpoint for packet
// verification. A state of another network or of another object is refused.
type sessionAgents struct {
	ctx     context.Context
	session ServiceActorSession
	network *nativev1.NetworkDomain
}

func (s sessionAgents) ResolveAgent(id string) (*nativev1.AgentStateV1, bool, error) {
	state, found, err := s.session.ResolveRegistry(s.ctx, id)
	if err != nil || !found {
		return nil, false, err
	}
	agent := state.GetAgent()
	if agent == nil || agent.AgentId != id || !proto.Equal(state.Network, s.network) {
		return nil, false, errors.New("the finalized state is not that Agent on this network")
	}
	return agent, true, nil
}
