package agentcarrier

import (
	"bytes"
	"context"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"slices"
)

func sameCard(a, b agentpacketseal.KeyCard) bool {
	return a.KeyID == b.KeyID && bytes.Equal(a.PublicKey, b.PublicKey) && a.NotBeforeUnix == b.NotBeforeUnix && a.NotAfterUnix == b.NotAfterUnix && slices.Equal(a.Relays, b.Relays)
}
func (l *Lane) verifyCard(ctx context.Context, raw []byte) (agentpacketseal.RecipientKey, agentpacketseal.KeyCard, error) {
	if len(raw) == 0 || len(raw) > agenttransport.MaxHintCardBytes {
		return agentpacketseal.RecipientKey{}, agentpacketseal.KeyCard{}, ErrRefused
	}
	p, err := agentpacket.DecodeJSON(raw)
	if err != nil || p.RecipientAgentID != agentpacketseal.KeyCardAudience || p.CapabilityID != agentpacketseal.KeyCardCapability || p.QuoteCommitment != "" {
		return agentpacketseal.RecipientKey{}, agentpacketseal.KeyCard{}, ErrRefused
	}
	expected, err := agentpacketseal.DecodeKeyCard(p.Payload)
	if err != nil {
		return agentpacketseal.RecipientKey{}, expected, ErrRefused
	}
	key, card, err := l.config.VerifyCard(ctx, raw, l.config.Now())
	if err != nil {
		return key, card, err
	}
	if key.AgentID != p.SenderAgentID || key.KeyID != expected.KeyID || !bytes.Equal(key.PublicKey, expected.PublicKey) || !sameCard(card, expected) {
		return key, card, ErrRefused
	}
	if agentpacketseal.CheckKeyCardTime(card, l.config.Now()) != nil {
		return key, card, ErrRefused
	}
	return key, card, nil
}
