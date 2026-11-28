package agentpacketrelay

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

func (c *V2Client) Revoke(ctx context.Context, agent string, entries []Revocation, credential []byte, holder ed25519.PrivateKey) error {
	if _, ok := parseAgentText(agent); !ok {
		return errors.New("invalid Agent")
	}
	body, err := EncodeRevocations(entries)
	if err != nil {
		return err
	}
	status, raw, err := c.exchange(ctx, "POST", c.path+"/v2/mailboxes/"+agent+"/revocations", body, credential, holder)
	if err != nil {
		return err
	}
	if status != 204 || len(raw) != 0 {
		return errors.New("invalid revocation response")
	}
	return nil
}

// Hint responses remain untrusted until the caller applies VerifyConsumerHint.
// A directory is a route source, never identity or controller authority.
func (c *V2Client) HintIndex(ctx context.Context, agent string) ([]HintIndexEntry, error) {
	if _, ok := parseAgentText(agent); !ok {
		return nil, errors.New("invalid Agent")
	}
	status, raw, err := c.exchange(ctx, "GET", c.path+"/v2/hints/"+agent, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, errors.New("invalid hint index status")
	}
	return DecodeHintIndex(raw)
}
func (c *V2Client) HintRecord(ctx context.Context, agent string, digest [32]byte) ([]byte, error) {
	if _, ok := parseAgentText(agent); !ok {
		return nil, errors.New("invalid Agent")
	}
	status, raw, err := c.exchange(ctx, "GET", c.path+"/v2/hints/"+agent+"/"+hex.EncodeToString(digest[:]), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, errors.New("invalid hint record status")
	}
	record, err := agenttransport.DecodeHintRecord(raw)
	if err != nil || record.Hint.Delegation.AgentID() != agent {
		return nil, errors.New("invalid hint record identity")
	}
	d, err := record.Hint.Delegation.Encode()
	if err != nil || sha256.Sum256(d) != digest {
		return nil, errors.New("invalid hint record digest")
	}
	return raw, nil
}
func (c *V2Client) PublishHint(ctx context.Context, raw []byte) error {
	record, err := agenttransport.DecodeHintRecord(raw)
	if err != nil {
		return err
	}
	status, body, err := c.exchange(ctx, "PUT", c.path+"/v2/hints/"+record.Hint.Delegation.AgentID(), raw, nil, nil)
	if err != nil {
		return err
	}
	if (status != 200 && status != 204) || len(body) != 0 {
		return errors.New("invalid hint publication response")
	}
	return nil
}

type V2Description struct {
	Schema                   string `json:"schema"`
	MaxEnvelopeBytes         uint64 `json:"max_envelope_bytes"`
	MaxTTLSeconds            uint64 `json:"max_ttl_seconds"`
	PerRecipientMaxEnvelopes uint64 `json:"per_recipient_max_envelopes"`
	PerRecipientMaxBytes     uint64 `json:"per_recipient_max_bytes"`
	StrangerMaxEnvelopes     uint64 `json:"stranger_max_envelopes"`
	StrangerMaxBytes         uint64 `json:"stranger_max_bytes"`
	MaxWaitSeconds           uint64 `json:"max_wait_seconds"`
	Directory                bool   `json:"directory"`
}

func (c *V2Client) Describe(ctx context.Context) (V2Description, error) {
	var out V2Description
	status, raw, err := c.exchange(ctx, "GET", c.path+"/v2/relay", nil, nil, nil)
	if err != nil {
		return out, err
	}
	if status != 200 || jsonstrict.Decode(raw, &out) != nil || out.Schema != "tos.service.agent-packet-relay.relay.v2" || out.MaxEnvelopeBytes == 0 || out.MaxEnvelopeBytes > MaxEnvelopeBytes || out.MaxTTLSeconds == 0 || out.MaxTTLSeconds > 86400 || out.PerRecipientMaxEnvelopes == 0 || out.PerRecipientMaxEnvelopes > 256 || out.PerRecipientMaxBytes == 0 || out.PerRecipientMaxBytes > 16<<20 || out.StrangerMaxEnvelopes > 64 || out.StrangerMaxBytes > 4<<20 || out.MaxWaitSeconds != 25 {
		return V2Description{}, errors.New("invalid V2 description")
	}
	return out, nil
}
