package buyeragent

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentcarrier"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

type TransportConfig struct {
	Delegation  []byte
	Key         ed25519.PrivateKey
	Verifier    *agenttransport.Verifier
	Relay       func(string) (agentcarrier.Relay, error)
	Directories []string
	Directory   func(string) (agentcarrier.Directory, error)
}

type purchaseLookupKey struct{}

func (c *Carrier) openTransport(ctx context.Context, transport TransportConfig) (err error) {
	delegation, err := agenttransport.DecodeDelegation(transport.Delegation)
	if err != nil || delegation.Purposes&(agenttransport.Relay|agenttransport.Hints) != agenttransport.Relay|agenttransport.Hints {
		return agentcarrier.ErrConfig
	}
	config := agentcarrier.Config{
		StateDir: c.config.StateDir, AgentID: c.config.BuyerAgentID, Kind: agentcarrier.Rail,
		Relays: c.config.Relays, Now: c.config.Now, Delegation: transport.Delegation,
		Verifier: transport.Verifier, Relay: transport.Relay, SignCard: c.signCard,
		VerifyCard: c.verifyCard, VerifyPacket: c.verifyPacket, Store: c.storePacket,
	}
	c.credentials, err = agentcarrier.OpenCredentialManager(ctx, config, transport.Key, c.admitContact)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = c.Close()
		}
	}()
	config.Credentials = c.credentials
	c.lane, err = agentcarrier.Open(ctx, config)
	if err != nil {
		return err
	}
	c.routes, err = agentcarrier.OpenResolver(c.lane, agentcarrier.ResolverConfig{
		Directories: transport.Directories, Directory: transport.Directory, TestSingleRelay: true,
	})
	if err != nil {
		return err
	}
	c.publisher, err = agentcarrier.OpenPublisher(c.lane, c.credentials, agentcarrier.PublicationConfig{
		Directories: transport.Directories, Directory: transport.Directory, TestSingleRelay: true,
	})
	if err != nil {
		return err
	}
	c.scheduler, err = agentcarrier.OpenScheduler(c.lane, c.routes)
	return err
}

func (c *Carrier) Close() error {
	var failures []error
	if c.scheduler != nil {
		failures = append(failures, c.scheduler.Close())
	}
	if c.publisher != nil {
		failures = append(failures, c.publisher.Close())
	}
	if c.routes != nil {
		failures = append(failures, c.routes.Close())
	}
	if c.lane != nil {
		failures = append(failures, c.lane.Close())
	}
	if c.credentials != nil {
		failures = append(failures, c.credentials.Close())
	}
	return errors.Join(failures...)
}

func (c *Carrier) signCard(ctx context.Context, card agentpacketseal.KeyCard) ([]byte, error) {
	packet, err := agentpacketseal.KeyCardPacket(c.config.BuyerAgentID, c.config.ControllerKeyID,
		card.NotBeforeUnix, card.KeyID, card.NotBeforeUnix, card)
	if err != nil {
		return nil, err
	}
	signed, err := agentpacket.Sign(ctx, c.config.Signer, c.config.Controller, packet)
	if err != nil {
		return nil, err
	}
	return agentpacket.EncodeJSON(signed)
}

func (c *Carrier) verifyCard(ctx context.Context, raw []byte, _ time.Time) (agentpacketseal.RecipientKey, agentpacketseal.KeyCard, error) {
	packet, err := agentpacket.DecodeJSON(raw)
	if err != nil {
		return agentpacketseal.RecipientKey{}, agentpacketseal.KeyCard{}, agentcarrier.ErrRefused
	}
	return c.config.Cards.VerifyAgentCard(ctx, c.config.Verifier, packet.SenderAgentID, raw)
}

func (c *Carrier) verifyPacket(ctx context.Context, packet agentpacket.Packet) error {
	err := c.config.Cards.VerifyPacket(ctx, c.config.Verifier, packet)
	if errors.Is(err, buyersdk.ErrPacketRefused) {
		return agentcarrier.ErrRefused
	}
	return err
}

func (c *Carrier) storePacket(ctx context.Context, raw []byte) error {
	lookup, ok := ctx.Value(purchaseLookupKey{}).(PurchaseLookup)
	if !ok {
		return agentcarrier.ErrUnavailable
	}
	packet, err := agentpacket.DecodeJSON(raw)
	if err != nil {
		return agentcarrier.ErrRefused
	}
	err = c.storeResultPacket(packet, lookup)
	if isPermanent(err) {
		return agentcarrier.ErrRefused
	}
	if err == nil {
		c.receiveContact(ctx, packet, raw)
	}
	return err
}

type purchasePeerKey struct{}

func (c *Carrier) admitContact(ctx context.Context, peer string) error {
	if ctx.Value(purchasePeerKey{}) == peer {
		return nil
	}
	return agentcarrier.ErrRefused
}

func (c *Carrier) issueContact(ctx context.Context, peer string) (railwork.ContactGrant, error) {
	credential, err := c.credentials.IssueContact(context.WithValue(ctx, purchasePeerKey{}, peer), peer)
	if err != nil {
		return "", err
	}
	wire, seed, err := credential.ExportForSealedPacket()
	defer clear(seed)
	if err != nil {
		return "", err
	}
	return railwork.NewContactGrant(wire, seed), nil
}

// receiveContact only reads a completed message of a purchase whose packets
// have already passed admission. A bad grant has no effect on the result.
func (c *Carrier) receiveContact(ctx context.Context, packet agentpacket.Packet, raw []byte) {
	frame, err := railwork.DecodeFrame(packet.Payload)
	if err != nil {
		return
	}
	round := ResultRound{ProviderAgentID: packet.SenderAgentID, Record: buyersdk.CallRecord{
		RequestHash: hex.EncodeToString(frame.Binding.RequestHash[:]), CapabilityID: packet.CapabilityID,
		QuoteCommitment: packet.QuoteCommitment,
	}}
	message, complete, err := c.assemble(round, hex.EncodeToString(frame.MessageDigest[:]))
	if err != nil || !complete || message.joinErr != nil {
		return
	}
	result, err := railwork.DecodeResult(message.message.Body)
	if err != nil || result.Header.Contact == "" {
		return
	}
	route := agentcarrier.Route{CardPacket: result.ProviderKeyCard}
	if _, err := c.routes.Resolve(ctx, packet.SenderAgentID, route); err != nil {
		return
	}
	ctx = context.WithValue(ctx, purchasePeerKey{}, packet.SenderAgentID)
	_ = c.credentials.ReceiveContact(ctx, raw, func(agentpacket.Packet) ([]byte, []byte, error) {
		return result.Header.Contact.Bytes()
	}, c.routes)
}
