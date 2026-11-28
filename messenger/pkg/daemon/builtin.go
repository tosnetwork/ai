package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/securefile"
	"github.com/tosnetwork/ai/messenger/pkg/chainagent"
	"github.com/tosnetwork/ai/messenger/pkg/transport"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentcarrier"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
)

// CarrierBuiltin names the in-process chat lane (relay_carriage.carrier).
// The empty value is the external carrier on carry_socket_path.
const CarrierBuiltin = "builtin"

// BuiltinCarrierConfig configures the chat lane the daemon runs itself. The
// lane commits its own transport delegation and publishes its own hint, so
// chat and rail keep separate keys and may name separate relays.
type BuiltinCarrierConfig struct {
	// StateDir is the lane's private directory, outside state_dir.
	StateDir string `json:"state_dir"`
	// Relays are the chat relays the lane polls and its hint names: at least
	// two, or one with test_single_relay.
	Relays []string `json:"relays"`
	// Directories are the directory relays hints are published to and
	// resolved from: at least two.
	Directories     []string `json:"directories"`
	TestSingleRelay bool     `json:"test_single_relay,omitempty"`
	// NetworkMode is the transport's test-network mode; production transport
	// needs a registry with authorization epochs and is not available yet.
	NetworkMode agenttransport.NetworkMode `json:"network_mode"`
	// TransportDelegationPath holds the lane's committed 167-byte transport
	// delegation; TransportKeyPath the 32-byte seed of the key it names.
	TransportDelegationPath string `json:"transport_delegation_path"`
	TransportKeyPath        string `json:"transport_key_path"`
	// Signer signs the lane's packets and cards with an Agent controller.
	Signer BuiltinSignerConfig `json:"signer"`
	// HintTTLSeconds is the hint lifetime, at most 86,400; default 21,600.
	HintTTLSeconds uint64 `json:"hint_ttl_seconds,omitempty"`
}

// BuiltinSignerConfig names the pinned tosctl helper with signing custody and
// the controller it signs with.
type BuiltinSignerConfig struct {
	Binary     string `json:"binary"`
	SHA256     string `json:"sha256"`
	ConfigPath string `json:"config_path"`
	VaultURL   string `json:"vault_url"`
	Controller string `json:"controller"`
	// KeyID is the controller's key ID text, as the finalized policy holds it.
	KeyID string `json:"key_id"`
}

// Validate checks the builtin lane's configuration shape.
func (b BuiltinCarrierConfig) Validate(stateDir string) error {
	for _, path := range []string{b.StateDir, b.TransportDelegationPath, b.TransportKeyPath, b.Signer.Binary,
		b.Signer.ConfigPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("relay_carriage.builtin paths must be absolute and clean")
		}
	}
	if pathWithin(b.StateDir, stateDir) || pathWithin(stateDir, b.StateDir) {
		return errors.New("relay_carriage.builtin state_dir must be separate from state_dir")
	}
	if len(b.Relays) < 1 || len(b.Relays) > 4 || (!b.TestSingleRelay && len(b.Relays) < 2) {
		return errors.New("relay_carriage.builtin needs two to four relays, or one with test_single_relay")
	}
	seen := map[string]bool{}
	for _, relay := range append(append([]string(nil), b.Relays...), b.Directories...) {
		if agentpacketseal.CheckRelayURL(relay) != nil {
			return errors.New("relay_carriage.builtin relay URLs must be canonical HTTPS relay URLs")
		}
		seen[relay] = true
	}
	if len(b.Directories) < 2 || len(b.Directories) > 8 {
		return errors.New("relay_carriage.builtin needs two to eight directory relays")
	}
	if b.NetworkMode != agenttransport.TestNetworkLegacyEpochZero && b.NetworkMode != agenttransport.TestNetworkEpochAware {
		return errors.New("relay_carriage.builtin network_mode must name a test-network transport mode")
	}
	if b.HintTTLSeconds > 86_400 {
		return errors.New("relay_carriage.builtin hint_ttl_seconds is above 86,400")
	}
	if b.Signer.Controller == "" || b.Signer.VaultURL == "" {
		return errors.New("relay_carriage.builtin signer needs a controller and a vault URL")
	}
	if _, err := mldsa44.ParseKeyIDText(b.Signer.KeyID); err != nil {
		return errors.New("relay_carriage.builtin signer key_id is not an ML-DSA-44 key ID")
	}
	return nil
}

// openBuiltinCarrier opens the in-process chat lane with the daemon's
// finalized readers and the pinned signing helper.
func (d *Daemon) openBuiltinCarrier(ctx context.Context) (*transport.Builtin, error) {
	relay := d.config.RelayCarriage
	if relay == nil || relay.Builtin == nil {
		return nil, errors.New("the builtin carrier is not configured")
	}
	b := *relay.Builtin
	delegation, err := securefile.ReadBoundedRegular(b.TransportDelegationPath, 1024)
	if err != nil {
		return nil, errors.New("read the chat transport delegation: " + err.Error())
	}
	seed, err := securefile.ReadBoundedRegular(b.TransportKeyPath, ed25519.SeedSize)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("read the chat transport key seed")
	}
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	if err := os.MkdirAll(b.StateDir, 0o700); err != nil {
		return nil, err
	}
	chain, policy, err := finalizedResolver(d.config)
	if err != nil {
		return nil, err
	}
	packets, err := newFinalizedPacketResolver(d.config)
	if err != nil {
		return nil, err
	}
	network := d.config.Network()
	var source agenttransport.FinalizedResolver
	if b.NetworkMode == agenttransport.TestNetworkLegacyEpochZero {
		if source, err = agenttransport.NewLegacyTestNetworkResolver(b.NetworkMode, network, chainReader{chain}); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("the epoch-aware finalized reader is not available to the daemon yet")
	}
	verifier, err := agenttransport.NewVerifier(agenttransport.Config{Mode: b.NetworkMode, Network: network,
		ChainPolicy: policy}, source)
	if err != nil {
		return nil, err
	}
	helper, err := d.config.MLDSA44VerifierHelper()
	if err != nil {
		return nil, err
	}
	signer, err := mldsa44.NewTosctl(mldsa44.TosctlConfig{Binary: b.Signer.Binary, SHA256: b.Signer.SHA256,
		ConfigPath: b.Signer.ConfigPath, VaultURL: b.Signer.VaultURL})
	if err != nil {
		return nil, err
	}
	keyID, err := mldsa44.ParseKeyIDText(b.Signer.KeyID)
	if err != nil {
		return nil, err
	}
	signing := packetSigning{agentID: d.config.AgentID, signer: signer, controller: b.Signer.Controller, keyID: keyID}
	checks := packetChecks{verifier: helper, resolver: packets}
	roundTripper := http.DefaultTransport.(*http.Transport).Clone()
	relays := func(url string) (*agentpacketrelay.V2Client, error) {
		return agentpacketrelay.NewV2Client(url, roundTripper, d.clock)
	}
	ttl := time.Duration(b.HintTTLSeconds) * time.Second
	return transport.Open(ctx, transport.Config{
		Lane: agentcarrier.Config{StateDir: b.StateDir, AgentID: d.config.AgentID, Relays: b.Relays,
			Delegation: delegation, Verifier: verifier, Now: d.clock,
			Relay:    func(url string) (agentcarrier.Relay, error) { return relays(url) },
			SignCard: signing.card, VerifyCard: checks.card},
		TransportKey: key, VerifyPacket: checks.packet, SignPacket: signing.packet,
		Admitted: d.admittedPeer,
		Resolver: agentcarrier.ResolverConfig{Directories: b.Directories, TestSingleRelay: b.TestSingleRelay,
			Directory: func(url string) (agentcarrier.Directory, error) { return relays(url) }},
		Publication: agentcarrier.PublicationConfig{Directories: b.Directories, TestSingleRelay: b.TestSingleRelay,
			TTL: ttl, Directory: func(url string) (agentcarrier.Directory, error) { return relays(url) }},
		CardPath: relay.CardPath,
	})
}

// admittedPeer is the lane's business admission: a peer this installation
// admitted (a session, an allow-listed contact or a settled invite).
func (d *Daemon) admittedPeer(_ context.Context, peer string) error {
	if d.discovery == nil || d.discovery.relay == nil {
		return agentcarrier.ErrUnavailable
	}
	admitted, err := d.discovery.relay.Admitted(peer)
	if err != nil {
		return agentcarrier.ErrUnavailable
	}
	if !admitted {
		return agentcarrier.ErrRefused
	}
	return nil
}

// chainReader adapts the daemon's finalized Agent resolver to the
// transport's typed finalized read.
type chainReader struct{ resolver *chainagent.Resolver }

func (r chainReader) ResolveState(ctx context.Context, agentID, _ string) (*nativev1.NativeStateV1, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	return r.resolver.ResolveAgent(agentID)
}

// packetSigning signs the lane's packets and key cards with one controller.
type packetSigning struct {
	agentID    string
	signer     mldsa44.Signer
	controller string
	keyID      [mldsa44.KeyIDSize]byte
}

func (s packetSigning) packet(ctx context.Context, packet agentpacket.Packet) (agentpacket.Packet, error) {
	packet.SenderKeyID = s.keyID
	return agentpacket.Sign(ctx, s.signer, s.controller, packet)
}

func (s packetSigning) card(ctx context.Context, card agentpacketseal.KeyCard) ([]byte, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	sequence := uint64(time.Now().UnixNano())
	packet, err := agentpacketseal.KeyCardPacket(s.agentID, s.keyID, sequence, nonce, card.NotBeforeUnix, card)
	if err != nil {
		return nil, err
	}
	signed, err := agentpacket.Sign(ctx, s.signer, s.controller, packet)
	if err != nil {
		return nil, err
	}
	return agentpacket.EncodeJSON(signed)
}

// packetChecks verifies packets and cards against finalized state. A failed
// finalized read is transient; anything the read answered is permanent.
type packetChecks struct {
	verifier mldsa44.Verifier
	resolver agentpacket.AgentResolver
}

func (c packetChecks) sender(agentID string) error {
	_, found, err := c.resolver.ResolveAgent(agentID)
	if err != nil {
		return agentcarrier.ErrUnavailable
	}
	if !found {
		return agentcarrier.ErrRefused
	}
	return nil
}

func (c packetChecks) packet(ctx context.Context, packet agentpacket.Packet) error {
	if err := c.sender(packet.SenderAgentID); err != nil {
		return err
	}
	if err := agentpacket.VerifySender(ctx, c.verifier, c.resolver, packet); err != nil {
		return errors.Join(agentcarrier.ErrRefused, err)
	}
	return nil
}

func (c packetChecks) card(ctx context.Context, raw []byte, now time.Time) (agentpacketseal.RecipientKey,
	agentpacketseal.KeyCard, error) {
	packet, err := agentpacket.DecodeJSON(raw)
	if err != nil {
		return agentpacketseal.RecipientKey{}, agentpacketseal.KeyCard{}, agentcarrier.ErrRefused
	}
	if err := c.sender(packet.SenderAgentID); err != nil {
		return agentpacketseal.RecipientKey{}, agentpacketseal.KeyCard{}, err
	}
	key, card, err := agentpacketseal.VerifyKeyCard(ctx, c.verifier, c.resolver, packet, now)
	if err != nil {
		return agentpacketseal.RecipientKey{}, agentpacketseal.KeyCard{}, errors.Join(agentcarrier.ErrRefused, err)
	}
	return key, card, nil
}
