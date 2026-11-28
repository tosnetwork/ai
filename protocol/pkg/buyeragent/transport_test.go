package buyeragent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentcarrier"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"google.golang.org/protobuf/proto"
)

func (c relayClient) ListWait(ctx context.Context, agent string, credential []byte, key ed25519.PrivateKey, _ int) ([]agentpacketrelay.V2MailboxEntry, error) {
	return c.List(ctx, agent, credential, key)
}

func (c relayClient) PublishPolicy(context.Context, string, agentpacketrelay.MailboxPolicy, []byte, ed25519.PrivateKey) error {
	return nil
}

type testTransportResolver map[string]agenttransport.Snapshot

func (r testTransportResolver) ResolveFinalizedAgent(_ context.Context, agent string) (agenttransport.Snapshot, error) {
	return r[agent], nil
}

type testTransportLocator struct{}

func (testTransportLocator) Locate(string, string) (string, error) { return "0:test", nil }

type testDirectory struct {
	clock      *clock
	delegation agenttransport.Delegation
	key        ed25519.PrivateKey
	relays     []string
}

func (d *testDirectory) record() ([]byte, error) {
	now := uint64(d.clock.Now().Unix())
	hint, err := agenttransport.SignHint(agenttransport.Hint{
		Delegation: d.delegation, IssuedAt: now, ExpiresAt: now + 3600, Relays: d.relays,
	}, d.key)
	if err != nil {
		return nil, err
	}
	return (agenttransport.HintRecord{Hint: hint}).Encode()
}

func (d *testDirectory) HintIndex(_ context.Context, agent string) ([]agentpacketrelay.HintIndexEntry, error) {
	if agent != d.delegation.AgentID() || len(d.relays) == 0 {
		return nil, nil
	}
	raw, err := d.record()
	if err != nil {
		return nil, err
	}
	wire, err := d.delegation.Encode()
	if err != nil {
		return nil, err
	}
	return []agentpacketrelay.HintIndexEntry{{Digest: sha256.Sum256(wire), IssuedAt: uint64(d.clock.Now().Unix()), Length: uint32(len(raw))}}, nil
}

func (d *testDirectory) HintRecord(context.Context, string, [32]byte) ([]byte, error) {
	return d.record()
}

func (*testDirectory) PublishHint(context.Context, []byte) error { return nil }

func fakeTransport(t *testing.T, chain *fakeChain, relays *fakeRelay) TransportConfig {
	t.Helper()
	network := &nativev1.NetworkDomain{NetworkId: "tos:global-id:3",
		GenesisRootHash: "65735247a371030abe811aeac0afe357301ce90e161450d26f88b4beb5b4c366",
		GenesisFileHash: "c3860fe196a2a1b5e4e74a9cf9448624a353ce68a8c4c5f6413347586d688769"}
	code := "tvm-cell-sha256:" + fmt.Sprintf("%064x", 3)
	states := testTransportResolver{}
	makeIdentity := func(id string) (agenttransport.Delegation, []byte, ed25519.PrivateKey) {
		seed := sha256.Sum256([]byte(id))
		key := ed25519.NewKeyFromSeed(seed[:])
		agent := proto.Clone(chain.agents[id]).(*nativev1.AgentStateV1)
		cell, err := nativecore.PolicyCell(agent.Policy)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := agentpacketseal.AgentDigest(id)
		if err != nil {
			t.Fatal(err)
		}
		now := uint64(chain.clock.Now().Unix())
		delegation := agenttransport.Delegation{AgentDigest: digest, Purposes: agenttransport.Relay | agenttransport.Hints,
			NotBefore: now - 7200, NotAfter: now + 100*86400, MaxCredentialSeconds: 604800}
		copy(delegation.PolicyHash[:], cell.Hash())
		copy(delegation.TransportKey[:], key[32:])
		wire, err := delegation.Encode()
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(wire)
		agent.DelegationDigests = []string{"sha256:" + hex.EncodeToString(hash[:])}
		states[id] = agenttransport.Snapshot{State: &nativev1.NativeStateV1{Network: network,
			TvmStateHash: "tvm-cell-sha256:" + fmt.Sprintf("%064x", 4),
			Reference:    &nativev1.ChainReference{FinalizedCheckpoint: 10, Account: "0:test", ContractCodeHash: code, TransactionHash: "sha256:" + fmt.Sprintf("%064x", 5)},
			State:        &nativev1.NativeStateV1_Agent{Agent: agent}}}
		return delegation, wire, key
	}
	_, wire, key := makeIdentity(fxBuyerAgent)
	peer, _, peerKey := makeIdentity(fxProvider)
	verifier, err := agenttransport.NewVerifier(agenttransport.Config{Mode: agenttransport.TestNetworkLegacyEpochZero, Network: network,
		ChainPolicy: agenttransport.ChainPolicy{RegistryCodeHashes: []string{code}, Locator: testTransportLocator{}}, Clock: chain.clock}, states)
	if err != nil {
		t.Fatal(err)
	}
	directory := &testDirectory{clock: chain.clock, delegation: peer, key: peerKey, relays: []string{providerRelay}}
	relays.directory = directory
	return TransportConfig{Delegation: wire, Key: key, Verifier: verifier, Relay: relays.client,
		Directories: []string{buyerRelay, providerRelay}, Directory: func(string) (agentcarrier.Directory, error) { return directory, nil }}
}

// heldTestKeys inspects the rail lane's durable keys for the envelope fixtures.
func (c *Carrier) heldTestKeys() ([]agentpacketseal.PrivateKey, []agentpacketseal.KeyCard, error) {
	path := filepath.Join(c.config.StateDir, "rail")
	files, err := os.ReadDir(path)
	if err != nil {
		return nil, nil, err
	}
	var keys []agentpacketseal.PrivateKey
	var cards []agentpacketseal.KeyCard
	for _, file := range files {
		if len(file.Name()) != 68 || file.Name()[:4] != "key-" {
			continue
		}
		var stored struct {
			Value json.RawMessage `json:"data"`
		}
		raw, err := os.ReadFile(filepath.Join(path, file.Name()))
		if err != nil {
			return nil, nil, err
		}
		if err := json.Unmarshal(raw, &stored); err != nil {
			return nil, nil, err
		}
		var record struct {
			Seed   []byte
			Packet []byte
		}
		if err := json.Unmarshal(stored.Value, &record); err != nil {
			return nil, nil, err
		}
		key, err := agentpacketseal.NewPrivateKey(c.config.BuyerAgentID, record.Seed)
		if err != nil {
			return nil, nil, err
		}
		packet, err := agentpacket.DecodeJSON(record.Packet)
		if err != nil {
			return nil, nil, err
		}
		card, err := agentpacketseal.DecodeKeyCard(packet.Payload)
		if err != nil {
			return nil, nil, err
		}
		keys = append(keys, key)
		cards = append(cards, card)
	}
	return keys, cards, nil
}
