// Package keycardtest builds signed encryption key card packets for tests.
// Its cards are signed by mldsa44test.Fake, which only Fake accepts; it is
// never a source of real cards.
package keycardtest

import (
	"bytes"
	"context"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44/mldsa44test"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

// Keys signs and verifies every card this package builds.
var Keys = &mldsa44test.Fake{}

// Spec names one card.
type Spec struct {
	AgentID    string
	Controller string
	// Seed is repeated into the 32-byte HPKE private key seed.
	Seed          byte
	NotBeforeUnix uint64
	NotAfterUnix  uint64
	Relays        []string
}

// Card returns the key card body Spec describes.
func Card(t testing.TB, spec Spec) agentpacketseal.KeyCard {
	t.Helper()
	private, err := agentpacketseal.NewPrivateKey(spec.AgentID, bytes.Repeat([]byte{spec.Seed}, agentpacketseal.PrivateKeySize))
	if err != nil {
		t.Fatal(err)
	}
	public, err := private.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	relays := spec.Relays
	if relays == nil {
		relays = []string{"https://relay.example"}
	}
	return agentpacketseal.KeyCard{PublicKey: public, KeyID: private.KeyID, NotBeforeUnix: spec.NotBeforeUnix,
		NotAfterUnix: spec.NotAfterUnix, Relays: relays}
}

// Packet returns the signed key card packet Spec describes.
func Packet(t testing.TB, spec Spec) agentpacket.Packet {
	t.Helper()
	signerKeyID, err := mldsa44.ParseKeyIDText(Keys.KeyID(spec.Controller))
	if err != nil {
		t.Fatal(err)
	}
	packet, err := agentpacketseal.KeyCardPacket(spec.AgentID, signerKeyID, 1, [32]byte{spec.Seed, 1},
		spec.NotBeforeUnix, Card(t, spec))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := agentpacket.Sign(context.Background(), Keys, spec.Controller, packet)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// JSON returns the signed key card packet Spec describes as Agent Packet
// JSON.
func JSON(t testing.TB, spec Spec) []byte {
	t.Helper()
	raw, err := agentpacket.EncodeJSON(Packet(t, spec))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Sign signs an arbitrary packet as controller, for tests that need a
// signed packet of another shape than a key card.
func Sign(t testing.TB, controller string, packet agentpacket.Packet) []byte {
	t.Helper()
	signed, err := agentpacket.Sign(context.Background(), Keys, controller, packet)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := agentpacket.EncodeJSON(signed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Agent returns the live finalized state of an Agent whose one controller is
// controller.
func Agent(agentID, controller string) *nativev1.AgentStateV1 {
	return &nativev1.AgentStateV1{EncodingVersion: nativecore.StateEncodingVersion, AuthorizationEpoch: 1, AgentId: agentID, Policy: &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1,
		Controllers: []*nativev1.ControllerV1{{KeyId: Keys.KeyID(controller),
			Mldsa44PublicKey: Keys.PublicKey(controller), Weight: 1, PurposeMask: 15, Recovery: true}}}}
}
