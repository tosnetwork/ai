package agentpacketseal

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44/mldsa44test"
)

type resolver map[string]*nativev1.AgentStateV1

func (r resolver) ResolveAgent(id string) (*nativev1.AgentStateV1, bool, error) {
	value, ok := r[id]
	return value, ok, nil
}

var fakeKeys = &mldsa44test.Fake{}

func controllerKeyID(t *testing.T, name string) [mldsa44.KeyIDSize]byte {
	t.Helper()
	id, err := mldsa44.ParseKeyIDText(fakeKeys.KeyID(name))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func liveAgent(id, controller string) *nativev1.AgentStateV1 {
	return &nativev1.AgentStateV1{AgentId: id, Policy: &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1,
		Controllers: []*nativev1.ControllerV1{{KeyId: fakeKeys.KeyID(controller),
			Mldsa44PublicKey: fakeKeys.PublicKey(controller), Weight: 1, PurposeMask: 15, Recovery: true}}}}
}

func testCard(t *testing.T, seed byte) KeyCard {
	t.Helper()
	_, public := keyPair(t, agentOf("11"), seed)
	return KeyCard{PublicKey: public.PublicKey, KeyID: public.KeyID, NotBeforeUnix: 1_000_000,
		NotAfterUnix: 1_000_000 + 7*24*3600, Relays: []string{"https://relay-a.example", "https://relay-b.example/mailbox"}}
}

func signedCard(t *testing.T, agentID, controller string, card KeyCard) agentpacket.Packet {
	t.Helper()
	packet, err := KeyCardPacket(agentID, controllerKeyID(t, controller), 1, [32]byte{1}, 1_000_000, card)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := agentpacket.Sign(context.Background(), fakeKeys, controller, packet)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestKeyCardRoundTripIsCanonical(t *testing.T) {
	card := testCard(t, 1)
	body, err := EncodeKeyCard(card)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeKeyCard(body)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EncodeKeyCard(decoded)
	if err != nil || string(again) != string(body) {
		t.Fatal("key card body does not re-encode to the same bytes")
	}
	if _, err := DecodeKeyCard(append(append([]byte(nil), body...), 0)); !errors.Is(err, ErrKeyCard) {
		t.Fatal("trailing byte accepted")
	}
	if _, err := DecodeKeyCard(body[:len(body)-1]); !errors.Is(err, ErrKeyCard) {
		t.Fatal("truncated body accepted")
	}
}

func TestKeyCardRejectsOutOfBounds(t *testing.T) {
	mutate := func(change func(*KeyCard)) KeyCard {
		card := testCard(t, 1)
		card.Relays = append([]string(nil), card.Relays...)
		change(&card)
		return card
	}
	cases := map[string]KeyCard{
		"key ID of another key": mutate(func(c *KeyCard) { c.KeyID[0] ^= 1 }),
		"short key":             mutate(func(c *KeyCard) { c.PublicKey = c.PublicKey[:10] }),
		"zero not before":       mutate(func(c *KeyCard) { c.NotBeforeUnix = 0 }),
		"empty window":          mutate(func(c *KeyCard) { c.NotAfterUnix = c.NotBeforeUnix }),
		"lifetime over 30 days": mutate(func(c *KeyCard) { c.NotAfterUnix = c.NotBeforeUnix + 30*24*3600 + 1 }),
		"no relay":              mutate(func(c *KeyCard) { c.Relays = nil }),
		"five relays": mutate(func(c *KeyCard) {
			c.Relays = []string{"https://a.example", "https://b.example", "https://c.example", "https://d.example",
				"https://e.example"}
		}),
		"unsorted relays":    mutate(func(c *KeyCard) { c.Relays[0], c.Relays[1] = c.Relays[1], c.Relays[0] }),
		"duplicate relay":    mutate(func(c *KeyCard) { c.Relays[1] = c.Relays[0] }),
		"plain http":         mutate(func(c *KeyCard) { c.Relays = []string{"http://relay.example"} }),
		"query":              mutate(func(c *KeyCard) { c.Relays = []string{"https://relay.example?token=x"} }),
		"empty query":        mutate(func(c *KeyCard) { c.Relays = []string{"https://relay.example?"} }),
		"fragment":           mutate(func(c *KeyCard) { c.Relays = []string{"https://relay.example#x"} }),
		"user information":   mutate(func(c *KeyCard) { c.Relays = []string{"https://user@relay.example"} }),
		"trailing slash":     mutate(func(c *KeyCard) { c.Relays = []string{"https://relay.example/"} }),
		"uppercase host":     mutate(func(c *KeyCard) { c.Relays = []string{"https://Relay.example"} }),
		"space":              mutate(func(c *KeyCard) { c.Relays = []string{"https://relay.example/a b"} }),
		"escaped path":       mutate(func(c *KeyCard) { c.Relays = []string{"https://relay.example/a%2Fb"} }),
		"escaped space":      mutate(func(c *KeyCard) { c.Relays = []string{"https://relay.example/a%20b"} }),
		"escaped percent":    mutate(func(c *KeyCard) { c.Relays = []string{"https://relay.example/a%25b"} }),
		"escaped quote":      mutate(func(c *KeyCard) { c.Relays = []string{"https://relay.example/%22"} }),
		"escaped unreserved": mutate(func(c *KeyCard) { c.Relays = []string{"https://relay.example/%41"} }),
		"escaped zone":       mutate(func(c *KeyCard) { c.Relays = []string{"https://[fe80::1%25eth0]"} }),
		"relative":           mutate(func(c *KeyCard) { c.Relays = []string{"relay.example"} }),
		"over 256 bytes":     mutate(func(c *KeyCard) { c.Relays = []string{"https://relay.example/" + strings.Repeat("a", 235)} }),
		"non-ascii host":     mutate(func(c *KeyCard) { c.Relays = []string{"https://relayé.example"} }),
		"another scheme":     mutate(func(c *KeyCard) { c.Relays = []string{"ftp://relay.example"} }),
		"opaque":             mutate(func(c *KeyCard) { c.Relays = []string{"https:relay.example"} }),
		"loopback with tls":  mutate(func(c *KeyCard) { c.Relays = []string{"http://127.0.0.2:8080"} }),
	}
	for name, card := range cases {
		if _, err := EncodeKeyCard(card); !errors.Is(err, ErrKeyCard) && !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s: encoded (%v)", name, err)
		}
	}
	for _, good := range []string{"http://127.0.0.1:8080", "http://localhost:9", "http://[::1]:7", "https://relay.example:8443/a/b"} {
		card := mutate(func(c *KeyCard) { c.Relays = []string{good} })
		if _, err := EncodeKeyCard(card); err != nil {
			t.Fatalf("%s refused: %v", good, err)
		}
	}
	thirtyDays := mutate(func(c *KeyCard) { c.NotAfterUnix = c.NotBeforeUnix + 30*24*3600 })
	if _, err := EncodeKeyCard(thirtyDays); err != nil {
		t.Fatalf("a 30-day card was refused: %v", err)
	}
}

func TestKeyCardTimeWindow(t *testing.T) {
	card := testCard(t, 1)
	at := func(unix int64) error { return CheckKeyCardTime(card, time.Unix(unix, 0)) }
	if at(1_000_000-300) != nil || at(1_000_000) != nil || at(int64(card.NotAfterUnix)-1) != nil {
		t.Fatal("a valid time was refused")
	}
	if at(1_000_000-301) == nil || at(int64(card.NotAfterUnix)) == nil || CheckKeyCardTime(card, time.Time{}) == nil {
		t.Fatal("a time outside the window was accepted")
	}
}

func TestVerifyKeyCard(t *testing.T) {
	ctx := context.Background()
	agentID := agentOf("11")
	states := resolver{agentID: liveAgent(agentID, "card")}
	now := time.Unix(1_000_100, 0)
	card := testCard(t, 1)
	packet := signedCard(t, agentID, "card", card)
	key, decoded, err := VerifyKeyCard(ctx, fakeKeys, states, packet, now)
	if err != nil {
		t.Fatal(err)
	}
	if key.AgentID != agentID || key.KeyID != card.KeyID || string(key.PublicKey) != string(card.PublicKey) ||
		len(decoded.Relays) != 2 {
		t.Fatal("verified card differs")
	}
	// A key card is never a deliverable packet: the all-zero audience is no
	// finalized Agent.
	if err := agentpacket.Verify(ctx, fakeKeys, states, &agentpacket.ReplayGuard{}, packet, now); err == nil {
		t.Fatal("a key card verified as a delivery")
	}
	wire, err := agentpacket.EncodeJSON(packet)
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip, err := agentpacket.DecodeJSON(wire); err != nil {
		t.Fatal(err)
	} else if _, _, err := VerifyKeyCard(ctx, fakeKeys, states, roundTrip, now); err != nil {
		t.Fatalf("card from its JSON: %v", err)
	}

	tampered := packet
	tampered.Payload = append([]byte(nil), packet.Payload...)
	tampered.Payload[len(tampered.Payload)-1] ^= 1
	if _, _, err := VerifyKeyCard(ctx, fakeKeys, states, tampered, now); err == nil {
		t.Fatal("tampered body accepted")
	}
	if _, _, err := VerifyKeyCard(ctx, fakeKeys, resolver{agentID: liveAgent(agentID, "other")}, packet, now); err == nil {
		t.Fatal("card by a controller outside the finalized policy accepted")
	}
	tombstoned := liveAgent(agentID, "card")
	tombstoned.Tombstoned = true
	if _, _, err := VerifyKeyCard(ctx, fakeKeys, resolver{agentID: tombstoned}, packet, now); err == nil {
		t.Fatal("card of a tombstoned Agent accepted")
	}
	if _, _, err := VerifyKeyCard(ctx, fakeKeys, states, packet, time.Unix(int64(card.NotAfterUnix), 0)); err == nil {
		t.Fatal("expired card accepted")
	}
	addressed := packet
	addressed.RecipientAgentID = agentOf("22")
	if _, _, err := VerifyKeyCard(ctx, fakeKeys, states, addressed, now); !errors.Is(err, ErrKeyCard) {
		t.Fatal("card to a live recipient accepted")
	}
	capability := packet
	capability.CapabilityID = "cap_" + strings.Repeat("33", 32)
	if _, _, err := VerifyKeyCard(ctx, fakeKeys, states, capability, now); !errors.Is(err, ErrKeyCard) {
		t.Fatal("card under a Capability accepted")
	}
	quoted := packet
	quoted.QuoteCommitment = "sha256:" + strings.Repeat("44", 32)
	if _, _, err := VerifyKeyCard(ctx, fakeKeys, states, quoted, now); !errors.Is(err, ErrKeyCard) {
		t.Fatal("card with a Quote commitment accepted")
	}
	// A delivered packet whose payload is a key card body is refused as a
	// card: the audience decides, not the payload.
	delivered, err := agentpacket.Sign(ctx, fakeKeys, "card", agentpacket.Packet{SenderAgentID: agentID,
		RecipientAgentID: agentOf("22"), CapabilityID: KeyCardCapability, Sequence: 1, Nonce: [32]byte{2},
		Payload: packet.Payload, CreatedAtUnix: 1_000_000, SenderKeyID: controllerKeyID(t, "card")})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyKeyCard(ctx, fakeKeys, states, delivered, now); !errors.Is(err, ErrKeyCard) {
		t.Fatal("a delivered packet was taken for a key card")
	}
	if _, err := KeyCardPacket(KeyCardAudience, controllerKeyID(t, "card"), 1, [32]byte{1}, 1, card); err == nil {
		t.Fatal("a card from the audience Agent was built")
	}
}
