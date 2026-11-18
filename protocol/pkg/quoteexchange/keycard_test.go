package quoteexchange

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal/keycardtest"
)

const (
	cardProvider = "agent_" + "11111111111111111111111111111111" + "11111111111111111111111111111111"
	cardOther    = "agent_" + "22222222222222222222222222222222" + "22222222222222222222222222222222"
	cardStart    = uint64(1_900_000_000)
	cardEnd      = cardStart + 7*24*3600
)

func cardSpec() keycardtest.Spec {
	return keycardtest.Spec{AgentID: cardProvider, Controller: "provider-packet", Seed: 7,
		NotBeforeUnix: cardStart, NotAfterUnix: cardEnd}
}

func cardNow() time.Time { return time.Unix(int64(cardStart)+3600, 0) }

func TestAProviderKeyCardOfTheProposalsProviderPasses(t *testing.T) {
	if err := CheckProviderKeyCard(keycardtest.JSON(t, cardSpec()), cardProvider, cardNow()); err != nil {
		t.Fatal(err)
	}
	// The validity window is the card's own: 300 s of skew before it, and
	// strictly before not_after.
	if err := CheckProviderKeyCard(keycardtest.JSON(t, cardSpec()), cardProvider,
		time.Unix(int64(cardStart)-300, 0)); err != nil {
		t.Fatal(err)
	}
}

func TestAProviderKeyCardOutsideItsBoundIsRefused(t *testing.T) {
	raw := keycardtest.JSON(t, cardSpec())
	if CheckProviderKeyCard(nil, cardProvider, cardNow()) == nil {
		t.Fatal("an empty card was accepted")
	}
	// Insignificant JSON whitespace keeps the packet decodable, so only the
	// byte bound refuses it.
	padded := append(bytes.Repeat([]byte{' '}, MaxProviderKeyCardBytes-len(raw)+1), raw...)
	if _, err := agentpacket.DecodeJSON(padded); err != nil {
		t.Fatalf("the padded card must still decode: %v", err)
	}
	if CheckProviderKeyCard(padded, cardProvider, cardNow()) == nil {
		t.Fatal("a card over the byte bound was accepted")
	}
	atBound := append(bytes.Repeat([]byte{' '}, MaxProviderKeyCardBytes-len(raw)), raw...)
	if err := CheckProviderKeyCard(atBound, cardProvider, cardNow()); err != nil {
		t.Fatalf("a card at the byte bound was refused: %v", err)
	}
	if CheckProviderKeyCard(raw, "", cardNow()) == nil {
		t.Fatal("a card was accepted for no provider")
	}
}

func TestAProviderKeyCardOfAnotherAgentIsRefused(t *testing.T) {
	spec := cardSpec()
	spec.AgentID = cardOther
	if CheckProviderKeyCard(keycardtest.JSON(t, spec), cardProvider, cardNow()) == nil {
		t.Fatal("another Agent's card was accepted for the provider")
	}
}

func TestAProviderKeyCardOutsideItsWindowIsRefused(t *testing.T) {
	raw := keycardtest.JSON(t, cardSpec())
	for name, now := range map[string]time.Time{
		"expired":      time.Unix(int64(cardEnd), 0),
		"not yet":      time.Unix(int64(cardStart)-301, 0),
		"zero clock":   {},
		"before epoch": time.Unix(-1, 0),
	} {
		if CheckProviderKeyCard(raw, cardProvider, now) == nil {
			t.Errorf("%s: a card outside its window was accepted", name)
		}
	}
}

func TestAPacketThatIsNotAKeyCardIsRefused(t *testing.T) {
	card := keycardtest.Packet(t, cardSpec())
	resign := func(change func(*agentpacket.Packet)) []byte {
		packet := card
		change(&packet)
		return keycardtest.Sign(t, "provider-packet", packet)
	}
	cases := map[string][]byte{
		"another audience":   resign(func(p *agentpacket.Packet) { p.RecipientAgentID = cardOther }),
		"another Capability": resign(func(p *agentpacket.Packet) { p.CapabilityID = "cap_" + strings.Repeat("3", 64) }),
		"a Quote commitment": resign(func(p *agentpacket.Packet) { p.QuoteCommitment = "sha256:" + strings.Repeat("4", 64) }),
		"a non-card body":    resign(func(p *agentpacket.Packet) { p.Payload = append([]byte("OFR1"), p.Payload...) }),
		"a trailing byte":    resign(func(p *agentpacket.Packet) { p.Payload = append(append([]byte(nil), p.Payload...), 0) }),
		"not JSON":           []byte("not a packet"),
	}
	for name, raw := range cases {
		if CheckProviderKeyCard(raw, cardProvider, cardNow()) == nil {
			t.Errorf("%s: accepted as a provider key card", name)
		}
	}
	// The fixed audience and Capability are what make a packet a card.
	if card.RecipientAgentID != agentpacketseal.KeyCardAudience || card.CapabilityID != agentpacketseal.KeyCardCapability {
		t.Fatal("the fixture is not a key card packet")
	}
}
