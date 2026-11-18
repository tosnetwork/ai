package buyersdk

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal/keycardtest"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
)

const cardController = "provider-packet"

// cardFixture is a buyer fixture whose provider Agent has one controller
// that signs its key cards.
func cardFixture(t *testing.T) *buyerFixture {
	t.Helper()
	fixture := newBuyerFixture(t, defaultLimits())
	fixture.chain.agent.State = &nativev1.NativeStateV1_Agent{Agent: keycardtest.Agent(saAgent, cardController)}
	return fixture
}

func providerCard(t *testing.T, agent, controller string) []byte {
	t.Helper()
	start := uint64(saNow.Add(-time.Hour).Unix())
	return keycardtest.JSON(t, keycardtest.Spec{AgentID: agent, Controller: controller, Seed: 9,
		NotBeforeUnix: start, NotAfterUnix: start + 7*24*3600})
}

func TestAProviderCardOfTheCapabilityOwnerIsVerifiedFromEverySource(t *testing.T) {
	fixture := cardFixture(t)
	raw := providerCard(t, saAgent, cardController)
	for _, source := range []ProviderCardSource{ProviderCardFromOffer, ProviderCardFromQuote, ProviderCardFromResult} {
		card, err := fixture.buyer.VerifyProviderCard(context.Background(), keycardtest.Keys, source, saCapability, raw)
		if err != nil {
			t.Fatalf("%s: %v", source, err)
		}
		if card.Source != source || card.Key.AgentID != saAgent || card.CapabilityID != saCapability ||
			!bytes.Equal(card.PacketJSON, raw) || !card.VerifiedAt.Equal(saNow) || card.Checkpoint == 0 {
			t.Fatalf("%s: verified card %+v", source, card)
		}
		if err := card.UsableAt(saNow); err != nil {
			t.Fatalf("%s: a freshly verified card is not usable: %v", source, err)
		}
	}
}

func TestAProviderCardIsUsableOnlyForTenMinutesAfterItsVerification(t *testing.T) {
	fixture := cardFixture(t)
	card, err := fixture.buyer.VerifyProviderCard(context.Background(), keycardtest.Keys, ProviderCardFromQuote, saCapability,
		providerCard(t, saAgent, cardController))
	if err != nil {
		t.Fatal(err)
	}
	if err := card.UsableAt(saNow.Add(ProviderCardReverifyAfter)); err != nil {
		t.Fatalf("a card at the end of its verification window was refused: %v", err)
	}
	for name, at := range map[string]time.Time{
		"after ten minutes":           saNow.Add(ProviderCardReverifyAfter + time.Second),
		"before its verification":     saNow.Add(-time.Second),
		"never verified (zero value)": saNow,
	} {
		subject := card
		if name == "never verified (zero value)" {
			subject = VerifiedProviderCard{Card: card.Card}
		}
		if err := subject.UsableAt(at); !errors.Is(err, ErrProviderCard) {
			t.Errorf("%s: the card was usable: %v", name, err)
		}
	}
	if ProviderCardReverifyAfter != 10*time.Minute {
		t.Fatal("the re-verification window is the relay's 10 minutes")
	}
}

// A card that expires inside the verification window is unusable from its
// own not_after on: a recent verification never extends a card.
func TestAProviderCardIsUnusableAfterItsOwnExpiryEvenWhenRecentlyVerified(t *testing.T) {
	fixture := cardFixture(t)
	start := uint64(saNow.Add(-time.Hour).Unix())
	end := uint64(saNow.Add(5 * time.Minute).Unix())
	card, err := fixture.buyer.VerifyProviderCard(context.Background(), keycardtest.Keys, ProviderCardFromQuote, saCapability,
		keycardtest.JSON(t, keycardtest.Spec{AgentID: saAgent, Controller: cardController, Seed: 9,
			NotBeforeUnix: start, NotAfterUnix: end}))
	if err != nil {
		t.Fatal(err)
	}
	if err := card.UsableAt(saNow.Add(4 * time.Minute)); err != nil {
		t.Fatalf("a card before its not_after was refused: %v", err)
	}
	if err := card.UsableAt(time.Unix(int64(end), 0)); !errors.Is(err, ErrProviderCard) {
		t.Fatalf("a card at its not_after was usable: %v", err)
	}
}

func TestAProviderCardThatIsNotTheOwnersIsRefused(t *testing.T) {
	other := "agent_" + strings.Repeat("66", 32)
	cases := map[string]func(*buyerFixture) []byte{
		// A finalized, live Agent signing its own card is still not the
		// Capability's owner.
		"another live Agent's own card": func(f *buyerFixture) []byte {
			f.chain.others = map[string]*nativev1.NativeStateV1{other: {Network: f.chain.agent.Network,
				State: &nativev1.NativeStateV1_Agent{Agent: keycardtest.Agent(other, cardController)}}}
			return providerCard(t, other, cardController)
		},
		"a Capability state of another object": func(f *buyerFixture) []byte {
			f.chain.capability.GetCapability().CapabilityId = "cap_" + strings.Repeat("99", 32)
			return providerCard(t, saAgent, cardController)
		},
		"an owner state of another Agent": func(f *buyerFixture) []byte {
			f.chain.agent.GetAgent().AgentId = other
			return providerCard(t, saAgent, cardController)
		},
		"an owner state that is not an Agent": func(f *buyerFixture) []byte {
			f.chain.agent.State = &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{CapabilityId: saCapability}}
			return providerCard(t, saAgent, cardController)
		},
		"a controller outside the owner's finalized policy": func(f *buyerFixture) []byte {
			return providerCard(t, saAgent, "removed-controller")
		},
		"a tombstoned owner": func(f *buyerFixture) []byte {
			f.chain.agent.GetAgent().Tombstoned = true
			return providerCard(t, saAgent, cardController)
		},
		"a tombstoned Capability": func(f *buyerFixture) []byte {
			f.chain.capability.GetCapability().Tombstoned = true
			return providerCard(t, saAgent, cardController)
		},
		"an owner state of another network": func(f *buyerFixture) []byte {
			f.chain.agent.Network = &nativev1.NetworkDomain{NetworkId: "other"}
			return providerCard(t, saAgent, cardController)
		},
		"a Capability state of another network": func(f *buyerFixture) []byte {
			f.chain.capability.Network = &nativev1.NetworkDomain{NetworkId: "other"}
			return providerCard(t, saAgent, cardController)
		},
		"an expired card": func(f *buyerFixture) []byte {
			start := uint64(saNow.Add(-8 * 24 * time.Hour).Unix())
			return keycardtest.JSON(t, keycardtest.Spec{AgentID: saAgent, Controller: cardController, Seed: 9,
				NotBeforeUnix: start, NotAfterUnix: start + 7*24*3600})
		},
		"an empty card": func(f *buyerFixture) []byte { return nil },
		"not a packet":  func(f *buyerFixture) []byte { return []byte("{}") },
		"over the card bound": func(f *buyerFixture) []byte {
			return append(bytes.Repeat([]byte{' '}, quoteexchange.MaxProviderKeyCardBytes), providerCard(t, saAgent, cardController)...)
		},
	}
	for name, build := range cases {
		fixture := cardFixture(t)
		raw := build(fixture)
		if _, err := fixture.buyer.VerifyProviderCard(context.Background(), keycardtest.Keys, ProviderCardFromQuote,
			saCapability, raw); err == nil {
			t.Errorf("%s: the card was verified", name)
		}
	}
}

func TestAProviderCardForAnUnknownCapabilityOrSourceIsRefused(t *testing.T) {
	fixture := cardFixture(t)
	raw := providerCard(t, saAgent, cardController)
	if _, err := fixture.buyer.VerifyProviderCard(context.Background(), keycardtest.Keys, ProviderCardFromQuote,
		"cap_"+strings.Repeat("99", 32), raw); !errors.Is(err, ErrProviderCard) {
		t.Fatalf("a card for a Capability not in finalized state was verified: %v", err)
	}
	if _, err := fixture.buyer.VerifyProviderCard(context.Background(), keycardtest.Keys, "gateway", saCapability, raw); !errors.Is(err, ErrProviderCard) {
		t.Fatalf("a card from an unknown source was verified: %v", err)
	}
	if _, err := fixture.buyer.VerifyProviderCard(context.Background(), nil, ProviderCardFromQuote, saCapability, raw); err == nil {
		t.Fatal("a card was verified without a verifier")
	}
}

func TestAnAgentsOwnCardVerifiesOnlyForThatLiveAgent(t *testing.T) {
	fixture := cardFixture(t)
	raw := providerCard(t, saAgent, cardController)
	key, card, err := fixture.buyer.VerifyAgentCard(context.Background(), keycardtest.Keys, saAgent, raw)
	if err != nil || key.AgentID != saAgent || card.NotAfterUnix == 0 {
		t.Fatalf("own card: %+v %v", key, err)
	}
	other := "agent_" + strings.Repeat("66", 32)
	if _, _, err := fixture.buyer.VerifyAgentCard(context.Background(), keycardtest.Keys, other, raw); !errors.Is(err, ErrAgentCard) {
		t.Fatalf("a card verified for another Agent: %v", err)
	}
	if _, _, err := fixture.buyer.VerifyAgentCard(context.Background(), keycardtest.Keys, saAgent,
		providerCard(t, saAgent, "removed-controller")); !errors.Is(err, ErrAgentCard) {
		t.Fatalf("a card of a controller outside the policy: %v", err)
	}
	if _, _, err := fixture.buyer.VerifyAgentCard(context.Background(), keycardtest.Keys, saAgent, []byte("{}")); !errors.Is(err, ErrAgentCard) {
		t.Fatalf("not a packet: %v", err)
	}
	if _, _, err := fixture.buyer.VerifyAgentCard(context.Background(), nil, saAgent, raw); err == nil {
		t.Fatal("a card verified without a verifier")
	}
	fixture.chain.agent.GetAgent().Tombstoned = true
	if _, _, err := fixture.buyer.VerifyAgentCard(context.Background(), keycardtest.Keys, saAgent, raw); !errors.Is(err, ErrAgentCard) {
		t.Fatalf("a tombstoned Agent's card: %v", err)
	}
}
