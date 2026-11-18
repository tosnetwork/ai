package nativegateway

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal/keycardtest"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"google.golang.org/protobuf/proto"
)

type fixedCard struct {
	raw []byte
	err error
}

func (c fixedCard) ProviderKeyCard() ([]byte, error) { return c.raw, c.err }

func cardNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{NetworkId: "test", GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
		GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
}

// cardOf returns a key card of agent valid from an hour before now for a
// week.
func cardOf(t *testing.T, agent string, now time.Time) []byte {
	t.Helper()
	start := uint64(now.Add(-time.Hour).Unix())
	return keycardtest.JSON(t, keycardtest.Spec{AgentID: agent, Controller: "provider-packet", Seed: 3,
		NotBeforeUnix: start, NotAfterUnix: start + 7*24*3600})
}

func quoteWithCard(t *testing.T, cards ProviderCardSource, now time.Time) (*nativev1.RequestQuoteProposalResponse, *nativev1.QuoteProposalPackageV1) {
	t.Helper()
	network := cardNetwork()
	value, msg := carriageQuote(t, network, 0)
	server := &Server{Authorizer: NewTokenAuthorizer("read-secret", "relay-secret"), QuoteSource: fixedQuote{value},
		ProviderCards: cards, Network: network, Now: func() time.Time { return now }}
	request := connect.NewRequest(msg)
	request.Header().Set("Authorization", "Bearer read-secret")
	response, err := server.RequestQuoteProposal(context.Background(), request)
	if err != nil {
		t.Fatalf("the Quote must be served whatever the card: %v", err)
	}
	return response.Msg, value
}

func TestTheGatewayServesTheProvidersKeyCardNextToTheQuote(t *testing.T) {
	now := time.Now()
	provider := "agent_" + strings.Repeat("55", 32)
	card := cardOf(t, provider, now)
	response, value := quoteWithCard(t, fixedCard{raw: card}, now)
	if !bytes.Equal(response.ProviderKeyCardPacketJson, card) {
		t.Fatal("the provider's valid card was not served next to the Quote")
	}
	if value.Proposal.ProviderAgentId != provider {
		t.Fatal("the fixture's provider is not the card's Agent")
	}
	// The card is next to the package, never in it: the package the buyer
	// carries in its task is the Quote source's, unchanged.
	if !proto.Equal(response.Package, value) {
		t.Fatal("the card changed the Quote package")
	}
}

func TestTheGatewayLeavesOutACardItCannotServe(t *testing.T) {
	now := time.Now()
	provider := "agent_" + strings.Repeat("55", 32)
	cases := map[string]ProviderCardSource{
		"no card source": nil,
		// A failed read is left out even when the source also returned
		// bytes that would pass the shape check.
		"unreadable":          fixedCard{raw: cardOf(t, provider, now), err: errors.New("card file changed while opening")},
		"another Agent":       fixedCard{raw: cardOf(t, "agent_"+strings.Repeat("66", 32), now)},
		"expired":             fixedCard{raw: cardOf(t, provider, now.Add(-8*24*time.Hour))},
		"not yet valid":       fixedCard{raw: cardOf(t, provider, now.Add(2*time.Hour))},
		"not a packet":        fixedCard{raw: []byte("{}")},
		"over the card bound": fixedCard{raw: append(bytes.Repeat([]byte{' '}, quoteexchange.MaxProviderKeyCardBytes), cardOf(t, provider, now)...)},
	}
	for name, cards := range cases {
		response, _ := quoteWithCard(t, cards, now)
		if len(response.ProviderKeyCardPacketJson) != 0 {
			t.Errorf("%s: the gateway served a card it must leave out", name)
		}
		if response.Package == nil {
			t.Errorf("%s: the Quote was not served", name)
		}
	}
}

// The served card is a copy: a source that reuses its buffer cannot change
// a response already handed out.
func TestTheServedCardIsACopy(t *testing.T) {
	now := time.Now()
	card := cardOf(t, "agent_"+strings.Repeat("55", 32), now)
	source := fixedCard{raw: card}
	response, _ := quoteWithCard(t, source, now)
	original := append([]byte(nil), card...)
	card[0] = 'X'
	if !bytes.Equal(response.ProviderKeyCardPacketJson, original) {
		t.Fatal("the served card aliases the source's buffer")
	}
}
