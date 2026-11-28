package agentcarrier

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

func await(t testing.TB, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		t.Fatal("carrier did not reach the controlled barrier")
	}
}
func TestCardSigningDoesNotBlockPolling(t *testing.T) {
	f := newFixture(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	sign := f.lane.config.SignCard
	f.lane.config.SignCard = func(ctx context.Context, card agentpacketseal.KeyCard) ([]byte, error) {
		close(entered)
		<-release
		return sign(ctx, card)
	}
	var cardErr error
	go func() { defer close(done); _, cardErr = f.lane.CurrentCard(t.Context()) }()
	defer func() {
		close(release)
		await(t, done)
		if cardErr != nil {
			t.Error(cardErr)
		}
	}()
	await(t, entered)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	v, err := f.lane.Poll(ctx)
	if err != nil || v.Listed != 2 {
		t.Fatal("card signer held the polling key gate", v, err)
	}
}
func TestWithdrawingOwnAuthorityWhileSigningReturnsNoCard(t *testing.T) {
	f := newFixture(t)
	sign := f.lane.config.SignCard
	f.lane.config.SignCard = func(ctx context.Context, card agentpacketseal.KeyCard) ([]byte, error) {
		f.resolver.mu.Lock()
		f.resolver.state[f.alice.agent].State.GetAgent().DelegationDigests = nil
		f.resolver.mu.Unlock()
		f.clock.n.Add(300)
		return sign(ctx, card)
	}
	card, err := f.lane.CurrentCard(t.Context())
	if !errors.Is(err, ErrTransportRevoked) || len(card.Packet) != 0 {
		t.Fatal("card escaped after transport authority failed", err)
	}
	index, err := f.lane.inventory()
	if err != nil || len(index.Keys) != 0 {
		t.Fatal("withdrawn issuer persisted a new key", err)
	}
}
func TestOneWaitDoesNotBlockPlainPolling(t *testing.T) {
	f := newFixture(t)
	r := f.relays[relayOne]
	r.waitEntered = make(chan struct{})
	r.waitRelease = make(chan struct{})
	done := make(chan struct{})
	var waitErr error
	go func() { defer close(done); _, waitErr = f.lane.Wait(t.Context(), relayOne, 25) }()
	defer func() {
		close(r.waitRelease)
		await(t, done)
		if waitErr != nil {
			t.Error(waitErr)
		}
	}()
	await(t, r.waitEntered)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := f.lane.Wait(ctx, relayOne, 25); !errors.Is(err, ErrCapacity) {
		t.Fatal("second waiting request was not refused", err)
	}
	v, err := f.lane.Poll(ctx)
	if err != nil || v.Listed != 2 {
		t.Fatal("long polling blocked plain polling", v, err)
	}
	for _, bad := range []int{0, 26} {
		if _, err := f.lane.Wait(t.Context(), relayOne, bad); !errors.Is(err, ErrConfig) {
			t.Fatal("invalid wait", bad, err)
		}
	}
	if _, err := f.lane.Wait(t.Context(), "https://127.0.0.1/not-owned", 25); !errors.Is(err, ErrCapacity) {
		t.Fatal("concurrent wait not bounded", err)
	}
}
func TestPollPrefersContactEntriesAndBoundsDownloads(t *testing.T) {
	f := newFixture(t)
	card, err := f.lane.CurrentCard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r := f.relays[relayOne]
	r.entries = []agentpacketrelay.V2MailboxEntry{}
	contacts := map[[32]byte]bool{}
	for i := 0; i < 33; i++ {
		var secret [32]byte
		secret[0] = byte(i + 1)
		raw, err := agentpacketseal.Seal(agentpacketseal.RecipientKey{AgentID: f.alice.agent, KeyID: card.Card.KeyID, PublicKey: card.Card.PublicKey}, secret, f.message(f.bob, f.alice), start+3600)
		if err != nil {
			t.Fatal(err)
		}
		h, err := agentpacketseal.ParseEnvelope(raw)
		if err != nil {
			t.Fatal(err)
		}
		putEnvelope(t, r, raw)
		lane := "stranger"
		if i >= 17 {
			lane = "contact"
			contacts[h.EnvelopeID] = true
		}
		r.entries = append(r.entries, agentpacketrelay.V2MailboxEntry{EnvelopeID: h.EnvelopeID, RecipientKeyID: h.RecipientKeyID, Size: uint32(len(raw)), ReceivedAtUnix: start, ExpiresAtUnix: start + 3600, Lane: lane})
	}
	if _, err = f.lane.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if r.fetches != 16 {
		t.Fatal("download pass exceeded its bound", r.fetches)
	}
	for _, id := range r.fetched {
		if !contacts[id] {
			t.Fatal("a stranger displaced a contact in the pass")
		}
	}
}
