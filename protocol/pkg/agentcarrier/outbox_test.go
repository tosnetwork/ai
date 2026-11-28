package agentcarrier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
)

func TestJournalPrecedesDepositAndRestartReusesBytes(t *testing.T) {
	f := newFixture(t)
	route := f.peerRoute()
	raw := f.message(f.alice, f.bob)
	if _, err := f.lane.Queue(t.Context(), "delivery", raw, start+7200); err != nil {
		t.Fatal(err)
	}
	relay := f.relays[relayOne]
	relay.before = func(wire []byte) {
		r, err := f.lane.readDelivery(deliveryName("delivery"))
		if err != nil || len(r.Generations) == 0 {
			t.Fatalf("no durable envelope before send: %v", err)
		}
		g := r.Generations[len(r.Generations)-1]
		if !bytes.Equal(g.Envelope, wire) || len(g.Targets) == 0 || g.Targets[0].Attempts == 0 {
			t.Fatal("the exact attempt is not on disk")
		}
	}
	relay.error = ErrUnavailable
	relay.saveOnError = true
	if _, err := f.lane.Attempt(t.Context(), "delivery", route, 0); !errors.Is(err, ErrUnavailable) || len(relay.deposits) != 1 {
		t.Fatal("did not reach an ambiguous deposit", err, len(relay.deposits))
	}
	original := bytes.Clone(relay.deposits[0])
	if err := f.lane.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.lane, err = Open(t.Context(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	relay.error = nil
	result, err := f.lane.Attempt(t.Context(), "delivery", route, 0)
	if err != nil || !result.Accepted || len(relay.deposits) != 2 || !bytes.Equal(original, relay.deposits[1]) {
		t.Fatal("restart did not retry the durable bytes", result, err)
	}
	if _, err = f.lane.Queue(t.Context(), "delivery", append(bytes.Clone(raw), ' '), start+7200); !errors.Is(err, ErrConflict) {
		t.Fatal("idempotency conflict accepted", err)
	}
}
func TestNoRouteOrBadHintNeverUsesCardRelays(t *testing.T) {
	f := newFixture(t)
	route := f.peerRoute()
	if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
		t.Fatal(err)
	}
	if _, err := f.lane.Attempt(t.Context(), "id", Route{CardPacket: route.CardPacket}, 0); !errors.Is(err, ErrNoRoute) {
		t.Fatal(err)
	}
	v, err := f.lane.Status(t.Context(), "id")
	if err != nil || v.Generations != 0 || v.Code != "no-route" {
		t.Fatal(v, err)
	}
	bad := route
	bad.HintRecord = bytes.Clone(route.HintRecord)
	bad.HintRecord[len(bad.HintRecord)-1] ^= 1
	if _, err = f.lane.Attempt(t.Context(), "id", bad, 0); err == nil {
		t.Fatal("tampered hint used")
	}
	result, err := f.lane.Attempt(t.Context(), "id", route, 0)
	if err != nil || !result.Accepted || len(f.relays[relayOne].deposits) != 1 || len(f.relays[relayTwo].deposits) != 0 {
		t.Fatal("a card's unrelated relay list became a route", result, err)
	}
}
func TestJournalFailureCannotSend(t *testing.T) {
	f := newFixture(t)
	route := f.peerRoute()
	if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
		t.Fatal(err)
	}
	// An actual directory at the target refuses writes even for a privileged test.
	path := filepath.Join(f.config.StateDir, string(Rail), deliveryName("id"))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := f.lane.Attempt(t.Context(), "id", route, 0); err == nil {
		t.Fatal("unsafe journal target accepted")
	}
	if len(f.relays[relayOne].deposits) != 0 {
		t.Fatal("sent after a journal refusal")
	}
}
func TestNewValidCardDoesNotResealAnAmbiguousAttempt(t *testing.T) {
	f := newFixture(t)
	first, second := f.peerRoute(), f.peerRoute()
	if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
		t.Fatal(err)
	}
	f.relays[relayOne].error = ErrUnavailable
	if _, err := f.lane.Attempt(t.Context(), "id", first, 0); err == nil {
		t.Fatal("expected ambiguity")
	}
	original := bytes.Clone(f.relays[relayOne].deposits[0])
	if _, err := f.lane.Attempt(t.Context(), "id", second, 1); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, f.relays[relayTwo].deposits[0]) {
		t.Fatal("new card changed a usable ambiguous envelope")
	}
	f.bob.cardDown.Store(true)
	if _, err := f.lane.Attempt(t.Context(), "id", second, 0); err == nil {
		t.Fatal("sent while card standing is unavailable")
	}
	if len(f.relays[relayOne].deposits) != 1 {
		t.Fatal("retried past an unavailable card check")
	}
}
func TestUnacceptedRevokedCardResealsButAcceptedCardStops(t *testing.T) {
	for _, priorAccepted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unaccepted", true: "accepted"}[priorAccepted], func(t *testing.T) {
			f := newFixture(t)
			first, second := f.peerRoute(), f.peerRoute()
			if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
				t.Fatal(err)
			}
			if !priorAccepted {
				f.relays[relayOne].error = ErrUnavailable
			}
			_, err := f.lane.Attempt(t.Context(), "id", first, 0)
			if (err == nil) != priorAccepted {
				t.Fatal(err)
			}
			original := bytes.Clone(f.relays[relayOne].deposits[0])
			check := f.lane.config.VerifyCard
			f.lane.config.VerifyCard = func(ctx context.Context, raw []byte, now time.Time) (agentpacketseal.RecipientKey, agentpacketseal.KeyCard, error) {
				if bytes.Equal(raw, first.CardPacket) {
					return agentpacketseal.RecipientKey{}, agentpacketseal.KeyCard{}, ErrRefused
				}
				return check(ctx, raw, now)
			}
			_, err = f.lane.Attempt(t.Context(), "id", second, 1)
			if priorAccepted {
				if !errors.Is(err, ErrPeerRevoked) || len(f.relays[relayTwo].deposits) != 0 {
					t.Fatal("replaced an already accepted envelope", err)
				}
			} else {
				if err != nil || len(f.relays[relayTwo].deposits) != 1 || bytes.Equal(original, f.relays[relayTwo].deposits[0]) {
					t.Fatal("did not reseal a revoked unaccepted card", err)
				}
			}
		})
	}
}
func TestContactFallbackUsesTheSameBytesAndDropsOnlyRevokedCredentials(t *testing.T) {
	for _, code := range []int{507, 403} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			f := newFixture(t)
			f.auth.hasContact = true
			relay := f.relays[relayOne]
			errorCode := "quota_exhausted"
			if code == 403 {
				errorCode = "credential_revoked"
			}
			relay.outcomes = []error{&agentpacketrelay.StatusError{StatusCode: code, Code: errorCode}, nil}
			if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
				t.Fatal(err)
			}
			result, err := f.lane.Attempt(t.Context(), "id", f.peerRoute(), 0)
			wantDrops := 0
			if code == 403 {
				wantDrops = 1
			}
			if err != nil || !result.Accepted || len(relay.deposits) != 2 || len(relay.creds[0]) == 0 || len(relay.creds[1]) != 0 || !bytes.Equal(relay.deposits[0], relay.deposits[1]) || f.auth.dropped != wantDrops {
				t.Fatal("invalid contact fallback", result, err)
			}
		})
	}
}
func TestRelayRefusalDoesNotSuppressAnotherRelay(t *testing.T) {
	f := newFixture(t)
	route := f.peerRoute()
	f.relays[relayOne].error = &agentpacketrelay.StatusError{StatusCode: 409, Code: "conflict"}
	if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
		t.Fatal(err)
	}
	if _, err := f.lane.Attempt(t.Context(), "id", route, 0); err == nil {
		t.Fatal("conflict counted as acceptance")
	}
	if _, err := f.lane.Attempt(t.Context(), "id", route, 1); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.relays[relayOne].deposits[0], f.relays[relayTwo].deposits[0]) {
		t.Fatal("relay selection changed the envelope")
	}
	if _, err := f.lane.Attempt(t.Context(), "id", route, 0); !errors.Is(err, ErrRefused) || len(f.relays[relayOne].deposits) != 1 {
		t.Fatal("permanent conflict retried", err)
	}
}
func TestRevokedOwnDelegationUsesStrangersAndDoesNotPoll(t *testing.T) {
	f := newFixture(t)
	f.auth.hasContact = true
	f.resolver.mu.Lock()
	f.resolver.state[f.alice.agent].State.GetAgent().DelegationDigests = nil
	f.resolver.mu.Unlock()
	f.clock.n.Add(300)
	if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
		t.Fatal(err)
	}
	if _, err := f.lane.Attempt(t.Context(), "id", f.peerRoute(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.relays[relayOne].creds[0]) != 0 {
		t.Fatal("revoked own authority used a contact credential")
	}
	if _, err := f.lane.Poll(t.Context()); !errors.Is(err, ErrTransportRevoked) {
		t.Fatal("revoked owner polled", err)
	}
	if _, err := f.lane.CurrentCard(t.Context()); !errors.Is(err, ErrTransportRevoked) {
		t.Fatal("revoked owner issued a card", err)
	}
	if f.lane.OwnNotice(t.Context()) != "transport-revoked" {
		t.Fatal("missing owner notice")
	}
}

func TestExpiryWhileJournallingWithholdsTheBody(t *testing.T) {
	f := newFixture(t)
	route := f.peerRoute()
	if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+60); err != nil {
		t.Fatal(err)
	}
	commits := 0
	f.lane.disk.cut = func(step string) error {
		if step == "renamed" {
			commits++
			if commits == 2 {
				f.clock.n.Store(int64(start + 61))
			}
		}
		return nil
	}
	if _, err := f.lane.Attempt(t.Context(), "id", route, 0); !errors.Is(err, ErrExpired) {
		t.Fatal("expired prepared attempt not withheld", err)
	}
	if len(f.relays[relayOne].deposits) != 0 {
		t.Fatal("expired prepared body escaped")
	}
}
func TestUntrustedErrorsStayFixedText(t *testing.T) {
	f := newFixture(t)
	if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
		t.Fatal(err)
	}
	f.relays[relayOne].error = errors.New("private-reflected-token")
	result, err := f.lane.Attempt(t.Context(), "id", f.peerRoute(), 0)
	if !errors.Is(err, ErrUnavailable) || err.Error() != "carrier-unavailable" || result.Code != "carrier-unavailable" {
		t.Fatal("untrusted error reflected", result, err)
	}
}
