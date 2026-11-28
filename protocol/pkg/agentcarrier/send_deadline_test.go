package agentcarrier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

func deadlineFixture(t *testing.T, kind string) *fixture {
	t.Helper()
	f := newFixture(t)
	if kind == "delegation" {
		d, e := agenttransport.DecodeDelegation(f.bob.wire)
		if e != nil {
			t.Fatal(e)
		}
		d.NotAfter = start + 600
		f.bob.wire, e = d.Encode()
		if e != nil {
			t.Fatal(e)
		}
		hash := sha256.Sum256(f.bob.wire)
		f.resolver.mu.Lock()
		snapshot := f.resolver.state[f.bob.agent]
		snapshot.State.GetAgent().DelegationDigests = []string{"sha256:" + hex.EncodeToString(hash[:])}
		snapshot.AdmissionEpochs = map[[32]byte]uint64{hash: 1}
		f.resolver.state[f.bob.agent] = snapshot
		f.resolver.mu.Unlock()
	}
	if _, e := f.verifier.VerifyDelegation(t.Context(), f.bob.wire, agenttransport.Hints); e != nil {
		t.Fatal(e)
	}
	if kind == "freshness" {
		f.resolver.mu.Lock()
		f.resolver.failure = agenttransport.ErrUnavailable
		f.resolver.mu.Unlock()
	}
	f.clock.n.Store(int64(start + 599))
	return f
}
func TestFinalCardReadCannotExtendHintAuthority(t *testing.T) {
	for _, kind := range []string{"delegation", "freshness"} {
		t.Run(kind, func(t *testing.T) {
			for _, delay := range []uint64{0, 2} {
				t.Run((time.Duration(delay) * time.Second).String(), func(t *testing.T) {
					f := deadlineFixture(t, kind)
					route := f.peerRoute()
					if _, e := f.lane.Queue(t.Context(), "deadline", f.message(f.alice, f.bob), start+7200); e != nil {
						t.Fatal(e)
					}
					reads, atLast := 0, 0
					f.lane.config.VerifyCard = func(ctx context.Context, raw []byte, now time.Time) (agentpacketseal.RecipientKey, agentpacketseal.KeyCard, error) {
						reads++
						if reads == 4 {
							f.clock.n.Store(int64(start + 599 + delay))
							f.resolver.mu.Lock()
							atLast = f.resolver.reads
							f.resolver.mu.Unlock()
						}
						return f.verifyCard(ctx, raw, now)
					}
					result, e := f.lane.Attempt(t.Context(), "deadline", route, 0)
					if reads != 4 {
						t.Fatal("final card read not reached", reads, e)
					}
					f.resolver.mu.Lock()
					after := f.resolver.reads
					f.resolver.mu.Unlock()
					if after != atLast {
						t.Fatal("blocking verification ran after the final card read", after-atLast)
					}
					if delay == 0 {
						if e != nil || !result.Accepted || len(f.relays[relayOne].deposits) != 1 {
							t.Fatal("unexpired hint refused", result, e)
						}
					} else {
						expected := ErrPeerRevoked
						if kind == "freshness" {
							expected = ErrUnavailable
						}
						if !errors.Is(e, expected) || result.Accepted || len(f.relays[relayOne].deposits) != 0 {
							t.Fatal("expired hint authorized a deposit", result, e)
						}
						saved, e := f.lane.readDelivery(deliveryName("deadline"))
						if e != nil || saved.State != "pending" || saved.Generations[0].Targets[0].State != "pending" {
							t.Fatal("unsent attempt was marked accepted", saved.State, e)
						}
					}
				})
			}
		})
	}
}
func TestVerifiedRouteRetainsAndEnforcesItsPassDeadline(t *testing.T) {
	for _, kind := range []string{"delegation", "freshness"} {
		t.Run(kind, func(t *testing.T) {
			f := deadlineFixture(t, kind)
			route := f.peerRoute()
			verified, e := f.lane.verifiedRoute(t.Context(), f.bob.agent, route)
			if e != nil {
				t.Fatal(e)
			}
			if kind == "delegation" && verified.DelegationUntil != start+600 {
				t.Fatal("delegation expiry discarded")
			}
			if kind == "freshness" && !verified.FreshUntil.Equal(time.Unix(int64(start+600), 0)) {
				t.Fatal("cached pass deadline renewed", verified.FreshUntil)
			}
			original := f.lane.config.VerifyCard
			f.lane.config.VerifyCard = func(ctx context.Context, raw []byte, now time.Time) (agentpacketseal.RecipientKey, agentpacketseal.KeyCard, error) {
				f.clock.n.Store(int64(start + 601))
				return original(ctx, raw, now)
			}
			if _, e = f.lane.verifiedRoute(t.Context(), f.bob.agent, route); e == nil {
				t.Fatal("route returned after its authority expired")
			}
		})
	}
}
