package agentcarrier

import (
	"context"
	"errors"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"testing"
	"time"
)

func TestPublicationEnforcesPassAfterItsLastBlockingStep(t *testing.T) {
	for _, kind := range []string{"hint-freshness", "hint-expiry", "policy-freshness"} {
		t.Run(kind, func(t *testing.T) {
			for _, delay := range []uint64{0, 2} {
				t.Run((time.Duration(delay) * time.Second).String(), func(t *testing.T) {
					f := newFixture(t)
					config := PublicationConfig{}
					if kind == "hint-expiry" {
						config.TTL = time.Second
					}
					p, dirs := publisherFixture(t, f, config)
					if kind == "policy-freshness" {
						for _, r := range f.relays {
							r.policyError = ErrUnavailable
						}
					} else {
						for _, d := range dirs {
							d.failure = ErrUnavailable
						}
					}
					if _, e := p.Publish(t.Context()); !errors.Is(e, ErrUnavailable) {
						t.Fatal("preparation did not leave pending targets", e)
					}
					for _, d := range dirs {
						d.failure = nil
						d.published = nil
					}
					for _, r := range f.relays {
						r.policyError = nil
						r.policies = nil
					}
					if kind != "hint-expiry" {
						f.resolver.mu.Lock()
						f.resolver.failure = agenttransport.ErrUnavailable
						f.resolver.mu.Unlock()
					}
					f.clock.n.Store(int64(start + 599))
					if _, err := f.verifier.VerifyDelegation(t.Context(), f.alice.wire, agenttransport.Relay); err != nil {
						t.Fatal("precondition own cached pass", err)
					}
					entered := false
					reads := 0
					block := func() {
						entered = true
						f.clock.n.Store(int64(start + 599 + delay))
						f.resolver.mu.Lock()
						reads = f.resolver.reads
						f.resolver.mu.Unlock()
					}
					if kind == "policy-freshness" {
						factory := p.lane.config.Relay
						p.lane.config.Relay = func(url string) (Relay, error) {
							if url == relayOne {
								block()
							}
							return factory(url)
						}
					} else {
						factory := p.config.Directory
						p.config.Directory = func(url string) (Directory, error) {
							if url == relayOne {
								block()
							}
							return factory(url)
						}
					}
					result, e := p.Publish(t.Context())
					if !entered {
						t.Fatal("final blocking step not reached", result, e)
					}
					if delay == 0 {
						if e != nil || result.HintTargets != 2 || result.PolicyTargets != 2 {
							t.Fatal("unexpired publication refused", result, e)
						}
						return
					}
					expected := ErrUnavailable
					if kind == "hint-expiry" {
						expected = ErrNoRoute
					}
					if !errors.Is(e, expected) {
						t.Fatal("wrong refusal", kind, result, e)
					}
					if len(dirs[relayOne].published) != 0 || len(dirs[relayTwo].published) != 0 || len(f.relays[relayOne].policies) != 0 || len(f.relays[relayTwo].policies) != 0 {
						t.Fatal("expired authority reached a publisher", kind)
					}
					f.resolver.mu.Lock()
					after := f.resolver.reads
					f.resolver.mu.Unlock()
					if after != reads {
						t.Fatal("another blocking check tried to renew the expired pass", after-reads)
					}
				})
			}
		})
	}
}

func TestOwnerGrantDoesNotEscapeAfterItsStorageWriteOutlivesAuthority(t *testing.T) {
	f := newFixture(t)
	m := credentialManager(t, f, f.alice, func(context.Context, string) error { return nil })
	f.clock.n.Store(int64(start + 599))
	f.resolver.mu.Lock()
	f.resolver.failure = agenttransport.ErrUnavailable
	f.resolver.mu.Unlock()
	reads := 0
	entered := false
	m.store.disk.cut = func(stage string) error {
		if stage == "renamed" {
			entered = true
			f.clock.n.Store(int64(start + 601))
			f.resolver.mu.Lock()
			reads = f.resolver.reads
			f.resolver.mu.Unlock()
		}
		return nil
	}
	credential, e := m.Owner(t.Context(), relayOne)
	if !entered || !errors.Is(e, ErrUnavailable) || len(credential.wire) != 0 {
		t.Fatal("expired grant returned after disk I/O", entered, e)
	}
	f.resolver.mu.Lock()
	after := f.resolver.reads
	f.resolver.mu.Unlock()
	if after != reads {
		t.Fatal("post-write verification renewed the expired pass")
	}
}
