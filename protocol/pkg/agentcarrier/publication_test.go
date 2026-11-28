package agentcarrier

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

func publisherFixture(t *testing.T, f *fixture, c PublicationConfig) (*Publisher, map[string]*fakeDirectory) {
	t.Helper()
	m := credentialManager(t, f, f.alice, func(context.Context, string) error { return nil })
	dirs := map[string]*fakeDirectory{relayOne: {records: map[[32]byte][]byte{}}, relayTwo: {records: map[[32]byte][]byte{}}}
	c.Directories = []string{relayOne, relayTwo}
	c.Directory = func(u string) (Directory, error) {
		d, ok := dirs[u]
		if !ok {
			return nil, ErrUnavailable
		}
		return d, nil
	}
	p, e := OpenPublisher(f.lane, m, c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := p.Close(); e != nil {
			t.Error(e)
		}
	})
	return p, dirs
}
func TestPublicationIsJournalledAndReducedBeforeAnyRelaySeesIt(t *testing.T) {
	f := newFixture(t)
	p, dirs := publisherFixture(t, f, PublicationConfig{})
	for _, d := range dirs {
		d.beforePublish = func(raw []byte) {
			var saved publication
			if e := p.store.read(routingName("current"), &saved); e != nil || !bytes.Equal(saved.Raw, raw) {
				t.Fatal("hint not durable before publication", e)
			}
		}
	}
	view, e := p.Publish(t.Context())
	if e != nil || view.HintTargets != 2 || view.PolicyTargets != 2 {
		t.Fatal(view, e)
	}
	record, e := agenttransport.DecodeHintRecord(dirs[relayOne].published[0])
	if e != nil || len(record.Objects) != 0 || len(record.Hint.Direct) != 0 {
		t.Fatal("reduced hint exposed private objects", e)
	}
	if record.Hint.ExpiresAt != start+21600 || record.Hint.IssuedAt != start {
		t.Fatal(record.Hint)
	}
	if len(f.relays[relayOne].policies) != 1 || f.relays[relayOne].policies[0].StrangerCount != 32 {
		t.Fatal("default publication closed stranger admission")
	}
	if _, e = p.Publish(t.Context()); e != nil {
		t.Fatal(e)
	}
	if len(dirs[relayOne].published) != 1 || len(f.relays[relayOne].policies) != 1 {
		t.Fatal("publication did not reuse its receipts")
	}
	f.clock.n.Store(int64(start + 10800))
	if _, e = p.Publish(t.Context()); e != nil {
		t.Fatal(e)
	}
	if len(dirs[relayOne].published) != 2 || bytes.Equal(dirs[relayOne].published[0], dirs[relayOne].published[1]) {
		t.Fatal("half-life refresh did not republish")
	}
}
func TestPublicationRetriesOnlyFailedTargetsAndRetainsRemovedRelays(t *testing.T) {
	f := newFixture(t)
	p, dirs := publisherFixture(t, f, PublicationConfig{PublishRailCard: true})
	dirs[relayTwo].failure = ErrUnavailable
	if view, e := p.Publish(t.Context()); !errors.Is(e, ErrUnavailable) || view.HintTargets != 1 {
		t.Fatal(view, e)
	}
	first := bytes.Clone(dirs[relayOne].published[0])
	dirs[relayTwo].failure = nil
	if _, e := p.Publish(t.Context()); e != nil {
		t.Fatal(e)
	}
	if len(dirs[relayOne].published) != 1 || len(dirs[relayTwo].published) != 2 || !bytes.Equal(first, dirs[relayTwo].published[1]) {
		t.Fatal("retry changed signed hint or resent an acknowledged target")
	}
	old, e := agenttransport.DecodeHintRecord(first)
	if e != nil || len(old.Objects) != 1 || old.Objects[0].Kind != agenttransport.RailCard {
		t.Fatal(e)
	}
	const third = "https://127.0.0.1:19003"
	f.relays[third] = newRelay()
	dirs[third] = &fakeDirectory{records: map[[32]byte][]byte{}}
	f.lane.config.Relays = []string{relayTwo, third}
	f.clock.n.Store(int64(start + 1))
	if _, e := p.Publish(t.Context()); e != nil {
		t.Fatal(e)
	}
	targets, e := f.lane.pollTargets()
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, target := range targets {
		if target.URL == relayOne {
			found = true
			if target.Until < old.Hint.ExpiresAt+86400+300 {
				t.Fatal("retired poll target lost its last hint horizon", target)
			}
		}
	}
	if !found {
		t.Fatal("retired relay disappeared")
	}
}
func TestRevokedTransportPublishesNothing(t *testing.T) {
	f := newFixture(t)
	p, dirs := publisherFixture(t, f, PublicationConfig{})
	f.resolver.mu.Lock()
	f.resolver.state[f.alice.agent].State.GetAgent().DelegationDigests = nil
	f.resolver.mu.Unlock()
	f.clock.n.Store(int64(start + 300))
	if _, e := p.Publish(t.Context()); !errors.Is(e, ErrTransportRevoked) {
		t.Fatal(e)
	}
	if len(dirs[relayOne].published) != 0 || len(dirs[relayTwo].published) != 0 || len(f.relays[relayOne].policies) != 0 {
		t.Fatal("revoked transport published")
	}
}
func TestPublicationRequiresExplicitConsentAndProductionRelayCount(t *testing.T) {
	f := newFixture(t)
	m := credentialManager(t, f, f.alice, func(context.Context, string) error { return nil })
	for _, c := range []PublicationConfig{{PublicContact: true}, {Evidence: []byte("private")}, {TTL: 25 * time.Hour}} {
		c.Directories = []string{relayOne, relayTwo}
		c.Directory = func(string) (Directory, error) { return &fakeDirectory{}, nil }
		if p, e := OpenPublisher(f.lane, m, c); e == nil {
			if closeErr := p.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			t.Fatal("unsafe publication configuration accepted")
		}
	}
	f.lane.config.Relays = []string{relayOne}
	if p, e := OpenPublisher(f.lane, m, PublicationConfig{Directories: []string{relayOne, relayTwo}, Directory: func(string) (Directory, error) { return &fakeDirectory{}, nil }}); e == nil {
		if closeErr := p.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		t.Fatal("single-relay production hint accepted")
	}
}

func TestNewDelegationRepublishesEvenAnUnchangedReducedHint(t *testing.T) {
	f := newFixture(t)
	admit := func(context.Context, string) error { return nil }
	m, e := OpenCredentialManager(t.Context(), f.config, f.alice.transport, admit)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if m != nil {
			if e := m.Close(); e != nil {
				t.Error(e)
			}
		}
	}()
	dirs := map[string]*fakeDirectory{relayOne: {records: map[[32]byte][]byte{}}, relayTwo: {records: map[[32]byte][]byte{}}}
	config := PublicationConfig{Directories: []string{relayOne, relayTwo}, Directory: func(u string) (Directory, error) { return dirs[u], nil }}
	p, e := OpenPublisher(f.lane, m, config)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if p != nil {
			if e := p.Close(); e != nil {
				t.Error(e)
			}
		}
	}()
	if _, e = p.Publish(t.Context()); e != nil {
		t.Fatal(e)
	}
	old := bytes.Clone(dirs[relayOne].published[0])
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	p = nil
	if e = m.Close(); e != nil {
		t.Fatal(e)
	}
	m = nil
	c, key, digest := rotatedTransport(t, f)
	admitRotatedTransport(f, digest)
	m, e = OpenCredentialManager(t.Context(), c, key, admit)
	if e != nil {
		t.Fatal(e)
	}
	f.lane.config.Delegation = c.Delegation
	p, e = OpenPublisher(f.lane, m, config)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Publish(t.Context()); e != nil {
		t.Fatal(e)
	}
	if len(dirs[relayOne].published) != 2 || bytes.Equal(old, dirs[relayOne].published[1]) {
		t.Fatal("old delegation's hint was reused after rotation")
	}
	decoded, e := agenttransport.DecodeHintRecord(dirs[relayOne].published[1])
	if e != nil {
		t.Fatal(e)
	}
	actual, e := decoded.Hint.Delegation.Encode()
	if e != nil || !bytes.Equal(actual, c.Delegation) {
		t.Fatal("hint was signed under the retired delegation", e)
	}
}
