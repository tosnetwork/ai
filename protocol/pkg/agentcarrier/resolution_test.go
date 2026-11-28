package agentcarrier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

type fakeDirectory struct {
	published     [][]byte
	beforePublish func([]byte)
	records       map[[32]byte][]byte
	reads         int
	failure       error
}

func (d *fakeDirectory) HintIndex(context.Context, string) ([]agentpacketrelay.HintIndexEntry, error) {
	d.reads++
	if d.failure != nil {
		return nil, d.failure
	}
	out := []agentpacketrelay.HintIndexEntry{}
	for digest, raw := range d.records {
		h, e := agenttransport.DecodeHintRecord(raw)
		if e != nil {
			return nil, e
		}
		out = append(out, agentpacketrelay.HintIndexEntry{Digest: digest, IssuedAt: h.Hint.IssuedAt, Length: uint32(len(raw))})
	}
	return out, nil
}
func (d *fakeDirectory) HintRecord(_ context.Context, _ string, h [32]byte) ([]byte, error) {
	raw, ok := d.records[h]
	if !ok {
		return nil, ErrNoRoute
	}
	return bytes.Clone(raw), nil
}
func (d *fakeDirectory) PublishHint(_ context.Context, raw []byte) error {
	if d.beforePublish != nil {
		d.beforePublish(raw)
	}
	d.published = append(d.published, bytes.Clone(raw))
	return d.failure
}
func directoryRecord(t *testing.T, f *fixture, route Route) []byte {
	t.Helper()
	h, e := agenttransport.DecodeHintRecord(route.HintRecord)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := f.verifier.BuildHintRecord(t.Context(), h.Hint, []agenttransport.HintObject{{Kind: agenttransport.RailCard, Bytes: route.CardPacket}}, f.bob.transport, agenttransport.PublishOptions{})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func resolverFixture(t *testing.T, f *fixture) (*Resolver, map[string]*fakeDirectory) {
	t.Helper()
	dirs := map[string]*fakeDirectory{relayOne: {records: map[[32]byte][]byte{}}, relayTwo: {records: map[[32]byte][]byte{}}}
	r, e := OpenResolver(f.lane, ResolverConfig{Directories: []string{relayOne, relayTwo}, Directory: func(u string) (Directory, error) {
		d, ok := dirs[u]
		if !ok {
			return nil, ErrUnavailable
		}
		return d, nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	})
	return r, dirs
}
func addDirectoryHint(t *testing.T, d *fakeDirectory, raw []byte) {
	t.Helper()
	h, e := agenttransport.DecodeHintRecord(raw)
	if e != nil {
		t.Fatal(e)
	}
	wire, e := h.Hint.Delegation.Encode()
	if e != nil {
		t.Fatal(e)
	}
	d.records[sha256.Sum256(wire)] = raw
}

func TestResolutionUsesVerifiedCacheThenContactThenBothDirectories(t *testing.T) {
	f := newFixture(t)
	r, dirs := resolverFixture(t, f)
	contact := f.peerRoute()
	raw := directoryRecord(t, f, contact)
	addDirectoryHint(t, dirs[relayTwo], raw)
	route, e := r.Resolve(t.Context(), f.bob.agent, Route{})
	if e != nil || !bytes.Equal(route.HintRecord, raw) || dirs[relayOne].reads != 1 || dirs[relayTwo].reads != 1 {
		t.Fatal(e, dirs[relayOne].reads, dirs[relayTwo].reads)
	}
	dirs[relayOne].failure = ErrUnavailable
	dirs[relayTwo].failure = ErrUnavailable
	route, e = r.Resolve(t.Context(), f.bob.agent, Route{})
	if e != nil || !bytes.Equal(route.HintRecord, raw) || dirs[relayTwo].reads != 1 {
		t.Fatal("verified cache missed", e)
	}
	f.clock.n.Store(int64(start + 21600))
	if _, e = r.Resolve(t.Context(), f.bob.agent, Route{CardPacket: contact.CardPacket}); !errors.Is(e, ErrNoRoute) {
		t.Fatal("expired route or card supplied routing", e)
	}
}
func TestContactCardAloneNeverSuppliesARoute(t *testing.T) {
	f := newFixture(t)
	r, dirs := resolverFixture(t, f)
	contact := f.peerRoute()
	if _, e := r.Resolve(t.Context(), f.bob.agent, Route{CardPacket: contact.CardPacket}); !errors.Is(e, ErrNoRoute) {
		t.Fatal(e)
	}
	if dirs[relayOne].reads != 1 || dirs[relayTwo].reads != 1 {
		t.Fatal("both directory lookups are required")
	}
	route, e := r.Resolve(t.Context(), f.bob.agent, contact)
	if e != nil || !bytes.Equal(route.HintRecord, contact.HintRecord) || dirs[relayTwo].reads != 1 {
		t.Fatal("valid contact hint lost priority", e)
	}
}
func TestResolutionRefusesUnsignedAndWrongAgentHints(t *testing.T) {
	f := newFixture(t)
	r, dirs := resolverFixture(t, f)
	contact := f.peerRoute()
	raw := directoryRecord(t, f, contact)
	record, e := agenttransport.DecodeHintRecord(raw)
	if e != nil {
		t.Fatal(e)
	}
	record.Hint.Signature[0] ^= 1
	bad, e := record.Encode()
	if e != nil {
		t.Fatal(e)
	}
	addDirectoryHint(t, dirs[relayOne], bad)
	if _, e = r.Resolve(t.Context(), f.bob.agent, Route{HintRecord: bad, CardPacket: contact.CardPacket}); !errors.Is(e, ErrNoRoute) {
		t.Fatal(e)
	}
	addDirectoryHint(t, dirs[relayTwo], raw)
	if _, e = r.Resolve(t.Context(), f.alice.agent, contact); !errors.Is(e, ErrNoRoute) {
		t.Fatal("another Agent's hint supplied a route", e)
	}
}
func TestRoutingInventoryRefusesMissingUsedRecordAndMixedIdentity(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.config.StateDir, "routing-test")
	s, e := openRoutingStore(root, f.lane.identity())
	if e != nil {
		t.Fatal(e)
	}
	name := routingName("one")
	if e = s.write(name, map[string]string{"one": "two"}); e != nil {
		t.Fatal(e)
	}
	if e = s.disk.remove(name); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if opened, e := openRoutingStore(root, f.lane.identity()); e == nil {
		if closeErr := opened.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		t.Fatal("missing indexed record accepted")
	}
	other := filepath.Join(f.config.StateDir, "other")
	s, e = openRoutingStore(other, f.lane.identity())
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	id := f.lane.identity()
	id.Kind = Chat
	if opened, e := openRoutingStore(other, id); e == nil {
		if closeErr := opened.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		t.Fatal("mixed lane accepted")
	}
	info, e := os.Stat(filepath.Join(other, "identity"))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal(info, e)
	}
}

func TestResolverRequiresTwoDirectoriesAndProductionRelays(t *testing.T) {
	f := newFixture(t)
	_, e := OpenResolver(f.lane, ResolverConfig{Directories: []string{relayOne}, Directory: func(string) (Directory, error) { return &fakeDirectory{}, nil }})
	if !errors.Is(e, ErrConfig) {
		t.Fatal("single directory accepted", e)
	}
	r, _ := resolverFixture(t, f)
	contact := f.peerRoute()
	h, e := agenttransport.DecodeHintRecord(contact.HintRecord)
	if e != nil {
		t.Fatal(e)
	}
	h.Hint.Relays = []string{relayOne}
	h.Hint, e = agenttransport.SignHint(h.Hint, f.bob.transport)
	if e != nil {
		t.Fatal(e)
	}
	contact.HintRecord, e = h.Encode()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Resolve(t.Context(), f.bob.agent, contact); !errors.Is(e, ErrNoRoute) {
		t.Fatal("single-relay hint accepted without test mode", e)
	}
	r.config.TestSingleRelay = true
	if _, e = r.Resolve(t.Context(), f.bob.agent, contact); e != nil {
		t.Fatal("explicit pinned test configuration refused", e)
	}
}
func TestResolutionCarriesFreshnessThroughCardVerification(t *testing.T) {
	f := newFixture(t)
	r, _ := resolverFixture(t, f)
	contact := f.peerRoute()
	f.lane.config.VerifyCard = func(ctx context.Context, raw []byte, now time.Time) (agentpacketseal.RecipientKey, agentpacketseal.KeyCard, error) {
		key, card, e := f.verifyCard(ctx, raw, now)
		f.clock.n.Store(int64(start + 601))
		return key, card, e
	}
	if _, e := r.Resolve(t.Context(), f.bob.agent, contact); !errors.Is(e, ErrNoRoute) {
		t.Fatal("stale hint pass survived blocking card verification", e)
	}
}

func TestPrivateContactHintKeepsItsVerifiedCardAcrossResolution(t *testing.T) {
	f := newFixture(t)
	r, dirs := resolverFixture(t, f)
	contact := f.peerRoute()
	first, e := r.Resolve(t.Context(), f.bob.agent, contact)
	if e != nil {
		t.Fatal(e)
	}
	dirs[relayOne].failure = ErrUnavailable
	dirs[relayTwo].failure = ErrUnavailable
	cached, e := r.Resolve(t.Context(), f.bob.agent, Route{})
	if e != nil || !bytes.Equal(first.CardPacket, cached.CardPacket) {
		t.Fatal("private contact card disappeared from verified cache", e)
	}
}

func TestSameDelegationHintTiesUseTheFrozenHintOrdering(t *testing.T) {
	f := newFixture(t)
	d, e := agenttransport.DecodeDelegation(f.bob.wire)
	if e != nil {
		t.Fatal(e)
	}
	var base []byte
	var first agenttransport.Hint
	for i := uint64(0); i < 128; i++ {
		h, e := agenttransport.SignHint(agenttransport.Hint{Delegation: d, IssuedAt: start, ExpiresAt: start + 21600 - i, Relays: []string{relayOne, relayTwo}}, f.bob.transport)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := (agenttransport.HintRecord{Hint: h, Objects: []agenttransport.HintObject{}}).Encode()
		if e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			base = raw
			first = h
			continue
		}
		order, e := agenttransport.CompareHints(h, first)
		if e != nil {
			t.Fatal(e)
		}
		a, b := sha256.Sum256(raw), sha256.Sum256(base)
		rawGreater := bytes.Compare(a[:], b[:]) > 0
		if rawGreater != (order > 0) {
			if hintNewer(raw, base) != (order > 0) {
				t.Fatal("record hash overrode the canonical hint order")
			}
			return
		}
	}
	t.Fatal("tie fixture did not distinguish hint bytes from record bytes")
}
