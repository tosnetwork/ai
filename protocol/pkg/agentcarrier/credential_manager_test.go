package agentcarrier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

func credentialManager(t *testing.T, f *fixture, p *person, admit Admission) *CredentialManager {
	t.Helper()
	c := f.config
	c.AgentID = p.agent
	c.Delegation = p.wire
	if p != f.alice {
		c.StateDir = t.TempDir()
		if e := os.Chmod(c.StateDir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	m, e := OpenCredentialManager(t.Context(), c, p.transport, admit)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := m.Close(); e != nil {
			t.Error(e)
		}
	})
	return m
}
func TestOwnerCredentialRefreshAndPrivateCustody(t *testing.T) {
	f := newFixture(t)
	m := credentialManager(t, f, f.alice, func(context.Context, string) error { return nil })
	first, e := m.Owner(t.Context(), relayOne)
	if e != nil {
		t.Fatal(e)
	}
	var saved credentialRecord
	if e = m.store.read(routingName("owner/"+relayOne), &saved); e != nil || !bytes.Equal(saved.Wire, first.wire) {
		t.Fatal("owner credential not durable before return", e)
	}
	c, e := agenttransport.DecodeCredential(first.wire)
	if e != nil {
		t.Fatal(e)
	}
	until, e := c.NotAfter()
	if e != nil || until != start+3600 {
		t.Fatal(until, e)
	}
	if c.CheckScope(start, relayOne, agenttransport.OperationList) != nil || c.CheckScope(start, relayTwo, agenttransport.OperationList) == nil {
		t.Fatal("owner relay binding")
	}
	again, e := m.Owner(t.Context(), relayOne)
	if e != nil || !bytes.Equal(first.wire, again.wire) {
		t.Fatal("owner rotated early", e)
	}
	f.clock.n.Store(int64(start + 3541))
	fresh, e := m.Owner(t.Context(), relayOne)
	if e != nil || bytes.Equal(first.wire, fresh.wire) {
		t.Fatal("owner was not refreshed before expiry", e)
	}
	info, e := os.Stat(filepath.Join(m.config.StateDir, "credentials-rail", routingName("authority")))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal(info, e)
	}
	if got := fmt.Sprintf("%+v", m); got != "[carrier credential manager]" {
		t.Fatal("manager exposes secret", got)
	}
	if _, e = json.Marshal(m); e == nil {
		t.Fatal("manager JSON exposed secret")
	}
}
func TestContactIssueRequiresAdmissionAndRenewsTheSameLane(t *testing.T) {
	f := newFixture(t)
	allow := false
	m := credentialManager(t, f, f.alice, func(context.Context, string) error {
		if !allow {
			return ErrRefused
		}
		return nil
	})
	if _, e := m.IssueContact(t.Context(), f.bob.agent); !errors.Is(e, ErrRefused) {
		t.Fatal("unadmitted contact issued", e)
	}
	allow = true
	first, e := m.IssueContact(t.Context(), f.bob.agent)
	if e != nil {
		t.Fatal(e)
	}
	c, e := agenttransport.DecodeCredential(first.wire)
	if e != nil {
		t.Fatal(e)
	}
	lane, explicit, e := c.Lane()
	if e != nil || !explicit {
		t.Fatal(e)
	}
	until, e := c.NotAfter()
	if e != nil || until != start+uint64(ContactLifetime/time.Second) {
		t.Fatal(until, e)
	}
	if c.CheckScope(start, relayOne, agenttransport.OperationList) == nil {
		t.Fatal("contact has owner read authority")
	}
	f.clock.n.Store(int64(start + uint64(ContactLifetime/time.Second)/2 + 1))
	second, e := m.IssueContact(t.Context(), f.bob.agent)
	if e != nil || bytes.Equal(first.wire, second.wire) {
		t.Fatal("contact not refreshed", e)
	}
	next, e := agenttransport.DecodeCredential(second.wire)
	if e != nil {
		t.Fatal(e)
	}
	other, _, e := next.Lane()
	if e != nil || other != lane {
		t.Fatal("renewal resets the contact quota", e)
	}
}
func TestContactImportVerifiesPacketIssuerAdmissionAndRoute(t *testing.T) {
	f := newFixture(t)
	r, dirs := resolverFixture(t, f)
	hint := directoryRecord(t, f, f.peerRoute())
	addDirectoryHint(t, dirs[relayTwo], hint)
	allow := true
	admit := func(context.Context, string) error {
		if !allow {
			return ErrRefused
		}
		return nil
	}
	alice := credentialManager(t, f, f.alice, admit)
	bob := credentialManager(t, f, f.bob, admit)
	grant, e := bob.IssueContact(t.Context(), f.alice.agent)
	if e != nil {
		t.Fatal(e)
	}
	wire, seed, e := grant.ExportForSealedPacket()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(seed)
	type fields struct{ Wire, Seed []byte }
	rawPacket := f.message(f.bob, f.alice)
	p, e := packet(rawPacket)
	if e != nil {
		t.Fatal(e)
	}
	p.Payload, e = json.Marshal(fields{wire, seed})
	if e != nil {
		t.Fatal(e)
	}
	rawPacket, e = agentpacket.EncodeJSON(p)
	if e != nil {
		t.Fatal(e)
	}
	extract := func(p agentpacket.Packet) ([]byte, []byte, error) {
		var v fields
		e := json.Unmarshal(p.Payload, &v)
		return v.Wire, v.Seed, e
	}
	allow = false
	if e = alice.ReceiveContact(t.Context(), rawPacket, extract, r); !errors.Is(e, ErrRefused) {
		t.Fatal("unadmitted import", e)
	}
	allow = true
	if e = alice.ReceiveContact(t.Context(), rawPacket, extract, r); e != nil {
		t.Fatal(e)
	}
	held, ok, e := alice.Contact(t.Context(), f.bob.agent, relayOne)
	if e != nil || !ok {
		t.Fatal(e)
	}
	c, e := agenttransport.DecodeCredential(held.wire)
	if e != nil {
		t.Fatal(e)
	}
	if c.CheckScope(start, relayOne, agenttransport.OperationDeposit) != nil || c.CheckScope(start, relayTwo, agenttransport.OperationDeposit) == nil {
		t.Fatal("contact relay attenuation missing")
	}
	wrongGrant, e := alice.IssueContact(t.Context(), f.bob.agent)
	if e != nil {
		t.Fatal(e)
	}
	wrongWire, wrongSeed, e := wrongGrant.ExportForSealedPacket()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(wrongSeed)
	p.Payload, e = json.Marshal(fields{wrongWire, wrongSeed})
	if e != nil {
		t.Fatal(e)
	}
	wrong, e := agentpacket.EncodeJSON(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = alice.ReceiveContact(t.Context(), wrong, extract, r); !errors.Is(e, ErrRefused) {
		t.Fatal("credential issuer differs from verified sender", e)
	}
	p.Payload, e = json.Marshal(fields{wire, seed})
	if e != nil {
		t.Fatal(e)
	}
	originalVerifier := alice.config.VerifyPacket
	alice.config.VerifyPacket = func(context.Context, agentpacket.Packet) error { return ErrUnavailable }
	if e = alice.ReceiveContact(t.Context(), rawPacket, extract, r); !errors.Is(e, ErrUnavailable) {
		t.Fatal("transient packet read became a permanent refusal", e)
	}
	alice.config.VerifyPacket = originalVerifier
	originalAdmission := alice.admitted
	alice.admitted = func(context.Context, string) error { return ErrUnavailable }
	if e = alice.ReceiveContact(t.Context(), rawPacket, extract, r); !errors.Is(e, ErrUnavailable) {
		t.Fatal("transient admission read became a permanent refusal", e)
	}
	alice.admitted = originalAdmission
	p.Payload, e = json.Marshal(fields{wire, seed[:31]})
	if e != nil {
		t.Fatal(e)
	}
	malformed, e := agentpacket.EncodeJSON(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = alice.ReceiveContact(t.Context(), malformed, extract, r); !errors.Is(e, ErrRefused) {
		t.Fatal("short holder seed accepted", e)
	}
	p.Payload, e = json.Marshal(fields{wire, seed})
	if e != nil {
		t.Fatal(e)
	}
	p.Signature[0] ^= 1
	wrong, e = agentpacket.EncodeJSON(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = alice.ReceiveContact(t.Context(), wrong, extract, r); !errors.Is(e, ErrRefused) {
		t.Fatal("unverified packet imported credential", e)
	}
	if e = alice.DropContact(t.Context(), f.bob.agent, relayOne); e != nil {
		t.Fatal(e)
	}
	if _, ok, e = alice.Contact(t.Context(), f.bob.agent, relayOne); e != nil || ok {
		t.Fatal("dropped credential survives", e)
	}
}
func TestCredentialIssuerRefusesWrongKeyAndRevokedAuthority(t *testing.T) {
	f := newFixture(t)
	if m, e := OpenCredentialManager(t.Context(), f.config, f.bob.transport, func(context.Context, string) error { return nil }); e == nil {
		if closeErr := m.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		t.Fatal("wrong transport key accepted")
	}
	m := credentialManager(t, f, f.alice, func(context.Context, string) error { return nil })
	if _, e := m.Owner(t.Context(), relayOne); e != nil {
		t.Fatal(e)
	}
	f.resolver.mu.Lock()
	f.resolver.state[f.alice.agent].State.GetAgent().DelegationDigests = nil
	f.resolver.mu.Unlock()
	f.clock.n.Store(int64(start + 300))
	if _, e := m.Owner(t.Context(), relayOne); !errors.Is(e, ErrTransportRevoked) {
		t.Fatal("revoked issuer signed", e)
	}
}

func rotatedTransport(t *testing.T, f *fixture) (Config, ed25519.PrivateKey, [32]byte) {
	t.Helper()
	key := testKey("rotated transport")
	d, e := agenttransport.DecodeDelegation(f.alice.wire)
	if e != nil {
		t.Fatal(e)
	}
	copy(d.TransportKey[:], key[32:])
	wire, e := d.Encode()
	if e != nil {
		t.Fatal(e)
	}
	c := f.config
	c.Delegation = wire
	return c, key, sha256.Sum256(wire)
}
func admitRotatedTransport(f *fixture, digest [32]byte) {
	f.resolver.mu.Lock()
	defer f.resolver.mu.Unlock()
	snapshot := f.resolver.state[f.alice.agent]
	snapshot.State.GetAgent().DelegationDigests = []string{"sha256:" + hex.EncodeToString(digest[:])}
	snapshot.AdmissionEpochs = map[[32]byte]uint64{digest: 1}
	f.resolver.state[f.alice.agent] = snapshot
}
func TestTransportRotationRequiresFinalizedAdmissionAndKeepsTheLane(t *testing.T) {
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
	old, e := m.IssueContact(t.Context(), f.bob.agent)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := agenttransport.DecodeCredential(old.wire)
	if e != nil {
		t.Fatal(e)
	}
	oldLane, _, e := decoded.Lane()
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Close(); e != nil {
		t.Fatal(e)
	}
	m = nil
	c, key, digest := rotatedTransport(t, f)
	if opened, e := OpenCredentialManager(t.Context(), c, key, admit); !errors.Is(e, ErrTransportRevoked) {
		if opened != nil {
			if err := opened.Close(); err != nil {
				t.Fatal(err)
			}
		}
		t.Fatal("uncommitted runtime key became authority", e)
	}
	admitRotatedTransport(f, digest)
	m, e = OpenCredentialManager(t.Context(), c, key, admit)
	if e != nil {
		t.Fatal(e)
	}
	fresh, e := m.IssueContact(t.Context(), f.bob.agent)
	if e != nil {
		t.Fatal("old credential row blocked rotation", e)
	}
	decoded, e = agenttransport.DecodeCredential(fresh.wire)
	if e != nil {
		t.Fatal(e)
	}
	wire, e := decoded.DelegationBytes()
	if e != nil || !bytes.Equal(wire, c.Delegation) {
		t.Fatal("new grant uses old authority", e)
	}
	lane, _, e := decoded.Lane()
	if e != nil || lane != oldLane {
		t.Fatal("rotation reset the contact lane", e)
	}
}

func TestCredentialPruningKeepsIssuedLanesThroughRelayRetention(t *testing.T) {
	f := newFixture(t)
	m := credentialManager(t, f, f.alice, func(context.Context, string) error { return nil })
	if _, e := m.Owner(t.Context(), relayOne); e != nil {
		t.Fatal(e)
	}
	if _, e := m.IssueContact(t.Context(), f.bob.agent); e != nil {
		t.Fatal(e)
	}
	f.clock.n.Store(int64(start + 3600))
	if e := m.Prune(t.Context()); e != nil {
		t.Fatal(e)
	}
	var record credentialRecord
	if e := m.store.read(routingName("owner/"+relayOne), &record); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("expired owner holder retained", e)
	}
	f.clock.n.Store(int64(start + uint64(ContactLifetime/time.Second)))
	if e := m.Prune(t.Context()); e != nil {
		t.Fatal(e)
	}
	if e := m.store.read(routingName("issued/"+f.bob.agent), &record); e != nil {
		t.Fatal("contact lane disappeared before old deposits expire", e)
	}
	f.clock.n.Add(86400 + 300)
	if e := m.Prune(t.Context()); e != nil {
		t.Fatal(e)
	}
	if e := m.store.read(routingName("issued/"+f.bob.agent), &record); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("expired contact lane retained forever", e)
	}
}
