package agentcarrier

import (
	"bytes"
	"context"
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
	m, e := OpenCredentialManager(c, p.transport, admit)
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
	if m, e := OpenCredentialManager(f.config, f.bob.transport, func(context.Context, string) error { return nil }); e == nil {
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
