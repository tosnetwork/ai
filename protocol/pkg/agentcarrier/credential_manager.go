package agentcarrier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

const ContactLifetime = 3 * 24 * time.Hour

// Admission is the lane's business admission decision, not a relay quota or a
// transport delegation. ErrRefused denies admission; other errors are transient.
// A refusal never creates a contact credential.
type Admission func(context.Context, string) error
type CredentialManager struct {
	config   Config
	store    *routingStore
	key      ed25519.PrivateKey
	admitted Admission
}
type authorityRecord struct {
	Delegation []byte `json:"delegation"`
	Seed       []byte `json:"seed"`
}
type credentialRecord struct {
	Peer   string   `json:"peer"`
	Relays []string `json:"relays"`
	Wire   []byte   `json:"wire"`
	Seed   []byte   `json:"seed"`
	Issued uint64   `json:"issued"`
	Until  uint64   `json:"until"`
}

func (m *CredentialManager) Format(s fmt.State, _ rune) {
	if _, e := s.Write([]byte("[carrier credential manager]")); e != nil {
		return
	}
}
func (m *CredentialManager) MarshalJSON() ([]byte, error) { return nil, ErrRefused }
func OpenCredentialManager(ctx context.Context, c Config, key ed25519.PrivateKey, admitted Admission) (*CredentialManager, error) {
	if c.Verifier == nil || c.Verifier.NetworkIdentity() == ([3]string{}) || admitted == nil || !validRelays(c.Relays) || len(key) != ed25519.PrivateKeySize {
		return nil, ErrConfig
	}
	d, e := agenttransport.DecodeDelegation(c.Delegation)
	if e != nil || d.AgentID() != c.AgentID || !bytes.Equal(d.TransportKey[:], key[32:]) || !bytes.Equal(ed25519.NewKeyFromSeed(key[:32]), key) {
		return nil, ErrConfig
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	id := identity{"tos.service.carrier.lane.v2", c.AgentID, c.Kind, c.Verifier.NetworkIdentity()}
	if c.Kind != Rail && c.Kind != Chat {
		return nil, ErrConfig
	}
	store, e := openRoutingStore(filepath.Join(c.StateDir, "credentials-"+string(c.Kind)), id)
	if e != nil {
		return nil, e
	}
	fail := func(err error) (*CredentialManager, error) { return nil, errors.Join(err, store.Close()) }
	var record authorityRecord
	e = store.read(routingName("authority"), &record)
	if errors.Is(e, os.ErrNotExist) {
		index, err := store.index()
		if err != nil || len(index.Names) != 0 {
			return fail(ErrStorage)
		}
		record = authorityRecord{bytes.Clone(c.Delegation), bytes.Clone(key[:32])}
		e = store.write(routingName("authority"), record)
	}
	if e != nil {
		clear(record.Seed)
		return fail(ErrStorage)
	}
	stored, decodeErr := agenttransport.DecodeDelegation(record.Delegation)
	if decodeErr != nil || stored.AgentID() != c.AgentID || len(record.Seed) != ed25519.SeedSize || !bytes.Equal(ed25519.NewKeyFromSeed(record.Seed)[32:], stored.TransportKey[:]) {
		clear(record.Seed)
		return fail(ErrStorage)
	}
	if !bytes.Equal(record.Delegation, c.Delegation) {
		// Rotation is authorized by a new finalized delegation, never merely by a
		// runtime key argument. Old peer grants remain independently verifiable.
		if _, _, err := c.Verifier.VerifyDelegationUntil(ctx, c.Delegation, agenttransport.Relay); err != nil {
			clear(record.Seed)
			return fail(ErrTransportRevoked)
		}
		clear(record.Seed)
		record = authorityRecord{bytes.Clone(c.Delegation), bytes.Clone(key[:32])}
		if err := store.write(routingName("authority"), record); err != nil {
			clear(record.Seed)
			return fail(err)
		}
	} else if !bytes.Equal(record.Seed, key[:32]) {
		clear(record.Seed)
		return fail(ErrStorage)
	}

	clear(record.Seed)
	c.Delegation = bytes.Clone(c.Delegation)
	c.Relays = append([]string(nil), c.Relays...)
	return &CredentialManager{c, store, bytes.Clone(key), admitted}, nil
}
func (m *CredentialManager) Close() error { clear(m.key); return m.store.Close() }
func (m *CredentialManager) authority(ctx context.Context) (agenttransport.Delegation, time.Time, error) {
	d, until, e := m.config.Verifier.VerifyDelegationUntil(ctx, m.config.Delegation, agenttransport.Relay)
	if e != nil {
		return d, until, ErrTransportRevoked
	}
	return d, until, nil
}
func (m *CredentialManager) current(record credentialRecord) (Credential, error) {
	if len(record.Seed) != ed25519.SeedSize {
		return Credential{}, ErrStorage
	}
	c, e := NewCredential(record.Wire, ed25519.NewKeyFromSeed(record.Seed))
	if e != nil {
		return c, ErrStorage
	}
	decoded, e := agenttransport.DecodeCredential(record.Wire)
	if e != nil {
		return c, ErrStorage
	}
	until, e := decoded.NotAfter()
	if e != nil || until != record.Until || record.Issued >= until {
		return c, ErrStorage
	}
	return c, nil
}

type authorizationDeadline struct {
	FreshUntil time.Time
	Until      uint64
}

func (a authorizationDeadline) check(now time.Time) error {
	if now.Unix() < 0 || !now.Before(a.FreshUntil) {
		return ErrUnavailable
	}
	if uint64(now.Unix()) >= a.Until {
		return ErrTransportRevoked
	}
	return nil
}
func (m *CredentialManager) liveCredential(ctx context.Context, c Credential, pass authorizationDeadline) (Credential, error) {
	now := m.config.Now()
	if e := pass.check(now); e != nil {
		return Credential{}, e
	}
	if ctx.Err() != nil {
		return Credential{}, ErrUnavailable
	}
	decoded, e := agenttransport.DecodeCredential(c.wire)
	if e != nil {
		return Credential{}, ErrStorage
	}
	until, e := decoded.NotAfter()
	if e != nil {
		return Credential{}, ErrStorage
	}
	if uint64(now.Unix()) >= until {
		return Credential{}, ErrUnavailable
	}
	return c, nil
}
func (m *CredentialManager) issue(ctx context.Context, peer string, owner bool, output *authorizationDeadline) (Credential, error) {
	ctx, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	d, fresh, e := m.authority(ctx)
	if e != nil {
		return Credential{}, e
	}
	pass := authorizationDeadline{FreshUntil: fresh, Until: d.NotAfter}
	if output != nil {
		*output = pass
	}
	if !owner {
		if _, e = agentpacketseal.AgentDigest(peer); e != nil {
			return Credential{}, ErrRefused
		}
		if e = m.admitted(ctx, peer); e != nil {
			if errors.Is(e, ErrRefused) {
				return Credential{}, ErrRefused
			}
			return Credential{}, ErrUnavailable
		}
	}
	name := routingName("issued/" + peer)
	if owner {
		name = routingName("owner/" + peer)
		if !validRelays([]string{peer}) {
			return Credential{}, ErrConfig
		}
	}
	if e = m.store.lock(ctx); e != nil {
		return Credential{}, e
	}
	defer m.store.unlock()
	now := m.config.Now()
	if now.Unix() < 0 || !now.Before(fresh) || uint64(now.Unix()) >= d.NotAfter {
		return Credential{}, ErrTransportRevoked
	}
	seconds := uint64(now.Unix())
	var previous credentialRecord
	e = m.store.read(name, &previous)
	if e == nil {
		credential, err := m.current(previous)
		clear(previous.Seed)
		if previous.Peer != peer || !bytes.Equal(credential.wire, previous.Wire) {
			return Credential{}, ErrStorage
		}
		decoded, decodeErr := agenttransport.DecodeCredential(previous.Wire)
		if decodeErr != nil {
			return Credential{}, ErrStorage
		}
		previousDelegation, decodeErr := decoded.DelegationBytes()
		if decodeErr != nil {
			return Credential{}, ErrStorage
		}
		oldAuthority, decodeErr := agenttransport.DecodeDelegation(previousDelegation)
		if decodeErr != nil || oldAuthority.AgentID() != m.config.AgentID {
			return Credential{}, ErrStorage
		}
		if err != nil {
			return Credential{}, err
		}
		threshold := (previous.Until - previous.Issued) / 2
		if owner {
			threshold = min(threshold, 60)
		}
		if bytes.Equal(previousDelegation, m.config.Delegation) && previous.Until > seconds && previous.Until-seconds > threshold {
			return m.liveCredential(ctx, credential, pass)
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return Credential{}, e
	}
	duration := uint64(ContactLifetime / time.Second)
	if owner {
		duration = 3600
	}
	duration = min(duration, uint64(d.MaxCredentialSeconds), d.NotAfter-seconds)
	if duration == 0 {
		return Credential{}, ErrTransportRevoked
	}
	public, holder, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return Credential{}, ErrUnavailable
	}
	defer clear(holder)
	caveats := []agenttransport.Caveat{agenttransport.NotBeforeCaveat(seconds), agenttransport.NotAfterCaveat(seconds + duration)}
	if owner {
		caveats = append(caveats, agenttransport.OperationsCaveat(agenttransport.OperationList|agenttransport.OperationFetch|agenttransport.OperationPublish|agenttransport.OperationRevoke), agenttransport.RelayCaveat(peer))
	} else {
		var lane [16]byte
		if len(previous.Wire) > 0 {
			old, e := agenttransport.DecodeCredential(previous.Wire)
			if e != nil {
				return Credential{}, ErrStorage
			}
			var explicit bool
			lane, explicit, e = old.Lane()
			if e != nil || !explicit {
				return Credential{}, ErrStorage
			}
		} else if _, e = rand.Read(lane[:]); e != nil || lane == ([16]byte{}) {
			return Credential{}, ErrUnavailable
		}
		caveats = append(caveats, agenttransport.OperationsCaveat(agenttransport.OperationDeposit), agenttransport.LaneCaveat(lane), agenttransport.MaxEnvelopesCaveat(64), agenttransport.MaxEnvelopeBytesCaveat(agenttransport.MaxEnvelopeBytes), agenttransport.MaxLaneBytesCaveat(16<<20))
	}
	raw, e := agenttransport.IssueCredential(m.config.Delegation, m.key, public, caveats)
	if e != nil {
		return Credential{}, ErrRefused
	}
	record := credentialRecord{Peer: peer, Relays: []string{}, Wire: raw, Seed: bytes.Clone(holder[:32]), Issued: seconds, Until: seconds + duration}
	defer clear(record.Seed)
	if !m.config.Now().Before(fresh) {
		return Credential{}, ErrTransportRevoked
	}
	if e = m.writeCredential(ctx, name, record); e != nil {
		return Credential{}, e
	}
	credential, e := NewCredential(raw, holder)
	if e != nil {
		return Credential{}, e
	}
	return m.liveCredential(ctx, credential, pass)
}
func (m *CredentialManager) ownerAuthorization(ctx context.Context, relay string) (Credential, authorizationDeadline, error) {
	var pass authorizationDeadline
	c, e := m.issue(ctx, relay, true, &pass)
	return c, pass, e
}
func (m *CredentialManager) Owner(ctx context.Context, relay string) (Credential, error) {
	return m.issue(ctx, relay, true, nil)
}

// IssueContact returns secret material only in an opaque value. The lane exports
// it solely into its signed, sealed business packet and repeats until admitted.
func (m *CredentialManager) IssueContact(ctx context.Context, peer string) (Credential, error) {
	return m.issue(ctx, peer, false, nil)
}
func (c Credential) ExportForSealedPacket() ([]byte, []byte, error) {
	if len(c.holder) != 64 {
		return nil, nil, ErrRefused
	}
	return bytes.Clone(c.wire), bytes.Clone(c.holder[:32]), nil
}

// ExtractContact must decode only the credential fields of this verified packet.
// It cannot provide a route: routing still runs the resolver's steps 1..3.
type ExtractContact func(agentpacket.Packet) (wire, holderSeed []byte, err error)

func (m *CredentialManager) ReceiveContact(ctx context.Context, packetBytes []byte, extract ExtractContact, routes *Resolver) error {
	if extract == nil || routes == nil || m.config.VerifyPacket == nil {
		return ErrConfig
	}
	p, e := packet(packetBytes)
	if e != nil || p.RecipientAgentID != m.config.AgentID {
		return ErrRefused
	}
	if e = m.config.VerifyPacket(ctx, p); e != nil {
		if errors.Is(e, ErrRefused) {
			return ErrRefused
		}
		return ErrUnavailable
	}
	if e = m.admitted(ctx, p.SenderAgentID); e != nil {
		if errors.Is(e, ErrRefused) {
			return ErrRefused
		}
		return ErrUnavailable
	}
	raw, seed, e := extract(p)
	if e != nil || len(seed) != ed25519.SeedSize {
		return ErrRefused
	}
	defer clear(seed)
	credential, e := NewCredential(raw, ed25519.NewKeyFromSeed(seed))
	if e != nil {
		return ErrRefused
	}
	c, e := agenttransport.DecodeCredential(raw)
	if e != nil {
		return ErrRefused
	}
	d, e := c.Delegation()
	if e != nil || d.AgentID() != p.SenderAgentID {
		return ErrRefused
	}
	wire, e := c.DelegationBytes()
	if e != nil {
		return ErrRefused
	}
	_, fresh, e := m.config.Verifier.VerifyDelegationUntil(ctx, wire, agenttransport.Relay)
	if e != nil {
		if errors.Is(e, agenttransport.ErrDelegationRevoked) {
			return ErrRefused
		}
		return ErrUnavailable
	}
	route, e := routes.Resolve(ctx, p.SenderAgentID, Route{})
	if e != nil {
		return e
	}
	h, e := agenttransport.DecodeHintRecord(route.HintRecord)
	if e != nil {
		return ErrRefused
	}
	now := m.config.Now()
	if now.Unix() < 0 || !now.Before(fresh) {
		return ErrRefused
	}
	for _, url := range h.Hint.Relays {
		if c.CheckScope(uint64(now.Unix()), url, agenttransport.OperationDeposit) != nil {
			return ErrRefused
		}
	}
	until, e := c.NotAfter()
	if e != nil {
		return ErrRefused
	}
	relays := append([]string(nil), h.Hint.Relays...)
	sort.Strings(relays)
	record := credentialRecord{Peer: p.SenderAgentID, Relays: relays, Wire: bytes.Clone(credential.wire), Seed: bytes.Clone(credential.holder[:32]), Issued: uint64(now.Unix()), Until: until}
	defer clear(record.Seed)
	if e = m.store.lock(ctx); e != nil {
		return e
	}
	defer m.store.unlock()
	if !m.config.Now().Before(fresh) || uint64(m.config.Now().Unix()) >= until {
		return ErrRefused
	}
	return m.writeCredential(ctx, routingName("held/"+p.SenderAgentID), record)
}
func (m *CredentialManager) Contact(ctx context.Context, peer, relay string) (Credential, bool, error) {
	if e := m.store.lock(ctx); e != nil {
		return Credential{}, false, e
	}
	var record credentialRecord
	e := m.store.read(routingName("held/"+peer), &record)
	m.store.unlock()
	if errors.Is(e, os.ErrNotExist) {
		return Credential{}, false, nil
	}
	if e != nil {
		return Credential{}, false, e
	}
	defer clear(record.Seed)
	if record.Peer != peer || !validRelays(record.Relays) || !slices.IsSorted(record.Relays) {
		return Credential{}, false, ErrStorage
	}
	credential, e := m.current(record)
	if e != nil {
		return Credential{}, false, e
	}
	if !slices.Contains(record.Relays, relay) {
		return Credential{}, false, nil
	}
	c, e := agenttransport.DecodeCredential(credential.wire)
	if e != nil {
		return Credential{}, false, ErrStorage
	}
	d, e := c.DelegationBytes()
	if e != nil {
		return Credential{}, false, ErrStorage
	}
	if _, e = m.config.Verifier.VerifyDelegation(ctx, d, agenttransport.Relay); e != nil {
		return Credential{}, false, nil
	}
	now := m.config.Now()
	if now.Unix() < 0 || c.CheckScope(uint64(now.Unix()), relay, agenttransport.OperationDeposit) != nil {
		return Credential{}, false, nil
	}
	raw, e := agenttransport.AppendCredentialBlock(credential.wire, credential.holder, ed25519.PublicKey(credential.holder[32:]), []agenttransport.Caveat{agenttransport.RelayCaveat(relay)})
	if e != nil {
		return Credential{}, false, nil
	}
	out, e := NewCredential(raw, credential.holder)
	return out, e == nil, e
}
func (m *CredentialManager) DropContact(ctx context.Context, peer, _ string) error {
	if e := m.store.lock(ctx); e != nil {
		return e
	}
	defer m.store.unlock()
	return m.store.remove(routingName("held/" + peer))
}

var _ Credentials = (*CredentialManager)(nil)
var _ json.Marshaler = (*CredentialManager)(nil)

func (m *CredentialManager) writeCredential(ctx context.Context, name string, record credentialRecord) error {
	e := m.store.write(name, record)
	if errors.Is(e, ErrCapacity) {
		if e = m.pruneLocked(ctx); e != nil {
			return e
		}
		return m.store.write(name, record)
	}
	return e
}
func (m *CredentialManager) pruneLocked(ctx context.Context) error {
	now := m.config.Now()
	if now.Unix() < 0 {
		return ErrConfig
	}
	index, e := m.store.index()
	if e != nil {
		return e
	}
	for _, name := range index.Names {
		if e := ctx.Err(); e != nil {
			return ErrUnavailable
		}
		if name == routingName("authority") {
			continue
		}
		var record credentialRecord
		if e = m.store.read(name, &record); e != nil {
			return e
		}
		credential, e := agenttransport.DecodeCredential(record.Wire)
		if e != nil {
			return ErrStorage
		}
		until, e := credential.NotAfter()
		if e != nil || until != record.Until || until > ^uint64(0)-86400-300 || record.Issued >= until || len(record.Seed) != 32 {
			return ErrStorage
		}
		clear(record.Seed)
		retire := until
		switch name {
		case routingName("issued/" + record.Peer):
			retire += 86400 + 300
		case routingName("owner/" + record.Peer), routingName("held/" + record.Peer):
		default:
			return ErrStorage
		}
		if uint64(now.Unix()) >= retire {
			if e = m.store.remove(name); e != nil {
				return e
			}
		}
	}
	return nil
}

// Prune keeps issued lane IDs through the last possible relay retention after
// credential expiry, then allows the bounded store to admit new counterparties.
func (m *CredentialManager) Prune(ctx context.Context) error {
	if e := m.store.lock(ctx); e != nil {
		return e
	}
	defer m.store.unlock()
	return m.pruneLocked(ctx)
}
