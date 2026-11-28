package agentcarrier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"google.golang.org/protobuf/proto"
)

const relayOne = "https://127.0.0.1:19001"
const relayTwo = "https://127.0.0.1:19002"
const start = uint64(1800000000)

type clock struct{ n atomic.Int64 }

func (c *clock) Now() time.Time { return time.Unix(c.n.Load(), 0) }

type location string

func (l location) Locate(string, string) (string, error) { return string(l), nil }

type resolver struct {
	mu    sync.Mutex
	state map[string]agenttransport.Snapshot
}

func (r *resolver) ResolveFinalizedAgent(ctx context.Context, id string) (agenttransport.Snapshot, error) {
	if _, ok := ctx.Deadline(); !ok {
		return agenttransport.Snapshot{}, errors.New("missing read bound")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.state[id]
	if !ok {
		return agenttransport.Snapshot{}, nil
	}
	s.State = proto.Clone(s.State).(*nativev1.NativeStateV1)
	return s, nil
}

type person struct {
	agent     string
	transport ed25519.PrivateKey
	wire      []byte
	holder    ed25519.PrivateKey
	keyID     [32]byte
	revoked   atomic.Bool
	cardDown  atomic.Bool
}
type credentials struct {
	owner      Credential
	contact    Credential
	hasContact bool
	dropped    int
	mu         sync.Mutex
}

func (c *credentials) Owner(context.Context, string) (Credential, error) { return c.owner, nil }
func (c *credentials) Contact(context.Context, string, string) (Credential, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.contact, c.hasContact, nil
}
func (c *credentials) DropContact(context.Context, string, string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dropped++
	c.hasContact = false
	return nil
}

type fakeRelay struct {
	outcomes    []error
	beforeAck   func([32]byte) error
	lists       int
	mu          sync.Mutex
	envelopes   map[[32]byte][]byte
	deposits    [][]byte
	creds       [][]byte
	acked       map[[32]byte]bool
	fetches     int
	error       error
	saveOnError bool
	before      func([]byte)
	listError   error
	entries     []agentpacketrelay.V2MailboxEntry
	ackError    error
}

func newRelay() *fakeRelay {
	return &fakeRelay{envelopes: map[[32]byte][]byte{}, acked: map[[32]byte]bool{}}
}
func (r *fakeRelay) Describe(context.Context) (agentpacketrelay.V2Description, error) {
	return agentpacketrelay.V2Description{Schema: "tos.service.agent-packet-relay.relay.v2", MaxTTLSeconds: 3600}, nil
}
func (r *fakeRelay) Deposit(_ context.Context, raw, wire []byte, _ ed25519.PrivateKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.before != nil {
		r.before(raw)
	}
	r.deposits = append(r.deposits, bytes.Clone(raw))
	r.creds = append(r.creds, bytes.Clone(wire))
	h, err := agentpacketseal.ParseEnvelope(raw)
	if err != nil {
		return err
	}
	if len(r.outcomes) > 0 {
		r.error = r.outcomes[0]
		r.outcomes = r.outcomes[1:]
	}
	if r.error == nil || r.saveOnError {
		r.envelopes[h.EnvelopeID] = bytes.Clone(raw)
	}
	return r.error
}
func (r *fakeRelay) List(_ context.Context, agent string, _ []byte, _ ed25519.PrivateKey) ([]agentpacketrelay.V2MailboxEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lists++
	if r.listError != nil {
		return nil, r.listError
	}
	if r.entries != nil {
		return append([]agentpacketrelay.V2MailboxEntry(nil), r.entries...), nil
	}
	out := []agentpacketrelay.V2MailboxEntry{}
	for _, raw := range r.envelopes {
		h, err := agentpacketseal.ParseEnvelope(raw)
		if err != nil {
			return nil, err
		}
		if h.RecipientAgentID == agent && !r.acked[h.EnvelopeID] {
			out = append(out, agentpacketrelay.V2MailboxEntry{EnvelopeID: h.EnvelopeID, RecipientKeyID: h.RecipientKeyID, Size: uint32(len(raw)), ReceivedAtUnix: start, ExpiresAtUnix: h.ExpiresAtUnix, Lane: "stranger"})
		}
	}
	return out, nil
}
func (r *fakeRelay) ListWait(ctx context.Context, a string, w []byte, h ed25519.PrivateKey, _ int) ([]agentpacketrelay.V2MailboxEntry, error) {
	return r.List(ctx, a, w, h)
}
func (r *fakeRelay) Fetch(_ context.Context, _ string, id [32]byte, _ []byte, _ ed25519.PrivateKey) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fetches++
	raw, ok := r.envelopes[id]
	if !ok {
		return nil, errors.New("missing")
	}
	return bytes.Clone(raw), nil
}
func (r *fakeRelay) Acknowledge(_ context.Context, _ string, secret [32]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.beforeAck != nil {
		if err := r.beforeAck(secret); err != nil {
			return err
		}
	}
	if r.ackError != nil {
		return r.ackError
	}
	id := agentpacketseal.AckHash(secret)
	r.acked[id] = true
	return nil
}

type fixture struct {
	t          *testing.T
	clock      *clock
	resolver   *resolver
	verifier   *agenttransport.Verifier
	alice, bob *person
	relays     map[string]*fakeRelay
	config     Config
	auth       *credentials
	lane       *Lane
	inboxMu    sync.Mutex
	inbox      map[[32]byte][]byte
}

func testKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, clock: &clock{}, resolver: &resolver{state: map[string]agenttransport.Snapshot{}}, relays: map[string]*fakeRelay{relayOne: newRelay(), relayTwo: newRelay()}, inbox: map[[32]byte][]byte{}}
	f.clock.n.Store(int64(start))
	network := &nativev1.NetworkDomain{NetworkId: "tos:global-id:3", GenesisRootHash: "65735247a371030abe811aeac0afe357301ce90e161450d26f88b4beb5b4c366", GenesisFileHash: "c3860fe196a2a1b5e4e74a9cf9448624a353ce68a8c4c5f6413347586d688769"}
	code := "tvm-cell-sha256:" + fmt.Sprintf("%064x", 3)
	makePerson := func(label string) *person {
		p := &person{agent: agentpacketseal.AgentID(sha256.Sum256([]byte(label))), transport: testKey(label + "transport"), holder: testKey(label + "holder")}
		public := make([]byte, mldsa44.PublicKeySize)
		public[0] = 1
		var err error
		p.keyID, err = mldsa44.KeyID(public)
		if err != nil {
			t.Fatal(err)
		}
		policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, Controllers: []*nativev1.ControllerV1{{KeyId: mldsa44.KeyIDText(p.keyID), Mldsa44PublicKey: public, Weight: 1, PurposeMask: 15, Recovery: true}}}
		cell, err := nativecore.PolicyCell(policy)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := agentpacketseal.AgentDigest(p.agent)
		if err != nil {
			t.Fatal(err)
		}
		d := agenttransport.Delegation{AgentDigest: digest, Purposes: agenttransport.Relay | agenttransport.Hints, AuthorizationEpoch: 1, NotBefore: start - 1, NotAfter: start + 29*86400, MaxCredentialSeconds: 604800}
		copy(d.PolicyHash[:], cell.Hash())
		copy(d.TransportKey[:], p.transport[32:])
		p.wire, err = d.Encode()
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(p.wire)
		epoch := uint64(1)
		state := &nativev1.NativeStateV1{Network: proto.Clone(network).(*nativev1.NetworkDomain), TvmStateHash: "tvm-cell-sha256:" + fmt.Sprintf("%064x", 4), Reference: &nativev1.ChainReference{FinalizedCheckpoint: 10, Account: "0:test", ContractCodeHash: code, TransactionHash: "sha256:" + fmt.Sprintf("%064x", 5)}, State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: p.agent, Policy: policy, DelegationDigests: []string{"sha256:" + hex.EncodeToString(hash[:])}}}}
		f.resolver.state[p.agent] = agenttransport.Snapshot{State: state, CurrentEpoch: &epoch, EpochCheckpoint: 10, AdmissionEpochs: map[[32]byte]uint64{hash: 1}}
		return p
	}
	f.alice = makePerson("alice")
	f.bob = makePerson("bob")
	var err error
	f.verifier, err = agenttransport.NewVerifier(agenttransport.Config{Mode: agenttransport.TestNetworkEpochAware, Network: network, ChainPolicy: agenttransport.ChainPolicy{RegistryCodeHashes: []string{code}, Locator: location("0:test")}, Clock: f.clock}, f.resolver)
	if err != nil {
		t.Fatal(err)
	}
	credential := func(p *person, contact bool) Credential {
		ops := agenttransport.OperationList | agenttransport.OperationFetch | agenttransport.OperationDeposit | agenttransport.OperationPublish | agenttransport.OperationRevoke
		caveats := []agenttransport.Caveat{agenttransport.NotBeforeCaveat(start - 1), agenttransport.NotAfterCaveat(start + 3600)}
		if contact {
			ops = agenttransport.OperationDeposit
		}
		caveats = append(caveats, agenttransport.OperationsCaveat(ops))
		raw, err := agenttransport.IssueCredential(p.wire, p.transport, p.holder.Public().(ed25519.PublicKey), caveats)
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewCredential(raw, p.holder)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	f.auth = &credentials{owner: credential(f.alice, false), contact: credential(f.bob, true)}
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	f.config = Config{StateDir: stateDir, AgentID: f.alice.agent, Kind: Rail, Relays: []string{relayOne, relayTwo}, Delegation: f.alice.wire, Verifier: f.verifier, Credentials: f.auth, Now: f.clock.Now, Relay: func(url string) (Relay, error) {
		r, ok := f.relays[url]
		if !ok {
			return nil, ErrUnavailable
		}
		return r, nil
	}}
	f.config.VerifyCard = f.verifyCard
	f.config.SignCard = func(_ context.Context, card agentpacketseal.KeyCard) ([]byte, error) {
		return f.cardPacket(f.alice, card), nil
	}
	f.config.VerifyPacket = func(_ context.Context, p agentpacket.Packet) error {
		if len(p.Signature) != mldsa44.SignatureSize || p.Signature[0] != 17 {
			return ErrRefused
		}
		return nil
	}
	f.config.Store = func(_ context.Context, raw []byte) error {
		f.inboxMu.Lock()
		defer f.inboxMu.Unlock()
		sum := sha256.Sum256(raw)
		f.inbox[sum] = bytes.Clone(raw)
		return nil
	}
	f.lane, err = Open(t.Context(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err = f.lane.Close(); err != nil {
			t.Error(err)
		}
	})
	return f
}
func (f *fixture) cardPacket(p *person, card agentpacketseal.KeyCard) []byte {
	f.t.Helper()
	var nonce [32]byte
	nonce[0] = 1
	packet, err := agentpacketseal.KeyCardPacket(p.agent, p.keyID, 1, nonce, card.NotBeforeUnix, card)
	if err != nil {
		f.t.Fatal(err)
	}
	packet.Signature = bytes.Repeat([]byte{17}, mldsa44.SignatureSize)
	raw, err := agentpacket.EncodeJSON(packet)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}
func (f *fixture) verifyCard(_ context.Context, raw []byte, now time.Time) (agentpacketseal.RecipientKey, agentpacketseal.KeyCard, error) {
	p, err := agentpacket.DecodeJSON(raw)
	if err != nil {
		return agentpacketseal.RecipientKey{}, agentpacketseal.KeyCard{}, ErrRefused
	}
	who := f.alice
	if p.SenderAgentID == f.bob.agent {
		who = f.bob
	} else if p.SenderAgentID != f.alice.agent {
		return agentpacketseal.RecipientKey{}, agentpacketseal.KeyCard{}, ErrRefused
	}
	if who.cardDown.Load() {
		return agentpacketseal.RecipientKey{}, agentpacketseal.KeyCard{}, ErrUnavailable
	}
	card, err := agentpacketseal.DecodeKeyCard(p.Payload)
	if err != nil || p.RecipientAgentID != agentpacketseal.KeyCardAudience || p.CapabilityID != agentpacketseal.KeyCardCapability || p.QuoteCommitment != "" || agentpacketseal.CheckKeyCardTime(card, now) != nil || len(p.Signature) != mldsa44.SignatureSize || p.Signature[0] != 17 || who.revoked.Load() {
		return agentpacketseal.RecipientKey{}, card, ErrRefused
	}
	return agentpacketseal.RecipientKey{AgentID: p.SenderAgentID, KeyID: card.KeyID, PublicKey: card.PublicKey}, card, nil
}
func (f *fixture) message(from, to *person) []byte {
	f.t.Helper()
	p := agentpacket.Packet{SenderAgentID: from.agent, RecipientAgentID: to.agent, CapabilityID: "cap_" + fmt.Sprintf("%064x", 6), Sequence: 1, CreatedAtUnix: uint64(f.clock.Now().Unix()), SenderKeyID: from.keyID, Payload: []byte("message"), Signature: bytes.Repeat([]byte{17}, mldsa44.SignatureSize)}
	p.Nonce[0] = 1
	raw, err := agentpacket.EncodeJSON(p)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}
func (f *fixture) peerRoute() Route {
	f.t.Helper()
	seed, err := agentpacketseal.GenerateSeed()
	if err != nil {
		f.t.Fatal(err)
	}
	defer clear(seed)
	key, err := agentpacketseal.NewPrivateKey(f.bob.agent, seed)
	if err != nil {
		f.t.Fatal(err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		f.t.Fatal(err)
	}
	card := agentpacketseal.KeyCard{PublicKey: pub, KeyID: key.KeyID, NotBeforeUnix: start - 1, NotAfterUnix: start + 7*86400, Relays: []string{"https://127.0.0.1:19999"}}
	d, err := agenttransport.DecodeDelegation(f.bob.wire)
	if err != nil {
		f.t.Fatal(err)
	}
	h, err := agenttransport.SignHint(agenttransport.Hint{Delegation: d, IssuedAt: start, ExpiresAt: start + 21600, Relays: []string{relayOne, relayTwo}}, f.bob.transport)
	if err != nil {
		f.t.Fatal(err)
	}
	raw, err := (agenttransport.HintRecord{Hint: h, Objects: []agenttransport.HintObject{}}).Encode()
	if err != nil {
		f.t.Fatal(err)
	}
	return Route{HintRecord: raw, CardPacket: f.cardPacket(f.bob, card)}
}
