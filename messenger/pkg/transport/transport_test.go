package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentcarrier"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"google.golang.org/protobuf/proto"
)

const start = uint64(1_800_000_000)

type clock struct{ n atomic.Int64 }

func (c *clock) Now() time.Time { return time.Unix(c.n.Load(), 0) }

type location string

func (l location) Locate(string, string) (string, error) { return string(l), nil }

type finalized struct {
	mu    sync.Mutex
	state map[string]agenttransport.Snapshot
}

func (r *finalized) ResolveFinalizedAgent(_ context.Context, id string) (agenttransport.Snapshot, error) {
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
	keyID     [32]byte
}

// inbound stands for the daemon: it records the frames it is handed and
// answers with response for copies.
type inbound struct {
	mu       sync.Mutex
	frames   [][]byte
	acks     [][]byte
	response func(frame []byte) carrierapi.Response
}

func (i *inbound) Deliver(_ context.Context, _ string, frame []byte) carrierapi.Response {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.frames = append(i.frames, bytes.Clone(frame))
	return i.response(frame)
}

func (i *inbound) DeliveryAck(_ context.Context, _ string, frame []byte) carrierapi.Response {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.acks = append(i.acks, bytes.Clone(frame))
	return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultApplied}
}

type world struct {
	t         *testing.T
	clock     *clock
	verifier  *agenttransport.Verifier
	relays    []string
	clients   map[string]*agentpacketrelay.V2Client
	people    map[string]*person
	admission map[string]map[string]bool
	mu        sync.Mutex
}

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func testKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func newWorld(t *testing.T, names ...string) *world {
	t.Helper()
	w := &world{t: t, clock: &clock{}, clients: map[string]*agentpacketrelay.V2Client{}, people: map[string]*person{},
		admission: map[string]map[string]bool{}}
	w.clock.n.Store(int64(start))
	network := &nativev1.NetworkDomain{NetworkId: "tos:global-id:3",
		GenesisRootHash: "65735247a371030abe811aeac0afe357301ce90e161450d26f88b4beb5b4c366",
		GenesisFileHash: "c3860fe196a2a1b5e4e74a9cf9448624a353ce68a8c4c5f6413347586d688769"}
	code := "tvm-cell-sha256:" + fmt.Sprintf("%064x", 3)
	chain := &finalized{state: map[string]agenttransport.Snapshot{}}
	for _, name := range names {
		p := &person{agent: agentpacketseal.AgentID(sha256.Sum256([]byte(name))), transport: testKey(name + "transport")}
		public := make([]byte, mldsa44.PublicKeySize)
		public[0] = byte(len(w.people) + 1)
		var err error
		if p.keyID, err = mldsa44.KeyID(public); err != nil {
			t.Fatal(err)
		}
		policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, Controllers: []*nativev1.ControllerV1{{
			KeyId: mldsa44.KeyIDText(p.keyID), Mldsa44PublicKey: public, Weight: 1, PurposeMask: 15, Recovery: true}}}
		cell, err := nativecore.PolicyCell(policy)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := agentpacketseal.AgentDigest(p.agent)
		if err != nil {
			t.Fatal(err)
		}
		d := agenttransport.Delegation{AgentDigest: digest, Purposes: agenttransport.Relay | agenttransport.Hints,
			AuthorizationEpoch: 1, NotBefore: start - 1, NotAfter: start + 29*86400, MaxCredentialSeconds: 604800}
		copy(d.PolicyHash[:], cell.Hash())
		copy(d.TransportKey[:], p.transport[32:])
		if p.wire, err = d.Encode(); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(p.wire)
		epoch := uint64(1)
		state := &nativev1.NativeStateV1{Network: proto.Clone(network).(*nativev1.NetworkDomain),
			TvmStateHash: "tvm-cell-sha256:" + fmt.Sprintf("%064x", 4),
			Reference: &nativev1.ChainReference{FinalizedCheckpoint: 10, Account: "0:test", ContractCodeHash: code,
				TransactionHash: "sha256:" + fmt.Sprintf("%064x", 5)},
			State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: p.agent, Policy: policy,
				DelegationDigests: []string{"sha256:" + hex.EncodeToString(hash[:])}}}}
		chain.state[p.agent] = agenttransport.Snapshot{State: state, CurrentEpoch: &epoch, EpochCheckpoint: 10,
			AdmissionEpochs: map[[32]byte]uint64{hash: 1}}
		w.people[name] = p
		w.admission[name] = map[string]bool{}
	}
	var err error
	w.verifier, err = agenttransport.NewVerifier(agenttransport.Config{Mode: agenttransport.TestNetworkEpochAware,
		Network: network, ChainPolicy: agenttransport.ChainPolicy{RegistryCodeHashes: []string{code}, Locator: location("0:test")},
		Clock: w.clock}, chain)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	var servers []*httptest.Server
	for index := 0; index < 2; index++ {
		store, err := agentpacketrelay.OpenV2Store(filepath.Join(privateDir(t), "relay"), agentpacketrelay.DefaultV2Limits(1024, 64<<20),
			w.clock.Now(), agentpacketrelay.V2OpenOptions{})
		if err != nil {
			t.Fatal(err)
		}
		var handler atomic.Pointer[agentpacketrelay.V2Server]
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			handler.Load().ServeHTTP(rw, r)
		}))
		server.StartTLS()
		url := "https://" + server.Listener.Addr().String()
		h, err := agentpacketrelay.NewV2Server(agentpacketrelay.V2ServerConfig{Store: store, URL: url, Verifier: w.verifier,
			Now: w.clock.Now, Directory: true})
		if err != nil {
			t.Fatal(err)
		}
		handler.Store(h)
		pool.AddCert(server.Certificate())
		servers = append(servers, server)
		w.relays = append(w.relays, url)
		t.Cleanup(func() {
			server.Close()
			if err := store.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	trusting := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	for _, url := range w.relays {
		client, err := agentpacketrelay.NewV2Client(url, trusting, w.clock.Now)
		if err != nil {
			t.Fatal(err)
		}
		w.clients[url] = client
	}
	return w
}

func (w *world) cardPacket(p *person, card agentpacketseal.KeyCard) []byte {
	var nonce [32]byte
	nonce[0] = 1
	packet, err := agentpacketseal.KeyCardPacket(p.agent, p.keyID, 1, nonce, card.NotBeforeUnix, card)
	if err != nil {
		w.t.Fatal(err)
	}
	packet.Signature = bytes.Repeat([]byte{17}, mldsa44.SignatureSize)
	raw, err := agentpacket.EncodeJSON(packet)
	if err != nil {
		w.t.Fatal(err)
	}
	return raw
}

func (w *world) verifyCard(_ context.Context, raw []byte, now time.Time) (agentpacketseal.RecipientKey, agentpacketseal.KeyCard, error) {
	p, err := agentpacket.DecodeJSON(raw)
	if err != nil {
		return agentpacketseal.RecipientKey{}, agentpacketseal.KeyCard{}, agentcarrier.ErrRefused
	}
	card, err := agentpacketseal.DecodeKeyCard(p.Payload)
	if err != nil || p.RecipientAgentID != agentpacketseal.KeyCardAudience || agentpacketseal.CheckKeyCardTime(card, now) != nil ||
		len(p.Signature) != mldsa44.SignatureSize || p.Signature[0] != 17 {
		return agentpacketseal.RecipientKey{}, card, agentcarrier.ErrRefused
	}
	return agentpacketseal.RecipientKey{AgentID: p.SenderAgentID, KeyID: card.KeyID, PublicKey: card.PublicKey}, card, nil
}

func (w *world) admit(who, peer string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.admission[who][w.people[peer].agent] = true
}

func (w *world) open(name string, handler Inbound) *Builtin {
	w.t.Helper()
	p := w.people[name]
	stateDir := filepath.Join(privateDir(w.t), name)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		w.t.Fatal(err)
	}
	relay := func(url string) (*agentpacketrelay.V2Client, error) {
		client, ok := w.clients[url]
		if !ok {
			return nil, agentcarrier.ErrUnavailable
		}
		return client, nil
	}
	b, err := Open(w.t.Context(), Config{
		Lane: agentcarrier.Config{StateDir: stateDir, AgentID: p.agent, Relays: w.relays, Delegation: p.wire,
			Verifier: w.verifier, Now: w.clock.Now,
			Relay: func(url string) (agentcarrier.Relay, error) { return relay(url) },
			SignCard: func(_ context.Context, card agentpacketseal.KeyCard) ([]byte, error) {
				return w.cardPacket(p, card), nil
			},
			VerifyCard: w.verifyCard},
		TransportKey: p.transport,
		VerifyPacket: func(_ context.Context, packet agentpacket.Packet) error {
			if len(packet.Signature) != mldsa44.SignatureSize || packet.Signature[0] != 17 {
				return agentcarrier.ErrRefused
			}
			return nil
		},
		SignPacket: func(_ context.Context, packet agentpacket.Packet) (agentpacket.Packet, error) {
			packet.SenderKeyID = p.keyID
			packet.Signature = bytes.Repeat([]byte{17}, mldsa44.SignatureSize)
			return packet, nil
		},
		Admitted: func(_ context.Context, peer string) error {
			w.mu.Lock()
			defer w.mu.Unlock()
			if w.admission[name][peer] {
				return nil
			}
			return agentcarrier.ErrRefused
		},
		Resolver: agentcarrier.ResolverConfig{Directories: w.relays,
			Directory: func(url string) (agentcarrier.Directory, error) { return relay(url) }},
		Publication: agentcarrier.PublicationConfig{Directories: w.relays,
			Directory: func(url string) (agentcarrier.Directory, error) { return relay(url) }},
		CardPath: filepath.Join(stateDir, "card.json"),
	})
	if err != nil {
		w.t.Fatal(err)
	}
	b.Attach(handler)
	w.t.Cleanup(func() {
		if err := b.Close(); err != nil {
			w.t.Error(err)
		}
	})
	b.Refresh(w.t.Context())
	return b
}

func card(t *testing.T, b *Builtin) []byte {
	t.Helper()
	raw, err := os.ReadFile(b.config.CardPath)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func copyFrame(t *testing.T, cardPacket, credential []byte, seed [32]byte) []byte {
	t.Helper()
	object, err := relayframe.EncodeCopy(relayframe.Copy{EventID: "evt_" + strings.Repeat("1", 64),
		SessionID: "ses_" + strings.Repeat("2", 64), RecipientEndpointID: "mep_" + strings.Repeat("3", 64),
		RecipientDeviceID: "dev_" + strings.Repeat("4", 64), ConversationID: "conv_" + strings.Repeat("5", 64),
		Ciphertext: bytes.Repeat([]byte{0x6a}, 64), ExpiresAtUnix: start + 86400})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := relayframe.Encode(relayframe.Frame{Kind: relayframe.KindCopy, PartCount: 1, Card: cardPacket,
		Evidence: []byte("evidence opaque to the lane"), Credential: credential, HolderSeed: seed, Part: object})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func ackFrame(t *testing.T) []byte {
	t.Helper()
	raw, err := relayframe.Encode(relayframe.Frame{Kind: relayframe.KindDeliveryAck, PartCount: 1,
		Evidence: []byte("evidence opaque to the lane"), Part: []byte("ack object opaque to the lane")})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func answer(outcome string, ack []byte) func([]byte) carrierapi.Response {
	return func([]byte) carrierapi.Response {
		return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultAck,
			AckFrameBase64: base64.StdEncoding.EncodeToString(ack), AckOutcome: outcome}
	}
}

// eventually polls the lane until check holds.
func eventually(t *testing.T, b *Builtin, check func() bool) {
	t.Helper()
	for attempt := 0; attempt < 50; attempt++ {
		if _, err := b.lane.Poll(t.Context()); err != nil {
			t.Fatal(err)
		}
		if check() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the condition did not hold")
}

// A copy crosses two real V2 relays from one builtin lane to another; the
// receiver's daemon answers with an acknowledgement that crosses back. The
// copy's contact credential is taken because the receiver admitted the
// sender, and a later copy then uses it.
func TestCopyCrossesTwoRelaysAndTheAdmittedCredentialIsTaken(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	w.admit("alice", "bob")
	w.admit("bob", "alice")
	bobInbound := &inbound{}
	aliceInbound := &inbound{response: answer("accepted", ackFrame(t))}
	bob := w.open("bob", bobInbound)
	alice := w.open("alice", aliceInbound)
	bobInbound.response = answer("accepted", ackFrame(t))
	if err := alice.LearnCard(t.Context(), w.people["bob"].agent, card(t, bob)); err != nil {
		t.Fatal(err)
	}
	credential, seed, ok, err := alice.ContactCredential(t.Context(), w.people["bob"].agent)
	if err != nil || !ok || len(credential) == 0 {
		t.Fatalf("alice issues bob a contact credential: %v %v", ok, err)
	}
	frame := copyFrame(t, card(t, alice), credential, seed)
	response, err := alice.Carry(t.Context(), w.people["bob"].agent, "copy-1", "", start+3600, frame)
	if err != nil || response.Result != carrierapi.ResultCarried || response.RelayTTLSeconds == 0 {
		t.Fatalf("carry: %+v %v", response, err)
	}
	again, err := alice.Carry(t.Context(), w.people["bob"].agent, "copy-1", "", start+3600, frame)
	if err != nil || again.Result != carrierapi.ResultCarried {
		t.Fatalf("an exact retry is carried again without a new signature: %+v %v", again, err)
	}
	eventually(t, bob, func() bool {
		bobInbound.mu.Lock()
		defer bobInbound.mu.Unlock()
		return len(bobInbound.frames) > 0
	})
	if !bytes.Equal(bobInbound.frames[0], frame) {
		t.Fatal("the daemon was handed other bytes than the sender carried")
	}
	// Each copy that reaches the daemon offers the credential again; it is
	// stored once per peer and relay set.
	if taken, refused := bob.Credentials(); taken < 1 || refused != 0 {
		t.Fatalf("credential taken %d refused %d: %v", taken, refused, bob.lastRefusal)
	}
	if _, held, err := bob.credentials.Contact(t.Context(), w.people["alice"].agent, w.relays[0]); err != nil || !held {
		t.Fatalf("bob holds alice's contact credential: %v %v", held, err)
	}
	eventually(t, alice, func() bool {
		aliceInbound.mu.Lock()
		defer aliceInbound.mu.Unlock()
		return len(aliceInbound.acks) > 0
	})
	if err := alice.Settled(t.Context(), w.people["bob"].agent, []string{"copy-1"}); err != nil {
		t.Fatal(err)
	}
	record, found, err := alice.journal.get("copy-1")
	if err != nil || !found || !record.Settled {
		t.Fatalf("the acknowledged copy is settled: %+v %v %v", record, found, err)
	}
}

// The receiver refuses a contact credential unless its daemon admitted the
// frame's sender: a refused copy, and a sender business admission no longer
// covers, leave no credential stored, while the frame itself is still handed
// over.
func TestCredentialIsRefusedWithoutAdmission(t *testing.T) {
	for _, test := range []struct {
		name    string
		outcome string
		admit   bool
	}{
		{"rejected copy", "rejected", true},
		{"peer not admitted", "accepted", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := newWorld(t, "alice", "bob")
			w.admit("alice", "bob")
			if test.admit {
				w.admit("bob", "alice")
			}
			bobInbound := &inbound{response: answer(test.outcome, ackFrame(t))}
			bob := w.open("bob", bobInbound)
			alice := w.open("alice", &inbound{response: answer("accepted", ackFrame(t))})
			// Bob can route to Alice already, so only admission decides.
			if err := bob.LearnCard(t.Context(), w.people["alice"].agent, card(t, alice)); err != nil {
				t.Fatal(err)
			}
			if _, err := bob.resolver.Resolve(t.Context(), w.people["alice"].agent, bob.contact(w.people["alice"].agent)); err != nil {
				t.Fatal(err)
			}
			if err := alice.LearnCard(t.Context(), w.people["bob"].agent, card(t, bob)); err != nil {
				t.Fatal(err)
			}
			credential, seed, ok, err := alice.ContactCredential(t.Context(), w.people["bob"].agent)
			if err != nil || !ok {
				t.Fatal(err)
			}
			frame := copyFrame(t, card(t, alice), credential, seed)
			if response, err := alice.Carry(t.Context(), w.people["bob"].agent, "copy-1", "", start+3600, frame); err != nil ||
				response.Result != carrierapi.ResultCarried {
				t.Fatalf("carry: %+v %v", response, err)
			}
			eventually(t, bob, func() bool {
				bobInbound.mu.Lock()
				defer bobInbound.mu.Unlock()
				return len(bobInbound.frames) > 0
			})
			// Each copy that reaches the daemon refuses its credential; the
			// daemon's journal, not the lane, applies a copy once.
			if taken, refused := bob.Credentials(); taken != 0 || refused < 1 {
				t.Fatalf("credential taken %d refused %d", taken, refused)
			}
			if _, held, err := bob.credentials.Contact(t.Context(), w.people["alice"].agent, w.relays[0]); err != nil || held {
				t.Fatalf("a refused credential was stored: %v %v", held, err)
			}
		})
	}
}

// A peer that is not admitted is issued no credential, and a frame that is no
// v2 relay frame is never carried.
func TestNoCredentialForStrangersAndOnlyFramesAreCarried(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice := w.open("alice", &inbound{response: answer("accepted", ackFrame(t))})
	if _, _, ok, err := alice.ContactCredential(t.Context(), w.people["bob"].agent); err != nil || ok {
		t.Fatalf("a stranger was issued a credential: %v %v", ok, err)
	}
	response, err := alice.Carry(t.Context(), w.people["bob"].agent, "not-a-frame", "", start+3600, []byte("plain bytes"))
	if err != nil || response.Result != carrierapi.ResultRefused || response.Code != carrierapi.CodeFrameMalformed {
		t.Fatalf("a non-frame was carried: %+v %v", response, err)
	}
	signed := bytes.Repeat([]byte{17}, mldsa44.SignatureSize)
	if err := alice.verifyPacket(t.Context(), agentpacket.Packet{CapabilityID: agentpacketseal.KeyCardCapability,
		Payload: ackFrame(t), Signature: signed}); err != nil {
		t.Fatalf("a signed chat frame failed the lane check: %v", err)
	}
	if err := alice.verifyPacket(t.Context(), agentpacket.Packet{CapabilityID: agentpacketseal.KeyCardCapability,
		Payload: []byte("rail packet"), Signature: signed}); !errors.Is(err, agentcarrier.ErrRefused) {
		t.Fatalf("a packet without a relay frame passed the lane check: %v", err)
	}
}
