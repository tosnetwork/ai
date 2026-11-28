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
	"encoding/json"
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
	// signs counts packet signatures; signDelay widens the window between
	// a key's read and its record, as a slow signing helper does.
	signs     atomic.Int64
	signDelay time.Duration
	// public holds, per person, the relay identity evidence its hint
	// discloses as public contact; a person absent publishes none.
	public map[string]*atomic.Pointer[[]byte]
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
	publication := agentcarrier.PublicationConfig{Directories: w.relays,
		Directory: func(url string) (agentcarrier.Directory, error) { return relay(url) }}
	var evidence func() ([]byte, error)
	if current, ok := w.public[name]; ok {
		publication.PublicContact = true
		publication.VerifyEvidence = func(_ context.Context, kind agenttransport.HintObjectKind, raw []byte) (string, error) {
			if kind != agenttransport.MessengerEvidence || !bytes.HasPrefix(raw, []byte("evidence of ")) {
				return "", agentcarrier.ErrRefused
			}
			return p.agent, nil
		}
		evidence = func() ([]byte, error) { return bytes.Clone(*current.Load()), nil }
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
			w.signs.Add(1)
			time.Sleep(w.signDelay)
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
		Publication: publication,
		CardPath:    filepath.Join(stateDir, "card.json"),
		Evidence:    evidence,
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
		t.Fatalf("credential taken %d refused %d", taken, refused)
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

// Callers of one key at once sign it once: a reply and a second poll of the
// same envelope, or a retry racing its first attempt, all carry the one
// journaled packet. A caller that records what it sent gets the journaled
// frame back; one that expects its own bytes exactly is refused.
func TestOneKeyIsSignedOnceUnderConcurrentCallers(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	w.admit("alice", "bob")
	bob := w.open("bob", &inbound{response: answer("accepted", ackFrame(t))})
	alice := w.open("alice", &inbound{response: answer("accepted", ackFrame(t))})
	if err := alice.LearnCard(t.Context(), w.people["bob"].agent, card(t, bob)); err != nil {
		t.Fatal(err)
	}
	w.signDelay = 20 * time.Millisecond
	before := w.signs.Load()
	first := copyFrame(t, card(t, alice), nil, [32]byte{})
	credential, seed, _, err := alice.ContactCredential(t.Context(), w.people["bob"].agent)
	if err != nil {
		t.Fatal(err)
	}
	second := copyFrame(t, card(t, alice), credential, seed)
	var group sync.WaitGroup
	frames := make([][]byte, 16)
	for index := range frames {
		group.Add(1)
		go func() {
			defer group.Done()
			raw := first
			if index%2 == 1 {
				raw = second
			}
			response, sent, err := alice.CarryFrame(t.Context(), w.people["bob"].agent, "copy-1", "", start+3600, raw)
			if err != nil || response.Result != carrierapi.ResultCarried {
				t.Errorf("carry %d: %+v %v", index, response, err)
			}
			frames[index] = sent
		}()
	}
	group.Wait()
	if signs := w.signs.Load() - before; signs != 1 {
		t.Fatalf("one key was signed %d times", signs)
	}
	for index, sent := range frames {
		if !bytes.Equal(sent, frames[0]) {
			t.Fatalf("caller %d was told another frame was carried", index)
		}
	}
	other := first
	if bytes.Equal(frames[0], first) {
		other = second
	}
	if response, err := alice.Carry(t.Context(), w.people["bob"].agent, "copy-1", "", start+3600, other); err != nil ||
		response.Result != carrierapi.ResultRefused || response.Code != carrierapi.CodeInvalidRequest {
		t.Fatalf("other bytes under a journaled key were carried: %+v %v", response, err)
	}
	if response, err := alice.Carry(t.Context(), w.people["bob"].agent, "copy-1", "", start+3600, frames[0]); err != nil ||
		response.Result != carrierapi.ResultCarried {
		t.Fatalf("the journaled bytes were refused: %+v %v", response, err)
	}
}

// ackCredentialFrame is a delivery ack frame carrying a contact credential.
func ackCredentialFrame(t *testing.T, credential []byte, seed [32]byte) []byte {
	t.Helper()
	raw, err := relayframe.Encode(relayframe.Frame{Kind: relayframe.KindDeliveryAck, PartCount: 1,
		Evidence: []byte("evidence opaque to the lane"), Credential: credential, HolderSeed: seed,
		Part: []byte("ack object opaque to the lane")})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func heldSeed(t *testing.T, b *Builtin, peer, relay string) ([]byte, bool) {
	t.Helper()
	held, ok, err := b.credentials.Contact(t.Context(), peer, relay)
	if err != nil || !ok {
		return nil, false
	}
	_, seed, err := held.ExportForSealedPacket()
	if err != nil {
		t.Fatal(err)
	}
	return seed, true
}

// A peer that only receives returns its credential on its acks: the sender
// takes it from an ack its daemon applied and deposits to the peer on the
// contact lane from then on; a renewed credential on later acks replaces it.
func TestAReceiveOnlyPeerReturnsItsCredentialOnItsAcks(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	w.admit("alice", "bob")
	w.admit("bob", "alice")
	bobInbound := &inbound{}
	aliceInbound := &inbound{response: answer("accepted", ackFrame(t))}
	bob := w.open("bob", bobInbound)
	alice := w.open("alice", aliceInbound)
	bobAgent, aliceAgent := w.people["bob"].agent, w.people["alice"].agent
	if err := alice.LearnCard(t.Context(), bobAgent, card(t, bob)); err != nil {
		t.Fatal(err)
	}
	if err := bob.LearnCard(t.Context(), aliceAgent, card(t, alice)); err != nil {
		t.Fatal(err)
	}
	if _, held := heldSeed(t, alice, bobAgent, w.relays[0]); held {
		t.Fatal("alice holds a credential before any ack")
	}
	credential, seed, ok, err := bob.ContactCredential(t.Context(), aliceAgent)
	if err != nil || !ok {
		t.Fatalf("bob issues alice a credential: %v %v", ok, err)
	}
	bobInbound.mu.Lock()
	bobInbound.response = answer("accepted", ackCredentialFrame(t, credential, seed))
	bobInbound.mu.Unlock()
	if response, err := alice.Carry(t.Context(), bobAgent, "copy-1", "", start+3600,
		copyFrame(t, card(t, alice), nil, [32]byte{})); err != nil || response.Result != carrierapi.ResultCarried {
		t.Fatalf("carry: %+v %v", response, err)
	}
	eventually(t, bob, func() bool {
		bobInbound.mu.Lock()
		defer bobInbound.mu.Unlock()
		return len(bobInbound.frames) > 0
	})
	eventually(t, alice, func() bool {
		_, held := heldSeed(t, alice, bobAgent, w.relays[0])
		return held
	})
	got, _ := heldSeed(t, alice, bobAgent, w.relays[0])
	if !bytes.Equal(got, seed[:]) {
		t.Fatal("alice holds another credential than bob's ack carried")
	}

	// A re-issued credential on bob's later acks replaces the one alice
	// holds. A second lane state of bob's issues it, as a renewal would:
	// another credential of the same Agent.
	reissuer := w.open("bob", &inbound{response: answer("accepted", ackFrame(t))})
	if err := reissuer.LearnCard(t.Context(), aliceAgent, card(t, alice)); err != nil {
		t.Fatal(err)
	}
	fresh, freshSeed, ok, err := reissuer.ContactCredential(t.Context(), aliceAgent)
	if err != nil || !ok || freshSeed == seed || bytes.Equal(fresh, credential) {
		t.Fatalf("a second credential of bob: %v %v", ok, err)
	}
	bobInbound.mu.Lock()
	bobInbound.response = answer("accepted", ackCredentialFrame(t, fresh, freshSeed))
	bobInbound.mu.Unlock()
	if response, err := alice.Carry(t.Context(), bobAgent, "copy-2", "", start+3600,
		copyFrame(t, card(t, alice), nil, [32]byte{})); err != nil || response.Result != carrierapi.ResultCarried {
		t.Fatalf("second carry: %+v %v", response, err)
	}
	eventually(t, bob, func() bool {
		bobInbound.mu.Lock()
		defer bobInbound.mu.Unlock()
		return len(bobInbound.frames) > 1
	})
	eventually(t, alice, func() bool {
		got, held := heldSeed(t, alice, bobAgent, w.relays[0])
		return held && bytes.Equal(got, freshSeed[:])
	})
}

// Acknowledgements to peers that are not admitted take their own bounded
// share of the journal and a share per peer: a flood of them never leaves
// this installation's own sends without capacity.
func TestStrangerAcksNeverTakeTheCapacityOfOwnSends(t *testing.T) {
	j, err := openJournal(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	record := func(key, recipient, class string) carried {
		return carried{Key: key, Recipient: recipient, Packet: []byte("signed"), Deadline: start + 60, Class: class}
	}
	taken := 0
	for peer := 0; peer < 2*maxStrangerAcks/maxStrangerAcksPerPeer; peer++ {
		for index := 0; index < maxStrangerAcksPerPeer+2; index++ {
			_, err := j.create(record(fmt.Sprintf("ack-%d-%d", peer, index), fmt.Sprintf("stranger-%d", peer), classStrangerAck), start)
			switch {
			case err == nil:
				taken++
			case !errors.Is(err, errJournalFull):
				t.Fatal(err)
			}
		}
		if held := j.liveStrangerAcks(fmt.Sprintf("stranger-%d", peer), start); held > maxStrangerAcksPerPeer {
			t.Fatalf("a stranger holds %d records", held)
		}
	}
	if taken != maxStrangerAcks {
		t.Fatalf("strangers took %d records, their share is %d", taken, maxStrangerAcks)
	}
	for index := 0; index < maxTrackedDelivery-maxStrangerAcks; index++ {
		if _, err := j.create(record(fmt.Sprintf("copy-%d", index), "contact", classOwn), start); err != nil {
			t.Fatalf("own send %d refused after the flood: %v", index, err)
		}
	}
	reopened, err := openJournal(filepath.Dir(filepath.Dir(j.root)))
	if err != nil || reopened.strangers != maxStrangerAcks || len(reopened.index) != maxTrackedDelivery {
		t.Fatalf("the bounds do not survive a restart: %v", err)
	}
}

// An acknowledgement to a peer this installation has not admitted is
// journaled as a stranger's record.
func TestAnAckToAStrangerIsJournaledAsOne(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	w.admit("alice", "bob")
	bobInbound := &inbound{response: answer("held", ackFrame(t))}
	bob := w.open("bob", bobInbound)
	alice := w.open("alice", &inbound{response: answer("accepted", ackFrame(t))})
	if err := alice.LearnCard(t.Context(), w.people["bob"].agent, card(t, bob)); err != nil {
		t.Fatal(err)
	}
	if err := bob.LearnCard(t.Context(), w.people["alice"].agent, card(t, alice)); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.resolver.Resolve(t.Context(), w.people["alice"].agent, bob.contact(w.people["alice"].agent)); err != nil {
		t.Fatal(err)
	}
	if response, err := alice.Carry(t.Context(), w.people["bob"].agent, "copy-1", "", start+3600,
		copyFrame(t, card(t, alice), nil, [32]byte{})); err != nil || response.Result != carrierapi.ResultCarried {
		t.Fatalf("carry: %+v %v", response, err)
	}
	eventually(t, bob, func() bool {
		records, err := bob.journal.list()
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range records {
			if record.Recipient == w.people["alice"].agent {
				if record.Class != classStrangerAck {
					t.Fatalf("an ack to a stranger is journaled as an own send: %+v", record.Class)
				}
				return true
			}
		}
		return false
	})
}

// A key's record is created once: a second create of the key, as another
// process writing the same key would do, keeps and returns the first bytes.
func TestAJournalRecordIsCreatedExclusively(t *testing.T) {
	j, err := openJournal(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	first := carried{Key: "copy-1", Recipient: "peer", Packet: []byte("first signature"), Deadline: start + 60}
	if kept, err := j.create(first, start); err != nil || !bytes.Equal(kept.Packet, first.Packet) {
		t.Fatalf("first create: %v", err)
	}
	second := first
	second.Packet = []byte("second signature")
	kept, err := j.create(second, start)
	if err != nil || !bytes.Equal(kept.Packet, first.Packet) {
		t.Fatalf("a second create replaced the first bytes: %q %v", kept.Packet, err)
	}
	// Another process's file appears between this one's read and its link.
	if created, err := writeExclusive(filepath.Join(j.root, recordName("copy-1")), []byte("other")); err != nil || created {
		t.Fatalf("an existing record was overwritten: %v %v", created, err)
	}
	stored, found, err := j.get("copy-1")
	if err != nil || !found || !bytes.Equal(stored.Packet, first.Packet) {
		t.Fatalf("stored record: %q %v %v", stored.Packet, found, err)
	}
}

// Packet sequences only increase: a clock that steps back, and a restart,
// still yield a sequence above the last one signed.
func TestPacketSequencesNeverGoBack(t *testing.T) {
	dir := privateDir(t)
	j, err := openJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := j.nextSequence(1000); err != nil || got != 1000 {
		t.Fatalf("first sequence %d %v", got, err)
	}
	if got, err := j.nextSequence(500); err != nil || got != 1001 {
		t.Fatalf("sequence after the clock stepped back: %d %v", got, err)
	}
	reopened, err := openJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.nextSequence(10); err != nil || got != 1002 {
		t.Fatalf("sequence after a restart: %d %v", got, err)
	}
}

// The cap per stranger counts acknowledgements still in flight: once a
// stranger's acks are past their deadline it is answered again, while every
// record still counts against the strangers' share until the lane drops it.
func TestAStrangersCapCountsOnlyLiveAcks(t *testing.T) {
	j, err := openJournal(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	ack := func(index int, deadline uint64) carried {
		return carried{Key: fmt.Sprintf("ack-%d", index), Recipient: "stranger", Packet: []byte("signed"),
			Deadline: deadline, Class: classStrangerAck}
	}
	for index := 0; index < maxStrangerAcksPerPeer; index++ {
		if _, err := j.create(ack(index, start+3600), start); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := j.create(ack(maxStrangerAcksPerPeer, start+3600), start); !errors.Is(err, errJournalFull) {
		t.Fatalf("a ninth live ack to one stranger: %v", err)
	}
	later := start + 3601
	if _, err := j.create(ack(maxStrangerAcksPerPeer, later+3600), later); err != nil {
		t.Fatalf("an ack after the earlier ones expired: %v", err)
	}
	if j.strangers != maxStrangerAcksPerPeer+1 {
		t.Fatalf("expired acks no longer count against the share: %d", j.strangers)
	}
}

// Temporary files a crash left behind are removed when the journal opens.
func TestTheJournalSweepsTemporaryFilesAtOpen(t *testing.T) {
	dir := privateDir(t)
	j, err := openJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	leftovers := []string{filepath.Join(j.root, ".tmp-1"), filepath.Join(j.cards, ".tmp-2"),
		filepath.Join(filepath.Dir(j.root), ".tmp-3")}
	for _, path := range leftovers {
		if err := os.WriteFile(path, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := openJournal(dir); err != nil {
		t.Fatal(err)
	}
	for _, path := range leftovers {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s survived the open: %v", path, err)
		}
	}
}

// The lane's outbox is as large as the journal: own sends beyond the lane's
// default outbox are queued, not refused at the lane's capacity.
func TestOwnSendsAreNotCappedBelowTheJournal(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice := w.open("alice", &inbound{response: answer("accepted", ackFrame(t))})
	frame := copyFrame(t, card(t, alice), nil, [32]byte{})
	for index := 0; index < agentcarrier.DefaultOutbox+8; index++ {
		response, err := alice.Carry(t.Context(), w.people["bob"].agent, fmt.Sprintf("copy-%d", index), "", start+3600, frame)
		if err != nil || response.Result == carrierapi.ResultRefused {
			t.Fatalf("own send %d: %+v %v", index, response, err)
		}
	}
}

// A record another process wrote is counted once this process meets it, so
// the in-memory bounds never undercount what is on disk.
func TestARecordFoundOnDiskIsCounted(t *testing.T) {
	j, err := openJournal(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	other := carried{Key: "ack-1", Recipient: "stranger", Packet: []byte("signed elsewhere"), Deadline: start + 60,
		Class: classStrangerAck}
	raw, err := json.Marshal(other)
	if err != nil {
		t.Fatal(err)
	}
	if created, err := writeExclusive(filepath.Join(j.root, recordName(other.Key)), raw); err != nil || !created {
		t.Fatalf("write the other process's record: %v %v", created, err)
	}
	if _, err := j.create(carried{Key: "ack-1", Recipient: "stranger", Packet: []byte("signed here"), Deadline: start + 60,
		Class: classStrangerAck}, start); err != nil {
		t.Fatal(err)
	}
	if len(j.index) != 1 || j.strangers != 1 {
		t.Fatalf("the found record is not counted: %d records, %d strangers", len(j.index), j.strangers)
	}
}

// An Agent that consents to public contact discloses its chat card and relay
// identity evidence in its hint: a sender resolves it by Agent ID alone, with
// no contact file, and the publication follows renewed evidence. An Agent
// without that consent discloses neither.
func TestAPublicContactIsResolvedByAgentIDAlone(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	current := &atomic.Pointer[[]byte]{}
	first := []byte("evidence of alice, first")
	current.Store(&first)
	w.public = map[string]*atomic.Pointer[[]byte]{"alice": current}
	alice := w.open("alice", &inbound{response: answer("accepted", ackFrame(t))})
	bob := w.open("bob", &inbound{response: answer("accepted", ackFrame(t))})
	cardPacket, evidence, err := bob.ResolvePublicContact(t.Context(), w.people["alice"].agent)
	if err != nil || !bytes.Equal(evidence, first) || !bytes.Equal(cardPacket, card(t, alice)) {
		t.Fatalf("resolve alice by Agent ID: %q %v", evidence, err)
	}
	// Without bob's card or evidence his hint gives no route at all.
	if _, evidence, err := alice.ResolvePublicContact(t.Context(), w.people["bob"].agent); err == nil || evidence != nil {
		t.Fatalf("bob published a contact without consent: %q %v", evidence, err)
	}
	renewed := []byte("evidence of alice, renewed")
	current.Store(&renewed)
	w.clock.n.Add(int64(publishInterval / time.Second))
	alice.Refresh(t.Context())
	other := w.open("bob", &inbound{response: answer("accepted", ackFrame(t))})
	if _, evidence, err := other.ResolvePublicContact(t.Context(), w.people["alice"].agent); err != nil ||
		!bytes.Equal(evidence, renewed) {
		t.Fatalf("the publication did not follow the renewed evidence: %q %v", evidence, err)
	}
}
