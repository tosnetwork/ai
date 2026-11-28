// Package transport runs the Messenger chat lane in process: the daemon's
// `carrier: builtin` (MESSENGER_TRANSPORT_V2.md 13.1, 14.3). It carries relay
// frames (tos.messaging.relay-frame.v2) as signed, sealed Agent Packets over V2
// relays through protocol/pkg/agentcarrier, which owns keys, cards, the outbox,
// two-copy delivery, re-deposit generations, polling, hint publication and the
// contact credentials of the lane.
//
// The chat lane is its own: its delegation, transport key, HPKE keys, cards,
// hints and state directory are separate from any rail lane of the same Agent.
// The package gains no Messenger authority. It never sees plaintext, keys or
// session state; the daemon re-verifies every frame it is handed, and decides
// which peers are admitted.
package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/protocol/pkg/agentcarrier"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// Lifetimes of the packets the lane signs. A copy lives at most a day less
// five minutes (the relay retention ceiling, so the envelope never outlives
// what a relay may keep); an acknowledgement or evidence frame lives an hour,
// as the carriage deposits it once and recovers a lost one by the next
// generation of the copy it answers.
const (
	PacketLifetime     = 24*time.Hour - 5*time.Minute
	AckPacketLifetime  = time.Hour
	publishInterval    = 5 * time.Minute
	maintenanceEvery   = time.Hour
	waitSeconds        = 25
	maxTrackedDelivery = agentcarrier.MaxOutbox
)

// Inbound is the daemon half of the lane: it applies the frames the lane
// receives. Its answers are carrierapi responses, the daemon's existing
// boundary types, so the external and the builtin carrier share one handler.
type Inbound interface {
	Deliver(ctx context.Context, sender string, frame []byte) carrierapi.Response
	DeliveryAck(ctx context.Context, sender string, frame []byte) carrierapi.Response
}

// Config wires the builtin lane. Lane is the agentcarrier lane configuration
// without its Kind, Credentials, VerifyPacket and Store, which this package
// sets. StateDir holds the lane's directories and this package's own.
type Config struct {
	Lane agentcarrier.Config
	// TransportKey is the lane's transport key, the one its delegation names.
	TransportKey ed25519.PrivateKey
	// VerifyPacket is the finalized sender verification of one Agent Packet
	// (agentpacket.VerifySender against finalized state). Only an error
	// wrapping agentcarrier.ErrRefused is permanent.
	VerifyPacket agentcarrier.PacketVerifier
	// SignPacket signs one packet with the Agent's controller, setting its
	// SenderKeyID: the daemon signs through the pinned tosctl helper.
	SignPacket func(context.Context, agentpacket.Packet) (agentpacket.Packet, error)
	// Admitted is business admission: whether the peer is a contact this
	// installation admitted. Only admitted peers are issued a contact
	// credential, and only their credentials are taken.
	Admitted    agentcarrier.Admission
	Resolver    agentcarrier.ResolverConfig
	Publication agentcarrier.PublicationConfig
	// CardPath receives the lane's current chat card packet, which the
	// daemon's relay evidence sink reads for the frames it builds.
	CardPath string
	// Report receives background failures (publication, polling, deliveries
	// and acknowledgements), which have no caller to return them to.
	Report func(what string, err error)
}

// Fixed transport failures. Nothing a peer or relay sent is repeated in them.
var (
	ErrConfig      = errors.New("messenger transport configuration is invalid")
	ErrNotAttached = errors.New("messenger transport has no inbound handler yet")
)

// Builtin is one open chat lane.
type Builtin struct {
	config      Config
	credentials *agentcarrier.CredentialManager
	lane        *agentcarrier.Lane
	resolver    *agentcarrier.Resolver
	scheduler   *agentcarrier.Scheduler
	publisher   *agentcarrier.Publisher
	journal     *journal

	cardsMu  sync.Mutex
	mu       sync.Mutex
	inbound  Inbound
	drivers  map[string]context.CancelFunc
	runCtx   context.Context
	lastCard []byte
	// taken counts the contact credentials this lane accepted and refused,
	// for the owner surface and tests.
	taken, refused int
}

// Open opens the lane, its credential manager, resolver, scheduler and
// publisher, and the transport's own journal of carried packets.
func Open(ctx context.Context, c Config) (b *Builtin, err error) {
	if ctx == nil || c.VerifyPacket == nil || c.SignPacket == nil || c.Admitted == nil || c.CardPath == "" ||
		c.Lane.StateDir == "" || len(c.TransportKey) != ed25519.PrivateKeySize {
		return nil, ErrConfig
	}
	b = &Builtin{config: c, drivers: map[string]context.CancelFunc{}}
	if b.journal, err = openJournal(c.Lane.StateDir); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, b.Close())
			b = nil
		}
	}()
	lane := c.Lane
	lane.Kind = agentcarrier.Chat
	lane.VerifyPacket = b.verifyPacket
	lane.Store = b.store
	if b.credentials, err = agentcarrier.OpenCredentialManager(ctx, lane, c.TransportKey, c.Admitted); err != nil {
		return nil, err
	}
	lane.Credentials = b.credentials
	if b.lane, err = agentcarrier.Open(ctx, lane); err != nil {
		return nil, err
	}
	if b.resolver, err = agentcarrier.OpenResolver(b.lane, c.Resolver); err != nil {
		return nil, err
	}
	if b.scheduler, err = agentcarrier.OpenScheduler(b.lane, b.resolver); err != nil {
		return nil, err
	}
	if b.publisher, err = agentcarrier.OpenPublisher(b.lane, b.credentials, c.Publication); err != nil {
		return nil, err
	}
	return b, nil
}

// Close stops every driver and closes the lane's stores.
func (b *Builtin) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	for key, cancel := range b.drivers {
		cancel()
		delete(b.drivers, key)
	}
	b.mu.Unlock()
	var errs []error
	if b.publisher != nil {
		errs = append(errs, b.publisher.Close())
	}
	if b.scheduler != nil {
		errs = append(errs, b.scheduler.Close())
	}
	if b.resolver != nil {
		errs = append(errs, b.resolver.Close())
	}
	if b.lane != nil {
		errs = append(errs, b.lane.Close())
	}
	if b.credentials != nil {
		errs = append(errs, b.credentials.Close())
	}
	if b.journal != nil {
		errs = append(errs, b.journal.close())
	}
	return errors.Join(errs...)
}

// Attach installs the daemon's inbound handler. Until it is attached a
// received packet stays at its relay.
func (b *Builtin) Attach(inbound Inbound) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.inbound = inbound
}

func (b *Builtin) now() time.Time {
	if b.config.Lane.Now != nil {
		return b.config.Lane.Now()
	}
	return time.Now()
}

// Credentials reports how many contact credentials the lane took and refused.
func (b *Builtin) Credentials() (taken, refused int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.taken, b.refused
}

// verifyPacket is the lane's packet check in both directions: a chat packet
// carries the chat Capability and a v2 relay frame, nothing else (no rail
// packet travels inside a chat copy), and its sender verifies against
// finalized state.
func (b *Builtin) verifyPacket(ctx context.Context, packet agentpacket.Packet) error {
	if packet.CapabilityID != agentpacketseal.KeyCardCapability || packet.QuoteCommitment != "" ||
		!bytes.HasPrefix(packet.Payload, []byte(canon.DomainRelayFrame)) {
		return agentcarrier.ErrRefused
	}
	if _, err := relayframe.Decode(packet.Payload); err != nil {
		return agentcarrier.ErrRefused
	}
	return b.config.VerifyPacket(ctx, packet)
}

// Carry signs one frame into a packet to the recipient, journals and queues
// it, and answers carried once the first relay accepted its envelope, with
// the smallest relay TTL of the recipient's hint. A key is signed once and
// carries the same bytes on every retry, also across a restart: a retry whose
// frame differs from the journaled one is refused. withdrawKey, when set,
// names the previous generation, settled once this one is carried.
func (b *Builtin) Carry(ctx context.Context, recipient, key, withdrawKey string, expiresAtUnix uint64,
	raw []byte) (carrierapi.Response, error) {
	response, journaled, err := b.carry(ctx, recipient, key, withdrawKey, expiresAtUnix, raw, classOwn)
	if err == nil && journaled != nil && !bytes.Equal(journaled, raw) {
		return carrierapi.Refusal(carrierapi.CodeInvalidRequest), nil
	}
	return response, err
}

// CarryFrame is Carry for a caller that records what it sent: on a key
// already journaled it carries the journaled frame, whatever raw holds now,
// and returns that frame, so the caller records the card, credential and
// evidence actually sent. frame is nil when nothing was journaled.
func (b *Builtin) CarryFrame(ctx context.Context, recipient, key, withdrawKey string, expiresAtUnix uint64,
	raw []byte) (response carrierapi.Response, frame []byte, err error) {
	return b.carry(ctx, recipient, key, withdrawKey, expiresAtUnix, raw, classOwn)
}

func (b *Builtin) carry(ctx context.Context, recipient, key, withdrawKey string, expiresAtUnix uint64,
	raw []byte, class string) (carrierapi.Response, []byte, error) {
	if ctx == nil || b == nil {
		return carrierapi.Retry(), nil, ErrConfig
	}
	frame, err := relayframe.Decode(raw)
	if err != nil {
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed), nil, nil
	}
	if _, err := agentpacketseal.AgentDigest(recipient); err != nil || recipient == b.config.Lane.AgentID ||
		key == "" || len(key) > 128 || len(withdrawKey) > 128 || withdrawKey == key {
		return carrierapi.Refusal(carrierapi.CodeInvalidRequest), nil, nil
	}
	now := uint64(b.now().Unix())
	if expiresAtUnix <= now {
		return carrierapi.Refusal(carrierapi.CodeInvalidRequest), nil, nil
	}
	record, refusal := b.journaled(ctx, recipient, key, withdrawKey, expiresAtUnix, raw, frame.Kind, class, now)
	if refusal != nil {
		return *refusal, nil, nil
	}
	journaledFrame, err := packetPayload(record.Packet)
	if err != nil {
		return carrierapi.Retry(), nil, nil
	}
	if _, err := b.lane.Queue(ctx, key, record.Packet, record.Deadline); err != nil {
		switch {
		case errors.Is(err, agentcarrier.ErrExpired), errors.Is(err, agentcarrier.ErrConflict),
			errors.Is(err, agentcarrier.ErrRefused):
			return carrierapi.Refusal(carrierapi.CodeInvalidRequest), journaledFrame, nil
		case errors.Is(err, agentcarrier.ErrCapacity):
			return carrierapi.Refusal(carrierapi.CodePeerCap), journaledFrame, nil
		default:
			return carrierapi.Retry(), journaledFrame, nil
		}
	}
	view, err := b.scheduler.Advance(ctx, key, b.contact(recipient))
	if err != nil {
		return carrierapi.Retry(), journaledFrame, nil
	}
	b.drive(key, recipient)
	switch {
	case view.Copies > 0:
	case view.State == "abandoned":
		return carrierapi.Refusal(carrierapi.CodeInvalidRequest), journaledFrame, nil
	default:
		return carrierapi.Retry(), journaledFrame, nil
	}
	if record.Withdraw != "" {
		if err := b.settle(ctx, record.Withdraw); err != nil {
			return carrierapi.Retry(), journaledFrame, nil
		}
	}
	ttl := view.TTLSeconds
	if ttl == 0 || ttl > carrierapi.MaxRelayTTLSeconds {
		ttl = carrierapi.MaxRelayTTLSeconds
	}
	return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultCarried,
		RelayTTLSeconds: ttl}, journaledFrame, nil
}

// journaled returns the record of a key, signing and creating it if there is
// none. The key's lock spans the read, the signature and the exclusive
// create, so two callers of one key never sign it twice; a create that finds
// a record another process wrote keeps that record.
func (b *Builtin) journaled(ctx context.Context, recipient, key, withdrawKey string, expiresAtUnix uint64,
	raw []byte, kind uint8, class string, now uint64) (carried, *carrierapi.Response) {
	unlock := b.journal.keys.lock(key)
	defer unlock()
	record, found, err := b.journal.get(key)
	if err != nil {
		retry := carrierapi.Retry()
		return carried{}, &retry
	}
	if !found {
		lifetime := PacketLifetime
		if kind == relayframe.KindDeliveryAck || kind == relayframe.KindEvidence {
			lifetime = AckPacketLifetime
		}
		deadline := min(expiresAtUnix, now+uint64(lifetime/time.Second))
		packet, err := b.sign(ctx, recipient, raw, now)
		if err != nil {
			b.report("sign a packet", err)
			retry := carrierapi.Retry()
			return carried{}, &retry
		}
		// The signed bytes are journaled before the lane sees them, so a retry
		// after a crash queues these bytes again instead of a new signature.
		record, err = b.journal.create(carried{Key: key, Recipient: recipient, Packet: packet, Deadline: deadline,
			Withdraw: withdrawKey, Class: class})
		if err != nil {
			if errors.Is(err, errJournalFull) {
				refusal := carrierapi.Refusal(carrierapi.CodePeerCap)
				return carried{}, &refusal
			}
			retry := carrierapi.Retry()
			return carried{}, &retry
		}
	}
	if record.Recipient != recipient {
		refusal := carrierapi.Refusal(carrierapi.CodeInvalidRequest)
		return carried{}, &refusal
	}
	return record, nil
}

func packetPayload(raw []byte) ([]byte, error) {
	packet, err := agentpacket.DecodeJSON(raw)
	if err != nil {
		return nil, err
	}
	return packet.Payload, nil
}

// sign builds and signs the chat packet that carries one frame. Its sequence
// is above every sequence the lane signed before.
func (b *Builtin) sign(ctx context.Context, recipient string, frame []byte, now uint64) ([]byte, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	nano := b.now().UnixNano()
	if nano < 0 {
		nano = 0
	}
	sequence, err := b.journal.nextSequence(uint64(nano))
	if err != nil {
		return nil, err
	}
	signed, err := b.config.SignPacket(ctx, agentpacket.Packet{SenderAgentID: b.config.Lane.AgentID,
		RecipientAgentID: recipient, CapabilityID: agentpacketseal.KeyCardCapability, Sequence: sequence,
		Nonce: nonce, Payload: bytes.Clone(frame), CreatedAtUnix: now})
	if err != nil {
		return nil, err
	}
	if signed.SenderAgentID != b.config.Lane.AgentID || signed.RecipientAgentID != recipient ||
		!bytes.Equal(signed.Payload, frame) {
		return nil, ErrConfig
	}
	return agentpacket.EncodeJSON(signed)
}

// report hands a background failure to the daemon's report hook.
func (b *Builtin) report(what string, err error) {
	if err == nil || b.config.Report == nil {
		return
	}
	b.config.Report("messenger transport: "+what, err)
}

// Withdraw settles a carried generation: the lane stops depositing it and
// withdraws its stored envelopes from every relay that holds them.
func (b *Builtin) Withdraw(ctx context.Context, recipient, key string) (carrierapi.Response, error) {
	if ctx == nil || b == nil {
		return carrierapi.Retry(), ErrConfig
	}
	record, found, err := b.journal.get(key)
	if err != nil {
		return carrierapi.Retry(), nil
	}
	if !found {
		return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultWithdrawn}, nil
	}
	if record.Recipient != recipient {
		return carrierapi.Refusal(carrierapi.CodeInvalidRequest), nil
	}
	if err := b.settle(ctx, key); err != nil {
		return carrierapi.Retry(), nil
	}
	return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultWithdrawn}, nil
}

// Settled is called once the recipient acknowledged a delivery: every
// generation of it is settled, so no relay receives it again.
func (b *Builtin) Settled(ctx context.Context, recipient string, keys []string) error {
	var errs []error
	for _, key := range keys {
		record, found, err := b.journal.get(key)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !found || record.Recipient != recipient {
			continue
		}
		errs = append(errs, b.settle(ctx, key))
	}
	return errors.Join(errs...)
}

// settle completes one delivery, lets the scheduler withdraw its envelopes and
// stops its driver.
func (b *Builtin) settle(ctx context.Context, key string) error {
	record, found, err := b.journal.get(key)
	if err != nil || !found {
		return err
	}
	if !record.Settled {
		if err := b.lane.Complete(ctx, key); err != nil {
			return err
		}
		record.Settled = true
		if err := b.journal.update(record); err != nil {
			return err
		}
	}
	b.mu.Lock()
	if cancel, ok := b.drivers[key]; ok {
		cancel()
		delete(b.drivers, key)
	}
	b.mu.Unlock()
	_, err = b.scheduler.Advance(ctx, key, b.contact(record.Recipient))
	return err
}

// RoomCards keeps the cards a room's roster taught, each only once it
// verifies as its Agent's chat card. A card is what a delivery is sealed to,
// never a route; the route still comes from the member's hint.
func (b *Builtin) RoomCards(ctx context.Context, _ string, _ uint64, cards []carrierapi.RoomCard) (carrierapi.Response, error) {
	var refused []string
	for _, card := range cards {
		raw, err := base64.StdEncoding.Strict().DecodeString(card.CardBase64)
		if err != nil || b.LearnCard(ctx, card.AgentID, raw) != nil {
			refused = append(refused, card.AgentID)
		}
	}
	return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultApplied,
		RefusedAgentIDs: refused}, nil
}

// ForgetRoomCards keeps the cards: a kept card grants nothing, and another
// admission of the member may still need it.
func (b *Builtin) ForgetRoomCards(context.Context, string, []string) (carrierapi.Response, error) {
	return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultApplied}, nil
}

// ContactCredential returns the contact credential this lane issues to an
// admitted peer, with its holder seed, for the credential field of the frames
// the daemon builds (9.3). ok is false for a peer that is not admitted.
func (b *Builtin) ContactCredential(ctx context.Context, peer string) (wire []byte,
	seed [relayframe.HolderSeedBytes]byte, ok bool, err error) {
	if err := b.config.Admitted(ctx, peer); err != nil {
		if errors.Is(err, agentcarrier.ErrRefused) {
			return nil, seed, false, nil
		}
		return nil, seed, false, err
	}
	credential, err := b.credentials.IssueContact(ctx, peer)
	if err != nil {
		if errors.Is(err, agentcarrier.ErrRefused) {
			return nil, seed, false, nil
		}
		return nil, seed, false, err
	}
	wire, holder, err := credential.ExportForSealedPacket()
	if err != nil || len(holder) != relayframe.HolderSeedBytes || len(wire) > relayframe.MaxCredentialBytes {
		return nil, seed, false, agentcarrier.ErrRefused
	}
	copy(seed[:], holder)
	clear(holder)
	return wire, seed, true, nil
}

// store is the lane's durable inbox: it hands the frame to the daemon and
// returns nil only once the daemon holds a durable result. A permanent
// refusal is reported as agentcarrier.ErrRefused, so the lane settles the
// envelope; anything else leaves it at its relay for the next pass.
func (b *Builtin) store(ctx context.Context, raw []byte) error {
	b.mu.Lock()
	inbound := b.inbound
	b.mu.Unlock()
	if inbound == nil {
		return ErrNotAttached
	}
	packet, err := agentpacket.DecodeJSON(raw)
	if err != nil {
		return agentcarrier.ErrRefused
	}
	frame, err := relayframe.Decode(packet.Payload)
	if err != nil {
		return agentcarrier.ErrRefused
	}
	var response carrierapi.Response
	if frame.Kind == relayframe.KindDeliveryAck {
		response = inbound.DeliveryAck(ctx, packet.SenderAgentID, packet.Payload)
	} else {
		response = inbound.Deliver(ctx, packet.SenderAgentID, packet.Payload)
	}
	switch response.Result {
	case carrierapi.ResultRetry:
		return errors.New("the Messenger daemon asked for a retry")
	case carrierapi.ResultRefused:
		return agentcarrier.ErrRefused
	}
	admitted := admittedFrame(frame.Kind, response)
	if admitted && len(frame.Card) > 0 {
		if err := b.LearnCard(ctx, packet.SenderAgentID, frame.Card); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			b.report("learn a peer card", err)
		}
		// The resolver keeps the verified card beside the peer's hint, so the
		// reply and the credential below route to it. A failure leaves the
		// route to the next delivery's resolution.
		if _, err := b.resolver.Resolve(ctx, packet.SenderAgentID, b.contact(packet.SenderAgentID)); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			b.report("resolve a peer", err)
		}
	}
	if len(frame.Credential) > 0 {
		b.takeCredential(ctx, raw, admitted)
	}
	if response.Result == carrierapi.ResultAck && response.AckFrameBase64 != "" {
		b.reply(ctx, packet, response.AckFrameBase64)
	}
	return nil
}

// takeCredential accepts a contact credential only from a frame the daemon
// admitted (a copy it accepted, holds or already had, or an admitted
// evidence frame), and only through the credential manager, which verifies
// the packet again, requires business admission and that the credential's
// delegation names the packet's sender. Anything else is refused and not
// stored; the frame itself stands.
func (b *Builtin) takeCredential(ctx context.Context, raw []byte, admitted bool) {
	err := agentcarrier.ErrRefused
	if admitted {
		err = b.credentials.ReceiveContact(ctx, raw, extractCredential, b.resolver)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		b.taken++
	} else {
		b.refused++
	}
}

// admittedFrame reports whether the daemon admitted the frame's sender for
// it: a copy it accepted, holds or already had, an admitted evidence frame,
// or a delivery acknowledgement it verified and applied. An acknowledgement
// is how a peer that only receives returns its credential; the credential
// manager still requires business admission of the peer.
func admittedFrame(kind uint8, response carrierapi.Response) bool {
	if kind == relayframe.KindDeliveryAck {
		return response.Result == carrierapi.ResultApplied
	}
	return response.Result == carrierapi.ResultAdmitted ||
		response.Result == carrierapi.ResultAck && (response.AckOutcome == "accepted" ||
			response.AckOutcome == "duplicate" || response.AckOutcome == "held")
}

// extractCredential decodes only the credential field of a verified packet.
func extractCredential(packet agentpacket.Packet) ([]byte, []byte, error) {
	frame, err := relayframe.Decode(packet.Payload)
	if err != nil || len(frame.Credential) == 0 {
		return nil, nil, agentcarrier.ErrRefused
	}
	seed := bytes.Clone(frame.HolderSeed[:])
	return frame.Credential, seed, nil
}

// reply carries the daemon's acknowledgement frame back to the packet's
// sender. Its key derives from the answered packet's nonce, so each
// generation of a copy gets one acknowledgement and a retry the same one.
//
// An acknowledgement to a peer that is not admitted is a stranger's record:
// it takes the strangers' bounded share of the journal, never the capacity
// of this installation's own sends.
func (b *Builtin) reply(ctx context.Context, packet agentpacket.Packet, encoded string) {
	frame, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		b.report("decode an acknowledgement", err)
		return
	}
	class := classOwn
	if err := b.config.Admitted(ctx, packet.SenderAgentID); err != nil {
		class = classStrangerAck
	}
	key := "ack-" + canon.Digest(append([]byte(canon.DomainBuiltinAckKey), packet.Nonce[:]...))[len("sha256:"):]
	expires := uint64(b.now().Add(AckPacketLifetime).Unix())
	background := b.background()
	go func() {
		call, cancel := context.WithTimeout(background, agentcarrier.CallTimeout)
		defer cancel()
		// A second delivery of one packet answers under the same key; the
		// acknowledgement journaled first is the one carried.
		response, _, err := b.carry(call, packet.SenderAgentID, key, "", expires, frame, class)
		if err != nil {
			b.report("carry an acknowledgement", err)
		} else if response.Result == carrierapi.ResultRefused {
			b.report("carry an acknowledgement", errors.New("refused: "+string(response.Code)))
		}
	}()
}

func (b *Builtin) background() context.Context {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.runCtx != nil {
		return b.runCtx
	}
	return context.Background()
}

// drive runs the scheduler for one delivery until it is complete, abandoned
// or settled: the second copy and later generations are its, not the
// daemon's call.
func (b *Builtin) drive(key, recipient string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.runCtx == nil {
		return
	}
	if _, running := b.drivers[key]; running || len(b.drivers) >= maxTrackedDelivery {
		return
	}
	ctx, cancel := context.WithCancel(b.runCtx)
	b.drivers[key] = cancel
	go func() {
		defer func() {
			b.mu.Lock()
			delete(b.drivers, key)
			b.mu.Unlock()
			cancel()
		}()
		contact := func(context.Context) (agentcarrier.Route, error) { return b.contact(recipient), nil }
		if _, err := b.scheduler.RunDelivery(ctx, key, contact); err != nil && ctx.Err() == nil {
			b.report("drive a delivery", err)
		}
	}()
}

// Run polls the lane's relays, publishes its hint, refreshes its card file,
// resumes the drivers of journaled deliveries and prunes, until ctx ends.
func (b *Builtin) Run(ctx context.Context) error {
	b.mu.Lock()
	b.runCtx = ctx
	b.mu.Unlock()
	records, err := b.journal.list()
	if err != nil {
		return err
	}
	for _, record := range records {
		if !record.Settled && record.Deadline > uint64(b.now().Unix()) {
			b.drive(record.Key, record.Recipient)
		}
	}
	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		b.waitLoop(ctx)
	}()
	b.refresh(ctx)
	poll := time.NewTicker(agentcarrier.PollInterval)
	publish := time.NewTicker(publishInterval)
	maintain := time.NewTicker(maintenanceEvery)
	defer poll.Stop()
	defer publish.Stop()
	defer maintain.Stop()
	for {
		select {
		case <-ctx.Done():
			group.Wait()
			return ctx.Err()
		case <-poll.C:
			if _, err := b.lane.Poll(ctx); err != nil && ctx.Err() == nil {
				b.report("poll the relays", err)
			}
		case <-publish.C:
			b.refresh(ctx)
		case <-maintain.C:
			b.prune(ctx)
		}
	}
}

// waitLoop keeps one long poll at the lane's first relay.
func (b *Builtin) waitLoop(ctx context.Context) {
	relays := b.config.Lane.Relays
	if len(relays) == 0 {
		return
	}
	for ctx.Err() == nil {
		if _, err := b.lane.Wait(ctx, relays[0], waitSeconds); err != nil {
			if ctx.Err() == nil {
				b.report("wait at the first relay", err)
			}
			timer := time.NewTimer(agentcarrier.PollInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}

// refresh republishes the hint when due and writes the current card for the
// daemon's frames.
func (b *Builtin) refresh(ctx context.Context) {
	if _, err := b.publisher.Publish(ctx); err != nil {
		if ctx.Err() != nil {
			return
		}
		b.report("publish the hint", err)
	}
	card, err := b.lane.CurrentCard(ctx)
	if err != nil {
		b.report("read the current card", err)
		return
	}
	b.mu.Lock()
	same := bytes.Equal(card.Packet, b.lastCard)
	b.mu.Unlock()
	if same {
		return
	}
	if err := writePrivate(b.config.CardPath, card.Packet); err != nil {
		b.report("write the card file", err)
		return
	}
	b.mu.Lock()
	b.lastCard = bytes.Clone(card.Packet)
	b.mu.Unlock()
}

// Refresh runs one publication and card refresh now.
func (b *Builtin) Refresh(ctx context.Context) { b.refresh(ctx) }

// prune drops settled or expired records of every store.
func (b *Builtin) prune(ctx context.Context) {
	now := uint64(b.now().Unix())
	if records, err := b.journal.list(); err == nil {
		for _, record := range records {
			if record.Deadline+uint64(agentcarrier.KeyRetention/time.Second) <= now {
				if err := b.journal.remove(record.Key); err != nil {
					continue
				}
			}
		}
	}
	for _, prune := range []func(context.Context) error{b.scheduler.Prune, b.lane.Prune, b.credentials.Prune} {
		if err := prune(ctx); err != nil && ctx.Err() != nil {
			return
		}
	}
}
