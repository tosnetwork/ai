package daemon

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/securefile"
	"github.com/tosnetwork/ai/messenger/pkg/admission"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/directory"
	"github.com/tosnetwork/ai/messenger/pkg/dispatch"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/messenger/pkg/transport"
)

const (
	// relayEvidenceRetry is how long a copy whose recipient evidence failed
	// waits before CheckPeer runs again.
	relayEvidenceRetry = time.Minute
	// relayCapRetry is how long a copy over the in-flight cap waits.
	relayCapRetry = 30 * time.Second
	// relayRetentionWindow is how long a relay may still hold an envelope:
	// the protocol ceiling, whatever a relay advertises, so the in-flight
	// count never undercounts.
	relayRetentionWindow = 24 * time.Hour
	// relayRedepositPercent is the share of the reported relay TTL after
	// which a carried envelope is deposited again.
	relayRedepositPercent = 80
	// relayResponseWindow is the per (peer, own descriptor) response limit.
	relayResponseWindow = time.Hour
	// relayDemandWindow is the least time a demand for a peer's evidence
	// keeps its request outstanding without being refreshed: the caller that
	// needs the evidence (a roster waiting to be built) refreshes it on every
	// retry, so the need ends by itself within the window once the caller
	// stops. The window is at least two maintenance passes (demandWindow), so
	// one late pass, or a sweep interval longer than this, does not end it.
	relayDemandWindow = 2 * relayEvidenceRetry
	// descriptorExpiredBase and descriptorExpiredCap bound the wait after a
	// descriptor-expired ack when this node's evidence is not newer.
	descriptorExpiredBase = 30 * time.Second
	descriptorExpiredCap  = 5 * time.Minute
	// maxAckSkew is how far ahead of this clock an ack may be dated.
	maxAckSkew = 5 * time.Minute
)

// evidenceCodes are the deferral codes that mean the recipient's stored
// evidence failed CheckPeer, which is what an evidence pull can repair.
var evidenceCodes = map[fault.Code]struct{}{
	fault.CodeDescriptorExpired: {}, fault.CodeDescriptorUnbound: {}, fault.CodeDelegationUncommitted: {},
	fault.CodeDelegationExpired: {}, fault.CodeDeviceRevoked: {}, fault.CodeSenderMismatch: {},
	fault.CodeOversized: {}, fault.CodePayloadMalformed: {},
}

// relayCarrier deposits one frame; *carrierapi.Client is the production one.
type relayCarrier interface {
	Carry(ctx context.Context, recipientAgentID, idempotencyKey, withdrawKey string,
		expiresAtUnix uint64, frame []byte) (carrierapi.Response, error)
	// Withdraw removes a deposited envelope from the recipient's relays.
	Withdraw(ctx context.Context, recipientAgentID, idempotencyKey string) (carrierapi.Response, error)
}

// frameCarrier is a carrier that journals the frame of a key: on a retry it
// carries the frame first journaled and returns it (the builtin lane).
type frameCarrier interface {
	CarryFrame(ctx context.Context, recipientAgentID, idempotencyKey, withdrawKey string,
		expiresAtUnix uint64, frame []byte) (carrierapi.Response, []byte, error)
}

// carry deposits one frame and returns the frame actually carried: the
// journaled one of a frame carrier, else the one given.
func (r *relayRuntime) carry(ctx context.Context, peer, key, withdraw string, expires uint64,
	frame []byte) (carrierapi.Response, []byte, error) {
	if journaling, ok := r.carrier.(frameCarrier); ok {
		response, sent, err := journaling.CarryFrame(ctx, peer, key, withdraw, expires, frame)
		if sent == nil {
			sent = frame
		}
		return response, sent, err
	}
	response, err := r.carrier.Carry(ctx, peer, key, withdraw, expires, frame)
	return response, frame, err
}

// sentGeneration is what a carried frame proves was sent: its evidence's
// descriptor, and the digests of the card and credential it carries.
func sentGeneration(raw []byte) (eventlog.RelayGeneration, error) {
	frame, err := relayframe.Decode(raw)
	if err != nil {
		return eventlog.RelayGeneration{}, err
	}
	digest, issued, err := directory.EvidenceDescriptor(frame.Evidence)
	if err != nil {
		return eventlog.RelayGeneration{}, err
	}
	generation := eventlog.RelayGeneration{DescriptorDigest: digest, DescriptorIssuedAtUnix: issued}
	if len(frame.Card) > 0 {
		generation.CardDigest = canon.Digest(frame.Card)
	}
	if len(frame.Credential) > 0 {
		generation.CredentialDigest = canon.Digest(frame.Credential)
	}
	return generation, nil
}

// relayRuntime is the daemon half of relay carriage.
type relayRuntime struct {
	daemon   *Daemon
	verifier *directory.RelayVerifier
	sink     *directory.RelayEvidenceSink
	carrier  relayCarrier
	server   *carrierapi.Server
	listener net.Listener
	signer   crypto.Signer
	interval time.Duration

	// ttlReported is set once a carried answer without a valid relay TTL
	// has been reported, so a carrier built against an older API shows on
	// the owner surface once per process rather than only as unreachable.
	ttlReported atomic.Bool

	// pulls serializes read-modify-write of evidence pull records.
	pulls sync.Mutex
	// demands holds, per peer, the last time a caller with no object of its
	// own waiting on the peer's evidence asked for it (guarded by pulls). It
	// is in memory only: after a restart the caller's next retry asks again.
	demands map[string]time.Time
	// sweep is the maintenance pass interval run was started with; zero
	// before run (tests drive the passes themselves).
	sweep time.Duration

	// index is the open-delivery index of the sweep in progress.
	indexMutex sync.Mutex
	index      *peerIndex

	// rooms receives kind-3 room objects; nil when private rooms over the
	// relay are not configured, and then kind 3 is not carried.
	rooms *roomRuntime

	// builtin is the in-process chat lane, or nil with an external carrier
	// (then server and listener carry the carrier socket).
	builtin *transport.Builtin
}

// builtinOpenTimeout bounds opening the in-process lane at startup.
const builtinOpenTimeout = 2 * time.Minute

// credentialCarrier is a carrier that issues this installation's contact
// credentials to admitted peers, for the credential field of its frames.
type credentialCarrier interface {
	ContactCredential(ctx context.Context, peer string) ([]byte, [relayframe.HolderSeedBytes]byte, bool, error)
}

// settlingCarrier is a carrier that keeps depositing a copy until told the
// recipient acknowledged it.
type settlingCarrier interface {
	Settled(ctx context.Context, recipient string, keys []string) error
}

// cardLearner is a carrier that keeps admitted peers' cards for sealing.
type cardLearner interface {
	LearnCard(ctx context.Context, peer string, card []byte) error
}

// configureRelayCarriage installs the relay route: the carrier client, the
// seal gate, the inbound carrier socket, and the same-Agent startup check.
func (d *Daemon) configureRelayCarriage(sink *directory.RelayEvidenceSink) error {
	relay := d.config.RelayCarriage
	if d == nil || relay == nil || d.dispatch == nil || d.discovery == nil || d.discovery.relay == nil ||
		d.prekeys == nil || d.prekeys.signer == nil || d.admission == nil || sink == nil {
		return errors.New("relay carriage dependencies are incomplete")
	}
	var builtin *transport.Builtin
	if relay.Carrier == CarrierBuiltin {
		ctx, cancel := context.WithTimeout(context.Background(), builtinOpenTimeout)
		defer cancel()
		opened, err := d.openBuiltinCarrier(ctx)
		if err != nil {
			return errors.New("open the builtin chat lane: " + err.Error())
		}
		// The lane writes its current chat card for the frames built below.
		opened.Refresh(ctx)
		builtin = opened
	}
	// The carrier and this installation must be one Agent: the local chat
	// card is the carrier's, and it must name this daemon's Agent.
	card, err := securefile.ReadBoundedRegular(relay.CardPath, relayframe.MaxCardBytes)
	if err != nil {
		return errors.New("read local chat card: " + err.Error())
	}
	if err := checkCardShape(card, d.config.AgentID); err != nil {
		return errors.Join(errors.New("local chat card does not belong to this installation's Agent: "+err.Error()),
			builtin.Close())
	}
	var carrier interface {
		relayCarrier
		roomCarrier
	}
	if builtin != nil {
		carrier = builtin
	} else {
		client, err := carrierapi.NewClient(relay.CarrySocketPath, relay.Timeout())
		if err != nil {
			return err
		}
		carrier = client
	}
	if err := d.installRelayRuntime(sink, carrier, relay.RedepositInterval(), relay.Timeout()); err != nil {
		return errors.Join(err, builtin.Close())
	}
	if builtin != nil {
		builtin.Attach(d.relay)
		d.relay.builtin = builtin
		if importer, ok := d.discovery.runner.(*contactImporter); ok {
			importer.learner = builtin
		}
	}
	if relay.MLSDriverPath == "" {
		return nil
	}
	driver := &group.OpenMLSSidecar{Command: []string{relay.MLSDriverPath}, Timeout: relay.MLSDriverTimeout()}
	settings, err := d.configuredRoomSettings(driver, carrier)
	if err != nil {
		return err
	}
	return d.installRoomRuntime(settings)
}

// configuredRoomSettings derives the room runtime's settings from the relay
// carriage configuration: the gap delay from the own relays' TTL, and the
// part size, handshake retention and authorization lifetime from the test
// settings, which a production build refuses. Config.Validate checked them
// already; checking again here keeps a production build from running with
// one whatever path built its configuration.
func (d *Daemon) configuredRoomSettings(driver group.AttributedDriver, cards roomCarrier) (roomRuntimeSettings, error) {
	relay := d.config.RelayCarriage
	if relay == nil || relay.MLSDriverPath == "" {
		return roomRuntimeSettings{}, errors.New("private rooms over the relay are not configured")
	}
	gapDelay, err := eventlog.RoomGapDelay(relay.OwnRelayMaxTTL())
	if err != nil {
		return roomRuntimeSettings{}, err
	}
	settings, err := relay.RoomSettings()
	if err != nil {
		return roomRuntimeSettings{}, err
	}
	return roomRuntimeSettings{driver: driver, cards: cards, skew: d.config.RoomClockSkew(),
		retention: settings.HandshakeRetention, gapDelay: gapDelay, partBytes: settings.PartBytes,
		authorization: settings.Authorization}, nil
}

// installRelayRuntime installs the relay sender, seal gate and inbound
// handler around a carrier.
func (d *Daemon) installRelayRuntime(sink *directory.RelayEvidenceSink, carrier relayCarrier,
	interval, timeout time.Duration) error {
	if d == nil || d.dispatch == nil || d.discovery == nil || d.discovery.relay == nil || d.prekeys == nil ||
		d.prekeys.signer == nil || sink == nil || carrier == nil {
		return errors.New("relay carriage dependencies are incomplete")
	}
	if interval < MinRelayRedepositInterval || interval > DefaultRelayRedepositInterval {
		return errors.New("relay re-deposit interval is outside 10m..20h")
	}
	runtime := &relayRuntime{daemon: d, verifier: d.discovery.relay, sink: sink, carrier: carrier,
		signer: d.prekeys.signer, interval: interval}
	server, err := carrierapi.NewServer(runtime, timeout)
	if err != nil {
		return err
	}
	runtime.server = server
	if err := d.dispatch.ConfigureTransport(d.prekeys.suite, relaySender{relay: runtime},
		dispatch.SessionBindings{Journal: d.journal, Identity: d.config.Identity(), Network: d.config.Network()}); err != nil {
		return err
	}
	if err := d.dispatch.ConfigureSealGate(relayGate{relay: runtime}); err != nil {
		return err
	}
	d.relay = runtime
	// Expired evidence held from before a restart frees its slots now.
	runtime.sweepEvidence()
	return nil
}

// sweepEvidence retires committed relay evidence that has expired, so the
// store's peer bound holds live peers (directory.SweepExpiredEvidence).
func (r *relayRuntime) sweepEvidence() {
	report, err := r.verifier.SweepExpiredEvidence(r.now())
	if err != nil {
		r.daemon.report("relay evidence sweep", err)
		return
	}
	if report.Kept > 0 {
		r.daemon.report("relay evidence sweep", errors.New("expired relay evidence kept: the floor store is full of floors inside their horizon"))
	}
}

func (r *relayRuntime) now() time.Time { return r.daemon.clock() }

// peerOf returns the peer Agent of a session.
func (r *relayRuntime) peerOf(sessionID string) (string, error) {
	record, found, err := r.daemon.journal.SessionState(sessionID)
	if err != nil {
		return "", err
	}
	if !found || record.Authority == nil {
		return "", errors.New("relay copy session has no verified authority")
	}
	return record.Authority.PeerAgentID, nil
}

// ownFrame assembles a frame of this node's: its current evidence always,
// and its chat card when required or while the peer has not acknowledged a
// frame that carried it.
func (r *relayRuntime) ownFrame(kind uint8, peer string, part []byte, requireCard bool) ([]byte, eventlog.RelayGeneration, error) {
	evidence, descriptorDigest, issued, err := r.sink.Current()
	if err != nil {
		return nil, eventlog.RelayGeneration{}, err
	}
	generation := eventlog.RelayGeneration{DescriptorDigest: descriptorDigest, DescriptorIssuedAtUnix: issued}
	card, cardErr := r.sink.Card()
	if cardErr != nil && requireCard {
		return nil, eventlog.RelayGeneration{}, errors.New("the local chat card is unavailable")
	}
	pull, _, err := r.daemon.journal.LoadRelayPull(peer)
	if err != nil {
		return nil, eventlog.RelayGeneration{}, err
	}
	var include []byte
	if cardErr == nil {
		digest := canon.Digest(card)
		if requireCard || pull.AckedCardDigest != digest {
			include = card
			generation.CardDigest = digest
		}
	}
	credential, seed := r.contactCredential(peer, pull, &generation)
	frame, err := relayframe.Encode(relayframe.Frame{Kind: kind, PartIndex: 0, PartCount: 1,
		Card: include, Evidence: evidence, Credential: credential, HolderSeed: seed, Part: part})
	if err != nil {
		return nil, eventlog.RelayGeneration{}, err
	}
	return frame, generation, nil
}

// contactCredential is the contact credential a frame to the peer carries:
// the carrier's credential for an admitted peer, until the peer acknowledged a
// frame that carried it (transport 9.3, like the card). A carrier without
// credentials, a peer that is not admitted, or a failure to issue one leaves
// the frame without a credential; the peer then deposits on the stranger lane.
func (r *relayRuntime) contactCredential(peer string, pull eventlog.RelayPull,
	generation *eventlog.RelayGeneration) ([]byte, [relayframe.HolderSeedBytes]byte) {
	var seed [relayframe.HolderSeedBytes]byte
	issuer, ok := r.carrier.(credentialCarrier)
	if !ok {
		return nil, seed
	}
	ctx, cancel := context.WithTimeout(context.Background(), credentialIssueTimeout)
	defer cancel()
	wire, holder, issued, err := issuer.ContactCredential(ctx, peer)
	if err != nil {
		r.daemon.report("issue contact credential", err)
		return nil, seed
	}
	if !issued {
		return nil, seed
	}
	digest := canon.Digest(wire)
	if pull.AckedCredentialDigest == digest {
		return nil, seed
	}
	generation.CredentialDigest = digest
	return wire, holder
}

// credentialIssueTimeout bounds issuing one contact credential.
const credentialIssueTimeout = 30 * time.Second

// relaySender carries one sealed copy as a kind-1 frame.
type relaySender struct{ relay *relayRuntime }

func (s relaySender) Send(ctx context.Context, message dispatch.Message) error {
	r := s.relay
	if r == nil || ctx == nil {
		return fault.New(fault.CodeInternal, "relay sender is not configured")
	}
	peer, err := r.peerOf(message.SessionID)
	if err != nil {
		return fault.Wrap(fault.CodeInternal, err)
	}
	object, err := relayframe.EncodeCopy(relayframe.Copy{EventID: message.EventID, SessionID: message.SessionID,
		RecipientEndpointID: message.RecipientEndpointID, RecipientDeviceID: message.RecipientDeviceID,
		ConversationID: message.ConversationID, Bootstrap: message.Bootstrap, AdmissionToken: message.AdmissionToken,
		Ciphertext: message.Ciphertext, ExpiresAtUnix: message.ExpiresAtUnix})
	if err != nil {
		return fault.Wrap(fault.CodePayloadMalformed, err)
	}
	// A room.key-package carries the joiner's card always: the authority
	// keeps it for the rosters of the Add (section 11.2).
	requireCard, err := r.carriesKeyPackage(message.DeliveryID)
	if err != nil {
		return fault.Wrap(fault.CodeInternal, err)
	}
	frame, _, err := r.ownFrame(relayframe.KindCopy, peer, object, requireCard)
	if err != nil {
		if errors.Is(err, relayframe.ErrContentTooLarge) {
			return fault.Wrap(fault.CodeContentTooLarge, err)
		}
		return fault.Wrap(fault.CodeInternal, err)
	}
	key, err := relayframe.CopyIdempotencyKey(message.DeliveryID, message.Generation)
	if err != nil {
		return fault.Wrap(fault.CodeInternal, err)
	}
	withdraw := ""
	if message.Generation > 1 {
		withdraw, err = relayframe.CopyIdempotencyKey(message.DeliveryID, message.Generation-1)
		if err != nil {
			return fault.Wrap(fault.CodeInternal, err)
		}
	}
	response, sent, err := r.carry(ctx, peer, key, withdraw, message.ExpiresAtUnix, frame)
	if err != nil {
		return fault.Wrap(fault.CodeUnreachable, err)
	}
	// The generation records what was carried: a retry of a journaled key
	// carries its first frame, not the one built now.
	generation, err := sentGeneration(sent)
	if err != nil {
		return fault.Wrap(fault.CodeInternal, err)
	}
	now := r.now()
	switch response.Result {
	case carrierapi.ResultCarried:
		delay, err := r.redepositDelay(response.RelayTTLSeconds)
		if err != nil {
			if errors.Is(err, carrierapi.ErrRelayTTL) && r.ttlReported.CompareAndSwap(false, true) {
				r.daemon.report("relay carrier reported no valid relay TTL", err)
			}
			// The same generation key is retried; the carrier answers carried
			// again without a new deposit.
			return fault.Wrap(fault.CodeUnreachable, err)
		}
		generation.Generation = message.Generation
		return &dispatch.Carried{Generation: generation, RedepositAt: now.Add(delay)}
	case carrierapi.ResultRetry:
		return fault.New(fault.CodeUnreachable, "the carrier asked for a retry")
	default:
		return carryRefusal(response.Code, now)
	}
}

// carriesKeyPackage reports whether a delivery copy carries a
// room.key-package Event.
func (r *relayRuntime) carriesKeyPackage(deliveryID string) (bool, error) {
	delivery, found, err := r.daemon.journal.LookupDeliveryCopy(deliveryID)
	if err != nil || !found {
		return false, err
	}
	payload, err := delivery.Payload()
	if err != nil {
		return false, err
	}
	event, err := envelope.DecodeEventJSON(payload)
	if err != nil {
		return false, err
	}
	return event.Kind == "room.key-package", nil
}

// redepositDelay is how long an envelope a relay accepted waits before its
// next generation is deposited. It is 80 % of ttlSeconds, the smallest
// retention the relays of the recipient's card advertise (as the carrier
// reported it), so the next generation is stored before every relay drops
// this one. It is never below MinRelayRedepositInterval, so a relay that
// advertises a tiny TTL cannot drive a re-deposit storm (below a 12.5-minute
// TTL the copy is then absent for part of each interval), and never above the
// configured interval.
func (r *relayRuntime) redepositDelay(ttlSeconds uint64) (time.Duration, error) {
	if err := carrierapi.ValidateRelayTTL(ttlSeconds); err != nil {
		return 0, err
	}
	// ttlSeconds is at most 86,400, so neither product can overflow.
	delay := time.Duration(ttlSeconds*relayRedepositPercent/100) * time.Second
	if delay < MinRelayRedepositInterval {
		delay = MinRelayRedepositInterval
	}
	if delay > r.interval {
		delay = r.interval
	}
	return delay, nil
}

// carryRefusal maps a carrier refusal to what the copy does next. A missing
// peer card or the carrier's in-flight cap waits; anything else is a frame
// the carrier will never carry.
func carryRefusal(code carrierapi.Code, now time.Time) error {
	switch code {
	case carrierapi.CodeNoPeerCard:
		return &dispatch.Deferred{Code: fault.CodeNoRouteAdvertised, Until: now.Add(relayEvidenceRetry)}
	case carrierapi.CodePeerCap:
		return &dispatch.Deferred{Code: fault.CodeRateLimited, Until: now.Add(relayCapRetry)}
	case carrierapi.CodePacketTooLarge:
		return fault.New(fault.CodeContentTooLarge, "the carrier refused the packet size")
	default:
		return fault.New(fault.CodePayloadMalformed, "the carrier refused the frame: "+string(code))
	}
}

// relayGate runs before every content seal and every content re-deposit.
type relayGate struct{ relay *relayRuntime }

func (g relayGate) CheckCopy(ctx context.Context, delivery eventlog.Delivery, sealing bool) error {
	r := g.relay
	if r == nil || ctx == nil {
		return fault.New(fault.CodeInternal, "relay gate is not configured")
	}
	now := r.now()
	peer, err := r.peerOf(delivery.SessionID)
	if err != nil {
		return fault.Wrap(fault.CodeInternal, err)
	}
	payload, err := delivery.Payload()
	if err != nil {
		return fault.Wrap(fault.CodeInternal, err)
	}
	// Room content crosses the relay only as an MLS room object, so a
	// member's removal takes effect; a room-addressed device copy is never
	// sealed or carried here.
	event, err := envelope.DecodeEventJSON(payload)
	if err != nil {
		return fault.Wrap(fault.CodeInternal, err)
	}
	if event.RoomID != "" {
		return fault.New(fault.CodePayloadMalformed, "a room-addressed event crosses the relay only as a room object")
	}
	if sealing {
		// Refused before sealing, so no message key is spent on a copy the
		// relay route cannot carry.
		if err := relayframe.CheckCopyFits(len(payload)); err != nil {
			return err
		}
	}
	pin := directory.Pin{EndpointID: delivery.RecipientEndpointID, DeviceID: delivery.RecipientDeviceID}
	if _, err := r.verifier.CheckStored(peer, pin, now); err != nil {
		code := fault.CodeOf(err)
		if code == fault.CodeInternal {
			return &dispatch.Deferred{Code: fault.CodeUnreachable, Until: now.Add(relayEvidenceRetry)}
		}
		if requestErr := r.requestEvidence(peer, now); requestErr != nil {
			r.daemon.report("relay evidence request", requestErr)
		}
		return &dispatch.Deferred{Code: code, Until: now.Add(relayEvidenceRetry)}
	}
	index, err := r.sweepIndex(now)
	if err != nil {
		return fault.Wrap(fault.CodeInternal, err)
	}
	pull, _, err := r.daemon.journal.LoadRelayPull(peer)
	if err != nil {
		return fault.Wrap(fault.CodeInternal, err)
	}
	// Reading the count and claiming this copy's envelope are one step, so
	// two copies of a sweep cannot both take the last slot.
	r.indexMutex.Lock()
	defer r.indexMutex.Unlock()
	if index.envelopes[peer]+pullEnvelopes(pull, now) >= MaxRelayPeerEnvelopes {
		return &dispatch.Deferred{Code: fault.CodeRateLimited, Until: now.Add(relayCapRetry)}
	}
	// This copy is about to deposit one more envelope; later copies of the
	// same sweep see it.
	index.envelopes[peer]++
	return nil
}

// peerIndex is one pass over the open deliveries, grouped by peer Agent.
type peerIndex struct {
	// envelopes counts this node's copy envelopes a relay may still hold for
	// each peer: a carried copy, a copy moved back to pending whose last
	// deposit may still be stored, and a previous generation that may not be
	// withdrawn yet. It is an early deferral, not the bound: the carrier,
	// which alone sees what each relay still stores (delivery acks, and older
	// generations a longer-TTL relay keeps after a failed withdrawal),
	// enforces the cap with peer-cap.
	envelopes map[string]int
	// onEvidence lists the pending copies held because the peer's stored
	// evidence failed CheckPeer.
	onEvidence map[string][]string
}

// PrepareSweep indexes the open deliveries once for the sweep about to run.
func (g relayGate) PrepareSweep(ctx context.Context, now time.Time) (func(), error) {
	if g.relay == nil || ctx == nil {
		return nil, errors.New("relay gate is not configured")
	}
	index, err := g.relay.buildIndex(now)
	if err != nil {
		return nil, err
	}
	g.relay.indexMutex.Lock()
	g.relay.index = &index
	g.relay.indexMutex.Unlock()
	return func() {
		g.relay.indexMutex.Lock()
		g.relay.index = nil
		g.relay.indexMutex.Unlock()
	}, nil
}

// sweepIndex returns the index of the sweep in progress. Outside a prepared
// sweep it builds a fresh index for this one call and keeps nothing, so no
// later check reads a stale count.
func (r *relayRuntime) sweepIndex(now time.Time) (peerIndex, error) {
	r.indexMutex.Lock()
	current := r.index
	r.indexMutex.Unlock()
	if current != nil {
		return *current, nil
	}
	return r.buildIndex(now)
}

func (r *relayRuntime) buildIndex(now time.Time) (peerIndex, error) {
	open, err := r.daemon.journal.OpenDeliveries()
	if err != nil {
		return peerIndex{}, err
	}
	seconds := uint64(now.Unix())
	window := uint64(relayRetentionWindow / time.Second)
	index := peerIndex{envelopes: map[string]int{}, onEvidence: map[string][]string{}}
	owners := map[string]string{}
	for _, delivery := range open {
		owner, known := owners[delivery.SessionID]
		if !known {
			peer, err := r.peerOf(delivery.SessionID)
			if err != nil {
				continue
			}
			owner = peer
			owners[delivery.SessionID] = peer
		}
		stored := delivery.State == eventlog.StateCarried ||
			delivery.State == eventlog.StatePending && delivery.Generation != 0 && delivery.LastDepositAtUnix+window > seconds
		if stored {
			index.envelopes[owner]++
			if delivery.Generation > 1 && delivery.LastDepositAtUnix+window > seconds {
				index.envelopes[owner]++
			}
		}
		if delivery.State == eventlog.StatePending {
			if _, evidence := evidenceCodes[delivery.LastCode]; evidence {
				index.onEvidence[owner] = append(index.onEvidence[owner], delivery.Key())
			}
		}
	}
	return index, nil
}

// pullEnvelopes counts the evidence envelopes a relay may still hold for a
// peer: the outstanding request, its previous generation, a recent response.
func pullEnvelopes(pull eventlog.RelayPull, now time.Time) int {
	seconds := uint64(now.Unix())
	window := uint64(relayRetentionWindow / time.Second)
	count := 0
	if pull.Requested && pull.RequestGeneration > 0 {
		count++
		if pull.RequestGeneration > 1 && pull.RequestLastAtUnix+window > seconds {
			count++
		}
	}
	if pull.ResponseAtUnix != 0 && pull.ResponseAtUnix+window > seconds {
		count++
	}
	return count
}

// roomWaitsOnEvidence reports whether a room object to a peer waits on the
// peer's stored evidence; without private rooms none does.
func (r *relayRuntime) roomWaitsOnEvidence(peer string, now time.Time) (bool, error) {
	if r.rooms == nil {
		return false, nil
	}
	return r.rooms.waitsOnEvidence(peer, now)
}

// requestEvidence opens the single outstanding evidence request to a peer;
// an already outstanding request is left on its schedule.
func (r *relayRuntime) requestEvidence(peer string, now time.Time) error {
	r.pulls.Lock()
	defer r.pulls.Unlock()
	return r.requestEvidenceLocked(peer, now)
}

// demandEvidence is requestEvidence for a caller that needs a peer's
// evidence before it can build anything (a roster entry), so no copy or
// room object waits on it yet. The demand keeps the request outstanding for
// relayDemandWindow after its last refresh; it never moves the request's
// deposit schedule, so a demand cannot raise the pull rate.
func (r *relayRuntime) demandEvidence(peer string, now time.Time) error {
	r.pulls.Lock()
	defer r.pulls.Unlock()
	if r.demands == nil {
		r.demands = map[string]time.Time{}
	}
	r.demands[peer] = now
	return r.requestEvidenceLocked(peer, now)
}

// demandedLocked reports whether a peer's evidence was demanded within the
// demand window; an older demand is dropped. The caller holds pulls.
func (r *relayRuntime) demandedLocked(peer string, now time.Time) bool {
	at, found := r.demands[peer]
	if !found {
		return false
	}
	if now.Sub(at) > r.demandWindow() {
		delete(r.demands, peer)
		return false
	}
	return true
}

// demandWindow is relayDemandWindow, or two maintenance passes when the
// sweep interval is longer: the Commit retry that refreshes a demand runs
// once per pass, after the pull sweep that judges it.
func (r *relayRuntime) demandWindow() time.Duration {
	return max(relayDemandWindow, 2*r.sweep)
}

func (r *relayRuntime) requestEvidenceLocked(peer string, now time.Time) error {
	pull, _, err := r.daemon.journal.LoadRelayPull(peer)
	if err != nil {
		return err
	}
	if pull.Requested {
		return nil
	}
	pull.Requested = true
	pull.RequestNextAtUnix = uint64(now.Unix())
	return r.daemon.journal.PutRelayPull(pull, now)
}

// sweepPulls deposits due evidence requests and owed responses, and ends a
// request once no copy and no room object for its peer is held pending on
// evidence.
func (r *relayRuntime) sweepPulls(ctx context.Context) {
	pulls, err := r.daemon.journal.ListRelayPulls()
	if err != nil {
		r.daemon.report("relay evidence pull", err)
		return
	}
	for _, pull := range pulls {
		if ctx.Err() != nil {
			return
		}
		if pull.ResponsePending {
			if err := r.sendResponse(ctx, pull.AgentID); err != nil {
				r.daemon.report("relay evidence response", err)
			}
		}
		if pull.Requested {
			if err := r.sendRequest(ctx, pull.AgentID); err != nil {
				r.daemon.report("relay evidence request", err)
			}
		}
	}
}

func (r *relayRuntime) sendRequest(ctx context.Context, peer string) error {
	// Room objects waiting on the peer's evidence are judged before the pull
	// lock is taken: the judgement reads finalized state.
	roomWaits, roomErr := r.roomWaitsOnEvidence(peer, r.now())
	r.pulls.Lock()
	defer r.pulls.Unlock()
	now := r.now()
	pull, _, err := r.daemon.journal.LoadRelayPull(peer)
	if err != nil || !pull.Requested {
		return err
	}
	index, err := r.buildIndex(now)
	if err != nil {
		return err
	}
	if len(index.onEvidence[peer]) == 0 && !r.demandedLocked(peer, now) {
		if roomErr != nil {
			// Whether a room object waits is not known: the request is left
			// as it is and judged again on the next pass.
			return roomErr
		}
		if !roomWaits {
			// No kind-4 request is sent, or kept outstanding, without a copy
			// or a room object waiting on the peer's evidence.
			pull.Requested, pull.RequestNextAtUnix = false, 0
			return r.daemon.journal.PutRelayPull(pull, now)
		}
	}
	if uint64(now.Unix()) < pull.RequestNextAtUnix {
		return nil
	}
	if pull.RequestGeneration == ^uint32(0) {
		return errors.New("relay evidence request generations are exhausted")
	}
	generation := pull.RequestGeneration + 1
	key, err := relayframe.EvidenceRequestKey(peer, generation)
	if err != nil {
		return err
	}
	withdraw := ""
	if generation > 1 {
		if withdraw, err = relayframe.EvidenceRequestKey(peer, generation-1); err != nil {
			return err
		}
	}
	frame, _, err := r.ownFrame(relayframe.KindEvidence, peer, []byte{relayframe.EvidenceRequest}, true)
	if err != nil {
		return err
	}
	expires := uint64(now.Add(relayRetentionWindow).Unix())
	response, _, err := r.carry(ctx, peer, key, withdraw, expires, frame)
	var delay time.Duration
	if err == nil && response.Result == carrierapi.ResultCarried {
		delay, err = r.redepositDelay(response.RelayTTLSeconds)
	}
	if err == nil && response.Result == carrierapi.ResultCarried {
		pull.RequestGeneration = generation
		pull.RequestLastAtUnix = uint64(now.Unix())
		pull.RequestNextAtUnix = uint64(now.Add(delay).Unix())
	} else {
		pull.RequestNextAtUnix = uint64(now.Add(relayEvidenceRetry).Unix())
		if err == nil && response.Result != carrierapi.ResultRetry {
			r.daemon.report("relay evidence request", fmt.Errorf("the carrier refused the evidence request to %s: "+
				"%s %s; it is tried again in %s", peer, response.Result, response.Code, relayEvidenceRetry))
		}
	}
	if putErr := r.daemon.journal.PutRelayPull(pull, now); putErr != nil {
		return putErr
	}
	if err != nil {
		return err
	}
	return nil
}

func (r *relayRuntime) sendResponse(ctx context.Context, peer string) error {
	r.pulls.Lock()
	defer r.pulls.Unlock()
	now := r.now()
	pull, _, err := r.daemon.journal.LoadRelayPull(peer)
	if err != nil || !pull.ResponsePending {
		return err
	}
	_, ownDigest, _, err := r.sink.Current()
	if err != nil {
		return err
	}
	window := uint64(relayResponseWindow / time.Second)
	if pull.ResponseDescriptor == ownDigest && pull.ResponseAtUnix+window > uint64(now.Unix()) {
		// At most one response per (peer, own descriptor) per hour; the
		// earlier response already carries this evidence.
		pull.ResponsePending = false
		return r.daemon.journal.PutRelayPull(pull, now)
	}
	hour := uint64(now.Unix()) / window
	if hour == 0 {
		return errors.New("invalid relay evidence response time")
	}
	key, err := relayframe.EvidenceResponseKey(peer, ownDigest, hour)
	if err != nil {
		return err
	}
	frame, _, err := r.ownFrame(relayframe.KindEvidence, peer, []byte{relayframe.EvidenceResponse}, true)
	if err != nil {
		return err
	}
	response, _, err := r.carry(ctx, peer, key, "", uint64(now.Add(relayRetentionWindow).Unix()), frame)
	if err != nil {
		return err
	}
	switch response.Result {
	case carrierapi.ResultCarried:
		pull.ResponsePending = false
		pull.ResponseDescriptor = ownDigest
		pull.ResponseAtUnix = uint64(now.Unix())
	case carrierapi.ResultRetry:
		return nil
	default:
		// The carrier will not take the response (no card of the peer, a
		// cap, an invalid request): it is not sent again for this request,
		// and the reason is reported rather than dropped silently.
		pull.ResponsePending = false
		r.daemon.report("relay evidence response", fmt.Errorf("the carrier refused the evidence response to %s: %s %s; "+
			"it is not sent again for this request", peer, response.Result, response.Code))
	}
	return r.daemon.journal.PutRelayPull(pull, now)
}

// Carry is the carrier's operation; the daemon does not serve it.
func (r *relayRuntime) Carry(context.Context, carrierapi.Request, []byte) carrierapi.Response {
	return carrierapi.NotServed()
}

// RoomCards is the carrier's operation (its chat peer store); the daemon
// does not serve it.
func (r *relayRuntime) RoomCards(context.Context, carrierapi.Request) carrierapi.Response {
	return carrierapi.NotServed()
}

// Withdraw is the carrier's operation (its relay outbox); the daemon does
// not serve it.
func (r *relayRuntime) Withdraw(context.Context, carrierapi.Request) carrierapi.Response {
	return carrierapi.NotServed()
}

// Deliver handles a verified packet's frame of kind 1, 3 or 4.
//
// The carrier handler's per-connection deadline does not bound CheckPeer's
// finalized-state reads: identity.AgentResolver takes no context. Each read
// is bounded instead by the finalized-state client's own per-query timeout,
// the daemon's chain_query_timeout_seconds (toschain.DefaultQueryTimeout,
// 5 s, when unset; at most 30 s).
func (r *relayRuntime) Deliver(ctx context.Context, sender string, raw []byte) carrierapi.Response {
	if sender == r.daemon.config.AgentID {
		return carrierapi.Refusal(carrierapi.CodeSenderMismatch)
	}
	frame, err := relayframe.Decode(raw)
	if err != nil {
		return frameRefusal(err)
	}
	switch frame.Kind {
	case relayframe.KindCopy:
		return r.deliverCopy(ctx, sender, frame)
	case relayframe.KindEvidence:
		return r.deliverEvidence(sender, frame)
	case relayframe.KindRoom:
		if r.rooms == nil {
			return carrierapi.Refusal(carrierapi.CodeKindNotCarried)
		}
		return r.rooms.deliver(ctx, sender, frame)
	default:
		return carrierapi.Refusal(carrierapi.CodeKindNotCarried)
	}
}

func frameRefusal(err error) carrierapi.Response {
	switch {
	case errors.Is(err, relayframe.ErrRelayEvidenceTooLarge):
		return carrierapi.Refusal(carrierapi.CodeRelayEvidenceTooLarge)
	case errors.Is(err, relayframe.ErrFrameKindUnsupported), errors.Is(err, relayframe.ErrFrameKind):
		return carrierapi.Refusal(carrierapi.CodeKindNotCarried)
	default:
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
	}
}

func (r *relayRuntime) deliverCopy(ctx context.Context, sender string, frame relayframe.Frame) carrierapi.Response {
	value, err := relayframe.DecodeCopy(frame.Part)
	if err != nil {
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
	}
	message := dispatch.Message{EventID: value.EventID, SessionID: value.SessionID,
		RecipientEndpointID: value.RecipientEndpointID, RecipientDeviceID: value.RecipientDeviceID,
		ConversationID: value.ConversationID, Bootstrap: value.Bootstrap, AdmissionToken: value.AdmissionToken,
		Ciphertext: value.Ciphertext, ExpiresAtUnix: value.ExpiresAtUnix}
	result, peer, err := r.daemon.ReceiveRelay(ctx, message, sender, frame.Evidence, frame.Card)
	if err != nil {
		var refusal *relayRefusal
		switch {
		case errors.As(err, &refusal):
			return carrierapi.Refusal(refusal.code)
		case errors.Is(err, eventlog.ErrSessionConflict):
			return carrierapi.Retry()
		case fault.DispositionOf(fault.CodeOf(err)) == fault.Transient && isFault(err):
			return carrierapi.Retry()
		case fault.CodeOf(err) == fault.CodeDescriptorExpired:
			// A retained message whose evidence expired is answered with a
			// signed rejection, so its sender learns to renew.
			result = ReceiveResult{Outcome: admission.Rejected, Code: fault.CodeDescriptorExpired, EventID: message.EventID}
		default:
			return carrierapi.Refusal(carrierapi.CodeNotAccepted)
		}
	}
	if peer != nil && admits(result.Outcome) {
		committed, commitErr := r.verifier.CommitPeer(*peer, r.now())
		if commitErr != nil {
			r.daemon.report("relay evidence commit", commitErr)
		} else if committed {
			r.wake(sender)
		}
		if r.rooms != nil {
			r.rooms.refreshMemberCard(sender, frame.Card, r.now())
		}
	}
	ack, err := r.ackFrame(sender, value, result)
	if err != nil {
		return carrierapi.Retry()
	}
	return ack
}

// admits reports the outcomes under which a sender's card and evidence may
// be stored.
func admits(outcome admission.Outcome) bool {
	return outcome == admission.Accepted || outcome == admission.Duplicate || outcome == admission.Held
}

func isFault(err error) bool {
	_, ok := fault.Of(err)
	return ok
}

// ackFrame signs the delivery ack for one copy and wraps it in a kind-2
// frame with this node's evidence.
func (r *relayRuntime) ackFrame(peer string, value relayframe.Copy, result ReceiveResult) (carrierapi.Response, error) {
	outcome := string(result.Outcome)
	code := result.Code
	if result.Outcome != admission.Rejected {
		code = ""
	} else if code == "" || !fault.PeerVisible(code) {
		code = fault.CodeRejected
	}
	ack, err := relayframe.SignAck(relayframe.Ack{EventID: value.EventID, SessionID: value.SessionID,
		RecipientEndpointID: r.daemon.config.EndpointID, RecipientDeviceID: r.daemon.config.DeviceID,
		CiphertextDigest: canon.Digest(value.Ciphertext), Outcome: outcome, Code: code,
		AcceptedAtUnix: uint64(r.now().Unix())}, r.signer)
	if err != nil {
		return carrierapi.Response{}, err
	}
	object, err := relayframe.EncodeAck(ack)
	if err != nil {
		return carrierapi.Response{}, err
	}
	frame, _, err := r.ownFrame(relayframe.KindDeliveryAck, peer, object, false)
	if err != nil {
		return carrierapi.Response{}, err
	}
	return carrierapi.Response{Result: carrierapi.ResultAck,
		AckFrameBase64: base64.StdEncoding.EncodeToString(frame), AckOutcome: outcome}, nil
}

// deliverEvidence handles a kind-4 request or response. A stranger gets the
// relay ack only: nothing is verified for it, written or answered.
func (r *relayRuntime) deliverEvidence(sender string, frame relayframe.Frame) carrierapi.Response {
	admitted, err := r.verifier.Admitted(sender)
	if err != nil {
		return carrierapi.Retry()
	}
	if !admitted {
		return carrierapi.Response{Result: carrierapi.ResultIgnored}
	}
	if err := checkCardShape(frame.Card, sender); err != nil {
		return carrierapi.Refusal(carrierapi.CodeSenderMismatch)
	}
	now := r.now()
	// Pulled evidence is checked against its own pin, not a session's: its
	// purpose includes learning a newer descriptor that removed a device, which
	// a session pin would refuse. It must still be a live finalized delegation
	// committed by the sender Agent itself (CheckPeer refuses evidence that
	// names another Agent), and content copies keep their session pin.
	peer, err := r.verifier.CheckContact(sender, frame.Evidence, now)
	if err != nil {
		if fault.CodeOf(err) == fault.CodeInternal {
			return carrierapi.Retry()
		}
		return carrierapi.Response{Result: carrierapi.ResultIgnored}
	}
	committed, err := r.verifier.CommitPeer(peer, now)
	if err != nil {
		return carrierapi.Retry()
	}
	if committed {
		r.wake(sender)
	}
	if r.rooms != nil {
		r.rooms.refreshMemberCard(sender, frame.Card, now)
	}
	r.pulls.Lock()
	defer r.pulls.Unlock()
	pull, _, err := r.daemon.journal.LoadRelayPull(sender)
	if err != nil {
		return carrierapi.Retry()
	}
	switch frame.Part[0] {
	case relayframe.EvidenceRequest:
		pull.ResponsePending = true
	case relayframe.EvidenceResponse:
		// A response answers the outstanding request and is never answered.
		pull.Requested, pull.RequestNextAtUnix = false, 0
	}
	if err := r.daemon.journal.PutRelayPull(pull, now); err != nil {
		return carrierapi.Retry()
	}
	return carrierapi.Response{Result: carrierapi.ResultAdmitted}
}

// wake makes copies for a peer that were waiting on its evidence due now.
func (r *relayRuntime) wake(peer string) {
	index, err := r.buildIndex(r.now())
	if err != nil {
		r.daemon.report("relay wake", err)
		return
	}
	if len(index.onEvidence[peer]) == 0 {
		return
	}
	if _, err := r.daemon.journal.WakeDeliveries(index.onEvidence[peer], r.now()); err != nil {
		r.daemon.report("relay wake", err)
	}
}

// DeliveryAck handles a verified packet's kind-2 frame. The ack settles a
// copy only if its packet sender is the Agent of the Endpoint that signed it.
func (r *relayRuntime) DeliveryAck(ctx context.Context, sender string, raw []byte) carrierapi.Response {
	if ctx == nil {
		return carrierapi.Retry()
	}
	if sender == r.daemon.config.AgentID {
		return carrierapi.Refusal(carrierapi.CodeSenderMismatch)
	}
	frame, err := relayframe.Decode(raw)
	if err != nil {
		return frameRefusal(err)
	}
	if frame.Kind != relayframe.KindDeliveryAck {
		return carrierapi.Refusal(carrierapi.CodeKindNotCarried)
	}
	if relayframe.IsRoomAck(frame.Part) {
		if r.rooms == nil {
			return carrierapi.Refusal(carrierapi.CodeKindNotCarried)
		}
		return r.rooms.roomAckReceived(ctx, sender, frame)
	}
	ack, err := relayframe.DecodeAck(frame.Part)
	if err != nil {
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
	}
	deliveryID, err := eventlog.NewDeliveryCopyID(ack.EventID, ack.RecipientEndpointID, ack.RecipientDeviceID)
	if err != nil {
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
	}
	delivery, found, err := r.daemon.journal.LookupDeliveryCopy(deliveryID)
	if err != nil {
		return carrierapi.Retry()
	}
	if !found {
		return carrierapi.Response{Result: carrierapi.ResultIgnored}
	}
	owner, err := r.peerOf(delivery.SessionID)
	if err != nil {
		return carrierapi.Retry()
	}
	if owner != sender {
		return carrierapi.Refusal(carrierapi.CodeSenderMismatch)
	}
	now := r.now()
	peer, err := r.verifier.CheckPeer(sender, frame.Evidence,
		directory.Pin{EndpointID: delivery.RecipientEndpointID, DeviceID: delivery.RecipientDeviceID}, now)
	if err != nil {
		if fault.CodeOf(err) == fault.CodeInternal {
			return carrierapi.Retry()
		}
		return carrierapi.Refusal(carrierapi.CodeEvidenceRefused)
	}
	if peer.Delegation.AgentID != sender || peer.Delegation.EndpointID != ack.RecipientEndpointID {
		return carrierapi.Refusal(carrierapi.CodeSenderMismatch)
	}
	if err := relayframe.VerifyAck(ack, peer.Delegation.IdentityPublicKey); err != nil {
		return carrierapi.Refusal(carrierapi.CodeSenderMismatch)
	}
	if ack.AcceptedAtUnix > uint64(now.Add(maxAckSkew).Unix()) || ack.AcceptedAtUnix > delivery.ExpiresAtUnix {
		return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
	}
	match := eventlog.RelayAckMatch{SessionID: ack.SessionID, DeviceID: ack.RecipientDeviceID,
		CiphertextDigest: ack.CiphertextDigest}
	if err := r.applyAck(sender, deliveryID, delivery, ack, match, now); err != nil {
		if errors.Is(err, eventlog.ErrAckMismatch) {
			return carrierapi.Refusal(carrierapi.CodeFrameMalformed)
		}
		if errors.Is(err, eventlog.ErrNotPending) {
			return carrierapi.Response{Result: carrierapi.ResultIgnored}
		}
		return carrierapi.Retry()
	}
	if committed, err := r.verifier.CommitPeer(peer, now); err != nil {
		r.daemon.report("relay evidence commit", err)
	} else if committed {
		r.wake(sender)
	}
	return carrierapi.Response{Result: carrierapi.ResultApplied}
}

func (r *relayRuntime) applyAck(peer, deliveryID string, delivery eventlog.Delivery, ack relayframe.Ack,
	match eventlog.RelayAckMatch, now time.Time) error {
	if ack.Outcome != relayframe.OutcomeRejected {
		settled, changed, err := r.daemon.journal.DeliveredByAck(deliveryID, match, now)
		if err != nil {
			return err
		}
		// The presented invite has done its work once the recipient accepted
		// a delivery that carried it: the sender is its contact now.
		if ack.Outcome == relayframe.OutcomeAccepted && delivery.AdmissionToken != "" {
			if _, err := r.daemon.journal.SettlePresentedInvite(peer, delivery.AdmissionToken); err != nil {
				r.daemon.report("presented invite settle", err)
			}
		}
		if !changed {
			// Already delivered: a lost ack's re-deposit answered again.
			r.settleCopies(peer, deliveryID, delivery)
			return eventlog.ErrNotPending
		}
		r.settleCopies(peer, deliveryID, settled)
		return r.recordAckedCard(settled, now)
	}
	if ack.Code != fault.CodeDescriptorExpired {
		rejected, err := r.daemon.journal.RelayRejected(deliveryID, match, ack.Code, "", now, now)
		if err != nil {
			return err
		}
		// A rejection that ends the copy, or holds it for the owner, settles
		// its generations at the carrier, so no relay receives it again; a
		// retry later is a new generation.
		if rejected.State != eventlog.StatePending {
			r.settleCopies(peer, deliveryID, rejected)
		}
		return nil
	}
	// descriptor-expired: retry at once only with evidence newer than the
	// evidence that was refused, in the single sense of "newer"; otherwise
	// wait for this node's own renewal on the normal backoff.
	sent := latestGeneration(delivery)
	_, currentDigest, currentIssued, err := r.sink.Current()
	if err != nil {
		return err
	}
	retryAt := now.Add(descriptorExpiredBackoff(delivery.Attempts + 1))
	if sent.DescriptorDigest != "" &&
		directory.NewerEvidence(currentDigest, currentIssued, sent.DescriptorDigest, sent.DescriptorIssuedAtUnix) {
		retryAt = now
	}
	refused := sent.DescriptorDigest
	if refused == "" {
		refused = currentDigest
	}
	_, err = r.daemon.journal.RelayRejected(deliveryID, match, ack.Code, refused, retryAt, now)
	return err
}

// recordAckedCard notes that the peer acknowledged a frame that carried this
// node's card, so later frames to it no longer carry the card. An ack binds
// the session, device and ciphertext, not the generation it answers, so it
// proves the peer saw a card only when every recorded generation of the copy
// carried that same card; otherwise the card keeps riding.
func (r *relayRuntime) recordAckedCard(delivery eventlog.Delivery, now time.Time) error {
	digest := ackedCardDigest(delivery)
	credential := ackedCredentialDigest(delivery)
	if digest == "" && credential == "" {
		return nil
	}
	peer, err := r.peerOf(delivery.SessionID)
	if err != nil {
		return err
	}
	r.pulls.Lock()
	defer r.pulls.Unlock()
	pull, _, err := r.daemon.journal.LoadRelayPull(peer)
	if err != nil {
		return err
	}
	changed := false
	if digest != "" && pull.AckedCardDigest != digest {
		pull.AckedCardDigest, changed = digest, true
	}
	if credential != "" && pull.AckedCredentialDigest != credential {
		pull.AckedCredentialDigest, changed = credential, true
	}
	if !changed {
		return nil
	}
	return r.daemon.journal.PutRelayPull(pull, now)
}

// ackedCredentialDigest is the contact credential an ack of this copy proves
// the peer received, or empty when its generations did not all carry one same
// credential.
func ackedCredentialDigest(delivery eventlog.Delivery) string {
	digest := ""
	for index, generation := range delivery.Generations {
		if generation.CredentialDigest == "" || index > 0 && generation.CredentialDigest != digest {
			return ""
		}
		digest = generation.CredentialDigest
	}
	return digest
}

// settleCopies tells a carrier that keeps depositing (the builtin lane) that
// every generation of the delivery is acknowledged.
func (r *relayRuntime) settleCopies(peer, deliveryID string, delivery eventlog.Delivery) {
	settler, ok := r.carrier.(settlingCarrier)
	if !ok {
		return
	}
	keys := make([]string, 0, delivery.Generation)
	for generation := uint32(1); generation <= delivery.Generation; generation++ {
		key, err := relayframe.CopyIdempotencyKey(deliveryID, generation)
		if err != nil {
			return
		}
		keys = append(keys, key)
	}
	ctx, cancel := context.WithTimeout(context.Background(), credentialIssueTimeout)
	defer cancel()
	if err := settler.Settled(ctx, peer, keys); err != nil {
		r.daemon.report("settle acknowledged copy", err)
	}
}

// ackedCardDigest is the card an ack of this copy proves the peer received,
// or empty when its generations did not all carry one same card.
func ackedCardDigest(delivery eventlog.Delivery) string {
	digest := ""
	for index, generation := range delivery.Generations {
		if generation.CardDigest == "" || index > 0 && generation.CardDigest != digest {
			return ""
		}
		digest = generation.CardDigest
	}
	return digest
}

func latestGeneration(delivery eventlog.Delivery) eventlog.RelayGeneration {
	var latest eventlog.RelayGeneration
	for _, generation := range delivery.Generations {
		if generation.Generation >= latest.Generation {
			latest = generation
		}
	}
	return latest
}

func descriptorExpiredBackoff(attempt uint32) time.Duration {
	delay := descriptorExpiredBase
	for index := uint32(1); index < attempt && delay < descriptorExpiredCap; index++ {
		delay *= 2
	}
	if delay > descriptorExpiredCap {
		delay = descriptorExpiredCap
	}
	return delay
}

// relayRefusal is a permanent inbound refusal with a fixed carrier code.
type relayRefusal struct {
	code   carrierapi.Code
	detail string
}

func (r *relayRefusal) Error() string { return string(r.code) + ": " + r.detail }

// ReceiveRelay receives one copy that arrived in a verified packet from
// packetSender, with the sender's relay identity evidence. CheckPeer runs on
// every frame before anything is opened; the packet sender must be the
// session's peer Agent; an Event already committed in the session is a
// duplicate whatever came after it. The verified peer is returned so the
// caller can commit it once Messenger's answer admits the sender.
func (d *Daemon) ReceiveRelay(ctx context.Context, message dispatch.Message, packetSender string,
	evidence, card []byte) (ReceiveResult, *directory.RelayPeer, error) {
	if err := d.receivable(ctx, message); err != nil {
		return ReceiveResult{}, nil, &relayRefusal{code: carrierapi.CodeNotAccepted, detail: err.Error()}
	}
	if d.discovery.relay == nil {
		return ReceiveResult{}, nil, errors.New("relay evidence verification is not configured")
	}
	now := d.clock()
	record, found, err := d.journal.SessionState(message.SessionID)
	if err != nil {
		return ReceiveResult{}, nil, fault.Wrap(fault.CodeInternal, err)
	}
	var pin directory.Pin
	var bootstrap e2ee.FirstContact
	if found {
		if record.Authority == nil {
			return ReceiveResult{}, nil, &relayRefusal{code: carrierapi.CodeNotAccepted, detail: "session has no authority"}
		}
		if record.Authority.PeerAgentID != packetSender {
			return ReceiveResult{}, nil, &relayRefusal{code: carrierapi.CodeSenderMismatch,
				detail: "packet sender is not the session's peer Agent"}
		}
		pin = directory.Pin{EndpointID: record.Authority.PeerEndpointID, DeviceID: record.Authority.PeerDeviceID}
	} else {
		bootstrap, err = e2ee.DecodeFirstContactJSON(message.Bootstrap)
		if err != nil {
			return ReceiveResult{}, nil, &relayRefusal{code: carrierapi.CodeNotAccepted, detail: err.Error()}
		}
		if bootstrap.Binding.SenderAgentID != packetSender {
			return ReceiveResult{}, nil, &relayRefusal{code: carrierapi.CodeSenderMismatch,
				detail: "packet sender is not the first-contact sender Agent"}
		}
		sender := bootstrap.SenderBundle
		pin = directory.Pin{EndpointID: bootstrap.Binding.SenderEndpointID, DeviceID: bootstrap.Binding.SenderDeviceID,
			Bundle: &sender}
	}
	peer, err := d.discovery.relay.CheckPeer(packetSender, evidence, pin, now)
	if err != nil {
		if fault.CodeOf(err) == fault.CodeInternal {
			return ReceiveResult{}, nil, err
		}
		if fault.CodeOf(err) == fault.CodeDescriptorExpired {
			// A signed descriptor-expired ack goes only to the session's peer
			// or an admitted peer. A stranger whose evidence fails gets the
			// relay ack only: no Endpoint signature and no write.
			known := found // the session's peer is packetSender, checked above
			if !known {
				admitted, admittedErr := d.discovery.relay.Admitted(packetSender)
				if admittedErr != nil {
					return ReceiveResult{}, nil, fault.Wrap(fault.CodeInternal, admittedErr)
				}
				known = admitted
			}
			if known {
				return ReceiveResult{}, nil, err
			}
		}
		return ReceiveResult{}, nil, &relayRefusal{code: carrierapi.CodeEvidenceRefused, detail: err.Error()}
	}
	verify := func(_ context.Context, agentID string, _ directory.Pin) (verifiedPeer, error) {
		if agentID != peer.AgentID {
			return verifiedPeer{}, errors.New("relay copy names another sender than its evidence")
		}
		return verifiedPeer{Delegation: peer.Delegation, EndpointID: peer.Descriptor.EndpointID, Bundles: peer.Bundles,
			Card: card}, nil
	}
	if !found {
		result, err := d.receiveFirstContact(ctx, message, bootstrap, admission.RouteRelay, now, verify)
		return result, &peer, refuseOpenFailure(err)
	}
	duplicate, err := d.committedDuplicate(record, message)
	if err != nil {
		return ReceiveResult{}, nil, fault.Wrap(fault.CodeInternal, err)
	}
	if duplicate {
		return ReceiveResult{Outcome: admission.Duplicate, EventID: message.EventID}, &peer, nil
	}
	result, err := d.receiveEstablished(ctx, message, record, admission.RouteRelay, now, verify)
	return result, &peer, refuseOpenFailure(err)
}

// refuseOpenFailure turns a failure to open or bind a copy into a permanent
// refusal, except a session race, which the carrier retries.
func refuseOpenFailure(err error) error {
	if err == nil || errors.Is(err, eventlog.ErrSessionConflict) {
		return err
	}
	if _, ok := fault.Of(err); ok {
		return err
	}
	return &relayRefusal{code: carrierapi.CodeNotAccepted, detail: err.Error()}
}

// runRelay serves the inbound carrier socket, sweeps evidence pulls,
// retires expired relay evidence and, with private rooms, drops expired room
// parts and retires ended rooms.
func (r *relayRuntime) run(ctx context.Context, sweep time.Duration, group *sync.WaitGroup) {
	r.pulls.Lock()
	r.sweep = sweep
	r.pulls.Unlock()
	group.Add(2)
	go func() {
		defer group.Done()
		if r.builtin != nil {
			if err := r.builtin.Run(ctx); err != nil && ctx.Err() == nil {
				r.daemon.report("builtin chat lane", err)
			}
			return
		}
		if err := r.server.Serve(ctx, r.listener); err != nil && !isClosed(err) {
			r.daemon.report("serve relay carrier", err)
		}
	}()
	go func() {
		defer group.Done()
		ticker := time.NewTicker(sweep)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.sweepPulls(ctx)
				r.sweepEvidence()
				if r.rooms != nil {
					r.rooms.maintain()
				}
			}
		}
	}()
}

// checkRelayComposition refuses, before anything is queued, what the relay
// route never carries: an Event class that holds an Agent Packet, and a
// payload whose worst-case copy frame exceeds the largest bucket.
func (d *Daemon) checkRelayComposition(kind string, encoded []byte) error {
	if d.config.Transport != TransportAgentPacketRelay {
		return nil
	}
	if carriesAgentPacket(kind) {
		return fault.New(fault.CodeClassNotDelegated, "Agent Packet events are not carried on the relay route")
	}
	return relayframe.CheckCopyFits(len(encoded))
}
