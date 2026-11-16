package daemon

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
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
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
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

	// index is the open-delivery index of the sweep in progress.
	indexMutex sync.Mutex
	index      *peerIndex
}

// configureRelayCarriage installs the relay route: the carrier client, the
// seal gate, the inbound carrier socket, and the same-Agent startup check.
func (d *Daemon) configureRelayCarriage(sink *directory.RelayEvidenceSink) error {
	relay := d.config.RelayCarriage
	if d == nil || relay == nil || d.dispatch == nil || d.discovery == nil || d.discovery.relay == nil ||
		d.prekeys == nil || d.prekeys.signer == nil || d.admission == nil || sink == nil {
		return errors.New("relay carriage dependencies are incomplete")
	}
	// OpenFox and this installation must be one Agent: the local chat card is
	// the carrier's, and it must name this daemon's Agent.
	card, err := securefile.ReadBoundedRegular(relay.CardPath, relayframe.MaxCardBytes)
	if err != nil {
		return errors.New("read local chat card: " + err.Error())
	}
	if err := checkCardShape(card, d.config.AgentID); err != nil {
		return errors.New("local chat card does not belong to this installation's Agent: " + err.Error())
	}
	client, err := carrierapi.NewClient(relay.CarrySocketPath, relay.Timeout())
	if err != nil {
		return err
	}
	return d.installRelayRuntime(sink, client, relay.RedepositInterval(), relay.Timeout())
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
	return nil
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
	var include []byte
	if cardErr == nil {
		pull, _, err := r.daemon.journal.LoadRelayPull(peer)
		if err != nil {
			return nil, eventlog.RelayGeneration{}, err
		}
		digest := canon.Digest(card)
		if requireCard || pull.AckedCardDigest != digest {
			include = card
			generation.CardDigest = digest
		}
	}
	frame, err := relayframe.Encode(relayframe.Frame{Kind: kind, PartIndex: 0, PartCount: 1,
		Card: include, Evidence: evidence, Part: part})
	if err != nil {
		return nil, eventlog.RelayGeneration{}, err
	}
	return frame, generation, nil
}

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
	frame, generation, err := r.ownFrame(relayframe.KindCopy, peer, object, false)
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
	response, err := r.carrier.Carry(ctx, peer, key, withdraw, message.ExpiresAtUnix, frame)
	if err != nil {
		return fault.Wrap(fault.CodeUnreachable, err)
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

// requestEvidence opens the single outstanding evidence request to a peer;
// an already outstanding request is left on its schedule.
func (r *relayRuntime) requestEvidence(peer string, now time.Time) error {
	r.pulls.Lock()
	defer r.pulls.Unlock()
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
// request once no copy for its peer is held pending on evidence.
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
	if len(index.onEvidence[peer]) == 0 {
		// No kind-4 request is sent, or kept outstanding, without a copy
		// waiting on the peer's evidence.
		pull.Requested, pull.RequestNextAtUnix = false, 0
		return r.daemon.journal.PutRelayPull(pull, now)
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
	response, err := r.carrier.Carry(ctx, peer, key, withdraw, expires, frame)
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
	response, err := r.carrier.Carry(ctx, peer, key, "", uint64(now.Add(relayRetentionWindow).Unix()), frame)
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
		pull.ResponsePending = false
	}
	return r.daemon.journal.PutRelayPull(pull, now)
}

// Carry is the carrier's operation; the daemon does not serve it.
func (r *relayRuntime) Carry(context.Context, carrierapi.Request, []byte) carrierapi.Response {
	return carrierapi.NotServed()
}

// Deliver handles a verified packet's frame of kind 1 or 4.
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
	result, peer, err := r.daemon.ReceiveRelay(ctx, message, sender, frame.Evidence)
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
			return eventlog.ErrNotPending
		}
		return r.recordAckedCard(settled, now)
	}
	if ack.Code != fault.CodeDescriptorExpired {
		_, err := r.daemon.journal.RelayRejected(deliveryID, match, ack.Code, "", now, now)
		return err
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
	if digest == "" {
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
	if pull.AckedCardDigest == digest {
		return nil
	}
	pull.AckedCardDigest = digest
	return r.daemon.journal.PutRelayPull(pull, now)
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
	evidence []byte) (ReceiveResult, *directory.RelayPeer, error) {
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
		return verifiedPeer{Delegation: peer.Delegation, EndpointID: peer.Descriptor.EndpointID, Bundles: peer.Bundles}, nil
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

// runRelay serves the inbound carrier socket and sweeps evidence pulls.
func (r *relayRuntime) run(ctx context.Context, sweep time.Duration, group *sync.WaitGroup) {
	group.Add(2)
	go func() {
		defer group.Done()
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
