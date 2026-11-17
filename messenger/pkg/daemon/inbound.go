package daemon

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/admission"
	"github.com/tosnetwork/ai/messenger/pkg/directory"
	"github.com/tosnetwork/ai/messenger/pkg/dispatch"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

type ReceiveResult struct {
	Outcome admission.Outcome
	Code    fault.Code
	EventID string
}

// verifiedPeer is the sender authority one route established for a copy.
type verifiedPeer struct {
	Delegation identity.Delegation
	EndpointID string
	Bundles    []e2ee.Bundle
}

// peerVerifier establishes a sender's current Endpoint authority. The
// network route resolves it through the refresh chain; the relay route checks
// the frame's locator-free evidence against finalized state.
type peerVerifier func(ctx context.Context, agentID string, pin directory.Pin) (verifiedPeer, error)

// ReceiveSealed authenticates, opens, admits and durably commits one device
// copy. The arrival route grants no identity or admission authority.
func (d *Daemon) ReceiveSealed(ctx context.Context, message dispatch.Message,
	route admission.Route) (ReceiveResult, error) {
	if route == admission.RouteRelay {
		// The relay route has its own evidence and sender rules; it enters
		// only through ReceiveRelay.
		return ReceiveResult{}, errors.New("relay copies are received with their relay evidence")
	}
	if err := d.receivable(ctx, message); err != nil {
		return ReceiveResult{}, err
	}
	now := d.clock()
	record, found, err := d.journal.SessionState(message.SessionID)
	if err != nil {
		return ReceiveResult{}, err
	}
	if found {
		duplicate, err := d.committedDuplicate(record, message)
		if err != nil || duplicate {
			return ReceiveResult{Outcome: admission.Duplicate, EventID: message.EventID}, err
		}
	}
	verify := func(ctx context.Context, agentID string, _ directory.Pin) (verifiedPeer, error) {
		resolved, err := d.discovery.contacts.Ensure(ctx, agentID)
		if err != nil {
			return verifiedPeer{}, err
		}
		return verifiedPeer{Delegation: resolved.Delegation, EndpointID: resolved.Descriptor.EndpointID,
			Bundles: resolved.Bundles}, nil
	}
	if !found {
		bootstrap, err := e2ee.DecodeFirstContactJSON(message.Bootstrap)
		if err != nil {
			return ReceiveResult{}, err
		}
		return d.receiveFirstContact(ctx, message, bootstrap, route, now, verify)
	}
	return d.receiveEstablished(ctx, message, record, route, now, verify)
}

func (d *Daemon) receivable(ctx context.Context, message dispatch.Message) error {
	if d == nil || d.journal == nil || d.discovery == nil || d.discovery.contacts == nil ||
		d.prekeys == nil || d.prekeys.devices == nil || d.admission == nil {
		return errors.New("inbound encrypted messaging is not configured")
	}
	if ctx == nil || message.EventID == "" || message.SessionID == "" || len(message.Ciphertext) == 0 ||
		message.RecipientEndpointID != d.config.EndpointID || message.RecipientDeviceID != d.config.DeviceID {
		return errors.New("sealed message targets another device")
	}
	return nil
}

func (d *Daemon) clock() time.Time {
	if d.now != nil {
		return d.now()
	}
	return time.Now()
}

// committedDuplicate recognises any Event already committed under the
// session, not only the most recent one, so an older duplicate is answered
// without its ciphertext reaching the ratchet.
func (d *Daemon) committedDuplicate(record eventlog.SessionRecord, message dispatch.Message) (bool, error) {
	if record.LastInboundEventID == message.EventID {
		return true, nil
	}
	return d.journal.EventCommittedInSession(message.SessionID, message.EventID)
}

func (d *Daemon) receiveFirstContact(ctx context.Context, message dispatch.Message, bootstrap e2ee.FirstContact,
	route admission.Route, now time.Time, verify peerVerifier) (ReceiveResult, error) {
	binding := bootstrap.Binding
	if binding.RecipientAgentID != d.config.AgentID || binding.RecipientEndpointID != d.config.EndpointID ||
		binding.RecipientDeviceID != d.config.DeviceID || binding.ConversationID != message.ConversationID ||
		binding.AlgorithmID != d.prekeys.suite.AlgorithmID() || !sameMessengerNetwork(binding.Network, d.config.Network()) {
		return ReceiveResult{}, errors.New("first-contact binding targets another authority")
	}
	expected, err := e2ee.DeviceSessionID(binding.SenderDeviceID, binding.RecipientDeviceID)
	if err != nil || expected != message.SessionID {
		return ReceiveResult{}, errors.New("first-contact session identity mismatch")
	}
	senderBundle := bootstrap.SenderBundle
	resolved, err := verify(ctx, binding.SenderAgentID, directory.Pin{EndpointID: binding.SenderEndpointID,
		DeviceID: binding.SenderDeviceID, Bundle: &senderBundle})
	if err != nil {
		return ReceiveResult{}, errors.New("verify first-contact sender directory: " + err.Error())
	}
	if resolved.Delegation.AgentID != binding.SenderAgentID ||
		resolved.EndpointID != binding.SenderEndpointID ||
		!containsExactBundle(resolved.Bundles, bootstrap.SenderBundle) {
		return ReceiveResult{}, errors.New("first-contact sender bundle is not verified directory evidence")
	}
	private, err := d.prekeys.devices.DevicePrekeyPrivate(d.config.EndpointID, d.config.DeviceID,
		bootstrap.RecipientBundleDigest, now)
	if err != nil {
		return ReceiveResult{}, err
	}
	defer clearSecret(private)
	associated, err := binding.Bytes()
	if err != nil {
		return ReceiveResult{}, err
	}
	state, err := d.prekeys.suite.Accept(private, bootstrap.SenderBundle.Material, bootstrap.Initial, associated)
	if err != nil {
		return ReceiveResult{}, err
	}
	plaintext, next, err := d.prekeys.suite.Open(state, message.Ciphertext, associated)
	if err != nil {
		return ReceiveResult{}, err
	}
	event, err := validateOpenedMessage(plaintext, message, binding)
	if err != nil {
		return ReceiveResult{}, err
	}
	if envelope.RequiresEstablishedDirect(event.Kind) {
		return ReceiveResult{}, errors.New("Agent Gift events are forbidden during first contact")
	}
	if refused, ok := refuseOnRoute(route, event); ok {
		return refused, nil
	}
	roomStep := d.roomInviteStep(route, event, resolved, now)
	if roomStep == nil {
		roomStep = d.roomKeyPackageStep(route, event, resolved, now)
	}
	delegationJSON, err := identity.EncodeJSON(resolved.Delegation)
	if err != nil {
		return ReceiveResult{}, err
	}
	decision, err := d.admission.AdmitWithCommit(admission.Inbound{Event: event,
		DelegationJSON: delegationJSON, AdmissionToken: message.AdmissionToken,
		Route: route, ReceivedAtUnix: uint64(now.Unix())}, func(entry eventlog.Entry) (bool, error) {
		if roomStep != nil {
			if err := roomStep(); err != nil {
				return false, err
			}
		}
		fresh, _, commitErr := d.journal.CommitInboundFirstContact(message.SessionID,
			binding.AlgorithmID, next, entry, bootstrap, now)
		return fresh, commitErr
	})
	if err != nil {
		return ReceiveResult{}, err
	}
	d.afterRoomEvent(route, event, decision.Outcome)
	return ReceiveResult{Outcome: decision.Outcome, Code: decision.Code, EventID: event.EventID}, nil
}

func (d *Daemon) receiveEstablished(ctx context.Context, message dispatch.Message, record eventlog.SessionRecord,
	route admission.Route, now time.Time, verify peerVerifier) (ReceiveResult, error) {
	if record.Authority == nil || record.AlgorithmID != d.prekeys.suite.AlgorithmID() {
		return ReceiveResult{}, errors.New("session has no supported verified authority")
	}
	a := record.Authority
	if a.LocalAgentID != d.config.AgentID || a.LocalEndpointID != d.config.EndpointID ||
		a.LocalDeviceID != d.config.DeviceID {
		return ReceiveResult{}, errors.New("session belongs to another local identity")
	}
	binding := e2ee.Binding{Network: d.config.Network(), AlgorithmID: record.AlgorithmID,
		ConversationID: message.ConversationID, SenderAgentID: a.PeerAgentID,
		SenderEndpointID: a.PeerEndpointID, SenderDeviceID: a.PeerDeviceID,
		RecipientAgentID: a.LocalAgentID, RecipientEndpointID: a.LocalEndpointID,
		RecipientDeviceID: a.LocalDeviceID}
	if len(message.Bootstrap) != 0 {
		bootstrap, err := e2ee.DecodeFirstContactJSON(message.Bootstrap)
		if err != nil || bootstrap.Binding.SenderAgentID != a.PeerAgentID ||
			bootstrap.Binding.SenderEndpointID != a.PeerEndpointID ||
			bootstrap.Binding.SenderDeviceID != a.PeerDeviceID {
			return ReceiveResult{}, errors.New("session bootstrap attempts authority substitution")
		}
	}
	state, err := record.State()
	if err != nil {
		return ReceiveResult{}, err
	}
	associated, err := binding.Bytes()
	if err != nil {
		return ReceiveResult{}, err
	}
	plaintext, next, err := d.prekeys.suite.Open(state, message.Ciphertext, associated)
	if err != nil {
		return ReceiveResult{}, err
	}
	event, err := validateOpenedMessage(plaintext, message, binding)
	if err != nil {
		return ReceiveResult{}, err
	}
	if refused, ok := refuseOnRoute(route, event); ok {
		return refused, nil
	}
	resolved, err := verify(ctx, a.PeerAgentID, directory.Pin{EndpointID: a.PeerEndpointID, DeviceID: a.PeerDeviceID})
	if err != nil || resolved.Delegation.AgentID != a.PeerAgentID ||
		resolved.EndpointID != a.PeerEndpointID {
		return ReceiveResult{}, errors.New("established sender no longer has verified Endpoint authority")
	}
	roomStep := d.roomInviteStep(route, event, resolved, now)
	if roomStep == nil {
		roomStep = d.roomKeyPackageStep(route, event, resolved, now)
	}
	delegationJSON, err := identity.EncodeJSON(resolved.Delegation)
	if err != nil {
		return ReceiveResult{}, err
	}
	decision, err := d.admission.AdmitWithCommit(admission.Inbound{Event: event,
		DelegationJSON: delegationJSON, AdmissionToken: message.AdmissionToken,
		Route: route, ReceivedAtUnix: uint64(now.Unix())}, func(entry eventlog.Entry) (bool, error) {
		if roomStep != nil {
			if err := roomStep(); err != nil {
				return false, err
			}
		}
		fresh, _, commitErr := d.journal.CommitInbound(message.SessionID, record.AlgorithmID,
			record.Generation, next, entry, now)
		return fresh, commitErr
	})
	if err != nil {
		return ReceiveResult{}, err
	}
	d.afterRoomEvent(route, event, decision.Outcome)
	return ReceiveResult{Outcome: decision.Outcome, Code: decision.Code, EventID: event.EventID}, nil
}

// refuseOnRoute closes two doors on the relay route before anything is
// committed. An Event class that carries an Agent Packet is refused, so a
// rail packet can never reach the rail inbox inside a chat copy. A
// room-addressed Event is refused too: room content crosses the relay only
// sealed to the room (kind 3), so a pairwise copy naming a room could carry
// content past an MLS removal.
func refuseOnRoute(route admission.Route, event envelope.Event) (ReceiveResult, bool) {
	if route != admission.RouteRelay {
		return ReceiveResult{}, false
	}
	if carriesAgentPacket(event.Kind) {
		return ReceiveResult{Outcome: admission.Rejected, Code: fault.CodeClassNotDelegated, EventID: event.EventID}, true
	}
	if event.RoomID != "" {
		return ReceiveResult{Outcome: admission.Rejected, Code: fault.CodePayloadMalformed, EventID: event.EventID}, true
	}
	return ReceiveResult{}, false
}

// carriesAgentPacket reports Event classes whose content is an Agent Packet.
func carriesAgentPacket(kind string) bool {
	class, known := envelope.ClassOf(kind)
	return known && class == "agent.packet"
}

func validateOpenedMessage(raw []byte, message dispatch.Message, binding e2ee.Binding) (envelope.Event, error) {
	event, err := envelope.DecodeEventJSON(raw)
	if err != nil {
		return envelope.Event{}, err
	}
	if event.EventID != message.EventID || event.ConversationID != message.ConversationID ||
		event.SenderAgentID != binding.SenderAgentID || event.SenderEndpointID != binding.SenderEndpointID ||
		event.SenderDeviceID != binding.SenderDeviceID || !sameMessengerNetwork(event.Network, binding.Network) {
		return envelope.Event{}, errors.New("opened Event conflicts with session binding")
	}
	return event, nil
}

func containsExactBundle(values []e2ee.Bundle, wanted e2ee.Bundle) bool {
	wire, err := e2ee.EncodeBundleJSON(wanted)
	if err != nil {
		return false
	}
	for _, value := range values {
		candidate, err := e2ee.EncodeBundleJSON(value)
		if err == nil && bytes.Equal(candidate, wire) {
			return true
		}
	}
	return false
}

func clearSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func sameMessengerNetwork(first, second *nativev1.NetworkDomain) bool {
	return first != nil && second != nil && first.NetworkId == second.NetworkId &&
		first.GenesisRootHash == second.GenesisRootHash && first.GenesisFileHash == second.GenesisFileHash
}
