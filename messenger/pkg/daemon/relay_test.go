package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/admission"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/directory"
	"github.com/tosnetwork/ai/messenger/pkg/dispatch"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/payload"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
)

// carried is one frame the daemon handed to its carrier.
type carried struct {
	recipient, key, withdraw string
	frame                    []byte
}

// recordingCarrier stands in for the OpenFox chat transport: it accepts
// every frame and keeps it for the test to deliver.
type recordingCarrier struct {
	mutex  sync.Mutex
	frames []carried
}

func (c *recordingCarrier) Carry(_ context.Context, recipient, key, withdraw string, _ uint64,
	frame []byte) (carrierapi.Response, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.frames = append(c.frames, carried{recipient: recipient, key: key, withdraw: withdraw,
		frame: append([]byte(nil), frame...)})
	return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultCarried}, nil
}

func (c *recordingCarrier) take() []carried {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	frames := c.frames
	c.frames = nil
	return frames
}

type relayNode struct {
	d       *Daemon
	carrier *recordingCarrier
	key     ed25519.PrivateKey
	export  string
}

var relayTestPolicy = directory.DescriptorPolicy{MaxEnvelopeBytes: 64 << 10, MaxLifetimeSeconds: 3600, AllowHTTPSEndpoint: true}

func relayCard(t *testing.T, agentID string) []byte {
	t.Helper()
	card, err := agentpacket.EncodeJSON(agentpacket.Packet{SenderAgentID: agentID,
		RecipientAgentID: "agent_" + strings.Repeat("f", 64), CapabilityID: "cap_" + strings.Repeat("e", 64),
		Sequence: 1, Nonce: [32]byte{1}, Payload: []byte("chat key card body"), CreatedAtUnix: 1,
		SenderKeyID: [mldsa44.KeyIDSize]byte{2}, Signature: make([]byte, mldsa44.SignatureSize)})
	if err != nil {
		t.Fatal(err)
	}
	return card
}

func relayResolver(nodes ...*Daemon) phaseAResolver {
	states := map[string]*nativev1.NativeStateV1{}
	for _, node := range nodes {
		digest, _ := identity.Digest(node.prekeys.planner.delegation)
		states[node.config.AgentID] = &nativev1.NativeStateV1{Network: node.config.Network(),
			TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("c", 64),
			Reference: &nativev1.ChainReference{Workchain: 0, Account: "0:" + strings.Repeat("d", 64),
				LogicalTime: 42, TransactionHash: "sha256:" + strings.Repeat("e", 64),
				ContractCodeHash: registryCode, FinalizedCheckpoint: 100},
			State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: node.config.AgentID,
				Policy: &nativev1.ControllerPolicyV1{Threshold: 1}, DelegationDigests: []string{digest}}}}
	}
	return phaseAResolver{states: states}
}

// newRelayNodes builds independent daemons with relay carriage, sharing one
// finalized view, each exporting its own relay evidence.
func newRelayNodes(t *testing.T, now time.Time, digits ...[2]string) []*relayNode {
	t.Helper()
	daemons := make([]*Daemon, 0, len(digits))
	for _, pair := range digits {
		daemons = append(daemons, newPhaseADaemon(t, now, pair[0], pair[1]))
	}
	resolver := relayResolver(daemons...)
	chain := identity.ChainPolicy{RegistryCodeHashes: []string{registryCode}, Locator: phaseALocator{}}
	nodes := make([]*relayNode, 0, len(daemons))
	for _, d := range daemons {
		d.config.Transport = TransportAgentPacketRelay
		delegation := d.prekeys.planner.delegation
		devices, err := d.journal.OpenDevices()
		if err != nil {
			t.Fatal(err)
		}
		verifier := &directory.RelayVerifier{Resolver: resolver, Network: d.config.Network(), Chain: chain,
			Judge: devices, Admitter: devices, Store: d.journal, LocalAgentID: d.config.AgentID}
		d.discovery = &discoveryRuntime{contacts: relayDirectory{verifier: verifier, now: d.clock}, chain: chain,
			resolver: resolver, devices: devices, relay: verifier}
		localRaw, _ := identity.EncodeJSON(delegation)
		policy, _ := d.config.AdmissionPolicy()
		gate, err := admission.New(admission.Config{Network: d.config.Network(), Chain: chain, Resolver: resolver,
			Journal: d.journal, Devices: devices, Policy: policy, LocalDelegationJSON: localRaw,
			LocalAgentID: d.config.AgentID, LocalEndpointID: d.config.EndpointID, Now: d.clock,
			InstallSalt: bytes.Repeat([]byte{0x5a}, admission.MinInstallSaltBytes)})
		if err != nil {
			t.Fatal(err)
		}
		d.admission = gate
		dispatcher, err := dispatch.New(dispatch.Config{Journal: d.journal, Identity: d.config.Identity(),
			Network: d.config.Network(), Now: d.clock, AllowedEventClasses: delegation.AllowedOutboundEventClasses})
		if err != nil {
			t.Fatal(err)
		}
		d.dispatch = dispatcher
		root := t.TempDir()
		cardPath := filepath.Join(root, "card.json")
		if err := os.WriteFile(cardPath, relayCard(t, d.config.AgentID), 0o600); err != nil {
			t.Fatal(err)
		}
		export := filepath.Join(root, "export")
		sink, err := directory.NewRelayEvidenceSink(export, cardPath, localRaw, relayTestPolicy)
		if err != nil {
			t.Fatal(err)
		}
		delegationDigest, _ := identity.Digest(delegation)
		publisher := &directory.GenerationPublisher{Signer: d.prekeys.signer, Delegation: delegation,
			Policy: relayTestPolicy, PublishInterval: time.Minute, Relay: sink,
			Descriptor: directory.Descriptor{Network: delegation.Network, AgentID: delegation.AgentID,
				EndpointID: delegation.EndpointID, DelegationDigest: delegationDigest, SupportedMessagingVersions: []uint32{1},
				HTTPSEndpoint:      "https://relay-only.example" + "/v1/tos-messenger/messages",
				PrekeyBundleDigest: "sha256:" + strings.Repeat("1", 64), InboxAdmissionPolicyDigest: delegation.InboxAdmissionPolicyDigest,
				MaximumEnvelopeBytes: 64 << 10, IssuedAtUnix: 1, ExpiresAtUnix: 2}}
		if err := publisher.Validate(); err != nil {
			t.Fatalf("relay-only publisher: %v", err)
		}
		d.prekeys.publisher = publisher
		if err := d.prekeys.publishCurrent(context.Background()); err != nil {
			t.Fatalf("publish own relay evidence: %v", err)
		}
		carrier := &recordingCarrier{}
		if err := d.installRelayRuntime(sink, carrier, MinRelayRedepositInterval, 30*time.Second); err != nil {
			t.Fatalf("install relay: %v", err)
		}
		key, ok := d.prekeys.signer.(ed25519.PrivateKey)
		if !ok {
			t.Fatal("test signer is not an Ed25519 key")
		}
		nodes = append(nodes, &relayNode{d: d, carrier: carrier, key: key, export: export})
	}
	return nodes
}

// importContact runs the contact-file import of peer's exported contact.
func importContact(t *testing.T, local, peer *relayNode) {
	t.Helper()
	importer := &contactImporter{verifier: local.d.discovery.relay, localAgentID: local.d.config.AgentID, now: local.d.clock}
	fresh, err := importer.importFile(filepath.Join(peer.export, directory.RelayContactFile))
	if err != nil || !fresh {
		t.Fatalf("import contact: fresh=%v err=%v", fresh, err)
	}
}

// deliver hands one frame to the recipient as the carrier would and, for a
// copy, returns the recipient's answer.
func deliver(t *testing.T, from, to *relayNode, frame []byte) carrierapi.Response {
	t.Helper()
	response := to.d.relay.Deliver(context.Background(), from.d.config.AgentID, frame)
	response.Schema = carrierapi.ResponseSchema
	if err := carrierapi.ValidateResponse(carrierapi.OpDeliver, response); err != nil {
		t.Fatalf("invalid deliver response %s/%s: %v", response.Result, response.Code, err)
	}
	return response
}

func ackFrameOf(t *testing.T, response carrierapi.Response) []byte {
	t.Helper()
	if response.Result != carrierapi.ResultAck {
		t.Fatalf("no ack: %+v", response)
	}
	raw, err := base64.StdEncoding.DecodeString(response.AckFrameBase64)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func onlyFrame(t *testing.T, node *relayNode) carried {
	t.Helper()
	frames := node.carrier.take()
	if len(frames) != 1 {
		t.Fatalf("carrier holds %d frames, want 1", len(frames))
	}
	return frames[0]
}

func copyState(t *testing.T, node *relayNode, eventID, peerEndpoint, peerDevice string) eventlog.Delivery {
	t.Helper()
	copyID, err := eventlog.NewDeliveryCopyID(eventID, peerEndpoint, peerDevice)
	if err != nil {
		t.Fatal(err)
	}
	delivery, found, err := node.d.journal.LookupDeliveryCopy(copyID)
	if err != nil || !found {
		t.Fatalf("copy %s: found=%v err=%v", copyID, found, err)
	}
	return delivery
}

func sendText(t *testing.T, from, to *relayNode, body, idem string, now time.Time) string {
	t.Helper()
	result, err := from.d.SendDirectMessage(context.Background(), to.d.config.AgentID, "text/plain; charset=utf-8",
		body, "idem_"+strings.Repeat(idem, 64), uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatalf("send %q: %v", body, err)
	}
	return result.EventID
}

func TestRelayCopyIsCarriedAndDeliveredOnlyOnAVerifiedAck(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)

	first := sendText(t, a, b, "hello B", "a", now)
	summary, err := a.d.dispatch.Sweep(context.Background(), 0)
	if err != nil || summary.Carried != 1 || summary.Sent != 0 || summary.Sealed != 1 {
		t.Fatalf("sweep: %+v %v", summary, err)
	}
	if state := copyState(t, a, first, b.d.config.EndpointID, b.d.config.DeviceID); state.State != eventlog.StateCarried ||
		state.Generation != 1 || len(state.Generations) != 1 || state.Generations[0].CardDigest == "" {
		t.Fatalf("copy after carry: %+v", state)
	}
	out := onlyFrame(t, a)
	frame, err := relayframe.Decode(out.frame)
	if err != nil || frame.Kind != relayframe.KindCopy || len(frame.Card) == 0 || len(frame.Evidence) == 0 {
		t.Fatalf("copy frame: kind=%d card=%d err=%v", frame.Kind, len(frame.Card), err)
	}
	copyID, _ := eventlog.NewDeliveryCopyID(first, b.d.config.EndpointID, b.d.config.DeviceID)
	if key, _ := relayframe.CopyIdempotencyKey(copyID, 1); out.key != key || out.withdraw != "" || out.recipient != b.d.config.AgentID {
		t.Fatalf("carry request: %+v", out)
	}
	if size := len(out.frame); size != 4<<10 && size != 8<<10 && size != 16<<10 {
		t.Fatalf("copy frame is %d bytes", size)
	}

	answer := deliver(t, a, b, out.frame)
	if answer.AckOutcome != relayframe.OutcomeAccepted {
		t.Fatalf("answer: %+v", answer)
	}
	assertPhaseAPendingText(t, b.d, first, "hello B", now)
	if admitted, err := b.d.discovery.relay.Admitted(a.d.config.AgentID); err != nil || !admitted {
		t.Fatal("an accepted copy did not leave its sender admitted")
	}
	// Storage is not delivery: until the ack arrives the copy stays carried.
	if state := copyState(t, a, first, b.d.config.EndpointID, b.d.config.DeviceID); state.State != eventlog.StateCarried {
		t.Fatalf("copy settled without an ack: %+v", state)
	}
	ack := ackFrameOf(t, answer)
	if applied := a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, ack); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("ack: %+v", applied)
	}
	if state := copyState(t, a, first, b.d.config.EndpointID, b.d.config.DeviceID); state.State != eventlog.StateDelivered {
		t.Fatalf("copy after a verified ack: %+v", state)
	}
	if repeated := a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, ack); repeated.Result != carrierapi.ResultIgnored {
		t.Fatalf("a repeated ack: %+v", repeated)
	}

	// B replies over the relay; its first frame carries its card.
	reply, err := b.d.ReplyDirectMessage(context.Background(), first, "text/plain; charset=utf-8", "hello A",
		"idem_"+strings.Repeat("b", 64), uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatalf("reply: %v", err)
	}
	if summary, err := b.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("reply sweep: %+v %v", summary, err)
	}
	replyAnswer := deliver(t, b, a, onlyFrame(t, b).frame)
	assertPhaseAPendingText(t, a.d, reply.EventID, "hello A", now)
	if applied := b.d.relay.DeliveryAck(context.Background(), a.d.config.AgentID, ackFrameOf(t, replyAnswer)); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("reply ack: %+v", applied)
	}

	// B acknowledged a frame that carried A's card, so A stops sending it.
	second := sendText(t, a, b, "again", "c", now)
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("second sweep: %+v %v", summary, err)
	}
	again, err := relayframe.Decode(onlyFrame(t, a).frame)
	if err != nil || len(again.Card) != 0 {
		t.Fatalf("a frame after the card was acknowledged still carries it: card=%d err=%v", len(again.Card), err)
	}
	_ = second
}

func TestRelayDeliveryAckIsAppliedOnlyFromTheSigningEndpointsAgent(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"}, [2]string{"5", "6"})
	a, b, c := nodes[0], nodes[1], nodes[2]
	importContact(t, a, b)
	importContact(t, b, a)
	first := sendText(t, a, b, "hello B", "a", now)
	if _, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	ack := ackFrameOf(t, deliver(t, a, b, onlyFrame(t, a).frame))

	// The right ack in a packet from another Agent is refused.
	if refused := a.d.relay.DeliveryAck(context.Background(), c.d.config.AgentID, ack); refused.Result != carrierapi.ResultRefused ||
		refused.Code != carrierapi.CodeSenderMismatch {
		t.Fatalf("ack from another Agent: %+v", refused)
	}
	// An ack for the copy signed by another key, in B's packet with B's
	// evidence, is refused too.
	decoded, err := relayframe.Decode(ack)
	if err != nil {
		t.Fatal(err)
	}
	original, err := relayframe.DecodeAck(decoded.Part)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := relayframe.SignAck(relayframe.Ack{EventID: original.EventID, SessionID: original.SessionID,
		RecipientEndpointID: original.RecipientEndpointID, RecipientDeviceID: original.RecipientDeviceID,
		CiphertextDigest: original.CiphertextDigest, Outcome: original.Outcome, AcceptedAtUnix: original.AcceptedAtUnix}, c.key)
	if err != nil {
		t.Fatal(err)
	}
	forgedObject, _ := relayframe.EncodeAck(forged)
	forgedFrame, err := relayframe.Encode(relayframe.Frame{Kind: relayframe.KindDeliveryAck, PartCount: 1,
		Evidence: decoded.Evidence, Part: forgedObject})
	if err != nil {
		t.Fatal(err)
	}
	if refused := a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, forgedFrame); refused.Result != carrierapi.ResultRefused {
		t.Fatalf("forged ack: %+v", refused)
	}
	// A copy frame is not an ack.
	if refused := a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, mustFrame(t, relayframe.KindEvidence, decoded.Evidence)); refused.Code != carrierapi.CodeKindNotCarried {
		t.Fatalf("evidence frame as ack: %+v", refused)
	}
	if state := copyState(t, a, first, b.d.config.EndpointID, b.d.config.DeviceID); state.State != eventlog.StateCarried {
		t.Fatalf("a refused ack settled the copy: %+v", state)
	}
	if applied := a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, ack); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("genuine ack: %+v", applied)
	}
}

func mustFrame(t *testing.T, kind uint8, evidence []byte) []byte {
	t.Helper()
	raw, err := relayframe.Encode(relayframe.Frame{Kind: kind, PartCount: 1, Card: []byte("card"), Evidence: evidence,
		Part: []byte{relayframe.EvidenceRequest}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRelayRefusesAgentPacketEventsAndSenderSubstitution(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"}, [2]string{"5", "6"})
	a, b, c := nodes[0], nodes[1], nodes[2]
	importContact(t, a, b)
	importContact(t, b, a)

	first := sendText(t, a, b, "establish", "a", now)
	if _, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	firstFrame := onlyFrame(t, a).frame
	// The first-contact copy in a packet from another Agent is refused before
	// it is opened.
	if refused := deliver(t, c, b, firstFrame); refused.Result != carrierapi.ResultRefused || refused.Code != carrierapi.CodeSenderMismatch {
		t.Fatalf("first contact from another packet sender: %+v", refused)
	}
	if _, found, _ := b.d.journal.Lookup(first); found {
		t.Fatal("a substituted first contact was committed")
	}
	a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, ackFrameOf(t, deliver(t, a, b, firstFrame)))

	// The composition boundary refuses an Agent Packet Event on this route.
	packetJSON := relayCard(t, a.d.config.AgentID)
	if _, err := a.d.SendDirectApplication(context.Background(), b.d.config.AgentID, "agent.packet", packetJSON,
		"idem_"+strings.Repeat("d", 64), uint64(now.Add(time.Hour).Unix())); fault.CodeOf(err) != fault.CodeClassNotDelegated {
		t.Fatalf("Agent Packet composition on the relay route: %v", err)
	}
	// One queued below that boundary is refused by the receiver, before
	// anything is committed.
	content, err := payload.Encode(payload.AgentPacketMessage{Foreign: payload.Foreign{Protocol: "agentpacket", Version: "1", Body: packetJSON}})
	if err != nil {
		t.Fatal(err)
	}
	delivered := copyState(t, a, first, b.d.config.EndpointID, b.d.config.DeviceID)
	event, err := envelope.NewEvent(envelope.Event{Network: a.d.config.Network(), ConversationID: delivered.ConversationID,
		SenderAgentID: a.d.config.AgentID, SenderEndpointID: a.d.config.EndpointID, SenderDeviceID: a.d.config.DeviceID,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), Kind: "agent.packet",
		IdempotencyKey: strings.Repeat("e", 64), Content: content})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.d.dispatch.QueueCopies(event, []dispatch.CopyTarget{{SessionID: delivered.SessionID,
		RecipientEndpointID: b.d.config.EndpointID, RecipientDeviceID: b.d.config.DeviceID}}, event.ExpiresAtUnix); err != nil {
		t.Fatal(err)
	}
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("sweep: %+v %v", summary, err)
	}
	packetFrame := onlyFrame(t, a).frame
	answer := deliver(t, a, b, packetFrame)
	ack, err := relayframe.Decode(ackFrameOf(t, answer))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := relayframe.DecodeAck(ack.Part)
	if err != nil || decoded.Outcome != relayframe.OutcomeRejected || decoded.Code != fault.CodeClassNotDelegated {
		t.Fatalf("agent.packet answer: %+v %v", decoded, err)
	}
	if _, found, _ := b.d.journal.Lookup(event.EventID); found {
		t.Fatal("an Agent Packet Event over the relay reached the journal")
	}
	// The sender applies the permanent rejection.
	a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, ackFrameOf(t, answer))
	if state := copyState(t, a, event.EventID, b.d.config.EndpointID, b.d.config.DeviceID); state.State != eventlog.StateAbandoned ||
		state.LastCode != fault.CodeClassNotDelegated {
		t.Fatalf("rejected Agent Packet copy: %+v", state)
	}
	// A copy of an established session in a packet from another Agent is
	// refused permanently.
	if refused := deliver(t, c, b, packetFrame); refused.Result != carrierapi.ResultRefused || refused.Code != carrierapi.CodeSenderMismatch {
		t.Fatalf("established copy from another packet sender: %+v", refused)
	}
}

func TestRelayOlderDuplicateAfterANewerEventIsADuplicate(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	sendText(t, a, b, "one", "a", now)
	if _, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	deliver(t, a, b, onlyFrame(t, a).frame)
	second := sendText(t, a, b, "two", "b", now)
	if _, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	secondFrame := onlyFrame(t, a).frame
	third := sendText(t, a, b, "three", "c", now)
	if _, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	thirdFrame := onlyFrame(t, a).frame
	if answer := deliver(t, a, b, secondFrame); answer.AckOutcome != relayframe.OutcomeAccepted {
		t.Fatalf("second: %+v", answer)
	}
	if answer := deliver(t, a, b, thirdFrame); answer.AckOutcome != relayframe.OutcomeAccepted {
		t.Fatalf("third: %+v", answer)
	}
	sessionID := copyState(t, a, second, b.d.config.EndpointID, b.d.config.DeviceID).SessionID
	before, _, err := b.d.journal.SessionState(sessionID)
	if err != nil || before.LastInboundEventID != third {
		t.Fatalf("session before the replay: last=%s err=%v", before.LastInboundEventID, err)
	}
	// The older copy arrives again after a newer Event of the same session.
	replay := deliver(t, a, b, secondFrame)
	if replay.Result != carrierapi.ResultAck || replay.AckOutcome != relayframe.OutcomeDuplicate {
		t.Fatalf("older duplicate: %+v", replay)
	}
	after, _, err := b.d.journal.SessionState(sessionID)
	if err != nil || after.Generation != before.Generation || after.StateBase64 != before.StateBase64 {
		t.Fatal("an older duplicate reached the ratchet")
	}
	assertPhaseAPendingText(t, b.d, second, "two", now)
}

// The same gap on the network route, through ReceiveSealed.
type capturingLoopSender struct {
	recipient *Daemon
	messages  *[]dispatch.Message
}

func (s capturingLoopSender) Send(ctx context.Context, message dispatch.Message) error {
	*s.messages = append(*s.messages, message)
	_, err := s.recipient.ReceiveSealed(ctx, message, admission.RouteDirect)
	return err
}

func TestNetworkRouteOlderDuplicateAfterANewerEventIsADuplicate(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	a := newPhaseADaemon(t, now, "2", "4")
	b := newPhaseADaemon(t, now, "7", "9")
	connectPhaseADirectories(a, b, now)
	connectPhaseADirectories(b, a, now)
	installPhaseAAdmission(t, now, a, b)
	installPhaseAAdmission(t, now, b, a)
	var messages []dispatch.Message
	dispatcher, err := dispatch.New(dispatch.Config{Journal: a.journal, Suite: e2ee.NewDefaultSuite(),
		Sender: capturingLoopSender{recipient: b, messages: &messages}, Bindings: dispatch.SessionBindings{Journal: a.journal,
			Identity: a.config.Identity(), Network: a.config.Network()},
		Now: func() time.Time { return now }, Identity: a.config.Identity(), Network: a.config.Network(),
		AllowedEventClasses: []string{"text"}})
	if err != nil {
		t.Fatal(err)
	}
	a.dispatch = dispatcher
	for index, body := range []string{"one", "two", "three"} {
		if _, err := a.SendDirectMessage(context.Background(), b.config.AgentID, "text/plain; charset=utf-8", body,
			"idem_"+strings.Repeat(string(rune('a'+index)), 64), uint64(now.Add(time.Hour).Unix())); err != nil {
			t.Fatal(err)
		}
		if summary, err := a.dispatch.Sweep(context.Background(), 0); err != nil || summary.Sent != 1 {
			t.Fatalf("send %s: %+v %v", body, summary, err)
		}
	}
	result, err := b.ReceiveSealed(context.Background(), messages[1], admission.RouteDirect)
	if err != nil || result.Outcome != admission.Duplicate {
		t.Fatalf("older duplicate on the network route: %+v %v", result, err)
	}
	if _, err := b.ReceiveSealed(context.Background(), messages[1], admission.RouteRelay); err == nil {
		t.Fatal("ReceiveSealed accepted the relay route, which needs its evidence")
	}
}

// oldEvidence builds expired evidence for a node with an older descriptor and
// a different bundle, signed by the node's own Endpoint key.
func oldEvidence(t *testing.T, node *relayNode, now time.Time) []byte {
	t.Helper()
	delegation := node.d.prekeys.planner.delegation
	public, _, err := e2ee.NewDefaultSuite().NewPrekeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	issued := uint64(now.Add(-50 * time.Second).Unix())
	expires := uint64(now.Add(-10 * time.Second).Unix())
	bundle, err := e2ee.SignBundle(e2ee.Bundle{Network: delegation.Network, AgentID: delegation.AgentID,
		EndpointID: delegation.EndpointID, DeviceID: node.d.config.DeviceID, AlgorithmID: e2ee.DefaultCandidateAlgorithmID,
		Material: public, IssuedAtUnix: issued, ExpiresAtUnix: expires}, node.key)
	if err != nil {
		t.Fatal(err)
	}
	set, _ := e2ee.EncodeBundleSetJSON([]e2ee.Bundle{bundle})
	setDigest, _ := e2ee.SetDigest([]e2ee.Bundle{bundle})
	delegationDigest, _ := identity.Digest(delegation)
	descriptor, err := directory.SignDescriptor(directory.Descriptor{Network: delegation.Network, AgentID: delegation.AgentID,
		EndpointID: delegation.EndpointID, DelegationDigest: delegationDigest, SupportedMessagingVersions: []uint32{1},
		HTTPSEndpoint: "https://relay-only.example/v1/tos-messenger/messages", PrekeyBundleDigest: setDigest,
		InboxAdmissionPolicyDigest: delegation.InboxAdmissionPolicyDigest, MaximumEnvelopeBytes: 64 << 10,
		IssuedAtUnix: issued, ExpiresAtUnix: expires}, node.key)
	if err != nil {
		t.Fatal(err)
	}
	descriptorJSON, _ := directory.EncodeDescriptorJSON(descriptor)
	delegationJSON, _ := identity.EncodeJSON(delegation)
	policyJSON, _ := directory.EncodeDescriptorPolicyJSON(relayTestPolicy)
	raw, err := relayframe.EncodeEvidence(relayframe.Evidence{Delegation: delegationJSON, Policy: policyJSON,
		Descriptor: descriptorJSON, BundleSet: set})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func framesOfKind(t *testing.T, frames []carried, kind uint8) []carried {
	t.Helper()
	var selected []carried
	for _, frame := range frames {
		decoded, err := relayframe.Decode(frame.frame)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Kind == kind {
			selected = append(selected, frame)
		}
	}
	return selected
}

func TestRelayEvidencePullRepairsStaleEvidenceInOneRoundTrip(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"}, [2]string{"5", "6"})
	a, b, stranger := nodes[0], nodes[1], nodes[2]
	importContact(t, a, b)
	importContact(t, b, a)
	first := sendText(t, a, b, "establish", "a", now)
	if _, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, ackFrameOf(t, deliver(t, a, b, onlyFrame(t, a).frame)))

	// No copy is pending: publishing a descriptor, or a sweep, sends nothing.
	if err := a.d.prekeys.publishCurrent(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.d.relay.sweepPulls(context.Background())
	if frames := a.carrier.take(); len(frames) != 0 {
		t.Fatalf("frames without a pending copy: %d", len(frames))
	}

	// Two copies are queued, then A's stored view of B goes stale.
	sendText(t, a, b, "pending one", "b", now)
	sendText(t, a, b, "pending two", "c", now)
	stored, _, err := a.d.journal.LoadRelayEvidence(b.d.config.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.d.journal.StoreRelayEvidence(b.d.config.AgentID, oldEvidence(t, b, now), canon.Digest(stored), now); err != nil {
		t.Fatal(err)
	}
	summary, err := a.d.dispatch.Sweep(context.Background(), 0)
	if err != nil || summary.Deferred != 2 || summary.Sealed != 0 || summary.Carried != 0 {
		t.Fatalf("stale evidence did not hold the copies unsealed: %+v %v", summary, err)
	}
	if frames := a.carrier.take(); len(frames) != 0 {
		t.Fatal("a copy was carried while the recipient's evidence failed CheckPeer")
	}
	// One request for two pending copies, and none again before its schedule.
	a.d.relay.sweepPulls(context.Background())
	a.d.relay.sweepPulls(context.Background())
	requests := a.carrier.take()
	if len(requests) != 1 || len(framesOfKind(t, requests, relayframe.KindEvidence)) != 1 {
		t.Fatalf("evidence requests: %d", len(requests))
	}
	request := requests[0]
	if key, _ := relayframe.EvidenceRequestKey(b.d.config.AgentID, 1); request.key != key {
		t.Fatalf("request key %s", request.key)
	}

	// A stranger's request gets nothing and writes nothing.
	strangerRequest, _, err := stranger.d.relay.ownFrame(relayframe.KindEvidence, b.d.config.AgentID,
		[]byte{relayframe.EvidenceRequest}, true)
	if err != nil {
		t.Fatal(err)
	}
	if ignored := deliver(t, stranger, b, strangerRequest); ignored.Result != carrierapi.ResultIgnored {
		t.Fatalf("stranger request: %+v", ignored)
	}
	if _, found, _ := b.d.journal.LoadRelayPull(stranger.d.config.AgentID); found {
		t.Fatal("a stranger's request was written")
	}
	if _, found, _ := b.d.journal.LoadRelayEvidence(stranger.d.config.AgentID); found {
		t.Fatal("a stranger's evidence was stored")
	}
	if _, found, _ := b.d.discovery.devices.Record(stranger.d.config.EndpointID); found {
		t.Fatal("a stranger's set reached the rollback boundary")
	}
	b.d.relay.sweepPulls(context.Background())
	if frames := b.carrier.take(); len(frames) != 0 {
		t.Fatal("a stranger was answered")
	}

	// B answers A's request once.
	if admitted := deliver(t, a, b, request.frame); admitted.Result != carrierapi.ResultAdmitted {
		t.Fatalf("request: %+v", admitted)
	}
	b.d.relay.sweepPulls(context.Background())
	responses := b.carrier.take()
	if len(responses) != 1 {
		t.Fatalf("responses: %d", len(responses))
	}
	response, err := relayframe.Decode(responses[0].frame)
	if err != nil || response.Kind != relayframe.KindEvidence || response.Part[0] != relayframe.EvidenceResponse || len(response.Card) == 0 {
		t.Fatalf("response frame: %+v %v", response.Kind, err)
	}
	// A repeated request within the hour for the same own descriptor gets no
	// second response.
	deliver(t, a, b, request.frame)
	b.d.relay.sweepPulls(context.Background())
	if again := b.carrier.take(); len(again) != 0 {
		t.Fatal("a second response within the hour")
	}

	// A commits B's fresh evidence; the request ends, is never answered, and
	// the copies are sealed and carried.
	if admitted := deliver(t, b, a, responses[0].frame); admitted.Result != carrierapi.ResultAdmitted {
		t.Fatalf("response: %+v", admitted)
	}
	pull, _, err := a.d.journal.LoadRelayPull(b.d.config.AgentID)
	if err != nil || pull.Requested || pull.ResponsePending {
		t.Fatalf("pull after the response: %+v %v", pull, err)
	}
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 2 || summary.Sealed != 2 {
		t.Fatalf("sweep after fresh evidence: %+v %v", summary, err)
	}
	a.d.relay.sweepPulls(context.Background())
	if frames := framesOfKind(t, a.carrier.take(), relayframe.KindEvidence); len(frames) != 0 {
		t.Fatal("an evidence frame was sent after the request was answered")
	}
	_ = first
}

func TestRelayRevocationHoldsTheCopyUnsealed(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	sendText(t, a, b, "establish", "a", now)
	if _, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	a.carrier.take()
	// A copy is queued, then B's Endpoint delegation is withdrawn in
	// finalized state before it is sealed.
	pending := sendText(t, a, b, "after revocation", "b", now)
	resolver := a.d.discovery.resolver.(phaseAResolver)
	resolver.states[b.d.config.AgentID].GetAgent().DelegationDigests = []string{"sha256:" + strings.Repeat("9", 64)}
	summary, err := a.d.dispatch.Sweep(context.Background(), 0)
	if err != nil || summary.Deferred != 1 || summary.Sealed != 0 {
		t.Fatalf("revoked Endpoint: %+v %v", summary, err)
	}
	state := copyState(t, a, pending, b.d.config.EndpointID, b.d.config.DeviceID)
	if state.State != eventlog.StatePending || state.LastCode != fault.CodeDelegationUncommitted || state.CiphertextBase64 != "" {
		t.Fatalf("copy to a revoked Endpoint: %+v", state)
	}
	if frames := framesOfKind(t, a.carrier.take(), relayframe.KindCopy); len(frames) != 0 {
		t.Fatal("a copy was carried to a revoked Endpoint")
	}
}

func TestRelayOversizedPayloadIsRefusedBeforeSealing(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	body := strings.Repeat("x", 110_000)
	if _, err := a.d.SendDirectMessage(context.Background(), b.d.config.AgentID, "text/plain; charset=utf-8", body,
		"idem_"+strings.Repeat("a", 64), uint64(now.Add(time.Hour).Unix())); fault.CodeOf(err) != fault.CodeContentTooLarge {
		t.Fatalf("oversized composition: %v", err)
	}
	if due, err := a.d.journal.Due(now); err != nil || len(due) != 0 {
		t.Fatalf("an oversized message was queued: %+v %v", due, err)
	}
}

func TestDescriptorExpiredRetriesAtOnceOnlyWithNewerEvidence(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	first := sendText(t, a, b, "one", "a", now)
	second := sendText(t, a, b, "two", "b", now)
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 2 {
		t.Fatalf("sweep: %+v %v", summary, err)
	}
	a.carrier.take()
	reject := func(eventID string, delivery eventlog.Delivery) eventlog.Delivery {
		t.Helper()
		ciphertext, _ := delivery.Ciphertext()
		ack := relayframe.Ack{EventID: eventID, SessionID: delivery.SessionID, RecipientEndpointID: b.d.config.EndpointID,
			RecipientDeviceID: b.d.config.DeviceID, CiphertextDigest: canon.Digest(ciphertext),
			Outcome: relayframe.OutcomeRejected, Code: fault.CodeDescriptorExpired, AcceptedAtUnix: uint64(now.Unix())}
		match := eventlog.RelayAckMatch{SessionID: delivery.SessionID, DeviceID: b.d.config.DeviceID,
			CiphertextDigest: ack.CiphertextDigest}
		if err := a.d.relay.applyAck(delivery.Key(), delivery, ack, match, now); err != nil {
			t.Fatal(err)
		}
		return copyState(t, a, eventID, b.d.config.EndpointID, b.d.config.DeviceID)
	}
	// The refused evidence is the current one: wait on the backoff.
	same := reject(first, copyState(t, a, first, b.d.config.EndpointID, b.d.config.DeviceID))
	if same.State != eventlog.StatePending || same.NextAttemptAtUnix < uint64(now.Add(30*time.Second).Unix()) ||
		same.NextAttemptAtUnix > uint64(now.Add(5*time.Minute).Unix()) || same.RejectedDescriptorDigest == "" {
		t.Fatalf("not-newer retry: %+v", same)
	}
	// The refused evidence is older than the current one: retry at once.
	older := copyState(t, a, second, b.d.config.EndpointID, b.d.config.DeviceID)
	older.Generations[len(older.Generations)-1].DescriptorDigest = "sha256:" + strings.Repeat("6", 64)
	older.Generations[len(older.Generations)-1].DescriptorIssuedAtUnix--
	newer := reject(second, older)
	if newer.State != eventlog.StatePending || newer.NextAttemptAtUnix != uint64(now.Unix()) {
		t.Fatalf("newer retry: %+v", newer)
	}
	for attempt, want := range map[uint32]time.Duration{1: 30 * time.Second, 2: time.Minute, 4: 4 * time.Minute, 9: 5 * time.Minute} {
		if got := descriptorExpiredBackoff(attempt); got != want {
			t.Fatalf("backoff %d = %v want %v", attempt, got, want)
		}
	}
}

func TestContactImportRefusesWhatItCannotVerify(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importer := &contactImporter{verifier: a.d.discovery.relay, localAgentID: a.d.config.AgentID, now: a.d.clock}
	raw, err := os.ReadFile(filepath.Join(b.export, directory.RelayContactFile))
	if err != nil {
		t.Fatal(err)
	}
	contact, err := relayframe.DecodeContactJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, value relayframe.Contact) string {
		t.Helper()
		encoded, err := relayframe.EncodeContactJSON(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	self := contact
	self.AgentID = a.d.config.AgentID
	self.Card = relayCard(t, a.d.config.AgentID)
	if _, err := importer.importFile(write("self.json", self)); err == nil {
		t.Fatal("a contact naming this installation was imported")
	}
	otherCard := contact
	otherCard.Card = relayCard(t, a.d.config.AgentID)
	if _, err := importer.importFile(write("card.json", otherCard)); err == nil {
		t.Fatal("a contact whose card names another Agent was imported")
	}
	if _, err := importer.importFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("a missing contact file was imported")
	}
	if admitted, _ := a.d.discovery.relay.Admitted(b.d.config.AgentID); admitted {
		t.Fatal("a refused contact was admitted")
	}
	if fresh, err := importer.importFile(filepath.Join(b.export, directory.RelayContactFile)); err != nil || !fresh {
		t.Fatalf("valid contact: %v %v", fresh, err)
	}
	if fresh, err := importer.importFile(filepath.Join(b.export, directory.RelayContactFile)); err != nil || fresh {
		t.Fatalf("re-importing the same contact must be a no-op: %v %v", fresh, err)
	}
}
