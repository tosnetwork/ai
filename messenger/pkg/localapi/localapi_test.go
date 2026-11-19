package localapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/contact"
	"github.com/tosnetwork/ai/messenger/pkg/directory"
	"github.com/tosnetwork/ai/messenger/pkg/dispatch"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/firewall"
	"github.com/tosnetwork/ai/messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
	protocolcodec "github.com/tosnetwork/ai/protocol/pkg/codec"
)

const (
	baseUnix  = uint64(1_800_000_000)
	algorithm = "tos.messaging.e2ee.test-double.v1"
	senderID  = "agent_" + "2222222222222222222222222222222222222222222222222222222222222222"
	senderMEP = "mep_" + "3333333333333333333333333333333333333333333333333333333333333333"
	peerMEP   = "mep_" + "6666666666666666666666666666666666666666666666666666666666666666"
	senderDev = "dev_" + "4444444444444444444444444444444444444444444444444444444444444444"
	targetDev = "dev_" + "7777777777777777777777777777777777777777777777777777777777777777"
	convoID   = "conv_" + "1111111111111111111111111111111111111111111111111111111111111111"
	sessionID = "ses_" + "8888888888888888888888888888888888888888888888888888888888888888"
	leaseID   = "lease_" + "9999999999999999999999999999999999999999999999999999999999999999"
)

type stubSuite struct{}

// textBody is a real typed body. A test that queued arbitrary bytes would be
// exercising a path the dispatcher no longer has.
func textBody(t *testing.T, body string) []byte {
	t.Helper()
	encoded, err := payload.Encode(payload.Text{MediaType: "text/plain; charset=utf-8", Body: body})
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	return encoded
}

func (stubSuite) AlgorithmID() string { return algorithm }
func (stubSuite) NewPrekeyMaterial() ([]byte, []byte, error) {
	return []byte("public"), []byte("private"), nil
}
func (stubSuite) Initiate([]byte, []byte, []byte) (e2ee.State, []byte, error) {
	return e2ee.State(make([]byte, 8)), []byte("initial"), nil
}
func (stubSuite) Accept([]byte, []byte, []byte, []byte) (e2ee.State, error) {
	return e2ee.State(make([]byte, 8)), nil
}
func (stubSuite) KeyMaterial(state e2ee.State) (e2ee.State, error) { return state, nil }
func (stubSuite) Seal(state e2ee.State, plaintext, _ []byte) ([]byte, e2ee.State, error) {
	next := make([]byte, 8)
	binary.BigEndian.PutUint64(next, binary.BigEndian.Uint64(state)+1)
	return append([]byte("sealed:"), plaintext...), next, nil
}
func (stubSuite) Open(e2ee.State, []byte, []byte) ([]byte, e2ee.State, error) {
	return nil, nil, e2ee.ErrNotAuthentic
}

type stubSender struct{ sent int }

func (s *stubSender) Send(context.Context, dispatch.Message) error { s.sent++; return nil }

type fixedContactResolver struct {
	result contact.Result
	err    error
	input  string
}

type fixedDirectConversationEnsurer struct {
	result DirectConversationResult
	err    error
	input  string
}

func (e *fixedDirectConversationEnsurer) EnsureDirectConversation(
	_ context.Context, input string,
) (DirectConversationResult, error) {
	e.input = input
	return e.result, e.err
}

func (r *fixedContactResolver) Resolve(_ context.Context, input string) (contact.Result, error) {
	r.input = input
	return r.result, r.err
}

type stubBindings struct{}

func (stubBindings) BindingFor(delivery eventlog.Delivery) (e2ee.Binding, error) {
	return e2ee.Binding{
		Network:             testNetwork(),
		AlgorithmID:         algorithm,
		ConversationID:      delivery.ConversationID,
		SenderAgentID:       senderID,
		SenderEndpointID:    senderMEP,
		SenderDeviceID:      senderDev,
		RecipientAgentID:    "agent_" + strings.Repeat("5", 64),
		RecipientEndpointID: delivery.RecipientEndpointID,
		RecipientDeviceID:   "dev_" + strings.Repeat("7", 64),
	}, nil
}

func testNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{
		NetworkId:       "tos-local",
		GenesisRootHash: strings.Repeat("a", 64),
		GenesisFileHash: strings.Repeat("b", 64),
	}
}

type harness struct {
	server     *Server
	journal    *eventlog.Journal
	sender     *stubSender
	dispatcher *dispatch.Dispatcher
	clock      time.Time
	// root is the journal's directory, for tests that damage a record.
	root string
}

func newHarness(t *testing.T) *harness { return newHarnessWithPolicy(t, firewall.Default()) }

func newHarnessWithPolicy(t *testing.T, policy firewall.Policy) *harness {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	journal, err := eventlog.Open(root)
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	t.Cleanup(func() { _ = journal.Close() })

	instance := &harness{journal: journal, sender: &stubSender{}, clock: time.Unix(int64(baseUnix), 0), root: root}
	dispatcher, err := dispatch.New(dispatch.Config{
		Journal: journal, Suite: stubSuite{}, Sender: instance.sender,
		Bindings: stubBindings{}, Now: func() time.Time { return instance.clock },
		Identity: dispatch.Identity{AgentID: senderID, EndpointID: senderMEP, DeviceID: senderDev},
		Network:  testNetwork(),
	})
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	server, err := NewServer(Config{
		Journal: journal, Dispatcher: dispatcher, Policy: policy,
		OwnerKey: testOwnerPublic(), LocalEndpointID: peerMEP,
		Now: func() time.Time { return instance.clock }, DeviceIDs: []string{senderDev, targetDev},
	})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	instance.server = server
	instance.dispatcher = dispatcher
	if err := journal.PutSessionState(sessionID, algorithm, e2ee.State(make([]byte, 8)), instance.clock); err != nil {
		t.Fatalf("session: %v", err)
	}
	return instance
}

func (h *harness) event(t *testing.T, body string) envelope.Event {
	t.Helper()
	event, err := envelope.NewEvent(envelope.Event{
		Network: testNetwork(), ConversationID: convoID,
		SenderAgentID: senderID, SenderEndpointID: senderMEP, SenderDeviceID: senderDev,
		CreatedAtUnix: baseUnix + 1, Kind: "text", Content: textBody(t, body),
	})
	if err != nil {
		t.Fatalf("event: %v", err)
	}
	return event
}

func TestOwnerCreatesScopedOneTimeAdmissionInvite(t *testing.T) {
	h := newHarness(t)
	expires := baseUnix + 600
	created := h.owner(t, Request{
		Op: OpCreateAdmissionInvite, InvitedAgentID: senderID, InviteExpiresAtUnix: expires,
	})
	if !created.OK || created.AdmissionToken == "" {
		t.Fatalf("create invite: %+v", created)
	}
	eventID := "evt_" + strings.Repeat("a", 64)
	if fresh, err := h.journal.ClaimAdmissionInvite(
		created.AdmissionToken, peerMEP, senderID, eventID, h.clock.Add(time.Minute),
	); err != nil || !fresh {
		t.Fatalf("claim invite: fresh=%v err=%v", fresh, err)
	}
	if _, err := h.journal.ClaimAdmissionInvite(
		created.AdmissionToken, peerMEP, senderID, "evt_"+strings.Repeat("b", 64), h.clock.Add(2*time.Minute),
	); err == nil {
		t.Fatal("owner-created invite authorized two events")
	}
}

func TestRuntimeResolvesRecipientToCanonicalAgentID(t *testing.T) {
	h := newHarness(t)
	resolver := &fixedContactResolver{result: contact.Result{AgentID: senderID, CanonicalName: "alice.tos"}}
	h.server.config.ContactResolver = resolver
	response := h.call(t, Request{Op: OpResolveContact, Recipient: "alice.tos"})
	if !response.OK || response.AgentID != senderID || response.CanonicalName != "alice.tos" || resolver.input != "alice.tos" {
		t.Fatalf("resolve contact: response=%+v input=%q", response, resolver.input)
	}
	if owner := h.owner(t, Request{Op: OpResolveContact, Recipient: "alice.tos"}); owner.OK {
		t.Fatal("owner socket unexpectedly exposed runtime contact resolution")
	}
}

func TestRuntimeEnsuresAgentBoundDirectConversationWithoutRouteAuthority(t *testing.T) {
	h := newHarness(t)
	ensurer := &fixedDirectConversationEnsurer{result: DirectConversationResult{
		AgentID: senderID, CanonicalName: "alice.tos", ConversationID: convoID,
		Readiness: "transport-pending",
	}}
	h.server.config.DirectConversationEnsurer = ensurer
	response := h.call(t, Request{Op: OpEnsureDirectConversation, Recipient: "alice.tos"})
	if !response.OK || response.AgentID != senderID || response.CanonicalName != "alice.tos" ||
		response.ConversationID != convoID || response.Readiness != "transport-pending" ||
		ensurer.input != "alice.tos" {
		t.Fatalf("ensure direct conversation: response=%+v input=%q", response, ensurer.input)
	}
	if owner := h.owner(t, Request{Op: OpEnsureDirectConversation, Recipient: "alice.tos"}); owner.OK {
		t.Fatal("owner socket unexpectedly exposed runtime conversation ensure")
	}
	for name, request := range map[string]Request{
		"session":  {Op: OpEnsureDirectConversation, Recipient: "alice.tos", SessionID: sessionID},
		"endpoint": {Op: OpEnsureDirectConversation, Recipient: "alice.tos", RecipientEndpointID: peerMEP},
		"body":     {Op: OpEnsureDirectConversation, Recipient: "alice.tos", Body: "route me"},
	} {
		if _, err := EncodeRequest(request); err == nil {
			t.Fatalf("direct conversation ensure accepted model-selected %s authority", name)
		}
	}
}

type fixedDirectMessageSender struct {
	result                              DirectMessageResult
	input, mediaType, body, idempotency string
	expires                             uint64
}

func (s *fixedDirectMessageSender) SendDirectMessage(_ context.Context, input, mediaType, body,
	idempotency string, expires uint64) (DirectMessageResult, error) {
	s.input, s.mediaType, s.body, s.idempotency, s.expires = input, mediaType, body, idempotency, expires
	return s.result, nil
}

func (s *fixedDirectMessageSender) SendDirectApplication(_ context.Context, input, kind string,
	body []byte, idempotency string, expires uint64) (DirectMessageResult, error) {
	s.input, s.mediaType, s.body, s.idempotency, s.expires = input, kind, string(body), idempotency, expires
	return s.result, nil
}

func (s *fixedDirectMessageSender) ReplyDirectMessage(_ context.Context, eventID, mediaType, body,
	idempotency string, expires uint64) (DirectMessageResult, error) {
	s.input, s.mediaType, s.body, s.idempotency, s.expires = eventID, mediaType, body, idempotency, expires
	return s.result, nil
}

func TestRuntimeSendsDirectIntentWithoutLowLevelAuthority(t *testing.T) {
	h := newHarness(t)
	eventID := "evt_" + strings.Repeat("d", 64)
	sender := &fixedDirectMessageSender{result: DirectMessageResult{AgentID: senderID,
		CanonicalName: "alice.tos", ConversationID: convoID, EventID: eventID, Readiness: "queued"}}
	h.server.config.DirectMessageSender = sender
	request := Request{Op: OpSendDirect, Recipient: "alice.tos", MediaType: "text/plain; charset=utf-8",
		Body: "hello", IdempotencyKey: "idem_" + strings.Repeat("e", 64), ExpiresAtUnix: baseUnix + 600}
	response := h.call(t, request)
	if !response.OK || response.AgentID != senderID || response.EventID != eventID ||
		response.ConversationID != convoID || response.Readiness != "queued" || sender.input != "alice.tos" {
		t.Fatalf("send direct: response=%+v sender=%+v", response, sender)
	}
	for name, mutate := range map[string]func(*Request){
		"session":                  func(r *Request) { r.SessionID = sessionID },
		"endpoint":                 func(r *Request) { r.RecipientEndpointID = peerMEP },
		"conversation":             func(r *Request) { r.ConversationID = convoID },
		"recipient Agent override": func(r *Request) { r.RecipientAgentID = senderID },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			mutate(&candidate)
			if _, err := EncodeRequest(candidate); err == nil {
				t.Fatal("model-selected routing authority was accepted")
			}
		})
	}
}

func TestRuntimeSendsOnlyBoundedGiftApplicationWithoutRouteAuthority(t *testing.T) {
	h := newHarness(t)
	eventID := "evt_" + strings.Repeat("d", 64)
	sender := &fixedDirectMessageSender{result: DirectMessageResult{AgentID: senderID,
		ConversationID: convoID, EventID: eventID, Readiness: "queued"}}
	h.server.config.DirectMessageSender = sender
	request := Request{Op: OpSendDirectApplication, Recipient: senderID,
		ApplicationKind: "agent.gift.address-request", ApplicationBody: []byte{0xa1, 0x01, 0x02},
		IdempotencyKey: "idem_" + strings.Repeat("e", 64), ExpiresAtUnix: baseUnix + 600}
	response := h.call(t, request)
	if !response.OK || response.EventID != eventID || sender.mediaType != request.ApplicationKind || sender.body != string(request.ApplicationBody) {
		t.Fatalf("send direct Gift: response=%+v sender=%+v", response, sender)
	}
	for name, mutate := range map[string]func(*Request){
		"room":         func(r *Request) { r.RoomID = "room_" + strings.Repeat("1", 64) },
		"session":      func(r *Request) { r.SessionID = sessionID },
		"text":         func(r *Request) { r.Body = "address from model" },
		"unknown kind": func(r *Request) { r.ApplicationKind = "agent.gift.magic" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			mutate(&candidate)
			if _, err := EncodeRequest(candidate); err == nil {
				t.Fatal("invalid Gift application authority was accepted")
			}
		})
	}
}

func TestRuntimeSendsBoundedAgentPacketApplication(t *testing.T) {
	h := newHarness(t)
	eventID := "evt_" + strings.Repeat("d", 64)
	sender := &fixedDirectMessageSender{result: DirectMessageResult{AgentID: senderID,
		ConversationID: convoID, EventID: eventID, Readiness: "queued"}}
	h.server.config.DirectMessageSender = sender
	body := bytes.Repeat([]byte{'p'}, payload.MaxAgreementPromotionBytes)
	request := Request{Op: OpSendDirectApplication, Recipient: senderID, ApplicationKind: "agent.packet",
		ApplicationBody: body, IdempotencyKey: "idem_" + strings.Repeat("e", 64), ExpiresAtUnix: baseUnix + 600}
	response := h.call(t, request)
	if !response.OK || response.EventID != eventID || sender.mediaType != "agent.packet" || sender.body != string(body) {
		t.Fatalf("send direct Agent Packet: response=%+v", response)
	}
	for name, mutate := range map[string]func(*Request){
		"oversized": func(r *Request) { r.ApplicationBody = append(append([]byte(nil), body...), 'p') },
		"empty":     func(r *Request) { r.ApplicationBody = nil },
		"room":      func(r *Request) { r.RoomID = "room_" + strings.Repeat("1", 64) },
		"text":      func(r *Request) { r.Body = "packet from model" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			mutate(&candidate)
			if _, err := EncodeRequest(candidate); err == nil {
				t.Fatal("invalid Agent Packet application was accepted")
			}
		})
	}
}

func TestRuntimeRepliesFromAuthenticatedEventWithoutLowLevelAuthority(t *testing.T) {
	h := newHarness(t)
	sourceEvent := "evt_" + strings.Repeat("a", 64)
	replyEvent := "evt_" + strings.Repeat("d", 64)
	sender := &fixedDirectMessageSender{result: DirectMessageResult{AgentID: senderID,
		ConversationID: convoID, EventID: replyEvent, Readiness: "queued"}}
	h.server.config.DirectMessageSender = sender
	request := Request{Op: OpReplyDirect, ReplyToEventID: sourceEvent,
		MediaType: "text/plain; charset=utf-8", Body: "reply",
		IdempotencyKey: "idem_" + strings.Repeat("e", 64), ExpiresAtUnix: baseUnix + 600}
	response := h.call(t, request)
	if !response.OK || response.EventID != replyEvent || sender.input != sourceEvent {
		t.Fatalf("reply direct: response=%+v sender=%+v", response, sender)
	}
	for name, mutate := range map[string]func(*Request){
		"recipient":    func(r *Request) { r.Recipient = senderID },
		"session":      func(r *Request) { r.SessionID = sessionID },
		"endpoint":     func(r *Request) { r.RecipientEndpointID = peerMEP },
		"conversation": func(r *Request) { r.ConversationID = convoID },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			mutate(&candidate)
			if _, err := EncodeRequest(candidate); err == nil {
				t.Fatal("reply accepted caller-selected authority")
			}
		})
	}
}

func TestRequestDecoderKeepsRollingUpgradeCompatibility(t *testing.T) {
	for _, schema := range []string{RequestSchemaV6, RequestSchemaV7, RequestSchemaV8, RequestSchemaV9, RequestSchemaV10, RequestSchemaV11, RequestSchema} {
		raw, err := json.Marshal(Request{Schema: schema, Op: OpPending, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeRequest(raw); err != nil {
			t.Fatalf("decode %s: %v", schema, err)
		}
	}
	raw, _ := json.Marshal(Request{Schema: "tos.messaging.local-request.v5", Op: OpPending})
	if _, err := DecodeRequest(raw); err == nil {
		t.Fatal("unsupported request schema was accepted")
	}
}

func TestAgentGiftInboxOperationsRequireRequestSchemaV12(t *testing.T) {
	requests := []Request{
		{Schema: RequestSchemaV11, Op: OpPendingAgentGifts, Limit: 1},
		{Schema: RequestSchemaV11, Op: OpClaimAgentGift, EventID: "evt_" + strings.Repeat("1", 64),
			LeaseID: "lease_" + strings.Repeat("2", 64), LeaseSeconds: 60},
	}
	for _, request := range requests {
		raw, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeRequest(raw); err == nil {
			t.Fatalf("pre-v12 schema accepted %s", request.Op)
		}
		request.Schema = RequestSchema
		raw, _ = json.Marshal(request)
		if _, err := DecodeRequest(raw); err != nil {
			t.Fatalf("v12 rejected %s: %v", request.Op, err)
		}
	}
}

func TestContactResolutionFailsClosed(t *testing.T) {
	h := newHarness(t)
	h.server.config.ContactResolver = &fixedContactResolver{err: errors.New("expired finalized proof")}
	if response := h.call(t, Request{Op: OpResolveContact, Recipient: "alice.tos"}); response.OK {
		t.Fatalf("unsafe contact resolved: %+v", response)
	}
	for name, request := range map[string]Request{
		"session": {Op: OpResolveContact, Recipient: "alice.tos", SessionID: sessionID},
		"endpoint": {
			Op: OpResolveContact, Recipient: "alice.tos", RecipientEndpointID: peerMEP,
		},
		"expiry": {Op: OpResolveContact, Recipient: "alice.tos", ExpiresAtUnix: baseUnix + 1},
		"action": {
			Op: OpResolveContact, Recipient: "alice.tos", Action: &ProposedAction{Effect: "message"},
		},
	} {
		if _, err := EncodeRequest(request); err == nil {
			t.Fatalf("contact resolution accepted model-selected %s authority", name)
		}
	}
}

func (h *harness) call(t *testing.T, request Request) Response {
	t.Helper()
	return h.callAs(t, PrincipalRuntime, request)
}

// owner signs every decision, because the daemon no longer takes the socket's
// word for who is calling.
func (h *harness) owner(t *testing.T, request Request) Response {
	t.Helper()
	if !Deciding(request.Op) {
		return h.callAs(t, PrincipalOwner, request)
	}
	issued := h.callAs(t, PrincipalOwner, Request{Op: OpChallenge})
	if !issued.OK || issued.Challenge == "" {
		t.Fatalf("challenge: %+v", issued)
	}
	signature, err := SignDecision(request, issued.Challenge, testOwnerKey())
	if err != nil {
		t.Fatalf("sign decision: %v", err)
	}
	request.Challenge = issued.Challenge
	request.OwnerSignature = signature
	return h.callAs(t, PrincipalOwner, request)
}

// accept records one inbound event waiting for the owner.
func (h *harness) accept(t *testing.T, body string) envelope.Event {
	t.Helper()
	event := h.event(t, body)
	stored, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, _, err := h.journal.Accept(eventlog.Entry{
		EventID: event.EventID, SenderEndpointID: event.SenderEndpointID,
		ConversationID: event.ConversationID, Payload: stored,
		Admission: eventlog.AdmissionPending, ReceivedAtUnix: uint64(h.clock.Unix()),
	}); err != nil {
		t.Fatalf("accept: %v", err)
	}
	return event
}

// runtimeAttempt sends a request from the runtime socket, signed the way an
// owner tool would sign it. A runtime that had somehow obtained a signature
// still must not be able to use it here.
func (h *harness) runtimeAttempt(t *testing.T, request Request) Response {
	t.Helper()
	if Deciding(request.Op) {
		request.Challenge = strings.Repeat("a", 64)
		signature, err := SignDecision(request, request.Challenge, testOwnerKey())
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		request.OwnerSignature = signature
	}
	return h.callAs(t, PrincipalRuntime, request)
}

// The owner's key is the boundary, so the tests hold one rather than relying
// on which socket a call arrived on.
func testOwnerKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6f}, ed25519.SeedSize))
}

func testOwnerPublic() ed25519.PublicKey {
	public, ok := testOwnerKey().Public().(ed25519.PublicKey)
	if !ok {
		panic("unexpected key type")
	}
	return public
}

func (h *harness) callAs(t *testing.T, principal Principal, request Request) Response {
	t.Helper()
	framed, err := EncodeRequest(request)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	body, err := ReadFrame(bytes.NewReader(framed))
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	response := h.server.Handle(context.Background(), principal, body)
	encoded, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	responseBody, err := ReadFrame(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("read response frame: %v", err)
	}
	decoded, err := DecodeResponse(responseBody)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return decoded
}

func (h *harness) receive(t *testing.T, event envelope.Event) {
	t.Helper()
	payload, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, _, err := h.journal.Accept(eventlog.Entry{
		EventID: event.EventID, SenderEndpointID: event.SenderEndpointID,
		ConversationID: event.ConversationID, Payload: payload,
		Admission:      eventlog.AdmissionAdmitted,
		ReceivedAtUnix: uint64(h.clock.Unix()),
	}); err != nil {
		t.Fatalf("accept: %v", err)
	}
}

// The runtime's half of the loop: see what is waiting, take one, finish it.
func TestRuntimeDrainsTheInbox(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "hello")
	h.receive(t, event)

	listing := h.call(t, Request{Op: OpPending})
	if !listing.OK || len(listing.Events) != 1 {
		t.Fatalf("unexpected listing: %+v", listing)
	}
	if listing.Events[0].EventID != event.EventID {
		t.Fatalf("unexpected event: %+v", listing.Events[0])
	}
	// The runtime receives the event itself, not a reference it has to resolve.
	decoded, err := envelope.DecodeEventJSON(listing.Events[0].Event)
	if err != nil {
		t.Fatalf("decode delivered event: %v", err)
	}
	// The runtime gets the typed body, and it is the same body that was sent.
	body, err := payload.Decode(decoded.Kind, decoded.Content)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if text, ok := body.(payload.Text); !ok || text.Body != "hello" {
		t.Fatalf("unexpected content: %+v", body)
	}

	claimed := h.call(t, Request{Op: OpClaim, EventID: event.EventID, LeaseID: leaseID, LeaseSeconds: 60})
	if !claimed.OK || claimed.Event == nil {
		t.Fatalf("unexpected claim: %+v", claimed)
	}
	// While the lease is live the event is not offered again.
	if listing := h.call(t, Request{Op: OpPending}); len(listing.Events) != 0 {
		t.Fatalf("a leased event was offered again: %+v", listing)
	}
	if done := h.call(t, Request{Op: OpComplete, EventID: event.EventID, LeaseID: leaseID}); !done.OK {
		t.Fatalf("complete: %+v", done)
	}
	if listing := h.call(t, Request{Op: OpPending}); len(listing.Events) != 0 {
		t.Fatalf("an applied event was offered again: %+v", listing)
	}
}

func TestRuntimeCannotListOrClaimDaemonOwnedTypedAdapters(t *testing.T) {
	h := newHarness(t)
	packetBody, err := payload.Encode(payload.AgentPacketMessage{Foreign: payload.Foreign{
		Protocol: "agentpacket", Version: "1", Body: []byte("{}"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	packetEvent, err := envelope.NewEvent(envelope.Event{
		Network: testNetwork(), ConversationID: convoID,
		SenderAgentID: senderID, SenderEndpointID: senderMEP, SenderDeviceID: senderDev,
		CreatedAtUnix: baseUnix, Kind: "agent.packet", Content: packetBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.receive(t, packetEvent)
	historical := h.event(t, "historical")
	historicalRaw, err := envelope.EncodeEventJSON(historical)
	if err != nil {
		t.Fatal(err)
	}
	historyBody, err := payload.Encode(payload.DeviceHistorySegment{
		SourceDeviceID: senderDev, TargetDeviceID: "dev_" + strings.Repeat("9", 64),
		ConversationID: convoID, Sequence: 1, Events: [][]byte{historicalRaw},
	})
	if err != nil {
		t.Fatal(err)
	}
	historyEvent, err := envelope.NewEvent(envelope.Event{
		Network: testNetwork(), ConversationID: convoID,
		SenderAgentID: senderID, SenderEndpointID: senderMEP, SenderDeviceID: senderDev,
		CreatedAtUnix: baseUnix + 1, Kind: "device.history.segment", Content: historyBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.receive(t, historyEvent)
	reserved := []envelope.Event{packetEvent, historyEvent}
	for index, foreign := range []struct {
		kind string
		body payload.Payload
	}{
		{"a2a.message", payload.A2AMessage{Foreign: payload.Foreign{Protocol: "a2a", Version: "1", Body: []byte("a2a")}}},
		{"mcp.call", payload.MCPCall{Foreign: payload.Foreign{Protocol: "mcp", Version: "1", Body: []byte("call")}}},
		{"mcp.result", payload.MCPResult{Foreign: payload.Foreign{Protocol: "mcp", Version: "1", Body: []byte("result")}}},
	} {
		content, encodeErr := payload.Encode(foreign.body)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		event, eventErr := envelope.NewEvent(envelope.Event{
			Network: testNetwork(), ConversationID: convoID,
			SenderAgentID: senderID, SenderEndpointID: senderMEP, SenderDeviceID: senderDev,
			CreatedAtUnix: baseUnix + uint64(index) + 2, Kind: foreign.kind, Content: content,
		})
		if eventErr != nil {
			t.Fatal(eventErr)
		}
		h.receive(t, event)
		reserved = append(reserved, event)
	}
	textEvent := h.event(t, "still visible")
	h.receive(t, textEvent)

	listing := h.call(t, Request{Op: OpPending, Limit: 1})
	if !listing.OK || len(listing.Events) != 1 || listing.Events[0].EventID != textEvent.EventID {
		t.Fatalf("typed packet hid or entered the runtime listing: %+v", listing)
	}
	for index, event := range reserved {
		claimed := h.call(t, Request{Op: OpClaim, EventID: event.EventID,
			LeaseID: "lease_" + strings.Repeat(string(rune('5'+index)), 64), LeaseSeconds: 60})
		if claimed.OK || claimed.Code != fault.CodeClassNotDelegated {
			t.Fatalf("runtime claimed daemon-owned %s: %+v", event.Kind, claimed)
		}
	}
}

func TestAgentGiftInboxCannotBeStarvedAndClaimsOnlyGiftKinds(t *testing.T) {
	h := newHarness(t)
	for index := 0; index < MaxEventsPerResponse+1; index++ {
		h.receive(t, h.event(t, "ordinary-"+strconv.Itoa(index)))
	}
	content, err := payload.Encode(payload.GiftAddressRequest{CanonicalRequest: []byte{0xa1, 0x01}})
	if err != nil {
		t.Fatal(err)
	}
	gift, err := envelope.NewEvent(envelope.Event{
		Network: testNetwork(), ConversationID: convoID,
		SenderAgentID: senderID, SenderEndpointID: senderMEP, SenderDeviceID: senderDev,
		CreatedAtUnix: baseUnix + 1, Kind: "agent.gift.address-request", Content: content,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.receive(t, gift)

	listing := h.call(t, Request{Op: OpPendingAgentGifts, Limit: 1})
	if !listing.OK || len(listing.Events) != 1 || listing.Events[0].EventID != gift.EventID {
		t.Fatalf("ordinary inbox traffic starved Agent Gift listing: %+v", listing)
	}
	if generic := h.call(t, Request{Op: OpClaim, EventID: gift.EventID,
		LeaseID: "lease_" + strings.Repeat("7", 64), LeaseSeconds: 60}); generic.OK || generic.Code != fault.CodeClassNotDelegated {
		t.Fatalf("generic runtime claimed reserved Agent Gift: %+v", generic)
	}
	ordinary := h.event(t, "not-a-gift")
	h.receive(t, ordinary)
	if typed := h.call(t, Request{Op: OpClaimAgentGift, EventID: ordinary.EventID,
		LeaseID: "lease_" + strings.Repeat("8", 64), LeaseSeconds: 60}); typed.OK || typed.Code != fault.CodeClassNotDelegated {
		t.Fatalf("Agent Gift adapter claimed ordinary event: %+v", typed)
	}
	claimed := h.call(t, Request{Op: OpClaimAgentGift, EventID: gift.EventID,
		LeaseID: leaseID, LeaseSeconds: 60})
	if !claimed.OK || claimed.Event == nil || claimed.Event.EventID != gift.EventID {
		t.Fatalf("Agent Gift claim failed: %+v", claimed)
	}
}

func TestPrivateHandoffInboxCannotBeStarvedOrEnterGenericChat(t *testing.T) {
	h := newHarness(t)
	for index := 0; index < MaxEventsPerResponse+1; index++ {
		h.receive(t, h.event(t, "ordinary-handoff-"+strconv.Itoa(index)))
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	content, err := payload.Encode(payload.PrivateHandoffStatus{HandoffID: "handoff:test", ActionID: digest,
		State: "accepted", EvidenceDigest: "sha256:" + strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	event, err := envelope.NewEvent(envelope.Event{Network: testNetwork(), ConversationID: convoID,
		SenderAgentID: senderID, SenderEndpointID: senderMEP, SenderDeviceID: senderDev, CreatedAtUnix: baseUnix + 2,
		Kind: "private.handoff.status", IdempotencyKey: strings.TrimPrefix(digest, "sha256:"), Content: content})
	if err != nil {
		t.Fatal(err)
	}
	h.receive(t, event)
	listing := h.call(t, Request{Op: OpPendingPrivateHandoffs, Limit: 1})
	if !listing.OK || len(listing.Events) != 1 || listing.Events[0].EventID != event.EventID {
		t.Fatalf("ordinary traffic starved private handoff listing: %+v", listing)
	}
	if generic := h.call(t, Request{Op: OpClaim, EventID: event.EventID,
		LeaseID: "lease_" + strings.Repeat("7", 64), LeaseSeconds: 60}); generic.OK || generic.Code != fault.CodeClassNotDelegated {
		t.Fatalf("generic runtime claimed private handoff control: %+v", generic)
	}
	claimed := h.call(t, Request{Op: OpClaimPrivateHandoff, EventID: event.EventID, LeaseID: leaseID, LeaseSeconds: 60})
	if !claimed.OK || claimed.Event == nil || claimed.Event.EventID != event.EventID {
		t.Fatalf("private handoff claim failed: %+v", claimed)
	}
}

func TestCommerceProfileInboxCannotBeStarvedOrEnterGenericChat(t *testing.T) {
	h := newHarness(t)
	for index := 0; index < MaxEventsPerResponse+1; index++ {
		h.receive(t, h.event(t, "ordinary-profile-"+strconv.Itoa(index)))
	}
	object := []byte{0xa1, 0x01, 0x02}
	eventBody := commerce.CommerceProfileEventV1{SchemaVersion: 1, ProfileURI: "tos.test.profile.v1", ProfileVersion: 1,
		ObjectKind: "test.object", ObjectContentType: "application/vnd.tos.test+cbor",
		ObjectDigest: "sha256:" + strings.Repeat("c", 64), ObjectSizeBytes: uint64(len(object)), CarriageKind: "inline",
		CanonicalObjectBytes: object, CreatedAtUnix: baseUnix, ExpiresAtUnix: baseUnix + 600}
	canonical, err := commerce.CanonicalCommerceProfileEventV1(eventBody, time.Unix(int64(baseUnix), 0))
	if err != nil {
		t.Fatal(err)
	}
	content, err := payload.Encode(payload.CommerceProfileEvent{ObjectDigest: eventBody.ObjectDigest, CanonicalEvent: canonical})
	if err != nil {
		t.Fatal(err)
	}
	event, err := envelope.NewEvent(envelope.Event{Network: testNetwork(), ConversationID: convoID,
		SenderAgentID: senderID, SenderEndpointID: senderMEP, SenderDeviceID: senderDev, CreatedAtUnix: baseUnix,
		Kind: "commerce.profile-event", IdempotencyKey: strings.Repeat("c", 64), Content: content})
	if err != nil {
		t.Fatal(err)
	}
	h.receive(t, event)
	listing := h.call(t, Request{Op: OpPendingCommerceProfileEvents, Limit: 1})
	if !listing.OK || len(listing.Events) != 1 || listing.Events[0].EventID != event.EventID {
		t.Fatalf("ordinary traffic starved commerce profile listing: %+v", listing)
	}
	if generic := h.call(t, Request{Op: OpClaim, EventID: event.EventID,
		LeaseID: "lease_" + strings.Repeat("7", 64), LeaseSeconds: 60}); generic.OK || generic.Code != fault.CodeClassNotDelegated {
		t.Fatalf("generic runtime claimed commerce profile event: %+v", generic)
	}
	claimed := h.call(t, Request{Op: OpClaimCommerceProfileEvent, EventID: event.EventID, LeaseID: leaseID, LeaseSeconds: 60})
	if !claimed.OK || claimed.Event == nil || claimed.Event.EventID != event.EventID {
		t.Fatalf("commerce profile claim failed: %+v", claimed)
	}
}

func TestOperationOutcomeInboxCannotEnterOrdinaryChatOrModelInput(t *testing.T) {
	h := newHarness(t)
	assertion, err := protocolcodec.Marshal(commerce.ActionResolutionReferencePayloadV1{StableActionID: "sha256:" + strings.Repeat("1", 64),
		ExactRequestDigest: "sha256:" + strings.Repeat("2", 64), AuthorizedActionDigest: "sha256:" + strings.Repeat("3", 64),
		ActionResolutionDigest: "sha256:" + strings.Repeat("4", 64), ResolutionState: commerce.ActionRejected, ResolutionStateRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	eventBody, err := commerce.BuildOperationOutcomeEventV1(commerce.OutcomeObservation,
		commerce.OutcomeSubjectRefV1{SubjectProfileURI: "tos.subject.semantic-action.v1", SubjectID: "sha256:" + strings.Repeat("1", 64)}, nil,
		commerce.OutcomeProfileActionResolutionReference, assertion, commerce.EmptyOutcomeEvidenceManifestV1("unverified_reference"),
		commerce.EmptyOutcomeExtensionSetV1())
	if err != nil {
		t.Fatal(err)
	}
	contentID, eventPayload, err := commerce.OperationOutcomeEventContentIDV1(eventBody)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize))
	body := commerce.AgentOperationBodyV1{SchemaVersion: 1, NetworkID: "tos:test", OpcodeNamespace: "OPERATION", OpcodeName: "OUTCOME", OpcodeVersion: 1,
		ActorAgentID: senderID, AuthorizationRef: commerce.ProfileRefV1{ProfileURI: "tos.identity.agent-key.v1", ProfileVersion: 1,
			ProfileDigest: "sha256:" + strings.Repeat("5", 64)}, AudienceDescriptor: "named-recipients", ObjectID: contentID,
		OrderingDomain: "outcome:test", Sequence: 1, Epoch: 1, CreatedAtUnix: baseUnix, PayloadProfile: commerce.OperationOutcomeProfileRefV1(),
		PayloadDigest: contentID, PayloadSize: uint64(len(eventPayload))}
	body.OperationID, err = commerce.DeriveAgentOperationIDV1(body)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := commerce.SignAgentOperationV1(body, senderID, key, []byte("historical-proof"))
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, envelopeDigest, err := commerce.MarshalAgentOperationEnvelopeV1(signed)
	if err != nil {
		t.Fatal(err)
	}
	recipients := []string{"agent:recipient"}
	recipientDigest, _ := protocolcodec.Digest("tos.messenger-recipient-set.v1", recipients)
	privateRequest := commerce.OperationPrivateRequestV1{SchemaVersion: 1, RecipientSetDigest: recipientDigest, RecipientAgentIDs: recipients,
		MembershipEpoch: 1, AudiencePolicyDigest: "sha256:" + strings.Repeat("6", 64), OperationID: body.OperationID,
		OperationEnvelopeDigest: envelopeDigest, ConversationScopeDigest: "sha256:" + strings.Repeat("7", 64),
		TransportProfile: commerce.ProfileRefV1{ProfileURI: "tos.messenger.operation-outcome.v1", ProfileVersion: 1,
			ProfileDigest: "sha256:" + strings.Repeat("8", 64)}, OperationEnvelope: envelopeBytes, EventPayload: eventPayload,
		Artifacts: commerce.OperationOutcomeArtifactBundleV1{AssertionPayload: assertion,
			EvidenceManifest: commerce.EmptyOutcomeEvidenceManifestV1("unverified_reference"), ExtensionSet: commerce.EmptyOutcomeExtensionSetV1(),
			AuthorityProofs: []commerce.OutcomeAuthorityProofMaterialV1{}}}
	canonical, err := protocolcodec.Marshal(privateRequest)
	if err != nil {
		t.Fatal(err)
	}
	content, err := payload.Encode(payload.OperationOutcome{OperationID: body.OperationID,
		OperationEnvelopeDigest: envelopeDigest, CanonicalRequest: canonical})
	if err != nil {
		t.Fatal(err)
	}
	event, err := envelope.NewEvent(envelope.Event{Network: testNetwork(), ConversationID: convoID, SenderAgentID: senderID,
		SenderEndpointID: senderMEP, SenderDeviceID: senderDev, CreatedAtUnix: baseUnix, Kind: "operation.outcome",
		IdempotencyKey: strings.Repeat("8", 64), Content: content})
	if err != nil {
		t.Fatal(err)
	}
	h.receive(t, event)
	if ordinary := h.call(t, Request{Op: OpPending}); !ordinary.OK || len(ordinary.Events) != 0 {
		t.Fatalf("operation outcome entered ordinary chat/model input: %+v", ordinary)
	}
	listing := h.call(t, Request{Op: OpPendingCommerceProfileEvents, Limit: 1})
	if !listing.OK || len(listing.Events) != 1 || listing.Events[0].EventID != event.EventID {
		t.Fatalf("operation outcome was not routed to its typed application queue: %+v", listing)
	}
	if generic := h.call(t, Request{Op: OpClaim, EventID: event.EventID, LeaseID: "lease_" + strings.Repeat("7", 64), LeaseSeconds: 60}); generic.OK || generic.Code != fault.CodeClassNotDelegated {
		t.Fatalf("generic runtime claimed an operation outcome: %+v", generic)
	}
}

func TestRejectedEventIsNotOfferedAgain(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "hello")
	h.receive(t, event)
	if claimed := h.call(t, Request{Op: OpClaim, EventID: event.EventID, LeaseID: leaseID, LeaseSeconds: 60}); !claimed.OK {
		t.Fatalf("claim: %+v", claimed)
	}
	refused := h.call(t, Request{Op: OpReject, EventID: event.EventID, LeaseID: leaseID,
		Code: fault.CodeContentTooLarge})
	if !refused.OK {
		t.Fatalf("reject: %+v", refused)
	}
	if listing := h.call(t, Request{Op: OpPending}); len(listing.Events) != 0 {
		t.Fatalf("a rejected event was offered again: %+v", listing)
	}
}

// A runtime holding no lease cannot finish somebody else's work.
func TestApplicationOutcomesNeedTheLease(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "hello")
	h.receive(t, event)
	if claimed := h.call(t, Request{Op: OpClaim, EventID: event.EventID, LeaseID: leaseID, LeaseSeconds: 60}); !claimed.OK {
		t.Fatalf("claim: %+v", claimed)
	}
	other := "lease_" + strings.Repeat("1", 64)
	if done := h.call(t, Request{Op: OpComplete, EventID: event.EventID, LeaseID: other}); done.OK {
		t.Fatal("a foreign lease completed the work")
	}
	unknown := h.call(t, Request{Op: OpComplete,
		EventID: "evt_" + strings.Repeat("0", 64), LeaseID: leaseID})
	if unknown.OK || unknown.Code != fault.CodeUnknownEventKind {
		t.Fatalf("unexpected outcome for an unknown event: %+v", unknown)
	}
}

func TestRuntimeSubmitsAnEvent(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "outbound")
	encoded, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	response := h.call(t, Request{
		Op: OpQueue, Event: json.RawMessage(encoded), SessionID: sessionID,
		RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 3600,
	})
	if !response.OK || !response.Fresh {
		t.Fatalf("unexpected submission: %+v", response)
	}
	delivery, found, err := h.journal.LookupDelivery(event.EventID)
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	if delivery.SessionID != sessionID {
		t.Fatalf("the submission lost its session: %+v", delivery)
	}

	// The daemon owns what goes on the wire, so a malformed submission is
	// refused here rather than sealed and sent.
	bad := h.call(t, Request{
		Op: OpQueue, Event: json.RawMessage(`{"schema":"tos.messaging.event.v2"}`),
		SessionID: sessionID, RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 3600,
	})
	if bad.OK {
		t.Fatal("a malformed event was queued")
	}
}

func TestRuntimeComposesDaemonOwnedEventWithStableRetry(t *testing.T) {
	h := newHarness(t)
	request := Request{Op: OpCompose, ConversationID: convoID, MediaType: "text/plain; charset=utf-8",
		Body: "daemon owns this envelope", IdempotencyKey: "idem_" + strings.Repeat("a", 64),
		SessionID: sessionID, RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 3600}
	first := h.call(t, request)
	if !first.OK || !first.Fresh || first.EventID == "" {
		t.Fatalf("first compose: %+v", first)
	}
	h.clock = h.clock.Add(30 * time.Second)
	retry := h.call(t, request)
	if !retry.OK || retry.Fresh || retry.EventID != first.EventID {
		t.Fatalf("retry changed the durable event: first=%+v retry=%+v", first, retry)
	}
	delivery, found, err := h.journal.LookupDelivery(first.EventID)
	if err != nil || !found {
		t.Fatalf("lookup composed delivery: found=%v err=%v", found, err)
	}
	raw, err := delivery.Payload()
	if err != nil {
		t.Fatal(err)
	}
	event, err := envelope.DecodeEventJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if event.SenderAgentID != senderID || event.SenderEndpointID != senderMEP ||
		event.SenderDeviceID != senderDev || event.Network.NetworkId != testNetwork().NetworkId {
		t.Fatalf("event escaped daemon authority: %+v", event)
	}

	substitution := request
	substitution.Body = "replace it"
	if response := h.call(t, substitution); response.OK {
		t.Fatal("one idempotency key accepted different content")
	}
	substitution = request
	substitution.RecipientEndpointID = "mep_" + strings.Repeat("9", 64)
	if response := h.call(t, substitution); response.OK {
		t.Fatal("one idempotency key accepted a different recipient")
	}
}

func TestProactiveCompositionReverifiesCanonicalAgentRoute(t *testing.T) {
	h := newHarness(t)
	recipientAgentID := "agent_" + strings.Repeat("5", 64)
	resolver := &fixedContactResolver{result: contact.Result{
		AgentID: recipientAgentID,
		Directory: directory.RefreshResult{Descriptor: directory.Descriptor{
			AgentID: recipientAgentID, EndpointID: peerMEP,
		}},
	}}
	h.server.config.ContactResolver = resolver
	request := Request{
		Op: OpCompose, ConversationID: convoID, MediaType: "text/plain; charset=utf-8", Body: "hello",
		IdempotencyKey: "idem_" + strings.Repeat("c", 64), SessionID: sessionID,
		RecipientEndpointID: peerMEP, RecipientAgentID: recipientAgentID, ExpiresAtUnix: baseUnix + 3600,
	}
	if response := h.call(t, request); !response.OK {
		t.Fatalf("canonical Agent route refused: %+v", response)
	}
	if resolver.input != recipientAgentID {
		t.Fatalf("compose re-resolved %q, want canonical AgentID", resolver.input)
	}
	wrong := request
	wrong.IdempotencyKey = "idem_" + strings.Repeat("d", 64)
	wrong.RecipientEndpointID = "mep_" + strings.Repeat("9", 64)
	if response := h.call(t, wrong); response.OK {
		t.Fatal("canonical Agent assertion accepted another Endpoint")
	}
}

func TestRuntimeComposesOnlyBoundProtocolResults(t *testing.T) {
	h := newHarness(t)
	request := Request{Op: OpComposeProtocolResult, ConversationID: convoID,
		ReplyToEventID: "evt_" + strings.Repeat("9", 64), ProtocolKind: "a2a.message",
		Protocol: "a2a", ProtocolVersion: "1", ProtocolBody: []byte(`{"task":"complete"}`),
		IdempotencyKey: "idem_" + strings.Repeat("b", 64), SessionID: sessionID,
		RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 3600}
	first := h.call(t, request)
	if !first.OK || !first.Fresh || first.EventID == "" {
		t.Fatalf("compose A2A result: %+v", first)
	}
	retry := h.call(t, request)
	if !retry.OK || retry.Fresh || retry.EventID != first.EventID {
		t.Fatalf("protocol result retry changed: first=%+v retry=%+v", first, retry)
	}
	delivery, found, err := h.journal.LookupDelivery(first.EventID)
	if err != nil || !found {
		t.Fatalf("lookup protocol result: found=%v err=%v", found, err)
	}
	raw, _ := delivery.Payload()
	event, err := envelope.DecodeEventJSON(raw)
	if err != nil || event.Kind != "a2a.message" || event.SenderAgentID != senderID || event.ReplyToEventID != request.ReplyToEventID {
		t.Fatalf("protocol result escaped daemon authority: %+v err=%v", event, err)
	}
	decoded, err := payload.Decode(event.Kind, event.Content)
	body, ok := decoded.(payload.A2AMessage)
	if err != nil || !ok || body.Protocol != "a2a" || !bytes.Equal(body.Body, request.ProtocolBody) {
		t.Fatalf("unexpected protocol result body: %+v err=%v", decoded, err)
	}
	for name, mutate := range map[string]func(*Request){
		"call kind":     func(r *Request) { r.ProtocolKind = "mcp.call"; r.Protocol = "mcp" },
		"cross profile": func(r *Request) { r.Protocol = "mcp" },
		"text body":     func(r *Request) { r.Body = "smuggled" },
		"no source":     func(r *Request) { r.ReplyToEventID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			if err := ValidateRequest(changed); err == nil {
				t.Fatalf("invalid protocol result validated: %+v", changed)
			}
		})
	}
}

func TestRuntimeComposesBoundRoomMessage(t *testing.T) {
	h := newHarness(t)
	roomID := "room_" + strings.Repeat("b", 64)
	response := h.call(t, Request{Op: OpCompose, ConversationID: convoID, RoomID: roomID,
		MembershipEpoch: 7, MediaType: "text/plain; charset=utf-8", Body: "room hello",
		IdempotencyKey: "idem_" + strings.Repeat("c", 64), SessionID: sessionID,
		RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 3600})
	if !response.OK {
		t.Fatalf("compose room message: %+v", response)
	}
	delivery, _, err := h.journal.LookupDelivery(response.EventID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := delivery.Payload()
	event, err := envelope.DecodeEventJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := payload.Decode(event.Kind, event.Content)
	if err != nil {
		t.Fatal(err)
	}
	message, ok := decoded.(payload.RoomMessage)
	if !ok || event.RoomID != roomID || message.RoomID != roomID || message.Epoch != 7 {
		t.Fatalf("room binding was lost: event=%+v payload=%+v", event, decoded)
	}
}

// The owner decision exists on this socket and nowhere else.
func TestOwnerDecisionResumesAHeldDelivery(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "outbound")
	encoded, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if response := h.call(t, Request{Op: OpQueue, Event: json.RawMessage(encoded),
		SessionID: sessionID, RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 86_400}); !response.OK {
		t.Fatalf("queue: %+v", response)
	}
	if _, err := h.journal.Failed(event.EventID, sendAttempt(t, h, event.EventID, 0x40), fault.CodeApprovalRequired, h.clock); err != nil {
		t.Fatalf("hold: %v", err)
	}

	approved := h.owner(t, Request{Op: OpApprove, EventID: event.EventID})
	if !approved.OK {
		t.Fatalf("approve: %+v", approved)
	}
	delivery, _, err := h.journal.LookupDelivery(event.EventID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if delivery.State != eventlog.StatePending {
		t.Fatalf("an approved delivery did not return to the queue: %+v", delivery)
	}

	// And the owner can refuse instead.
	second := h.event(t, "second")
	secondEncoded, err := envelope.EncodeEventJSON(second)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if response := h.call(t, Request{Op: OpQueue, Event: json.RawMessage(secondEncoded),
		SessionID: sessionID, RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 86_400}); !response.OK {
		t.Fatalf("queue: %+v", response)
	}
	if _, err := h.journal.Failed(second.EventID, sendAttempt(t, h, second.EventID, 0x41), fault.CodeApprovalRequired, h.clock); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if denied := h.owner(t, Request{Op: OpDeny, EventID: second.EventID}); !denied.OK {
		t.Fatalf("deny: %+v", denied)
	}
	delivery, _, err = h.journal.LookupDelivery(second.EventID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if delivery.State != eventlog.StateAbandoned {
		t.Fatalf("a denied delivery was not abandoned: %+v", delivery)
	}
}

// Every operation names exactly the fields it uses.
func TestRequestsCarryOnlyWhatTheyUse(t *testing.T) {
	cases := map[string]Request{
		"unknown op":          {Op: "inbox.everything"},
		"pending with lease":  {Op: OpPending, LeaseID: leaseID},
		"pending with event":  {Op: OpPending, EventID: "evt_" + strings.Repeat("0", 64)},
		"claim without lease": {Op: OpClaim, EventID: "evt_" + strings.Repeat("0", 64)},
		"claim without time": {Op: OpClaim, EventID: "evt_" + strings.Repeat("0", 64),
			LeaseID: leaseID},
		"reject with unknown code": {Op: OpReject, EventID: "evt_" + strings.Repeat("0", 64),
			LeaseID: leaseID, Code: "invented"},
		"queue without session": {Op: OpQueue, Event: json.RawMessage(`{}`),
			RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix},
		"queue without recipient": {Op: OpQueue, Event: json.RawMessage(`{}`),
			SessionID: sessionID, ExpiresAtUnix: baseUnix},
		"approve with lease": {Op: OpApprove, EventID: "evt_" + strings.Repeat("0", 64),
			LeaseID: leaseID},
		"approve without event": {Op: OpApprove},
	}
	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateRequest(request); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
			if _, err := EncodeRequest(request); err == nil {
				t.Fatalf("expected %q to be unencodable", name)
			}
		})
	}
}

func TestDecodeRejectsMalformedFrames(t *testing.T) {
	framed, err := EncodeRequest(Request{Op: OpPending})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	body, err := ReadFrame(bytes.NewReader(framed))
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	line := string(body)
	for name, raw := range map[string][]byte{
		"unknown field": []byte(line[:len(line)-1] + `,"extra":1}`),
		"trailing json": []byte(line + "{}"),
		"wrong schema":  []byte(strings.Replace(line, RequestSchema, "other", 1)),
		"empty":         []byte(""),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequest(raw); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}

// The socket is owner-private: a private directory, a narrowed socket file,
// and on Linux a check of who is calling.
func TestSocketIsOwnerPrivate(t *testing.T) {
	root := filepath.Join(t.TempDir(), "run")
	path := filepath.Join(root, "messenger.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	directory, err := os.Lstat(root)
	if err != nil {
		t.Fatalf("stat directory: %v", err)
	}
	if directory.Mode().Perm() != 0o700 {
		t.Fatalf("the socket directory is not private: %v", directory.Mode().Perm())
	}
	socket, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if socket.Mode().Perm() != 0o600 {
		t.Fatalf("the socket is not private: %v", socket.Mode().Perm())
	}

	// A second daemon must not take the socket away from a live one.
	if _, err := Listen(path); err == nil {
		t.Fatal("a second listener took over a live socket")
	}

	for name, candidate := range map[string]string{
		"relative":  "run/messenger.sock",
		"empty":     "",
		"uncleaned": "/tmp/../tmp/messenger.sock",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Listen(candidate); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}

// A widened directory is refused rather than served.
func TestSharedDirectoryIsRefused(t *testing.T) {
	root := filepath.Join(t.TempDir(), "shared")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := Listen(filepath.Join(root, "messenger.sock")); err == nil {
		t.Fatal("a world-readable socket directory was accepted")
	}
}

func TestServeOverTheSocket(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "hello")
	h.receive(t, event)

	path := filepath.Join(t.TempDir(), "run", "messenger.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() { _ = h.server.Serve(context.Background(), listener, PrincipalRuntime) }()

	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer connection.Close()

	request, err := EncodeRequest(Request{Op: OpPending})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := connection.Write(request); err != nil {
		t.Fatalf("write: %v", err)
	}
	body, err := ReadFrame(bufio.NewReader(connection))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	response, err := DecodeResponse(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !response.OK || len(response.Events) != 1 {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestServerRequiresEveryDependency(t *testing.T) {
	h := newHarness(t)
	dispatcher, err := dispatch.New(dispatch.Config{
		Journal: h.journal, Suite: stubSuite{}, Sender: h.sender, Bindings: stubBindings{},
		Identity: dispatch.Identity{AgentID: senderID, EndpointID: senderMEP, DeviceID: senderDev},
	})
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	complete := Config{
		Journal: h.journal, Dispatcher: dispatcher, Policy: firewall.Default(),
		OwnerKey: testOwnerPublic(),
	}
	missing := map[string]func(*Config){
		"no journal":     func(c *Config) { c.Journal = nil },
		"no dispatcher":  func(c *Config) { c.Dispatcher = nil },
		"no policy":      func(c *Config) { c.Policy = firewall.Policy{} },
		"no owner key":   func(c *Config) { c.OwnerKey = nil },
		"zero owner key": func(c *Config) { c.OwnerKey = make(ed25519.PublicKey, ed25519.PublicKeySize) },
		"bad timeout":    func(c *Config) { c.Timeout = -1 },
	}
	for name, mutate := range missing {
		config := complete
		mutate(&config)
		if _, err := NewServer(config); err == nil {
			t.Fatalf("expected %q to be refused", name)
		}
	}
}

// The invariant the separation exists for: the party that asks for an approval
// must not be able to grant it.
func TestRuntimeCannotApproveAnything(t *testing.T) {
	h := newHarness(t)
	for _, operation := range []Operation{OpApprove, OpDeny, OpAdmit, OpRefuse, OpAwaitingAdmission} {
		t.Run(string(operation), func(t *testing.T) {
			if Permits(PrincipalRuntime, operation) {
				t.Fatalf("the runtime principal permits %q", operation)
			}
			request := Request{Op: operation, EventID: "evt_" + strings.Repeat("0", 64)}
			if operation == OpAwaitingAdmission {
				request = Request{Op: operation}
			}
			if operation == OpRefuse {
				request.Code = fault.CodeRejected
			}
			if Deciding(operation) {
				// Signed properly, and still refused: the runtime is not the
				// owner however well-formed its request is.
				request.Challenge = strings.Repeat("a", 64)
				signature, err := SignDecision(request, request.Challenge, testOwnerKey())
				if err != nil {
					t.Fatalf("sign: %v", err)
				}
				request.OwnerSignature = signature
			}
			response := h.callAs(t, PrincipalRuntime, request)
			if response.OK {
				t.Fatalf("the runtime performed %q", operation)
			}
		})
	}
	// And the owner does no Agent work.
	for _, operation := range []Operation{OpPending, OpClaim, OpComplete, OpReject, OpQueue} {
		if Permits(PrincipalOwner, operation) {
			t.Fatalf("the owner principal permits %q", operation)
		}
	}
	if Permits("someone-else", OpPending) {
		t.Fatal("an unknown principal was permitted")
	}
}

func TestOwnerHistoryExportIsBoundedAndRetryStable(t *testing.T) {
	h := newHarness(t)
	composed := h.call(t, Request{Op: OpCompose, ConversationID: convoID, SessionID: sessionID,
		RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 3600,
		MediaType: "text/plain; charset=utf-8", Body: "durable history",
		IdempotencyKey: "idem_" + strings.Repeat("1", 64)})
	if !composed.OK {
		t.Fatalf("compose history source: %+v", composed)
	}
	if summary, err := h.dispatcher.Sweep(context.Background(), 0); err != nil || summary.Sent != 1 {
		t.Fatalf("deliver history source: %+v err=%v", summary, err)
	}
	request := Request{Op: OpExportDeviceHistory, TargetDeviceID: targetDev, ConversationID: convoID,
		HistorySequence: 1, Limit: 1, IdempotencyKey: "idem_" + strings.Repeat("2", 64),
		ExpiresAtUnix: baseUnix + 3600}
	first := h.owner(t, request)
	if !first.OK || !first.Fresh || first.EventID == "" || first.HistorySegmentDigest == "" ||
		first.LastEventID != composed.EventID || first.LastEventCreatedAt == 0 {
		t.Fatalf("export first history page: %+v", first)
	}

	// Arrival of more eligible history cannot change a page already bound to
	// this idempotency intent.
	h.clock = h.clock.Add(time.Second)
	secondSource := h.call(t, Request{Op: OpCompose, ConversationID: convoID, SessionID: sessionID,
		RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 3600,
		MediaType: "text/plain; charset=utf-8", Body: "newer history",
		IdempotencyKey: "idem_" + strings.Repeat("3", 64)})
	if !secondSource.OK {
		t.Fatalf("compose newer source: %+v", secondSource)
	}
	if summary, err := h.dispatcher.Sweep(context.Background(), 0); err != nil || summary.Sent != 1 {
		t.Fatalf("deliver newer source: %+v err=%v", summary, err)
	}
	retry := h.owner(t, request)
	if !retry.OK || retry.Fresh || retry.EventID != first.EventID ||
		retry.HistorySegmentDigest != first.HistorySegmentDigest || retry.LastEventID != first.LastEventID {
		t.Fatalf("history retry changed the committed page: first=%+v retry=%+v", first, retry)
	}
}

func TestHistoryExportNeedsOwnerAndSignatureCoversTerms(t *testing.T) {
	h := newHarness(t)
	base := Request{Op: OpExportDeviceHistory, TargetDeviceID: targetDev, ConversationID: convoID,
		HistorySequence: 2, PreviousSegmentDigest: "sha256:" + strings.Repeat("a", 64),
		AfterCreatedAtUnix: baseUnix, AfterEventID: "evt_" + strings.Repeat("b", 64), Limit: 1,
		IdempotencyKey: "idem_" + strings.Repeat("c", 64), ExpiresAtUnix: baseUnix + 3600}
	if Permits(PrincipalRuntime, OpExportDeviceHistory) || !Permits(PrincipalOwner, OpExportDeviceHistory) ||
		!Deciding(OpExportDeviceHistory) {
		t.Fatal("history export is not confined to an owner decision")
	}
	if response := h.runtimeAttempt(t, base); response.OK || response.Code != fault.CodeClassNotDelegated {
		t.Fatalf("runtime exported history: %+v", response)
	}
	challenge := h.callAs(t, PrincipalOwner, Request{Op: OpChallenge}).Challenge
	signature, err := SignDecision(base, challenge, testOwnerKey())
	if err != nil {
		t.Fatal(err)
	}
	substituted := base
	substituted.TargetDeviceID = "dev_" + strings.Repeat("8", 64)
	substituted.Challenge, substituted.OwnerSignature = challenge, signature
	if response := h.callAs(t, PrincipalOwner, substituted); response.OK || response.Code != fault.CodeNotAuthentic {
		t.Fatalf("target substitution used an owner signature: %+v", response)
	}

	original, err := DecisionBytes(base, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Request){
		"target":         func(r *Request) { r.TargetDeviceID = "dev_" + strings.Repeat("8", 64) },
		"conversation":   func(r *Request) { r.ConversationID = "conv_" + strings.Repeat("9", 64) },
		"sequence":       func(r *Request) { r.HistorySequence++ },
		"predecessor":    func(r *Request) { r.PreviousSegmentDigest = "sha256:" + strings.Repeat("e", 64) },
		"created cursor": func(r *Request) { r.AfterCreatedAtUnix++ },
		"event cursor":   func(r *Request) { r.AfterEventID = "evt_" + strings.Repeat("f", 64) },
		"limit":          func(r *Request) { r.Limit++ },
		"idempotency":    func(r *Request) { r.IdempotencyKey = "idem_" + strings.Repeat("0", 64) },
		"expiry":         func(r *Request) { r.ExpiresAtUnix++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			encoded, err := DecisionBytes(changed, strings.Repeat("d", 64))
			if err != nil || bytes.Equal(encoded, original) {
				t.Fatalf("term is not committed: err=%v", err)
			}
		})
	}
}

func TestOwnerListsCommittedDisplayHistoryWithoutApplicationLease(t *testing.T) {
	h := newHarness(t)
	historical := h.event(t, "display only")
	historical.CreatedAtUnix = baseUnix - 10
	historical.EventID = ""
	var err error
	historical, err = envelope.NewEvent(historical)
	if err != nil {
		t.Fatal(err)
	}
	historicalRaw, err := envelope.EncodeEventJSON(historical)
	if err != nil {
		t.Fatal(err)
	}
	segment := payload.DeviceHistorySegment{SourceDeviceID: targetDev, TargetDeviceID: senderDev,
		ConversationID: convoID, Sequence: 1, Events: [][]byte{historicalRaw}}
	content, err := payload.Encode(segment)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := envelope.NewEvent(envelope.Event{Network: testNetwork(), ConversationID: convoID,
		SenderAgentID: senderID, SenderEndpointID: senderMEP, SenderDeviceID: targetDev,
		CreatedAtUnix: baseUnix, Kind: "device.history.segment", Content: content})
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := h.journal.ApplyHistorySegment(outer, segment, senderID, senderMEP, senderDev,
		[]string{senderDev, targetDev}, h.clock); err != nil || !fresh {
		t.Fatalf("apply display history: fresh=%v err=%v", fresh, err)
	}
	request := Request{Op: OpListDeviceHistory, ConversationID: convoID, Limit: 1}
	if response := h.call(t, request); response.OK || response.Code != fault.CodeClassNotDelegated {
		t.Fatalf("runtime read owner history surface: %+v", response)
	}
	response := h.owner(t, request)
	if !response.OK || len(response.History) != 1 {
		t.Fatalf("owner history listing: %+v", response)
	}
	listed, err := envelope.DecodeEventJSON(response.History[0])
	if err != nil || listed.EventID != historical.EventID {
		t.Fatalf("listed history changed: %+v err=%v", listed, err)
	}
	if _, err := EncodeRequest(Request{Op: OpListDeviceHistory, ConversationID: convoID,
		Limit: MaxHistoryEventsPerResponse + 1}); err == nil {
		t.Fatal("oversized history listing was encoded")
	}
}

// The owner's half of the loop: see what is waiting, decide, and only then
// does the runtime see it.
func TestOwnerAdmitsAnInboundEvent(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "from a stranger")
	payload, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, _, err := h.journal.Accept(eventlog.Entry{
		EventID: event.EventID, SenderEndpointID: event.SenderEndpointID,
		ConversationID: event.ConversationID, Payload: payload,
		Admission: eventlog.AdmissionPending, ReceivedAtUnix: uint64(h.clock.Unix()),
	}); err != nil {
		t.Fatalf("accept: %v", err)
	}

	if listing := h.call(t, Request{Op: OpPending}); len(listing.Events) != 0 {
		t.Fatalf("a waiting event was offered to the runtime: %+v", listing)
	}
	waiting := h.owner(t, Request{Op: OpAwaitingAdmission})
	if !waiting.OK || len(waiting.Events) != 1 {
		t.Fatalf("the owner sees nothing waiting: %+v", waiting)
	}
	if admitted := h.owner(t, Request{Op: OpAdmit, EventID: event.EventID}); !admitted.OK {
		t.Fatalf("admit: %+v", admitted)
	}
	if listing := h.call(t, Request{Op: OpPending}); len(listing.Events) != 1 {
		t.Fatalf("an admitted event did not reach the runtime: %+v", listing)
	}
}

func TestOwnerRefusesAnInboundEvent(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "from a stranger")
	payload, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, _, err := h.journal.Accept(eventlog.Entry{
		EventID: event.EventID, SenderEndpointID: event.SenderEndpointID,
		ConversationID: event.ConversationID, Payload: payload,
		Admission: eventlog.AdmissionPending, ReceivedAtUnix: uint64(h.clock.Unix()),
	}); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if refused := h.owner(t, Request{Op: OpRefuse, EventID: event.EventID,
		Code: fault.CodeAdmissionRequired}); !refused.OK {
		t.Fatalf("refuse: %+v", refused)
	}
	if listing := h.call(t, Request{Op: OpPending}); len(listing.Events) != 0 {
		t.Fatalf("a refused event reached the runtime: %+v", listing)
	}
	if waiting := h.owner(t, Request{Op: OpAwaitingAdmission}); len(waiting.Events) != 0 {
		t.Fatalf("a decided event is still waiting: %+v", waiting)
	}
	// The decision is made once.
	if again := h.owner(t, Request{Op: OpAdmit, EventID: event.EventID}); again.OK {
		t.Fatal("a refused event was admitted afterwards")
	}
}

// The frame bound has to be the bound, not whatever buffer the reader happened
// to allocate. A 4 KiB reader silently made every larger message unsendable.
func TestLargeFramesTravelOverTheSocket(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "run", "runtime.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() { _ = h.server.Serve(context.Background(), listener, PrincipalRuntime) }()

	for _, size := range []int{4 << 10, 64 << 10, 100 << 10} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			event := h.event(t, strings.Repeat("x", size))
			encoded, err := envelope.EncodeEventJSON(event)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			request, err := EncodeRequest(Request{
				Op: OpQueue, Event: json.RawMessage(encoded), SessionID: sessionID,
				RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 3600,
			})
			if err != nil {
				t.Fatalf("encode request: %v", err)
			}
			if len(request) <= size {
				t.Fatalf("the request did not carry its content: %d bytes", len(request))
			}

			connection, err := net.Dial("unix", path)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer connection.Close()
			if _, err := connection.Write(request); err != nil {
				t.Fatalf("write: %v", err)
			}
			body, err := ReadFrame(bufio.NewReader(connection))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			response, err := DecodeResponse(body)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !response.OK {
				t.Fatalf("a %d byte event was refused: %+v", size, response)
			}
		})
	}
}

// A frame past the bound costs four bytes, not the size it claimed.
func TestOversizedFrameIsRefusedBeforeAllocation(t *testing.T) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(MaxFrameBytes+1))
	if _, err := ReadFrame(bytes.NewReader(header[:])); err == nil {
		t.Fatal("an oversized frame was accepted")
	}
	binary.BigEndian.PutUint32(header[:], 0)
	if _, err := ReadFrame(bytes.NewReader(header[:])); err == nil {
		t.Fatal("an empty frame was accepted")
	}
	// A frame whose declared length exceeds what follows fails rather than
	// returning a short body.
	binary.BigEndian.PutUint32(header[:], 16)
	if _, err := ReadFrame(bytes.NewReader(append(header[:], []byte("short")...))); err == nil {
		t.Fatal("a truncated frame was accepted")
	}
}

func sendAttempt(t *testing.T, h *harness, eventID string, seed byte) string {
	t.Helper()
	id, err := eventlog.NewAttemptID(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatalf("attempt id: %v", err)
	}
	if _, err := h.journal.ClaimForSend(eventID, id, h.clock, time.Minute); err != nil {
		t.Fatalf("claim for send: %v", err)
	}
	return id
}

func testProposal(effect string, origins ...ActionOrigin) *ProposedAction {
	proposal := &ProposedAction{Effect: effect, Summary: "call the payments tool", Derived: origins}
	if effect == "tool-call" {
		proposal.IdempotencyKey = "idem_" + strings.Repeat("a", 64)
	}
	return proposal
}

func testActionOrigin() ActionOrigin {
	return ActionOrigin{
		AgentID:        senderID,
		EndpointID:     senderMEP,
		DeviceID:       senderDev,
		EventID:        "evt_" + strings.Repeat("7", 64),
		ConversationID: convoID,
		Kind:           "text",
		ReceivedAtUnix: baseUnix,
	}
}

// An action a stranger's message led to stops, waits for a person, and
// proceeds exactly once when that person says yes.
func TestActionDerivedFromReceivedContentWaitsForTheOwner(t *testing.T) {
	h := newHarness(t)

	asked := h.call(t, Request{Op: OpRequestAction, Action: testProposal("tool-call", testActionOrigin())})
	if !asked.OK || asked.Decision != "require-owner-approval" {
		t.Fatalf("a tool call a stranger's message drove ran unattended: %+v", asked)
	}
	if asked.ActionID == "" || asked.Authorised {
		t.Fatalf("the runtime was told it could proceed: %+v", asked)
	}

	// The runtime may look, and looking consumes nothing.
	status := h.call(t, Request{Op: OpActionStatus, ActionID: asked.ActionID})
	if status.State != "pending" {
		t.Fatalf("unexpected state before a decision: %+v", status)
	}
	if claimed := h.call(t, Request{Op: OpClaimAction, ActionID: asked.ActionID}); claimed.Authorised {
		t.Fatal("an undecided action was performed")
	}

	// The owner sees the question, and what caused it.
	waiting := h.owner(t, Request{Op: OpPendingActions})
	if len(waiting.Actions) != 1 || waiting.Actions[0].ActionID != asked.ActionID {
		t.Fatalf("the owner was not asked: %+v", waiting)
	}
	if len(waiting.Actions[0].Origins) != 1 ||
		waiting.Actions[0].Origins[0].EventID != testActionOrigin().EventID {
		t.Fatalf("the owner would not know what caused it: %+v", waiting.Actions[0])
	}
	if waiting.Actions[0].IdempotencyKey != askedKey(t, asked.ActionID, testProposal("tool-call", testActionOrigin())) {
		t.Fatal("the owner was not shown the tool invocation idempotency key")
	}

	if granted := h.owner(t, Request{Op: OpGrantAction, ActionID: asked.ActionID}); !granted.OK {
		t.Fatalf("grant: %+v", granted)
	}
	first := h.call(t, Request{Op: OpClaimAction, ActionID: asked.ActionID})
	if !first.Authorised {
		t.Fatalf("a granted action could not proceed: %+v", first)
	}
	second := h.call(t, Request{Op: OpClaimAction, ActionID: asked.ActionID})
	if second.Authorised {
		t.Fatal("one decision authorised the same action twice")
	}
}

func TestPhysicalIORequiresLocalCapabilityAndOneShotOwnerDecision(t *testing.T) {
	h := newHarnessWithPolicy(t, firewall.Policy{
		UnattendedCeiling: firewall.EffectMessage, OwnInitiativeCeiling: firewall.EffectPhysicalIO,
	})
	proposal := &ProposedAction{
		Effect: "physical-io", Summary: "read local temperature sensor",
		IdempotencyKey: "idem_" + strings.Repeat("b", 64),
		Physical: &PhysicalOperation{CapabilityID: "cap_" + strings.Repeat("c", 64),
			Tool: "i2c", Operation: "read",
			ArgumentsDigest: "sha256:16384135fc236bb03583cf3024b9fb573cc1ae45f908a98d0601d2ab45f8cfbe",
			ArgumentsJSON:   `{"action":"read"}`},
	}
	asked := h.call(t, Request{Op: OpRequestAction, Action: proposal})
	if !asked.OK || asked.Decision != string(firewall.RequireOwnerApproval) || asked.State != "pending" || asked.Authorised {
		t.Fatalf("physical I/O escaped owner hold: %+v", asked)
	}
	waiting := h.owner(t, Request{Op: OpPendingActions})
	if len(waiting.Actions) != 1 || waiting.Actions[0].Physical == nil ||
		*waiting.Actions[0].Physical != *proposal.Physical {
		t.Fatalf("owner did not receive exact physical operation: %+v", waiting)
	}
	if granted := h.owner(t, Request{Op: OpGrantAction, ActionID: asked.ActionID}); !granted.OK {
		t.Fatalf("grant: %+v", granted)
	}
	if first := h.call(t, Request{Op: OpClaimAction, ActionID: asked.ActionID}); !first.Authorised {
		t.Fatalf("physical grant could not be claimed: %+v", first)
	}
	if second := h.call(t, Request{Op: OpClaimAction, ActionID: asked.ActionID}); second.Authorised {
		t.Fatal("one physical decision authorized two invocations")
	}

	mutated := *proposal
	physical := *proposal.Physical
	mutated.Physical = &physical
	mutated.Physical.ArgumentsDigest = "sha256:fc8d3bb5fdbbf709135d031562103a482a000d9f0385762020409ca235915f85"
	mutated.Physical.ArgumentsJSON = `{"action":"read","length":2}`
	conflict := h.call(t, Request{Op: OpRequestAction, Action: &mutated})
	if conflict.Decision != string(firewall.Refuse) || conflict.ActionID == asked.ActionID {
		t.Fatalf("argument substitution reused a physical invocation key: %+v", conflict)
	}
}

func askedKey(t *testing.T, actionID string, proposal *ProposedAction) string {
	t.Helper()
	action, err := toAction(*proposal)
	if err != nil {
		t.Fatalf("action: %v", err)
	}
	derived, err := firewall.ActionID(action)
	if err != nil || derived != actionID {
		t.Fatalf("proposal did not reproduce action id: %s %v", derived, err)
	}
	return proposal.IdempotencyKey
}

func TestPolicyAllowedToolCallIsClaimedOncePerIdempotencyKey(t *testing.T) {
	h := newHarness(t)
	first := testProposal("tool-call")
	allowed := h.call(t, Request{Op: OpRequestAction, Action: first})
	if !allowed.OK || allowed.Decision != "allow" || allowed.Authorised || allowed.State != "granted" {
		t.Fatalf("tool call did not become a one-shot grant: %+v", allowed)
	}
	if claimed := h.call(t, Request{Op: OpClaimAction, ActionID: allowed.ActionID}); !claimed.Authorised {
		t.Fatalf("tool call grant could not be claimed: %+v", claimed)
	}
	replayed := h.call(t, Request{Op: OpRequestAction, Action: first})
	if replayed.ActionID != allowed.ActionID || replayed.State != "spent" {
		t.Fatalf("same idempotency key minted another grant: %+v", replayed)
	}
	if claimed := h.call(t, Request{Op: OpClaimAction, ActionID: replayed.ActionID}); claimed.Authorised {
		t.Fatal("same tool invocation was authorised twice")
	}
	reworded := *first
	reworded.Summary = "same invocation, gentler description"
	conflict := h.call(t, Request{Op: OpRequestAction, Action: &reworded})
	if conflict.Decision != "refuse" || conflict.ActionID == allowed.ActionID {
		t.Fatalf("re-described invocation reused one key: %+v", conflict)
	}

	second := testProposal("tool-call")
	second.IdempotencyKey = "idem_" + strings.Repeat("b", 64)
	distinct := h.call(t, Request{Op: OpRequestAction, Action: second})
	if distinct.ActionID == allowed.ActionID || distinct.State != "granted" {
		t.Fatalf("distinct tool invocation was collapsed into a replay: %+v", distinct)
	}
}

func TestToolCallRequiresCanonicalIdempotencyKey(t *testing.T) {
	for name, key := range map[string]string{"missing": "", "malformed": "idem_not-hex"} {
		t.Run(name, func(t *testing.T) {
			request := Request{Op: OpRequestAction, Action: &ProposedAction{
				Effect: "tool-call", Summary: "invoke tool", IdempotencyKey: key,
			}}
			if _, err := EncodeRequest(request); err == nil {
				t.Fatalf("tool call idempotency key %q was accepted", key)
			}
		})
	}
}

// The identifier is derived from the action, so an approval cannot be spent on
// a different one.
func TestApprovalCannotBeSpentOnAnotherAction(t *testing.T) {
	h := newHarness(t)
	origin := testActionOrigin()

	harmless := h.call(t, Request{Op: OpRequestAction, Action: testProposal("tool-call", origin)})
	if harmless.ActionID == "" {
		t.Fatalf("request: %+v", harmless)
	}
	if granted := h.owner(t, Request{Op: OpGrantAction, ActionID: harmless.ActionID}); !granted.OK {
		t.Fatalf("grant: %+v", granted)
	}

	// The same words, a stronger effect. A different action, and so a
	// different identifier with no approval behind it.
	stronger := h.call(t, Request{Op: OpRequestAction, Action: testProposal("key-use", origin)})
	if stronger.ActionID == harmless.ActionID {
		t.Fatal("two different actions shared one identifier")
	}
	if claimed := h.call(t, Request{Op: OpClaimAction, ActionID: stronger.ActionID}); claimed.Authorised {
		t.Fatal("an approval for one action authorised another")
	}
}

// The party that asks for an approval must not be able to grant it, and the
// party that grants does no Agent work.
func TestNeitherSideCanPlayTheOtherOnActions(t *testing.T) {
	h := newHarness(t)
	asked := h.call(t, Request{Op: OpRequestAction, Action: testProposal("tool-call", testActionOrigin())})
	if asked.ActionID == "" {
		t.Fatalf("request: %+v", asked)
	}
	for _, operation := range []Operation{OpGrantAction, OpDenyAction, OpPendingActions} {
		request := Request{Op: operation, ActionID: asked.ActionID}
		if operation == OpDenyAction {
			request.Reason = "no"
		}
		if operation == OpPendingActions {
			request.ActionID = ""
		}
		if response := h.runtimeAttempt(t, request); response.OK {
			t.Fatalf("the runtime performed %q", operation)
		}
	}
	for _, operation := range []Operation{OpRequestAction, OpActionStatus, OpClaimAction} {
		request := Request{Op: operation, ActionID: asked.ActionID}
		if operation == OpRequestAction {
			request.ActionID = ""
			request.Action = testProposal("tool-call", testActionOrigin())
		}
		if response := h.owner(t, request); response.OK {
			t.Fatalf("the owner performed %q", operation)
		}
	}
}

// Replying is ordinary Agent work and does not stop for a person.
func TestOrdinaryWorkNeedsNoDecision(t *testing.T) {
	h := newHarness(t)
	reply := h.call(t, Request{Op: OpRequestAction, Action: &ProposedAction{
		Effect: "message", Summary: "answer the message", Derived: []ActionOrigin{testActionOrigin()},
	}})
	if !reply.OK || !reply.Authorised || reply.Decision != "allow" {
		t.Fatalf("answering a message required a person: %+v", reply)
	}
	// Nothing was written down, because nothing was asked.
	if waiting := h.owner(t, Request{Op: OpPendingActions}); len(waiting.Actions) != 0 {
		t.Fatalf("an allowed action was put to the owner: %+v", waiting)
	}
}

// A malformed proposal is refused as a result rather than escalated: no owner
// decision makes it coherent.
func TestMalformedProposalIsRefusedNotAsked(t *testing.T) {
	h := newHarness(t)
	response := h.call(t, Request{Op: OpRequestAction, Action: testProposal("delete-everything")})
	if !response.OK || response.Decision != "refuse" {
		t.Fatalf("an unknown effect was not refused: %+v", response)
	}
	if waiting := h.owner(t, Request{Op: OpPendingActions}); len(waiting.Actions) != 0 {
		t.Fatalf("a malformed proposal was put to the owner: %+v", waiting)
	}
}

// Spending is not this interface's to authorise. A proposal naming the
// retired spend effect is refused as a result, never put to the owner, and the
// retired mandate operations are refused on both sockets.
func TestRetiredSpendSurfaceIsRefused(t *testing.T) {
	h := newHarness(t)
	for _, effect := range firewall.RetiredEffects {
		for _, proposal := range []*ProposedAction{testProposal(string(effect)), testProposal(string(effect), testActionOrigin())} {
			response := h.call(t, Request{Op: OpRequestAction, Action: proposal})
			if !response.OK || response.Decision != string(firewall.Refuse) {
				t.Fatalf("retired effect %q was not refused: %+v", effect, response)
			}
		}
	}
	if waiting := h.owner(t, Request{Op: OpPendingActions}); len(waiting.Actions) != 0 {
		t.Fatalf("a retired effect was put to the owner: %+v", waiting)
	}
	for _, operation := range RetiredOperations {
		if _, err := EncodeRequest(Request{Op: operation}); err == nil {
			t.Fatalf("retired operation %q was encoded", operation)
		}
		raw := []byte(`{"schema":"` + RequestSchema + `","op":"` + string(operation) + `"}`)
		if _, err := DecodeRequest(raw); err == nil {
			t.Fatalf("retired operation %q was decoded", operation)
		}
	}
}

// Peer credentials establish which Unix user is calling, and the Agent runtime
// commonly is that user. What separates the owner is a key the runtime does
// not have, so an unsigned or wrongly signed decision is refused however it
// arrived.
func TestOwnerDecisionsNeedTheOwnersKey(t *testing.T) {
	h := newHarness(t)
	event := h.accept(t, "hello")
	held := Request{Op: OpAdmit, EventID: event.EventID}

	issued := h.callAs(t, PrincipalOwner, Request{Op: OpChallenge})
	if !issued.OK || issued.Challenge == "" {
		t.Fatalf("challenge: %+v", issued)
	}

	// Someone else's key does not do.
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x99}, ed25519.SeedSize))
	forged, err := SignDecision(held, issued.Challenge, stranger)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	attempt := held
	attempt.Challenge = issued.Challenge
	attempt.OwnerSignature = forged
	if response := h.callAs(t, PrincipalOwner, attempt); response.OK {
		t.Fatal("a decision signed by a stranger was accepted")
	}

	// A signature for one decision is not a signature for another.
	other := Request{Op: OpRefuse, EventID: event.EventID, Code: fault.CodeRejected}
	genuine, err := SignDecision(held, issued.Challenge, testOwnerKey())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	other.Challenge = issued.Challenge
	other.OwnerSignature = genuine
	if response := h.callAs(t, PrincipalOwner, other); response.OK {
		t.Fatal("a signature for one decision authorised another")
	}

	// The genuine one works, once.
	attempt.OwnerSignature = genuine
	if response := h.callAs(t, PrincipalOwner, attempt); !response.OK {
		t.Fatalf("the owner's own decision was refused: %+v", response)
	}
	if response := h.callAs(t, PrincipalOwner, attempt); response.OK {
		t.Fatal("a decision was replayed")
	}
}

// A challenge is single use and does not outlive its window.
func TestChallengesExpireAndDoNotRepeat(t *testing.T) {
	h := newHarness(t)
	first := h.callAs(t, PrincipalOwner, Request{Op: OpChallenge})
	second := h.callAs(t, PrincipalOwner, Request{Op: OpChallenge})
	if first.Challenge == second.Challenge {
		t.Fatal("two challenges were the same")
	}

	event := h.accept(t, "hello")
	request := Request{Op: OpAdmit, EventID: event.EventID}
	signature, err := SignDecision(request, first.Challenge, testOwnerKey())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	request.Challenge = first.Challenge
	request.OwnerSignature = signature

	h.clock = h.clock.Add(DefaultChallengeLifetime + time.Second)
	if response := h.callAs(t, PrincipalOwner, request); response.OK {
		t.Fatal("an expired challenge was accepted")
	}
}

// A wrong signature must not burn a challenge the owner is about to use.
func TestAFailedAttemptDoesNotConsumeTheChallenge(t *testing.T) {
	h := newHarness(t)
	event := h.accept(t, "hello")
	issued := h.callAs(t, PrincipalOwner, Request{Op: OpChallenge})

	request := Request{Op: OpAdmit, EventID: event.EventID, Challenge: issued.Challenge}
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x99}, ed25519.SeedSize))
	forged, err := SignDecision(request, issued.Challenge, stranger)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	request.OwnerSignature = forged
	if response := h.callAs(t, PrincipalOwner, request); response.OK {
		t.Fatal("a forged decision was accepted")
	}

	genuine, err := SignDecision(Request{Op: OpAdmit, EventID: event.EventID}, issued.Challenge, testOwnerKey())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	request.OwnerSignature = genuine
	if response := h.callAs(t, PrincipalOwner, request); !response.OK {
		t.Fatalf("a failed attempt consumed the challenge: %+v", response)
	}
}

// A tool call the policy allows is authorised once. One decision -- the
// owner's or the policy's -- backs one execution, and asking again for the
// same invocation finds its grant already spent.
func TestAllowedToolCallIsAuthorisedOnce(t *testing.T) {
	h := newHarness(t)
	tool := testProposal("tool-call")

	asked := h.call(t, Request{Op: OpRequestAction, Action: tool})
	if !asked.OK || asked.Decision != "allow" {
		t.Fatalf("an own-initiative tool call was not allowed: %+v", asked)
	}
	// Allowed is not yet authorised: the grant has to be claimed.
	if asked.Authorised {
		t.Fatalf("an allowed tool call was authorised without a claim: %+v", asked)
	}
	if asked.State != "granted" {
		t.Fatalf("the policy's grant was not recorded: %+v", asked)
	}

	first := h.call(t, Request{Op: OpClaimAction, ActionID: asked.ActionID})
	if !first.Authorised {
		t.Fatalf("a granted tool call could not proceed: %+v", first)
	}
	second := h.call(t, Request{Op: OpClaimAction, ActionID: asked.ActionID})
	if second.Authorised {
		t.Fatal("one policy decision backed two executions")
	}
	// Asking again does not mint a second execution either.
	again := h.call(t, Request{Op: OpRequestAction, Action: tool})
	if again.State != "spent" {
		t.Fatalf("re-asking reopened a spent grant: %+v", again)
	}
	if claimed := h.call(t, Request{Op: OpClaimAction, ActionID: again.ActionID}); claimed.Authorised {
		t.Fatal("a replayed invocation was executed")
	}

	// A reply stays inline: the machinery is spent where the damage is.
	reply := h.call(t, Request{Op: OpRequestAction, Action: &ProposedAction{
		Effect: "message", Summary: "answer", Derived: []ActionOrigin{testActionOrigin()},
	}})
	if !reply.Authorised {
		t.Fatalf("a reply needed a claim: %+v", reply)
	}
}
