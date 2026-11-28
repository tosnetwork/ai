package localapi

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/internal/localwire"
	"github.com/tosnetwork/ai/messenger/pkg/attachmentadmission"
	"github.com/tosnetwork/ai/messenger/pkg/attachmentops"
	"github.com/tosnetwork/ai/messenger/pkg/contact"
	"github.com/tosnetwork/ai/messenger/pkg/dispatch"
	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/firewall"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/payload"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	commerce "github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
	protocolcodec "github.com/tosnetwork/ai/protocol/pkg/codec"
)

// DefaultRequestTimeout bounds how long one call may hold a connection.
const DefaultRequestTimeout = 30 * time.Second

// Config wires one server.
type Config struct {
	Journal    *eventlog.Journal
	Dispatcher *dispatch.Dispatcher
	// Policy is what the Agent may reach unattended. It is required: a server
	// with no policy would answer every firewall question with whatever the
	// zero value happened to mean.
	Policy firewall.Policy
	// OwnerKey is the public key the owner signs decisions with. It is
	// required, and it must not be reachable by the Agent runtime: it is the
	// only thing that distinguishes the owner from anything else running under
	// the same Unix user.
	OwnerKey ed25519.PublicKey
	// LocalEndpointID scopes every admission invite minted by this server.
	LocalEndpointID string
	// ChallengeLifetime bounds how long an unanswered decision challenge
	// stands.
	ChallengeLifetime time.Duration
	Now               func() time.Time
	Timeout           time.Duration
	// RoomClockSkew is the daemon's clock-skew bound: a member stops sealing
	// for a private room at its end minus this bound (D18), so nothing is
	// sent that a receiver whose clock runs ahead would refuse. Zero means
	// DefaultRoomClockSkew.
	RoomClockSkew time.Duration
	// DeviceIDs is the complete, sorted current Endpoint roster. An empty
	// roster disables owner-authorized history export.
	DeviceIDs []string
	// AttachmentAdmitter is optional. When absent, encrypted attachment Events
	// remain daemon-reserved and no runtime can obtain their secret payload.
	AttachmentAdmitter AttachmentAdmitter
	// AttachmentEmitter is optional and independently operator-configured. It
	// owns outbound encryption, capability signing, upload and durable ordering.
	AttachmentEmitter AttachmentEmitter
	// ContactResolver is the daemon-owned alias/AgentID canonicalization
	// boundary. The runtime receives no directory, endpoint, device, prekey, or
	// session authority through this interface.
	ContactResolver ContactResolver
	// DirectConversationEnsurer owns the durable AgentID-keyed first-contact
	// boundary. Its result deliberately exposes no Endpoint, Device or Session.
	DirectConversationEnsurer DirectConversationEnsurer
	// DirectMessageSender accepts only human recipient intent and message
	// semantics. It never accepts Endpoint, Device, Session or route authority.
	DirectMessageSender DirectMessageSender
	// ContactStates answers contacts.state; nil refuses it as not configured.
	ContactStates ContactStateReader
	// EconomicActionAdmitter is a daemon-owned durable writer-generation and
	// exact-action boundary. When absent, autonomous economic sends fail closed.
	EconomicActionAdmitter EconomicActionAdmitter
	// RoomOperator is the daemon's private-room runtime: membership changes,
	// joining and room-wide composition over the relay. When absent, those
	// operations are refused as not configured; rooms.list and rooms.gaps
	// read the journal and work without it.
	RoomOperator RoomOperator
}

// RoomComposition is a room-wide message: the runtime's meaning, which the
// daemon seals to the room in its current epoch and fans out to its members.
type RoomComposition struct {
	RoomID, ConversationID, ReplyToEventID, MediaType, Body, IdempotencyKey string
	MembershipEpoch, ExpiresAtUnix                                          uint64
}

// RoomOperator owns private-room membership and room-wide carriage. Every
// membership method is reached only by a verified owner decision.
type RoomOperator interface {
	CreateRoom(ctx context.Context, roomID string) error
	AddRoomMember(ctx context.Context, roomID, agentID string) error
	RemoveRoomMember(ctx context.Context, roomID, agentID string) error
	JoinRoom(ctx context.Context, roomID, authorityAgentID string) error
	ComposeRoomMessage(ctx context.Context, composition RoomComposition) (eventID string, fresh bool, err error)
}

type EconomicActionAdmitter interface {
	Admit(commerce.AuthorizedAction, commerce.WriterFence, map[string]commerce.SemanticValue, []byte, time.Time) (commerce.ActionResolution, error)
	Submit(string, string) (commerce.ActionResolution, error)
	Resolve(string, string) (commerce.ActionResolution, error)
	Accept(string, string, string) (commerce.ActionResolution, error)
}

// ContactStateReader reports how this installation stands with an Agent,
// without writing anything.
type ContactStateReader interface {
	ContactState(ctx context.Context, agentID string) (ContactStanding, error)
}

type ContactResolver interface {
	Resolve(context.Context, string) (contact.Result, error)
}

type DirectConversationResult struct {
	AgentID        string
	CanonicalName  string
	ConversationID string
	Readiness      string
}

type DirectConversationEnsurer interface {
	EnsureDirectConversation(context.Context, string) (DirectConversationResult, error)
}

type DirectMessageResult struct {
	AgentID, CanonicalName, ConversationID, EventID, Readiness string
}

type DirectMessageSender interface {
	SendDirectMessage(context.Context, string, string, string, string, uint64) (DirectMessageResult, error)
	SendDirectApplication(context.Context, string, string, []byte, string, uint64) (DirectMessageResult, error)
	ReplyDirectMessage(context.Context, string, string, string, string, uint64) (DirectMessageResult, error)
}

type AttachmentAdmitter interface {
	Admit(context.Context, envelope.Event) (attachmentadmission.Result, error)
}

type AttachmentEmitter interface {
	Begin(attachmentops.BeginRequest) (attachmentops.Progress, error)
	Append(string, uint32, []byte) (attachmentops.Progress, error)
	Commit(context.Context, string) (attachmentops.Progress, error)
}

// Server answers calls on the owner-private socket.
type Server struct {
	config     Config
	challenges *challenges
}

// NewServer builds a server.
func NewServer(config Config) (*Server, error) {
	if config.Journal == nil {
		return nil, errors.New("the local API requires a durable journal")
	}
	if config.Dispatcher == nil {
		return nil, errors.New("the local API requires a dispatcher")
	}
	if err := config.Policy.Validate(); err != nil {
		return nil, err
	}
	if len(config.OwnerKey) != ed25519.PublicKeySize || canon.IsZero(config.OwnerKey) {
		return nil, errors.New("the local API requires the owner's public key")
	}
	if !identity.EndpointPattern.MatchString(config.LocalEndpointID) {
		return nil, errors.New("the local API requires its local endpoint identifier")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.RoomClockSkew == 0 {
		config.RoomClockSkew = DefaultRoomClockSkew
	}
	if config.RoomClockSkew < 0 || config.RoomClockSkew > time.Hour {
		return nil, errors.New("the room clock-skew bound is outside 0 .. 1 h")
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultRequestTimeout
	}
	if config.Timeout < 0 {
		return nil, errors.New("invalid local API timeout")
	}
	if len(config.DeviceIDs) > 0 {
		if !sort.StringsAreSorted(config.DeviceIDs) {
			return nil, errors.New("device-history roster must be sorted")
		}
		localDeviceID := config.Dispatcher.LocalIdentity().DeviceID
		foundLocal := false
		for index, deviceID := range config.DeviceIDs {
			if !ids.Device.MatchString(deviceID) || index > 0 && config.DeviceIDs[index-1] == deviceID {
				return nil, errors.New("invalid device-history roster")
			}
			foundLocal = foundLocal || deviceID == localDeviceID
		}
		if !foundLocal {
			return nil, errors.New("device-history roster omits the local device")
		}
		config.DeviceIDs = append([]string(nil), config.DeviceIDs...)
	}
	return &Server{config: config, challenges: newChallenges(config.ChallengeLifetime)}, nil
}

// Serve accepts connections for one principal until the listener is closed.
//
// A principal belongs to a listener rather than to a request, so a caller
// cannot choose which one it speaks for. The runtime reaches the daemon
// through a socket that has no approval operations on it at all.
func (s *Server) Serve(ctx context.Context, listener net.Listener, principal Principal) error {
	if _, known := permitted[principal]; !known {
		return errors.New("unknown local principal")
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.serveConnection(ctx, connection, principal)
	}
}

func (s *Server) serveConnection(ctx context.Context, connection net.Conn, principal Principal) {
	defer connection.Close()
	if err := localwire.VerifyPeer(connection); err != nil {
		// A caller this daemon cannot identify learns nothing about why.
		return
	}
	reader := bufio.NewReader(connection)
	for {
		if err := connection.SetDeadline(s.config.Now().Add(s.config.Timeout)); err != nil {
			return
		}
		body, err := ReadFrame(reader)
		if err != nil {
			return
		}
		response := s.handle(ctx, principal, body)
		encoded, err := EncodeResponse(response)
		if err != nil {
			return
		}
		if _, err := connection.Write(encoded); err != nil {
			return
		}
	}
}

// Handle answers one request for one principal. It is exported so a caller can
// drive the API in process, which is what a test and a single-binary
// deployment both want.
func (s *Server) Handle(ctx context.Context, principal Principal, raw []byte) Response {
	return s.handle(ctx, principal, raw)
}

func (s *Server) handle(ctx context.Context, principal Principal, raw []byte) Response {
	request, err := DecodeRequest(raw)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	if !Permits(principal, request.Op) {
		// Said plainly: this is not a capability this connection has, and no
		// amount of asking changes that.
		return refuse(fault.CodeClassNotDelegated,
			errors.New(string(principal)+" may not perform "+string(request.Op)))
	}
	if err := ctx.Err(); err != nil {
		return refuse(fault.CodeInternal, err)
	}
	now := s.config.Now()
	if err := s.authoriseDecision(request, now); err != nil {
		return refuse(fault.CodeNotAuthentic, err)
	}
	switch request.Op {
	case OpPending:
		return s.pending(request, now)
	case OpClaim:
		return s.claim(request, now)
	case OpPendingAgentGifts:
		return s.pendingAgentGifts(request, now)
	case OpClaimAgentGift:
		return s.claimAgentGift(request, now)
	case OpPendingAgreements:
		return s.pendingAgreements(request, now)
	case OpClaimAgreement:
		return s.claimAgreement(request, now)
	case OpPendingPrivateHandoffs:
		return s.pendingPrivateHandoffs(request, now)
	case OpClaimPrivateHandoff:
		return s.claimPrivateHandoff(request, now)
	case OpPendingCommerceProfileEvents:
		return s.pendingCommerceProfileEvents(request, now)
	case OpClaimCommerceProfileEvent:
		return s.claimCommerceProfileEvent(request, now)
	case OpComplete:
		return s.complete(request, now)
	case OpReject:
		return s.reject(request, now)
	case OpQueue:
		return s.queue(request)
	case OpCompose:
		return s.compose(ctx, request)
	case OpComposeProtocolResult:
		return s.composeProtocolResult(request)
	case OpResolveContact:
		return s.resolveContact(ctx, request)
	case OpEnsureDirectConversation:
		return s.ensureDirectConversation(ctx, request)
	case OpSendDirect:
		return s.sendDirect(ctx, request)
	case OpSendDirectApplication:
		return s.sendDirectApplication(ctx, request)
	case OpEconomicSendDirect:
		return s.economicSendDirect(ctx, request, now)
	case OpEconomicActionStatus:
		return s.economicActionStatus(request)
	case OpReplyDirect:
		return s.replyDirect(ctx, request)
	case OpPendingAttachments:
		return s.pendingAttachments(request, now)
	case OpClaimAttachment:
		return s.claimAttachment(ctx, request, now)
	case OpBeginOutboundAttachment:
		return s.beginOutboundAttachment(request)
	case OpAppendOutboundAttachment:
		return s.appendOutboundAttachment(request)
	case OpCommitOutboundAttachment:
		return s.commitOutboundAttachment(ctx, request)
	case OpAwaitingAdmission:
		return s.awaitingAdmission(request, now)
	case OpAdmit:
		return s.admit(request, now)
	case OpRefuse:
		return s.refuseEvent(request, now)
	case OpApprove:
		return s.approve(request, now)
	case OpDeny:
		return s.deny(request, now)
	case OpRequestAction:
		return s.requestAction(request, now)
	case OpActionStatus:
		return s.actionStatus(request)
	case OpClaimAction:
		return s.claimAction(request, now)
	case OpPendingActions:
		return s.pendingActions(request, now)
	case OpGrantAction:
		return s.grantAction(request, now)
	case OpDenyAction:
		return s.denyAction(request, now)
	case OpChallenge:
		return s.challenge(now)
	case OpCreateAdmissionInvite:
		return s.createAdmissionInvite(request, now)
	case OpPresentInvite:
		if _, err := s.config.Journal.PresentInvite(request.InviteRecipientAgentID, request.InviteToken,
			time.Unix(int64(request.InviteExpiresAtUnix), 0), now); err != nil {
			switch {
			case errors.Is(err, eventlog.ErrInvalidPresentedInvite):
				return refuse(fault.CodePayloadMalformed, err)
			case errors.Is(err, eventlog.ErrPresentedInvitesFull):
				return refuse(fault.CodeQuotaExceeded, err)
			default:
				return refuse(fault.CodeInternal, err)
			}
		}
		return Response{OK: true}
	case OpRemoveContact:
		removed, err := s.config.Journal.RemoveInvitedContact(request.ContactAgentID)
		if err != nil {
			return refuse(fault.CodeInternal, err)
		}
		if !removed {
			return refuse(fault.CodePayloadMalformed, errors.New("no invited contact for that Agent"))
		}
		return Response{OK: true}
	case OpExportDeviceHistory:
		return s.exportDeviceHistory(request)
	case OpListDeviceHistory:
		return s.listDeviceHistory(request)
	case OpCreateRoom, OpAddRoomMember, OpRemoveRoomMember, OpJoinRoom:
		return s.changeRoom(ctx, request)
	case OpListRooms:
		return s.listRooms(now)
	case OpListConversations:
		return s.listConversations(request, now)
	case OpMessageStatus:
		return s.messageStatus(request)
	case OpContactState:
		return s.contactState(ctx, request)
	case OpRoomGaps:
		return s.roomGaps(request)
	}
	return refuse(fault.CodeInternal, errors.New("unknown local operation"))
}

func (s *Server) economicSendDirect(ctx context.Context, request Request, now time.Time) Response {
	if s.config.EconomicActionAdmitter == nil || s.config.DirectMessageSender == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("economic messaging is not configured"))
	}
	effect, err := commerce.DecodeMessengerEffectRequest(request.ExactEconomicRequest)
	if err != nil {
		return refuse(fault.CodeNotAuthentic, err)
	}
	fields, err := commerce.ImportSemanticFields(request.EconomicAction.ActionKind, request.EconomicFields)
	if err != nil || !economicKindMatchesEffect(request.EconomicAction.ActionKind, effect.EventKind) {
		return refuse(fault.CodeNotAuthentic, errors.New("economic action kind does not authorize the Messenger effect"))
	}
	if request.EconomicAction.ActionKind == "operation.private-send" {
		if err := validateOperationPrivateSendEffect(*request.EconomicAction, effect, fields); err != nil {
			return refuse(fault.CodeNotAuthentic, err)
		}
	}
	resolution, err := s.config.EconomicActionAdmitter.Admit(*request.EconomicAction, *request.EconomicWriterFence,
		fields, request.ExactEconomicRequest, now)
	if err != nil || resolution.State == commerce.ActionConflict {
		return refuse(fault.CodeNotAuthentic, errors.New("economic action admission failed"))
	}
	if resolution.State == commerce.ActionAccepted {
		return Response{OK: true, AgentID: effect.RecipientAgentIDs[0], EventID: resolution.SinkReference,
			Readiness: "queued", EconomicResolution: &resolution}
	}
	if resolution.State != commerce.ActionPrepared && resolution.State != commerce.ActionSubmitted {
		return refuse(fault.CodeNotAuthentic, errors.New("economic action is not sendable"))
	}
	if resolution.State == commerce.ActionPrepared {
		resolution, err = s.config.EconomicActionAdmitter.Submit(request.EconomicAction.StableActionID, request.EconomicAction.ExactRequestDigest)
		if err != nil || resolution.State != commerce.ActionSubmitted {
			return refuse(fault.CodeInternal, errors.New("economic action could not enter durable submitted state"))
		}
	}
	idempotency := "idem_" + strings.TrimPrefix(request.EconomicAction.StableActionID, "sha256:")
	var sent DirectMessageResult
	if effect.EventKind == "text" {
		sent, err = s.config.DirectMessageSender.SendDirectMessage(ctx, effect.RecipientAgentIDs[0], effect.ContentType,
			string(effect.Payload), idempotency, request.EconomicAction.ExpiresAtUnix)
	} else {
		sent, err = s.config.DirectMessageSender.SendDirectApplication(ctx, effect.RecipientAgentIDs[0], effect.EventKind,
			effect.Payload, idempotency, request.EconomicAction.ExpiresAtUnix)
	}
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	resolution, err = s.config.EconomicActionAdmitter.Accept(request.EconomicAction.StableActionID,
		request.EconomicAction.ExactRequestDigest, sent.EventID)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, AgentID: sent.AgentID, CanonicalName: sent.CanonicalName,
		ConversationID: sent.ConversationID, EventID: sent.EventID, Readiness: sent.Readiness, EconomicResolution: &resolution}
}

func validateOperationPrivateSendEffect(action commerce.AuthorizedAction, effect commerce.MessengerEffectRequestV1,
	fields map[string]commerce.SemanticValue) error {
	if effect.EventKind != "operation.outcome" || effect.ContentType != "application/vnd.tos.operation-outcome-private+cbor" ||
		len(effect.RecipientAgentIDs) != 1 {
		return errors.New("operation private-send Messenger effect is invalid")
	}
	var outcome commerce.OperationPrivateRequestV1
	if protocolcodec.Unmarshal(effect.Payload, &outcome) != nil || commerce.ValidateOperationPrivateRequestV1(outcome) != nil ||
		len(outcome.RecipientAgentIDs) != 1 || outcome.RecipientAgentIDs[0] != effect.RecipientAgentIDs[0] {
		return errors.New("operation private-send payload does not bind its recipient")
	}
	expected, err := commerce.OperationPrivateSendSemanticFieldsV1(action.OwnerID, action.AgentID, outcome)
	if err != nil {
		return err
	}
	expectedOrdered, expectedErr := commerce.ExportSemanticFields(action.ActionKind, expected)
	actualOrdered, actualErr := commerce.ExportSemanticFields(action.ActionKind, fields)
	if expectedErr != nil || actualErr != nil || !reflect.DeepEqual(expectedOrdered, actualOrdered) {
		return errors.New("operation private-send semantic fields do not bind its payload")
	}
	return nil
}

func (s *Server) economicActionStatus(request Request) Response {
	if s.config.EconomicActionAdmitter == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("economic messaging is not configured"))
	}
	resolution, err := s.config.EconomicActionAdmitter.Resolve(request.EconomicStableID, request.EconomicRequestDigest)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, EconomicResolution: &resolution}
}

func economicKindMatchesEffect(actionKind, eventKind string) bool {
	switch actionKind {
	case "messenger.contact":
		return eventKind == "text" || eventKind == "intent.application"
	case "messenger.send":
		return eventKind == "text" || eventKind == "private.handoff.challenge" ||
			eventKind == "private.handoff.acknowledgement" || eventKind == "private.handoff.status" ||
			eventKind == "private.handoff.delete" || eventKind == "commerce.profile-event"
	case "operation.private-send":
		return eventKind == "operation.outcome"
	case "agreement.propose":
		return eventKind == "agreement.propose"
	case "agreement.authorize":
		return eventKind == "agreement.accept" || eventKind == "agreement.evidence"
	case "agreement.withdraw":
		return eventKind == "agreement.withdraw"
	case "disclosure.release":
		return eventKind == "private.handoff.authorization"
	case "content.upload":
		return eventKind == "private.handoff.acknowledgement" || eventKind == "private.handoff.status"
	case "content.delete":
		return eventKind == "private.handoff.delete" || eventKind == "private.handoff.status"
	case "delivery.release":
		return eventKind == "agreement.delivery"
	default:
		return false
	}
}

func (s *Server) sendDirect(ctx context.Context, request Request) Response {
	if s.config.DirectMessageSender == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("direct message sending is not configured"))
	}
	result, err := s.config.DirectMessageSender.SendDirectMessage(ctx, request.Recipient,
		request.MediaType, request.Body, request.IdempotencyKey, request.ExpiresAtUnix)
	if err != nil {
		return refuse(fault.CodeNotAuthentic, err)
	}
	if !agentPattern.MatchString(result.AgentID) || !conversationPattern.MatchString(result.ConversationID) ||
		!eventPattern.MatchString(result.EventID) || result.Readiness != "queued" {
		return refuse(fault.CodeNotAuthentic, errors.New("direct message result is not canonical"))
	}
	return Response{OK: true, AgentID: result.AgentID, CanonicalName: result.CanonicalName,
		ConversationID: result.ConversationID, EventID: result.EventID, Readiness: result.Readiness}
}

func (s *Server) sendDirectApplication(ctx context.Context, request Request) Response {
	if s.config.DirectMessageSender == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("direct application sending is not configured"))
	}
	result, err := s.config.DirectMessageSender.SendDirectApplication(ctx, request.Recipient,
		request.ApplicationKind, request.ApplicationBody, request.IdempotencyKey, request.ExpiresAtUnix)
	if err != nil {
		return refuse(fault.CodeNotAuthentic, err)
	}
	if !agentPattern.MatchString(result.AgentID) || !conversationPattern.MatchString(result.ConversationID) ||
		!eventPattern.MatchString(result.EventID) || result.Readiness != "queued" {
		return refuse(fault.CodeNotAuthentic, errors.New("direct application result is not canonical"))
	}
	return Response{OK: true, AgentID: result.AgentID, CanonicalName: result.CanonicalName,
		ConversationID: result.ConversationID, EventID: result.EventID, Readiness: result.Readiness}
}

func (s *Server) replyDirect(ctx context.Context, request Request) Response {
	if s.config.DirectMessageSender == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("direct message sending is not configured"))
	}
	result, err := s.config.DirectMessageSender.ReplyDirectMessage(ctx, request.ReplyToEventID,
		request.MediaType, request.Body, request.IdempotencyKey, request.ExpiresAtUnix)
	if err != nil {
		return refuse(fault.CodeNotAuthentic, err)
	}
	if !agentPattern.MatchString(result.AgentID) || !conversationPattern.MatchString(result.ConversationID) ||
		!eventPattern.MatchString(result.EventID) || result.Readiness != "queued" {
		return refuse(fault.CodeNotAuthentic, errors.New("direct reply result is not canonical"))
	}
	return Response{OK: true, AgentID: result.AgentID, ConversationID: result.ConversationID,
		EventID: result.EventID, Readiness: result.Readiness}
}

func (s *Server) resolveContact(ctx context.Context, request Request) Response {
	if s.config.ContactResolver == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("contact resolution is not configured"))
	}
	result, err := s.config.ContactResolver.Resolve(ctx, request.Recipient)
	if err != nil {
		return refuse(fault.CodeNotAuthentic, err)
	}
	if !agentPattern.MatchString(result.AgentID) {
		return refuse(fault.CodeNotAuthentic, errors.New("contact resolution returned no canonical AgentID"))
	}
	return Response{OK: true, AgentID: result.AgentID, CanonicalName: result.CanonicalName}
}

func (s *Server) ensureDirectConversation(ctx context.Context, request Request) Response {
	if s.config.DirectConversationEnsurer == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("direct conversation discovery is not configured"))
	}
	result, err := s.config.DirectConversationEnsurer.EnsureDirectConversation(ctx, request.Recipient)
	if err != nil {
		return refuse(fault.CodeNotAuthentic, err)
	}
	if !agentPattern.MatchString(result.AgentID) || !conversationPattern.MatchString(result.ConversationID) ||
		result.Readiness != "transport-pending" {
		return refuse(fault.CodeNotAuthentic, errors.New("direct conversation result is not canonical"))
	}
	return Response{
		OK: true, AgentID: result.AgentID, CanonicalName: result.CanonicalName,
		ConversationID: result.ConversationID, Readiness: result.Readiness,
	}
}

func (s *Server) beginOutboundAttachment(request Request) Response {
	if s.config.AttachmentEmitter == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("outbound attachment emission is not configured"))
	}
	progress, err := s.config.AttachmentEmitter.Begin(attachmentops.BeginRequest{
		ConversationID: request.ConversationID, RoomID: request.RoomID, ReplyToEventID: request.ReplyToEventID,
		MembershipEpoch: request.MembershipEpoch, IdempotencyKey: request.IdempotencyKey,
		SessionID: request.SessionID, RecipientEndpointID: request.RecipientEndpointID,
		Filename: request.Filename, MediaType: request.MediaType, PlaintextDigest: request.PlaintextDigest,
		PlaintextBytes: request.PlaintextBytes})
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, UploadID: progress.UploadID, NextChunk: progress.NextChunk,
		Complete: progress.Complete, EventID: progress.EventID}
}

func (s *Server) appendOutboundAttachment(request Request) Response {
	if s.config.AttachmentEmitter == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("outbound attachment emission is not configured"))
	}
	progress, err := s.config.AttachmentEmitter.Append(request.UploadID, request.ChunkIndex, request.Chunk)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, UploadID: progress.UploadID, NextChunk: progress.NextChunk}
}

func (s *Server) commitOutboundAttachment(ctx context.Context, request Request) Response {
	if s.config.AttachmentEmitter == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("outbound attachment emission is not configured"))
	}
	progress, err := s.config.AttachmentEmitter.Commit(ctx, request.UploadID)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, Complete: progress.Complete, EventID: progress.EventID}
}

func (s *Server) createAdmissionInvite(request Request, now time.Time) Response {
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return refuse(fault.CodeInternal, errors.New("generate admission invite"))
	}
	token, _, err := s.config.Journal.CreateAdmissionInvite(
		entropy, s.config.LocalEndpointID, request.InvitedAgentID,
		time.Unix(int64(request.InviteExpiresAtUnix), 0), now,
	)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, AdmissionToken: token}
}

func (s *Server) pending(request Request, now time.Time) Response {
	limit := request.Limit
	if limit == 0 || limit > MaxEventsPerResponse {
		limit = MaxEventsPerResponse
	}
	// Fetch the complete bounded journal view before filtering. Otherwise a
	// page filled by daemon-owned typed packets could hide ordinary messages
	// that follow it from the runtime indefinitely.
	records, err := s.config.Journal.ListPending(now, 0)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	events := make([]PendingEvent, 0, len(records))
	for _, record := range records {
		event, err := pendingEvent(record)
		if err != nil {
			// A damaged record is skipped rather than failing the listing: one
			// unreadable event must not stop every other one from being
			// delivered.
			continue
		}
		decoded, err := envelope.DecodeEventJSON(event.Event)
		if err != nil || daemonApplicationKind(decoded.Kind) {
			continue
		}
		events = append(events, event)
		if len(events) == limit {
			break
		}
	}
	return Response{OK: true, Events: events}
}

func (s *Server) claim(request Request, now time.Time) Response {
	record, err := s.config.Journal.ClaimForApplicationExceptKinds(request.EventID, request.LeaseID, now,
		time.Duration(request.LeaseSeconds)*time.Second,
		[]string{"agent.packet", "device.history.segment", "artifact.encrypted", "a2a.message", "mcp.call", "mcp.result",
			"agent.gift.address-request", "agent.gift.address-response", "agent.gift.signed-boc-offer",
			"intent.application", "agreement.propose", "agreement.accept", "agreement.evidence", "agreement.withdraw", "agreement.delivery",
			"commerce.profile-event", "operation.outcome",
			"private.handoff.challenge", "private.handoff.authorization", "private.handoff.acknowledgement", "private.handoff.status", "private.handoff.delete"})
	if err != nil {
		return refuse(claimCode(err), err)
	}
	event, err := pendingEvent(record)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, Event: &event}
}

func (s *Server) pendingAgentGifts(request Request, now time.Time) Response {
	limit := request.Limit
	if limit == 0 || limit > MaxEventsPerResponse {
		limit = MaxEventsPerResponse
	}
	records, err := s.config.Journal.ListPending(now, 0)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	events := make([]PendingEvent, 0, limit)
	for _, record := range records {
		event, err := pendingEvent(record)
		if err != nil {
			continue
		}
		decoded, err := envelope.DecodeEventJSON(event.Event)
		if err != nil || !agentGiftApplicationKind(decoded.Kind) {
			continue
		}
		events = append(events, event)
		if len(events) == limit {
			break
		}
	}
	return Response{OK: true, Events: events}
}

func (s *Server) claimAgentGift(request Request, now time.Time) Response {
	record, err := s.config.Journal.ClaimForApplicationKinds(request.EventID, request.LeaseID, now,
		time.Duration(request.LeaseSeconds)*time.Second,
		[]string{"agent.gift.address-request", "agent.gift.address-response", "agent.gift.signed-boc-offer"})
	if err != nil {
		return refuse(claimCode(err), err)
	}
	event, err := pendingEvent(record)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, Event: &event}
}

func (s *Server) pendingAgreements(request Request, now time.Time) Response {
	limit := request.Limit
	if limit == 0 || limit > MaxEventsPerResponse {
		limit = MaxEventsPerResponse
	}
	records, err := s.config.Journal.ListPending(now, 0)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	events := make([]PendingEvent, 0, limit)
	for _, record := range records {
		event, err := pendingEvent(record)
		if err != nil {
			continue
		}
		decoded, err := envelope.DecodeEventJSON(event.Event)
		if err != nil || !agreementApplicationKind(decoded.Kind) {
			continue
		}
		events = append(events, event)
		if len(events) == limit {
			break
		}
	}
	return Response{OK: true, Events: events}
}

func (s *Server) claimAgreement(request Request, now time.Time) Response {
	record, err := s.config.Journal.ClaimForApplicationKinds(request.EventID, request.LeaseID, now,
		time.Duration(request.LeaseSeconds)*time.Second,
		[]string{"intent.application", "agreement.propose", "agreement.accept", "agreement.evidence", "agreement.withdraw", "agreement.delivery"})
	if err != nil {
		return refuse(claimCode(err), err)
	}
	event, err := pendingEvent(record)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, Event: &event}
}

func (s *Server) pendingPrivateHandoffs(request Request, now time.Time) Response {
	limit := request.Limit
	if limit == 0 || limit > MaxEventsPerResponse {
		limit = MaxEventsPerResponse
	}
	records, err := s.config.Journal.ListPending(now, 0)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	events := make([]PendingEvent, 0, limit)
	for _, record := range records {
		event, eventErr := pendingEvent(record)
		if eventErr != nil {
			continue
		}
		decoded, decodeErr := envelope.DecodeEventJSON(event.Event)
		if decodeErr != nil || !privateHandoffApplicationKind(decoded.Kind) {
			continue
		}
		events = append(events, event)
		if len(events) == limit {
			break
		}
	}
	return Response{OK: true, Events: events}
}

func (s *Server) claimPrivateHandoff(request Request, now time.Time) Response {
	record, err := s.config.Journal.ClaimForApplicationKinds(request.EventID, request.LeaseID, now,
		time.Duration(request.LeaseSeconds)*time.Second,
		[]string{"private.handoff.challenge", "private.handoff.authorization", "private.handoff.acknowledgement", "private.handoff.status", "private.handoff.delete"})
	if err != nil {
		return refuse(claimCode(err), err)
	}
	event, err := pendingEvent(record)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, Event: &event}
}

func (s *Server) pendingCommerceProfileEvents(request Request, now time.Time) Response {
	limit := request.Limit
	if limit == 0 || limit > MaxEventsPerResponse {
		limit = MaxEventsPerResponse
	}
	records, err := s.config.Journal.ListPending(now, 0)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	events := make([]PendingEvent, 0, limit)
	for _, record := range records {
		event, eventErr := pendingEvent(record)
		if eventErr != nil {
			continue
		}
		decoded, decodeErr := envelope.DecodeEventJSON(event.Event)
		if decodeErr != nil || (decoded.Kind != "commerce.profile-event" && decoded.Kind != "operation.outcome") {
			continue
		}
		events = append(events, event)
		if len(events) == limit {
			break
		}
	}
	return Response{OK: true, Events: events}
}

func (s *Server) claimCommerceProfileEvent(request Request, now time.Time) Response {
	record, err := s.config.Journal.ClaimForApplicationKinds(request.EventID, request.LeaseID, now,
		time.Duration(request.LeaseSeconds)*time.Second, []string{"commerce.profile-event", "operation.outcome"})
	if err != nil {
		return refuse(claimCode(err), err)
	}
	event, err := pendingEvent(record)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, Event: &event}
}

func daemonApplicationKind(kind string) bool {
	return kind == "agent.packet" || kind == "device.history.segment" || kind == "artifact.encrypted" ||
		kind == "a2a.message" || kind == "mcp.call" || kind == "mcp.result" || kind == "commerce.profile-event" || kind == "operation.outcome" ||
		agentGiftApplicationKind(kind) || agreementApplicationKind(kind) || privateHandoffApplicationKind(kind)
}

func agentGiftApplicationKind(kind string) bool {
	return kind == "agent.gift.address-request" || kind == "agent.gift.address-response" || kind == "agent.gift.signed-boc-offer"
}

func agreementApplicationKind(kind string) bool {
	return kind == "intent.application" || kind == "agreement.propose" || kind == "agreement.accept" || kind == "agreement.evidence" ||
		kind == "agreement.withdraw" || kind == "agreement.delivery"
}

func privateHandoffApplicationKind(kind string) bool {
	return kind == "private.handoff.challenge" || kind == "private.handoff.authorization" ||
		kind == "private.handoff.acknowledgement" || kind == "private.handoff.status" || kind == "private.handoff.delete"
}

func (s *Server) pendingAttachments(request Request, now time.Time) Response {
	if s.config.AttachmentAdmitter == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("attachment admission is not configured"))
	}
	limit := request.Limit
	if limit == 0 || limit > MaxEventsPerResponse {
		limit = MaxEventsPerResponse
	}
	records, err := s.config.Journal.ListPending(now, 0)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	offers := make([]PendingAttachment, 0, len(records))
	for _, record := range records {
		pending, pendingErr := pendingEvent(record)
		if pendingErr != nil {
			continue
		}
		event, decodeErr := envelope.DecodeEventJSON(pending.Event)
		if decodeErr != nil || event.Kind != "artifact.encrypted" ||
			event.PayloadSchema != (payload.EncryptedAttachment{}).Schema() {
			continue
		}
		offers = append(offers, PendingAttachment{EventID: pending.EventID, SenderEndpointID: pending.SenderEndpointID,
			ConversationID: pending.ConversationID, ReceivedAtUnix: pending.ReceivedAtUnix})
		if len(offers) == limit {
			break
		}
	}
	return Response{OK: true, Attachments: offers}
}

func (s *Server) claimAttachment(ctx context.Context, request Request, now time.Time) Response {
	if s.config.AttachmentAdmitter == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("attachment admission is not configured"))
	}
	record, err := s.config.Journal.ClaimForApplicationKind(request.EventID, request.LeaseID, now,
		time.Duration(request.LeaseSeconds)*time.Second, "artifact.encrypted")
	if err != nil {
		return refuse(claimCode(err), err)
	}
	raw, err := record.Payload()
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	event, err := envelope.DecodeEventJSON(raw)
	if err != nil || event.EventID != record.EventID || event.SenderEndpointID != record.SenderEndpointID ||
		event.ConversationID != record.ConversationID || event.PayloadSchema != (payload.EncryptedAttachment{}).Schema() {
		return refuse(fault.CodeNotAuthentic, errors.New("stored attachment Event conflicts with its journal binding"))
	}
	admitted, err := s.config.AttachmentAdmitter.Admit(ctx, event)
	if err != nil {
		return refuse(fault.CodeInternal, errors.New("attachment admission failed: "+err.Error()))
	}
	scans := make([]AttachmentScan, 0, len(admitted.Report.Scans))
	for _, scan := range admitted.Report.Scans {
		resources := make([]AttachmentScanResource, len(scan.Resources))
		for index, resource := range scan.Resources {
			resources[index] = AttachmentScanResource{Name: resource.Name, Digest: resource.Digest}
		}
		scans = append(scans, AttachmentScan{ScannerID: scan.ScannerID, ScannerDigest: scan.ScannerDigest,
			Resources: resources})
	}
	return Response{OK: true, Attachment: &AdmittedAttachment{EventID: event.EventID,
		SenderAgentID: event.SenderAgentID, SenderEndpointID: event.SenderEndpointID,
		SenderDeviceID: event.SenderDeviceID, ConversationID: event.ConversationID, RoomID: event.RoomID,
		ReplyToEventID: event.ReplyToEventID, ReceivedAtUnix: record.ReceivedAtUnix,
		Filename: admitted.Metadata.Filename, MediaType: admitted.Metadata.MediaType,
		PlaintextDigest: admitted.Report.PlaintextDigest, SizeBytes: admitted.Report.SizeBytes,
		Body: admitted.Body, Scans: scans}}
}

func (s *Server) complete(request Request, now time.Time) Response {
	if _, err := s.config.Journal.CompleteApplication(request.EventID, request.LeaseID, now); err != nil {
		return refuse(claimCode(err), err)
	}
	return Response{OK: true}
}

func (s *Server) reject(request Request, now time.Time) Response {
	code := request.Code
	if code == "" {
		code = fault.CodeInternal
	}
	if _, err := s.config.Journal.RejectApplication(request.EventID, request.LeaseID, code, now); err != nil {
		return refuse(claimCode(err), err)
	}
	return Response{OK: true}
}

func (s *Server) queue(request Request) Response {
	// The runtime submits an encoded event, which is decoded and validated
	// here rather than trusted: the daemon owns what goes on the wire.
	event, err := envelope.DecodeEventJSON(request.Event)
	if err != nil {
		return refuse(fault.CodeUnknownEventKind, err)
	}
	fresh, _, err := s.config.Dispatcher.Queue(event, request.SessionID,
		request.RecipientEndpointID, request.ExpiresAtUnix)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, Fresh: fresh}
}

func (s *Server) compose(ctx context.Context, request Request) Response {
	if request.RoomID != "" {
		private, err := s.privateRoom(request.RoomID)
		if err != nil {
			return refuse(fault.CodeInternal, err)
		}
		if RoomWideComposition(request) {
			if !private {
				return refuse(fault.CodePayloadMalformed, errors.New("a room-wide composition needs a private room held here"))
			}
			return s.composeRoom(ctx, request)
		}
		// A private room's content is sealed to the room, so its members'
		// removal takes effect; it is never a pairwise device copy.
		if private {
			return refuse(fault.CodePayloadMalformed, errors.New("a private room's messages are composed to the room, not to a device"))
		}
	}
	if request.RecipientAgentID != "" {
		if s.config.ContactResolver == nil {
			return refuse(fault.CodeClassNotDelegated, errors.New("recipient route verification is not configured"))
		}
		resolved, err := s.config.ContactResolver.Resolve(ctx, request.RecipientAgentID)
		if err != nil || resolved.AgentID != request.RecipientAgentID ||
			resolved.Directory.Descriptor.AgentID != request.RecipientAgentID ||
			resolved.Directory.Descriptor.EndpointID != request.RecipientEndpointID {
			if err == nil {
				err = errors.New("recipient route is not bound to the canonical AgentID")
			}
			return refuse(fault.CodeNotAuthentic, err)
		}
	}
	event, fresh, err := s.config.Dispatcher.ComposeAndQueue(dispatch.ComposeRequest{
		ConversationID: request.ConversationID, RoomID: request.RoomID,
		ReplyToEventID: request.ReplyToEventID, MembershipEpoch: request.MembershipEpoch,
		MediaType: request.MediaType, Body: request.Body, IdempotencyKey: request.IdempotencyKey,
		SessionID: request.SessionID, RecipientEndpointID: request.RecipientEndpointID,
		RecipientAgentID: request.RecipientAgentID,
		ExpiresAtUnix:    request.ExpiresAtUnix,
	})
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, Fresh: fresh, EventID: event.EventID}
}

// privateRoom reports whether a room is a private room held here.
func (s *Server) privateRoom(roomID string) (bool, error) {
	ledger, err := s.config.Journal.OpenRoomMLS()
	if err != nil {
		return false, err
	}
	_, found, err := ledger.Current(roomID)
	return found, err
}

// composeRoom takes the kind-3 path: the composition is checked against the
// room's current epoch and this installation's membership, and handed to the
// room runtime, which seals it to the room.
func (s *Server) composeRoom(ctx context.Context, request Request) Response {
	ledger, err := s.config.Journal.OpenRoomMLS()
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	record, found, err := ledger.Current(request.RoomID)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	if !found {
		return refuse(fault.CodePayloadMalformed, errors.New("a room-wide composition needs a private room held here"))
	}
	if !record.Membership().Contains(s.config.Dispatcher.LocalIdentity().AgentID) {
		return refuse(fault.CodeNotARoomMember, errors.New("this installation is not a member of the room"))
	}
	if request.MembershipEpoch != record.RoomEpoch {
		return refuse(fault.CodeRoomEpochGap, errors.New("the composition names another room epoch than the current one"))
	}
	// D18: a member stops sealing at the room's end minus the skew bound.
	if roomSendingStopped(record.RoomEndsAtUnix, s.config.RoomClockSkew, s.config.Now()) {
		return refuse(fault.CodeRoomEnded, errors.New("the room has ended"))
	}
	// A member removed from the room seals nothing more in it (section 11.4).
	if _, removed, err := s.config.Journal.RoomRemovalOf(request.RoomID); err != nil {
		return refuse(fault.CodeInternal, err)
	} else if removed {
		return refuse(fault.CodeNotARoomMember, errors.New("this installation was removed from the room"))
	}
	// A room whose credential list cannot be read (for example one a crash
	// left half retired) sends nothing.
	if _, _, err := ledger.RoomCredential(request.RoomID, s.config.Dispatcher.LocalIdentity().AgentID); err != nil {
		return refuse(fault.CodeInternal, err)
	}
	// The sealed Event is bounded before the MLS seal; the body alone already
	// exceeding it is refused here.
	if len(request.Body) > relayframe.MaxRoomApplicationPlaintextBytes {
		return refuse(fault.CodeContentTooLarge, errors.New("a room message exceeds the room plaintext bound"))
	}
	if s.config.RoomOperator == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("private rooms over the relay are not configured"))
	}
	eventID, fresh, err := s.config.RoomOperator.ComposeRoomMessage(ctx, RoomComposition{
		RoomID: request.RoomID, ConversationID: request.ConversationID, ReplyToEventID: request.ReplyToEventID,
		MediaType: request.MediaType, Body: request.Body, IdempotencyKey: request.IdempotencyKey,
		MembershipEpoch: request.MembershipEpoch, ExpiresAtUnix: request.ExpiresAtUnix,
	})
	if err != nil {
		return refuse(faultCodeOr(err, fault.CodeInternal), err)
	}
	return Response{OK: true, Fresh: fresh, EventID: eventID, RoomID: request.RoomID}
}

// DefaultRoomClockSkew is the default clock-skew bound of the room end.
const DefaultRoomClockSkew = 5 * time.Minute

// roomSendingStopped reports whether now is at or past end - skew.
func roomSendingStopped(endsAtUnix uint64, skew time.Duration, now time.Time) bool {
	if endsAtUnix == 0 || endsAtUnix > uint64(1<<62) {
		return true
	}
	return !now.Before(time.Unix(int64(endsAtUnix), 0).Add(-skew))
}

// changeRoom carries one owner membership decision to the room runtime.
func (s *Server) changeRoom(ctx context.Context, request Request) Response {
	if s.config.RoomOperator == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("private rooms over the relay are not configured"))
	}
	var err error
	switch request.Op {
	case OpCreateRoom:
		err = s.config.RoomOperator.CreateRoom(ctx, request.RoomID)
	case OpAddRoomMember:
		err = s.config.RoomOperator.AddRoomMember(ctx, request.RoomID, request.RoomMemberAgentID)
	case OpRemoveRoomMember:
		err = s.config.RoomOperator.RemoveRoomMember(ctx, request.RoomID, request.RoomMemberAgentID)
	case OpJoinRoom:
		err = s.config.RoomOperator.JoinRoom(ctx, request.RoomID, request.RoomAuthorityAgentID)
	default:
		return refuse(fault.CodeInternal, errors.New("unknown room operation"))
	}
	if err != nil {
		return refuse(faultCodeOr(err, fault.CodeInternal), err)
	}
	return Response{OK: true, RoomID: request.RoomID}
}

// listRooms reads the private rooms held here and the live pending joins.
func (s *Server) listRooms(now time.Time) Response {
	ledger, err := s.config.Journal.OpenRoomMLS()
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	records, err := ledger.List()
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	joins, err := s.config.Journal.ListPendingRoomJoins(now)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	local := s.config.Dispatcher.LocalIdentity().AgentID
	rooms := make([]RoomSummary, 0, len(records)+len(joins))
	for _, record := range records {
		rooms = append(rooms, RoomSummary{RoomID: record.RoomID, State: "joined", AuthorityAgentID: record.AuthorityAgentID,
			IsAuthority: record.AuthorityAgentID == local, RoomEpoch: record.RoomEpoch, MLSEpoch: record.MLSEpoch,
			Members: append([]string(nil), record.Members...)})
	}
	for _, join := range joins {
		rooms = append(rooms, RoomSummary{RoomID: join.RoomID, State: string(join.State), AuthorityAgentID: join.AuthorityAgentID,
			InviteExpiresAtUnix: join.InviteExpiresAtUnix})
	}
	return Response{OK: true, Rooms: rooms}
}

func (s *Server) contactState(ctx context.Context, request Request) Response {
	if s.config.ContactStates == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("contact state is not configured"))
	}
	standing, err := s.config.ContactStates.ContactState(ctx, request.RecipientAgentID)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	switch standing.State {
	case ContactKnown, ContactStranger, ContactHeld:
	default:
		return refuse(fault.CodeInternal, errors.New("contact state is not canonical"))
	}
	return Response{OK: true, AgentID: request.RecipientAgentID, Standing: &standing}
}

// messageStatus summarizes one outbound message's copies. A copy held by
// this installation's own policy is still pending here; held is reported only
// from the recipient's signed acknowledgement.
func (s *Server) messageStatus(request Request) Response {
	copies, err := s.config.Journal.EventCopies(request.EventID)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	if len(copies) == 0 {
		return refuse(fault.CodeNotAuthentic, errors.New("no outbound message has this event"))
	}
	return Response{OK: true, Message: summarizeCopies(request.EventID, copies)}
}

func summarizeCopies(eventID string, copies []eventlog.Delivery) *MessageStatus {
	status := &MessageStatus{EventID: eventID, Copies: len(copies)}
	delivered, held, carried := 0, 0, 0
	for _, copy := range copies {
		switch copy.State {
		case eventlog.StateAbandoned:
			status.State, status.Code = MessageRejected, copy.LastCode
			return status
		case eventlog.StateDelivered:
			delivered++
			if copy.RecipientOutcome == eventlog.RecipientHeld {
				held++
			}
		case eventlog.StateCarried:
			carried++
		}
	}
	switch {
	case delivered == len(copies) && held > 0:
		status.State = MessageHeld
	case delivered == len(copies):
		status.State = MessageDelivered
	case carried > 0 || delivered > 0:
		status.State = MessageCarried
	default:
		status.State = MessagePending
	}
	return status
}

// listConversations returns one page of direct conversations, newest first.
func (s *Server) listConversations(request Request, now time.Time) Response {
	limit := request.Limit
	if limit == 0 {
		limit = MaxConversationsPerPage
	}
	local := s.config.Dispatcher.LocalIdentity().AgentID
	records, err := s.config.Journal.ListDirectConversations(local, request.BeforeCreatedAtUnix,
		request.BeforeConversationID, limit)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	unread, err := s.unreadByConversation(now)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	conversations := make([]ConversationSummary, 0, len(records))
	for _, record := range records {
		conversations = append(conversations, ConversationSummary{ConversationID: record.ConversationID,
			RemoteAgentID: record.RemoteAgentID, CreatedAtUnix: record.CreatedAtUnix, UpdatedAtUnix: record.UpdatedAtUnix,
			Unread: unread[record.ConversationID]})
	}
	return Response{OK: true, Conversations: conversations}
}

// unreadByConversation counts, per conversation, the pending inbound events
// the runtime is offered: the inbox.pending view, without its page bound.
func (s *Server) unreadByConversation(now time.Time) (map[string]int, error) {
	records, err := s.config.Journal.ListPending(now, 0)
	if err != nil {
		return nil, err
	}
	unread := map[string]int{}
	for _, record := range records {
		event, err := pendingEvent(record)
		if err != nil {
			continue
		}
		decoded, err := envelope.DecodeEventJSON(event.Event)
		if err != nil || daemonApplicationKind(decoded.Kind) {
			continue
		}
		unread[event.ConversationID]++
	}
	return unread, nil
}

// roomGaps reads one room's gap records, newest first.
func (s *Server) roomGaps(request Request) Response {
	gaps, err := s.config.Journal.RoomGaps(request.RoomID, request.Limit)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	listed := make([]RoomGap, 0, len(gaps))
	for _, gap := range gaps {
		listed = append(listed, RoomGap{GapID: gap.ID, SenderAgentID: gap.SenderAgentID, FirstSequence: gap.FirstSequence,
			LastSequence: gap.LastSequence, Reason: string(gap.Reason), Dropped: gap.Dropped, DeclaredAtUnix: gap.DeclaredAtUnix})
	}
	return Response{OK: true, RoomID: request.RoomID, RoomGaps: listed}
}

// faultCodeOr returns the fault code an error carries, or fallback.
func faultCodeOr(err error, fallback fault.Code) fault.Code {
	if value, ok := fault.Of(err); ok {
		return value.Code
	}
	return fallback
}

func (s *Server) composeProtocolResult(request Request) Response {
	event, fresh, err := s.config.Dispatcher.ComposeProtocolResultAndQueue(dispatch.ProtocolResultRequest{
		ConversationID: request.ConversationID, ReplyToEventID: request.ReplyToEventID,
		Kind: request.ProtocolKind, Protocol: request.Protocol, Version: request.ProtocolVersion,
		Body: request.ProtocolBody, IdempotencyKey: request.IdempotencyKey,
		SessionID: request.SessionID, RecipientEndpointID: request.RecipientEndpointID,
		ExpiresAtUnix: request.ExpiresAtUnix,
	})
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, Fresh: fresh, EventID: event.EventID}
}

func (s *Server) exportDeviceHistory(request Request) Response {
	found := false
	for _, deviceID := range s.config.DeviceIDs {
		found = found || deviceID == request.TargetDeviceID
	}
	if !found || request.TargetDeviceID == s.config.Dispatcher.LocalIdentity().DeviceID {
		return refuse(fault.CodeDeviceRevoked, errors.New("history target is not another current device"))
	}
	event, segment, fresh, err := s.config.Dispatcher.ComposeHistoryAndQueue(dispatch.HistoryRequest{
		TargetDeviceID: request.TargetDeviceID, ConversationID: request.ConversationID,
		Sequence: request.HistorySequence, PreviousSegmentDigest: request.PreviousSegmentDigest,
		AfterCreatedAtUnix: request.AfterCreatedAtUnix, AfterEventID: request.AfterEventID,
		Limit: request.Limit, IdempotencyKey: request.IdempotencyKey, ExpiresAtUnix: request.ExpiresAtUnix,
	})
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	last, err := envelope.DecodeEventJSON(segment.Events[len(segment.Events)-1])
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, Fresh: fresh, EventID: event.EventID,
		HistorySegmentDigest: canon.Digest(event.Content), LastEventCreatedAt: last.CreatedAtUnix, LastEventID: last.EventID}
}

func (s *Server) listDeviceHistory(request Request) Response {
	limit := request.Limit
	if limit == 0 {
		limit = MaxHistoryEventsPerResponse
	}
	events, err := s.config.Journal.History(request.ConversationID, limit)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	history := make([]json.RawMessage, 0, len(events))
	for _, event := range events {
		encoded, err := envelope.EncodeEventJSON(event)
		if err != nil {
			return refuse(fault.CodeInternal, err)
		}
		history = append(history, encoded)
	}
	return Response{OK: true, History: history}
}

// awaitingAdmission lists what the owner has yet to decide about.
func (s *Server) awaitingAdmission(request Request, now time.Time) Response {
	limit := request.Limit
	if limit == 0 || limit > MaxEventsPerResponse {
		limit = MaxEventsPerResponse
	}
	records, err := s.config.Journal.ListAwaitingAdmission(now, limit)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	events := make([]PendingEvent, 0, len(records))
	for _, record := range records {
		event, err := pendingEvent(record)
		if err != nil {
			continue
		}
		events = append(events, event)
	}
	return Response{OK: true, Events: events}
}

// admit is the owner letting an inbound event reach the runtime.
func (s *Server) admit(request Request, now time.Time) Response {
	if _, err := s.config.Journal.AdmitEvent(request.EventID, now); err != nil {
		return refuse(claimCode(err), err)
	}
	return Response{OK: true}
}

// refuseEvent is the owner refusing one. It is never offered to a runtime.
func (s *Server) refuseEvent(request Request, now time.Time) Response {
	code := request.Code
	if code == "" {
		code = fault.CodeRejected
	}
	if _, err := s.config.Journal.DenyEvent(request.EventID, code, now); err != nil {
		return refuse(claimCode(err), err)
	}
	return Response{OK: true}
}

// approve is the owner releasing a held outbound delivery.
//
// This operation exists on this socket and nowhere else. The matching event
// kinds are refused on every network route, so a remote party cannot reach
// this decision by sending a message, however well signed.
func (s *Server) approve(request Request, now time.Time) Response {
	if _, err := s.config.Journal.Resume(request.EventID, now); err != nil {
		return refuse(claimCode(err), err)
	}
	return Response{OK: true}
}

func (s *Server) deny(request Request, now time.Time) Response {
	if _, err := s.config.Journal.Abandon(request.EventID, now); err != nil {
		return refuse(claimCode(err), err)
	}
	return Response{OK: true}
}

func pendingEvent(record eventlog.Record) (PendingEvent, error) {
	payload, err := record.Payload()
	if err != nil {
		return PendingEvent{}, err
	}
	if !json.Valid(payload) {
		return PendingEvent{}, errors.New("stored event is not a document")
	}
	return PendingEvent{
		EventID:          record.EventID,
		SenderEndpointID: record.SenderEndpointID,
		ConversationID:   record.ConversationID,
		ReceivedAtUnix:   record.ReceivedAtUnix,
		Event:            json.RawMessage(payload),
	}, nil
}

// claimCode maps the journal's own outcomes onto the shared vocabulary, so a
// runtime distinguishes "somebody else holds this" from "this never existed".
func claimCode(err error) fault.Code {
	switch {
	case errors.Is(err, eventlog.ErrUnknown):
		return fault.CodeUnknownEventKind
	case errors.Is(err, eventlog.ErrLeaseMismatch), errors.Is(err, eventlog.ErrNotPending),
		errors.Is(err, eventlog.ErrNotAdmitted):
		return fault.CodeReplayed
	case errors.Is(err, eventlog.ErrApplicationKind):
		return fault.CodeClassNotDelegated
	default:
		return fault.CodeInternal
	}
}

func refuse(code fault.Code, err error) Response {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	// Detail is local. This socket has one caller and it is the owner's own
	// runtime, so the reason is useful here in a way it never is to a peer.
	return Response{OK: false, Code: code, Detail: detail}
}

// requestAction puts one proposed action to the firewall.
//
// The identifier is derived from the action, never taken from the request. A
// runtime that could name an identifier without presenting the action could
// have a harmless one approved and perform a different one under the same
// permission.
func (s *Server) requestAction(request Request, now time.Time) Response {
	action, err := toAction(*request.Action)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	decision, err := firewall.Evaluate(s.config.Policy, action)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	if decision.Outcome == firewall.Refuse {
		// A refusal is a result, not a local failure.
		return Response{Schema: ResponseSchema, OK: true, Decision: string(decision.Outcome),
			Detail: decision.Reason}
	}
	actionID, err := firewall.ActionID(action)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	if decision.Outcome == firewall.Allow {
		// An allowed tool call is authorised once, not indefinitely. The grant
		// is recorded the way an owner's would be and consumed by ClaimAction,
		// so one decision -- human or policy -- backs one execution. Tool calls
		// use the runtime's explicit idempotency key to tell a retry from a
		// second invocation. Weaker effects remain inline: a repeated reply is
		// a nuisance, while a repeated external invocation is an uncontrolled
		// side effect.
		if action.Effect == firewall.EffectToolCall || action.Effect == firewall.EffectPhysicalIO {
			bound, _, err := s.config.Journal.ClaimToolExecution(action.IdempotencyKey, actionID, now)
			if err != nil {
				return refuse(fault.CodeInternal, err)
			}
			if bound != actionID {
				return Response{Schema: ResponseSchema, OK: true, ActionID: actionID,
					Decision: string(firewall.Refuse), Detail: "this tool invocation key is already bound to another action"}
			}
			approval, err := s.config.Journal.RecordAutoAuthorization(eventlog.ApprovalRequest{
				ActionID: actionID, Effect: string(action.Effect), Summary: action.Summary,
				IdempotencyKey: action.IdempotencyKey,
				Reason:         "allowed by policy", Origins: toApprovalOrigins(decision.Provenance),
				AskedAt: uint64(now.Unix()),
			})
			if err != nil {
				return refuse(fault.CodeInternal, err)
			}
			return Response{Schema: ResponseSchema, OK: true, ActionID: actionID,
				Decision: string(decision.Outcome), Detail: decision.Reason,
				State: string(approval.State)}
		}
		return Response{Schema: ResponseSchema, OK: true, ActionID: actionID,
			Decision: string(decision.Outcome), Detail: decision.Reason, Authorised: true}
	}
	// The decision requires an owner.
	if action.Effect == firewall.EffectToolCall || action.Effect == firewall.EffectPhysicalIO {
		bound, _, err := s.config.Journal.ClaimToolExecution(action.IdempotencyKey, actionID, now)
		if err != nil {
			return refuse(fault.CodeInternal, err)
		}
		if bound != actionID {
			return Response{Schema: ResponseSchema, OK: true, ActionID: actionID,
				Decision: string(firewall.Refuse), Detail: "this tool invocation key is already bound to another action"}
		}
	}
	approval, err := s.config.Journal.RequestApproval(eventlog.ApprovalRequest{
		ActionID: actionID, Effect: string(action.Effect), Summary: action.Summary,
		IdempotencyKey: action.IdempotencyKey,
		Reason:         decision.Reason, Origins: toApprovalOrigins(decision.Provenance),
		Physical: toApprovalPhysical(action.Physical), AskedAt: uint64(now.Unix()),
	})
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{Schema: ResponseSchema, OK: true, ActionID: actionID,
		Decision: string(decision.Outcome), Detail: decision.Reason,
		State: string(approval.State)}
}

// actionStatus reads where a request has got to. It changes nothing, so a
// runtime may poll it without consuming anything.
func (s *Server) actionStatus(request Request) Response {
	approval, found, err := s.config.Journal.LookupApproval(request.ActionID)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	if !found {
		return Response{Schema: ResponseSchema, OK: true, ActionID: request.ActionID,
			Detail: "no decision was ever asked for about this action"}
	}
	return Response{Schema: ResponseSchema, OK: true, ActionID: request.ActionID,
		State: string(approval.State), Detail: approval.DenialReason}
}

// claimAction consumes a granted authorisation, once.
//
// The state change is durable before the runtime is told it may proceed, so a
// crash between the two loses the permission rather than reusing it. Losing a
// permission costs the owner one more decision; reusing one spends their
// authority on something they never saw.
func (s *Server) claimAction(request Request, now time.Time) Response {
	approval, err := s.config.Journal.SpendApproval(request.ActionID, now)
	if err != nil {
		if errors.Is(err, eventlog.ErrApprovalNotGranted) || errors.Is(err, eventlog.ErrApprovalUnknown) {
			return Response{Schema: ResponseSchema, OK: true, ActionID: request.ActionID,
				Authorised: false, Detail: err.Error()}
		}
		return refuse(fault.CodeInternal, err)
	}
	return Response{Schema: ResponseSchema, OK: true, ActionID: request.ActionID,
		State: string(approval.State), Authorised: true}
}

func (s *Server) pendingActions(request Request, now time.Time) Response {
	waiting, err := s.config.Journal.ListPendingApprovals(now, request.Limit)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	actions := make([]WaitingAction, 0, len(waiting))
	for _, approval := range waiting {
		// The owner is never shown -- and must never sign -- an action whose
		// stored structured fields do not reproduce its identifier. A mismatch
		// means the summary and the identifier disagree about what is being
		// approved, which is exactly the substitution this record exists to
		// prevent, so it is surfaced as a fault rather than presented.
		if !approvalReproducesID(approval) {
			return refuse(fault.CodeInternal,
				errors.New("a pending approval's stored action does not reproduce its identifier"))
		}
		actions = append(actions, WaitingAction{
			ActionID: approval.ActionID, Effect: approval.Effect, Summary: approval.Summary,
			IdempotencyKey: approval.IdempotencyKey,
			Reason:         approval.Reason, Origins: fromApprovalOrigins(approval.Origins),
			Physical: fromApprovalPhysical(approval.Physical), AskedAtUnix: approval.AskedAtUnix,
		})
	}
	return Response{Schema: ResponseSchema, OK: true, Actions: actions}
}

func (s *Server) grantAction(request Request, now time.Time) Response {
	approval, err := s.config.Journal.GrantAction(request.ActionID, now)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{Schema: ResponseSchema, OK: true, ActionID: request.ActionID,
		State: string(approval.State)}
}

func (s *Server) denyAction(request Request, now time.Time) Response {
	approval, err := s.config.Journal.DenyAction(request.ActionID, request.Reason, now)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{Schema: ResponseSchema, OK: true, ActionID: request.ActionID,
		State: string(approval.State)}
}

func toAction(proposed ProposedAction) (firewall.Action, error) {
	origins := make([]firewall.Origin, 0, len(proposed.Derived))
	for _, origin := range proposed.Derived {
		origins = append(origins, firewall.Origin{
			AgentID: origin.AgentID, EndpointID: origin.EndpointID, DeviceID: origin.DeviceID,
			EventID: origin.EventID, ConversationID: origin.ConversationID,
			Kind: origin.Kind, ReceivedAtUnix: origin.ReceivedAtUnix,
		})
	}
	action := firewall.Action{
		Effect: firewall.Effect(proposed.Effect), Summary: proposed.Summary,
		IdempotencyKey: proposed.IdempotencyKey,
		DerivedFrom:    origins, Physical: toPhysical(proposed.Physical),
	}
	return action, nil
}

func toPhysical(operation *PhysicalOperation) *firewall.PhysicalOperation {
	if operation == nil {
		return nil
	}
	return &firewall.PhysicalOperation{CapabilityID: operation.CapabilityID, Tool: operation.Tool,
		Operation: operation.Operation, ArgumentsDigest: operation.ArgumentsDigest, ArgumentsJSON: operation.ArgumentsJSON}
}

func toApprovalPhysical(operation *firewall.PhysicalOperation) *eventlog.ApprovalPhysicalOperation {
	if operation == nil {
		return nil
	}
	return &eventlog.ApprovalPhysicalOperation{CapabilityID: operation.CapabilityID, Tool: operation.Tool,
		Operation: operation.Operation, ArgumentsDigest: operation.ArgumentsDigest, ArgumentsJSON: operation.ArgumentsJSON}
}

func fromApprovalPhysical(operation *eventlog.ApprovalPhysicalOperation) *PhysicalOperation {
	if operation == nil {
		return nil
	}
	return &PhysicalOperation{CapabilityID: operation.CapabilityID, Tool: operation.Tool,
		Operation: operation.Operation, ArgumentsDigest: operation.ArgumentsDigest, ArgumentsJSON: operation.ArgumentsJSON}
}

func toApprovalOrigins(origins []firewall.Origin) []eventlog.ApprovalOrigin {
	stored := make([]eventlog.ApprovalOrigin, 0, len(origins))
	for _, origin := range origins {
		stored = append(stored, eventlog.ApprovalOrigin{
			AgentID: origin.AgentID, EndpointID: origin.EndpointID, DeviceID: origin.DeviceID,
			EventID: origin.EventID, ConversationID: origin.ConversationID, Kind: origin.Kind,
			ReceivedAtUnix: origin.ReceivedAtUnix,
		})
	}
	return stored
}

func fromApprovalOrigins(origins []eventlog.ApprovalOrigin) []ActionOrigin {
	shown := make([]ActionOrigin, 0, len(origins))
	for _, origin := range origins {
		shown = append(shown, ActionOrigin{
			AgentID: origin.AgentID, EndpointID: origin.EndpointID, DeviceID: origin.DeviceID,
			EventID: origin.EventID, ConversationID: origin.ConversationID, Kind: origin.Kind,
			ReceivedAtUnix: origin.ReceivedAtUnix,
		})
	}
	return shown
}

// firewallOrigins reconstructs the provenance in the form the action identifier
// is derived from, so a stored approval can be re-identified from what it holds.
func firewallOrigins(origins []eventlog.ApprovalOrigin) []firewall.Origin {
	rebuilt := make([]firewall.Origin, 0, len(origins))
	for _, origin := range origins {
		rebuilt = append(rebuilt, firewall.Origin{
			AgentID: origin.AgentID, EndpointID: origin.EndpointID, DeviceID: origin.DeviceID,
			EventID: origin.EventID, ConversationID: origin.ConversationID, Kind: origin.Kind,
			ReceivedAtUnix: origin.ReceivedAtUnix,
		})
	}
	return rebuilt
}

// approvalReproducesID recomputes the action identifier from the structured
// fields a stored approval holds and reports whether it matches the identifier
// on record. It is the daemon's own check that what the owner is shown -- and
// what a signature would commit to -- is the action the identifier names, not a
// gentler description substituted for a harsher one.
func approvalReproducesID(approval eventlog.Approval) bool {
	action := firewall.Action{
		Effect:         firewall.Effect(approval.Effect),
		Summary:        approval.Summary,
		IdempotencyKey: approval.IdempotencyKey,
		DerivedFrom:    firewallOrigins(approval.Origins),
		Physical:       toPhysical(fromApprovalPhysical(approval.Physical)),
	}
	recomputed, err := firewall.ActionID(action)
	if err != nil {
		return false
	}
	return recomputed == approval.ActionID
}
