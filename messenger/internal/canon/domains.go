package canon

// Domain separators for every signed or digest-committed object.
//
// They live in one list because a reused separator is not a merge conflict, it
// is a signature-confusion defect: two object kinds that share a namespace can
// produce the same preimage, and a signature over one becomes a valid
// signature over the other. Each package is internally consistent when that
// happens, so nothing else catches it. The uniqueness test beside this file
// does.
//
// Adding an object means adding a separator here first.
const (
	// DomainEndpointDelegation namespaces a Messaging Endpoint delegation.
	DomainEndpointDelegation = "tos.messaging.endpoint-delegation.v2\x00"
	// DomainEndpointID namespaces the endpoint identifier derivation.
	DomainEndpointID = "tos.messaging.endpoint-id.v2\x00"
	// DomainOwnerDecision namespaces what an owner signs to authorise one
	// decision on their own interface. v2 dropped the mandate fields from the
	// preimage.
	DomainOwnerDecision = "tos.messaging.owner-decision.v2\x00"
	// DomainAgentAction namespaces the content-addressed identifier of an
	// action an Agent proposes to take.
	DomainAgentAction = "tos.messaging.agent-action.v1\x00"
	// DomainPayload prefixes every typed event body. The body's own schema
	// follows it, so bytes that parse under one schema cannot be replayed as
	// another.
	DomainPayload = "tos.messaging.payload.v1\x00"
	// DomainInboxPolicy namespaces the published identity of an inbox
	// admission policy.
	DomainInboxPolicy = "tos.messaging.inbox-policy.v1\x00"
	// DomainAdmissionInvite namespaces the private digest of a random one-time
	// inbox invitation. The bearer itself is never persisted.
	DomainAdmissionInvite = "tos.messaging.admission-invite.v1\x00"
	// DomainDescriptorPolicy namespaces what an Agent commits its endpoint may
	// advertise.
	DomainDescriptorPolicy = "tos.messaging.descriptor-policy.v1\x00"
	// DomainRelaySet namespaces a published Mailbox Relay set.
	DomainRelaySet = "tos.messaging.relay-set.v1\x00"
	// DomainContactDescriptor namespaces a Messaging Contact Descriptor.
	DomainContactDescriptor = "tos.messaging.contact-descriptor.v2\x00"
	// DomainDHTLocator namespaces a published DHT locator.
	DomainDHTLocator = "tos.messaging.dht-locator.v1\x00"
	// DomainEventID namespaces the content-addressed Event identifier.
	DomainEventID = "tos.messaging.event-id.v2\x00"
	// DomainPrekeyBundle namespaces one published prekey bundle.
	DomainPrekeyBundle = "tos.messaging.prekey-bundle.v2\x00"
	// DomainPrekeyBundleSet namespaces a published device set.
	DomainPrekeyBundleSet = "tos.messaging.prekey-bundle-set.v2\x00"
	// DomainDeviceSession namespaces the session identifier a device pair
	// derives without negotiating.
	DomainDeviceSession = "tos.messaging.device-session.v1\x00"
	// DomainE2EEBinding namespaces the associated data of a ciphertext.
	DomainE2EEBinding = "tos.messaging.e2ee-binding.v2\x00"
	// DomainReachabilityTrial namespaces one measured trial record. v4 folds in
	// bounded sized-echo and segmented RLDP recovery results, so transport
	// evidence cannot be added, removed, reordered, or changed after signing.
	// It also retains the collector-manifest digests of both endpoints and the
	// phase-status booleans: a sidecar at the same orchestrator commit remains a
	// distinct implementation, and a failed phase cannot become unattempted.
	DomainReachabilityTrial = "tos.messaging.reachability-trial.v4\x00"
	// DomainReachabilityCollectorManifest namespaces the content-addressed
	// description of one collector build: orchestrator, ADNL implementation,
	// dependency version, binary hash, target, toolchain, and wire profile. The
	// digest over it is what a trial commits and what the two halves of a pair
	// cross-check about each other.
	DomainReachabilityCollectorManifest = "tos.messaging.reachability-collector-manifest.v1\x00"
	// DomainReachabilityPolicy namespaces a predeclared acceptance policy. v4
	// additionally folds in segmented RLDP and same-transfer recovery gates.
	DomainReachabilityPolicy = "tos.messaging.reachability-policy.v4\x00"
	// DomainReachabilityRLDPPayload derives deterministic, independently
	// reproducible bytes for the RLDP measurement response.
	DomainReachabilityRLDPPayload = "tos.messaging.reachability-rldp-payload.v1\x00"
	// DomainReachabilityOperator namespaces the opaque operator derivation.
	DomainReachabilityOperator = "tos.messaging.reachability-operator.v1\x00"
	// DomainReachabilitySite namespaces the opaque site derivation.
	DomainReachabilitySite = "tos.messaging.reachability-site.v1\x00"
	// DomainReachabilityPairID namespaces the pair identifier derived from a
	// session. It is separate from the digest over a completed pair because
	// one domain must carry one meaning: reusing a separator across two object
	// kinds is signature confusion waiting for the field widths to change.
	DomainReachabilityPairID = "tos.messaging.reachability-pair-id.v1\x00"
	// DomainReachabilityPairResult namespaces the digest over the two halves
	// of one completed measurement.
	DomainReachabilityPairResult = "tos.messaging.reachability-pair-result.v1\x00"
	// DomainReachabilityCoordinator namespaces the coordinator identifier.
	DomainReachabilityCoordinator = "tos.messaging.reachability-coordinator.v1\x00"
	// DomainReachabilityObservation namespaces a coordinator attestation.
	DomainReachabilityObservation = "tos.messaging.reachability-observation.v1\x00"
	// DomainRoomMembership namespaces the digest a room commits over the members
	// of one epoch. The epoch is inside the preimage, so two epochs with the
	// same member set commit different digests and cannot be mistaken for each
	// other.
	DomainRoomMembership = "tos.messaging.room-membership.v1\x00"
	// DomainRoomAuthorityTransfer namespaces the current authority Endpoint's
	// signature over one single-step room-authority transition.
	DomainRoomAuthorityTransfer = "tos.messaging.room-authority-transfer.v1\x00"
	// DomainRoomMembershipAuthorization namespaces the current authority's
	// signature over one founding or successor membership.
	DomainRoomMembershipAuthorization = "tos.messaging.room-membership-authorization.v1\x00"
	// DomainRoomRolePolicy namespaces the current room authority's bounded
	// assignment of elevated administrator and moderator powers.
	DomainRoomRolePolicy = "tos.messaging.room-role-policy.v1\x00"
	// DomainPublicChannelID namespaces a route-neutral public channel identity.
	DomainPublicChannelID = "tos.messaging.public-channel-id.v1\x00"
	// DomainPublicChannelProfile namespaces the authority-signed publisher and
	// moderator roster for one public-channel epoch.
	DomainPublicChannelProfile = "tos.messaging.public-channel-profile.v1\x00"
	// DomainPublicChannelEvent namespaces one publisher-signed public event.
	DomainPublicChannelEvent = "tos.messaging.public-channel-event.v1\x00"
	// DomainPublicChannelHistory namespaces a convergent complete event-set
	// commitment; transport arrival order is deliberately absent.
	DomainPublicChannelHistory = "tos.messaging.public-channel-history.v1\x00"
	// DomainStoredAck namespaces a Relay's durable-storage acknowledgement.
	// It is deliberately distinct from delivery and application ACK payloads:
	// a Relay storing ciphertext proves neither recipient nor runtime action.
	DomainStoredAck = "tos.messaging.stored-ack.v1\x00"
	// DomainConformanceReport namespaces an implementation's signed claim that
	// it consumed the committed positive and adversarial vector artifacts.
	DomainConformanceReport = "tos.messaging.conformance-report.v1\x00"
	// DomainMLSDeviceCredential namespaces the endpoint signature authorising
	// one device's distinct MLS leaf key and exact KeyPackage. v2 encodes both
	// genesis hashes as raw 32-byte values rather than display hex.
	DomainMLSDeviceCredential = "tos.messaging.mls-device-credential.v2\x00"
	// DomainMLSLeafCredential namespaces the Endpoint-signed leaf credential
	// a relay room leaf's 128-byte compact identity names by digest.
	DomainMLSLeafCredential = "tos.messaging.mls-leaf-credential.v1\x00"
	// DomainMLSGroupID namespaces the network-bound MLS group identifier.
	DomainMLSGroupID = "tos.messaging.mls-group-id.v1\x00"
	// DomainAttachmentMetadata commits plaintext metadata kept inside E2EE.
	DomainAttachmentMetadata = "tos.messaging.attachment-metadata.v1\x00"
	// DomainAttachmentChunk binds every AEAD chunk to its position and shape.
	DomainAttachmentChunk = "tos.messaging.attachment-chunk.v1\x00"
	// DomainAttachmentManifest identifies the ordered ciphertext chunk set.
	DomainAttachmentManifest = "tos.messaging.attachment-manifest.v1\x00"
	// DomainAttachmentCapabilityGrant namespaces an Endpoint-signed capability
	// key and its exact storage identity, manifest, operation and retention scope.
	DomainAttachmentCapabilityGrant = "tos.messaging.attachment-capability-grant.v1\x00"
	// DomainAttachmentAccessRequest namespaces one capability-signed operation.
	DomainAttachmentAccessRequest = "tos.messaging.attachment-access-request.v1\x00"
	// DomainAttachmentOperationBody namespaces the exact body an access request
	// authorizes; upload, fetch and deletion can never share a signature.
	DomainAttachmentOperationBody = "tos.messaging.attachment-operation-body.v1\x00"
	// DomainAttachmentAccessClaim namespaces the durable grant+nonce replay key.
	DomainAttachmentAccessClaim = "tos.messaging.attachment-access-claim.v1\x00"
	// DomainAttachmentStoredAck namespaces a storage operator's durable lease
	// acknowledgement. It is not a TOS commercial Receipt.
	DomainAttachmentStoredAck = "tos.messaging.attachment-stored-ack.v1\x00"
	// DomainAttachmentDeleteAck namespaces a storage operator's observation that
	// its local lease was removed. It cannot prove destruction of other copies.
	DomainAttachmentDeleteAck = "tos.messaging.attachment-delete-ack.v1\x00"
	// DomainAgentPacketClaim namespaces a durable sender+nonce replay claim.
	DomainAgentPacketClaim = "tos.messaging.agent-packet-claim.v1\x00"
	// DomainMailboxCapabilityGrant namespaces one Endpoint-signed capability
	// key and its exact Relay, mailbox, operation and lifetime scope.
	DomainMailboxCapabilityGrant = "tos.messaging.mailbox-capability-grant.v1\x00"
	// DomainMailboxAccessRequest namespaces one capability-signed operation.
	DomainMailboxAccessRequest = "tos.messaging.mailbox-access-request.v1\x00"
	// DomainMailboxOperationBody namespaces the body digest a request signs.
	DomainMailboxOperationBody = "tos.messaging.mailbox-operation-body.v1\x00"
	// DomainMailboxAccessClaim namespaces the durable grant+nonce replay key.
	DomainMailboxAccessClaim = "tos.messaging.mailbox-access-claim.v1\x00"
	// DomainLabToken namespaces the hash of a local acceptance credential. It
	// is not a production authentication profile.
	DomainLabToken = "tos.messaging.lab.token.v1\x00"
	// DomainLabRoom namespaces a deterministic local acceptance room.
	DomainLabRoom = "tos.messaging.lab.room.v1\x00"
	// DomainLabMessage namespaces a local acceptance message identifier.
	DomainLabMessage = "tos.messaging.lab.message.v1\x00"
	// DomainOpenFoxMLSAAD binds a local encrypted acceptance message to the
	// exact room, authenticated sender, and retry-stable client identifier.
	DomainOpenFoxMLSAAD = "tos.messaging.openfox-mls-message-aad.v1\x00"
	// DomainOutboundIntent binds a runtime's semantic message and fixed route
	// independently of the daemon-owned creation time and Event ID.
	DomainOutboundIntent = "tos.messaging.outbound-intent.v1\x00"
	// DomainDeliveryCopy derives one durable target copy from a logical Event
	// and daemon-verified recipient Endpoint/Device pair.
	DomainDeliveryCopy = "tos.messaging.delivery-copy.v1\x00"
	// DomainHTTPSDeliveryAck authenticates a recipient Endpoint's durable
	// acceptance of one encrypted device copy.
	DomainHTTPSDeliveryAck = "tos.messaging.https-delivery-ack.v1\x00"
	// DomainRelayFrame prefixes one padded relay carriage frame, version 2:
	// the version with the contact credential field. No other version decodes.
	DomainRelayFrame = "tos.messaging.relay-frame.v2\x00"
	// DomainRelayObject derives the digest of the object a relay frame
	// carries, so the parts of one object share one commitment.
	DomainRelayObject = "tos.messaging.relay-object.v1\x00"
	// DomainRelayEvidence prefixes the locator-free relay identity evidence:
	// delegation, descriptor policy, Contact Descriptor and prekey set.
	DomainRelayEvidence = "tos.messaging.relay-evidence.v1\x00"
	// DomainRelayDelivery prefixes the binary device copy a relay frame of
	// kind 1 carries.
	DomainRelayDelivery = "tos.messaging.relay-delivery.v1\x00"
	// DomainRelayDeliveryAck authenticates a recipient Endpoint's outcome for
	// one relay-carried device copy. It is distinct from the HTTPS ack domain
	// so an ack never verifies on the other route.
	DomainRelayDeliveryAck = "tos.messaging.relay-delivery-ack.v1\x00"
	// DomainRelayIdempotency derives the carrier idempotency key of one
	// relay deposit generation.
	DomainRelayIdempotency = "tos.messaging.relay-idempotency.v1\x00"
	// DomainBuiltinAckKey derives the carrier key of the acknowledgement the
	// builtin chat lane deposits for one received packet, from its nonce.
	DomainBuiltinAckKey = "tos.messaging.builtin-ack-key.v1\x00"
	// DomainRelayRoomObject prefixes one room object a kind-3 relay frame
	// carries: a Commit, Welcome, application message or roster.
	DomainRelayRoomObject = "tos.messaging.relay-room-object.v1\x00"
	// DomainRoomAAD prefixes the MLS authenticated data of a room
	// application message, binding room, epochs, epoch authenticator, sender
	// Agent and Event.
	DomainRoomAAD = "tos.messaging.room-aad.v1\x00"
	// DomainRelayRoomAck authenticates a member Endpoint's outcome for one
	// room handshake object. It is distinct from the copy ack domain, so a
	// room ack never verifies as a copy ack.
	DomainRelayRoomAck = "tos.messaging.relay-room-ack.v1\x00"
	// DomainOutboundAttachmentIntent binds exact plaintext evidence and the
	// operator-selected route/storage policy before streaming encryption begins.
	DomainOutboundAttachmentIntent = "tos.messaging.outbound-attachment-intent.v1\x00"
	// DomainAttachmentCorpusManifest namespaces an external approver's exact
	// private hostile-corpus selection. Approval is evidence about the selected
	// bytes and scope, not a claim that the repository owns or redistributes them.
	DomainAttachmentCorpusManifest = "tos.messaging.attachment-corpus-manifest.v1\x00"
	// DomainAttachmentCorpusReport namespaces a runner's signed claim that the
	// approved corpus produced the committed results under one pinned admission
	// policy. It is deliberately distinct from the approver's signature.
	DomainAttachmentCorpusReport = "tos.messaging.attachment-corpus-report.v1\x00"
)

// Domains is every separator in use. A new object appends to it, and the
// uniqueness test refuses a duplicate.
var Domains = []string{
	DomainEndpointDelegation,
	DomainEndpointID,
	DomainDescriptorPolicy,
	DomainRelaySet,
	DomainContactDescriptor,
	DomainDHTLocator,
	DomainEventID,
	DomainPrekeyBundle,
	DomainPrekeyBundleSet,
	DomainDeviceSession,
	DomainE2EEBinding,
	DomainReachabilityTrial,
	DomainReachabilityCollectorManifest,
	DomainReachabilityPolicy,
	DomainReachabilityRLDPPayload,
	DomainReachabilityOperator,
	DomainReachabilitySite,
	DomainReachabilityPairID,
	DomainReachabilityPairResult,
	DomainReachabilityCoordinator,
	DomainReachabilityObservation,
	DomainRoomMembership,
	DomainRoomAuthorityTransfer,
	DomainRoomMembershipAuthorization,
	DomainRoomRolePolicy,
	DomainPublicChannelID,
	DomainPublicChannelProfile,
	DomainPublicChannelEvent,
	DomainPublicChannelHistory,
	DomainStoredAck,
	DomainConformanceReport,
	DomainMLSDeviceCredential,
	DomainMLSLeafCredential,
	DomainMLSGroupID,
	DomainAttachmentMetadata,
	DomainAttachmentChunk,
	DomainAttachmentManifest,
	DomainAttachmentCapabilityGrant,
	DomainAttachmentAccessRequest,
	DomainAttachmentOperationBody,
	DomainAttachmentAccessClaim,
	DomainAttachmentStoredAck,
	DomainAttachmentDeleteAck,
	DomainAgentPacketClaim,
	DomainMailboxCapabilityGrant,
	DomainMailboxAccessRequest,
	DomainMailboxOperationBody,
	DomainMailboxAccessClaim,
	DomainLabToken,
	DomainLabRoom,
	DomainLabMessage,
	DomainOpenFoxMLSAAD,
	DomainOutboundIntent,
	DomainDeliveryCopy,
	DomainHTTPSDeliveryAck,
	DomainRelayFrame,
	DomainRelayObject,
	DomainRelayEvidence,
	DomainRelayDelivery,
	DomainRelayDeliveryAck,
	DomainRelayIdempotency,
	DomainBuiltinAckKey,
	DomainRelayRoomObject,
	DomainRoomAAD,
	DomainRelayRoomAck,
	DomainOutboundAttachmentIntent,
	DomainAttachmentCorpusManifest,
	DomainAttachmentCorpusReport,
	DomainPayload,
	DomainInboxPolicy,
	DomainAdmissionInvite,
	DomainOwnerDecision,
	DomainAgentAction,
}

// RetiredDomains are separators that once committed an object this build no
// longer has. They are never reused, under any meaning: a preimage built under
// one would still verify against whatever an old peer or record signed. They
// belonged to the escrow-era negotiation, mandate and budget objects, which
// left Messenger with commerce, and to the owner-decision layout that signed
// mandate fields.
var RetiredDomains = []string{
	"tos.messaging.negotiation-record.v1\x00",
	"tos.messaging.budget.v1\x00",
	"tos.messaging.budget.v2\x00",
	"tos.messaging.budget.v3\x00",
	"tos.messaging.mandate-budget.v1\x00",
	"tos.messaging.mandate-budget.v2\x00",
	"tos.messaging.mandate-budget.v3\x00",
	"tos.messaging.negotiation-terms.v1\x00",
	"tos.messaging.negotiation-terms.v2\x00",
	"tos.messaging.negotiation-terms.v3\x00",
	"tos.messaging.mandate.v1\x00",
	"tos.messaging.mandate.v2\x00",
	"tos.messaging.mandate.v3\x00",
	"tos.messaging.economic-execution.v1\x00",
	"tos.messaging.owner-decision.v1\x00",
}
