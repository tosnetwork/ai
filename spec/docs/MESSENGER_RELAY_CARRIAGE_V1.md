# Messenger Relay Carriage V1

How private chat between two OpenFox Agents crosses machines by reusing
[Agent Packet Relay V1](AGENT_PACKET_RELAY_V1.md) ("relay spec") with no new
transport, no relay change and no new authority.

**Status: ⬜ Design only.** No code implements it. Section 8 states what each
phase's live record must prove; section 9 lists the M-R1 changes.

MUST, MUST NOT, SHOULD and MAY are normative. Citations are `path:line` in this
repository at the commit this document lands on, and `openfox path:line` in
`tosnetwork/openfox` `main` `3e26dc24`.

## 0. Context

Owner decisions taken as given: Messenger exists so OpenFox Agents can chat
privately; it lives in `messenger/`, imports only `protocol/`, and nothing in
this repository imports it (OpenFox does, openfox
`pkg/servicebridge/transport.go:47-70`). Cross-host carriage reuses the packet
relay, which has no authority: it cannot read or forge, and may drop, delay
and see metadata (`AGENT_PACKET_RELAY_V1.md:18-38`).

What exists:

- Messenger seals one copy per recipient device and hands it to a
  `dispatch.Sender` whose `nil` means "a recipient device durably accepted it"
  (`messenger/pkg/dispatch/dispatch.go:33-56`); the dispatcher then marks it
  `delivered` (`dispatch.go:811-816`). The only network sender is the
  synchronous `https-bootstrap` carrier, which needs a public port-443 listener
  at the recipient and returns an Endpoint-signed ack in the HTTP response
  (`messenger/pkg/directhttps/transport.go:169-240`). Modes are `none` and
  `https-bootstrap` (`messenger/pkg/daemon/config.go:65-68`).
- **M0-R** is the Messenger reachability study: measure whether direct ADNL, a
  tunnel or a Mailbox Relay must be primary before the M1 route order is
  frozen (`AGENT_NATIVE_MESSENGER_V1.md:1715-1724`, `:1787-1799`). Tooling
  exists; the study has not run (`messenger/docs/ROADMAP.md:26`). Messenger's
  own Mailbox Relay (`tos-mailboxd`, `AGENT_NATIVE_MESSENGER_V1.md:2093-2118`)
  has a store but no network service.
- OpenFox has a complete relay client for its paid-work rail: own keys and
  cards, verified peer cards, a sender journal keyed by idempotency key, and a
  poller (openfox `pkg/servicebridge/relay_carrier.go:15-60`,
  `relay_transport.go:262-310`, `relay_inbound.go:282-341`), live on two test
  relays (`AI_SERVICE_PROVIDER_IMPLEMENTATION_STATUS.md:370-424`).

This document fixes the route for the OpenFox chat profile by owner decision,
not by the study: in V1 the packet relay is the only cross-host route (Q1).

## 1. Layering

**Decision.** A Messenger copy crosses the relay as the payload of an ordinary
signed Agent Packet V1, sealed, journaled and deposited by OpenFox's existing
`RelayTransport`. The relay program, relay spec, seal codec and corpus are
unchanged.

| Packet field | Value |
|---|---|
| `sender_agent_id` | the local Agent (equal to the Messenger installation's Agent) |
| `recipient_agent_id` | the peer Agent |
| `capability_id` | `cap_` + 64 `0` |
| `quote_commitment` | empty |
| `payload` | one relay frame (1.1) |

The zero Capability is reserved and never finalized; with a real recipient the
packet is not a key card (`AGENT_PACKET_RELAY_V1.md:113-135`), and
`agentpacket.Verify` checks shape, sender policy and recipient but resolves no
Capability (`protocol/pkg/agentpacket/packet.go:224-280`). A derived non-zero
ID was rejected because it would look resolvable. The packet is carriage only:
conversation, room, device, encryption and delivery semantics stay in the
sealed Messenger copy, so the event model is not forced into Agent Packet,
which `AGENT_NATIVE_MESSENGER_V1.md:2004-2021` forbids.

Frames use `RelayTransport.Send`, not the rail `Courier`, which splits rail
messages into `OFR1` frames (openfox `transport.go:189-263`, `frames.go:30`).
`RelayTransport` takes any signed packet, journals the envelope before the
first deposit, and on a retry with the same idempotency key reuses the
journaled envelope even if the caller re-signed (openfox
`relay_transport.go:262-310`): relay spec 8.4 step 4 (`:370-372`) for free.

**Rejected: a separate envelope class** (a Messenger plaintext wrapper without
an Agent Packet, authenticated only by the Endpoint key). It saves one
ML-DSA-44 signature and about 5.4 KiB per frame, but changes relay spec
sections 7 and 8.5 (`:290-307`, `:395-424`), the codec and the corpus, adds a
second plaintext format every recipient must refuse correctly, and drops the
post-quantum outer sender authentication while the Messenger one-to-one suite
is classical X25519/Ed25519 (`messenger/docs/E2EE_SUITE_DECISION.md:13-30`).
The accepted cost is one `tosctl` signature per frame; vault contention has
already delayed signatures (`AI_SERVICE_PROVIDER_IMPLEMENTATION_STATUS.md:304-307`),
so M-R1 measures it.

**No loop.** A node using this carriage MUST NOT also send rail packets through
`MessengerTransport` (openfox `transport.go:47-70`); a packet in a copy in a
packet buys nothing and halves every bound.

### 1.1 Frame

```text
relay_frame =
  D("tos.messaging.relay-frame.v1")   29 bytes
  frame_kind      u8    1 = copy, 2 = delivery-ack, 3 = room (M-R2)
  part_index      u8    0 .. part_count-1
  part_count      u8    1 .. 8; kinds 1 and 2 require 1
  object_digest   32    SHA-256(D("tos.messaging.relay-object.v1") || object)
  card_length     u16   0, or 1 .. 9,216
  card            exact key-card packet JSON (2.3)
  part_length     u32
  part            this part of the object
  padding         zero bytes up to the frame's size bucket (6)
```

`D(x)` and big-endian integers as in relay spec section 4. Decoders reject
unknown kinds, non-zero padding, a total that is not a bucket size, and
trailing bytes. A frame is at most **190,464 bytes**: base64 makes it 253,952,
plus 5,424 bytes of fixed packet fields (hex ML-DSA-44 signature, IDs, key ID)
gives 259,376, under the 260,771-byte packet bound
(`protocol/pkg/agentpacketseal/seal.go:64-74`).

A kind-1 object is the canonical length-prefixed encoding of exactly the
`dispatch.Message` fields (`dispatch.go:34-46`), schema
`tos.messaging.relay-delivery.v1`; binary rather than the HTTPS JSON
(`directhttps/transport.go:41-53`) so the ciphertext is not base64-encoded
twice. A kind-2 object is the ack of 5.2.

## 2. Addressing and keys

### 2.1 Addressing

A chat peer is addressed by Agent ID, which is also the relay mailbox key
(relay spec 9.2). It resolves to (a) the Messaging Endpoint delegation whose
digest the finalized Agent commits (`messenger/pkg/identity/delegation.go:256-310`),
with locator, descriptor and signed prekey set verified by the existing
refresh chain (`messenger/pkg/directory/refresh.go:16-22`); and (b) the peer's
**chat key card**, verified with `VerifyKeyCard` (`AGENT_PACKET_RELAY_V1.md:129-139`),
whose Agent MUST equal the delegation's Agent.

### 2.2 Keys and purposes

No key serves two purposes and none is derived from another:

| Key | Holder | Only purpose |
|---|---|---|
| ML-DSA-44 packet controller (finalized policy) | `tosctl` vault, used by OpenFox | signing Agent Packets and key cards |
| Relay rail key (X-Wing, card A) | OpenFox `relay/keys` | opening rail envelopes |
| **Relay chat key** (X-Wing, card B, new) | OpenFox `relay/chat-keys` | opening chat envelopes |
| Messaging Endpoint Ed25519 | external Endpoint signer | descriptors, prekeys, delivery acks |
| X3DH / Double Ratchet keys | Messenger journal | one-to-one content |
| MLS leaf and epoch secrets | Messenger MLS ledger | room content (M-R2) |
| Attachment AES keys | inside the E2EE Reference | attachment chunks (M-R3) |

The controller signs rail and chat packets under the one Agent Packet context;
the payload domain (`OFR1` or the frame domain) separates them under the
signature. As the relay spec recommends (`:197-204`), the chat card SHOULD be
signed by a dedicated card-signing controller.

**Purpose is enforced at the key.** An envelope that opens under the chat key
MUST carry a relay frame, and one under the rail key an `OFR1` frame; anything
else is refused permanently and relay-acknowledged (`:417-422`). A sender
tricked into sealing to the wrong card loses only availability.

### 2.3 Card distribution

Cards travel only inside objects the counterparty verifies (`:267-270`):

- **First contact: a contact file** (section 9), an unsigned container the two
  operators exchange out of band with the five Messenger discovery objects and
  the chat card. Everything in it is verified on import; it is rendezvous, not
  authority, like the bootstrap files of
  `messenger/docs/DISCOVERY_BOOTSTRAP.md:10-26`. Its card SHOULD last the
  30-day maximum and be republished under 15 days, like the offer card
  (`AGENT_PACKET_RELAY_V1.md:256-266`).
- **In band.** A frame carries the sender's current chat card until the peer
  has acknowledged a frame that carried it. The receiver takes it only from a
  verified packet whose sender is the card's Agent, after `VerifyKeyCard`; a
  failing card is ignored and does not invalidate the frame (as `:216-228`).
  A card packet is at most 9,216 bytes (a 2,346-byte body, `:170`, in base64
  plus packet fields).

Chat and rail cards live in separate peer-card stores and are never learned
from the other's objects: `PeerCards` keeps the newest card per Agent
(openfox `relay_cards.go:509-553`), so one store would mix purposes.
**Rejected: a card field in the Contact Descriptor**, which would change a
signed, vector-frozen object under M0 freeze review
(`messenger/docs/ROADMAP.md:25`) to carry something self-authenticating.

### 2.4 Identity binding

Two independent finalized-state checks must name the same Agent: the packet
signature by a controller of `sender_agent_id` (`packet.go:247-265`), and the
Messenger session whose peer comes from a delegation that Agent commits
(`delegation.go:296-306`, `messenger/pkg/daemon/inbound.go:120-191`). After
opening, the daemon MUST require the packet sender (passed with the frame) to
equal the authenticated Event sender Agent, the rule `agentpacketbridge`
applies in the other direction (`messenger/docs/AGENT_PACKET_BRIDGE.md:7-9`);
a mismatch is refused permanently. OpenFox and the Messenger installation MUST
be the same Agent, checked at startup.

V1 carries **one Messenger device per Agent**: mailbox and card belong to the
Agent, so a second device with its own chat key would get envelopes it cannot
open, and a shared chat key would break device separation (Q3).

## 3. Double encryption

**Decision.** Every copy is sealed to the peer's chat card although its
content is already end-to-end encrypted, because:

1. **Metadata.** Unsealed, the relay and any downloader (download is open,
   `AGENT_PACKET_RELAY_V1.md:781-788`) would read the copy's clear fields:
   Event, session, conversation, Endpoint and device IDs, the admission token,
   and on first contact the sender's signed prekey evidence, which names the
   sender (`dispatch.go:34-46`).
2. **Post-quantum confidentiality.** The relay seal is hybrid MLKEM768-X25519
   (`:854-859`); the one-to-one suite is X25519 only. Open download makes
   harvesting easy, and the seal protects recorded chat against a later
   quantum adversary while the chat key holds.
3. **No relay change.** The recipient rules expect a sealed Agent Packet
   (`:395-411`).

Cost: 1,373 bytes and one HPKE seal and open per envelope. The two layers'
keys are independent (2.2).

## 4. Size and fan-out

**One-to-one copies are never split.** A Messenger payload is at most 160 KiB
and its ciphertext 165 KiB (`messenger/pkg/eventlog/journal.go:65-69`); a copy
with a card exceeds one frame only if a first-contact bootstrap above about
11 KiB (bounded by `messenger/pkg/e2ee/bundle_set.go:19`, `bootstrap.go:19`)
meets a maximal ciphertext. The daemon MUST compute the worst-case frame size
**before sealing** and refuse an oversize delivery with `content-too-large`
(`messenger/pkg/fault/fault.go:123`), so no message key is spent.

**Room handshake objects are split (M-R2).** MLS objects reach 1 MiB
(`messenger/pkg/group/openmls_sidecar.go:28`). A kind-3 object above one frame
is split into at most 8 parts, one packet each, sharing `object_digest`; the
receiver holds at most 8 incomplete objects per peer for at most 24 h 5 min and
releases an object only when its digest matches.

**Attachments stay out of band (M-R3)** in the existing encrypted attachment
store (`messenger/docs/ENCRYPTED_ATTACHMENTS.md:1-40`; up to 2,048 chunks of
1 MiB, `messenger/pkg/attachments/attachments.go:35-38`); the relay carries only
the `artifact.encrypted` event, whose Reference is already E2EE. **Rejected:
chunks through the relay**: one 16 MiB attachment fills the per-recipient
quota (`AGENT_PACKET_RELAY_V1.md:640`) and blocks task results, and its chunks
expire after 24 h at an offline recipient.

**Fan-out is one envelope per recipient Agent**: per device for copies, per
member Agent for room frames, each signed and sealed separately. M-R2 bounds
relay rooms to **32 members** (32 signatures per message, one envelope in each
member's quota).

**Offline beyond the 24 h relay TTL** (`:636-640`):

- **One-to-one copies are re-deposited.** A copy with no verified delivery ack
  20 h after its last accepted deposit (a test MAY set 10 min to 20 h and
  records it) is deposited again: the same ciphertext, since a retry never
  re-seals (`messenger/README.md:121`), in a new packet and envelope under the
  next generation's key. Once a relay accepts it, the sender withdraws the
  previous envelope with its secret (`AGENT_PACKET_RELAY_V1.md:603-606`), so at
  most two copies are ever stored. This runs until the delivery's own expiry,
  by default **7 days** and never beyond 30 days
  (`messenger/pkg/envelope/envelope.go:49`); then the delivery is `abandoned`
  with `retention-exceeded` (`fault.go:141`) on the owner surface. Nothing is
  lost silently.
- **Room application messages: loss with notice.** One deposit, 24 h; a member
  detects the gap from the MLS per-sender generation and the runtime is told.
  Re-depositing to N members multiplies load by N per day of absence.
- **Room Commits and Welcomes** follow the one-to-one rule with a per-member
  ack: a lost Commit cuts a member off.

A copy whose recipient card expired waits for a fresh card (contact file or in
band) until its own expiry.

## 5. Ordering, duplicates, acknowledgements

### 5.1 Guarantees

Carriage is at least once and unordered (`AGENT_PACKET_RELAY_V1.md:36-38`);
application processing is exactly once, because the journal commits the
ratchet step with the Event and the runtime takes it under an application
lease (`messenger/README.md:109-117`).

- **Duplicates** (relay replay, two relays, re-deposit generations) MUST answer
  `duplicate` with a signed ack and never reach the ratchet. Today only the
  session's *last* inbound Event is recognized
  (`messenger/pkg/daemon/inbound.go:45-47`); an older duplicate would fail to
  open. M-R1 checks every Event ID committed for the session before `Open`.
- **Order.** The Double Ratchet accepts out-of-order delivery
  (`E2EE_SUITE_DECISION.md:37-40`); the runtime sees arrival order, causal
  order is `reply_to` (`AGENT_NATIVE_MESSENGER_V1.md:2073-2078`).
- **MLS (M-R2).** The single room authority serializes Commits
  (`messenger/docs/OPEN_DECISIONS.md:147`); the ledger applies them in epoch
  order with persist-before-output and Welcome replay refusal. A frame for a
  future epoch waits in a bounded buffer (256 per room) for its Commit; a
  past-epoch or replayed object is refused and still relay-acknowledged.

### 5.2 Acknowledgements

Storage is not delivery (`AGENT_NATIVE_MESSENGER_V1.md:2080-2091`):

| Signal | Meaning | Signed by |
|---|---|---|
| relay `200`/`201`/`410` | a relay durably holds the envelope (a StoredAck in effect) | nobody |
| relay ack (`POST …/ack`) | the recipient node has a durable Messenger result; frees quota | secret only |
| **delivery ack** (kind 2) | the recipient device accepted, deduplicated, held or rejected the copy | recipient Endpoint |
| `ReadAck` | optional; an ordinary sealed Messenger event | recipient Endpoint |

The kind-2 object has the HTTPS ack fields (`directhttps/transport.go:55-66`:
Event, session, recipient Endpoint and device, ciphertext digest, outcome,
code, time) under schema `tos.messaging.relay-delivery-ack.v1` and a new
signing domain beside `DomainHTTPSDeliveryAck`
(`messenger/internal/canon/domains.go:205-207`), so no ack verifies on the
other route. The sender verifies it under the peer's finalized Endpoint key as
`directhttps/transport.go:214-229` does; `accepted`, `duplicate` and `held`
mean `delivered`, `rejected` applies its code (`:230-239`). Acks are not
acknowledged: a lost ack costs one re-deposit, answered `duplicate` with a new
ack. The acking node's idempotency key binds the copy packet's nonce, so each
generation gets a fresh ack envelope that no tombstone (`410`) suppresses.

### 5.3 Journals

- **Sender Messenger journal** (`messenger/pkg/eventlog/delivery.go:84-109`)
  gains state **`carried`** with generation, last accepted deposit and next
  re-deposit time: `pending → carried` when the carrier answers `carried`,
  `carried → delivered` only on a verified kind-2 ack, and a `carried` copy
  past its re-deposit time is due again. The ciphertext stays until settled.
- **Sender OpenFox chat outbox** (`RelayTransport` record, openfox
  `relay_transport.go:54-104`): envelope bytes, ack secret and signed packet per
  idempotency key `idem_` + SHA-256 of (`delivery_id`, generation) for copies
  or of the copy packet's nonce for acks. `carried` means one relay answered
  `200`/`201`/`410`, `Send`'s existing contract (`AGENT_PACKET_RELAY_V1.md:719-725`).
- **Crash windows.** Messenger dying after `carried` but before recording it
  retries the same generation key and gets `carried` with no new deposit.
  OpenFox dying between the Messenger commit and the relay ack sees the
  envelope listed again, gets `duplicate`, and acks.

## 6. Metadata and privacy

The operator, and since listing and download are open anyone who knows an
Agent ID (`AGENT_PACKET_RELAY_V1.md:772-779`), learns: the recipient Agent ID
and chat key ID (which, with a separate chat card, tells chat from task
traffic to someone who has seen both cards); the padded size bucket; deposit,
listing, download and ack times. The operator also sees sender and recipient
IP addresses, kept per stored envelope for quota (`:688-689`), and can infer
room fan-out from one address depositing to N mailboxes at once. Nobody learns
the sender Agent, Endpoint, device, conversation, room, Event ID, frame kind,
content or attachment bytes. Keying mailboxes by Agent ID instead of the
opaque mailbox IDs Messenger planned (`AGENT_NATIVE_MESSENGER_V1.md:2105`) is a
privacy regression accepted to reuse the relay unchanged.

Mitigations in V1, none touching the relay:

- **Padding** to buckets of 1, 2, 4, 8, 16, 32, 64, 128 KiB and 190,464 bytes;
  acks and short texts share the 1 or 2 KiB bucket.
- **No extra signals**: no typing or presence over the relay; read state only
  as an ordinary sealed `ReadAck` event.
- **Prompt relay ack** (15 s poll, openfox `relay_inbound.go:18-37`), so
  envelopes and their stored address live seconds while the peer is online.
- Hiding IP addresses is the node's own network-layer matter.

**Privacy statement** (consistent with the test-relay statement):

> Chat between OpenFox Agents crosses the relays sealed twice. The relays
> cannot read, alter, forge or delete it. The operator, and anyone who knows
> your Agent ID, can see the recipient Agent ID and key ID, padded envelope
> sizes, counts and times; the operator also sees IP addresses. No relay sees
> who sent a message, which conversation it belongs to, or any content.
> Envelopes are kept until acknowledged or at most 24 hours; an unacknowledged
> one-to-one message is re-deposited by its sender for up to 7 days.

## 7. Abuse and task traffic

Chat and paid task or result traffic would share one mailbox per Agent per
relay: 256 envelopes, 16 MiB, 64 per (client, recipient) (`:636-646`).

**Decision.** Chat uses a **separate card and key**. A node that sells
services SHOULD name chat relays that are other relay instances than its rail
relays (own stores, so own per-recipient quotas), so chat volume and spam can
never take task quota; this needs more instances, not relay changes. A
chat-only node MAY name its rail relays. M-R1 MAY use the two test relays for
both, with quota isolation listed as not proven (Q2).

Recipient protections, strongest first:

1. **Prompt acknowledgement.** Everything that opens under the chat key is
   relay-acknowledged once handled, refusals included (wrong purpose, bad
   signature, unprovisioned peer, admission refusal), so an online recipient
   holds chat for one poll interval. Only unopenable junk holds quota 24 h, as
   it already can against the rail key (`:790-800`).
2. **Messenger admission.** The first-contact default (allow-listed contacts,
   one-time invites, owner hold otherwise) applies on this route as on every
   route (`messenger/docs/OPEN_DECISIONS.md:148`), as `admission.RouteRelay`
   (`messenger/pkg/admission/admit.go:41`). An unresolvable sender is refused
   before anything is stored.
3. **Sender in-flight cap.** An honest sender keeps at most 32 `carried`
   deliveries per peer Agent and holds the rest `pending`, so an offline
   recipient holds at most 32 (briefly 64) envelopes per relay from one peer.
4. A peer that ignores the cap is the open-deposit flood the relay spec
   already bounds as an availability attack.

**Rejected: per-purpose mailboxes at the relay** (`/v1/mailboxes/{agent}/{purpose}`):
a relay API and storage change that still cannot stop spam, since anyone may
deposit anywhere, and puts the purpose in the URL.

## 8. Phasing and acceptance gates

Each phase is accepted by a live record under `spec/deployments/`, built like
the relay records (commits, binary hashes, checks, `not_verified`,
`qualifies_as_public_acceptance: false` while relays and chain are the core
team's) and described in `AI_SERVICE_PROVIDER_IMPLEMENTATION_STATUS.md`.

### M-R1: one-to-one text, two OpenFox, two hosts

Record `messenger-relay-one-to-one-<date>.json`, schema
`tos.messaging.relay-carriage.acceptance.v1`. A run MUST show:

1. **Relay only.** A on a host behind NAT with no inbound port, B on a
   separate VPS, each running `tos-messengerd` (transport `agent-packet-relay`,
   discovery `contact-files`) and OpenFox; no HTTPS ingress, DHT, shared
   socket or TCP path between them (probed); both cards name both test relays
   and pin the test CA.
2. **Conversation.** A texts B; B's runtime answers via `messages.reply-direct`.
   Each delivery becomes `delivered` only on a verified kind-2 ack; the record
   shows `carried → delivered` times.
3. **First contact** over the relay with an admission invite, and B learning
   A's card in band, not only from the contact file.
4. **Relay outage.** relay-1 down for the whole conversation; relay-2 carries it.
5. **Offline peer.** B stopped beyond the re-deposit interval; A deposits
   generation 2 and withdraws generation 1; B applies the message once and
   answers the other generation `duplicate`.
6. **Crash windows.** B killed between Messenger commit and relay ack; A killed
   between `carried` and its journal write. One runtime application; on
   restart the same envelope (`200`).
7. **Refusals.** A rail packet sealed to the chat key and a frame sealed to
   the rail key are refused and relay-acknowledged; a packet sender differing
   from the Event sender is refused; an oversize payload is refused before
   sealing.
8. **Nothing readable at the relays.** Relay state copied while each held a
   copy and an ack contains no message text, conversation, Event, Endpoint or
   device ID and no sender Agent ID (a control file proves the search finds
   each); every envelope size is a bucket size.
9. **Cost.** `tosctl` sign-to-deposit time per frame.

Not proven: third-party relays or hosts, a public chain, quota isolation under
flood, multi-device, M0 freeze evidence (independent review and a second E2EE
implementation, `messenger/docs/ROADMAP.md:25`), any Gate O claim.

### M-R2: private rooms

Three OpenFox on three hosts: room creation, two Welcomes (one split) and a
Remove Commit over the relay; a member offline across a Commit catches up in
epoch order; a member offline beyond 24 h gets a gap notice yet receives the
Commit; the removed member cannot decrypt later messages. Not proven: rooms
above 32 members, concurrent authorities.

### M-R3: attachments

A `text/plain` attachment above 16 MiB through a core-team HTTPS attachment
store while its reference event crosses the relay; the recipient fetches,
verifies every tag and admits it through the scanner; no chunk ever appears in
relay state. Not proven: a store run by anyone else, other media types.

## 9. M-R1 code changes

Boundaries hold: `messenger/` imports only `protocol/`; nothing in `ai`
imports `messenger/`; OpenFox imports both.

**`ai/messenger`**

1. `pkg/relayframe` (new): frame codec (kinds 1–2, buckets, strict decode,
   worst-case size), copy object codec, kind-2 ack preimage/sign/verify with a
   new `canon.DomainRelayDeliveryAck`; vectors in `internal/vectors`. Imports
   `protocol/pkg/agentpacketseal` for size constants only.
2. `pkg/carrierapi` (new): strict bounded client and server on mode-0600 Unix
   sockets, modelled on `pkg/prekeyapi`: `carrier.carry` (daemon → OpenFox:
   one frame plus idempotency key; `carried`, `retry` or a fixed refusal),
   `carrier.deliver` (OpenFox → daemon: verified copy frame plus packet sender;
   signed ack object or `retry`), `carrier.delivery-ack` (OpenFox → daemon:
   verified kind-2 frame plus packet sender).
3. `pkg/eventlog`: `carried` state and fields; `carried → delivered` by ack
   match (Event, session, device, ciphertext digest); "Event ID committed in
   session" lookup; schema bump (pre-launch, no migration).
4. `pkg/dispatch`: a distinct `carried` sender result routed to the new state
   instead of `Delivered` (`dispatch.go:811-816`), keeping the `nil` contract
   (`:48-56`); pre-seal size check; re-deposit generations; per-peer cap.
5. `pkg/daemon`: `TransportAgentPacketRelay` (`config.go:65-68`) with carry and
   listen socket paths; `configureRelayCarriage` beside `configureHTTPSBootstrap`
   (`direct_https.go:61-75`); `ReceiveSealed(…, admission.RouteRelay)` with the
   duplicate lookup before `Open` (`inbound.go:41-51`) and the sender check of
   2.4; the same-Agent startup check.
6. `pkg/directory` and daemon config: `contact-files` discovery, a
   `RefreshSource` (`refresh.go:16-22`) over per-peer files verified exactly as
   the network source, and a publication sink writing the node's own objects
   to an export directory.
7. `docs/RUNNING.md`, `docs/ROADMAP.md`: the mode and its status.

**`ai/protocol`**: none. **Relay program, relay spec**: none. **`ai/spec`**:
this document.

**`openfox`**

1. `pkg/servicebridge/relay_chat.go` (new): a second `RelayKeys` set
   (`relay/chat-keys`, own relay URLs defaulting to the rail list), a chat
   `PeerCards` without Capability-owner binding (`relay/chat-peers`, unlike
   `relay_cards.go:292-345`), a chat `RelayTransport` (`relay/chat-outbox`),
   one shared relay pool; and the `carrier.carry` server: validate the frame,
   sign (zero Capability, expiry = min(copy expiry, now + `PacketLifetime`),
   `transport.go:25-27`), `Send`, answer `carried` only on acceptance.
2. `relay_inbound.go`: one poll loop over rail and chat relays, dispatching by
   key ID. Rail keys: unchanged `acceptPacket` (`receiver.go:105-140`). Chat
   keys: decode, recipient, zero Capability, frame domain, `agentpacket.Verify`,
   frame decode, card learning, `carrier.deliver` or `carrier.delivery-ack`;
   `retry` and finalized-state failures leave the envelope unacknowledged,
   every other outcome is relay-acknowledged; a copy's returned ack goes out
   as a kind-2 frame.
3. `relay_transport.go:267`: per-instance packet bound; rail keeps 128 KiB
   (`receiver.go:17`), chat uses `agentpacketseal.MaxPacketJSONBytes`.
4. CLI and config: `init --chat-relay-url` (repeatable),
   `--messenger-carrier-socket`; `openfox chat contact export|import`
   (`tos.openfox.chat-contact.v1`, verified on import); chat card
   republication; status and preflight entries; refusal to combine
   `MessengerTransport` with this carriage.
5. `scripts/messenger-relay-two-host-e2e.{sh,py}` producing the M-R1 record.

## 10. Owner questions

- **Q1.** For the OpenFox profile this replaces M0-R's route decision and
  Messenger's own Mailbox Relay. Retire the study and
  `tos-mailboxd`/`pkg/mailbox`, or keep them for a possible later direct route?
- **Q2.** Run a second relay instance per test host now to prove quota
  isolation in M-R1, or accept shared quota until production?
- **Q3.** V1 allows one Messenger device per Agent. Multi-device needs
  per-device cards and a device selector the Agent-keyed mailbox lacks. Defer?
- **Q4.** M-R1 discovery is out-of-band contact files, because `tos-dht-https`
  needs a DHT (down with the stopped testnet) and a public HTTPS origin per
  peer. Accept files for M-R1 and decide in-band or DHT discovery later?
