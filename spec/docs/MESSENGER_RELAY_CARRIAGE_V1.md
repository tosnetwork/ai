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
not by the study: in V1 the packet relay is the only cross-host route, and
the study and Messenger's own Mailbox Relay are retired for this profile (D1).

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
packet buys nothing and halves every bound. The receiving side is closed too:
on `admission.RouteRelay` the daemon MUST refuse `agent.packet` Events and any
other Event class that carries an Agent Packet
(`messenger/docs/AGENT_PACKET_BRIDGE.md:1-9`). Otherwise a rail packet could
reach the rail inbox inside a chat copy, bypassing the key-purpose rule of 2.2.

### 1.1 Frame

```text
relay_frame =
  D("tos.messaging.relay-frame.v1")   29 bytes
  frame_kind      u8    1 = copy, 2 = delivery-ack, 3 = room (M-R2), 4 = evidence
  part_index      u8    0 .. part_count-1
  part_count      u8    1 .. 8; kinds 1, 2 and 4 require 1 (kind 4: 1 = request, 2 = response)
  object_digest   32    SHA-256(D("tos.messaging.relay-object.v1") || object)
  card_length     u16   0, or 1 .. 9,216
  card            exact key-card packet JSON (2.3)
  evidence_length u16   1 .. 18,432 (required in kinds 1, 2, 4)
  evidence        the sender's current relay identity evidence (2.5)
  part_length     u32
  part            this part of the object
  padding         zero bytes up to the frame's size bucket (6)
```

`D(x)` and big-endian integers as in relay spec section 4. Decoders reject
unknown kinds, non-zero padding, a total that is not a bucket size, and
trailing bytes. A frame is at most **190,464 bytes**: base64 makes it 253,952,
plus at most 5,432 bytes of fixed packet fields (hex ML-DSA-44 signature, IDs,
key ID, maximal integers) gives 259,384, under the 260,771-byte packet bound
(`protocol/pkg/agentpacketseal/seal.go:64-74`) with 1,387 bytes spare.

**What the relay observes.** The stored envelope is not the frame. It is the
frame in base64 inside the signed packet JSON, plus the seal overhead
(`AGENT_PACKET_RELAY_V1.md:313-328`):

```text
envelope_size = 1,373 + F + 4·⌈B/3⌉
```

Here B is the frame's padded bucket and F is the packet's fixed fields. F
varies between 5,394 and 5,432 bytes, only through the decimal widths of
`sequence` and `created_at_unix`, which encode nothing beyond the sender's
clock. The relay therefore learns B and nothing finer about the content.

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
with descriptor and signed prekey set verified as the refresh chain does but
without its locator stage (2.5); and (b) the peer's
**chat key card**, verified with `VerifyKeyCard` (`AGENT_PACKET_RELAY_V1.md:129-139`),
whose Agent MUST equal the delegation's Agent.

### 2.2 Keys and purposes

No key serves two purposes and none is derived from another:

| Key | Holder | Only purpose |
|---|---|---|
| ML-DSA-44 packet controller | `tosctl` vault, used by OpenFox | signing Agent Packets and key cards |
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
  operators exchange out of band with the relay identity evidence of 2.5
  (four signed or committed Messenger objects, no locator) and the chat card.
  Everything in it is verified on import; it is rendezvous, not authority, like the bootstrap files of
  `messenger/docs/DISCOVERY_BOOTSTRAP.md:10-26`. Its card SHOULD last the
  30-day maximum and be republished under 15 days, like the offer card
  (`AGENT_PACKET_RELAY_V1.md:256-266`).
- **In band.** A frame carries the sender's current chat card until the peer
  has acknowledged a frame that carried it. The receiver takes it only from a
  verified packet whose sender is the card's Agent, after `VerifyKeyCard`; a
  failing card is ignored and does not invalidate the frame (as `:216-228`).
  A card packet is at most 9,216 bytes (a 2,346-byte body, `:170`, in base64
  plus packet fields).

**Cards are stored only for admitted peers.** OpenFox's peer-card store holds
cards of at most 1,024 peers and does not evict valid cards to admit a new one
(openfox `relay_cards.go:34`, `:353-385`), so cards learned from strangers
could block new contacts for up to a card lifetime. An in-band card is
therefore stored only after `carrier.deliver` answers `accepted`, `duplicate`
or `held` for the frame that carried it (never `rejected`), or when it comes
from a peer with an established Messenger session. A contact-file card goes
into the same admitted store, because importing the file is the owner's
decision. A refused stranger's card is never stored.

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
open, and a shared chat key would break device separation (D3).

### 2.5 Relay identity evidence (no locator)

**The problem in the current code.** File-only discovery would stop working
within a day:

- a locator lives at most 24 h (`messenger/pkg/directory/locator.go:43-46`);
- `VerifyLocator` refuses an expired one (`locator.go:285-305`), and the
  refresh chain runs it on every refresh (`refresh.go:117-128`);
- `Manager.Ensure` re-refreshes once a result's refresh time has passed, and
  returns the error with no stale fallback (`manager.go:35-55`). The refresh
  time is the earlier of the descriptor and locator expiries
  (`refresh.go:183-198`);
- the daemon calls `Ensure` on first contact (`inbound.go:70-72`) and for every
  established-session message (`inbound.go:160-163`).

So an imported contact would stop receiving within 24 h, and a peer returning
after days would have no fresh evidence for its retained messages.

**Decision.** A locator says how to reach a peer over a network route. On
`admission.RouteRelay` the route is the chat card, so the relay route MUST
NOT require a locator. Everything else the network route checks, on either
side, keeps a relay equivalent on the same side. That is why this section has
one shape: a single read-only check, used identically by sender and receiver,
and a separate commit that runs only after admission.

**Skipped on `RouteRelay`**, exactly the locator stage:

- the locator fetch and `VerifyLocator` (`refresh.go:117-128`);
- `MatchesDescriptor(locator, descriptor)` (`locator.go:320`, called at
  `refresh.go:136`);
- the locator's term in the refresh time.

**Relay identity evidence** is the four remaining objects of the refresh
chain, under schema `tos.messaging.relay-evidence.v1`:

| Object | Network-route bound | Relay bound | Vector size |
|---|---|---|---|
| Endpoint delegation | 64 KiB (`file_delegations.go:13`) | 4,096 | 1,012 |
| Descriptor policy | 4 KiB (`policy_json.go:10`) | 1,024 | 153 |
| Contact Descriptor | 32 KiB (`https_source.go:24`) | 4,096 | 1,321 |
| Prekey bundle set, one device (D3) | 128 KiB | 8,192 | 827 per bundle |

Vector sizes are from `messenger/internal/vectors/testdata/vectors.json`. One
bundle's material is at most 4 KiB (`messenger/pkg/e2ee/bundle.go:27`), which
is 5,462 bytes in base64 plus its fields, so 8,192 bytes covers one device.

**Chosen: a derived cap, not a bare limit.** The evidence is at most
**18,432 bytes**: the four relay bounds plus 1,024 bytes for the schema and
length prefixes. The real objects are four to eight times below their relay
bounds, so lowering the per-object bounds costs nothing. A node whose own
objects exceed a relay bound cannot publish relay evidence: export fails with
the fixed error `relay-evidence-too-large`. Import, and an in-band frame,
refuse such evidence the same way. The codec vectors include an over-bound
object of each kind.

**`CheckPeer`: one read-only check, the same on both sides.**
`CheckPeer(peer Agent, evidence, pin, now)` passes only if all of these hold:

1. The delegation, re-read from finalized state on every call, is still
   committed by the live Agent and inside its window
   (`identity/delegation.go:256-310`, at most 365 days, `:44`). Its Endpoint is
   the one in `pin`.
2. The policy reproduces the digest the delegation commits.
3. The descriptor is signed by that Endpoint and unexpired
   (`messenger/pkg/directory/descriptor.go:35`, `:311`).
4. The bundle set matches the descriptor's digest and contains the device in
   `pin`.
5. The set is not a rollback against the stored boundary. This is read-only:
   the boundary is read, and nothing is written.

The `pin` is the session's pinned peer Endpoint and device, or on first
contact the bootstrap's sender bundle. `CheckPeer` writes nothing durable, so
verifying a stranger's evidence costs no storage and moves no rollback state.

**`CommitPeer`: the only durable step.** It stores the evidence and calls
`AdmitPublishedSet` (`refresh.go:26-28`) only when the evidence is newer than
the stored one: a different descriptor digest and a later issue time.
Otherwise it is a no-op. It runs only under the admission rule of 2.3:

- after `carrier.deliver` answers `accepted`, `duplicate` or `held`;
- or for a peer with an established session;
- or on contact-file import.

Only provisioned or admitted peers are ever committed.

**Receiver.** `CheckPeer` runs on every frame. It uses the frame's evidence
for kinds 1, 2 and 4, and the stored evidence for kind 3. This replaces
`Ensure` at `inbound.go:70` and `:160` on `RouteRelay`.

**Sender: scope.** `CheckPeer` gates only the sealing and re-depositing of
*content* copies: kind 1, and kind 3 in M-R2. Kinds 2 and 4 deliver no
Messenger content to a device. They need only a currently valid, verified
chat card of the peer, so an ack (including a `descriptor-expired` ack) and an
evidence request can always be sent while the peer's card is valid.

**Sender.** `CheckPeer` runs on the stored recipient evidence before every
content seal and before every content re-deposit on `RouteRelay`. This matches the HTTPS
route, which re-resolves the peer and requires the pinned device to be current
on every attempt (`messenger/pkg/daemon/direct_https.go:31-49`), as does the
reply path (`daemon.go:415-418`). If the check fails, the copy is not sealed
and not carried (a sealed copy is not re-deposited). It stays `pending` until
fresher evidence arrives, either in band (pulled with kind 4, below) or from a
new contact file, or until it expires.

**The freshness window differs from the network route.** A device removed by
a newer descriptor is noticed on the network route within the 24 h locator
lifetime. On the relay route it is noticed when the newer evidence arrives,
and at the latest when the stored descriptor expires (at most 7 days).

An Endpoint revocation (the delegation is withdrawn on chain) is noticed at
once on the relay route, because check 1 reads finalized state on every call.
On the network route it is noticed within the cached refresh window, at most
24 h (`manager.go:44-46`, `refresh.go:183-198`).

**In-band renewal.**

- **Every frame carries evidence.** Every frame of kind 1, 2 and 4 carries the
  sender's current evidence, including every re-deposit generation. A
  re-deposit is a new frame and seal anyway (a fresh ack secret, 5.3), so the
  outer frame takes fresh evidence while the inner ciphertext stays
  byte-identical. The daemon keeps its own descriptor fresh on its existing
  publication schedule.
- **Kind 4: pulled evidence, a request and a response.** A kind-4 frame carries
  no object, only the sender's evidence (as every frame does) and optionally a
  card. A one-byte object marks it as a request or a response.
  - **Request.** A node sends one kind-4 request to a peer only while it holds
    a kind-1 copy for that peer `pending` because the stored evidence fails
    `CheckPeer`. The request is re-deposited on the copy's 20 h schedule. It
    ends when the copy is sent or abandoned, or when the request is answered.
    No kind-4 frame is ever sent to a peer with no pending copy.
  - **Receiving a request.** The node runs `CheckPeer` on the frame's evidence,
    read-only. If the sender is an established or admitted peer and the check
    passes, it runs `CommitPeer` and answers with one kind-4 response carrying
    its own current evidence. It sends at most one response per (peer, own
    descriptor digest) per hour. A stranger gets the relay ack only: no
    response and no write.
  - **Receiving a response.** It is checked and committed the same way, and is
    never answered.

  Kind-4 envelopes get relay acks but no delivery acks, and they count against
  the in-flight cap of section 7.
- **Why one round trip resolves mutual staleness.** Each node's own evidence
  is always current, because its publication keeps it fresh. Suppose A and B
  each hold the other's expired evidence.
  - A holds a copy for B, so A sends a request carrying A's fresh evidence. B
    commits it, and B's view of A is now fresh.
  - B's response carries B's fresh evidence. A commits it, A's view of B is
    fresh, and A seals or re-deposits the copy.
  - If B holds a copy for A, B's own request (or the request it received)
    repairs the other direction the same way.
  - If the responder was offline for more than 24 h, the request it missed is
    re-deposited every 20 h, so it is waiting at the relay when B returns.
  - Kinds 2 and 4 need only the peer's card, never `CheckPeer`, so nothing in
    this exchange is blocked by the staleness it repairs.

  What remains: the exchange fails if a node cannot renew its own descriptor
  (for example, its Endpoint signer is unavailable), if the peer's chat card
  has expired, or if the requester is a stranger to the responder (first
  contact needs a current contact file).
- **Retained message whose evidence expired.** The receiver accepts the
  message if the frame's evidence passes `CheckPeer`. Otherwise it answers a
  signed `rejected` delivery ack with `descriptor-expired`
  (`messenger/pkg/fault/fault.go:72`) and relay-acknowledges the frame. The
  sender's journal records the code and the descriptor digest of the evidence
  it had sent.
  - It retries at once only if its current evidence is newer than the one
    rejected, meaning a different descriptor digest or a later issue time.
  - Otherwise it waits for its own renewal, with the normal 30 s to 5 min
    backoff, every attempt counted against the 24-envelope cap.

  The descriptor-expired retry therefore cannot loop on clock skew.

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
and its ciphertext 165 KiB (`messenger/pkg/eventlog/journal.go:65-69`). A
first-contact bootstrap carries one sender bundle, whose material is at most
4 KiB (`messenger/pkg/e2ee/bundle.go:27`), plus an initial message of at most
4 KiB (`bootstrap.go:19`), in JSON. Every frame also carries up to 18,432
bytes of evidence (2.5) and possibly a card, so the relay route's largest
payload is below Messenger's own: the frame codec derives the exact worst case
from the maximal card, evidence and bootstrap. The daemon MUST compute the worst-case frame
size from it **before sealing** and refuse an oversize delivery with
`content-too-large` (`messenger/pkg/fault/fault.go:123`), so no message key is
spent.

**Room handshake objects are split (M-R2).** MLS objects reach 1 MiB
(`messenger/pkg/group/openmls_sidecar.go:28`). A kind-3 object above one frame
is split into at most 8 parts, one packet each, sharing `object_digest`. The
receiver:

- holds parts only from admitted room members;
- caps one object at 1 MiB (the sidecar bound), refusing a part whose declared
  or accumulated size exceeds it;
- holds at most 4 incomplete objects and 4 MiB of incomplete parts per peer,
  and at most 16 MiB of incomplete parts in total, refusing (and
  relay-acknowledging) parts beyond any cap, so filling the global cap takes
  at least four admitted peers;
- drops an incomplete object after 24 h 5 min;
- releases an object only when its digest matches.

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
| **delivery ack** (kind 2) | the recipient device accepted, deduplicated, held or rejected it | recipient Endpoint |
| `ReadAck` | optional; an ordinary sealed Messenger event | recipient Endpoint |

The kind-2 object has the HTTPS ack fields (`directhttps/transport.go:55-66`:
Event, session, recipient Endpoint and device, ciphertext digest, outcome,
code, time) under schema `tos.messaging.relay-delivery-ack.v1` and a new
signing domain beside `DomainHTTPSDeliveryAck`
(`messenger/internal/canon/domains.go:205-207`), so no ack verifies on the
other route. The sender verifies it under the peer's finalized Endpoint key as
`directhttps/transport.go:214-229` does, and the ack packet's sender Agent
MUST equal the Agent of the Endpoint that signed the ack (otherwise it is
refused and relay-acknowledged); `accepted`, `duplicate` and `held`
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
  Re-deposit works within the relay spec: a fresh ack secret gives a fresh
  envelope ID, a withdrawn generation's tombstone cannot block the next one,
  and 20 h stays under the 24 h minus 5 min packet lifetime.
- **Generation withdrawal.** When generation N+1 is accepted at a relay,
  `carrier.carry` withdraws generation N there (9.5) through
  `RelayTransport.Withdraw(idempotencyKey)`. The withdrawal is journaled and
  retried with the same bounds and backoff as the existing withdrawal after a
  card revocation, which today is the only path that withdraws (openfox
  `relay_transport.go:733-780`).
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
traffic to someone who has seen both cards); the frame bucket, through the
envelope size of 1.1 and nothing finer; deposit,
listing, download and ack times. The operator also sees sender and recipient
IP addresses, kept per stored envelope for quota (`:688-689`), and can infer
room fan-out from one address depositing to N mailboxes at once.

Evidence is pulled, never pushed. A node sends a kind-4 request only to a peer
it holds a pending copy for, and a response only to a requester. Publishing a
new descriptor therefore sends nothing to anyone, and the relay never sees a
burst to every contact that would reveal the contact graph.

**Sender unlinkability is not provided in V1.** The sender Agent is not in any
envelope, but an operator can usually infer it: the address that deposits a
chat envelope is normally the address that polls the sender's own mailbox
(listing names the Agent). Because the listing is open, anyone polling it also
sees when a recipient acknowledges and so learns that recipient's online
times. No observer learns, from the envelope alone, the sender Agent,
Endpoint, device, conversation, room, Event ID, frame kind, content or
attachment bytes. Keying mailboxes by Agent ID instead of the
opaque mailbox IDs Messenger planned (`AGENT_NATIVE_MESSENGER_V1.md:2105`) is a
privacy regression accepted to reuse the relay unchanged.

Mitigations in V1, none touching the relay:

- **Padding** of the binary frame to frame buckets of 1, 2, 4, 8, 16, 32, 64,
  128 KiB and 190,464 bytes. Every frame carries evidence (about 3.5 KB with
  the vector-sized objects of 2.5), so acks and short texts share one frame
  bucket: typically 8 KiB, or 16 KiB when a card rides along.
- **Stored sizes** (1.1, at the maximum F):

  | Frame bucket | Stored envelope (bytes) |
  |---|---|
  | 8 KiB | 17,729 |
  | 16 KiB | 28,653 |
  | 32 KiB | 50,497 |

  An ack therefore stores about 2.2 to 3.5 times what a bare 1 KiB frame
  would (8,173 bytes). That is the price of carrying evidence everywhere.
  With frames this size, the relay's 256-envelope count limit binds before
  its 16 MiB byte limit: 256 × 28,653 bytes ≈ 7.0 MiB.
- **No extra signals**: no typing or presence over the relay; read state only
  as an ordinary sealed `ReadAck` event.
- **Prompt relay ack** (15 s poll, openfox `relay_inbound.go:18-37`), so
  envelopes and their stored address live seconds while the peer is online.
  The price is the online-time exposure above.
- Hiding IP addresses, and polling and depositing over separate network paths
  so the two cannot be matched, is the node's own network-layer measure.

**Privacy statement** (consistent with the test-relay statement):

> Chat between OpenFox Agents crosses the relays sealed twice. The relays
> cannot read, alter, forge or delete it. The operator, and anyone who knows
> your Agent ID, can see the recipient Agent ID and key ID, padded envelope
> sizes, counts and times, and from the acknowledgement times when you are
> online; the operator also sees IP addresses, and by matching the address
> that deposits a message with the address that polls a mailbox it can
> usually tell which Agent sent it. No relay sees which conversation a message
> belongs to, or any content. Envelopes are kept until acknowledged or at most 24 hours; an unacknowledged
> one-to-one message is re-deposited by its sender for up to 7 days.

## 7. Abuse and task traffic

Chat and paid task or result traffic would share one mailbox per Agent per
relay: 256 envelopes, 16 MiB, 64 per (client, recipient) (`:636-646`).

**Decision.** Chat uses a **separate card and key**. Before any production use,
a node that sells services MUST name chat relays that are other relay
instances than its rail relays (own stores, so own per-recipient quotas), so
chat volume and spam can never take task quota. This needs more instances,
not relay changes. A chat-only node MAY name its rail relays. M-R1 uses the
two test relays for both, and quota isolation is not proven there (D2).

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
3. **Sender in-flight cap.** An honest sender holds at most **24** chat
   envelopes per peer Agent at any relay. The count includes every envelope
   still stored, including earlier generations not yet withdrawn and the
   node's own kind-2 ack and kind-4 evidence envelopes to that peer, which
   share the same relay bound; the rest stay `pending` and are not deposited. The relay caps one client address at 64
   envelopes per recipient (`:641`). On shared relays, 24 chat envelopes leave
   at least 40 of that 64 for the same sender's rail deposits (tasks, results,
   acks) to the same peer.
4. **A malicious sender ignores its own cap.** Four IPv6 /64s at 64 envelopes
   each fill a 256-envelope mailbox. That is the open-deposit exposure the rail
   already has (`:790-800`): an availability attack that grants no authority.
   Separate chat relays (above) keep it away from task traffic.

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
5. **Offline peer and duplicates.** B is stopped beyond the re-deposit
   interval. A deposits generation 2, and generation 1 is withdrawn at every
   relay that held it (the relay answers it `404` or `410` afterwards). B
   applies the message once and answers any other generation `duplicate`.
   An older duplicate that arrives after a newer Event of the same session gets
   a `duplicate` ack and never reaches the ratchet (the `inbound.go:45-47`
   gap).
   **Beyond 24 h:** B is also stopped for more than 24 h, across at least one
   re-deposit and past every locator lifetime, then restarted. B still
   receives A's retained message, and both continue the conversation, with no
   second out-of-band exchange. The record shows the evidence carried in band
   and that no locator was checked on the relay route.
   **Descriptor expiry:** B's stored descriptor for A expires while a message
   of A's is retained. B accepts it because the frame carries fresh evidence,
   or B answers `descriptor-expired` and A retries once with newer evidence
   (and only then). This case is a live step if the run can wait out a
   descriptor lifetime with a test-shortened descriptor. Otherwise it is a
   named unit test listed in `not_verified`.
   **Peer revocation:** a test removes B's device through a newer descriptor,
   and separately withdraws B's Endpoint delegation on chain. After each, A
   seals and carries no copy to the old device. The copy stays `pending`, and
   the record shows A's `CheckPeer` refusal.
   **Evidence pull:**
   - Mutual staleness: A and B each hold only the other's expired evidence,
     and A has a pending copy. One kind-4 request and response round trip
     makes both views fresh, and the copy is sealed. A `descriptor-expired`
     kind-2 ack is sent while B's evidence is stale.
   - Responder offline: the same with B offline for more than 24 h. The
     request is re-deposited and answered when B returns.
   - A stranger's request gets a relay ack only: no response and no write.
   - No kind-4 frame is ever sent to a peer without a pending copy, and
     publishing a descriptor sends none (checked from the chat outbox).
6. **Crash windows.** B killed between Messenger commit and relay ack; A killed
   between `carried` and its journal write. One runtime application; on
   restart the same envelope (`200`).
7. **Refusals.** A rail packet sealed to the chat key and a frame sealed to
   the rail key are refused and relay-acknowledged; a packet sender differing
   from the Event sender is refused; a kind-2 ack whose packet sender is not
   the signing Endpoint's Agent is refused; an `agent.packet` Event arriving
   over the relay is refused; an oversize payload is refused before sealing;
   a refused stranger's in-band card and evidence are not stored, and its
   evidence leaves the rollback boundary unchanged.
8. **Public-ID race.** An observer pre-deposits junk under a chat envelope's ID
   at one relay. The honest deposit there gets `409` and is abandoned at that
   relay, while delivery succeeds through the other relay.
9. **Nothing readable at the relays.** Relay state copied while each held a
   copy and an ack contains no message text, conversation, Event, Endpoint or
   device ID and no sender Agent ID (a control file proves the search finds
   each). Every decoded frame (B's opened packets and A's chat outbox) is
   exactly a padded bucket size, and every stored envelope size equals
   1,373 + F + 4·⌈B/3⌉ with F in the 5,394–5,432 range of 1.1.
10. **Cost.** `tosctl` sign-to-deposit time per frame.

Not proven: third-party relays or hosts, a public chain, quota isolation
between chat and task traffic (it must be shown before production, D2),
sender unlinkability (section 6), multi-device, M0 freeze evidence
(independent review and a second E2EE implementation,
`messenger/docs/ROADMAP.md:25`), any Gate O claim.

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

1. `pkg/relayframe` (new): the frame codec (kinds 1, 2 and 4, buckets, strict
   decode, worst-case size); the copy object codec; the relay identity
   evidence codec with the per-object relay bounds of 2.5 and
   `relay-evidence-too-large`; and the kind-2 ack preimage, signing and
   verification with a new `canon.DomainRelayDeliveryAck`. Vectors go in
   `internal/vectors`, including an over-bound object of each kind. Imports
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
   (`:48-56`); pre-seal size check; `CheckPeer` before every content seal
   and re-deposit on the relay route (kinds 1 and 3); re-deposit generations recording each
   generation's evidence digest; per-peer cap.
5. `pkg/daemon`: `TransportAgentPacketRelay` (`config.go:65-68`) with carry and
   listen socket paths; `configureRelayCarriage` beside `configureHTTPSBootstrap`
   (`direct_https.go:61-75`); `ReceiveSealed(…, admission.RouteRelay)` with the
   duplicate lookup before `Open` (`inbound.go:41-51`), the sender check of
   2.4, and refusal of Agent-Packet-carrying Event classes on that route; the
   same-Agent startup check.
6. `pkg/directory` and daemon config: `contact-files` discovery with the two
   functions of 2.5.
   - `CheckPeer` is read-only: the refresh chain (`refresh.go:16-22`) minus
     its locator stage, plus the pin check and a rollback comparison that does
     not write.
   - `CommitPeer` stores evidence and calls `AdmitPublishedSet`
     (`refresh.go:26-28`) only when it is newer than the stored one, and only
     under the admission rule.

   `CheckPeer` replaces `Manager.Ensure` on `RouteRelay` in three places:
   - on receive, at `inbound.go:70` and `:160`;
   - on send, before every content seal and every re-deposit, with a failure
     holding the copy `pending` and starting the kind-4 request (in
     `pkg/dispatch`, item 4);
   - on reply, at `daemon.go:415`.

   `CheckPeer` gates kinds 1 and 3 only; kinds 2 and 4 need only the peer's
   card. `CommitPeer` writes only newer evidence.

   Also: the kind-4 pull (a request while a copy is held `pending`,
   re-deposited on its schedule; a response to an admitted requester, at most
   one per peer and own descriptor per hour; never sent unprompted), the
   `descriptor-expired`
   retry rule (retry at once only with newer evidence, else 30 s to 5 min
   backoff), and a publication sink that writes the node's own current
   evidence to an export directory.
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
   `transport.go:25-27`), `Send`, answer `carried` only on acceptance; and
   once generation N+1 is accepted, call the new
   `RelayTransport.Withdraw(idempotencyKey)` for generation N. That call is
   journaled and retried with the bounds and backoff of the revocation path
   (`relay_transport.go:733-780`), and is tested: generation N is withdrawn and
   N+1 is delivered. The chat store keeps a card only under the admission rule
   of 2.3.
2. `relay_inbound.go`: one poll loop over rail and chat relays, dispatching by
   key ID. Rail keys: unchanged `acceptPacket` (`receiver.go:105-140`). Chat
   keys: decode, recipient, zero Capability, frame domain, `agentpacket.Verify`,
   frame decode, `carrier.deliver` or `carrier.delivery-ack`, then card
   learning only if the answer admits the sender (2.3);
   `retry` and finalized-state failures leave the envelope unacknowledged,
   every other outcome is relay-acknowledged; a copy's returned ack goes out
   as a kind-2 frame.
3. `relay_transport.go:267`: per-instance packet bound; rail keeps 128 KiB
   (`receiver.go:17`), chat uses `agentpacketseal.MaxPacketJSONBytes`.
4. CLI and config: `init --chat-relay-url` (repeatable),
   `--messenger-carrier-socket`; `openfox chat contact export|import`
   (`tos.openfox.chat-contact.v1`: relay identity evidence plus card, verified
   on import); pass the daemon's current evidence into every frame; chat card
   republication; status and preflight entries; refusal to combine
   `MessengerTransport` with this carriage.
5. `scripts/messenger-relay-two-host-e2e.{sh,py}` producing the M-R1 record.

## 10. Owner decisions

- **D1. M0-R and Messenger's own Mailbox Relay are retired for the OpenFox
  profile.** This covers `tos-mailboxd`, `pkg/mailbox` and the M0-R study.
  The code is removed in a separate PR after M-R1 passes. Reason: one relay
  infrastructure, as the owner decided.
- **D2. No second relay instance now.** M-R1 shares the two test relays
  between chat and rail. Quota isolation is listed as not proven in M-R1, and
  it must be shown before production (section 7).
- **D3. Multi-device over the relay is deferred.** V1 is one Messenger device
  per Agent (2.4). Multi-device needs per-device cards and a device selector
  that the Agent-keyed mailbox lacks.
- **D4. The out-of-band contact file is accepted for M-R1.** Its authenticity
  comes from the signatures of the objects inside it and their binding to the
  finalized Agent, not from the channel. DHT discovery would need the stopped
  testnet.
