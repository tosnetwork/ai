# Messenger Relay Carriage V1

How private chat between two OpenFox Agents crosses machines by reusing
[Agent Packet Relay V1](AGENT_PACKET_RELAY_V1.md) ("relay spec") with no new
transport, no relay change and no new authority.

**Status: M-R1 ✅ accepted (section 8); M-R2 ⬜ design only (section 11).**
Section 8 states what each phase's live record must prove; section 9 lists
the code changes of M-R1 (9.1) and M-R2 (9.2). Citations added for M-R2 refer
to `tosnetwork/openfox` `main` `edd88e11`.

**Errata (implementation).** Section 4 is corrected to the code and measurements of the M-R1 Messenger implementation: the ciphertext bound is 164 KiB, the first-contact bootstrap bound is 18 KiB (measured worst case 16,951 bytes), and the largest relay Event payload is 139,547 bytes; sections 2.5, 7 and 9 now state the relay-only descriptor route and the split of the 24-envelope count.

**Errata (M-R2 relay frame implementation).** Section 11.1 gains the
normative room-object header layout. The largest valid header is 2,653 bytes
(2,661 since the room end time of D18 was added to it), so the largest valid
object is 1,051,319 bytes (now 1,051,327): five 190,464-byte frames and
one 131,072-byte frame, 1,485,354 stored bytes per member. The 8,192-byte
header and 1,056,858-byte object limits stay as codec bounds; the six full
frames and 1,564,542 bytes the section stated before are an upper bound no
valid object reaches. A room ack (11.7) of a pending joiner refusing its
Welcome carries no epoch authenticator and MLS epoch 0.

**Errata (M-R2 journal implementation).** The MLS state bound is derived from the worst case the driver configuration allows at the relay room bound of 32 leaves, not from in-order traffic at 64: with an out-of-order tolerance of 32, 63 senders skipping 7 generations in each retained epoch exceed 512 KiB at 64 leaves. The tolerance is therefore 8 and the forward distance 1,000; the worst case at 32 leaves is measured in section 11.3 (sections 8 item 17, 9.2 item 2, 11.3), corrected by the leaf-identity erratum below. The fused record names the memberships of the two earlier room epochs by digest, because three member lists do not fit its 8,192 bytes; those content-addressed membership records are named by the fused record and collected with the other staged records (sections 9.2 item 4, 11.3, 11.7).

**Errata (M-R2 leaf identity).** The 32-leaf worst case this document stated before, 272,968 bytes, was measured with 9-byte test identities (`member-NN`). The MLS BasicCredential identity of a leaf is copied into the ratchet tree and every retained epoch, and the library stores byte strings as JSON number arrays, so each identity byte costs about 384 bytes of state at 32 leaves for typical values (up to about 4 characters, "255,", per stored byte). The identity then specified (every DeviceCredential field except the KeyPackage, the validity window and the signature) was 497 bytes on the test network and 616 at a 128-character network ID. With it the worst case is 458,784 and 504,300 bytes: 12.5 % and 3.8 % headroom, under the 20 % item 17 requires. Carrying the full DeviceCredential in the identity is impossible twice over: its Endpoint signature covers the KeyPackage, which carries the identity, so the identity would have to contain itself; and a KeyPackage of up to 64 KiB exceeds the driver's 4,096-byte identity limit. Carrying the DeviceCredential in roster entries would exceed the 1 MiB body bound by about 2 MB. The leaf identity is therefore a fixed 128-byte compact binding, and the member's Endpoint-signed **leaf credential** (at most 473 bytes, no KeyPackage) is issued, distributed, stored and revoked as section 11.8 states. V1 rooms do not renew credentials: a room ends when its authority's leaf credential does (D18). Re-measured with maximal identities of the costliest byte values, the worst case is at most 339,038 bytes over repeated runs (the keys are random; 334,536 before the driver kept the past epochs' leaf keys for `open`, section 11.3), 35 % under the bound (sections 8 items 17, 19, 20, 9.2, 11.1, 11.2, 11.3, 11.5, 11.8, D15, D18).

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
  part_count      u8    1 .. 8; kinds 1, 2 and 4 require 1
  object_digest   32    SHA-256(D("tos.messaging.relay-object.v1") || object),
                        of the whole object, the same in every part
  card_length     u16   0, or 1 .. 9,216; at least 1 in kind 4;
                        0 in kind-3 parts other than part 0
  card            exact key-card packet JSON (2.3)
  evidence_length u16   1 .. 18,432 in kinds 1, 2, 4 and kind-3 part 0;
                        0 in every other kind-3 part
  evidence        the sender's current relay identity evidence (2.5)
  part_length     u32   1 .. 190,392
  part            this part of the object (kind 3: cut as in 11.1)
                  (kind 4: a one-byte object, 1 = request, 2 = response)
  padding         zero bytes up to the frame's size bucket (6)
```

A decoder checks `object_digest` against the part only when `part_count` is
1; a multi-part kind-3 object is checked once, on reassembly (section 4).

`D(x)` and big-endian integers as in relay spec section 4. Decoders reject
unknown kinds, non-zero padding, a total that is not a bucket size or not
the smallest bucket that holds the frame, and trailing bytes. A frame is at most **190,464 bytes**: base64 makes it 253,952,
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
twice. A kind-2 object is the ack of 5.2, or the room ack of 11.7. A kind-3
object is the room object of 11.1.

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
signature. The relay spec recommends a dedicated card-signing controller
(`:197-204`). OpenFox signs the chat card with its packet controller by
choice, as it does its rail and offer cards. The verifiers
(`VerifyKeyCard`, `agentpacket.VerifyContact`, `agentpacket.VerifySender`)
accept any controller of the finalized policy and check no purpose or weight,
so a second controller in the same custody would only add a key that can sign
any packet or card as the Agent. The recommendation is worth meeting only
once off-chain verification checks a signing purpose (relay spec section 11).

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

**The descriptor's route on a relay-only node.** The Contact Descriptor
format is unchanged and stays vector-frozen, and its validator requires an
advertised route (`messenger/pkg/directory/descriptor.go`). A relay-only node
advertises the delegation's ADNL identity (which `Bind` requires the
descriptor to repeat) and no HTTPS endpoint; it MUST NOT publish a placeholder
HTTPS endpoint. Its delegation therefore commits an ADNL identity.

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

**"Newer", defined once.** Evidence E is *newer* than evidence F only if E's
descriptor digest differs from F's **and** E's descriptor issue time is later.
Both `CommitPeer` and the `descriptor-expired` retry rule use this definition.

**Publisher invariant.** Each descriptor a node publishes has a strictly later
issue time than its previous one. So a node's successive evidences are totally
ordered by "newer".

**`CommitPeer`: the only durable step.** It stores the evidence and calls
`AdmitPublishedSet` (`refresh.go:26-28`) only when the evidence is newer than
the stored one. Otherwise it is a no-op. It runs only under the admission rule of 2.3:

- after `carrier.deliver` answers `accepted`, `duplicate` or `held`;
- or for a peer with an established session;
- or on contact-file import.

Only provisioned or admitted peers are ever committed.

**Stored evidence expires.** The store holds at most 4,096 peers and evicts
none. A record whose evidence `CheckPeer` would refuse for its own expiry
(its descriptor's or a bundle's `expires_at` has passed) is retired at start
and on the relay timer, so the bound holds live peers. Retirement keeps a
**floor**, the retired descriptor's digest and issue time, and deletes the
record, each durably and in that order. The floor keeps the peer admitted
and is what `CommitPeer` judges "newer" against while the peer has no
record. It is needed because expiry is not monotonic in the ordering key:
an older descriptor may have a longer lifetime than a newer one and still be
unexpired. A floor may be dropped once its issue time plus the largest
descriptor lifetime (7 days) has passed, since all evidence at or below it
has then expired; floors are dropped only past that horizon, only when
their own store (at most 4,096) is full, and never the floor of a contact
(configured, or made by a claimed invite) or of a peer with a session here,
whose admission it is; a record is kept rather than retired without a
floor. The device-set rollback boundary is separate and
is never swept.

**Receiver.** `CheckPeer` runs on every frame. It uses the frame's evidence
for kinds 1, 2 and 4, and for kind 3 the evidence of part 0, checked when
part 0 arrives, pinned to the sender's MLS leaf (11.2, 11.3). This replaces
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
- **Kind 4: pulled evidence, a request and a response.** A kind-4 frame's
  object is one byte, 1 for a request and 2 for a response. Besides the
  sender's evidence (as every frame has), it MUST carry the sender's current
  chat card, request and response alike. A responder holding only the
  requester's expired card can therefore still answer.
  - **Request.** A node holds at most one outstanding kind-4 request per peer,
    however many content copies (kinds 1 and 3) it holds `pending` for that
    peer because the stored evidence fails `CheckPeer`. It is re-deposited on
    the copies' TTL-derived schedule (section 4), and ends when no copy is
    pending any more, or when it is answered. No kind-4 *request* is ever sent
    to a peer with no pending copy, except under a demand; responses go only
    to requesters.
  - **Demand (M-R2).** A room authority building a roster (section 11.2)
    needs every current member's committed evidence before any object exists
    that could wait on it. Its Commit retry therefore *demands* the evidence:
    the demand keeps the one outstanding request alive while it is refreshed,
    and lapses two request-retry intervals (2 minutes) after the last refresh,
    so the request ends by itself once the Commit is made or abandoned (the
    room ended, the add finished). A demand is held in memory only; after a
    restart the next retry demands again. It never moves the request's
    deposit schedule, so it cannot raise the pull rate
    (`messenger/pkg/daemon/relay.go` `demandEvidence`, `sendRequest`).
  - **Receiving a request.** The node runs `CheckPeer` on the frame's evidence,
    read-only. If the sender is an established or admitted peer and the check
    passes, it runs `CommitPeer` (for the frame's evidence and card) and
    answers with one kind-4 response carrying its own current evidence and
    card. It sends at most one response per (peer, own
    descriptor digest) per hour. A stranger gets the relay ack only: no
    response and no write. **Privacy rule:** a node answers a kind-4 request
    only from a peer it admitted on this route before, one with committed
    evidence or its floor (`RelayVerifier.Admitted`); room membership alone
    does not make a peer admitted, so a pull cannot probe whether a node runs
    or which rooms it is in. A member admits its authority through the
    room.invite copy, and keeps that floor across evidence expiry and
    `contacts.remove`, so an authority's pull to its members is answered. Kind-4 evidence is checked against its own pin
    (the Endpoint and single device it names), not a session's pin, because
    its purpose includes learning a newer descriptor that removed a device;
    it still has to be a live finalized delegation committed by the sender
    Agent itself, and content copies keep their session pin.
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
  - If the responder was offline for longer than the relay TTL, the request
    it missed is re-deposited before each TTL runs out (every 48 minutes
    against 1-hour test relays, every 2 hours 24 minutes against 3-hour
    production relays), so it is waiting at the relay when B returns.
  - Kinds 2 and 4 need only the peer's card, never `CheckPeer`, so nothing in
    this exchange is blocked by the staleness it repairs.

  What remains: the exchange fails if a node cannot renew its own descriptor
  (for example, its Endpoint signer is unavailable), if the requester holds
  only the responder's expired card, or if the requester is a stranger to the responder (first
  contact needs a current contact file).
- **Retained message whose evidence expired.** The receiver accepts the
  message if the frame's evidence passes `CheckPeer`. Otherwise it answers a
  signed `rejected` delivery ack with `descriptor-expired`
  (`messenger/pkg/fault/fault.go:72`) and relay-acknowledges the frame. The
  signed `descriptor-expired` ack goes only to the session's peer or an
  admitted peer (one with committed evidence); a stranger whose evidence
  fails, like a stranger's kind-4 request, gets the relay ack only: no
  Endpoint-signed answer and no write. The sender's journal records the code and the descriptor digest of the evidence
  it had sent.
  - It retries at once only if its current evidence is newer than the one
    rejected, in the single sense defined above (a different digest and a
    later issue time).
  - Otherwise it waits for its own renewal, with the normal 30 s to 5 min
    backoff, every attempt counted against the 24-envelope cap.

  The descriptor-expired retry therefore cannot loop on clock skew.

## 3. Double encryption

**Decision.** Every copy is sealed to the peer's chat card although its
content is already end-to-end encrypted, because:

1. **Metadata.** Unsealed, the relay and any downloader (download is open,
   `AGENT_PACKET_RELAY_V1.md:581-586`) would read the copy's clear fields:
   Event, session, conversation, Endpoint and device IDs, the admission token,
   and on first contact the sender's signed prekey evidence, which names the
   sender (`dispatch.go:34-46`).
2. **Post-quantum confidentiality.** The relay seal is hybrid MLKEM768-X25519
   (`:897-898`); the one-to-one suite is X25519 only. Open download makes
   harvesting easy, and the seal protects recorded chat against a later
   quantum adversary while the chat key holds.
3. **No relay change.** The recipient rules expect a sealed Agent Packet
   (`:395-411`).

Cost: 1,373 bytes and one HPKE seal and open per envelope. The two layers'
keys are independent (2.2).

## 4. Size and fan-out

**One-to-one copies are never split.** A Messenger payload is at most 160 KiB
and its ciphertext 164 KiB (`messenger/pkg/eventlog/journal.go:65-69`), so
sealing adds at most 4,096 bytes. A first-contact bootstrap carries one
sender bundle, whose material is at most 4 KiB (`messenger/pkg/e2ee/bundle.go:27`),
plus an initial message of at most 4 KiB (`bootstrap.go:19`), in JSON; with
the longest network identifier in its most-escaped JSON form the measured
worst case is 16,951 bytes, so a copy's bootstrap is bounded at **18 KiB**
(18,432 bytes). Every frame also carries up to 18,432 bytes of evidence (2.5)
and possibly a card, so the relay route's largest payload is below
Messenger's own. The frame codec derives the exact worst case from the
maximal card (9,216), evidence (18,432), bootstrap (18,432) and admission
token (256), the copy object's 413 fixed bytes, the frame's 72 fixed bytes
and the 4,096-byte seal overhead: 190,464 − 50,917 = **139,547 bytes** is
the largest Event payload the relay route carries. The daemon MUST compute the worst-case frame
size from it **before sealing** and refuse an oversize delivery with
`content-too-large` (`messenger/pkg/fault/fault.go:123`), so no message key is
spent.

**Room handshake objects are split (M-R2).** MLS objects reach 1 MiB
(`messenger/pkg/group/openmls_sidecar.go:28`). A kind-3 object above one frame
is split into at most 8 parts, one packet each, sharing `object_digest`; with
the bounds of 11.1 a maximal object needs 6. The receiver (the daemon, in a
durable part store; OpenFox only verifies packets and forwards frames):

- holds parts only from current members of a room it belongs to, or from the
  authority of a room it asked to join (11.2), keyed by (packet sender,
  `object_digest`); a part with a different `part_count`, or a repeated index
  with different bytes, drops the whole object;
- caps one object at 1,056,858 bytes (1 MiB of MLS bytes plus the room-object
  header, 11.1), refusing a part whose accumulated size exceeds it;
- holds at most 4 incomplete objects and 4 MiB of incomplete parts (part
  bytes, not frame bytes) per peer,
  and at most 16 MiB of incomplete parts in total, refusing (and
  relay-acknowledging) parts beyond any cap, so filling the global cap takes
  at least four admitted peers (four maximal objects exceed 4 MiB; an honest
  authority has one in flight per room and member, 11.3);
- drops an incomplete object after 24 h 5 min;
- releases an object only when its digest matches.

Each held part is relay-acknowledged once stored; a lost or refused part
costs the sender one re-deposit of the whole object (11.3).

**Attachments stay out of band (M-R3)** in the existing encrypted attachment
store (`messenger/docs/ENCRYPTED_ATTACHMENTS.md:1-40`; up to 2,048 chunks of
1 MiB, `messenger/pkg/attachments/attachments.go:35-38`); the relay carries only
the `artifact.encrypted` event, whose Reference is already E2EE. **Rejected:
chunks through the relay**: one 16 MiB attachment fills the per-recipient
quota (`AGENT_PACKET_RELAY_V1.md:655`) and blocks task results, and its chunks
expire after the relay TTL (at most 24 h) at an offline recipient.

**Fan-out is one envelope per recipient Agent**: per device for copies, per
member Agent for room frames, each signed and sealed separately. M-R2 bounds
relay rooms to **32 members** (32 signatures per message, one envelope in each
member's quota). The per-peer, deposit-rate and mailbox arithmetic of
fan-out is in 11.2.

**Offline beyond the relay TTL** (`AGENT_PACKET_RELAY_V1.md` sections 9.6,
9.8 and 10). A relay keeps an unacknowledged envelope for its TTL, an operator
ceiling of at most 24 h: 1 h on the project's test relays, 3 h on its
production relays.

- **The carrier reports the TTL.** OpenFox reads each relay's advertised
  `max_ttl_seconds` and answers every `carrier.carry` that a relay accepted
  with `carried` and `relay_ttl_seconds`, the smallest value among the relays
  of the recipient's chat card (a relay whose description cannot be read
  counts as 86,400 until it is read). The field is required on `carried`, in
  1..86,400, and absent from every other answer. The daemon has no relay
  client of its own; the card and its relays are the carrier's.
- **One-to-one copies are re-deposited.** A copy with no verified delivery ack
  is deposited again **80 % of the reported TTL** after its last accepted
  deposit, never sooner than 10 minutes after it and never later than
  `redeposit_interval_seconds` (default and maximum 20 h; a test MAY set
  10 min to 20 h and records it). Each `carried` answer schedules the next
  generation from the TTL it reports, so a card that changes its relays
  changes the schedule at the next deposit. The new deposit has the same
  ciphertext, since a retry never re-seals (`messenger/README.md:121`), in a
  new packet and envelope under the next generation's key. Once a relay
  accepts it, the sender withdraws the previous envelope with its secret
  (`AGENT_PACKET_RELAY_V1.md` section 9.5). This runs until the delivery's own
  expiry, by default **7 days** and never beyond 30 days
  (`messenger/pkg/envelope/envelope.go:49`); then the delivery is `abandoned`
  with `retention-exceeded` (`fault.go:141`) on the owner surface. Nothing is
  lost silently.

  | Relay TTL | Re-deposit every | Deposits over 7 days | Over 30 days | Per pending copy per day |
  |---|---|---|---|---|
  | 1 h (test) | 48 min | 210 | 900 | 30 |
  | 3 h (production) | 2 h 24 min | 70 | 300 | 10 |
  | 24 h (V1 bound) | 19 h 12 min | 9 | 38 | 1.25 |

  Deposits are counted from the first one at time 0 up to, not including, the
  delivery's expiry (a re-deposit due at or after the expiry is not made). The
  generation number is a 32-bit counter. The journal records only the latest
  16 generations of a delivery. That is a bound on the record, not on what
  the relays store: every generation carries the same ciphertext, and a
  delivery ack matches the Event, session, device and ciphertext digest
  (5.2), not a generation, so an older generation still held at a relay is
  answered like any other.
- **How many generations a relay holds.** Let d be the re-deposit interval
  (80 % of the smallest TTL of the card, within the 10-minute floor and the
  configured cap). Relay R keeps generation k until its receipt plus R's own
  TTL at the latest, and generation k+j is deposited at least j·d later.
  Without a successful withdrawal, R therefore holds up to ⌈TTL_R / d⌉
  generations of one copy. That is at most two only when **every relay of the
  card has a TTL of at most 2d**, which holds whenever all the card's relays
  advertise the same TTL (2d = 1.6 TTL) and for any mix within a factor of
  1.6. A card that mixes, say, a 1 h and a 24 h relay re-deposits every
  48 minutes, and the 24 h relay would hold up to 30 generations if every
  withdrawal failed. In that case, and for a configured interval below half
  the TTL, staying within two generations relies on the withdrawal of
  generation N once N+1 is accepted (5.3, 9.5), and the per-peer cap of 24
  (section 7) is enforced by the carrier, which alone knows what is still
  stored or still being withdrawn at each relay. The daemon counts two
  envelopes per copy, each previous generation for 24 h after its deposit;
  that count defers early and can undercount for such a card, and it is not
  the authority.
- **The rate.** A shorter TTL changes how often a copy is deposited, not the
  cap. The relay's own deposit rate (60 per minute per client address) is far
  above what the cap allows: 24 envelopes re-deposited every 48 minutes is one
  deposit every 2 minutes.
- **Room application messages: loss with notice.** One deposit, kept for the
  relay TTL; a member detects the gap from the per-sender room sequence
  number inside the sealed Event (11.3; the MLS generation restarts every
  epoch and the driver does not expose it) and the runtime is told.
  Re-depositing to N members would multiply the load above by N.
- **Room Commits, Welcomes and rosters** follow the one-to-one rule with a
  per-member room ack (11.7), re-deposited until acked or 7 days: a lost
  Commit cuts a member off.

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
  future epoch waits in a bounded buffer (256 objects and 8 MiB per room,
  32 MiB in total) for its Commit; a replayed object is answered `duplicate`
  or dropped, and a too-old one is a gap, each relay-acknowledged (11.3).

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
  and the interval (at most 80 % of the reported TTL, and at most 20 h) stays
  under both the relays' retention and the 24 h minus 5 min packet lifetime.
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
  `200`/`201`/`410`, `Send`'s existing contract (`AGENT_PACKET_RELAY_V1.md:736`).
- **Crash windows.** Messenger dying after `carried` but before recording it
  retries the same generation key and gets `carried` with no new deposit.
  OpenFox dying between the Messenger commit and the relay ack sees the
  envelope listed again, gets `duplicate`, and acks.

## 6. Metadata and privacy

The operator, and since listing and download are open anyone who knows an
Agent ID (`AGENT_PACKET_RELAY_V1.md:554-586`), learns: the recipient Agent ID
and chat key ID (which, with a separate chat card, tells chat from task
traffic to someone who has seen both cards); the frame bucket, through the
envelope size of 1.1 and nothing finer; deposit,
listing, download and ack times. The operator also sees sender and recipient
IP addresses, kept per stored envelope for quota (`:703-704`), and can infer
room fan-out from one address depositing to N mailboxes at once.

**Rooms (M-R2) reveal more.** Fan-out is one envelope per member (11.2): the
operator, and anyone listing mailboxes, sees one address deposit equal-bucket
envelopes to N mailboxes in one pacing window. Repeated, that reveals the
room's size, its member Agent IDs, the authority (whose bursts precede the
others' epoch changes) and each member's posting times. The object type is
**not** hidden either: handshake objects come only from the authority, are
answered by a fan-in of room acks from every member to the authority's
mailbox (which names the authority), are re-deposited on the D10 cadence,
and large ones show as runs of 190,464-byte frames. Hidden: room ID, epoch
and content. Random member order and pacing do not meaningfully hide any of
this. Not provided: hiding membership, the authority or the object type, or
cover traffic; a room whose membership is itself sensitive should not use
the relay route in V1.

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
> usually tell which Agent sent it. For a private room it can also see how
> many members it has and which Agents they are. No relay sees which conversation a message
> belongs to, or any content. Envelopes are kept until acknowledged or at most
> for the relay's retention time (3 hours on the project's relays, never more
> than 24 hours); an unacknowledged one-to-one message is re-deposited by its
> sender before that time runs out, for up to 7 days.

## 7. Abuse and task traffic

Chat and paid task or result traffic would share one mailbox per Agent per
relay: 256 envelopes, 16 MiB, 64 per (client, recipient) (`:651-660`).

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
   holds chat for one poll interval. Only unopenable junk holds quota for the
   relay TTL (at most 24 h), as
   it already can against the rail key (`:833-838`).
2. **Messenger admission.** The first-contact default (allow-listed contacts,
   one-time invites, owner hold otherwise) applies on this route as on every
   route (`messenger/docs/OPEN_DECISIONS.md:148`), as `admission.RouteRelay`
   (`messenger/pkg/admission/admit.go:41`). An unresolvable sender is refused
   before anything is stored.
3. **Sender in-flight cap.** An honest sender holds at most **24** chat
   envelopes per peer Agent at any relay. The count includes every envelope
   still stored, including earlier generations not yet withdrawn and the
   node's own kind-2 ack and kind-4 evidence envelopes to that peer, which
   share the same relay bound; the rest stay `pending` and are not deposited.
   **The carrier enforces the 24.** OpenFox alone sees what is stored at each
   relay: its outbox holds every envelope it deposited and has not seen
   expire, including kind-2 acks, earlier generations whose withdrawal is
   still pending or failed, and envelopes kept longer by a relay with a
   longer TTL than the card's smallest. It counts all of them per peer across
   its relays (at least each relay's count, so the bound is conservative) and
   answers `carrier.carry` with the fixed refusal `peer-cap` when the deposit
   would take that count above 24. The Messenger daemon
   counts what it can see (its carried copies, each with a previous
   generation that may not yet be withdrawn, and its kind-4 envelopes) and
   defers a copy at the cap before asking. That early deferral saves a round
   trip; it can undercount (section 4) and is not the bound. The relay caps one client address at 64
   envelopes per recipient (`:656`). On shared relays, 24 chat envelopes leave
   at least 40 of that 64 for the same sender's rail deposits (tasks, results,
   acks) to the same peer. **Rooms (M-R2)** live inside the 24: at most 16
   kind-3 envelopes per peer, so at least 8 stay for kinds 1, 2 and 4, and
   kind-3 deposits are paced to half the relay's deposit rate (11.2).
4. **A malicious sender ignores its own cap.** Four IPv6 /64s at 64 envelopes
   each fill a 256-envelope mailbox. That is the open-deposit exposure the rail
   already has (`:833-838`): an availability attack that grants no authority.
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

**Status: accepted** by `messenger-relay-one-to-one-20261116.json` (four
machines, the two deployed test relays) and
`local-messenger-relay-one-to-one-20261116.json` (one host, namespaces), both
described in `AI_SERVICE_PROVIDER_IMPLEMENTATION_STATUS.md`. Item 3 was met
by the recipient's configured admission allow-list (B held no contact file of
A); invite-based first contact moved to M-R2 (decision of 2026-11-16: an
invite cannot yet be attached to an outbound copy).

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
3. **First contact** over the relay, admitted by the recipient's admission
   allow-list, and B learning A's card in band, not only from the contact
   file. (Invite-based first contact is part of M-R2.)
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
   - No kind-4 *request* is ever sent to a peer without a pending copy, and
     at most one is outstanding per peer with several pending copies.
     Publishing a descriptor sends none (checked from the chat outbox).
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

### M-R2: private rooms and invites

Record `messenger-relay-rooms-<date>.json`, same schema, design in section 11.
Three OpenFox with `tos-messengerd` on three hosts (A behind NAT with no
inbound port, B and C on separate VPSs), carriage only through the two test
relays as in M-R1 item 1; A is the authority. A node MAY share a host with a
test relay only if it reaches that relay through the relay's public TLS URL
(no loopback or local socket shortcut); the record states it, and that
node's traffic counts as cross-host, since node and relay share no state.
*Live* items MUST be run steps; *unit*
items MAY be named tests listed in `not_verified`. Test-shortened values
(part size, handshake retention, card and descriptor lifetimes) are recorded.

1. **Invites (live).** C refuses unknown senders without an invite and holds
   no allow-list entry for A or B. A presents C's unscoped invite (11.6); A's first
   copy carries it sealed, C admits it, every later generation of that Event
   is `duplicate`. The claim adds A to C's known contacts (journaled, D12):
   A's later Events are admitted, and after `contacts.remove` they meet the
   policy again. B presenting the spent token, and B presenting a second,
   expired invite, are refused, and each refusal leaves C's journal, contacts,
   rollback boundary and chat-card store unchanged.
2. **Creation and two Welcomes (live).** A adds B, then C (two Commits, two
   Welcomes, KeyPackages over the 1:1 sessions); a handshake object of C's
   (its full roster, the largest) is split by the recorded test part size
   (11.1) and reassembled. The recorded part size must let the largest
   handshake object fit in the 8-part cap: in a three-member room C's
   Welcome measures 1,874 bytes and C's full roster 22,396 bytes, so the part
   size is at least 2,800 bytes and the Welcome is not split. All three
   exchange messages, each applied once.
3. **Catch-up in epoch order (live).** C stopped, A commits twice
   (refreshes); on restart C gets the second only after acking the first,
   applies both in order, and opens buffered newer-epoch messages.
4. **Offline beyond the relay TTL (live).** B stopped beyond the 1 h TTL
   while A commits and C posts; on restart B applies the re-deposited Commit
   (generations and withdrawals recorded) and gets a `room.gap` naming C.
5. **Remove (live).** A removes C: later objects are not addressed to C
   (chat outboxes); C's driver fails to open one handed to it by the harness;
   C's room messages are refused `not-a-room-member`; A's and B's pending
   envelopes to C are withdrawn; B, for whom C is no contact, has forgotten
   C's card and room leaf credential. C's relay evidence is left to the
   evidence store's expiry (2.5): it is public, signed routing data, and every
   room path requires membership, so it is never used for the room.
6. **Authority only (unit, one live refusal).** A Commit from B is refused
   `not-authentic`; a second Commit for one epoch is refused `room-fork`.
7. **Reassembly caps (named unit tests).** Each cap of section 4, an oversize object,
   a non-member's part, inconsistent part counts and a digest mismatch are
   refused and relay-acknowledged; an incomplete object expires.
8. **States (live).** Each handshake object is `carried → delivered` per
   member on a verified room ack; application copies end `carried`.
9. **Caps and pacing (live counters).** No peer exceeds 16 kind-3 or 24 chat
   envelopes; kind-3 deposits stay within 30 per minute per relay.
10. **Sizes (live, production cut).** Every kind-3 frame cut by the
    production rule is its smallest bucket, non-final parts are 190,464
    bytes, stored envelopes match 1,373 + F + 4·⌈B/3⌉. Frames cut at a test P
    are only checked to be buckets. A separate local record
    (`local-messenger-relay-rooms-<date>.json`, one host, a local relay)
    carries a production-cut largest valid object (6 parts, 11.1) and checks the same.
11. **Nothing readable (live).** As M-R1 item 9, also searching for the room
    ID, members, KeyPackages, roster contents and the invite token.
12. **Room admission stays in the room (live, D11).** B, a member of the room
    but no contact of C, sends C a 1:1 copy not naming the room; it meets C's
    normal policy (refused), while B's room messages are admitted. A room
    Event whose packet sender is not in the latest committed roster at its
    epoch is refused (unit).
13. **Owner-only management (unit, D13).** The runtime principal is refused
    `rooms.create`, `rooms.add`, `rooms.remove`, `rooms.join`,
    `invites.present` and `contacts.remove`.
14. **Catch-up beyond the authorization window (live, 11.3).** A issues
    authorizations with a test-shortened expiry (standing in for 24 h) and a
    test handshake retention W; C is stopped longer than that expiry but
    less than W while A commits twice; C then applies both in order and
    exchanges messages, and a header older than W is refused. Objects are
    byte-identical across generations.
15. **Crash windows (live, like M-R1 item 6).** C killed during a handshake
    between relay ack and room ack, and A killed between the driver's Commit
    and the fused record: after restart each room is usable, the exact repeat
    is `duplicate`, A's staged output is either published once or discarded,
    and no member forks.
16. **Renewal among non-contacts (live, 11.2).** With test-shortened card and
    descriptor lifetimes, B and C (no contacts) keep exchanging room messages
    across several expiries, in steady state renewed only by kind-3 part 0;
    a kind-4 pull may occur only (a) for a peer whose evidence went stale
    while it was offline (in the record: inside an offline window of the run
    or within one re-deposit interval after it ends), or (b) when the
    requester's held copy of that peer's evidence had already expired at
    send time because the two exchanged nothing for longer than its
    lifetime, at most one pull exchange per peer per expiry, after which
    kind-3 part 0 renews it in band. The record classifies every kind-4
    pull under (a) or (b), naming the expiry case (b) relied on; any other
    pull fails the item.
17. **Driver bounds (unit).** The 512 KiB state bound holds, with at least
    20 % headroom, for the worst case at 32 leaves with `max_past_epochs(2)`,
    every leaf carrying a maximal (128-byte) leaf identity, never a short test
    name: every other member's ratchet holding the 8 skipped keys the
    tolerance keeps in the current and both retained epochs, and a sender
    jumping the 1,000 generation forward distance; it fits 2 state chunks, and
    an operation whose state would exceed the bound is refused; a leaf
    identity of any other length, a leaf credential whose digest differs from
    the identity's, one not signed by the finalized Endpoint, one whose leaf
    signature key is not the leaf's, and an expired one are refused; a roster
    of 31 maximal entries, leaf credentials included, fits the body bound; a maximal fused record
    (32 members, maximal authorization and IDs) encodes within its 8,192-byte
    cap; a record over the cap is refused on write and on read; a chunk or
    state digest mismatch fails the read closed; garbage collection keeps an
    older Commit and a roster named only by outbox heads, deletes
    superseded state chunks, and deletes nothing when a root is unreadable.
18. **Roster to an already-joined member (live, 11.2 case b).** B has
    joined; A adds C; B applies the Add Commit, accepts the roster of added
    members, learns C's card and evidence from it, and exchanges a room
    message with C (no contact between them); the roster is answered
    `accepted`, not `room-fork`. Unit: a roster naming an Agent not in the
    committed membership, one from a non-authority, one for an epoch above
    current, and a second different roster for the same epoch are refused;
    a late roster for current − 1 or current − 2 is accepted and teaches only
    entries still members now; a roster with one stale entry (failing
    `VerifyKeyCard` or `CheckPeer`) skips that entry's card and evidence
    but learns its valid leaf credential, learns the rest and answers
    `accepted`; an MLS-only refresh Commit (room epoch unchanged) is applied,
    not refused as a fork; an authority crash between staging and the fused
    write, and right after it, leaves the Add's rosters delivered once, after
    their Commit or Welcome.
19. **Room end (live, D18).** With a test-shortened credential lifetime,
    the room ends at A's leaf-credential expiry. At the end, B and C refuse
    new Commits, Welcomes, rosters and application objects for the room with
    `room-ended` and an owner notice. A stops its queues, and the room's
    stores become collectable after the handshake retention. Unit: A refuses
    to add a member whose leaf credential ends before the room's end, and a
    receiver refuses a roster entry or a leaf whose credential does; a
    header naming another end time than the room's is refused. A sender
    stops at end − skew; the authority makes no handshake in the last d
    before it; a receiver refuses at end + skew; an application object
    sealed before the end and arriving after end + skew is a gap with the
    notice. `room_ends_at` must equal the authority's leaf-credential
    expiry: a joiner checks the Welcome's value against the credential its
    `room.invite` carried, and a mismatch is refused `not-authentic`. Retirement at
    end + retention + skew deletes the outbox heads, part store, buffer and
    receive state, then the credential list, then the fused record last; a
    crash at each step is finished at restart, and garbage collection then
    reclaims what nothing names.
20. **Credential storage and holding (unit, 11.8).**
    - A learned leaf credential, its list and a fused write naming the
      list's digest are durable before the roster's room ack. A crash after
      the ack leaves the credentials rooted across a restart; a crash
      before the fused write leaves the roster unacknowledged and it is
      learned again.
    - The fused record's credential-list digest is a garbage-collection
      root: an unreadable list deletes nothing.
    - Remove deletes the removed member's credential.
    - An object from a current member whose credential is not yet known is
      held in the future-epoch buffer and opened once the roster arrives.
    - That object is refused `not-authentic` only after a roster arrived
      without a verifying entry for the member.
    - A first-time joiner authenticates its Welcome with the authority's
      leaf credential carried in the `room.invite`: an invite whose
      credential does not verify against the finalized delegation (wrong
      Agent, Endpoint, network, signature or window) is refused
      `not-authentic` and records no pending join; the verified credential
      survives a restart inside the pending join; a Welcome whose sending
      leaf identity names another digest, or whose leaf signature key differs
      from the credential's, is refused `not-authentic`; the Welcome's
      install roots the credential before the pending join ends, and the
      full roster's authority entry has the same digest.
    - A roster entry whose card or evidence is stale but whose leaf
      credential verifies contributes that credential (stored, listed and
      rooted before the room ack); only the card and evidence are skipped.
      An entry whose credential fails is skipped whole.

Not proven: more than 3 live members (32 is a unit bound), multi-device
(D3), concurrent authorities, authority transfer over the relay, fork
recovery (11.5), hiding membership, the authority or object types (section
6), quota isolation (D2), post-compromise security for members (D15).

### M-R3: attachments

A `text/plain` attachment above 16 MiB through a core-team HTTPS attachment
store while its reference event crosses the relay; the recipient fetches,
verifies every tag and admits it through the scanner; no chunk ever appears in
relay state. Not proven: a store run by anyone else, other media types.

## 9. Code changes

### 9.1 M-R1

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
   one frame plus idempotency key; `carried` with the card's smallest relay
   TTL in `relay_ttl_seconds`, `retry` or a fixed refusal),
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
   - Relay-only publication signs a descriptor whose route is the
     delegation's ADNL identity, with no HTTPS endpoint (2.5).

   `CheckPeer` replaces `Manager.Ensure` on `RouteRelay` in three places:
   - on receive, at `inbound.go:70` and `:160`;
   - on send, before every content seal and every re-deposit, with a failure
     holding the copy `pending` and starting the kind-4 request (in
     `pkg/dispatch`, item 4);
   - on reply, at `daemon.go:415`.

   `CheckPeer` gates kinds 1 and 3 only; kinds 2 and 4 need only the peer's
   card. `CommitPeer` writes only newer evidence.

   Also: the kind-4 pull (at most one outstanding request per peer while any
   content copy is held `pending`, on the earliest copy's schedule; a response
   to an admitted requester, at most one per peer and own descriptor per hour;
   the sender's card mandatory in both; never sent unprompted); the single
   "newer" predicate and the publisher's strictly-increasing issue time; the
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
   `transport.go:25-27`), `Send`, answer `carried` only on acceptance, with
   the smallest advertised `max_ttl_seconds` among the recipient card's
   relays (each relay's description read and cached with a bounded refresh;
   86,400 for a relay not yet read); and
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

### 9.2 M-R2

Same boundaries. **`ai/protocol`: none** (the zero-Capability packet and the
seal already carry any frame; nothing new is resolved on chain).
**Relay program, relay spec: none.**

**`ai/messenger`**

1. `pkg/relayframe`: accept kind 3 (`frame.go:28-30`, `:286-297`); the
   part rules of 1.1 (card and evidence only in part 0, digest checked per
   part only when `part_count` is 1, `frame.go:280`); the room-object codec
   and fixed cut of 11.1 with a test part size (an empty header for an
   MLS-only refresh Commit); `SplitRoomObject` and a
   bounded `Reassembler`; the room ack (11.7) with
   `canon.DomainRelayRoomAck`; the roster codec with each entry's leaf
   credential (11.1); vectors for a maximal
   6-part object, each refusal of section 4, and the room ack (with the
   epoch authenticator); `internal/canon` domains for the room object, room
   AAD and room ack.
2. `rust/openmls-driver` and `pkg/group`: `max_past_epochs(2)`, an
   out-of-order tolerance of 8 and a maximum forward distance of 1,000 in
   both group configs (`src/main.rs:335-338`, `:432-434`). A message more
   than 8 generations behind its sender's ratchet is a gap (11.3). A message
   ahead derives the skipped secrets but keeps only the last 8, so the
   forward distance bounds the work per message, not the state. `open` and
   `apply` return the sender's credential identity and leaf signature key
   (`:443-465`, `:484-520`; for a past-epoch message, the key the sealing
   leaf had in that epoch, which the driver keeps for the two retained
   epochs) and `inspect` the epoch authenticator; the Go
   `Driver` gains those results. A `signer` operation makes a leaf signature
   key before any identity exists and `identity` then makes the KeyPackage
   for that signer, because the identity names a credential that names the
   key (11.8). `join` returns the leaf that authored the Welcome (index,
   identity and signature key), which the joiner requires to be the leaf
   its invite's authority credential binds before anything is installed
   (11.3). A read-only `members` operation returns
   (leaf index, identity, signature key) for every leaf, used when learning
   roster entries and when building per-member pins (11.8). The driver keeps
   its generic
   4,096-byte identity limit (the lab uses other identities); the Go relay
   room path (`pkg/group` and the room controller) refuses any leaf identity
   that is not exactly the 128-byte compact binding of 11.2. A vector test
   of the 512 KiB state bound covers the worst case at 32 leaves with
   `max_past_epochs(2)` and maximal leaf identities of the costliest byte
   values (item 17).
3. `pkg/room`: a relay-route authorization check (11.3: signature against
   the delegation as finalized now, window issued + retention + skew);
   `pkg/group`: the leaf credential and compact leaf identity of 11.2
   (codec, Endpoint signing, strict decoding, `canon.DomainMLSLeafCredential`);
   `pkg/directory`: the `CheckPeer` pin taken from a member's verified leaf
   credential (Endpoint and device) for kind 3, beside the session pin of 2.5.
4. `pkg/eventlog`: the fused room and MLS record (≤ 8,192 bytes, digests
   only, now also naming the room's leaf-credential list and its end time,
   11.8, D18) with
   exact-repeat no-op (11.3, replacing the two writes for MLS rooms) and its
   bound test; content-addressed leaf-credential records and the per-room
   credential list (11.8); staged MLS state chunks (≤ 2 of 262,144 bytes),
   delegation records and the memberships of the two earlier room epochs by
   digest; a room outbox of chunk records, with
   the Commit, Welcome and an Add's rosters staged under the `CommitRef`
   before the fused record and queues rebuilt as (Commit or Welcome, then
   roster) on restart (11.7); the fused record's
   KeyPackage and Welcome refs and retained epoch authenticators, chunk and
   state digest verification on read; garbage collection rooted at every
   fused record and room-outbox head, failing closed, plus deletion of
   superseded state chunks after each fused write; a durable part store and a future-epoch buffer with the
   bounds of section 4 and 11.3 (per-sender share, k = 4); the committed
   membership of the last 3 epochs; applied Commit and Welcome digests by
   MLS epoch (last 64) and applied roster digests by room epoch (last 64),
   with the roster window [current − 2, current] and per-entry skipping
   (11.2, 11.3); and
   received application digests (24 h 5 min); per (room, sender) sequence
   state and `room.gap` records; pending joins (each a garbage-collection
   root, since it names the joiner's staged identity state, and each
   holding the authority's verified leaf credential from its invite), with
   the implementation bounds of 11.3; presented invites with
   `AdmissionToken` on `Delivery` (`delivery.go:109-144`); the unswept
   invited-contact list; schema bumps, no migration.
5. `pkg/dispatch`: set `Message.AdmissionToken` on every delivery to the
   invited Agent until one settles `accepted` (`dispatch.go:920-930`);
   refuse a room-addressed kind-1 copy on the relay route.
6. `pkg/payload`, `pkg/envelope`: `room.invite` gains the authority's leaf
   credential (11.6, bound 512 bytes); `room.key-package` (a `DeviceCredential`
   and the joiner's leaf credential, 11.2)
   in the registry with class `room` (`registry.go:71-74`,
   `envelope/event.go:132-135`); a `sequence` field in `RoomMessage`
   (`kinds_more.go:795-800`).
7. `pkg/fault`: `room-epoch-gap`, `room-fork`, `room-fork-suspected` and
   `room-roster-conflict`, with their dispositions and peer visibility.
8. `pkg/admission`: room-scoped admission (11.2, D11), after the room
   overlay (`admit.go:304-317`) and with `JudgeMember`, checking the packet
   sender against the committed membership at the Event's epoch; on a spent
   token, the policy re-run without it; after a successful claim
   (`admit.go:383-392`, `eventlog/admission_invite.go:183`) an idempotent
   journaled contact-add step before the Event's commit (D12), with
   `ContactPolicy.Admits` reading that list beside the config roster
   (`admission/policy.go:174-192`; blocked still wins); refusal `not-authentic`
   of a room object whose sender's leaf credential has expired (11.5).
9. `pkg/localapi`: owner-only (D13, in the principal table,
   `api.go:229-237`) `rooms.create`, `rooms.add`, `rooms.remove`,
   `rooms.join`, `invites.present`, `contacts.remove` (invited contacts);
   runtime `rooms.list`, `rooms.gaps`;
   `outbox.compose` with a `room_id` of an MLS room takes the kind-3 path.
10. `pkg/carrierapi`: `carrier.room-cards` (admit or forget chat cards
    learned from a roster) and `carrier.withdraw`; `carried` for kind-3
    parts; `admitted` for an admitted kind-3 object or stored part (11.2);
    `peer-cap` also at 16 kind-3 envelopes. An admission carries the room's
    end (D18) in `room_ends_at_unix`, copied from the fused record's
    `room_ends_at`; it is required on an admission and refused on a forget
    and on every other operation. Both the client and the server refuse an
    end later than now + 30 days + 1 h, the longest leaf credential plus the
    largest clock-skew bound (`invalid-request` at the server, before the
    carrier stores anything). The carrier drops the room's admissions on its
    own at end + 1 h (`RoomEndSlackSeconds`), so a daemon that stopped
    before its forget (11.8) cannot leave them behind. The slack is the
    largest clock-skew bound a daemon accepts
    (`admission.max_clock_skew_seconds` ≤ 3,600 in daemon config, the
    local API's room clock-skew bound ≤ 1 h), and every member refuses the
    room's objects from end + skew on (11.8), so the sweep never drops an
    admission the daemon still uses.
11. `pkg/daemon` and config: a room runtime beside `relayRuntime`
    (`relay.go:88-139`): the joining flow, the authority's per-member
    in-order queue (stopped on a `rejected` ack), handshake priority and the
    507 backoff, fan-out with per-recipient `CheckPeer`, the receive order of
    11.3, `CommitPeer` on part-0 evidence, `Deliver` for kind 3
    (`relay.go:615-622`), room acks, removal notices, Remove's withdrawals
    and card forgetting; the test settings `room_part_bytes`,
    `room_handshake_retention_seconds` and `room_authorization_seconds`,
    refused by a production build; and `relay_carriage.own_relay_max_ttl_seconds`
    (1 .. 86,400, default 86,400), the largest TTL of this node's own chat
    relays that T of 11.3 is derived from.
12. `docs/RUNNING.md`, `docs/ROADMAP.md`: rooms over the relay, invites, and
    the limits of D15.

**Replacements in merged or in-review code** (made in the room runtime
part, C3):

- `group.BasicCredentialIdentity` (`pkg/group/mls_encoding.go:29`) and the
  Add path's KeyPackage validation (`mls_profile.go:465`,
  `openmls_sidecar.go:190-204`) move to the 128-byte compact identity.
- The roster codec (`pkg/relayframe/room.go:363-427`) and
  `internal/vectors/testdata/relay-room-vectors.json` gain each entry's
  leaf credential. This is a wire change, with no migration before launch.
- The room-object header codec (`pkg/relayframe/room.go`) and its vectors
  gain the room's end time (D18), and `pkg/fault` gains `room-ended`.
- C1's `room.key-package` payload gains the leaf credential, and the
  `room.invite` payload gains the authority's leaf credential (11.6).
- C2's (#34) pending-join record gains the authority's verified leaf
  credential from the invite (11.6, 11.8), and its roster learning keeps an
  entry's verified credential when only the card or evidence is stale
  (11.2).
- In C2 (#34), the helpers for the old identity are removed, and
  `directory.LeafPin` takes the leaf credential instead of the
  DeviceCredential.

**Still to change in the room runtime part (C3)**, beyond the items above:

- D11's credential input (`admission.RoomCarriage.SenderCredential`)
  changes from `group.DeviceCredential` and `CredentialSigningBytes` to the
  member's leaf credential, with the same checks: Agent, Endpoint, device
  and network, the Endpoint signature, and the validity window.
- `BufferRoomObject` also holds objects at the current epoch (e = r) from a
  member whose leaf credential is not yet known, counted against the room
  and sender shares, until the roster that teaches it arrives.

**`openfox`**

1. `pkg/servicebridge/relay_chat.go`: `carrier.carry` accepts kind 3
   (`relay_chat.go:331`); a per-peer count of kind-3 envelopes (refuse above
   16) beside the 24, on the same listing refresh (`:36`, `:471-481`,
   `:531-580`), with the frame kind recorded in each chat outbox record
   (including records that hold no packet yet) so the count needs no
   decoding; a per-relay token bucket for kind-3 deposits (30 per minute,
   burst 16); kind-3 application packets expiring at now + the card's
   smallest TTL (as kind 4, `:348-357`); inbound kind 3 to
   `carrier.deliver`, learning part 0's card on `admitted` (`:716-722`), and
   the room ack to `carrier.delivery-ack` (`:682-691`);
   `carrier.room-cards` against the chat peer store (cards verified with
   `VerifyKeyCard`; forgetting never removes a card stored under another
   admission; each room admission stored with its room end and dropped by a
   sweep at end + 1 h, as a forget would drop it); `carrier.withdraw` through `RelayTransport.Withdraw`
   (`relay_transport.go:1207`).
2. CLI: `openfox chat room create|add|remove|join|list` and
   `openfox chat invite present`, each through the owner socket;
   `openfox chat contact import --invite` presenting the invite with the
   contact file.
3. Status and preflight entries for rooms, invites and the kind-3 counters.
4. `scripts/messenger-relay-three-host-rooms-e2e.{sh,py}` producing the M-R2
   record, and a one-host variant producing the local production-cut record.

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

M-R2 decisions (2026-11-16, delegated by the owner):

- **D11. Room-scoped admission, narrowly.** Once the owner has joined a room,
  an Event is admitted without the allow-list only if it names that room, it
  is room content (kind `room.message` or `artifact.encrypted`, the kinds a
  room's application object carries, 11.1), its packet sender is a member in
  the authority's latest committed roster at the Event's epoch, and the room
  and peer caps still apply. Any other kind, even from a member and naming
  the room, meets the normal policy. It grants no 1:1
  admission, and a member's card is stored only under the admission and
  roster rule (11.2). Reason: joining is the owner's explicit consent to hear
  from that room's members; scoping it to the room leaves 1:1 admission
  unchanged.
- **D12. A claimed invite makes a contact.** The claim adds the sender Agent
  verified at claim time to the known contacts, journaled and removable with
  `contacts.remove` (11.6). Reason: an invite exists to establish a contact;
  admitting one Event and holding the rest defeats its purpose.
- **D13. Room management is owner-only in V1.** Create, add, remove and join
  are owner operations; the runtime may send and read room messages only.
  Runtime-managed rooms are a later change behind an explicit owner policy
  (for example only existing contacts, a member cap). Reason: membership
  changes affect privacy and the spam surface; start closed.
- **D14. `max_past_epochs` is 2.** Reason: it covers messages in flight
  across one Commit at little forward-secrecy cost; anything older already
  gets a gap notice (11.3).
- **D15. No post-compromise security for members in V1.** Members never
  commit, so a compromised member leaf is not healed; a room lives no
  longer than its authority's leaf credential (D18), so no member credential
  needs renewing inside a room. Member Updates are a
  later change.
- **D16. Catch-up authorization window and journal shape** (review of ai #28).
  On the relay route a header authorization is checked against the
  delegation as finalized now, within issued + handshake retention + skew,
  never re-signed per generation; the room and MLS advance is one journal
  write of a small fused record (≤ 8,192 bytes) holding only digests,
  membership, authorization and `CommitRef`; the MLS state, delegation and
  Commit output are staged first as chunk records it names, and unnamed
  staged records are deleted on restart (11.3, 11.7). Reason: a record near
  its bound becomes unreadable once a field is added.
- **D18. A room ends when its authority's credential does.** A room's end
  time is fixed at creation: the expiry of the authority's leaf credential
  (at most 30 days). The fused record records it, and so does every header
  the authority sends (Commits that change the room epoch, Welcomes and
  rosters). The authority adds a member only if the member's leaf credential
  is valid at least until the room's end. Receivers refuse a roster entry or
  a leaf whose credential expires before it, and a header naming another
  end. At the end, every member stops accepting new Commits, Welcomes,
  rosters and application objects for the room: they are refused with the
  fixed code `room-ended` and an owner notice. The authority stops its
  queues, and the room is retired after the handshake retention (11.8). The
  end is applied with the clock-skew bound at both ends, as D16's window is,
  and in-flight objects are handled as 11.8 states. To continue, the owner
  creates a new room. Reason (first
  principles): a room that never outlives any member's credential has no
  expiry inside it to store, distribute or renew. This matches task-scoped
  Agent rooms. Renewal is deferred to M-R2.1 (11.8).

## 11. M-R2: rooms and invites

**What exists** (paths under `messenger/`): one-authority membership epochs
(`pkg/room/authority.go:24-29`, `pkg/eventlog/rooms.go:95`); an MLS ledger
whose controller persists state before returning any Commit, Welcome or
ciphertext (`pkg/eventlog/mls_controller.go:3-6`, `:65-125`); the OpenMLS
sidecar and Rust driver (one Welcome per Commit,
`rust/openmls-driver/src/main.rs:400-404`); the 32-Agent, 64-leaf bound
(`pkg/group/mls_profile.go:37-40`); the `room.invite` payload
(`pkg/payload/kinds_more.go:700-705`). The daemon drives no MLS: only the lab
proxy does, with all states made on one host (`pkg/mlslab/bootstrap.go:18-20`),
and `room.message` is a pairwise copy (`pkg/dispatch/dispatch.go:465-467`).
M-R2 wires MLS rooms into the daemon, with kind 3 as their only carriage.
Paths below without a repository are under `messenger/`.

### 11.1 Room objects and the split

**Decision.** A kind-3 object is one room object:

```text
room_object =
  D("tos.messaging.relay-room-object.v1")   35 bytes
  object_type   u8   1 = Commit, 2 = Welcome, 3 = application, 4 = roster
  room_id       32   the raw digest of the room_ ID
  room_epoch    u64  the epoch the object produces (1, 2), was sealed in (3),
                     or describes (4)
  mls_epoch     u64  likewise for the MLS clock (group.Clock, mls_profile.go:88-91)
  header_length u16  0 .. 8,192
  header        a Commit or Welcome that changes the room epoch, and every
                roster: the Membership of that epoch and its
                MembershipAuthorization (room/authority.go:41-50);
                an MLS-only refresh Commit and an application object: empty
  body_length   u32  1 .. 1,048,576
  body          the MLS Commit, Welcome or PrivateMessage; or the roster
```

Fixed bytes are 35 + 1 + 32 + 8 + 8 + 2 + 4 = 90, so an object is at most
90 + 8,192 + 1,048,576 = **1,056,858 bytes**. A roster lists the members'
entries in ascending Agent order:

```text
roster_entry =
  agent              70   agent_ ID
  card_length        u16  1 .. 9,216
  card               the member's chat card
  evidence_length    u16  1 .. 18,432
  evidence           the member's relay identity evidence (2.5)
  credential_length  u16  1 .. 512
  credential         the member's leaf credential (11.2)
```

so a roster is at most 31 × (70 + 2 + 9,216 + 2 + 18,432 + 2 + 473) =
31 × 28,197 = **874,107 bytes**, inside the 1,048,576-byte body bound with
174,469 bytes to spare (the codec's 512-byte credential bound adds at most
31 × 39 = 1,209 more). A roster is separate from the Welcome because a
Welcome with its ratchet tree plus a full roster could exceed 1 MiB.
The entry's card is the one the authority keeps for that member (11.8,
**Member cards**); an entry is built only from a stored card inside its
validity window, so no roster goes out with an expired card.

**The header** (normative; room ID and room epoch come from the object, and
the membership digest is recomputed from them and the members):

```text
room_header =
  member_count  u8   1 .. 32
  members            agent_ IDs, 70 bytes each, ascending
  network_id    u16-prefixed, 1 .. 128 bytes
  genesis_root  32
  genesis_file  32
  authority     agent_ ID (70) and mep_ ID (68)
  issued_at     u64
  expires_at    u64
  signature     64
  room_ends_at  u64  the room's end time (D18), the same in every header
```

The network-ID bytes are exactly the authority delegation's `network_id`
(and so its characters): an authorization whose network differs from the
delegation's is refused. A decoder re-encodes the header and refuses any
other encoding of the same values. The largest valid header is therefore
1 + 32·70 + 2 + 128 + 32 + 32 + 70 + 68 + 8 + 8 + 64 + 8 = **2,661 bytes**,
and the largest valid object 90 + 2,661 + 1,048,576 = **1,051,327 bytes**.
The room end time MUST equal `expires_at` of the authority's leaf credential,
which the authority's Endpoint signs and which is identical in every roster.
That signature authenticates it. It stays out of the MembershipAuthorization
preimage, whose merged format is unchanged. A receiver requires the equality
against the authority's verified leaf credential: a joiner checks its
Welcome's value against the credential its `room.invite` carried (11.2,
11.8), which its full roster later confirms (the same digest); a member
already joined holds that credential since its own join. A mismatch, or a
later header naming another end, is refused `not-authentic`. The
codec limits stay 8,192 header bytes and 1,056,858 object bytes: a safe upper
bound that no valid object reaches.

**The cut is fixed, not size-driven.** The frame's fixed part is 72 bytes
(29 + 3 + 32 + 2 + 2 + 4, `messenger/pkg/relayframe/frame.go:53-58`). Part 0
carries the evidence and, while unacknowledged, the card; the other parts
carry neither (1.1). So part 0 always holds the first
c0 = 190,464 − 72 − 9,216 − 18,432 = **162,744** object bytes and every later
part c = 190,464 − 72 = **190,392**, the last part the rest:

| Parts n | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---|---|---|---|---|---|---|---|
| Object bytes up to c0 + (n−1)·c | 162,744 | 353,136 | 543,528 | 733,920 | 924,312 | 1,114,704 | 1,305,096 | 1,495,488 |

A maximal object takes **6 parts**; the 8-part limit leaves 438,630 bytes
spare and decoders still refuse any object above 1,056,858 bytes. Cut points
do not depend on the actual card or evidence size, so every re-deposit
generation has byte-identical parts and the same digest although part 0's
card is dropped once acknowledged. Every non-final part is exactly the
190,464-byte bucket; a full part stores 1,373 + 5,432 + 4·63,488 = 260,757
bytes at a relay (≤ 262,144). The last part is padded to its bucket (6). The
largest valid object (1,051,327 bytes) is five 190,464-byte frames and a last
part of 127,015 object bytes, a 127,087-byte frame in the 128 KiB bucket:
5 · 260,757 + (1,373 + 5,432 + 4 · 43,691) = **1,485,354 stored bytes per
member**. (An object at the 1,056,858-byte codec limit, which no valid header
reaches, would be six 190,464-byte frames with a last part of 132,546 bytes
and 1,564,542 stored bytes; that figure is an upper bound, never reached.)
**Test part size:** a test build MAY set
`room_part_bytes` P in 1,024 .. 162,744, cutting every part of a *handshake*
object at P (application objects keep the production rule); an object that
would need more than 8 parts at P is refused at the sender (staged, never
deposited, abandoned at the handshake retention), so P must let the largest
handshake object fit in 8 parts: a roster entry is about 11 KiB (a
three-member room's full roster to C measures 22,396 bytes, P ≥ 2,800). The
record states P, and a production build refuses the setting.

**Application objects are never split.** Their Event plaintext is at most
131,072 bytes, checked before the MLS seal (as 4 does for copies, refused
`content-too-large`); with a PrivateMessage overhead bound of 4,096 bytes
(vector-tested) the body is at most 135,168 ≤ 162,744 − 90. The plaintext is
the canonical Event (kind `room.message` or `artifact.encrypted`) whose
`RoomMessage` gains a per (room, sender) `sequence`, and the MLS AAD binds
D("tos.messaging.room-aad.v1"), room ID, room and MLS epoch, the sealing
epoch's MLS epoch authenticator (new driver output), sender Agent and Event
ID.

**Rejected:** size-driven cuts (parts would change between generations) and
evidence in every part (up to 7 × 27,648 bytes per object for nothing).

### 11.2 Joining and fan-out

**Joining (1:1 first).** The authority's owner calls `rooms.add` (B), which
sends `room.invite` to B as a kind-1 copy over their 1:1 session (an
allow-listed contact, or an invite, 11.6). The `room.invite` payload carries
the authority's own leaf credential (at most 473 bytes, 11.8), so the joiner
holds a verified credential of the authority before the Welcome arrives:
B verifies it against the authority's finalized delegation when it records
the pending join, and stores it with that join (11.8). B's owner calls `rooms.join`: B's
daemon makes its leaf credential (below), has its Endpoint sign it, and makes
an MLS identity and KeyPackage (`openmls_sidecar.go:111`) whose identity is
the compact binding naming that credential. It has the Endpoint sign a
`DeviceCredential` (`mls_profile.go:150-160`; KeyPackage ≤ 64 KiB, `:33`)
with the same window, and returns both as a new kind-1 event
`room.key-package`, within the 139,547-byte copy bound. Both events leave `Event.RoomID` empty and
name the room only inside their payload, so the room-addressed kind-1 refusal
below does not apply; `room.key-package` is registered in the payload
registry with class `room`, like `room.invite`
(`pkg/payload/registry.go:71-74`, `pkg/envelope/event.go:132-135`). The
authority checks it with
`BindDeviceCredential` (`mls_profile.go:280`) against finalized state;
requires the leaf credential to name the same Agent, Endpoint, device,
device-set digest, leaf signature key and window, its signature to verify,
and the KeyPackage's identity to be the compact binding of it; and then
commits the Add (its owner already decided). The joiner's daemon always
carries its chat card in part 0 of the `room.key-package` frame, whether or
not the authority has acknowledged it, and the authority keeps that card
for the Add's rosters (11.8, **Member cards**); a frame with no card, or a
card failing those checks, refuses the KeyPackage and records nothing.

**Leaf identity and leaf credential.** The identity in a leaf's MLS
BasicCredential is copied into the ratchet tree and into every retained
epoch, so it is minimal and has a fixed size. The full credential is needed
once per member and travels in rosters:

```text
leaf_identity =                          exactly 128 bytes
  agent                   32   raw digest of the agent_ ID
  endpoint                32   raw digest of the mep_ ID
  device                  32   raw digest of the dev_ ID
  leaf_credential_digest  32   SHA-256(leaf_credential)

leaf_credential =
  D("tos.messaging.mls-leaf-credential.v1")   37 bytes
  network_id          u16-prefixed, 1 .. 128 bytes (the delegation's)
  genesis_root        32
  genesis_file        32
  agent               32   raw digest of the agent_ ID
  endpoint            32   raw digest of the mep_ ID
  device              32   raw digest of the dev_ ID
  device_set_digest   32   the device set the device was current in
  leaf_signature_key  32   Ed25519, the leaf's MLS signature key
  cipher_suite        u16  0x0001
  issued_at           u64
  expires_at          u64  issued < expires ≤ issued + 30 days, and not
                           after the delegation's expiry
  signature           64   the Endpoint's Ed25519 signature over every
                           byte before it
```

The largest leaf credential is 37 + 2 + 128 + 32 + 32 + 5 × 32 + 2 + 8 + 8 +
64 = **473 bytes**. Decoders refuse trailing bytes, any other encoding of the
same values and an identity that is not exactly 128 bytes. The leaf
credential does not name the KeyPackage: the KeyPackage carries the
identity, which names the credential's digest, so a reference back would be
circular. It is bound to the leaf by the leaf signature key, which the leaf
node carries and is signed with.

How a leaf credential is issued, distributed, verified, stored and
revoked is section 11.8; every other section refers to it. Create, add, remove and join are
owner-only (D13); the runtime only sends and reads room messages. A Welcome
is accepted only from the authority whose `room.invite` the owner accepted
with `rooms.join` (several Agents may have invited this installation to one
room ID; the join names one, and the others are discarded), and only if the
Welcome's sending leaf identity (the authority's leaf) names the digest of
the leaf credential stored with that join, with the same Agent, Endpoint
and device, and that leaf's signature key is the credential's.

**Accepting a roster** for room R, in both cases below, requires that its
packet sender is R's authority, that its header carries a valid
MembershipAuthorization (relay-route window, 11.3) for room epoch E, that E
lies in [current − 2, current] of the receiver's committed room epochs (the
memberships it retains for D11; normally E is current, because the in-order
queue delivers the Commit or Welcome first; a newer E answers
`room-epoch-gap`, an older one is dropped silently and relay-acknowledged),
that the header's membership digest matches the committed membership of E,
and that every entry names a member of E other than the receiver, so a
roster can never add an Agent the Commits did not. Only entries that are
still members now are learned, under D11, so a late roster degrades
gracefully. An entry's leaf credential is judged independently of its
rendezvous data, because it verifies against the finalized delegation and
the leaf, not against the card or evidence (11.8): an entry whose card fails
`VerifyKeyCard` or whose evidence fails `CheckPeer` still contributes its
leaf credential if that verifies, and only the stale card or evidence is
skipped (the kind-4 pull repairs it later). The converse does not hold: an
entry whose credential fails is skipped whole, because its evidence is
pinned to that credential's Endpoint and device. The rest are learned and
the roster is answered `accepted`, so one stale entry cannot freeze the
queue, and one roster is the only delivery a credential needs.

- (a) **During a pending join:** R's authority is the one named in the
  `room.invite`; the roster is accepted once the Welcome has been applied
  (the join then ends and E is the Welcome's epoch). Its authority entry
  confirms the credential the `room.invite` carried: the authority's leaf
  identity names that credential's digest, so an entry carrying any other
  credential fails the digest check of 11.8.
- (b) **Already joined:** R's authority is the current one of the
  receiver's `RoomLedger`; this is the roster of added members that follows
  an Add Commit.

**Senders.** Only the authority sends Commits, Welcomes and rosters (11.5):
a Commit to every member but itself, and once to a removed member (11.4); a
Welcome to each joiner, then a full roster; after an Add, a roster of the
added members to the others. The rosters of an Add are built before the
authority's fused write and staged with its Commit and Welcome under the
`CommitRef` (11.7), and the authority never queues a roster for epoch E
after a Commit for E + 1. Any member sends application objects to every
other member of the epoch it seals in.

**One envelope per member per part**, each signed and sealed separately.
Kind 3 is content, so before every first deposit and re-deposit the sender
runs `CheckPeer` (2.5) on that member's stored evidence, pinned to the
Endpoint and device of the member's verified leaf credential (the one its
leaf identity names by digest); a member failing it
gets nothing and the kind-4 pull starts, while the others proceed. Members
learn each other's cards and evidence from rosters, checked with
`VerifyKeyCard` and `CheckPeer` and committed (`CommitPeer`,
`carrier.room-cards`) only after the Welcome or Commit that made that Agent a
member is applied: an extension of 2.3's admission rule; a roster is
rendezvous, not authority.

**Renewal among non-contacts.** Two members that are not contacts renew each
other's cards and evidence only through room traffic: `carrier.deliver`
answers `admitted` for an admitted kind-3 object, complete or a stored part
of it; OpenFox then learns part 0's card under the D11 rule (as it does for
kind 4, openfox `relay_chat.go:716-722`), and the daemon runs `CommitPeer` on
part 0's evidence (newer only). A sender includes its card in part 0 until a
room ack confirms it (application objects are never acked, so a room-only
peer gets the card in every part 0). The authority's handshake objects carry its card
in every part 0 as well, acknowledged or not: a superset of the rule above,
and the cut does not depend on the card (11.1).

**Room-scoped admission (D11).** Once the owner has joined a room, an Event
is admitted without the allow-list only if it names that room, it is room
content (`room.message` or `artifact.encrypted`), and its packet sender is a
member in the authority's latest committed roster at the Event's epoch; the
room and peer caps still apply. Any other kind meets the normal policy. The
sender's credential must be of this installation's network. The daemon keeps the committed
membership of the current and the 2 previous epochs (D14), so this can be
judged for every epoch it can still open. It runs after the room overlay
(`admission/admit.go:304-317`) and both must pass: D11 and
`RoomLedger.JudgeMember` (`eventlog/rooms.go:315`). It runs before the
contact policy, grants no 1:1
admission (a member's copy not naming the room meets the normal policy), and
stores the member's card only under the admission and roster rule above. A
room-addressed kind-1 copy is refused on the relay route, so room content
cannot bypass MLS removal.

**Per-peer cap.** Of the carrier's 24 chat envelopes per peer (openfox
`pkg/servicebridge/relay_chat.go:36`, `:471-481`), kind 3 holds at most
**16**, refused `peer-cap` by the carrier; at least 8 stay for copies, acks
and evidence. The kind-3 count uses the same listing refresh as the 24
(`:531-580`), so envelopes the peer already acknowledged stop counting. A
`peer-cap` answer leaves the object `pending` and retried; it is never
dropped for the cap, and handshake objects go first. Counters are per peer,
not per room: 31 counters in a 32-member room. With one handshake object in
flight per (room, member) (11.3), the production cut needs at most 6 + 6 =
12 (current and not yet withdrawn generation; 8 + 8 = 16 only with a test P),
a single-part Commit 2, leaving at least 4 for application objects. The rail
keeps at least 40 of the relay's 64 per (client, recipient) (7).

**Lifetimes.** A kind-3 application packet expires at now + the smallest TTL
of the recipient card's relays, as kind 4 does (openfox
`relay_chat.go:348-357`). An application object not deposited to a member
within the smallest relay TTL of that member's card, counted from sealing,
is `abandoned` for that member and becomes a gap there (the one rule, also
in 11.7). Handshake
packets take the copy rule (4).

**Deposit rate.** The relay allows 60 deposits per minute, burst 32, per
client address, shared with the rail (`AGENT_PACKET_RELAY_V1.md:651-660`). The
carrier paces kind 3 to **30 per minute per relay, burst 16**, so rail and
kinds 1, 2, 4 keep at least half. A message or single-part Commit to 31
members then takes about 30 s; a maximal Commit to 31 (186 parts) about
5 min 40 s. Signing is not the bound: 186 × 0.043 s ≈ 8 s (M-R1 record,
`signing_cost`).

**Not bounded: an offline member's mailbox.** A relay holds 256 envelopes
and 16 MiB per recipient (`AGENT_PACKET_RELAY_V1.md:651-660`). The bytes bind
first for large objects: 16 MiB holds only 64 maximal (260,757-byte)
envelopes, about ten maximal 6-part objects; for small ones the count
binds (31 members × 16 = 496 > 256). Either fills an offline member's
mailbox. Then every
deposit to it answers `507`, including 1:1 copies, acks and evidence from
anyone (and, on shared relays, the rail), until it returns and acknowledges.
The carrier answers `retry`; a 507'd handshake deposit is retried with the
30 s to 5 min backoff of 2.5, and handshake objects go before application
objects in every per-peer queue. Hence D2 before production.

**Rejected: a room mailbox** (one deposit read by all): a relay
change, and an envelope sealed to a shared key opens for removed members.

### 11.3 Ordering, catch-up and retention

**Handshake objects per member in epoch order.** The authority keeps one
queue per (room, member) with at most one object in flight: the next is
deposited only after a verified room ack (11.7) of the previous, `accepted`
or `duplicate`. A member never sees a Commit before the one it follows,
however long it was offline; catch-up costs one poll round trip per missed
epoch, and one slow member delays no other.

**Authorization window on the relay route.** A MembershipAuthorization
lives at most 24 h and is refused once now ≥ its expiry
(`room/authority.go:20-21`, `:109-111`, `:125-126`), checked at receive time
(`eventlog/rooms.go:105`), while catch-up may take up to the 7-day handshake
retention. On the relay route the receiver therefore verifies the header's
signature against the authority's delegation as finalized **now**, but checks
its window as issued − skew ≤ now < issued + handshake retention + skew, with
skew the daemon's clock-skew bound, instead of its own expiry (clocks drift
both ways, so the skew applies at both ends). The authorization is never
re-signed per generation: object bytes and digest stay identical. A test
build MAY shorten the retention (`room_handshake_retention_seconds`;
production 7 days) and the expiry the authority signs
(`room_authorization_seconds`; production 24 h); the record states both.

**Receiver, handshake.** For a Commit or Welcome the daemon checks the
sender (11.5) and the authorization as above, then advances the room epoch
and the MLS state in **one journal write**, the fused room record, which is
the single commit point. Large values never live in it; they are staged
first as content-addressed records:

- the opaque MLS state (≤ 512 KiB, `eventlog/mls.go:24`) as chunk records of
  262,144 bytes (349,528 in base64), at most ⌈524,288 / 262,144⌉ = **2**
  chunks, named by the state digest;
- the authority delegation (≤ 65,536 bytes,
  `directory/file_delegations.go:13`) as one record named by its digest;
- the memberships of the two earlier retained room epochs, one record each
  named by its membership digest (three member lists would not fit the
  record's cap);
- Commit, Welcome and roster objects as the chunk records of 11.7.

The state bound is set by the worst case the driver configuration allows at
the relay room bound of 32 leaves: every other member's ratchet holding the 8
skipped keys the out-of-order tolerance keeps, in the current and both
retained epochs, with every leaf carrying a maximal 128-byte leaf identity
(11.2) whose bytes all have the costliest stored width. Measured over repeated
runs (the keys are random), that is 338,574 to 339,038 bytes (about 210,000
with in-order traffic), 35 % under 524,288
(`worst_case_state_fits_at_the_relay_room_bound` in `rust/openmls-driver`).
That includes the leaf signature keys of the two retained past epochs, which
the driver keeps beside the library's state (about 4.4 KB at 32 leaves): the
library retains those epochs' trees but does not expose their keys, and
`open` must report the key of the leaf that sealed a past-epoch message in
that epoch.
The library stores byte strings as JSON number arrays, so each identity byte
costs about 384 bytes of state at 32 leaves for typical values and up to
about 4 characters per stored byte. That is why the identity is a fixed
compact binding and the credential travels in rosters. A sender far ahead within the 1,000-generation
forward distance stores no more than the tolerance (item 17). The profile's
64-leaf bound (several devices per Agent, not carried over the relay, D3) can
exceed 512 KiB under the same skipping; the driver then refuses the operation
rather than return a state the journal cannot hold.

The fused record holds only: room ID, room and MLS epochs, membership digest
and the ≤ 32 member IDs, the digests of the two earlier retained
memberships, the authority's Agent and Endpoint, the
MembershipAuthorization, the prior and accepted `CommitRef`, the state digest
and its chunk digests, the delegation digest, the consumed KeyPackage ref and
the processed Welcome ref (one digest each, today in `eventlog/mls.go:45-46`,
checked by `keyPackageConsumed` `:336-358` and the replay refusal `:98`), and
the epoch authenticators of the current and 2 previous epochs, and the
digest of the room's leaf-credential list (11.8) and the room's end time
(D18). Worst case about
**5.2 KB**: measured 5,196 bytes with the credential-list digest and the
end time, which added 140 bytes with their field names to the earlier 5,056
(`TestFusedRecordMaximalEncodingFitsItsCap`) (2,336 bytes for 32 member IDs, about 900 for an
authorization with a maximal network ID, about 150 for the two refs, the rest
digests and IDs, plus field names); the codec caps it at **8,192 bytes**,
leaving 778,240 bytes (99 %) of the 768 KiB record bound
(`eventlog/journal.go:63`) as headroom. Reading it verifies each chunk
digest and the reassembled state digest, and fails closed on a mismatch.
Opening an object at e = r − 1 or r − 2 (below) needs those epochs'
retained authenticators, which is why the record keeps them. Today they are two
writes that refuse a repeat (`eventlog/rooms.go:139-141` `ErrRoomRollback`,
`mls_controller.go:108-110` `ErrMLSFork`), so a crash between them would
strand the room. An exact repeat (same membership digest, authorization and
`CommitRef`) is a no-op answered `duplicate`.

**Receive order, keyed by object class.** Commits and Welcomes are ordered
and fork-checked by **MLS epoch** (every Commit advances it, including an
MLS-only refresh that leaves the room epoch unchanged), in order:

1. a digest among the last 64 applied Commits and Welcomes answers
   `duplicate`;
2. another Commit or Welcome for an MLS epoch within that window answers
   `room-fork` (11.5);
3. one older than the window is dropped silently and relay-acknowledged;
4. an MLS epoch above current + 1 answers `rejected` with `room-epoch-gap`,
   except that a member treats a verified Commit whose header removes it, at
   any epoch above its own, as a removal notice (11.4).

A joiner's Welcome arrives before the joiner has any MLS epoch, so steps 2–4
do not apply to it: it goes through the pending-join path (11.2; from the
authority named in the `room.invite`). The sender check of 11.5 then uses
the authority's leaf credential stored with the pending join, which the
joiner verified when it recorded the invite: the Welcome's sending leaf
identity MUST name that credential's digest (with its Agent, Endpoint and
device), its leaf signature key MUST be the credential's, and the
credential MUST still verify against the delegation as finalized now and be
inside its window; otherwise the Welcome is refused `not-authentic`. There
is no bootstrap exception: the joiner never accepts a Welcome before it
holds a verified authority credential. Replay is refused by the ledger
(`eventlog/mls.go:98`); once installed, later copies of it answer
`duplicate` under step 1.

Rosters are keyed by (roster, room epoch E) and checked as in 11.2: a digest
among the last 64 applied rosters answers `duplicate`; a second, different
roster for the same E to the same receiver answers `rejected` with the
dedicated code `room-roster-conflict` and an owner notice naming it (a
roster conflict, not `room-fork`, since a roster carries no MLS state). Welcome replay stays refused (`eventlog/mls.go:98`). On any `rejected` room
ack the authority stops that member's queue with an owner notice.

**Receiver, application.** Let e be the object's MLS epoch and r the
member's:

- e = r: opened; the MLS sender identity (new driver output, the leaf
  identity of 11.2) MUST name the packet sender's Agent and a verified leaf
  credential whose leaf signature key is the sender leaf's, then the Event goes through admission and the journal as a
  copy does, and the envelope is relay-acknowledged after the commit. If
  `Open` fails for an authenticated current member (the AAD's epoch
  authenticator differs from this member's), the object is
  `room-fork-suspected` with an owner notice.
- r < e ≤ r + 4: kept in a durable future-epoch buffer (at most 256 objects
  and 8 MiB per room, of which at most 16 objects and 1 MiB per sender, and
  32 MiB in total) and opened in arrival order once the Commits up to e are
  applied. k = 4 covers a member catching up a few epochs; above it the
  object is dropped as a gap.
- r − 2 ≤ e < r: opened with the retained past-epoch secrets. The driver is
  configured with `max_past_epochs(2)` (D14): Commit fan-out takes up to minutes
  (11.2), so messages sealed just before a Commit land after it. **Rejected:**
  0 (the driver default today, `src/main.rs:335-338`, `:432-434`), which loses
  every message in flight across a Commit, and a larger window, which keeps
  more old epoch secrets on disk.
- e < r − 2, e > r + 4, a full buffer or sender share, or a buffered object
  older than 24 h 5 min: dropped, relay-acknowledged, and counted as a gap.

A received application digest seen within 24 h 5 min is relay-acknowledged
and dropped before `Open` (a second relay or a replay), so it never spends
a ratchet step.

**Gap notice.** The daemon keeps, per (room, sender), the highest `sequence`
it holds. A missing sequence is declared lost, as a `room.gap` record
(room, sender, first and last missing sequence, reason) readable by the
runtime through `rooms.gaps`, when it is dropped as above, or when it has not
arrived T after a later one did, with T the largest `max_ttl_seconds` of this
node's own chat relays plus 5 minutes (a missing envelope can only still be
waiting at one of them). No carrier reports this node's own relays' TTL, so
the daemon reads it from `relay_carriage.own_relay_max_ttl_seconds` (1 ..
86,400; default 86,400, the relay V1 ceiling): a value above the real TTL
only declares a gap later, never wrongly, and a record states the value it
ran with (3,600 for the 1 h test relays). An object dropped unopened reveals no sequence, so
its gap record names only the sender until a later sequence fixes the range.
Loss at a sender's tail is noticed at that sender's next message.

**Implementation bounds of the receive state.** None of the following
records may grow without limit, so each has a fixed bound:

- At most **262,144** live received-application digests across all rooms,
  **16,384** per room and **2,048** per sender in a room. A digest is
  marked only after its sender is authenticated as a member. At a bound,
  the expired ones are swept first. If the live ones still fill it, the
  digest is not recorded and the object is answered `retry` (left
  unacknowledged at the relay), so nothing is dropped unrecorded. The
  counts are kept in memory, so no marker costs a directory scan.
- At most **64** pending joins, at most **8** per inviting Agent, each for
  at most **7 days** (a `room.invite` expires within 7 days of its Event,
  checked on receipt). Joins are keyed by (room, inviting Agent), so a
  stranger's invite for a room ID cannot pre-empt the real authority's.
  The owner's `rooms.join` names the authority it accepts (the signed
  decision commits it), and accepting one discards the room's other
  invites. Expired invites are swept before a new one is refused. Eight
  Agents with eight invites each fill the 64 slots; that costs each Agent
  an on-chain registration, which is the Sybil cost this bound relies on.
- At most **64** private rooms per installation, held or being joined;
  creating or joining another is refused (`ErrRoomsFull`). It bounds every
  per-room store.
- At most **1,024** `room.gap` records per room, **128** per sender in a
  room and **16,384** across rooms; the oldest are pruned first.
- At most **64** undeclared missing ranges per sender. A range beyond that
  is declared lost at once, without waiting T.
- At most **4,096** per (room, sender) sequence records across rooms (128
  rooms of 32 members); beyond it the object is answered `retry`.

A removed member's sequence record is deleted. A room's sequence, gap,
applied-digest, received-digest and future-epoch records are deleted when
the room is neither held (no fused record) nor pending (no pending join),
and at restart for any room in that state.

**Parts.** Part 0's evidence is checked (`CheckPeer`, read-only) when part 0
arrives; when several generations deliver part 0, the evidence that is newest
under 2.5's "newer" is kept. Parts 1..n that arrive first are checked against
the sender set (current members, or the authority of a pending join) and
checked again when part 0 arrives and at completion. The reassembly caps of
section 4 count part bytes, not frame bytes. An application object of a current
member whose leaf credential is not yet known (11.8) has no credential to pin
its evidence to: its part 0 evidence is checked by `CheckContact` (read-only,
pinned to the evidence's own Endpoint and device), the object is only held in
the future-epoch buffer and answered `ignored`, and nothing of it is committed
(no `CommitPeer`, no card); handshake objects are always checked pinned.

**Re-deposit (D10).** A handshake object is re-deposited to each member
that has not acked it, at 80 % of the smallest TTL of that member's card
(10-minute floor, as copies, 4), all parts together, the previous generation
withdrawn, until acked or 7 days; then that member is `abandoned` with
`retention-exceeded` on the owner surface, its queue stops, and its owner
should remove it. The re-deposit wait follows the TTL the carrier reports for
the recipient's card; the gap delay T (above) follows this node's own relays'
TTL, configured as `own_relay_max_ttl_seconds`. Application objects are deposited once only. **Cost:** a
pending handshake object of p parts costs p signatures and deposits per
member per generation: on 1 h test relays 30 generations a day, so a maximal
object pending for all 31 members is at most 5,580 deposits a day, inside the
kind-3 pacing (43,200 a day per relay); a single-part Commit, 930.

### 11.4 Remove

The authority's owner calls `rooms.remove` (M). The authority derives
`Membership.Remove` (`room/membership.go:134`), signs its
MembershipAuthorization, and commits an MLS Remove of all of M's leaves (one
in V1, D3), journaled with its outbox entry as 11.7 requires.

- **Cannot decrypt later messages.** The Remove Commit carries a fresh
  UpdatePath encrypted only to the remaining tree, so the next epoch's secrets
  are derived from a commit secret M never receives (RFC 9420 section 12.4.2);
  the group refutation floor checks exactly this property (`pkg/group/group.go:17-22`).
  No member addresses an object sealed in epoch ≥ N+1 to M, because fan-out
  uses the sealing epoch's membership. M's events naming the room are refused
  `not-a-room-member` once a member has advanced its ledger
  (`admission/admit.go:310-317`).
- **What M still reads:** objects sealed in epoch ≤ N, including those of
  members not yet at N+1, which M was entitled to; the window is the
  Commit's fan-out (11.2) plus a member's offline time.
- **M's devices and cards.** Members forget M's chat card
  (`carrier.room-cards`) unless held under another admission (contact,
  session), and its leaf credential (the fused write drops it, 11.8). M's
  relay evidence is not deleted: it is public, signed routing data, every room
  path requires membership, so it is never used for the room, and the
  evidence store's expiry (2.5) retires it like any peer's. M gets the
  Commit once (no re-deposit, no ack, outside its in-order queue). That one
  deposit checks M's stored evidence against the evidence's own Endpoint and
  device (`CheckStoredContact`), not pinned to M's leaf credential, because
  the removing fused write already dropped that credential; the Commit
  carries no content M could open. M treats a Commit whose verified header removes M, at any
  epoch above its own, as a removal notice: it marks the room removed without
  applying it to MLS. If that one deposit is lost, M is not told: its later
  room messages are refused at members and relay-acknowledged without an
  answer, and M learns of the removal only out of band.
- **No re-add in V1.** A removed member cannot be added to the same room
  again until the room retires: its removal marker stops it taking that
  room's handshake objects, and a fresh Welcome into a room ID it held would
  need a fused-ledger transition V1 does not have (the same one M-R2.1's
  member re-key needs, 11.8). To include it again, the authority creates a
  new room. Members also forget a removed member again on their own: the
  card admission, sequence record and parts are reconciled against the
  current membership at start and on the relay timer, so a crash or a
  failed carrier call after the removing Commit leaves no card admission,
  sequence record or part behind (relay evidence follows 2.5). A removed
  member's card admission for the room ends at the latest when the room
  retires (11.8), which bounds every leftover admission to the room's
  lifetime.
- **M's pending envelopes.** The authority withdraws its in-flight handshake
  generations to M (`carrier.withdraw`); members withdraw stored kind-3
  envelopes to M of epoch ≥ N+1 and drop undeposited ones; epoch ≤ N ones
  stay until their TTL.

### 11.5 One authority, no concurrent Commits

**V1 rule:** the room's single authority is the only Agent that sends
Commits, Welcomes and rosters, including MLS-only refreshes; members never
commit or propose (`messenger/docs/OPEN_DECISIONS.md:147`,
`messenger/docs/FIRST_PRINCIPLES_DECISIONS.md:76-82`). A receiver requires:
the packet sender is the current authority Agent of its `RoomLedger`; the MLS
committer identity (new driver output of `apply`) is that Agent's leaf
identity, naming its verified leaf credential (11.2; for a joiner's
Welcome, the one its `room.invite` carried, 11.3); and a
membership change carries the authority's MembershipAuthorization. Anything
else is refused `not-authentic`, relay-acknowledged, and nothing is stored.

**What V1 does not do.** Two honest members can never produce concurrent
Commits, because only one may commit. Two different Commits for one epoch can
come only from the authority itself (for example a restored backup): each
member keeps the first it applied and refuses the other `room-fork` with an
owner notice; the room is then forked, and recovery is a new room. Authority
transfer (`eventlog/rooms.go:185`) is not carried over the relay in M-R2.
**Rejected: MLS's own reject-and-retry among several committers,** which
needs an ordering service; relay arrival order is not authority.

**Not provided in V1 (D15).** Post-compromise security for members: members
never commit, so a compromised member leaf is not healed by its own Update
(only the authority's Commits refresh the path; member Updates are a later
change). A member's leaf credential lives at most 30 days, the window of
its `DeviceCredential` (`mls_profile.go:34`). No member's credential expires
inside a room: the room ends at the authority's credential expiry, and only
members whose credential lasts until then are added (D18). A credential that
nevertheless fails (for example an Endpoint withdrawn on chain) makes
receivers refuse that member's objects `not-authentic`, and the authority's
queue to it stops.

### 11.6 Invites over the relay

**Why M-R1 could not.** The receive side is complete: a kind-1 object
carries `AdmissionToken` (`relayframe/copy.go:50`, `:66`), the daemon passes
it to admission (`daemon/relay.go:641-644`), which checks and then claims it
for exactly one authenticated Event (`admission/admit.go:333-347`, `:383-392`;
`eventlog/admission_invite.go:31-65`, `:144-195`). Nothing sends one:
`invites.create` returns the token to the recipient's owner once
(`localapi/server.go:580-592`, `docs/RUNNING.md:82-99`) to give out of band,
but no operation accepts a received token, `Delivery` has no field for it
(`eventlog/delivery.go:109-144`), and `dispatch` builds every `Message`
without it (`dispatch/dispatch.go:920-930`). The HTTPS route is the same.

**Decision: a new owner operation, not a field on the send.**
`invites.present` (owner principal) takes the recipient Agent, the
`invite_…` token and its expiry, and stores them in the sender's journal.
Every delivery to that Agent, first contact or an existing session, records
the token on its `Delivery` and `dispatch` sets `Message.AdmissionToken`, so
every re-deposit generation carries the same token for the same Event; this
continues until one delivery to that Agent settles `accepted`, and the token
is deleted then, or at its expiry. Only a verified relay delivery ack reports
`accepted`; the HTTPS route's durable acceptance does not tell `accepted`
from `duplicate` or `held`, so there the token is kept until its expiry. That
is safe: the token is single use, and once it is spent the receiver re-runs
its policy without it, under which the claim has already made the sender a
contact (D12). The token is held per recipient Agent, not per Endpoint: if
that Agent had several Endpoints, an `accepted` ack from any of them settles
it (a V1 limit; V1 carries one device per Agent, D3). **Rejected: an `admission_token`
field on `messages.send-direct`,** which would hand a bearer the recipient's
owner issued to the runtime, able to spend it on any Event. **Carried only
sealed:** inside the kind-1 object in the sealed packet (3), never in a
packet field, card or evidence.

**Checked on receipt** exactly as on every route: the contact policy runs
first; the token is consulted only when it answers `require-admission` or
`invite-or-hold` (`admit.go:333`); it must be unexpired, scoped to the
recipient Endpoint and, if scoped, to the sender Agent; the claim binds it to
the first Event, and an exact re-deposit is idempotent (`duplicate`). A spent
token on another Event does not refuse at once: the policy is re-run without
the token, since the sender may by then be a contact (D12); only if that
fails is it refused. **Relation to M-R1's allow-list (D12):** an
allow-listed sender never needs one; after a successful claim (whose write is
`eventlog/admission_invite.go:183`) a separate, idempotent journaled step adds
the sender Agent verified at claim time to the known contacts, **between the
claim and the Event's commit**. A crash before the commit is healed by the
exact retry (claim and contact add both repeat as no-ops, then the commit);
once the Event is committed the contact already exists, so the duplicate
path needs no step of its own.
Today the known roster is only the daemon config's
(`admission/policy.go:181`) and no operation removes a contact, so M-R2 adds a
journaled invited-contact list that is never swept (unlike invite records),
that `ContactPolicy.Admits` reads beside the config roster (blocked still
wins), and an owner `contacts.remove` that deletes an entry from it. A
removal sticks: it leaves a tombstone naming the Agent and the invite, under
which that invite never adds the contact again, and only a fresh claim (or
the exact retry of an Event not yet committed) runs the contact-add step, so
re-sending the claimed Event cannot undo the owner's removal. A racing second
Event that loses the claim meets the policy without the token, like any
spent token. The list holds at most 4,096 entries: if it is full when a
claim succeeds, the claim stands and spends the invite, but the contact
cannot be added, so that Event is refused `quota-exceeded`, and so is every
later copy of it (a V1 limit; the owner frees entries with
`contacts.remove`).
**On refusal nothing is stored:** admission refuses before
any journal write (`admit.go:323-331`), the card is not stored and
`CheckPeer` writes nothing (2.3, 2.5).

**A `room.invite` carries the authority's leaf credential.** Besides the
room, invitee, purpose and expiry, the payload carries the inviting
authority's leaf credential (11.2, at most 473 bytes; the payload codec
bounds it at 512). An invite is recorded as a pending join only if that
credential decodes strictly and names the invite's packet sender Agent, an
Endpoint and device of its delegation as finalized now, the delegation's
network and genesis, and a valid window that has not ended; its signature
MUST verify under that Endpoint key. Otherwise the invite is refused
`not-authentic` and nothing is stored. The verified credential is stored
inside the pending-join record, which is already a garbage-collection root
(11.7), so it survives a restart until the join ends or expires.

### 11.7 Room acks, delivery states and journals

**Room ack.** A kind-2 frame carries either the copy ack of 5.2 or a room
ack, schema `tos.messaging.relay-room-ack.v1`: room ID, object digest,
recipient Endpoint and device, the recipient's MLS epoch and epoch
authenticator after handling the object (so the authority sees a diverged
state; a pending joiner that refuses its Welcome holds no MLS state, so its
`rejected` ack, and only a rejection, carries no authenticator and MLS epoch
0), outcome, code and time, signed by the
recipient Endpoint under a new domain `DomainRelayRoomAck`, verified like
5.2. It is sent only for handshake objects (types 1, 2 and 4), never for
application objects (31 acks per message would double the deposits).

| Object | Per-member states | Settles on |
|---|---|---|
| Commit, Welcome, roster | `pending → carried → delivered`, or `rejected` with its code, or `abandoned` | a verified room ack (`accepted` or `duplicate` mean delivered); 7 days |
| Removed member's Commit | `pending → carried` | one deposit |
| Application | `pending → carried`, or `abandoned` (not deposited within the smallest relay TTL of the member's card, from sealing) | the relay TTL; never `delivered` |

**Sender journal (room outbox).** An object's bytes are stored once (not
per member) as chunk records under the 768 KiB record bound
(`eventlog/journal.go:63`): chunks of 262,144 object bytes (349,528 in
base64, plus fields), so at most ⌈1,056,858 / 262,144⌉ = 5 chunks per object.
A head record holds digest, type, room, epochs, chunk digests, and per member:
state, generation, last deposit, next re-deposit, the evidence digest sent,
and the ack outcome and code.

**Commit output is journaled with the state advance.** Today
`MLSController.Commit` makes the next state durable before the caller can
record the Commit (`mls_controller.go:64-95`); an authority crash in between
would leave it in an epoch no member can reach. Instead the driver's output
is first staged: the next state as state chunks under its digest (11.3), and
the Commit, the Welcome and, for an Add, the rosters (a full one for each
joiner, one of the added members for the others, built before the write) as
object chunks under the `CommitRef`; then the fused room record of 11.3,
naming both, is the single commit point, so a crash can lose no roster. On
restart each member's queue is rebuilt from the membership as (that epoch's
Commit or Welcome, then its roster), ahead of any later object; the
authority never queues a roster for E after a Commit for E + 1.

**Garbage collection.** The roots are every fused record (and through it
the room's leaf-credential list, 11.8), every pending join and every
room-outbox head record: an older Commit stays re-depositable for up to
7 days after the authority has moved on, and a roster or Commit whose fused
record has been superseded is named only by its outbox head. A staged state, delegation, membership or object chunk that no root names is
deleted at restart (nothing was published from it and the old state stands);
the state chunks a successful fused write supersedes are deleted right after
that write. Collection fails closed: if any root record, or any staged
Commit output that restart could not resolve, is unreadable, nothing is
deleted. The part store and the future-epoch buffer are separate
stores with their own bounds (section 4, 11.3).
Idempotency keys are `idem_` + SHA-256 of (object
digest, member, generation, part index), so a retry reuses the journaled
envelope (1). A handshake object is kept until every member is settled; an
application record keeps its ciphertext until every member's relay TTL has
passed (at most 24 h), then only its digest and per-member states. The
OpenFox chat outbox is unchanged (5.3).

### 11.8 Leaf credential lifecycle

A member's leaf credential (format in 11.2) is what every other member pins
`CheckPeer` to (2.5, 11.2), what D11 and D15 judge (11.2, 11.5), and what
binds an MLS leaf to an Agent, Endpoint and device. Its lifecycle is the
following, and the other sections refer here.

**Issue.** The founding authority's daemon makes its own leaf credential
at `rooms.create`, as a joiner's is made below, and puts it in every `room.invite` it
sends (11.6). A joining member's daemon (11.2) makes a fresh leaf signature key
and its leaf credential. The window is the one of the `DeviceCredential` it
makes beside it: at most 30 days, and not past the delegation's expiry. The
authority adds the member only if that window lasts at least until the
room's end (D18). The founding authority's own leaf credential fixes the
room's end. The Endpoint signs the
credential. The KeyPackage's identity is the 128-byte compact binding naming
the credential's digest. `room.key-package` carries the `DeviceCredential`
and the leaf credential. The authority checks both (11.2) and refuses any
other identity; the Go relay room path enforces the 128-byte length.

**Distribute.** The authority sends each credential once to every member
that needs it, in roster entries staged under the Commit's `CommitRef`
(11.7), and its own credential also in every `room.invite` (11.6):

- the `room.invite` carries the authority's credential, so a joiner can
  authenticate the Welcome's sender before any roster (11.3);
- a joiner's full roster carries every other member's credential, the
  authority's included (the same digest as the invite's, which confirms it);
- the roster of added members carries the joiners' credentials to the
  others.

**Member cards.** Roster entries also carry each member's chat card, which
the authority's daemon keeps itself, beside the member's relay evidence:

- **Source.** Part 0 of the member's own frames, after admission: first
  the joiner's `room.key-package` frame (11.2), whose card is required.
- **Checks.** The daemon checks only that the card is one canonical key
  card packet sent by the frame's authenticated packet sender to the
  key-card audience, and that its validity window holds now. A card naming
  another Agent is refused. Its signature is each receiving member's
  carrier's to verify when it admits the card (`carrier.room-cards`), so a
  card that does not verify is never used.
- **Refresh.** A later admitted frame of the member (kind 1, 3 or 4)
  replaces the stored card only with a newer one, by the card packet's
  creation time and then its sequence, that passes the same checks.
- **Use.** A stored card that is missing or past its window gives the
  member no roster entry yet: the member's evidence pull starts (its kind-4
  frames carry its card) and the roster, with the Commit it is staged with,
  waits.
- **Bounds and deletion.** One card per (room, member) of a room held here,
  for a current member or a live pending add: at most 32 per room and 64
  rooms. Remove deletes the member's card with its credential; retirement
  deletes the room's cards with its other per-room state.

A receiver takes the leaves from the driver's read-only `members` operation
(leaf index, identity, signature key). For each entry it requires:

- the credential's digest equals the one in that member's leaf identity;
- its Agent, Endpoint and device equal the identity's;
- its signature verifies under the Endpoint key of the member's delegation
  as finalized now;
- its leaf signature key equals the leaf's;
- it is inside its window, and the window lasts at least until the room's
  end (D18).

These checks read only the leaf, the credential and finalized state, never
the entry's card or evidence. A credential that passes them is learned even
when the entry's card or evidence is stale; only that card or evidence is
skipped and later repaired by the kind-4 pull (11.2). An entry whose
credential fails is skipped whole, and the rest of the roster is learned.

The device check, here and at every later use of a credential, is that the
credential's device is present, under the same Endpoint, in that Endpoint's
current device set and is not revoked from it; `device_set_digest` records
the set the credential was issued in and is never compared again. So a
credential stays valid across the member's prekey renewals, which change the
set's digest and not its device, and is refused once its device leaves or is
revoked from the set.

**Store.** The room's credential list is a content-addressed record of the
digests of the current members' credentials, and the fused record names it
by a 32-byte digest. That makes it a garbage-collection root: collection
keeps every credential it names, and an unreadable list deletes nothing
(11.7). Learning a roster takes three steps, all before the roster's room
ack is signed:

1. Write each verified credential as a content-addressed record named by its
   digest (the one in the leaf identity).
2. Write the new list that names those credentials.
3. Make a fused write naming the new list's digest, under the same
   atomic-replace and directory-fsync rules as every fused write (11.3). An
   exact repeat (the same list digest) is a no-op.

**A joiner's first credential.** Until its Welcome is installed, a joiner
keeps the authority's credential only inside its pending-join record, a
garbage-collection root (11.6, 11.7). Installing the Welcome takes the same
three steps: the authority's credential is written as a content-addressed
record, then a one-entry list naming it, and the fused write that installs
the Welcome names that list; only then does the pending join end. A crash
before the fused write leaves the pending join, credential included, and
the Welcome unacknowledged; a crash after it finds the credential rooted.
The full roster that follows writes the other members' credentials and a
list naming them all; the authority's entry has the same digest, so its
record is an exact repeat.

So a credential is rooted before it is acknowledged. A crash before step 3
leaves unrooted records that restart collects; the roster is not yet
acknowledged, so it is re-deposited and learned again. A crash after the ack
finds the credentials rooted. Remove (11.4) drops the removed member's digest from
the list, and its record is collected. Objects of a current MLS member
whose credential is not yet known (its roster has not arrived) are held in
the future-epoch buffer (11.3; same caps, 24 h 5 min) and opened once the
roster arrives. They are refused `not-authentic` only after a roster
arrived without a verifying entry for that member. A held object keeps no
frame evidence, so it is opened only against the sender's stored evidence
checked by `CheckPeer` pinned to the now-known credential's Endpoint and
device (`LeafPin`); if that check fails the object stays held, is tried again
on the next roster, Commit or maintenance pass, and becomes a `buffer-expired`
gap if it never passes.

**Room end (D18).** Let `end` be the room's end time, `skew` the daemon's
clock-skew bound, and d the re-deposit interval (80 % of the smallest relay
TTL, 4).

- **Senders stop at end − skew.** The authority's queues and every member's
  sealing stop at end − skew, so nothing is sent that a receiver with a
  clock ahead would refuse.
- **No handshake near the end.** The authority makes no new Commit, Welcome
  or roster within the last d before end − skew. Such an object could not
  be delivered and acknowledged before senders stop.
- **Receivers refuse at end + skew.** At now ≥ end + skew a member refuses
  the room's Commits, Welcomes, rosters and application objects with
  `room-ended`, relay-acknowledges them and raises one owner notice.
- **Late application objects are gaps.** An application object sealed
  before the end that arrives after end + skew is recorded as a gap (11.3),
  with the `room-ended` notice.

Credentials are never renewed inside a room: continuing means a new room.

**Retirement.** At end + handshake retention + skew, the daemon retires the
room, in this order:

1. delete its room-outbox heads, its part-store entries, its future-epoch
   buffer and its receive state (sequences, gaps, applied and received
   digests);
2. delete the room's credential list;
3. delete the fused record last, as the commit point, with a directory
   fsync.

With retirement the daemon also drops the room's admission of every
member's chat card (`carrier.room-cards` forget). That call is made outside
the journal steps and never holds them back; a failed one is retried on the
next maintenance pass while the daemon runs (V1 keeps no journal record of
it, so a restart before it succeeds leaves the admission to the carrier).
The carrier does not depend on that forget: every room-cards admission
carries the room's end (the fused record's `room_ends_at`, 9.2 item 10), and
the carrier drops the room's admissions on its own at end + 1 h. The 1 h
slack is the largest clock-skew bound a daemon may be configured with, so
the carrier never drops an admission before the daemon refuses the room's
objects (end + skew, above). The forget at retirement then finds the
admissions already gone, which is a no-op; a daemon that crashed before it
leaves no admission past end + 1 h.

At restart the daemon retires again any room past that time whose fused
record still exists, so a crash during retirement only repeats it. Ordinary
garbage collection (11.7) then reclaims the state chunks, credentials,
memberships, delegations and object chunks nothing names any more.

**Revoke.** A credential stops counting when it expires (D15: the member's
objects are refused `not-authentic` and the authority's queue to it stops),
when the member is removed (11.4), when the room ends (D18), or when the
delegation's Endpoint is withdrawn on chain (the signature check above reads
finalized state on every use).

**M-R2.1 (deferred): credential renewal.** These are not part of V1, and
they wait for a later milestone:

- **Authority renewal.** An MLS-only refresh whose UpdatePath carries the
  authority's new compact identity (`refresh` gaining a new-identity
  parameter), with a one-entry renewal roster queued before the Commit, and
  a store, root and crash rule for the pending renewal credential.
- **Automatic same-member re-key.** Remove(old leaf) + Add(new leaf)
  without the owner, bounded in time and rate. It needs a fused-ledger
  transition for the member's own Welcome into a room it already holds, and
  a bound against churn from short windows.
- **Roster keying.** A renewal or re-key sends a roster at an unchanged room
  epoch, so rosters would be keyed by (room epoch, MLS epoch).
- **Gate items** for an authority renewal across a credential expiry and an
  automatic member re-key.

Until then, D18 bounds every room by its authority's credential.
