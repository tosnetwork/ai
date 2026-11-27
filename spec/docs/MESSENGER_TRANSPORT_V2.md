# Messenger Transport V2

How Messenger copies, and every other Agent Packet, cross machines once the
carrier leaves OpenFox: relay-first store-and-forward with an optional direct
upgrade, signed reachability hints, and short-lived relay credentials that
are verified offline and revoked by finalized chain state.

**Status: ⬜ Design draft.** Nothing in this document is implemented. It is
an incubation design under [ROADMAP section 8.1](ROADMAP.md#81-incubation-designs):
it carries no gate status and supplies no gate evidence. Section 16 lists the
evidence each part needs; section 17 is the implementation order.

MUST, MUST NOT, SHOULD and MAY are normative. "Relay spec" is
[Agent Packet Relay V1](AGENT_PACKET_RELAY_V1.md); "carriage" is
[Messenger Relay Carriage V1](MESSENGER_RELAY_CARRIAGE_V1.md); "messenger
spec" is [the Agent-Native Messenger architecture](AGENT_NATIVE_MESSENGER_V1.md).
Paths are in this repository unless they name `openfox` or `tos`.

## 0. Context

What exists and stays:

- Agent Packet V1: every packet is signed with ML-DSA-44 by a controller of
  the sender Agent's finalized policy ([`AGENT_PACKET_V1.md`](AGENT_PACKET_V1.md)).
- The relay seal: HPKE (MLKEM768-X25519, HKDF-SHA256, AES-256-GCM) to a
  recipient key published in a signed key card; the envelope is at most
  256 KiB and is deleted only with an acknowledgement secret carried inside
  the ciphertext (relay spec sections 3 to 8).
- Carriage: Messenger copies travel as relay frames inside signed packets,
  double encrypted, with in-band cards and relay identity evidence; M-R1 and
  M-R2 are accepted on team-operated relays (carriage sections 1 to 11).
- D10: a packet expires at its business deadline; relays keep an
  unacknowledged envelope for their TTL, 1 hour on test relays and 3 hours on
  production relays, never more than 24 hours; a sender re-deposits at 80 % of
  the smallest advertised TTL (relay spec 9.6 and 10, carriage section 4).

What is wrong with it:

1. **The carrier lives in OpenFox.** The chat lane is OpenFox's
   `pkg/servicebridge` (`relay_chat.go`, `relay_transport.go`,
   `relay_inbound.go`), reached from `tos-messengerd` over `carrierapi`. A
   second rail carrier exists in `protocol/pkg/buyeragent`. An Agent without
   OpenFox cannot chat at all, and the two rail carriers drift.
2. **Relays are open.** Anyone who knows an Agent ID can list its mailbox,
   download its ciphertext and learn its online times (relay spec 9.3, 9.4
   and 11). Anyone can deposit, so a stranger's flood takes the same quota a
   contact needs (carriage section 7).
3. **Routes travel only in band.** The relay list sits inside a key card that
   lives up to 30 days, and V1 has no directory because a relay without chain
   access cannot tell a genuine card from junk (relay spec 6.4). First contact
   needs an out-of-band contact file (carriage D4) or an invite.
4. **The route decision is stuck.** M0-R was meant to choose a primary route
   (messenger spec section 11); for the OpenFox profile it was retired by
   decision D1 and the relay became the only cross-host route. The tooling
   (`messenger/pkg/reachability`, the native probe sidecar
   `tos` `adnl/tos-adnl-probe.cpp`, coordinator-signed NAT mapping and
   filtering, the reachability tunnel) exists, but no field study has run.

What the M0-R work did establish, and this design relies on:

- the native ADNL stack is IPv4-only: an IPv6 send aborts in the sidecar,
  so a direct route is IPv4 or nothing;
- one ADNL query carries at most 8,192 bytes (8,176 bytes of probe payload),
  so anything larger than a control message needs RLDP2;
- a reconnect resets only the channel: the peer's ADNL identity and address
  survive it, so a binding made to the ADNL identity survives a reconnect;
- NAT mapping and filtering classes can be derived only from
  coordinator-signed observations, never from an endpoint's claim about
  itself (`messenger/docs/M0R_STUDY.md`).

## 1. Goals and non-goals

### 1.1 Goals

- **G1. Any Agent can chat.** The carrier is a library in this repository,
  run by `tos-messengerd` itself, with an MCP server beside it, so a buyer on
  any MCP client, or any program that speaks the local API, can chat with an
  OpenFox Agent and with each other. OpenFox uses the same library.
- **G2. Relay first, always.** The relay path works for every pair of Agents
  that can make outbound HTTPS connections. A direct ADNL path is an
  optimisation that is attempted only where measured facts say it can work
  and is never required for delivery.
- **G3. Relays authorize storage by credentials rooted in finalized state.**
  A relay verifies a short-lived, attenuable credential offline, and
  re-checks the Agent's finalized state, so revocation and rotation take
  effect within a bounded re-check interval instead of at credential expiry.
- **G4. Mailboxes are private to their owner.** Listing and downloading need
  the owner's credential. Other relay users learn nothing about a mailbox.
- **G5. Strangers cannot crowd out contacts.** Deposits without a credential
  share a small stranger lane; each contact deposits in its own lane.
- **G6. An Agent ID is enough to find a peer.** Signed reachability hints in
  relay directories name the peer's relays, cards and Messenger evidence, so
  first contact needs no contact file. A hint never authorizes anything.
- **G7. Redundancy with bounded cost.** Each Agent names up to four relays;
  a sender keeps two copies; the recipient deduplicates across relays and the
  direct path.
- **G8. Reuse what is frozen.** The envelope, seal, key card, Agent Packet,
  Messenger E2EE and the room carriage are unchanged. The relay frame gains
  one field (section 9.3).

### 1.2 Non-goals

- A trusted control plane, an admission service, or any component whose word
  is believed. Finalized TOS state is the only authority; relays, directories
  and hints have none.
- Identity from a federated login provider. Identity is the finalized Agent.
- A new peer-to-peer stack. The native path reuses ADNL and RLDP2 of the TOS
  node; nothing else is introduced.
- NAT-to-NAT hole punching, IPv6 direct routes, and push wake-ups (section 18).
- Hiding the sender from a relay operator who correlates addresses
  (section 11), or hiding room membership (carriage section 6).
- Relay payment, leases or bonds: they stay behind the Expansion Gate
  (ROADMAP section 8).
- Multi-device over the relay (carriage D3 stands).
- Backward compatibility. TOS is pre-launch: V1 relay endpoints, the
  `carrierapi` boundary and OpenFox's chat lane are removed, not kept
  (section 17).

## 2. Authority model

- **Identity:** the finalized Agent and its weighted ML-DSA-44 controller
  policy ([`NATIVE_IDENTITY_V1.md`](NATIVE_IDENTITY_V1.md)). Packets remain
  signed by a controller; this design adds no second sender identity.
- **Transport authority:** a **transport delegation** (section 5.1) names one
  Ed25519 transport key. It is valid only while its digest is committed by the
  live finalized Agent and the Agent's finalized policy is the one it names.
  The transport key signs hints, credentials and direct hellos and nothing
  else. It cannot sign a packet, a key card, a Messenger object or a registry
  action.
- **Why a new delegation and not the Messaging Endpoint key.** The relay is
  protocol-level and serves rail lanes of Agents that never register a
  Messaging Endpoint (an MCP buyer). The Endpoint key signs descriptors,
  prekeys and delivery acks; a key that only routes must not be able to forge
  those (carriage 2.2, "no key serves two purposes"). Its compromise then
  costs routing and relay access, never message authenticity.
- **Why Ed25519.** Credentials and hints are re-signed every few hours and
  request proofs on every request. ML-DSA-44 lives in `tosctl` custody behind
  a subprocess (`protocol/pkg/mldsa44`), and relays hold no `tosctl`. The
  post-quantum root is the finalized policy that commits the delegation; the
  Ed25519 key authorizes only storage and routing, which a later quantum
  adversary cannot use retroactively. Confidentiality stays post-quantum
  through the hybrid seal.
- **Relays read finalized state.** A V2 relay resolves Agent state with the
  strict-majority finalized reader (`protocol/pkg/toschain`). It reads; it
  never signs, submits or holds keys. A relay that reads a wrong state can
  only admit or refuse storage wrongly; every recipient still verifies every
  packet against its own finalized reads.

## 3. Threat model

| Adversary | Can | Cannot |
|---|---|---|
| Relay operator | drop, delay, replay, reorder or duplicate envelopes; lie in listings and status codes; refuse service; correlate addresses (section 11); serve stale hints | read or alter a packet; forge a hint, credential, receipt or packet; delete an envelope without its secret; reuse a credential proof at another relay; make a revoked delegation work at an honest relay |
| Network attacker | observe and drop traffic; spoof UDP sources | read anything (TLS, ADNL channel, HPKE); complete a direct hello without the peer's transport key; replay a request proof outside its window |
| Stranger | deposit into the stranger lane up to its quota; publish its own hints; look up public hints | list or download another mailbox; take contact-lane capacity; fill a directory without a live finalized Agent per record |
| Malicious contact | deposit up to its lane quota; hand its credential to others | widen its credential (section 6.4); deposit after revocation; hide that its lane is the one filling |
| Compromised transport key | sign hints and credentials for its Agent until the delegation is revoked, so redirect new traffic to relays it chooses and fetch ciphertext from the real relays | read a packet (the HPKE keys are separate); sign a packet; outlive a policy update or the delegation's withdrawal by more than the re-check interval |
| Compromised controller | everything the Agent can do | nothing less than total identity compromise; recovered by policy rotation, which also revokes every transport delegation (5.1) |
| Lying chain endpoint at a relay | answer a stale or false state, if it controls a majority of that relay's configured endpoints | affect any other relay or any recipient's own verification |
| MCP client or model | send and read through the runtime API within owner policy | choose a route, relay, key, device or session; approve a stranger; manage rooms (section 13) |

Invariants:

- **I1.** No hint, directory answer, credential, relay status or direct
  receipt is ever authority over a protocol fact. Each is verified, and each
  failure costs availability only.
- **I2.** The relay path never depends on the direct path. A node with the
  direct path disabled, IPv6 only or behind any NAT delivers every message.
- **I3.** The same journaled envelope bytes travel on every path, so every
  copy deduplicates by envelope ID and inner packet.
- **I4.** A relay never evicts a stored envelope to admit another (relay
  spec 9.8), and no lane can take another lane's reserved capacity.
- **I5.** Revocation is a chain fact: a policy update, a delegation
  withdrawal (once that action exists, section 18 Q1) or a tombstone stops
  every credential and hint of the delegation within 300 seconds at every
  honest relay and sender, without waiting for expiry.

## 4. Components

| Component | Repository and package | Role |
|---|---|---|
| Transport codecs | `protocol/pkg/agenttransport` (new) | transport delegation, credential, request proof, hint and hint record, direct hello and receipt: strict codecs, verifiers against a finalized resolver, frozen vectors |
| Relay V2 | `protocol/pkg/agentpacketrelay` (extended), `protocol/cmd/tos-service-packet-relay` | credentialed mailboxes, lanes, mailbox policy, revocations, hint directory, bounded long poll; finalized reads through `protocol/pkg/toschain` |
| Carrier library | `protocol/pkg/agentcarrier` (new) | one lane per HPKE key family (rail, chat): own keys and cards, transport key and delegation, hint publication and resolution, credential issue and refresh, outbox journal, multi-relay deposit, poller, direct-path state machine |
| Direct path driver | `protocol/pkg/adnlpath` (new) | Go driver of the native transport sidecar over a JSON-lines pipe, as `messenger/pkg/probe` drives the probe; no cgo |
| Native transport sidecar | `tos` `adnl/tos-adnl-transport` (new) | the probe's ADNL and RLDP2 core as a production program: listen, dial, query, RLDP2 query, keepalive; IPv4 only |
| Messenger chat lane | `messenger/pkg/transport` (new), `messenger/pkg/daemon` | binds relay frames to an `agentcarrier` chat lane inside `tos-messengerd`; replaces `carrierapi` |
| MCP server | `messenger/pkg/mcpmessenger`, `messenger/cmd/tos-messenger-mcp` (new) | stdio MCP server over the daemon's runtime socket (section 13) |
| Wallet step | `protocol/cmd/tos-service-wallet` | creates a transport key and delegation and submits the existing `DelegateAgentV1` action |
| OpenFox | `openfox` `pkg/servicebridge` | rail lane on `agentcarrier`; chat through `tos-messengerd` only (section 14) |
| Buyer agent | `protocol/pkg/buyeragent` | rail lane on `agentcarrier` instead of its own carrier |

The relay is still a separate program, the Gateway stays stateless, and
nothing here enters the Native Connect contract. A Gateway MAY serve a
provider's hint record beside a Quote package exactly as it serves the
provider key card today ([`API.md`](API.md)); it checks shape only.

## 5. Wire objects

Common rules are those of relay spec section 4: unsigned big-endian
integers; `D(x)` is the ASCII string `x` followed by one zero byte;
`agent_digest(id)` is the 32 bytes of `agent_<64 hex>`; every decoder rejects
unknown versions, wrong lengths, non-canonical values and trailing bytes.
Ed25519 is pure Ed25519 (RFC 8032); a public key that is all zero or of small
order is rejected; a signature is verified with the cofactorless equation the
Go standard library uses. Every signed preimage begins with its own domain,
so no signature verifies as another object.

These are fixed-layout binary Carrier encodings, not protobuf messages, for
the reason relay spec section 2 gives: they never cross the Native service
boundary, never enter a signed Native action and add no chain field. No proto
change is made. Frozen vectors (A1) pin them.

### 5.1 Transport delegation

```text
transport_delegation (159 bytes) =
  D("tos.service.agent-transport-delegation.v1")   42
  agent_digest                                     32
  transport_public_key                             32   Ed25519
  policy_hash                                      32   representation hash of the
                                                        finalized policy cell at issue
  purposes                                         u8   bit 0 relay access, bit 1 hints,
                                                        bit 2 direct sessions; non-zero;
                                                        other bits zero
  not_before_unix                                  u64
  not_after_unix                                   u64  0 < nb < na, na - nb <= 31,536,000
  max_credential_seconds                           u32  1 .. 604,800

delegation_digest = SHA-256(transport_delegation)
```

The Agent commits `delegation_digest` with the existing add-delegation action
(`DelegateAgentV1`, [`NATIVE_REGISTRY_STATE_MACHINES.md`](NATIVE_REGISTRY_STATE_MACHINES.md)),
authorized by its delegation-purpose controllers. No chain change is needed.

`VerifyDelegation(bytes, purpose, now)` passes only if:

1. the bytes decode strictly;
2. the Agent resolves from finalized state, is not tombstoned, and
   `CheckState` accepts it;
3. `delegation_digest` is in the Agent's finalized `delegation_digests`;
4. `policy_hash` equals the hash of the Agent's finalized policy;
5. `not_before_unix <= now + 300` and `now < not_after_unix`;
6. the requested purpose bit is set.

Checks 2 to 4 are the revocation checks. A verifier MAY reuse a passing
result for at most **300 seconds** (the re-check interval); after that it
reads finalized state again before the next use. When finalized state cannot
be read, a cached pass stays usable until it is **600 seconds** old and is
then refused (fail closed).

**Revocation and rotation.** Any policy update, recovery completion or
tombstone changes check 2 or 4 and revokes every transport delegation of the
Agent at once; a node re-commits a fresh delegation after a policy update.
The registry has no action that removes one delegation digest; section 18 Q1
decides to add it, and check 3 then also covers withdrawal. Until then,
revoking one compromised transport key without touching the policy is not
possible, and the response to a compromised transport key is a policy update.

**Between a revocation and the new delegation.** Mailboxes are keyed by
Agent, not by delegation, so nothing stored is lost: relays keep accepting
stranger-lane deposits, and contact credentials of the revoked delegation are
refused (`credential_revoked`), so contacts fall back to the stranger lane.
The owner cannot fetch until its new delegation is finalized; it then fetches
everything still held, republishes its hints, and issues new contact
credentials in band. Envelopes that outlive the gap at a relay are covered by
the senders' re-deposit until the delivery acknowledgement (D10).

An Agent SHOULD keep one delegation per lane process (the chat node and the
rail node each hold their own key) and MUST NOT hold more than 4 transport
delegations that verify at once; a verifier that sees more uses none of them
past the fourth in digest order, so a fifth cannot displace live ones.

### 5.2 Relay credential

```text
credential =
  D("tos.service.relay-credential.v1")     32
  transport_delegation                     159
  block_count                              u8    1 .. 4
  block × block_count

block =
  block_length       u16   length of the rest of this block
  next_public_key    32    Ed25519; signs the next block and every request proof
  caveat_count       u8    1 .. 8
  caveat × count           strictly ascending type, each type at most once per block
  signature          64

caveat = type u8 || value_length u16 || value
```

Signing, with `signer_0` the transport key and `signer_i` (i > 0) the key
whose public half is `next_public_key` of block `i - 1`:

```text
chain_0     = SHA-256( D("tos.service.relay-credential.chain.v1") || delegation_digest )
preimage_i  = D("tos.service.relay-credential.block.v1") || chain_i || u8(i)
              || next_public_key_i || caveat_count_i || caveats_i
signature_i = Ed25519.Sign(signer_i, preimage_i)
chain_i+1   = SHA-256( D("tos.service.relay-credential.chain.v1") || chain_i || signature_i )
credential_id = chain_block_count
holder key    = next_public_key of the last block
```

Each signature covers the chain value, which covers every earlier signature,
so blocks cannot be reordered, dropped from the middle, or spliced from
another credential. The holder can append a block (it holds the private holder
key) but cannot remove or change one. A credential is at most **2,048
bytes**; the largest valid one is 1,908.

### 5.3 Caveats

The caveat set is closed. An unknown type is a decode error, never ignored.

| Type | Name | Value | Satisfied when |
|---|---|---|---|
| 1 | `not_before` | u64 | `not_before <= now + 300` |
| 2 | `not_after` | u64 | `now < not_after` |
| 3 | `relay` | canonical relay base URL, 1..256 bytes, the key-card URL rules of relay spec 6.2 | it equals the base URL the relay is configured with, byte for byte |
| 4 | `operations` | u16 bitmask: bit 0 deposit, bit 1 list, bit 2 fetch, bit 3 publish, bit 4 revoke; others zero | the request's operation bit is set |
| 5 | `lane` | 16 bytes, not all zero | always; names the quota lane of deposits (6.2) |
| 6 | `max_envelopes` | u32, at least 1 | the lane holds fewer stored envelopes than the value |
| 7 | `max_envelope_bytes` | u32, 1 .. 262,144 | the deposited envelope is no longer |
| 8 | `max_lane_bytes` | u64, at least 1 | the lane's stored bytes plus this envelope do not exceed it |

Rules:

- Block 0 MUST carry `not_before`, `not_after` and `operations`, with
  `not_after - not_before <= max_credential_seconds` of the delegation.
- A request satisfies a credential only if it satisfies **every caveat of
  every block**. Caveats therefore only narrow: a later block can repeat,
  shrink or add a bound, and an attempt to widen one is simply another bound
  the request must also meet. The effective lifetime is the minimum
  `not_after` and the maximum `not_before` over the blocks.
- At most one `lane` value may appear over the whole chain; two different
  values make the credential unusable, so a holder cannot move its deposits
  into another lane by appending one.
- There is no sealing: appending only narrows, so the ability to append
  grants nothing.

Profiles (what honest issuers produce):

| Profile | Issued by | Blocks | Operations | Lifetime |
|---|---|---|---|---|
| owner credential | the lane process for itself | 1 | list, fetch, publish, revoke | at most 3,600 s; regenerated locally |
| contact credential | the mailbox owner, for one peer Agent | 1, held by the peer | deposit | at most 604,800 s, SHOULD be 259,200; with `lane`, `max_envelopes` <= 64, `max_envelope_bytes` |
| relay-scoped copy | the holder, for one relay | holder appends 1 block | unchanged | unchanged; adds `relay` |

The contact credential's holder key is a fresh Ed25519 key whose private
half travels to the peer inside the sealed, signed packet that carries the
credential (9.3), so only that peer can make request proofs. Its lane is a
random 16-byte value per peer, never derived from the peer's Agent ID.

### 5.4 Request proof

Every credentialed relay request carries a proof by the holder key:

```text
proof_preimage =
  D("tos.service.relay-request.v1")
  credential_id                32
  relay_url_length u16 || relay base URL
  method_length    u8  || method
  path_length      u16 || escaped request path
  body_digest                  32   SHA-256 of the request body (of zero bytes when empty)
  issued_at_unix               u64
  nonce                        32   random

TOS-Relay-Credential: base64url(credential), no padding
TOS-Relay-Proof:      base64url(issued_at_unix u64 || nonce 32 || signature 64), no padding
```

The relay requires `|now - issued_at_unix| <= 120`, claims the nonce per
`credential_id` for 240 seconds in a bounded table, and refuses a reused one.
Binding the relay URL means a malicious relay cannot replay a proof it
received at another relay; binding the body means a proof cannot carry other
bytes. Credentials and proofs never appear in a URL.

### 5.5 Reachability hint and hint record

```text
hint =
  D("tos.service.agent-reachability-hint.v1")     39
  transport_delegation                            159
  issued_at_unix                                  u64
  expires_at_unix                                 u64  issued < expires <= issued + 86,400
  relay_count                                     u8   1 .. 4
  relay × relay_count       url_length u16 (1..256) || url; priority order, no duplicates
  direct_count                                    u8   0 .. 2
  direct × direct_count     kind u8 (1 = ADNL over UDP/IPv4) || adnl_id 32 || ipv4 4
                            || port u16 (non-zero) || inbound_class u8 (1 or 2)
  object_count                                    u8   0 .. 3
  object × object_count     kind u8 || length u32 || digest 32; strictly ascending kind
  signature                                       64   transport key, over every preceding byte

object kinds:  1 = rail key card packet JSON (<= 9,216 bytes)
               2 = chat key card packet JSON (<= 9,216 bytes)
               3 = Messenger relay identity evidence (<= 18,432 bytes, carriage 2.5)
object digest = SHA-256( D("tos.service.agent-reachability-hint.object.v1") || u8(kind) || object )

hint_record =
  D("tos.service.agent-reachability-record.v1")
  hint_length u16 || hint
  object bytes, in the hint's order, each exactly its listed length
```

A hint is at most 1,536 bytes (1,504 when maximal); a hint record at most
**40,960 bytes**.

`inbound_class` is what the publisher knows about inbound UDP to that
address: 1 = declared by its operator (a public address or a forwarded port),
2 = verified, meaning the node holds a coordinator-signed filtering receipt
from a cold source no older than 24 hours (`messenger/pkg/reachability`).
Both are claims of the hint's signer; a wrong claim costs one failed probe
(section 8). A hint with a direct entry exposes that address publicly, so a
node lists one only when its owner enabled direct sessions (8.1).

`VerifyHint(record, now)`, run by every consumer and by relays:

1. strict decode of record and hint; every object present with its length
   and digest;
2. `VerifyDelegation(transport_delegation, hints, now)`;
3. the signature verifies under the delegation's transport key;
4. `issued_at_unix <= now + 300` and `now < expires_at_unix`;
5. relay URLs canonical (relay spec 6.2); IPv4 addresses public unicast
   (a test configuration MAY admit private ranges and records it).

Consumers additionally verify each card with `VerifyKeyCard` and require its
Agent to equal the hint's Agent, and verify evidence with `CheckPeer`
(carriage 2.5), before using either. A relay cannot verify cards (it holds no
`tosctl`); it checks digests and that the card packet's `sender_agent_id`
field equals the hint's Agent.

**Newest.** Of the verified hints of one delegation, the newest is the one
with the greatest `issued_at_unix`, ties broken by the greater SHA-256 of the
hint bytes. Hints of different delegations are independent: each describes
its own lane process.

**A hint never authorizes.** Its relays are where to deposit and its direct
entries where to dial; its cards are verified as cards. A valid hint that
points at a dead or hostile relay loses availability, which multi-relay
deposit (section 10) and the carriage's redelivery bound.

**Precedence over the card's relay list.** While a valid hint of the
recipient's lane is held, its relay list replaces the relay list of the key
card it carries; without one, the card's list is used as in V1. Section 18
Q11 removes the card's list later.

### 5.6 Direct hello and receipt

```text
hello =
  D("tos.service.agent-direct-hello.v1")      34
  role                                        u8   1 = initiator, 2 = responder
  transport_delegation                        159
  local_adnl_id                               32
  peer_adnl_id                                32
  initiator_nonce                             32
  responder_nonce                             32   all zero in the initiator's hello
  issued_at_unix                              u64
  signature                                   64   transport key, over every preceding byte

deliver_request = D("tos.service.agent-direct-deliver.v1") || envelope   (envelope <= 262,144)

receipt =
  D("tos.service.agent-direct-receipt.v1")
  recipient_agent_digest                      32
  envelope_id                                 32
  outcome                                     u8   1 stored, 2 duplicate, 3 refused
  received_at_unix                            u64
  signature                                   64   recipient's transport key
```

A hello is 394 bytes and travels in one ADNL query, inside the measured
8,192-byte cap. Envelopes travel only as RLDP2 queries, because almost every
relay frame bucket exceeds one ADNL query.

## 6. Relay V2

V2 keeps every rule of relay spec section 9 that this section does not
change: HTTPS only, no redirects, no query strings, the request evaluation
order, the deposit steps, the acknowledgement secret, tombstones, bounds,
retention and the D10 TTLs. Paths are below the base URL `B`.

### 6.1 Operations

| Request | Credential | Effect |
|---|---|---|
| `PUT B/v2/mailboxes/{agent}/envelopes/{id}` | none (stranger lane) or deposit | deposit, relay spec 9.2 steps, then lane quotas |
| `GET B/v2/mailboxes/{agent}/envelopes` | list, owner | the V1 listing plus `"lane": "stranger"` or `"contact"` per entry; optional `TOS-Relay-Wait: 1..25` holds the answer until an entry exists or the wait ends |
| `GET B/v2/mailboxes/{agent}/envelopes/{id}` | fetch, owner | download |
| `POST B/v2/mailboxes/{agent}/envelopes/{id}/ack` | none | acknowledgement by secret, unchanged; the sender can still withdraw |
| `PUT B/v2/mailboxes/{agent}/policy` | publish, owner | mailbox policy (6.2) |
| `POST B/v2/mailboxes/{agent}/revocations` | revoke, owner | revoke credential chains (6.3) |
| `PUT B/v2/hints/{agent}` | none | store a hint record (6.5) |
| `GET B/v2/hints/{agent}` | none | the newest record of each delegation of the Agent, at most 4 |
| `GET B/v2/relay` | none | description: the V1 fields plus `stranger_max_envelopes`, `stranger_max_bytes`, `max_wait_seconds`, `directory` |

`{agent}` MUST equal the Agent of the credential's delegation; a mismatch is
`403 credential_scope`. Mailboxes stay keyed by Agent ID (section 18 Q4).

Credential checks run after the V1 steps 1 to 5 of relay spec 9.1 (address,
rate limit, query, path, method) and before the operation, cheapest first:
decode; delegation shape and Agent match; block chain and signatures;
caveats against the request; proof window, signature and nonce; the
mailbox's revocation set; and last `VerifyDelegation` with the relay-access
purpose, which may need a finalized read. A deposit's caveats that depend on
the stored envelope (sizes, lane counts) are checked at the quota step.

### 6.2 Lanes and mailbox policy

Every stored envelope belongs to one lane of its mailbox:

- **stranger lane**: deposits without a credential. Per mailbox at most
  `stranger_max_envelopes` (relay default and maximum 64, default 32) and
  `stranger_max_bytes` (default 2 MiB, maximum 4 MiB); per (client address,
  mailbox) at most 8 envelopes. Address aggregation is relay spec 9.8's.
- **contact lanes**: deposits with a deposit credential, keyed by the
  credential's `lane` value or, without one, by `credential_id`. A lane holds
  at most `min(max_envelopes, 64)` envelopes and `max_lane_bytes` bytes.

The per-recipient bound of 256 envelopes and 16 MiB stays, and the stranger
lane can never hold more than 64 of it, so contact lanes always keep at least
192 envelopes. A full lane answers `507 quota_exhausted` with the lane in
the error (`"lane": "stranger"` or `"contact"`).

The owner MAY lower its stranger lane, to zero for a closed mailbox:

```text
mailbox_policy =
  D("tos.service.relay-mailbox-policy.v1")
  issued_at_unix           u64   strictly greater than the stored policy's
  stranger_max_envelopes   u16   0 .. relay maximum
  stranger_max_bytes       u32   0 .. relay maximum
```

The policy request is authorized by the owner credential and proof; the
relay stores the newest policy per mailbox durably.

### 6.3 Revocation of credentials

Chain revocation (I5) covers the whole delegation. To revoke what it gave
one contact, the owner posts:

```text
revocation_request =
  D("tos.service.relay-revocation.v1")
  count  u8  1 .. 32
  count × ( chain_value 32 || until_unix u64 )
```

A `chain_value` is any `chain_i` of a credential (5.2), so revoking the value
after block 0 of a contact credential revokes that credential and everything
its holder appended. The relay keeps each entry until `until_unix`, which
MUST be at most `now + 604,800 + 300`; a mailbox holds at most 1,024 entries
(`507` past that). An owner revoking a contact posts to every relay of its
live hints and of its retired relays under 9.4. It journals the revocation
first and retries each relay with back-off until that relay answered `204`
or the revoked credential has expired, so a relay that was down at the time
learns it on return; until then the contact can deposit there, bounded by its
lane quota. Stored envelopes of a revoked lane stay until acknowledged or
expired: revocation stops new deposits, it does not delete.

### 6.4 Narrowing, checked

A relay MUST evaluate the credential only as section 5.3 defines: every
caveat of every block, a closed caveat set, at most one lane. Implementations
MUST NOT collapse blocks into a merged scope before checking, because a merge
that takes the last value of a caveat instead of every value is exactly the
widening the format exists to prevent. Section 16 A2 requires a property test
of this.

### 6.5 Hint directory

A relay stores a hint record only after `VerifyHint` passes, and only if it
is newer than the stored record of the same delegation; an equal
`issued_at_unix` with different bytes is `409 hint_conflict`. It keeps at
most 4 records per Agent (one per delegation; a fifth delegation's record is
refused, not swapped in) and a configured number of Agents (default 16,384).
A full directory refuses new Agents with `507` and evicts only expired
records. A relay stores records of Agents whose hint names it; a relay whose
description says `"directory": true` stores records of any Agent.

Storage is bounded by cost: every record needs a live finalized Agent with a
committed delegation, which costs a chain transaction, so filling a directory
costs one Agent registration per record. Lookups are open (hints are public),
rate-limited per client address (default 60 per minute) and answer `404` for
an Agent with no record. A relay re-verifies a stored record's delegation
before serving it once the 300-second re-check interval has passed and drops
records whose delegation no longer verifies.

**Bootstrap.** Network settings list directory relays as bootstrap hints,
like DHT bootstrap nodes: operated by more than one party, none trusted. A
node publishes its record to every relay of the hint and to at least two
directory relays, and republishes before half of the hint's lifetime has
passed.

### 6.6 Errors

The V1 codes stay. V2 adds, each code belonging to exactly one status:

| Status | Code | Meaning |
|---|---|---|
| 401 | `credential_required` | list, fetch, policy or revocation without a credential |
| 403 | `credential_invalid` | decode, chain, signature, proof or nonce failure |
| 403 | `credential_scope` | a caveat fails, or the path names another Agent |
| 403 | `credential_revoked` | the delegation no longer verifies, or a chain value is revoked |
| 409 | `hint_conflict` | an equal-time hint with different bytes |
| 503 | `chain_unavailable` | finalized state could not be read and no cached pass younger than 600 s exists; retryable |

`403` with `credential_revoked` is terminal for that credential at that relay;
the other `403` codes are terminal for those bytes. A client believes a code
only when it is one of its status's codes.

## 7. Session setup and mutual verification

Three layers, each verified independently:

1. **Relay sessions.** The client authenticates the relay by TLS (WebPKI, or
   a pinned CA on test relays); the relay authenticates the client per
   request by credential and proof (5.4). Neither identifies the other as an
   Agent beyond that.
2. **Direct sessions.** The ADNL channel authenticates both ADNL keys; the
   hello exchange (8.3) binds each ADNL key to a transport delegation of the
   expected Agent, verified against finalized state.
3. **End to end.** Every packet is signed by a finalized controller of its
   sender and names its recipient; Messenger copies are additionally E2EE
   under the session and its pinned Endpoint and device (carriage 2.4). This
   layer is the same on every path, and it is the only one that establishes
   who sent a message.

## 8. Relay-first and direct upgrade

### 8.1 When an upgrade is attempted

A lane attempts a direct session to a peer only when **all** hold:

- both owners enabled direct sessions (`direct: true` in the lane
  configuration; default off), so neither side's address is exposed without
  consent;
- the peer's newest verified hint for this lane has a direct entry of kind 1
  with `inbound_class` 1 or 2, and the delegation has the direct purpose;
- the local node has IPv4 egress (the native stack sends no IPv6);
- the peer is an admitted contact on this lane (a Messenger peer with an
  established session, or a rail counterparty of a live purchase);
- the lane has an envelope to send to that peer;
- the peer is not in cooldown, and the probe budget allows it (at most one
  probe per peer per 10 minutes and 16 probes per minute in total).

No upgrade is attempted when neither side has an inbound entry. M0-R has no
field evidence for NAT-to-NAT establishment, and hole punching needs a
rendezvous this design does not add (section 18 Q6). An Agent behind NAT can
still reach a peer with an inbound address: it dials, and the peer answers
over the mapping the dial opened.

### 8.2 States

Per (lane, peer Agent):

```text
            attempt rule (8.1)                hello verified
  RELAY ------------------------> PROBING ----------------------> DIRECT
    ^  ^                            |                               |
    |  |  idle 600 s, peer hint     | timeout 5 s, refusal,         | 2 consecutive deliver
    |  |  dropped the entry,        | verification failure          | failures, 2 missed
    |  |  re-check failed           v                               | keepalives after one
    |  +--------------------------- COOLDOWN <----------------------+ reconnect
    |   (re-check failure: RELAY, peer marked revoked until a new hint)
    +--- cooldown elapsed
```

- **RELAY.** Every envelope goes to relays (section 10). This is the start
  state and the state after every restart; direct state is never persisted.
- **PROBING.** The initiator dials the peer's ADNL address, confirms the
  channel with an ADNL ping, and exchanges hellos (8.3) within **5 seconds**.
  Envelopes due meanwhile go to relays; nothing waits for a probe.
- **DIRECT.** Envelopes are delivered over RLDP2 (8.4). A keepalive ping runs
  every **15 seconds** (under the 30-second UDP mapping timeout common on
  consumer NATs). After two missed keepalives the initiator resets the
  channel once; the hello binding is kept, because a reconnect resets only
  the channel and the ADNL identities it binds are unchanged. The peer's
  delegation is re-verified every 300 seconds; a failure closes the session.
- **COOLDOWN.** 1 hour after the first failure, doubling per consecutive
  failure to at most 24 hours; cleared when the peer publishes a hint with a
  different direct entry. Cooldowns are kept in memory only; the probe
  budget bounds probing after a restart.

### 8.3 Hello exchange

1. The initiator sends its hello (`role = 1`, its `local_adnl_id`, the
   dialed `peer_adnl_id`, a fresh `initiator_nonce`) as an ADNL query.
2. The responder requires: `local_adnl_id` equals the channel's
   authenticated peer; `peer_adnl_id` is its own; `|now - issued_at| <= 120`;
   `VerifyDelegation` with the direct purpose; the signature; and that the
   delegation's Agent is an admitted contact of this lane. It answers a
   failure with nothing (a stranger learns nothing, not even that the node
   runs), and success with its hello (`role = 2`, the same
   `initiator_nonce`, a fresh `responder_nonce`).
3. The initiator requires the mirror checks, that the delegation's Agent is
   the intended peer, and that the responder's `local_adnl_id` equals the
   ADNL ID of the hint entry it dialed.

A session ends at once when either side stops admitting the other (contact
removed, purchase ended), not at the next re-check.

At most one session per (lane, peer); at most 64 direct sessions per lane;
a crossed dial (both sides initiating) keeps the session whose initiator has
the smaller ADNL ID and closes the other.

### 8.4 Delivery on the direct path

The sender journals the envelope before the first attempt (relay spec 8.4
step 4), sends it as a `deliver_request` RLDP2 query, and waits at most 5
seconds plus its length at 32 KiB/s (at most 13 seconds). The recipient runs
exactly the relay spec 8.5 steps 1 to 6 and answers:

- `stored` or `duplicate` after the durable inbox write: the envelope is
  settled. The sender verifies the receipt under the peer's transport key and
  treats it as delivered by the carrier; it does **not** deposit at relays.
  This is stronger than a relay's `201`: it is what the relay acknowledgement
  means;
- `refused` for a permanent 8.5 step 4 or 5 failure: the sender does not
  deposit either, exactly as a relay copy the recipient refused is
  acknowledged and gone;
- no receipt, a transient failure, or an invalid receipt: the sender deposits
  the same journaled bytes at relays at once (I3), counts a failure, and
  stays in DIRECT until the second consecutive failure.

What the carrier reports does not depend on the path. A settled or refused
direct delivery is reported to the Messenger daemon as `carried`, with the smallest advertised TTL of the hint's relays, so the
Messenger journal keeps its re-deposit schedule and still waits for the
Endpoint-signed delivery acknowledgement (carriage 5.2, 5.3); a lost
acknowledgement costs one relay re-deposit, answered `duplicate`.

Crash windows: the sender journals before the first attempt, so a sender
that dies after a receipt but before recording it restarts in RELAY and
deposits the same bytes, which the recipient acknowledges at the relay
without downloading (below), or, if a restart lost its memory of settled
IDs, downloads and finds to be a duplicate in its inbox. A recipient that dies after its inbox write
but before answering leaves the sender to time out and deposit; the copy is
then a duplicate.

The recipient keeps polling its relays in every state: other peers, and this
peer's fallbacks, still arrive there. An envelope ID settled on the direct
path is settled for every relay (relay spec 8.6): when a relay later lists
it, the recipient acknowledges it with the secret it already recovered,
without downloading it.

Bounds on the responder: deliver requests at most 60 per minute per peer;
at most 4 in flight per peer and 16 per lane; a request larger than 262,144
bytes plus its domain is refused by the driver before it is read; no answer
exceeds 256 bytes.

## 9. Credentials and hints in use

### 9.1 Own state of a lane

A lane process holds: its transport key (mode 0600 in its state directory,
or behind an external signer), its committed delegation, its HPKE keys and
cards (relay spec 6.3), its current hint, an owner credential renewed every
hour, and the contact credentials it issued (lane, holder key, expiry) and
holds (per peer, per relay).

On start it verifies its own delegation; if that fails it publishes nothing,
deposits only on stranger lanes, and raises the owner notice
`transport-revoked`. It then publishes its hint record and mailbox policy to
its relays and directory relays.

### 9.2 Resolving a peer

In order, using the first that yields a valid hint for the needed lane:

1. a hint the peer carried in band in a verified packet of this lane;
2. the local hint cache (newest per delegation, bounded to 4,096 peers);
3. a hint record from a contact file, invite, offer file or Gateway Quote
   package;
4. `GET /v2/hints/{agent}` at the peer's last known relays, then at directory
   relays.

Every answer is verified with `VerifyHint` before use, and the resolved
cards and evidence with their own verifiers. With no valid hint, the V1 card
relay list is used. With neither, the send stays pending with `no-route`.

### 9.3 Distributing contact credentials

The owner issues a contact credential to a peer when it admits that peer on
the lane (a Messenger peer with a session or admitted under carriage 2.3, a
rail counterparty of a live purchase), and renews it once less than half its
lifetime remains. It travels in band, inside the sealed and signed packets
the lane already sends to that peer:

- **chat lane:** a new `credential` field of the relay frame, which becomes
  `tos.messaging.relay-frame.v2`:
  `credential_length u16 (0 or 1 .. 2,048) || credential || holder_seed 32`
  (the seed present only with a credential) directly after `evidence`,
  present until the peer acknowledged a frame that carried it, like the card
  (carriage 2.3). The frame bounds of carriage 1.1 and 4 are recomputed in the
  frame PR; the largest Event payload falls by at most 2,082 bytes;
- **rail lane:** beside the key card in the task, result and
  acknowledgement headers that carry the card today (relay spec 6.4).

A receiver takes a credential only from a verified packet of a peer it
admitted, only when the credential's delegation Agent equals that packet's
sender (it opens the sender's mailbox to the receiver), and stores at most one
per (peer Agent, relay set). A sender without a valid contact credential for
a recipient deposits on the stranger lane, where admission at the recipient
is unchanged: the stranger lane is a quota, not an admission decision.

### 9.4 Publishing and retiring relays

A hint SHOULD live 6 hours (at most 24) and is republished at half its
lifetime and whenever its relays, direct entries or cards change. A lane MUST
keep polling a relay it no longer names until the last hint that named it
expired plus that relay's `max_ttl_seconds` plus 300 seconds, so envelopes
deposited from a stale hint are still collected.

## 10. Multi-relay delivery and deduplication

**Sender.**

1. Resolve the recipient's relays (9.2): up to 4, in hint order.
2. Seal once and journal before the first deposit (relay spec 8.4).
3. If DIRECT and the direct delivery settles (8.4), stop.
4. Deposit to relays in order, each with its contact credential (with a
   `relay` caveat appended for that relay) or on the stranger lane. Report
   `carried` on the first acceptance (`200`, `201`, `410`), with the smallest
   advertised `max_ttl_seconds` of the hint's relays, exactly as the carriage
   reports it today.
5. Continue in the background until **two** relays accepted the envelope, or
   every relay was tried. A `409` abandons that relay for this envelope
   (relay spec 8.6); a `507` on a contact lane retries that relay once on the
   stranger lane; a `403 credential_revoked` drops that credential.
6. Re-deposit and withdraw generations as the carriage specifies
   (section 4, D10): next generation at 80 % of the reported TTL, at least 10
   minutes apart, until the delivery's own expiry; packet expiry stays the
   business deadline.

Two copies instead of V1's one per relay: two survive any single relay loss,
and four copies of every envelope would spend four relays' quotas for no
further independence when the relays share an operator.

**Recipient.**

- Poll every relay of every live hint of the lane, and retired relays under
  9.4, with the owner credential; use `TOS-Relay-Wait` on at most one relay
  at a time (the hint's first reachable relay) and plain listing every 15
  seconds on the others.
- Download only entries whose `recipient_key_id` it holds and that it has not
  settled; prefer contact-lane entries when a poll returns more than it will
  download at once.
- Settle by the relay spec 8.5 rules, then acknowledge at every relay that
  listed the ID. Settled IDs from the direct path count (8.4).
- Exactly-once processing stays where it is: the inner packet's replay guard
  and the Messenger journal (carriage 5.1), or the rail inbox and the Native
  Execution Gate claim.

## 11. Metadata a relay sees

| Observer | Learns | Does not learn |
|---|---|---|
| Relay operator, mailbox it hosts | the owner's Agent ID and transport delegation (public in its hint); its poll and acknowledgement times and address; per envelope: recipient key ID, size (the frame bucket of carriage 1.1), deposit time, expiry, depositor address, and the lane: `stranger`, or an opaque lane value that links deposits of one contact over time | the sender Agent (except by matching addresses, as in V1), Endpoint, device, conversation, room, Event, frame kind, content |
| Relay operator, directory | which address looked up which Agent, and when | why |
| Another relay user, or anyone knowing an Agent ID | the Agent's public hints: relays, cards, Messenger evidence, and direct addresses if its owner enabled them | anything about its mailbox: count, sizes, times, ciphertext |
| Network observer | that a node talks HTTPS to a relay, or ADNL to an address | anything inside |
| Direct peer | the other side's IPv4 address and port | nothing a relay would not; it is the counterparty anyway |

Compared with V1, the public loses all mailbox metadata (G4); the operator
gains the lane value of contact deposits. Rules that keep the operator's view
minimal:

- lane values are random per peer and never derived from an Agent ID or a key;
- a relay MUST NOT log credentials, proofs, lane values, envelope IDs or
  acknowledgement secrets, and keeps the depositing address only beside the
  stored envelope for the per-(address, mailbox) quota, as V1 does;
- owner credentials carry no lane, and owner proofs no stable value beyond
  the credential ID, which changes every hour;
- padding to frame buckets, prompt acknowledgement and the no-presence rule
  of carriage section 6 stay.

## 12. Failure and refusal modes

| Situation | Behaviour | Surface |
|---|---|---|
| No valid hint and no card | send stays pending; retried on the next resolution | `no-route` |
| Hint expired, cards valid | card relay list (V1 behaviour) | none |
| Peer's delegation no longer verifies | no seal, no deposit, no direct; pending until a hint of a verifying delegation arrives | `peer-revoked` |
| Own delegation no longer verifies | stop publishing; stranger lanes only; owner credential unusable, so no fetch | `transport-revoked` owner notice |
| Contact credential refused (`credential_revoked`) | drop it; stranger lane | none |
| Lane full (`507`) | next relay; then stranger lane; then pending | `peer-cap` if every relay is full |
| `chain_unavailable` at a relay | other relays; stranger lane deposit at that relay is still possible | none |
| All relays down | journaled; retried with back-off; direct used if DIRECT | `carrier-unavailable` after 10 minutes |
| Directory answers junk or nothing | `VerifyHint` refuses junk; next source (9.2) | none |
| Hello refused, timed out or unverifiable | COOLDOWN; relay | none |
| Direct receipt invalid or missing | deposit the same bytes at relays | none |
| Peer hint lists only IPv6 or private addresses | not a direct entry; relay | none |
| Equal-time conflicting hints | relay keeps the first (`409`); consumers keep the one they verified first and log the conflict | `hint-conflict` in telemetry |

Every surface code is fixed text; nothing a peer, relay or directory sent is
repeated in it.

## 13. Local API and MCP tools

### 13.1 Local node

`tos-messengerd` runs the chat lane in process (`carrier: builtin`). Its
owner and runtime sockets keep their current form: mode-0600 Unix sockets in
a private directory, one single-writer daemon per state directory
(`messenger/pkg/localapi`). The runtime socket gains one operation,
`conversations.list` (bounded, newest first, at most 64 per page). The daemon
signs packets through `tosctl` as OpenFox does today; it holds the transport
key and HPKE keys of its lane, never wallet keys.

### 13.2 MCP server

`tos-messenger-mcp` speaks MCP over stdio, started by the MCP client as a
child process, like `tos-service-buyer-mcp`
([`MCP_BUYER_ADAPTER_V1.md`](MCP_BUYER_ADAPTER_V1.md) 2.2). It holds no
secret and connects only to the daemon's runtime socket, never the owner
socket.

| Tool | Kind | Input | Output |
|---|---|---|---|
| `tos_messenger_resolve` | read-only | `recipient`: `.tos` name or Agent ID | canonical Agent ID, contact state (`contact`, `stranger`, `held`), whether a route is known |
| `tos_messenger_send` | idempotent per `idempotency_key` | `recipient`, `text` (at most the payload bound), optional `reply_to`, `idempotency_key` | delivery ID and state (`pending`, `carried`, `delivered`, `held`, `rejected` with its fixed code) |
| `tos_messenger_receive` | not read-only | optional `conversation`, `max` (1..16), `wait_seconds` (0..25) | admitted inbox items, each completed when returned |
| `tos_messenger_conversations` | read-only | optional page token | conversations: peer Agent ID, last activity, unread count |
| `tos_messenger_status` | read-only | delivery ID | its state and fixed code |

Rules:

- No tool accepts or returns a relay, ADNL address, Endpoint, device,
  session, key or credential: those are unrepresentable at this boundary
  (economy plan section 8).
- Owner operations stay off MCP: admitting strangers, invites, rooms
  management (carriage D13), contact removal and lane configuration.
- Received text is returned as untrusted data in a dedicated field, never in
  tool names, titles or descriptions, and passes the context firewall of the
  messenger spec section 19.2.
- A first message to a stranger is sent on the stranger lane and is held at
  the recipient under its admission policy; the tool reports `held` only
  when the recipient's signed ack says so.

## 14. OpenFox migration

1. OpenFox's rail lane moves onto `protocol/pkg/agentcarrier`: keys, cards,
   outbox, poller and relay client are the library's; OpenFox keeps only its
   rail frames, courier and receiver (`openfox` `pkg/servicebridge/transport.go`).
2. OpenFox's chat lane is deleted (`relay_chat.go`, `relay_chat_setup.go`,
   the chat parts of `relay_cards.go` and `relay_inbound.go`). OpenFox starts
   or connects to `tos-messengerd` with `carrier: builtin` and reaches chat
   only through the local API it already uses.
3. Each of the two processes commits its own transport delegation and
   publishes its own hint, so chat and rail keep separate keys and may name
   separate relays (carriage section 7).
4. No state migration: pre-launch nodes are re-provisioned with fresh keys,
   delegations and cards; contacts re-establish by Agent ID through hints.
5. `messenger/pkg/carrierapi` and the V1 relay endpoints are removed once no
   client uses them (section 17, PR 14). The no-loop rule of carriage 1
   stays: no rail packet travels inside a chat copy.

## 15. Limits

| Item | Bound |
|---|---|
| Transport delegation | 159 bytes; lifetime at most 365 days; at most 4 verifying per Agent |
| Re-check of finalized state | every 300 s; cached pass refused after 600 s without a read |
| Credential | at most 2,048 bytes; 1..4 blocks; 1..8 caveats per block |
| Owner credential lifetime | at most 3,600 s |
| Contact credential lifetime | at most 604,800 s (and the delegation's `max_credential_seconds`); SHOULD 259,200 |
| Request proof | clock window ±120 s; nonce memory 240 s per credential |
| Hint / hint record | 1,536 / 40,960 bytes; lifetime at most 86,400 s, SHOULD 21,600; 1..4 relays; 0..2 direct entries; 0..3 objects |
| Directory | at most 4 records per Agent; default 16,384 Agents; lookups 60/min per address |
| Stranger lane | default 32 envelopes and 2 MiB per mailbox, at most 64 and 4 MiB; 8 per (address, mailbox) |
| Contact lane | at most 64 envelopes; contact lanes keep at least 192 of the 256 per recipient |
| Revocations | 1..32 per request; 1,024 per mailbox; kept at most 604,800 + 300 s |
| Long poll | 1..25 s; one waiting request per mailbox |
| Envelope | at most 262,144 bytes (unchanged) |
| Envelope expiry (D10) | at most the packet's business deadline and deposit + 86,400 s (unchanged) |
| Relay TTL (D10) | 3,600 s on test relays, 10,800 s on production relays, at most 86,400 s |
| Re-deposit (D10) | 80 % of the smallest advertised TTL; at least 600 s apart; until the delivery expiry (default 7 days, at most 30) |
| Copies per envelope | two accepting relays |
| Direct hello | 394 bytes, one ADNL query (cap 8,192) |
| Direct deliver | RLDP2, envelope at most 262,144 bytes; timeout 5 s + length at 32 KiB/s, at most 13 s |
| Direct timing | probe 5 s; keepalive 15 s; idle close 600 s; cooldown 1 h doubling to 24 h |
| Direct budget | 1 probe per peer per 10 min; 16 probes/min; 64 sessions per lane; 60 delivers/min and 4 in flight per peer |
| Direct addresses | IPv4 only |

## 16. Acceptance criteria

Each item is accepted by evidence recorded as the relay and carriage records
are (`spec/deployments/`, commits, binary hashes, commands, `not_verified`,
`qualifies_as_public_acceptance: false` while relays and chain are the core
team's).

| Item | Shows | Evidence |
|---|---|---|
| A1 Codecs | delegation, credential, proof, hint, record, hello and receipt decode strictly; every negative refused with its class | frozen corpus `spec/test-vectors/agent-transport-v1.json`; an independent reproducer run with `python3 -I` under `make spec-check` |
| A2 Narrowing | no appended block widens time, relay, operations, lane or size; splice, reorder and drop are refused | property and fuzz tests naming the generator seed; red-control mutants that merge blocks are caught |
| A3 Chain revocation | after a policy update on a test chain, owner and contact credentials are refused (`credential_revoked`) by two relays within 300 s, and hints stop being served | chain transaction hash, relay logs of the refusal times, both relay commits |
| A4 Fail closed | with every chain endpoint of a relay stopped, credentialed requests get `503 chain_unavailable` once the cached pass is 600 s old; stranger deposits continue | relay log and client transcript |
| A5 Closed mailbox | list and fetch without a credential `401`; with another Agent's credential `403`; a proof replayed at a second relay `403` | integration test and a live transcript against a deployed test relay |
| A6 Lane isolation | a stranger flood from 64 IPv4 addresses fills only the stranger lane; a contact deposits throughout; `507` names the stranger lane | live run against a test relay, quota counters before and after |
| A7 Contact revocation | a revoked contact's deposits are refused at every relay of the hint; its stored envelopes stay until acknowledged | live transcript |
| A8 Multi-relay | with two relays, one killed mid-run: no loss, exactly-once application, acknowledgement at both after restart, two accepted copies per envelope | relay store snapshots, journals, runtime outcome log |
| A9 First contact by Agent ID | an MCP client on a host without OpenFox resolves an OpenFox Agent by Agent ID through a directory relay (no contact file), sends, the owner admits, and the conversation proceeds both ways across two hosts | deployment record with both hosts' commits, the hint records, the MCP transcript |
| A10 OpenFox on the library | OpenFox has no chat carrier code and imports `agentcarrier`; the M-R1 and M-R2 scenarios pass again on V2 relays | `go list -deps` output, the openfox commit, rerun records |
| A11 Direct upgrade | between a node with a verified inbound IPv4 entry and a node behind NAT: upgrade after the first envelope, later envelopes delivered direct with no deposits at relays; a firewall drop mid-run falls back to relays within 13 s with no loss and no duplicate execution | relay deposit counters, sidecar logs, the receipts |
| A12 Never required | with direct disabled, on an IPv6-only host, and between two NATed nodes: no probe is made and every message is delivered by relay | probe counters equal zero, delivery records |
| A13 Metadata | relay store, logs and directory contain nothing of section 11's "does not learn" column; a third party holding the Agent ID gets only public hints | dumps of relay state and logs taken while envelopes were held |
| A14 D10 | test relays at 1 h: re-deposit at 48 min; production profile at 3 h: 2 h 24 min; packet expiry equals the business deadline | carrier journal timestamps against relay descriptions |
| A15 Hygiene | no credential, proof, secret, lane value or plaintext in any URL or log; the relay holds no key but its TLS key and no `tosctl` | grep of logs and the relay's file system; process inspection |

Production claims additionally need relays and directory relays run by an
operator other than the core team, and a public chain, as ROADMAP Gate O
requires.

## 17. Implementation plan

Small pull requests, in order; each runs `make verify` and lands with its
tests.

1. This specification.
2. `agenttransport`: transport delegation codec and `VerifyDelegation`
   against a finalized resolver; vectors.
3. `agenttransport`: credential, caveats and request proof; vectors;
   independent reproducer in `spec/scripts/`; narrowing property tests (A1,
   A2).
4. `agenttransport`: hint, hint record, hello and receipt; vectors.
5. `tos-service-wallet`: create a transport key and delegation, submit
   `DelegateAgentV1`, print the delegation.
6. Relay: finalized reader, credential middleware, `/v2` mailbox list, fetch
   and deposit lanes, mailbox policy (A4, A5, A6).
7. Relay: revocations, hint directory, long poll, description fields (A3, A7).
8. `agentcarrier` part 1: lanes, keys and cards, outbox journal, poller and
   deposit over V2, extracted from `buyeragent` and OpenFox's rail lane.
9. `agentcarrier` part 2: hint publication and resolution, credential issue,
   storage and refresh, two-copy deposit (A8).
10. `buyeragent` on `agentcarrier`.
11. Messenger: relay frame v2 with the credential field; recomputed bounds;
    vectors.
12. Messenger: `messenger/pkg/transport` and `carrier: builtin` in
    `tos-messengerd`; `conversations.list`.
13. Messenger: `tos-messenger-mcp` (A9).
14. OpenFox: rail on `agentcarrier`, chat lane removed (A10); then remove
    `carrierapi` and the V1 relay endpoints here.
15. `tos`: `adnl/tos-adnl-transport` sidecar from the probe core.
16. `adnlpath` driver and the direct state machine in `agentcarrier`, off by
    default (A11, A12).
17. Live evidence runs (A13 to A15) and status updates in this document,
    the carriage, the relay spec and ROADMAP.

Independent of the order: the registry action that withdraws one delegation
digest (section 18 Q1), in `tos` and `protocol/pkg/nativecore`.

## 18. Decisions

The questions this design raised, each with its decision (recorded
2026-11-27).

- **Q1. The registry cannot withdraw a delegation digest.** Add-delegation
  exists; removal does not, so today a delegation dies only with a policy
  change or a tombstone (the carriage's "withdrawn on chain" assumes an
  action that does not exist). **Decided:** a registry action that withdraws
  one delegation digest is added as the reverse of `DelegateAgentV1`,
  authorized like it. It is a `tos` contract change, scheduled after the
  USDC and USDT settlement work. Until it lands, the `policy_hash` binding is
  the revocation; once it lands, check 3 of 5.1 covers withdrawal with no
  change to this design.
- **Q2. Bind delegations to the policy hash?** It makes every policy update
  revoke every transport key, so a benign update costs a re-delegation.
  **Decided: yes, permanently.** A policy update is how an Agent responds to
  compromise; a transport key that survives it would be the one key a
  rotation misses.
- **Q3. One lane per contact, or one shared contact lane?** Per-contact lanes
  give the operator a stable pseudonym per contact; a shared lane lets one
  contact fill it. **Decided: per contact.** Abuse isolation is the point of
  lanes, and the operator can already link a sender's deposits by address.
- **Q4. Opaque mailbox IDs instead of Agent IDs?** The relay learns the Agent
  from the owner credential anyway, which it needs to check revocation, and
  closed listing already hides mailboxes from everyone else. **Decided: keep
  Agent IDs**; an opaque ID would add a mapping and hide nothing.
- **Q5. Hints in the TOS DHT?** A DHT key is the short ID of the publishing
  key, not the Agent ID, and a DHT value is at most 768 bytes, below a hint
  record. **Decided: not in V2**; relay directories answer lookup by Agent
  ID. Revisit for nodes that run only the native stack.
- **Q6. NAT-to-NAT hole punching?** No field evidence; it needs a rendezvous
  and simultaneous dials that the probe avoids on purpose (crossed
  handshakes). **Decided: not in V2**; reopen when a field M0-R study shows a
  cell worth it, with relays offering a UDP reflection service.
- **Q7. Native sidecar or a Go ADNL implementation?** The measured facts come
  from the native stack, and the study itself asks for cross-checking against
  it. **Decided: the native sidecar in production**; the Go implementation
  stays a test peer.
- **Q8. IPv6 direct routes?** The native sidecar aborts on udp6.
  **Decided: no**, until native IPv6 is a separate `tos` work item with its
  own evidence; IPv6-only nodes use relays.
- **Q9. Should a settled direct delivery skip the relay deposit?**
  **Decided: yes.** The receipt states what a relay acknowledgement states;
  depositing anyway doubles load and changes no guarantee.
- **Q10. Drop the per-frame ML-DSA packet signature now that relays check
  credentials?** **Decided: no.** Credentials authorize storage at a relay;
  the packet signature is what proves the sender, post-quantum, on every
  path (carriage 1).
- **Q11. Remove the relay list from the key card?** Two signed sources of
  routes is one too many. **Decided:** after A9, a key card V2 without a
  relay list; until then the hint takes precedence (5.5).
- **Q12. Who runs directory relays?** **Decided:** at least two operators
  listed in network settings, the core team being one; none is trusted, and
  every answer is verified.
- **Q13. Credential lifetimes.** **Decided:** 1 hour for owner credentials
  (local, cheap) and 3 days for contact credentials (at most 7), because
  revocation is by chain re-check and relay revocation lists, and a peer away
  for days should not drop to the stranger lane on return.
- **Q14. Long poll or push?** **Decided:** a bounded long poll on one relay;
  push wake-ups would add a third party that learns online times.

## 19. Changes to other documents

- [`MESSENGER_RELAY_CARRIAGE_V1.md`](MESSENGER_RELAY_CARRIAGE_V1.md): a note
  that the carrier moves into this repository and the relay changes under
  this design; frames, double encryption, evidence and rooms stay.
- [`OPENFOX_AUTONOMOUS_MESSENGER_ECONOMY_PLAN.md`](OPENFOX_AUTONOMOUS_MESSENGER_ECONOMY_PLAN.md):
  Phase B records that the route is relay-first by this design and that M0-R
  evidence now gates only the direct upgrade.
- [`ROADMAP.md`](ROADMAP.md) section 8.1: this design is listed as an
  incubation design.
- [`AGENT_PACKET_RELAY_V1.md`](AGENT_PACKET_RELAY_V1.md) stays the V1
  specification; the V2 relay API is section 6 here.
