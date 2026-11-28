# Messenger Transport V2

How Messenger copies, and every other Agent Packet, cross machines once the
carrier leaves OpenFox: relay-first store-and-forward with an optional direct
upgrade, signed reachability hints, and short-lived relay credentials that
are verified offline and revoked by finalized chain state.

**Status: 🟡 Delegation, credential and reachability boundaries implemented;
transport not accepted.** `protocol/pkg/agenttransport` implements the
finalized delegation verifier of phase 1 item 2; credential, caveat, request
proof and replay admission logic of item 3; and hint, hint record, hello and
receipt codecs/verifiers of item 4. Each has frozen vectors and an independent
reproducer, with synthetic epoch/cache, narrowing, replay and boundary tests.
Production configuration refuses; there is no registry epoch adapter, relay
deployment or live revocation evidence. The remaining runtime transport
surfaces are not implemented. This remains an incubation design under
[ROADMAP section 8.1](ROADMAP.md#81-incubation-designs):
it carries no gate status and supplies no gate evidence. Section 16 lists the
evidence each part needs; section 17 is the implementation order. Until the
registry change of section 18 Q1 is finalized on a network, V2 transport is
limited to test networks (5.1).

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
  share a small stranger lane per mailbox and a bounded stranger share of the
  whole relay; each contact deposits in its own lane.
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
- Backward compatibility. TOS is pre-launch and keeps Messenger V2 only:
  V1 relay endpoints, the `carrierapi` boundary and OpenFox's chat lane are
  removed, not kept (section 17). No V2 component reads a V1 store, decodes
  a V1 frame, accepts a V1-only object or falls back to a V1 route, and no
  pull request adds a compatibility shim, dual-read path or state migration.

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
| Compromised transport key | sign hints and credentials for its Agent until the delegation is revoked, so redirect new traffic to relays it chooses and fetch ciphertext from the real relays | read a packet (the HPKE keys are separate); sign a packet; outlive a policy update, recovery completion or withdrawal by more than the revocation bounds of 5.1 on a network with the authorization epoch |
| Compromised controller | everything the Agent can do | nothing less than total identity compromise; recovered by policy rotation, which also revokes every transport delegation (5.1) |
| The Agent's own delegation authority | admit any delegation it chooses, including one crafted outside the tooling, such as one encoding a future epoch, and re-admit after an epoch bump a delegation it withdrew before | nothing: it is the root of trust and outside this design's threat model; withdrawal is permanent against everyone else (5.1) |
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
  spec 9.8). Stranger deposits can never take the capacity reserved for
  contact lanes, neither within one mailbox nor across the relay (6.2).
- **I5.** Revocation is a chain fact: a policy update, a recovery
  completion, a tombstone or a delegation withdrawal (the last only once the
  registry change of section 18 Q1 exists) stops every credential and hint
  of the delegation at every honest relay and sender without waiting for
  expiry: within 300 seconds while finalized reads succeed, and within 600
  seconds while they fail (5.1). On test networks without the authorization
  epoch, a policy change that returns to an earlier policy is a known gap
  (5.1).

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
| Wallet step | `protocol/cmd/tos-service-wallet` (`transport-delegate`) | journals test-network issuance, creates a non-extractable transport key in controller custody, submits the existing `DelegateAgentV1` action and verifies finalized membership |
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
transport_delegation (167 bytes) =
  D("tos.service.agent-transport-delegation.v1")   42
  agent_digest                                     32
  transport_public_key                             32   Ed25519
  authorization_epoch                              u64  the Agent's finalized authorization
                                                        epoch at issue (below); 0 only on
                                                        test networks before it exists
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
authorized by its delegation-purpose controllers.

**Why the policy hash is not enough.** The registry keeps delegation digests
across an ordinary policy update; only recovery completion and the tombstone
clear them (`tos` `crypto/smartcont/native-registry-code.fc`: the
`kind::update_agent_policy` branch at line 759 replaces only the policy,
while the `kind::complete_recovery` branch at line 780 empties the
delegations at line 790 and the `kind::revoke_agent` branch at lines 791-792
does too; checked at `tos` `db4503c02`). A binding to the
policy hash alone is therefore undone by a policy change A → B → A, which
makes a delegation issued under A verify again, and is never triggered by an
update that installs identical policy bytes.

**No existing value fits.** The Agent state holds `generation` and
`sequence` (`native-registry-code.fc:504-509`). `generation` advances only on
recovery completion (`:690-691`). `sequence` advances on every action
(`:693`), including `DelegateAgentV1` itself, so a delegation bound to it
would be revoked by the commit of the next delegation, and its own commit
cannot be named in it.

**The authorization epoch.** The Agent state gains a u64
`authorization_epoch`, set to 1 at registration and incremented by exactly
the actions that change who controls the Agent: policy update (whatever
bytes it installs), recovery completion and tombstone. Recovery initiation
does not change it, because authority has not changed until completion.
Adding a delegation does not change it, and neither does withdrawing one:
withdrawal removes its digest, which check 3 below already refuses, so one
transport key can be revoked without revoking the Agent's others. The epoch
is never decremented or reused. It ships together with the
withdraw-delegation action of section 18 Q1, as one registry change in
`tos` and `protocol/pkg/nativecore`, outside this plan (section 17). That
change MUST:

- version the Agent state encoding (the Agent root has room for another
  u64) and update every reader and projection of it in the same change;
- increment with checked overflow, refusing the action rather than wrapping;
- keep exact-action replay idempotent: a replayed action returns without a
  second increment, as the registry's replay path does today;
- require every later authority-changing action to increment it, and every
  state migration to preserve or advance it, never reset it.

**Production gating.** Until that change is finalized on a network, V2
transport runs only on test networks: delegations carry
`authorization_epoch = 0`, verifiers check the policy hash only, and the A →
B → A and same-bytes cases above are known gaps. A verifier configured for a
production network refuses every delegation with epoch 0, and a production
network configuration that lacks the epoch is refused at startup. The
test-network exception MUST also match a reviewed, code-pinned allowlist of
exact `(global_id, zero_state_root_hash, zero_state_file_hash)` identities.
Selecting a test mode is not enrollment: an unlisted identity, including a
production identity, is refused in every mode before any delegation is
verified. The list is never supplied by runtime configuration; a new genesis
requires a reviewed code change.

`VerifyDelegation(bytes, purpose, now)` passes only if:

1. the bytes decode strictly;
2. the Agent resolves from finalized state, is not tombstoned, and
   `CheckState` accepts it;
3. `delegation_digest` is in the Agent's finalized live delegation set;
4. `authorization_epoch` equals the epoch the registry recorded when it
   admitted that digest, and both equal the Agent's finalized authorization
   epoch (on a test network without the epoch: the field is 0 and the
   recorded epoch does not exist);
5. `policy_hash` equals the hash of the Agent's finalized policy;
6. `not_before_unix <= now + 300` and `now < not_after_unix`;
7. the requested purpose bit is set.

Checks 2 to 5 are the revocation checks. A verifier MAY reuse a passing
result for at most **300 seconds** (the re-check interval); after that it
reads finalized state again before the next use. When finalized state cannot
be read, a cached pass stays usable until it is **600 seconds** old and is
then refused (fail closed).

**Revocation bounds.** Measured from the moment the verifier's finalized
reader first can return the revoking state (finality and the reader's own lag
are not part of the bound):

- **healthy reads:** at most 300 seconds, because the next use after the
  re-check interval reads the revoking state;
- **reads failing:** at most 600 seconds, because a cached pass is refused at
  that age. The worst case is a revocation that finalizes just after a
  successful read, followed at once by the reader's endpoints failing: the
  stale pass is honoured for the remainder of the 600 seconds and then
  refused.

**Revocation and rotation.** A policy update, recovery completion or
tombstone changes check 2 or 4 and revokes every transport delegation of the
Agent at once; a node then re-commits a fresh delegation under the new
epoch. A withdrawal (once it exists) is selective: it removes one digest, so
check 3 refuses that delegation alone, the epoch is unchanged and the
Agent's other delegations keep verifying. The registry has no action that
removes one delegation digest today; section 18 Q1 adds it.

**Withdrawal is permanent.** A withdrawn delegation never verifies again
unless the Agent's own delegation authority deliberately admits it anew
after an epoch bump, which is outside the threat model (section 3). Three
mechanisms guarantee it: within an epoch, the registry refuses to re-add a
withdrawn digest; every epoch bump clears every delegation; and check 4
refuses a delegation whose encoded epoch is not the one it was admitted in,
or not the current one.

**Admission epoch.** The registry records, with every committed digest, the
epoch in which it was admitted: `DelegateAgentV1` names the current epoch,
is refused if that is not the Agent's finalized epoch, and stores it as the
digest's value (today the value is one bit, `native-registry-code.fc:770`).
The registry cannot read the encoded epoch, because it stores opaque digests
(`:764`), so the equality of the encoded and recorded epochs is the
verifier's check 4. A delegation encoded with a future epoch is therefore
refused in the epoch it was admitted in, and is cleared before the epoch it
names begins. All tooling (`tosctl`, `protocol/cmd/tos-service-wallet`, the
`agenttransport` and `messenger/pkg/identity` builders) MUST refuse to build
or submit a delegation whose encoded epoch differs from the Agent's current
finalized epoch.

The registry change MUST therefore keep, per Agent and **for the current
epoch**, the live set with admission epochs and a withdrawn-digest set:

- withdrawal moves a digest from the live set to the withdrawn set; it is
  refused only for a digest that is not live, so it **never fails for lack
  of space** and a compromised key can always be revoked;
- add-delegation refuses a digest in the withdrawn set;
- within one epoch the live set stays bounded at 128 digests, as today, and
  the live and withdrawn sets together at **384**; storage at the bound is
  about 12 KiB, paid by the Agent like any other state;
- when either bound is reached, add-delegation is refused **until the next
  epoch bump**; withdrawal still works;
- every epoch bump (policy update, recovery completion) clears **both** the
  live and the withdrawn set, as recovery completion and the tombstone
  already clear the live set (`native-registry-code.fc:790-792`). Live
  entries are dead after a bump anyway, since check 4 refuses their epoch;
  clearing the withdrawn set is safe because a cleared digest re-added later
  is a new admission by the Agent's own authority. So an Agent that filled
  either bound (for example 128 live and 256 withdrawn) regains the full
  capacity with a policy update, which also revokes every delegation it
  held; it is never locked out.

**Every delegation kind carries the epoch.** The same registry change adds
`authorization_epoch` to the Messaging Endpoint delegation
(`MessagingEndpointDelegationV1`, [`AGENT_NATIVE_MESSENGER_V1.md`](AGENT_NATIVE_MESSENGER_V1.md)
section 9.2, implemented in `messenger/pkg/identity`), and its verifier
requires it to equal both the digest's recorded admission epoch and the
Agent's finalized epoch, as check 4 does here. TOS
is pre-launch, so the format changes in place and its vectors are
regenerated in that change. Every delegation kind is then withdrawn
permanently by the same rule, and a policy update revokes every kind alike.
A delegation kind added later MUST carry the epoch too.

Replacing a compromised transport key therefore always uses a fresh
delegation: a new key, hence a new digest, committed after the old one is
withdrawn.

**Between a revocation and the new delegation.** Mailboxes are keyed by
Agent, not by delegation, so nothing stored is lost: relays keep accepting
stranger-lane deposits, and contact credentials of the revoked delegation are
refused (`credential_revoked`), so contacts fall back to the stranger lane.
The owner cannot fetch until its new delegation is finalized; it then fetches
everything still held, republishes its hints, and issues new contact
credentials in band. Envelopes that outlive the gap at a relay are covered by
the senders' re-deposit until the delivery acknowledgement (D10).

**Objects written under a delegation.** A relay stores every owner-written
object (mailbox policy, hint record) together with the delegation that
authorized it, and treats the object as void once that delegation no longer
verifies, whatever its timestamps: a new epoch therefore supersedes
everything written under an older one. Among objects whose delegations
verify, the newest is the one with the greatest `issued_at_unix`, then the
greatest SHA-256 of its bytes. A relay refuses an object whose
`issued_at_unix` is more than 300 seconds ahead of its clock. Revocation
entries (6.3) are the exception: they only refuse, so they stay until their
own expiry whichever delegation wrote them.

**Selecting among delegations.** Finalized state holds digests, not their
preimages, so no verifier enumerates an Agent's delegations. A verifier
verifies only the delegation presented to it, in a credential, a hint or a
hello. An Agent SHOULD keep one delegation per lane process (the chat node
and the rail node each hold their own key). The only per-Agent count is the
directory's (6.5), which admits a new delegation's record only into a free
slot and never displaces one.

### 5.2 Relay credential

```text
credential =
  D("tos.service.relay-credential.v1")     32
  transport_delegation                     167
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
issuer_chain  = chain_1
holder key    = next_public_key of the last block
```

Each signature covers the chain value, which covers every earlier signature,
so blocks cannot be reordered, dropped from the middle, or spliced from
another credential. The holder can append a block (it holds the private holder
key) but cannot remove or change one. A credential is at most **2,048
bytes**; the largest valid one is 1,916.

**What a holder cannot change.** Every appended block yields a new
`credential_id`, and a holder can append as often as it likes, with fresh
next keys, from the credential it received. `credential_id` therefore only
makes a request proof unique (5.4); nothing that bounds a holder is keyed by
it. `issuer_chain`, the chain value after block 0, is created by the
transport key alone and is shared by every credential appended from one
issued credential. The per-credential replay bound (5.4) and the default
quota lane (6.2) are keyed by it, so appending mints no new capacity.

### 5.3 Caveats

The caveat set is closed. An unknown type is a decode error, never ignored.

| Type | Name | Value | Satisfied when |
|---|---|---|---|
| 1 | `not_before` | u64 | `not_before <= now + 300` |
| 2 | `not_after` | u64 | `now < not_after` |
| 3 | `relay` | canonical relay base URL, 1..256 bytes, the key-card URL rules of relay spec 6.2 | it equals the base URL the relay is configured with, byte for byte |
| 4 | `operations` | u16 bitmask: bit 0 deposit, bit 1 list, bit 2 fetch, bit 3 publish, bit 4 revoke; others zero; 0 is valid and satisfied by no request | the request's operation bit is set |
| 5 | `lane` | 16 bytes, not all zero | always; names the quota lane of deposits (6.2) |
| 6 | `max_envelopes` | u32, at least 1 | the lane holds fewer stored envelopes than the value (deposits only) |
| 7 | `max_envelope_bytes` | u32, 1 .. 262,144 | the deposited envelope is no longer (deposits only) |
| 8 | `max_lane_bytes` | u64, at least 1 | the lane's stored bytes plus this envelope do not exceed it (deposits only) |

Rules:

- Block 0 MUST carry `not_before`, `not_after` and `operations`, with
  `not_before < not_after` and
  `not_after - not_before <= max_credential_seconds` of the delegation; a
  block 0 that breaks either is a decode error.
- A request satisfies a credential only if it satisfies **every caveat of
  every block**. Caveats therefore only narrow: a later block can repeat,
  shrink or add a bound, and an attempt to widen one is simply another bound
  the request must also meet. The effective lifetime is the minimum
  `not_after` and the maximum `not_before` over the blocks.
- At most one `lane` value may appear over the whole chain (the same value
  may repeat); two different values make the credential unusable, so a
  holder cannot move its deposits into another lane by appending one. Such a
  credential decodes, and every request with it is refused as
  `credential_scope`. Issuing tooling refuses to build one.
- The size and count caveats (types 6 to 8) constrain deposits only and are
  evaluated at the quota step (6.1); for every other operation they are
  always satisfied. A contact lane holds at most 64 envelopes whatever its
  caveats say (6.2).
- There is no sealing: appending only narrows, so the ability to append
  grants nothing. Appending does mint a new `credential_id`, which is why
  holder bounds are keyed by `issuer_chain` instead (5.2).

Profiles (what honest issuers produce). Their lifetimes and operation sets
are issuer policy: a verifier does not enforce them, only the caveats and
the delegation's `max_credential_seconds`.

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

The relay base URL follows the `relay` caveat rules (5.3). The method is
1 to 255 uppercase ASCII letters (`A` to `Z`). The path is 1 to 65,535
bytes of printable ASCII (`0x21` to `0x7e`), begins with `/` and contains no
`?` or `#`. The relay binds the escaped path exactly as received in the
request target, never a decoded or re-escaped form. Both headers are the
canonical unpadded base64url spelling: any other spelling, padding, line
break or non-zero trailing bit is `credential_invalid`.

The relay requires `|now - issued_at_unix| <= 120` and claims the pair
(`credential_id`, `nonce`) in its replay table before acting. The table:

- holds at most a configured number of entries (default 262,144, about
  19 MB of keys) and at most 64 live entries per issued credential, keyed by
  `issuer_chain` (5.2) and never by `credential_id`, which a holder can mint
  by appending; when either is full it refuses the request
  (`503 replay_table_full`, or `429` for one issued credential) instead of
  evicting a live entry. It never evicts an entry
  whose `issued_at_unix` is still inside the window;
- drops an entry only once `now - issued_at_unix > 120`, and keeps a
  **floor**, the greatest `issued_at_unix` it ever dropped; a proof whose
  `issued_at_unix` is at or below the floor is refused. A backward step of the
  wall clock therefore cannot bring a dropped proof back into the window;
- survives a restart without being written per request: every 10 seconds
  the relay durably records a **high-water mark**
  `H = max(H_recorded, now + 140)`, so the recorded mark never decreases,
  whatever the wall clock does. It admits a proof only if its
  `issued_at_unix` is below the last recorded `H`; a proof at or above it is
  answered `503 replay_table_full`, retryable, because the relay cannot
  admit what it has not durably bounded. With a correct clock an
  honest proof always is (`issued_at_unix <= now + 120`, and the recorded `H`
  is at least `now + 130`); if recording fails, proofs soon exceed `H` and
  are refused, so the failure is closed. After a restart the floor starts at
  the recorded `H`, so every proof admitted before the restart, at any clock
  setting, is refused: a proof admitted at clock 1000 with time 1100 stays
  refused after a rollback to 900 and a restart, because the mark stayed at
  1140 or above. A proof at or below the floor is answered
  `503 proof_floor` with `Retry-After` up to when a fresh proof can pass;
  clients re-sign then. Stranger deposits and acknowledgements need no proof
  and are unaffected.
- is written as one checksummed record, replaced atomically with file and
  directory sync. A relay whose V2 store exists refuses to start when the
  record is missing or fails its checksum, because it cannot know what it
  admitted before; it never initializes a used relay's floor silently. Only
  a relay with an empty V2 store starts with a fresh record. An operator
  recovers a damaged record only with an explicit start option that names a
  floor of at least `now + 140`, which the relay logs; choosing it after a
  clock rollback is the operator's responsibility.

The replay table and its durable record belong to the relay (section 17
item 6). `protocol/pkg/agenttransport` provides the admission logic only:
claim, bounds, floor, mark and restore; the relay persists the record and
enforces the start rules above.

**Restart refusal delay.** After a restart, a fresh proof passes once its
`issued_at_unix` exceeds the floor `F`, that is from `F + 1` in whole
seconds, while the relay's window still admits it
(`issued_at_unix >= relay_now - 120`). With `F` at most the restart time
plus 140 seconds:

- **aligned clocks** (client and relay agree, and the relay clock was not
  stepped back): at most **141 seconds** (`F + 1`);
- **worst permitted skew** (the client clock 120 seconds behind the relay's,
  the most the window admits): at most **261 seconds**, since the client's
  clock must reach `F + 1`;
- **relay clock stepped back by d before the restart:** both bounds grow by
  d, because the mark kept its earlier, higher value.

The floor is not weakened to shorten these delays; credentialed requests at
this relay wait, stranger deposits do not, and senders use the other relay
(section 10).

Binding the relay URL means a malicious relay cannot replay a proof it
received at another relay; binding the body means a proof cannot carry other
bytes. Credentials and proofs never appear in a URL.

### 5.5 Reachability hint and hint record

```text
hint =
  D("tos.service.agent-reachability-hint.v1")     39
  transport_delegation                            167
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
relay_count:   1 .. 4 on test networks; 2 .. 4 on a production network (section 10)
object digest = SHA-256( D("tos.service.agent-reachability-hint.object.v1") || u8(kind) || object )

hint_record =
  D("tos.service.agent-reachability-record.v1")
  hint_length u16 || hint
  object bytes, in the hint's order, each exactly its listed length
```

A hint is at most 1,536 bytes (1,512 when maximal); a hint record at most
**40,960 bytes**.

**What a hint publishes, and why no more.** A hint is public. By default it
carries only what a peer needs to reach a lane: relays, and the rail card of
an Agent that sells (rail cards are already public in offer files). The chat
card (kind 2) and the Messenger evidence (kind 3) are published only when the
owner opts the chat lane into **public contact** (`public_contact: true`,
default off), which is what first contact by Agent ID needs: a stranger must
seal to the chat card and run the first-contact bootstrap against the
evidence. That evidence discloses the Agent's Messaging Endpoint delegation
(Endpoint ID and key, ADNL identity commitment, policy digests), its
descriptor policy, its Contact Descriptor and its device's signed prekey
bundle set (device ID and keys): exactly what a contact file holds today,
now readable by anyone. An Agent that does not opt in stays reachable only
by invite or contact file, as in carriage D4. Direct entries are published
only under 8.1. Nothing else about an Agent is published.

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
recipient's lane is held, its relay list is the only route; the relay list of
the key card it carries is ignored, and without a valid hint the send stays
pending with `no-route`. Section 18 Q11 removes the card's list from the
format later.

### 5.6 Direct hello and receipt

```text
hello =
  D("tos.service.agent-direct-hello.v1")      34
  role                                        u8   1 = initiator, 2 = responder
  transport_delegation                        167
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

A hello is 402 bytes and travels in one ADNL query, inside the measured
8,192-byte cap. Envelopes travel only as RLDP2 queries, because almost every
relay frame bucket exceeds one ADNL query.

## 6. Relay V2

V2 keeps every rule of relay spec section 9 that this section does not
change: HTTPS only, no redirects, no query strings, the request evaluation
order, the deposit steps, the acknowledgement secret, tombstones, bounds,
retention and the D10 TTLs, including the 64 KiB bound on every response
but a downloaded envelope and the mailbox listing (below). Paths are below the base URL `B`.

**V2 only.** The V2 mailboxes live in a store of their own; no V1 request
reads, lists, downloads or acknowledges an envelope deposited through V2, and
no V2 request reads the V1 store. The V1 endpoints exist only until their
last client has moved (section 17): `buyeragent` in PR 10, `carrierapi` and
OpenFox's rail and chat lanes in PR 14. Each pull request that moves a client
deletes that client's V1 code path, and PR 14 deletes `carrierapi`, the V1
endpoints and the V1 store. Nothing is migrated and no V2 client falls back to V1. The privacy
claims of this design (G4, section 11) hold for the V2 store.

**Listing bound.** The 64 KiB response bound has one exception: the mailbox
listing (`GET B/v2/mailboxes/{agent}/envelopes`) is bounded at 80 KiB
(81,920 bytes). A full legal listing, 256 entries (64 stranger, 192 contact)
in compact JSON with every field at its maximum length, timestamps at the
u64 maximum included, is at most 72,920 bytes; the remaining room is
headroom, not a larger envelope count. Listings are not paginated.
The relay tests build that maximal listing and require it to fit, and a
listing that would exceed the bound is a relay bug that answers `500`,
never a truncated list. A client reads at most 81,920 bytes of a listing,
with or without `TOS-Relay-Wait`, and at most 65,536 bytes of every other
response but a downloaded envelope (262,144); a larger body is refused,
never truncated.

### 6.1 Operations

| Request | Credential | Effect |
|---|---|---|
| `PUT B/v2/mailboxes/{agent}/envelopes/{id}` | none (stranger lane) or deposit | deposit, relay spec 9.2 steps, then lane quotas |
| `GET B/v2/mailboxes/{agent}/envelopes` | list, owner | the listing of relay spec section 9 plus `"lane": "stranger"` or `"contact"` per entry, bounded by the listing rule of section 6; optional `TOS-Relay-Wait: 1..25` holds the answer until an entry exists or the wait ends |
| `GET B/v2/mailboxes/{agent}/envelopes/{id}` | fetch, owner | download |
| `POST B/v2/mailboxes/{agent}/envelopes/{id}/ack` | none | acknowledgement by secret, unchanged; the sender can still withdraw |
| `PUT B/v2/mailboxes/{agent}/policy` | publish, owner | mailbox policy (6.2) |
| `POST B/v2/mailboxes/{agent}/revocations` | revoke, owner | revoke credential chains (6.3) |
| `PUT B/v2/hints/{agent}` | none | store a hint record (6.5) |
| `GET B/v2/hints/{agent}` | none | the hint index (6.5): one entry per live record of the Agent, at most 4 |
| `GET B/v2/hints/{agent}/{digest}` | none | one hint record (6.5), by its delegation digest |
| `GET B/v2/relay` | none | description: the relay spec description fields plus `stranger_max_envelopes`, `stranger_max_bytes`, `max_wait_seconds`, `directory` |

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
  credential's `lane` value or, without one, by its `issuer_chain` (5.2),
  never by `credential_id`, so appending blocks cannot open a fresh lane. A
  lane holds
  at most `min(max_envelopes, 64)` envelopes and `max_lane_bytes` bytes.

The per-recipient bound of 256 envelopes and 16 MiB stays, and the stranger
lane can never hold more than 64 of it, so contact lanes always keep at least
192 envelopes.

**Relay-wide reservation.** The global count and byte limits of relay spec
9.8 are split: stranger envelopes across all mailboxes together hold at most
25 % of each (`stranger_global_share`, at most 25 %), and the rest is
reserved for contact lanes. One client address holds at most 64 stranger
envelopes across all mailboxes (IPv6 per /64, and 256 per /48). A stranger
flood spread over many arbitrary Agent IDs therefore fills at most the
stranger share and leaves every contact lane its capacity. What remains: a
contact lane deposit can still meet the contact share's own exhaustion, which
takes many credentials from many owners.

**Tombstones keep their charge.** The global count of relay spec 9.8 counts
tombstones, and a stranger knows the acknowledgement secrets of its own
envelopes, so it could deposit and withdraw repeatedly, freeing the envelope
each time while tombstones accumulate. A tombstone therefore keeps the count
charge of the envelope it replaced, until the tombstone expires: against the
stranger share and the depositing address's relay-wide stranger cap for a
stranger deposit, against the contact share for a contact deposit. The
tombstone record stores its lane class and depositing address, so the charge
survives a restart. A tombstone does not count against the mailbox's own
stranger lane, so a recipient that acknowledges promptly still frees its
lane. With the deposit rate limit (relay spec 9.8) this bounds a
deposit-and-withdraw cycle to the stranger share, like any other stranger
flood.

A full lane or share answers `507 quota_exhausted` with the lane in the error
(`"lane": "stranger"` or `"contact"`).

The owner MAY lower its stranger lane, to zero for a closed mailbox:

```text
mailbox_policy =
  D("tos.service.relay-mailbox-policy.v1")
  issued_at_unix           u64   at most now + 300 at the relay
  stranger_max_envelopes   u16   0 .. relay maximum
  stranger_max_bytes       u32   0 .. relay maximum
```

The policy request is authorized by the owner credential and proof. The
relay stores the newest policy per mailbox durably, together with the
delegation that authorized it, under the rule for objects written under a
delegation (5.1): a policy more than 300 seconds ahead is refused
(`400 invalid_request`); a stored policy is void once its delegation no
longer verifies, and the relay's defaults apply until the owner publishes
again under a verifying delegation, whatever timestamp the void one carried.
Among policies of verifying delegations a newer `issued_at_unix` wins. So a
compromised transport key can write at most a policy dated 300 seconds
ahead, and the owner's rotation voids it at once.

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
`issued_at_unix` with different bytes is `409 hint_conflict`. A stored record
is void once its delegation no longer verifies (5.1).

**Slots.** A relay keeps at most 4 live records per Agent, one per
delegation digest. A record is live while its hint is unexpired and its
delegation verifies. A record of a new delegation is admitted only into a
free slot; with 4 live records it is refused (`507`), whatever its digest or
time, and never replaces a live record. A slot frees when its record expires
or its delegation stops verifying. Relays fill their slots independently, so
two relays may hold different records of one Agent; a consumer asks at least
two relays and merges what they return. The relay keeps a configured number
of Agents (default 16,384).

**Encoding.** The index and the records are separate responses, each within
the 64 KiB response bound:

```text
hint_index (at most 209 bytes) =
  D("tos.service.relay-hint-index.v1")
  count u8 (0 .. 4)
  count × ( delegation_digest 32 || issued_at_unix u64 || record_length u32 )
  strictly ascending by delegation_digest
```

`GET B/v2/hints/{agent}` answers the index, `application/octet-stream`;
`GET B/v2/hints/{agent}/{digest}` answers one record, at most 40,960 bytes,
or `404`. Neither hint response is paginated because neither can exceed the 64 KiB bound;
A1's vectors include an index of 4 entries and a maximal record.
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
| 403 | `credential_scope` | a caveat fails, the chain carries two different lane values, or the path names another Agent |
| 403 | `credential_revoked` | the delegation no longer verifies, or a chain value is revoked |
| 409 | `hint_conflict` | an equal-time hint with different bytes |
| 503 | `chain_unavailable` | finalized state could not be read and no cached pass younger than 600 s exists; retryable |
| 503 | `replay_table_full` | the replay table is full, or the proof's time is at or above the last recorded high-water mark (5.4); retryable |
| 503 | `proof_floor` | the proof's time is at or below the replay floor (5.4); retry with a new proof after `Retry-After` |

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

1. the local hint cache (newest per delegation, bounded to 4,096 peers);
2. a hint record from a contact file, invite, offer file or Gateway Quote
   package;
3. the hint index and records (6.5) at the peer's last known relays, then at
   no fewer than two directory relays, merged.

Every answer is verified with `VerifyHint` before use, and the resolved
cards and evidence with their own verifiers. With no valid hint, the send
stays pending with `no-route`; the card's relay list is never a route.

No packet carries a route in band: a reply resolves its sender like any
peer. A contact file, invite, offer file or Gateway Quote package supplies
the Agent ID and cards; it supplies a route only through a hint record it
carries that still verifies. Otherwise step 3 is required; the formats that
gain a hint record field are listed in section 19.

A delivery pending with `no-route`, and every re-deposit generation that
falls due without a valid hint, stays in the journal. The sender re-runs
resolution (steps 1 to 3) with back-off from 30 s doubling to 10 minutes,
and at least at every due generation, until a valid hint is found or the
delivery expires (then `abandoned` with `retention-exceeded`, carriage 4). A
recipient offline longer than its hint's remaining lifetime receives nothing
new at relays until it republishes; its pending messages wait in the
senders' journals and are delivered once a sender resolves the republished
hint.

### 9.3 Distributing contact credentials

The owner issues a contact credential to a peer when it admits that peer on
the lane (a Messenger peer with a session or admitted under carriage 2.3, a
rail counterparty of a live purchase), and renews it once less than half its
lifetime remains. It travels in band, inside the sealed and signed packets
the lane already sends to that peer:

- **chat lane:** a new `credential` field of the relay frame, which becomes
  `tos.messaging.relay-frame.v2`:
  `credential_length u16 (0 or 1 .. 2,048) || credential || holder_seed 32`
  (the seed present only with a credential, and never all zero) directly
  after `evidence`,
  present until the peer acknowledged a frame that carried it, like the card
  (carriage 2.3). A credential on an ack frame rides on every ack until it is
  renewed, because acks are never acknowledged: a peer that only receives
  returns its credential on its acks, and the sender takes it from an ack it
  verified and applied. The frame bounds of carriage 1.1, 4 and 11.1 are recomputed
  from a real maximal frame: the frame's fixed part is 74 bytes, the largest
  relay Event payload is 137,465 bytes (2,082 below v1), part 0 of a room
  object holds 160,662 object bytes and every later part 190,390. Only v2
  frames decode; vectors in `messenger/internal/vectors/testdata/relay-vectors.json`
  are reproduced by `spec/scripts/reproduce-messenger-relay-frame-v2.py`;
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
5. Continue in the background until **two** relays accepted the envelope.
   A `409`, a `422` and a `403` other than `credential_revoked` abandon that
   relay for this envelope (relay spec 8.6, 9.2); a `507` on a contact lane
   retries that relay once on the stranger lane; a `403 credential_revoked`
   drops that credential and retries on the stranger lane. Every other
   failure is retried at that relay with back-off from 30 seconds doubling to
   10 minutes. The loop ends when two relays accepted, the delivery was
   acknowledged, the envelope expired, or every relay was abandoned; ending
   with one copy is recorded as `single-copy` in telemetry.
6. Re-deposit and withdraw generations as the carriage specifies
   (section 4, D10): next generation at 80 % of the reported TTL, at least 10
   minutes apart, until the delivery's own expiry; packet expiry stays the
   business deadline.

Two copies instead of V1's one per relay: two survive any single relay loss,
and four copies of every envelope would spend four relays' quotas for no
further independence when the relays share an operator. Two copies need two
relays, so a production hint MUST name at least two (5.5); a one-relay hint
is a test configuration, and its records say so.

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
| Relay operator, mailbox it hosts | everything public in the owner's hints (row below), so its Endpoint and device when it opted into public contact; its poll and acknowledgement times and address; per envelope: recipient key ID, size (the frame bucket of carriage 1.1), deposit time, expiry, depositor address, and the lane: `stranger`, or an opaque lane value, credential chain values and holder key that link deposits of one contact over time | the sender Agent (except by matching addresses, as in V1), the sender's Endpoint or device, conversation, room, Event, frame kind, content |
| Relay operator, directory | which address looked up which Agent, and when | why |
| Another relay user, or anyone knowing an Agent ID | the Agent's public hints (5.5): its relays and transport delegation; its rail card if it sells; with public contact, its chat card and Messenger evidence, which name its Messaging Endpoint (ID, key, ADNL commitment), its Contact Descriptor, and its device (ID, signed prekey bundles); direct addresses if its owner enabled them | anything about its mailbox: count, sizes, times, ciphertext |
| Network observer | that a node talks HTTPS to a relay, or ADNL to an address | anything inside |
| Direct peer | the other side's IPv4 address and port | nothing a relay would not; it is the counterparty anyway |

Compared with V1, the public loses all mailbox metadata (G4); the operator
gains the lane value of contact deposits.

**Correlation across relays.** Operators that share what they see link
traffic without matching addresses: a sender deposits the same envelope ID
and bytes at two relays (dedup needs that); a contact presents the same
credential blocks, chain values, lane value and holder key at every relay of
the owner, differing only in the appended relay block; and every relay sees
the owner's same transport delegation. Unlinkability across relays is not a
goal; choosing relays of independent operators buys availability, not
privacy against their collusion.

Rules that keep the operator's view minimal:

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
| No valid hint (none resolved, or every resolved hint expired), whatever cards are held | send stays pending; resolution retried by the schedule of 9.2; the card's relay list is never used | `no-route` |
| Recipient's hint expired while it was offline | as no valid hint; a due generation is deposited at the first valid hint | `no-route` |
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
5. `messenger/pkg/carrierapi` and the V1 relay endpoints are removed as their
   in-repo clients move, the last in PR 14 (section 17); none is kept for
   compatibility. The no-loop rule of carriage 1
   stays: no rail packet travels inside a chat copy.

## 15. Limits

| Item | Bound |
|---|---|
| Mailbox listing | at most 81,920 bytes, the only response other than a download above 64 KiB; maximal legal listing at most 72,920 bytes; not paginated; same bound under `TOS-Relay-Wait` |
| Transport delegation | 167 bytes; lifetime at most 365 days; production needs the authorization epoch (5.1) |
| Re-check of finalized state | every 300 s; cached pass refused after 600 s without a read |
| Credential | at most 2,048 bytes; 1..4 blocks; 1..8 caveats per block; block 0 `not_before < not_after`; at most one lane value |
| Owner credential lifetime | at most 3,600 s (issuer policy, 5.3) |
| Contact credential lifetime | at most 604,800 s (and the delegation's `max_credential_seconds`); SHOULD 259,200 |
| Request proof | clock window ±120 s; replay table default 262,144 entries, 64 per issued credential (`issuer_chain`), fail closed when full; high-water mark never decreases; restart refusal at most 141 s (`F + 1`) with aligned clocks, 261 s at the worst permitted skew, plus any backward relay clock step |
| Revocation | at most 300 s with healthy reads, 600 s with failing reads (5.1) |
| Owner-written objects | `issued_at_unix` at most 300 s ahead; void once their delegation fails |
| Hint / hint record | 1,536 / 40,960 bytes; lifetime at most 86,400 s, SHOULD 21,600; 2..4 relays in production (1..4 in test); 0..2 direct entries; 0..3 objects |
| Directory | at most 4 live records per Agent, never displaced; default 16,384 Agents; index at most 209 bytes; lookups 60/min per address |
| Stranger lane | default 32 envelopes and 2 MiB per mailbox, at most 64 and 4 MiB; 8 per (address, mailbox); at most 64 per address relay-wide; at most 25 % of the relay's global limits |
| Contact lane | at most 64 envelopes; keyed by the `lane` value or else `issuer_chain`, never `credential_id`; contact lanes keep at least 192 of the 256 per recipient |
| Revocations | 1..32 per request; 1,024 per mailbox; kept at most 604,800 + 300 s |
| Long poll | 1..25 s; one waiting request per mailbox |
| Relay frame (chat lane) | `relay-frame.v2` only; at most 190,464 bytes (unchanged); credential at most 2,048 bytes plus a 32-byte holder seed; fixed part 74 bytes; largest relay Event payload 137,465 bytes; room part 0 160,662 and later parts 190,390 object bytes |
| Envelope | at most 262,144 bytes (unchanged) |
| Envelope expiry (D10) | at most the packet's business deadline and deposit + 86,400 s (unchanged) |
| Relay TTL (D10) | 3,600 s on test relays, 10,800 s on production relays, at most 86,400 s |
| Re-deposit (D10) | 80 % of the smallest advertised TTL; at least 600 s apart; until the delivery expiry (default 7 days, at most 30) |
| Copies per envelope | two accepting relays |
| Direct hello | 402 bytes, one ADNL query (cap 8,192) |
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
| A1 Codecs | delegation, credential, proof, hint, record, hello and receipt decode strictly; every negative refused with its class | frozen corpora `spec/test-vectors/agent-transport-v1.json` (delegation) and `spec/test-vectors/agent-transport-credential-v1.json` (credential and request proof), and one per later surface; an independent reproducer per corpus run with `python3 -I` under `make spec-check` |
| A2 Narrowing | no appended block widens time, relay, operations, lane or size; splice, reorder and drop are refused | property and fuzz tests naming the generator seed; red-control mutants that merge blocks are caught |
| A3 Chain revocation | after a policy update on a test chain, owner and contact credentials are refused (`credential_revoked`) by two relays within 300 s of the update being readable, and hints stop being served; and, combined, a revocation finalized just after a relay's successful read followed by stopping that relay's chain endpoints is refused within 600 s and not honoured after | chain transaction hashes, relay logs of the read and refusal times, both relay commits |
| A4 Fail closed | with every chain endpoint of a relay stopped, credentialed requests get `503 chain_unavailable` once the cached pass is 600 s old; stranger deposits continue | relay log and client transcript |
| A5 Closed mailbox and replay | list and fetch without a credential `401`; with another Agent's credential `403`; a proof replayed at a second relay `403`; the same proof replayed at the same relay `403`, also after the relay restarted (`proof_floor` until the floor passes) and after a backward clock step (`403` or `503 proof_floor`: a dropped proof is at or below the floor, which the relay cannot tell from an honest proof at the floor); one holder appending many blocks to one issued credential holds at most 64 live replay entries and one default lane; the combined control: proof admitted, clock rolled back, high-water mark recorded, relay restarted, clock restored, same proof refused; a relay with a used V2 store refuses to start with its record missing and with it corrupted; the restart delay measured with aligned clocks (at most 141 s) and with the client 120 s behind (at most 261 s); a proof at or above the recorded high-water mark refused (`503 replay_table_full`); a full replay table refuses (`503 replay_table_full`) and evicts no live entry | integration tests with the controls named; a live transcript against a deployed test relay |
| A6 Lane isolation | a stranger flood from 64 IPv4 addresses into one mailbox fills only its stranger lane; a stranger flood spread over 10,000 arbitrary Agent IDs stops at the relay-wide stranger share; a stranger deposit-and-withdraw cycle stops at the stranger share by its tombstones, also across a relay restart; contacts deposit throughout all three; `507` names the stranger lane; the maximal listing (256 entries) fits 81,920 bytes and a client accepts it | live run against a test relay, per-mailbox and global quota counters (tombstones included) before and after |
| A7 Contact revocation | a revoked contact's deposits are refused at every relay of the hint; its stored envelopes stay until acknowledged | live transcript |
| A8 Multi-relay | with the minimum production configuration of two relays, one killed mid-run: no loss, exactly-once application, acknowledgement at both after restart; every delivery deposited while one relay was down that is still pending and unexpired when it returns reaches its second copy through the retry of section 10; separately, a delivery the recipient acknowledged through the surviving relay during the outage gets no second copy and is not re-deposited | relay store snapshots, journals, `single-copy` telemetry, runtime outcome log |
| A9 First contact by Agent ID | an MCP client on a host without OpenFox resolves an OpenFox Agent by Agent ID through a directory relay (no contact file), sends, the owner admits, and the conversation proceeds both ways across two hosts | deployment record with both hosts' commits, the hint records, the MCP transcript |
| A10 OpenFox on the library | OpenFox has no chat carrier code and imports `agentcarrier`; the M-R1 and M-R2 scenarios pass again on V2 relays | `go list -deps` output, the openfox commit, rerun records |
| A11 Direct upgrade | between a node with a verified inbound IPv4 entry and a node behind NAT: upgrade after the first envelope, later envelopes delivered direct with no deposits at relays; a firewall drop mid-run falls back to relays within 13 s with no loss and no duplicate execution | relay deposit counters, sidecar logs, the receipts |
| A12 Never required | with direct disabled, on an IPv6-only host, and between two NATed nodes: no probe is made and every message is delivered by relay | probe counters equal zero, delivery records |
| A13 Metadata | relay store, logs and directory contain nothing of section 11's "does not learn" column; a third party holding the Agent ID gets only the hint contents section 5.5 lists for the Agent's publication setting, and every V1 URL (list, download, acknowledgement, deposit, description) answers `404`, so nothing about any mailbox is reachable through V1 | dumps of relay state and logs taken while envelopes were held; requests to the V1 URLs recorded, each `404` |
| A14 D10 | test relays at 1 h: re-deposit at 48 min; production profile at 3 h: 2 h 24 min; packet expiry equals the business deadline | carrier journal timestamps against relay descriptions |
| A15 Hygiene | no credential, proof, secret, lane value or plaintext in any URL or log; the relay holds no key but its TLS key and no `tosctl` | grep of logs and the relay's file system; process inspection |
| A16 Timestamp poisoning | a mailbox policy and a hint dated `UINT64_MAX`, and one dated 301 s ahead, are refused; a compromised transport key's policy dated 300 s ahead with a zero stranger lane is accepted, then voided by the owner's policy update (on an epoch network) or by the delegation no longer verifying (on a test network), after which the owner's new policy with an earlier `issued_at_unix` is accepted | relay tests, and a live transcript on a test chain |
| A17 Epoch revocation | on a registry with the authorization epoch: a delegation issued under policy A is refused after A → B → A, and after a policy update that installs identical bytes; on a test network without the epoch the same run shows the gap, which is why production is gated | registry and relay tests; the chain transactions |
| A18 Directory slots | two relays populated with five delegations of one Agent in different orders each hold four live records and refuse the fifth; neither displaces a live record; a consumer merging both finds the lane's hint; a slot frees on expiry | relay tests; directory dumps |
| A19 Permanent withdrawal | within an epoch, re-adding a withdrawn digest is refused by the registry and the Agent's other delegations keep verifying; after a policy update clears both sets, a delegation encoding the earlier epoch, re-added, is refused by `VerifyDelegation` (check 4); the future-epoch sequence: at epoch E the tooling refuses to build a delegation encoding E+1; one crafted outside the tooling and admitted at E is refused by check 4 at E (encoded E+1, recorded E), is withdrawn, is cleared by the bump to E+1, and a re-add at E+1 is a new admission by the Agent's authority, recorded as such; withdrawal still succeeds with both sets at their bound; add-delegation is refused at the 384 bound and, from a population of 128 live and 256 withdrawn, succeeds after a policy update; a withdrawn Messaging Endpoint delegation re-added after an epoch bump is refused by its epoch check | registry tests in `tos`; `agenttransport` and `messenger/pkg/identity` verifier tests; chain transactions on a test network |

Production claims additionally need relays and directory relays run by an
operator other than the core team, and a public chain, as ROADMAP Gate O
requires.

The reachability/control-object portion of A1 is frozen separately in
`spec/test-vectors/agent-transport-reachability-v1.json`, with an independent
stdlib reproducer `spec/scripts/reproduce-agent-transport-reachability-v1.py`
under `make spec-check`. This covers phase 1 item 4's codecs, signatures,
finalized delegation verification and synthetic boundary tests; it does not
claim directory, carrier, live first-contact or direct-path acceptance. The
167-byte delegation corpus remains unchanged.

## 17. Implementation plan

Small pull requests, in order; each runs `make verify` and lands with its
tests. Phase 1 ships first and alone makes the transport usable on test
networks; phase 2 is gated separately; the registry change and the key card
V2 are separate work outside this plan.

**Phase 1: carrier extraction, relay V2 delivery and MCP.**

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
10. `buyeragent` on `agentcarrier`; its V1 relay client path is deleted.
11. Messenger: relay frame v2 with the credential field; recomputed bounds;
    vectors.
12. Messenger: `messenger/pkg/transport` and `carrier: builtin` in
    `tos-messengerd`; `conversations.list`.
13. Messenger: `tos-messenger-mcp` (A9).
14. OpenFox: rail on `agentcarrier`, chat lane removed (A10); then remove
    `carrierapi`, the V1 relay endpoints and the V1 store here (section 6).
15. Live evidence runs for phase 1 (A3 to A10, A13 to A16, A18) and status
    updates in this document, the carriage, the relay spec and ROADMAP.

**Phase 2: the direct path.** It starts only after phase 1 is accepted on
test networks, and is enabled per lane by its own configuration.

16. `tos`: `adnl/tos-adnl-transport` sidecar from the probe core.
17. `adnlpath` driver and the direct state machine in `agentcarrier`, off by
    default, with its evidence (A11, A12).

**Separate work, outside this plan.**

- The registry change of section 18 Q1: the withdraw-delegation action; the
  authorization epoch; the admission epoch recorded with every digest; the
  per-epoch live and withdrawn sets (live at most 128, live and withdrawn at
  most 384), both cleared on every epoch bump; the tooling refusal of
  delegations not encoding the current epoch; in `tos` and
  `protocol/pkg/nativecore`, together with the epoch field and check in the
  Messaging Endpoint delegation (`messenger/pkg/identity` and its vectors)
  (A17, A19).
  Until it is finalized on a network, V2 transport runs on test networks
  only (5.1).
- Key card V2 without a relay list (section 18 Q11).

## 18. Decisions

The questions this design raised, each with its decision (recorded
2026-11-27).

- **Q1. The registry cannot withdraw a delegation digest.** Add-delegation
  exists; removal does not, so today a delegation dies only with a policy
  change or a tombstone (the carriage's "withdrawn on chain" assumes an
  action that does not exist). **Decided:** a registry action that withdraws
  one delegation digest is added as the reverse of `DelegateAgentV1`,
  authorized like it, together with the Agent's authorization epoch of
  5.1, which every policy update, recovery completion and tombstone
  increments; withdrawal removes one digest without changing the epoch, so
  it revokes one transport key and leaves the others. Withdrawal is
  permanent: within an epoch the registry refuses to re-add a withdrawn
  digest from a per-epoch set (live at most 128, live and withdrawn at most
  384); every epoch bump clears both sets; the registry records each
  digest's admission epoch and verifiers require the encoded epoch to equal
  it and the current one (5.1). A full set blocks new delegations only until
  the next epoch bump, never a withdrawal. Tooling refuses to build a
  delegation for any epoch but the current one; crafting one outside it
  needs the Agent's own authority, which is outside the threat model. The Messaging Endpoint delegation gains
  the epoch in the same change, so every delegation kind follows one rule. A
  compromised key is replaced by a fresh delegation. It is a `tos` contract change, scheduled after the
  USDC and USDT settlement work. Until it lands, V2 transport runs on test
  networks only, with the `policy_hash` binding as the revocation; once it
  lands, check 3 of 5.1 covers withdrawal and check 4 every policy change,
  with no change to this design.
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
  relay list. Until then the card's list is never a route: a V2 sender
  ignores it and uses only a valid hint (5.5, 9.2).
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
  this design; frames, double encryption, evidence and rooms stay. V2 keeps
  no V1 compatibility: routes come only from hints, never from a card's relay
  list; section 4's re-deposit TTL is the smallest of the hint's relays; and
  a contact file (D4) supplies a route only through a valid hint record it
  carries, otherwise the route comes from a directory lookup (9.2).
- The contact file, invite, offer file and Gateway Quote package formats
  gain an optional hint record field (9.2); until a format has it, first
  contact through it needs a directory lookup.
- [`OPENFOX_AUTONOMOUS_MESSENGER_ECONOMY_PLAN.md`](OPENFOX_AUTONOMOUS_MESSENGER_ECONOMY_PLAN.md):
  Phase B records that the route is relay-first by this design and that M0-R
  evidence now gates only the direct upgrade.
- [`ROADMAP.md`](ROADMAP.md) section 8.1: this design is listed as an
  incubation design.
- [`AGENT_PACKET_RELAY_V1.md`](AGENT_PACKET_RELAY_V1.md): a status note
  that V2 keeps no V1 compatibility, that its endpoints are deleted in
  section 17 PR 14, that a key card's relay list is not a route under V2,
  and that the V2 mailbox listing is bounded at 80 KiB (section 6). Its
  envelope, seal, card and section 9 rules stay normative as V2 inherits
  them; the V2 relay API is section 6 here.
