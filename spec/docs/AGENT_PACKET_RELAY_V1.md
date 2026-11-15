# Agent Packet Relay V1

Agent Packet Relay V1 is a cross-host Carrier for [Agent Packet V1](AGENT_PACKET_V1.md):
an end-to-end-encrypted store-and-forward mailbox. A sender seals one exact
signed Agent Packet V1 JSON to an encryption key the recipient Agent
published, deposits the sealed envelope at a relay the recipient chose, and
the recipient fetches, opens, verifies, stores and then acknowledges it.

**Status: ⬜ Design, frozen vectors, relay program and client library.** This
document, the reference codec `protocol/pkg/agentpacketseal`, the corpus
`spec/test-vectors/agent-packet-relay-v1.json`, the relay service and Go
client `protocol/pkg/agentpacketrelay` and the daemon
`protocol/cmd/tos-service-packet-relay` exist. No OpenFox client and no
cross-host evidence exist yet; section 12 lists what those must show.

The key words MUST, MUST NOT, SHOULD and MAY are normative.

## 1. Authority

The relay has no authority of any kind. It is a bounded byte store keyed by
recipient Agent ID.

- Finalized TOS state remains the only authority: the inner packet is accepted
  only after `agentpacket.DecodeJSON` and `agentpacket.Verify` (or the
  receiver's equivalent finalized-state check) pass, exactly as for every other
  Carrier.
- The relay never decrypts, never holds a key, never signs, never needs chain
  RPC and never sees the packet, the sender Agent, the Capability, the Quote
  commitment or the payload.
- Encryption adds confidentiality only. Sender authentication is the inner
  ML-DSA-44 signature by a finalized controller of the sender Agent; the HPKE
  layer authenticates nobody.
- A relay URL is a non-authoritative hint chosen by the recipient Agent in its
  signed key card. A relay, its operator or its database disappearing changes
  availability, never protocol facts.
- Delivery is at least once and unordered. Execution stays at most once through
  the receiver's durable inbox and the Native Execution Gate claim, which no
  Carrier can bypass.

The relay is a separate program. The Gateway stays stateless and does not host
mailboxes. The relay is not part of the Native Connect contract.

## 2. Why these encodings are not protobuf messages

`spec/proto/tos/service/v1/native.proto` is the Native Connect contract between
callers and the Native service. Agent Packet V1, Contact Cards and OpenFox rail
frames are off-chain Carrier encodings with their own strict codecs and are not
proto messages. The relay envelope, the plaintext wrapper and the key card body
follow that precedent: they are fixed-layout binary encodings, frozen by
vectors, that never cross the Native service boundary, never enter a signed
Native action and add no chain field. A proto definition would add a second,
non-canonical encoding of the same bytes. No proto change is therefore made.

## 3. Suite

V1 has exactly one suite, RFC 9180 HPKE in base mode (`mode_base`, 0x00):

| Component | Algorithm | IANA ID |
|---|---|---|
| KEM | MLKEM768-X25519 (X-Wing) | `0x647a` |
| KDF | HKDF-SHA256 | `0x0001` |
| AEAD | AES-256-GCM | `0x0002` |

Sizes: public key 1,216 bytes (ML-KEM-768 encapsulation key followed by the
X25519 public key); private key 32 bytes (the seed, as `SerializePrivateKey`
outputs it); encapsulated key 1,120 bytes; AEAD tag 16 bytes. The reference
codec uses the Go 1.26 standard library `crypto/hpke`
(`MLKEM768X25519`, `HKDFSHA256`, `AES256GCM`). Any other suite identifier is
rejected; a new suite needs a new version of this document.

Each envelope is one HPKE context used for exactly one `Seal`, so no AEAD nonce
is ever reused.

## 4. Common rules

- Integers are unsigned big-endian.
- `D(x)` is the ASCII domain string `x` followed by one zero byte.
- `suite` is the six bytes `0x647a 0x0001 0x0002`.
- `agent_digest(id)` is the 32 bytes the strict text form
  `agent_<64 lowercase hex>` names; any other spelling is rejected. The
  all-zero digest is reserved (section 6.1) and is never a recipient.
- `KeyIDText(id)` is `hpke:<64 lowercase hex>`; the all-zero key ID is invalid.
- Every decoder rejects unknown versions, unknown suites, wrong lengths and
  trailing bytes. A decoder never ignores input it does not understand.

## 5. Encryption key ID

```text
key_id = SHA-256( D("tos.service.agent-packet-relay.key-id.v1") || suite || public_key )
```

`public_key` is exactly 1,216 bytes. Including the suite means a key ID never
names the same bytes under another suite.

## 6. Encryption Key Card

### 6.1 Carrying packet

A key card is an ordinary Agent Packet V1, signed with `agentpacket.Sign` under
context `TOS-AGENT-PACKET-V1` by a controller of the card's Agent. It needs no
new signature use and no `tosctl` change. Its fields are fixed:

| Packet field | Value |
|---|---|
| `sender_agent_id` | the Agent whose key this is |
| `recipient_agent_id` | `agent_` followed by 64 `0` (the key card audience) |
| `capability_id` | `cap_` followed by 64 `0` |
| `quote_commitment` | empty |
| `sequence` | strictly positive; not interpreted |
| `nonce`, `created_at_unix`, `sender_key_id`, `signature` | as for any packet |
| `payload` | the key card body (6.2) |

Agent Packet V1 forbids `sender == recipient`, so a self-addressed card cannot
be signed or decoded. The fixed all-zero audience replaces it. Agent and
Capability IDs are SHA-256 outputs of identity cells, so no finalized Agent or
Capability has the all-zero digest; consequently:

- `agentpacket.Verify` rejects every key card ("recipient Agent is not
  finalized"), so no Agent Packet receiver can ever take a key card as a
  delivered packet;
- OpenFox's receiver additionally rejects it because the recipient is not the
  local Agent, and the payload does not begin with the rail frame magic
  `OFR1`;
- the Messenger `agent.packet` bridge rejects it because the recipient is not a
  finalized, live installation;
- the body begins with its own domain string, which no rail frame, Messenger
  event or other payload starts with.

A card is verified with `agentpacketseal.VerifyKeyCard`, which requires the
fixed audience, Capability and empty Quote commitment, decodes the body, checks
the validity window, and calls `agentpacket.VerifySender`: shape, finalized
live sender Agent, and a signature by a controller of its finalized policy.
`VerifySender` resolves no recipient and claims no replay key; it authorizes no
delivery. A packet to any other recipient is never a key card, whatever its
payload.

The Agent ID is network-bound (it hashes the network domain), and the card
verifies only against finalized state of the verifier's network, so the card
carries no separate network tuple.

### 6.2 Body

```text
key_card_body =
  D("tos.service.agent-packet-relay.key-card.v1")   43 bytes
  suite                                             6
  public_key                                        1216
  key_id                                            32   (must equal section 5)
  not_before_unix                                   u64
  not_after_unix                                    u64
  relay_count                                       u8   (1..4)
  relay_count × ( url_length u16 (1..256) || url )
```

Rules:

- `key_id` MUST equal the section 5 derivation of `public_key`, and the KEM
  MUST accept `public_key`.
- `0 < not_before_unix < not_after_unix` and
  `not_after_unix - not_before_unix <= 2,592,000` (30 days).
- Relay URLs are in strictly ascending byte order (so no duplicates), each a
  canonical base URL: printable ASCII; `https`, or `http` only to the hosts
  `127.0.0.1`, `localhost` or `::1`; non-empty lowercase host; optional port;
  no user information, query (not even an empty `?`), fragment, opaque part,
  percent-escaped path, or trailing slash; path empty or beginning with `/`;
  re-serializing the parsed URL yields the same string. No `%` byte appears
  anywhere in the URL: re-serialization alone does not catch an escape the
  parser keeps verbatim (such as `%20`), and a host has no valid escape here
  (an IPv6 zone is never a relay host).
- The body is at most 2,346 bytes; the end of the last URL is the end of the
  body.

### 6.3 Validity and use

A sender MAY seal to a card only when, at sealing time,
`not_before_unix <= now + 300` and `now < not_after_unix`, and only after
`VerifyKeyCard` succeeded against finalized state no more than 10 minutes
earlier. Re-verification at use is what revokes a card early: removing the
signing controller from the Agent's finalized policy, or tombstoning the Agent,
makes every card that controller signed unusable.

When several valid cards of one Agent are known, the sender seals to the one
with the greatest `not_before_unix`, ties broken by the greatest key ID in byte
order. A sender MUST NOT seal to a card whose Agent differs from the packet's
`recipient_agent_id`.

The card's Agent:

- SHOULD issue cards of at most 7 days, except the card it publishes in an
  offer file (6.4), which SHOULD use up to the 30-day maximum, and MUST NOT
  exceed 30 days;
- SHOULD publish a successor card at least 24 hours before the current
  `not_after_unix`;
- MUST keep each private key until `not_after_unix + 86,400 + 300` (the
  longest an envelope sealed before expiry can wait at a relay), and MUST
  destroy it after that;
- MUST poll every relay named by any card whose private key it still holds;
- SHOULD sign its cards with a dedicated card-signing controller, used for
  nothing else, so that revoking a card (by removing that controller from the
  finalized policy) does not stop its packets or require a full identity
  rotation. The first OpenFox implementation signs cards with its packet
  controller; revoking a card there means removing the packet controller,
  which also stops every packet the node sends until a new controller is
  registered on chain.

### 6.4 Distribution

- **Provider.** The provider's current card travels in its offer file next to
  the manifest (an OpenFox offer file version bump, since that decoder rejects
  unknown fields). The offer file stays unsigned and non-authoritative: the
  buyer verifies the card itself. The buyer MUST check that the card's Agent
  equals the Capability's finalized owner, read from finalized state and never
  taken from the offer file, before sealing to it. `VerifyKeyCard` proves only
  that the card's own Agent signed it; it cannot know which Capability the
  card is used for, so this owner check is the client's.
- **Provider, in band.** A card lives at most 30 days, but a request can run
  longer (a response SLA of up to 30 days plus the redelivery horizon), so the
  card a buyer took from the offer file can expire while the buyer still has
  packets to send. The provider SHOULD therefore also carry its current card
  inside each result it delivers, valid until the end of that result's
  redelivery horizon; the result is signed and, over this Carrier, encrypted.
  The buyer MUST take such a card only from a packet of its own purchase,
  whose sender is that purchase's provider, and MUST verify it exactly like an
  offer-file card: `VerifyKeyCard` against finalized state and the card's
  Agent equal to the Capability's finalized owner. A card that fails either
  check is not used and does not invalidate the result. Where OpenFox carries
  it (the result message header) is specified in the OpenFox Service Actor
  rail guide.
- **Buyer.** The buyer's current card travels inside its task message, which is
  itself signed and, over this Carrier, encrypted. The provider requires the
  card's Agent to equal the task packet's sender and seals results and
  redeliveries to it. The buyer SHOULD send a card whose `not_after_unix`
  covers the request's response deadline plus the provider's redelivery
  horizon; a provider holding only expired buyer cards cannot deliver and the
  request ends through the existing timeout refund. Because a card lives at
  most 30 days, the buyer SHOULD also carry its current card in each task
  redelivery and in each result acknowledgement, so a card that would expire
  before that horizon is refreshed in band. The provider MUST take such a card
  only from a packet it ties to that purchase (a task the admission gate
  matched to the request, or an acknowledgement from the request's buyer for
  its result), only when the card's Agent is the packet's sender, and only
  after `VerifyKeyCard` against finalized state; of the valid cards it holds
  it seals to the one 6.3 selects. Where OpenFox carries it is specified in the
  OpenFox Service Actor rail guide.
- **Buyer, after the respond.** Once the respond is final the buyer has nothing
  to send until the result arrives, so neither a task redelivery nor an
  acknowledgement refreshes its card; a buyer away for longer than the card the
  provider holds would then never get a result it paid for. A buyer that sees
  a finalized respond and holds no accepted result SHOULD therefore send its
  current card in band, in a packet that only asks for the result again: when
  it first sees that state, and then at a bounded rate (OpenFox: at most every
  6 hours) until the result arrives or its retention ends. The provider MUST
  take it only from the request's buyer and only for a request it responded to
  and still retains, MUST verify the card as above, and MAY then deliver the
  result early, at a bounded rate. Such a packet never admits, executes or
  responds. For the same reason the card a provider publishes in its offer
  file SHOULD be long-lived (OpenFox: the 30-day maximum, republished once it
  runs under 15 days), so a returning buyer can still reach the provider. A
  buyer away for longer than the provider card it holds has no in-band route
  left and needs a fresh offer file. The trade-off is that the worst case of
  section 11 (a stale offer file keeps a card in use until its
  `not_after_unix`) becomes the normal case for the offer card, so an
  offer-file card SHOULD be signed by the dedicated card-signing controller of
  6.3: removing that controller is the only early revocation of a stale offer
  card. The first OpenFox implementation signs it with its packet controller,
  with the cost the OpenFox note in 6.3 describes.
- **Relay directory: none in V1.** A relay without chain access cannot tell a
  genuine card from junk under the same Agent ID, so any card directory it kept
  could be filled or evicted by anyone. Cards therefore travel only inside
  objects the counterparty already verifies.

### 6.5 Unknown or expired key IDs

A recipient that fetches an envelope naming a key ID it does not hold (never
issued, or already destroyed) cannot open it and cannot delete it. It MUST NOT
retry opening the same bytes, SHOULD remember them until the listed expiry so
they are not downloaded again from that relay, and leaves them to expire at the
relay. The memory follows the not-again rules of section 8.6. A recipient MAY
open an envelope under any key it still holds, including one whose card has
passed `not_after_unix`.

A recipient MAY skip the download altogether when the listing (9.3) names a
`recipient_key_id` it does not hold, remembering the entry under the same
rules. The listed key ID is the relay's unauthenticated word; a relay that
lies about it can only hide that envelope from this recipient, which it can do
anyway by not listing it.

## 7. Plaintext wrapper

The HPKE plaintext is:

```text
plaintext =
  D("tos.service.agent-packet-relay.plaintext.v1")  44 bytes
  ack_secret                                        32 bytes, not all zero
  packet_json_length                                u32
  packet_json                                       1..260,771 bytes
```

`packet_json` is the exact signed Agent Packet V1 JSON the sender's transport
was handed (`OutboundPacket.JSON`), byte for byte; it is never re-encoded. The
plaintext header is 80 bytes; `packet_json_length` MUST equal the remaining
length. The wrapper carries nothing else: the packet itself names the sender,
recipient, Capability and Quote commitment under its signature.

`ack_secret` is drawn uniformly at random by the sender for each envelope and is
used for nothing else.

## 8. Envelope

### 8.1 Layout

```text
header (157 bytes, the HPKE additional authenticated data) =
  D("tos.service.agent-packet-relay.envelope.v1")  43 bytes
  suite                                            6
  recipient_agent_digest                           32
  recipient_key_id                                 32
  envelope_id                                      32
  expires_at_unix                                  u64
  ciphertext_length                                u32
envelope = header || enc (1,120 bytes) || aead_ciphertext (plaintext length + 16)
```

`ciphertext_length` is the length of `enc || aead_ciphertext` and MUST equal
the remaining length. The envelope is at most 262,144 bytes (256 KiB), which
fixes the largest `packet_json` at
`262,144 - 157 - 1,120 - 16 - 80 = 260,771` bytes.

### 8.2 Acknowledgement hash

```text
envelope_id = SHA-256( D("tos.service.agent-packet-relay.ack.v1") || ack_secret )
```

The pair (recipient Agent, envelope ID) is the relay's storage key, and the
envelope ID is the only deletion credential check: whoever presents a 32-byte
value hashing to the envelope ID may delete the envelope under that mailbox. The value exists in clear only inside the ciphertext and at the
sender. The domain prefix keeps the hash unrelated to any other SHA-256 use.

### 8.3 HPKE binding

```text
info = D("tos.service.agent-packet-relay.hpke-info.v1") || suite
       || recipient_agent_digest || recipient_key_id
enc, ctx = SetupBaseS(pkR, info)
aead_ciphertext = ctx.Seal(aad = header, plaintext)
```

- `info` enters the key schedule, so an envelope sealed for one recipient Agent
  or key ID cannot be opened under another binding even with the right private
  key (a different Agent that happens to hold the same key seed included).
- The whole header is the AAD, so a relay can read the recipient, key ID,
  envelope ID and expiry but cannot change any of them undetected.
- The relay URL is deliberately not bound. The same envelope bytes MAY be
  deposited at every relay the recipient names, and one acknowledgement secret
  deletes every copy. Binding the relay would give no confidentiality or
  integrity gain (a copied envelope yields the same packet, which the inner
  replay checks absorb) and would break multi-relay deposit and relay
  renaming.
- A network domain is not bound separately: the recipient Agent ID already is
  network-specific.

### 8.4 Sender rules

1. Verify the recipient's card (6.3) and take its key.
2. Draw `ack_secret`; compute the plaintext, header and envelope.
3. `expires_at_unix` MUST NOT exceed the packet's own deliverable expiry
   (`OutboundPacket.ExpiresAtUnix`) nor `deposit_time + 86,400`.
4. Journal the envelope bytes durably **before** the first deposit. Sealing is
   randomized; a retry of an ambiguous deposit MUST resend the journaled bytes,
   never a fresh seal, so the relay can recognize it as the same envelope.
5. Before journaled bytes are sent again (a retry, a redundant deposit to
   another relay of the card, or a resend after a restart), the sender checks
   the card they were sealed to: if its last successful `VerifyKeyCard` is 10
   minutes old or older, it verifies it again (6.3). If the card has expired
   (`now >= not_after_unix`), was revoked (it no longer verifies against
   finalized state) or is no longer held, the sender MUST NOT send those bytes
   again. For a send that no relay has accepted yet it seals the same packet
   JSON to the recipient's current valid card under a fresh `ack_secret` (a new
   envelope ID), journals that envelope before its first deposit, and
   continues with it; without a valid card the send fails and is retried
   later. An envelope that a relay already accepted is not deposited at
   further relays. If finalized state cannot answer the check, nothing is sent
   and the send is retried; the bytes are never sent to a card whose standing
   is unknown past the 10-minute window. Step 4 still holds: a fresh seal
   happens only because the old card cannot be used, never to retry an
   ambiguous deposit to a usable card.
6. When a recipient card is revoked after relays accepted envelopes sealed to
   it, a sender that kept those envelopes' acknowledgement secrets MAY
   withdraw them (9.5) to shorten their exposure to a possibly compromised
   key. A sender is not required to keep the secrets; without them the
   envelopes stay until they expire.

### 8.5 Recipient rules

In this order, stopping at the first failure:

1. Parse the header (`ParseEnvelope`); require the recipient to be this Agent
   and the key ID one it holds.
2. HPKE-open with the section 8.3 `info` and the header as AAD.
3. Decode the plaintext wrapper; require `envelope_id` to equal the section 8.2
   hash of the recovered `ack_secret` (constant-time comparison).
4. `agentpacket.DecodeJSON(packet_json)`; require the packet's
   `recipient_agent_id` to equal this Agent and the envelope's recipient.
5. Verify against finalized state exactly as the existing receiver does
   (`agentpacket.Verify`) and apply the receiver's own bounds (OpenFox: packet
   JSON at most 128 KiB, rail frame decode).
6. Store durably (OpenFox: `Inbox.Put`). A duplicate is success.
7. Only then acknowledge (section 9.5) at every relay the envelope was fetched
   from.

Failure handling:

- Steps 1–3 failing: the envelope is not this key's or is corrupt. Do not
  acknowledge (step 3 failing means the secret cannot be trusted); remember it
  under section 8.6 until its expiry; let it expire.
- Steps 4–5 failing permanently (malformed packet, foreign recipient, bad
  signature, sender not finalized or tombstoned): acknowledge, since the
  recovered secret matches the ID, so junk sealed to this key does not hold
  quota for 24 hours. Record the refusal in local telemetry without packet
  contents.
- Step 5 failing transiently (finalized state unavailable) or step 6 failing:
  do not acknowledge; retry on a later poll.

### 8.6 Envelope IDs are public

Listing is open (9.3), so anyone who watches one relay learns envelope IDs and
can deposit different bytes under the same ID at another relay before the
honest sender does. That copy is junk the recipient cannot open, and it makes
the honest deposit at that relay fail with `409`. So that it cannot suppress
the genuine copy elsewhere:

- A recipient's record of envelopes it failed to open, or refused, is keyed by
  `(relay base URL, envelope_id)` or by SHA-256 of the downloaded bytes, never
  by the envelope ID alone.
- A failed open at one relay never suppresses listing, downloading or opening
  the same envelope ID at another relay. Only a successful open followed by
  the durable inbox write (8.5 step 6) settles an ID, and the acknowledgement
  then goes to every relay that listed it.
- A sender that receives `409` from a relay treats that relay as unusable for
  this envelope: it stops depositing this envelope there and does not count it
  as acceptance. `Send` still succeeds once any other relay accepted (9.2), and
  the redundancy loop terminates. If no relay accepted and at least one
  answered `409`, the sender replaces the journaled envelope with a fresh seal
  of the same packet JSON under a fresh acknowledgement secret (a new ID),
  journaled before its first deposit, and `Send` fails so the courier retries
  with it. Re-sealing one packet is safe: the recipient's inbox deduplicates
  the packet whichever envelope delivers it.

The attack costs the recipient at most that relay's copy; it delays delivery
only when the attacker pre-empts every relay in the card, and then only until
the next packet generation.

## 9. Relay HTTP API

### 9.1 Transport

- HTTPS is required. Plain HTTP is allowed only on a loopback address, for
  development, matching Agent Packet V1 `Post`.
- The relay never redirects, and clients never follow redirects.
- No request carries a query string; the relay rejects any request with one
  (`400`). No secret is ever placed in a URL. Acknowledgement secrets travel
  only in request bodies, and the relay MUST NOT log bodies.
- No cookies, sessions, accounts or bearer tokens are used or required. A relay
  operator MAY add transport authentication for its own resource policy; it
  never becomes authority over envelopes.
- Every response body is at most 64 KiB except a downloaded envelope.

All paths are below the base URL `B` named in a key card.
`{agent}` is the strict `agent_<64 hex>` form, `{id}` is the envelope ID as 64
lowercase hex; any other spelling, the all-zero agent, or the all-zero ID is
`404` and never normalized. The relay matches the escaped request path
exactly: a percent-escape, an empty segment or a trailing slash anywhere is
`404`.

A relay evaluates every request in this order, answering at the first
failure:

1. client address (section 9.8); a peer address that does not parse is `400`;
2. the rate limit of the request's class (`429` with `Retry-After` in whole
   seconds, at least 1): `PUT` is the deposit class, every other method the
   list/download/ack class; every request takes a token, including ones
   later refused;
3. a query string, even an empty `?` (`400`);
4. the path (`404`);
5. the method: a path that exists with another method is `405`
   (`method_not_allowed`) with an `Allow` header; `HEAD` is not supported;
6. the operation's own checks below.

Successful `200`/`201` deposit answers and `204` acknowledgement answers
carry no body.

### 9.2 Deposit

`PUT B/v1/mailboxes/{agent}/envelopes/{id}`, `Content-Type:
application/octet-stream`, body = the envelope.

The relay, without decrypting:

1. Checks the rate limit (`429` with `Retry-After`) and `Content-Length`
   present and at most 262,144 (`413`) **before** reading the body; reads at
   most 262,145 bytes.
2. Requires `Content-Type: application/octet-stream`, then `ParseEnvelope`:
   domain, suite, non-zero fields, exact length (`400`).
3. Requires the header recipient and envelope ID to equal the path (`400`).
4. Requires `now < expires_at_unix <= now + 86,400 + 300` (`422`), and stores
   the effective expiry `min(expires_at_unix, now + 86,400)`.
5. If the ID is already stored: identical bytes → `200`; different bytes →
   `409`. If the ID was acknowledged and its tombstone is still held → `410`.
6. Checks quotas (`507`): per recipient, per (client, recipient), global.
7. Writes the envelope durably (data and directory synced) and only then
   answers `201`.

Details of these steps:

- A request with no `Content-Length` (a chunked body) is `413` like an
  oversized one, since its size cannot be checked before reading. A body that
  ends before its `Content-Length` is `400`.
- `Content-Type` must be exactly `application/octet-stream`, without
  parameters.
- Envelopes and tombstones are keyed by (recipient, envelope ID), never by
  the ID alone. A deposit under one mailbox can never answer `409` or `410`
  for, hide, or be charged to another mailbox: junk under mailbox Y carrying
  X's envelope ID is stored for Y, counted against Y's quotas, and leaves
  X's deposit, listing, download and acknowledgement untouched. Within one
  mailbox the section 8.6 race still applies, and the genuine
  acknowledgement deletes a same-mailbox squat because the secret hashes to
  its ID.
- A held tombstone answers `410` whatever bytes are deposited under its key:
  the relay keeps no copy to compare, and a tombstone can only exist because
  someone presented the secret.
- Step 4 precedes step 5, so an identical retry whose `expires_at_unix` has
  passed is `422`, not `200`. `422` is terminal for those exact bytes: an
  expiry already past never becomes acceptable, and an expiry beyond the
  bound breaks section 8.4. For an honest sender a `422` means the packet
  is past its deliverable expiry (8.4 step 3) or a clock is wrong; the
  sender does not retry those bytes and does not re-seal. Quotas apply only
  to a new key: an identical retry of a stored envelope is `200` even when
  the mailbox is full.
- An envelope whose effective expiry has passed is gone for every purpose
  before the expiry sweep removes its file; a deposit under the same key is
  then judged as new, and the expired file is removed whether or not the new
  deposit is admitted.

`200`, `201` and `410` are durable acceptance: the envelope is stored, or was
stored and already acknowledged by its recipient. A transport `Send` returns
nil only on one of these. `409` is never acceptance and is never retried at
that relay (8.6). `422` is terminal for those bytes (above): they are not
retried and not re-sealed. Every other status, a timeout or a connection
error is a failure the sender retries with the same journaled bytes, subject
to the card check of 8.4 step 5 before each resend.

### 9.3 List

`GET B/v1/mailboxes/{agent}/envelopes` →
`200`, `application/json`:

```json
{
  "schema": "tos.service.agent-packet-relay.mailbox.v1",
  "agent_id": "agent_…",
  "envelopes": [
    {"envelope_id": "<64 hex>", "recipient_key_id": "hpke:<64 hex>",
     "size": 6804, "received_at_unix": 1767225600, "expires_at_unix": 1767312000}
  ]
}
```

At most 256 entries (the per-recipient count quota), ordered by
`received_at_unix` then `envelope_id` ascending; never an acknowledged or
expired envelope. An empty mailbox is `200` with an empty list (`[]`, never
`null`). `expires_at_unix` is the effective expiry, the earlier of the
envelope's own expiry and receipt plus the relay's retention. Clients decode
the list strictly (unknown fields, a missing or `null` list, more than 256
entries, non-canonical IDs, sizes outside the envelope bounds,
`expires_at_unix <= received_at_unix`, and entries not strictly in the order
above are rejected) and treat every value as an unauthenticated hint;
`received_at_unix` is the relay's word only.

### 9.4 Download

`GET B/v1/mailboxes/{agent}/envelopes/{id}` → `200`,
`application/octet-stream`, the exact deposited bytes; `404` when absent or
expired. Clients read at most 262,144 bytes.

### 9.5 Acknowledge

`POST B/v1/mailboxes/{agent}/envelopes/{id}/ack`,
`Content-Type: application/octet-stream`, body = exactly the 32-byte
`ack_secret`.

- Hash matches a stored envelope: delete it durably, keep a tombstone of the ID
  until its effective expiry, answer `204`.
- Hash matches a held tombstone: `204` (idempotent).
- Body not exactly 32 bytes, or `Content-Type` not exactly
  `application/octet-stream`: `400`. Hash does not match the path ID: `403`.
  Unknown or expired ID, or an ID held under another recipient: `404`.
- These are checked in that order: `400`, then `403` (which needs no lookup,
  so a wrong secret never reveals whether an ID exists), then `404` or
  `204`.

The relay compares in constant time. Without the secret nobody can delete an
envelope: not another recipient, not a party that downloaded the ciphertext.
The sender knows the secret and can withdraw its own envelope; it gains nothing
it could not by not depositing.

### 9.6 Relay description

`GET B/v1/relay` → `200`, JSON
`{"schema": "tos.service.agent-packet-relay.relay.v1", "max_envelope_bytes": 262144,
"max_ttl_seconds": 86400, "per_recipient_max_envelopes": n, "per_recipient_max_bytes": n}`.
It is advisory and grants nothing. `max_ttl_seconds` and the per-recipient
values report the operator's configured bounds, which MAY be lower than the
V1 ceilings.

### 9.7 Errors

Error responses are `application/json`
`{"schema": "tos.service.agent-packet-relay.error.v1", "code": "<code>"}` with one fixed
code per status: `invalid_request` (400), `forbidden` (403), `not_found` (404),
`method_not_allowed` (405), `request_timeout` (408), `conflict` (409), `gone`
(410), `too_large` (413), `expiry_out_of_bounds` (422), `rate_limited` (429),
`quota_exhausted` (507), `unavailable` (503). No response repeats request
bytes. `503` is a persistence failure or a relay shutting down; it is
retryable. `408` is a deposit body that did not arrive within its read
deadline (section 9.8); it is retryable with the same bytes. It is `408`
rather than `503` because the cause is the request's own transfer, not the
relay's state, and rather than `400` because the bytes may be valid: a
`400` would tell a slow but honest sender to give up on this relay. A
client believes a code only when it is the fixed code of the response's
status.

### 9.8 Bounds

| Bound | V1 value |
|---|---|
| Envelope | ≤ 262,144 bytes |
| Retention | ≤ 86,400 s from receipt, and ≤ the envelope's `expires_at_unix` |
| Per recipient | ≤ 256 envelopes and ≤ 16 MiB (operator MAY lower) |
| Per (client address, recipient) | ≤ 64 envelopes (operator MAY lower) |
| Global | operator-configured byte and count limit; required, no default unlimited |
| Tombstones | one per acknowledged ID until its effective expiry; counted in the global count |
| Deposit rate | per client address; default 60/min, burst 32 |
| List/download/ack rate | per client address; default 600/min |
| Request body read | ≤ 262,145 bytes (deposit), exactly 32 bytes (ack) |

Client address means the IP address, with IPv6 aggregated to its /64. A full
mailbox rejects new deposits (`507`); a relay never evicts a stored envelope to
admit another, because eviction would let anyone delete genuine envelopes.

Where the table above leaves a choice, the reference relay makes these:

- The client address is the TCP peer. `X-Forwarded-For` is believed only from
  peers the operator lists as trusted proxies; it is then walked from the
  right and the first address that is not a trusted proxy is the client.
- Connections are bounded when accepted, when only the TCP peer is known: at
  most 1,024 in total, 16 per peer address (IPv6 per /64) and 64 per IPv6
  /48 by default. A /48 is the usual assignment to one site, so without
  the /48 bound one holder would fill the table from 64 of its /64s; with
  it, filling the table takes 16 distinct /48s or 64 IPv4 addresses (or a
  mix). A connection past any bound is closed at once, never queued, so a
  full table cannot block other clients or shutdown. Trusted proxies count
  only against the total; a terminating proxy bounds its own clients. Idle
  keep-alive connections close after 30 seconds, long enough to span one
  15-second poll interval with its jitter.
- The list/download/ack burst defaults to 100. Rate limits are token buckets
  in a table of bounded size (65,536 per class) kept in least-recently-used
  order. A new client is never refused for lack of room: the least recently
  used bucket is evicted in constant time. A limited client can lose its
  state only after as many other clients as the table holds have been
  active more recently. Within one IPv6 /48 at most 256 /64 clients get
  their own bucket; further /64s of that /48 share one bucket, so one /48
  holds at most 257 entries and cannot by itself flush the table.
- The global byte limit counts envelope bytes; the global count limit counts
  envelopes plus tombstones; neither has a default. Retention defaults to the
  24-hour ceiling and the operator MAY lower it.
- At most a configured number of deposit bodies (default 256, so 64 MiB) are
  read at once, whatever the number of connections or HTTP/2 streams; a
  deposit past it is answered `503` with `Retry-After` before its body is
  read. One client address holds at most 4 of them at once and all clients
  in one IPv6 /48 at most 16 (past either its deposit is `429` with
  `Retry-After`), so holding every slot takes 16 distinct /48s or 64 IPv4
  addresses (or a mix); IPv4 addresses are not grouped further. A body must arrive within 5 s plus its declared length at
  32 KiB/s (at most 13 s, well under the 30-second request read timeout);
  a slower body is cut off with `408` (retryable) and the connection closed,
  so a trickling sender holds a slot for seconds, not half a minute.
- The relay keeps the depositing client address with each stored envelope so
  that the per-(client, recipient) quota survives a restart.
- A record that fails its checksum, an unknown file or an unknown layout
  makes the relay refuse to start rather than guess.

**Why 256 KiB.** OpenFox frames carry at most 60 KiB of data; as base64 inside a
signed packet JSON (2,420-byte signature in hex plus fields) each packet stays
under the 128 KiB receiver bound. The plaintext header, HPKE encapsulation and
tag add 1,216 bytes and the envelope header 157 bytes, so every OpenFox packet
fits with two-fold headroom for other Agent Packet users, while one request
still needs at most 256 KiB of relay memory and the 16 MiB per-recipient quota
still holds at least 64 maximal envelopes (one complete 32-frame rail message
fits several times). Agent Packet V1's 1 MiB payload is not reachable through
this Carrier in one envelope; larger content is chunked by the application,
as OpenFox frames already are.

## 10. OpenFox client behaviour

The client is a `PacketTransport` plus a poller; neither changes packet
signing, frames, the courier journal or the receiver.

**Send** (`Send(ctx, OutboundPacket) error`):

1. Resolve the recipient's current verified card (provider card from the offer
   file, buyer card from the task). No card → a fixed `no route` error; the
   courier keeps the packet journaled.
2. Seal once per `IdempotencyKey`, with `expires_at_unix =
   min(OutboundPacket.ExpiresAtUnix, now + 86,400)`. The envelope is durably
   journaled, keyed by the packet's idempotency key, before the first deposit;
   it is sealed again only under the 8.4 step 5 card rule or the 8.6
   conflict rule.
3. Deposit the journaled bytes to every relay in the card, in card order, each
   with a bounded timeout (default 30 s). Return nil once at least one relay
   answered `200`, `201` or `410`; keep trying the remaining relays in the
   background for redundancy, except a relay that answered `409`, which is
   abandoned for this envelope (8.6). All failed → error; the courier retries.

A nil return therefore means one relay durably holds the envelope, which is the
contract the courier relies on. The existing redelivery (buyer task every 10
minutes while pending; provider result from 1 minute backing off to 1 hour)
creates new packet generations, hence new envelopes; the receiver's inbox
deduplicates them.

**Poll:**

- List each relay of each held key every 15 seconds while the node runs
  (minimum 5 seconds; add up to 20 % random jitter). On error or `429` back off
  exponentially to at most 5 minutes, honouring `Retry-After`.
- Download envelopes not seen before, one at a time, and process them with the
  section 8.5 rules; the decrypted packet enters the same accept path as a
  Messenger or direct delivery (decode → recipient check → `agentpacket.Verify`
  → durable `Inbox.Put`).
- Acknowledge only after the durable inbox write, at every relay that listed
  the same envelope ID.
- A relay outage delays delivery only; nothing is lost while any one relay of
  the card holds the envelope and its TTL has not passed.

**Implementation bounds.** These bound the client's own memory and are not
protocol limits; another client may choose others. The OpenFox client keeps
at most 8,192 entries in its not-again memory and at most 8,192 in its memory
of settled envelope IDs, and forgets an entry after its listed expiry and at
the latest 24 hours and 5 minutes after it was recorded; evicting an entry
early only costs a repeated download. It keeps at most 8 cards per peer Agent
(dropping the least preferred under 6.3) and cards of at most 1,024 peers, and
holds at most 16 of its own keys.

## 11. Threat model

**Relay or network can:** drop, delay, reorder, duplicate or replay
envelopes; refuse service; serve stale lists; lie about status codes
(including a false `201`, which the sender's redelivery bounds); and fake an
outage. Replays and duplicates are harmless: the same packet opens again, the
durable inbox deduplicates the frame and the Native Execution Gate keeps
execution at most once. A relay can also replay an envelope after its
acknowledgement; a held tombstone (`410`) refuses honest re-deposit of the same
ID, and the receiver's duplicate handling covers a malicious relay.

**Relay or network cannot:** read a packet (HPKE with a hybrid post-quantum
KEM); forge or alter one (the inner ML-DSA-44 signature verified against
finalized state, plus AEAD over the header and plaintext); re-address an
envelope to another recipient or key (info and AAD binding, and the signed
packet recipient); delete an envelope without its secret; or create any
authority.

**Metadata the relay learns:** recipient Agent ID and key ID; envelope sizes
and counts; deposit, fetch and acknowledgement times; client IP addresses of
senders and recipient. Because listing and download are open (9.3, 9.4), anyone
who knows an Agent ID can also learn its pending envelope count, sizes, key IDs
and times, and can download ciphertext. It never learns the sender Agent, the
Capability, the Quote or any content. Sizes are not padded in V1; frames are
mostly at their fixed chunk size anyway. Senders that need to hide their IP
address use their own network-layer measures.

**Open fetch trade-off.** Proving recipient identity to a relay needs either
chain access (to check an ML-DSA signature against the finalized policy) or a
registration the relay cannot authenticate, which a squatter could claim
first; a key-possession challenge would add a relay-side KEM operation and
challenge state per poll. With end-to-end encryption, open fetch leaks
only the metadata listed above, which the relay operator learns in any case.
V1 therefore chooses open listing and download and keeps deletion strictly
secret-bound. A later version MAY add a key-possession challenge for listing.

**Spam and denial of service.** Anyone can deposit for any Agent ID. Junk is
bounded by the envelope size, the per-recipient and per-(client, recipient)
quotas, the deposit rate limit, the global limit and the 24-hour TTL. Junk sealed
to the recipient's real key is acknowledged and removed on the next poll
(8.5); junk naming an unknown key ID or failing decryption cannot be removed and
holds quota until it expires. Residual risk: a distributed flood can keep a
recipient's mailbox full at one relay, so honest deposits get `507` and the
sender falls back to the recipient's other relays and its redelivery
schedule; that is an availability attack only. Admission fees, proof-of-work or
operator allow-lists are possible later admission policies and remain Carrier
policy, never authority.

**Sign-then-encrypt pitfalls.** The plaintext is a packet whose signed preimage
already names the recipient Agent, so a recipient cannot re-encrypt a received
packet to a third party and have it accepted (the third party's recipient
check fails). A packet sealed to a different Agent's key is refused at step 4.

**Why HPKE base mode is sufficient.** Authenticated HPKE modes would add a
second, KEM-key-based sender identity that finalized state does not hold. The
sender's identity is already proven, post-quantum, by the ML-DSA-44 signature
over the exact packet, verified against the finalized controller policy after
decryption. An attacker who can only seal to the public key gains nothing:
its envelope decrypts to bytes that must still carry a valid finalized-controller
signature naming this recipient.

**Sender proof of possession.** The inner ML-DSA-44 signature by a controller of
the finalized sender Agent policy, over the exact packet, is the sender's proof
of possession. There is no separate challenge: the relay grants nothing a
challenge could protect, and the recipient checks the signature against
finalized state after opening and before acting. This relay is a Carrier, not
the private content handoff profile of
[OpenFox Autonomous Earning Roadmap §6.11](OPENFOX_AUTONOMOUS_EARNING_ROADMAP.md#611-private-content-handoff).
A §6.11 handoff adapter built on top of it MUST still bind its own Agreement,
obligation, direction, purpose, digest and expiry fields inside the signed
packet payload; the relay supplies only the authenticated-encryption transport.

**Key compromise.**

- Recipient HPKE private key: past and pending envelopes to that key (as far
  as anyone harvested them; open download makes harvesting easy) become
  readable, but nothing can be forged. Exposure is bounded by the card lifetime
  (at most 30 days, 7 recommended), the 24-hour envelope TTL and prompt
  acknowledgement. V1 offers no forward secrecy within one key's lifetime.
  **A new card does not revoke the old key.** A stale or tampered offer file
  (it is unsigned) can keep handing senders the old, still validly signed card
  until its `not_after_unix`, up to 30 days; publishing a successor helps only
  senders who see it. Once the private key is compromised, the only way to
  stop senders sealing to it before `not_after_unix` is to remove the
  controller that signed its card from the finalized policy (6.3). Envelopes
  relays already hold for that key stay readable to whoever has the key until
  they expire (at most 24 hours) unless their senders withdraw them with their
  acknowledgement secrets, which 8.4 step 6 permits. That is why
  cards SHOULD come from a dedicated card-signing controller; with the first
  OpenFox implementation's packet controller, revocation also stops the node's
  packets until a new controller is registered.
- Sender's ack secret: lets its holder delete one envelope; it is single-use
  and per envelope.
- Controller ML-DSA-44 key: the attacker can sign cards for its own HPKE key
  and so receive future traffic sealed from that point on, as well as sign
  packets. This is total identity compromise and is recovered on chain by
  policy rotation, which also invalidates cards the removed controller signed
  (6.3).
- Relay compromise: equals a malicious relay above.

**Post-quantum stance.** Confidentiality uses the hybrid MLKEM768-X25519 KEM,
secure while either ML-KEM-768 or X25519 holds, which protects recorded
ciphertext against a future quantum adversary. Authentication is ML-DSA-44.
HKDF-SHA256 and AES-256-GCM keep adequate margins. The KEM is specified in the
HPKE post-quantum draft; V1 pins the IANA identifier `0x647a` and the frozen
vectors, so any interoperable implementation must reproduce them.

## 12. Acceptance plan

The later implementation pull requests (relay program, OpenFox client) MUST
show, with commands and commits recorded:

1. **Two hosts.** Buyer and provider OpenFox nodes in two isolated network
   namespaces with no shared filesystem or Unix socket, reachable only through
   a relay in a third namespace; one complete paid task → result → result-ack
   lifecycle on a local chain, with execution exactly once.
2. **Relay outage and recovery.** Relay stopped mid-transfer (deposits failing,
   courier retrying), restarted from its durable store; and a second relay in
   the card carrying traffic while the first is down. No packet lost, no
   duplicate execution.
3. **Crash windows.** Recipient killed between inbox write and
   acknowledgement (envelope redelivered, deduplicated), and sender killed
   between journaling and deposit (identical bytes resent, `200`).
4. **Adversarial envelopes.** Every negative in the frozen corpus refused by
   the relay or the client as specified; a tampered header, ciphertext and tag;
   an envelope re-addressed to another Agent; an envelope replayed after
   acknowledgement (`410` or deduplicated); a foreign envelope sealed to the
   recipient's real key carrying a packet signed by a non-controller or naming
   another recipient (refused, acknowledged, no execution); deletion attempts
   with wrong secrets (`403`), from other clients, and by URL (impossible); and
   the public-ID race of section 8.6: an observer of relay A pre-deposits junk
   under the same envelope ID at relay B, the honest deposit at B gets `409` and
   is abandoned there while `Send` succeeds through A, and the recipient
   polling B first still opens the genuine copy from A in the same poll cycle.
5. **Quota exhaustion.** Per-recipient, per-(client, recipient) and global
   quotas reached by a flood from one and from several client addresses; honest
   deposits receive `507`, use the other relay, and succeed after expiry or
   acknowledgement frees space; the relay never evicts.
6. **Key expiry and rotation.** Card expiry with a successor card published;
   envelopes sealed to the old key still opened until its destruction time; a
   card refused after its signing controller is removed from the finalized
   policy; envelopes to a destroyed key left to expire.
7. **Bounds and hygiene.** Oversized bodies refused before reading; no
   redirects followed; query strings refused; no secrets or plaintext in relay
   or client logs; the relay process has no chain RPC configuration and no key
   material.
8. **Corpus.** The relay's parser and the client's opener run against
   `spec/test-vectors/agent-packet-relay-v1.json`; a second independent
   implementation reproducing the open direction is required before this
   profile claims cross-implementation conformance.

This evidence is Carrier evidence for root Gate O ("at least two independent
Carrier paths", "recover … after a Carrier outage") only when it is produced
against independent deployments as that gate requires. Until then this
profile is an incubation design (ROADMAP section 8.1) and supplies no gate
evidence.

## 13. Reference implementation and vectors

- `protocol/pkg/agentpacketseal` — the codec: key ID, key card body and
  carrying packet, plaintext wrapper, envelope header parse, seal and open,
  acknowledgement hash. It is deliberately small and holds no relay, storage,
  HTTP or OpenFox logic.
- `protocol/pkg/agentpacketrelay` — the relay HTTP API of section 9 over a
  durable on-disk store (atomic, checksummed records; expiry sweep;
  tombstones), and the Go client a sender or recipient uses: deposit with a
  typed outcome (accepted `200`/`201`/`410`, `409` conflict, refused bytes,
  retryable), strict list decoding, checked download and acknowledgement;
  HTTPS or loopback HTTP only, no redirects, an explicit proxy only. It holds
  no key and runs no packet verification.
- `protocol/cmd/tos-service-packet-relay` — the relay daemon, with a systemd
  unit and operator notes in `protocol/deploy/packet-relay/`.
- `agentpacket.VerifySender` — the sender-signature half of
  `agentpacket.Verify`, used for key cards; `Verify` now calls it and is
  otherwise unchanged.
- `spec/test-vectors/agent-packet-relay-v1.json` — generated by the
  `TestRelayVectors` test of `agentpacketseal`. It contains two fixed key
  seeds with their public keys and key IDs, acknowledgement hashes, key card
  bodies and 21 rejected mutations, an example key card packet, plaintext
  wrappers and 7 rejected mutations, two sealed envelopes with their `info`,
  AAD and plaintext, and 22 rejected envelope mutations, each with its
  rejection class.

The standard library offers no deterministic sealing interface, so the
generator runs as a Go test under `testing/cryptotest.SetGlobalRandom`. The test
rebuilds the corpus and requires the committed file to match byte for byte
(it regenerates only when `AGENTPACKETSEAL_WRITE_VECTORS=1` is set, never on
mismatch), then checks the committed file in the open direction only. The
open-direction checks are normative and toolchain-independent; byte-identical
re-sealing holds only for the generator toolchain `go1.26.11`. The inner packets
in the corpus carry signatures from the in-process test stand-in, not
ML-DSA-44: the seal layer treats `packet_json` as opaque bytes, and real
ML-DSA-44 packet signatures are covered by the Agent Packet tests through the
pinned `tosctl`.
