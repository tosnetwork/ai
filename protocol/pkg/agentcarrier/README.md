# V2 carrier lanes and routing

A lane owns one private HPKE key family, its signed cards, a bounded outbox and
its poller. Rail and chat use separate directories, keys, cards and journals.
This package imports protocol code only. The only concrete relay client is
`agentpacketrelay.V2Client`; there is no retired relay route or store reader.
The unchanged signed packet, encryption card and HPKE envelope codecs remain
those frozen by the transport specification; their version names are not relay
fallbacks.

The extraction keeps the existing rail carriers' key lifetime and retention,
journal-before-deposit, corrupt-copy isolation and durable-inbox-before-ACK
rules. Business packet signing, finalized packet/card verification and inbox
admission are injected lane interfaces. A verifier must honor its context and
classify permanent refusals with `ErrRefused`; all other failures remain
transient. A successful inbox callback promises durable, duplicate-safe storage,
not execution. The business inbox and its replay guard still own exactly-once
processing. The carrier holds no wallet controller key. Its transport delegation
is verified on opening and on credential use; the credential manager may retain
the transport signing key in external custody.

`Queue` saves the already signed packet and exact business deadline. Reusing an
id with different bytes refuses. `Attempt` accepts a raw hint record and a signed
card, re-verifies both, selects one relay by index from the verified hint, and
sends only journaled envelope bytes. The card's relay list never selects a
peer route. Only the selected lane card is consumed as authority; unused hint
objects stay opaque and are never exposed as verified identities. A lost response or crash after send reuses those bytes. The result's
TTL is that relay's description, **not** a claim about every relay in the hint.
The later fanout scheduler computes the minimum advertised TTL and carriage
report. Relay acceptance never authenticates a business outcome.

`Poll` is a bounded plain-listing pass over retained owner-selected targets;
the runtime calls it every 15 seconds. `Wait` is a separate single-waiter pass
at a retained relay, so a long poll need not delay plain polling. It admits
contact entries first, bounds downloads, opens only held keys, verifies and
stores before acknowledging. Successful durable admission settles an ID across
relays; corrupt or permanently refused copies remain scoped to their relay.
A restart may download again; the durable inbox must recognize the duplicate.

Key cards normally live seven days and rotate 48 hours early. Seeds stay until
card expiry plus 24 hours and 300 seconds. TrackRelays only extends existing
poll retention. Hint publication supplies its own retirement deadline through
this API in part 2. Opening or operating a used store refuses missing/corrupt
records, mixed lane or verifier-network identities, unsafe permissions, symlinks and multiple
writers. Atomic files carry a checksum; uncertain writes poison the instance
until restart. A checksummed inventory admits new key/outbox files only after
they are synced, and retires references before unlinking; a missing referenced
file refuses startup. Temporary files left before rename are never delivery records.

Bounds: 16 retained keys, 32 poll targets, default 256/max 4,096 outbox records,
2 MiB per record, four retained envelope generations, 16 remembered relay
attempt targets per generation, 8,192 entries in each bounded receive memory,
16 downloads per relay pass, 30-second ordinary and 40-second waiting calls.
No network call holds the disk mutex. One outbound operation per lane serializes
its journal; polling uses separate gates. Different lanes are independent.

Routing and credential APIs compose with the primitives:

1. `OpenCredentialManager` takes the lane config, the transport key and the
   business admission callback. Its private, checksummed store holds that key,
   owner grants, issued contact grants and received grants. It holds no controller
   key. A changed transport key/delegation replaces authority only after the new
   delegation passes finalized verification. Old own grants renew lazily under
   the new delegation while preserving the contact lane ID.
2. Put that manager in `Config.Credentials`, open the lane, then `OpenResolver`,
   `OpenPublisher` and `OpenScheduler`. Quiesce operations before closing them.
3. `Publisher.Publish` journals exact hint bytes before publication and receipts
   afterward. Call it periodically and on local configuration changes: it reuses
   a live hint until half-life, and republishes when public cards, relays, policy
   or delegation change. Same-second changes get monotonically increasing hint
   and policy stamps within the permitted clock skew, so relays do not ignore an
   equal-time update. Partial failures retry only missing targets with the
   saved bytes. Default hints disclose no objects or direct addresses. Rail card
   disclosure is explicit; chat public contact requires both consent and an
   independently verified evidence object. Default mailbox policy is 32/2 MiB;
   `PolicyConfigured` makes an explicit closed policy distinguishable from the
   default. Retired relays are polled through hint expiry + 86,400 + 300 seconds,
   conservatively covering every permitted advertised TTL.
4. `Resolver.Resolve` tries verified cache, a supplied out-of-band hint, then
   indexes/records at last-known relays and at least two configured directories.
   Directory answers are merged and reverified. It retains the selected verified
   card beside private hints, and never uses a card's relay list as a route.
   Production-shaped hints require two relays; allowing one is an explicit test
   configuration, still subject to the verifier's pinned test-network identity.
5. Queue a signed packet, then call `Scheduler.RunDelivery` for its ID (or drive
   `Advance` at `NextAttempt`). No-route retries are durable: 30 s doubling to
   600 s, with a due-generation override. A valid republished hint resumes the
   pending delivery; its business deadline abandons it with retention-exceeded.
   One envelope is sent to two accepting relays, in hint order. Backoff is saved
   before transport, so restart cannot reset it. Once business receipt processing
   calls `Lane.Complete`, a returning relay receives no further deposit. Re-deposit
   generations use 80 percent of the smallest advertised hint-relay TTL, at least
   600 seconds apart; unreadable descriptions count as 86,400 seconds. Old ACK
   secrets and targets enter a compact durable withdrawal journal before full
   envelopes retire. This permits long deliveries without retaining unbounded
   full ciphertext generations. Expired metadata is pruned after key retention.

Owner grants last at most an hour and renew shortly before expiry. Contact grants
last three days (bounded by the delegation), renew at half-life, and keep the same
explicit lane ID. `IssueContact` requires business admission. Export the opaque
credential only into a signed, sealed business header and repeat it until that
header is acknowledged. `ReceiveContact` verifies packet/admission/issuer, obtains
routing independently from the resolver and stores the holder seed privately;
its extractor cannot supply a route. Transient proof/admission failures remain
`ErrUnavailable`; the consumer retains the private signed header for later import
and keeps optional credential processing distinct from business admission. The
business header integration is the
consumer migration's responsibility. Received grants are attenuated to the exact
relay at deposit; revoked grants are dropped before stranger fallback.

Each auxiliary namespace has an inventory and single-writer lock, is bound to
Agent/lane/network identity, and refuses missing indexed files and unsafe storage.
Routing cache: at most 4,096 peers and four records per peer. Each credential or
scheduler namespace has at most 4,096 records; the latter has at most 148 compact
withdrawals per delivery. Every file remains bounded at 2 MiB. No retired relay
client, frame decoder, store reader or fallback is added. This package does not
migrate existing clients, implement direct sessions, or claim live cross-host A8.
Local tests use actual V2 TLS services and a synthetic finalized-state resolver.

Validation: run `GOWORK=off go test -race ./protocol/pkg/agentcarrier` and
`GOWORK=off make agentcarrier-mutants` and
`GOWORK=off make agentcarrier-routing-mutants`. The controls use isolated source
overlays, require the named test to fail, and do not count compile errors or
timeouts as a successful control. No live endpoint or wallet is needed.
