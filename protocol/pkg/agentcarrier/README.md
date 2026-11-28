# V2 carrier primitives (part 1)

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

Part 2 adds hint publication/resolution, credential issue/storage/refresh,
two-copy fanout, no-route retries (30 seconds doubling to ten minutes), and the
D10 generation schedule. The journal already has pending no-route state and
reserved resolution timing fields. This PR does not start that scheduler,
migrate an existing client or store, add direct transport, or claim live A8.

Validation: run `GOWORK=off go test -race ./protocol/pkg/agentcarrier` and
`GOWORK=off make agentcarrier-mutants`. The controls use isolated source
overlays, require the named test to fail, and do not count compile errors or
timeouts as a successful control. No live endpoint or wallet is needed.
