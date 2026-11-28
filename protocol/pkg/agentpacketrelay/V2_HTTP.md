# V2-only relay HTTP surface

The separate command is `tos-service-packet-relay-v2 -config CONFIG.json`.
It never opens V1 storage, serves `/v1`, reads key-card routes, or tries a
legacy route after a refusal. The old command remains for its unmigrated
in-repository clients; it must use a different directory and listener.
V2Store and the listing schema/codec are independent of the old mailbox API.
The sealed outer envelope, packet signature and acknowledgement-secret format
remain the unchanged cryptographic carriage specified by Messenger V2; the
relay does not decode a chat frame inside ciphertext.

## Configuration and authority

CONFIG is strict JSON, at most 64 KiB, with duplicate/unknown fields and trailing
values refused. Required fields:

| Field | Meaning |
| --- | --- |
| `listen` | Numeric loopback for a plaintext listener behind a TLS proxy; otherwise TLS required |
| `url` | Canonical external HTTPS base URL; proofs bind this configured value, never Host |
| `tls_cert`, `tls_key` | Both PEM paths for native TLS, or both empty behind a loopback proxy |
| `state_dir` | Absolute, private V2-only store directory |
| `checkpoint` | Separate absolute finalized-reader high-water file; keep it across restarts |
| `global_entries`, `global_bytes` | Explicit finite global store limits |
| `endpoints` | 3–8 distinct read-only registry RPC endpoints; strict majority required |
| `network` | Configured `network_id`, bare `genesis_root_hash`, bare `genesis_file_hash` tuple |
| `code_base64`, `code_hash` | Frozen registry code BOC and its pinned representation hash |

Optional `ttl_seconds` selects retention from 1 to 86,400 seconds (default
86,400), including the 1-hour test and 3-hour production D10 profiles.
The checkpoint path must be outside state_dir, whose root inventory is closed.

Optional `stranger_max_envelopes`, `stranger_max_bytes` and
`stranger_global_share` lower or select the operator limits: defaults 32,
2 MiB and 25; hard maxima 64, 4 MiB and 25. Zero closes that allowance.
The owner can lower its mailbox further, never enlarge the operator's limits.
Optional trusted_proxies lists at most 16 canonical CIDR prefixes whose
forwarded client addresses are trusted. Leave it empty for direct TLS; enable
it only for controlled proxies, never for arbitrary peers.

Copy the network tuple and registry release from the reviewed deployment
manifest, not from a responding endpoint. The transport constructors additionally
require the code-pinned approved test-network tuple. Production is refused:
this reader does not invent authorization/admission epochs. The source checks
the endpoint-majority genesis identity on every finalized registry read and
uses the existing deterministic locator and persisted checkpoint fence.
This is the spec's strict-majority read trust model, not cryptographic
account-proof verification. A dishonest configured majority is outside it.

Only transport failures of every endpoint are classified as an outage.
Malformed data, a split quorum, wrong genesis, regressed checkpoints and
other integrity failures never use stale-pass fallback. Delegation passes
refresh at 300 seconds and are refused at 600 seconds if reads stay unavailable.
No signing tool or business-controller key is loaded by this service.
The only service key is its TLS key. Do not log request URLs, credentials,
proofs, nonces, lane keys or payloads at a reverse proxy.

## Operations in this step

- PUT `/v2/mailboxes/{agent}/envelopes/{id}`: stranger or credentialed contact.
- GET `/v2/mailboxes/{agent}/envelopes`: credentialed list only.
- GET `/v2/mailboxes/{agent}/envelopes/{id}`: credentialed fetch only.
- POST `/v2/mailboxes/{agent}/envelopes/{id}/ack`: the unchanged secret authority.
- PUT `/v2/mailboxes/{agent}/policy`: credentialed owner publication.

Revocation sets, directory, description and long polling are the following
relay step (section 17 item 7). Unsupported paths and wait headers refuse;
none falls back or silently ignores the unsupported operation.

Address/rate/query/path/method checks precede authorization. Provided invalid
credentials never become stranger access. Stateless chain, scope and proof
checks precede nonce claim and finalized delegation verification. Identity and
lane derivation take only a CheckedRequest whose chain was verified. Explicit
lanes and default issuer chains retain their distinct persistent tags.
The handler rechecks time-dependent scope after a finalized read.

Bodies have finite slots (256 total, 4 per client, 16 per IPv6 /48), a size
limit before reading, and a read deadline. Per-client/site slot exhaustion is
429; global slot exhaustion is 503. Per-request operations have a 30-second
context bound. Listener connection limits and discarded connection-error logs
are enabled by the command. No error response reflects request or source bytes.

Only the GET listing accepts 81,920 bytes; it is never paginated or truncated.
A response exceeding that bound answers 500. Every other non-download response
keeps 65,536 bytes; a download keeps the envelope bound. The V2 client reads
only those bounds and rejects V1 schemas, redirects, unknown errors and excess
bytes. It never retries a submission. Its caller supplies a route selected
from a valid hint; this library has no key-card or V1 fallback.

Mailbox policy has one exact domain-separated binary encoding. Its frozen
positive/negative corpus is generated deliberately and checked by an independent
Python reproducer. Policies persist atomically with their authorizing delegation.
An unavailable or malformed read cannot lift a closed policy. Unavailable reads
reuse only the verifier's existing pass (under 600 seconds); after that the
request refuses, while the policy record remains. Malformed evidence refuses
without cache fallback. A verified tombstone, removed delegation, advanced
finalized epoch, changed policy, or expiry voids the policy; the next owner's
earlier timestamp can then win.

Policy refresh snapshots the delegation digest and issuance time under the store
gate, releases it for the finalized read, then checks the same identity again
before committing. A replacement discards the stale result and refuses that
request. Publishing also checks the snapshot after re-taking the gate. Network
I/O never holds the store gate. Local file reads and synced atomic writes still
hold it to preserve store consistency. The verifier's own bounded read gate is
separate; this change does not remove its serialization of finalized checks.
Expired policy records are reclaimed, including for unvisited mailboxes.
The policy table is bounded at 4,096 records; admission past it is unavailable.

## Evidence and remaining gates

See V2_STORE.md for replay F+1 recovery, tombstone accounting and exceptional
recovery rules. The command runs replay recording and expiry maintenance and
drains them before closing storage. Preserve the state and checkpoint files;
do not delete them to bypass a refusal.

`go test -race` covers TLS client/server delivery, closed reads, restart/floor,
clock rollback, independent proof relay binding, outage/600-second refusal,
policy timestamp poisoning/revocation, body limits, and A6 floods through HTTP.
Policy regressions cover tombstones at 300/601 seconds, outage at 599/600,
stalled refresh with an unrelated deposit, and replacement by either a new
delegation digest or issuance time.
`make relay-v2-store-mutants relay-v2-http-mutants` uses overlays and named
failures; compilation errors and timeouts do not count as red controls.
`make relay-v2-policy-vectors-check` compares frozen bytes and independently
reproduces them. Unit/integration fixtures are not a deployed-relay A4–A6 live
transcript; that remains part of the phase-1 live acceptance gate.
