# Relay V2 directory and revocation controls

The V2 server uses only its separate, checksummed V2 store. It neither reads
V1 state nor routes a V2 request through a V1 handler. All credentialed routes
verify the signed credential chain before using its issuer chain or replay
identity. A directory record is routing information, never controller authority.
The finalized resolver requires the pinned Registry v2 release and verifies the configured network tuple.

## Owner controls

`POST /v2/mailboxes/{agent}/revocations` requires the owner revoke capability.
The binary request uses the `tos.service.relay-revocation.v1` domain, a one-byte
count (1–32), and that many 32-byte chain values followed by big-endian u64
expiry times. Every chain value in a presented credential is checked. A root
revocation also blocks credentials with appended blocks. Existing encrypted
payloads are retained and remain available to an authorized owner.

Until is bounded to seven days plus 300 seconds from the relay clock. Merging
never shortens an existing revocation. There are at most 1,024 live entries per
mailbox; the default relay-wide bound is 65,536. Capacity refusal is 507.
A successful response follows the synced atomic control-record replacement;
an uncertain write poisons the store. The carrier must journal revocation intent
and retry delivery to every active and retired relay; the low-level client makes
one attempt and does not implement the carrier's delivery policy.

## Hint directory

`PUT /v2/hints/{agent}` admits only a fully verified hint record. Unless the
server explicitly enables directory mode, the signed hint must name this relay.
`GET /v2/hints/{agent}` returns the binary index; appending `/{digest}` returns
the corresponding record. Digest is SHA-256 of the encoded delegation.

Each Agent has at most four live delegation records. A newer issued time replaces
the same delegation; identical times with different bytes return 409. A different
live delegation never displaces an occupied slot. The default directory Agent
bound is 16,384. Expiry and positively established finalized revocation free a
slot; an unavailable or malformed finalized read never evicts a live record.
Public lookups are limited to 60 per minute per client address. Consumers must
independently run `VerifyConsumerHint` on fetched records before using routes.

The index is at most 209 bytes and sorted by unique digest; each record is at
most 40,960 bytes. The frozen corpus is generated explicitly by
`go run ./protocol/cmd/relay-directory-vectors`. `make spec-check` compares,
never updates it, and runs the independent Python reproducer.

## Long poll and description

A credentialed listing GET may carry one canonical decimal `TOS-Relay-Wait`
header from 1 through 25. The server allows one waiting request per mailbox and
a default 512 waiting requests relay-wide. It registers with the mailbox snapshot
under the store lock, wakes after a committed deposit, and rechecks credential
scope, local revocations and finalized delegation before returning. Timeout
returns the same ordinary listing; there is no separate response format or
pagination. Both listing forms alone permit 81,920 response bytes. Other response
limits are unchanged. The wait endpoint and client have a 40-second total budget.

`GET /v2/relay` reports the V2 schema, envelope size and TTL, mailbox and stranger
quotas, `max_wait_seconds: 25`, and the boolean `directory`. The client requires
all nine fields, rejects unknown or duplicate fields, and validates their bounds.

## Validation and scope

Unit and race tests cover two independent relays observing finalized withdrawal,
contact-root and appended-child revocation with retained envelopes, cache outage
refusal, directory saturation and persistence, controlled-clock wait expiry and
cancellation, and process-exit cuts before and after control-file rename. Those
cuts exercise restart consistency; they are not power-loss simulation.
`make relay-v2-directory-mutants` removes named guards in isolated Go overlays;
a compile failure is not accepted as a killed control.

These tests do not claim live A3/A7 acceptance. The phase-1 live evidence gate
still needs chain transaction hashes, both relays' read/refusal times and commits,
and a contact-revocation transcript at every relay in the published hint.
