# V2 relay storage foundation

The storage foundation is used by V2Server and the separate V2-only relay
command. See V2_HTTP.md for authentication, finalized reads, policy and clients.
The retired V1 API remains isolated for clients not yet moved; it is never a
V2 data source or fallback. Unit/integration evidence is not a live A4–A6
acceptance transcript.

## Ownership and bounds

Open a distinct absolute, owner-private directory with `OpenV2Store`. Never
point it at V1 data. The format and Go store type are disjoint; an exclusive
OS lock prevents concurrent writers and is released by process exit.
Windows is refused because this backend requires the owner-private file checks.

Both configured global counts and bytes are split into fixed stranger/contact
reservations. Strangers get at most 25 percent; contacts get the rest. Neither
borrows the other reservation. Default stranger mailbox bounds are 32 entries
and 2 MiB, with hard maxima 64 and 4 MiB; a future owner policy may only lower
the operator's bounds. Per-address stranger limits are 8 per mailbox and 64
across the relay. IPv6 addresses share their /64; a /48 shares 256 entries.
Mailbox and per-client bounds inherited from V1 also apply.

A contact lane has at most 64 active entries and obeys the credential's smaller
count/byte/envelope caveats. Identity is derived only from a checked request whose
credential chain is reverified. Default lanes use block-0 issuer_chain.
Explicit lanes carry a distinct type tag; zero padding cannot alias a default
lane. An appended block may repeat a root explicit lane but cannot replace the
implicit default lane with a new explicit lane.

ACK atomically replaces the envelope record with a tombstone. Until expiry,
that tombstone charges its original global class count and stranger address
counters; it no longer charges active mailbox/lane counts or payload bytes.
Deletion, restart and expiry reconstruct the same counters. Mailbox listings
walk only their bounded active index. Disk-backed indexes retain metadata,
not encrypted bodies; bodies are read with a fixed maximum on fetch.

## Replay lifecycle

The caller must run `store.Replay().Run(ctx, clock, onFailure)` for the service
lifetime. This records a high-water mark at startup and every 10 seconds.
The mark is at least the previous mark and relay time plus 140 seconds.
A successful file sync, rename and parent-directory sync precede publication
to request admission. An uncertain write retains its candidate, preventing a
later clock rollback from lowering a mark that might already be on disk.

The replay table is bounded (default 262144, 64 per issuer_chain); it never
evicts a live proof to make space. Nonce identity remains (credential_id, nonce).
The table's existing 120-second expiry and floor rules are reused. On reopen,
the recorded high-water mark becomes floor F and only issued_at >= F+1 can
enter. An aligned client waits about 141 seconds; a clock 120 seconds behind
can wait about 261 seconds. Compute Retry-After using the proof's issued_at,
not the relay clock. HTTP status mapping is the follow-on change.

Missing, corrupt, truncated or unknown-version replay records in a used store
refuse startup, even if there are no live envelopes. Startup never recreates
missing used-store data directories. An interrupted first initialization can
also refuse; it must not be mistaken for an unused store once files exist.

## Disk transaction and recovery rules

Each canonical JSON record has a domain-separated SHA-256 checksum. This detects
accidental corruption, not malicious modification by the directory's owner.
Write a private temporary record, sync it, atomically rename it, and sync the
destination directory before changing the in-memory index or returning success.
Ordinary failed writes remove their temporary files; process-crash leftovers
are checked and removed at startup. Uncertain envelope writes poison the open
store: refuse further reads/writes until it is reopened and reconciled.

A service restart is the normal response to an I/O failure; never erase REPLAY,
FORMAT or a record to make startup pass. Preserve the failed directory for
investigation. A restore of a whole old snapshot cannot be detected by a
checksum: monotonic external snapshot management remains an operator obligation.

For exceptional replay-record recovery, stop the service, preserve evidence,
and use the explicit RecoveryFloor option with an audit callback. Supply a floor
at least current relay time + 140 and no lower than any valid saved mark.
If an earlier higher mark is known externally, preserve it too. This action
invalidates old proofs and creates an F+1 delay; it does not recover erased
envelopes. The callback must retain the public floor audit without logging
credentials, lane keys, mailbox identifiers or proof nonces. No recovery occurs
automatically and no production recovery command is enabled by this foundation.

The process cannot guarantee filesystem durability on storage that lies about
fsync, or detect removal/rollback of the entire store by its trusted owner.
Crash tests cover process exits before rename and after rename/before directory
sync, not a physical power-cut simulation.

## Validation

`GOWORK=off go test -race ./protocol/pkg/agentpacketrelay` covers V1 and V2.
`make relay-v2-store-mutants` uses Go overlays and unique anchors; every mutant
must build and fail its named test. A timeout or compilation failure does not
count as a killed mutant. The record decoder also has a bounded fuzz target,
`FuzzV2RecordDecoder`.
