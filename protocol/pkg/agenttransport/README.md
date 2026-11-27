# Transport delegations

This package implements Messenger Transport V2 section 5.1 only: the 167-byte
fixed binary delegation, its SHA-256 digest, finalized authorization and the
bounded revocation cache. Credentials, request proofs, hints and sessions are
later surfaces. A delegation has no off-chain signature of its own.

## Authority and deployment gate

`NewVerifier` refuses `Production`, the zero mode and every unknown mode.
Every mode is first bound to a code-pinned allowlist of approved test-network
identities. The exact tuple is the canonical `tos:global-id:N` identifier and
both bare zero-state hashes. A mode string, a known global id with another
genesis, or a different global id with known hashes cannot enroll a network.
Both constructors refuse an unlisted identity with `ErrUnapprovedNetwork`
before mode selection or any resolver read. The allowlist is constants in
`networks.go`, never runtime configuration.

The reviewed pins are:

| Network | Global id | Zero-state root | Zero-state file |
| --- | --- | --- | --- |
| Local PQ network | 3 | `65735247a371030abe811aeac0afe357301ce90e161450d26f88b4beb5b4c366` | `c3860fe196a2a1b5e4e74a9cf9448624a353ce68a8c4c5f6413347586d688769` |
| Public testnet epoch 8 | 2 | `7095f2295d9c0a2310e7530f3d4f7ac03970133a19d96167ac6aa87d03ff908c` | `bfc773cfbb122917353c93f72494035d4986b7e4ae0dc8b7be39347f7a546186` |

The local pins were checked against the operator's `network.json` and both
local global-config copies; the public pins against the published epoch-8
`genesis.json` (its hexadecimal and base64 zero-state representations agree).
These are enrollment/provenance checks, not live transport acceptance. A new
genesis requires a reviewed source change; it is refused until then. Production
global id 1 is not enrolled even if a test mode is selected.

The deployed registry has no authorization or admission epochs. This PR does
not add fields to registry state, infer epochs from sequence/generation, or
claim production readiness.

`TestNetworkLegacyEpochZero` explicitly enables the deployed epoch-less
reader through `NewLegacyTestNetworkResolver` (the `ResolveState` interface
provided by the protocol chain resolver). It checks the original network tuple
before normalizing native `sha256:`-prefixed genesis hashes to transport hashes.
Delegations must encode zero;
no current/admission epoch metadata may be supplied. Policy A → B → A and an
update with identical policy bytes remain known revocation gaps in this mode.
Do not use it for production networks.

`TestNetworkEpochAware` exercises all epoch rules with synthetic finalized
snapshots. It is not an adapter for an existing registry. A later registry
change must expose an atomic finalized snapshot with the current epoch and
each live digest's admission epoch, at `EpochCheckpoint` equal to the outer
state's finalized checkpoint, before production can be enabled. Neither epoch
is guessed when absent. A future-encoded digest admitted early fails both
before and after that future epoch begins unless deliberately admitted again
by the new authority. The registry must also enforce withdrawal permanence
and clear its live and withdrawn sets at each epoch bump; those changes are
outside this package.

`Snapshot` is one immutable result, including the outer native state. The
resolver must authenticate its proof and finality, honor its context deadline,
and bound its response. `CheckState`, shared with Messaging Endpoint identity,
checks the network tuple, accepted registry code, deterministic account,
finalized checkpoint, typed state and Agent identity/liveness again. Policy
hashes are rebuilt as TVM policy-cell representation hashes, not JSON hashes.
The verifier does not turn an unverified RPC response into finalized evidence.

Only `ErrUnavailable` permits the stale-pass fallback. An absent Agent is a
successful read with nil state; invalid proofs, contradictions and all other
errors fail closed and erase the old pass. Adapters must not classify them as
unavailability. Registry epochs and membership must come from the same
checkpoint as the policy.

## Codec, issuance and cache

`Delegation.Encode` is a structural serializer. It can encode arbitrary epochs
for conformance tests; use `Verifier.BuildDelegation` before issuance to bind
the bytes to the current finalized policy and epoch, then commit their digest
with the existing authorized native action. The builder does not commit or
send anything. Consumers use `VerifyDelegation`, not decoding as authorization.
Keys must be canonical non-small-order Edwards points. Purposes are the
nonempty subset of relay, hints and direct; a verification request names one
purpose, never a composite or unknown purpose.

Time and purpose are checked on every use and again after a read. A successful
read is reused for strictly less than 300 seconds. At 300 it is refreshed;
only unavailability permits reuse until strictly less than 600 seconds, and
failed reads never reset that age. Successful revoking reads are refused
immediately. Read start time anchors the cache age conservatively. Clock
rollback discards cached passes and refuses until the prior time is reached.
The default clock is the real monotonic-capable system clock.

Each verifier holds at most 1,024 passing digests (a configurable smaller bound
is allowed), about 56 KiB of key/timestamp payload before map overhead. When
full, new successful reads pass without being cached; no entry is evicted in
a way that could extend its authority. Reads are serialized, context-bounded
(default 5 seconds, maximum 30), and no background refresh worker is created.
Cancellation is not converted to authority.

## Reproduction and controls

Generate the corpus deliberately with:

```
GOWORK=off go run ./protocol/cmd/agenttransport-vectors > spec/test-vectors/agent-transport-v1.json
```

Normal tests only read the frozen corpus; a mismatch never rewrites it.
`make spec-check` runs `python3 -I spec/scripts/reproduce-agent-transport-v1.py`:
an independent stdlib implementation of the wire, digest and Edwards key
validation/derivation. All four positive vectors carry their test-only seeds
and complete codec inputs. Fifteen negative mutations cover domain, lengths,
key encodings, purpose bits and lifetime limits.

`make agenttransport-mutants` uses Go overlays, never mutating the checkout.
A removed check counts red only if its named test fails; compiler errors and
missing anchors are script failures. Run Go and make in worktrees with `GOWORK=off`.

No contract change, registry deployment or live-network acceptance is claimed.

## Reachability and direct control objects

Phase 1 item 4 adds `Hint`, `HintRecord`, `Hello` and `Receipt` binary codecs,
signing helpers and verifiers. Domain prefixes include the zero byte; all
integers are big endian. Decoders reject unknown kinds/roles/outcomes, malformed
embedded delegations, lengths, ordering, duplicates, trailing bytes and bounds.
The hint relay list is **priority order**, not sorted. Key cards keep their own
canonical relay-list rule. The same existing `agentpacketseal.CheckRelayURL`
validator is reused. No credential code or new production network mode is needed.

`Verifier.VerifyHint` checks the full record/digests, finalized hints delegation,
signature, final clock (future skew <=300 s, now strictly before expiry), IPv4
policy, and each card packet's strict JSON and matching `sender_agent_id`. This
is the relay boundary, **not card authentication**. `VerifyConsumerHint` additionally
requires an `ObjectVerifier` callback for every embedded object. It must run
`VerifyKeyCard` or `CheckPeer` as appropriate and return the authenticated Agent,
which must equal the hint Agent. This keeps Messenger dependencies outside
protocol/. The callback must honor its context; the result is rechecked after
callbacks, including cancellation, time and delegation validity.

`BuildHintRecord` has explicit `PublishOptions`. The default publishes relays and
at most the supplied public rail card: chat card/evidence need `PublicContact`,
and direct entries need `DirectEnabled`. Consent is local owner policy, not a
wire flag an attacker can set. A consumer does not infer missing owner consent
from a received signed hint; disclosure is controlled at publication. Direct
session admission, contact relationships and all the other section 8.1 gates
remain the carrier's responsibilities before probing.

Direct addresses default to public unicast IPv4, excluding private, loopback,
link-local, shared-address, documentation, benchmark and reserved ranges. The
explicit `HintPolicy.AllowPrivateIPv4` exception admits only private ranges,
not other reserved addresses, and is recorded in `VerifiedHint.PrivateIPv4Allowed`.
The existing verifier constructor still admits only exact code-pinned test
networks; production configuration refuses. No production one-relay mode is
introduced: production verification is not available until registry epochs ship.

A hello is **402 bytes**, including the 167-byte epoch-bearing delegation, and
fits in one 8,192-byte ADNL query. `VerifyHello` requires authenticated channel
IDs, the expected role/Agent, the responder's matching initiator challenge,
current direct delegation, signature and ±120 s timestamp window (checked again
after a finalized read). Contact admission is required on both sides; the
callback must be a nonblocking local lane-policy lookup. Initiator hellos carry
an all-zero responder nonce. Callers create fresh random challenges; this codec
cannot prove randomness. The responder may learn the Agent from an initiator's
hello, but it must be an admitted contact. An initiator must pin the intended
Agent from the verified hint. The actual probe/hello exchange needs a caller
context bounded to 5 s; this PR opens no network path.

`VerifyReceipt` uses the verified peer delegation with direct purpose and pins
the expected recipient Agent and exact envelope ID. All three outcomes are
signed. The spec defines no separate receipt timestamp window; replay of a
receipt for the same immutable envelope describes the same carrier outcome.
The recipient must sign stored/duplicate **only after durable inbox write**;
that storage ordering belongs to the future carrier, not this codec. A receipt
never authenticates a packet or creates an execution/settlement fact.

`CompareHints` is for already verified hints of **the same delegation** only:
issued time, then greater SHA-256 of complete hint bytes. Independent lane
processes are never merged into one timestamp race. Revoked hints are void,
regardless of their timestamps; no directory storage or newest-record cache is
implemented here.

Generate deliberately with:

```
GOWORK=off go run ./protocol/cmd/agenttransport-reachability-vectors > spec/test-vectors/agent-transport-reachability-v1.json
```

`make spec-check` compares that output and runs the stdlib-only independent
Python wire/signature reproducer. It derives test keys and each pure signature
from the public fixture seed, using a cofactorless verification equation.
The 13 positive and 57 negative objects include reduced/public-contact/maximal
hints, a private test configuration, all hello roles and receipt outcomes,
structural and re-signed semantic refusals. Embedded card/evidence bytes are
relay-level structural fixtures, **not authenticated ML-DSA cards or Messenger
bootstrap evidence**. Chain revocation and consumer callbacks are tested
separately against the finalized verifier's synthetic pinned-network snapshots.

`make agenttransport-mutants` also runs the separate reachability overlays;
`make agenttransport-reachability-mutants` selects only this surface. Missing
anchors, compiler errors and survivors fail the control run. Normal tests never
regenerate frozen files. No live transport or first-contact acceptance is claimed.
