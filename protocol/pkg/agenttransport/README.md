# Transport delegations

This package implements Messenger Transport V2 sections 5.1 to 5.4: the
167-byte fixed binary delegation, its SHA-256 digest, finalized authorization
and the bounded revocation cache; relay credentials, their closed caveat set
and request proofs; and the in-memory replay admission logic. Hints and direct
sessions are later surfaces. A delegation has no off-chain signature of its
own.

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

## Credentials and request proofs

`DecodeCredential` is strict: domain, an embedded delegation that decodes,
1 to 4 blocks whose `block_length` matches their content exactly, 1 to 8
caveats per block in strictly ascending type, canonical non-small-order next
keys, the closed caveat set with its value rules, block 0 carrying
`not_before`, `not_after` and `operations` within the delegation's
`max_credential_seconds`, at most 2,048 bytes and no trailing byte. Decoding
does not verify signatures; `VerifyChain` does, block 0 under the transport
key and block i under block i-1's next key, each preimage covering the chain
value of every earlier signature.

`CheckScope` and `CheckDeposit` evaluate every caveat of every block on its
own. Nothing merges blocks, so a later block can only add bounds (section
6.4). Two different lane values make a credential unusable
(`credential_scope`); the builders refuse to produce one. A contact lane holds
at most 64 envelopes whatever its caveats say. `IssueCredential` and
`AppendCredentialBlock` sort the caveats, sign, and decode their own output,
so issuance has no separate rule set. Owner and contact lifetimes of the
profile table are issuer policy and are not enforced here.

`CheckRequest` runs the stateless request checks of section 6.1 in order:
header and credential decode, Agent match, chain, caveats, proof window and
holder signature. Every refusal wraps exactly one of `ErrCredentialInvalid`
or `ErrCredentialScope`. The relay then claims the nonce, checks its mailbox
revocation set against `ChainValues`, and calls `VerifyDelegation` with the
relay purpose.

`ReplayTable` is the admission logic of the replay table: claim once per
`(credential_id, nonce)`, at most the configured entries and 64 per
credential, refusing rather than evicting; entries drop only once more than
120 seconds old, raising the floor; proofs at or below the floor
(`ErrProofFloor`) or at or above the last recorded high-water mark
(`ErrProofMark`) are refused. `NextMark` never decreases, and
`RestoreReplayTable` starts the floor at the recorded mark. Durable storage of
the mark (one checksummed record, atomic replacement with file and directory
sync, refusal to start on a missing or corrupt record of a used store, the
operator override) belongs to the relay and is not implemented here.

## Reproduction and controls

Generate the corpus deliberately with:

```
GOWORK=off go run ./protocol/cmd/agenttransport-vectors > spec/test-vectors/agent-transport-v1.json
```

and the credential corpus with:

```
GOWORK=off go run ./protocol/cmd/agenttransport-vectors -corpus credential > spec/test-vectors/agent-transport-credential-v1.json
```

Normal tests only read the frozen corpora; a mismatch never rewrites them.
`make spec-check` also runs `python3 -I
spec/scripts/reproduce-agent-transport-credential-v1.py`, which re-derives
every key from its seed, re-signs every block and proof with its own RFC 8032
Ed25519, rebuilds every credential, and re-evaluates every scope, deposit,
proof and negative case with its own decoder.

`TestNarrowingProperty` (seed printed; `AGENTTRANSPORT_NARROWING_SEED`
replays another) compares every prefix of 1,500 random chains against an
independent per-block oracle, requires that no appended block ever admits a
request its prefix refused, and requires the generator to reach cases where a
last-value merge of blocks would widen. `FuzzNarrowing` and
`FuzzDecodeCredential` run under `make fuzz`.
`make spec-check` runs `python3 -I spec/scripts/reproduce-agent-transport-v1.py`:
an independent stdlib implementation of the wire, digest and Edwards key
validation/derivation. All four positive vectors carry their test-only seeds
and complete codec inputs. Fifteen negative mutations cover domain, lengths,
key encodings, purpose bits and lifetime limits.

`make agenttransport-mutants` uses Go overlays, never mutating the checkout.
A removed check counts red only if its named test fails; compiler errors and
missing anchors are script failures. Run this and all Go commands under the
workspace thermal guard with `GOFLAGS=-p=2`.

No contract change, registry deployment or live-network acceptance is claimed.
