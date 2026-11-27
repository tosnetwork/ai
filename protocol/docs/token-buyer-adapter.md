# Token buyer adapter and gateway

The buyer daemon, its terminal confirmer and the MCP server run from this
repository. The token path does not depend on another buyer application. Use
`tos-service-buyer agent`, `tos-service-buyer confirm` and
`tos-service-buyer-mcp` with the same private socket arrangement as the native
adapter. Keys remain in the pinned custody helper's vault; neither a gateway
nor the MCP client receives them.

## Owner policy

One agent configuration is token-only or native-only, never both. Run separate
configurations, private state directories and sockets to use both rails. A
token-only configuration may pin multiple independent token assets.

Use the token actor's pinned release hash as `actor_code_hash`. Add an optional
`token_assets` array to the owner-private agent configuration. Each entry has:

- `master` (raw workchain-0 address), `bridge` (raw masterchain address),
  `bridge_config_param` (79, 81, 82 or 83), `decimals`;
- `source_chain_id`, `source_token` (40 lowercase hex digits);
- `bridge_code_hash`, `minter_code_hash`, `wallet_code_hash`, each a
  `tvm-cell-sha256:` digest;
- `max_per_call_atomic` and `max_window_atomic`, canonical positive decimal
  strings below 2^120, with the window at least the per-call cap.

Omitting this array permits no token purchases. Duplicate masters are refused.
Each asset is keyed by master, wallet code hash and decimals. Caps and spend
records are separate; two assets are never converted, netted or added together.
The existing native budget independently covers the wallet message value.
A native-only daemon remains compatible with its existing configuration and
journal records. A token daemon uses versioned token call records; an older
binary must not operate its journal.

A quote is an offer, not permission to pay. Search, local quote and gateway
quote revalidate finalized capability, actor policy, recognized asset and
`accepting_tokens` in one checkpoint. Prepare repeats those checks and obtains
the exact unsigned token funding transfer at that checkpoint. Call repeats
admission before custody and refuses changed funding, suspended or unpinned
assets and actors no longer accepting tokens. It never silently raises a
confirmed amount.

The preview and terminal confirmation distinguish token principal from native
fees. They show the pinned asset identity, decimal rendering alongside atomic
units, exact transfer and received amount, token wallet, actor, attached native
value, forwarded native amount and minimum forward. The supported pinned
token-wallet code transfers principal without a token transfer fee; the received
amount equals the transfer amount. This is not support for arbitrary
fee-charging token wallets. Source-side transfer fees do not change that claim.

The confirmation code binds the exact funding document as well as the quote,
request and archive. The non-broadcasting build-only preflight runs before the
journal enters `sending`; a preflight refusal leaves the call prepared and
retryable, or leaves no lifecycle attempt. The broadcast is still journaled
before submission. An ambiguous submission remains reserved and is not sent
again. Finalized notification/admission and authenticated payout outcomes decide
its status; a sequence number alone is not settlement. A finalized funding
refusal with no payout is terminal `funding_surplus`: no request was admitted
and no buyer return is owed. Its spent principal remains in the asset budget
until the normal window expires. Refused payouts remain
returned entries until claimed. Underfunded/no-forward transfers can become
provider surplus, so the adapter refuses to build them. The provider is
responsible for keeping its token wallet funded for storage.

## Gateway boundary

A gateway can carry a token Quote Proposal with fields 18 and 19. It cannot add
an asset, choose a price or convert an amount. Those fields must reproduce the
canonical manifest and finalized actor policy. Native proposals containing either
token field are refused. A gateway's owner-profile pins only constrain its quote
source; they confer no payment authority. Buyers apply their independent pins
and caps. Local quotes need no gateway.

## Evidence and limits

Token evidence uses the existing token evidence schema and independent verifier.
The export links the payer, sender token wallet and actor token wallet by exact
message hashes, then verifies the admitted call and subsequent outcome at one
finalized checkpoint before writing evidence. No key, confirmation nonce,
endpoint credential or source archive is exported. Unit fixtures and refusal
controls are not public-network Gate D evidence: an independent provider and
verifier still have to execute that acceptance run.

See [the verification record](token-buyer-verification.md) for acceptance tests,
commands and the remaining network acceptance gate.

Token calls and lifecycle sends use an explicit `--valid-until`, chosen once as
the post-preflight send time plus the fixed two-minute `TokenMessageLifetime`.
Calls persist it as `token_valid_until_unix`; lifecycle attempts store the same
value in `valid_until_unix` and `valid_until_bound_unix`. The sender passes that
exact value, and its process deadline cannot outlive it. Build-only preflight
also supplies an explicit expiry, so an older helper refuses before `sending`.

A lifecycle retry is allowed after a finalized checkpoint is strictly past the
recorded explicit expiry with the wallet seqno unchanged, proving the attempt
never executed. An old default-derived bound alone is insufficient: legacy
attempts without an explicit expiry stay fail-closed unless execution is proven.
Token records use v2 only. Pre-launch v1 records are refused with an explicit
unsupported-version message; they are never upgraded or discarded automatically.
Preserve an old record and reconcile any pending transfer before creating a new
journal. Native preflight also consumes v2 and records its echoed expiry as
`preflight_valid_until_unix`. That is build-only metadata, never the expiry of a
separately signed broadcast. Native lifecycle sends record the actual signed
expiry from custody and use it for finalized expiry reconciliation. If that
report is lost, no assumed default lifetime authorizes a retry.

The helper must implement `wallet send --valid-until` and return
`tosctl.wallet-prepared-send.v2` from `--build-only`, with a numeric `valid_until`
equal to the requested expiry. Missing, null, mismatched or out-of-range values,
v1 output and unknown fields are refused before `sending`. This confirms the
effective expiry reported by the helper, rather than trusting flag acceptance.
Companion CLI support is a deployment prerequisite; local tests exercise the
concrete sender with a recording runner, not a live submission. The adapter
never retries without the option or falls back to a default lifetime.

## Two independently pinned assets

A token configuration accepts at most two pins, matching the resolver's policy
bound. This is separate from the 16-entry governance dictionary limit. To use
test USDC and test USDT locally, install the two governance-derived pins in
`token_assets`, each with its own `master`, source token and atomic budget. Both
use six decimals and bridge slot 81, and may share all three audited code
hashes and the bridge address. Sharing code or decimals never joins masters.
The clients contain no default production USDT master or recognition record:
production pins remain absent until governance and its release checks complete.

Obtain the local deployment identities and exact ConfigParam 84 value from the
operations governance receipt. Do not promote the synthetic unit-test pins to a
deployment or derive authority from a ticker. Before a purchase, the reader
checks the selected entry, bridge-stored codes, derived master and deployed
minter at one finalized checkpoint. An active USDC entry can still be used when
the USDT entry is suspended; a shared bridge failure can affect both.

Principal reservations and MCP summaries have one bucket for each complete
configured asset key (master, wallet-code hash, decimals). The daemon's fixed
network and independently pinned minter release supply the remaining identity
context. Never add these buckets together or convert between them. Native fee
reservations are separate and may be shared across the two assets. Existing
liabilities continue to resolve against their immutable quote/actor identity
when recognition is suspended; suspension only blocks new admission.

The two-asset tests exercise majority reads, independent budgets, separate
reservation aggregates and MCP rendering. Foreign-wallet notifications do not
become accepted token calls, even when the amount, decimals and payload match.
Contract execution and the second asset's live lifecycles are separate local
acceptance runs, not claims made by these client fixtures.

Reproduce the client isolation controls from the repository root, under the
host's prescribed thermal/build guard:

```sh
make token-assets-mutants TOKEN_ASSET_MUTANT_LOG_DIR="$EVIDENCE/token-assets-mutants"
```

Every selected test must pass unmutated and fail by its named assertion when
mutated. Missing tests, source patterns, compilation failures and panics do not
count as kills. The driver restores every source before proceeding.

## Finalized state and retained history

A fresh offer derives recognition, bridge-stored release codes, minter identity,
actor policy and wallet balances from account/config state at one strict-majority
finalized checkpoint. An idle bridge's last transaction need not remain in the
node's transaction archive for those state reads to succeed. The last-transaction
identifier in account state remains the anchor; a state read does not manufacture
or certify that transaction's execution.

Executed purchases, funding and settlement still require the exact relevant
transaction cells and outcome checks. Keep their archived evidence before node
pruning; unavailable execution history remains a refusal, never inferred success.
