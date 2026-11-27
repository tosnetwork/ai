# Issuer observations and received amounts

`Policy` is owner-controlled input: exact source chain id, token, bridge address,
issuer interface, expected deployed-runtime SHA-256 and RPC URL. A quote, gateway
or MCP caller cannot supply or replace it. `Reader.Read` checks blacklist for its
receiver, global pause and, for the legacy interface, deprecation. The buyer uses
the pinned bridge as receiver, stopping imports into a frozen bridge.

Reads select `finalized` and pin all code/getter calls to its hash using
`requireCanonical`. The number/hash is checked again, and freshness is checked
both before and after: at most 1,800 seconds old, no more than 30 seconds future.
The 45-second total deadline covers all requests, each response is bounded to
4 MiB, and the method set is read-only. Redirects, credentials/query strings in
URLs, malformed booleans, wrong chain/code, RPC errors and missing data refuse.
This is endpoint-authenticated observation, not a proof of the source chain.

`Snapshot.Received` uses atomic integer math, including the issuer fee cap. The
buyer SDK's source preview checks the minted delta against the specific asset's
remaining/per-call budget, and exposes nominal, fee, minted and budget amounts.
No source lock executes and no budget is reserved by this preview. Already-minted
TOS tokens transfer exactly: purchase confirmation and journals retain the exact
actor price and do not subtract a source fee again. A source import whose net
amount differs from the actor's price is not sufficient exact funding by itself.
Fees/restrictions can change after the observation; the actual lock credits the
actual received delta.

The custody config's optional `token_assets[].issuer` has the Policy fields
(`rpc_url`, `chain_id`, `token`, `bridge`, `code_sha256`, `profile`). Its token and
chain must match the asset's existing source pins. `profile` is `standard` or
`legacy_usdt`. Without this configuration the new preview refuses, while existing
purchases from already-minted tokens retain their normal TOS checks. RPC routing
is omitted from public evidence exports, including credential-bearing URL paths.

The MCP tool is `tos_buyer_preview_token_lock`, with `quote_id` and
`nominal_atomic`; the local agent method is `token_lock_preview`. It takes no
endpoint or asset override. It prints no RPC response bodies and has no signer.

Redemption is a separate unsigned tool in tos-ops:
`testnet/scripts/prepare-token-redemption.py`, using the shared T14b RPC pattern.
It checks both receiver and bridge sender, and warns that a recorded burn is
final. Generic token-wallet burn helpers are not bridge redemption entry points.
There was no bridge redemption command in tosctl/ai, and no inherited upstream
implementation is changed by these TOS-specific issuer/bridge adapters.

Verification: unit/race tests cover all refusals and fee on/off/cap math;
`make token-issuer-mutants` uses overlays and requires each removed check to fail
its named test. The independent anvil lane in tos-ops `anvil_t19_ai.py` runs the
production Go reader with `protocol/tests/token-issuer-fixture`. It requires the
built probe explicitly and never skips a missing dependency. This local evidence
does not deploy a production asset or enable T12 by itself.
