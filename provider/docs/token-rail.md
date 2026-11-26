# Token provider management

The provider program and its agent can manage already-deployed token actors,
without an external host application. Each actor has one pinned master and one
operator-chosen asset label. Token prices, revenue and liability bounds are
canonical decimal strings in atomic units; TOS amounts are nanoTOS. Labels are
local monitor identifiers, never authority to replace an asset pin.

Use the normal owner-private rail configuration and agent socket described in
[the provider guide](../README.md). Add a `token` object to the rail configuration:

- `pins`: independent `toschain.TokenAssetPin` records, including the master,
  wallet/minter/bridge code hashes, bridge address and parameter, source chain
  and token, and decimals. At most two assets are configured.
- `actors`: at most 64 records. Each names `address`, `code_hash`, `asset_id`,
  `master`, `capability_id`, `version`, and an absolute `manifest_file`.
- Each actor also requires `min_price_atomic`, `max_price_atomic`,
  `max_liability_atomic`, `max_storage_fee_nanotos`,
  `max_cleanup_bounty_nanotos`, `min_actor_free_nanotos`, and
  `min_wallet_nanotos`. Every bound is positive and below `2^120`.
- `monitor_report`: the absolute path to the trusted settlement monitor's
  owner-private `report.json`. `max_report_age_seconds` defaults to 300 and
  cannot exceed 3600.

Keep this configuration and action input files private. The monitor's
`tos-settlement-report/1` report must include its checkpoint and
`provider_pause_assets`; missing, stale, future or malformed reports refuse
admission and resume. This is a trusted local monitoring input, not a proof.
The asset labels must match the monitor configuration exactly. One master cannot
have multiple labels. Unconfigured labels never authorize changes to an actor.

## Commands and human confirmation

Build the programs with `go build ./provider/cmd/...`. Read-only inspection:

```sh
tos-service-provider token --rail-config "$RAIL_CONFIG" --inspect status --actor "$ACTOR"
tos-service-provider token --rail-config "$RAIL_CONFIG" --inspect offer --actor "$ACTOR"
tos-service-provider token --rail-config "$RAIL_CONFIG" --inspect export-offer --actor "$ACTOR"
```

`offer` validates the published registry/manifest binding, current recognition,
operator bounds, ownership and both floors at one finalized checkpoint.
`export-offer` emits the existing public offer-file format. The library's
`BuildTokenManifest` uses the shared canonical protocol encoder. Deployment,
registry publication and custody initialization remain explicit operator work;
these commands do not silently deploy or register an actor.

An owner-private action input, for example a withdrawal, is:

```json
{
  "actor": "0:<64 lowercase hexadecimal digits>",
  "operation": "withdraw-revenue",
  "token_amount": "1000000",
  "tos_amount_nanotos": "100000000",
  "idempotency_key": "withdrawal-operation-0001"
}
```

Replace the illustrative address before use. Omit a revenue amount to leave it
untouched, or use `all_tokens` / `all_tos` instead of the respective amount.
Preview, review the exact amounts and envelope, then explicitly confirm its digest:

```sh
tos-service-provider token --rail-config "$RAIL_CONFIG" --input "$ACTION_INPUT"
tos-service-provider token --rail-config "$RAIL_CONFIG" --input "$ACTION_INPUT" \
  --yes --confirmed-digest "$REVIEWED_DIGEST"
```

Other operations are `recover-surplus` (`token_amount`), `recheck-payout` and
`abandon-payout` (`id`), `update-policy` (`policy`), `pause` and `resume`.
Policy fields are `price_atomic`, `storage_fee_nanotos`,
`cleanup_bounty_nanotos`, `max_liability_atomic`, `response_sla_seconds` and
`refund_claim_window_seconds`. Updates preserve all unspecified on-chain policy
fields. The shared protocol builder enforces the reference sender, payout kind,
amount, cap, sequence and funding prechecks; age warnings remain warnings as in
the reference CLI.

The MCP tools are `tos_provider_token_preview`,
`tos_provider_token_offer_describe` and `tos_provider_token_status`.
Payout IDs on the socket are decimal **strings**, so a client cannot truncate a
64-bit ID. A preview is not permission to sign: the existing custody-side
`confirm` flow must approve it. A changed preview expires. Direct `pause` is an
operator command; monitoring pauses are automatic authority reductions.

## Recovery and safeguards

A token action is journaled under the same setup lock as other custody changes,
before signing. Keep the same input and idempotency key after interruption:
repeating the command observes the original finalized transaction and payout;
it never blindly signs or sends again. Agent `actions` refreshes unresolved
token records. The payout is `paying` until a matching outcome, `returned`,
`delivered`, `failed` or `abandoned` is proven. Unavailable or incomplete history
keeps it unresolved. There is no automatic expiry-based resend.

An unresolved action blocks further independent actions for that actor;
recheck, abandon and emergency pause remain available subject to protocol
prechecks. Do not edit or delete an unresolved journal to bypass this rule. The journal
refuses new actions above 4096 records; archive only resolved records under
operator custody.
Token revenue and TOS revenue remain separate. The wallet balance alone is not
compared with attributed principal: payouts in transit are part of the token
accounting invariant.

Offer/status/preflight reads use shared protocol sessions. Admission is held
below either the actor's locked backing plus operating reserve plus configured
free floor, or its token wallet's TOS floor. A restored floor removes only the
derived hold; it never removes an operator pause. TOS withdrawals cannot breach
the actor floor. Existing recovery actions remain available under a hold.

The agent polls the monitor once per configured service interval, including
when no native offer is configured. A freeze, pause or destroy hook signs the
owner's `update_policy(active=false)` for each configured actor of that asset.
The durable operation key coalesces repeated polls. Other assets are untouched;
cleared alarms never automatically re-enable an actor. Human-confirmed resume
requires current recognition, clear monitoring and both floors.

## Verification boundary

The token tests extend the adapter's confirmation, custody separation,
interruption, redaction, floor, offer and outcome cases using shared production
protocol builders and finalized-session fixtures. They do not claim a live
network acceptance run. The token paid-work execution loop and the full local
buyer/provider lifecycle and recorded release acceptance remain separate
integration gates; the existing native paid-work loop is not relabelled as a
token executor. Do not advertise this management path as a production token
service before those gates pass.
