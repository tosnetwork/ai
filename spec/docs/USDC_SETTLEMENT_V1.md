# USDC Settlement V1 (design)

**Scope: USDC and USDT.** The filename is kept, but since 2026-11-25 this
design covers two recognized assets, both bridged from Ethereum by the TOS
token bridge:

- USDC, first;
- USDT (Tether), second (owner decision, team memo STATUS 13.583, section 10).

The two differ only in configuration and in the risks of section 7.5. Every
mechanism below applies to each independently.

They do share one bridge. A failure of the bridge, or the exhaustion of its
shared windows, affects both assets (6.3, 7.5).

**Status:** design, 2026-11-24, amended 2026-11-25. The owner has taken the
decisions in section 10 (team memo STATUS 13.581 and 13.583). Nothing here is
normative until the normative documents named in section 9 are written.

**Correction, 2026-11-25.** The wallet side (T1) is implemented in
tosnetwork/tos#512 (head `0a3bdbe78`, approved, not yet merged). Section 4.3
now describes the wallet as built, and sections 4.4-4.6, 5.4 and 8 carry its
consequences for the actor (T3). Where the wallet and the earlier text of this
design differ, the wallet and its protocol section govern:
`crosschain/token-bridge/SETTLEMENT-PROTOCOL.md` section 20 at `0a3bdbe78`. No
other contract in this document is implemented, released or deployed.

**Owner decision it implements (2026-11-24, team memo STATUS 13.580).** AI
services on TOS settle in a stablecoin, and only in **USDC, not USDT**. The
source is the TOS token bridge (`crosschain/token-bridge` in tos), which brings
USDC from its home network. Issuance by Circle on TOS is a later target, not a
dependency. The `ai` repository may assume one or two officially recognized
stablecoin contract identities and proceed. This lifts D8 as a direction. D8
reads
([`SERVICE_ACTOR_SETTLEMENT_DESIGN.md`](SERVICE_ACTOR_SETTLEMENT_DESIGN.md):567-570):

> **D8 Settlement asset.** (a) native TOS for current-domain acceptance, and
> amend `PRODUCT_STRATEGY.md` §9 and `SETTLEMENT.md`; stablecoin pricing waits
> for a token integration that reports payout outcomes.

That condition stays. A production rail must learn the outcome of every token
payout. Section 4 states under exactly which bounds it does.

**Sources pinned.** Every tos reference is to tos main `db4503c02`. Prefixes:

| Prefix | File |
|---|---|
| `SA:N` | `crypto/smartcont/service-actor-code.fc` (byte-identical to the release commit `fc5e7723e`, [`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md):61-63) |
| `TW:N`, `TM:N`, `TB:N`, `TU:N`, `TC:N`, `OP:N` | `token-wallet.fc`, `token-minter.fc`, `token-bridge.fc`, `utils.fc`, `config.fc`, `op-codes.fc`, all under `crosschain/token-bridge/tvm/contracts/` |
| `BR:N`, `SP:N`, `SEC:N`, `BS:N` | `crosschain/token-bridge/README.md`, `SETTLEMENT-PROTOCOL.md`, `SECURITY.md`, `evm/contracts/Bridge.sol` |
| `TLB:N`, `CFG:N`, `GZ:N`, `STD:N` | `crypto/block/block.tlb`, `crypto/smartcont/config-code.fc`, `crypto/smartcont/gen-zerostate.fif`, `crypto/smartcont/stdlib.fc` |
| `GV:N`, `TX:N` | `doc/GlobalVersions.md`, `crypto/block/transaction.cpp` |
| `TT:N`, `TTS:N` | `crypto/smartcont/token-wallet.tol`, `crypto/smartcont/tol-stdlib/token.tol` |
| `RW:N`, `RSP:N`, `RST:N`, `RER:N`, `ROP:N`, `RSL:N` | **at tos `0a3bdbe78` (T1, tosnetwork/tos#512):** `token-wallet.fc`, `SETTLEMENT-PROTOCOL.md`, `settlement.fc`, `errors.fc`, `op-codes.fc`, `stdlib.fc` under `crosschain/token-bridge/` (contracts under `tvm/contracts/`) |
| `RT:N` | at tos `0a3bdbe78`: `tosctl/src/node-control/contracts/tests/token_bridge/reported.rs` |

tos-ops references are to tos-ops main `c5a11a9`. Relayer references are to
relayer main `95a2d91`. `ai` references are to this repository at `a25b7fa1`.

## 1. Goal and scope

V1 adds one settlement asset kind beside native TOS: a **recognized TOS-network
token**. At most two recognized assets exist in v1, and the owner has filled
both slots (section 10):

1. **USDC** (Circle), bridged from Ethereum, first.
2. **USDT** (Tether), bridged from Ethereum by the same token bridge into its
   own derived minter. It is the second ConfigParam 84 entry.

USDC goes end to end first, and USDT follows as configuration (section 8). A
Service Actor of the new token rail (section 5) fixes one of them at deploy.
It then:

- prices calls in that asset;
- holds the price in its own token wallet;
- pays every token payout through a transfer whose outcome comes back to it.

In scope:

- recognition (section 3);
- the payout-outcome protocol (section 4);
- the token rail (section 5);
- the `ai` changes (section 6);
- the bridge production path (section 7);
- the work plan (section 8).

Out of scope:

- shielded transfers;
- Energy;
- every asset other than USDC and USDT;
- network fees paid in a token;
- fee sponsorship for the pilot (section 10, Q4);
- x402 settlement ([`X402_ADAPTER_DECISION.md`](X402_ADAPTER_DECISION.md):10-25
  stays in force);
- any change to the native-TOS rail.

This design does not change the authority model:

- finalized TVM state is the only authority, and the gateway has none
  ([`SETTLEMENT.md`](SETTLEMENT.md):36-39, :68-69);
- only the buyer can claim a refund
  ([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md) section 7.4);
- the Receipt commits to the result, and the contract does not decode it (D9,
  [`SOFTWARE_WORK_RECEIPT_TVM_V1.md`](SOFTWARE_WORK_RECEIPT_TVM_V1.md):46-54).

## 2. Facts this design rests on

### 2.1 Why the retired escrow could not settle a token

When a recipient wallet refused a payout, the tokens bounced into the escrow's
own wallet "without telling the escrow". The escrow stayed `release_pending`
or `refund_pending`, and "any retry could pay twice"
([`STABLECOIN_ESCROW_TVM_V2.md`](STABLECOIN_ESCROW_TVM_V2.md):181-189). It
treated `excesses` as proof of nothing (:179). Production needed a token
wallet that "reports each payout's outcome to the escrow in an authenticated,
request-specific, replay-safe way" (:198-200).

### 2.2 The bridge token wallet (the wallet bridged USDC uses)

**Op codes.** `transfer 0xf8a7ea5`, `transfer_notification 0x7362d09c`,
`internal_transfer 0x178d4519`, `excesses 0xd53276db` (OP:3-6).

**Sending** (`send_tokens`):

- requires the owner as sender (TW:105) and enough balance (TW:106);
- forces the destination onto workchain 0 (TW:102; `params.fc`:10-14);
- sends one bounceable `internal_transfer` with the receiver's StateInit
  (TW:115-130), carrying `query_id, amount, from = w_owner, response_address,
  forward_tos_amount, forward_payload` (TW:121-128);
- sends in mode 64 without +16 (TW:139), and debits in the same transaction
  (TW:140-141);
- ignores `custom_payload` (TW:111);
- requires the attached value to exceed `forward_tos_amount + fwd_count *
  fwd_fee + 2 * wallet_gas_consumption + wallet_min_tos_for_storage`
  (TW:131-137). The last two terms come from the bridge ConfigParam (TW:696),
  not from network gas prices;
- throws on transfer if that ConfigParam is absent (TC:7-11).

**Receiving** (`receive_tokens`):

- accepts only a sender equal to `calculate_user_token_wallet_address(from,
  w_master, w_code)` (TW:153-154);
- sends `transfer_notification(query_id, amount, from, forward_payload)` to
  **the receiver's owner**, and only when `forward_tos_amount != 0`
  (TW:162-180). That send is non-bounceable, in mode 1, without +16 (TW:174,
  TW:180);
- sends `excesses`, which carries only `query_id`, with ignore-errors
  (TW:183-191).

The wallet's own comment says action-phase failures must not happen, "since
in that case there will be no bounce" (TW:145-146). The standalone TOS Token
sets +16 on its sends (TT:343).

**Mints.** A bridge mint credits the wallet through `on_credit` and sends
nothing to the owner (TW:294-326).

**Refusal.** `on_bounce` handles only a bounced `internal_transfer`. It adds the
amount back to the balance and does nothing else (TW:199-209). No message
reaches the sender's owner, on success or on refusal.

**Settlement scope.** The settlement protocol (version 5, SP:3) gives mints and
burns durable completion (SEC:99). Transfers between wallets are "outside
settlement" (SP:271-272), and their "bounce restore ... is unchanged"
(SP:685-687). The wallet accepts settlement ops 40-63 only from its minter,
except `advance` and `cancel_burn` (TW:647-659).

**Addresses.**

- Wallet StateInit is `0b00, code, data = (balance 0, owner, master,
  ^wallet_code, ^empty_wallet_settlement)`. The address is
  `0:cell_hash(StateInit)`, built as a canonical `addr_std` with no anycast
  (TU:21-38, TU:66-80).
- The minter stores the wallet code (TM:20).
- The minter address is derived from `(content = chain_id, token_address,
  decimals; wallet code; bridge address)` (TU:44-56; TB:112-120). The content
  layout is `chain_id:uint32 token_address:uint160 decimals:uint8`
  (TU:100-119).
- The bridge's own data embeds `b_minter_code` and `b_wallet_code` (TB:79-80,
  TB:96-100), so a wallet or minter code change also changes the bridge's
  StateInit and address.
- The EVM side pins the TOS bridge's account hash per generation (`tosBridge`,
  BS:38, BS:182-196).

**Getters and admin.**

- `get_wallet_address(owner)` (TM:1389-1392) and `get_wrapped_token_data`
  (TM:1395-1398) exist.
- `get_token_data` reports an `addr_none` admin (TM:1386).
- Neither the minter nor the wallet calls `set_code`.
- A plain top-up with an empty body is accepted (TW:627).

**Lifecycle.** A wallet whose storage debt exceeds the limits is frozen, then
deleted. A deleted wallet's balance is gone (SP:769-777, SP:792-794). Wallets
"rely on their reserve, which is topped up by every credit" (SP:819).

### 2.3 Transaction semantics the protocol depends on

**Action phase.** When an action fails in the action phase, the transaction's
state is not committed. A bounce is generated only if the failing action asked
for it with mode +16:

- `need_bounce_on_fail` is cleared per action and set only by +16 (TX:2709,
  TX:2736-2761, TX:3326-3328);
- +16 is enabled from global version 4 (TX:4993);
- without +16, a failed send rolls back the whole transaction and nothing
  returns.

**Gas.**

- An ordinary internal message buys gas only with its own value (TX:1637-1639).
- `SETGASLIMIT` sets the limit to the minimum of its argument and the gas that
  the account's balance can buy, and resets the credit. An argument of at least
  2^63-1 is `ACCEPT` (STD:253-257; `crypto/vm/tosops.cpp`:71-96).
- `gas_max` is bought with the account's whole balance (TX:1631). A
  `SETGASLIMIT` above what the message's own value buys therefore spends the
  **account's** TOS. Whoever sends a message that reaches such a call can make
  the account pay for gas beyond what the message brought.

**Rule for every contract in this design.** This applies to the wallet (T1)
and to the token actor (T3) alike:

> No `set_gas_limit` or `accept_message` may run before the sender is
> authenticated, or before the message itself pays for the raised gas
> (`msg_value >= get_compute_fee(limit)`).

A lowering call, one that does not exceed what the message buys, is always
allowed. Sections 4.3, 4.4 and 5 apply this rule handler by handler.
- `GETGASFEE`, `GETFORWARDFEE` and `GETORIGINALFWDFEE` give network prices to a
  contract (STD:279-297).

**Bounce.**

- A bounce is dropped when the message's remaining value cannot pay its
  forward fee (TX:4101-4105). A compute phase that used all of the message's
  gas can therefore end without a bounce.
- The action phase clears the `bounced` flag of every outbound message
  (TX:3435-3436), so a contract cannot forge a bounce.
- A bounced body carries 256 bits of the original body when
  `capBounceMsgBody` is set (TX:4990). The genesis sets it (GZ:190). Since
  global version 12 a sender may instead request the new bounce format
  (`extra_flags`, GV:221-242).

### 2.4 The standalone TOS Token

`token-wallet.tol` and `token-minter.tol` behave like the bridge wallet at
this boundary:

- the notification goes to the receiver's owner (TTS:270-292);
- `excesses` carries only `query_id` (TTS:295-304);
- the bounce handler restores the balance and tells no one (TT:403-419).

They differ in three ways:

- the wallet data has no settlement cell (TTS:90-134);
- sends set +16 (TT:300, TT:343);
- the minter has an admin who can mint, change the admin and change the content
  (`token-minter.tol`:212-214, :286-288, :301-303).

Bridged USDC does not use them.

### 2.5 Configuration and governance

**Bridge parameters.** ConfigParams 79, 81, 82 and 83 hold the bridge
parameters for Ethereum, BNB Smart Chain, Polygon and Tron (BR:69-78;
TLB:887-890). They carry no per-token data (TLB:878-885).

**Free numbers.** No TL-B entry exists for 26, 27, 38, 41, 42, 46, 49-70,
74-78, 80, or 84 and above (TLB:643-890).

**Voting.**

- Each round needs votes of more than 3/4 of validator weight (CFG:645).
- A proposal is adopted after `min_wins` won rounds (CFG:498): 2 for an
  ordinary parameter, 3 for a critical one (GZ:436-437).
- Each round runs under a different validator set, and votes are signed again
  after every rotation (tos-ops `testnet/scripts/testnet-governance.py`:38-40).
- A parameter listed in ConfigParam 10 must be proposed as critical
  (CFG:596-601).

**Critical at genesis.** -999, -1000, -1001, 0, 1, 3, 4, 5, 8, 9, 10, 12, 14,
15, 16, 17, 19, 32, 34 and 36 (GZ:414). The quantum-network variant adds 48
(GZ:419). The gas and forward prices (ConfigParams 21 and 25, TLB:746,
TLB:769) and the bridge slots are ordinary.

**Procedure.** tos-ops `testnet/CEREMONY.md` §8.2 (:768-813) is the procedure.
"With four equal validators every round needs all four votes" (:795-796).

### 2.6 Fees

Network fees are paid in TOS. The sponsorship profile
([`AGENT_GAS_SPONSORSHIP_AND_TRANSACTION_RELAY_V1.md`](AGENT_GAS_SPONSORSHIP_AND_TRANSACTION_RELAY_V1.md)):

- lets a Provider top up an agent account with native TOS, relay exact signed
  bytes, or both (:52-65, :117-121);
- adds no opcode, paymaster or bridge (:67-68);
- keeps the network fee in TOS (:2274-2285).

No paymaster exists in tos or `ai`. The team's stablecoin plan (team memo
`stablecoin-strategy/TOS-STABLECOIN-ADOPTION-PLAN-20261007.md`) requires capped
native-TOS pre-funding for sponsored token payments (:257). It leaves charging
the payer's fees in stablecoin to a separate design (:260).

### 2.7 Where `ai` is native-TOS only today

**Manifest.** Key 20 admits only `{0: "native-tos"}`
([`SOFTWARE_WORK_MANIFEST_V1.md`](SOFTWARE_WORK_MANIFEST_V1.md):79-84;
`protocol/pkg/nativecore/manifest.go`:69-86, :219-221).

**Proto.**

- `QuoteProposalV1` carries `price_nanotos` and `storage_fee_nanotos`
  (`spec/proto/tos/service/v1/native.proto`:364-368).
- `TOSAssetIdentityV1 { master, wallet_code_hash, decimals }` is defined but
  unused (`spec/proto/tos/service/v1/native.proto`:333-337;
  `protocol/api/tos/service/v1/native.proto`:139). Only the metrics profile
  refers to it
  ([`AGENT_ECONOMY_METRICS_V1.md`](AGENT_ECONOMY_METRICS_V1.md):182-184).

**Accepted Quote and Receipt.**

- The Accepted Quote says "The asset is native TOS and has no field"
  ([`ACCEPTED_QUOTE_TVM_V1.md`](ACCEPTED_QUOTE_TVM_V1.md):67).
- The Receipt's `charged_atomic_amount` is in nanoTOS
  ([`SOFTWARE_WORK_RECEIPT_TVM_V1.md`](SOFTWARE_WORK_RECEIPT_TVM_V1.md):13-14).

**Contract.**

- The actor accepts native value only (SA:611-616).
- It ignores bounces (SA:558).
- It pays with non-bounceable, empty-body sends (SA:207-214).
- `claim_refund` loads `destination` without validating it (SA:751-754).

**Buyer tooling.**

- Budgets are in nanoTOS
  ([`MCP_BUYER_ADAPTER_V1.md`](MCP_BUYER_ADAPTER_V1.md):1008-1012), with an
  upper bound of 2^64-1 nanoTOS (:1019-1020).
- Amounts are "decimal nanoTOS strings" (:439-440).
- The buyer sender passes `--amount-nanotos`
  (`protocol/pkg/buyersdk/service_actor_sender.go`:152).

**Provider tooling.** Offer bounds and the wallet floor are in nanoTOS
([`MCP_PROVIDER_ADAPTER_V1.md`](MCP_PROVIDER_ADAPTER_V1.md):201-209, :294-299,
:420).

## 3. Recognition

### 3.1 ConfigParam 84 (decided: critical)

The recognized-asset list is a new configuration parameter. Validators vote it,
and it is read from finalized masterchain state:

```text
settlement_asset_origin$_ kind:uint8 bridge_address:bits256
  source_chain_id:uint32 source_token:bits160 = SettlementAssetOriginV1;

settlement_asset_v1#01 status:uint8 decimals:uint8
  minter_code_hash:bits256 wallet_code_hash:bits256
  max_liability_per_actor:Coins
  origin:^SettlementAssetOriginV1 = SettlementAssetV1;     -- <= 660 bits

settlement_assets_v1#01 assets:(HashmapE 256 SettlementAssetV1)
  = SettlementAssets;

_ SettlementAssets = ConfigParam 84;
```

84 is listed in ConfigParam 10, so every change is critical (owner, Q2).

| Field | Meaning |
|---|---|
| key | the account id of the token master (the bridge minter) on workchain 0 |
| `status` | `1` active; `2` admission suspended; `3` retired. No other value is valid. |
| `decimals` | decimals of the atomic unit; equals the minter content's `decimals` (TU:100-119) |
| `minter_code_hash` | the master account's code hash |
| `wallet_code_hash` | `cell_hash` of the wallet code the minter derives wallets with (TM:20) |
| `max_liability_per_actor` | the largest token liability one actor may hold in this asset (5.4); non-zero |
| `origin.kind` | `1` bridged by the TOS token bridge; `2` reserved for native issuance |
| `origin.bridge_address` | the masterchain account id of the bridge that created the minter; for kind 1 it equals `bridge_address` in the source chain's bridge ConfigParam (TLB:885) |
| `origin.source_chain_id`, `origin.source_token` | the minter content's `chain_id` and `token_address` |

**Status gates admission only.** A token actor admits a `call` only while its
asset's entry has status 1 (section 5.3). No payout, refund, sweep, return,
recovery or withdrawal reads recognition. Status 3 tells clients to refuse new
deployments and quotes.

**Status is not an emergency brake.** A critical change needs 3 won rounds,
each under a different validator set (2.5). Its latency is therefore at least
three validator-set rotations, which is days on a production election period.
The fast controls are:

- **Providers clear `active` through `update_policy`.** This is one owner
  transaction, effective from the next block, after which `call` refuses with
  1901 (SA:577). Each provider must act.
- **Buyer tooling refuses an asset by local policy** at once. This is not chain
  authority. It only stops that buyer from paying.

Status 2 is the slow, network-wide stop that also covers providers who do not
act.

**Client policy.**

- A client pins the masters it supports. In v1 that is up to two per
  network: the USDC entry and the USDT entry. Each is verified and treated
  independently (6.3).
- A client ignores dictionary entries it does not pin. More than two entries is
  never an error.
- A ticker is not a field. Display names come from a client table keyed by the
  master, and are never identity
  ([`SOFTWARE_WORK_MANIFEST_V1.md`](SOFTWARE_WORK_MANIFEST_V1.md):82-84).

**Size cap.** ConfigParam 84 holds at most **16** entries.

- When a new configuration is installed, every parameter is validated against
  a budget of 1,024 cells (`crypto/block/block.cpp`:1924).
- A value over that budget makes the collator refuse the configuration with a
  fatal error, and the masterchain halts
  (`validator/impl/collator.cpp`:5308-5333).
  - "About 342 entries" is an approximation. The real limit depends on the
    shape of the dictionary and of each record.
  - The builder therefore checks the actual cell count of the value, not an
    entry count.
- The config contract does not check this. Proposal tooling (the `tosctl`
  value builder of T2, and `testnet-governance.py` of T5) therefore refuses:
  - a value with more than 16 entries;
  - a value whose cell count exceeds the budget;
  - a value that does not validate against the full TL-B of section 3.1. A
    malformed value halts the chain in the same way.
- **Readers ignore unpinned entries, whatever their number.**
  - A reader decodes the whole value strictly by TL-B, then uses only the
    entries it pins.
  - More than 16 entries raises a T14 alarm, not an error. No payout reads
    ConfigParam 84 (5.3), so failing closed would protect no funds. It would
    only stop every new purchase after a governance slip.
  - A malformed or over-budget value can never be installed at all.

**Rollout precondition: no ConfigParam 84 before every validator knows its
TL-B.**

- **Why.** `valid_config_data` validates every parameter in a new
  configuration (`crypto/block/block.cpp`:1950). For an index with no TL-B
  constructor, the validation of that parameter fails (`block.cpp`:1923-1924).
  The collator then stops with `fatal_error("attempting to install invalid new
  configuration")` (`collator.cpp`:5331-5333). Upstream ignores such a change;
  this build makes it fatal.
- **Consequence.** A node without the ConfigParam 84 TL-B halts on **any**
  ConfigParam 84 value, well-formed or not.
- **Precondition.** Every validator must run a node release that contains the
  ConfigParam 84 TL-B (T2) before:
  - any ConfigParam 84 proposal; and
  - any zero state that contains ConfigParam 84.
- **Tooling.** The T2 `tosctl` builder and proposal path, and T5
  `testnet-governance.py`, refuse to propose ConfigParam 84 until every
  current validator reports that release or a later one.
- **General rule.** The same applies to any new ConfigParam in tos. Ship the
  TL-B in a node release, confirm that every validator runs it, and only then
  propose a value.

**ConfigParam 84 is one value, so changes are serialized.** A proposal replaces
the whole dictionary. Two proposals built from the same old value would
silently drop each other's entry. Adding USDT, suspending one asset or
migrating a bridge is therefore always one change at a time. Proposal tooling:

- builds each change from the current installed value;
- shows the diff, and asserts that it touches exactly one entry;
- binds the proposal to the current value's hash, as the config contract
  allows (`if_hash_equal`, TLB:668);
- warns about, and refuses to stack on, any other pending ConfigParam 84
  proposal.

**Self-verifying entry.** For kind 1, a reader re-derives the master from the
entry and refuses any mismatch. **Every read below is taken at one block:** a
single masterchain seqno, and the basechain state that block references. That
covers ConfigParam 84, the source chain's bridge ConfigParam, the bridge
account, the master account and the code cells read from them.

1. **The bridge's codes.**
   - Read the bridge account `-1:origin.bridge_address`, and check that the
     source chain's bridge ConfigParam names it. For Ethereum that is
     ConfigParam 79 (BR:73).
   - From the bridge's stored data, take `b_minter_code` and `b_wallet_code`
     (TB:79-80). The bridge writes them back unchanged (TB:96-100).
   - Require `minter_code_hash == cell_hash(b_minter_code)` and
     `wallet_code_hash == cell_hash(b_wallet_code)`.
   - **Pinned releases.** Clients, `ai` included, pin three code hashes and
     require all of them:
     - the bridge account's code hash equals the pinned bridge release;
     - `cell_hash(b_wallet_code)` equals the pinned reported-transfer wallet
       release (T1). This makes B1 of 4.5 checkable from state;
     - `cell_hash(b_minter_code)` equals the pinned minter release.

     A record can only point at codes that the vote itself names. The pins
     make sure those codes are the audited ones.
2. **The master's address, derived from the bridge's codes.** Compute
   `0:cell_hash(StateInit(b_minter_code, pack_minter_initial_data(content,
   b_wallet_code, -1:origin.bridge_address)))` (TU:44-56, TB:112-120), with
   `content = (source_chain_id, source_token, decimals)`. The record's key
   must be the canonical `addr_std` account id of that address on workchain 0
   (TU:66-72).
3. **The deployed master.** The master account's code hash equals
   `cell_hash(b_minter_code)`, and its `get_wrapped_token_data`
   (TM:1395-1398) equals the origin.

**Correction.** An earlier text checked the master's code hash only against
the record's own `minter_code_hash`. That let a counterfeit minter pass: anyone
could deploy one with their own code, but with the real wallet code and the
real bridge address in its initial data (tosnetwork/tos#513, review finding
P1-2). Taking both codes from the live bridge account closes that.

**A vote can therefore recognize only a minter that the bridge listed in its
ConfigParam created.** Such a minter is the only account whose address derives
from that bridge's own minter code, wallet code and address. Whoever deploys
that StateInit, the result is the same account, and that account's settlement
is driven only by that bridge (TB:112-120, TB:246-247).

**How `ai` reads it.** `toschain` reads ConfigParam 84 with `getConfigParam` at
the checkpoint seqno, under the read quorum. It already reads ConfigParam 4
(`protocol/pkg/toschain/dns.go`:157-188) and ConfigParam 19
(`protocol/pkg/toschain/agent_gift.go`:322-341) this way. It decodes the pinned
entries exactly (tags, and no trailing bits or references). It then applies
the self-verification above in full, with every read at the same masterchain
seqno and quorum:

- ConfigParam 84;
- the bridge ConfigParam;
- the bridge account's code hash, its data and its two code cells, checked
  against the three pinned releases;
- the master account's code and getter.

A mismatch in a pinned entry, or a read at another block, is a verification
error. Unpinned entries are ignored, and a count above 16 raises only a T14
alarm.

**Historical verification needs archive state.** A resolver that checks an
existing request re-runs this check at the request's admission seqno. That
requires archive-state access to the bridge account at that seqno, not only
current state, because a later bridge migration replaces the account (7.4).

**Testnets.**

- The same parameter carries a test asset: a minter of a test bridge with a
  test oracle set and a test ERC-20.
- Local networks set it in the zero state. The public testnet sets it through
  `testnet-governance.py` (section 8, T5).
- No list is hard-coded in `ai`.
- Where a network has no ConfigParam 84 yet, a deployment tool may pin one
  record by flag, but only for a run marked `"non_production": true`, as the
  escrow rule did
  ([`STABLECOIN_ESCROW_TVM_V2.md`](STABLECOIN_ESCROW_TVM_V2.md):193-197).

### 3.2 Alternatives rejected

| Alternative | Why rejected |
|---|---|
| An existing ConfigParam (31, 44, the bridge params) | None has fields for a master, a wallet code hash, decimals and status. 31 means "special account". 79/81-83 are per chain and carry no tokens (TLB:878-885). |
| A token list inside 79/81-83 | It couples recognition to one bridge layout and one source chain, and cannot express native issuance. Every bridge contract parses that type (TC:7-11). |
| A governed registry contract | It needs its own governance key, which is a new authority beside the validators. The actor cannot read it synchronously, so admission could not check status. |
| A list hard-coded in `ai` | That is client authority. [`PRODUCT_STRATEGY.md`](PRODUCT_STRATEGY.md):320-324 requires identity, issuer, decimals and status to be "independently resolvable from finalized TOS state". |
| The master only, without the wallet code hash | The outcome protocol depends on the wallet code, so the code must be pinned. |

## 4. Payout-outcome protocol

### 4.1 Requirement

The token payouts are:

- buyer refund;
- sweep to the caller;
- provider revenue withdrawal;
- return of a refused funding;
- payout of a returned entry;
- owner recovery of surplus.

For each of them, the paying contract must learn the outcome, **delivered** or
**refused**, and the report must be:

- **authenticated:** it comes from an address that only the token's own code
  controls, and the payer derives that address itself;
- **bound to the payout:** it names the payer's payout id and amount, and, for
  delivery, the recipient;
- **replay-safe:** it is accepted at most once, and any other report changes
  nothing.

Section 4.5 proves **at most one** outcome unconditionally, and **at least
one** under bounds B1-B5.

### 4.2 Options

| Option | What changes | Verdict |
|---|---|---|
| **A. Payment contract only** | Actor logic over the unchanged wallet | **Impossible.** A `transfer_notification` goes to the recipient's owner, never to the payer (TW:162-180). `excesses` carries only `query_id` (TW:189), so anyone can spoof a success: send a 1-unit transfer to the same recipient, with `response_destination` set to the actor and the actor's pending `query_id`, and the recipient's genuine wallet sends a matching `excesses`. A refusal is silent (TW:199-209). |
| **B. Wallet only** | Wallet reports; the actor stays native-only | Useless alone: no contract consumes the reports. |
| **C. Route transfers through the minter's settlement protocol** | Minter and wallet | Rejected. Every payout would pass through the single minter account, bringing storage growth and contention, and it reopens the settlement state machine (SP sections 3-16) for a non-bridge purpose. |
| **D. Reported transfer in the wallet, consumed by a new actor** (recommended) | Wallet: additive ops. Actor: new token-rail code | Meets 4.1 under B1-B5, at the costs of 4.7. |

### 4.3 Wallet change: reported transfer and balance report

All of these ops are new and additive. `transfer`, `internal_transfer`, burn
and all settlement ops keep their message formats. Section 4.7 lists the one
behaviour change to existing sends.

The op values below are the ones the implementation froze (ROP:10-20). The wallet
as built also documents its own TL-B (RW:211-232), and its protocol section
governs (RSP:1660-1864).

```text
reported_transfer#52545231 query_id:uint64 amount:Coins
  destination:MsgAddressInt response_destination:MsgAddress
  report_tos_amount:Coins forward_tos_amount:Coins
  forward_payload:(Either Cell ^Cell) = ReportedTransfer;          -- owner -> S

internal_transfer_reported#52544931 query_id:uint64 amount:Coins
  from:MsgAddressInt response_destination:MsgAddress
  report_tos_amount:Coins forward_tos_amount:Coins
  forward_payload:(Either Cell ^Cell) = InternalTransferReported;  -- S -> R

transfer_delivered#52544431 query_id:uint64 amount:Coins
  recipient:MsgAddressInt = TransferDelivered;                     -- R -> from
transfer_refused#52544631 query_id:uint64 amount:Coins
  = TransferRefused;                                               -- S -> owner
transfer_rereported#52545232 query_id:uint64 total:Coins
  = TransferRereported;                                            -- S -> owner
rereport_refusal#52545131 query_id:uint64 = RereportRefusal;       -- anyone -> S
clear_refusal#52544331 query_id:uint64 = ClearRefusal;             -- owner -> S

provide_balance#52544231 query_id:uint64 = ProvideBalance;         -- owner -> S
take_balance#52544232 query_id:uint64 balance:Coins
  = TakeBalance;                                                   -- S -> owner
```

`S` is the paying wallet, its owner `P` is the payer (the actor), and `R` is
the recipient's wallet.

**New wallet state.** The wallet data ends with `refusals_count:uint16` and
`refusals:(HashmapE 64 Coins)`, keyed by `query_id`.

- Both are empty in the initial data, so wallet addresses stay derived from
  the code and the empty fields (`utils.fc`:21-34 at `0a3bdbe78`).
- A record holds the **total** refused under its query id: a second refusal
  under the same id adds to it (RW:441-452).
- At most `REFUSALS_LIMIT = 32` records exist (RW:257-262). The wallet's worst
  case, with every record at its largest, is 206 cells, under the declared 256
  (RST:129-142).

**Wallet constants.** These are frozen in the wallet code (RW:234-262), and
changing any of them is a wallet code change. Each gas constant is at least
twice the most either engine measured (RSP:1773-1792; RT:1136-1255):

| Constant | Value | Bounds | Most measured |
|---|---|---|---|
| `R_GAS_LIMIT` | 41,000 | R on `internal_transfer_reported` | 20,267 |
| `S_BOUNCE_GAS` | 58,000 | S on the bounce, with `refusals` at its limit | 28,701 (9,951 with `refusals` empty) |
| `S_TRANSFER_GAS` | 127,000 | S on `reported_transfer`, at the 256-cell body with the deepest lookup | 63,006 |
| `REPORTED_BODY_CELLS` | 256 | the cells of S's body to R, forward payload included | — |
| `REPORT_MARGIN` | 10 | the factor R's budget is priced at | — |
| `REFUSALS_LIMIT` | 32 | recorded refusals | — |

Other measured legs:

- `clear_refusal`: 25,856, paid by P's message;
- `rereport_refusal`: 9,521, paid by its sender;
- `provide_balance`: 6,369, paid by P's message (RSP:1788-1790).

**S on `reported_transfer`.**

1. **Compute checks**, in this order. Any failure throws. P's message is
   bounceable and P attaches more than its bounce cost (5.4), so a throw
   returns it to P:
   - ConfigParam 79 is present (666). This check comes first: the wallet reads
     the configuration at dispatch, before it handles `reported_transfer`
     (RW:1028-1031);
   - then, in `send_reported_tokens` (RW:328-340; RSP:1660-1674): the sender
     is the owner (705);
   - `amount > 0`, and the balance covers it (706);
   - the destination is a canonical `addr_std` on workchain 0 (711,
     `not_canonical_destination`);
   - the forward payload has at least 1 bit (708);
   - `query_id` has no recorded refusal (712, `refusal_pending`);
   - fewer than `REFUSALS_LIMIT` refusals are recorded (714, `refusals_full`);
   - S's body to R, forward payload included, has at most
     `REPORTED_BODY_CELLS` (256) cells (713, `payload_too_large`). S's
     compute grows with the cells it measures, so this cap is what bounds S by
     `S_TRANSFER_GAS` (RW:242-247).

   The error names are at RER:27-34.
2. **Value check** (709; `reported_need`, RW:298-318; RSP:1675-1704). The
   attached value must exceed the sum of:
   - `forward_tos_amount + report_tos_amount`;
   - the forwarding fee of S's message to R;
   - R's bounce of it (32 + 256 bits, one cell), at `REPORT_MARGIN` times
     the forwarding price;
   - R's compute, at `REPORT_MARGIN` times the larger of
     `get_compute_fee(R_GAS_LIMIT)` and ConfigParam 79's
     `wallet_gas_consumption` (RW:269-273), so a mis-set bridge price cannot
     underfund R;
   - **S's own compute, `get_compute_fee(S_TRANSFER_GAS)`.** S pays it from
     the value before mode 64 passes the rest to R, so without this term R's
     budget would depend on the storage reserve;
   - R's largest action fine, at `REPORT_MARGIN` times the forwarding price of
     the body's cells plus two. A failed send is fined per cell of the
     messages R built, and the fine is deducted from the bounce value
     (TX:2754, TX:4098-4100);
   - `wallet_min_tos_for_storage`.

   R runs after S, at the prices of its own leg, so its compute, its bounce and
   its fine carry the margin (RW:249-255). The margin is locked, not spent: R
   computes its excess with the unmargined price, so what it does not use goes
   back with the excess or the bounce (RSP:1696-1701). The getter
   `get_reported_transfer_need(body)` returns this value at current prices
   (RW:1101-1118).

   The bridge's stdlib gained `get_compute_fee` and `get_forward_fee`
   (RSL:63-66). They need global version 6 or later (STD:272-276). Equivalents
   already existed in `settlement.fc` (`gas_fee`, `forward_fee`, RST:197-198).
3. Debit the balance and send `internal_transfer_reported` to R, bounceable
   and with StateInit, in **mode 64 + 16** (RW:344-347). An action-phase
   failure at S, for example a StateInit or forward cost above the estimate,
   then bounces P's message back to P instead of rolling back silently
   (TX:2759-2761).

**R on `internal_transfer_reported`.**

1. **Cap R's gas, paid by the message.** R calls `set_gas_limit(R_GAS_LIMIT)`
   only when `msg_value >= get_compute_fee(R_GAS_LIMIT)`. Below that, R runs
   on the gas its message bought, and an underfunded message simply fails on
   its own value.

   **Correction.** An earlier text of this design, and the T1 wallet at
   `0a3bdbe78` (RW:958-962), call it unconditionally, straight after op
   dispatch. That is wrong. The message is not yet authenticated there, so
   anyone can send underfunded forged `internal_transfer_reported` messages.
   Each one raises R's limit to `R_GAS_LIMIT` at R's own expense, then fails
   authentication, and this drains R's TOS (tosnetwork/tos#512, review
   finding P1). The guard above, or moving the call after step 2, fixes it.

   A genuine message from S always meets the guard: S's value check prices
   R's compute at `REPORT_MARGIN` (4.3), so for it the call only caps
   consumption. If R then runs out of gas, the gas fee is at most
   `get_compute_fee(0, R_GAS_LIMIT)`, and the remaining value still pays the
   bounce (TX:4101-4105).
2. Authenticate as TW:153-154: the sender must be the wallet of `from`.
3. Credit under the supply bound (TW:157), and top up storage as in
   TW:159-161.
4. If `forward_tos_amount > 0`, send the ordinary `transfer_notification` in
   mode 1 + 16.
5. Send `transfer_delivered(query_id, amount, recipient = w_owner)` to `from`,
   non-bounceable, carrying `report_tos_amount`, in mode 1 + 16.
6. Send the remainder as `excesses` to `response_destination` with
   ignore-errors (as TW:183-191).

Every way R can fail bounces to S: a compute failure, running out of the capped
gas, or an action-phase failure in step 4 or step 5. R never commits a credit
without committing the `transfer_delivered` send.

**S on a bounce of `internal_transfer_reported`.**

1. Identify it from the 256-bit bounced body (`capBounceMsgBody`, TX:4990,
   GZ:190), which holds `op`, `query_id` and `amount` in 32 + 64 + at most 124
   bits.
2. Before the wallet loads its data, call `set_gas_limit(S_BOUNCE_GAS)`
   (RW:926-933). This pays S's handler from S's own balance if the bounce
   value is short. It meets the rule of 2.3, because the bounce is
   authenticated by construction:
   - a bounce cannot be forged (TX:3435-3436);
   - a bounce returns only to the sender of the bounced message, so each such
     bounce answers a debit that S itself made, and is paid at most once per
     transfer.

   **Operational bound on ConfigParam 79.** The storage reserve,
   `wallet_min_tos_for_storage`, must cover `REPORT_MARGIN ×
   get_compute_fee(S_BOUNCE_GAS)`. This reserve is what funds the refusal of
   a third-party transfer whose bounce a price rise left short; the actor's
   payouts fund their refusal leg themselves (4.4). It is a governance bound
   on the parameter, not a contract check (RSP:1816-1824). T1 checks it for
   the configuration it runs (RT:1254-1255).
3. **Restore and record** (RW:436-457). Restore the balance, then record the
   refusal:
   - if `refusals[query_id]` exists, add the amount to it (the total);
   - else, if fewer than `REFUSALS_LIMIT` records exist, insert it and
     increment `refusals_count`;
   - else (a transfer that was already in flight when the limit was reached)
     record nothing. The tokens are back, and the report below still goes out,
     but it cannot be repeated (RSP:1739-1743).
4. Send `transfer_refused(query_id, amount)` to the owner with the bounced
   value, in mode 64 + 2 (RW:458). The restore and the record commit even if
   this report fails.

**S on `rereport_refusal`** (permissionless, funded by the sender; RW:461-472).
If the record exists, S sends **`transfer_rereported(query_id, total)`**, a
distinct op, to the owner in mode 64 without ignore-errors. A failure fails the
transaction and keeps the record. If there is no record, S does nothing. The
distinct op lets the owner tell a re-report, which names the recorded total,
from a new refusal.

**S on `clear_refusal`** (owner only, 705; RW:474-483). S deletes the record
and decrements `refusals_count`. An absent record is not an error and counts
nothing. `refusals` is therefore bounded by `REFUSALS_LIMIT` and by the
payer's uncleared refusals.

Getters `get_refusal(query_id)` and `get_refusals_count()` expose the records
(RW:1088-1099).

**S on `provide_balance`** (owner only): S sends `take_balance(query_id,
w_balance)` to the owner with the message's remaining value, in mode 64.

### 4.4 Payer side

The actor keeps `next_payout_id:uint64`, which is never reused, and
`payouts:(HashmapE 64 ^Payout)`:

```text
payout$_ kind:uint3 request_id:uint64 recipient:MsgAddressInt
  requester:MsgAddressInt amount:Coins created_at:uint32
  ^payout_auth = PayoutV1;
payout_auth$_ recipient_wallet:MsgAddressInt own_wallet:MsgAddressInt
  outcome_fee_lock:Coins ^ledger_undo = PayoutAuthV1;
-- kind: 1 refund, 2 sweep, 3 revenue withdrawal, 4 funding return,
--       5 returned-entry claim, 6 surplus recovery, 7 returned-entry sweep
```

The transfer's `query_id` is the payout id.

`recipient_wallet` and `own_wallet` are derived when the payout is created
(TU:78-80). The handlers can then authenticate by comparing addresses, with no
derivation before the gas limit is raised. `ledger_undo` holds the ledger
changes that a bounce at S reverts (5.4).

**Outcome gas constants** of the actor release:

- `PRE_ACCEPT_GAS`: the gas spent before a handler raises its limit;
- `OUTCOME_HANDLER_GAS`: the gas cap of the whole handler;
- `REPORT_MARGIN = 10`.

Each gas constant is twice the maximum measured on both VMs, with `payouts` at
its bound (T3).

**Report funding.**

- `report_tos_amount` is computed when the payout is sent:

  ```text
  report_tos_amount = REPORT_MARGIN * (get_compute_fee(0, PRE_ACCEPT_GAS)
                                       + get_compute_fee(0, S_BOUNCE_GAS))
                    + REPORT_MARGIN * get_forward_fee(transfer_refused)
                    + get_forward_fee(report)
  ```

  It funds both possible reports, not only the delivery report.
  - **Delivery report.** On delivery, R sends it with `transfer_delivered`,
    and it pays the actor's pre-accept part.
  - **Refusal report.** On a refusal at R, R's failure rolls back R's sends,
    so this value is not spent at R and comes back to S inside the bounce.
    There it pays S's bounce handler (up to `S_BOUNCE_GAS`), the forwarding of
    `transfer_refused` and the actor's pre-accept part, each at
    `REPORT_MARGIN` times the send-time prices. Within B2 the refusal report
    is therefore funded by the payout itself, whatever the ConfigParam 79
    storage reserve holds.

  The wallet's `reported_need` margins only R's compute, R's action fine and
  R's bounce forwarding (RW:310-318). It does not cover S's bounce compute or
  the `transfer_refused` forwarding, and the protocol expects a short bounce
  to be topped up from the reserve (RSP:1816-1822). That is why the actor sets
  this larger value.

  **Rejected alternative:** a wallet-side term in `reported_need` for S's
  refusal leg. It is not needed: the payer chooses `report_tos_amount`, the
  actor already sets it this way, and changing the wallet would reopen T1 for
  no gain.
- `outcome_fee_lock` is reserved from the requester's attached TOS into
  `locked_outcome_fees`. It equals `get_compute_fee(0, OUTCOME_HANDLER_GAS)`
  plus the value and forward fee of every send the outcome handler may make:
  - `clear_refusal`;
  - the change to the requester;
  - for kinds 1 and 2, the forward fee of the `cleanup_bounty` send, whose
    value comes from the request's storage fee.

  The lock is part of backing (5.6), and it is released when the outcome is
  processed or the payout is abandoned.
- **Sends inside an outcome handler use mode +2 (ignore errors).** A failed
  `cleanup_bounty`, `clear_refusal` or change send therefore never rolls back
  the outcome. A bounty or change that could not be sent stays in the actor's
  balance as an unaccounted operator buffer. A `clear_refusal` that could not
  be sent leaves a record at S. The next `transfer_rereported` clears it,
  because the actor answers every authenticated re-report with
  `clear_refusal`.

**Handler order.** Before raising its gas limit, each handler reads only `op`,
`query_id`, the root cell and the `payouts` reference. It looks up the payout
and compares the sender, the amount, and (for delivery) the recipient. Only
then does it call `set_gas_limit(OUTCOME_HANDLER_GAS)`.

- From that call on, the handler is paid from `outcome_fee_lock`, once per
  payout, because the payout is deleted in the same transaction.
- A message that does not match never raises the gas limit. It fails, or ends,
  on its own value.
- **This order is the rule of 2.3.** The only `set_gas_limit` in an outcome
  handler comes after authentication. The sender address is compared with the
  stored `recipient_wallet` or `own_wallet`, and the amount (and, for
  delivery, the recipient) with the payout. The gas raised is the gas
  `outcome_fee_lock` reserved for that payout.

**The rule across the actor's other handlers (section 5).** No other actor
handler raises its gas limit. Each runs on its message's own value:

- `call` funding through `transfer_notification` (5.2);
- the absent-payout branch of `transfer_refused`, which answers with
  `clear_refusal` on the report's own value;
- the stale-record branch of `transfer_rereported`, where the wallet
  derivation is paid by the re-report's value;
- `take_balance`, `recover_surplus`, `recheck_payout` and `abandon_payout`;
- every owner-only op;
- every buyer op: `claim_refund`, `claim_returned`, `sweep_*`, `expire`.

**T3 must keep it that way:** no `accept_message`, and no `set_gas_limit`
above what the message buys, outside the authenticated outcome handlers.

| Message | Authenticated by | Accepted when | Effect |
|---|---|---|---|
| `transfer_delivered` | sender `==` `recipient_wallet` | the payout exists, and `amount` and `recipient` equal it | delete the payout; apply its ledger change (5.4); release `outcome_fee_lock`; emit `SAO1` |
| `transfer_refused` | sender `==` `own_wallet` | the payout exists, and `amount` equals it | delete the payout; apply the refusal (5.4); release the lock; emit `SAO1`; send `clear_refusal(query_id)` |
| `transfer_rereported(query_id, total)` | sender `==` `own_wallet` (for an absent payout, the actor derives its own wallet on the message's own value, without raising gas) | the payout exists and `total` equals its amount: treat as `transfer_refused`. No payout: the record is stale | payout exists with an equal total: as `transfer_refused`, including `clear_refusal(query_id)`. **No payout:** send `clear_refusal(query_id)`. **Payout exists with another total:** do **not** clear; log it (`SAO1` with outcome `mismatch`) and leave both the payout and the record. T14 alarms. It cannot arise while query ids are never reused. |
| bounce of the actor's own `reported_transfer` | bounce source `==` `own_wallet`, and the 256-bit body names `reported_transfer` | the payout exists, and `amount` equals it | delete the payout; undo it to the pre-payout ledger position (5.4); release the lock; emit `SAO1` |

**Refusal records.**

- A `transfer_refused` for a payout that no longer exists still gets
  `clear_refusal`.
- The actor never reuses a query id, so a re-report's total equals the one
  payout's amount.
- **A bounce from S for any reason is an ordinary S refusal.** That includes
  714 `refusals_full`, 712 and 713: no token left S, and the payout returns to
  its pre-payout position. The actor cannot see the exit code in the 256-bit
  bounce body, and does not need to.
- **The catch-all is narrow.** "Every other message is ignored without
  throwing" covers messages not listed in this table. It never swallows
  `transfer_rereported` or `transfer_refused` from `own_wallet`. Both end in
  `clear_refusal`, except in the mismatch case of the row above.

**Why this matters.** An actor that ignored re-reports, or treated 714 as
something other than a refusal, would halt every token payout permanently once
32 uncleared records accumulated at S, because S then refuses every new
reported transfer with 714 (RW:335).

The rules above make clearing possible; they do not by themselves keep S
below the limit:

- A record is cleared when its report, or a re-report, reaches the actor and
  the actor's `clear_refusal` reaches S.
- A record whose report or clear failed (both are sent ignoring errors) stays
  until someone sends a funded `rereport_refusal`.

**Liveness therefore depends on funded re-reports** by T14 or any third party.
T14 watches `get_refusals_count()` and sends `rereport_refusal` for every
recorded query id it finds. It enumerates them from the actor's `paying`
payouts and from S's refusal transactions, and confirms each with
`get_refusal`.

A re-reporter must attach enough for the whole chain, with a factor of 2 for
price movement between legs:

- S's `rereport_refusal` compute: 9,521 gas measured, `get_compute_fee`;
- the forwarding of `transfer_rereported` to the actor;
- the actor's handler for an absent payout, which derives its own wallet
  (TU:78-80) on the message's own value and sends `clear_refusal`. Its gas is
  measured in T3;
- the forwarding of `clear_refusal`;
- S's `clear_refusal` compute: about 25,856 gas, measured at the deepest path
  (RSP:1788).

The actor's `clear_refusal` carries the rest of the re-report's value, so S's
compute is paid by the re-reporter and never by the actor's locks. Tooling
computes this value at current prices. T3 publishes the actor's measured gas
for it.

Every actor send to S uses mode 1 + 16. An action-phase failure in the actor
then bounces the requester's message, and the transaction's state, including
the payout's creation, rolls back.

### 4.5 Outcome guarantee

**At most one outcome, unconditionally.**

- The three accepted messages come from disjoint branches: S bounced P's
  message; S sent and R committed; or S sent and R failed.
- Each message is authenticated against an address from which only that
  branch's wallet can send.
- The first accepted outcome deletes the payout, and payout ids are never
  reused.
- No third party can produce an accepted message:
  - a `transfer_delivered` with `from` equal to the actor needs a message from
    the actor's own wallet, which R authenticates (TW:153-154);
  - a `transfer_refused` comes only from that wallet;
  - a bounce cannot be forged (TX:3435-3436).

**At least one outcome**, under these bounds:

- **B1** The actor's wallet code is the recognized reported-transfer code,
  whose hash is pinned by ConfigParam 84 and by the asset route, and
  `capBounceMsgBody` stays on (GZ:190).
- **B2** Basechain gas and forward prices (ConfigParams 21 and 25) rise by less
  than `REPORT_MARGIN` between a payout's send and the processing of its
  report. That includes S's refusal leg, which the actor's
  `report_tos_amount` prices at the margin (4.4). These are ordinary parameters (GZ:414), so a change is a public
  validator vote of at least two rounds.
- **B3** No handler exceeds its gas constant: `R_GAS_LIMIT`, `S_BOUNCE_GAS`,
  `S_TRANSFER_GAS`, `PRE_ACCEPT_GAS` or `OUTCOME_HANDLER_GAS`. For the wallet
  this holds by measurement at half or less (4.3), and for the
  storage reserve by the operational bound on ConfigParam 79 (4.3).
- **B4** Neither S nor the actor is frozen or deleted while the payout is in
  flight (held by 5.6).
- **B5** The actor's balance covers `locked_outcome_fees`, which include the
  values and forward fees of every in-handler send (4.4). This is held by the
  backing rule of 5.6. Because those sends use +2, a failed in-handler send
  never removes an outcome.

Case analysis under B1-B5:

- **(i) S throws in compute, or fails in its action phase.** P's bounceable
  message (+16) bounces to P (4.3 step 3). Its value covers the bounce,
  because P attached the full budget. The bounce is accepted (row 3).
- **(ii) R fails: in compute, out of its capped gas, or in its action phase.**
  R bounces with value left for the bounce fee (B3, 4.3). S's handler runs
  with raised gas, restores the tokens and, below `REFUSALS_LIMIT`, records
  the refusal. Whether the refusal report is delivered depends on who set
  `report_tos_amount`:
  - **The actor's payouts.** The actor sets `report_tos_amount` to cover S's
    refusal leg at `REPORT_MARGIN` (4.4). R's failure rolls back R's sends,
    so that value returns inside the bounce and pays S's handler,
    `transfer_refused` and the actor's pre-accept part within B2, whatever
    the ConfigParam 79 reserve holds. An in-bounds refusal report is therefore
    always delivered. The outcome guarantee needs no condition on refusal
    capacity, or on the number of concurrent transfers: at the limit the
    refusal is not recorded, but its report still arrives.
  - **Third-party reported transfers** (not the actor's). The wallet's own
    value check does not fund S's refusal leg (RW:310-318). A bounce can be
    short inside the bounds and is then topped up from the reserve
    (RSP:1816-1822); with a low reserve near a 10× price rise, the
    `transfer_refused` can be dropped. The guarantee then needs either:
    - S below `REFUSALS_LIMIT`, so the record lets a funded `rereport_refusal`
      re-send it as `transfer_rereported`; or
    - a `report_tos_amount` at least as large as the actor's rule.

  For the actor, a report dropped at the limit needs a price rise beyond the
  margin (4.5, "Outside the bounds"). `recheck_payout` (buyer kinds) and
  `abandon_payout` (kinds 3 and 6) recover it. The storage claim of 5.2 rests
  on the same rule.
- **(iii) R commits.** The `transfer_delivered` send commits together with the
  credit, under +16. Its value covers `PRE_ACCEPT_GAS` with margin (B2), and
  the rest of the handler is paid from the lock (B5).

**Outside the bounds** no double payment is possible, because at-most-one
holds unconditionally.

- If B2 or B3 is broken for R's delivered report, the report is lost and the
  payout stays `paying`.
- If B4 is broken, a frozen or deleted S loses its balance (5.6).
- If B1 is broken, the reported-transfer ops do not exist.
- **A dropped, unrecorded refusal at the limit.** A transfer already in flight
  when S reached `REFUSALS_LIMIT` is refused at R and restored, but not
  recorded (RW:445-456). If its `transfer_refused` is then dropped (mode
  64 + 2), nothing can re-send it. The payout stays `paying` while its tokens
  are back at S.
  - **Kinds 3 and 6.** Recovery is `abandon_payout`. The tokens then become
    surplus, which the owner recovers (5.4). While the payout is still in
    `in_flight`, surplus subtracts it, so nothing is recoverable before the
    abandon.
  - **Buyer kinds (1, 2, 4, 5, 7).** The actor cannot tell this case from a
    lost delivery report, and T14 alarms on it. Recovery is
    **`recheck_payout`** (5.4), after `PAYOUT_RECHECK_AGE`. If the tokens are
    provably back in the wallet, beyond every other liability, the payout
    resolves as refused at R, so a buyer's principal is never stuck
    permanently.

  This case needs a transfer in flight at the moment S reaches the limit. For
  the actor's payouts it also needs a price rise beyond the margin, because
  the actor's `report_tos_amount` funds the refusal report within it (4.4).
  Funded re-reports (4.4) keep S away from the limit.
- **A price rise can turn a delivery into a refusal.** This affects large
  payloads. R pays the notification's forwarding of the payload at its own
  leg's prices (RW:368-383), sending with +16. Beyond what the margin covers,
  that send fails in R's action phase and the transfer bounces to S. This is
  sound: the tokens are restored and refused, never lost (RSP:1807-1815;
  T-R6, T-R14). The actor's own payouts carry no payload (5.4), so this
  concerns only third-party reported transfers.

Beyond `REPORT_MARGIN`, the T1 measurements show where the guarantee ends
(RSP:1807-1815):

- up to 20 times the price, R still delivered;
- at 30 times, R's action phase failed with no funded bounce;
- from 50 times, R ran out of gas with no bounce.

In the last two cases the tokens were lost. This is the B2 boundary of this
section, measured.

Recovery:

- For kinds 3 and 6, which are the owner's own money, the owner may
  `abandon_payout` after `PAYOUT_ABANDON_AGE` (30 days). This deletes the
  record without re-crediting it. If the tokens are in fact still in S, they
  show as surplus, which the owner can recover (5.4).
- For buyer kinds (1, 2, 4, 5, 7), anyone may `recheck_payout` after
  `PAYOUT_RECHECK_AGE` (30 days) (5.4).
  - If the wallet's balance proves the tokens are back beyond every other
    liability, the payout resolves as refused at R.
  - If the report was a lost delivery, the conversion can pay the buyer twice,
    out of unattributed surplus only. The owner bears that, bounded by the
    amount.
  - Monitoring (T14) alarms on every payout older than its age bound.

### 4.6 Crash, retry and replay

| Failure point | Chain state | Recovery |
|---|---|---|
| A client sends a payout-creating op and crashes | Nothing (not included, or bounced), or a payout in `payouts` | Resolve from finalized state before any retry ([`SETTLEMENT.md`](SETTLEMENT.md):167). A second claim on the same entry fails: a refund is no longer in `refunds` (1917), and a returned entry is marked paying (1930). |
| S refuses in compute (insufficient value; ConfigParam 79 absent per TC:11) | A bounce at the actor | Undo to the pre-payout position (5.4). The requester's TOS change returns. |
| S fails in its action phase | A bounce at the actor (+16) | As above. |
| S is frozen or deleted | A bounce at the actor (no state to execute) | As above. A deleted S has lost its balance; see 5.6. |
| R fails, including out of capped gas | A bounce at S; a record (an addition if the id has one); a refusal report | The actor applies the refusal and clears the record. A dropped report is re-sent by `rereport_refusal` as `transfer_rereported`, which the actor also answers with `clear_refusal`. |
| S holds `REFUSALS_LIMIT` records | New reported transfers bounce with 714 | An ordinary S refusal: the payout returns to its pre-payout position. A funded `rereport_refusal` per record lets the actor clear them, and payouts resume. |
| R refuses while S is at the limit, and the report is dropped | Tokens back at S, no record | 4.5, "Outside the bounds". |
| A price change between legs, within B2 | Absorbed by the margins | — |
| A price change beyond B2 | A delivered report may be lost | 4.5, "Outside the bounds". |
| A duplicate or stale report | The payout is not present | Ignored, plus `clear_refusal` for every authenticated `transfer_refused` or `transfer_rereported`. |

### 4.7 Costs, compatibility and audit scope

**Messages** per payout, excluding the request that triggers it:

- **Delivered:** actor→S, S→R, R→actor and R→excesses. That is one more message
  and one more actor transaction than an ordinary transfer.
- **Refused at R:** actor→S, S→R, R→S bounce, S→actor and actor→S
  `clear_refusal`. That is two more messages and one more wallet transaction
  than a bounced ordinary transfer.

No gas figure is quoted here: T1 and T3 measure each leg on both VMs.
Recipients pay nothing extra. The requester's attached TOS funds every leg and
the outcome lock.

**Compatibility.** The wallet code changes. The minter address depends on the
wallet code (TU:44-56), and the bridge address depends on both the minter code
and the wallet code (TB:79-80, TB:96-100). So every bridge and minter address
changes, and so do:

- `bridge_address` in ConfigParam 79 and in any other populated bridge slot
  (TLB:885);
- the EVM side's `tosBridge` for the generation that names the new bridge
  (BS:38, BS:182-196);
- pinned fixtures:
  - the token-bridge sandbox suites
    (`tosctl/src/node-control/contracts/tests/token_bridge/`);
  - the replay and mutation evidence (`scripts/replay-token-bridge-trace.py`,
    `scripts/token-bridge-mutations.results.json`);
  - `crosschain/token-bridge/tests/vectors/`.

None of this is deployed in production (BR:3, BR:78). The owner's
no-backward-compatibility rule applies (SP:25-30), and test deployments are
redeployed.

Ordinary `transfer` keeps its format. Wallets, explorers and the iOS and
Android clients keep working. They need the new ops only to use reported
transfers.

**Behaviour change in existing sends.** T1 adds +16 to the ordinary
`transfer_notification` (TW:180), and recommends the same for the ordinary
outbound `internal_transfer` (TW:139).

- Today, an action-phase failure there loses the tokens in flight: the sender
  is debited, the credit rolls back, and nothing bounces (TW:145-146).
- With +16, the transfer bounces back to the sender instead.

This changes observable behaviour: a transfer that used to vanish now returns.
It is listed as a behaviour change in the bridge's compatibility section (SP
section 12).

**Audit scope.**

- The wallet is already in the bridge's mandatory audit scope (SEC:102). The
  owner decided (Q3) to make this change before that audit, so the audit
  covers the final wallet.
- The token-rail actor and the wallet change also get an independent security
  review (T13).

## 5. Service Actor token rail

The token rail is a new contract, `service-actor-token-code.fc`, released as
`tos-service-actor-token-v1` with rail id `tos.service.service-actor-token.v1`.

It keeps the native actor's request lifecycle, terms, attestor, SRP2 and
snapshot design ([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md)
sections 3-8). Funding, payouts and accounting change. The native actor is
unchanged (5.7).

### 5.1 Asset fixed at deploy

```text
asset_route$_ master:MsgAddressInt wallet_code_hash:uint256
  wallet_code:^Cell = ServiceActorAssetRouteV1;
```

The route must satisfy:

- `master` is a canonical `addr_std` on workchain 0 with no anycast (TU:66-72);
- `cell_hash(wallet_code) == wallet_code_hash`.

While either check fails, admission refuses with reason 1932. This mirrors the
native re-check of deploy data at `call` (SA:578-604). No op changes the route.

The actor's own wallet is `calculate_user_token_wallet_address(my_address(),
master, wallet_code)`, in the bridge layout (TU:21-38, TU:78-80).

- The actor derives it at run time: the actor's address depends on its own
  StateInit, so the wallet address cannot be stored there.
- Resolvers reproduce it independently, as the retired escrow required
  ([`STABLECOIN_ESCROW_TVM_V2.md`](STABLECOIN_ESCROW_TVM_V2.md):80-84).

The `terms_hash` preimage gains the asset in its root (compare SA:263-291):

```text
token_terms$_ policy_version:uint32 price_per_call:Coins storage_fee:Coins
  cleanup_bounty:Coins response_sla:uint32 refund_claim_window:uint32
  asset_master:uint256 asset_wallet_code_hash:uint256
  ^terms_tail = ServiceActorTokenTermsV1;        -- root <= 980 bits
```

`terms_tail` is unchanged. SRP2 keeps its layout
([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md) section 6) and binds the
asset through `terms_hash`.

Units:

- `price_per_call` is in the token's atomic units;
- `storage_fee`, `cleanup_bounty`, the allowances, the outcome locks and the
  operating reserve stay in nanoTOS.

The policy gains `max_token_liability:Coins`, which the owner sets. Admission
uses the lesser of it and the recognition record's `max_liability_per_actor`
(5.2).

### 5.2 Funding a `call`

The buyer sends an ordinary token `transfer` to the actor:

- `amount = price_per_call`;
- `forward_tos_amount >= storage_fee + ADMISSION_GAS_ALLOWANCE +
  RETURN_BUDGET`;
- `forward_payload` is:

```text
token_call#53544301 request_hash:uint256 expected_terms_hash:uint256
```

`RETURN_BUDGET` covers one funding return: a reported transfer's value check
(4.3), its outcome lock and its log. `MIN_FUNDING_VALUE` is
`ADMISSION_GAS_ALLOWANCE + RETURN_BUDGET`, priced at run time with `GETGASFEE`
and `GETFORWARDFEE`.

The actor's wallet then sends `transfer_notification(query_id, amount, from =
buyer, forward_payload)` with `forward_tos_amount` as its value (TW:162-180).
The actor handles op `0x7362d09c` in these steps.

**1. Foreign or spoofed notification** (the sender is not the actor's own
wallet).

- No token reached the actor's wallet, so no state changes. A wrong master is
  this case.
- The actor asks the sender to transfer `amount` back to `from`, carrying only
  the message's own value (mode 64), and stops.
- If the sender is a genuine wallet that the actor owns, this returns the
  tokens. Otherwise the request is harmless. This follows the retired escrow
  (`STABLECOIN_ESCROW_TVM_V2.md`:117-122).

**2. Underfunded** (`msg_value < MIN_FUNDING_VALUE`).

- The actor stores nothing and emits `SAF1` with reason `underfunded`.
- The tokens become **surplus**, recoverable only through the owner's surplus
  recovery (5.4).
- If the value cannot even pay for the log, or for the compute phase up to
  this check, the transaction fails. The notification is non-bounceable
  (TW:174), so the tokens again become surplus.

Buyer tooling must therefore enforce the **full** budget, not just
`forward_tos_amount != 0`. It must refuse to build any transfer to an actor
below that budget. The buyer preview states that tokens sent to an actor
underfunded, or with no forward amount, become the provider's.

Surplus covers only tokens whose attribution was lost through the sender's own
error:

- underfunded or forward-less transfers;
- direct bridge mints.

A correctly funded payment that the actor refuses stays attributed to its
sender (step 6).

**3. Authenticated and funded: from here the handler never throws.**

- The caller is `from`, which the chain authenticated at the actor's wallet
  (TW:153-154).
- Two parses are wrapped in `try`/`catch` (supported by FunC and used by the
  config contract):
  - the `token_call` payload parse; any failure gives reason
    `malformed_payload`;
  - the ConfigParam 84 lookup and record parse; any failure gives reason 1933
    `asset_not_recognized`.

  Both failures take the refusal path. Gas exhaustion cannot be caught. Step 2
  and B3 exclude it.

**4. Admission checks, in order.**

1. `active` and the policy bounds hold (as SA:577-594).
2. The attestor commitments hold (SA:598-604).
3. The asset route holds (5.1).
4. ConfigParam 84 holds the master with status 1 and the route's
   `wallet_code_hash`.
5. `from` is admitted by `open_access` or `authorized_caller` (SA:607-608),
   comparing `from` and not the message sender.
6. `amount == price_per_call` exactly: overpayment and underpayment are both
   refused.
7. The value covers `storage_fee`, then `ADMISSION_GAS_ALLOWANCE`, then
   `RETURN_BUDGET`.
8. Capacity, id overflow and the daily rate limit hold (SA:617-632).
9. `accepting_tokens` holds, and `from`'s returned-entry count is below its
   cap (5.4). Otherwise the reason is 1935 `not_accepting_tokens`.
10. The token liability plus `price_per_call` stays within
    `max_token_liability` and `max_liability_per_actor`. Otherwise the reason
    is 1937 `exposure_cap`.
    - **Token liability** is `pending + refundable + returned + in_flight`.
      Revenue is excluded.
    - **No cap** is written as `2^120 - 1`, the largest `Coins` value.
    - **Bypass.** The caps are per actor, so deploying many actors bypasses
      them. Only the aggregate watch of T14 sees that.
11. `expected_terms_hash == terms_hash`.
12. TOS backing covers the storage locks, the outcome locks and the operating
    reserve (as SA:660-666).

**5. Admitted.**

- The actor stores the pending request with `caller = from`, and adds `price`
  to the token pending liability.
- It emits `SAT1` (`0x53415431`). This is the `SAR1` layout
  ([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md) section 8.1) with the
  token terms cell.
- It returns the TOS change to `from`.

**6. Refused.**

- The actor creates a kind-4 payout of `amount` to `from`, funded by
  `RETURN_BUDGET`, and sends it as a reported transfer.
- It emits `SAF1` (`0x53414631`): `query_id:uint64 from:MsgAddressInt
  amount:Coins reason:uint16 payout_id:uint64`.
- No cap applies to kind-4 payouts, so a funded refusal never becomes
  surplus. That is safe for storage:
  - each return carries its own `RETURN_BUDGET`;
  - it exists only while in flight. Under B1-B5 it reaches an outcome within
    the legs of section 4, which delete it. A refusal report reaches the actor
    even at `REFUSALS_LIMIT`, because the actor's `report_tos_amount` funds
    S's refusal leg (4.4, 4.5 case (ii));
  - a flood of refused fundings therefore costs the flooder one
    `RETURN_BUDGET` plus the tokens per return, and leaves no entry behind.
- If the return is itself refused or bounced, the amount becomes an ordinary
  `returned` entry with `caller = from`, keyed by the payout id (5.4). It
  stays attributed to its sender and is never surplus.

**Not funding.** Native value with a `call`-shaped body is not funding: a
native `call` op is unknown on this rail (1910). Bridge mints credited straight
to the actor's wallet produce no notification (TW:294-326), and those tokens
are also surplus.

### 5.3 Admission reads recognition; payouts never do

The ConfigParam 84 check is part of admission only, and no payout path reads
it. Suspending an asset stops new calls on every actor of that asset, with the
latency of 3.1, and cannot freeze money already admitted. A network without
ConfigParam 84 admits no token call.

### 5.4 Requests, payouts and their outcomes

**State.**

- `payouts`, as in 4.4.
- `returned:(HashmapE 64 ^Returned)`, keyed by the payout id whose refusal
  created the entry:
  `returned$_ caller:MsgAddressInt amount:Coins paying:uint64
  return_deadline:uint64 = ReturnedV1`. `paying` is the payout id in flight
  for the entry, or 0.
- The token ledger, in atomic units: `pending_liability`,
  `refundable_liability`, `returned_liability`, `in_flight` and
  `withdrawable_token_revenue`.
- The native ledger, in nanoTOS: `locked_storage_fees`, `locked_outcome_fees`,
  `withdrawable_tos_revenue` and the operating reserve.
- Counters: `returned_count` (global), a per-caller returned count and
  `revenue_payouts_in_flight`.
- `accepting_tokens` is derived, never stored, and equals `returned_count <
  MAX_RETURNED_GLOBAL`. While it is false, the actor admits no call. A full
  `returned` store stops new admissions and never reclassifies money.

A returned entry arises from a refused or bounced payout of any of these
kinds:

- a refund or sweep (kinds 1 and 2), with `caller` = the request's caller;
- a funding return (kind 4), with `caller = from`.

**Destination validation.** `claim_refund` and `claim_returned` check, in
compute and before any state change, that `destination` is a canonical
`addr_std` with no anycast, on workchain 0, and not the actor itself.
Otherwise they fail with 1934 `invalid_destination`.

**Claimant workchain.** No entry is claimed against a bare 256-bit account id:

- A claim compares the message sender's full address with the stored
  `caller`.
- The per-caller counters are keyed by `slice_hash` of the full address, which
  includes the workchain (SA:527-533). The token actor keeps that keying for
  its returned count.

The rail is workchain 0 only, so the actor also requires its counterparties to
be there:

- `call` admission requires `from` on workchain 0. Otherwise it refuses with
  1934 and returns the tokens.
- `claim_refund` and `claim_returned` refuse a sender off workchain 0 with
  1934.

A sender that is a contract unable to send the claim leaves its entry stranded
until `return_deadline`. After that, `sweep_returned`, which anyone may send,
pays the entry's `amount` to the stored `caller`, never to the sweeper (table
below, kind 7). Receiving needs no action from the caller: its token wallet is
deployed by the transfer's StateInit.

**Recipients.** Every payout goes to a validated destination, the caller or the
owner, never to the actor. Actor payouts carry `forward_tos_amount = 0` and a
1-bit empty forward payload, so no notification reaches a recipient. Together
with the self-check, this rules out refund or return loops between token
actors.

**Ledger effects commit at the outcome.** Creating a payout moves its amounts
into the payout record and its `ledger_undo`. Then:

- delivered: the change applies;
- refused at R: the refusal column below applies;
- bounced at S: no token moved, so the actor restores the exact pre-payout
  ledger position. The entry returns to where it was, with its storage-fee and
  bounty amounts, and any revenue debit is re-credited.

  The one exception is kind 4. A funding return has no prior position, so a
  bounce at S is treated like a refusal at R: the amount becomes a returned
  entry for `from`, never surplus.

  "Bounced at S" covers every refusal at S: 712, 713, 714 `refusals_full`,
  insufficient value, an absent ConfigParam 79, and an action-phase failure
  (4.4).
- A `transfer_rereported` whose total equals a pending payout's amount is that
  payout's refusal at R. Every authenticated `transfer_refused` or
  `transfer_rereported` ends in `clear_refusal` (4.4).

A request's TOS side settles once, at the outcome of its payout, and settles
the same way whether that payout is delivered or refused at R:

- `storage_fee - cleanup_bounty` is credited to TOS revenue (D4);
- `cleanup_bounty` is paid to the claimer (`claim_refund`) or to the sweeper
  (sweep).

Only the principal's destination differs between those two outcomes. A bounce
at S reverts the TOS side too.

| Op | Checks | Payout | Delivered | Refused at R |
|---|---|---|---|---|
| `respond` | as SA:680-706 | none | — | — |
| `expire` | as SA:722-749 | none | — | — |
| `claim_refund(request_id, destination)` | as SA:751-772, plus destination validation; the attached TOS covers the reported-transfer budget and the outcome lock | `price` to `destination` (kind 1) | refund done: credit `storage_fee - cleanup_bounty` to TOS revenue, pay `cleanup_bounty` to the claimer, release capacity | same TOS settlement (`storage_fee - cleanup_bounty` to TOS revenue, `cleanup_bounty` to the claimer); a returned entry for the caller with `return_deadline = now + 2,592,000`; release capacity |
| `sweep_expired_request(request_id)` | as SA:789-855 | `price` to the request's caller (kind 2) | credit `storage_fee - cleanup_bounty` to TOS revenue, pay the bounty to the sweeper, release capacity | same TOS settlement (`storage_fee - cleanup_bounty` to TOS revenue, `cleanup_bounty` to the sweeper); a returned entry for the caller as for `claim_refund`; release capacity |
| `withdraw_revenue(token_amount, tos_amount)` | owner only; the TOS part as SA:963-994; `token_amount <= withdrawable_token_revenue`; `revenue_payouts_in_flight < 4` | `token_amount` to the owner (kind 3) | — | re-credit `withdrawable_token_revenue` |
| `claim_returned(id, destination)` (`0x5354430A`) | caller only; the entry exists (else 1931); `paying == 0` (else **1930** `payout_in_flight`); destination validation | `amount` to `destination` (kind 5) | delete the entry | clear `paying`; the entry stays |
| `sweep_returned(id)` (`0x5354430D`) | permissionless; `now >= return_deadline`; `paying == 0` (else 1930) | `amount` to the entry's **caller** (kind 7) | delete the entry | clear `paying`; set `return_deadline = now + 2,592,000` |
| funding return (5.2) | — | `amount` to `from` (kind 4) | — | a returned entry for `from` with `return_deadline = now + 2,592,000`, keyed by the payout id (also on a bounce at S) |
| `recover_surplus(amount)` (`0x5354430B`) | owner only; supersedes any pending balance query | after an accepted `take_balance`: `amount` to the owner (kind 6) | — | the amount stays surplus |
| `recheck_payout(id)` (`0x5354430F`) | permissionless and funded; kind 1, 2, 4, 5 or 7; `now >= created_at + PAYOUT_RECHECK_AGE` (else 1940/1941/1942) | none: a recheck balance query | — | on `surplus' >= amount`: as this kind's "Refused at R" (see "Recheck" below) |
| `abandon_payout(id)` (`0x5354430C`) | owner only; kind 3 or 6; `now >= created_at + PAYOUT_ABANDON_AGE` (else 1938); a pending balance query younger than `RECHECK_QUERY_TTL` refuses it (1943); an older one it clears, and the owner re-queries | — | — | — |

**Bounty on prompt claims.** The D3 incentive note
([`SERVICE_ACTOR_SETTLEMENT_DESIGN.md`](SERVICE_ACTOR_SETTLEMENT_DESIGN.md):407-421)
is fixed: a delivered `claim_refund` pays the `cleanup_bounty` to the claimer.
Claiming promptly is therefore never worse than sweeping.

**No double payout from a returned entry.**

- `claim_returned` and `sweep_returned` set `paying` before they send.
- A second claim, in the same block or later, fails with 1930 while the first
  is in flight.
- The entry is deleted only on delivery.

**Abandon.** `abandon_payout` deletes the payout, releases its
`outcome_fee_lock` and removes its amount from `in_flight`. For kind 3 it also
decrements `revenue_payouts_in_flight`. It credits nothing: the owner bears
the risk, and tokens still in S show as surplus later.

An abandon must not run against a pending answer that still counts the
amount: the amount would leave `in_flight` while that answer is computed.

- While a balance query younger than `RECHECK_QUERY_TTL` is pending,
  `abandon_payout` fails with 1943 and is retried.
- Against an older pending query, it clears the query, and the owner
  re-queries.

**Counters on every exit path.** Payout creation moves the entry out of its
dictionary into the payout's `ledger_undo`. The counters of live entries
change at the outcome, never at creation. `lock` is `locked_outcome_fees`.

| Kind | At creation | Delivered | Refused at R | Bounced at S | Abandoned |
|---|---|---|---|---|---|
| 1 refund | `refundable -= p`; `in_flight += p`; `lock += l` | `in_flight -= p`; `live_count`, caller live, `locked_storage_fees` decrease; TOS settlement; `lock -= l` | as delivered, plus `returned += p`, `returned_count += 1`, caller returned `+= 1` | `in_flight -= p`; `refundable += p`; entry restored; `lock -= l` | not allowed |
| 2 sweep | `pending` or `refundable -= p` (and `pending_count` unchanged); `in_flight += p`; `lock += l` | `in_flight -= p`; `live_count`, caller live, `locked_storage_fees` decrease, and `pending_count -= 1` if the entry was pending; TOS settlement; `lock -= l` | as delivered, plus the returned increments of kind 1 | `in_flight -= p`; liability and entry restored; `lock -= l` | not allowed |
| 3 revenue | `withdrawable_token_revenue -= a`; `in_flight += a`; `revenue_payouts_in_flight += 1`; `lock += l` | `in_flight -= a`; `revenue_payouts_in_flight -= 1`; `lock -= l` | `in_flight -= a`; `withdrawable_token_revenue += a`; `revenue_payouts_in_flight -= 1`; `lock -= l` | as refused | `in_flight -= a`; `revenue_payouts_in_flight -= 1`; `lock -= l` |
| 4 funding return | `in_flight += a`; `lock += l` | `in_flight -= a`; `lock -= l` | `in_flight -= a`; `returned += a`; `returned_count += 1`; `from`'s returned count `+= 1`; `lock -= l` | as refused | not allowed |
| 5 returned claim | `returned -= a`; `in_flight += a`; `paying = id`; `lock += l` | `in_flight -= a`; entry deleted; `returned_count -= 1`, caller returned `-= 1`; `lock -= l` | `in_flight -= a`; `returned += a`; `paying = 0`; `lock -= l` | as refused | not allowed |
| 7 returned sweep | as kind 5 | as kind 5 | as kind 5, and `return_deadline` reset | as kind 5 refused, deadline unchanged | not allowed |
| 6 surplus | `in_flight += a`; `lock += l` | `in_flight -= a`; `lock -= l` | `in_flight -= a` (back to surplus); `lock -= l` | as refused | `in_flight -= a`; `lock -= l` |

**Rechecked** (`recheck_payout` with `surplus' >= amount`). This applies only
to kinds 1, 2, 4, 5 and 7, and exactly as their "Refused at R" column:

| Kind | Rechecked |
|---|---|
| 1 refund | `in_flight -= p`; `live_count`, caller live, `locked_storage_fees` decrease; TOS settlement; `returned += p`, `returned_count += 1`, caller returned `+= 1`; `lock -= l` |
| 2 sweep | as kind 1 refused, including `pending_count -= 1` if the entry was pending |
| 4 funding return | `in_flight -= a`; `returned += a`; `returned_count += 1`; `from`'s returned count `+= 1`; `lock -= l` |
| 5 returned claim | `in_flight -= a`; `returned += a`; `paying = 0`; `lock -= l` |
| 7 returned sweep | as kind 5, with `return_deadline` reset |

Kinds 3 and 6 are never rechecked: they use `abandon_payout`.

**Storage bound.** Each structure is bounded as follows.

- **`payouts`.** Each record exists only while in flight, and is created
  from:
  - a live entry, bounded by `MAX_LIVE_GLOBAL` (SA:202-203);
  - a returned entry, one in flight per entry because of `paying`;
  - at most 4 revenue payouts;
  - at most one surplus payout per accepted balance answer;
  - a self-funded funding return, which is transient (5.2 step 6).
- **`returned`.**
  - Returned entries do **not** hold live-capacity slots.
  - `MAX_RETURNED_PER_CALLER` is 16 and `MAX_RETURNED_GLOBAL` is 10,000.
  - At either cap, admission stops for that caller, or for everyone
    (`accepting_tokens`, 1935).
  - A refusal of a payout already in flight still creates its entry, because
    principal is never dropped or reclassified. Those payouts are refunds and
    sweeps (at most `MAX_LIVE_GLOBAL`) and funding returns. The global bound is
    therefore `MAX_RETURNED_GLOBAL` plus the refunds and sweeps in flight when
    admission stopped, plus refused funding returns.
  - A funding return is refused only when the sender's own, already deployed
    wallet fails the credit. Under B1-B5 that cannot happen: the wallet
    exists, the credit is within supply, and R's gas is capped and funded. So
    under the bounds, funding returns add no returned entry, and the bound is
    `MAX_RETURNED_GLOBAL + MAX_LIVE_GLOBAL`.
  - Outside the bounds, T14 alarms on any returned entry of kind 4.
  - Every returned entry has a `return_deadline`, after which `sweep_returned`
    deletes it on delivery. No entry is permanent.
- **Refusal at R.** With destinations validated, a caller cannot induce a
  refusal at R under B3: the token wallet of any valid owner can be deployed
  and accepts the credit.

**Surplus recovery (owner decision Q5).**

1. **Query.** `recover_surplus` allocates a new payout id as `query_id`. It
   records `balance_query_id = query_id`, `query_floor = query_id` and
   `delivered_since_floor_amount = 0`, then sends `provide_balance` to the
   actor's own wallet in mode 1 + 16.

   At most one balance query is pending at a time. It is either a surplus
   query or a recheck query (below), and the actor records its purpose and its
   `created_at`. Only the latest `balance_query_id` is ever accepted.

   **Supersede rule.** No request may replace or clear a pending query that is
   younger than `RECHECK_QUERY_TTL` (3,600 seconds). That covers
   `recover_surplus`, `recheck_payout` and `abandon_payout` alike. Within the
   TTL each fails with 1943 `balance_query_busy`, and the sender retries.
   Superseding exists only to recover from a lost `take_balance`: once a
   pending query is older than the TTL, any of the three may replace it
   (`abandon_payout` clears it).

   **Liveness.** An answer normally returns within seconds, and it frees the
   slot: the query is cleared whatever the outcome. A griefer therefore cannot
   hold the slot continuously. Each hold lasts one round trip, unless the
   griefer's own answer is lost, and costs a funded request. The victim can
   retry in any gap. A lost answer blocks the slot for at most the TTL.
2. **Correction.** While a query is pending, accepting a `transfer_delivered`
   for any payout with id `>= query_floor` adds that payout's amount to
   `delivered_since_floor_amount` (checked addition).
3. **Answer.** `take_balance` from `own_wallet` is accepted only when its
   `query_id` equals `balance_query_id`. The actor computes:

   ```text
   surplus = balance - delivered_since_floor_amount
             - (pending + refundable + returned + in_flight
                + withdrawable_token_revenue)
   ```

   A negative result is treated as zero.
4. **Pay.** If `amount <= surplus`, the actor creates a kind-6 payout to the
   owner. Otherwise it fails with 1936 `surplus_insufficient`. The query is
   cleared either way.

**Why the answer never over-counts.** Messages from one account to another
are processed in creation order. Compare, for every token, `balance` (as S
saw it when answering) with what the actor subtracts at `take_balance`.

- **A payout with id at or above the floor.** The actor sent it to S after
  `provide_balance`, so S debits it only after answering, and `balance`
  includes it. At `take_balance` it is in exactly one of two states:
  - its delivery has already been accepted, so it has left `in_flight` and is
    counted once in `delivered_since_floor_amount`;
  - it is still in `in_flight`.

  Its refusal, or a bounce, comes from S after `take_balance` and cannot
  overtake. Each such payout is therefore subtracted exactly once, which makes
  this case **exact**.
- **A payout with id below the floor.** The actor sent it to S before
  `provide_balance`, so S debited it before answering, and `balance` excludes
  it.
  - If its outcome was accepted before `take_balance`, its ledger change has
    been applied:
    - delivered: it is gone from both sides;
    - refused, with S's restore before the answer: it is back in both.
  - If it is still in flight, the actor subtracts it as `in_flight` although
    `balance` excludes it. That under-counts. The tokens stay recoverable by a
    later query.
- **Notifications.** Those that S sent before answering are processed before
  `take_balance`. Credits S makes after answering are in neither `balance` nor
  the ledger.

The computed surplus is therefore never more than the true unattributed
balance. It is exact when no payout older than the query is still in flight.

T3 tests the race in which a new payout is delivered between
`recover_surplus` and `take_balance`. The amount correction subtracts it, and
surplus is unchanged.

Surplus is exactly the tokens whose attribution was lost through the sender's
own error, or that the owner gave up:

- underfunded or failed notifications (5.2 step 2);
- transfers sent with no forward amount;
- bridge mints credited straight to the actor (TW:294-326);
- abandoned owner payouts that were in fact refused.

A funded payment that the actor refuses is never surplus. A refused or bounced
return of it is a returned entry for its sender, and admission stops before
the returned store would ever force anything else (`accepting_tokens`).

**Recheck of a stuck buyer payout (`recheck_payout(id)`, `0x5354430F`).** A
buyer's principal must never be stuck permanently. A buyer payout whose
report was lost (4.5, "Outside the bounds") can be resolved from the wallet's
balance, at a bounded cost borne by the owner.

1. **Request.** Anyone may send it, funded.
   - The payout must exist (else 1940 `payout_not_found`).
   - Its kind must be 1, 2, 4, 5 or 7 (else 1941 `recheck_not_allowed`).
   - It must satisfy `now >= created_at + PAYOUT_RECHECK_AGE`, which is
     2,592,000 seconds (30 days) (else 1942 `recheck_too_early`).
   - The actor then issues a recheck balance query exactly as step 1 of
     surplus recovery: a new `query_id`, `query_floor` and
     `delivered_since_floor_amount = 0`, with `recheck_target = id`. It
     follows the supersede rule: within `RECHECK_QUERY_TTL` of a pending
     query it fails with 1943 and is retried.
   - The sender's value pays for `provide_balance`, the `take_balance`
     handling and the conversion. No lock or backing of the actor pays.
2. **Answer.** On the matching `take_balance`:
   - If the target payout no longer exists (its delivery, refusal or
     re-report arrived meanwhile), nothing happens and the query is cleared.
   - Otherwise the actor computes `surplus'`: the surplus of step 3, but with
     the target's `amount` removed from `in_flight`.
   - If `surplus' >= amount`, the payout is **resolved as refused at R**. The
     effects are exactly those of the "Refused at R" column of the counter
     table for its kind:
     - kinds 1 and 2: a returned entry for the request's caller, with the TOS
       side settled;
     - kind 4: a returned entry for `from`;
     - kinds 5 and 7: the entry's `paying` cleared.

     The lock is released, and `SAO1` is emitted with outcome `rechecked`.
   - Otherwise the payout stays `paying`. The query is cleared either way.

**It never pays from another customer's liabilities.** `surplus'` subtracts
every other liability in full (`pending`, `refundable`, `returned`,
`withdrawable_token_revenue`), plus every other payout in `in_flight`. It
removes only the target's own amount. The case argument of surplus recovery
applies unchanged to every other token: each is subtracted at least once.

The target is older than the query, so S handled it long before answering.

- **If it was refused at R and not recorded,** S restored its tokens before
  the answer. `balance` includes them, and `surplus' >= amount` holds.
- **If it was actually delivered and only the report was lost,** `balance`
  excludes it. `surplus' >= amount` then holds only if at least `amount` of
  unattributed surplus exists, and the conversion pays the buyer again out of
  that surplus.

**The owner bears that double payment.** It is bounded per payout by its
`amount`, and in total by the unattributed surplus. That surplus is tokens
the owner could otherwise recover (Q5), never another customer's.

**Late reports after conversion.** The payout is gone, so later reports
change nothing:

- a late `transfer_delivered` finds no payout and is ignored;
- a late `transfer_refused` or `transfer_rereported` finds no payout and is
  answered with `clear_refusal` only (4.4).

**Outcome log.** Every outcome emits `SAO1` (`0x53414f31`) `payout_id:uint64
kind:uint3 request_id:uint64 recipient:MsgAddressInt amount:Coins
outcome:uint3`. The outcome values are:

| Value | Outcome |
|---|---|
| 0 | delivered |
| 1 | refused at R |
| 2 | bounced at S |
| 3 | rechecked |
| 4 | mismatch, logged only (4.4) |
| 5 | abandoned |

A request is **refunded** or **swept** only when its payout is
delivered. A refused refund or sweep leaves it **returned**, a new
buyer-visible state with the action `claim_returned`.

### 5.5 Operation and exit codes

The ops use the prefix `0x5354430x`:

| Op | Code |
|---|---|
| `respond` | 02 |
| `expire` | 03 |
| `claim_refund` | 04 |
| `sweep_expired_request` | 05 |
| `update_policy` | 06 |
| `rotate_attestor_key` | 07 |
| `revoke_attestor` | 08 |
| `withdraw_revenue` | 09 |
| `claim_returned` | 0A |
| `recover_surplus` | 0B |
| `abandon_payout` | 0C |
| `sweep_returned` | 0D |
| `recheck_payout` | 0F |

The `token_call` payload tag is `0x53544301`. The actor also handles the
outcome inputs of 4.4 and `take_balance`.

Exit codes keep 1900-1929 with their meanings
([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md) section 9) and add:

| Code | Name |
|---|---|
| 1930 | `payout_in_flight` |
| 1931 | `returned_not_found` |
| 1932 | `asset_route_invalid` |
| 1933 | `asset_not_recognized` |
| 1934 | `invalid_destination` |
| 1935 | `not_accepting_tokens` |
| 1936 | `surplus_insufficient` |
| 1937 | `exposure_cap` |
| 1938 | `abandon_too_early` |
| 1940 | `payout_not_found` |
| 1941 | `recheck_not_allowed` |
| 1942 | `recheck_too_early` |
| 1943 | `balance_query_busy` |

On the notification path these appear only as `SAF1` reasons, never as a
throw.

### 5.6 The actor's TOS floor and its own wallet

**Backing.** After every admission and withdrawal, the actor's balance, net of
the incoming message, must cover `locked_storage_fees + locked_outcome_fees +
MINIMUM_OPERATING_RESERVE` (1 TOS, SA:181), as in SA:227-236.

- A payout op adds its `outcome_fee_lock` from the requester's attached TOS.
- `withdraw_revenue` never takes TOS that a lock needs.
- Storage rent can still erode the reserve, as on the native actor
  (SA:180).
- The provider runtime keeps the balance above a configured floor (T8).

**The actor's own token wallet holds every customer's principal.** A wallet
deleted for storage debt loses its balance (SP:792-794, SP:819). Controls:

- every incoming transfer tops up its storage reserve (TW:159-161);
- every reported transfer's value check includes `wallet_min_tos_for_storage`
  (4.3);
- the provider runtime monitors the wallet's TOS balance and tops it up with a
  plain transfer (TW:627), as the bridge requires for minters (SP:814-817);
- the wallet-floor pause
  ([`MCP_PROVIDER_ADAPTER_V1.md`](MCP_PROVIDER_ADAPTER_V1.md):294-299)
  extends to this wallet.

These controls are operational, not a contract guarantee. The buyer preview
states this, and B4 depends on it.

### 5.7 Storage, release and code hash

**Storage.** Compared with the native layout
([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md) section 4), the actor
adds:

- the asset route reference;
- `next_payout_id`;
- the `payouts` and `returned` dictionaries;
- the counters of 5.4;
- the two revenue counters;
- `max_token_liability`;
- the new liabilities and locks.

Accounting splits into a native cell and a token cell.

**Release.** As for the native pair
([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md):14-44):

- release manifests `crypto/smartcont/tos-service-actor-token-v1.release.json`
  and a test-only `tos-service-actor-token-v1-test.release.json` with
  600-second windows;
- `scripts/check-service-actor-bytecode.py` covers both codes;
- conformance vectors are generated from contract execution. They cover the
  deployed data, the token terms and `terms_hash`, `SAT1`, `SAF1` and `SAO1`,
  every funding outcome, every payout kind and outcome, and a surplus recovery.

Clients pin the token release hash for this rail only.

**Native actors keep working.** The native code and release hash, the rail
string `tos.service.service-actor.v1`, manifest key 20 `native-tos`, Accepted
Quote schema 1 and Receipt schema 1 are all unchanged. `ai` selects the
verifier by the key 21 rail string and the pinned code hash.

## 6. `ai` changes

The identifiers this section introduces are unused today:

- **ConfigParam 84.** `crypto/block/block.tlb` has no `ConfigParam 84` entry:
  its token entries end with 83 at TLB:890. A search of tos `crypto/` and
  `crosschain/` for `ConfigParam 84` finds nothing.
- **Proto fields 18 and 19.** Neither copy of `native.proto` has a field
  numbered 18 or 19: a search for `= 18;` and `= 19;` finds no match in
  `spec/proto/tos/service/v1/native.proto` or
  `protocol/api/tos/service/v1/native.proto`.
- **Accepted Quote schema 3.** The Accepted Quote defines schema 1 only
  ([`ACCEPTED_QUOTE_TVM_V1.md`](ACCEPTED_QUOTE_TVM_V1.md):22), and schema 2 is
  retired (:15-17).
- **Receipt schema 2.** The Receipt defines schema 1 only
  ([`SOFTWARE_WORK_RECEIPT_TVM_V1.md`](SOFTWARE_WORK_RECEIPT_TVM_V1.md):19).

### 6.1 Asset identity in every object

**Capability manifest** ([`SOFTWARE_WORK_MANIFEST_V1.md`](SOFTWARE_WORK_MANIFEST_V1.md),
edited in place as D6 was).

- Key 20 stays exactly one entry:
  - either `{0: "native-tos"}`;
  - or `{0: "tos-token", 1: <32-byte master account id>, 2: <32-byte wallet
    code hash>, 3: <decimals>}`.
- The token entry equals the actor's asset route and a pinned ConfigParam 84
  record with status 1 at the admission checkpoint.
- Key 21 field 1 admits `tos.service.service-actor-token.v1`; field 4 must then
  equal the token release hash.
- Any cross-combination of rail and asset is refused.
- `manifest.go`:219-221 gains the second form, and the negative corpus gains a
  case for each mismatch.

**Quote Proposal.** Both copies of `native.proto` add `TOSAssetIdentityV1 asset
= 18;` (the message unchanged, :333-337) and `string price_atomic = 19;`.

- Exactly one of `price_nanotos` or (`asset` with `price_atomic`) is set.
- `storage_fee_nanotos` stays in nanoTOS on both rails.

**Accepted Quote** ([`ACCEPTED_QUOTE_TVM_V1.md`](ACCEPTED_QUOTE_TVM_V1.md)).
Schema 3 is the token-rail layout. Schema 2 is retired, so its number is not
reused (:15-17).

```text
accepted_quote$_ magic:uint32=0x4e415131 schema:uint16=3
  ^network_domain ^identity ^rail ^authority = AcceptedQuoteTokenV1;
rail$_ actor:MsgAddressInt actor_code_hash:uint256 policy_version:uint32
  ^rail_terms ^asset = QuoteTokenRailV1;
rail_terms$_ terms_hash:uint256 price_atomic:Coins storage_fee:Coins
  = QuoteTokenRailTermsV1;
asset$_ master:MsgAddressInt minter_code_hash:uint256
  wallet_code_hash:uint256 decimals:uint8 = QuoteAssetV1;     -- 787 bits
```

`ServiceRequestV1` is unchanged. It commits to `quote_commitment`, which now
binds the asset.

**Receipt** ([`SOFTWARE_WORK_RECEIPT_TVM_V1.md`](SOFTWARE_WORK_RECEIPT_TVM_V1.md)).
Schema 2 is the token-rail layout:

```text
economic_v2$_ charged_atomic_amount:uint128 asset_master:uint256
  provider_agent_id:uint256 = ReceiptEconomicV2;
```

The charge equals `price_atomic`, and the master equals the Quote's. Attestor
custody refuses anything else (D9).

### 6.2 Atomic units and decimals

- **Encoding.** Token amounts are unsigned atomic units, written as canonical
  base-10 text ([`SETTLEMENT.md`](SETTLEMENT.md):58-66) and kept below `2^120`.
- **Decimals.** They come only from the ConfigParam 84 record, cross-checked
  against the minter (3.1).
  - Display divides by `10^decimals` in integer arithmetic, never floating
    point.
  - Bridged USDC carries the source token's decimals in the minter content
    (TU:100-119; BS:293-296), which is 6 for Ethereum USDC.
  - The design assumes no scaling between source units and TOS atomic units.
    T1 confirms this on the mint path.
- **Aggregation** is per exact asset identity, never per ticker
  ([`AGENT_ECONOMY_METRICS_V1.md`](AGENT_ECONOMY_METRICS_V1.md):182-184).

### 6.3 Price per asset

One actor has one asset (5.1). A provider selling in TOS, USDC and USDT runs
one actor per asset, published as separate Capability versions or
Capabilities.

**Two pinned assets, treated independently.** `ai` clients pin both the USDC
and the USDT ConfigParam 84 entries (3.1).

- **No mixing.** Each asset has its own release pins, actors, quotes, budgets
  (`max_per_call_atomic`, `max_window_atomic` per asset, 6.4) and aggregation
  ([`AGENT_ECONOMY_METRICS_V1.md`](AGENT_ECONOMY_METRICS_V1.md):182-184). A
  price in one is never converted into, or netted against, the other.
- **Asset failures stay local; bridge failures do not.** A suspended entry, an
  issuer freeze, or a failing asset affects only that asset's actors and
  purchases. Both assets cross the same bridge, though:
  - a bridge or oracle failure stops minting and redemption for both;
  - so does the exhaustion of the bridge's shared windows: at most
    `SWAP_WINDOW = 16` EVM locks in flight at once, and at most
    `CHANNEL_LIMIT = 8` minters per bridge (`settlement.fc`:125-126 under
    `tvm/contracts/`).
  - `Bridge.sol` keeps only a deny list (BS:21, BS:132), so locks of junk
    ERC-20 tokens can occupy minter channels and the swap window.
  - The controls are an oracle-side token allowlist (SEC:111), and opening
    the USDT minter's channel early. Both are in T12 and T16, and the oracle
    rule is in T11.
- **Display.** The buyer preview names the asset by its pinned identity. The
  ticker is display only.

### 6.4 Components

| Component | Change |
|---|---|
| `protocol/pkg/nativecore` | Codecs for the token terms, `SAT1`, `SAF1`, `SAO1`, schema 3 Accepted Quote, schema 2 Receipt and the key 20 token entry; the token release hash. |
| `protocol/pkg/toschain` | The ConfigParam 84 reader, with the self-verification of 3.1. It decodes the whole value strictly by TL-B and uses pinned entries only; more than 16 entries is a T14 alarm, not an error. It reads the bridge account, requires the bridge code, `b_minter_code` and `b_wallet_code` to equal the three pinned release hashes, derives the master with those codes, and checks the master's deployed code. Every read is at one masterchain seqno, using archive state for historical checks; actor-wallet derivation; history decoding of notifications, reports, balance answers and outcome logs. |
| `protocol/pkg/serviceactor` | Both verification procedures ([`SERVICE_ACTOR_SETTLEMENT_DESIGN.md`](SERVICE_ACTOR_SETTLEMENT_DESIGN.md) section 2.4) for the token rail. Added checks: the asset route equals the manifest, the Quote and a pinned status-1 record; the funding notification came from the actor's derived wallet with the exact amount. New states: `paying` and `returned`. |
| `protocol/pkg/buyersdk` | Builds the token transfer with the `token_call` payload. Refuses a `forward_tos_amount` below the full budget of 5.2, and validates destinations as 5.4 does. The journal records the transfer, the notification transaction and its `SAT1` or `SAF1`. Duties: `expire`, `claim_refund`, and `claim_returned` while a returned entry exists, including one from a refused funding return. The preview states that underfunded or forward-less tokens become the provider's. |
| `provider` (`servicebridge`, `tos-service-provider`, MCP provider) | Offers in atomic units within per-asset offer bounds ([`MCP_PROVIDER_ADAPTER_V1.md`](MCP_PROVIDER_ADAPTER_V1.md):201-206); `max_token_liability`; withdrawal of both revenues, with in-flight and refused outcomes; `recover_surplus` and `abandon_payout` behind confirmation; the actor TOS floor and the token-wallet floor (5.6). |
| MCP buyer (`tos-service-buyer-mcp`) | Budgets per asset (`max_per_call_atomic`, `max_window_atomic`) on top of the existing nanoTOS limits ([`MCP_BUYER_ADAPTER_V1.md`](MCP_BUYER_ADAPTER_V1.md):1008-1020). The preview shows the price in the asset and every TOS cost separately ([`SETTLEMENT.md`](SETTLEMENT.md):152-155), and states 5.6. |
| `tos-service-verify` | Accepts the token release hash; verifies the recognition record at the call checkpoint, the funding notification chain and the outcome logs. Its usage gains an asset option (`protocol/cmd/tos-service-verify/main.go`:44-46). |
| `purchaseevidence` | Adds the ConfigParam 84 value hash at the checkpoint, the funding transactions and the outcome transactions ([`PURCHASE_EVIDENCE_V1.md`](PURCHASE_EVIDENCE_V1.md)). |
| gateway (`internal/quotesource`) | Builds token Quote Proposals from finalized actor state and the pinned record, and pins both release hashes. It has no authority and holds no balance. |

### 6.5 What stays nanoTOS

These stay in nanoTOS:

- network fees;
- the storage fee and cleanup bounty;
- the 0.2 TOS allowances (SA:187-188) and `RETURN_BUDGET`;
- the outcome locks and the operating reserve (SA:181);
- the attached TOS of each token transfer;
- registry operations.

There is no pilot fee sponsorship (Q4). A buyer agent therefore holds:

- USDC for the price;
- TOS for its wallet fee, the token transfer value, the full
  `forward_tos_amount` of 5.2 and, for a refund, the claim's attached value.

A USDC-only buyer is not supported in v1.

## 7. Bridge production path for USDC and USDT

### 7.1 Preconditions

From the bridge itself (BR:3, BR:150-152, SEC:97-113):

- two independent audits of the exact build;
- an oracle key ceremony, with HSM keys, operator diversity and a quorum of
  2/3 or more;
- per-token, per-transaction, hourly and daily caps;
- timelocked governance;
- reconciliation indexers;
- pause drills;
- token allowlisting;
- the bridge listed in ConfigParam 31;
- a deployment inventory;
- a canary approved through TOS governance;
- a bug bounty.

Only durable settlement is done (SEC:99), and no slot is populated (BR:78).

Added by this design:

- the reported-transfer and balance-report wallet (T1), in the audited build;
- ConfigParam 84 (T2);
- TOS-side exposure caps: `max_liability_per_actor` per asset (3.1) and
  `max_token_liability` per actor (5.1). The aggregate per-asset exposure is
  bounded by the bridge's per-token caps (SEC:105) and watched by monitoring
  (T14); no on-chain state sums it across actors;
- a USDC review under SEC:111. USDC is an upgradeable contract whose issuer
  can blacklist addresses and pause transfers (external fact). A blacklisted
  bridge lock address would freeze the USDC that backs the wrapped supply on
  TOS. The TOS-side responses are those of 3.1.
- **A blacklisted unlock receiver** (USDC and USDT alike).
  - A recorded burn on TOS is final, but `unlock` to a blacklisted, or
    paused, receiver reverts every time (BS:206). Those tokens are then
    unredeemable to that receiver.
  - Redemption tooling therefore reads the issuer contract's blacklist and
    pause state for the receiver on Ethereum before it builds the burn. It
    refuses a blacklisted receiver, and the burn preview warns about the
    finality.
  - The check is in T10 and T12.

### 7.2 Relayer gap

The relayer has no live path:

- `crates/relayer/src/main.rs`:96-99 bails with "the relayer has no live-node
  path yet";
- the binaries are "skeletons only" and the audit is "not started"
  (`README.md`:115-116);
- the same README's line 7 says "Nothing here is implemented yet."

Its protocol is older than v5:

- `docs/protocol.md`:159-171 votes `ext_chain_hash, internal_index, addr_hash,
  mint_jetton_amount, ^wrapped_token_data, forward_coins_amount`, keyed by
  `cell_hash(ext_chain_hash, internal_index)` (:342-351);
- it names `jetton-bridge.fc` (:173, :342) and `"protocol_version": 1`
  (:365).

The v5 bridge, by contrast:

- decodes `generation:uint32, n:uint64, evm_chain_id:uint32,
  evm_bridge:uint160, recipient_hash:uint256, amount, ^wrapped_token_data`
  (TB:304-311);
- keys payments by `n` (TB:320-322);
- adds `cancel_lock` and `activate_generation` votes (TB:441-444).

Until the relayer implements v5, mints need a stand-in oracle (T5).

### 7.3 Home network: Ethereum (decided)

The owner chose Ethereum (ConfigParam 79) and left the second slot empty
(Q1). The alternatives that were weighed follow. Statements about Circle's
issuance are external facts, to be confirmed against Circle's published
contract list before the slot is populated.

| Home | For | Against |
|---|---|---|
| **Ethereum (79)** (chosen) | Circle's original issuance; deepest liquidity; slot and params exist | Highest lock and unlock gas for users; slower finality |
| Polygon PoS (82) | Native Circle USDC; cheap | Two USDC contracts (native and the older bridged one); reorg history needs deeper confirmation |
| Base or Arbitrum | Native USDC; cheap | No bridge slot or params exist |
| BNB Smart Chain (81) | Supported slot | Its USDC is not Circle-issued |
| Tron (83) | Supported slot | Chain id is derived, not observed (BR:80, BR:148); Circle issuance there is discontinued (external fact) |

### 7.4 What the TOS side must recognize

Two ConfigParam 84 records, one for each minter that the production bridge
derives. Both have the same bridge and the same reported-transfer wallet code,
but each has its own derived minter, because the minter address depends on
the content (TU:44-56):

| Field | USDC (first) | USDT (second) |
|---|---|---|
| `chain_id` | 1 | 1 |
| `token_address` | Circle's USDC contract on Ethereum | Tether's USDT contract on Ethereum |
| `decimals` | 6 | 6 |
| wallet code | the reported-transfer wallet | the same |
| bridge | the production bridge address | the same |
| `max_liability_per_actor` | set for the canary | set for its own canary, independently |

Both token addresses are external facts, to be confirmed against the issuers'
published contract lists before the vote. Each record follows the same
critical vote and the same bridge-anchored re-derivation (3.1). The USDT
record is proposed only after the USDC path has run end to end (section 8).

The TOS side also needs ConfigParam 79 populated for the new bridge address
(4.7), and the bridge listed in ConfigParam 31 (SEC:101). Recognition is
proposed only after the canary has run under the caps.

**Bridge migration.** Any change of `bridge_address` in ConfigParam 79 makes
the existing record's bridge check fail (3.1). Its old minter is no longer the
listed bridge's.

- The record's status 2 or 3 must therefore be adopted **before** that change.
  A proposal sets one parameter, and 84 (critical, 3 won rounds) and 79
  (ordinary, 2) cannot share a vote. Proposal tooling refuses a ConfigParam 79
  `bridge_address` proposal while a record of the old bridge still has status 1.
- A new record for the new bridge's minter follows separately.

Existing requests keep settling, because no payout reads recognition (5.3).
Verifying them historically uses archive state at their admission seqno
(3.1).

### 7.5 USDT: what the bridge already handles, and its own risks

**What `Bridge.sol` already handles.** Line numbers are BS, identical at
`db4503c02` and at tos main `b82c4ad58`:

- **No boolean return.** USDT's `transfer` and `transferFrom` return no
  `bool`. The bridge uses OpenZeppelin `SafeERC20` (BS:5, BS:18) for every
  token call:
  - `safeTransferFrom` in `lock` (BS:137);
  - `safeTransfer` in `unlock` (BS:206);
  - `safeTransfer` in `refundLock` (BS:174).
- **Fee switch on locks.** USDT has a transfer-fee switch, currently zero
  (external fact). `lock` credits the **balance delta**, not the requested
  amount: `received = newBalance - oldBalance` (BS:135-147). The lock record,
  and the `Lock` event that the oracles mint from, both carry `received`
  (BS:148-159). A non-zero fee therefore mints on TOS exactly what the bridge
  received.
- **Fee switch on payouts.** `unlock` and `refundLock` send the recorded
  amount with `safeTransfer`. `unlock` then reads the new balance only for its
  event (BS:206-208). Neither credits by delta. With a non-zero fee, the
  Ethereum receiver gets the amount less Tether's fee, while the bridge's
  balance falls by the full amount, so the backing stays exact. The shortfall
  falls on the receiver and is shown to them (below).
- **Approval race.** USDT's `approve` refuses to change a non-zero allowance to
  another non-zero value (external fact).
  - The bridge never calls `approve`. `Bridge.sol` has no such call, so the
    bridge itself is unaffected.
  - The locker's own approval is a client concern. Lock tooling approves the
    exact amount, and first resets any non-zero allowance to zero.
- **Decimals.** USDT reports 6 decimals (external fact). `getDecimals`
  (BS:292-300) passes them into the `Lock` event, and from there into the
  minter content (TU:100-119). As for USDC, no scaling happens.

  USDT declares `decimals` as `uint256`, while the bridge's interface expects
  `uint8` (BS:13-15). The call decodes correctly only because the value, 6,
  fits in `uint8`. T10 checks this against the deployed contract.
- **Token disable.** Oracles can disable or re-enable a token by vote
  (`voteForDisableToken`, BS:242-258); `lock` refuses a disabled token
  (BS:132). This is the source-side stop for new USDT locks.
- **Upgradeable issuer contract.** Tether's contract can be deprecated in
  favour of an upgraded implementation that it forwards calls to (external
  fact), so its behaviour can change after review. The behavioural review
  below repeats on every such change.

No USDT-specific contract code is needed.

**Risks and controls.**

- **Blacklist freeze.** Tether can blacklist addresses (external fact).
  - **Effect.** A blacklisted bridge contract can no longer send USDT, so
    `unlock` and `refundLock` fail, and the bridged USDT on TOS loses its
    redeemable backing.
  - **TOS-side holders.** TOS holders still hold their tokens: TOS
    transfers, actor payouts and refunds keep working, because none of them
    touches Ethereum. But redemption to Ethereum stops, and the wrapped token
    trades at whatever the market believes about an unfreeze.
  - **Destroy and pause.** Tether can also destroy a blacklisted address's
    balance (`destroyBlackFunds`) and pause the whole contract (external
    fact).
    - If the bridge's USDT balance is destroyed, the wrapped supply on TOS is
      **permanently unbacked**. No unfreeze can restore it.
    - A pause stops `unlock`, `refundLock` and `lock` alike until it is
      lifted.
  - **Source-side stop.** When the freeze alarm fires, the oracles vote at
    once:
    - `voteForDisableToken(USDT)` (BS:242-258), after which `lock` refuses the
      token (BS:132); or
    - `voteForSwitchLock` (BS:229-239), which stops every lock.

    The reason is that Tether's `transferFrom` is believed to check only the
    sender's blacklist status, not the recipient's (external fact, to be
    confirmed against the deployed contract). A `lock` into a blacklisted
    bridge may then still succeed, and mint wrapped USDT that can never be
    redeemed. This step is in the T14 runbook.
  - **TOS-side response.** ConfigParam 84 status 2 for the USDT entry stops
    new purchases (3.1). Existing requests settle in the frozen token, as
    admitted. No on-chain automatic stop is possible, because no TOS contract
    can observe Ethereum. Two defaults stand in for one:
    - **Provider auto-pause.** The provider runtime clears `active` on its own
      USDT actors when a T14 freeze, pause or destroy alarm fires. This is
      the provider's own signed `update_policy` (T8, T18).
    - **Buyer refusal.** Buyer clients refuse USDT by local policy while the
      alarm is up. They read the Ethereum state themselves: the bridge's
      blacklist status and the contract's pause.
  - **Controls:**
    - a per-token lock cap on the EVM side (SEC:105), so that exposure is
      bounded. `Bridge.sol` has no cap today, only the supply bound
      (BS:143). The cap is bridge code that SEC:105 requires for every
      token, USDC included; it is not USDT-specific;
    - `max_liability_per_actor` for the USDT entry;
    - T14 monitoring of the bridge address's blacklist status in the USDT
      contract, and of Tether's pause and `destroyBlackFunds` events.
- **Blacklisted unlock receiver.** As for USDC (7.1), redemption tooling
  checks the receiver's blacklist and pause status before building a burn.
- **Fee switch.**
  - Locks credit the delta, as above.
  - Every buyer-facing and redeemer-facing preview shows the **received**
    amount, not the sent one:
    - for a lock, the amount minted;
    - for an unlock, the amount after Tether's fee.

    On TOS no fee applies: wallet transfers are exact.
- **Regulatory exposure.** The trend that made the owner prefer USDC (team
  memo STATUS 13.580) applies to USDT more strongly. The owner's order is
  therefore USDC first, and USDT as the second asset only after the USDC path
  is proven.
- **Upstream incident.** The upstream bridge's issue `token-bridge-solidity#12`
  reports 3,000 USDT stuck after jUSDT minting was disabled. A lock was taken,
  but could no longer be minted or returned (team memo
  `crosschain/BRIDGE-PROVENANCE-AUDIT-20261125.md`:29). This bridge's change 13
  covers that case: an oracle vote `cancel_lock` makes the lock terminally
  cancelled on TOS, and only then may oracles sign the EVM `refundLock`, which
  returns it once (SEC:65; README.md:37; BS:165-176).
- **Behavioural review.** SEC:111 requires an explicit analysis of
  fee-on-transfer, rebasing and blacklisting ERC-20s. USDT has a fee switch,
  a blacklist and an upgrade path, though it does not rebase. Its review is
  therefore part of the T12 audit scope.

## 8. Work breakdown

Sizes: S is up to 1 week, M is 1-3 weeks, L is 3-6 weeks, and XL is external
or longer. T1-T10, T13 and T14 run on local and test networks with a test
USDC. T11 and T12 gate production.

**Order: USDC end to end first, then USDT as configuration.** USDT adds no new
contract code (7.5). Its work is listed in T15-T18 and in the USDT parts of
T10, T12 and T14. That work starts once USDC has passed T1-T10 on testnet.

The per-token EVM lock cap (T16) is bridge code that SEC:105 requires for
every token. It is listed with USDT because USDT's blacklist makes it urgent,
but it gates USDC production too.

| # | Repo | Item | Depends on | Acceptance | Size |
|---|---|---|---|---|---|
| T1 | tos | **Implemented:** tosnetwork/tos#512, head `0a3bdbe78`, approved; tests T-R1 to T-R15 (RSP:1835-1864). `token-wallet.fc`: the reported transfer and the balance report (4.3); `R_GAS_LIMIT`, `S_BOUNCE_GAS` and `S_TRANSFER_GAS`; the body cap (713); additive refusal records under `REFUSALS_LIMIT` (714); `transfer_rereported`; the network-priced value check, including S's compute and the action fine; `get_compute_fee` and `get_forward_fee` in the bridge stdlib (global version 6 or later, STD:272-276; `settlement.fc` already had equivalents); +16 on the reported sends and on the ordinary notification (a behaviour change, 4.7); a `SETTLEMENT-PROTOCOL.md` section; `verify-token-bridge.py` invariants; regenerated fixtures and evidence (4.7) | — | Sandbox on both VMs covers:<br>• delivered;<br>• refused at R by compute failure, by **R out of gas** (the bounce is still funded) and by action failure;<br>• an **S action-phase failure** (bounces to P);<br>• every S compute refusal;<br>• **ConfigParam 79 `wallet_gas_consumption` set too low** (the network-priced check still holds);<br>• **a gas or forward price change between legs**, within and beyond `REPORT_MARGIN`;<br>• rereport, clear, and a duplicate query id;<br>• spoof attempts (excesses, foreign delivered, forged refused), all ignored;<br>• `provide_balance`;<br>• `capBounceMsgBody` turned off fails the suite (pins the dependency).<br>Also: supply and balance are conserved in each case; each guard goes red when removed; gas is measured per leg; the mint path does no scaling. | L |
| T2 | tos | ConfigParam 84 TL-B; a typed JSON-RPC view; 84 listed in ConfigParam 10 in genesis (GZ:414, GZ:419); `tosctl` decode and a proposal value builder that refuses more than 16 entries, a value over the 1,024-cell validation budget (actual cell count), and any value that fails the full TL-B (3.1); the proposal path refuses ConfigParam 84 until every current validator reports a node release with its TL-B (rollout precondition, 3.1) | — | Round trip through `getConfigParam`; an uncritical proposal is refused (CFG:596-601); malformed records are refused by the decoder and by the builder; **a node without the ConfigParam 84 TL-B refuses a configuration containing 84** (the halt the precondition prevents, shown in a sandbox or local net); the proposal path refuses while any validator reports an older release | M |
| T3 | tos | `service-actor-token-code.fc` (section 5); Rust builders and decoder; sandbox; release manifests; bytecode check; vectors; exposure caps | T1, T2 | Every native sandbox case ported, plus:<br>• spoofed and foreign notifications;<br>• underfunded and below-`MIN_FUNDING_VALUE` notifications (nothing stored; surplus);<br>• a **malformed or absent ConfigParam 84** and a **malformed payload**, each taking the refusal path without a throw;<br>• every admission refusal ending in a funding return, with no stranded token;<br>• the exact-amount rule, status 2 and the exposure caps;<br>• every payout kind × {delivered, refused at R, bounced at S};<br>• **a double `claim_returned` in one block** (1930);<br>• **destination validation** (non-std, anycast, wc != 0, self: 1934);<br>• returned-entry caps and `sweep_returned`;<br>• a flood of refused fundings, leaving no entry and no surplus;<br>• a refused or bounced funding return becoming a returned entry for `from` (never surplus), then claimed, double-claimed (1930) and swept to `from` after the deadline;<br>• `accepting_tokens` false at `MAX_RETURNED_GLOBAL`, with no money reclassified;<br>• senders off workchain 0 refused (1934);<br>• surplus recovery, covering:<br>&nbsp;&nbsp;– a notification in flight before `take_balance`;<br>&nbsp;&nbsp;– **the race where `recover_surplus` is followed by a new payout whose delivery arrives before `take_balance`** (subtracted through `delivered_since_floor_amount`, so surplus is unchanged);<br>&nbsp;&nbsp;– an older payout still in flight (under-counted, never over-counted);<br>&nbsp;&nbsp;– a superseded query whose late `take_balance` is ignored;<br>• `abandon_payout`, checking every counter of the exit-path table, refused (1943) by a pending query younger than the TTL and clearing an older one;<br>• a failing in-handler send (bounty, `clear_refusal`, change) that leaves the outcome committed;<br>• **`transfer_rereported`**:<br>&nbsp;&nbsp;– for a pending payout, applied as its refusal and answered with `clear_refusal`;<br>&nbsp;&nbsp;– for an absent payout, answered with `clear_refusal` only;<br>&nbsp;&nbsp;– never swallowed by the catch-all;<br>• **a 714 `refusals_full` bounce from S** handled as an ordinary S refusal (pre-payout position), and likewise 712 and 713;<br>• **no permanent halt**: S driven to 32 records by refusals whose reports were dropped, then funded re-reports clear every record, and the next payout succeeds;<br>• a refusal at the limit that is not recorded and whose report is dropped: the payout stays `paying` and the tokens are back at S, and for kinds 3 and 6 recovery goes through `abandon_payout` and surplus;<br>• **`recheck_payout`**, covering:<br>&nbsp;&nbsp;– each buyer kind (1, 2, 4, 5, 7) after an unrecorded refusal whose report was dropped, converted to a returned entry with counters as the table;<br>&nbsp;&nbsp;– a lost delivery report with no surplus, where the payout stays `paying`;<br>&nbsp;&nbsp;– a lost delivery report with enough surplus, where the double payment comes from surplus only and every other liability stays backed;<br>&nbsp;&nbsp;– a late delivery or re-report after conversion (ignored, or `clear_refusal` only);<br>&nbsp;&nbsp;– the target resolved while the query is pending (no-op);<br>&nbsp;&nbsp;– kinds 3 and 6 refused (1941), too early (1942), and an absent id (1940);<br>&nbsp;&nbsp;– the supersede rule for each pair of `recover_surplus`, `recheck_payout` and `abandon_payout`: 1943 within `RECHECK_QUERY_TTL` of a pending query, superseded (or cleared) after it;<br>&nbsp;&nbsp;– a griefer loop of back-to-back queries does not block a victim's recheck indefinitely: the victim lands in a gap after an answer;<br>&nbsp;&nbsp;– a lost answer blocks the slot for at most the TTL;<br>• **a refusal report funded by the payout:** refused at R after a 9× price rise between the legs, with the ConfigParam 79 storage reserve at 0 and S at `REFUSALS_LIMIT`; the `transfer_refused` is delivered and the payout ends as refused;<br>• **a re-report mismatch** (a pending payout, another total): not cleared, logged;<br>• the measured gas of the actor's absent-payout re-report handler, published for re-reporters (4.4);<br>• **no gas drain (rule of 2.3):** for each actor handler, send a forged message (wrong sender, wrong amount or recipient, unknown payout or query id) and an underfunded genuine-shaped one. The actor's TOS balance, excluding the message's own value, is unchanged afterwards, and the code contains no `accept_message` and no raising `set_gas_limit` outside the authenticated outcome handlers.<br>Also: the token invariant is checked after every step, and gas is measured on both VMs at capacity for every op and for `PRE_ACCEPT_GAS` and `OUTCOME_HANDLER_GAS`. | L |
| T4 | tos | `tosctl`: a token transfer with `token_call` and `--build-only`; `claim_returned`, `sweep_returned`, the two-part `withdraw_revenue`, `recover_surplus` and `abandon_payout`; top-ups of the actor and its wallet | T3 | The `--build-only` output is reproduced by `buyersdk` byte for byte; a below-budget forward and an invalid destination are refused | M |
| T5 | tos-ops | Test USDC on the local net and the public testnet: a test bridge, a stand-in oracle signing v5 votes, ConfigParams 79 and 84 through `testnet-governance.py` (84 as critical), and a CEREMONY addendum | T1, T2 | `adopted` shows both params on every validator (CEREMONY:797); a test mint reaches a buyer wallet | M |
| T6 | ai `spec/` | `SERVICE_ACTOR_TOKEN_TVM_V1.md`; the in-place edits of section 9; both proto copies; the T3 vectors copied byte for byte | T3 | The spec vectors equal the tos fixture; a negative corpus exists for every new rule | M |
| T7 | ai `protocol/` | nativecore, toschain, serviceactor, buyersdk, purchaseevidence, `tos-service-verify` | T4, T6 | Every vector is reproduced; every state, including `paying` and `returned`, is derived from finalized data at one checkpoint; a mismatched master, wallet code hash, decimals or status is refused; unpinned ConfigParam 84 entries are ignored | L |
| T8 | ai `provider/` | Token offers; both withdrawals; recovery and abandon; the floors; MCP provider tools | T7 | The `MCP_PROVIDER_ADAPTER_V1.md` section 10 cases are extended to a token actor. **Default auto-pause:** on a T14 freeze, pause or destroy alarm for an asset, the provider runtime clears `active` on its own actors of that asset with its own signed `update_policy`, and a test shows that it does | M |
| T9 | ai MCP buyer, gateway | Per-asset budgets and preview; gateway token proposals | T7 | The `MCP_BUYER_ADAPTER_V1.md` section 15 cases are extended; the gateway never adds or changes an asset | M |
| T10 | all | Live lifecycles on a v16 local net, then on the public testnet: responded, refunded, swept, returned (a refusal forced by a test-only wallet build), funding refused, surplus recovered. **USDT cases** after USDC passes:<br>• the same lifecycles with a test USDT of 6 decimals behind the same bridge, under its own ConfigParam 84 entry and its own actors;<br>• on testnet, a fee-on-transfer variant of the test token, where the amount minted equals the bridge's received delta and the previews show the received amount;<br>• a lock and an unlock of a token whose `transfer` returns no `bool` | T5, T7-T9; T15-T17 for the USDT cases | Each is reconstructed by a second resolver, and the evidence is recorded as for the native rail. USDC and USDT actors run side by side, with no cross-asset effect. **Freeze rehearsal** with a test USDT that has blacklist and pause switches:<br>• blacklist the bridge;<br>• the oracles disable the token, and the alarm fires;<br>• providers auto-pause, and status 2 is proposed;<br>• existing requests still settle on TOS;<br>• redemption tooling refuses a blacklisted receiver (USDC and USDT).<br>Also: the `uint256` `decimals` of the deployed USDT decodes as 6 | M |
| T11 | relayer | Settlement v5 (vote layout, generations, `cancel_lock`, `activate_generation`) and the live loop. **The oracle refuses to vote for locks of tokens not on its allowlist** (SEC:111), so junk ERC-20 locks cannot occupy minter channels or the swap window (6.3) | — | Simnet end to end against the v5 contracts; a lock of a non-allowlisted token gets no vote | L |
| T12 | tos, tos-ops, external | The bridge production gates (7.1). The two audits explicitly cover the T1 wallet change and the T3 token actor, and the USDT behavioural review of 7.5 (SEC:111: fee switch, blacklist, no-bool return, approval race, upgrade path). Then the canary, then the ConfigParam 84 USDC record by validator vote, and later the USDT record under its own canary, only after the rollout precondition of 3.1 holds. Any later change of ConfigParam 79 `bridge_address` follows the migration rule of 7.4: the old record's status 2 or 3 is adopted before the change (separate proposals; tooling refuses the 79 change while the old record has status 1) | T1, T2, T11, T13 | Every SEC:97-113 item is checked; every validator runs a node release with the ConfigParam 84 TL-B; the record is adopted; a migration rehearsal on testnet suspends the old record before or with the bridge change. Also:<br>• the oracle-side token allowlist (USDC and USDT only) is in force;<br>• the USDT minter's channel is opened early, so that junk locks cannot take the last of the `CHANNEL_LIMIT` channels (6.3);<br>• redemption tooling's receiver blacklist and pause check (7.1) is reviewed | XL |
| T13 | external | An independent security review of the token-rail actor and the wallet change, against sections 4-5 | T1, T3 | Findings are resolved, or accepted by the owner, before T12's audits | M |
| T14 | tos-ops, ai `provider/` | Monitoring per actor and asset:<br>• payouts in flight longer than N blocks;<br>• count and age of returned entries;<br>• any returned entry from a refused funding return (kind 4);<br>• actor TOS balance against the backing floor;<br>• token-wallet TOS balance;<br>• S-side `get_refusals_count()` against `REFUSALS_LIMIT`, with a funded `rereport_refusal` for each recorded query id;<br>• aggregate token liability per asset against the bridge cap;<br>• ConfigParam 84 holding more than 16 entries;<br>• a ConfigParam 79 `bridge_address` change while a record for the old bridge still has status 1;<br>• for USDT: the bridge contract's blacklist status in the USDT contract, the EVM lock cap's headroom, any non-zero USDT transfer fee, and any upgrade of the USDT contract; each asset is monitored separately. | T3, T7 | Each alarm fires in a test that crosses its threshold, and stays silent below it. Further alarms:<br>• Tether `pause` and `destroyBlackFunds` events;<br>• for pending redemptions, the receiver's blacklist and pause status;<br>• swap-window occupancy against `SWAP_WINDOW` and minter-channel occupancy against `CHANNEL_LIMIT`.<br>**Runbook:** on a freeze, pause or destroy alarm, the oracles vote `voteForDisableToken` or `voteForSwitchLock` at once (7.5), providers auto-pause (T8), and status 2 is proposed | M |
| T15 | tos-ops, governance | **The USDT ConfigParam 84 entry** (7.4): the second record, under the same critical vote and the bridge-anchored re-derivation of 3.1; first on testnet with a test USDT | T2, T5, USDC through T10 | The record re-derives from the listed bridge's codes at one block; both entries validate, and the value stays within the 16-entry and cell-budget checks | S |
| T16 | tos (EVM) | **The per-token EVM lock cap** (SEC:105), set per token, with USDT's set independently of USDC's. It is bridge code required for every token (7.5) | — | A lock that would exceed its token's cap is refused; the caps are changed only by oracle vote; Hardhat tests for each token. **Every SEC:105 cap is placed:**<br>• per-token and per-transaction caps in `Bridge.sol` `lock`;<br>• hourly and daily caps in `Bridge.sol` as rolling per-token sums, checked in `lock`;<br>• all of them also enforced by the oracle's own policy before it votes (T11).<br>Also: the token allowlist on the oracle side (6.3) | M |
| T17 | ai | **A second pinned asset**: USDT release pins and the ConfigParam 84 entry in clients, budgets per asset, and asset-separated aggregation (6.3) | T7, T15 | USDC and USDT are verified and budgeted independently; a suspended USDT entry leaves USDC purchases unaffected | S |
| T18 | providers, tos-ops | **USDT token actors**: deployment and offers of actors fixed to the USDT master, with their own `max_token_liability` | T3, T15, T17 | A USDT actor admits only USDT funding, and a USDC notification to it takes the foreign-notification path (5.2); the provider runtime auto-pauses USDT actors on a T14 freeze, pause or destroy alarm (T8), and buyer clients refuse USDT while the alarm is up | S |

**T3 follow-up in tos (not changed by this design).** The wallet's TL-B
comment block lists the reported-transfer messages but omits
`transfer_rereported` (RW:211-232), which the op codes (ROP:16) and the
protocol section (RSP:1748-1751) define. T3 corrects the comment with its own
wallet-facing work.

**T1 correction in tos (not changed by this design).** R's
`set_gas_limit(R_GAS_LIMIT)` at RW:958-962 must be guarded by
`msg_value >= get_compute_fee(R_GAS_LIMIT)`, or moved after R's sender
authentication (4.3, R step 1; tosnetwork/tos#512, review finding P1). Its
test sends underfunded forged `internal_transfer_reported` messages to R and
requires R's TOS balance unchanged.

A refusal at R cannot be provoked on a live chain with the real wallet when the
budget is correct. T10 therefore uses a test-only wallet build that refuses on
demand, pinned like the test actor build. Production never accepts that build,
because ConfigParam 84 pins the real wallet code hash.

## 9. Documents this design changes

**New:** `SERVICE_ACTOR_TOKEN_TVM_V1.md`, the normative layout from section 5.

**Edited in place in `spec/`:**

- `SOFTWARE_WORK_MANIFEST_V1.md`: keys 20 and 21.
- `ACCEPTED_QUOTE_TVM_V1.md`: schema 3.
- `SOFTWARE_WORK_RECEIPT_TVM_V1.md`: schema 2.
- `SETTLEMENT.md`: delivery scope and asset roles (:9-19, :150-155).
- `SERVICE_ACTOR_SETTLEMENT_DESIGN.md`: D8 is superseded, citing this document.
- Both MCP adapter documents: budgets and amounts.
- `ROADMAP.md`: gate entries.
- `PRODUCT_STRATEGY.md` §9 (:293-327). Today :320-324 says that "an
  external-chain token, custodial balance, bridged claim on another network,
  or gateway database balance is not a settlement asset", and requires an
  "issuer identity". The rewrite says three things:
  - a token minted on TOS by the TOS token bridge is a settlement asset only
    while ConfigParam 84 recognizes it;
  - for bridged kind 1, the issuer identity is the bridge (`origin`) together
    with the source token;
  - a claim held on another network, a custodial balance and a gateway balance
    stay excluded.

**In tos:**

- `crosschain/token-bridge/SETTLEMENT-PROTOCOL.md`: reported transfers and the
  behaviour change.
- `SECURITY.md`: the USDC review item.

## 10. Owner decisions (taken 2026-11-24, team memo STATUS 13.581; amended 2026-11-25, STATUS 13.583)

- **Q1 Home network and second asset.** **Taken:** Ethereum (ConfigParam 79).
  The second recognized slot stays empty. *Superseded on 2026-11-25 by Q6.*
- **Q2 Recognition changes as critical parameters.** **Taken:** ConfigParam 84
  is critical and is listed in ConfigParam 10, so a change needs 3 won rounds.
- **Q3 Changing the bridge wallet before its audit.** **Taken:** change it now,
  before the audit (T1 comes before T12).
- **Q4 TOS for fees.** **Taken:** no fee sponsorship for the pilot. Buyers hold
  the TOS listed in 6.5.
- **Q5 Unattributable tokens.** **Taken:**
  - Tooling refuses to build unattributable transfers, meaning transfers with
    no forward amount or with less than the full budget of 5.2.
  - The token actor can obtain its wallet balance, so that its owner can recover
    unattributable tokens. This uses the balance-report wallet op
    (`provide_balance` and `take_balance`, T1) and the actor's
    `recover_surplus` (5.4, T3).
  - The earlier recommendation to leave such tokens stranded is superseded.
- **Q6 USDT (2026-11-25, team memo STATUS 13.583).** The owner, verbatim:
  "好，那把USDT也纳入导入范畴。" ("Good, then bring USDT into the import scope
  as well.") **Taken:**
  - Ethereum USDT (Tether) is bridged by the same token bridge into its own
    derived minter, and is the second ConfigParam 84 entry.
  - USDC stays first. USDT follows as configuration once USDC has run end to
    end (section 8).
  - This supersedes "the second slot stays empty" of Q1.
