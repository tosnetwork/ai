# USDC Settlement V1 (design)

**Status:** design proposal, 2026-11-24. Nothing here is normative until the
owner takes the decisions of section 10 and the normative documents named in
section 9 are written. No contract in this document is implemented, released or
deployed.

**Owner decision it implements (2026-11-24, team memo STATUS 13.580).** AI
services on TOS settle in a stablecoin, **USDC only, not USDT**. The source is
the TOS token bridge (`crosschain/token-bridge` in tos), which brings USDC from
its home network; issuance by Circle on TOS is a later target, not a dependency.
The `ai` repository may assume one or two officially recognized stablecoin
contract identities and proceed. This lifts D8 as a direction
([`SERVICE_ACTOR_SETTLEMENT_DESIGN.md`](SERVICE_ACTOR_SETTLEMENT_DESIGN.md):567-570:
native TOS "until a token integration reports payout outcomes"). The condition
attached to D8 stays: a production rail must learn the outcome of every token
payout.

**Sources pinned.** Every tos reference is to tos main `db4503c02`. Prefixes:

| Prefix | File |
|---|---|
| `SA:N` | `crypto/smartcont/service-actor-code.fc` (byte-identical to the release commit `fc5e7723e`, [`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md):61-63) |
| `TW:N` | `crosschain/token-bridge/tvm/contracts/token-wallet.fc` |
| `TM:N` | `crosschain/token-bridge/tvm/contracts/token-minter.fc` |
| `TB:N` | `crosschain/token-bridge/tvm/contracts/token-bridge.fc` |
| `TU:N` | `crosschain/token-bridge/tvm/contracts/utils.fc` |
| `TC:N` | `crosschain/token-bridge/tvm/contracts/config.fc` |
| `OP:N` | `crosschain/token-bridge/tvm/contracts/op-codes.fc` |
| `BR:N`, `SP:N`, `SEC:N` | `crosschain/token-bridge/README.md`, `SETTLEMENT-PROTOCOL.md`, `SECURITY.md` |
| `TLB:N` | `crypto/block/block.tlb` |
| `CFG:N`, `GZ:N` | `crypto/smartcont/config-code.fc`, `crypto/smartcont/gen-zerostate.fif` |
| `GV:N`, `TX:N` | `doc/GlobalVersions.md`, `crypto/block/transaction.cpp` |
| `TT:N`, `TTS:N` | `crypto/smartcont/token-wallet.tol`, `crypto/smartcont/tol-stdlib/token.tol` |

tos-ops references are to tos-ops main `c5a11a9`. Relayer references are to
relayer main `95a2d91`. `ai` references are to this repository at `a25b7fa1`.

## 1. Goal and scope

V1 adds one settlement asset kind beside native TOS: a **recognized TOS-network
token**, USDC first. At most two recognized assets exist in v1. A Service Actor
of the new token rail (section 5) prices calls in that asset, holds the price in
its own token wallet and pays every token payout through a transfer whose
outcome comes back to it.

In scope:

- a finalized on-chain list of recognized assets and how `ai` reads it
  (section 3);
- a payout-outcome protocol between the actor and the bridge token wallet
  (section 4);
- the Service Actor token rail, a new actor code beside the native one
  (section 5);
- the `ai` object, SDK, adapter and verifier changes (section 6);
- the bridge production path for USDC (section 7);
- the work plan (section 8).

Out of scope: shielded transfers, Energy, every asset other than USDC, network
fees paid in a token, x402 settlement
([`X402_ADAPTER_DECISION.md`](X402_ADAPTER_DECISION.md):10-25 stays in force),
and changing the native-TOS rail.

Fixed by the authority model and unchanged here: finalized TVM state is the
only authority; the gateway has no authority
([`SETTLEMENT.md`](SETTLEMENT.md):36-39, :68-69); refunds are claimable by the
buyer alone ([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md) section 7.4);
the Receipt commits to the result and the contract does not decode it (D9,
[`SOFTWARE_WORK_RECEIPT_TVM_V1.md`](SOFTWARE_WORK_RECEIPT_TVM_V1.md):46-54).

## 2. Facts this design rests on

### 2.1 Why the retired escrow could not settle a token

The retired escrow paid out with an ordinary token transfer. When the recipient
wallet refused it, the tokens bounced into the escrow's own wallet "without
telling the escrow", so it stayed `release_pending` or `refund_pending` and
"any retry could pay twice"
([`STABLECOIN_ESCROW_TVM_V2.md`](STABLECOIN_ESCROW_TVM_V2.md):181-189). It
treated `excesses` as proof of nothing (:179). Production needed "a new
integration in which the token's wallet reports each payout's outcome to the
escrow in an authenticated, request-specific, replay-safe way" (:198-200).

### 2.2 The bridge token wallet (the wallet bridged USDC uses)

Op codes: `transfer 0xf8a7ea5`, `transfer_notification 0x7362d09c`,
`internal_transfer 0x178d4519`, `excesses 0xd53276db` (OP:3-6).

**Outgoing transfer.**

- `send_tokens` requires the owner as sender (TW:105) and enough balance
  (TW:106). It forces the destination onto workchain 0 (TW:102; `params.fc`:10-14).
- It sends one bounceable `internal_transfer` with the receiver's StateInit
  (TW:115-130). The body is `query_id, amount, from = w_owner,
  response_address, forward_tos_amount, forward_payload` (TW:121-128).
- The send uses mode 64 (TW:139). The balance is debited in the same
  transaction (TW:140-141).
- `custom_payload` is loaded and ignored (TW:111).
- The attached value must exceed `forward_tos_amount + fwd_count * fwd_fee +
  2 * wallet_gas_consumption + wallet_min_tos_for_storage` (TW:131-137). Those
  prices come from the bridge ConfigParam (TW:696), and the transfer path throws
  if that ConfigParam is absent (TC:7-11).

**Receiving.**

- `receive_tokens` accepts only a sender equal to
  `calculate_user_token_wallet_address(from, w_master, w_code)` (TW:153-154).
- It sends `transfer_notification(query_id, amount, from, forward_payload)` to
  **the receiver's owner**, and only when `forward_tos_amount != 0`
  (TW:162-180). That send is non-bounceable in mode 1 (TW:174, TW:180).
- It sends `excesses`, which carries `query_id` only, to the response address
  with ignore-errors (TW:183-191).
- The handler notes that action-phase failures must not happen, "since in that
  case there will be no bounce" (TW:145-146). The notification send carries no
  bounce-on-action-fail flag (TW:180). By contrast, the standalone TOS Token
  sets that flag (TT:343).

**Refusal.**

- `on_bounce` handles only a bounced `internal_transfer`: it adds the amount
  back to the balance and does nothing else (TW:199-209).
- No message reaches the sender's owner, on success or on refusal.

**Settlement protocol scope.**

- The settlement protocol (version 5, SP:3) gives mints and burns durable,
  authenticated, idempotent completion (SEC:99).
- Transfers between wallets are "outside settlement" (SP:271-272). Their
  "bounce restore ... is unchanged" (SP:685-687).
- The wallet accepts settlement ops 40-63 only from its minter, except `advance`
  and `cancel_burn` (TW:647-659).

So the completion record of mints and burns cannot be reused for transfers
without changing the wallet.

**Address and authentication.**

- The wallet StateInit is `0b00, code, data = (balance 0, owner, master,
  ^wallet_code, ^empty_wallet_settlement)` (TU:21-38). The address is
  `0:cell_hash(StateInit)` (TU:74-80).
- The wallet code is fixed per minter. The minter stores it (TM:20). The bridge
  supplies it at minter creation (TB:112-120). No contract in the bridge calls
  `set_code`.
- The minter address is derived from `(content = chain_id, token_address,
  decimals; wallet code; bridge address)` (TU:44-56; TB:112-120), with the
  content layout `chain_id:uint32 token_address:uint160 decimals:uint8`
  (TU:100-119).
- Any contract holding the wallet code can therefore derive its own wallet, and
  the wallet of any owner, and authenticate a message from either.
- Getters:
  - `get_wallet_address(owner)` (TM:1389-1392);
  - `get_wrapped_token_data` returns `(chain_id, token_address, decimals)`
    (TM:1395-1398);
  - `get_token_data` returns an `addr_none` admin (TM:1386).
- The minter has no admin, mint, content or code-change op. Bridge state flags
  gate burns, not transfers (TW:709).
- A plain top-up with an empty body is accepted (TW:627).

**Bounces.**

- The `bounced` flag of an outbound message is always cleared by the action
  phase (TX:3435-3436), so a contract cannot forge a bounce.
- Since global version 12 a sender may request the full original body in a
  bounce (`extra_flags`, GV:221-242). Otherwise the bounce returns only part of
  the original body.

**Lifecycle risk.** A wallet whose storage debt exceeds the configured limits is
frozen and then deleted. A deleted wallet's balance is gone, and wallets "rely
on their reserve, which is topped up by every credit" (SP:769-777, SP:819).

### 2.3 The standalone TOS Token

`token-wallet.tol` and `token-minter.tol` behave the same way at the boundary
that matters:

- The transfer notification goes to the receiver's owner (TTS:270-292).
- `excesses` carries `query_id` only (TTS:295-304).
- The bounce handler restores the balance and tells no one (TT:403-419).

It differs in three ways:

- Its wallet data has no settlement cell, so its addresses differ (TTS:90-134).
- It sets bounce-on-action-fail on its sends (TT:300, TT:343).
- Its minter has an admin who can mint, change the admin and change the content
  (`token-minter.tol`:212-214, :286-288, :301-303).

Bridged USDC does not use it. It is not considered further.

### 2.4 Configuration and governance

**Bridge ConfigParams.**

- ConfigParams 79, 81, 82 and 83 are the bridge parameters for Ethereum, BNB
  Smart Chain, Polygon and Tron (BR:69-78; TLB:887-890).
- Each holds the bridge and oracle addresses, the oracle map, state flags, a
  price cell and the external bridge address (TLB:878-885). They hold no
  per-token data.

**Free ConfigParam numbers.** No TL-B entry exists for 26, 27, 38, 41, 42, 46,
49-70, 74-78, 80 or 84 and above (TLB:643-890).

**Changing a parameter.**

- Validators vote on proposals in the config contract.
- Each round needs votes of more than 3/4 of the validator weight (CFG:645).
  A proposal is accepted after `min_wins` won rounds (CFG:498).
- A parameter listed in ConfigParam 10 must be proposed as critical
  (CFG:596-601).
- Genesis marks 0, 1, 3, 4, 5, 8, 9, 10, 12, 14-17, 19, 32 and 34 as critical,
  plus the negative administrator parameters (GZ:414).
- ConfigParam 11 sets the win counts: 2 won rounds for an ordinary parameter and
  3 for a critical one (GZ:436-437).

**Testnet procedure.**

- tos-ops `testnet/scripts/testnet-governance.py` runs `propose`, `sign`, `vote`
  and `adopted`. Votes must be signed again after every rotation (:38-40).
- `testnet/CEREMONY.md` §8.2 (:768-813) is the procedure. "With four equal
  validators every round needs all four votes" (:795-796).

### 2.5 Fees

- Network fees are paid in TOS.
- The sponsorship profile
  ([`AGENT_GAS_SPONSORSHIP_AND_TRANSACTION_RELAY_V1.md`](AGENT_GAS_SPONSORSHIP_AND_TRANSACTION_RELAY_V1.md)):
  - lets a Provider top up an agent account with native TOS, relay its exact
    signed bytes, or both (:52-65, :117-121);
  - adds no opcode, paymaster or bridge (:67-68);
  - keeps the network fee in TOS (:2274-2285).
- No paymaster exists in tos or `ai`.
- The team's stablecoin plan (team memo
  `stablecoin-strategy/TOS-STABLECOIN-ADOPTION-PLAN-20261007.md`:248-262):
  - requires capped native-TOS pre-funding for sponsored token payments (:257);
  - requires sponsorship only for registered assets and request types (:258);
  - leaves charging the payer in stablecoin for fees to a separate design,
    because the fee leg and the payment leg are not atomic (:260).

### 2.6 Where `ai` is native-TOS only today

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

**Accepted Quote.** It has no asset field: "The asset is native TOS and has no
field" ([`ACCEPTED_QUOTE_TVM_V1.md`](ACCEPTED_QUOTE_TVM_V1.md):67).

**Receipt.** `charged_atomic_amount` is in nanoTOS
([`SOFTWARE_WORK_RECEIPT_TVM_V1.md`](SOFTWARE_WORK_RECEIPT_TVM_V1.md):13-14).

**Contract.**

- The actor accepts native value only (SA:611-616).
- It ignores bounces (SA:558).
- It pays out with non-bounceable empty-body sends (SA:207-214).

**Buyer tooling.**

- Budgets are in nanoTOS
  ([`MCP_BUYER_ADAPTER_V1.md`](MCP_BUYER_ADAPTER_V1.md):1008-1012), bounded at
  2^64-1 nanoTOS (:1019-1020).
- Amounts are "decimal nanoTOS strings" (:439-440).
- The buyer sender passes `--amount-nanotos` (`protocol/pkg/buyersdk/service_actor_sender.go`:152).

**Provider tooling.** Offer bounds and the wallet floor are in nanoTOS
([`MCP_PROVIDER_ADAPTER_V1.md`](MCP_PROVIDER_ADAPTER_V1.md):201-209, :294-299,
:420).

## 3. Recognition

### 3.1 Recommendation: a new ConfigParam 84

The recognized-asset list is a new configuration parameter, voted by validators
and read from finalized masterchain state:

```text
settlement_asset_origin$_ kind:uint8 bridge_address:bits256
  source_chain_id:uint32 source_token:bits160 = SettlementAssetOriginV1;

settlement_asset_v1#01 status:uint8 decimals:uint8
  minter_code_hash:bits256 wallet_code_hash:bits256
  origin:^SettlementAssetOriginV1 = SettlementAssetV1;

settlement_assets_v1#01 assets:(HashmapE 256 SettlementAssetV1)
  = SettlementAssets;

_ SettlementAssets = ConfigParam 84;
```

The dictionary key is the token master's account id. The master is always on
workchain 0: the bridge forces workchain 0 (`params.fc`:10-14), and the actor
rail is workchain 0 only ([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md):85-88).

| Field | Meaning |
|---|---|
| key | account id of the token master (the bridge minter) on workchain 0 |
| `status` | `1` active; `2` admission suspended; `3` retired. No other value. |
| `decimals` | display decimals of the atomic unit; equals the minter content's `decimals` (TU:100-119) |
| `minter_code_hash` | code hash of the master account |
| `wallet_code_hash` | `cell_hash` of the wallet code the minter derives wallets with (TM:20) |
| `origin.kind` | `1` bridged by the TOS token bridge; `2` reserved for native issuance |
| `origin.bridge_address` | masterchain account id of the bridge that created the minter; for kind 1 it equals `bridge_address` in the bridge ConfigParam of the source chain (TLB:885) |
| `origin.source_chain_id`, `origin.source_token` | the minter content's `chain_id` and `token_address` |

**Status semantics.**

- Status gates **admission only**: a token actor admits a `call` only while its
  asset's entry has status 1 (section 5.3).
- No payout, refund, sweep or withdrawal ever reads recognition. Removing or
  suspending an asset cannot strand an existing customer's principal.
- Status 2 is the emergency brake, for example after a depeg or a bridge
  incident.
- Status 3 tells clients to refuse new deployments and quotes.

**Rules for `ai`.**

- Clients refuse a dictionary with more than 2 entries in v1 (owner: "one or
  two").
- A ticker is not a field. Display names come from a client table keyed by the
  master and are never identity
  ([`SOFTWARE_WORK_MANIFEST_V1.md`](SOFTWARE_WORK_MANIFEST_V1.md):82-84).

**Self-verifying entry.** For kind 1 a reader must re-derive the master from
the entry and refuse any mismatch:

1. `master = 0:cell_hash(StateInit(minter code, pack_minter_initial_data(content,
   wallet_code, bridge)))` (TU:44-56, TB:112-120), with
   `content = (source_chain_id, source_token, decimals)`. This needs the wallet
   code preimage of `wallet_code_hash`, which the reader takes from the
   master's `get_token_data` (TM:1386) or from its account data, and checks by
   hash.
2. The master account's code hash equals `minter_code_hash`, and
   `get_wrapped_token_data` (TM:1395-1398) equals the origin.
3. The bridge ConfigParam of `source_chain_id` (79 for Ethereum, BR:73)
   names `origin.bridge_address`.

A governance vote can only recognize a minter the bridge actually created. A
typo in the vote is refused by every reader.

**Who changes it.** Validators, by a config proposal (section 2.4). The
recommendation is to list 84 in ConfigParam 10, so that every change is
critical: 3 won rounds instead of 2 (GZ:436-437). A recognition change decides
which asset buyers' money moves into. It should be at least as hard as the
bridge parameters, which today are ordinary (GZ:414).

**How `ai` reads it.**

- `toschain` reads ConfigParam 84 with `getConfigParam` at the checkpoint seqno
  under the read quorum, exactly as it already reads ConfigParam 4
  (`protocol/pkg/toschain/dns.go`:157-188) and ConfigParam 19
  (`protocol/pkg/toschain/agent_gift.go`:322-341).
- It decodes the record exactly (tags, no trailing bits or references) and
  applies the self-verification above.
- The resolved record is part of the checkpoint the quote and the request are
  verified at.

**Testnets and local networks.**

- The same parameter carries a test asset: a minter of a test bridge with its
  own test oracle set and test ERC-20.
- Local networks set it in the zero state.
- The public testnet sets it by `testnet-governance.py` (section 8, T5).
- No list is hard-coded in `ai`. A test asset is distinguished by its network
  domain and global id, as every other state is.
- Where a network has no ConfigParam 84 yet, a deployment tool may pin one
  record by flag. It must mark the run `"non_production": true`, as the escrow
  rule did ([`STABLECOIN_ESCROW_TVM_V2.md`](STABLECOIN_ESCROW_TVM_V2.md):193-197).
  That pin is never a production path.

### 3.2 Alternatives rejected

| Alternative | Why rejected |
|---|---|
| An existing ConfigParam (31, 44, the bridge params) | None has fields for a master, a wallet code hash, decimals and status. 31 means "special account" (rent-exempt), which is the wrong semantics. 79/81-83 are per chain, carry no tokens (TLB:878-885), and change shape when the bridge does. |
| Add a token list to ConfigParams 79/81-83 | It couples recognition to one bridge's parameter layout and to one source chain, and it cannot express native issuance (the later target). Editing it changes the type every bridge contract parses (TC:7-11). |
| A governed registry contract | It needs its own governance key or multisig, which is a new authority beside the validators. The actor cannot read another contract synchronously, so admission could not check status. A ConfigParam is readable by `CONFIGPARAM` in the actor and by `getConfigParam` in `ai`, under the existing validator vote. |
| A list hard-coded in `ai` | That is gateway or client authority, which the authority model forbids ([`PRODUCT_STRATEGY.md`](PRODUCT_STRATEGY.md):320-324 requires the identity, issuer, decimals and status "independently resolvable from finalized TOS state"). |
| The master only, without the wallet code hash | The actor and every resolver derive wallets from the code. A recognized master with an unpinned code would let the code that the reporting protocol depends on go unchecked. |

## 4. Payout-outcome protocol

### 4.1 The requirement

For every token payout (provider revenue withdrawal, buyer refund, sweep, and
the return of a refused funding) the paying contract must learn exactly one
outcome, **delivered** or **refused**. The report must be:

- **authenticated:** it comes from an address only the token's own code
  controls, and that address is derived by the payer itself;
- **bound to the request:** it names the payer's own payout id, amount and
  recipient;
- **replay-safe:** it is accepted at most once, and a report about another
  payout, or a repeated report, changes nothing.

### 4.2 Options

| Option | What changes | Verdict |
|---|---|---|
| **A. Payment contract only** | Actor logic over the unchanged wallet | **Impossible.** The success signals available are a `transfer_notification`, which goes to the recipient's owner and never to the payer (TW:162-180), and `excesses`, which carries only `query_id` (TW:189). Anyone can send a 1-unit transfer to the same recipient, with `response_destination` = the actor and the actor's pending `query_id`. The recipient's genuine wallet then sends the actor a matching `excesses`, a spoofed success. A refusal is silent (TW:199-209). This is exactly the retired escrow's failure. |
| **B. Wallet only** | The wallet reports, while the actor stays native-only | Useless alone: no contract consumes the reports. |
| **C. Route transfers through the minter's settlement protocol** | Minter and wallet | Rejected. Every payout would pass through the single minter account, with storage growth and contention there. It reopens the settlement state machine (SP sections 3-16) for a non-bridge purpose. |
| **D. Reported transfer in the wallet, consumed by a new actor** (recommended) | Wallet: additive ops. Actor: new token-rail code | Meets 4.1 with one extra message on success and two on refusal (4.6). |

### 4.3 Wallet change: reported transfer

These ops are new and additive. `transfer`, `internal_transfer`,
`transfer_notification`, `excesses`, burn and all settlement ops keep their
current behaviour. Op values are proposals; the implementation freezes them.

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

rereport_refusal#52545131 query_id:uint64 = RereportRefusal;       -- anyone -> S
clear_refusal#52544331 query_id:uint64 = ClearRefusal;             -- owner -> S
```

`S` is the paying wallet, its owner `P` is the payer (the actor), and `R` is the
recipient's wallet. New wallet state: `refusals:(HashmapE 64 Coins)`, keyed by
`query_id`, in the wallet's settlement cell or a new reference. It is empty in
the initial data, so wallet addresses stay derived from code and the empty
cells (TU:11-29).

**S on `reported_transfer`.**

1. Run the checks of `send_tokens` (TW:102-113), in compute phase:
   - the sender is the owner;
   - the balance covers the amount;
   - the destination is on workchain 0;
   - the forward payload has at least 1 bit.
2. Additionally require `amount > 0`, and require that `query_id` is not in
   `refusals`, so a reused id cannot merge with a recorded refusal.
3. Value check, extending TW:131-137: the attached value must exceed
   `forward_tos_amount + report_tos_amount + (fwd_count + 1) * fwd_fee +
   2 * wallet_gas_consumption + wallet_min_tos_for_storage +
   bounce_reserve`. `bounce_reserve` covers S's bounce handler and the refusal
   report. It is priced, like the other terms, from the bridge ConfigParam
   price cell (TLB:878-882), which gains one field for it.
4. Debit the balance and send `internal_transfer_reported` to `R` (bounceable,
   with StateInit), in mode 64.
5. Any refusal throws. `P`'s bounceable message then bounces back to `P`, and
   no token has moved.

**R on `internal_transfer_reported`.**

1. Authenticate exactly as TW:153-154: the sender must be the wallet of `from`.
2. Credit the balance under the supply bound (TW:157). Top up storage as
   TW:159-161.
3. If `forward_tos_amount > 0`, send the ordinary `transfer_notification` to
   R's owner.
4. Send `transfer_delivered(query_id, amount, recipient = w_owner)` to `from`,
   non-bounceable, carrying `report_tos_amount`, in mode `1 + 16` (pay fees
   separately, bounce on action fail). The notification of step 3 also uses
   `1 + 16`.
5. Send the remainder as `excesses` to `response_destination` with
   ignore-errors (as TW:183-191).

Every way R can fail turns into a bounce to S, because the message is
bounceable and both report-bearing sends carry `+16`:

- a compute-phase failure;
- running out of gas;
- an unpayable notification or report.

R never commits a credit without also committing the `transfer_delivered` send.

**S on a bounce of `internal_transfer_reported`.**

1. The bounce carries `op`, `query_id` and `amount` within its first 256 bits:
   32 + 64 + at most 124 bits. The legacy bounce body is enough, and the new
   bounce format (GV:221-242) is not required.
2. Restore the balance, as TW:206-208.
3. Insert `refusals[query_id] = amount`.
4. Send `transfer_refused(query_id, amount)` to the owner, carrying the bounced
   value, in mode `64 + 2`.

The balance restore and the record always commit, even if the report cannot be
sent, so the tokens are never lost. A lost report is recoverable through
`rereport_refusal`.

The bounce needs no source check. The `bounced` flag cannot be forged
(TX:3435-3436), and a bounce returns only to the original sender. A bounced
`internal_transfer_reported` at S is therefore always one S itself sent. The
existing `on_bounce` relies on the same property (TW:199-209).

**S on `rereport_refusal` (permissionless, funded).**

- If `query_id` is in `refusals`, re-send `transfer_refused` to the owner in
  mode 64, with no ignore-errors. A failure rolls the transaction back and
  keeps the record.
- If `query_id` is not in `refusals`, do nothing.

**S on `clear_refusal` (owner only).** Delete the record. This keeps wallet
storage bounded by the payer's unacknowledged refusals.

### 4.4 Payer side: what the actor holds and accepts

The actor keeps `next_payout_id:uint64`, which is never reused, and
`payouts:(HashmapE 64 ^Payout)`:

```text
payout$_ kind:uint3 request_id:uint64 recipient:MsgAddressInt
  requester:MsgAddressInt amount:Coins = PayoutV1;
-- kind: 1 refund, 2 sweep, 3 revenue withdrawal, 4 funding return,
--       5 returned-entry claim
```

`query_id` of the transfer is the payout id. The actor accepts these three
outcome messages, and no others:

| Message | Authenticated by | Accepted when | Effect |
|---|---|---|---|
| `transfer_delivered` | sender `==` the wallet of `recipient` derived from the actor's master and wallet code (TU:78-80) | `payouts[query_id]` exists and `amount` and `recipient` equal it | delete the payout; finalize by kind (5.4); emit the outcome log |
| `transfer_refused` | sender `==` the actor's own wallet | `payouts[query_id]` exists and `amount` equals it | delete the payout; restore by kind (5.4); emit the outcome log; send `clear_refusal(query_id)` to the own wallet |
| bounce of the actor's own `reported_transfer` | bounce source `==` own wallet; body op is `reported_transfer` | `payouts[query_id]` exists and `amount` equals it | as refused, without `clear_refusal`: no token left the wallet |

A `transfer_refused` for an id that is not pending still gets a
`clear_refusal`: it is a re-report after the outcome was already applied. Every
other message is ignored without throwing. The reports are non-bounceable, so a
throw would only burn gas.

**Why exactly one outcome per payout.**

- The actor's `reported_transfer` either fails at S, so it bounces to the
  actor (outcome 3), or S commits the debit and sends to R.
- R then either commits the credit together with `transfer_delivered`
  (outcome 1), or fails, so its message bounces to S, which records and reports
  the refusal (outcome 2).
- These cases are disjoint transactions on disjoint branches, and the actor
  deletes the payout on the first outcome it accepts.

**Why replay-safe.** A third party cannot produce any of the three:

- `transfer_delivered` with `from` = the actor requires a message from the
  actor's own wallet, which is authenticated at R (TW:153-154).
- `transfer_refused` comes only from the actor's own wallet.
- A bounce cannot be forged.

Payout ids are never reused, so an old report cannot match a newer payout.

### 4.5 Crash, retry and replay analysis

| Failure point | What the chain holds | Recovery |
|---|---|---|
| A client sends `claim_refund`, `sweep_expired_request` or `withdraw_revenue` and crashes | Either nothing (the message was not included) or a payout in `payouts` | The client reads the finalized actor state and history before any retry ([`SETTLEMENT.md`](SETTLEMENT.md):167). A second `claim_refund` for the same request fails while the payout is in flight: the entry is no longer in `refunds` (1917). |
| S refuses (insufficient value, ConfigParam 79 absent per TC:11, frozen or deleted S) | Bounce at the actor | The payout returns to its pre-payout ledger position (5.4); the requester's TOS change goes back to the requester. A deleted S means lost principal: see 5.6. |
| R fails in compute or action | Bounce at S; record in `refusals`; refusal report | The actor restores the payout. If the report was dropped (mode 64+2), anyone sends `rereport_refusal`. |
| The `transfer_delivered` report cannot be processed by the actor | — | The actor's handler is bounded (one dictionary lookup and delete, one log) and paid by `report_tos_amount`. The actor fixes `report_tos_amount` itself and sizes it from the gas gate (section 8, T3). The actor keeps its 1 TOS reserve (SA:181), so it is never frozen while live. This is the one path with no retransmission. Its safety rests on that gas bound, which the sandbox must test at the bound. |
| A duplicate report (rereport after clear, or a stale message) | Payout not pending | Ignored, plus `clear_refusal` where applicable. |
| A config price change between the send and the bounce | The bounce reserve may fall short | The S restore still commits (ignore-errors on the report). `rereport_refusal` is funded by the caller. |

### 4.6 Costs: gas, compatibility, audit scope

**Messages per payout** (excluding the request that triggers it):

- an ordinary transfer: actor→S, S→R, R→excesses;
- a reported transfer that is delivered: the same plus R→actor
  `transfer_delivered`, so one more message and one more actor transaction;
- a reported transfer that is refused: actor→S, S→R, R→S bounce, S→actor
  `transfer_refused`, actor→S `clear_refusal`, so two more messages and one more
  wallet transaction than a bounced ordinary transfer.

No gas figure is quoted here. Each leg is measured on both VMs by T1 and T3
(section 8), as the native actor's gates require
([`SERVICE_ACTOR_SETTLEMENT_DESIGN.md`](SERVICE_ACTOR_SETTLEMENT_DESIGN.md):625-629).
Recipients pay nothing extra: the requester's attached TOS funds every leg.

**Compatibility.**

- The wallet code changes. The minter address is derived from the wallet code
  (TU:44-56), so **every minter address changes** and wallets cannot be
  upgraded in place (no `set_code`).
- The change must therefore land before the first production USDC minter
  exists. It is free now: nothing is deployed in production (BR:3), and the
  owner rule is no backward compatibility (SP:25-30).
- Existing test deployments are redeployed.
- Ordinary `transfer` is unchanged. Wallets, explorers and the iOS and Android
  clients keep working, and they need the new ops only if they want reported
  transfers.
- The added fields fit the wallet's existing data and code limits. T1 checks
  this.

**Audit scope.**

- The wallet is already in the bridge's mandatory two-audit scope (SEC:102).
  Adding the ops before that audit costs one more state machine in a contract
  being audited anyway; adding them after costs a re-audit.
- The new token-rail actor needs its own review, as the native actor does
  ([`SERVICE_ACTOR_SETTLEMENT_DESIGN.md`](SERVICE_ACTOR_SETTLEMENT_DESIGN.md):649).

**Hardening of existing sends (recommended in the same change).** Add `+16` to
the ordinary `transfer_notification` send (TW:180). The current wallet can lose
tokens in flight on an action-phase failure there (TW:145-146): the sender is
debited, the receiver's credit rolls back, and nothing bounces. This also
matters for funding (5.3).

## 5. Service Actor token rail

A new contract, `service-actor-token-code.fc`, released as
`tos-service-actor-token-v1` (rail id `tos.service.service-actor-token.v1`). It
keeps the native actor's request lifecycle, terms, attestor, SRP2 and snapshot
design ([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md) sections 3-8).
Only funding, payouts and accounting change. The native actor is unchanged
(5.7).

### 5.1 Asset fixed at deploy

The root data gains a reference that never changes after deploy:

```text
asset_route$_ master:MsgAddressInt wallet_code_hash:uint256
  wallet_code:^Cell = ServiceActorAssetRouteV1;
```

**Deploy-time consistency.**

- `call` refuses to admit while `cell_hash(wallet_code) != wallet_code_hash` or
  the master is not on workchain 0. This mirrors how the native actor
  re-checks deploy data at `call` (SA:578-604).
- No op changes the route.

**The actor's own wallet** is
`calculate_user_token_wallet_address(my_address(), master, wallet_code)` with
the bridge layout (TU:21-38, TU:78-80).

- It is derived at run time, because the actor's address depends on its own
  StateInit, so the address cannot be stored there.
- Resolvers reproduce it independently, as the retired escrow required
  ([`STABLECOIN_ESCROW_TVM_V2.md`](STABLECOIN_ESCROW_TVM_V2.md):80-84).

**The terms commit to the asset.** `terms_hash` (SA:263-291) gains the asset in
its root cell:

```text
token_terms$_ policy_version:uint32 price_per_call:Coins storage_fee:Coins
  cleanup_bounty:Coins response_sla:uint32 refund_claim_window:uint32
  asset_master:uint256 asset_wallet_code_hash:uint256
  ^terms_tail = ServiceActorTokenTermsV1;        -- root <= 980 bits
```

`terms_tail` is unchanged. The SRP2 statement keeps its layout
([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md) section 6). It binds the
asset through `terms_hash`, and the price through `price` and `terms_hash`.

**Units.**

- `price_per_call` is in the token's atomic units.
- `storage_fee`, `cleanup_bounty`, the allowances and the operating reserve
  stay nanoTOS. They pay for chain resources and the sweeper, not for the
  service.

### 5.2 Funding a `call`

The buyer sends the price as an ordinary token `transfer` from its own wallet:

- `destination` = the actor;
- `amount` = `price_per_call`;
- `forward_tos_amount >= storage_fee + ADMISSION_GAS_ALLOWANCE + the actor's
  return budget`;
- `forward_payload` =

```text
token_call#53544301 request_hash:uint256 expected_terms_hash:uint256
```

The actor's wallet sends `transfer_notification(query_id, amount, from = buyer,
forward_payload)` with `forward_tos_amount` as value (TW:162-180). The actor
handles op `0x7362d09c`:

1. **Spoofed or foreign notification.** If the sender is not the actor's own
   derived wallet, the message is a notification from a wallet of another
   master, or a fake one. No token reached the actor's wallet, so no state
   changes. The actor sends that sender a `transfer` of `amount` back to
   `from`, carrying only the message's own value (mode 64). It then stops. If
   the sender is a genuine wallet owned by the actor, this returns the
   tokens; if it is a fake, the message is harmless. This follows the retired
   escrow (`STABLECOIN_ESCROW_TVM_V2.md`:117-122). A wrong master is this case.
2. **Authenticated notification.** From here on the handler **never throws**.
   The notification is non-bounceable (TW:174), and the tokens are already in
   the actor's wallet, so a throw would strand them. The caller is `from`: the
   chain authenticated it at the actor's wallet (TW:153-154).
3. The actor admits only if all of the following hold, in this order:
   - `active` and the policy bounds (as SA:577-594) hold;
   - the attestor commitments are consistent (SA:598-604);
   - the asset route is consistent (5.1);
   - **ConfigParam 84 holds the master with status 1 and `wallet_code_hash`
     equal to the route's**;
   - `from` is admitted by `open_access` or `authorized_caller` (SA:607-608),
     comparing `from`, not the message sender;
   - `amount == price_per_call` **exactly**: overpayment and underpayment are
     refused alike;
   - the message value covers `storage_fee`, then `ADMISSION_GAS_ALLOWANCE`,
     then the return budget;
   - capacity, id overflow and the daily rate limit (SA:617-632) hold;
   - the forward payload parses exactly as `token_call` with no trailing data;
   - `expected_terms_hash == terms_hash`;
   - TOS backing covers the storage locks and the operating reserve (as
     SA:660-666).
4. **Admitted.** The actor stores the pending request with `caller = from` and
   adds `price` to the token pending liability. It emits the request snapshot,
   tag `SAT1` (`0x53415431`): the `SAR1` layout
   ([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md) section 8.1) with the
   token terms cell. It returns the TOS change to `from` (mode 128 after
   `raw_reserve`).
5. **Refused.** The actor creates a payout of kind 4 (funding return) of
   `amount` to `from`, with requester `from`, and sends it as a reported
   transfer (section 4). It also emits `SAF1` (`0x53414631`) `query_id:uint64
   from:MsgAddressInt amount:Coins reason:uint16 payout_id:uint64`. The reason
   is the exit code the native actor would have thrown. A resolver reads it
   from the transaction, since the transaction itself succeeds. If the message
   value cannot fund the return, the actor stores a returned entry for `from`
   instead (5.4), claimable later.

Native value sent with a `call`-shaped body outside a notification is not
funding. A native `call` op is unknown on this rail (1910).

A transfer with `forward_tos_amount = 0` produces no notification (TW:162). The
tokens arrive unattributed and the actor cannot know of them. Buyer tooling
must refuse to build such a transfer to an actor. Recovering such tokens is
left out of v1 (section 10, Q5).

### 5.3 Admission reads recognition; payouts never do

The ConfigParam 84 check is in admission only. `respond`, `expire`,
`claim_refund`, `claim_returned`, sweep and `withdraw_revenue` never read it:

- suspending an asset stops new calls on every actor of that asset at once;
- it cannot freeze money already admitted.

If ConfigParam 84 is absent, no call is admitted, so a network without the
parameter cannot settle in a token by accident.

### 5.4 Requests, payouts and their outcomes

**New state.**

- `payouts` (4.4).
- `returned:(HashmapE 64 ^Returned)`, where
  `returned$_ caller:MsgAddressInt amount:Coins = ReturnedV1`. It is keyed by
  the payout id that failed, or by the request id for a funding that could not
  be returned at once.
- A token ledger of `pending_liability`, `refundable_liability`,
  `returned_liability`, `in_flight` and `withdrawable_token_revenue`, all in
  atomic units.
- The native ledger: `locked_storage_fees`, `withdrawable_tos_revenue` and the
  operating reserve, in nanoTOS.

**Token invariant.** The actor's wallet balance is at least the sum of the
token ledger.

- Tokens enter the wallet only through authenticated notifications, credited
  exactly.
- They leave only through the actor's reported transfers, debited at send.
- They return on refusal.
- Unattributed deposits (5.2) only make the balance larger.

The actor cannot read its wallet balance. The sandbox checks the invariant
after every transition.

| Operation | Change from the native actor | Payout | On delivered | On refused or bounced |
|---|---|---|---|---|
| `respond` | none in checks (SA:680-706). Credits `price` to `withdrawable_token_revenue` and `storage_fee` to `withdrawable_tos_revenue` | none | — | — |
| `expire` | none (SA:722-749) | none | — | — |
| `claim_refund(request_id, destination)` | checks as SA:751-772, but the token backing check becomes the ledger check. The attached TOS must also cover the reported-transfer budget. The refund entry moves to `payouts` (kind 1), and the price moves from refundable liability to `in_flight`. The storage fee is credited to TOS revenue (D4) | `price` to `destination` | release capacity; `in_flight -= price` | a returned entry for the caller, **with no deadline**: the caller acted in time, and a refusal must not cost it the claim |
| `sweep_expired_request(request_id)` | checks as SA:789-855. The bounty is paid in TOS to the sweeper at once (mode 1), as SA:875-877 | `price` to the request's caller (kind 2) | release capacity | a returned entry for the caller |
| `withdraw_revenue(token_amount, tos_amount)` | owner only. The TOS part works as SA:963-994. The token part must not exceed `withdrawable_token_revenue`, and at most 4 revenue payouts may be in flight | `token_amount` to the owner (kind 3) | — | re-credit `withdrawable_token_revenue` |
| `claim_returned(id, destination)` (new, `0x5354430A`) | only the entry's caller; the attached TOS covers the budget | `amount` to `destination` (kind 5) | delete the entry | the entry stays, and the caller may try another destination |
| funding return (5.2) | — | `amount` to `from` (kind 4) | — | a returned entry for `from` |

**Common rules.**

- Every payout carries `response_destination = requester`, so the excess TOS
  goes back to whoever paid for the payout.
- Every outcome emits `SAO1` (`0x53414f31`) `payout_id:uint64 kind:uint3
  request_id:uint64 recipient:MsgAddressInt amount:Coins outcome:uint2`.
  Resolvers derive the terminal states of
  [`SERVICE_ACTOR_SETTLEMENT_DESIGN.md`](SERVICE_ACTOR_SETTLEMENT_DESIGN.md)
  section 5.1 from it.
- A request is **refunded** or **swept** only when its payout is delivered. A
  refused refund is **returned**, a new buyer-visible state with the action
  `claim_returned`.

**Capacity.** In-flight payouts and returned entries keep their capacity slot
until delivered, so the native caps (SA:202-203) bound `payouts` and `returned`.
Revenue withdrawals add at most 4.

The D3 incentive note
([`SERVICE_ACTOR_SETTLEMENT_DESIGN.md`](SERVICE_ACTOR_SETTLEMENT_DESIGN.md):407-421)
is fixed in the same new code: `claim_refund` also pays the `cleanup_bounty` to
the claimer, so claiming promptly is never worse than sweeping.

### 5.5 Operation codes and exit codes

Ops use the prefix `0x5354430x`, `ST` for "Service Token":

- `respond` 02, `expire` 03, `claim_refund` 04, `sweep_expired_request` 05,
  `update_policy` 06, `rotate_attestor_key` 07, `revoke_attestor` 08,
  `withdraw_revenue` 09, `claim_returned` 0A;
- the `token_call` payload tag is `0x53544301`;
- plus the three outcome inputs of 4.4.

Exit codes reuse 1900-1929 with their meanings
([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md) section 9) and add:

- 1930 `payout_in_flight`;
- 1931 `returned_not_found`;
- 1932 `asset_route_invalid`;
- 1933 `asset_not_recognized`.

The last two appear only as `SAF1` reasons, never as a throw on the
notification path.

### 5.6 The actor's own wallet must not be deleted

The actor's token wallet holds every customer's principal. A wallet deleted for
storage debt loses its balance (SP:792-794, SP:819).

**Controls.**

- Every incoming transfer tops up the wallet's storage reserve (TW:159-161).
- Every reported transfer attaches `wallet_min_tos_for_storage` in its value
  check (4.3).
- The provider runtime monitors the wallet's TOS balance against a floor and
  tops it up with a plain transfer (TW:627), as the minter monitoring the
  bridge already requires (SP:814-817).
- The pause rule of the provider wallet floor
  ([`MCP_PROVIDER_ADAPTER_V1.md`](MCP_PROVIDER_ADAPTER_V1.md):294-299) extends
  to the actor's token wallet.

This is an operational control, not a contract guarantee, and the buyer
preview must state it.

### 5.7 Storage, release and code hash

**Storage.** Compared with the native layout
([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md) section 4), the token
actor adds:

- the asset route reference (one wallet code cell tree, shared by hash);
- `next_payout_id`;
- the `payouts` and `returned` dictionaries;
- the two revenue counters and the two new liabilities.

The `accounting` cell grows past one cell and splits into a native part and a
token part.

**Release.**

- Release manifests `crypto/smartcont/tos-service-actor-token-v1.release.json`
  and a test-only build `tos-service-actor-token-v1-test.release.json` with
  600-second windows, as the native pair
  ([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md):14-44).
- `scripts/check-service-actor-bytecode.py` covers both codes.
- Conformance vectors are generated from contract execution:
  - the deployed data;
  - the token terms cell and `terms_hash`;
  - `SAT1`, `SAF1` and `SAO1`;
  - a funding notification, every payout outcome and a refused funding.
- Clients pin the token release code hash for this rail only.

**Native actors keep working.**

- The native code, release hash, rail string `tos.service.service-actor.v1`,
  manifest key 20 `native-tos`, Accepted Quote schema 1 and Receipt schema 1
  are all unchanged.
- `ai` selects the verifier by the manifest key 21 rail string and the pinned
  code hash. Both rails coexist and nothing migrates.

## 6. `ai` changes

### 6.1 Asset identity in every object

**Capability manifest** ([`SOFTWARE_WORK_MANIFEST_V1.md`](SOFTWARE_WORK_MANIFEST_V1.md),
edited in place as D6 was).

- Key 20 stays an array of exactly one entry, now one of:
  - `{0: "native-tos"}`;
  - `{0: "tos-token", 1: <32-byte master account id>, 2: <32-byte wallet code
    hash>, 3: <decimals>}`.
- The token entry equals the actor's asset route and a ConfigParam 84 record
  with status 1 at the admission checkpoint.
- Key 21 field 1 admits `tos.service.service-actor-token.v1`. Field 4 must then
  equal the token release hash.
- A native rail with a token entry, or the reverse, is refused.
- `manifest.go`:219-221 gains the second form, and the negative corpus gains a
  case for each mismatch.

**Quote Proposal** (`native.proto`, both copies:
`spec/proto/tos/service/v1/native.proto` and
`protocol/api/tos/service/v1/native.proto`).

- Add `TOSAssetIdentityV1 asset = 18;` and `string price_atomic = 19;`, using
  `TOSAssetIdentityV1` as it is (:333-337):
  - `master` is the minter's workchain, account and code hash;
  - `wallet_code_hash`;
  - `decimals`.
- Exactly one of `price_nanotos` or (`asset` with `price_atomic`) is set.
- `storage_fee_nanotos` stays nanoTOS on both rails.

**Accepted Quote** ([`ACCEPTED_QUOTE_TVM_V1.md`](ACCEPTED_QUOTE_TVM_V1.md)).

Schema 3 is added for the token rail. Schema 2 is the retired Paid Demand
layout, so its number is not reused (:15-17).

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

- The network domain, identity and authority cells are unchanged.
- `ServiceRequestV1` is unchanged: it commits to `quote_commitment`, which now
  binds the asset.

**Receipt** ([`SOFTWARE_WORK_RECEIPT_TVM_V1.md`](SOFTWARE_WORK_RECEIPT_TVM_V1.md)).

Schema 2 for the token rail:

```text
economic_v2$_ charged_atomic_amount:uint128 asset_master:uint256
  provider_agent_id:uint256 = ReceiptEconomicV2;
```

- The charge equals `price_atomic`, and the master equals the Quote's.
- Attestor custody refuses any other value (D9).
- Schema 1 stays for native TOS.

### 6.2 Atomic units and decimals

- Token amounts are unsigned atomic units as canonical base-10 text, with the
  rule of [`SETTLEMENT.md`](SETTLEMENT.md):58-66, below `2^120`. That bound is
  the wallet's `Coins`, the same as the actor's.
- `decimals` comes only from the ConfigParam 84 record, cross-checked against
  the minter (3.1). The value shown is `amount / 10^decimals`, rendered by
  integer arithmetic, never floating point.
- Bridged USDC carries 6 decimals in the minter content if the oracle vote
  reports the source token's decimals (TU:100-119; `evm/contracts/Bridge.sol`:293-296).
  The design assumes no scaling between the source and the TOS atomic units.
  T1 confirms this against the mint path.
- Aggregation is per exact asset identity, never per ticker
  ([`AGENT_ECONOMY_METRICS_V1.md`](AGENT_ECONOMY_METRICS_V1.md):182-184).

### 6.3 Price per asset

- A token actor has one asset (5.1), so a price is always "N atomic units of
  asset X".
- A provider that wants to sell in both TOS and USDC runs two actors and
  publishes two Capability versions or two Capabilities. One actor never takes
  two assets.
- Discovery shows the asset with each offer.

### 6.4 Components

| Component | Change |
|---|---|
| `protocol/pkg/nativecore` | Codecs for the token terms cell, `SAT1`, `SAF1`, `SAO1`, schema 3 Accepted Quote, schema 2 Receipt and the manifest key 20 token entry; the token release code hash. |
| `protocol/pkg/toschain` | ConfigParam 84 reader and self-verification (3.1); actor-wallet derivation; history decoding of notifications, reports and outcome logs. |
| `protocol/pkg/serviceactor` | Both verification procedures ([`SERVICE_ACTOR_SETTLEMENT_DESIGN.md`](SERVICE_ACTOR_SETTLEMENT_DESIGN.md) section 2.4) for the token rail. They add: the asset route equals the manifest, the Quote and a status-1 recognition record at the admission checkpoint; the funding notification came from the actor's derived wallet, with the exact amount. The lifecycle gains the states `paying` and `returned`. |
| `protocol/pkg/buyersdk` | `Prepare` and `Call` build the token transfer with the `token_call` payload and a non-zero `forward_tos_amount`. They refuse `forward_tos_amount = 0`. The journal records the transfer, the notification transaction and either the `SAT1` or the `SAF1` result. Duties: `expire`, `claim_refund`, and `claim_returned` while a returned entry exists. |
| `provider` (`servicebridge`, `tos-service-provider`, MCP provider) | Offers in atomic units within per-asset offer bounds ([`MCP_PROVIDER_ADAPTER_V1.md`](MCP_PROVIDER_ADAPTER_V1.md):201-206). Withdrawal of both revenues, with in-flight and refused outcomes shown. The token-wallet TOS floor (5.6). |
| MCP buyer (`tos-service-buyer-mcp`) | Budgets per asset: `max_per_call_atomic` and `max_window_atomic` for each recognized asset, plus the existing nanoTOS limits for storage fee, allowances and fees ([`MCP_BUYER_ADAPTER_V1.md`](MCP_BUYER_ADAPTER_V1.md):1008-1020). The preview shows the price in the asset and every TOS cost separately (as [`SETTLEMENT.md`](SETTLEMENT.md):152-155). |
| `tos-service-verify` | Accepts the token release code hash and verifies the recognition record at the call checkpoint, the funding notification chain and the payout outcome logs. The usage gains an asset option beside `--actor-code-hash` (`protocol/cmd/tos-service-verify/main.go`:44-46). |
| `purchaseevidence` | Adds the ConfigParam 84 value hash at the checkpoint, the funding transfer and notification transactions, and the outcome transactions ([`PURCHASE_EVIDENCE_V1.md`](PURCHASE_EVIDENCE_V1.md)). |
| gateway (`internal/quotesource`) | Builds token Quote Proposals from finalized actor state and the recognition record; pins both release hashes. No authority, no balance. |

### 6.5 What stays nanoTOS

The following stay nanoTOS on the token rail:

- network fees;
- storage fee and cleanup bounty;
- the 0.2 TOS allowances (SA:187-188);
- the operating reserve (SA:181);
- the attached TOS budgets of each token transfer;
- sponsorship top-ups;
- registry operations.

A buyer agent therefore needs, minimally:

- USDC for the price;
- a small TOS balance per call covering the wallet fee, the token transfer
  value, `forward_tos_amount` (storage fee + allowance + return budget) and,
  for a refund, the claim's attached value.

Alternatively, a sponsoring Provider tops up that TOS under the existing
sponsorship profile (2.5). A USDC-only buyer with no TOS is not supported in
v1, because no paymaster exists.

## 7. Bridge production path for USDC

### 7.1 Preconditions

**From the bridge itself** (BR:3, BR:150-152, SEC:97-113):

- two independent audits of the exact build;
- an oracle key ceremony with HSM keys and operator diversity, at a quorum of
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

Only durable settlement is done (SEC:99). No ConfigParam slot is populated
(BR:78).

**Added by this design:**

- the reported-transfer wallet (T1), in the audited build;
- ConfigParam 84 (T2);
- an explicit USDC review under SEC:111. USDC is an upgradeable contract whose
  issuer can blacklist addresses and pause transfers (external fact). A
  blacklisted bridge lock address would freeze every locked USDC, so the risk
  is backed by the wrapped supply on TOS. ConfigParam 84 status 2 is the TOS-side
  response for new calls; the source-side risk is the issuer's.

### 7.2 Relayer gap

The relayer has no live path:

- `crates/relayer/src/main.rs`:96-99 bails, "the relayer has no live-node path
  yet".
- The oracle and relayer binaries are "skeletons only", and the audit is "not
  started" (`README.md`:115-116). Line 7 of the same README says "Nothing here
  is implemented yet."

Its protocol is older than settlement v5:

- `docs/protocol.md`:159-171 defines the swap vote as `ext_chain_hash,
  internal_index, addr_hash, mint_jetton_amount, ^wrapped_token_data,
  forward_coins_amount`, keyed by `cell_hash(ext_chain_hash, internal_index)`
  (:342-351).
- It names the old `jetton-bridge.fc` (:173, :342) and `"protocol_version": 1`
  (:365).
- The v5 bridge decodes `generation:uint32, n:uint64, evm_chain_id:uint32,
  evm_bridge:uint160, recipient_hash:uint256, amount, ^wrapped_token_data`
  (TB:304-311). It keys payments by `n` (TB:320-322) and adds `cancel_lock`
  and `activate_generation` votes (TB:441-444).

Until the relayer implements v5, no mint happens on any network without a
stand-in oracle (section 8, T5).

### 7.3 Which home network first

The bridge supports Ethereum (79), BNB Smart Chain (81), Polygon (82) and Tron
(83) (BR:71-76). Base, Arbitrum, Optimism and Solana are absent. The statements
about where Circle issues USDC are external facts that must be confirmed
against Circle's published contract list before the slot is populated.

| Home | For | Against |
|---|---|---|
| **Ethereum (79)** | Circle's original issuance and deepest liquidity; slot and params exist; the EVM counterpart is exercised on EVM networks | highest lock and unlock gas for users; slower finality to wait out |
| Polygon PoS (82) | native Circle USDC exists; cheap | two USDC contracts exist there, Circle's native one and the older bridged one, and a wrong recognition would be costly; reorg history requires deeper confirmation |
| Base or Arbitrum | native USDC, cheap | not supported by the bridge: needs a new slot, params file and EVM deployment |
| BNB Smart Chain (81) | supported slot | its USDC is not Circle-issued: refused by the owner's "Circle-issued USDC" reason |
| Tron (83) | supported slot | the chain id is derived, not observed (BR:80, BR:148); Circle issuance there is discontinued (external fact) |

**Recommendation: Ethereum first.** It is the only supported slot whose USDC is
unambiguously Circle's own. The second recognized asset, if any, is a decision
for later (Q1).

### 7.4 What the TOS side must recognize

One ConfigParam 84 record for the minter the production bridge derives:

- `chain_id = 1`;
- `token_address` = Circle's USDC contract on Ethereum;
- `decimals = 6`;
- the reported-transfer wallet code;
- the production bridge address (3.1).

It also requires the bridge ConfigParam 79 populated, and the bridge listed in
ConfigParam 31 (SEC:101). Recognition is proposed only after the canary has run
under the caps.

## 8. Work breakdown

Sizes: S up to 1 week, M 1-3 weeks, L 3-6 weeks, XL external or longer.
Everything up to T10 runs on local and test networks with a test USDC (a test
ERC-20 behind a test bridge). Only T11 and T12 gate production.

| # | Repo | Item | Depends on | Acceptance | Size |
|---|---|---|---|---|---|
| T1 | tos | Reported transfer in `token-wallet.fc` (4.3), bounce reserve price field in the bridge price cell (TLB:878-882), `+16` on the ordinary notification; `SETTLEMENT-PROTOCOL.md` section for reported transfers; `scripts/verify-token-bridge.py` invariants | — | Sandbox on both VMs (`token_bridge_sandbox.rs`): delivered, refused at R (forced compute and action failure), refused at S (each refusal), rereport, clear, duplicate query id, third-party spoof attempts (excesses, foreign delivered, forged refused) all ignored; supply and balance conserved in each; each guard shown red by removing it; gas per leg measured; decimals and no-scaling confirmed on the mint path | L |
| T2 | tos | ConfigParam 84 TL-B in `block.tlb`, typed JSON-RPC view, critical listing in genesis for local nets (GZ:414), `tosctl` decode; reader rule refusing more than 2 entries | — | Round trip through `getConfigParam`; config contract refuses an uncritical proposal once listed (CFG:596-601); a malformed record refused by the decoder | M |
| T3 | tos | `service-actor-token-code.fc` (section 5), Rust builders and decoder, sandbox, release manifests (release and test), bytecode check, vectors | T1, T2 | Every native sandbox case ported; plus: spoofed and foreign notifications, every admission refusal giving `SAF1` and a funding return with no stranded token, exact-amount rule, recognition status 2 and absent param, every payout kind x {delivered, refused, bounced at S}, returned entries, capacity at the bound, the token invariant checked after every step; gas of each op on both VMs within its allowance | L |
| T4 | tos | `tosctl`: token transfer with `token_call` payload and `--build-only`, `claim_returned`, two-part `withdraw_revenue`, top-up of the actor's token wallet, ConfigParam 84 proposal value builder | T3 | `--build-only` output reproduced by `buyersdk` byte for byte; refuses `forward_tos_amount = 0` to an actor | M |
| T5 | tos-ops | Test USDC on the local net and public testnet: test bridge, test oracle stand-in signing v5 votes, ConfigParam 79 and 84 by `testnet-governance.py`, CEREMONY addendum | T1, T2 | `adopted` shows both params on every validator (CEREMONY:797); a test mint reaches a buyer wallet | M |
| T6 | ai `spec/` | Normative `SERVICE_ACTOR_TOKEN_TVM_V1.md`; in-place edits of the manifest (key 20 and 21), Accepted Quote (schema 3), Receipt (schema 2), `SETTLEMENT.md`, `PRODUCT_STRATEGY.md` §9, `X402_ADAPTER_DECISION.md` note; both proto copies; vectors from T3 copied byte for byte | T3 (vectors) | Spec vectors equal the tos fixture; negative corpus for every new rule | M |
| T7 | ai `protocol/` | nativecore codecs, toschain ConfigParam 84 reader, serviceactor verification, buyersdk token call and journal, purchaseevidence, `tos-service-verify` | T4, T6 | Unit tests reproduce every vector; resolver derives every state including `paying` and `returned` from finalized data at one checkpoint; a mismatched master, wallet code hash, decimals or status refused | L |
| T8 | ai `provider/` | Token offers, withdrawals with outcomes, wallet floor, MCP provider tools | T7 | Provider MCP acceptance (`MCP_PROVIDER_ADAPTER_V1.md` section 10) extended to a token actor | M |
| T9 | ai MCP buyer, gateway | Per-asset budgets and preview; gateway token proposals | T7 | Buyer MCP Gate D cases (`MCP_BUYER_ADAPTER_V1.md` section 15) extended to a token actor; gateway never adds or changes an asset | M |
| T10 | all | Live lifecycles on a v16 local net, then the public testnet, with test USDC: responded, refunded, swept, returned (a refusal forced by the test-only wallet build), funding refused | T5, T7-T9 | Each reconstructed by a second resolver, evidence recorded as for the native rail | M |
| T11 | relayer | Implement settlement v5 (vote layout, generations, `cancel_lock`, `activate_generation`) and the live loop | — | Simnet end to end against the v5 contracts | L |
| T12 | tos, tos-ops, external | Bridge production gates (7.1) including T1 in the audited build, the USDC review, the canary, then the ConfigParam 84 USDC record by validator vote | T1, T2, T11 | Every SEC:97-113 item checked; record adopted | XL |

A refusal cannot be provoked on a live chain with the real wallet when the
budget is right. T10 therefore uses a test-only wallet build that refuses on
demand, pinned like the test actor build. Production code never accepts it,
because ConfigParam 84 pins the real wallet code hash.

## 9. Documents this design changes once decided

- New: `SERVICE_ACTOR_TOKEN_TVM_V1.md` (normative layout, from section 5).
- Edited in place:
  - `SOFTWARE_WORK_MANIFEST_V1.md` keys 20 and 21;
  - `ACCEPTED_QUOTE_TVM_V1.md` schema 3;
  - `SOFTWARE_WORK_RECEIPT_TVM_V1.md` schema 2;
  - `SETTLEMENT.md` delivery scope and asset roles (:9-19, :150-155);
  - `PRODUCT_STRATEGY.md` §9 (:293-327);
  - `SERVICE_ACTOR_SETTLEMENT_DESIGN.md` D8 (superseded, citing this
    document);
  - both MCP adapter documents' budget and amount rules;
  - `ROADMAP.md` gate entries.
- tos: `crosschain/token-bridge/SETTLEMENT-PROTOCOL.md` (reported transfers),
  `SECURITY.md` (USDC review item).

## 10. Open questions for the owner

- **Q1 Home network and second asset.** Is Ethereum (ConfigParam 79) the home
  network for USDC? Is the second recognized slot reserved, or used now, and
  for what (for example native Circle issuance later)? *Recommend:* Ethereum
  first; leave the second slot empty.
- **Q2 Recognition changes as critical parameters.** *Recommend:* yes, list
  ConfigParam 84 in ConfigParam 10: 3 won rounds, and a higher proposal
  storage price (CEREMONY:778-781).
- **Q3 Changing the bridge wallet before its audit.** The reported-transfer
  ops are required for D8's condition and change every minter address.
  *Recommend:* yes, now, so the audit covers the final wallet.
- **Q4 TOS for fees.** The storage fee, cleanup bounty and allowances stay in
  TOS, so a buyer needs a little TOS, or a sponsor. Is a sponsor-funded default
  needed for the first pilot? *Recommend:* buyer-held TOS for the pilot,
  sponsorship as is.
- **Q5 Unattributed deposits.** Tokens sent to an actor without a notification
  cannot be attributed. Leave them stranded (tooling refuses to build such
  transfers), or add a wallet balance report that lets the owner recover the
  surplus? *Recommend:* stranded in v1, with tooling refusal.
