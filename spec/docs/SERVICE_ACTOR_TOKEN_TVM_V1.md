# Service Actor Token TVM V1

**Status:** normative layout of the token-rail Service Actor, the contract of
section 5 of the design [`USDC_SETTLEMENT_V1.md`](USDC_SETTLEMENT_V1.md) (work
item T3). It settles one recognized TOS-network token (USDC, then USDT) through
reported transfers of the bridge token wallet (T1). The contract is
implemented in tosnetwork/tos#516 (open; final head
`7a32aa402944bb944a1c778197e491605f909df4`, final non-author APPROVE at that
head in the review record
https://github.com/tosnetwork/tos/pull/516#issuecomment-7168420438); it is not
merged, not released on
tos main and not deployed on any network. This document describes that
implementation exactly. Where it and the design text differ, this document and
the implementation govern, and the design records the change with the
decision that drives it (design section 11).

**Code identity.** The release manifest
`crypto/smartcont/tos-service-actor-token-v1.release.json` at the head above is
the authority; these values are copied from it:

```text
contract    tos-service-actor-token-v1
rail        tos.service.service-actor-token.v1
code hash   tvm-cell-sha256:4e797ecffa62614831f53f03dbf94d851b6e6418fa3e84d05af8ba575df7085a
BOC sha256  sha256:125aece02726d617df07a61f9cd46f0a27d87b6add4964bab2fc35075b4ebf64
BOC size    14,317 bytes
tos commit  6d59d09a82795436fedea6a114f4701c928db9bf
compiler    FunC v0.4.6 (392bc162e)
```

The contract source is identical at the manifest's `tos_commit` and at the PR
head. Clients pin this code hash for the token rail only, and select the
verifier by the manifest key 21 rail string and the pinned code hash. The
native Service Actor ([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md)), its
release hash and its rail string are unchanged. Until the PR merges and the
release is published from tos main, the hash above is a candidate: a change to
the contract changes it, and this document and its vectors are then updated
together.

**Test-only build.** `crypto/smartcont/tos-service-actor-token-v1-test.release.json`
pins a second build of the same source for test networks only. It sets
`MIN_RESPONSE_SLA` and `MIN_REFUND_CLAIM_WINDOW` to 600 seconds, and nothing
else changes:

```text
code hash   tvm-cell-sha256:edf727b8bb61786e33e3e00dc57fa1db41f8eeb6cbddc0382b3e8daf227e4c89
BOC sha256  sha256:0482be914785ec7a1367137b3bb5fced63c944520af5b6fd57211fe0bd353bfe
BOC size    14,317 bytes
```

Production clients refuse it.

**Vectors.** Section 16.

**Sources.** `SAT:N` is line `N` of `crypto/smartcont/service-actor-token-code.fc`
at the head above. `SDK:N` is line `N` of
`tosctl/src/node-control/contracts/src/service_actor_token.rs` (the Rust
builders and decoders). `TST <file>::<test>` names a sandbox test in
`tosctl/src/node-control/contracts/tests/service_actor_token/` at the same
head. `FND` is the token-rail section of `docs/service-actor-funding.md`.
`design §N` is a section of [`USDC_SETTLEMENT_V1.md`](USDC_SETTLEMENT_V1.md).
`T3 decision N` is decision N of the 16 listed in tosnetwork/tos#516; each is
also carried into the design (design section 11).

## 1. Role

A token-rail Service Actor sells per-call access priced in one recognized
token, fixed at deploy by its asset route (section 4.6). It keeps the native
actor's request lifecycle, terms tail, attestor, SRP2 response domain and
request snapshot. Funding, payouts and accounting differ:

- a call is funded by an ordinary token `transfer` to the actor, whose
  `transfer_notification` carries a `token_call` payload (section 7.1);
- once the notification is authenticated and funded, the handler never
  throws: every admission refusal is a funding return of the tokens to their
  sender (section 7.1);
- every token payout is a reported transfer, and its outcome (delivered,
  refused at the recipient's wallet R, or bounced at the actor's own wallet S)
  comes back authenticated, bound to the payout id and amount, and is accepted
  at most once. Ledger effects commit at the outcome (section 8);
- ConfigParam 84 is read at admission only. No payout, refund, sweep, return,
  recovery or withdrawal reads it (section 10).

The contract never decodes a Receipt (D9). The rail is workchain 0 only: the
actor, its asset master, its wallets, its callers and every payout destination
are canonical `addr_std` on workchain 0.

Units: `price_per_call`, every token liability and every payout amount are in
the token's atomic units. `storage_fee`, `cleanup_bounty`, every allowance,
every lock and the operating reserve are nanoTOS.

## 2. Constants

SAT:224-373. Changing any value is a contract change with its own release.

| Name | Value | Meaning |
|---|---|---|
| `MAX_COINS` (exclusive) | `2^120` | bound of every checked sum (SAT:224-236) |
| `MINIMUM_CLEANUP_BOUNTY` / `MAXIMUM_CLEANUP_BOUNTY` | 0.1 TOS / 1 TOS | as the native rail |
| `MINIMUM_STORAGE_FEE` | 0.1 TOS; `storage_fee >= MINIMUM_STORAGE_FEE + cleanup_bounty` | as the native rail |
| `MINIMUM_OPERATING_RESERVE` | 1 TOS | as the native rail |
| `MIN_RESPONSE_SLA`, `MAX_RESPONSE_SLA` | 3,600 / 2,592,000 s (600 s minimum in the test-only build) | as the native rail |
| `MIN_REFUND_CLAIM_WINDOW`, `MAX_REFUND_CLAIM_WINDOW` | 3,600 / 2,592,000 s (600 s minimum in the test-only build) | as the native rail |
| `MAX_LIVE_GLOBAL` | 1,500 | live (pending or refundable) requests (section 13) |
| `MAX_LIVE_PER_CALLER` | 1,000 | live requests of one caller |
| `MAX_RETURNED_GLOBAL` | 1,500 | returned entries at which admission stops (1935) |
| `MAX_RETURNED_PER_CALLER` | 16 | returned entries of one caller at which its admission stops (1935) |
| `MAX_RETURNS_IN_FLIGHT` | 512 | funding returns in flight; at the cap a refused funding makes no return (section 7.1) |
| `MAX_REVENUE_PAYOUTS` | 4 | revenue payouts in flight (1930) |
| `MAX_SURPLUS_PAYOUTS` | 4 | surplus payouts in flight (1930) |
| `MAX_LIVE_ATTESTOR_KEYS` | 4 | distinct attestor keys named by pending requests (1944) |
| `ACCEPTING_HEADROOM` | 64 | how far below each cap `get_accepting_tokens` turns false (section 13) |
| `RETURN_WINDOW` | 2,592,000 s | a returned entry's `return_deadline` after its creation or a refused sweep |
| `PAYOUT_RECHECK_AGE` | 2,592,000 s | age before `recheck_payout` of a buyer payout |
| `PAYOUT_ABANDON_AGE` | 2,592,000 s | age before `abandon_payout` of an owner payout |
| `RECHECK_QUERY_TTL` | 3,600 s | a pending balance query younger than this is never replaced or cleared |
| `NO_TOKEN_CAP` | `2^120 - 1` | the "no cap" value of `max_token_liability` and `max_liability_per_actor` |
| `PAYOUT_GAS_ALLOWANCE` | 0.2 TOS | the actor's own compute for a payout-creating op and for a balance-query leg; unused value returns |
| `TOKEN_WALLET_ALLOWANCE` | 0.3 TOS | the wallet storage reserve priced when no bridge parameter parses (section 11) |

The wallet constants the actor prices against are frozen in the T1 wallet code
(design 4.3) and copied at SAT:348-355: `R_GAS_LIMIT` 41,000,
`S_BOUNCE_GAS` 58,000, `S_TRANSFER_GAS` 127,000, `REPORT_MARGIN` 10,
`CLEAR_REFUSAL_GAS` 52,000 and `S_REREPORT_GAS` 19,042 (twice the most
measured at S's deepest `clear_refusal` and `rereport_refusal` paths). A
wallet code change that moves any of them requires a new actor release.

The actor's own gas constants are in section 12.

## 3. Post-quantum key material

As [`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md) section 3, unchanged:
`StoredKeyV1` of 1,312 bytes, `StoredSignatureV1` of 2,420 bytes, key id
`SHA-256("TOS-PQ-CONSENSUS-KEY-v1" || 0x01 0x00 || public_key)`, Pure
ML-DSA-44 under the context `TOS-SERVICE-ACTOR-RESPOND-V1`, exits 62 and 63 for
a bad length and a non-canonical chain, and 9 for a malformed wrapper.

## 4. Persistent data

SAT:28-79, SAT:414-504. Every cell is read with `end_parse`; trailing data in
stored state is a contract fault and fails the transaction with exit 9.

### 4.1 Root

```text
service_actor_token_data$_ owner:MsgAddress active:uint1
  next_request_id:uint64 pending_count:uint32 live_count:uint32
  next_payout_id:uint64
  ^ServiceActorTokenPolicyV1 ^ServiceActorTokenAccountingV1
  ^ServiceActorTokenRequestsV1 ^ServiceActorTokenPayoutDictsV1
  = ServiceActorTokenDataV1;
```

Deploy data (SDK:384-461) has `active = 1`, `next_request_id = 0`, zero
counters, `next_payout_id = 1`, `policy_version = 0`, empty ledgers and
dictionaries, and the empty balance query. Payout id `0` therefore never names
a payout; logs use it for "none".

### 4.2 Policy

SAT:506-555:

```text
policy$_ policy_version:uint32 price_per_call:Coins storage_fee:Coins
  cleanup_bounty:Coins response_sla:uint32 refund_claim_window:uint32
  open_access:uint1 has_authorized_caller:uint1 authorized_caller:MsgAddress
  rate_limit_per_day:uint32 max_token_liability:Coins
  ^policy_commitments = ServiceActorTokenPolicyV1;

policy_commitments$_ metadata_hash:uint256 proof_scheme_hash:uint256
  has_attestor:uint1 attestor_key_id:uint256
  attestor_key:(Maybe ^StoredKeyV1) = ServiceActorPolicyCommitmentsV1;
```

The native policy plus `max_token_liability`, the owner's cap on the actor's
token liability (`NO_TOKEN_CAP` for none). The commitments are the native ones
with the same two encodings of "no attestor" and "attestor"
([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md) section 4.1). A
deploy-time inconsistency is refused at admission with reason 1925 (section
7.1), never thrown.

### 4.3 Accounting, token ledger and balance query

SAT:39-51, SAT:427-446, SAT:557-590:

```text
accounting$_ withdrawable_tos_revenue:Coins locked_storage_fees:Coins
  locked_outcome_fees:Coins call_day:uint32 calls_today:uint32
  revenue_payouts_in_flight:uint8 returned_count:uint32
  returns_in_flight:uint16 surplus_payouts_in_flight:uint8
  attestor_key_count:uint8
  ^token_ledger ^balance_query ^asset_route = ServiceActorTokenAccountingV1;

token_ledger$_ pending_liability:Coins refundable_liability:Coins
  returned_liability:Coins in_flight:Coins withdrawable_token_revenue:Coins
  = ServiceActorTokenLedgerV1;                 -- token atomic units

balance_query$_ active:uint1 query_id:uint64 purpose:uint1 created_at:uint32
  floor:uint64 delivered_since_floor:Coins recheck_target:uint64
  amount:Coins requester:MsgAddress = ServiceActorBalanceQueryV1;
```

The native ledger (`withdrawable_tos_revenue`, `locked_storage_fees`,
`locked_outcome_fees`, the operating reserve) is in nanoTOS. `purpose` is 0 for
a surplus query and 1 for a recheck query. The empty query is all zero bits
with `requester = addr_none` (236 bits, SAT:588-590, SDK:1090-1102).

**Token invariant.** The actor's token wallet balance, plus the tokens of every
payout that has left the wallet, has not been credited back to it (as after a
refusal at R), and whose outcome the actor has not yet applied,
is at least `attributed = pending_liability + refundable_liability +
returned_liability + in_flight + withdrawable_token_revenue` (SDK:881-887).
During a payout S debits its balance before the outcome report reaches the
actor, which keeps the amount in `in_flight` until then (section 8.3), so the
wallet balance alone can be below `attributed` while a payout is in transit; a
resolver or solvency monitor that checks the balance alone must therefore add
the in-transit payouts, or check only at a point where none is in transit. When
no payout is in transit, the rest of the balance is **surplus** (section 8.5
explains why surplus is only ever under-counted while one is). The token
**liability** the exposure caps bound is the same sum without
`withdrawable_token_revenue` (SDK:890-895).

### 4.4 Requests

SAT:55-58, SAT:447-451, SAT:928-990, SAT:1053-1099:

```text
requests$_ pending_requests:(HashmapE 64 ^PendingRequestV1)
  refunds:(HashmapE 64 ^RefundV1)
  caller_live_counts:(HashmapE 256 uint32)
  attestor_keys:(HashmapE 256 AttestorKeyRefV1) = ServiceActorTokenRequestsV1;

attestor_key_ref$_ refs:uint32 key:^StoredKeyV1 = AttestorKeyRefV1;
```

`PendingRequestV1` and `RefundV1` keep the native layouts
([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md) sections 4.2-4.3), with one
difference: the `attestor_key` reference of a pending request's commitments is
always absent (T3 decision 3). A pending request names its key by
`attestor_key_id`; `attestor_keys` holds each named key once, keyed by key id,
with the number of pending requests that name it (`refs`), and
`attestor_key_count` is the number of its entries. A key is added or its count
incremented at admission, and decremented when a pending request leaves the
pending store by `respond`, by `expire`, or by a sweep payout of a pending
entry that settles (delivered, refused at R or rechecked; a bounce at S
restores the entry and keeps its reference); the entry is deleted at zero. `respond`
verifies against the key in `attestor_keys`, never against the policy.

`caller_live_counts` is keyed by `slice_hash` of the caller's full address,
workchain included (SAT:1026-1043).

### 4.5 Payouts and returned entries

SAT:59-79, SAT:452-455, SAT:1004-1021, SAT:1103-1176:

```text
payout_dicts$_ payouts:(HashmapE 64 ^PayoutV1)
  returned:(HashmapE 64 ^ReturnedV1)
  caller_returned_counts:(HashmapE 256 uint32)
  = ServiceActorTokenPayoutDictsV1;

payout$_ kind:uint3 request_id:uint64 recipient:MsgAddressInt
  requester:MsgAddressInt amount:Coins created_at:uint32
  ^payout_auth = PayoutV1;
payout_auth$_ recipient_wallet:MsgAddressInt own_wallet:MsgAddressInt
  outcome_fee_lock:Coins ^ledger_undo = PayoutAuthV1;
ledger_undo$_ source:uint2 entry:(source != 0 ? ^Cell : nothing)
  = LedgerUndoV1;

returned$_ caller:MsgAddressInt amount:Coins paying:uint64
  return_deadline:uint64 = ReturnedV1;
```

| `kind` | Payout | `request_id` | `recipient` | `requester` |
|---:|---|---|---|---|
| 1 | refund (`claim_refund`) | the request id | the claim's `destination` | the claimer (the request's caller) |
| 2 | sweep (`sweep_expired_request`) | the request id | the request's caller | the sweeper |
| 3 | revenue withdrawal | 0 | the owner | the owner |
| 4 | funding return | 0 | the funding's `from` | the funding's `from` |
| 5 | returned-entry claim (`claim_returned`) | the returned entry's id | the claim's `destination` | the claimer (the entry's caller) |
| 6 | surplus recovery | 0 | the owner | the sender of `recover_surplus` |
| 7 | returned-entry sweep (`sweep_returned`) | the returned entry's id | the entry's caller | the sweeper |

- Payouts are keyed by payout id. The transfer's `query_id` is the payout id.
  `next_payout_id` only increases and is never reused; every payout-creating
  op requires `next_payout_id < 2^64 - 1` (1909; T3 decision 10), and
  `recover_surplus`, which consumes two ids, requires `< 2^64 - 2`.
- `recipient_wallet` is the bridge wallet of `recipient` under the route
  (section 4.6), derived when the payout is created; `own_wallet` is the
  actor's own wallet. The outcome handlers authenticate by comparing the
  sender with these stored addresses, so they derive nothing before their gas
  limit is raised.
- `ledger_undo.source` is 0 (none), 1 (the entry came from `pending_requests`)
  or 2 (from `refunds`); for kinds 1 and 2 the entry's cell is the reference,
  and a bounce at S restores it to its dictionary. Every other kind has source
  0 and no reference.
- `returned` is keyed by the id of the payout whose refusal created the entry.
  `paying` is the id of the kind 5 or 7 payout in flight for the entry, or 0.
  `caller_returned_counts` is keyed like `caller_live_counts`.

### 4.6 Asset route

SAT:52-54, SAT:592-619; SDK:186-216:

```text
asset_route$_ master:MsgAddressInt wallet_code_hash:uint256
  wallet_code:^Cell bridge_config_param:uint32 = ServiceActorAssetRouteV1;
```

- `master` is the token master (a bridge minter): a canonical `addr_std` on
  workchain 0 with no anycast.
- `wallet_code_hash == cell_hash(wallet_code)`; `wallet_code` is the code the
  minter derives wallets with (the reported-transfer wallet of T1).
- `bridge_config_param` names the asset's token bridge parameter, one of 79,
  81, 82 or 83 (T3 decision 4). The SDK refuses any other value at deploy
  (SDK:476-480), and admission refuses one with 1932 (SAT:1621-1623).

No op changes the route. Admission refuses with 1932 while any of the three
conditions fails, mirroring the native re-check of deploy data at `call`.

**Wallet derivation** (SAT:628-662; SDK:1068-1088). The bridge wallet of
`owner` under the route is `0:cell_hash(StateInit)` with

```text
StateInit = (split_depth: none, special: none, code: wallet_code,
             data: wallet_data, library: empty)
wallet_data = balance:Coins(0) owner:MsgAddressInt master:MsgAddressInt
  ^wallet_code ^empty_settlement refusals_count:uint16(0)
  refusals:(HashmapE 64 Coins)(empty)
empty_settlement = 161 zero bits, 192 zero bits, an empty dictionary bit,
  128 zero bits, an empty dictionary bit           -- 483 bits, no references
```

as the bridge's `calculate_token_wallet_state_init` builds it. The actor's own
wallet is the wallet of `my_address()`. The actor derives it at run time (its
address depends on its own StateInit, so the address cannot be stored there);
resolvers reproduce it independently from the route in the account data.

## 5. `terms_hash`

SAT:870-906; SDK:246-343:

```text
terms_hash = cell_hash(token_terms)
token_terms$_ policy_version:uint32 price_per_call:Coins storage_fee:Coins
  cleanup_bounty:Coins response_sla:uint32 refund_claim_window:uint32
  asset_master:uint256 asset_wallet_code_hash:uint256
  ^terms_tail = ServiceActorTokenTermsV1;                -- root <= 980 bits
terms_tail$_ metadata_hash:uint256 proof_scheme_hash:uint256
  has_attestor:uint1 attestor_key_id:uint256 = ServiceActorTermsTailV1;
```

- `asset_master` is the route master's 256-bit account id, and
  `asset_wallet_code_hash` the route's `wallet_code_hash`. A route whose master
  is not canonical yields `asset_master = 0` (SAT:896-906); such a route admits
  nothing (1932).
- `terms_tail` is the native tail unchanged; `attestor_key_id` is zero when
  `has_attestor = 0`.
- `price_per_call` is atomic units; `storage_fee` and `cleanup_bounty` are
  nanoTOS. Admission gates (`open_access`, `authorized_caller`,
  `rate_limit_per_day`) and `max_token_liability` are excluded.
- A conforming decoder (SDK:298-342) refuses trailing bits or references in
  either cell, `has_attestor = 1` with a zero key id, `has_attestor = 0` with a
  non-zero key id, and any cell whose canonical re-encoding has another hash
  (for example a non-minimal Coins length).

## 6. Response statement (SRP2)

As [`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md) section 6, unchanged
(SAT:908-924): the same `srp2` and `srp2_tail` layouts, `GLOBALID`, the actor's
own address, and `price` equal to the request's `price_per_call`, here in
atomic units. The asset is bound through `terms_hash`.

## 7. Inbound messages

SAT:81-106, SAT:1288-2061. Every body starts with `op:uint32 query_id:uint64`
(SAT:1343-1344). An empty body is a plain top-up and is ignored (SAT:1340).
`excesses` (`0xd53276db`) is accepted as value only (SAT:1488). An op that no
branch handles fails with 1910 (SAT:1905-1907, SAT:2060); this includes the
native rail's `call#53564301`, so native value with a `call`-shaped body is not
funding. Every lifecycle and owner handler ends its body parse with
`end_parse` (exit 9 for trailing data or a missing field).

Bounced messages are handled in section 8.6. A bounced message whose body has
fewer than 96 bits after the bounce prefix is ignored (SAT:1297-1300).

**Addresses with anycast or `addr_var`.** `LDMSGADDR` refuses them from global
version 10, so a body naming one fails with exit 9 at its parse, before any
state change (T3 decision 11; TST `payouts::claim_destinations_are_validated`).
The checks below that refuse 1934 therefore see only `addr_std` and
`addr_none`.

### 7.1 Funding: `transfer_notification`

SAT:1492-1717. The buyer sends an ordinary token `transfer` to the actor
(SDK:549-586):

```text
transfer#0f8a7ea5 query_id:uint64 amount:Coins destination:MsgAddress
  response_destination:MsgAddress custom_payload:(Maybe ^Cell)
  forward_tos_amount:Coins forward_payload:(Either Cell ^Cell)

token_call#53544301 request_hash:uint256 expected_terms_hash:uint256
```

with `destination` = the actor, `amount = price_per_call`, no custom payload,
`forward_tos_amount >= storage_fee + MIN_FUNDING_VALUE` (section 11) and the
`token_call` as forward payload, inline or by reference. The actor's wallet
then sends

```text
transfer_notification#7362d09c query_id:uint64 amount:Coins from:MsgAddress
  forward_payload:(Either Cell ^Cell)
```

with `forward_tos_amount` as its value. Notifications are non-bounceable, so
nothing in this handler can return the tokens by bouncing. The handler runs in
these steps, each on the notification's own value (it never raises its gas
limit):

1. **Foreign or spoofed notification** (the sender is not the actor's own
   wallet, derived from the stored route; SAT:1496-1513). No token reached the
   actor's wallet and no state changes. The actor sends the sender, in mode 64
   and non-bounceable,
   `transfer query_id amount destination=from response_destination=from
   custom_payload=none forward_tos_amount=0 forward_payload=(inline, empty)`.
   A wallet the actor owns returns the tokens; anything else ignores it. A
   notification from a wallet of another master (a wrong asset) is this case.
2. **Underfunded** (`msg_value < MIN_FUNDING_VALUE`; SAT:1514-1523). Nothing is
   stored and the tokens are surplus. `SAF1` with reason 1929 and payout id 0
   is emitted only when `msg_value >= ADMISSION_GAS_ALLOWANCE`; otherwise
   nothing is sent (T3 decisions 7 and 15). If the value cannot pay for the
   compute up to this point, the transaction fails, and the tokens are again
   surplus.
3. **Authenticated and funded: from here nothing throws.** `from` is the
   caller, authenticated by the actor's wallet. Three parses run in
   `try`/`catch` and feed a reason instead of throwing (SAT:1525-1599):
   - the payload: one bit `1` then exactly one reference and nothing else, or
     bit `0` and the payload inline; then the tag `0x53544301`, 256 + 256
     bits and nothing else. Any other shape gives 1939 `malformed_payload`
     (T3 decision 7; TST
     `funding::a_malformed_payload_takes_the_refusal_path_without_a_throw`,
     `funding::an_inline_payload_is_admitted_like_a_referenced_one`);
   - ConfigParam 84 (section 10); any failure gives 1933;
   - a deploy-time attestor key: with `has_attestor = 1` the key must be a
     canonical stored key whose id equals `attestor_key_id`; with
     `has_attestor = 0` the key must be absent and the id zero. Any failure,
     including a malformed key, gives 1925.
4. **Admission checks**, in this order; the first failure is the refusal
   reason (SAT:1601-1656):

   | # | Condition | Reason |
   |---:|---|---|
   | 1 | the payload parsed | 1939 |
   | 2 | `active` | 1901 |
   | 3 | `response_sla` in bounds | 1903 |
   | 4 | `refund_claim_window` in bounds | 1904 |
   | 5 | `cleanup_bounty` in bounds | 1905 |
   | 6 | `storage_fee >= MINIMUM_STORAGE_FEE + cleanup_bounty` | 1906 |
   | 7 | `price_per_call > 0` and `max_token_liability > 0` | 1902 |
   | 8 | the attestor commitments hold (step 3) | 1925 |
   | 9 | with an attestor whose key is not yet in `attestor_keys`, `attestor_key_count < MAX_LIVE_ATTESTOR_KEYS` | 1944 |
   | 10 | the route holds (section 4.6) | 1932 |
   | 11 | ConfigParam 84 lists the master with status 1 and the route's `wallet_code_hash` (section 10) | 1933 |
   | 12 | `from` is a canonical `addr_std` on workchain 0 | 1934 |
   | 13 | `open_access`, or `has_authorized_caller` and `from == authorized_caller` | 1923 |
   | 14 | `amount == price_per_call` exactly (overpayment and underpayment alike) | 1902 |
   | 15 | `msg_value >= storage_fee + MIN_FUNDING_VALUE` | 1902 |
   | 16 | `pending_liability + price`, `locked_storage_fees + storage_fee` and `backing + storage_fee` stay below `2^120` | 1927 |
   | 17 | `live_count < MAX_LIVE_GLOBAL` | 1907 |
   | 18 | `from`'s live count `< MAX_LIVE_PER_CALLER` | 1908 |
   | 19 | `next_request_id < 2^64 - 1` | 1909 |
   | 20 | the daily rate limit (`0` is unlimited) | 1924 |
   | 21 | `returned_count < MAX_RETURNED_GLOBAL` and `from`'s returned count `< MAX_RETURNED_PER_CALLER` | 1935 |
   | 22 | `liability + price_per_call <= min(max_token_liability, max_liability_per_actor)` | 1937 |
   | 23 | `expected_terms_hash == terms_hash` (section 5) | 1926 |
   | 24 | `backing >= locked_storage_fees + locked_outcome_fees + MINIMUM_OPERATING_RESERVE`, where `backing = max(balance - msg_value, 0)` | 1928 |

   `liability` is `pending + refundable + returned + in_flight` (revenue
   excluded); `max_liability_per_actor` comes from the recognition record. The
   caps are per actor, so many actors can exceed them in aggregate; only the
   aggregate watch of T14 sees that.

   **Checked arithmetic and the no-throw guarantee** (SAT:224-271; the T3
   checked-arithmetic change, review round 4 of tos#516). Every monetary
   quantity uses checked or saturating helpers:

   - Every predicate in the table and every budget of section 11 is computed
     with saturating sums, products and differences, which never throw. A
     saturated sum or product is capped at `MAX_COINS` (`2^120`), which no
     Coins field holds, and each sits on the side of its comparison where a
     larger value refuses. A difference below zero is zero.
   - Row 16 (1927) now comes before the capacity checks. A pending liability
     that would reach `2^120` is therefore refused with 1927, where it used to
     reach the exposure cap and be refused with 1937 (TST
     `funding::a_ledger_one_below_the_coins_bound_refuses_a_new_admission_with_amount_range`,
     `funding::amounts_at_the_coins_bound_are_refused_by_a_predicate_and_never_thrown`).
   - Each ledger mutation after acceptance is checked, and is guarded by a
     predicate computed on the same values, so no checked mutation can throw
     after a funded, authenticated notification is accepted.
   - A saturated budget that is stored or sent as Coins (the transfer body's
     `report_tos_amount`, a payout's `outcome_fee_lock`) cannot reach
     `MAX_COINS` after acceptance. Any such saturation also saturates
     `MIN_FUNDING_VALUE`, so the notification takes the underfunded branch
     (step 2) first.
5. **Admitted** (SAT:1658-1691). The actor stores the pending request under
   `request_id = next_request_id` with `caller = from`, the policy's price, fee,
   bounty and version, the deadlines `response_deadline = now + response_sla`
   and `refund_claim_deadline = response_deadline + refund_claim_window`, the
   `request_hash`, the `terms_hash`, the attestor flag and id, and no key
   reference; it references the key in `attestor_keys`, increments the
   counters and the daily count, adds `price` to `pending_liability` and
   `storage_fee` to `locked_storage_fees`; then `raw_reserve(backing +
   storage_fee, 0)`, emits `SAT1` (mode 1, section 9.1) and sends the change to
   `from` (mode 128).
6. **Refused** (SAT:1693-1716). The tokens go back to `from` as a kind 4
   funding return paid from the notification's `RETURN_BUDGET`
   (section 8): `SAF1` names the reason and the payout id, then the reported
   transfer follows. No funding return is made, and `SAF1` names payout id 0,
   when:
   - `amount == 0` (nothing to return);
   - `next_payout_id` is exhausted;
   - `returns_in_flight >= MAX_RETURNS_IN_FLIGHT` (T3 decision 2); or
   - `from` is not a canonical `addr_std` on workchain 0 (T3 decision 14; the
     bridge forces workchain 0, so this is unreachable with the bridge wallet);
     or
   - the return would not fit its ledgers in Coins: `in_flight + amount`,
     `locked_outcome_fees + outcome_fee_lock` or `backing + outcome_fee_lock`
     would reach `2^120` (the checked-arithmetic change).

   In those cases nothing is stored and the tokens are surplus, recoverable
   only by `recover_surplus`. In every other refusal the tokens stay attributed
   to `from` (section 8.3).

`request_hash` is stored opaquely; buyers never reuse one and never send zero.

### 7.2 `respond`

SAT:1722-1753:

```text
respond#53544302 query_id:uint64 request_id:uint64 response_hash:uint256
  signature:(request has_attestor ? ^StoredSignatureV1 : nothing)
```

Checks, in order: sender is the owner (1900); request pending (1913);
`now < response_deadline` (1912); with an attestor, the signature reference
(9 when absent), the stored signature (62, 63, 9) and its verification over
SRP2 under the request's key from `attestor_keys` (1911); `end_parse` (9).
Effect: deletes the request and releases its key reference and capacity;
`pending_liability -= price`, `withdrawable_token_revenue += price`,
`locked_storage_fees -= storage_fee`, `withdrawable_tos_revenue +=
storage_fee`. No message is sent.

### 7.3 `expire`

SAT:1755-1773. `expire#53544303 query_id:uint64 request_id:uint64`.
Permissionless; pending (1913); `response_deadline <= now` (1914);
`now < refund_claim_deadline` (1915). Moves the request to `refunds`
(releasing its key reference) and its price from pending to refundable
liability. Capacity is not released.

### 7.4 `claim_refund`

SAT:1777-1799:

```text
claim_refund#53544304 query_id:uint64 request_id:uint64 destination:MsgAddressInt
```

Checks, in order: the sender is a canonical `addr_std` on workchain 0 (1934);
refund present (1917); sender is the refund's caller (1918);
`now < refund_claim_deadline` (1916); `next_payout_id < 2^64 - 1` (1909);
`destination` is a canonical `addr_std` on workchain 0 and not the actor
(1934); `msg_value >= PAYOUT_FUNDING` (1929); `balance - msg_value >= 0`
(1921). Effect: deletes the refund, `refundable_liability -= price`, creates a
kind 1 payout of `price` to `destination` with the refund entry as its
`ledger_undo`, and sends it (section 8.1). Capacity and the TOS side settle at
the outcome.

### 7.5 `sweep_expired_request`

SAT:1801-1835. `sweep_expired_request#53544305 query_id:uint64 request_id:uint64`.
Permissionless. Checks: the request is pending or refundable (1920);
`next_payout_id < 2^64 - 1` (1909); `now >= refund_claim_deadline` (1919);
`msg_value >= PAYOUT_FUNDING` (1929); `balance - msg_value >= 0` (1921).
Effect: deletes the entry from its dictionary and its price from its
liability (`pending_count` unchanged), creates a kind 2 payout of `price` to
the request's **caller** with the entry and its source as `ledger_undo`, and
sends it.

### 7.6 `claim_returned`

SAT:1837-1860:

```text
claim_returned#5354430a query_id:uint64 id:uint64 destination:MsgAddressInt
```

Checks: the sender is canonical on workchain 0 (1934); the entry exists
(1931); sender is its caller (1918); `paying == 0` (1930); `next_payout_id <
2^64 - 1` (1909); destination as `claim_refund` (1934); `msg_value >=
PAYOUT_FUNDING` (1929); `balance - msg_value >= 0` (1921). Effect:
`returned_liability -= amount`, creates a kind 5 payout of `amount` to
`destination`, sets the entry's `paying` to the payout id, and sends it. A
second claim, in the same block or later, fails with 1930 while the first is
in flight (TST `payouts::a_double_claim_returned_in_one_block_is_refused_with_1930`).

### 7.7 `sweep_returned`

SAT:1862-1881. `sweep_returned#5354430d query_id:uint64 id:uint64`.
Permissionless. Checks: the entry exists (1931); `next_payout_id < 2^64 - 1`
(1909); `now >= return_deadline` (1919); `paying == 0` (1930); `msg_value >=
PAYOUT_FUNDING` (1929); `balance - msg_value >= 0` (1921). Effect as
`claim_returned`, but a kind 7 payout to the entry's **caller**, never to the
sweeper.

### 7.8 `recheck_payout`

SAT:1883-1902. `recheck_payout#5354430f query_id:uint64 id:uint64`.
Permissionless and funded. Checks: the payout exists (1940); its kind is 1, 2,
4, 5 or 7 (1941); `now >= created_at + PAYOUT_RECHECK_AGE` (1942); no balance
query younger than `RECHECK_QUERY_TTL` is pending (1943); `msg_value >=
PAYOUT_GAS_ALLOWANCE` (1929); `next_payout_id < 2^64 - 1` (1909). Effect: a
new query id from `next_payout_id`, a recheck query (`purpose = 1`, `floor =
query_id`, `delivered_since_floor = 0`, `recheck_target = id`, `requester =
sender`) replacing any older query, and `provide_balance(query_id)` to the
actor's wallet, bounceable, mode 64 + 16. The answer is section 8.5.

### 7.9 Owner operations

SAT:1904-2058. For `update_policy`, `rotate_attestor_key`, `revoke_attestor`,
`withdraw_revenue`, `recover_surplus` and `abandon_payout`, any other op is
1910 first, then a sender other than the owner is 1900.

**`update_policy`** (SAT:1913-1945):

```text
update_policy#53544306 query_id:uint64
  price_per_call:Coins storage_fee:Coins cleanup_bounty:Coins
  response_sla:uint32 refund_claim_window:uint32
  active:uint1 open_access:uint1 has_authorized_caller:uint1
  authorized_caller:MsgAddress rate_limit_per_day:uint32
  max_token_liability:Coins
  ^[ metadata_hash:uint256 proof_scheme_hash:uint256 ]
```

Bounds in order: 1903, 1904, 1905, 1906 (as admission), then `price_per_call
> 0` (1902) and `max_token_liability > 0` (1937) (T3 decision 10). Replaces
the policy and `active` and sets `policy_version + 1`. It cannot change the
route or the attestor.

**`rotate_attestor_key`** (SAT:1947-1957). `rotate_attestor_key#53544307
query_id:uint64 attestor_key:^StoredKeyV1`. Derives the key id (62, 63, 9),
then refuses with **1944** `attestor_keys_full` while `attestor_key_count >=
MAX_LIVE_ATTESTOR_KEYS` (T3 decision 3), whatever the key. Writes
`has_attestor = 1`, the id and the key; `policy_version` is not bumped.

**`revoke_attestor`** (SAT:1959-1965). `revoke_attestor#53544308
query_id:uint64`. Writes the "no attestor" encoding. Pending requests keep
naming their keys.

**`withdraw_revenue`** (SAT:1967-2015):

```text
withdraw_revenue#53544309 query_id:uint64 token_amount:Coins tos_amount:Coins
```

With `backing = balance - msg_value`: `backing >= 0`, then `backing` covers
`locked_storage_fees`, then `locked_outcome_fees`, then
`MINIMUM_OPERATING_RESERVE`, and `tos_amount <= min(withdrawable_tos_revenue,
remainder)` and `token_amount <= withdrawable_token_revenue`; any failure is
1922. With `token_amount > 0`: `revenue_payouts_in_flight <
MAX_REVENUE_PAYOUTS` (1930), the owner canonical on workchain 0 (1934; T3
decision 10), `next_payout_id < 2^64 - 1` (1909) and `msg_value >=
PAYOUT_FUNDING` (1929); otherwise `msg_value >= PAYOUT_GAS_ALLOWANCE` (1929).
Effect: `withdrawable_tos_revenue -= tos_amount`; with a token part,
`withdrawable_token_revenue -= token_amount` and a kind 3 payout to the owner;
`tos_amount` is sent to the owner in mode 1, and the rest as the payout's
value (section 8.1) or as change to the sender (mode 128).

**`recover_surplus`** (SAT:2017-2035). `recover_surplus#5354430b
query_id:uint64 amount:Coins`. Checks: `amount > 0` (1936);
`surplus_payouts_in_flight < MAX_SURPLUS_PAYOUTS` (1930); the owner canonical
on workchain 0 (1934); no balance query younger than `RECHECK_QUERY_TTL` (1943);
`msg_value >= PAYOUT_GAS_ALLOWANCE + PAYOUT_FUNDING` (1929); `next_payout_id <
2^64 - 2` (1909). Effect: a surplus query (`purpose = 0`, `floor = query_id`,
`amount`, `requester = sender`) replacing any older query, and
`provide_balance(query_id)` to the actor's wallet, bounceable, mode 64 + 16
(T3 decision 6). The answer is section 8.5.

**`abandon_payout`** (SAT:2037-2058). `abandon_payout#5354430c query_id:uint64
id:uint64`. Checks: the payout exists (1940); its kind is 3 or 6 (**1941**, T3
decision 7); `now >= created_at + PAYOUT_ABANDON_AGE` (1938); no balance query
younger than `RECHECK_QUERY_TTL` (1943; an older one is cleared, and the owner
re-queries); `balance - msg_value >= 0` (1921). Effect: the "Abandoned" column
of section 8.3, `SAO1` with outcome 5 (mode 1), and the change to the sender
after `raw_reserve(max(backing - lock, 0), 0)`. It credits nothing: tokens
still in S show later as surplus.

## 8. Outcome protocol

### 8.1 Sending a payout

SAT:682-699, SAT:828-842, SAT:1150-1186.

- **Creation** (`create_payout`): a fresh payout id, `recipient_wallet`
  derived, `outcome_fee_lock` computed at current prices, `in_flight +=
  amount`, `locked_outcome_fees += lock`.
- **Body.** One cell, so 713 `payload_too_large` cannot arise at S (T3
  decision 12):

  ```text
  reported_transfer#52545231 query_id:uint64(payout id) amount:Coins
    destination:MsgAddressInt(recipient) response_destination:MsgAddress(requester)
    report_tos_amount:Coins forward_tos_amount:Coins(0)
    forward_payload:(Either Cell ^Cell)(one bit 0: inline and empty)
  ```

  No notification reaches the recipient, which rules out refund or return
  loops between token actors.
- **Value.** `raw_reserve(retained, 0)` where `retained` is the balance before
  the requester's message plus the lock, then the reported transfer to
  `own_wallet`, bounceable, in mode **128 + 16** (T3 decision 6): everything the
  requester attached above its lock goes to S, which spends what it needs and
  passes the rest to R, whose excess returns to the requester (the
  `response_destination`). An action-phase failure at the actor bounces the
  requester's message, and the payout's creation rolls back.
- **`report_tos_amount`** = `10 × (gas_fee(PRE_ACCEPT_GAS) +
  gas_fee(S_BOUNCE_GAS) + F) + F`, where `F = get_forward_fee(1023 bits, 1
  cell)`. On delivery R sends it with `transfer_delivered` and it pays the
  actor's pre-accept part. On a refusal at R it returns inside the bounce and
  pays S's bounce handler, the forwarding of `transfer_refused` and the actor's
  pre-accept part, each at `REPORT_MARGIN`, whatever the bridge parameter's
  storage reserve holds.
- **`outcome_fee_lock`** = `10 × (gas_fee(OUTCOME_HANDLER_GAS) +
  gas_fee(CLEAR_REFUSAL_GAS) + 4F)`, reserved from the requester's TOS (T3
  decision 5). It funds the whole outcome handler, the `clear_refusal` it may
  send with its value, and the forwarding of every send it may make. The
  unspent part returns to the requester as change. The lock counts in backing.

`gas_fee(g)` is `GETGASFEE(g, basechain)` and `get_forward_fee` is
`GETFORWARDFEE` on the basechain, both at the prices of the running
transaction.

### 8.2 Accepted outcome inputs

SAT:1293-1409. Before raising its gas limit, each handler reads only the op,
the query id, the root and the `payouts` reference (`peek_payout`), compares
the stored payout with the message, and only then calls
`set_gas_limit(OUTCOME_HANDLER_GAS)`. A message that does not match never
raises the limit and ends on its own value.

| Input | Authenticated by | Accepted when | Outcome |
|---|---|---|---|
| `transfer_delivered#52544431 query_id amount:Coins recipient:MsgAddressInt` | sender `==` stored `recipient_wallet` | the payout exists, `amount` and `recipient` equal it | delivered (0) |
| `transfer_refused#52544631 query_id amount:Coins` | sender `==` stored `own_wallet` | the payout exists and `amount` equals it | refused at R (1), then `clear_refusal` |
| `transfer_rereported#52545232 query_id total:Coins` | as `transfer_refused` | as `transfer_refused` | as `transfer_refused` |
| bounce of `reported_transfer` (bounced body `op query_id amount ...`) | bounce sender `==` stored `own_wallet` | the payout exists and the bounced amount equals it | bounced at S (2); for kind 4 the ledger applies "refused" |

**Non-matching and stale inputs** (SAT:1347-1400):

- `transfer_delivered` for an absent payout, from another sender, or with
  another amount or recipient: ignored.
- `transfer_refused` or `transfer_rereported` for an **absent** payout: if the
  sender is the actor's own wallet (derived on the message's own value), the
  actor answers `clear_refusal(query_id)` to it, non-bounceable, mode 64, on the
  message's own value. This is the branch `ABSENT_REPORT_GAS` bounds.
- `transfer_refused` or `transfer_rereported` from `own_wallet` for an existing
  payout with **another amount**: the payout and S's record both stay, and
  `SAO1` with outcome 4 (`mismatch`) and the reported amount is emitted only
  when `msg_value >= gas_fee(PRE_ACCEPT_GAS) + F` (T3 decision 15). It cannot
  arise while payout ids are never reused.
- A bounce of `reported_transfer` from another sender, for an absent payout or
  with another amount: ignored.

Every bounce from S is an ordinary S refusal, whatever its exit code (712
`refusal_pending`, 714 `refusals_full`, an insufficient value, an absent bridge
parameter, an action-phase failure): no token left S. 713 cannot arise for
the actor's one-cell body (T3 decision 12). The actor cannot read the exit code
from the 256-bit bounce body and does not need it.

### 8.3 Ledger effects and the exit-path table

SAT:1188-1266. `p` is the request's price, `a` the payout amount, `l` the lock.
Every accepted outcome deletes the payout and `locked_outcome_fees -= l`.
"TOS settlement" is `locked_storage_fees -= storage_fee`,
`withdrawable_tos_revenue += storage_fee - cleanup_bounty`, and the
`cleanup_bounty` owed to the requester (the claimer or the sweeper). "Live
release" is `live_count -= 1`, the caller's live count `-= 1`, and, for an
entry that came from `pending_requests`, `pending_count -= 1` and the release
of its attestor key reference. "Returned for `c`" is a new returned entry keyed
by the payout id, for caller `c`, with `return_deadline = now + RETURN_WINDOW`,
`returned_liability += a`, `returned_count += 1` and `c`'s returned count `+=
1`.

| Kind | At creation | Delivered | Refused at R (and rechecked) | Bounced at S | Abandoned |
|---|---|---|---|---|---|
| 1 refund | `refundable -= p`; `in_flight += p`; `lock += l` | `in_flight -= p`; live release; TOS settlement | as delivered, plus returned for the request's caller | `in_flight -= p`; the refund entry restored; `refundable += p` | refused (1941) |
| 2 sweep | `pending` or `refundable -= p`; `in_flight += p`; `lock += l` | `in_flight -= p`; live release; TOS settlement | as delivered, plus returned for the request's caller | `in_flight -= p`; the entry restored to its source; its liability `+= p` | refused (1941) |
| 3 revenue | `withdrawable_token_revenue -= a`; `revenue_payouts_in_flight += 1`; `in_flight += a`; `lock += l` | `in_flight -= a`; `revenue_payouts_in_flight -= 1` | `in_flight -= a`; `revenue_payouts_in_flight -= 1`; `withdrawable_token_revenue += a` | as refused | `in_flight -= a`; `revenue_payouts_in_flight -= 1` |
| 4 funding return | `returns_in_flight += 1`; `in_flight += a`; `lock += l` | `in_flight -= a`; `returns_in_flight -= 1` | `in_flight -= a`; `returns_in_flight -= 1`; returned for `from` | as refused (`SAO1` outcome 2) | refused (1941) |
| 5 returned claim | `returned -= a`; `paying = id`; `in_flight += a`; `lock += l` | `in_flight -= a`; the entry deleted; `returned_count -= 1`; the caller's returned count `-= 1` | `in_flight -= a`; `returned += a`; `paying = 0` | as refused | refused (1941) |
| 7 returned sweep | as kind 5 | as kind 5 | as kind 5, and `return_deadline = now + RETURN_WINDOW` | as kind 5 refused, deadline unchanged | refused (1941) |
| 6 surplus | `surplus_payouts_in_flight += 1`; `in_flight += a`; `lock += l` | `in_flight -= a`; `surplus_payouts_in_flight -= 1` | as delivered (the amount is back in surplus) | as delivered | as delivered |

Kinds 3 and 6 are never rechecked (1941). A request is **refunded** or
**swept** only when its payout is delivered; a refused refund or sweep leaves
it **returned**, a buyer-visible state with the action `claim_returned`.

### 8.4 Finishing an outcome

SAT:1268-1284 (`finish_outcome`). With `backing` the balance before the
outcome message, the actor saves state, then:

1. emits `SAO1` (mode 1 + 2);
2. `raw_reserve(max(backing - l - bounty, 0), 2)`;
3. for a refused outcome, sends `clear_refusal#52544331 query_id` to
   `own_wallet` with value `gas_fee(CLEAR_REFUSAL_GAS)`, non-bounceable, mode
   1 + 2;
4. sends everything else (the bounty owed, the unspent lock and the
   message's remaining value) to the requester in **one** send, mode 128 + 2
   (T3 decision 9).

Every send ignores errors, so no failed send rolls an outcome back. A send that
could not be made leaves its value in the actor's balance as an unaccounted
operator buffer; a `clear_refusal` that could not be made leaves a record at S,
which the next `transfer_rereported` clears. The change of a refusal re-sent by
a third party's `rereport_refusal` goes to the payout's requester, not to the
re-reporter.

### 8.5 Balance queries: surplus recovery and recheck

SAT:1326-1336, SAT:1411-1486. At most one balance query is pending. Only a
`take_balance#52544232 query_id balance:Coins` from the actor's own wallet
(derived on the message's value) whose `query_id` equals the pending query's
id is accepted; any other is ignored. An accepted answer always clears the
query, then:

- **Correction.** While a query is pending, every accepted
  `transfer_delivered` of a payout with id `>= floor` adds its amount to
  `delivered_since_floor` (SAT:1363-1368).
- **Surplus query.** `surplus = max(balance - delivered_since_floor -
  (pending + refundable + returned + withdrawable_token_revenue) - in_flight,
  0)`. If `0 < amount <= surplus` and a payout id is left, a kind 6 payout of
  `amount` to the owner is created, `SAB1` is emitted with result 0 and the
  payout id (mode 1), and the payout is sent with `requester` = the
  `recover_surplus` sender. Otherwise `SAB1` reports result 1936 with payout
  id 0 (T3 decision 8).
- **Recheck query.** If the target payout no longer exists, nothing changes but
  the query. Otherwise `surplus' = max(balance - delivered_since_floor -
  (pending + refundable + returned + withdrawable_token_revenue) - (in_flight
  - target amount), 0)`. If `surplus' >= amount`, the payout is resolved as
  refused at R (section 8.3, "rechecked"), `SAO1` with outcome 3 and `SAB1`
  with result 0 and payout id = the target are emitted, the payout's lock and
  bounty go to its requester (mode 1 + 2) and the change to the recheck's
  sender (mode 128 + 2). Otherwise `SAB1` reports result 1936.
- A **bounced** `provide_balance` from the actor's own wallet whose id equals
  the pending query frees the slot (T3 decision 10).

**Supersede rule.** `recover_surplus`, `recheck_payout` and `abandon_payout`
refuse with 1943 while a query younger than `RECHECK_QUERY_TTL` is pending.
Against an older one, the first two replace it and `abandon_payout` clears it.

**Why the surplus never over-counts.** Design 5.4: every payout older than the
query that is still in flight is subtracted although S has already debited it
(an under-count), every payout newer than the query is subtracted exactly once
through `in_flight` or `delivered_since_floor`, and notifications S sent before
answering are processed before `take_balance`. The computed surplus is never
more than the true unattributed balance. The recheck's `surplus'` removes only
the target's own amount, so a recheck that converts a lost delivery report pays
the buyer again only out of unattributed surplus, which the owner bears.

### 8.6 Guarantee

**At most one outcome, unconditionally.** The three accepted inputs come from
disjoint branches (S bounced; S sent and R committed; S sent and R failed),
each is authenticated against an address only that branch's wallet can send
from, a bounce cannot be forged, and the first accepted outcome deletes the
payout, whose id is never reused.

**At least one outcome** under the bounds B1-B5 of design 4.5, of which the
actor's side is: `report_tos_amount` and `outcome_fee_lock` at
`REPORT_MARGIN` (B2), the gas constants of section 12 at twice the most measured
(B3), the actor and its wallet not frozen or deleted (B4, operational), and
backing covering `locked_outcome_fees` (B5). Outside the bounds, a lost report
leaves the payout `paying`; `recheck_payout` (buyer kinds) and
`abandon_payout` (kinds 3 and 6) recover it.

**Refusals at R.** With destinations validated, a caller cannot induce a
refusal at R under the bounds, **except** that a recipient wallet frozen for
storage debt still refuses the credit (T3 decision 16). The outcome is then an
ordinary refusal: the principal becomes a returned entry for its caller,
never lost.

## 9. External out-messages (logs)

SAT:108-116, SAT:812-866. Every log is `ext_out_msg_info` with `src =
addr_none`, `dest = addr_none`, no `init`, the body by reference; in the
finalized transaction `src` is the actor. Decoders (SDK:934-1064) refuse
another tag, a missing field, and trailing bits or references.

### 9.1 `SAT1` (request snapshot)

```text
request_snapshot#53415431 request_id:uint64 caller:MsgAddressInt
  request_hash:uint256 response_deadline:uint64 refund_claim_deadline:uint64
  terms:^ServiceActorTokenTermsV1 = ServiceActorTokenRequestSnapshotV1;
```

Emitted once per admitted call, mode 1, after the reserve and before the change
(SAT:1680-1688). It is the native `SAR1` layout with the token terms cell.
`terms_hash` is the cell hash of `terms`; a decoder (SDK:946-977) also refuses
terms that section 5 refuses and `response_deadline + refund_claim_window !=
refund_claim_deadline` (checked addition).

### 9.2 `SAF1` (funding not admitted)

```text
funding_log#53414631 query_id:uint64 from:MsgAddressInt amount:Coins
  reason:uint16 payout_id:uint64 = ServiceActorFundingLogV1;
```

`query_id` and `amount` are the notification's; `reason` is a section 7.1
reason, or 1929 for an underfunded notification; `payout_id` is the funding
return's id, or 0 when none was made (section 7.1 step 6). Mode 1.

### 9.3 `SAO1` (payout outcome)

```text
outcome_log#53414f31 payout_id:uint64 kind:uint3 request_id:uint64
  recipient:MsgAddressInt amount:Coins outcome:uint3 = ServiceActorOutcomeLogV1;
```

`kind` is 1-7 and `outcome` is 0 delivered, 1 refused at R, 2 bounced at S, 3
rechecked, 4 mismatch (logged only; `amount` is the reported one), 5
abandoned. A decoder (SDK:1016-1034) refuses kind 0 and outcomes 6 and 7.
Mode 1 + 2 in outcome handlers and on a recheck, mode 1 for a mismatch and an
abandon.

### 9.4 `SAB1` (balance answer)

```text
balance_log#53414231 query_id:uint64 purpose:uint1 target:uint64
  balance:Coins surplus:Coins result:uint16 payout_id:uint64
  = ServiceActorBalanceLogV1;
```

Emitted for every accepted `take_balance` (T3 decision 8): `purpose` 0 surplus,
1 recheck; `target` the recheck target (0 for surplus); `balance` S's reported
balance; `surplus` the computed surplus or `surplus'`; `result` 0 when the query
paid or converted, else 1936; `payout_id` the surplus payout or the converted
target, else 0. "Fails with 1936" is reported here, not thrown, because the
query must still be cleared.

**Resolver checks beyond the T3 decoders.** The contract emits only the values
above. A resolver additionally refuses: a `SAF1` reason outside the set of
section 7.1 and 1929; a `SAF1` with reason 1929 (underfunded) and a non-zero
payout id, since an underfunded notification is never returned; a `SAB1`
result other than 0 or 1936; a `SAB1` with result 0 and payout id 0, or with
result 1936 and a non-zero payout id; a `SAB1` with purpose 0 (surplus) and a
non-zero target; and an `SAO1` whose fields differ from the payout it names. The T3 Rust decoders do
not range-check these fields (section 16.3).

## 10. Recognition reads: ConfigParam 84 at admission only

SAT:1544-1574. During admission, inside `try`/`catch`, the actor reads
ConfigParam 84 (`SettlementAssets`, design 3.1 and the T2 TL-B):

```text
settlement_assets_v1#01 assets:(HashmapE 256 SettlementAssetV1) = SettlementAssets;
settlement_asset_v1#01 status:uint8 decimals:uint8
  minter_code_hash:bits256 wallet_code_hash:bits256
  max_liability_per_actor:Coins origin:^SettlementAssetOriginV1 = SettlementAssetV1;
settlement_asset_origin$_ kind:uint8 bridge_address:bits256
  source_chain_id:uint32 source_token:bits160 = SettlementAssetOriginV1;
```

It requires: the root tag `0x01`, the dictionary and nothing else; the route
master canonical on workchain 0, and its account id present as a key; the
record tag `0x01`, a status in 1-3, the record ending after its origin
reference, an origin kind 1 or 2 ending after `source_token`, and
`max_liability_per_actor > 0`. Any failure, including an absent parameter,
gives reason 1933. Admission then requires status 1 and the record's
`wallet_code_hash` equal to the route's (1933), and uses
`max_liability_per_actor` in the exposure cap (1937).

The contract does **not** check `decimals`, `minter_code_hash` or the origin
fields, does not re-derive the master, and does not count entries. That
self-verification is client-side (design 3.1; `toschain`, T7), at one
masterchain block. No other handler reads ConfigParam 84: suspending an asset
(status 2) stops new calls on every actor of that asset and never freezes
money already admitted (TST `funding::payouts_never_read_recognition`). A
network without ConfigParam 84 admits no token call.

## 11. Funding values and bridge-parameter pricing

SAT:670-789. Every TOS amount is priced at run time from the basechain gas and
forwarding prices; `get_funding_prices` returns them (section 14).

The wallet's own value check also prices the bridge parameter's
`wallet_gas_consumption` and `wallet_min_tos_for_storage`. The actor reads them
(SAT:701-733) from the asset's own bridge parameter, the one the route names
(`bridge_config_param`), and, if that does not parse, from its negative slot
(`-bridge_config_param`), which the bridge falls back to. The parse is
`token_bridge_params_v1`: 8 + 256 + 256 bits skipped, the `oracles`
dictionary, 8 bits, then the `prices` reference, of which
`wallet_min_tos_for_storage` and `wallet_gas_consumption` are the third and
fourth Coins. It never throws: when neither parses, the reserve is priced at
`TOKEN_WALLET_ALLOWANCE` (0.3 TOS) and the wallet gas at zero, so
`gas_fee(R_GAS_LIMIT)` alone bounds R's compute. A vote that raises the bridge
parameter's values raises the actor's budgets with it, so a payout never
bounces for it (TST
`payouts::payouts_still_deliver_after_a_bridge_parameter_vote_raises_the_wallet_terms`).
This is a bridge parameter, not recognition: payouts read it, and never
ConfigParam 84.

With `F` as in section 8.1 and `(cells, bits)` the size of the route's wallet
code (capped at 8,192 cells):

```text
TRANSFER_BUDGET  = report_tos_amount + F + gas_fee(S_TRANSFER_GAS)
                 + get_forward_fee(bits + 4 × 1023, cells + 4)
                 + 10 × (max(gas_fee(R_GAS_LIMIT), wallet_gas_consumption)
                         + get_forward_fee(32 + 256 bits, 1 cell)
                         + get_forward_fee(0 bits, 3 cells))
                 + wallet_min_tos_for_storage
RETURN_BUDGET    = TRANSFER_BUDGET + outcome_fee_lock + F
ADMISSION_GAS_ALLOWANCE = gas_fee(ADMISSION_GAS) + 2F
MIN_FUNDING_VALUE       = ADMISSION_GAS_ALLOWANCE + RETURN_BUDGET
PAYOUT_FUNDING          = PAYOUT_GAS_ALLOWANCE + RETURN_BUDGET
REREPORT_FUNDING        = 2 × (gas_fee(S_REREPORT_GAS) + gas_fee(ABSENT_REPORT_GAS)
                               + gas_fee(CLEAR_REFUSAL_GAS) + 2F)
```

Every `+` and `×` above is saturating at `MAX_COINS` (section 7.1, "Checked
arithmetic"), so a budget never throws; a saturated budget refuses every
funding as underfunded.

`TRANSFER_BUDGET` is what the wallet's `reported_need` requires for the
actor's one-cell body, with S's message to R carrying the wallet StateInit.
A call's `forward_tos_amount` must be at least `storage_fee +
MIN_FUNDING_VALUE`. A re-reporter sends `rereport_refusal` to the actor's
wallet with at least `REREPORT_FUNDING` (`get_rereport_funding`).

## 12. Gas

SAT:357-365; FND "Gas"; TST `gas.rs`. Each constant is at least twice the most
either engine measured at capacity, with every dictionary at its deepest shape;
CI replays every measured transaction in the native engine and reports the
same gas.

| Constant | Value | Most measured | Bounds |
|---|---:|---:|---|
| `PRE_ACCEPT_GAS` | 24,000 | 10,026 | an outcome handler up to its `set_gas_limit` |
| `OUTCOME_HANDLER_GAS` | 300,000 | 117,865 | a whole outcome handler (a refund or sweep refused at R) |
| `ADMISSION_GAS` | 300,000 | 146,463 | the notification handler, with a 16-entry ConfigParam 84 whose last entry is the actor's master |
| `ABSENT_REPORT_GAS` | 20,000 | 8,178 | the answer to a report of an absent payout |

**Gas rule** (design 2.3). There is no `accept_message`. The only
`set_gas_limit` calls are the three in the outcome handlers (SAT:1317,
SAT:1360, SAT:1401), each after the payout lookup and the sender, amount (and
recipient) checks; from there the handler is paid from that payout's lock,
once. Every other handler, the notification included, runs on the gas its own
message bought. Mutation controls (TST `mutations.rs`) remove each handler's
sender check or amount and recipient check, or move its raise ahead of them,
and each mutant lets the matching forged message through.

## 13. State bound and the `accepting_tokens` headroom

SAT:282-341; FND "State bound"; TST `capacity.rs`. A basechain account holds
at most ConfigParam 43's `max_acc_state_cells` (65,536 at genesis). A state
over it fails the action phase, and a failed notification leaves its tokens
unattributed, so every growing structure is capped and the caps keep the worst
state at 80% of the limit (52,428 cells; T3 decision 1):

| Part | Cells each | Count | Cells |
|---|---:|---|---:|
| base: code, policy, attestor key, route | | | 360 |
| live entry being swept, with its caller's counter | 9 | `MAX_LIVE_GLOBAL` = 1,500 | 13,500 |
| returned entry being paid, with its caller's counter | 10 | 1,500 + 1,500 + 512 | 35,120 |
| funding return in flight | 5 | `MAX_RETURNS_IN_FLIGHT` = 512 | 2,560 |
| owner payout in flight | 5 | 4 revenue + 4 surplus | 40 |
| attestor key named by pending requests | 15 | `MAX_LIVE_ATTESTOR_KEYS` = 4 | 60 |
| one notification in flight | | | 10 |
| total | | | 51,650 |

The returned count is `MAX_RETURNED_GLOBAL` plus every live entry and funding
return, because a payout refused in flight still creates its entry; that
over-counts. Each dictionary entry adds at most two cells. The sandbox builds
the worst state with every cell distinct and counts 47,046 cells (the larger
code of the checked-arithmetic change raised the base allowance from 320 to 360). In that
state the test (`capacity::with_every_cap_full_a_further_funding_is_refused_and_returned`,
built by `worst_state(1)`) leaves one funding-return slot free, so a further
funding is refused (1907) and returned. With `returns_in_flight` at
`MAX_RETURNS_IN_FLIGHT` (512) the refused funding is not returned: it is logged
surplus with payout id 0 (section 7.1 step 6; TST
`capacity::at_the_funding_return_cap_a_refusal_is_logged_and_its_tokens_are_surplus`).

**Headroom.** Admission stops exactly at the caps (1907, 1935). A refused
funding at `MAX_RETURNS_IN_FLIGHT` unresolved returns cannot be returned (a
notification cannot bounce, and a return needs state): `SAF1` names it with
payout id 0 and its tokens are surplus (T3 decision 2). To keep honest buyers
clear of that, `get_accepting_tokens` is true only while

```text
live_count        < MAX_LIVE_GLOBAL       - 64   (1,436)
returned_count    < MAX_RETURNED_GLOBAL   - 64   (1,436)
returns_in_flight < MAX_RETURNS_IN_FLIGHT - 64   (448)
```

Buyers read it at the finalized state they quote from, and buyer tooling refuses
to build a funding transfer while it is false (SDK:565-569). Fundings already
sent then still find room below the caps: admitted, or refused and returned.
Only a flood of refused fundings faster than their returns resolve reaches the
cap. T14 alarms on funding returns in flight near it.

## 14. Getters

SAT:2063-2225. Convenience only; resolvers decode the account data exactly.

| Getter | Returns |
|---|---|
| `get_service_data()` | `owner, active, policy_version, price_per_call, storage_fee, cleanup_bounty, response_sla, refund_claim_window, open_access, has_authorized_caller, authorized_caller, rate_limit_per_day, metadata_hash, proof_scheme_hash, has_attestor, attestor_key_id, max_token_liability, next_request_id, pending_count, live_count, next_payout_id` |
| `get_native_ledger()` | `withdrawable_tos_revenue, locked_storage_fees, locked_outcome_fees, call_day, calls_today, revenue_payouts_in_flight, returned_count, returns_in_flight, surplus_payouts_in_flight` |
| `get_token_ledger()` | `pending_liability, refundable_liability, returned_liability, in_flight, withdrawable_token_revenue` |
| `get_balance_query()` | the balance query fields of section 4.3 |
| `get_asset_route()` | `master, wallet_code_hash, wallet_code` |
| `get_bridge_config_param()` | the route's `bridge_config_param` (any 32-bit value decodes; admission accepts only 79, 81, 82 or 83) |
| `get_own_wallet()` | the actor's derived wallet |
| `get_terms_hash()`, `get_terms()` | the current terms hash and cell |
| `get_funding_prices()` | `MIN_FUNDING_VALUE, ADMISSION_GAS_ALLOWANCE, RETURN_BUDGET, report_tos_amount, outcome_fee_lock, PAYOUT_FUNDING` |
| `get_accepting_tokens()` | section 13 |
| `get_attestor_key_count()` | `attestor_key_count` |
| `get_rereport_funding()` | `REREPORT_FUNDING` |
| `get_request(id)`, `get_refund(id)` | as the native getters |
| `get_payout(id)` | `found, kind, request_id, recipient, requester, amount, created_at, recipient_wallet, own_wallet, outcome_fee_lock` |
| `get_returned(id)` | `found, caller, amount, paying, return_deadline` |
| `get_caller_live_count(a)`, `get_caller_returned_count(a)` | the per-caller counts |
| `get_attestor_key()` | the policy's stored key, or null |
| `get_request_attestor_key(id)` | the key a pending request names, or null; 1913 when not pending |
| `get_pending_count()`, `get_live_count()` | the counters |

The SDK's stack decoders range-check before narrowing (SDK:738-842): a kind
outside 1-7, a 32-bit field above `2^32 - 1`, and `revenue_payouts_in_flight`,
`returns_in_flight` or `surplus_payouts_in_flight` above their caps are
refused.

## 15. Exit and reason codes

SAT:149-194. "Throw" is a transaction exit; "reason" appears only as a `SAF1`
reason on the notification path (never thrown there); "result" appears only in
`SAB1`.

| Code | Name | Raised by |
|---:|---|---|
| 9 | TVM cell underflow | any handler: missing field, trailing data, a signature reference absent or unexpected, a malformed stored key or signature wrapper, an anycast or `addr_var` address (throw) |
| 62 | `pq::error::key_length` | `rotate_attestor_key`, `respond` (throw); a deploy key at admission gives 1925 instead |
| 63 | `pq::error::malformed_key` | as 62 |
| 1900 | `not_owner` | `respond` and every owner op (throw) |
| 1901 | `inactive` | admission (reason) |
| 1902 | `insufficient_payment` | admission: a zero price or cap, an amount other than the price, a value below `storage_fee + MIN_FUNDING_VALUE` (reason); `update_policy` zero price (throw) |
| 1903 | `invalid_response_sla` | admission (reason), `update_policy` (throw) |
| 1904 | `invalid_refund_claim_window` | as 1903 |
| 1905 | `invalid_cleanup_bounty` | as 1903 |
| 1906 | `insufficient_storage_fee` | as 1903 |
| 1907 | `capacity_exceeded_global` | admission (reason) |
| 1908 | `capacity_exceeded_caller` | admission (reason) |
| 1909 | `request_id_overflow` | admission (reason); every payout-creating op and `recheck_payout` (throw) |
| 1910 | `unknown_op` | any (throw) |
| 1911 | `bad_response_signature` | `respond` (throw) |
| 1912 | `response_window_closed` | `respond` (throw) |
| 1913 | `request_not_pending` | `respond`, `expire`, getter `get_request_attestor_key` (throw) |
| 1914 | `expire_too_early` | `expire` (throw) |
| 1915 | `expire_too_late` | `expire` (throw) |
| 1916 | `refund_claim_expired` | `claim_refund` (throw) |
| 1917 | `refund_not_found` | `claim_refund` (throw) |
| 1918 | `not_refund_caller` | `claim_refund`, `claim_returned` (throw) |
| 1919 | `sweep_too_early` | `sweep_expired_request`, `sweep_returned` (throw) |
| 1920 | `request_not_live` | `sweep_expired_request` (throw) |
| 1921 | `insufficient_balance` | `claim_refund`, `sweep_expired_request`, `claim_returned`, `sweep_returned`, `abandon_payout` (throw): the balance is below the message's own value, because storage fees took part of it |
| 1922 | `insufficient_revenue` | `withdraw_revenue` (throw): the amounts exceed what is withdrawable, or, as for 1921, the balance is below the message's own value |
| 1923 | `not_authorized` | admission (reason) |
| 1924 | `rate_limited` | admission (reason) |
| 1925 | `bad_attestor_key` | admission (reason) |
| 1926 | `terms_mismatch` | admission (reason) |
| 1927 | `amount_range` | admission (reason, before the capacity checks); every checked sum on supplied state (throw) |
| 1928 | `operating_reserve_unfunded` | admission (reason) |
| 1929 | `insufficient_execution_payment` | an underfunded notification (`SAF1` reason); every payout-creating op, `recheck_payout`, `recover_surplus`, `withdraw_revenue` (throw) |
| 1930 | `payout_in_flight` | `claim_returned`, `sweep_returned`, `withdraw_revenue` (4 revenue payouts), `recover_surplus` (4 surplus payouts) (throw) |
| 1931 | `returned_not_found` | `claim_returned`, `sweep_returned` (throw) |
| 1932 | `asset_route_invalid` | admission (reason) |
| 1933 | `asset_not_recognized` | admission (reason) |
| 1934 | `invalid_destination` | admission: `from` off workchain 0 (reason); `claim_refund`, `claim_returned` (sender or destination), `withdraw_revenue` with a token part and `recover_surplus` (owner) (throw) |
| 1935 | `not_accepting_tokens` | admission (reason) |
| 1936 | `surplus_insufficient` | `recover_surplus` with a zero amount (throw); a surplus or recheck answer that cannot pay (`SAB1` result) |
| 1937 | `exposure_cap` | admission (reason); `update_policy` with a zero cap (throw) |
| 1938 | `abandon_too_early` | `abandon_payout` (throw) |
| 1939 | `malformed_payload` | admission (reason) |
| 1940 | `payout_not_found` | `recheck_payout`, `abandon_payout` (throw) |
| 1941 | `recheck_not_allowed` | `recheck_payout` (kinds 3, 6), `abandon_payout` (kinds 1, 2, 4, 5, 7) (throw) |
| 1942 | `recheck_too_early` | `recheck_payout` (throw) |
| 1943 | `balance_query_busy` | `recheck_payout`, `recover_surplus`, `abandon_payout` (throw) |
| 1944 | `attestor_keys_full` | admission (reason); `rotate_attestor_key` (throw) |

The bridge wallet's own exits (712 `refusal_pending`, 714 `refusals_full` and
the others of design 4.3) never reach the actor as codes: each is a bounce at
S (section 8.2).

## 16. Conformance evidence

### 16.1 Positive vectors

Generated by contract execution in the tos sandbox (TST
`ported::conformance_vectors_come_from_contract_execution`, which fails when
the committed fixture differs from what execution produces). Copied byte for
byte:

```text
source repo  github.com/tosnetwork/tos
source sha   7a32aa402944bb944a1c778197e491605f909df4  (tosnetwork/tos#516)
source path  tosctl/src/node-control/contracts/tests/fixtures/service_actor_token/conformance-vectors.json
spec copy    test-vectors/service-actor-token-conformance-vectors.json
sha256       f78ea0df4c70a0476000ccae035b32e554e727fa28a808a7c7a754c2a30e919a (52,944 bytes)
```

The provenance is recorded in
[`test-vectors/service-actor-token-conformance-vectors.source.json`](../test-vectors/service-actor-token-conformance-vectors.source.json).
`scripts/verify-service-actor-token-vector-copy.py`, which `make spec-check`
runs, fails when the spec copy's bytes differ from the recorded digest and
length; with `--tos-repo <tos checkout>` it also reads the fixture at the
recorded sha with `git show` and fails on any byte difference. A regenerated
fixture therefore changes the digest, and the copy, the sidecar and this
section change together.

The vectors cover the release code and its hash, the wallet code hash, the
master, actor and actor-wallet addresses, the deploy data and its inputs, the
terms cell and `terms_hash`, the actor's `funding_prices` at the funding's
state (`get_funding_prices`, the storage fee of `get_service_data` and
`get_accepting_tokens`), a funding transfer body, `SAT1`, `SAF1` for a refused
amount and for an underfunded notification, `SAO1` for every payout kind under
every outcome (delivered, refused at R, bounced at S) and four lifecycle cases,
and `SAB1` of a surplus recovery.

An `attested` section covers an actor deployed with an attestor
(`has_attestor = 1`): its deploy data with the stored ML-DSA-44 key, the key id
and the key's SHA-256, its terms and `terms_hash`, its funding prices, its
`SAT1`, and a signed `respond` that the actor accepted, given by the
network's `global_id`, the request id, `response_hash`, the SRP2 domain hash
and the signing context. The signature bytes are not pinned: ML-DSA-44 signing
is hedged, so a response is identified by its request and `response_hash`
(section 3). A verifier recomputes the domain hash and verifies a signature it
is given; it never compares signature bytes.

### 16.2 Independent reproduction

`scripts/reproduce-service-actor-token-v1.py` (stdlib only, shares no code with
the implementation; `make spec-check` runs it) decodes every BOC, and
reproduces:

- the code hash from the code BOC;
- the actor address from `StateInit(code, deploy data)`;
- the actor's wallet from the route in the deploy data (section 4.6);
- every deploy-data field against `init`, and the empty ledgers, query and
  dictionaries;
- the terms cell from the deploy data's policy and route, and `terms_hash`;
- the funding prices' own relations (`MIN_FUNDING_VALUE =
  ADMISSION_GAS_ALLOWANCE + RETURN_BUDGET`, `PAYOUT_FUNDING =
  PAYOUT_GAS_ALLOWANCE + RETURN_BUDGET`), and the funding transfer against
  section 7.1, its `forward_tos_amount` against the full `storage_fee +
  MIN_FUNDING_VALUE` budget, and its `token_call` payload;
- every log against section 9, including the kind and outcome that each
  `SAO1` vector's name states;
- for the `attested` section: the actor address, the stored key's canonical
  chain, its SHA-256, the key id from the key bytes (section 3), the terms
  with `has_attestor = 1`, the `SAT1`, and the SRP2 domain hash of the
  accepted `respond` from the snapshot, the actor address and `global_id`
  (section 6).

### 16.3 Negative corpus

[`test-vectors/service-actor-token-negative-v1.json`](../test-vectors/service-actor-token-negative-v1.json),
written by the same script (`--write`) and compared byte for byte on every
check (it never rewrites the committed file). It has three parts:

1. **`decoder_negatives`**: for each log and the terms cell, single-field
   mutations of a positive vector (another tag, a trailing bit, a trailing
   reference, a missing field, a kind of 0, outcomes 6 and 7, `addr_none` where
   an address is required, an attestor flag that disagrees with its key id, a
   non-minimal Coins length, snapshot deadlines that disagree with the
   window). Each records its rule, its base vector, the BOC and whether the T3
   Rust decoder refuses it (`t3_decoder`) or only a resolver check of section
   9.4 does (`resolver`). The script refuses each and accepts its unmutated
   base.
2. **`payload_negatives`**: the `token_call` payloads of the T3 test
   `funding::a_malformed_payload_takes_the_refusal_path_without_a_throw`
   (no payload, another tag, too short, trailing bits, a trailing reference),
   rebuilt from that test's construction, with the inline and referenced
   payloads it admits as positives. The script applies the contract's parse
   (section 7.1 step 3) and gives 1939 for each negative.
3. **`refusal_codes`**: every exit and reason code of section 15 with its
   handlers, its path (throw, reason or result) and the T3 sandbox tests that
   execute it, or the reason no test does. With `--tos-repo`,
   `verify-service-actor-token-vector-copy.py` checks that each named test
   exists at the recorded sha and names the code.

The BOCs of parts 1 and 2 are derived by the script, not emitted by the
implementation: no Rust or contract execution runs in this repository. That is
safe because each is a positive vector, or a T3 test input, with one stated
edit; the script checks that the unmutated base decodes and the edit alone is
refused; and the rules they exercise are the decoders' and the contract's
parse as cited. T7 must reproduce every part with the production Go decoders,
and the T3 Rust decoders must refuse every `t3_decoder` case; until then the
corpus is checked only by the reference script.

### 16.4 Gates before this layout is frozen

The tos PR merged and the release published from tos main; the T3 vectors
regenerated at that commit and recopied; T7's Go codecs and resolver
reproducing every vector and refusing every negative; the T13 independent
security review; the T10 live lifecycles. None is recorded.

## 17. Invariants

1. Coin arithmetic is checked below `2^120`; no ledger goes negative.
2. The token wallet balance plus the tokens of the payouts in transit (debited
   at S and not yet credited back to it, outcome not yet applied) covers
   `attributed` (section 4.3) after every transaction; with no payout in
   transit, surplus is the rest of the balance.
3. The actor's balance, net of the incoming message, covers
   `locked_storage_fees + locked_outcome_fees + MINIMUM_OPERATING_RESERVE`
   after every admission and withdrawal.
4. Each payout has at most one accepted outcome; payout ids are never reused,
   and id 0 names none.
5. A request resolves exactly once: respond (price to token revenue), a
   delivered refund or sweep (price to the caller or its destination), or a
   returned entry for its caller. The storage fee is never refunded.
6. A correctly funded refusal stays attributed to its sender, except at
   `MAX_RETURNS_IN_FLIGHT`, for a sender off workchain 0, and for a return whose
   ledgers would not fit in Coins, where it is logged
   surplus (section 7.1 step 6).
7. No payout path reads ConfigParam 84.
8. No `accept_message`; no gas raise outside the authenticated outcome
   handlers.
9. Every admitted call emits exactly one `SAT1` equal to the stored request,
   whose terms cell hashes to the stored `terms_hash`.
10. A pending request's attestor key is in `attestor_keys` with a reference
    count equal to the pending requests naming it, and at most
    `MAX_LIVE_ATTESTOR_KEYS` keys are named at once.
