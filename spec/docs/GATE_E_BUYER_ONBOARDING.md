# Gate E Buyer Onboarding

**Escrow-rail runbook; not current (rail change 2026-11-07).** Stablecoin
escrow v2 is retired and the software-work profile settles in native TOS on the
Service Actor ([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md),
[`SERVICE_ACTOR_SETTLEMENT_DESIGN.md`](SERVICE_ACTOR_SETTLEMENT_DESIGN.md)).
A buyer pays with one native-TOS `call` and owns the `expire` and
`claim_refund` duties before `refund_claim_deadline`. This runbook still
describes the escrow rail and cannot produce Gate E evidence:

- **Void:** the stablecoin, escrow and funding statements of "Status";
  "Authority and custody boundary" items 3-5 and 8 (escrow acceptance,
  stablecoin identity, escrow deployment, funded escrow as payment success);
  "Buyer sequence" steps 3-7 (`FundPurchase` and the stablecoin sender no
  longer exist; the current path is `protocol/pkg/buyersdk`
  `ServiceActorBuyer`: Discover, Prepare, Call, Resolve); the escrow, asset
  and wallet fields of "Crash and budget rules"; and the funding, stablecoin
  and escrow entries of "Current implementation and remaining acceptance".
- **Still binding:** Quote Proposals are never canonical; independent
  manifest and finalized Capability verification; `tosctl` custody; transport
  responses are observations only; the owner-private budget directory and the
  never-pay-twice journal rules.
- **Next:** a Service Actor rewrite of this runbook follows in a separate
  change. For a buyer using an MCP client, the Service Actor guide is
  [`MCP_BUYER_GUIDE.md`](MCP_BUYER_GUIDE.md). Where this document conflicts
  with the Service Actor documents, they govern.

## Status

The buyer SDK, wallet-budget foundation, and production `tosctl` stablecoin
sender are implemented. This is not Gate E acceptance: a fresh buyer must
still complete the purchase from public documentation, and the same session
must include the fresh-provider sale required by the Gate.

A same-host three-validator rehearsal has additionally funded a new escrow
from a `tosctl`-native V1R3 wc=0 buyer. It verified the exact signed-message
prepare/broadcast boundary and the post-payment escrow and stablecoin-wallet
state with three agreeing endpoints. The record is
`deployments/archive/pre-tos-service-v1/local-gate-e-tosctl-buyer-funding-2026-08-15.json`. This is
implementation evidence only: it did not exercise the complete public buyer
SDK session or establish external operator independence.

On the retired rail, the production asset read no longer required a
caller-supplied balance view: a finalized stablecoin resolver in
`protocol/pkg/toschain` authenticated the master code, extracted and verified
its wallet-code preimage, derived the buyer wallet, and checked the wallet
code, owner, master, unlocked status, balance, genesis, and monotonic finalized
checkpoint through strict-majority TOS RPC. Its local live result is included
in the same deployment record. That resolver was removed with the stablecoin
rail (`protocol/` commit `b9ad8e17`) and has no replacement: a native-TOS buyer
has no stablecoin to resolve. The current buyer path is
`protocol/pkg/buyersdk` `ServiceActorBuyer`, whose `tosctl` sender preflights
the amount, network and wallet bindings before the one native-TOS `call`.

The complete buyer preflight was also run against that live state through the
production SDK and the in-process `toschain.DirectNativeClient`. It resolved
the finalized Capability directly from the three TOS nodes, reproduced the
manifest digest, Quote commitment, deterministic escrow and buyer stablecoin
wallet, and accepted the exact finalized funded amount at checkpoint `143512`.
Because the escrow was already funded, this was deliberately a read-only
idempotency check and caused no second wallet broadcast. It closes the
integration gap between the production resolvers and Buyer SDK, but it is not
the required fresh-buyer onboarding session.

## Authority and custody boundary

- a Quote Proposal is discovery input and is never canonical;
- the buyer independently verifies the manifest and finalized typed Capability;
- the Accepted Quote becomes canonical only through the exact TOS escrow;
- the exact TOS-network stablecoin master and wallet code hash identify the
  payment asset; a ticker or gateway balance is insufficient;
- escrow deployment is finalized before any stablecoin funding attempt;
- the wallet signer remains behind the reviewed `tosctl` custody boundary;
- gateway, resolver, and sender responses are transport observations only; and
- payment success means finalized escrow state contains the exact funded amount.

## Buyer sequence

1. Create an owner-private `0700` budget directory and choose explicit window,
   purchase-count, per-purchase, and total atomic-unit limits.
2. Obtain a Quote Proposal and retrieve the manifest independently by its
   digest. Use `protocol/pkg/buyersdk` to strictly decode the manifest and
   verify the exact finalized Capability version and provider ownership.
3. Resolve the quoted TOS stablecoin through finalized TOS state. Verify its
   master identity, wallet code, buyer wallet, balance, and checkpoint.
4. Build the exact Accepted Quote and deterministic escrow. Review the buyer,
   provider, amount, asset, deadlines, execution signer, transport commitment,
   Quote commitment, and escrow address.
5. Deploy the reviewed StateInit through the buyer custody boundary. Wait for
   the exact code hash and data to be finalized in `awaiting_funding` state.
6. Call `FundPurchase` with a durable retry key. Immediately before wallet use,
   the SDK reconstructs every commitment and repeats all authoritative reads.
   The production sender asks `tosctl` to build and sign once, validates the
   exact signed BOC before acquiring the broadcast lease, and then broadcasts
   those same bytes without rebuilding or re-signing.
7. Treat the stablecoin sender result as ambiguous until the exact escrow and
   amount are finalized. Continue to Receipt and settlement only from that
   finalized funded state.

## Crash and budget rules

The durable purchase record contains the network, escrow, Quote commitment,
exact asset, buyer wallet, amount, and deterministic query ID. One atomic claim
both reserves budget and records the full intent. Only `prepared` can acquire a
single broadcast lease. A pre-send crash is recoverable; a crash or error after
the record reaches `broadcasting` is read-only recovery and cannot trigger an
automatic second payment. Request keys are retry aliases and do not define the
payment identity.

Budget records are owner-only regular files and are counted for the entire
configured window, including unresolved reservations. Operators must not
delete, weaken, or edit the journal to recover capacity. Ambiguous entries are
reconciled against finalized chain history under an explicit operational
procedure.

## Current implementation and remaining acceptance

- buyer safety boundary: `protocol/pkg/buyersdk`
- Go guide: [`protocol/docs/buyer-sdk.md`](../../protocol/docs/buyer-sdk.md)
- exact prepared-message broadcast boundary: `tos` commit
  `d9d725534cb1a9120b1e49854b360c01f043c22a`
- production `tosctl` funding adapter: `protocol/` commit
  `d1a845eb7808365a413106d075c7c6316be67e27`
- production finalized stablecoin resolver (removed with the stablecoin rail
  in `protocol/` commit `b9ad8e17`): `protocol/` commit
  `57f6429f2a0dc21b3292de8a27fa5d3a26255dd4`
- direct finalized Native SDK adapter and full live Buyer SDK revalidation:
  `protocol/` commit `a18162af3df971af265bf101ae9d40396e3c1370`
- verified test-fixture custody import and exact-message submit CLI: `tos`
  commit `c8fbead6851cf63c4858035195045b4de0406302`
- canonical Quote and escrow rules: `docs/ACCEPTED_QUOTE_TVM_V1.md` and the
  escrow version 1 specification (retired on 2026-10-05; the current escrow is
  `docs/STABLECOIN_ESCROW_TVM_V2.md`)
- external commercial lifecycle: `docs/GATE_D_EXTERNAL_PILOT.md`

Before the buyer item can be complete, run a fresh-buyer session with no source
edits, hidden database changes, developer-only instructions, or key material
outside custody. Record release commits, network/genesis tuple,
Capability/version, manifest digest, Quote commitment, escrow, exact asset and
amount, budget policy, funding transaction, finalized checkpoint, Receipt, and
settlement. Never record tokens, mnemonics, private keys, or wallet seeds.
