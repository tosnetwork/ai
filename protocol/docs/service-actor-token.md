# Token-rail Service Actor protocol

This is the protocol library for the separate token rail, not a deployment or
an enablement of purchases in the provider or gateway runtimes. The normative
wire formats, release identities and operating limits are in
[the token actor specification](../../spec/docs/SERVICE_ACTOR_TOKEN_TVM_V1.md).
The rollout and independent audit gates in
[the settlement design](../../spec/docs/USDC_SETTLEMENT_V1.md) remain required.
No network transaction is sent by the verifier or the builders below.

## Release and encoding pins

The contract vectors are pinned to source commit
`7a32aa402944bb944a1c778197e491605f909df4`; the build-only CLI fixtures are
pinned to `bb388496634a6901d03c8db01ae92de70c831bd8`. The release and explicit
test-profile actor code hashes are separate. A client must supply independent
`toschain.TokenAssetPin` records for its recognized assets. They bind the
master, decimals, bridge slot and source namespace, and bridge, minter and
wallet code hashes. ConfigParam 84 is recognition, not a source of client pins.
Unpinned entries are ignored. More than sixteen valid entries is observable,
not grounds for refusing a separately pinned entry.

`nativecore` decodes the entire actor state, including payouts, undo cells,
returned entries, attestor keys and counters. It bounds dictionary and code
cell graphs and rejects trailing bits, references and exotic cells where
ordinary cells are required. The log decoders additionally enforce the
funding-reason set, reason 1929 with payout zero, balance result/payout
consistency, and purpose zero with target zero.

The manifest asset record is `tos-token`, with master account ID, wallet code
hash and decimals. Token Accepted Quotes use schema 3 and token Receipts use
schema 2. Their native counterparts retain schema 1 and their existing frozen
bytes. A native Quote with protobuf field 18 or 19 remains refused. The new
[protocol encoding vector](../../spec/test-vectors/service-actor-token-protocol-v1.json)
is synthetic encoding evidence, not evidence of a commercial admission. Its
manifest CBOR and complete Quote/Receipt cell graphs are independently
reproduced by a standard-library Python implementation.

## One finalized session

Open the existing `toschain.ServiceActorReader` with the chosen actor code
hash and a strict-majority endpoint quorum, then call `Begin` once. Pass that
`ServiceActorSession` to every read for the result:

1. `ReadTokenActor` validates the account and derives its own token wallet.
2. For new admission, `ReadTokenAsset` checks current active recognition and
   independently pinned bridge/minter/wallet identities at the same checkpoint.
3. `GatherTokenEvidence` and `VerifyTokenAdmission` bind the registry, manifest,
   actor, attestor, exact asset and current terms. A wrong master, wallet hash,
   decimals, inactive status or checkpoint is refused.
4. `ResolveTokenRequests` or `ReplayTokenRequests` derives lifecycle state from
   a complete hash-linked history and reconciles it with current typed cells.
   Missing or bounded-out history is a refusal, never an empty success.

`paying` is an in-flight token payout, not a completed refund. `returned` is a
retained liability that can be claimed again. Delivery is authenticated by the
recipient's derived wallet; refusal by the actor's own wallet; a bounce also
requires the transaction's bounced flag and matching original body. A dropped
best-effort outcome log does not override an authenticated report. Funding
refusals remain separate from admitted requests and can be inspected through
`ResolveTokenFundingRefusals`.

Existing-request verification uses the immutable SAT1 emitted by the pinned
actor and the client's asset pins. That executed admission proves the
contract's admission predicates; it does not establish a separately reported
historical ConfigParam 84 hash. Current recognition is deliberately not read
for payouts, recovery or existing requests: an asset suspension stops new
admission without trapping an existing liability. Registry revocations and
terminal transitions still need their finalized transition evidence. An
explicit historical view is archive evidence, not a substitute for the
configuration at an unknown admission block.

## Build a message

Use `buyersdk.PrepareTokenAtSession` with that same session, the actor address,
client pins and a `TokenBuildRequest`. It reads pricing, wallet state and
recognition only where required, and refuses checkpoint drift. Its response
contains one destination, value, bounce flag and body BOC; it neither signs nor
submits it. Call preparation takes separate wallet and forwarded TOS values,
not a native price pretending to be a token amount.

`PrepareTokenMessage` is the lower-level pure builder for an already assembled
`TokenBuildSnapshot`. Callers assembling one themselves must preserve the same
checkpoint and independent pin guarantees. Prefer the session adapter.

`TokenPreparedMessage.Pretty` reproduces the pinned CLI's complete build-only
JSON bytes, including field order, newline and BOC header `0x01` without index
or CRC32C. The conservative wallet-need calculation includes the transfer body
as a referenced cell. Seventeen CLI fixtures are tested from their inputs,
not copied as builder output.

The pinned CLI prose lists gas before reserve in the bridge terms layout.
Its actual decoder, like the contract specification, reads reserve third and
gas fourth and returns them as gas/reserve. The Go reader follows those actual
bytes. This documentation discrepancy does not change the wire format.

## Public evidence and verifier

`purchaseevidence.TokenBundle` has schema
`tos.service.purchase-evidence.token.v1`. It carries a portable Quote package,
the exact schema-3 Accepted Quote, NSR1 request, source digest, buyer wallet,
three funding transaction identities and actor call identity. These are claims,
not authority. `VerifyToken` validates them against one finalized session,
including the three exact message-hash links: payer to sender token wallet,
sender wallet to actor wallet, actor wallet to actor notification. It also
checks both token wallets' deployed identities. A supplied schema-2 Receipt
must be the exact finalized response and bind the asset, amount, execution,
source, provider, toolchain and sandbox. Supplied artifacts are checked against
all Receipt member digests. Computation correctness and endpoint independence
are explicitly not claimed.

Select the token verifier with `--asset-pins`:

```bash
go run ./protocol/cmd/tos-service-verify \
  --network-domain network.json \
  --rpc https://rpc-a.example/jsonRPC,https://rpc-b.example/jsonRPC,https://rpc-c.example/jsonRPC \
  --registry-code-boc registry-code.boc --registry-code-hash "$REGISTRY_HASH" \
  --actor-code-hash "$TOKEN_ACTOR_HASH" --asset-pins asset-pins.json \
  --evidence evidence.json --receipt receipt.boc --artifact artifact.tar
```

The pin file is a JSON array of one or two `toschain.TokenAssetPin` records;
`SourceToken` is a twenty-byte JSON array. Pin files are local owner policy.
Without a bundle, use `--actor` and repeatable `--request-id` or
`--request-hash`. A hash may also select an authenticated refused funding.
That mode reports chain state and recovery actions but makes no Quote,
Capability-binding or funding-chain claim. Missing data and disagreement fail
closed. The native verifier's flags and formats are unchanged when
`--asset-pins` is absent.

## Reproduce the checks

Set `TOS_SERVICE_TOKEN_CLI_REPO` to a local repository containing the exact CLI
fixture commit, then run from the repository root:

```bash
go test ./protocol/pkg/nativecore ./protocol/pkg/toschain ./protocol/pkg/serviceactor \
  ./protocol/pkg/buyersdk ./protocol/pkg/purchaseevidence ./protocol/pkg/quoteexchange \
  ./protocol/cmd/tos-service-verify
go vet ./protocol/pkg/nativecore ./protocol/pkg/toschain ./protocol/pkg/serviceactor \
  ./protocol/pkg/buyersdk ./protocol/pkg/purchaseevidence ./protocol/pkg/quoteexchange \
  ./protocol/cmd/tos-service-verify
make spec-check schema-check boundary-lint
```

Existing real-custody and registration-signature tests additionally require
`TOS_SERVICE_TOSCTL` and `TOS_SERVICE_TOSCTL_SHA256`; missing dependencies fail,
not skip. CI builds that helper and separately checks out the pinned CLI
fixtures. The negative corpus runs 38 decoder cases and 6 payload cases through
production decoders. Its 48 refusal-code records are classification metadata,
not 48 executable contract-state tests. Local-chain commercial lifecycles and
production deployment acceptance belong to the subsequent integration gates.
