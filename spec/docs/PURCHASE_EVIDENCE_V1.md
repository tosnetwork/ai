# Purchase Evidence and Verification V1

## Status and scope

**Status:** implemented. `protocol/pkg/purchaseevidence` holds the
verification and the evidence bundle schema; `protocol/cmd/tos-service-verify`
is the third-party verifier; `tos-service-buyer evidence` is the buyer's
export ([`MCP_BUYER_ADAPTER_V1.md`](MCP_BUYER_ADAPTER_V1.md) section 15).

This document defines two local file formats, the evidence bundle
(`tos.service.purchase-evidence.v1`) and the verdict
(`tos.service.purchase-verdict.v1`), and the checks behind them. It adds no
protocol object, contract message, frame or authority. Finalized TOS state is
the only authority: a bundle, a Receipt and an artifact are untrusted files,
each checked against finalized state and against each other, never believed.
Where this document and the Service Actor documents
([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md),
[`SERVICE_ACTOR_SETTLEMENT_DESIGN.md`](SERVICE_ACTOR_SETTLEMENT_DESIGN.md),
[`SERVICE_ACTOR_RAIL_WORK_FRAMES_V1.md`](SERVICE_ACTOR_RAIL_WORK_FRAMES_V1.md))
conflict, they govern.

It serves the Gate D verifier role (`ROADMAP.md` section 4): another resolver
reconstructs a purchase from finalized state without a private gateway
database. A passing verdict is evidence for that role only. The Gate D pilot
record (`tos.service.gate-d-external-pilot-record.v1`, verdict
`PASS_INDEPENDENT_SERVICE_ACTOR_SOFTWARE_WORK`) wraps this tool's verdict in
`verifier_output`, and
[`GATE_D_EXTERNAL_PILOT.md`](GATE_D_EXTERNAL_PILOT.md) section 8.4 maps each
check ID to the acceptance item it shows. A tool `pass` is necessary for that
verdict but not sufficient: the record also needs the role, custody,
endpoint-operator and signature items that this tool does not judge.

## 1. The verifier: `tos-service-verify`

The verifier is a separate binary rather than a `tos-service-buyer`
subcommand. A third party should not need a buyer's flags (state directory,
buyer wallet, budget), and a binary that links no buyer runtime cannot sign,
send or read a buyer's state, whatever its flags say: it links none of
`buyersdk`, `buyeragent`, `buyerinit`, `buyerconfirm`, `mcpbuyer`,
`chainactionpublisher`, `nativewallet` or `providersdk`, and a test holds it to
that. It holds no key, reads no `VAULT_URL` and runs no `tosctl`.

### 1.1 Inputs

All inputs are public:

| Input | Flag |
|---|---|
| network genesis | `--global-config FILE --network-id ID` (the masterchain `zero_state` root and file hashes, base64, become `sha256:<hex>`), or `--network-domain FILE` (`{network_id, genesis_root_hash, genesis_file_hash}`, strict) |
| endpoints | `--rpc URL,URL,URL` (3 to 8; remote ones HTTPS) |
| quorum | `--quorum N`: agreeing endpoints required, a strict majority at least; **default every endpoint given** |
| Native Registry release | `--registry-code-boc FILE --registry-code-hash tvm-cell-sha256:<hex>` |
| Service Actor release | `--actor-code-hash tvm-cell-sha256:<hex>` |
| the actor | `--actor 0:<hex>`, or the bundle's |
| the requests | `--request-id N` and `--request-hash H`, repeatable, at most 64 in all; a bundle selects its own `request_hash` |
| buyer files (optional) | `--evidence evidence.json`, `--receipt receipt.boc`, `--artifact artifact.tar` |

A Receipt or artifact is checked against exactly one selected request, and an
artifact only with its Receipt. A bundle selects only its own request.

The verifier keeps no state between runs. Its finality fences live in a
private scratch directory that it removes on exit.

### 1.2 What it reads

Every read is taken at one quorum-finalized checkpoint, and every account
read and getter must report the same masterchain block
(`toschain.ServiceActorSession`). Each endpoint's genesis is also checked on
its own, without a quorum, and reported. A reachable endpoint on another
genesis is never part of the quorum, because every account read checks the
genesis too.

### 1.3 Checks

Each check has a stable ID in the verdict. The verdict passes only when every
check passed. A read that cannot be made is a failing check, never a partial
pass.

| ID | Passes when |
|---|---|
| `input` | the inputs are usable (above) |
| `finalized-read` | (only on failure) the quorum session could not be opened |
| `actor-account` | the actor is active at the checkpoint, reads under the pinned code hash at the quorum, decodes exactly, and `get_attestor_key` equals the decoded policy key |
| `actor-code-hash` | the account's code hash is the pinned release |
| `actor-history` | the history is complete back to the first transaction and ends at the account's last transaction |
| `actor-replay` | the whole history replays (`serviceactor.Replay`): request IDs run from 0 to `next_request_id - 1`, every transition is legal at its time and from its allowed sender, and the pending and refund sets equal the account data entry by entry |
| `request-selected` | each selector names exactly one request. A `request_hash` that only an aborted call carries is reported `refused`. Two calls with one `request_hash` are refused as ambiguous; select by ID. With a bundle, only a call from the bundle's buyer wallet with its journaled `query_id` is selected. |
| `request-getters` | `get_request` and `get_refund` agree with the decoded state for the request |
| `receipt-canonical` | the Receipt is a canonical SoftwareWorkReceiptV1 BOC of at most 512 bytes |
| `receipt-response-hash` | the request is responded, and the Receipt's cell hash is the finalized respond's `response_hash` |
| `receipt-request-hash` | the Receipt's `quote_commitment`, `execution_id` and `input_digest` rebuild the NSR1 `request_hash` the call carried, so the Receipt binds this request and no other |
| `receipt-terms` | the Receipt charges the snapshotted price, with `exit_code` 0 and a completion time |
| `receipt-binding` | (with a bundle) the Receipt binds the bundle Quote's commitment, execution, input, source digest, price, provider, toolchain and manifest (`railwork.CheckReceiptBinding`) |
| `artifact-digest` | the artifact's SHA-256 is the Receipt's `artifact_digest` |
| `artifact-members` | the artifact is the two-member USTAR tar, and `output.log` and `report.json` hash to the Receipt's `result_digest` and `report_digest` |
| `bundle-pins` | the bundle names the verifier's network, actor and actor release |
| `bundle-quote` | the Quote package validates (`quoteexchange.ValidatePortable`), rebuilds the bundle's Accepted Quote BOC and `quote_commitment`, and its rail and offer equal the bundle's actor, terms hash, policy version, price, storage fee, provider, manifest and toolchain |
| `bundle-request-hash` | `input_digest` is the rail input commitment of `source_digest`, and the Quote, `execution_id` and `input_digest` rebuild the bundle's `request_hash` |
| `bundle-journal` | the journaled call transaction and request ID are the finalized ones; an aborted call has no request ID |
| `bundle-binding` | the settlement design's existing-request verification (section 2.4) passes at the checkpoint: the Capability, the version and its manifest (the package's bytes, checked against the finalized digest), the owner Agent and the actor binding, with liveness judged at the call, then the call and its snapshot against the Quote |
| `bundle-finalized` | the call and outcome transactions the bundle records are the finalized ones, and its checkpoint is not after the verifier's. An outcome finalized after the export is not a mismatch. |
| `bundle-result` | an accepted result's `response_hash` is the finalized one, and the Receipt and artifact files given are the bundle's |

### 1.4 What it reports

For the actor: address, code hash and pinned hash, owner, balance, policy
version, `next_request_id`, live counts, last transaction and history length.
For each request: ID, `request_hash`, state (`pending`, `expired`,
`responded`, `refunded`, `swept`, or `refused` for an aborted call), the
buyer-visible status at the checkpoint, the caller, price, storage fee,
cleanup bounty, terms hash, policy version, attestor key, the deadlines, and
the call transaction (lt, hash, time, sender, value, `query_id`). It then
reports whichever of these exist:

- the respond transaction, with the provider wallet (the actor owner who sent
  it) and the `response_hash`;
- the expire transaction;
- the `claim_refund` transaction, with its destination and payout;
- the sweep transaction, with its payout.

It adds the Receipt's fields and file digest, and the artifact's members, when
those files are given.

### 1.5 Output and exit status

Standard output carries the verdict, one JSON object:

- `schema`, `result` (`pass` or `fail`), `tool` (build and VCS revision);
- `network`, `reads` (each endpoint and its own genesis check, and the
  quorum), `inputs` (the SHA-256 of every file read);
- `checkpoint` (sequence number, chain time, block root and file hash),
  `actor`, `requests`, `checks`, `not_claimed`.

Standard error carries a human summary of the same verdict. The exit status
is 0 for a pass, 1 for a failing verdict (a verdict is still printed) and 2
for unusable inputs.

```sh
tos-service-verify \
  --global-config global.config.json --network-id tos:global-id:2 \
  --rpc https://ENDPOINT_A/jsonRPC,https://ENDPOINT_B/jsonRPC,https://ENDPOINT_C/jsonRPC \
  --registry-code-boc native-registry.boc --registry-code-hash tvm-cell-sha256:REGISTRY_HASH \
  --actor-code-hash tvm-cell-sha256:ACTOR_HASH \
  --evidence evidence/evidence.json --receipt evidence/receipt.boc --artifact evidence/artifact.tar \
  > verdict.json
```

## 2. The buyer's export: `tos-service-buyer evidence`

```sh
tos-service-buyer evidence --config AGENT_CONFIG --request-hash REQUEST_HASH --out-dir /ABSOLUTE/NEW/DIR
```

The buyer runs it as the custody account, against the state of
`tos-service-buyer agent` (section 2.4 of the adapter), which may keep
running. It reads:

- the agent configuration, strictly, as the agent does;
- the purchase's call journal record, under the journal lock but without
  opening the journal, so a record a running agent holds in `sending` is
  neither recovered nor rewritten;
- the purchase record;
- the accepted result, if any, under the carrier's checks. The stored Receipt
  must hash to the accepted `response_hash`, and the artifact must match the
  Receipt.

It writes only the new output directory and the agent's finality fences.
Its finalized reads use the agent's own endpoints and quorum, and the
agent's own fences: the `registry.checkpoint` and `service-actor.checkpoint`
files in the state directory's `chain` subdirectory. Every fence update,
from the agent or from `evidence`, is one read-compare-raise under an
exclusive `flock` on that fence file (`toschain`'s checkpoint store). A
running agent and an export therefore never lose each other's update, and a
fence only ever advances.

Before it writes anything, it verifies the purchase at a fresh finalized
checkpoint exactly as section 1 does, with the bundle, the Receipt and the
artifact. A purchase that does not verify is not exported. The verdict is
printed instead and the command fails. A verified bundle records that
checkpoint and the request's finalized report in `finalized`.

The output directory must not exist. It is created `0700`, and each file is
created new, `0600`:

| File | Content |
|---|---|
| `evidence.json` | the bundle (below) |
| `receipt.boc` | the accepted Receipt, if any |
| `artifact.tar` | the accepted artifact, if any |

Standard output names the directory, each file's SHA-256 and size, and the
checkpoint.

### 2.1 Bundle contents

`tos.service.purchase-evidence.v1`, decoded strictly (unknown fields,
duplicate keys and trailing data refused; at most 8 MiB):

- `tool`, `exported_unix`;
- `network`, `registry_code_hash`, `actor_code_hash`, `actor`,
  `buyer_wallet`, `buyer_agent_id`. The buyer's endpoints and quorum are not
  exported: they are private, and a verifier brings its own (the independence
  of section 1);
- `offer`: Capability ID and version, manifest and toolchain digests, provider
  Agent, result retention;
- `quote`: the deterministic protobuf Quote package, the Quote request's buyer
  address, the Accepted Quote BOC and `quote_commitment`, terms hash, policy
  version, price, storage fee, payment, cleanup bounty, response SLA, refund
  claim window, expiry and attestor key ID;
- `request`: `request_hash`, `execution_id`, `input_digest`, the source
  archive's `source_digest` and size;
- `journal`: phase, `query_id`, creation and send times, request ID, call
  transaction (lt and hash), exit code, and the expire, claim_refund and sweep
  sends (operation, `query_id`, phase, time, wallet message hash);
- `result`: whether a result was accepted and when, its `response_hash`, the
  Receipt and artifact file digests, the member digests, and the Receipt's
  result, artifact and report digests;
- `budget`: the buyer's spending policy (window, call count, per-call and
  window limits, unconfirmed and lifecycle-send bounds);
- `finalized`: the checkpoint and the request report of section 1.4.

A bundle holds no secret. It never contains a key, seed, mnemonic, vault URL
or export, token, confirmation code or nonce, execution nonce, idempotency
key, Quote ID, `tosctl` path or configuration, relay CA, state path, RPC
endpoint or quorum, the buyer's source, or its member names. It holds only the source digest and
size. Every field comes from an explicit list, and a test checks the
exported bytes against these values.

## 3. What a pass does not establish

A pass establishes only that the files and selected requests are consistent
with finalized state at the checkpoint, read at the stated quorum. It does
not establish:

- operator independence of the endpoints. Agreeing endpoints run by one
  operator are one source, so the verifier records each endpoint's operator
  separately;
- computation correctness. A Receipt is the provider's attested statement of
  the digests it binds (settlement design section 4);
- the identity or independence of the buyer, the provider or the verifier;
- anything after the checkpoint, or about a request the run did not select;
- the Capability binding of a request verified without a bundle. That needs
  the Quote, so `bundle-binding` runs only with a bundle.
- whose purchase a request is, when no bundle is given. Without a bundle, a
  request is proven only to come from its caller wallet, and the verdict's
  `not_claimed` says so. A Gate D record must bind each selected request to
  the buyer's declared wallet: the reported `caller` must equal that wallet.

## 4. Bounds

- The actor history is read in full up to `toschain`'s bound of 10,000
  transactions. A longer history fails `actor-history` rather than being
  judged in part.
- At most 64 requests are selected per run.
- File bounds: a Receipt of 512 bytes, an artifact of the rail's result
  bound, a bundle of 8 MiB, a global config of 1 MiB.
