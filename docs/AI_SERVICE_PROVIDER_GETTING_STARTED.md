# TOS AI Service Provider — Getting Started

**Audience:** a technically capable user who wants to buy software work, or
sell it, on the TOS Service Actor rail.
**Status:** guide to the commands that exist on `main` of each repository on
2026-11-14. It changes no requirement, gate or roadmap status; see
[Requirements V1](AI_SERVICE_PROVIDER_REQUIREMENTS_V1.md) and the
[Implementation Status](AI_SERVICE_PROVIDER_IMPLEMENTATION_STATUS.md).

Every command, flag and configuration field below exists in the named
repository. Where no command exists for a step, the guide says
**not yet implemented** instead of inventing one.

## 1. What it is

A provider registers an Agent and a software-work Capability in the Native
Registry and deploys a **Service Actor**, an on-chain contract that holds the
price and terms. A buyer verifies the offer against finalized chain state and
pays the actor with a `call`. The provider runs the work in a private, bounded
sandbox and settles with an attestor-signed `respond`. **Finalized TOS chain
state is the only authority.** Gateways, catalogs, Quote packages and local
journals are transport or cache; none of them can create or change a
purchase.

What a buyer is guaranteed by the contract once a `call` is final:

| Outcome | When | Effect |
|---|---|---|
| Responded | the owner sends `respond` with the attestor's signature before the response deadline | price and storage fee are credited to the provider |
| Refunded | no response by the response deadline; anyone sends `expire`, then the caller sends `claim_refund` before the refund-claim deadline | price paid to the destination the caller chooses; the storage fee stays with the provider |
| Swept | the request is still pending or refundable at the refund-claim deadline; anyone sends `sweep_expired_request` | price returned to the caller; the sweeper earns a 0.1–1 TOS bounty taken from the storage fee |

The response window and the refund-claim window are each **at least one hour**
(at most 30 days). A buyer therefore waits at least one hour before a refund
can start, and has at least one more hour to claim it.

What it is **not**, today:

- no one-command installer and no GUI: you run several command-line tools;
- software work only (a Go test run of an inline source archive of at most
  1 MiB); general model inference is not available (it is locked behind a
  later expansion gate);
- no public network: the public testnet was stopped on 2026-11-14;
- validated end to end only on a **local, single-host** network (see the
  [M1 record](AI_SERVICE_PROVIDER_IMPLEMENTATION_STATUS.md#m1--local-settlement-lifecycle)).

## 2. Prerequisites

- **OS:** Linux x86-64 or arm64. A provider host also needs cgroup v2,
  containerd 2.x, runc v2, overlayfs and root access.
- **Go 1.26.11** for the Go repositories; Rust (`cargo`) for `tosctl`.
- **A funded wallet** on the network you use, held in `tosctl` custody.
- **Network facts:** at least three independent JSON-RPC endpoints (3 to 8 are
  accepted), the network domain (network id, genesis root hash, genesis file
  hash), the Native Registry code BOC and the pinned Service Actor release
  code hash.

### Build the tools

```sh
# tosctl (repository tos): wallets, registry actions, Service Actor messages
cd <TOS_CHECKOUT>/tosctl/src && cargo build --release -p tosctl
# -> <TOS_CHECKOUT>/tosctl/src/target/release/tosctl

# tos-service-protocol: buyer, publication, signing and discovery tools
cd <PROTOCOL_CHECKOUT>
GOWORK=off go build -o <BIN_DIR>/ ./cmd/tos-service-buyer ./cmd/tos-service-provider-publish \
  ./cmd/tos-service-wallet ./cmd/tos-service-discovery

# openfox: the agent runtime that buys and sells on the rail
cd <OPENFOX_CHECKOUT> && GOWORK=off go build -o <BIN_DIR>/ ./cmd/openfox

# tos-ai: the provider's sandboxed executor
cd <TOS_AI_CHECKOUT> && GOWORK=off go build -o <BIN_DIR>/ ./cmd/software-work-execute
```

Record the SHA-256 of `tosctl` (`sha256sum <TOSCTL>`): every tool that drives
it takes that digest and refuses a different binary.

The pinned release artifacts live in the `tos` repository:

| Value | Source |
|---|---|
| Native Registry code BOC | `crypto/smartcont/tos-service-native-registry-v1.boc.base64` |
| Service Actor release code hash | `code_hash` in `crypto/smartcont/tos-service-actor-v1.release.json` |

### Set up tosctl custody

`tosctl` keeps its configuration and a file-backed vault in an owner-only
directory, and reads the vault location from `VAULT_URL` (see
`tosctl/README.md`):

```sh
export TOSCTL_HOME=<OWNER_ONLY_DIR>            # chmod 700
export VAULT_URL="file://<TOSCTL_HOME>/vault.json?master_key=<MASTER_KEY>"
export CONFIG_PATH=<TOSCTL_HOME>/config.json   # tosctl's -c/--config default
tosctl config generate -o "$CONFIG_PATH"
# edit chain_rpc.urls in that file to list your JSON-RPC endpoints
tosctl wallet create -n <WALLET> -v V3R2 -w 0
tosctl wallet ls --format json   # shows the address to fund
# fund the address, then:
tosctl wallet activate -n <WALLET>
```

The local end-to-end run used `V3R2` wallets; `wallet create` also accepts
`V4R2` and `V5R1`, which this path has not exercised. Never put the master
key on a command line or in a shared file.

The commands below assume `CONFIG_PATH` and `VAULT_URL` are exported. Tools
that take `--tosctl-config` need the same configuration path.

### Try everything on one machine

`tos-service-protocol` ships the script that produced the local evidence. It
boots a fresh three-validator ML-DSA-44 network on loopback and drives the
real `tosctl` and `tos-service-buyer` commands:

```sh
TOS_SOURCE=<TOS_CHECKOUT> \
TOS_BUILD=<TOS_BUILD_DIR> \
TOSCTL=<TOSCTL> \
E2E_WORKDIR=<OWNER_ONLY_WORK_DIR> \
REGISTRY_CODE_BOC=<TOS_CHECKOUT>/crypto/smartcont/tos-service-native-registry-v1.boc.base64 \
ACTOR_CODE_HASH=<SERVICE_ACTOR_CODE_HASH> \
THERMAL_GUARD=<GUARD_PROGRAM> \
  <PROTOCOL_CHECKOUT>/scripts/service-actor-buyer-e2e.sh
```

- `TOS_BUILD` is a build of the `tos` repository with the PQ genesis tools;
  `TOS_SOURCE` must have its Python environment ready (see
  [Troubleshooting](#5-troubleshooting)).
- `THERMAL_GUARD` is a program the script starts with the run's process-group
  id so it can pause the run under heat; `/bin/true` disables it.
- Optional: `E2E_LIFECYCLE=1` adds the expire, refund, withdrawal and sweep
  paths (about two hours of real deadlines); `E2E_EXECUTE=1` adds paid
  execution in the private containerd sandbox and needs `E2E_EXECUTOR`
  (run under `sudo -n`) and `E2E_TOS_AI_COMMIT`.
- The run fails unless the protocol checkout is clean, and it ends with one
  `ALL PASS` or `FAIL` line and `<E2E_WORKDIR>/evidence.json`.

The script uses `service-actor-e2e-fixture` for the manifest, metadata hash,
Quote package and the attestor's Receipt check. That tool is a **local
stand-in** with no authority; it is not a production tool.

## 3. Buyer guide

### Before you pay, check

- **Network:** every tool takes the network domain and refuses endpoints that
  serve another genesis. Get the genesis hashes from a source you trust, not
  from the provider.
- **Actor code hash:** pin the Service Actor release code hash
  (`--actor-code-hash`, or `actor_code_hash` in OpenFox). An actor running
  other code is refused.
- **Attestor:** the actor must have an attestor that matches the manifest.
  Attestor-less actors are refused, because without one the owner alone could
  settle. You can inspect an actor yourself:
  `tosctl agent service show --address <ACTOR> --format json`
  (look at `attestor_key_id`).
- **Price and windows:** the payment is `price + storage fee + 0.2 TOS`
  admission allowance (unused allowance is returned). The storage fee is never
  refunded. A refund costs two more transactions from your wallet.

### Path A: OpenFox

OpenFox runs the whole purchase, delivery, acceptance and refund for you.
It needs a Messenger daemon for your Agent and a rail configuration; see
[the OpenFox rail guide](https://github.com/tosnetwork/openfox/blob/main/docs/guides/service-actor-rail.md).

The rail configuration is an owner-only (`0600`) JSON file. Its buyer section
holds the spending policy (amounts in nanoTOS):

```json
"buyer": {
  "gateway_url": "<GATEWAY_URL>",
  "gateway_token_file": "<TOKEN_FILE>",
  "caller_id": "<CALLER_ID>",
  "policy": {
    "max_committed_per_purchase_nanotos": "<PER_PURCHASE_MAX>",
    "max_committed_in_window_nanotos": "<WINDOW_MAX>",
    "window_seconds": 86400,
    "max_open_purchases": 4,
    "confirm_above_nanotos": "<ASK_ABOVE>",
    "refund_reserve_nanotos": "<RESERVE_FOR_REFUND_FEES>",
    "allowed_providers": ["agent_<PROVIDER_AGENT_HEX>"]
  }
}
```

`gateway_ca_file` is optional. The rest of the file (network, endpoints,
`tosctl` pin, wallet, sockets, state directory) is shown in the OpenFox guide.

```sh
openfox earning service buy --rail-config <RAIL_CONFIG> \
  --capability-id cap_<HEX> --version 1.0.0 --source <SOURCE_ARCHIVE>
# --quote-package <FILE> uses a Quote obtained out of band instead of the gateway
# --yes confirms a purchase the policy routes to you; otherwise you are asked
openfox earning service serve --rail-config <RAIL_CONFIG>      # keep running
openfox earning service purchases --rail-config <RAIL_CONFIG>
```

`buy` shows the costs before paying. `serve` delivers the work once the call is
admitted, accepts a result only if its Receipt matches the finalized attested
response, and sends `expire` and `claim_refund` itself when the provider does
not answer in time. `purchases` shows each purchase's phase, status, required
action, deadlines and costs.

The local M1 run exercised Path B, not the OpenFox buyer.

### Path B: tos-service-buyer, step by step

Every command prints JSON and takes the same common flags:

```sh
COMMON="--network-domain <NETWORK_DOMAIN_JSON> \
  --rpc <RPC_1>,<RPC_2>,<RPC_3> \
  --registry-code-boc <REGISTRY_CODE_BOC> \
  --registry-code-hash tvm-cell-sha256:<HEX> \
  --actor-code-hash tvm-cell-sha256:<HEX> \
  --state-dir <ABSOLUTE_OWNER_ONLY_DIR> \
  --manifest-dir <MANIFEST_DIR> \
  --buyer-wallet 0:<BUYER_WALLET_HEX>"
```

- `<NETWORK_DOMAIN_JSON>` holds exactly
  `{"network_id": "...", "genesis_root_hash": "sha256:...", "genesis_file_hash": "sha256:..."}`.
- `<MANIFEST_DIR>` holds manifests named `<sha256 hex>.cbor`. The bytes are
  untrusted and used only if they match the finalized digest. Get them from
  the provider or from a Gateway catalog
  (`tos-service-discovery get --gateway <URL> --caller-id <ID> --manifest-digest sha256:<HEX>`
  prints them base64-encoded in `canonical_cbor`).
- Budgets: `--max-per-call-nanotos` (default 1 TOS),
  `--max-window-nanotos` (default 10 TOS), `--max-calls` (default 100) and
  `--budget-window` (default 24h). Outstanding calls count against the window
  whatever their age. `--quorum` defaults to a strict majority of `--rpc`.

1. **Discover** and verify the offer at one finalized checkpoint:

   ```sh
   tos-service-buyer discover $COMMON --capability-id cap_<HEX> --version 1.0.0
   ```

2. **Get a Quote package** (`QuoteProposalPackageV1`, protojson).
   **Not yet implemented in `tos-service-buyer`:** there is no command that
   requests one from a Gateway. OpenFox `buy` does this; the local script
   uses the `service-actor-e2e-fixture quote` stand-in.

3. **Prepare**: validate the Quote, reserve the budget and journal the call.
   Nothing is sent:

   ```sh
   tos-service-buyer prepare $COMMON --package <QUOTE_PACKAGE_JSON> \
     --execution-id <64_HEX> --input-digest <64_HEX>
   ```

   The output carries `request_hash`, `payment_nanotos` and the terms. The
   input digest commits to your source archive; how it is derived from the
   archive is the transport's rule. **Not yet implemented as a standalone
   command:** computing the input digest and delivering the archive and Quote
   to the provider. OpenFox does both over Agent Packets.

4. **Call**: sign and send through `tosctl`. The vault is read from
   `VAULT_URL` in the environment, never from a flag:

   ```sh
   tos-service-buyer call $COMMON --request-hash <REQUEST_HASH> \
     --tosctl <TOSCTL> --tosctl-sha256 <TOSCTL_SHA256> \
     --tosctl-config <TOSCTL_CONFIG> --wallet <WALLET>
   ```

   The call commits to the quoted terms hash, so terms the provider changed
   after the Quote are refused on chain.

5. **Status**: resolve the call from finalized history:

   ```sh
   tos-service-buyer status $COMMON --request-hash <REQUEST_HASH>
   tos-service-buyer requests $COMMON --actor 0:<ACTOR_HEX> --caller 0:<BUYER_WALLET_HEX>
   ```

   `status` reports `phase`, `request_id`, `state`, `status`,
   `required_action`, `response_deadline`, `refund_claim_deadline`,
   `call_transaction` and, once responded, `response_hash`. `requests` pages
   with `--page-size` (at most 100) and `--after-request-id`.

### The three outcomes

| `status` | Meaning | What to do |
|---|---|---|
| `pending` | waiting for the provider | nothing; check again |
| `responded` | settled; `response_hash` is the attested Receipt hash | check the delivered result against it |
| `overdue` | response deadline passed, no response | send `expire`, then `claim-refund`, before the refund-claim deadline |
| `refundable` | `expire` is final | send `claim-refund` before the refund-claim deadline |
| `lapsed` | refund-claim deadline passed | nothing to claim; a sweep returns the price to you |
| `refunded`, `swept` | price returned | nothing |

With `tosctl`:

```sh
tosctl agent service request-show --address <ACTOR> --request-id <ID> --format json
tosctl agent service send --operation expire --address <ACTOR> --from <WALLET> \
  --request-id <ID> --yes
tosctl agent service refund-show --address <ACTOR> --request-id <ID> --format json
tosctl agent service send --operation claim-refund --address <ACTOR> --from <WALLET> \
  --request-id <ID> --destination <REFUND_ADDRESS> --yes
# after the refund-claim deadline, anyone may sweep:
tosctl agent service send --operation sweep-expired-request --address <ACTOR> \
  --from <WALLET> --request-id <ID> --yes
```

`claim-refund` and `sweep-expired-request` attach 0.2 TOS by default to pay
their own fees; unused funding is returned.

### Crash recovery

The buyer journal (`<state-dir>/journal`) records every call before custody
starts. A call interrupted between recording and a confirmed submission is
marked `ambiguous` and is **never sent again**. Run `status` with the same
`--request-hash`: it settles the call from finalized history as `admitted`
(the call landed; continue as above) or not found. Do not prepare a new call
for the same work until `status` has resolved the old one. Back up the state
directory; it holds the only record of your outstanding calls.

## 4. Provider guide

Do the steps in order. Each key stays in `tosctl` custody.

### 4.1 Identity and controller keys

```sh
tosctl agent native-registry new-controller --name <PROVIDER_CONTROLLER>
tosctl agent native-registry new-controller --name <ATTESTOR_CONTROLLER>
```

Each prints the ML-DSA-44 `public_key` and `key_id`. Write the Agent policy
file, for example
`{"threshold": 1, "recovery_threshold": 1, "recovery_timelock": 3600, "controllers": [{"public_key": "<HEX>", "weight": 1, "purposes": 15}]}`,
then build, sign and send the registration (`register-agent` never sends;
`wallet send` does):

```sh
tosctl agent native-registry register-agent --global-config <GLOBAL_CONFIG> \
  --network-label <NETWORK_LABEL> --policy <POLICY_JSON> \
  --nonce <64_HEX> --signer <PROVIDER_CONTROLLER>
tosctl wallet send --from <OWNER_WALLET> --to <DESTINATION> --amount 2 \
  --body-boc <BODY_BOC> --state-init-boc <STATE_INIT_BOC> --yes
tosctl agent native-registry show --global-config <GLOBAL_CONFIG> \
  --network-label <NETWORK_LABEL> --address <DESTINATION>
```

Your Agent id is `agent_<object_id>`. `<NETWORK_LABEL>` names the identity
domain, for example `tos:global-id:<GLOBAL_ID>`.

### 4.2 Deploy the Service Actor with an attestor

```sh
tosctl agent service deploy --name <LOCAL_NAME> --owner <OWNER_WALLET_ADDRESS> \
  --open-access --price-per-call <TOS> --storage-fee <TOS> --cleanup-bounty <TOS> \
  --response-sla <SECONDS> --refund-claim-window <SECONDS> --rate-limit-per-day 0 \
  --metadata-hash <64_ZERO_HEX> --proof-scheme-hash <64_ZERO_HEX> \
  --attestor-controller <ATTESTOR_CONTROLLER> \
  --from <OWNER_WALLET> --amount 3 -w 0 --yes --format json
```

- `--response-sla` and `--refund-claim-window` are at least 3600 seconds.
  The storage fee must cover 0.1 TOS plus the cleanup bounty; the bounty is
  0.1–1 TOS. Deploy funding is at least 1.2 TOS.
- **Always pass `--attestor-controller`** (or `--attestor-pubkey`). Buyers
  and OpenFox refuse an attestor-less actor.
- The metadata hash is set later (4.4), once the Capability exists.
- `openfox earning service preflight` (4.6) later checks that the actor is
  active, runs the pinned release code and has the manifest's attestor.

### 4.3 Build the manifest

```sh
openfox earning service manifest --provider-agent agent_<HEX> --actor 0:<ACTOR_HEX> \
  --code-hash tvm-cell-sha256:<HEX> --attestor mldsa44:<ATTESTOR_KEY_ID> \
  --version 1.0.0 --retention-seconds 86400 --out-dir <ABSOLUTE_DIR>
```

It writes `<digest hex>.cbor` and prints `manifest_digest` and the next steps.
It has no chain effect. The manifest is immutable once published; check it
first.

### 4.4 Publish the Capability

There are two implemented routes.

**Direct with tosctl** (the route the local run validated):

```sh
tosctl agent native-registry action --global-config <GLOBAL_CONFIG> \
  --network-label <NETWORK_LABEL> --kind register-capability \
  --agent <AGENT_ADDRESS> --nonce <64_HEX> --object-nonce <64_HEX> \
  --version 1.0.0 --manifest <MANIFEST_DIGEST_HEX> --signer <PROVIDER_CONTROLLER>
tosctl wallet send --from <OWNER_WALLET> --to <DESTINATION> --amount 2 \
  --body-boc <BODY_BOC> --yes
```

Read `final_target` from the action output, then
`tosctl agent native-registry show ... --address <FINAL_TARGET>` until it is
registered; the Capability id is `cap_<object_id>`. To list the manifest in a
Gateway catalog:
`tos-service-discovery publish --gateway <URL> --caller-id <ID> --capability-id cap_<HEX> --manifest-cbor <MANIFEST_CBOR> --idempotency-key <KEY>`.

**Journaled through a Gateway** with `tos-service-provider-publish`
(restartable at every phase). It takes the manifest as reviewed software-work
manifest JSON (see [Software Work Manifest V1](SOFTWARE_WORK_MANIFEST_V1.md)),
and needs a Gateway and its relay token:

```sh
PUB="--state-dir <ABSOLUTE_OWNER_ONLY_DIR> --gateway <GATEWAY_URL> \
  --token-file <TOKEN_FILE> --caller-id agent_<HEX> \
  --tosctl <TOSCTL> --tosctl-sha256 <TOSCTL_SHA256>"
tos-service-provider-publish prepare $PUB --network-id <NETWORK_ID> \
  --genesis-root sha256:<HEX> --genesis-file sha256:<HEX> \
  --registry-code-hash tvm-cell-sha256:<HEX> --owner-agent-id agent_<HEX> \
  --manifest-json <MANIFEST_JSON> \
  --rpc <RPC_1>,<RPC_2>,<RPC_3> --registry-code-boc <REGISTRY_CODE_BOC> \
  --actor-code-hash tvm-cell-sha256:<HEX> > <UNSIGNED_ACTION_JSON>
tos-service-provider-publish preview $PUB --action-hash sha256:<HEX> \
  --rpc <RPC_1>,<RPC_2>,<RPC_3> --registry-code-boc <REGISTRY_CODE_BOC> \
  --actor-code-hash tvm-cell-sha256:<HEX>
tos-service-wallet --action <UNSIGNED_ACTION_JSON> --output <SIGNED_ACTION_JSON> \
  --tosctl <TOSCTL> --tosctl-sha256 <TOSCTL_SHA256> --tosctl-config <TOSCTL_CONFIG> \
  --authority-controller <PROVIDER_CONTROLLER>
tos-service-provider-publish apply $PUB --action-hash sha256:<HEX> \
  --signed-action <SIGNED_ACTION_JSON>
tos-service-provider-publish status --state-dir <ABSOLUTE_OWNER_ONLY_DIR>
```

Read the preview before signing; `prepare` refuses a manifest that names
another actor release, and the preview marks an attestor-less actor as a
mismatch. Re-run `apply` with the same `--action-hash` after any crash; it
resumes and never relays a different action. This route has unit and restart
tests but **has not been run end to end against a Gateway**.

**Then, for either route,** bind the actor to the Capability version:

```sh
openfox earning service metadata --network-id <NETWORK_ID> \
  --genesis-root-hash sha256:<HEX> --genesis-file-hash sha256:<HEX> \
  --capability-id cap_<HEX> --provider-agent agent_<HEX> --version 1.0.0 \
  --manifest-digest sha256:<HEX>
tosctl agent service send --operation update-policy --address <ACTOR> --from <OWNER_WALLET> \
  --price-per-call <TOS> --storage-fee <TOS> --cleanup-bounty <TOS> \
  --response-sla <SECONDS> --refund-claim-window <SECONDS> --active true \
  --open-access --rate-limit-per-day 0 \
  --metadata-hash <METADATA_HASH> --proof-scheme-hash <PROOF_SCHEME_HASH> --yes
```

`update-policy` replaces the whole policy, so pass every field.
`openfox earning service metadata` prints `metadata_hash` only. The
software-work proof scheme hash is a fixed constant
(`ServiceActorSoftwareWorkProofScheme` in `tos-service-protocol`
`pkg/nativecore`), the SHA-256 of a fixed string; no command prints it, so
compute it:

```sh
printf %s 'tos.service.service-actor.receipt.software-work-v1' | sha256sum
```

Buyers who use a Gateway get Quotes from the Gateway's provider Quote profile
(`TOS_SERVICE_PROVIDER_QUOTE_PROFILE_FILE`, example in
`tos-service-gateway/docs/provider-quote-profile.example.json`). For OpenFox,
set its transport to `security_mode` `2`, `base_url`
`agent-packet:<PROVIDER_AGENT_ID>` and `max_request_bytes` `1048576`.

### 4.5 Install the private containerd

Follow
[tos-ai `deploy/provider/README.md`](https://github.com/tosnetwork/tos-ai/blob/main/deploy/provider/README.md).
In short:

1. Install `containerd.toml` and `tos-service-containerd.service` as root and
   enable the unit. It serves its own socket at
   `/run/tos-service-containerd/containerd.sock`. Never reuse the system,
   Docker or Kubernetes containerd; raw socket access equals root.
2. Check the directory is `root:root 700` and the socket `root:root 600`.
3. Build the image archive with `build/software-work-go-1.26.5/build.sh`,
   import it into namespace `tos-service-paid-work`, and **tag it with its
   digest-qualified name** (`<NAME>@sha256:<INDEX_DIGEST>`). The executor
   looks the image up by that exact name.
4. Run the live backend conformance tests from that README. Both must pass
   before the host serves paid work.

### 4.6 Preflight

Write the provider rail configuration (fields in the
[OpenFox rail guide](https://github.com/tosnetwork/openfox/blob/main/docs/guides/service-actor-rail.md#configuration);
the provider section names `capability_id`, `version`, `manifest_file`,
`attestor_controller`, `respond_budget_seconds`, `executor_binary`,
`executor_sha256`, `containerd_socket` and `fifo_dir`), then:

```sh
openfox earning service preflight --rail-config <RAIL_CONFIG>
```

It runs side-effect-free checks (permissions, pins, endpoints and genesis,
Registry, Capability, actor, attestor, clock skew, signer keys) and exits
non-zero if any fails. It sends and signs nothing.

### 4.7 Serve

**Run exactly one provider runtime per Service Actor and offer.** Two runtimes
with separate state for the same actor can each admit and execute the same
request. Pick one of these:

**OpenFox** (admits, executes, checks and responds for you):

```sh
openfox earning service serve --rail-config <RAIL_CONFIG>
```

For each task it admits the request once through finalized state, runs the
pinned executor, builds the Receipt, has it checked against the attestor
policy, re-checks that the request is still pending, and sends `respond`.
A failed or ambiguous execution is never attested; the buyer's refund path
applies.

**Standalone paid command** (tos-ai), run as root against the private daemon.
Its rail config is described in the tos-ai README:

```sh
software-work-execute paid --rail-config <EXECUTOR_RAIL_JSON> \
  --containerd-socket /run/tos-service-containerd/containerd.sock \
  --fifo-dir <PRIVATE_FIFO_DIR> --state-dir <PERSISTENT_PAID_STATE_DIR> \
  --source <SOURCE_TAR> --quote-package <QUOTE_PB> \
  --buyer-wallet 0:<BUYER_HEX> --actor 0:<ACTOR_HEX> \
  --request-id <ID> --call-lt <CALL_LT> --call-hash <CALL_TX_HASH_HEX> \
  --execution-id sha256:<HEX> --input-digest sha256:<HEX>
```

Exit codes: `0` completed, `1` refused or unavailable, `2` usage,
`3` already taken, `4` not pending now, `5` ambiguous (never rerun or respond),
`6` not admitted, `7` execution failed, `8` refused before execution. Keep the
state directory persistent; it holds the at-most-once slots. Sweep expired
artifacts with `software-work-execute artifacts-gc --state-dir <DIR> --limit 64`.

### 4.8 Respond

OpenFox `serve` responds by itself. With the standalone command, respond only
when it reports `completed` and `respond_check` is `passed`, and only after the
attestor has checked the Receipt against the finalized request:

```sh
tosctl agent service send --operation respond --address <ACTOR> --from <OWNER_WALLET> \
  --request-id <ID> --response-hash <RESPONSE_HASH> \
  --attestor-controller <ATTESTOR_CONTROLLER> --yes
```

`tosctl` signs whatever hash you give it. **Not yet implemented as a
production command:** the standalone attestor Receipt check. OpenFox does it
in process; the local script uses the `service-actor-e2e-fixture
receipt-check` stand-in.

### 4.9 Pause and resume

```sh
openfox earning service pause --rail-config <RAIL_CONFIG> --reason "<TEXT>"
openfox earning service resume --rail-config <RAIL_CONFIG>
```

Pausing stops new local admission only; admitted work still finishes. Buyers
can still call the actor; to stop new calls on chain, send `update-policy`
with `--active false`. Calls that arrive during a long pause fall to refund.

### 4.10 Status and revenue

```sh
openfox earning service status --rail-config <RAIL_CONFIG>
tosctl agent service show --address <ACTOR> --format json
```

`credited_revenue_nanotos` (the contract's `withdrawable_revenue`) is money
the actor owes you, **not** money in your wallet. Each request has one
`operator_state`: `admitted`, `executing`, `result_available`, `responded`,
`refunded`, `swept` or `outcome_unknown`.

### 4.11 Withdraw revenue

```sh
tosctl agent service send --operation withdraw-revenue --address <ACTOR> \
  --from <OWNER_WALLET> --withdraw-amount <TOS> --yes
```

Then check the wallet balance yourself. **Not yet implemented:** OpenFox does
not track withdrawals or wallet credit (`wallet_receipt` is `not_tracked`).

## 5. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `containerd socket is not private` (or `... socket directory is not private`) | the socket is not `0600`, or its directory is not `0700`, owned by the executor's user. containerd creates the socket `0660` | use the current tos-ai unit, which tightens the socket after start; run the executor as the socket owner (root) |
| image `not found` from containerd at execution | the image was imported under its plain tag only | `ctr ... images tag <NAME> <NAME>@<DIGEST>`, then `images ls "name==<NAME>@<DIGEST>"` |
| `--destination is required` | `claim-refund` without a destination | add `--destination <REFUND_ADDRESS>` |
| `claim-refund` refused on chain | the refund-claim deadline passed (`status` shows `lapsed`) | run `sweep-expired-request`, which returns the price to the caller. Send `expire` and `claim-refund` early; the window is only one hour at the minimum |
| tostester fails with missing generated TL modules | the TL bindings are generated, not committed | in the `tos` checkout: `uv sync --locked`, then `uv run test/tostester/generate_tl.py` |
| `call needs --tosctl, --tosctl-sha256, --tosctl-config and --wallet` | missing custody flags | pass all four, with `VAULT_URL` exported |
| `--state-dir must be absolute and clean` | relative or unclean path | use an absolute path without `..` or a trailing `/` |
| layer permission errors inside the sandbox | the daemon ran under a strict umask | use the unit's `UMask=0022`, then re-import the image |

## 6. Limits and next steps

- No public network today; independent buyers and providers (WP-07) and
  Gates D–G are not done. Inference (WP-08) is locked.
- The OpenFox path and the Gateway publication route were not part of the
  local M1 run.
- Read next:
  - [AI Service Provider Requirements V1](AI_SERVICE_PROVIDER_REQUIREMENTS_V1.md)
  - [Implementation Status](AI_SERVICE_PROVIDER_IMPLEMENTATION_STATUS.md)
  - Local evidence:
    [M1](../deployments/local-service-actor-provider-m1-20261114.json),
    [settlement lifecycle](../deployments/local-service-actor-settlement-lifecycle-20261114.json),
    [paid execution](../deployments/local-service-actor-paid-execution-20261114.json)
  - [Service Actor TVM V1](SERVICE_ACTOR_TVM_V1.md),
    [Software Work Manifest V1](SOFTWARE_WORK_MANIFEST_V1.md),
    [Software Work Execution V1](SOFTWARE_WORK_EXECUTION_V1.md)
  - [Gate E Buyer Onboarding](GATE_E_BUYER_ONBOARDING.md),
    [Gate E Provider Onboarding](GATE_E_PROVIDER_ONBOARDING.md)
  - `tos-service-protocol/docs/provider-sdk.md`,
    `openfox/docs/guides/service-actor-rail.md`,
    `tos-ai/deploy/provider/README.md`
