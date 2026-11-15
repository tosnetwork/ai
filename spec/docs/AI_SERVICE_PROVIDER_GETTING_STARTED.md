# TOS AI Service Provider — Getting Started

**Audience:** a technically capable user who wants to buy software work, or
sell it, on the TOS Service Actor rail.
**Status:** guide to the commands that exist on `main` of each repository on
2026-11-15. It changes no requirement, gate or roadmap status; see
[Requirements V1](AI_SERVICE_PROVIDER_REQUIREMENTS_V1.md) and the
[Implementation Status](AI_SERVICE_PROVIDER_IMPLEMENTATION_STATUS.md).

Every command, flag and configuration field below exists in the named
repository. Where no command exists for a step, the guide says
**not yet implemented** instead of inventing one.

`openfox earning service` is the entry point for both roles (sections 3 to 5).
The step-by-step `tosctl`, `tos-service-buyer` and
`tos-service-provider-publish` commands remain available and are described in
[Manual and advanced paths](#6-manual-and-advanced-paths).

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

- no installer and no GUI: one command-line entry point drives the sale and
  the purchase, but the wallet, the chain files and the provider's container
  runtime are still set up with other tools
  ([section 3.7](#37-what-still-needs-another-tool));
- software work only (a Go test run of an inline source archive of at most
  1 MiB); general model inference is not available (it is locked behind a
  later expansion gate);
- no public network: the public testnet was stopped on 2026-11-14;
- validated end to end only on a **local, single-host** network (see the
  [local records](AI_SERVICE_PROVIDER_IMPLEMENTATION_STATUS.md#openfox-front-door--local-two-node-sale));
- no delivery between two hosts yet: that needs a Messenger daemon per Agent,
  which has not been run between two nodes
  ([section 3.6](#36-carrying-the-work-transports));
- the provider node runs as an ordinary user, but the operator still installs
  the private container runtime and the executor service in front of it as
  root, once ([section 3.8](#38-the-provider-node-runs-as-an-ordinary-user)).

## 2. Prerequisites

- **OS:** Linux x86-64 or arm64. A provider host also needs cgroup v2,
  containerd 2.x, runc v2, overlayfs, and root access for the operator's
  one-time installation of the container runtime and the executor service
  (section 4.1). The provider node itself runs as an ordinary user.
- **Go 1.26.11** for the Go repositories; Rust (`cargo`) for `tosctl`.
- **A funded, activated wallet** on the network you use, held in `tosctl`
  custody, of type V3R2, V4R2 or V5R1
  ([section 3.4](#34-accepted-wallet-types)).
- **Network facts:** at least three independent JSON-RPC endpoints (3 to 8 are
  accepted), the chain global configuration file, the network label of the
  identity domain (for example `tos:global-id:<GLOBAL_ID>`), the Native
  Registry code BOC and the pinned Service Actor release code hash. The manual
  tools also take the network domain (network id, genesis root hash, genesis
  file hash) and the registry code hash; OpenFox derives those.

### Build the tools

```sh
# tosctl (repository tos): wallets, registry actions, Service Actor messages
cd <TOS_CHECKOUT>/tosctl/src && cargo build --release -p tosctl
# -> <TOS_CHECKOUT>/tosctl/src/target/release/tosctl

# openfox: the entry point for selling and buying on the rail
cd <OPENFOX_CHECKOUT> && GOWORK=off go build -tags goolm,stdjson -o <BIN_DIR>/ ./cmd/openfox

# tos-ai: the provider's sandboxed executor, the root-run executor service in
# front of it, and the collection command its timer runs
cd <TOS_AI_CHECKOUT> && GOWORK=off go build -o <BIN_DIR>/ ./cmd/software-work-execute ./cmd/software-work-executord

# tos-service-protocol: only for the manual paths of section 6
cd <PROTOCOL_CHECKOUT>
GOWORK=off go build -o <BIN_DIR>/ ./cmd/tos-service-buyer ./cmd/tos-service-provider-publish \
  ./cmd/tos-service-wallet ./cmd/tos-service-discovery
```

Record the SHA-256 of `tosctl` (`sha256sum <FILE>`): every tool that drives
it pins that digest and refuses a different binary. The same holds for the
executor binary in the legacy single-user mode (section 3.8), where OpenFox
runs it itself; with the executor service, OpenFox runs no executor binary.

The pinned release artifacts live in the `tos` repository:

| Value | Source |
|---|---|
| Native Registry code BOC (`--registry-code-boc`, `registry_code_boc_file`) | `crypto/smartcont/tos-service-native-registry-v1.boc.base64` |
| Native Registry code hash (`--registry-code-hash`, `registry_code_hash`; derived by OpenFox `init`) | `code_hash` in `crypto/smartcont/tos-service-native-registry-v1.release.json` |
| Service Actor release code hash (`--actor-code-hash`, `actor_code_hash`) | `code_hash` in `crypto/smartcont/tos-service-actor-v1.release.json` |

Copy each `code_hash` (a `tvm-cell-sha256:<hex>` value) from the file;
do not retype it.

### Set up tosctl custody and the wallet

OpenFox holds no key and does not create, fund or activate a wallet. Do that
with `tosctl`, which keeps its configuration and a file-backed vault in an
owner-only directory and reads the vault location from `VAULT_URL` (see
`tosctl/README.md`):

```sh
export TOSCTL_HOME=<OWNER_ONLY_DIR>            # chmod 700
export VAULT_URL="file://<TOSCTL_HOME>/vault.json?master_key=<MASTER_KEY>"
export CONFIG_PATH=<TOSCTL_HOME>/config.json   # tosctl's -c/--config default
tosctl config generate -o "$CONFIG_PATH"
# edit chain_rpc.urls in that file to list your JSON-RPC endpoints
tosctl wallet create -n <WALLET> -v V5R1 -w 0
tosctl wallet ls --format json   # shows the address to fund
# fund the address, then:
tosctl wallet activate -n <WALLET>
```

`wallet create` has no default version. Its help says
"V3R2 only for bootstrap and operating keys, V4R2, V5R1", so use `V5R1` (the
version tosctl's `agent wallet create` defaults to) or `V4R2` for a wallet that
holds funds. **Both validated local runs used `V3R2` wallets**; `V4R2` and
`V5R1` are accepted by the code but have not yet been exercised on this path.
Never put the master key on a command line or in a shared file.

The commands below assume `VAULT_URL` is exported in the shell that runs them.
OpenFox passes it to `tosctl` and never prints or stores it. The manual tools
of section 6 also need `CONFIG_PATH`, or `--tosctl-config` with the same path.

### Try everything on one machine

Two scripts produced the local evidence. Each boots a fresh three-validator
ML-DSA-44 network on loopback, ends with one `ALL PASS` or `FAIL` line and
writes `<E2E_WORKDIR>/evidence.json`.

**The OpenFox front door** (`openfox` `scripts/service-front-door-e2e.sh`):
two nodes and one paid job, driven only by `openfox earning service` commands
apart from wallet funding and infrastructure:

```sh
TOS_SOURCE=<TOS_CHECKOUT> \
TOS_BUILD=<TOS_BUILD_DIR> \
TOSCTL=<TOSCTL> \
E2E_WORKDIR=<OWNER_ONLY_WORK_DIR> \
REGISTRY_CODE_BOC=<TOS_CHECKOUT>/crypto/smartcont/tos-service-native-registry-v1.boc.base64 \
ACTOR_CODE_HASH=<SERVICE_ACTOR_CODE_HASH> \
E2E_EXECUTOR_SOCKET=/run/tos-service-executor/executor.sock \
THERMAL_GUARD=<GUARD_PROGRAM> \
  <OPENFOX_CHECKOUT>/scripts/service-front-door-e2e.sh
```

It needs the private container runtime and the executor service of
[section 4.1](#41-install-the-private-container-runtime-and-the-executor-service),
installed by the operator beforehand; the script installs and starts nothing.
With `E2E_EXECUTOR_SOCKET` both nodes run as the invoking user, whose uid the
service must allow and whose current login session must carry the socket's
group, and the run uses no root command. The nodes' state is staged under
`<E2E_WORKDIR>/private/nodes` (or `E2E_ROOT_BASE`); choose a work directory
outside your home directory, because the run fails when its evidence names a
home path. Without `E2E_EXECUTOR_SOCKET` the script runs the legacy
single-user mode with `E2E_EXECUTOR=<SOFTWARE_WORK_EXECUTE>`, both nodes as
root under `sudo -n` (section 3.8).

**The manual path** (`tos-service-protocol`
`scripts/service-actor-buyer-e2e.sh`): the real `tosctl` and
`tos-service-buyer` commands:

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

For both scripts:

- `TOS_BUILD` is a build of the `tos` repository with the PQ genesis tools;
  `TOS_SOURCE` must have its Python environment ready (see
  [Troubleshooting](#7-troubleshooting)).
- `THERMAL_GUARD` is a program the script starts with the run's process-group
  id so it can pause the run under heat; `/bin/true` disables it.
- `E2E_WORKDIR` must not exist yet; every run takes a fresh one.

For the manual-path script only:

- Optional: `E2E_LIFECYCLE=1` adds the expire, refund, withdrawal and sweep
  paths (about two hours of real deadlines); `E2E_EXECUTE=1` adds paid
  execution in the private containerd sandbox and needs `E2E_EXECUTOR`
  (run under `sudo -n`) and `E2E_TOS_AI_COMMIT`. It stages the provider's
  root-owned state under `E2E_ROOT_BASE` (default `/tos/m1-e2e-root`), in a
  subdirectory named after the work directory, which must not exist yet.
- The run fails unless the protocol checkout is clean.
- It uses `service-actor-e2e-fixture` for the manifest, metadata hash, Quote
  package and the attestor's Receipt check. That tool is a **local stand-in**
  with no authority; it is not a production tool.

## 3. The OpenFox front door

### 3.1 Commands

| Role | Command | What it does |
|---|---|---|
| both | `init` | pins `tosctl`, derives and cross-checks the network domain and registry code hash, resolves the wallet, creates the packet controller if absent, registers the node's Agent, writes the rail configuration |
| provider | `offer` | creates the attestor controller if absent, deploys the Service Actor, builds the manifest, registers the Capability, sets the actor policy, verifies the result, writes the offer file |
| provider | `preflight` | side-effect-free readiness report; exits non-zero if a check fails |
| both | `serve` | long-running: the provider admits, executes and responds; the buyer delivers the task, accepts the result or claims the refund |
| provider | `status` | admission, the actor's finalized accounting, withdrawals, one operator state per request |
| provider | `pause`, `resume` | stop and restart local admission of new requests |
| provider | `withdraw` | withdraws credited revenue to the owner wallet and tracks the withdrawal |
| buyer | `buy` | verifies the offer, shows the costs, pays the actor with one `call` |
| buyer | `purchases` | lists each purchase with phase, status, required action, deadlines and costs |

Every command takes `--rail-config <RAIL_CONFIG>`, the owner-only (`0600`)
JSON file that `init` writes and `offer` completes. Its fields are listed in
[the OpenFox rail guide](https://github.com/tosnetwork/openfox/blob/main/docs/guides/service-actor-rail.md#configuration);
you do not need to write it by hand.

Each command prints one JSON report on standard output and its preview and
progress on standard error. Neither holds a secret or the vault URL.

### 3.2 Preview first, `--yes` to act

`init`, `offer` and `withdraw` are the commands that create keys, sign or
send. **Without `--yes` each prints what it would do, creates, signs and sends
nothing, and exits non-zero** with
`nothing was signed or sent; review the preview and re-run with --yes` and
`"confirmed": false` in its report. Read the preview, then run the same
command again with `--yes`.

**`buy` has no preview step. By default it pays immediately**: it prints the
costs and sends the `call` in the same run. To be asked first, give `init`
`--confirm-above <TOS>`: a purchase committing more than that (price +
storage fee + 0.2 TOS allowance + refund reserve) then needs `buy --yes` or
`y` at the prompt. Restate `--confirm-above` every time you re-run `init`
with `--allow-provider`, or the threshold is dropped.

OpenFox never signs. Every signature and send is made by the pinned `tosctl`,
run from a sealed in-memory copy with only the vault URL in its environment.

### 3.3 Restart safety

`init` and `offer` keep one journal, `<STATE_DIR>/setup/journal.json`. It
records the inputs that determine on-chain identities, the nonces drawn for
them (before anything is built) and, for every chain message, that it was
handed to `tosctl` (before it is sent). Therefore:

- **Re-running resumes.** Each step reads finalized state first and is done
  if its effect is there. A re-run never creates a second Agent, Service
  Actor or Capability.
- **A message whose outcome is unknown is never sent twice** while it could
  still be included. The command reports
  `the outcome of a sent message is not yet established` and exits; run it
  again later. Only after the message's inclusion window (five minutes of
  finalized chain time after the send began) with the effect still absent is
  it sent again.
- **A changed identity input is refused** after its step was sent (another
  network or packet controller would be a second Agent; other terms a second
  actor and Capability). To change a published actor's terms see
  [section 4.10](#410-change-the-terms); to start over use another state
  directory and rail configuration.
- **One run at a time per state directory.** `init`, `offer`, `withdraw` and
  `withdraw --acknowledge` take an exclusive lock; a second run fails at once
  with `another init, offer or withdraw run is in progress`, having read,
  signed and sent nothing. `serve`, `status`, `preflight`, `pause` and
  `resume` do not take it, so you can withdraw beside a serving node.

Keep the state directory. If it is lost after the Agent registration was sent
and before `init` wrote the rail configuration, a new `init` registers a
second Agent. Back it up as a buyer too: it holds the only record of your
outstanding purchases.

### 3.4 Accepted wallet types

`init`, `offer` and `withdraw` send only from a **V3R2, V4R2 or V5R1** wallet.
`tosctl` signs their messages with an expiry, and every "the earlier message
can no longer be included, so it is safe to send again" decision rests on that
expiry. Any other type (a V1R3 message never expires and could be included
later and paid twice) and a wallet whose type `tosctl` did not report are
refused before anything is signed.

### 3.5 The tosctl pin is trust on first use

`init` hashes the `tosctl` binary and pins it. With `--tosctl-sha256 <HEX>`
the binary must have that digest. Without it, the digest printed is the
digest of whatever binary was found: **compare it with the release you meant
to install.** A binary that later differs from the pin is refused until its
new digest is given explicitly. In the legacy single-user mode `offer` pins
the executor binary the same way (`--executor-sha256`).

### 3.6 Carrying the work: transports

The source archive and the result travel between the two nodes as Agent
Packets signed by the sender's packet controller. A receiver verifies every
packet against the sender's finalized Agent state, whatever carried it.
A node needs one transport before `serve`, `buy` or `preflight` will run:

| Transport | Flag of `init` | Scope | State |
|---|---|---|---|
| direct | `--direct-peer agent_<HEX>=<PEER_RECEIVER_SOCKET>` (repeatable) | **same host, same user only** | used by the live local run |
| Messenger | `--messenger-socket <SOCKET>` | any hosts; one `tos-messengerd` daemon per Agent | **not yet run between two nodes** |

The direct transport posts a packet to the other node's receiver socket
(default `<STATE_DIR>/rail-receiver.sock`). It is for trials and
single-operator setups:

- it gives **no confidentiality** beyond the socket's file permissions;
- it has **no carrier-level admission** or rate limiting;
- it is refused when the socket is a symbolic link, not a socket, owned by
  another user, in a directory group or others can write, or (on Linux) when
  the listening process runs as another user.

Delivery between hosts needs the Messenger: each Agent runs a `tos-messengerd`
daemon whose delegation allows the `agent.packet` outbound event class and
whose Agent Packet receiver socket points at the node's receiver socket.
OpenFox does not install or configure that daemon, and the Messenger path was
not part of the live run.

`init` may be run without a transport. It then establishes the node and
reports `transport: missing`. Two direct nodes need this, because each needs
the other's Agent id, which only that node's `init` produces:

1. provider: `init` (no transport), then `offer`;
2. buyer: `init` with `--allow-provider` and `--direct-peer` for the provider;
3. provider: `init` again with `--direct-peer` for the buyer (it sends
   nothing), then `preflight` and `serve`;
4. buyer: `serve`, then `buy --offer`.

### 3.7 What still needs another tool

OpenFox does not do these:

- **Create, fund and activate the wallet:** `tosctl wallet create`, a
  transfer to its address, `tosctl wallet activate` (section 2). `init` and
  `offer` stop with the address and the amount needed when the wallet is
  missing, inactive or short.
- **Provide the chain files:** the chain global configuration file and the
  Native Registry code BOC. You supply both; `init` checks that they agree
  with each other and with a quorum of the RPC endpoints.
- **Install the private container runtime, its image and the executor
  service**, as root, once (section 4.1). `offer` only asks the service to
  describe itself and records its socket.
- **Change a published actor's terms:**
  `tosctl agent service send --operation update-policy` (section 4.10).
- **Carry packets between hosts:** a Messenger daemon per Agent (section 3.6).
- **Export the bought artifact:** it is stored in the buyer's state directory
  (section 5.4); no command prints that path or copies the file out.

### 3.8 The provider node runs as an ordinary user

A job runs in a private container runtime, and raw access to that runtime's
socket is equivalent to root, so only root may reach it. Nothing else a
provider node does needs root: not `tosctl`, not the vault, not the packet
listener. The operator therefore installs, as root and once, the runtime and
the **executor service** (`tos-ai` `software-work-executord`) in front of it
(section 4.1). The service is the only process that opens the runtime socket.
It listens on `/run/tos-service-executor/executor.sock` and serves exactly one
uid, the provider node's user. That user runs every provider command; the rail
configuration, the state directory, the `tosctl` configuration and the vault
belong to it.

What the node's uid can make root do is what the service offers, and the
service enforces it: run the one frozen job (the pinned image, `go test ./...
-count=1`, no network, no device, a read-only root, no host mount) a bounded
number at a time, under limits a request can only tighten; keep each job's
records and objects in the service's own root-only directories until a
deadline within the service's storage bounds; and spend execution identities,
each run at most once. A request carries no path, image, command, argument,
environment variable, mount, network, device or user.

The node trusts only a socket that root serves, verifies every outcome and the
artifact and report bytes itself, and keeps its own copy of them for delivery
and retention. The OpenFox guide lists what each answer of the service leads to
([Executor](https://github.com/tosnetwork/openfox/blob/main/docs/guides/service-actor-rail.md#executor)).

`preflight` reports `process.user` as `pass` for an ordinary user and as
`fail` for a node that runs as root with the executor service: a root node
would give `tosctl`, the vault access and the listeners the privilege the
service exists to confine.

#### Legacy single-user mode

**Not the recommended setup.** An operator who runs the node and a container
runtime as one user can keep the earlier arrangement: `offer --executor
<SOFTWARE_WORK_EXECUTE> --containerd-socket <SOCKET>` (optionally
`--executor-sha256` and `--fifo-dir`). OpenFox then runs the pinned executor
binary as its own child and reads its artifact store. The executor accepts
only a runtime socket, in a private directory, that its own user owns, so the
node runs as the socket's owner. With the root-only runtime of section 4.1 that
is root: every provider command, and through it `tosctl` and the vault, runs
as root; on the direct transport the buyer node runs as root too; `tosctl` run
as root refuses a configuration under a directory another user can modify;
and `preflight` warns `process.user`. In this mode an execution that has no
outcome when the node restarts is ambiguous for good and is never attested.
The [front-door record](AI_SERVICE_PROVIDER_IMPLEMENTATION_STATUS.md#openfox-front-door--local-two-node-sale)
was produced in this mode.

## 4. Provider guide

Do the steps in order. Each key stays in `tosctl` custody.

### 4.1 Install the private container runtime and the executor service

Not OpenFox; done by the operator as root, once. Follow
[`execution/deploy/provider/README.md`](../../execution/deploy/provider/README.md);
this is only a summary:

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
5. Install the executor service, section "Executor service: an unprivileged
   provider node" of that README: the `software-work-executord` binary, a
   dedicated system group (`tos-executor` in the README) whose only member is
   the provider node's user, `/etc/tos-service/executor.env` with
   `TOS_EXECUTOR_ALLOWED_UID` (the node user's uid) and
   `TOS_EXECUTOR_SOCKET_GID` (the group's gid), and the units
   `tos-service-executor.service` and `tos-service-executor-gc.timer`, both
   enabled and started. The timer is part of the installation: nothing else
   collects expired jobs. Then run the README's checks: the socket directory
   `root:<group> 750` and the socket `660`, both units active, one collection
   run by hand, and one real job through the socket as the provider user.
6. A user who was just added to the group reaches the socket only from a
   **new login session**, or through `sg tos-executor -c '<COMMAND>'`.
   `preflight` says so when that is why the socket cannot be reached.

From here on, every provider command runs as the node's ordinary user.

### 4.2 Establish the node: `init`

```sh
openfox earning service init \
  --rail-config <RAIL_CONFIG> --state-dir <STATE_DIR> \
  --rpc <RPC_1> --rpc <RPC_2> --rpc <RPC_3> \
  --global-config <GLOBAL_CONFIG> --network-label <NETWORK_LABEL> \
  --tosctl <TOSCTL> --tosctl-sha256 <TOSCTL_SHA256> \
  --tosctl-config <TOSCTL_CONFIG> --wallet <WALLET> \
  --registry-code-boc <REGISTRY_CODE_BOC> \
  --actor-code-hash tvm-cell-sha256:<HEX>
# read the preview, then repeat the command with --yes
```

All paths are absolute. `init` derives the network domain and the registry
code hash through `tosctl`, requires the registry code file and a quorum of
the endpoints (and no endpoint of another network) to agree, creates the
packet controller (`--packet-controller`, default `openfox-packet`) in the
vault if it is absent, and registers the node's Agent from the wallet with
2 TOS attached. Its report names `agent_id`; the buyer needs it only through
the offer file.

Optional: `--quorum` (default: a strict majority of `--rpc`),
`--receiver-socket`, `--vault-url-env` (default `VAULT_URL`).

### 4.3 Publish the offer: `offer`

```sh
openfox earning service offer --rail-config <RAIL_CONFIG> \
  --price <TOS> --storage-fee <TOS> --cleanup-bounty <TOS> \
  --response-sla <SECONDS> --refund-claim-window <SECONDS>
# read the preview, then repeat the command with --yes
```

The executor is the executor service at
`/run/tos-service-executor/executor.sock`; `--executor-socket <PATH>` names a
service on another socket. Before `offer` creates a key or sends a message it
asks the service to describe itself and stops unless root answers on that
socket, the service is ready and it runs the image and the limits the manifest
commits to. `--executor` and `--containerd-socket` select the legacy
single-user mode instead (section 3.8); the two cannot be combined.

Amounts are decimal TOS. The contract's bounds are applied before anything is
sent: the price is positive; the cleanup bounty is 0.1 to 1 TOS; the storage
fee is at least 0.1 TOS plus the cleanup bounty; the response SLA and the
refund-claim window are 3600 to 2592000 seconds.

Optional: `--version` (default `1.0.0`), `--attestor-controller` (default
`service-attestor`, created if absent), `--deploy-funding` (default and
minimum 1.2 TOS), `--retention-seconds` (default 86400),
`--respond-budget-seconds` (default 120), `--offer-out`; in the legacy mode
also `--executor-sha256` and `--fifo-dir` (default `<STATE_DIR>/fifo`; the
executor needs a private, empty one).

The preview shows the owner wallet, the terms, the value attached to each
message and the totals. With the defaults the three messages attach
3.21 TOS in all (1.2 deployment, 2 Capability registration, 0.01
`update-policy`) plus wallet fees. While the attestor controller does not
exist yet, what derives from its key (the actor address, the manifest digest,
the Capability id) is left open in the preview; the run with `--yes` creates
the key, prints them and sends.

With `--yes`, `offer` deploys the actor with the attestor, checks from
finalized state that it runs the pinned code, is owned by your wallet and
holds that attestor, registers the Capability, sends `update-policy` with the
metadata hash and proof scheme, runs the preflight's own chain checks, and
only then writes the provider section of the rail configuration and the
**offer file**. No manifest JSON, metadata hash or proof scheme hash is
written or computed by hand.

### 4.4 The offer file

`offer` writes `<STATE_DIR>/setup/offer.json` (or `--offer-out <FILE>`),
schema `tos.openfox.rail-offer.v1`:

| Field | Content |
|---|---|
| `capability_id`, `version` | the Capability version on offer |
| `provider_agent_id` | your Agent |
| `manifest_digest`, `manifest_cbor_base64` | the manifest and its SHA-256 |
| `updated_unix` | when the file was written |

It holds nothing secret and carries no authority. **Hand it to buyers by any
channel** (copy the file, publish it, send it). A buyer does not have to
trust it or the channel: `buy --offer` takes the provider from the
Capability's finalized owner, requires the manifest bytes to hash to the
finalized digest of the version, and reads price, storage fee and terms from
the actor's finalized policy. A file that finalized state contradicts is
refused before payment.

For the direct transport, also tell the buyer your receiver socket path, and
get the buyer's Agent id and receiver socket path in return; then run `init`
again, with the same flags as in 4.2, plus:

```sh
  --direct-peer agent_<BUYER_AGENT_HEX>=<BUYER_RECEIVER_SOCKET> --yes
```

This run sends nothing and keeps the provider section. A re-run that names a
transport replaces the recorded one, so list every peer each time.

### 4.5 Preflight

```sh
openfox earning service preflight --rail-config <RAIL_CONFIG>
```

It runs side-effect-free checks (permissions, pins, transport, endpoints and
genesis, Registry, Capability, actor, attestor, clock skew, signer keys, and
the executor service: `executor.service`, `executor.image`,
`executor.limits`), prints a JSON report and exits non-zero if any check is
`fail`. It sends and signs nothing. Two results are expected today and are not
failures: `rpc.independence` and `signer.wallet` are always `unknown`.
`process.user` passes for an ordinary user (section 3.8).
`transport.peers` warns while a direct peer's socket is absent, which means
that node is not serving yet.

### 4.6 Serve

```sh
openfox earning service serve --rail-config <RAIL_CONFIG>      # keep running
```

**Run exactly one provider runtime per Service Actor and offer.** Two runtimes
with separate state for the same actor can each admit and execute the same
request.

For each task `serve` asks the executor service whether it can run the job
(a task it cannot run waits, unadmitted, for at most one hour, or less when
the inbox's held-task bound is reached), admits the
request once through finalized state, sends the job to the service and
verifies the outcome and its bytes, builds the Receipt, has it checked against the attestor
policy, re-checks that the request is still pending, and sends `respond`.
After the respond is final it delivers the result and redelivers it until the
buyer acknowledges it or the manifest retention ends. A failed or ambiguous
execution is never attested; the buyer's refund path applies.

### 4.7 Status

```sh
openfox earning service status --rail-config <RAIL_CONFIG>
```

`credited_revenue_nanotos` (the contract's `withdrawable_revenue`) is money
the actor owes you, **not** money in your wallet. Each request has one
`operator_state`: `admitted`, `executing`, `result_available`, `responded`,
`refunded`, `swept` or `outcome_unknown`. `withdrawals` lists the ten newest
withdrawals made with `withdraw`. `--offline` skips the chain read;
`--records` prints only the request list.

### 4.8 Pause and resume

```sh
openfox earning service pause --rail-config <RAIL_CONFIG> --reason "<TEXT>"
openfox earning service resume --rail-config <RAIL_CONFIG>
```

Pausing stops new local admission only; a running `serve` sees it without a
restart and admitted work still finishes. A task that arrives while paused is
held, not refused, and is admitted after `resume` if its request is still
admissible. Buyers can still call the actor; to stop new calls on chain, send
`update-policy` with `--active false` (section 4.10). Calls that are never
answered fall to refund.

### 4.9 Withdraw revenue

```sh
openfox earning service withdraw --rail-config <RAIL_CONFIG> --amount <TOS>   # or --all
# read the preview, then repeat the command with --yes
```

Give exactly one of `--amount` and `--all`. The preview shows the amount, the
credited revenue at a finalized checkpoint, the destination (the owner
wallet: the contract pays a withdrawal to the actor's owner) and the 0.2 TOS
attached for fees. Zero and more than the credit are refused.

With `--yes` the withdrawal is recorded in `<STATE_DIR>/withdrawals/` before
it is sent, tagged with a query id, and resolved from the finalized
transaction that carries that id and pays exactly the amount to the owner.
A record is `submitted`, then `finalized`, `failed` (nothing was debited),
`not_included` (the inclusion window passed without it) or `unknown`. An
unresolved withdrawal blocks the next one.

`finalized` means the actor paid out. **The wallet's own credit is not
followed:** every record says `wallet_credit: not_verified`, and `status`
reports `wallet_receipt` as `not_tracked`. Check the wallet balance yourself.

A withdrawal can stay `unknown` for good (the actor's history no longer
reaches the record, or a transaction carries its query id without a payout of
exactly the amount). Nothing closes such a record automatically. Compare
`credited_before_nanotos` in the record with the credited revenue in `status`,
look at the owner wallet's transactions since `started_unix`, then close it:

```sh
openfox earning service withdraw --rail-config <RAIL_CONFIG> \
  --acknowledge <QUERY_ID> --note "<WHAT_YOU_CHECKED>"
# read what the node knows, then repeat the command with --yes
```

`--acknowledge` first tries once more to resolve the record from finalized
state. Otherwise it is accepted only after the withdrawal's inclusion window
has passed on finalized chain time. It moves no funds, sends nothing and does
not say whether the actor paid out; it stores the record as
`owner_acknowledged` with your note so that it no longer blocks withdrawals.
`--note` is required with it, and it cannot be combined with `--amount` or
`--all`. This path has unit tests but was **not part of the live run**.

### 4.10 Change the terms

**Not in OpenFox.** `offer` refuses changed terms once a step was sent. Change
a published actor's policy with `tosctl`, passing every field:

```sh
tosctl agent service send --operation update-policy --address <ACTOR> --from <OWNER_WALLET> \
  --price-per-call <TOS> --storage-fee <TOS> --cleanup-bounty <TOS> \
  --response-sla <SECONDS> --refund-claim-window <SECONDS> --active true \
  --open-access --rate-limit-per-day 0 \
  --metadata-hash <METADATA_HASH> --proof-scheme-hash <PROOF_SCHEME_HASH> --yes
```

See [section 6.2](#62-provider-publish-by-hand-with-tosctl) for the two hash
values and the required fields. The actor address and both hashes are in the
`offer` preview.

## 5. Buyer guide

### 5.1 Before you pay, check

OpenFox makes these checks itself; know what they are.

- **Network:** `init` refuses endpoints that serve another genesis. Get the
  chain global configuration and the network label from a source you trust,
  not from the provider.
- **Actor code hash:** pin the Service Actor release code hash
  (`--actor-code-hash`). An actor running other code is refused.
- **Attestor:** the actor must have an attestor that matches the manifest.
  Attestor-less actors are refused, because without one the owner alone could
  settle. You can inspect an actor yourself:
  `tosctl agent service show --address <ACTOR> --format json`
  (look at `attestor_key_id`).
- **Price and windows:** the payment is `price + storage fee + 0.2 TOS`
  admission allowance (unused allowance is returned). The storage fee is never
  refunded. A refund costs two more transactions from your wallet.

### 5.2 Establish the node: `init`

Get the offer file from the provider. Take `provider_agent_id` from it for
`--allow-provider`; your spending policy is an allow-list of providers. For
the direct transport, pair the same Agent id with the provider's receiver
socket path in `--direct-peer`:

```sh
openfox earning service init \
  --rail-config <RAIL_CONFIG> --state-dir <STATE_DIR> \
  --rpc <RPC_1> --rpc <RPC_2> --rpc <RPC_3> \
  --global-config <GLOBAL_CONFIG> --network-label <NETWORK_LABEL> \
  --tosctl <TOSCTL> --tosctl-sha256 <TOSCTL_SHA256> \
  --tosctl-config <TOSCTL_CONFIG> --wallet <WALLET> \
  --registry-code-boc <REGISTRY_CODE_BOC> \
  --actor-code-hash tvm-cell-sha256:<HEX> \
  --allow-provider agent_<PROVIDER_AGENT_HEX> \
  --direct-peer agent_<PROVIDER_AGENT_HEX>=<PROVIDER_RECEIVER_SOCKET> \
  --confirm-above 0
# read the preview, then repeat the command with --yes
```

**Set `--confirm-above`.** Without it `buy` pays as soon as it is run.
`--confirm-above 0` asks before every purchase; a higher value asks only for
purchases that commit more than it. The spending-policy caps below are the
hard bound either way: a purchase over them is refused, confirmed or not.

Use `--messenger-socket <SOCKET>` instead of `--direct-peer` when a Messenger
daemon carries the packets (section 3.6). `init` registers your node's Agent
from the wallet with 2 TOS attached. Give the provider your `agent_id` (in
the report) and your receiver socket path (default
`<STATE_DIR>/rail-receiver.sock`) so it can list you as a peer.

Spending policy, in TOS: `--max-per-purchase` (default 2), `--max-in-window`
(default 10), `--window-seconds` (default 86400), `--max-open-purchases`
(default 4), `--refund-reserve` (default 0.3, kept for the refund
transactions) and `--confirm-above` (no default: unset, nothing asks before
paying). `--allow-provider` is repeatable. Running `init` again with
`--allow-provider` rebuilds the whole buyer section from the flags of that
run: a policy flag you leave out returns to its default, and an omitted
`--confirm-above` removes the threshold without a warning.

A Gateway is optional: `--gateway-url`, `--gateway-token-file`,
`--gateway-ca-file` and `--caller-id` are needed only to buy without an offer
file.

### 5.3 Serve and buy

**`buy` has no preview step and by default pays immediately.** It asks first
only for a purchase that commits more than the `--confirm-above` you gave
`init` (section 3.2); then pass `--yes`, or answer `y` at the
`Confirm this purchase [y/N]:` prompt (anything else declines).

```sh
openfox earning service serve --rail-config <RAIL_CONFIG>      # keep running
openfox earning service buy --rail-config <RAIL_CONFIG> \
  --offer <OFFER_FILE> --source <SOURCE_ARCHIVE>
openfox earning service purchases --rail-config <RAIL_CONFIG>
```

`buy` uses exactly one Quote source: `--offer`, `--quote-package <FILE>` (a
package obtained out of band) or, with neither, the configured Gateway.
**With `--offer` no Gateway is needed:** the Quote Proposal package is built
locally from the offer file and finalized state. `--capability-id` and
`--version` may be given only if they agree with the file. The source archive
is at most 1 MiB. `--source` and `--offer` must be absolute paths.

`buy` verifies the offer at a finalized checkpoint, refuses oversize input
before anything is reserved or paid, shows the costs, applies your policy and
sends one `call` with the quoted terms hash; terms the provider changed
afterwards are refused on chain.

`serve` is a separate process and must be running for delivery. It delivers
the task once the call is admitted, accepts a result only if its Receipt
hashes to the finalized attested response and binds your own request, price
and provider and the artifact matches every digest the Receipt states, and
acknowledges it. If the provider does not answer in time it sends `expire`
and `claim_refund` itself.

`purchases` shows each purchase's `phase` (for example `called`, then
`completed`), `status`, deadlines and costs.

**A failed `buy` may already have paid.** Every `buy` is a new purchase;
nothing deduplicates a repeat. After any non-zero exit run `purchases`:

- No new entry, or a new entry with `phase: not-called`: nothing was sent.
  Repeat the `buy`.
- A new entry with `phase: called` (it carries `failure`): the call may be on
  its way. Do **not** repeat. Keep `serve` running until the entry shows a
  `status` or the phase `refused`. Until then it holds its budget and one
  open-purchase slot.

### 5.4 Where the result lands

An accepted artifact is stored at
`<STATE_DIR>/purchases/<REQUEST_HASH>/artifact.tar`; the request hash is in
the `buy` and `purchases` reports. **Not yet implemented:** a command that
prints that path or exports the file. Copy it out yourself.

### 5.5 The outcomes

| `status` | Meaning | What to do |
|---|---|---|
| `pending` | waiting for the provider | nothing; check again |
| `responded` | settled; `response_hash` is the attested Receipt hash | check the delivered result against it |
| `overdue` | response deadline passed, no response | send `expire`, then `claim-refund`, before the refund-claim deadline |
| `refundable` | `expire` is final | send `claim-refund` before the refund-claim deadline |
| `lapsed` | refund-claim deadline passed | nothing to claim; a sweep returns the price to you |
| `refunded`, `swept` | price returned | nothing |

OpenFox `serve` sends `expire` and `claim_refund` for you. The response
window and the refund-claim window are each at least one hour, so a refund
cannot start earlier than one hour after the call. The same steps with
`tosctl` are in [section 6.1](#61-buyer-tos-service-buyer-and-tosctl).

## 6. Manual and advanced paths

These are the individual `tosctl`, `tos-service-buyer`,
`tos-service-provider-publish` and `software-work-execute` commands. Use them
to inspect what OpenFox did, to recover by hand, to publish through a
Gateway, or to build your own runtime. The local M1 run exercised these
commands, not OpenFox.

### 6.1 Buyer: tos-service-buyer and tosctl

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
  prints them base64-encoded in `canonical_cbor`). `tos-service-discovery`
  reads its bearer token only from the `TOS_SERVICE_TOKEN` environment
  variable, for example `export TOS_SERVICE_TOKEN="$(cat <TOKEN_FILE>)"`.
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
   requests one from a Gateway. OpenFox `buy` obtains one from a Gateway, or
   with `--offer` builds one locally inside its own purchase (section 5.3); it
   does not write a package for `tos-service-buyer`. The local script uses
   the `service-actor-e2e-fixture quote` stand-in.

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

**Refund and sweep with `tosctl`** (statuses as in
[section 5.5](#55-the-outcomes)):

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

**Crash recovery.**
The buyer journal (`<state-dir>/journal`) records every call before custody
starts. A call interrupted between recording and a confirmed submission is
marked `ambiguous` and is **never sent again**. Run `status` with the same
`--request-hash`. It reads finalized history at one checkpoint and reports one
of these:

- **admitted** (`phase` `admitted`, `found` true): the call landed and created
  a request; continue as above.
- **refused** (`phase` `refused`, `found` true, with `exit_code`): the call
  landed and the actor aborted it; its budget reservation is released.
- **not found yet** (`found` false): no matching call is in finalized history
  *at that checkpoint*.

> **"Not found" is not final.** The call may still finalize later. Keep
> running `status`, and **never prepare a new call for the same purchase**
> while the old one is unresolved, or you may pay twice. The old call keeps
> its budget reservation until it resolves.

Back up the state directory; it holds the only record of your outstanding
calls.

### 6.2 Provider: publish by hand with tosctl

`openfox earning service offer` does all of this section in one restartable
command (section 4.3). Do it by hand only if you need a step OpenFox does not
offer, such as a Gateway catalog listing.

**Identity and controller keys.**

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

**Deploy the Service Actor with an attestor.**

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
- The metadata hash is set later (below), once the Capability exists.
- `openfox earning service preflight` (section 4.5) later checks that the
  actor is active, runs the pinned release code and has the manifest's
  attestor.

**Build the manifest.**

```sh
openfox earning service manifest --provider-agent agent_<HEX> --actor 0:<ACTOR_HEX> \
  --code-hash tvm-cell-sha256:<HEX> --attestor mldsa44:<ATTESTOR_KEY_ID> \
  --version 1.0.0 --retention-seconds 86400 --out-dir <ABSOLUTE_DIR>
```

It writes `<digest hex>.cbor` and prints `manifest_digest` and the next steps.
It has no chain effect. The manifest is immutable once published; check it
first.

**Publish the Capability.** There are two manual routes.

**Direct with tosctl** (the route the local M1 run validated):

```sh
tosctl agent native-registry action --global-config <GLOBAL_CONFIG> \
  --network-label <NETWORK_LABEL> --kind register-capability \
  --agent <AGENT_ADDRESS> --nonce <64_HEX> --object-nonce <64_HEX> \
  --version 1.0.0 --manifest <MANIFEST_DIGEST_HEX> --signer <PROVIDER_CONTROLLER>
tosctl wallet send --from <OWNER_WALLET> --to <DESTINATION> --amount 2 \
  --body-boc <BODY_BOC> --yes
```

`--manifest` takes the 64-character hex digest **without** the `sha256:`
prefix that `openfox earning service manifest` prints; strip it.

Read `final_target` from the action output, then
`tosctl agent native-registry show ... --address <FINAL_TARGET>` until it is
registered; the Capability id is `cap_<object_id>`. To list the manifest in a
Gateway catalog:

```sh
export TOS_SERVICE_TOKEN="$(cat <TOKEN_FILE>)"   # the only way it takes the token
tos-service-discovery publish --gateway <URL> --caller-id <ID> \
  --capability-id cap_<HEX> --manifest-cbor <ABSOLUTE_PATH_TO_MANIFEST_CBOR> \
  --idempotency-key <KEY>
```

`--manifest-cbor` must be an absolute, clean path.

**Journaled through a Gateway** with `tos-service-provider-publish`
(restartable at every phase). It takes the manifest as reviewed software-work
manifest JSON (see [Software Work Manifest V1](SOFTWARE_WORK_MANIFEST_V1.md))
and needs a Gateway and its relay token. `openfox earning service offer`
publishes without any hand-written file, but not through a Gateway. For this
route, `openfox earning service manifest` writes only canonical CBOR and
**converting it to JSON is not yet implemented**, so write the JSON by hand
from the same fields and compare the digest that `prepare` reports with the
one OpenFox printed.

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

`tosctl` requires every policy field shown above (price, storage fee, bounty,
SLA, refund window, active flag, rate limit, metadata hash and proof scheme
hash) and refuses the command if one is missing. Also pass the access setting,
`--open-access` or `--authorized-caller <ADDRESS>`: it is the one optional part,
and leaving it out changes who may call the actor.
`openfox earning service metadata` prints `metadata_hash` only. The
software-work proof scheme hash is a fixed constant
(`ServiceActorSoftwareWorkProofScheme` in `tos-service-protocol`
`pkg/nativecore`), the SHA-256 of a fixed string; no command prints it, so
compute it:

```sh
printf %s 'tos.service.service-actor.receipt.software-work-v1' | sha256sum | cut -d' ' -f1
```

Pass only the 64-character hex, not the trailing `-` that `sha256sum` prints.

Buyers who use a Gateway get Quotes from the Gateway's provider Quote profile
(`TOS_SERVICE_PROVIDER_QUOTE_PROFILE_FILE`, example in
`tos-service-gateway/docs/provider-quote-profile.example.json`). For buyers
who use OpenFox, set that profile's `transport` block (in the Gateway's
profile file, not in the OpenFox rail configuration) to `security_mode` `2`,
`base_url` `agent-packet:<PROVIDER_AGENT_ID>` and `max_request_bytes`
`1048576`.

After a manual publication, write the provider section of the rail
configuration by hand (fields in the
[OpenFox rail guide](https://github.com/tosnetwork/openfox/blob/main/docs/guides/service-actor-rail.md#configuration):
`capability_id`, `version`, `manifest_file`, `attestor_controller`,
`respond_budget_seconds` and `executor_socket`; or, for the legacy mode,
`executor_binary`, `executor_sha256`, `containerd_socket` and `fifo_dir`
instead of `executor_socket`), then continue at section 4.5.

### 6.3 Provider: execute and respond without OpenFox

**Standalone paid command** (tos-ai), run as root against the private daemon.
Do not run it beside OpenFox `serve` for the same actor. Its rail config is
described in the tos-ai README:

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

**Respond.** Respond only when the command reports `completed` and
`respond_check` is `passed`, and only after the attestor has checked the
Receipt against the finalized request:

```sh
tosctl agent service send --operation respond --address <ACTOR> --from <OWNER_WALLET> \
  --request-id <ID> --response-hash <RESPONSE_HASH> \
  --attestor-controller <ATTESTOR_CONTROLLER> --yes
```

`tosctl` signs whatever hash you give it. **Not yet implemented as a
production command:** the standalone attestor Receipt check. OpenFox does it
in process; the local script uses the `service-actor-e2e-fixture
receipt-check` stand-in.

### 6.4 Provider: withdraw with tosctl

```sh
tosctl agent service send --operation withdraw-revenue --address <ACTOR> \
  --from <OWNER_WALLET> --withdraw-amount <TOS> --yes
```

Like `claim-refund` and `sweep-expired-request`, `withdraw-revenue` attaches
0.2 TOS by default to pay its own fees; the unused part comes back as change.
Then check the wallet balance yourself. A withdrawal sent this way is not
recorded by OpenFox: `status` lists only withdrawals made with
`openfox earning service withdraw` (section 4.9), and neither path verifies
the wallet credit.

## 7. Troubleshooting

OpenFox front door:

| Symptom | Cause | Fix |
|---|---|---|
| `nothing was signed or sent; review the preview and re-run with --yes`, non-zero exit | `init`, `offer` or `withdraw` without `--yes` | expected; read the preview, then add `--yes` |
| `init` reports `transport: missing`; `serve`, `buy` or `preflight` refuse with `the rail node has no packet transport` | the node was established without a transport | run `init` again with `--direct-peer` or `--messenger-socket`; it sends nothing |
| `the outcome of a sent message is not yet established` | an earlier run sent a message that is not in finalized state yet | wait and run the same command again; never switch to a new state directory to "retry" |
| `another init, offer or withdraw run is in progress` | a second setup or withdraw run in the same state directory | wait for the first; the lock is released when its process ends |
| `finalized state is unavailable`, `quorum not reached`, `no finalized checkpoint` | too few endpoints answered in time | run `init`, `offer`, `withdraw`, `preflight` or `status` again. A running `serve` logs it and retries on its next round |
| `buy` exits non-zero, for any reason | it may have failed before or after the `call` was sent | never repeat it blindly: run `purchases` and follow the rule in section 5.3 (repeat only with no new entry or `phase: not-called`; with `phase: called` keep `serve` running and wait) |
| `buy` prints `Confirm this purchase [y/N]:`, or ends with `the owner declined the purchase` in a script | the purchase commits more than `--confirm-above` and standard input gave no `y` | pass `--yes` once you have checked the costs |
| `the owner wallet's type is not supported` | the wallet is not V3R2, V4R2 or V5R1, or `tosctl` did not report its type | use a wallet of an accepted type (section 3.4); nothing was sent |
| `init` or `offer` stops naming a wallet address and an amount | the wallet is missing, not active or short | fund and activate it with `tosctl` (section 2), then run the command again |
| `the tosctl configuration is under a directory another user can modify` | `tosctl` run as root refuses such a configuration | put the node's files under directories whose every ancestor is owned by the user running OpenFox or by root |
| `the tosctl binary changed since it was pinned` (likewise the executor in the legacy mode) | the binary was replaced after `init` or `offer` pinned it | verify the new binary, then pass its digest with `--tosctl-sha256` or `--executor-sha256` |
| `an input that determines an on-chain identity changed after a step was sent` | `init` or `offer` re-run with another network, controller or terms | restore the original inputs; change terms with `update-policy` (section 4.10) |
| `preflight`: `executor.service` says the user is a member of the group in the group database but the process does not carry it | the user was added to the socket's group after this login session began | log in again, or run the command with `sg tos-executor -c '…'` |
| `preflight`: `executor.service` says the service refuses this user | the service admits one uid, and it is another | set `TOS_EXECUTOR_ALLOWED_UID` to this user's uid and restart the service (section 4.1) |
| `preflight`: `executor.service` says the socket is not served by root | another process listens at that path | point `--executor-socket` (or `executor_socket`) at the root-run executor service's socket |
| `preflight`: `executor.service` or `executor.image` reports the service not ready | the private runtime is down, or the pinned image is not imported and unpacked in it | start the runtime and import and tag the image (section 4.1); a job sent now is refused with nothing claimed |
| `serve` logs `executor not ready` every round | the executor service cannot run work now | nothing was admitted or spent; fix the service. A task waits at most one hour (less if the inbox's held-task bound is reached), then is retired with a logged reason |
| `preflight`: `process.user` fails | the node runs as root with the executor service | run the node as the ordinary user the service allows |
| `preflight`: `containerd.socket` fails as a non-root user although the daemon runs (legacy mode) | a socket in a root-only directory reads as missing to any other user | use the executor service (section 3.8) |
| `preflight`: `process.user` is `warn` (legacy mode) | the node runs as root | expected in the legacy mode with a root-only runtime; use the executor service |
| `preflight`: `transport.peers` is `warn` | a direct peer's receiver socket is absent | start `serve` on that node first |
| `the direct peer socket is missing, a symbolic link, not a socket, owned by another user ...` or `the direct peer's receiver runs as another user` | the direct transport joins nodes of one user on one host only | run both nodes as the same user with owner-only socket directories, or use the Messenger |
| `no route to the recipient Agent` | the recipient is not a direct peer and no Messenger is configured | add it with `init --direct-peer`, listing every peer |
| `the offer's manifest does not hash to the digest the offer states`, or `the offer file does not match finalized state` | the offer file was altered, or is not the published version | nothing was paid; get the offer file again from the provider |
| the executor fails with `containerd FIFO residue is present` or `containerd FIFO directory is not private` (legacy mode) | the FIFO directory holds leftovers of an earlier run, or others can access it | give `offer` a private, empty `--fifo-dir` |
| a script cannot parse a command's output | the preview and progress are on standard error | parse standard output only; it is exactly one JSON document when it is a pipe or a file |

Runtime, `tosctl` and the manual tools:

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

## 8. Limits and next steps

- No public network today; independent buyers and providers (WP-07) and
  Gates D–G are not done. Inference (WP-08) is locked.
- The OpenFox front door has run end to end only on one host, over the direct
  transport: once in the legacy mode with both nodes as root, and once with
  both nodes as an ordinary user through the executor service. Not covered by
  those runs: the Messenger transport, nodes on different hosts, a refund,
  `withdraw --acknowledge`, a node restart during a run, and more than one
  job at a time on the executor service.
- The Gateway publication route was not part of any local run.
- `buy` has no preview step, unlike `init`, `offer` and `withdraw`; it pays
  at once unless `--confirm-above` is set, and the live run always passed
  `--yes`.
- Re-running `init` with `--allow-provider` drops a previously set
  `--confirm-above` unless it is restated.
- No command closes a purchase whose call never landed: it stays `called`
  and holds its budget and its open-purchase slot indefinitely.
- Read next:
  - [AI Service Provider Requirements V1](AI_SERVICE_PROVIDER_REQUIREMENTS_V1.md)
  - [Implementation Status](AI_SERVICE_PROVIDER_IMPLEMENTATION_STATUS.md)
  - Local evidence:
    [OpenFox provider as an ordinary user](../deployments/local-openfox-unprivileged-provider-20261115.json),
    [OpenFox front door (legacy mode)](../deployments/local-openfox-front-door-20261115.json),
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
