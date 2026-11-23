# MCP Provider Adapter V1

## Status and scope

**Status:** implemented; accepted locally on 2026-11-23
(`deployments/local-agent-operated-provider-run-20261123.json`) with one
developer account under the owner's waiver in section 12; not Gate D
evidence. The library prerequisites of
section 13, the provider agent (`tos-service-provider agent`, package
`provider/pkg/provideragent`), the confirmer (`tos-service-provider
confirm`) and the MCP server `tos-service-provider-mcp` (package
`provider/pkg/mcpprovider`) are implemented, with the tests of 10.1; the
user guide is [`MCP_PROVIDER_GUIDE.md`](MCP_PROVIDER_GUIDE.md). The run's
driver is `protocol/e2e/provider-mcp-acceptance/`. It is the
selling-side counterpart of
[`MCP_BUYER_ADAPTER_V1.md`](MCP_BUYER_ADAPTER_V1.md) ("the buyer spec"
below), and it is written against ai main at merge `57b1a448` and the
provider program `provider/cmd/tos-service-provider` (ai #126).

**Purpose.** A developer who works in an MCP client (Claude Code, Codex or
any other MCP host that starts stdio servers) can **operate** a TOS provider
node from that client without installing OpenFox: see whether the node is
ready, publish its offer, pause and resume admission, read its requests and
revenue, hand its offer file to buyers and withdraw its revenue. Every step
that commits the owner to something new or moves funds needs a human
confirmation on the custody side. With the buyer adapter, it lets agents of
those clients both buy and sell using only the `ai` repository.

**What the adapter does not change.** The sold work is fixed: the one
commerce profile is fixed-price software work through a Service Actor
contract ([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md),
[`SERVICE_ACTOR_SETTLEMENT_DESIGN.md`](SERVICE_ACTOR_SETTLEMENT_DESIGN.md)).
The work is a frozen, digest-pinned container job run by `execution/`'s
executor service with no network
([`SOFTWARE_WORK_EXECUTION_V1.md`](SOFTWARE_WORK_EXECUTION_V1.md)); its
manifest is the one `servicebridge.BuildManifest` builds
(`provider/pkg/servicebridge/manifest.go:60`), and the provider's attestor
signs a Receipt that binds the toolchain and sandbox digests
([`SOFTWARE_WORK_RECEIPT_TVM_V1.md`](SOFTWARE_WORK_RECEIPT_TVM_V1.md)). The
model operates the node. It never does the paid work, never chooses what
runs, and never sees a task's source.

**Normative inputs.** This design adds no protocol object, frame, contract
message or authority, and no wire field. It composes the documents the
buyer spec lists under "Normative inputs", the provider program's command
contract (`provider/README.md`, "Output and exit codes" and "Custody"), and
the retry dispositions of [`PUBLIC_ERRORS_V1.md`](PUBLIC_ERRORS_V1.md).
Where this document and one of these conflict, they govern.

**Reused definitions.** Where this document says "as the buyer spec", the
rule of that section applies with `buyer` read as `provider` and the buyer
agent read as the provider agent of 2.1. That covers the stdio transport
(buyer spec 2.2), the socket's directory and peer-credential rules (2.3),
the common tool rules (4.1), the confirmer's channel and terminal checks
(5.1), its rendering rules (5.2), elicitation (5.4) and the untrusted-content
rules (section 9).

**Reused code.** `provider/pkg/servicebridge` (the rail node library, its
setup, offer, preflight, status, pause and withdrawal functions, and the
serving node `OpenNode` with `Service.Run`), the MCP layer pattern of
`protocol/pkg/mcpbuyer` over `github.com/modelcontextprotocol/go-sdk`
v1.7.0, and the socket, role and confirmer pattern of
`protocol/pkg/buyeragent` (`server.go`, `peer_linux.go`, `confirm.go`).

Key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

### Non-goals

- **An LLM as the worker.** Work done by a model (a prompt in, an answer
  out) is a different commerce profile: it has no frozen toolchain digest, no
  deterministic sandbox and no Receipt that binds what ran. It needs its own
  manifest profile, Receipt statement and settlement review, and so a new
  commerce profile behind the locked expansion gate (`ROADMAP.md` section 8,
  "Expansion gate"). This adapter does not move toward it: no tool takes a
  prompt, returns a task's source, or lets the model influence an outcome.
- **Publishing arbitrary images or commands.** The manifest, toolchain and
  sandbox digests are those the library builds. No tool takes an image, a
  digest, a command line, an executor path or a manifest.
- **Changing the terms of a published actor.** The program has no
  `update-policy` verb (`provider/README.md`, "Custody"); a terms change is
  done by the owner with `tosctl` and is out of V1 (decision P6, section 12).
- **Chat** or any Messenger lane: a rail configuration with a `chat` section
  or `messenger_socket` is refused, as the program refuses it.
- **Acting for several providers.** One provider agent serves one rail
  configuration, one provider Agent and one Capability. Operating several
  nodes takes several agents, sockets and MCP server entries.
- **Buying.** A rail configuration with a `buyer` section is refused (2.4);
  buying is the buyer adapter's job.
- **Running `init`** through MCP (3.1), an HTTP binding, MCP resources,
  prompts, sampling and task augmentation.

## 1. Principles

1. **The model never holds signing authority.** Nothing an MCP client, a
   model, a tool argument or a tool result says can make the node sign or
   send a transaction that the node would not sign or send on its own under
   2.5. A new commitment or a value transfer happens only after a human
   confirms it on a channel the model's tool environment cannot read or
   drive (section 5).
2. **Custody never passes through MCP.** The `tosctl` vault credential, the
   wallet, the packet controller, the attestor controller, the relay
   decryption keys, the rail configuration and every journal stay in the
   custody account. The process the MCP client starts holds none of them.
3. **Finalized state is the only authority.** The node already admits,
   responds and withdraws only against quorum-finalized state; the adapter
   adds no shortcut and reports chain facts with the checkpoint they were
   read at.
4. **Buyer- and relay-supplied bytes are data.** Task headers, buyer card
   fields, relay answers and error text from those parties are never
   instructions (section 9).
5. **The adapter owns almost no state.** The node's own journals stay the
   record of everything; the adapter adds only the three records of section 8.
6. **Serving does not depend on the MCP session.** The provider agent runs
   the node's duties whether or not a client is connected.
7. **No OpenFox dependency.** Everything runs from `ai` binaries, `tosctl`
   and the public specification.

## 2. Components, transport and custody

### 2.1 Components

| Component | Runs as | Holds | Role |
|---|---|---|---|
| `tos-service-provider-mcp` (MCP server) | the developer's OS account, started by the MCP client | nothing secret; write access to its export directory | MCP tools; renders results; writes the offer file it is asked to export |
| `tos-service-provider agent` (provider agent) | a separate **custody account** | the rail configuration, the state directory with every node journal, the vault credential (environment only), the agent configuration, the action and pause-origin records of section 8 | runs the node (as `serve` does); serves the socket; prepares and applies confirmable actions |
| `tos-service-provider confirm` (confirmer) | the custody account, in a terminal the human opens | nothing beyond the agent's socket | shows pending actions; takes the human's decision |
| `tos-service-provider` verbs | the custody account, by the human | as the program today | `init`, `withdraw --acknowledge`, recovery |
| `tosctl` | invoked by the node, pinned by SHA-256 | the keys | signs and submits |
| executor service (`software-work-executord`) | root, as installed from `execution/deploy/provider/` | the container runtime | runs the frozen job |

`agent` and `confirm` are new verbs of `provider/cmd/tos-service-provider`;
the MCP server is a separate binary so that the code the model can reach has
no custody path. As in the buyer spec, the MCP server MUST NOT import
`servicebridge`'s setup, offer, withdrawal or node packages; it speaks only
the socket API.

### 2.2 MCP transport

As the buyer spec 2.2: stdio only, JSON-RPC on stdin and stdout, diagnostics
on stderr, no listener. Section 4.1 lists what the tool definitions use so
that both Claude Code and Codex run them.

### 2.3 Agent socket and roles

The socket, its directory (setgid `2750`, group shared with the developer
account, socket `0660`), the `SO_PEERCRED` role decision, the strict JSON
request of at most 2 MiB and the per-role connection limits (12 client, 4
custody) are those of the buyer spec 2.3. The schema is
`tos.service.mcp-provider.agent-api.v1`, local between binaries of one
release.

| Peer uid | Allowed methods |
|---|---|
| the custody account | everything, including `pending`, `present`, `decide` (section 5) and the unredacted views of 4.3 |
| the configured client uid | `status`, `records`, `preflight`, `offer_describe`, `export_offer`, `pause`, `resume`, `offer_preview`, `withdraw_preview`, `request_confirmation`, `actions`, `cancel` |
| any other | refused before the request is read |

**The agent trusts nothing the MCP server checked.** It re-validates every
client request: every identifier, enum, bound and amount of 4.4 to 4.13; the
idempotency key's syntax and its binding to the action's inputs; that a named
`action_id` is in its own action store and in a phase the request may act
on; and every rate bound of 4.2. The agent refuses to start when the client
uid equals its own, when the client uid is 0, when its state directory, rail
configuration, agent configuration or `tosctl` configuration is readable or
writable by group or others, or when its configuration names no client uid.

The MCP server refuses to start when its effective uid is the custody
account (the owner of the socket at `--agent-socket`), when `VAULT_URL` (or
the rail configuration's `vault_url_env`, named with `--vault-url-env`) is
set in its environment, or when it can open the path named by
`--rail-config` or by `--agent-state-dir`. That check opens only the named
paths: a path whose open fails for lack of permission passes, and a path
that does not exist under a directory the developer account can search is
refused as one that cannot be checked. A wrong path under a directory the
developer account cannot search (for example a mistyped name under the
custody account's `0750` home) therefore passes, since its open fails for
permission like the real one's. The check catches a custody directory or
file left open to the developer account; it does not prove that the paths
are the agent's. The real guard is the agent side: the agent's own start-up
checks above (its state directory, rail configuration, agent configuration
and `tosctl` configuration private to the custody account) and the OS
account boundary between the two accounts. The confirmer, conversely, refuses a socket path that is not a socket owned by
its own uid. Custody and the peer-credential check are Linux interfaces, so
V1 runs on Linux.

### 2.4 `tos-service-provider agent`

`tos-service-provider agent --config <file>` runs in the custody account.
The configuration (schema `tos.service.mcp-provider.agent-config.v1`) is a
custody-owned regular file of mode `0600` or stricter, decoded strictly
(unknown fields, duplicate keys and trailing data refused). It names:

- the rail configuration file (the one `init` wrote) and the socket
  directory, and the client uid;
- the agent's own state directory for the records of section 8, which MUST
  NOT be the rail configuration's `state_dir` or lie inside it;
- the **operator offer inputs** the model can never supply (4.9): the
  executor (`executor_socket`, or the subprocess executor with its pin), the
  deploy funding, the respond budget, the offer file and gateway card paths,
  and `test_profile_actor`;
- the **offer bounds** a previewed offer must lie in (4.9): lowest and
  highest price, highest storage fee and cleanup bounty, the allowed range
  of response SLA and refund claim window, and the allowed range of
  `retention_seconds` (within 3,600 to 2,592,000), each inside the
  contract's and the manifest profile's own bounds (`ActorTerms.ValidateFor`,
  `provider/pkg/servicebridge/setup_tosctl.go:430`);
- the **autonomous bounds** of 2.5: `max_admissions_per_day` (default 50)
  and `min_wallet_nanotos`, the owner wallet balance below which admission
  pauses (default 2 TOS);
- the withdrawal bound `max_withdraw_previews_per_day` (default 8).

It refuses a rail configuration that has a `buyer` section, a `chat` section
or `messenger_socket`, or whose `state_dir` is not an owner-private directory
of the custody account. A rail configuration without a provider section is
accepted: it is a node `init` set up whose offer the agent is to publish
(3.1, step 4). Until a confirmed offer writes the provider section, the
agent serves no node but holds the node's serve lock, so `serve` and a second
agent are refused from its start; once the section exists it releases the
lock and opens the node in its place (`OpenNode` takes the lock again).
Methods that need the offer answer `MCP_PROVIDER_NOT_OFFERED` until then.

Running, it:

1. takes an **exclusive serve lock** on the rail configuration's
   `state_dir`. The library has no serve lock today (`setup_lock.go`: `serve`
   takes none); section 13 adds one, and `tos-service-provider serve` takes
   the same lock, so a node is never served twice. `init`, `offer` and
   `withdraw` keep their own run lock (`lockSetup`), which the agent takes
   around each confirmed action (6.3);
2. opens the node exactly as `serve` does (`servicebridge.OpenNode`, the
   receiver socket `OpenAgentPacketUnixServer`, `RelayCarrier.Run`,
   `Service.Run` at the 5-second service interval;
   `provider/cmd/tos-service-provider/node.go`), with the same reporting of
   serving problems, now also kept in a bounded in-memory ring (last 256
   lines, redacted under 4.3) that `status` shows;
3. serves the socket, and runs the bound checks of 2.5 once per service
   interval.

A socket failure stops the agent; the node stops with it, and work already
admitted resumes from the node's own records on the next start, as after a
`serve` restart.

### 2.5 What the node signs on its own, and within which bounds

The provider agent keeps the program's custody contract
(`provider/README.md`, "Custody") unchanged. Without any human or model
action it signs and sends exactly what `serve` signs and sends:

| Automatic action | Signed by | Only when | Where |
|---|---|---|---|
| Agent Packet signatures of results and acks (frames 5.2, 5.3) | packet controller | for a request the gate admitted, toward that request's buyer only | `PacketSigner` (`transport.go:77`), `Courier.Deliver` (`transport.go:217`), from `Provider.deliver` (`provider.go:757`) |
| relay key cards and successor cards | packet controller | for the node's own relays, rotation by the relay carrier | `RelayKeys.Maintain` and `Current` (`relay_keys.go:361`, `:388`), `RelayCarrier.Run` (`relay_carrier.go:169`) |
| `respond` with the attested `response_hash` | attestor controller, sent from the owner wallet | the request was admitted against finalized state (`provider.go:305`); the execution ended in a successful outcome, and a failed or unknown one is never attested (`provider_service.go:130`); the Receipt built from it is attestable (`provider_service.go:144`, `provider.go:380`); and a fresh finalized check made just before the send shows the request still pending and unchanged with the respond budget ahead (`provider.go:392` before `:402`; `provider.go:745` before `:754`; before every retry `provider.go:682`) | `TOSCTLLifecycle.Respond` (`lifecycle.go:176`) |

It also rewrites, without signing a transaction, the offer file and the
gateway key card file when it issues a successor card
(`ProviderNode.OfferFile`, `GatewayCardFile`, `node.go`). It never
withdraws, never changes the policy and never sends `expire`, `claim_refund`
or a sweep (the configuration has no buyer section).

**Bounds on automatic work.** Admission, and with it every later signature
for a request, is bounded by:

- **Concurrency:** the executor service's `--max-executions` (1 to 8,
  default 1; `execution/pkg/executorservice/server.go:24`). A task the
  executor cannot take now is held, not admitted (`ErrExecutorNotReady`,
  `provider.go:302`). The inbox bounds its assemblies
  (`max_assemblies`, `NodeConfig.MaxAssemblies`).
- **Contract capacity:** `MAX_LIVE_GLOBAL` and `MAX_LIVE_PER_CALLER`
  (100,000 and 1,000; `SERVICE_ACTOR_TVM_V1.md` section 2), enforced by the
  actor at `call`.
- **Pause marker:** while `<state_dir>/admission-paused` exists, or cannot
  be read, nothing new is admitted (`provider.go:293`, `pause.go`). Admitted
  work still executes, responds and delivers, or falls to the buyer's refund
  path. Who wrote the marker, and who may remove it, is decided by 2.6.
- **Daily admissions:** `max_admissions_per_day`. The actor's own
  `rate_limit_per_day` would be the authoritative cap, but `offer` always
  publishes it as 0, unlimited (`setup_offer.go:381`), and the program cannot
  change it. The agent therefore enforces the cap at admission through an
  admission limiter that the library consults right after the pause check
  (`provider.go:293`; library work, section 13). A provider record has no
  admission time today: `ProviderRecord` (`provider.go:51`) carries only
  `updated_unix`, which every later update moves. Section 13 therefore adds
  one field to the record, `admitted_unix`, written once when the record is
  first stored after `Gate.Admit` and never changed. The limiter counts the
  records whose `admitted_unix` lies in the last 86,400 seconds of host time;
  a record without the field (written before the change) counts as admitted
  at its `updated_unix`, which can only over-count. At the cap a task is held
  as if paused and admitted once the count falls; a buyer's resend of a held
  task is held the same way, as during a pause. Provider records that cannot
  be read hold the task too: the count is then unknown, and the limiter fails
  closed. The field is new state in
  the node's own record, owned by the library, not by the adapter.
- **Wallet floor:** when the owner wallet's finalized balance falls below
  `min_wallet_nanotos`, the agent writes an agent pause marker (2.6) with the
  fixed reason `wallet below the configured floor`. Each `respond` is a
  wallet message that pays network fees from that wallet, so a price below
  the respond fee could otherwise drain it. Relay deposits are HTTP
  store-and-forward and cost the wallet nothing. The agent lifts that pause
  by itself once the balance is at or above the floor at a later checkpoint,
  and only by the compare-and-remove of 2.6, so a pause anyone else wrote or
  re-stamped is never lifted. A model's `tos_provider_pause` over the
  floor's own marker leaves the marker unchanged (2.6, "Agent pause") and
  moves the pause-origin record (8.2) of those bytes from `wallet_floor` to
  `model`; from then on the floor never lifts it, and it is lifted only by
  the model's own resume of 4.11, which also requires the floor to be met, or
  by a confirmed resume. Moving the record keeps the model's later stop from
  being dropped silently when the balance recovers, without making the
  model's own pause need a human to lift.

**Residual fee exposure.** The floor is checked once per service interval,
and work already admitted still responds. Below the floor the wallet can
therefore still pay at most `(max_executions + R) × respond_fee`, where `R`
is the number of requests already executed or responding when the floor is
crossed, plus the respond retries the library makes for an ambiguous send
(`provider.go:682`, at most one per minute per request while its window is
open). The floor is set with that margin in mind; the run of 10.2 records the
fee per respond so the margin can be chosen from a measured value.

None of these bounds can be raised through MCP; they change only by editing
the custody-owned configurations (and the executor's flags as root) and
restarting.

### 2.6 Pause origin and removal

The operator must be able to stop admission at any time with the program,
whether or not the agent runs, and a model must never be able to lift that
stop. Today `PauseAdmission` refuses to replace an existing marker and
reports `already_paused` (`pause.go:67`, CLI `node.go:176`), so an operator
pause on top of an agent pause would leave the agent's marker unchanged and
indistinguishable. Section 13 therefore changes the library and the program:

- **Marker origin.** The marker (schema bumped to
  `tos.openfox.rail-admission-pause.v2`) carries `origin`, either `operator`
  or `agent`, and `stamp`, 16 random bytes in hex drawn at each write. A v1
  marker reads as `origin = operator`. A v2 marker with any other `origin`,
  and a marker of a schema the release does not know, reads as unreadable:
  admission stays paused, and only the operator's `resume` or a confirmed
  resume lifts it.
- **Operator pause re-stamps.** `tos-service-provider pause`, and a pause
  the custody uid asks of the agent, always leave an `operator` marker. On a
  marker that is already `operator` it changes nothing, as today. On an
  `agent` marker it replaces the marker atomically with an `operator` marker
  that keeps the first `paused_unix` and draws a new `stamp`. On an
  unreadable marker it refuses and says so; admission stays paused.
- **Agent pause.** The agent writes `origin = agent` only when no marker
  exists; on an existing marker it changes nothing and reports the existing
  origin.
- **Compare-and-remove.** Every removal the agent makes, by a direct resume
  (4.11) or by the wallet-floor lift (2.5), names the exact marker bytes it
  expects and removes the marker only if the file still holds those bytes.
  Pause, re-stamp and removal all run under one exclusive lock file in
  `state_dir`, so a re-stamp between the agent's read and its removal makes
  the removal fail with `MCP_PROVIDER_CONFLICT` and leaves the operator's
  marker in place. As a second safeguard, independent of the pause-origin
  record, the agent's direct removals (the model's resume and the floor
  lift) also decode the expected bytes and refuse any whose `origin` is not
  `agent`, so a record that somehow held an operator marker's bytes still
  could not lift it. Only a confirmed resume, which a human decided, may
  remove an `operator` marker, and only by its confirmed bytes. The
  program's own `resume` stays unconditional: it is the operator's command.

The agent's pause-origin record (8.2) holds the bytes of each marker it
wrote and why (`model` or `wallet_floor`); a marker whose bytes differ from
the record, or whose origin is `operator`, is never removed by the agent
without a confirmed action.

## 3. Setup without OpenFox

### 3.1 `init` stays a custody-side command

`init` establishes the trust roots of a node: the pinned `tosctl`, the
wallet, the endpoints and quorum, the Native Registry code, the actor code
hash, the relays, and the packet controller it creates or adopts. It runs
before the provider agent can exist, since the agent's configuration names
the rail configuration `init` writes. It is therefore not a tool. The human
runs it as the custody account, previewed and then with `--yes`, as
`provider/README.md` shows. With ai #127, `init` without
`--packet-controller` takes the controller from the setup journal first, then
the rail configuration (`servicebridge.RecordedPacketController`); the
adapter relies on that so that an interrupted `init` is continued, not
duplicated.

The guide for this adapter (section 13) states the order:

1. create the custody account and the developer account; install the
   executor service as root;
2. as the custody account: `tos-service-provider init` (preview, then
   `--yes`), and `tos-service-provider preflight` until only the offer checks
   fail;
3. write the agent configuration and start `tos-service-provider agent`
   (a systemd unit of the custody account, or a terminal it keeps open);
4. in the MCP client: `tos_provider_preflight`, then
   `tos_provider_offer_preview` and `tos_provider_request_confirmation`;
   the human confirms in `tos-service-provider confirm` (section 5).

**Permitted custody-side commands.** With the adapter in use, the custody
account runs these program commands and no others as part of normal
operation: `init` (preview and `--yes`); `preflight` after `init` and before
the agent starts; `agent`; `confirm`; `pause` and `resume` as the operator's
own stop and start (2.6); `withdraw --acknowledge`; and `status` for the
operator's own inspection. `offer`, `withdraw` and `serve` are not run by
hand while the agent runs (`serve` would be refused by the serve lock); any
other use is recovery and, in the acceptance run, a CLI-fallback step
(10.2).

### 3.2 Relays and two accounts on one host

Direct peers (`--direct-peer`) deliver only to a receiver socket of the same
host and user. A buyer agent runs under its own custody account, so a buyer
and a provider on one host are carried by an Agent Packet Relay, as on
different hosts. The adapter adds nothing to relay use.

## 4. Tools

### 4.1 Common rules

The rules of the buyer spec 4.1 apply: typed input and output structs,
constant tool metadata with no buyer, relay or chain text in it, inputs
validated before any read, amounts as decimal nanoTOS strings with a TOS
rendering beside them, annotations as below (hints that grant nothing),
`structuredContent` matching the output schema plus one text block that
renders the same content, and the finalized checkpoint named for every
chain-derived value.

**Client compatibility.** The tools MUST work unchanged in Claude Code and
Codex, the two clients of the acceptance run (section 10):

- inputs are JSON Schema objects with `"additionalProperties": false`
  using only `type`, `properties`, `required`, `enum`, `minimum`,
  `maximum`, `minLength`, `maxLength`, `pattern` and `description`; no
  `$ref`, `oneOf`, `anyOf`, `allOf`, `not` or conditional keywords at any
  depth, and no input that is not an object;
- every result's text block carries the whole content, so a client that
  ignores `structuredContent` or `outputSchema` loses nothing;
- no tool depends on progress notifications, elicitation, sampling,
  resources, prompts or list-changed notifications. A progress notification
  MAY be sent where the buyer spec sends one (4.6) and grants nothing;
- every tool returns within 30 seconds except
  `tos_provider_request_confirmation`, whose wait the caller chooses (0 to
  300 seconds, default 45). The buyer's `tos_buyer_request_payment` defaults
  to 120 seconds and its guide sets Codex's `tool_timeout_sec = 330`
  (`MCP_BUYER_GUIDE.md` section 7.2). Here the default is 45 seconds so that
  the tools work with Codex's default `tool_timeout_sec` of 60 seconds and no
  client setting at all: a provider operator confirms rarely (an offer, a
  withdrawal, a resume), so asking again while the answer is
  `awaiting_confirmation` costs little. The provider guide still shows the
  longer timeout for a user who wants longer waits.

**Authority classes.** Every tool is one of:

- **read-only:** no state of the node, the chain or the agent changes;
- **direct bounded action:** the agent acts at once, and the action only
  removes authority or restores authority the model itself removed;
- **request for confirmation:** the agent prepares a preview and stores a
  pending action. Only a custody-uid `decide` (5.3) carries it out.

No tool takes a wallet, a destination, a key or controller name, an
endpoint, a relay URL, a path of the custody account, an executor, a
manifest, a bound of 2.5 or a budget value.

### 4.2 Tool set

| Tool | Class | Annotations | Agent method | Verb or library call |
|---|---|---|---|---|
| `tos_provider_status` | read-only | read-only, idempotent | `status` | `status` = `servicebridge.ReadProviderStatus` with `OpenStatusChain` (`status.go:499`, `:184`) |
| `tos_provider_records` | read-only | read-only, idempotent | `records` | `status --records` = `ReadProviderStatus(...).Requests` |
| `tos_provider_preflight` | read-only | read-only, idempotent | `preflight` | `preflight` = `servicebridge.RunPreflight` (`preflight.go:278`) |
| `tos_provider_offer_describe` | read-only | read-only, idempotent | `offer_describe` | `ReadOfferFile` (`offer_file.go:165`), the manifest file, and the actor read of `status` |
| `tos_provider_export_offer` | read-only (writes only in the developer account) | not read-only, idempotent, not destructive | `export_offer` | `ReadOfferFile`; the MCP server writes the bytes |
| `tos_provider_pause` | direct bounded action | not read-only, idempotent, not destructive | `pause` | `pause` = `servicebridge.PauseAdmission` (`pause.go:67`) |
| `tos_provider_resume` | direct for the model's own pause; otherwise request for confirmation | not read-only, idempotent, not destructive | `resume` | `resume` = `servicebridge.ResumeAdmission` (`pause.go:106`), after `RunPreflight` |
| `tos_provider_offer_preview` | request for confirmation | not read-only, idempotent per key, not destructive | `offer_preview` | `offer` without `--yes` = `servicebridge.RunOffer` with `Yes = false` (`setup_offer.go:551`) |
| `tos_provider_withdraw_preview` | request for confirmation | not read-only, idempotent per key, not destructive | `withdraw_preview` | `withdraw --amount` without `--yes` = `servicebridge.RunWithdraw` with `Yes = false` (`withdraw.go:292`) |
| `tos_provider_request_confirmation` | request for confirmation | not read-only, idempotent, not destructive | `request_confirmation` | none; queues the action for the confirmer and waits |
| `tos_provider_actions` | read-only | read-only, idempotent | `actions` | the agent's action store (8.1) |
| `tos_provider_cancel` | direct bounded action | not read-only, idempotent, not destructive | `cancel` | the agent's action store |

Program verbs with no tool: `init` (3.1); `serve` (the agent runs the node);
`withdraw --acknowledge`, which closes a withdrawal record on the operator's
own judgment of facts finalized state cannot decide (`withdraw.go:520`) and
stays a custody-side command; `manifest` and `metadata`, whose by-hand use
`offer` already covers.

**Rate bounds.** The agent serves per minute at most 30 `status` and
`records`, 20 `offer_describe` and `export_offer`, 6 `preflight` (each runs
quorum reads and a `tosctl` controller probe), 10 `pause` and `resume`, and
10 `offer_preview` and `withdraw_preview` together; and per day at most
`max_withdraw_previews_per_day` withdrawal previews. Over a bound it refuses
with `MCP_PROVIDER_RATE_LIMITED` before reading anything. A request refused
for its input does not count. The bounds apply to the client uid; the
custody uid is the operator and is not bounded.

### 4.3 Redaction

Every answer to the client uid is redacted by the agent before it leaves the
socket. The MCP server applies the same rules again to anything it renders.

- **Endpoints.** An RPC endpoint is shown only as `rpc_endpoints[i]`, as the
  library already redacts every spelling of it in error text
  (`redactEndpoints`, `redact.go:17`), and a preflight endpoint check names
  it as `host:port` (`endpointHost`, `preflight.go:780`); the agent keeps
  both forms and adds no other. A relay URL is public, since it is printed
  in the node's signed key card. It is shown as the card shows it, except
  that a URL with user information, a query or a fragment is shown as
  `relay_urls[i]`.
- **Custody paths.** Every path of the custody account (`state_dir`, the
  rail configuration, the receiver and executor sockets, the manifest, offer
  and gateway card files, the `tosctl` binary and configuration, the
  registry code file, the relay CA copy) is replaced by its configuration key
  in angle brackets, for example `<state_dir>`, longest path first. The
  library's messages quote some of them (for example the `state_dir.private`
  checks, `preflight.go:415`).
- **Never shown:** the vault URL or its environment variable's value, any
  key material or signature, a relay decryption key, a gateway or relay
  token, the agent configuration, and the confirmation nonce or code (5.3).
- **Large and buyer-supplied fields.** From a provider record
  (`ProviderRecord`, `provider.go:51`), `package_base64` and
  `receipt_boc_base64` are dropped and replaced by their SHA-256 and length.
  The digests, the request identity, the buyer Agent and wallet (public
  chain facts), the deadlines and the state stay. `detail` and every other
  free-text field that can quote a buyer, relay or `tosctl` message is an
  `untrusted_*` field under section 9, after the path and endpoint rules.
- **Custody view.** The custody uid receives the same views unredacted, so
  the confirmer and the operator see what the node sees.

### 4.4 `tos_provider_status`

Input: none. Output: the `ProviderStatus` report (schema and version as
`servicebridge.ProviderStatusSchema`), redacted, with `requests` replaced by
counts per operator state (the list is `tos_provider_records`): the admission
state (paused, since when, the reason as untrusted text, and whether the
agent recorded the pause as the model's or its own, 8.2); the actor's
finalized accounting at its checkpoint (active, pending and live counts,
balance, credited revenue, liabilities, locked storage fees, and the
library's note that credited revenue is not money in a wallet); the
withdrawals; the relay delivery report; the autonomous bounds of 2.5 with
today's admission count and the wallet's finalized balance against the
floor; whether the node is serving, and the last 16 lines of the serving
report ring. A failed chain read is reported in `actor.error` as the program
does and is not a tool error.

### 4.5 `tos_provider_records`

Input: optional `operator_state` (one of the library's operator states),
`page_size` (1 to 100, default 20), optional `page_token`. Output: one
redacted record per request (4.3), newest first, and `next_page_token`. The
agent caps one answer at 256 KiB and shortens the page to fit.

### 4.6 `tos_provider_preflight`

Input: none. Runs `RunPreflight` on the rail configuration with the agent's
environment. Output: the `PreflightReport` (`ok`, `admission_paused`, and
every check's `id`, `status` and redacted `message`). A failed check is a
result with `ok = false`, not a tool error, as exit code 3 is a report in the
program.

### 4.7 `tos_provider_offer_describe`

Input: none. Output, read from the offer file the node keeps and checked
against finalized state at one checkpoint: the Capability ID and version,
provider Agent, actor, manifest digest, toolchain digest, the manifest's
limits and `retention_seconds`, the attestor key ID, the finalized policy
(price, storage fee, cleanup bounty, response SLA, refund claim window,
`policy_version`, `terms_hash`, active, open access), the offer file's
SHA-256 and the validity window of the key card it carries. The manifest's
`name` and `description` are returned as untrusted text, although the
library writes them, since a manifest file is read from disk. Before an offer
exists it answers `MCP_PROVIDER_NOT_OFFERED`.

### 4.8 `tos_provider_export_offer`

Input: none. The agent returns the offer file's bytes (schema
`tos.openfox.rail-offer.v2`, at most 256 KiB) and its SHA-256, after the
checks of 4.7. The MCP server writes them to
`<export_dir>/offer-<capability_id>-<version>.json` under the same file rules
as the buyer's results directory (buyer spec 4.9, "Writing the files"):
`--export-dir` resolved once, not group or world writable, the file created
fresh and linked into place, an existing file kept only if it has the same
bytes. The file is written readable by all, as public data. The server
checks the bytes against the stated length and SHA-256, the 256 KiB bound
and the schema, and refuses a capability ID or version that cannot name a
file (a version is any printable ASCII, so it could hold a path separator). This is how the provider hands the offer to a buyer (buyer spec 4.4,
owner decision O7 there). The offer file is public by design: it carries the
manifest and the provider's key card.

### 4.9 `tos_provider_offer_preview`

Input: `price_nanotos`, `storage_fee_nanotos`, `cleanup_bounty_nanotos`
(decimal strings, each greater than zero and at most 2^64-1),
`response_sla_seconds`, `refund_claim_window_seconds` (integers),
optional `capability_version` (1 to 128 bytes of `0x21` to `0x7e`, default
`1.0.0`), optional `retention_seconds` (default 86,400, the library's
`DefaultRetentionSeconds`), and `idempotency_key` (16 to 64 characters
`[A-Za-z0-9_-]`).

The agent:

1. refuses terms or a retention outside the offer bounds of 2.4 or the
   contract's bounds (`ActorTerms.ValidateFor`) with
   `MCP_PROVIDER_BAD_INPUT`;
2. returns the existing action for a key already used with the same inputs,
   and refuses one used with other inputs (`MCP_PROVIDER_CONFLICT`);
3. refuses with `MCP_PROVIDER_ALREADY_OFFERED` when the setup journal holds a
   finished offer, and with `MCP_PROVIDER_CONFLICT` when it holds an
   unfinished offer under other inputs (the library would refuse it,
   `setup_offer.go:670`). An unfinished offer with the same inputs is
   previewed again, which is how an interrupted offer is finished;
4. builds `OfferInput` from the model's terms plus the operator offer inputs
   of 2.4, and runs `RunOffer` with `Yes = false`, which signs and sends
   nothing (exit 4 in the program);
5. stores the action (8.1) with the inputs, the preview and its digest.

Output: `action_id`, the preview (`OfferPreview`: owner wallet, provider
Agent, actor address, actor code hash, attestor controller and key ID or
"to be created", terms, version, manifest digest, Capability ID and address,
metadata hash, proof scheme hash, deploy funding, the attached value of the
registration and of the policy step, the total attached, what a buyer
attaches per call, and the library's note), the planned steps, the action's
`expires_at_unix` (10 minutes after the preview), the **action reference**
(5.3) and `state = awaiting_confirmation`. Nothing is sent.

### 4.10 `tos_provider_withdraw_preview`

Input: either `amount_nanotos` (greater than zero) or `all = true`, and
`idempotency_key`. Runs `RunWithdraw` with `Yes = false` at one finalized
checkpoint. With `all`, the agent turns the request into the exact credited
amount the preview read, so the human confirms one amount and the send moves
exactly that amount (a later credit stays for a later withdrawal). It
refuses: zero (`MCP_PROVIDER_BAD_INPUT`), more than credited
(`ErrWithdrawOverCredit`) or nothing credited (`ErrNothingToWithdraw`) as
`MCP_PROVIDER_NOTHING_TO_DO`, and an earlier withdrawal that finalized state
has not decided (`ErrWithdrawalPending`) as `MCP_PROVIDER_AMBIGUOUS` with the
record.

Output: `action_id`, the preview (`WithdrawPreview`: actor, destination, which
is always the owner wallet by contract, credited before and after, amount,
attached value, checkpoint and the library's notes), `expires_at_unix` (10
minutes), the action reference and `state = awaiting_confirmation`.

### 4.11 `tos_provider_pause` and `tos_provider_resume`

`tos_provider_pause` input: optional `reason` (one line, at most 200 bytes of
printable ASCII). It writes an `agent` marker (2.6) with the reason
prefixed by `mcp: ` (the marker holds at most 256 bytes, `pause.go:21`) and
records its bytes in the pause-origin record (8.2) as the model's. Pausing a
node that is already paused changes nothing and reports `already_paused`
with the existing origin. Pausing removes authority, so the model may do it
without a human, as the buyer's `withdraw`.

`tos_provider_resume` input: `idempotency_key`. Resuming restores the node's
automatic signing for new requests, so:

- **The model's own pause.** The model resumes directly only when all of
  these hold: the marker on disk is byte for byte the one the pause-origin
  record holds as the model's, with `origin = agent`; the owner wallet's
  finalized balance is at or above `min_wallet_nanotos`; and `RunPreflight`
  passes apart from the admission check itself. The agent then removes the
  marker by compare-and-remove against those bytes (2.6) and deletes the
  origin record. A failing preflight refuses with `MCP_PROVIDER_NOT_READY`
  and the report; a wallet under the floor refuses with
  `MCP_PROVIDER_NOT_READY` and the balance; a marker that changed between
  the check and the removal refuses with `MCP_PROVIDER_CONFLICT` and the
  marker stays.
- **Any other pause.** An `operator` marker (including one the operator
  re-stamped over the model's pause), the agent's wallet-floor marker, a
  marker the agent cannot read, or a marker whose bytes differ from the
  origin record is not resumed by the model. The tool stores a confirmable
  `resume` action (8.1) with the marker's bytes and the preflight report as
  its preview, and returns it with `state = awaiting_confirmation`. A
  wallet-floor marker that the agent will lift by itself once the floor is
  met is reported as such and stores no action.

### 4.12 `tos_provider_request_confirmation`

Input: `action_id`, `wait_seconds` (0 to 300, default 45). As the buyer's
`tos_buyer_request_payment` (buyer spec 4.6): it makes the action visible in
the confirmer's queue and waits up to `wait_seconds` for the human's decision.
A progress notification, when the request carries a token, gives the action
reference and says that the action must be confirmed in the confirmer and
that nothing answered in the client confirms it. No elicitation is sent.

Output: one of `awaiting_confirmation` (call again), `declined`, `expired`
(the preview's lifetime passed, or the re-run preview of 6.2 differed),
`applying`, `applied` with the setup steps or the withdrawal record,
`failed` with the redacted reason, or `ambiguous` with the record to resolve.

### 4.13 `tos_provider_actions` and `tos_provider_cancel`

`tos_provider_actions` input: optional `action_id`, optional state filter,
`page_size` (1 to 50). Output: the actions with kind, inputs, preview
digest, reference, state and timestamps.

`tos_provider_cancel` input: `action_id`. Moves an action still
`awaiting_confirmation` to the terminal `cancelled`; a repeat on an action it
already cancelled answers the same `cancelled` action (7, "Idempotency"), and
any other later state is refused with its current state
(`MCP_PROVIDER_CONFLICT`). Cancelling only
removes authority, so the model may do it without a human. At most 4 actions
await confirmation at once (`MCP_PROVIDER_OVER_LIMIT` beyond), so a model
cannot flood the confirmer.

## 5. Confirmation

### 5.1 Decisions: what needs a human

| Action | Who completes it | Reason |
|---|---|---|
| `init` | the human, with the program, as the custody account | it chooses every trust root (the pinned `tosctl`, wallet, endpoints, registry code, actor code hash, relays) and spends the registration's value; the agent cannot exist before it (3.1) |
| offer (first publication, or finishing an interrupted one) | confirmable; the human in the confirmer | it spends the deploy funding and registration values and publishes the terms every later automatic `respond` is bound by; after it the node earns and signs on its own |
| terms change (`update-policy`) | not in V1; the owner with `tosctl` | the program has no verb; decision P6 |
| withdraw | confirmable; the human in the confirmer | it is a value-carrying wallet send. The destination is fixed to the owner wallet by contract and the risk is bounded, so it could become a direct bounded action later (decision P2); V1 keeps the program's previewed `--yes` boundary |
| `withdraw --acknowledge` | the human, with the program | it closes a record on the operator's own judgment of facts finalized state cannot decide |
| pause | the model, directly | it only removes authority |
| resume of the model's own pause | the model, directly, only with the marker bytes unchanged, the wallet floor met and a passing preflight (4.11) | it restores only what the model itself removed, with no wider authority than before the pause |
| resume of any other pause | confirmable; the human in the confirmer | an operator pause is often a response to something the model cannot see (an executor fault, a key rotation, an incident); a wallet-floor pause protects the wallet |
| packet, key card and `respond` signatures | the node, automatically, under 2.5 | the program's custody contract; each is bound to a finalized admitted request and a successful attested outcome |
| cancelling a pending action | the model, directly | it only removes authority |

The model may REQUEST every confirmable action, by preparing its preview. It
can never complete one.

### 5.2 Boundary and confirmer

The boundary is the buyer's (buyer spec 5.1): the OS account boundary, a
confirmer whose terminal input and display MUST NOT pass through any process
of the developer account, the confirmer's terminal-owner and controlling
terminal checks, and the same residual risk (`ssh localhost`, `su --pty` or
`sudo -u` under `use_pty` from the developer's session). A single-account
mode is not offered (as the buyer's O1).

`tos-service-provider confirm` shows, for each action awaiting confirmation,
from the agent's own record and never from text the MCP server supplied, the
two blocks of buyer spec 5.2 under its rendering rules:

- the **untrusted block**: the manifest's `name` and `description` for an
  offer, the pause reason for a resume, under the fixed heading that this is
  text read from files and not from TOS;
- the **protocol block**, after the fixed rule line: the action kind; for an
  offer every `OfferPreview` field, the terms in TOS and nanoTOS, what one
  call pays the provider and what a buyer gets back on no answer
  (buyer spec section 8), and that after confirmation the node responds to
  admitted calls on its own; for a withdrawal the actor, the destination
  (the owner wallet), the amount, the credited revenue before and after, the
  attached value and the checkpoint; for a resume the marker's time and
  origin and the preflight checks; then the action reference, the preview
  digest and, last, the confirmation code.

### 5.3 Code and decision

As buyer spec 5.3, with:

```text
confirmation_digest = SHA-256("tos.service.mcp-provider.confirmation.v1" || 0x00 ||
    confirmation_nonce || network_id || 0x00 || provider_agent_id || 0x00 ||
    owner_wallet || 0x00 || action_kind || 0x00 || action_id || 0x00 ||
    preview_digest)
preview_digest      = SHA-256 of the RFC 8785 canonical JSON of the stored
                      action inputs and preview
action_id           = SHA-256("tos.service.mcp-provider.action.v1" || 0x00 ||
                      action_kind || 0x00 || idempotency_key || 0x00 ||
                      canonical JSON of the inputs), as 64 lowercase hex
action reference    = the first 16 hex digits of action_id in four groups of four
```

The nonce is drawn only on a custody `present`, lives 10 minutes, and never
reaches the client uid; `decide` is accepted only from the custody uid for a
presented action, the code is recomputed from the agent's own records and
compared in constant time, and 3 wrong codes cancel the action.

## 6. Applying a confirmed action

### 6.1 Order

On a matching code the agent, holding its own action lock (8.1) from step 1
to step 5 so that no two actions of the agent interleave:

1. moves the action to `applying` durably (8.1);
2. makes a **fresh library call** with `Yes = false` and the stored inputs,
   and computes the comparison of 6.1.1 itself, from that fresh result and
   its stored record. Nothing the client sent, and no earlier result, takes
   part. A comparison that fails moves the action to `expired` and sends
   nothing;
3. runs the call with `Yes = true` and the same stored inputs: `RunOffer`,
   `RunWithdraw` with the confirmed exact amount (never `all`), or the
   compare-and-remove of 2.6 against the confirmed marker bytes;
4. stores the library's result;
5. moves the action to `applied`, `failed` or `ambiguous` (6.2).

**The setup lock is not held across steps 2 and 3.** `RunOffer` and
`RunWithdraw` each take the state directory's run lock (`lockSetup`,
`setup_lock.go:28`) inside the call and release it when they return, and the
lock does not wait, so the agent cannot hold it around both calls. The gap is
safe for these reasons:

- the `Yes = true` call uses the stored inputs, fixed at preview and bound by
  the confirmation code; nothing in the gap can change what is asked;
- under its own lock the `Yes = true` call re-reads the setup journal or the
  withdrawal records and finalized state, and refuses or resumes exactly as
  a second program run would. An offer step already sent in the gap is never
  sent again, and a withdrawal sent in the gap makes the library report
  `ErrWithdrawalPending` or refuse the amount as over credit;
- a withdrawal's destination is the owner wallet by contract, and its amount
  is the confirmed exact amount, so no interleaving can send value
  elsewhere or send more than was confirmed;
- `offer` and `withdraw` are not run by hand while the agent runs (3.1). A
  hand run in the gap is refused with `ErrSetupBusy` if it overlaps either
  call, and otherwise is caught by the re-read above.
- the agent's own library calls never meet at the run lock: one preview slot
  serializes every client preview and an apply's fresh preview together with
  its send. A client preview waits at most 5 seconds for the slot (and its
  offer preview is bounded to 20 seconds), then is refused with
  `MCP_PROVIDER_CONFLICT`; a confirmed action's apply waits for the slot, so
  a client preview at the same moment can never make its fresh preview fail
  with `ErrSetupBusy` and expire it.

#### 6.1.1 Apply-time comparison

The fresh `Yes = false` result must match the confirmed preview as follows.
Every other field (checkpoint, chain time, generated time) is ignored.

| Kind | Must hold |
|---|---|
| withdraw | `actor`, `destination` and `attached_nanotos` equal to the confirmed preview; `amount_nanotos` equal to the confirmed exact amount; the fresh `credited_revenue_nanotos` at least that amount |
| offer | every `OfferPreview` field (`setup_offer.go:106`) equal to the confirmed preview, except `checkpoint` where present, and the list of planned steps equal |
| resume | the marker file's bytes equal to the confirmed marker bytes, and a fresh `RunPreflight` passes apart from the admission check |

### 6.2 Outcomes and retries

- **Offer.** The setup journal makes `RunOffer` resumable: a re-run never
  sends a step whose effect is finalized and waits on a step marked as
  sending. An offer that stopped part way is `failed` with its steps; the
  model may preview it again (4.9 item 3), and its completion needs a new
  confirmation. A journal marked `stopped` is refused and needs the operator.
- **Withdraw.** A withdrawal whose outcome finalized state has not decided is
  `ambiguous`; the agent never sends another withdrawal while the library
  reports `ErrWithdrawalPending`, and the status shows the record until
  finalized history decides it or the operator acknowledges it with the
  program.
- **Resume.** Removing the marker is local and atomic; it is `applied` or
  `failed`.

## 7. Errors

Domain failures are tool results with `isError: true` and
`structuredContent` `{"error": {"code", "disposition", "message", "state"}}`,
as buyer spec section 12. `message` is fixed server text, redacted under
4.3, and never carries untrusted text. `state` is the action's state when
the refusal is about one (for example a cancel of an applied action), and
empty otherwise; a value the agent attached to the refusal (an action, the
offer's steps, an undecided withdrawal record, a preflight report) is
returned beside it under `result`. A client that does not recognise a code
treats it as `NEVER`. A request the SDK rejects against the input schema
never reaches the agent; go-sdk v1.7.0 answers it with a tool result that
has `isError: true`, its validation text and no `structuredContent`.

| Code | Meaning | Disposition |
|---|---|---|
| `MCP_PROVIDER_BAD_INPUT` | an input breaks its pattern or bound, or terms lie outside the offer or contract bounds | `NEVER` |
| `MCP_PROVIDER_NOT_FOUND` | no such action or record | `NEVER` |
| `MCP_PROVIDER_NOT_OFFERED` | the node has no published offer yet | `NEVER` |
| `MCP_PROVIDER_ALREADY_OFFERED` | the node's offer is published; a terms change is out of V1 | `NEVER` |
| `MCP_PROVIDER_NOT_READY` | a preflight check needed for the action failed; the report is attached | `NEVER` |
| `MCP_PROVIDER_NOTHING_TO_DO` | nothing credited, or more than credited, to withdraw | `NEVER` |
| `MCP_PROVIDER_OVER_LIMIT` | 4 actions already await confirmation | `NEVER` |
| `MCP_PROVIDER_EXPIRED` | the preview's lifetime passed or the re-run preview differed (6.1) | `NEVER` |
| `MCP_PROVIDER_CONFLICT` | an idempotency key reused with other inputs; an action or offer in another phase; another setup run holds the state directory (`ErrSetupBusy`) | `NEVER` |
| `MCP_PROVIDER_DECLINED` | the human declined | `NEVER` |
| `MCP_PROVIDER_DEPENDENCY_UNAVAILABLE` | no RPC quorum, the executor service or a relay unreachable; nothing was sent | `SAME_REQUEST_AFTER_BACKOFF` |
| `MCP_PROVIDER_AGENT_UNAVAILABLE` | the agent socket does not answer | `SAME_REQUEST_AFTER_BACKOFF` |
| `MCP_PROVIDER_AMBIGUOUS` | a confirmed send may have been submitted, or an earlier withdrawal is undecided | `RESOLVE_BEFORE_RETRY` |
| `MCP_PROVIDER_PERMISSION_DENIED` | the socket peer's account may not call this method | `NEVER` |
| `MCP_PROVIDER_RATE_LIMITED` | over a bound of 4.2 | `SAME_REQUEST_AFTER_BACKOFF` |
| `MCP_PROVIDER_INTERNAL` | anything else | `NEVER` |

There is no "not configured" code. A rail configuration that names a buyer,
chat or messenger carrier keeps the agent from starting (2.4), so no client
ever reaches an agent serving one; a rail configuration without a provider
section is served, and before the offer every method that needs it answers
`MCP_PROVIDER_NOT_OFFERED`. The MCP server refuses its own bad deployment
(2.3) by not starting, which the client reports as a server that failed to
start, not as a tool result.

**Timeouts.** Every agent method answers within 30 seconds except
`request_confirmation` (its `wait_seconds` plus 5). A chain read past 20
seconds ends with `MCP_PROVIDER_DEPENDENCY_UNAVAILABLE`. A confirmed action's
`tosctl` sends keep the library's own deadlines; the tool answers
`applying` when they outlast the wait, and the action goes on in the agent.

**Idempotency.** Read-only tools, `pause`, `cancel` and
`request_confirmation` are idempotent by their inputs; `offer_preview`,
`withdraw_preview` and `resume` by their key. A client that repeats a call
after a lost response gets the same action. An action is applied at most
once: only an action in `awaiting_confirmation` that was presented can enter
`applying`, under the action store's lock.

## 8. State and crash safety

The node's own records stay authoritative: the setup journal and run lock,
the rail configuration, the railgate execution slots, the provider request
records, the inbox, the courier and relay outbox journals, the relay keys and
peer cards, the pause marker and the withdrawal records. The provider agent
writes into them only through the library calls of 4.2 and the pause
functions of 2.6.

The adapter's library prerequisites change three of the node's own formats
(section 13): the provider record gains `admitted_unix` (2.5), the pause
marker gains `origin` and `stamp` with its v2 schema and a lock file (2.6),
and `state_dir` gains the serve lock (2.4). These are library state, written
by the library for every node, with or without the adapter.

**One release.** The program (`tos-service-provider`), the provider agent and
the MCP server MUST come from one release. A program of the release before
these changes cannot read a v2 pause marker: its `pause` fails on one (the
node it serves treats the marker as unreadable, so admission stays paused),
and it reads a provider record with `admitted_unix` as invalid. Every program
of this release refuses a marker schema it does not know with a message that
says so, and reads v1 markers and records without `admitted_unix`.

The adapter itself adds exactly three things, in its own state directory
(owner-only `0700`, atomic synced replacements, one agent per directory under
an exclusive directory lock). The action lock of 6.1 is a separate lock file
in that directory, taken only around one action's apply, so that the
directory lock, held for the agent's whole life, never doubles as it:

### 8.1 The action store

One record per confirmable action: `action_id`, kind (`offer`, `withdraw`,
`resume`), the idempotency key, the inputs, the preview and its digest, the
state (`awaiting_confirmation`, `cancelled`, `declined`, `expired`,
`applying`, `applied`, `failed`, `ambiguous`), the confirmation nonce with
its draw time and the failure count (custody-only fields), the library's
result, and timestamps. Terminal records are kept for 30 days and then
removed. On start, an action in `applying` is resolved from the node's own
records, never re-sent on the strength of its old confirmation: an offer
reads the setup journal, a withdrawal its withdrawal record, a resume the
marker. Before a withdrawal's send the agent stores, in the action, the
query IDs of every withdrawal record the node holds; the send's own record
is then the one of the confirmed amount and actor whose query ID is not
among them, so no clock (which may step) takes part, and an action without
the stored IDs never reached its send. An action written without its
idempotency key (a crash between the two writes) is returned, and its key
written, when the same key and inputs are previewed again.

### 8.2 The pause-origin record

When the agent writes an `agent` marker (for the model, or for the wallet
floor), it records the marker's exact bytes and why (`model` or
`wallet_floor`), before it reports the pause. The node honours the marker
alone; the record only decides whether the agent may lift it, and only by the
compare-and-remove of 2.6 against those bytes (4.11). A marker without a
record with the same bytes, and every `operator` marker, is an operator
pause. A crash between writing the marker and the record leaves a marker the
agent does not recognise, which the model then cannot lift: the safe
direction.

### 8.3 What is not kept

Rate counters and the serving report ring are memory only. The daily
admission count is derived from the provider records' `admitted_unix`. The
agent keeps no copy of a key, a task source, a Receipt or an artifact.

A crash of the agent is a crash of `serve`: the node resumes from its records
(an executing request is asked of the executor service again, an executed one
rechecked before it is responded, a responding one resolved from finalized
history; `provider.go:632`), which PR #129's harness exercises with a kill
between execution and respond.

## 9. Untrusted content

Buyer spec section 9 applies, with these sources untrusted: every field of a
task header or buyer key card the node stored, provider record `detail`
texts, the pause marker's reason, the manifest's text fields as read from
disk, relay answers, and every `tosctl`, executor or library error text that
can quote any of them. They appear only in `untrusted_*` fields and in the
delimited spans of buyer spec 9 rule 3. No agent action is derived from
them.

**Residual risk.** A model can still be misled by a buyer's text, for example
into pausing a node. The defence that does not depend on the model is that
nothing it can be led into signs, publishes or moves funds without the human.

## 10. Conformance and acceptance

The adapter counts as implemented only when all of the following hold at one
ai commit, with the record of 10.3 committed under `spec/deployments/`.

### 10.1 Tests

With the happy path, bounds, refusals and red controls (each guard reverted
and its test seen failing):

1. **Roles.** Every method from the client uid, the custody uid and a third
   uid, against the table of 2.3; `present` and `decide` from the client uid
   refused; start refused when the uids are equal, when the client is root,
   and for each private file that is group- or world-accessible; the MCP
   server refuses to start as the custody uid, with `VAULT_URL` set, or when
   it can read the rail configuration.
2. **Re-validation.** Every tool input bound enforced by the agent when the
   socket is called directly, bypassing the MCP server.
3. **Redaction.** Status, records, preflight and every error rendered with
   endpoints carrying user information, paths and tokens, and with custody
   paths: none appears in any client answer; `package_base64` and
   `receipt_boc_base64` never appear; a buyer `detail` text containing an
   end marker cannot close its span.
4. **Confirmation.** No client answer, log the client can read or
   notification contains a nonce or code; a wrong code three times cancels;
   a declined, cancelled or expired action never applies; a preview that
   changes between confirmation and apply (wallet, actor, credited amount)
   expires and sends nothing; `--all` withdraws exactly the confirmed
   amount.
5. **Pause and resume.**
   - The model resumes its own pause only when the marker bytes match, the
     wallet is at or above the floor and preflight passes; each of the three
     failing refuses.
   - An operator pause, a wallet-floor pause and an unreadable marker each
     need the confirmer.
   - **Stacked pause:** the model pauses, then the operator runs
     `tos-service-provider pause`. The marker is re-stamped `operator` with
     the first `paused_unix` kept, and the model's `tos_provider_resume`
     becomes a confirmable action. The same with the agent stopped while
     the operator pauses.
   - **Stacked floor pause:** the floor pause is written, the operator
     pauses on top, and the balance recovers. The agent does not lift the
     marker.
   - **Race:** a re-stamp between the agent's read and its removal makes the
     compare-and-remove fail, and the operator marker stays (a test hook
     between the two steps).
   - A v1 marker reads as `operator`.
6. **Bounds.**
   - At `max_admissions_per_day` a task is held and admitted after the
     count falls, counted by `admitted_unix`.
   - A record updated many times after admission counts once, at its
     admission time.
   - Under the wallet floor admission pauses, and it resumes by itself once
     the floor is met.
   - A held task is never counted as a failed handling.
7. **Crash safety.** The agent killed in each action state, and between the
   library's `--yes` send and its result: no action is applied twice; an
   `applying` withdrawal is resolved from its record; two agents, or an
   agent and `serve`, on one state directory: the second refuses to start.
8. **Clients.** The tool list and schemas load in the Claude Code and Codex
   versions of the run, and a schema test asserts the keyword subset of 4.1.

`provider/` keeps its import boundary (it imports `protocol/` and
`execution/` only, `make boundary-lint`), and the MCP server links no
custody code (a test over its import graph).

### 10.2 The local agent-operated run

Owner ruling: test networks run locally on this host, and locally Claude
Code and Codex replace OpenFox for using and accepting `ai`. The run MUST:

- run on a **local 4-validator TOS test network** built from a pinned tos
  commit, with the release Service Actor build (the test-profile actor cannot
  be configured by `tosctl` today, PR #129's finding), a pinned `tosctl`, and
  at least one Agent Packet Relay with a pinned CA;
- use two custody accounts and two developer accounts on that host (one
  provider and one buyer side per role assignment), with no OpenFox binary,
  source or configuration present, which the record shows from the binary
  list and a scan;
- have every provider step after `init` done by the model through
  `tos-service-provider-mcp`, and every buyer step after `init` through
  `tos-service-buyer-mcp`. The human-only steps (`init`, and the custody
  confirmations of offers, payments and withdrawals) MAY be driven by the
  harness through the real confirmers on custody-owned terminals, as the
  2026-11-19 pilot drove the buyer confirmer, and the record says so;
- **Role assignment A:** a Codex session operates the provider and a Claude
  Code session buys. **Role assignment B:** the roles swapped, each with its
  own provider node, Capability and buyer Agent. Each client is thereby shown
  both buying and selling;
- in each assignment show, from the model's tool calls: preflight; the offer
  previewed, confirmed and applied; the offer file exported and handed to the
  buyer workspace; one paid call answered, its result accepted by the buyer
  against the finalized `response_hash`, and the provider's record `acked`;
  a pause by the model, during which a second paid call is not admitted and
  ends refunded by the buyer agent's duties, then a resume by the model; an
  operator pause that the model's `tos_provider_resume` turns into a
  confirmable action; a **stacked pause**: the model pauses, the operator
  then pauses over it with `tos-service-provider pause`, and the model's
  `tos_provider_resume` becomes a confirmable action instead of resuming;
  each `respond`'s fee read from the owner wallet's finalized transactions;
  and a withdrawal previewed, confirmed and applied,
  with the actor's credited revenue and the owner wallet's balance read
  independently of the provider's report (as PR #129's withdraw scenario
  reads them);
- span a **validator-set switch that changes membership**: a new validator
  set takes effect at a recorded masterchain block, and at least one
  validator of the old set is not in the new one and at least one validator
  of the new set was not in the old one. A re-election of the same members,
  which also changes the configuration's hash, does not count. The local
  network's rotation meets this: a network installed with
  `local/scripts/setup-testnet.sh --rotate` (tos-ops) runs the ten-minute
  development election profile with candidate node 7 added, and its election
  driver (`local/scripts/local-pq-elections.py`, the `tos-pq-elections`
  service) alternates the four-member sets {1, 2, 3, 7} and {1, 2, 3, 4}
  (tos-ops `local/README.md`, "Staking wallets and continuous elections"). During the switch at least one
  paid request is pending at the provider; that request is responded and
  accepted after the switch, and a further purchase runs entirely after it.
  Both agents keep their strict-majority reads through the switch;
- end with a **third, independent check**: `tos-service-verify`
  ([`PURCHASE_EVIDENCE_V1.md`](PURCHASE_EVIDENCE_V1.md)), built from a fresh
  clone, verifies every purchase from the buyers' `tos-service-buyer
  evidence` exports at a quorum of the validators' endpoints.
  `tos-service-verify` verifies purchases only. The provider-side facts
  (respond and withdrawal transactions, credited revenue, respond fees,
  wallet balances) are read by the harness itself at a strict majority of
  the validators, never from the provider's own report, and the record says
  which facts came from which reader;
- CLI fallback: any provider step after `init` that is run with the
  `tos-service-provider` CLI instead of through the adapter is a
  **CLI-fallback step**. It runs in the custody account and so outside the
  adapter's custody separation. The permitted custody-side commands of 3.1
  (`init`, the preflight after `init`, `agent`, `confirm`, the operator's
  `pause` and `resume` of the stacked-pause scenario, `status` for
  inspection) are not fallback steps. The record lists each fallback step
  under `cli_fallback_steps`, and an assignment with any fallback step does
  not count toward this acceptance (decision P7).

### 10.3 The record

The run produces one JSON record in the style of
`deployments/public-testnet-epoch7-gate-d-agent-pilot-20261119.json`, with
schema `tos.service.local-agent-operated-provider-run-record.v1` and at
least:

- `status`, `verdict` (`LOCAL_AGENT_OPERATED_RUN_PASSED` or `_FAILED`),
  `operation_mode: "agent-operated"`, `network_kind: "local"`,
  `qualifies_as_gate_d: false`, `qualifies_as_public_acceptance: false` and a
  `qualification_note` saying it is a local agent-operated run by the core
  team and not Gate D evidence;
- `network` (network ID, genesis hashes, global config hash, validator
  count 4) and `validator_set_switch`: the block and time at which the new
  set took effect, the configuration's hash before and after, the member
  list of each set (validator public key hashes and their local indices),
  the members that left and that joined (each at least one), and the
  requests pending across it;
- `releases` and `source_commits` (`ai`, `tos`, the harness; no `openfox`
  key), `binaries` with SHA-256 of every binary including both clients and
  `tos-service-provider`, `tos-service-provider-mcp`,
  `tos-service-buyer`, `tos-service-buyer-mcp`, `tos-service-verify`,
  `tosctl` and the executor service, and `openfox_absent: true` with the
  scan it rests on;
- `accounts` (the four uids' roles, never names) and the custody checks the
  agents made at start;
- `role_assignments` A and B, each with: the provider and buyer model
  clients (CLI version, binary SHA-256, models, the hashes of the prompts,
  transcripts and tool-call logs), the provider objects (Agent, wallet,
  actor, Capability and version, manifest digest, attestor key ID, terms
  hash, offer file SHA-256), the provider actions (kind, `action_id`,
  preview digest, how confirmed, outcome), the purchases (request hash,
  request ID, call, respond or refund transactions, `response_hash`,
  Receipt and artifact digests, final state), the pause and resume events
  with their origin and marker stamps (including the stacked pause), the
  withdrawals (query ID, amount, transaction, the independently read
  balances) and `cli_fallback_steps`;
- `respond_fees` for every respond: the request, the respond transaction,
  the fee it paid in nanoTOS, and the owner wallet's finalized balance before
  and after it, with the reader (harness) and checkpoint. A summary gives the
  highest and mean fee, against which the wallet floor (P3) is set;
- `confirmations`: for every confirmed action and payment, which confirmer,
  on which terminal kind, driven by whom;
- `verifier_output` (tool commit, verdict hashes, checkpoint, results), for
  purchases only, and `provider_facts_reader: "harness"` with the strict
  majority reads the provider-side facts rest on;
- `checks` (each with its result), `known_limitations` (at least: the core
  team operated every role; the confirmers were harness-driven; every
  endpoint is a local validator), and `record_sha256`.

## 11. Threat model

The buyer spec's rows on custody, the confirmer channel, direct socket
calls, malware in the developer account, a compromised custody account, a
lying RPC endpoint, a substituted `tosctl`, crashes and single-account
setups carry over. In addition:

| Threat | Mitigation | Residual |
|---|---|---|
| The model publishes ruinous terms (price below the respond fee, a refund window it cannot meet) | offers are confirmable and bounded by the custody-owned offer bounds (2.4); the confirmer states what a call pays | a human who confirms without reading |
| The model withdraws revenue elsewhere | the destination is fixed to the owner wallet by contract; withdrawals are confirmable | fees |
| The model resumes a node the operator stopped on purpose, including an operator pause stacked on the model's own | operator pauses re-stamp the marker as `operator`; the agent removes only by compare-and-remove against the marker bytes it wrote, with the floor met and preflight passing (2.6, 4.11) | none at the lock |
| Buyers drain the owner wallet through respond fees | the daily admission cap and the wallet floor (2.5); pause | `(max_executions + R) × respond_fee` below the floor, plus retries of ambiguous responds (2.5) |
| Buyer text steers the model | section 9; the model holds no authority that signs | nuisance pauses |
| The model reads secrets through status | the redaction of 4.3, enforced in the agent | none beyond its rules |
| Two processes serve one node | the serve lock (2.4) | none at the lock |

## 12. Decisions

Owner rulings:

- Test networks run locally on this host; there is no public network now.
  The acceptance of 10.2 is local and is not Gate D evidence.
- Locally, Claude Code and Codex replace OpenFox for using and accepting
  `ai` (10.2).
- An LLM as the worker is out of scope; it needs a new commerce profile
  behind the expansion gate.
- **2026-11-23, waiver of the two developer accounts of 10.2.** The owner
  waives the requirement of 10.2 that the run use two developer accounts,
  and accepts the run recorded in
  `deployments/local-agent-operated-provider-run-20261123.json` (verdict
  `LOCAL_AGENT_OPERATED_RUN_PASSED`, 41 checks). That run used one
  developer account, the operator's own, which has sudo and holds keys and
  configurations from earlier work. Why: the separation a second developer
  account buys is between the two clients, not custody. Custody separation
  was complete in the run: separate custody OS accounts for the provider
  and the buyer, and agent sockets that admit callers by their peer
  credentials (2.3); the run's custody keys and vaults existed only in the
  two custody accounts, none in the developer account. Each client was
  given only its role's MCP server, with no shell or file tool (Codex still
  listed its code-mode exec, `apply_patch` and its collaboration tools; no
  session used them), so the clients could not read the developer
  account's files. What remains true: the core team operated every role, and the
  run is not Gate D evidence (`qualifies_as_gate_d: false`).

Decided for V1 on 2026-11-23, in the review of this specification (ai #130);
the owner may reopen any of them:

- **P1. Daily cap:** the agent enforces `max_admissions_per_day` now (2.5),
  counted by the new `admitted_unix`. Using the actor's own
  `rate_limit_per_day` waits for an `update-policy` verb (P6).
- **P2. Withdraw without a human:** withdrawals stay confirmable in V1. A
  direct `withdraw` of credited revenue with a per-day count may come later,
  since the destination is fixed by contract.
- **P3. Wallet floor:** default 2 TOS, pausing admission below it (2.5). The
  run of 10.2 records the fee of every respond (10.3 `respond_fees`), and the
  default is revisited from those values.
- **P4. Resume of the model's own pause:** allowed directly, only with
  matching marker bytes, the floor met and a passing preflight (4.11).
- **P5. Packaging:** `agent` and `confirm` are verbs of
  `tos-service-provider`; the MCP server is its own binary,
  `tos-service-provider-mcp`, mirroring the buyer.
- **P6. Terms changes:** an `update-policy` verb is added to the program
  first, then a confirmable `tos_provider_update_policy_preview` in a V1.1 of
  this adapter. Until then the owner changes terms with `tosctl`.
- **P7. CLI fallback in acceptance:** a CLI-fallback step (10.2)
  disqualifies its role assignment.

## 13. Implementation work and dependencies

A follow-up implementation delivers, with the tests of 10.1:

- `provider/pkg/servicebridge` and the program, as prerequisites of the
  adapter:
  - a serve lock on `state_dir`, taken by `serve` and the agent;
  - `admitted_unix` in `ProviderRecord`, written once when the record is
    first stored after `Gate.Admit`;
  - an admission limiter hook consulted after the pause check
    (`provider.go:293`), held like a pause and counted by `admitted_unix`;
  - the v2 pause marker with `origin` and `stamp`, a pause lock file,
    `PauseAdmission` with an origin, the operator re-stamp of an `agent`
    marker, and a compare-and-remove `ResumeAdmissionIf(state_dir,
    expected_bytes)`. The program's `pause` writes `operator` and re-stamps,
    and its `resume` stays unconditional (2.6);
  - a read of the owner wallet's finalized balance for the floor;
- a provider agent package in `provider/` (socket, roles, re-validation,
  action store, pause-origin record, redaction, confirmation code and
  `decide`), and the verbs `tos-service-provider agent` and `confirm`;
- `provider/cmd/tos-service-provider-mcp` on go-sdk v1.7.0;
- a provider-side MCP guide, in the form of `MCP_BUYER_GUIDE.md`, with the
  Claude Code and Codex entries;
- the harness of 10.2, built on PR #129's `protocol/e2e/provider-buyer`
  (which runs a 3-validator network in one container with no MCP provider)
  extended to the local 4-validator network, the validator-set switch and
  both client sessions, and the record writer of 10.3.

Dependencies: ai #127 (the output contract, and `RecordedPacketController`
for an interrupted `init`) and ai #129 (the provider-buyer harness and its
finding that `tosctl` cannot operate the test-profile actor, which keeps the
refund scenario on the release actor's 3,600-second windows) MUST merge
before the implementation. The tos-side fix that lets `tosctl` operate the
test-profile actor would shorten the run by about an hour.
