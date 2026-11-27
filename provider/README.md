# TOS AI service provider

`provider/` is the selling side of the Service Actor rail: a provider
registers an Agent, publishes a software-work Capability with its price and
terms in a Service Actor, serves paid calls and withdraws its revenue.
Finalized TOS chain state is the only authority; nothing here can create or
change a purchase.

| Path | Contents |
|---|---|
| `pkg/servicebridge` | The rail node library: setup, offer, preflight, relay and direct carriage, execution through the executor service, receipts, status and withdrawal. It also holds the rail's buyer counterpart, which the two-sided node and the tests use. |
| `cmd/tos-service-provider` | The provider program: a thin command-line wrapper over the library, with the `agent` and `confirm` verbs of the MCP provider adapter. |
| `pkg/provideragent` | The provider agent of the MCP provider adapter ([`MCP_PROVIDER_ADAPTER_V1.md`](../spec/docs/MCP_PROVIDER_ADAPTER_V1.md)): runs the node, serves the agent socket, keeps the action store and the pause-origin record, and applies an action only after a human confirmed it. |
| `pkg/provideragent/agentapi` | The agent socket's API and client; it links no custody code. |
| `pkg/providerconfirm` | The adapter's confirmer, on a custody-account terminal. |
| `pkg/mcpprovider`, `cmd/tos-service-provider-mcp` | The adapter's stdio MCP server, which an MCP client starts in the developer account: the `tos_provider_*` tools, each one agent method over the socket. Its binary links only `agentapi`, `protocol/pkg/agentsocket` and the MCP SDK. |

`provider/` imports `protocol/` and `execution/` only, and nothing imports
`provider/` (`make boundary-lint`).

## Build

```sh
go build -o tos-service-provider ./provider/cmd/tos-service-provider
go build -o tos-service-provider-mcp ./provider/cmd/tos-service-provider-mcp
```

Operating the node from Claude Code or Codex (two OS accounts, the agent,
the confirmer and each client's MCP entry) is the
[MCP provider guide](../spec/docs/MCP_PROVIDER_GUIDE.md).

The program needs, at run time, a pinned `tosctl` with a vault and a funded
wallet, three to eight chain RPC endpoints, the Native Registry code file,
and the executor service (`execution/cmd/software-work-executord`, installed
from `execution/deploy/provider/`).

## Run

```text
tos-service-provider init       establish the node's Agent and write the rail configuration
tos-service-provider offer      deploy the Service Actor, register the Capability, set the policy
tos-service-provider preflight  check that the node is ready to admit paid work
tos-service-provider serve      receive rail packets, execute admitted work and respond
tos-service-provider status     admission, credited revenue and each request's state
tos-service-provider pause      stop admitting new requests
tos-service-provider resume     admit new requests again
tos-service-provider withdraw   withdraw credited revenue to the owner wallet
tos-service-provider manifest   build a Capability manifest by hand (no chain effect)
tos-service-provider metadata   print the metadata hash an actor policy must carry
tos-service-provider agent      run the node for the MCP provider adapter and serve its agent socket
tos-service-provider confirm    confirm or decline the adapter's pending actions, on a custody terminal
```

`agent --config <file>` reads the owner-private agent configuration (schema
`tos.service.mcp-provider.agent-config.v1`, section 2.4 of the adapter
specification) and runs in the custody account; `confirm --agent-socket
<path> [--watch]` runs there too, on a terminal that account logged in on.
Before the offer is published the agent serves no node and holds the node's
serve lock; the model previews the offer and the human confirms it.

`tos-service-provider <command> -h` lists a command's flags. The step-by-step
walk-through is the
[provider guide](../spec/docs/AI_SERVICE_PROVIDER_GETTING_STARTED.md); it was
written around another program's `earning service` commands. Each of the
first ten provider verbs above appears there as `earning service <verb>`
(`agent` and `confirm` do not), and each flag
the guide gives one of them exists here with the same name and meaning, with
these exceptions:

- `init --messenger-socket` does not exist here: this program carries
  packets over direct sockets and relays only.
- The buyer flags of `init` (`--allow-provider`, `--confirm-above`, the
  spending-policy flags and the gateway flags) do not exist here, nor do the
  guide's `buy` and `purchases` commands: buying is
  `protocol/cmd/tos-service-buyer` and the MCP buyer server.
- `init --packet-controller` defaults to `service-packet` here, not
  `openfox-packet`, when neither the setup journal nor the rail
  configuration of the node records one (see below).

A minimal sequence, with the paths and amounts replaced by your own:

```sh
tos-service-provider init --rail-config "$DIR/rail.json" --state-dir "$DIR/state" \
  --rpc "$RPC1" --rpc "$RPC2" --rpc "$RPC3" \
  --global-config "$DIR/global.config.json" --network-label "$NETWORK_LABEL" \
  --tosctl "$TOSCTL" --tosctl-sha256 "$TOSCTL_SHA256" --tosctl-config "$DIR/tosctl.json" \
  --wallet provider --registry-code-boc "$DIR/registry-code.boc" \
  --actor-code-hash "$ACTOR_CODE_HASH" --relay-url "$RELAY_URL"          # preview
tos-service-provider init ...same flags... --yes                          # sign and send

tos-service-provider offer --rail-config "$DIR/rail.json" --price 0.1 --storage-fee 0.2 \
  --cleanup-bounty 0.1 --response-sla 3600 --refund-claim-window 3600     # preview
tos-service-provider offer ...same flags... --yes

tos-service-provider preflight --rail-config "$DIR/rail.json"
tos-service-provider serve --rail-config "$DIR/rail.json"
tos-service-provider status --rail-config "$DIR/rail.json"
tos-service-provider withdraw --rail-config "$DIR/rail.json" --all        # preview
tos-service-provider withdraw --rail-config "$DIR/rail.json" --all --yes
```

### Output and exit codes

Diagnostics (previews, progress, the reason of a failure) go to standard
error. For every command that did not succeed (any exit code other than 0)
the last line of standard error is exactly one line
`tos-service-provider: <reason>`; text that explains it, such as the usage
after an unknown command or no command, or a flag list after a malformed
flag, comes before it, and a reason that would span lines is joined into
one. Standard output carries JSON or nothing:

- **On success** every command prints one JSON document. `serve` prints one
  JSON line, `{"serving": true, ...}`, and then runs until SIGINT or SIGTERM;
  a problem it meets while serving is one line on standard error.
  `"serving": true` means the node is assembled and its receiver socket is
  open; it does not mean the node is ready to sell (that the chain is
  reachable, the actor and Capability are live, the executor answers).
  `preflight` is the readiness check: run it first, and rely on its report.
- **`preflight`** always prints its report, also when the configuration
  cannot be read (that is one of its failed checks), and exits 0 or 3.
- **`init`, `offer` and `withdraw`**, once they have started, print their
  report also when they fail (exit 1) and when they only previewed (exit 4).
  That includes the checks of the arguments that the library makes and the
  program does not: `offer --price 0`, a response SLA out of range, or a
  missing or unreadable rail configuration print the report and exit 1,
  not 2.
- **Nothing is printed on standard output** in exactly these cases:
  - the program refuses the arguments (exit 2);
  - `init`, `offer` or `withdraw` (also `withdraw --acknowledge`) refuse
    before they start because an existing rail configuration names another
    carrier (exit 1);
  - `init` without `--packet-controller` refuses before it starts because
    the setup journal under `--state-dir` exists but cannot be read or has
    another schema (exit 1);
  - `status`, `pause`, `resume`, `manifest` or `metadata` fail, or `serve`
    fails before it prints its `"serving": true` line, including a rail
    configuration that is missing, unreadable, has no provider section or
    names another carrier (exit 1); a `serve` that fails after that line
    exits 1 with that one line on standard output;
  - `<command> -h` (exit 0, below).
- **`help`**, `-h` or `--help` as the command prints the usage as plain text
  on standard output and exits 0. `<command> -h` prints that command's flags
  as plain text on standard error, nothing on standard output, and exits 0.

| Exit code | Meaning |
|---|---|
| 0 | done (or help printed) |
| 1 | the command failed, including argument checks made by the library; `init`, `offer`, `withdraw` and `preflight` still print their report |
| 2 | the program refused the arguments (unknown command, unknown or malformed flag, missing required flag, positional argument, an amount that is not a decimal TOS amount, `withdraw --amount 0`, flags that exclude each other); nothing is printed on standard output and nothing was read or changed |
| 3 | `preflight` printed its report and at least one required check failed |
| 4 | a preview was printed and nothing was signed or sent; run the same command with `--yes` |

### An existing provider directory

The rail configuration file, the state directory, the journals and the
request records are the library's formats. This release changes three of
them, and reads every earlier form:

- a request record gains `admitted_unix`, the time the gate admitted it,
  written once; a record without it is read as before;
- the admission pause marker is written as schema
  `tos.openfox.rail-admission-pause.v2` with an `origin` (`operator` or
  `agent`) and a random `stamp`; a v1 marker is read as an operator pause.
  Every pause, re-stamp and removal runs under `<state_dir>/admission-pause.lock`;
- `serve` holds `<state_dir>/serve.lock` while it runs, so a second `serve`,
  or a provider agent, on the same node is refused
  (`another process already serves the node of this state directory`).
  OpenFox's own `earning service serve` is built on its own copy of the
  library, which takes no serve lock: it is not refused, and it must never
  run on a node this program or the provider agent serves.

Use one release for every program that touches a node. An earlier
release's program cannot read a v2 marker (its `pause` fails and its node
treats the marker as unreadable, so admission stays paused) nor a record with
`admitted_unix`. This release refuses a marker of a schema it does not know,
with a message that says to run the program of the same release; admission
stays paused until the right program resumes it.

`pause` always leaves an operator marker: over an agent's pause it replaces
the marker with an operator one that keeps the first `paused_unix`, carries
the new `--reason` (the old one when none is given) and a new stamp, and
reports `"restamped": true` with the `previous_origin`, so the agent can no
longer lift it. Over a marker it cannot read it changes nothing and fails.
`resume` stays unconditional: it removes whatever marker there is. A
directory
made by the earlier `earning service init` and `offer` commands is operated
by this program as it is: name the same `--rail-config`. A re-run of `init`
without `--packet-controller` keeps the controller the node already has: the
one the setup journal under `--state-dir` records (an earlier `init` that
stopped after writing its journal and before writing the rail configuration
is found only there), else the one the rail configuration records, else
`service-packet`. A setup journal that exists but cannot be read stops
`init` with exit 1 instead.

The program carries rail packets over direct sockets (`--direct-peer`) and
Agent Packet Relays (`--relay-url`) only. A configuration that has a `chat`
section or names `messenger_socket` is refused by every command with the
library's error; remove the section or the field. It has no buyer commands:
buying is `protocol/cmd/tos-service-buyer` and the MCP buyer server.

## Custody

- **Keys live in `tosctl`, under the operator's account.** The program holds
  no key and has no command that prints or exports one. Every signature and
  every send is made by the `tosctl` binary pinned by SHA-256 in the rail
  configuration. The vault URL is read from the environment variable the
  configuration names (`VAULT_URL` by default), handed to `tosctl` in its
  environment, and never printed or stored.
- **`init`, `offer` and `withdraw` are previewed.** Without `--yes` they
  print what they would create, sign and send, change nothing on chain, and
  exit with code 4. `withdraw --acknowledge` likewise records nothing without
  `--yes`. The one policy change the program sends is the step of `offer`
  that sets the published Capability version's policy, previewed with the
  rest of the offer; changing the terms of an actor already published is not
  a command here, and the owner does it with `tosctl` directly.
- **`serve` signs `respond` on its own, and only then:** the request was
  admitted against finalized state
  (`pkg/servicebridge/provider.go:305`); the execution ended in a successful
  outcome — a failed or unknown outcome is never attested
  (`pkg/servicebridge/provider_service.go:130`); the Receipt built from that
  outcome is attestable (`pkg/servicebridge/provider_service.go:144`); and a
  fresh check of finalized state, made immediately before the send, shows
  the request still pending and unchanged with the respond budget ahead
  (`pkg/servicebridge/provider.go:745`, sent at `provider.go:754`; the same
  check precedes every retry, `provider.go:682`). `serve` sends no other
  transaction for the provider: it never withdraws and never changes the
  policy. If the rail configuration also has a buyer section, `serve` keeps
  that section's own purchases moving as the library always did, which
  includes sending `expire` and `claim_refund` for them.
- **A model operates a provider through the provider agent,** never with
  these commands. `tos-service-provider agent` runs in a custody account the
  model's account cannot read; the model's MCP server reaches it only
  through the agent socket, whose peer uid decides what it may do. An offer,
  a withdrawal and a resume of any pause but the model's own are previewed
  and wait for a human, who confirms them with `tos-service-provider confirm`
  on a custody terminal; the agent re-runs the preview before it sends.
  The confirmer talks only to a socket its own account owns. The MCP server
  (`tos-service-provider-mcp`) holds nothing secret and refuses to start as
  the custody account, with the vault variable set, or where it can open the
  rail configuration or the agent's state directory.

## Not here yet

- **Acceptance of the MCP provider adapter beyond the team's local run.**
  The agent, the confirmer and the MCP server are implemented and tested,
  and the adapter was accepted locally on 2026-11-23
  (`spec/deployments/local-agent-operated-provider-run-20261123.json`) with
  one developer account under the owner's waiver in section 12 of the
  specification; not Gate D evidence. In that run Claude Code and Codex
  each operated a provider, and the core team operated every role.
- **A live run on a public network.** No record shows this program serving a
  paid call on a public test network; the recorded paid-work runs used the
  same library inside another program.
- **A rewrite of the provider guide** around this program's commands.

## Token actors

See [token provider management](docs/token-rail.md) for asset pins, atomic offer
bounds, both revenue withdrawals, recovery, the settlement-monitor auto-pause
hook and the token MCP tools. The guide states the remaining integration gates.

Token paid-work execution fails closed when the monitor report is missing or
stale, or when its `provider_pause_assets` contains this actor's asset. That
field carries the latched emergency alarms: `bridge_frozen`, `token_paused`,
`destroyed_funds`, `token_deprecated`, `unexplained_decrease` and `backing_shortfall`. Non-emergency
monitor alarms do not stop execution. A transient pre-execution safety refusal
keeps the funded slot admitted and retryable while its execution and response
budgets still fit before the response deadline; it neither starts work nor
abandons the request. Refund remains available under the
contract's normal deadlines.
