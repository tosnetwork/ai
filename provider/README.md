# TOS AI service provider

`provider/` is the selling side of the Service Actor rail: a provider
registers an Agent, publishes a software-work Capability with its price and
terms in a Service Actor, serves paid calls and withdraws its revenue.
Finalized TOS chain state is the only authority; nothing here can create or
change a purchase.

| Path | Contents |
|---|---|
| `pkg/servicebridge` | The rail node library: setup, offer, preflight, relay and direct carriage, execution through the executor service, receipts, status and withdrawal. It also holds the rail's buyer counterpart, which the two-sided node and the tests use. |
| `cmd/tos-service-provider` | The provider program: a thin command-line wrapper over the library. |

`provider/` imports `protocol/` and `execution/` only, and nothing imports
`provider/` (`make boundary-lint`).

## Build

```sh
go build -o tos-service-provider ./provider/cmd/tos-service-provider
```

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
```

`tos-service-provider <command> -h` lists a command's flags. The step-by-step
walk-through is the
[provider guide](../spec/docs/AI_SERVICE_PROVIDER_GETTING_STARTED.md); it was
written around another program's `earning service` commands, and every
provider command in it exists here under the same name with the same flags.

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

Every command prints JSON on standard output and diagnostics (previews,
progress, the reason of a failure) on standard error, so an agent that only
runs commands can operate a provider. `serve` prints one JSON line when the
node is assembled and its receiver socket is open, then runs until it
receives SIGINT or SIGTERM; a problem it meets while serving is one line on
standard error.

| Exit code | Meaning |
|---|---|
| 0 | done |
| 1 | the command failed; a setup or withdrawal command still prints its report |
| 2 | the arguments were refused; nothing was read or changed |
| 3 | `preflight` printed its report and at least one required check failed |
| 4 | a preview was printed and nothing was signed or sent; run the same command with `--yes` |

### An existing provider directory

The rail configuration file, the state directory, the journals and the
request records are the library's formats and did not change. A directory
made by the earlier `earning service init` and `offer` commands is operated
by this program as it is: name the same `--rail-config`. A re-run of `init`
without `--packet-controller` keeps the controller the configuration
records.

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
- **An agent operating a provider runs these commands** under the operator's
  account, with that account's access to the vault. Separating the model
  from the keys, as the MCP buyer adapter does with its custody account, is
  not built for the selling side yet (see below).

## Not here yet

- **An MCP provider adapter.** A later phase adds one with a
  custody-separated daemon, mirroring the buyer adapter
  ([`MCP_BUYER_ADAPTER_V1.md`](../spec/docs/MCP_BUYER_ADAPTER_V1.md)).
- **A live run on a public network.** No record shows this program serving a
  paid call on a public test network; the recorded paid-work runs used the
  same library inside another program.
- **A rewrite of the provider guide** around this program's commands.
