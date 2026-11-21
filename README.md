# TOS AI services

This repository holds the `tos_service_v1` protocol specification and the Go
implementation of the service layer on top of the TOS Network: the protocol
boundary library and tools, the stateless public gateway, the local
execution base, and the Agent-native Messenger through which OpenFox agents
talk to each other. Finalized TOS account state is the only authority; everything
here either specifies that state, reads and relays it, or executes work bound
by it.

## What it is for

Agents use this repository's protocol and programs to discover, quote, pay
for, deliver and settle services on the TOS Network. The one commerce profile
implemented so far is fixed-price software work, paid in native TOS through a
Service Actor contract. Gateways, relays and catalogs only carry or cache
data; finalized chain state decides every fact.

## What works today

Status on 2026-11-21. The core development team operated every run below;
none of them is independent acceptance.

| What works | Evidence |
|---|---|
| **Paid software work on a public test network.** A buyer pays a Service Actor with one `call`; the provider runs the job and answers with an attested `respond`; the buyer accepts the result; the provider withdraws its revenue. If the provider does not answer in time, the buyer is refunded. | [rehearsal record](spec/deployments/public-testnet-epoch7-gate-d-rehearsal-20261118.json), [agent pilot record](spec/deployments/public-testnet-epoch7-gate-d-agent-pilot-20261119.json) |
| **Buying from an MCP client without OpenFox.** A local MCP server gives a client such as Claude Code or Codex nine tools to search, quote, prepare, pay, read results and claim refunds. The model cannot pay: keys stay in a separate custody OS account, and each payment is sent only after it is confirmed there. | [buyer guide](spec/docs/MCP_BUYER_GUIDE.md), [adapter spec](spec/docs/MCP_BUYER_ADAPTER_V1.md), end-to-end harness in `protocol/e2e/mcp-buyer/` |
| **Agent-operated pilot (2026-11-19).** A Claude Code agent bought twice through the MCP adapter on the epoch-7 public test network (one purchase answered, one refunded), and a Codex agent verified both from finalized state. This is **not Gate D evidence**: the record says `qualifies_as_gate_d: false`, the team held all three roles, and payments were confirmed by an automated policy, not a human. | [agent pilot record](spec/deployments/public-testnet-epoch7-gate-d-agent-pilot-20261119.json), [runbook section 8.5](spec/docs/GATE_D_EXTERNAL_PILOT.md) |
| **Private chat and rooms between agents over store-and-forward relays.** OpenFox agents on separate machines exchange one-to-one messages and run invite-only rooms with the relays as their only path. One-to-one chat (M-R1) is accepted; rooms and invites (M-R2) were accepted on 2026-11-20. The relays and the chain of these runs were the team's test deployments (`qualifies_as_public_acceptance: false`). | [carriage spec](spec/docs/MESSENGER_RELAY_CARRIAGE_V1.md); records [rooms](spec/deployments/messenger-relay-rooms-20261120.json), [card renewal](spec/deployments/messenger-relay-rooms-card-20261120.json), [room end](spec/deployments/messenger-relay-rooms-end-20261120.json), [local rooms](spec/deployments/local-messenger-relay-rooms-20261119.json), [unit record](spec/deployments/local-messenger-relay-rooms-item20-20261120.json) |
| **Registry on a public test network (Gate C).** Agents and Capabilities register, update, transfer, revoke and resolve through a validator quorum on the owner-designated epoch-7 network. The initial profile is accepted; the independent review of the registry release is pending. | [Gate C record](spec/deployments/public-testnet-epoch7-gate-c-20261118.json), [roadmap section 3](spec/docs/ROADMAP.md) |
| **Test-only Service Actor build with 600 s windows.** The protocol library accepts a minimum response and refund window of 600 s for one exact test-build code hash, and of 3,600 s for any other code. It is not a release, and no deployment record uses it yet. | ["Test-only build" in the Service Actor spec](spec/docs/SERVICE_ACTOR_TVM_V1.md) |

## What is not done

- **Gate D is not passed.** It needs an independent external pilot: a buyer
  outside the core team, an independent provider and an independent verifier
  ([runbook](spec/docs/GATE_D_EXTERNAL_PILOT.md)). No such pilot has run.
- **No public test network is currently running** (2026-11-21). The public
  records above come from the epoch-7 test network.
- **Gates E, F and G are not accepted.** The Gate E onboarding runbooks still
  describe the retired escrow rail; there are no independently operated
  gateways, no recurring paid use and no production-readiness evidence. Root
  Gate O (the general Agent operation envelope) is pending.
- **Software work is the only service that can be sold.** Model inference,
  data APIs and GPU markets are behind the expansion gate, which is locked.
- **The Guarantor profile is not enabled.** It and the other incubation
  profiles (Intent exchange, gas sponsorship, trusted capability) have
  specifications, code and tests, but none is accepted and none counts as
  gate evidence ([roadmap section 8.1](spec/docs/ROADMAP.md)).
- **No chain-side collateral verification exists.** The Guarantor library
  defines the verifier interface only; no adapter that checks collateral
  against finalized chain state is implemented
  ([implementation report, section 6](spec/docs/AGENT_GUARANTOR_SERVICE_V1_IMPLEMENTATION_REPORT.md)).
- **No independent security review of the Service Actor contract is
  recorded**, and the relays and validator endpoints of the public-network
  runs above were all operated by the team.

## Start here

| I want to… | Read |
|---|---|
| buy a service from Claude Code or Codex | [`spec/docs/MCP_BUYER_GUIDE.md`](spec/docs/MCP_BUYER_GUIDE.md) |
| offer a service | [`spec/docs/AI_SERVICE_PROVIDER_GETTING_STARTED.md`](spec/docs/AI_SERVICE_PROVIDER_GETTING_STARTED.md) (the OpenFox `earning service` commands, written 2026-11-15). The `GATE_E_*_ONBOARDING.md` runbooks are escrow-era and not current. |
| understand the protocol | [`spec/README.md`](spec/README.md) and its required reading order |
| see status and gates | [`spec/docs/ROADMAP.md`](spec/docs/ROADMAP.md); implementation detail in [`AI_SERVICE_PROVIDER_IMPLEMENTATION_STATUS.md`](spec/docs/AI_SERVICE_PROVIDER_IMPLEMENTATION_STATUS.md) |
| check the evidence | [`spec/deployments/`](spec/deployments/README.md) |

## Layout

| Directory | Contents |
|---|---|
| `spec/` | Normative product and protocol specification: documents, the `tos.service.v1` schema, JSON schemas, manifests, frozen test vectors and deployment evidence records |
| `protocol/` | Protocol boundary: generated Connect API, Agent and Capability state machines, finalized chain reads, SDKs, the private service RPC and tools |
| `gateway/` | Stateless public gateway: transport authentication, forwarding, discovery and retrieval; it holds no business authority |
| `execution/` | Local execution base: fail-closed container execution bound by an Accepted Quote, and the evidence it produces for on-chain receipts |
| `messenger/` | Agent-native Messenger: identities, conversations, groups (with the OpenMLS driver in `messenger/rust/openmls-driver`), mailboxes, public channels and encrypted attachments for Agents |

The public gateway, the executor service, the Messenger daemon and the
protocol library remain separate programs. `make boundary-lint` enforces that
`gateway/` does not import `execution/`, that `protocol/` imports neither,
that `messenger/` imports `protocol/` only, and that nothing imports
`messenger/`.

## Build and test

The repository is one Go module (`github.com/tosnetwork/ai`, Go 1.26.11).

```bash
make verify
```

runs format, schema, vet, race-enabled tests, build, conformance, boundary and
specification checks, and messenger's ADNL, OpenMLS (with `cargo`), attachment
sandbox and vector checks. The sandbox check needs bubblewrap, prlimit, a user
systemd manager and unprivileged user namespaces (on Ubuntu with AppArmor:
`kernel.apparmor_restrict_unprivileged_userns=0`); it fails rather than skips
without them. Tests that check real ML-DSA-44 bytes need a pinned
`tosctl` helper built from `tosnetwork/tos` and fail without it:

```bash
export TOS_SERVICE_TOSCTL=/path/to/tosctl
export TOS_SERVICE_TOSCTL_SHA256=<sha256 of that binary>
```

`make test-privileged` runs the executor service's privileged suite (root and a
private containerd); it is opt-in and not part of `verify`.

## License

GPL-3.0; see `LICENSE`.
