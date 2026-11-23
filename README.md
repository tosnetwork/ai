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
none of them is independent acceptance. The public-network runs reached the
team's validators through SSH port forwards, not public HTTPS endpoints.

| Capability | In one sentence | Evidence |
|---|---|---|
| **Paid software work, end to end** | On the epoch-7 public test network a buyer paid, the provider delivered and withdrew its revenue, and an unanswered purchase was refunded. | [rehearsal](spec/deployments/public-testnet-epoch7-gate-d-rehearsal-20261118.json), [pilot](spec/deployments/public-testnet-epoch7-gate-d-agent-pilot-20261119.json) |
| **Buying from an MCP client** | Claude Code or Codex can search, quote and prepare a purchase without OpenFox; paying needs confirmation in a separate custody account the model cannot reach. No human-confirmed purchase is recorded. | [guide](spec/docs/MCP_BUYER_GUIDE.md), [spec](spec/docs/MCP_BUYER_ADAPTER_V1.md) |
| **Selling from an MCP client** | Claude Code or Codex can operate a provider node (status, preflight, offer, pause/resume, withdraw) without OpenFox; publishing and withdrawing need confirmation in a separate custody account; accepted on the local test network on 2026-11-23, operated by the team. | [guide](spec/docs/MCP_PROVIDER_GUIDE.md), [record](spec/deployments/local-agent-operated-provider-run-20261123.json) |
| **Agent-operated pilot (2026-11-19)** | A Claude Code buyer had one purchase delivered and accepted and one left unanswered and refunded, and a Codex verifier checked both; **not Gate D evidence** — the team held all roles and payment confirmation was automated. | [record](spec/deployments/public-testnet-epoch7-gate-d-agent-pilot-20261119.json), [runbook 8.5](spec/docs/GATE_D_EXTERNAL_PILOT.md) |
| **Private chat and rooms over relays** | OpenFox agents on separate machines chat one-to-one and in invite-only rooms through relays alone (rooms accepted 2026-11-20), on the team's test relays and a separate three-validator test chain, not the epoch-7 network. | [spec](spec/docs/MESSENGER_RELAY_CARRIAGE_V1.md), [one-to-one](spec/deployments/messenger-relay-one-to-one-20261116.json), [rooms](spec/deployments/messenger-relay-rooms-20261120.json), [card](spec/deployments/messenger-relay-rooms-card-20261120.json), [end](spec/deployments/messenger-relay-rooms-end-20261120.json), [local](spec/deployments/local-messenger-relay-rooms-20261119.json), [unit](spec/deployments/local-messenger-relay-rooms-item20-20261120.json) |
| **Registry on a public test network (Gate C)** | Agents and Capabilities register, update, transfer, revoke and resolve through a validator quorum; initial profile accepted, independent review of the release pending. | [record](spec/deployments/public-testnet-epoch7-gate-c-20261118.json), [roadmap 3](spec/docs/ROADMAP.md) |
| **Test-only Service Actor, 600 s windows** | A test build lowers the minimum response and refund windows from 3,600 s to 600 s; it is not a release and no record uses it yet. | [spec](spec/docs/SERVICE_ACTOR_TVM_V1.md) |

## What is not done

- **Gate D is not passed**: no pilot with an outside buyer, an independent
  provider and an independent verifier has run ([runbook](spec/docs/GATE_D_EXTERNAL_PILOT.md)).
- **As of 2026-11-21 the epoch-7 test network is stopped**
  ([operator statement](spec/deployments/public-testnet-epoch7-stopped-20261121.json),
  not independently verifiable); the paid-work, pilot and Gate C records
  above were made on it.
- **Gates E, F and G are not accepted**: the onboarding runbooks are
  escrow-era, and no independent gateway, recurring paid use or production
  evidence exists.
- **Only software work can be sold**; model inference, data APIs and GPU
  markets are behind the locked expansion gate.
- **The Guarantor and other incubation profiles are not enabled or
  accepted**, though specified and tested ([roadmap 8.1](spec/docs/ROADMAP.md)).
- **No chain-side collateral verification exists**: only the verifier
  interface is defined ([report, section 6](spec/docs/AGENT_GUARANTOR_SERVICE_V1_IMPLEMENTATION_REPORT.md)).
- **No independent security review of the Service Actor contract is
  recorded**, and the team operated every relay and validator endpoint used.

## Start here

| I want to… | Read |
|---|---|
| buy a service from Claude Code or Codex | [`MCP_BUYER_GUIDE.md`](spec/docs/MCP_BUYER_GUIDE.md) |
| offer a service | [`provider/README.md`](provider/README.md) (`tos-service-provider`), and [`MCP_PROVIDER_GUIDE.md`](spec/docs/MCP_PROVIDER_GUIDE.md) to operate it from Claude Code or Codex; the `GATE_E_*_ONBOARDING.md` runbooks are escrow-era, not current |
| understand the protocol | [`spec/README.md`](spec/README.md) and its required reading order |
| see status and gates | [`ROADMAP.md`](spec/docs/ROADMAP.md) |
| check the evidence | [`spec/deployments/`](spec/deployments/README.md) |

## Layout

| Directory | Contents |
|---|---|
| `spec/` | Normative product and protocol specification: documents, the `tos.service.v1` schema, JSON schemas, manifests, frozen test vectors and deployment evidence records |
| `protocol/` | Protocol boundary: generated Connect API, Agent and Capability state machines, finalized chain reads, SDKs, the private service RPC and tools |
| `gateway/` | Stateless public gateway: transport authentication, forwarding, discovery and retrieval; it holds no business authority |
| `execution/` | Local execution base: fail-closed container execution bound by an Accepted Quote, and the evidence it produces for on-chain receipts |
| `messenger/` | Agent-native Messenger: identities, conversations, groups (with the OpenMLS driver in `messenger/rust/openmls-driver`), mailboxes, public channels and encrypted attachments for Agents |
| `provider/` | The Service Actor rail node: the selling side (setup, offer, preflight, relay and direct carriage, execution through the executor service, receipts, status and withdrawal) and the rail's buyer counterpart, which the two-sided node and the tests use; ships the library and the `tos-service-provider` program ([`provider/README.md`](provider/README.md)), which has not yet served a paid call on a public network |

The public gateway, the executor service, the Messenger daemon and the
protocol library remain separate programs. `make boundary-lint` enforces that
`gateway/` does not import `execution/`, that `protocol/` imports neither,
that `messenger/` imports `protocol/` only, that `provider/` imports
`protocol/` and `execution/` only, and that nothing imports `messenger/` or
`provider/`.

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
