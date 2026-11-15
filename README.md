# TOS AI services

This repository holds the `tos_service_v1` protocol specification and the Go
implementation of the service layer on top of the TOS Network: the protocol
boundary library and tools, the stateless public gateway, the local
execution base, and the Agent-native Messenger through which OpenFox agents
talk to each other. Finalized TOS account state is the only authority; everything
here either specifies that state, reads and relays it, or executes work bound
by it.

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

## Origin

This repository supersedes five repositories. Each was imported with its full
history (every original commit keeps its SHA) at the following point:

| Directory | Former repository | Import point |
|---|---|---|
| `spec/` | `tosnetwork/tos-service-spec` | `a67148cc969d26c637bf6f88e1c3c544432c6dc0` |
| `protocol/` | `tosnetwork/tos-service-protocol` | `49a25714e971f3f5b5ad7ad3fe8915936752efd4` |
| `gateway/` | `tosnetwork/tos-service-gateway` | `4561e4ac44a3de1245a60f81f9061ca92756dc1c` |
| `execution/` | `tosnetwork/tos-ai` | `9e0728c8e53bcd4c4c71eb02d676021e4d4d9d1b` |
| `messenger/` | `tosnetwork/tos-messenger` | `5668b3a2b5f12f8454abf35ba241eb8c454ec6cb` |

Go import paths changed by prefix only:

| Former module | Package path here |
|---|---|
| `github.com/tosnetwork/tos-service-protocol` | `github.com/tosnetwork/ai/protocol` |
| `github.com/tosnetwork/tos-service-gateway` | `github.com/tosnetwork/ai/gateway` |
| `github.com/tosnetwork/tos-ai` | `github.com/tosnetwork/ai/execution` |
| `github.com/tosnetwork/tos-messenger` | `github.com/tosnetwork/ai/messenger` |

Evidence records under `spec/deployments/` are hash-pinned and still name the
former repositories; their commits resolve in this repository unchanged.

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
