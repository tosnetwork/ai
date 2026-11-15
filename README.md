# TOS AI services

This repository holds the `tos_service_v1` protocol specification and the Go
implementation of the service layer on top of the TOS Network: the protocol
boundary library and tools, the stateless public gateway, and the local
execution base. Finalized TOS account state is the only authority; everything
here either specifies that state, reads and relays it, or executes work bound
by it.

## Layout

| Directory | Contents |
|---|---|
| `spec/` | Normative product and protocol specification: documents, the `tos.service.v1` schema, JSON schemas, manifests, frozen test vectors and deployment evidence records |
| `protocol/` | Protocol boundary: generated Connect API, Agent and Capability state machines, finalized chain reads, SDKs, the private service RPC and tools |
| `gateway/` | Stateless public gateway: transport authentication, forwarding, discovery and retrieval; it holds no business authority |
| `execution/` | Local execution base: fail-closed container execution bound by an Accepted Quote, and the evidence it produces for on-chain receipts |

The public gateway, the executor service and the protocol library remain
separate programs. `make boundary-lint` enforces that `gateway/` does not
import `execution/` and that `protocol/` imports neither.

## Origin

This repository supersedes four repositories. Each was imported with its full
history (every original commit keeps its SHA) at the following point:

| Directory | Former repository | Import point |
|---|---|---|
| `spec/` | `tosnetwork/tos-service-spec` | `a67148cc969d26c637bf6f88e1c3c544432c6dc0` |
| `protocol/` | `tosnetwork/tos-service-protocol` | `49a25714e971f3f5b5ad7ad3fe8915936752efd4` |
| `gateway/` | `tosnetwork/tos-service-gateway` | `2dae45404d3cab91589664da1549458a50765147` |
| `execution/` | `tosnetwork/tos-ai` | `274e7ee47c73005205e24666a3b256086a44443c` |

Go import paths changed by prefix only:

| Former module | Package path here |
|---|---|
| `github.com/tosnetwork/tos-service-protocol` | `github.com/tosnetwork/ai/protocol` |
| `github.com/tosnetwork/tos-service-gateway` | `github.com/tosnetwork/ai/gateway` |
| `github.com/tosnetwork/tos-ai` | `github.com/tosnetwork/ai/execution` |

Evidence records under `spec/deployments/` are hash-pinned and still name the
former repositories; their commits resolve in this repository unchanged.

## Build and test

The repository is one Go module (`github.com/tosnetwork/ai`, Go 1.26.11).

```bash
make verify
```

runs format, schema, vet, race-enabled tests, build, conformance, boundary and
specification checks. Tests that check real ML-DSA-44 bytes need a pinned
`tosctl` helper built from `tosnetwork/tos` and fail without it:

```bash
export TOS_SERVICE_TOSCTL=/path/to/tosctl
export TOS_SERVICE_TOSCTL_SHA256=<sha256 of that binary>
```

`make test-privileged` runs the executor service's privileged suite (root and a
private containerd); it is opt-in and not part of `verify`.

## License

GPL-3.0; see `LICENSE`.
