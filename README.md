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
