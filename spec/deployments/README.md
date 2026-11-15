# Native Registry Deployment Records

This directory is reserved for immutable public-network deployment evidence.
Copy `public-testnet.template.json`, replace every `REQUIRED` value with
verified chain data, and rename it to the network and deployment date. An
initial profile may use same-host endpoints only when the record declares that
operator independence and public Internet reachability are false. A mature
profile requires independently operated HTTPS endpoints. A template is never
evidence and must not be marked accepted.

Before publication:

1. reproduce the release BOC and verify every frozen vector;
2. obtain the exact network genesis hashes from endpoint quorum;
3. deploy with a funded testnet wallet using semantic confirmation;
4. resolve the first Agent account from quorum after finality; and
5. attach transaction, state, lifecycle, independent resolver, and audit
   evidence required by `docs/NATIVE_REGISTRY_PUBLIC_TESTNET_GATE.md`.

Test-only asset and lifecycle records may also live here when they bind the
exact network, contracts, code hashes, supply, holder state, transactions,
endpoint quorum, manifests, artifacts, and receipts. They must state explicitly
that they are test infrastructure and make no production reserve, issuer, or
operator-independence claim.

The directory currently contains no accepted `tos_service_v1` deployment.
Evidence produced under the pre-release protocol domain is preserved unchanged
under `archive/pre-tos-service-v1/` for audit history. Because protocol-domain
strings participate in cryptographic commitments, those files cannot satisfy a
current acceptance gate and must never be relabeled as current evidence.

For a post-acceptance Gateway handoff, retain the complete Quote package and
the output of `native-receipt-release`, then assemble the portable bundle with
`tos-service-protocol/cmd/native-safe-handoff-pack`. Use
`safe-handoff.template.json` only as a field guide: it is not evidence. Verify
the resulting bundle with `native-safe-handoff-check` against at least three
validator endpoints and an absolute durable checkpoint path. The checker must
be run while the original Gateway is unavailable; its JSON output is the
machine-readable handoff evidence attached to the independent operator record.

Gate G evidence must use `production-readiness-evidence.template.json` as its
starting shape. A template is never an acceptance record; it must bind exact
release commits, contract hashes, endpoint diversity, drills, reconciliation,
and operator signatures.

## Former repositories

The records here name the repositories they were produced in. Those
repositories were merged into this one with their full history; every
original commit keeps its SHA, so each commit a record names still resolves
here (for example `git show 3bcbd43` or `git show 3eb4dd3`). The records are
therefore unchanged and remain valid. Read a repository name in a record as
the directory in this table:

| Former repository | Commits | Directory | Import commit in `ai` |
|---|---|---|---|
| `tosnetwork/tos-service-spec` | its history up to `a67148cc969d26c637bf6f88e1c3c544432c6dc0` | `spec/` | `c252b68c3747893bf8965569611b10044d483405` |
| `tosnetwork/tos-service-protocol` | its history up to `49a25714e971f3f5b5ad7ad3fe8915936752efd4` | `protocol/` | `0cec503e0d72e7159c55eff237e03a201707c23d` |
| `tosnetwork/tos-service-gateway` | its history up to `4561e4ac44a3de1245a60f81f9061ca92756dc1c` | `gateway/` | `446a6cfa3d9181556b7ee6167bb5666a2fda294d` |
| `tosnetwork/tos-ai` | its history up to `9e0728c8e53bcd4c4c71eb02d676021e4d4d9d1b` | `execution/` | `cf1b38fcc7b16a05a9c516b081bdeedd5f465c81` |

Each import commit is a byte-exact copy of the former repository's tree at its
import point; the module paths were rewritten afterwards, in their own
commits (`tosnetwork/ai` #2, merged as `ba76780b`). Commits made after an
import point exist only in this repository.

Records produced from this repository keep the field names of the former
ones. In `local-service-actor-paid-execution-ai-20261115.json`,
`protocol_commit` and `execute.executor.tos_ai_commit` hold the `ai` commit
`ba76780b` (the latter is operator-asserted, as before).
`local-openfox-front-door-ai-20261115.json` names its OpenFox commit; the
executor service it ran against was built from `ai` by the operator, and the
record binds only the `openfox` and `tosctl` digests.
