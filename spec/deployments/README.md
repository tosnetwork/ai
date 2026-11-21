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

The first `tos_service_v1` deployment record is
`public-testnet-epoch7-gate-c-20261118.json` (Gate C lifecycle on the epoch-7
public testnet, designated by the owner on 2026-11-18 as the initial
public test network for Gate C), with its labeled quorum outputs in
`artifacts/public-testnet-epoch7-gate-c-20261118/`.

`public-testnet-epoch7-gate-d-rehearsal-20261118.json` records a
same-operator public rehearsal of the paid software-work loop on the Service
Actor rail on the same network: OpenFox provider and buyer nodes on two hosts,
Quotes from the gateway, every packet carried by the installed relays, and
sales that ended responded, refunded and swept. It is not Gate D evidence
(`qualifies_as_gate_d: false`); Gate D needs an external buyer pilot.

`public-testnet-epoch7-stopped-20261121.json` is an operator statement, not
evidence: the operator stopped the epoch-7 public test network (validators
and both test relays) on 2026-11-21 (UTC), with data retained. It binds no
chain data, cannot be verified from this repository and satisfies no gate.

Evidence produced under the pre-release protocol domain is preserved unchanged
under `archive/pre-tos-service-v1/` for audit history. Because protocol-domain
strings participate in cryptographic commitments, those files cannot satisfy a
current acceptance gate and must never be relabeled as current evidence.

For a post-acceptance Gateway handoff, retain the complete Quote package and
the Receipt release output. The tools that assemble and check a portable
safe-handoff bundle (`native-receipt-release`, `native-safe-handoff-pack` and
`native-safe-handoff-check`) are not in this repository yet. Use
`safe-handoff.template.json` only as a field guide: it is not evidence. When
the tools exist, the bundle is checked against at least three validator
endpoints and an absolute durable checkpoint path while the original Gateway
is unavailable, and that JSON output is the machine-readable handoff evidence
attached to the independent operator record.

Gate G evidence must use `production-readiness-evidence.template.json` as its
starting shape. A template is never an acceptance record; it must bind exact
release commits, contract hashes, endpoint diversity, drills, reconciliation,
and operator signatures.

## Field names in records

In `local-service-actor-paid-execution-ai-20261115.json`, `protocol_commit`
and `execute.executor.tos_ai_commit` hold the `ai` commit `ba76780b` (the
latter is operator-asserted). `local-openfox-front-door-ai-20261115.json`
names its OpenFox commit; the executor service it ran against was built from
`ai` by the operator, and the record binds only the `openfox` and `tosctl`
digests.
