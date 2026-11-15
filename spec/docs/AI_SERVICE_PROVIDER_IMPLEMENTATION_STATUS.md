# TOS AI Service Provider — Implementation Status (WP-01)

**Status:** implementation and local-integration record for
[AI Service Provider Requirements V1](AI_SERVICE_PROVIDER_REQUIREMENTS_V1.md).
It is not acceptance evidence: it changes no roadmap gate, and every item below
still needs the independent, current-domain evidence that WP-07 and Gates D–G
require.

**Date:** 2026-11-15

To try the delivered commands as a buyer or provider, see
[Getting Started](AI_SERVICE_PROVIDER_GETTING_STARTED.md).

Each row names the pull request, the exact head that was reviewed, and its merge
commit on `main`. "Reviewed" means a non-author review with each finding
re-checked against code and a follow-up review of the fixes; a merge is not a
release or a gate decision.

All four repositories build with Go 1.26.11 (standard-library advisory
GO-2026-6859): `openfox` #34, `tos-service-protocol` #45, `tos-service-gateway`
#25, `tos-ai` #13. Third-party advisories reported by `govulncheck` were fixed in
`tos-service-protocol` #46, `tos-service-gateway` #26 and `tos-ai` #14
(containerd v2.0.13, x/net v0.62.0, grpc v1.83.2, x/text and others);
`govulncheck -show verbose ./...` reports no vulnerabilities in any of the four
at those merges. The containerd upgrade has not been run against a live daemon.

## Work packages

| Work package | Pull request, reviewed head, merge | What it delivers | Verification | Review | Open follow-ups |
|---|---|---|---|---|---|
| WP-02 onboarding and publication | `tos-service-protocol` #44, `dcdd5a0`, merged `b5503e9` | Owner-private, versioned publication journal (prepared → signed → submitting → submitted → finalized → cataloged, plus ambiguous); restart never rebuilds, re-signs or relays a different action; per-record relay lock so a live relay is never taken over; pre-signing preview of every PRV-04 field with explicit unknown/absent/mismatch status; pinned actor release refused before anything is journaled | `make verify` (33 packages, conformance); restart at every phase; real SIGKILL tests inside the relay and with a live second process; 25 first-round mutations and every mutation of the review fixes killed, except one CLI-only fallback with no Gateway end-to-end test | Approved after one round of fixes (1 medium, 7 low) | No end-to-end CLI test against a Connect Gateway; transport binding, publication fee estimate and actor-owner ↔ Agent binding are shown as unknown because no resolver exists for them |
| WP-03 bounded provider execution | `tos-ai` #12, `36ed06d`, merged `3bcbd43` | `software-work-execute paid`: execution only through railgate Admit → pre-execution check → Run → Complete/Fail, distinct exit codes (completed, refused, already taken, not pending now, ambiguous, not admitted, execution failed, refused before execution, unavailable); the sandbox runs under exactly the manifest's CPU, memory, scratch, output and wall-clock limits, and out-of-range manifests are refused before admission; Receipt hash bound to the exact job and result; content-addressed artifact retention with pending records, holds and a crash-safe tombstoned sweep that always makes progress; a record cap on deadline-bearing jobs checked before paid admission; retention lock waits bounded by the deadline slack; `artifacts-gc` operator command | `make verify` on Go 1.26.11; 57 mutations killed; railgate fixtures for every status; tests re-run on the tree merged with current `main` | Approved with nits after four review rounds, including two GitHub Codex findings (manifest limits, GC at the record bound) and one regression they introduced (default-mode jobs exhausting the cap) | Default mode with `--retain-until` on a full store fails after the run (a rerun is safe); leaked pending files slow sweeps without limit; OpenFox should pass `--retain-until` so default-mode objects become collectable; a live paid run through the private containerd now passes (see M1), but only on one host; no shared multi-worker slot store (EXE-02) |
| WP-04 public interfaces | `tos-service-gateway` #24, `1a85d36`, merged `1327c3e` | Public Native, DNS alias and discovery Connect services capped at the advertised 1 MiB (raw and decoded), 10 s body read deadline, one shared limiter for global and per-client concurrency and rate, clients keyed by the loopback TLS terminator's header (right-most `X-Forwarded-For` by default), IPv6 by /64, overflow bucket instead of refusal, bounded configuration | `make verify`; 30 mutations killed | Approved with nits after two rounds (round one blocking: every caller shared one bucket behind the terminator) | Eviction is linear in the client table while it is full (bounded); Intent Carrier still has body caps only |
| PRV-01/05/06 operator experience | `openfox` #33, `a9aae30`, merged `d8749bf` | `openfox earning service preflight`: 26 side-effect-free checks with a versioned JSON report (pins, permissions, endpoints and genesis, registry/actor/attestor state, clock skew, signer probe that cannot sign); `status` with per-request operator states derived only from finalized evidence (anything uncertain is `outcome_unknown`) and credited revenue labeled apart from wallet receipt; durable `pause`/`resume` of new admission with a separate bound for held tasks | `go test -race` of both touched packages (re-run independently); 36 mutations killed | Approved with nits after one round of fixes (1 medium, 7 low) | Withdrawal submission and finalization are tracked since `openfox` #35 (below); wallet credit is still not verified; pausing stops local admission only, so funded calls during a pause fall to refund unless the owner changes the actor policy |
| WP-06 buyer budgets | no change needed | PAY-01's budgets are met by existing `buyersdk` reservation with one combined amount cap: a per-call maximum, plus one total over a rolling window (24 h for a daily budget) that also counts every outstanding call whatever its age | Code reading of `pkg/buyersdk/service_actor_journal.go` (`reservation`, `fitsBudget`), confirmed by the non-author review of this record | Reviewed in spec #74 | A separately configurable outstanding-amount cap (today outstanding and window spend share one total; OpenFox's open-purchase cap bounds a count); one purchase identity across more than the Agent Packet transport |
| OpenFox front door (one entry point for provider and buyer) | `openfox` #35, `122de0e7`, merged `512d3f5d` | `openfox earning service` as the one entry point for selling and buying: `init` (tosctl pin, derived and cross-checked network domain and registry code hash, packet controller, Agent registration, rail configuration), `offer` (attestor controller, Service Actor deployment, manifest, Capability registration, `update-policy`, verification with the preflight's chain checks, offer file), `withdraw` (`--amount`, `--all`, recorded before sending, resolved from the finalized transaction with its query id; `--acknowledge` closes an undecidable record on the owner's word), `buy --offer` (Quote Proposal package built locally from finalized state and the offer file, no Gateway), and a same-host, same-user direct packet transport (`init --direct-peer`). Every signature and send goes through one sealed, pinned tosctl runner; `init`, `offer` and `withdraw` create, sign or send nothing without a preview and `--yes`; `buy` pays without confirmation unless `--confirm-above` is set; one journal makes `init` and `offer` restartable without a second Agent, actor or Capability; one run at a time per state directory; only V3R2, V4R2 and V5R1 wallets send | `go test -race -tags goolm,stdjson` of `pkg/servicebridge` and `cmd/openfox` at `122de0e7`, including tests against the real tosctl; SIGKILL at every chain step of `init`, `offer` and `withdraw`; 87 mutations killed in the first round (3 not killed, each explained in the pull request) and 47 of 47 for the review and live-run fixes, per the pull request; CI green (Linter, Security Check, Tests, Integration Tests); live local two-node run (below) | Approved after three non-author rounds (`16b4005` approve with nits, eight findings fixed; `a6eaac1e` approve; `122de0e7` approve); GitHub Codex P1 (concurrent setup runs) and P2 (preflight peer status) fixed | Closed: with a root-only container runtime the whole provider node, tosctl and vault included, ran as root; it now runs as an ordinary user (provider privilege boundary, next row). Still open: Messenger carriage between hosts has not been run between two nodes; no command exports the bought artifact; re-running `init` must restate every flag; several `init` inputs could be derived from the offer file or the tosctl configuration; wallet credit after a withdrawal is not verified; no command closes a purchase whose call never landed (it holds its budget and open-purchase slot indefinitely); re-running `init` with `--allow-provider` drops a previously set `--confirm-above` unless restated (code follow-up: preserve the existing policy on re-run); `buy` has no preview step, unlike `init`, `offer` and `withdraw` |
| Provider privilege boundary (the provider node runs as an ordinary user) | `tos-ai` #16 (executor service), head `d4647191`, merged `619084c`; `tos-ai` #17 (`Gate.Reconcile`), head `1930f7db`, merged `274e7ee`; `openfox` #36, head `3c5ac8be`, merged `c71a334c` (tree identical to the head) | `software-work-executord`: a root-run service, the only process that opens the private containerd socket, offering exactly one allowed uid (`TOS_EXECUTOR_ALLOWED_UID`) one operation over `/run/tos-service-executor/executor.sock` (`root:<group> 0660` in a `0750` directory). A request carries the source archive, four digests and limits that may only tighten the frozen preset, and no path, image, command, mount, network, device or user. The service is idempotent per execution id and never reruns; a run outlives its caller; its journal binds an id to its limits. `tos-service-executor-gc.timer` sweeps the service's store hourly. `Gate.Reconcile` completes a slot left ambiguous by a restart from a freshly verified request and the recorded outcome's response hash, so the gate keeps "an ambiguous slot is never attested". OpenFox: `provider.executor_socket` (exactly one of it and the earlier `executor_binary` group), `offer --executor-socket`, defaulting to the service socket and failing closed before anything is signed unless root serves it, it is ready and it runs the manifest's image and limits; a socket runner that verifies every outcome and its object bytes itself and keeps its own copy for delivery and retention; requests recorded `executing` and re-asked with identical limits; after a restart the outcome goes through `Gate.Reconcile` before `respond`; a task the service cannot run before admission waits without using handling attempts (at most one hour, or less when the inbox's shared held-task bound is reached); `preflight` checks `executor.service`, `executor.image`, `executor.limits`, and fails `process.user` for a root node that uses the socket | OpenFox: `go test -race` of `pkg/servicebridge` and `cmd/openfox`, the new tests also `-count=5`, `pkg/earning` with and without `-race`, golangci-lint on the diff, 74 of 75 mutations killed (the survivor is a redundant offer check), per the pull request; SIGKILL of the provider node during a run, recovered through `Gate.Reconcile`; live local run in socket mode (below) | Non-author agent reviews delivered in-session, not GitHub approvals. `tos-ai` #16: security review round 1 at `c2a2d5b` requested changes (11 findings, no privilege escalation); round 2 at `4533786` approved (all 11 closed); a live install under the real unit then found every job failing at container creation (a client-side snapshot mount forbidden by `CapabilityBoundingSet` and `SystemCallFilter`), fixed in `f1aab3c` without relaxing the sandbox, round 3 approved; `d464719` (collection `--limit 128`, deploy text and one pinned test value) checked by the coordinator; GitHub Codex P2 (retention-slot reservation) fixed in `c57a678` with a reply. `tos-ai` #17: approved at `ce86fd8`; `1930f7d` is a comment-only correction that review requested. `openfox` #36: two reviews approved (`6a2cc0f7`, then `6a2cc0f7..3c5ac8be`); GitHub Codex P2 (an executor outage before admission used up a task's handling attempts) fixed in `578808bf` | see [Open follow-ups of the privilege boundary](#open-follow-ups-of-the-privilege-boundary) |

## M1 — local settlement lifecycle

Local integration evidence only: one host runs every validator and endpoint,
so none of it qualifies as public or independent acceptance. Each run boots a
fresh three-validator ML-DSA-44 network from the operator's `tos` checkout at
`5af405dcb` (operator-asserted; the records bind the build by path and the
tosctl binary by digest, not the tos commit) (tosctl sha256
`6de21cb2…`, Service Actor release code hash `…d63e09428e42aa0c`) and drives
the real `tosctl agent service` and `tos-service-buyer` commands through
`tos-service-protocol` `scripts/service-actor-buyer-e2e.sh` (PR #47).

| Record | What it proves | Script commit | Result |
|---|---|---|---|
| [`local-service-actor-provider-m1-20261114.json`](../deployments/local-service-actor-provider-m1-20261114.json) | **M1 record.** `E2E_LIFECYCLE=1 E2E_EXECUTE=1` in one run, 13:33–15:37 UTC, with the checks hardened by the review of PR #47: real paid execution and its attested Receipt, rerun and failing-test controls; crash before broadcast (the buyer's whole process group killed, no request created) and after broadcast (journal resolved to `admitted`, settled once); `withdraw_revenue`; after the real one-hour deadline `expire` and `claim_refund` for the lifecycle request and for the request whose execution failed; after the real refund-claim deadline `sweep_expired_request`. Every payout is checked against its payout message value and every wallet reconciles exactly | `3eb4dd3` (clean tree; merged as `49a2571` via PR #47, whose head `95f203a` differs only in comments) | ALL PASS, 66 of 66 |
| [`local-service-actor-settlement-lifecycle-20261114.json`](../deployments/local-service-actor-settlement-lifecycle-20261114.json) | `E2E_LIFECYCLE=1`, 09:47–11:50 UTC: crash before broadcast (no request, quarantined as ambiguous, never re-sent, no funds moved); crash after broadcast (one finalized call resolved, never re-sent, settled once); `withdraw_revenue`; after the real one-hour deadline `expire` then `claim_refund` (price returned, storage fee credited to the provider); after the real refund-claim deadline `sweep_expired_request` (the payout message carries exactly the price, the provider is credited storage fee less bounty, the sweeper receives the bounty) | `8e6e50f` (tree state not recorded; the clean-tree check was added later) | ALL PASS, 38 of 38 |
| [`local-service-actor-paid-execution-20261114.json`](../deployments/local-service-actor-paid-execution-20261114.json) | `E2E_EXECUTE=1`: the provider runs `software-work-execute paid` (executor sha256 `26801be5…`, built from tos-ai `3bcbd43` — the commit is operator-asserted, the digest is recorded) against the private containerd with the frozen image `sha256:9624bca7…`; railgate admits the finalized request, the buyer's Go module is tested in the sandbox, the attestor's check anchors every Receipt binding to the finalized request snapshot, and the buyer resolves exactly that Receipt hash; reruns while pending and after respond are refused with the slot and journal unchanged; a failing test ends `execution_failed` and is never responded; every wallet involved reconciles exactly | `ef3c03c` (clean tree) | ALL PASS, 37 of 37 |

The two earlier records are kept as supporting runs: the settlement-lifecycle
record predates the review of PR #47, whose fixes replaced its bounded refund
and withdrawal checks with exact payout-message checks and made the
crash-before-broadcast case kill the whole buyer process group; the
paid-execution record covers the execution phase alone. A combined run at
`f97420b`, before those fixes, also caught a test-ordering defect (the
failed-execution refund was attempted after its refund window had closed,
which the contract correctly refused), fixed in `3eb4dd3` before the M1 record.

The private containerd host deployment used for these runs was installed from
`tos-ai` `deploy/provider` and surfaced three defects that are fixed in
`tos-ai` #15 (socket mode, layer-root permissions under the unit umask, and
the digest-qualified image name); the live backend conformance suite now passes
on containerd v2.0.13.

## OpenFox front door — local two-node sale

Local integration evidence only. One host runs every validator, every
endpoint and both nodes, and both nodes run as root (the legacy single-user
mode, before the privilege boundary below), so it does not qualify as public
or independent acceptance.

| Record | What it proves | Script commit | Result |
|---|---|---|---|
| [`local-openfox-front-door-20261115.json`](../deployments/local-openfox-front-door-20261115.json) | `openfox` `scripts/service-front-door-e2e.sh`, 2026-11-14 23:59 to 2026-11-15 00:03 UTC, on a fresh three-validator ML-DSA-44 network (`tos` `5af405dcb`, tosctl sha256 `6de21cb2…`, executor sha256 `26801be5…`, Service Actor release code hash `…d63e09428e42aa0c`, V3R2 wallets). A complete paid sale between two nodes with `openfox earning service` commands only, apart from wallet creation, funding and activation, staging, and the private container runtime: `init` and `offer` without `--yes` send nothing; provider `init`, `offer`, `preflight`, `serve`; buyer `init --allow-provider --direct-peer`, `serve`, `buy --offer`; the job runs in the private containerd sandbox; exactly one request on chain, called by the buyer wallet with price, storage fee and allowance and responded by the provider wallet; the response hash on chain equals the Receipt hash both nodes report and is the hash of the Receipt cell; the received artifact hashes to the artifact digest in the Receipt; `withdraw --all` finalized and its first payout message carries exactly the amount to the owner wallet; `init` and `offer` run again cause no transaction on any wallet, Agent, actor or Capability; a tampered offer file is refused before payment, also with its digest recomputed; a paused provider holds a second purchase unexecuted and serves it after `resume`. Every chain fact is read by the script from the validators' JSON-RPC, not taken from an OpenFox report | `122de0e7101183b78ad8ff7ac5471c6b3fdac8d4` (clean tree: `openfox_tree_dirty` false) | ALL PASS, 36 of 36; `qualifies_as_public_acceptance: false` |

The record lists every program that ran as root (`ran_as_root`) and why
(`root.why`): the executor accepts only a runtime socket its own user owns,
OpenFox runs the executor as its own child, and the direct transport joins
nodes of one user. The provider's `preflight` passed with `process.user` at
`warn` and `rpc.independence` and `signer.wallet` at `unknown`
(`preflight_not_passing`). The buyer's `serve` logged one finalized read that
missed its quorum in time and completed the purchase on a later round.

Not covered by this record:

- the Messenger transport, and nodes on different hosts;
- a refund (the contract's minimum deadlines are one hour; the M1 record
  covers `expire`, `claim_refund` and the sweep with the manual tools);
- `withdraw --acknowledge` (unit tests only);
- `buy` without `--yes` and the `--confirm-above` prompt (the run always
  passed `--yes`);
- V4R2 and V5R1 wallets;
- a provider node that does not run as root (covered by the next record).

## OpenFox provider node as an ordinary user — local two-node sale

Local integration evidence only. One host runs every validator, every endpoint
and both nodes, so it does not qualify as public or independent acceptance.

| Record | What it proves | Script commit | Result |
|---|---|---|---|
| [`local-openfox-unprivileged-provider-20261115.json`](../deployments/local-openfox-unprivileged-provider-20261115.json) (sha256 `2429756a590b8993c517713fc8bf08f35d229203ea0fa86a83f6e7654b4a1771`, copied byte for byte) | `openfox` `scripts/service-front-door-e2e.sh` with `E2E_EXECUTOR_SOCKET`, 2026-11-15 03:55 to 03:58 UTC, on a fresh three-validator ML-DSA-44 network (`tos` `5af405dcb`, tosctl sha256 `6de21cb2…`, Service Actor release code hash `…d63e09428e42aa0c`), `executor_mode` `executor service socket`. Both nodes run as the same ordinary, non-root user and the run uses no root command (`ran_as_root` is empty); the provider executes through the installed executor service and reads none of its files. The same sale as the front-door record: `init` and `offer` without `--yes` send nothing; provider `init`, `offer` (with `--executor-socket`), `preflight`, `serve`; buyer `init --allow-provider --direct-peer`, `serve`, `buy --offer`; exactly one request on chain, called by the buyer wallet and responded by the provider wallet with the Receipt hash both nodes report; the received artifact hashes to the artifact digest in the Receipt; the provider holds the verified objects of exactly one execution, the purchase's; `withdraw --all` finalized with exactly the amount; `init` and `offer` run again change nothing on chain; a tampered offer file is refused before payment; a paused provider holds a second purchase and serves it after `resume`. Ownership in the record is numeric, and the run fails if the invoking user's login name or home path appears in it or in its transcripts and logs | `3c5ac8beecdbb19035628f184a290a516f7e3577` (clean tree: `openfox_tree_dirty` false; its tree is the tree of merge `c71a334c`) | ALL PASS, 37 of 37; `qualifies_as_public_acceptance: false` |

The provider's `preflight` passed with only `rpc.independence` and
`signer.wallet` not at `pass` (both `unknown` by design,
`preflight_not_passing`); `process.user` passed. Neither `serve` logged a line
other than pause notices. The executor service on that host was installed by
the operator from `tos-ai` `619084c` following `deploy/provider/README.md`;
the record does not bind the service's binaries (their digests are
operator-asserted). `tos-ai` `main` has since moved to `274e7ee`, which
changes only `pkg/railgate`. The installed daemon does not link it; the
collection command `software-work-execute` does, but its `artifacts-gc` path
does not use it.

Not covered by this record:

- a restart of the provider node during a run, and an executor outage before
  admission (unit tests only, against the service's own server on a fake
  container runtime);
- more than one job at a time, load, or a long soak of the executor service;
- the Messenger transport, nodes on different hosts, and a refund.

### Open follow-ups of the privilege boundary

- When admission is paused and the executor service is down at the same time,
  the inbox's held marker keeps the first cause (review note, deferred).
- A duplicate task that arrives while the executor service still cannot run
  it is only logged, not held; the buyer's next delivery tries again (review
  note, deferred).
- A crash between the rail gate's admission and the provider's own record
  still loses the request to the buyer's refund path.
- An object stored for an execution but not yet given its retention deadline
  when the request is abandoned is never swept from the node's store.
- The production client's check that root serves the socket has been
  exercised only in this live run; the unit tests serve the socket as the
  test user.
- The executor service has not been run under load or with
  `--max-executions` above 1.
- Retention of the service's copy: the `tos-ai` runbook says a provider
  runtime should ask the service to keep its copy until the end of the
  response window plus the manifest's `retention_seconds`, while OpenFox asks
  only until the response deadline and serves results from its own copy.
  Both are safe; one of the two should be aligned with the other.
- Carried over from the front door, unchanged: Agent Packet carriage between
  hosts through the Messenger, a `buy` preview step, keeping `--confirm-above`
  when `init` is re-run with `--allow-provider`, and a command that closes a
  purchase whose call never landed (see
  [Not delivered by these changes](#not-delivered-by-these-changes)).

## Repository consolidation

`tos-service-spec`, `tos-service-protocol`, `tos-service-gateway` and `tos-ai`
were merged into `tosnetwork/ai` as `spec/`, `protocol/`, `gateway/` and
`execution/`, with their full history (every original commit keeps its SHA;
the mapping is in [`deployments/README.md`](../deployments/README.md#former-repositories)).
The move changes paths only. Binary names, the `tos.service.v1` schema, protocol
domains and signing domains are unchanged.

| Change | Pull request, reviewed head, merge | What it does |
|---|---|---|
| Protocol pins aligned first | `tos-service-gateway` #27 (merge `4561e4ac`), `tos-ai` #18 (merge `9e0728c8`) | Both raise their `tos-service-protocol` requirement to `49a25714`, the protocol import point, so the single module changes no protocol code for any component |
| Import | `ai` #2, head `1d2695ee`, merge `ba76780b` | Import commits `c252b68` (spec at `a67148cc`), `0cec503` (protocol at `49a25714`), `446a6cf` (gateway at `4561e4ac`), `cf1b38f` (tos-ai at `9e0728c8`); scripted import-path rewrite; one root `go.mod`; regenerated `protocol/gen`; root `make verify` and CI; boundary lint; relative links |
| Messenger switch | `tos-messenger` #36, head `f4b12df1`, merge `57d96473` | Imports `ai/protocol` instead of `tos-service-protocol`; x/text v0.43.0 fixes GO-2026-5970, which govulncheck reported as called before |
| OpenFox switch | `openfox` #37, head `66b8b4c3`, merge `03a256e1` | Imports `ai/protocol` and `ai/execution` instead of `tos-service-protocol` and `tos-ai`, and uses messenger `57d96473` |

Gates, all run locally:

- **Import:** each import commit's subtree equals the source tree at its import
  point. Re-running `scripts/rewrite-imports.sh` reproduces the rewrite commit.
  The `protocol/api` descriptor is unchanged apart from `go_package`, and
  `spec/proto` matches it. 80 frozen vector, golden, fixture, schema, manifest
  and evidence files are byte-identical to the sources.
- **`ai`:** `make verify` (with `-race` and the pinned tosctl) passes the same
  65 test packages as the three source suites at their import points. `--help`
  of all 23 `cmd/` binaries and 13 subcommands is unchanged. The boundary lint
  passes on host, windows, darwin and a textual import scan, and goes red on a
  forbidden import in a windows-only file. `govulncheck` reports nothing.
- **Consumers:** messenger: the same 67 packages pass `make verify`, and
  `--help` of its 18 binaries is unchanged. OpenFox: the same 107 packages pass
  the CI test form; the `-race` run passes the same 106 packages and fails the
  same one as `main`. Neither consumer links an old module path. Only
  `ai/protocol/gen/tos/service/v1` registers `tos/service/v1/native.proto`.
- **Dependency weight:** no container-runtime module of `execution/` is linked
  into a consumer binary. The consumers' binaries shrink slightly (messenger
  −204,512 bytes over 18 binaries, OpenFox −172,301 bytes over 11), so `ai`
  stays one module.

Two runs rebuilt from the merged code. Both are local integration evidence
only: one host runs every validator, every endpoint and both nodes, so neither
qualifies as public or independent acceptance.

| Record | What it proves | Code | Result |
|---|---|---|---|
| [`local-service-actor-paid-execution-ai-20261115.json`](../deployments/local-service-actor-paid-execution-ai-20261115.json) (sha256 `606b3e704c8e8e424098702808be3c4edb92d3fa0ef89d7f291b45dc6222a9ba`, copied byte for byte) | `protocol/scripts/service-actor-buyer-e2e.sh` with `E2E_EXECUTE=1` (short form, no `E2E_LIFECYCLE`), 2026-11-15 07:49 to 07:51 UTC, on a fresh three-validator network (tosctl sha256 `6de21cb2…`, Service Actor release code hash `…d63e09428e42aa0c`). Paid execution through the legacy root command, with `software-work-execute` built from `ai` `execution/cmd/software-work-execute` (sha256 `0dbe3749…`) | `ai` `ba76780b` (clean tree: `protocol_tree_dirty` false) | ALL PASS, 37 of 37; `qualifies_as_public_acceptance: false` |
| [`local-openfox-front-door-ai-20261115.json`](../deployments/local-openfox-front-door-ai-20261115.json) (sha256 `23024529fa929cfde72ef1a20e69f126c15d5bcf0531c4115192b17c27e98463`, copied byte for byte) | `openfox` `scripts/service-front-door-e2e.sh` with `E2E_EXECUTOR_SOCKET`, 2026-11-15 07:45 to 07:49 UTC (`tos` `5af405dcb`, the same tosctl and code hash), `executor_mode` `executor service socket`. Both nodes run as an ordinary user and no root command is used (`ran_as_root` empty). The operator reinstalled the root executor service from `ai`-built binaries (`software-work-executord` sha256 `8fef5233…`, `software-work-execute` `0dbe3749…`); the unit files were byte-identical to `execution/deploy/provider` at `ba76780b` (only their `Documentation=` URL has changed since). The record binds only the `openfox` and `tosctl` digests, so the service binaries are operator-asserted | `openfox` `66b8b4c3` (clean tree; its tree is the tree of merge `03a256e1`) | ALL PASS, 37 of 37; `qualifies_as_public_acceptance: false` |

An earlier paid-execution attempt ran at the same time as the front-door run
and failed 4 of 37 checks. The legacy command refused a private containerd
namespace that held the executor service's containers ("containerd backend
namespace is not clean"), so the failure was fail-closed. That attempt is not
evidence.

### Open follow-ups of the consolidation

- The legacy root command and the executor service must not share the private
  containerd namespace at the same time. Run them one after the other, or give
  them separate namespaces; this is an operator note until a guard exists.
- `spec/scripts/run-openfox-autonomous-earning-three-node.sh` names packages
  that no longer exist (`execution/pkg/messengereventbridge`,
  `protocol/pkg/executiongate`, `protocol/pkg/paiddemand`). This predates the
  move (review of `ai` #2). Update the package lists or retire the script.
- Gateway: a Quote profile whose Agent Packet transport names another Agent
  loads at startup, but every quote request then fails as a retryable
  dependency error (`tos-service-gateway` #27). A startup check would refuse it
  early.
- `tos-messenger` CI (`verify`) has been red on `main` since `22d8c4e`
  (2026-11-08). The sandboxed attachment-scanner tests fail on the GitHub
  runners; the local `make verify` passes.
- OpenFox `main`: a data race in `web/backend/api`
  (`TestStartGatewayLocked_ForwardsWildcardHostForPublicLauncher`) under
  `-race`. CI does not run `-race`.
- `tos-messenger` still mentions `tos-service-protocol` in prose (three places:
  `docs/AGENT_PACKET_BRIDGE.md`, `pkg/chainagent/resolver.go`,
  `pkg/payload/agent_gift.go`).
- Two stale references predate the move and were left unchanged by it:
  `spec/docs/GATE_E_BUYER_ONBOARDING.md` names
  `tos-service-protocol/pkg/toschain.StablecoinResolver`, which no longer
  exists, and `spec/deployments/README.md` and `spec/docs/ROADMAP.md` name
  `native-safe-handoff-pack` and `native-safe-handoff-check`, which are not in
  `protocol/cmd`. Correct or remove them in a separate change.
- Planned later, each as its own reviewed change: make `spec/proto` the single
  schema source and remove `protocol/api`, and reconcile the diverged copies of
  `internal/osguard` and `internal/actionauthoritytest`.

## Agent Packet Relay — sale through a relay daemon, nodes in separate network namespaces

Local integration evidence only. Everything runs on one physical host. The
buyer, the provider and the relay are separated by Linux network namespaces
and firewall rules, not by machines. The relay is operated by the run itself,
and no internet path exists. So this does not qualify as public or
independent acceptance, and it is not Gate O evidence (relay spec section 12).

| Record | What it proves | Script commit | Result |
|---|---|---|---|
| [`local-openfox-relay-loopback-20261115.json`](../deployments/local-openfox-relay-loopback-20261115.json) (sha256 `228648e3d0e3b9586132c6e031775e6d76aace28ab4976eb0b08b5448359611a`, copied byte for byte) | `openfox` `scripts/service-front-door-e2e.sh` with `E2E_RELAY_URL=http://127.0.0.1:49960` and `E2E_EXECUTOR_SOCKET`, 2026-11-15 14:18 to 14:22 UTC (`tos` `5af405dcb`). The front-door sale with both nodes on one user and one network stack, carried only by a `tos-service-packet-relay` daemon process on loopback (built from `ai` `c957c17b`; plain HTTP, which the relay allows only on loopback) instead of the direct transport. The offer file carries the provider's key card, both nodes name the relay and no direct peer, and the provider's envelopes were accepted by the relay. The first run of this mode found an `openfox` defect: `preflight` failed `relay.card` on every relay node because its checkpoint fences were deleted before the relay checks ran. It is fixed in `openfox` `92dbf349` (tosnetwork/openfox#40) | `openfox` `92dbf349` (clean tree) | ALL PASS, 40 of 40; `qualifies_as_public_acceptance: false` |
| [`local-openfox-relay-two-host-20261115.json`](../deployments/local-openfox-relay-two-host-20261115.json) (sha256 `d173c45bd2b408aba13d6ec1b0a84deaf4ea6d71fa50ae6066a5e2d3450b70a2`, copied byte for byte) | `openfox` `scripts/service-relay-two-host-e2e.sh`, 2026-11-15 14:43 to 14:46 UTC (`tos` `5af405dcb`, tosctl sha256 `6de21cb2…`, relay daemon built from `ai` `c957c17b` with sha256 `f8ff662f…`). The setup: the buyer, the provider and the relay daemon run in three network namespaces on a private bridge with no default route. The chain stays in the host namespace on 127.0.0.1 and is reached only through explicit forwarders: on the bridge's host end, and on each node namespace's loopback. Every node, relay and forwarder process runs as the same ordinary uid. **Isolation.** A listener in each node namespace is reachable from the other node before the firewall rules and times out after them, in both directions. A node reaches neither host services nor the internet, and the relay namespace cannot reach the chain. Each node sees the other node's directory, the run's private files and the relay state as empty. **TLS.** The relay serves TLS on its namespace address under a certificate authority generated for the run. The nodes trust only that authority (`SSL_CERT_FILE` plus an empty `SSL_CERT_DIR`; verification on), and a preflight with an unrelated authority cannot reach the relay. **Sale.** Relay only: no direct peer and no Messenger socket. One paid sale with the front-door checks: exactly one request on chain, the Receipt hash on chain and on both nodes, the artifact digest inside the Receipt, and exactly one execution. **Outages.** The relay daemon is stopped by SIGTERM while it holds the task, the provider's polls fail, and after a restart on the same state directory the relay still holds the task. It is stopped again as soon as the provider acknowledged the task: the provider responds on chain while its result deposits fail and stay journaled, and after the restart the courier's retry delivers the result. **No plaintext.** No file the relay wrote contains the source archive, the artifact, the buyer wallet address or the Quote package. That includes copies of its state taken while it held the task and while it held the result. The search is shown to find each of these in a control file, and the relay log names no Agent and no client address. **Root.** Only the namespace, firewall and teardown commands and namespace entry ran as root (`ran_as_root`); uid and gid are recorded numerically | `openfox` `5d4ceb39` (clean tree; tosnetwork/openfox#41, stacked on #40) | ALL PASS, 56 of 56; `qualifies_as_public_acceptance: false` |

The relay spec's section 12.1 marks the acceptance items these records cover.

Not covered by these records:

- two physical machines, an internet path, or a relay operated by anyone but
  the run itself;
- a second relay in the card carrying traffic while the first is down;
- live adversarial cases: tampered, forged, foreign and replayed envelopes,
  quota pressure, and the section 8.6 public-ID race. No live adversarial run
  was performed. The two-host record lists by name the merged in-repository
  tests that cover them (`protocol/pkg/agentpacketrelay`,
  `protocol/pkg/agentpacketseal`, `openfox` `pkg/servicebridge`);
- key expiry and rotation, covered by unit tests only (listed by name in the
  record);
- crash windows of the nodes (relay spec section 12 item 3);
- a per-relay certificate authority option in OpenFox: a relay with a private
  authority currently needs the system trust store or `SSL_CERT_FILE`.

A run of the two-host script at the same commit, before the recorded one,
failed `buy` with `Quote Capability is not available from finalized state`.
`buy` and the buyer's `serve` share the state directory's monotonic registry
checkpoint fence. `buy` checks the offer and builds the Quote at one pinned
finalized checkpoint, so when `serve` commits a newer checkpoint in between,
the second registry read at the pinned checkpoint is refused as a regression.
`quoteprovider.RequestQuoteProposal` reports any read error as "not
available", so the cause is not visible. This is an open follow-up for both
repositories, not fixed by these changes.

## Not delivered by these changes

- WP-07 independent commercial acceptance: a provider and buyer outside the
  core team, independent resolution, and Gate D/E submission.
- WP-08 inference profile and adapters: locked until the expansion gate opens.
- A paid run on an independent provider host (the M1 and front-door runs each
  use one host for everything).
- Agent Packet carriage between two physical hosts, run end to end. The relay
  record above separates the nodes by network namespaces on one host.
- A `buy` preview step; keeping `--confirm-above` when `init` is re-run with
  `--allow-provider`; a command that closes a purchase whose call never
  landed.
- A command that exports a bought artifact from the buyer's state directory.
- Gate F/G operation, independent operators, and production controls.
