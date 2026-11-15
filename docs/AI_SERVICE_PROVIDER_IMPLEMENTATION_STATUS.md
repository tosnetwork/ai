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
| OpenFox front door (one entry point for provider and buyer) | `openfox` #35, `122de0e7`, merged `512d3f5d` | `openfox earning service` as the one entry point for selling and buying: `init` (tosctl pin, derived and cross-checked network domain and registry code hash, packet controller, Agent registration, rail configuration), `offer` (attestor controller, Service Actor deployment, manifest, Capability registration, `update-policy`, verification with the preflight's chain checks, offer file), `withdraw` (`--amount`, `--all`, recorded before sending, resolved from the finalized transaction with its query id; `--acknowledge` closes an undecidable record on the owner's word), `buy --offer` (Quote Proposal package built locally from finalized state and the offer file, no Gateway), and a same-host, same-user direct packet transport (`init --direct-peer`). Every signature and send goes through one sealed, pinned tosctl runner; `init`, `offer` and `withdraw` create, sign or send nothing without a preview and `--yes`; `buy` pays without confirmation unless `--confirm-above` is set; one journal makes `init` and `offer` restartable without a second Agent, actor or Capability; one run at a time per state directory; only V3R2, V4R2 and V5R1 wallets send | `go test -race -tags goolm,stdjson` of `pkg/servicebridge` and `cmd/openfox` at `122de0e7`, including tests against the real tosctl; SIGKILL at every chain step of `init`, `offer` and `withdraw`; 87 mutations killed in the first round (3 not killed, each explained in the pull request) and 47 of 47 for the review and live-run fixes, per the pull request; CI green (Linter, Security Check, Tests, Integration Tests); live local two-node run (below) | Approved after three non-author rounds (`16b4005` approve with nits, eight findings fixed; `a6eaac1e` approve; `122de0e7` approve); GitHub Codex P1 (concurrent setup runs) and P2 (preflight peer status) fixed | With a root-only container runtime the whole provider node, tosctl and vault included, runs as root, and on the direct transport the buyer does too: a privilege boundary between node and executor is not built; Messenger carriage between hosts has not been run between two nodes; no command exports the bought artifact; re-running `init` must restate every flag; several `init` inputs could be derived from the offer file or the tosctl configuration; wallet credit after a withdrawal is not verified; no command closes a purchase whose call never landed (it holds its budget and open-purchase slot indefinitely); re-running `init` with `--allow-provider` drops a previously set `--confirm-above` unless restated (code follow-up: preserve the existing policy on re-run); `buy` has no preview step, unlike `init`, `offer` and `withdraw` |

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
endpoint and both nodes, and both nodes run as root, so it does not qualify as
public or independent acceptance.

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
- a provider node that does not run as root.

## Not delivered by these changes

- WP-07 independent commercial acceptance: a provider and buyer outside the
  core team, independent resolution, and Gate D/E submission.
- WP-08 inference profile and adapters: locked until the expansion gate opens.
- A paid run on an independent provider host (the M1 and front-door runs each
  use one host for everything).
- A privilege boundary between the provider node and the executor: with a
  root-only container runtime the node, tosctl and the vault run as root.
- Agent Packet carriage between two hosts (a Messenger daemon per Agent), run
  end to end.
- A command that exports a bought artifact from the buyer's state directory.
- Gate F/G operation, independent operators, and production controls.
