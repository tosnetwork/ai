# Gate D External Pilot

**Status:** the runbook for the Gate D external acceptance task on the
Service Actor rail. It replaces the escrow-rail version of this document
(rail change 2026-11-07); that version is git history and none of its
escrow, stablecoin, two-stage Receipt signing or checker steps applies.
Gate D is **not accepted**: no independent pilot under this runbook has run.
An agent-operated pilot (section 8.5), with all three roles held by the core
development team, ran on 2026-11-19; its record
(`../deployments/public-testnet-epoch7-gate-d-agent-pilot-20261119.json`,
`qualifies_as_gate_d: false`) is not Gate D evidence. The code prerequisites
of section 10 are merged.

Where this runbook conflicts with the Service Actor documents
([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md),
[`SERVICE_ACTOR_SETTLEMENT_DESIGN.md`](SERVICE_ACTOR_SETTLEMENT_DESIGN.md),
[`SERVICE_ACTOR_RAIL_WORK_FRAMES_V1.md`](SERVICE_ACTOR_RAIL_WORK_FRAMES_V1.md))
or the MCP buyer adapter ([`MCP_BUYER_ADAPTER_V1.md`](MCP_BUYER_ADAPTER_V1.md)),
they govern. [`ROADMAP.md`](ROADMAP.md) is authoritative for Gate D status.
The buyer's step-by-step instructions are in
[`MCP_BUYER_GUIDE.md`](MCP_BUYER_GUIDE.md).

## 1. Purpose

The acceptance condition is the one of `ROADMAP.md` section 4:

> Accept when a buyer outside the core development team pays an independent
> provider on a public TOS network and another resolver reconstructs the
> complete history without a private gateway database.

The same-operator rehearsal on the epoch-7 public testnet
(`deployments/public-testnet-epoch7-gate-d-rehearsal-20261118.json`) shows
that the paid loop works on a public network. It does not show that
unrelated parties can use it, and it is not Gate D evidence. This pilot
closes that difference: an outside buyer pays with one native-TOS `call`, the
provider answers with an attested `respond`, and a third party reconstructs
the purchase from finalized TOS state alone.

## 2. Roles

| Role | Holds | Does |
|---|---|---|
| **Provider** | its Agent controller, its wallet and the actor's ML-DSA-44 attestor key, in its own `tosctl` custody; its executor host | publishes the Agent, the software-work Capability (manifest key 21) and a Service Actor from the pinned release code; hands the buyer an offer file (`tos.openfox.rail-offer.v2`); runs the pinned executor; answers each admitted request with `respond`; withdraws its revenue |
| **External buyer** | its wallet and buyer Agent (packet controller), in its own `tosctl` custody under a custody OS account | resolves the Capability and terms itself from finalized state; builds the Quote locally; pays with one `call` after confirming on its own custody terminal; delivers the task over the relays; checks the returned Receipt and artifact; runs the refund duties; exports its evidence |
| **Verifier** | a clean checkout of this repository at the pilot commit; its own resolver and endpoint list | reconstructs every purchase of the pilot from finalized state and public inputs only, without gateway data or files a gateway supplied; issues the verdict |

The reference provider is an OpenFox node on the Service Actor rail
(openfox `docs/guides/service-actor-rail.md`). The reference buyer is the
MCP buyer adapter (`tos-service-buyer` and `tos-service-buyer-mcp`), driven
from an MCP client such as Claude Code or Codex. Another implementation may
take either role if it produces the same on-chain facts and the evidence of
section 8.

The packet relays and, where one is used, a gateway are carriers and hint
sources. They hold no authority (`AGENT_PACKET_RELAY_V1.md` section 1;
`MCP_BUYER_ADAPTER_V1.md` O3): a relay cannot create, change or authorize any
protocol fact, and every packet it carries is verified against finalized
state. A team-operated relay therefore takes no role and does not affect the
independence of the roles.

## 3. Independence rules

1. The three roles must not share a private key, a gateway database, a
   filesystem, a host or an operator-controlled source of protocol truth.
2. **One organization may not claim multiple roles**, under the same or
   different test identities. A person acting for an organization counts as
   that organization.
3. The core development team may hold at most one role. The buyer is outside
   the core development team.
4. The buyer runs on a machine it controls, under accounts it created. It
   uses no machine, account, key, vault or configuration file of another
   role. The operator may hand it public data only (section 6 step 3).
5. The verifier's resolver is operated by the verifier, from a clean
   checkout, with no state carried over from the provider, the buyer or a
   gateway.
6. Endpoints. The verifier records, for every JSON-RPC endpoint it reads, the
   legal or organizational operator. Several URLs, processes, containers or
   hosts run by one operator are one operator and do not establish
   independence. `ROADMAP.md` section 10 asks for "an independently operated
   resolver or endpoint set"; the earlier runbook asked the verifier to use
   independently operated endpoints. Which of the two this pilot requires is
   an open owner decision. Until it is taken, a record states each
   endpoint's operator and claims endpoint independence only where it holds
   (section 9).

## 4. Custody of identities

- Every identity of the pilot is freshly generated through `tosctl`: wallets,
  Agent controllers, packet controllers, attestor keys and the declaration
  keys of section 8.3. The plaintext identities under `test-vectors/` are
  local test fixtures and are forbidden in the pilot.
- The buyer creates its wallet and packet controller with
  `tos-service-buyer init` in its custody account
  (`MCP_BUYER_ADAPTER_V1.md` 3.2). The developer account in which the MCP
  client and the model run cannot read the vault, the agent configuration or
  the journal, and cannot act as the custody account (5.1). Every payment is
  confirmed by the human on a terminal of the custody account that no process
  of the developer account reaches.
- No seed, mnemonic, private key, vault URL, vault export, master key, bearer
  token or other signing credential may appear in the evidence or in any
  message between the roles.

## 5. Frozen profile

The pilot uses one software-work profile and pins, before it starts:

- the network tuple: network label, genesis root hash and genesis file hash,
  and the SHA-256 of the global configuration file;
- the Native Registry code file and code hash, and the Service Actor release
  code hash (`crypto/smartcont/tos-service-actor-v1.release.json` in tos);
- the tos release tag and commit, and the SHA-256 of the `tosctl` binary each
  role runs (each role pins its own and records it);
- the ai commit the buyer and verifier build from, and the SHA-256 of every
  binary each role builds;
- the provider implementation's commit and binary SHA-256;
- the offer: Capability ID and version, provider Agent, actor address,
  manifest digest, price, storage fee, cleanup bounty, response SLA and
  refund claim window (the contract allows 3,600 to 2,592,000 seconds; a
  window of at least two hours gives an outside buyer room to act).

A change to the provider Agent, the actor, the attestor, the terms or the
manifest is a new offer. The buyer quotes it again; a Quote is never edited.

## 6. Execution sequence

1. **Freeze.** The operator records the profile of section 5 in a draft
   record and publishes the pilot commit set. No role starts before the
   prerequisites of section 10 are merged at those commits.
2. **Provider setup.** The provider publishes its Agent, Capability and a
   Service Actor for the pilot, so the pilot's request IDs start at 0 and do
   not mix with earlier evidence. It runs its preflight and its long-running
   node, and writes the offer file.
3. **Pilot package.** The buyer and the verifier receive public data only:
   the network tuple and global configuration with its SHA-256, the registry
   code file's source (tos tag and path), the actor code hash, the relay base
   URLs and the relay CA certificate (its SHA-256 sent over a second
   channel), the endpoint access instructions, and the offer file with its
   SHA-256.
4. **Buyer setup.** The buyer builds the binaries at the pilot commit and
   runs `tos-service-buyer init plan`, then `init apply`, which creates the
   wallet and packet controller in custody and stops until the wallet is
   funded. The buyer sends the wallet address (public) to whoever funds the
   pilot and, once funded, runs `init apply` again to activate the wallet and
   register the buyer Agent. It starts
   `tos-service-buyer agent` in the custody account and configures its MCP
   client (`MCP_BUYER_GUIDE.md`).
5. **Independent resolution.** The buyer resolves the offer with
   `tos_buyer_quote` (offer-file source, local Quote) and the verifier
   resolves the same Capability version, actor policy and `terms_hash` with
   its own resolver, both at finalized checkpoints and before payment.
6. **Purchase.** The buyer prepares the purchase, requests payment and
   confirms it on its custody terminal with the code shown there. The agent
   sends one `call` with the quoted `expected_terms_hash`.
7. **Execution.** The provider executes the bound source under the pinned
   image and fail-closed isolation. A crash-ambiguous execution is not
   retried under the same execution ID. The executor's private containerd
   socket is never shared with a gateway, and the executor holds no signing
   key. The provider attests the result with `respond`.
8. **Result.** The buyer's agent accepts the result only after the Receipt's
   cell hash equals the finalized `response_hash` and every bound digest
   matches (`MCP_BUYER_ADAPTER_V1.md` 7.3); `tos_buyer_result` writes the
   files.
9. **Refund path (recommended).** The provider pauses intake, the buyer makes
   a second purchase, and after the response deadline the buyer's agent runs
   `expire` and `claim_refund`. The purchase ends `refunded` and the price
   returns to the buyer wallet.
10. **Provider withdrawal.** The provider withdraws its revenue with
    `withdraw_revenue`.
11. **Evidence.** The buyer exports its evidence as the custody account. The
    provider exports its own. The verifier waits for finality and
    reconstructs every purchase from a clean environment (section 7, A6),
    then issues its verdict.
12. **Record.** The operator assembles the record of section 8. Every party
    checks it and signs its digest. The record is committed under
    `spec/deployments/` through a pull request reviewed by someone other than
    its author.

## 7. Acceptance items

Gate D is accepted only when every item holds and is shown by the record:

- **A1. Public network.** Every transaction is on the pinned public TOS
  network, read at finalized checkpoints by a strict-majority quorum of at
  least three endpoints.
- **A2. Roles.** Three declared parties hold the three roles under the rules
  of section 3; the buyer is outside the core development team; no
  organization holds two roles.
- **A3. Fresh custody.** Every identity was generated through `tosctl` for
  the pilot; none comes from `test-vectors/`; the evidence holds no secret.
- **A4. Independent resolution.** The buyer and the verifier each resolved
  the Capability version, manifest digest, actor code hash, policy, attestor
  and `terms_hash` from finalized state before payment, without a private
  gateway database.
- **A5. Responded purchase.** At least one purchase was paid with one `call`
  carrying the quoted `expected_terms_hash`, confirmed by the buyer's human on
  the custody terminal, answered by `respond`, and accepted by the buyer: the
  Receipt's cell hash equals the finalized `response_hash`, the Receipt binds
  the purchase's `quote_commitment`, execution ID, input, source, price,
  provider, toolchain and manifest digests, `exit_code` is 0, and the artifact
  matches the digests the Receipt binds.
- **A6. Reconstruction.** The verifier reconstructed from finalized state and
  public inputs only: the Capability and manifest digest; the actor's code
  hash, policy and `terms_hash`; the `call` transaction and the request's
  state; the `respond` transaction and its `response_hash`, compared with the
  Receipt's cell hash; the artifact digest; for a refunded purchase the
  `expire` and `claim_refund` transactions and the refund credited to the
  buyer wallet; and the provider's `withdraw_revenue`.
- **A7. No gateway dependency.** No role relied on gateway-held data for any
  fact the record states. A gateway, if used at all, was a hint source whose
  every answer was re-verified.
- **A8. Endpoint observations.** Every endpoint each role used is listed with
  its operator.
- **A9. Agreement.** All three parties signed the same record digest with the
  keys their declarations name.
- **A10. Verdict.** The verifier returned
  `PASS_INDEPENDENT_SERVICE_ACTOR_SOFTWARE_WORK` over that record.

The refunded purchase of step 9 is recommended, not required: A6 covers it
when it runs. Any missing object, ambiguous chain outcome, quorum failure or
private gateway dependency leaves Gate D open.

## 8. Pilot evidence record

### 8.1 File and schema

One JSON file,
`spec/deployments/public-testnet-<epoch>-gate-d-external-pilot-<yyyymmdd>.json`,
schema `tos.service.gate-d-external-pilot-record.v1`. Hashes are lowercase
hex with the prefix the source uses (`sha256:`, `tvm-cell-sha256:`) or bare
64-hex where the protocol object is bare (`request_hash`,
`response_hash`, transaction hashes). Amounts are decimal nanoTOS strings.
Times are UTC ISO 8601. Logs, archives and BOC files stay outside Git; the
record names each by SHA-256 and says who retains it.

### 8.2 Fields

| Field | Content |
|---|---|
| `schema`, `protocol` | `tos.service.gate-d-external-pilot-record.v1`, `tos_service_v1` |
| `status`, `verdict` | `pilot-passed` with `PASS_INDEPENDENT_SERVICE_ACTOR_SOFTWARE_WORK`, or `pilot-failed` with `FAIL` and the failing acceptance items |
| `participants[]` | per role: `role` (`provider`, `buyer`, `verifier`), the organization or person (at least a publishable identifier), the statement that it is or is not part of the core development team, who controls its hosts and network, its declaration public key and algorithm, and the statement that it shares no key with another party |
| `buyer_declaration` | the independent buyer statement: the wallet and buyer Agent were freshly generated by the buyer through `tosctl`; every payment was confirmed by the buyer on its own custody terminal; no machine, account or key of another role was used |
| `network` | network label, genesis root hash, genesis file hash, global configuration SHA-256 |
| `releases` | Native Registry code hash, Service Actor code hash, and whether every endpoint served that actor code hash |
| `source_commits` | the ai commit (buyer and verifier), the provider implementation's commit, the tos tag and commit |
| `binaries` | per role, the SHA-256 of every binary it ran, `tosctl` included; who built each |
| `endpoints[]` | per role, each endpoint's form (for example "loopback forward to a validator's JSON-RPC" or "own full node"), its operator, and the quorum used |
| `objects` | provider Agent ID, actor address, Capability ID and version, manifest digest, metadata hash, attestor key ID, `terms_hash`, policy version; buyer Agent ID and wallet address; offer file SHA-256 |
| `terms` | price, storage fee, cleanup bounty, response SLA, refund claim window, retention |
| `purchases[]` | per purchase: label, outcome (`responded`, `refunded`, `swept`), Quote source, Quote package SHA-256 and `quote_commitment`, `request_hash`, `request_id`, the `call` transaction (hash, lt), the `respond` transaction (hash, lt) and `response_hash`, or the `expire` and `claim_refund` (or sweep) transactions (hash, lt) and the refunded amount; the Receipt BOC SHA-256 and its cell hash; the artifact digest and its member digests; the confirmation time on the custody terminal |
| `provider_withdrawals[]` | `withdraw_revenue` transaction (hash, lt), query ID, amount |
| `funding` | each funding operation's ID, destination, amount and transaction (hash, lt), and the SHA-256 of the operations journal |
| `verifier_output` | the verifier tool's commit and binary SHA-256, the SHA-256 of its output, the finalized checkpoint it read at, and its verdict |
| `known_limitations[]` | every limitation that applies, in words, including each item of section 9 the pilot cannot exclude |
| `record_sha256` | the digest of section 8.3 |
| `signatures[]` | per participant: role, declaration public key, signature over `record_sha256` |

### 8.3 What binds the record

`record_sha256` is the SHA-256 of the record with the `record_sha256` and
`signatures` fields removed, encoded as canonical JSON (RFC 8785). Each
participant signs those 32 bytes with the declaration key its entry names,
held in its own `tosctl` custody (for an Ed25519 key, `tosctl wallet sign
--name <key> --message-hex <record_sha256 hex>`). The record is bound by:

- the commits and binary SHA-256s each role ran, so the code is fixed;
- the network tuple, the registry code hash and the actor code hash, so the
  chain and contracts are fixed;
- the request IDs, `request_hash` values and transaction hashes and logical
  times, which anyone can look up in finalized state;
- the Receipt BOC and artifact digests, which tie the delivered files to the
  attested `response_hash`;
- the verifier's verdict and the hash of its output, and the three
  signatures over one digest.

### 8.4 Who produces which part

- The buyer's part comes from its evidence export, run as the custody
  account, and contains no secret (`MCP_BUYER_ADAPTER_V1.md` section 15).
- The provider's part comes from its node's status and its withdrawal.
- The verifier's part comes from the verifier tool's output; nothing in it is
  copied from the other two parts.
- The verifier tool is `tos-service-verify`, and the buyer's export is
  `tos-service-buyer evidence` ([`PURCHASE_EVIDENCE_V1.md`](PURCHASE_EVIDENCE_V1.md)).
  The tool's `pass`/`fail` result and check IDs map into this record as
  follows. The verdict's SHA-256, checkpoint and `result` become
  `verifier_output`. Check IDs map to acceptance items:
  - A1: `actor-account` and the verdict's `reads.quorum`.
  - A4 (verifier side): `bundle-binding`.
  - A5: `receipt-canonical`, `receipt-response-hash`, `receipt-request-hash`,
    `receipt-terms`, `receipt-binding`, `artifact-digest` and
    `artifact-members`.
  - A6: `actor-code-hash`, `actor-history`, `actor-replay`,
    `request-selected`, `request-getters`, `bundle-binding`,
    `bundle-journal`, `bundle-finalized` and `bundle-result`.
  - A10: `PASS_INDEPENDENT_SERVICE_ACTOR_SOFTWARE_WORK` may be given only
    when the tool returns `pass` for every purchase of `purchases[]`.

  The tool does not judge A2, A3, A7, A8 or A9. It does not cover A6's
  `withdraw_revenue` either, and it shows a refund only as the `claim_refund`
  payout to the buyer wallet, not as the wallet's credit. Those come from the
  record's other parts. Without a bundle the tool proves a request's caller
  wallet only, so each purchase in `purchases[]` must have its reported
  `caller` equal the buyer's declared wallet in `objects`.

### 8.5 Agent-operated pilot record

A pilot whose three roles are all held by the core development team, with
agents in the buyer and verifier roles, is recorded under a distinct schema
so that no reader or tool can take it for Gate D evidence:
`tos.service.gate-d-agent-operated-pilot-record.v1`, in
`spec/deployments/public-testnet-<epoch>-gate-d-agent-pilot-<yyyymmdd>.json`.

- It carries the fields of section 8.2 and, in addition,
  `qualifies_as_gate_d: false`, `qualifies_as_public_acceptance: false`,
  `operation_mode: "agent-operated"`, an `independence` block listing each
  rule of section 3 the pilot does not meet, and an `automation` block that
  names the model clients, their binaries, prompts and transcripts by
  SHA-256, and states that payment confirmation was automated, with no
  human.
- Its verdict is `AGENT_OPERATED_PILOT_PASSED` or
  `AGENT_OPERATED_PILOT_FAILED` (status `agent-pilot-passed` or
  `agent-pilot-failed`), never `PASS_INDEPENDENT_SERVICE_ACTOR_SOFTWARE_WORK`.
- It names the Service Actor code hash the provider used and whether that
  is the production release.
- It is built by script from the run's files
  (`protocol/e2e/mcp-buyer-pilot/make_record.py`); its `checks` list every
  condition the verdict rests on, including the verifier tool's results
  mapped as in section 8.4.

Such a record shows that the paid loop runs end to end on the public
network with agent clients. It does not close Gate D.

## 9. What a pilot record must not claim

- **Gate F.** No public HTTPS gateway, no two independently operated
  gateways, no three providers or ten Capabilities, no recurring paid use and
  no safe handoff. A gateway on loopback or behind a private CA proves none of
  these.
- **Gate E acceptance.** It is claimed only if a buyer completes a purchase
  from the public documentation alone in one working session and an
  independently operated provider onboards fresh; otherwise the pilot is at
  most supporting evidence for the buyer side of Gate E.
- **Endpoint independence** where it does not hold: if every endpoint is run
  by the project, the record says so, and independence refers to the roles
  only.
- **Public-HTTPS chain endpoints.** Validator JSON-RPC reached through a
  forward to a loopback listener is not a public endpoint.
- **Production relays.** The test relays are run by the team, use a private
  CA and a short TTL; the record claims neither relay independence nor
  production readiness.
- **Computation correctness.** A Receipt is an attested statement of the
  digests it binds (`SERVICE_ACTOR_SETTLEMENT_DESIGN.md` section 4). It
  proves that the provider's attestor committed to those digests, not that
  the computation was correct.
- **Readiness beyond the pilot.** No production readiness, mainnet, real
  money, Messenger carriage, independent security review of the Service Actor
  or both-VM replay, unless separately recorded.

## 10. Prerequisites and tooling status

Merged on ai main (`ROADMAP.md` section 4):

- the buyer agent, confirmer, refund duties, carriage, delivery, result
  acceptance and `tos-service-buyer agent`;
- `init plan` and `init apply`, with their follow-ups (ai #80, #84),
  including the optional gateway and catalog flags;
- the stdio MCP server with all nine tools, `tos_buyer_search` and
  `tos_buyer_quote` included (ai #81);
- the buyer's evidence export `tos-service-buyer evidence` and the
  third-party verifier `tos-service-verify` (ai #83,
  [`PURCHASE_EVIDENCE_V1.md`](PURCHASE_EVIDENCE_V1.md), mapped into the
  record in section 8.4);
- the bound on a Quote's lifetime and the search and quote rate limits
  (ai #85, merge `69feee99`);
- the end-to-end test of the MCP buyer against an OpenFox provider on a local
  chain (`MCP_BUYER_ADAPTER_V1.md` section 15, plan item 9; ai #91, merge
  `bde3b791`, `protocol/e2e/mcp-buyer/`); and
- the agent-operated pilot harness and record builder of section 8.5
  (ai #89, merge `1ddf88a1`, `protocol/e2e/mcp-buyer-pilot/`).

No code prerequisite of this section is unmerged.

Operational prerequisites (endpoint access for the buyer and verifier,
funding, the published global configuration) are decided by the operator and
the owner and recorded in the pilot record, not here.
