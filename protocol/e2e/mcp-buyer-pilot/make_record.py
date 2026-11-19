#!/usr/bin/env python3
"""Build the record of the agent-operated Gate D pilot from its evidence.

Usage: make_record.py RUN_DIR OUT_JSON

Every value comes from a file of the run or from git; nothing is typed by
hand. The only constants are the record's schema, its qualification
statements and the verdict strings. Schema
`tos.service.gate-d-agent-operated-pilot-record.v1` (GATE_D_EXTERNAL_PILOT.md
section 8.5) carries the fields of section 8.2, plus the statements that the
pilot is team-operated and does not qualify as Gate D.

The verdict is AGENT_OPERATED_PILOT_PASSED only when every computed check
holds (`checks` lists them); otherwise AGENT_OPERATED_PILOT_FAILED. This
script never writes PASS_INDEPENDENT_SERVICE_ACTOR_SOFTWARE_WORK.

It prints {"record_sha256", "verdict", "failed_checks"} and exits 0 only for
a passing record.
"""

import base64
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

RUN = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2])
HERE = Path(__file__).resolve().parent
PRODUCTION_ACTOR = "tvm-cell-sha256:0594f9a5743440f9c5f63913ab790c0ea6f4fd5c627d9962d63e09428e42aa0c"
FORBIDDEN_VERDICT = "PASS_INDEPENDENT_SERVICE_" + "ACTOR_SOFTWARE_WORK"


def load(path: Path):
    return json.loads(path.read_text()) if path.exists() else None


def sha(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def canonical(value) -> bytes:
    """RFC 8785 for this record: strings, integers, booleans and null only."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def latest(directory: Path, prefix: str):
    files = sorted(directory.glob(prefix + "-*.json"), key=lambda p: int(p.stem.split("-")[-1]))
    return load(files[-1]) if files else None


orchestration = load(RUN / "orchestration.json") or {}
build = load(RUN / "bin" / "build.json")
buyer = RUN / "buyer-c"
provider = RUN / "provider-c"
profile = load(buyer / "out" / "public" / "profile.json")
handoff = load(RUN / "handoff" / "handoff.json")
vout = RUN / "verifier-work" / "out"
verdicts = {label: load(vout / f"verdict-{label}.json") for label in ("R", "F", "all")}
codex = load(vout / "codex-summary.json") or {}
verifier_build = load(vout / "build.json") or {}
offer_report = load(provider / "out" / "provider" / "offer.json") or {}
withdraw_status = latest(provider / "out" / "provider", "status") or {}
withdrawals = ((withdraw_status.get("report") or {}).get("withdrawals")) or []
confirmations = [json.loads(line) for line in (buyer / "logs" / "confirmations.jsonl").read_text().splitlines()
                 if line.strip()] if (buyer / "logs" / "confirmations.jsonl").exists() else []
funding = load(RUN / "funding-operations.json")
signatures = load(RUN / "record" / "signatures.json")
global_config = RUN / "public" / "global-config.json"
zero_state = json.loads(global_config.read_text())["validator"]["zero_state"]
objects, terms = profile["objects"], profile["terms"]
buyer_wallet = objects["buyer_wallet_raw"].lower()
actor_hash = profile["releases"]["service_actor_code_hash"]

checks = []


def check(name: str, ok: bool, detail=None) -> bool:
    checks.append({"id": name, "ok": bool(ok), "detail": detail})
    return bool(ok)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()


# --- Purchases ----------------------------------------------------------------------

requests_all = {r["request_hash"]: r for r in (verdicts["all"] or {}).get("requests", [])}
purchases = []
for label in ("R", "F"):
    bundle = load(RUN / "handoff" / label / "evidence.json") or {}
    request_hash = handoff["requests"][label]["request_hash"]
    report = requests_all.get(request_hash, {})
    own = next((r for r in (verdicts[label] or {}).get("requests", []) if r.get("request_hash") == request_hash), {})
    confirmation = next((c for c in confirmations if c.get("request_hash") == request_hash and c.get("confirm")), {})
    quote = bundle.get("quote") or {}
    package = base64.b64decode(quote.get("package_base64", "")) if quote.get("package_base64") else b""
    entry = {
        "label": label, "outcome": report.get("state"), "quote_source": "offer file, built locally by the buyer agent",
        "quote_package_sha256": hashlib.sha256(package).hexdigest() if package else None,
        "quote_commitment": quote.get("quote_commitment"), "request_hash": request_hash,
        "request_id": report.get("request_id"), "caller": report.get("caller"),
        "call": {k: (report.get("call") or {}).get(k) for k in ("hash", "lt", "now", "value_nanotos", "query_id")},
        "confirmed_utc": confirmation.get("at"), "confirmation_by": confirmation.get("by"),
        "confirmation_screen_sha256": confirmation.get("screen_sha256")}
    if report.get("respond"):
        entry["respond"] = {k: report["respond"].get(k) for k in ("hash", "lt", "sender")}
        entry["response_hash"] = report.get("response_hash")
        receipt = own.get("receipt") or {}
        artifact = own.get("artifact") or {}
        entry["receipt"] = {"file_sha256": receipt.get("file_sha256"), "cell_hash": receipt.get("cell_hash"),
                            "exit_code": receipt.get("exit_code"), "artifact_digest": receipt.get("artifact_digest")}
        entry["artifact"] = {"file_sha256": artifact.get("file_sha256"), "members": artifact.get("members")}
    for operation in ("expire", "claim_refund", "sweep"):
        if report.get(operation):
            entry[operation] = {k: report[operation].get(k) for k in ("hash", "lt", "sender", "destination", "payouts")}
    purchases.append(entry)

r_entry, f_entry = purchases

# --- Checks -----------------------------------------------------------------------

for label in ("R", "F", "all"):
    check(f"verifier-tool-pass-{label}", (verdicts[label] or {}).get("result") == "pass",
          [c["id"] for c in (verdicts[label] or {}).get("checks", []) if not c.get("ok")])
check("callers-are-the-buyer-wallet", all((p.get("caller") or "").lower() == buyer_wallet for p in purchases),
      [p.get("caller") for p in purchases])
check("R-responded-and-accepted", r_entry.get("outcome") == "responded" and
      (r_entry.get("receipt") or {}).get("exit_code") == 0 and
      (r_entry.get("receipt") or {}).get("cell_hash") == r_entry.get("response_hash") and
      bool((r_entry.get("artifact") or {}).get("file_sha256")))
refund_payouts = ((f_entry.get("claim_refund") or {}).get("payouts")) or []
check("F-refunded-to-the-buyer", f_entry.get("outcome") == "refunded" and any(
    (p.get("destination") or "").lower() == buyer_wallet and p.get("amount_nanotos") == terms["price_nanotos"]
    for p in refund_payouts), refund_payouts)
check("F-expire-and-claim-by-the-buyer-agent", bool(f_entry.get("expire")) and bool(f_entry.get("claim_refund")))
last_withdrawal = withdrawals[0] if withdrawals else {}
actor_last = ((verdicts["all"] or {}).get("actor") or {}).get("last_transaction") or {}
check("provider-withdrawal-finalized-and-last", last_withdrawal.get("state") == "finalized" and
      actor_last.get("hash") == last_withdrawal.get("transaction_hash"),
      {"withdrawal": last_withdrawal.get("transaction_hash"), "actor_last": actor_last.get("hash")})
confirmed = [c for c in confirmations if c.get("confirm")]
check("two-automated-confirmations-each-passing-its-policy", len(confirmed) == 2 and
      all(all(x.get("ok") for x in c.get("checks", [])) for c in confirmed) and
      {c.get("request_hash") for c in confirmed} == {r_entry["request_hash"], f_entry["request_hash"]},
      [{"request_hash": c.get("request_hash"), "outcome": c.get("outcome")} for c in confirmations])
sessions = orchestration.get("sessions") or []
model_tools = sorted({tool for s in sessions for tool in (s.get("tools") or [])})
check("the-model-had-only-the-tos-buyer-mcp-tools", bool(sessions) and bool(model_tools) and
      all(tool.startswith("mcp__tos-buyer__") for tool in model_tools), model_tools)
check("dry-check-passed-before-payment", (profile.get("dry_check") or {}).get("withdrawn") == "withdrawn")
check("actor-code-hash-on-every-endpoint", ((verdicts["all"] or {}).get("actor") or {}).get("code_hash_matches") is True)
check("funding-journal-present", funding is not None)

# The credentials: the driver scanned the evidence for every token value
# and deleted the token files before this record is built
# (run_pilot.py finish_credentials); this script repeats the pattern scan.
credentials_end = orchestration.get("credentials_end") or {}
check("model-credentials-scanned-and-deleted-before-the-record", credentials_end.get("deleted") is True and
      credentials_end.get("leaks") == [] and not (RUN / "secrets" / "claude.env").exists() and
      not (RUN / "secrets" / "codex.env").exists(), credentials_end)
patterns = [re.compile(rb"master_key=[0-9A-Fa-f]{8,}"), re.compile(rb"VAULT_URL="),
            re.compile(rb"sk-ant-[A-Za-z0-9_-]{8,}"), re.compile(rb'"refresh_token"\s*:\s*"[^"]+')]
leaks = []
for root in [RUN / "logs", RUN / "handoff", vout, RUN / "orchestration.json",
             *[RUN / f"{r}-c" / sub for r in ("provider", "buyer", "verifier") for sub in ("logs", "out", "control")]]:
    for path in ([root] if root.is_file() else (p for p in root.rglob("*") if p.is_file()) if root.exists() else []):
        if any(p.search(path.read_bytes()) for p in patterns):
            leaks.append(str(path.relative_to(RUN)))
check("no-vault-or-credential-pattern-in-the-evidence", not leaks, leaks)

# The tosctl every role ran: the release named by its provenance record,
# and listed with this digest in the release's SHA256SUMS.
provenance = load(RUN / "public" / "release-provenance.json") or {}
release_sums = (RUN / "public" / "release-SHA256SUMS").read_text().split() if \
    (RUN / "public" / "release-SHA256SUMS").exists() else []
tosctl_listed = any(release_sums[i] == build["tosctl_sha256"] and release_sums[i + 1] == "tosctl-linux-x86_64"
                    for i in range(0, len(release_sums) - 1, 2))
check("tosctl-is-the-released-binary", tosctl_listed, provenance.get("tag"))

def ok_of(name: str) -> bool:
    return any(c["id"] == name and c["ok"] for c in checks)


computed_pass = all(c["ok"] for c in checks)
codex_verdict = codex.get("verdict")
check("codex-verdict-agrees", codex_verdict == ("AGENT_OPERATED_PILOT_PASSED" if computed_pass else
                                                "AGENT_OPERATED_PILOT_FAILED"), codex_verdict)
passed = all(c["ok"] for c in checks)
verdict = "AGENT_OPERATED_PILOT_PASSED" if passed else "AGENT_OPERATED_PILOT_FAILED"

# --- The record -----------------------------------------------------------------------

ai_root = HERE.parents[2]
endpoint_forms = [{"role": role, "form": "SSH local forward through the restricted pilot-rpc account, with the role's "
                                         "own key, to each validator's loopback JSON-RPC (127.0.0.1:8081)",
                   "validators": [v["name"] for v in profile["endpoints"]["validators"]],
                   "operator": "TOS core development team (project operator of every epoch-7 validator)",
                   "quorum": {"buyer": 2, "provider": 2, "verifier": 3}[role]}
                  for role in ("buyer", "provider", "verifier")]
record = {
    "schema": "tos.service.gate-d-agent-operated-pilot-record.v1",
    "protocol": "tos_service_v1",
    "status": "agent-pilot-passed" if passed else "agent-pilot-failed",
    "verdict": verdict,
    "qualifies_as_gate_d": False,
    "qualifies_as_public_acceptance": False,
    "operation_mode": "agent-operated",
    "qualification_note": "an agent-operated pilot: the buyer is a Claude Code agent and the verifier a Codex agent, "
                          "both run by the core development team, and the provider is the team's OpenFox reference "
                          "seller. It does not meet GATE_D_EXTERNAL_PILOT section 3 and is not Gate D evidence; an "
                          "independent external pilot remains open.",
    "independence": {
        "meets_gate_d_section_3": False,
        "rules_not_met": ["1: all three roles run on one host under one operator",
                          "2 and 3: one organization, the core development team, holds all three roles",
                          "4: the buyer's machine is a container on the provider's host, created by the operator",
                          "5: the verifier reads the same project-run validators as the buyer and the provider"]},
    "participants": [{"role": role, "organization": "TOS core development team", "core_development_team": True,
                      "actor": actor, "hosts_and_network": "the team's coordinator host and its Docker bridge",
                      "declaration_key": "a fresh tosctl Ed25519 key in the role's own custody; its public key is in "
                                         "signatures[]",
                      "shares_no_key_with_another_role": True}
                     for role, actor in (("provider", "OpenFox reference seller, operated by the team"),
                                         ("buyer", "Claude Code CLI agent, operated by the team"),
                                         ("verifier", "Codex CLI agent, operated by the team"))],
    "buyer_declaration": "; ".join([
        "the buyer wallet and packet controller were created by tos-service-buyer init through tosctl in the custody "
        "account of a container the team operates",
        "the model (Claude Code) had only the tos_buyer_* MCP tools and no shell, file or web tool" if ok_of(
            "the-model-had-only-the-tos-buyer-mcp-tools") else
        "the check that the model had only the tos_buyer_* MCP tools did NOT pass (see checks)",
        "every payment was confirmed by the automated pty confirmer under its policy, which no model process could "
        "reach" if ok_of("two-automated-confirmations-each-passing-its-policy") else
        "the check of the automated confirmations did NOT pass (see checks)",
        "no human confirmed any payment",
        "the container's host also runs the provider"]),
    "automation": {
        "buyer_model_client": {"cli": build.get("claude_version"), "binary_sha256": build["binaries"].get("claude"),
                               "models": sorted({s.get("model") for s in sessions if s.get("model")}),
                               "tools": model_tools, "sessions": [
                                   {k: s.get(k) for k in ("name", "prompt_sha256", "transcript_sha256", "started_utc",
                                                          "finished_utc", "tool_calls")} for s in sessions]},
        "verifier_model_client": {"cli": build.get("codex_version"), "binary_sha256": build["binaries"].get("codex"),
                                  "events_sha256": (orchestration.get("verifier") or {}).get("events_sha256"),
                                  "prompt_sha256": (orchestration.get("verifier") or {}).get("prompt_sha256"),
                                  "summary_sha256": sha(vout / "codex-summary.json"), "verdict": codex_verdict},
        "payment_confirmation": "automated: the harness (container root) drove the real tos-service-buyer confirm "
                                "--watch on a pty owned by the custody account and typed the code only when the "
                                "confirmation policy held (harness/confirm_policy.py); no human read the screen or "
                                "typed the code",
        "init_sends": "tos-service-buyer init apply and OpenFox init and offer ran with --yes, approved by the harness",
        "credentials": "the buyer and verifier agents authenticated with the operator's own Claude and ChatGPT "
                       "accounts, with short-lived access tokens only (no refresh token), passed to the CLI process "
                       "alone; " + ("the evidence was scanned for every token value and the token files were deleted "
                                    "before this record was built" if ok_of(
                                        "model-credentials-scanned-and-deleted-before-the-record") else
                                    "the token scan and deletion before this record did NOT pass (see checks)")},
    "network": {"network_id": profile["network_label"],
                "genesis_root_hash": "sha256:" + base64.b64decode(zero_state["root_hash"]).hex(),
                "genesis_file_hash": "sha256:" + base64.b64decode(zero_state["file_hash"]).hex(),
                "global_config_sha256": "sha256:" + sha(global_config)},
    "releases": {"native_registry_code_hash": profile["releases"]["native_registry_code_hash"],
                 "service_actor_code_hash": actor_hash,
                 "service_actor_release": "production" if actor_hash == PRODUCTION_ACTOR else "test-profile",
                 "actor_code_hash_on_every_endpoint":
                     ((verdicts["all"] or {}).get("actor") or {}).get("code_hash_matches")},
    "source_commits": {"ai": build["ai_commit"], "openfox": build["openfox_commit"],
                       "operator_driver": git(ai_root, "rev-parse", "HEAD"),
                       "operator_driver_tree_clean": git(ai_root, "status", "--porcelain") == "",
                       "harness_commits_after_the_containers_started": [
                           line for line in git(ai_root, "log", "--format=%h %s", f"{build['ai_commit']}..HEAD", "--",
                                                "protocol/e2e/mcp-buyer-pilot").splitlines()],
                       "tosctl": {"repository": provenance.get("repository"), "release_tag": provenance.get("tag"),
                                  "tag_commit": provenance.get("tag_commit"), "asset": "tosctl-linux-x86_64",
                                  "listed_in_release_sha256sums": tosctl_listed},
                       "verifier_clone": verifier_build.get("commit")},
    "binaries": {"built_by_operator": build["binaries"], "tosctl_sha256": build["tosctl_sha256"],
                 "verifier_tos_service_verify_sha256": verifier_build.get("sha256") or verifier_build.get(
                     "binary_sha256"), "verifier_built_by": "the Codex verifier, from a fresh clone"},
    "endpoints": endpoint_forms,
    "relays": {"urls": profile["relays"], "operator": "TOS core development team (test relays, private CA)"},
    "objects": {k: objects.get(k) for k in ("capability_id", "capability_version", "provider_agent_id", "actor",
                                            "manifest_digest", "metadata_hash", "attestor_key_id", "capability_address",
                                            "provider_wallet", "buyer_agent_id", "offer_sha256")} |
               {"buyer_wallet": objects["buyer_wallet_raw"],
                "terms_hash": ((load(RUN / "handoff" / "R" / "evidence.json") or {}).get("quote") or {}).get("terms_hash")},
    "terms": terms,
    "dry_check": profile.get("dry_check"),
    "purchases": purchases,
    "provider_withdrawals": [{k: last_withdrawal.get(k) for k in ("transaction_hash", "query_id", "amount_nanotos",
                                                                  "state", "finalized_checkpoint")}],
    "funding": funding,
    "verifier_output": {"tool_commit": verifier_build.get("commit") or verifier_build.get("ai_commit"),
                        "verdict_sha256": {label: sha(vout / f"verdict-{label}.json") for label in ("R", "F", "all")},
                        "checkpoint": (verdicts["all"] or {}).get("checkpoint"),
                        "results": {label: (verdicts[label] or {}).get("result") for label in ("R", "F", "all")}},
    "checks": checks,
    "known_limitations": [
        "no outside party took part: the core development team operated the provider, the buyer agent and the "
        "verifier agent",
        "the payment confirmer is code under a fixed policy, not a human",
        "every chain endpoint is a project-run validator reached through the project's pilot-rpc accounts; endpoint "
        "independence is not claimed",
        "the packet relays are the team's test relays with a private CA; relay independence and production readiness "
        "are not claimed",
        "the job source and the offer file were placed in the developer workspace by the operator, not by the model",
        "a model's tool calls follow its prompt; the prompts and transcripts are kept and named by SHA-256, not "
        "published",
        "a Receipt is the provider's attested statement of the digests it binds, not proof the computation was correct",
        "no Gate E or Gate F claim: no public HTTPS gateway, no gateway was used at all",
        *(["the provider used the production Service Actor, whose minimum windows are 3600 s"]
          if actor_hash == PRODUCTION_ACTOR else
          ["the provider used a test-profile Service Actor (its own code hash) with 600 s windows; production keeps "
           "the 3600 s minimum"]),
        *([] if funding else ["the funding operations journal was not attached to this record"])],
}
def verify_signature(signature: dict, digest: str) -> bool:
    if signature.get("message_hex") != digest or not re.fullmatch(r"[0-9a-f]{64}", signature.get("public_key_hex", "")):
        return False
    with tempfile.TemporaryDirectory() as directory:
        spki = bytes.fromhex("302a300506032b6570032100" + signature["public_key_hex"])
        Path(directory, "key.pem").write_text("-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(spki).decode() +
                                              "\n-----END PUBLIC KEY-----\n")
        Path(directory, "msg").write_bytes(bytes.fromhex(digest))
        try:
            Path(directory, "sig").write_bytes(bytes.fromhex(signature.get("signature_hex", "")))
        except ValueError:
            return False
        return subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", f"{directory}/key.pem", "-rawin",
                               "-in", f"{directory}/msg", "-sigfile", f"{directory}/sig"],
                              capture_output=True).returncode == 0


def refuse_gate_d_verdict(value) -> None:
    if FORBIDDEN_VERDICT in json.dumps(value):
        raise SystemExit("the record would name the Gate D verdict; nothing was written")


refuse_gate_d_verdict(record)
record_sha256 = hashlib.sha256(canonical(record)).hexdigest()
if signatures:
    verified = [verify_signature(s, record_sha256) for s in signatures]
    roles_signed = sorted(s.get("role") for s, ok in zip(signatures, verified) if ok)
    if roles_signed != ["buyer", "provider", "verifier"]:
        # A signature that does not verify over the signed digest fails the
        # written record itself: the verdict, the status and the check say
        # so, and the digest is recomputed over that failed record.
        record["checks"].append({"id": "three-declaration-signatures-verify", "ok": False,
                                 "detail": [{"role": s.get("role"), "verified": ok} for s, ok in zip(signatures, verified)]})
        record["verdict"], record["status"] = "AGENT_OPERATED_PILOT_FAILED", "agent-pilot-failed"
        refuse_gate_d_verdict(record)
        record_sha256 = hashlib.sha256(canonical(record)).hexdigest()
    record["record_sha256"] = record_sha256
    record["signatures"] = [{"role": s.get("role"), "algorithm": s.get("algorithm"),
                             "public_key_hex": s.get("public_key_hex"), "signature_hex": s.get("signature_hex"),
                             "verified": ok} for s, ok in zip(signatures, verified)]
else:
    record["record_sha256"] = record_sha256
OUT.write_text(json.dumps(record, indent=2) + "\n")
failed = [c["id"] for c in record["checks"] if not c["ok"]]
print(json.dumps({"record_sha256": record_sha256, "verdict": record["verdict"], "signed": bool(signatures),
                  "failed_checks": failed}))
sys.exit(0 if record["verdict"] == "AGENT_OPERATED_PILOT_PASSED" else 1)
