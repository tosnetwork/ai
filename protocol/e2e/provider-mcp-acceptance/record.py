"""The section 10.3 record of the local agent-operated provider run.

Built from the driver's state only (RUN/private/state.json): the sessions
and their transcripts' digests, the confirmations, the operator's permitted
custody-side commands, the strict-majority chain reads and the verifier's
verdicts. It names no account, no path of a real user and no secret: the
accounts appear by role and uid.
"""

from __future__ import annotations

import hashlib
import json
import statistics
import subprocess
from pathlib import Path

SCHEMA = "tos.service.local-agent-operated-provider-run-record.v1"
ROLE_ASSIGNMENTS = {"a": "A", "b": "B"}
STEPS = [
    "provider-offer",
    "buy-r1-across-switch",
    "result-r1",
    "records-acked",
    "buy-r2",
    "result-r2",
    "pause-for-refund",
    "buy-f-paused",
    "status-f-refunded",
    "resume-own",
    "resume-operator",
    "pause-stacked",
    "resume-stacked",
    "withdraw",
    "records-final",
]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def client_versions(clients: dict) -> dict:
    out = {}
    for name, entry in clients.items():
        version = subprocess.run([entry["path"], "--version"], capture_output=True, text=True, timeout=60)
        out[name] = {
            "cli_version": version.stdout.strip().splitlines()[0] if version.stdout.strip() else None,
            "binary_sha256": entry["sha256"],
        }
    return out


def build(state: dict, run: Path, facts: dict) -> dict:
    network = json.loads(Path("/data/network.json").read_text())
    global_config = Path(run / "public" / "global-config.json").read_bytes()
    tos_commit = subprocess.run(
        ["git", "-C", str(facts["tos_root"]), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    clients = client_versions(facts["clients"])
    checks: list = []

    def check(name: str, ok, detail=None) -> None:
        checks.append({"name": name, "result": "pass" if ok else "fail", "detail": detail})

    assignments, all_fees = {}, []
    for x, label in ROLE_ASSIGNMENTS.items():
        a = state["assignments"][x]
        sessions = [s for s in state["sessions"] if s["assignment"] == x]
        confirmations = [c for c in state["confirmations"] if c.get("assignment") == x]
        fees = (facts["respond_fees"].get(x) or {}).get("responds", [])
        all_fees += fees
        provider_client = next((s["client"] for s in sessions if s["role"] == "provider"), None)
        buyer_client = next((s["client"] for s in sessions if s["role"] == "buyer"), None)
        answers = {s["step"]: s.get("answer") or {} for s in sessions if s["exit"] == 0}
        switch = next((s for s in state["switches"] if s["assignment"] == x), None)
        purchases = a["purchases"]
        assignments[label] = {
            "provider_model_client": {
                "client": provider_client,
                **clients.get(provider_client or "", {}),
                "models": sorted({m for s in sessions if s["role"] == "provider" for m in s.get("models", [])}),
            },
            "buyer_model_client": {
                "client": buyer_client,
                **clients.get(buyer_client or "", {}),
                "models": sorted({m for s in sessions if s["role"] == "buyer" for m in s.get("models", [])}),
            },
            "sessions": [
                {
                    k: s.get(k)
                    for k in (
                        "step",
                        "role",
                        "client",
                        "started_utc",
                        "finished_utc",
                        "exit",
                        "prompt_sha256",
                        "transcript_sha256",
                        "tool_calls",
                    )
                }
                for s in sessions
            ],
            "provider_objects": {
                # The offer file's path names the developer's home; its
                # SHA-256 stays.
                **{k: v for k, v in (a.get("offer") or {}).items() if k != "offer_file"},
                "provider_init": a.get("provider_init"),
                "wallet": a["wallets"].get(f"provider-{x}"),
            },
            "buyer_objects": {**(a.get("buyer") or {}), "wallet": a["wallets"].get(f"buyer-{x}")},
            "provider_actions": [
                {
                    "kind": c.get("kind"),
                    "reference": c.get("reference"),
                    "identifier": c.get("identifier"),
                    "typed": c.get("typed"),
                    "outcome": c.get("outcome"),
                    "confirmed_by": "harness through the real confirmer",
                }
                for c in confirmations
                if c.get("program") == "provider"
            ],
            "purchases": {
                name: {
                    **entry,
                    "verdict": next(
                        (
                            r
                            for r in (state.get("verifier") or {}).get("results", [])
                            if r["assignment"] == x and r["label"] == name
                        ),
                        None,
                    ),
                }
                for name, entry in purchases.items()
            },
            "pause_events": a["pauses"],
            "operator_commands": a["operator"],
            "withdrawal": {"before": a.get("withdraw_before"), "after": a.get("withdraw_after"), "reader": "harness"},
            "custody_start": {
                "agent_start_lines": a.get("agent_start_lines"),
                "mcp_startup": a.get("mcp_startup"),
                "custody_preflight_after_init": a.get("custody_preflight"),
            },
            "cli_fallback_steps": a["cli_fallback_steps"],
        }
        check(
            f"{label}: every step ran through the model's tool calls",
            a["steps_done"] == STEPS,
            {"done": a["steps_done"]},
        )
        check(f"{label}: no CLI-fallback step", not a["cli_fallback_steps"])
        check(
            f"{label}: the offer was previewed, confirmed and applied",
            (answers.get("provider-offer") or {}).get("state") == "applied" and bool(a.get("offer")),
        )
        check(
            f"{label}: every confirmation the steps needed was typed by the harness into the real confirmer",
            all(c.get("exit") == 0 for c in confirmations) and len(confirmations) == 7,
            [{"kind": c.get("kind"), "outcome": c.get("outcome")} for c in confirmations],
        )
        check(
            f"{label}: the validator-set switch changed membership (at least one left, one joined)",
            bool(switch and switch["left"] and switch["joined"]),
            switch and {"left": switch["left"], "joined": switch["joined"]},
        )
        took = ((switch or {}).get("took_effect") or {}).get("header") or {}
        r1, r2, f = purchases.get("R1", {}), purchases.get("R2", {}), purchases.get("F", {})
        check(
            f"{label}: R1 was paid before the switch and responded after it",
            bool(took)
            and (r1.get("call_utime") or 0) <= took.get("utime", 0)
            and all(t["utime"] >= took.get("utime", 0) for t in r1.get("respond_seen", [{"utime": 0}])),
            {"call_utime": r1.get("call_utime"), "switch_utime": took.get("utime"), "respond": r1.get("respond_seen")},
        )
        check(
            f"{label}: R2 ran entirely after the switch",
            (r2.get("call_utime") or 0) > took.get("utime", 1 << 62),
            {"call_utime": r2.get("call_utime")},
        )
        check(
            f"{label}: R1 and R2 were accepted by the buyer against the finalized response_hash",
            (answers.get("result-r1") or {}).get("accepted") is True
            and (answers.get("result-r2") or {}).get("accepted") is True,
        )
        refund = f.get("refund_seen") or {}
        check(
            f"{label}: the paused call F was not answered and ended refunded (expire and claim_refund on chain)",
            bool(refund.get("expires")) and bool(refund.get("claims")) and not refund.get("responds"),
            refund,
        )
        stacked = next((p for p in a["pauses"] if p.get("by") == "operator over model"), {})
        check(
            f"{label}: the stacked operator pause re-stamped the model's marker as operator and kept paused_unix",
            stacked.get("restamped")
            and stacked.get("first_paused_unix_kept")
            and stacked.get("origin_after") == "operator",
            stacked,
        )
        resumes = [c for c in confirmations if c.get("kind") == "resume"]
        check(
            f"{label}: the model's resume of the operator pause and of the stacked pause each became a "
            "confirmable action",
            len(resumes) == 2 and all(c.get("typed") == "code" for c in resumes),
        )
        own = answers.get("resume-own") or {}
        check(
            f"{label}: the model resumed its own pause directly, with no confirmable action",
            bool(own.get("resume_outcome")) and not own.get("action_id"),
            own,
        )
        after = a.get("withdraw_after") or {}
        before = a.get("withdraw_before") or {}
        check(
            f"{label}: the withdrawal reached the owner wallet (harness reads: actor transaction, wallet balance)",
            bool(after.get("withdraw_transactions"))
            and (after.get("wallet_balance_nanotos") or 0) > (before.get("wallet_balance_nanotos") or 0),
            {"before": before, "after": after},
        )
        check(
            f"{label}: a fee was read for every respond",
            len(fees) >= 2 and all("fee_nanotos" in r for r in fees),
            len(fees),
        )
        check(
            f"{label}: each client operated the role this assignment gives it",
            (provider_client, buyer_client) == (("codex", "claude") if x == "a" else ("claude", "codex")),
        )
    verifier = state.get("verifier") or {}
    check(
        "tos-service-verify, built from a fresh clone, passes every purchase",
        bool(verifier.get("results")) and all(r["exit"] == 0 for r in verifier["results"]),
        [{k: r[k] for k in ("assignment", "label", "exit", "verdict")} for r in verifier.get("results", [])],
    )
    check(
        "no OpenFox binary, source or configuration is present", facts["openfox_scan"]["absent"], facts["openfox_scan"]
    )
    misuse = [
        {"step": s["step"], "client": s["client"], "use": s.get("unexpected_tool_use")}
        for s in state["sessions"]
        if s.get("unexpected_tool_use")
    ]
    check("no model session used any tool outside its role's MCP server", not misuse, misuse)
    fee_values = [r["fee_nanotos"] for r in all_fees]
    passed = all(c["result"] == "pass" for c in checks)
    binaries = dict(facts["build"]["binaries"])
    binaries.update(
        {
            "tosctl": facts["install"]["tosctl"]["sha256"],
            "software-work-executord": facts["install"].get("executor", {}).get("sha256"),
            "claude": facts["clients"]["claude"]["sha256"],
            "codex": facts["clients"]["codex"]["sha256"],
        }
    )
    document = {
        "schema": SCHEMA,
        "protocol": "tos_service_v1",
        "status": "completed"
        if all(state["assignments"][x]["steps_done"] == STEPS for x in ROLE_ASSIGNMENTS)
        else "incomplete",
        "verdict": "LOCAL_AGENT_OPERATED_RUN_PASSED" if passed else "LOCAL_AGENT_OPERATED_RUN_FAILED",
        "operation_mode": "agent-operated",
        "network_kind": "local",
        "qualifies_as_gate_d": False,
        "qualifies_as_public_acceptance": False,
        "qualification_note": "A local agent-operated run by the core team on the host's own four-validator test "
        "network. It is not Gate D evidence and not a public acceptance.",
        "network": {
            "network_id": facts["network_label"],
            "genesis_root_hash": "sha256:" + network["zerostate_root"],
            "genesis_file_hash": "sha256:" + network["zerostate_file"],
            "global_config_sha256": "sha256:" + hashlib.sha256(global_config).hexdigest(),
            "validator_count": network["validators"],
            "endpoints": "the five validator candidates' loopback JSON-RPC; four form each set",
        },
        "validator_set_switch": [
            {
                "assignment": ROLE_ASSIGNMENTS[s["assignment"]],
                "took_effect": s["took_effect"],
                "config34_hash_before": s["before"]["config34_cell_hash"],
                "config34_hash_after": s["after"]["config34_cell_hash"],
                "members_before": s["before"]["members"],
                "members_after": s["after"]["members"],
                "left_local_indices": s["left"],
                "joined_local_indices": s["joined"],
                "requests_pending_across": s["requests_pending_across"],
                "pending_held_by": "the provider agent stopped by the operator (systemctl --user) "
                "from before the paid call until the new set took effect",
            }
            for s in state["switches"]
        ],
        "releases": {
            "service_actor_code_hash": facts["actor_code_hash"],
            "service_actor_release": "production",
            "native_registry_code_hash": facts["registry_code_hash"],
        },
        "source_commits": {
            "ai": facts["ai_commit"],
            "tos": tos_commit,
            "harness": facts["harness_commit"],
            "harness_tree_clean": facts["harness_clean"],
        },
        "binaries": binaries,
        "openfox_absent": facts["openfox_scan"]["absent"],
        "openfox_scan": facts["openfox_scan"],
        "accounts": [{"role": role, "uid": value} for role, value in facts["uids"].items()],
        "relay": {k: (state.get("relay") or {}).get(k) for k in ("url", "ca_sha256", "binary_sha256", "account")},
        "role_assignments": assignments,
        "respond_fees": {
            "reader": "harness",
            "per_assignment": {ROLE_ASSIGNMENTS[x]: v for x, v in facts["respond_fees"].items()},
            "summary": {
                "count": len(fee_values),
                "highest_nanotos": max(fee_values, default=None),
                "mean_nanotos": int(statistics.mean(fee_values)) if fee_values else None,
            },
        },
        "confirmations": [
            {
                k: c.get(k)
                for k in (
                    "assignment",
                    "program",
                    "kind",
                    "reference",
                    "typed",
                    "outcome",
                    "terminal",
                    "driven_by",
                    "confirmer",
                    "screen_sha256",
                    "at",
                )
            }
            for c in state["confirmations"]
        ],
        "verifier_output": verifier,
        "provider_facts_reader": "harness",
        "provider_facts_reads": "every provider-side fact (respond and withdrawal transactions, credited revenue, "
        "respond fees, wallet balances) was read by the harness from the validators' JSON-RPC "
        "and taken only at a strict majority of the five candidate endpoints",
        "checks": checks,
        "known_limitations": [
            "the core team operated every role: the owner, the coordinator and the two model clients",
            "the confirmers were harness-driven: the real confirmers on pseudo-terminals the custody accounts "
            "opened, typing the code only for the action or purchase the model's own tool result named",
            "init of each provider and buyer node was harness-driven in the custody accounts",
            "every endpoint is a local validator of this host",
            "one developer account ran both clients (the coordinator's decision), not two",
            "the paid request pending across the switch was held by stopping the provider agent, not by load",
            "Codex 0.171 still lists, with its shell and file tools disabled and a read-only sandbox, its code-mode "
            "exec (the host through which it calls MCP tools), apply_patch and its collaboration tools; the harness "
            "stops a session that uses anything but the role's MCP server (check above)",
        ]
        + (
            [
                "the developer account is the operator account and has sudo (owner ruling: the clients already "
                "logged in there were used); the clients had no shell, file or other built-in tool, only the one "
                "MCP server of their role, so the model could not use it"
            ]
            if facts.get("developer_is_operator")
            else []
        )
        + (
            [
                f"the operator's home, which is the developer account's, holds "
                f"{facts['openfox_scan']['openfox_items_in_operator_home']} OpenFox files from earlier work; no run "
                "process executed, read or had on its PATH any of them (the clients had no shell or file tool), and "
                "openfox_absent covers every binary, installed directory, custody home and the run's PATH"
            ]
            if facts["openfox_scan"].get("openfox_items_in_operator_home")
            else []
        ),
        "funding": facts.get("funding"),
    }
    document["record_sha256"] = sha256_text(json.dumps(document, sort_keys=True, separators=(",", ":")))
    return document
