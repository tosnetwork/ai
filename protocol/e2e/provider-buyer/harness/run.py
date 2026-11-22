"""End-to-end run of the selling side without OpenFox.

The buyer side is protocol/e2e/mcp-buyer's, imported from it unchanged: the
local PQ validators, the packet relay, the gateway, `tos-service-buyer init`
and `agent` as custody, the MCP server as developer and the real confirmer.
The provider is this repository's tos-service-provider, as the provider
account, through its own commands only: init, offer, preflight, serve,
status, pause, resume and withdraw.

Scenarios:

1. A paid call through a gateway Quote. While the call runs, the provider's
   chain reads pass through a proxy that holds each request for a moment, so
   the provider's record stays `executed` (executed, not yet responded) long
   enough to be seen; a watcher running as the provider account then kills
   `serve` with SIGKILL. The harness checks the wait status, that no respond
   reached the actor, restarts `serve`, and checks that exactly one respond
   reached the actor, that the buyer accepted the result and that the
   provider recorded the buyer's ack.
2. The provider withdraws the credited revenue: a preview (exit 4) first,
   then `--yes`, until finalized state shows the withdrawal.
3. An unanswered call: admission is paused, the buyer pays, nothing is
   responded, and the buyer agent's refund duties expire the request and
   claim the refund once the response window is over. With the test-only
   Service Actor build (600 s windows) this takes about twenty minutes;
   E2E_SKIP_REFUND=1 skips it.

Execution is protocol/e2e/mcp-buyer's stand-in executor service: it reads
the source archive and executes nothing.

The run ends with work/evidence.json and one ALL PASS or FAIL line.
"""

import asyncio
import datetime
import importlib.util
import json
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

BASE_HARNESS = Path("/e2e-mounts/base-harness")
sys.path.insert(0, str(BASE_HARNESS))
_spec = importlib.util.spec_from_file_location("mcp_buyer_harness", BASE_HARNESS / "run.py")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

record, poll, rpc, structured = base.record, base.poll, base.rpc, base.structured
BIN, WORK, MOUNTS = base.BIN, base.WORK, base.MOUNTS
PROVIDER_RAIL = base.PROVIDER_RAIL
RAIL_CONFIG = PROVIDER_RAIL / "rail.json"
NANO = base.NANO

# The test-only Service Actor build (SERVICE_ACTOR_TVM_V1.md, "Test-only
# build"): the same contract with 600 s minimum windows.
TEST_PROFILE_CODE_HASH = "tvm-cell-sha256:79a566f5f4281f7abe59cd1c16a7bc3b2d990e840f42b00d55cb0ae4b0545960"
TEST_PROFILE = base.ACTOR_CODE_HASH == TEST_PROFILE_CODE_HASH
WINDOW = 600 if TEST_PROFILE else 3600
RESPOND_OPCODE = 0x53564302

# The provider reads the chain through these ports; each forwards to one
# validator's JSON-RPC port.
PROXY_PORTS = [47780, 47781, 47782]
HOLD = {"seconds": 0.0}


# --- The provider's chain-read proxy ------------------------------------------

def _pump(source: socket.socket, target: socket.socket, held: bool) -> None:
    try:
        while True:
            chunk = source.recv(65536)
            if not chunk:
                break
            if held and HOLD["seconds"] > 0:
                time.sleep(HOLD["seconds"])
            target.sendall(chunk)
    except OSError:
        pass
    finally:
        for end in (source, target):
            try:
                end.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            end.close()


def _serve_proxy(listener: socket.socket, target_port: int) -> None:
    while True:
        try:
            client, _ = listener.accept()
        except OSError:
            return
        try:
            upstream = socket.create_connection(("127.0.0.1", target_port), timeout=10)
            upstream.settimeout(None)
        except OSError:
            client.close()
            continue
        threading.Thread(target=_pump, args=(client, upstream, True), daemon=True).start()
        threading.Thread(target=_pump, args=(upstream, client, False), daemon=True).start()


def start_proxies() -> None:
    """A forwarding proxy per validator for the provider's reads. While
    HOLD is set, every request it forwards waits that long first; the reads
    stay well inside the provider's per-query timeout."""
    for port, target in zip(PROXY_PORTS, base.RPC_PORTS):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(64)
        threading.Thread(target=_serve_proxy, args=(listener, target), daemon=True).start()
    record("the provider's chain-read proxies forward to the validators", True,
           dict(zip(PROXY_PORTS, base.RPC_PORTS)))


def provider_endpoints() -> list[str]:
    return [f"http://127.0.0.1:{port}/jsonRPC" for port in PROXY_PORTS]


# --- The provider: tos-service-provider ---------------------------------------

def provider_cli(*args: str, check: bool = True, timeout: int = 900) -> subprocess.CompletedProcess:
    return base.as_account("provider", [str(BIN / "tos-service-provider"), *args], check=check, timeout=timeout)


def report(result: subprocess.CompletedProcess):
    """The one JSON document a command printed, or None."""
    try:
        return json.loads(result.stdout) if result.stdout.strip() else None
    except json.JSONDecodeError:
        return None


def provider_status() -> dict:
    return report(provider_cli("status", "--rail-config", str(RAIL_CONFIG), check=False)) or {}


def start_serve(log: str) -> subprocess.Popen:
    process = base.start("provider", [str(BIN / "tos-service-provider"), "serve", "--rail-config", str(RAIL_CONFIG)], log)
    path = WORK / "logs" / log

    def serving():
        for line in path.read_text().splitlines():
            if line.startswith("{") and json.loads(line).get("serving") is True:
                return json.loads(line)
        return None
    started = poll(serving, 120, 1)
    record(f"serve printed its serving line ({log})", bool(started) and process.poll() is None, started)
    return process


def setup_provider(tosctl_sha256: str) -> dict:
    base.private_dir(PROVIDER_RAIL, "provider")
    base.private_dir(base.GATEWAY_CARD.parent, "provider")
    rpc_flags = [flag for endpoint in provider_endpoints() for flag in ("--rpc", endpoint)]
    init = ["init", "--rail-config", str(RAIL_CONFIG), "--state-dir", str(PROVIDER_RAIL), *rpc_flags,
            "--global-config", str(base.PUBLIC / "global.json"), "--network-label", base.NETWORK_LABEL,
            "--tosctl", str(BIN / "tosctl"), "--tosctl-sha256", tosctl_sha256,
            "--tosctl-config", str(base.HOME["provider"] / "private" / "tosctl-config.json"), "--wallet", "provider",
            "--registry-code-boc", str(base.REGISTRY_BOC), "--actor-code-hash", base.ACTOR_CODE_HASH,
            "--relay-url", base.RELAY_URL, "--relay-ca-file", str(base.HOME["provider"] / "private" / "relay-ca.pem")]
    preview = provider_cli(*init, check=False)
    record("init without --yes prints its preview and exits 4", preview.returncode == 4 and
           (report(preview) or {}).get("confirmed") is False, {"exit": preview.returncode})
    initialized = report(provider_cli(*init, "--yes")) or {}
    record("init registered the provider Agent with the default packet controller",
           initialized.get("confirmed") is True and initialized.get("packet_controller") == "service-packet" and
           str(initialized.get("agent_id", "")).startswith("agent_"),
           {"agent_id": initialized.get("agent_id"), "packet_controller": initialized.get("packet_controller")})
    offer_flags = ["offer", "--rail-config", str(RAIL_CONFIG), "--price", "0.1", "--storage-fee", "0.2",
                   "--cleanup-bounty", "0.1", "--response-sla", str(WINDOW), "--refund-claim-window", str(WINDOW),
                   "--executor-socket", str(base.EXECUTOR_SOCKET), "--gateway-card-out", str(base.GATEWAY_CARD)]
    if TEST_PROFILE:
        offer_flags.append("--test-profile-actor")
    # offer resumes after a stop: a send whose outcome finalized state has
    # not established yet is never repeated, and a later run continues from
    # the journal. The harness runs it again, as an operator would, and
    # records every attempt.
    attempts = []
    offered = {}
    for _ in range(6):
        result = provider_cli(*offer_flags, "--yes", check=False)
        offered = report(result) or {}
        attempts.append({"exit": result.returncode, "last_stderr_line": (result.stderr.strip().splitlines() or [""])[-1]})
        if result.returncode == 0 and offered.get("confirmed") is True:
            break
        if "update-policy failed" in result.stderr and "policy_diagnosis" not in base.evidence:
            # The library keeps tosctl's own message to itself; the same send,
            # made once by the harness as the provider, records it.
            preview = offered.get("preview") or {}
            diagnosis = base.tosctl(
                "provider", "agent", "service", "send", "--operation", "update-policy", "--address",
                preview.get("actor", ""), "--from", "provider", "--price-per-call", "0.1", "--storage-fee", "0.2",
                "--cleanup-bounty", "0.1", "--response-sla", str(WINDOW), "--refund-claim-window", str(WINDOW),
                "--rate-limit-per-day", "0", "--active", "true", "--open-access", "--metadata-hash",
                preview.get("metadata_hash", ""), "--proof-scheme-hash", preview.get("proof_scheme_hash", ""),
                "--yes", check=False)
            base.evidence["policy_diagnosis"] = {"exit": diagnosis.returncode,
                                                 "stdout": diagnosis.stdout[-1500:], "stderr": diagnosis.stderr[-1500:]}
            record("diagnosis: the policy send made directly with tosctl", diagnosis.returncode == 0,
                   base.evidence["policy_diagnosis"])
        time.sleep(20)
    record("offer completed (runs of the command: %d)" % len(attempts), offered.get("confirmed") is True, attempts)
    offer = json.loads(base.as_account("provider", ["/bin/cat", str(PROVIDER_RAIL / "setup" / "offer.json")]).stdout)
    record("offer published the Capability and wrote the offer file and the gateway key card",
           offered.get("confirmed") is True and bool(offer.get("capability_id")),
           {"capability_id": offer.get("capability_id"), "next_steps": offered.get("next_steps"),
            "test_profile_actor": TEST_PROFILE, "windows_seconds": WINDOW})
    checked = provider_cli("preflight", "--rail-config", str(RAIL_CONFIG), check=False)
    readiness = report(checked) or {}
    record("preflight reports the node ready (exit 0)", checked.returncode == 0 and readiness.get("ok") is True,
           {"exit": checked.returncode, "failed": [c for c in readiness.get("checks", []) if c.get("status") == "fail"]})
    return offer


# --- Chain facts -----------------------------------------------------------------

def actor_transactions(actor: str) -> list:
    answer = rpc("getTransactions", address=actor, limit=100, lt="", hash="")
    return answer.get("result") or []


def message_opcode(message: dict):
    """The first 32 bits of an inbound message body, or None."""
    from pytosiq_core import Cell
    body = ((message or {}).get("msg_data") or {}).get("body")
    if not body:
        return None
    try:
        return Cell.one_from_boc(body).begin_parse().load_uint(32)
    except Exception:  # noqa: BLE001 - an empty or short body has no opcode
        return None


def responds(actor: str) -> list:
    """The actor's transactions whose inbound message is a respond."""
    return [tx for tx in actor_transactions(actor) if message_opcode(tx.get("in_msg")) == RESPOND_OPCODE]


# --- Scenario 1: a paid call, serve killed between execution and respond -------

WATCHER = """
import json, os, signal, sys, time
path, pid, deadline = sys.argv[1], int(sys.argv[2]), time.monotonic() + float(sys.argv[3])
seen = []
while time.monotonic() < deadline:
    try:
        with open(path) as handle:
            state = json.load(handle).get("state")
    except (OSError, ValueError):
        state = None
    if state and (not seen or seen[-1] != state):
        seen.append(state)
    if state == "executed":
        os.kill(pid, signal.SIGKILL)
        print(json.dumps({"killed": True, "state": state, "seen": seen}), flush=True)
        sys.exit(0)
    if state in ("responding", "delivering", "acked"):
        print(json.dumps({"killed": False, "state": state, "seen": seen}), flush=True)
        sys.exit(1)
    time.sleep(0.02)
print(json.dumps({"killed": False, "state": None, "seen": seen}), flush=True)
sys.exit(2)
"""


def quote_and_prepare(offer: dict, label: str) -> str:
    quoted = base.mcp("tos_buyer_quote", {"capability_id": offer["capability_id"],
                                          "capability_version": offer["version"], "source": "gateway"})
    quote = structured(quoted).get("quote") or structured(quoted)
    record(f"{label}: a gateway Quote carriable to the relay-only provider",
           not quoted["is_error"] and bool(quote.get("carriable")),
           {"quote_id": quote.get("quote_id"), "error": quote.get("error")})
    if not quote.get("quote_id"):
        base.diagnose_discovery(offer)
        raise RuntimeError(f"{label}: no Quote")
    prepared = base.mcp("tos_buyer_prepare", {"quote_id": quote["quote_id"], "source_path": str(base.source_tree()),
                                              "idempotency_key": "e2e-" + label.replace(" ", "-") + "-" +
                                                                 secrets.token_hex(4)})
    purchase = structured(prepared).get("purchase", {})
    record(f"{label}: prepare reserves the purchase and pays nothing",
           not prepared["is_error"] and purchase.get("state") == "awaiting_confirmation", purchase.get("state"))
    return purchase.get("request_hash", "")


def provider_record(request_hash: str) -> dict:
    path = PROVIDER_RAIL / "provider" / f"{request_hash}.json"
    result = base.as_account("provider", ["/bin/cat", str(path)], check=False)
    return json.loads(result.stdout) if result.returncode == 0 else {}


def scenario_paid_call(offer: dict, serve: subprocess.Popen) -> subprocess.Popen:
    request_hash = quote_and_prepare(offer, "paid call")
    record_path = PROVIDER_RAIL / "provider" / f"{request_hash}.json"
    HOLD["seconds"] = 2.0
    watcher = base.start("provider", [str(MOUNTS / "venv" / "bin" / "python3"), "-I", "-c", WATCHER, str(record_path),
                                      str(serve.pid), "1500"], "kill-watcher.log")
    paid = base.confirm_payment(request_hash)
    paid_state = structured(paid).get("purchase", {}).get("state")
    record("paid call: the confirmed purchase is paid with one call",
           not paid.get("is_error", True) and paid_state not in (None, "awaiting_confirmation", "declined"), paid_state)
    try:
        watcher.wait(timeout=1600)
    except subprocess.TimeoutExpired:
        pass
    lines = (WORK / "logs" / "kill-watcher.log").read_text().strip().splitlines()
    seen = json.loads(lines[-1]) if lines else {}
    try:
        status = serve.wait(timeout=60)
    except subprocess.TimeoutExpired:
        status = None
    # Popen reports death by a signal as the negative signal number.
    record("paid call: serve was killed by SIGKILL while its record was executed (executed, not responded)",
           seen.get("killed") is True and status == -signal.SIGKILL,
           {"watcher": seen, "serve_returncode": status})
    entry = provider_record(request_hash)
    actor = entry.get("actor", "")
    before = responds(actor) if actor else None
    record("paid call: no respond reached the actor before the restart", before == [],
           {"actor": actor, "state": entry.get("state"), "responds": len(before or [])})
    HOLD["seconds"] = 0.0
    serve = start_serve("provider-serve-2.log")
    result = poll(lambda: (lambda r: r if not r["is_error"] else None)(
        base.mcp("tos_buyer_result", {"request_hash": request_hash, "max_inline_bytes": 4096})), 1800, 20)
    accepted = structured(result) if result else {}
    files = accepted.get("files") or {}
    record("paid call: the buyer accepted the result against the finalized response hash",
           bool(result) and bool(files.get("receipt_boc")),
           {"response_hash": (accepted.get("result") or {}).get("response_hash"), "files": sorted(files)})
    base.mcp("tos_buyer_refund", {"request_hash": request_hash})
    acked = poll(lambda: provider_record(request_hash).get("state") == "acked", 600, 15)
    record("paid call: the provider recorded the buyer's ack", acked is not None,
           {"state": provider_record(request_hash).get("state")})
    after = responds(actor) if actor else []
    hashes = sorted({(tx.get("transaction_id") or {}).get("hash", "") for tx in after})
    record("paid call: exactly one respond reached the actor after the restart",
           len(after) == 1, {"responds": len(after), "transactions": hashes})
    evidence_for("paid_call", {"request_hash": request_hash, "actor": actor, "kill": seen,
                               "serve_returncode_after_kill": status, "responds": len(after)})
    return serve


# --- Scenario 2: withdraw the credited revenue -----------------------------------

def scenario_withdraw() -> None:
    before = provider_status().get("actor") or {}
    credited = int(before.get("credited_revenue_nanotos") or 0)
    record("withdraw: status shows credited revenue after the paid call", credited > 0,
           {"credited_revenue_nanotos": before.get("credited_revenue_nanotos")})
    preview = provider_cli("withdraw", "--rail-config", str(RAIL_CONFIG), "--all", check=False)
    record("withdraw without --yes previews and exits 4", preview.returncode == 4 and
           (report(preview) or {}).get("confirmed") is False, {"exit": preview.returncode})
    sent = provider_cli("withdraw", "--rail-config", str(RAIL_CONFIG), "--all", "--yes", check=False, timeout=1200)
    withdrawal = (report(sent) or {}).get("withdrawal") or {}
    record("withdraw --all --yes sends the withdrawal", sent.returncode == 0 and bool(withdrawal),
           {"exit": sent.returncode, "state": withdrawal.get("state"), "amount": withdrawal.get("amount_nanotos")})

    def finalized():
        status = provider_status()
        records = status.get("withdrawals") or []
        done = records and records[0].get("state") == "finalized"
        return status if done else None
    status = poll(finalized, 600, 10) or provider_status()
    latest = (status.get("withdrawals") or [{}])[0]
    left = int((status.get("actor") or {}).get("credited_revenue_nanotos") or 0)
    record("withdraw: finalized state shows the payout and no credited revenue left",
           latest.get("state") == "finalized" and int(latest.get("payout_nanotos") or 0) == credited and left == 0,
           {"state": latest.get("state"), "payout_nanotos": latest.get("payout_nanotos"), "credited_before": credited,
            "credited_after": left})
    evidence_for("withdraw", {"credited_before_nanotos": credited, "withdrawal": latest})


# --- Scenario 3: an unanswered call is refunded -----------------------------------

def scenario_refund(offer: dict) -> None:
    paused = report(provider_cli("pause", "--rail-config", str(RAIL_CONFIG), "--reason", "refund scenario")) or {}
    record("refund: pause stops new admissions", paused.get("paused") is True, paused)
    request_hash = quote_and_prepare(offer, "unanswered call")
    paid = base.confirm_payment(request_hash)
    record("refund: the unanswered call is paid", not paid.get("is_error", True), structured(paid).get("purchase", {}).get("state"))
    started = time.monotonic()

    def refunded():
        duty = structured(base.mcp("tos_buyer_refund", {"request_hash": request_hash})).get("duty") or {}
        seen.append({"status": duty.get("status"), "operation": duty.get("operation"), "sent": duty.get("sent")})
        return duty if duty.get("status") == "refunded" else None
    seen: list = []
    duty = poll(refunded, WINDOW * 3 + 900, 30)
    compact = [entry for index, entry in enumerate(seen) if index == 0 or entry != seen[index - 1]]
    record("refund: the buyer's duties expired the request and claimed the refund", bool(duty),
           {"seconds": int(time.monotonic() - started), "statuses": compact[-12:]})
    entry = provider_record(request_hash)
    record("refund: the paused provider admitted nothing for the unanswered call",
           entry.get("state") in (None, "") or entry == {}, {"provider_record_state": entry.get("state")})
    resumed = report(provider_cli("resume", "--rail-config", str(RAIL_CONFIG))) or {}
    record("refund: resume admits new requests again", resumed.get("paused") is False, resumed)
    evidence_for("refund", {"request_hash": request_hash, "statuses": compact, "window_seconds": WINDOW})


def evidence_for(name: str, value: dict) -> None:
    base.evidence.setdefault("scenarios", {})[name] = value


# --- Main -------------------------------------------------------------------------

async def main() -> int:
    from tostester.install import Install
    from tostester.n6_cluster import _wait_all_heights
    from tostester.network import Network, StartOptions, _write_model
    import os

    # As the mcp-buyer harness: take the work directory over for the run,
    # leaving the host's thermal log and build untouched.
    os.chown(WORK, 0, 0)
    for path in WORK.rglob("*"):
        if path.name == "thermal.jsonl" or path.is_symlink() or WORK / "bin" in [path, *path.parents] or \
                path == WORK / "build.json":
            continue
        os.chown(path, 0, 0)
    base.private_dir(WORK / "logs", None)
    build = json.loads((WORK / "build.json").read_text())
    base.evidence.update({
        "schema": "tos.service.provider-buyer.local-e2e.v1",
        "qualifies_as_public_acceptance": False,
        "reason": "one container runs every validator, the relay, the gateway and both parties",
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "build": build, "actor_code_hash": base.ACTOR_CODE_HASH, "network_label": base.NETWORK_LABEL,
        "provider": "tos-service-provider", "test_profile_actor": TEST_PROFILE,
        "refund_scenario": "skipped (E2E_SKIP_REFUND=1)" if base.SKIP_REFUND else "run",
        "stand_ins": {"executor": "software-work-executord-e2e: the real executor service with a backend that reads "
                                  "the source archive and executes nothing"}})
    serve = None
    try:
        base.install_binaries(build)
        base.private_dir(base.PUBLIC, None, 0o755)
        base.setup_accounts()
        async with Network(Install(MOUNTS / "tos-build", MOUNTS / "tos-source"), Path("/var/lib/e2e-network"),
                           base_port=base.BASE_PORT) as network:
            dht = network.create_dht_node()
            nodes = []
            for _ in base.RPC_PORTS:
                node = network.create_full_node()
                node.announce_to(dht)
                node.make_initial_pq_validator(secrets.token_bytes(32), secrets.token_bytes(32))
                nodes.append(node)
            await dht.run(StartOptions(threads=1, verbosity=1))
            for node, port in zip(nodes, base.RPC_PORTS):
                await node.run(StartOptions(threads=2, verbosity=1, args=["--json-rpc-address", f"127.0.0.1:{port}"]))
            await _wait_all_heights(nodes, 5, 300)
            client = await nodes[0].toslib_client()
            global_config = json.loads((nodes[0].directory / "config.global.json").read_text())
            _write_model(WORK / "liteserver.json", nodes[0].liteserver_config)
            global_config["liteservers"] = json.loads((WORK / "liteserver.json").read_text())["liteservers"]
            (base.PUBLIC / "global.json").write_text(json.dumps(global_config, indent=2))
            (base.PUBLIC / "global.json").chmod(0o644)
            zerostate = network.zerostate.as_block()
            base.evidence["network"] = {"network_id": base.NETWORK_LABEL,
                                        "genesis_root_hash": "sha256:" + zerostate.root_hash.hex(),
                                        "genesis_file_hash": "sha256:" + zerostate.file_hash.hex(),
                                        "validators": len(nodes)}
            ready = poll(lambda: "result" in rpc("getMasterchainInfo"), 180)
            record("every validator serves finalized JSON-RPC", bool(ready))
            base.evidence["wallets"] = await base.provision(network.zerostate.main_wallet(client))
            base.start_relay()
            base.start_executor()
            start_proxies()
            tosctl_sha256 = build["tosctl_sha256"]
            base.evidence["registry_code_hash"] = json.loads(base.as_account(None, [
                str(BIN / "service-actor-e2e-fixture"), "code-hash", "--boc-file", str(base.REGISTRY_BOC)]).stdout)["code_hash"]
            offer = setup_provider(tosctl_sha256)
            base.evidence["provider_offer"] = offer
            serve = start_serve("provider-serve-1.log")
            base.start_gateway(offer["provider_agent_id"])
            base.evidence["buyer"] = base.setup_buyer(base.evidence["wallets"]["custody"], tosctl_sha256)
            serve = scenario_paid_call(offer, serve)
            scenario_withdraw()
            if not base.SKIP_REFUND:
                scenario_refund(offer)
    except Exception as error:  # noqa: BLE001 - the evidence records the failure
        import traceback
        record("run completed without an exception", False, {"error": repr(error),
                                                              "traceback": traceback.format_exc()[-4000:]})
    finally:
        base.stop_all()
    base.evidence["steps"] = base.steps
    thermal = WORK / "thermal.jsonl"
    base.evidence["thermal_pauses"] = [json.loads(line) for line in thermal.read_text().splitlines()] \
        if thermal.exists() else []
    base.evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    passed = bool(base.steps) and all(step["pass"] for step in base.steps)
    base.evidence["result"] = "ALL PASS" if passed else "FAIL"
    (WORK / "evidence.json").write_text(json.dumps(base.redact_value(base.evidence), indent=2) + "\n")
    print(f"evidence: {WORK / 'evidence.json'}")
    print("ALL PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    status = 1
    try:
        status = asyncio.run(main())
    finally:
        base.give_back()
    sys.exit(status)
