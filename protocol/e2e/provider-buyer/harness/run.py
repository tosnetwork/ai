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
   then `--yes`, until finalized state shows the withdrawal: the actor's
   withdraw_revenue transaction, its transfer to the provider wallet, and the
   wallet's balance before and after.
3. An unanswered call: admission is paused, the buyer pays, nothing is
   responded, and once the response window is over the request is expired
   and the buyer agent claims the refund; the chain shows the expire, the
   claim and the transfer to the buyer wallet, received after the claim, and
   the buyer wallet's balance moves within the bounds of what it sent the
   actor and received from it after the paying call. With the release Service
   Actor build the response window is at least an hour, so the scenario
   takes about an hour; E2E_SKIP_REFUND=1 skips it. (The test-only build's
   600 s windows would shorten it, but tosctl operates only the release
   build: a test-only actor can be deployed and not configured.)

Chain facts the checks rest on (respond counts, the withdrawal, the refund,
wallet balances) are read from every validator's JSON-RPC and taken only
when a strict majority of them agree, not from the provider's own status.

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
# Service Actor inbound opcodes (protocol/pkg/nativecore/service_actor.go).
CALL_OPCODE = 0x53564301
RESPOND_OPCODE = 0x53564302
EXPIRE_OPCODE = 0x53564303
CLAIM_REFUND_OPCODE = 0x53564304
WITHDRAW_OPCODE = 0x53564309
# What a wallet may lose to fees on one send, beyond the value it attached.
FEE_ALLOWANCE = NANO // 10
# The offer's price per call, "--price 0.1" below.
PRICE = "0.1"
PRICE_NANO = NANO // 10

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
    offer_flags = ["offer", "--rail-config", str(RAIL_CONFIG), "--price", PRICE, "--storage-fee", "0.2",
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
            # made once by the harness as the provider, records it. That send
            # is the harness's, not the program's: whatever it returns, the
            # step fails, so an offer that a later attempt completes on top of
            # it can never make the run pass.
            preview = offered.get("preview") or {}
            diagnosis = base.tosctl(
                "provider", "agent", "service", "send", "--operation", "update-policy", "--address",
                preview.get("actor", ""), "--from", "provider", "--price-per-call", PRICE, "--storage-fee", "0.2",
                "--cleanup-bounty", "0.1", "--response-sla", str(WINDOW), "--refund-claim-window", str(WINDOW),
                "--rate-limit-per-day", "0", "--active", "true", "--open-access", "--metadata-hash",
                preview.get("metadata_hash", ""), "--proof-scheme-hash", preview.get("proof_scheme_hash", ""),
                "--yes", check=False)
            base.evidence["policy_diagnosis"] = {"exit": diagnosis.returncode,
                                                 "stdout": diagnosis.stdout[-1500:], "stderr": diagnosis.stderr[-1500:]}
            record("diagnosis (fails the run): offer's policy send failed; the harness made the same send with "
                   "tosctl", False, base.evidence["policy_diagnosis"])
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
#
# Every chain fact a check rests on is read from each validator's JSON-RPC
# directly (not through the provider's proxies) and taken only when a strict
# majority of the validators return the same value.

def rpc_at(port: int, method: str, **params) -> dict:
    import urllib.request
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{port}/jsonRPC", data=body,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def majority_read(method: str, view, timeout: float = 180, **params):
    """view(answer) as a strict majority of the validators return it, polled
    until they agree. Returns {"value": ..., "agreeing": n, "of": m}, or None
    when no strict majority agreed before the timeout."""
    def attempt():
        tally: dict = {}
        for port in base.RPC_PORTS:
            try:
                value = view(rpc_at(port, method, **params))
            except Exception:  # noqa: BLE001 - a validator that cannot answer does not vote
                continue
            entry = tally.setdefault(json.dumps(value, sort_keys=True), [value, 0])
            entry[1] += 1
        for value, count in tally.values():
            if count * 2 > len(base.RPC_PORTS):
                return {"value": value, "agreeing": count, "of": len(base.RPC_PORTS)}
        return None
    return poll(attempt, timeout, 3)


def decode_transaction(transaction: dict) -> dict:
    """The facts of one transaction, decoded from the BOC the endpoint
    returns: its hash, the inbound opcode, sender and value, whether it was
    aborted, and its outbound internal transfers. decoded is False when the
    BOC does not decode."""
    from pytosiq_core import Cell, InternalMsgInfo, Transaction
    facts = {"hash": (transaction.get("transaction_id") or {}).get("hash", ""), "decoded": False}
    try:
        decoded = Transaction.deserialize(Cell.one_from_boc(transaction["data"]).begin_parse())
    except Exception as error:  # noqa: BLE001 - recorded; a check that needs a decode fails on it
        facts["error"] = repr(error)
        return facts
    facts.update({"decoded": True, "lt": decoded.lt, "opcode": None, "source": None, "value": 0,
                  "aborted": bool(getattr(decoded.description, "aborted", True)), "transfers": []})
    message = decoded.in_msg
    if message is not None:
        if isinstance(message.info, InternalMsgInfo):
            facts["source"] = message.info.src.to_str(is_user_friendly=False).lower() if message.info.src else None
            facts["value"] = message.info.value_coins
        body = message.body.begin_parse()
        if body.remaining_bits >= 32:
            facts["opcode"] = body.load_uint(32)
    for out in decoded.out_msgs:
        if isinstance(out.info, InternalMsgInfo):
            facts["transfers"].append({"to": out.info.dest.to_str(is_user_friendly=False).lower(),
                                       "value": out.info.value_coins})
    return facts


def account_transactions(address: str) -> dict:
    """An account's latest transactions, decoded, as a strict majority of the
    validators return them, or None."""
    return majority_read("getTransactions", lambda answer: [decode_transaction(tx) for tx in answer["result"]],
                         address=address, limit=100, lt="", hash="")


def wallet_balance(address: str):
    read = majority_read("getAddressInformation", lambda answer: int(answer["result"]["balance"]), address=address)
    return read["value"] if read else None


def with_opcode(transactions: list, opcode: int) -> list:
    return [tx for tx in transactions if tx.get("opcode") == opcode]


def paid_to(transaction: dict, address: str) -> int:
    return sum(transfer["value"] for transfer in transaction.get("transfers", []) if transfer["to"] == address)


def credited_from(wallet: str, sender: str, origin: dict):
    """The wallet's transaction that received an outbound transfer of origin,
    a transaction of the sender, as a strict majority of the validators
    return it, polled until it appears. It must come from the sender, carry
    exactly one of the values origin sent to the wallet, and have a logical
    time after origin's, so an older transfer of the same value can never
    stand in for it. None when origin sent the wallet nothing."""
    values = [transfer["value"] for transfer in origin.get("transfers", []) if transfer["to"] == wallet]
    if not values or not origin.get("decoded"):
        return None

    def found():
        read = account_transactions(wallet)
        for tx in (read or {}).get("value", []):
            if tx.get("decoded") and tx.get("source") == sender and tx.get("value") in values \
                    and tx.get("lt", 0) > origin["lt"] and not tx.get("aborted"):
                return tx
        return None
    return poll(found, 180, 5)


def respond_count(actor: str) -> dict:
    """How many transactions of the actor carry a respond, accepted or not (a
    second respond would be one), from a strict-majority read. The read must
    also hold the call that paid for the request, decoded: a decoder that
    decodes nothing would otherwise count zero responds."""
    read = account_transactions(actor)
    transactions = (read or {}).get("value") or []
    return {"read": bool(read), "agreeing": (read or {}).get("agreeing"), "transactions": len(transactions),
            "decoded": sum(1 for tx in transactions if tx.get("decoded")),
            "calls": len(with_opcode(transactions, CALL_OPCODE)),
            "responds": len(with_opcode(transactions, RESPOND_OPCODE)),
            "respond_hashes": sorted(tx["hash"] for tx in with_opcode(transactions, RESPOND_OPCODE))}


def respond_read_sound(count: dict) -> bool:
    return count["read"] and count["decoded"] == count["transactions"] and count["calls"] >= 1


# --- Scenario 1: a paid call, serve killed between execution and respond -------

WATCHER = """
import json, os, signal, sys, time
directory, request_hash = sys.argv[1], sys.argv[2]
pid, deadline = int(sys.argv[3]), time.monotonic() + float(sys.argv[4])
seen = []
def current_state():
    # A record is named by its slot, not its request hash: find it by the
    # request hash it holds.
    try:
        names = os.listdir(directory)
    except OSError:
        return None
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(directory, name)) as handle:
                record = json.load(handle)
        except (OSError, ValueError):
            continue
        if record.get("request_hash") == request_hash:
            return record.get("state")
    return None
while time.monotonic() < deadline:
    state = current_state()
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


def provider_record(request_hash: str, strict: bool = False):
    """The provider's local record of a request, found by the request hash it
    holds (records are named by their slot), or {} when none holds it. With
    strict, None when the records could not all be listed and read, so that
    "no record" is never concluded from a failed read."""
    records = PROVIDER_RAIL / "provider"
    listed = base.as_account("provider", ["/usr/bin/find", str(records), "-maxdepth", "1", "-name", "*.json"],
                             check=False)
    if listed.returncode != 0:
        return None if strict else {}
    for name in listed.stdout.split():
        result = base.as_account("provider", ["/bin/cat", name], check=False)
        try:
            entry = json.loads(result.stdout) if result.returncode == 0 else None
        except json.JSONDecodeError:
            entry = None
        if entry is None:
            if strict:
                return None
            continue
        if entry.get("request_hash") == request_hash:
            return entry
    return {}


def scenario_paid_call(offer: dict, serve: subprocess.Popen) -> subprocess.Popen:
    request_hash = quote_and_prepare(offer, "paid call")
    HOLD["seconds"] = 2.0
    watcher = base.start("provider", [str(MOUNTS / "venv" / "bin" / "python3"), "-I", "-c", WATCHER,
                                      str(PROVIDER_RAIL / "provider"), request_hash, str(serve.pid), "1500"],
                         "kill-watcher.log")
    paid = base.confirm_payment(request_hash)
    paid_state = structured(paid).get("purchase", {}).get("state")
    record("paid call: the confirmed purchase is paid with one call",
           not paid.get("is_error", True) and paid_state not in (None, "awaiting_confirmation", "declined"), paid_state)
    try:
        watcher_status = watcher.wait(timeout=1600)
    except subprocess.TimeoutExpired:
        watcher_status = None
        base.as_account("provider", ["/bin/kill", "-TERM", str(watcher.pid)], check=False)
    record("paid call: the kill watcher ended on its own", watcher_status is not None,
           {"watcher_exit": watcher_status})
    lines = (WORK / "logs" / "kill-watcher.log").read_text().strip().splitlines()
    seen = json.loads(lines[-1]) if lines else {}
    try:
        status = serve.wait(timeout=60)
    except subprocess.TimeoutExpired:
        status = None
    # Popen reports death by a signal as the negative signal number.
    record("paid call: serve was killed by SIGKILL while its record was executed (executed, not responded)",
           seen.get("killed") is True and status == -signal.SIGKILL and watcher_status == 0,
           {"watcher": seen, "serve_returncode": status})
    entry = provider_record(request_hash)
    actor = entry.get("actor", "")
    record("paid call: after the kill the provider's record still reads executed (the kill landed before "
           "the respond was recorded)", entry.get("state") == "executed", {"state": entry.get("state")})
    before = respond_count(actor) if actor else None
    record("paid call: no respond reached the actor before the restart (strict-majority read of the actor's "
           "transactions, every one decoded, the paying call among them)",
           before is not None and respond_read_sound(before) and before["responds"] == 0,
           {"actor": actor, "state": entry.get("state"), "read": before})
    HOLD["seconds"] = 0.0
    serve = start_serve("provider-serve-2.log")
    result = poll(lambda: (lambda r: r if not r["is_error"] else None)(
        base.mcp("tos_buyer_result", {"request_hash": request_hash, "max_inline_bytes": 4096})), 1800, 20)
    accepted = structured(result) if result else {}
    files = accepted.get("files") or {}
    record("paid call: the buyer accepted the result against the finalized response hash",
           bool(result) and bool(files.get("receipt_boc")),
           {"response_hash": (accepted.get("result") or {}).get("response_hash"), "files": sorted(files)})
    # The agent's duty round after acceptance sends the ack (refund_now runs
    # that round now and reports it).
    round_ = base.mcp("tos_buyer_refund", {"request_hash": request_hash})
    duty = structured(round_).get("duty") or {}
    record("paid call: the agent's result round after acceptance (ack sent or due)",
           not round_.get("is_error", True) and bool((duty.get("result") or {}).get("accepted")), duty.get("result"))
    acked = poll(lambda: provider_record(request_hash).get("state") == "acked", 600, 15)
    record("paid call: the provider recorded the buyer's ack", acked is not None,
           {"state": provider_record(request_hash).get("state")})
    after = respond_count(actor) if actor else None
    record("paid call: exactly one respond reached the actor after the restart (strict-majority read)",
           after is not None and respond_read_sound(after) and after["responds"] == 1, after)
    evidence_for("paid_call", {"request_hash": request_hash, "actor": actor, "kill": seen,
                               "serve_returncode_after_kill": status, "before_restart": before,
                               "after_restart": after})
    if not actor:
        raise RuntimeError("paid call: the provider's record names no actor")
    return serve, actor


# --- Scenario 2: withdraw the credited revenue -----------------------------------

def scenario_withdraw(actor: str) -> None:
    wallet = base.evidence["wallets"]["provider"]
    balance_before = wallet_balance(wallet)
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
    # The program's record says the payout finalized and leaves the wallet
    # credit unverified; the chain is checked here, independently of it.
    read = account_transactions(actor)
    withdrawals = with_opcode((read or {}).get("value") or [], WITHDRAW_OPCODE)
    accepted = [tx for tx in withdrawals if tx.get("source") == wallet and not tx.get("aborted")]
    sent_out = paid_to(accepted[0], wallet) if len(accepted) == 1 else 0
    record("withdraw: on chain, the actor accepted one withdraw_revenue from the provider wallet and sent it at "
           "least the credited amount (strict-majority read)", len(accepted) == 1 and credited > 0 and
           sent_out >= credited, {"withdraw_transactions": withdrawals, "sent_to_wallet_nanotos": sent_out})
    credit = credited_from(wallet, actor, accepted[0]) if credited > 0 and len(accepted) == 1 else None
    attached = int(withdrawal.get("attached_nanotos") or latest.get("attached_nanotos") or 0)
    # The wallet paid the attached value and its own fee and received what the
    # actor sent (the payout plus the change of the attached value). Read
    # after the credit is final; polled briefly for a lagging majority.

    def within(value):
        return value is not None and balance_before is not None and \
            sent_out - attached - FEE_ALLOWANCE <= value - balance_before <= sent_out
    balance_after = poll(lambda: (lambda value: value if within(value) else None)(wallet_balance(wallet)), 60, 5) \
        if credit is not None else None
    if balance_after is None:
        balance_after = wallet_balance(wallet)
    delta = balance_after - balance_before if balance_after is not None and balance_before is not None else None
    record("withdraw: on chain, the provider wallet received the transfer and its balance moved by it, less "
           "the attached value and fees", credit is not None and within(balance_after),
           {"credit_transaction": (credit or {}).get("hash"), "credit_nanotos": (credit or {}).get("value"),
            "balance_before": balance_before, "balance_after": balance_after, "delta_nanotos": delta,
            "attached_nanotos": attached, "fee_allowance_nanotos": FEE_ALLOWANCE})
    evidence_for("withdraw", {"credited_before_nanotos": credited, "withdrawal": latest,
                              "on_chain": {"withdraw_transactions": withdrawals, "sent_to_wallet_nanotos": sent_out,
                                           "wallet_balance_before": balance_before,
                                           "wallet_balance_after": balance_after, "delta_nanotos": delta}})


# --- Scenario 3: an unanswered call is refunded -----------------------------------

def scenario_refund(offer: dict, actor: str) -> None:
    buyer_wallet = base.evidence["wallets"]["custody"]
    paused = report(provider_cli("pause", "--rail-config", str(RAIL_CONFIG), "--reason", "refund scenario")) or {}
    record("refund: pause stops new admissions", paused.get("paused") is True, paused)
    request_hash = quote_and_prepare(offer, "unanswered call")

    def buyer_calls():
        read = account_transactions(actor)
        return [tx for tx in with_opcode((read or {}).get("value") or [], CALL_OPCODE)
                if tx.get("source") == buyer_wallet and not tx.get("aborted")] if read else None
    # The buyer's calls already at the actor, read before the payment. A read
    # that failed is not "no calls" (None stays distinct from []): taking it
    # as none would let any earlier call stand for the paying one.
    read_before = poll(lambda: (lambda calls: (calls,) if calls is not None else None)(buyer_calls()), 120, 5)
    calls_before = read_before[0] if read_before else None
    record("refund: the buyer's calls at the actor are read before the payment", calls_before is not None,
           {"calls_before": None if calls_before is None else len(calls_before)})
    paid = base.confirm_payment(request_hash)
    record("refund: the unanswered call is paid", not paid.get("is_error", True), structured(paid).get("purchase", {}).get("state"))
    started = time.monotonic()
    # The buyer's balance after the call, read once the call itself is
    # finalized at the actor and the change it sent the buyer wallet is
    # received there: the change can land in a later block than the call,
    # and the bound below counts only what the actor sent after the call.
    new_calls = (poll(lambda: (lambda calls: calls if calls is not None and len(calls) > len(calls_before) else None)(
        buyer_calls()), 300, 5) or []) if calls_before is not None else []
    call_lt = max((tx["lt"] for tx in new_calls), default=None)
    paying = [tx for tx in new_calls if tx["lt"] == call_lt]
    change_sent = paid_to(paying[0], buyer_wallet) if paying else 0
    change = credited_from(buyer_wallet, actor, paying[0]) if change_sent > 0 else None
    change_received = change_sent == 0 or change is not None
    balance_paid = wallet_balance(buyer_wallet) if call_lt is not None and change_received else None
    record("refund: the paying call is finalized at the actor and its change is received by the buyer wallet "
           "before the buyer's balance is read",
           call_lt is not None and change_received and balance_paid is not None,
           {"call_lt": call_lt, "change_sent_nanotos": change_sent, "change_transaction": (change or {}).get("hash"),
            "balance": balance_paid})

    def refunded():
        duty = structured(base.mcp("tos_buyer_refund", {"request_hash": request_hash})).get("duty") or {}
        seen.append({"status": duty.get("status"), "operation": duty.get("operation"), "sent": duty.get("sent")})
        return duty if duty.get("status") == "refunded" else None
    seen: list = []
    duty = poll(refunded, WINDOW * 3 + 900, 30)
    compact = [entry for index, entry in enumerate(seen) if index == 0 or entry != seen[index - 1]]
    sent_operations = sorted({entry["operation"] for entry in seen if entry.get("sent") and entry.get("operation")})
    record("refund: the buyer agent's duty status reads refunded once the response window is over", bool(duty),
           {"seconds": int(time.monotonic() - started), "statuses": compact[-12:],
            "operations_sent_through_refund_calls": sent_operations})
    # On chain: the request was expired (permissionless; the call above names
    # who sent it) and the buyer's claim_refund paid the price to the buyer
    # wallet, which holds the transfer.
    read = account_transactions(actor)
    transactions = (read or {}).get("value") or []
    expires = [tx for tx in with_opcode(transactions, EXPIRE_OPCODE) if not tx.get("aborted")]
    claims = [tx for tx in with_opcode(transactions, CLAIM_REFUND_OPCODE)
              if tx.get("source") == buyer_wallet and not tx.get("aborted")]
    price = PRICE_NANO
    refunded_out = paid_to(claims[0], buyer_wallet) if len(claims) == 1 else 0
    credit = credited_from(buyer_wallet, actor, claims[0]) if refunded_out >= price else None
    record("refund: on chain, the request was expired and one claim_refund from the buyer wallet paid at least "
           "the price back to it, received by the buyer wallet after the claim (strict-majority read)",
           bool(expires) and len(claims) == 1 and refunded_out >= price and credit is not None,
           {"expire_transactions": [{"hash": tx["hash"], "from": tx.get("source")} for tx in expires],
            "claim_refund_transactions": [tx["hash"] for tx in claims], "sent_to_buyer_nanotos": refunded_out,
            "price_nanotos": price, "buyer_credit_transaction": (credit or {}).get("hash")})
    # Bound the buyer's balance by what moved between it and the actor after
    # the paying call: it gained at most what the actor sent it less the
    # values it attached, and lost at most one fee allowance per send on top.
    window = [tx for tx in transactions if call_lt is not None and tx.get("lt", 0) > call_lt]
    sends = [tx for tx in window if tx.get("source") == buyer_wallet]
    received = sum(paid_to(tx, buyer_wallet) for tx in window)
    attached = sum(tx.get("value", 0) for tx in sends)
    high = received - attached
    low = high - FEE_ALLOWANCE * len(sends)

    def bounded(value):
        return value is not None and balance_paid is not None and low <= value - balance_paid <= high
    balance_refunded = poll(lambda: (lambda value: value if bounded(value) else None)(wallet_balance(buyer_wallet)),
                            60, 5) if credit is not None else None
    if balance_refunded is None:
        balance_refunded = wallet_balance(buyer_wallet)
    delta = balance_refunded - balance_paid if balance_refunded is not None and balance_paid is not None else None
    record("refund: on chain, the buyer wallet's balance moved by the refund and change the actor sent it, less "
           "the values it attached and at most one fee allowance per send (strict-majority read)",
           credit is not None and bounded(balance_refunded) and delta is not None and delta > 0,
           {"buyer_balance_after_payment": balance_paid, "buyer_balance_after_refund": balance_refunded,
            "delta_nanotos": delta, "received_from_actor_nanotos": received, "attached_nanotos": attached,
            "sends_to_actor": len(sends), "bounds_nanotos": [low, high], "fee_allowance_nanotos": FEE_ALLOWANCE})
    entry = provider_record(request_hash, strict=True)
    record("refund: the paused provider admitted nothing for the unanswered call", entry == {},
           {"provider_record": "unreadable: the records could not all be listed and read" if entry is None else
            "none: no provider record holds the request hash" if entry == {} else entry.get("state")})
    resumed = report(provider_cli("resume", "--rail-config", str(RAIL_CONFIG))) or {}
    record("refund: resume admits new requests again", resumed.get("paused") is False, resumed)
    evidence_for("refund", {"request_hash": request_hash, "statuses": compact, "window_seconds": WINDOW,
                            "on_chain": {"expires": expires, "claims": claims, "sent_to_buyer_nanotos": refunded_out}})


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
            serve, actor = scenario_paid_call(offer, serve)
            scenario_withdraw(actor)
            if not base.SKIP_REFUND:
                scenario_refund(offer, actor)
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
    # A pause freezes the whole container; the run's result says how often.
    base.evidence["thermal_pause_count"] = sum(1 for entry in base.evidence["thermal_pauses"]
                                               if entry.get("event") == "pause")
    print(f"thermal pauses: {base.evidence['thermal_pause_count']}")
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
