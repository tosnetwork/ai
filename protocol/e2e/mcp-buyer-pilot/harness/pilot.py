"""Containers of the agent-operated Gate D pilot on the epoch-7 public testnet.

A thin layer over the MCP buyer e2e harness (protocol/e2e/mcp-buyer): the
same digest-pinned image, the same pty confirmer, the same custody and
developer split, the same root-owned binaries checked against build.json.
What differs is the network: the chain is the public epoch-7 testnet, read
through each role's own `pilot-rpc` SSH forwards to three validators'
loopback JSON-RPC, and the relays are the public test relays with their
private CA. Each role runs in its own container on the coordinator host:

- provider: OpenFox as the uid the host's executor service admits, with its
  own fresh tosctl wallet, Agent, Service Actor and Capability;
- buyer: custody (2001) runs `tos-service-buyer init`, the agent and the
  confirmer; developer (2002) runs the MCP client. Claude Code is started
  from the host with `docker exec -u developer`, never by this harness, so
  the model's credential never enters this process;
- verifier: only its own forwards; Codex is started from the host.

Nothing here is a human. The confirmer is the real `tos-service-buyer
confirm --watch` on a pty custody owns, decided by confirm_policy.

Commands (as container root):

  serve provider|buyer|verifier   the role container's main process
  chain-state HASH...             finalized state of requests (read only)
  provider ACTION                 pause, resume, status, withdraw
  export LABEL HASH               the buyer's evidence export, as custody
  sign ROLE HEX                   a declaration signature (custody|provider)
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

MOUNTS = Path("/pilot-mounts")
PUBLIC_IN = MOUNTS / "public"
BIN = Path("/opt/pilot-bin")
WORK = Path("/pilot/work")
HOMES = WORK / "homes"
CONTROL = WORK / "control"
OUT = WORK / "out"
LOGS = WORK / "logs"
PUBLIC = OUT / "public"
sys.path.insert(0, str(MOUNTS / "scripts"))
sys.path.insert(0, str(MOUNTS / "harness"))
from service_actor_e2e_redact import redact, redact_value, register_secret  # noqa: E402
import confirm_policy  # noqa: E402
from confirmer import WatchConfirmer  # noqa: E402

PROVIDER_UID = int(os.environ.get("PILOT_PROVIDER_UID", "1000"))
EXECUTOR_GID = int(os.environ.get("PILOT_EXECUTOR_GID", "997"))
ACCOUNTS = {"custody": (2001, 2001), "developer": (2002, 2002), "provider": (PROVIDER_UID, PROVIDER_UID),
            "verifier": (2101, 2101)}
SOCKET_GROUP = 2003
HOME = {name: HOMES / name for name in ACCOUNTS}
SOCKET_DIR = Path("/run/tos-buyer")
SOCKET = SOCKET_DIR / "agent.sock"
EXECUTOR_SOCKET = Path("/run/tos-service-executor/executor.sock")
TUNNEL_ACCOUNT = {"provider": "provider", "buyer": "custody", "verifier": "verifier"}

# The network, the validators the forwards reach and the relays come from
# the operator's pilot-endpoints.json beside the pilot pack, not from here.
_ENDPOINTS = json.loads((PUBLIC_IN / "pilot-endpoints.json").read_text())
NETWORK_LABEL = _ENDPOINTS["network_label"]
VALIDATORS = [(v["name"], v["host"], int(v["local_port"])) for v in _ENDPOINTS["validators"]]
RELAYS = list(_ENDPOINTS["relays"])
RPC = [f"http://127.0.0.1:{port}/jsonRPC" for _, _, port in VALIDATORS]
RPC_BASES = [f"http://127.0.0.1:{port}" for _, _, port in VALIDATORS]

# The frozen terms (GATE-D-AGENT-PILOT-PLAN section 4). The windows follow the
# actor release: 3600 s is the production actor's minimum; a test-profile
# actor (its own code hash, ACTOR_CODE_HASH) admits 600 s.
TERMS = {"price": "0.1", "storage_fee": "0.2", "cleanup_bounty": "0.1",
         "response_sla": int(os.environ.get("PILOT_RESPONSE_SLA", "3600")),
         "refund_claim_window": int(os.environ.get("PILOT_REFUND_WINDOW", "3600"))}
ALLOWANCE_NANOTOS = "200000000"
FUNDING_NANOTOS = {"provider": 5_600_000_000, "buyer": 4_000_000_000}
JOB = {"go.mod": "module example.test/paidwork\n\ngo 1.26.5\n",
       "work_test.go": "package paidwork\n\nimport \"testing\"\n\nfunc TestWork(t *testing.T) {\n"
                       "\tif 2+2 != 4 {\n\t\tt.Fatal(\"arithmetic\")\n\t}\n}\n"}

processes: list = []
tunnels: dict = {}


# --- Plumbing ---------------------------------------------------------------------

def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def record(name: str, ok: bool, detail=None) -> None:
    entry = {"name": name, "pass": bool(ok), "detail": redact_value(detail), "at": now()}
    with (LOGS / "steps.jsonl").open("a") as handle:
        handle.write(json.dumps(entry) + "\n")
    print(("PASS " if ok else "FAIL ") + name, flush=True)
    if not ok:
        raise RuntimeError(f"step failed: {name}")


def groups_of(account: str) -> list:
    return {"developer": [SOCKET_GROUP], "provider": [EXECUTOR_GID]}.get(account, [])


def vault_env(account: str) -> dict:
    """The account's VAULT_URL, read as that account from its own file."""
    text = subprocess.run(["/bin/cat", str(HOME[account] / "private" / "vault.env")], capture_output=True, text=True,
                          user=ACCOUNTS[account][0], group=ACCOUNTS[account][1], extra_groups=[],
                          env={"PATH": "/usr/bin:/bin"}).stdout
    value = text.strip().removeprefix("VAULT_URL=")
    if not value.startswith("file://"):
        raise RuntimeError(f"{account} has no vault")
    register_secret(value)
    return {"VAULT_URL": value}


def account_env(account: str | None, vault: bool) -> tuple[dict, dict]:
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    kwargs = {}
    if account is not None:
        uid, gid = ACCOUNTS[account]
        kwargs = {"user": uid, "group": gid, "extra_groups": groups_of(account)}
        env["HOME"] = str(HOME[account])
        if vault:
            env.update(vault_env(account))
    return env, kwargs


def as_account(account: str | None, command: list, *, check: bool = True, timeout: int = 900,
               input_text: str | None = None, vault: bool = False, groups: list | None = None
               ) -> subprocess.CompletedProcess:
    env, kwargs = account_env(account, vault)
    if groups is not None and account is not None:
        kwargs["extra_groups"] = groups
    result = subprocess.run([str(c) for c in command], capture_output=True, text=True, timeout=timeout, env=env,
                            input=input_text, **kwargs)
    with (LOGS / "transcript.jsonl").open("a") as transcript:
        transcript.write(json.dumps({"at": now(), "account": account or "root",
                                     "command": redact(" ".join(map(str, command)))[:2000], "status": result.returncode,
                                     "stdout": redact(result.stdout[-6000:]),
                                     "stderr": redact(result.stderr[-6000:])}) + "\n")
    if check and result.returncode != 0:
        raise RuntimeError(f"{Path(str(command[0])).name} failed: {redact(result.stderr[-2000:])}")
    return result


def start(account: str | None, command: list, log: str, vault: bool = False) -> subprocess.Popen:
    env, kwargs = account_env(account, vault)
    out = open(LOGS / log, "a")
    process = subprocess.Popen([str(c) for c in command], stdout=out, stderr=subprocess.STDOUT, env=env, **kwargs)
    processes.append((account, process))
    return process


def stop_all() -> None:
    for account, process in reversed(processes + list(tunnels.values())):
        if process.poll() is None:
            if account is None:
                process.terminate()
            else:
                as_account(account, ["/bin/kill", "-TERM", str(process.pid)], check=False)
    for _, process in processes + list(tunnels.values()):
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            pass


def poll(predicate, timeout: float, interval: float = 2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = predicate()
        except Exception:  # noqa: BLE001 - a poll retries until its deadline
            value = None
        if value:
            return value
        time.sleep(interval)
    return None


def last_json(text: str):
    start_at = text.find("{")
    return json.loads(text[start_at:]) if start_at >= 0 else None


def account_dir(path: Path, account: str, mode: int = 0o700) -> Path:
    as_account(account, ["/bin/mkdir", "-p", "-m", oct(mode)[2:], path])
    as_account(account, ["/bin/chmod", oct(mode)[2:], path])
    return path


def root_dir(path: Path, mode: int = 0o755) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, 0, 0)
    path.chmod(mode)
    return path


def write_as(account: str, path: Path, text: str, mode: str = "0600") -> None:
    as_account(account, ["/usr/bin/tee", path], input_text=text)
    as_account(account, ["/bin/chmod", mode, path])


def read_as(account: str, path: Path) -> str:
    return as_account(account, ["/bin/cat", path]).stdout


def write_public(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    path.chmod(0o644)


def raw_address(address: str) -> str:
    """A user-friendly address (base64url: flags, workchain, hash, crc) in
    the raw 0:<hex> form the confirmer and the verifier print."""
    if re.fullmatch(r"-?\d+:[0-9a-f]{64}", address):
        return address
    data = base64.urlsafe_b64decode(address + "=" * (-len(address) % 4))
    if len(data) != 36:
        raise ValueError("not a user-friendly address")
    workchain = int.from_bytes(data[1:2], "big", signed=True)
    return f"{workchain}:{data[2:34].hex()}"


def rpc(port: int, method: str, **params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{port}/jsonRPC", data=body,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read())


def balance(address: str) -> int:
    """The smallest balance three endpoints report (a strict reading)."""
    return min(int(rpc(port, "getAddressInformation", address=address)["result"]["balance"])
               for _, _, port in VALIDATORS)


def stopped() -> bool:
    return (CONTROL / "stop").exists()


# --- Set-up shared by every role -------------------------------------------------------

def take_over_work() -> None:
    os.chown(WORK, 0, 0)
    WORK.chmod(0o755)
    for directory in (LOGS, OUT, PUBLIC, OUT / "provider", OUT / "buyer", OUT / "handoff"):
        root_dir(directory)


def install_binaries() -> dict:
    build = json.loads((MOUNTS / "bin" / "build.json").read_text())
    BIN.mkdir(mode=0o755, exist_ok=True)
    for name, digest in build["binaries"].items():
        source = MOUNTS / "bin" / name
        if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"{name} does not match build.json")
        shutil.copyfile(source, BIN / name)
        os.chown(BIN / name, 0, 0)
        (BIN / name).chmod(0o755)
    record("root-owned copies of every staged binary match build.json", True, sorted(build["binaries"]))
    return build


def setup_accounts(names: list[str]) -> None:
    root_dir(HOMES)
    for account in names:
        uid, gid = ACCOUNTS[account]
        home = HOME[account]
        home.mkdir(exist_ok=True)
        os.chown(home, uid, gid)
        home.chmod(0o700)
        private = account_dir(home / "private", account)
        if account in ("custody", "provider"):
            master = secrets.token_hex(32)
            register_secret(master)
            url = f"file://{private}/vault.json?master_key={master}"
            register_secret(url)
            write_as(account, private / "vault.env", f"VAULT_URL={url}\n")
    record("accounts and vaults prepared", True, {a: ACCOUNTS[a][0] for a in names})


def start_tunnels(role: str) -> None:
    """This role's own pilot-rpc forwards, run as its account with its own
    key: 127.0.0.1:18081/28081/38081 -> each validator's 127.0.0.1:8081."""
    account = TUNNEL_ACCOUNT[role]
    ssh = account_dir(HOME[account] / ".ssh", account)
    write_as(account, ssh / "pilot-rpc", (MOUNTS / "key").read_text())
    write_as(account, ssh / "known_hosts", (PUBLIC_IN / "validators.known_hosts").read_text(), "0644")
    for name, host, port in VALIDATORS:
        open_tunnel(account, name, host, port)
    ready = poll(lambda: all("result" in rpc(port, "getMasterchainInfo") for _, _, port in VALIDATORS), 120, 3)
    record(f"the {role}'s own pilot-rpc forwards reach V1, V2 and V3", bool(ready), RPC)


def open_tunnel(account: str, name: str, host: str, port: int) -> None:
    ssh = HOME[account] / ".ssh"
    tunnels[name] = (account, start(account, [
        "/usr/bin/ssh", "-N", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o",
        f"UserKnownHostsFile={ssh / 'known_hosts'}", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=4", "-o", "IdentitiesOnly=yes", "-i", ssh / "pilot-rpc", "-L",
        f"127.0.0.1:{port}:127.0.0.1:8081", f"pilot-rpc@{host}"], f"tunnel-{name}.log"))
    processes.pop()


def keep_tunnels() -> None:
    for name, host, port in VALIDATORS:
        account, process = tunnels[name]
        if process.poll() is not None:
            with (LOGS / "tunnel-restarts.jsonl").open("a") as handle:
                handle.write(json.dumps({"at": now(), "tunnel": name, "exit": process.returncode}) + "\n")
            open_tunnel(account, name, host, port)


def configure_tosctl(account: str) -> Path:
    config = HOME[account] / "private" / "tosctl-config.json"
    as_account(account, [BIN / "tosctl", "config", "generate", "-o", config, "--force"])
    value = json.loads(read_as(account, config))
    value["chain_rpc"] = {"urls": RPC_BASES, "api_key": None}
    value["elections"] = None
    write_as(account, config, json.dumps(value, indent=2))
    return config


def wallet_address(account: str, name: str) -> str:
    config = HOME[account] / "private" / "tosctl-config.json"
    listed = json.loads(as_account(account, [BIN / "tosctl", "wallet", "ls", "-c", config, "--format", "json"],
                                   vault=True).stdout)
    for wallet in listed:
        if wallet.get("name") == name and wallet.get("address"):
            return wallet["address"]
    raise RuntimeError(f"no wallet {name}")


def wait_funding(role: str, address: str, needed: int) -> None:
    write_public(OUT / f"{role}-wallet.json", json.dumps({"role": role, "address": address,
                                                          "raw": raw_address(address), "needed_nanotos": str(needed),
                                                          "at": now()}))
    print(f"waiting for funding of the {role} wallet {address}", flush=True)
    funded = poll(lambda: balance(address) >= needed, 3 * 3600, 20)
    record(f"the {role} wallet holds its funding on all three endpoints", bool(funded),
           {"address": address, "needed_nanotos": str(needed)})


# --- The provider (OpenFox) --------------------------------------------------------------

def openfox(*args, timeout: int = 1800, check: bool = True) -> subprocess.CompletedProcess:
    return as_account("provider", [BIN / "openfox", "earning", "service", *args], timeout=timeout, vault=True,
                      check=check)


def provider_rail() -> Path:
    return HOME["provider"] / "rail" / "rail.json"


def serve_provider(build: dict) -> None:
    setup_accounts(["provider"])
    start_tunnels("provider")
    rail = account_dir(HOME["provider"] / "rail", "provider")
    config = configure_tosctl("provider")
    as_account("provider", [BIN / "tosctl", "wallet", "create", "-n", "provider", "-v", "V4R2", "-w", "0", "-c", config],
               vault=True)
    address = wallet_address("provider", "provider")
    wait_funding("provider", address, FUNDING_NANOTOS["provider"])
    as_account("provider", [BIN / "tosctl", "wallet", "activate", "-n", "provider", "-c", config], vault=True)
    write_as("provider", HOME["provider"] / "private" / "relay-ca.pem", (PUBLIC_IN / "relay-ca.pem").read_text())
    write_as("provider", HOME["provider"] / "private" / "registry-code.boc",
             (PUBLIC_IN / "tos-service-native-registry-v1.boc.base64").read_text())
    rpc_flags = [flag for endpoint in RPC for flag in ("--rpc", endpoint)]
    relay_flags = [flag for url in RELAYS for flag in ("--relay-url", url)]
    init = openfox("init", "--rail-config", rail / "rail.json", "--state-dir", rail, *rpc_flags, "--global-config",
                   PUBLIC_IN / "global-config.json", "--network-label", NETWORK_LABEL, "--tosctl", BIN / "tosctl",
                   "--tosctl-sha256", build["tosctl_sha256"], "--tosctl-config", config, "--wallet", "provider",
                   "--registry-code-boc", HOME["provider"] / "private" / "registry-code.boc", "--actor-code-hash",
                   os.environ["ACTOR_CODE_HASH"], *relay_flags, "--relay-ca-file",
                   HOME["provider"] / "private" / "relay-ca.pem", "--yes")
    write_public(OUT / "provider" / "init.json", redact(init.stdout))
    record("provider init registered the provider Agent", True, (last_json(init.stdout) or {}).get("agent_id"))
    offer = openfox("offer", "--rail-config", rail / "rail.json", "--price", TERMS["price"], "--storage-fee",
                    TERMS["storage_fee"], "--cleanup-bounty", TERMS["cleanup_bounty"], "--response-sla",
                    str(TERMS["response_sla"]), "--refund-claim-window", str(TERMS["refund_claim_window"]),
                    "--executor-socket", EXECUTOR_SOCKET, "--yes")
    report = last_json(offer.stdout) or {}
    write_public(OUT / "provider" / "offer.json", json.dumps(redact_value(report), indent=2))
    offer_file = json.loads(read_as("provider", rail / "setup" / "offer.json"))
    write_public(PUBLIC / "offer-pilot.json", json.dumps(offer_file, indent=2))
    preflight = openfox("preflight", "--rail-config", rail / "rail.json", check=False)
    write_public(OUT / "provider" / "preflight.json", redact(preflight.stdout))
    preview = report.get("preview") or {}
    record("OpenFox published a fresh actor and Capability with the pilot's terms and wrote its offer file",
           bool(offer_file.get("capability_id")) and bool(preview.get("actor")),
           {"capability_id": offer_file.get("capability_id"), "actor": preview.get("actor"),
            "preflight_exit": preflight.returncode})
    start("provider", [BIN / "openfox", "earning", "service", "serve", "--rail-config", rail / "rail.json"],
          "openfox.log", vault=True)
    write_public(OUT / "ready.json", json.dumps({"role": "provider", "ready_utc": now()}))


def provider_action(action: str) -> dict:
    rail = provider_rail()
    commands = {"pause": ["pause", "--rail-config", rail, "--reason", "pilot purchase F: no answer by design"],
                "resume": ["resume", "--rail-config", rail], "status": ["status", "--rail-config", rail],
                "withdraw": ["withdraw", "--rail-config", rail, "--all", "--yes"]}
    if action not in commands:
        raise SystemExit(f"unknown provider action {action}")
    result = openfox(*commands[action], check=False)
    report = last_json(result.stdout) or {"stdout": redact(result.stdout[-2000:])}
    report = {"action": action, "exit": result.returncode, "at": now(), "report": redact_value(report),
              "stderr_tail": redact(result.stderr[-800:])}
    write_public(OUT / "provider" / f"{action}-{int(time.time())}.json", json.dumps(report, indent=2))
    return report


# --- The buyer -----------------------------------------------------------------------

def buyer_flags(build: dict) -> list:
    custody = HOME["custody"]
    return ["--config", custody / "private" / "agent.json", "--state-dir", custody / "state", "--socket-dir", SOCKET_DIR,
            "--client-uid", str(ACCOUNTS["developer"][0]), "--network-label", NETWORK_LABEL,
            "--global-config", custody / "private" / "global-config.json", "--rpc", ",".join(RPC), "--quorum", "2",
            "--registry-code-boc", custody / "private" / "registry-code.boc", "--actor-code-hash",
            os.environ["ACTOR_CODE_HASH"], "--manifest-dir", custody / "manifests", "--tosctl", BIN / "tosctl",
            "--tosctl-sha256", build["tosctl_sha256"], "--tosctl-config", custody / "private" / "tosctl-config.json",
            "--wallet", "buyer", "--packet-controller", "buyer-packet",
            *[part for url in RELAYS for part in ("--relay", url)],
            "--relay-ca-file", custody / "private" / "relay-ca.pem", "--budget-window", "24h", "--max-calls", "4",
            "--max-per-call-nanotos", "1000000000", "--max-window-nanotos", "3000000000", "--max-unconfirmed", "4",
            "--duty-interval-seconds", "30"]


MCP_CLIENT = r'''
import json, subprocess, sys
calls = json.loads(sys.stdin.read())
server = subprocess.Popen(sys.argv[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def send(message):
    server.stdin.write(json.dumps(message) + "\n"); server.stdin.flush()
def answer(ident):
    while True:
        line = server.stdout.readline()
        if not line:
            raise SystemExit("the MCP server closed its output")
        message = json.loads(line)
        if message.get("id") == ident:
            return message
send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18",
      "capabilities": {}, "clientInfo": {"name": "pilot-dry-check", "version": "1"}}})
answer(1)
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
results = []
for index, (name, arguments) in enumerate(calls, start=2):
    if name == "prepare" and results:
        arguments["quote_id"] = (results[-1].get("structuredContent") or {}).get("quote", {}).get("quote_id") or \
            (results[-1].get("structuredContent") or {}).get("quote_id")
    if name == "withdraw" and results:
        arguments["request_hash"] = ((results[-1].get("structuredContent") or {}).get("purchase") or {}).get("request_hash")
    send({"jsonrpc": "2.0", "id": index, "method": "tools/call", "params": {"name": "tos_buyer_" + name,
          "arguments": arguments}})
    reply = answer(index)
    results.append(reply.get("result") or {"isError": True, "error": reply.get("error")})
    if results[-1].get("isError"):
        break
server.stdin.close(); server.wait(timeout=30)
print(json.dumps(results))
'''


def dry_check(offer: dict, workspace: dict) -> dict:
    """The offer-file quote and a prepare through the real MCP server as the
    developer, as the model will call them, then the prepared purchase
    withdrawn: nothing is paid. The pilot stops here if the offer-file
    path, which no earlier run exercised, fails."""
    mcp = json.loads(read_as("developer", Path(workspace["mcp_config"])))["mcpServers"]["tos-buyer"]
    calls = [("quote", {"capability_id": offer["capability_id"], "capability_version": offer["version"],
                        "offer_file": workspace["offer_path"], "source": "local"}),
             ("prepare", {"source_path": workspace["src"] + "/job",
                          "idempotency_key": "agent-pilot-dry-check-" + secrets.token_hex(4)}),
             ("withdraw", {})]
    result = as_account("developer", ["/usr/bin/python3", "-I", "-c", MCP_CLIENT, mcp["command"], *mcp["args"]],
                        input_text=json.dumps(calls), timeout=900, check=False)
    replies = json.loads(result.stdout) if result.stdout.strip().startswith("[") else []
    content = [(reply.get("structuredContent") or {}) for reply in replies]
    quote = (content[0].get("quote") or content[0]) if content else {}
    record("dry check: the offer-file Quote validates at a finalized checkpoint and is carriable",
           len(replies) >= 1 and not replies[0].get("isError") and bool(quote.get("carriable")),
           {"carriable": quote.get("carriable"), "not_carriable_item": quote.get("not_carriable_item"),
            "error": replies[0] if replies and replies[0].get("isError") else redact(result.stderr[-800:])})
    purchase = (content[1].get("purchase") or {}) if len(content) > 1 else {}
    record("dry check: prepare reserves a purchase from that Quote and pays nothing",
           purchase.get("state") == "awaiting_confirmation",
           {"state": purchase.get("state"), "error": replies[1] if len(replies) > 1 and replies[1].get("isError") else None})
    withdrawn = (content[2].get("purchase") or {}) if len(content) > 2 else {}
    record("dry check: the prepared purchase is withdrawn and will never be paid", withdrawn.get("state") == "withdrawn",
           {"state": withdrawn.get("state")})
    return {"quote_carriable": True, "dry_request_hash": purchase.get("request_hash"), "withdrawn": withdrawn.get("state")}


def serve_buyer(build: dict) -> None:
    setup_accounts(["custody", "developer"])
    SOCKET_DIR.mkdir(parents=True, exist_ok=True)
    os.chown(SOCKET_DIR, ACCOUNTS["custody"][0], SOCKET_GROUP)
    # Container root holds no FSETID: the owner sets setgid holding the group.
    as_account("custody", ["/bin/chmod", "2750", SOCKET_DIR], groups=[SOCKET_GROUP])
    start_tunnels("buyer")
    custody = HOME["custody"]
    account_dir(custody / "state", "custody")
    account_dir(custody / "manifests", "custody")
    for name, source in (("global-config.json", "global-config.json"), ("relay-ca.pem", "relay-ca.pem"),
                         ("registry-code.boc", "tos-service-native-registry-v1.boc.base64")):
        write_as("custody", custody / "private" / name, (PUBLIC_IN / source).read_text())
    configure_tosctl("custody")
    flags = buyer_flags(build)
    plan = as_account("custody", [BIN / "tos-service-buyer", "init", "plan", *flags], vault=True)
    record("init plan prints the changes and sends nothing", bool(plan.stdout.strip()))
    first = as_account("custody", [BIN / "tos-service-buyer", "init", "apply", *flags, "--yes"], vault=True,
                       check=False)
    report = last_json(first.stdout) or {}
    record("the first init apply created the wallet and stopped for funding",
           first.returncode != 0 and "needs funding" in first.stderr and bool(report.get("wallet_address")),
           {"wallet": report.get("wallet_address"), "funding_needed_nanotos": report.get("funding_needed_nanotos")})
    wait_funding("buyer", report["wallet_address"], FUNDING_NANOTOS["buyer"])
    second = as_account("custody", [BIN / "tos-service-buyer", "init", "apply", *flags, "--yes"], vault=True)
    done = last_json(second.stdout) or {}
    write_public(OUT / "buyer" / "init-apply.json", json.dumps(redact_value(done), indent=2))
    config = json.loads(read_as("custody", custody / "private" / "agent.json"))
    record("the second init apply activated the wallet and registered the buyer Agent",
           bool(done.get("complete")) and config.get("buyer_agent_id", "").startswith("agent_"),
           {"agent_id": config.get("buyer_agent_id"), "wallet": config.get("buyer_wallet")})
    start("custody", [BIN / "tos-service-buyer", "agent", "--config", custody / "private" / "agent.json"], "agent.log",
          vault=True)
    ready = poll(lambda: as_account("developer", ["/usr/bin/test", "-S", SOCKET], check=False).returncode == 0, 120, 1)
    record("the buyer agent serves its socket as custody", bool(ready))
    # The provider's offer, handed over as a file by the operator.
    print("waiting for the provider's offer file in control/", flush=True)
    poll(lambda: (CONTROL / "offer-pilot.json").exists() and (CONTROL / "provider-offer.json").exists(), 3 * 3600, 10)
    offer_text = (CONTROL / "offer-pilot.json").read_text()
    offer = json.loads(offer_text)
    preview = json.loads((CONTROL / "provider-offer.json").read_text()).get("preview") or {}
    workspace = setup_workspace(offer_text)
    dry = dry_check(offer, workspace)
    terms = preview.get("terms") or {}
    wallet = config["buyer_wallet"]
    profile = {
        "schema": "tos.service.gate-d-agent-pilot-profile.v1", "frozen_utc": now(),
        "network_label": NETWORK_LABEL,
        "global_config_sha256": hashlib.sha256((PUBLIC_IN / "global-config.json").read_bytes()).hexdigest(),
        "releases": {"service_actor_code_hash": os.environ["ACTOR_CODE_HASH"],
                     "native_registry_code_hash": os.environ["REGISTRY_CODE_HASH"]},
        "endpoints": {"rpc": RPC, "validators": [{"name": n, "host": h} for n, h, _ in VALIDATORS]},
        "relays": RELAYS,
        "objects": {"capability_id": offer["capability_id"], "capability_version": offer["version"],
                    "provider_agent_id": offer["provider_agent_id"], "manifest_digest": offer["manifest_digest"],
                    "actor": preview.get("actor"), "attestor_key_id": preview.get("attestor_key_id"),
                    "metadata_hash": preview.get("metadata_hash"), "capability_address": preview.get("capability_address"),
                    "provider_wallet": preview.get("owner_wallet"), "buyer_wallet": wallet,
                    "buyer_wallet_raw": raw_address(wallet), "buyer_agent_id": config["buyer_agent_id"],
                    "offer_sha256": hashlib.sha256(offer_text.encode()).hexdigest()},
        "terms": {"price_nanotos": terms.get("price_nanotos"), "storage_fee_nanotos": terms.get("storage_fee_nanotos"),
                  "cleanup_bounty_nanotos": terms.get("cleanup_bounty_nanotos"),
                  "response_sla_seconds": TERMS["response_sla"],
                  "refund_claim_window_seconds": TERMS["refund_claim_window"],
                  "execution_allowance_nanotos": ALLOWANCE_NANOTOS},
        "workspace": workspace, "dry_check": dry, "build": build}
    write_public(PUBLIC / "profile.json", json.dumps(profile, indent=2))
    threading.Thread(target=confirm_watch, args=(profile,), daemon=True).start()
    write_public(OUT / "ready.json", json.dumps({"role": "buyer", "ready_utc": now()}))


def setup_workspace(offer_text: str) -> dict:
    """The developer's workspace: the job and the provider's offer file. The
    harness places them; the model has no tool that writes files."""
    developer = HOME["developer"]
    for directory in ("src", "src/job", "src/offer", "results"):
        account_dir(developer / directory, "developer")
    for name, body in JOB.items():
        write_as("developer", developer / "src" / "job" / name, body, "0644")
    write_as("developer", developer / "src" / "offer" / "offer-pilot.json", offer_text, "0644")
    mcp = {"mcpServers": {"tos-buyer": {
        # The MCP server never sees the model client's credential.
        "command": "/usr/bin/env",
        "args": ["-u", "CLAUDE_CODE_OAUTH_TOKEN", str(BIN / "tos-service-buyer-mcp"), "--agent-socket", str(SOCKET),
                 "--agent-state-dir", str(HOME["custody"] / "state"), "--workspace-root", str(developer / "src"),
                 "--results-dir", str(developer / "results")]}}}
    write_as("developer", developer / "mcp.json", json.dumps(mcp, indent=2))
    return {"src": str(developer / "src"), "offer_path": str(developer / "src" / "offer" / "offer-pilot.json"),
            "mcp_config": str(developer / "mcp.json"), "home": str(developer), "job": sorted(JOB)}


# --- The automated confirmer ------------------------------------------------------------

PREPARE_TOOL = "mcp__tos-buyer__tos_buyer_prepare"
HASH_IN_RESULT = re.compile(r'request_hash\\*"?\s*:\s*\\*"([0-9a-f]{64})')


def prepared_hashes() -> set[str]:
    """The request_hash values tos_buyer_prepare returned to the model, from
    the transcripts the host writes under control/transcripts."""
    found: set[str] = set()
    for path in sorted((CONTROL / "transcripts").glob("*.jsonl")) if (CONTROL / "transcripts").is_dir() else []:
        prepare_ids = set()
        for line in path.read_text(errors="replace").splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            content = (event.get("message") or {}).get("content")
            if not isinstance(content, list):
                continue
            for item in content:
                if not isinstance(item, dict):
                    continue
                if item.get("type") == "tool_use" and item.get("name") == PREPARE_TOOL:
                    prepare_ids.add(item.get("id"))
                if item.get("type") == "tool_result" and item.get("tool_use_id") in prepare_ids:
                    found.update(HASH_IN_RESULT.findall(json.dumps(item.get("content"))))
    return found


def confirm_watch(profile: dict) -> None:
    objects, terms = profile["objects"], profile["terms"]
    expected = confirm_policy.Expected(
        capability_id=objects["capability_id"], capability_version=objects["capability_version"],
        provider_agent_id=objects["provider_agent_id"], actor=objects["actor"],
        attestor_key_id=objects["attestor_key_id"], manifest_digest=objects["manifest_digest"],
        price_nanotos=terms["price_nanotos"], storage_fee_nanotos=terms["storage_fee_nanotos"],
        allowance_nanotos=ALLOWANCE_NANOTOS, response_sla_seconds=terms["response_sla_seconds"],
        refund_claim_window_seconds=terms["refund_claim_window_seconds"], buyer_wallet=objects["buyer_wallet_raw"],
        members=sorted(JOB), max_confirmations=2, buyer_wallet_aliases=(objects["buyer_wallet"],))
    confirmer = WatchConfirmer(str(BIN / "tos-service-buyer"), str(SOCKET), *ACCOUNTS["custody"],
                               {"PATH": "/usr/bin:/bin", "HOME": str(HOME["custody"]), "TERM": "dumb"})
    confirmer.start()
    confirmed = 0
    log = LOGS / "confirmations.jsonl"
    try:
        while not stopped():
            confirmer.read(1)
            text = confirmer.pending_presentation()
            if text is None:
                continue
            decision = confirm_policy.decide(text, expected, prepared_hashes(), confirmed)
            screen = re.sub(r"Confirmation code:\s+\S+", "Confirmation code:  <code>", text)
            outcome = confirmer.answer(decision.code if decision.confirm else "decline")
            confirmed += 1 if decision.confirm else 0
            entry = {"at": now(), "by": "automated policy (container root); no human", **decision.public(),
                     "outcome": outcome, "screen_sha256": hashlib.sha256(screen.encode()).hexdigest()}
            with log.open("a") as handle:
                handle.write(json.dumps(entry) + "\n")
            write_public(LOGS / f"confirmer-screen-{int(time.time())}.txt", screen)
            print(f"confirmer: {'confirmed' if decision.confirm else 'declined'} {decision.request_hash}: {outcome}",
                  flush=True)
    except Exception as error:  # noqa: BLE001 - the watcher's end is logged
        with log.open("a") as handle:
            handle.write(json.dumps({"at": now(), "watcher_error": redact(repr(error))}) + "\n")
    finally:
        confirmer.finish()


# --- Observation, export, signatures ---------------------------------------------------

def chain_state(hashes: list[str]) -> dict:
    """Finalized state of requests, read by tos-service-verify (no key, no
    send) through this container's forwards."""
    profile = json.loads((PUBLIC / "profile.json").read_text())
    command = [BIN / "tos-service-verify", "--global-config", PUBLIC_IN / "global-config.json", "--network-id",
               NETWORK_LABEL, "--rpc", ",".join(RPC), "--registry-code-boc",
               PUBLIC_IN / "tos-service-native-registry-v1.boc.base64", "--registry-code-hash",
               profile["releases"]["native_registry_code_hash"], "--actor-code-hash",
               profile["releases"]["service_actor_code_hash"], "--actor", profile["objects"]["actor"]]
    for request_hash in hashes:
        command += ["--request-hash", request_hash]
    result = as_account(None, command, check=False, timeout=600)
    verdict = json.loads(result.stdout) if result.stdout.strip().startswith("{") else {}
    return {"result": verdict.get("result"), "checkpoint": verdict.get("checkpoint"),
            "failing": [c.get("id") for c in verdict.get("checks", []) if not c.get("ok")],
            "requests": [{key: request.get(key) for key in ("request_id", "request_hash", "state", "status", "caller",
                                                             "response_deadline", "refund_claim_deadline")}
                         for request in verdict.get("requests", [])]}


def boc_root_data(boc: bytes) -> bytes:
    """The data bytes of a BOC's root cell (enough for a config param's
    leading fields)."""
    if boc[:4] != bytes.fromhex("b5ee9c72"):
        raise ValueError("not a BOC")
    flags, offset_bytes = boc[4], boc[5]
    size = flags & 7
    field = lambda at: int.from_bytes(boc[at:at + size], "big")  # noqa: E731
    cells, roots = field(6), field(6 + size)
    position = 6 + 3 * size + offset_bytes
    root = field(position)
    position += size * roots
    if flags & 0x80:
        position += cells * offset_bytes
    for index in range(cells):
        descriptor1, descriptor2 = boc[position], boc[position + 1]
        length = (descriptor2 + 1) // 2
        if index == root:
            return boc[position + 2:position + 2 + length]
        position += 2 + length + (descriptor1 & 7) * size
    raise ValueError("no root cell")


def validator_set_times() -> dict:
    """utime_since and utime_until of ConfigParam 34 (current set) and 36
    (next set, when one is elected), at each endpoint; the set switches at
    these times."""
    result = {}
    for config_id in (34, 36):
        seen = set()
        for _, _, port in VALIDATORS:
            answer = rpc(port, "getConfigParam", config_id=config_id).get("result") or {}
            cell = ((answer.get("config") or {}).get("bytes")) or ""
            if not cell:
                seen.add(None)
                continue
            data = boc_root_data(base64.b64decode(cell))
            seen.add((int.from_bytes(data[1:5], "big"), int.from_bytes(data[5:9], "big")))
        if len(seen) != 1:
            raise RuntimeError(f"the endpoints disagree on ConfigParam {config_id}")
        value = seen.pop()
        result[str(config_id)] = None if value is None else {"utime_since": value[0], "utime_until": value[1]}
    return result


def export(label: str, request_hash: str) -> dict:
    custody = HOME["custody"]
    account_dir(custody / "exports", "custody")
    target = custody / "exports" / label
    result = as_account("custody", [BIN / "tos-service-buyer", "evidence", "--config", custody / "private" / "agent.json",
                                    "--request-hash", request_hash, "--out-dir", target], check=False)
    copied = {}
    if result.returncode == 0:
        for name in ("evidence.json", "receipt.boc", "artifact.tar"):
            if as_account("custody", ["/usr/bin/test", "-f", target / name], check=False).returncode == 0:
                raw = base64.b64decode(as_account("custody", ["/usr/bin/base64", "-w0", target / name]).stdout)
                write_public(OUT / "handoff" / label / name, raw)
                copied[name] = hashlib.sha256(raw).hexdigest()
    write_public(OUT / "handoff" / label / "export-stdout.txt", redact(result.stdout))
    return {"label": label, "exit": result.returncode, "files": copied, "stderr": redact(result.stderr[-1500:])}


def sign(role: str, message_hex: str) -> dict:
    if role not in ("custody", "provider") or not re.fullmatch(r"[0-9a-f]{64}", message_hex):
        raise SystemExit("usage: sign custody|provider <64 hex>")
    config = HOME[role] / "private" / "tosctl-config.json"
    listed = json.loads(as_account(role, [BIN / "tosctl", "wallet", "ls", "-c", config, "--format", "json"],
                                   vault=True).stdout)
    if not any(w.get("name") == "declaration" for w in listed):
        as_account(role, [BIN / "tosctl", "wallet", "create", "-n", "declaration", "-v", "V4R2", "-c", config],
                   vault=True)
    signed = as_account(role, [BIN / "tosctl", "wallet", "sign", "-n", "declaration", "--message-hex", message_hex,
                               "-c", config], vault=True)
    return json.loads(signed.stdout)


# --- Main process of a role container ------------------------------------------------------

def serve(role: str) -> int:
    take_over_work()
    status = 1
    try:
        build = install_binaries()
        if role == "provider":
            serve_provider(build)
        elif role == "buyer":
            serve_buyer(build)
        elif role == "verifier":
            setup_accounts(["verifier"])
            # The verifier's own work directory: a fresh clone, its build and
            # its outputs. Readable by the host, writable only by verifier.
            verifier_work = Path("/v/work")
            uid, gid = ACCOUNTS["verifier"]
            os.chown(verifier_work, uid, gid)
            verifier_work.chmod(0o755)
            for sub in ("home", "out"):
                as_account("verifier", ["/bin/mkdir", "-p", "-m", "0755", verifier_work / sub])
            start_tunnels("verifier")
            write_public(OUT / "ready.json", json.dumps({"role": "verifier", "ready_utc": now()}))
        else:
            raise SystemExit(f"unknown role {role}")
        print("ready", flush=True)
        while not stopped():
            keep_tunnels()
            for account, process in processes:
                if process.poll() is not None:
                    record(f"a long-running process of {account or 'root'} stayed up", False,
                           {"exit": process.returncode, "args": redact(" ".join(map(str, process.args))[:300])})
            time.sleep(5)
        status = 0
    except Exception as error:  # noqa: BLE001 - the steps record the failure
        import traceback
        with (LOGS / "steps.jsonl").open("a") as handle:
            handle.write(json.dumps({"name": f"serve {role} ended with an exception", "pass": False,
                                     "detail": redact(traceback.format_exc()[-4000:]), "at": now()}) + "\n")
        write_public(OUT / "failed.json", json.dumps({"error": redact(repr(error)), "at": now()}))
        # Stay up for inspection until the operator stops the container.
        while not stopped():
            time.sleep(5)
    finally:
        stop_all()
        give_back()
    return status


def give_back() -> None:
    """The host gets back what the run wrote outside the account homes."""
    host_uid, host_gid = int(os.environ["HOST_UID"]), int(os.environ["HOST_GID"])
    for top in (LOGS, OUT):
        for path in [*sorted(top.rglob("*"), key=lambda p: len(p.parts), reverse=True), top]:
            if not path.is_symlink():
                try:
                    os.chown(path, host_uid, host_gid)
                except OSError as error:
                    print(f"could not return {path}: {error}", flush=True)
    os.chown(WORK, host_uid, host_gid)


def main(argv: list[str]) -> int:
    if not argv:
        raise SystemExit(__doc__)
    command, args = argv[0], argv[1:]
    if command == "serve" and len(args) == 1:
        return serve(args[0])
    if command == "validator-set-times":
        print(json.dumps(validator_set_times()))
        return 0
    if command == "chain-state":
        print(json.dumps(chain_state(args)))
        return 0
    if command == "provider" and len(args) == 1:
        print(json.dumps(provider_action(args[0])))
        return 0
    if command == "export" and len(args) == 2:
        result = export(*args)
        print(json.dumps(result))
        return 0 if result["exit"] == 0 else 1
    if command == "sign" and len(args) == 2:
        print(json.dumps(sign(*args)))
        return 0
    raise SystemExit(__doc__)


if __name__ == "__main__":
    # serve takes the work directory over first (container root holds no
    # DAC_OVERRIDE); every other command runs after it.
    sys.exit(main(sys.argv[1:]))
