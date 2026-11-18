"""End-to-end run of the MCP buyer adapter (MCP_BUYER_ADAPTER_V1 section 15).

Runs inside the container run.sh starts, as container root, which keeps only
SETUID, SETGID, CHOWN and FOWNER. Every component runs as its own account:

- custody (2001): the buyer agent and the confirmer, with the buyer's tosctl
  vault;
- developer (2002): the MCP server, through mcp-buyer-e2e-client;
- provider (2004): the OpenFox provider, with its own tosctl vault;
- stranger (2005): only the peer-credential negatives;
- root: the local PQ validators, the packet relay and the stand-in executor
  service (OpenFox requires a root executor service, as in production).

Execution is the e2e stand-in (software-work-executord-e2e): it reads the
source archive and executes nothing. Real sandboxed execution is covered by
protocol/scripts/service-actor-buyer-e2e.sh with E2E_EXECUTE=1.

The run ends with work/evidence.json and one ALL PASS or FAIL line.
"""

import asyncio
import datetime
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

MOUNTS = Path("/e2e-mounts")
# The mounted binaries belong to the host account; tosctl and the executor
# pins accept only root- or self-owned executables, so the harness installs
# root-owned copies, checked against build.json, and runs those.
BIN = Path("/opt/e2e-bin")
WORK = Path("/e2e/work")
sys.path.insert(0, str(MOUNTS / "scripts"))
sys.path.insert(0, str(MOUNTS / "tos-source" / "test" / "tostester" / "src"))
sys.path.insert(0, str(MOUNTS / "harness"))
from service_actor_e2e_redact import redact, redact_value, register_secret  # noqa: E402
from confirmer import Confirmer  # noqa: E402

ACTOR_CODE_HASH = os.environ["ACTOR_CODE_HASH"]
SKIP_REFUND = os.environ.get("E2E_SKIP_REFUND") == "1"
NETWORK_LABEL = "tos:global-id:3"
RPC_PORTS = [47680, 47681, 47682]
BASE_PORT = 47600
RELAY_PORT = 47690
NANO = 1_000_000_000

ACCOUNTS = {"custody": (2001, 2001), "developer": (2002, 2002), "provider": (2004, 2004), "stranger": (2005, 2005)}
SOCKET_GROUP = 2003
HOME = {name: Path("/home") / name for name in ACCOUNTS}
SOCKET_DIR = Path("/run/tos-buyer")
EXECUTOR_DIR = Path("/run/tos-service-executor")
EXECUTOR_SOCKET = EXECUTOR_DIR / "executor.sock"
RELAY_URL = f"https://127.0.0.1:{RELAY_PORT}"

steps: list = []
evidence: dict = {}
vaults: dict = {}
processes: list = []


def record(name: str, ok: bool, detail=None) -> None:
    steps.append({"name": name, "pass": bool(ok), "detail": redact_value(detail),
                  "at": datetime.datetime.now(datetime.timezone.utc).isoformat()})
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {redact(str(detail))}"), flush=True)


def as_account(account: str | None, command: list, *, check: bool = True, timeout: int = 300,
               env_extra: dict | None = None, input_text: str | None = None) -> subprocess.CompletedProcess:
    """Run a command as an account (root when None), with only that
    account's environment: its home, and its own vault when it has one."""
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    kwargs = {}
    if account is not None:
        uid, gid = ACCOUNTS[account]
        groups = [SOCKET_GROUP] if account == "developer" else []
        kwargs = {"user": uid, "group": gid, "extra_groups": groups}
        env["HOME"] = str(HOME[account])
        if account in vaults:
            env["VAULT_URL"] = vaults[account]
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env, input=input_text, **kwargs)
    with (WORK / "transcript.jsonl").open("a") as transcript:
        transcript.write(json.dumps({"account": account or "root", "command": redact(" ".join(map(str, command))),
                                     "status": result.returncode, "stdout": redact(result.stdout[-4000:]),
                                     "stderr": redact(result.stderr[-4000:])}) + "\n")
    if check and result.returncode != 0:
        raise RuntimeError(f"{command[0]} failed: {redact(result.stderr[-2000:])}")
    return result


def start(account: str | None, command: list, log: str, env_extra: dict | None = None) -> subprocess.Popen:
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    kwargs = {}
    if account is not None:
        uid, gid = ACCOUNTS[account]
        kwargs = {"user": uid, "group": gid, "extra_groups": []}
        env["HOME"] = str(HOME[account])
        if account in vaults:
            env["VAULT_URL"] = vaults[account]
    if env_extra:
        env.update(env_extra)
    out = open(WORK / "logs" / log, "w")
    process = subprocess.Popen(command, stdout=out, stderr=subprocess.STDOUT, env=env, **kwargs)
    processes.append(process)
    return process


def last_json(text: str):
    start_at = text.find("{")
    return json.loads(text[start_at:]) if start_at >= 0 else None


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


def rpc(method: str, **params):
    import urllib.request
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{RPC_PORTS[0]}/jsonRPC", data=body,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def private_dir(path: Path, account: str | None, mode: int = 0o700, group: int | None = None) -> Path:
    """An owned directory. Container root holds no DAC_OVERRIDE, so a
    directory inside an account's home is made by that account itself."""
    if account is not None and HOME[account] in path.parents:
        as_account(account, ["/bin/mkdir", "-p", "-m", oct(mode)[2:], str(path)])
        as_account(account, ["/bin/chmod", oct(mode)[2:], str(path)])
        return path
    path.mkdir(parents=True, exist_ok=True)
    uid, gid = ACCOUNTS[account] if account else (0, 0)
    os.chown(path, uid, gid if group is None else group)
    path.chmod(mode)
    return path


def install_binaries(build: dict) -> None:
    import hashlib
    import shutil
    BIN.mkdir(mode=0o755, exist_ok=True)
    for name, digest in build["binaries"].items():
        source = MOUNTS / "bin" / name
        if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"{name} does not match build.json")
        shutil.copyfile(source, BIN / name)
        os.chown(BIN / name, 0, 0)
        (BIN / name).chmod(0o755)
    record("root-owned copies of every built binary match build.json", True, sorted(build["binaries"]))


def norm(address: str) -> str:
    from pytosiq_core import Address
    return Address(address).to_str(is_user_friendly=False).lower()


# --- Accounts and tosctl vaults ----------------------------------------------

def tosctl(account: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    config = HOME[account] / "private" / "tosctl-config.json"
    return as_account(account, [str(BIN / "tosctl"), *args, "-c", str(config)], check=check)


def tosctl_json(account: str, *args: str):
    return json.loads(tosctl(account, *args, "--format", "json").stdout)


def setup_accounts() -> None:
    for account in ("custody", "provider"):
        private = private_dir(HOME[account] / "private", account)
        master = secrets.token_hex(32)
        register_secret(master)
        vaults[account] = f"file://{private}/vault.json?master_key={master}"
        register_secret(vaults[account])
    private_dir(SOCKET_DIR, "custody", 0o750, SOCKET_GROUP)
    private_dir(EXECUTOR_DIR, None, 0o750, ACCOUNTS["provider"][1])
    record("accounts, vaults and runtime directories prepared", True,
           {account: {"uid": ids[0]} for account, ids in ACCOUNTS.items()})


def configure_tosctl(account: str) -> None:
    config = HOME[account] / "private" / "tosctl-config.json"
    as_account(account, [str(BIN / "tosctl"), "config", "generate", "-o", str(config), "--force"])
    value = json.loads(as_account(account, ["/bin/cat", str(config)]).stdout)
    value["chain_rpc"] = {"urls": [f"http://127.0.0.1:{port}" for port in RPC_PORTS], "api_key": None}
    value["elections"] = None
    as_account(account, ["/usr/bin/tee", str(config)], input_text=json.dumps(value, indent=2))
    as_account(account, ["/bin/chmod", "0600", str(config)])


def wallet_address(account: str, name: str) -> str:
    for wallet in tosctl_json(account, "wallet", "ls"):
        if wallet.get("name") == name and wallet.get("address"):
            return norm(wallet["address"])
    raise RuntimeError(f"no wallet {name}")


async def fund(faucet, address: str, amount_tos: int) -> None:
    from contract import tos
    from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, WalletMessage
    await faucet.send(WalletMessage(send_mode=3, message=MessageAny(
        info=InternalMsgInfo(ihr_disabled=True, bounce=False, bounced=False, src=faucet.address, dest=Address(address),
                             value=tos(amount_tos), ihr_fee=0, fwd_fee=0, created_lt=0, created_at=0),
        init=None, body=Cell.empty())))


async def provision(faucet) -> dict:
    wallets = {}
    for account, name in (("custody", "buyer"), ("provider", "provider")):
        configure_tosctl(account)
        tosctl(account, "wallet", "create", "-n", name, "-v", "V4R2", "-w", "0")
        address = wallet_address(account, name)
        await fund(faucet, address, 80)
        funded = poll(lambda a=address: int(rpc("getAddressInformation", address=a)["result"]["balance"]) >= 79 * NANO, 180)
        tosctl(account, "wallet", "activate", "-n", name)
        active = poll(lambda a=address: rpc("getAddressState", address=a).get("result") == "active", 180)
        record(f"{account} wallet funded and active", bool(funded) and bool(active), address)
        wallets[account] = address
    return wallets


# --- Relay and executor --------------------------------------------------------

def start_relay() -> Path:
    tls = private_dir(Path("/var/lib/e2e-relay-tls"), None)
    as_account(None, ["/usr/bin/openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                      "-nodes", "-days", "2", "-subj", "/CN=e2e relay CA", "-keyout", str(tls / "ca.key"),
                      "-out", str(tls / "ca.pem"), "-addext", "basicConstraints=critical,CA:TRUE"])
    as_account(None, ["/usr/bin/openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                      "-subj", "/CN=127.0.0.1", "-keyout", str(tls / "relay.key"), "-out", str(tls / "relay.csr")])
    (tls / "san.ext").write_text("subjectAltName=IP:127.0.0.1\n")
    as_account(None, ["/usr/bin/openssl", "x509", "-req", "-in", str(tls / "relay.csr"), "-CA", str(tls / "ca.pem"),
                      "-CAkey", str(tls / "ca.key"), "-CAcreateserial", "-days", "2", "-extfile", str(tls / "san.ext"),
                      "-out", str(tls / "relay.pem")])
    state = private_dir(Path("/var/lib/e2e-relay"), None)
    start(None, [str(BIN / "tos-service-packet-relay"), "-listen", f"127.0.0.1:{RELAY_PORT}",
                 "-tls-cert", str(tls / "relay.pem"), "-tls-key", str(tls / "relay.key"), "-state-dir", str(state),
                 "-global-max-entries", "100000"], "relay.log")
    # Each account gets its own copy of the CA certificate it pins.
    for account in ("custody", "provider"):
        copy = HOME[account] / "private" / "relay-ca.pem"
        as_account(account, ["/usr/bin/tee", str(copy)], input_text=(tls / "ca.pem").read_text())
        as_account(account, ["/bin/chmod", "0600", str(copy)])
    import ssl
    import urllib.request
    context = ssl.create_default_context(cafile=str(tls / "ca.pem"))
    ready = poll(lambda: urllib.request.urlopen(RELAY_URL + "/v1/relay", context=context, timeout=5).status == 200, 60, 1)
    record("packet relay serves HTTPS under the run's own CA", bool(ready), RELAY_URL)
    return tls / "ca.pem"


def start_executor() -> None:
    state = private_dir(Path("/var/lib/e2e-executor"), None)
    start(None, [str(BIN / "software-work-executord-e2e"), "--i-am-the-e2e-stand-in", "--socket", str(EXECUTOR_SOCKET),
                 "--socket-gid", str(ACCOUNTS["provider"][1]), "--state-dir", str(state),
                 "--allow-uid", str(ACCOUNTS["provider"][0])], "executor.log")
    ready = poll(lambda: EXECUTOR_SOCKET.is_socket(), 30, 0.5)
    record("stand-in executor service serves the provider uid only (it executes nothing)", bool(ready),
           {"socket": str(EXECUTOR_SOCKET), "allowed_uid": ACCOUNTS["provider"][0]})


# --- Chain objects ----------------------------------------------------------------

PUBLIC = Path("/var/lib/e2e-public")
REGISTRY_BOC = MOUNTS / "registry-code.boc"


def rpc_endpoints() -> list[str]:
    return [f"http://127.0.0.1:{port}/jsonRPC" for port in RPC_PORTS]


def registry_show(account: str, address: str) -> dict:
    return tosctl_json(account, "agent", "native-registry", "show", "--global-config", str(PUBLIC / "global.json"),
                       "--network-label", NETWORK_LABEL, "--address", address)


def register_agent(account: str, wallet: str, controller: str) -> tuple[str, str]:
    """Register an Agent whose one controller is `controller`; returns the
    Agent ID and the controller's key ID text."""
    created = tosctl_json(account, "agent", "native-registry", "new-controller", "--name", controller)
    policy = HOME[account] / "private" / f"{controller}-policy.json"
    as_account(account, ["/usr/bin/tee", str(policy)], input_text=json.dumps(
        {"threshold": 1, "recovery_threshold": 1, "recovery_timelock": 3600,
         "controllers": [{"public_key": created["public_key"], "weight": 1, "purposes": 15}]}))
    view = tosctl_json(account, "agent", "native-registry", "register-agent", "--global-config", str(PUBLIC / "global.json"),
                       "--network-label", NETWORK_LABEL, "--policy", str(policy), "--nonce", secrets.token_hex(32),
                       "--signer", controller)
    args = ["wallet", "send", "--from", wallet, "--to", view["destination"], "--amount", "2", "--body-boc",
            view["body_boc"], "--yes"]
    if view.get("state_init_boc"):
        args += ["--state-init-boc", view["state_init_boc"]]
    tosctl(account, *args)
    registered = poll(lambda: registry_show(account, view["destination"]).get("registered"), 240, 3)
    agent_id = "agent_" + view["object_id"]
    record(f"{account} Agent registered with its packet controller", bool(registered), agent_id)
    return agent_id, "mldsa44:" + created["key_id"]


# --- The OpenFox provider -----------------------------------------------------------

PROVIDER_RAIL = HOME["provider"] / "rail"
GATEWAY_CARD = HOME["provider"] / "gateway" / "provider-key-card.json"


def openfox(*args: str, timeout: int = 900) -> subprocess.CompletedProcess:
    return as_account("provider", [str(BIN / "openfox"), "earning", "service", *args], timeout=timeout)


def setup_provider(tosctl_sha256: str) -> dict:
    private_dir(PROVIDER_RAIL, "provider")
    private_dir(GATEWAY_CARD.parent, "provider")
    rpc_flags = [flag for endpoint in rpc_endpoints() for flag in ("--rpc", endpoint)]
    openfox("init", "--rail-config", str(PROVIDER_RAIL / "rail.json"), "--state-dir", str(PROVIDER_RAIL), *rpc_flags,
            "--global-config", str(PUBLIC / "global.json"), "--network-label", NETWORK_LABEL,
            "--tosctl", str(BIN / "tosctl"), "--tosctl-sha256", tosctl_sha256,
            "--tosctl-config", str(HOME["provider"] / "private" / "tosctl-config.json"), "--wallet", "provider",
            "--registry-code-boc", str(REGISTRY_BOC), "--actor-code-hash", ACTOR_CODE_HASH,
            "--relay-url", RELAY_URL, "--relay-ca-file", str(HOME["provider"] / "private" / "relay-ca.pem"), "--yes")
    openfox("offer", "--rail-config", str(PROVIDER_RAIL / "rail.json"), "--price", "0.1", "--storage-fee", "0.2",
            "--cleanup-bounty", "0.1", "--response-sla", "3600", "--refund-claim-window", "3600",
            "--executor-socket", str(EXECUTOR_SOCKET), "--gateway-card-out", str(GATEWAY_CARD), "--yes")
    offer = json.loads(as_account("provider", ["/bin/cat", str(PROVIDER_RAIL / "setup" / "offer.json")]).stdout)
    card = as_account("provider", ["/usr/bin/stat", "-c", "%u %a", str(GATEWAY_CARD)], check=False).stdout.split()
    record("OpenFox published its offer and its current key card for the gateway",
           bool(offer.get("capability_id")) and card[:1] == [str(ACCOUNTS["provider"][0])],
           {"capability_id": offer.get("capability_id"), "card_owner_and_mode": card})
    start("provider", [str(BIN / "openfox"), "earning", "service", "serve", "--rail-config",
                       str(PROVIDER_RAIL / "rail.json")], "openfox.log")
    return offer


# --- The buyer agent -----------------------------------------------------------------

AGENT_STATE = HOME["custody"] / "agent-state"
AGENT_CONFIG = HOME["custody"] / "private" / "agent.json"


def setup_buyer(wallet: str, tosctl_sha256: str) -> dict:
    agent_id, key_id = register_agent("custody", "buyer", "buyer-packet")
    private_dir(AGENT_STATE, "custody")
    private_dir(HOME["custody"] / "manifests", "custody")
    for directory in ("work", "results"):
        private_dir(HOME["developer"] / directory, "developer")
    code_hash = json.loads(as_account(None, [str(BIN / "service-actor-e2e-fixture"), "code-hash", "--boc-file",
                                             str(REGISTRY_BOC)]).stdout)["code_hash"]
    config = {
        "schema": "tos.service.mcp-buyer.agent-config.v1", "state_dir": str(AGENT_STATE), "socket_dir": str(SOCKET_DIR),
        "client_uid": ACCOUNTS["developer"][0], "network": {key: evidence["network"][key] for key in
                                                          ("network_id", "genesis_root_hash", "genesis_file_hash")},
        "rpc_endpoints": rpc_endpoints(), "quorum": 2, "registry_code_boc_file": str(REGISTRY_BOC),
        "registry_code_hash": code_hash, "registry_workchain": 0, "actor_code_hash": ACTOR_CODE_HASH,
        "manifest_dir": str(HOME["custody"] / "manifests"), "buyer_wallet": wallet, "buyer_agent_id": agent_id,
        "tosctl": {"binary": str(BIN / "tosctl"), "sha256": tosctl_sha256,
                   "config_path": str(HOME["custody"] / "private" / "tosctl-config.json"), "wallet": "buyer",
                   "packet_controller": "buyer-packet"},
        "packet_controller_key_id": key_id, "relays": [RELAY_URL],
        "relay_ca_file": str(HOME["custody"] / "private" / "relay-ca.pem"),
        "budget": {"window_seconds": 86400, "max_calls": 10, "max_per_call_nanotos": "2000000000",
                   "max_window_nanotos": "10000000000", "max_unconfirmed": 4, "max_lifecycle_sends_per_window": 28,
                   "duty_interval_seconds": 30}}
    as_account("custody", ["/usr/bin/tee", str(AGENT_CONFIG)], input_text=json.dumps(config, indent=2))
    as_account("custody", ["/bin/chmod", "0600", str(AGENT_CONFIG)])
    start("custody", [str(BIN / "tos-service-buyer"), "agent", "--config", str(AGENT_CONFIG)], "agent.log")
    # Root cannot search the 0750 socket directory; the developer account,
    # in its group, checks for the socket.
    ready = poll(lambda: as_account("developer", ["/usr/bin/test", "-S", str(SOCKET_DIR / "agent.sock")],
                                    check=False).returncode == 0, 120, 1)
    record("the buyer agent serves its socket as custody", bool(ready), {"agent_id": agent_id})
    return {"agent_id": agent_id, "packet_key_id": key_id}


# --- Negatives that need no purchase --------------------------------------------

def socket_request(account: str, method: str, params: dict) -> dict | None:
    """One raw agent-socket request from an account; None when refused at
    connect (the agent closes an unknown peer without reading)."""
    program = (
        "import json, socket, sys\n"
        "s = socket.socket(socket.AF_UNIX)\n"
        f"s.connect({str(SOCKET_DIR / 'agent.sock')!r})\n"
        f"s.sendall((json.dumps({{'schema': 'tos.service.mcp-buyer.agent-api.v1', 'method': {method!r}, "
        f"'params': {json.dumps(params)}}}) + '\\n').encode())\n"
        "data = s.makefile().readline()\n"
        "print(data)\n")
    result = as_account(account, [str(MOUNTS / "venv" / "bin" / "python3"), "-I", "-c", program], check=False, timeout=30)
    line = result.stdout.strip()
    return json.loads(line) if line else None


def peer_negatives() -> None:
    stranger = socket_request("stranger", "purchases", {"page_size": 1})
    record("a third account is refused before its request is read", stranger is None, stranger)
    decide = socket_request("developer", "decide", {"request_hash": "00" * 32, "decision": "confirm", "code": "x"})
    refused = bool(decide) and not decide.get("ok") and decide.get("error", {}).get("code") == "MCP_BUYER_PERMISSION_DENIED"
    record("the developer account cannot call decide", refused, decide)
    for account in ("developer", "provider"):
        result = as_account(account, ["/bin/ls", str(HOME["custody"] / "agent-state")], check=False)
        record(f"{account} cannot read the custody state", result.returncode != 0, result.stderr.strip())
    result = as_account("developer", ["/bin/ls", str(HOME["provider"])], check=False)
    record("developer cannot read the provider state", result.returncode != 0, result.stderr.strip())


def mcp(tool: str | None, arguments: dict | None = None) -> dict:
    """One MCP call from the developer account through the real server."""
    server_flags = ["--agent-socket", str(SOCKET_DIR / "agent.sock"), "--agent-state-dir",
                    str(HOME["custody"] / "agent-state"), "--workspace-root", str(HOME["developer"] / "work"),
                    "--results-dir", str(HOME["developer"] / "results")]
    action = ["list"] if tool is None else ["call", tool, json.dumps(arguments or {})]
    result = as_account("developer", [str(BIN / "mcp-buyer-e2e-client"), "--server", str(BIN / "tos-service-buyer-mcp"),
                                      *action, "--", *server_flags], timeout=420)
    return json.loads(result.stdout.strip().splitlines()[-1])


# --- Main -----------------------------------------------------------------------

async def main() -> int:
    from tostester.install import Install
    from tostester.n6_cluster import _wait_all_heights
    from tostester.network import Network, StartOptions, _write_model

    # Container root holds no DAC_OVERRIDE: it takes the work directory over
    # with CHOWN for the run and gives it back to the host account at the
    # end.
    # Only the directory itself: the host's thermal guard keeps appending to
    # thermal.jsonl in it.
    os.chown(WORK, 0, 0)
    private_dir(WORK / "logs", None)
    build = json.loads((WORK / "build.json").read_text())
    evidence.update({
        "schema": "tos.service.mcp-buyer.local-e2e.v1",
        "qualifies_as_public_acceptance": False,
        "reason": "one container runs every validator, the relay, the gateway and both parties",
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "build": build, "actor_code_hash": ACTOR_CODE_HASH, "network_label": NETWORK_LABEL,
        "refund_scenario": "skipped (E2E_SKIP_REFUND=1)" if SKIP_REFUND else "run",
        "stand_ins": {"executor": "software-work-executord-e2e: the real executor service with a backend that reads "
                                  "the source archive and executes nothing; real sandboxed execution is covered by "
                                  "protocol/scripts/service-actor-buyer-e2e.sh with E2E_EXECUTE=1"}})
    try:
        install_binaries(build)
        private_dir(PUBLIC, None, 0o755)
        setup_accounts()
        async with Network(Install(MOUNTS / "tos-build", MOUNTS / "tos-source"), Path("/var/lib/e2e-network"),
                           base_port=BASE_PORT) as network:
            dht = network.create_dht_node()
            nodes = []
            for _ in RPC_PORTS:
                node = network.create_full_node()
                node.announce_to(dht)
                node.make_initial_pq_validator(secrets.token_bytes(32), secrets.token_bytes(32))
                nodes.append(node)
            await dht.run(StartOptions(threads=1, verbosity=1))
            for node, port in zip(nodes, RPC_PORTS):
                await node.run(StartOptions(threads=2, verbosity=1, args=["--json-rpc-address", f"127.0.0.1:{port}"]))
            await _wait_all_heights(nodes, 5, 300)
            client = await nodes[0].toslib_client()
            global_config = json.loads((nodes[0].directory / "config.global.json").read_text())
            _write_model(WORK / "liteserver.json", nodes[0].liteserver_config)
            global_config["liteservers"] = json.loads((WORK / "liteserver.json").read_text())["liteservers"]
            (PUBLIC / "global.json").write_text(json.dumps(global_config, indent=2))
            (PUBLIC / "global.json").chmod(0o644)
            zerostate = network.zerostate.as_block()
            evidence["network"] = {"network_id": NETWORK_LABEL,
                                   "genesis_root_hash": "sha256:" + zerostate.root_hash.hex(),
                                   "genesis_file_hash": "sha256:" + zerostate.file_hash.hex(),
                                   "validators": len(nodes)}
            ready = poll(lambda: "result" in rpc("getMasterchainInfo"), 180)
            record("every validator serves finalized JSON-RPC", bool(ready))
            evidence["wallets"] = await provision(network.zerostate.main_wallet(client))
            start_relay()
            start_executor()
            tosctl_sha256 = build["tosctl_sha256"]
            evidence["provider"] = setup_provider(tosctl_sha256)
            evidence["buyer"] = setup_buyer(evidence["wallets"]["custody"], tosctl_sha256)
            listed = mcp(None)
            record("the developer's MCP client lists the buyer tools through the real server",
                   "tos_buyer_result" in listed.get("tools", []), listed.get("tools"))
            peer_negatives()
    except Exception as error:  # noqa: BLE001 - the evidence records the failure
        import traceback
        record("run completed without an exception", False, {"error": repr(error),
                                                              "traceback": traceback.format_exc()[-4000:]})
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
    evidence["steps"] = steps
    thermal = WORK / "thermal.jsonl"
    evidence["thermal_pauses"] = [json.loads(line) for line in thermal.read_text().splitlines()] if thermal.exists() else []
    evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    passed = bool(steps) and all(step["pass"] for step in steps)
    evidence["result"] = "ALL PASS" if passed else "FAIL"
    (WORK / "evidence.json").write_text(json.dumps(redact_value(evidence), indent=2) + "\n")
    # Everything the host reads back belongs to the host account.
    host_uid, host_gid = int(os.environ["HOST_UID"]), int(os.environ["HOST_GID"])
    # The work directory itself last: once it is the host's again, root can
    # no longer enter it.
    for path in [*sorted(WORK.rglob("*"), key=lambda p: len(p.parts), reverse=True), WORK]:
        if path.is_symlink():
            continue
        os.chown(path, host_uid, host_gid)
    print(f"evidence: {WORK / 'evidence.json'}")
    print("ALL PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
