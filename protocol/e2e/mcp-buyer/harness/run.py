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
import base64
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
# A version 16 genesis needs a 32-byte AUTH network tag; a fresh one per run
# keeps this network's signatures from any other's (tostester reads it).
os.environ["TOS_AUTH_NETWORK_TAG"] = secrets.token_hex(32)

steps: list = []
evidence: dict = {}
vaults: dict = {}
processes: list = []


def record(name: str, ok: bool, detail=None) -> None:
    steps.append({"name": name, "pass": bool(ok), "detail": redact_value(detail),
                  "at": datetime.datetime.now(datetime.timezone.utc).isoformat()})
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {redact(str(detail))}"), flush=True)


def as_account(account: str | None, command: list, *, check: bool = True, timeout: int = 300,
               env_extra: dict | None = None, input_text: str | None = None,
               groups: list | None = None) -> subprocess.CompletedProcess:
    """Run a command as an account (root when None), with only that
    account's environment: its home, and its own vault when it has one.
    Only the developer is in the socket group unless groups says otherwise."""
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    kwargs = {}
    if account is not None:
        uid, gid = ACCOUNTS[account]
        if groups is None:
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
    processes.append((account, process))
    return process


def stop_all() -> None:
    """Stop every started process. Root holds no KILL capability, so a
    process of an account is signalled by that account itself."""
    for account, process in reversed(processes):
        if process.poll() is not None:
            continue
        if account is None:
            process.terminate()
        else:
            as_account(account, ["/bin/kill", "-TERM", str(process.pid)], check=False)
    for _, process in processes:
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            pass


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
    # setgid, so the socket the agent creates there belongs to tos-buyer and
    # the developer account in that group can reach it.
    private_dir(SOCKET_DIR, "custody", 0o750, SOCKET_GROUP)
    # Container root holds no FSETID, so a chmod by it drops the setgid bit
    # on a directory of a group it is not in. The owner sets it, holding the
    # shared group for that one call, as an operator's sudo install would.
    as_account("custody", ["/bin/chmod", "2750", str(SOCKET_DIR)], groups=[SOCKET_GROUP])
    mode = as_account("custody", ["/usr/bin/stat", "-c", "%a %g", str(SOCKET_DIR)]).stdout.split()
    if mode != ["2750", str(SOCKET_GROUP)]:
        raise RuntimeError(f"the socket directory is {mode}, not setgid 2750 of the shared group")
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
                      "-out", str(tls / "ca.pem"), "-addext", "basicConstraints=critical,CA:TRUE",
                      "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
    as_account(None, ["/usr/bin/openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                      "-subj", "/CN=127.0.0.1", "-keyout", str(tls / "relay.key"), "-out", str(tls / "relay.csr")])
    (tls / "san.ext").write_text("subjectAltName=IP:127.0.0.1\nkeyUsage=critical,digitalSignature\n"
                                 "extendedKeyUsage=serverAuth\n")
    as_account(None, ["/usr/bin/openssl", "x509", "-req", "-in", str(tls / "relay.csr"), "-CA", str(tls / "ca.pem"),
                      "-CAkey", str(tls / "ca.key"), "-CAcreateserial", "-days", "2", "-extfile", str(tls / "san.ext"),
                      "-out", str(tls / "relay.pem")])
    state = private_dir(Path("/var/lib/e2e-relay"), None)
    start(None, [str(BIN / "tos-service-packet-relay"), "-listen", f"127.0.0.1:{RELAY_PORT}",
                 "-tls-cert", str(tls / "relay.pem"), "-tls-key", str(tls / "relay.key"), "-state-dir", str(state),
                 "-global-max-entries", "100000", "-global-max-bytes", str(1 << 30)], "relay.log")
    # Each account gets its own copy of the CA certificate it pins.
    for account in ("custody", "provider"):
        copy = HOME[account] / "private" / "relay-ca.pem"
        as_account(account, ["/usr/bin/tee", str(copy)], input_text=(tls / "ca.pem").read_text())
        as_account(account, ["/bin/chmod", "0600", str(copy)])
    import ssl
    import urllib.request
    context = ssl.create_default_context(cafile=str(tls / "ca.pem"))
    last = {}

    def probe():
        try:
            return urllib.request.urlopen(RELAY_URL + "/v1/relay", context=context, timeout=5).status == 200
        except Exception as error:  # noqa: BLE001 - the last failure goes into the record
            last["error"] = repr(error)
            return False
    ready = poll(probe, 60, 1)
    record("packet relay serves HTTPS under the run's own CA", bool(ready), {"url": RELAY_URL, **last})
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


# --- The gateway, under the provider uid ------------------------------------------------

GATEWAY_PORT = 47691
GATEWAY_URL = f"http://127.0.0.1:{GATEWAY_PORT}"
GATEWAY_DIR = HOME["provider"] / "gateway"


def write_private(account: str, path: Path, text: str) -> None:
    as_account(account, ["/usr/bin/tee", str(path)], input_text=text)
    as_account(account, ["/bin/chmod", "0600", str(path)])


def start_gateway(provider_agent_id: str) -> None:
    """The reference gateway quoting for the OpenFox provider. It runs as the
    provider uid because it serves the key card file OpenFox keeps, which it
    accepts only when its own uid owns it."""
    rail = json.loads(as_account("provider", ["/bin/cat", str(PROVIDER_RAIL / "rail.json")]).stdout)
    registry = GATEWAY_DIR / "registry-code.boc"
    write_private("provider", registry, REGISTRY_BOC.read_text())
    state = private_dir(GATEWAY_DIR / "quote-state", "provider")
    catalog = private_dir(GATEWAY_DIR / "catalog", "provider")
    # The gateway serves the provider's manifest by digest
    # (GetSoftwareWorkManifest): a buyer with no offer file takes the
    # manifest from there and checks it against the finalized digest.
    manifest_hex = as_account("provider", ["/usr/bin/sha256sum", rail["provider"]["manifest_file"]]).stdout.split()[0]
    as_account("provider", ["/bin/cp", rail["provider"]["manifest_file"], str(catalog / f"manifest-{manifest_hex}.cbor")])
    as_account("provider", ["/bin/chmod", "0600", str(catalog / f"manifest-{manifest_hex}.cbor")])
    profile = GATEWAY_DIR / "quote-profile.json"
    write_private("provider", profile, json.dumps({
        "schema": "tos.service.provider-quote-profile.v2", "provider_agent_id": provider_agent_id,
        "manifest_cbor_file": rail["provider"]["manifest_file"],
        "transport": {"security_mode": 2, "max_request_bytes": 1 << 20, "base_url": "agent-packet:" + provider_agent_id},
        "proposal_ttl_seconds": 900, "tos_rpc_endpoints": rpc_endpoints(), "registry_code_boc_file": str(registry),
        "service_actor_code_hash": ACTOR_CODE_HASH, "state_directory": str(state),
        "provider_key_card_file": str(GATEWAY_CARD)}))
    read_token, relay_token, rpc_token = (secrets.token_hex(24) for _ in range(3))
    for token in (read_token, relay_token, rpc_token):
        register_secret(token)
    write_private("custody", HOME["custody"] / "private" / "gateway-token", read_token)
    network = evidence["network"]
    # The gateway's protocol backend, which it requires at start. It relays
    # nothing in this run; its sender is the provider's own tosctl wallet.
    rpc_state = private_dir(GATEWAY_DIR / "rpc-state", "provider")
    rpc_config = GATEWAY_DIR / "tos-service-v1.json"
    # The relay sender pins exactly one RPC endpoint: a copy of the
    # provider's tosctl configuration that names only the first.
    sender_config = GATEWAY_DIR / "tosctl-sender.json"
    tosctl_config = json.loads(as_account("provider", ["/bin/cat", str(HOME["provider"] / "private" /
                                                                       "tosctl-config.json")]).stdout)
    tosctl_config["chain_rpc"] = {"urls": [f"http://127.0.0.1:{RPC_PORTS[0]}"], "api_key": None}
    write_private("provider", sender_config, json.dumps(tosctl_config, indent=2))
    write_private("provider", rpc_config, json.dumps({
        "protocol": "tos_service_v1",
        "network": {"network_id": network["network_id"], "genesis_root_hash": network["genesis_root_hash"],
                    "genesis_file_hash": network["genesis_file_hash"]},
        "endpoints": rpc_endpoints(), "quorum": 2, "registry_workchain": 0,
        "contract_code_boc_base64": "".join(REGISTRY_BOC.read_text().split()),
        "contract_code_hash": evidence["registry_code_hash"], "funding_nanotos": 200_000_000, "relay_window_seconds": 600,
        "max_actions_per_target": 4, "max_funding_per_target_nanotos": 1_000_000_000, "max_actions_per_wallet": 16,
        "max_funding_per_wallet_nanotos": 4_000_000_000, "recovery_relay_safety_seconds": 600,
        "state_directory": str(rpc_state),
        "sender": {"network": network["network_id"], "binary": str(BIN / "tosctl"),
                   "configPath": str(sender_config), "vaultUrl": vaults["provider"],
                   # The sender takes the genesis hashes as Base64 of the raw bytes.
                   "rpcUrl": f"http://127.0.0.1:{RPC_PORTS[0]}",
                   "genesisRootHash": base64.b64encode(bytes.fromhex(network["genesis_root_hash"][7:])).decode(),
                   "genesisFileHash": base64.b64encode(bytes.fromhex(network["genesis_file_hash"][7:])).decode(),
                   "walletName": "provider",
                   "payer": evidence["wallets"]["provider"]},
        "signature_helper": {"binary": str(BIN / "tosctl"), "sha256": evidence["build"]["tosctl_sha256"]}}))
    start("provider", [str(BIN / "tos-service-rpc"), "-listen", "127.0.0.1:47692", "-bearer-token", rpc_token,
                       "-native-v1-config", str(rpc_config)], "service-rpc.log")
    import urllib.request
    rpc_ready = poll(lambda: urllib.request.urlopen("http://127.0.0.1:47692/healthz", timeout=5).status == 200, 60, 1)
    record("the gateway's protocol backend is up under the provider uid", bool(rpc_ready))
    start("provider", [str(BIN / "tos-service-gateway")], "gateway.log", env_extra={
        "TOS_SERVICE_ADDR": f"127.0.0.1:{GATEWAY_PORT}", "TOS_SERVICE_PUBLIC_BASE_URL": GATEWAY_URL,
        "TOS_SERVICE_READ_TOKEN": read_token, "TOS_SERVICE_RELAY_TOKEN": relay_token,
        "TOS_SERVICE_TOS_RPC_URL": "http://127.0.0.1:47692", "TOS_SERVICE_TOS_RPC_INSECURE": "true",
        "TOS_SERVICE_TOS_RPC_TOKEN": rpc_token,
        "TOS_SERVICE_CAPABILITY_CATALOG_DIRECTORY": str(GATEWAY_DIR / "catalog"),
        "TOS_SERVICE_NETWORK_ID": network["network_id"], "TOS_SERVICE_GENESIS_ROOT_HASH": network["genesis_root_hash"],
        "TOS_SERVICE_GENESIS_FILE_HASH": network["genesis_file_hash"],
        "TOS_SERVICE_REGISTRY_CODE_HASH": evidence["registry_code_hash"],
        "TOS_SERVICE_PROVIDER_QUOTE_PROFILE_FILE": str(profile)})
    import urllib.request
    ready = poll(lambda: urllib.request.urlopen(GATEWAY_URL + "/livez", timeout=5).status == 200, 60, 1)
    record("the gateway serves Quotes for the provider under its uid, with its key card file", bool(ready), GATEWAY_URL)


# --- The buyer agent -----------------------------------------------------------------

AGENT_STATE = HOME["custody"] / "agent-state"
AGENT_CONFIG = HOME["custody"] / "private" / "agent.json"


def setup_buyer(wallet: str, tosctl_sha256: str) -> dict:
    """The buyer's identity without OpenFox: `tos-service-buyer init` plans,
    then applies (packet controller, Agent registration, configuration);
    the harness then names the loopback gateway in the configuration."""
    private_dir(AGENT_STATE, "custody")
    private_dir(HOME["custody"] / "manifests", "custody")
    for directory in ("work", "results"):
        private_dir(HOME["developer"] / directory, "developer")
    flags = ["--config", str(AGENT_CONFIG), "--state-dir", str(AGENT_STATE), "--socket-dir", str(SOCKET_DIR),
             "--client-uid", str(ACCOUNTS["developer"][0]), "--network-label", NETWORK_LABEL,
             "--global-config", str(PUBLIC / "global.json"), "--rpc", ",".join(rpc_endpoints()), "--quorum", "2",
             "--registry-code-boc", str(REGISTRY_BOC), "--actor-code-hash", ACTOR_CODE_HASH,
             "--manifest-dir", str(HOME["custody"] / "manifests"), "--tosctl", str(BIN / "tosctl"),
             "--tosctl-sha256", tosctl_sha256, "--tosctl-config", str(HOME["custody"] / "private" / "tosctl-config.json"),
             "--wallet", "buyer", "--packet-controller", "buyer-packet", "--relay", RELAY_URL,
             "--relay-ca-file", str(HOME["custody"] / "private" / "relay-ca.pem"), "--budget-window", "24h",
             "--max-calls", "10", "--max-per-call-nanotos", "2000000000", "--max-window-nanotos", "10000000000",
             "--max-unconfirmed", "4", "--duty-interval-seconds", "30"]
    plan = as_account("custody", [str(BIN / "tos-service-buyer"), "init", "plan", *flags], timeout=600)
    record("init plan prints the changes and sends nothing", bool(plan.stdout.strip()), plan.stdout[-1500:])
    as_account("custody", [str(BIN / "tos-service-buyer"), "init", "apply", *flags, "--yes"], timeout=900)
    config = json.loads(as_account("custody", ["/bin/cat", str(AGENT_CONFIG)]).stdout)
    agent_id, key_id = config["buyer_agent_id"], config["packet_controller_key_id"]
    registered = config.get("buyer_wallet") == wallet and agent_id.startswith("agent_")
    record("init apply registered the buyer Agent and wrote the configuration", registered,
           {"agent_id": agent_id, "wallet": config.get("buyer_wallet")})
    # The gateway on loopback, quoting with the read token.
    config["gateway_url"] = GATEWAY_URL
    config["gateway_token_file"] = str(HOME["custody"] / "private" / "gateway-token")
    write_private("custody", AGENT_CONFIG, json.dumps(config, indent=2))
    start("custody", [str(BIN / "tos-service-buyer"), "agent", "--config", str(AGENT_CONFIG)], "agent.log")
    # Root cannot search the 0750 socket directory; the developer account,
    # in its group, checks for the socket.
    ready = poll(lambda: as_account("developer", ["/usr/bin/test", "-S", str(SOCKET_DIR / "agent.sock")],
                                    check=False).returncode == 0, 120, 1)
    record("the buyer agent serves its socket as custody", bool(ready), {"agent_id": agent_id})
    return {"agent_id": agent_id, "packet_key_id": key_id}


# --- Scenario 1: a gateway-quoted purchase from a relay-only provider ----------------

def structured(result: dict) -> dict:
    # The client prints the structured content as a JSON object.
    return result.get("structured") or {}


def source_tree() -> Path:
    """A small source directory in the developer's workspace."""
    source = HOME["developer"] / "work" / "src"
    private_dir(source, "developer")
    as_account("developer", ["/usr/bin/tee", str(source / "main.go")],
               input_text="package main\n\nfunc main() { println(\"built over the TOS rail\") }\n")
    as_account("developer", ["/usr/bin/tee", str(source / "go.mod")], input_text="module example.com/e2e\n\ngo 1.26\n")
    return source


def confirm_payment(request_hash: str) -> dict:
    """request_payment from the developer while the human confirms in the
    real confirmer on custody's own terminal."""
    waiting = subprocess.Popen(
        [str(BIN / "mcp-buyer-e2e-client"), "--server", str(BIN / "tos-service-buyer-mcp"), "call",
         "tos_buyer_request_payment", json.dumps({"request_hash": request_hash, "wait_seconds": 240}), "--",
         "--agent-socket", str(SOCKET_DIR / "agent.sock"), "--agent-state-dir", str(AGENT_STATE),
         "--workspace-root", str(HOME["developer"] / "work"), "--results-dir", str(HOME["developer"] / "results")],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, user=ACCOUNTS["developer"][0],
        group=ACCOUNTS["developer"][1], extra_groups=[SOCKET_GROUP],
        env={"PATH": "/usr/bin:/bin", "HOME": str(HOME["developer"])})
    # The confirmer shows only purchases a client has asked a decision for;
    # one opened before request_payment reaches the agent finds none and
    # exits. Open it once the purchase is marked requested.
    requested = poll(lambda: structured(mcp("tos_buyer_status", {"request_hash": request_hash}))
                     .get("purchase", {}).get("payment_requested"), 120, 2)
    record("request_payment made the purchase visible to the confirmer", bool(requested))
    confirmer = Confirmer(str(BIN / "tos-service-buyer"), str(SOCKET_DIR / "agent.sock"), *ACCOUNTS["custody"],
                          {"PATH": "/usr/bin:/bin", "HOME": str(HOME["custody"]), "TERM": "dumb"})
    confirmer.start()
    try:
        code = confirmer.confirm(timeout=180)
        record("the human confirmed in the real confirmer on custody's terminal", bool(code), {"code_length": len(code)})
    except (EOFError, TimeoutError) as error:
        # What the confirmer showed, for the record.
        record("the human confirmed in the real confirmer on custody's terminal", False,
               {"error": repr(error), "screen": confirmer.screen.decode(errors="replace")[-2000:]})
        raise
    finally:
        status = confirmer.finish()
    stdout, stderr = waiting.communicate(timeout=300)
    result = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {"error": stderr[-500:]}
    record("the confirmer exited cleanly", status == 0, status)
    return result


def diagnose_discovery(offer: dict) -> None:
    """The agent tells a client only that discovery failed; the same
    discovery through `tos-service-buyer discover` names the failing step,
    for the record."""
    diag = private_dir(HOME["custody"] / "diag", "custody")
    manifests = private_dir(diag / "manifests", "custody")
    rail = json.loads(as_account("provider", ["/bin/cat", str(PROVIDER_RAIL / "rail.json")]).stdout)
    manifest = as_account("provider", ["/usr/bin/base64", "-w0", rail["provider"]["manifest_file"]]).stdout
    digest = offer["manifest_digest"].removeprefix("sha256:")
    as_account("custody", ["/bin/sh", "-c", f"/usr/bin/base64 -d > {manifests / (digest + '.cbor')}"], input_text=manifest)
    network = evidence["network"]
    write_private("custody", diag / "network.json", json.dumps(
        {key: network[key] for key in ("network_id", "genesis_root_hash", "genesis_file_hash")}))
    result = as_account("custody", [str(BIN / "tos-service-buyer"), "discover", "--network-domain", str(diag / "network.json"),
                                    "--rpc", ",".join(rpc_endpoints()), "--registry-code-boc", str(REGISTRY_BOC),
                                    "--registry-code-hash", evidence["registry_code_hash"], "--actor-code-hash",
                                    ACTOR_CODE_HASH, "--state-dir", str(diag), "--manifest-dir", str(manifests),
                                    "--buyer-wallet", evidence["wallets"]["custody"], "--capability-id",
                                    offer["capability_id"], "--version", offer["version"]], check=False)
    record("diagnosis: discovery of the offer with tos-service-buyer discover", result.returncode == 0,
           {"stdout": result.stdout[-1500:], "stderr": result.stderr[-1500:]})


def scenario_gateway_purchase(offer: dict) -> None:
    capability, version = offer["capability_id"], offer["version"]
    quoted = mcp("tos_buyer_quote", {"capability_id": capability, "capability_version": version, "source": "gateway"})
    # tos_buyer_quote's structured content holds the Quote under "quote".
    quote = structured(quoted).get("quote") or structured(quoted)
    record("a gateway Quote validated against finalized state, carriable to the relay-only provider",
           not quoted["is_error"] and bool(quote.get("carriable")) and bool(quote.get("offer", {}).get("provider_card_held")),
           {"quote_id": quote.get("quote_id"), "source": quote.get("quote_source"),
            "card_refused": quote.get("provider_card_refused"), "not_carriable_item": quote.get("not_carriable_item"),
            "error": quote.get("error")})
    if not quote.get("quote_id"):
        diagnose_discovery(offer)
        raise RuntimeError("no Quote: scenario 1 stops here")
    source = source_tree()
    prepared = mcp("tos_buyer_prepare", {"quote_id": quote["quote_id"], "source_path": str(source),
                                         "idempotency_key": "e2e-first-purchase-" + secrets.token_hex(4)})
    purchase = structured(prepared).get("purchase", {})
    request_hash = purchase.get("request_hash", "")
    record("prepare reserves the purchase and pays nothing", not prepared["is_error"] and
           purchase.get("state") == "awaiting_confirmation", {"request_hash": request_hash, "state": purchase.get("state")})
    paid = confirm_payment(request_hash)
    paid_state = structured(paid).get("purchase", {}).get("state")
    record("the confirmed purchase is paid with one call", not paid.get("is_error", True) and
           paid_state not in (None, "awaiting_confirmation", "declined"), paid_state)
    # The agent delivers the task over the relay; OpenFox executes (stand-in),
    # responds and returns the result; the agent accepts it and acks.
    result = poll(lambda: (lambda r: r if not r["is_error"] else None)(
        mcp("tos_buyer_result", {"request_hash": request_hash, "max_inline_bytes": 4096})), 1800, 20)
    accepted = structured(result) if result else {}
    files = accepted.get("files") or {}
    record("the result is accepted against the finalized response hash and written as four files",
           bool(result) and bool(files.get("receipt_boc")),
           {"response_hash": (accepted.get("result") or {}).get("response_hash"), "files": files})
    if files:
        sizes = as_account("developer", ["/usr/bin/stat", "-c", "%n %s", *files.values()], check=False).stdout
        record("the developer holds receipt.boc, artifact.tar, output.log and report.json", "artifact.tar" in sizes,
               sizes.strip().splitlines())
    # The agent's own view of the ack: its duty round sends it after
    # acceptance (refund_now runs that round now and reports it).
    duty = structured(mcp("tos_buyer_refund", {"request_hash": request_hash})).get("duty") or {}
    record("the agent's result round after acceptance (ack sent or due)", bool((duty.get("result") or {}).get("accepted")),
           duty.get("result"))

    def provider_entry() -> dict:
        status = json.loads(openfox("status", "--rail-config", str(PROVIDER_RAIL / "rail.json")).stdout)
        return next((r for r in status.get("requests", []) if r.get("request_hash") == request_hash), {})
    acked = poll(lambda: provider_entry().get("operator_state") == "acked", 600, 15)
    entry = provider_entry()
    record("OpenFox recorded the buyer's ack", acked is not None, entry)


# --- Negatives that need no purchase --------------------------------------------

def socket_request(account: str, method: str, params: dict, groups: list | None = None) -> dict:
    """One raw agent-socket request from an account: whether it connected,
    and the answer line, if any (the agent closes an unknown peer without
    reading or answering)."""
    request = json.dumps({"schema": "tos.service.mcp-buyer.agent-api.v1", "method": method, "params": params})
    program = (
        "import json, socket, sys\n"
        "s = socket.socket(socket.AF_UNIX)\n"
        "try:\n"
        f"    s.connect({str(SOCKET_DIR / 'agent.sock')!r})\n"
        "except OSError as error:\n"
        "    print(json.dumps({'connected': False, 'error': error.strerror})); sys.exit(0)\n"
        f"s.sendall({(request + chr(10)).encode()!r})\n"
        "try:\n"
        "    line = s.makefile().readline().strip()\n"
        "except ConnectionResetError:\n"
        "    line = ''\n"
        "print(json.dumps({'connected': True, 'answer': json.loads(line) if line else None}))\n")
    result = as_account(account, [str(MOUNTS / "venv" / "bin" / "python3"), "-I", "-c", program], check=False,
                        timeout=30, groups=groups)
    return json.loads(result.stdout.strip() or '{"connected": false, "error": "no output"}')


def peer_negatives() -> None:
    outside = socket_request("stranger", "purchases", {"page_size": 1})
    record("an account outside the socket group cannot reach the socket", not outside.get("connected"), outside)
    # In the socket group, the agent's own peer-credential check decides.
    member = socket_request("stranger", "purchases", {"page_size": 1}, groups=[SOCKET_GROUP])
    record("a third account in the socket group is refused before its request is read",
           member.get("connected") and member.get("answer") is None, member)
    decide = socket_request("developer", "decide", {"request_hash": "00" * 32, "decision": "confirm", "code": "x"})
    answer = decide.get("answer") or {}
    refused = not answer.get("ok", True) and (answer.get("error") or {}).get("code") == "MCP_BUYER_PERMISSION_DENIED"
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
    # Everything a previous run left too (root cannot write a file the host
    # owns), except thermal.jsonl, which the host's thermal guard keeps
    # appending to, and the build the host made.
    os.chown(WORK, 0, 0)
    for path in WORK.rglob("*"):
        if path.name == "thermal.jsonl" or path.is_symlink() or WORK / "bin" in [path, *path.parents] or \
                path == WORK / "build.json":
            continue
        os.chown(path, 0, 0)
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
            evidence["registry_code_hash"] = json.loads(as_account(None, [
                str(BIN / "service-actor-e2e-fixture"), "code-hash", "--boc-file", str(REGISTRY_BOC)]).stdout)["code_hash"]
            offer = setup_provider(tosctl_sha256)
            evidence["provider"] = offer
            start_gateway(offer["provider_agent_id"])
            evidence["buyer"] = setup_buyer(evidence["wallets"]["custody"], tosctl_sha256)
            listed = mcp(None)
            record("the developer's MCP client lists the buyer tools through the real server",
                   "tos_buyer_quote" in listed.get("tools", []) and "tos_buyer_result" in listed.get("tools", []),
                   listed.get("tools"))
            peer_negatives()
            scenario_gateway_purchase(offer)
    except Exception as error:  # noqa: BLE001 - the evidence records the failure
        import traceback
        record("run completed without an exception", False, {"error": repr(error),
                                                              "traceback": traceback.format_exc()[-4000:]})
    finally:
        stop_all()
    evidence["steps"] = steps
    thermal = WORK / "thermal.jsonl"
    evidence["thermal_pauses"] = [json.loads(line) for line in thermal.read_text().splitlines()] if thermal.exists() else []
    evidence["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    passed = bool(steps) and all(step["pass"] for step in steps)
    evidence["result"] = "ALL PASS" if passed else "FAIL"
    (WORK / "evidence.json").write_text(json.dumps(redact_value(evidence), indent=2) + "\n")
    print(f"evidence: {WORK / 'evidence.json'}")
    print("ALL PASS" if passed else "FAIL")
    return 0 if passed else 1


def give_back() -> None:
    """Everything the host reads back belongs to the host account again; the
    work directory itself last, since root cannot enter it after that."""
    host_uid, host_gid = int(os.environ["HOST_UID"]), int(os.environ["HOST_GID"])
    for path in [*sorted(WORK.rglob("*"), key=lambda p: len(p.parts), reverse=True), WORK]:
        if path.is_symlink():
            continue
        try:
            os.chown(path, host_uid, host_gid)
        except OSError as error:
            print(f"could not return {path}: {error}", flush=True)


if __name__ == "__main__":
    status = 1
    try:
        status = asyncio.run(main())
    finally:
        # Whatever ends the run, the host gets its work directory back.
        give_back()
    sys.exit(status)
