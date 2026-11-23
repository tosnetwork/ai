#!/usr/bin/env python3
"""Driver of the local agent-operated provider run (MCP_PROVIDER_ADAPTER_V1
section 10.2) on the existing local four-validator PQ network of this host.

It runs as the operator's own account, never as root. Every custody-side
command runs as its custody account and every model client as the developer
account, through `sudo -n -u <account>`; the operator's sudo rights are used
for nothing else. The root steps (accounts, groups, socket directories,
binaries, the executor's allowed uid) are the separate setup script's, which
the owner runs; the faucet funding is the separate funding script's.

Accounts (MCP_PROVIDER_GUIDE.md section 3, MCP_BUYER_GUIDE.md section 3):

- tosprov1: provider custody; vault, rail state, provider agents, confirmer;
- tosbuy1:  buyer custody; vault, buyer agents, confirmer;
- agentdev: the developer account; runs Claude Code and Codex, and through
  them tos-service-provider-mcp and tos-service-buyer-mcp; in the two socket
  groups only, no sudo, no route to either custody account.

Role assignments: A, Codex operates provider node a and Claude Code buys from
buyer node a; B, Claude Code operates provider node b and Codex buys from
buyer node b. Each assignment has its own provider node (wallet, Agent,
actor, Capability) and buyer Agent in the same two custody accounts, served
by the one executor installation.

Usage: acceptance.py RUN_DIR COMMAND [ARGS]

  build                 build the ai binaries at AI_COMMIT into RUN/bin
  check [--before-setup]
                        check every precondition; exit 1 on any failure
  relay start|status    the run's Agent Packet Relay (operator account,
                        127.0.0.1:47790, HTTPS under the run's own test CA)
  prepare a|b           custody vaults, tosctl configurations and wallets;
                        writes RUN/public/funding-request-<x>.json
  init a|b              after funding: activate the wallets, provider init
                        (preview, then --yes) and preflight, buyer init, the
                        agent configurations and user units, the developer
                        workspace and client configurations
  commands a|b          print every client command and prompt of the
                        assignment, as the coordinator would start them
  step a|b STEP         run one step (a model session, the confirmer it
                        needs, the operator action it names); see STEPS
  status a|b            what has run, what is next
  evidence a|b          the buyer evidence exports, as the buyer custody
  verify                tos-service-verify from a fresh clone, every purchase
  record                the section 10.3 record under RUN/record/

Environment: TOS_ROOT (the tos checkout the local network was built from;
its venv runs this driver), AI_COMMIT (default: this file's pinned main),
ACCEPTANCE_DEVELOPER (default agentdev), ACCEPTANCE_CLAUDE and
ACCEPTANCE_CODEX (the client binaries).

The clients start in RUN/client-cwd, outside every home directory, with
CLAUDE.md, auto-memory, bundled skills, user settings and user MCP servers
off (Claude Code), and user configuration, rules and project documents off
(Codex), so that only the task prompt and the one MCP server reach them.
"""

from __future__ import annotations

import datetime
import grp
import hashlib
import json
import os
import pwd
import re
import shlex
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE))
import chain  # noqa: E402

AI_COMMIT = os.environ.get("AI_COMMIT", "571e9c50e43cc7a23950fe13932abf4579c9e09d")
TOS_ROOT = chain.TOS_ROOT
# Set by main() from the command line.
RUN = PRIVATE = PUBLIC = TRANSCRIPTS = Path("/nonexistent")
COMMAND, ARGS = "", []
INSTALL_RECORD = Path("/var/lib/tos-acceptance/install.json")
BIN = Path("/usr/local/bin")
TOSCTL = BIN / "tosctl"
# The model clients. ACCEPTANCE_CLAUDE and ACCEPTANCE_CODEX name the
# binaries already logged in in the developer account when it is not the
# dedicated one (the record lists each binary's SHA-256).
CLAUDE = Path(os.environ.get("ACCEPTANCE_CLAUDE", "/opt/tos-acceptance-clients/claude/claude"))
CODEX = Path(os.environ.get("ACCEPTANCE_CODEX", "/opt/tos-acceptance-clients/codex/bin/codex"))
EXECUTOR_SOCKET = "/run/tos-service-executor/executor.sock"
NETWORK_LABEL = "tos:global-id:3"
RELAY_PORT = 47790
RELAY_URL = f"https://127.0.0.1:{RELAY_PORT}"
NANO = 1_000_000_000
PROVIDER, BUYER = "tosprov1", "tosbuy1"
# The developer account that runs both model clients and both MCP servers.
# ACCEPTANCE_DEVELOPER names another account, for example the operator's own
# when the clients are logged in only there; the record then states that
# the developer account is the operator account, with sudo, and that the
# clients had no shell or file tool.
DEVELOPER = os.environ.get("ACCEPTANCE_DEVELOPER", "agentdev")
DEVELOPER_IS_OPERATOR = DEVELOPER == pwd.getpwuid(os.getuid()).pw_name
GROUPS = {PROVIDER: "tosprov1-clients", BUYER: "tosbuy1-clients"}
ASSIGNMENTS = {
    "a": {"provider_client": "codex", "buyer_client": "claude"},
    "b": {"provider_client": "claude", "buyer_client": "codex"},
}
FUNDING = {"provider": 20 * NANO, "buyer": 10 * NANO}
# The release Service Actor's windows: 3,600 s is its minimum.
WINDOW = 3600
TERMS = {"price": "100000000", "storage_fee": "200000000", "cleanup_bounty": "100000000"}
BINARIES = {
    "tos-service-provider": "./provider/cmd/tos-service-provider",
    "tos-service-provider-mcp": "./provider/cmd/tos-service-provider-mcp",
    "tos-service-buyer": "./protocol/cmd/tos-service-buyer",
    "tos-service-buyer-mcp": "./protocol/cmd/tos-service-buyer-mcp",
    "tos-service-verify": "./protocol/cmd/tos-service-verify",
    "tos-service-packet-relay": "./protocol/cmd/tos-service-packet-relay",
}
# Vault credentials, and e-mail addresses (a client's login status names one).
SECRET = re.compile(r"master_key=[0-9A-Fa-f]+|VAULT_URL=\S+|[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def redact(text: str) -> str:
    return SECRET.sub("<vault credential>", text)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def release(name: str) -> dict:
    return json.loads((TOS_ROOT / "crypto" / "smartcont" / f"{name}.release.json").read_text())


ACTOR_CODE_HASH = release("tos-service-actor-v1")["code_hash"]
REGISTRY_CODE_HASH = release("tos-service-native-registry-v1")["code_hash"]
REGISTRY_BOC = TOS_ROOT / "crypto" / "smartcont" / "tos-service-native-registry-v1.boc.base64"


# --- State -----------------------------------------------------------------------


# The state is kept in one file per scope: state-a.json and state-b.json for
# the two assignments, state-global.json for the rest. An invocation writes
# only its own scope's file, so the two assignments can run side by side
# (B's first steps during A's hour-long refund wait) without overwriting
# each other.
SCOPE = "global"
PER_ASSIGNMENT = ("sessions", "confirmations", "switches", "events")


def load_state() -> dict:
    loaded = {
        "schema": "tos.service.local-agent-operated-provider-run-state.v1",
        "events": [],
        "sessions": [],
        "confirmations": [],
        "assignments": {
            x: {
                "purchases": {},
                "pauses": [],
                "actions": [],
                "operator": [],
                "cli_fallback_steps": [],
                "steps_done": [],
            }
            for x in ASSIGNMENTS
        },
        "switches": [],
    }
    global_file = PRIVATE / "state-global.json"
    if global_file.exists():
        part = json.loads(global_file.read_text())
        loaded["events"] += part.pop("events", [])
        loaded.update(part)
    for x in ASSIGNMENTS:
        path = PRIVATE / f"state-{x}.json"
        if path.exists():
            part = json.loads(path.read_text())
            loaded["assignments"][x] = part["assignment"]
            for key in PER_ASSIGNMENT:
                loaded[key] += part.get(key, [])
    return loaded


state: dict = {}


def save() -> None:
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if SCOPE in ASSIGNMENTS:
        part = {"assignment": state["assignments"][SCOPE]}
        for key in PER_ASSIGNMENT:
            part[key] = [entry for entry in state[key] if entry.get("assignment", entry.get("scope")) == SCOPE]
        target = PRIVATE / f"state-{SCOPE}.json"
    else:
        part = {k: v for k, v in state.items() if k not in ("assignments", *PER_ASSIGNMENT)}
        part["events"] = [entry for entry in state["events"] if entry.get("scope") == "global"]
        target = PRIVATE / "state-global.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(part, indent=2, sort_keys=True) + "\n")
    temporary.replace(target)


def event(name: str, **detail) -> None:
    entry = {"at": now(), "event": name, "scope": SCOPE, **detail}
    state["events"].append(entry)
    save()
    print(f"{entry['at']} {name} {redact(json.dumps(detail, sort_keys=True))[:600]}", flush=True)


def fail(message: str) -> None:
    event("failed", message=message)
    raise SystemExit(f"FAIL: {message}")


# --- Running as an account ------------------------------------------------------------


def uid(account: str) -> int:
    return pwd.getpwnam(account).pw_uid


def home(account: str) -> Path:
    return Path(pwd.getpwnam(account).pw_dir)


def account_env(account: str, extra: dict | None = None) -> list[str]:
    env = {
        "HOME": str(home(account)),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "XDG_RUNTIME_DIR": f"/run/user/{uid(account)}",
    }
    env.update(extra or {})
    return [f"{k}={v}" for k, v in env.items()]


def as_cmd(
    account: str, argv: list, *, vault: bool = False, extra_env: dict | None = None, chdir: Path | None = None
) -> list[str]:
    """The command line that runs argv as account with only that account's
    environment, in its home (or chdir). With vault, the account's own
    vault.env is sourced inside the account, so the credential never passes
    through this driver."""
    argv = [str(a) for a in argv]
    if vault:
        argv = ["/bin/bash", "-c", 'set -a; . "$HOME/custody/vault.env"; set +a; exec "$@"', "bash", *argv]
    directory = str(chdir or home(account))
    return [
        "sudo",
        "-n",
        "-u",
        account,
        "--",
        "/usr/bin/env",
        "-i",
        "-C",
        directory,
        *account_env(account, extra_env),
        *argv,
    ]


def run_as(
    account: str,
    argv: list,
    *,
    vault: bool = False,
    check: bool = True,
    timeout: float = 900,
    input_text: str | None = None,
    extra_env: dict | None = None,
) -> subprocess.CompletedProcess:
    command = as_cmd(account, argv, vault=vault, extra_env=extra_env)
    # The driver's own directory may be closed to the account; sudo starts
    # from "/" and env -C enters the account's home.
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, input=input_text, cwd="/")
    TRANSCRIPTS.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (PRIVATE / "commands.jsonl").open("a") as log:
        log.write(
            json.dumps(
                {
                    "at": now(),
                    "account": account,
                    "argv": [redact(str(a)) for a in argv],
                    "vault_env_sourced_in_account": vault,
                    "exit": result.returncode,
                    "stdout_tail": redact(result.stdout[-3000:]),
                    "stderr_tail": redact(result.stderr[-3000:]),
                }
            )
            + "\n"
        )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"{account}: {' '.join(map(str, argv[:3]))} exited {result.returncode}: {redact(result.stderr[-1500:])}"
        )
    return result


def write_as(account: str, path: str | Path, text: str, mode: str = "0600") -> None:
    run_as(account, ["/bin/sh", "-c", f'umask 077; cat > "$1" && chmod {mode} "$1"', "sh", str(path)], input_text=text)


def read_as(account: str, path: str | Path, check: bool = True) -> str:
    return run_as(account, ["/bin/cat", str(path)], check=check).stdout


def last_json(text: str):
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    try:
        return json.loads(text)
    except ValueError:
        return None


def poll(predicate, timeout: float, interval: float = 5):
    deadline = time.monotonic() + timeout
    while True:
        try:
            value = predicate()
        except Exception:  # noqa: BLE001 - a poll retries until its deadline
            value = None
        if value:
            return value
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval)


# --- Paths of one assignment ------------------------------------------------------------


def paths(x: str) -> dict:
    prov, buy, dev = home(PROVIDER), home(BUYER), home(DEVELOPER)
    return {
        "node": prov / f"node-{x}",
        "rail_config": prov / f"node-{x}" / "rail.json",
        "rail_state": prov / f"node-{x}" / "rail",
        "agent_state": prov / f"node-{x}" / "agent-state",
        "agent_config": prov / f"node-{x}" / "agent.json",
        "provider_socket_dir": Path(f"/run/tos-provider-1{x}"),
        "provider_socket": Path(f"/run/tos-provider-1{x}/agent.sock"),
        "provider_wallet": f"provider-{x}",
        "packet_controller": f"service-packet-{x}",
        "attestor_controller": f"service-attestor-{x}",
        "provider_unit": f"tos-service-provider-agent-{x}.service",
        "buyer_node": buy / f"node-{x}",
        "buyer_config": buy / f"node-{x}" / "agent.json",
        "buyer_state": buy / f"node-{x}" / "state",
        "buyer_manifests": buy / f"node-{x}" / "manifests",
        "buyer_socket_dir": Path(f"/run/tos-buyer-1{x}"),
        "buyer_socket": Path(f"/run/tos-buyer-1{x}/agent.sock"),
        "buyer_wallet": f"buyer-{x}",
        "buyer_controller": f"buyer-packet-{x}",
        "buyer_unit": f"tos-service-buyer-agent-{x}.service",
        "buyer_evidence": buy / "evidence",
        "dev_work": dev / "acceptance",
        "export_dir": dev / f"tos-offers-{x}",
        "src": dev / f"src-{x}" / "job",
        "results": dev / f"tos-results-{x}",
    }


def custody_file(account: str, name: str) -> Path:
    return home(account) / "custody" / name


def installed() -> dict:
    if not INSTALL_RECORD.exists():
        fail(f"{INSTALL_RECORD} is missing: the setup script has not run with --go")
    return json.loads(INSTALL_RECORD.read_text())


def tosctl_sha256() -> str:
    return installed()["tosctl"]["sha256"]


def tosctl_as(account: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return run_as(account, [TOSCTL, *args, "-c", custody_file(account, "tosctl.json")], vault=True, check=check)


def wallet_address(account: str, name: str) -> str | None:
    listed = tosctl_as(account, "wallet", "ls", "--format", "json", check=False)
    try:
        wallets = json.loads(listed.stdout)
    except ValueError:
        return None
    for wallet in wallets:
        if wallet.get("name") == name and wallet.get("address"):
            from pytosiq_core import Address

            return Address(wallet["address"]).to_str(is_user_friendly=False).lower()
    return None


def user_systemctl(account: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return run_as(account, ["/usr/bin/systemctl", "--user", *args], check=check)


# --- build ------------------------------------------------------------------------------


def cmd_build() -> None:
    """One ai build at AI_COMMIT, from a detached worktree of this
    repository, into RUN/bin with build.json. Never as root."""
    if os.geteuid() == 0:
        fail("build runs as the operator, not root")
    source = RUN / "ai-src"
    if not source.exists():
        subprocess.run(["git", "-C", str(REPO), "worktree", "add", "--detach", str(source), AI_COMMIT], check=True)
    head = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "-C", str(source), "status", "--porcelain"], capture_output=True, text=True, check=True
    ).stdout.strip()
    if head != AI_COMMIT or dirty:
        fail(f"the build tree is at {head} (dirty: {bool(dirty)}), not a clean {AI_COMMIT}")
    out = RUN / "bin"
    out.mkdir(mode=0o755, exist_ok=True)
    env = {**os.environ, "GOWORK": "off", "CGO_ENABLED": "0", "GOTOOLCHAIN": "go1.26.11", "GOFLAGS": "-p=4"}
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(out) + "/", *BINARIES.values()], cwd=source, env=env, check=True
    )
    go_version = subprocess.run(["go", "version"], cwd=source, env=env, capture_output=True, text=True).stdout.strip()
    build = {
        "schema": "tos.service.acceptance-build.v1",
        "ai_commit": head,
        "go": go_version,
        "built_utc": now(),
        "flags": "GOWORK=off CGO_ENABLED=0 GOTOOLCHAIN=go1.26.11 go build -trimpath",
        "binaries": {name: sha256_file(out / name) for name in BINARIES},
    }
    (out / "build.json").write_text(json.dumps(build, indent=2, sort_keys=True) + "\n")
    for path in out.iterdir():
        path.chmod(0o755 if path.name != "build.json" else 0o644)
    out.chmod(0o755)
    print(json.dumps(build, indent=2, sort_keys=True))


# --- check ------------------------------------------------------------------------------


def checks_before_setup() -> list:
    results = []

    def check(name, ok, detail=None):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    check("the driver runs as a non-root account", os.geteuid() != 0, {"uid": os.geteuid()})
    build = RUN / "bin" / "build.json"
    check(
        "RUN/bin holds one build at AI_COMMIT",
        build.exists() and json.loads(build.read_text()).get("ai_commit") == AI_COMMIT,
        str(build),
    )
    view = chain.validator_set()
    check(
        "a strict majority of the candidate endpoints agree on a four-member validator set",
        bool(view) and len(view["members"]) == 4,
        view and chain.membership(view),
    )
    heads = chain.heads()
    numeric = [h for h in heads.values() if isinstance(h, int)]
    check(
        "every candidate endpoint answers and the heads lie within 10 blocks",
        len(numeric) == len(heads) and max(numeric) - min(numeric) <= 10,
        heads,
    )
    elections = subprocess.run(["systemctl", "is-active", "tos-pq-elections"], capture_output=True, text=True)
    check(
        "the election service runs (membership changes every election)",
        elections.stdout.strip() == "active",
        elections.stdout.strip(),
    )
    network = json.loads(Path("/data/network.json").read_text())
    check(
        "the network is the local PQ network of /data/network.json (global id 3, 4 validators)",
        network.get("global_id") == 3 and network.get("validators") == 4 and network.get("mode") == "pq",
        {k: network.get(k) for k in ("global_id", "validators", "zerostate_root", "zerostate_file")},
    )
    check(
        "the tos checkout carries the release Service Actor and Native Registry artifacts",
        REGISTRY_BOC.exists() and ACTOR_CODE_HASH.startswith("tvm-cell-sha256:"),
        {"actor_code_hash": ACTOR_CODE_HASH, "registry_code_hash": REGISTRY_CODE_HASH},
    )
    temperature = subprocess.run(["sensors"], capture_output=True, text=True).stdout
    packages = [float(m) for m in re.findall(r"Package id \d+:\s+\+([0-9.]+)", temperature)]
    check("every CPU package is below 85 C", packages and max(packages) < 85, packages)
    return results


def checks_after_setup() -> list:
    results = checks_before_setup()

    def check(name, ok, detail=None):
        results.append({"name": name, "pass": bool(ok), "detail": detail})

    record = installed()
    build = json.loads((RUN / "bin" / "build.json").read_text())
    for name, digest in build["binaries"].items():
        path = BIN / name
        ok = path.exists() and sha256_file(path) == digest and path.stat().st_uid == 0
        check(f"/usr/local/bin/{name} is root-owned and matches build.json", ok, digest[:16])
    check(
        "the installed tosctl is root-owned and matches its pin",
        TOSCTL.exists() and TOSCTL.stat().st_uid == 0 and sha256_file(TOSCTL) == record["tosctl"]["sha256"],
        record["tosctl"],
    )
    for account in (PROVIDER, BUYER, DEVELOPER):
        try:
            entry = pwd.getpwnam(account)
        except KeyError:
            check(f"account {account} exists", False)
            continue
        mode = Path(entry.pw_dir).stat().st_mode & 0o777
        check(f"account {account} has a home closed to others", mode & 0o007 == 0, oct(mode))
        probe = subprocess.run(["sudo", "-n", "-u", account, "--", "/bin/true"], capture_output=True, text=True)
        check(
            f"the operator can run commands as {account} without a password prompt",
            probe.returncode == 0,
            probe.stderr.strip()[:200],
        )
    # Group membership as a fresh login of the developer gets it (sudo -u
    # runs initgroups), which is how every client process is started.
    groups = run_as(DEVELOPER, ["/usr/bin/id", "-nG"], check=False).stdout.split()
    check("the developer account is in both socket groups", set(GROUPS.values()) <= set(groups), groups)
    custody_groups = {PROVIDER, BUYER} & set(groups)
    check("the developer account is in no custody account's own group", not custody_groups, sorted(custody_groups))
    if DEVELOPER_IS_OPERATOR:
        # Known limitation of the run: the clients get no shell or file tool,
        # so the model cannot use the account's sudo (record: accounts).
        check("the developer account is the operator account (has sudo; clients run without shell tools)", True)
    else:
        forbidden = {"sudo", "adm", "admin", "wheel", "docker", "lxd", "tos-executor"}
        check("the developer account is in no privileged group", not forbidden & set(groups), groups)
        sudo_probe = run_as(DEVELOPER, ["/usr/bin/sudo", "-n", "true"], check=False)
        check("the developer account cannot use sudo without a password", sudo_probe.returncode != 0)
    for account in (PROVIDER, BUYER):
        probe = run_as(DEVELOPER, ["/bin/ls", home(account)], check=False)
        check(f"the developer account cannot open {account}'s home", probe.returncode != 0, probe.stderr.strip()[:160])
        linger = Path("/var/lib/systemd/linger") / account
        check(f"{account} lingers (its user units run without a login)", linger.exists())
    login_env = subprocess.run(as_cmd(DEVELOPER, ["/bin/bash", "-lc", "env"]), capture_output=True, text=True, cwd="/")
    check("no VAULT_URL in the developer account's login environment", "VAULT_URL=" not in login_env.stdout)
    for x in ASSIGNMENTS:
        p = paths(x)
        for directory, owner, group in (
            (p["provider_socket_dir"], PROVIDER, GROUPS[PROVIDER]),
            (p["buyer_socket_dir"], BUYER, GROUPS[BUYER]),
        ):
            ok = False
            if directory.exists():
                info = directory.stat()
                ok = (
                    info.st_mode & 0o7777 == 0o2750
                    and info.st_uid == uid(owner)
                    and info.st_gid == grp.getgrnam(group).gr_gid
                )
            check(f"{directory} is setgid 2750 {owner}:{group}", ok)
    check("tmpfiles recreates the socket directories at boot", Path("/etc/tmpfiles.d/tos-acceptance.conf").exists())
    executor = subprocess.run(["pgrep", "-a", "-f", "software-work-executord"], capture_output=True, text=True).stdout
    allowed = re.findall(r"--allow-uid (\d+)", executor)
    check("the executor service allows exactly tosprov1's uid", allowed == [str(uid(PROVIDER))], allowed)
    executor_groups = subprocess.run(["id", "-nG", PROVIDER], capture_output=True, text=True).stdout.split()
    check("tosprov1 is in the executor's socket group", "tos-executor" in executor_groups, executor_groups)
    for client, binary in (("claude", CLAUDE), ("codex", CODEX)):
        check(f"the {client} client exists", binary.exists(), str(binary))
    claude_auth = run_as(DEVELOPER, [CLAUDE, "auth", "status"], check=False, timeout=60)
    # Only the exit status: the status text names the account's login.
    check("Claude Code is logged in in the developer account", claude_auth.returncode == 0)
    codex_auth = run_as(DEVELOPER, [CODEX, "login", "status"], check=False, timeout=60)
    check("Codex is logged in in the developer account", codex_auth.returncode == 0)
    relay = relay_probe()
    check("the run's relay serves HTTPS under the run's CA", relay.get("ok"), relay)
    check("no OpenFox binary, source or configuration is present", openfox_scan()["absent"], openfox_scan())
    return results


def openfox_scan() -> dict:
    """Every place the run's programs could come from or keep state in, for
    an OpenFox file name or the OpenFox module path."""
    hits = []
    places = [BIN, Path("/opt/tos-acceptance-clients"), RUN / "bin", client_cwd()]
    for place in places:
        if place.exists():
            found = subprocess.run(["find", str(place), "-iname", "*openfox*"], capture_output=True, text=True)
            hits += found.stdout.split()
    # Every account's home, and the PATH the run's processes get (the
    # driver gives every one of them the same fixed PATH).
    run_path = "/usr/local/bin:/usr/bin:/bin"
    developer_home = []
    for account in (PROVIDER, BUYER, DEVELOPER):
        found = run_as(
            account, ["/usr/bin/find", home(account), "-iname", "*openfox*", "-not", "-path", "*/.cache/*"], check=False
        ).stdout.split()
        if account == DEVELOPER and DEVELOPER_IS_OPERATOR:
            developer_home += found
        else:
            hits += found
        which = run_as(account, ["/bin/sh", "-c", f"PATH={run_path} command -v openfox || true"], check=False)
        hits += which.stdout.split()
    strings = []
    for name in BINARIES:
        path = BIN / name
        if path.exists() and b"github.com/tosnetwork/openfox" in path.read_bytes():
            strings.append(name)
    return {
        # Absent from everything the run executes, installs, reads or keeps
        # state in. When the developer account is the operator's own, OpenFox
        # files in its home are counted separately (no path is recorded):
        # the clients had no shell or file tool, the MCP servers read only
        # their flags' paths, and no run process has them on its PATH.
        "absent": not hits and not strings,
        "file_hits": hits,
        "binaries_linking_openfox": strings,
        "run_path": run_path,
        "developer_home_is_operator_home": DEVELOPER_IS_OPERATOR,
        "openfox_items_in_operator_home": len(developer_home),
        "scanned": [str(p) for p in places]
        + [f"home of the {role}" for role in ("provider custody", "buyer custody", "developer account")],
        "at": now(),
    }


def cmd_check() -> None:
    results = checks_before_setup() if "--before-setup" in ARGS else checks_after_setup()
    for entry in results:
        print(
            ("PASS " if entry["pass"] else "FAIL ")
            + entry["name"]
            + ("" if entry["pass"] else f"  {json.dumps(entry['detail'])[:300]}")
        )
    state.setdefault("checks", []).append({"at": now(), "results": results})
    save()
    if not all(entry["pass"] for entry in results):
        raise SystemExit(1)


# --- relay ------------------------------------------------------------------------------


def relay_probe() -> dict:
    import ssl
    import urllib.request

    ca = PUBLIC / "relay-ca.pem"
    if not ca.exists():
        return {"ok": False, "error": "no relay CA yet"}
    try:
        context = ssl.create_default_context(cafile=str(ca))
        status = urllib.request.urlopen(RELAY_URL + "/v1/relay", context=context, timeout=5).status
        return {"ok": status == 200, "url": RELAY_URL, "ca_sha256": sha256_file(ca)}
    except Exception as error:  # noqa: BLE001 - reported
        return {"ok": False, "error": repr(error)[:200]}


def cmd_relay() -> None:
    """The run's relay, as the operator's own user service. Its test CA is
    made once for the run and pinned by SHA-256 in the record; the CA key
    never leaves RUN/relay (0700)."""
    action = ARGS[0] if ARGS else "status"
    tls = RUN / "relay"
    if action == "status":
        print(json.dumps(relay_probe()))
        return
    if action != "start":
        fail("relay takes start or status")
    tls.mkdir(mode=0o700, parents=True, exist_ok=True)
    PUBLIC.mkdir(mode=0o755, parents=True, exist_ok=True)
    if not (tls / "ca.pem").exists():

        def openssl(*args):
            subprocess.run(["openssl", *args], check=True, capture_output=True)

        openssl(
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "14",
            "-subj",
            "/CN=local acceptance relay CA",
            "-keyout",
            str(tls / "ca.key"),
            "-out",
            str(tls / "ca.pem"),
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        )
        openssl(
            "req",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
            "-keyout",
            str(tls / "relay.key"),
            "-out",
            str(tls / "relay.csr"),
        )
        (tls / "san.ext").write_text(
            "subjectAltName=IP:127.0.0.1\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
        )
        openssl(
            "x509",
            "-req",
            "-in",
            str(tls / "relay.csr"),
            "-CA",
            str(tls / "ca.pem"),
            "-CAkey",
            str(tls / "ca.key"),
            "-CAcreateserial",
            "-days",
            "14",
            "-extfile",
            str(tls / "san.ext"),
            "-out",
            str(tls / "relay.pem"),
        )
    (PUBLIC / "relay-ca.pem").write_text((tls / "ca.pem").read_text())
    (PUBLIC / "relay-ca.pem").chmod(0o644)
    (tls / "state").mkdir(mode=0o700, exist_ok=True)
    relay = BIN / "tos-service-packet-relay"
    unit = "tos-acceptance-relay"
    active = subprocess.run(["systemctl", "--user", "is-active", unit], capture_output=True, text=True).stdout.strip()
    if active != "active":
        subprocess.run(
            [
                "systemd-run",
                "--user",
                "--unit",
                unit,
                "--property",
                "Restart=on-failure",
                str(relay),
                "-listen",
                f"127.0.0.1:{RELAY_PORT}",
                "-tls-cert",
                str(tls / "relay.pem"),
                "-tls-key",
                str(tls / "relay.key"),
                "-state-dir",
                str(tls / "state"),
                "-global-max-entries",
                "100000",
                "-global-max-bytes",
                str(1 << 30),
            ],
            check=True,
        )
    probe = poll(lambda: relay_probe() if relay_probe().get("ok") else None, 60, 1) or relay_probe()
    state["relay"] = {
        "url": RELAY_URL,
        "ca_sha256": sha256_file(PUBLIC / "relay-ca.pem"),
        "binary_sha256": sha256_file(relay),
        "account": "operator",
        "unit": unit,
        "listen": f"127.0.0.1:{RELAY_PORT}",
        "probe": probe,
    }
    event("relay started", **state["relay"])


# --- prepare ----------------------------------------------------------------------------


def publish_public_inputs() -> None:
    PUBLIC.mkdir(mode=0o755, parents=True, exist_ok=True)
    for name, source in (
        ("global-config.json", Path("/data/configs/global.json")),
        ("registry-code.boc", REGISTRY_BOC),
    ):
        target = PUBLIC / name
        target.write_text(source.read_text())
        target.chmod(0o644)
    RUN.chmod(0o755)


def custody_base(account: str) -> None:
    """The account's vault and tosctl configuration, once. The vault master
    key is drawn inside the account and never read by this driver."""
    run_as(
        account,
        [
            "/bin/sh",
            "-c",
            'umask 077; mkdir -p "$HOME/custody"; cd "$HOME/custody"; '
            '[ -f vault.env ] || printf "VAULT_URL=file://%s/custody/vault.json?master_key=%s\\n" '
            '"$HOME" "$(openssl rand -hex 32)" > vault.env; chmod 0600 vault.env',
        ],
    )
    config = custody_file(account, "tosctl.json")
    if run_as(account, ["/usr/bin/test", "-f", config], check=False).returncode != 0:
        run_as(account, [TOSCTL, "config", "generate", "-o", config], vault=True)
    value = json.loads(read_as(account, config))
    value["chain_rpc"] = {"urls": chain.tosctl_urls(), "api_key": None}
    value["elections"] = None
    write_as(account, config, json.dumps(value, indent=2))
    for name in ("relay-ca.pem", "global-config.json", "registry-code.boc"):
        write_as(account, custody_file(account, name), (PUBLIC / name).read_text())


def cmd_prepare(x: str) -> None:
    p = paths(x)
    publish_public_inputs()
    if not (PUBLIC / "relay-ca.pem").exists():
        fail("start the relay first (acceptance.py RUN relay start)")
    requests = []
    for account, role, wallet in ((PROVIDER, "provider", p["provider_wallet"]), (BUYER, "buyer", p["buyer_wallet"])):
        custody_base(account)
        if wallet_address(account, wallet) is None:
            tosctl_as(account, "wallet", "create", "-n", wallet, "-v", "V4R2", "-w", "0")
        address = wallet_address(account, wallet)
        if address is None:
            fail(f"{account} has no wallet {wallet}")
        requests.append({"label": f"{role}-{x}", "address": address, "amount_nanotos": FUNDING[role]})
    request = {
        "schema": "tos.service.acceptance-funding-request.v1",
        "assignment": x,
        "network": NETWORK_LABEL,
        "zerostate_root": json.loads(Path("/data/network.json").read_text())["zerostate_root"],
        "transfers": requests,
        "made_utc": now(),
    }
    target = PUBLIC / f"funding-request-{x}.json"
    target.write_text(json.dumps(request, indent=2) + "\n")
    target.chmod(0o644)
    state["assignments"][x]["wallets"] = {r["label"]: r["address"] for r in requests}
    event(f"prepared {x}", funding_request=str(target), transfers=requests)


# --- init ---------------------------------------------------------------------------------


def provider_init_flags(x: str) -> list:
    p = paths(x)
    rpc = [part for endpoint in chain.endpoints() for part in ("--rpc", endpoint)]
    return [
        "init",
        "--rail-config",
        p["rail_config"],
        "--state-dir",
        p["rail_state"],
        *rpc,
        "--global-config",
        custody_file(PROVIDER, "global-config.json"),
        "--network-label",
        NETWORK_LABEL,
        "--tosctl",
        TOSCTL,
        "--tosctl-sha256",
        tosctl_sha256(),
        "--tosctl-config",
        custody_file(PROVIDER, "tosctl.json"),
        "--wallet",
        p["provider_wallet"],
        "--packet-controller",
        p["packet_controller"],
        "--registry-code-boc",
        custody_file(PROVIDER, "registry-code.boc"),
        "--actor-code-hash",
        ACTOR_CODE_HASH,
        "--relay-url",
        RELAY_URL,
        "--relay-ca-file",
        custody_file(PROVIDER, "relay-ca.pem"),
    ]


def provider_agent_config(x: str) -> dict:
    p = paths(x)
    return {
        "schema": "tos.service.mcp-provider.agent-config.v1",
        "rail_config": str(p["rail_config"]),
        "state_dir": str(p["agent_state"]),
        "socket_dir": str(p["provider_socket_dir"]),
        "client_uid": uid(DEVELOPER),
        "offer": {"executor_socket": EXECUTOR_SOCKET, "attestor_controller": p["attestor_controller"]},
        "offer_bounds": {
            "min_price_nanotos": "10000000",
            "max_price_nanotos": "5000000000",
            "max_storage_fee_nanotos": "1000000000",
            "max_cleanup_bounty_nanotos": "500000000",
            "min_response_sla_seconds": WINDOW,
            "max_response_sla_seconds": 86400,
            "min_refund_claim_window_seconds": WINDOW,
            "max_refund_claim_window_seconds": 86400,
            "min_retention_seconds": 3600,
            "max_retention_seconds": 604800,
        },
        "max_admissions_per_day": 50,
        "min_wallet_nanotos": "2000000000",
        "max_withdraw_previews_per_day": 8,
    }


def unit_text(description: str, exec_start: str) -> str:
    return (
        "[Unit]\nDescription=" + description + "\n\n[Service]\nEnvironmentFile=%h/custody/vault.env\n"
        "ExecStart=" + exec_start + "\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n"
    )


def install_unit(account: str, name: str, text: str) -> None:
    directory = home(account) / ".config" / "systemd" / "user"
    run_as(account, ["/bin/mkdir", "-p", directory])
    write_as(account, directory / name, text, "0644")
    user_systemctl(account, "daemon-reload")


def wait_funded(address: str, amount: int) -> None:
    funded = poll(lambda: (chain.balance(address) or 0) >= amount * 9 // 10, 600, 10)
    if not funded:
        fail(f"{address} is not funded; run the funding script first")


def activate(account: str, wallet: str, address: str) -> None:
    current = chain.account_state(address) or {}
    if not current.get("active"):
        tosctl_as(account, "wallet", "activate", "-n", wallet)
    if not poll(lambda: (chain.account_state(address) or {}).get("active"), 300, 5):
        fail(f"{wallet} did not become active")


def cmd_init(x: str) -> None:
    p = paths(x)
    a = state["assignments"][x]
    wallets = a.get("wallets") or fail("run prepare first")
    for account, role, wallet in ((PROVIDER, "provider", p["provider_wallet"]), (BUYER, "buyer", p["buyer_wallet"])):
        wait_funded(wallets[f"{role}-{x}"], FUNDING[role])
        activate(account, wallet, wallets[f"{role}-{x}"])
    # Provider: init (preview, then --yes), preflight, agent configuration
    # and unit. init is a human-only step the harness drives (section 10.2).
    for directory in (p["node"], p["rail_state"], p["agent_state"]):
        run_as(PROVIDER, ["/bin/mkdir", "-p", "-m", "0700", directory])
        run_as(PROVIDER, ["/bin/chmod", "0700", directory])
    exe = BIN / "tos-service-provider"
    preview = run_as(PROVIDER, [exe, *provider_init_flags(x)], vault=True, check=False)
    a["init_preview"] = {"exit": preview.returncode, "report": last_json(preview.stdout)}
    if preview.returncode not in (0, 4):
        fail(f"provider init preview exited {preview.returncode}: {redact(preview.stderr[-800:])}")
    done = run_as(PROVIDER, [exe, *provider_init_flags(x), "--yes"], vault=True, timeout=1800)
    a["provider_init"] = last_json(done.stdout)
    run_as(PROVIDER, ["/bin/chmod", "0600", p["rail_config"]])
    preflight = run_as(PROVIDER, [exe, "preflight", "--rail-config", p["rail_config"]], vault=True, check=False)
    report = last_json(preflight.stdout) or {}
    failing = [c.get("id") or c.get("name") for c in report.get("checks", []) if c.get("status") == "fail"]
    a["custody_preflight"] = {"exit": preflight.returncode, "failing": failing}
    write_as(PROVIDER, p["agent_config"], json.dumps(provider_agent_config(x), indent=2))
    install_unit(
        PROVIDER,
        p["provider_unit"],
        unit_text(f"TOS MCP provider agent {x}", f"{exe} agent --config {p['agent_config']}"),
    )
    user_systemctl(PROVIDER, "enable", "--now", p["provider_unit"])
    # Buyer: init plan, then apply --yes, and the agent unit.
    for directory in (p["buyer_node"], p["buyer_state"], p["buyer_manifests"], p["buyer_evidence"]):
        run_as(BUYER, ["/bin/mkdir", "-p", "-m", "0700", directory])
    flags = [
        "--config",
        p["buyer_config"],
        "--state-dir",
        p["buyer_state"],
        "--socket-dir",
        p["buyer_socket_dir"],
        "--client-uid",
        uid(DEVELOPER),
        "--network-label",
        NETWORK_LABEL,
        "--global-config",
        custody_file(BUYER, "global-config.json"),
        "--rpc",
        ",".join(chain.endpoints()),
        "--quorum",
        "3",
        "--registry-code-boc",
        custody_file(BUYER, "registry-code.boc"),
        "--actor-code-hash",
        ACTOR_CODE_HASH,
        "--manifest-dir",
        p["buyer_manifests"],
        "--tosctl",
        TOSCTL,
        "--tosctl-sha256",
        tosctl_sha256(),
        "--tosctl-config",
        custody_file(BUYER, "tosctl.json"),
        "--wallet",
        p["buyer_wallet"],
        "--packet-controller",
        p["buyer_controller"],
        "--relay",
        RELAY_URL,
        "--relay-ca-file",
        custody_file(BUYER, "relay-ca.pem"),
        "--budget-window",
        "24h",
        "--max-calls",
        "10",
        "--max-per-call-nanotos",
        "1000000000",
        "--max-window-nanotos",
        "6000000000",
        "--max-unconfirmed",
        "4",
        "--duty-interval-seconds",
        "30",
    ]
    buyer = BIN / "tos-service-buyer"
    plan = run_as(BUYER, [buyer, "init", "plan", *flags], vault=True, timeout=900)
    a["buyer_init_plan_sha256"] = hashlib.sha256(plan.stdout.encode()).hexdigest()
    run_as(BUYER, [buyer, "init", "apply", *flags, "--yes"], vault=True, timeout=1800)
    config = json.loads(read_as(BUYER, p["buyer_config"]))
    a["buyer"] = {
        "agent_id": config.get("buyer_agent_id"),
        "wallet": config.get("buyer_wallet"),
        "packet_controller_key_id": config.get("packet_controller_key_id"),
    }
    install_unit(
        BUYER, p["buyer_unit"], unit_text(f"TOS MCP buyer agent {x}", f"{buyer} agent --config {p['buyer_config']}")
    )
    user_systemctl(BUYER, "enable", "--now", p["buyer_unit"])
    for socket in (p["provider_socket"], p["buyer_socket"]):
        if not poll(
            lambda s=socket: run_as(DEVELOPER, ["/usr/bin/test", "-S", s], check=False).returncode == 0, 180, 3
        ):
            fail(f"{socket} did not appear")
    a["agent_start_lines"] = {
        "provider": journal_lines(PROVIDER, p["provider_unit"]),
        "buyer": journal_lines(BUYER, p["buyer_unit"]),
    }
    developer_workspace(x)
    event(
        f"initialized {x}",
        provider_agent=(a["provider_init"] or {}).get("agent_id"),
        buyer=a["buyer"],
        preflight_failing=failing,
    )


def journal_lines(account: str, unit: str) -> list:
    out = run_as(
        account, ["/usr/bin/journalctl", "--user", "-u", unit, "-o", "cat", "-n", "40", "--no-pager"], check=False
    ).stdout
    return [redact(line) for line in out.splitlines() if line.startswith("{")][-5:]


def mcp_args(x: str, role: str) -> tuple[str, list]:
    p = paths(x)
    if role == "provider":
        return str(BIN / "tos-service-provider-mcp"), [
            "--agent-socket",
            str(p["provider_socket"]),
            "--agent-state-dir",
            str(p["agent_state"]),
            "--rail-config",
            str(p["rail_config"]),
            "--export-dir",
            str(p["export_dir"]),
        ]
    return str(BIN / "tos-service-buyer-mcp"), [
        "--agent-socket",
        str(p["buyer_socket"]),
        "--agent-state-dir",
        str(p["buyer_state"]),
        "--workspace-root",
        str(p["export_dir"]),
        "--workspace-root",
        str(p["src"].parent),
        "--results-dir",
        str(p["results"]),
    ]


def server_name(role: str) -> str:
    return "tos-provider" if role == "provider" else "tos-buyer"


def developer_workspace(x: str) -> None:
    p = paths(x)
    for directory in (p["dev_work"], p["export_dir"], p["src"].parent, p["src"], p["results"]):
        run_as(DEVELOPER, ["/bin/mkdir", "-p", "-m", "0700", directory])
        run_as(DEVELOPER, ["/bin/chmod", "0700", directory])
    write_as(
        DEVELOPER, p["src"] / "main.go", 'package main\n\nfunc main() { println("built over the TOS rail") }\n', "0644"
    )
    write_as(DEVELOPER, p["src"] / "go.mod", "module example.com/acceptance\n\ngo 1.26\n", "0644")
    for role in ("provider", "buyer"):
        command, args = mcp_args(x, role)
        write_as(
            DEVELOPER,
            p["dev_work"] / f"claude-mcp-{x}-{role}.json",
            json.dumps({"mcpServers": {server_name(role): {"command": command, "args": args}}}, indent=2),
        )
        # The server's own start-up checks, as the developer: stdin closed,
        # it refuses at once or serves and ends at end of input.
        probe = run_as(DEVELOPER, [command, *args], check=False, timeout=30, input_text="")
        state["assignments"][x].setdefault("mcp_startup", {})[role] = {
            "exit": probe.returncode,
            "stderr": redact(probe.stderr.strip()[-300:]),
        }
    save()


# --- clients and steps --------------------------------------------------------------------


def client_command(client: str, x: str, role: str) -> tuple[list, bool]:
    """The non-interactive client command line (without the sudo prefix) and
    whether the prompt goes on stdin."""
    p = paths(x)
    server = server_name(role)
    if client == "claude":
        return [
            str(CLAUDE),
            "-p",
            "{PROMPT}",
            "--mcp-config",
            str(p["dev_work"] / f"claude-mcp-{x}-{role}.json"),
            "--strict-mcp-config",
            "--setting-sources",
            "",
            "--tools",
            "",
            "--allowedTools",
            f"mcp__{server}__*",
            "--permission-mode",
            "dontAsk",
            "--output-format",
            "stream-json",
            "--verbose",
            "--no-session-persistence",
        ], False
    command, args = mcp_args(x, role)
    return [
        str(CODEX),
        "exec",
        "--skip-git-repo-check",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "-s",
        "read-only",
        "--disable",
        "shell_tool",
        "--disable",
        "unified_exec",
        "--disable",
        "apps",
        "--disable",
        "plugins",
        "--disable",
        "browser_use",
        "--disable",
        "computer_use",
        "--disable",
        "image_generation",
        "--disable",
        "in_app_browser",
        # No image reading, no subagents, goals or sleep, no web search. The
        # code-mode host stays: Codex 0.171 reaches MCP tools through it (a
        # probe with it disabled listed no callable MCP tool).
        "--disable",
        "view_image",
        "--disable",
        "multi_agent",
        "--disable",
        "goals",
        "--disable",
        "sleep_tool",
        "-c",
        'web_search="disabled"',
        "-c",
        f'mcp_servers.{server}.command="{command}"',
        "-c",
        f"mcp_servers.{server}.args={json.dumps(args)}",
        "-c",
        f"mcp_servers.{server}.tool_timeout_sec=330",
        "-c",
        f'mcp_servers.{server}.default_tools_approval_mode="approve"',
        # No AGENTS.md or other project document reaches the model.
        "-c",
        "project_doc_max_bytes=0",
        "-C",
        str(client_cwd()),
        "--json",
        "-",
    ], True


def client_cwd() -> Path:
    """The clients' working directory: outside every home directory, so no
    CLAUDE.md or AGENTS.md of a parent directory is found."""
    return RUN / "client-cwd"


CLIENT_ENV = {
    "claude": {
        "DISABLE_AUTOUPDATER": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1",
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
        "CLAUDE_CODE_DISABLE_BUNDLED_SKILLS": "1",
        "MCP_TOOL_TIMEOUT": "330000",
    },
    "codex": {},
}


def fill(template: str, values: dict) -> str:
    for key, value in values.items():
        template = template.replace("{" + key + "}", str(value))
    left = re.findall(r"\{[A-Z_]+\}", template)
    if left:
        raise ValueError(f"unfilled placeholders {left}")
    return template


def prompt_for(role: str, name: str, values: dict) -> str:
    common = (HERE / "prompts" / f"{role}-common.prompt").read_text()
    body = (HERE / "prompts" / f"{name}.prompt").read_text()
    return fill(common + body, values)


def purchase(x: str, label: str) -> dict:
    return state["assignments"][x]["purchases"].get(label) or {}


def offer_values(x: str) -> dict:
    offer = state["assignments"][x].get("offer") or fail("run provider-offer first")
    return {
        "OFFER_FILE": offer["offer_file"],
        "CAP_ID": offer["capability_id"],
        "CAP_VER": offer["capability_version"],
        "SRC": str(paths(x)["src"]),
    }


def idem(x: str, name: str) -> str:
    """A key stable for one step of one run: a step run again (after a
    client timeout, say) prepares the same purchase or action, never a
    second one."""
    wallets = state["assignments"][x].get("wallets") or fail("run prepare first")
    nonce = hashlib.sha256(json.dumps(wallets, sort_keys=True).encode()).hexdigest()[:8]
    return f"acc-{x}-{name}-{nonce}"[:64]


# Each step: the role whose client runs it, the prompt, the confirmations
# it needs (tool whose result names the action or purchase, program, kind,
# decision, protocol expectations), and the operator actions around it.
STEPS = {
    "provider-offer": {
        "role": "provider",
        "prompt": "provider-offer",
        "confirm": [
            (
                "tos_provider_offer_preview",
                "provider",
                "offer",
                "confirm",
                {
                    "Network": NETWORK_LABEL,
                    "Price per call": "(100000000 nanoTOS)",
                    "Storage fee": "(200000000 nanoTOS)",
                    "Cleanup bounty": "(100000000 nanoTOS)",
                },
            )
        ],
        "finish": "provider-offer-finish",
        "finish_kind": "offer",
    },
    "buy-r1-across-switch": {
        "role": "buyer",
        "prompt": "buyer-buy",
        "label": "R1",
        "before": "stop_provider_agent",
        "after": "switch_then_start_agent",
        "confirm": [("tos_buyer_prepare", "buyer", "", "confirm", {})],
    },
    "result-r1": {"role": "buyer", "prompt": "buyer-result", "label": "R1", "before": "wait_responded"},
    "records-acked": {
        "role": "provider",
        "prompt": "provider-records",
        "extra": "Say whether the record of every answered request reads acked.",
    },
    "buy-r2": {
        "role": "buyer",
        "prompt": "buyer-buy",
        "label": "R2",
        "before": "require_switch",
        "confirm": [("tos_buyer_prepare", "buyer", "", "confirm", {})],
    },
    "result-r2": {"role": "buyer", "prompt": "buyer-result", "label": "R2", "before": "wait_responded"},
    "pause-for-refund": {"role": "provider", "prompt": "provider-pause", "reason": "refund scenario: hold new calls"},
    "buy-f-paused": {
        "role": "buyer",
        "prompt": "buyer-buy",
        "label": "F",
        "confirm": [("tos_buyer_prepare", "buyer", "", "confirm", {})],
    },
    "status-f-refunded": {"role": "buyer", "prompt": "buyer-status", "label": "F", "before": "wait_refunded"},
    "resume-own": {"role": "provider", "prompt": "provider-resume", "after": "expect_resumed"},
    "resume-operator": {
        "role": "provider",
        "prompt": "provider-resume",
        "before": "operator_pause",
        "confirm": [("tos_provider_resume", "provider", "resume", "confirm", {"Marker origin": "operator"})],
        "finish": "provider-resume-finish",
        "finish_kind": "resume",
        "after": "expect_resumed",
    },
    "pause-stacked": {
        "role": "provider",
        "prompt": "provider-pause",
        "reason": "stacked pause: model first",
        "after": "operator_pause_stacked",
    },
    "resume-stacked": {
        "role": "provider",
        "prompt": "provider-resume",
        "confirm": [("tos_provider_resume", "provider", "resume", "confirm", {"Marker origin": "operator"})],
        "finish": "provider-resume-finish",
        "finish_kind": "resume",
        "after": "expect_resumed",
    },
    "withdraw": {
        "role": "provider",
        "prompt": "provider-withdraw",
        "before": "balances_before_withdraw",
        "confirm": [("tos_provider_withdraw_preview", "provider", "withdraw", "confirm", {"Network": NETWORK_LABEL})],
        "finish": "provider-withdraw-finish",
        "finish_kind": "withdraw",
        "after": "withdrawal_facts",
    },
    "records-final": {
        "role": "provider",
        "prompt": "provider-records",
        "extra": "Also call tos_provider_actions with page_size 20 and report each action's kind and state.",
    },
}
ORDER = list(STEPS)


def step_values(x: str, name: str, spec: dict) -> dict:
    values = {"LABEL": f"{x}-{name}"}
    if spec["prompt"] == "buyer-buy":
        values.update(offer_values(x))
        values["IDEM"] = idem(x, name)
    elif spec["prompt"] in ("buyer-result", "buyer-status"):
        values["REQUEST_HASH"] = purchase(x, spec["label"]).get("request_hash") or fail(f"no purchase {spec['label']}")
    elif spec["prompt"] in ("provider-offer", "provider-resume", "provider-withdraw"):
        values["IDEM"] = idem(x, name)
    elif spec["prompt"] == "provider-pause":
        values["REASON"] = spec["reason"]
    elif spec["prompt"] == "provider-records":
        values["EXTRA"] = spec.get("extra", "")
    return values


ID_PATTERNS = {
    "provider": re.compile(r'action_id\\*"\s*:\s*\\*"([A-Za-z0-9_-]{16,128})'),
    "buyer": re.compile(r'request_hash\\*"\s*:\s*\\*"([0-9a-f]{64})'),
}


def reference(identifier: str) -> str:
    return "-".join(identifier[i : i + 4] for i in range(0, 16, 4))


def tool_results(event_value, names: dict) -> list:
    """(tool name, result text) pairs found in one client event: Claude's
    tool_use / tool_result pairs and Codex's MCP tool call items."""
    found = []
    if isinstance(event_value, dict):
        if event_value.get("type") == "tool_use" and event_value.get("id"):
            names[event_value["id"]] = str(event_value.get("name", ""))
        if event_value.get("type") == "tool_result" and event_value.get("tool_use_id") in names:
            found.append((names[event_value["tool_use_id"]], json.dumps(event_value.get("content"))))
        # A Codex item that has started carries "result": null; only its
        # completed form counts.
        if "tool" in event_value and (event_value.get("result") is not None or event_value.get("output") is not None):
            found.append((str(event_value["tool"]), json.dumps(event_value.get("result", event_value.get("output")))))
        for value in event_value.values():
            found += tool_results(value, names)
    elif isinstance(event_value, list):
        for value in event_value:
            found += tool_results(value, names)
    return found


def run_confirmer(x: str, program: str, identifier: str, kind: str, decision: str, expect: dict) -> dict:
    p = paths(x)
    account = PROVIDER if program == "provider" else BUYER
    binary = BIN / ("tos-service-provider" if program == "provider" else "tos-service-buyer")
    socket = p["provider_socket"] if program == "provider" else p["buyer_socket"]
    argv = [
        "/usr/bin/python3",
        "-I",
        HERE / "custody_confirm.py",
        "--program",
        program,
        "--binary",
        binary,
        "--socket",
        socket,
        "--reference",
        reference(identifier),
        "--decision",
        decision,
        "--timeout",
        "900",
    ]
    if kind:
        argv += ["--kind", kind]
    for label, text in expect.items():
        argv += ["--expect", f"{label}={text}"]
    result = run_as(account, argv, check=False, timeout=960)
    outcome = last_json(result.stdout) or {"error": redact(result.stderr[-500:])}
    outcome.update(
        {
            "assignment": x,
            "identifier": identifier,
            "exit": result.returncode,
            "at": now(),
            "confirmer": f"{binary.name} confirm --watch",
            "account_role": f"{program} custody",
        }
    )
    state["confirmations"].append(outcome)
    save()
    return outcome


def confirm_into(results: list, x: str, trigger: tuple, identifier: str) -> None:
    """A confirmer thread: decide the action or purchase the trigger names."""
    _, program, kind, decision, expect = trigger
    results.append(run_confirmer(x, program, identifier, kind, decision, expect))


def run_session(x: str, name: str, finish: dict | None = None) -> dict:
    """One model session of a step. With finish ({"ACTION_ID", ...}), the
    step's continuation: the action was confirmed and has been applied, and
    the session reads its outcome and does the rest of the task."""
    spec = STEPS[name]
    role = spec["role"]
    client = ASSIGNMENTS[x][f"{role}_client"]
    if finish:
        prompt = prompt_for(role, spec["finish"], {**step_values(x, name, spec), **finish})
    else:
        prompt = prompt_for(role, spec["prompt"], step_values(x, name, spec))
    template, on_stdin = client_command(client, x, role)
    argv = [prompt if part == "{PROMPT}" else part for part in template]
    client_cwd().mkdir(mode=0o700, exist_ok=True)
    command = as_cmd(DEVELOPER, argv, extra_env=CLIENT_ENV[client], chdir=client_cwd())
    index = len(state["sessions"]) + 1
    transcript = TRANSCRIPTS / f"{index:02d}-{x}-{name}{'-finish' if finish else ''}-{client}.jsonl"
    TRANSCRIPTS.mkdir(mode=0o700, parents=True, exist_ok=True)
    started = now()
    names: dict = {}
    pending = [] if finish else list(spec.get("confirm", []))
    confirmers: list = []
    seen_ids: dict = {}
    # stderr goes to a file: a client that writes much to it can never block
    # on a full pipe while this loop reads stdout.
    stderr_path = transcript.with_suffix(".stderr")
    stderr_file = stderr_path.open("w")
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr_file, text=True, cwd="/"
    )
    if on_stdin:
        process.stdin.write(prompt)
    process.stdin.close()
    with transcript.open("w") as handle:
        for line in process.stdout:
            handle.write(redact(line))
            handle.flush()
            try:
                value = json.loads(line)
            except ValueError:
                continue
            for tool, text in tool_results(value, names):
                for trigger in list(pending):
                    if not tool.endswith(trigger[0]):
                        continue
                    found = ID_PATTERNS[trigger[1]].search(text)
                    if not found:
                        continue
                    pending.remove(trigger)
                    if trigger[1] == "provider" and "awaiting_confirmation" not in text:
                        # The same key returned an action already decided
                        # (a step run again): nothing to confirm.
                        seen_ids[trigger[0]] = found.group(1)
                        continue
                    seen_ids[trigger[0]] = found.group(1)
                    thread = threading.Thread(
                        target=confirm_into, args=(confirmers, x, trigger, found.group(1)), daemon=True
                    )
                    thread.start()
                    confirmers.append(thread)
    status = process.wait(timeout=120)
    stderr_file.close()
    stderr = redact(stderr_path.read_text())
    stderr_path.write_text(stderr)
    for item in list(confirmers):
        if isinstance(item, threading.Thread):
            item.join(timeout=960)
    answer = last_json(_final_text(transcript, client))
    tools_called = [tool for tool, _ in _calls(transcript)]
    unexpected = unexpected_tools(transcript, client, server_name(role))
    session = {
        "unexpected_tool_use": unexpected,
        "assignment": x,
        "step": name,
        "finish": bool(finish),
        "role": role,
        "client": client,
        "started_utc": started,
        "finished_utc": now(),
        "exit": status,
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "transcript": str(transcript.relative_to(RUN)),
        "transcript_sha256": sha256_file(transcript),
        "tool_calls": tools_called,
        "answer": answer,
        "identifiers": seen_ids,
        "unconfirmed_triggers": [t[0] for t in pending],
        "stderr_tail": redact(stderr[-600:]),
        "models": _models(transcript, client),
    }
    (PRIVATE / "prompts").mkdir(mode=0o700, exist_ok=True)
    (PRIVATE / "prompts" / f"{index:02d}-{x}-{name}.txt").write_text(prompt)
    state["sessions"].append(session)
    save()
    return session


CODEX_ITEMS_ALLOWED = {"agent_message", "reasoning", "mcp_tool_call", "error", "todo_list"}


def unexpected_tools(transcript: Path, client: str, server: str) -> list:
    """Every tool use other than the role's own MCP server: for Claude Code a
    tool_use not named mcp__<server>__*, for Codex an item that is not a
    message, reasoning, error or a call to that server. Any entry stops the
    assignment."""
    found = []

    def walk(value):
        if isinstance(value, dict):
            if value.get("type") == "tool_use" and not str(value.get("name", "")).startswith(f"mcp__{server}__"):
                found.append({"tool_use": value.get("name")})
            for inner in value.values():
                walk(inner)
        elif isinstance(value, list):
            for inner in value:
                walk(inner)

    for event_value in _events(transcript):
        if client == "claude":
            walk(event_value)
            continue
        item = event_value.get("item") if str(event_value.get("type", "")).startswith("item.") else None
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind not in CODEX_ITEMS_ALLOWED or (kind == "mcp_tool_call" and item.get("server") != server):
            found.append({"item": kind, "server": item.get("server"), "tool": item.get("tool")})
    return found


def _events(transcript: Path) -> list:
    out = []
    for line in transcript.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _calls(transcript: Path) -> list:
    names: dict = {}
    calls = []
    for value in _events(transcript):
        calls += tool_results(value, names)
    return calls


def _final_text(transcript: Path, client: str) -> str:
    events = _events(transcript)
    if client == "claude":
        final = next((e for e in reversed(events) if e.get("type") == "result"), {})
        return final.get("result") or ""
    texts = [json.dumps(e) for e in events if "agent_message" in json.dumps(e)]
    if not texts:
        return ""
    last = json.loads(texts[-1])
    item = last.get("item") or last.get("msg") or {}
    return item.get("text") or item.get("message") or ""


def _models(transcript: Path, client: str) -> list:
    models = set()
    for value in _events(transcript):
        if client == "claude" and value.get("type") == "system" and value.get("model"):
            models.add(value["model"])
        if client == "codex" and isinstance(value.get("model"), str):
            models.add(value["model"])
    return sorted(models)


# --- operator actions (permitted custody-side commands, section 3.1) ------------------------


def operator(x: str, action: str, **detail) -> dict:
    p = paths(x)
    exe = BIN / "tos-service-provider"
    if action in ("pause", "resume"):
        argv = [exe, action, "--rail-config", p["rail_config"]]
        if action == "pause":
            argv += ["--reason", detail.get("reason", "operator stop")]
        result = run_as(PROVIDER, argv, vault=True, check=False)
        outcome = {"exit": result.returncode, "report": last_json(result.stdout)}
    elif action in ("stop-agent", "start-agent"):
        result = user_systemctl(
            PROVIDER, "stop" if action == "stop-agent" else "start", p["provider_unit"], check=False
        )
        outcome = {"exit": result.returncode}
    else:
        raise ValueError(action)
    entry = {
        "at": now(),
        "action": action,
        "command_kind": "permitted custody-side command (section 3.1)",
        **detail,
        **outcome,
    }
    state["assignments"][x]["operator"].append(entry)
    event(f"operator {action} {x}", **{k: v for k, v in entry.items() if k != "at"})
    return entry


def pause_marker(x: str) -> dict | None:
    text = read_as(PROVIDER, paths(x)["rail_state"] / "admission-paused", check=False)
    try:
        return json.loads(text)
    except ValueError:
        return None


def actor_of(x: str) -> str:
    return (state["assignments"][x].get("offer") or {}).get("actor") or fail("no actor recorded")


def request_call(x: str, label: str) -> dict | None:
    """The finalized call of a purchase at the actor: the buyer wallet's
    call transaction, recorded with the request hash the buyer prepared."""
    buyer_wallet = state["assignments"][x]["wallets"][f"buyer-{x}"]
    read = chain.transactions(actor_of(x))
    if not read:
        return None
    known = {purchase(x, other).get("call_lt") for other in state["assignments"][x]["purchases"]}
    calls = [
        tx
        for tx in chain.inbound(read["value"], chain.CALL_OPCODE, buyer_wallet)
        if not tx["aborted"] and tx["lt"] not in known
    ]
    return min(calls, key=lambda tx: tx["lt"]) if calls else None


def hook(x: str, name: str, which: str) -> None:
    spec = STEPS[name]
    action = spec.get(which)
    a = state["assignments"][x]
    if action is None:
        return
    if action == "stop_provider_agent":
        a["switch_set_before"] = chain.validator_set()
        operator(x, "stop-agent", why="hold the paid request pending at the provider across a validator-set switch")
    elif action == "switch_then_start_agent":
        label = spec["label"]
        call = poll(lambda: request_call(x, label), 600, 10) or fail(f"{label}'s call is not finalized at the actor")
        a["purchases"][label]["call_lt"], a["purchases"][label]["call_hash"] = call["lt"], call["hash"]
        a["purchases"][label]["call_utime"] = call["utime"]
        save()
        # The set the call was finalized under: read now, after the call, so
        # a switch between the agent's stop and the payment cannot count.
        before = chain.validator_set() or fail("no strict-majority read of the validator set")
        if call["utime"] >= before["utime_until"]:
            fail("the call's set has already expired; run the step again")

        def changed():
            view = chain.validator_set()
            if not view or view["config34_cell_hash"] == before["config34_cell_hash"]:
                return None
            left = set(chain.membership(before)) - set(chain.membership(view))
            joined = set(chain.membership(view)) - set(chain.membership(before))
            return view if left and joined else None

        after = poll(changed, 1500, 15) or fail("no membership-changing validator-set switch within 25 minutes")
        switch = {
            "assignment": x,
            "before": before,
            "after": after,
            "left": sorted(set(chain.membership(before)) - set(chain.membership(after))),
            "joined": sorted(set(chain.membership(after)) - set(chain.membership(before))),
            "took_effect": first_block_with_set(
                before["observed_at_seqno"], after["observed_at_seqno"], after["config34_cell_hash"]
            ),
            "requests_pending_across": [{"label": label, "call": {"lt": call["lt"], "hash": call["hash"]}}],
        }
        state["switches"].append(switch)
        operator(x, "start-agent", why="the switch has taken effect; the provider admits the pending request")
        event(
            f"validator-set switch {x}", left=switch["left"], joined=switch["joined"], took_effect=switch["took_effect"]
        )
    elif action == "require_switch":
        if not any(s["assignment"] == x for s in state["switches"]):
            fail("run buy-r1-across-switch first: R2 must run entirely after the switch")
    elif action == "wait_responded":
        label = spec["label"]
        entry = purchase(x, label)
        if "call_lt" not in entry:
            call = poll(lambda: request_call(x, label), 600, 10) or fail(f"{label}'s call is not finalized")
            entry["call_lt"], entry["call_hash"] = call["lt"], call["hash"]
        responded = poll(
            lambda: [
                tx
                for tx in chain.inbound(
                    (chain.transactions(actor_of(x)) or {"value": []})["value"], chain.RESPOND_OPCODE
                )
                if tx["lt"] > entry["call_lt"] and not tx["aborted"]
            ],
            3000,
            20,
        )
        if not responded:
            fail(f"{label} was not responded")
        entry["respond_seen"] = [{"lt": tx["lt"], "hash": tx["hash"], "utime": tx["utime"]} for tx in responded]
        call = next(
            (tx for tx in (chain.transactions(actor_of(x)) or {"value": []})["value"] if tx["lt"] == entry["call_lt"]),
            None,
        )
        entry["call_utime"] = call and call["utime"]
        save()
        # The buyer agent accepts the result after fetching it from the
        # relay and then acks it; the provider's own record reading acked
        # (custody file, read as the provider custody) shows that happened,
        # so the model's result session does not start too early.
        acked = poll(lambda: provider_record_state(x, entry["request_hash"]) == "acked", 900, 15)
        entry["provider_record_before_result_session"] = provider_record_state(x, entry["request_hash"])
        save()
        if not acked:
            fail(f"{label}: the provider's record did not reach acked within 15 minutes")
    elif action == "wait_refunded":
        label = spec["label"]
        entry = purchase(x, label)
        if "call_lt" not in entry:
            call = poll(lambda: request_call(x, label), 600, 10) or fail(f"{label}'s call is not finalized")
            entry["call_lt"], entry["call_hash"] = call["lt"], call["hash"]
        buyer_wallet = a["wallets"][f"buyer-{x}"]

        def refunded():
            txs = (chain.transactions(actor_of(x)) or {"value": []})["value"]
            later = [tx for tx in txs if tx["lt"] > entry["call_lt"] and not tx.get("aborted")]
            expires = chain.inbound(later, chain.EXPIRE_OPCODE)
            claims = chain.inbound(later, chain.CLAIM_REFUND_OPCODE, buyer_wallet)
            responds = chain.inbound(later, chain.RESPOND_OPCODE)
            return {"expires": expires, "claims": claims, "responds": responds} if expires and claims else None

        found = poll(refunded, WINDOW * 2 + 1200, 60) or fail(f"{label} was not refunded")
        entry["refund_seen"] = {
            k: [{"lt": tx["lt"], "hash": tx["hash"], "paid_to_buyer": chain.paid_to(tx, buyer_wallet)} for tx in v]
            for k, v in found.items()
        }
        save()
    elif action == "operator_pause":
        operator(x, "pause", reason="operator stop before the model's resume")
        a["pauses"].append({"at": now(), "origin_expected": "operator", "marker": pause_marker(x), "by": "operator"})
    elif action == "operator_pause_stacked":
        model_marker = pause_marker(x)
        operator(x, "pause", reason="operator stop stacked on the model's pause")
        stacked = pause_marker(x)
        a["pauses"].append(
            {
                "at": now(),
                "by": "operator over model",
                "marker_before": model_marker,
                "marker_after": stacked,
                "restamped": bool(model_marker and stacked and model_marker.get("stamp") != stacked.get("stamp")),
                "first_paused_unix_kept": bool(
                    model_marker and stacked and model_marker.get("paused_unix") == stacked.get("paused_unix")
                ),
                "origin_after": (stacked or {}).get("origin"),
            }
        )
    elif action == "expect_resumed":
        a["pauses"].append({"at": now(), "event": f"after {name}", "marker": pause_marker(x)})
    elif action == "balances_before_withdraw":
        wallet = a["wallets"][f"provider-{x}"]
        a["withdraw_before"] = {
            "wallet_balance_nanotos": chain.balance(wallet),
            "actor": actor_of(x),
            "actor_balance_nanotos": chain.balance(actor_of(x)),
            "actor_service_data": chain.service_data(actor_of(x)),
        }
    elif action == "withdrawal_facts":
        wallet = a["wallets"][f"provider-{x}"]

        def withdrawn():
            read = chain.transactions(actor_of(x))
            if not read:
                return None
            found = [tx for tx in chain.inbound(read["value"], chain.WITHDRAW_OPCODE, wallet) if not tx["aborted"]]
            return (read, found) if found else None

        read, withdrawals = poll(withdrawn, 600, 10) or ({"value": []}, [])
        a["withdraw_after"] = {
            "withdraw_transactions": [
                {"lt": tx["lt"], "hash": tx["hash"], "sent_to_wallet_nanotos": chain.paid_to(tx, wallet)}
                for tx in withdrawals
            ],
            # Read once the payout has reached the wallet.
            "wallet_balance_nanotos": poll(
                lambda: (lambda b: b if b and b > (a["withdraw_before"]["wallet_balance_nanotos"] or 0) else None)(
                    chain.balance(wallet)
                ),
                300,
                10,
            ),
            "actor_service_data": chain.service_data(actor_of(x)),
            "agreeing": read.get("agreeing"),
            "of": read.get("of"),
        }
    save()


def first_block_with_set(low: int, high: int, cell_hash: str) -> dict:
    """The first masterchain block whose Config34 is the new set, by binary
    search between a block that held the old set and one that holds the new
    one, each probe a strict-majority read."""
    from pytosiq_core import Cell
    import base64

    def holds(seqno: int) -> bool | None:
        read = chain.majority("getConfigParam", lambda r: r["config"]["bytes"], timeout=30, param=34, seqno=seqno)
        if read is None:
            return None
        return Cell.one_from_boc(base64.b64decode(read["value"])).hash.hex() == cell_hash

    while high - low > 1:
        middle = (low + high) // 2
        answer = holds(middle)
        if answer is None:
            return {"seqno_between": [low, high], "exact": False}
        low, high = (low, middle) if answer else (middle, high)
    header = chain.majority(
        "getBlockHeader",
        lambda r: {"utime": int(r.get("gen_utime") or 0), "root_hash": r["id"]["root_hash"]},
        timeout=30,
        workchain=-1,
        shard=chain.MASTERCHAIN_SHARD,
        seqno=high,
    )
    return {"seqno": high, "exact": True, "header": header and header["value"]}


def provider_record_state(x: str, request_hash: str) -> str | None:
    """The state of the provider node's own record of a request (records are
    named by slot, so found by the request hash they hold)."""
    directory = paths(x)["rail_state"] / "provider"
    listed = run_as(PROVIDER, ["/usr/bin/find", directory, "-maxdepth", "1", "-name", "*.json"], check=False)
    for name in listed.stdout.split():
        try:
            entry = json.loads(read_as(PROVIDER, name, check=False))
        except ValueError:
            continue
        if entry.get("request_hash") == request_hash:
            return entry.get("state")
    return None


def wait_applied(x: str, kind: str) -> None:
    """Wait, from custody and chain reads, until a confirmed action's effect
    is in place: the offer's actor in the operator's status, the marker gone
    for a resume, the withdraw_revenue at the actor for a withdrawal."""
    p = paths(x)

    def offered():
        status = (
            last_json(
                run_as(
                    PROVIDER,
                    [BIN / "tos-service-provider", "status", "--rail-config", p["rail_config"]],
                    vault=True,
                    check=False,
                ).stdout
            )
            or {}
        )
        return ((status.get("actor") or {}).get("address") or "") != ""

    def resumed():
        return (
            run_as(PROVIDER, ["/usr/bin/test", "-e", p["rail_state"] / "admission-paused"], check=False).returncode == 1
        )

    def withdrawn():
        wallet = state["assignments"][x]["wallets"][f"provider-{x}"]
        read = chain.transactions(actor_of(x))
        before = {t["hash"] for t in (state["assignments"][x].get("withdraw_before") or {}).get("withdrawals", [])}
        return read and [
            t
            for t in chain.inbound(read["value"], chain.WITHDRAW_OPCODE, wallet)
            if not t["aborted"] and t["hash"] not in before
        ]

    check = {"offer": offered, "resume": resumed, "withdraw": withdrawn}[kind]
    if not poll(check, 1800, 15):
        fail(f"the confirmed {kind} did not take effect within 30 minutes")
    # The agent records the outcome after the effect; give it a moment.
    time.sleep(20)


def cmd_step(x: str, name: str, finish_action: str | None = None) -> None:
    """One step. With finish_action, only the continuation of an action an
    earlier session of this step had confirmed and left applying."""
    if name not in STEPS:
        fail(f"unknown step {name}; steps: {', '.join(ORDER)}")
    a = state["assignments"][x]
    done = a["steps_done"]
    position = ORDER.index(name)
    missing = [s for s in ORDER[:position] if s not in done]
    if missing:
        fail(f"steps before {name} have not run: {missing}")
    spec = STEPS[name]
    if finish_action:
        if not spec.get("finish") or not any(
            c.get("identifier") == finish_action and c.get("typed") == "code" for c in state["confirmations"]
        ):
            fail(f"{finish_action} is not an action this run confirmed for a step with a continuation")
        session = {"unexpected_tool_use": [], "unconfirmed_triggers": [], "exit": 0, "identifiers": {}}
        answer = {"state": "applying", "action_id": finish_action, "action_reference": reference(finish_action)}
    else:
        hook(x, name, "before")
        session = run_session(x, name)
        answer = session.get("answer") or {}
    if session["unexpected_tool_use"]:
        fail(
            f"step {name}: the {session['client']} client used tools outside its MCP server "
            f"{session['unexpected_tool_use']}; the assignment stops; see {session['transcript']}"
        )
    # A confirmed action's send can outlast every request_confirmation the
    # session may make (the tool answers at once while the action applies).
    # The driver then waits for the applied effect itself and starts a
    # continuation session that reads the outcome and finishes the task.
    if spec.get("finish") and answer.get("state") == "applying" and answer.get("action_id"):
        wait_applied(x, spec["finish_kind"])
        session = run_session(
            x, name, {"ACTION_ID": answer["action_id"], "ACTION_REFERENCE": answer.get("action_reference", "")}
        )
        if session["unexpected_tool_use"]:
            fail(
                f"step {name}: the {session['client']} client used tools outside its MCP server "
                f"{session['unexpected_tool_use']}; the assignment stops; see {session['transcript']}"
            )
        answer = {**answer, **(session.get("answer") or {})}
    if spec["prompt"] == "provider-offer" and answer.get("capability_id"):
        offer_file = answer.get("offer_file", "")
        text = read_as(DEVELOPER, offer_file)
        offer = json.loads(text)
        # The actor's address only: the operator's own `status` (a permitted
        # custody-side command) names it; every fact about it is then read
        # from the chain, and the record checks the address there too.
        status = (
            last_json(
                run_as(
                    PROVIDER,
                    [BIN / "tos-service-provider", "status", "--rail-config", paths(x)["rail_config"]],
                    vault=True,
                    check=False,
                ).stdout
            )
            or {}
        )
        a["offer"] = {
            "capability_id": answer["capability_id"],
            "capability_version": answer.get("capability_version"),
            "offer_file": offer_file,
            "offer_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "actor": ((status.get("actor") or {}).get("address") or "").lower(),
            "provider_agent_id": offer.get("provider_agent_id"),
            "manifest_digest": offer.get("manifest_digest"),
            "offer_schema": offer.get("schema"),
        }
        (PUBLIC / "offers").mkdir(mode=0o755, exist_ok=True)
        (PUBLIC / "offers" / f"{x}-{Path(offer_file).name}").write_text(text)
    if spec["prompt"] == "buyer-buy" and answer.get("request_hash"):
        a["purchases"].setdefault(spec["label"], {})["request_hash"] = answer["request_hash"]
        # The request hash the model reported must be the one its prepare
        # result named, which is the one the confirmer was driven for.
        if session["identifiers"].get("tos_buyer_prepare") != answer["request_hash"]:
            save()
            fail(f"step {name}: the reported request_hash is not the prepared one")
    if spec["prompt"] == "buyer-result" and answer.get("accepted") is not True:
        save()
        fail(f"step {name}: the buyer agent has not accepted the result yet; run the step again shortly")
    if spec.get("finish") and spec["finish_kind"] != "resume" and answer.get("state") != "applied":
        save()
        fail(f"step {name}: the action ends {answer.get('state')!r}, not applied; see {session['transcript']}")
    if spec["prompt"] == "provider-offer" and not a.get("offer"):
        save()
        fail(f"step {name}: no exported offer; see {session['transcript']}")
    if session["unconfirmed_triggers"] or session["exit"] != 0:
        save()
        fail(
            f"step {name}: exit {session['exit']}, unconfirmed {session['unconfirmed_triggers']}; see "
            f"{session['transcript']}"
        )
    hook(x, name, "after")
    done.append(name)
    event(f"step {x} {name}", client=session["client"], tool_calls=session["tool_calls"], answer=answer)


def cmd_commands(x: str) -> None:
    """Every client command of the assignment, with its prompt, as the
    coordinator would start it by hand (the step command does the same)."""
    for name in ORDER:
        spec = STEPS[name]
        role = spec["role"]
        client = ASSIGNMENTS[x][f"{role}_client"]
        try:
            values = step_values(x, name, spec)
        except SystemExit:
            values = {
                "LABEL": f"{x}-{name}",
                "IDEM": "<fresh key>",
                "REQUEST_HASH": "<from the buy step>",
                "OFFER_FILE": "<from provider-offer>",
                "CAP_ID": "<from provider-offer>",
                "CAP_VER": "<from provider-offer>",
                "SRC": str(paths(x)["src"]),
                "REASON": spec.get("reason", ""),
                "EXTRA": spec.get("extra", ""),
            }
        try:
            prompt = prompt_for(role, spec["prompt"], values)
        except ValueError:
            prompt = "(prompt needs earlier results)"
        template, on_stdin = client_command(client, x, role)
        argv = ["<prompt>" if part == "{PROMPT}" else part for part in template]
        command = as_cmd(DEVELOPER, argv, extra_env=CLIENT_ENV[client], chdir=client_cwd())
        print(
            f"### {x} {name}: {client} operates the {role}"
            + (f"; before: {spec['before']}" if spec.get("before") else "")
            + (f"; after: {spec['after']}" if spec.get("after") else "")
        )
        print(" ".join(shlex.quote(part) for part in command) + (" < prompt" if on_stdin else ""))
        for trigger in spec.get("confirm", []):
            print(
                f"#   confirmer: {trigger[1]} custody confirms the {trigger[2] or 'purchase'} named by "
                f"{trigger[0]}'s result, on its own pty (custody_confirm.py)"
            )
        print("--- prompt ---")
        print(prompt)
        print()


def cmd_status(x: str) -> None:
    a = state["assignments"][x]
    done = a["steps_done"]
    print(
        json.dumps(
            {
                "done": done,
                "next": next((s for s in ORDER if s not in done), None),
                "purchases": a["purchases"],
                "offer": a.get("offer"),
                "operator": a["operator"][-5:],
            },
            indent=2,
        )
    )


# --- evidence, verify, record ---------------------------------------------------------------


def cmd_evidence(x: str) -> None:
    p = paths(x)
    out = PUBLIC / "evidence" / x
    out.mkdir(mode=0o755, parents=True, exist_ok=True)
    exports = {}
    for label, entry in state["assignments"][x]["purchases"].items():
        target = p["buyer_evidence"] / f"{x}-{label}"
        if run_as(BUYER, ["/usr/bin/test", "-e", target], check=False).returncode != 0:
            run_as(
                BUYER,
                [
                    BIN / "tos-service-buyer",
                    "evidence",
                    "--config",
                    p["buyer_config"],
                    "--request-hash",
                    entry["request_hash"],
                    "--out-dir",
                    target,
                ],
                timeout=900,
            )
        files = {}
        for name in ("evidence.json", "receipt.boc", "artifact.tar"):
            encoded = run_as(BUYER, ["/usr/bin/base64", "-w0", target / name], check=False)
            if encoded.returncode == 0:
                import base64

                data = base64.b64decode(encoded.stdout)
                (out / label).mkdir(mode=0o755, exist_ok=True)
                (out / label / name).write_bytes(data)
                files[name] = hashlib.sha256(data).hexdigest()
        exports[label] = {"request_hash": entry["request_hash"], "files": files}
    state["assignments"][x]["evidence"] = exports
    event(f"evidence {x}", exports=exports)


def cmd_verify() -> None:
    source = RUN / "verify-clone"
    if not source.exists():
        subprocess.run(["git", "clone", "--quiet", "https://github.com/tosnetwork/ai.git", str(source)], check=True)
        subprocess.run(["git", "-C", str(source), "checkout", "--quiet", "--detach", AI_COMMIT], check=True)
    head = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    if head != AI_COMMIT:
        fail(f"the verifier clone is at {head}")
    env = {**os.environ, "GOWORK": "off", "CGO_ENABLED": "0", "GOTOOLCHAIN": "go1.26.11"}
    subprocess.run(
        ["go", "build", "-trimpath", "-o", "out/", "./protocol/cmd/tos-service-verify"], cwd=source, env=env, check=True
    )
    verify = source / "out" / "tos-service-verify"
    results = []
    for x in ASSIGNMENTS:
        for label, export in (state["assignments"][x].get("evidence") or {}).items():
            folder = PUBLIC / "evidence" / x / label
            argv = [
                str(verify),
                "--global-config",
                str(PUBLIC / "global-config.json"),
                "--network-id",
                NETWORK_LABEL,
                "--rpc",
                ",".join(chain.endpoints()),
                "--registry-code-boc",
                str(PUBLIC / "registry-code.boc"),
                "--registry-code-hash",
                REGISTRY_CODE_HASH,
                "--actor-code-hash",
                ACTOR_CODE_HASH,
                "--evidence",
                str(folder / "evidence.json"),
            ]
            if (folder / "receipt.boc").exists():
                argv += ["--receipt", str(folder / "receipt.boc"), "--artifact", str(folder / "artifact.tar")]
            done = subprocess.run(argv, capture_output=True, text=True, timeout=600)
            (folder / "verdict.json").write_text(done.stdout)
            verdict = last_json(done.stdout) or {}
            results.append(
                {
                    "assignment": x,
                    "label": label,
                    "request_hash": export["request_hash"],
                    "exit": done.returncode,
                    "verdict": verdict.get("verdict") or verdict.get("result"),
                    "verdict_sha256": hashlib.sha256(done.stdout.encode()).hexdigest(),
                    "checkpoint": verdict.get("checkpoint"),
                }
            )
    state["verifier"] = {
        "tool_commit": head,
        "built_from": "fresh clone of https://github.com/tosnetwork/ai",
        "binary_sha256": sha256_file(verify),
        "quorum": "every endpoint given (default)",
        "endpoints": chain.endpoints(),
        "results": results,
        "at": now(),
    }
    event("verified", results=results)


def cmd_record() -> None:
    import record as record_builder

    out = RUN / "record"
    out.mkdir(mode=0o755, exist_ok=True)
    document = record_builder.build(
        state,
        RUN,
        {
            "ai_commit": AI_COMMIT,
            "network_label": NETWORK_LABEL,
            "actor_code_hash": ACTOR_CODE_HASH,
            "registry_code_hash": REGISTRY_CODE_HASH,
            "install": installed(),
            "build": json.loads((RUN / "bin" / "build.json").read_text()),
            "tos_root": TOS_ROOT,
            "harness_commit": subprocess.run(
                ["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True
            ).stdout.strip(),
            "harness_clean": not subprocess.run(
                ["git", "-C", str(REPO), "status", "--porcelain", "--untracked-files=no", "--", str(HERE)],
                capture_output=True,
                text=True,
            ).stdout.strip(),
            "openfox_scan": openfox_scan(),
            "developer_is_operator": DEVELOPER_IS_OPERATOR,
            "funding": json.loads((PUBLIC / "funding-receipts.json").read_text())
            if (PUBLIC / "funding-receipts.json").exists()
            else None,
            "uids": {
                role: uid(account)
                for role, account in (
                    ("provider_custody", PROVIDER),
                    ("buyer_custody", BUYER),
                    ("developer", DEVELOPER),
                )
            },
            "respond_fees": {
                x: chain.respond_fees(state["assignments"][x]["wallets"][f"provider-{x}"], actor_of(x))
                for x in ASSIGNMENTS
                if state["assignments"][x].get("offer")
            },
            "clients": {
                "claude": {"path": str(CLAUDE), "sha256": sha256_file(CLAUDE)},
                "codex": {"path": str(CODEX), "sha256": sha256_file(CODEX)},
            },
        },
    )
    target = out / f"local-agent-operated-provider-run-{datetime.date.today().strftime('%Y%m%d')}.json"
    target.write_text(json.dumps(document, indent=2) + "\n")
    print(target)
    print(document["verdict"])


def main() -> None:
    global state, RUN, PRIVATE, PUBLIC, TRANSCRIPTS, COMMAND, ARGS, SCOPE
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    RUN = Path(sys.argv[1]).resolve()
    COMMAND, ARGS = sys.argv[2], sys.argv[3:]
    PRIVATE, PUBLIC = RUN / "private", RUN / "public"
    TRANSCRIPTS = PRIVATE / "transcripts"
    if ARGS and ARGS[0] in ASSIGNMENTS and COMMAND in ("prepare", "init", "step", "evidence"):
        SCOPE = ARGS[0]
    state = load_state()
    if os.geteuid() == 0:
        raise SystemExit("run the driver as the operator's own account, not root")
    handlers = {"build": cmd_build, "check": cmd_check, "relay": cmd_relay, "verify": cmd_verify, "record": cmd_record}
    per_assignment = {
        "prepare": cmd_prepare,
        "init": cmd_init,
        "commands": cmd_commands,
        "status": cmd_status,
        "evidence": cmd_evidence,
    }
    if COMMAND in handlers:
        handlers[COMMAND]()
    elif COMMAND in per_assignment and ARGS and ARGS[0] in ASSIGNMENTS:
        per_assignment[COMMAND](ARGS[0])
    elif COMMAND == "step" and len(ARGS) == 2 and ARGS[0] in ASSIGNMENTS:
        cmd_step(ARGS[0], ARGS[1])
    elif COMMAND == "step" and len(ARGS) == 4 and ARGS[0] in ASSIGNMENTS and ARGS[2] == "--finish":
        cmd_step(ARGS[0], ARGS[1], ARGS[3])
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
