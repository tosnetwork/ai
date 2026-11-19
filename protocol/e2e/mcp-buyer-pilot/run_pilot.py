#!/usr/bin/env python3
"""Operator driver of the agent-operated Gate D pilot on the epoch-7 testnet.

Three role containers from one digest-pinned image (Dockerfile), each with
its own accounts, key and pilot-rpc forwards (harness/pilot.py):

- provider: OpenFox with a fresh wallet, Agent, Service Actor and
  Capability, sending jobs to the host's executor service;
- buyer: custody runs init, the agent and the automated confirmer;
  developer runs the Claude Code CLI, started here with
  `docker exec -u developer`, with no built-in tool and only the tos-buyer
  MCP tools;
- verifier: its own forwards; the Codex CLI, started here, builds
  tos-service-verify from a fresh clone and reads only the public handoff.

Model credentials (owner ruling, fallback A'): the operator's current
short-lived access tokens only, never a refresh token, in 0600 files under
RUN/secrets, given with `docker exec --env-file` to the CLI process alone,
never logged, deleted by `stop`. A token that expires mid-run stops the run.

Usage: run_pilot.py RUN_DIR start|offer|purchases|stop

  start      build the image, write the credentials, start the three
             containers; they print the wallets to fund and wait for funding
  offer      hand the provider's published offer file to the buyer
  purchases  purchases R (answered) and F (provider paused, refunded),
             withdrawal, exports, the verifier, the record and signatures
  stop       stop the containers, scan for secrets, delete the credentials

RUN_DIR holds bin/ (build.sh), keys/{provider,buyer,verifier} (pilot-rpc
ed25519 keys) and public/ (the pilot pack and validators.known_hosts).
Environment: ACTOR_CODE_HASH, REGISTRY_CODE_HASH; optional
PILOT_RESPONSE_SLA, PILOT_REFUND_WINDOW (default 3600 each; 600 only with a
test-profile actor), PILOT_MIN_TOKEN_SECONDS (default 9000).
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
if len(sys.argv) != 3:
    raise SystemExit(__doc__)
RUN = Path(sys.argv[1]).resolve()
COMMAND = sys.argv[2]
ROLES = ("provider", "buyer", "verifier")
WORKS = {role: RUN / f"{role}-c" for role in ROLES}
CONTAINERS = {role: f"gaap-{role}-{RUN.name}" for role in ROLES}
LOGS = RUN / "logs"
SECRETS = RUN / "secrets"
HANDOFF = RUN / "handoff"
RECORD = RUN / "record"
TRANSCRIPTS = WORKS["buyer"] / "control" / "transcripts"
MIN_TOKEN_SECONDS = int(os.environ.get("PILOT_MIN_TOKEN_SECONDS", "9000"))
STATE = RUN / "orchestration.json"


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def load_state() -> dict:
    return json.loads(STATE.read_text()) if STATE.exists() else {
        "schema": "tos.service.gate-d-agent-pilot-orchestration.v1", "events": [], "sessions": []}


state = load_state()


def tokens() -> list[str]:
    values = []
    for name in ("claude.env", "codex.env"):
        path = SECRETS / name
        if path.exists():
            values += [line.split("=", 1)[1] for line in path.read_text().splitlines()
                       if "=" in line and not line.startswith("CODEX_ACCOUNT_ID")]
    return [v for v in values if len(v) > 20]


def scrub(value, secret_values=None):
    secret_values = tokens() if secret_values is None else secret_values
    if isinstance(value, str):
        for token in secret_values:
            value = value.replace(token, "<credential>")
        return value
    if isinstance(value, dict):
        return {k: scrub(v, secret_values) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v, secret_values) for v in value]
    return value


def save() -> None:
    STATE.write_text(json.dumps(scrub(state), indent=2) + "\n")


def event(name: str, **detail) -> None:
    entry = {"at": now(), "event": name, **detail}
    state["events"].append(entry)
    save()
    print(f"{entry['at']} {name} {json.dumps(scrub(detail))[:500]}", flush=True)


def run(command: list, *, check: bool = True, timeout: float = 900, input_text: str | None = None
        ) -> subprocess.CompletedProcess:
    result = subprocess.run([str(c) for c in command], capture_output=True, text=True, timeout=timeout,
                            input=input_text)
    if check and result.returncode != 0:
        raise RuntimeError(f"{[str(c) for c in command[:4]]} failed ({result.returncode}): "
                           f"{scrub(result.stderr or '')[-1500:]}")
    return result


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def harness(role: str, *args: str, timeout: float = 900, check: bool = True) -> dict:
    result = run(["docker", "exec", CONTAINERS[role], "python3", "-I", "/pilot-mounts/harness/pilot.py", *args],
                 timeout=timeout, check=check)
    lines = [line for line in result.stdout.splitlines() if line.startswith("{")]
    return json.loads(lines[-1]) if lines else {"exit": result.returncode, "stderr": scrub(result.stderr[-800:])}


# --- start -----------------------------------------------------------------------

def jwt_expiry(token: str) -> int:
    payload = token.split(".")[1]
    return int(json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["exp"])


def write_secret(path: Path, lines: dict) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        for key, value in lines.items():
            handle.write(f"{key}={value}\n")


def prepare_credentials() -> None:
    """The operator's current access tokens, and nothing that can refresh
    them. Refused when either would expire before the run can end."""
    SECRETS.mkdir(mode=0o700, exist_ok=True)
    for name in ("claude.env", "codex.env"):
        if (SECRETS / name).exists():
            (SECRETS / name).unlink()
    claude =json.loads((Path.home() / ".claude" / ".credentials.json").read_text())["claudeAiOauth"]
    codex = json.loads((Path.home() / ".codex" / "auth.json").read_text())["tokens"]
    claude_end, codex_end = claude["expiresAt"] / 1000, jwt_expiry(codex["access_token"])
    state["credentials"] = {
        "claude_access_token_expires_utc": datetime.datetime.fromtimestamp(claude_end, datetime.timezone.utc).isoformat(),
        "codex_access_token_expires_utc": datetime.datetime.fromtimestamp(codex_end, datetime.timezone.utc).isoformat(),
        "refresh_tokens_copied": False,
        "accounts": "the operator's own Claude and ChatGPT accounts (team-operated agents)"}
    if min(claude_end, codex_end) - time.time() < MIN_TOKEN_SECONDS:
        raise SystemExit("a model access token expires too soon; wait for the host to refresh it")
    write_secret(SECRETS / "claude.env", {"CLAUDE_CODE_OAUTH_TOKEN": claude["accessToken"]})
    write_secret(SECRETS / "codex.env", {"CODEX_ACCESS_TOKEN": codex["access_token"], "CODEX_ID_TOKEN": codex["id_token"],
                                         "CODEX_ACCOUNT_ID": codex["account_id"]})
    event("credentials written", **state["credentials"])


def image() -> str:
    pinned = next(line.split()[1] for line in (HERE / "Dockerfile").read_text().splitlines() if line.startswith("FROM "))
    local = "ubuntu@" + run(["docker", "image", "inspect", "ubuntu:24.04", "--format",
                             "{{index .RepoDigests 0}}"]).stdout.strip().split("@")[1]
    if pinned != local:
        raise SystemExit(f"the Dockerfile's base {pinned} is not the local ubuntu:24.04 ({local})")
    tag = "tos-gaap-pilot:" + sha256_file(HERE / "Dockerfile")[:12]
    executor_gid = str(os.stat("/run/tos-service-executor").st_gid)
    run(["docker", "build", "--quiet", "--build-arg", f"PROVIDER_UID={os.getuid()}", "--build-arg",
         f"EXECUTOR_GID={executor_gid}", "--tag", tag, HERE], timeout=1200)
    state["image"] = {"tag": tag, "base": pinned, "provider_uid": os.getuid(), "executor_gid": executor_gid,
                      "image_id": run(["docker", "image", "inspect", tag, "--format", "{{.Id}}"]).stdout.strip()}
    return tag


def start_container(role: str, tag: str) -> None:
    work = WORKS[role]
    (work / "control" / "transcripts").mkdir(parents=True, exist_ok=True)
    key = RUN / "keys" / role
    key.chmod(0o644)  # read by container root to install as the role's own 0600 key; RUN/keys stays 0700
    mounts = [(work, "/pilot/work", False), (RUN / "bin", "/pilot-mounts/bin", True),
              (HERE / "harness", "/pilot-mounts/harness", True),
              (REPO / "protocol" / "scripts", "/pilot-mounts/scripts", True),
              (RUN / "public", "/pilot-mounts/public", True), (key, "/pilot-mounts/key", True)]
    extra = []
    if role == "provider":
        mounts.append((Path("/run/tos-service-executor"), "/run/tos-service-executor", True))
    if role == "verifier":
        HANDOFF.mkdir(exist_ok=True)
        (RUN / "verifier-work").mkdir(exist_ok=True)
        mounts += [(HANDOFF, "/v/in", True), (RUN / "verifier-work", "/v/work", False),
                   # The Go toolchain the module pins (go env GOROOT), not
                   # whatever /usr/local/go holds: the verifier builds with
                   # GOTOOLCHAIN=local.
                   (Path(run(["go", "env", "GOROOT"]).stdout.strip()), "/opt/go", True)]
        extra = ["--tmpfs", "/run/codex-home:uid=2101,gid=2101,mode=0700"]
    command = ["docker", "run", "--detach", "--name", CONTAINERS[role], "--network", "bridge", "--cpus", "4",
               "--pids-limit", "2048", "--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add",
               "CHOWN", "--cap-add", "FOWNER", "--security-opt", "no-new-privileges", *extra]
    for source, target, readonly in mounts:
        command += ["--mount", f"type=bind,src={source},dst={target}" + (",readonly" if readonly else "")]
    for name in ("ACTOR_CODE_HASH", "REGISTRY_CODE_HASH", "PILOT_RESPONSE_SLA", "PILOT_REFUND_WINDOW"):
        if os.environ.get(name):
            command += ["--env", f"{name}={os.environ[name]}"]
    command += ["--env", f"HOST_UID={os.getuid()}", "--env", f"HOST_GID={os.getgid()}", "--env",
                f"PILOT_PROVIDER_UID={os.getuid()}", "--env", f"PILOT_EXECUTOR_GID={state['image']['executor_gid']}",
                "--entrypoint", "python3", tag, "-I", "/pilot-mounts/harness/pilot.py", "serve", role]
    run(command)
    event("container started", role=role, container=CONTAINERS[role])


def cmd_start() -> None:
    for name in ("ACTOR_CODE_HASH", "REGISTRY_CODE_HASH"):
        if not os.environ.get(name):
            raise SystemExit(f"{name} is required")
    for directory in (LOGS, RECORD):
        directory.mkdir(parents=True, exist_ok=True)
    state["terms_env"] = {"actor_code_hash": os.environ["ACTOR_CODE_HASH"],
                          "response_sla": os.environ.get("PILOT_RESPONSE_SLA", "3600"),
                          "refund_window": os.environ.get("PILOT_REFUND_WINDOW", "3600")}
    tag = image()
    prepare_credentials()
    for role in ROLES:
        start_container(role, tag)
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        wallets = {role: WORKS[role] / "out" / f"{role}-wallet.json" for role in ("provider", "buyer")}
        if all(path.exists() for path in wallets.values()):
            for role, path in wallets.items():
                event("wallet to fund", **json.loads(path.read_text()))
            return
        for role in ROLES:
            if (WORKS[role] / "out" / "failed.json").exists():
                raise SystemExit(f"{role} failed: {(WORKS[role] / 'out' / 'failed.json').read_text()}")
        time.sleep(5)
    raise SystemExit("the wallets did not appear within 10 minutes; see the role logs")


# --- offer --------------------------------------------------------------------------

def cmd_offer() -> None:
    provider_out = WORKS["provider"] / "out"
    if not (provider_out / "ready.json").exists():
        raise SystemExit("the provider has not published its offer yet")
    control = WORKS["buyer"] / "control"
    offer = (provider_out / "public" / "offer-pilot.json").read_bytes()
    (control / "provider-offer.json").write_bytes((provider_out / "provider" / "offer.json").read_bytes())
    (control / "offer-pilot.json").write_bytes(offer)
    event("offer handed to the buyer", offer_sha256=hashlib.sha256(offer).hexdigest())


# --- purchases ------------------------------------------------------------------------

def fill(template: str, values: dict) -> str:
    for key, value in values.items():
        template = template.replace("{" + key + "}", str(value))
    leftover = re.findall(r"\{[A-Z_]+\}", template)
    if leftover:
        raise RuntimeError(f"unfilled placeholders {leftover}")
    return template


def claude(name: str, prompt_file: str, values: dict, profile: dict) -> dict:
    """One non-interactive Claude Code session as the developer account:
    no built-in tool, only the tos-buyer MCP server."""
    prompt = fill((HERE / "prompts" / prompt_file).read_text(), values)
    home = profile["workspace"]["home"]
    index = len(state["sessions"]) + 1
    transcript = TRANSCRIPTS / f"{index:02d}-{name}.jsonl"
    command = ["docker", "exec", "--env-file", SECRETS / "claude.env", "-u", "developer", "-w", home, "-e",
               f"HOME={home}", "-e", "DISABLE_AUTOUPDATER=1", "-e", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", "-e",
               "MCP_TOOL_TIMEOUT=330000", CONTAINERS["buyer"], "/opt/pilot-bin/claude", "-p", prompt, "--mcp-config",
               profile["workspace"]["mcp_config"], "--strict-mcp-config", "--setting-sources", "", "--tools", "",
               "--allowedTools", "mcp__tos-buyer__*", "--permission-mode", "dontAsk", "--output-format",
               "stream-json", "--verbose", "--no-session-persistence"]
    started = now()
    secret_values = tokens()
    with transcript.open("w") as handle:
        process = subprocess.Popen([str(c) for c in command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in process.stdout:
            handle.write(scrub(line, secret_values))
            handle.flush()
        stderr = process.stderr.read()
        status = process.wait(timeout=60)
    transcript.chmod(0o644)
    events = [json.loads(line) for line in transcript.read_text().splitlines() if line.startswith("{")]
    init = next((e for e in events if e.get("type") == "system" and e.get("subtype") == "init"), {})
    final = next((e for e in reversed(events) if e.get("type") == "result"), {})
    answer = None
    for line in reversed((final.get("result") or "").strip().splitlines()):
        if line.strip().startswith("{"):
            try:
                answer = json.loads(line.strip())
            except ValueError:
                pass
            break
    tool_calls = [item.get("name") for e in events if e.get("type") == "assistant"
                  for item in (e.get("message") or {}).get("content", []) if item.get("type") == "tool_use"]
    session = {"name": name, "prompt": prompt_file, "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
               "started_utc": started, "finished_utc": now(), "exit": status,
               "transcript": str(transcript.relative_to(RUN)), "transcript_sha256": sha256_file(transcript),
               "model": init.get("model"), "tools": init.get("tools"),
               "claude_code_version": init.get("claude_code_version"), "tool_calls": tool_calls, "answer": answer,
               "is_error": final.get("is_error"), "stderr_tail": scrub(stderr[-600:], secret_values)}
    state["sessions"].append(session)
    event(f"claude session {name}", exit=status, answer=answer, tool_calls=tool_calls)
    if status != 0 or final.get("is_error"):
        raise RuntimeError(f"the Claude session {name} failed; see {transcript}")
    return session


def chain_request(request_hash: str) -> dict:
    observed = harness("buyer", "chain-state", request_hash, timeout=600, check=False)
    return next((r for r in observed.get("requests") or [] if r.get("request_hash") == request_hash), {})


def wait_state(request_hash: str, states: set, timeout: float, interval: float = 30) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        request = chain_request(request_hash)
        if request.get("state") in states:
            return request
        time.sleep(interval)
    raise RuntimeError(f"{request_hash[:16]} did not reach {sorted(states)} within {timeout} s")


def buy(label: str, profile: dict, extra: str = "") -> str:
    objects, terms = profile["objects"], profile["terms"]
    session = claude(f"buy-{label}", "buy.prompt", {
        "SRC": profile["workspace"]["src"], "OFFER_PATH": profile["workspace"]["offer_path"],
        "CAP_ID": objects["capability_id"], "CAP_VER": objects["capability_version"],
        "PROVIDER_AGENT": objects["provider_agent_id"], "PRICE_NANO": terms["price_nanotos"],
        "STORAGE_NANO": terms["storage_fee_nanotos"], "SLA": terms["response_sla_seconds"],
        "REFUND_WINDOW": terms["refund_claim_window_seconds"], "IDEM": f"agent-pilot-{label.lower()}-{RUN.name}",
        "LABEL": label, "EXTRA": extra}, profile)
    request_hash = (session.get("answer") or {}).get("request_hash") or ""
    if not re.fullmatch(r"[0-9a-f]{64}", request_hash):
        raise RuntimeError(f"the buy session for {label} reported no request_hash")
    return request_hash


def provider(action: str) -> dict:
    report = harness("provider", "provider", action)
    event(f"provider {action}", exit=report.get("exit"))
    return report


def provider_saw(request_hash: str) -> str | None:
    requests = (provider("status").get("report") or {}).get("requests") or []
    entry = next((r for r in requests if r.get("request_hash") == request_hash), {})
    return entry.get("operator_state")


def withdraw_and_wait() -> dict:
    provider("withdraw")
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        withdrawals = (provider("status").get("report") or {}).get("withdrawals") or []
        if withdrawals and withdrawals[0].get("state") == "finalized":
            return withdrawals[0]
        time.sleep(30)
    raise RuntimeError("the provider's withdrawal did not finalize")


def write_handoff(profile: dict, requests: dict, withdrawal: dict) -> dict:
    buyer_out = WORKS["buyer"] / "out"
    for name in ("global-config.json", "tos-service-native-registry-v1.boc.base64", "validators.known_hosts"):
        (HANDOFF / name).write_bytes((RUN / "public" / name).read_bytes())
    (HANDOFF / "offer-pilot.json").write_bytes((WORKS["buyer"] / "control" / "offer-pilot.json").read_bytes())
    for label in ("R", "F"):
        (HANDOFF / label).mkdir(exist_ok=True)
        for name in ("evidence.json", "receipt.boc", "artifact.tar"):
            source = buyer_out / "handoff" / label / name
            if source.exists():
                (HANDOFF / label / name).write_bytes(source.read_bytes())
    (HANDOFF / "verifier-summary.schema.json").write_bytes(
        (HERE / "verifier" / "verifier-summary.schema.json").read_bytes())
    handoff = {"schema": "tos.service.gate-d-agent-pilot-handoff.v1", "network_id": profile["network_label"],
               "registry_code_hash": profile["releases"]["native_registry_code_hash"],
               "actor_code_hash": profile["releases"]["service_actor_code_hash"], "actor": profile["objects"]["actor"],
               "capability_id": profile["objects"]["capability_id"],
               "capability_version": profile["objects"]["capability_version"],
               "provider_agent_id": profile["objects"]["provider_agent_id"],
               "buyer_wallet": profile["objects"]["buyer_wallet_raw"],
               "buyer_agent_id": profile["objects"]["buyer_agent_id"],
               "requests": {label: {"request_id": r["request_id"], "request_hash": r["request_hash"]}
                            for label, r in requests.items()},
               "provider_withdraw_transaction": withdrawal.get("transaction_hash"),
               "ai_commit": profile["build"]["ai_commit"]}
    (HANDOFF / "handoff.json").write_text(json.dumps(handoff, indent=2) + "\n")
    sums = [f"{sha256_file(p)}  {p.relative_to(HANDOFF)}" for p in sorted(HANDOFF.rglob("*"))
            if p.is_file() and p.name != "SHA256SUMS"]
    (HANDOFF / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    for path in HANDOFF.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    event("handoff written", files=len(sums))
    return handoff


CODEX_AUTH = ("import json, os, datetime\n"
              "a = {'auth_mode': 'chatgpt', 'OPENAI_API_KEY': None, 'tokens': {'id_token': os.environ['CODEX_ID_TOKEN'],"
              " 'access_token': os.environ['CODEX_ACCESS_TOKEN'], 'refresh_token': '', 'account_id':"
              " os.environ['CODEX_ACCOUNT_ID']}, 'last_refresh': datetime.datetime.now(datetime.timezone.utc)"
              ".strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
              "fd = os.open('/run/codex-home/auth.json.new', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)\n"
              "os.write(fd, json.dumps(a).encode()); os.close(fd)\n"
              "os.replace('/run/codex-home/auth.json.new', '/run/codex-home/auth.json')\n")


def run_verifier(handoff: dict, profile: dict) -> None:
    container = CONTAINERS["verifier"]
    run(["docker", "exec", "--env-file", SECRETS / "codex.env", "-u", "verifier", container, "python3", "-I", "-c",
         CODEX_AUTH])
    endpoints = json.loads((RUN / "public" / "pilot-endpoints.json").read_text())
    rpc = ",".join(f"http://127.0.0.1:{v['local_port']}/jsonRPC" for v in endpoints["validators"])
    names = ", ".join(v["name"] for v in endpoints["validators"])
    prompt = fill((HERE / "verifier" / "verifier.prompt").read_text(), {
        "AI_COMMIT": handoff["ai_commit"], "NETWORK_ID": handoff["network_id"], "RPC": rpc,
        "REGISTRY_HASH": handoff["registry_code_hash"], "ACTOR_HASH": handoff["actor_code_hash"],
        "ACTOR": handoff["actor"], "R_ID": handoff["requests"]["R"]["request_id"],
        "R_HASH": handoff["requests"]["R"]["request_hash"], "F_ID": handoff["requests"]["F"]["request_id"],
        "F_HASH": handoff["requests"]["F"]["request_hash"], "BUYER_WALLET": handoff["buyer_wallet"],
        "PRICE_NANO": profile["terms"]["price_nanotos"], "WITHDRAW_TX": handoff["provider_withdraw_transaction"],
        "ENDPOINT_SETUP": "Your own pilot-rpc forwards are already open in this container, with your own key: "
                          f"{rpc} ({names}: each a validator's loopback JSON-RPC, operated by the project). "
                          "Open no other connection to them.",
        "ENDPOINT_TEARDOWN": "Leave the forwards to the container; they close when it stops."})
    (RUN / "verifier-prompt.txt").write_text(prompt)
    started = now()
    with (LOGS / "codex-events.jsonl").open("w") as handle:
        result = subprocess.run(["docker", "exec", "-i", "-u", "verifier", "-w", "/v/work", "-e", "HOME=/v/work/home",
                                 "-e", "CODEX_HOME=/run/codex-home", "-e", "PATH=/opt/go/bin:/usr/bin:/bin", "-e",
                                 "GOTOOLCHAIN=local", container, "/opt/pilot-bin/codex", "exec",
                                 "--skip-git-repo-check", "--ephemeral", "-s", "danger-full-access", "--output-schema",
                                 "/v/in/verifier-summary.schema.json", "-o", "/v/work/out/codex-summary.json", "--json",
                                 "-"], input=prompt, stdout=handle, stderr=subprocess.PIPE, text=True, timeout=5400)
    state["verifier"] = {"started_utc": started, "finished_utc": now(), "exit": result.returncode,
                         "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                         "events_sha256": sha256_file(LOGS / "codex-events.jsonl"),
                         "stderr_tail": scrub(result.stderr[-600:])}
    event("codex verifier finished", exit=result.returncode)
    if result.returncode != 0:
        raise RuntimeError("the Codex verifier session failed")


def verifier_sign(message_hex: str) -> dict:
    # A fresh declaration key per signing, in the verifier's tmpfs only.
    script = ("set -e; n=$(openssl rand -hex 8); "
              "export VAULT_URL=\"file:///run/codex-home/declaration-$n.json?master_key=$(openssl rand -hex 32)\"; "
              "c=/run/codex-home/declaration-tosctl-$n.json; /opt/pilot-bin/tosctl config generate -o $c >/dev/null; "
              "/opt/pilot-bin/tosctl wallet create -n declaration -v V4R2 -c $c >/dev/null; "
              f"/opt/pilot-bin/tosctl wallet sign -n declaration --message-hex {message_hex} -c $c")
    return json.loads(run(["docker", "exec", "-u", "verifier", "-e", "HOME=/v/work/home", CONTAINERS["verifier"],
                           "/bin/sh", "-c", script]).stdout)


def sign_record(record_sha256: str) -> None:
    signatures = []
    for role, signer in (("buyer", lambda: harness("buyer", "sign", "custody", record_sha256)),
                         ("provider", lambda: harness("provider", "sign", "provider", record_sha256)),
                         ("verifier", lambda: verifier_sign(record_sha256))):
        signed = signer()
        signatures.append({"role": role, "algorithm": signed["algorithm"], "public_key_hex": signed["public_key_hex"],
                           "message_hex": signed["message_hex"], "signature_hex": signed["signature_hex"],
                           "signed_utc": now()})
    (RECORD / "signatures.json").write_text(json.dumps(signatures, indent=2) + "\n")
    event("record signed", roles=[s["role"] for s in signatures])


SWITCH_QUIET_SECONDS = 600


def switch_times() -> list[int]:
    """Validator-set switch times read from the chain: ConfigParam 34's
    utime_until and 36's utime_since and utime_until, continued on their
    period. Read fresh at every hold, since a late election shifts them."""
    times = harness("buyer", "validator-set-times", timeout=120)
    known = sorted({t for param in times.values() if param for t in (param["utime_since"], param["utime_until"])})
    current = times["34"]
    period = current["utime_until"] - current["utime_since"]
    last = known[-1]
    state.setdefault("validator_set_times", []).append({"at": now(), **times})
    return known + [last + k * period for k in range(1, 6)]


def next_clear(start: int, spans: list[tuple[int, int]], switches: list[int]) -> int:
    """The first time >= start at which every span (offsets in seconds) of
    the sends it starts stays more than SWITCH_QUIET_SECONDS from every
    switch."""
    candidate = start
    while any(abs(candidate + offset - switch) < SWITCH_QUIET_SECONDS for low, high in spans
              for offset in range(low, high + 1, 30) for switch in switches):
        candidate += 60
    return candidate


def hold_until_clear(what: str, spans: list[tuple[int, int]]) -> None:
    start = next_clear(int(time.time()), spans, switch_times())
    if start > time.time():
        event(f"holding {what} so its sends clear the set switches", until_unix=start)
        time.sleep(start - time.time())


def cmd_purchases() -> None:
    buyer_out = WORKS["buyer"] / "out"
    if not (buyer_out / "ready.json").exists():
        raise SystemExit("the buyer is not ready (no dry check passed yet)")
    profile = json.loads((buyer_out / "public" / "profile.json").read_text())
    requests = {}
    # R: the provider answers it. F follows as soon as the provider holds
    # R, with admission paused, so F runs alongside R and its response
    # deadline (the run's floor) starts minutes after R's call.
    hold_until_clear("R (call, execution and respond)", [(0, 1500)])
    r_hash = buy("R", profile)
    state["R"] = r_hash
    held = None
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline and held not in ("admitted", "executing", "result_available", "responded"):
        time.sleep(20)
        held = provider_saw(r_hash)
    event("the provider holds R", operator_state=held)
    provider("pause")
    # F's response deadline, when the buyer agent sends expire and
    # claim_refund, must stay 10 minutes clear of every validator-set switch
    # (read from ConfigParam 34 and 36); PILOT_F_NOT_BEFORE (Unix seconds)
    # can hold F's payment later still.
    sla = int(profile["terms"]["response_sla_seconds"])
    not_before = max(int(os.environ.get("PILOT_F_NOT_BEFORE", "0")), int(time.time()))
    start_f = next_clear(not_before, [(0, 180), (sla, sla + 900)], switch_times())
    if start_f > time.time():
        event("holding F so its call, deadline and refund sends clear the set switches", until_unix=start_f)
        time.sleep(start_f - time.time())
    f_hash = buy("F", profile, "The provider may not answer this purchase; that is expected. Do not withdraw it "
                               "and do not request a refund.\n")
    state["F"] = f_hash
    requests["R"] = wait_state(r_hash, {"responded"}, 2400)
    event("R responded on chain", request_id=requests["R"].get("request_id"))
    for attempt in range(10):
        answer = claude(f"result-R-{attempt + 1}", "result.prompt", {"REQUEST_HASH": r_hash, "LABEL": "R"},
                        profile).get("answer") or {}
        if answer.get("accepted") is True:
            break
        time.sleep(90)
    else:
        raise RuntimeError("the buyer never accepted R's result")
    pending = wait_state(f_hash, {"pending", "expired", "refunded"}, 1200)
    wait_seconds = max(0, int(pending.get("response_deadline") or 0) - int(time.time())) + 60
    event("F pending with the provider paused; waiting for its response deadline", seconds=wait_seconds)
    time.sleep(wait_seconds)
    requests["F"] = wait_state(f_hash, {"refunded"}, 2400)
    event("F refunded on chain by the buyer agent's refund duty", request_id=requests["F"].get("request_id"))
    claude("refund-F", "refund.prompt", {"REQUEST_HASH": f_hash, "LABEL": "F"}, profile)
    claude("purchases", "purchases.prompt", {}, profile)
    provider("resume")
    hold_until_clear("the provider's withdrawal", [(0, 600)])
    withdrawal = withdraw_and_wait()
    event("provider withdrawal finalized", transaction=withdrawal.get("transaction_hash"))
    for label, request_hash in (("R", r_hash), ("F", f_hash)):
        exported = harness("buyer", "export", label, request_hash, timeout=900, check=False)
        event(f"buyer evidence export {label}", exit=exported.get("exit"), files=exported.get("files"))
        if exported.get("exit") != 0:
            raise RuntimeError(f"the evidence export of {label} failed: {exported.get('stderr')}")
    handoff = write_handoff(profile, requests, withdrawal)
    finish_pilot(handoff, profile)


def cmd_verify() -> None:
    """Run the verifier and the record again over the existing handoff,
    after a verifier attempt that could not run (refresh-credentials
    first). The earlier attempt's files are kept under attempt names."""
    attempt = 1 + len([e for e in state["events"] if e["event"] == "codex verifier finished"])
    events = LOGS / "codex-events.jsonl"
    if events.exists():
        events.rename(LOGS / f"codex-events-attempt-{attempt - 1}.jsonl")
    run(["docker", "exec", "-u", "verifier", CONTAINERS["verifier"], "/bin/sh", "-c",
         f"cd /v/work/out && for f in *; do case $f in attempt-*) ;; *) mv \"$f\" \"attempt-{attempt - 1}-$f\";; esac; "
         f"done; cd /v/work && for d in ai ai-*; do [ -d \"$d\" ] && mv \"$d\" \"attempt-{attempt - 1}-$d\"; done; true"],
        check=False)
    profile = json.loads((WORKS["buyer"] / "out" / "public" / "profile.json").read_text())
    handoff = json.loads((HANDOFF / "handoff.json").read_text())
    event("verifier attempt", attempt=attempt)
    finish_pilot(handoff, profile)


def finish_pilot(handoff: dict, profile: dict) -> None:
    run_verifier(handoff, profile)
    finish_credentials()
    save()
    build_record()


def build_record() -> None:
    """The unsigned record, the three signatures over its digest, and the
    signed record. Signatures of an earlier attempt are set aside first, so
    the unsigned record is built without any."""
    old = RECORD / "signatures.json"
    if old.exists():
        old.rename(RECORD / f"signatures-set-aside-{int(time.time())}.json")
    unsigned =run([sys.executable, "-I", HERE / "make_record.py", RUN, RECORD / "record-unsigned.json"], check=False)
    event("unsigned record", summary=unsigned.stdout[-800:])
    sign_record(json.loads(unsigned.stdout)["record_sha256"])
    final = run([sys.executable, "-I", HERE / "make_record.py", RUN, RECORD / "record.json"], check=False)
    event("record built", exit=final.returncode, summary=final.stdout[-800:])


# --- stop -----------------------------------------------------------------------------

def leak_scan(secret_values: list[str]) -> list:
    found = []
    roots = [LOGS, RECORD, HANDOFF, RUN / "verifier-work" / "out", STATE, RUN / "verifier-prompt.txt",
             *[WORKS[r] / sub for r in ROLES for sub in ("logs", "out", "control")]]
    # A vault URL is a secret only through its master key; the harness logs
    # vault URLs with the key redacted, so the key's hex is what is searched.
    patterns = [re.compile(rb"master_key=[0-9A-Fa-f]{8,}"),
                re.compile(rb"sk-ant-[A-Za-z0-9_-]{8,}"), re.compile(rb'"refresh_token"\s*:\s*"[^"]+')]
    for root in roots:
        files = [root] if root.is_file() else ([p for p in root.rglob("*") if p.is_file()] if root.exists() else [])
        for path in files:
            try:
                data = path.read_bytes()
            except PermissionError:
                found.append(f"unreadable: {path.relative_to(RUN)}")
                continue
            if any(token.encode() in data for token in secret_values) or any(p.search(data) for p in patterns):
                found.append(str(path.relative_to(RUN)))
    return found


def delete_credentials() -> bool:
    for name in ("claude.env", "codex.env"):
        path = SECRETS / name
        if path.exists():
            with open(path, "r+b") as handle:
                handle.write(b"\0" * path.stat().st_size)
            path.unlink()
    if SECRETS.exists():
        SECRETS.rmdir()
    return not SECRETS.exists()


def finish_credentials() -> None:
    """Once no model session is left: scan the evidence for every token
    value, then delete the token files, before the record is built. The
    verifier's in-memory Codex login goes with its container."""
    secret_values = tokens()
    leaks = leak_scan(secret_values)
    deleted = delete_credentials()
    state["credentials_end"] = {"at": now(), "token_values_scanned": len(secret_values), "leaks": leaks,
                                "deleted": deleted}
    event("credentials scanned and deleted", leaks=leaks, deleted=deleted)
    if leaks:
        raise RuntimeError(f"a credential was found in {leaks}")


def cmd_stop() -> None:
    for role in ROLES:
        (WORKS[role] / "control" / "stop").write_text(now())
    for role in ROLES:
        run(["docker", "wait", CONTAINERS[role]], check=False, timeout=600)
        logs = run(["docker", "logs", CONTAINERS[role]], check=False, timeout=120)
        (LOGS / f"{CONTAINERS[role]}.log").write_text(scrub((logs.stdout or "") + (logs.stderr or "")))
        run(["docker", "rm", "-f", CONTAINERS[role]], check=False)
    secret_values = tokens()
    leaks = leak_scan(secret_values)
    deleted = delete_credentials()
    state["stop"] = {"at": now(), "leaks": leaks, "credentials_deleted": deleted}
    event("stopped", leaks=leaks, credentials_deleted=deleted)
    if leaks:
        raise SystemExit(f"secrets found in {leaks}")


def cmd_refresh_credentials() -> None:
    """Replace the token files with the operator's current access tokens
    (again never a refresh token), when the run waited long enough for the
    first ones to near their end. Each replacement is an event."""
    prepare_credentials()
    event("credentials replaced with the operator's current access tokens", **state["credentials"])


if __name__ == "__main__":
    {"start": cmd_start, "offer": cmd_offer, "purchases": cmd_purchases, "stop": cmd_stop, "verify": cmd_verify,
     "record": build_record,
     "refresh-credentials": cmd_refresh_credentials}[COMMAND]()
