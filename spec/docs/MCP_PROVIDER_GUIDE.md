# Operating a TOS Provider Node from an MCP Client

This guide is for a developer who works in an MCP client, Claude Code or
Codex, and wants to sell one software-work service on the TOS network
without running OpenFox: publish the node's offer, watch its requests,
pause and resume it, hand its offer file to buyers and withdraw its revenue.
It is the user guide of
[`MCP_PROVIDER_ADAPTER_V1.md`](MCP_PROVIDER_ADAPTER_V1.md) ("the adapter
spec" below), which governs where the two differ. The buying side is
[`MCP_BUYER_GUIDE.md`](MCP_BUYER_GUIDE.md).

## Status

The guide describes the commands and flags of ai main once the MCP server
`tos-service-provider-mcp` is merged (ai #131 and #132 for the library, the
agent and the confirmer). The adapter is implemented and accepted locally
on 2026-11-23 (`../deployments/local-agent-operated-provider-run-20261123.json`)
with one developer account under the owner's waiver in adapter spec section
12; not Gate D evidence. In that run of adapter spec section 10.2, Claude
Code and Codex each operated a provider node that answered paid calls; the
core team operated every role.

## 1. How it works

Three programs and two OS accounts:

| Program | Runs as | Holds |
|---|---|---|
| `tos-service-provider-mcp` | your **developer account**, started by the MCP client | nothing secret; it writes the exported offer file |
| `tos-service-provider agent` | a separate **custody account**, all the time | the rail configuration, every node journal, the `tosctl` vault credential (in its environment), the agent configuration, the action store |
| `tos-service-provider confirm` | the custody account, on a terminal you open yourself | nothing |

The agent runs the node exactly as `tos-service-provider serve` does: it
admits paid calls against finalized state, runs them on the executor
service, signs the results and the `respond` transactions, and keeps doing
so while no MCP session is open. The model can read the node's state, run
preflight, pause admission, resume its own pause, and **prepare** an offer,
a withdrawal or the resume of someone else's pause. It **cannot complete**
any of those: the agent applies one only after you type, in the confirmer,
a confirmation code shown only on the confirmer's terminal.

A model with a shell can run anything your developer account can run, read
its files and drive its terminals, so the separation is an OS account
boundary: the model must never be able to type into or read the confirmer
(adapter spec 5.2). The confirmer therefore runs on a separate login, never
in a terminal of your desktop session, IDE or MCP client.

What the node does on its own, and its bounds (adapter spec 2.5):

- it answers only requests admitted against finalized state, and attests
  only successful executions;
- it admits at most `max_admissions_per_day` requests in any 24 hours
  (default 50);
- it pauses admission by itself while the owner wallet is below
  `min_wallet_nanotos` (default 2 TOS), since every `respond` pays network
  fees from that wallet, and lifts that pause by itself when the balance is
  back;
- it never withdraws and never changes the published terms.

None of these bounds can be raised through MCP.

## 2. Requirements

- Linux on x86-64 or arm64; custody and the peer-credential checks are
  Linux only.
- Administrator rights, to create the accounts, the socket directory and
  the executor service.
- Go 1.26.11 to build the ai binaries, and `git`.
- The released `tosctl`, pinned by SHA-256 (as the buyer guide, section 4.2).
- The private container runtime and the executor service, installed as root
  from [`execution/deploy/provider/README.md`](../../execution/deploy/provider/README.md).
- A funded owner wallet in the custody account's `tosctl` vault: about 2 TOS
  for the Agent registration, the deploy funding and registration values of
  the offer (`tos-service-provider offer` previews them), and a margin above
  the wallet floor for `respond` fees.
- The network's public data: the network label, the global configuration
  file, three to eight JSON-RPC endpoints, the Native Registry code file,
  the Service Actor code hash, at least one Agent Packet Relay URL and its
  CA certificate. Check every SHA-256 you were given.
- A confirmation channel that does not pass through your developer account:
  a separate virtual console (for example Ctrl+Alt+F3) logged in as the
  custody account, a separate graphical session of that account, or SSH to
  that account **from another device**.

## 3. Accounts and directories

The examples call the developer account `dev`, the custody account
`tosprov1` and the group they share for the socket `tosprov1-clients`; the
`1` numbers the node, so a second node on the same host is `tosprov2` with
`/run/tos-provider-2`. Run as an administrator:

```bash
sudo useradd --create-home --shell /bin/bash tosprov1
sudo passwd tosprov1                      # for the console or SSH login
sudo chmod 0750 /home/tosprov1            # its own group only; dev is not in it
sudo groupadd tosprov1-clients
sudo usermod -aG tosprov1-clients dev     # log dev out and in again afterwards

# The socket directory: owned by tosprov1, group tosprov1-clients, setgid so
# the socket the agent creates inherits the group; dev may enter, not write.
sudo install -d -m 2750 -o tosprov1 -g tosprov1-clients /run/tos-provider-1
# /run is emptied at every boot; recreate the directory there each time:
echo 'd /run/tos-provider-1 2750 tosprov1 tosprov1-clients -' | sudo tee /etc/tmpfiles.d/tos-provider-1.conf
```

The executor service lets one uid reach its socket. Install it with the
custody account as that uid (`TOS_EXECUTOR_ALLOWED_UID=$(id -u tosprov1)`
in `/etc/tos-service/executor.env`) and add `tosprov1` to the executor's
socket group (`tos-executor` in the executor README):

```bash
sudo usermod -aG tos-executor tosprov1
```

Then check, and fix anything that fails:

- `dev` cannot become `tosprov1`: no passwordless `sudo` rule, no `su`
  without a password, no shared SSH key. The agent cannot check this for you.
- `dev` is not in the `tosprov1` group, so it cannot open `/home/tosprov1`.
- `VAULT_URL` is never set anywhere in the `dev` account. The MCP server
  refuses to start when it is set.
- `id -u dev` prints the uid you will name as `client_uid` below; it is not
  0 and not `tosprov1`'s.

Everything from here to section 6 runs as `tosprov1`, except where it says
`dev`.

## 4. Install the binaries

```bash
git clone https://github.com/tosnetwork/ai.git
cd ai
git checkout <pinned ai commit>
git rev-parse HEAD                       # must print the pinned commit
GOWORK=off GOTOOLCHAIN=go1.26.11 CGO_ENABLED=0 go build -trimpath -o out/ \
  ./provider/cmd/tos-service-provider ./provider/cmd/tos-service-provider-mcp
sha256sum out/tos-service-provider out/tos-service-provider-mcp
sudo install -o root -g root -m 0755 out/tos-service-provider out/tos-service-provider-mcp /usr/local/bin/
```

Root-owned binaries mean neither account can replace what the other runs.
The program, the agent and the MCP server must come from one build (adapter
spec section 8, "One release").

## 5. Custody setup (as `tosprov1`)

### 5.1 Vault, `tosctl` and the node's directories

```bash
umask 077
mkdir -p ~/custody ~/rail ~/agent-state
openssl rand -hex 32 > ~/custody/master-key            # keep a backup offline
printf 'VAULT_URL=file://%s/custody/vault.json?master_key=%s\n' \
  "$HOME" "$(cat ~/custody/master-key)" > ~/custody/vault.env
tosctl config generate --output ~/custody/tosctl.json
tosctl config chain-rpc set --config ~/custody/tosctl.json --url "<one of the --rpc endpoints>"
chmod 0600 ~/custody/*
```

Create or import the owner wallet in the vault with `tosctl`, fund it, and
save the relay CA certificate as `~/custody/relay-ca.pem`.

Three directories, none inside another, all `0700`:

| Directory | What it is |
|---|---|
| `~/rail` | the node's `state_dir`: journals, request records, pause marker |
| `~/agent-state` | the agent's own records: the action store and the pause-origin record |
| `/run/tos-provider-1` | the socket directory (section 3) |

### 5.2 `init`, then `preflight`

`init` is never a tool: it chooses the node's trust roots (adapter spec
3.1). Run it as `provider/README.md` shows, previewed and then with
`--yes`:

```bash
set -a; . ~/custody/vault.env; set +a
tos-service-provider init --rail-config ~/rail.json --state-dir ~/rail \
  --rpc "$RPC1" --rpc "$RPC2" --rpc "$RPC3" \
  --global-config ~/custody/global.config.json --network-label "$NETWORK_LABEL" \
  --tosctl /usr/local/bin/tosctl --tosctl-sha256 "$TOSCTL_SHA256" --tosctl-config ~/custody/tosctl.json \
  --wallet provider --registry-code-boc ~/custody/registry-code.boc \
  --actor-code-hash "$ACTOR_CODE_HASH" --relay-url "$RELAY_URL" --relay-ca-file ~/custody/relay-ca.pem
# read the preview (exit 4), then repeat the same command with --yes
chmod 0600 ~/rail.json
tos-service-provider preflight --rail-config ~/rail.json
```

Repeat `preflight` until only the checks about the offer fail; the offer is
the model's to prepare. Do not run `offer` yourself.

### 5.3 The agent configuration

`~/agent.json`, mode `0600` (schema
`tos.service.mcp-provider.agent-config.v1`, adapter spec 2.4; unknown
fields, duplicate keys and trailing data are refused):

```json
{
  "schema": "tos.service.mcp-provider.agent-config.v1",
  "rail_config": "/home/tosprov1/rail.json",
  "state_dir": "/home/tosprov1/agent-state",
  "socket_dir": "/run/tos-provider-1",
  "client_uid": 1001,
  "offer": {
    "executor_socket": "/run/tos-service-executor/executor.sock",
    "offer_path": "/home/tosprov1/rail/setup/offer.json"
  },
  "offer_bounds": {
    "min_price_nanotos": "10000000",
    "max_price_nanotos": "5000000000",
    "max_storage_fee_nanotos": "1000000000",
    "max_cleanup_bounty_nanotos": "500000000",
    "min_response_sla_seconds": 3600,
    "max_response_sla_seconds": 86400,
    "min_refund_claim_window_seconds": 3600,
    "max_refund_claim_window_seconds": 86400,
    "min_retention_seconds": 3600,
    "max_retention_seconds": 604800
  },
  "max_admissions_per_day": 50,
  "min_wallet_nanotos": "2000000000",
  "max_withdraw_previews_per_day": 8
}
```

- `client_uid` is `id -u dev`.
- `offer` holds the operator's offer inputs, which the model can never
  supply: the executor (`executor_socket`, or `executor_binary` with
  `executor_sha256` for the subprocess executor), optionally
  `deploy_funding_nanotos` (at least 1 TOS), `respond_budget_seconds`,
  `offer_path` and `gateway_card_path`, `attestor_controller`, and
  `test_profile_actor`.
- `offer_bounds` is the range every offer the model previews must lie in,
  each inside the contract's own bounds: the cleanup bounty 0.1 to 1 TOS,
  the storage fee at least 0.1 TOS plus the bounty, the windows 3,600 to
  2,592,000 seconds (600 with the test-profile actor), the retention 3,600 to
  2,592,000 seconds.
- `max_admissions_per_day`, `min_wallet_nanotos` and
  `max_withdraw_previews_per_day` may be left out for their defaults.

## 6. Run the agent and the confirmer (as `tosprov1`)

### 6.1 The agent

The agent must be running before the MCP client starts the MCP server. A
systemd user service keeps it running when you log out:

```bash
sudo loginctl enable-linger tosprov1      # once, as an administrator
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/tos-service-provider-agent.service <<'EOF'
[Unit]
Description=TOS MCP provider agent

[Service]
EnvironmentFile=%h/custody/vault.env
ExecStart=/usr/local/bin/tos-service-provider agent --config %h/agent.json
Restart=on-failure

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now tos-service-provider-agent
journalctl --user -u tos-service-provider-agent -f
```

Started, it prints one line, `{"agent": true, "socket":
"/run/tos-provider-1/agent.sock", ...}`, and creates the socket (`0660`,
group `tosprov1-clients`). Before the offer is published it serves no node
but holds the node's serve lock, so `tos-service-provider serve` and a
second agent are refused; once a confirmed offer has written the provider
section, it opens and serves the node. It refuses to start for the reasons
in section 10.2.

### 6.2 The confirmer

On the separate login (console, separate session, or SSH from another
device), as `tosprov1`:

```bash
tos-service-provider confirm --agent-socket /run/tos-provider-1/agent.sock --watch
```

It refuses a standard input that is not a terminal, a terminal that is not
`tosprov1`'s, and a socket path that is not a socket owned by `tosprov1`.
For each action the model asked you to decide, it shows two blocks: first
the text read from files (the manifest's name and description for an
offer, the pause reason for a resume), behind a gutter and under a heading
that says it is not from TOS; then, after a fixed rule line, the protocol
block from the agent's own record: for an offer every preview field, the
terms in TOS and nanoTOS, what one call pays and what a buyer gets back on
no answer; for a withdrawal the actor, the destination (always the owner
wallet), the amount, the credited revenue before and after; for a resume
the marker's time and origin and the preflight checks. Then the action
reference, the preview digest and, last, the confirmation code. Type the
code to confirm, `decline` to decline, or press Enter to skip. Three wrong
codes cancel the action.

Before it sends, the agent repeats the preview from its own record; if
anything changed since you confirmed (wallet, actor, planned steps,
credited amount, the pause marker), the action expires and nothing is
sent.

## 7. Configure the MCP client (as `dev`)

```bash
mkdir -p ~/tos-offers && chmod 0700 ~/tos-offers
```

The MCP server's flags:

| Flag | Value |
|---|---|
| `--agent-socket` | `/run/tos-provider-1/agent.sock` |
| `--agent-state-dir` | `/home/tosprov1/agent-state`; the server checks that `dev` **cannot** open it |
| `--rail-config` | `/home/tosprov1/rail.json`; the server checks that `dev` **cannot** open it |
| `--export-dir` | where `tos_provider_export_offer` writes the offer file; must not be writable by group or others |
| `--vault-url-env` | only when the rail configuration's `vault_url_env` is not `VAULT_URL`: the variable that must not be set |

### 7.1 Claude Code

```bash
claude mcp add --scope user --transport stdio tos-provider -- \
  /usr/local/bin/tos-service-provider-mcp \
  --agent-socket /run/tos-provider-1/agent.sock \
  --agent-state-dir /home/tosprov1/agent-state \
  --rail-config /home/tosprov1/rail.json \
  --export-dir /home/dev/tos-offers
claude mcp list                           # tos-provider: ... - Connected
```

Everything after `--` is the server's own command line. `--scope user` keeps
the entry out of shared project files. The file form, in `.mcp.json`:

```json
{
  "mcpServers": {
    "tos-provider": {
      "command": "/usr/local/bin/tos-service-provider-mcp",
      "args": ["--agent-socket", "/run/tos-provider-1/agent.sock",
               "--agent-state-dir", "/home/tosprov1/agent-state",
               "--rail-config", "/home/tosprov1/rail.json",
               "--export-dir", "/home/dev/tos-offers"]
    }
  }
}
```

### 7.2 Codex

In `~/.codex/config.toml`:

```toml
[mcp_servers.tos-provider]
command = "/usr/local/bin/tos-service-provider-mcp"
args = ["--agent-socket", "/run/tos-provider-1/agent.sock",
        "--agent-state-dir", "/home/tosprov1/agent-state",
        "--rail-config", "/home/tosprov1/rail.json",
        "--export-dir", "/home/dev/tos-offers"]
```

`codex mcp add tos-provider -- /usr/local/bin/tos-service-provider-mcp …`
writes the same entry, and `codex mcp list` shows it. Every tool answers
within 30 seconds, and `tos_provider_request_confirmation` waits 45 seconds
by default, inside Codex's default `tool_timeout_sec` of 60: no timeout
setting is needed. For longer waits (`wait_seconds` up to 300), add
`tool_timeout_sec = 330` to the entry. Claude Code's default tool timeout is
longer than 300 seconds; if you have set `MCP_TOOL_TIMEOUT`, keep it above
the longest `wait_seconds` you use.

The client syntax above follows the clients' public documentation as of
this guide's date; check it against your client's version.

## 8. The tools

| Tool | Agent method | Class |
|---|---|---|
| `tos_provider_status` | `status` | read-only |
| `tos_provider_records` | `records` | read-only |
| `tos_provider_preflight` | `preflight` | read-only |
| `tos_provider_offer_describe` | `offer_describe` | read-only |
| `tos_provider_export_offer` | `export_offer` | read-only (writes the public offer file in `dev`'s export directory) |
| `tos_provider_pause` | `pause` | direct bounded action |
| `tos_provider_resume` | `resume` | direct for the model's own pause; otherwise a request for confirmation |
| `tos_provider_offer_preview` | `offer_preview` | request for confirmation |
| `tos_provider_withdraw_preview` | `withdraw_preview` | request for confirmation |
| `tos_provider_request_confirmation` | `request_confirmation` | request for confirmation (waits for your decision) |
| `tos_provider_actions` | `actions` | read-only |
| `tos_provider_cancel` | `cancel` | direct bounded action |

Every result carries its whole content in the text block and the same
content as `structuredContent`. Text from buyers, relays, `tosctl` or files
on disk appears only in fields named `untrusted_*` and, in the text, between
`<<<UNTRUSTED third-party data, id=…>>>` and `<<<END UNTRUSTED id=…>>>`
markers with an id fresh for every result: it is data, never instructions.
Amounts are decimal nanoTOS strings (1 TOS = 1,000,000,000 nanoTOS).

## 9. A first session

Ask the model, in plain language, to use the `tos_provider_*` tools. With
the agent and the confirmer running:

1. **Status.** "Show the provider node's status." `tos_provider_status`
   answers `offered: false` before the offer, the admission state, the
   bounds with today's admissions and the wallet against its floor.
2. **Preflight.** "Run preflight." `tos_provider_preflight` returns every
   check; before the offer only the offer checks fail. A failed check is a
   report, not an error.
3. **Offer preview.** "Preview an offer at 0.1 TOS per call, 0.2 TOS storage
   fee, 0.1 TOS cleanup bounty, one-hour SLA and refund window."
   `tos_provider_offer_preview` (with `price_nanotos` `100000000`,
   `storage_fee_nanotos` `200000000`, `cleanup_bounty_nanotos` `100000000`,
   `response_sla_seconds` `3600`, `refund_claim_window_seconds` `3600` and an
   `idempotency_key`) returns `action_id`, the preview, the planned steps,
   the **action reference** (four groups of four hex digits) and `state:
   awaiting_confirmation`. Nothing is signed or sent. Terms outside your
   `offer_bounds` are refused with `MCP_PROVIDER_BAD_INPUT`.
4. **Ask for confirmation.** The model calls
   `tos_provider_request_confirmation` with the `action_id`. It waits up to
   45 seconds and answers `awaiting_confirmation` until you decide; the model
   calls it again.
5. **Confirm on custody.** In the confirmer, check that the action reference
   matches the one the model showed, read the protocol block, and type the
   code. The agent repeats the preview, sends the offer's steps, and the next
   `tos_provider_request_confirmation` answers `applying` and then `applied`
   with the steps.
6. **Status again.** `tos_provider_status` now answers `offered: true`,
   `serving: true` and the actor's finalized accounting.
7. **Hand out the offer.** `tos_provider_export_offer` writes
   `~/tos-offers/offer-<capability_id>-<version>.json`; give that file to the
   buyer, who quotes from it (buyer guide section 8).

Later:

- **Pause and resume.** `tos_provider_pause` stops admission at once.
  `tos_provider_resume` lifts the model's own pause directly when the
  wallet is at or above the floor and preflight passes. A pause you made
  with `tos-service-provider pause` (including one stacked on the model's)
  is never lifted by the model: its resume becomes an action for the
  confirmer.
- **Withdraw.** `tos_provider_withdraw_preview` with `amount_nanotos`, or
  `all: true` (the preview fixes the exact credited amount), then
  `tos_provider_request_confirmation` and your confirmation. The destination
  is always the owner wallet.
- **Requests.** `tos_provider_records` lists them newest first, with
  `operator_state` as a filter.
- **Cancel.** `tos_provider_cancel` withdraws an action still awaiting your
  decision; it will never be applied.

Your own commands in the custody account while the agent runs (adapter spec
3.1): `confirm`, `pause` and `resume` as your own stop and start,
`withdraw --acknowledge`, and `status`. Do not run `offer`, `withdraw` or
`serve` by hand.

## 10. Troubleshooting

### 10.1 Tool errors

A tool error carries `{"error": {"code", "disposition", "message",
"state"}}`; `state` is the action's state when the refusal is about one, and
what the agent attached (an action, the offer's steps, an undecided
withdrawal) is under `result`. The message is fixed text. An input that
breaks the schema is refused by the MCP SDK before anything is sent, with
its validation text and no `error` object.

| Code | Meaning | What to do |
|---|---|---|
| `MCP_PROVIDER_BAD_INPUT` | an input breaks its pattern or bound, or the terms lie outside the offer or contract bounds | fix the input; check `offer_bounds` |
| `MCP_PROVIDER_NOT_FOUND` | no such action | check the `action_id` with `tos_provider_actions` |
| `MCP_PROVIDER_NOT_OFFERED` | the node has no published offer yet | preview and confirm the offer |
| `MCP_PROVIDER_ALREADY_OFFERED` | the offer is published; changing terms is not in V1 | change terms with `tosctl` as the owner |
| `MCP_PROVIDER_NOT_READY` | a preflight check the action needs failed, the wallet is below the floor, or an offer stopped part way; the report is attached | fix what the report names; an interrupted offer is finished by previewing it again |
| `MCP_PROVIDER_NOTHING_TO_DO` | nothing credited, or more than credited, to withdraw | check `tos_provider_status` |
| `MCP_PROVIDER_OVER_LIMIT` | 4 actions already await confirmation | decide or cancel one |
| `MCP_PROVIDER_EXPIRED` | the preview's 10 minutes passed, or the fresh preview at apply time differed | preview again |
| `MCP_PROVIDER_CONFLICT` | an idempotency key reused with other inputs; an action in another phase; another preview or a confirmed action is using the node's state directory. A confirmed offer or withdrawal holds that slot for its whole send, which can take minutes (an offer's steps are each awaited in finalized state), while a preview waits at most 5 seconds for it | use a new key; check the action; ask again once the confirmed action reads `applied` (`tos_provider_actions`) |
| `MCP_PROVIDER_DECLINED` | you declined, or three wrong codes cancelled it | none |
| `MCP_PROVIDER_DEPENDENCY_UNAVAILABLE` | no RPC quorum, or a finalized read did not finish in 20 seconds; nothing was sent | check endpoints; retry |
| `MCP_PROVIDER_AGENT_UNAVAILABLE` | the agent socket does not answer | check the agent service and its log |
| `MCP_PROVIDER_AMBIGUOUS` | a withdrawal may have been sent, or an earlier one is undecided | do not repeat; `tos_provider_status` shows the record until finalized history decides it, or acknowledge it with `withdraw --acknowledge` |
| `MCP_PROVIDER_PERMISSION_DENIED` | the socket peer's account may not call this method | run the MCP server as `dev`, the configured `client_uid` |
| `MCP_PROVIDER_RATE_LIMITED` | over a per-minute bound, or `max_withdraw_previews_per_day` | wait |
| `MCP_PROVIDER_INTERNAL` | anything else | check the agent log |

A code the client does not know is treated as "do not retry".

### 10.2 Start-up refusals

| Program | Message (abridged) | Cause |
|---|---|---|
| MCP server | `a vault credential variable is set in the MCP server's environment` | remove `VAULT_URL` (or the `--vault-url-env` variable) from `dev`'s environment and the client's entry |
| MCP server | `the MCP server can open the provider agent's state directory` | `dev` can open the path named by `--agent-state-dir`; tighten the home and directory modes |
| MCP server | `the MCP server can open the rail configuration` | as above, for the path named by `--rail-config` |
| MCP server | `... cannot be checked; name the real paths` | `--agent-state-dir` or `--rail-config` names a path that does not exist under a directory `dev` can search |
| MCP server | `the agent socket is not a socket` | start the agent first; check `--agent-socket` |
| MCP server | `the MCP server runs as the account that owns the agent socket` | the client was started as `tosprov1`; start it as `dev` |
| MCP server | `the export directory must not be writable by group or others` | `chmod 0700 ~/tos-offers` |
| agent | `client_uid must differ from the agent's own uid` / `must not be root` | name `dev`'s uid |
| agent | `... must be a directory private to the agent's account` | `chmod 0700` the rail state, agent state directory |
| agent | `the rail configuration names a buyer, chat or messenger carrier` | the provider agent serves provider nodes only |
| agent | `the agent state_dir, the socket_dir and the rail state_dir must be separate directories` | none may lie inside another |
| agent | `the socket directory must be setgid (mode 2750) ...` / `must belong to the group the client account shares` | recreate it as in section 3 |
| agent | `another provider agent uses this state directory` / `another process already serves the node` | stop the other agent or `serve` |
| confirmer | `the agent socket is not owned by this account` | run the confirmer as `tosprov1`, with that agent's socket |
| confirmer | `the confirmer's terminal is not owned by the custody account` | you started it from a `dev` terminal; log in as `tosprov1` on a separate console or from another device |
| confirmer | `the confirmer reads decisions only from a terminal` | do not pipe input into `confirm` |

The MCP server's two "can open" checks open only the paths you name. A
mistyped path under `/home/tosprov1`, which `dev` cannot search, fails to
open for permission just as the real one does, so it passes: the server
starts with a wrong `--agent-state-dir` or `--rail-config` and nothing
tells you. Copy the paths from `agent.json`. These checks only catch a
custody file or directory left open to `dev`; what keeps custody private is
the agent's own start-up checks (section 6.1) and the separate accounts.

### 10.3 Other checks

- `claude mcp list` or `codex mcp list` shows the server failed: run its
  command line by hand as `dev`; it prints the refusal on standard error.
- The model's call times out while it waits: keep `wait_seconds` at the
  default or raise the client's timeout (section 7.2); the action is not
  lost, call `tos_provider_request_confirmation` again.
- A confirmed action answers `expired`: something the preview showed
  changed before the send; nothing was sent. Preview again.
- Admission stays paused with `pause_recorded_as: wallet_floor`: fund the
  owner wallet; the agent lifts its own pause at the next check.
