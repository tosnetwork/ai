# Buying TOS Software Work from an MCP Client

This guide is for a developer who works in an MCP client, such as Claude Code
or Codex, and wants to buy one software-work service on the TOS network
without running OpenFox. It is the user guide of
[`MCP_BUYER_ADAPTER_V1.md`](MCP_BUYER_ADAPTER_V1.md) ("the adapter spec"
below), which governs where the two differ. The external buyer of the Gate D
pilot ([`GATE_D_EXTERNAL_PILOT.md`](GATE_D_EXTERNAL_PILOT.md)) follows it.

## Status

The guide describes the commands and flags of ai main at merge `fcddd6bc`.
Parts depend on work that is not merged yet; they are marked **[pending]**:

- **[pending #81]** `tos_buyer_search` and `tos_buyer_quote`, and the
  optional gateway and catalog fields of the agent configuration, are in ai
  pull request #81 (branch `feat/mcp-buyer-search-quote`). On main the MCP
  server has no quote tool, so a purchase cannot start there: `prepare` needs
  the `quote_id` that only `quote` returns. Use a commit that includes #81.
- **[pending #80]** follow-ups to `init` (every send bounded by a deadline; a
  generic "not found" from `tosctl` treated as an unknown outcome). The flags
  this guide uses do not change.
- **[pending]** the evidence export (`tos-service-buyer evidence`) and the
  third-party verifier. Until they merge, keep the outputs of `status` and
  `result`.

For the pilot, use exactly the ai commit and the `tosctl` release the pilot
package names.

## 1. How it works

Three programs and two OS accounts:

| Program | Runs as | Holds |
|---|---|---|
| `tos-service-buyer-mcp` | your **developer account**, started by the MCP client | nothing secret |
| `tos-service-buyer agent` | a separate **custody account**, all the time | the `tosctl` vault credential, the wallet and packet controller (inside `tosctl`), the journal, the relay keys, the budget |
| `tos-service-buyer confirm` | the custody account, on a terminal you open yourself | nothing |

The model can search, quote, prepare a purchase and read results. It
**cannot pay**. A payment is sent only after you type, in the confirmer, a
confirmation code that is shown only on the confirmer's terminal. A model with
a shell can run anything your developer account can run, read its files and
drive its terminals, so the separation is an OS account boundary: the model
must never be able to type into or read the confirmer (adapter spec 5.1).
That is why the confirmer runs on a separate login, never in a terminal of
your desktop session, IDE or MCP client.

The agent keeps running while no MCP session is open: it delivers the task
to the provider through the packet relays, fetches and checks the result, and
claims refunds when a provider does not answer.

## 2. Requirements

- Linux on x86-64 or arm64, with a C runtime at least as new as Ubuntu
  24.04's and `libssl.so.3`, `libcrypto.so.3` (Ubuntu package `libssl3t64`)
  and `libgcc_s.so.1` for the released `tosctl`. Custody and the
  peer-credential checks are Linux only; macOS and Windows are not supported.
- Administrator rights once, to create the custody account and two
  directories.
- Go 1.26.11 to build the ai binaries, and `git`.
- A confirmation channel that does not pass through your developer account:
  a separate virtual console (for example Ctrl+Alt+F3) logged in as the
  custody account, a separate seat or graphical session of that account, or
  SSH to that account **from another device**.
- The machine stays online with the agent running from payment until the
  purchase ends: the provider's response SLA plus the refund claim window,
  about three hours for the pilot's terms.
- From the operator or provider (the pilot package), all of it public data:
  - the network label (for the epoch-7 testnet `tos:global-id:2`) and the
    global configuration file, with its SHA-256;
  - three to eight JSON-RPC endpoints, or instructions to reach them
    (section 5.3);
  - the relay base URLs and the relay CA certificate, with the certificate's
    SHA-256 sent over a second channel;
  - the Service Actor code hash
    (`tvm-cell-sha256:0594f9a5743440f9c5f63913ab790c0ea6f4fd5c627d9962d63e09428e42aa0c`
    for the current release, in `crypto/smartcont/tos-service-actor-v1.release.json`
    of the tos repository);
  - the provider's offer file and its SHA-256, and the Capability ID and
    version.

Check every SHA-256 you were given before you use the file.

## 3. Accounts and directories

The examples call the developer account `dev` and the custody account
`tosbuyer`. Run as an administrator:

```bash
sudo useradd --create-home --shell /bin/bash tosbuyer
sudo passwd tosbuyer                      # for the console or SSH login
sudo groupadd tosbuyer-clients
sudo usermod -aG tosbuyer-clients dev     # log dev out and in again afterwards

# The socket directory: owned by tosbuyer, group tosbuyer-clients, setgid so
# the socket the agent creates inherits the group; dev may enter, not write.
sudo install -d -o tosbuyer -g tosbuyer-clients -m 2750 /var/lib/tosbuyer-sock

sudo chmod 0750 /home/tosbuyer
```

Then check, and fix anything that fails:

- `dev` cannot become `tosbuyer`: no passwordless `sudo` rule, no `su`
  without a password, no shared SSH key, no `tosbuyer` entry in a sudoers file
  that `dev` can use. The agent cannot check this for you.
- `dev` is not in the `tosbuyer` group, so it cannot read `/home/tosbuyer`.
- Never set `VAULT_URL` anywhere in the `dev` account. The MCP server refuses
  to start when it is set.

Everything from here to section 6 runs as `tosbuyer`, except where it says
`dev`.

## 4. Install the binaries

### 4.1 ai binaries, built from source at a pinned commit

```bash
git clone https://github.com/tosnetwork/ai.git
cd ai
git checkout <pinned ai commit>          # from the pilot package
git rev-parse HEAD                       # must print the pinned commit
GOWORK=off GOTOOLCHAIN=go1.26.11 CGO_ENABLED=0 \
  go build -trimpath -o out/ ./protocol/cmd/tos-service-buyer ./protocol/cmd/tos-service-buyer-mcp
sha256sum out/tos-service-buyer out/tos-service-buyer-mcp   # keep for your evidence
sudo install -o root -g root -m 0755 out/tos-service-buyer out/tos-service-buyer-mcp /usr/local/bin/
```

Installing root-owned binaries means neither account can replace what the
other runs.

### 4.2 `tosctl`, pinned by SHA-256

Use the `tosctl` the pilot package names, from a published tos release (for
example `v2026.11-1`). Download `tosctl-linux-x86_64` or `tosctl-linux-arm64`
and `SHA256SUMS` from the release page, then:

```bash
sha256sum --check --ignore-missing SHA256SUMS
# optional, with the GitHub CLI logged in; see the release notes:
gh attestation verify release-provenance.json --repo tosnetwork/tos \
  --cert-identity https://github.com/tosnetwork/tos/.github/workflows/create-release.yml@refs/heads/main \
  --source-ref refs/heads/main
sudo install -o root -g root -m 0755 tosctl-linux-x86_64 /usr/local/bin/tosctl
sha256sum /usr/local/bin/tosctl          # this is your --tosctl-sha256
```

`init` and the agent run `tosctl` only when its SHA-256 equals the pin.

## 5. Custody setup (as `tosbuyer`)

### 5.1 Vault and `tosctl` configuration

```bash
umask 077
mkdir -p ~/custody ~/manifests
openssl rand -hex 32 > ~/custody/master-key            # keep a backup offline
printf 'VAULT_URL=file://%s/custody/vault.json?master_key=%s\n' \
  "$HOME" "$(cat ~/custody/master-key)" > ~/custody/vault.env
tosctl config generate --output ~/custody/tosctl.json
tosctl config chain-rpc set --config ~/custody/tosctl.json --url "http://127.0.0.1:18081"
chmod 0600 ~/custody/*
```

The vault URL carries the vault's master key. It lives only in the custody
account; the agent reads it from the `VAULT_URL` environment variable and
hands it to `tosctl` only in `tosctl`'s environment. `init` and the agent
refuse a `tosctl` configuration that group or others can read.

The `chain_rpc` URL is the endpoint `tosctl` submits through. It must be one
of the `--rpc` endpoints of section 5.3, spelled the same way (base URL,
without `/jsonRPC`).

### 5.2 Relay CA

Save the relay CA certificate as `~/custody/relay-ca.pem` and compare its
SHA-256 with the value you received over the second channel. The agent
verifies the relays against this file only, never the system certificate
store.

### 5.3 Chain endpoints

The buyer reads finalized state from 3 to 8 JSON-RPC endpoints and needs a
strict majority of them to agree (`--quorum`, default a majority). An
endpoint must:

- answer the node's operator JSON-RPC, including `getConsensusBlock`, which
  the finality check uses. A public lite-query RPC service that does not
  serve it cannot be used;
- be `https` with a certificate the system store trusts, or `http` on a
  loopback address (there is no CA pin for RPC endpoints);
- have its own host and port; two URLs with the same authority are refused.

A common setup forwards three validators' loopback JSON-RPC listeners to
local ports, for example with SSH local forwards the operator gives you
access for (`ssh -N -L 18081:127.0.0.1:<rpc port> <account>@<validator-1>`,
and likewise 28081 and 38081 for validator-2 and validator-3). Keep the
forwards running, for example as `tosbuyer` user services. Your own full node
on loopback is also an endpoint. Record who operates each endpoint: the
pilot record lists them.

### 5.4 `init plan` and `init apply`

`plan` prints every change and sends nothing. Run it first:

```bash
set -a; . ~/custody/vault.env; set +a
tos-service-buyer init plan \
  --config /home/tosbuyer/agent.json \
  --state-dir /home/tosbuyer/state \
  --socket-dir /var/lib/tosbuyer-sock \
  --client-uid "$(id -u dev)" \
  --network-label tos:global-id:2 \
  --global-config /home/tosbuyer/global-config.json \
  --rpc http://127.0.0.1:18081,http://127.0.0.1:28081,http://127.0.0.1:38081 \
  --quorum 2 \
  --registry-code-boc /home/tosbuyer/tos-service-native-registry-v1.boc.base64 \
  --actor-code-hash tvm-cell-sha256:0594f9a5743440f9c5f63913ab790c0ea6f4fd5c627d9962d63e09428e42aa0c \
  --manifest-dir /home/tosbuyer/manifests \
  --tosctl /usr/local/bin/tosctl --tosctl-sha256 <sha256 of /usr/local/bin/tosctl> \
  --tosctl-config /home/tosbuyer/custody/tosctl.json \
  --wallet buyer --packet-controller buyer-packet \
  --relay https://<relay-1>:8443 --relay https://<relay-2>:8443 \
  --relay-ca-file /home/tosbuyer/custody/relay-ca.pem \
  --budget-window 24h --max-calls 4 \
  --max-per-call-nanotos 1000000000 --max-window-nanotos 3000000000
```

Notes on the inputs:

- Save the global configuration from the pilot package as
  `/home/tosbuyer/global-config.json` and the registry code file beside it,
  after checking their SHA-256s.
- The registry code file is `crypto/smartcont/tos-service-native-registry-v1.boc.base64`
  from the tos repository at the release tag. `init` refuses it unless it
  holds the code that your `tosctl` signs for.
- The configuration file must be outside the state directory; every path is
  absolute and clean.
- `--relay` is required (1 to 4) until official relay URLs are published, and
  an `https` relay requires `--relay-ca-file`.
- The budget is enforced by the agent: `--max-calls` and the two nanoTOS caps
  in the window, `--max-unconfirmed` (default 4) prepared purchases awaiting
  a decision, and `--max-lifecycle-sends` refund sends. Every amount counts
  the whole attached payment (price + storage fee + 0.2 TOS execution
  allowance). Only the custody account can change these, by editing the
  configuration and restarting the agent.
- `init` refuses to run as root or as the `--client-uid` account.

Then run the same command with `apply` in place of `plan`. The first `apply`
creates the wallet (V4R2, workchain 0) and the packet controller in the vault
and stops with "the wallet needs funding", printing the wallet address and the
amount (`funding_needed_nanotos`; about 2.15 TOS for a new wallet: 2 TOS
attached to the Agent registration, the activation and fees).

**Funding.** Fund the address with testnet TOS. In the Gate D pilot the team
funds it: send the address (it is public) to the operator, and ask for
enough for your purchases too (each attaches price + storage fee + 0.2 TOS;
the unused allowance returns). Wait until the operator confirms.

Run `apply` again. It asks on this terminal before each chain send
(activation, then the Agent registration); type `yes` to send. It waits for
the Agent in finalized state and writes `/home/tosbuyer/agent.json` (`0600`).
If it is interrupted, run it again: it reads finalized state first, never
sends a step twice, and waits out a send whose outcome is not yet known.

## 6. Run the agent (as `tosbuyer`)

The agent must be running before the MCP client starts the MCP server. A
systemd user service keeps it running when you log out:

```bash
sudo loginctl enable-linger tosbuyer      # once, as an administrator
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/tos-service-buyer-agent.service <<'EOF'
[Unit]
Description=TOS MCP buyer agent

[Service]
EnvironmentFile=%h/custody/vault.env
ExecStart=/usr/local/bin/tos-service-buyer agent --config %h/agent.json
Restart=on-failure

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now tos-service-buyer-agent
journalctl --user -u tos-service-buyer-agent -f
```

The agent refuses to start when `VAULT_URL` is missing, when its state
directory, configuration or `tosctl` configuration is readable by group or
others, when the client uid is its own, or when an `https` relay has no
pinned CA. It creates `/var/lib/tosbuyer-sock/agent.sock` (`0660`).

## 7. Configure the MCP client (as `dev`)

```bash
mkdir -p ~/src ~/tos-results && chmod 0700 ~/tos-results
```

The MCP server's flags:

| Flag | Value |
|---|---|
| `--agent-socket` | `/var/lib/tosbuyer-sock/agent.sock` |
| `--agent-state-dir` | `/home/tosbuyer/state`; the server checks that `dev` **cannot** read it |
| `--workspace-root` | a directory sources and offer files may be taken from; repeatable |
| `--results-dir` | where results are written; must not be writable by group or others |

It refuses to start when `VAULT_URL` is set, when it can read the agent's
state directory, when the socket is missing, or when it runs as the account
that owns the socket.

### 7.1 Claude Code

```bash
claude mcp add --scope user --transport stdio tos-buyer -- \
  /usr/local/bin/tos-service-buyer-mcp \
  --agent-socket /var/lib/tosbuyer-sock/agent.sock \
  --agent-state-dir /home/tosbuyer/state \
  --workspace-root /home/dev/src \
  --results-dir /home/dev/tos-results
```

Everything after `--` is the server's own command line. `--scope user` makes
the server available in all your projects and keeps it out of shared project
files; the paths are yours, so a project `.mcp.json` is not the right place.
If you prefer the file form, the same entry in `.mcp.json` is:

```json
{
  "mcpServers": {
    "tos-buyer": {
      "command": "/usr/local/bin/tos-service-buyer-mcp",
      "args": ["--agent-socket", "/var/lib/tosbuyer-sock/agent.sock",
               "--agent-state-dir", "/home/tosbuyer/state",
               "--workspace-root", "/home/dev/src",
               "--results-dir", "/home/dev/tos-results"]
    }
  }
}
```

`tos_buyer_request_payment` can wait up to 300 seconds. Claude Code's
default tool timeout is far longer; if you have set `MCP_TOOL_TIMEOUT` or a
per-server `timeout` (milliseconds), keep it above 300000.

### 7.2 Codex

In `~/.codex/config.toml`:

```toml
[mcp_servers.tos-buyer]
command = "/usr/local/bin/tos-service-buyer-mcp"
args = ["--agent-socket", "/var/lib/tosbuyer-sock/agent.sock",
        "--agent-state-dir", "/home/tosbuyer/state",
        "--workspace-root", "/home/dev/src",
        "--results-dir", "/home/dev/tos-results"]
tool_timeout_sec = 330
```

`codex mcp add tos-buyer -- /usr/local/bin/tos-service-buyer-mcp …` writes
the same entry. Codex's default `tool_timeout_sec` is 60 seconds, shorter
than a payment wait; set it above 300 as shown, or ask the model to call
`tos_buyer_request_payment` with `wait_seconds` below the timeout and call it
again while it reports `awaiting_confirmation`.

The MCP client syntax above follows the clients' public documentation as of
this guide's date; check it against your client's version.

## 8. Buying

Ask the model, in plain language, to use the `tos_buyer_*` tools. Every
chain-derived value names the finalized checkpoint it was read at. Text from
providers is returned between `<<<UNTRUSTED provider data …>>>` markers: it
is data from a third party, never instructions.

1. **Find the offer.** Put the provider's offer file under a workspace root.
   **[pending #81]** `tos_buyer_quote` with `capability_id`,
   `capability_version` and `offer_file` (its absolute path) verifies the
   offer at one finalized checkpoint and builds the Quote locally (`source`
   `local`, the default). It returns `quote_id`, the price, storage fee,
   payment, response SLA, refund claim window, the Quote's expiry (15 minutes
   for a local Quote) and `carriable`. A Quote with `carriable = false`
   cannot be prepared; `not_carriable_item` says why.
   `tos_buyer_search` with a `capability_id` lists that Capability's verified
   versions. A gateway Quote (`source` `gateway`) or a text search needs a
   gateway or catalog in the agent configuration (`gateway_url`,
   `gateway_ca_file`, `gateway_token_file`, `catalog_dir`; adapter spec 2.4,
   in #81); the pilot does not need one.
2. **Prepare.** `tos_buyer_prepare` with `quote_id`, `source_path` (a
   directory or POSIX tar under a workspace root) and an `idempotency_key`
   (16 to 64 characters of `[A-Za-z0-9_-]`; the same key returns the same
   purchase). The source is what the provider's manifest asks for. It is
   packed into a canonical archive of at most 1 MiB (or the Quote's smaller
   bound): regular files and directories only, names of
   `[A-Za-z0-9._+-]` and `/`. Prepare pays nothing; it returns a preview with
   the `request_hash` and a **purchase reference** (the first 16 hex digits of
   the `request_hash`, in groups of four). The **whole archive goes to the
   provider**; leave secrets out of the source directory.
3. **Request payment.** `tos_buyer_request_payment` with the `request_hash`
   puts the purchase in the confirmer's queue and waits for your decision.
4. **Confirm, on the custody terminal.** Switch to your custody login (a
   virtual console, another seat, or SSH from another device; **never** a
   terminal opened from your desktop, IDE, MCP client or multiplexer, and
   never `su`, `sudo -u` or `ssh localhost` from the `dev` account):

   ```bash
   tos-service-buyer confirm --agent-socket /var/lib/tosbuyer-sock/agent.sock
   ```

   (`--watch` keeps it open and shows each new purchase.) It refuses to run
   unless its input is a terminal owned by `tosbuyer` and controlled by its
   own session. Check, against what you discussed with the model:
   - the purchase reference;
   - the provider block, which is the provider's own text, not the
     protocol's;
   - Capability, version, provider Agent, actor and attestor;
   - price, storage fee, execution allowance and total attached;
   - what you get back on success and on no answer, the response deadline and
     the refund window;
   - the source member list, with sensitive-looking names highlighted
     (`.env`, `*.pem`, `id_*`, `.git/` and others);
   - the budget before and after.

   To pay, type the confirmation code shown at the end. The code appears only
   on this terminal and changes every presentation, so the model cannot know
   it. Three wrong codes withdraw the purchase; declining withdraws it too.
   The agent re-checks the offer and the budget and sends one `call` that pins
   the quoted terms; if anything changed, the send is refused and costs at
   most fees.
5. **Follow it.** `tos_buyer_request_payment` (called again) or
   `tos_buyer_status` reports `submitted`, `admitted`, then the request's
   state: `pending`, `responded`, or on the refund path `overdue`,
   `refundable`, `refunded`, `lapsed`, `swept`.
6. **Result.** Once the agent has accepted the result, `tos_buyer_result`
   writes `receipt.boc`, `artifact.tar`, `output.log` and `report.json` under
   `<results-dir>/<request_hash>/` and lists every digest as checked: the
   Receipt's cell hash equals the finalized `response_hash`, and it binds this
   purchase's Quote, source, price, provider, toolchain and manifest, with
   exit code 0. A Receipt is the provider's attested statement of those
   digests; it does **not** prove the computation was correct. Before
   acceptance the tool returns `MCP_BUYER_RESULT_NOT_READY`.

`tos_buyer_withdraw` cancels a purchase that is still awaiting confirmation;
`tos_buyer_purchases` lists purchases and the budget in use.

## 9. Refunds

If the provider does not answer by the response deadline, the agent sends
`expire` and then `claim_refund` on its own; the price returns to your
wallet. `tos_buyer_refund` only makes it run the due step now. These sends
cost network fees only, so they need no confirmation, and they are bounded by
`--max-lifecycle-sends`.

| Outcome | You pay | You get back |
|---|---|---|
| responded | price + storage fee + fees | the unused allowance |
| no answer, refunded in the window | storage fee + fees | price |
| no answer, refund window missed, swept | storage fee + fees | price (plus the cleanup bounty if your agent sweeps) |

The storage fee is not refunded. The refund needs the agent online between
the response deadline and the refund deadline; if it is offline for the whole
window the right to claim lapses, but a sweep, by anyone or by your agent
when it returns, still pays the price back to you. The confirmer warns when
the refund window is shorter than 24 hours.

## 10. Troubleshooting

### 10.1 Tool errors

A tool error carries `{"error": {"code", "disposition", "message",
"state"}}`. The message is fixed text; it never contains a key name or
provider text.

| Code | Meaning | What to do |
|---|---|---|
| `MCP_BUYER_BAD_INPUT` | an input breaks its pattern or bound, or a path is outside the roots | fix the input; check the workspace roots |
| `MCP_BUYER_NOT_FOUND` | no such Capability version, offer, Quote or purchase | check IDs; quote again |
| `MCP_BUYER_OFFER_INVALID` | finalized state does not verify the offer, Quote or manifest | do not buy; ask the provider for a current offer file |
| `MCP_BUYER_PROVIDER_NOT_ALLOWED` | the provider is not on the allow-list | change the custody configuration if intended |
| `MCP_BUYER_NOT_CARRIABLE` | the purchase could not be carried over the relays (the item is named) | check relays and the provider's key card; nothing was paid |
| `MCP_BUYER_CARD_WINDOW_TOO_LONG` | expiry, SLA and retention together exceed the 30-day key card | choose another offer |
| `MCP_BUYER_OVER_BUDGET` | a per-call, window, count, unconfirmed or lifecycle bound | wait for the window, withdraw unconfirmed purchases, or raise the limit in custody |
| `MCP_BUYER_QUOTE_EXPIRED` | the Quote expired or the terms changed before the send | quote and prepare again |
| `MCP_BUYER_CONFLICT` | an idempotency key reused with other inputs, or a purchase in another phase | use a new key; check `tos_buyer_status` |
| `MCP_BUYER_DECLINED` | you declined | none |
| `MCP_BUYER_RESULT_NOT_READY` | no accepted result yet | retry after a while |
| `MCP_BUYER_DEPENDENCY_UNAVAILABLE` | no RPC quorum, or a relay or gateway unreachable; nothing was sent | check endpoints, forwards and relays; retry |
| `MCP_BUYER_AGENT_UNAVAILABLE` | the agent socket does not answer | check the agent service and its log |
| `MCP_BUYER_AMBIGUOUS` | a `call` or refund send may have been submitted | do not repeat; `tos_buyer_status` resolves it from finalized history |
| `MCP_BUYER_PERMISSION_DENIED` | the socket peer's account may not call this method | run the MCP server as `dev`, the configured client uid |
| `MCP_BUYER_NOT_CONFIGURED` **[pending #81]** | a gateway Quote without a gateway, or a search with neither a source nor a `capability_id` | quote from the offer file, or search by `capability_id` |
| `MCP_BUYER_INTERNAL` | anything else | check the agent log |

A code the client does not know is treated as "do not retry".

### 10.2 Start-up refusals

| Message (abridged) | Cause |
|---|---|
| `VAULT_URL is set in the MCP server's environment` | remove it from the `dev` account's environment and the client's server entry |
| `the MCP server can read the buyer agent's state directory` | `dev` can read `/home/tosbuyer/state`; tighten the home and state directory modes |
| `the buyer agent's state directory cannot be checked` | `--agent-state-dir` names no existing directory |
| `the agent socket is not a socket` | start the agent first; check `--agent-socket` |
| `the MCP server runs as the account that owns the agent socket` | the client was started as `tosbuyer`; start it as `dev` |
| `the socket directory must be the agent's own, unwritable by group and closed to others` | recreate it as in section 3 (`2750`, owner `tosbuyer`) |
| `an https relay is configured but relay_ca_file pins no CA` | re-run `init` with `--relay-ca-file` |
| `VAULT_URL must name the tosctl vault` | the agent's environment lacks the vault file (`EnvironmentFile`) |
| `the confirmer's terminal is not owned by the custody account` | you started the confirmer from a `dev` terminal; log in as `tosbuyer` on a separate console or from another device |
| `the confirmer reads decisions only from a terminal` | do not pipe input into `confirm` |
| `buyerinit: the wallet needs funding` | fund the printed address, then run `init apply` again |
| `buyerinit: the outcome of an earlier send is not known yet` | wait a few minutes and run `init apply` again; it will not send twice |
| `buyerinit: an identity input changed after the Agent was registered` | restore the original wallet, controller, network and registry inputs |
| `buyerinit: RPC endpoint <n> does not serve the network's genesis` | that endpoint is for another network; check the forward |

### 10.3 Other checks

- The model's tool call times out during payment: raise the client's tool
  timeout (section 7) or use a smaller `wait_seconds`; the purchase is not
  lost, call `tos_buyer_request_payment` again.
- A purchase stays `pending` with no result: the agent keeps redelivering the
  task; after the response deadline it starts the refund path by itself.
- Evidence for the pilot **[pending]**: until `tos-service-buyer evidence`
  merges, keep the JSON outputs of `init`, `tos_buyer_status` and
  `tos_buyer_result`, and the SHA-256 of every binary you built.
