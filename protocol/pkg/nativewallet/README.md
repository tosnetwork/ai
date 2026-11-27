# Wallet transport delegation issuance

`tos-service-wallet transport-delegate` creates a transport key, builds the
existing 167-byte delegation, submits `DelegateAgentV1` with the existing relay
client and token, then waits for finalized membership before printing a public
JSON result. It does not introduce a controller authority or a registry opcode.
The original `--action` review/sign command remains available unchanged.

This is **test-network-only**. The exact network tuple must be in
`agenttransport`'s compiled allowlist. The command accepts only explicit
`test-network-legacy-epoch-zero` mode with `--authorization-epoch 0`, because
the deployed registry has no epoch field. Policy A -> B -> A remains the known
test-network revocation gap. Neither a mode string nor a config can enroll a
production or unknown genesis. The library tests also exercise synthetic
explicit-epoch snapshots; the command does not offer a fabricated epoch adapter.

## Custody

Use `--tosctl`, `--tosctl-sha256`, and `--tosctl-config` as for action signing.
Also supply `--vault-helper` and `--vault-helper-sha256` naming the existing
`secrets-vault-cli` executable. Build it with `cargo build -p secrets-vault
--bin secrets-vault-cli --features secrets-vault-cli --locked` in the helper's
workspace. Both executables are hashed and executed from sealed immutable
snapshots on Linux. The vault helper is the existing encrypted-storage CLI,
not a caller-defined signing protocol.

`VAULT_URL` is the same credential-bearing environment input as for the
controller signer. The transport view derives its custody location from that
signer; it cannot silently select a second store. The key is generated **inside
the vault**, Ed25519, non-extractable, using `NewOnly`. Only the public key is
read. There is no plaintext seed file or seed argument. On a crash after vault
commit, the same record is read back; generation never overwrites it. Existing
extractable keys and other algorithms are refused. The vault enforces its
existing file ownership, permissions, encrypted save and locking rules.
`--key-name` is limited to 30 canonical characters because the existing CLI's
public metadata table truncates longer names. The parser requires one complete
matching row; format changes refuse rather than guessing. Helper error bodies
are never printed.

## Configuration and invocation

`--transport-config` is an absolute, owner-private regular JSON file containing:

- `network`: `network_id` (`tos:global-id:2` or `tos:global-id:3`) and the exact
  approved bare-hex `genesis_root_hash` / `genesis_file_hash`;
- `mode`: `test-network-legacy-epoch-zero`;
- `rpc`: three to eight independent endpoints, and `quorum`: a strict majority;
- `registry_code_boc_base64` and independently pinned `registry_code_hash`;
- `min_finalized_checkpoint`: the operator's known checkpoint floor;
- `relay_url`, with `insecure_relay` only for an explicitly selected plaintext
  test relay. `TOS_SERVICE_RELAY_TOKEN` supplies the existing relay bearer token.

The existing quorum-backed direct resolver reads deterministic registry
accounts. These are quorum reads, **not new cryptographic proof verification**.
The tuple and registry pin are checked by the transport verifier; the native
locator/action boundary uses the same genesis with `sha256:` hash prefixes.
The relay acknowledgement is never treated as finalized state.

Pass `--agent`, `--key-name`, `--journal` (one absolute owner-private directory
per operation), repeated `--authority-controller`, and optional
`--purposes` (1..7, default 7), `--lifetime-seconds` (default 86400, maximum
31536000), `--max-credential-seconds` (default 21600, maximum 604800).
The full native action is reviewed and its complete action hash must be typed
before controller signing. `--timeout` defaults to ten minutes, maximum thirty.
The timeout also cancels a blocked confirmation prompt; input is capped at
256 bytes. The command has one prompt reader which ends on input or process
exit after cancellation. No success or delegation is printed before a fresh
`VerifyDelegation` passes.
The result contains only the delegation's canonical base64, digest and key name.
Transport keys remain separate from packet encryption and controller keys.

## Crash and retry rules

Keep both the vault and the journal. Repeat the **same arguments and journal**:

1. The request/network/key name is saved before key creation.
2. The exact delegation and unsigned action (including nonce) are saved before
   controller signing. A declined prompt can be resumed without changing them.
3. The signed submission is atomically saved and synced before dispatch.
4. A dispatching marker is synced before calling the relay. Every later rerun
   only reconciles; it neither signs again nor resubmits. A lost acknowledgement
   can become success only through a fresh finalized read and live-delegation
   verification, never a cached prior success.

A crash after the dispatch marker but before the RPC actually leaves is
intentionally unresolved. The tool cannot distinguish it from a lost send.
It will time out without success and will not pay for another attempt. Preserve
the record for read-only/operator reconciliation; do not delete it or create a
second operation as an automatic retry. This phase does not implement automatic
re-voting or a delegation-withdrawal workflow. An expired or revoked delegation
cannot be reported as a successful live delegation, even on a completed rerun.

Records and locks are owner-private; a process-wide nonblocking OS lock rejects
concurrent use of the operation directory. Saves use a private temporary file,
file sync, atomic replacement, and directory sync. A process dying releases the
OS lock; never delete the stable lock file. Local storage rollback, deletion or
multiple independently chosen journals is outside this single-operation guard.

## Verification

CI builds the vault helper alongside its already pinned tosctl. For local Go
and make runs, set `GOWORK=off`, `TOS_SERVICE_TOSCTL`, its
`TOS_SERVICE_TOSCTL_SHA256`, `TOS_SERVICE_TOKEN_CLI_REPO`, and optionally
`TOS_SERVICE_VAULT_HELPER` (otherwise the test looks for `secrets-vault-cli`
beside tosctl). Missing custody helpers fail, never skip.

The tests include real encrypted-key storage and a real controller signature
through shared custody, plus a finalized-state harness, strict config/network
refusals, epoch bounds, journal ordering, concurrent-lock refusal, and lost-ack
reruns. They are not live relay or production registry acceptance evidence.
The wire is unchanged: section 17 item 2's frozen delegation vectors and
independent reproducer remain the conformance evidence.
