# Wallet transport delegation issuance

`tos-service-wallet transport-delegate` creates a transport key, builds the
existing 167-byte delegation, submits `DelegateAgentV1` with the existing relay
client and token, then waits for finalized membership before printing a public
JSON result. It does not introduce a controller authority or a registry opcode.
The `--action` review/sign command requires `--registry-config` and
`--registry-checkpoint` for delegation adds and withdrawals. It rechecks the
finalized predecessor and epoch after confirmation and before custody signs.

This command requires a reviewed test-network tuple and the frozen Registry v2
code hash. Pass the positive current finalized epoch with
`--authorization-epoch`. The wallet checks the epoch before signing, binds it
in both the delegation and the action, and confirms live admission at that
epoch using finalized state. Use the separately pinned December release to
reconcile any outstanding Registry v1 journal.

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
signer; it cannot silently select a second store. Each operation journals a fresh random 128-bit `mtv2-` vault ID before accessing
custody. The user-provided name is a label, never the ID of an existing payment
key. The key is generated **inside the vault**, Ed25519, non-extractable, using
`NewOnly`. Only the public key is
read. There is no plaintext seed file or seed argument. On a crash after vault
commit, the same record is read back; generation never overwrites it. Existing
extractable keys and other algorithms are refused. The vault enforces its
existing file ownership, permissions, encrypted save and locking rules.
`--key-name` is a label of at most 30 canonical characters. The generated vault
ID is 27 characters, below the existing CLI's 30-character table limit. The parser requires one complete
matching row; format changes refuse rather than guessing. Helper error bodies
are never printed.

## Configuration and invocation

`--transport-config` is an absolute, owner-private regular JSON file containing:

- `network`: `network_id` (`tos:global-id:2` or `tos:global-id:3`) and the exact
  approved bare-hex `genesis_root_hash` / `genesis_file_hash`;
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
The result contains only the delegation's canonical base64, digest and actual
vault key ID (the `key_name` field), which future transport signers can use.
Transport keys remain separate from packet encryption and controller keys.

## Confirming withdrawal

After submitting the original signed action, run `confirm-withdrawal` with
the same action JSON, the Registry config and checkpoint fence, and the exact
prior finalized block tuple from which the action was built
(`--prior-checkpoint`, `--prior-root`, `--prior-file`). The command reads the
authenticated predecessor and a fresh finalized post-state. It reports
`withdrawn` for a digest withdrawn in the same epoch or
`cleared_by_epoch_bump` for an absent formerly live digest after a proven bump.
It issues no signature or submission. Reconcile the exact action before
deciding whether to retry. After a finalized policy rotation, issue a fresh
delegation for the new epoch before reconnecting.

## Crash and retry rules

Keep both the vault and the journal. Repeat the **same arguments and journal**,
including the original `--key-name` label; the returned random vault ID is for
future transport signing, not a replacement label for this command:

1. The request/network/label and fresh internal vault key ID are saved before key creation.
2. The exact delegation and unsigned action (including nonce) are saved before
   controller signing. A declined prompt can be resumed without changing them.
3. The signed submission is atomically saved and synced before dispatch.
4. Expiry is checked before and again after the final finalized read, immediately
   before the dispatch marker. A delegation that has expired by then is never
   submitted; the journal is marked `expired`, and every rerun refuses without
   reading, signing, or sending. Start a new operation in a fresh journal.
5. A dispatching marker is synced before calling the relay. Every later rerun
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
