# Provider deployment template

This template installs one dedicated, root-owned containerd boundary for the
fixed Native software-work executor. It is deliberately not a gateway service
and exposes no public port. Finalized TOS state, not this daemon, remains the
authority for Capability and payment state.

The systemd unit hides the distribution-level `/etc/containerd/conf.d` import
directory with an empty read-only mount before this daemon starts. The supplied
configuration also disables CRI, NRI, and restart-management plugins so
Kubernetes configuration, runtime mutation hooks, or host restart policy
cannot silently widen the fixed executor surface. Startup requires the content,
metadata, overlayfs, and runc task plugins used by the reviewed backend.

## Host prerequisites

- Linux with cgroup v2, containerd 2.x, runc v2, and overlayfs;
- the reviewed `software-work-execute` binary built from the pinned release;
- the exact digest-qualified OCI image committed by the Capability manifest;
- a separate unprivileged `tosctl` vault for the execution signer; and
- an operator with root access for installation and each privileged execution
  run by hand; a provider runtime reaches the executor through the
  [executor service](#executor-service-an-unprivileged-provider-node) instead
  and needs no privilege.

Do not reuse `/run/containerd/containerd.sock`, Docker's daemon, or a
Kubernetes containerd. Do not grant a gateway or provider account access to
the private socket and do not add a general `sudo` rule for
`software-work-execute`. Raw containerd access is equivalent to host-root
authority; an unprivileged provider process uses the executor service below.

## Install the private daemon

Review both template files, then install them as root:

```bash
install -d -o root -g root -m 0755 /etc/tos-service
install -o root -g root -m 0600 deploy/provider/containerd.toml \
  /etc/tos-service/containerd.toml
install -o root -g root -m 0644 deploy/provider/tos-service-containerd.service \
  /etc/systemd/system/tos-service-containerd.service
systemctl daemon-reload
systemctl enable --now tos-service-containerd.service
```

Before proceeding, require all of these checks to pass:

```bash
systemctl is-active --quiet tos-service-containerd.service
test "$(stat -c '%U:%G:%a' /run/tos-service-containerd)" = root:root:700
test "$(stat -c '%U:%G:%a' /run/tos-service-containerd/containerd.sock)" = root:root:600
ctr --address /run/tos-service-containerd/containerd.sock plugins ls
```

The unit tightens the socket (and the ttrpc socket beside it) to `0600` after
the daemon reports readiness; containerd itself creates them `0660`, which the
executor refuses. It runs with
`UMask=0022` because the overlayfs snapshotter creates each layer's root
directory itself: under a stricter umask those become `0700` and the
unprivileged sandbox user cannot traverse `/`. The daemon's root and state
directories remain `0700`, so this widens nothing on the host.

Build the reproducible OCI archive with
`build/software-work-go-1.26.5/build.sh` (it verifies the toolchain ZIP and the
resulting index digest). Import it into namespace `tos-service-paid-work`,
unpacked for `overlayfs`. The executor looks the image up by its exact
digest-qualified reference, so that reference must exist as an image name.
The pinned value is the OCI image *index* digest (the SHA-256 of the archive's
`index.json`). Never use a mutable tag without it: the plain `$name` tag that the
import creates is not used by the executor and may be removed after tagging.

```bash
socket=/run/tos-service-containerd/containerd.sock
name=docker.io/tosnetwork/software-work-go:1.26.5
digest=sha256:9624bca74096f810c5b24e489521dde124fadcfa1808581648b38bdc1ba1b105
test "sha256:$(tar -xOf software-work-go-1.26.5.oci.tar index.json | sha256sum | cut -d' ' -f1)" = "$digest"
ctr --address "$socket" -n tos-service-paid-work images import \
  --index-name "$name" --snapshotter overlayfs software-work-go-1.26.5.oci.tar
ctr --address "$socket" -n tos-service-paid-work images tag "$name" "$name@$digest"
ctr --address "$socket" -n tos-service-paid-work images ls "name==$name@$digest" | grep -qF "$digest"
ctr --address "$socket" -n tos-service-paid-work images check
```

Then run the live backend conformance suite against this daemon. Build the
test binary as an unprivileged user and run only the binary as root:

```bash
GOWORK=off go test -c -o containerdbackend.test ./pkg/executor/containerdbackend
install -d -o root -g root -m 0700 /run/tos-service-containerd/test-fifos
env TOS_AI_CONTAINERD_TEST_SOCKET="$socket" \
  TOS_AI_CONTAINERD_TEST_NAMESPACE=tos-service-paid-work \
  TOS_AI_CONTAINERD_TEST_FIFO_DIR=/run/tos-service-containerd/test-fifos \
  TOS_AI_CONTAINERD_TEST_IMAGE_REFERENCE="$name@$digest" \
  TOS_AI_CONTAINERD_TEST_IMAGE_DIGEST="$digest" \
  ./containerdbackend.test -test.run 'TestContainerdBackendLive(Conformance|Workspace)$' -test.v
```

Both tests must pass before the host serves paid work.

Known limitation: the runc v2 shim of this daemon still keeps its runc state
under the host-wide `/run/containerd/runc/<namespace>` and its shim sockets
under `/run/containerd/s`, beside any distribution containerd. Their modes are
set explicitly (not by the umask), but the private daemon does not yet have its
own runc root.

## Paid path: admit, then execute

`software-work-execute paid` is the only standalone way to execute paid work.
It refuses to run anything until finalized TOS state proves the request:

1. every flag and the rail config are validated, the Quote package is checked
   against the configured provider offer and `--actor`, and the containerd
   executor, journal, artifact store and slot directory are opened. The
   manifest must state a non-zero `retention_seconds`. Any missing or
   malformed piece refuses the run before admission;
2. `railgate` `Admit` verifies the call, the pending request, the Quote and
   input binding and the deadline slack at a fresh finalized checkpoint and
   creates an at-most-once slot keyed by `(quote_commitment, actor,
   request_id)`;
3. the verified request is checked against this executor (actor, request,
   manifest, toolchain, a positive price, a representable retention
   deadline); a refusal abandons the slot before anything runs;
4. `Run` re-verifies at another fresh checkpoint immediately before
   execution and durably marks the slot started;
5. the run's artifact and report are retained first, until the response
   deadline plus the manifest's `retention_seconds`; a successful run's
   objects are then re-read and bound into the `SoftwareWorkReceiptV1` whose
   cell hash is recorded with `Complete`; any other outcome is recorded with
   `Fail` and is never attested;
6. a final fresh `Recheck` reports whether respond may be sent now.

The paid state directory holds the slots, the resolver checkpoints, the job
journal and the artifacts. It must be **persistent and shared by every paid
run of the provider offer**: deleting or splitting it would forget which
requests were already admitted. One process owns it at a time; a concurrent
run fails to open it rather than share it.

**Run exactly one provider runtime per Service Actor and offer.** The
at-most-once guarantee holds only within one slot directory. Two paid state
directories for the same offer, or `software-work-execute paid` next to
another provider runtime that keeps its own slots for the same actor (for
example an agent runtime with its own state directory), can each admit and
execute the same request. Pick one runtime for an actor and route every
paid request for it through that runtime's single slot directory.

The rail config is a private JSON file owned by the executor identity:

```json
{
  "schema": "tos.ai.railgate-config.v1",
  "network": {
    "network_id": "tos-testnet",
    "genesis_root_hash": "sha256:...",
    "genesis_file_hash": "sha256:..."
  },
  "rpc_endpoints": ["https://rpc-a:443", "https://rpc-b:443", "https://rpc-c:443"],
  "quorum": 0,
  "registry_code_boc_file": "/etc/tos-service/registry-code.boc",
  "registry_code_hash": "tvm-cell-sha256:...",
  "actor_code_hash": "tvm-cell-sha256:...",
  "provider_agent_id": "agent_...",
  "capability_id": "cap_...",
  "version": "1.0.0",
  "manifest_file": "/etc/tos-service/manifest.cbor",
  "respond_budget_seconds": 120
}
```

`quorum: 0` means a strict majority of the endpoints. Agreement among
endpoints one operator runs is not independent finality; choosing
independent operators is a configuration responsibility. The manifest file
must be the canonical CBOR the Capability version publishes, and its
`toolchain_digest` must be the executor's pinned image. The sandbox runs
under exactly the manifest's `limits`: `cpu_millis`, `memory_bytes`,
`scratch_bytes` (the workspace disk bound), `output_bytes` and
`wall_clock_millis`, which is also the execution budget reserved before the
response deadline. Each must be non-zero and no larger than the frozen
preset (120 000 CPU ms, 1 GiB memory, 2 GiB disk, 16 MiB output, 180 s);
a manifest outside those bounds is refused before admission. The default
mode takes no manifest and runs under the frozen preset (with an optional
tighter `--output-bytes`).

```bash
/usr/local/libexec/tos-service/software-work-execute paid \
  --rail-config /etc/tos-service/rail.json \
  --containerd-socket /run/tos-service-containerd/containerd.sock \
  --fifo-dir /run/tos-service-containerd/paid-fifos \
  --state-dir /var/lib/tos-service-provider/paid \
  --source /var/lib/tos-service-provider/inbox/REQUEST/source.tar \
  --quote-package /var/lib/tos-service-provider/inbox/REQUEST/quote.pb \
  --buyer-wallet 0:BUYER_WALLET_HEX \
  --actor 0:SERVICE_ACTOR_HEX \
  --request-id REQUEST_ID \
  --call-lt CALL_LT --call-hash CALL_TX_HASH_HEX \
  --execution-id sha256:EXECUTION_ID --input-digest sha256:INPUT_DIGEST
```

The command prints one JSON object (`status`, `exit_code`, `actor`,
`request_id`, `quote_commitment`, `slot_state`, and on completion
`response_hash`, `receipt_boc_base64`, `retain_until_unix`, `respond_check`
and the `outcome`; `error` explains every other status) and exits with:

| Exit | `status` | Meaning and operator action |
|---|---|---|
| 0 | `completed` | Admitted, executed once, Receipt hash recorded. Sign respond through `tosctl` only while `respond_check` is `passed`; otherwise rerun the check before the response deadline. |
| 0 | (none) | `-h`: usage printed, nothing run. |
| 1 | `refused` | Invalid flags or config, or a local dependency (executor, journal, store) cannot be opened. Nothing was admitted or run; fix and retry. |
| 1 | `unavailable` | No finalized checkpoint could be opened (resolver or quorum outage), or the slot store failed before a slot existed. Nothing was admitted or run; retry. |
| 2 | `usage` | The command line does not parse. |
| 3 | `already_taken` | The request already has a slot (admitted, completed, failed or abandoned). It is not executed again. |
| 4 | `not_pending_now` | Admitted, but the pre-execution check found the request no longer pending with room to execute and respond. The slot is abandoned; nothing ran. |
| 5 | `ambiguous` | A run may have started without a recorded outcome (a crash, or a result that could not be recorded), or the slot store failed in a way that left a slot behind. Never rerun or respond; the buyer's refund path applies. |
| 6 | `not_admitted` | Finalized state at an open checkpoint does not prove the claim (unknown call, other terms, incomplete history, too close to the deadline). A read that fails after the checkpoint opened also lands here. No slot was created; nothing ran. |
| 7 | `execution_failed` | The execution ran and did not succeed. The slot is failed and is never attested. |
| 8 | `refused_before_execution` | Admitted, but the verified request does not fit this executor (actor, request, manifest, toolchain, price or retention). The slot is abandoned; nothing ran. |

A resolver outage during the pre-execution re-verification (step 4) cannot
be told apart from a request that stopped being pending; it abandons the
slot and reports `not_pending_now`.

The input digest is the value the paid call committed. How a transport
derives it from the source archive is that transport's rule; the Receipt
binds the digest of the archive actually executed, so stage only the archive
the buyer delivered for this request.

## Pre-admitted jobs (default mode)

Without a subcommand the executor runs a job whose admission its caller has
already proved, for example a provider process that owns its own `railgate`
slots. It performs no chain verification, so **never use it directly for paid
work**. For each job, create a new private directory and copy—not link—the
already content-verified source archive into it:

```bash
install -d -o root -g root -m 0700 /var/lib/tos-service-provider/job-UNIQUE
install -o root -g root -m 0600 SOURCE.tar \
  /var/lib/tos-service-provider/job-UNIQUE/source.tar
install -d -o root -g root -m 0700 \
  /var/lib/tos-service-provider/job-UNIQUE/state \
  /run/tos-service-containerd/job-UNIQUE-fifos

/usr/local/libexec/tos-service/software-work-execute \
  --containerd-socket /run/tos-service-containerd/containerd.sock \
  --fifo-dir /run/tos-service-containerd/job-UNIQUE-fifos \
  --state-dir /var/lib/tos-service-provider/job-UNIQUE/state \
  --source /var/lib/tos-service-provider/job-UNIQUE/source.tar \
  --quote tvm-cell-sha256:ACCEPTED_QUOTE_COMMITMENT \
  --execution-id sha256:UNIQUE_EXECUTION_ID \
  --input-digest sha256:CANONICAL_INPUT_DIGEST \
  --retain-until RETAIN_UNTIL_UNIX_SECOND
```

The source archive is unpacked into a private directory for the run. Only
regular files and directories are accepted; links, devices, duplicate paths,
path traversal and sparse entries are refused, as is an archive whose
entries claim more bytes than the archive itself holds or that would create
more than 32 768 files and directories. A refused archive writes nothing.

`--retain-until` gives the job's artifact and report a retention deadline;
without it the job's retention record stays pending and the objects are
never swept (see [Artifact retention](#artifact-retention)). The caller must first resolve the exact Capability
version, Accepted Quote, and the pending Service Actor request `(actor,
request_id)` that was called under the quoted `terms_hash` and
`request_hash`. A crash-ambiguous execution ID is never reused. The executor
output and content-addressed objects are public evidence; they contain no
signing credential.

## Executor service: an unprivileged provider node

A provider runtime that drives the default mode as its own child process
must itself be the executor identity, which means root: the executor accepts
only a containerd socket and state, source and FIFO directories owned by its
own user. `software-work-executord` removes that requirement. It is a small
root-run service that is the only process opening the private containerd
socket, and it offers exactly one local caller uid exactly one operation
over a Unix socket. The provider node, its `tosctl`, its vault and its
network listeners then run as an ordinary user.

Do not replace it with either shortcut: giving the node's user the containerd
socket gives that user host root, and a `sudo` rule for `software-work-execute`
lets an unprivileged caller choose the paths a root process reads and writes.

### What the allowed uid can make root do

Exactly this, and nothing else:

- run **one bounded sandboxed job at a time** (`--max-executions`, default 1)
  under the frozen V1 policy: the pinned image, `go test ./... -count=1`,
  uid/gid 65532, no network, no device, read-only root, no host mount, and
  limits that a request may only tighten (each of `cpu_millis`,
  `memory_bytes`, `scratch_bytes`, `output_bytes`, `wall_clock_millis` must be
  non-zero and at most the frozen preset; anything else is refused before
  the request's payload is read);
- **stage one source per running job on disk**, under
  `/var/lib/tos-service-executor/staging`, for the length of the run. The
  unpacked tree can never be larger than the archive that was sent (at most
  16 MiB) nor hold more than 32 768 files and directories: an archive with
  sparse entries, or whose entries claim more bytes than the archive holds,
  is refused before anything is written. Nothing a caller sends is unpacked
  onto `/run`;
- **fill bounded storage**: per job a journal record of at most 32 KiB, a
  report and an artifact of at most the job's output bound plus the report
  (the store refuses any object over 64 MiB). Every job's objects get a
  deadline no later than `--max-retention` (31 days) after the job
  completed, and the store admits at most 65 536 jobs with a deadline, so
  the worst case is 65 536 retained jobs of about 16 MiB each, roughly
  1 TiB. Long before that the free-space floor applies: a new job is
  refused, with nothing claimed, while the state filesystem has less than
  `--min-free-bytes` (4 GiB) or `--min-free-inodes` (262 144) free. Swept
  on schedule, storage is bounded by what one caller can run in 31 days;
- hold at most 256 MiB of request and response payloads in the service's
  memory across all connections; the unit caps the whole process at 1 GiB.

A request carries no path, image, command, argument, environment, mount,
network, device or user: there is no field for any of them and an unknown
field refuses the request. The service stages everything in its own
directories; a caller never reads them and gets the outcome, artifact and
report as bytes in the response. The allowed uid also spends execution
identities: an identity whose run failed or was interrupted is ambiguous for
good, exactly as with the CLI.

**One caller identity.** The service keeps no separation between callers:
execution identities, retention deadlines and execution slots are shared by
whoever is allowed. It therefore serves exactly one uid (`--allow-uid`) and
refuses to start with none, a list, a name, or the id of no real user. One
provider node per Service Actor needs one identity; a second node needs its
own service instance and state directory.

### Socket permission model

| Path | Owner | Mode | Purpose |
|---|---|---|---|
| `/run/tos-service-executor` | `root:<socket gid>` | `0750` | only root and the group can reach the socket |
| `/run/tos-service-executor/executor.sock` | `root:<socket gid>` | `0660` | only root and the group can connect |
| `/run/tos-service-executor-private` | `root:root` | `0700` | container stdio FIFOs only |
| `/var/lib/tos-service-executor` | `root:root` | `0700` | journal, artifact store and staged workspaces |

systemd creates the runtime directories `root:root 0700`; the executor opens
the first one to the group itself, and only after the socket inside it has
its final mode. The file modes only decide who can connect. Who is served is
decided per connection from the kernel's peer credential (`SO_PEERCRED`)
against `TOS_EXECUTOR_ALLOWED_UID`: a member of the group with another uid
is refused, and so is root unless it is the allowed uid. Both ids must be
numeric. Neither may be 65534, which is what the kernel reports for an
identity that has no mapping, nor 4294967295. Use a dedicated group whose
only member is the allowed user. The client checks the other direction: it
refuses a socket that is not served by root.

### Install

Build `software-work-executord` from the pinned release and install it next
to `software-work-execute`. With the private daemon running and the image
imported as above:

```bash
install -o root -g root -m 0755 software-work-executord \
  /usr/local/libexec/tos-service/software-work-executord
groupadd --system tos-executor
usermod -a -G tos-executor PROVIDER_USER
install -o root -g root -m 0600 deploy/provider/executor.env.example \
  /etc/tos-service/executor.env
# Set both values in /etc/tos-service/executor.env:
#   TOS_EXECUTOR_ALLOWED_UID=$(id -u PROVIDER_USER)
#   TOS_EXECUTOR_SOCKET_GID=$(getent group tos-executor | cut -d: -f3)
install -o root -g root -m 0644 deploy/provider/tos-service-executor.service \
  /etc/systemd/system/tos-service-executor.service
install -o root -g root -m 0644 deploy/provider/tos-service-executor-gc.service \
  /etc/systemd/system/tos-service-executor-gc.service
install -o root -g root -m 0644 deploy/provider/tos-service-executor-gc.timer \
  /etc/systemd/system/tos-service-executor-gc.timer
systemctl daemon-reload
systemctl enable --now tos-service-executor.service
systemctl enable --now tos-service-executor-gc.timer
```

The timer is part of the installation, not an option: nothing else collects
expired jobs, and at the store's record bound every new job is refused with
`retention_full`.

Then require:

```bash
systemctl is-active --quiet tos-service-executor.service
test "$(stat -c '%U:%a' /run/tos-service-executor)" = root:750
test "$(stat -c '%U:%a' /run/tos-service-executor/executor.sock)" = root:660
test "$(stat -c '%U:%G:%a' /run/tos-service-executor-private)" = root:root:700
test "$(stat -c '%U:%G:%a' /var/lib/tos-service-executor)" = root:root:700
systemctl is-enabled --quiet tos-service-executor-gc.timer
systemctl is-active --quiet tos-service-executor-gc.timer
systemctl start tos-service-executor-gc.service   # one sweep now; must exit 0
journalctl -u tos-service-executor-gc.service -n 12 --no-pager   # its JSON report
```

and, as the provider user, a `describe` call that reports `ready: true` and
the pinned image digest. `ready` means the daemon answers **and** holds the
pinned image unpacked; a new job is refused, with nothing claimed, while it
is false. A `describe` that is ready does not prove a job runs: finish with
one real job through the socket.

On a host with passwordless `sudo`, `make test-privileged` runs the
real-uid and live checks: it builds the test binaries as the invoking user,
runs only those binaries as root, and fails (it does not skip) when it
cannot. Its last check starts the daemon in a transient systemd unit that
carries every `[Service]` setting of the shipped unit file except its paths,
runs a real job through that socket as an unprivileged uid, and then runs
the collection command under the shipped collection unit's settings against
the still-running daemon. A sandbox setting the code cannot live under fails
there, before it reaches a host.

The unit is ordered after and requires `tos-service-containerd.service`. It
runs with no network namespace access, a read-only system, no home
directories, other processes hidden, `CAP_CHOWN` as its only capability
(used once, to give the socket to the group), and memory and task caps. It
cannot mount anything and does not need to: the container's specification is
built from the runtime defaults and the fixed isolation settings, never from
the image's own configuration, which would make the client mount the
container's snapshot in the executor process. The
private containerd unit and its socket modes are unchanged: the socket stays
`root:root 0600` and only this service and operator-run
`software-work-execute` open it. **Do not run the two against the same state
directory**, and do not run a by-hand job while the service is executing
one: both would use the one private namespace.

### When a job fails

A caller only ever gets a fixed status and message. The cause is in the
service's own log, which only root reads:

```bash
journalctl -u tos-service-executor.service -n 50 --no-pager
```

A line `backend run failed: "..."` (or `readiness`, or `residue` at start)
carries the runtime's own error for the `execution_failed` or `unavailable`
that follows it. The text is cut to 2048 bytes and escaped, because it can
quote names out of a caller's archive.

### Stopping, and cleaning up after a kill

On `systemctl stop` the service stops accepting and waits up to
`--stop-grace` (200 s, past the frozen 180 s wall clock) for a running job
to record its outcome, then cancels it and waits for its container to be
removed. `TimeoutStopSec=270s` is the outer limit: **if the service is still
waiting then, systemd sends SIGKILL**, as it does on an out-of-memory kill.
A killed service leaves, for the job that was running:

- its execution identity `ambiguous` for good (never rerun, never attest);
- possibly its container and snapshot in the private namespace;
- possibly its unpacked source under
  `/var/lib/tos-service-executor/staging/workspaces/`.

The service refuses to start while either of the last two is present; it
never adopts or silently removes them. After five failed starts in five
minutes the unit stays failed. Clean up as root, then start it again:

```bash
socket=/run/tos-service-containerd/containerd.sock
ctr --address "$socket" -n tos-service-paid-work tasks ls
ctr --address "$socket" -n tos-service-paid-work tasks kill -s SIGKILL ID   # if listed
ctr --address "$socket" -n tos-service-paid-work containers rm ID
ctr --address "$socket" -n tos-service-paid-work snapshots --snapshotter overlayfs rm ID
chmod -R u+rwx /var/lib/tos-service-executor/staging/workspaces
rm -rf /var/lib/tos-service-executor/staging/workspaces/*
systemctl reset-failed tos-service-executor.service
systemctl start tos-service-executor.service
```

Never delete the journal or the artifact store to "fix" a start.

### Protocol

One request per connection on a stream socket; the client half-closes after
its request and the service closes after its response.

```
request  = length(4 bytes, big endian) header-JSON source-bytes EOF
response = length(4 bytes, big endian) header-JSON artifact-bytes report-bytes EOF
```

The request header (at most 4 KiB) is
`{"schema":"tos.ai.executor-service.request.v1","operation":"describe"}` or

```json
{
  "schema": "tos.ai.executor-service.request.v1",
  "operation": "execute",
  "execute": {
    "execution_id": "sha256:...",
    "quote_commitment": "tvm-cell-sha256:...",
    "input_digest": "sha256:...",
    "manifest_digest": "sha256:...",
    "limits": {"cpu_millis": 0, "memory_bytes": 0, "scratch_bytes": 0, "output_bytes": 0, "wall_clock_millis": 0},
    "retain_until_unix": 0,
    "source_digest": "sha256:...",
    "source_bytes": 0
  }
}
```

followed by exactly `source_bytes` (1 to 16 MiB) bytes of the USTAR source
archive whose SHA-256 is `source_digest`. The response header (at most
16 KiB) is `{"schema":"tos.ai.executor-service.response.v1","status":...}`
with `describe` (version, commit, image digest and reference, the frozen
limits, payload bounds, `max_executions`, `default_retention_seconds`,
`max_retention_seconds`, `ready`) or `outcome` (the same object the CLI
prints) with `retain_until_unix`, the deadline this request gave the
objects. For an outcome the artifact and report bytes follow in that order,
their sizes and digests being the outcome's descriptors. An unknown field,
another schema, data after the header or after the payload, an oversize
length or a digest mismatch is refused.

| `status` | Meaning for the caller |
|---|---|
| `ok` | The response carries the description, or a recorded successful outcome and its objects. |
| `not_allowed` | The peer uid is not the allowed uid. Nothing was read. |
| `invalid_request` | Malformed, oversize, another version, trailing data, or bytes that do not match their digest. Nothing was claimed. |
| `limits_refused` | A limit is zero or looser than the frozen preset. Nothing was claimed. |
| `timeout` | The request was not received within the read deadlines (10 s header, 30 s payload). |
| `busy` | A bound is reached: 8 connections, `--max-executions` running jobs, or the in-flight byte budget. Nothing was claimed; retry. |
| `in_progress` | This execution id is running now. Send the same request later to get its outcome. |
| `ambiguous` | The execution id was claimed and has no recorded outcome (a crash, a failed run, a forced stop). It is never run again; never attest it. |
| `conflict` | The execution id is bound to other commitments or other limits. |
| `execution_failed` | The run started and did not produce a recorded success. The id is `ambiguous` from now on. |
| `unavailable` | The backend is not ready (daemon down, image missing or not unpacked), or the journal or store cannot serve now. A new run was not claimed; retry. |
| `storage_full` | The state filesystem is below its free-byte or free-inode floor. Nothing was claimed; sweep. |
| `retention_full` | The store holds its maximum of jobs with a deadline. A new run was not claimed; sweep. |
| `objects_unavailable` | The outcome is recorded but its objects were swept after their retention ended. |

Every refusal carries a fixed message and none of the caller's data.

**Idempotence.** The journal is keyed by `execution_id`, as in the CLI. An
identity is bound to its quote commitment, input digest, source digest,
manifest digest **and limits**: a repeated request with all of them equal
returns the journaled outcome and its stored objects without running
anything, and any difference is a `conflict`. (The CLI does not bind the
limits, because there they follow from the manifest.) Readiness, the
free-space floors and retention capacity are checked before the identity is
claimed, so those refusals do not spend it.

**While an execution id is running**, every other request for that id is
answered `in_progress`, whatever its other fields are: a request with
different commitments learns of the `conflict` only once the run has ended.
A request can only ever get `ambiguous` for an execution that is not
running.

**A caller that disconnects does not cancel its run.** The run belongs to
the service: it continues to its own wall-clock limit and its outcome is
journaled, so the caller asks again with the same request (`in_progress`
while it runs, then `ok`). Cancelling instead would turn a paid execution
ambiguous whenever a provider node restarts. The only thing that cancels a
run is a service stop that outlasts `--stop-grace`; see above.

A provider runtime imports `pkg/executorservice` for the client side:
`NewClient(ClientConfig{SocketPath: ...})`, then `Describe` for its preflight
and `Execute` per job. The client verifies that the socket is served by
root, that the outcome is a success of exactly the request it sent in the
frozen image, and that each returned object matches the digest the outcome
names. A call whose context has no deadline is bounded at 10 minutes.

### Retention and collection

The service's store is the same artifact store as the CLI's, under
`/var/lib/tos-service-executor/artifacts`, swept the same way (see
[Artifact retention](#artifact-retention)), with one difference: **a
service job is never left pending**. Counted from the second the job
completed:

- a request without `retain_until_unix` (zero) keeps the objects for
  `--default-retention` (7 days);
- a request with one keeps them until then, but never later than
  `--max-retention` (31 days);
- a repeated request may extend the deadline within that same bound and
  never shortens it. Because the bound counts from completion, repeating a
  request cannot keep objects alive past it.

The response states the deadline that was applied. The service's copy is a
convenience for asking again; **a provider runtime keeps its own copy of the
returned bytes for delivery** and should send the end of the response window
plus the manifest's `retention_seconds` as `retain_until_unix`.

`tos-service-executor-gc.timer` sweeps hourly by running the existing
command as root, in its own sandbox with no capability at all:

```bash
/usr/local/libexec/tos-service/software-work-execute artifacts-gc \
  --state-dir /var/lib/tos-service-executor --limit 1024
```

It may run while the service is serving. The two coordinate through the
store's retention lock only: committing an object, giving a job its deadline
and each sweep take it and wait a bounded time for one another, and the
sweep never opens the service's journal, FIFOs or sockets. A sweep that
cannot get the lock in time fails and the next hour's run does the work;
`systemctl start tos-service-executor-gc.service` runs one by hand.

With `--max-executions` above 1 the service holds a retention record for
each job from its admission until the job has recorded its own, so two jobs
are never admitted against the last free record.

Journal records are never collected: they are what keeps an execution id
from running twice.

### What the service does not replace

The service runs pre-admitted work only: like the default mode it performs
no chain verification, and its caller must own the `railgate` slots that
admit a paid request. The standalone `software-work-execute paid` command
remains for operators who admit and run paid work by hand as root, with its
own state directory.

## Artifact retention

Objects are deduplicated by content, so one object may belong to several
jobs. Every job has a record in `STATE/artifacts/retention/` naming its
objects. The record is written as each object is committed and stays
pending (`<job>.pending`), keeping its objects, until the job is given its
last retained unix second (`<job>.json`; the paid path does this itself, the
default mode with `--retain-until`). Objects stored without a job get a permanent hold
(`<object>.hold`). Sweep expired jobs with:

```bash
/usr/local/libexec/tos-service/software-work-execute artifacts-gc \
  --state-dir /var/lib/tos-service-provider/paid --limit 64
```

The sweep deletes at most `--limit` (1–1024) expired jobs per call and prints
a JSON report (`deleted_jobs`, `deleted_objects`, `kept_shared`, `deferred`,
`live` retained jobs not yet expired, `pending` jobs without a deadline, and
`held` objects); rerun it while `deferred` is non-zero, for example from a
systemd timer. An object stays while a pending, unexpired or deferred job
names it or a hold keeps it, so a sweep never deletes an object that a
running job just committed or deduplicated. Committing an object, retaining
a job and sweeping take one retention lock; each waits up to 60 seconds for
the others, so a timer-driven sweep does not fail a run that finishes at the
same moment.

A store keeps at most 65 536 deadline-bearing job records and tombstones.
At that bound, giving a new job its first deadline is refused (jobs that
already have one can still add objects and be extended), and `paid` refuses
to start a run, exiting 1 before anything is admitted or executed. A sweep
reads every entry however many there are, so it always makes progress, and
each expired job it deletes makes room again.

Pending records and holds are references that must never be broken, so they
are never refused and do not count toward the bound. The default mode does
not check capacity: without `--retain-until` it keeps working indefinitely,
and its storage grows the way it always did before retention existed,
because objects of jobs that never get a deadline are never collected. **A
provider runtime that drives the default mode should pass
`--retain-until`** (for example the end of the response window plus the
manifest's `retention_seconds`) so its objects become collectable. With
`--retain-until` the default mode needs room for a deadline after the run;
at the bound that run fails after executing, so keep sweeping.

In the paid path every retention lock wait (the runner's two object commits
and the final `Retain`) is also bounded by the time left before the response
deadline minus the respond budget, or by the 60 second cap if that is
shorter. A wait that runs out fails the execution (`execution_failed`, or
`ambiguous` if the outcome cannot be recorded); it never reads as success.

Each deletion is marked by a tombstone first, so an interrupted sweep leaves
no live record pointing at a deleted object and the next run finishes it.
Before deleting anything, the sweep refuses when it cannot get the lock in
time or when any record or hold is malformed or unexpected. An object that
turns out not to be a regular file stops the sweep at that job: jobs deleted
earlier in the same call stay deleted, the offending job keeps its tombstone
and object, and a rerun after the operator fixes it continues. The sweep
never follows symlinks. Jobs whose record stays pending (for example
default-mode runs without `--retain-until`, or a run that crashed before it
was retained) keep their objects until a deadline is set.

## Settlement and signing custody

Settlement is the actor's `respond`, authorized by the attestor's SRP2
signature. Review the response outside this root boundary and sign its exact
32-byte SRP2 hash through `tosctl`. Never copy a mnemonic, vault export,
private key, or vault master key into `/var/lib/tos-service-provider`,
`/run/tos-service-containerd`, the source archive, or executor environment.

## Acceptance checks

Run the live conformance suite from
`docs/isolated-backend-conformance.md` on the exact deployment image. A provider
template is ready only when the private socket checks, pinned-image workspace
test, residue cleanup, cgroup metrics, and a complete local Receipt flow pass.
The template is operational scaffolding, not an isolation certification.
