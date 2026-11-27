#!/usr/bin/env python3
"""Semantic red controls for the durable V2 relay foundation; no source edits."""

import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "./protocol/pkg/agentpacketrelay"
MUTANTS = [
    (
        "tagged-lane",
        "v2_store.go",
        "v2DefaultLane  = 2",
        "v2DefaultLane  = 1",
        "TestV2TaggedLaneAndVerifiedIdentity",
    ),
    (
        "verified-chain",
        "v2_replay.go",
        "if err := checked.Credential.VerifyChain(); err != nil {",
        "if err := error(nil); err != nil {",
        "TestV2TaggedLaneAndVerifiedIdentity",
    ),
    (
        "default-lane-binding",
        "v2_store.go",
        "if !firstExplicit {",
        "if false && !firstExplicit {",
        "TestV2HolderCannotReplaceDefaultLane",
    ),
    (
        "issuer-key",
        "v2_store.go",
        "identity.IssuerChain}, nil",
        "identity.CredentialID}, nil",
        "TestV2AppendedCredentialsShareDefaultLane",
    ),
    (
        "mailbox-stranger-count",
        "v2_store.go",
        "usedStranger.Count < stranger.Count",
        "(usedStranger.Count < stranger.Count || true)",
        "TestV2StrangerMailboxAndRelayReservation",
    ),
    (
        "mailbox-stranger-address",
        "v2_store.go",
        "fromStranger < 8",
        "(fromStranger < 8 || true)",
        "TestV2AddressAndByteShares/per-mailbox-address",
    ),
    (
        "relay-stranger-address",
        "v2_store.go",
        "if s.strangers[rec.Client] >= 64 {",
        "if false && s.strangers[rec.Client] >= 64 {",
        "TestV2AddressAndByteShares/relay-address",
    ),
    (
        "site-48",
        "v2_store.go",
        "ok && s.sites[site] >= 256",
        "ok && false && s.sites[site] >= 256",
        "TestV2AddressAndByteShares/ipv6-sites",
    ),
    (
        "address-64",
        "v2_store.go",
        "addr = netip.PrefixFrom(addr, 64).Masked().Addr()",
        "// retain host bits",
        "TestV2IPv6AddressesShareTheir64",
    ),
    (
        "share-count",
        "v2_store.go",
        "usage.Count >= countLimit",
        "(usage.Count >= countLimit && false)",
        "TestV2StrangerMailboxAndRelayReservation",
    ),
    (
        "share-bytes",
        "v2_store.go",
        "usage.Bytes > byteLimit-rec.Size",
        "(usage.Bytes > byteLimit-rec.Size && false)",
        "TestV2AddressAndByteShares/byte-reservation",
    ),
    (
        "mailbox-count",
        "v2_store.go",
        "count >= s.limits.Base.PerRecipientMaxEnvelopes",
        "(count >= s.limits.Base.PerRecipientMaxEnvelopes && false)",
        "TestV2ContactMailboxCountAndBytes/count",
    ),
    (
        "mailbox-bytes",
        "v2_store.go",
        "used > s.limits.Base.PerRecipientMaxBytes-rec.Size",
        "(used > s.limits.Base.PerRecipientMaxBytes-rec.Size && false)",
        "TestV2ContactMailboxCountAndBytes/bytes",
    ),
    (
        "tombstone-charge",
        "v2_store.go",
        "s.add(key, stone)",
        "// do not retain tombstone charge",
        "TestV2TombstoneChargesSurviveRestart",
    ),
    (
        "tombstone-address",
        "v2_store.go",
        "if !rec.Contact {\n\t\ts.strangers[rec.Client]++",
        "if !rec.Contact && !rec.Tombstone {\n\t\ts.strangers[rec.Client]++",
        "TestV2TombstoneChargesSurviveRestart",
    ),
    (
        "candidate-monotonic",
        "v2_replay.go",
        "max(r.candidate, r.table.NextMark(now))",
        "r.table.NextMark(now)",
        "TestV2UncertainMarkNeverDecreasesAndStoreWritesFailClosed",
    ),
    (
        "publish-after-sync",
        "v2_replay.go",
        'if err = r.disk.write("REPLAY", raw); err != nil {',
        "if err = error(nil); err != nil {\n        _ = raw",
        "TestV2UncertainMarkNeverDecreasesAndStoreWritesFailClosed",
    ),
    (
        "checksum",
        "v2_disk.go",
        "if wrapper.SHA256 != hex.EncodeToString(sum[:]) {",
        "if false && wrapper.SHA256 != hex.EncodeToString(sum[:]) {",
        "TestV2RecordChecksumsAndNames",
    ),
    (
        "format",
        "v2_disk.go",
        "err != nil || string(format) != v2Format",
        "err != nil || (string(format) != v2Format && false)",
        "TestV2CheckedRecordShapeAndStorePermissions/format",
    ),
    (
        "recovery-audit",
        "v2_replay.go",
        "audit == nil || now >",
        "false || now >",
        "TestV2ExplicitReplayRecovery/no-audit",
    ),
    (
        "recovery-bound",
        "v2_replay.go",
        "*recoverFloor < now+agenttransport.MarkLeadSeconds",
        "(*recoverFloor < now+agenttransport.MarkLeadSeconds && false)",
        "TestV2ExplicitReplayRecovery/too-low",
    ),
    (
        "recovery-monotonic",
        "v2_replay.go",
        "readErr == nil && *recoverFloor < mark.Mark",
        "readErr == nil && false && *recoverFloor < mark.Mark",
        "TestV2ExplicitReplayRecovery/valid-old-mark",
    ),
    (
        "issuer-replay-counter",
        "../agenttransport/replay.go",
        "group := k.IssuerChain",
        "group := k.CredentialID",
        "TestV2ReplayIssuerBoundAndNoLiveEviction",
    ),
    (
        "floor-on-restore",
        "../agenttransport/replay.go",
        "t.floor, t.mark = recordedMark, recordedMark",
        "t.floor, t.mark = 0, recordedMark",
        "TestV2ReplayRestartFloorRollbackAndBounds",
    ),
    (
        "f-plus-one",
        "../agenttransport/replay.go",
        "return wait + 1",
        "return wait",
        "TestV2ReplayRestartFloorRollbackAndBounds",
    ),
    (
        "high-water-gate",
        "../agenttransport/replay.go",
        "if p.IssuedAt >= t.mark {",
        "if false && p.IssuedAt >= t.mark {",
        "TestV2ReplayRestartFloorRollbackAndBounds",
    ),
]


def execute(args):
    result = subprocess.run(
        args,
        cwd=ROOT,
        env={**os.environ, "GOWORK": "off"},
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result.returncode, result.stdout + result.stderr


def main():
    code, output = execute(["go", "test", "-count=1", "-run", "^TestV2", PACKAGE])
    if code:
        raise RuntimeError("baseline failed\n" + output)
    for name, filename, old, new, test in MUTANTS:
        source = (ROOT / "protocol/pkg/agentpacketrelay" / filename).resolve()
        original = source.read_text()
        if original.count(old) != 1:
            raise RuntimeError("nonunique anchor: " + name)
        with tempfile.TemporaryDirectory(prefix="relay-v2-mutant-") as tmp:
            replacement = Path(tmp) / source.name
            replacement.write_text(original.replace(old, new))
            overlay = Path(tmp) / "overlay.json"
            overlay.write_text(json.dumps({"Replace": {str(source): str(replacement)}}))
            code, output = execute(
                [
                    "go",
                    "test",
                    "-vet=off",
                    "-count=1",
                    "-overlay",
                    str(overlay),
                    "-run",
                    "^" + test + "$",
                    PACKAGE,
                ]
            )
        if code == 0 or "--- FAIL: " + test not in output or "[build failed]" in output:
            raise RuntimeError(
                "mutant did not fail its named test: " + name + "\n" + output
            )
        print("RED " + name + ": " + test, flush=True)
    print(f"RELAY_V2_STORE_MUTANTS_OK: {len(MUTANTS)} controls")


if __name__ == "__main__":
    main()
