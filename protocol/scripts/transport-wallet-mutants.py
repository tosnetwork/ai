#!/usr/bin/env python3
"""Require named semantic failures when transport-wallet guards are removed."""

import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
WALLET = "./protocol/pkg/nativewallet"
CUSTODY = "./protocol/pkg/mldsa44"
COMMAND = "./protocol/cmd/tos-service-wallet"
MUTANTS = [
    (
        "network",
        "agenttransport/networks.go",
        "if !approvedLocal && !approvedPublic {",
        "if false && !approvedLocal && !approvedPublic {",
        WALLET,
        "TestTransportEpochAndNetworkRefusals",
    ),
    (
        "epoch",
        "agenttransport/verify.go",
        "if d.AuthorizationEpoch != 0 || s.CurrentEpoch != nil || s.AdmissionEpochs != nil || s.EpochCheckpoint != 0 {",
        "if false && (d.AuthorizationEpoch != 0 || s.CurrentEpoch != nil || s.AdmissionEpochs != nil || s.EpochCheckpoint != 0) {",
        WALLET,
        "TestTransportEpochAndNetworkRefusals",
    ),
    (
        "finalized-membership",
        "nativewallet/transport.go",
        "err == nil {\n\t\t\treturn bytes.Clone(r.Delegation), nil",
        "err == nil || len(r.Delegation)>0 {\n\t\t\treturn bytes.Clone(r.Delegation), nil",
        WALLET,
        "TestTransportAcknowledgementIsNotFinalization",
    ),
    (
        "second-send",
        "nativewallet/transport.go",
        'if r.Phase == "prepared" {',
        'if r.Phase == "prepared" || r.Phase == "dispatching" {',
        WALLET,
        "TestTransportLostAcknowledgementReconcilesWithoutResubmit",
    ),
    (
        "draft-before-sign",
        "nativewallet/transport.go",
        'r.Delegation, r.Submission, r.Phase = wire, submission, "drafted"\n\t\tif err = saveTransport(path, r); err != nil {',
        'r.Delegation, r.Submission, r.Phase = wire, submission, "drafted"\n\t\tif err = error(nil); err != nil {',
        WALLET,
        "TestTransportDraftIsDurableBeforeSigning",
    ),
    (
        "dispatch-before-send",
        "nativewallet/transport.go",
        'r.Phase = "dispatching"\n\t\tif err = saveTransport(path, r); err != nil {',
        'r.Phase = "dispatching"\n\t\tif err = error(nil); err != nil {',
        WALLET,
        "TestTransportRoundTripAndRerun",
    ),
    (
        "expiry",
        "nativewallet/transport.go",
        "if now.Unix() < 0 || uint64(now.Unix()) >= d.NotAfter {",
        "if false && (now.Unix() < 0 || uint64(now.Unix()) >= d.NotAfter) {",
        WALLET,
        "TestTransportExpiryBeforeDispatchRefuses",
    ),
    (
        "request-binding",
        "nativewallet/transport.go",
        "!bytes.Equal(expected, actual)",
        "(!bytes.Equal(expected, actual) && false)",
        WALLET,
        "TestTransportPrivateJournalAndBinding/request",
    ),
    (
        "empty-record",
        "nativewallet/transport.go",
        "r = transportRecord{}",
        "// leave defaults in the decoder",
        WALLET,
        "TestTransportPrivateJournalAndBinding/corrupt",
    ),
    (
        "key-binding",
        "nativewallet/transport.go",
        "d.TransportKey != key",
        "(d.TransportKey != key && false)",
        WALLET,
        "TestTransportPrivateJournalAndBinding/key",
    ),
    (
        "private-directory",
        "nativewallet/transport.go",
        "info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info)",
        "info.Mode()&os.ModeSymlink != 0 || (info.Mode().Perm()&0o077 != 0 && false) || !osguard.CurrentUserOwns(info)",
        WALLET,
        "TestTransportPrivateJournalAndBinding/directory",
    ),
    (
        "hardlink",
        "nativewallet/transport.go",
        "!singleTransportLink(info)",
        "(!singleTransportLink(info) && false)",
        WALLET,
        "TestTransportPrivateJournalAndBinding/lock-link",
    ),
    (
        "ancestor",
        "nativewallet/transport.go",
        "info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0",
        "false && info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0",
        WALLET,
        "TestTransportUntrustedAncestorRefuses",
    ),
    (
        "read-bound",
        "nativewallet/transport.go",
        "if len(raw) > 1<<20 {\n\t\treturn nil,",
        "if false && len(raw) > 1<<20 {\n\t\treturn nil,",
        WALLET,
        "TestTransportReadAndWriteBounds",
    ),
    (
        "write-bound",
        "nativewallet/transport.go",
        "if len(raw) > 1<<20 {\n\t\treturn errors.New",
        "if false && len(raw) > 1<<20 {\n\t\treturn errors.New",
        WALLET,
        "TestTransportReadAndWriteBounds",
    ),
    (
        "nonextractable",
        "mldsa44/transport_vault.go",
        'fields[3] != "No"',
        '(fields[3] != "No" && false)',
        CUSTODY,
        "TestTransportVaultTableRefusals/extractable",
    ),
    (
        "key-algorithm",
        "mldsa44/transport_vault.go",
        'fields[1] != "Ed25519"',
        '(fields[1] != "Ed25519" && false)',
        CUSTODY,
        "TestTransportVaultTableRefusals/algorithm",
    ),
    (
        "key-name",
        "mldsa44/transport_vault.go",
        "fields[0] != name",
        "(fields[0] != name && false)",
        CUSTODY,
        "TestTransportVaultTableRefusals/name",
    ),
    (
        "epoch-command",
        "../cmd/tos-service-wallet/transport.go",
        "|| *epoch != 0",
        "|| (*epoch != 0 && false)",
        COMMAND,
        "TestTransportCommandNetworkGatePrecedesSideEffects/epoch",
    ),
    (
        "reflected-error",
        "nativewallet/transport.go",
        'errors.New("delegation outcome unknown; keep this journal and rerun to reconcile")',
        'fmt.Errorf("delegation outcome unknown: %w", err)',
        WALLET,
        "TestTransportSubmissionErrorDoesNotReflectCredentials",
    ),
]


def run(args):
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
    code, output = run(
        ["go", "test", "-count=1", "-run", "Transport", WALLET, CUSTODY, COMMAND]
    )
    if code:
        raise RuntimeError("baseline failed\n" + output)
    for name, filename, old, new, package, test in MUTANTS:
        source = (ROOT / "protocol/pkg" / filename).resolve()
        text = source.read_text()
        if text.count(old) != 1:
            raise RuntimeError("nonunique anchor: " + name)
        replacement = text.replace(old, new)
        with tempfile.TemporaryDirectory(prefix="transport-wallet-mutant-") as tmp:
            modified = Path(tmp) / source.name
            modified.write_text(replacement)
            overlay = Path(tmp) / "overlay.json"
            overlay.write_text(json.dumps({"Replace": {str(source): str(modified)}}))
            code, output = run(
                [
                    "go",
                    "test",
                    "-vet=off",
                    "-count=1",
                    "-overlay",
                    str(overlay),
                    "-run",
                    "^" + test + "$",
                    package,
                ]
            )
        if code == 0 or "--- FAIL: " + test not in output or "[build failed]" in output:
            raise RuntimeError(
                "control did not fail its named test: " + name + "\n" + output
            )
        print("RED " + name + ": " + test, flush=True)
    print(f"TRANSPORT_WALLET_MUTANTS_OK: {len(MUTANTS)} controls")


if __name__ == "__main__":
    main()
