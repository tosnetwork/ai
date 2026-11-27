#!/usr/bin/env python3
"""Overlay-only assertion-red controls for issuer reads and buyer previews."""

import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASES = [
    (
        "blacklist",
        "protocol/pkg/tokenissuer/issuer.go",
        "if blocked {",
        "if false && blocked {",
        "./protocol/pkg/tokenissuer",
        "TestIssuerRefusals/blacklisted",
    ),
    (
        "pause",
        "protocol/pkg/tokenissuer/issuer.go",
        "if paused {",
        "if false && paused {",
        "./protocol/pkg/tokenissuer",
        "TestIssuerRefusals/paused",
    ),
    (
        "deprecated",
        "protocol/pkg/tokenissuer/issuer.go",
        "if deprecated {",
        "if false && deprecated {",
        "./protocol/pkg/tokenissuer",
        "TestIssuerRefusals/deprecated",
    ),
    (
        "stale",
        "protocol/pkg/tokenissuer/issuer.go",
        "seconds > stamp && seconds-stamp > MaxAgeSeconds",
        "false",
        "./protocol/pkg/tokenissuer",
        "TestIssuerRefusals/stale",
    ),
    (
        "late-stale",
        "protocol/pkg/tokenissuer/issuer.go",
        "if err = r.fresh(stamp); err != nil",
        "if err = r.fresh(stamp); false && err != nil",
        "./protocol/pkg/tokenissuer",
        "TestIssuerReadRechecksTimeAfterRPC",
    ),
    (
        "chain",
        "protocol/pkg/tokenissuer/issuer.go",
        "id.Uint64() != r.policy.ChainID",
        "false",
        "./protocol/pkg/tokenissuer",
        "TestIssuerRefusals/chain",
    ),
    (
        "code",
        "protocol/pkg/tokenissuer/issuer.go",
        "hex.EncodeToString(digest[:]) != r.policy.CodeSHA256",
        "false && hex.EncodeToString(digest[:]) != r.policy.CodeSHA256",
        "./protocol/pkg/tokenissuer",
        "TestIssuerRefusals/code",
    ),
    (
        "reorg",
        "protocol/pkg/tokenissuer/issuer.go",
        "if sameHash != hash {",
        "if false && sameHash != hash {",
        "./protocol/pkg/tokenissuer",
        "TestIssuerRefusals/reorg",
    ),
    (
        "rpc-error",
        "protocol/pkg/tokenissuer/issuer.go",
        "len(answer.Error) != 0",
        "false",
        "./protocol/pkg/tokenissuer",
        "TestIssuerRefusals/error-and-result",
    ),
    (
        "boolean",
        "protocol/pkg/tokenissuer/issuer.go",
        "n.Uint64() > 1",
        "false",
        "./protocol/pkg/tokenissuer",
        "TestIssuerRefusals/boolean",
    ),
    (
        "fee-rate",
        "protocol/pkg/tokenissuer/issuer.go",
        "rate.Uint64() >= 10000",
        "false",
        "./protocol/pkg/tokenissuer",
        "TestIssuerRefusals/fee-rate",
    ),
    (
        "fee-cap",
        "protocol/pkg/tokenissuer/issuer.go",
        "if fee.Cmp(maximum) > 0 {",
        "if false && fee.Cmp(maximum) > 0 {",
        "./protocol/pkg/tokenissuer",
        "TestFinalizedIssuerReadAndReceivedAmount",
    ),
    (
        "fee-math",
        "protocol/pkg/tokenissuer/issuer.go",
        "fee.Quo(fee, big.NewInt(10000))",
        "fee.Quo(fee, big.NewInt(1000))",
        "./protocol/pkg/tokenissuer",
        "TestFinalizedIssuerReadAndReceivedAmount",
    ),
    (
        "minted-budget",
        "protocol/pkg/buyersdk/token_lock_preview.go",
        "received.Cmp(limits.MaxPerCallAtomic) > 0",
        "nominal.Cmp(limits.MaxPerCallAtomic) > 0",
        "./protocol/pkg/buyersdk",
        "TestTokenLockBudgetUsesMintedAmount",
    ),
    (
        "per-call-budget",
        "protocol/pkg/buyersdk/token_lock_preview.go",
        "received.Cmp(limits.MaxPerCallAtomic) > 0",
        "false",
        "./protocol/pkg/buyersdk",
        "TestTokenLockBudgetUsesMintedAmount",
    ),
    (
        "window-budget",
        "protocol/pkg/buyersdk/token_lock_preview.go",
        "received.Cmp(remaining) > 0",
        "false && received.Cmp(remaining) > 0",
        "./protocol/pkg/buyersdk",
        "TestTokenLockBudgetUsesMintedAmount",
    ),
    (
        "fee-warning",
        "protocol/pkg/buyersdk/token_lock_preview.go",
        "if fee.Sign() > 0 {",
        "if false && fee.Sign() > 0 {",
        "./protocol/pkg/buyersdk",
        "TestTokenLockBudgetUsesMintedAmount",
    ),
    (
        "issuer-token-binding",
        "protocol/cmd/tos-service-buyer/token.go",
        'policy.Token != "0x"+asset.SourceToken',
        "false",
        "./protocol/cmd/tos-service-buyer",
        "TestIssuerPolicyIsBoundToThePinnedSourceAsset",
    ),
    (
        "issuer-chain-binding",
        "protocol/cmd/tos-service-buyer/token.go",
        "policy.ChainID != uint64(asset.SourceChainID)",
        "false",
        "./protocol/cmd/tos-service-buyer",
        "TestIssuerPolicyIsBoundToThePinnedSourceAsset",
    ),
    (
        "mcp-warning",
        "protocol/pkg/mcpbuyer/token_lock_preview.go",
        "preview.Warning)",
        '"")',
        "./protocol/pkg/mcpbuyer",
        "TestTokenLockPreviewIsReadOnlyAndShowsReceivedAmount",
    ),
]


def execute(command):
    result = subprocess.run(
        command,
        cwd=ROOT,
        env={**os.environ, "GOWORK": "off"},
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    return result.returncode, result.stdout + result.stderr


def main():
    packages = sorted({c[4] for c in CASES})
    code, output = execute(
        [
            "go",
            "test",
            "-count=1",
            "-run",
            "^(TestIssuer.*|TestFinalizedIssuer.*|TestTokenLock.*|TestNoIssuerFee.*)$",
            *packages,
        ]
    )
    if code:
        raise RuntimeError("baseline failed\n" + output)
    for name, file, old, new, package, test in CASES:
        source = ROOT / file
        original = source.read_text()
        if original.count(old) != 1:
            raise RuntimeError("non-unique anchor: " + name)
        with tempfile.TemporaryDirectory(prefix="token-issuer-mutant-") as directory:
            path = Path(directory) / source.name
            path.write_text(original.replace(old, new))
            overlay = Path(directory) / "overlay.json"
            overlay.write_text(json.dumps({"Replace": {str(source): str(path)}}))
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
                    package,
                ]
            )
        if code == 0 or "--- FAIL: " + test not in output or "[build failed]" in output:
            raise RuntimeError("survivor or invalid mutant: " + name + "\n" + output)
        print("RED " + name + ": " + test, flush=True)
    print(f"TOKEN_ISSUER_MUTANTS_OK: {len(CASES)} checks caught")


if __name__ == "__main__":
    main()
