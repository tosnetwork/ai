#!/usr/bin/env python3
"""Assertion-red controls for two-asset isolation; run under the build guard.

Only the selected test may kill a mutant. Build errors, panics, skips, missing
patterns, absent tests and timeouts are invalid results, never kills. Sources
are restored after every case, including on failure. Logs belong outside Git.
"""

import argparse
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASES = (
    (
        "no-implicit-production-pins",
        "protocol/cmd/tos-service-buyer/token.go",
        "var pins []toschain.TokenAssetPin",
        "pins := []toschain.TokenAssetPin{{}}",
        "cmd/tos-service-buyer",
        "TestTokenPolicyRequiresExplicitAssetPins",
        "implicit asset pins appeared:",
    ),
    (
        "gate-second-pin",
        "execution/pkg/railgate/token.go",
        "range v.config.TokenPins {",
        "range v.config.TokenPins[:1] {",
        "execution/pkg/railgate",
        "TestTwoAssetGateSelectsPinByIdentityNotPosition",
        "second configured asset could not execute:",
    ),
    (
        "independent-verification",
        "protocol/pkg/toschain/service_actor_token_asset.go",
        "if pin.Master == master {",
        "if index == 0 {",
        "toschain",
        "TestTwoPinnedAssetsVerifyIndependently",
        "asset 1:",
    ),
    (
        "suspension-is-local",
        "protocol/pkg/toschain/service_actor_token_asset.go",
        "if record.Status != 1 {",
        "if false {",
        "toschain",
        "TestSuspendedSecondAssetLeavesFirstActive",
        "suspended asset:",
    ),
    (
        "status-applied-to-every-entry",
        "protocol/pkg/toschain/service_actor_token_asset.go",
        "if record.Status != 1 {",
        'for _, entry := range assets.Entries { if entry.Status != 1 { return nil, errors.New("pinned token is not active") } }; if record.Status != 1 {',
        "toschain",
        "TestSuspendedSecondAssetLeavesFirstActive",
        "active first asset affected by second status:",
    ),
    (
        "provider-pause-is-asset-local",
        "provider/pkg/servicebridge/token_monitor.go",
        "if !alerts[a.AssetID] {",
        "if len(alerts) == 0 {",
        "provider/pkg/servicebridge",
        "TestTokenProviderPauseIsAssetScopedAndPreservesPolicy",
        "asset-specific pause",
    ),
    (
        "independent-budgets",
        "protocol/pkg/buyersdk/service_actor_journal.go",
        " || TokenAssetBudgetKey(existing.AssetMaster, existing.AssetWalletCodeHash, existing.AssetDecimals) != key",
        "",
        "buyersdk",
        "TestTwoAssetsHaveIndependentBudgets",
        "second asset shared first budget",
    ),
    (
        "separate-aggregation",
        "protocol/pkg/buyersdk/service_actor_journal.go",
        "key := TokenAssetBudgetKey(r.AssetMaster, r.AssetWalletCodeHash, r.AssetDecimals)",
        'key := "all-assets"',
        "buyersdk",
        "TestTwoAssetsAggregateOnlyWithinTheirOwnIdentity",
        "mixed principal:",
    ),
    (
        "foreign-wallet",
        "protocol/pkg/serviceactor/token_verify.go",
        "call.Sender != e.Actor.OwnWallet || ",
        "",
        "serviceactor",
        "TestOtherAssetNotificationCannotFundThePinnedActor",
        "foreign notification admitted:",
    ),
    (
        "foreign-notification-class",
        "protocol/pkg/toschain/service_actor_token_history.go",
        "if snapshots == 1 {",
        "if snapshots <= 1 {",
        "toschain",
        "TestTokenNotificationWithoutSAT1IsNotAnAdmission",
        "foreign notification relabelled as admission:",
    ),
    (
        "second-mcp-budget",
        "protocol/pkg/mcpbuyer/tools.go",
        "range page.Budget.TokenAssets {",
        "range page.Budget.TokenAssets[:1] {",
        "mcpbuyer",
        "TestPurchasesRenderEachAssetBudgetSeparately",
        "asset budget not rendered:",
    ),
    (
        "client-resolver-bound",
        "protocol/cmd/tos-service-buyer/token.go",
        "len(configs) > toschain.MaxPinnedTokenAssets",
        "len(configs) > 16",
        "cmd/tos-service-buyer",
        "TestClientPolicyHasTheSameTwoAssetBoundAsTheResolver",
        "client accepted a policy its resolver refuses:",
    ),
)


def run_test(package, test, output):
    target = (
        "./" + package
        if package.startswith(("execution/", "provider/"))
        else "./protocol/"
        + (package if package.startswith("cmd/") else "pkg/" + package)
    )
    with output.open("w") as log:
        result = subprocess.run(
            [
                "go",
                "test",
                "-p=2",
                "-json",
                "-count=1",
                "-timeout=5m",
                target,
                "-run",
                "^" + test + "$",
            ],
            cwd=ROOT,
            env={**os.environ, "GOWORK": "off", "GOMAXPROCS": "2"},
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=900,
            check=False,
        )
    if output.stat().st_size > 5 << 20:
        raise RuntimeError("unexpectedly large test log")
    text = output.read_text()
    events = []
    for line in text.splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    failures = [
        e for e in events if e.get("Action") == "fail" and e.get("Test") == test
    ]
    passed = [e for e in events if e.get("Action") == "pass" and e.get("Test") == test]
    invalid = any(
        marker in text
        for marker in ("panic:", "[build failed]", "build-failed", "no test files")
    )
    return result.returncode, failures, passed, invalid, text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-dir", type=Path, required=True)
    args = parser.parse_args()
    args.log_dir.mkdir(parents=True, exist_ok=True)
    labels = [case[0] for case in CASES]
    mutations = [(case[1], case[2], case[3]) for case in CASES]
    if len(set(labels)) != len(labels) or len(set(mutations)) != len(mutations):
        raise RuntimeError("duplicate control or mutation")
    # Establish all positive baselines before writing any mutated source.
    for label, _, _, _, package, test, _ in CASES:
        code, failures, passed, invalid, _ = run_test(
            package, test, args.log_dir / (label + "-baseline.jsonl")
        )
        if code or failures or not passed or invalid:
            raise RuntimeError("invalid positive baseline: " + label)
    results = []
    for label, relative, before, after, package, test, expected in CASES:
        path = ROOT / relative
        original = path.read_bytes()
        source = original.decode()
        if source.count(before) != 1:
            raise RuntimeError("pattern must occur exactly once: " + label)
        try:
            path.write_text(source.replace(before, after))
            syntax = subprocess.run(
                ["gofmt", str(path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
            )
            if syntax.returncode:
                raise RuntimeError("invalid syntax: " + label)
            code, failures, _, invalid, text = run_test(
                package, test, args.log_dir / (label + ".jsonl")
            )
            if code != 1 or not failures or invalid or expected not in text:
                raise RuntimeError("survived or invalid failure: " + label)
            results.append({"control": label, "test": test, "result": "assertion-red"})
            print(label + ": assertion-red", flush=True)
        finally:
            path.write_bytes(original)
    (args.log_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(str(len(results)) + "/" + str(len(CASES)) + " assertion-red")


if __name__ == "__main__":
    main()
