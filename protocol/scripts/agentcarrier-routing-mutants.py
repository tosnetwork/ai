#!/usr/bin/env python3
"""Semantic carrier refusal/order controls; compile failure is not a kill."""

import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "./protocol/pkg/agentcarrier"
CONTROLS = []


def add(name, file, old, new, test):
    CONTROLS.append((name, file, old, new, test))


add(
    "two-directories",
    "resolution.go",
    "len(c.Directories) < 2",
    "false",
    "TestResolverRequiresTwoDirectoriesAndProductionRelays",
)
add(
    "production-relays",
    "resolution.go",
    "!r.config.TestSingleRelay && len(hint.Record.Hint.Relays) < 2",
    "false",
    "TestResolverRequiresTwoDirectoriesAndProductionRelays",
)
add(
    "resolution-commit-freshness",
    "resolution.go",
    "!now.Before(hint.FreshUntil)",
    "(false && !now.Before(hint.FreshUntil))",
    "TestResolutionCarriesFreshnessThroughCardVerification",
)
add(
    "both-directory-indexes",
    "resolution.go",
    "fetch(r.config.Directories)",
    "fetch(r.config.Directories[:1])",
    "TestResolutionUsesVerifiedCacheThenContactThenBothDirectories",
)
add(
    "routing-state-identity",
    "routing_store.go",
    "i.Identity != s.identity",
    "false",
    "TestRoutingInventoryRefusesMissingUsedRecordAndMixedIdentity",
)
add(
    "routing-record-hole",
    "routing_store.go",
    "len(expected) != 0",
    "false",
    "TestRoutingInventoryRefusesMissingUsedRecordAndMixedIdentity",
)


def execute(arguments):
    result = subprocess.run(
        arguments,
        cwd=ROOT,
        env={**os.environ, "GOWORK": "off"},
        capture_output=True,
        text=True,
        errors="replace",
        timeout=180,
        check=False,
    )
    return result.returncode, result.stdout + result.stderr


def main():
    code, output = execute(["go", "test", "-count=1", PACKAGE])
    if code:
        raise RuntimeError("baseline failed\n" + output)
    for name, file, old, new, test in CONTROLS:
        source = ROOT / "protocol/pkg/agentcarrier" / file
        text = source.read_text()
        if text.count(old) != 1:
            raise RuntimeError("nonunique anchor: " + name)
        changed = text.replace(old, new)
        if name == "hint-relays-only":
            changed += "\nfunc chosenUnusedRelays(raw []byte)[]string {p,e:=agentpacket.DecodeJSON(raw);if e!=nil{return nil};c,e:=agentpacketseal.DecodeKeyCard(p.Payload);if e!=nil{return nil};return c.Relays}\n"
        with tempfile.TemporaryDirectory(prefix="carrier-mutant-") as temp:
            replacement = Path(temp) / source.name
            replacement.write_text(changed)
            overlay = Path(temp) / "overlay.json"
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
        if (
            code == 0
            or "--- FAIL: " + test.split("/")[0] not in output
            or "[build failed]" in output
        ):
            raise RuntimeError(
                "control did not fail its named test: " + name + "\n" + output
            )
        print("RED " + name + ": " + test, flush=True)
    print(f"AGENTCARRIER_MUTANTS_OK: {len(CONTROLS)} controls")


if __name__ == "__main__":
    main()
