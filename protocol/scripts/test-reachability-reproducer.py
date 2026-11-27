#!/usr/bin/env python3
"""Show that the independent reproducer refuses tampered public corpora."""

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "spec/test-vectors/agent-transport-reachability-v1.json"
REPRODUCER = ROOT / "spec/scripts/reproduce-agent-transport-reachability-v1.py"
REFERENCE = ROOT / "spec/scripts/reproduce-agent-transport-v1.py"


def run(value):
    with tempfile.TemporaryDirectory(
        prefix="reachability-reference-control-"
    ) as directory:
        root = Path(directory)
        scripts, vectors = root / "scripts", root / "test-vectors"
        scripts.mkdir()
        vectors.mkdir()
        (scripts / REPRODUCER.name).write_bytes(REPRODUCER.read_bytes())
        (scripts / REFERENCE.name).write_bytes(REFERENCE.read_bytes())
        (vectors / CORPUS.name).write_text(json.dumps(value))
        result = subprocess.run(
            [sys.executable, "-I", str(scripts / REPRODUCER.name)],
            text=True,
            capture_output=True,
            timeout=120,
            check=False,
        )
        return result.returncode, result.stdout + result.stderr


def main():
    base = json.loads(CORPUS.read_text())
    code, output = run(base)
    if code or "13 signed objects reproduced; 57 negatives refused" not in output:
        raise RuntimeError("invalid reproducer baseline\n" + output)
    cases = []
    value = copy.deepcopy(base)
    wire = bytearray.fromhex(value["positive"][0]["wire"])
    wire[-1] ^= 1
    value["positive"][0]["wire"] = wire.hex()
    cases.append(("wire-signature", value, "wire/signature/digest differs"))
    value = copy.deepcopy(base)
    value["positive"][0]["hint"]["Relays"][0] = "https://changed.invalid"
    cases.append(("input-relay", value, "wire/signature/digest differs"))
    value = copy.deepcopy(base)
    value["positive"][0]["test_seed"] = hashlib.sha256(
        b"different-public-fixture-seed"
    ).hexdigest()
    cases.append(("seed", value, "seed/key"))
    value = copy.deepcopy(base)
    value["positive"][0]["hint"]["Signature"][0] = 1
    cases.append(("unsigned-input", value, "unsigned hint input"))
    value = copy.deepcopy(base)
    first = value["negative"][0]
    first["wire"] = next(
        v["wire"] for v in value["positive"] if v["name"] == first["base"]
    )
    cases.append(("accepted-negative", value, "negative accepted"))
    value = copy.deepcopy(base)
    first = next(v for v in value["positive"] if v["name"] == "rail-public")
    old_body = bytes.fromhex(first["objects"][0]["hex"])
    body = bytearray(old_body)
    body[old_body.index(b"padding")] ^= 1
    raw = bytes.fromhex(first["wire"])
    if raw[-len(old_body) :] != old_body:
        raise RuntimeError("object fixture moved")
    wire = raw[: -len(old_body)] + body
    first["objects"][0]["hex"], first["wire"], first["sha256"] = (
        body.hex(),
        wire.hex(),
        hashlib.sha256(wire).hexdigest(),
    )
    cases.append(
        ("self-consistent-wire-with-wrong-object-digest", value, "object digest")
    )
    for label, value, expected in cases:
        code, output = run(value)
        if code != 1 or "ValueError:" not in output or expected not in output:
            raise RuntimeError(
                "reproducer control survived or invalid: " + label + "\n" + output
            )
        print("RED reproducer: " + label, flush=True)
    print(f"REACHABILITY_REPRODUCER_CONTROLS_OK: {len(cases)}")


if __name__ == "__main__":
    main()
