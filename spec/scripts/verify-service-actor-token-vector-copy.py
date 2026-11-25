#!/usr/bin/env python3
"""The spec copy of the token-rail Service Actor vectors equals the tos fixture.

Always: the copy's SHA-256 and length equal the values recorded in its
provenance file, and its code hash equals the recorded release code hash.

With --tos-repo <tos checkout>: the fixture is read at the recorded sha with
`git show` and must equal the copy byte for byte, and every T3 sandbox test the
negative corpus names must exist at that sha, be a #[test], and name its code.

    python3 -I scripts/verify-service-actor-token-vector-copy.py [--tos-repo DIR]
"""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "test-vectors/service-actor-token-conformance-vectors.source.json"
CORPUS = ROOT / "test-vectors/service-actor-token-negative-v1.json"
SHA = re.compile(r"^[0-9a-f]{40}$")
ERR_NAMES = {1934: "INVALID_DESTINATION"}


def fail(message):
    raise SystemExit(f"verify-service-actor-token-vector-copy: {message}")


def git_show(repo, sha, path):
    result = subprocess.run(["git", "-C", str(repo), "show", f"{sha}:{path}"], capture_output=True, check=False)
    if result.returncode != 0:
        fail(f"git show {sha}:{path} failed: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def test_body(source, name):
    """The body of `fn name` if a #[test] attribute precedes it."""
    match = re.search(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn\s+" + re.escape(name) + r"\s*\(", source)
    if not match:
        return None
    following = re.search(r"\n(?:#\[|fn |pub fn |mod )", source[match.end():])
    return source[match.end():match.end() + following.start()] if following else source[match.end():]


def names_code(body, code, constant):
    """The test names the code as its err:: constant (a whole identifier), or
    as a whole-number literal inside an asserting call: assert*, refused_with,
    refused_call or an exit_code comparison. A stray digit elsewhere does not
    count."""
    for name in {constant, ERR_NAMES.get(code, constant)}:
        if re.search(r"\berr::" + re.escape(name) + r"\b", body):
            return True
    literal = r"(?<![0-9A-Za-z_.])" + str(code) + r"(?![0-9A-Za-z_.])"
    context = r"(?:assert\w*!|refused_with|refused_call|exit_code)\s*\([^;]*?" + literal
    return re.search(context, body) is not None


def check_tests(repo, corpus):
    meta = corpus["t3_tests"]
    if meta["sha"] != json.loads(SOURCE.read_text())["source_sha"]:
        fail("the corpus names tests at another sha than the vectors")
    sources = {}
    checked = 0
    for entry in corpus["refusal_codes"]:
        constant = entry["name"].upper()
        for test in entry["tests"]:
            module, name = test.split("::")
            if module not in sources:
                sources[module] = git_show(repo, meta["sha"], f"{meta['directory']}/{module}.rs").decode()
            body = test_body(sources[module], name)
            if body is None:
                fail(f"code {entry['code']}: no #[test] fn {test} at {meta['sha']}")
            if not names_code(body, entry["code"], constant):
                fail(f"code {entry['code']}: {test} does not name it")
            checked += 1
    return checked


def main():
    args = sys.argv[1:]
    repo = None
    if args[:1] == ["--tos-repo"] and len(args) == 2:
        repo = Path(args[1])
    elif args:
        raise SystemExit("usage: verify-service-actor-token-vector-copy.py [--tos-repo DIR]")
    source = json.loads(SOURCE.read_text())
    if not SHA.match(source["source_sha"]):
        fail("source_sha is not a full commit id")
    copy = (ROOT / source["copy"]).read_bytes()
    if len(copy) != source["bytes"] or hashlib.sha256(copy).hexdigest() != source["sha256"]:
        fail(f"{source['copy']} differs from the recorded fixture digest")
    if json.loads(copy)["contract_code_hash"] != source["release_code_hash"]:
        fail("the vectors' code hash is not the recorded release code hash")
    message = f"{source['copy']}: sha256 {source['sha256']} as recorded"
    if repo is not None:
        fixture = git_show(repo, source["source_sha"], source["source_path"])
        if fixture != copy:
            fail(f"{source['copy']} differs from {source['source_path']} at {source['source_sha']}")
        checked = check_tests(repo, json.loads(CORPUS.read_text()))
        message += f"; byte-equal to the tos fixture at {source['source_sha'][:12]}; {checked} test references found"
    print(message)


if __name__ == "__main__":
    main()
