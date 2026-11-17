#!/usr/bin/env python3
"""Independent stdlib-only reproducer for the Service Actor manifest vector.

It shares no code with the Go implementation. It rebuilds the canonical CBOR
and digest of the positive manifest from its JSON projection, and refuses
every case of the negative corpus: JSON cases by validating the projection,
CBOR cases by strict decoding, validation and re-encoding.
"""

import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "test-vectors/software-work-manifest-v1-service-actor.json"
ACTOR_VECTORS = ROOT / "test-vectors/service-actor-conformance-vectors.json"
SCHEMA = "tos.service.software-work-manifest.v1.service-actor.vector"

PROTOCOL = "tos.service.software-work-manifest.v1"
RAIL = "tos.service.service-actor.v1"
NATIVE_TOS = "native-tos"
REFUND = "no-attested-response-before-deadline"
SUCCESS = "exit-code-zero-and-valid-reports"
OPERATIONS = {"compile", "test", "static-analysis", "dependency-scan", "vulnerability-scan",
              "reproducible-build", "bounded-transform-and-test"}
SOURCE_KINDS = {"content-addressed-archive", "immutable-repository-commit"}
SHELLS = {"sh", "bash", "dash", "zsh", "cmd.exe", "powershell"}
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ATTESTOR = re.compile(r"^mldsa44:[0-9a-f]{64}$")

ROOT_FIELDS = [
    "protocol", "version", "name", "description", "operation", "accepted_source_kinds",
    "input_schema_digest", "output_schema_digest", "toolchain_digest", "invocation",
    "network_policy", "limits", "artifact_media_types", "report_media_types",
    "success_condition", "refund_conditions", "endpoint_commitment",
    "execution_signer_authorization", "retention_seconds", "supported_assets", "settlement",
]
INVOCATION_FIELDS = ["executable", "arguments", "working_directory"]
LIMIT_FIELDS = ["cpu_millis", "memory_bytes", "scratch_bytes", "output_bytes", "wall_clock_millis"]
SETTLEMENT_FIELDS = ["rail", "actor_workchain", "actor_account_id", "actor_code_hash", "attestor_key"]


class Refused(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Refused(reason)


# --- canonical CBOR -------------------------------------------------------

def head(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    for info, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (8 * width):
            return bytes([(major << 5) | info]) + value.to_bytes(width, "big")
    raise Refused("integer too large")


def encode(value):
    if isinstance(value, bool):
        raise Refused("booleans are not used")
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, dict):
        entries = sorted((encode(key), encode(item)) for key, item in value.items())
        entries.sort(key=lambda entry: (len(entry[0]), entry[0]))
        return head(5, len(entries)) + b"".join(key + item for key, item in entries)
    raise Refused(f"unsupported value {type(value).__name__}")


def decode(data):
    """Strict decoder: definite lengths, integer map keys, no tags or floats."""

    def item(offset, depth):
        require(depth < 16, "nesting too deep")
        require(offset < len(data), "truncated")
        initial = data[offset]
        major, info = initial >> 5, initial & 31
        offset += 1
        require(info != 31, "indefinite length")
        require(info < 28, "reserved additional information")
        if info < 24:
            argument = info
        else:
            width = 1 << (info - 24)
            require(offset + width <= len(data), "truncated")
            argument = int.from_bytes(data[offset:offset + width], "big")
            offset += width
        if major == 0:
            return argument, offset
        if major == 1:
            return -1 - argument, offset
        if major in (2, 3):
            require(offset + argument <= len(data), "truncated")
            raw = data[offset:offset + argument]
            offset += argument
            if major == 2:
                return bytes(raw), offset
            try:
                return raw.decode("utf-8"), offset
            except UnicodeDecodeError as error:
                raise Refused("invalid UTF-8") from error
        if major == 4:
            values = []
            for _ in range(argument):
                value, offset = item(offset, depth + 1)
                values.append(value)
            return values, offset
        if major == 5:
            result = {}
            for _ in range(argument):
                key, offset = item(offset, depth + 1)
                require(isinstance(key, int) and not isinstance(key, bool), "non-integer map key")
                require(key not in result, "duplicate map key")
                result[key], offset = item(offset, depth + 1)
            return result, offset
        raise Refused("tags, floats and simple values are not used")

    value, end = item(0, 0)
    require(end == len(data), "trailing bytes")
    return value


# --- JSON projection to the integer-keyed model ---------------------------

def exact(value, fields, where):
    require(isinstance(value, dict), f"{where} is not an object")
    require(set(value) == set(fields), f"{where} fields {sorted(set(value) ^ set(fields))}")


def projection_bytes(value, where):
    require(isinstance(value, str), f"{where} is not Base64 text")
    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error as error:
        raise Refused(f"{where} is not Base64") from error
    require(base64.b64encode(raw).decode() == value, f"{where} is not canonical Base64")
    return raw


def model_from_projection(manifest):
    exact(manifest, ROOT_FIELDS, "manifest")
    model = {index + 1: manifest[name] for index, name in enumerate(ROOT_FIELDS)}
    exact(manifest["invocation"], INVOCATION_FIELDS, "invocation")
    model[10] = {index + 1: manifest["invocation"][name] for index, name in enumerate(INVOCATION_FIELDS)}
    exact(manifest["limits"], LIMIT_FIELDS, "limits")
    model[12] = {index + 1: manifest["limits"][name] for index, name in enumerate(LIMIT_FIELDS)}
    assets = manifest["supported_assets"]
    require(isinstance(assets, list), "supported_assets is not an array")
    model[20] = []
    for asset in assets:
        exact(asset, ["kind"], "asset")
        model[20].append({0: asset["kind"]})
    settlement = manifest["settlement"]
    exact(settlement, SETTLEMENT_FIELDS, "settlement")
    model[21] = {
        1: settlement["rail"], 2: settlement["actor_workchain"],
        3: projection_bytes(settlement["actor_account_id"], "actor_account_id"),
        4: projection_bytes(settlement["actor_code_hash"], "actor_code_hash"),
        5: settlement["attestor_key"],
    }
    return model


# --- validation of the integer-keyed model --------------------------------

def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def printable(value, low, high):
    if not isinstance(value, str) or not low <= len(value.encode("utf-8")) <= high:
        return False
    return all(ord(char) >= 0x20 and ord(char) != 0x7F for char in value)


def digest(value):
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None and value[7:] != "0" * 64


def sorted_unique(values, low, high, allowed=None, pattern=None):
    require(isinstance(values, list) and low <= len(values) <= high, "list size")
    require(all(isinstance(value, str) for value in values), "list entries are not text")
    require(values == sorted(values) and len(set(values)) == len(values), "list not sorted and unique")
    if allowed is not None:
        require(set(values) <= allowed, "list value not allowed")
    if pattern is not None:
        require(all(pattern.fullmatch(value) for value in values), "list value malformed")


def bounded(value, low, high):
    return is_int(value) and low <= value <= high


def validate(model):
    require(isinstance(model, dict) and set(model) == set(range(1, 22)), "root keys are not exactly 1-21")
    require(model[1] == PROTOCOL, "protocol")
    require(isinstance(model[2], str) and VERSION.fullmatch(model[2]) is not None, "version")
    require(printable(model[3], 1, 128) and printable(model[4], 1, 2048), "name or description")
    require(model[5] in OPERATIONS, "operation")
    sorted_unique(model[6], 1, 8, allowed=SOURCE_KINDS)
    require(all(digest(model[key]) for key in (7, 8, 9, 17, 18)), "digest field")
    invocation = model[10]
    require(isinstance(invocation, dict) and set(invocation) == {1, 2, 3}, "invocation keys")
    executable, arguments, directory = invocation[1], invocation[2], invocation[3]
    require(printable(executable, 2, 256) and executable.startswith("/"), "executable")
    require(executable.rsplit("/", 1)[-1].lower() not in SHELLS, "shell executable")
    require(isinstance(arguments, list) and len(arguments) <= 64, "arguments")
    require(all(printable(argument, 0, 512) for argument in arguments), "argument")
    require(printable(directory, 10, 256) and directory.startswith("/workspace"), "working directory")
    require(model[11] == "none", "network policy")
    limits = model[12]
    require(isinstance(limits, dict) and set(limits) == {1, 2, 3, 4, 5}, "limit keys")
    require(bounded(limits[1], 1, 86_400_000) and bounded(limits[2], 16 << 20, 64 << 30) and
            bounded(limits[3], 1, 1 << 40) and bounded(limits[4], 1, 1 << 30) and
            bounded(limits[5], 1, 86_400_000), "limits")
    sorted_unique(model[13], 1, 16, pattern=MEDIA_TYPE)
    sorted_unique(model[14], 1, 16, pattern=MEDIA_TYPE)
    require(model[15] == SUCCESS, "success condition")
    require(model[16] == [REFUND], "key 16 is not exactly the no-attested-response refund")
    require(bounded(model[19], 3600, 30 * 24 * 3600), "retention")
    require(model[20] == [{0: NATIVE_TOS}], "key 20 is not exactly the native TOS entry")
    settlement = model[21]
    require(isinstance(settlement, dict) and set(settlement) == {1, 2, 3, 4, 5}, "key 21 keys are not exactly 1-5")
    require(settlement[1] == RAIL, "key 21 rail")
    require(is_int(settlement[2]) and settlement[2] == 0, "key 21 workchain")
    for key in (3, 4):
        value = settlement[key]
        require(isinstance(value, bytes) and len(value) == 32 and value != bytes(32), f"key 21 field {key}")
    attestor = settlement[5]
    require(isinstance(attestor, str) and ATTESTOR.fullmatch(attestor) is not None and
            attestor[8:] != "0" * 64, "key 21 attestor text form")
    require(model[18] == "sha256:" + hashlib.sha256(attestor.encode("ascii")).hexdigest(),
            "key 18 does not commit to the key 21 attestor")


def refuse_projection(manifest):
    try:
        validate(model_from_projection(manifest))
    except Refused:
        return True
    return False


def refuse_cbor(raw):
    try:
        model = decode(raw)
        validate(model)
        require(encode(model) == raw, "not the canonical encoding")
    except Refused:
        return True
    return False


def main():
    vector = json.loads(VECTOR.read_text())
    if vector.get("schema") != SCHEMA:
        raise SystemExit("unexpected vector schema")
    model = model_from_projection(vector["manifest"])
    validate(model)
    encoded = encode(model)
    digest_text = "sha256:" + hashlib.sha256(encoded).hexdigest()
    if digest_text != vector["expected"]["digest"] or \
            base64.b64encode(encoded).decode() != vector["expected"]["canonical_cbor_base64"]:
        raise SystemExit("frozen manifest vector mismatch")
    if refuse_cbor(encoded):
        raise SystemExit("the canonical CBOR does not decode back")

    actor = json.loads(ACTOR_VECTORS.read_text())
    if "tvm-cell-sha256:" + model[21][4].hex() != actor["contract_code_hash"] or \
            model[21][5] != "mldsa44:" + actor["init"]["attestor_key_id"]:
        raise SystemExit("key 21 does not name the release code hash and attestor of the contract vectors")

    names = set()
    for case in vector["negative_json"] + vector["negative_cbor"]:
        if case["name"] in names:
            raise SystemExit(f"duplicate negative case {case['name']}")
        names.add(case["name"])
    if not vector["negative_json"] or not vector["negative_cbor"]:
        raise SystemExit("the negative corpus is empty")
    for case in vector["negative_json"]:
        if not refuse_projection(case["manifest"]):
            raise SystemExit(f"negative JSON case accepted: {case['name']}")
    for case in vector["negative_cbor"]:
        if not refuse_cbor(base64.b64decode(case["cbor_base64"], validate=True)):
            raise SystemExit(f"negative CBOR case accepted: {case['name']}")
    print(f"software-work manifest v1 Service Actor vector: PASS ({digest_text}, "
          f"{len(vector['negative_json'])} JSON and {len(vector['negative_cbor'])} CBOR negatives refused)")


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"software-work manifest v1 Service Actor vector: FAIL: {error}")
