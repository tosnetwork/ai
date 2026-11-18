#!/usr/bin/env python3
"""Independent stdlib-only reproducer for the rail work frame vectors.

It shares no code with OpenFox. It recomputes the derived values of
SERVICE_ACTOR_RAIL_WORK_FRAMES_V1 section 6, rebuilds and decodes every
message and frame, checks the result's artifact against its Receipt digests,
and refuses every negative frame, message and frame set.
"""

import base64
import binascii
import hashlib
import io
import json
import re
import struct
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "test-vectors/service-actor-rail-work-frames-v1.json"

MAGIC = 0x4F465231
VERSION = 1
HEADER = 121
CHUNK = 61440
MAX_CHUNKS = 32
MAX_HEADER = 65536
MAX_INPUT = 1 << 20
MAX_RESULT = (1 << 20) + (64 << 10)
MAX_CARD = 16384
CARD_B64 = (MAX_CARD + 2) // 3 * 4
BOUNDS = {
    1: 4 + MAX_HEADER + MAX_INPUT,
    2: 4 + MAX_HEADER + MAX_RESULT,
    3: 4 + 4096 + CARD_B64,
    4: 4 + 4096 + CARD_B64,
}
INPUT_DOMAIN = b"tos.openfox.rail-input.v1\x00"
EXECUTION_DOMAIN = b"tos.openfox.rail-execution-id.v1"

HEX64 = re.compile(r"^[0-9a-f]{64}$")
AGENT = re.compile(r"^agent_[0-9a-f]{64}$")
CAP = re.compile(r"^cap_[0-9a-f]{64}$")
WALLET = re.compile(r"^0:[0-9a-f]{64}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")

# Field order, optional fields and schema of each message kind.
FIELDS = {
    1: ("tos.openfox.rail-task.v1",
        ["schema", "buyer_agent_id", "buyer_wallet", "capability_id", "capability_version", "package_base64",
         "execution_id", "execution_nonce", "source_digest", "request_id", "call_lt", "call_hash",
         "buyer_key_card_base64"], {"buyer_key_card_base64"}),
    2: ("tos.openfox.rail-result.v1",
        ["schema", "response_hash", "receipt_boc_base64", "provider_key_card_base64"], {"provider_key_card_base64"}),
    3: ("tos.openfox.rail-result-ack.v1", ["schema", "response_hash", "buyer_key_card_base64"],
        {"buyer_key_card_base64"}),
    4: ("tos.openfox.rail-result-request.v1", ["schema", "buyer_key_card_base64"], {"buyer_key_card_base64"}),
}
INTEGERS = {"request_id", "call_lt"}


class Refused(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def strict_b64(text, where):
    require(isinstance(text, str), f"{where} is not text")
    try:
        raw = base64.b64decode(text, validate=True)
    except binascii.Error as error:
        raise Refused(f"{where} is not Base64") from error
    require(base64.b64encode(raw).decode() == text, f"{where} is not strict Base64")
    return raw


# --- canonical header JSON ------------------------------------------------

def encode_string(value):
    require(all(0x20 <= ord(char) < 0x7F for char in value), "this reproducer encodes printable ASCII only")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return '"' + escaped + '"'


def encode_header(kind, header):
    _, order, optional = FIELDS[kind]
    parts = []
    for name in order:
        if name not in header:
            continue
        value = header[name]
        if name in optional and value == "":
            continue
        if name in INTEGERS:
            parts.append(f'"{name}":{value}')
        else:
            parts.append(f'"{name}":' + encode_string(value))
    return ("{" + ",".join(parts) + "}").encode()


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate field {key}")
        result[key] = value
    return result


def decode_message(raw, kind):
    require(len(raw) >= 4 and len(raw) <= BOUNDS[kind], "message outside its bound")
    (length,) = struct.unpack(">I", raw[:4])
    require(0 < length <= MAX_HEADER and length <= len(raw) - 4, "header length invalid")
    header_bytes = raw[4:4 + length]
    try:
        header = json.loads(header_bytes.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Refused("header does not decode as one JSON value") from error
    schema, order, optional = FIELDS[kind]
    require(isinstance(header, dict), "header is not an object")
    require(set(header) <= set(order) and set(order) - optional <= set(header), "header fields")
    for name, value in header.items():
        if name in INTEGERS:
            require(isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 1 << 64, f"{name}")
        else:
            require(isinstance(value, str), f"{name} is not a string")
    require(encode_header(kind, header) == header_bytes, "header is not canonical")
    require(header["schema"] == schema, "schema")
    return header, raw[4 + length:]


def card(header, name):
    value = header.get(name, "")
    require(len(value) <= CARD_B64, "key card exceeds its bound")
    return value


def decode_task(raw):
    header, body = decode_message(raw, 1)
    require(AGENT.fullmatch(header["buyer_agent_id"]) and WALLET.fullmatch(header["buyer_wallet"]) and
            CAP.fullmatch(header["capability_id"]), "identities")
    version = header["capability_version"]
    require(0 < len(version.encode("utf-8")) <= 128, "capability_version")
    require(header["package_base64"] != "", "package_base64 is empty")
    for name in ("execution_id", "execution_nonce", "call_hash"):
        require(HEX64.fullmatch(header[name]), name)
    require(SHA256.fullmatch(header["source_digest"]), "source_digest")
    require(header["call_lt"] != 0, "call_lt")
    card(header, "buyer_key_card_base64")
    require(0 < len(body) <= MAX_INPUT, "archive size")
    require(header["source_digest"] == "sha256:" + hashlib.sha256(body).hexdigest(), "archive digest")
    require(len(strict_b64(header["package_base64"], "package_base64")) > 0, "package is empty")
    return header, body


def decode_result(raw):
    header, body = decode_message(raw, 2)
    require(HEX64.fullmatch(header["response_hash"]), "response_hash")
    require(0 < len(body) <= MAX_RESULT, "artifact size")
    card(header, "provider_key_card_base64")
    require(len(strict_b64(header["receipt_boc_base64"], "receipt")) > 0, "receipt is empty")
    return header, body


def decode_ack(raw):
    header, body = decode_message(raw, 3)
    require(body == b"" and HEX64.fullmatch(header["response_hash"]), "ack")
    card(header, "buyer_key_card_base64")
    return header, body


def decode_result_request(raw):
    header, body = decode_message(raw, 4)
    require(body == b"", "result request has a body")
    card(header, "buyer_key_card_base64")
    return header, body


DECODERS = {1: decode_task, 2: decode_result, 3: decode_ack, 4: decode_result_request}


# --- frames ----------------------------------------------------------------

def chunk_length(total, index, count):
    want = (total + CHUNK - 1) // CHUNK
    require(want == count and index < count, "chunk count does not match the length")
    return CHUNK if index + 1 < count else total - (count - 1) * CHUNK


def decode_frame(raw):
    require(HEADER <= len(raw) <= HEADER + CHUNK, "frame size")
    magic, version, kind = struct.unpack(">IHB", raw[:7])
    require(magic == MAGIC and version == VERSION, "not a rail frame")
    require(kind in BOUNDS, "unknown kind")
    frame = {
        "kind": kind, "actor": raw[7:39], "request_id": struct.unpack(">Q", raw[39:47])[0],
        "request_hash": raw[47:79], "digest": raw[79:111], "total": struct.unpack(">I", raw[111:115])[0],
        "index": raw[115], "count": raw[116], "data": raw[HEADER:],
    }
    (length,) = struct.unpack(">I", raw[117:121])
    require(length == len(raw) - HEADER, "data length")
    zero = bytes(32)
    require(frame["actor"] != zero and frame["request_hash"] != zero and frame["digest"] != zero, "binding")
    require(0 < frame["total"] <= BOUNDS[kind] and 0 < frame["count"] <= MAX_CHUNKS and
            frame["index"] < frame["count"] and 0 < len(frame["data"]) <= CHUNK, "frame bounds")
    require(chunk_length(frame["total"], frame["index"], frame["count"]) == len(frame["data"]), "chunking")
    return frame


def encode_frame(kind, actor, request_id, request_hash, digest, total, index, count, data):
    return struct.pack(">IHB", MAGIC, VERSION, kind) + actor + struct.pack(">Q", request_id) + request_hash + \
        digest + struct.pack(">IBBI", total, index, count, len(data)) + data


def split(kind, actor, request_id, request_hash, message):
    require(0 < len(message) <= BOUNDS[kind], "message outside its bound")
    count = (len(message) + CHUNK - 1) // CHUNK
    digest = hashlib.sha256(message).digest()
    return [encode_frame(kind, actor, request_id, request_hash, digest, len(message), index, count,
                         message[index * CHUNK:(index + 1) * CHUNK]) for index in range(count)]


def join(raws):
    require(0 < len(raws) <= MAX_CHUNKS, "no complete frame set")
    frames = [decode_frame(raw) for raw in raws]
    first = frames[0]
    ordered = [None] * first["count"]
    for frame in frames:
        for key in ("kind", "actor", "request_id", "request_hash", "digest", "total", "count"):
            require(frame[key] == first[key], "frames of different messages")
        require(ordered[frame["index"]] is None, "repeated index")
        ordered[frame["index"]] = frame["data"]
    require(all(chunk is not None for chunk in ordered), "incomplete set")
    message = b"".join(ordered)
    require(len(message) == first["total"] and hashlib.sha256(message).digest() == first["digest"], "digest")
    return message


def refused(function, *arguments):
    try:
        function(*arguments)
    except Refused:
        return True
    return False


# --- vector checks -----------------------------------------------------------

def fill(size, seed):
    return bytes((seed + 7 * index) % 256 for index in range(size))


def archive_from(fields):
    match = re.fullmatch(r"byte i is \((\d+) \+ 7\*i\) mod 256", fields["archive_rule"])
    if not match:
        raise SystemExit("unknown archive rule")
    return fill(fields["archive_bytes"], int(match.group(1)))


def nsr1_hash(quote, execution, input_digest):
    data = struct.pack(">IH", 0x4E535231, 1) + quote + execution + input_digest
    # An ordinary cell of 816 bits and no references: descriptors 0 and 204.
    return hashlib.sha256(bytes([0, 2 * len(data)]) + data).digest()


def check_binding(document):
    binding = document["binding"]
    nonce = bytes.fromhex(binding["execution_nonce_hex"])
    execution = hashlib.sha256(EXECUTION_DOMAIN + b"\x00" + binding["buyer_agent_id"].encode() + b"\x00" + nonce).digest()
    if execution.hex() != binding["execution_id_hex"]:
        raise SystemExit("execution_id mismatch")
    source = bytes.fromhex(binding["source_digest"].removeprefix("sha256:"))
    input_digest = hashlib.sha256(INPUT_DOMAIN + source).digest()
    if input_digest.hex() != binding["input_digest_hex"]:
        raise SystemExit("input_digest mismatch")
    quote = bytes.fromhex(binding["quote_commitment"].removeprefix("tvm-cell-sha256:"))
    if nsr1_hash(quote, execution, input_digest).hex() != binding["request_hash_hex"]:
        raise SystemExit("request_hash mismatch")
    if binding["actor"] != "0:" + binding["actor_account_hex"]:
        raise SystemExit("actor mismatch")
    receipt = document["receipt"]
    small = bytes.fromhex(receipt["source_digest"].removeprefix("sha256:"))
    if hashlib.sha256(INPUT_DOMAIN + small).hexdigest() != receipt["input_digest_hex"]:
        raise SystemExit("receipt input_digest mismatch")
    return execution, input_digest


def check_receipt(document):
    receipt = document["receipt"]
    artifact = base64.b64decode(receipt["artifact_base64"], validate=True)
    if "sha256:" + hashlib.sha256(artifact).hexdigest() != receipt["artifact_digest"]:
        raise SystemExit("artifact digest mismatch")
    members = {}
    end = 0
    with tarfile.open(fileobj=io.BytesIO(artifact), mode="r:") as archive:
        for member in archive.getmembers():
            if not member.isreg() or member.name in members or member.name not in ("output.log", "report.json"):
                raise SystemExit("artifact members")
            members[member.name] = archive.extractfile(member).read()
            end = max(end, member.offset_data + (member.size + 511) // 512 * 512)
    # Section 7.2: the end-of-archive marker follows the last member and
    # nothing follows the marker.
    if artifact[end:] != bytes(1024):
        raise SystemExit("artifact does not end exactly with the end-of-archive marker")
    if set(members) != {"output.log", "report.json"} or \
            "sha256:" + hashlib.sha256(members["output.log"]).hexdigest() != receipt["result_digest"] or \
            "sha256:" + hashlib.sha256(members["report.json"]).hexdigest() != receipt["report_digest"]:
        raise SystemExit("artifact member digests mismatch")
    return artifact


def check_messages(document, artifact):
    binding = document["binding"]
    actor = bytes.fromhex(binding["actor_account_hex"])
    request_hash = bytes.fromhex(binding["request_hash_hex"])
    request_id = binding["request_id"]
    positive = {}
    for item in document["messages"]:
        kind = item["kind"]
        header_json = item["header_json"].encode()
        if "message_base64" in item:
            message = base64.b64decode(item["message_base64"], validate=True)
        else:
            message = struct.pack(">I", len(header_json)) + header_json + archive_from(item["fields"])
        if hashlib.sha256(message).hexdigest() != item["message_sha256"]:
            raise SystemExit(f"{item['name']}: message digest mismatch")
        header, body = DECODERS[kind](message)
        if encode_header(kind, header) != header_json or len(body) != item["body_length"]:
            raise SystemExit(f"{item['name']}: header mismatch")
        frame_request_id = item.get("request_id", request_id)
        if kind == 1:
            if header["execution_id"] != binding["execution_id_hex"] or header["request_id"] != frame_request_id:
                raise SystemExit(f"{item['name']}: execution_id or request_id")
            if "archive_rule" in item["fields"] and body != archive_from(item["fields"]):
                raise SystemExit(f"{item['name']}: archive")
        if kind == 2:
            if body != artifact or header["receipt_boc_base64"] != document["receipt"]["receipt_boc_base64"] or \
                    header["response_hash"] != document["receipt"]["response_hash_hex"]:
                raise SystemExit(f"{item['name']}: result does not carry the vector Receipt and artifact")
        if kind == 3 and header["response_hash"] != document["receipt"]["response_hash_hex"]:
            raise SystemExit(f"{item['name']}: ack response hash")
        frames = split(kind, actor, frame_request_id, request_hash, message)
        if len(frames) != len(item["frames"]):
            raise SystemExit(f"{item['name']}: frame count")
        for raw, expected in zip(frames, item["frames"]):
            if raw[:HEADER].hex() != expected["header_hex"] or hashlib.sha256(raw).hexdigest() != expected["frame_sha256"]:
                raise SystemExit(f"{item['name']}: frame {expected['index']} mismatch")
            frame = decode_frame(raw)
            start = expected["data_offset"]
            if frame["data"] != message[start:start + expected["data_length"]]:
                raise SystemExit(f"{item['name']}: frame data range")
        if join(list(reversed(frames))) != message:
            raise SystemExit(f"{item['name']}: join")
        positive[item["name"]] = frames
    return positive


def apply_edits(positive, reference):
    raw = bytearray(positive[reference["message"]][reference["index"]])
    for edit in reference.get("set", []):
        value = bytes.fromhex(edit["hex"])
        raw[edit["offset"]:edit["offset"] + len(value)] = value
    if "truncate_to" in reference:
        del raw[reference["truncate_to"]:]
    raw += bytes.fromhex(reference.get("append_hex", ""))
    raw = bytes(raw)
    if hashlib.sha256(raw).hexdigest() != reference["result_sha256"]:
        raise SystemExit(f"negative edit of {reference['message']} does not give the recorded bytes")
    return raw


def check_negatives(document, positive):
    names = set()
    for group in ("negative_frames", "negative_messages", "negative_joins"):
        for item in document[group]:
            if item["name"] in names:
                raise SystemExit(f"duplicate negative case {item['name']}")
            names.add(item["name"])
    for item in document["negative_frames"]:
        if not refused(decode_frame, apply_edits(positive, item["frame"])):
            raise SystemExit(f"negative frame accepted: {item['name']}")
    for item in document["negative_messages"]:
        raw = base64.b64decode(item["base64"], validate=True)
        if not refused(DECODERS[item["kind"]], raw):
            raise SystemExit(f"negative message accepted: {item['name']}")
    for item in document["negative_joins"]:
        raws = [apply_edits(positive, reference) for reference in item["frames"]]
        if not refused(join, raws):
            raise SystemExit(f"negative frame set joined: {item['name']}")
    return len(document["negative_frames"]), len(document["negative_messages"]), len(document["negative_joins"])


def main():
    document = json.loads(VECTOR.read_text())
    if document.get("schema") != "tos.service.rail-work-frames.v1.vectors":
        raise SystemExit("unexpected vector schema")
    constants = document["constants"]
    expected = {"frame_header_bytes": HEADER, "max_chunk_data": CHUNK, "max_chunks": MAX_CHUNKS,
                "max_message_header_bytes": MAX_HEADER, "max_inline_input_bytes": MAX_INPUT,
                "max_result_bytes": MAX_RESULT, "max_key_card_json_bytes": MAX_CARD,
                "max_task_message_bytes": BOUNDS[1], "max_result_message_bytes": BOUNDS[2],
                "max_ack_message_bytes": BOUNDS[3], "max_result_request_message_bytes": BOUNDS[4],
                "frame_magic_hex": "%08x" % MAGIC, "frame_version": VERSION}
    for name, value in expected.items():
        if constants.get(name) != value:
            raise SystemExit(f"constant {name} differs")
    check_binding(document)
    artifact = check_receipt(document)
    positive = check_messages(document, artifact)
    frames, messages, joins = check_negatives(document, positive)
    print(f"rail work frames v1 vectors: PASS ({len(positive)} messages; {frames} frame, {messages} message and "
          f"{joins} join negatives refused)")


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, TypeError, ValueError, tarfile.TarError, json.JSONDecodeError) as error:
        raise SystemExit(f"rail work frames v1 vectors: FAIL: {error}")
