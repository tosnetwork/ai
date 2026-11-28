#!/usr/bin/env python3
"""Independent stdlib-only reproduction of the Messenger relay frame v2 codec.

It decodes every relay frame in the committed Messenger vectors
(messenger/internal/vectors/testdata/relay-vectors.json and the frames of
relay-room-vectors.json) from MESSENGER_RELAY_CARRIAGE_V1.md 1.1 as extended by
MESSENGER_TRANSPORT_V2.md 9.3, without the Go code, and requires each to decode
or fail exactly as its vector says. It then derives the frame-dependent bounds
from the field bounds alone and checks them against the values the
specification states. No network; run with python3 -I.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "messenger/internal/vectors/testdata"

FRAME_DOMAIN = b"tos.messaging.relay-frame.v2\0"
OBJECT_DOMAIN = b"tos.messaging.relay-object.v1\0"
MAX_FRAME = 190_464
BUCKETS = [1 << 10, 2 << 10, 4 << 10, 8 << 10, 16 << 10, 32 << 10, 64 << 10, 128 << 10, MAX_FRAME]
MAX_CARD = 9_216
MAX_EVIDENCE = 18_432
MAX_CREDENTIAL = 2_048
HOLDER_SEED = 32
MAX_PARTS = 8
KIND_COPY, KIND_ACK, KIND_ROOM, KIND_EVIDENCE = 1, 2, 3, 4
FIXED = len(FRAME_DOMAIN) + 3 + 32 + 2 + 2 + 2 + 4

# The fixed error texts of the Go codec, named by the vectors.
MALFORMED = "relay frame is malformed"
SIZE = "relay frame size is not a bucket size"
PADDING = "relay frame padding is not zero"
KIND = "relay frame kind is unknown"
DIGEST = "relay frame object digest mismatch"
CARD_LARGE = "relay frame card exceeds its bound"
CARD_REQUIRED = "relay frame of this kind must carry the sender card"
EVIDENCE_REQUIRED = "relay frame must carry relay identity evidence"
EVIDENCE_LARGE = "relay-evidence-too-large"
NOT_MINIMAL = "relay frame is not padded to its smallest bucket"
CREDENTIAL_LARGE = "relay frame credential exceeds its bound"
CREDENTIAL_MALFORMED = "relay frame credential or holder seed is malformed"


class Refused(Exception):
    pass


def refuse(reason):
    raise Refused(reason)


class Reader:
    def __init__(self, raw, offset):
        self.raw, self.offset = raw, offset

    def take(self, count):
        if count < 0 or count > len(self.raw) - self.offset:
            refuse(MALFORMED)
        value = self.raw[self.offset : self.offset + count]
        self.offset += count
        return value

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack(">H", self.take(2))[0]

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]


def smallest_bucket(n):
    for bucket in BUCKETS:
        if n <= bucket:
            return bucket
    return None


def object_digest(part):
    return hashlib.sha256(OBJECT_DOMAIN + part).digest()


def decode(raw):
    if len(raw) not in BUCKETS:
        refuse(SIZE)
    if not raw.startswith(FRAME_DOMAIN):
        refuse(MALFORMED)
    reader = Reader(raw, len(FRAME_DOMAIN))
    kind, index, count = reader.u8(), reader.u8(), reader.u8()
    digest = reader.take(32)
    if kind in (KIND_COPY, KIND_ACK, KIND_EVIDENCE):
        if count != 1 or index != 0:
            refuse(MALFORMED)
    elif kind == KIND_ROOM:
        if count == 0 or count > MAX_PARTS or index >= count:
            refuse(MALFORMED)
    else:
        refuse(KIND)
    card_length = reader.u16()
    if card_length > MAX_CARD:
        refuse(CARD_LARGE)
    card = reader.take(card_length)
    evidence_length = reader.u16()
    if evidence_length > MAX_EVIDENCE:
        refuse(EVIDENCE_LARGE)
    evidence = reader.take(evidence_length)
    credential_length = reader.u16()
    if credential_length > MAX_CREDENTIAL:
        refuse(CREDENTIAL_LARGE)
    credential = reader.take(credential_length)
    seed = reader.take(HOLDER_SEED) if credential_length else bytes(HOLDER_SEED)
    part_length = reader.u32()
    if part_length == 0 or part_length > MAX_FRAME - FIXED:
        refuse(MALFORMED)
    part = reader.take(part_length)
    if smallest_bucket(reader.offset) != len(raw):
        refuse(NOT_MINIMAL)
    if any(raw[reader.offset :]):
        refuse(PADDING)
    if kind == KIND_EVIDENCE and not card:
        refuse(CARD_REQUIRED)
    if kind == KIND_ROOM and index > 0:
        if card or evidence or not part:
            refuse(MALFORMED)
    else:
        if not evidence:
            refuse(EVIDENCE_REQUIRED)
        if kind == KIND_EVIDENCE and part not in (b"\x01", b"\x02"):
            refuse(MALFORMED)
    if credential and (seed == bytes(HOLDER_SEED) or kind == KIND_ROOM and index > 0):
        refuse(CREDENTIAL_MALFORMED)
    if count == 1 and object_digest(part) != digest:
        refuse(DIGEST)
    if count > 1 and digest == bytes(32):
        refuse(MALFORMED)
    return {"kind": kind, "credential": credential, "seed": seed, "part": part}


def check_vectors():
    checked = 0
    relay = json.loads((VECTORS / "relay-vectors.json").read_text())
    for vector in relay:
        if not vector["name"].startswith("relay-frame"):
            continue
        raw = bytes.fromhex(vector["wire_hex"])
        if len(raw) != vector["bytes"] or "sha256:" + hashlib.sha256(raw).hexdigest() != vector["sha256"]:
            raise SystemExit(f"{vector['name']}: bytes or digest")
        expected = vector.get("error", "")
        try:
            decoded = decode(raw)
            got = ""
        except Refused as error:
            decoded, got = None, str(error)
        if got != expected:
            raise SystemExit(f"{vector['name']}: reproducer says {got!r}, vector says {expected!r}")
        if vector["name"] == "relay-frame-copy-credential-maximal" and len(decoded["credential"]) != MAX_CREDENTIAL:
            raise SystemExit("maximal credential vector is not maximal")
        checked += 1
    rooms = json.loads((VECTORS / "relay-room-vectors.json").read_text())
    for vector in rooms:
        for frame in vector.get("frames", []):
            if "wire_hex" not in frame:
                continue
            try:
                decode(bytes.fromhex(frame["wire_hex"]))
            except Refused as error:
                # A reassembly vector may hold frames that only reassembly
                # refuses; every frame still decodes as a frame.
                raise SystemExit(f"{vector['name']}: frame refused: {error}")
            checked += 1
    return checked


def check_bounds():
    copy_fixed = len(b"tos.messaging.relay-delivery.v1\0") + 4 * (4 + 68) + (4 + 69) + 4 + 4 + 4 + 8
    bootstrap, token, seal = 18 << 10, 256, 4 << 10
    credential_field = MAX_CREDENTIAL + HOLDER_SEED
    largest_payload = MAX_FRAME - FIXED - MAX_CARD - MAX_EVIDENCE - credential_field - copy_fixed - bootstrap - token - seal
    first_part = MAX_FRAME - FIXED - MAX_CARD - MAX_EVIDENCE - credential_field
    later_part = MAX_FRAME - FIXED
    stated = {"largest relay Event payload": (largest_payload, 137_465),
              "fall from v1 (139,547)": (139_547 - largest_payload, 2_082),
              "frame fixed bytes": (FIXED, 74),
              "room part 0 object bytes": (first_part, 160_662),
              "room later part object bytes": (later_part, 190_390)}
    for name, (derived, want) in stated.items():
        if derived != want:
            raise SystemExit(f"{name}: derived {derived}, stated {want}")
    # A maximal room object still needs six parts.
    room_max = 1_056_858
    parts, covered = 1, first_part
    while covered < room_max:
        parts, covered = parts + 1, covered + later_part
    if parts != 6:
        raise SystemExit(f"maximal room object needs {parts} parts")
    return stated


def main():
    count = check_vectors()
    stated = check_bounds()
    print(f"relay frame v2 reproduced: {count} frames; bounds " +
          ", ".join(f"{name} {value}" for name, (value, _) in stated.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
