#!/usr/bin/env python3
"""Independently reproduce the mailbox policy wire bytes and their refusals."""

import json
from pathlib import Path
import struct

DOMAIN = b"tos.service.relay-mailbox-policy.v1\x00"


def decode(raw):
    if len(raw) != len(DOMAIN) + 14 or not raw.startswith(DOMAIN):
        raise ValueError("policy shape")
    return struct.unpack(">QHI", raw[len(DOMAIN) :])


def accepts(raw, now, maximum_count, maximum_bytes):
    try:
        issued, count, size = decode(raw)
        return issued <= now + 300 and count <= maximum_count and size <= maximum_bytes
    except ValueError:
        return False


def main():
    path = (
        Path(__file__).resolve().parents[1]
        / "test-vectors/relay-mailbox-policy-v1.json"
    )
    corpus = json.loads(path.read_text())
    if corpus["schema"] != "tos.service.relay-mailbox-policy.vectors.v1":
        raise ValueError("corpus schema")
    for vector in corpus["vectors"]:
        expected = DOMAIN + struct.pack(
            ">QHI", vector["issued"], vector["count"], vector["bytes"]
        )
        raw = bytes.fromhex(vector["hex"])
        if raw != expected or not accepts(raw, 1800000000, 64, 4 << 20):
            raise ValueError("positive vector mismatch")
        for bad in [raw + b"\x00", raw[:-1], b"X" + raw[1:]]:
            if accepts(bad, 1800000000, 64, 4 << 20):
                raise ValueError("shape refusal missing")
    for fields in [
        (1800000301, 0, 0),
        (2**64 - 1, 0, 0),
        (1800000000, 65, 0),
        (1800000000, 0, (4 << 20) + 1),
    ]:
        if accepts(DOMAIN + struct.pack(">QHI", *fields), 1800000000, 64, 4 << 20):
            raise ValueError("semantic refusal missing")
    for vector in corpus["negative"]:
        expected = DOMAIN + struct.pack(
            ">QHI", vector["issued"], vector["count"], vector["bytes"]
        )
        if vector["name"] == "trailing":
            expected += b"\x00"
        elif vector["name"] == "truncated":
            expected = expected[:-1]
        elif vector["name"] == "domain":
            expected = bytes([expected[0] ^ 1]) + expected[1:]
        raw = bytes.fromhex(vector["hex"])
        if expected != raw or accepts(
            raw, corpus["now"], corpus["maximum_count"], corpus["maximum_bytes"]
        ):
            raise ValueError("frozen negative mismatch")
    print(
        "policy vectors independently reproduced: 3 positive, 7 frozen negative, 13 derived controls"
    )


if __name__ == "__main__":
    main()
