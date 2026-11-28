#!/usr/bin/env python3
"""Independent directory/revocation encodings and frozen refusal mutations."""

import hashlib
import json
import struct
from pathlib import Path

REV = b"tos.service.relay-revocation.v1\0"
INDEX = b"tos.service.relay-hint-index.v1\0"


def produce(kind, count, now):
    if kind == "revocation":
        return (
            REV
            + bytes([count])
            + b"".join(
                hashlib.sha256(f"revocation:{i}".encode()).digest()
                + struct.pack(">Q", now + i + 1)
                for i in range(count)
            )
        )
    entries = sorted(
        (hashlib.sha256(f"hint-index:{i}".encode()).digest(), now + i)
        for i in range(count)
    )
    return (
        INDEX
        + bytes([count])
        + b"".join(d + struct.pack(">QI", issued, 40960) for d, issued in entries)
    )


def accepts(raw, kind):
    domain, width, maximum = (REV, 40, 32) if kind == "revocation" else (INDEX, 44, 4)
    if not raw.startswith(domain) or len(raw) <= len(domain):
        return False
    count = raw[len(domain)]
    if (
        count > maximum
        or (kind == "revocation" and count == 0)
        or len(raw) != len(domain) + 1 + count * width
    ):
        return False
    if kind == "index":
        previous = None
        for i in range(count):
            entry = raw[len(domain) + 1 + i * width : len(domain) + 1 + (i + 1) * width]
            digest, size = entry[:32], struct.unpack(">I", entry[40:])[0]
            if not 0 < size <= 40960 or (previous is not None and digest <= previous):
                return False
            previous = digest
    return True


def mutate(raw, kind, mutation):
    if mutation == "trailing":
        return raw + b"\0"
    if mutation == "truncated":
        return raw[:-1]
    raw = bytearray(raw)
    start = len(INDEX) + 1
    if mutation == "domain":
        raw[0] ^= 1
    elif mutation == "count":
        raw[len(REV) if kind == "revocation" else len(INDEX)] = (
            33 if kind == "revocation" else 5
        )
    elif mutation == "duplicate":
        raw[start + 44 : start + 76] = raw[start : start + 32]
    elif mutation == "order":
        raw[start : start + 44], raw[start + 44 : start + 88] = (
            raw[start + 44 : start + 88],
            raw[start : start + 44],
        )
    elif mutation == "zero-length":
        raw[start + 40 : start + 44] = b"\0" * 4
    else:
        raise ValueError("unknown mutation")
    return bytes(raw)


def main():
    corpus = json.loads(
        (
            Path(__file__).resolve().parents[1] / "test-vectors/relay-directory-v2.json"
        ).read_text()
    )
    if (
        corpus["schema"] != "tos.service.relay-directory.vectors.v2"
        or len(corpus["positive"]) != 4
        or len(corpus["negative"]) != 11
    ):
        raise ValueError("incomplete corpus")
    bases = {}
    for vector in corpus["positive"]:
        raw = produce(vector["kind"], vector["count"], corpus["now"])
        if raw.hex() != vector["hex"] or not accepts(raw, vector["kind"]):
            raise ValueError("positive vector mismatch")
        bases[vector["name"]] = (raw, vector["kind"])
    for vector in corpus["negative"]:
        base, kind = bases[vector["base"]]
        raw = mutate(base, kind, vector["mutation"])
        if raw.hex() != vector["hex"] or accepts(raw, kind):
            raise ValueError("negative vector mismatch")
    print("directory wire: 4 positive and 11 negative vectors independently reproduced")


if __name__ == "__main__":
    main()
