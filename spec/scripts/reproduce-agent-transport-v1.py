#!/usr/bin/env python3
"""Independent, isolated stdlib-only reproduction of transport delegation bytes.

Public keys are derived from the recorded test seeds with Edwards arithmetic;
no Go code, external module, subprocess, or generated encoder is used.
"""

import hashlib
import json
import struct
from pathlib import Path

DOMAIN = b"tos.service.agent-transport-delegation.v1\x00"
P = 2**255 - 19
D = -121665 * pow(121666, -1, P) % P
IDENTITY = (0, 1)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def add(a, b):
    x, y = a
    u, v = b
    z = D * x * u * y * v % P
    return (
        (x * v + y * u) * pow(1 + z, -1, P) % P,
        (y * v + x * u) * pow(1 - z, -1, P) % P,
    )


def mul(point, n):
    result = IDENTITY
    while n:
        if n & 1:
            result = add(result, point)
        point = add(point, point)
        n >>= 1
    return result


def decode_key(raw):
    require(len(raw) == 32, "key length")
    integer = int.from_bytes(raw, "little")
    y, sign = integer & (2**255 - 1), integer >> 255
    require(y < P, "noncanonical y")
    xx = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if x * x % P != xx:
        x = x * pow(2, (P - 1) // 4, P) % P
    require(x * x % P == xx, "off-curve key")
    if x & 1 != sign:
        x = P - x
    require(x < P and not (x == 0 and sign), "noncanonical x")
    require(mul((x, y), 8) != IDENTITY, "small-order key")
    return x, y


def public_key(seed):
    secret = bytearray(hashlib.sha512(seed).digest()[:32])
    secret[0] &= 248
    secret[31] = (secret[31] & 63) | 64
    # The canonical base point is y=4/5 with even x.
    base = decode_key((4 * pow(5, -1, P) % P).to_bytes(32, "little"))
    x, y = mul(base, int.from_bytes(secret, "little"))
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def decode(raw):
    require(len(raw) == 167 and raw[:42] == DOMAIN, "size/domain")
    decode_key(raw[74:106])
    purposes = raw[146]
    nb, na, maximum = struct.unpack(">QQI", raw[147:])
    require(0 < purposes <= 7, "purposes")
    require(0 < nb < na and na - nb <= 31536000, "lifetime")
    require(0 < maximum <= 604800, "credential limit")


def main():
    corpus = json.loads(
        (
            Path(__file__).resolve().parents[1] / "test-vectors/agent-transport-v1.json"
        ).read_text()
    )
    require(corpus["schema"] == "tos.agent-transport-delegation-v1.vectors", "schema")
    require(
        len(corpus["positive"]) == 4 and len(corpus["negative"]) == 15,
        "corpus coverage",
    )
    for v in corpus["positive"]:
        key = public_key(bytes.fromhex(v["seed"]))
        require(key.hex() == v["transport_key"], "public key derivation")
        raw = (
            DOMAIN
            + bytes.fromhex(v["agent_digest"])
            + key
            + struct.pack(">Q", v["epoch"])
            + bytes.fromhex(v["policy_hash"])
            + struct.pack(
                ">BQQI",
                v["purposes"],
                v["not_before"],
                v["not_after"],
                v["max_credential_seconds"],
            )
        )
        decode(raw)
        require(raw.hex() == v["wire"], "wire mismatch: " + v["name"])
        require(hashlib.sha256(raw).hexdigest() == v["digest"], "digest mismatch")
    for v in corpus["negative"]:
        try:
            decode(bytes.fromhex(v["wire"]))
        except ValueError:
            continue
        raise ValueError("negative accepted: " + v["name"])
    print("agent transport: 4 positive / 15 negative vectors independently reproduced")


if __name__ == "__main__":
    main()
