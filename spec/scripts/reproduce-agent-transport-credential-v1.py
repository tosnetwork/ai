#!/usr/bin/env python3
"""Independent, isolated stdlib-only reproduction of relay credentials and
request proofs (Messenger Transport V2 sections 5.2 to 5.4).

Every key is derived from its recorded test seed, every block and proof is
signed again with RFC 8032 Ed25519 written here, and every credential is
decoded, chain-verified and evaluated by this file's own rules. No Go code,
external module, subprocess or generated encoder is used.
"""

import base64
import hashlib
import json
import re
import struct
from pathlib import Path

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, -1, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

CREDENTIAL_DOMAIN = b"tos.service.relay-credential.v1\x00"
CHAIN_DOMAIN = b"tos.service.relay-credential.chain.v1\x00"
BLOCK_DOMAIN = b"tos.service.relay-credential.block.v1\x00"
PROOF_DOMAIN = b"tos.service.relay-request.v1\x00"
DELEGATION_DOMAIN = b"tos.service.agent-transport-delegation.v1\x00"

CAVEATS = {
    "not_before": 1,
    "not_after": 2,
    "relay": 3,
    "operations": 4,
    "lane": 5,
    "max_envelopes": 6,
    "max_envelope_bytes": 7,
    "max_lane_bytes": 8,
}
OPERATIONS = {"deposit": 1, "list": 2, "fetch": 4, "publish": 8, "revoke": 16}
MAX_ENVELOPE = 262144


class Refused(Exception):
    def __init__(self, cls, message):
        super().__init__(cls + ": " + message)
        self.cls = cls


def invalid(ok, message):
    if not ok:
        raise Refused("credential_invalid", message)


def scope(ok, message):
    if not ok:
        raise Refused("credential_scope", message)


def require(ok, message):
    if not ok:
        raise AssertionError(message)


# --- Ed25519, RFC 8032, extended coordinates -------------------------------


def point_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    pa = (y1 - x1) * (y2 - x2) % P
    pb = (y1 + x1) * (y2 + x2) % P
    pc = 2 * t1 * t2 * D % P
    pd = 2 * z1 * z2 % P
    e, f, g, h = pb - pa, pd - pc, pd + pc, pb + pa
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def point_mul(s, point):
    result = (0, 1, 1, 0)
    while s:
        if s & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        s >>= 1
    return result


def encode_point(point):
    x, y, z, _ = point
    zi = pow(z, -1, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def decode_point(raw):
    """Strict decoding: canonical y and x, as the Go side's re-encoding check."""
    if len(raw) != 32:
        return None
    value = int.from_bytes(raw, "little")
    y, sign = value & (2**255 - 1), value >> 255
    if y >= P:
        return None
    xx = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if x * x % P != xx:
        x = x * SQRT_M1 % P
    if x * x % P != xx:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = P - x
    return (x, y, 1, x * y % P)


BASE = decode_point((4 * pow(5, -1, P) % P).to_bytes(32, "little"))
IDENTITY = encode_point((0, 1, 1, 0))


def check_key(raw):
    point = decode_point(raw)
    invalid(point is not None, "noncanonical Ed25519 key")
    invalid(encode_point(point_mul(8, point)) != IDENTITY, "small-order Ed25519 key")


def secret(seed):
    digest = hashlib.sha512(seed).digest()
    scalar = bytearray(digest[:32])
    scalar[0] &= 248
    scalar[31] = (scalar[31] & 63) | 64
    return int.from_bytes(scalar, "little"), digest[32:]


def public_key(seed):
    return encode_point(point_mul(secret(seed)[0], BASE))


def sign(seed, message):
    a, prefix = secret(seed)
    public = encode_point(point_mul(a, BASE))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    big_r = encode_point(point_mul(r, BASE))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little") % L
    return big_r + ((r + k * a) % L).to_bytes(32, "little")


def verify(public, message, signature):
    """Cofactorless check by re-encoding R, with canonical S."""
    point = decode_point(public)
    if point is None or len(signature) != 64:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % L
    x, y, z, t = point
    negative = (P - x, y, z, P - t)
    return encode_point(point_add(point_mul(s, BASE), point_mul(k, negative))) == signature[:32]


# --- delegation and relay URL ---------------------------------------------


def encode_delegation(v):
    return (
        DELEGATION_DOMAIN
        + bytes.fromhex(v["agent_digest"])
        + bytes.fromhex(v["transport_key"])
        + struct.pack(">Q", v["epoch"])
        + bytes.fromhex(v["policy_hash"])
        + struct.pack(">BQQI", v["purposes"], v["not_before"], v["not_after"], v["max_credential_seconds"])
    )


def decode_delegation(raw):
    invalid(len(raw) == 167 and raw[:42] == DELEGATION_DOMAIN, "delegation size/domain")
    check_key(raw[74:106])
    purposes = raw[146]
    nb, na, maximum = struct.unpack(">QQI", raw[147:])
    invalid(0 < purposes <= 7, "delegation purposes")
    invalid(0 < nb < na and na - nb <= 31536000, "delegation lifetime")
    invalid(0 < maximum <= 604800, "delegation credential limit")
    return {"agent": raw[42:74], "key": raw[74:106], "max": maximum}


URL = re.compile(r"^(https?)://(\[[0-9a-f:.]+\]|[a-z0-9._~!$&'()*+,;=-]+)(:[0-9]*)?(/[^?#]*)?$")


def relay_url_ok(raw):
    if not 1 <= len(raw) <= 256 or any(c <= 0x20 or c >= 0x7F or c == 0x25 for c in raw):
        return False
    match = URL.match(raw.decode("ascii"))
    if not match:
        return False
    scheme, host, _, path = match.groups()
    if path and path.endswith("/"):
        return False
    loopback = host in ("127.0.0.1", "localhost", "[::1]")
    return scheme == "https" or loopback


# --- credential ------------------------------------------------------------


def caveat_bytes(entries):
    return b"".join(bytes([t]) + struct.pack(">H", len(v)) + v for t, v in entries)


def typed_value(name, value):
    if name in ("not_before", "not_after", "max_lane_bytes"):
        return struct.pack(">Q", value)
    if name in ("max_envelopes", "max_envelope_bytes"):
        return struct.pack(">I", value)
    if name == "operations":
        return struct.pack(">H", value)
    if name == "relay":
        return value.encode("ascii")
    return bytes.fromhex(value)


def check_caveat(t, v):
    if t in (1, 2):
        invalid(len(v) == 8, "time caveat length")
    elif t == 3:
        invalid(relay_url_ok(v), "relay caveat")
    elif t == 4:
        invalid(len(v) == 2 and struct.unpack(">H", v)[0] & ~0x1F == 0, "operations caveat")
    elif t == 5:
        invalid(len(v) == 16 and any(v), "lane caveat")
    elif t == 6:
        invalid(len(v) == 4 and struct.unpack(">I", v)[0] >= 1, "max_envelopes caveat")
    elif t == 7:
        invalid(len(v) == 4 and 1 <= struct.unpack(">I", v)[0] <= MAX_ENVELOPE, "max_envelope_bytes caveat")
    elif t == 8:
        invalid(len(v) == 8 and struct.unpack(">Q", v)[0] >= 1, "max_lane_bytes caveat")
    else:
        invalid(False, "unknown caveat type %d" % t)


def chain_step(previous, extra):
    return hashlib.sha256(CHAIN_DOMAIN + previous + extra).digest()


def block_preimage(chain, index, next_key, entries):
    return BLOCK_DOMAIN + chain + bytes([index]) + next_key + bytes([len(entries)]) + caveat_bytes(entries)


def decode_credential(raw):
    invalid(len(raw) <= 2048, "credential size")
    invalid(len(raw) >= 200 and raw[:32] == CREDENTIAL_DOMAIN, "credential domain")
    delegation = decode_delegation(raw[32:199])
    count = raw[199]
    invalid(1 <= count <= 4, "block count")
    rest, blocks = raw[200:], []
    for _ in range(count):
        invalid(len(rest) >= 2, "block truncated")
        (length,) = struct.unpack(">H", rest[:2])
        invalid(len(rest) - 2 >= length, "block length")
        body, rest = rest[2 : 2 + length], rest[2 + length :]
        invalid(len(body) >= 97, "block too short")
        next_key = body[:32]
        check_key(next_key)
        caveat_count = body[32]
        invalid(1 <= caveat_count <= 8, "caveat count")
        cursor, end, entries = 33, len(body) - 64, []
        for _ in range(caveat_count):
            invalid(end - cursor >= 3, "caveat truncated")
            t = body[cursor]
            (n,) = struct.unpack(">H", body[cursor + 1 : cursor + 3])
            invalid(end - cursor - 3 >= n, "caveat value truncated")
            invalid(not entries or t > entries[-1][0], "caveat order")
            value = body[cursor + 3 : cursor + 3 + n]
            check_caveat(t, value)
            entries.append((t, value))
            cursor += 3 + n
        invalid(cursor == end, "block length disagrees")
        blocks.append({"next": next_key, "caveats": entries, "signature": body[end:]})
    invalid(not rest, "trailing bytes")
    first = dict(blocks[0]["caveats"])
    invalid(1 in first and 2 in first and 4 in first, "block 0 rule")
    nb, na = struct.unpack(">Q", first[1])[0], struct.unpack(">Q", first[2])[0]
    invalid(nb < na and na - nb <= delegation["max"], "block 0 lifetime")
    chain = [chain_step(hashlib.sha256(raw[32:199]).digest(), b"")]
    for b in blocks:
        chain.append(chain_step(chain[-1], b["signature"]))
    return {"delegation": delegation, "blocks": blocks, "chain": chain}


def verify_chain(credential):
    signer = credential["delegation"]["key"]
    for index, b in enumerate(credential["blocks"]):
        message = block_preimage(credential["chain"][index], index, b["next"], b["caveats"])
        invalid(verify(signer, message, b["signature"]), "block %d signature" % index)
        signer = b["next"]


def check_scope(credential, now, relay, operation):
    lanes = {v for b in credential["blocks"] for t, v in b["caveats"] if t == 5}
    scope(len(lanes) <= 1, "two lane values")
    for b in credential["blocks"]:
        for t, v in b["caveats"]:
            if t == 1:
                scope(struct.unpack(">Q", v)[0] <= now + 300, "not_before")
            elif t == 2:
                scope(now < struct.unpack(">Q", v)[0], "not_after")
            elif t == 3:
                scope(v == relay.encode("ascii"), "relay")
            elif t == 4:
                scope(struct.unpack(">H", v)[0] & operation, "operations")


def check_deposit(credential, usage):
    stored, stored_bytes, size = usage["stored_envelopes"], usage["stored_bytes"], usage["envelope_bytes"]
    scope(1 <= size <= MAX_ENVELOPE and stored < 64, "lane bounds")
    for b in credential["blocks"]:
        for t, v in b["caveats"]:
            if t == 6:
                scope(stored < struct.unpack(">I", v)[0], "max_envelopes")
            elif t == 7:
                scope(size <= struct.unpack(">I", v)[0], "max_envelope_bytes")
            elif t == 8:
                scope(stored_bytes + size <= struct.unpack(">Q", v)[0], "max_lane_bytes")


# --- request proof ---------------------------------------------------------

B64 = re.compile(r"^[A-Za-z0-9_-]*$")


def decode_b64(text, limit):
    invalid(len(text) <= limit and B64.match(text) and len(text) % 4 != 1, "header alphabet")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    invalid(base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == text, "header spelling")
    return raw


def proof_preimage(credential_id, relay, method, path, body, issued_at, nonce):
    invalid(relay_url_ok(relay.encode("ascii")), "proof relay")
    invalid(1 <= len(method) <= 255 and re.match(r"^[A-Z]+$", method), "proof method")
    invalid(
        1 <= len(path) <= 65535 and path[0] == "/" and all(0x20 < ord(c) < 0x7F and c not in "?#" for c in path),
        "proof path",
    )
    return (
        PROOF_DOMAIN
        + credential_id
        + struct.pack(">H", len(relay))
        + relay.encode("ascii")
        + bytes([len(method)])
        + method.encode("ascii")
        + struct.pack(">H", len(path))
        + path.encode("ascii")
        + hashlib.sha256(body).digest()
        + struct.pack(">Q", issued_at)
        + nonce
    )


def check_request(v):
    raw = decode_b64(v["credential_header"], 2731)
    credential = decode_credential(raw)
    proof = decode_b64(v["proof_header"], 139)
    invalid(len(proof) == 104, "proof length")
    agent = "agent_" + credential["delegation"]["agent"].hex()
    scope(agent == v["agent"], "path names another Agent")
    verify_chain(credential)
    check_scope(credential, v["now"], v["relay_url"], OPERATIONS[v["operation"]])
    (issued,) = struct.unpack(">Q", proof[:8])
    invalid(abs(v["now"] - issued) <= 120, "proof window")
    message = proof_preimage(
        credential["chain"][-1], v["relay_url"], v["method"], v["path"], bytes.fromhex(v["body"]), issued, proof[8:40]
    )
    invalid(verify(credential["blocks"][-1]["next"], message, proof[40:]), "proof signature")
    return message, proof[40:]


def outcome(action):
    try:
        action()
    except Refused as refusal:
        return refusal.cls
    return "accept"


def main():
    corpus = json.loads(
        (Path(__file__).resolve().parents[1] / "test-vectors/agent-transport-credential-v1.json").read_text()
    )
    require(corpus["schema"] == "tos.agent-transport-credential-v1.vectors", "schema")
    seeds = {}
    for k in corpus["keys"]:
        seed = bytes.fromhex(k["seed"])
        require(public_key(seed).hex() == k["public"], "key derivation " + k["name"])
        seeds[k["name"]] = seed
    delegations = {}
    for v in corpus["delegations"]:
        raw = encode_delegation(v)
        decode_delegation(raw)
        require(raw.hex() == v["wire"] and hashlib.sha256(raw).hexdigest() == v["digest"], "delegation " + v["name"])
        delegations[v["name"]] = raw
    credentials = {}
    for v in corpus["credentials"]:
        delegation = delegations[v["delegation"]]
        chain = [chain_step(hashlib.sha256(delegation).digest(), b"")]
        wire = CREDENTIAL_DOMAIN + delegation + bytes([len(v["blocks"])])
        for index, b in enumerate(v["blocks"]):
            entries = [(CAVEATS[c["type"]], typed_value(c["type"], c["value"])) for c in b["caveats"]]
            next_key = public_key(seeds[b["next"]])
            signature = sign(seeds[b["signer"]], block_preimage(chain[-1], index, next_key, entries))
            body = next_key + bytes([len(entries)]) + caveat_bytes(entries) + signature
            wire += struct.pack(">H", len(body)) + body
            chain.append(chain_step(chain[-1], signature))
        require(wire.hex() == v["wire"] and len(wire) == v["length"], "credential wire " + v["name"])
        require([c.hex() for c in chain] == v["chain"] and chain[-1].hex() == v["credential_id"], "chain " + v["name"])
        decoded = decode_credential(wire)
        verify_chain(decoded)
        require(decoded["blocks"][-1]["next"].hex() == v["holder"], "holder " + v["name"])
        credentials[v["name"]] = decoded
    require(max(len(bytes.fromhex(v["wire"])) for v in corpus["credentials"]) == 1916, "maximal credential")
    for e in corpus["evaluations"]:
        credential = credentials[e["credential"]]

        def evaluate():
            check_scope(credential, e["now"], e["relay_url"], OPERATIONS[e["operation"]])
            if e.get("usage"):
                check_deposit(credential, e["usage"])

        require(outcome(evaluate) == e["expect"], "evaluation " + e["name"])
    for v in corpus["proofs"]:
        result = {}

        def run():
            result["message"], result["signature"] = check_request(v)

        got = outcome(run)
        require(got == v["expect"], "proof %s: %s, want %s" % (v["name"], got, v["expect"]))
        if got == "accept":
            require(result["message"].hex() == v["preimage"], "proof preimage " + v["name"])
            require(result["signature"].hex() == v["signature"], "proof signature " + v["name"])
            require(sign(seeds[v["signer"]], result["message"]) == result["signature"], "proof resign " + v["name"])
    for v in corpus["negative_credentials"]:
        raw = bytes.fromhex(v["wire"])
        require(v["class"] == "credential_invalid", "negative class " + v["name"])
        if v["stage"] == "decode":
            require(outcome(lambda: decode_credential(raw)) == "credential_invalid", "negative decoded " + v["name"])
        else:
            decoded = decode_credential(raw)
            require(outcome(lambda: verify_chain(decoded)) == "credential_invalid", "negative verified " + v["name"])
    print(
        "agent transport credentials: %d credentials, %d evaluations, %d proofs, %d negatives independently reproduced"
        % (len(credentials), len(corpus["evaluations"]), len(corpus["proofs"]), len(corpus["negative_credentials"]))
    )


if __name__ == "__main__":
    main()
