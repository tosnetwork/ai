#!/usr/bin/env python3
"""Independent stdlib-only wire and pure-signature reproduction; no network.

Embedded cards/evidence are structural relay fixtures, not authenticated cards.
Finalized-state and consumer-authentication checks have separate Go tests.
"""

import hashlib
import importlib.util
import ipaddress
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "delegation_reference", Path(__file__).with_name("reproduce-agent-transport-v1.py")
)
DELEGATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DELEGATION)
P, D = DELEGATION.P, DELEGATION.D
L = 2**252 + 27742317777372353535851937790883648493
B = DELEGATION.decode_key((4 * pow(5, -1, P) % P).to_bytes(32, "little"))
HD = b"tos.service.agent-reachability-hint.v1\0"
RD = b"tos.service.agent-reachability-record.v1\0"
OD = b"tos.service.agent-reachability-hint.object.v1\0"
LD = b"tos.service.agent-direct-hello.v1\0"
TD = b"tos.service.agent-direct-receipt.v1\0"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def integer(value, bits):
    require(type(value) is int and 0 <= value < 2**bits, "integer")
    return value


def octets(value, size):
    require(isinstance(value, list) and len(value) == size, "array size")
    return bytes(integer(v, 8) for v in value)


def point(raw):
    require(len(raw) == 32, "point length")
    v = int.from_bytes(raw, "little")
    y, sign = v & (2**255 - 1), v >> 255
    require(y < P, "point canonical y")
    xx = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if x * x % P != xx:
        x = x * pow(2, (P - 1) // 4, P) % P
    require(x * x % P == xx, "point curve")
    if x & 1 != sign:
        x = (-x) % P
    require(not (x == 0 and sign), "point sign")
    return x, y


def encode_point(value):
    x, y = value
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def sign(seed, preimage):
    require(len(seed) == 32, "seed length")
    expanded = hashlib.sha512(seed).digest()
    secret = bytearray(expanded[:32])
    secret[0] &= 248
    secret[31] = (secret[31] & 63) | 64
    scalar = int.from_bytes(secret, "little")
    key = encode_point(DELEGATION.mul(B, scalar))
    nonce = (
        int.from_bytes(hashlib.sha512(expanded[32:] + preimage).digest(), "little") % L
    )
    r = encode_point(DELEGATION.mul(B, nonce))
    challenge = (
        int.from_bytes(hashlib.sha512(r + key + preimage).digest(), "little") % L
    )
    return r + ((nonce + challenge * scalar) % L).to_bytes(32, "little")


def verify(key, preimage, signature):
    require(len(signature) == 64, "signature length")
    public = DELEGATION.decode_key(key)
    r, s = point(signature[:32]), int.from_bytes(signature[32:], "little")
    require(s < L, "signature scalar")
    challenge = (
        int.from_bytes(
            hashlib.sha512(signature[:32] + key + preimage).digest(), "little"
        )
        % L
    )
    # Pure, cofactorless verification; R need not be a non-small-order key.
    require(
        DELEGATION.mul(B, s) == DELEGATION.add(r, DELEGATION.mul(public, challenge)),
        "signature",
    )


def delegation_input(value):
    raw = (
        DELEGATION.DOMAIN
        + octets(value["AgentDigest"], 32)
        + octets(value["TransportKey"], 32)
        + struct.pack(">Q", integer(value["AuthorizationEpoch"], 64))
        + octets(value["PolicyHash"], 32)
        + bytes([integer(value["Purposes"], 8)])
        + struct.pack(
            ">QQI",
            integer(value["NotBefore"], 64),
            integer(value["NotAfter"], 64),
            integer(value["MaxCredentialSeconds"], 32),
        )
    )
    DELEGATION.decode(raw)
    return raw


def object_hash(kind, raw):
    require(
        kind in (1, 2, 3) and 0 < len(raw) <= (18432 if kind == 3 else 9216),
        "object size/kind",
    )
    return hashlib.sha256(OD + bytes([kind]) + raw).digest()


def canonical_relay(value):
    from urllib.parse import urlsplit

    require(
        1 <= len(value) <= 256 and all(32 < ord(c) < 127 and c != "%" for c in value),
        "relay bytes",
    )
    parsed = urlsplit(value)
    require(
        parsed.netloc
        and parsed.netloc == parsed.netloc.lower()
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and "?" not in value
        and not parsed.fragment
        and "#" not in value,
        "relay authority",
    )
    require(
        not parsed.path.endswith("/")
        and (not parsed.path or parsed.path.startswith("/")),
        "relay path",
    )
    require(
        parsed.scheme == "https"
        or (
            parsed.scheme == "http"
            and parsed.hostname in ("127.0.0.1", "localhost", "::1")
        ),
        "relay scheme",
    )
    # urlsplit normalizes the scheme, so compare the literal spelling too.
    require(value.startswith(parsed.scheme + "://"), "relay canonical scheme")


def hint_input(value):
    require(octets(value["Signature"], 64) == bytes(64), "unsigned hint input")
    raw = HD + delegation_input(value["Delegation"])
    issued, expires = integer(value["IssuedAt"], 64), integer(value["ExpiresAt"], 64)
    require(issued < expires and expires - issued <= 86400, "hint TTL")
    relays = value["Relays"]
    require(
        1 <= len(relays) <= 4 and len(set(relays)) == len(relays),
        "relay count/duplicate",
    )
    raw += struct.pack(">QQB", issued, expires, len(relays))
    for relay in relays:
        canonical_relay(relay)
        encoded = relay.encode("ascii")
        raw += struct.pack(">H", len(encoded)) + encoded
    direct = value["Direct"] or []
    require(len(direct) <= 2, "direct count")
    raw += bytes([len(direct)])
    for entry in direct:
        require(
            integer(entry["Kind"], 8) == 1
            and 1 <= integer(entry["Port"], 16) <= 65535
            and integer(entry["InboundClass"], 8) in (1, 2),
            "direct shape",
        )
        raw += (
            bytes([entry["Kind"]])
            + octets(entry["ADNLID"], 32)
            + octets(entry["IPv4"], 4)
            + struct.pack(">HB", entry["Port"], entry["InboundClass"])
        )
    objects = value["Objects"] or []
    require(len(objects) <= 3, "object count")
    raw += bytes([len(objects)])
    previous = 0
    for ob in objects:
        kind, length = integer(ob["Kind"], 8), integer(ob["Length"], 32)
        require(
            previous < kind <= 3 and 0 < length <= (18432 if kind == 3 else 9216),
            "object shape/order",
        )
        raw += struct.pack(">BI", kind, length) + octets(ob["Digest"], 32)
        previous = kind
    require(len(raw) + 64 <= 1536, "hint size")
    return raw


class Reader:
    def __init__(self, raw):
        self.raw, self.at = raw, 0

    def take(self, n):
        require(0 <= n <= len(self.raw) - self.at, "truncated")
        value = self.raw[self.at : self.at + n]
        self.at += n
        return value

    def number(self, n):
        return int.from_bytes(self.take(n), "big")

    def end(self):
        require(self.at == len(self.raw), "trailing")


def decode_hint(raw):
    require(len(raw) <= 1536, "hint size")
    r = Reader(raw)
    require(r.take(len(HD)) == HD, "hint domain")
    delegation = r.take(167)
    DELEGATION.decode(delegation)
    issued, expires = r.number(8), r.number(8)
    require(issued < expires and expires - issued <= 86400, "hint TTL")
    count = r.number(1)
    require(1 <= count <= 4, "relay count")
    relays = []
    for _ in range(count):
        n = r.number(2)
        require(1 <= n <= 256, "relay length")
        relay = r.take(n).decode("ascii")
        canonical_relay(relay)
        require(relay not in relays, "relay duplicate")
        relays.append(relay)
    count = r.number(1)
    require(count <= 2, "direct count")
    directs = []
    for _ in range(count):
        kind, adnl, ip, port, inbound = (
            r.number(1),
            r.take(32),
            r.take(4),
            r.number(2),
            r.number(1),
        )
        require(kind == 1 and port > 0 and inbound in (1, 2), "direct shape")
        directs.append((adnl, ip, port, inbound))
    count = r.number(1)
    require(count <= 3, "object count")
    objects, previous = [], 0
    for _ in range(count):
        kind, n, digest = r.number(1), r.number(4), r.take(32)
        require(
            previous < kind <= 3 and 0 < n <= (18432 if kind == 3 else 9216),
            "object shape/order",
        )
        objects.append((kind, n, digest))
        previous = kind
    signature = r.take(64)
    r.end()
    return dict(
        delegation=delegation,
        issued=issued,
        expires=expires,
        direct=directs,
        objects=objects,
        signature=signature,
    )


def decode_record(raw):
    require(len(raw) <= 40960, "record size")
    r = Reader(raw)
    require(r.take(len(RD)) == RD, "record domain")
    size = r.number(2)
    require(size <= 1536, "hint length")
    hw = r.take(size)
    hint = decode_hint(hw)
    objects = []
    for kind, n, digest in hint["objects"]:
        value = r.take(n)
        require(object_hash(kind, value) == digest, "object digest")
        objects.append((kind, value))
    r.end()
    return hint, hw, objects


def hello_input(h):
    require(octets(h["Signature"], 64) == bytes(64), "unsigned hello input")
    require(integer(h["Role"], 8) in (1, 2), "role")
    require(
        h["Role"] != 1 or octets(h["ResponderNonce"], 32) == bytes(32),
        "initiator nonce shape",
    )
    return (
        LD
        + bytes([h["Role"]])
        + delegation_input(h["Delegation"])
        + octets(h["LocalADNL"], 32)
        + octets(h["PeerADNL"], 32)
        + octets(h["InitiatorNonce"], 32)
        + octets(h["ResponderNonce"], 32)
        + struct.pack(">Q", integer(h["IssuedAt"], 64))
    )


def decode_hello(raw):
    require(len(raw) == 402, "hello size")
    r = Reader(raw)
    require(r.take(len(LD)) == LD, "hello domain")
    role = r.number(1)
    delegation = r.take(167)
    DELEGATION.decode(delegation)
    local, peer, initiator, responder, issued = (
        r.take(32),
        r.take(32),
        r.take(32),
        r.take(32),
        r.number(8),
    )
    require(
        role in (1, 2) and (role != 1 or responder == bytes(32)), "hello role/nonce"
    )
    signature = r.take(64)
    r.end()
    return dict(
        role=role,
        delegation=delegation,
        local=local,
        peer=peer,
        initiator=initiator,
        responder=responder,
        issued=issued,
        signature=signature,
    )


def receipt_input(receipt):
    require(octets(receipt["Signature"], 64) == bytes(64), "unsigned receipt input")
    require(integer(receipt["Outcome"], 8) in (1, 2, 3), "outcome")
    return (
        TD
        + octets(receipt["RecipientAgent"], 32)
        + octets(receipt["EnvelopeID"], 32)
        + bytes([receipt["Outcome"]])
        + struct.pack(">Q", integer(receipt["ReceivedAt"], 64))
    )


def decode_receipt(raw):
    require(len(raw) == len(TD) + 137, "receipt size")
    r = Reader(raw)
    require(r.take(len(TD)) == TD, "receipt domain")
    agent, envelope, outcome, received, signature = (
        r.take(32),
        r.take(32),
        r.number(1),
        r.number(8),
        r.take(64),
    )
    require(outcome in (1, 2, 3), "outcome")
    r.end()
    return dict(
        agent=agent,
        envelope=envelope,
        outcome=outcome,
        received=received,
        signature=signature,
    )


def unique_pairs(entries):
    value = {}
    for key, item in entries:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def direct_address(raw, private):
    ip = ipaddress.IPv4Address(raw)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
        if ip in ipaddress.IPv4Network(cidr):
            return private
    return not any(
        ip in ipaddress.IPv4Network(cidr)
        for cidr in (
            "0.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
        )
    )


def verify_object(v, raw, now, decode_only=False):
    kind = v["kind"]
    expected_delegation = delegation_input(v["delegation"])
    key, expected_agent = expected_delegation[74:106], expected_delegation[42:74]
    if kind == "hint-record":
        hint, hw, objects = decode_record(raw)
        if decode_only:
            return
        require(hint["delegation"] == expected_delegation, "delegation binding")
        verify(key, hw[:-64], hint["signature"])
        require(hint["issued"] <= now + 300 and now < hint["expires"], "hint time")
        for _, ip, _, _ in hint["direct"]:
            require(
                direct_address(ip, v.get("allow_private_ipv4", False)), "direct address"
            )
        for kind, body in objects:
            if kind in (1, 2):
                packet = json.loads(body, object_pairs_hook=unique_pairs)
                require(
                    isinstance(packet, dict)
                    and packet.get("sender_agent_id")
                    == "agent_" + expected_agent.hex(),
                    "card sender",
                )
    elif kind == "hello":
        h = decode_hello(raw)
        if decode_only:
            return
        e = v["hello"]
        require(
            h["delegation"] == expected_delegation and h["role"] == e["Role"],
            "hello Agent/role",
        )
        require(
            h["local"] == octets(e["LocalADNL"], 32)
            and h["peer"] == octets(e["PeerADNL"], 32),
            "channel",
        )
        require(
            h["role"] != 2 or h["initiator"] == octets(e["InitiatorNonce"], 32),
            "challenge",
        )
        require(abs(h["issued"] - now) <= 120, "hello time")
        verify(key, raw[:-64], h["signature"])
    elif kind == "receipt":
        r = decode_receipt(raw)
        if decode_only:
            return
        require(
            r["agent"] == expected_agent
            and r["envelope"] == octets(v["receipt"]["EnvelopeID"], 32),
            "receipt binding",
        )
        verify(key, raw[:-64], r["signature"])
    else:
        raise ValueError("unknown kind")


def check_identity_r():
    seed = hashlib.sha256(b"public-cofactorless-reference-control").digest()
    expanded = hashlib.sha512(seed).digest()
    secret = bytearray(expanded[:32])
    secret[0] &= 248
    secret[31] = (secret[31] & 63) | 64
    key, message = (
        DELEGATION.public_key(seed),
        b"cofactorless receipt verification control",
    )
    identity = encode_point(DELEGATION.IDENTITY)
    challenge = (
        int.from_bytes(hashlib.sha512(identity + key + message).digest(), "little") % L
    )
    signature = identity + (
        (challenge * int.from_bytes(secret, "little")) % L
    ).to_bytes(32, "little")
    verify(key, message, signature)


def main():
    check_identity_r()
    corpus = json.loads(
        (ROOT / "test-vectors/agent-transport-reachability-v1.json").read_text()
    )
    require(corpus["schema"] == "tos.agent-transport-reachability-v1.vectors", "schema")
    require(len(corpus["positive"]) == 13 and len(corpus["negative"]) == 57, "coverage")
    bases = {}
    for v in corpus["positive"]:
        require(integer(v["delegation"]["AuthorizationEpoch"], 64) > 0, "positive Registry epoch")
        require(v["name"] not in bases, "duplicate positive")
        seed = bytes.fromhex(v["test_seed"])
        require(
            DELEGATION.public_key(seed) == octets(v["delegation"]["TransportKey"], 32),
            "seed/key",
        )
        kind = v["kind"]
        if kind == "hint-record":
            require(
                delegation_input(v["hint"]["Delegation"])
                == delegation_input(v["delegation"]),
                "hint delegation input",
            )
            preimage = hint_input(v["hint"])
            hint = preimage + sign(seed, preimage)
            objects = b"".join(bytes.fromhex(ob["hex"]) for ob in v.get("objects", []))
            require(
                [ob["kind"] for ob in v.get("objects", [])]
                == [ob["Kind"] for ob in (v["hint"]["Objects"] or [])],
                "input object kinds",
            )
            raw = RD + struct.pack(">H", len(hint)) + hint + objects
        elif kind == "hello":
            require(
                delegation_input(v["hello"]["Delegation"])
                == delegation_input(v["delegation"]),
                "hello delegation input",
            )
            preimage = hello_input(v["hello"])
            raw = preimage + sign(seed, preimage)
        elif kind == "receipt":
            preimage = receipt_input(v["receipt"])
            raw = preimage + sign(seed, preimage)
        else:
            raise ValueError("kind")
        require(
            raw.hex() == v["wire"] and hashlib.sha256(raw).hexdigest() == v["sha256"],
            "wire/signature/digest differs: " + v["name"],
        )
        verify_object(v, raw, corpus["now"])
        bases[v["name"]] = v
    names = set()
    for n in corpus["negative"]:
        require(
            n["name"] not in names and n["stage"] in ("decode", "verify"),
            "negative name/stage",
        )
        names.add(n["name"])
        v = bases[n["base"]]
        require(
            n["class"]
            == {
                "hint-record": "hint_invalid",
                "hello": "hello_invalid",
                "receipt": "receipt_invalid",
            }[v["kind"]],
            "negative class",
        )
        try:
            verify_object(
                v, bytes.fromhex(n["wire"]), corpus["now"], n["stage"] == "decode"
            )
        except (ValueError, UnicodeError):
            continue
        raise ValueError("negative accepted: " + n["name"])
    print(
        f"reachability: {len(bases)} signed objects reproduced; {len(names)} negatives refused"
    )


if __name__ == "__main__":
    main()
