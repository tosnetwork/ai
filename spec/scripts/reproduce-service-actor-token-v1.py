#!/usr/bin/env python3
"""Independent stdlib-only reproducer for the token-rail Service Actor vectors.

It shares no code with the implementation. It decodes every BOC of
test-vectors/service-actor-token-conformance-vectors.json, reproduces the code
hash, the actor address, the actor's token wallet, the deploy data, the terms
and terms_hash, the funding transfer and every log against
SERVICE_ACTOR_TOKEN_TVM_V1, then rebuilds the negative corpus
test-vectors/service-actor-token-negative-v1.json, compares it byte for byte
with the committed file, and refuses every negative case for its stated rule.

    python3 -I scripts/reproduce-service-actor-token-v1.py           # check
    python3 -I scripts/reproduce-service-actor-token-v1.py --write   # regenerate
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "test-vectors/service-actor-token-conformance-vectors.json"
CORPUS = ROOT / "test-vectors/service-actor-token-negative-v1.json"

TAG_SAT1 = 0x53415431
TAG_SAF1 = 0x53414631
TAG_SAO1 = 0x53414F31
TAG_SAB1 = 0x53414231
OP_TRANSFER = 0x0F8A7EA5
TOKEN_CALL = 0x53544301
MAX_COINS = 1 << 120
NO_TOKEN_CAP = MAX_COINS - 1
BRIDGE_PARAMS = (79, 81, 82, 83)
OUTCOMES = {"delivered": 0, "refused_at_r": 1, "bounced_at_s": 2}
# Every reason a SAF1 may carry: the admission reasons and 1929 (underfunded).
FUNDING_REASONS = {1901, 1902, 1903, 1904, 1905, 1906, 1907, 1908, 1909, 1923, 1924, 1925,
                   1926, 1927, 1928, 1929, 1932, 1933, 1934, 1935, 1937, 1939, 1944}


class Refused(ValueError):
    """A refusal, carrying the identifier of the rule that refused."""

    def __init__(self, rule):
        super().__init__(rule)
        self.rule = rule


def require(condition, rule):
    if not condition:
        raise Refused(rule)


# ---- cells and BOCs ----------------------------------------------------------------


class Cell:
    __slots__ = ("bits", "refs")

    def __init__(self, bits="", refs=()):
        if len(bits) > 1023 or len(refs) > 4:
            raise ValueError("cell overflow")
        self.bits = bits
        self.refs = tuple(refs)

    def depth(self):
        return 0 if not self.refs else 1 + max(r.depth() for r in self.refs)

    def data(self):
        bits = self.bits
        if len(bits) % 8:
            bits += "1" + "0" * (7 - len(bits) % 8)
        return int(bits, 2).to_bytes(len(bits) // 8, "big") if bits else b""

    def descriptors(self):
        n = len(self.bits)
        return bytes([len(self.refs), n // 8 + (n + 7) // 8])

    def hash(self):
        h = hashlib.sha256(self.descriptors() + self.data())
        for r in self.refs:
            h.update(r.depth().to_bytes(2, "big"))
        for r in self.refs:
            h.update(r.hash())
        return h.digest()


def from_boc(text):
    raw = base64.b64decode(text, validate=True)
    if raw[:4] != bytes.fromhex("b5ee9c72"):
        raise ValueError("not a BOC")
    flags, off = raw[4], raw[5]
    if flags & 0x38:
        raise ValueError("unsupported BOC flags")
    size, pos = flags & 7, 6

    def read(n):
        nonlocal pos
        value = int.from_bytes(raw[pos:pos + n], "big")
        pos += n
        return value

    count, roots, absent, total = read(size), read(size), read(size), read(off)
    if roots != 1 or absent:
        raise ValueError("a BOC of one root and no absent cells")
    root = read(size)
    if flags & 0x80:
        pos += count * off
    start, parsed = pos, []
    for _ in range(count):
        d1, d2 = raw[pos], raw[pos + 1]
        pos += 2
        if d1 & 0xF8:
            raise ValueError("an exotic or levelled cell")
        length = (d2 + 1) // 2
        bits = "".join(f"{b:08b}" for b in raw[pos:pos + length])
        pos += length
        if d2 % 2:
            bits = bits[:bits.rindex("1")]
        parsed.append((bits, [read(size) for _ in range(d1 & 7)]))
    if pos - start != total:
        raise ValueError("cell data size mismatch")
    if flags & 0x40:
        pos += 4
    if pos != len(raw):
        raise ValueError("trailing bytes")
    built = [None] * count
    for i in range(count - 1, -1, -1):
        bits, refs = parsed[i]
        if any(r <= i for r in refs):
            raise ValueError("a reference that does not point forward")
        built[i] = Cell(bits, [built[r] for r in refs])
    return built[root]


def to_boc(root):
    order, index, queue = [], {}, [root]
    while queue:
        cell = queue.pop(0)
        if cell.hash() in index:
            continue
        index[cell.hash()] = len(order)
        order.append(cell)
        queue.extend(cell.refs)
    size = max(1, (len(order).bit_length() + 7) // 8)
    body = b"".join(c.descriptors() + c.data() + b"".join(index[r.hash()].to_bytes(size, "big") for r in c.refs)
                    for c in order)
    off = max(1, (len(body).bit_length() + 7) // 8)
    head = bytes.fromhex("b5ee9c72") + bytes([size, off]) + len(order).to_bytes(size, "big")
    head += (1).to_bytes(size, "big") + (0).to_bytes(size, "big") + len(body).to_bytes(off, "big")
    return base64.b64encode(head + (0).to_bytes(size, "big") + body).decode()


class Slice:
    def __init__(self, cell):
        self.cell, self.pos, self.ref_pos = cell, 0, 0

    def uint(self, n):
        require(self.pos + n <= len(self.cell.bits), "missing_field")
        value = int(self.cell.bits[self.pos:self.pos + n] or "0", 2)
        self.pos += n
        return value

    def ref(self):
        require(self.ref_pos < len(self.cell.refs), "missing_field")
        self.ref_pos += 1
        return self.cell.refs[self.ref_pos - 1]

    def coins(self):
        return self.uint(8 * self.uint(4))

    def address(self):
        """MsgAddressInt: addr_std or addr_var; refuses addr_none and addr_extern."""
        tag = self.uint(2)
        require(tag in (2, 3), "address_required")
        if self.uint(1):
            self.uint(self.uint(5))
        if tag == 2:
            wc = self.uint(8)
            return (wc - 256 if wc >= 128 else wc, self.uint(256), True)
        length = self.uint(9)
        wc = self.uint(32)
        self.uint(length)
        return (wc, None, False)

    def end(self):
        require(self.pos == len(self.cell.bits) and self.ref_pos == len(self.cell.refs), "trailing_data")


class Builder:
    def __init__(self):
        self.bits, self.refs = "", []

    def uint(self, value, n):
        self.bits += format(value, f"0{n}b") if n else ""
        return self

    def coins(self, value, extra=0):
        length = (value.bit_length() + 7) // 8 + extra
        return self.uint(length, 4).uint(value, 8 * length)

    def std(self, account, wc=0):
        return self.uint(2, 2).uint(0, 1).uint(wc & 0xFF, 8).uint(account, 256)

    def ref(self, cell):
        self.refs.append(cell)
        return self

    def cell(self):
        return Cell(self.bits, self.refs)


def parse_text_address(text):
    wc, account = text.split(":")
    return int(wc), int(account, 16)


# ---- decoders (SERVICE_ACTOR_TOKEN_TVM_V1 sections 5 and 9) -------------------------


def encode_terms(t):
    tail = Builder().uint(t["metadata_hash"], 256).uint(t["proof_scheme_hash"], 256)
    tail.uint(t["has_attestor"], 1).uint(t["attestor_key_id"], 256)
    root = Builder().uint(t["policy_version"], 32)
    for name in ("price_per_call", "storage_fee", "cleanup_bounty"):
        root.coins(t[name])
    root.uint(t["response_sla"], 32).uint(t["refund_claim_window"], 32)
    root.uint(t["asset_master"], 256).uint(t["asset_wallet_code_hash"], 256)
    return root.ref(tail.cell()).cell()


def decode_terms(cell):
    s = Slice(cell)
    t = {"policy_version": s.uint(32), "price_per_call": s.coins(), "storage_fee": s.coins(),
         "cleanup_bounty": s.coins(), "response_sla": s.uint(32), "refund_claim_window": s.uint(32),
         "asset_master": s.uint(256), "asset_wallet_code_hash": s.uint(256)}
    tail = Slice(s.ref())
    s.end()
    t.update(metadata_hash=tail.uint(256), proof_scheme_hash=tail.uint(256), has_attestor=tail.uint(1),
             attestor_key_id=tail.uint(256))
    tail.end()
    require(t["has_attestor"] == (t["attestor_key_id"] != 0), "attestor_flag_disagrees")
    require(encode_terms(t).hash() == cell.hash(), "terms_not_canonical")
    return t


def decode_sat1(cell):
    s = Slice(cell)
    require(s.uint(32) == TAG_SAT1, "tag")
    log = {"request_id": s.uint(64), "caller": s.address(), "request_hash": s.uint(256),
           "response_deadline": s.uint(64), "refund_claim_deadline": s.uint(64)}
    terms_cell = s.ref()
    s.end()
    log["terms"] = decode_terms(terms_cell)
    log["terms_hash"] = terms_cell.hash().hex()
    require(log["response_deadline"] + log["terms"]["refund_claim_window"] == log["refund_claim_deadline"],
            "deadlines_disagree")
    return log


def decode_saf1(cell, resolver=True):
    s = Slice(cell)
    require(s.uint(32) == TAG_SAF1, "tag")
    log = {"query_id": s.uint(64), "from": s.address(), "amount": s.coins(), "reason": s.uint(16),
           "payout_id": s.uint(64)}
    s.end()
    if resolver:
        require(log["reason"] in FUNDING_REASONS, "resolver_reason_outside_set")
    return log


def decode_sao1(cell):
    s = Slice(cell)
    require(s.uint(32) == TAG_SAO1, "tag")
    log = {"payout_id": s.uint(64), "kind": s.uint(3), "request_id": s.uint(64), "recipient": s.address(),
           "amount": s.coins(), "outcome": s.uint(3)}
    s.end()
    require(1 <= log["kind"] <= 7, "kind_range")
    require(log["outcome"] <= 5, "outcome_range")
    return log


def decode_sab1(cell, resolver=True):
    s = Slice(cell)
    require(s.uint(32) == TAG_SAB1, "tag")
    log = {"query_id": s.uint(64), "purpose": s.uint(1), "target": s.uint(64), "balance": s.coins(),
           "surplus": s.coins(), "result": s.uint(16), "payout_id": s.uint(64)}
    s.end()
    if resolver:
        require(log["result"] in (0, 1936), "resolver_result_outside_set")
        require((log["result"] == 0) == (log["payout_id"] != 0), "resolver_result_disagrees_with_payout")
    return log


DECODERS = {"terms": decode_terms, "sat1": decode_sat1, "saf1": decode_saf1, "sao1": decode_sao1,
            "sab1": decode_sab1}


def token_call_payload(either):
    """The contract's parse of a notification's forward payload (section 7.1 step 3)."""
    s = Slice(either)
    if s.uint(1):
        inner = s.ref()
        s.end()
        s = Slice(inner)
    require(s.uint(32) == TOKEN_CALL, "payload_tag")
    request_hash, terms_hash = s.uint(256), s.uint(256)
    s.end()
    return request_hash, terms_hash


# ---- reproduction of the positive vectors ---------------------------------------------


def wallet_address(owner, master, code):
    settlement = Cell("0" * (64 + 64 + 1 + 32) + "0" * 192 + "0" + "0" * 128 + "0")
    data = Builder().coins(0).std(owner[1], owner[0]).std(master[1], master[0])
    data.ref(code).ref(settlement).uint(0, 16).uint(0, 1)
    return (0, int.from_bytes(Cell("00110", [code, data.cell()]).hash(), "big"))


def check_vectors(v):
    code = from_boc(v["contract_code_boc_base64"])
    require(v["contract_code_hash"] == "tvm-cell-sha256:" + code.hash().hex(), "code_hash")
    require(v["rail"] == "tos.service.service-actor-token.v1", "rail")
    data = from_boc(v["deploy_data_boc_base64"])
    actor = (0, int.from_bytes(Cell("00110", [code, data]).hash(), "big"))
    require(actor == parse_text_address(v["actor"]), "actor_address")

    s = Slice(data)
    owner = s.address()
    root = [s.uint(1), s.uint(64), s.uint(32), s.uint(32), s.uint(64)]
    require(root == [1, 0, 0, 0, 1], "deploy_root")
    policy, accounting, requests, payouts = (Slice(s.ref()) for _ in range(4))
    s.end()
    init = v["init"]
    require(owner[:2] == parse_text_address(init["owner"]), "owner")
    p = {"policy_version": policy.uint(32), "price_per_call": policy.coins(), "storage_fee": policy.coins(),
         "cleanup_bounty": policy.coins(), "response_sla": policy.uint(32),
         "refund_claim_window": policy.uint(32)}
    open_access, has_auth, auth = policy.uint(1), policy.uint(1), policy.address()
    rate, max_tokens = policy.uint(32), policy.coins()
    commitments = Slice(policy.ref())
    policy.end()
    require(p["policy_version"] == 0, "policy_version")
    for name in ("price_per_call", "storage_fee", "cleanup_bounty", "response_sla", "refund_claim_window"):
        require(str(p[name]) == str(init[name]), name)
    require(str(max_tokens) == init["max_token_liability"] and 0 < max_tokens <= NO_TOKEN_CAP, "max_token_liability")
    require(open_access == 1 and has_auth == 0 and auth == owner and rate == 0, "access")
    p.update(metadata_hash=commitments.uint(256), proof_scheme_hash=commitments.uint(256),
             has_attestor=commitments.uint(1), attestor_key_id=commitments.uint(256))
    require(commitments.uint(1) == 0 and p["has_attestor"] == 0 and p["attestor_key_id"] == 0, "attestor")
    commitments.end()

    native = [accounting.coins() for _ in range(3)]
    native += [accounting.uint(32), accounting.uint(32), accounting.uint(8), accounting.uint(32),
               accounting.uint(16), accounting.uint(8), accounting.uint(8)]
    require(native == [0] * 10, "native_ledger")
    token, query, route = Slice(accounting.ref()), accounting.ref(), Slice(accounting.ref())
    accounting.end()
    require([token.coins() for _ in range(5)] == [0] * 5, "token_ledger")
    token.end()
    require(query.bits == "0" * 236 and not query.refs, "empty_query")
    master = route.address()
    wallet_code_hash = route.uint(256)
    wallet_code = route.ref()
    bridge_param = route.uint(32)
    route.end()
    require(master[2] and master[:2] == parse_text_address(v["master"]), "route_master")
    require(wallet_code_hash == int(v["wallet_code_hash"], 16) == int.from_bytes(wallet_code.hash(), "big"),
            "route_wallet_code")
    require(bridge_param in BRIDGE_PARAMS, "route_bridge_param")
    require(requests.cell.bits == "0000" and payouts.cell.bits == "000", "empty_dictionaries")
    require(not requests.cell.refs and not payouts.cell.refs, "empty_dictionaries")
    require(wallet_address(actor, master, wallet_code) == parse_text_address(v["actor_wallet"]), "actor_wallet")

    p.update(asset_master=master[1], asset_wallet_code_hash=wallet_code_hash)
    terms_cell = from_boc(v["terms_cell_boc_base64"])
    require(decode_terms(terms_cell) == p and encode_terms(p).hash() == terms_cell.hash(), "terms")
    require(terms_cell.hash().hex() == v["terms_hash"], "terms_hash")

    f = Slice(from_boc(v["funding_transfer_body_boc_base64"]))
    require(f.uint(32) == OP_TRANSFER, "funding_op")
    f.uint(64)
    require(f.coins() == p["price_per_call"], "funding_amount")
    require(f.address()[:2] == actor, "funding_destination")
    f.address()
    require(f.uint(1) == 0, "funding_custom_payload")
    require(f.coins() > p["storage_fee"], "funding_forward")
    payload = Cell(f.cell.bits[f.pos:], f.cell.refs)
    require(token_call_payload(payload)[1] == int(v["terms_hash"], 16), "funding_payload")

    sat1 = decode_sat1(from_boc(v["sat1"][0]))
    require(sat1["terms_hash"] == v["terms_hash"] and sat1["terms"] == p, "sat1_terms")
    require(sat1["request_id"] == 0 and sat1["caller"][2], "sat1_request")
    refused = decode_saf1(from_boc(v["saf1_refused_amount"][0]))
    require(refused["reason"] == 1902 and refused["payout_id"] != 0
            and refused["amount"] == p["price_per_call"] + 1, "saf1_refused_amount")
    under = decode_saf1(from_boc(v["saf1_underfunded"][0]))
    require(under["reason"] == 1929 and under["payout_id"] == 0, "saf1_underfunded")
    for name, bocs in v["sao1"].items():
        for text in bocs:
            log = decode_sao1(from_boc(text))
            if name.startswith("kind_"):
                kind, way = name[5], name[7:]
                require(log["kind"] == int(kind) and log["outcome"] == OUTCOMES[way], name)
    require(decode_sao1(from_boc(v["sao1"]["funding_return_delivered"][0]))["payout_id"] == refused["payout_id"],
            "funding_return_payout")
    sab1 = decode_sab1(from_boc(v["sab1_surplus"][0]))
    surplus = decode_sao1(from_boc(v["sao1"]["surplus_delivered"][0]))
    require(sab1["purpose"] == 0 and sab1["result"] == 0 and sab1["payout_id"] == surplus["payout_id"]
            and surplus["kind"] == 6 and surplus["amount"] <= sab1["surplus"], "sab1_surplus")


# ---- the negative corpus -----------------------------------------------------------------


def rebuilt(cell, bits=None, refs=None):
    return Cell(cell.bits if bits is None else bits, cell.refs if refs is None else refs)


def with_tag(cell, tag):
    return rebuilt(cell, format(tag, "032b") + cell.bits[32:])


def set_bits(cell, offset, width, value):
    return rebuilt(cell, cell.bits[:offset] + format(value, f"0{width}b") + cell.bits[offset + width:])


def coins_noncanonical(cell, offset):
    """Re-encodes the Coins at `offset` one byte longer, with a leading zero byte."""
    length = int(cell.bits[offset:offset + 4], 2)
    value = cell.bits[offset + 4:offset + 4 + 8 * length]
    longer = format(length + 1, "04b") + "0" * 8 + value
    return rebuilt(cell, cell.bits[:offset] + longer + cell.bits[offset + 4 + 8 * length:])


def addr_none_at(cell, offset):
    """Replaces the 267-bit addr_std at `offset` with addr_none."""
    return rebuilt(cell, cell.bits[:offset] + "00" + cell.bits[offset + 267:])


EMPTY = Cell()


def sat1_terms(sat1, edit):
    terms = sat1.refs[0]
    return rebuilt(sat1, refs=(edit(terms),))


def tail_edit(edit):
    return lambda terms: rebuilt(terms, refs=(edit(terms.refs[0]),))


def decoder_cases(v):
    sat1 = from_boc(v["sat1"][0])
    terms = from_boc(v["terms_cell_boc_base64"])
    saf1 = from_boc(v["saf1_refused_amount"][0])
    sao1 = from_boc(v["sao1"]["kind_1_delivered"][0])
    sab1 = from_boc(v["sab1_surplus"][0])
    # Field offsets: SAT1 tag 32, request_id 64, caller 267, request_hash 256,
    # deadlines 64 + 64. Terms: version 32, then price Coins. SAO1: tag 32,
    # payout_id 64, kind 3, request_id 64, recipient 267, amount, outcome 3.
    sat1_rcd = 32 + 64 + 267 + 256 + 64
    terms_tail_flag = 512
    sao1_kind, sao1_recipient = 96, 96 + 3 + 64
    sao1_outcome = len(sao1.bits) - 3
    sab1_result = len(sab1.bits) - 64 - 16
    sab1_payout = len(sab1.bits) - 64
    cases = [
        ("sat1", "sat1_wrong_tag", "sat1", "t3_decoder", "tag", "the tag is SAT1 (0x53415431)",
         with_tag(sat1, 0x53415231)),
        ("sat1", "sat1_trailing_bit", "sat1", "t3_decoder", "trailing_data", "no bit follows the last field",
         rebuilt(sat1, sat1.bits + "0")),
        ("sat1", "sat1_trailing_reference", "sat1", "t3_decoder", "trailing_data",
         "exactly one reference, the terms", rebuilt(sat1, refs=sat1.refs + (EMPTY,))),
        ("sat1", "sat1_missing_terms", "sat1", "t3_decoder", "missing_field", "the terms reference is present",
         rebuilt(sat1, refs=())),
        ("sat1", "sat1_missing_refund_claim_deadline", "sat1", "t3_decoder", "missing_field",
         "every field is present", rebuilt(sat1, sat1.bits[:sat1_rcd])),
        ("sat1", "sat1_caller_addr_none", "sat1", "t3_decoder", "address_required",
         "caller is a MsgAddressInt", addr_none_at(sat1, 96)),
        ("sat1", "sat1_deadlines_disagree", "sat1", "t3_decoder", "deadlines_disagree",
         "response_deadline + refund_claim_window == refund_claim_deadline",
         set_bits(sat1, sat1_rcd, 64, int(sat1.bits[sat1_rcd:sat1_rcd + 64], 2) + 1)),
        ("sat1", "sat1_terms_attestor_flag_without_key", "sat1", "t3_decoder", "attestor_flag_disagrees",
         "has_attestor = 1 needs a non-zero key id",
         sat1_terms(sat1, tail_edit(lambda t: set_bits(t, terms_tail_flag, 1, 1)))),
        ("sat1", "sat1_terms_key_without_attestor", "sat1", "t3_decoder", "attestor_flag_disagrees",
         "has_attestor = 0 needs a zero key id",
         sat1_terms(sat1, tail_edit(lambda t: set_bits(t, terms_tail_flag + 1, 256, 1)))),
        ("sat1", "sat1_terms_noncanonical_price", "sat1", "t3_decoder", "terms_not_canonical",
         "the terms are the canonical encoding", sat1_terms(sat1, lambda t: coins_noncanonical(t, 32))),
        ("terms", "terms_trailing_bit", "terms_cell", "t3_decoder", "trailing_data",
         "no bit follows asset_wallet_code_hash", rebuilt(terms, terms.bits + "1")),
        ("terms", "terms_trailing_reference", "terms_cell", "t3_decoder", "trailing_data",
         "exactly one reference, the tail", rebuilt(terms, refs=terms.refs + (EMPTY,))),
        ("terms", "terms_missing_tail", "terms_cell", "t3_decoder", "missing_field", "the tail is present",
         rebuilt(terms, refs=())),
        ("terms", "terms_tail_trailing_bit", "terms_cell", "t3_decoder", "trailing_data",
         "no bit follows attestor_key_id", tail_edit(lambda t: rebuilt(t, t.bits + "0"))(terms)),
        ("terms", "terms_noncanonical_storage_fee", "terms_cell", "t3_decoder", "terms_not_canonical",
         "the terms are the canonical encoding",
         coins_noncanonical(terms, 32 + 4 + 8 * int(terms.bits[32:36], 2))),
        ("saf1", "saf1_wrong_tag", "saf1_refused_amount", "t3_decoder", "tag", "the tag is SAF1 (0x53414631)",
         with_tag(saf1, TAG_SAO1)),
        ("saf1", "saf1_trailing_bit", "saf1_refused_amount", "t3_decoder", "trailing_data",
         "no bit follows payout_id", rebuilt(saf1, saf1.bits + "0")),
        ("saf1", "saf1_trailing_reference", "saf1_refused_amount", "t3_decoder", "trailing_data",
         "no reference", rebuilt(saf1, refs=(EMPTY,))),
        ("saf1", "saf1_missing_payout_id", "saf1_refused_amount", "t3_decoder", "missing_field",
         "every field is present", rebuilt(saf1, saf1.bits[:-64])),
        ("saf1", "saf1_from_addr_none", "saf1_refused_amount", "t3_decoder", "address_required",
         "from is a MsgAddressInt", addr_none_at(saf1, 96)),
        ("saf1", "saf1_reason_not_a_funding_reason", "saf1_refused_amount", "resolver",
         "resolver_reason_outside_set", "reason is an admission reason or 1929",
         set_bits(saf1, len(saf1.bits) - 64 - 16, 16, 1910)),
        ("sao1", "sao1_wrong_tag", "sao1.kind_1_delivered", "t3_decoder", "tag", "the tag is SAO1 (0x53414f31)",
         with_tag(sao1, TAG_SAB1)),
        ("sao1", "sao1_trailing_bit", "sao1.kind_1_delivered", "t3_decoder", "trailing_data",
         "no bit follows outcome", rebuilt(sao1, sao1.bits + "0")),
        ("sao1", "sao1_trailing_reference", "sao1.kind_1_delivered", "t3_decoder", "trailing_data",
         "no reference", rebuilt(sao1, refs=(EMPTY,))),
        ("sao1", "sao1_missing_outcome", "sao1.kind_1_delivered", "t3_decoder", "missing_field",
         "every field is present", rebuilt(sao1, sao1.bits[:-3])),
        ("sao1", "sao1_kind_zero", "sao1.kind_1_delivered", "t3_decoder", "kind_range", "kind is 1-7",
         set_bits(sao1, sao1_kind, 3, 0)),
        ("sao1", "sao1_outcome_six", "sao1.kind_1_delivered", "t3_decoder", "outcome_range", "outcome is 0-5",
         set_bits(sao1, sao1_outcome, 3, 6)),
        ("sao1", "sao1_outcome_seven", "sao1.kind_1_delivered", "t3_decoder", "outcome_range",
         "outcome is 0-5", set_bits(sao1, sao1_outcome, 3, 7)),
        ("sao1", "sao1_recipient_addr_none", "sao1.kind_1_delivered", "t3_decoder", "address_required",
         "recipient is a MsgAddressInt", addr_none_at(sao1, sao1_recipient)),
        ("sab1", "sab1_wrong_tag", "sab1_surplus", "t3_decoder", "tag", "the tag is SAB1 (0x53414231)",
         with_tag(sab1, TAG_SAF1)),
        ("sab1", "sab1_trailing_bit", "sab1_surplus", "t3_decoder", "trailing_data", "no bit follows payout_id",
         rebuilt(sab1, sab1.bits + "1")),
        ("sab1", "sab1_trailing_reference", "sab1_surplus", "t3_decoder", "trailing_data", "no reference",
         rebuilt(sab1, refs=(EMPTY,))),
        ("sab1", "sab1_missing_payout_id", "sab1_surplus", "t3_decoder", "missing_field",
         "every field is present", rebuilt(sab1, sab1.bits[:-64])),
        ("sab1", "sab1_result_not_0_or_1936", "sab1_surplus", "resolver", "resolver_result_outside_set",
         "result is 0 or 1936", set_bits(sab1, sab1_result, 16, 1)),
        ("sab1", "sab1_paid_without_payout", "sab1_surplus", "resolver",
         "resolver_result_disagrees_with_payout", "result 0 names its payout",
         set_bits(sab1, sab1_payout, 64, 0)),
        ("sab1", "sab1_refused_with_payout", "sab1_surplus", "resolver",
         "resolver_result_disagrees_with_payout", "result 1936 names no payout",
         set_bits(sab1, sab1_result, 16, 1936)),
    ]
    return cases


def payload_cases():
    call = Builder().uint(TOKEN_CALL, 32).uint(0, 512).cell()
    positives = [
        ("by_reference", "bit 1 and the token_call by reference", Cell("1", [call])),
        ("inline", "bit 0 and the token_call inline", Cell("0" + call.bits)),
    ]
    negatives = [
        ("no_payload", "a token_call is present (bit 0 and nothing inline)", Cell("0")),
        ("another_tag", "the tag is 0x53544301",
         Cell("1", [Builder().uint(0x53544399, 32).uint(0, 512).cell()])),
        ("too_short", "request_hash and expected_terms_hash are present",
         Cell("1", [Builder().uint(TOKEN_CALL, 32).uint(0, 256).cell()])),
        ("trailing_bits", "no bit follows expected_terms_hash", Cell("1", [Cell(call.bits + "1")])),
        ("trailing_reference", "the token_call has no reference", Cell("1", [Cell(call.bits, [EMPTY])])),
        ("reference_and_trailing_bit", "nothing follows the payload reference", Cell("10", [call])),
    ]
    return positives, negatives


# Every exit and reason code of SERVICE_ACTOR_TOKEN_TVM_V1 section 15, the path
# it takes, and the T3 sandbox tests (tests/service_actor_token/<file>.rs) that
# execute it. "tests" are checked against the tos sources by
# verify-service-actor-token-vector-copy.py --tos-repo.
REFUSAL_CODES = [
    (9, "cell_underflow", "throw", "any handler; anycast or addr_var addresses",
     ["payouts::claim_destinations_are_validated"], None),
    (62, "pq_key_length", "throw", "rotate_attestor_key, respond",
     [], "asserted only as aborted (ported::malformed_attestor_keys_and_signatures_are_refused)"),
    (63, "pq_malformed_key", "throw", "rotate_attestor_key, respond",
     [], "asserted only as aborted (ported::malformed_attestor_keys_and_signatures_are_refused)"),
    (1900, "not_owner", "throw", "respond, owner ops",
     ["ported::only_owner_can_call_owner_only_operations", "ported::respond_requires_owner_and_a_pending_request"],
     None),
    (1901, "inactive", "reason", "admission", ["funding::every_admission_refusal_ends_in_a_funding_return"], None),
    (1902, "insufficient_payment", "reason; throw in update_policy",
     "admission (zero price or cap, amount other than the price, value below the budget), update_policy",
     ["funding::the_exact_amount_rule_refuses_over_and_underpayment",
      "funding::every_admission_refusal_ends_in_a_funding_return", "ported::update_policy_enforces_every_bound"],
     None),
    (1903, "invalid_response_sla", "reason; throw in update_policy", "admission, update_policy",
     ["funding::every_admission_refusal_ends_in_a_funding_return", "ported::update_policy_enforces_every_bound"],
     None),
    (1904, "invalid_refund_claim_window", "reason; throw in update_policy", "admission, update_policy",
     ["funding::every_admission_refusal_ends_in_a_funding_return", "ported::update_policy_enforces_every_bound"],
     None),
    (1905, "invalid_cleanup_bounty", "reason; throw in update_policy", "admission, update_policy",
     ["funding::every_admission_refusal_ends_in_a_funding_return", "ported::update_policy_enforces_every_bound"],
     None),
    (1906, "insufficient_storage_fee", "reason; throw in update_policy", "admission, update_policy",
     ["funding::every_admission_refusal_ends_in_a_funding_return", "ported::update_policy_enforces_every_bound"],
     None),
    (1907, "capacity_exceeded_global", "reason", "admission",
     ["capacity::with_every_cap_full_a_further_funding_is_refused_and_returned",
      "funding::every_admission_refusal_ends_in_a_funding_return"], None),
    (1908, "capacity_exceeded_caller", "reason", "admission",
     ["funding::every_admission_refusal_ends_in_a_funding_return"], None),
    (1909, "request_id_overflow", "reason; throw in payout-creating ops", "admission, payout-creating ops",
     ["funding::every_admission_refusal_ends_in_a_funding_return"],
     "the payout-id guards of the payout-creating ops are not executed by a test"),
    (1910, "unknown_op", "throw", "any", [],
     "asserted only as a refusal that leaves the balance unchanged (gas::* unknown op case)"),
    (1911, "bad_response_signature", "throw", "respond",
     ["ported::a_response_signed_for_another_network_is_refused",
      "ported::malformed_attestor_keys_and_signatures_are_refused"], None),
    (1912, "response_window_closed", "throw", "respond", ["ported::respond_boundary_is_exact"], None),
    (1913, "request_not_pending", "throw", "respond, expire",
     ["ported::respond_requires_owner_and_a_pending_request", "ported::duplicate_expire_claim_and_sweep_are_rejected"],
     None),
    (1914, "expire_too_early", "throw", "expire", ["ported::expire_boundary_is_exact"], None),
    (1915, "expire_too_late", "throw", "expire", ["ported::expire_boundary_is_exact"], None),
    (1916, "refund_claim_expired", "throw", "claim_refund", ["ported::claim_refund_boundary_is_exact"], None),
    (1917, "refund_not_found", "throw", "claim_refund", ["ported::duplicate_expire_claim_and_sweep_are_rejected"],
     None),
    (1918, "not_refund_caller", "throw", "claim_refund, claim_returned",
     ["ported::only_the_original_caller_can_claim_their_refund", "payouts::claim_destinations_are_validated"], None),
    (1919, "sweep_too_early", "throw", "sweep_expired_request, sweep_returned",
     ["ported::sweep_boundary_is_exact", "payouts::a_returned_entry_is_swept_to_its_caller_after_its_deadline"],
     None),
    (1920, "request_not_live", "throw", "sweep_expired_request",
     ["ported::sweep_works_against_a_properly_expired_refund_entry_and_not_on_a_request_live_nowhere"], None),
    (1921, "insufficient_balance", "throw", "payout-creating ops, abandon_payout", [],
     "defensive: the balance includes the incoming message, so it is unreachable"),
    (1922, "insufficient_revenue", "throw", "withdraw_revenue",
     ["ported::withdraw_revenue_is_capped_by_balance_and_never_takes_locked_fees"], None),
    (1923, "not_authorized", "reason", "admission", ["funding::every_admission_refusal_ends_in_a_funding_return"],
     None),
    (1924, "rate_limited", "reason", "admission", ["funding::every_admission_refusal_ends_in_a_funding_return"],
     None),
    (1925, "bad_attestor_key", "reason", "admission",
     ["ported::a_deployed_attestor_key_must_match_its_published_key_id_and_revocation_clears_it",
      "funding::every_admission_refusal_ends_in_a_funding_return"], None),
    (1926, "terms_mismatch", "reason", "admission",
     ["ported::a_call_quoted_under_one_policy_is_refused_under_another"], None),
    (1927, "amount_range", "reason; throw on checked sums", "admission, checked sums",
     ["ported::a_liability_that_would_go_negative_is_refused_with_the_range_code"], None),
    (1928, "operating_reserve_unfunded", "reason", "admission",
     ["ported::solvency_admission_requires_existing_obligations_and_preserves_operator_excess"], None),
    (1929, "insufficient_execution_payment", "reason when underfunded; throw in payout ops",
     "underfunded notification, payout-creating ops, recheck_payout, recover_surplus, withdraw_revenue",
     ["funding::underfunded_and_forwardless_transfers_store_nothing_and_become_surplus",
      "ported::solvency_payouts_require_execution_budget"], None),
    (1930, "payout_in_flight", "throw", "claim_returned, sweep_returned, withdraw_revenue, recover_surplus",
     ["payouts::a_double_claim_returned_in_one_block_is_refused_with_1930", "capacity::surplus_payouts_in_flight_are_capped",
      "ported::withdraw_revenue_is_capped_by_balance_and_never_takes_locked_fees"], None),
    (1931, "returned_not_found", "throw", "claim_returned, sweep_returned",
     ["payouts::a_returned_entry_is_swept_to_its_caller_after_its_deadline"], None),
    (1932, "asset_route_invalid", "reason", "admission",
     ["funding::a_route_naming_no_bridge_parameter_is_refused_and_returned"], None),
    (1933, "asset_not_recognized", "reason", "admission",
     ["funding::an_absent_or_malformed_configparam_84_takes_the_refusal_path"], None),
    (1934, "invalid_destination", "reason at admission; throw elsewhere",
     "admission (from off workchain 0), claim_refund, claim_returned, withdraw_revenue, recover_surplus",
     ["funding::a_sender_off_workchain_0_is_refused_and_its_tokens_are_logged_surplus",
      "payouts::claim_destinations_are_validated"], None),
    (1935, "not_accepting_tokens", "reason", "admission",
     ["funding::accepting_tokens_is_false_at_the_global_returned_cap_and_reclassifies_nothing",
      "payouts::returned_entries_stop_admission_at_the_per_caller_cap"], None),
    (1936, "surplus_insufficient", "throw in recover_surplus; SAB1 result", "recover_surplus, take_balance",
     ["surplus::surplus_recovery_pays_only_unattributed_tokens",
      "surplus::an_older_payout_still_in_flight_is_under_counted_never_over_counted"], None),
    (1937, "exposure_cap", "reason; throw in update_policy", "admission, update_policy",
     ["funding::the_exposure_caps_bound_the_token_liability", "ported::update_policy_enforces_every_bound"], None),
    (1938, "abandon_too_early", "throw", "abandon_payout",
     ["surplus::abandon_checks_every_counter_and_respects_a_young_query"], None),
    (1939, "malformed_payload", "reason", "admission",
     ["funding::a_malformed_payload_takes_the_refusal_path_without_a_throw"], None),
    (1940, "payout_not_found", "throw", "recheck_payout, abandon_payout",
     ["surplus::recheck_refuses_owner_kinds_early_and_absent_payouts"], None),
    (1941, "recheck_not_allowed", "throw", "recheck_payout, abandon_payout",
     ["surplus::recheck_refuses_owner_kinds_early_and_absent_payouts",
      "surplus::abandon_checks_every_counter_and_respects_a_young_query"], None),
    (1942, "recheck_too_early", "throw", "recheck_payout",
     ["surplus::recheck_refuses_owner_kinds_early_and_absent_payouts"], None),
    (1943, "balance_query_busy", "throw", "recheck_payout, recover_surplus, abandon_payout",
     ["surplus::the_supersede_rule_holds_for_every_pair_of_query_ops"], None),
    (1944, "attestor_keys_full", "reason at admission; throw in rotate_attestor_key",
     "admission, rotate_attestor_key",
     ["capacity::attestor_rotation_is_refused_while_four_keys_are_named_and_allowed_after_they_resolve"], None),
]


def build_corpus(v):
    decoder = []
    for kind, name, base, cls, rule, statement, cell in decoder_cases(v):
        decoder.append({"name": name, "object": kind, "base": base, "class": cls, "rule": rule,
                        "statement": statement, "boc_base64": to_boc(cell)})
    positives, negatives = payload_cases()
    refusal = []
    for code, name, path, raised_by, tests, note in REFUSAL_CODES:
        entry = {"code": code, "name": name, "path": path, "raised_by": raised_by, "tests": tests}
        if note:
            entry["not_executed"] = note
        refusal.append(entry)
    return {
        "schema": "tos.service.actor.token.v1.negative",
        "specification": "docs/SERVICE_ACTOR_TOKEN_TVM_V1.md section 16.3",
        "positive_vectors": "test-vectors/service-actor-token-conformance-vectors.json",
        "generator": "scripts/reproduce-service-actor-token-v1.py --write",
        "derivation": ("BOCs are single stated edits of implementation-generated positive vectors or of "
                       "the T3 sandbox test inputs, derived by the generator; no contract or Rust code runs "
                       "in this repository"),
        "t3_tests": {"repository": "github.com/tosnetwork/tos",
                     "sha": "12cf5522801a30806eeb7cda9ee85fbd051ecbca",
                     "directory": "tosctl/src/node-control/contracts/tests/service_actor_token"},
        "decoder_negatives": decoder,
        "payload_positives": [{"name": n, "statement": s, "boc_base64": to_boc(c)} for n, s, c in positives],
        "payload_negatives": [{"name": n, "rule": s, "expected_reason": 1939, "boc_base64": to_boc(c)}
                              for n, s, c in negatives],
        "refusal_codes": refusal,
    }


def base_cell(v, base):
    if base == "terms_cell":
        return from_boc(v["terms_cell_boc_base64"])
    if base.startswith("sao1."):
        return from_boc(v["sao1"][base[5:]][0])
    return from_boc(v[base][0])


def check_corpus(v, corpus):
    names = set()
    for case in corpus["decoder_negatives"]:
        require(case["name"] not in names, "duplicate case " + case["name"])
        names.add(case["name"])
        decoder = DECODERS[case["object"]]
        decoder(base_cell(v, case["base"]))
        cell = from_boc(case["boc_base64"])
        try:
            decoder(cell)
        except Refused as refusal:
            if refusal.rule != case["rule"]:
                raise SystemExit(f"{case['name']}: refused by {refusal.rule}, expected {case['rule']}")
        else:
            raise SystemExit(f"negative accepted: {case['name']}")
        if case["class"] == "resolver":
            # A resolver-only rule: the decoder without the resolver checks accepts it.
            {"saf1": decode_saf1, "sab1": decode_sab1}[case["object"]](cell, resolver=False)
    for case in corpus["payload_positives"]:
        token_call_payload(from_boc(case["boc_base64"]))
    for case in corpus["payload_negatives"]:
        try:
            token_call_payload(from_boc(case["boc_base64"]))
        except Refused:
            continue
        raise SystemExit(f"payload accepted: {case['name']}")
    codes = [entry["code"] for entry in corpus["refusal_codes"]]
    require(codes == sorted(set(codes)), "refusal codes sorted and unique")
    require(set(range(1900, 1945)) <= set(codes) and {9, 62, 63} <= set(codes), "every code is listed")
    for entry in corpus["refusal_codes"]:
        require(bool(entry["tests"]) or "not_executed" in entry, f"code {entry['code']} has no evidence")


def main():
    vectors = json.loads(VECTORS.read_text())
    check_vectors(vectors)
    corpus = build_corpus(vectors)
    text = json.dumps(corpus, indent=2) + "\n"
    if sys.argv[1:] == ["--write"]:
        CORPUS.write_text(text)
    elif sys.argv[1:]:
        raise SystemExit("usage: reproduce-service-actor-token-v1.py [--write]")
    committed = CORPUS.read_text()
    if committed != text:
        raise SystemExit(f"{CORPUS.relative_to(ROOT)} differs from what the generator emits")
    check_corpus(vectors, json.loads(committed))
    print(f"service-actor-token vectors reproduced; {len(corpus['decoder_negatives'])} decoder, "
          f"{len(corpus['payload_negatives'])} payload negatives refused; "
          f"{len(corpus['refusal_codes'])} refusal codes listed")


if __name__ == "__main__":
    try:
        main()
    except Refused as refusal:
        raise SystemExit(f"refused: {refusal.rule}")
