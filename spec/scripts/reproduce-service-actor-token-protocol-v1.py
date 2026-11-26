#!/usr/bin/env python3
"""Independently reproduce the token protocol's manifest, quote and receipt.

The frozen inputs are encoded by stdlib-only CBOR and cell implementations,
without importing the Go implementation or invoking a contract tool.
"""

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


cells = module("token_cells", "reproduce-service-actor-token-v1.py")
cbor = module("manifest_cbor", "reproduce-software-work-manifest-v1-service-actor.py")


def require(condition, rule):
    if not condition:
        raise ValueError(rule)


def digest(text, prefix):
    require(isinstance(text, str) and text.startswith(prefix), "digest prefix")
    raw = bytes.fromhex(text[len(prefix) :])
    require(len(raw) == 32 and raw != bytes(32), "digest width or zero")
    require(text == prefix + raw.hex(), "digest canonical form")
    return raw


def binary(text):
    raw = base64.b64decode(text, validate=True)
    require(len(raw) == 32 and raw != bytes(32), "account/hash width or zero")
    require(base64.b64encode(raw).decode() == text, "Base64 canonical form")
    return raw


def number(text):
    require(isinstance(text, str) and text.isdecimal(), "amount syntax")
    value = int(text)
    require(str(value) == text and 0 < value < 1 << 120, "amount range/canonical form")
    return value


def h256(builder, raw):
    return builder.uint(int.from_bytes(raw, "big"), 256)


def raw_string(text):
    raw = text.encode("utf-8")
    require(1 <= len(raw) <= 128, "capability version length")
    chunks = [raw[pos : pos + 127] for pos in range(0, len(raw), 127)]
    result = None
    for chunk in reversed(chunks):
        result = cells.Cell(
            "".join(f"{value:08b}" for value in chunk),
            () if result is None else (result,),
        )
    return result


def manifest_model(projection):
    # Reuse the common field validator with a native-rail surrogate, then
    # independently impose the additional token identity and canonical map.
    surrogate = copy.deepcopy(projection)
    surrogate["supported_assets"] = [{"kind": "native-tos"}]
    surrogate["settlement"]["rail"] = "tos.service.service-actor.v1"
    model = cbor.model_from_projection(surrogate)
    cbor.validate(model)
    assets = projection["supported_assets"]
    require(len(assets) == 1, "one token asset")
    asset = assets[0]
    cbor.exact(
        asset,
        ["kind", "master_account_id", "wallet_code_hash", "decimals"],
        "token asset",
    )
    require(
        asset["kind"] == "tos-token"
        and type(asset["decimals"]) is int
        and 0 <= asset["decimals"] <= 18,
        "token asset kind/decimals",
    )
    model[20] = [
        {
            0: "tos-token",
            1: binary(asset["master_account_id"]),
            2: binary(asset["wallet_code_hash"]),
            3: asset["decimals"],
        }
    ]
    require(
        projection["settlement"]["rail"] == "tos.service.service-actor-token.v1",
        "token rail",
    )
    model[21][1] = projection["settlement"]["rail"]
    return model


def quote_cell(v):
    p, network = v["proposal"], v["network"]
    b = cells.Builder
    domain = h256(
        h256(
            h256(b(), digest(network["genesis_root_hash"], "sha256:")),
            digest(network["genesis_file_hash"], "sha256:"),
        ),
        hashlib.sha256(network["network_id"].encode()).digest(),
    ).cell()
    version = (
        h256(
            h256(
                h256(b(), hashlib.sha256(p["capability_version"].encode()).digest()),
                digest(p["manifest_digest"], "sha256:"),
            ),
            digest(p["transport_binding_digest"], "sha256:"),
        )
        .uint(p["expires_at_unix_seconds"], 64)
        .ref(raw_string(p["capability_version"]))
        .cell()
    )
    identity = (
        h256(
            h256(b(), digest(p["capability_id"], "cap_")),
            digest(p["provider_agent_id"], "agent_"),
        )
        .ref(version)
        .cell()
    )
    terms = (
        h256(b(), digest(p["terms_hash"], ""))
        .coins(number(p["price_atomic"]))
        .coins(number(p["storage_fee_nanotos"]))
        .cell()
    )
    asset = p["asset"]
    require(
        asset["master"].get("workchain", 0) == 0
        and p["actor"].get("workchain", 0) == 0,
        "basechain identity",
    )
    master = binary(asset["master"]["account_id"])
    wallet_hash = digest(asset["wallet_code_hash"], "tvm-cell-sha256:")
    asset_cell = (
        h256(
            h256(
                b().std(int.from_bytes(master, "big")),
                digest(asset["master"]["code_hash"], "tvm-cell-sha256:"),
            ),
            wallet_hash,
        )
        .uint(asset["decimals"], 8)
        .cell()
    )
    rail = (
        h256(
            b().std(int.from_bytes(binary(p["actor"]["account_id"]), "big")),
            digest(p["actor_code_hash"], "tvm-cell-sha256:"),
        )
        .uint(p.get("policy_version", 0), 32)
        .ref(terms)
        .ref(asset_cell)
        .cell()
    )
    authority = h256(b(), digest(p["attestor_key_id"], "mldsa44:")).cell()
    return (
        b()
        .uint(0x4E415131, 32)
        .uint(3, 16)
        .ref(domain)
        .ref(identity)
        .ref(rail)
        .ref(authority)
        .cell()
    )


def receipt_cell(v):
    r = v["receipt"]
    b = cells.Builder

    def hashes(fields, prefixes):
        result = b()
        for field, prefix in zip(fields, prefixes):
            h256(result, digest(r[field], prefix))
        return result.cell()

    binding = hashes(
        ["QuoteCommitment", "ExecutionID", "InputDigest"],
        ["tvm-cell-sha256:", "sha256:", "sha256:"],
    )
    outcome = hashes(
        ["ResultDigest", "ArtifactDigest", "ReportDigest"], ["sha256:"] * 3
    )
    evidence = hashes(
        ["SourceDigest", "ToolchainDigest", "SandboxDigest"], ["sha256:"] * 3
    )
    require(r["ExitCode"] == 0 and r["CompletedAt"] > 0, "receipt success/time")
    master = bytes(r["AssetMaster"])
    require(
        master == binary(v["proposal"]["asset"]["master"]["account_id"]),
        "receipt asset binding",
    )
    require(
        r["ChargedAtomicAmount"] == v["proposal"]["price_atomic"],
        "receipt amount binding",
    )
    require(
        r["ProviderAgentID"] == v["proposal"]["provider_agent_id"],
        "receipt provider binding",
    )
    economic = h256(
        h256(b().uint(number(r["ChargedAtomicAmount"]), 128), master),
        digest(r["ProviderAgentID"], "agent_"),
    ).cell()
    return (
        b()
        .uint(0x4E575231, 32)
        .uint(2, 16)
        .uint(r["CompletedAt"], 64)
        .uint(r["ExitCode"], 32)
        .ref(binding)
        .ref(outcome)
        .ref(evidence)
        .ref(economic)
        .cell()
    )


def check_cell(cell, expected_boc, expected_hash, name):
    require(cell.hash() == digest(expected_hash, "tvm-cell-sha256:"), name + " hash")
    require(cells.from_boc(expected_boc).hash() == cell.hash(), name + " frozen BOC")

    # Cell order in a BOC is not part of its commitment. Compare the full
    # independently rebuilt cell graph, without assuming one serializer order.
    def same(left, right):
        return (
            left.bits == right.bits
            and len(left.refs) == len(right.refs)
            and all(same(a, b) for a, b in zip(left.refs, right.refs))
        )

    require(same(cell, cells.from_boc(expected_boc)), name + " BOC cell graph")


def main():
    path = ROOT / "test-vectors/service-actor-token-protocol-v1.json"
    v = json.loads(path.read_text())
    require(v["schema"] == "tos.service.token-rail.protocol.v1.vectors", "schema")
    source = ROOT / "test-vectors/service-actor-token-conformance-vectors.json"
    require(
        hashlib.sha256(source.read_bytes()).hexdigest()
        == v["sources"]["contract_vectors_sha256"],
        "contract vectors pin",
    )
    encoded = cbor.encode(manifest_model(v["manifest"]))
    require(
        encoded
        == base64.b64decode(v["expected"]["manifest_cbor_base64"], validate=True),
        "manifest CBOR",
    )
    manifest_digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    require(
        manifest_digest
        == v["expected"]["manifest_digest"]
        == v["proposal"]["manifest_digest"],
        "manifest digest",
    )
    asset = v["manifest"]["supported_assets"][0]
    proposal = v["proposal"]
    require(
        binary(asset["master_account_id"])
        == binary(proposal["asset"]["master"]["account_id"]),
        "manifest master binding",
    )
    require(
        binary(asset["wallet_code_hash"])
        == digest(proposal["asset"]["wallet_code_hash"], "tvm-cell-sha256:"),
        "manifest wallet-code binding",
    )
    require(
        asset["decimals"] == proposal["asset"]["decimals"], "manifest decimal binding"
    )
    settlement = v["manifest"]["settlement"]
    require(
        binary(settlement["actor_account_id"])
        == binary(proposal["actor"]["account_id"]),
        "manifest actor binding",
    )
    require(
        binary(settlement["actor_code_hash"])
        == digest(proposal["actor_code_hash"], "tvm-cell-sha256:"),
        "manifest actor-code binding",
    )
    require(
        settlement["attestor_key"] == proposal["attestor_key_id"],
        "manifest attestor binding",
    )
    quote = quote_cell(v)
    check_cell(
        quote, v["expected"]["quote_boc_base64"], v["expected"]["quote_hash"], "quote"
    )
    require(
        v["receipt"]["QuoteCommitment"] == v["expected"]["quote_hash"],
        "receipt quote binding",
    )
    receipt = receipt_cell(v)
    check_cell(
        receipt,
        v["expected"]["receipt_boc_base64"],
        v["expected"]["receipt_hash"],
        "receipt",
    )
    print(
        "token protocol: independent manifest CBOR, schema-3 quote and schema-2 receipt reproduced"
    )


if __name__ == "__main__":
    main()
