"""Strict-majority chain reads of the local agent-operated provider run.

Every provider-side fact of the record (respond and withdrawal
transactions, credited revenue, respond fees, wallet balances) and every
validator-set observation is read here, from the validators' own loopback
JSON-RPC, and taken only when a strict majority of the endpoints return the
same value. Nothing is read from the provider's or the buyer's own reports.

The transaction and Config34 decoders are the tos checkout's (pytosiq_core
and scripts/x02_config34_proof.py), imported from TOS_ROOT.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

TOS_ROOT = Path(os.environ.get("TOS_ROOT", ""))
if not (TOS_ROOT / "test" / "tostester" / "src").is_dir():
    raise SystemExit("TOS_ROOT must name the tos checkout the local network was built from")
sys.path.insert(0, str(TOS_ROOT / "test" / "tostester" / "src"))
sys.path.insert(0, str(TOS_ROOT / "scripts"))

# The local network's full nodes that are validator candidates: nodes 1, 2,
# 3, 4 and 7 (JSON-RPC 8010 + index). Four of them form each validator set;
# the fifth stays online as a full node. Observers 5 and 6 are not used.
CANDIDATES = (1, 2, 3, 4, 7)
RPC_PORTS = {index: 8010 + index for index in CANDIDATES}
NODE_CONFIG = Path("/data/configs")
MASTERCHAIN_SHARD = "-9223372036854775808"

# Service Actor inbound opcodes (protocol/pkg/nativecore/service_actor.go).
CALL_OPCODE = 0x53564301
RESPOND_OPCODE = 0x53564302
EXPIRE_OPCODE = 0x53564303
CLAIM_REFUND_OPCODE = 0x53564304
WITHDRAW_OPCODE = 0x53564309


def endpoints() -> list[str]:
    """The endpoints both agents read through, as --rpc spells them."""
    return [f"http://127.0.0.1:{port}/jsonRPC" for port in RPC_PORTS.values()]


def tosctl_urls() -> list[str]:
    """The same endpoints as a tosctl chain_rpc names them (base URL)."""
    return [f"http://127.0.0.1:{port}" for port in RPC_PORTS.values()]


def rpc_at(port: int, method: str, /, **params) -> dict:
    # Positional-only: runGetMethod's own parameters include one named "method".
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/jsonRPC", data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        answer = json.loads(response.read())
    if "result" not in answer:
        raise RuntimeError(f"{method} at {port}: {str(answer.get('error'))[:200]}")
    return answer["result"]


def majority(method: str, view, /, timeout: float = 120, interval: float = 3, **params):
    """view(result) as a strict majority of the candidate endpoints return it,
    polled until they agree: {"value", "agreeing", "of", "ports"}, or None."""
    deadline = time.monotonic() + timeout
    while True:
        tally: dict = {}
        for port in RPC_PORTS.values():
            try:
                value = view(rpc_at(port, method, **params))
            except Exception:  # noqa: BLE001 - an endpoint that cannot answer does not vote
                continue
            entry = tally.setdefault(json.dumps(value, sort_keys=True), [value, []])
            entry[1].append(port)
        for value, ports in tally.values():
            if len(ports) * 2 > len(RPC_PORTS):
                return {"value": value, "agreeing": len(ports), "of": len(RPC_PORTS), "ports": sorted(ports)}
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval)


def masterchain_seqno() -> int | None:
    """A masterchain height every answering endpoint has reached (the lowest
    head of a strict majority of them), so a read pinned to it can agree."""
    seen = [h for h in heads().values() if isinstance(h, int)]
    if len(seen) * 2 <= len(RPC_PORTS):
        return None
    return sorted(seen, reverse=True)[len(RPC_PORTS) // 2]


def heads() -> dict:
    """Every candidate's masterchain head, for the record (no majority)."""
    out = {}
    for index, port in RPC_PORTS.items():
        try:
            out[str(index)] = int(rpc_at(port, "getMasterchainInfo")["last"]["seqno"])
        except Exception as error:  # noqa: BLE001 - recorded
            out[str(index)] = f"unreachable: {type(error).__name__}"
    return out


# --- Accounts -------------------------------------------------------------------


def balance(address: str):
    read = majority("getAddressInformation", lambda r: int(r["balance"]), address=address)
    return read["value"] if read else None


def account_state(address: str):
    read = majority(
        "getAddressInformation",
        lambda r: {"balance": int(r["balance"]), "active": bool(r.get("code"))},
        address=address,
    )
    return read["value"] if read else None


def _opcode(message) -> int | None:
    body = message.body.begin_parse()
    return body.load_uint(32) if body.remaining_bits >= 32 else None


def _raw(address) -> str | None:
    return address.to_str(is_user_friendly=False).lower() if address is not None else None


def decode_transaction(transaction: dict) -> dict:
    """One transaction's facts, decoded from the BOC the endpoint returned."""
    from pytosiq_core import Cell, InternalMsgInfo, Transaction

    ident = transaction.get("transaction_id") or {}
    facts = {
        "hash": ident.get("hash", ""),
        "lt": int(ident.get("lt") or 0),
        "utime": int(transaction.get("utime") or 0),
        "fee_nanotos": int(transaction.get("fee") or 0),
        "decoded": False,
    }
    try:
        decoded = Transaction.deserialize(Cell.one_from_boc(base64.b64decode(transaction["data"])).begin_parse())
    except Exception as error:  # noqa: BLE001 - recorded; a check that needs the decode fails on it
        facts["error"] = repr(error)
        return facts
    facts.update(
        {
            "decoded": True,
            "lt": decoded.lt,
            "aborted": bool(getattr(decoded.description, "aborted", True)),
            "total_fees_nanotos": decoded.total_fees.tomis,
            "in": None,
            "out": [],
        }
    )
    message = decoded.in_msg
    if message is not None:
        inbound = {"opcode": _opcode(message), "internal": isinstance(message.info, InternalMsgInfo)}
        if inbound["internal"]:
            inbound.update({"source": _raw(message.info.src), "value_nanotos": message.info.value_coins})
        facts["in"] = inbound
    for out in decoded.out_msgs:
        if isinstance(out.info, InternalMsgInfo):
            facts["out"].append(
                {"to": _raw(out.info.dest), "value_nanotos": out.info.value_coins, "opcode": _opcode(out)}
            )
    return facts


def transactions(address: str, limit: int = 100):
    """An account's latest transactions, decoded, as a strict majority returns
    them: {"value": [...], "agreeing", "of", "ports"}, or None."""
    return majority(
        "getTransactions", lambda r: [decode_transaction(tx) for tx in r], address=address, limit=limit, lt="", hash=""
    )


def inbound(txs: list, opcode: int, source: str | None = None) -> list:
    return [
        tx
        for tx in txs
        if tx.get("decoded")
        and (tx.get("in") or {}).get("opcode") == opcode
        and (source is None or (tx.get("in") or {}).get("source") == source)
    ]


def paid_to(tx: dict, address: str) -> int:
    return sum(out["value_nanotos"] for out in tx.get("out", []) if out["to"] == address)


def wallet_ledger(wallet: str, current_balance: int, txs: list) -> list:
    """Each wallet transaction with the wallet's balance before and after it,
    reconstructed backwards from the finalized current balance: after - before
    = inbound value - outbound values - total fees. The newest transaction
    first, as the endpoint lists them."""
    rows, after = [], current_balance
    for tx in txs:
        if not tx.get("decoded"):
            break
        received = (tx.get("in") or {}).get("value_nanotos") or 0
        sent = sum(out["value_nanotos"] for out in tx["out"])
        before = after - received + sent + tx["total_fees_nanotos"]
        rows.append({**tx, "balance_before_nanotos": before, "balance_after_nanotos": after})
        after = before
    return rows


def respond_fees(wallet: str, actor: str) -> dict:
    """Every respond the owner wallet sent the actor, with its cost to the
    wallet: the wallet transaction's fees and attached value, less what the
    actor sent back to the wallet from that respond's transaction, plus the
    fees of the wallet transaction that received it."""
    wallet_read, actor_read = transactions(wallet), transactions(actor)
    current = balance(wallet)
    if wallet_read is None or actor_read is None or current is None:
        return {"read": False}
    ledger = wallet_ledger(wallet, current, wallet_read["value"])
    actor_txs = actor_read["value"]
    responds = []
    for row in ledger:
        attached = [out for out in row.get("out", []) if out["to"] == actor and out["opcode"] == RESPOND_OPCODE]
        if not attached:
            continue
        # The actor's transaction that took this respond: the first respond
        # from the wallet after the wallet's send, carrying the attached value.
        taken = sorted(
            (
                tx
                for tx in inbound(actor_txs, RESPOND_OPCODE, wallet)
                if tx["lt"] > row["lt"] and tx["in"]["value_nanotos"] == attached[0]["value_nanotos"]
            ),
            key=lambda tx: tx["lt"],
        )
        actor_tx = taken[0] if taken else None
        returned = paid_to(actor_tx, wallet) if actor_tx else 0
        credit = None
        if actor_tx and returned:
            credit = next(
                (
                    r
                    for r in sorted(ledger, key=lambda r: r["lt"])
                    if r["lt"] > actor_tx["lt"]
                    and (r.get("in") or {}).get("source") == actor
                    and (r.get("in") or {}).get("value_nanotos") == returned
                ),
                None,
            )
        fee = (
            row["total_fees_nanotos"]
            + attached[0]["value_nanotos"]
            - returned
            + (credit["total_fees_nanotos"] if credit else 0)
        )
        responds.append(
            {
                "wallet_transaction": {"lt": row["lt"], "hash": row["hash"], "utime": row["utime"]},
                "actor_transaction": actor_tx
                and {"lt": actor_tx["lt"], "hash": actor_tx["hash"], "aborted": actor_tx["aborted"]},
                "attached_nanotos": attached[0]["value_nanotos"],
                "returned_nanotos": returned,
                "return_credit_transaction": credit and {"lt": credit["lt"], "hash": credit["hash"]},
                "fee_nanotos": fee,
                "balance_before_nanotos": row["balance_before_nanotos"],
                "balance_after_nanotos": (credit or row)["balance_after_nanotos"],
            }
        )
    return {
        "read": True,
        "agreeing": min(wallet_read["agreeing"], actor_read["agreeing"]),
        "of": wallet_read["of"],
        "wallet_balance_nanotos": current,
        "responds": sorted(responds, key=lambda r: r["wallet_transaction"]["lt"]),
    }


def _stack_int(entry) -> int:
    kind, value = entry[0], entry[1]
    if kind != "num":
        raise ValueError(f"stack entry is {kind}, not num")
    text = str(value)
    return int(text, 16) if text.lower().startswith(("0x", "-0x")) else int(text)


# get_service_data's return values (crypto/smartcont/service-actor-code.fc):
# owner, active, policy_version, price_per_call, storage_fee, cleanup_bounty,
# response_sla, refund_claim_window, open_access, has_authorized_caller,
# authorized_caller, rate_limit_per_day, metadata_hash, proof_scheme_hash,
# has_attestor, attestor_key_id, next_request_id, pending_count, live_count,
# withdrawable_revenue, locked_storage_fees, pending_liability,
# refundable_liability, call_day, calls_today.
SERVICE_DATA = {
    "active": 1,
    "price_per_call": 3,
    "storage_fee": 4,
    "next_request_id": 16,
    "pending_count": 17,
    "live_count": 18,
    "withdrawable_revenue": 19,
    "locked_storage_fees": 20,
    "pending_liability": 21,
    "refundable_liability": 22,
}


def service_data(actor: str):
    """The actor's accounting from its own getter, at a strict majority, all
    pinned to one masterchain height."""
    seqno = masterchain_seqno()
    if seqno is None:
        return None

    def view(result):
        if result.get("exit_code") != 0:
            raise ValueError("get_service_data failed")
        stack = result["stack"]
        if len(stack) != 25:
            raise ValueError("get_service_data returned another shape")
        # The endpoint lists the stack top first: the last return value
        # comes first, so return value i is stack[24 - i].
        return {name: _stack_int(stack[24 - index]) for name, index in SERVICE_DATA.items()}

    read = majority("runGetMethod", view, address=actor, method="get_service_data", stack=[], seqno=seqno)
    return read and {**read, "seqno": seqno}


# --- Validator sets ---------------------------------------------------------------


def candidate_ids() -> dict:
    """controller id hex -> local node index, from the public node configs."""
    out = {}
    for index in CANDIDATES:
        config = json.loads((NODE_CONFIG / f"node-{index}.json").read_text())
        out[base64.b64decode(config["extraconfig"]["pq_consensus"]["validator_id"]).hex()] = index
    return out


def validator_set() -> dict | None:
    """The current Config34 as a strict majority returns its bytes, decoded,
    with each member's local index."""
    from pytosiq_core import Cell
    from x02_config34_proof import decode_validator_set

    seqno = masterchain_seqno()
    if seqno is None:
        return None
    read = majority("getConfigParam", lambda r: r["config"]["bytes"], param=34, seqno=seqno)
    if read is None:
        return None
    cell = Cell.one_from_boc(base64.b64decode(read["value"]))
    decoded = decode_validator_set(cell)
    ids = candidate_ids()
    return {
        "observed_at_seqno": seqno,
        "agreeing": read["agreeing"],
        "of": read["of"],
        "config34_cell_hash": cell.hash.hex(),
        "utime_since": decoded["utime_since"],
        "utime_until": decoded["utime_until"],
        "members": [
            {
                "local_index": ids.get(v["controller_id_hex"]),
                "controller_id_hex": v["controller_id_hex"],
                "consensus_key_id_hex": v["consensus_key_id_hex"],
            }
            for v in decoded["validators"]
        ],
    }


def membership(view: dict) -> list:
    return sorted(m["local_index"] for m in view["members"])
