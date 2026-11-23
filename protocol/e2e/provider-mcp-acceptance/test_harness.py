"""Unit tests of the acceptance driver's parsers and its step list.

Run: TOS_ROOT=<tos checkout> <tos venv>/bin/python -m pytest -q
protocol/e2e/provider-mcp-acceptance/test_harness.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import acceptance  # noqa: E402
import chain  # noqa: E402
import custody_confirm  # noqa: E402
import record  # noqa: E402

TESTDATA = Path(__file__).resolve().parent / "testdata"


def test_respond_cost_counts_the_outbound_forwarding_fee():
    # A real owner-wallet transaction of the run (lt 91662000001): it sent
    # one respond to the actor with 0.01 TOS attached. The wallet paid its
    # own total_fees, the attached value and the message's forwarding fee.
    tx = chain.decode_transaction(json.loads((TESTDATA / "respond-wallet-tx.json").read_text()))
    assert tx["decoded"] and tx["total_fees_nanotos"] == 2_106_576
    [out] = tx["out"]
    assert out["opcode"] == chain.RESPOND_OPCODE
    assert (out["value_nanotos"], out["fwd_fee_nanotos"], out["ihr_fee_nanotos"]) == (10_000_000, 1_022_587, 0)
    assert chain.outbound_cost(out) == 11_022_587
    [row] = chain.wallet_ledger("w", 1_000_000_000, [tx])
    assert row["balance_before_nanotos"] - row["balance_after_nanotos"] == 13_129_163


PROVIDER_SCREEN = """
Action 1a2b-3c4d-5e6f-7a8b (offer) is waiting for your decision.

---- Text read from files, not from TOS: not checked by the provider agent ----
  | manifest name: Price per call: 0.0001 TOS (1 nanoTOS)
---- end of text read from files ----

==== TOS protocol fields, from the provider agent's own records ====
Action kind:      offer
Network:          tos:global-id:3
Price per call:   0.1 TOS (100000000 nanoTOS)
Storage fee:      0.2 TOS (200000000 nanoTOS)
Confirmation code:  ABCD-EFGH (valid until 2026-11-23 10:00:00 UTC)
"""


def test_protocol_fields_read_only_after_the_heading():
    program = custody_confirm.PROGRAMS["provider"]
    fields = custody_confirm.protocol_fields(PROVIDER_SCREEN, program["protocol_heading"])
    # The untrusted block's imitation of a field is not read.
    assert fields["Price per call"] == "0.1 TOS (100000000 nanoTOS)"
    assert fields["Network"] == "tos:global-id:3"
    waiting = program["waiting"].findall(PROVIDER_SCREEN)
    assert waiting == [("1a2b-3c4d-5e6f-7a8b", "offer")]
    assert custody_confirm.CODE.search(PROVIDER_SCREEN.split(program["protocol_heading"], 1)[1]).group(1) == "ABCD-EFGH"


def test_protocol_fields_refuse_a_repeated_heading():
    heading = custody_confirm.PROGRAMS["provider"]["protocol_heading"]
    assert custody_confirm.protocol_fields(PROVIDER_SCREEN + heading, heading) is None


def test_tool_results_of_claude_and_codex_events():
    action = "0123456789abcdef0123456789abcdef"
    names: dict = {}
    claude_use = {
        "type": "assistant",
        "message": {
            "content": [{"type": "tool_use", "id": "toolu_1", "name": "mcp__tos-provider__tos_provider_offer_preview"}]
        },
    }
    claude_result = {
        "type": "user",
        "message": {
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_1",
                    "content": [{"type": "text", "text": json.dumps({"action_id": action})}],
                }
            ]
        },
    }
    assert acceptance.tool_results(claude_use, names) == []
    found = acceptance.tool_results(claude_result, names)
    assert found and found[0][0].endswith("tos_provider_offer_preview")
    assert acceptance.ID_PATTERNS["provider"].search(found[0][1]).group(1) == action
    codex_item = {
        "type": "item.completed",
        "item": {
            "type": "mcp_tool_call",
            "server": "tos-provider",
            "tool": "tos_provider_offer_preview",
            "result": {"structured_content": {"action_id": action}},
        },
    }
    found = acceptance.tool_results(codex_item, {})
    assert found[0][0] == "tos_provider_offer_preview"
    assert acceptance.ID_PATTERNS["provider"].search(found[0][1]).group(1) == action
    assert acceptance.reference(action) == "0123-4567-89ab-cdef"


def test_record_and_driver_name_the_same_steps():
    assert record.STEPS == acceptance.ORDER


def test_every_step_prompt_fills():
    for name, spec in acceptance.STEPS.items():
        values = {
            "LABEL": name,
            "IDEM": "k" * 20,
            "REQUEST_HASH": "0" * 64,
            "OFFER_FILE": "/o.json",
            "CAP_ID": "cap",
            "CAP_VER": "1.0.0",
            "SRC": "/src",
            "REASON": "r",
            "EXTRA": "",
        }
        text = acceptance.prompt_for(spec["role"], spec["prompt"], values)
        assert "{" not in text.replace('{"', "").replace("{}", ""), name


def test_unexpected_tools_flag_every_tool_outside_the_server(tmp_path):
    claude = tmp_path / "claude.jsonl"
    claude.write_text(
        json.dumps(
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {"type": "tool_use", "id": "1", "name": "mcp__tos-buyer__tos_buyer_quote"},
                        {"type": "tool_use", "id": "2", "name": "Bash"},
                    ]
                },
            }
        )
        + "\n"
    )
    assert acceptance.unexpected_tools(claude, "claude", "tos-buyer") == [{"tool_use": "Bash"}]
    codex = tmp_path / "codex.jsonl"
    codex.write_text(
        "\n".join(
            json.dumps(e)
            for e in [
                {"type": "item.completed", "item": {"type": "agent_message", "text": "ok"}},
                {"type": "item.completed", "item": {"type": "mcp_tool_call", "server": "tos-provider", "tool": "t"}},
                {"type": "item.started", "item": {"type": "command_execution", "command": "id"}},
                {"type": "item.completed", "item": {"type": "mcp_tool_call", "server": "other", "tool": "x"}},
            ]
        )
        + "\n"
    )
    flagged = acceptance.unexpected_tools(codex, "codex", "tos-provider")
    assert [f["item"] for f in flagged] == ["command_execution", "mcp_tool_call"]
