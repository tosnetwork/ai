"""The automated confirmation policy of the agent-operated pilot.

No human confirms payments in this pilot (STATUS 13.569). The harness
drives the real `tos-service-buyer confirm --watch` on a pty that the
custody account owns. This module decides, from the confirmer's screen alone,
whether to type the confirmation code or to decline.

It types the code only when every check holds:

- the protocol fields (Capability, version, provider Agent, actor, attestor,
  manifest digest) equal the frozen profile;
- the price, storage fee, allowance and total attached equal the frozen
  terms, as nanoTOS;
- the response SLA and the refund window equal the frozen terms;
- the buyer wallet is the buyer's own;
- the source members are exactly the job the harness placed;
- the request_hash is one that a tos_buyer_prepare result of the model's
  transcript returned;
- fewer than the allowed number of purchases were confirmed before.

Only the part of the screen after the protocol heading is read. The
provider-supplied block above it is untrusted text, so a line in it that
imitates a protocol field cannot change the decision. The heading must
appear exactly once, after the provider block.

The renderer is protocol/pkg/buyerconfirm/render.go; the labels below are
copied from it, and test_confirm_policy.py holds the layout to it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

PROVIDER_HEADING = "---- Provider-supplied text: written by the provider, not by TOS or the buyer agent ----"
PROVIDER_END = "---- end of provider-supplied text ----"
PROTOCOL_HEADING = "==== TOS protocol fields, from the buyer agent's verified records ===="
SENSITIVE_MARKER = "!! SENSITIVE"
WAITING = re.compile(r"Purchase (\S+) is waiting for your decision\.")
PROMPT = 'Type the confirmation code to pay, "decline" to decline, or press Enter to skip: '

_FIELD = re.compile(r"^(Capability|Provider Agent|Actor \(payee\)|Attestor key|Manifest digest|Price|Storage fee|"
                    r"Allowance|Total attached|Network|Buyer wallet|request_hash|terms_hash|quote_commitment|"
                    r"Purchase reference|Confirmation code):\s+(.*)$")
_NANO = re.compile(r"\((\d+) nanoTOS\)")
_TERMS = re.compile(r"^Response SLA (.+), refund window (.+), result retention (.+)\.$")
_MEMBER = re.compile(r"^  (  |!! SENSITIVE) (\[dir\] )?(\S+)(?: \((\d+) bytes\))?$")
_CODE = re.compile(r"^(\S+) \(valid until .+\)$")


def duration(seconds: int) -> str:
    """The renderer's duration text (render.go duration)."""
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    return f"{hours}h {minutes}m"


@dataclass
class Expected:
    capability_id: str
    capability_version: str
    provider_agent_id: str
    actor: str
    attestor_key_id: str
    manifest_digest: str
    price_nanotos: str
    storage_fee_nanotos: str
    allowance_nanotos: str
    response_sla_seconds: int
    refund_claim_window_seconds: int
    buyer_wallet: str
    members: list[str]
    max_confirmations: int
    # Other spellings of the buyer's own wallet (raw and user-friendly).
    buyer_wallet_aliases: tuple = ()


@dataclass
class Decision:
    confirm: bool
    code: str | None
    request_hash: str | None
    checks: list[dict] = field(default_factory=list)

    def public(self) -> dict:
        """The decision without the confirmation code."""
        return {"confirm": self.confirm, "request_hash": self.request_hash,
                "code_length": len(self.code) if self.code else 0, "checks": self.checks}


def presentation(screen: str) -> str | None:
    """The last complete presentation on the screen: from its "is waiting"
    line to the decision prompt, or None while none is complete."""
    text = screen.replace("\r\n", "\n").replace("\r", "\n")
    end = text.rfind(PROMPT)
    if end < 0:
        return None
    starts = [m.start() for m in WAITING.finditer(text, 0, end)]
    if not starts:
        return None
    return text[starts[-1]:end]


def parse(block: str) -> dict:
    """The protocol fields of one presentation. Raises ValueError when the
    layout is not the renderer's."""
    lines = block.split("\n")
    if lines.count(PROTOCOL_HEADING) != 1 or lines.count(PROVIDER_HEADING) != 1 or lines.count(PROVIDER_END) != 1:
        raise ValueError("the presentation does not have exactly one provider block and one protocol heading")
    if not lines.index(PROVIDER_HEADING) < lines.index(PROVIDER_END) < lines.index(PROTOCOL_HEADING):
        raise ValueError("the protocol heading does not follow the provider block")
    fields: dict = {"members": []}
    in_members = False
    for line in lines[lines.index(PROTOCOL_HEADING) + 1:]:
        if line == "The whole archive goes to the provider:":
            in_members = True
            continue
        if in_members:
            if line == "" or line.startswith(SENSITIVE_MARKER + ":"):
                in_members = False
                continue
            member = _MEMBER.match(line)
            if not member:
                raise ValueError("a source member line does not have the renderer's layout")
            fields["members"].append({"name": member.group(3), "directory": bool(member.group(2)),
                                      "sensitive": member.group(1) == SENSITIVE_MARKER})
            continue
        terms = _TERMS.match(line)
        if terms:
            fields["sla"], fields["refund_window"], fields["retention"] = terms.groups()
            continue
        found = _FIELD.match(line)
        if found:
            label, value = found.groups()
            if label in fields:
                raise ValueError(f"the field {label} appears twice")
            fields[label] = value
    return fields


def _nano(value: str | None) -> str | None:
    if value is None:
        return None
    found = _NANO.search(value)
    return found.group(1) if found else None


def decide(screen: str, expected: Expected, prepared_hashes: set[str], confirmed_before: int) -> Decision:
    """Decide one presentation. A screen that cannot be read declines."""
    block = presentation(screen)
    if block is None:
        return Decision(False, None, None, [{"id": "presentation", "ok": False, "detail": "no complete presentation"}])
    try:
        fields = parse(block)
    except ValueError as error:
        return Decision(False, None, None, [{"id": "layout", "ok": False, "detail": str(error)}])
    request_hash = fields.get("request_hash")
    capability = fields.get("Capability", "")
    want_members = sorted(expected.members)
    got_members = sorted(m["name"] for m in fields["members"] if not m["directory"])
    total = str(int(expected.price_nanotos) + int(expected.storage_fee_nanotos) + int(expected.allowance_nanotos))
    checks = [
        ("capability", capability == f"{expected.capability_id} version {expected.capability_version}"),
        ("provider-agent", fields.get("Provider Agent") == expected.provider_agent_id),
        ("actor", fields.get("Actor (payee)") == expected.actor),
        ("attestor", fields.get("Attestor key") == expected.attestor_key_id),
        ("manifest", fields.get("Manifest digest") == expected.manifest_digest),
        ("price", _nano(fields.get("Price")) == expected.price_nanotos),
        ("storage-fee", _nano(fields.get("Storage fee")) == expected.storage_fee_nanotos),
        ("allowance", _nano(fields.get("Allowance")) == expected.allowance_nanotos),
        ("total", _nano(fields.get("Total attached")) == total),
        ("response-sla", fields.get("sla") == duration(expected.response_sla_seconds)),
        ("refund-window", fields.get("refund_window") == duration(expected.refund_claim_window_seconds)),
        ("buyer-wallet", (fields.get("Buyer wallet") or "").split(" ")[0] in
         {expected.buyer_wallet, *expected.buyer_wallet_aliases}),
        ("members", got_members == want_members and not any(m["sensitive"] for m in fields["members"])),
        ("prepared-by-model", request_hash in prepared_hashes),
        ("reference", bool(request_hash) and fields.get("Purchase reference", "").replace("-", "").replace(" ", "")
         == request_hash[:16]),
        ("count", confirmed_before < expected.max_confirmations),
    ]
    code_match = _CODE.match(fields.get("Confirmation code", ""))
    checks.append(("code-shown", code_match is not None))
    results = [{"id": name, "ok": bool(ok)} for name, ok in checks]
    confirm = all(r["ok"] for r in results)
    return Decision(confirm, code_match.group(1) if (confirm and code_match) else None, request_hash, results)
