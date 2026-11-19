"""Tests of make_record.py on a synthetic run directory.

Run from the repository root:

    python3 -I protocol/e2e/mcp-buyer-pilot/test_make_record.py

They cover a passing record (unsigned, then signed by three Ed25519 keys),
a failing verifier verdict, a signature that does not verify (the WRITTEN
record must then fail), a credential left on disk, and the refusal to
write any record that names the Gate D verdict.
"""

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "make_record.py"
FORBIDDEN = "PASS_INDEPENDENT_SERVICE_" + "ACTOR_SOFTWARE_WORK"
WALLET = "0:" + "e1" * 32
PROVIDER_WALLET = "0:" + "58" * 32
ACTOR = "0:" + "a7" * 32
R_HASH, F_HASH = "11" * 32, "22" * 32
WITHDRAW_TX = "77" * 32
TOSCTL_SHA = "73" * 32


def write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value))


def tx(digest: str, **extra) -> dict:
    return {"hash": digest, "lt": 1000, "now": 1795000000, "sender": WALLET, **extra}


def build_run(root: Path) -> None:
    write(root / "bin" / "build.json", {
        "ai_commit": subprocess.run(["git", "-C", str(HERE), "rev-parse", "HEAD"], capture_output=True, text=True,
                                    check=True).stdout.strip(),
        "openfox_commit": "a7" * 20, "tosctl_sha256": TOSCTL_SHA, "claude_version": "2.1.328 (Claude Code)",
        "codex_version": "codex-cli 0.170.0", "binaries": {"claude": "c1" * 32, "codex": "c2" * 32}})
    write(root / "public" / "global-config.json", {"validator": {"zero_state": {"root_hash": "S2A4", "file_hash": "R151"}}})
    write(root / "public" / "release-provenance.json", {"repository": "tosnetwork/tos", "tag": "v2026.11-1",
                                                        "tag_commit": "80" * 20})
    write(root / "public" / "release-SHA256SUMS", f"{TOSCTL_SHA}  tosctl-linux-x86_64\n")
    profile = {
        "network_label": "tos:global-id:2",
        "releases": {"service_actor_code_hash": "tvm-cell-sha256:" + "05" * 32,
                     "native_registry_code_hash": "tvm-cell-sha256:" + "d3" * 32},
        "endpoints": {"validators": [{"name": "V1"}, {"name": "V2"}, {"name": "V3"}]},
        "relays": ["https://relay-1.invalid:8443"],
        "objects": {"capability_id": "cap_" + "be" * 32, "capability_version": "1.0.0", "provider_agent_id": "agent_x",
                    "manifest_digest": "sha256:" + "87" * 32, "actor": ACTOR, "attestor_key_id": "mldsa44:" + "29" * 32,
                    "metadata_hash": "63" * 32, "capability_address": "0:" + "73" * 32, "provider_wallet": PROVIDER_WALLET,
                    "buyer_wallet": WALLET, "buyer_wallet_raw": WALLET, "buyer_agent_id": "agent_b",
                    "offer_sha256": "0f" * 32},
        "terms": {"price_nanotos": "100000000", "storage_fee_nanotos": "200000000", "cleanup_bounty_nanotos": "100000000",
                  "response_sla_seconds": 3600, "refund_claim_window_seconds": 3600,
                  "execution_allowance_nanotos": "200000000"},
        "dry_check": {"withdrawn": "withdrawn"}}
    write(root / "buyer-c" / "out" / "public" / "profile.json", profile)
    write(root / "handoff" / "handoff.json", {"requests": {"R": {"request_id": 0, "request_hash": R_HASH},
                                                           "F": {"request_id": 1, "request_hash": F_HASH}}})
    for label in ("R", "F"):
        write(root / "handoff" / label / "evidence.json", {"quote": {"package_base64": "AAEC", "quote_commitment": "qc",
                                                                     "terms_hash": "th"}})
    r_request = {"request_id": 0, "request_hash": R_HASH, "state": "responded", "caller": WALLET, "call": tx("c1" * 32),
                 "respond": tx("d1" * 32, sender=PROVIDER_WALLET), "response_hash": "e1" * 32,
                 "receipt": {"file_sha256": "f1" * 32, "cell_hash": "e1" * 32, "exit_code": 0, "artifact_digest": "a1"},
                 "artifact": {"file_sha256": "a2" * 32, "members": []}}
    f_request = {"request_id": 1, "request_hash": F_HASH, "state": "refunded", "caller": WALLET, "call": tx("c2" * 32),
                 "expire": tx("e2" * 32), "claim_refund": tx("e3" * 32, payouts=[
                     {"destination": WALLET, "amount_nanotos": "100000000"}])}
    actor = {"code_hash_matches": True, "last_transaction": {"hash": WITHDRAW_TX, "lt": 2000}}
    vout = root / "verifier-work" / "out"
    write(vout / "verdict-R.json", {"result": "pass", "checks": [], "requests": [r_request]})
    write(vout / "verdict-F.json", {"result": "pass", "checks": [], "requests": [f_request]})
    write(vout / "verdict-all.json", {"result": "pass", "checks": [], "actor": actor, "checkpoint": {"seqno": 5},
                                      "requests": [r_request, f_request]})
    write(vout / "codex-summary.json", {"verdict": "AGENT_OPERATED_PILOT_PASSED"})
    write(vout / "build.json", {"commit": "c0" * 20, "sha256": "5e" * 32})
    write(root / "provider-c" / "out" / "provider" / "status-1795000000.json", {"report": {"withdrawals": [
        {"state": "finalized", "transaction_hash": WITHDRAW_TX, "query_id": "1", "amount_nanotos": "300000000"}]}})
    checks = [{"id": "x", "ok": True}]
    write(root / "buyer-c" / "logs" / "confirmations.jsonl",
          "\n".join(json.dumps({"request_hash": h, "confirm": True, "checks": checks, "outcome": "ok", "at": "t",
                                "by": "automated", "screen_sha256": "5c" * 32}) for h in (R_HASH, F_HASH)) + "\n")
    write(root / "funding-operations.json", {"operations": []})
    write(root / "orchestration.json", {
        "sessions": [{"name": "buy-R", "tools": ["mcp__tos-buyer__tos_buyer_quote"], "model": "m"}],
        "credentials_end": {"deleted": True, "leaks": []}})


def make(root: Path) -> tuple[int, dict, Path]:
    out = root / "record.json"
    if out.exists():
        out.unlink()
    result = subprocess.run([sys.executable, "-I", str(SCRIPT), str(root), str(out)], capture_output=True, text=True)
    summary = json.loads(result.stdout) if result.stdout.strip().startswith("{") else {"stderr": result.stderr}
    return result.returncode, summary, out


def sign_all(root: Path, digest: str, tamper: str | None = None) -> None:
    signatures = []
    for role in ("buyer", "provider", "verifier"):
        key = root / f"{role}.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)], check=True)
        der = subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"], capture_output=True,
                             check=True).stdout
        message = root / "message"
        message.write_bytes(bytes.fromhex(digest))
        signature = subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(message)],
                                   capture_output=True, check=True).stdout
        if role == tamper:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        signatures.append({"role": role, "algorithm": "Ed25519", "public_key_hex": der[-32:].hex(),
                           "message_hex": digest, "signature_hex": signature.hex()})
    write(root / "record" / "signatures.json", signatures)


class MakeRecordTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        build_run(self.root)

    def tearDown(self):
        self.directory.cleanup()

    def test_pass_unsigned_then_signed(self):
        status, summary, out = make(self.root)
        self.assertEqual(status, 0, summary)
        record = json.loads(out.read_text())
        self.assertEqual(record["verdict"], "AGENT_OPERATED_PILOT_PASSED")
        self.assertIs(record["qualifies_as_gate_d"], False)
        self.assertEqual(record["releases"]["service_actor_release"], "test-profile")
        self.assertIn("had only the tos_buyer_* MCP tools", record["buyer_declaration"])
        self.assertIn("deleted before this record was built", record["automation"]["credentials"])
        keys = {p["role"]: p["declaration_key"] for p in record["participants"]}
        self.assertFalse(keys["verifier"]["retained"])
        self.assertIn("after the run", keys["verifier"]["created"])
        self.assertTrue(keys["buyer"]["retained"] and keys["provider"]["retained"])
        sign_all(self.root, summary["record_sha256"])
        status, signed, out = make(self.root)
        self.assertEqual(status, 0, signed)
        self.assertEqual(signed["record_sha256"], summary["record_sha256"])
        record = json.loads(out.read_text())
        self.assertTrue(all(s["verified"] for s in record["signatures"]))
        body = {k: v for k, v in record.items() if k not in ("record_sha256", "signatures")}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), record["record_sha256"])

    def test_a_failing_verifier_verdict_fails_the_record(self):
        path = self.root / "verifier-work" / "out" / "verdict-F.json"
        verdict = json.loads(path.read_text())
        verdict["result"] = "fail"
        verdict["checks"] = [{"id": "actor-replay", "ok": False}]
        write(path, verdict)
        write(self.root / "verifier-work" / "out" / "codex-summary.json", {"verdict": "AGENT_OPERATED_PILOT_FAILED"})
        status, summary, out = make(self.root)
        self.assertEqual(status, 1)
        record = json.loads(out.read_text())
        self.assertEqual(record["verdict"], "AGENT_OPERATED_PILOT_FAILED")
        self.assertEqual(record["status"], "agent-pilot-failed")
        self.assertIn("verifier-tool-pass-F", summary["failed_checks"])

    def test_a_bad_signature_fails_the_written_record(self):
        _, summary, _ = make(self.root)
        sign_all(self.root, summary["record_sha256"], tamper="verifier")
        status, signed, out = make(self.root)
        self.assertEqual(status, 1)
        record = json.loads(out.read_text())
        self.assertEqual(record["verdict"], "AGENT_OPERATED_PILOT_FAILED")
        self.assertEqual(record["status"], "agent-pilot-failed")
        self.assertIn("three-declaration-signatures-verify", signed["failed_checks"])
        self.assertFalse(next(s for s in record["signatures"] if s["role"] == "verifier")["verified"])
        self.assertNotEqual(record["record_sha256"], summary["record_sha256"])

    def test_a_model_with_other_tools_is_not_declared_restricted(self):
        orchestration = json.loads((self.root / "orchestration.json").read_text())
        orchestration["sessions"][0]["tools"].append("Bash")
        write(self.root / "orchestration.json", orchestration)
        write(self.root / "verifier-work" / "out" / "codex-summary.json", {"verdict": "AGENT_OPERATED_PILOT_FAILED"})
        status, _, out = make(self.root)
        record = json.loads(out.read_text())
        self.assertEqual(status, 1)
        self.assertIn("did NOT pass", record["buyer_declaration"])

    def test_credentials_left_on_disk_fail_the_record(self):
        write(self.root / "secrets" / "claude.env", "CLAUDE_CODE_OAUTH_TOKEN=" + "x" * 40 + "\n")
        write(self.root / "verifier-work" / "out" / "codex-summary.json", {"verdict": "AGENT_OPERATED_PILOT_FAILED"})
        status, summary, out = make(self.root)
        self.assertEqual(status, 1)
        self.assertIn("model-credentials-scanned-and-deleted-before-the-record", summary["failed_checks"])
        self.assertIn("did NOT pass", json.loads(out.read_text())["automation"]["credentials"])

    def test_binaries_added_after_start_are_carried_and_marked(self):
        path = self.root / "bin" / "build.json"
        build = json.loads(path.read_text())
        build["binaries"]["codex-code-mode-host"] = "ff" * 32
        build["added_after_start"] = [{"at": "2026-11-19T07:22:40+00:00", "binaries": {"codex-code-mode-host": "ff" * 32},
                                       "reason": "the Codex CLI's companion executable"}]
        write(path, build)
        status, summary, out = make(self.root)
        self.assertEqual(status, 0, summary)
        binaries = json.loads(out.read_text())["binaries"]
        self.assertEqual(binaries["added_after_start"], build["added_after_start"])
        self.assertTrue(binaries["built_by_operator"]["codex-code-mode-host"]["added_after_start"])
        self.assertFalse(binaries["built_by_operator"]["claude"]["added_after_start"])
        # An addition whose digest is not the build's fails the record.
        build["added_after_start"][0]["binaries"]["codex-code-mode-host"] = "ee" * 32
        write(path, build)
        write(self.root / "verifier-work" / "out" / "codex-summary.json", {"verdict": "AGENT_OPERATED_PILOT_FAILED"})
        status, summary, _ = make(self.root)
        self.assertEqual(status, 1)
        self.assertIn("binaries-added-after-start-are-in-build-json", summary["failed_checks"])

    def test_refuses_to_write_the_gate_d_verdict(self):
        write(self.root / "verifier-work" / "out" / "codex-summary.json", {"verdict": FORBIDDEN})
        status, summary, out = make(self.root)
        self.assertNotEqual(status, 0)
        self.assertFalse(out.exists())
        self.assertIn("would name the Gate D verdict", summary.get("stderr", ""))


if __name__ == "__main__":
    unittest.main()
