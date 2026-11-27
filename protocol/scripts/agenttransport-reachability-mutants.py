#!/usr/bin/env python3
"""Remove or perturb a reachability boundary; named assertion failure required."""

import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "./protocol/pkg/agenttransport"
MUTANTS = [
    (
        "reader-bound",
        "reachability_wire.go",
        "n < 0 || n > len(r.raw)-r.at",
        "false",
        "TestHintWireRefusals",
    ),
    (
        "sign-key-length",
        "reachability_wire.go",
        "len(key) != ed25519.PrivateKeySize",
        "false",
        "TestTransportSigningKeyRefusals",
    ),
    (
        "sign-key-binding",
        "reachability_wire.go",
        "!bytes.Equal(derived, key) || !bytes.Equal(derived[ed25519.SeedSize:], delegation.TransportKey[:])",
        "false && (!bytes.Equal(derived, key) || !bytes.Equal(derived[ed25519.SeedSize:], delegation.TransportKey[:]))",
        "TestTransportSigningKeyRefusals",
    ),
    (
        "object-domain",
        "reachability_wire.go",
        '"tos.service.agent-reachability-hint.object.v1\\x00"',
        '"tos.service.agent-reachability-hint.object.v2\\x00"',
        "TestFrozenReachabilityVectors",
    ),
    (
        "object-kind-domain",
        "hint.go",
        "append([]byte(hintObjectDomain), byte(kind))",
        "append([]byte(hintObjectDomain), byte(0))",
        "TestFrozenReachabilityVectors",
    ),
    (
        "hint-ttl-order",
        "hint.go",
        "h.ExpiresAt <= h.IssuedAt",
        "false",
        "TestHintStructuralRefusals/ttl-equal",
    ),
    (
        "hint-ttl-bound",
        "hint.go",
        "h.ExpiresAt-h.IssuedAt > MaxHintLifetimeSeconds",
        "false",
        "TestHintStructuralRefusals/ttl-long",
    ),
    (
        "hint-min-relays",
        "hint.go",
        "len(h.Relays) < 1",
        "false",
        "TestHintStructuralRefusals/no-relays",
    ),
    (
        "hint-max-relays",
        "hint.go",
        "len(h.Relays) > MaxHintRelays",
        "false",
        "TestHintStructuralRefusals/many-relays",
    ),
    (
        "hint-direct-bound",
        "hint.go",
        "len(h.Direct) > MaxDirectEntries",
        "false",
        "TestHintStructuralRefusals/many-direct",
    ),
    (
        "hint-url",
        "hint.go",
        "agentpacketseal.CheckRelayURL(relay) != nil",
        "false && agentpacketseal.CheckRelayURL(relay) != nil",
        "TestHintStructuralRefusals/bad-url",
    ),
    (
        "hint-duplicate-url",
        "hint.go",
        "|| seen[relay]",
        "|| false",
        "TestHintStructuralRefusals/duplicate-relay",
    ),
    (
        "direct-kind",
        "hint.go",
        "entry.Kind != 1",
        "false",
        "TestHintStructuralRefusals/direct-kind",
    ),
    (
        "direct-port",
        "hint.go",
        "entry.Port == 0",
        "false",
        "TestHintStructuralRefusals/direct-port",
    ),
    (
        "direct-class",
        "hint.go",
        "(entry.InboundClass != 1 && entry.InboundClass != 2)",
        "false",
        "TestHintStructuralRefusals/direct-class",
    ),
    (
        "object-order",
        "hint.go",
        "object.Kind <= previous",
        "previous > 255",
        "TestHintStructuralRefusals/object-order",
    ),
    (
        "object-zero",
        "hint.go",
        "object.Length == 0",
        "false",
        "TestHintStructuralRefusals/object-zero",
    ),
    (
        "object-length",
        "hint.go",
        "object.Length > limit",
        "false",
        "TestHintStructuralRefusals/object-long",
    ),
    (
        "object-closed-kind",
        "hint.go",
        "default:\n\t\treturn 0",
        "default:\n\t\treturn MaxHintCardBytes",
        "TestHintStructuralRefusals/object-kind",
    ),
    (
        "hint-size-edge",
        "hint.go",
        "len(out)+ed25519.SignatureSize > MaxHintSize",
        "len(out)+ed25519.SignatureSize > 1511",
        "TestHintLimitsAndReducedPublication",
    ),
    (
        "hint-wire-domain",
        "hint.go",
        "!bytes.HasPrefix(raw, []byte(hintDomain))",
        "false",
        "TestHintWireRefusals",
    ),
    (
        "hint-trailing",
        "hint.go",
        "if !r.done() {",
        "if false {",
        "TestHintWireRefusals",
    ),
    (
        "record-domain",
        "hint.go",
        "!bytes.HasPrefix(raw, []byte(hintRecordDomain))",
        "false",
        "TestHintWireRefusals",
    ),
    (
        "record-trailing",
        "hint.go",
        "if !reader.done() {",
        "if false {",
        "TestHintWireRefusals",
    ),
    (
        "record-object-count",
        "hint.go",
        "len(r.Objects) != len(r.Hint.Objects)",
        "false",
        "TestHintObjectsArePresentAndBound",
    ),
    (
        "record-object-kind",
        "hint.go",
        "object.Kind != ref.Kind",
        "false",
        "TestHintObjectsArePresentAndBound",
    ),
    (
        "record-object-digest",
        "hint.go",
        "if err != nil || digest != ref.Digest {",
        "if err != nil || (false && digest != ref.Digest) {",
        "TestHintObjectsArePresentAndBound",
    ),
    (
        "hint-chain",
        "hint.go",
        "v.VerifyDelegation(ctx, delegation, Hints); err != nil",
        "v.VerifyDelegation(ctx, delegation, Hints); false && err != nil",
        "TestHintChecksSignatureAndFinalizedDelegation",
    ),
    (
        "hint-purpose",
        "hint.go",
        "v.VerifyDelegation(ctx, delegation, Hints)",
        "v.VerifyDelegation(ctx, delegation, Relay)",
        "TestHintRequiresHintsPurpose",
    ),
    (
        "hint-signature",
        "hint.go",
        "!ed25519.Verify(record.Hint.Delegation.TransportKey[:], preimage, record.Hint.Signature[:])",
        "false && !ed25519.Verify(record.Hint.Delegation.TransportKey[:], preimage, record.Hint.Signature[:])",
        "TestHintChecksSignatureAndFinalizedDelegation",
    ),
    (
        "hint-future",
        "hint.go",
        "(h.IssuedAt > now && h.IssuedAt-now > 300)",
        "false",
        "TestHintTimestamps/future-over",
    ),
    (
        "hint-expiry",
        "hint.go",
        "now >= h.ExpiresAt",
        "false",
        "TestHintTimestamps/expiry-edge",
    ),
    (
        "hint-late-time",
        "hint.go",
        "checkHintTime(record.Hint, now); err != nil",
        "checkHintTime(record.Hint, now); false && err != nil",
        "TestHintTimestamps/during-read",
    ),
    (
        "hint-address",
        "hint.go",
        "!validDirectIPv4(entry.IPv4, policy.AllowPrivateIPv4)",
        "false",
        "TestDirectAddressPolicy",
    ),
    (
        "private-default",
        "hint.go",
        "return allowPrivate",
        "return true",
        "TestDirectAddressPolicy",
    ),
    (
        "reserved-address",
        "hint.go",
        "prefix.Contains(ip)",
        "false && prefix.Contains(ip)",
        "TestDirectAddressPolicy",
    ),
    (
        "card-json",
        "hint.go",
        "jsonstrict.Decode(object.Bytes, &packet)",
        "(func() error { _ = jsonstrict.Decode; return json.Unmarshal(object.Bytes, &packet) })()",
        "TestHintObjectsArePresentAndBound",
    ),
    (
        "card-agent",
        "hint.go",
        "sender != record.Hint.Delegation.AgentID()",
        "false",
        "TestHintObjectsArePresentAndBound",
    ),
    (
        "consumer-required",
        "hint.go",
        "len(result.Record.Objects) > 0 && verify == nil",
        "false",
        "TestConsumerMustAuthenticateObjects",
    ),
    (
        "consumer-agent",
        "hint.go",
        "agent != result.Record.Hint.Delegation.AgentID()",
        "false",
        "TestConsumerMustAuthenticateObjects",
    ),
    (
        "consumer-late-check",
        "hint.go",
        "return v.VerifyHint(ctx, raw, policy)",
        "return result, nil",
        "TestConsumerMustAuthenticateObjects",
    ),
    (
        "publish-chat-opt-in",
        "hint.go",
        "object.Kind != RailCard && !options.PublicContact",
        "false",
        "TestHintLimitsAndReducedPublication",
    ),
    (
        "publish-direct-opt-in",
        "hint.go",
        "!options.DirectEnabled && len(h.Direct) > 0",
        "false",
        "TestHintLimitsAndReducedPublication",
    ),
    (
        "newest-delegation",
        "hint.go",
        "err != nil || !bytes.Equal(da, db)",
        "err != nil || (false && !bytes.Equal(da, db))",
        "TestHintNewestIsPerDelegation",
    ),
    (
        "newest-issued",
        "hint.go",
        "a.IssuedAt < b.IssuedAt",
        "false",
        "TestHintNewestIsPerDelegation",
    ),
    (
        "newest-tie",
        "hint.go",
        "bytes.Compare(ha[:], hb[:])",
        "-bytes.Compare(ha[:], hb[:])",
        "TestHintNewestIsPerDelegation",
    ),
    (
        "hello-role",
        "direct.go",
        "h.Role != HelloInitiator && h.Role != HelloResponder",
        "false",
        "TestHelloFixedWireAndRoles",
    ),
    (
        "hello-zero-response",
        "direct.go",
        "h.Role == HelloInitiator && h.ResponderNonce != ([32]byte{})",
        "false",
        "TestHelloFixedWireAndRoles",
    ),
    (
        "hello-domain",
        "direct.go",
        "!bytes.HasPrefix(raw, []byte(helloDomain))",
        "false",
        "TestHelloFixedWireAndRoles",
    ),
    (
        "hello-size-edge",
        "direct.go",
        "len(raw) != HelloSize",
        "len(raw) != HelloSize-8",
        "TestHelloFixedWireAndRoles",
    ),
    (
        "hello-role-binding",
        "direct.go",
        "h.Role != expected.Role",
        "false",
        "TestHelloBindsChannelAgentChallengeAndContact/role",
    ),
    (
        "hello-channel-peer",
        "direct.go",
        "h.LocalADNL != expected.PeerADNL",
        "false",
        "TestHelloBindsChannelAgentChallengeAndContact/channel-peer",
    ),
    (
        "hello-channel-local",
        "direct.go",
        "h.PeerADNL != expected.LocalADNL",
        "false",
        "TestHelloBindsChannelAgentChallengeAndContact/channel-local",
    ),
    (
        "hello-known-peer",
        "direct.go",
        'expected.ExpectedAgent == ""',
        "false",
        "TestHelloBindsChannelAgentChallengeAndContact/missing-agent",
    ),
    (
        "hello-challenge",
        "direct.go",
        "h.InitiatorNonce != expected.InitiatorNonce",
        "false",
        "TestHelloBindsChannelAgentChallengeAndContact/challenge",
    ),
    (
        "hello-agent",
        "direct.go",
        "expected.ExpectedAgent != h.Delegation.AgentID()",
        "false",
        "TestHelloBindsChannelAgentChallengeAndContact/expected-agent",
    ),
    (
        "hello-admission-required",
        "direct.go",
        "expected.AdmittedContact == nil",
        "false",
        "TestHelloBindsChannelAgentChallengeAndContact/no-admission",
    ),
    (
        "hello-contact",
        "direct.go",
        "!expected.AdmittedContact(h.Delegation.AgentID())",
        "false",
        "TestHelloBindsChannelAgentChallengeAndContact/removed-contact",
    ),
    (
        "hello-chain",
        "direct.go",
        "v.VerifyDelegation(ctx, delegation, Direct); err != nil",
        "v.VerifyDelegation(ctx, delegation, Direct); false && err != nil",
        "TestHelloSignatureAndDirectPurpose",
    ),
    (
        "hello-purpose",
        "direct.go",
        "v.VerifyDelegation(ctx, delegation, Direct)",
        "v.VerifyDelegation(ctx, delegation, Hints)",
        "TestHelloSignatureAndDirectPurpose",
    ),
    (
        "hello-signature",
        "direct.go",
        "!ed25519.Verify(h.Delegation.TransportKey[:], preimage, h.Signature[:])",
        "false && !ed25519.Verify(h.Delegation.TransportKey[:], preimage, h.Signature[:])",
        "TestHelloSignatureAndDirectPurpose",
    ),
    (
        "hello-future-edge",
        "direct.go",
        "issued-now <= 120",
        "issued-now <= 121",
        "TestHelloTimeWindowAndReadDelay/future-over",
    ),
    (
        "hello-past-edge",
        "direct.go",
        "now-issued <= 120",
        "now-issued <= 121",
        "TestHelloTimeWindowAndReadDelay/past-over",
    ),
    (
        "hello-late-time",
        "direct.go",
        "now, err = v.objectTime(ctx)\n\tif err != nil || !withinDirectWindow(h.IssuedAt, now)",
        "now, err = v.objectTime(ctx)\n\tif err != nil",
        "TestHelloTimeWindowAndReadDelay/during-read",
    ),
    (
        "receipt-min-outcome",
        "direct.go",
        "r.Outcome < ReceiptStored",
        "false",
        "TestReceiptOutcomesAndBindings",
    ),
    (
        "receipt-max-outcome",
        "direct.go",
        "r.Outcome > ReceiptRefused",
        "false",
        "TestReceiptOutcomesAndBindings",
    ),
    (
        "receipt-domain",
        "direct.go",
        "!bytes.HasPrefix(raw, []byte(receiptDomain))",
        "false",
        "TestReceiptOutcomesAndBindings",
    ),
    (
        "receipt-size-edge",
        "direct.go",
        "len(raw) != ReceiptSize",
        "len(raw) != ReceiptSize+1",
        "TestReceiptOutcomesAndBindings",
    ),
    (
        "receipt-signer-agent",
        "direct.go",
        "r.RecipientAgent != delegation.AgentDigest",
        "false",
        "TestReceiptOutcomesAndBindings",
    ),
    (
        "receipt-agent",
        "direct.go",
        "r.RecipientAgent != expectedAgent",
        "false",
        "TestReceiptOutcomesAndBindings",
    ),
    (
        "receipt-envelope",
        "direct.go",
        "r.EnvelopeID != expectedEnvelope",
        "false",
        "TestReceiptOutcomesAndBindings",
    ),
    (
        "receipt-peer-agent",
        "direct.go",
        "d.AgentDigest != expectedAgent",
        "false",
        "TestReceiptRequiresPeerDelegation",
    ),
    (
        "receipt-purpose",
        "direct.go",
        "v.VerifyDelegation(ctx, peerDelegation, Direct)",
        "v.VerifyDelegation(ctx, peerDelegation, Hints)",
        "TestReceiptRequiresPeerDelegation",
    ),
    (
        "receipt-signature",
        "direct.go",
        "!ed25519.Verify(d.TransportKey[:], preimage, r.Signature[:])",
        "false && !ed25519.Verify(d.TransportKey[:], preimage, r.Signature[:])",
        "TestReceiptOutcomesAndBindings",
    ),
]


def execute(command):
    result = subprocess.run(
        command,
        cwd=ROOT,
        env={**os.environ, "GOWORK": "off"},
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    return result.returncode, result.stdout + result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--only", help="one control for diagnosis; full run is required for acceptance"
    )
    args = parser.parse_args()
    code, output = execute(["go", "test", "-count=1", PACKAGE])
    if code:
        raise RuntimeError("baseline failed\n" + output)
    selected = [m for m in MUTANTS if args.only is None or m[0] == args.only]
    if not selected:
        raise RuntimeError("unknown control")
    for name, filename, old, new, test in selected:
        source = ROOT / "protocol/pkg/agenttransport" / filename
        original = source.read_text()
        if original.count(old) != 1:
            raise RuntimeError("non-unique anchor: " + name)
        with tempfile.TemporaryDirectory(prefix="reachability-mutant-") as tmp:
            replacement = Path(tmp) / filename
            replacement.write_text(original.replace(old, new))
            overlay = Path(tmp) / "overlay.json"
            overlay.write_text(json.dumps({"Replace": {str(source): str(replacement)}}))
            code, output = execute(
                [
                    "go",
                    "test",
                    "-vet=off",
                    "-count=1",
                    "-overlay",
                    str(overlay),
                    "-run",
                    "^" + test + "$",
                    PACKAGE,
                ]
            )
        if code == 0 or "--- FAIL: " + test not in output or "[build failed]" in output:
            raise RuntimeError("control survived or invalid: " + name + "\n" + output)
        print("RED " + name + ": " + test, flush=True)
    print(f"REACHABILITY_MUTANTS_OK: {len(selected)} controls caught")


if __name__ == "__main__":
    main()
