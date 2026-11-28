#!/usr/bin/env python3
"""Semantic controls for V2 authorization, listing and policy boundaries."""

import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
RELAY = "./protocol/pkg/agentpacketrelay"
CONTROLS = [
    (
        "retention-before-conversion",
        "../cmd/tos-service-packet-relay-v2/main.go",
        "*c.TTLSeconds > uint64(agentpacketrelay.MaxTTL/time.Second)",
        "false",
        "./protocol/cmd/tos-service-packet-relay-v2",
        "TestV2ConfiguredRetentionIsBoundedBeforeConversion",
    ),
    (
        "checkpoint-outside-store",
        "../cmd/tos-service-packet-relay-v2/main.go",
        '(!strings.HasPrefix(relative, ".."+string(os.PathSeparator)) && relative != "..")',
        '(false && (!strings.HasPrefix(relative, ".."+string(os.PathSeparator)) && relative != ".."))',
        "./protocol/cmd/tos-service-packet-relay-v2",
        "TestV2ConfigIsStrictAndHasNoLegacyMode",
    ),
    (
        "deposit-size-status",
        "agentpacketrelay/v2_http.go",
        "r.ContentLength > MaxEnvelopeBytes)",
        "false)",
        RELAY,
        "TestV2HTTPRejectsOversizeBeforeReadingAndBoundsSlots",
    ),
    (
        "per-client-body-slots",
        "agentpacketrelay/v2_http.go",
        "s.clients[client] >= DefaultMaxConcurrentDepositsPerClient",
        "false",
        RELAY,
        "TestV2HTTPRejectsOversizeBeforeReadingAndBoundsSlots",
    ),
    (
        "global-body-slots",
        "agentpacketrelay/v2_http.go",
        "make(chan struct{}, DefaultMaxConcurrentDeposits)",
        "make(chan struct{}, DefaultMaxConcurrentDeposits+1)",
        RELAY,
        "TestV2HTTPRejectsOversizeBeforeReadingAndBoundsSlots",
    ),
    (
        "policy-expiry-reclamation",
        "agentpacketrelay/v2_store.go",
        "if err := s.sweepPolicies(unixNow(now)); err != nil {",
        "if err := error(nil); err != nil {",
        RELAY,
        "TestV2ExpiredPoliciesAreReclaimedWithoutAVisitor",
    ),
    (
        "config-unknown-fields",
        "../internal/jsonstrict/decode.go",
        "decoder.DisallowUnknownFields()",
        "// allow unknown fields",
        "./protocol/cmd/tos-service-packet-relay-v2",
        "TestV2ConfigIsStrictAndHasNoLegacyMode",
    ),
    (
        "config-duplicate-fields",
        "../internal/jsonstrict/decode.go",
        "if _, duplicate := seen[key]; duplicate {",
        "if _, duplicate := seen[key]; false && duplicate {",
        "./protocol/cmd/tos-service-packet-relay-v2",
        "TestV2ConfigIsStrictAndHasNoLegacyMode",
    ),
    (
        "finalized-authorization",
        "agentpacketrelay/v2_http.go",
        "_, err = s.verifier.VerifyDelegation(r.Context(), raw, agenttransport.Relay)",
        "_ = raw; err=nil",
        RELAY,
        "TestV2HTTPFinalizedCacheBoundAndStrangersContinue",
    ),
    (
        "path-agent",
        "agenttransport/proof.go",
        "if c.delegation.AgentID() != r.AgentID {",
        "if false {",
        RELAY,
        "TestV2HTTPClosedReadsAndNoV1Route",
    ),
    (
        "listing-bound",
        "agentpacketrelay/v2_http.go",
        "MaxV2ListingBytes = 80 << 10",
        "MaxV2ListingBytes = 64 << 10",
        RELAY,
        "TestV2MaximalListingAndOversizeBug",
    ),
    (
        "listing-never-truncate",
        "agentpacketrelay/v2_http.go",
        "status = 500",
        "status = 200",
        RELAY,
        "TestV2MaximalListingAndOversizeBug",
    ),
    (
        "listing-client-bound",
        "agentpacketrelay/v2_client.go",
        "bound = MaxV2ListingBytes",
        "bound = MaxResponseBytes",
        RELAY,
        "TestV2ClientAcceptsOnlyListingExceptionAndNoFallback",
    ),
    (
        "other-client-bound",
        "agentpacketrelay/v2_client.go",
        "bound := MaxResponseBytes",
        "bound := MaxV2ListingBytes",
        RELAY,
        "TestV2ClientAcceptsOnlyListingExceptionAndNoFallback",
    ),
    (
        "v2-schema",
        "agentpacketrelay/v2_client.go",
        "listing.Schema != SchemaV2Mailbox",
        "listing.Schema != SchemaV2Mailbox && listing.Schema != SchemaMailbox",
        RELAY,
        "TestV2ClientAcceptsOnlyListingExceptionAndNoFallback",
    ),
    (
        "required-credential",
        "agentpacketrelay/v2_http.go",
        "if optional {",
        "if true {",
        RELAY,
        "TestV2HTTPClosedReadsAndNoV1Route",
    ),
    (
        "provided-invalid-is-not-stranger",
        "agentpacketrelay/v2_http.go",
        "if len(cv) == 0 && len(pv) == 0 {",
        "if optional || (len(cv) == 0 && len(pv) == 0) {",
        RELAY,
        "TestV2HTTPInvalidCredentialsNeverBecomeStrangers",
    ),
    (
        "replay-claim",
        "agentpacketrelay/v2_http.go",
        "if err = s.store.Replay().Claim(checked, unixNow(s.now())); err != nil {",
        "if err = error(nil); err != nil {",
        RELAY,
        "TestV2HTTPRestartSecondRelayAndClockRollback",
    ),
    (
        "relay-binding",
        "agentpacketrelay/v2_http.go",
        "RelayURL: s.relay,",
        'RelayURL: "https://127.0.0.1",',
        RELAY,
        "TestV2HTTPProofBindsConfiguredRelayWithoutRelayCaveat",
    ),
    (
        "post-read-scope",
        "agentpacketrelay/v2_http.go",
        "if err = checked.Credential.CheckScope(unixNow(s.now()), s.relay, op); err == nil {",
        "if err = error(nil); err == nil {",
        RELAY,
        "TestV2HTTPRechecksCredentialAfterFinalizedRead",
    ),
    (
        "freshness-refusal-code",
        "agenttransport/verify.go",
        'fmt.Errorf("%w: no usable cached pass", ErrUnavailable)',
        'errors.New("no usable cached pass")',
        RELAY,
        "TestV2HTTPFinalizedCacheBoundAndStrangersContinue",
    ),
    (
        "cache-600",
        "agenttransport/verify.go",
        "RefuseAfter                       = 600 * time.Second",
        "RefuseAfter                       = 601 * time.Second",
        RELAY,
        "TestV2HTTPFinalizedCacheBoundAndStrangersContinue",
    ),
    (
        "policy-future",
        "agentpacketrelay/v2_policy.go",
        "!(p.IssuedAt > now && p.IssuedAt-now > 300)",
        "true",
        RELAY,
        "TestV2HTTPPolicyDurabilityTimestampAndRevocation",
    ),
    (
        "policy-count",
        "agentpacketrelay/v2_policy.go",
        "p.StrangerCount <= uint16(l.StrangerMaxEnvelopes)",
        "true",
        RELAY,
        "TestV2PolicyCodecStrictAndLowerOnly",
    ),
    (
        "policy-bytes",
        "agentpacketrelay/v2_policy.go",
        "uint64(p.StrangerBytes) <= uint64(l.StrangerMaxBytes)",
        "true",
        RELAY,
        "TestV2PolicyCodecStrictAndLowerOnly",
    ),
    (
        "policy-domain",
        "agentpacketrelay/v2_policy.go",
        "string(raw[:len(v2PolicyDomain)]) != v2PolicyDomain",
        "false",
        RELAY,
        "TestV2PolicyCodecStrictAndLowerOnly",
    ),
    (
        "policy-bound",
        "agentpacketrelay/v2_policy.go",
        "len(s.store.policies) >= MaxV2Policies",
        "false",
        RELAY,
        "TestV2HTTPPolicyBoundAndUncertainWrite/bound",
    ),
    (
        "policy-void",
        "agentpacketrelay/v2_policy.go",
        "!errors.Is(err, agenttransport.ErrDelegationRevoked)",
        "true",
        RELAY,
        "TestV2RotatedOwnerCanReplaceFuturePolicyWithEarlierTimestamp",
    ),
    (
        "policy-integrity-does-not-open",
        "agentpacketrelay/v2_policy.go",
        "!errors.Is(err, agenttransport.ErrDelegationRevoked)",
        "errors.Is(err, agenttransport.ErrUnavailable)",
        RELAY,
        "TestV2HTTPPolicyReadFailureDoesNotOpenClosedMailbox",
    ),
    (
        "policy-durability",
        "agentpacketrelay/v2_policy.go",
        "err = s.store.disk.write(policyName(agent), encoded)",
        "_ = encoded",
        RELAY,
        "TestV2HTTPPolicyDurabilityTimestampAndRevocation",
    ),
    (
        "all-endpoint-outage",
        "toschain/quorum.go",
        "transportFailures == len(nodes)",
        "false",
        "./protocol/pkg/toschain",
        "TestEndpointOutageIsNotIntegrityFailure/network",
    ),
    (
        "integrity-is-not-outage",
        "toschain/quorum.go",
        "transportFailures == len(nodes)",
        "true",
        "./protocol/pkg/toschain",
        "TestEndpointOutageIsNotIntegrityFailure/integrity",
    ),
    (
        "genesis-root",
        "toschain/network_genesis.go",
        "got.Root != rootHash",
        "false",
        "./protocol/pkg/toschain",
        "TestCheckNetworkGenesisUsesEndpointQuorum/root",
    ),
    (
        "genesis-file",
        "toschain/network_genesis.go",
        "got.File != fileHash",
        "false",
        "./protocol/pkg/toschain",
        "TestCheckNetworkGenesisUsesEndpointQuorum/file",
    ),
]


def execute(args):
    result = subprocess.run(
        args,
        cwd=ROOT,
        env={**os.environ, "GOWORK": "off"},
        capture_output=True,
        text=True,
        timeout=180,
    )
    return result.returncode, result.stdout + result.stderr


def main():
    for package in {c[4] for c in CONTROLS}:
        code, output = execute(
            [
                "go",
                "test",
                "-run",
                "TestV2HTTP|TestV2Client|TestV2Maximal|TestV2Policy|TestV2Rotated|TestV2Config|TestV2Configured|TestV2Expired|TestEndpointOutage|TestCheckNetworkGenesis",
                "-count=1",
                package,
            ]
        )
        if code:
            raise RuntimeError("baseline failed\n" + output)
    for name, filename, old, new, package, test in CONTROLS:
        source = (ROOT / "protocol/pkg" / filename).resolve()
        text = source.read_text()
        if text.count(old) != 1:
            raise RuntimeError("nonunique anchor: " + name)
        with tempfile.TemporaryDirectory(prefix="relay-v2-http-mutant-") as tmp:
            replacement = Path(tmp) / source.name
            replacement.write_text(text.replace(old, new))
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
                    package,
                ]
            )
        if code == 0 or "--- FAIL: " + test not in output or "[build failed]" in output:
            raise RuntimeError(
                "mutant did not fail its named test: " + name + "\n" + output
            )
        print("RED " + name + ": " + test, flush=True)
    print(f"RELAY_V2_HTTP_MUTANTS_OK: {len(CONTROLS)} controls")


if __name__ == "__main__":
    main()
