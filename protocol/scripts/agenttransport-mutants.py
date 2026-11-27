#!/usr/bin/env python3
"""Remove one boundary check per overlay; require its named test to go red.

The checkout is never mutated. A build failure or an absent/duplicate anchor is
an error, not a killed mutant. Run under the same thermal guard as Go tests.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "./protocol/pkg/agenttransport"
# name, source, unique old text, replacement, named test
MUTANTS = [
    (
        "source-network",
        "legacy.go",
        '(n.GenesisRootHash != r.network.GenesisRootHash && n.GenesisRootHash != "sha256:"+r.network.GenesisRootHash)',
        "false",
        "TestLegacyReaderUsesTheOriginalNetworkBeforeNormalization",
    ),
    (
        "legacy-epoch",
        "verify.go",
        "d.AuthorizationEpoch != 0 || s.CurrentEpoch != nil || s.AdmissionEpochs != nil || s.EpochCheckpoint != 0",
        "false",
        "TestProductionAndLegacyModes",
    ),
    (
        "legacy-adapter-gate",
        "legacy.go",
        "mode != TestNetworkLegacyEpochZero || source == nil",
        "source == nil",
        "TestLegacyAdapterIsExplicit",
    ),
    (
        "set-bound",
        "verify.go",
        "len(agent.DelegationDigests) > 128 || len(s.AdmissionEpochs) > 128",
        "false",
        "TestFinalizedSetBounds",
    ),
    (
        "cache-capacity",
        "verify.go",
        "len(v.passes) < v.config.CacheEntries",
        "true",
        "TestCacheCapacityAndClockRollback",
    ),
    (
        "time-after-read",
        "verify.go",
        "if err = checkUse(d, purpose, after); err != nil",
        "if err = checkUse(d, purpose, after); false && err != nil",
        "TestTimeAfterReadAtExpiration",
    ),
    (
        "size",
        "delegation.go",
        "len(b) != DelegationSize",
        "false",
        "TestFrozenVectors/trailing",
    ),
    (
        "production-gate",
        "verify.go",
        "c.Mode != TestNetworkLegacyEpochZero && c.Mode != TestNetworkEpochAware",
        "false",
        "TestProductionAndLegacyModes",
    ),
    (
        "builder",
        "verify.go",
        "if err = v.checkSnapshot(d, sha256.Sum256(b), s, false); err != nil",
        "if err = v.checkSnapshot(d, sha256.Sum256(b), s, false); false && err != nil",
        "TestBuilderRequiresCurrentEpochAndPolicy",
    ),
    (
        "domain",
        "delegation.go",
        "!bytes.Equal(b[:len(delegationDomain)], []byte(delegationDomain))",
        "false",
        "TestFrozenVectors/wrong-domain",
    ),
    (
        "key-canonical",
        "delegation.go",
        "!bytes.Equal(p.Bytes(), d.TransportKey[:])",
        "false",
        "TestFrozenVectors/noncanonical-key",
    ),
    (
        "key-order",
        "delegation.go",
        "new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1",
        "false",
        "TestFrozenVectors/identity-key",
    ),
    (
        "purpose-bits",
        "delegation.go",
        "d.Purposes == 0 || d.Purposes & ^Purpose(7) != 0",
        "false",
        "TestFrozenVectors/unknown-purpose",
    ),
    (
        "lifetime",
        "delegation.go",
        "d.NotBefore == 0 || d.NotAfter <= d.NotBefore || d.NotAfter-d.NotBefore > MaxDelegationSeconds",
        "false",
        "TestFrozenVectors/excessive-lifetime",
    ),
    (
        "credential-limit",
        "delegation.go",
        "d.MaxCredentialSeconds == 0 || d.MaxCredentialSeconds > MaxCredentialSeconds",
        "false",
        "TestFrozenVectors/excessive-credential",
    ),
    (
        "network",
        "chain.go",
        "state.Network.NetworkId != network.NetworkId",
        "false",
        "TestVerificationChecks/network",
    ),
    (
        "finality",
        "chain.go",
        "reference.FinalizedCheckpoint == 0",
        "false",
        "TestVerificationChecks/finality",
    ),
    (
        "minimum-checkpoint",
        "chain.go",
        "reference.FinalizedCheckpoint < policy.MinFinalizedCheckpoint",
        "false",
        "TestVerificationChecks/stale-checkpoint",
    ),
    (
        "registry",
        "chain.go",
        "!policy.AcceptsRegistry(reference.ContractCodeHash)",
        "false",
        "TestVerificationChecks/registry-code",
    ),
    (
        "account",
        "chain.go",
        "expected != reference.Account",
        "false && expected != reference.Account",
        "TestVerificationChecks/account",
    ),
    (
        "tombstone",
        "chain.go",
        "agent.Tombstoned || agent.Policy == nil",
        "agent.Policy == nil",
        "TestVerificationChecks/tombstone",
    ),
    (
        "agent",
        "chain.go",
        "agent.AgentId != agentID",
        "false",
        "TestVerificationChecks/agent",
    ),
    (
        "state-hash",
        "chain.go",
        "!chainDigestPattern.MatchString(state.TvmStateHash)",
        "false",
        "TestVerificationChecks/typed-state-hash",
    ),
    (
        "transaction-hash",
        "chain.go",
        "!chainDigestPattern.MatchString(reference.TransactionHash)",
        "false",
        "TestVerificationChecks/transaction-hash",
    ),
    (
        "membership",
        "verify.go",
        'if !found {\n\t\t\treturn errors.New("delegation is not in the finalized live set")',
        'if false && !found {\n\t\t\treturn errors.New("delegation is not in the finalized live set")',
        "TestVerificationChecks/membership",
    ),
    (
        "current-epoch",
        "verify.go",
        "d.AuthorizationEpoch != *s.CurrentEpoch",
        "false",
        "TestVerificationChecks/current-epoch",
    ),
    (
        "admission-epoch",
        "verify.go",
        "epoch != d.AuthorizationEpoch",
        "false && epoch != d.AuthorizationEpoch",
        "TestVerificationChecks/admission-epoch",
    ),
    (
        "admission-present",
        "verify.go",
        "!present || epoch != d.AuthorizationEpoch",
        "epoch != d.AuthorizationEpoch && present",
        "TestVerificationChecks/missing-admission",
    ),
    (
        "epoch-checkpoint",
        "verify.go",
        "s.State.Reference.FinalizedCheckpoint != s.EpochCheckpoint",
        "false",
        "TestVerificationChecks/mixed-checkpoints",
    ),
    (
        "policy",
        "verify.go",
        "!bytes.Equal(policy.Hash(), d.PolicyHash[:])",
        "false && !bytes.Equal(policy.Hash(), d.PolicyHash[:])",
        "TestVerificationChecks/policy",
    ),
    (
        "not-before",
        "verify.go",
        "(d.NotBefore > seconds && d.NotBefore-seconds > 300)",
        "false",
        "TestVerificationChecks/not-before",
    ),
    (
        "not-after",
        "verify.go",
        "seconds >= d.NotAfter",
        "false",
        "TestVerificationChecks/expired",
    ),
    (
        "purpose-use",
        "verify.go",
        "d.Purposes&purpose == 0",
        "false",
        "TestVerificationChecks/purpose",
    ),
    (
        "purpose-known",
        "verify.go",
        "purpose != Relay && purpose != Hints && purpose != Direct",
        "false",
        "TestVerificationChecks/unknown-purpose",
    ),
    (
        "refresh",
        "verify.go",
        "now.Sub(checked) < RefreshAfter",
        "now.Sub(checked) <= RefreshAfter",
        "TestCacheBounds",
    ),
    (
        "stale-refusal",
        "verify.go",
        "after.Sub(checked) < RefuseAfter",
        "after.Sub(checked) <= RefuseAfter",
        "TestCacheBounds",
    ),
    (
        "integrity-fallback",
        "verify.go",
        "!errors.Is(readErr, ErrUnavailable)",
        "false",
        "TestFallbackNeverHidesRevocationOrIntegrity",
    ),
]


def execute(args):
    result = subprocess.run(
        args,
        check=False,
        cwd=ROOT,
        env={**os.environ, "GOWORK": "off", "GOFLAGS": "-p=2"},
        capture_output=True,
        text=True,
        timeout=180,
    )
    return result.returncode, result.stdout + result.stderr


def main():
    code, output = execute(["go", "test", "-count=1", PACKAGE])
    if code:
        raise RuntimeError("baseline failed\n" + output)
    for name, filename, old, new, test in MUTANTS:
        source = ROOT / "protocol/pkg/agenttransport" / filename
        original = source.read_text()
        if original.count(old) != 1:
            raise RuntimeError("non-unique anchor: " + name)
        with tempfile.TemporaryDirectory(prefix="agenttransport-mutant-") as tmp:
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
        # Subtests indent their marker; require the exact named failure, never
        # a compiler error, timeout, missing test or unrelated failing test.
        if code == 0 or "--- FAIL: " + test not in output or "[build failed]" in output:
            raise RuntimeError(
                "mutant did not fail its named test: " + name + "\n" + output
            )
        print("RED " + name + ": " + test, flush=True)
    print(f"AGENTTRANSPORT_MUTANTS_OK: {len(MUTANTS)} checks removed and caught")


if __name__ == "__main__":
    main()
