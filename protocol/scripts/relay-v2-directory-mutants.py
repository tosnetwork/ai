#!/usr/bin/env python3
"""Named semantic controls for directory, revocations and long polling."""

import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RELAY = "./protocol/pkg/agentpacketrelay"
CONTROLS = []


def add(name, file, old, new, test, package=RELAY):
    CONTROLS.append((name, file, old, new, package, test))


add(
    "revocation-time",
    "agentpacketrelay/v2_revocations.go",
    "if !validRevocationTime(entry.Until, now) {",
    "if false && !validRevocationTime(entry.Until, now) {",
    "TestV2RevocationQuotaAndDeadline",
)
add(
    "mailbox-revocations",
    "agentpacketrelay/v2_revocations.go",
    "len(updated) > 1024",
    "false",
    "TestV2RevocationQuotaAndDeadline",
)
add(
    "global-revocations",
    "agentpacketrelay/v2_revocations.go",
    "s.revocationCount-len(s.revocations[agent])+len(updated) > s.controlLimits.RevocationEntries",
    "false",
    "TestV2RevocationNeverShortensAndGlobalCountIsBounded",
)
add(
    "monotonic-revocations",
    "agentpacketrelay/v2_revocations.go",
    "max(updated[entry.Chain], entry.Until)",
    "entry.Until",
    "TestV2RevocationNeverShortensAndGlobalCountIsBounded",
)
add(
    "revocation-check-before-source",
    "agentpacketrelay/v2_http.go",
    "if err = s.store.checkRevoked(r.Context(), agent, checked, unixNow(s.now())); err != nil {",
    "if err = error(nil); err != nil {",
    "TestV2RevocationIsCheckedBeforeFinalizedRead",
)
add(
    "deposit-commit-revocation",
    "agentpacketrelay/v2_store.go",
    "if s.revokedLocked(header.RecipientAgentID, chains, in.now) {",
    "if false && s.revokedLocked(header.RecipientAgentID, chains, in.now) {",
    "TestV2RevocationCommitRechecksLocalAuthority",
)
add(
    "hint-native-authority",
    "agentpacketrelay/v2_hints.go",
    "verified, err := s.verifier.VerifyHint(ctx, raw, s.hintPolicy)",
    "record, err := agenttransport.DecodeHintRecord(raw); verified:=agenttransport.VerifiedHint{Record:record, FreshUntil:s.now().Add(agenttransport.RefuseAfter)}",
    "TestV2DirectoryRefusesUnadmittedDelegation",
)
add(
    "hint-signature",
    "agenttransport/hint.go",
    "!ed25519.Verify(record.Hint.Delegation.TransportKey[:], preimage, record.Hint.Signature[:])",
    "(false && !ed25519.Verify(record.Hint.Delegation.TransportKey[:], preimage, record.Hint.Signature[:]))",
    "TestV2DirectoryRefusesPoisonedTimeAndSignature",
)
add(
    "hint-relay-membership",
    "agentpacketrelay/v2_hints.go",
    "if !namesRelay {",
    "if false && !namesRelay {",
    "TestV2HintMustNameRelayUnlessDirectory",
)
add(
    "hint-slots",
    "agentpacketrelay/v2_hints.go",
    "len(s.store.hints[agent]) >= 4",
    "false",
    "TestV2DirectorySlotsConflictAndPersistence",
)
add(
    "directory-agents",
    "agentpacketrelay/v2_hints.go",
    "len(s.store.hints) >= s.store.controlLimits.DirectoryAgents",
    "false",
    "TestV2DirectoryDoesNotEvictLiveAgent",
)
add(
    "hint-newer-only",
    "agentpacketrelay/v2_hints.go",
    "if existing.IssuedAt > meta.IssuedAt {",
    "if false && existing.IssuedAt > meta.IssuedAt {",
    "TestV2DirectoryKeepsNewestAndFreesRevokedSlots",
)
add(
    "hint-equal-conflict",
    "agentpacketrelay/v2_hints.go",
    "if existing.Sum != meta.Sum {",
    "if false && existing.Sum != meta.Sum {",
    "TestV2DirectorySlotsConflictAndPersistence",
)
add(
    "hint-serve-authority",
    "agentpacketrelay/v2_hints.go",
    "verified, err = s.verifier.VerifyHint(ctx, record.Raw, s.hintPolicy)",
    "verified, err = agenttransport.VerifiedHint{}, nil",
    "TestV2DirectoryKeepsNewestAndFreesRevokedSlots",
)
add(
    "outage-no-eviction",
    "agentpacketrelay/v2_hints.go",
    "if expired || errors.Is(err, agenttransport.ErrDelegationRevoked) {",
    "if expired || err != nil {",
    "TestV2DirectoryReadOutageDoesNotEvictLiveSlots",
)
add(
    "hint-durable-write",
    "agentpacketrelay/v2_hints.go",
    "if err = s.store.disk.write(hintName(agent, meta.Digest), encoded); err != nil {",
    "if err = error(nil); err != nil { _ = encoded",
    "TestV2DirectorySlotsConflictAndPersistence",
)
add(
    "one-waiter",
    "agentpacketrelay/v2_wait.go",
    "if previous == nil && s.waiters[agent] != nil {",
    "if false && previous == nil && s.waiters[agent] != nil {",
    "TestV2WaitRegistryCommitNotificationAndBusyBound",
)
add(
    "bounded-waiters",
    "agentpacketrelay/v2_wait.go",
    "len(s.waiters) >= s.controlLimits.Waiters",
    "false",
    "TestV2WaitRegistrationBoundsAndRearms",
)
add(
    "commit-wake",
    "agentpacketrelay/v2_store.go",
    "s.notifyLocked(rec.Agent)",
    "// no commit notification",
    "TestV2WaitRegistryCommitNotificationAndBusyBound",
)
add(
    "wait-cleanup",
    "agentpacketrelay/v2_wait.go",
    "delete(s.waiters, agent)",
    "// leak registration",
    "TestV2WaitRegistrationBoundsAndRearms",
)
add(
    "wait-rearm",
    "agentpacketrelay/v2_wait.go",
    "case <-previous:\n\t\t\tprevious = make(chan struct{})",
    "case <-previous:\n\t\t\t// retain closed channel",
    "TestV2WaitRegistrationBoundsAndRearms",
)
add(
    "wait-minimum",
    "agentpacketrelay/v2_directory_http.go",
    "n < 1",
    "false",
    "TestV2LongPollHeadersAreStrict",
)
add(
    "wait-maximum",
    "agentpacketrelay/v2_directory_http.go",
    "n > 25",
    "false",
    "TestV2LongPollHeadersAreStrict",
)
add(
    "wait-canonical",
    "agentpacketrelay/v2_directory_http.go",
    "strconv.Itoa(n) != values[0]",
    "false",
    "TestV2LongPollHeadersAreStrict",
)
add(
    "wait-credential-expiry",
    "agentpacketrelay/v2_directory_http.go",
    "if err := checked.Credential.CheckScope(unixNow(s.now()), s.relay, agenttransport.OperationList); err != nil {",
    "if err := error(nil); err != nil {",
    "TestV2LongPollWakeTimeoutAndSingleWaiter/expiry",
)
add(
    "wait-native-withdrawal",
    "agentpacketrelay/v2_directory_http.go",
    "_, err = s.verifier.VerifyDelegation(ctx, raw, agenttransport.Relay)",
    "_ = raw; err = nil",
    "TestV2LongPollRechecksNativeWithdrawal",
)
add(
    "index-order",
    "agentpacketrelay/v2_directory_wire.go",
    "(i > 0 && bytes.Compare(entries[i-1].Digest[:], e.Digest[:]) >= 0)",
    "(false && i > 0 && bytes.Compare(entries[i-1].Digest[:], e.Digest[:]) >= 0)",
    "TestV2DirectoryCodecBounds",
)
add(
    "index-length",
    "agentpacketrelay/v2_directory_wire.go",
    "e.Length == 0 || e.Length > agenttransport.MaxHintRecordSize",
    "false && (e.Length == 0 || e.Length > agenttransport.MaxHintRecordSize)",
    "TestV2FrozenDirectoryVectors",
)
add(
    "revocation-domain",
    "agentpacketrelay/v2_directory_wire.go",
    "!bytes.HasPrefix(raw, []byte(revocationDomain))",
    "false",
    "TestV2FrozenDirectoryVectors",
)
add(
    "hint-index-domain",
    "agentpacketrelay/v2_directory_wire.go",
    "!bytes.HasPrefix(raw, []byte(hintIndexDomain))",
    "false",
    "TestV2FrozenDirectoryVectors",
)
add(
    "lookup-address-rate",
    "agentpacketrelay/v2_http.go",
    "limiter = s.lookups",
    "// use the mailbox rate",
    "TestV2DirectoryPublicLookupRateAndAgentBinding",
)
add(
    "absent-agent",
    "agenttransport/verify.go",
    "if s.State == nil {",
    "if false && s.State == nil {",
    "TestV2DirectoryDropsAbsentAndTombstonedAgents/absent",
)
add(
    "tombstoned-agent",
    "agenttransport/chain.go",
    "if agent.Tombstoned {",
    "if false && agent.Tombstoned {",
    "TestV2DirectoryDropsAbsentAndTombstonedAgents/tombstoned",
)

add(
    "description-presence",
    "agentpacketrelay/v2_directory_client.go",
    "len(fields) != 9",
    "false",
    "TestV2DescriptionRequiresEveryField",
)
add(
    "description-null",
    "agentpacketrelay/v2_directory_client.go",
    'string(value) == "null"',
    'false && string(value) == "null"',
    "TestV2DescriptionRequiresEveryField",
)

add(
    "failed-rearm-cleanup",
    "agentpacketrelay/v2_directory_http.go",
    "nextEntries, next, err := s.store.waitSnapshot(r.Context(), agent, unixNow(s.now()), ch)",
    "nextEntries, next, err := s.store.waitSnapshot(r.Context(), agent, unixNow(s.now()), ch); if err != nil { ch=nil }",
    "TestV2WaitRearmFailureStillReleasesItsRegistration",
)

for method in ["list", "get"]:
    file = ROOT / "protocol/pkg/agentpacketrelay/v2_store.go"
    text = file.read_text()
    start = text.index("func (s *V2Store) " + method + "(")
    end = text.index("\nfunc ", start + 1)
    old = text[start:end]
    guard = 's.revokedLocked("agent_"+hexAgent(agent), chains, now)'
    if old.count(guard) != 1:
        raise RuntimeError("missing atomic read guard")
    add(
        "atomic-" + method,
        "agentpacketrelay/v2_store.go",
        old,
        old.replace(guard, "false && " + guard),
        "TestV2RevocationCommitRechecksLocalAuthority",
    )


add(
    "credential-post-read-scope",
    "agentpacketrelay/v2_directory_http.go",
    "return checked.Credential.CheckScope(unixNow(s.now()), s.relay, agenttransport.OperationList)",
    "return nil",
    "TestV2LongPollCredentialExpiresDuringFinalRead",
)
add(
    "hint-commit-freshness",
    "agentpacketrelay/v2_directory_http.go",
    "if !s.now().Before(record.FreshUntil) {",
    "if false && !s.now().Before(record.FreshUntil) {",
    "TestV2HintIndexCommitRefusesEarlierStalePass",
)


add(
    "original-pass-deadline",
    "agenttransport/verify.go",
    "if cached && after.Sub(checked) < RefuseAfter {\n\t\t\treturn d, checked.Add(RefuseAfter), nil",
    "if cached && after.Sub(checked) < RefuseAfter {\n\t\t\treturn d, after.Add(RefuseAfter), nil",
    "TestVerificationDeadlineStaysAtTheOriginalRead",
    "./protocol/pkg/agenttransport",
)


def execute(args):
    result = subprocess.run(
        args,
        check=False,
        cwd=ROOT,
        env={**os.environ, "GOWORK": "off"},
        capture_output=True,
        text=True,
        errors="replace",
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
                "TestV2|TestPresence",
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
    print(f"RELAY_V2_DIRECTORY_MUTANTS_OK: {len(CONTROLS)} controls")


if __name__ == "__main__":
    main()
