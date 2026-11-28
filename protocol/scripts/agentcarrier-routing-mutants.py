#!/usr/bin/env python3
"""Semantic carrier refusal/order controls; compile failure is not a kill."""

import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "./protocol/pkg/agentcarrier"
CONTROLS = []


def add(name, file, old, new, test):
    CONTROLS.append((name, file, old, new, test))


add(
    "two-directories",
    "resolution.go",
    "len(c.Directories) < 2",
    "false",
    "TestResolverRequiresTwoDirectoriesAndProductionRelays",
)
add(
    "production-relays",
    "resolution.go",
    "!r.config.TestSingleRelay && len(hint.Record.Hint.Relays) < 2",
    "false",
    "TestResolverRequiresTwoDirectoriesAndProductionRelays",
)
add(
    "resolution-commit-freshness",
    "resolution.go",
    "!now.Before(hint.FreshUntil)",
    "(false && !now.Before(hint.FreshUntil))",
    "TestResolutionCarriesFreshnessThroughCardVerification",
)
add(
    "both-directory-indexes",
    "resolution.go",
    "fetch(r.config.Directories)",
    "fetch(r.config.Directories[:1])",
    "TestResolutionUsesVerifiedCacheThenContactThenBothDirectories",
)
add(
    "routing-state-identity",
    "routing_store.go",
    "i.Identity != s.identity",
    "false",
    "TestRoutingInventoryRefusesMissingUsedRecordAndMixedIdentity",
)
add(
    "routing-record-hole",
    "routing_store.go",
    "len(expected) != 0",
    "false",
    "TestRoutingInventoryRefusesMissingUsedRecordAndMixedIdentity",
)


add(
    "contact-admission",
    "credential_manager.go",
    "if e = m.admitted(ctx, peer); e != nil {",
    "if e = error(nil); e != nil {",
    "TestContactIssueRequiresAdmissionAndRenewsTheSameLane",
)
add(
    "owner-lifetime",
    "credential_manager.go",
    "duration = 3600",
    "duration = 7200",
    "TestOwnerCredentialRefreshAndPrivateCustody",
)
add(
    "owner-credential-journal",
    "credential_manager.go",
    "if e = m.store.write(name, record); e != nil {",
    "if e = error(nil); e != nil {",
    "TestOwnerCredentialRefreshAndPrivateCustody",
)
add(
    "contact-import-admission",
    "credential_manager.go",
    "if e = m.admitted(ctx, p.SenderAgentID); e != nil {",
    "if e = error(nil); e != nil {",
    "TestContactImportVerifiesPacketIssuerAdmissionAndRoute",
)
add(
    "contact-import-packet",
    "credential_manager.go",
    "if e = m.config.VerifyPacket(ctx, p); e != nil {",
    "if e = error(nil); e != nil {",
    "TestContactImportVerifiesPacketIssuerAdmissionAndRoute",
)
add(
    "contact-import-issuer",
    "credential_manager.go",
    "d.AgentID() != p.SenderAgentID",
    "(false && d.AgentID() != p.SenderAgentID)",
    "TestContactImportVerifiesPacketIssuerAdmissionAndRoute",
)
add(
    "contact-relay-attenuation",
    "credential_manager.go",
    "[]agenttransport.Caveat{agenttransport.RelayCaveat(relay)}",
    "[]agenttransport.Caveat{}",
    "TestContactImportVerifiesPacketIssuerAdmissionAndRoute",
)
add(
    "contact-half-life",
    "credential_manager.go",
    "threshold := (previous.Until - previous.Issued) / 2",
    "threshold := uint64(0)",
    "TestContactIssueRequiresAdmissionAndRenewsTheSameLane",
)
add(
    "two-copy-stop",
    "scheduler.go",
    "copies(r) >= 2",
    "copies(r) >= 4",
    "TestTwoCopiesStopBeforeAThirdRelayAndJournalBeforeTransport",
)
add(
    "generation-force-resolution",
    "scheduler.go",
    "forced := generationDue && m.ResolvedGeneration != m.NextGeneration",
    "forced := false",
    "TestNoRouteBackoffAndDueGenerationAreDurable",
)
add(
    "no-route-abandonment",
    "scheduler.go",
    'r.State = "abandoned"',
    "// leave pending",
    "TestNoRouteBackoffAndDueGenerationAreDurable",
)
add(
    "generation-counter",
    "outbox.go",
    "number := r.GenerationCounter",
    "var number uint32",
    "TestGenerationWithdrawalAndCounterSurviveManyDeposits",
)
add(
    "hint-half-life",
    "publication.go",
    "(h.Hint.ExpiresAt-h.Hint.IssuedAt)/2",
    "(h.Hint.ExpiresAt-h.Hint.IssuedAt)",
    "TestPublicationIsJournalledAndReducedBeforeAnyRelaySeesIt",
)

manager = (ROOT / "protocol/pkg/agentcarrier/credential_manager.go").read_text()
start = manager.index("func (m *CredentialManager) authority(")
end = manager.index("\nfunc ", start + 1)
authority = manager[start:end]
add(
    "credential-issuance-authority",
    "credential_manager.go",
    authority,
    authority.replace(
        "d, until, e := m.config.Verifier.VerifyDelegationUntil(ctx, m.config.Delegation, agenttransport.Relay)",
        "d,e:=agenttransport.DecodeDelegation(m.config.Delegation);until:=m.config.Now().Add(agenttransport.RefuseAfter)",
    ),
    "TestCredentialIssuerRefusesWrongKeyAndRevokedAuthority",
)

source = (ROOT / "protocol/pkg/agentcarrier/publication.go").read_text()
start = source.index("\tif !reuse {")
end = source.index("\n\ttargets :=", start)
block = source[start:end]
add(
    "publication-before-network",
    "publication.go",
    block,
    block.replace(
        'if e = p.store.write(routingName("current"), current); e != nil {',
        "if e = error(nil); e != nil {",
    ),
    "TestPublicationIsJournalledAndReducedBeforeAnyRelaySeesIt",
)

source = (ROOT / "protocol/pkg/agentcarrier/scheduler.go").read_text()
start = source.index("\t\tretry.After =")
end = source.index("\n\t\tresult, err :=", start)
block = source[start:end]
add(
    "retry-before-network",
    "scheduler.go",
    block,
    block.replace("if e = s.save(m); e != nil {", "if e = error(nil); e != nil {"),
    "TestTwoCopiesStopBeforeAThirdRelayAndJournalBeforeTransport",
)


def execute(arguments):
    result = subprocess.run(
        arguments,
        cwd=ROOT,
        env={**os.environ, "GOWORK": "off"},
        capture_output=True,
        text=True,
        errors="replace",
        timeout=180,
        check=False,
    )
    return result.returncode, result.stdout + result.stderr


def main():
    code, output = execute(["go", "test", "-count=1", PACKAGE])
    if code:
        raise RuntimeError("baseline failed\n" + output)
    for name, file, old, new, test in CONTROLS:
        source = ROOT / "protocol/pkg/agentcarrier" / file
        text = source.read_text()
        if text.count(old) != 1:
            raise RuntimeError("nonunique anchor: " + name)
        changed = text.replace(old, new)
        if name == "hint-relays-only":
            changed += "\nfunc chosenUnusedRelays(raw []byte)[]string {p,e:=agentpacket.DecodeJSON(raw);if e!=nil{return nil};c,e:=agentpacketseal.DecodeKeyCard(p.Payload);if e!=nil{return nil};return c.Relays}\n"
        with tempfile.TemporaryDirectory(prefix="carrier-mutant-") as temp:
            replacement = Path(temp) / source.name
            replacement.write_text(changed)
            overlay = Path(temp) / "overlay.json"
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
        if (
            code == 0
            or "--- FAIL: " + test.split("/")[0] not in output
            or "[build failed]" in output
        ):
            raise RuntimeError(
                "control did not fail its named test: " + name + "\n" + output
            )
        print("RED " + name + ": " + test, flush=True)
    print(f"AGENTCARRIER_MUTANTS_OK: {len(CONTROLS)} controls")


if __name__ == "__main__":
    main()
