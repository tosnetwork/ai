#!/usr/bin/env python3
"""Red controls for the security checks of the MCP buyer agent.

Each mutant removes or weakens one check of protocol/pkg/buyeragent or of
the buyersdk journal it relies on: archive and input re-validation, the
confirmation code and its lifetime, the peer-credential role table, the
deployment checks and the prepared-call cap. A mutant is applied through
`go test -overlay`, so the working tree is never modified.

A mutant is caught only when its named test reports `--- FAIL: <test>`.
A mutant whose text does not occur exactly once, or that does not build, is
a script error, not a catch. The unmutated packages must pass first.

Usage (from the repository root):

    python3 -I protocol/scripts/buyeragent-mutants.py [--only NAME]

Checks with no mutant here are redundant with another check, so removing
one alone changes no outcome:

- the parse-time header checks the canonical comparison also enforces. A
  header or archive that breaks one of them can never equal the canonical
  encoding of its parsed members, so it is refused by the comparison as
  well; the parse checks stay for their specific errors. They are:
  - the USTAR magic and version;
  - the checksum;
  - bytes after a field's terminator;
  - the link name;
  - the type flag;
  - a directory's size;
  - a repeated name (the packer refuses it too);
  - non-zero bytes after the end marker;
  - the second end-marker block;
- the member-count bound of CheckSourceArchive: every member takes at least
  one 512-byte block, so the 1 MiB size bound already allows at most 2,046
  members, below the 4,096 bound;
- the octal digit check: a non-octal size or checksum field also fails
  strconv.ParseInt;
- the member-overrun check: a member that runs past the end leaves no room
  for the end-of-archive marker, which the next loop step refuses;
- the no-presentation check in Decide: a purchase never presented has a
  presentation time of zero, which the code-lifetime check refuses with the
  same conflict;
- the 2 MiB request-line check of the socket: every field a request can
  carry is bounded below it, so an over-long line is refused by those
  bounds, or as a line without a newline once the bounded reader stops; the
  check only bounds the memory a read takes.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AGENT = "protocol/pkg/buyeragent/"
SDK = "protocol/pkg/buyersdk/"

# (name, file from the repository root, original text, mutated text, test
# that must fail). The test runs in the mutated file's package.
MUTANTS = [
    # Archive rules (section 4.5).
    ("member-charset", AGENT + "archive.go",
     "len(name) > MaxMemberNameBytes || !memberNamePattern.MatchString(name)",
     "len(name) > MaxMemberNameBytes",
     "TestArchiveMemberNamesOutsideTheSafeCharsetAreRefused"),
    ("member-length", AGENT + "archive.go",
     "len(name) == 0 || len(name) > MaxMemberNameBytes ||",
     "len(name) == 0 || len(name) > 4096 ||",
     "TestArchiveMemberNamesOutsideTheSafeCharsetAreRefused"),
    ("member-dot-segments", AGENT + "archive.go",
     'if segment == "." || segment == ".." {',
     "if false {",
     "TestArchiveMemberNamesOutsideTheSafeCharsetAreRefused"),
    ("member-file-trailing-slash", AGENT + "archive.go",
     'if strings.HasSuffix(name, "/") && !directory {',
     "if false {",
     "TestArchiveMemberNamesOutsideTheSafeCharsetAreRefused"),
    ("no-regular-file", AGENT + "archive.go",
     "if regular == 0 {",
     "if false {",
     "TestArchiveDuplicatesCountAndSizeAreBounded"),
    ("archive-size-bound", AGENT + "archive.go",
     "if len(raw) == 0 || len(raw) > maxBytes {",
     "if len(raw) == 0 || len(raw) > maxBytes+1 {",
     "TestArchiveDuplicatesCountAndSizeAreBounded"),

    # Canonical bytes: one comparison closes every hidden channel, and each
    # channel class has its own test that the comparison's removal fails.
    ("canonical-padding", AGENT + "archive.go",
     "if !bytes.Equal(canonical, raw) {", "if !bytes.Equal(canonical, raw) && false {", "TestArchivePaddingBytesAreRefused"),
    ("canonical-owner-names", AGENT + "archive.go",
     "if !bytes.Equal(canonical, raw) {", "if !bytes.Equal(canonical, raw) && false {", "TestArchiveOwnerNamesAreRefused"),
    ("canonical-modes", AGENT + "archive.go",
     "if !bytes.Equal(canonical, raw) {", "if !bytes.Equal(canonical, raw) && false {", "TestArchiveModesAreRefused"),
    ("canonical-times-ids-devices", AGENT + "archive.go",
     "if !bytes.Equal(canonical, raw) {", "if !bytes.Equal(canonical, raw) && false {", "TestArchiveTimesIDsAndDevicesAreRefused"),
    ("canonical-header-tail", AGENT + "archive.go",
     "if !bytes.Equal(canonical, raw) {", "if !bytes.Equal(canonical, raw) && false {", "TestArchiveHeaderTailIsRefused"),
    ("canonical-trailing-blocks", AGENT + "archive.go",
     "if !bytes.Equal(canonical, raw) {", "if !bytes.Equal(canonical, raw) && false {", "TestArchiveTrailingZeroBlocksAreRefused"),
    ("canonical-order-and-names", AGENT + "archive.go",
     "if !bytes.Equal(canonical, raw) {", "if !bytes.Equal(canonical, raw) && false {", "TestArchiveMemberOrderAndNamesMustBeCanonical"),
    ("canonical-reproduced-case", AGENT + "archive.go",
     "if !bytes.Equal(canonical, raw) {", "if !bytes.Equal(canonical, raw) && false {", "TestArchiveHiddenChannelsTogetherAreRefused"),
    ("canonical-packer-sorts", AGENT + "canonical.go",
     "sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })",
     "_ = sort.Slice",
     "TestPackSourceArchiveIsDeterministicAndReadable"),
    ("canonical-packer-pads", AGENT + "canonical.go",
     "\t\tout = append(out, make([]byte, paddedLength(len(entry.Content))-len(entry.Content))...)\n",
     "\n",
     "TestASafeArchiveIsAcceptedWithItsMembers"),

    # Re-validation of client input (section 2.3).
    ("prepare-quote-id", AGENT + "agent.go",
     "if !hex64Pattern.MatchString(p.QuoteID) {",
     "if false {",
     "TestPrepareRevalidatesEveryClientField"),
    ("prepare-idempotency-key", AGENT + "agent.go",
     "if !idempotencyKeyPattern.MatchString(p.IdempotencyKey) {",
     "if false {",
     "TestPrepareRevalidatesEveryClientField"),
    ("prepare-canonical-base64", AGENT + "agent.go",
     "if err != nil || base64.StdEncoding.EncodeToString(raw) != p.ArchiveBase64 {",
     "if err != nil {",
     "TestPrepareRevalidatesEveryClientField"),
    ("prepare-archive-recheck", AGENT + "agent.go",
     'if err != nil {\n\t\treturn PurchaseView{}, refusal(CodeBadInput, "the source archive breaks the archive rules", err)',
     'if false {\n\t\treturn PurchaseView{}, refusal(CodeBadInput, "the source archive breaks the archive rules", err)',
     "TestPrepareRevalidatesEveryClientField"),
    ("prepare-key-binding", AGENT + "agent.go",
     "if found && (key.QuoteID != params.QuoteID || key.SourceDigest != sourceDigest) {",
     "if false {",
     "TestPrepareIsIdempotentPerKeyAndRefusesAReusedKey"),
    ("prepare-carriage", AGENT + "agent.go",
     "if carriageErr := a.config.Carriage.CheckCarriage(ctx, record, archive); carriageErr != nil {",
     "if carriageErr := error(nil); carriageErr != nil {",
     "TestAnUncarriablePurchaseIsWithdrawnAndNeverPaid"),

    # Confirmation (section 5.3).
    ("code-compare", AGENT + "confirm.go",
     "return subtle.ConstantTimeCompare([]byte(want), []byte(normalized)) == 1",
     "return subtle.ConstantTimeCompare([]byte(want), []byte(normalized)) >= 0",
     "TestDecideRecomputesTheCodeAndPaysAtMostOnce"),
    ("code-binds-nonce", AGENT + "confirm.go",
     "\thash.Write(nonce[:])\n",
     "\n",
     "TestACodeFromAnotherNonceConfirmsNothing"),
    ("code-binds-fields", AGENT + "confirm.go",
     "\t\thash.Write([]byte(value))\n",
     "\t\t_ = value\n",
     "TestConfirmationCodeBindsTheNonceAndEveryField"),
    ("code-failure-lockout", AGENT + "agent.go",
     "if purchase.CodeFailures >= MaxCodeFailures {",
     "if false {",
     "TestThreeWrongCodesWithdrawThePurchase"),
    ("code-expiry", AGENT + "agent.go",
     'if !now.Before(time.Unix(purchase.PresentedUnix, 0).Add(ConfirmationLifetime)) {\n\t\tpurchase.ConfirmationNonce',
     'if false && !now.Before(time.Unix(purchase.PresentedUnix, 0).Add(ConfirmationLifetime)) {\n\t\tpurchase.ConfirmationNonce',
     "TestAnExpiredCodeAndAMissingPresentationConfirmNothing"),
    ("code-spent-before-send", AGENT + "agent.go",
     '\tpurchase.ConfirmationNonce, purchase.PresentedUnix = "", 0\n\tif err := a.store.writePurchase(purchase); err != nil {\n\t\ta.mutex.Unlock()',
     '\tif err := a.store.writePurchase(purchase); err != nil {\n\t\ta.mutex.Unlock()',
     "TestASpentCodeCannotConfirmARetry"),
    ("present-needs-request", AGENT + "agent.go",
     "if record.Phase != buyersdk.PhasePrepared || purchase.RequestedUnix == 0 {\n\t\treturn Presentation{}",
     "if record.Phase != buyersdk.PhasePrepared {\n\t\treturn Presentation{}",
     "TestOnlyTheConfirmerFetchDrawsTheNonce"),
    ("present-keeps-valid-nonce", AGENT + "agent.go",
     'if purchase.ConfirmationNonce == "" || !now.Before(',
     "if true || !now.Before(",
     "TestOnlyTheConfirmerFetchDrawsTheNonce"),
    ("client-view-leaks-nonce", AGENT + "agent.go",
     "SourceDigest: purchase.SourceDigest, ArchiveBytes: purchase.ArchiveBytes,",
     "SourceDigest: purchase.ConfirmationNonce, ArchiveBytes: purchase.ArchiveBytes,",
     "TestClientViewsNeverCarryTheCode"),
    ("send-carriage", AGENT + "agent.go",
     "if err := a.config.Carriage.CheckCarriage(ctx, record, archive); err != nil {",
     "if err := error(nil); err != nil {",
     "TestCarriageIsRecheckedBeforeTheSend"),
    ("send-archive-digest", AGENT + "agent.go",
     'if sum := sha256.Sum256(archive); "sha256:"+hex.EncodeToString(sum[:]) != purchase.SourceDigest {',
     "if false {",
     "TestATamperedArchiveCopyIsNeverSent"),

    # Agent start-up (sections 2.3, 6).
    ("open-private-state", AGENT + "agent.go",
     "if err := checkPrivateDir(config.StateDir); err != nil {\n\t\treturn nil, err\n\t}\n\tlimits",
     "\tlimits",
     "TestOpenRefusesUnsafeStateAndASecondAgent"),
    ("open-prepared-cap", AGENT + "agent.go",
     "if !limits.Valid() || limits.MaxPrepared == 0 {",
     "if !limits.Valid() {",
     "TestOpenRefusesUnsafeStateAndASecondAgent"),
    ("open-single-instance", AGENT + "agent.go",
     "if !acquired {",
     "if !acquired && false {",
     "TestOpenRefusesUnsafeStateAndASecondAgent"),

    # Socket roles and deployment (section 2.3).
    ("role-present", AGENT + "server.go",
     '"present":         {RoleCustody: true},',
     '"present":         {RoleCustody: true, RoleClient: true},',
     "TestSocketRolesComeFromPeerCredentials"),
    ("role-decide", AGENT + "server.go",
     '"decide":          {RoleCustody: true},',
     '"decide":          {RoleCustody: true, RoleClient: true},',
     "TestSocketRolesComeFromPeerCredentials"),
    ("role-equal-uids", AGENT + "server.go",
     "case custodyUID == clientUID:",
     "case false:",
     "TestTheRoleTableKeepsDecisionsWithTheCustodyAccount"),
    ("role-unknown-peer", AGENT + "server.go",
     "\tcase RoleNone:\n\t\treturn RoleNone, nil, false\n",
     "\tcase RoleNone:\n\t\tpool = s.client\n",
     "TestAnUnknownPeerIsRefusedBeforeItsRequestIsRead"),
    ("custody-pool-reserved", AGENT + "server.go",
     "\tcase RoleCustody:\n\t\tpool = s.custody\n",
     "\tcase RoleCustody:\n\t\tpool = s.client\n",
     "TestAClientCannotTakeTheConfirmersConnections"),
    ("code-failures-literal", AGENT + "confirm.go",
     "MaxCodeFailures = 3",
     "MaxCodeFailures = 4",
     "TestThreeWrongCodesWithdrawThePurchase"),
    ("code-lifetime-literal", AGENT + "confirm.go",
     "ConfirmationLifetime = 10 * time.Minute",
     "ConfirmationLifetime = 20 * time.Minute",
     "TestAnExpiredCodeAndAMissingPresentationConfirmNothing"),
    ("role-check", AGENT + "server.go",
     "if !Allowed(role, request.Method) {",
     "if false {",
     "TestSocketRolesComeFromPeerCredentials"),
    ("listen-distinct-uids", AGENT + "server.go",
     "if config.ClientUID == 0 || config.ClientUID == custody {",
     "if config.ClientUID == 0 {",
     "TestListenRefusesUnsafeDeployments"),
    ("listen-socket-dir-mode", AGENT + "server.go",
     "if !info.IsDir() || !osguard.CurrentUserOwns(info) || info.Mode().Perm()&0o027 != 0 {",
     "if !info.IsDir() || !osguard.CurrentUserOwns(info) {",
     "TestListenRefusesUnsafeDeployments"),
    ("listen-socket-outside-state", AGENT + "server.go",
     'if relative != ".." && !strings.HasPrefix(relative, "../") {',
     'if relative != ".." && !strings.HasPrefix(relative, "../") && false {',
     "TestListenRefusesUnsafeDeployments"),
    ("listen-socket-path-kind", AGENT + "server.go",
     "if info.Mode()&os.ModeSocket == 0 || !osguard.CurrentUserOwns(info) {",
     "if (info.Mode()&os.ModeSocket == 0 || !osguard.CurrentUserOwns(info)) && false {",
     "TestListenRefusesUnsafeDeployments"),
    ("listen-socket-mode", AGENT + "server.go",
     "if err := os.Chmod(path, 0o660); err != nil {",
     "if err := os.Chmod(path, 0o666); err != nil {",
     "TestListenRefusesUnsafeDeployments"),
    ("strict-envelope", AGENT + "server.go",
     "if err := jsonstrict.Decode(raw, &request); err != nil {",
     "if err := json.Unmarshal(raw, &request); err != nil {",
     "TestTheSocketDecodesRequestsStrictly"),
    ("strict-params", AGENT + "server.go",
     "if err := jsonstrict.Decode(raw, value); err != nil {",
     "if err := json.Unmarshal(raw, value); err != nil {",
     "TestTheSocketDecodesRequestsStrictly"),
    ("envelope-schema", AGENT + "server.go",
     "if request.Schema != APISchema {",
     "if false {",
     "TestTheSocketDecodesRequestsStrictly"),

    # Journal (buyersdk).
    ("journal-prepared-cap", SDK + "service_actor_journal.go",
     "if limits.MaxPrepared > 0 && waitingPrepared(records, now) >= limits.MaxPrepared {",
     "if false {",
     "TestPreparedCallsAreCappedSeparately"),
    ("journal-withdrawn-reserves", SDK + "service_actor_journal.go",
     "case PhaseRefused, PhaseWithdrawn:",
     "case PhaseRefused:",
     "TestWithdrawnCallsAreNeverSentAndHoldNoReservation"),
    ("journal-withdraw-only-prepared", SDK + "service_actor_journal.go",
     "return j.Transition(requestHash, []CallPhase{PhasePrepared}, func(r *CallRecord) error {\n\t\tr.Phase, r.UpdatedUnix = PhaseWithdrawn",
     "return j.Transition(requestHash, []CallPhase{PhasePrepared, PhaseSubmitted}, func(r *CallRecord) error {\n\t\tr.Phase, r.UpdatedUnix = PhaseWithdrawn",
     "TestWithdrawnCallsAreNeverSentAndHoldNoReservation"),
    ("limits-prepared-cap-bound", SDK + "service_actor_journal.go",
     "l.MaxPrepared >= 0 && l.MaxPrepared <= l.MaxCalls",
     "l.MaxPrepared >= 0",
     "TestLimitsRefuseAPreparedCapAboveTheCallCap"),
]


def go_env():
    env = dict(os.environ)
    env.setdefault("GOWORK", "off")
    env.setdefault("GOFLAGS", "-p=8")
    return env


def run(arguments, env):
    return subprocess.run(arguments, cwd=ROOT, env=env, capture_output=True, text=True, check=False)


def package_of(file_name):
    return "./" + str(Path(file_name).parent)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", action="append", default=[], help="run only the named mutants")
    options = parser.parse_args()
    env = go_env()
    names = [mutant[0] for mutant in MUTANTS]
    if len(names) != len(set(names)):
        print("script error: duplicate mutant names", file=sys.stderr)
        return 2
    unknown = set(options.only) - set(names)
    if unknown:
        print(f"script error: unknown mutants {sorted(unknown)}", file=sys.stderr)
        return 2
    selected = [m for m in MUTANTS if not options.only or m[0] in options.only]

    packages = sorted({package_of(file_name) for _, file_name, _, _, _ in selected})
    tests = {}
    for package in packages:
        baseline = run(["go", "test", "-count=1", package], env)
        if baseline.returncode != 0:
            print(f"script error: the unmutated package {package} does not pass\n" + baseline.stdout + baseline.stderr,
                  file=sys.stderr)
            return 2
        tests[package] = set(run(["go", "test", "-list", ".", package], env).stdout.split())
    survivors, errors = [], []
    with tempfile.TemporaryDirectory(prefix="buyeragent-mutants-") as scratch:
        for name, file_name, original, mutated, test in selected:
            package = package_of(file_name)
            if test not in tests[package]:
                errors.append(f"{name}: no test named {test} in {package}")
                continue
            source = ROOT / file_name
            text = source.read_text()
            if text.count(original) != 1:
                errors.append(f"{name}: the original text occurs {text.count(original)} times in {file_name}")
                continue
            target = Path(scratch) / f"{name}-{source.name}"
            target.write_text(text.replace(original, mutated))
            overlay = Path(scratch) / f"{name}.json"
            overlay.write_text(json.dumps({"Replace": {str(source): str(target)}}))
            build = run(["go", "test", "-c", "-o", os.devnull, f"-overlay={overlay}", package], env)
            if build.returncode != 0:
                errors.append(f"{name}: the mutant does not build:\n{build.stdout}{build.stderr}")
                continue
            result = run(["go", "test", "-count=1", f"-overlay={overlay}", "-run", f"^{test}$", package], env)
            caught = result.returncode != 0 and f"--- FAIL: {test} " in result.stdout
            print(f"{'caught' if caught else 'SURVIVED'}  {name}  ({test})", flush=True)
            if not caught:
                survivors.append(name)
    for error in errors:
        print(f"script error: {error}", file=sys.stderr)
    if errors:
        return 2
    if survivors:
        print(f"{len(survivors)} of {len(selected)} mutants survived: {', '.join(survivors)}", file=sys.stderr)
        return 1
    print(f"buyeragent mutants: all {len(selected)} caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())
