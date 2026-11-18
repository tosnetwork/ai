#!/usr/bin/env python3
"""Red controls for the security checks of the MCP buyer agent.

Each mutant removes or weakens one check of protocol/pkg/buyeragent or of
the buyersdk journal it relies on: archive and input re-validation, the
confirmation code and its lifetime, the peer-credential role table, the
deployment checks and the prepared-call cap. A mutant is applied through
`go test -overlay`, so the working tree is never modified.

A mutant is caught only when its named test reports `--- FAIL: <test>`.
These are script errors, not catches:
- a failed run without that line (a panic outside the test's goroutine, a
  timeout, an init failure);
- a mutant whose text does not occur exactly once;
- a mutant that does not build.

A test whose check guards a panic therefore runs the guarded code on its own
goroutine, where a panic is reported as the test's failure. The unmutated
packages must pass first.

A check with no mutant must be redundant, and the script proves it rather
than asserting it. Each entry of REDUNDANT deletes one such check, and the
whole package's tests must still pass without a panic. A deletion that
breaks a test is a script error: the check is not redundant and needs a
mutant and a test.

Usage (from the repository root):

    python3 -I protocol/scripts/buyeragent-mutants.py [--only NAME]
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
CONFIRM = "protocol/pkg/buyerconfirm/"
MCP = "protocol/pkg/mcpbuyer/"

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
    ("member-overrun", AGENT + "archive.go",
     "if member.SizeBytes < 0 || padded > int64(len(raw)-offset) {",
     "if member.SizeBytes < 0 {",
     "TestAMemberSizePastTheEndIsRefusedWithoutAPanic"),
    ("handler-recover", AGENT + "server.go",
     "\t\tif recovered := recover(); recovered != nil {\n",
     "\t\tif recovered := any(nil); recovered != nil {\n",
     "TestTheHandlerTurnsAPanicIntoAnInternalError"),
    ("send-panic-marks-ambiguous", SDK + "service_actor_buyer.go",
     "\t\t\t_, _ = b.config.Journal.Transition(requestHash, []CallPhase{PhaseSending}, func(r *CallRecord) error {\n"
     "\t\t\t\tr.Phase, r.UpdatedUnix = PhaseAmbiguous, b.config.Now().Unix()\n\t\t\t\treturn nil\n\t\t\t})\n",
     "",
     "TestAPanicDuringTheSendLeavesTheCallAmbiguousAndResolvable"),
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
     '\tpurchase.ConfirmationNonce, purchase.PresentedUnix = "", 0\n\tif err := a.store.writePurchase(purchase); err != nil {\n\t\treturn record, purchase, PurchaseView{}, false, err\n\t}\n\treturn record, purchase, PurchaseView{}, true, nil',
     '\tif err := a.store.writePurchase(purchase); err != nil {\n\t\treturn record, purchase, PurchaseView{}, false, err\n\t}\n\treturn record, purchase, PurchaseView{}, true, nil',
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

    # The confirmer (sections 5.1 to 5.3).
    # The allowlist of section 5.2: each widening of the shown categories
    # is caught by the test of what it would let through.
    ("allow-marks", CONFIRM + "render.go",
     "return unicode.In(r, unicode.L, unicode.N, unicode.P, unicode.S)",
     "return unicode.In(r, unicode.L, unicode.N, unicode.P, unicode.S, unicode.M)",
     "TestStackedCombiningMarksAreEscaped"),
    ("allow-format", CONFIRM + "render.go",
     "return unicode.In(r, unicode.L, unicode.N, unicode.P, unicode.S)",
     "return unicode.In(r, unicode.L, unicode.N, unicode.P, unicode.S, unicode.Cf)",
     "TestInvisibleFormatAndTagCharactersAreEscaped"),
    ("allow-controls", CONFIRM + "render.go",
     "return unicode.In(r, unicode.L, unicode.N, unicode.P, unicode.S)",
     "return unicode.In(r, unicode.L, unicode.N, unicode.P, unicode.S, unicode.Cc)",
     "TestEscapeMakesControlsBidiAndInvalidBytesVisible"),
    ("allow-separators", CONFIRM + "render.go",
     "return unicode.In(r, unicode.L, unicode.N, unicode.P, unicode.S)",
     "return unicode.In(r, unicode.L, unicode.N, unicode.P, unicode.S, unicode.Zl, unicode.Zp)",
     "TestEscapeMakesControlsBidiAndInvalidBytesVisible"),
    ("allow-private-and-unassigned", CONFIRM + "render.go",
     "return unicode.In(r, unicode.L, unicode.N, unicode.P, unicode.S)",
     "return !unicode.In(r, unicode.M, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Zs) || "
     "unicode.In(r, unicode.L, unicode.N, unicode.P, unicode.S)",
     "TestNoProviderRowEverExceedsTheWidth"),
    ("allow-space", CONFIRM + "render.go",
     "\tif r == ' ' {\n\t\treturn true\n\t}\n\tif (r >= 0xfe00",
     "\tif (r >= 0xfe00",
     "TestEscapeMakesControlsBidiAndInvalidBytesVisible"),
    ("nfc-first", CONFIRM + "render.go",
     "\ts = norm.NFC.String(s)\n",
     "\t_ = norm.NFC\n",
     "TestTextIsComposedBeforeTheAllowlist"),
    ("escape-bound", CONFIRM + "render.go",
     "if count == limit {",
     "if count == limit && false {",
     "TestEscapeBoundsEachString"),
    ("provider-block-bound", CONFIRM + "render.go",
     "budget -= utf8.RuneCountInString(value)",
     "budget -= 0 * utf8.RuneCountInString(value)",
     "TestTheProviderBlockIsBoundedAsAWhole"),
    ("provider-text-escaped", CONFIRM + "render.go",
     'providerRows(item.label + ": " + Escape(value, limit))',
     'providerRows(item.label + ": " + value + Escape("", limit))',
     "TestRenderKeepsProviderTextBeforeAndApartFromTheProtocolFields"),
    ("provider-spaces-collapsed", CONFIRM + "render.go",
     "value := collapseSpaces(item.value)",
     "value := item.value",
     "TestProviderTextIsWrappedBehindAGutter"),
    ("provider-hard-wrap", CONFIRM + "render.go",
     "if columns+w > ProviderWrapWidth {",
     "if columns+w > ProviderWrapWidth && false {",
     "TestProviderTextIsWrappedBehindAGutter"),
    ("provider-gutter", CONFIRM + "render.go",
     "return append(rows, ProviderGutter+row.String())",
     "return append(rows, row.String())",
     "TestProviderTextIsWrappedBehindAGutter"),
    ("provider-gutter-left-to-right", CONFIRM + "render.go",
     'ProviderGutter = "p| "',
     'ProviderGutter = "| "',
     "TestEveryProviderRowStartsWithAStrongLeftToRightLetter"),
    ("provider-continuation-gutter", CONFIRM + "render.go",
     "\t\t\trows = append(rows, ProviderGutter+row.String())",
     '\t\t\trows = append(rows, "| "+row.String())',
     "TestEveryProviderRowStartsWithAStrongLeftToRightLetter"),
    ("provider-width-by-columns", CONFIRM + "render.go",
     "w := displayWidth(r)",
     "w := 1 + 0*displayWidth(r)",
     "TestWideTextIsCountedTwoColumns"),
    ("provider-non-ascii-counts-two", CONFIRM + "render.go",
     "\t\treturn 1\n\t}\n\treturn 2\n",
     "\t\treturn 1\n\t}\n\treturn 1\n",
     "TestAnEmojiPresentationSelectorIsEscapedAndTheEmojiCountedWide"),
    ("provider-ascii-range", CONFIRM + "render.go",
     "if r >= 0x20 && r <= 0x7e {\n\t\treturn 1",
     "if r >= 0x20 && r <= 0xffff {\n\t\treturn 1",
     "TestNoProviderRowEverExceedsTheWidth"),
    ("provider-unicode-spaces-collapse", CONFIRM + "render.go",
     "return unicode.Is(unicode.Zs, r)",
     "return r == ' '",
     "TestEveryUnicodeSpaceCollapses"),
    ("protocol-fields-escaped", CONFIRM + "render.go",
     "func field(s string) string { return Escape(s, MaxProtocolString) }",
     "func field(s string) string { return s }",
     "TestARefusedDecisionIsShownEscaped"),
    ("code-printed-last", CONFIRM + "render.go",
     '\tline("Confirmation code:  %s (valid until %s)", field(p.Code), utc(p.ValidUntilUnix))\n\treturn b.String()',
     '\tline("Network again:    %s", field(p.NetworkID))\n\treturn b.String()',
     "TestRenderKeepsProviderTextBeforeAndApartFromTheProtocolFields"),
    ("sensitive-members", CONFIRM + "render.go",
     "if Sensitive(member.Name, sensitive) {",
     "if Sensitive(member.Name, sensitive) && false {",
     "TestRenderFlagsSensitiveMembersAndShortRefundWindows"),
    ("refund-window-warning", CONFIRM + "render.go",
     "if time.Duration(p.RefundClaimWindowSeconds)*time.Second < refundWarningAge {",
     "if time.Duration(p.RefundClaimWindowSeconds)*time.Second < refundWarningAge && false {",
     "TestRenderFlagsSensitiveMembersAndShortRefundWindows"),
    ("terminal-stdin", CONFIRM + "terminal.go",
     "case !facts.StdinIsTerminal:",
     "case false:",
     "TestTheTerminalCheckRefusesEveryUnsafeChannel"),
    ("terminal-char-device", CONFIRM + "terminal.go",
     "case !facts.StdinIsCharDevice:",
     "case false:",
     "TestTheTerminalCheckRefusesEveryUnsafeChannel"),
    ("terminal-controlling", CONFIRM + "terminal.go",
     "case !facts.StdinIsControlling:",
     "case false:",
     "TestTheTerminalCheckRefusesEveryUnsafeChannel"),
    ("terminal-owner", CONFIRM + "terminal.go",
     "case facts.StdinOwner != facts.EffectiveUID:",
     "case false:",
     "TestTheTerminalCheckRefusesEveryUnsafeChannel"),
    ("terminal-reopened-device", CONFIRM + "terminal.go",
     "case facts.ReopenedDevice != facts.StdinDevice:",
     "case false:",
     "TestTheTerminalCheckRefusesEveryUnsafeChannel"),
    ("terminal-isatty-probe", CONFIRM + "terminal_linux.go",
     "if _, err := unix.IoctlGetTermios(fd, unix.TCGETS); err == nil {",
     "if _, err := unix.IoctlGetTermios(fd, unix.TCGETS); err == nil || true {",
     "TestOpenTerminalRefusesAPipe"),
    ("terminal-owner-probe", CONFIRM + "terminal_linux.go",
     "facts.StdinOwner = stdinStat.Uid",
     "facts.StdinOwner = 0",
     "TestOpenTerminalAcceptsTheControllingTerminalOfItsOwnSession"),
    ("terminal-session-probe", CONFIRM + "terminal_linux.go",
     "facts.StdinIsControlling = sessionErr == nil && ownErr == nil && terminalSession == ownSession",
     "facts.StdinIsControlling = true || (sessionErr == nil && ownErr == nil && terminalSession == ownSession)",
     "TestOpenTerminalRefusesATerminalThatIsNotTheSessionsOwn"),
    ("terminal-reopen-probe", CONFIRM + "terminal_linux.go",
     "facts.ReopenedDevice = reopenedStat.Rdev",
     "facts.ReopenedDevice = reopenedStat.Rdev + 1",
     "TestOpenTerminalAcceptsTheControllingTerminalOfItsOwnSession"),

    # The terms the confirmer shows come from the admission (section 5.2).
    ("journal-admitted-sla", SDK + "service_actor_buyer.go",
     "ResponseSLASeconds: admission.Policy.ResponseSLA,",
     "ResponseSLASeconds: admission.Policy.ResponseSLA + 1,",
     "TestBuyerDiscoversVerifiesCallsAndResolves"),
    ("journal-admitted-bounty", SDK + "service_actor_buyer.go",
     "CleanupBountyNanoTOS: admission.Policy.CleanupBounty.String()}",
     'CleanupBountyNanoTOS: "1"}',
     "TestBuyerDiscoversVerifiesCallsAndResolves"),
    ("presented-terms-from-record", AGENT + "agent.go",
     "ResponseSLASeconds: record.ResponseSLASeconds, RefundClaimWindowSeconds: record.RefundClaimWindowSeconds,\n"
     "\t\tRetentionSeconds: validated.Manifest.RetentionSeconds,",
     "ResponseSLASeconds: 3_600, RefundClaimWindowSeconds: record.RefundClaimWindowSeconds,\n"
     "\t\tRetentionSeconds: validated.Manifest.RetentionSeconds,",
     "TestTheShownTermsComeOnlyFromTheJournalRecord"),
    ("preview-terms-from-record", AGENT + "agent.go",
     "ResponseSLASeconds: record.ResponseSLASeconds, RefundClaimWindowSeconds: record.RefundClaimWindowSeconds,\n"
     "\t\tCleanupBountyNanoTOS: record.CleanupBountyNanoTOS, RetentionSeconds: purchase.RetentionSeconds}",
     "ResponseSLASeconds: 3_601, RefundClaimWindowSeconds: record.RefundClaimWindowSeconds,\n"
     "\t\tCleanupBountyNanoTOS: record.CleanupBountyNanoTOS, RetentionSeconds: purchase.RetentionSeconds}",
     "TestThePreviewCarriesTheProviderAndTheAdmittedTerms"),
    ("presented-terms-required", AGENT + "agent.go",
     'if record.ResponseSLASeconds == 0 || record.RefundClaimWindowSeconds == 0 || record.CleanupBountyNanoTOS == "" {',
     "if false {",
     "TestTheShownTermsComeOnlyFromTheJournalRecord"),
    ("decision-line-bound", CONFIRM + "session.go",
     "\t\tif len(line) > MaxDecisionBytes+1 {\n\t\t\tfmt.Fprintln(",
     "\t\tif len(line) > MaxDecisionBytes+1 && false {\n\t\t\tfmt.Fprintln(",
     "TestAnOverlongLineOrAClosedTerminalDecidesNothing"),
    ("decision-needs-newline", CONFIRM + "session.go",
     '\t\tcase err != nil:\n\t\t\treturn "", ErrInputClosed',
     '\t\tcase err != nil && len(line) == 0:\n\t\t\treturn "", ErrInputClosed',
     "TestAnOverlongLineOrAClosedTerminalDecidesNothing"),
    ("empty-line-skips", CONFIRM + "session.go",
     '\tcase typed == "":',
     "\tcase false:",
     "TestATypedCodeConfirmsAndOtherInputDoesNot"),
    ("pack-size-bound", AGENT + "canonical.go",
     "\t\tif size > MaxArchiveBytes {",
     "\t\tif size > MaxArchiveBytes && false {",
     "TestPackSourceArchiveIsDeterministicAndReadable"),

    # The MCP server (sections 2, 4 and 9).
    ("mcp-root-containment", MCP + "source.go",
     'if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {',
     'if err == nil && (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) || true) {',
     "TestASourceOutsideEveryRootIsRefused"),
    ("mcp-real-path", MCP + "source.go",
     "real, err := filepath.EvalSymlinks(source)",
     "real, err := filepath.Clean(source), error(nil)",
     "TestASourceOutsideEveryRootIsRefused"),
    ("mcp-walk-refuses-links", MCP + "source.go",
     '\t\tdefault:\n\t\t\treturn sourceError("the source holds a symlink, device, FIFO or socket")',
     "\t\tdefault:\n\t\t\treturn nil",
     "TestLinksAndSpecialFilesInADirectoryAreRefused"),
    ("mcp-tar-refuses-other-entries", MCP + "source.go",
     '\t\tdefault:\n\t\t\treturn nil, sourceError("the source tar holds an entry',
     '\t\tdefault:\n\t\t\tcontinue\n\t\t\treturn nil, sourceError("the source tar holds an entry',
     "TestASuppliedTarIsRepackedCanonically"),
    ("mcp-untrusted-escaped", MCP + "untrusted.go",
     "Text: buyerconfirm.Escape(value, MaxUntrustedChars)",
     "Text: value + buyerconfirm.Escape(\"\", MaxUntrustedChars)",
     "TestProviderTextIsDelimitedWithAFreshID"),
    ("mcp-fresh-delimiter", MCP + "untrusted.go",
     "if err := random(raw[:]); err != nil {",
     "if err := error(nil); err != nil {",
     "TestProviderTextIsDelimitedWithAFreshID"),
    ("mcp-internal-error-fixed", MCP + "tools.go",
     'Message: "the MCP buyer server could not complete the request"}',
     "Message: err.Error()}",
     "TestAgentRefusalsKeepTheirCodeAndDisposition"),
    ("mcp-refusal-keeps-code", MCP + "tools.go",
     "toolErr = &ToolError{Code: known.Code, Disposition: known.Disposition, Message: known.Message}",
     "toolErr = &ToolError{Code: buyeragent.CodeInternal, Disposition: known.Disposition, Message: known.Message}",
     "TestAgentRefusalsKeepTheirCodeAndDisposition"),
    ("mcp-deploy-vault", MCP + "deployment.go",
     'if strings.HasPrefix(entry, "VAULT_URL=") {',
     'if strings.HasPrefix(entry, "VAULT_URL=") && false {',
     "TestDeploymentChecksRefuseAReachableCustody"),
    ("mcp-deploy-state-readable", MCP + "deployment.go",
     "\tcase err == nil:\n\t\tdirectory.Close()\n\t\treturn ErrStateReadable",
     "\tcase err == nil:\n\t\tdirectory.Close()\n\t\treturn nil",
     "TestDeploymentChecksRefuseAReachableCustody"),
    ("mcp-deploy-state-unchecked", MCP + "deployment.go",
     "\tcase !errors.Is(err, fs.ErrPermission):\n\t\treturn ErrStateUnchecked",
     "\tcase !errors.Is(err, fs.ErrPermission):\n\t\treturn nil",
     "TestDeploymentChecksRefuseAReachableCustody"),
    ("mcp-deploy-custody-owner", MCP + "deployment.go",
     "if osguard.CurrentUserOwns(info) {",
     "if osguard.CurrentUserOwns(info) && false {",
     "TestDeploymentChecksRefuseAReachableCustody"),
    ("mcp-deploy-socket-kind", MCP + "deployment.go",
     "if err != nil || info.Mode()&os.ModeSocket == 0 {",
     "if err != nil {",
     "TestDeploymentChecksRefuseAReachableCustody"),
]

# (name, file, original text, text after deleting the check, why it is
# redundant). Deleting the check must leave every test of its package
# passing; the script runs the whole package to prove it.
REDUNDANT = [
    # The variation selectors are category Mn, which the category rule
    # already escapes; the explicit exclusion states the spec's rule and
    # keeps it if a selector were ever recategorized.
    ("variation-selectors", CONFIRM + "render.go",
     "\tif (r >= 0xfe00 && r <= 0xfe0f) || (r >= 0xe0100 && r <= 0xe01ef) {\n\t\treturn false\n\t}\n",
     "",
     "the variation selectors are Mn, which the category rule escapes"),
    # Parse-time header checks that the canonical comparison also enforces:
    # a header or archive that breaks one can never equal the canonical
    # encoding of its parsed members. They stay for their specific errors.
    ("ustar-magic", AGENT + "archive.go",
     '\tif !bytes.Equal(header[257:263], []byte("ustar\\x00")) || !bytes.Equal(header[263:265], []byte("00")) {\n'
     '\t\treturn Member{}, archiveError("a member header is not a USTAR header")\n\t}\n',
     "",
     "canonical comparison"),
    ("header-checksum", AGENT + "archive.go",
     "\tif err := checkChecksum(header); err != nil {\n\t\treturn Member{}, err\n\t}\n",
     "",
     "canonical comparison"),
    ("field-terminator", AGENT + "archive.go",
     '\tif !isZeroBlock(value[end:]) {\n\t\treturn "", archiveError("a header field has bytes after its terminator")\n\t}\n',
     "",
     "canonical comparison"),
    ("link-name", AGENT + "archive.go",
     '\tif linkName != "" {\n\t\treturn Member{}, archiveError("member %s names a link target", printable(name))\n\t}\n',
     "\t_ = linkName\n",
     "canonical comparison"),
    ("type-flag", AGENT + "archive.go",
     '\tdefault:\n\t\treturn Member{}, archiveError("member %s is not a regular file or a directory", printable(name))\n',
     "",
     "canonical comparison"),
    ("directory-size", AGENT + "archive.go",
     '\t\tif size != 0 {\n\t\t\treturn Member{}, archiveError("directory %s has a size", printable(name))\n\t\t}\n',
     "",
     "canonical comparison; the packer refuses a directory with content"),
    ("repeated-name", AGENT + "archive.go",
     '\t\tif seen[key] {\n\t\t\treturn CheckedArchive{}, archiveError("member %q appears twice", key)\n\t\t}\n',
     "",
     "the packer refuses a repeated name"),
    ("bytes-after-end-marker", AGENT + "archive.go",
     '\t\t\tif !isZeroBlock(raw[offset+2*blockSize:]) {\n'
     '\t\t\t\treturn CheckedArchive{}, archiveError("it has bytes after the end-of-archive marker")\n\t\t\t}\n',
     "",
     "canonical comparison"),
    ("second-end-block", AGENT + "archive.go",
     "if offset+2*blockSize > len(raw) || !isZeroBlock(raw[offset+blockSize:offset+2*blockSize]) {",
     "if offset+2*blockSize > len(raw) {",
     "canonical comparison"),
    ("member-count", AGENT + "archive.go",
     '\t\tif len(members) == MaxArchiveEntries {\n'
     '\t\t\treturn CheckedArchive{}, archiveError("it has more than %d members", MaxArchiveEntries)\n\t\t}\n',
     "",
     "each member takes a 512-byte block, so the 1 MiB bound allows at most 2,046"),
    ("octal-digits", AGENT + "archive.go",
     "\tfor _, c := range text {\n\t\tif c < '0' || c > '7' {\n\t\t\treturn 0, errors.New(\"invalid octal field\")\n\t\t}\n\t}\n",
     "",
     "strconv.ParseInt refuses other digits, the overrun check refuses a negative size, and "
     "the canonical comparison refuses a sign"),
    ("decide-no-presentation", AGENT + "agent.go",
     'purchase.RequestedUnix == 0 || purchase.ConfirmationNonce == "" {\n\t\treturn record, purchase, a.viewOf',
     "purchase.RequestedUnix == 0 {\n\t\treturn record, purchase, a.viewOf",
     "a purchase never presented has presentation time zero, which the lifetime check refuses alike"),
    ("request-line-bound", AGENT + "server.go",
     '\tcase len(line) > MaxRequestBytes:\n\t\treturn failure(refusal(CodeBadInput, "the request exceeds the 2 MiB bound", nil))\n',
     "",
     "every request field is bounded below 2 MiB, and the bounded reader ends an over-long line "
     "without a newline; the check only bounds memory"),
    ("mcp-absolute-path", MCP + "source.go",
     '\tif !filepath.IsAbs(source) {\n\t\treturn "", sourceError("source_path must be absolute")\n\t}\n',
     "",
     "a relative path stays relative after EvalSymlinks, and filepath.Rel refuses to relate it to an "
     "absolute root"),
    ("mcp-read-bound", MCP + "source.go",
     "if err != nil || len(content) > limit {",
     "if err != nil {",
     "a read past the remaining bound means the archive exceeds 1 MiB, which the packer refuses; the "
     "check only bounds memory"),
    ("mcp-packed-bound", MCP + "source.go",
     "\tif len(archive) > maxBytes {\n\t\treturn nil, sourceError(\"the packed source archive exceeds its bound\")\n\t}\n",
     "",
     "every caller passes the 1 MiB archive bound, which the packer enforces itself"),
]


def prove_redundant(selected, env, scratch, errors):
    """Delete each redundant check and require its whole package to pass."""
    for name, file_name, original, deleted, reason in selected:
        package = package_of(file_name)
        source = ROOT / file_name
        text = source.read_text()
        if text.count(original) != 1:
            errors.append(f"redundant {name}: the original text occurs {text.count(original)} times in {file_name}")
            continue
        target = Path(scratch) / f"redundant-{name}-{source.name}"
        target.write_text(text.replace(original, deleted))
        overlay = Path(scratch) / f"redundant-{name}.json"
        overlay.write_text(json.dumps({"Replace": {str(source): str(target)}}))
        result = run(["go", "test", "-count=1", f"-overlay={overlay}", package], env)
        if result.returncode != 0:
            errors.append(f"redundant {name}: deleting it breaks the tests, so it is not redundant ({reason}):\n"
                          f"{result.stdout[-2000:]}{result.stderr[-2000:]}")
            continue
        print(f"redundant  {name}  ({reason})", flush=True)


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
    names = [mutant[0] for mutant in MUTANTS] + [entry[0] for entry in REDUNDANT]
    if len(names) != len(set(names)):
        print("script error: duplicate mutant names", file=sys.stderr)
        return 2
    unknown = set(options.only) - set(names)
    if unknown:
        print(f"script error: unknown mutants {sorted(unknown)}", file=sys.stderr)
        return 2
    selected = [m for m in MUTANTS if not options.only or m[0] in options.only]
    redundant = [r for r in REDUNDANT if not options.only or r[0] in options.only]

    packages = sorted({package_of(m[1]) for m in selected} | {package_of(r[1]) for r in redundant})
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
            if result.returncode != 0 and f"--- FAIL: {test} " not in result.stdout:
                # A failure that is not the named test failing (a panic
                # elsewhere, a timeout, a build or init failure) proves
                # nothing about the mutant.
                errors.append(f"{name}: the run failed without --- FAIL: {test}:\n"
                              f"{result.stdout[-2000:]}{result.stderr[-2000:]}")
                continue
            caught = result.returncode != 0
            print(f"{'caught' if caught else 'SURVIVED'}  {name}  ({test})", flush=True)
            if not caught:
                survivors.append(name)
        prove_redundant(redundant, env, scratch, errors)
    for error in errors:
        print(f"script error: {error}", file=sys.stderr)
    if errors:
        return 2
    if survivors:
        print(f"{len(survivors)} of {len(selected)} mutants survived: {', '.join(survivors)}", file=sys.stderr)
        return 1
    print(f"buyeragent mutants: all {len(selected)} caught; {len(redundant)} redundant checks proven by deletion")
    return 0


if __name__ == "__main__":
    sys.exit(main())
