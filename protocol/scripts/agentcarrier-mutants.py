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
    "lane-kind",
    "lane.go",
    "(c.Kind != Rail && c.Kind != Chat)",
    "(false && c.Kind != Rail && c.Kind != Chat)",
    "TestNoSigningOrMutationOnInvalidConfiguration",
)
add(
    "relay-duplicates",
    "lane.go",
    "|| seen[url]",
    "|| (false && seen[url])",
    "TestNoSigningOrMutationOnInvalidConfiguration",
)
add(
    "used-inventory",
    "lane.go",
    "if len(expected) != 0 {",
    "if false && len(expected) != 0 {",
    "TestUsedInventoryRefusesMissingKeysAndDeliveries",
)
add(
    "inventory-collections",
    "inventory.go",
    "index.Keys == nil || index.Deliveries == nil",
    "false",
    "TestUsedInventoryRequiresBothCollections",
)
add(
    "queue-inventory",
    "outbox.go",
    "if err = l.index(ctx, deliveryName(id), true); err != nil {",
    "if err = error(nil); err != nil {",
    "TestInventoryAdmitsQueueBeforeItReturns",
)
add(
    "key-inventory",
    "keys.go",
    "if err = l.index(ctx, keyName(key.KeyID), true); err != nil {",
    "if err = error(nil); err != nil {",
    "TestKeysRotateRetainAndRemainSeparateByLane",
)
add(
    "key-namespace",
    "keys.go",
    "r.Identity != l.identity()",
    "false",
    "TestCopyingARailKeyIntoChatIsRefused",
)
add(
    "key-destruction",
    "keys.go",
    "now >= card.NotAfterUnix+uint64(KeyRetention/time.Second)",
    "now > card.NotAfterUnix+uint64(KeyRetention/time.Second)",
    "TestKeysRotateRetainAndRemainSeparateByLane",
)
add(
    "key-retention",
    "keys.go",
    "now >= card.NotAfterUnix+uint64(KeyRetention/time.Second)",
    "now >= card.NotAfterUnix",
    "TestKeysRotateRetainAndRemainSeparateByLane",
)
add(
    "key-successor",
    "keys.go",
    "r.card.NotAfterUnix <= now+uint64(SuccessorLead/time.Second)",
    "r.card.NotAfterUnix <= now",
    "TestKeysRotateRetainAndRemainSeparateByLane",
)
add(
    "key-cap-before-sign",
    "keys.go",
    "if len(records) >= MaxKeys {",
    "if false && len(records) >= MaxKeys {",
    "TestSixteenKeysAreAHardBound",
)
add(
    "owner-root-before-publish",
    "keys.go",
    "if err = l.own(ctx); err != nil {",
    "if err = error(nil); err != nil {",
    "TestWithdrawingOwnAuthorityWhileSigningReturnsNoCard",
)
add(
    "signer-not-under-key-gate",
    "keys.go",
    "packet, err := l.config.SignCard(ctx, card)",
    "if e:=l.keys.lock(ctx);e!=nil{return OwnCard{},e}; packet, err := l.config.SignCard(ctx, card); l.keys.unlock()",
    "TestCardSigningDoesNotBlockPolling",
)
add(
    "file-single-link",
    "storage_unix.go",
    "s.Nlink == 1",
    "(true || s.Nlink == 1)",
    "TestExclusiveStoreAndUnsafeFilesRefuse",
)
add(
    "file-private-mode",
    "storage_unix.go",
    "info.Mode().Perm() == 0600",
    "true",
    "TestExclusiveStoreAndUnsafeFilesRefuse",
)
add(
    "root-private-mode",
    "storage.go",
    "info.Mode().Perm() != 0700",
    "false",
    "TestStateDirectoryMustBePrivate",
)
add(
    "ancestor-write-permission",
    "storage.go",
    "(info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0)",
    "false",
    "TestWritableNonStickyAncestorRefusesBeforeCreatingState",
)
add(
    "record-checksum",
    "storage.go",
    "record.Sum != hex.EncodeToString(sum[:])",
    "(false && record.Sum != hex.EncodeToString(sum[:]))",
    "TestUsedStoreRefusesMissingIdentityAndCorruptJournal/checksum",
)
add(
    "record-size",
    "storage.go",
    "len(encoded) > MaxRecordBytes",
    "false",
    "TestAtomicWriteRefusalAndRecordSizeKeepThePreviousFile",
)
add(
    "no-route",
    "outbox.go",
    "if len(route.HintRecord) == 0 {",
    "if false && len(route.HintRecord) == 0 {",
    "TestNoRouteOrBadHintNeverUsesCardRelays",
)
add(
    "hint-relays-only",
    "outbox.go",
    "Relays: append([]string(nil), verified.Record.Hint.Relays...)",
    "Relays: append([]string(nil), chosenUnusedRelays(route.CardPacket)...)",
    "TestNoRouteOrBadHintNeverUsesCardRelays",
)
add(
    "old-card-standing",
    "outbox.go",
    "oldValid := oldErr == nil",
    "oldValid := true || oldErr == nil",
    "TestUnacceptedRevokedCardResealsButAcceptedCardStops",
)
add(
    "no-gratuitous-reseal",
    "outbox.go",
    "if !oldValid || header.ExpiresAtUnix <= now {",
    "if !oldValid || header.RecipientKeyID != key.KeyID || header.ExpiresAtUnix <= now {",
    "TestNewValidCardDoesNotResealAnAmbiguousAttempt",
)
add(
    "accepted-card-stop",
    "outbox.go",
    "if accepted(*g) && header.ExpiresAtUnix > now {",
    "if false && accepted(*g) && header.ExpiresAtUnix > now {",
    "TestUnacceptedRevokedCardResealsButAcceptedCardStops/accepted",
)
add(
    "expiry-after-journal",
    "outbox.go",
    "if now >= r.Deadline || h.ExpiresAtUnix <= now {",
    "if false && (now >= r.Deadline || h.ExpiresAtUnix <= now) {",
    "TestExpiryWhileJournallingWithholdsTheBody",
)
add(
    "expiry-after-verification",
    "outbox.go",
    "if deadline <= fresh {",
    "if false && deadline <= fresh {",
    "TestQueueRechecksDeadlineAfterVerification",
)
add(
    "attempt-counter",
    "outbox.go",
    "\n\tif t.Attempts == math.MaxUint32 {",
    "\n\tif false && t.Attempts == math.MaxUint32 {",
    "TestAttemptCounterDoesNotWrap",
)
add(
    "envelope-business-deadline",
    "outbox.go",
    "min(r.Deadline, now+86400)",
    "now+86400",
    "TestEnvelopeExpiryIsBoundedByBusinessDeadlineAndOneDay/7200",
)
add(
    "envelope-day",
    "outbox.go",
    "min(r.Deadline, now+86400)",
    "r.Deadline",
    "TestEnvelopeExpiryIsBoundedByBusinessDeadlineAndOneDay/172800",
)
add(
    "fallback-quota",
    "outbox.go",
    'status(err, 507, "") || status(err, 403, "credential_revoked")',
    'false || status(err, 403, "credential_revoked")',
    "TestContactFallbackUsesTheSameBytesAndDropsOnlyRevokedCredentials/507",
)
add(
    "fallback-revoked",
    "outbox.go",
    'status(err, 507, "") || status(err, 403, "credential_revoked")',
    'status(err, 507, "") || false',
    "TestContactFallbackUsesTheSameBytesAndDropsOnlyRevokedCredentials/403",
)
add(
    "gone-acceptance",
    "outbox.go",
    'err == nil || status(err, 410, "")',
    "err == nil",
    "TestPermanentRelayerRefusalsAndGone/410",
)
add(
    "owner-delegation-binding",
    "outbox.go",
    "!bytes.Equal(raw, own)",
    "(false && !bytes.Equal(raw, own))",
    "TestOwnerCredentialCannotSubstituteAnotherDelegationOfTheSameAgent",
)
add(
    "credential-signature",
    "types.go",
    "c.VerifyChain() != nil",
    "false",
    "TestCredentialConstructorRejectsTamperedSignature",
)
add(
    "expired-contact",
    "outbox.go",
    "if until <= now {",
    "if false && until <= now {",
    "TestAnExpiredContactCredentialUsesTheStrangerLane",
)
add(
    "refusal-scope",
    "poll.go",
    'local := url + "\\x00" + id',
    "local := id",
    "TestCorruptCopyDoesNotSuppressTheGoodCopyElsewhere",
)
add(
    "memory-bound",
    "poll.go",
    "len(table) >= MaxEnvelopeMemory",
    "false",
    "TestReceiveMemoryIsBounded",
)
add(
    "memory-expiry",
    "poll.go",
    "if value.Until <= now {",
    "if false && value.Until <= now {",
    "TestReceiveMemoryIsBounded",
)
add(
    "transient-no-ack",
    "poll.go",
    "if verifyErr != nil && !errors.Is(verifyErr, ErrRefused) {",
    "if false && verifyErr != nil && !errors.Is(verifyErr, ErrRefused) {",
    "TestTransientVerifyOrStoreFailureNeverAcknowledges",
)
add(
    "inbox-before-ack",
    "poll.go",
    "verifyErr = l.config.Store(ctx, opened.PacketJSON)",
    "verifyErr = nil",
    "TestPollStoresDurablyBeforeAcknowledgingAndDeduplicatesRelays",
)
add(
    "packet-verification",
    "poll.go",
    "verifyErr = l.config.VerifyPacket(ctx, p)",
    "verifyErr = nil",
    "TestTransientVerifyOrStoreFailureNeverAcknowledges/verification",
)
add(
    "packet-recipient",
    "poll.go",
    "p.RecipientAgentID != l.config.AgentID",
    "false",
    "TestForeignRecipientPacketIsRefusedBeforeStore",
)
add(
    "held-key-before-fetch",
    "poll.go",
    "if !ok {",
    "if false && !ok {",
    "TestUnknownKeysAreNeverFetched",
)
add(
    "download-bound",
    "poll.go",
    "if downloads >= 16 {",
    "if false && downloads >= 16 {",
    "TestPollPrefersContactEntriesAndBoundsDownloads",
)
add(
    "contact-priority",
    "poll.go",
    'entries[i].Lane == "contact" && entries[j].Lane != "contact"',
    "false && entries[i].Lane == entries[j].Lane",
    "TestPollPrefersContactEntriesAndBoundsDownloads",
)
add(
    "wait-one",
    "lane.go",
    "wait: make(gate, 1)",
    "wait: make(gate, 2)",
    "TestOneWaitDoesNotBlockPlainPolling",
)
add(
    "retired-relay",
    "lane.go",
    "max(merged[url], until)",
    "until",
    "TestOutboxAndPollTargetsHaveHardBounds",
)
add(
    "poll-target-bound",
    "lane.go",
    "if len(merged) > MaxPollRelays {",
    "if false && len(merged) > MaxPollRelays {",
    "TestOutboxAndPollTargetsHaveHardBounds",
)
add(
    "outbox-bound",
    "outbox.go",
    "if count >= l.config.OutboxLimit {",
    "if false && count >= l.config.OutboxLimit {",
    "TestOutboxAndPollTargetsHaveHardBounds",
)

add(
    "zero-secret-memory",
    "poll.go",
    "if mem.CanAck {",
    "if mem.Secret != ([32]byte{}) {",
    "TestAZeroRecoveredSecretCanStillBeAcknowledgedAgain",
)
add(
    "holder-seed-binding",
    "types.go",
    "!bytes.Equal(ed25519.NewKeyFromSeed(holder[:32]), holder)",
    "false",
    "TestCredentialsCannotBePrintedOrMarshalled",
)
add(
    "source-no-legacy",
    "source_guard_test.go",
    "!allowed[s.Sel.Name]",
    "false",
    "TestCarrierGuardRefusesAliasesAndLegacyObjects",
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
