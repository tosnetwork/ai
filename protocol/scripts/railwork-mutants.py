#!/usr/bin/env python3
"""Red controls for the security-relevant checks of protocol/pkg/railwork.

Each mutant removes or weakens one check: the request binding, an all-zero
field refusal, a size bound or a digest comparison. A mutant is applied
through `go test -overlay`, so the working tree is never modified and runs
cannot leave a mutated file behind.

A mutant is caught only when its named test reports `--- FAIL: <test>`.
A mutant whose text does not occur exactly once, or that does not build, is
a script error, not a catch. The unmutated package must pass first.

Usage (from the repository root):

    python3 -I protocol/scripts/railwork-mutants.py [--only NAME]

Checks with no mutant here are redundant with a later check, so removing
one alone changes no outcome:

- the frame size bound in DecodeFrame: the per-kind bound and canonical
  chunking already bound the data at 61,440 bytes;
- the trailing-value check of a header: the canonical re-encoding of the
  first value differs from bytes that hold a second;
- the key card text bound: canonical Base64 longer than 21,848 characters
  always decodes to more than the 16,384-byte card bound;
- the non-empty package after decoding: an empty package_base64 is refused
  by the header check, and canonical non-empty Base64 never decodes empty;
- the Receipt rebuild in DecodeReceipt: the nativecore decoder is exact,
  and a non-canonical cell could not hash to the finalized response hash.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "./protocol/pkg/railwork"
SOURCE = ROOT / "protocol/pkg/railwork"

# (name, file, original text, mutated text, test that must fail)
MUTANTS = [
    # Frame: all-zero binding fields, bounds, chunking.
    ("frame-zero-actor", "frame.go",
     "if frame.Binding.ActorAccount == ([32]byte{}) || frame.Binding.RequestHash == ([32]byte{}) ||",
     "if false || frame.Binding.RequestHash == ([32]byte{}) ||",
     "TestVectorNegativeFramesAreRefused"),
    ("frame-zero-request-hash", "frame.go",
     "if frame.Binding.ActorAccount == ([32]byte{}) || frame.Binding.RequestHash == ([32]byte{}) ||",
     "if frame.Binding.ActorAccount == ([32]byte{}) || false ||",
     "TestVectorNegativeFramesAreRefused"),
    ("frame-zero-message-digest", "frame.go",
     "\t\tframe.MessageDigest == ([32]byte{}) {",
     "\t\tfalse {",
     "TestVectorNegativeFramesAreRefused"),
    ("frame-kind-bound", "frame.go",
     "if frame.TotalLength == 0 || frame.TotalLength > bound {",
     "if frame.TotalLength == 0 || frame.TotalLength > bound+MaxChunkData {",
     "TestFrameTotalOverTheKindBoundIsRefusedEvenWhenChunkingAgrees"),
    ("frame-data-length-field", "frame.go",
     "if uint64(length) != uint64(len(raw)-FrameHeaderBytes) {",
     "if false && uint64(length) != uint64(len(raw)-FrameHeaderBytes) {",
     "TestVectorNegativeFramesAreRefused"),
    ("frame-canonical-chunking", "frame.go",
     "if uint64(expected) != uint64(len(frame.Data)) {",
     "if false && uint64(expected) != uint64(len(frame.Data)) {",
     "TestVectorNegativeFramesAreRefused"),
    # Join: same message, each index once, digest.
    ("join-same-message", "frame.go",
     "if !sameMessage(frame, first) {",
     "if false && !sameMessage(frame, first) {",
     "TestVectorNegativeJoinsAreRefused"),
    ("join-repeated-index", "frame.go",
     "if ordered[frame.Index] != nil {",
     "if false && ordered[frame.Index] != nil {",
     "TestJoinRefusesARepeatedIndexEvenInAnOtherwiseCompleteSet"),
    ("join-digest", "frame.go",
     "if uint64(len(message)) != uint64(first.TotalLength) || sha256.Sum256(message) != first.MessageDigest {",
     "if uint64(len(message)) != uint64(first.TotalLength) {",
     "TestVectorNegativeJoinsAreRefused"),
    ("assembly-conflict", "assembly.go",
     "if !bytes.Equal(held, frame.Data) {",
     "if false && !bytes.Equal(held, frame.Data) {",
     "TestAssemblyRefusesAConflictingFrame"),
    # Message: canonical header, strict Base64, digests, bounds.
    ("header-canonical", "message.go",
     "if err != nil || !bytes.Equal(reencoded, raw) {",
     "if err != nil || len(reencoded) == 0 {",
     "TestVectorNegativeMessagesAreRefused"),
    ("header-length-bound", "message.go",
     "if length == 0 || length > MaxMessageHeaderBytes || uint64(length) > uint64(len(raw)-4) {",
     "if length == 0 || uint64(length) > uint64(len(raw)-4) {",
     "TestAHeaderOverItsBoundIsRefusedWhenEverythingElseIsValid"),
    ("base64-line-breaks", "message.go",
     "if err != nil || base64.StdEncoding.EncodeToString(raw) != text {",
     "if err != nil {",
     "TestBase64WithLineBreaksIsRefused"),
    ("key-card-decoded-bound", "message.go",
     "if !ok || len(card) == 0 || len(card) > MaxKeyCardBytes {",
     "if !ok || len(card) == 0 {",
     "TestKeyCardsMustBeCanonicalBase64WhenDecoded"),
    ("task-source-digest", "message.go",
     "if header.SourceDigest != sha256Text(sha256.Sum256(archive)) {",
     "if false && header.SourceDigest != sha256Text(sha256.Sum256(archive)) {",
     "TestVectorNegativeMessagesAreRefused"),
    ("task-archive-bound", "message.go",
     "case archiveBytes <= 0 || archiveBytes > MaxInlineInputBytes:",
     "case archiveBytes <= 0:",
     "TestATaskArchiveOverOneMiBIsRefusedWhenDecoded"),
    ("task-call-lt-zero", "message.go",
     "case header.CallLT == 0:",
     "case false:",
     "TestVectorNegativeMessagesAreRefused"),
    ("result-artifact-bound", "message.go",
     "case len(artifact) == 0 || len(artifact) > MaxResultBytes:",
     "case len(artifact) == 0:",
     "TestAResultArtifactOverItsBoundIsRefusedWhenDecoded"),
    ("result-receipt-empty", "message.go",
     "if !ok || len(receipt) == 0 {",
     "if !ok {",
     "TestAResultWithAnEmptyReceiptIsRefused"),
    ("ack-body", "message.go",
     "\tcase len(rest) != 0:\n\t\treturn Ack{}, invalidMessage(\"an acknowledgement has a body\")",
     "\tcase len(rest) < 0:\n\t\treturn Ack{}, invalidMessage(\"an acknowledgement has a body\")",
     "TestVectorNegativeMessagesAreRefused"),
    # Derived values.
    ("input-domain", "derive.go",
     "InputDomain       = \"tos.openfox.rail-input.v1\"",
     "InputDomain       = \"tos.openfox.rail-input.v2\"",
     "TestVectorDerivedValues"),
    ("execution-id-agent", "derive.go",
     "\thash.Write([]byte(buyerAgentID))\n",
     "",
     "TestVectorDerivedValues"),
    # Provider admission (section 7.1).
    ("admit-sender-is-buyer", "admission.go",
     "if message.SenderAgentID != header.BuyerAgentID {",
     "if false && message.SenderAgentID != header.BuyerAgentID {",
     "TestProviderRefusesTasksThatDoNotBindToItsQuote"),
    ("admit-frame-request-id", "admission.go",
     "if message.Binding.RequestID != header.RequestID {",
     "if false && message.Binding.RequestID != header.RequestID {",
     "TestProviderRefusesTasksThatDoNotBindToItsQuote"),
    ("admit-version", "admission.go",
     "if proposal.GetCapabilityId() != p.CapabilityID || proposal.GetCapabilityVersion() != p.Version ||",
     "if proposal.GetCapabilityId() != p.CapabilityID ||",
     "TestProviderRefusesTasksThatDoNotBindToItsQuote"),
    ("admit-transport-recipient", "admission.go",
     "if err != nil || recipient != p.AgentID {",
     "if false && (err != nil || recipient != p.AgentID) {",
     "TestProviderRefusesAQuoteThatDoesNotDeliverToIt"),
    ("admit-quoted-request-bound", "admission.go",
     "if uint64(len(task.Archive)) > uint64(validated.TransportBinding.MaxRequestBytes) ||",
     "if false ||",
     "TestProviderRefusesTasksThatDoNotBindToItsQuote"),
    ("admit-execution-id", "admission.go",
     "if err != nil || committed != executionID {",
     "if err != nil || len(committed) == 0 {",
     "TestProviderRefusesTasksThatDoNotBindToItsQuote"),
    ("admit-verified-request-hash", "admission.go",
     "if a.Message.Binding.RequestHash != verifiedRequestHash || a.Message.Binding.Actor() != verifiedActor {",
     "if a.Message.Binding.Actor() != verifiedActor {",
     "TestFrameBindingMustEqualTheVerifiedRequest"),
    ("admit-verified-actor", "admission.go",
     "if a.Message.Binding.RequestHash != verifiedRequestHash || a.Message.Binding.Actor() != verifiedActor {",
     "if a.Message.Binding.RequestHash != verifiedRequestHash {",
     "TestFrameBindingMustEqualTheVerifiedRequest"),
    # Buyer acceptance (section 7.2) and the attestor policy.
    ("accept-finalized-hash", "receipt.go",
     "if hash != finalizedResponseHash {",
     "if false && hash != finalizedResponseHash {",
     "TestBuyerRefusesAResultThatDoesNotBindItsPurchase"),
    ("accept-header-hash", "receipt.go",
     "if result.Header.ResponseHash != hex.EncodeToString(hash[:]) {",
     "if false && result.Header.ResponseHash != hex.EncodeToString(hash[:]) {",
     "TestBuyerRefusesAResultThatDoesNotBindItsPurchase"),
    ("accept-quote-commitment", "receipt.go",
     "case receipt.QuoteCommitment != binding.QuoteCommitment:",
     "case false:",
     "TestBuyerRefusesAResultThatDoesNotBindItsPurchase"),
    ("accept-execution-id", "receipt.go",
     "case receipt.ExecutionID != sha256Text(binding.ExecutionID):",
     "case false:",
     "TestBuyerRefusesAResultThatDoesNotBindItsPurchase"),
    ("accept-input-digest", "receipt.go",
     "case receipt.InputDigest != sha256Text(binding.InputDigest):",
     "case false:",
     "TestBuyerRefusesAResultThatDoesNotBindItsPurchase"),
    ("accept-source-digest", "receipt.go",
     "case receipt.SourceDigest != binding.SourceDigest:",
     "case false:",
     "TestBuyerRefusesAResultThatDoesNotBindItsPurchase"),
    ("accept-price", "receipt.go",
     "case receipt.ChargedAtomicAmount != binding.Price.String():",
     "case false:",
     "TestBuyerRefusesAResultThatDoesNotBindItsPurchase"),
    ("accept-provider", "receipt.go",
     "case receipt.ProviderAgentID != binding.ProviderAgentID:",
     "case false:",
     "TestBuyerRefusesAResultThatDoesNotBindItsPurchase"),
    ("accept-sandbox", "receipt.go",
     "case receipt.ToolchainDigest != binding.ToolchainDigest || receipt.SandboxDigest != binding.SandboxDigest:",
     "case receipt.ToolchainDigest != binding.ToolchainDigest:",
     "TestBuyerRefusesAResultThatDoesNotBindItsPurchase"),
    ("accept-artifact-digest", "receipt.go",
     "if receipt.ArtifactDigest != sha256Text(sha256.Sum256(result.Artifact)) {",
     "if false && receipt.ArtifactDigest != sha256Text(sha256.Sum256(result.Artifact)) {",
     "TestBuyerRefusesAResultThatDoesNotBindItsPurchase"),
    ("artifact-regular-files", "receipt.go",
     "if err != nil || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > MaxResultBytes {",
     "if err != nil || header.Size < 0 || header.Size > MaxResultBytes {",
     "TestArtifactMustHoldExactlyItsOutputAndReport"),
    ("artifact-repeated-member", "receipt.go",
     "if _, seen := members[header.Name]; seen {",
     "if _, seen := members[header.Name]; false && seen {",
     "TestArtifactMustHoldExactlyItsOutputAndReport"),
    ("attest-outcome", "receipt.go",
     "receipt.CompletedAt != outcome.CompletedAtUnix {",
     "false {",
     "TestAttestorPolicyRequiresTheActualOutcome"),
    ("result-from-provider", "receipt.go",
     "if message.SenderAgentID != providerAgentID || message.Binding != binding {",
     "if message.Binding != binding {",
     "TestResultsAcksAndResultRequestsMustComeFromTheCounterpartyForTheBinding"),
    ("ack-response-hash", "receipt.go",
     "\t\tack.Header.ResponseHash != hex.EncodeToString(responseHash[:]) {",
     "\t\tfalse {",
     "TestResultsAcksAndResultRequestsMustComeFromTheCounterpartyForTheBinding"),
    ("result-request-sender", "receipt.go",
     "if message.SenderAgentID != buyerAgentID || message.Binding != binding {\n\t\treturn ResultRequest{}",
     "if message.Binding != binding {\n\t\treturn ResultRequest{}",
     "TestResultsAcksAndResultRequestsMustComeFromTheCounterpartyForTheBinding"),
]


def go_env():
    env = dict(os.environ)
    env.setdefault("GOWORK", "off")
    env.setdefault("GOFLAGS", "-p=8")
    return env


def run(arguments, env):
    return subprocess.run(arguments, cwd=ROOT, env=env, capture_output=True, text=True, check=False)


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

    baseline = run(["go", "test", "-count=1", PACKAGE], env)
    if baseline.returncode != 0:
        print("script error: the unmutated package does not pass\n" + baseline.stdout + baseline.stderr, file=sys.stderr)
        return 2
    listing = run(["go", "test", "-list", ".", PACKAGE], env)
    tests = set(listing.stdout.split())
    survivors, errors = [], []
    with tempfile.TemporaryDirectory(prefix="railwork-mutants-") as scratch:
        for name, file_name, original, mutated, test in selected:
            if test not in tests:
                errors.append(f"{name}: no test named {test}")
                continue
            source = SOURCE / file_name
            text = source.read_text()
            if text.count(original) != 1:
                errors.append(f"{name}: the original text occurs {text.count(original)} times in {file_name}")
                continue
            target = Path(scratch) / f"{name}-{file_name}"
            target.write_text(text.replace(original, mutated))
            overlay = Path(scratch) / f"{name}.json"
            overlay.write_text(json.dumps({"Replace": {str(source): str(target)}}))
            build = run(["go", "test", "-c", "-o", os.devnull, f"-overlay={overlay}", PACKAGE], env)
            if build.returncode != 0:
                errors.append(f"{name}: the mutant does not build:\n{build.stdout}{build.stderr}")
                continue
            result = run(["go", "test", "-count=1", f"-overlay={overlay}", "-run", f"^{test}$", PACKAGE], env)
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
    print(f"railwork mutants: all {len(selected)} caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())
