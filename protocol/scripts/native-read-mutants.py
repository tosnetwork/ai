#!/usr/bin/env python3
"""Overlay-only assertion-red controls for finalized Native state reads.

State readers must survive a pruned last transaction, the state anchor must
stay strict, and execution-time readers must keep the exact transaction.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "./protocol/pkg/toschain"
TOSCHAIN = "protocol/pkg/toschain/"
STATE = "readNativeAccountStateAt("
EXACT = "readNativeAccountAt("
RECOGNITION = "TestTokenRecognitionReadsOneCheckpointAndChecksEveryBinding"
REGISTRY = "TestOfferRegistryStateSurvivesPrunedLastTransaction"
WALLET = "TestTokenWalletStateSurvivesPrunedLastTransaction"
RELAY = "TestRelayObservationReadsTheExactLastTransactionFirst"
ANCHORED = "TestAnchoredWalksReachAPrunedAnchorByItsVerifiedLink"
AGENT_BLOCK = "TestAgentAccountReadsBindToOneBlockOfTheSeqno"
GIFT_DESTINATION = "TestResolveGiftReadsTheDestinationAtTheStateBlock"
BRIDGE = "./provider/pkg/servicebridge"

# (name, file, unique source anchor, replacement, test that must fail[, package])
CASES = [
    # State reads restored to the exact-transaction read.
    (
        "bridge-state-read",
        "service_actor_token_asset.go",
        STATE + "ctx, node, selected.Bridge,",
        EXACT + "ctx, node, selected.Bridge,",
        RECOGNITION,
    ),
    (
        "minter-state-read",
        "service_actor_token_asset.go",
        STATE + "ctx, node, master,",
        EXACT + "ctx, node, master,",
        RECOGNITION,
    ),
    (
        "token-actor-state-read",
        "service_actor_token.go",
        STATE + "ctx, node, canonical,",
        EXACT + "ctx, node, canonical,",
        "TestTokenActorInspectionDoesNotReadCurrentRecognition",
    ),
    (
        "token-wallet-state-read",
        "service_actor_token.go",
        STATE + "ctx, node, address,",
        EXACT + "ctx, node, address,",
        WALLET,
    ),
    (
        "registry-state-read",
        "service_actor.go",
        STATE + "ctx, node, identity.Address, s.seqno,",
        EXACT + "ctx, node, identity.Address, s.seqno,",
        REGISTRY,
    ),
    (
        "simplified-checkpoint-state-read",
        "simplified_native.go",
        STATE + "ctx, node, canonical, checkpoint.Sequence,",
        EXACT + "ctx, node, canonical, checkpoint.Sequence,",
        REGISTRY,
    ),
    (
        "simplified-finalized-state-read",
        "simplified_native.go",
        STATE + "ctx, node, identity.Address, observation.seqno,",
        EXACT + "ctx, node, identity.Address, observation.seqno,",
        REGISTRY,
    ),
    (
        "service-actor-state-read",
        "service_actor.go",
        STATE + "ctx, node, canonical, s.seqno, s.reader.network, s.reader.codeHash)",
        EXACT + "ctx, node, canonical, s.seqno, s.reader.network, s.reader.codeHash)",
        "TestServiceActorStateSurvivesPrunedLastTransaction",
    ),
    (
        "agent-account-state-read",
        "agent_gift.go",
        STATE + "ctx, node, canonical, observation.seqno, r.network, r.accountCode)",
        EXACT + "ctx, node, canonical, observation.seqno, r.network, r.accountCode)",
        "TestAgentAccountStateSurvivesPrunedLastTransaction",
    ),
    # The state anchor stays strict without fetching the transaction.
    (
        "anchor-type-check",
        "native_read.go",
        (
            'if info.LastTransactionID.Type != "internal.transactionId" {\n'
            '\t\treturn nativeAccountVote{}, errors.New("Native account last transaction is malformed")'
        ),
        (
            'if false && info.LastTransactionID.Type != "internal.transactionId" {\n'
            '\t\treturn nativeAccountVote{}, errors.New("Native account last transaction is malformed")'
        ),
        RECOGNITION,
    ),
    (
        "anchor-tuple-check",
        "native_read.go",
        "if _, _, err := transactionTuple(vote); err != nil {",
        "if false {",
        RECOGNITION,
    ),
    # The actor state read is pinned to the session's one block.
    (
        "actor-block-pin",
        "service_actor.go",
        (
            "if err := s.pin(vote); err != nil {\n\t\treturn nil, false, err\n\t}\n"
            "\tif !vote.Found {\n\t\treturn nil, false, nil\n\t}\n\tdataCell"
        ),
        "if !vote.Found {\n\t\treturn nil, false, nil\n\t}\n\tdataCell",
        "TestServiceActorStateSurvivesPrunedLastTransaction",
    ),
    # Agent Account reads are bound to the state read's block, not its seqno.
    (
        "agent-global-id-block-bind",
        "agent_gift.go",
        "if !block.matches(vote.Root, vote.File) {",
        "if false && !block.matches(vote.Root, vote.File) {",
        AGENT_BLOCK,
    ),
    (
        "agent-last-transaction-block-bind",
        "agent_gift.go",
        "if !block.matches(root, file) {",
        "if false && !block.matches(root, file) {",
        AGENT_BLOCK,
    ),
    (
        "agent-block-file-hash",
        "agent_gift.go",
        "b.root == root && b.file == file",
        "b.root == root",
        AGENT_BLOCK,
    ),
    # The global id is read with with_proof: without it the node names no block.
    (
        "agent-global-id-without-proof",
        "agent_gift.go",
        "}{19, seqno, true}, &result)",
        "}{19, seqno, false}, &result)",
        AGENT_BLOCK,
    ),
    # A Gift's destination walk starts at a last transaction of the state block.
    (
        "gift-destination-unpinned",
        "agent_gift.go",
        "finalizedAccountLastTransaction(ctx, node, destination, observation.seqno, block)",
        "finalizedAccountLastTransaction(ctx, node, destination, observation.seqno, agentGiftBlock{})",
        GIFT_DESTINATION,
    ),
    (
        "gift-destination-block-bind",
        "agent_gift.go",
        "if !block.matches(root, file) {",
        "if false && !block.matches(root, file) {",
        GIFT_DESTINATION,
    ),
    # The Agent Account code pin is the production one and is reported as read.
    (
        "agent-code-constructor",
        "agent_gift.go",
        "accountCode: agentgift.AgentAccountCodeHash}",
        'accountCode: agentgift.AgentAccountCodeHash + "0"}',
        "TestAgentGiftReaderPinsTheAgentAccountCode",
    ),
    (
        "agent-code-reported",
        "agent_gift.go",
        "CodeHash: codeHash, DeploymentID:",
        "CodeHash: agentgift.AgentAccountCodeHash, DeploymentID:",
        "TestAgentAccountStateSurvivesPrunedLastTransaction",
    ),
    (
        "agent-code-reported-to-relay",
        "agent_gift.go",
        "CodeHash: codeHash, DeploymentID:",
        "CodeHash: agentgift.AgentAccountCodeHash, DeploymentID:",
        RELAY,
    ),
    # An anchored walk reaches a pruned anchor through the verified link.
    (
        "anchor-link-history",
        "service_actor.go",
        "if anchor != nil && lastMatches(next, *anchor) {\n\t\t\treturn out, HistoryAnchorReached, nil\n\t\t}",
        "",
        ANCHORED,
    ),
    (
        "anchor-link-withdraw",
        "service_actor.go",
        "if anchor != nil && lastMatches(next, *anchor) {\n\t\t\treturn out, HistoryAnchorReached, nil\n\t\t}",
        "",
        "TestWithdrawalResolvesAfterItsAnchorIsPruned",
        BRIDGE,
    ),
    (
        "anchor-link-hash-only",
        "service_actor.go",
        "if anchor != nil && lastMatches(next, *anchor) {",
        (
            "if anchor != nil && func() bool {\n"
            "\t\t\traw, err := hex.DecodeString(anchor.Hash)\n"
            "\t\t\treturn err == nil && next.Hash == base64.StdEncoding.EncodeToString(raw)\n"
            "\t\t}() {"
        ),
        ANCHORED,
    ),
    (
        "link-stop-in-execution-walk",
        "service_actor_token_history.go",
        (
            "Hash: base64.StdEncoding.EncodeToString(oldest.PrevTxHash)}\n\t}\n}\n"
            "func reduceTokenWalletTransaction("
        ),
        (
            "Hash: base64.StdEncoding.EncodeToString(oldest.PrevTxHash)}\n"
            "\t\tif lastMatches(next, target) {\n\t\t\treturn page[len(page)-1], nil\n\t\t}\n\t}\n}\n"
            "func reduceTokenWalletTransaction("
        ),
        "TestTokenWalletTransactionNeedsThePrunedTargetCell",
    ),
    # Execution-time readers keep the exact transaction.
    (
        "exact-read-guard",
        "native_read.go",
        (
            "vote.TransactionTime, err = verifyNativeLastTransactionTuple(ctx, node, address, id)\n"
            "\tif err != nil {\n\t\treturn nativeAccountVote{}, err\n\t}"
        ),
        "_ = id",
        RELAY,
    ),
    (
        "relay-exact-read",
        "agent_relay_resolution.go",
        EXACT + "ctx, node, parsed.SenderAgentAccount,",
        STATE + "ctx, node, parsed.SenderAgentAccount,",
        RELAY,
    ),
    (
        "wallet-transaction-inferred-from-anchor",
        "service_actor_token_history.go",
        (
            "\t\tcase err != nil:\n\t\t\treturn tokenWalletAnchoredRead{}, err\n\t\t}\n"
            "\t\tif !bytes.Equal(entry.transaction.AccountAddr, account) {"
        ),
        (
            "\t\tcase err != nil:\n\t\t\treturn tokenWalletAnchoredRead{Result: HistoryAnchorReached, "
            "Transaction: TokenActorTransaction{LT: id.LT, Hash: id.Hash, TookEffect: true}, "
            "BlockRoot: root, BlockFile: file}, nil\n\t\t}\n"
            "\t\tif !bytes.Equal(entry.transaction.AccountAddr, account) {"
        ),
        WALLET,
    ),
    (
        "pruned-history-as-known-absence",
        "service_actor_token_history.go",
        (
            "page, err := historyEntriesAt(ctx, node, address, next, actorHistoryPage)\n"
            "\t\tif err != nil {\n\t\t\treturn historyEntry{}, err\n\t\t}"
        ),
        (
            "page, err := historyEntriesAt(ctx, node, address, next, actorHistoryPage)\n"
            "\t\tif err != nil {\n\t\t\treturn historyEntry{}, ErrHistoryAnchorMissing\n\t\t}"
        ),
        WALLET,
    ),
]


def execute(command):
    result = subprocess.run(
        command,
        cwd=ROOT,
        env={**os.environ, "GOWORK": "off"},
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    return result.returncode, result.stdout + result.stderr


def package_of(case):
    return case[5] if len(case) > 5 else PACKAGE


def main():
    for package in sorted({package_of(c) for c in CASES}):
        tests = sorted({c[4] for c in CASES if package_of(c) == package})
        code, output = execute(
            ["go", "test", "-count=1", "-run", "^(" + "|".join(tests) + ")$", package]
        )
        if code:
            raise RuntimeError("baseline failed\n" + output)
    for case in CASES:
        name, file, old, new, test = case[:5]
        package = package_of(case)
        source = ROOT / (TOSCHAIN + file)
        original = source.read_text()
        if original.count(old) != 1:
            raise RuntimeError("non-unique anchor: " + name)
        with tempfile.TemporaryDirectory(prefix="native-read-mutant-") as directory:
            path = Path(directory) / source.name
            path.write_text(original.replace(old, new))
            overlay = Path(directory) / "overlay.json"
            overlay.write_text(json.dumps({"Replace": {str(source): str(path)}}))
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
        if (
            code == 0
            or "--- FAIL: " + test not in output
            or "[build failed]" in output
            or "panic:" in output
        ):
            raise RuntimeError("survivor or invalid mutant: " + name + "\n" + output)
        print("RED " + name + ": " + test, flush=True)
    print(f"NATIVE_READ_MUTANTS_OK: {len(CASES)} checks caught")


if __name__ == "__main__":
    main()
