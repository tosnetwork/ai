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
RELAY = "TestRelayObservationKeepsExactLastTransactionTime"

# (name, file, unique source anchor, replacement, test that must fail)
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


def main():
    tests = sorted({c[4] for c in CASES})
    code, output = execute(
        ["go", "test", "-count=1", "-run", "^(" + "|".join(tests) + ")$", PACKAGE]
    )
    if code:
        raise RuntimeError("baseline failed\n" + output)
    for name, file, old, new, test in CASES:
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
                    PACKAGE,
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
