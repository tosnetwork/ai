#!/usr/bin/env python3
"""Red controls for the room end on carrier.room-cards admissions.

Each control applies one exact-once source edit, runs the named tests and
requires a `--- FAIL: <name>` line from one of them; the edit is then undone
by the reverse edit and the file is compared with its original bytes. A
mutation whose package does not build is a script error, never a catch.

Run from the repository root:

    TOS_OPENMLS_DRIVER=/path/to/tos-openmls-driver \
        python3 -I messenger/scripts/red-controls-carrier-room-end.py

The daemon controls need the OpenMLS driver (the room tests skip without it).
Exit status: 0 every control caught, 1 a control survived, 2 script error.
"""

import hashlib
import os
import pathlib
import re
import subprocess
import sys

CARRIERAPI = "./messenger/pkg/carrierapi"
DAEMON = "./messenger/pkg/daemon"
API = "messenger/pkg/carrierapi/api.go"
SOCKET = "messenger/pkg/carrierapi/socket.go"
HANDSHAKE = "messenger/pkg/daemon/room_handshake.go"

CONTROLS = [
    {
        "name": "an admission without a room end is accepted",
        "file": API,
        "old": "\t\tif request.RoomEndsAtUnix == 0 {\n\t\t\treturn ErrRoomEnd\n\t\t}\n",
        "new": "\t\t// red control: no room end required\n",
        "package": CARRIERAPI,
        "tests": ["TestRoomEndIsNamedByAdmissionsOnly"],
    },
    {
        "name": "a forget or another operation may name a room end",
        "file": API,
        "old": "if request.RoomEndsAtUnix != 0 && (request.Op != OpRoomCards",
        "new": "if false && request.RoomEndsAtUnix != 0 && (request.Op != OpRoomCards",
        "package": CARRIERAPI,
        "tests": ["TestRoomEndIsNamedByAdmissionsOnly"],
    },
    {
        "name": "the clock bound admits one second too many",
        "file": API,
        "old": "\tif roomEndsAtUnix > latest {\n",
        "new": "\tif roomEndsAtUnix > latest+1 {\n",
        "package": CARRIERAPI,
        "tests": ["TestValidateRoomEndBoundsTheEndByTheClock", "TestRoomEndBeyondTheClockIsRefusedAtBothEnds"],
    },
    {
        "name": "the drop time omits the slack",
        "file": API,
        "old": "\treturn roomEndsAtUnix + RoomEndSlackSeconds, true\n",
        "new": "\treturn roomEndsAtUnix, true\n",
        "package": CARRIERAPI,
        "tests": ["TestRoomAdmissionDropsAtTheEndPlusTheSlack"],
    },
    {
        "name": "the client sends an end beyond its clock",
        "file": SOCKET,
        "old": "\tif err := ValidateRoomEnd(roomEndsAtUnix, c.now()); err != nil {\n",
        "new": "\tif err := ValidateRoomEnd(roomEndsAtUnix, c.now()); err != nil && roomEndsAtUnix == 0 {\n",
        "package": CARRIERAPI,
        "tests": ["TestRoomEndBeyondTheClockIsRefusedAtBothEnds"],
    },
    {
        "name": "the server hands its handler an end beyond its clock",
        "file": SOCKET,
        "old": "\t\tValidateRoomEnd(request.RoomEndsAtUnix, s.now()) != nil {\n",
        "new": "\t\tValidateRoomEnd(request.RoomEndsAtUnix, s.now()) != nil && false {\n",
        "package": CARRIERAPI,
        "tests": ["TestRoomEndBeyondTheClockIsRefusedAtBothEnds"],
    },
    {
        "name": "the client drops the end from the request",
        "file": SOCKET,
        "old": "\t\tRoomEndsAtUnix: roomEndsAtUnix, RoomCards: cards})\n",
        "new": "\t\tRoomCards: cards})\n",
        "package": CARRIERAPI,
        "tests": ["TestRoomCardsAndWithdrawOverTheSocket", "TestRoomEndBeyondTheClockIsRefusedAtBothEnds"],
    },
    {
        "name": "the slack is shorter than the largest daemon clock skew",
        "file": API,
        "old": "\tRoomEndSlackSeconds uint64 = 3_600\n",
        "new": "\tRoomEndSlackSeconds uint64 = 1_800\n",
        "package": DAEMON,
        "tests": ["TestCarrierRoomEndSlackIsTheLargestDaemonClockSkew"],
    },
    {
        "name": "the daemon admits under another end than the fused record's",
        "file": HANDSHAKE,
        "old": "r.cards.RoomCards(in.ctx, in.object.RoomID, roomEndsAtUnix, learned.cards)",
        "new": "r.cards.RoomCards(in.ctx, in.object.RoomID, roomEndsAtUnix+1, learned.cards)",
        "package": DAEMON,
        "tests": ["TestRoomReceiverJoinsAppliesAndLearnsInOrder"],
    },
    {
        "name": "the daemon admits without a room end",
        "file": HANDSHAKE,
        "old": "r.cards.RoomCards(in.ctx, in.object.RoomID, roomEndsAtUnix, learned.cards)",
        "new": "r.cards.RoomCards(in.ctx, in.object.RoomID, 0, learned.cards)",
        "package": DAEMON,
        "tests": ["TestRoomReceiverJoinsAppliesAndLearnsInOrder"],
    },
]


class ScriptError(Exception):
    pass


def replace_once(path, old, new):
    # Both sides must be non-empty and distinct, or the reverse edit could
    # not find its text exactly once.
    if not old or not new or old == new:
        raise ScriptError(f"{path}: an edit needs a non-empty old and new text that differ")
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise ScriptError(f"{path}: the edit text occurs {text.count(old)} times, not once")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def run_tests(package, tests):
    pattern = "^(" + "|".join(tests) + ")$"
    result = subprocess.run(
        ["go", "test", "-count=1", "-run", pattern, "-v", package],
        capture_output=True, text=True, check=False)
    return result.returncode, result.stdout + result.stderr


def built(output):
    return not re.search(r"\[build failed\]|\[setup failed\]|^# ", output, re.MULTILINE)


def ran_all(output, tests):
    return all(re.search(rf"^(--- PASS|--- FAIL): {re.escape(test)} ", output, re.MULTILINE) for test in tests)


def main():
    root = pathlib.Path.cwd()
    if not (root / "go.mod").is_file() or not (root / API).is_file():
        raise ScriptError("run from the repository root")
    if not os.environ.get("TOS_OPENMLS_DRIVER"):
        raise ScriptError("TOS_OPENMLS_DRIVER is not set; the daemon room tests would skip")
    for control in CONTROLS:
        # Check every edit before any file changes.
        text = (root / control["file"]).read_text(encoding="utf-8")
        if not control["old"] or not control["new"] or control["old"] == control["new"] or \
                text.count(control["old"]) != 1 or text.count(control["new"]) != 0:
            raise ScriptError(f"control '{control['name']}' is not an exact-once reversible edit")
    survivors = []
    for control in CONTROLS:
        path = root / control["file"]
        original = path.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        code, output = run_tests(control["package"], control["tests"])
        if code != 0 or not built(output) or not ran_all(output, control["tests"]):
            raise ScriptError(f"baseline of {control['tests']} does not pass:\n{output}")
        replace_once(path, control["old"], control["new"])
        try:
            code, output = run_tests(control["package"], control["tests"])
        finally:
            replace_once(path, control["new"], control["old"])
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ScriptError(f"{path}: the reverse edit did not restore the original bytes")
        if not built(output):
            raise ScriptError(f"mutation '{control['name']}' does not build:\n{output}")
        caught = [test for test in control["tests"]
                  if re.search(rf"^\s*--- FAIL: {re.escape(test)} ", output, re.MULTILINE)]
        if caught:
            print(f"CAUGHT   {control['name']}: --- FAIL: {', '.join(caught)}")
        else:
            print(f"SURVIVED {control['name']}")
            survivors.append(control["name"])
    if survivors:
        print(f"{len(survivors)} of {len(CONTROLS)} controls survived")
        return 1
    print(f"all {len(CONTROLS)} controls caught")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ScriptError as error:
        print(f"script error: {error}", file=sys.stderr)
        sys.exit(2)
