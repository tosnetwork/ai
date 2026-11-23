"""Drive one real confirmer decision on a terminal the custody account owns.

Run AS the custody account (the driver starts it with `sudo -u <custody>`).
It opens a fresh pseudo-terminal; the kernel gives the slave side to the
account that opened it, so the terminal is the custody account's own. A
child starts a new session with setsid(), makes the slave its controlling
terminal with TIOCSCTTY and only then executes the real confirmer
(`tos-service-provider confirm --watch` or `tos-service-buyer confirm
--watch`). The confirmer's own checks (input is a terminal, owned by this
account, controlling terminal of its own session; the socket is owned by
this account) therefore run unmodified.

The parent reads the confirmer's screen and decides exactly one
presentation: the one whose reference equals --reference and whose kind
equals --kind. Every other presentation is skipped (Enter). Only the part
of the screen after the protocol heading is read, so text in the untrusted
block cannot imitate a field. For a confirm decision every --expect
"Label=text" pair must appear as a protocol line "Label: ..." whose value
contains the text; if one does not, "decline" is typed instead and the
result says why.

stdout is one JSON object: the decision, the confirmer's outcome line, the
SHA-256 of the whole screen, the terminal facts. The confirmation code
never leaves this process: it is neither printed nor logged.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pty
import re
import select
import sys
import termios
import time

PROGRAMS = {
    "provider": {
        "protocol_heading": "==== TOS protocol fields, from the provider agent's own records ====",
        "waiting": re.compile(r"Action (\S+) \((\S+)\) is waiting for your decision\."),
        "prompt": 'Type the confirmation code to confirm, "decline" to decline, or press Enter to skip: ',
        "decided": re.compile(r"(Action \S+ is now \S+\.|Not confirmed: [^\r\n]*)"),
    },
    "buyer": {
        "protocol_heading": "==== TOS protocol fields, from the buyer agent's verified records ====",
        "waiting": re.compile(r"Purchase (\S+) is waiting for your decision\."),
        "prompt": 'Type the confirmation code to pay, "decline" to decline, or press Enter to skip: ',
        "decided": re.compile(r"(Purchase \S+ is now \S+\.|Not paid: [^\r\n]*)"),
    },
}
CODE = re.compile(r"^Confirmation code:\s+(\S+) \(valid until .+\)$", re.M)
FIELD = re.compile(r"^([A-Za-z][A-Za-z _()/-]*?):\s+(.*?)\s*$")


class Terminal:
    def __init__(self, argv: list[str]):
        master, slave = pty.openpty()
        self.slave_name = os.ttyname(slave)
        stat = os.stat(self.slave_name)
        self.slave_owner_uid, self.slave_mode = stat.st_uid, oct(stat.st_mode & 0o777)
        pid = os.fork()
        if pid == 0:
            try:
                os.close(master)
                os.setsid()
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
                for fd in (0, 1, 2):
                    os.dup2(slave, fd)
                if slave > 2:
                    os.close(slave)
                os.execv(argv[0], argv)
            finally:
                os._exit(127)
        os.close(slave)
        self.master, self.pid, self.screen = master, pid, ""

    def read(self, timeout: float) -> None:
        ready, _, _ = select.select([self.master], [], [], timeout)
        if not ready:
            return
        try:
            chunk = os.read(self.master, 65536)
        except OSError:
            chunk = b""
        if not chunk:
            raise EOFError("the confirmer closed its terminal")
        self.screen += chunk.decode("utf-8", "replace").replace("\r\n", "\n")

    def type(self, line: str) -> None:
        os.write(self.master, line.encode() + b"\n")

    def close(self) -> int | None:
        os.close(self.master)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                return os.waitstatus_to_exitcode(status)
            time.sleep(0.2)
        return None


def protocol_fields(block: str, heading: str) -> dict | None:
    """Label -> value of the protocol block, or None when the heading does not
    appear exactly once."""
    if block.count(heading) != 1:
        return None
    fields = {}
    for line in block.split(heading, 1)[1].splitlines():
        found = FIELD.match(line)
        if found and found.group(1) not in fields:
            fields[found.group(1).strip()] = found.group(2)
    return fields


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", choices=sorted(PROGRAMS), required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--reference", required=True, help="the action or purchase reference the model showed")
    parser.add_argument("--kind", default="", help="provider action kind (offer, withdraw, resume)")
    parser.add_argument("--decision", choices=("confirm", "decline"), required=True)
    parser.add_argument("--expect", action="append", default=[], help="Label=value a protocol line must show")
    parser.add_argument("--timeout", type=float, default=600)
    args = parser.parse_args()
    program = PROGRAMS[args.program]
    expect = dict(item.split("=", 1) for item in args.expect)
    terminal = Terminal([args.binary, "confirm", "--watch", "--interval", "2s", "--agent-socket", args.socket])
    result = {
        "schema": "tos.service.acceptance-custody-confirmation.v1",
        "program": args.program,
        "reference": args.reference,
        "kind": args.kind,
        "requested_decision": args.decision,
        "account_uid": os.getuid(),
        "terminal": {
            "kind": "pseudo-terminal opened by the custody account",
            "slave_owner_uid": terminal.slave_owner_uid,
            "slave_mode": terminal.slave_mode,
            "controlling_terminal_of_own_session": True,
        },
        "driven_by": "harness",
        "skipped": [],
        "typed": None,
        "outcome": None,
    }
    offset, deadline = 0, time.monotonic() + args.timeout
    try:
        while time.monotonic() < deadline and result["outcome"] is None:
            terminal.read(1)
            pending = terminal.screen[offset:]
            if program["prompt"] not in pending:
                continue
            presentation = pending[: pending.index(program["prompt"])]
            waiting = program["waiting"].findall(presentation)
            shown = waiting[-1] if waiting else None
            reference = shown[0] if isinstance(shown, tuple) else shown
            kind = shown[1] if isinstance(shown, tuple) else ""
            if reference != args.reference or (args.kind and kind != args.kind):
                terminal.type("")
                result["skipped"].append({"reference": reference, "kind": kind})
                offset = len(terminal.screen)
                continue
            fields = protocol_fields(presentation, program["protocol_heading"]) or {}
            mismatched = {
                label: fields.get(label) for label, value in expect.items() if value not in (fields.get(label) or "")
            }
            code = CODE.search(presentation.split(program["protocol_heading"], 1)[-1])
            typed = "decline"
            if args.decision == "confirm" and not mismatched and code:
                typed = code.group(1)
            result["typed"] = "code" if typed != "decline" else "decline"
            result["mismatched_expectations"] = mismatched
            result["protocol_fields"] = {k: v for k, v in fields.items() if k != "Confirmation code"}
            terminal.type(typed)
            offset = len(terminal.screen)
            while time.monotonic() < deadline:
                found = program["decided"].search(terminal.screen, offset)
                if found:
                    result["outcome"] = found.group(1)
                    break
                terminal.read(1)
    except EOFError as error:
        result["error"] = str(error)
    finally:
        # The screen holds the code; only its digest leaves this process.
        result["screen_sha256"] = hashlib.sha256(terminal.screen.encode()).hexdigest()
        result["confirmer_exit"] = terminal.close()
    print(json.dumps(result, sort_keys=True))
    ok = result["outcome"] is not None and result["typed"] == ("code" if args.decision == "confirm" else "decline")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
