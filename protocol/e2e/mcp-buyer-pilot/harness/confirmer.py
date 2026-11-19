"""Drive the real `tos-service-buyer confirm --watch` on a pseudo-terminal.

The pty set-up is the MCP buyer e2e harness's (protocol/e2e/mcp-buyer/
harness/confirmer.py): the confirmer refuses any input that is not a
terminal the custody account owns and that is the controlling terminal of
its own session. So the slave side is chowned to custody (mode 0620), and
the child starts a new session with setsid(), makes the slave its
controlling terminal with TIOCSCTTY, drops to custody's uid and gid with no
supplementary groups, and only then executes the confirmer.

What differs: the confirmer runs with --watch for the whole pilot, and each
presentation is decided by confirm_policy, not typed blindly. The code is
typed only when the policy confirms; otherwise "decline" is typed. Nothing
here is a human.
"""

import fcntl
import os
import pty
import re
import select
import termios
import time

import confirm_policy

DECIDED = re.compile(rb"(Purchase \S+ is now \S+\.|Not paid: [^\r\n]*)")


class WatchConfirmer:
    def __init__(self, binary: str, socket: str, uid: int, gid: int, env: dict):
        self.binary, self.socket, self.uid, self.gid, self.env = binary, socket, uid, gid, env
        self.master = -1
        self.pid = -1
        self.screen = b""
        self.offset = 0

    def start(self) -> None:
        master, slave = pty.openpty()
        slave_name = os.ttyname(slave)
        os.chown(slave_name, self.uid, self.gid)
        os.chmod(slave_name, 0o620)
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
                os.setgroups([])
                os.setgid(self.gid)
                os.setuid(self.uid)
                os.execve(self.binary, [self.binary, "confirm", "--watch", "--interval", "5s", "--agent-socket",
                                        self.socket], self.env)
            finally:
                os._exit(127)
        os.close(slave)
        self.master, self.pid = master, pid

    def alive(self) -> bool:
        pid, _ = os.waitpid(self.pid, os.WNOHANG)
        return pid == 0

    def read(self, timeout: float) -> None:
        ready, _, _ = select.select([self.master], [], [], timeout)
        if ready:
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                chunk = b""
            if not chunk:
                raise EOFError("the confirmer closed its terminal")
            self.screen += chunk

    def pending_presentation(self) -> str | None:
        """The text of a complete, undecided presentation, if one is shown."""
        text = self.screen[self.offset:].decode("utf-8", "replace")
        if confirm_policy.PROMPT not in text:
            return None
        return text

    def answer(self, typed: str, timeout: float = 120) -> str:
        """Type one decision line and wait for the confirmer's outcome."""
        os.write(self.master, typed.encode() + b"\n")
        self.offset = len(self.screen)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = DECIDED.search(self.screen, self.offset)
            if found:
                self.offset = found.end()
                return found.group(1).decode("utf-8", "replace")
            self.read(1)
        raise TimeoutError("the confirmer did not report the outcome")

    def finish(self, timeout: float = 30) -> int:
        deadline = time.monotonic() + timeout
        os.close(self.master)
        while time.monotonic() < deadline:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                return os.waitstatus_to_exitcode(status)
            time.sleep(0.2)
        # Container root holds no KILL capability for another account's
        # process; a confirmer that outlived its closed terminal is reported.
        return -1
