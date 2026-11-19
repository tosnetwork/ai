"""Drive the real `tos-service-buyer confirm` on a pseudo-terminal.

The confirmer refuses any input that is not a terminal the custody account
owns and that is the controlling terminal of its own session. This helper
gives it exactly that: a fresh pty whose slave side is owned by custody
(mode 0620), a child that starts a new session with setsid(), makes the
slave its controlling terminal with TIOCSCTTY, drops to the custody uid and
gid with no supplementary groups, and only then executes the confirmer.

The parent reads the confirmer's screen from the master side, finds the
confirmation code the confirmer shows, and types it.
"""

import fcntl
import os
import pty
import re
import select
import termios
import time

CODE_LINE = re.compile(rb"Confirmation code:\s+(\S+) \(valid until")


class Confirmer:
    def __init__(self, binary: str, socket: str, uid: int, gid: int, env: dict):
        self.binary, self.socket, self.uid, self.gid, self.env = binary, socket, uid, gid, env
        self.master = -1
        self.pid = -1
        self.screen = b""

    def start(self) -> None:
        master, slave = pty.openpty()
        slave_name = os.ttyname(slave)
        # The confirmer requires a terminal its own account owns.
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
                os.execve(self.binary, [self.binary, "confirm", "--agent-socket", self.socket], self.env)
            finally:
                os._exit(127)
        os.close(slave)
        self.master, self.pid = master, pid

    def read_until(self, pattern: re.Pattern, timeout: float) -> re.Match:
        deadline = time.monotonic() + timeout
        while True:
            found = pattern.search(self.screen)
            if found:
                return found
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("the confirmer did not show the expected text")
            ready, _, _ = select.select([self.master], [], [], remaining)
            if ready:
                try:
                    chunk = os.read(self.master, 65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    raise EOFError("the confirmer closed its terminal")
                self.screen += chunk

    def confirm(self, timeout: float = 120) -> str:
        """Wait for a presented purchase and type its code; return the code."""
        code = self.read_until(CODE_LINE, timeout).group(1).decode()
        self.read_until(re.compile(rb"press Enter to skip: "), timeout)
        os.write(self.master, code.encode() + b"\n")
        self.read_until(re.compile(rb"is now \S+\."), timeout)
        return code

    def finish(self, timeout: float = 30) -> int:
        """Close the terminal and reap the confirmer; return its exit status."""
        deadline = time.monotonic() + timeout
        os.close(self.master)
        while time.monotonic() < deadline:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                return os.waitstatus_to_exitcode(status)
            time.sleep(0.2)
        os.kill(self.pid, 9)
        _, status = os.waitpid(self.pid, 0)
        return os.waitstatus_to_exitcode(status)
