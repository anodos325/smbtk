"""perf's control FIFOs: start with events off, then switch them on and
off at the moments that matter."""

from __future__ import annotations

import ctypes
import errno
import os
import select
import signal
import subprocess
import time


def _die_with_parent() -> None:
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGINT)  # PR_SET_PDEATHSIG
    except (OSError, AttributeError):
        pass


def start(cmd: list[str], **kw) -> subprocess.Popen:
    """perf in its own session, so Ctrl-C reaches only the tool, which
    stops perf in order; perf gets SIGINT if the tool dies first."""
    return subprocess.Popen(cmd, start_new_session=True,
                            preexec_fn=_die_with_parent, **kw)


def stop(proc: subprocess.Popen, timeout: float = 300) -> None:
    """perf writes out what it has on SIGINT; that can take a while."""
    if proc.poll() is None:
        proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


class Control:
    def __init__(self, directory: str) -> None:
        self.ctl = os.path.join(directory, "ctl.fifo")
        self.ack = os.path.join(directory, "ack.fifo")
        os.mkfifo(self.ctl, 0o600)
        os.mkfifo(self.ack, 0o600)
        self.wfd: int | None = None
        self.rfd: int | None = None

    def args(self) -> list[str]:
        return ["-D", "-1", f"--control=fifo:{self.ctl},{self.ack}"]

    def connect(self, proc: subprocess.Popen, timeout: float = 60) -> bool:
        """Wait for perf to open its end; False if it exits first."""
        deadline = time.monotonic() + timeout
        self.rfd = os.open(self.ack, os.O_RDONLY | os.O_NONBLOCK)
        while True:
            try:
                self.wfd = os.open(self.ctl, os.O_WRONLY | os.O_NONBLOCK)
                return True
            except OSError as e:
                if e.errno != errno.ENXIO:
                    raise
            if proc.poll() is not None or time.monotonic() > deadline:
                return False
            time.sleep(0.01)

    def send(self, command: str, proc: subprocess.Popen,
             timeout: float = 60) -> bool:
        """Send enable or disable and wait for perf's ack."""
        os.write(self.wfd, (command + "\n").encode())
        buf = b""
        deadline = time.monotonic() + timeout
        while b"ack" not in buf:
            if proc.poll() is not None or time.monotonic() > deadline:
                return False
            r, _, _ = select.select([self.rfd], [], [], 0.05)
            if r:
                chunk = os.read(self.rfd, 64)
                if not chunk:
                    time.sleep(0.01)
                buf += chunk
        return True

    def close(self) -> None:
        for fd in (self.wfd, self.rfd):
            if fd is not None:
                os.close(fd)
        self.wfd = self.rfd = None
