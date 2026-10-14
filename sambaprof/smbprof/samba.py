"""Samba's own tools: where the counters are, their layout, and
switching profiling in one process (smbcontrol PID profile ...)."""

from __future__ import annotations

import json
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor

from .layout import Layout

SEARCH = ("/usr/bin", "/usr/sbin", "/usr/local/samba/bin",
          "/usr/local/samba/sbin")
# Not "flush": see tdb.wipe().
SET_LEVELS = ("off", "count", "on")
# smbcontrol profilelevel replies
REPLY = {"not enabled": "unsupported", "off": "off", "count only": "count",
         "count and time": "on"}


class SambaError(Exception):
    pass


class Samba:
    def __init__(self, prefix: str | None = None,
                 configfile: str | None = None) -> None:
        self.prefix = prefix
        self.configfile = configfile
        if prefix:
            self.path = [os.path.join(prefix, "bin"),
                         os.path.join(prefix, "sbin")]
        else:
            self.path = os.environ.get("PATH", "").split(os.pathsep) + \
                list(SEARCH)
        self._params: dict = {}

    def tool(self, name: str) -> str:
        for d in self.path:
            p = os.path.join(d, name)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        where = f" under {self.prefix}" if self.prefix else \
            " (--samba DIR names a Samba install)"
        raise SambaError(f"{name} not found{where}")

    def run(self, name: str, args: list[str],
            timeout: float = 30) -> subprocess.CompletedProcess:
        cmd = [self.tool(name)]
        if self.configfile:
            cmd.append(f"--configfile={self.configfile}")
        try:
            return subprocess.run(cmd + args, capture_output=True, text=True,
                                  timeout=timeout)
        except subprocess.TimeoutExpired:
            raise SambaError(f"{name} {' '.join(args)}: no answer in "
                             f"{timeout:g} s") from None

    def profile_text(self) -> str:
        r = self.run("smbstatus", ["--profile"])
        if r.returncode != 0 or "****" not in r.stdout:
            msg = (r.stderr or r.stdout).strip().splitlines()
            raise SambaError("smbstatus --profile: " +
                             (msg[-1] if msg else f"exit {r.returncode}"))
        return r.stdout

    def layout(self) -> Layout:
        return Layout.from_profile_text(self.profile_text())

    def param(self, name: str, section: str | None = None) -> str | None:
        """A parameter's value as testparm resolves it."""
        key = (name, section)
        if key not in self._params:
            cmd = [self.tool("testparm"), "-s", f"--parameter-name={name}"]
            if section:
                cmd.append(f"--section-name={section}")
            if self.configfile:
                cmd.append(self.configfile)
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=30)
            self._params[key] = r.stdout.strip() if r.returncode == 0 \
                else None
        return self._params[key]

    def tdb_path(self) -> str:
        d = self.param("cache directory")
        if not d:
            raise SambaError("testparm did not give the cache directory")
        return os.path.join(d, "smbprofile.tdb")

    def main_pid(self) -> int | None:
        """The main smbd, from its pidfile."""
        d = self.param("pid directory")
        try:
            with open(os.path.join(d or "", "smbd.pid")) as f:
                pid = int(f.read().strip())
        except (OSError, ValueError):
            return None
        return pid if os.path.exists(f"/proc/{pid}") else None

    def version(self) -> str:
        r = self.run("smbstatus", ["-V"])
        return r.stdout.strip().replace("Version ", "")

    def get_level(self, pid: int) -> str | None:
        r = self.run("smbcontrol", ["-t", "5", str(pid), "profilelevel"],
                     timeout=15)
        m = re.search(r"Profiling (.+) on pid \d+", r.stdout)
        return REPLY.get(m.group(1)) if m else None

    def set_level(self, pid: int, level: str) -> bool:
        if level not in SET_LEVELS:
            raise ValueError(level)
        r = self.run("smbcontrol", [str(pid), "profile", level], timeout=15)
        return r.returncode == 0

    def get_levels(self, pids: list[int]) -> dict[int, str | None]:
        with ThreadPoolExecutor(max_workers=16) as ex:
            return dict(zip(pids, ex.map(self.get_level, pids)))

    def set_levels(self, pids: list[int], level: str) -> dict[int, bool]:
        with ThreadPoolExecutor(max_workers=16) as ex:
            return dict(zip(pids, ex.map(
                lambda p: self.set_level(p, level), pids)))

    def sessions(self) -> dict[int, list[dict]]:
        """Sessions by smbd pid (user, machine, dialect, encryption,
        signing); empty when smbstatus cannot say."""
        try:
            r = self.run("smbstatus", ["-p", "--json"])
            data = json.loads(r.stdout)
        except (SambaError, ValueError, OSError):
            return {}
        out: dict[int, list[dict]] = {}
        for s in (data.get("sessions") or {}).values():
            try:
                pid = int(s["server_id"]["pid"])
            except (KeyError, TypeError, ValueError):
                continue
            out.setdefault(pid, []).append({
                "user": s.get("username"),
                "machine": s.get("remote_machine"),
                "dialect": s.get("session_dialect"),
                "encryption": (s.get("encryption") or {}).get("cipher"),
                "signing": (s.get("signing") or {}).get("cipher"),
            })
        return out
