"""A recording read back: samples, the processes and shares behind them,
and sums of their counters over any selection."""

from __future__ import annotations

import gzip
import json
import os
from dataclasses import dataclass, field

from .layout import Layout
from .smbd import host_of, serves, with_port

SMB2_NAMES = {
    "smb2_negprot": "NEGOTIATE", "smb2_sesssetup": "SESSION_SETUP",
    "smb2_logoff": "LOGOFF", "smb2_tcon": "TREE_CONNECT",
    "smb2_tdis": "TREE_DISCONNECT", "smb2_create": "CREATE",
    "smb2_close": "CLOSE", "smb2_flush": "FLUSH", "smb2_read": "READ",
    "smb2_write": "WRITE", "smb2_lock": "LOCK", "smb2_ioctl": "IOCTL",
    "smb2_cancel": "CANCEL", "smb2_keepalive": "ECHO",
    "smb2_find": "QUERY_DIRECTORY", "smb2_notify": "CHANGE_NOTIFY",
    "smb2_getinfo": "QUERY_INFO", "smb2_setinfo": "SET_INFO",
    "smb2_break": "OPLOCK_BREAK",
}
SHORT = {"FIND": "smb2_find", "GETINFO": "smb2_getinfo",
         "SETINFO": "smb2_setinfo", "NOTIFY": "smb2_notify",
         "BREAK": "smb2_break", "TCON": "smb2_tcon", "TDIS": "smb2_tdis",
         "NEGPROT": "smb2_negprot", "SESSSETUP": "smb2_sesssetup",
         "KEEPALIVE": "smb2_keepalive"}
# Requests that wait for an event (a change, a lease break) rather than
# work: left out of time totals unless asked for.
WAITS = ("smb2_notify",)
BIN_LABELS = ("<1ms", "1-2ms", "2-4ms", "4-8ms", "8-16ms", "16-32ms",
              "32-64ms", "64-128ms", "128-256ms", ">=256ms")
SECTION_SMB2 = "SMB2 Calls"
SECTION_SYSCALLS = "System Calls"


def label(name: str) -> str:
    if name in SMB2_NAMES:
        return SMB2_NAMES[name]
    return name[8:] if name.startswith("syscall_") else name


def resolve_ops(text: str, layout: Layout) -> list[str]:
    """Counter names for a comma list of SMB2 command names, short forms
    or Samba's names (smb2_read, syscall_openat, openat)."""
    by_label = {v: k for k, v in SMB2_NAMES.items()}
    out = []
    for item in filter(None, (s.strip() for s in text.split(","))):
        u = item.upper()
        name = by_label.get(u) or SHORT.get(u) or item
        if name not in layout.by_name and "syscall_" + item in layout.by_name:
            name = "syscall_" + item
        if name not in layout.by_name:
            raise ValueError(f"unknown counter {item!r}")
        out.append(name)
    return out


def open_text(path: str):
    with open(path, "rb") as f:
        gz = f.read(2) == b"\x1f\x8b"
    return gzip.open(path, "rt") if gz else open(path)


class Acc:
    """Sums of counter deltas: {counter: {field: int or bucket list}}."""

    def __init__(self) -> None:
        self.c: dict[str, dict] = {}

    def add(self, d: dict) -> None:
        for name, fields in d.items():
            tgt = self.c.setdefault(name, {})
            for f, v in fields.items():
                if isinstance(v, list):
                    cur = tgt.get(f)
                    tgt[f] = [a + b for a, b in zip(cur, v)] if cur \
                        else list(v)
                else:
                    tgt[f] = tgt.get(f, 0) + v

    def merge(self, other: "Acc") -> None:
        self.add(other.c)

    def get(self, name: str, f: str) -> int:
        return self.c.get(name, {}).get(f, 0)

    def buckets(self, name: str) -> list[int] | None:
        return self.c.get(name, {}).get("buckets")

    def names(self, layout: Layout, section: str) -> list[str]:
        return [c.name for c in layout.counters
                if c.section == section and c.name in self.c]

    def smb2(self, layout: Layout, waits: bool = False) -> dict:
        """Totals over SMB2 commands; waits only count requests."""
        t = {"count": 0, "failed": 0, "time": 0, "idle": 0, "in": 0,
             "out": 0}
        for name in self.names(layout, SECTION_SMB2):
            t["count"] += self.get(name, "count")
            t["failed"] += self.get(name, "failed_count")
            t["in"] += self.get(name, "inbytes")
            t["out"] += self.get(name, "outbytes")
            if waits or name not in WAITS:
                t["time"] += self.get(name, "time")
                t["idle"] += self.get(name, "idle")
        return t

    def cpu(self) -> int:
        return self.get("cpu_user", "time") + self.get("cpu_system", "time")


def bins(buckets: list[int] | None) -> list[int] | None:
    """Requests per latency bin, from Samba's cumulative buckets
    (below 1, 2, 4 ... 256 ms, then all)."""
    if not buckets:
        return None
    return [buckets[0]] + [buckets[i] - buckets[i - 1]
                           for i in range(1, len(buckets))]


def bin_of(buckets: list[int] | None, p: float) -> int | None:
    """The bin holding the p-th percentile."""
    if not buckets or not buckets[-1]:
        return None
    want = p / 100 * buckets[-1]
    for i, v in enumerate(buckets):
        if v >= want:
            return i
    return len(buckets) - 1


def pct_label(buckets: list[int] | None, p: float) -> str:
    i = bin_of(buckets, p)
    return "-" if i is None else BIN_LABELS[i]


@dataclass
class Selection:
    t_from: float | None = None
    t_to: float | None = None
    clients: list[str] = field(default_factory=list)
    pids: list[int] = field(default_factory=list)
    shares: list[str] = field(default_factory=list)


class Run:
    def __init__(self, path: str) -> None:
        self.path = path
        self.name = os.path.basename(path)
        self.meta: dict = {}
        self.end: dict = {}
        self.procs: dict[int, dict] = {}
        self.shares: dict[str, dict] = {}
        self.samples: list[dict] = []
        self.exits: dict[int, float] = {}
        self.events: list[dict] = []
        with open_text(path) as f:
            for n, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    if n == 1:
                        raise ValueError(f"{path}: not a recording")
                    break  # cut short while being written
                self._take(rec)
        if self.meta.get("tool") != "smb-prof-record":
            raise ValueError(f"{path}: not an smb-prof-record recording")
        self.layout = Layout.from_json(self.meta["layout"])
        self.t0 = self.samples[0]["t"] if self.samples else self.meta["time"]
        self.t1 = self.samples[-1]["t"] if self.samples else self.t0

    def _take(self, rec: dict) -> None:
        kind = rec.get("type")
        if kind == "sample":
            self.samples.append(rec)
        elif kind == "proc":
            info = self.procs.setdefault(rec["pid"], {"clients": []})
            clients = sorted(set(info["clients"]) | set(rec.get("clients")
                                                         or []))
            info.update(rec)
            info["clients"] = clients
        elif kind == "share":
            self.shares[rec["key"]] = rec
        elif kind == "exit":
            self.exits[rec["pid"]] = rec["t"]
        elif kind == "start":
            self.meta = rec
        elif kind == "end":
            self.end = rec
        elif kind == "event":
            self.events.append(rec)

    @property
    def duration(self) -> float:
        return self.t1 - self.t0

    @property
    def times(self) -> bool:
        """Whether time and latency buckets were counted."""
        return self.meta.get("level") != "count"

    def proc_label(self, pid: int) -> str:
        info = self.procs.get(pid, {})
        if info.get("main"):
            return "(closed)"
        hosts = sorted({host_of(c) for c in info.get("clients", [])})
        return ",".join(hosts) if hosts else f"pid {pid}"

    def users(self, pid: int) -> str:
        return ",".join(sorted(set(self.procs.get(pid, {}).get("users",
                                                                 [])))) or "-"

    def has_shares(self) -> bool:
        return any(s.get("shares") for s in self.samples)

    def window(self, sel: Selection):
        for s in self.samples:
            if not s.get("dt"):
                continue
            if sel.t_from is not None and s["t"] <= sel.t_from:
                continue
            if sel.t_to is not None and s["t"] - s["dt"] >= sel.t_to:
                continue
            yield s

    def seconds(self, sel: Selection) -> float:
        return sum(s["dt"] for s in self.window(sel))

    def proc_items(self, sel: Selection):
        """(sample, pid, entry) for the processes chosen."""
        want = None
        if sel.clients or sel.pids:
            want = {pid for pid, info in self.procs.items()
                    if pid in sel.pids or any(
                        serves(info.get("clients", []), c)
                        for c in sel.clients)}
        for s in self.window(sel):
            for k, e in s["procs"].items():
                pid = int(k)
                if want is None or pid in want:
                    yield s, pid, e

    def share_items(self, sel: Selection):
        """(sample, key, entry) for the per-share records chosen."""
        names = {n.lower() for n in sel.shares}
        for s in self.window(sel):
            for key, e in s.get("shares", {}).items():
                info = self.shares.get(key, {})
                if names and info.get("share", "").lower() not in names:
                    continue
                if sel.pids and info.get("pid") not in sel.pids:
                    continue
                if sel.clients and not any(
                        serves([with_port(info.get("remote", ""))], c) or
                        serves(self.procs.get(info.get("pid"), {}).get(
                            "clients", []), c) for c in sel.clients):
                    continue
                yield s, key, e
