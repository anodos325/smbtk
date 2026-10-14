"""Successive snapshots of the profile tdb turned into what each process
and share did in each interval.

What the records do, and how it is undone here:
- a process's record is cumulative; cpu_user/cpu_system are its whole
  rusage, so a record that appears for a process already running is
  measured from the CPU /proc gave when the process was first seen;
- a reset deletes every record: counts that go down start again
  from zero;
- when a process exits, cleanupd adds its record to the main smbd's:
  the counts already seen are taken back out of the main record's
  growth, and if one process left, what remains is its last moments.
"""

from __future__ import annotations

import re
import sys

from .layout import GAUGES, Layout
from .smbd import Proc

SHARE_KEY = re.compile(
    r"(?P<share>.*):(?P<pid>\d+)\.(?P<snum>\d+)\[(?P<remote>.*)\]")
DEBT_TTL = 120.0


def share_key(key: bytes) -> dict | None:
    """'share:pid.snum[remote]' of a per-share record."""
    try:
        text = key.rstrip(b"\0").decode()
    except UnicodeDecodeError:
        return None
    m = SHARE_KEY.fullmatch(text)
    if not m:
        return None
    return {"key": text, "share": m["share"], "pid": int(m["pid"]),
            "snum": int(m["snum"]), "remote": m["remote"]}


class Collector:
    def __init__(self, layout: Layout, magics: set[int] | None = None):
        self.layout = layout
        self.magics = magics or set()
        self.last_p: dict[int, tuple] = {}
        self.last_s: dict[str, tuple] = {}
        self.started: dict[int, int] = {}
        self.cpu_base: dict[int, tuple[int, int]] = {}
        self.gauges: dict[int, tuple] = {}
        self.described: dict[int, tuple] = {}
        self.clients: dict[int, set[str]] = {}
        self.debts: list[list] = []
        self.t: float | None = None
        self.mono = 0.0
        self.foreign = 0
        skip = set(layout.gauge_words) | set(layout.cpu_words)
        self.mono_idx = [i for i in range(layout.words) if i not in skip]
        self.gauge_names = [g for g in GAUGES if g in layout.by_name]

    def decode(self, records: dict[bytes, bytes]):
        procs: dict[int, tuple] = {}
        shares: dict[str, tuple[dict, tuple]] = {}
        sizes = self.layout.record_sizes()
        for k, v in records.items():
            if len(v) not in sizes:
                continue
            magic, _, words = self.layout.unpack(v)
            if len(k) == 4:
                if self.magics and magic not in self.magics:
                    self.foreign += 1
                    continue
                procs[int.from_bytes(k, sys.byteorder, signed=True)] = words
            elif len(k) >= 5:
                info = share_key(k)
                if info:
                    shares[info["key"]] = (info, words)
        return procs, shares

    def _delta(self, cur: tuple, last: tuple) -> list[int]:
        d = [c - p for c, p in zip(cur, last)]
        if any(d[i] < 0 for i in self.mono_idx):
            for i in self.mono_idx:
                d[i] = cur[i]
        for i in self.layout.cpu_words:
            d[i] = max(d[i], 0)
        return d

    def _settle(self, d: list[int], t: float) -> list[int]:
        """Exited processes whose last counts the main record's growth
        `d` covers; their counts are taken out of `d`."""
        settled = []
        for debt in list(self.debts):
            pid, words, since = debt
            if all(d[i] >= words[i] for i in self.mono_idx):
                for i in self.mono_idx:
                    d[i] -= words[i]
                for i in self.layout.cpu_words:
                    d[i] = max(d[i] - words[i], 0)
                settled.append(pid)
                self.debts.remove(debt)
            elif t - since > DEBT_TTL:
                self.debts.remove(debt)
        return settled

    def _entry(self, pid: int, d: list[int] | None, cur: tuple) -> dict:
        e = {}
        if d is not None:
            for i in self.layout.gauge_words:
                d[i] = 0
            sp = self.layout.sparse(d)
            if sp:
                e["d"] = sp
        g = tuple(cur[self.layout.by_name[n].offset]
                  for n in self.gauge_names)
        if g != self.gauges.get(pid):
            self.gauges[pid] = g
            e["g"] = dict(zip(self.gauge_names, g))
        return e

    def _describe(self, pid: int, p: Proc | None, main: int | None,
                  t: float, extra: dict) -> dict | None:
        info = {"pid": pid, "main": pid == main}
        if p is not None:
            seen = self.clients.setdefault(pid, set())
            seen.update(p.clients)
            info.update(ppid=p.ppid, comm=p.comm, clients=sorted(seen))
        info.update(extra.get(pid, {}))
        sig = tuple(sorted((k, str(v)) for k, v in info.items()))
        if self.described.get(pid) == sig:
            return None
        self.described[pid] = sig
        if p is not None:
            info["started"] = round(p.started, 3)
        return {"type": "proc", "t": t, **info}

    def sample(self, t: float, mono: float, records: dict[bytes, bytes],
               procs: dict[int, Proc], main: int | None,
               extra: dict[int, dict] | None = None) -> list[dict]:
        """Lines for one snapshot: proc, share and exit lines, then the
        sample. `procs` are the smbd processes running now."""
        extra = extra or {}
        p_now, s_now = self.decode(records)
        first = self.t is None
        prev_t = self.t
        lines: list[dict] = []
        out_p: dict[str, dict] = {}
        out_s: dict[str, dict] = {}
        main_d = None
        for pid in sorted(p_now):
            cur = p_now[pid]
            p = procs.get(pid)
            last = self.last_p.get(pid)
            if last is not None and p is not None and \
                    self.started.get(pid, p.ticks) != p.ticks:
                last = None
            d = None
            if not first:
                if last is None:
                    d = list(cur)
                    # The main record holds only what exited processes
                    # left; any other holds its process's whole CPU.
                    base = self.cpu_base.get(pid)
                    if pid != main and base is not None:
                        for i, b in zip(self.layout.cpu_words, base):
                            d[i] = max(d[i] - b, 0)
                    elif pid != main and (p is None or p.started < prev_t):
                        for i in self.layout.cpu_words:
                            d[i] = 0
                else:
                    d = self._delta(cur, last)
            self.last_p[pid] = cur
            if p is not None:
                self.started[pid] = p.ticks
            info = self._describe(pid, p, main, t, extra)
            if info:
                lines.append(info)
            if pid == main and d is not None:
                main_d = (d, cur)
                continue
            e = self._entry(pid, d, cur)
            if e:
                out_p[str(pid)] = e
        # A record counts from when profiling began in the process: about
        # when it was first seen here, or switched on.
        for pid, p in procs.items():
            if pid not in p_now:
                self.cpu_base.setdefault(pid, p.cpu_us)
            else:
                self.cpu_base.pop(pid, None)
        for pid in [x for x in self.cpu_base if x not in procs]:
            del self.cpu_base[pid]
        for pid in [x for x in self.last_p if x not in p_now]:
            p = procs.get(pid)
            if p is not None and self.started.get(pid, p.ticks) == p.ticks:
                continue
            if pid != main:
                self.debts.append([pid, self.last_p[pid], t])
            for m in (self.last_p, self.started, self.gauges, self.described,
                      self.clients):
                m.pop(pid, None)
            lines.append({"type": "exit", "t": t, "pid": pid})
        if main_d is not None:
            d, cur = main_d
            settled = self._settle(d, t)
            if len(settled) == 1:
                for i in self.layout.gauge_words:
                    d[i] = 0
                sp = self.layout.sparse(d)
                if sp:
                    out_p[str(settled[0])] = {"d": sp, "exit": True}
                    d = [0] * len(d)
            e = self._entry(main, d, cur)
            if e:
                out_p[str(main)] = e
        for key in sorted(s_now):
            info, cur = s_now[key]
            last = self.last_s.get(key)
            if last is None:
                lines.append({"type": "share", "t": t, **info})
            if not first:
                d = list(cur) if last is None else self._delta(cur, last)
                sp = self.layout.sparse(d)
                if sp:
                    out_s[key] = {"d": sp}
            self.last_s[key] = cur
        for key in [k for k in self.last_s if k not in s_now]:
            del self.last_s[key]
        lines.append({"type": "sample", "t": round(t, 6),
                      "dt": round(0.0 if first else mono - self.mono, 6),
                      "procs": out_p, "shares": out_s})
        self.t, self.mono = t, mono
        return lines
