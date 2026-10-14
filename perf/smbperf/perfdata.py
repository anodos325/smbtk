"""Running perf script, and reading the samples it prints."""

from __future__ import annotations

import bisect
import gzip
import hashlib
import json
import os
import re
import subprocess
import tempfile
from typing import IO, Iterable

FORMAT_VERSION = 1
FIELDS = "comm,pid,tid,time,period,event,trace,ip,sym,dso"
SWITCH = "sched:sched_switch"
SYS_ENTER = "raw_syscalls:sys_enter"

# Frame kind bits.
KERNEL = 1
INLINE = 2
MODULE = 8  # in a kernel module (zfs, spl ...)

_HEADER = re.compile(
    r"^\s*(?P<comm>.*?)\s+(?P<pid>-?\d+)(?:/(?P<tid>-?\d+))?\s+"
    r"(?:\[\d+\]\s+)?(?P<time>\d+\.\d+):\s*(?P<rest>.*?)\s*$")
_EVENT = re.compile(
    r"^(?:(?P<period>\d+)\s+)?(?P<event>\S+?):(?:\s+(?P<trace>.*))?$")
_FRAME = re.compile(
    r"^\s*(?P<addr>[0-9a-fA-F]+)\s+(?P<sym>.*?)\s+\((?P<dso>[^()]*)\)\s*$")
_OFFSET = re.compile(r"\+0x[0-9a-fA-F]+$")
_ARGS = re.compile(r"\((?!anonymous namespace\)).*")
_GO = re.compile(r"\.\(.*\)\.")
_STATE = re.compile(r"prev_state=(\S+)")
_NEXT_PID = re.compile(r"next_pid=(\d+)")
_NR = re.compile(r"^NR (\d+)")
_CORE = {"[kernel.kallsyms]", "[guest.kernel.kallsyms]", "[unknown]",
         "inlined", "[vdso]", "[vsyscall]"}


class PerfError(Exception):
    pass


class Profile:
    """The samples of one recording. A sample is (time ns, pid, tid,
    comm id, event id, weight, stack id, aux); stacks are frame ids, root
    first; a frame is (name, dso, kind). For sched_switch the weight is
    the time off the CPU (-1 when the task was not seen back) and aux the
    state it left in; for sys_enter aux is the syscall number."""

    def __init__(self) -> None:
        self.frames: list[tuple[str, str, int]] = []
        self.stacks: list[tuple[int, ...]] = []
        self.comms: list[str] = []
        self.events: list[str] = []
        self.samples: list[tuple] = []
        self.header: dict = {}
        self.warnings: list[str] = []

    def to_json(self) -> dict:
        return {"v": FORMAT_VERSION, "frames": self.frames,
                "stacks": self.stacks, "comms": self.comms,
                "events": self.events, "samples": self.samples,
                "header": self.header, "warnings": self.warnings}

    @classmethod
    def from_json(cls, d: dict) -> Profile:
        if d.get("v") != FORMAT_VERSION:
            raise ValueError("cache format")
        p = cls()
        p.frames = [tuple(f) for f in d["frames"]]
        p.stacks = [tuple(s) for s in d["stacks"]]
        p.comms = d["comms"]
        p.events = d["events"]
        p.samples = [tuple(s) for s in d["samples"]]
        p.header = d["header"]
        p.warnings = d["warnings"]
        return p


def ns(text: str) -> int:
    sec, _, frac = text.partition(".")
    return int(sec) * 1_000_000_000 + int((frac + "000000000")[:9])


def tidy(sym: str, dso: str) -> str:
    """A symbol as flamegraph.pl's stackcollapse-perf.pl writes it."""
    sym = _OFFSET.sub("", sym)
    if sym == "[unknown]":
        if dso and dso != "[unknown]":
            return "[" + dso.rsplit("/", 1)[-1] + "]"
        return sym
    sym = sym.replace(";", ":")
    if "(" in sym and not _GO.search(sym):
        sym = _ARGS.sub("", sym)
    return sym.replace('"', "").replace("'", "")


def parse(lines: Iterable[str]) -> Profile:
    """perf script output, with or without callchains. Lines starting
    with a tab are frames; the header lines of a sample may start with
    spaces (perf pads the name when it prints no callchain)."""
    prof = Profile()
    raw_ids: dict[tuple[str, str, bool, bool], int] = {}
    frame_ids: dict[tuple[str, str, int], int] = {}
    stack_ids: dict[tuple[int, ...], int] = {}
    comm_ids: dict[str, int] = {}
    event_ids: dict[str, int] = {}
    header: list[str] = []
    switch_in: dict[int, list[int]] = {}
    cur: tuple | None = None
    frames: list[int] = []

    def frame(m: re.Match) -> None:
        addr, sym, dso = m.group("addr", "sym", "dso")
        kernel = len(addr) >= 16
        module = kernel and (addr.lower() >= "ffffffffc0000000" or (
            dso.startswith("[") and dso not in _CORE))
        key = (sym, dso, kernel, module)
        fid = raw_ids.get(key)
        if fid is None:
            if sym.startswith("("):
                fid = -1
            else:
                kind = (KERNEL if kernel else 0) | (
                    INLINE if dso == "inlined" else 0) | (
                    MODULE if module else 0)
                f = (tidy(sym, dso), dso, kind)
                fid = frame_ids.get(f)
                if fid is None:
                    fid = frame_ids[f] = len(prof.frames)
                    prof.frames.append(f)
            raw_ids[key] = fid
        if fid >= 0:
            frames.append(fid)

    def finish() -> None:
        nonlocal cur, frames
        if cur is None:
            return
        stack = tuple(reversed(frames))
        sid = stack_ids.get(stack)
        if sid is None:
            sid = stack_ids[stack] = len(prof.stacks)
            prof.stacks.append(stack)
        t, pid, tid, comm, ev, period, aux = cur
        prof.samples.append((t, pid, tid, comm, ev, period, sid, aux))
        cur = None
        frames = []

    for line in lines:
        if line.startswith("\t"):
            if cur is not None:
                m = _FRAME.match(line)
                if m:
                    frame(m)
            continue
        if line.startswith("#"):
            header.append(line)
            continue
        if not line.strip():
            finish()
            continue
        m = _HEADER.match(line)
        if m is None:
            if cur is not None:
                fm = _FRAME.match(line)
                if fm:
                    frame(fm)
            continue
        finish()
        pid, tid = int(m["pid"]), m["tid"]
        if tid is None:
            tid, pid = pid, -1
        else:
            tid = int(tid)
        t = ns(m["time"])
        rest = m["rest"]
        if rest.startswith("PERF_RECORD_"):
            parts = rest.split()
            if parts[0].startswith("PERF_RECORD_SWITCH") and \
                    len(parts) > 1 and parts[1] == "IN":
                switch_in.setdefault(tid, []).append(t)
            continue
        em = _EVENT.match(rest)
        if em is None:
            continue
        event = em["event"]
        trace = em["trace"] or ""
        aux = None
        if event == SWITCH:
            s = _STATE.search(trace)
            n = _NEXT_PID.search(trace)
            aux = [s.group(1) if s else "", int(n.group(1)) if n else -1]
        elif event == SYS_ENTER:
            n = _NR.match(trace)
            aux = int(n.group(1)) if n else -1
        comm = m["comm"]
        cid = comm_ids.get(comm)
        if cid is None:
            cid = comm_ids[comm] = len(prof.comms)
            prof.comms.append(comm)
        eid = event_ids.get(event)
        if eid is None:
            eid = event_ids[event] = len(prof.events)
            prof.events.append(event)
        cur = (t, pid, tid, cid, eid, int(em["period"] or 1), aux)
    finish()
    if SWITCH in event_ids:
        _off_cpu(prof, event_ids[SWITCH], switch_in)
    prof.header = parse_header(header)
    return prof


def _off_cpu(prof: Profile, ev: int, switch_in: dict[int, list[int]]) -> None:
    """Time off the CPU: from a task's switch-out to its next switch-in.
    Without switch records (a system-wide sched_switch recording), the
    switch-in is the next event naming the task as next_pid."""
    if not switch_in:
        for s in prof.samples:
            if s[4] == ev and s[7][1] > 0:
                switch_in.setdefault(s[7][1], []).append(s[0])
    for times in switch_in.values():
        times.sort()
    for i, s in enumerate(prof.samples):
        if s[4] != ev:
            continue
        times = switch_in.get(s[2], ())
        j = bisect.bisect_right(times, s[0])
        dur = times[j] - s[0] if j < len(times) else -1
        prof.samples[i] = s[:5] + (dur, s[6], s[7][0])


_HEADER_KEYS = {
    "captured on": "captured", "hostname": "hostname",
    "os release": "os_release", "perf version": "perf_version",
    "cmdline": "cmdline", "time of first sample": "first",
    "time of last sample": "last", "nrcpus online": "cpus",
}


def parse_header(lines: Iterable[str]) -> dict:
    """What perf report --header-only (or perf script --header) says."""
    h: dict = {}
    for line in lines:
        if not line.startswith("# "):
            continue
        body = line[2:].strip()
        if body.startswith("reference time:"):
            m = re.search(r"= ([\d.]+) \(TOD\) = ([\d.]+) \((\w+)\)", body)
            if m:
                h["tod_offset_ns"] = ns(m.group(1)) - ns(m.group(2))
                h["clock"] = m.group(3)
            continue
        if body.startswith("event : name = "):
            h.setdefault("events", []).append(
                body[len("event : name = "):].split(",", 1)[0])
            continue
        key, sep, val = body.partition(" : ")
        name = _HEADER_KEYS.get(key.strip())
        if sep and name:
            h[name] = val.strip()
    for k in ("first", "last"):
        if k in h:
            try:
                h[k + "_ns"] = ns(h.pop(k))
            except ValueError:
                pass
    return h


def is_perf_data(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(8) in (b"PERFILE2", b"PERFFILE")
    except OSError:
        return False


def script(path: str, perf: str = "perf") -> Profile:
    with tempfile.TemporaryFile("w+") as err:
        try:
            p = subprocess.Popen(
                [perf, "script", "-i", path, "-F", FIELDS, "--ns",
                 "--show-switch-events"],
                stdout=subprocess.PIPE, stderr=err, text=True,
                errors="replace", bufsize=1 << 20)
        except OSError as e:
            raise PerfError(f"cannot run {perf}: {e}")
        try:
            prof = parse(p.stdout)
        finally:
            p.stdout.close()
            rc = p.wait()
        err.seek(0)
        msgs = [m.strip() for m in err if m.strip()
                and "not valid for" not in m]
    if rc != 0 and not prof.samples:
        raise PerfError(f"perf script failed on {path}: "
                        + ("; ".join(msgs[-3:]) or f"exit {rc}"))
    prof.warnings = msgs
    try:
        out = subprocess.run([perf, "report", "-i", path, "--header-only"],
                             capture_output=True, text=True, timeout=120,
                             errors="replace").stdout
        prof.header = parse_header(out.splitlines())
    except (OSError, subprocess.TimeoutExpired):
        pass
    return prof


def cache_path(path: str) -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    cdir = os.path.join(base, "smb_toolkit", "perf")
    os.makedirs(cdir, exist_ok=True)
    st = os.stat(path)
    tag = hashlib.sha1(os.path.realpath(path).encode()).hexdigest()[:8]
    return os.path.join(cdir, f"{os.path.basename(path)}-{tag}-"
                        f"{st.st_size}-{int(st.st_mtime)}.json.gz")


def load(path: str, perf: str = "perf", refresh: bool = False,
         cache: bool = True) -> Profile:
    """A perf.data file through perf script (cached), or saved perf
    script output."""
    if not is_perf_data(path):
        with open_text(path) as f:
            return parse(f)
    cpath = cache_path(path) if cache else None
    if cpath and not refresh and os.path.exists(cpath):
        try:
            with gzip.open(cpath, "rt") as f:
                return Profile.from_json(json.load(f))
        except (OSError, ValueError, KeyError, TypeError):
            pass
    prof = script(path, perf)
    if cpath:
        tmp = cpath + ".tmp"
        with gzip.open(tmp, "wt", compresslevel=3) as f:
            json.dump(prof.to_json(), f, separators=(",", ":"))
        os.replace(tmp, cpath)
        # Older extractions of the same file.
        stem = os.path.basename(cpath).rsplit("-", 2)[0] + "-"
        for name in os.listdir(os.path.dirname(cpath)):
            if name.startswith(stem) and name != os.path.basename(cpath):
                try:
                    os.unlink(os.path.join(os.path.dirname(cpath), name))
                except OSError:
                    pass
    return prof


def open_text(path: str) -> IO[str]:
    with open(path, "rb") as f:
        gz = f.read(2) == b"\x1f\x8b"
    if gz:
        return gzip.open(path, "rt", errors="replace")
    return open(path, errors="replace")


def unit_of(event: str) -> str:
    """What a sample's weight counts."""
    if event == SWITCH:
        return "ns"
    if event == SYS_ENTER:
        return "calls"
    base, _, mod = event.partition(":")
    if mod and not re.fullmatch(r"[ukhIGHpPSDWebX]+", mod):
        return "events"
    if base in ("cycles", "cpu-cycles", "cpu/cycles/", "ref-cycles"):
        return "cycles"
    if base in ("instructions", "cpu/instructions/"):
        return "instructions"
    if base in ("cpu-clock", "task-clock"):
        return "ns"
    return "events"
