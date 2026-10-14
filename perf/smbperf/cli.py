"""What the analysis tools share: inputs, selection, loading."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import platform
import sys
from dataclasses import dataclass, field

from . import perfdata, stacks
from .fmt import UNITS, parse_when
from .smbd import host_of
from .stacks import ROOTS, Selection, Stacks


def note(text: str) -> None:
    print(text, file=sys.stderr)


def add_input_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("input", metavar="INPUT",
                    help="a directory from smb-perf-record, a perf.data "
                    "file, saved perf script output, or folded stacks")
    g = ap.add_argument_group("reading perf.data")
    g.add_argument("--perf", default="perf", help="perf binary")
    g.add_argument("--refresh", action="store_true",
                   help="re-run perf script even if a cache exists")
    g.add_argument("--no-cache", action="store_true",
                   help="do not keep perf script's output under "
                   "~/.cache/smb_toolkit/perf")


def add_select_args(ap: argparse.ArgumentParser) -> None:
    g = ap.add_argument_group("selection")
    g.add_argument("--from", dest="t_from", metavar="T",
                   help="only samples at or after T: seconds into the "
                   "recording (12.5, 1m3s) or a wall-clock time (@EPOCH, "
                   "2026-10-13T01:30:38.5, 01:30:38.5; UTC unless an "
                   "offset is given)")
    g.add_argument("--to", dest="t_to", metavar="T",
                   help="only samples at or before T")
    g.add_argument("--client", action="append", default=[], metavar="ADDR",
                   help="only the smbd serving ADDR (repeatable)")
    g.add_argument("--comm", action="append", default=[], metavar="GLOB",
                   help="only processes or threads named GLOB, e.g. "
                   "'smbd*' or 'iou-wrk*' (repeatable)")
    g.add_argument("--pid", action="append", type=int, default=[],
                   help="only this process (repeatable)")
    g.add_argument("--tid", action="append", type=int, default=[],
                   help="only this thread (repeatable)")
    g.add_argument("--event", metavar="EVENT",
                   help="the event to read when the recording has several")
    g.add_argument("--root", choices=ROOTS, default="process",
                   help="the first frames: process (smbd[client], then the "
                   "thread's role, e.g. iou-wrk), role (smbd[client] for "
                   "every client, merging them), comm (the thread's name, "
                   "as stackcollapse-perf.pl), pid (comm-pid) or none "
                   "(default process)")
    g.add_argument("--samples", action="store_true",
                   help="count samples instead of summing their periods")
    g.add_argument("--no-inline", action="store_true",
                   help="leave out inlined functions")
    g.add_argument("--user-only", action="store_true",
                   help="leave out kernel frames; their weight goes to the "
                   "user function that entered the kernel")
    g.add_argument("--no-kernel-mark", action="store_true",
                   help="do not append _[k] to kernel functions")


def add_stack_args(ap: argparse.ArgumentParser) -> None:
    g = ap.add_argument_group("stacks")
    g.add_argument("--grep", action="append", default=[], metavar="RE",
                   help="only stacks with a function matching RE "
                   "(repeatable: all must match)")
    g.add_argument("--exclude", action="append", default=[], metavar="RE",
                   help="drop stacks with a function matching RE")
    g.add_argument("--focus", metavar="RE",
                   help="only stacks through a function matching RE, "
                   "starting there (its callers merged)")
    g.add_argument("--keep-loop", action="store_true",
                   help="keep smbd's stacks whole; by default they start "
                   "at the handler its event loop ran, under one [event "
                   "loop] frame, so stacks perf cut short line up with "
                   "whole ones")
    g.add_argument("--unit", choices=UNITS,
                   help="what the weights in folded input count (default: "
                   "from the recording's perf.json)")


def add_base_args(g) -> None:
    g.add_argument("--base-from", metavar="T",
                   help="--from for BASE (times differ between recordings)")
    g.add_argument("--base-to", metavar="T", help="--to for BASE")


def base_args(args: argparse.Namespace) -> argparse.Namespace:
    """The options for loading BASE: its own window, no pids or tids."""
    b = argparse.Namespace(**vars(args))
    b.t_from, b.t_to = args.base_from, args.base_to
    b.pid, b.tid = [], []
    return b


@dataclass
class Loaded:
    stacks: Stacks
    path: str
    kind: str                       # data, script or folded
    meta: dict = field(default_factory=dict)
    header: dict = field(default_factory=dict)
    window: tuple[int | None, int | None] = (None, None)

    def title(self) -> str:
        m = self.meta
        what = {"cpu": "on-CPU", "off": "off-CPU",
                "syscalls": "system calls"}.get(m.get("mode", ""), "")
        host = m.get("host", {}).get("hostname") or \
            self.header.get("hostname")
        when = m.get("start", "")[:19].replace("T", " ")
        parts = [p for p in ("smbd " + what if what else "", host, when)
                 if p]
        return ", ".join(parts) or os.path.basename(self.path)


def _meta_for(path: str) -> dict:
    """perf.json beside a perf.data or folded file, or <stem>.json."""
    stem = os.path.splitext(path)[0]
    for cand in (stem + ".json",
                 os.path.join(os.path.dirname(path) or ".", "perf.json")):
        if os.path.exists(cand):
            try:
                with open(cand) as f:
                    d = json.load(f)
            except (OSError, ValueError):
                continue
            if d.get("tool") == "smb-perf-record":
                return d
    return {}


def resolve(path: str) -> tuple[str, str, dict]:
    """(file, kind, metadata) for an input path."""
    if not os.path.exists(path):
        raise SystemExit(f"error: {path}: no such file or directory")
    if os.path.isdir(path):
        meta = _meta_for(os.path.join(path, "perf.json"))
        data = os.path.join(path, "perf.data")
        folded = os.path.join(path, "perf.folded")
        here = platform.node()
        recorded = meta.get("host", {}).get("hostname")
        if os.path.exists(data) and not (
                recorded and recorded != here and os.path.exists(folded)):
            return data, "data", meta
        if os.path.exists(folded):
            if os.path.exists(data):
                note(f"{path}: recorded on {recorded}; reading "
                     "perf.folded (perf.data needs that machine's "
                     "binaries)")
            return folded, "folded", meta
        raise SystemExit(f"error: {path}: no perf.data or perf.folded")
    meta = _meta_for(path)
    if perfdata.is_perf_data(path):
        return path, "data", meta
    with perfdata.open_text(path) as f:
        head = [ln for _, ln in zip(range(200), f)]
    return path, "folded" if stacks.looks_folded(head) else "script", meta


def selection(args: argparse.Namespace, meta: dict) -> Selection:
    procs = meta.get("processes", {})
    names, clients_of = {}, {}
    for pid, p in procs.items():
        if p.get("name"):
            names[int(pid)] = p["name"]
        if p.get("clients"):
            clients_of[int(pid)] = [host_of(c) for c in p["clients"]]
    return Selection(
        event=args.event, comms=args.comm, pids=args.pid, tids=args.tid,
        clients=args.client, root=args.root,
        kernel_mark=not args.no_kernel_mark, inline=not args.no_inline,
        user_only=args.user_only, count_samples=args.samples, names=names,
        clients_of=clients_of)


def load(path: str, args: argparse.Namespace,
         root: str | None = None) -> Loaded:
    """Stacks from any input, with the selection and stack options
    applied; `root` overrides --root."""
    file, kind, meta = resolve(path)
    sel_args = hasattr(args, "t_from")
    if kind == "folded":
        if sel_args and (args.t_from or args.t_to or args.pid or args.tid
                         or args.event):
            raise SystemExit(f"error: {file} holds folded stacks: no "
                             "times, pids or events to select by")
        unit = getattr(args, "unit", None) or meta.get("unit", "weight")
        with perfdata.open_text(file) as f:
            st = stacks.read_folded(f, unit)
        if sel_args and (args.comm or args.client):
            st = _filter_roots(st, args.comm, args.client)
        loaded = Loaded(st, file, kind, meta)
    else:
        try:
            if kind == "data":
                prof = perfdata.load(file, args.perf, args.refresh,
                                     not args.no_cache)
            else:
                with perfdata.open_text(file) as f:
                    prof = perfdata.parse(f)
        except perfdata.PerfError as e:
            raise SystemExit(f"error: {e}")
        if not prof.samples:
            raise SystemExit(f"error: {file}: no samples")
        sel = selection(args, meta) if sel_args else Selection()
        if root:
            sel.root = root
        h = prof.header
        first = h.get("first_ns") or min(s[0] for s in prof.samples)
        offset = h.get("tod_offset_ns")
        if offset is None and meta.get("tod_offset_ns") is not None:
            offset = meta["tod_offset_ns"]
        try:
            if sel_args and args.t_from:
                sel.t_from = parse_when(args.t_from, first, offset)
            if sel_args and args.t_to:
                sel.t_to = parse_when(args.t_to, first, offset)
            st = stacks.fold(prof, sel)
        except ValueError as e:
            raise SystemExit(f"error: {e}")
        h = dict(h, first_ns=first)
        if offset is not None:
            h["tod_offset_ns"] = offset
        for w in prof.warnings:
            if "lost" in w.lower():
                st.notes.append("perf: " + w)
        loaded = Loaded(st, file, kind, meta, h, (sel.t_from, sel.t_to))
    if hasattr(args, "keep_loop") and not args.keep_loop:
        loaded.stacks = stacks.cut_loop(loaded.stacks)
    for rx in getattr(args, "grep", []):
        loaded.stacks = stacks.grep(loaded.stacks, rx)
    for rx in getattr(args, "exclude", []):
        loaded.stacks = stacks.grep(loaded.stacks, rx, keep=False)
    if getattr(args, "focus", None):
        loaded.stacks = stacks.focus(loaded.stacks, args.focus)
    return loaded


def _filter_roots(st: Stacks, comms: list[str], clients: list[str]) -> Stacks:
    def keep(stack: tuple[str, ...]) -> bool:
        if not stack:
            return False
        head = stack[:2]
        if comms and not any(fnmatch.fnmatchcase(f, g)
                             for f in head for g in comms):
            return False
        if clients and not any(stacks.serves(stack[0], c)
                               for c in clients):
            return False
        return True
    return st.derive({s: w for s, w in st.weights.items() if keep(s)})


def table(rows: list[list[object]], headers: list[str],
          align: str | None = None, indent: str = "") -> str:
    """Plain columns; `align` has one char per column, 'l' or 'r'."""
    cols = len(headers)
    align = align or "l" * cols
    text = [[str(c) for c in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in text:
        for i, c in enumerate(row):
            widths[i] = max(widths[i], len(c))

    def line(cells: list[str]) -> str:
        parts = []
        for i, c in enumerate(cells):
            if i == cols - 1 and align[i] == "l":
                parts.append(c)
            elif align[i] == "r":
                parts.append(c.rjust(widths[i]))
            else:
                parts.append(c.ljust(widths[i]))
        return (indent + "  ".join(parts)).rstrip()

    out = [line(headers), indent + "  ".join("-" * w for w in widths)]
    out.extend(line(r) for r in text)
    return "\n".join(out)
