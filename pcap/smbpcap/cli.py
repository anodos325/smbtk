"""What every tool shares: loading inputs, filtering, printing."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Iterable, Sequence

from . import extract, names
from .model import Capture, Exchange, Filter
from .stats import parse_duration


def add_input_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("inputs", nargs="+", metavar="CAPTURE",
                    help="pcap/pcapng files, or .smbx files from smb-extract;"
                    " several are merged in time order")
    g = ap.add_argument_group("extraction")
    g.add_argument("--no-cache", action="store_true",
                   help="do not keep the extraction under ~/.cache/smb_toolkit")
    g.add_argument("--refresh", action="store_true",
                   help="re-run tshark even if a cache exists")
    g.add_argument("--tshark", default="tshark", help="tshark binary")
    g.add_argument("--pref", action="append", default=[], metavar="PREF",
                   help="tshark -o preference (repeatable)")
    g.add_argument("--tshark-filter", metavar="FILTER",
                   help="extra display filter applied during extraction")


def add_filter_args(ap: argparse.ArgumentParser) -> None:
    g = ap.add_argument_group("selection")
    g.add_argument("--client", action="append", default=[], metavar="IP")
    g.add_argument("--server", action="append", default=[], metavar="IP")
    g.add_argument("--share", action="append", default=[], metavar="NAME")
    g.add_argument("--user", action="append", default=[], metavar="TEXT",
                   help="substring of DOMAIN\\user")
    g.add_argument("--file", action="append", default=[], metavar="GLOB",
                   help="path glob or substring, case-insensitive")
    g.add_argument("--cmd", action="append", default=[], metavar="CMD",
                   help="command name(s), comma separated: CREATE, READ, "
                   "FIND, GETINFO, SETINFO, NOTIFY, IOCTL ...")
    g.add_argument("--status", action="append", default=[], metavar="STATUS",
                   help="NT status name or number, e.g. ACCESS_DENIED or "
                   "0xc0000022")
    g.add_argument("--stream", action="append", default=[], type=int,
                   metavar="N", help="tcp.stream number")
    g.add_argument("--session", action="append", default=[], metavar="ID",
                   help="session id, hex")
    g.add_argument("--from", dest="t_from", metavar="T",
                   help="only requests at or after T seconds into the "
                   "capture (also 1m30s, 250ms)")
    g.add_argument("--to", dest="t_to", metavar="T",
                   help="only requests at or before T")
    g.add_argument("--errors-only", action="store_true",
                   help="only failed and unanswered requests")


def add_wait_arg(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--waits", action="store_true",
                    help="include CHANGE_NOTIFY and other requests that "
                    "wait for an event by design")


def add_idle_arg(ap: argparse.ArgumentParser, what: str) -> None:
    ap.add_argument("--idle", action="store_true",
                    help=f"add client idle time to {what}; idle is the "
                    "time the client had nothing outstanding before a "
                    "request: its think time, plus the network round trip "
                    "when seen from the server")


def idle_meaning(verdict: str) -> str:
    """What idle time holds, seen from where the capture was taken."""
    trip = {"server": " plus the network round trip", "client": "",
            "path": " plus part of the round trip"}.get(
                verdict, " plus an unknown share of the round trip")
    return f"think time{trip}"


def parse_status(text: str) -> int:
    key = text.strip().upper()
    try:
        return int(key, 0)
    except ValueError:
        pass
    if not key.startswith("STATUS_"):
        key = "STATUS_" + key
    for code, name in names.names_gen.NT_STATUS.items():
        if name == key:
            return code
    raise argparse.ArgumentTypeError(f"unknown status {text!r}")


def make_filter(args: argparse.Namespace, waits: bool = True) -> Filter:
    cmds = []
    for item in args.cmd:
        for part in item.split(","):
            if part.strip():
                cmds.append(names.parse_cmd(part))
    statuses = [parse_status(s) for s in args.status]
    sessions = [int(s, 16) for s in args.session]
    return Filter(
        clients=args.client, servers=args.server, shares=args.share,
        users=args.user, files=args.file, cmds=cmds, statuses=statuses,
        streams=args.stream, sessions=sessions,
        t_from=parse_duration(args.t_from) if args.t_from else None,
        t_to=parse_duration(args.t_to) if args.t_to else None,
        errors_only=args.errors_only, waits=waits,
    )


def cache_path(pcap: str) -> str:
    """Where a capture's extraction is kept: under the user's cache
    directory, never beside the capture."""
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    cdir = os.path.join(base, "smb_toolkit")
    os.makedirs(cdir, exist_ok=True)
    st = os.stat(pcap)
    return os.path.join(
        cdir, f"{os.path.basename(pcap)}-{st.st_size}-{int(st.st_mtime)}.smbx")


def _cache_fresh(path: str, pcap: str, tshark_filter: str | None) -> bool:
    if not os.path.exists(path):
        return False
    try:
        head = next(extract.read_records(path))
    except (StopIteration, ValueError, OSError):
        return False
    st = os.stat(pcap)
    return (head.get("k") == "h" and head.get("v") == extract.FORMAT_VERSION
            and head.get("size") == st.st_size
            and head.get("mtime") == int(st.st_mtime)
            and head.get("filter", "") == (tshark_filter or ""))


def records_for(path: str, args: argparse.Namespace) -> Iterable[dict]:
    if not os.path.exists(path):
        raise SystemExit(f"error: {path}: no such file")
    if not extract.is_capture(path):
        return extract.read_records(path)
    cache = cache_path(path)
    if not args.refresh and _cache_fresh(cache, path, args.tshark_filter):
        return extract.read_records(cache)
    note(f"extracting {path} with tshark ...")
    try:
        if args.no_cache:
            return list(extract.extract(path, args.tshark, args.tshark_filter,
                                        args.pref))
        extract.write_records(
            extract.extract(path, args.tshark, args.tshark_filter, args.pref),
            cache)
    except extract.ExtractError as e:
        raise SystemExit(f"error: {e}")
    note(f"cached as {cache}")
    return extract.read_records(cache)


def load_capture(args: argparse.Namespace) -> Capture:
    """Several inputs are taken in time order (rotated files sort badly
    by name: file1, file10, file2)."""
    cap = Capture()
    if len(args.inputs) == 1:
        cap.add_records(records_for(args.inputs[0], args))
        cap.inputs.append(args.inputs[0])
    else:
        loaded = []
        for path in args.inputs:
            recs = list(records_for(path, args))
            first = min((r["t"] for r in recs if "t" in r), default=0)
            loaded.append((first, path, recs))
        loaded.sort(key=lambda e: e[0])
        for i, (_, path, recs) in enumerate(loaded):
            cap.add_records(recs, i)
            cap.inputs.append(path)
    cap.finish()
    return cap


def note(text: str) -> None:
    print(text, file=sys.stderr)


def frame_ref(cap: Capture, x: Exchange) -> str:
    """'123' or '2:123' when several captures were merged."""
    if len(cap.inputs) > 1:
        return f"{x.fileidx + 1}:{x.frame}"
    return str(x.frame)


def frames_ref(cap: Capture, x: Exchange) -> str:
    """Request and response frame numbers, 'req->resp'."""
    r = frame_ref(cap, x)
    if x.resp_frame is None:
        return f"{r}->"
    if len(cap.inputs) > 1:
        return f"{r}->{x.resp_fileidx + 1}:{x.resp_frame}"
    return f"{r}->{x.resp_frame}"


def table(rows: Sequence[Sequence[object]], headers: Sequence[str],
          align: str | None = None, indent: str = "") -> str:
    """Plain columns; `align` has one char per column, 'l' or 'r'."""
    if not rows and not headers:
        return ""
    cols = len(headers)
    align = align or "l" * cols
    text = [[str(c) for c in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in text:
        for i, c in enumerate(row):
            widths[i] = max(widths[i], len(c))
    out = []

    def line(cells: Sequence[str]) -> str:
        parts = []
        for i, c in enumerate(cells):
            if i == cols - 1 and align[i] == "l":
                parts.append(c)
            elif align[i] == "r":
                parts.append(c.rjust(widths[i]))
            else:
                parts.append(c.ljust(widths[i]))
        return (indent + "  ".join(parts)).rstrip()

    out.append(line(headers))
    out.append(indent + "  ".join("-" * w for w in widths))
    for row in text:
        out.append(line(row))
    return "\n".join(out)


def rel_time(cap: Capture, t: int) -> str:
    return f"{cap.rel(t):.6f}"


def shorten(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    keep = width - 3
    return "..." + text[-keep:]
