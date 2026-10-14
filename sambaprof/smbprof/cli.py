"""Options and output shared by the tools."""

from __future__ import annotations

import argparse
import sys

from .data import Run, Selection
from .fmt import parse_when, wall_full


def note(text: str) -> None:
    print(text, file=sys.stderr)


def add_samba_args(ap: argparse.ArgumentParser) -> None:
    g = ap.add_argument_group("Samba")
    g.add_argument("--samba", metavar="DIR",
                   help="a Samba install to use (its bin/, sbin/ and "
                   "Python modules) instead of the system's")
    g.add_argument("-s", "--configfile", metavar="FILE",
                   help="smb.conf of the smbd to work on")
    g.add_argument("--tdb", metavar="FILE",
                   help="the counters' tdb (default: smbprofile.tdb in "
                   "the cache directory)")
    g.add_argument("--no-bindings", action="store_true",
                   help="read the tdb here, without Samba's tdb module")


def add_select_args(ap: argparse.ArgumentParser) -> None:
    g = ap.add_argument_group("selection")
    g.add_argument("--from", dest="t_from", metavar="T",
                   help="start: seconds into the recording ('90', "
                   "'1m30s') or wall clock (@EPOCH, ISO 8601, HH:MM:SS; "
                   "UTC)")
    g.add_argument("--to", dest="t_to", metavar="T", help="end, as --from")
    g.add_argument("--client", action="append", default=[], metavar="ADDR",
                   help="smbd processes serving this client address "
                   "(addr or addr:port; repeatable)")
    g.add_argument("--pid", action="append", type=int, default=[],
                   help="one smbd process (repeatable)")
    g.add_argument("--share", action="append", default=[], metavar="NAME",
                   help="per-share counters of this share (repeatable; "
                   "needs 'smbd profiling share = yes')")


def selection(args: argparse.Namespace, run: Run) -> Selection:
    def when(text):
        return None if text is None else parse_when(text, run.t0)
    return Selection(t_from=when(args.t_from), t_to=when(args.t_to),
                     clients=args.client, pids=args.pid, shares=args.share)


def load(path: str) -> Run:
    try:
        return Run(path)
    except (OSError, ValueError, KeyError) as e:
        raise SystemExit(f"{path}: {e}")


def header(run: Run, sel: Selection | None = None) -> str:
    m = run.meta
    span = f"{wall_full(run.t0)}, {run.duration:.1f} s"
    if sel and (sel.t_from or sel.t_to):
        span += f" (window {run.seconds(sel):.1f} s)"
    host = m.get("host", {}).get("hostname", "?")
    level = m.get("level", "?")
    every = m.get("interval")
    return (f"{run.name}: {span}, Samba {m.get('samba', '?')} on {host}, "
            f"profiling {level}" + (f", every {every:g} s" if every else ""))


def table(rows: list[list[object]], headers: list[str],
          align: str | None = None, indent: str = "") -> str:
    """Plain columns; `align` has one char per column, 'l' or 'r'."""
    cols = len(headers)
    align = align or "l" + "r" * (cols - 1)
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
