"""smb-dirscans: directories listed again and again."""

from __future__ import annotations

import argparse
import json

from . import cli, dirscans, names
from .dirscans import Directory, Scan
from .stats import fmt_dur, percentile


def _n(v: int | None) -> str:
    return "?" if v is None else f"{v:,}"


def _count(n: int, one: str, many: str) -> str:
    return f"{n:,} {one if n == 1 else many}"


def _distinct(d: Directory) -> str:
    return ("~" if d.changed and d.distinct is not None else "") + \
        _n(d.distinct)


def _ratio(r: float | None) -> str:
    return "?" if r is None else f"{r:.1f}x"


def _end(s: Scan) -> str:
    if s.end == "failed":
        return names.status_name(s.status)
    return s.end


def _notes(cap, d: Directory) -> list[str]:
    n = len(d.scans)
    done = d.count("end", "complete")
    out = []
    rewinds = d.count("kind", "rewind")
    if rewinds:
        tail = "none reached the end" if not done else \
            f"{done} reached the end"
        out.append(f"{rewinds} of {n} scans started from the top again "
                   f"after an earlier one stopped short; {tail}")
    repeats = [s for s in d.scans if s.kind == "repeat"]
    if repeats:
        gaps = []
        for i, s in enumerate(d.scans):
            if s.kind == "repeat":
                gaps.append(s.t0 - d.scans[i - 1].t1)
        gaps.sort()
        out.append(f"{_count(len(repeats), 'scan', 'scans')} listed it again "
                   f"after a complete listing, "
                   f"{fmt_dur(percentile(gaps, 50))} after it (median)")
    overlaps = d.count("kind", "overlap")
    if overlaps:
        out.append(f"{_count(overlaps, 'scan', 'scans')} began while another "
                   f"scan of it was still open")
    rate = d.rate()
    if rate is not None:
        t_a, c_a, t_b, c_b = rate
        per_s = (c_b - c_a) / ((t_b - t_a) / 1e9)
        out.append(f"entries seen: {c_a:,} by {cap.rel(t_a):.2f}s, {c_b:,} "
                   f"by {cap.rel(t_b):.2f}s, {per_s:,.0f} new entries/s")
    if d.changed:
        sizes = d.sizes()
        held = f": complete listings held {sizes[0]:,} to {sizes[-1]:,} " \
            f"entries" if len(sizes) > 1 else ""
        out.append(f"it changed between scans{held}; distinct counts "
                   f"positions, not names")
    unknown = sum(s.unknown for s in d.scans)
    if unknown:
        out.append(f"{unknown} replies could not be counted: they shared a "
                   f"frame with another reply that carries names")
    return out


def _scan_rows(cap, d: Directory) -> list[list]:
    rows = []
    for i, s in enumerate(d.scans):
        rows.append([
            i, f"{cap.rel(s.t0):.3f}", s.how, s.kind, len(s.queries),
            _n(s.entries), _n(s.pos0), _n(s.reach), _n(s.new), _end(s),
            fmt_dur(s.t1 - s.t0), fmt_dur(s.time),
        ])
    return rows


def _json(cap, d: Directory) -> dict:
    return {
        "client": d.client, "share": d.share, "directory": d.path,
        "pattern": d.pattern, "scans": len(d.scans),
        "complete": d.count("end", "complete"),
        "rewinds": d.count("kind", "rewind"),
        "repeats": d.count("kind", "repeat"),
        "overlaps": d.count("kind", "overlap"),
        "joined": d.count("kind", "joined"),
        "returned": d.returned, "distinct": d.distinct,
        "changed": d.changed,
        "ratio": None if d.ratio is None else round(d.ratio, 3),
        "time_ns": d.time, "lookups": d.lookups,
        "scan_list": [{
            "start_s": round(cap.rel(s.t0), 6), "how": s.how,
            "kind": s.kind, "fid": s.fid, "queries": len(s.queries),
            "entries": s.entries, "unknown_replies": s.unknown,
            "from": s.pos0, "to": s.reach, "new": s.new, "end": s.end,
            "status": None if s.status is None else
            names.status_name(s.status),
            "duration_ns": s.t1 - s.t0, "time_ns": s.time,
        } for s in d.scans],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Directories a client listed more than once: scans "
                    "started over before reaching the end, complete "
                    "listings repeated, scans of one directory at the same "
                    "time. Counts the entries returned against the entries "
                    "the directory holds.")
    cli.add_input_args(ap)
    cli.add_filter_args(ap)
    ap.add_argument("--top", type=int, default=20,
                    help="directories to show (default 20)")
    ap.add_argument("--min-scans", type=int, default=2,
                    help="scans a directory needs to be shown (default 2)")
    ap.add_argument("--min-ratio", type=float, default=2.0,
                    help="entries returned per entry held, to be shown "
                    "(default 2)")
    ap.add_argument("--all", action="store_true",
                    help="every directory listed or searched, regardless "
                    "of the thresholds")
    ap.add_argument("--scans", action="store_true",
                    help="list each scan of the directories shown")
    ap.add_argument("--json", action="store_true",
                    help="one JSON object per directory shown")
    args = ap.parse_args(argv)
    cap = cli.load_capture(args)
    flt = cli.make_filter(args)
    dirs = dirscans.find(cap, flt.apply(cap))
    if args.all:
        shown = dirs
    else:
        shown = [d for d in dirs if d.reread(args.min_scans, args.min_ratio)]
    shown.sort(key=lambda d: (-d.wasted, -d.time, -len(d.scans),
                              -d.lookups))
    if args.json:
        for d in shown[:args.top]:
            print(json.dumps(_json(cap, d), ensure_ascii=False))
        return 0

    scanned = [d for d in dirs if d.scans]
    nscans = sum(len(d.scans) for d in scanned)
    lookups = sum(d.lookups for d in dirs)
    returned = sum(d.returned for d in scanned)
    print(f"{_count(nscans, 'scan', 'scans')} of "
          f"{_count(len(scanned), 'directory', 'directories')} returned "
          f"{_count(returned, 'entry', 'entries')}; "
          f"{_count(lookups, 'lookup', 'lookups')} of a single name")
    if dirscans.entry_counts_missing(cap):
        print("replies carry no entry counts: the .smbx predates them; run "
              "smb-extract on the capture again")
    if not shown:
        print(f"no directory was scanned {args.min_scans} times or more with "
              f"{args.min_ratio:g}x its entries returned (--all lists them "
              f"all)")
        return 0
    print()
    rows = []
    for d in shown[:args.top]:
        rows.append([
            d.client, d.share, cli.shorten(d.path, 50), len(d.scans),
            d.count("end", "complete"), d.count("kind", "rewind"),
            d.count("kind", "repeat"), _n(d.returned), _distinct(d),
            _ratio(d.ratio), fmt_dur(d.time), d.lookups,
        ])
    print(cli.table(rows, [
        "client", "share", "directory", "scans", "complete", "rewinds",
        "repeats", "returned", "distinct", "ratio", "time", "lookups"],
        "lllrrrrrrrrr"))
    if len(shown) > args.top:
        print(f"... {len(shown) - args.top} more directories")
    print("complete: reached the end; rewinds: started from the top after an "
          "earlier scan stopped short;\nrepeats: listed again after a "
          "complete listing; distinct: entries the scans covered (~: the "
          "directory\nchanged); time: summed latency of the scans' queries")
    for d in shown[:args.top]:
        notes = _notes(cap, d)
        if not notes and not args.scans:
            continue
        print()
        print(f"{d.path} ({d.client}, {d.share}, pattern {d.pattern}):")
        for line in notes:
            print(f"  {line}")
        if args.scans and d.scans:
            print(cli.table(_scan_rows(cap, d), [
                "#", "start", "how", "kind", "queries", "entries", "from",
                "to", "new", "end", "duration", "time"],
                "rrllrrrrrlrr", "  "))
    return 0
