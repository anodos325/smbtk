"""smb-prof-hist: how smbd's counters moved over a recording, one row
per interval, one column per command or group."""

from __future__ import annotations

import argparse
import csv
import sys

from . import cli
from .cmd_summary import merged_buckets
from .data import SECTION_SMB2, WAITS, Acc, label, pct_label, resolve_ops
from .fmt import bar, fmt_bytes, fmt_n, fmt_rate, fmt_us, parse_duration, wall

METRICS = {
    "rate": "requests per second",
    "count": "requests",
    "failed": "failed requests",
    "time": "time in requests",
    "mean": "mean latency",
    "p99": "bin holding the 99th percentile latency",
    "in": "bytes received per second",
    "out": "bytes sent per second",
    "cpu": "CPU, share of one CPU",
}
BY = ("op", "none", "pid", "client", "user", "share")
ADDITIVE = ("rate", "count", "failed", "time", "in", "out", "cpu")


def pick_interval(duration: float, floor: float, buckets: int = 40) -> float:
    raw = max(duration / buckets, floor)
    for step in (0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800,
                 3600):
        if step >= raw - 1e-9:
            return step
    return 3600.0


def value(metric: str, acc: Acc, names: list[str], seconds: float):
    """The metric over `names` (counters) in one cell."""
    count = sum(acc.get(n, "count") for n in names)
    if metric == "count":
        return count
    if metric == "rate":
        return count / seconds if seconds else 0
    if metric == "failed":
        return sum(acc.get(n, "failed_count") for n in names)
    if metric == "time":
        return sum(acc.get(n, "time") for n in names)
    if metric == "mean":
        return sum(acc.get(n, "time") for n in names) / count if count \
            else None
    if metric == "p99":
        return pct_label(merged_buckets(acc, names), 99) if count else None
    if metric in ("in", "out"):
        f = "inbytes" if metric == "in" else "outbytes"
        return sum(acc.get(n, f) for n in names) / seconds if seconds else 0
    if metric == "cpu":
        return acc.cpu() / 1e6 / seconds if seconds else 0
    raise ValueError(metric)


def show(metric: str, v) -> str:
    if v is None or v == 0:
        return ""
    if metric in ("time", "mean"):
        return fmt_us(v)
    if metric in ("in", "out"):
        return fmt_bytes(v)
    if metric == "cpu":
        return f"{100 * v:.0f}%"
    if metric == "rate":
        return fmt_rate(v)
    if metric == "p99":
        return v
    return fmt_n(v)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="smbd's counters over time from an smb-prof-record "
        "recording: one row per interval, one column per SMB2 command (or "
        "process, client, user, share).",
        epilog="metrics: " + "; ".join(f"{k}: {v}"
                                       for k, v in METRICS.items()))
    ap.add_argument("input", metavar="FILE")
    cli.add_select_args(ap)
    ap.add_argument("--by", choices=BY, default="op",
                    help="columns (default: op, the SMB2 commands; none for "
                    "one column)")
    ap.add_argument("--metric", choices=list(METRICS), default="rate")
    ap.add_argument("--op", metavar="OPS",
                    help="counters to count: SMB2 commands or system calls "
                    "(READ,WRITE; openat). Columns with --by op")
    ap.add_argument("--interval", metavar="T",
                    help="row width (default: about 40 rows, no finer "
                    "than the recording)")
    ap.add_argument("--top", type=int, default=8,
                    help="columns to show; the rest add up in 'other'")
    ap.add_argument("--waits", action="store_true",
                    help="keep CHANGE_NOTIFY in time, mean and p99")
    ap.add_argument("--csv", action="store_true", help="CSV to stdout")
    ap.add_argument("--bars", action="store_true",
                    help="a bar per row: the row total, or the first column")
    args = ap.parse_args(argv)
    run = cli.load(args.input)
    if args.metric == "cpu" and args.by in ("op", "share"):
        ap.error("cpu is per process: use --by none, pid, client or user")
    if args.metric in ("time", "mean", "p99") and not run.times:
        raise SystemExit(f"{args.input}: recorded with profiling level "
                         "count, which keeps no times")
    try:
        sel = cli.selection(args, run)
        ops = resolve_ops(args.op, run.layout) if args.op else None
        width = parse_duration(args.interval) if args.interval else \
            pick_interval(run.duration, run.meta.get("interval") or 1)
    except ValueError as e:
        ap.error(str(e))
    timed = args.metric in ("time", "mean", "p99")
    smb2 = [c.name for c in run.layout.counters if c.section == SECTION_SMB2]
    counters = ops or [n for n in smb2 if args.waits or not timed or
                       n not in WAITS]

    if args.by in ("op", "none"):
        items = ((s, "all", e) for s, _, e in run.proc_items(sel)) \
            if not sel.shares else \
            ((s, "all", e) for s, _, e in run.share_items(sel))
    elif args.by == "share":
        items = ((s, run.shares.get(k, {}).get("share", k), e)
                 for s, k, e in run.share_items(sel))
    else:
        def grp(pid):
            if args.by == "pid":
                return f"{pid} {run.proc_label(pid)}"
            return run.users(pid) if args.by == "user" else \
                run.proc_label(pid)
        items = ((s, grp(pid), e) for s, pid, e in run.proc_items(sel))

    nb = int(run.duration / width) + 1

    def bucket(s: dict) -> int:
        return max(0, min(int((s["t"] - 1e-6 - run.t0) // width), nb - 1))

    seconds = [0.0] * nb
    for s in run.window(sel):
        seconds[bucket(s)] += s["dt"]
    cells: dict[tuple[int, str], Acc] = {}
    totals: dict[str, Acc] = {}
    for s, g, e in items:
        d = e.get("d")
        if d:
            cells.setdefault((bucket(s), g), Acc()).add(d)
            totals.setdefault(g, Acc()).add(d)

    if args.by == "op":
        acc = Acc()
        for a in totals.values():
            acc.merge(a)
        rank = sorted(counters, key=lambda n: -(acc.get(n, "time")
                                                if timed else
                                                acc.get(n, "count")))
        rank = [n for n in rank if acc.get(n, "count")]
        keep = rank[:args.top]
        cols = [(label(n), [n]) for n in keep]
        rest = rank[args.top:]
        if rest:
            cols.append(("other", rest))
        groups = {"all"}
    else:
        rank = sorted(totals, key=lambda g: -sum(
            totals[g].get(n, "time" if timed else "count") for n in counters))
        keep = rank[:args.top]
        cols = [(g, counters) for g in keep]
        groups = set(keep)
        if len(rank) > len(keep):
            cols.append(("other", counters))

    rows = []
    for b in range(nb):
        row = []
        for name, names in cols:
            if args.by == "op":
                acc = cells.get((b, "all"), Acc())
            elif name == "other":
                acc = Acc()
                for g in totals:
                    if g not in groups and (b, g) in cells:
                        acc.merge(cells[(b, g)])
            else:
                acc = cells.get((b, name), Acc())
            row.append(value(args.metric, acc, names, seconds[b]))
        rows.append(row)

    names = [c[0] for c in cols]
    if args.csv:
        w = csv.writer(sys.stdout)
        w.writerow(["start_s", "time"] + names)
        for b, row in enumerate(rows):
            w.writerow([f"{b * width:g}", wall(run.t0 + b * width)] +
                       ["" if v is None else round(v, 3)
                        if isinstance(v, float) else v for v in row])
        return 0
    print(cli.header(run, sel))
    what = METRICS[args.metric]
    print(f"{what}, per {width:g} s" +
          ("" if args.by == "none" else f", by {args.by}"))
    if timed and not args.waits and not ops:
        print("  (CHANGE_NOTIFY left out; --waits keeps it)")
    print()
    additive = args.metric in ADDITIVE
    sums = [sum(v for v in row if v) if additive else
            (row[0] if row else None) for row in rows]
    mx = max((v for v in sums if isinstance(v, (int, float))), default=0)
    out = []
    for b, row in enumerate(rows):
        line = [wall(run.t0 + b * width), f"{b * width:g}"] + \
            [show(args.metric, v) for v in row]
        if args.bars:
            v = sums[b]
            line.append(bar(v, mx, 30) if isinstance(v, (int, float)) else "")
        out.append(line)
    headers = ["time", "+s"] + names + (["bar"] if args.bars else [])
    align = "lr" + "r" * len(names) + ("l" if args.bars else "")
    print(cli.table(out, headers, align))
    return 0
