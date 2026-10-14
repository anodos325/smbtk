"""smb-hist: how the request mix changes over the capture."""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter, defaultdict

from . import cli
from .levels import level_value, levels_help, parse_levels
from .stats import bar, fmt_bytes, fmt_dur, parse_duration, percentile

METRICS = {
    "count": "requests sent in the interval",
    "errors": "requests sent in the interval that failed",
    "time": "server time of requests sent in the interval",
    "idle": "client idle time before requests sent in the interval",
    "bytes": "READ and WRITE bytes of requests sent in the interval",
    "inflight": "most requests outstanding at once during the interval",
    "p50": "median latency of requests sent in the interval",
    "max": "slowest request sent in the interval",
}


def pick_interval(duration: float, buckets: int = 40) -> float:
    if duration <= 0:
        return 1.0
    raw = duration / buckets
    for step in (0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2,
                 5, 10, 30, 60, 120, 300, 600, 1800, 3600):
        if step >= raw:
            return step
    return 3600.0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Histogram of requests over time, one column per "
                    "group: see bursts, repeated request families, when "
                    "errors cluster, how deep the queue got.",
        epilog="levels: " + levels_help() + ". metrics: " + "; ".join(
            f"{k}: {v}" for k, v in METRICS.items()))
    cli.add_input_args(ap)
    cli.add_filter_args(ap)
    cli.add_wait_arg(ap)
    ap.add_argument("--by", default="cmd", metavar="LEVEL",
                    help="column grouping (default: cmd); 'none' for one "
                    "column")
    ap.add_argument("--metric", default="count", choices=list(METRICS))
    ap.add_argument("--interval", metavar="T",
                    help="bucket width, e.g. 1s, 250ms (default: about 40 "
                    "buckets)")
    ap.add_argument("--top", type=int, default=8,
                    help="columns to show; the rest are summed as 'other'")
    ap.add_argument("--csv", action="store_true", help="CSV to stdout")
    ap.add_argument("--bars", action="store_true",
                    help="draw a bar per row of the first column's value")
    args = ap.parse_args(argv)
    levels = []
    if args.by != "none":
        try:
            levels = parse_levels(args.by)
        except ValueError as e:
            ap.error(str(e))
    cap = cli.load_capture(args)
    flt = cli.make_filter(args, waits=args.waits)
    xs = list(flt.apply(cap))
    interval = parse_duration(args.interval) if args.interval else \
        pick_interval(cap.duration())
    width_ns = int(interval * 1e9)
    t0 = cap.t0 or 0
    nb = int(cap.duration() / interval) + 1

    def group_of(x) -> str:
        if not levels:
            return "all"
        return " ".join(level_value(cap, x, lv) for lv in levels)

    totals: Counter[str] = Counter()
    for x in xs:
        totals[group_of(x)] += 1
    keep = [g for g, _ in totals.most_common(args.top)]
    columns = keep + (["other"] if len(totals) > len(keep) else [])
    col_of = {g: (g if g in keep else "other") for g in totals}

    cells: dict[tuple[int, str], list] = defaultdict(list)
    for x in xs:
        b = (x.t_req - t0) // width_ns
        cells[(b, col_of[group_of(x)])].append(x)

    def value(items: list, b: int, col: str) -> float | int:
        m = args.metric
        if m == "count":
            return len(items)
        if m == "errors":
            return sum(1 for x in items
                       if x.status_class in ("error", "unanswered"))
        if m == "time":
            return sum(x.weight for x in items)
        if m == "idle":
            return sum(x.idle or 0 for x in items)
        if m == "bytes":
            return sum(x.nbytes for x in items if x.ok)
        if m == "p50":
            lat = sorted(x.latency for x in items if x.latency is not None)
            return percentile(lat, 50) if lat else 0
        if m == "max":
            return max((x.latency for x in items if x.latency is not None),
                       default=0)
        raise ValueError(m)

    rows: list[list] = []
    if args.metric == "inflight":
        # Sweep: +1 at request, -1 at response (end of capture if none).
        events: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for x in xs:
            col = col_of[group_of(x)]
            events[col].append((x.t_req, 1))
            events[col].append((x.t_resp if x.t_resp is not None
                                else (cap.t1 or x.t_req), -1))
        peak: dict[tuple[int, str], int] = {}
        for col, evs in events.items():
            evs.sort()
            cur = 0
            for t, d in evs:
                cur += d
                b = (t - t0) // width_ns
                if cur > peak.get((b, col), 0):
                    peak[(b, col)] = cur
            # carry the level across empty buckets
            cur = 0
            last_b = -1
            for t, d in evs:
                b = (t - t0) // width_ns
                for bb in range(last_b + 1, b):
                    if cur > peak.get((bb, col), 0):
                        peak[(bb, col)] = cur
                cur += d
                last_b = b
        for b in range(nb):
            rows.append([b * interval] + [peak.get((b, c), 0)
                                          for c in columns])
    else:
        for b in range(nb):
            rows.append([b * interval] + [
                value(cells.get((b, c), []), b, c) for c in columns])

    fmt = {"time": fmt_dur, "idle": fmt_dur, "p50": fmt_dur, "max": fmt_dur,
           "bytes": fmt_bytes}.get(args.metric, str)
    if args.csv:
        w = csv.writer(sys.stdout)
        w.writerow(["start_s"] + columns)
        for r in rows:
            w.writerow([f"{r[0]:.3f}"] + list(r[1:]))
        return 0
    print(f"{METRICS[args.metric]}, per {interval:g} s, "
          f"{len(xs)} requests" + (f", by {args.by}" if levels else ""))
    if not args.waits and any(x.wait for x in cap.exchanges):
        print("  (CHANGE_NOTIFY and similar waits left out; --waits "
              "includes them)")
    print()
    mx = max((r[1] for r in rows if len(r) > 1), default=0)
    out_rows = []
    for r in rows:
        line = [f"{r[0]:.3f}"] + [fmt(v) if v else "" for v in r[1:]]
        if args.bars:
            line.append(bar(r[1], mx, 30))
        out_rows.append(line)
    headers = ["start"] + columns + (["bar"] if args.bars else [])
    print(cli.table(out_rows, headers, "r" * (len(columns) + 1) + "l"))
    return 0
