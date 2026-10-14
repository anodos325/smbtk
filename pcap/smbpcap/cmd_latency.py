"""smb-latency: how long the server took, by command or anything else."""

from __future__ import annotations

import argparse
import bisect
import json
from collections import defaultdict

from . import cli
from .levels import level_value, levels_help, parse_levels
from .stats import (
    LATENCY_LABELS, bar, fmt_dur, fmt_pct, latency_buckets, summarize,
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Request latency statistics: time from the request's "
                    "last byte to the response's last byte, grouped.",
        epilog="levels: " + levels_help())
    cli.add_input_args(ap)
    cli.add_filter_args(ap)
    cli.add_wait_arg(ap)
    ap.add_argument("--by", default="cmd", metavar="LEVELS",
                    help="comma-separated grouping levels (default: cmd)")
    ap.add_argument("--sort", default="time",
                    choices=["time", "n", "p50", "p99", "max", "idle"],
                    help="row order (default: total time)")
    cli.add_idle_arg(ap, "each group (total and median)")
    ap.add_argument("--top", type=int, default=40, help="rows to show")
    ap.add_argument("--min-count", type=int, default=1)
    ap.add_argument("--hist", action="store_true",
                    help="latency distribution per group")
    ap.add_argument("--slowest", type=int, default=0, metavar="N",
                    help="list the N slowest requests with context")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable output")
    args = ap.parse_args(argv)
    try:
        levels = parse_levels(args.by)
    except ValueError as e:
        ap.error(str(e))
    cap = cli.load_capture(args)
    flt = cli.make_filter(args, waits=args.waits)
    xs = [x for x in flt.apply(cap) if x.latency is not None]
    groups: dict[tuple[str, ...], list] = defaultdict(list)
    for x in xs:
        groups[tuple(level_value(cap, x, lv) for lv in levels)].append(x)
    total = sum(x.weight for x in xs)
    rows = []
    for key, members in groups.items():
        if len(members) < args.min_count:
            continue
        s = summarize([x.latency for x in members])
        errs = sum(1 for x in members if x.status_class == "error")
        tm = sum(x.weight for x in members)
        idle = summarize([x.idle for x in members if x.idle is not None])
        rows.append((key, s, errs, tm, members, idle))
    sort_key = {
        "time": lambda r: -r[3], "n": lambda r: -r[1]["n"],
        "p50": lambda r: -r[1]["p50"], "p99": lambda r: -r[1]["p99"],
        "max": lambda r: -r[1]["max"], "idle": lambda r: -r[5]["sum"],
    }[args.sort]
    rows.sort(key=sort_key)
    verdict, detail = cap.vantage()
    if args.json:
        groups_out = []
        for k, s, e, tm, _, idle in rows[:args.top]:
            g = {"key": list(k), "n": s["n"], "errors": e, "time_ns": tm,
                 "min_ns": s["min"], "p50_ns": s["p50"], "p90_ns": s["p90"],
                 "p99_ns": s["p99"], "max_ns": s["max"]}
            if args.idle:
                g["idle_ns"] = idle["sum"]
                g["idle_p50_ns"] = idle["p50"]
            groups_out.append(g)
        print(json.dumps({
            "vantage": verdict, "levels": levels, "total_time_ns": total,
            "groups": groups_out,
        }, indent=1))
        return 0
    where = {"server": "server time", "client": "server time plus the "
             "network round trip (capture taken on the client)",
             "path": "server time plus part of the round trip",
             "unknown": "server time plus an unknown share of the round "
             "trip"}[verdict]
    print(f"Latency is {where}; {len(xs)} answered requests, "
          f"{fmt_dur(total)} in all.")
    if args.idle:
        print("Idle is the time the client had nothing outstanding "
              f"before a request, its {cli.idle_meaning(verdict)}; "
              f"{fmt_dur(sum(x.idle or 0 for x in xs))} before these.")
    if not args.waits:
        waits = sum(1 for x in cap.exchanges if x.wait)
        if waits:
            print(f"  {waits} CHANGE_NOTIFY and similar waits left out "
                  f"(--waits includes them)")
    print()
    table_rows = []
    for key, s, errs, tm, _, idle in rows[:args.top]:
        table_rows.append(list(key) + [
            s["n"], errs or "", fmt_dur(s["min"]), fmt_dur(s["p50"]),
            fmt_dur(s["p90"]), fmt_dur(s["p99"]), fmt_dur(s["max"]),
            fmt_dur(tm), fmt_pct(tm, total),
        ] + ([fmt_dur(idle["sum"]) if idle["n"] else "-",
              fmt_dur(idle["p50"]) if idle["n"] else "-"]
             if args.idle else []))
    headers = levels + ["n", "errors", "min", "p50", "p90", "p99", "max",
                        "time", "share"] + (["idle", "idle p50"]
                                            if args.idle else [])
    print(cli.table(table_rows, headers,
                    "l" * len(levels) + "r" * (len(headers) - len(levels))))
    if len(rows) > args.top:
        print(f"... {len(rows) - args.top} more groups")
    if args.hist:
        print()
        for key, s, errs, tm, members, _ in rows[:args.top]:
            counts = latency_buckets([x.latency for x in members])
            print(" / ".join(key) + f"  (n={s['n']})")
            mx = max(counts) or 1
            for label, c in zip(LATENCY_LABELS, counts):
                if c:
                    print(f"  {label:>7s} {c:8d} {bar(c, mx, 40)}")
    if args.slowest:
        print()
        _slowest(cap, xs, args.slowest)
    return 0


def _slowest(cap, xs, n: int) -> None:
    break_times = sorted(b["t"] for b in cap.breaks)
    rows = []
    for x in sorted(xs, key=lambda x: -(x.latency or 0))[:n]:
        notes = []
        if x.interim is not None:
            notes.append(f"async after {fmt_dur(x.pending_after())}")
        if x.cancel is not None:
            notes.append("cancelled")
        if x.chain_len > 1:
            notes.append(f"in {x.chain_sig}")
        if break_times and x.t_resp is not None:
            lo = bisect.bisect_right(break_times, x.t_req)
            hi = bisect.bisect_left(break_times, x.t_resp)
            if hi > lo:
                notes.append(f"{hi - lo} break(s) sent meanwhile")
        rows.append([
            cli.frames_ref(cap, x), f"{cap.rel(x.t_req):.6f}", x.client,
            x.label, cli.shorten(x.target, 48), x.status_name,
            fmt_dur(x.latency), "; ".join(notes),
        ])
    print(cli.table(rows, ["frames", "time", "client", "request", "target",
                           "status", "latency", "notes"], "lrlllllrl"))
