"""smb-prof-latency: latency of each SMB2 command from Samba's buckets,
by process, client, user or share."""

from __future__ import annotations

import argparse
import json

from . import cli
from .cmd_summary import gather
from .data import (BIN_LABELS, SECTION_SMB2, SECTION_SYSCALLS, WAITS, Acc,
                   bins, label, pct_label, resolve_ops)
from .fmt import bar, fmt_n, fmt_us

BY = ("pid", "client", "user", "share")


def rows_for(run, acc: Acc, ops: list[str] | None, group: str | None):
    out = []
    for n in acc.names(run.layout, SECTION_SMB2):
        if ops and n not in ops:
            continue
        count = acc.get(n, "count")
        b = acc.buckets(n)
        if not count:
            continue
        t = acc.get(n, "time")
        idle = acc.get(n, "idle")
        out.append({
            "group": group, "op": label(n), "counter": n, "count": count,
            "failed": acc.get(n, "failed_count"),
            "mean_us": t / count, "busy_us": (t - idle) / count,
            "bins": bins(b),
            "p50": pct_label(b, 50), "p90": pct_label(b, 90),
            "p99": pct_label(b, 99), "wait": n in WAITS})
    out.sort(key=lambda r: -r["mean_us"] * r["count"])
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Latency of SMB2 commands as smbd measured it, from "
        "dispatch to reply: count, mean, mean without time parked "
        "waiting (busy), the share of requests in each of Samba's bins "
        "and the bins holding p50, p90 and p99.",
        epilog="Bins are Samba's: below 1, 2, 4 ... 256 ms, then the rest. "
        "Times need profiling level 'on'.")
    ap.add_argument("input", metavar="FILE")
    cli.add_select_args(ap)
    ap.add_argument("--by", choices=BY, help="one block per group")
    ap.add_argument("--op", metavar="OPS",
                    help="commands to show (READ,CREATE; FIND; smb2_read)")
    ap.add_argument("--counts", action="store_true",
                    help="requests per bin instead of shares")
    ap.add_argument("--hist", action="store_true",
                    help="draw each command's bins as bars")
    ap.add_argument("--syscalls", action="store_true",
                    help="also the mean time of each system call")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    run = cli.load(args.input)
    if not run.times:
        raise SystemExit(f"{args.input}: recorded with profiling level "
                         "count, which keeps no times")
    try:
        sel = cli.selection(args, run)
        ops = resolve_ops(args.op, run.layout) if args.op else None
    except ValueError as e:
        ap.error(str(e))
    total, groups = gather(run, sel, args.by)
    blocks = [(None, total)] if not args.by else sorted(
        groups.items(), key=lambda kv: -kv[1].smb2(run.layout)["time"])
    rows = []
    for g, acc in blocks:
        rows.extend(rows_for(run, acc, ops, g))
    sys_rows = []
    if args.syscalls:
        for n in total.names(run.layout, SECTION_SYSCALLS):
            c = total.get(n, "count")
            if c:
                sys_rows.append({"name": label(n), "count": c,
                                 "mean_us": total.get(n, "time") / c})
        sys_rows.sort(key=lambda r: -r["mean_us"])
    if args.json:
        print(json.dumps({"file": run.path, "bins": list(BIN_LABELS),
                          "rows": rows, "syscalls": sys_rows or None},
                         indent=1))
        return 0
    print(cli.header(run, sel))
    used = [i for i in range(len(BIN_LABELS))
            if any(r["bins"] and r["bins"][i] for r in rows)]
    for group in dict.fromkeys(r["group"] for r in rows):
        block = [x for x in rows if x["group"] == group]
        print()
        if group is not None:
            print(f"{args.by} {group}")
        if args.hist:
            for x in block:
                print(f"{x['op']}: {fmt_n(x['count'])} requests, mean "
                      f"{fmt_us(x['mean_us'])}, busy {fmt_us(x['busy_us'])}")
                b = x["bins"] or []
                mx = max(b or [0])
                full = [i for i, v in enumerate(b) if v]
                for i in range(full[0], full[-1] + 1) if full else ():
                    v = b[i]
                    print(f"  {BIN_LABELS[i]:>9}  {fmt_n(v):>6}  "
                          f"{100 * v / x['count']:5.1f}%  {bar(v, mx, 40)}")
            continue
        table = []
        for x in block:
            cells = [x["op"] + (" (wait)" if x["wait"] else ""),
                     fmt_n(x["count"]),
                     fmt_n(x["failed"]) if x["failed"] else "",
                     fmt_us(x["mean_us"]), fmt_us(x["busy_us"])]
            for i in used:
                v = x["bins"][i] if x["bins"] else 0
                if not v:
                    cells.append("")
                elif args.counts:
                    cells.append(fmt_n(v))
                else:
                    cells.append(f"{100 * v / x['count']:.0f}%"
                                 if v * 200 >= x["count"] else "<1%")
            table.append(cells + [x["p50"], x["p90"], x["p99"]])
        print(cli.table(table, ["SMB2", "count", "failed", "mean", "busy"] +
                        [BIN_LABELS[i] for i in used] + ["p50", "p90", "p99"]))
    if not rows:
        print("\nno SMB2 requests in the selection")
    if sys_rows:
        print()
        print(cli.table([[x["name"], fmt_n(x["count"]), fmt_us(x["mean_us"])]
                         for x in sys_rows],
                        ["System calls", "count", "mean"]))
    return 0
