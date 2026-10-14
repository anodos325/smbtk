"""smb-prof-compare: recordings side by side, per request where the
workloads differ in length: rate, latency, CPU and system calls."""

from __future__ import annotations

import argparse
import json
import os

from . import cli
from .cmd_summary import gather, merged_buckets
from .data import (SECTION_SMB2, SECTION_SYSCALLS, WAITS, label, pct_label,
                   resolve_ops)
from .fmt import fmt_bytes, fmt_change, fmt_n, fmt_rate, fmt_us


def stem(path: str) -> str:
    name = os.path.basename(path)
    for ext in (".gz", ".jsonl", ".json"):
        if name.endswith(ext):
            name = name[:-len(ext)]
    return name


def measure(run, sel, waits: bool) -> dict:
    acc, _ = gather(run, sel)
    seconds = run.seconds(sel)
    lay = run.layout
    t = acc.smb2(lay, waits)
    n = t["count"]
    names = [x for x in acc.names(lay, SECTION_SMB2)
             if waits or x not in WAITS]
    ops = {}
    for x in acc.names(lay, SECTION_SMB2):
        c = acc.get(x, "count")
        if c:
            ops[x] = {"count": c, "rate": c / seconds if seconds else None,
                      "mean_us": acc.get(x, "time") / c if run.times
                      else None,
                      "p99": pct_label(acc.buckets(x), 99) if run.times
                      else "-",
                      "time_us": acc.get(x, "time"),
                      "failed": acc.get(x, "failed_count")}
    sys_ = {}
    for x in acc.names(lay, SECTION_SYSCALLS):
        c = acc.get(x, "count")
        if c:
            sys_[x] = {"count": c, "per_request": c / n if n else None,
                       "mean_us": acc.get(x, "time") / c if run.times
                       else None}
    cpu = acc.cpu()
    return {
        "file": run.path, "seconds": seconds, "samba": run.meta.get("samba"),
        "totals": {
            "requests": n, "rate": n / seconds if seconds else None,
            "failed": t["failed"],
            "mean_us": t["time"] / n if n and run.times else None,
            "p99": pct_label(merged_buckets(acc, names), 99)
            if run.times else "-",
            "cpu_us": cpu,
            "cpu_per_request_us": cpu / n if n and cpu else None,
            "in_per_s": t["in"] / seconds if seconds else None,
            "out_per_s": t["out"] / seconds if seconds else None,
            "syscalls_per_request": sum(v["count"] for v in sys_.values()) / n
            if n else None,
            "identity_per_request": (acc.get("set_sec_ctx", "count") +
                                     acc.get("set_root_sec_ctx", "count")) / n
            if n else None,
        },
        "ops": ops, "syscalls": sys_}


TOTALS = (
    ("requests/s", "rate", fmt_rate),
    ("mean latency", "mean_us", fmt_us),
    ("p99 bin", "p99", str),
    ("CPU per request", "cpu_per_request_us", fmt_us),
    ("syscalls per request", "syscalls_per_request", lambda v: f"{v:.2f}"),
    ("identity switches per request", "identity_per_request",
     lambda v: f"{v:.2f}"),
    ("in/s", "in_per_s", fmt_bytes),
    ("out/s", "out_per_s", fmt_bytes),
    ("failed", "failed", fmt_n),
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Recordings side by side, against the first: requests "
        "per second, mean latency and p99 bin, CPU, system calls and "
        "identity switches per request; then each SMB2 command and each "
        "system call.",
        epilog="Run the same workload against each build or setting and "
        "record each with smb-prof-record. Per-request numbers compare "
        "workloads of different lengths.")
    ap.add_argument("inputs", nargs="+", metavar="FILE")
    cli.add_select_args(ap)
    ap.add_argument("--label", metavar="A,B,...",
                    help="names for the recordings (default: file names)")
    ap.add_argument("--op", metavar="OPS", help="SMB2 commands to list")
    ap.add_argument("--top", type=int, default=15,
                    help="rows per table (default 15)")
    ap.add_argument("--waits", action="store_true",
                    help="keep CHANGE_NOTIFY in latency totals")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if len(args.inputs) < 2:
        ap.error("give two or more recordings")
    labels = args.label.split(",") if args.label else \
        [stem(p) for p in args.inputs]
    if len(labels) != len(args.inputs):
        ap.error("one --label per recording")
    runs = [cli.load(p) for p in args.inputs]
    res = []
    for run in runs:
        try:
            sel = cli.selection(args, run)
            ops = resolve_ops(args.op, run.layout) if args.op else None
        except ValueError as e:
            ap.error(str(e))
        res.append(measure(run, sel, args.waits))
    if args.json:
        print(json.dumps({"labels": labels, "runs": res}, indent=1))
        return 0
    for lab, r in zip(labels, res):
        print(f"{lab}: {r['file']}, {r['seconds']:.1f} s, Samba "
              f"{r['samba']}, {fmt_n(r['totals']['requests'])} SMB2 requests")
    print()
    heads = [""] + labels + [f"{lab} vs {labels[0]}" for lab in labels[1:]]
    rows = []
    for name, key, fmt in TOTALS:
        vals = [r["totals"].get(key) for r in res]
        cells = [fmt(v) if v not in (None, "-") else "-" for v in vals]
        if key == "p99":
            changes = [""] * (len(res) - 1)
        else:
            changes = [fmt_change(v, vals[0]) for v in vals[1:]]
        rows.append([name] + cells + changes)
    print(cli.table(rows, heads))

    names = list(dict.fromkeys(
        n for r in res for n in sorted(r["ops"], key=lambda x: -(
            r["ops"][x]["time_us"] or r["ops"][x]["count"]))))
    if ops:
        names = [n for n in names if n in ops]
    if names:
        print()
        heads = ["SMB2"] + [f"{lab} /s" for lab in labels] + \
            [f"{lab} mean" for lab in labels] + \
            [f"{lab} vs {labels[0]}" for lab in labels[1:]] + \
            [f"{lab} p99" for lab in labels]
        rows = []
        for n in names[:args.top]:
            ops_ = [r["ops"].get(n, {}) for r in res]
            rows.append(
                [label(n)] +
                [fmt_rate(o["rate"]) if o.get("rate") else "-" for o in ops_] +
                [fmt_us(o.get("mean_us")) for o in ops_] +
                [fmt_change(o.get("mean_us"), ops_[0].get("mean_us"))
                 for o in ops_[1:]] +
                [o.get("p99", "-") for o in ops_])
        print(cli.table(rows, heads))

    sys_names = list(dict.fromkeys(
        n for r in res for n in sorted(r["syscalls"], key=lambda x: -(
            r["syscalls"][x]["per_request"] or 0))))
    if sys_names:
        print()
        heads = ["System calls"] + [f"{lab} /req" for lab in labels] + \
            [f"{lab} vs {labels[0]}" for lab in labels[1:]] + \
            [f"{lab} mean" for lab in labels]
        rows = []
        for n in sys_names[:args.top]:
            v = [r["syscalls"].get(n, {}) for r in res]
            rows.append(
                [label(n)] +
                [f"{x['per_request']:.2f}" if x.get("per_request") is not None
                 else "-" for x in v] +
                [fmt_change(x.get("per_request"), v[0].get("per_request"))
                 for x in v[1:]] +
                [fmt_us(x.get("mean_us")) for x in v])
        print(cli.table(rows, heads))
    return 0
