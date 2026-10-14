"""smb-prof-summary: what smbd did over a recording, by SMB2 command,
system call and process."""

from __future__ import annotations

import argparse
import json

from . import cli
from .data import (BIN_LABELS, SECTION_SMB2, SECTION_SYSCALLS, WAITS, Acc,
                   bins, label, pct_label)
from .fmt import fmt_bytes, fmt_n, fmt_pct, fmt_rate, fmt_us

BY = ("pid", "client", "user", "share")
IDENTITY = ("set_sec_ctx", "set_root_sec_ctx", "push_sec_ctx", "pop_sec_ctx")


def gather(run, sel, by: str | None = None):
    """Acc of the selection, and per group when `by` is given."""
    total = Acc()
    groups: dict[str, Acc] = {}
    if sel.shares or by == "share":
        items = ((key, e) for _, key, e in run.share_items(sel))

        def group_of(key):
            return run.shares.get(key, {}).get("share", key)
    else:
        items = ((pid, e) for _, pid, e in run.proc_items(sel))

        def group_of(pid):
            if by == "pid":
                info = run.procs.get(pid, {})
                return f"{pid} {run.proc_label(pid)}" if not info.get(
                    "main") else f"{pid} (closed connections)"
            if by == "user":
                return run.users(pid)
            return run.proc_label(pid)
    for src, e in items:
        d = e.get("d")
        if not d:
            continue
        total.add(d)
        if by:
            groups.setdefault(group_of(src), Acc()).add(d)
    return total, groups


def merged_buckets(acc: Acc, names) -> list[int] | None:
    out = None
    for n in names:
        b = acc.buckets(n)
        if b:
            out = list(b) if out is None else [x + y for x, y in zip(out, b)]
    return out


def smb2_rows(run, acc: Acc, seconds: float, waits: bool) -> list[dict]:
    names = acc.names(run.layout, SECTION_SMB2)
    busy = sum(acc.get(n, "time") for n in names if waits or n not in WAITS)
    rows = []
    for n in names:
        count = acc.get(n, "count")
        t = acc.get(n, "time")
        rows.append({
            "op": label(n), "counter": n, "count": count,
            "rate": count / seconds if seconds else None,
            "failed": acc.get(n, "failed_count"),
            "mean_us": t / count if count and run.times else None,
            "time_us": t if run.times else None,
            "share": t / busy if busy and run.times and (
                waits or n not in WAITS) else None,
            "idle_us": acc.get(n, "idle") if run.times else None,
            "p50": pct_label(acc.buckets(n), 50) if run.times else "-",
            "p99": pct_label(acc.buckets(n), 99) if run.times else "-",
            "bins": bins(acc.buckets(n)) if run.times else None,
            "in": acc.get(n, "inbytes"), "out": acc.get(n, "outbytes"),
            "wait": n in WAITS})
    rows.sort(key=lambda r: (r["wait"] and not waits, -(r["time_us"] or 0),
                             -r["count"]))
    return rows


def basic_rows(run, acc: Acc, section: str, seconds: float,
               requests: int) -> list[dict]:
    rows = []
    for n in acc.names(run.layout, section):
        count = acc.get(n, "count")
        t = acc.get(n, "time")
        if not count and not t:
            continue
        rows.append({
            "name": label(n), "counter": n, "count": count,
            "rate": count / seconds if seconds else None,
            "per_request": count / requests if requests else None,
            "mean_us": t / count if count and run.times else None,
            "time_us": t if run.times else None,
            "bytes": acc.get(n, "bytes")})
    rows.sort(key=lambda r: (-(r["time_us"] or 0), -r["count"]))
    return rows


def group_rows(run, groups: dict[str, Acc], seconds: float,
               waits: bool) -> list[dict]:
    rows = []
    for g, acc in groups.items():
        t = acc.smb2(run.layout, waits)
        names = [n for n in acc.names(run.layout, SECTION_SMB2)
                 if waits or n not in WAITS]
        busiest = max(names, key=lambda n: acc.get(n, "time"), default=None)
        cpu = acc.cpu()
        rows.append({
            "group": g, "requests": t["count"],
            "rate": t["count"] / seconds if seconds else None,
            "failed": t["failed"],
            "mean_us": t["time"] / t["count"] if t["count"] and run.times
            else None,
            "time_us": t["time"] if run.times else None,
            "p99": pct_label(merged_buckets(acc, names), 99)
            if run.times else "-",
            "cpu_us": cpu,
            "cpu_per_request_us": cpu / t["count"] if t["count"] else None,
            "loop_idle_us": acc.get("idle", "time"),
            "in": t["in"], "out": t["out"],
            "busiest": label(busiest) if busiest else "-"})
    rows.sort(key=lambda r: (-(r["time_us"] or 0), -r["requests"]))
    return rows


def report(run, sel, args) -> dict:
    total, groups = gather(run, sel, args.by)
    seconds = run.seconds(sel)
    t = total.smb2(run.layout, args.waits)
    cpu = total.cpu()
    ident = {n: total.get(n, "count") for n in IDENTITY}
    return {
        "file": run.path, "start": run.t0, "seconds": seconds,
        "samba": run.meta.get("samba"), "level": run.meta.get("level"),
        "per_share": bool(sel.shares or args.by == "share"),
        "processes": len({pid for _, pid, _ in run.proc_items(sel)}),
        "requests": t["count"], "failed": t["failed"],
        "smb_requests": total.get("request", "count"),
        "time_us": t["time"] if run.times else None,
        "idle_us": t["idle"] if run.times else None,
        "in": t["in"], "out": t["out"], "cpu_us": cpu,
        "connects": total.get("connect", "count"),
        "disconnects": total.get("disconnect", "count"),
        "auth": total.get("authentication", "count"),
        "auth_failed": total.get("authentication_failed", "count"),
        "identity": ident,
        "smb2": smb2_rows(run, total, seconds, args.waits),
        "syscalls": basic_rows(run, total, SECTION_SYSCALLS, seconds,
                               t["count"]),
        "other": {sec: basic_rows(run, total, sec, seconds, t["count"])
                  for sec in run.layout.sections
                  if sec not in (SECTION_SMB2, SECTION_SYSCALLS, "SMBD loop",
                                 "Authentication")},
        "groups": group_rows(run, groups, seconds, args.waits)
        if args.by else None,
    }


def rate(v: float | None) -> str:
    return "-" if v is None else fmt_rate(v)


def print_report(run, sel, r: dict, top: int) -> None:
    s = r["seconds"]
    print(cli.header(run, sel))
    if r["per_share"]:
        conns = {(run.shares.get(k, {}).get("share", k),
                  run.shares.get(k, {}).get("remote", "?"))
                 for _, k, _ in run.share_items(sel)}
        print("per-share counters (smbd profiling share): " + ", ".join(
            f"{sh} from {rem}" for sh, rem in sorted(conns)) or "none")
    else:
        who = sorted({run.proc_label(pid)
                      for _, pid, _ in run.proc_items(sel)})
        print(f"{r['processes']} smbd process(es): {', '.join(who) or '-'}")
    print()
    n = r["requests"]

    def per_s(v):
        return f"{fmt_bytes(v / s)}/s" if s else "-"
    rows = [["requests", f"{fmt_n(n)}  {fmt_rate(n / s) if s else '-'}/s  "
             f"failed {fmt_n(r['failed'])} ({fmt_pct(r['failed'], n)})"],
            ["bytes", f"in {fmt_bytes(r['in'])} ({per_s(r['in'])})  "
             f"out {fmt_bytes(r['out'])} ({per_s(r['out'])})"]]
    if r["time_us"] is not None and n:
        parked = f", {fmt_pct(r['idle_us'], r['time_us'])} parked" \
            if r["idle_us"] else ""
        rows.append(["time", f"{fmt_us(r['time_us'])} in SMB2 requests, "
                     f"{fmt_us(r['time_us'] / n)} each{parked}"])
    if r["cpu_us"]:
        per = f", {fmt_us(r['cpu_us'] / n)} per request" if n else ""
        rows.append(["cpu", f"{fmt_us(r['cpu_us'])} "
                     f"({fmt_pct(r['cpu_us'], s * 1e6)} of one CPU){per}"])
    ident = r["identity"]
    switches = ident["set_sec_ctx"] + ident["set_root_sec_ctx"]
    if switches:
        rows.append(["identity", f"{fmt_n(switches)} switches "
                     f"({ident['set_root_sec_ctx']} to root), "
                     f"{switches / n:.2f} per request" if n else
                     f"{fmt_n(switches)} switches"])
    if r["connects"] or r["auth"]:
        rows.append(["sessions", f"{r['connects']} connected, "
                     f"{r['disconnects']} disconnected, {r['auth']} "
                     f"authentications ({r['auth_failed']} failed)"])
    for k, v in rows:
        print(f"{k:9} {v}")
    smb2 = r["smb2"][:top]
    if smb2:
        print()
        out = []
        for x in smb2:
            out.append([
                x["op"] + (" (wait)" if x["wait"] else ""), fmt_n(x["count"]),
                rate(x["rate"]),
                fmt_n(x["failed"]) if x["failed"] else "",
                fmt_us(x["mean_us"]), x["p50"], x["p99"],
                fmt_us(x["time_us"]) if x["time_us"] is not None else "-",
                f"{100 * x['share']:.1f}%" if x["share"] is not None else "",
                fmt_pct(x["idle_us"], x["time_us"]) if x["idle_us"] else "",
                fmt_bytes(x["in"]), fmt_bytes(x["out"])])
        print(cli.table(out, ["SMB2", "count", "/s", "failed", "mean", "p50",
                              "p99", "time", "time%", "parked", "in", "out"]))
    for title, rows_ in [("System calls", r["syscalls"])] + [
            (sec, v) for sec, v in r["other"].items() if v]:
        if not rows_:
            continue
        shown = rows_[:top]
        with_bytes = any(x["bytes"] for x in shown)
        print()
        print(cli.table([[x["name"], fmt_n(x["count"]), rate(x["rate"]),
                          f"{x['per_request']:.2f}"
                          if x["per_request"] is not None else "-",
                          fmt_us(x["mean_us"]),
                          fmt_us(x["time_us"]) if x["time_us"] is not None
                          else "-"] +
                         ([fmt_bytes(x["bytes"]) if x["bytes"] else ""]
                          if with_bytes else [])
                         for x in shown],
                        [title, "count", "/s", "per req", "mean", "time"] +
                        (["bytes"] if with_bytes else [])))
    if r["groups"]:
        print()
        g = r["groups"][:top]
        print(cli.table([[x["group"], fmt_n(x["requests"]), rate(x["rate"]),
                          fmt_n(x["failed"]) if x["failed"] else "",
                          fmt_us(x["mean_us"]), x["p99"],
                          fmt_us(x["cpu_us"]) if x["cpu_us"] else "",
                          fmt_us(x["cpu_per_request_us"])
                          if x["cpu_us"] else "",
                          fmt_bytes(x["in"]), fmt_bytes(x["out"]),
                          x["busiest"]] for x in g],
                        ["by " + str(r.get("by", "")), "requests", "/s",
                         "failed", "mean", "p99", "cpu", "cpu/req", "in",
                         "out", "busiest"], "l" + "r" * 9 + "l"))
    if run.times:
        return
    print("\n(profiling level count: no times or latency buckets)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="What smbd did over a recording from smb-prof-record: "
        "requests, bytes, time, CPU and identity switches; every SMB2 "
        "command with rate, failures, mean, p50/p99 bins, share of time, "
        "time parked waiting and bytes; system calls and ACL calls with "
        "calls per request and mean time.",
        epilog="p50/p99 are the latency bins Samba counts (below 1, 2, 4 "
        "... 256 ms). CHANGE_NOTIFY waits for an event; its time is left "
        "out of totals unless --waits.")
    ap.add_argument("input", metavar="FILE", help="a recording (.jsonl, "
                    ".jsonl.gz)")
    cli.add_select_args(ap)
    ap.add_argument("--by", choices=BY,
                    help="add a table per process, client, user or share")
    ap.add_argument("--top", type=int, default=20,
                    help="rows per table (default 20)")
    ap.add_argument("--waits", action="store_true",
                    help="count CHANGE_NOTIFY time in the totals")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    run = cli.load(args.input)
    try:
        sel = cli.selection(args, run)
    except ValueError as e:
        ap.error(str(e))
    r = report(run, sel, args)
    r["by"] = args.by
    if args.json:
        r["bins"] = list(BIN_LABELS)
        print(json.dumps(r, indent=1))
        return 0
    print_report(run, sel, r, args.top)
    return 0
