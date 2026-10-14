"""smb-trace: the requests, one per line, in order."""

from __future__ import annotations

import argparse
import json
import sys

from . import cli
from .stats import fmt_dur


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="List requests in time order with what they acted "
                    "on, how they ended and how long they took. Narrow "
                    "it with the selection options, e.g. --file '*.docx' "
                    "--client 10.1.2.3.")
    cli.add_input_args(ap)
    cli.add_filter_args(ap)
    ap.add_argument("--limit", type=int, default=0, help="stop after N rows")
    ap.add_argument("--events", action="store_true",
                    help="interleave break notifications, resets and "
                    "retransmissions")
    ap.add_argument("--json", action="store_true",
                    help="one JSON object per line")
    ap.add_argument("--wide", action="store_true",
                    help="do not shorten paths")
    cli.add_idle_arg(ap, "each request")
    args = ap.parse_args(argv)
    cap = cli.load_capture(args)
    flt = cli.make_filter(args)
    xs = list(flt.apply(cap))
    if args.limit:
        xs = xs[:args.limit]
    if args.json:
        for x in xs:
            d = x.to_dict()
            d["t_rel"] = cap.rel(x.t_req)
            if args.idle:
                d["idle_ns"] = x.idle
            print(json.dumps(d, ensure_ascii=False))
        return 0
    idle = [""] if args.idle else []
    rows: list[tuple[int, list[str]]] = []
    width = 10_000 if args.wide else 60
    for x in xs:
        flags = []
        if x.chain_len > 1:
            flags.append(f"chain{x.chain_len}")
        if x.interim is not None:
            flags.append("async")
        if x.cancel is not None:
            flags.append("cancel")
        if x.req.get("signed"):
            flags.append("signed")
        rows.append((x.t_req, [f"{cap.rel(x.t_req):.6f}"] + (
            ["" if x.idle == 0 else fmt_dur(x.idle)] if args.idle else []) + [
            cli.frames_ref(cap, x), x.client,
            x.user if x.user != "?" else "", x.label,
            cli.shorten(x.target, width), x.status_name, fmt_dur(x.latency),
            " ".join(flags),
        ]))
    if args.events:
        for b in cap.breaks:
            rows.append((b["t"], [f"{cap.rel(b['t']):.6f}"] + idle + [
                str(b["frame"]), b["dst"], "",
                f"** {b.get('kind', '')} break", b.get("file", ""), "", "",
                "",
            ]))
        for e in cap.tcp_events:
            what = "reset" if "R" in e.get("flags", "") else ",".join(
                e.get("ev", []))
            rows.append((e["t"], [f"{cap.rel(e['t']):.6f}"] + idle + [
                str(e["frame"]), e["src"], "",
                f"** tcp {what}", f"stream {e['stream']}", "", "", "",
            ]))
        rows.sort(key=lambda r: r[0])
    out = cli.table([r for _, r in rows], ["time"] + (
        ["idle"] if args.idle else []) + [
        "frames", "client", "user", "request", "target", "status",
        "latency", "flags"], "l" + ("r" if args.idle else "") + "llllllrl")
    try:
        print(out)
    except BrokenPipeError:
        sys.stderr.close()
    return 0
