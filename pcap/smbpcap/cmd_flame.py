"""smb-flame: where the server's time (or the request count, or the
bytes) went, as a flame graph."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import cli, flame
from .levels import level_values, levels_help, parse_levels
from .stats import fmt_bytes, fmt_dur

DEFAULT_STACK = "client,share,cmd,sub,status"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Flame graph of a capture. Each request is a sample "
                    "whose stack is the levels in --stack order and whose "
                    "width is its server time (default), its count, its "
                    "bytes or its client's idle time before it.",
        epilog="levels: " + levels_help())
    cli.add_input_args(ap)
    cli.add_filter_args(ap)
    cli.add_wait_arg(ap)
    ap.add_argument("--stack", default=DEFAULT_STACK, metavar="LEVELS",
                    help=f"comma-separated levels, root first (default: "
                    f"{DEFAULT_STACK})")
    ap.add_argument("--weight", default="time",
                    choices=["time", "count", "bytes", "idle"],
                    help="what a frame's width means (default: time; idle: "
                    "client idle time before the requests); the hover "
                    "text has time, count and bytes either way")
    cli.add_idle_arg(ap, "the tree, the JSON and the hover text")
    ap.add_argument("-o", "--svg", metavar="FILE",
                    help="write the SVG here (default: <capture>.flame.svg; "
                    "'-' for stdout)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--tree", action="store_true",
                   help="print the tree as indented text instead of an SVG")
    g.add_argument("--json", action="store_true",
                   help="print the tree as JSON instead of an SVG: name, "
                   "value, n, time_ns, bytes, idle_ns (with --idle), "
                   "children")
    g.add_argument("--collapsed", action="store_true",
                   help="print folded stacks instead of an SVG, for "
                   "flamegraph.pl or speedscope")
    ap.add_argument("--top", type=int, default=20, metavar="N",
                    help="children per node in --tree, the rest summed "
                    "into one row (default: 20; 0: all)")
    ap.add_argument("--title")
    ap.add_argument("--width", type=int, default=1400)
    ap.add_argument("--min-pct", type=float, default=0.05,
                    help="omit frames narrower than this percent")
    args = ap.parse_args(argv)
    try:
        levels = parse_levels(args.stack)
    except ValueError as e:
        ap.error(str(e))
    cap = cli.load_capture(args)
    flt = cli.make_filter(args, waits=args.waits)
    idle = args.idle or args.weight == "idle"
    samples = []
    for x in flt.apply(cap):
        time = x.weight if x.latency is not None else 0
        nbytes = x.nbytes if x.ok else 0
        think = x.idle or 0
        w = {"time": time, "bytes": nbytes, "count": 1,
             "idle": think}[args.weight]
        if w <= 0:
            continue
        stack = tuple(v for lv in levels for v in level_values(cap, x, lv))
        samples.append((stack, w, time, nbytes, think))
    if args.collapsed:
        sys.stdout.write(flame.collapsed(samples))
        return 0
    root = flame.build(samples)
    total = root.value
    verdict, _ = cap.vantage()
    if args.json:
        json.dump({"inputs": cap.inputs, "vantage": verdict,
                   "weight": args.weight, "levels": levels,
                   "root": flame.to_dict(root, idle)},
                  sys.stdout, indent=1, ensure_ascii=False)
        sys.stdout.write("\n")
        return 0
    what = {"time": "server time" if verdict == "server" else "response "
            "time", "count": "requests", "bytes": "bytes",
            "idle": "client idle time"}[args.weight]
    amount = f"{len(samples)} requests"
    if args.weight != "count":
        unit = fmt_bytes if args.weight == "bytes" else fmt_dur
        amount = f"{unit(total)} in {amount}"
    if idle and args.weight != "idle":
        amount += f", {fmt_dur(root.idle)} idle"
    title = args.title or (
        f"{os.path.basename(cap.inputs[0])}: {what} by {' > '.join(levels)}"
        f" ({amount})")
    if args.tree:
        print(title + "\n")
        sys.stdout.write(flame.render_tree(root, args.weight,
                                           args.min_pct / 100, args.top,
                                           idle=idle))
        return 0
    svg = flame.render_svg(root, title, args.weight, args.width,
                           args.min_pct / 100,
                           "hover for details, click to zoom", idle)
    out = args.svg or (cap.inputs[0] + ".flame.svg")
    if out == "-":
        sys.stdout.write(svg)
    else:
        with open(out, "w", encoding="utf-8") as f:
            f.write(svg)
        cli.note(f"wrote {out} ({amount})")
    return 0
