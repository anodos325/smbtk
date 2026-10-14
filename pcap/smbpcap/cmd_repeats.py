"""smb-repeats: the same request, over and over."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict

from . import cli
from .model import Exchange
from .names import (
    CHANGE_NOTIFY, CLOSE, CREATE, FLUSH, IOCTL, LOCK, QUERY_DIRECTORY,
    QUERY_INFO, READ, SESSION_SETUP, SET_INFO, TREE_CONNECT, WRITE,
)
from .stats import fmt_dur, summarize


def repeat_key(x: Exchange) -> str:
    """What makes two requests 'the same request'."""
    r = x.req
    if x.proto != "smb2":
        return x.target
    c = x.cmd
    if c == CREATE:
        return f"{x.target} [{x.sub}]"
    if c in (READ, WRITE):
        return f"{x.target} @{r.get('off', 0)}+{r.get('len', 0)}"
    if c in (QUERY_INFO, SET_INFO, IOCTL, LOCK, CHANGE_NOTIFY):
        return f"{x.target} [{x.sub}]"
    if c == QUERY_DIRECTORY:
        return f"{x.target} [{x.sub} {r.get('pattern', '')!r}]"
    if c in (CLOSE, FLUSH, TREE_CONNECT, SESSION_SETUP):
        return x.target
    return x.target


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Requests repeated on the same target: a client "
                    "re-opening one path hundreds of times, re-reading "
                    "the same range, polling a directory, probing a "
                    "missing file. Grouped by client, command and target.")
    cli.add_input_args(ap)
    cli.add_filter_args(ap)
    ap.add_argument("--top", type=int, default=30)
    ap.add_argument("--min-count", type=int, default=3)
    ap.add_argument("--all-clients", action="store_true",
                    help="merge clients instead of grouping per client")
    ap.add_argument("--window", type=float, default=1.0,
                    help="seconds, for the peak rate column (default 1)")
    args = ap.parse_args(argv)
    cap = cli.load_capture(args)
    flt = cli.make_filter(args)
    xs = list(flt.apply(cap))
    groups: dict[tuple, list[Exchange]] = defaultdict(list)
    for x in xs:
        key = (x.cmd_name, repeat_key(x))
        if not args.all_clients:
            key = (x.client,) + key
        groups[key].append(x)
    fam: dict[str, tuple[int, int]] = {}
    for key, group in groups.items():
        cmd = key[-2]
        n, d = fam.get(cmd, (0, 0))
        fam[cmd] = (n + len(group), d + 1)
    win = int(args.window * 1e9)
    rows = []
    for key, group in groups.items():
        if len(group) < args.min_count:
            continue
        times = sorted(x.t_req for x in group)
        peak = 0
        j = 0
        for i, t in enumerate(times):
            while times[j] < t - win:
                j += 1
            peak = max(peak, i - j + 1)
        statuses = Counter(x.status_name for x in group)
        st = ", ".join(f"{s} {n}" if n > 1 else s
                       for s, n in statuses.most_common(3))
        lat = summarize([x.latency for x in group if x.latency is not None])
        tm = sum(x.weight for x in group)
        rows.append((len(group), [
            len(group), peak, f"{cap.rel(times[0]):.3f}",
            f"{cap.rel(times[-1]):.3f}", fmt_dur(tm), fmt_dur(lat["p50"]),
            st,
        ] + list(key[:-1]) + [cli.shorten(key[-1], 70)]))
    rows.sort(key=lambda r: -r[0])
    print(f"{len(xs)} requests in {len(groups)} distinct "
          f"(client, command, target) groups; per command:")
    for cmd, (n, d) in sorted(fam.items(), key=lambda kv: -kv[1][0]):
        print(f"  {cmd:16s} {n:7d} requests on {d:6d} targets"
              f"  ({n / d:.1f} per target)")
    print()
    if not rows:
        print(f"no target repeated {args.min_count} times or more")
        return 0
    headers = ["n", f"peak/{args.window:g}s", "first", "last", "time", "p50",
               "statuses"] + ([] if args.all_clients else ["client"]) + [
               "command", "target"]
    align = "rrrrrrl" + ("" if args.all_clients else "l") + "ll"
    print(cli.table([r for _, r in rows[:args.top]], headers, align))
    if len(rows) > args.top:
        print(f"... {len(rows) - args.top} more groups")
    return 0
