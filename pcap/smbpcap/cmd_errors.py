"""smb-errors: what failed, what merely looked like it, what never
came back."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict

from . import cli
from .model import Exchange
from .stats import fmt_dur, fmt_pct


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Failed requests grouped by command and status, with "
                    "the protocol-flow and probe statuses set apart; "
                    "unanswered requests; TCP resets.")
    cli.add_input_args(ap)
    cli.add_filter_args(ap)
    ap.add_argument("--examples", type=int, default=3,
                    help="example requests per status")
    ap.add_argument("--all", action="store_true",
                    help="list every failed request")
    ap.add_argument("--by-client", action="store_true",
                    help="split the tables per client")
    args = ap.parse_args(argv)
    cap = cli.load_capture(args)
    flt = cli.make_filter(args)
    xs = list(flt.apply(cap))
    per_cmd = Counter(x.cmd_name for x in xs)
    classes = Counter(x.status_class for x in xs)
    print(f"{len(xs)} requests: {classes.get('ok', 0)} ok, "
          f"{classes.get('flow', 0)} protocol flow, "
          f"{classes.get('probe', 0)} probes, "
          f"{classes.get('collateral', 0)} collateral, "
          f"{classes.get('error', 0)} errors, "
          f"{classes.get('unanswered', 0)} unanswered")
    print()

    def section(title: str, cls: str, note: str) -> None:
        groups: dict[tuple, list[Exchange]] = defaultdict(list)
        for x in xs:
            if x.status_class != cls:
                continue
            key = (x.cmd_name, x.status_name)
            if args.by_client:
                key = (x.client,) + key
            groups[key].append(x)
        if not groups:
            return
        print(f"{title} ({sum(len(g) for g in groups.values())}): {note}")
        rows = []
        for key, group in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            clients = {x.client for x in group}
            first = min(x.t_req for x in group)
            last = max(x.t_req for x in group)
            cmd = key[-2]
            rows.append(list(key) + [
                len(group), fmt_pct(len(group), per_cmd[cmd]),
                len(clients), f"{cap.rel(first):.3f}", f"{cap.rel(last):.3f}",
                cli.shorten(_example(group), 60),
            ])
        headers = (["client"] if args.by_client else []) + [
            "command", "status", "n", "of cmd", "clients", "first", "last",
            "example target"]
        print(cli.table(rows, headers, "l" * (len(headers) - 6) + "rrrrrl",
                        "  "))
        if args.examples and cls == "error":
            print()
            for key, group in sorted(groups.items(),
                                     key=lambda kv: -len(kv[1])):
                print(f"  {' '.join(key)}:")
                shown = group if args.all else group[:args.examples]
                for x in shown:
                    print(f"    {cli.frames_ref(cap, x):>12s} "
                          f"{cap.rel(x.t_req):10.6f} {x.client:15s} "
                          f"{x.user:18s} {x.label:28s} "
                          f"{cli.shorten(x.target, 60)}")
                if len(group) > len(shown):
                    print(f"    ... {len(group) - len(shown)} more")
        print()

    section("Errors", "error",
            "answers the client did not ask for")
    section("Probes", "probe",
            "negative answers to existence checks and capability probes; "
            "normal unless the client keeps repeating them (smb-repeats)")
    section("Collateral", "collateral",
            "compound members not attempted because an earlier member "
            "failed")
    section("Protocol flow", "flow",
            "part of a normal exchange: end of listing, EOF, pending, "
            "notify cancelled ...")

    unanswered = [x for x in xs if x.resp is None and x.cmd_name != "CANCEL"]
    if unanswered:
        print(f"Unanswered ({len(unanswered)}): requests with no response "
              f"in the capture")
        rows = []
        shown = unanswered if args.all else unanswered[:20]
        for x in shown:
            rows.append([
                cli.frame_ref(cap, x), f"{cap.rel(x.t_req):.6f}", x.client,
                x.label, cli.shorten(x.target, 50),
                fmt_dur((cap.t1 or x.t_req) - x.t_req),
                "interim pending" if x.interim else
                ("cancelled" if x.cancel else ""),
            ])
        print(cli.table(rows, ["frame", "time", "client", "request",
                               "target", "outstanding", ""], "lrllllr",
                        "  "))
        if len(unanswered) > len(shown):
            print(f"  ... {len(unanswered) - len(shown)} more (--all)")
        print()
    if cap.orphans:
        kinds = Counter((o.get("cmd_name", "?"),
                         cli.names.status_name(o.get("status")))
                        for o in cap.orphans)
        print(f"Responses whose request is not in the capture "
              f"({len(cap.orphans)}): " + ", ".join(
                  f"{c} {s} x{n}" for (c, s), n in kinds.most_common(8)))
        print()
    resets = [e for e in cap.tcp_events if "R" in e.get("flags", "")]
    if resets or any(st.events for st in cap.streams.values()):
        ev = Counter()
        for st in cap.streams.values():
            ev.update(st.events)
        print("TCP: " + ", ".join(f"{k} {v}" for k, v in sorted(ev.items())))
        for e in resets:
            st = cap.streams.get(e["stream"])
            who = "server" if st and e["src"] == st.server else "client"
            print(f"  reset by the {who} ({e['src']}) at "
                  f"{cap.rel(e['t']):.6f}, stream {e['stream']}, "
                  f"frame {e['frame']}")
    if cap.encrypted_pdus:
        print(f"{cap.encrypted_pdus} encrypted PDUs could not be read.")
    return 0


def _example(group: list[Exchange]) -> str:
    targets = Counter(x.target for x in group)
    t, n = targets.most_common(1)[0]
    return f"{t} (x{n})" if n > 1 and len(targets) > 1 else t
