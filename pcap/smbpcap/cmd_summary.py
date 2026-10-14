"""smb-summary: what is in the capture."""

from __future__ import annotations

import argparse
import datetime
from collections import Counter, defaultdict

from . import cli, dirscans
from .model import Exchange
from .stats import fmt_bytes, fmt_dur, fmt_pct, percentile, summarize

SESSION_FLAGS = {1: "guest", 2: "null", 4: "encrypt"}
SHARE_TYPES = {1: "disk", 2: "pipe", 3: "print"}


def _flags(v: int | None) -> str:
    if not v:
        return ""
    return ",".join(n for bit, n in SESSION_FLAGS.items() if v & bit)


def _dialect(v: int | None) -> str:
    from .names import DIALECT
    if v is None:
        return "?"
    return DIALECT.get(v, hex(v))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Overview of an SMB capture: connections, sessions, "
                    "shares, command mix, failures, TCP trouble.")
    cli.add_input_args(ap)
    cli.add_filter_args(ap)
    ap.add_argument("--top", type=int, default=12,
                    help="rows to show in the longer tables")
    cli.add_idle_arg(ap, "a table per client")
    args = ap.parse_args(argv)
    cap = cli.load_capture(args)
    flt = cli.make_filter(args)
    xs = list(flt.apply(cap))
    out = []
    p = out.append

    # -- capture ------------------------------------------------------------
    t0 = datetime.datetime.fromtimestamp(
        (cap.t0 or 0) / 1e9, datetime.timezone.utc)
    p(f"Capture: {', '.join(cap.inputs)}")
    p(f"  first record {t0:%Y-%m-%d %H:%M:%S.%f} UTC, "
      f"{cap.duration():.3f} s long")
    smb1 = sum(1 for x in cap.exchanges if x.proto == "smb")
    p(f"  {cap.pdus} SMB PDUs, {len(cap.exchanges)} requests"
      f"{f', {smb1} of them SMB1' if smb1 else ''}, "
      f"{len(cap.orphans)} responses without a request, "
      f"{len(cap.breaks)} break notifications")
    if cap.encrypted_pdus:
        p(f"  {cap.encrypted_pdus} encrypted PDUs in {cap.encrypted_frames} "
          f"frames: their commands are not visible (pass session keys to "
          f"tshark with --pref to decrypt)")
    verdict, detail = cap.vantage()
    where = {
        "server": "taken on the server: latencies are server time",
        "client": "taken on the client: latencies include the network "
                  "round trip",
        "path": "taken in the network path: latencies include part of the "
                "round trip",
        "unknown": "vantage unknown",
    }[verdict]
    p(f"  {where}" + (f" ({detail})" if detail else ""))
    if xs is not cap.exchanges and len(xs) != len(cap.exchanges):
        p(f"  selection: {len(xs)} of {len(cap.exchanges)} requests")
    d = cap.diag
    if d.get("frames_broken") or d.get("frames_unattributed"):
        p(f"  extractor: {d.get('frames_broken', 0)} frames unparsed, "
          f"{d.get('frames_unattributed', 0)} frames with body fields "
          f"it could not attribute {d.get('unattributed', {})}")
    p("")

    # -- connections --------------------------------------------------------
    rows = []
    for st in sorted(cap.streams.values(), key=lambda s: s.first or 0):
        if not st.requests and not st.encrypted and st.resets == 0:
            continue
        ev = ", ".join(f"{k} {v}" for k, v in sorted(st.events.items()))
        rows.append([
            st.id, f"{st.client}:{st.client_port}",
            f"{st.server}:{st.server_port}", _dialect(st.dialect),
            st.requests, fmt_dur(st.min_latency),
            f"{cap.rel(st.first or 0):.3f}", f"{cap.rel(st.last or 0):.3f}",
            st.resets or "", ev,
        ])
    p(f"Connections ({len(rows)}):")
    p(cli.table(rows[:args.top * 2], [
        "stream", "client", "server", "dialect", "reqs", "fastest", "first",
        "last", "rst", "tcp events"], "rllllrrrrl", "  "))
    if len(rows) > args.top * 2:
        p(f"  ... {len(rows) - args.top * 2} more")
    p("")

    # -- sessions -----------------------------------------------------------
    rows = []
    for ses in cap.sessions.values():
        rows.append([
            f"{ses.id:#x}", ses.user, ses.host, ses.auth or "?", ses.client,
            _flags(ses.flags),
            "" if ses.setup_status in (0, None) else
            cli.names.status_name(ses.setup_status),
        ])
    p(f"Sessions ({len(rows)}):")
    if rows:
        p(cli.table(rows[:args.top], [
            "session", "user", "host", "auth", "client", "flags", "setup"],
            indent="  "))
    p("")

    # -- client idle ------------------------------------------------------
    if args.idle:
        by_client: dict[str, list[Exchange]] = defaultdict(list)
        for x in xs:
            by_client[x.client].append(x)
        rows = []
        for client, group in sorted(by_client.items()):
            span = max(x.t_resp or x.t_req for x in group) - min(
                x.t_start for x in group)
            gaps = sorted(x.idle for x in group if x.idle)
            idle = sum(gaps)
            rows.append([
                client, len(group), fmt_dur(span),
                fmt_dur(idle) if gaps else "-", fmt_pct(idle, span),
                len(gaps), fmt_dur(gaps[-1]) if gaps else "-",
                fmt_dur(percentile(gaps, 50)) if gaps else "-",
            ])
        p(f"Client idle ({cli.idle_meaning(verdict)}):")
        p(cli.table(rows[:args.top], [
            "client", "reqs", "span", "idle", "share", "pauses", "longest",
            "median"], "lrrrrrrr", "  "))
        p("  idle: time with nothing outstanding before a request; span: "
          "first request to last response; pauses: requests sent after "
          "idle time")
        p("")

    # -- shares -------------------------------------------------------------
    by_share: dict[str, list[Exchange]] = defaultdict(list)
    for x in xs:
        by_share[x.share].append(x)
    rows = []
    for share, group in sorted(by_share.items(),
                               key=lambda kv: -len(kv[1])):
        types = {x.share_type for x in group if x.share_type}
        sessions = {x.sesid for x in group}
        errs = sum(1 for x in group if x.status_class == "error")
        tm = sum(x.weight for x in group if not x.wait)
        rb = sum(x.nbytes for x in group if x.cmd_name == "READ" and x.ok)
        wb = sum(x.nbytes for x in group if x.cmd_name == "WRITE" and x.ok)
        rows.append([
            share, "/".join(SHARE_TYPES.get(t, str(t)) for t in types) or "?",
            len(sessions), len(group), errs or "", fmt_dur(tm),
            fmt_bytes(rb) if rb else "", fmt_bytes(wb) if wb else "",
        ])
    p(f"Shares ({len(rows)}):")
    if rows:
        p(cli.table(rows[:args.top], [
            "share", "type", "sessions", "reqs", "errors", "time", "read",
            "written"], "llrrrrrr", "  "))
    p("")

    # -- commands -----------------------------------------------------------
    by_cmd: dict[str, list[Exchange]] = defaultdict(list)
    for x in xs:
        by_cmd[x.cmd_name].append(x)
    total_time = sum(x.weight for x in xs if not x.wait)
    rows = []
    wait_note = []
    for name, group in by_cmd.items():
        lat = [x.latency for x in group if x.latency is not None]
        s = summarize(lat)
        unanswered = sum(1 for x in group if x.resp is None)
        cls = Counter(x.status_class for x in group)
        is_wait = all(x.wait for x in group)
        tm = sum(x.weight for x in group)
        if is_wait:
            wait_note.append(f"{name} ({len(group)} requests, {fmt_dur(tm)} "
                             f"waiting)")
        rows.append((tm if not is_wait else -1, [
            name, len(group), unanswered or "", cls.get("error", 0) or "",
            cls.get("probe", 0) or "",
            (cls.get("flow", 0) + cls.get("collateral", 0)) or "",
            fmt_dur(s["p50"]) if lat else "-",
            fmt_dur(s["p99"]) if lat else "-",
            fmt_dur(s["max"]) if lat else "-",
            fmt_dur(tm) if not is_wait else "(wait)",
            fmt_pct(tm, total_time) if not is_wait else "",
        ]))
    rows.sort(key=lambda r: -r[0])
    p("Commands:")
    p(cli.table([r for _, r in rows], [
        "command", "reqs", "no resp", "errors", "probes", "flow", "p50",
        "p99", "max", "time", "share"], "lrrrrrrrrrr", "  "))
    p(f"  time is server time summed over requests, {fmt_dur(total_time)} "
      f"in all; a compound's members share theirs")
    if wait_note:
        p(f"  waiting for events, not counted: {'; '.join(wait_note)}")
    p("")

    # -- directories listed again -------------------------------------------
    reread = [d for d in dirscans.find(cap, xs) if d.reread(2, 2.0)]
    if reread:
        reread.sort(key=lambda d: (-d.wasted, -d.time))
        p("Directories listed again (smb-dirscans has the scans):")
        for d in reread[:3]:
            kinds = ", ".join(
                f"{n} {k}s" if n > 1 else f"{n} {k}"
                for k in ("rewind", "repeat", "overlap")
                if (n := d.count("kind", k)))
            distinct = "?" if d.distinct is None else (
                ("~" if d.changed else "") + f"{d.distinct:,}")
            ratio = "" if d.ratio is None else f" ({d.ratio:.1f}x)"
            p(f"  {cli.shorten(d.path, 40)} from {d.client}: "
              f"{len(d.scans)} scans{', ' + kinds if kinds else ''}; "
              f"{d.returned:,} entries returned for {distinct}{ratio} in "
              f"{fmt_dur(d.time)}")
        if len(reread) > 3:
            p(f"  ... {len(reread) - 3} more")
        p("")

    # -- breaks, unanswered, orphans ---------------------------------------
    if cap.breaks:
        kinds = Counter(b.get("kind", "?") for b in cap.breaks)
        p("Break notifications: " + ", ".join(
            f"{v} {k}" for k, v in kinds.items()))
    unanswered = [x for x in xs if x.resp is None and x.cmd_name != "CANCEL"]
    if unanswered:
        p(f"Requests without a response ({len(unanswered)}):")
        rows = []
        for x in unanswered[:args.top]:
            rows.append([
                cli.frame_ref(cap, x), f"{cap.rel(x.t_req):.6f}", x.client,
                x.label, cli.shorten(x.target, 50),
                fmt_dur((cap.t1 or x.t_req) - x.t_req),
                "pending" if x.interim else "",
            ])
        p(cli.table(rows, ["frame", "time", "client", "request", "target",
                           "outstanding", "note"], "lrlllll", "  "))
        if len(unanswered) > args.top:
            p(f"  ... {len(unanswered) - args.top} more (smb-errors lists "
              f"them all)")
    if cap.orphans:
        kinds = Counter(o.get("cmd_name", "?") for o in cap.orphans)
        p("Responses whose request is not in the capture: "
          + ", ".join(f"{k} {v}" for k, v in kinds.most_common(6)))
    p("")

    # -- tcp ------------------------------------------------------------------
    ev = Counter()
    resets = []
    for st in cap.streams.values():
        for k, v in st.events.items():
            ev[k] += v
        if st.resets:
            resets.append(st)
    if ev or resets:
        p("TCP: " + ", ".join(f"{k} {v}" for k, v in sorted(ev.items()))
          + (f"; resets on {len(resets)} connection(s)" if resets else ""))
        for e in cap.tcp_events:
            if "R" in e.get("flags", ""):
                p(f"  reset at {cap.rel(e['t']):.6f} from {e['src']} on "
                  f"stream {e['stream']} (frame {e['frame']})")
    print("\n".join(out).rstrip())
    return 0
