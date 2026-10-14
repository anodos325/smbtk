"""smb-prof-record: switch Samba's profiling on in chosen smbd processes
and write what their counters did, interval by interval, as JSON
lines."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import platform
import signal
import subprocess
import sys
import threading
import time

from . import cli, smbd
from .collect import Collector
from .data import SMB2_NAMES, WAITS, Acc
from .fmt import fmt_bytes, fmt_rate, fmt_us, parse_duration, wall
from .samba import Samba, SambaError
from .tdb import Reader, TdbError, wipe


def serving(p: smbd.Proc, main: int | None) -> bool:
    """The main smbd and the processes serving clients, not its helpers
    (notifyd, cleanupd ...)."""
    return p.pid == main or p.comm == "smbd" or p.comm.startswith("smbd[")


def host_info() -> dict:
    u = platform.uname()
    info = {"hostname": u.node, "kernel": u.release, "cpus": os.cpu_count()}
    try:
        with open("/etc/version") as f:
            info["truenas"] = f.read().strip()
    except OSError:
        pass
    return info


def session_extra(sessions: dict[int, list[dict]]) -> dict[int, dict]:
    out = {}
    for pid, ss in sessions.items():
        e = {"users": sorted({s["user"] for s in ss if s.get("user")})}
        for k in ("dialect", "encryption", "signing"):
            vals = sorted({s[k] for s in ss if s.get(k)})
            if vals:
                e[k] = ",".join(vals)
        out[pid] = e
    return out


class Live:
    """One line per interval on stderr."""

    def __init__(self, layout) -> None:
        self.layout = layout
        self.n = 0

    def show(self, sample: dict) -> None:
        dt = sample["dt"]
        if not dt:
            return
        acc = Acc()
        for e in sample["procs"].values():
            acc.add(e.get("d", {}))
        t = acc.smb2(self.layout)
        busy = {n: acc.get(n, "time") for n in SMB2_NAMES
                if n not in WAITS and acc.get(n, "time")}
        total = sum(busy.values())
        top = " ".join(f"{SMB2_NAMES[n]} {100 * v / total:.0f}%"
                       for n, v in sorted(busy.items(),
                                          key=lambda kv: -kv[1])[:3])
        mean = t["time"] / t["count"] if t["count"] else None
        if self.n % 20 == 0:
            print(f"{'time':8}  {'req/s':>7}  {'fail/s':>6}  {'mean':>7}  "
                  f"{'in/s':>7}  {'out/s':>7}  {'cpu':>5}  "
                  "busiest commands", file=sys.stderr)
        self.n += 1
        print(f"{wall(sample['t']):8}  {fmt_rate(t['count'] / dt):>7}  "
              f"{fmt_rate(t['failed'] / dt):>6}  {fmt_us(mean):>7}  "
              f"{fmt_bytes(t['in'] / dt):>7}  {fmt_bytes(t['out'] / dt):>7}  "
              f"{100 * acc.cpu() / 1e6 / dt:>4.0f}%  {top}",
              file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Turn on Samba's profiling counters in smbd processes "
        "(every one, or those serving a client), sample them every "
        "interval and write the change per process and per share as JSON "
        "lines, for smb-prof-summary, -latency, -hist and -compare. "
        "Profiling is put back as it was at the end.",
        epilog="examples: smb-prof-record --client 10.1.2.3 --duration 1m; "
        "smb-prof-record -o run.jsonl -- ./workload.sh")
    ap.add_argument("command", nargs=argparse.REMAINDER,
                    help="a workload to run; recording stops when it exits")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="JSON lines, gzipped if FILE ends in .gz "
                    "(default: ./smbprof-<time>.jsonl)")
    ap.add_argument("--interval", default="1", metavar="T",
                    help="sampling interval (default 1s; smbd writes its "
                    "counters about once a second)")
    ap.add_argument("--duration", metavar="T",
                    help="stop after T (default: when the command exits, "
                    "else Ctrl-C)")
    g = ap.add_argument_group("processes")
    g.add_argument("--client", action="append", default=[], metavar="ADDR",
                   help="the smbd serving this client, and any that start "
                   "serving it while recording (repeatable)")
    g.add_argument("--pid", action="append", type=int, default=[],
                   help="one smbd process (repeatable)")
    g.add_argument("--port", action="append", type=int, default=[],
                   help="SMB port, to find clients (default: the main "
                   "smbd's listening ports)")
    g = ap.add_argument_group("profiling")
    g.add_argument("--level", choices=("on", "count"), default="on",
                   help="on: counts, time and latency buckets (default); "
                   "count: counts only")
    g.add_argument("--reset", action="store_true",
                   help="delete the counters' records first, so smbstatus "
                   "--profile shows this run too (the recording itself "
                   "starts from its first sample either way)")
    g.add_argument("--keep", action="store_true",
                   help="leave profiling on at the end")
    g.add_argument("--no-enable", action="store_true",
                   help="change no profiling level; record what is "
                   "counting already")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="no line per interval, no summary")
    cli.add_samba_args(ap)
    args = ap.parse_args(argv)
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    try:
        interval = parse_duration(args.interval)
        duration = parse_duration(args.duration) if args.duration else None
    except ValueError as e:
        ap.error(str(e))
    if interval <= 0:
        ap.error("--interval must be positive")

    samba = Samba(args.samba, args.configfile)
    try:
        layout = samba.layout()
        tdb_path = args.tdb or samba.tdb_path()
        version = samba.version()
    except (SambaError, OSError) as e:
        raise SystemExit(f"smb-prof-record: {e}")
    magics = {m for m in (layout.magic(16), layout.magic(8)) if m}
    reader = Reader(tdb_path, args.samba, not args.no_bindings)
    try:
        first = reader.read()
    except (OSError, TdbError) as e:
        raise SystemExit(f"smb-prof-record: {tdb_path}: {e}")
    main_pid, procs = smbd.instance(samba.main_pid(), args.port or None)
    if not procs:
        raise SystemExit("smb-prof-record: no smbd running")
    probe = Collector(layout, magics)
    matched, _ = probe.decode(first)
    if probe.foreign and not matched:
        cli.note(f"warning: no record in {tdb_path} matches the layout "
                 "smbstatus gives; is it from another Samba build?")

    all_mode = not (args.client or args.pid)
    targets = {p.pid for p in procs.values() if serving(p, main_pid) and (
        all_mode or p.pid in args.pid or
        any(smbd.serves(p.clients, c) for c in args.client))}
    if args.pid:
        missing = set(args.pid) - set(procs)
        if missing:
            raise SystemExit("smb-prof-record: not an smbd of this "
                             f"instance: {sorted(missing)}")
    if not targets and not args.client:
        raise SystemExit("smb-prof-record: no smbd process chosen")

    prev: dict[int, str | None] = {}
    if not args.no_enable:
        prev = samba.get_levels(sorted(targets | ({main_pid} if main_pid
                                                  else set())))
        if any(v == "unsupported" for v in prev.values()):
            raise SystemExit("smb-prof-record: this smbd was built without "
                             "profiling")

    out_path = args.output or time.strftime("smbprof-%Y%m%d-%H%M%S.jsonl")
    try:
        out = gzip.open(out_path, "wt") if out_path.endswith(".gz") \
            else open(out_path, "w")
    except OSError as e:
        raise SystemExit(f"smb-prof-record: {e}")

    def write(rec: dict) -> None:
        out.write(json.dumps(rec, separators=(",", ":")) + "\n")

    start = time.time()
    write({"type": "start", "tool": "smb-prof-record", "format": 1,
           "time": round(start, 6), "interval": interval,
           "level": "as found" if args.no_enable else args.level,
           "reset": args.reset, "samba": version, "tdb": tdb_path,
           "reader": reader.how, "configfile": args.configfile,
           "host": host_info(), "main_pid": main_pid,
           "targets": {"all": all_mode, "clients": args.client,
                       "pids": sorted(targets)},
           "previous_levels": {str(k): v for k, v in prev.items()},
           "command": args.command or None,
           "magic": [f"{m:016x}" for m in sorted(magics)],
           "layout": layout.to_json()})
    out.flush()

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    collector = Collector(layout, magics)
    live = None if args.quiet else Live(layout)
    inherited: set[int] = set()
    work = None
    samples = 0
    t0 = time.monotonic()
    try:
        if not args.no_enable:
            failed = [p for p, ok in samba.set_levels(
                sorted(targets), args.level).items() if not ok]
            if failed:
                cli.note(f"warning: smbcontrol could not reach {failed}")
        if args.reset:
            try:
                wipe(tdb_path, args.samba)
            except (OSError, TdbError) as e:
                raise SystemExit(f"smb-prof-record: {tdb_path}: {e}")
        work = subprocess.Popen(args.command) if args.command else None
        if not args.quiet:
            if all_mode:
                what = "every smbd"
            elif args.client:
                what = "smbd serving " + ", ".join(args.client) + \
                    ("" if targets else " (none yet)")
            else:
                what = "smbd " + ", ".join(map(str, sorted(targets)))
            until = f" for {duration:g} s" if duration else \
                (" while the command runs" if work else "; Ctrl-C to stop")
            cli.note(f"recording {what} to {out_path}, every {interval:g} s"
                     f"{until} ({reader.how})")
        extra = session_extra(samba.sessions())
        sessions_at = time.monotonic()
        t0 = time.monotonic()
        next_t = t0
        drain = None
        while True:
            m = time.monotonic()
            now = time.time()
            _, procs = smbd.instance(main_pid, args.port or None)
            if args.client and not args.no_enable:
                new = [p for p, pr in procs.items() if p not in targets and
                       serving(pr, main_pid) and
                       any(smbd.serves(pr.clients, c) for c in args.client)]
                if new:
                    prev.update(samba.get_levels(new))
                    samba.set_levels(new, args.level)
                    targets.update(new)
                    write({"type": "event", "t": round(now, 6),
                           "what": "enabled", "pids": new})
            elif all_mode:
                inherited.update(p for p, pr in procs.items()
                                 if p not in targets and p != main_pid and
                                 serving(pr, main_pid))
            if any(p not in extra for p, pr in procs.items()
                   if p != main_pid and serving(pr, main_pid)) and \
                    m - sessions_at > 5:
                extra = session_extra(samba.sessions())
                sessions_at = m
            try:
                records = reader.read()
            except (OSError, TdbError) as e:
                cli.note(f"warning: {e}")
                records = {}
            for rec in collector.sample(now, m, records, procs, main_pid,
                                        extra):
                write(rec)
                if rec["type"] == "sample" and live:
                    live.show(rec)
            samples += 1
            out.flush()
            if work is not None and work.poll() is not None and \
                    drain is None:
                # Its connections close now; cleanupd merges them after.
                drain = m + max(2.0, interval)
            done = stop.is_set() or \
                (duration is not None and m - t0 >= duration - 1e-3) or \
                (drain is not None and m >= drain - 1e-3)
            if done:
                break
            next_t += interval
            if duration is not None:
                next_t = min(next_t, t0 + duration)
            stop.wait(max(0.0, next_t - time.monotonic()))
    finally:
        status = None
        if work is not None:
            if work.poll() is None:
                work.terminate()
            try:
                status = work.wait(timeout=30)
            except subprocess.TimeoutExpired:
                work.kill()
                status = work.wait()
        restored = {}
        if not (args.keep or args.no_enable):
            alive = smbd.processes()
            back = {p: prev.get(p) for p in targets}
            back.update({p: prev.get(main_pid) for p in inherited})
            for level in ("off", "count", "on"):
                pids = [p for p, v in back.items() if v == level and
                        p in alive and v != args.level]
                for p, ok in samba.set_levels(pids, level).items():
                    restored[str(p)] = level if ok else "failed"
        write({"type": "end", "t": round(time.time(), 6), "samples": samples,
               "seconds": round(time.monotonic() - t0, 3),
               "command_status": status, "restored": restored,
               "foreign_records": collector.foreign})
        out.close()
    if not args.quiet:
        cli.note(f"\nwrote {out_path}")
        from .cmd_summary import main as summary
        summary([out_path, "--top", "12"])
    return (status or 0) if work is not None else 0
