"""smb-perf-stat: count what smbd spends on a workload."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import subprocess
import tempfile
import time

from . import cli, control, smbd, sysinfo
from .control import Control
from .fmt import fmt_si, parse_duration, parse_per

EVENTS = ("cycles", "instructions", "task-clock", "context-switches",
          "cpu-migrations", "page-faults")


def parse_stat(text: str, interval: bool, per_thread: bool) -> list[dict]:
    """perf stat -x, output as rows: {t, thread, event, value}; value is
    None when the event was not counted or not supported."""
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        f = line.split(",")
        t = None
        if interval:
            try:
                t = float(f.pop(0))
            except ValueError:
                continue
        thread = f.pop(0) if per_thread else None
        if len(f) < 3:
            continue
        raw, event = f[0], f[2]
        try:
            value = float(raw)
        except ValueError:
            value = None
        rows.append({"t": t, "thread": thread,
                     "event": event.split(":")[0], "value": value})
    return rows


def totals(rows: list[dict]) -> dict[str, float]:
    out: dict[str, float] = {}
    for r in rows:
        if r["value"] is not None:
            out[r["event"]] = out.get(r["event"], 0) + r["value"]
    return out


def derived(t: dict[str, float], wall: float) -> dict:
    """CPU seconds, CPUs busy, GHz while running, instructions per cycle."""
    cpu = t.get("task-clock", 0) / 1000
    d = {"cpu_s": cpu, "cpus": cpu / wall if wall else None}
    if t.get("cycles") and cpu:
        d["ghz"] = t["cycles"] / cpu / 1e9
    if t.get("cycles") and t.get("instructions"):
        d["ipc"] = t["instructions"] / t["cycles"]
    return d


def thread_owners(pids: list[int]) -> dict[int, int]:
    owners = {}
    for pid in pids:
        for tid in smbd.threads(pid):
            owners[tid] = pid
    return owners


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Count smbd's CPU time, cycles, instructions, context "
                    "switches and migrations over a workload or a time. "
                    "Cycles measure work; seconds depend on the clock, which "
                    "the frequency governor moves with load.",
        epilog="Runs saved with -o and --label compare with "
               "smb-perf-compare.")
    ap.add_argument("command", nargs="*",
                    help="a workload to run (after --); counting stops when "
                    "it exits")
    ap.add_argument("--duration", metavar="T",
                    help="how long without a command (default 10s)")
    t = ap.add_argument_group("what to count (default: every smbd process)")
    t.add_argument("--client", action="append", default=[], metavar="ADDR",
                   help="the smbd serving ADDR (repeatable)")
    t.add_argument("--pid", action="append", type=int, default=[],
                   help="a process (repeatable)")
    t.add_argument("--comm", action="append", default=[], metavar="GLOB",
                   help="processes named GLOB (repeatable)")
    t.add_argument("--system", action="store_true",
                   help="every CPU, everything on it")
    t.add_argument("--port", action="append", type=int, default=[],
                   metavar="N", help="an SMB port besides 445 and 139")
    ap.add_argument("--events", default=",".join(EVENTS),
                    help="perf events (default: %(default)s)")
    ap.add_argument("--interval", metavar="T",
                    help="also print the counts every T (e.g. 1s)")
    ap.add_argument("--per", metavar="N[:UNIT]",
                    help="the work done, e.g. 3000:file: adds cost per unit")
    ap.add_argument("--label", default="run",
                    help="name of this build or setting, for "
                    "smb-perf-compare")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="save the run as JSON")
    ap.add_argument("--json", action="store_true",
                    help="print the run as JSON")
    ap.add_argument("--perf", default="perf", help="perf binary")
    args = ap.parse_args(argv)
    perf = shutil.which(args.perf)
    if perf is None:
        ap.error(f"{args.perf} not found (install linux-perf)")
    try:
        duration = parse_duration(args.duration) if args.duration else (
            None if args.command else 10.0)
        interval = parse_duration(args.interval) if args.interval else None
        per = parse_per(args.per) if args.per else None
    except ValueError as e:
        ap.error(str(e))
    ports = tuple(sorted(set(smbd.SMB_PORTS) | set(args.port)))
    procs = [] if args.system else smbd.select(
        args.client, args.pid, args.comm, ports)
    if not args.system and not procs:
        cli.note("error: no process to count")
        return 1
    pids = [p.pid for p in procs]
    owners = thread_owners(pids)
    names = {p.pid: p.name for p in procs}
    info, freq = sysinfo.host(), sysinfo.cpufreq()
    for w in sysinfo.warnings(freq, info):
        cli.note(f"note: {w}")
    per_thread = not args.system
    started = datetime.datetime.now(datetime.timezone.utc)
    with tempfile.TemporaryDirectory(prefix="smbperf-") as tmp:
        out = os.path.join(tmp, "stat.csv")
        ctl = Control(tmp)
        cmd = [perf, "stat", "-x,", "-o", out, "-e", args.events]
        if interval:
            cmd += ["-I", str(max(10, int(interval * 1000)))]
        cmd += ["-a"] if args.system else [
            "--per-thread", "-p", ",".join(str(p) for p in pids)]
        err = os.path.join(tmp, "stderr")
        with open(err, "w") as ef:
            st = control.start(cmd + ctl.args(), stdout=subprocess.DEVNULL,
                               stderr=ef)
        on = False
        t0 = time.monotonic()
        status = None
        try:
            on = ctl.connect(st) and ctl.send("enable", st)
            t0 = time.monotonic()
            if on and args.command:
                try:
                    status = subprocess.run(args.command).returncode
                except OSError as e:
                    cli.note(f"error: {e}")
            elif on:
                while st.poll() is None and (
                        not duration or time.monotonic() - t0 < duration):
                    time.sleep(0.05)
        except KeyboardInterrupt:
            pass
        finally:
            if on and st.poll() is None:
                ctl.send("disable", st)
            wall = time.monotonic() - t0
            control.stop(st, timeout=60)
            ctl.close()
        if not on:
            with open(err) as ef:
                cli.note(f"error: perf stat failed: {ef.read().strip()}")
            return 1
        try:
            with open(out) as f:
                text = f.read()
        except OSError:
            text = ""
    rows = parse_stat(text, bool(interval), per_thread)
    final = [r for r in rows if not interval or r["t"] is not None]
    tot = totals(final)
    run = {
        "tool": "smb-perf-stat", "label": args.label,
        "who": "everything" if args.system else "smbd" if all(
            smbd.is_smbd(p.comm) for p in procs) else "selected processes",
        "start": started.isoformat(), "wall_s": round(wall, 6),
        "command": args.command or None, "status": status,
        "targets": "system" if args.system else pids,
        "events": args.events.split(","), "totals": tot,
        **derived(tot, wall),
        "per": {"n": per[0], "unit": per[1]} if per else None,
        "processes": _by_process(final, owners, names),
        "host": info, "cpufreq": freq,
    }
    if interval:
        run["intervals"] = _intervals(rows)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(run, f, indent=1)
    if args.json:
        print(json.dumps(run, indent=1))
        return 0
    _print(run, per)
    if args.output:
        cli.note(f"saved {args.output}")
    return 0


def _by_process(rows: list[dict], owners: dict[int, int],
                names: dict[int, str]) -> list[dict]:
    acc: dict[str, dict[str, float]] = {}
    for r in rows:
        if r["thread"] is None or r["value"] is None:
            continue
        comm, _, tid = r["thread"].rpartition("-")
        pid = owners.get(int(tid)) if tid.isdigit() else None
        key = names.get(pid, comm) if pid else comm
        if pid:
            key = f"{key} {pid}"
        d = acc.setdefault(key, {})
        d[r["event"]] = d.get(r["event"], 0) + r["value"]
    return [{"process": k, **v} for k, v in
            sorted(acc.items(), key=lambda kv: -kv[1].get("task-clock", 0))]


def _intervals(rows: list[dict]) -> list[dict]:
    acc: dict[float, dict[str, float]] = {}
    for r in rows:
        if r["t"] is not None and r["value"] is not None:
            d = acc.setdefault(r["t"], {})
            d[r["event"]] = d.get(r["event"], 0) + r["value"]
    out, prev = [], 0.0
    for t in sorted(acc):
        out.append({"t": t, "seconds": t - prev, **acc[t]})
        prev = t
    return out


def _print(run: dict, per: tuple[float, str] | None) -> None:
    tot = run["totals"]
    wall = run["wall_s"]
    parts = [f"{run['who']}: {run['cpu_s']:.3f} s CPU in {wall:.3f} s "
             f"({run['cpus']:.2f} CPUs)"]
    if "ghz" in run:
        parts.append(f"{fmt_si(tot['cycles'])} cycles at "
                     f"{run['ghz']:.2f} GHz")
    if "ipc" in run:
        parts.append(f"{fmt_si(tot['instructions'])} instructions, "
                     f"{run['ipc']:.2f} per cycle")
    sw = [f"{fmt_si(tot[k])} {k.replace('-', ' ')}"
          for k in ("context-switches", "cpu-migrations", "page-faults")
          if k in tot]
    if sw:
        parts.append(", ".join(sw))
    print("\n  ".join(parts))
    if run["command"]:
        print(f"workload: {' '.join(run['command'])} took {wall:.3f} s, "
              f"exit {run['status']}")
    if per:
        n, unit = per
        bits = [f"{1000 * run['cpu_s'] / n:.3f} ms CPU"]
        if tot.get("cycles"):
            bits.append(f"{fmt_si(tot['cycles'] / n)} cycles")
        if tot.get("instructions"):
            bits.append(f"{fmt_si(tot['instructions'] / n)} instructions")
        if run["command"]:
            bits.append(f"{1000 * wall / n:.3f} ms elapsed")
        print(f"per {unit} ({n:g}): " + ", ".join(bits))
    procs = run["processes"]
    if len(procs) > 1:
        rows = []
        for p in procs[:15]:
            d = derived(p, wall)
            rows.append([p["process"], f"{d['cpu_s']:.3f}",
                         f"{d['cpus']:.2f}",
                         f"{d['ghz']:.2f}" if "ghz" in d else "-",
                         f"{d['ipc']:.2f}" if "ipc" in d else "-",
                         fmt_si(p.get("context-switches", 0))])
        print()
        print(cli.table(rows, ["process", "CPU s", "CPUs", "GHz", "IPC",
                               "ctx sw"], "lrrrrr"))
        if len(procs) > 15:
            print(f"... {len(procs) - 15} more")
        if any(p["process"].startswith("smbd ") for p in procs):
            print("the parent smbd's line includes connections that started "
                  "during the count")
    if run.get("intervals"):
        rows = []
        for i in run["intervals"]:
            d = derived(i, i["seconds"])
            rows.append([f"{i['t']:.3f}", f"{d['cpus']:.2f}",
                         f"{d['ghz']:.2f}" if "ghz" in d else "-",
                         f"{d['ipc']:.2f}" if "ipc" in d else "-",
                         fmt_si(i.get("cycles", 0)),
                         fmt_si(i.get("context-switches", 0))])
        print()
        print(cli.table(rows, ["time", "CPUs", "GHz", "IPC", "cycles",
                               "ctx sw"], "rrrrrr"))
    govs = run["cpufreq"].get("governors")
    if govs:
        print(f"\nclock: {sysinfo.describe(run['cpufreq'])}")

