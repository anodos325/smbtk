"""smb-perf-record: profile smbd with perf."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time

from . import cli, control, perfdata, smbd, stacks, sysinfo
from .control import Control
from .flame import render_svg
from .fmt import fmt_dur, fmt_val, parse_duration

MODES = {
    "cpu": "where smbd's CPU time goes: cycles sampled --freq times a "
           "second per thread",
    "off": "where smbd waits: each switch off the CPU, timed until the "
           "thread runs again",
    "syscalls": "every system call smbd makes, with the code path making "
                "it",
}
CALL_GRAPH = {"cpu": "dwarf,16384", "off": "dwarf,8192",
              "syscalls": "dwarf,8192"}


def perf_command(perf: str, mode: str, out: str, pids: list[int],
                 system: bool, freq: int, call_graph: str,
                 max_size: str | None) -> list[str]:
    cmd = [perf, "record", "-k", "monotonic", "-o", out, "--call-graph",
           call_graph]
    if mode == "cpu":
        cmd += ["-F", str(freq)]
    elif mode == "off":
        cmd += ["-e", "sched:sched_switch", "--switch-events"]
    else:
        cmd += ["-e", "raw_syscalls:sys_enter"]
    if system:
        cmd.append("-a")
    else:
        cmd += ["-p", ",".join(str(p) for p in pids)]
    if max_size:
        cmd += ["--max-size", max_size]
    return cmd


def list_processes(ports) -> None:
    procs = smbd.smbd_processes(ports)
    if not procs:
        print("no smbd running")
        return
    now = time.time()
    rows = []
    for p in procs:
        rows.append([p.pid, p.ppid, p.name, ", ".join(p.clients),
                     p.threads, f"{p.cpu_s:.1f}",
                     fmt_dur((now - p.started) * 1e9)])
    print(cli.table(rows, ["pid", "ppid", "process", "clients", "threads",
                           "cpu s", "running"], "rrlllrr"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Profile smbd with perf and write perf.data, folded "
                    "stacks, a flame graph and a summary. Modes: "
                    + "; ".join(f"{k}: {v}" for k, v in MODES.items()) + ".",
        epilog="Recording every smbd attaches to the parent daemon too, so "
               "connections made during the run are recorded (perf follows "
               "forks). Stop early with Ctrl-C.")
    ap.add_argument("command", nargs="*",
                    help="a workload to run while recording (after --); "
                    "the recording stops when it exits")
    ap.add_argument("-o", "--output", metavar="DIR",
                    help="output directory (default: "
                    "./smbperf-<mode>-<time>)")
    ap.add_argument("--mode", choices=tuple(MODES), default="cpu",
                    help="what to record (default cpu; see above)")
    ap.add_argument("--duration", metavar="T",
                    help="how long (default 10s without a command; 0 runs "
                    "until Ctrl-C)")
    t = ap.add_argument_group(
        "what to record (default: every smbd process)")
    t.add_argument("--client", action="append", default=[], metavar="ADDR",
                   help="the smbd serving ADDR (repeatable)")
    t.add_argument("--pid", action="append", type=int, default=[],
                   help="a process (repeatable)")
    t.add_argument("--comm", action="append", default=[], metavar="GLOB",
                   help="processes named GLOB, e.g. 'rpcd_*' (repeatable)")
    t.add_argument("--system", action="store_true",
                   help="every process on the machine")
    t.add_argument("--port", action="append", type=int, default=[],
                   metavar="N", help="an SMB port besides 445 and 139")
    p = ap.add_argument_group("perf")
    p.add_argument("--freq", type=int, default=999, metavar="HZ",
                   help="cpu mode: samples per second per thread "
                   "(default 999, out of step with timer ticks)")
    p.add_argument("--call-graph", metavar="MODE",
                   help="dwarf[,BYTES], fp or lbr (default dwarf,16384 for "
                   "cpu, dwarf,8192 otherwise: Samba is built without frame "
                   "pointers)")
    p.add_argument("--max-size", default="4G", metavar="SIZE",
                   help="stop writing perf.data at SIZE (default 4G)")
    p.add_argument("--perf", default="perf", help="perf binary")
    ap.add_argument("--no-fold", action="store_true",
                    help="only record; fold and render later")
    ap.add_argument("--list", action="store_true",
                    help="list smbd processes and their clients, and exit")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the perf command and exit")
    args = ap.parse_args(argv)
    ports = tuple(sorted(set(smbd.SMB_PORTS) | set(args.port)))
    if args.list:
        list_processes(ports)
        return 0
    perf = shutil.which(args.perf)
    if perf is None:
        ap.error(f"{args.perf} not found (install linux-perf)")
    try:
        duration = parse_duration(args.duration) if args.duration else (
            None if args.command else 10.0)
    except ValueError as e:
        ap.error(str(e))
    if args.system and (args.client or args.pid or args.comm):
        ap.error("--system records everything; select later with "
                 "smb-perf-flame --client/--comm/--pid")
    procs = [] if args.system else smbd.select(
        args.client, args.pid, args.comm, ports)
    if not args.system and not procs:
        what = ", ".join(args.client + [str(p) for p in args.pid]
                         + args.comm) or "smbd"
        cli.note(f"error: no process found for {what}"
                 + (" (smb-perf-record --list shows who is connected)"
                    if args.client else ""))
        return 1
    pids = [p.pid for p in procs]
    started = datetime.datetime.now(datetime.timezone.utc)
    outdir = os.path.abspath(args.output or f"smbperf-{args.mode}-"
                             f"{started.strftime('%Y%m%d-%H%M%S')}")
    data = os.path.join(outdir, "perf.data")
    cg = args.call_graph or CALL_GRAPH[args.mode]
    cmd = perf_command(perf, args.mode, data, pids, args.system, args.freq,
                       cg, args.max_size)
    if args.dry_run:
        print(" ".join(cmd))
        return 0
    if os.geteuid() != 0:
        cli.note("warning: not root; perf needs root (or CAP_PERFMON) to "
                 "attach to smbd and to read kernel stacks")
    if os.path.exists(data):
        cli.note(f"error: {data} exists; choose another -o")
        return 1
    os.makedirs(outdir, exist_ok=True)
    info, freq = sysinfo.host(), sysinfo.cpufreq()
    for w in sysinfo.warnings(freq, info):
        cli.note(f"note: {w}")
    watcher = smbd.Watcher(ports)
    watcher.poll()
    meta = {
        "tool": "smb-perf-record", "mode": args.mode,
        "start": started.isoformat(), "perf_command": cmd,
        "freq": args.freq if args.mode == "cpu" else None,
        "call_graph": cg,
        "targets": "system" if args.system else pids,
        "selection": {"client": args.client, "pid": args.pid,
                      "comm": args.comm},
        "workload": args.command or None, "host": info, "cpufreq": freq,
        "smbd_version": sysinfo.smbd_version(),
        "perf_version": sysinfo.perf_version(perf),
        "tod_offset_ns": time.time_ns() - time.clock_gettime_ns(
            time.CLOCK_MONOTONIC),
    }
    _write_meta(outdir, meta)
    cli.note(f"recording {args.mode} ({MODES[args.mode]}) of "
             + ("every process" if args.system else
                f"{len(pids)} process{'es' if len(pids) != 1 else ''}: "
                + _names(procs))
             + (f" for {duration:g}s" if duration else
                " until the workload exits" if args.command else
                " until Ctrl-C"))
    log_path = os.path.join(outdir, "perf.log")
    with open(log_path, "w") as log, \
            tempfile.TemporaryDirectory(prefix="smbperf-") as tmp:
        ctl = Control(tmp)
        rec = control.start(cmd + ctl.args(), stdout=log, stderr=log)
        stop = threading.Event()
        poller = threading.Thread(target=_poll, args=(watcher, stop),
                                  daemon=True)
        on = False
        t0 = time.monotonic()
        reason = "duration"
        try:
            on = ctl.connect(rec) and ctl.send("enable", rec)
            if on:
                poller.start()
                t0 = time.monotonic()
                reason = _run(args.command, duration, rec, meta)
        except KeyboardInterrupt:
            reason = "interrupted"
        finally:
            if on and rec.poll() is None:
                ctl.send("disable", rec)
            elapsed = time.monotonic() - t0
            control.stop(rec)
            ctl.close()
            stop.set()
            if poller.is_alive():
                poller.join(timeout=5)
        if not on:
            cli.note(f"error: perf record failed: {_tail(log_path)}")
            return 1
    watcher.poll()
    names = watcher.names()
    log_text = _read(log_path)
    m = re.search(r"Captured and wrote ([\d.]+ \w+) .*?\((\d+) samples\)",
                  log_text)
    meta.update({
        "end": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "seconds": round(elapsed, 6), "stopped": reason,
        "perf_status": rec.returncode,
        "perf_samples": int(m.group(2)) if m else None,
        "perf_lost": re.findall(r"^.*lost.*$", log_text, re.M | re.I),
        "processes": {str(pid): dict(e, **({"name": names[pid]}
                                           if pid in names else {}))
                      for pid, e in watcher.seen.items()},
        "unit": {"cpu": "cycles", "off": "ns",
                 "syscalls": "calls"}[args.mode],
    })
    for pid in pids:
        meta["processes"].setdefault(str(pid), {"comm": next(
            (p.comm for p in procs if p.pid == pid), "")})
    _write_meta(outdir, meta)
    if not os.path.exists(data) or os.path.getsize(data) == 0:
        cli.note(f"error: no data recorded; {_tail(log_path)}")
        return 1
    cli.note(f"{outdir}: perf.data {_size(data)}, "
             f"{meta['perf_samples'] or '?'} samples over {elapsed:.1f}s "
             f"({reason})")
    for line in meta["perf_lost"]:
        cli.note(f"perf: {line.strip()}")
    if args.no_fold:
        return 0
    return _fold(outdir, data, meta, names, perf)


def _fold(outdir: str, data: str, meta: dict, names: dict[int, str],
          perf: str) -> int:
    try:
        prof = perfdata.load(data, perf)
    except perfdata.PerfError as e:
        cli.note(f"error: {e}")
        return 1
    if not prof.samples:
        cli.note("no samples: was smbd idle?")
        return 0
    st = stacks.cut_loop(stacks.fold(prof, stacks.Selection(names=names)))
    meta["unit"] = st.unit
    _write_meta(outdir, meta)
    with open(os.path.join(outdir, "perf.folded"), "w") as f:
        stacks.write_folded(st, f)
    loaded = cli.Loaded(st, data, "data", meta, prof.header)
    root = stacks.tree(st)
    what = {"cpu": f"{st.unit if st.unit != 'ns' else 'CPU time'} sampled "
                   f"at {meta.get('freq')} Hz",
            "off": "time off the CPU, by the stack each thread blocked in",
            "syscalls": "system calls, by the code path making them"}
    sub = (f"{what[meta['mode']]}; {meta['seconds']:.1f}s; "
           f"{sysinfo.describe(meta['cpufreq'])}")
    with open(os.path.join(outdir, "flame.svg"), "w") as f:
        f.write(render_svg(root, st, loaded.title(), sub))
    _summary(st, meta)
    print(f"\nflame graph: {os.path.join(outdir, 'flame.svg')}; more with "
          f"smb-perf-top {outdir} [--ops|--below FUNC|--stacks]")
    for n in st.notes:
        cli.note(n)
    return 0


def _summary(st: stacks.Stacks, meta: dict) -> None:
    total = st.total()
    unit = st.unit
    secs = meta["seconds"] or 1
    if meta["mode"] == "off":
        print(f"{fmt_dur(total)} off the CPU in {st.samples()} switches")
    else:
        print(f"{fmt_val(total, unit)}{'' if unit == 'ns' else ' ' + unit} "
              f"in {st.samples()} samples over {secs:.1f}s")
    procs: dict[str, float] = {}
    for s, w in st.weights.items():
        procs[s[0] if s else ""] = procs.get(s[0] if s else "", 0) + w
    rows = [[p, f"{100 * w / total:.1f}", fmt_val(w, unit)]
            for p, w in sorted(procs.items(), key=lambda kv: -kv[1])[:8]]
    print(cli.table(rows, ["process", "%", "weight"], "lrr"))
    if meta["mode"] != "syscalls":
        ops: dict[str, float] = {}
        for s, w in st.weights.items():
            op = smbd.command(s)
            ops[op] = ops.get(op, 0) + w
        rows = [[o, f"{100 * w / total:.1f}", fmt_val(w, unit)]
                for o, w in sorted(ops.items(), key=lambda kv: -kv[1])[:10]
                if o != "not smbd"]
        if rows:
            print()
            print(cli.table(rows, ["smbd work", "%", "weight"], "lrr"))
    else:
        calls: dict[str, float] = {}
        for s, w in st.weights.items():
            calls[s[-1]] = calls.get(s[-1], 0) + w
        rows = [[c[:-2], f"{100 * w / total:.1f}", fmt_val(w, unit),
                 f"{w / secs:.0f}"]
                for c, w in sorted(calls.items(), key=lambda kv: -kv[1])[:12]]
        print()
        print(cli.table(rows, ["system call", "%", "calls", "per second"],
                        "lrrr"))


def _run(command: list[str], duration: float | None,
         rec: subprocess.Popen, meta: dict) -> str:
    """Run the workload, or wait out the duration; why it ended."""
    t0 = time.monotonic()
    if command:
        try:
            meta["workload_status"] = subprocess.run(command).returncode
        except OSError as e:
            cli.note(f"error: {e}")
            meta["workload_status"] = None
        meta["workload_s"] = round(time.monotonic() - t0, 6)
        return "workload exited"
    while rec.poll() is None and (
            not duration or time.monotonic() - t0 < duration):
        time.sleep(0.1)
    return "perf exited" if rec.poll() is not None else "duration"


def _poll(watcher: smbd.Watcher, stop: threading.Event) -> None:
    while not stop.wait(0.5):
        try:
            watcher.poll()
        except OSError:
            pass




def _names(procs: list[smbd.Proc]) -> str:
    shown = [f"{p.name} ({p.pid})" for p in procs[:4]]
    if len(procs) > 4:
        shown.append(f"{len(procs) - 4} more")
    return ", ".join(shown)


def _write_meta(outdir: str, meta: dict) -> None:
    tmp = os.path.join(outdir, "perf.json.tmp")
    with open(tmp, "w") as f:
        json.dump(meta, f, indent=1)
    os.replace(tmp, os.path.join(outdir, "perf.json"))


def _read(path: str) -> str:
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _tail(path: str) -> str:
    lines = [ln.strip() for ln in _read(path).splitlines() if ln.strip()]
    return "; ".join(lines[-3:]) or "no output"


def _size(path: str) -> str:
    n = float(os.path.getsize(path))
    for unit in ("bytes", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"
