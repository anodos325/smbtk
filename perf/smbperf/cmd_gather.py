"""smb-perf-gather: the box as it bears on smbd, in one report: host,
CPUs, memory, disks, pools, network and Samba itself; all of it or the
sections named, sampled over a few seconds, kept as JSON."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import re
import shutil
import sys
import textwrap
import time

from . import blockdev, cli, cmd_disk, net, smbconf, smbd, sysinfo, sysstat, zfs
from .fmt import fmt_bytes, fmt_dur, fmt_si, parse_duration, wrap_items

SECTIONS = ("host", "cpu", "memory", "disk", "pool", "net", "smb")
WHAT = {
    "host": "kernel, OS, hardware, uptime, boot options, perf readiness",
    "cpu": "topology, clock policy, mitigations, usage, interrupts, top "
           "processes",
    "memory": "usage, swap, hugepages, vm sysctls, reclaim, NUMA, pressure",
    "disk": "the block devices, their queues and links, I/O rates",
    "pool": "ZFS pools, vdevs, ARC, ZIL, transaction groups, datasets",
    "net": "interfaces, offloads, rings, drops, TCP counters and sysctls",
    "smb": "Samba's processes, sessions, connections and settings",
}
TOP = 12           # processes in the CPU table
MAX_ROWS = 40      # Samba processes, sessions and connections listed
TROUBLE_IF = re.compile(r"err|drop|miss|fifo|over|coll|crc|abort|carrier",
                        re.I)
STANDARD_IF = re.compile(r"^(rx|tx)_(dropped|errors|missed_errors|fifo_errors"
                         r"|crc_errors|over_errors|frame_errors|length_errors"
                         r"|aborted_errors|carrier_errors)$")


# -- gathering -----------------------------------------------------------------

def gather(sections, interval: float, pools: list[str], shares: list[str],
           all_datasets: bool) -> dict:
    want = set(sections)
    started = datetime.datetime.now(datetime.timezone.utc)
    run: dict = {"tool": "smb-perf-gather", "start": started.isoformat(),
                 "interval_s": interval, "seconds": 0,
                 "sections": [s for s in SECTIONS if s in want],
                 "host": sysinfo.host(), "smbd_version": sysinfo.smbd_version(),
                 "memory": blockdev.meminfo(),
                 "zfs": {"available": zfs.have_zfs(), "version": zfs.version()},
                 "errors": []}
    if "host" in want:
        run["host"].update(_host_details(started))
    if "cpu" in want:
        run["cpu"] = {"topology": sysstat.topology(),
                      "freq": sysinfo.cpufreq(),
                      "mitigations": sysstat.mitigations(),
                      "load": sysstat.loadavg(),
                      "pressure": sysstat.pressure("cpu")}
    if "memory" in want:
        arc = zfs.read_kstat(f"{zfs.KSTAT}/arcstats")
        run["vm"] = {"sysctl": sysstat.sysctls(sysstat.VM_SYSCTLS),
                     "thp": sysstat.thp(), "numa": sysstat.numa_memory(),
                     "pressure": sysstat.pressure("memory"), "vmstat": None,
                     "arc_size": (arc or {}).get("data", {}).get("size")}
    if want & {"disk", "pool", "smb"}:
        run["mounts"] = blockdev.zfs_mounts()
    if want & {"disk", "pool"}:
        run["devices"] = blockdev.devices()
        for d in run["devices"]:
            d["zfs"] = []
        run["io"] = {"seconds": 0, "devices": {}}
    if "disk" in want:
        for d in run["devices"]:
            d["link"] = _link(d["name"])
    if want & {"smb", "pool"}:
        run["io_uring"] = {
            "disabled": blockdev.sysctl("kernel.io_uring_disabled"),
            "group": blockdev.sysctl("kernel.io_uring_group")}
        cmd_disk.collect_samba(run, shares)
    pool_names: list[str] = []
    if "pool" in want:
        pool_names = cmd_disk.collect_zfs(run, pools, all_datasets)
        cmd_disk.link_devices(run)
    if "net" in want:
        run["net"] = _net_static()
    if "smb" in want:
        _smb_static(run)
    _sample(run, want, interval, pools, pool_names)
    run["notes"] = notes(run)
    return run


def _host_details(started: datetime.datetime) -> dict:
    out: dict = {"uptime_s": sysstat.uptime(), "cmdline": sysstat.cmdline(),
                 "dmi": sysstat.dmi(),
                 "virtualization": sysstat.virtualization(),
                 "sysctl": sysstat.sysctls(sysstat.KERNEL_SYSCTLS),
                 "python": platform.python_version()}
    if out["uptime_s"] is not None:
        boot = started - datetime.timedelta(seconds=out["uptime_s"])
        out["boot_time"] = boot.isoformat()
    perf = shutil.which("perf")
    out["perf"] = {"path": perf,
                   "version": sysinfo.perf_version(perf) if perf else None}
    local = datetime.datetime.now().astimezone()
    out["timezone"] = local.tzname()
    return out


def _link(name: str) -> dict:
    """The links a disk hangs on: its SATA link's speed against the
    fastest it could do, and the PCIe link of the device or its
    controller."""
    out: dict = {}
    real = os.path.realpath(f"/sys/class/block/{name}/device")
    m = re.search(r"/ata(\d+)/", real)
    if m:
        base = f"/sys/class/ata_link/link{m.group(1)}"
        spd = sysstat._read(f"{base}/sata_spd")
        if spd:
            out["sata"] = {"speed": spd,
                           "max": sysstat._read(f"{base}/sata_spd_max")}
    d = real
    while d and d != "/":
        if os.path.exists(f"{d}/current_link_speed"):
            out["pcie"] = {
                "device": os.path.basename(d),
                "speed": sysstat._read(f"{d}/current_link_speed"),
                "width": sysstat._read(f"{d}/current_link_width"),
                "max_speed": sysstat._read(f"{d}/max_link_speed"),
                "max_width": sysstat._read(f"{d}/max_link_width"),
                "shared": "ata" in real or "host" in real.split(d)[-1]}
            break
        d = os.path.dirname(d)
    return out


def _net_static() -> dict:
    addrs = net.addresses()
    ifaces = {}
    for name in net.interfaces():
        link = net.link(name)
        link["addresses"] = addrs.get(name, [])
        if link["kind"] != "loopback" and link.get("state") != "down":
            link["ethtool"] = net.nic(name)
        ifaces[name] = link
    return {"interfaces": ifaces, "sysctl": net.sysctls(), "sockstat": None,
            "snmp": None, "softnet": None}


def _smb_static(run: dict) -> None:
    s = run["samba"]
    s["processes"] = []
    for p in smbd.samba_processes():
        entry = {"pid": p.pid, "ppid": p.ppid, "comm": p.comm, "name": p.name,
                 "threads": p.threads, "cpu_s": p.cpu_s, "started": p.started,
                 "clients": p.clients, "title_client": p.title_client}
        entry.update(sysstat.proc_details(p.pid))
        s["processes"].append(entry)
    cgroups = sorted({p["cgroup"] for p in s["processes"] if p.get("cgroup")})
    s["cgroups"] = {c: sysstat.cgroup_limits(c) for c in cgroups}
    s["status"] = smbd.smbstatus()
    s["effective"], s["effective_error"] = smbconf.effective_globals()
    if not s["effective"]:
        g = s.get("global", {})
        s["effective"] = {k: g[k] for k in smbconf.PERF_PARAMS if k in g}


def _snapshot(want: set, run: dict) -> dict:
    s: dict = {}
    if "cpu" in want:
        s["stat"] = sysstat.read_stat()
        s["softirqs"] = sysstat.read_softirqs()
    if want & {"cpu", "net"}:
        s["interrupts"] = sysstat.read_interrupts()
    if want & {"cpu", "smb"}:
        s["procs"] = {p.pid: p for p in smbd.processes()}
    if "memory" in want:
        s["vmstat"] = sysstat.read_vmstat()
    if "disk" in want and "pool" not in want:
        s["diskstats"] = blockdev.read_diskstats()
    if "disk" in want:
        s["ioerr"] = {d["name"]: blockdev.sysfs_disk(d["name"]).get("ioerr_cnt")
                      for d in run["devices"]}
    if "net" in want:
        ifaces = run["net"]["interfaces"]
        s["ifstats"] = {n: net.read_stats(n) for n in ifaces}
        s["nicstats"] = {n: net.nic_stats(n) for n, l in ifaces.items()
                         if l.get("ethtool")}
        s["snmp"] = net.read_snmp()
        s["softnet"] = net.read_softnet()
    if "smb" in want:
        s["sched"] = {p["pid"]: sysstat.proc_sched(p["pid"])
                      for p in run["samba"]["processes"]}
        s["cgroup_cpu"] = {c: sysstat.cgroup_cpu_stat(c)
                           for c in run["samba"]["cgroups"]}
    return s


def _sample(run: dict, want: set, interval: float, pools: list[str],
            pool_names: list[str]) -> None:
    """Every counter read twice an interval apart, the pool sampler
    started and finished around the same wait."""
    before = _snapshot(want, run)
    t0 = time.monotonic()
    state = cmd_disk.sample_start(run, interval, pools, pool_names) \
        if "pool" in want else None
    if interval > 0:
        time.sleep(interval)
    after = _snapshot(want, run)
    seconds = time.monotonic() - t0
    live = interval > 0
    run["seconds"] = seconds if live else 0
    if state is not None:
        cmd_disk.sample_finish(run, state)
    if "cpu" in want:
        _finish_cpu(run, before, after, seconds, live)
    if "memory" in want:
        a, b = after["vmstat"], before["vmstat"]
        run["vm"]["vmstat"] = {
            "snapshot": a,
            "delta": {k: a[k] - b[k] for k in a if k in b} if live else None}
    if "disk" in want and "pool" not in want and live:
        run["io"]["seconds"] = seconds
        run["io"]["devices"] = blockdev.io_rates(
            before["diskstats"], after["diskstats"], seconds)
    if "disk" in want:
        run["io"]["pressure"] = sysstat.pressure("io")
        for d in run["devices"]:
            a, b = after["ioerr"].get(d["name"]), before["ioerr"].get(d["name"])
            if isinstance(a, int):
                d["ioerr_cnt"] = a
                if live and isinstance(b, int):
                    d["ioerr_delta"] = a - b
    if "net" in want:
        _finish_net(run, before, after, seconds, live)
    if "smb" in want:
        _finish_smb(run, before, after, seconds, live)


def _finish_cpu(run: dict, before: dict, after: dict, seconds: float,
                live: bool) -> None:
    c = run["cpu"]
    if not live:
        c["usage"] = c["softirqs"] = c["interrupts"] = c["top"] = None
        return
    c["usage"] = sysstat.cpu_usage(before["stat"], after["stat"], seconds)
    c["softirqs"] = sysstat.softirq_rates(before["softirqs"],
                                          after["softirqs"], seconds)
    irqs = sysstat.irq_rates(before["interrupts"], after["interrupts"],
                             seconds)
    top = sorted(irqs.items(), key=lambda kv: -kv[1]["per_s"])[:10]
    c["interrupts"] = {"total_s": sum(v["per_s"] for v in irqs.values()),
                       "top": [{"irq": k, **v} for k, v in top]}
    c["top"] = top_processes(before["procs"], after["procs"], seconds)


def top_processes(before: dict, after: dict, seconds: float,
                  top: int = TOP) -> dict:
    """The processes that used the most CPU between two readings, with
    the CPUs used in all and by smbd."""
    rows = []
    total = smbd_total = 0.0
    me = os.getpid()
    for pid, a in after.items():
        b = before.get(pid)
        if b is None or b.started != a.started or pid == me:
            continue
        d = a.cpu_s - b.cpu_s
        if d < 0:
            continue
        total += d
        if smbd.is_smbd(a.comm):
            smbd_total += d
        rows.append((d, a))
    rows.sort(key=lambda r: (-r[0], r[1].pid))
    rows = [r for r in rows[:top] if r[0] > 0]
    pids = [a.pid for _, a in rows if smbd.is_smbd(a.comm)]
    cl = smbd.clients(pids) if pids else {}
    out = []
    for d, a in rows:
        a.clients = sorted(cl.get(a.pid, []))
        st = sysstat.proc_status(a.pid)
        out.append({"pid": a.pid, "name": a.name, "comm": a.comm,
                    "cpu": d / seconds if seconds else None,
                    "threads": a.threads, "rss": st.get("rss")})
    return {"processes": out,
            "cpus_used": total / seconds if seconds else None,
            "smbd_cpus": smbd_total / seconds if seconds else None}


def _finish_net(run: dict, before: dict, after: dict, seconds: float,
                live: bool) -> None:
    n = run["net"]
    n["sockstat"] = net.read_sockstat()
    irqs = sysstat.irq_rates(before["interrupts"], after["interrupts"],
                             seconds) if live else {}
    for name, link in n["interfaces"].items():
        link["stats"] = after["ifstats"].get(name, {})
        if live:
            link["rates"] = net.stat_rates(before["ifstats"].get(name, {}),
                                           link["stats"], seconds)
        a = after.get("nicstats", {}).get(name)
        if a is not None:
            b = before.get("nicstats", {}).get(name, {})
            link["driver_stats"] = {
                k: {"value": v,
                    "delta": v - b[k] if live and k in b else None}
                for k, v in a.items() if v or (k in b and v != b[k])}
        if link.get("irqs"):
            mine = [irqs[str(i)] for i in link["irqs"] if str(i) in irqs]
            cpus: set[int] = set()
            for r in mine:
                cpus.update(r["cpus"])
            link["irq_rate"] = {"per_s": sum(r["per_s"] for r in mine),
                                "cpus": sorted(cpus)} if mine else None
    n["snmp"] = {"snapshot": after["snmp"],
                 "delta": net.snmp_delta(before["snmp"], after["snmp"])
                 if live else None}
    n["softnet"] = net.softnet_delta(before["softnet"], after["softnet"]) \
        if live else None


def _map_pids(processes: list[dict], conns: list[dict]) -> None:
    """Which smbd serves each connection: by the socket when the process's
    descriptors could be read, else by the client address in the process
    title when one process and one connection have it."""
    by_client: dict[str, int] = {}
    by_host: dict[str, set[int]] = {}
    for p in processes:
        for c in p.get("clients", []):
            by_client[c] = p["pid"]
        if p.get("title_client") and not p.get("clients"):
            by_host.setdefault(p["title_client"], set()).add(p["pid"])
    peers: dict[str, int] = {}
    for c in conns:
        if c["state"] != "LISTEN":
            peers[c["peer"]] = peers.get(c["peer"], 0) + 1
    for c in conns:
        if c["state"] == "LISTEN":
            continue
        peer = c["peer"] if ":" not in c["peer"] else f"[{c['peer']}]"
        pid = by_client.get(f"{peer}:{c['pport']}")
        if pid is None and peers.get(c["peer"]) == 1 and \
                len(by_host.get(c["peer"], ())) == 1:
            pid = next(iter(by_host[c["peer"]]))
        if pid is not None:
            c["pid"] = pid


def _finish_smb(run: dict, before: dict, after: dict, seconds: float,
                live: bool) -> None:
    s = run["samba"]
    for p in s["processes"]:
        pid = p["pid"]
        a, b = after["procs"].get(pid), before["procs"].get(pid)
        if a:
            p["threads"] = a.threads
        if live and a and b and a.started == b.started:
            p["cpu"] = (a.cpu_s - b.cpu_s) / seconds
        sa, sb = after["sched"].get(pid), before["sched"].get(pid)
        if live and sa and sb:
            p["rq_wait"] = (sa["wait_ns"] - sb["wait_ns"]) / (seconds * 1e9)
            if "involuntary_switches" in sa and "involuntary_switches" in sb:
                p["preempted_s"] = (sa["involuntary_switches"]
                                    - sb["involuntary_switches"]) / seconds
    s["cgroup_cpu"] = {}
    for c, a in after.get("cgroup_cpu", {}).items():
        if a is None:
            continue
        b = before.get("cgroup_cpu", {}).get(c)
        entry: dict = {"snapshot": a}
        if live and b:
            entry["delta"] = {k: a[k] - b[k] for k in a if k in b}
        s["cgroup_cpu"][c] = entry
    conns, err = net.ss_connections(smbd.SMB_PORTS)
    if err:
        run["errors"].append(err)
    _map_pids(s["processes"], conns)
    addrs = {n: l.get("addresses", []) for n, l in
             run.get("net", {}).get("interfaces", {}).items()} \
        if "net" in run else net.addresses()
    states: dict[str, int] = {}
    for c in conns:
        c["interface"] = net.interface_of(c["local"], addrs) \
            if c["local"] not in ("*", "0.0.0.0", "::") else None
        states[c["state"]] = states.get(c["state"], 0) + 1
    s["connections"] = conns
    s["connection_states"] = states


# -- what stands out -----------------------------------------------------------

def _pct(x: float | None) -> str:
    return "-" if x is None else f"{100 * x:.1f}%"


def _per_s(v: float | None) -> str:
    return "-" if v is None else fmt_si(v) + "/s"


def _bps(v: float | None) -> str:
    return "-" if v is None else fmt_bytes(v) + "/s"


def _bits(v: float | None) -> str:
    """Bits a second as link speeds are quoted: 940 Mb/s, 9.4 Gb/s."""
    if v is None:
        return "-"
    for div, suffix in ((1e9, "Gb/s"), (1e6, "Mb/s"), (1e3, "Kb/s")):
        if v >= div:
            x = v / div
            return f"{x:.0f} {suffix}" if x >= 10 else f"{x:.1f} {suffix}"
    return f"{v:.0f} b/s"


def _mbps(v: int | None) -> str:
    if not v:
        return "-"
    return f"{v / 1000:g} Gb/s" if v >= 1000 else f"{v} Mb/s"


def _span(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    s = int(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m:02d}m"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def _psi(p: dict | None) -> str | None:
    if not p:
        return None
    parts = []
    for k in ("some", "full"):
        v = p.get(k)
        if v:
            parts.append(f"{k} {v.get('avg10', 0):.1f}% / "
                         f"{v.get('avg60', 0):.1f}% / {v.get('avg300', 0):.1f}%")
    return "; ".join(parts) + " (10 s / 1 min / 5 min)" if parts else None


def cpu_notes(run: dict) -> list[str]:
    out: list[str] = []
    c = run.get("cpu") or {}
    out += sysinfo.warnings(c.get("freq") or {}, run.get("host", {}))
    usage = c.get("usage") or {}
    u = usage.get("total")
    per = usage.get("per_cpu") or {}
    ncpu = len(per) or run.get("host", {}).get("cpus") or 0
    if u:
        hot = [n[3:] for n, v in per.items() if v["busy"] >= 0.9]
        if u["busy"] >= 0.85:
            out.append(f"CPUs {_pct(u['busy'])} busy over the interval: the "
                       "box is CPU-bound")
        elif hot and u["busy"] < 0.6:
            out.append(f"{len(hot)} CPU(s) over 90% busy "
                       f"(CPU {', '.join(hot[:4])}) while the average was "
                       f"{_pct(u['busy'])}: one thread or one interrupt line "
                       "is the bottleneck, not the number of CPUs")
        if u["iowait"] >= 0.2:
            out.append(f"{_pct(u['iowait'])} of CPU time was iowait: tasks "
                       "sat waiting for disks")
        if u["irq"] + u["softirq"] >= 0.15:
            out.append(f"{_pct(u['irq'] + u['softirq'])} of CPU time went to "
                       "interrupts and softirqs: network or disk interrupt "
                       "load; see which CPUs take them")
        if u["steal"] >= 0.02:
            out.append(f"{_pct(u['steal'])} steal time: the hypervisor gave "
                       "this guest's CPUs to others")
    rx = (c.get("softirqs") or {}).get("NET_RX")
    if rx and rx["per_s"] > 1000 and ncpu >= 2 and rx["top_share"] >= 0.6:
        out.append(f"{_pct(rx['top_share'])} of NET_RX softirqs "
                   f"({_per_s(rx['per_s'])}) ran on CPU {rx['top_cpu']}: "
                   "receive processing is concentrated on one CPU; more NIC "
                   "queues, RSS or RPS would spread it")
    load = c.get("load")
    if load and ncpu and load["1m"] > 2 * ncpu:
        out.append(f"load average {load['1m']:.1f} on {ncpu} CPUs: far more "
                   "tasks runnable or in D state than CPUs")
    some = (c.get("pressure") or {}).get("some", {})
    if some.get("avg10", 0) >= 10:
        out.append(f"CPU pressure: some task waited for a CPU "
                   f"{some['avg10']:.0f}% of the last 10 s (PSI)")
    if "mitigations=off" in (run.get("host", {}).get("cmdline") or ""):
        out.append("booted with mitigations=off")
    if (c.get("topology") or {}).get("smt") in ("off", "forceoff"):
        out.append("SMT is off: one hardware thread per core")
    return out


def memory_notes(run: dict) -> list[str]:
    out: list[str] = []
    m = run.get("memory", {})
    vm = run.get("vm") or {}
    total, avail = m.get("MemTotal"), m.get("MemAvailable")
    if total and avail is not None and avail < max(0.05 * total, 1 << 30):
        out.append(f"only {fmt_bytes(avail)} of {fmt_bytes(total)} "
                   "available: reclaim and swapping are near")
    d = (vm.get("vmstat") or {}).get("delta") or {}
    secs = run.get("seconds") or 0
    if d.get("pswpin", 0) + d.get("pswpout", 0):
        out.append(f"swapping over the interval: {fmt_si(d.get('pswpin', 0))} "
                   f"pages in, {fmt_si(d.get('pswpout', 0))} out")
    if secs and d.get("pgmajfault", 0) / secs > 50:
        out.append(f"{_per_s(d['pgmajfault'] / secs)} major page faults: "
                   "code or data read back from disk")
    stalls = sum(v for k, v in d.items() if k.startswith("allocstall"))
    if stalls:
        out.append(f"{fmt_si(stalls)} direct reclaim stalls over the "
                   "interval: allocations waited while memory was freed")
    thp = vm.get("thp") or {}
    if d.get("compact_stall"):
        out.append(f"{fmt_si(d['compact_stall'])} compaction stalls over the "
                   "interval: allocations waited for contiguous memory "
                   f"(transparent hugepages {thp.get('enabled', '?')}, defrag "
                   f"{thp.get('defrag', '?')})")
    if d.get("oom_kill"):
        out.append(f"{d['oom_kill']} OOM kill{'s' if d['oom_kill'] != 1 else ''}"
                   " over the interval")
    p = vm.get("pressure") or {}
    if p.get("full", {}).get("avg10", 0) >= 1 or \
            p.get("some", {}).get("avg10", 0) >= 5:
        out.append(f"memory pressure: some task was stalled on memory "
                   f"{p.get('some', {}).get('avg10', 0):.0f}% of the last "
                   "10 s (PSI)")
    if thp.get("enabled") == "always" and thp.get("defrag") == "always":
        out.append("transparent hugepages enabled=always with defrag=always: "
                   "a page fault can wait for compaction")
    numa = vm.get("numa") or {}
    if len(numa) > 1:
        full = [k for k, v in numa.items()
                if v.get("MemTotal") and v.get("MemFree", 0) < 0.02 * v["MemTotal"]]
        roomy = [k for k, v in numa.items()
                 if v.get("MemTotal") and v.get("MemFree", 0) > 0.2 * v["MemTotal"]]
        if full and roomy:
            out.append(f"NUMA node {', '.join(full)} nearly full while node "
                       f"{', '.join(roomy)} has room: allocations there reclaim "
                       "or go to the other node")
    if (vm.get("sysctl") or {}).get("vm.zone_reclaim_mode"):
        out.append("vm.zone_reclaim_mode set: a node reclaims its own memory "
                   "before using another's")
    return out


def disk_notes(run: dict) -> list[str]:
    out: list[str] = []
    rates = (run.get("io") or {}).get("devices", {})
    for d in run.get("devices", []):
        name = d["name"]
        r = rates.get(name)
        rot = d.get("rotational")
        if r:
            if r["util"] >= 0.9:
                out.append(f"{name}: {_pct(r['util'])} busy over the "
                           f"interval, {r['queue']:.1f} requests queued on "
                           "average: saturated")
            slow = 100e6 if rot else 20e6
            for k, lab in (("read_wait_ns", "read"), ("write_wait_ns", "write")):
                if r.get(k) and r[k] > slow and r[f"{lab}s_s"] >= 5:
                    out.append(f"{name}: mean {lab} wait {fmt_dur(r[k])} at "
                               f"{_per_s(r[lab + 's_s'])}: slow for "
                               + ("a disk" if rot else "an SSD"))
        if d.get("ioerr_delta"):
            out.append(f"{name}: the SCSI layer counted {d['ioerr_delta']} "
                       f"command errors over the interval ({d.get('ioerr_cnt')}"
                       " since boot): retries, timeouts or resets")
        if d.get("state") and d["state"] not in ("running", "live"):
            out.append(f"{name}: device state {d['state']}")
        link = d.get("link") or {}
        sata = link.get("sata") or {}
        if sata.get("speed") and sata.get("max") and \
                sata["speed"] != sata["max"]:
            out.append(f"{name}: SATA link at {sata['speed']} of "
                       f"{sata['max']} possible: the cable, port or a power "
                       "setting holds it down")
        pcie = link.get("pcie") or {}
        if all(pcie.get(k) for k in ("speed", "width", "max_speed",
                                     "max_width")) and (
                pcie["speed"] != pcie["max_speed"]
                or pcie["width"] != pcie["max_width"]):
            out.append(f"{name}: PCIe link {pcie['speed']} x{pcie['width']} "
                       f"of {pcie['max_speed']} x{pcie['max_width']} the "
                       f"device can do ({pcie['device']}"
                       + (", its controller)" if pcie.get("shared") else ")"))
        if d.get("scheduler") in ("bfq", "kyber", "cfq") and rot is False:
            out.append(f"{name}: I/O scheduler {d['scheduler']} on an SSD: "
                       "none or mq-deadline costs less, and ZFS orders its own "
                       "I/O")
    p = (run.get("io") or {}).get("pressure") or {}
    full = p.get("full", {}).get("avg10", 0)
    some = p.get("some", {}).get("avg10", 0)
    if full >= 10 or some >= 25:
        out.append(f"I/O pressure: some task was stalled on I/O {some:.0f}% "
                   f"of the last 10 s, every task {full:.0f}% (PSI)")
    return out


def net_notes(run: dict) -> list[str]:
    out: list[str] = []
    n = run.get("net") or {}
    for name, link in n.get("interfaces", {}).items():
        if link.get("kind") == "loopback" or link.get("state") == "down":
            continue
        et = link.get("ethtool") or {}
        st = et.get("settings") or {}
        if link.get("speed_mbps") and st.get("supported_max_mbps") and \
                st["supported_max_mbps"] > link["speed_mbps"]:
            out.append(f"{name}: linked at {_mbps(link['speed_mbps'])} though "
                       f"the NIC supports {_mbps(st['supported_max_mbps'])}: "
                       "the switch port, cable or autonegotiation holds it "
                       "down")
        if link.get("duplex") == "half":
            out.append(f"{name}: half duplex")
        feats = et.get("features") or {}
        off = [short for long_, short in net.FEATURES
               if long_ in feats and not feats[long_]["on"]
               and not feats[long_]["fixed"]
               and short in ("tso", "gso", "gro", "sg", "rx-csum", "tx-csum")]
        if off and link.get("kind") == "physical":
            out.append(f"{name}: {', '.join(off)} off: the CPU does per-packet "
                       "work the NIC could do")
        rings = et.get("rings") or {}
        cur, mx = rings.get("current", {}), rings.get("max", {})
        stats = link.get("stats") or {}
        d = (link.get("rates") or {}).get("delta", {})
        missed_keys = ("rx_missed_errors", "rx_fifo_errors", "rx_over_errors")
        missed = sum(stats.get(k, 0) for k in missed_keys)
        missed_d = sum(d.get(k, 0) for k in missed_keys)
        ring = f"; rx ring {cur['rx']} of {mx['rx']} max" \
            if cur.get("rx") and mx.get("rx") and cur["rx"] < mx["rx"] else ""
        if missed_d:
            out.append(f"{name}: {fmt_si(missed_d)} packets missed by the NIC "
                       "over the interval (receive ring full): the CPU did "
                       f"not drain it in time{ring}")
        elif missed:
            out.append(f"{name}: {fmt_si(missed)} packets missed by the NIC "
                       f"since boot, none in this interval{ring}")
        drops = d.get("rx_dropped", 0) + d.get("tx_dropped", 0)
        if drops:
            out.append(f"{name}: {fmt_si(drops)} packets dropped over the "
                       "interval")
        errs = sum(d.get(k, 0) for k in ("rx_errors", "tx_errors",
                                         "rx_crc_errors", "rx_frame_errors"))
        if errs:
            out.append(f"{name}: {fmt_si(errs)} packet error"
                       f"{'s' if errs != 1 else ''} over the interval: CRC or "
                       "framing, so cable, optics or duplex")
        moved = {k: v["delta"] for k, v in (link.get("driver_stats") or {}).items()
                 if v.get("delta") and not STANDARD_IF.match(k)}
        if moved:
            top = sorted(moved.items(), key=lambda kv: -kv[1])[:4]
            out.append(f"{name}: driver counters moved over the interval: "
                       + ", ".join(f"{k} +{fmt_si(v)}" for k, v in top))
        irq = link.get("irq_rate")
        if irq and irq["per_s"] > 5000 and len(irq["cpus"]) == 1 and (
                (link.get("queues") or {}).get("rx", 1) > 1
                or (link.get("speed_mbps") or 0) >= 10000):
            out.append(f"{name}: {_per_s(irq['per_s'])} interrupts, all on "
                       f"CPU {irq['cpus'][0]}: one CPU serves the NIC; "
                       "irqbalance or affinity would spread them")
        co = et.get("coalesce") or {}
        if co and co.get("adaptive_rx") is False and co.get("rx-usecs") == 0 \
                and (link.get("speed_mbps") or 0) >= 10000:
            out.append(f"{name}: interrupt coalescing off (rx-usecs 0, not "
                       "adaptive): an interrupt per packet at "
                       f"{_mbps(link['speed_mbps'])}")
    sn = (n.get("snmp") or {}).get("delta") or {}
    tcp, ext = sn.get("Tcp", {}), sn.get("TcpExt", {})
    if tcp.get("OutSegs") and tcp.get("RetransSegs", 0) / tcp["OutSegs"] > 1e-3:
        out.append(f"TCP retransmitted {fmt_si(tcp['RetransSegs'])} of "
                   f"{fmt_si(tcp['OutSegs'])} segments sent over the interval "
                   f"({_pct(tcp['RetransSegs'] / tcp['OutSegs'])}): packet "
                   "loss or a congested switch; each costs at least a "
                   "round trip"
                   + (f", {ext['TCPTimeouts']} of them full timeouts"
                      if ext.get("TCPTimeouts") else ""))
    elif ext.get("TCPTimeouts"):
        out.append(f"{ext['TCPTimeouts']} TCP retransmission timeouts over "
                   "the interval: whole RTO waits of 200 ms or more each")
    if tcp.get("InCsumErrors") or sn.get("IpExt", {}).get("InCsumErrors"):
        out.append("TCP or IP checksum errors over the interval: a bad NIC, "
                   "cable or offload")
    ld = ext.get("ListenOverflows", 0) + ext.get("ListenDrops", 0)
    if ld:
        out.append(f"{ld} connection attempts dropped from a full listen "
                   "queue over the interval (net.core.somaxconn and smbd's "
                   "backlog)")
    pruned = ext.get("PruneCalled", 0) + ext.get("RcvPruned", 0) \
        + ext.get("TCPRcvCollapsed", 0)
    if pruned:
        out.append(f"receive queues pruned or collapsed {fmt_si(pruned)} times "
                   "over the interval: a socket's receive memory ran out "
                   "before smbd read it; tcp_rmem's maximum or a fixed "
                   "SO_RCVBUF is the limit")
    if ext.get("TCPMemoryPressures") or ext.get("TCPAbortOnMemory"):
        out.append("TCP entered memory pressure over the interval: "
                   "net.ipv4.tcp_mem's thresholds were hit")
    sd = ext.get("TCPBacklogDrop", 0) + ext.get("TCPRcvQDrop", 0) \
        + ext.get("TCPZeroWindowDrop", 0)
    if sd:
        out.append(f"{sd} packets dropped at sockets over the interval "
                   "(backlog, receive queue or zero window)")
    if ext.get("TCPOFOQueue") and tcp.get("InSegs") and \
            ext["TCPOFOQueue"] / tcp["InSegs"] > 0.01:
        out.append(f"{_pct(ext['TCPOFOQueue'] / tcp['InSegs'])} of received "
                   "segments arrived out of order: reordering or loss on the "
                   "path")
    sfn = n.get("softnet") or {}
    if sfn.get("dropped"):
        out.append(f"{fmt_si(sfn['dropped'])} packets dropped by the per-CPU "
                   f"backlog over the interval on {sfn['cpus_dropping']} "
                   "CPU(s): net.core.netdev_max_backlog too small for the "
                   "burst")
    if sfn.get("time_squeeze"):
        out.append(f"{fmt_si(sfn['time_squeeze'])} NAPI polls cut short by the "
                   "budget over the interval: packets waited for the next "
                   "softirq round (net.core.netdev_budget, "
                   "netdev_budget_usecs)")
    sock = n.get("sockstat") or {}
    sysc = n.get("sysctl") or {}
    mem = (sock.get("TCP") or {}).get("mem")
    tm = str(sysc.get("net.ipv4.tcp_mem", "")).split()
    page = sock.get("page_size") or 4096
    if mem and len(tm) == 3 and tm[1].isdigit() and mem >= int(tm[1]):
        out.append(f"TCP holds {fmt_bytes(mem * page)} of socket memory, "
                   f"over the pressure threshold {fmt_bytes(int(tm[1]) * page)}"
                   " (net.ipv4.tcp_mem)")
    if sysc.get("net.ipv4.tcp_window_scaling") == 0:
        out.append("net.ipv4.tcp_window_scaling = 0: windows stop at 64 KB, "
                   "so each connection moves at most 64 KB per round trip")
    if sysc.get("net.ipv4.tcp_sack") == 0:
        out.append("net.ipv4.tcp_sack = 0: one lost segment costs a whole "
                   "window")
    if sysc.get("net.ipv4.tcp_moderate_rcvbuf") == 0:
        out.append("net.ipv4.tcp_moderate_rcvbuf = 0: receive buffers do not "
                   "grow with the connection; each stays at tcp_rmem's "
                   "default")
    for c in run.get("samba", {}).get("connections") or []:
        if c["state"] != "ESTAB":
            continue
        who = f"{c['peer']}:{c['pport']}"
        if c.get("busy_ms", 0) >= 1000:
            if c.get("rwnd_limited_pct", 0) >= 25:
                out.append(f"{who}: receive-window limited "
                           f"{c['rwnd_limited_pct']:.0f}% of its busy time: "
                           "the client's advertised window caps what smbd can "
                           "send; the client's socket buffer, or the round "
                           "trip, is the limit")
            if c.get("sndbuf_limited_pct", 0) >= 25:
                out.append(f"{who}: send-buffer limited "
                           f"{c['sndbuf_limited_pct']:.0f}% of its busy time: "
                           "smbd's socket send buffer filled; a fixed "
                           "SO_SNDBUF in socket options, or tcp_wmem's "
                           "maximum, is the limit")
        if c.get("retrans_total") and c.get("segs_out") and \
                c["retrans_total"] / c["segs_out"] > 1e-3:
            out.append(f"{who}: {c['retrans_total']} of "
                       f"{fmt_si(c['segs_out'])} segments retransmitted on "
                       f"this connection "
                       f"({_pct(c['retrans_total'] / c['segs_out'])})")
        if (c.get("rtt_ms") or 0) > 20:
            out.append(f"{who}: RTT {c['rtt_ms']:.1f} ms: every request and "
                       "response pays it; high for a LAN")
    return out


def smb_notes(run: dict) -> list[str]:
    out: list[str] = []
    s = run.get("samba") or {}
    procs = s.get("processes")
    if procs is None:
        return out
    if not any(smbd.is_smbd(p["comm"]) for p in procs):
        out.append("no smbd process is running")
    waits = [(p["name"], p["rq_wait"]) for p in procs
             if p.get("rq_wait", 0) >= 0.05 and p.get("cpu", 0) >= 0.05]
    if waits:
        top = sorted(waits, key=lambda x: -x[1])[:3]
        out.append("Samba processes waited for a CPU while runnable: "
                   + ", ".join(f"{n} {_pct(w)} of the interval" for n, w in top)
                   + ": CPU contention, not I/O")
    limits = s.get("cgroups") or {}
    for c, v in (s.get("cgroup_cpu") or {}).items():
        d = v.get("delta") or {}
        if d.get("throttled_usec"):
            out.append(f"cgroup {c}: throttled "
                       f"{fmt_dur(d['throttled_usec'] * 1000)} over the "
                       f"interval by its CPU quota (cpu.max "
                       f"{limits.get(c, {}).get('cpu.max', '?')})")
    for c, lim in limits.items():
        cm = str(lim.get("cpu.max", "max"))
        if not cm.startswith("max"):
            out.append(f"cgroup {c}: CPU quota {cm} (us per period)")
        if isinstance(lim.get("memory.max"), int):
            out.append(f"cgroup {c}: memory limited to "
                       f"{fmt_bytes(lim['memory.max'])}"
                       + (f", using {fmt_bytes(lim['memory.current'])}"
                          if lim.get("memory.current") else ""))
    for p in _parents(procs):
        of = p.get("open_files")
        if of and of[0] is not None and of[0] < 16384:
            out.append(f"smbd {p['pid']}: open files limited to {of[0]} "
                       f"(hard {of[1]}): each open file, directory and socket "
                       "takes one")
    st = s.get("status") or {}
    if st.get("error"):
        out.append(f"{st['error']}: sessions, dialects, encryption and "
                   "signing not seen; run as root")
    else:
        sess = st.get("sessions", [])
        old = [x for x in sess if x.get("dialect")
               and not str(x["dialect"]).startswith("SMB3")]
        if old:
            dialects = sorted({str(x["dialect"]) for x in old})
            out.append(f"{len(old)} of {len(sess)} sessions negotiated "
                       f"{', '.join(dialects)}: no multichannel or encryption "
                       "before SMB3"
                       + ("; SMB2_02 also lacks large reads and writes and "
                          "leases" if any("2_02" in d or "2.02" in d
                                          for d in dialects) else ""))
        enc = [x for x in sess if x.get("encryption")
               and not str(x["encryption"]).startswith(("none", "-"))]
        if enc:
            out.append(f"{len(enc)} of {len(sess)} sessions encrypted, "
                       f"{', '.join(sorted({str(x['encryption']) for x in enc}))}"
                       ": every byte is encrypted and decrypted on the CPU")
        sig = [x for x in sess if str(x.get("signing", "")).startswith("full")]
        if sig:
            out.append(f"{len(sig)} of {len(sess)} sessions sign every "
                       "packet: a hash per packet on the CPU")
    eff = s.get("effective") or {}
    so = eff.get("socket options", "")
    if re.search(r"SO_(RCV|SND)BUF\s*=", so):
        out.append(f"socket options = {so}: a fixed socket buffer turns off "
                   "the kernel's autotuning; a connection moves at most "
                   "buffer / RTT")
    prof = eff.get("smbd profiling level", "off")
    if prof.lower() not in ("off", "0", "no", "false"):
        out.append(f"smbd profiling level = {prof}: smbd times every call")
    lvl = eff.get("log level")
    if lvl:
        nums = [int(x) for x in re.findall(r"\b(\d+)\b", lvl)]
        if nums and max(nums) >= 3:
            out.append(f"log level = {lvl}: smbd writes a line for most "
                       "operations")
    if eff.get("strict locking", "").lower() in ("yes", "true", "1"):
        out.append("strict locking = yes: every read and write checks "
                   "byte-range locks")
    if eff.get("kernel oplocks", "").lower() in ("yes", "true", "1"):
        out.append("kernel oplocks = yes: leases are taken from the kernel "
                   "on every open")
    if eff.get("server multi channel support", "").lower() in ("no", "false",
                                                                "0"):
        out.append("server multi channel support = no: each client uses one "
                   "connection")
    return out


def _parents(procs: list[dict]) -> list[dict]:
    pids = {p["pid"] for p in procs if smbd.is_smbd(p["comm"])}
    return [p for p in procs if p["comm"] == "smbd" and p["ppid"] not in pids]


def notes(run: dict) -> dict[str, list[str]]:
    """Notes by section; "general" for what could not be run."""
    want = set(run.get("sections") or SECTIONS)
    out: dict[str, list[str]] = {}
    general = [f"could not run: {e}" for e in run.get("errors", [])]
    if general:
        out["general"] = general
    if "cpu" in want:
        out["cpu"] = cpu_notes(run)
    if "memory" in want:
        out["memory"] = cmd_disk.memory_notes(run) + memory_notes(run)
    if "disk" in want:
        out["disk"] = disk_notes(run)
    if "pool" in want:
        out["pool"] = [n for n in cmd_disk.pool_notes(run)
                       if not n.startswith("could not run: ")]
        if "memory" not in want:
            out["pool"] += cmd_disk.memory_notes(run)
    if "net" in want:
        out["net"] = net_notes(run)
    if "smb" in want:
        out["smb"] = smb_notes(run) + cmd_disk.share_notes(run)
    elif "pool" in want:
        out["pool"] += cmd_disk.share_notes(run)
    return {k: v for k, v in out.items() if v}


# -- output --------------------------------------------------------------------

def _wrap(prefix: str, text: str, indent: str = "    ") -> str:
    return textwrap.fill(text, width=100, initial_indent=prefix,
                         subsequent_indent=indent, break_long_words=False,
                         break_on_hyphens=False)


def print_host(run: dict) -> None:
    h = run.get("host", {})
    print("\nhost")
    if h.get("uptime_s") is not None:
        boot = (h.get("boot_time") or "")[:19].replace("T", " ")
        print(f"  up {_span(h['uptime_s'])} since {boot} UTC"
              + (f", local time zone {h['timezone']}" if h.get("timezone")
                 else ""))
    dmi = h.get("dmi") or {}
    hw = " ".join(x for x in (dmi.get("sys_vendor"), dmi.get("product_name"))
                  if x)
    if dmi.get("board_name"):
        hw += f" (board {dmi.get('board_vendor', '')} {dmi['board_name']})" \
            .replace("( ", "(")
    if dmi.get("bios_version"):
        hw += f", firmware {dmi['bios_version']} {dmi.get('bios_date', '')}" \
            .rstrip()
    v = h.get("virtualization") or {}
    kind = f"virtual machine on {v['vm']}" if v.get("vm") else "bare metal"
    if v.get("container"):
        kind += f", inside a {v['container']} container"
    print(f"  {hw or 'unknown hardware'}; {kind}")
    if h.get("cmdline"):
        print(_wrap("  boot: ", h["cmdline"]))
    sc = h.get("sysctl") or {}
    perf = h.get("perf") or {}
    print(f"  perf: {perf.get('version') or 'not installed'}; "
          f"kernel.perf_event_paranoid {sc.get('kernel.perf_event_paranoid', '-')}"
          f", kptr_restrict {sc.get('kernel.kptr_restrict', '-')}; "
          f"python {h.get('python', '-')}")
    fnr = str(sc.get("fs.file-nr", "")).split()
    if len(fnr) == 3 and all(x.isdigit() for x in fnr):
        limit = "no limit" if int(fnr[2]) >= 1 << 62 else fmt_si(int(fnr[2]))
        print(f"  files: {fmt_si(int(fnr[0]))} open of {limit} "
              "(fs.file-max); nr_open "
              f"{sc.get('fs.nr_open', '-')}; aio {sc.get('fs.aio-nr', '-')} "
              f"of {sc.get('fs.aio-max-nr', '-')}; inotify watches "
              f"{sc.get('fs.inotify.max_user_watches', '-')}")


def print_cpu(run: dict) -> None:
    c = run.get("cpu")
    if not c:
        return
    h = run.get("host", {})
    t = c.get("topology") or {}
    print("\nCPU")
    topo = (f"{t.get('sockets') or '?'} socket(s), {t.get('cores') or '?'} "
            f"cores, {t.get('cpus') or h.get('cpus') or '?'} threads")
    if t.get("smt"):
        topo += f", SMT {t['smt']}"
    nodes = t.get("numa_nodes") or {}
    if len(nodes) > 1:
        topo += f", {len(nodes)} NUMA nodes (" + "; ".join(
            f"node {k}: CPUs {v}" for k, v in nodes.items()) + ")"
    print(f"  {h.get('cpu') or 'unknown model'}: {topo}")
    if t.get("caches"):
        print("  caches: " + ", ".join(f"{k} {v}" for k, v in t["caches"].items()))
    freq = c.get("freq") or {}
    clock = sysinfo.describe(freq)
    if freq.get("cur_mhz"):
        clock += f", now {freq['cur_mhz'][0]}-{freq['cur_mhz'][1]} MHz"
    print(f"  clock: {clock}")
    mit = c.get("mitigations") or {}
    if mit:
        active = sorted(k for k, v in mit.items() if v.startswith("Mitigation"))
        vuln = sorted(k for k, v in mit.items() if v.startswith("Vulnerable"))
        print(_wrap("  mitigations: ",
                    f"{len(active)} active ({', '.join(active)}); "
                    f"{len(vuln)} vulnerable"
                    + (f" ({', '.join(vuln)})" if vuln else "")
                    + f"; {len(mit) - len(active) - len(vuln)} not affected"))
    secs = run.get("seconds")
    u = c.get("usage") or {}
    tt = u.get("total")
    per = u.get("per_cpu") or {}
    if tt and secs:
        print(f"  over {secs:.1f} s: {_pct(tt['busy'])} busy: user "
              f"{_pct(tt['user'] + tt['nice'])}, system {_pct(tt['system'])}, "
              f"iowait {_pct(tt['iowait'])}, irq {_pct(tt['irq'])}, softirq "
              f"{_pct(tt['softirq'])}, steal {_pct(tt['steal'])}; "
              f"{_per_s(u.get('ctxt_s'))} context switches, "
              f"{_per_s(u.get('intr_s'))} interrupts, "
              f"{_per_s(u.get('processes_s'))} forks")
        if per:
            hot = sorted(per.items(), key=lambda kv: -kv[1]["busy"])[:4]
            print("  busiest CPUs: " + ", ".join(
                f"{n[3:]} {_pct(v['busy'])}" for n, v in hot)
                + f"; {sum(1 for v in per.values() if v['busy'] >= 0.9)} of "
                f"{len(per)} over 90%")
    load = c.get("load")
    if load:
        line = (f"  load {load['1m']:.2f} {load['5m']:.2f} {load['15m']:.2f}, "
                f"{load['running']} running of {load['threads']} threads")
        if u.get("procs_blocked") is not None:
            line += f", {u['procs_blocked']} blocked in D state"
        print(line)
    so = c.get("softirqs")
    if so:
        top = sorted(so.items(), key=lambda kv: -kv[1]["per_s"])[:6]
        parts = []
        for k, v in top:
            if v["per_s"] < 1:
                continue
            text = f"{k} {_per_s(v['per_s'])}"
            if len(per) > 1 and v["top_share"] >= 0.5:
                text += f" ({_pct(v['top_share'])} on CPU {v['top_cpu']})"
            parts.append(text)
        if parts:
            print("  softirqs: " + ", ".join(parts))
    irq = c.get("interrupts")
    if irq and irq.get("top"):
        parts = []
        for i in irq["top"][:6]:
            name = sysstat.irq_name(i["irq"], i.get("desc") or "")
            parts.append(f"{name} {_per_s(i['per_s'])} on {len(i['cpus'])} "
                         f"CPU{'s' if len(i['cpus']) != 1 else ''}")
        print(wrap_items(f"  interrupts {_per_s(irq['total_s'])}: ", parts))
    psi = _psi(c.get("pressure"))
    if psi:
        print(f"  CPU pressure: {psi}")
    top = c.get("top")
    if top and top.get("processes") and secs:
        print(f"  processes over {secs:.1f} s: {top['cpus_used']:.2f} CPUs "
              f"used in all, {top['smbd_cpus']:.2f} by smbd")
        rows = [[p["name"], p["pid"], _pct(p["cpu"]), p["threads"],
                 fmt_bytes(p["rss"]) if p.get("rss") else "-"]
                for p in top["processes"]]
        print(cli.table(rows, ["process", "pid", "CPU", "threads", "rss"],
                        "lrrrr", indent="    "))


def print_memory(run: dict) -> None:
    vm = run.get("vm")
    if vm is None:
        return
    m = run.get("memory", {})
    total = m.get("MemTotal")
    print("\nmemory")
    parts = []
    for k, lab in (("Cached", "page cache"), ("AnonPages", "anonymous"),
                   ("Shmem", "shmem"), ("Slab", "slab"),
                   ("KernelStack", "kernel stacks"),
                   ("PageTables", "page tables"), ("Unevictable", "unevictable")):
        if m.get(k) is not None:
            text = f"{lab} {fmt_bytes(m[k])}"
            if k == "Slab" and m.get("SReclaimable") is not None:
                text += f" ({fmt_bytes(m['SReclaimable'])} reclaimable)"
            parts.append(text)
    arc = (run.get("zfs") or {}).get("arc") or {}
    arc_size = arc.get("size") or vm.get("arc_size")
    if arc_size:
        text = f"ARC {fmt_bytes(arc_size)}"
        if total:
            text += f" ({100 * arc_size / total:.0f}% of RAM)"
        parts.insert(0, text)
    if m.get("HugePages_Total"):
        parts.append(f"huge pages {m['HugePages_Total']} x "
                     f"{fmt_bytes(m.get('Hugepagesize'))}")
    print(wrap_items("  used: ", parts))
    if m.get("CommitLimit"):
        print(f"  committed {fmt_bytes(m.get('Committed_AS'))} of "
              f"{fmt_bytes(m['CommitLimit'])} limit; dirty "
              f"{fmt_bytes(m.get('Dirty'))}, writeback "
              f"{fmt_bytes(m.get('Writeback'))}")
    thp = vm.get("thp") or {}
    if thp:
        print("  transparent hugepages: " + ", ".join(
            f"{k.replace('_', ' ')} {v}" for k, v in thp.items())
            + (f"; {fmt_bytes(m['AnonHugePages'])} in use"
               if m.get("AnonHugePages") is not None else ""))
    sysc = vm.get("sysctl") or {}
    if sysc:
        print(wrap_items("  vm: ", [
            f"{k.split('.', 1)[1] if k.startswith('vm.') else k} {v}"
            for k, v in sysc.items()]))
    numa = vm.get("numa") or {}
    if len(numa) > 1:
        print("  NUMA: " + "; ".join(
            f"node {k}: {fmt_bytes(v.get('MemTotal'))}, "
            f"{fmt_bytes(v.get('MemFree'))} free, file "
            f"{fmt_bytes(v.get('FilePages'))}, anon {fmt_bytes(v.get('AnonPages'))}"
            for k, v in numa.items()))
    d = (vm.get("vmstat") or {}).get("delta")
    secs = run.get("seconds")
    if d and secs:
        stalls = sum(v for k, v in d.items() if k.startswith("allocstall"))
        print(f"  over {secs:.1f} s: {_per_s(d.get('pgfault', 0) / secs)} page "
              f"faults ({_per_s(d.get('pgmajfault', 0) / secs)} major); swap "
              f"in {fmt_si(d.get('pswpin', 0))}, out {fmt_si(d.get('pswpout', 0))}"
              f" pages; reclaim: kswapd scanned {fmt_si(d.get('pgscan_kswapd', 0))}"
              f", direct {fmt_si(d.get('pgscan_direct', 0))}, {fmt_si(stalls)} "
              f"allocation stalls, {fmt_si(d.get('compact_stall', 0))} "
              f"compaction stalls, {d.get('oom_kill', 0)} OOM kills")
    psi = _psi(vm.get("pressure"))
    if psi:
        print(f"  memory pressure: {psi}")


def _kind(d: dict) -> str:
    r = d.get("rotational")
    return "-" if r is None else ("HDD" if r else "SSD")


def _cell(v) -> str:
    return "-" if v is None or v == "" else str(v)


def _link_text(link: dict | None) -> str:
    link = link or {}
    sata = link.get("sata") or {}
    if sata.get("speed"):
        return sata["speed"].replace(" Gbps", "G SATA")
    pcie = link.get("pcie") or {}
    if pcie.get("speed") and not pcie.get("shared"):
        return f"PCIe {pcie['speed'].split()[0]} x{pcie.get('width', '?')}"
    return "-"


def print_disks(run: dict) -> None:
    devices = run.get("devices")
    if devices is None:
        return
    rows = []
    for d in devices:
        use = sorted({z["pool"] for z in d.get("zfs", [])})
        if not use:
            for p in d.get("partitions", []):
                what = p.get("fstype") or p.get("parttypename") or ""
                if p.get("label"):
                    what += f" {p['label']}"
                use.append(f"{p['name']} {what}".strip())
        rows.append([d["name"], (d.get("model") or "-")[:28],
                     fmt_bytes(d.get("size")), _kind(d),
                     d.get("transport") or "-", _link_text(d.get("link")),
                     d.get("scheduler") or "-", _cell(d.get("queue_depth")),
                     _cell(d.get("nr_requests")), d.get("write_cache") or "-",
                     _cell(d.get("ioerr_cnt")), ", ".join(use) or "-"])
    if rows:
        print("\ndisks")
        print(cli.table(rows, ["disk", "model", "size", "kind", "bus", "link",
                               "sched", "qd", "nr_req", "wcache", "ioerr",
                               "used by"], "llrllllrrlrl", indent="  "))
    cmd_disk.print_io(run)
    psi = _psi((run.get("io") or {}).get("pressure"))
    if psi:
        print(f"  I/O pressure: {psi}")


def print_pool(run: dict, show_params: bool, others: bool) -> None:
    if (run.get("zfs") or {}).get("arc"):
        print()
    cmd_disk.print_arc(run)
    cmd_disk.print_pools(run)
    cmd_disk.print_vdevs(run, others=others)
    if "disk" not in (run.get("sections") or ()):
        cmd_disk.print_io(run)
    cmd_disk.print_zpool_iostat(run)
    cmd_disk.print_zil(run)
    cmd_disk.print_txgs(run)
    cmd_disk.print_prefetch(run)
    cmd_disk.print_dataset_io(run)
    cmd_disk.print_datasets(run)
    cmd_disk.print_params(run, show_params)


def print_net(run: dict) -> None:
    n = run.get("net")
    if not n:
        return
    print("\nnetwork")
    rows = []
    for name, link in n.get("interfaces", {}).items():
        et = link.get("ethtool") or {}
        feats = et.get("features") or {}
        on = [short for long_, short in net.FEATURES
              if feats.get(long_, {}).get("on")]
        rings = et.get("rings") or {}
        cur = rings.get("current") or {}
        ring = "-"
        if cur.get("rx") is not None or cur.get("tx") is not None:
            ring = f"{cur.get('rx', '-')}/{cur.get('tx', '-')}"
            if (rings.get("max") or {}).get("rx"):
                ring += f" of {rings['max']['rx']}"
        q = link.get("queues") or {}
        co = et.get("coalesce") or {}
        coal = "-"
        if co:
            coal = "adaptive" if co.get("adaptive_rx") else \
                f"{co.get('rx-usecs', '-')} us"
        irq = link.get("irq_rate")
        irqs = f"{_per_s(irq['per_s'])} on {len(irq['cpus'])}" if irq else "-"
        kind = link.get("kind") or "-"
        if link.get("master"):
            kind += f" in {link['master']}"
        elif link.get("lower"):
            joiner = "of" if kind in ("bridge", "bond") else "on"
            kind += f" {joiner} {','.join(link['lower'])}"
        rows.append([name, kind, link.get("state") or "-",
                     _mbps(link.get("speed_mbps")), link.get("mtu") or "-",
                     link.get("driver") or (et.get("driver") or {}).get("driver")
                     or "-", f"{q.get('rx', '-')}/{q.get('tx', '-')}", ring,
                     coal, " ".join(on) or "-", irqs,
                     ", ".join((link.get("addresses") or [])[:2]) or "-"])
    print(cli.table(rows, ["interface", "kind", "state", "speed", "mtu",
                           "driver", "queues", "rings", "coalesce",
                           "offloads on", "irqs/s", "addresses"],
                    "lllrrlrlllll", indent="  "))
    secs = run.get("seconds")
    if secs:
        rows = []
        for name, link in n["interfaces"].items():
            r = link.get("rates")
            if not r:
                continue
            if link.get("kind") == "loopback" and not (
                    r["rx_bytes_s"] or r["tx_bytes_s"]):
                continue
            d = r.get("delta") or {}
            trouble = ", ".join(f"{k} +{v}" for k, v in sorted(d.items())
                                if v and TROUBLE_IF.search(k))
            bits = (r["rx_bytes_s"] + r["tx_bytes_s"]) * 8
            use = _pct(bits / (link["speed_mbps"] * 1e6)) \
                if link.get("speed_mbps") else "-"
            rows.append([name, _bps(r["rx_bytes_s"]), _bps(r["tx_bytes_s"]),
                         _per_s(r["rx_packets_s"]), _per_s(r["tx_packets_s"]),
                         use, trouble or "-"])
        if rows:
            print(f"  traffic over {secs:.1f} s:")
            print(cli.table(rows, ["interface", "rx", "tx", "rx pkts",
                                   "tx pkts", "of link", "errors and drops"],
                            "lrrrrrl", indent="  "))
    sn = n.get("snmp") or {}
    d = sn.get("delta") or {}
    snap = sn.get("snapshot") or {}
    tcp_d, ext_d = d.get("Tcp", {}), d.get("TcpExt", {})
    if secs and tcp_d:
        out_segs = tcp_d.get("OutSegs", 0)
        retr = tcp_d.get("RetransSegs", 0)
        print(_wrap(f"  TCP over {secs:.1f} s: ",
                    f"{_per_s(tcp_d.get('InSegs', 0) / secs)} segments in, "
                    f"{_per_s(out_segs / secs)} out; {retr} retransmitted "
                    f"({_pct(retr / out_segs) if out_segs else '-'}), "
                    f"{ext_d.get('TCPTimeouts', 0)} timeouts, "
                    f"{ext_d.get('TCPLossProbes', 0)} loss probes, "
                    f"{ext_d.get('TCPOFOQueue', 0)} out of order; "
                    f"{tcp_d.get('PassiveOpens', 0)} accepted, "
                    f"{tcp_d.get('ActiveOpens', 0)} opened, "
                    f"{tcp_d.get('EstabResets', 0)} resets; receive pruned "
                    f"{ext_d.get('PruneCalled', 0) + ext_d.get('RcvPruned', 0)}, "
                    f"collapsed {ext_d.get('TCPRcvCollapsed', 0)}; listen drops "
                    f"{ext_d.get('ListenDrops', 0)}, backlog drops "
                    f"{ext_d.get('TCPBacklogDrop', 0)}, memory pressures "
                    f"{ext_d.get('TCPMemoryPressures', 0)}"))
    tcp_s, ext_s = snap.get("Tcp", {}), snap.get("TcpExt", {})
    if tcp_s:
        out_segs = tcp_s.get("OutSegs", 0)
        retr = tcp_s.get("RetransSegs", 0)
        print(_wrap("  TCP since boot: ",
                    f"{tcp_s.get('CurrEstab', '-')} connections established "
                    f"now; {fmt_si(retr)} of {fmt_si(out_segs)} segments "
                    f"retransmitted ({_pct(retr / out_segs) if out_segs else '-'})"
                    f"; {tcp_s.get('InCsumErrors', 0)} checksum errors; "
                    f"{ext_s.get('ListenDrops', 0)} listen drops; "
                    f"{ext_s.get('PruneCalled', 0)} receive prunes; "
                    f"{ext_s.get('TCPMemoryPressures', 0)} memory pressures"))
    sfn = n.get("softnet")
    if sfn and secs:
        print(f"  softnet over {secs:.1f} s: "
              f"{_per_s(sfn['processed'] / secs)} packets processed, "
              f"{sfn['dropped']} dropped (backlog full), "
              f"{sfn['time_squeeze']} time squeezes, {sfn['received_rps']} "
              "steered by RPS")
    sock = n.get("sockstat") or {}
    tcp = sock.get("TCP") or {}
    if tcp:
        page = sock.get("page_size") or 4096
        text = (f"TCP {tcp.get('inuse', '-')} in use, {tcp.get('tw', '-')} "
                f"time-wait, {tcp.get('orphan', '-')} orphaned, "
                f"{tcp.get('alloc', '-')} allocated, "
                f"{fmt_bytes((tcp.get('mem') or 0) * page)} of memory")
        tm = str((n.get("sysctl") or {}).get("net.ipv4.tcp_mem", "")).split()
        if len(tm) == 3 and all(x.isdigit() for x in tm):
            text += (f" (pressure at {fmt_bytes(int(tm[1]) * page)}, limit "
                     f"{fmt_bytes(int(tm[2]) * page)})")
        print(f"  sockets: {text}")
    sysc = n.get("sysctl") or {}
    if sysc:
        print(wrap_items("  sysctl: ", [
            f"{k.split('.', 2)[-1]} {v}" for k, v in sysc.items()]))


def print_smb(run: dict) -> None:
    s = run.get("samba")
    if s is None or "processes" not in s:
        return
    ver = run.get("smbd_version")
    print("\nSamba" + (f" {ver.replace('Version ', '')}" if ver else ""))
    procs = s.get("processes") or []
    secs = run.get("seconds")
    try:
        start = datetime.datetime.fromisoformat(run["start"]).timestamp()
    except (KeyError, ValueError):
        start = time.time()
    if procs:
        fam: dict[str, dict] = {}
        for p in procs:
            k = "smbd" if smbd.is_smbd(p["comm"]) else p["comm"]
            f = fam.setdefault(k, {"n": 0, "cpu": 0.0, "rss": 0})
            f["n"] += 1
            f["cpu"] += p.get("cpu") or 0
            f["rss"] += p.get("rss") or 0
        print("  processes: " + ", ".join(
            f"{k} x{v['n']}" + (f" ({_pct(v['cpu'])} CPU)" if secs else "")
            + f" {fmt_bytes(v['rss'])}"
            for k, v in sorted(fam.items(), key=lambda kv: -kv[1]["n"])))
        ordered = sorted(procs, key=lambda p: (-(p.get("cpu") or 0), p["pid"]))
        rows = []
        for p in ordered[:MAX_ROWS]:
            rows.append([
                p["name"], p["pid"], p.get("threads", "-"),
                _pct(p["cpu"]) if p.get("cpu") is not None else "-",
                _pct(p["rq_wait"]) if p.get("rq_wait") is not None else "-",
                _per_s(p["preempted_s"]) if p.get("preempted_s") is not None
                else "-",
                fmt_bytes(p["rss"]) if p.get("rss") else "-",
                p["fds"] if p.get("fds") is not None else "-",
                _span(start - p["started"]) if p.get("started") else "-",
                f"{p.get('cpu_s', 0):.1f}",
                ", ".join(sorted({smbd.host_of(c) for c in p.get("clients", [])})
                          or ([p["title_client"]] if p.get("title_client")
                              else []))])
        print(cli.table(rows, ["process", "pid", "thr", "CPU", "rq wait",
                               "preempt", "rss", "fds", "up", "CPU s",
                               "clients"], "lrrrrrrrrrl", indent="  "))
        if len(procs) > MAX_ROWS:
            print(f"  ... {len(procs) - MAX_ROWS} more")
        for p in _parents(procs):
            of = p.get("open_files")
            print(f"  smbd {p['pid']}: open files "
                  f"{of[0] if of and of[0] is not None else 'unlimited'} "
                  f"(hard {of[1] if of and of[1] is not None else 'unlimited'})"
                  + (f", cgroup {p['cgroup']}" if p.get("cgroup") else ""))
        for c, lim in (s.get("cgroups") or {}).items():
            bits = [f"{k} {fmt_bytes(v) if k.startswith('memory.') and isinstance(v, int) else v}"
                    for k, v in lim.items()]
            d = ((s.get("cgroup_cpu") or {}).get(c) or {}).get("delta") or {}
            if d and secs:
                bits.append(f"over {secs:.1f} s: "
                            f"{fmt_dur(d.get('usage_usec', 0) * 1000)} CPU, "
                            f"throttled {fmt_dur(d.get('throttled_usec', 0) * 1000)}"
                            f" in {d.get('nr_throttled', 0)} periods")
            if bits:
                print(wrap_items(f"  cgroup {c}: ", bits, sep="; "))
    st = s.get("status") or {}
    if st.get("error"):
        print(f"  {st['error']}")
    elif st:
        sess = st.get("sessions") or []
        shares = st.get("shares") or {}
        by_share = ", ".join(f"{k} {v['tcons']}" for k, v in shares.items()
                             if v.get("tcons"))
        print(f"  sessions {len(sess)}, tree connections "
              f"{len(st.get('tcons') or [])}"
              + (f" ({by_share})" if by_share else "")
              + f", open files {st['open_files'] if st.get('open_files') is not None else '-'}"
              + f", locks {st['locks'] if st.get('locks') is not None else '-'}")
        rows = [[x.get("user") or "-", x.get("machine") or "-",
                 ", ".join(x.get("addresses") or []) or "-",
                 x.get("dialect") or "-", x.get("encryption") or "-",
                 x.get("signing") or "-", x.get("channels") or "-",
                 x.get("pid") or "-"] for x in sess[:MAX_ROWS]]
        if rows:
            print(cli.table(rows, ["user", "machine", "address", "dialect",
                                   "encryption", "signing", "channels", "pid"],
                            "llllllrr", indent="  "))
    conns = s.get("connections")
    if conns is not None:
        states = s.get("connection_states") or {}
        listen = [c for c in conns if c["state"] == "LISTEN"]
        text = ", ".join(f"{v} {k.lower()}" for k, v in sorted(states.items())
                         if k != "LISTEN") or "no connections"
        items = [f"{c['local']}:{c['lport']} (backlog {c['recvq']} of "
                 f"{c['sendq']})" for c in listen]
        if items:
            items[0] = f"{text}; listening on {items[0]}"
        else:
            items = [text]
        print(wrap_items("  TCP: ", items))
        rest = sorted((c for c in conns if c["state"] != "LISTEN"),
                      key=lambda c: -(c.get("bytes_sent", 0)
                                      + c.get("bytes_received", 0)))
        rows = []
        for c in rest[:MAX_ROWS]:
            rows.append([
                f"{c['peer']}:{c['pport']}", c.get("pid") or "-",
                c.get("interface") or "-",
                c["state"].lower() if c["state"] != "ESTAB" else "",
                f"{c['rtt_ms']:.2f}" if c.get("rtt_ms") is not None else "-",
                c.get("cwnd", "-"), c.get("mss", "-"),
                c.get("retrans_total") if c.get("retrans_total") is not None
                else "-",
                fmt_bytes(c.get("bytes_sent")) if c.get("bytes_sent") is not None
                else "-",
                fmt_bytes(c.get("bytes_received"))
                if c.get("bytes_received") is not None else "-",
                _bits(c.get("send_bps")), _bits(c.get("delivery_rate_bps")),
                f"{c['busy_ms'] / 1000:.1f}s" if c.get("busy_ms") is not None
                else "-",
                f"{c['rwnd_limited_pct']:.0f}%" if "rwnd_limited_pct" in c
                else "-",
                f"{c['sndbuf_limited_pct']:.0f}%" if "sndbuf_limited_pct" in c
                else "-", c.get("sendq", "-"), c.get("recvq", "-")])
        if rows:
            print(cli.table(rows, ["client", "pid", "iface", "state", "rtt ms",
                                   "cwnd", "mss", "retrans", "sent", "received",
                                   "send rate", "delivery", "busy", "rwnd lim",
                                   "sndbuf lim", "send-Q", "recv-Q"],
                            "lrll" + "r" * 13, indent="  "))
            if len(rest) > MAX_ROWS:
                print(f"  ... {len(rest) - MAX_ROWS} more")
    cmd_disk.print_shares(run)
    eff = s.get("effective") or {}
    if eff:
        head = "  [global] effective (testparm -v): " \
            if not s.get("effective_error") else \
            "  [global] as set in the file (testparm failed, see notes): "
        print(wrap_items(head, [f"{k} = {v}" for k, v in eff.items()]))


def print_notes(run: dict, show: set) -> None:
    notes_ = run.get("notes") or {}
    if isinstance(notes_, list):
        lines = notes_
    else:
        lines = []
        for k in ("general",) + SECTIONS:
            if k == "general" or k in show:
                lines += notes_.get(k, [])
    if lines:
        print("\nnotes")
        for n in lines:
            print(_wrap("  - ", n))


def print_run(run: dict, show=None, show_params: bool = False) -> None:
    show = set(show or run.get("sections") or SECTIONS)
    cmd_disk.print_head(run)
    if "host" in show:
        print_host(run)
    if "cpu" in show:
        print_cpu(run)
    if "memory" in show:
        print_memory(run)
    if "disk" in show:
        print_disks(run)
    if "pool" in show:
        print_pool(run, show_params, others="disk" not in show)
    if "net" in show:
        print_net(run)
    if "smb" in show:
        print_smb(run)
    print_notes(run, show)


# -- main ----------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="The box as it bears on smbd, in one report: host, "
                    "CPUs, memory, disks, ZFS pools, network and Samba "
                    "itself, each sampled over a few seconds, with notes on "
                    "what costs time. All sections by default, or the ones "
                    "named. Runs on the server; root sees Samba's sessions "
                    "and effective configuration.",
        epilog="A run saved with -o prints again as INPUT, whole or by "
               "section: smb-perf-gather run.json net smb.")
    ap.add_argument("what", nargs="*", metavar="SECTION|INPUT",
                    help="sections to gather: " + ", ".join(SECTIONS)
                    + " (default all; --list describes them); or a saved "
                    "run to print")
    ap.add_argument("--interval", default="5", metavar="T",
                    help="how long to sample counters (default 5s; 0 for "
                    "none)")
    ap.add_argument("--pool", action="append", default=[], metavar="NAME",
                    help="only this pool (repeatable)")
    ap.add_argument("--share", action="append", default=[], metavar="NAME",
                    help="only this share (repeatable)")
    ap.add_argument("--all-datasets", action="store_true",
                    help="properties of every filesystem, not only the "
                    "shares' and the pools' roots")
    ap.add_argument("--params", action="store_true",
                    help="print every ZFS module parameter")
    ap.add_argument("--list", action="store_true",
                    help="describe the sections and exit")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="save everything gathered as JSON")
    ap.add_argument("--json", action="store_true",
                    help="print the JSON instead of the report")
    args = ap.parse_args(argv)
    if args.list:
        for s in SECTIONS:
            print(f"{s:8}{WHAT[s]}")
        return 0
    sections: list[str] = []
    inputs: list[str] = []
    for w in args.what:
        if w in SECTIONS:
            sections.append(w)
        elif w == "all":
            sections.extend(SECTIONS)
        elif os.path.isfile(w):
            inputs.append(w)
        else:
            ap.error(f"{w}: not a section ({', '.join(SECTIONS)}) or a "
                     "saved run")
    if len(inputs) > 1:
        ap.error("one saved run at a time")
    chosen = [s for s in SECTIONS if s in sections]
    if inputs:
        try:
            with open(inputs[0]) as f:
                run = json.load(f)
        except (OSError, ValueError) as e:
            cli.note(f"error: {inputs[0]}: {e}")
            return 1
        if run.get("tool") != "smb-perf-gather":
            cli.note(f"error: {inputs[0]}: not a smb-perf-gather run")
            return 1
        show = chosen or run.get("sections") or list(SECTIONS)
    else:
        try:
            interval = parse_duration(args.interval)
        except ValueError as e:
            ap.error(str(e))
        if interval < 0:
            ap.error("--interval must be 0 or more")
        show = chosen or list(SECTIONS)
        try:
            run = gather(show, interval, args.pool, args.share,
                         args.all_datasets)
        except KeyboardInterrupt:
            cli.note("interrupted")
            return 130
    if args.output:
        with open(args.output, "w") as f:
            json.dump(run, f, indent=1)
    if args.json:
        print(json.dumps(run, indent=1))
    else:
        print_run(run, show, args.params)
    if args.output and not args.json:
        sys.stdout.flush()
        cli.note(f"saved {args.output}")
    return 0
