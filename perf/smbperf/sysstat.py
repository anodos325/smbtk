"""What the kernel counts for the box as a whole: CPUs and how busy they
were, memory and reclaim, interrupts, stalls, and what each process got;
from /proc and /sys, read twice where a rate is wanted."""

from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess

from .blockdev import sysctl

CPU_FIELDS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq",
              "steal", "guest", "guest_nice")
# /proc/vmstat has hundreds of counters; these say whether memory hurt.
VMSTAT_KEYS = (
    "pgfault", "pgmajfault", "pswpin", "pswpout", "pgpgin", "pgpgout",
    "pgscan_kswapd", "pgscan_direct", "pgsteal_kswapd", "pgsteal_direct",
    "allocstall_dma", "allocstall_dma32", "allocstall_normal",
    "allocstall_movable", "allocstall_device", "compact_stall",
    "compact_success", "compact_fail", "thp_fault_alloc",
    "thp_fault_fallback", "thp_collapse_alloc", "oom_kill", "drop_pagecache",
    "drop_slab", "nr_dirty", "nr_writeback", "nr_free_pages", "numa_hit",
    "numa_miss", "numa_foreign", "numa_pages_migrated", "pgmigrate_success",
    "kswapd_low_wmark_hit_quickly", "kswapd_high_wmark_hit_quickly")
VM_SYSCTLS = (
    "vm.swappiness", "vm.dirty_ratio", "vm.dirty_background_ratio",
    "vm.dirty_bytes", "vm.dirty_background_bytes",
    "vm.dirty_expire_centisecs", "vm.dirty_writeback_centisecs",
    "vm.min_free_kbytes", "vm.overcommit_memory", "vm.overcommit_ratio",
    "vm.vfs_cache_pressure", "vm.zone_reclaim_mode", "vm.max_map_count",
    "vm.watermark_scale_factor", "vm.page-cluster",
    "vm.compaction_proactiveness", "kernel.numa_balancing")
KERNEL_SYSCTLS = (
    "kernel.perf_event_paranoid", "kernel.kptr_restrict",
    "kernel.perf_event_max_sample_rate", "kernel.sched_autogroup_enabled",
    "kernel.timer_migration", "kernel.nmi_watchdog", "kernel.watchdog",
    "kernel.pid_max", "kernel.threads-max", "fs.file-max", "fs.file-nr",
    "fs.nr_open", "fs.aio-max-nr", "fs.aio-nr", "fs.inotify.max_user_watches",
    "fs.inotify.max_user_instances")
DMI_KEYS = ("sys_vendor", "product_name", "product_version", "board_vendor",
            "board_name", "bios_vendor", "bios_version", "bios_date")
CGROUP = "/sys/fs/cgroup"


def _read(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def _int(text: str | None) -> int | None:
    if text is not None and re.fullmatch(r"-?\d+", text):
        return int(text)
    return None


# -- CPUs ----------------------------------------------------------------------

def parse_stat(text: str) -> dict:
    """/proc/stat: the CPU lines in ticks, interrupts, context switches,
    forks, runnable and blocked tasks."""
    out: dict = {"cpus": {}}
    for line in text.splitlines():
        f = line.split()
        if not f:
            continue
        if f[0].startswith("cpu"):
            vals = {}
            for k, v in zip(CPU_FIELDS, f[1:]):
                if v.isdigit():
                    vals[k] = int(v)
            if f[0] == "cpu":
                out["cpu"] = vals
            else:
                out["cpus"][f[0]] = vals
        elif f[0] in ("intr", "softirq", "ctxt", "btime", "processes",
                      "procs_running", "procs_blocked") and len(f) > 1 \
                and f[1].isdigit():
            out[f[0]] = int(f[1])
    return out


def read_stat() -> dict:
    return parse_stat(_read("/proc/stat") or "")


def _shares(before: dict, after: dict) -> dict | None:
    d = {k: after.get(k, 0) - before.get(k, 0) for k in CPU_FIELDS}
    # guest time is counted in user and nice already
    total = sum(d[k] for k in CPU_FIELDS if not k.startswith("guest"))
    if total <= 0:
        return None
    out = {k: d[k] / total for k in CPU_FIELDS if not k.startswith("guest")}
    out["busy"] = 1 - (d["idle"] + d["iowait"]) / total
    return out


def cpu_usage(before: dict, after: dict, seconds: float) -> dict:
    """Shares of the interval the CPUs spent in each state, as top shows
    them, overall and per CPU; interrupts, context switches and forks a
    second; tasks running and blocked at the end."""
    out: dict = {"total": _shares(before.get("cpu", {}), after.get("cpu", {})),
                 "per_cpu": {}}
    for name, a in after.get("cpus", {}).items():
        b = before.get("cpus", {}).get(name)
        s = _shares(b, a) if b else None
        if s:
            out["per_cpu"][name] = {
                "busy": s["busy"], "user": s["user"] + s["nice"],
                "system": s["system"], "irq": s["irq"] + s["softirq"],
                "iowait": s["iowait"], "steal": s["steal"]}
    if seconds > 0:
        for k in ("ctxt", "intr", "processes"):
            if k in before and k in after:
                out[k + "_s"] = (after[k] - before[k]) / seconds
    for k in ("procs_running", "procs_blocked"):
        if k in after:
            out[k] = after[k]
    return out


def parse_softirqs(text: str) -> dict[str, list[int]]:
    out = {}
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) > 1 and f[0].endswith(":"):
            out[f[0][:-1]] = [int(x) for x in f[1:] if x.isdigit()]
    return out


def read_softirqs() -> dict[str, list[int]]:
    return parse_softirqs(_read("/proc/softirqs") or "")


def softirq_rates(before: dict, after: dict, seconds: float) -> dict:
    """Per kind: softirqs a second, and the CPU that handled most of them
    with its share."""
    out = {}
    if seconds <= 0:
        return out
    for name, a in after.items():
        b = before.get(name)
        if not b:
            continue
        d = [x - y for x, y in zip(a, b)]
        total = sum(d)
        if total <= 0:
            continue
        top = max(range(len(d)), key=d.__getitem__)
        out[name] = {"per_s": total / seconds, "top_cpu": top,
                     "top_share": d[top] / total}
    return out


def parse_interrupts(text: str) -> dict:
    """/proc/interrupts: per IRQ (or named kind) its counts per CPU and
    the chip, pin and handler description."""
    lines = text.splitlines()
    if not lines:
        return {"cpus": 0, "irqs": {}}
    ncpu = len(lines[0].split())
    irqs = {}
    for line in lines[1:]:
        f = line.split()
        if not f or not f[0].endswith(":"):
            continue
        counts = []
        i = 1
        while i < len(f) and len(counts) < ncpu and f[i].isdigit():
            counts.append(int(f[i]))
            i += 1
        irqs[f[0][:-1]] = {"counts": counts, "desc": " ".join(f[i:])}
    return {"cpus": ncpu, "irqs": irqs}


def read_interrupts() -> dict:
    return parse_interrupts(_read("/proc/interrupts") or "")


IRQ_KINDS = {"LOC": "local timer", "RES": "rescheduling IPI",
             "CAL": "function call IPI", "TLB": "TLB shootdown",
             "PMI": "performance counters", "NMI": "NMI", "IWI": "IRQ work",
             "RTR": "APIC retrigger", "HYP": "hypervisor callback",
             "MCE": "machine check", "MCP": "machine check poll",
             "THR": "thermal", "TRM": "thermal", "SPU": "spurious",
             "ERR": "error", "MIS": "misc", "PIN": "posted interrupt",
             "NPI": "nested posted interrupt", "PIW": "posted wakeup"}


def irq_name(label: str, desc: str) -> str:
    """A short name for an interrupt line: the device for a numbered
    IRQ, the kind for the kernel's own."""
    if label in IRQ_KINDS:
        return IRQ_KINDS[label]
    f = desc.split()
    return f[-1] if f else label


def irq_rates(before: dict, after: dict, seconds: float) -> dict[str, dict]:
    """Per IRQ that fired: interrupts a second, the CPUs that took 1% or
    more of them, the busiest CPU's share, and the description."""
    out = {}
    if seconds <= 0:
        return out
    for label, a in after.get("irqs", {}).items():
        b = before.get("irqs", {}).get(label)
        if not b:
            continue
        d = [x - y for x, y in zip(a["counts"], b["counts"])]
        total = sum(d)
        if total <= 0:
            continue
        out[label] = {"per_s": total / seconds, "desc": a["desc"],
                      "cpus": [i for i, v in enumerate(d) if v >= 0.01 * total],
                      "top_share": max(d) / total}
    return out


def pressure(kind: str) -> dict | None:
    """/proc/pressure/<cpu|memory|io>: the share of time some task, or
    every task, was stalled on it, over 10 s, 1 min and 5 min."""
    text = _read(f"/proc/pressure/{kind}")
    if text is None:
        return None
    out = {}
    for line in text.splitlines():
        f = line.split()
        if not f:
            continue
        vals = {}
        for kv in f[1:]:
            k, _, v = kv.partition("=")
            try:
                vals[k] = int(v) if k == "total" else float(v)
            except ValueError:
                pass
        if vals:
            out[f[0]] = vals
    return out or None


def loadavg() -> dict | None:
    f = (_read("/proc/loadavg") or "").split()
    try:
        running, threads = f[3].split("/")
        return {"1m": float(f[0]), "5m": float(f[1]), "15m": float(f[2]),
                "running": int(running), "threads": int(threads)}
    except (IndexError, ValueError):
        return None


def topology() -> dict:
    """Online CPUs, sockets, cores, SMT, NUMA nodes with their CPUs, and
    the cache sizes of CPU 0."""
    base = "/sys/devices/system/cpu"
    cpus = []
    for d in glob.glob(f"{base}/cpu[0-9]*"):
        if (_read(f"{d}/online") or "1") == "1":
            cpus.append(int(os.path.basename(d)[3:]))
    packages, cores = set(), set()
    for c in sorted(cpus):
        pkg = _read(f"{base}/cpu{c}/topology/physical_package_id")
        core = _read(f"{base}/cpu{c}/topology/core_id")
        if pkg is not None and core is not None:
            packages.add(pkg)
            cores.add((pkg, core))
    out: dict = {"cpus": len(cpus), "sockets": len(packages) or None,
                 "cores": len(cores) or None,
                 "smt": _read(f"{base}/smt/control")}
    nodes = {}
    for d in sorted(glob.glob("/sys/devices/system/node/node[0-9]*")):
        cl = _read(f"{d}/cpulist")
        if cl is not None:
            nodes[os.path.basename(d)[4:]] = cl
    out["numa_nodes"] = nodes
    caches = {}
    for d in sorted(glob.glob(f"{base}/cpu0/cache/index[0-9]*")):
        level, kind, size = (_read(f"{d}/{k}") for k in ("level", "type",
                                                          "size"))
        if level and size:
            suffix = {"Data": "d", "Instruction": "i"}.get(kind or "", "")
            caches[f"L{level}{suffix}"] = size
    out["caches"] = caches
    return out


def mitigations() -> dict[str, str]:
    out = {}
    for p in sorted(glob.glob("/sys/devices/system/cpu/vulnerabilities/*")):
        v = _read(p)
        if v is not None:
            out[os.path.basename(p)] = v
    return out


# -- the machine ---------------------------------------------------------------

def cmdline() -> str | None:
    return _read("/proc/cmdline")


def uptime() -> float | None:
    f = (_read("/proc/uptime") or "").split()
    try:
        return float(f[0])
    except (IndexError, ValueError):
        return None


def dmi() -> dict[str, str]:
    """Vendor, product and firmware from the DMI tables (no serials)."""
    out = {}
    for k in DMI_KEYS:
        v = _read(f"/sys/class/dmi/id/{k}")
        if v and v.lower() not in ("to be filled by o.e.m.", "default string",
                                   "none", "not specified", "system product name",
                                   "system manufacturer", "n/a"):
            out[k] = v
    return out


def virtualization() -> dict:
    """What systemd-detect-virt says about a hypervisor and a container,
    or the CPU's hypervisor flag."""
    out: dict = {"vm": None, "container": None}
    exe = shutil.which("systemd-detect-virt")
    if exe:
        for key, flag in (("vm", "--vm"), ("container", "--container")):
            try:
                p = subprocess.run([exe, flag], capture_output=True, text=True,
                                   timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                continue
            v = p.stdout.strip()
            out[key] = None if not v or v == "none" else v
        return out
    cpu = _read("/proc/cpuinfo") or ""
    m = re.search(r"^flags\s*:(.*)$", cpu, re.M)
    if m and "hypervisor" in m.group(1).split():
        out["vm"] = _read("/sys/hypervisor/type") or "yes"
    for marker, name in (("/.dockerenv", "docker"),
                         ("/run/.containerenv", "podman")):
        if os.path.exists(marker):
            out["container"] = name
    return out


def thp() -> dict[str, str]:
    """Transparent hugepage settings, the chosen value of each."""
    base = "/sys/kernel/mm/transparent_hugepage"
    out = {}
    for k, path in (("enabled", f"{base}/enabled"),
                    ("defrag", f"{base}/defrag"),
                    ("shmem_enabled", f"{base}/shmem_enabled"),
                    ("khugepaged_defrag", f"{base}/khugepaged/defrag")):
        v = _read(path)
        if v is None:
            continue
        m = re.search(r"\[([^\]]+)\]", v)
        out[k] = m.group(1) if m else v
    return out


def numa_memory() -> dict[str, dict[str, int]]:
    """Per NUMA node, in bytes: total, free, file pages, anonymous, slab."""
    out = {}
    for d in sorted(glob.glob("/sys/devices/system/node/node[0-9]*")):
        text = _read(f"{d}/meminfo") or ""
        vals = {}
        for m in re.finditer(r"^Node \d+ (\w+):\s+(\d+)(\s+kB)?", text, re.M):
            vals[m.group(1)] = int(m.group(2)) * (1024 if m.group(3) else 1)
        keep = {k: vals[k] for k in ("MemTotal", "MemFree", "MemUsed",
                                     "FilePages", "AnonPages", "Slab")
                if k in vals}
        if keep:
            out[os.path.basename(d)[4:]] = keep
    return out


def parse_vmstat(text: str) -> dict[str, int]:
    out = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) == 2 and f[1].lstrip("-").isdigit():
            out[f[0]] = int(f[1])
    return out


def read_vmstat(keys=VMSTAT_KEYS) -> dict[str, int]:
    all_ = parse_vmstat(_read("/proc/vmstat") or "")
    return {k: all_[k] for k in keys if k in all_}


def sysctls(names) -> dict:
    out = {}
    for n in names:
        v = sysctl(n)
        if v is not None:
            out[n] = v
    return out


# -- processes -----------------------------------------------------------------

def proc_status(pid: int) -> dict:
    """From /proc/PID/status: memory in bytes, threads, context
    switches."""
    text = _read(f"/proc/{pid}/status") or ""
    out: dict = {}
    for m in re.finditer(r"^(VmRSS|VmHWM|VmSwap|VmSize|Threads|"
                         r"voluntary_ctxt_switches|nonvoluntary_ctxt_switches"
                         r"|Uid):\s+(\d+)(\s+kB)?", text, re.M):
        k = {"VmRSS": "rss", "VmHWM": "rss_peak", "VmSwap": "swap",
             "VmSize": "vsize", "Threads": "threads", "Uid": "uid",
             "voluntary_ctxt_switches": "voluntary_switches",
             "nonvoluntary_ctxt_switches": "involuntary_switches"}[m.group(1)]
        out[k] = int(m.group(2)) * (1024 if m.group(3) else 1)
    return out


def proc_sched(pid: int) -> dict | None:
    """From /proc/PID/schedstat: time on a CPU, time runnable but
    waiting for one, and timeslices, since the process started; with the
    involuntary context switches (preemptions)."""
    f = (_read(f"/proc/{pid}/schedstat") or "").split()
    if len(f) < 3 or not all(x.isdigit() for x in f[:3]):
        return None
    out = {"run_ns": int(f[0]), "wait_ns": int(f[1]), "slices": int(f[2])}
    st = proc_status(pid)
    if "involuntary_switches" in st:
        out["involuntary_switches"] = st["involuntary_switches"]
    return out


def proc_limits(pid: int) -> dict:
    out = {}
    for line in (_read(f"/proc/{pid}/limits") or "").splitlines():
        m = re.match(r"^Max open files\s+(\S+)\s+(\S+)", line)
        if m:
            out["open_files"] = [None if v == "unlimited" else int(v)
                                 for v in m.groups()]
    return out


def proc_cgroup(pid: int) -> str | None:
    """The unified cgroup path (0::/...) of a process."""
    for line in (_read(f"/proc/{pid}/cgroup") or "").splitlines():
        if line.startswith("0::"):
            return line[3:]
    return None


def proc_fds(pid: int) -> int | None:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None


def proc_details(pid: int) -> dict:
    out = proc_status(pid)
    out["fds"] = proc_fds(pid)
    out.update(proc_limits(pid))
    out["cgroup"] = proc_cgroup(pid)
    return out


def cgroup_limits(path: str) -> dict:
    """cpu.max, cpu.weight, memory.max, memory.high, memory.current and
    pids.max of a unified cgroup, where set."""
    out = {}
    base = CGROUP + path.rstrip("/")
    for k in ("cpu.max", "cpu.weight", "memory.max", "memory.high",
              "memory.current", "memory.swap.max", "pids.max"):
        v = _read(f"{base}/{k}")
        if v is not None:
            out[k] = int(v) if v.isdigit() else v
    return out


def cgroup_cpu_stat(path: str) -> dict[str, int] | None:
    """cpu.stat of a unified cgroup: usage and throttling, in us."""
    text = _read(CGROUP + path.rstrip("/") + "/cpu.stat")
    if text is None:
        return None
    out = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) == 2 and f[1].isdigit():
            out[f[0]] = int(f[1])
    return out
