"""What about the machine changes perf numbers: CPU, clock policy,
versions."""

from __future__ import annotations

import glob
import os
import platform
import re
import shutil
import subprocess


def _read(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def host() -> dict:
    info: dict = {"kernel": platform.release(), "hostname": platform.node(),
                  "cpus": os.cpu_count()}
    v = _read("/etc/version")
    if v:
        info["truenas"] = v
    osr = _read("/etc/os-release") or ""
    m = re.search(r'^PRETTY_NAME="?([^"\n]*)', osr, re.M)
    if m:
        info["os"] = m.group(1)
    cpu = _read("/proc/cpuinfo") or ""
    m = re.search(r"^model name\s*:\s*(.+)$", cpu, re.M)
    if m:
        info["cpu"] = m.group(1).strip()
    info["sockets"] = len(set(re.findall(r"^physical id\s*:\s*(\d+)", cpu,
                                         re.M))) or None
    smt = _read("/sys/devices/system/cpu/smt/active")
    if smt is not None:
        info["smt"] = smt == "1"
    m = re.search(r"^flags\s*:(.*)$", cpu, re.M)
    info["virtual"] = bool(m and "hypervisor" in m.group(1).split())
    return info


def cpufreq() -> dict:
    """Governors, driver and frequency range over all CPUs."""
    govs: dict[str, int] = {}
    cur: list[int] = []
    out: dict = {}
    for d in sorted(glob.glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq")):
        g = _read(f"{d}/scaling_governor")
        if g:
            govs[g] = govs.get(g, 0) + 1
        c = _read(f"{d}/scaling_cur_freq")
        if c and c.isdigit():
            cur.append(int(c))
        if "driver" not in out:
            out["driver"] = _read(f"{d}/scaling_driver")
            for k in ("cpuinfo_min_freq", "cpuinfo_max_freq"):
                v = _read(f"{d}/{k}")
                if v and v.isdigit():
                    out[k.split("_")[1] + "_mhz"] = int(v) // 1000
            epp = _read(f"{d}/energy_performance_preference")
            if epp:
                out["epp"] = epp
    if govs:
        out["governors"] = govs
    if cur:
        out["cur_mhz"] = [min(cur) // 1000, max(cur) // 1000]
    boost = _read("/sys/devices/system/cpu/cpufreq/boost")
    nt = _read("/sys/devices/system/cpu/intel_pstate/no_turbo")
    if boost is not None:
        out["boost"] = boost == "1"
    elif nt is not None:
        out["boost"] = nt == "0"
    idle = _read("/sys/devices/system/cpu/cpuidle/current_driver")
    if idle:
        out["idle_driver"] = idle
        states = []
        for s in sorted(glob.glob("/sys/devices/system/cpu/cpu0/cpuidle/"
                                  "state[0-9]*")):
            name = _read(f"{s}/name")
            if name and _read(f"{s}/disable") != "1":
                states.append(name)
        out["idle_states"] = states
    return out


def smbd_version() -> str | None:
    exe = shutil.which("smbd") or next(
        (p for p in ("/usr/sbin/smbd", "/usr/local/sbin/smbd")
         if os.path.exists(p)), None)
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "-V"], capture_output=True, text=True,
                             timeout=10).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out or None


def perf_version(perf: str = "perf") -> str | None:
    try:
        return subprocess.run([perf, "--version"], capture_output=True,
                              text=True, timeout=10).stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def warnings(freq: dict, info: dict) -> list[str]:
    out = []
    govs = freq.get("governors", {})
    slow = sorted(g for g in govs if g != "performance")
    if slow:
        out.append(
            f"CPU frequency governor {', '.join(slow)}: the clock follows "
            "load, so a request-response workload can run at a fraction of "
            "full speed and times shift between runs; compare cycles, or "
            "set the performance governor for timing runs")
    if info.get("virtual"):
        out.append("running in a virtual machine: cycle counters may be "
                   "missing or shared with other guests")
    return out


def describe(freq: dict) -> str:
    govs = freq.get("governors")
    if not govs:
        return "no cpufreq"
    parts = ["governor " + ", ".join(sorted(govs))]
    if "min_mhz" in freq:
        parts.append(f"{freq['min_mhz']}-{freq['max_mhz']} MHz")
    if "boost" in freq:
        parts.append("boost on" if freq["boost"] else "boost off")
    if freq.get("idle_states"):
        parts.append("idle " + "/".join(freq["idle_states"]))
    return ", ".join(parts)
