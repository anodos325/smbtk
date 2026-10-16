"""The block devices under the pools: what they are, how the kernel
queues to them and how busy they were; the box's memory and mounts."""

from __future__ import annotations

import json
import os
import re
import subprocess

# Device names that are not disks: loop files, zvols, optical, floppy.
SKIP = ("loop", "ram", "zd", "sr", "fd", "nbd")
LSBLK_COLS = ("NAME", "KNAME", "PATH", "TYPE", "SIZE", "ROTA", "TRAN",
              "MODEL", "SERIAL", "VENDOR", "REV", "SCHED", "RQ-SIZE",
              "PHY-SEC", "LOG-SEC", "WWN", "HCTL", "STATE", "FSTYPE",
              "PARTLABEL", "PARTTYPENAME", "PKNAME", "SUBSYSTEMS",
              "ZONED", "RA", "PARTUUID", "LABEL")
LSBLK_MIN = ("NAME", "KNAME", "TYPE", "SIZE", "ROTA", "MODEL", "SERIAL",
             "PKNAME")
# lsblk's names for what we keep.
LSBLK_MAP = {"path": "path", "type": "type", "size": "size",
             "rota": "rotational", "tran": "transport", "model": "model",
             "serial": "serial", "vendor": "vendor", "rev": "rev",
             "wwn": "wwn", "hctl": "hctl", "state": "state",
             "sched": "scheduler", "rq_size": "nr_requests",
             "phy_sec": "physical_block_size",
             "log_sec": "logical_block_size", "subsystems": "subsystems",
             "zoned": "zoned", "ra": "read_ahead_kb"}
PART_KEYS = ("name", "kname", "path", "size", "fstype", "label", "partlabel",
             "parttypename", "partuuid")
NUMERIC = {"size", "rq_size", "phy_sec", "log_sec", "ra", "min_io",
           "opt_io", "alignment"}
# /proc/diskstats after major, minor, name (kernel 5.5+ has all 17).
DISKSTAT_FIELDS = ("rd_ios", "rd_merges", "rd_sectors", "rd_ticks",
                   "wr_ios", "wr_merges", "wr_sectors", "wr_ticks",
                   "in_flight", "io_ticks", "time_in_queue", "ds_ios",
                   "ds_merges", "ds_sectors", "ds_ticks", "fl_ios",
                   "fl_ticks")
QUEUE_ATTRS = ("scheduler", "nr_requests", "read_ahead_kb",
               "max_sectors_kb", "max_hw_sectors_kb", "rotational",
               "write_cache", "physical_block_size", "logical_block_size",
               "nomerges", "wbt_lat_usec", "discard_max_bytes",
               "io_timeout", "rq_affinity")
DEVICE_ATTRS = ("vendor", "model", "rev", "firmware_rev", "serial", "state",
                "queue_depth", "timeout", "ioerr_cnt", "numa_node",
                "transport", "queue_count")


def _read(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


# -- devices -------------------------------------------------------------------

def lsblk(lsblk_bin: str = "lsblk") -> list[dict] | None:
    """lsblk's device tree as JSON, sizes in bytes; None without
    lsblk."""
    for cols in (LSBLK_COLS, LSBLK_MIN):
        try:
            p = subprocess.run([lsblk_bin, "-J", "-b", "-o", ",".join(cols)],
                               capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if p.returncode == 0:
            try:
                return json.loads(p.stdout).get("blockdevices", [])
            except ValueError:
                return None
    return None


def _norm(node: dict) -> dict:
    """lsblk keys lowercased, old lsblk's "0"/"1" strings as booleans
    and numbers as numbers."""
    out: dict = {}
    for k, v in node.items():
        k = k.lower().replace("-", "_")
        if k == "children":
            out[k] = [_norm(c) for c in v]
            continue
        if isinstance(v, str):
            s = v.strip()
            if k in ("rota", "rand", "rm", "ro", "hotplug"):
                v = s in ("1", "true", "yes")
            elif k in NUMERIC and re.fullmatch(r"\d+", s):
                v = int(s)
            else:
                v = s
        out[k] = v
    return out


def parent_disk(name: str) -> str:
    """The whole disk a partition is on (sdb1 -> sdb); a disk is its
    own."""
    real = os.path.realpath(f"/sys/class/block/{name}")
    parent = os.path.basename(os.path.dirname(real))
    if parent != "block" and os.path.exists(f"/sys/class/block/{parent}"):
        return parent
    return name


def sysfs_disk(name: str) -> dict:
    """What sysfs says about a disk: size, its queue's settings, the
    device's identity and error count."""
    base = f"/sys/class/block/{name}"
    out: dict = {}
    size = _read(f"{base}/size")
    if size and size.isdigit():
        out["size"] = int(size) * 512
    for a in QUEUE_ATTRS:
        v = _read(f"{base}/queue/{a}")
        if v is None:
            continue
        if a == "scheduler":
            m = re.search(r"\[([^\]]+)\]", v)
            out[a] = m.group(1) if m else v
        elif a == "rotational":
            out[a] = v == "1"
        elif re.fullmatch(r"-?\d+", v):
            out[a] = int(v)
        else:
            out[a] = v
    for a in DEVICE_ATTRS:
        v = _read(f"{base}/device/{a}")
        if v is None:
            continue
        if a == "ioerr_cnt":
            try:
                out[a] = int(v, 16)
            except ValueError:
                out[a] = v
        elif re.fullmatch(r"-?\d+", v) and a not in ("serial", "rev",
                                                      "firmware_rev"):
            out[a] = int(v)
        else:
            out[a] = v
    return out


def _from_lsblk(node: dict) -> dict:
    out = {}
    for k, ours in LSBLK_MAP.items():
        v = node.get(k)
        if v not in (None, ""):
            out[ours] = v
    return out


def devices(lsblk_bin: str = "lsblk") -> list[dict]:
    """Whole disks with their partitions: identity from lsblk (udev
    knows the full model), queue settings from sysfs."""
    tree = lsblk(lsblk_bin)
    out = []
    if tree is not None:
        for raw in tree:
            n = _norm(raw)
            name = n.get("kname") or n.get("name")
            if not name or name.startswith(SKIP) or n.get("type") == "rom":
                continue
            d: dict = {"name": name}
            d.update(sysfs_disk(name))
            for k, v in _from_lsblk(n).items():
                if k not in d or k in ("model", "serial", "vendor",
                                       "transport", "rev"):
                    d[k] = v
            d["partitions"] = []
            for c in n.get("children", []):
                part = {k: c[k] for k in PART_KEYS if c.get(k) not in
                        (None, "")}
                part["name"] = c.get("kname") or c.get("name")
                d["partitions"].append(part)
            out.append(d)
        return out
    try:
        names = sorted(os.listdir("/sys/class/block"))
    except OSError:
        return out
    for name in names:
        if name.startswith(SKIP) or os.path.exists(
                f"/sys/class/block/{name}/partition"):
            continue
        d = {"name": name, "path": f"/dev/{name}", "type": "disk"}
        d.update(sysfs_disk(name))
        d["partitions"] = [
            {"name": p, "size": int(_read(f"/sys/class/block/{p}/size")
                                    or 0) * 512}
            for p in sorted(os.listdir(f"/sys/class/block/{name}"))
            if os.path.exists(f"/sys/class/block/{name}/{p}/partition")]
        out.append(d)
    return out


# -- I/O -----------------------------------------------------------------------

def parse_diskstats(text: str) -> dict[str, dict[str, int]]:
    out = {}
    for line in text.splitlines():
        f = line.split()
        if len(f) < 14:
            continue
        vals = [int(x) for x in f[3:3 + len(DISKSTAT_FIELDS)]]
        out[f[2]] = dict(zip(DISKSTAT_FIELDS, vals))
    return out


def read_diskstats() -> dict[str, dict[str, int]]:
    return parse_diskstats(_read("/proc/diskstats") or "")


def io_rates(before: dict[str, dict], after: dict[str, dict],
             seconds: float) -> dict[str, dict]:
    """What iostat -x derives from two readings of /proc/diskstats:
    requests and bytes a second, mean wait (ns) and size per request,
    requests in flight on average, the share of time busy."""
    out: dict[str, dict] = {}
    if seconds <= 0:
        return out
    for name, b in before.items():
        a = after.get(name)
        if not a:
            continue
        d = {k: a[k] - b[k] for k in b if k in a}

        def per(total: int, count: int, scale: float = 1.0) -> float | None:
            return total * scale / count if count else None

        r = {
            "reads_s": d["rd_ios"] / seconds,
            "writes_s": d["wr_ios"] / seconds,
            "read_bytes_s": d["rd_sectors"] * 512 / seconds,
            "write_bytes_s": d["wr_sectors"] * 512 / seconds,
            "read_merges_s": d["rd_merges"] / seconds,
            "write_merges_s": d["wr_merges"] / seconds,
            "read_wait_ns": per(d["rd_ticks"], d["rd_ios"], 1e6),
            "write_wait_ns": per(d["wr_ticks"], d["wr_ios"], 1e6),
            "read_size": per(d["rd_sectors"] * 512, d["rd_ios"]),
            "write_size": per(d["wr_sectors"] * 512, d["wr_ios"]),
            "discards_s": d.get("ds_ios", 0) / seconds,
            "flushes_s": d.get("fl_ios", 0) / seconds,
            "flush_wait_ns": per(d.get("fl_ticks", 0), d.get("fl_ios", 0),
                                 1e6),
            "queue": d["time_in_queue"] / (seconds * 1000),
            "util": min(1.0, d["io_ticks"] / (seconds * 1000)),
            "in_flight": a.get("in_flight", 0),
        }
        out[name] = r
    return out


# -- the box -------------------------------------------------------------------

def parse_meminfo(text: str) -> dict[str, int]:
    """/proc/meminfo in bytes."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^(\w+):\s+(\d+)(\s+kB)?", line)
        if m:
            out[m.group(1)] = int(m.group(2)) * (1024 if m.group(3) else 1)
    return out


def meminfo() -> dict[str, int]:
    return parse_meminfo(_read("/proc/meminfo") or "")


def _unescape(s: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def parse_mounts(text: str, fstype: str = "zfs") -> list[dict]:
    """Mounts of one filesystem type from /proc/mounts: {"dataset" (the
    source), "mountpoint", "options"}."""
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 4 or f[2] != fstype:
            continue
        out.append({"dataset": _unescape(f[0]),
                    "mountpoint": _unescape(f[1]),
                    "options": f[3].split(",")})
    return out


def zfs_mounts() -> list[dict]:
    return parse_mounts(_read("/proc/mounts") or "")


def mount_for(path: str, mounts: list[dict]) -> dict | None:
    """The mount holding `path`: the longest mountpoint above it."""
    p = path.rstrip("/") or "/"
    best = None
    for m in mounts:
        mp = m["mountpoint"].rstrip("/") or "/"
        if mp == "/" or p == mp or p.startswith(mp + "/"):
            if best is None or len(mp) > len(
                    best["mountpoint"].rstrip("/") or "/"):
                best = m
    return best


def sysctl(name: str) -> int | str | None:
    v = _read("/proc/sys/" + name.replace(".", "/"))
    if v is None:
        return None
    return int(v) if re.fullmatch(r"-?\d+", v) else v
