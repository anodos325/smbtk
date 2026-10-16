"""smb-perf-disk: the storage under the shares in one look: pools and
their vdevs, the disks and how the kernel queues to them, the ARC, ZIL
and transaction groups, the datasets the shares live on and their
settings, and what moved over a few seconds."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import time

from . import blockdev, cli, smbconf, sysinfo, zfs
from .fmt import fmt_bytes, fmt_dur, fmt_si, parse_duration, wrap_items
from .zfs import ZfsError

# Dataset properties in the datasets table, in order.
DATASET_PROPS = (
    "recordsize", "compression", "compressratio", "sync", "logbias",
    "atime", "relatime", "xattr", "dnodesize", "acltype", "casesensitivity",
    "primarycache", "special_small_blocks", "copies", "dedup", "encryption",
    "direct", "quota", "refquota")
# Module parameters printed without --params.
PARAMS_OF_NOTE = (
    "zfs_arc_max", "zfs_arc_min", "zfs_arc_meta_balance", "zfs_arc_sys_free",
    "zfs_dirty_data_max", "zfs_dirty_data_max_percent",
    "zfs_dirty_data_sync_percent", "zfs_delay_min_dirty_percent",
    "zfs_txg_timeout", "zfs_vdev_max_active",
    "zfs_vdev_sync_read_max_active", "zfs_vdev_sync_write_max_active",
    "zfs_vdev_async_read_max_active", "zfs_vdev_async_write_max_active",
    "zfs_vdev_aggregation_limit", "zfs_vdev_aggregation_limit_non_rotating",
    "zfs_prefetch_disable", "zfetch_max_distance", "zfetch_max_idistance",
    "zfs_compressed_arc_enabled", "zfs_abd_scatter_enabled",
    "zil_slog_bulk", "zfs_immediate_write_sz", "zil_nocacheflush",
    "zfs_nocacheflush", "zfs_bclone_enabled", "zfs_bclone_wait_dirty",
    "zfs_dio_enabled", "zfs_dmu_offset_next_sync", "zfs_max_recordsize",
    "zfs_zil_saxattr", "zfs_xattr_compat", "l2arc_write_max",
    "l2arc_noprefetch", "spa_slop_shift")
BYTES_PARAMS = ("zfs_arc_max", "zfs_arc_min", "zfs_arc_sys_free",
                "zfs_dirty_data_max", "zfs_vdev_aggregation_limit",
                "zfs_vdev_aggregation_limit_non_rotating",
                "zfetch_max_distance", "zfetch_max_idistance",
                "zil_slog_bulk", "zfs_immediate_write_sz",
                "zfs_max_recordsize", "l2arc_write_max")
ZIL_BYTES = ("zil_itx_indirect_bytes", "zil_itx_copied_bytes",
             "zil_itx_needcopy_bytes")


# -- gathering -----------------------------------------------------------------

def gather(interval: float, pools: list[str], shares: list[str],
           all_datasets: bool) -> dict:
    started = datetime.datetime.now(datetime.timezone.utc)
    run: dict = {"tool": "smb-perf-disk", "start": started.isoformat(),
                 "interval_s": interval, "host": sysinfo.host(),
                 "smbd_version": sysinfo.smbd_version(),
                 "memory": blockdev.meminfo(),
                 "io_uring": {
                     "disabled": blockdev.sysctl("kernel.io_uring_disabled"),
                     "group": blockdev.sysctl("kernel.io_uring_group")},
                 "mounts": blockdev.zfs_mounts(),
                 "devices": blockdev.devices(), "errors": []}
    collect_samba(run, shares)
    pool_names = collect_zfs(run, pools, all_datasets)
    link_devices(run)
    _sample(run, interval, pools, pool_names)
    run["notes"] = notes(run)
    return run


def collect_samba(run: dict, wanted: list[str]) -> None:
    """The shares and the dataset each lives on, into run['samba']."""
    conf = smbconf.load()
    g = conf["sections"].get("global", {})
    run["samba"] = {"source": conf["source"], "file": conf["file"],
                    "error": conf["error"], "global": g, "shares": {}}
    for name, params in smbconf.shares(conf["sections"]).items():
        if wanted and name not in wanted:
            continue
        path = smbconf.share_path(params)
        m = blockdev.mount_for(path, run["mounts"]) if path else None
        run["samba"]["shares"][name] = {
            "path": params.get("path"),
            "dataset": m["dataset"] if m else None,
            "mountpoint": m["mountpoint"] if m else None,
            "mount_options": m["options"] if m else None,
            "io": smbconf.io_settings(params, g), "params": params}


def collect_zfs(run: dict, wanted: list[str], all_datasets: bool) -> list[str]:
    """Pools, their vdevs and properties, the datasets; the pool names."""
    z = run["zfs"] = {"available": zfs.have_zfs(), "version": zfs.version(),
                      "params": zfs.params(),
                      "modprobe": zfs.modprobe_options(), "pools": {},
                      "kstats": {}, "arc": None}
    status: dict = {}
    props: dict = {}
    if z["available"]:
        try:
            status = zfs.pool_status(wanted or None)
        except ZfsError as e:
            run["errors"].append(str(e))
        try:
            props = zfs.pool_props(wanted or None)
        except ZfsError as e:
            run["errors"].append(str(e))
    names = sorted(set(status) | set(props)) or [
        p for p in zfs.kstat_pools() if not wanted or p in wanted]
    for name in names:
        st = status.get(name, {})
        tree = st.get("vdevs")
        txgs = zfs.pool_txgs(name)
        z["pools"][name] = {
            "state": st.get("state") or zfs.pool_state(name),
            "status": st.get("text", {}).get("status"),
            "action": st.get("text", {}).get("action"),
            "scan": st.get("scan"),
            "scan_in_progress": st.get("scan_in_progress", False),
            "errors": st.get("errors"), "vdevs": tree,
            "leaves": zfs.leaves(tree), "layout": zfs.layout(tree),
            "props": props.get(name, {}).get("props", {}),
            "sources": props.get(name, {}).get("sources", {}),
            "txgs": zfs.txg_summary(txgs) if txgs else {},
            "kstats": {}, "iostat": None}
    rows: list[dict] = []
    if z["available"]:
        try:
            rows = zfs.datasets()
        except ZfsError as e:
            run["errors"].append(str(e))
    if wanted:
        rows = [r for r in rows if r["name"].split("/")[0] in wanted]
    run["datasets"] = {r["name"]: {"pool": r["name"].split("/")[0],
                                   "list": r} for r in rows}
    detail = {s["dataset"] for s in run["samba"]["shares"].values()
              if s["dataset"]} | set(names)
    if all_datasets:
        detail |= {r["name"] for r in rows if r["type"] == "filesystem"}
    if rows:
        detail &= set(run["datasets"])
    if detail and z["available"]:
        try:
            got = zfs.dataset_props(sorted(detail))
        except ZfsError as e:
            run["errors"].append(str(e))
            got = {}
        for name, d in got.items():
            entry = run["datasets"].setdefault(
                name, {"pool": name.split("/")[0]})
            entry["props"] = d["props"]
            entry["sources"] = d["sources"]
    run["detailed"] = sorted(detail)
    return names


def link_devices(run: dict) -> None:
    """Which pool, vdev and class each disk serves, and which disk each
    leaf vdev is on."""
    devices = {d["name"]: d for d in run["devices"]}
    for d in run["devices"]:
        d["zfs"] = []
    for pool, p in run["zfs"]["pools"].items():
        for leaf in p["leaves"]:
            disk = blockdev.parent_disk(leaf["dev"])
            leaf["disk"] = disk
            d = devices.get(disk)
            if d is not None:
                d["zfs"].append({
                    "pool": pool, "vdev": leaf["vdev"],
                    "class": leaf["class"], "leaf": leaf["dev"],
                    "state": leaf["state"], "read": leaf["read"],
                    "write": leaf["write"], "cksum": leaf["cksum"],
                    "slow": leaf["slow"], "note": leaf["note"]})


def _snap(run: dict, pool_names: list[str], wanted: list[str]) -> dict:
    return {"diskstats": blockdev.read_diskstats(),
            "kstats": zfs.global_kstats(),
            "pools": {p: zfs.pool_kstats(p) for p in pool_names},
            "objsets": zfs.objsets(wanted or None)}


def sample_start(run: dict, interval: float, wanted: list[str],
                 pool_names: list[str]) -> dict:
    """The first reading of the counters, and zpool iostat started over
    the interval; the caller waits, then sample_finish() reads again."""
    state = {"before": _snap(run, pool_names, wanted), "t0": time.monotonic(),
             "proc": None, "interval": interval, "wanted": wanted,
             "pool_names": pool_names}
    if interval > 0 and run["zfs"]["available"] and pool_names:
        try:
            state["proc"] = zfs.start_iostat(interval, wanted or None)
        except ZfsError as e:
            run["errors"].append(str(e))
    return state


def sample_finish(run: dict, state: dict) -> None:
    """The second reading, the deltas and rates, and zpool iostat's rows
    attached to the vdev tree."""
    z = run["zfs"]
    wanted, pool_names = state["wanted"], state["pool_names"]
    before, interval, proc = state["before"], state["interval"], state["proc"]
    after = _snap(run, pool_names, wanted)
    seconds = time.monotonic() - state["t0"]
    live = interval > 0

    def pair(name: str, b: dict | None, a: dict | None) -> dict | None:
        if a is None:
            return None
        d = zfs.delta(b["data"], a["data"]) if live and b else None
        return {"snapshot": a["data"], "delta": d}

    run["io"] = {"seconds": seconds if live else 0,
                 "devices": blockdev.io_rates(
                     before["diskstats"], after["diskstats"], seconds)
                 if live else {}}
    for name, k in after["kstats"].items():
        z["kstats"][name] = pair(name, before["kstats"].get(name), k)
    arc = z["kstats"].get("arcstats")
    if arc:
        z["arc"] = zfs.arc_summary(arc["snapshot"])
        z["arc"]["interval"] = zfs.arc_summary(arc["delta"]) \
            if arc["delta"] else None
    for p in pool_names:
        pk = z["pools"][p]["kstats"]
        for name, k in after["pools"].get(p, {}).items():
            pk[name] = pair(name, before["pools"].get(p, {}).get(name), k)
    for name, k in after["objsets"].items():
        entry = run["datasets"].setdefault(name, {"pool": k["pool"]})
        entry["io"] = pair(name, before["objsets"].get(name), k)
    if proc is not None:
        try:
            rows = zfs.parse_iostat(zfs.finish_iostat(proc, interval))
        except ZfsError as e:
            run["errors"].append(str(e))
            rows = []
        trees = {p: {"vdevs": z["pools"][p]["vdevs"]} for p in pool_names}
        for p, att in zfs.attach_iostat(rows, trees).items():
            z["pools"][p]["iostat"] = att


def _sample(run: dict, interval: float, wanted: list[str],
            pool_names: list[str]) -> None:
    """Two readings of the counters an interval apart, and zpool iostat
    over the same interval."""
    state = sample_start(run, interval, wanted, pool_names)
    if interval > 0:
        time.sleep(interval)
    sample_finish(run, state)


# -- what stands out -----------------------------------------------------------

def _first(text: str | None) -> str:
    return text.strip().splitlines()[0] if text and text.strip() else ""


def pool_notes(run: dict) -> list[str]:
    """What costs time in the pools, the ARC and the write path."""
    out: list[str] = []
    z = run.get("zfs", {})
    pools = z.get("pools", {})
    devices = {d["name"]: d for d in run.get("devices", [])}
    if not z.get("available"):
        out.append("zpool and zfs not found: no pool, vdev or dataset "
                   "information")
    for e in run.get("errors", []):
        out.append(f"could not run: {e}")
    for name, p in pools.items():
        props = p.get("props", {})
        if p.get("scan_in_progress"):
            out.append(f"{name}: {_first(p['scan'])}: a scrub or resilver "
                       "competes with the workload for the disks")
        if p.get("state") and p["state"] != "ONLINE":
            out.append(f"{name} is {p['state']}: {_first(p.get('status'))}")
        elif p.get("status"):
            out.append(f"{name}: {_first(p['status'])}")
        cap = props.get("capacity")
        if isinstance(cap, int) and cap >= 80:
            out.append(f"{name}: {cap}% full: ZFS searches harder for free "
                       "space above about 80%, much harder above 90%, and "
                       "writes slow down")
        frag = props.get("fragmentation")
        if isinstance(frag, int) and frag >= 50:
            out.append(f"{name}: free space {frag}% fragmented: new data "
                       "lands in small pieces, so more seeks per write")
        ashift = props.get("ashift")
        kinds: dict[tuple, set] = {}
        untrimmed = []
        for leaf in p.get("leaves", []):
            dev = leaf.get("dev")
            errs = [leaf.get(k) or 0 for k in ("read", "write", "cksum")]
            if any(errs):
                out.append(f"{name}: {dev} has errors read/write/cksum "
                           f"{errs[0]}/{errs[1]}/{errs[2]}: retries and "
                           "repairs cost time, and a failing disk is slow "
                           "before it is dead")
            if leaf.get("slow"):
                out.append(f"{name}: {dev}: {leaf['slow']} slow I/Os "
                           "(over 30 s each)")
            disk = devices.get(leaf.get("disk") or "")
            if disk:
                phys = disk.get("physical_block_size")
                if isinstance(ashift, int) and isinstance(phys, int) and \
                        2 ** ashift < phys:
                    out.append(f"{name}: ashift {ashift} ({2 ** ashift} B "
                               f"blocks) on {dev} with {phys} B sectors: "
                               "the disk rewrites a whole sector for each "
                               "small block")
                key = (leaf.get("class"), leaf.get("vdev") or dev)
                kinds.setdefault(key, set()).add(disk.get("rotational"))
                if leaf.get("class") == "normal" and \
                        disk.get("rotational") is False and \
                        "untrimmed" in (leaf.get("note") or ""):
                    untrimmed.append(dev)
        for (cls, vdev), ks in kinds.items():
            if {True, False} <= ks:
                out.append(f"{name}: {vdev} ({cls}) mixes rotating disks "
                           "and SSDs: it runs at the pace of the slowest")
        if untrimmed and props.get("autotrim") == "off":
            out.append(f"{name}: SSDs never trimmed ({', '.join(untrimmed)}; "
                       "autotrim off, no zpool trim on record): the drives "
                       "do not know which blocks are free and garbage "
                       "collection gets costlier as they fill")
        t = p.get("txgs") or {}
        if t.get("sync_avg_ns", 0) > 2e9 or t.get("sync_max_ns", 0) > 10e9:
            out.append(f"{name}: a transaction group takes "
                       f"{fmt_dur(t['sync_avg_ns'])} to sync on average, "
                       f"{fmt_dur(t['sync_max_ns'])} at most: the pool "
                       "writes out dirty data slower than it comes in, and "
                       "writers stall when the next group cannot open")
    dmu = (z.get("kstats") or {}).get("dmu_tx") or {}
    d = dmu.get("delta") or {}
    s = dmu.get("snapshot") or {}
    delayed = d.get("dmu_tx_dirty_delay", 0) + d.get("dmu_tx_dirty_throttle", 0)
    total = s.get("dmu_tx_dirty_delay", 0) + s.get("dmu_tx_dirty_throttle", 0)
    if delayed:
        out.append(f"writes were held back by the dirty-data throttle "
                   f"{fmt_si(delayed)} times over the interval: the pool "
                   "absorbs writes slower than they arrive")
    elif total:
        out.append(f"the dirty-data throttle has held writes back "
                   f"{fmt_si(total)} times since boot (not in this "
                   "interval)")
    arc = z.get("arc") or {}
    mem = run.get("memory", {}).get("MemTotal")
    params = z.get("params", {})
    if arc.get("max") and mem and params.get("zfs_arc_max") and \
            arc["max"] < 0.3 * mem:
        out.append(f"ARC capped at {fmt_bytes(arc['max'])} of "
                   f"{fmt_bytes(mem)} RAM by zfs_arc_max")
    iv = arc.get("interval") or {}
    if iv.get("memory_throttles"):
        out.append(f"the ARC was throttled by memory pressure "
                   f"{iv['memory_throttles']} times over the interval")
    ghosts = (iv.get("mru_ghost_hits") or 0) + (iv.get("mfu_ghost_hits") or 0)
    if arc.get("size") and arc.get("max") and \
            arc["size"] >= 0.95 * arc["max"] and ghosts and \
            iv.get("accesses") and ghosts > 0.01 * iv["accesses"]:
        out.append(f"ARC is full and {fmt_si(ghosts)} of its "
                   f"{fmt_si(iv['accesses'])} accesses over the interval "
                   "were for data it had just evicted: more RAM would hit")
    return out


def memory_notes(run: dict) -> list[str]:
    out: list[str] = []
    m = run.get("memory", {})
    if m.get("SwapTotal") and m["SwapTotal"] - m.get("SwapFree", 0) > \
            max(0.1 * m["SwapTotal"], 256 << 20):
        out.append(f"swap in use: {fmt_bytes(m['SwapTotal'] - m['SwapFree'])}"
                   f" of {fmt_bytes(m['SwapTotal'])}")
    return out


def share_notes(run: dict) -> list[str]:
    """What in the shares' datasets and Samba settings costs time, and
    how the configuration was read."""
    out: list[str] = []
    pools = run.get("zfs", {}).get("pools", {})
    datasets = run.get("datasets", {})
    io_uring = run.get("io_uring", {})
    for share, sh in run.get("samba", {}).get("shares", {}).items():
        ds = sh.get("dataset")
        props = datasets.get(ds, {}).get("props", {}) if ds else {}
        pool = pools.get(ds.split("/")[0], {}) if ds else {}
        has_log = bool(pool.get("layout", {}).get("log"))
        who = f"{share} ({ds})" if ds else share
        if not ds and sh.get("path"):
            out.append(f"{share}: {sh['path']} is not on a ZFS dataset "
                       "mounted here")
        if props.get("sync") == "always":
            out.append(f"{who}: sync=always: every write waits for the ZIL "
                       + ("on the log device" if has_log else
                          "on the data disks (no log vdev)"))
        elif props.get("sync") == "disabled":
            out.append(f"{who}: sync=disabled: flushes and sync writes "
                       "return before reaching disk; up to a transaction "
                       "group of data is lost on power loss")
        if props.get("logbias") == "throughput" and has_log:
            out.append(f"{who}: logbias=throughput: sync writes bypass the "
                       "log device")
        if props.get("atime") == "on" and props.get("relatime") != "on":
            out.append(f"{who}: atime=on without relatime: every read "
                       "writes an access time")
        if props.get("xattr") and props["xattr"] != "sa":
            out.append(f"{who}: xattr={props['xattr']}: extended attributes "
                       "(DOS attributes, ACLs, streams) live in hidden "
                       "directories, an extra lookup and I/O per file; "
                       "xattr=sa keeps them in the dnode")
        if props.get("dnodesize") == "legacy" and props.get("xattr") == "sa":
            out.append(f"{who}: dnodesize=legacy with xattr=sa: attributes "
                       "that do not fit the 512-byte dnode go to a spill "
                       "block, an extra I/O per file; dnodesize=auto lets "
                       "the dnode grow (zfsprops(7) suggests it for Samba)")
        if props.get("casesensitivity") == "sensitive" and \
                sh.get("io", {}).get("case sensitive", "auto").lower() \
                not in ("yes", "true"):
            out.append(f"{who}: casesensitivity=sensitive: smbd resolves "
                       "case-insensitive names by scanning the directory; "
                       "casesensitivity=insensitive lets ZFS do it")
        if props.get("dedup") not in (None, "off"):
            out.append(f"{who}: dedup={props['dedup']}: every write looks "
                       "up the dedup table")
        if props.get("primarycache") in ("none", "metadata"):
            out.append(f"{who}: primarycache={props['primarycache']}: file "
                       "data is not cached in the ARC")
        if isinstance(props.get("copies"), int) and props["copies"] > 1:
            out.append(f"{who}: copies={props['copies']}: every block is "
                       f"written {props['copies']} times")
        if props.get("encryption") not in (None, "off"):
            out.append(f"{who}: encrypted ({props['encryption']}): every "
                       "block is decrypted on read and encrypted on write")
        io = sh.get("io", {})
        if io.get("sync always", "no").lower() in ("yes", "true"):
            out.append(f"{share}: sync always = yes: smbd fsyncs after "
                       "every write")
        if io.get("strict sync", "yes").lower() in ("no", "false"):
            out.append(f"{share}: strict sync = no: a client's flush does "
                       "not reach the disk")
        if io.get("strict allocate", "no").lower() in ("yes", "true"):
            out.append(f"{share}: strict allocate = yes: extending a file "
                       "allocates the space first, extra writes")
        for k in ("aio read size", "aio write size"):
            if io.get(k, "1") == "0":
                out.append(f"{share}: {k} = 0: those requests block the "
                           "smbd instead of running asynchronously")
        if smbconf.has_vfs(sh.get("params", {}), "io_uring"):
            if io_uring.get("disabled") == 2:
                out.append(f"{share}: vfs io_uring with "
                           "kernel.io_uring_disabled=2: io_uring is off "
                           "for everyone")
            elif io_uring.get("disabled") == 1:
                out.append(f"{share}: vfs io_uring with "
                           "kernel.io_uring_disabled=1: only group "
                           f"{io_uring.get('group')} may use io_uring")
    samba = run.get("samba", {})
    if samba.get("error"):
        src = samba.get("source")
        out.append(f"{samba['error']}; " + (
            f"shares read from {src} as written: shares kept in the registry "
            "and defaults are not seen; run as root for the effective "
            "configuration" if src else "no share information"))
    return out


def notes(run: dict) -> list[str]:
    return pool_notes(run) + memory_notes(run) + share_notes(run)


# -- output --------------------------------------------------------------------

def _cell(v) -> str:
    """A property value for a table: floats (ratios) with two decimals."""
    if v is None:
        return "-"
    return f"{v:.2f}" if isinstance(v, float) else str(v)


def _pct(x: float | None) -> str:
    return "-" if x is None else f"{100 * x:.1f}%"


def _bps(v: float | None) -> str:
    return "-" if v is None else fmt_bytes(v) + "/s"


def _per_s(v: float | None) -> str:
    return "-" if v is None else fmt_si(v) + "/s"


def _dur(ns: float | None) -> str:
    return "-" if ns is None else fmt_dur(ns)


def _kind(dev: dict | None) -> str:
    r = dev.get("rotational") if dev else None
    return "-" if r is None else ("HDD" if r else "SSD")


def _disks_of(p: dict, devices: dict) -> str:
    kinds: dict[str, int] = {}
    for leaf in p.get("leaves", []):
        if leaf.get("class") == "normal":
            k = _kind(devices.get(leaf.get("disk") or ""))
            kinds[k] = kinds.get(k, 0) + 1
    return " + ".join(f"{n} {k}" for k, n in sorted(kinds.items())) or "-"


def _layout(p: dict) -> str:
    lay = p.get("layout") or {}
    parts = []
    normal = lay.get("normal", [])
    if normal:
        counts: dict[str, int] = {}
        for v in normal:
            counts[v] = counts.get(v, 0) + 1
        parts.append(", ".join(f"{n} x {v}" if n > 1 else v
                               for v, n in counts.items()))
    for cls in ("log", "special", "dedup", "cache", "spare"):
        if lay.get(cls):
            parts.append(f"{cls}: {', '.join(lay[cls])}")
    return "; ".join(parts) or "-"


def print_head(run: dict) -> None:
    h = run.get("host", {})
    z = run.get("zfs", {})
    smb = run.get("smbd_version")
    bits = [f"TrueNAS {h['truenas']}" if h.get("truenas") else h.get("os"),
            f"Linux {h['kernel']}" if h.get("kernel") else None,
            f"OpenZFS {z['version']}" if z.get("version") else
            (None if z.get("available") else "no ZFS tools"),
            f"Samba {smb.replace('Version ', '')}" if smb else None,
            f"{h['cpus']} CPUs" if h.get("cpus") else None,
            f"at {run['start'][:19].replace('T', ' ')} UTC"
            if run.get("start") else None]
    print(f"host {h.get('hostname', '?')}: " + ", ".join(b for b in bits if b))
    m = run.get("memory", {})
    if m.get("MemTotal"):
        parts = [f"{fmt_bytes(m.get('MemFree'))} free",
                 f"{fmt_bytes(m.get('MemAvailable'))} available",
                 f"{fmt_bytes(m.get('Dirty'))} dirty"]
        if m.get("SwapTotal"):
            parts.append(f"swap {fmt_bytes(m['SwapTotal'] - m.get('SwapFree', 0))}"
                         f" of {fmt_bytes(m['SwapTotal'])} used")
        else:
            parts.append("no swap")
        print(f"memory {fmt_bytes(m['MemTotal'])}: " + ", ".join(parts))


def print_arc(run: dict) -> None:
    arc = run.get("zfs", {}).get("arc")
    if not arc:
        return
    mem = run.get("memory", {}).get("MemTotal")
    size, mx = arc.get("size"), arc.get("max")
    head = f"ARC {fmt_bytes(size)}"
    if mx:
        head += f" of {fmt_bytes(mx)} max"
        if mem:
            head += f" ({100 * mx / mem:.0f}% of RAM)"
    if arc.get("target"):
        head += f", target {fmt_bytes(arc['target'])}"
    parts = []
    for k, label in (("mru", "MRU"), ("mfu", "MFU"), ("data", "data"),
                     ("metadata", "metadata"), ("dnode", "dnodes"),
                     ("dbuf", "dbufs"), ("headers", "headers")):
        if arc.get(k) is not None:
            parts.append(f"{label} {fmt_bytes(arc[k])}")
    if arc.get("compressed") and arc.get("uncompressed"):
        parts.append(f"{arc['uncompressed'] / arc['compressed']:.2f}x "
                     "compressed")
    print(head + ": " + ", ".join(parts))

    def line(a: dict, label: str, rate: bool) -> str:
        n = a.get("accesses") or 0
        bits = [f"{fmt_si(n)} accesses" + ("/s" if rate else ""),
                f"{_pct(a.get('hit_ratio'))} hits"]
        detail = []
        for k, lab in (("demand_data", "demand data"),
                       ("demand_metadata", "demand metadata"),
                       ("prefetch_data", "prefetch data"),
                       ("prefetch_metadata", "prefetch metadata")):
            r = (a.get(k) or {}).get("hit_ratio")
            if r is not None:
                detail.append(f"{lab} {_pct(r)}")
        if a.get("iohits"):
            detail.append(f"iohits {_pct(a['iohits'] / n) if n else '-'}")
        if detail:
            bits[-1] += f" ({', '.join(detail)})"
        bits.append(f"{fmt_si(a.get('misses') or 0)} misses"
                    + ("/s" if rate else ""))
        if a.get("memory_throttles"):
            bits.append(f"{a['memory_throttles']} memory throttles")
        return f"  {label}: " + ", ".join(bits)
    print(line(arc, "since boot", False))
    iv = arc.get("interval")
    secs = run.get("io", {}).get("seconds")
    if iv and secs:
        rates = dict(iv)
        rates["accesses"] = (iv.get("accesses") or 0) / secs
        rates["misses"] = (iv.get("misses") or 0) / secs
        print(line(rates, f"over {secs:.1f} s", True))
    if arc.get("l2_devices"):
        print(f"  L2ARC: {arc['l2_devices']} device(s), "
              f"{fmt_bytes(arc.get('l2_size'))} "
              f"({fmt_bytes(arc.get('l2_asize'))} on disk), "
              f"{_pct(arc.get('l2_hit_ratio'))} hits since boot")


def print_pools(run: dict) -> None:
    pools = run.get("zfs", {}).get("pools", {})
    if not pools:
        return
    devices = {d["name"]: d for d in run.get("devices", [])}
    rows = []
    for name, p in pools.items():
        pr = p.get("props", {})
        cap = pr.get("capacity")
        frag = pr.get("fragmentation")
        rows.append([
            name, fmt_bytes(pr.get("size")), fmt_bytes(pr.get("allocated")),
            f"{cap}%" if cap is not None else "-",
            f"{frag}%" if frag is not None else "-",
            pr.get("ashift", "-"), p.get("state") or "-", _layout(p),
            _disks_of(p, devices), pr.get("autotrim", "-"),
            _cell(pr.get("dedupratio"))])
    print("\npools")
    print(cli.table(rows, ["pool", "size", "alloc", "cap", "frag", "ashift",
                           "state", "layout", "disks", "autotrim", "dedup"],
                    "lrrrrrlllll", indent="  "))
    for name, p in pools.items():
        for key in ("scan", "status", "action"):
            if p.get(key):
                text = p[key] if key == "scan" else _first(p[key])
                print(f"  {name} {key}: " + "\n    ".join(text.splitlines()))
        if p.get("errors") and "No known" not in p["errors"]:
            print(f"  {name} errors: {_first(p['errors'])}")


def print_vdevs(run: dict, others: bool = True) -> None:
    pools = run.get("zfs", {}).get("pools", {})
    devices = {d["name"]: d for d in run.get("devices", [])}
    rows = []
    for name, p in pools.items():
        for leaf in p.get("leaves", []):
            d = devices.get(leaf.get("disk") or "") or {}
            errs = "/".join("-" if leaf.get(k) is None else str(leaf[k])
                            for k in ("read", "write", "cksum"))
            rows.append([
                name, leaf.get("vdev") or "-", leaf.get("class", "-"),
                leaf.get("dev", "-"),
                leaf.get("disk") if leaf.get("disk") != leaf.get("dev")
                else "", (d.get("model") or "-")[:28],
                fmt_bytes(d.get("size")), _kind(d),
                d.get("transport") or "-", d.get("scheduler") or "-",
                d.get("queue_depth", "-"), d.get("nr_requests", "-"),
                leaf.get("state") or "-", errs,
                "-" if leaf.get("slow") is None else leaf["slow"],
                leaf.get("note") or ""])
    if not rows:
        return
    print("\nvdevs")
    print(cli.table(rows, ["pool", "vdev", "class", "device", "disk", "model",
                           "size", "kind", "bus", "sched", "qd", "nr_req",
                           "state", "r/w/c", "slow", "note"],
                    "llllllrlllrrlrrl", indent="  "))
    rest = [d for d in run.get("devices", []) if not d.get("zfs")]
    if others and rest:
        rows = [[d["name"], (d.get("model") or "-")[:28],
                 fmt_bytes(d.get("size")), _kind(d),
                 d.get("transport") or "-", d.get("scheduler") or "-",
                 ", ".join(f"{p['name']} {p.get('fstype') or p.get('parttypename') or ''}".strip()
                           for p in d.get("partitions", [])) or "-"]
                for d in rest]
        print("  other disks:")
        print(cli.table(rows, ["disk", "model", "size", "kind", "bus",
                               "sched", "partitions"], "llrllll",
                        indent="  "))


def print_io(run: dict) -> None:
    io = run.get("io", {})
    rates = io.get("devices", {})
    secs = io.get("seconds")
    if not rates or not secs:
        return
    devices = run.get("devices", [])
    names = [d["name"] for d in devices if d["name"] in rates]
    names.sort(key=lambda n: (not any(d.get("zfs") for d in devices
                                      if d["name"] == n), n))
    rows = []
    for n in names:
        r = rates[n]
        d = next((d for d in devices if d["name"] == n), {})
        where = ", ".join(sorted({f"{m['pool']}" for m in d.get("zfs", [])}))
        rows.append([
            n, where or "-", _per_s(r["reads_s"]), _per_s(r["writes_s"]),
            _bps(r["read_bytes_s"]), _bps(r["write_bytes_s"]),
            _dur(r["read_wait_ns"]), _dur(r["write_wait_ns"]),
            fmt_bytes(r["read_size"]) if r["read_size"] else "-",
            fmt_bytes(r["write_size"]) if r["write_size"] else "-",
            _per_s(r["flushes_s"]) if r["flushes_s"] else "-",
            f"{r['queue']:.2f}", _pct(r["util"])])
    print(f"\ndisk I/O over {secs:.1f} s")
    print(cli.table(rows, ["disk", "pool", "reads", "writes", "read", "write",
                           "r_wait", "w_wait", "r_size", "w_size", "flushes",
                           "queue", "busy"], "llrrrrrrrrrrr", indent="  "))


def print_zpool_iostat(run: dict) -> None:
    pools = run.get("zfs", {}).get("pools", {})
    secs = run.get("io", {}).get("seconds")
    rows = []
    for name, p in pools.items():
        ios = p.get("iostat")
        if not ios:
            continue

        def row(label: str, r: dict) -> list:
            return [label, _per_s(r.get("ops_read")), _per_s(r.get("ops_write")),
                    _bps(r.get("bytes_read")), _bps(r.get("bytes_write")),
                    _dur(r.get("total_wait_read")),
                    _dur(r.get("total_wait_write")),
                    _dur(r.get("disk_wait_read")),
                    _dur(r.get("disk_wait_write")),
                    _dur(r.get("syncq_wait_read")),
                    _dur(r.get("syncq_wait_write")),
                    _dur(r.get("asyncq_wait_read")),
                    _dur(r.get("asyncq_wait_write")),
                    _dur(r.get("scrub_wait")), _dur(r.get("trim_wait"))]
        rows.append(row(name, ios["pool"]))
        tree = p.get("vdevs") or {}

        def walk(node: dict, depth: int) -> None:
            for c in node.get("children", []):
                if c.get("heading"):
                    walk(c, depth)
                    continue
                label = "  " * depth + os.path.basename(c["name"])
                r = ios["vdevs"].get(c["name"]) if c.get("children") else \
                    ios["devices"].get(os.path.basename(c["name"]))
                if r:
                    rows.append(row(label, r))
                if c.get("children"):
                    walk(c, depth + 1)
        walk(tree, 1)
    if not rows:
        return
    print(f"\nzpool iostat over {secs:.1f} s (waits are means per I/O)")
    print(cli.table(rows, ["vdev", "reads", "writes", "read", "write",
                           "total r", "total w", "disk r", "disk w",
                           "syncq r", "syncq w", "asyncq r", "asyncq w",
                           "scrub", "trim"], "lrrrrrrrrrrrrrr", indent="  "))


def _zil_line(label: str, d: dict, secs: float | None) -> str:
    def rate(k: str) -> str:
        v = d.get(k)
        if v is None:
            return "-"
        return _per_s(v / secs) if secs else fmt_si(v)

    def brate(k: str) -> str:
        v = d.get(k)
        if v is None:
            return "-"
        return _bps(v / secs) if secs else fmt_bytes(v)
    sync_bytes = sum(d.get(k, 0) for k in ZIL_BYTES)
    parts = [f"{rate('zil_commit_count')} commits",
             f"{rate('zil_itx_count')} records: "
             f"{_bps(sync_bytes / secs) if secs else fmt_bytes(sync_bytes)}"
             " written synchronously ("
             f"indirect {brate('zil_itx_indirect_bytes')}, "
             f"copied {brate('zil_itx_copied_bytes')}, "
             f"needcopy {brate('zil_itx_needcopy_bytes')})",
             f"log blocks {brate('zil_itx_metaslab_normal_write')} on the "
             f"data vdevs, {brate('zil_itx_metaslab_slog_write')} on log "
             "devices"]
    if d.get("zil_commit_stall_count"):
        parts.append(f"{rate('zil_commit_stall_count')} stalls")
    return f"  {label}: " + "; ".join(parts)


def print_zil(run: dict) -> None:
    z = run.get("zfs", {})
    secs = run.get("io", {}).get("seconds")
    k = (z.get("kstats") or {}).get("zil")
    pool_k = {p: (v.get("kstats") or {}).get("zil")
              for p, v in z.get("pools", {}).items()}
    pool_k = {p: v for p, v in pool_k.items() if v}
    if not k and not pool_k:
        return
    print("\nZIL (sync writes)")
    if k:
        print(_zil_line("since boot", k["snapshot"], None))
        if k.get("delta") and secs:
            print(_zil_line(f"over {secs:.1f} s", k["delta"], secs))
    for p, v in pool_k.items():
        print(_zil_line(f"{p} since boot", v["snapshot"], None))
        if v.get("delta") and secs:
            print(_zil_line(f"{p} over {secs:.1f} s", v["delta"], secs))


def print_txgs(run: dict) -> None:
    z = run.get("zfs", {})
    pools = z.get("pools", {})
    lines = []
    for name, p in pools.items():
        t = p.get("txgs") or {}
        if not t:
            continue
        span = f" over {fmt_dur(t['span_ns'])}" if t.get("span_ns") else ""
        lines.append(
            f"  {name}: last {t['count']} committed{span}, {t['busy']} with "
            f"dirty data: dirty {fmt_bytes(t['dirty_avg'])} avg, "
            f"{fmt_bytes(t['dirty_max'])} max; sync {fmt_dur(t['sync_avg_ns'])}"
            f" avg, {fmt_dur(t['sync_max_ns'])} max; open "
            f"{fmt_dur(t['open_avg_ns'])} avg; {fmt_bytes(t['written'])} "
            f"written, {fmt_bytes(t['read'])} read")
    dmu = (z.get("kstats") or {}).get("dmu_tx")
    if dmu:
        s, d = dmu["snapshot"], dmu.get("delta") or {}

        def both(k: str) -> str:
            v = s.get(k, 0)
            return f"{fmt_si(d[k])} ({fmt_si(v)} since boot)" if k in d \
                else fmt_si(v)
        lines.append("  write throttle: dirty delays " + both("dmu_tx_dirty_delay")
                     + ", throttled " + both("dmu_tx_dirty_throttle")
                     + ", over max " + both("dmu_tx_dirty_over_max")
                     + ", memory reclaim " + both("dmu_tx_memory_reclaim"))
    if lines:
        print("\ntransaction groups")
        print("\n".join(lines))


def print_prefetch(run: dict) -> None:
    z = run.get("zfs", {})
    secs = run.get("io", {}).get("seconds")
    zf = (z.get("kstats") or {}).get("zfetchstats")
    db = (z.get("kstats") or {}).get("dbufstats")
    lines = []
    if zf:
        def ratio(d: dict) -> str:
            h, m = d.get("hits", 0), d.get("misses", 0)
            return _pct(h / (h + m)) if h + m else "-"
        s = zf["snapshot"]
        text = f"  prefetch (zfetch): {ratio(s)} of {fmt_si(s.get('hits', 0) + s.get('misses', 0))} accesses hit a stream since boot"
        if zf.get("delta") and secs:
            d = zf["delta"]
            text += (f"; over {secs:.1f} s: {ratio(d)} of "
                     f"{_per_s((d.get('hits', 0) + d.get('misses', 0)) / secs)}"
                     f", {_per_s(d.get('io_issued', 0) / secs)} prefetch I/Os"
                     " issued")
        lines.append(text)
    if db:
        s = db["snapshot"]
        text = (f"  dbuf cache: {fmt_bytes(s.get('cache_size_bytes'))} of "
                f"{fmt_bytes(s.get('cache_target_bytes'))} target")
        h, m = s.get("hash_hits", 0), s.get("hash_misses", 0)
        if h + m:
            text += f", {_pct(h / (h + m))} hash hits since boot"
        if db.get("delta"):
            d = db["delta"]
            h, m = d.get("hash_hits", 0), d.get("hash_misses", 0)
            if h + m:
                text += f" ({_pct(h / (h + m))} over the interval)"
        lines.append(text)
    for p, v in z.get("pools", {}).items():
        k = (v.get("kstats") or {}).get("iostats")
        if k and k.get("delta") and secs:
            d = k["delta"]
            if any(d.get(x) for x in ("arc_read_count", "arc_write_count",
                                      "direct_read_count",
                                      "direct_write_count")):
                lines.append(
                    f"  {p} over {secs:.1f} s: ARC reads "
                    f"{_per_s(d.get('arc_read_count', 0) / secs)} "
                    f"({_bps(d.get('arc_read_bytes', 0) / secs)}), writes "
                    f"{_per_s(d.get('arc_write_count', 0) / secs)} "
                    f"({_bps(d.get('arc_write_bytes', 0) / secs)}); direct "
                    f"I/O reads {_per_s(d.get('direct_read_count', 0) / secs)}"
                    f", writes {_per_s(d.get('direct_write_count', 0) / secs)}")
    if lines:
        print("\ncaching")
        print("\n".join(lines))


def print_dataset_io(run: dict) -> None:
    secs = run.get("io", {}).get("seconds")
    if not secs:
        return
    share_ds = {s["dataset"] for s in run.get("samba", {}).get("shares", {}).values()
                if s.get("dataset")}
    rows = []
    for name, d in run.get("datasets", {}).items():
        io = d.get("io")
        if not io or not io.get("delta"):
            continue
        dl = io["delta"]
        ops = dl.get("reads", 0) + dl.get("writes", 0) + dl.get("nunlinks", 0) \
            + dl.get("zil_commit_count", 0)
        if not ops and name not in share_ds:
            continue
        sync_bytes = sum(dl.get(k, 0) for k in ZIL_BYTES)
        rows.append((ops, [
            name, _per_s(dl.get("reads", 0) / secs),
            _bps(dl.get("nread", 0) / secs),
            _per_s(dl.get("writes", 0) / secs),
            _bps(dl.get("nwritten", 0) / secs),
            _per_s(dl.get("nunlinks", 0) / secs),
            _per_s(dl.get("zil_commit_count", 0) / secs)
            if "zil_commit_count" in dl else "-",
            _bps(sync_bytes / secs) if "zil_commit_count" in dl else "-"]))
    if not rows:
        return
    rows.sort(key=lambda r: -r[0])
    print(f"\ndataset I/O over {secs:.1f} s (share datasets, and any that moved)")
    print(cli.table([r for _, r in rows[:25]],
                    ["dataset", "reads", "read", "writes", "write", "unlinks",
                     "zil commits", "sync writes"], "lrrrrrrr", indent="  "))
    if len(rows) > 25:
        print(f"  ... {len(rows) - 25} more")


def print_shares(run: dict) -> None:
    samba = run.get("samba", {})
    shares = samba.get("shares", {})
    print(f"\nshares ({samba.get('source') or 'no configuration found'})")
    if not shares:
        print("  none")
        return
    rows = [[name, s.get("path") or "-", s.get("dataset") or "-",
             " ".join(s.get("params", {}).get("vfs objects", "").split())
             or "-"] for name, s in shares.items()]
    print(cli.table(rows, ["share", "path", "dataset", "vfs objects"],
                    indent="  "))
    for name, s in shares.items():
        io = {k: v for k, v in s.get("io", {}).items() if k != "vfs objects"}
        if io:
            print(wrap_items(f"  {name}: ",
                             [f"{k} = {v}" for k, v in io.items()]))
    g = samba.get("global", {})
    gio = {k: v for k, v in smbconf.io_settings({}, g).items()}
    if gio:
        print(wrap_items("  [global]: ",
                         [f"{k} = {v}" for k, v in gio.items()]))
    iu = run.get("io_uring", {})
    using = [n for n, s in shares.items()
             if smbconf.has_vfs(s.get("params", {}), "io_uring")]
    if iu.get("disabled") is not None or using:
        state = {0: "allowed", 1: f"group {iu.get('group')} only",
                 2: "disabled"}.get(iu.get("disabled"), "no sysctl")
        print(f"  io_uring: {state} (kernel.io_uring_disabled="
              f"{iu.get('disabled')}); shares with vfs io_uring: "
              f"{', '.join(using) or 'none'}")


def print_datasets(run: dict) -> None:
    datasets = run.get("datasets", {})
    names = [n for n in run.get("detailed", []) if datasets.get(n, {}).get("props")]
    if not names:
        return
    rows = []
    for n in names:
        d = datasets[n]
        p = d["props"]
        src = d.get("sources", {})
        cells = [n]
        for k in DATASET_PROPS:
            v = p.get(k)
            if v is None:
                cells.append("-")
                continue
            if k in ("recordsize", "special_small_blocks", "quota",
                     "refquota") and isinstance(v, int):
                text = fmt_bytes(v) if v else (
                    "none" if k in ("quota", "refquota") else "0")
            else:
                text = _cell(v)
            if k in src and k not in ("compressratio",):
                text += "*"
            cells.append(text)
        lst = d.get("list", {})
        cells += [fmt_bytes(lst.get("used") if lst else p.get("used")),
                  fmt_bytes(lst.get("avail") if lst else p.get("available")),
                  fmt_bytes(p.get("usedbysnapshots"))]
        rows.append(cells)
    print("\ndatasets (* set here or inherited, not the default)")
    print(cli.table(rows, ["dataset", "recsize", "compress", "ratio", "sync",
                           "logbias", "atime", "relatime", "xattr", "dnode",
                           "acltype", "case", "pcache", "special", "copies",
                           "dedup", "encrypt", "direct", "quota", "refquota",
                           "used", "avail", "snaps"],
                    "l" + "r" * 2 + "l" * 17 + "rrr", indent="  "))
    counts: dict[str, int] = {}
    for d in datasets.values():
        t = (d.get("list") or {}).get("type")
        if t:
            counts[t] = counts.get(t, 0) + 1
    if counts:
        print("  " + ", ".join(f"{n} {t}s" for t, n in sorted(counts.items()))
              + " in all")


def print_params(run: dict, show_all: bool) -> None:
    z = run.get("zfs", {})
    params = z.get("params", {})
    if not params:
        return
    names = sorted(params) if show_all else [p for p in PARAMS_OF_NOTE
                                             if p in params]
    rows = []
    for n in names:
        v = params[n]
        text = str(v)
        if n in BYTES_PARAMS and isinstance(v, int) and v > 0:
            text += f" ({fmt_bytes(v)})"
        elif n in BYTES_PARAMS and v == 0:
            text += " (auto)"
        rows.append([n, text])
    print(f"\nZFS module parameters{'' if show_all else ' of note (--params for all)'}")
    print(cli.table(rows, ["parameter", "value"], indent="  "))
    for line in z.get("modprobe", []):
        print(f"  {line}")


def print_notes(run: dict) -> None:
    notes_ = run.get("notes", [])
    if notes_:
        print("\nnotes")
        for n in notes_:
            print(f"  - {n}")


def print_run(run: dict, show_params: bool = False) -> None:
    print_head(run)
    print_arc(run)
    print_pools(run)
    print_vdevs(run)
    print_io(run)
    print_zpool_iostat(run)
    print_zil(run)
    print_txgs(run)
    print_prefetch(run)
    print_dataset_io(run)
    print_shares(run)
    print_datasets(run)
    print_params(run, show_params)
    print_notes(run)


# -- main ----------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="The storage under the SMB shares in one look: pools, "
                    "vdevs and disks with their queue settings, ARC, ZIL and "
                    "transaction groups, the datasets the shares live on and "
                    "their settings, I/O rates and latencies over a few "
                    "seconds, and notes on what costs time. Runs on the "
                    "server; root sees the effective Samba configuration.",
        epilog="A run saved with -o prints again as INPUT.")
    ap.add_argument("input", nargs="?", metavar="INPUT",
                    help="a saved run (JSON) to print instead of gathering")
    ap.add_argument("--interval", default="5", metavar="T",
                    help="how long to sample I/O and cache counters "
                    "(default 5s; 0 for none)")
    ap.add_argument("--pool", action="append", default=[], metavar="NAME",
                    help="only this pool (repeatable)")
    ap.add_argument("--share", action="append", default=[], metavar="NAME",
                    help="only this share (repeatable)")
    ap.add_argument("--all-datasets", action="store_true",
                    help="properties of every filesystem, not only the "
                    "shares' and the pools' roots")
    ap.add_argument("--params", action="store_true",
                    help="print every ZFS module parameter")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="save everything gathered as JSON")
    ap.add_argument("--json", action="store_true",
                    help="print the JSON instead of the report")
    args = ap.parse_args(argv)
    if args.input:
        try:
            with open(args.input) as f:
                run = json.load(f)
        except (OSError, ValueError) as e:
            cli.note(f"error: {args.input}: {e}")
            return 1
        if run.get("tool") != "smb-perf-disk":
            cli.note(f"error: {args.input}: not a smb-perf-disk run")
            return 1
    else:
        try:
            interval = parse_duration(args.interval)
        except ValueError as e:
            ap.error(str(e))
        if interval < 0:
            ap.error("--interval must be 0 or more")
        try:
            run = gather(interval, args.pool, args.share, args.all_datasets)
        except KeyboardInterrupt:
            cli.note("interrupted")
            return 130
    if args.output:
        with open(args.output, "w") as f:
            json.dump(run, f, indent=1)
    if args.json:
        print(json.dumps(run, indent=1))
    else:
        print_run(run, args.params)
    if args.output and not args.json:
        sys.stdout.flush()
        cli.note(f"saved {args.output}")
    return 0
