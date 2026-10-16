"""ZFS as userland sees it: pools and their vdevs, datasets and their
properties, and the kernel's counters under /proc/spl/kstat/zfs."""

from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess

KSTAT = "/proc/spl/kstat/zfs"
PARAMS = "/sys/module/zfs/parameters"
# zpool status heads the vdevs outside the normal class with these words.
CLASSES = {"logs": "log", "cache": "cache", "special": "special",
           "dedup": "dedup", "spares": "spare"}
STATES = {"ONLINE", "DEGRADED", "FAULTED", "OFFLINE", "UNAVAIL", "REMOVED",
          "AVAIL", "INUSE", "SUSPENDED", "SPLIT"}
FIELDS = {"pool", "state", "status", "action", "see", "scan", "scrub",
          "remove", "checkpoint", "expand", "config", "errors"}
LIST_COLS = ("name", "type", "used", "avail", "refer", "mountpoint",
             "mounted")
# zpool iostat -vlHp, after the name; latencies in ns with -p.
IOSTAT_COLS = (
    "alloc", "free", "ops_read", "ops_write", "bytes_read", "bytes_write",
    "total_wait_read", "total_wait_write", "disk_wait_read",
    "disk_wait_write", "syncq_wait_read", "syncq_wait_write",
    "asyncq_wait_read", "asyncq_wait_write", "scrub_wait", "trim_wait",
    "rebuild_wait")
# The kstats sampled over the interval.
GLOBAL_KSTATS = ("arcstats", "zfetchstats", "dmu_tx", "dbufstats", "zil")
POOL_KSTATS = ("iostats", "zil")


class ZfsError(Exception):
    pass


def run(cmd: list[str], timeout: float = 120) -> str:
    """stdout of a zpool or zfs command; ZfsError if it is missing, fails
    or hangs (a suspended pool can hang zpool)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
    except OSError as e:
        raise ZfsError(f"{cmd[0]}: {e.strerror or e}") from None
    except subprocess.TimeoutExpired:
        raise ZfsError(f"{' '.join(cmd[:2])}: no answer in "
                       f"{timeout:g} s") from None
    if p.returncode != 0:
        err = p.stderr.strip().splitlines()
        raise ZfsError(f"{' '.join(cmd[:2])}: "
                       f"{err[0] if err else 'failed'}")
    return p.stdout


def have_zfs() -> bool:
    return bool(shutil.which("zpool") and shutil.which("zfs"))


def _read(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def value(text: str):
    """A field of -H -p output: '-' is None, a number a number."""
    if text == "-":
        return None
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d+\.\d+", text):
        return float(text)
    return text


def nicenum(text: str) -> int | None:
    """A count as zpool prints it without -p: 12, 1.25K (1024-based)."""
    if text == "-":
        return None
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([KMGTPE]?)", text)
    if not m:
        return None
    power = "KMGTPE".index(m.group(2)) + 1 if m.group(2) else 0
    return int(float(m.group(1)) * 1024 ** power)


def parse_table(text: str, columns: tuple[str, ...],
                raw: tuple[str, ...] = ("name",)) -> list[dict]:
    """zpool/zfs -H output, tab separated, as dicts; `raw` columns stay
    text."""
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        f = line.split("\t")
        rows.append({c: (v if c in raw else value(v))
                     for c, v in zip(columns, f)})
    return rows


def parse_get(text: str) -> dict[str, dict]:
    """zpool/zfs get -Hp -o name,property,value,source as {name:
    {"props": {prop: value}, "sources": {prop: source}}}; a source is
    kept when it is not the default."""
    out: dict[str, dict] = {}
    for line in text.splitlines():
        f = line.split("\t")
        if len(f) < 3:
            continue
        d = out.setdefault(f[0], {"props": {}, "sources": {}})
        d["props"][f[1]] = value(f[2])
        src = f[3] if len(f) > 3 else "-"
        if src not in ("-", "default"):
            d["sources"][f[1]] = src
    return out


# -- zpool status --------------------------------------------------------------

def _vdev_row(line: str) -> dict:
    """A line of the config: indentation gives the depth, then name,
    state, the error counters, and a note like (resilvering)."""
    body = line.lstrip("\t")
    indent = len(body) - len(body.lstrip(" "))
    tokens = body.split()
    row: dict = {"name": tokens[0], "depth": indent // 2, "state": None,
                 "read": None, "write": None, "cksum": None, "slow": None,
                 "note": ""}
    rest = tokens[1:]
    if rest and rest[0] in STATES:
        row["state"] = rest.pop(0)
        for key in ("read", "write", "cksum", "slow"):
            if rest and re.fullmatch(r"\d+(?:\.\d+)?[KMGTPE]?|-", rest[0]):
                row[key] = nicenum(rest.pop(0))
            else:
                break
    row["note"] = " ".join(rest)
    return row


def _tree(rows: list[dict]) -> dict | None:
    """The pool's vdevs nested as zpool status indents them; vdevs
    under a class heading (logs, cache, special, dedup, spares) carry
    that class."""
    pool = None
    stack: list[dict] = []
    cls = "normal"
    for r in rows:
        depth = r["depth"]
        node = {k: v for k, v in r.items() if k != "depth"}
        node["children"] = []
        if depth == 0:
            if pool is None:
                pool = node
                node["class"] = cls
            else:
                cls = CLASSES.get(r["name"], r["name"])
                node["class"] = cls
                node["heading"] = True
                pool["children"].append(node)
            stack = [node]
            continue
        node["class"] = cls
        while len(stack) > depth:
            stack.pop()
        if not stack:
            stack = [pool] if pool else []
            if not stack:
                continue
        stack[-1]["children"].append(node)
        stack.append(node)
    return pool


def parse_status(text: str) -> dict[str, dict]:
    """zpool status as {pool: {"state", "text": {field: text}, "scan":
    text, "scan_in_progress", "errors", "vdevs": tree}}."""
    pools: dict[str, dict] = {}
    cur: dict | None = None
    field = None
    in_config = False
    for line in text.splitlines():
        if in_config:
            if not re.match(r"^\s*errors:", line):
                s = line.strip()
                if s and not s.startswith("NAME ") and cur is not None:
                    cur["rows"].append(_vdev_row(line))
                continue
            in_config = False
        m = re.match(r"^\s*([a-z]+):(?:\s+|$)(.*)$", line)
        if m and m.group(1) in FIELDS:
            field = m.group(1)
            rest = m.group(2).strip()
            if field == "pool":
                cur = pools.setdefault(rest, {"state": None, "text": {},
                                              "rows": []})
            elif field == "config":
                in_config = True
            elif cur is not None:
                if field == "state":
                    cur["state"] = rest
                else:
                    cur["text"][field] = rest
            continue
        if cur is not None and field not in (None, "pool", "state") \
                and line.strip():
            prev = cur["text"].get(field, "")
            cur["text"][field] = (prev + "\n" + line.strip()).strip()
    for name, p in pools.items():
        scan = p["text"].get("scan") or p["text"].get("scrub")
        p["scan"] = scan
        p["scan_in_progress"] = bool(scan and "in progress" in scan)
        p["errors"] = p["text"].get("errors")
        p["vdevs"] = _tree(p.pop("rows"))
    return pools


def leaves(pool_tree: dict | None) -> list[dict]:
    """The leaf vdevs (devices) of a status tree, each with its class,
    the vdev (mirror-0, raidz1-0) it belongs to, if any, and `dev`, the
    device's basename."""
    out: list[dict] = []

    def walk(node: dict, group: str | None) -> None:
        for c in node.get("children", []):
            if c.get("heading"):
                walk(c, None)
            elif c.get("children"):
                walk(c, c["name"])
            else:
                leaf = {k: v for k, v in c.items() if k != "children"}
                leaf["vdev"] = group
                leaf["dev"] = os.path.basename(c["name"])
                out.append(leaf)
    if pool_tree:
        walk(pool_tree, None)
    return out


def layout(pool_tree: dict | None) -> dict[str, list[str]]:
    """Vdev types by class: {"normal": ["raidz1 of 3", "raidz1 of 3"],
    "log": ["disk"], "cache": ["mirror of 2"]}."""
    out: dict[str, list[str]] = {}

    def describe(node: dict) -> str:
        if not node.get("children"):
            return "disk"
        kind = re.sub(r"-\d+$", "", node["name"])
        n = len(node["children"])
        return f"{kind} of {n}"

    def walk(node: dict, cls: str) -> None:
        for c in node.get("children", []):
            if c.get("heading"):
                walk(c, c["class"])
            else:
                out.setdefault(cls, []).append(describe(c))
    if pool_tree:
        walk(pool_tree, "normal")
    return out


def pool_status(pools: list[str] | None = None) -> dict[str, dict]:
    """zpool status with real device paths and, where the version has
    them, slow I/O counts and TRIM state."""
    names = list(pools or [])
    try:
        text = run(["zpool", "status", "-LPpst"] + names)
    except ZfsError:
        text = run(["zpool", "status", "-LP"] + names)
    return parse_status(text)


def pool_props(pools: list[str] | None = None) -> dict[str, dict]:
    text = run(["zpool", "get", "-Hp", "-o", "name,property,value,source",
                "all"] + list(pools or []))
    return parse_get(text)


# -- zpool iostat --------------------------------------------------------------

def start_iostat(interval: float, pools: list[str] | None = None):
    """zpool iostat over one interval, with per-vdev latencies, started
    now; finish_iostat() collects it."""
    cmd = ["zpool", "iostat", "-vlHpLy", f"{interval:g}", "1"] \
        + list(pools or [])
    try:
        return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
    except OSError as e:
        raise ZfsError(f"zpool iostat: {e.strerror or e}") from None


def finish_iostat(proc, interval: float) -> str:
    try:
        out, err = proc.communicate(timeout=interval + 60)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise ZfsError("zpool iostat: no answer") from None
    if proc.returncode != 0:
        err = err.strip().splitlines()
        raise ZfsError(f"zpool iostat: {err[0] if err else 'failed'}")
    return out


def parse_iostat(text: str) -> list[dict]:
    """zpool iostat -vlHp rows, flat, as printed: pool, its vdevs,
    their devices; -H prints no class headings."""
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        f = line.split("\t")
        row: dict = {"name": f[0]}
        for c, v in zip(IOSTAT_COLS, f[1:]):
            row[c] = value(v)
        rows.append(row)
    return rows


def attach_iostat(rows: list[dict], status: dict[str, dict]) -> dict:
    """iostat rows by pool: {pool: {"pool": row, "vdevs": {name: row},
    "devices": {dev: row}}}, using the status tree to tell them apart;
    a pool's row starts its section."""
    out: dict[str, dict] = {}
    cur = None
    groups: set[str] = set()
    devs: set[str] = set()
    for r in rows:
        name = r["name"]
        if name in status and (cur is None or name != cur):
            cur = name
            out[cur] = {"pool": r, "vdevs": {}, "devices": {}}
            tree = status[name].get("vdevs")
            groups = set()

            def collect(node: dict) -> None:
                for c in node.get("children", []):
                    if c.get("children") and not c.get("heading"):
                        groups.add(c["name"])
                    collect(c)
            if tree:
                collect(tree)
            devs = {lf["dev"] for lf in leaves(tree)}
            continue
        if cur is None:
            continue
        base = os.path.basename(name)
        if name in groups:
            out[cur]["vdevs"][name] = r
        elif base in devs or name in devs:
            out[cur]["devices"][base] = r
        else:
            out[cur].setdefault("other", {})[name] = r
    return out


# -- datasets ------------------------------------------------------------------

def datasets() -> list[dict]:
    text = run(["zfs", "list", "-Hp", "-t", "filesystem,volume", "-o",
                ",".join(LIST_COLS)])
    rows = parse_table(text, LIST_COLS,
                       raw=("name", "type", "mountpoint", "mounted"))
    for r in rows:
        r["mounted"] = r.get("mounted") == "yes"
    return rows


def dataset_props(names: list[str]) -> dict[str, dict]:
    if not names:
        return {}
    text = run(["zfs", "get", "-Hp", "-o", "name,property,value,source",
                "all"] + list(names))
    return parse_get(text)


# -- kstats --------------------------------------------------------------------

_ROW = re.compile(r"^(.*?)\s+(\d+)\s+(\S.*)$")


_HEADER = re.compile(r"^\d+ \d+ 0x[0-9a-f]+ \d+ \d+ \d+ (\d+)\s*$")


def _snaptime(lines: list[str]) -> int | None:
    """The kstat header's snapshot time, ns on the monotonic clock;
    None when the kstat prints its own header instead (txgs does)."""
    if lines:
        m = _HEADER.match(lines[0])
        if m:
            return int(m.group(1))
    return None


def parse_kstat(text: str) -> dict:
    """A named kstat: {"snaptime": ns or None, "data": {name: value}};
    counters are ints, names such as dataset_name text."""
    lines = text.splitlines()
    out: dict = {"snaptime": _snaptime(lines), "data": {}}
    for line in lines:
        if line.startswith("name ") or _HEADER.match(line):
            continue
        m = _ROW.match(line.rstrip())
        if not m:
            continue
        name, data = m.group(1).strip(), m.group(3).strip()
        out["data"][name] = int(data) if re.fullmatch(r"-?\d+", data) \
            else data
    return out


def parse_txgs(text: str) -> dict:
    """The txgs kstat: {"snaptime", "txgs": [{txg, birth, state, ndirty,
    nread, nwritten, reads, writes, otime, qtime, wtime, stime}]}."""
    lines = text.splitlines()
    out: dict = {"snaptime": _snaptime(lines), "txgs": []}
    cols = None
    for line in lines:
        f = line.split()
        if not f or _HEADER.match(line):
            continue
        if f[0] == "txg":
            cols = f
            continue
        if cols is None or len(f) < len(cols):
            continue
        out["txgs"].append({c: int(v) if v.isdigit() else v
                            for c, v in zip(cols, f)})
    return out


def txg_summary(parsed: dict) -> dict:
    """Over the committed txgs on record: how many, how much time they
    span, dirty data and sync time (over the ones that had dirty data),
    time open, bytes written."""
    rows = [t for t in parsed.get("txgs", []) if t.get("state") == "C"]
    if not rows:
        return {}
    busy = [t for t in rows if t.get("ndirty", 0) > 0] or rows
    snap = parsed.get("snaptime")
    out = {
        "count": len(rows), "busy": len(busy),
        "span_ns": (snap - rows[0]["birth"]) if snap else None,
        "dirty_avg": sum(t["ndirty"] for t in busy) / len(busy),
        "dirty_max": max(t["ndirty"] for t in rows),
        "sync_avg_ns": sum(t["stime"] for t in busy) / len(busy),
        "sync_max_ns": max(t["stime"] for t in rows),
        "wait_avg_ns": sum(t["wtime"] for t in rows) / len(rows),
        "open_avg_ns": sum(t["otime"] for t in rows) / len(rows),
        "written": sum(t.get("nwritten", 0) for t in rows),
        "read": sum(t.get("nread", 0) for t in rows),
    }
    return out


def read_kstat(path: str) -> dict | None:
    text = _read(path)
    return parse_kstat(text) if text is not None else None


def global_kstats(names=GLOBAL_KSTATS) -> dict[str, dict]:
    out = {}
    for n in names:
        k = read_kstat(f"{KSTAT}/{n}")
        if k is not None:
            out[n] = k
    return out


def pool_kstats(pool: str, names=POOL_KSTATS) -> dict[str, dict]:
    out = {}
    for n in names:
        k = read_kstat(f"{KSTAT}/{pool}/{n}")
        if k is not None:
            out[n] = k
    return out


def pool_txgs(pool: str) -> dict | None:
    text = _read(f"{KSTAT}/{pool}/txgs")
    return parse_txgs(text) if text is not None else None


def pool_state(pool: str) -> str | None:
    text = _read(f"{KSTAT}/{pool}/state")
    return text.strip() if text else None


def objsets(pools: list[str] | None = None) -> dict[str, dict]:
    """Per-dataset counters: {dataset: {"pool", "snaptime", "data":
    {reads, nread, writes, nwritten, nunlinks, nunlinked, zil_*}}}."""
    out: dict[str, dict] = {}
    for path in glob.glob(f"{KSTAT}/*/objset-*"):
        pool = os.path.basename(os.path.dirname(path))
        if pools and pool not in pools:
            continue
        k = read_kstat(path)
        if k is None:
            continue
        name = k["data"].pop("dataset_name", None)
        if isinstance(name, str) and name:
            out[name] = {"pool": pool, **k}
    return out


def delta(before: dict, after: dict) -> dict:
    """after - before for every integer both have."""
    return {k: after[k] - v for k, v in before.items()
            if isinstance(v, int) and isinstance(after.get(k), int)}


def kstat_pools() -> list[str]:
    """Pools the kernel has imported, from the kstat directories."""
    out = []
    try:
        for d in sorted(os.listdir(KSTAT)):
            if os.path.isdir(f"{KSTAT}/{d}") and os.path.exists(
                    f"{KSTAT}/{d}/txgs"):
                out.append(d)
    except OSError:
        pass
    return out


# -- the module ----------------------------------------------------------------

def version() -> str | None:
    v = _read("/sys/module/zfs/version")
    if v and v.strip():
        return v.strip()
    try:
        out = run(["zfs", "version"], timeout=10)
    except ZfsError:
        return None
    return out.strip().splitlines()[0] if out.strip() else None


def params() -> dict:
    """Every module parameter, as the kernel reports it."""
    out = {}
    for path in sorted(glob.glob(f"{PARAMS}/*")):
        v = _read(path)
        if v is None:
            continue
        v = v.strip()
        out[os.path.basename(path)] = value(v) if v != "-" else v
    return out


def modprobe_options() -> list[str]:
    """zfs lines from /etc/modprobe.d: parameters set at boot."""
    out = []
    for path in sorted(glob.glob("/etc/modprobe.d/*.conf")):
        text = _read(path) or ""
        for line in text.splitlines():
            if re.match(r"^\s*options\s+(zfs|spl)\b", line):
                out.append(f"{os.path.basename(path)}: {line.strip()}")
    return out


# -- derived -------------------------------------------------------------------

def arc_summary(data: dict) -> dict:
    """What the ARC holds and how it does, from arcstats."""
    g = data.get

    def ratio(hits: int, iohits: int, misses: int) -> float | None:
        total = hits + iohits + misses
        return hits / total if total else None

    def kind(prefix: str) -> dict:
        h, io, m = (g(f"{prefix}_hits", 0), g(f"{prefix}_iohits", 0),
                    g(f"{prefix}_misses", 0))
        return {"hits": h, "iohits": io, "misses": m,
                "hit_ratio": ratio(h, io, m)}

    hits, iohits, misses = g("hits", 0), g("iohits", 0), g("misses", 0)
    out = {
        "size": g("size"), "target": g("c"), "min": g("c_min"),
        "max": g("c_max"), "mru": g("mru_size"), "mfu": g("mfu_size"),
        "anon": g("anon_size"), "data": g("data_size"),
        "metadata": g("metadata_size"), "meta_used": g("arc_meta_used"),
        "dnode": g("dnode_size"), "dbuf": g("dbuf_size"),
        "headers": g("hdr_size"), "compressed": g("compressed_size"),
        "uncompressed": g("uncompressed_size"),
        "accesses": hits + iohits + misses,
        "hits": hits, "iohits": iohits, "misses": misses,
        "hit_ratio": ratio(hits, iohits, misses),
        "demand_data": kind("demand_data"),
        "demand_metadata": kind("demand_metadata"),
        "prefetch_data": kind("prefetch_data"),
        "prefetch_metadata": kind("prefetch_metadata"),
        "mru_hits": g("mru_hits"), "mfu_hits": g("mfu_hits"),
        "mru_ghost_hits": g("mru_ghost_hits"),
        "mfu_ghost_hits": g("mfu_ghost_hits"),
        "memory_throttles": g("memory_throttle_count"),
        "no_grow": g("arc_no_grow"), "need_free": g("arc_need_free"),
        "evict_skip": g("evict_skip"),
        "l2_devices": g("l2_ndev", 0), "l2_size": g("l2_size"),
        "l2_asize": g("l2_asize"), "l2_hits": g("l2_hits"),
        "l2_misses": g("l2_misses"),
        "l2_hit_ratio": ratio(g("l2_hits", 0), 0, g("l2_misses", 0)),
    }
    return out
