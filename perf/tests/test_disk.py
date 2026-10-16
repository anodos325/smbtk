"""smb-perf-disk: its parsers on text as zpool, zfs, the kernel and Samba
print it, the notes it draws, and a live run with what the box has."""

from __future__ import annotations

import io
import json
import os
import re
import sys
from contextlib import redirect_stdout

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from smbperf import blockdev, cmd_disk, smbconf, zfs  # noqa: E402

STATUS = """\
  pool: tank
 state: DEGRADED
status: One or more devices has experienced an unrecoverable error.  An
\tattempt was made to correct the error.  Applications are unaffected.
action: Determine if the device needs to be replaced, and clear the errors
\tusing 'zpool clear' or replace the device with 'zpool replace'.
   see: https://openzfs.github.io/openzfs-docs/msg/ZFS-8000-9P
  scan: scrub in progress since Thu Oct 15 10:00:00 2026
\t1.20T / 5.00T scanned at 1.10G/s, 500G / 5.00T issued at 450M/s
\t0B repaired, 10.00% done, 02:50:00 to go
config:

\tNAME                STATE     READ WRITE CKSUM  SLOW
\ttank                DEGRADED     3     0    12     -
\t  mirror-0          DEGRADED     3     0    12     -
\t    /dev/sda1       ONLINE       0     0     0     0  (untrimmed)
\t    /dev/sdb1       FAULTED      3     0    12     2  too many errors
\t  mirror-1          ONLINE       0     0     0     -
\t    /dev/sdc1       ONLINE       0     0     0     0
\t    /dev/sdd1       ONLINE       0     0     0     0
\tspecial
\t  mirror-2          ONLINE       0     0     0     -
\t    /dev/nvme0n1p1  ONLINE       0     0     0     0
\t    /dev/nvme1n1p1  ONLINE       0     0     0     0
\tlogs
\t  /dev/nvme2n1p1    ONLINE       0     0     0     0
\tcache
\t  /dev/nvme2n1p2    ONLINE       0     0     0     0
\tspares
\t  /dev/sde1         AVAIL

errors: No known data errors

  pool: boot-pool
 state: ONLINE
  scan: scrub repaired 0B in 00:01:11 with 0 errors on Wed Oct 14 03:46:12 2026
config:

\tNAME         STATE     READ WRITE CKSUM  SLOW
\tboot-pool    ONLINE       0     0     0     -
\t  /dev/sdf3  ONLINE       0     0     0     0  (untrimmed)

errors: No known data errors
"""


def iostat_row(name, *vals):
    return "\t".join([name] + [str(v) for v in vals])


LAT = (1000000, 2000000, 900000, 1900000, 100, 200, 300, 400, "-", "-", "-")
IOSTAT = "\n".join([
    iostat_row("tank", 1000, 2000, 10, 20, 1024, 2048, *LAT),
    iostat_row("mirror-0", 500, 1000, 5, 10, 512, 1024, *LAT),
    iostat_row("sda1", 0, 0, 2, 5, 256, 512, *LAT),
    iostat_row("sdb1", 0, 0, 3, 5, 256, 512, *LAT),
    iostat_row("mirror-1", 500, 1000, 5, 10, 512, 1024, *LAT),
    iostat_row("sdc1", 0, 0, 2, 5, 256, 512, *LAT),
    iostat_row("sdd1", 0, 0, 3, 5, 256, 512, *LAT),
    "",
    iostat_row("mirror-2", 10, 20, 1, 2, 128, 256, *LAT),
    iostat_row("nvme0n1p1", 0, 0, 1, 1, 64, 128, *LAT),
    iostat_row("nvme1n1p1", 0, 0, 0, 1, 64, 128, *LAT),
    "",
    iostat_row("nvme2n1p1", 0, 0, 0, 50, 0, 4096, "-", 50000, "-", 49000,
               "-", 100, "-", 0, "-", "-", "-"),
    "",
    iostat_row("nvme2n1p2", 0, 0, 7, 0, 7000, 0, *LAT),
    iostat_row("boot-pool", 10, 20, 0, 31, 0, 158000, *LAT),
    iostat_row("sdf3", 10, 20, 0, 31, 0, 158000, *LAT),
])

GET = """\
tank\tsize\t2989297238016\t-
tank\tcapacity\t7\t-
tank\tashift\t12\tlocal
tank\tautotrim\toff\tdefault
tank\tdedupratio\t1.00\t-
tank\tfragmentation\t17\t-
tank\thealth\tONLINE\t-
"""

DS_GET = """\
dozer/STUFF\trecordsize\t131072\tdefault
dozer/STUFF\tcompression\tlz4\tinherited from dozer
dozer/STUFF\tcompressratio\t1.70\t-
dozer/STUFF\tsync\tstandard\tdefault
dozer/STUFF\txattr\tsa\tlocal
dozer/STUFF\tcasesensitivity\tinsensitive\t-
dozer/STUFF\torg.freenas:description\t\tlocal
"""

LIST = ("dozer\tfilesystem\t153742059680\t1775366512128\t95529104\t/mnt/dozer"
        "\tyes\ndozer/STUFF\tfilesystem\t33953637344\t1775366512128\t"
        "24091759120\t/mnt/dozer/STUFF\tyes\n123\tfilesystem\t1\t2\t3\tnone"
        "\tno\n")

ARCSTATS = """\
21 1 0x01 148 40256 7819322602 1680323537987871
name                            type data
hits                            4    900
iohits                          4    50
misses                          4    50
demand_data_hits                4    400
demand_data_iohits              4    0
demand_data_misses              4    100
demand_metadata_hits            4    500
demand_metadata_iohits          4    0
demand_metadata_misses          4    0
c                               4    1000
c_max                           4    2000
size                            4    1500
mru_size                        4    600
mfu_size                        4    900
memory_throttle_count           4    0
l2_ndev                         4    0
"""

OBJSET = """\
220 1 0x01 28 7872 61904739909 1680435336804209
name                            type data
dataset_name                    7    dozer/STUFF
writes                          4    10
nwritten                        4    4096
reads                           4    20
nread                           4    8192
zil_commit_count                4    3
"""

HISTO = """\
170 1 0x01 26 7072 61366965007 1680435340951004
name                            type data
1 ns                            4    0
512 ns                          4    1
1 us                            4    7
"""

TXGS = """\
txg      birth            state ndirty       nread        nwritten     reads    writes   otime        qtime        wtime        stime       
3313208  1680312643425864 C     4657664      0            1327104      0        237      5119890969   5755         12591        10661010    
3313209  1680317763316833 C     0            0            0            0        0        5119903053   6672         15021        82128       
3313210  1680322883219886 O     0            0            0            0        0        0            0            0            0           
"""  # noqa: E501

DISKSTATS_A = """\
   8      16 sdb 1000 10 80000 500 2000 20 160000 1000 0 1500 1600 0 0 0 0 10 5
   8      17 sdb1 1000 10 80000 500 2000 20 160000 1000 0 1500 1600 0 0 0 0 0 0
"""
DISKSTATS_B = """\
   8      16 sdb 1100 10 96000 540 2200 20 184000 1100 2 2000 2600 0 0 0 0 20 10
   8      17 sdb1 1100 10 96000 540 2200 20 184000 1100 2 2000 2600 0 0 0 0 0 0
"""

MOUNTS = """\
boot-pool/ROOT/x / zfs rw,relatime,xattr,noacl,casesensitive 0 0
dozer /mnt/dozer zfs rw,noatime,xattr,posixacl,casesensitive 0 0
dozer/STUFF /mnt/dozer/STUFF zfs rw,noatime,xattr,nfs4acl,caseinsensitive 0 0
dozer/with\\040space /mnt/dozer/with\\040space zfs rw 0 0
tmpfs /tmp tmpfs rw,nosuid 0 0
"""

SMBCONF = """\
# comment
[Global]
    workgroup = WORKGROUP
    zfs_core:zfs_block_cloning = False
    strict sync = no

[STUFF]
    path = /mnt/dozer/STUFF
    vfs objects = fruit truenas_streams_xattr shadow_copy_zfs ixnas \\
        zfs_core io_uring
    readonly = False
    ; a comment
    Case  Sensitive = yes

[homes]
    path = /mnt/dozer/home/%U
    writable = yes

[printers]
    printable = yes
"""


# -- zpool and zfs ---------------------------------------------------------------

def test_values():
    assert zfs.value("-") is None and zfs.value("12") == 12
    assert zfs.value("1.50") == 1.5 and zfs.value("on") == "on"
    assert zfs.nicenum("1.25K") == 1280 and zfs.nicenum("7") == 7
    assert zfs.nicenum("-") is None


def test_status_tree_classes_and_scan():
    st = zfs.parse_status(STATUS)
    assert set(st) == {"tank", "boot-pool"}
    t = st["tank"]
    assert t["state"] == "DEGRADED" and t["scan_in_progress"]
    assert t["text"]["status"].startswith("One or more devices")
    assert "Applications are unaffected." in t["text"]["status"]
    assert t["text"]["see"].startswith("https://")
    assert "02:50:00 to go" in t["scan"]
    by = {lf["dev"]: lf for lf in zfs.leaves(t["vdevs"])}
    assert list(by) == ["sda1", "sdb1", "sdc1", "sdd1", "nvme0n1p1",
                        "nvme1n1p1", "nvme2n1p1", "nvme2n1p2", "sde1"]
    bad = by["sdb1"]
    assert (bad["state"], bad["read"], bad["write"], bad["cksum"],
            bad["slow"], bad["note"]) == ("FAULTED", 3, 0, 12, 2,
                                          "too many errors")
    assert by["sda1"]["note"] == "(untrimmed)"
    assert by["sda1"]["vdev"] == "mirror-0" and by["sda1"]["class"] == "normal"
    assert by["nvme0n1p1"]["class"] == "special"
    assert by["nvme0n1p1"]["vdev"] == "mirror-2"
    assert by["nvme2n1p1"]["class"] == "log" and by["nvme2n1p1"]["vdev"] is None
    assert by["nvme2n1p2"]["class"] == "cache"
    assert by["sde1"]["class"] == "spare" and by["sde1"]["state"] == "AVAIL"
    assert by["sde1"]["read"] is None
    assert zfs.layout(t["vdevs"]) == {
        "normal": ["mirror of 2", "mirror of 2"], "special": ["mirror of 2"],
        "log": ["disk"], "cache": ["disk"], "spare": ["disk"]}
    b = st["boot-pool"]
    assert not b["scan_in_progress"] and b["errors"] == "No known data errors"
    assert b["scan"].startswith("scrub repaired 0B")
    assert zfs.layout(b["vdevs"]) == {"normal": ["disk"]}
    assert zfs.leaves(b["vdevs"])[0]["dev"] == "sdf3"
    assert zfs.leaves(None) == [] and zfs.layout(None) == {}


def test_iostat_rows_find_their_vdevs():
    rows = zfs.parse_iostat(IOSTAT)
    assert rows[0]["name"] == "tank" and rows[0]["ops_read"] == 10
    assert rows[0]["total_wait_read"] == 1000000
    assert rows[0]["scrub_wait"] is None and rows[0]["rebuild_wait"] is None
    att = zfs.attach_iostat(rows, zfs.parse_status(STATUS))
    assert set(att) == {"tank", "boot-pool"}
    tank = att["tank"]
    assert tank["pool"]["bytes_write"] == 2048
    assert set(tank["vdevs"]) == {"mirror-0", "mirror-1", "mirror-2"}
    assert set(tank["devices"]) == {"sda1", "sdb1", "sdc1", "sdd1",
                                    "nvme0n1p1", "nvme1n1p1", "nvme2n1p1",
                                    "nvme2n1p2"}
    log = tank["devices"]["nvme2n1p1"]
    assert log["total_wait_write"] == 50000 and log["total_wait_read"] is None
    assert "other" not in tank
    assert att["boot-pool"]["devices"]["sdf3"]["ops_write"] == 31


def test_get_values_and_sources():
    g = zfs.parse_get(GET)["tank"]
    assert g["props"]["size"] == 2989297238016 and g["props"]["capacity"] == 7
    assert g["props"]["dedupratio"] == 1.0 and g["props"]["health"] == "ONLINE"
    assert g["sources"] == {"ashift": "local"}
    d = zfs.parse_get(DS_GET)["dozer/STUFF"]
    assert d["props"]["compression"] == "lz4"
    assert d["props"]["recordsize"] == 131072
    assert d["props"]["org.freenas:description"] == ""
    assert d["sources"] == {"compression": "inherited from dozer",
                            "xattr": "local", "org.freenas:description": "local"}


def test_list_keeps_names_as_text():
    rows = zfs.parse_table(LIST, zfs.LIST_COLS,
                           raw=("name", "type", "mountpoint", "mounted"))
    assert rows[2]["name"] == "123" and rows[0]["used"] == 153742059680
    assert rows[1]["mountpoint"] == "/mnt/dozer/STUFF"
    assert rows[2]["mounted"] == "no"


# -- kstats ----------------------------------------------------------------------

def test_kstat_named_and_arc_summary():
    k = zfs.parse_kstat(ARCSTATS)
    assert k["snaptime"] == 1680323537987871
    assert k["data"]["hits"] == 900 and len(k["data"]) == 16
    a = zfs.arc_summary(k["data"])
    assert a["accesses"] == 1000 and a["hit_ratio"] == 0.9
    assert a["demand_data"]["hit_ratio"] == 0.8
    assert a["demand_metadata"]["hit_ratio"] == 1.0
    assert a["prefetch_data"]["hit_ratio"] is None
    assert a["size"] == 1500 and a["max"] == 2000 and a["mru"] == 600
    assert a["l2_hit_ratio"] is None and a["l2_devices"] == 0


def test_kstat_strings_spaces_and_delta():
    k = zfs.parse_kstat(OBJSET)
    assert k["data"]["dataset_name"] == "dozer/STUFF"
    later = dict(k["data"], writes=15, nwritten=8192, zil_commit_count=5)
    assert zfs.delta(k["data"], later) == {
        "writes": 5, "nwritten": 4096, "reads": 0, "nread": 0,
        "zil_commit_count": 2}
    assert zfs.parse_kstat(HISTO)["data"] == {"1 ns": 0, "512 ns": 1,
                                              "1 us": 7}
    assert zfs.parse_kstat("")["data"] == {}


def test_txgs_without_kstat_header():
    t = zfs.parse_txgs(TXGS)
    assert t["snaptime"] is None and len(t["txgs"]) == 3
    assert t["txgs"][0]["ndirty"] == 4657664 and t["txgs"][2]["state"] == "O"
    s = zfs.txg_summary(t)
    assert s["count"] == 2 and s["busy"] == 1
    assert s["dirty_avg"] == 4657664 and s["dirty_max"] == 4657664
    assert s["sync_avg_ns"] == 10661010 and s["sync_max_ns"] == 10661010
    assert s["written"] == 1327104 and s["span_ns"] is None
    assert s["open_avg_ns"] == pytest.approx((5119890969 + 5119903053) / 2)
    assert zfs.txg_summary({"txgs": []}) == {}


# -- the box ---------------------------------------------------------------------

def test_io_rates_like_iostat():
    a = blockdev.parse_diskstats(DISKSTATS_A)
    b = blockdev.parse_diskstats(DISKSTATS_B)
    assert set(a) == {"sdb", "sdb1"} and a["sdb"]["fl_ios"] == 10
    r = blockdev.io_rates(a, b, 2.0)["sdb"]
    assert r["reads_s"] == 50 and r["writes_s"] == 100
    assert r["read_bytes_s"] == pytest.approx(16000 * 512 / 2)
    assert r["read_wait_ns"] == pytest.approx(400_000)      # 40 ms / 100
    assert r["write_wait_ns"] == pytest.approx(500_000)     # 100 ms / 200
    assert r["read_size"] == pytest.approx(16000 * 512 / 100)
    assert r["write_size"] == pytest.approx(24000 * 512 / 200)
    assert r["flushes_s"] == 5 and r["flush_wait_ns"] == pytest.approx(500_000)
    assert r["queue"] == pytest.approx(0.5) and r["util"] == pytest.approx(0.25)
    assert r["in_flight"] == 2
    assert blockdev.io_rates(a, b, 0) == {}


def test_meminfo_mounts_and_lsblk_values():
    m = blockdev.parse_meminfo("MemTotal:       32832512 kB\n"
                               "HugePages_Total:       0\n")
    assert m == {"MemTotal": 32832512 * 1024, "HugePages_Total": 0}
    mounts = blockdev.parse_mounts(MOUNTS)
    assert [x["dataset"] for x in mounts] == [
        "boot-pool/ROOT/x", "dozer", "dozer/STUFF", "dozer/with space"]
    assert mounts[3]["mountpoint"] == "/mnt/dozer/with space"
    assert blockdev.mount_for("/mnt/dozer/STUFF/sub/dir",
                              mounts)["dataset"] == "dozer/STUFF"
    assert blockdev.mount_for("/mnt/dozer/STUFFED", mounts)["dataset"] == \
        "dozer"
    assert blockdev.mount_for("/mnt/dozer/STUFF", mounts)["dataset"] == \
        "dozer/STUFF"
    assert blockdev.mount_for("/srv/x", mounts)["dataset"] == \
        "boot-pool/ROOT/x"
    assert "nfs4acl" in blockdev.mount_for("/mnt/dozer/STUFF",
                                           mounts)["options"]
    assert blockdev.mount_for("/x", []) is None
    n = blockdev._norm({"NAME": "sda", "ROTA": "0", "SIZE": "1000",
                        "RQ-SIZE": "64", "SERIAL": "0123",
                        "children": [{"NAME": "sda1", "ROTA": True}]})
    assert n == {"name": "sda", "rota": False, "size": 1000, "rq_size": 64,
                 "serial": "0123",
                 "children": [{"name": "sda1", "rota": True}]}


# -- Samba -----------------------------------------------------------------------

def test_smbconf_sections_synonyms_and_paths():
    secs = smbconf.parse(SMBCONF)
    assert set(secs) == {"global", "STUFF", "homes", "printers"}
    st = secs["STUFF"]
    assert st["vfs objects"].split() == [
        "fruit", "truenas_streams_xattr", "shadow_copy_zfs", "ixnas",
        "zfs_core", "io_uring"]
    assert st["read only"] == "False" and st["case sensitive"] == "yes"
    assert secs["homes"]["read only"] == "no"
    assert smbconf.share_path(st) == "/mnt/dozer/STUFF"
    assert smbconf.share_path(secs["homes"]) == "/mnt/dozer/home"
    assert smbconf.share_path(secs["printers"]) is None
    io_ = smbconf.io_settings(st, secs["global"])
    assert io_["strict sync"] == "no" and "workgroup" not in io_
    assert io_["zfs_core:zfs_block_cloning"] == "False"
    assert io_["vfs objects"].split()[-1] == "io_uring"
    assert "vfs objects" not in smbconf.io_settings(secs["printers"],
                                                    secs["global"])
    assert smbconf.has_vfs(st, "io_uring")
    assert not smbconf.has_vfs(st, "aio_pthread")
    assert set(smbconf.shares(secs)) == {"STUFF", "homes", "printers"}


# -- notes and the report --------------------------------------------------------

def disk_of(dev: str) -> str:
    return re.sub(r"p\d+$", "", dev) if dev.startswith("nvme") \
        else re.sub(r"\d+$", "", dev)


def pool_entry(name: str, props: dict | None = None) -> dict:
    st = zfs.parse_status(STATUS)[name]
    leaves_ = zfs.leaves(st["vdevs"])
    for lf in leaves_:
        lf["disk"] = disk_of(lf["dev"])
    return {"state": st["state"], "status": st["text"].get("status"),
            "action": st["text"].get("action"), "scan": st["scan"],
            "scan_in_progress": st["scan_in_progress"],
            "errors": st["errors"], "vdevs": st["vdevs"], "leaves": leaves_,
            "layout": zfs.layout(st["vdevs"]), "props": props or {},
            "sources": {}, "txgs": {}, "kstats": {}, "iostat": None}


def device(name: str, rotational: bool, phys: int = 512) -> dict:
    return {"name": name, "rotational": rotational,
            "physical_block_size": phys, "model": f"Model {name}",
            "size": 1 << 40, "transport": "sata", "scheduler": "mq-deadline",
            "queue_depth": 32, "nr_requests": 64, "partitions": [],
            "zfs": []}


def base_run() -> dict:
    return {"tool": "smb-perf-disk", "start": "2026-10-15T23:00:00+00:00",
            "interval_s": 0, "host": {"hostname": "box", "kernel": "6.18",
                                      "truenas": "27.0", "cpus": 8},
            "smbd_version": "Version 4.24.4", "memory": {"MemTotal": 32 << 30},
            "io_uring": {"disabled": 0, "group": -1}, "mounts": [],
            "devices": [], "errors": [], "io": {"seconds": 0, "devices": {}},
            "samba": {"source": "testparm", "file": "/etc/smb4.conf",
                      "error": None, "global": {}, "shares": {}},
            "zfs": {"available": True, "version": "2.4.4-1", "params": {},
                    "modprobe": [], "pools": {}, "kstats": {}, "arc": None},
            "datasets": {}, "detailed": [], "notes": []}


def has(notes, *words):
    return any(all(w in n for w in words) for n in notes)


def test_notes_on_a_troubled_pool():
    run = base_run()
    run["zfs"]["pools"]["tank"] = pool_entry(
        "tank", {"capacity": 85, "fragmentation": 60, "ashift": 9,
                 "autotrim": "off"})
    run["zfs"]["pools"]["boot-pool"] = pool_entry(
        "boot-pool", {"capacity": 3, "fragmentation": 1, "ashift": 12,
                      "autotrim": "on"})
    run["devices"] = [device("sda", False, 4096), device("sdb", True),
                      device("sdc", True), device("sdd", True),
                      device("nvme0n1", False), device("nvme1n1", False),
                      device("nvme2n1", False), device("sde", True),
                      device("sdf", False)]
    n = cmd_disk.notes(run)
    assert has(n, "tank: scrub in progress", "competes")
    assert has(n, "tank is DEGRADED: One or more devices")
    assert has(n, "tank: 85% full")
    assert has(n, "tank: free space 60% fragmented")
    assert has(n, "sdb1 has errors read/write/cksum 3/0/12")
    assert has(n, "sdb1: 2 slow I/Os")
    assert has(n, "ashift 9 (512 B blocks) on sda1 with 4096 B sectors")
    assert has(n, "mirror-0 (normal) mixes rotating disks and SSDs")
    assert has(n, "tank: SSDs never trimmed (sda1;")
    assert not has(n, "boot-pool")
    assert not has(n, "mirror-1") and not has(n, "mirror-2 (special) mixes")


def test_notes_on_shares_and_datasets():
    run = base_run()
    run["zfs"]["pools"]["tank"] = pool_entry("tank", {"autotrim": "on"})
    run["zfs"]["pools"]["boot-pool"] = pool_entry("boot-pool",
                                                 {"autotrim": "on"})
    run["io_uring"] = {"disabled": 2, "group": -1}
    run["samba"]["shares"] = {
        "nolog": {"path": "/mnt/boot-pool/s", "dataset": "boot-pool/s",
                  "io": {"sync always": "yes", "strict sync": "no",
                         "strict allocate": "yes", "aio read size": "0"},
                  "params": {"vfs objects": "io_uring"}},
        "withlog": {"path": "/mnt/tank/s", "dataset": "tank/s",
                    "io": {"case sensitive": "yes"}, "params": {}},
        "gone": {"path": "/mnt/nowhere", "dataset": None, "io": {},
                 "params": {}},
    }
    run["datasets"] = {
        "boot-pool/s": {"props": {
            "sync": "always", "atime": "on", "relatime": "off",
            "xattr": "on", "dnodesize": "legacy", "casesensitivity":
            "sensitive", "dedup": "on", "primarycache": "metadata",
            "copies": 2, "encryption": "aes-256-gcm"}},
        "tank/s": {"props": {
            "sync": "disabled", "logbias": "throughput", "atime": "on",
            "relatime": "on", "xattr": "sa", "dnodesize": "legacy",
            "casesensitivity": "sensitive", "dedup": "off", "copies": 1,
            "encryption": "off"}},
    }
    n = cmd_disk.notes(run)
    assert has(n, "nolog (boot-pool/s): sync=always", "on the data disks")
    assert has(n, "boot-pool/s): atime=on without relatime")
    assert has(n, "boot-pool/s): xattr=on")
    assert has(n, "boot-pool/s): casesensitivity=sensitive")
    assert has(n, "boot-pool/s): dedup=on")
    assert has(n, "boot-pool/s): primarycache=metadata")
    assert has(n, "boot-pool/s): copies=2", "written 2 times")
    assert has(n, "boot-pool/s): encrypted (aes-256-gcm)")
    assert has(n, "nolog: sync always = yes")
    assert has(n, "nolog: strict sync = no")
    assert has(n, "nolog: strict allocate = yes")
    assert has(n, "nolog: aio read size = 0")
    assert has(n, "nolog: vfs io_uring with kernel.io_uring_disabled=2")
    assert has(n, "withlog (tank/s): sync=disabled")
    assert has(n, "withlog (tank/s): logbias=throughput")
    assert has(n, "withlog (tank/s): dnodesize=legacy with xattr=sa")
    assert not has(n, "withlog (tank/s): casesensitivity")
    assert not has(n, "withlog (tank/s): atime")
    assert has(n, "gone: /mnt/nowhere is not on a ZFS dataset")
    run["zfs"]["pools"]["tank"]["layout"].pop("log")
    run["datasets"]["tank/s"]["props"]["sync"] = "always"
    n = cmd_disk.notes(run)
    assert has(n, "withlog (tank/s): sync=always", "no log vdev")
    assert not has(n, "logbias=throughput")


def test_notes_on_memory_throttle_and_samba():
    run = base_run()
    run["zfs"]["available"] = False
    run["errors"] = ["zpool status: no answer in 120 s"]
    run["zfs"]["params"] = {"zfs_arc_max": 4 << 30}
    run["zfs"]["arc"] = {"max": 4 << 30, "size": 4 << 30, "interval": {
        "memory_throttles": 3, "accesses": 1000, "mru_ghost_hits": 50,
        "mfu_ghost_hits": 0}}
    run["zfs"]["kstats"]["dmu_tx"] = {
        "snapshot": {"dmu_tx_dirty_delay": 7, "dmu_tx_dirty_throttle": 0},
        "delta": {"dmu_tx_dirty_delay": 5, "dmu_tx_dirty_throttle": 0}}
    run["memory"] = {"MemTotal": 32 << 30, "SwapTotal": 4 << 30,
                     "SwapFree": 1 << 30}
    run["samba"] = {"source": "/etc/smb4.conf", "error":
                    "testparm: regdb_init: Permission denied", "shares": {}}
    n = cmd_disk.notes(run)
    assert has(n, "zpool and zfs not found")
    assert has(n, "could not run: zpool status: no answer")
    assert has(n, "ARC capped at 4.00G of 32.0G RAM")
    assert has(n, "throttled by memory pressure 3 times")
    assert has(n, "ARC is full and 50 of its 1.00K accesses")
    assert has(n, "held back by the dirty-data throttle 5 times")
    assert has(n, "swap in use: 3.00G of 4.00G")
    assert has(n, "testparm: regdb_init: Permission denied; shares read "
                  "from /etc/smb4.conf", "run as root")
    run["zfs"]["kstats"]["dmu_tx"]["delta"] = {"dmu_tx_dirty_delay": 0}
    assert has(cmd_disk.notes(run), "held writes back 7 times since boot")


def synthetic_run() -> dict:
    run = base_run()
    run["interval_s"] = 2.0
    run["zfs"]["pools"]["tank"] = pool_entry("tank", {
        "size": 10 << 40, "allocated": 1 << 40, "capacity": 10,
        "fragmentation": 5, "ashift": 12, "autotrim": "on",
        "dedupratio": 1.0})
    run["zfs"]["pools"]["boot-pool"] = pool_entry("boot-pool", {
        "size": 1 << 40, "allocated": 1 << 30, "capacity": 1,
        "fragmentation": 0, "ashift": 12, "autotrim": "off",
        "dedupratio": 1.0})
    tx = zfs.parse_txgs(TXGS)
    run["zfs"]["pools"]["tank"]["txgs"] = zfs.txg_summary(tx)
    rows = zfs.parse_iostat(IOSTAT)
    for p, att in zfs.attach_iostat(rows, zfs.parse_status(STATUS)).items():
        run["zfs"]["pools"][p]["iostat"] = att
    run["devices"] = [device(d, d.startswith("sd") and d not in ("sda", "sdf"))
                      for d in ("sda", "sdb", "sdc", "sdd", "sde", "sdf",
                                "nvme0n1", "nvme1n1", "nvme2n1", "sdz")]
    for p, pe in run["zfs"]["pools"].items():
        for lf in pe["leaves"]:
            for d in run["devices"]:
                if d["name"] == lf["disk"]:
                    d["zfs"].append({"pool": p, "leaf": lf["dev"]})
    arc = zfs.parse_kstat(ARCSTATS)["data"]
    later = dict(arc, hits=1900, misses=60, size=1600)
    run["zfs"]["kstats"]["arcstats"] = {"snapshot": later,
                                        "delta": zfs.delta(arc, later)}
    run["zfs"]["arc"] = zfs.arc_summary(later)
    run["zfs"]["arc"]["interval"] = zfs.arc_summary(zfs.delta(arc, later))
    zil = {"zil_commit_count": 100, "zil_itx_count": 300,
           "zil_itx_indirect_bytes": 1 << 30, "zil_itx_copied_bytes": 1 << 20,
           "zil_itx_needcopy_bytes": 1 << 24,
           "zil_itx_metaslab_normal_write": 1 << 28,
           "zil_itx_metaslab_slog_write": 1 << 29}
    run["zfs"]["kstats"]["zil"] = {"snapshot": zil, "delta": dict(
        zil, zil_commit_count=10, zil_itx_count=30)}
    run["zfs"]["kstats"]["dmu_tx"] = {"snapshot": {"dmu_tx_dirty_delay": 0},
                                      "delta": {"dmu_tx_dirty_delay": 0}}
    run["zfs"]["kstats"]["zfetchstats"] = {
        "snapshot": {"hits": 300, "misses": 100, "io_issued": 50},
        "delta": {"hits": 3, "misses": 1, "io_issued": 2}}
    run["zfs"]["kstats"]["dbufstats"] = {
        "snapshot": {"cache_size_bytes": 1 << 29, "cache_target_bytes": 1 << 30,
                     "hash_hits": 99, "hash_misses": 1}, "delta": None}
    run["io"] = {"seconds": 2.0, "devices": blockdev.io_rates(
        blockdev.parse_diskstats(DISKSTATS_A),
        blockdev.parse_diskstats(DISKSTATS_B), 2.0)}
    run["samba"]["shares"]["STUFF"] = {
        "path": "/mnt/tank/STUFF", "dataset": "tank/STUFF",
        "io": {"strict sync": "no"},
        "params": {"path": "/mnt/tank/STUFF", "vfs objects": "zfs_core io_uring"}}
    props = zfs.parse_get(DS_GET.replace("dozer/STUFF", "tank/STUFF"))
    run["datasets"]["tank/STUFF"] = {
        "pool": "tank", "list": {"type": "filesystem", "used": 1 << 30,
                                 "avail": 1 << 40},
        "props": dict(props["tank/STUFF"]["props"], dnodesize="auto"),
        "sources": props["tank/STUFF"]["sources"],
        "io": {"snapshot": {}, "delta": {"reads": 20, "nread": 40960,
                                         "writes": 4, "nwritten": 8192,
                                         "nunlinks": 0,
                                         "zil_commit_count": 2,
                                         "zil_itx_indirect_bytes": 8192}}}
    run["detailed"] = ["tank/STUFF"]
    run["zfs"]["params"] = {"zfs_arc_max": 0, "zfs_txg_timeout": 5,
                            "zfs_dirty_data_max": 3362049228, "other": 1}
    run["notes"] = cmd_disk.notes(run)
    return run


def test_report_covers_every_section():
    run = synthetic_run()
    out = io.StringIO()
    with redirect_stdout(out):
        cmd_disk.print_run(run)
    text = out.getvalue()
    for heading in ("host box: TrueNAS 27.0", "memory 32.0G", "ARC 1.56K of 1.95K max",
                    "\npools\n", "2 x mirror of 2; log: disk; special: "
                    "mirror of 2; cache: disk; spare: disk",
                    "tank scan: scrub in progress", "\nvdevs\n",
                    "nvme2n1p1", "(untrimmed)", "other disks:", "sdz",
                    "disk I/O over 2.0 s", "zpool iostat over 2.0 s",
                    "ZIL (sync writes)", "\ntransaction groups\n",
                    "last 2 committed", "\ncaching\n", "dataset I/O over",
                    "tank/STUFF", "shares (testparm)", "STUFF: strict sync",
                    "io_uring: allowed", "datasets (*", "lz4*", "1.70",
                    "ZFS module parameters of note", "zfs_txg_timeout",
                    "3362049228 (3.13G)", "\nnotes\n", "tank is DEGRADED"):
        assert heading in text, heading
    assert "other" not in text.split("ZFS module parameters")[1].split(
        "\nnotes")[0]
    out = io.StringIO()
    with redirect_stdout(out):
        cmd_disk.print_run(run, show_params=True)
    assert "  other " in out.getvalue()
    line = next(ln for ln in text.splitlines() if ln.startswith("  sdb "))
    assert "50/s" in line and "100/s" in line and "25.0%" in line
    assert "mirror-0 (normal) mixes" in text   # a note, from the synthetic disks


def test_main_prints_a_saved_run(tmp_path, capsys):
    run = synthetic_run()
    path = tmp_path / "disk.json"
    path.write_text(json.dumps(run))
    assert cmd_disk.main([str(path)]) == 0
    assert "host box:" in capsys.readouterr().out
    assert cmd_disk.main([str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["tool"] == "smb-perf-disk"
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"tool": "smb-perf-stat"}))
    assert cmd_disk.main([str(other)]) == 1
    assert cmd_disk.main([str(tmp_path / "missing.json")]) == 1


@pytest.mark.skipif(not os.path.exists("/proc/diskstats"),
                    reason="needs Linux")
def test_live_run(tmp_path, capsys):
    out = tmp_path / "run.json"
    assert cmd_disk.main(["--interval", "0.2", "-o", str(out)]) == 0
    text = capsys.readouterr().out
    assert text.startswith("host ")
    run = json.loads(out.read_text())
    assert run["tool"] == "smb-perf-disk" and isinstance(run["devices"], list)
    assert run["io"]["seconds"] >= 0.2
    assert "notes" in run and isinstance(run["zfs"]["params"], dict)
    if zfs.have_zfs() and run["zfs"]["pools"]:
        pool = next(iter(run["zfs"]["pools"].values()))
        assert pool["state"] and pool["props"]
        assert pool["leaves"] and pool["iostat"]["pool"]["ops_read"] is not None
        assert "disk I/O over" in text and "zpool iostat over" in text
    if run["samba"]["shares"]:
        assert "shares (" in text
