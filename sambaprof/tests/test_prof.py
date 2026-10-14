"""Tests on synthetic tdb files and counter snapshots; the live one needs
root and a Samba build with profiling (SMBPROF_SAMBA=prefix)."""

from __future__ import annotations

import io
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from contextlib import redirect_stdout
from pathlib import Path

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from smbprof import (  # noqa: E402
    cmd_compare, cmd_hist, cmd_latency, cmd_record, cmd_summary, data, fmt,
    smbd, tdb,
)
from smbprof.collect import Collector, share_key  # noqa: E402
from smbprof.layout import Layout, LayoutError  # noqa: E402

FIXTURE = os.path.join(HERE, "profile-4.24.txt")
MAGIC_424 = 0x8F2AD693D9DEE87F

SMALL = """\
**** SMBD loop ****************************************************************
connect_count:                                0
disconnect_count:                             0
idle_count:                                   0
idle_time:                                    0
cpu_user_time:                                0
cpu_system_time:                              0
request_count:                                0
set_root_sec_ctx_count:                       0
set_root_sec_ctx_time:                        0
num_sessions_count:                           0
num_tcons_count:                              0
num_files_count:                              0
**** Authentication ***********************************************************
authentication_count:                         0
authentication_failed_count:                  0
**** System Calls *************************************************************
syscall_openat_count:                         0
syscall_openat_time:                          0
syscall_asys_pread_count:                     0
syscall_asys_pread_time:                      0
syscall_asys_pread_idle:                      0
syscall_asys_pread_bytes:                     0
**** SMB2 Calls ***************************************************************
"""
for _op in ("smb2_create", "smb2_read", "smb2_notify"):
    SMALL += "".join(f"{_op}_{f}: 0\n" for f in (
        "count", "failed_count", "time")) + f"{_op}_buckets: " + \
        ",".join("0" * 10) + "\n" + "".join(
            f"{_op}_{f}: 0\n" for f in ("idle", "inbytes", "outbytes"))


def small() -> Layout:
    return Layout.from_profile_text(SMALL)


# -- tdb files ---------------------------------------------------------------

def tdb_image(records: dict[bytes, bytes], hash_size: int = 7,
              mutex: bool = False, dead=()) -> bytes:
    """A tdb file holding `records` (and dead ones) in hash chains by a
    toy hash; reading needs no real one."""
    base = 8192 if mutex else 0
    start = 168 + 4 * (hash_size + 1)
    heads = [0] * hash_size
    body = bytearray()
    items = [(k, v, tdb.REC_MAGIC) for k, v in records.items()] + \
        [(k, v, tdb.DEAD_MAGIC) for k, v in dead]
    for k, v, magic in items:
        b = sum(k) % hash_size
        rec_len = len(k) + len(v) + 4
        off = start + len(body)
        body += struct.pack("<6I", heads[b], rec_len, len(k), len(v), 0,
                            magic) + k + v + struct.pack("<I", rec_len + 24)
        heads[b] = off
    header = b"TDB file\n\0".ljust(32, b"\0") + struct.pack(
        "<9I", tdb.VERSION, hash_size,
        tdb.FEATURE_FLAG_MAGIC if mutex else 0, 0, 0, 0, 0,
        tdb.FEATURE_MUTEX if mutex else 0, base) + bytes(100)
    table = struct.pack(f"<{hash_size + 1}I", 0, *heads)
    pre = header.ljust(base, b"\0") if mutex else b""
    return pre + header + table + bytes(body)


def test_tdb_parse_plain_and_mutex():
    recs = {struct.pack("<i", 1234): b"a" * 40, b"t:1234.0[10.1.2.3]": b"b",
            struct.pack("<i", 99): b""}
    for mutex in (False, True):
        img = tdb_image(recs, mutex=mutex, dead=[(b"gone", b"x")])
        assert tdb.parse(img) == recs


def test_tdb_parse_rejects_damage():
    img = bytearray(tdb_image({b"k": b"v"}))
    with pytest.raises(tdb.TdbError):
        tdb.parse(b"not a tdb" + bytes(200))
    first = struct.unpack_from("<I", img, 172 + 4 * (sum(b"k") % 7))[0]
    struct.pack_into("<I", img, first + 20, 0x12345678)
    with pytest.raises(tdb.TdbError):
        tdb.parse(bytes(img))
    img = bytearray(tdb_image({b"k": b"v"}))
    struct.pack_into("<I", img, first, first)
    with pytest.raises(tdb.TdbError, match="loops"):
        tdb.parse(bytes(img))


def test_reader_without_bindings(tmp_path):
    path = tmp_path / "x.tdb"
    path.write_bytes(tdb_image({b"k": b"v"}, mutex=True))
    r = tdb.Reader(str(path), bindings=False)
    assert r.how == "built-in reader" and r.read() == {b"k": b"v"}


# -- layout ------------------------------------------------------------------

def test_layout_of_samba_424_matches_its_magic():
    lay = Layout.from_profile_text(open(FIXTURE).read())
    assert lay.words == 655
    assert lay.record_sizes()[5256] == 16
    assert lay.magic(16) == MAGIC_424
    c = lay.by_name["authentication_failed"]
    assert (c.kind, c.fields) == ("count", ("count",))
    r = lay.by_name["smb2_read"]
    assert r.kind == "iobytes" and r.width == 16 and r.section == "SMB2 Calls"
    assert lay.by_name["syscall_asys_pread"].kind == "bytes"


def test_layout_round_trip_and_errors():
    lay = small()
    again = Layout.from_json(json.loads(json.dumps(lay.to_json())))
    assert [c.offset for c in again.counters] == \
        [c.offset for c in lay.counters]
    assert lay.gauge_words == [lay.by_name[g].offset for g in
                               ("num_sessions", "num_tcons", "num_files")]
    with pytest.raises(LayoutError):
        Layout.from_profile_text("**** X ****\nfoo_bar: 1\n")
    with pytest.raises(LayoutError):
        lay.unpack(b"\0" * 10)


def record(lay: Layout, values: dict, magic: int = 7,
           summary: bool = False) -> bytes:
    """A profile_stats blob: {(counter, field): int or bucket list}."""
    words = [0] * lay.words
    for (name, f), v in values.items():
        for field, i, n in lay.by_name[name].slots():
            if field == f:
                if n == 1:
                    words[i] = v
                else:
                    words[i:i + n] = v
    return struct.pack("<QB7x", magic, summary) + \
        struct.pack(f"<{lay.words}Q", *words)


def test_unpack_and_sparse():
    lay = small()
    blob = record(lay, {("smb2_read", "count"): 3,
                        ("smb2_read", "buckets"): [1, 2, 3, 3, 3, 3, 3, 3,
                                                   3, 3]}, summary=True)
    magic, summary, words = lay.unpack(blob)
    assert (magic, summary) == (7, True)
    assert lay.sparse(words) == {"smb2_read": {
        "count": 3, "buckets": [1, 2, 3, 3, 3, 3, 3, 3, 3, 3]}}
    assert lay.unpack(blob[:8] + blob[16:])[1] is False


# -- the delta engine ---------------------------------------------------------

PID = struct.pack("<i", 1001)
PID2 = struct.pack("<i", 1002)
MAIN = struct.pack("<i", 1000)


def proc(pid, ticks=100, started=0.0, cpu=(0, 0), clients=()):
    return smbd.Proc(pid=pid, ppid=1000 if pid != 1000 else 1, comm="smbd"
                     if pid == 1000 else "smbd[10.1.2.3]", started=started,
                     ticks=ticks, cpu_us=cpu, clients=list(clients))


def vals(n_read, cpu=0, files=0, sessions=1):
    return {("smb2_read", "count"): n_read,
            ("smb2_read", "time"): 100 * n_read,
            ("smb2_read", "buckets"): [n_read] * 10,
            ("smb2_read", "outbytes"): 4096 * n_read,
            ("cpu_user", "time"): cpu, ("num_files", "count"): files,
            ("num_sessions", "count"): sessions}


def sample_of(lines):
    return [x for x in lines if x["type"] == "sample"][-1]


def test_collector_deltas_gauges_and_exit_tail():
    lay = small()
    col = Collector(lay, {7})
    procs = {1000: proc(1000), 1001: proc(1001, clients=["10.1.2.3:5000"])}
    out = col.sample(10.0, 1.0, {PID: record(lay, vals(5, cpu=1000, files=2))},
                     procs, 1000)
    first = sample_of(out)
    assert first["dt"] == 0 and "d" not in first["procs"]["1001"]
    assert first["procs"]["1001"]["g"]["num_files"] == 2
    assert [x["pid"] for x in out if x["type"] == "proc"] == [1001]
    out = col.sample(11.0, 2.0, {PID: record(lay, vals(8, cpu=1500, files=2))},
                     procs, 1000)
    e = sample_of(out)["procs"]["1001"]
    assert e["d"]["smb2_read"] == {"count": 3, "time": 300,
                                   "buckets": [3] * 10, "outbytes": 12288}
    assert e["d"]["cpu_user"] == {"time": 500} and "g" not in e
    # The process exits; cleanupd adds its final record to the main one.
    del procs[1001]
    out = col.sample(12.0, 3.0, {}, procs, 1000)
    assert {"type": "exit", "t": 12.0, "pid": 1001} in out
    merged = record(lay, {("smb2_read", "count"): 10,
                          ("smb2_read", "time"): 1000,
                          ("smb2_read", "buckets"): [10] * 10,
                          ("smb2_read", "outbytes"): 40960,
                          ("cpu_user", "time"): 1700}, summary=True)
    out = col.sample(13.0, 4.0, {MAIN: merged}, procs, 1000)
    s = sample_of(out)
    assert s["procs"]["1001"]["exit"] is True
    assert s["procs"]["1001"]["d"]["smb2_read"]["count"] == 2
    assert s["procs"]["1001"]["d"]["cpu_user"] == {"time": 200}
    assert "d" not in s["procs"].get("1000", {})


def test_collector_two_exits_go_to_main_and_resets():
    lay = small()
    col = Collector(lay, {7})
    procs = {1000: proc(1000), 1001: proc(1001), 1002: proc(1002)}
    snap = {PID: record(lay, vals(5)), PID2: record(lay, vals(7))}
    col.sample(10.0, 1.0, snap, procs, 1000)
    del procs[1001], procs[1002]
    col.sample(11.0, 2.0, {}, procs, 1000)
    out = col.sample(12.0, 3.0, {MAIN: record(lay, vals(15, sessions=0))},
                     procs, 1000)
    s = sample_of(out)
    assert s["procs"]["1000"]["d"]["smb2_read"]["count"] == 3
    assert "1001" not in s["procs"] and "1002" not in s["procs"]
    # A reset deletes the main record; counts start again from zero.
    out = col.sample(13.0, 4.0, {}, procs, 1000)
    assert not [x for x in out if x["type"] == "exit"]
    out = col.sample(14.0, 5.0, {MAIN: record(lay, vals(2, sessions=0))},
                     procs, 1000)
    assert sample_of(out)["procs"]["1000"]["d"]["smb2_read"]["count"] == 2


def test_collector_new_records_cpu_and_pid_reuse():
    lay = small()
    col = Collector(lay, {7})
    procs = {1000: proc(1000), 1001: proc(1001, started=5.0, cpu=(4000, 0))}
    col.sample(10.0, 1.0, {}, procs, 1000)
    # Switched on while running: CPU counts from when it was first seen.
    out = col.sample(11.0, 2.0, {PID: record(lay, vals(3, cpu=5000))},
                     procs, 1000)
    assert sample_of(out)["procs"]["1001"]["d"]["cpu_user"] == {"time": 1000}
    # Started during the interval: all of its CPU is in it.
    procs[1002] = proc(1002, started=11.5)
    out = col.sample(12.0, 3.0, {PID: record(lay, vals(3, cpu=5000)),
                                 PID2: record(lay, vals(1, cpu=800))},
                     procs, 1000)
    assert sample_of(out)["procs"]["1002"]["d"]["cpu_user"] == {"time": 800}
    # pid 1001 reused by a new process: a new baseline, not a reset.
    procs[1001] = proc(1001, ticks=999, started=12.5)
    out = col.sample(13.0, 4.0, {PID: record(lay, vals(4, cpu=300)),
                                 PID2: record(lay, vals(1, cpu=800))},
                     procs, 1000)
    d = sample_of(out)["procs"]["1001"]["d"]
    assert d["smb2_read"]["count"] == 4 and d["cpu_user"] == {"time": 300}


def test_collector_shares_and_foreign_records():
    lay = small()
    col = Collector(lay, {7})
    key = b"data:1001.2[10.1.2.3]"
    procs = {1000: proc(1000), 1001: proc(1001)}
    out = col.sample(10.0, 1.0, {key: record(lay, vals(1), magic=0),
                                 PID: record(lay, vals(1), magic=99)},
                     procs, 1000)
    assert col.foreign == 1
    assert [x for x in out if x["type"] == "share"][0]["share"] == "data"
    out = col.sample(11.0, 2.0, {key: record(lay, vals(4), magic=0)}, procs,
                     1000)
    assert sample_of(out)["shares"]["data:1001.2[10.1.2.3]"]["d"][
        "smb2_read"]["count"] == 3
    assert share_key(b"a:b:12.3[fe80::1]")["share"] == "a:b"
    assert share_key(b"\x01\x02\x03\x04\x05") is None


# -- recordings and the analysis tools ---------------------------------------

def recording(path, lay: Layout, steps, level="on", interval=1.0):
    """Write a recording: `steps` are (t, snapshot, procs) from the
    second sample on, after an empty baseline at t=100."""
    col = Collector(lay, {7})
    lines = [{"type": "start", "tool": "smb-prof-record", "format": 1,
              "time": 100.0, "interval": interval, "level": level,
              "samba": "4.24.4", "host": {"hostname": "nas"},
              "layout": lay.to_json()}]
    procs0 = steps[0][2]
    lines += col.sample(100.0, 0.0, {}, procs0, 1000)
    for t, snap, procs in steps:
        lines += col.sample(t, t - 100.0, snap, procs, 1000)
    lines.append({"type": "end", "t": steps[-1][0]})
    with open(path, "w") as f:
        for x in lines:
            f.write(json.dumps(x) + "\n")
    return path


def workload(tmp_path, name="a.jsonl", scale=1):
    """Two clients over 10 s: 10.1.2.3 reads, 10.1.2.4 creates."""
    lay = small()
    procs = {1000: proc(1000),
             1001: proc(1001, clients=["10.1.2.3:5000"]),
             1002: proc(1002, clients=["10.1.2.4:6000"])}
    steps = []
    for i in range(1, 11):
        n = 10 * i * scale
        steps.append((100.0 + i, {
            PID: record(lay, {
                ("smb2_read", "count"): n, ("smb2_read", "time"): 2500 * n,
                ("smb2_read", "buckets"): [0, 0, n // 2, n, n, n, n, n, n, n],
                ("smb2_read", "outbytes"): 65536 * n,
                ("syscall_asys_pread", "count"): n,
                ("syscall_asys_pread", "time"): 2000 * n,
                ("syscall_asys_pread", "bytes"): 65536 * n,
                ("cpu_user", "time"): 300 * n}),
            PID2: record(lay, {
                ("smb2_create", "count"): 2 * n,
                ("smb2_create", "failed_count"): i,
                ("smb2_create", "time"): 400 * n,
                ("smb2_create", "buckets"): [2 * n] * 10,
                ("syscall_openat", "count"): 6 * n,
                ("syscall_openat", "time"): 12 * n,
                ("smb2_notify", "count"): 1, ("smb2_notify", "time"): 10**6,
                ("smb2_notify", "idle"): 10**6,
                ("smb2_notify", "buckets"): [0] * 9 + [1],
                ("cpu_user", "time"): 100 * n})}, procs))
    return recording(str(tmp_path / name), lay, steps)


def run(main, *argv) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert main([str(a) for a in argv]) in (0, None)
    return buf.getvalue()


def test_summary_tool(tmp_path):
    rec = workload(tmp_path)
    r = json.loads(run(cmd_summary.main, rec, "--json"))
    assert r["requests"] == 100 + 200 + 1 and r["seconds"] == 10.0
    ops = {x["op"]: x for x in r["smb2"]}
    assert ops["READ"]["mean_us"] == 2500 and ops["READ"]["p50"] == "2-4ms"
    assert ops["CREATE"]["failed"] == 10 and ops["CREATE"]["p99"] == "<1ms"
    assert ops["CHANGE_NOTIFY"]["wait"] and ops["CHANGE_NOTIFY"]["share"] \
        is None
    assert r["time_us"] == 2500 * 100 + 400 * 100
    assert ops["CREATE"]["mean_us"] == 200
    assert r["cpu_us"] == 300 * 100 + 100 * 100
    sys_ = {x["name"]: x for x in r["syscalls"]}
    assert sys_["openat"]["per_request"] == pytest.approx(600 / 301)
    text = run(cmd_summary.main, rec, "--by", "client")
    assert "10.1.2.3" in text and "CHANGE_NOTIFY (wait)" in text
    one = json.loads(run(cmd_summary.main, rec, "--json", "--client",
                         "10.1.2.4", "--from", "5", "--to", "8"))
    assert one["requests"] == 3 * 20 and one["seconds"] == 3.0


def test_latency_tool(tmp_path):
    rec = workload(tmp_path)
    rows = json.loads(run(cmd_latency.main, rec, "--json"))["rows"]
    read = [x for x in rows if x["op"] == "READ"][0]
    assert read["bins"][:4] == [0, 0, 50, 50] and read["p90"] == "4-8ms"
    text = run(cmd_latency.main, rec, "--op", "READ", "--hist")
    assert "2-4ms" in text and "#" in text and "CREATE" not in text
    text = run(cmd_latency.main, rec, "--by", "pid", "--syscalls")
    assert "1001 10.1.2.3" in text and "openat" in text


def test_hist_tool(tmp_path):
    rec = workload(tmp_path)
    text = run(cmd_hist.main, rec, "--interval", "2", "--bars")
    assert "READ" in text and "CREATE" in text and "#" in text
    rows = run(cmd_hist.main, rec, "--by", "client", "--metric", "count",
               "--interval", "5", "--csv").splitlines()
    assert rows[0] == "start_s,time,10.1.2.4,10.1.2.3"
    assert rows[1].endswith(",101,50") and rows[2].endswith(",100,50")
    cpu = run(cmd_hist.main, rec, "--by", "none", "--metric", "cpu", "--csv")
    assert cpu.splitlines()[2].endswith(",0.004")
    mean = run(cmd_hist.main, rec, "--by", "none", "--metric", "mean",
               "--csv").splitlines()
    assert mean[2].endswith(f",{(2500 * 10 + 400 * 10) / 30:.3f}")


def test_compare_tool(tmp_path):
    a = workload(tmp_path, "a.jsonl")
    b = workload(tmp_path, "b.jsonl", scale=2)
    r = json.loads(run(cmd_compare.main, a, b, "--json"))
    ta, tb = (x["totals"] for x in r["runs"])
    assert tb["rate"] == pytest.approx(2 * ta["rate"], rel=0.01)
    text = run(cmd_compare.main, a, b, "--label", "old,new")
    assert "new vs old" in text and "READ" in text and "openat" in text


def test_selection_by_share_and_ops(tmp_path):
    lay = small()
    key = b"data:1001.0[10.1.2.3]"
    procs = {1000: proc(1000), 1001: proc(1001, clients=["10.1.2.3:5"])}
    steps = [(101.0, {PID: record(lay, vals(4)),
                      key: record(lay, vals(3), magic=0)}, procs)]
    rec = recording(str(tmp_path / "s.jsonl"), lay, steps)
    r = json.loads(run(cmd_summary.main, rec, "--json", "--share", "data"))
    assert r["requests"] == 3 and r["per_share"]
    run_ = data.Run(rec)
    assert data.resolve_ops("read,NOTIFY,openat,smb2_create", lay) == [
        "smb2_read", "smb2_notify", "syscall_openat", "smb2_create"]
    with pytest.raises(ValueError):
        data.resolve_ops("nope", run_.layout)


def test_helpers():
    assert data.bins([1, 2, 4, 4, 4, 4, 4, 4, 4, 5]) == \
        [1, 1, 2, 0, 0, 0, 0, 0, 0, 1]
    assert data.pct_label([1, 2, 4, 4, 4, 4, 4, 4, 4, 5], 99) == ">=256ms"
    assert data.pct_label(None, 50) == "-"
    assert fmt.parse_duration("1m30s") == 90 and fmt.parse_duration("250ms") \
        == 0.25
    assert fmt.parse_when("90", 1000.0) == 1090.0
    assert fmt.parse_when("@12.5", 0) == 12.5
    assert fmt.parse_when("1970-01-01T00:01:00Z", 0) == 60
    assert fmt.parse_when("00:02:00", 30.0) == 120
    assert fmt.fmt_us(820) == "820us" and fmt.fmt_us(1500) == "1.50ms"
    assert fmt.fmt_rate(4.0) == "4" and fmt.fmt_rate(0.57) == "0.57"
    assert [fmt.fmt_n(v) for v in (1234, 25081, 2.5e6, 12000)] == \
        ["1234", "25.1K", "2.5M", "12K"]
    assert smbd.serves(["10.1.2.3:51234"], "10.1.2.3")
    assert smbd.serves(["10.1.2.3:51234"], "10.1.2.3:51234")
    assert not smbd.serves(["10.1.2.3:51234"], "10.1.2.3:1")
    assert smbd.serves(["[fe80::1]:445"], "fe80:0::1")
    assert smbd.host_of("[fe80::1]:445") == "fe80::1"


def test_clients_from_proc(tmp_path):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    cl = socket.create_connection(("127.0.0.1", port))
    conn, addr = srv.accept()
    try:
        me = smbd.Proc(pid=os.getpid(), ppid=0, comm="x")
        smbd.attach_clients({me.pid: me}, [port])
        assert f"127.0.0.1:{addr[1]}" in me.clients
        assert port in smbd.listen_ports(os.getpid())
    finally:
        for s in (conn, cl, srv):
            s.close()


# -- live: a private smbd ---------------------------------------------------

PREFIX = os.environ.get("SMBPROF_SAMBA")


def _samba_ok() -> bool:
    return bool(PREFIX) and os.geteuid() == 0 and os.path.exists(
        os.path.join(PREFIX, "sbin", "smbd"))


live = pytest.mark.skipif(not _samba_ok(),
                          reason="needs root and SMBPROF_SAMBA=prefix")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def private_smbd():
    # The guest account must reach the share: not under pytest's 0700 dir.
    d = Path(tempfile.mkdtemp(prefix="smbprof-test-"))
    os.chmod(d, 0o755)
    for sub in ("private", "lk", "st", "cache", "run", "nc", "bd", "log",
                "share"):
        (d / sub).mkdir(parents=True)
    os.chmod(d / "share", 0o777)
    (d / "share" / "big").write_bytes(os.urandom(4 << 20))
    for i in range(50):
        (d / "share" / f"f{i}.txt").write_text(f"file {i}\n")
    port = _free_port()
    conf = d / "smb.conf"
    conf.write_text(f"""[global]
server role = standalone server
interfaces = 127.0.0.1
bind interfaces only = yes
server smb transports = tcp:{port}
disable netbios = yes
passdb backend = tdbsam:{d}/private/passdb.tdb
private dir = {d}/private
lock directory = {d}/lk
state directory = {d}/st
cache directory = {d}/cache
pid directory = {d}/run
ncalrpc dir = {d}/nc
binddns dir = {d}/bd
log file = {d}/log/log.%m
logging = file
load printers = no
disable spoolss = yes
map to guest = Bad User
guest account = nobody
rpc_daemon:mdssd = disabled
rpc_server:mdssvc = disabled
[t]
path = {d}/share
guest ok = yes
read only = no
smbd profiling share = yes
""")
    p = subprocess.Popen([os.path.join(PREFIX, "sbin", "smbd"), "-F", "-s",
                          str(conf), "--debug-stdout", "-d0"],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    yield conf, port, d
    p.terminate()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    shutil.rmtree(d, ignore_errors=True)


def _client(port, seconds, cmd):
    c = subprocess.Popen([os.path.join(PREFIX, "bin", "smbclient"),
                          "//127.0.0.1/t", "-p", str(port), "-N", "-m",
                          "SMB3"], stdin=subprocess.PIPE,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    end = time.time() + seconds
    while time.time() < end:
        c.stdin.write((cmd + "\n").encode())
        c.stdin.flush()
        time.sleep(0.05)
    c.stdin.write(b"quit\n")
    c.stdin.close()
    c.wait()


@live
def test_record_live_matches_smbstatus(private_smbd, tmp_path):
    conf, port, d = private_smbd
    out = tmp_path / "r.jsonl"
    rec = subprocess.Popen([sys.executable, os.path.join(
        os.path.dirname(HERE), "smb-prof-record"), "--samba", PREFIX, "-s",
        str(conf), "--reset", "--duration", "8", "-q", "-o", str(out)])
    time.sleep(1.5)
    _client(port, 3, "ls")
    _client(port, 2, "get big /dev/null")
    assert rec.wait(30) == 0
    text = subprocess.run([os.path.join(PREFIX, "bin", "smbstatus"), "-s",
                           str(conf), "--profile"], capture_output=True,
                          text=True).stdout
    run_ = data.Run(str(out))
    acc = data.Acc()
    for s in run_.samples:
        for e in s["procs"].values():
            acc.add(e.get("d", {}))
    want = {}
    for line in text.splitlines():
        if ":" in line and not line.startswith("*"):
            k, v = line.split(":", 1)
            want[k.strip()] = [int(x) for x in v.split(",")] if "," in v \
                else int(v)
    for c in run_.layout.counters:
        if c.name.startswith(("num_", "cpu_")):
            continue
        for f in c.fields:
            got = acc.c.get(c.name, {}).get(f, [0] * 10 if f == "buckets"
                                             else 0)
            assert got == want[f"{c.name}_{f}"], (c.name, f)
    assert acc.get("smb2_find", "count") > 0
    assert run_.has_shares()
    assert os.path.getsize(d / "cache" / "smbprofile.tdb") < 4 << 20


@live
def test_bindings_and_built_in_reader_agree(private_smbd, tmp_path):
    conf, port, d = private_smbd
    path = str(d / "cache" / "smbprofile.tdb")
    subprocess.run([os.path.join(PREFIX, "bin", "smbcontrol"), "-s",
                    str(conf), open(d / "run" / "smbd.pid").read().strip(),
                    "profile", "on"], check=True)
    _client(port, 2, "ls")
    time.sleep(2)
    a = tdb.Reader(path, PREFIX)
    b = tdb.Reader(path, bindings=False)
    assert a.mod is not None
    assert a.read() == b.read() != {}
    tdb.wipe(path, PREFIX)
    assert b.read() == {}


def test_record_without_samba_tools(tmp_path):
    with pytest.raises(SystemExit, match="smbstatus not found"):
        cmd_record.main(["--samba", str(tmp_path), "--duration", "1"])
